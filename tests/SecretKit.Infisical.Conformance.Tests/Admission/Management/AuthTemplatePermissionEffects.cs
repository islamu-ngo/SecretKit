using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent injection: IAuthTemplatePermissionSource on InfisicalPermissionFamilies;
// GovernanceObservers.AuthTemplatePermissions; ManagementClientEffects.Resolve
// selects authTemplatePermission before generic fallback and forwards the source.
// No project registrar/denominator changes. Original factory label is retained.
internal static class AuthTemplatePermissionEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext context, IAuthTemplatePermissionSource? source, CancellationToken token)
    {
        var input = AuthTemplatePermissionInput.FromScope(context.Input);
        if (!AuthTemplatePermissionContract.Owns(context.Definition) || input is null ||
            context.Variant != AuthTemplatePermissionContract.Variant(input.Action) || AuthTemplatePermissionContract.Gate(input.Action) is not null)
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalAuthTemplatePermissionSource(new(input.Observer), input.Observer.Identity);
        var root = new AuthTemplatePermissionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            context.Environment.Origin.AbsoluteUri, context.OrganizationId, context.Definition.Key.Operation, context.Variant,
            context.Definition.Key.Case, context.Definition.Key.Scope, source.Identity, source.Kind, input.Action,
            new(context.Required("setupIdentityId"), context.Required("runtimeIdentityId"), context.Required("deniedIdentityId"),
                context.Required("administrativeIdentityId"), context.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await AuthTemplatePermissionTrial.OpenAsync(source, root, capability,
            t => context.Cleanup(async _ => { await t.DisposeAsync(); return true; }), token);
        await WitnessAsync(context.Environment, trial, false, token);
        await trial.ArmAsync(token);
        await trial.SettleAsync(await DispatchAsync(context.Environment, root, trial.Plan, trial.Issued, token), token);
        if (trial.Outcome == AuthTemplatePermissionOutcome.Partial) { context.Probe.Effect(NativeObservation.Unavailable); return; }
        await ActivateAsync(context.Environment, trial, token);
        await WitnessAsync(context.Environment, trial, true, token);
        context.Probe.Effect(NativeObservation.Matched);
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, AuthTemplatePermissionTrial trial, bool after, CancellationToken token)
    {
        await trial.BeginAsync(after, token); var attempts = new List<AuthTemplatePermissionAttempt>();
        foreach (var row in trial.Rows()) attempts.Add(await AttemptAsync(env, trial.Root, trial.Issued, row, token));
        await trial.ObserveAsync(after, attempts.ToArray(), token);
        await ReadbackAsync(env, trial.Root, trial.Inventory, token);
    }
    internal static async ValueTask<AuthTemplatePermissionAttempt> AttemptAsync(NativeEnvironment env, AuthTemplatePermissionRoot root,
        AuthTemplatePermissionIssued issued, AuthTemplatePermissionRow row, CancellationToken token)
    {
        using var tokens = new MemberPermissionTokens(issued.Actors[row.Actor].Credential);
        var client = env.CreateManagementClient(); var plan = new AuthTemplatePermissionPlan(root);
        var authority = new ManagementAuthority(client.Authority, tokens, root.Organization);
        switch (row.Action)
        {
            case AuthTemplatePermissionAction.List:
                return await Send(IdentityTemplateOperations.SearchIdentityTemplates(root.Organization, limit: 100), value => value.Items.ToArray(), value => value.IsComplete, false);
            case AuthTemplatePermissionAction.Attach:
                return await Send(IdentityTemplateOperations.ListIdentityTemplates(root.Organization, IdentityTemplateAuthMethod.Kubernetes), value => value.Items.ToArray(), value => value.IsComplete, false);
            case AuthTemplatePermissionAction.Create:
                using (var fields = plan.CreateFields())
                    return await Send(IdentityTemplateOperations.CreateKubernetesIdentityTemplate(root.Organization, plan.Name(AuthTemplatePermissionPlan.Created), fields), value => [value], _ => true, true);
            case AuthTemplatePermissionAction.Edit:
                using (var fields = plan.EditFields())
                    return await Send(IdentityTemplateOperations.UpdateIdentityTemplateConfiguration(root.Organization, issued.Id(AuthTemplatePermissionPlan.Selected), fields, plan.Name("changed")), value => [value], _ => true, true);
            case AuthTemplatePermissionAction.Delete:
                return await Send(IdentityTemplateOperations.DeleteIdentityTemplate(root.Organization, issued.Id(AuthTemplatePermissionPlan.Selected)), _ => [], _ => true, true);
            default: throw new NativeCaseFailureException("observer-unavailable");
        }
        async ValueTask<AuthTemplatePermissionAttempt> Send<T>(ManagementRequest<T> request, Func<T, IdentityTemplateSummary[]> values, Func<T, bool> complete, bool mutation) where T : notnull
        {
            using (request)
            {
                var receipt = mutation ? client.CreateReceipt(request) : null;
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token);
                return new(row, tokens.Hash, result.Status, receipt, receipt?.Evidence ?? DispatchEvidence.NotDispatched,
                    mutation ? request.Target.SecondaryId ?? "" : "", result.IsSuccess ? values(result.Value) : [], !result.IsSuccess || complete(result.Value));
            }
        }
    }
    internal static string OriginalPath(AuthTemplatePermissionRoot root, AuthTemplatePermissionIssued issued) =>
        "/api/v1/organization/roles" + (AuthTemplatePermissionContract.Create(root.Operation) ? "" : "/" + issued.Id(AuthTemplatePermissionPlan.Policy));
    internal static ValueTask<AuthTemplatePermissionReceipt> DispatchAsync(NativeEnvironment env, AuthTemplatePermissionRoot root,
        AuthTemplatePermissionPlan plan, AuthTemplatePermissionIssued issued, CancellationToken token)
    {
        var change = new OrganizationRoleChange(plan.Slug, plan.Slug,
            permissions: [new(OrganizationRoleSubject.MachineIdentityAuthTemplate, AuthTemplatePermissionContract.Sdk(root.Action))]);
        return SendAsync(env, root, AuthTemplatePermissionContract.Create(root.Operation) ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
            RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.Id(AuthTemplatePermissionPlan.Policy), change), token);
    }
    internal static async ValueTask ActivateAsync(NativeEnvironment env, AuthTemplatePermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome != AuthTemplatePermissionOutcome.Applied) return;
        trial.Activated(await SendAsync(env, trial.Root, OrganizationMembershipOperations.UpdateOrganizationMembership(trial.Root.Organization,
            trial.Issued.Id("member-0"), trial.Plan.Slug), token, true));
    }
    internal static async ValueTask ReadbackAsync(NativeEnvironment env, AuthTemplatePermissionRoot root, AuthTemplatePermissionState[] states, CancellationToken token)
    {
        // The observer has a separate authority. Never add ListTemplates to the
        // exercising actor merely to make a mutation readback convenient.
        foreach (var state in states.Where(s => s.Organization == root.Organization))
        {
            var client = env.CreateManagementClient();
            using var request = IdentityTemplateOperations.GetIdentityTemplate(root.Organization, state.Id);
            var authority = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), cancellationToken: token);
            AuthTemplatePermissionContract.Require(result.IsSuccess, "effect-mismatch"); Match(result.Value, state);
        }
    }
    internal static void Match(IdentityTemplateSummary value, AuthTemplatePermissionState state)
    {
        var c = value.Configuration; var s = state.Configuration;
        AuthTemplatePermissionContract.Require(value.Id == state.Id && value.OrganizationId == state.Organization && value.Name == state.Name &&
            value.AuthMethod == IdentityTemplateAuthMethod.Kubernetes && value.CreatedAt == state.CreatedAt && value.UpdatedAt == state.UpdatedAt &&
            value.HasStoredCredential == s.HasCredential && c.TokenReviewMode == s.Mode && c.HasKubernetesHost && c.KubernetesHost == s.Host &&
            c.CaCertificate == s.Ca && c.VerifyTlsCertificate == s.VerifyTls && c.AllowedAudience == s.Audience &&
            !c.HasGatewayId && !c.HasGatewayPoolId && s.Gateway is null && s.GatewayPool is null, "effect-mismatch");
    }
    internal static async ValueTask<AuthTemplatePermissionReceipt> SendAsync<T>(NativeEnvironment env, AuthTemplatePermissionRoot root,
        ManagementRequest<T> request, CancellationToken token, bool setup = false) where T : notnull
    {
        using (request)
        {
            var client = env.CreateManagementClient(); var receipt = client.CreateReceipt(request);
            var role = setup ? NativeIdentityRole.Setup : root.Boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
            var barrier = !setup && root.Boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(role)) : null;
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), root.Organization, request.Target.ProjectId);
            using var loss = !setup && root.Boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancellation) : null;
            using var scope = loss?.Enter(); Task? entered = barrier?.Entered;
            var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, cancellation.Token).AsTask();
            SecretOutcome<T>? result = null; bool cancelled = false;
            try
            {
                if (entered is not null) { await entered.WaitAsync(token); cancellation.Cancel(); barrier!.Release(); }
                try { result = await execution; }
                catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !token.IsCancellationRequested) { cancelled = true; }
                AuthTemplatePermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
                return new(receipt, result?.Status, cancelled, request.Target.SecondaryId ?? "");
            }
            finally
            {
                cancellation.Cancel(); barrier?.Release();
                try { result ??= await execution; } catch (OperationCanceledException) { }
                if (result is { IsSuccess: true } completed && completed.Value is IDisposable owned) owned.Dispose();
            }
        }
    }
}
