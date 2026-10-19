using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent integration: optional IGatewayPermissionSource in registrars/observers;
// source selection before unavailable gate, generic resolution to configured action.
internal static class GatewayPermissionEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext context, IGatewayPermissionSource? source, CancellationToken token)
    {
        var input = GatewayPermissionInput.FromScope(context.Input);
        if (!GatewayPermissionContract.Owns(context.Definition) || input is null ||
            context.Variant != GatewayPermissionContract.Variant(input.Action) || GatewayPermissionContract.Gate(input.ScopeProfile, input.Action) is not null)
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalGatewayPermissionSource(new(input.Observer), input.Observer.Identity);
        var root = new GatewayPermissionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            context.Environment.Origin.AbsoluteUri, context.OrganizationId, context.Definition.Key.Operation, context.Variant,
            context.Definition.Key.Case, context.Definition.Key.Scope, source.Identity, source.Kind, input.ScopeProfile, input.ActorKind,
            input.Action, new(context.Required("setupIdentityId"), context.Required("runtimeIdentityId"), context.Required("deniedIdentityId"),
                context.Required("administrativeIdentityId"), context.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await GatewayPermissionTrial.OpenAsync(source, root, capability,
            t => context.Cleanup(async _ => { await t.DisposeAsync(); return true; }), token);
        await WitnessAsync(context.Environment, root, trial, false, token);
        await trial.ArmAsync(token);
        await trial.SettleAsync(await DispatchAsync(context.Environment, root, trial.Plan, trial.Issued, token), token);
        if (trial.Outcome == GatewayPermissionOutcome.Partial) { context.Probe.Effect(NativeObservation.Unavailable); return; }
        await ActivateAsync(context.Environment, root, trial, token);
        await WitnessAsync(context.Environment, root, trial, true, token);
        context.Probe.Effect(NativeObservation.Matched);
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, GatewayPermissionRoot root, GatewayPermissionTrial trial, bool after, CancellationToken token)
    {
        await trial.BeginAsync(after, token); var attempts = new List<GatewayPermissionAttempt>();
        foreach (var row in trial.Rows(after)) attempts.Add(await GatewayPermissionClient.ExecuteAsync(env, root, trial.Plan, trial.Issued, row, token));
        await trial.ObserveAsync(after, attempts.ToArray(), token);
    }
    internal static string OriginalPath(GatewayPermissionRoot root, GatewayPermissionPlan plan, GatewayPermissionIssued issued) =>
        "/api/v1/organization/roles" + (GatewayPermissionContract.Create(root.Operation) ? "" : "/" + issued.Id(plan.PolicyKey));
    internal static ValueTask<GatewayPermissionReceipt> DispatchAsync(NativeEnvironment env, GatewayPermissionRoot root,
        GatewayPermissionPlan plan, GatewayPermissionIssued issued, CancellationToken token)
    {
        var action = root.Action == GatewayPermissionAction.Create ? OrganizationRoleAction.CreateGateways : OrganizationRoleAction.EditGateways;
        var change = new OrganizationRoleChange(plan.Slug, plan.Slug, permissions: [new(OrganizationRoleSubject.Gateway, action)]);
        return SendAsync(env, root, GatewayPermissionContract.Create(root.Operation) ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
            RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.Id(plan.PolicyKey), change), token);
    }
    internal static async ValueTask<GatewayPermissionReceipt> SendAsync<T>(NativeEnvironment env, GatewayPermissionRoot root,
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
                GatewayPermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
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
    internal static async ValueTask ActivateAsync(NativeEnvironment env, GatewayPermissionRoot root, GatewayPermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome == GatewayPermissionOutcome.Applied && GatewayPermissionContract.Create(root.Operation))
            trial.Activated(await SendAsync(env, root, OrganizationMembershipOperations.UpdateOrganizationMembership(root.Organization,
                trial.Issued.Id(trial.Plan.ActorMembership(0)), role: trial.Plan.Slug), token, true));
    }
}
internal static class GatewayPermissionClient
{
    internal static string Method(GatewayPermissionAction action) => action == GatewayPermissionAction.Create ? "POST" : "PATCH";
    internal static string Path(GatewayPermissionRoot root, GatewayPermissionPlan plan, GatewayPermissionIssued issued, GatewayPermissionRow row) =>
        "/api/v3/gateways" + (row.Action == GatewayPermissionAction.Create ? "" : "/" + issued.Id(row.Target));
    internal static async ValueTask<GatewayPermissionAttempt> ExecuteAsync(NativeEnvironment env, GatewayPermissionRoot root,
        GatewayPermissionPlan plan, GatewayPermissionIssued issued, GatewayPermissionRow row, CancellationToken token)
    {
        var actor = issued.Actors[row.Actor];
        using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) : new MemberPermissionTokens(env.Tokens(NativeIdentityRole.Runtime));
        int version = row.Action == GatewayPermissionAction.Edit ? 2 : 1;
        using var auth = GatewayAuthenticationInput.Aws(GatewayPermissionPlan.Accounts(version), GatewayPermissionPlan.Principals(version));
        using var request = row.Action == GatewayPermissionAction.Create ?
            GatewayAdministrationOperations.Create(issued.Id(row.Organization), new(row.Name, auth)) :
            GatewayAdministrationOperations.Update(issued.Id(row.Organization), issued.Id(row.Target), new(row.Name + "-edited", auth));
        var client = env.CreateManagementClient(); var receipt = client.CreateReceipt(request);
        var authority = new ManagementAuthority(client.Authority, tokens, issued.Id(row.Organization));
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token);
        GatewayPermissionState? value = result.IsSuccess ? plan.Snapshot(row, issued, result.Value, version) : null;
        if (result.IsSuccess)
        {
            // Observer Get is a fresh projection, NOT a list permission witness.
            using var read = GatewayAdministrationOperations.Get(issued.Id(row.Organization), result.Value.Id);
            var observer = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), issued.Id(row.Organization));
            var fresh = await client.ExecuteAsync(read, observer, observer.IssueGrant(read.OperationId, read.Target), cancellationToken: token);
            GatewayPermissionContract.Require(fresh.IsSuccess && plan.Snapshot(row, issued, fresh.Value, version) == value, "effect-mismatch");
        }
        return new(row, tokens.Hash, result.Status, receipt.Evidence, value, true, request.Target.SecondaryId ?? "");
    }
}
