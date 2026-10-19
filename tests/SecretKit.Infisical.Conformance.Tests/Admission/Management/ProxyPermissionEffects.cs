using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent integration: optional IProxyPermissionSource in registrars/observers;
// source selection before unavailable gate, generic resolution to configured action.
internal static class ProxyPermissionEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext context, IProxyPermissionSource? source, CancellationToken token)
    {
        var input = ProxyPermissionInput.FromScope(context.Input);
        if (!ProxyPermissionContract.Owns(context.Definition) || input is null ||
            context.Variant != ProxyPermissionContract.Variant(input.Action) || ProxyPermissionContract.Gate(input.ScopeProfile, input.Action) is not null)
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalProxyPermissionSource(new(input.Observer), input.Observer.Identity);
        var root = new ProxyPermissionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            context.Environment.Origin.AbsoluteUri, context.OrganizationId, context.Definition.Key.Operation, context.Variant,
            context.Definition.Key.Case, context.Definition.Key.Scope, source.Identity, source.Kind, input.ScopeProfile, input.ActorKind,
            input.Action, new(context.Required("setupIdentityId"), context.Required("runtimeIdentityId"), context.Required("deniedIdentityId"),
                context.Required("administrativeIdentityId"), context.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await ProxyPermissionTrial.OpenAsync(source, root, capability,
            t => context.Cleanup(async _ => { await t.DisposeAsync(); return true; }), token);
        await WitnessAsync(context.Environment, root, trial, false, token);
        await trial.ArmAsync(token);
        await trial.SettleAsync(await DispatchAsync(context.Environment, root, trial.Plan, trial.Issued, token), token);
        if (trial.Outcome == ProxyPermissionOutcome.Partial) { context.Probe.Effect(NativeObservation.Unavailable); return; }
        await ActivateAsync(context.Environment, root, trial, token);
        await WitnessAsync(context.Environment, root, trial, true, token);
        context.Probe.Effect(NativeObservation.Matched);
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, ProxyPermissionRoot root, ProxyPermissionTrial trial, bool after, CancellationToken token)
    {
        await trial.BeginAsync(after, token); var attempts = new List<ProxyPermissionAttempt>();
        foreach (var row in trial.Rows(after)) attempts.Add(await ProxyPermissionClient.ExecuteAsync(env, root, trial.Plan, trial.Issued, row, token));
        await trial.ObserveAsync(after, attempts.ToArray(), token);
        await ProxyPermissionClient.InventoryAsync(env, root, trial.Plan, trial.Issued, trial.States, token);
    }
    internal static string OriginalPath(ProxyPermissionRoot root, ProxyPermissionPlan plan, ProxyPermissionIssued issued) =>
        (ProxyPermissionContract.Template(root.Operation) ? "/api/v1/project-templates" : root.ActorKind == MemberPermissionActorKind.Machine ? "/api/v2/identity-project-additional-privilege" :
            "/api/v1/projects/" + issued.Id(ProxyPermissionPlan.Project) + "/roles") +
        (ProxyPermissionContract.Create(root.Operation) ? "" : "/" + issued.Id(plan.PolicyKey));
    internal static async ValueTask<ProxyPermissionReceipt> DispatchAsync(NativeEnvironment env, ProxyPermissionRoot root,
        ProxyPermissionPlan plan, ProxyPermissionIssued issued, CancellationToken token)
    {
        bool create = ProxyPermissionContract.Create(root.Operation);
        var action = Enum.Parse<ProjectRoleAction>(root.Action.ToString());
        if (ProxyPermissionContract.Template(root.Operation))
        {
            var configuration = new ProjectTemplateConfiguration(
                [new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.ProxiedServices, action, conditions: [new(RoleConditionField.Environment, ProjectTemplateStringClause.Literal("witness")), new(RoleConditionField.SecretPath, ProjectTemplateStringClause.Literal("/closed"))])])],
                ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1.5)]),
                users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(plan.ActorKey(0)), [plan.Slug])]));
            return await SendAsync(env, root, create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: configuration) :
                ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: configuration), token);
        }
        ProjectRolePermission[] permissions = [new(ProjectRoleSubject.ProxiedServices, action, conditions: [new(RoleConditionField.Environment, RoleStringClause.Literal("witness")), new(RoleConditionField.SecretPath, RoleStringClause.Literal("/closed"))])];
        if (root.ActorKind == MemberPermissionActorKind.User)
        {
            var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
            return await SendAsync(env, root, create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(ProxyPermissionPlan.Project), change) :
                RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(ProxyPermissionPlan.Project), issued.Id(plan.PolicyKey), change), token);
        }
        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Id(ProxyPermissionPlan.Project), plan.ProjectSlug,
            issued.Actors[0].Principal, issued.Id(plan.ActorMembership(0)));
        var privilege = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
        return await SendAsync(env, root, create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, privilege) :
            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.Id(plan.PolicyKey), privilege), token);
    }
    internal static async ValueTask<ProxyPermissionReceipt> SendAsync<T>(NativeEnvironment env, ProxyPermissionRoot root,
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
                ProxyPermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
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
    internal static async ValueTask ActivateAsync(NativeEnvironment env, ProxyPermissionRoot root, ProxyPermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome != ProxyPermissionOutcome.Applied) return;
        var p = trial.Plan; var v = trial.Issued;
        if (ProxyPermissionContract.Template(root.Operation))
            trial.Activated(await SendAsync(env, root, ProjectOperations.CreateProject(root.Organization, p.CopySlug, p.CopySlug,
                template: p.Slug, createDefaultEnvironments: false), token, true));
        else if (root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal))
            trial.Activated(await SendAsync(env, root, ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization,
                v.Id(ProxyPermissionPlan.Project), v.Id(p.ActorMembership(0)), [new(p.Slug)]), token, true));
    }
}
