using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent hooks: optional ISettingsPermissionSource on permission/project
// registrars and GovernanceObservers; select settingsPermission before the
// unavailable gate; generic ExecuteAsync resolves to the configured action while
// retaining its factory label. No SDK or existing integration point is edited.
internal static class SettingsPermissionEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext context, ISettingsPermissionSource? source, CancellationToken token)
    {
        var input = SettingsPermissionInput.FromScope(context.Input);
        if (!SettingsPermissionContract.Owns(context.Definition) || input is null ||
            context.Variant != SettingsPermissionContract.Variant(input.Action) ||
            SettingsPermissionContract.Gate(input.ScopeProfile, input.Action) is not null)
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalSettingsPermissionSource(new(input.Observer), input.Observer.Identity);
        var root = new SettingsPermissionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            context.Environment.Origin.AbsoluteUri, context.OrganizationId, context.Definition.Key.Operation, context.Variant,
            context.Definition.Key.Case, context.Definition.Key.Scope, source.Identity, source.Kind, input.ScopeProfile, input.ActorKind,
            input.Action, new(context.Required("setupIdentityId"), context.Required("runtimeIdentityId"), context.Required("deniedIdentityId"),
                context.Required("administrativeIdentityId"), context.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await SettingsPermissionTrial.OpenAsync(source, root, capability,
            t => context.Cleanup(async _ => { await t.DisposeAsync(); return true; }), token);
        await WitnessAsync(context.Environment, trial, false, token);
        await trial.ArmAsync(token);
        await trial.SettleAsync(await DispatchAsync(context.Environment, root, trial.Plan, trial.Issued, token), token);
        if (trial.Outcome == SettingsPermissionOutcome.Partial) { context.Probe.Effect(NativeObservation.Unavailable); return; }
        await ActivateAsync(context.Environment, root, trial, token);
        await WitnessAsync(context.Environment, trial, true, token);
        context.Probe.Effect(NativeObservation.Matched);
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, SettingsPermissionTrial trial, bool after, CancellationToken token)
    {
        await trial.BeginAsync(after, token);
        var attempts = new List<SettingsPermissionAttempt>();
        // ManagementClient uses the environment's shared transport. Each dispatch
        // gets a fresh ONE-USE token source; a case uses one pooled connection.
        foreach (var row in trial.Rows(after)) attempts.Add(await PatchAsync(env, trial.Root, trial.Issued, row, token));
        await trial.ObserveAsync(after, attempts.ToArray(), token);
        await SettingsPermissionReadback.CheckAsync(env, trial.Root, trial.Inventory, token);
    }
    internal static async ValueTask<SettingsPermissionAttempt> PatchAsync(NativeEnvironment env, SettingsPermissionRoot root,
        SettingsPermissionIssued issued, SettingsPermissionRow row, CancellationToken token)
    {
        var actor = issued.Actors[row.Actor];
        using var tokens = new MemberPermissionTokens(actor.Credential);
        var client = env.CreateManagementClient(); var plan = new SettingsPermissionPlan(root);
        using var request = ProjectOperations.UpdateProject(root.Organization, issued.Id(row.Project),
            plan.ChangedName, plan.ChangedSlug, plan.ChangedDescription);
        var receipt = client.CreateReceipt(request);
        var authority = new ManagementAuthority(client.Authority, tokens, root.Organization, issued.Id(row.Project));
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token);
        return new(row, tokens.Hash, result.Status, receipt, receipt.Evidence, request.Target.SecondaryId ?? "",
            result.IsSuccess ? result.Value : null);
    }
    internal static string OriginalPath(SettingsPermissionRoot root, SettingsPermissionPlan plan, SettingsPermissionIssued issued) =>
        (SettingsPermissionContract.Template(root.Operation) ? "/api/v1/project-templates" :
            root.ActorKind == MemberPermissionActorKind.Machine ? "/api/v2/identity-project-additional-privilege" :
            "/api/v1/projects/" + issued.Id(SettingsPermissionPlan.Project) + "/roles") +
        (SettingsPermissionContract.Create(root.Operation) ? "" : "/" + issued.Id(plan.PolicyKey));
    internal static async ValueTask<SettingsPermissionReceipt> DispatchAsync(NativeEnvironment env, SettingsPermissionRoot root,
        SettingsPermissionPlan plan, SettingsPermissionIssued issued, CancellationToken token)
    {
        bool create = SettingsPermissionContract.Create(root.Operation);
        ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Settings, ProjectRoleAction.Edit)];
        if (SettingsPermissionContract.Template(root.Operation))
        {
            var configuration = new ProjectTemplateConfiguration([new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.Settings, ProjectRoleAction.Edit)])],
                ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Development", "dev", 1.5)]),
                users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(0), [plan.Slug])]));
            return await SendAsync(env, root, create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: configuration) :
                ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: configuration), token);
        }
        if (root.ActorKind == MemberPermissionActorKind.User)
        {
            var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
            return await SendAsync(env, root, create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(SettingsPermissionPlan.Project), change) :
                RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(SettingsPermissionPlan.Project), issued.Id(plan.PolicyKey), change), token);
        }
        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Id(SettingsPermissionPlan.Project), plan.ProjectSlug,
            issued.Actors[0].Identity.Principal, issued.Id("member-0"));
        var privilege = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
        return await SendAsync(env, root, create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, privilege) :
            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.Id(plan.PolicyKey), privilege), token);
    }
    internal static async ValueTask<SettingsPermissionReceipt> SendAsync<T>(NativeEnvironment env, SettingsPermissionRoot root,
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
                SettingsPermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
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
    internal static async ValueTask ActivateAsync(NativeEnvironment env, SettingsPermissionRoot root, SettingsPermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome != SettingsPermissionOutcome.Applied) return;
        var p = trial.Plan; var v = trial.Issued;
        if (SettingsPermissionContract.Template(root.Operation))
            trial.Activated(await SendAsync(env, root, ProjectOperations.CreateProject(root.Organization, p.CopySlug, p.CopySlug,
                template: p.Slug, createDefaultEnvironments: false), token, true));
        else if (root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal))
            trial.Activated(await SendAsync(env, root, ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization,
                v.Id(SettingsPermissionPlan.Project), v.Id("member-0"), [new(p.Slug)]), token, true));
    }
}
