using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent integration: optional IWorkspacePermissionSource in registrars/observers;
// source selection before unavailable gate, generic resolution to configured action.
internal static class WorkspacePermissionEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext context, IWorkspacePermissionSource? source, CancellationToken token)
    {
        var input = WorkspacePermissionInput.FromScope(context.Input);
        if (!WorkspacePermissionContract.Owns(context.Definition) || input is null ||
            context.Variant != WorkspacePermissionContract.Variant(input.Action) || WorkspacePermissionContract.Gate(input.ScopeProfile, input.Action) is not null)
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalWorkspacePermissionSource(new(input.Observer), input.Observer.Identity);
        var root = new WorkspacePermissionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            context.Environment.Origin.AbsoluteUri, context.OrganizationId, context.Definition.Key.Operation, context.Variant,
            context.Definition.Key.Case, context.Definition.Key.Scope, source.Identity, source.Kind, input.ScopeProfile, input.ActorKind,
            input.Action, new(context.Required("setupIdentityId"), context.Required("runtimeIdentityId"), context.Required("deniedIdentityId"),
                context.Required("administrativeIdentityId"), context.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await WorkspacePermissionTrial.OpenAsync(source, root, capability,
            t => context.Cleanup(async _ => { await t.DisposeAsync(); return true; }), token);
        await WitnessAsync(context.Environment, root, trial, false, token);
        await trial.ArmAsync(token);
        await trial.SettleAsync(await DispatchAsync(context.Environment, root, trial.Plan, trial.Issued, token), token);
        if (trial.Outcome == WorkspacePermissionOutcome.Partial) { context.Probe.Effect(NativeObservation.Unavailable); return; }
        await ActivateAsync(context.Environment, root, trial, token);
        await WitnessAsync(context.Environment, root, trial, true, token);
        context.Probe.Effect(NativeObservation.Matched);
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, WorkspacePermissionRoot root, WorkspacePermissionTrial trial, bool after, CancellationToken token)
    {
        await trial.BeginAsync(after, token); var attempts = new List<WorkspacePermissionAttempt>();
        foreach (var row in trial.Rows(after)) attempts.Add(await WorkspacePermissionClient.ExecuteAsync(env, root, trial.Plan, trial.Issued, row, token));
        await trial.ObserveAsync(after, attempts.ToArray(), token);
        await WorkspacePermissionReadback.CheckAsync(env, root, trial, token);
    }
    internal static string OriginalPath(WorkspacePermissionRoot root, WorkspacePermissionPlan plan, WorkspacePermissionIssued issued) =>
        (WorkspacePermissionContract.Template(root.Operation) ? "/api/v1/project-templates" : root.ScopeProfile == WorkspacePermissionScope.Organization ?
            "/api/v1/organization/roles" : root.ActorKind == MemberPermissionActorKind.Machine ? "/api/v2/identity-project-additional-privilege" :
            "/api/v1/projects/" + issued.Id(WorkspacePermissionPlan.Project) + "/roles") +
        (WorkspacePermissionContract.Create(root.Operation) ? "" : "/" + issued.Id(plan.PolicyKey));
    internal static async ValueTask<WorkspacePermissionReceipt> DispatchAsync(NativeEnvironment env, WorkspacePermissionRoot root,
        WorkspacePermissionPlan plan, WorkspacePermissionIssued issued, CancellationToken token)
    {
        bool create = WorkspacePermissionContract.Create(root.Operation);
        if (root.ScopeProfile == WorkspacePermissionScope.Organization)
        {
            var change = new OrganizationRoleChange(plan.Slug, plan.Slug,
                permissions: [new(OrganizationRoleSubject.Workspace, Enum.Parse<OrganizationRoleAction>(root.Action.ToString()))]);
            return await SendAsync(env, root, create ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
                RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.Id(plan.PolicyKey), change), token);
        }
        var action = Enum.Parse<ProjectRoleAction>(root.Action.ToString());
        if (WorkspacePermissionContract.Template(root.Operation))
        {
            var configuration = new ProjectTemplateConfiguration(
                [new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.Workspace, action)])],
                ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([]),
                users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(plan.ActorKey(0)), [plan.Slug])]),
                groups: ProjectTemplateCollection<ProjectTemplateGroup>.FromValues([]),
                identities: ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues([]),
                projectManagedIdentities: ProjectTemplateCollection<ProjectTemplateManagedIdentity>.FromValues([]));
            return await SendAsync(env, root, create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: configuration) :
                ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: configuration), token);
        }
        ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Workspace, action)];
        if (root.ActorKind == MemberPermissionActorKind.User)
        {
            var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
            return await SendAsync(env, root, create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(WorkspacePermissionPlan.Project), change) :
                RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(WorkspacePermissionPlan.Project), issued.Id(plan.PolicyKey), change), token);
        }
        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Id(WorkspacePermissionPlan.Project), plan.ProjectSlug,
            issued.Actors[0].Principal, issued.Id(plan.ActorMembership(0)));
        var privilege = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
        return await SendAsync(env, root, create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, privilege) :
            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.Id(plan.PolicyKey), privilege), token);
    }
    internal static async ValueTask<WorkspacePermissionReceipt> SendAsync<T>(NativeEnvironment env, WorkspacePermissionRoot root,
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
                WorkspacePermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
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
    internal static async ValueTask ActivateAsync(NativeEnvironment env, WorkspacePermissionRoot root, WorkspacePermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome != WorkspacePermissionOutcome.Applied) return;
        var p = trial.Plan; var v = trial.Issued;
        if (WorkspacePermissionContract.Template(root.Operation))
            trial.Activated(await SendAsync(env, root, ProjectOperations.CreateProject(root.Organization, p.CopySlug, p.CopySlug,
                template: p.Slug, createDefaultEnvironments: false), token, true));
        else if (root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal))
            trial.Activated(await SendAsync(env, root, ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization,
                v.Id(WorkspacePermissionPlan.Project), v.Id(p.ActorMembership(0)), [new(p.Slug)]), token, true));
        else if (root.Operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal))
            trial.Activated(await SendAsync(env, root, OrganizationMembershipOperations.UpdateOrganizationMembership(root.Organization,
                v.Id(p.ActorMembership(0)), role: p.Slug), token, true));
    }
}
internal static class WorkspacePermissionClient
{
    internal static string Method(WorkspacePermissionAction action) => action switch
    { WorkspacePermissionAction.Create => "POST", WorkspacePermissionAction.Edit => "PATCH", _ => "DELETE" };
    internal static string Path(WorkspacePermissionRoot root, WorkspacePermissionPlan plan, WorkspacePermissionIssued issued, WorkspacePermissionRow row) =>
        "/api/v1/projects" + (row.Action == WorkspacePermissionAction.Create ? "" : "/" + issued.Id(row.Target));
    internal static ManagementRequest<ProjectSummary> Request(WorkspacePermissionRoot root, WorkspacePermissionIssued issued, WorkspacePermissionRow row) => row.Action switch
    {
        WorkspacePermissionAction.Create => ProjectOperations.CreateProject(issued.Id(row.Organization), row.Name, row.Slug,
            "closed-v1", deleteProtection: false, createDefaultEnvironments: false),
        WorkspacePermissionAction.Edit => ProjectOperations.UpdateProject(issued.Id(row.Organization), issued.Id(row.Target),
            name: row.Name + "-edited", slug: row.Slug + "-v2", description: "closed-v2", deleteProtection: false,
            auditRetentionDays: 17, secretSharing: true, autoCapitalization: true, encryptedMetadata: true,
            pointInTimeVersionLimit: 23, showLegacySnapshots: true, secretDetectionIgnoreValues: []),
        _ => ProjectOperations.DeleteProject(issued.Id(row.Organization), issued.Id(row.Target))
    };
    internal static async ValueTask<WorkspacePermissionAttempt> ExecuteAsync(NativeEnvironment env, WorkspacePermissionRoot root,
        WorkspacePermissionPlan plan, WorkspacePermissionIssued issued, WorkspacePermissionRow row, CancellationToken token)
    {
        var actor = issued.Actors[row.Actor];
        using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) :
            new MemberPermissionTokens(env.Tokens(actor.Principal == root.Authorities.Denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime));
        var client = env.CreateManagementClient(); using var request = Request(root, issued, row);
        var authority = new ManagementAuthority(client.Authority, tokens, issued.Id(row.Organization), request.Target.ProjectId);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token);
        return new(row, tokens.Hash, result.Status, receipt.Evidence,
            result.IsSuccess ? plan.Snapshot(row, issued, result.Value, row.Action == WorkspacePermissionAction.Edit ? 2 : 1) : null,
            true, request.Target.SecondaryId ?? WorkspacePermissionContract.RawHash([]));
    }
}
