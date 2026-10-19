using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent integration: optional IRolePermissionSource in registrars/observers;
// source selection before unavailable gate, generic resolution to configured action.
internal static class RolePermissionEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext context, IRolePermissionSource? source, CancellationToken token)
    {
        var input = RolePermissionInput.FromScope(context.Input);
        if (!RolePermissionContract.Owns(context.Definition) || input is null ||
            context.Variant != RolePermissionContract.Variant(input.Action) || RolePermissionContract.Gate(input.ScopeProfile, input.Action) is not null)
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalRolePermissionSource(new(input.Observer), input.Observer.Identity);
        var root = new RolePermissionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            context.Environment.Origin.AbsoluteUri, context.OrganizationId, context.Definition.Key.Operation, context.Variant,
            context.Definition.Key.Case, context.Definition.Key.Scope, source.Identity, source.Kind, input.ScopeProfile, input.ActorKind,
            input.Action, new(context.Required("setupIdentityId"), context.Required("runtimeIdentityId"), context.Required("deniedIdentityId"),
                context.Required("administrativeIdentityId"), context.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await RolePermissionTrial.OpenAsync(source, root, capability,
            t => context.Cleanup(async _ => { await t.DisposeAsync(); return true; }), token);
        await WitnessAsync(context.Environment, root, trial, false, token);
        await trial.ArmAsync(token);
        await trial.SettleAsync(await DispatchAsync(context.Environment, root, trial.Plan, trial.Issued, token), token);
        if (trial.Outcome == RolePermissionOutcome.Partial) { context.Probe.Effect(NativeObservation.Unavailable); return; }
        await ActivateAsync(context.Environment, root, trial, token);
        await WitnessAsync(context.Environment, root, trial, true, token);
        context.Probe.Effect(NativeObservation.Matched);
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, RolePermissionRoot root, RolePermissionTrial trial, bool after, CancellationToken token)
    {
        await trial.BeginAsync(after, token); var attempts = new List<RolePermissionAttempt>();
        foreach (var row in trial.Rows(after)) attempts.Add(await RolePermissionClient.ExecuteAsync(env, root, trial.Plan, trial.Issued, row, token));
        await trial.ObserveAsync(after, attempts.ToArray(), token);
    }
    internal static string OriginalPath(RolePermissionRoot root, RolePermissionPlan plan, RolePermissionIssued issued) =>
        (RolePermissionContract.Template(root.Operation) ? "/api/v1/project-templates" : root.ScopeProfile == RolePermissionScope.Organization ?
            "/api/v1/organization/roles" : root.ActorKind == MemberPermissionActorKind.Machine ? "/api/v2/identity-project-additional-privilege" :
            "/api/v1/projects/" + issued.Id(RolePermissionPlan.Project) + "/roles") +
        (RolePermissionContract.Create(root.Operation) ? "" : "/" + issued.Id(plan.PolicyKey));
    internal static async ValueTask<RolePermissionReceipt> DispatchAsync(NativeEnvironment env, RolePermissionRoot root,
        RolePermissionPlan plan, RolePermissionIssued issued, CancellationToken token)
    {
        bool create = RolePermissionContract.Create(root.Operation);
        if (root.ScopeProfile == RolePermissionScope.Organization)
        {
            var change = new OrganizationRoleChange(plan.Slug, plan.Slug,
                permissions: [new(OrganizationRoleSubject.Role, Enum.Parse<OrganizationRoleAction>(root.Action.ToString()))]);
            return await SendAsync(env, root, create ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
                RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.Id(plan.PolicyKey), change), token);
        }
        var action = Enum.Parse<ProjectRoleAction>(root.Action.ToString());
        if (RolePermissionContract.Template(root.Operation))
        {
            var configuration = new ProjectTemplateConfiguration(
                [new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.Role, action)])],
                ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
                users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(plan.ActorKey(0)), [plan.Slug])]));
            return await SendAsync(env, root, create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: configuration) :
                ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: configuration), token);
        }
        ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Role, action)];
        if (root.ActorKind == MemberPermissionActorKind.User)
        {
            var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
            return await SendAsync(env, root, create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(RolePermissionPlan.Project), change) :
                RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(RolePermissionPlan.Project), issued.Id(plan.PolicyKey), change), token);
        }
        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Id(RolePermissionPlan.Project), plan.ProjectSlug,
            issued.Actors[0].Principal, issued.Id(plan.ActorMembership(0)));
        var privilege = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
        return await SendAsync(env, root, create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, privilege) :
            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.Id(plan.PolicyKey), privilege), token);
    }
    internal static async ValueTask<RolePermissionReceipt> SendAsync<T>(NativeEnvironment env, RolePermissionRoot root,
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
                RolePermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
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
    internal static async ValueTask ActivateAsync(NativeEnvironment env, RolePermissionRoot root, RolePermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome != RolePermissionOutcome.Applied) return;
        var p = trial.Plan; var v = trial.Issued;
        if (RolePermissionContract.Template(root.Operation))
            trial.Activated(await SendAsync(env, root, ProjectOperations.CreateProject(root.Organization, p.CopySlug, p.CopySlug,
                template: p.Slug, createDefaultEnvironments: false), token, true));
        else if (root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal))
            trial.Activated(await SendAsync(env, root, ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization,
                v.Id(RolePermissionPlan.Project), v.Id(p.ActorMembership(0)), [new(p.Slug)]), token, true));
        else if (root.Operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal))
            trial.Activated(await SendAsync(env, root, OrganizationMembershipOperations.UpdateOrganizationMembership(root.Organization,
                v.Id(p.ActorMembership(0)), role: p.Slug), token, true));
    }
}
internal static class RolePermissionClient
{
    internal static string Method(RolePermissionAction action) => action switch
    { RolePermissionAction.Read => "GET", RolePermissionAction.Create => "POST", RolePermissionAction.Edit => "PATCH", _ => "DELETE" };
    internal static string Path(RolePermissionRoot root, RolePermissionPlan plan, RolePermissionIssued issued, RolePermissionRow row) =>
        root.ScopeProfile == RolePermissionScope.Organization ? "/api/v1/organization/roles" + (row.Action == RolePermissionAction.Create ? "" : "/" + issued.Id(row.Target)) :
        row.Action == RolePermissionAction.Read ? "/api/v1/projects/roles/" + issued.Id(row.Target) :
        "/api/v1/projects/" + issued.Id(row.Project) + "/roles" + (row.Action == RolePermissionAction.Create ? "" : "/" + issued.Id(row.Target));
    internal static ManagementRequest<RoleSummary> Request(RolePermissionRoot root, RolePermissionIssued issued, RolePermissionRow row)
    {
        string org = issued.Id(row.Organization), project = issued.Id(row.Project), id = issued.Id(row.Target);
        bool edit = row.Action == RolePermissionAction.Edit;
        string name = edit ? row.Name + "-edited" : row.Name, slug = edit ? row.Slug + "-v2" : row.Slug;
        var description = new RoleDescription(edit ? "closed-v2" : "closed-v1");
        if (root.ScopeProfile == RolePermissionScope.Organization)
            return row.Action switch
            {
                RolePermissionAction.Read => ScopedAccessOperations.GetOrganizationRole(org, id),
                RolePermissionAction.Create => RoleChangeOperations.CreateOrganizationRole(org, new(name, slug, description, [])),
                RolePermissionAction.Edit => RoleChangeOperations.UpdateOrganizationRole(org, id, new(name, slug, description, [])),
                _ => ScopedAccessOperations.DeleteOrganizationRole(org, id)
            };
        return row.Action switch
        {
            RolePermissionAction.Read => ProjectOperations.GetProjectRole(org, project, id),
            RolePermissionAction.Create => RoleChangeOperations.CreateProjectRole(org, project, new(name, slug, description, [])),
            RolePermissionAction.Edit => RoleChangeOperations.UpdateProjectRole(org, project, id, new(name, slug, description, [])),
            _ => ProjectOperations.DeleteProjectRole(org, project, id)
        };
    }
    internal static async ValueTask<RolePermissionAttempt> ExecuteAsync(NativeEnvironment env, RolePermissionRoot root,
        RolePermissionPlan plan, RolePermissionIssued issued, RolePermissionRow row, CancellationToken token)
    {
        var actor = issued.Actors[row.Actor];
        using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) :
            new MemberPermissionTokens(env.Tokens(actor.Principal == root.Authorities.Denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime));
        var client = env.CreateManagementClient(); using var request = Request(root, issued, row);
        var authority = new ManagementAuthority(client.Authority, tokens, issued.Id(row.Organization), request.Target.ProjectId);
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token);
        return new(row, tokens.Hash, result.Status, receipt?.Evidence,
            result.IsSuccess ? plan.Snapshot(row, issued, result.Value, row.Action == RolePermissionAction.Edit ? 2 : 1) : null, true);
    }
}
