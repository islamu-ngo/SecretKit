using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent integration: optional IGroupPermissionSource in registrars/observers;
// source selection before unavailable gate, generic resolution to configured action.
internal static class GroupPermissionEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext context, IGroupPermissionSource? source, CancellationToken token)
    {
        var input = GroupPermissionInput.FromScope(context.Input);
        if (!GroupPermissionContract.Owns(context.Definition) || input is null ||
            context.Variant != GroupPermissionContract.Variant(input.Action) || GroupPermissionContract.Gate(input.ScopeProfile, input.Action) is not null)
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalGroupPermissionSource(new(input.Observer), input.Observer.Identity);
        var root = new GroupPermissionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            context.Environment.Origin.AbsoluteUri, context.OrganizationId, context.Definition.Key.Operation, context.Variant,
            context.Definition.Key.Case, context.Definition.Key.Scope, source.Identity, source.Kind, input.ScopeProfile, input.ActorKind,
            input.Action, new(context.Required("setupIdentityId"), context.Required("runtimeIdentityId"), context.Required("deniedIdentityId"),
                context.Required("administrativeIdentityId"), context.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await GroupPermissionTrial.OpenAsync(source, root, capability,
            t => context.Cleanup(async _ => { await t.DisposeAsync(); return true; }), token);
        await WitnessAsync(context.Environment, root, trial, false, token);
        await trial.ArmAsync(token);
        await trial.SettleAsync(await DispatchAsync(context.Environment, root, trial.Plan, trial.Issued, token), token);
        if (trial.Outcome == GroupPermissionOutcome.Partial) { context.Probe.Effect(NativeObservation.Unavailable); return; }
        await ActivateAsync(context.Environment, root, trial, token);
        await WitnessAsync(context.Environment, root, trial, true, token);
        context.Probe.Effect(NativeObservation.Matched);
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, GroupPermissionRoot root, GroupPermissionTrial trial, bool after, CancellationToken token)
    {
        await trial.BeginAsync(after, token); var attempts = new List<GroupPermissionAttempt>();
        foreach (var row in trial.Rows(after)) attempts.Add(await GroupPermissionClient.ExecuteAsync(env, root, trial.Plan, trial.Issued, row, token));
        await trial.ObserveAsync(after, attempts.ToArray(), token);
    }
    internal static string OriginalPath(GroupPermissionRoot root, GroupPermissionPlan plan, GroupPermissionIssued issued) =>
        (GroupPermissionContract.Template(root.Operation) ? "/api/v1/project-templates" : root.ScopeProfile == GroupPermissionScope.Organization ?
            "/api/v1/organization/roles" : root.ActorKind == MemberPermissionActorKind.Machine ? "/api/v2/identity-project-additional-privilege" :
            "/api/v1/projects/" + issued.Id(GroupPermissionPlan.Project) + "/roles") +
        (GroupPermissionContract.Create(root.Operation) ? "" : "/" + issued.Id(plan.PolicyKey));
    internal static async ValueTask<GroupPermissionReceipt> DispatchAsync(NativeEnvironment env, GroupPermissionRoot root,
        GroupPermissionPlan plan, GroupPermissionIssued issued, CancellationToken token)
    {
        bool create = GroupPermissionContract.Create(root.Operation);
        if (root.ScopeProfile == GroupPermissionScope.Organization)
        {
            var change = new OrganizationRoleChange(plan.Slug, plan.Slug,
                permissions: [new(OrganizationRoleSubject.Groups, Enum.Parse<OrganizationRoleAction>(root.Action.ToString()))]);
            return await SendAsync(env, root, create ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
                RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.Id(plan.PolicyKey), change), token);
        }
        string[] names = plan.Rows.Where(r => r.Control == "selected").Select(r => r.Name).ToArray();
        RoleCondition[]? conditions = root.Action == GroupPermissionAction.AssignRole ?
            [new(RoleConditionField.GroupName, RoleStringClause.Compare(included: names)),
                new(RoleConditionField.AssignableRole, RoleStringClause.Literal(plan.Role))] : null;
        var action = Enum.Parse<ProjectRoleAction>(root.Action.ToString());
        if (GroupPermissionContract.Template(root.Operation))
        {
            ProjectTemplateCondition[]? templateConditions = root.Action == GroupPermissionAction.AssignRole ?
                [new(RoleConditionField.GroupName, ProjectTemplateStringClause.Compare(included: names)),
                    new(RoleConditionField.AssignableRole, ProjectTemplateStringClause.Literal(plan.Role))] : null;
            var configuration = new ProjectTemplateConfiguration(
                [new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.Groups, action, conditions: templateConditions)])],
                ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
                users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(plan.ActorKey(0)), [plan.Slug])]));
            return await SendAsync(env, root, create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: configuration) :
                ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: configuration), token);
        }
        ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Groups, action, conditions: conditions)];
        if (root.ActorKind == MemberPermissionActorKind.User)
        {
            var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
            return await SendAsync(env, root, create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(GroupPermissionPlan.Project), change) :
                RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(GroupPermissionPlan.Project), issued.Id(plan.PolicyKey), change), token);
        }
        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Id(GroupPermissionPlan.Project), plan.ProjectSlug,
            issued.Actors[0].Principal, issued.Id(plan.ActorMembership(0)));
        var privilege = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
        return await SendAsync(env, root, create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, privilege) :
            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.Id(plan.PolicyKey), privilege), token);
    }
    internal static async ValueTask<GroupPermissionReceipt> SendAsync<T>(NativeEnvironment env, GroupPermissionRoot root,
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
                GroupPermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
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
    internal static async ValueTask ActivateAsync(NativeEnvironment env, GroupPermissionRoot root, GroupPermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome != GroupPermissionOutcome.Applied) return;
        var p = trial.Plan; var v = trial.Issued;
        if (GroupPermissionContract.Template(root.Operation))
            trial.Activated(await SendAsync(env, root, ProjectOperations.CreateProject(root.Organization, p.CopySlug, p.CopySlug,
                template: p.Slug, createDefaultEnvironments: false), token, true));
        else if (root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal))
            trial.Activated(await SendAsync(env, root, ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization,
                v.Id(GroupPermissionPlan.Project), v.Id(p.ActorMembership(0)), [new(p.Slug)]), token, true));
        else if (root.Operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal))
            trial.Activated(await SendAsync(env, root, OrganizationMembershipOperations.UpdateOrganizationMembership(root.Organization,
                v.Id(p.ActorMembership(0)), role: p.Slug), token, true));
    }
}
internal static class GroupPermissionClient
{
    internal static MemberPermissionTokens Tokens(NativeEnvironment env, GroupPermissionRoot root, GroupPermissionActor actor) =>
        actor.Owned ? new(actor.Credential) : new(env.Tokens(actor.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime :
            actor.Principal == root.Authorities.Denied ? NativeIdentityRole.Denied : throw new NativeCaseFailureException("missing-input")));
    internal static string Method(GroupPermissionAction action) => action switch
    {
        GroupPermissionAction.Read => "GET",
        GroupPermissionAction.Create or GroupPermissionAction.AddMembers or GroupPermissionAction.AddIdentities => "POST",
        GroupPermissionAction.Delete or GroupPermissionAction.RemoveMembers or GroupPermissionAction.RemoveIdentities => "DELETE",
        _ => "PATCH"
    };
    internal static string Path(GroupPermissionRoot root, GroupPermissionPlan plan, GroupPermissionIssued issued, GroupPermissionRow row) =>
        root.ScopeProfile == GroupPermissionScope.Project ? "/api/v1/projects/" + issued.Id(row.Project) + "/memberships/groups/" + issued.Id(row.Group) :
        "/api/v1/groups" + (row.Action == GroupPermissionAction.Create ? "" : "/" + issued.Id(row.Group)) + (row.Action switch
        {
            GroupPermissionAction.AddMembers or GroupPermissionAction.RemoveMembers => "/users/" + Uri.EscapeDataString(plan.Username(row.User)),
            GroupPermissionAction.AddIdentities or GroupPermissionAction.RemoveIdentities => "/machine-identities/" + issued.Id(row.Identity),
            _ => ""
        });
    internal static async ValueTask<GroupPermissionAttempt> ExecuteAsync(NativeEnvironment env, GroupPermissionRoot root,
        GroupPermissionPlan plan, GroupPermissionIssued issued, GroupPermissionRow row, CancellationToken token)
    {
        using var tokens = Tokens(env, root, issued.Actors[row.Actor]); var client = env.CreateManagementClient();
        string org = issued.Id(row.Organization), project = issued.Id(row.Project), group = issued.Id(row.Group), membership = issued.Id(row.Membership);
        string role = row.Control == "role" ? "admin" : plan.Role;
        if (root.ScopeProfile == GroupPermissionScope.Project)
        {
            if (row.Action == GroupPermissionAction.AssignRole)
            {
                using var request = MembershipOperations.UpdateProjectGroupRoles(org, project, group, membership, [new(role)]);
                var result = await Send(request);
                return new(row, tokens.Hash, result.Outcome.Status, result.Receipt?.Evidence, group, membership, "", "",
                    result.Outcome.IsSuccess ? result.Outcome.Value.Items.Single().Role : "", !result.Outcome.IsSuccess || result.Outcome.Value.IsComplete);
            }
            using var change = row.Action switch
            {
                GroupPermissionAction.Read => MembershipOperations.GetProjectGroup(org, project, group),
                GroupPermissionAction.Create => MembershipOperations.AddProjectGroup(org, project, group, new MembershipRoleSelection(role: "no-access")),
                GroupPermissionAction.Delete => MembershipOperations.RemoveProjectGroup(org, project, group),
                _ => throw new NativeCaseFailureException("observer-unavailable")
            };
            var changed = await Send(change);
            return new(row, tokens.Hash, changed.Outcome.Status, changed.Receipt?.Evidence, changed.Outcome.IsSuccess ? changed.Outcome.Value.PrincipalId : "",
                changed.Outcome.IsSuccess ? changed.Outcome.Value.Id : "", "", changed.Outcome.IsSuccess ? changed.Outcome.Value.Group?.Name.Value ?? "" : "", "", true);
        }
        if (row.Action is GroupPermissionAction.AddMembers or GroupPermissionAction.RemoveMembers)
        {
            using var request = row.Action == GroupPermissionAction.AddMembers ? ScopedAccessOperations.AddGroupUser(org, group, plan.Username(row.User)) :
                ScopedAccessOperations.RemoveGroupUser(org, group, plan.Username(row.User));
            var result = await Send(request);
            return new(row, tokens.Hash, result.Outcome.Status, result.Receipt?.Evidence, group, "",
                result.Outcome.IsSuccess ? result.Outcome.Value.Id : "", result.Outcome.IsSuccess ? result.Outcome.Value.Username : "", "", true);
        }
        if (row.Action is GroupPermissionAction.AddIdentities or GroupPermissionAction.RemoveIdentities)
        {
            using var request = row.Action == GroupPermissionAction.AddIdentities ? ScopedAccessOperations.AddGroupIdentity(org, group, issued.Id(row.Identity)) :
                ScopedAccessOperations.RemoveGroupIdentity(org, group, issued.Id(row.Identity));
            var result = await Send(request);
            return new(row, tokens.Hash, result.Outcome.Status, result.Receipt?.Evidence, group,
                result.Outcome.IsSuccess ? result.Outcome.Value.Id : "", "", "", "", true);
        }
        using var native = row.Action switch
        {
            GroupPermissionAction.Read => ScopedAccessOperations.GetGroup(org, group),
            GroupPermissionAction.Create => ScopedAccessOperations.CreateGroup(org, row.Name, row.Name, "no-access"),
            GroupPermissionAction.Edit => ScopedAccessOperations.UpdateGroup(org, group, name: row.Name + "-edited"),
            GroupPermissionAction.GrantPrivileges => ScopedAccessOperations.UpdateGroup(org, group, role: role),
            GroupPermissionAction.Delete => ScopedAccessOperations.DeleteGroup(org, group),
            _ => throw new NativeCaseFailureException("observer-unavailable")
        };
        var response = await Send(native);
        return new(row, tokens.Hash, response.Outcome.Status, response.Receipt?.Evidence,
            response.Outcome.IsSuccess ? response.Outcome.Value.Id : "", "", "", response.Outcome.IsSuccess ? response.Outcome.Value.Name : "", "", true);
        async ValueTask<(SecretOutcome<T> Outcome, ManagementReceipt? Receipt)> Send<T>(ManagementRequest<T> request) where T : notnull
        {
            var authority = new ManagementAuthority(client.Authority, tokens, org, root.ScopeProfile == GroupPermissionScope.Project ? project : null);
            var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
            return (await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token), receipt);
        }
    }
}
