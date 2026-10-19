using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent integration: optional IIdentityPermissionSource in registrars/observers;
// source selection before unavailable gate, generic resolution to configured action.
internal static class IdentityPermissionEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext context, IIdentityPermissionSource? source, CancellationToken token)
    {
        var input = IdentityPermissionInput.FromScope(context.Input);
        if (!IdentityPermissionContract.Owns(context.Definition) || input is null ||
            context.Variant != IdentityPermissionContract.Variant(input.Action) || IdentityPermissionContract.Gate(input.ScopeProfile, input.Action) is not null)
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalIdentityPermissionSource(new(input.Observer), input.Observer.Identity);
        var root = new IdentityPermissionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            context.Environment.Origin.AbsoluteUri, context.OrganizationId, context.Definition.Key.Operation, context.Variant,
            context.Definition.Key.Case, context.Definition.Key.Scope, source.Identity, source.Kind, input.ScopeProfile, input.ActorKind,
            input.Action, new(context.Required("setupIdentityId"), context.Required("runtimeIdentityId"), context.Required("deniedIdentityId"),
                context.Required("administrativeIdentityId"), context.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await IdentityPermissionTrial.OpenAsync(source, root, capability,
            t => context.Cleanup(async _ => { await t.DisposeAsync(); return true; }), token);
        await WitnessAsync(context.Environment, root, trial, false, token);
        await trial.ArmAsync(token);
        await trial.SettleAsync(await DispatchAsync(context.Environment, root, trial.Plan, trial.Issued, token), token);
        if (trial.Outcome == IdentityPermissionOutcome.Partial) { context.Probe.Effect(NativeObservation.Unavailable); return; }
        await ActivateAsync(context.Environment, root, trial, token);
        await WitnessAsync(context.Environment, root, trial, true, token);
        context.Probe.Effect(NativeObservation.Matched);
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, IdentityPermissionRoot root, IdentityPermissionTrial trial, bool after, CancellationToken token)
    {
        await trial.BeginAsync(after, token); var attempts = new List<IdentityPermissionAttempt>();
        foreach (var row in trial.Rows(after)) attempts.Add(await IdentityPermissionClient.ExecuteAsync(env, root, trial.Plan, trial.Issued, row, (id, material) => trial.CaptureAsync(row, id, material, token), token));
        await trial.ObserveAsync(after, attempts.ToArray(), token);
    }
    internal static string OriginalPath(IdentityPermissionRoot root, IdentityPermissionPlan plan, IdentityPermissionIssued issued) =>
        (IdentityPermissionContract.Template(root.Operation) ? "/api/v1/project-templates" : root.ScopeProfile == IdentityPermissionScope.Organization ?
            "/api/v1/organization/roles" : root.ActorKind == MemberPermissionActorKind.Machine ? "/api/v2/identity-project-additional-privilege" :
            "/api/v1/projects/" + issued.Id(IdentityPermissionPlan.Project) + "/roles") +
        (IdentityPermissionContract.Create(root.Operation) ? "" : "/" + issued.Id(plan.PolicyKey));
    internal static async ValueTask<IdentityPermissionReceipt> DispatchAsync(NativeEnvironment env, IdentityPermissionRoot root,
        IdentityPermissionPlan plan, IdentityPermissionIssued issued, CancellationToken token)
    {
        bool create = IdentityPermissionContract.Create(root.Operation);
        if (root.ScopeProfile == IdentityPermissionScope.Organization)
        {
            var change = new OrganizationRoleChange(plan.Slug, plan.Slug,
                permissions: [new(OrganizationRoleSubject.Identity, Enum.Parse<OrganizationRoleAction>(root.Action.ToString()))]);
            return await SendAsync(env, root, create ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
                RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.Id(plan.PolicyKey), change), token);
        }
        string[] names = plan.Rows.Where(r => r.Control == "selected" && r.Action == root.Action)
            .Select(r => issued.Id(r.Identity)).Where(id => id.Length > 0).ToArray();
        RoleCondition[]? conditions = root.Action == IdentityPermissionAction.AssignRole ?
            [new(RoleConditionField.IdentityId, RoleStringClause.Compare(included: names)),
                new(RoleConditionField.AssignableRole, RoleStringClause.Literal(plan.Role))] : root.Action == IdentityPermissionAction.AssignAdditionalPrivileges ?
            [new(RoleConditionField.IdentityId, RoleStringClause.Compare(included: names)),
                new(RoleConditionField.AssignableSubject, RoleStringClause.Literal("identity")),
                new(RoleConditionField.AssignableAction, RoleStringClause.Literal("read"))] : null;
        var action = Enum.Parse<ProjectRoleAction>(root.Action.ToString());
        if (IdentityPermissionContract.Template(root.Operation))
        {
            ProjectTemplateCondition[]? templateConditions = root.Action == IdentityPermissionAction.AssignRole ?
                [new(RoleConditionField.IdentityId, ProjectTemplateStringClause.Compare(included: names)),
                    new(RoleConditionField.AssignableRole, ProjectTemplateStringClause.Literal(plan.Role))] : root.Action == IdentityPermissionAction.AssignAdditionalPrivileges ?
                [new(RoleConditionField.IdentityId, ProjectTemplateStringClause.Compare(included: names)),
                    new(RoleConditionField.AssignableSubject, ProjectTemplateStringClause.Literal("identity")),
                    new(RoleConditionField.AssignableAction, ProjectTemplateStringClause.Literal("read"))] : null;
            var configuration = new ProjectTemplateConfiguration(
                [new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.Identity, action, conditions: templateConditions)])],
                ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
                users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(plan.ActorKey(0)), [plan.Slug])]));
            return await SendAsync(env, root, create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: configuration) :
                ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: configuration), token);
        }
        ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Identity, action, conditions: conditions)];
        if (root.ActorKind == MemberPermissionActorKind.User)
        {
            var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
            return await SendAsync(env, root, create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(IdentityPermissionPlan.Project), change) :
                RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(IdentityPermissionPlan.Project), issued.Id(plan.PolicyKey), change), token);
        }
        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Id(IdentityPermissionPlan.Project), plan.ProjectSlug,
            issued.Actors[0].Principal, issued.Id(plan.ActorMembership(0)));
        var privilege = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
        return await SendAsync(env, root, create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, privilege) :
            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.Id(plan.PolicyKey), privilege), token);
    }
    internal static async ValueTask<IdentityPermissionReceipt> SendAsync<T>(NativeEnvironment env, IdentityPermissionRoot root,
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
                IdentityPermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
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
    internal static async ValueTask ActivateAsync(NativeEnvironment env, IdentityPermissionRoot root, IdentityPermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome != IdentityPermissionOutcome.Applied) return;
        var p = trial.Plan; var v = trial.Issued;
        if (IdentityPermissionContract.Template(root.Operation))
            trial.Activated(await SendAsync(env, root, ProjectOperations.CreateProject(root.Organization, p.CopySlug, p.CopySlug,
                template: p.Slug, createDefaultEnvironments: false), token, true));
        else if (root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal))
            trial.Activated(await SendAsync(env, root, ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization,
                v.Id(IdentityPermissionPlan.Project), v.Id(p.ActorMembership(0)), [new(p.Slug)]), token, true));
        else if (root.Operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal))
            trial.Activated(await SendAsync(env, root, OrganizationMembershipOperations.UpdateOrganizationMembership(root.Organization,
                v.Id(p.ActorMembership(0)), role: p.Slug), token, true));
    }
}
