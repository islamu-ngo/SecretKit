using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent hooks: optional IMemberPermissionSource in both registrars and GovernanceObservers;
// select MemberPermissionInput before the existing unavailable gate. Generic Resolve
// chooses Variant(input.Action), preserving its original factory label. No input
// leaves existing gates unchanged. Do not infer scope or actor kind from "Member".
internal static class MemberPermissionEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext context, IMemberPermissionSource? source, CancellationToken token)
    {
        var input = MemberPermissionInput.FromScope(context.Input);
        if (!MemberPermissionContract.Owns(context.Definition) || input is null ||
            context.Variant != MemberPermissionContract.Variant(input.Action) ||
            MemberPermissionContract.Gate(input.ScopeProfile, input.Action) is not null)
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalMemberPermissionSource(new(input.Observer), input.Observer.Identity);
        var root = new MemberPermissionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            context.Environment.Origin.AbsoluteUri, context.OrganizationId, context.Definition.Key.Operation,
            context.Variant, context.Definition.Key.Case, context.Definition.Key.Scope, source.Identity, source.Kind,
            input.ScopeProfile, input.ActorKind, input.Action, new(context.Required("setupIdentityId"),
                context.Required("runtimeIdentityId"), context.Required("deniedIdentityId"),
                context.Required("administrativeIdentityId"), context.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await MemberPermissionTrial.OpenAsync(source, root, capability,
            owned => context.Cleanup(async _ => { await owned.DisposeAsync(); return true; }), token);
        await WitnessAsync(context.Environment, root, trial, false, token);
        await trial.ArmAsync(token);
        await trial.SettleAsync(await DispatchAsync(context.Environment, root, trial.Issued, token), token);
        if (trial.Outcome == MemberPermissionOutcome.Partial)
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        await ActivateAsync(context.Environment, root, trial, token);
        await WitnessAsync(context.Environment, root, trial, true, token);
        context.Probe.Effect(NativeObservation.Matched);
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, MemberPermissionRoot root,
        MemberPermissionTrial trial, bool after, CancellationToken token)
    {
        await trial.BeginAsync(after, token);
        var attempts = new List<MemberPermissionAttempt>();
        foreach (var row in trial.Rows(after))
            attempts.Add(await MemberPermissionClient.ExecuteAsync(env, root, trial.Issued, row, token));
        await trial.ObserveAsync(after, attempts.ToArray(), token);
    }
    internal static string OriginalPath(MemberPermissionRoot root, MemberPermissionIssued issued)
    {
        string suffix = MemberPermissionContract.Create(root.Operation) ? "" : "/" +
            (MemberPermissionContract.Template(root.Operation) ? issued.TemplateId : issued.PolicyId);
        return (MemberPermissionContract.Template(root.Operation) ? "/api/v1/project-templates" :
            root.ScopeProfile == MemberPermissionScope.Organization ? "/api/v1/organization/roles" :
            root.ActorKind == MemberPermissionActorKind.Machine ? "/api/v2/identity-project-additional-privilege" :
            "/api/v1/projects/" + issued.Project + "/roles") + suffix;
    }
    internal static async ValueTask<MemberPermissionReceipt> DispatchAsync(NativeEnvironment env,
        MemberPermissionRoot root, MemberPermissionIssued issued, CancellationToken token)
    {
        bool create = MemberPermissionContract.Create(root.Operation);
        if (root.ScopeProfile == MemberPermissionScope.Organization)
        {
            var change = new OrganizationRoleChange(issued.PolicySlug, issued.PolicySlug,
                permissions: [new(OrganizationRoleSubject.Member, MemberPermissionContract.OrganizationSdk(root.Action))]);
            return await SendAsync(env, root, create ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
                RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.PolicyId, change), token);
        }
        var emails = issued.Rows.Where(r => r.Control == "selected").Select(r => r.User.Email).ToArray();
        RoleCondition[]? conditions = root.Action == MemberPermissionAction.AssignRole ?
            [new(RoleConditionField.UserEmail, RoleStringClause.Compare(included: emails)),
                new(RoleConditionField.AssignableRole, RoleStringClause.Literal(issued.AssignedRole))] : null;
        if (MemberPermissionContract.Template(root.Operation))
        {
            var configuration = new ProjectTemplateConfiguration(
                [new(issued.PolicySlug, issued.PolicySlug, [new(ProjectRoleSubject.Member,
                    MemberPermissionContract.Sdk(root.Action), conditions: conditions?.Select(c => new ProjectTemplateCondition(c.Field,
                        c.Field == RoleConditionField.UserEmail ? ProjectTemplateStringClause.Compare(included: emails) :
                            ProjectTemplateStringClause.Literal(issued.AssignedRole))).ToArray())])],
                ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
                users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues(
                    [new(issued.Principals[0].Username, [issued.PolicySlug])]));
            return await SendAsync(env, root, create ?
                ProjectTemplateOperations.CreateProjectTemplate(root.Organization, issued.PolicySlug, configuration: configuration) :
                ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.TemplateId, configuration: configuration), token);
        }
        ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Member, MemberPermissionContract.Sdk(root.Action), conditions: conditions)];
        if (root.ActorKind == MemberPermissionActorKind.User)
        {
            var change = new ProjectRoleChange(issued.PolicySlug, issued.PolicySlug, permissions: permissions);
            return await SendAsync(env, root, create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Project, change) :
                RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Project, issued.PolicyId, change), token);
        }
        var actor = issued.Principals[0];
        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Project, issued.ProjectSlug,
            actor.Id, actor.ProjectMembership);
        var privilege = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), issued.PolicySlug);
        return await SendAsync(env, root, create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, privilege) :
            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.PolicyId, privilege), token);
    }
    internal static async ValueTask<MemberPermissionReceipt> SendAsync<T>(NativeEnvironment env, MemberPermissionRoot root,
        ManagementRequest<T> request, CancellationToken token, bool setup = false) where T : notnull
    {
        using (request)
        {
            var client = env.CreateManagementClient();
            var original = client.CreateReceipt(request);
            var role = setup ? NativeIdentityRole.Setup : root.Boundary == "denied-authority" ?
                NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
            var barrier = !setup && root.Boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(role)) : null;
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), root.Organization, request.Target.ProjectId);
            using var loss = !setup && root.Boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancellation) : null;
            using var scope = loss?.Enter();
            Task? entered = barrier?.Entered;
            var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                original, cancellation.Token).AsTask();
            SecretOutcome<T>? result = null; bool cancelled = false;
            try
            {
                if (entered is not null) { await entered.WaitAsync(token); cancellation.Cancel(); barrier!.Release(); }
                try { result = await execution; }
                catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !token.IsCancellationRequested) { cancelled = true; }
                MemberPermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
                return new(original, result?.Status, cancelled, request.Target.SecondaryId ?? "");
            }
            finally
            {
                cancellation.Cancel(); barrier?.Release();
                try { result ??= await execution; } catch (OperationCanceledException) { }
                if (result is { IsSuccess: true } completed && completed.Value is IDisposable owned) owned.Dispose();
            }
        }
    }
    internal static async ValueTask ActivateAsync(NativeEnvironment env, MemberPermissionRoot root,
        MemberPermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome != MemberPermissionOutcome.Applied) return;
        var issued = trial.Issued;
        if (MemberPermissionContract.Template(root.Operation))
            trial.Activated(await SendAsync(env, root, ProjectOperations.CreateProject(root.Organization, issued.CopySlug, issued.CopySlug,
                template: issued.PolicySlug, createDefaultEnvironments: false), token, true));
        else if (root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal))
            trial.Activated(await SendAsync(env, root, ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization,
                issued.Project, issued.Principals[0].ProjectMembership, [new(issued.PolicySlug)]), token, true));
        else if (root.Operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal))
            trial.Activated(await SendAsync(env, root, OrganizationMembershipOperations.UpdateOrganizationMembership(root.Organization,
                issued.Principals[0].OrganizationMembership, role: issued.PolicySlug), token, true));
    }
}
