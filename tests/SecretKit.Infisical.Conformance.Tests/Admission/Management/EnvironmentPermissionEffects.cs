using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent integration: optional IEnvironmentPermissionSource in registrars/observers;
// source selection before unavailable gate, generic resolution to configured action.
internal static class EnvironmentPermissionEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext context, IEnvironmentPermissionSource? source, CancellationToken token)
    {
        var input = EnvironmentPermissionInput.FromScope(context.Input);
        if (!EnvironmentPermissionContract.Owns(context.Definition) || input is null ||
            context.Variant != EnvironmentPermissionContract.Variant(input.Action) || EnvironmentPermissionContract.Gate(input.ScopeProfile, input.Action) is not null)
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalEnvironmentPermissionSource(new(input.Observer), input.Observer.Identity);
        var root = new EnvironmentPermissionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            context.Environment.Origin.AbsoluteUri, context.OrganizationId, context.Definition.Key.Operation, context.Variant,
            context.Definition.Key.Case, context.Definition.Key.Scope, source.Identity, source.Kind, input.ScopeProfile, input.ActorKind,
            input.Action, new(context.Required("setupIdentityId"), context.Required("runtimeIdentityId"), context.Required("deniedIdentityId"),
                context.Required("administrativeIdentityId"), context.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await EnvironmentPermissionTrial.OpenAsync(source, root, capability,
            t => context.Cleanup(async _ => { await t.DisposeAsync(); return true; }), token);
        await WitnessAsync(context.Environment, root, trial, false, token);
        await trial.ArmAsync(token);
        await trial.SettleAsync(await DispatchAsync(context.Environment, root, trial.Plan, trial.Issued, token), token);
        if (trial.Outcome == EnvironmentPermissionOutcome.Partial) { context.Probe.Effect(NativeObservation.Unavailable); return; }
        await ActivateAsync(context.Environment, root, trial, token);
        await WitnessAsync(context.Environment, root, trial, true, token);
        context.Probe.Effect(NativeObservation.Matched);
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, EnvironmentPermissionRoot root, EnvironmentPermissionTrial trial, bool after, CancellationToken token)
    {
        await trial.BeginAsync(after, token); var attempts = new List<EnvironmentPermissionAttempt>();
        foreach (var row in trial.Rows(after)) attempts.Add(await EnvironmentPermissionClient.ExecuteAsync(env, root, trial.Plan, trial.Issued, row, token));
        await trial.ObserveAsync(after, attempts.ToArray(), token);
        await EnvironmentPermissionClient.InventoryAsync(env, root, trial.Issued, trial.States, token);
    }
    internal static string OriginalPath(EnvironmentPermissionRoot root, EnvironmentPermissionPlan plan, EnvironmentPermissionIssued issued) =>
        (EnvironmentPermissionContract.Template(root.Operation) ? "/api/v1/project-templates" : root.ActorKind == MemberPermissionActorKind.Machine ? "/api/v2/identity-project-additional-privilege" :
            "/api/v1/projects/" + issued.Id(EnvironmentPermissionPlan.Project) + "/roles") +
        (EnvironmentPermissionContract.Create(root.Operation) ? "" : "/" + issued.Id(plan.PolicyKey));
    internal static async ValueTask<EnvironmentPermissionReceipt> DispatchAsync(NativeEnvironment env, EnvironmentPermissionRoot root,
        EnvironmentPermissionPlan plan, EnvironmentPermissionIssued issued, CancellationToken token)
    {
        bool create = EnvironmentPermissionContract.Create(root.Operation);
        var action = Enum.Parse<ProjectRoleAction>(root.Action.ToString());
        if (EnvironmentPermissionContract.Template(root.Operation))
        {
            var configuration = new ProjectTemplateConfiguration(
                [new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.Environments, action)])],
                ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1.5)]),
                users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(plan.ActorKey(0)), [plan.Slug])]));
            return await SendAsync(env, root, create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: configuration) :
                ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: configuration), token);
        }
        ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Environments, action)];
        if (root.ActorKind == MemberPermissionActorKind.User)
        {
            var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
            return await SendAsync(env, root, create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(EnvironmentPermissionPlan.Project), change) :
                RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(EnvironmentPermissionPlan.Project), issued.Id(plan.PolicyKey), change), token);
        }
        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Id(EnvironmentPermissionPlan.Project), plan.ProjectSlug,
            issued.Actors[0].Principal, issued.Id(plan.ActorMembership(0)));
        var privilege = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
        return await SendAsync(env, root, create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, privilege) :
            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.Id(plan.PolicyKey), privilege), token);
    }
    internal static async ValueTask<EnvironmentPermissionReceipt> SendAsync<T>(NativeEnvironment env, EnvironmentPermissionRoot root,
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
                EnvironmentPermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
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
    internal static async ValueTask ActivateAsync(NativeEnvironment env, EnvironmentPermissionRoot root, EnvironmentPermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome != EnvironmentPermissionOutcome.Applied) return;
        var p = trial.Plan; var v = trial.Issued;
        if (EnvironmentPermissionContract.Template(root.Operation))
            trial.Activated(await SendAsync(env, root, ProjectOperations.CreateProject(root.Organization, p.CopySlug, p.CopySlug,
                template: p.Slug, createDefaultEnvironments: false), token, true));
        else if (root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal))
            trial.Activated(await SendAsync(env, root, ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization,
                v.Id(EnvironmentPermissionPlan.Project), v.Id(p.ActorMembership(0)), [new(p.Slug)]), token, true));
    }
}
internal static class EnvironmentPermissionClient
{
    internal static string Method(EnvironmentPermissionAction action) => action switch
    { EnvironmentPermissionAction.Read => "GET", EnvironmentPermissionAction.Create => "POST", EnvironmentPermissionAction.Edit => "PATCH", _ => "DELETE" };
    internal static string Path(EnvironmentPermissionRoot root, EnvironmentPermissionPlan plan, EnvironmentPermissionIssued issued, EnvironmentPermissionRow row) =>
        "/api/v1/projects/" + issued.Id(row.Project) + "/environments" +
        (row.Action == EnvironmentPermissionAction.Create ? "" : "/" + issued.Id(row.Target)) +
        (row.Action == EnvironmentPermissionAction.Delete ? "?hardDelete=true" : "");
    internal static ManagementRequest<ProjectEnvironment> Request(EnvironmentPermissionRoot root, EnvironmentPermissionIssued issued, EnvironmentPermissionRow row)
    {
        string org = issued.Id(row.Organization), project = issued.Id(row.Project), id = issued.Id(row.Target);
        return row.Action switch
        {
            EnvironmentPermissionAction.Read => ProjectOperations.GetEnvironment(org, project, id),
            EnvironmentPermissionAction.Create => ProjectOperations.CreateEnvironment(org, project, row.Name, row.Slug, 1.5),
            EnvironmentPermissionAction.Edit => ProjectOperations.UpdateEnvironment(org, project, id, row.Name + "-edited", row.Slug + "-v2", 2.75),
            _ => ProjectOperations.DeleteEnvironment(org, project, id, permanently: true)
        };
    }
    internal static async ValueTask<EnvironmentPermissionAttempt> ExecuteAsync(NativeEnvironment env, EnvironmentPermissionRoot root,
        EnvironmentPermissionPlan plan, EnvironmentPermissionIssued issued, EnvironmentPermissionRow row, CancellationToken token)
    {
        var actor = issued.Actors[row.Actor];
        using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) :
            new MemberPermissionTokens(env.Tokens(actor.Principal == root.Authorities.Denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime));
        var client = env.CreateManagementClient(); using var request = Request(root, issued, row);
        var authority = new ManagementAuthority(client.Authority, tokens, issued.Id(row.Organization), request.Target.ProjectId);
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token);
        return new(row, tokens.Hash, result.Status, receipt?.Evidence,
            result.IsSuccess ? plan.Snapshot(row, issued, result.Value, row.Action == EnvironmentPermissionAction.Edit ? 2 : 1) : null, true);
    }
    internal static async ValueTask InventoryAsync(NativeEnvironment env, EnvironmentPermissionRoot root, EnvironmentPermissionIssued issued,
        IEnumerable<EnvironmentPermissionState> expected, CancellationToken token)
    {
        var all = expected.ToArray();
        foreach (string project in new[] { EnvironmentPermissionPlan.Project, EnvironmentPermissionPlan.OtherProject, EnvironmentPermissionPlan.CopyProject }.Select(issued.Id).Where(p => p.Length != 0))
        {
            var client = env.CreateManagementClient(); using var request = ProjectOperations.GetProject(root.Organization, project);
            var authority = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization, project);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), cancellationToken: token);
            EnvironmentPermissionContract.Require(result.IsSuccess && result.Value.Environments.IsPresent && result.Value.DeletedEnvironments.IsPresent, "effect-mismatch");
            var persisted = all.Where(s => s.Project == project).ToArray();
            EnvironmentPermissionContract.Require(result.Value.Environments.Value.Select(e => e.Id).Order().SequenceEqual(persisted.Where(s => !s.Deleted).Select(s => s.Target).Order()) &&
                result.Value.DeletedEnvironments.Value.Select(e => e.Id).Order().SequenceEqual(persisted.Where(s => s.Deleted).Select(s => s.Target).Order()), "effect-mismatch");
            foreach (var reference in result.Value.DeletedEnvironments.Value)
            {
                var state = persisted.Single(s => s.Target == reference.Id);
                EnvironmentPermissionContract.Require(reference.Name == state.Name && reference.Slug == state.Slug &&
                    reference.SoftDeletedAt == state.SoftDeletedAt && reference.DeleteAfter == state.DeleteAfter &&
                    reference.DeletedBy is { Type: ProjectDeletedByType.Identity } by && "identity:" + by.Id == state.DeletedBy, "effect-mismatch");
            }
            foreach (var reference in result.Value.Environments.Value)
            {
                var state = persisted.Single(s => s.Target == reference.Id);
                EnvironmentPermissionContract.Require(reference.Name == state.Name && reference.Slug == state.Slug, "effect-mismatch");
                using var get = ProjectOperations.GetEnvironmentBySlug(root.Organization, project, state.Slug);
                var fetched = await client.ExecuteAsync(get, authority, authority.IssueGrant(get.OperationId, get.Target), cancellationToken: token);
                EnvironmentPermissionContract.Require(fetched.IsSuccess && fetched.Value.Id == state.Target && fetched.Value.Name == state.Name && fetched.Value.Slug == state.Slug &&
                    fetched.Value.Position == state.Position && fetched.Value.SoftDeletedAtField.IsPresent && fetched.Value.SoftDeletedAtField.IsNull &&
                    fetched.Value.DeleteAfterField.IsPresent && fetched.Value.DeleteAfterField.IsNull && fetched.Value.DeletedByUserId.IsPresent && fetched.Value.DeletedByUserId.IsNull &&
                    fetched.Value.DeletedByIdentityId.IsPresent && fetched.Value.DeletedByIdentityId.IsNull, "effect-mismatch");
            }
        }
    }
}
