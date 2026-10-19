using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent integration owns optional source forwarding and generic configured-action resolution.
internal static class ProjectTemplatePermissionEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext context, IProjectTemplatePermissionSource? source, CancellationToken token)
    {
        var input = ProjectTemplatePermissionInput.FromScope(context.Input);
        if (!ProjectTemplatePermissionContract.Owns(context.Definition) || input is null || context.Variant != ProjectTemplatePermissionContract.Variant(input.Action))
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalProjectTemplatePermissionSource(new(input.Observer), input.Observer.Identity);
        var root = new ProjectTemplatePermissionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), context.Environment.Origin.AbsoluteUri,
            context.OrganizationId, context.Definition.Key.Operation, context.Variant, context.Definition.Key.Case, context.Definition.Key.Scope,
            source.Identity, source.Kind, input.ScopeProfile, input.ActorKind, input.Action,
            new(context.Required("setupIdentityId"), context.Required("runtimeIdentityId"), context.Required("deniedIdentityId"),
                context.Required("administrativeIdentityId"), context.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await ProjectTemplatePermissionTrial.OpenAsync(source, root, capability,
            t => context.Cleanup(async _ => { await t.DisposeAsync(); return true; }), token);
        await WitnessAsync(context.Environment, root, trial, false, token); await trial.ArmAsync(token);
        await trial.SettleAsync(await DispatchAsync(context.Environment, root, trial.Plan, trial.Issued, token), token);
        if (trial.Outcome == ProjectTemplatePermissionOutcome.Partial) { context.Probe.Effect(NativeObservation.Unavailable); return; }
        await ActivateAsync(context.Environment, root, trial, token);
        await WitnessAsync(context.Environment, root, trial, true, token); context.Probe.Effect(NativeObservation.Matched);
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, ProjectTemplatePermissionRoot root, ProjectTemplatePermissionTrial trial, bool after, CancellationToken token)
    {
        await trial.BeginAsync(after, token); var attempts = new List<ProjectTemplatePermissionAttempt>();
        foreach (var row in trial.Rows(after)) attempts.Add(await ProjectTemplatePermissionClient.ExecuteAsync(env, root, trial.Plan, trial.Issued, row, token));
        await trial.ObserveAsync(after, attempts.ToArray(), token);
    }
    internal static string OriginalPath(ProjectTemplatePermissionRoot root, ProjectTemplatePermissionPlan plan, ProjectTemplatePermissionIssued issued) =>
        "/api/v1/organization/roles" + (ProjectTemplatePermissionContract.Create(root.Operation) ? "" : "/" + issued.Id(plan.PolicyKey));
    internal static async ValueTask<ProjectTemplatePermissionReceipt> DispatchAsync(NativeEnvironment env, ProjectTemplatePermissionRoot root,
        ProjectTemplatePermissionPlan plan, ProjectTemplatePermissionIssued issued, CancellationToken token)
    {
        var change = new OrganizationRoleChange(plan.Slug, plan.Slug,
            permissions: [new(OrganizationRoleSubject.ProjectTemplates, Enum.Parse<OrganizationRoleAction>(root.Action.ToString()))]);
        return await SendAsync(env, root, ProjectTemplatePermissionContract.Create(root.Operation) ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
            RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.Id(plan.PolicyKey), change), token);
    }
    internal static async ValueTask<ProjectTemplatePermissionReceipt> SendAsync<T>(NativeEnvironment env, ProjectTemplatePermissionRoot root,
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
                ProjectTemplatePermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
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
    internal static async ValueTask ActivateAsync(NativeEnvironment env, ProjectTemplatePermissionRoot root, ProjectTemplatePermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome == ProjectTemplatePermissionOutcome.Applied && ProjectTemplatePermissionContract.Create(root.Operation))
            trial.Activated(await SendAsync(env, root, OrganizationMembershipOperations.UpdateOrganizationMembership(root.Organization,
                trial.Issued.Id(trial.Plan.ActorMembership(0)), role: trial.Plan.Slug), token, true));
    }
}
internal static class ProjectTemplatePermissionClient
{
    internal static string Method(ProjectTemplatePermissionAction action) => action switch
    { ProjectTemplatePermissionAction.Read => "GET", ProjectTemplatePermissionAction.Create => "POST", ProjectTemplatePermissionAction.Edit => "PATCH", _ => "DELETE" };
    internal static string Path(ProjectTemplatePermissionIssued issued, ProjectTemplatePermissionRow row) =>
        "/api/v1/project-templates" + (row.Action == ProjectTemplatePermissionAction.Create ? "" : "/" + issued.Id(row.Template));
    internal static async ValueTask<ProjectTemplatePermissionAttempt> ExecuteAsync(NativeEnvironment env, ProjectTemplatePermissionRoot root,
        ProjectTemplatePermissionPlan plan, ProjectTemplatePermissionIssued issued, ProjectTemplatePermissionRow row, CancellationToken token)
    {
        var actor = issued.Actors[row.Actor];
        using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) : new MemberPermissionTokens(env.Tokens(NativeIdentityRole.Runtime));
        var client = env.CreateManagementClient(); string org = issued.Id(row.Organization), id = issued.Id(row.Template);
        using var request = row.Action switch
        {
            ProjectTemplatePermissionAction.Read => ProjectTemplateOperations.GetProjectTemplate(org, id),
            ProjectTemplatePermissionAction.Create => ProjectTemplateOperations.CreateProjectTemplate(org, row.Name, ProjectTemplateType.SecretManager, "closed-v1", plan.NativeConfiguration(1)),
            ProjectTemplatePermissionAction.Edit => ProjectTemplateOperations.UpdateProjectTemplate(org, id, row.Name + "-edited", "closed-v2", plan.NativeConfiguration(2)),
            _ => ProjectTemplateOperations.DeleteProjectTemplate(org, id)
        };
        var authority = new ManagementAuthority(client.Authority, tokens, org); var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token);
        return new(row, tokens.Hash, result.Status, receipt?.Evidence, result.IsSuccess ? plan.Snapshot(row, result.Value,
            row.Action == ProjectTemplatePermissionAction.Edit ? 2 : 1) : null, true);
    }
}
