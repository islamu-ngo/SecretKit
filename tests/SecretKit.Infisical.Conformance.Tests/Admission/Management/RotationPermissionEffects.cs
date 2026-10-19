using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent integration (existing files deliberately read-only):
// - Add IRotationPermissionSource? to both native family registrars and GovernanceObservers.
// - Select RotationPermissionInput.Selected BEFORE the existing unavailable gate,
//   then ExecuteAsync; do not widen unrelated subjects/metadata/default policies.
// - Generic Resolve must explicitly choose Variant(input.Action),
//   preserving the ORIGINAL factory label and all five original boundary labels.
// - No optional input means the existing unavailable reasons remain unchanged.
internal static class RotationPermissionEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext context, IRotationPermissionSource? source,
        CancellationToken token, RotationPermissionRuntime? runtime = null)
    {
        var input = RotationPermissionInput.FromScope(context.Input);
        if (input is null || !RotationPermissionContract.Supported(context.Definition, input.Profile.SqlProfile) ||
            context.Variant != RotationPermissionContract.Variant(input.Action) || runtime is null ||
            runtime.Origin.Scheme != Uri.UriSchemeHttps)
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalRotationPermissionSource(new(input.Observer), input.Observer.Identity);
        var root = new RotationPermissionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            context.Environment.Origin.AbsoluteUri, context.OrganizationId, context.Definition.Key.Operation,
            context.Variant, context.Definition.Key.Case, context.Definition.Key.Scope, source.Identity, source.Kind,
            input.Action, new(context.Required("setupIdentityId"), context.Required("runtimeIdentityId"),
                context.Required("deniedIdentityId"), context.Required("administrativeIdentityId"),
                context.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await RotationPermissionTrial.OpenAsync(source, root, capability,
            owned => context.Cleanup(async _ => { await owned.DisposeAsync(); return true; }), token);
        await WitnessAsync(context.Environment, root, trial, false, token, runtime);
        await trial.ArmAsync(token);
        await trial.SettleAsync(await DispatchAsync(context.Environment, root, trial.Issued, token), token);
        if (trial.Outcome == RotationPermissionOutcome.Partial)
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        await ActivateAsync(context.Environment, root, trial, token);
        await WitnessAsync(context.Environment, root, trial, true, token, runtime);
        context.Probe.Effect(NativeObservation.Matched);
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, RotationPermissionRoot root,
        RotationPermissionTrial trial, bool after, CancellationToken token, RotationPermissionRuntime? runtime = null)
    {
        await trial.BeginAsync(after, token);
        var attempts = new List<RotationPermissionAttempt>();
        foreach (var row in trial.Rows(after))
            attempts.Add(await RotationPermissionClient.ExecuteAsync(env, root, row, token, runtime));
        await trial.ObserveAsync(after, attempts.ToArray(), token);
    }
    internal static string OriginalPath(RotationPermissionRoot root, RotationPermissionIssued issued)
    {
        bool create = RotationPermissionContract.Create(root.Operation);
        if (RotationPermissionContract.Template(root.Operation))
            return "/api/v1/project-templates" + (create ? "" : "/" + issued.TemplateId);
        if (root.Operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal))
            return "/api/v1/projects/" + issued.Project + "/roles" + (create ? "" : "/" + issued.PolicyId);
        return "/api/v2/identity-project-additional-privilege" + (create ? "" : "/" + issued.PolicyId);
    }
    internal static async ValueTask<RotationPermissionReceipt> DispatchAsync(NativeEnvironment env,
        RotationPermissionRoot root, RotationPermissionIssued issued, CancellationToken token)
    {
        bool create = RotationPermissionContract.Create(root.Operation);
        var action = RotationPermissionContract.Sdk(root.Action);
        if (RotationPermissionContract.Template(root.Operation))
        {
            var configuration = new ProjectTemplateConfiguration(
                [new(issued.PolicySlug, issued.PolicySlug, [new(ProjectRoleSubject.SecretRotation, action, conditions: RotationPermissionContract.Conditions(issued.Connection)
                    .Select(c => new ProjectTemplateCondition(c.Field, ProjectTemplateStringClause.Literal(c.Field == RoleConditionField.Environment ? "witness" : c.Field == RoleConditionField.SecretPath ? "/owned" : issued.Connection))).ToArray())])],
                ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
                identities: ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues(
                    [new(root.Authorities.Runtime, [issued.PolicySlug])]));
            return await SendAsync(env, root, () => create ?
                ProjectTemplateOperations.CreateProjectTemplate(root.Organization, issued.PolicySlug, configuration: configuration) :
                ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.TemplateId, configuration: configuration), token);
        }
        ProjectRolePermission[] permissions = [new(ProjectRoleSubject.SecretRotation, action, conditions: RotationPermissionContract.Conditions(issued.Connection))];
        if (root.Operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal))
        {
            var change = new ProjectRoleChange(issued.PolicySlug, issued.PolicySlug, permissions: permissions);
            return await SendAsync(env, root, () => create ?
                RoleChangeOperations.CreateProjectRole(root.Organization, issued.Project, change) :
                RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Project, issued.PolicyId, change), token);
        }
        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Project, issued.Slug,
            root.Authorities.Runtime, issued.Membership);
        var privilege = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), issued.PolicySlug);
        return await SendAsync(env, root, () => create ?
            IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, privilege) :
            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.PolicyId, privilege), token);
    }
    internal static async ValueTask<RotationPermissionReceipt> SendAsync<T>(NativeEnvironment env,
        RotationPermissionRoot root, Func<ManagementRequest<T>> factory, CancellationToken token) where T : notnull
    {
        var client = env.CreateManagementClient();
        using var request = factory();
        var original = client.CreateReceipt(request);
        var role = root.Boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
        var selectedTokens = new RotationPermissionTokens(env.Tokens(role));
        var barrier = root.Boundary == "cancellation-boundary" ? new ProjectTokenBarrier(selectedTokens) : null;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        var authority = new ManagementAuthority(client.Authority, barrier ?? (IInfisicalTokenSource)selectedTokens, root.Organization,
            request.Target.ProjectId);
        using var loss = root.Boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancellation) : null;
        using var scope = loss?.Enter();
        Task? entered = barrier?.Entered; // subscribe before the sole mutation
        var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
            original, cancellation.Token).AsTask();
        SecretOutcome<T>? outcome = null; bool cancelled = false;
        try
        {
            if (entered is not null) { await entered.WaitAsync(token); cancellation.Cancel(); barrier!.Release(); }
            try { outcome = await execution; }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !token.IsCancellationRequested)
            { cancelled = true; }
            RotationPermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
            return new(original, outcome?.Status, cancelled, request.Target.SecondaryId ?? "", selectedTokens.Hash);
        }
        finally
        {
            cancellation.Cancel(); barrier?.Release();
            try { outcome ??= await execution; } catch (OperationCanceledException) { }
            if (outcome is { IsSuccess: true } result && result.Value is IDisposable owned) owned.Dispose();
        }
    }
    internal static async ValueTask ActivateAsync(NativeEnvironment env, RotationPermissionRoot root,
        RotationPermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome != RotationPermissionOutcome.Applied) return;
        var issued = trial.Issued; var client = env.CreateManagementClient();
        if (root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal))
        {
            using var request = MembershipOperations.UpdateProjectIdentityRoles(root.Organization, issued.Project,
                root.Authorities.Runtime, [new(issued.PolicySlug)]);
            var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization, issued.Project);
            var receipt = client.CreateReceipt(request);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                receipt, token);
            RotationPermissionContract.Require(result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied, "effect-mismatch");
            trial.Activated(new(receipt, result.Status, false, request.Target.SecondaryId ?? ""));
        }
        else if (RotationPermissionContract.Template(root.Operation))
        {
            using var request = ProjectOperations.CreateProject(root.Organization, issued.CopySlug, issued.CopySlug,
                template: issued.PolicySlug, createDefaultEnvironments: false);
            var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization);
            var receipt = client.CreateReceipt(request);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token);
            RotationPermissionContract.Require(result.IsSuccess && result.Value.Id == issued.CopyProject &&
                receipt.Evidence == DispatchEvidence.Applied, "effect-mismatch");
            trial.Activated(new(receipt, result.Status, false, request.Target.SecondaryId ?? ""));
        }
    }
}
