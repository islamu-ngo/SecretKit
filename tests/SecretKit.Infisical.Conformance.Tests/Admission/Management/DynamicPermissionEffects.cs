using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent integration (existing files deliberately read-only):
// - Add IDynamicPermissionSource? to both native family registrars and GovernanceObservers.
// - Select DynamicPermissionInput.Selected BEFORE the existing unavailable gate,
//   then ExecuteAsync; do not widen unrelated subjects/metadata/default policies.
// - Generic Resolve must explicitly choose Variant(operation, input.Action),
//   preserving the ORIGINAL factory label and all five original boundary labels.
// - No optional input means the existing unavailable reasons remain unchanged.
internal static class DynamicPermissionEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext context, IDynamicPermissionSource? source,
        CancellationToken token)
    {
        var input = DynamicPermissionInput.FromScope(context.Input);
        if (!DynamicPermissionContract.Owns(context.Definition) || input is null ||
            context.Variant != DynamicPermissionContract.Variant(context.Definition.Key.Operation, input.Action))
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalDynamicPermissionSource(new(input.Observer), input.Observer.Identity);
        var root = new DynamicPermissionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            context.Environment.Origin.AbsoluteUri, context.OrganizationId, context.Definition.Key.Operation,
            context.Variant, context.Definition.Key.Case, context.Definition.Key.Scope, source.Identity, source.Kind,
            input.Action, new(context.Required("setupIdentityId"), context.Required("runtimeIdentityId"),
                context.Required("deniedIdentityId"), context.Required("administrativeIdentityId"),
                context.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await DynamicPermissionTrial.OpenAsync(source, root, capability,
            owned => context.Cleanup(async _ => { await owned.DisposeAsync(); return true; }), token);
        await WitnessAsync(context.Environment, root, trial, false, token);
        await trial.ArmAsync(token);
        await trial.SettleAsync(await DispatchAsync(context.Environment, root, trial.Issued, token), token);
        if (trial.Outcome == DynamicPermissionOutcome.Partial)
        { context.Probe.Effect(NativeObservation.Unavailable); return; }
        await ActivateAsync(context.Environment, root, trial, token);
        await WitnessAsync(context.Environment, root, trial, true, token);
        context.Probe.Effect(NativeObservation.Matched);
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, DynamicPermissionRoot root,
        DynamicPermissionTrial trial, bool after, CancellationToken token)
    {
        await trial.BeginAsync(after, token);
        var attempts = new List<DynamicPermissionAttempt>();
        foreach (var row in trial.Rows(after))
            attempts.Add(await DynamicPermissionClient.ExecuteAsync(env, root, trial, row, after, token));
        await trial.ObserveAsync(after, attempts.ToArray(), token);
    }
    internal static string OriginalPath(DynamicPermissionRoot root, DynamicPermissionIssued issued)
    {
        bool create = DynamicPermissionContract.Create(root.Operation);
        if (DynamicPermissionContract.Template(root.Operation))
            return "/api/v1/project-templates" + (create ? "" : "/" + issued.TemplateId);
        if (root.Operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal))
            return "/api/v1/projects/" + issued.Project + "/roles" + (create ? "" : "/" + issued.PolicyId);
        return "/api/v2/identity-project-additional-privilege" + (create ? "" : "/" + issued.PolicyId);
    }
    internal static async ValueTask<DynamicPermissionReceipt> DispatchAsync(NativeEnvironment env,
        DynamicPermissionRoot root, DynamicPermissionIssued issued, CancellationToken token)
    {
        bool create = DynamicPermissionContract.Create(root.Operation);
        var action = DynamicPermissionContract.Sdk(root.Action);
        if (DynamicPermissionContract.Template(root.Operation))
        {
            var configuration = new ProjectTemplateConfiguration(
                [new(issued.PolicySlug, issued.PolicySlug, [new(ProjectRoleSubject.DynamicSecrets, action,
                    conditions: [new(RoleConditionField.Environment, ProjectTemplateStringClause.Literal("witness")),
                        new(RoleConditionField.SecretPath, ProjectTemplateStringClause.Literal("/"))])])],
                ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
                identities: ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues(
                    [new(root.Authorities.Runtime, [issued.PolicySlug])]));
            return await SendAsync(env, root, () => create ?
                ProjectTemplateOperations.CreateProjectTemplate(root.Organization, issued.PolicySlug, configuration: configuration) :
                ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.TemplateId, configuration: configuration), token);
        }
        ProjectRolePermission[] permissions = [new(ProjectRoleSubject.DynamicSecrets, action,
            conditions: [new(RoleConditionField.Environment, RoleStringClause.Literal("witness")),
                new(RoleConditionField.SecretPath, RoleStringClause.Literal("/"))])];
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
    internal static async ValueTask<DynamicPermissionReceipt> SendAsync<T>(NativeEnvironment env,
        DynamicPermissionRoot root, Func<ManagementRequest<T>> factory, CancellationToken token) where T : notnull
    {
        var client = env.CreateManagementClient();
        using var request = factory();
        var original = client.CreateReceipt(request);
        var role = root.Boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
        var barrier = root.Boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(role)) : null;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), root.Organization,
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
            DynamicPermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
            return new(original, outcome?.Status, cancelled, request.Target.SecondaryId ?? "");
        }
        finally
        {
            cancellation.Cancel(); barrier?.Release();
            try { outcome ??= await execution; } catch (OperationCanceledException) { }
            if (outcome is { IsSuccess: true } result && result.Value is IDisposable owned) owned.Dispose();
        }
    }
    internal static async ValueTask ActivateAsync(NativeEnvironment env, DynamicPermissionRoot root,
        DynamicPermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome != DynamicPermissionOutcome.Applied) return;
        var issued = trial.Issued; var client = env.CreateManagementClient();
        if (root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal))
        {
            using var request = MembershipOperations.UpdateProjectIdentityRoles(root.Organization, issued.Project,
                root.Authorities.Runtime, [new(issued.PolicySlug)]);
            var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization, issued.Project);
            var receipt = client.CreateReceipt(request);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                receipt, token);
            DynamicPermissionContract.Require(result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied, "effect-mismatch");
            trial.Activated(new(receipt, result.Status, false, request.Target.SecondaryId ?? ""));
        }
        else if (DynamicPermissionContract.Template(root.Operation))
        {
            using var request = ProjectOperations.CreateProject(root.Organization, issued.CopySlug, issued.CopySlug,
                template: issued.PolicySlug, createDefaultEnvironments: false);
            var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization);
            var receipt = client.CreateReceipt(request);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token);
            DynamicPermissionContract.Require(result.IsSuccess && result.Value.Id == issued.CopyProject &&
                receipt.Evidence == DispatchEvidence.Applied, "effect-mismatch");
            trial.Activated(new(receipt, result.Status, false, request.Target.SecondaryId ?? ""));
        }
    }
    internal static string ActionBodyHash(DynamicPermissionIssued issued, DynamicPermissionRow row)
    {
        if (row.Action == DynamicPermissionAction.Read) return DynamicPermissionContract.RawHash([]);
        using var stream = new MemoryStream();
        try
        {
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                writer.WriteString("projectSlug", row.Slug); writer.WriteString("environmentSlug", row.Environment);
                writer.WriteString("path", row.Path);
                switch (row.Action)
                {
                    case DynamicPermissionAction.Create:
                        writer.WriteString("name", row.Name); writer.WriteString("defaultTTL", "300s"); writer.WriteString("maxTTL", "600s");
                        writer.WriteStartObject("provider"); writer.WriteString("type", "sql-database");
                        writer.WriteStartObject("inputs");
                        writer.WriteString("client", issued.Sql.Engine switch
                        {
                            NativeSqlEngine.Postgres => "postgres",
                            NativeSqlEngine.Mysql => "mysql2",
                            NativeSqlEngine.Oracle => "oracledb",
                            NativeSqlEngine.SqlServer => "mssql",
                            NativeSqlEngine.SapAse => "sap-ase",
                            NativeSqlEngine.Vertica => "vertica",
                            _ => throw new NativeCaseFailureException("missing-input")
                        });
                        writer.WriteString("host", issued.Sql.Host); writer.WriteString("username", issued.Sql.Username);
                        writer.WriteString("password", issued.Sql.Password); writer.WriteString("database", issued.Sql.Database);
                        writer.WriteString("creationStatement", issued.Sql.Creation); writer.WriteString("revocationStatement", issued.Sql.Revocation);
                        writer.WriteNumber("port", issued.Sql.Port); writer.WriteEndObject(); writer.WriteEndObject();
                        break;
                    case DynamicPermissionAction.Edit:
                        writer.WriteStartObject("data"); writer.WriteString("defaultTTL", "240s"); writer.WriteEndObject(); break;
                    case DynamicPermissionAction.Delete: writer.WriteBoolean("isForced", false); break;
                    case DynamicPermissionAction.Lease: writer.WriteString("dynamicSecretName", row.Name); break;
                }
                writer.WriteEndObject();
            }
            return DynamicPermissionContract.RawHash(stream.GetBuffer().AsSpan(0, (int)stream.Length));
        }
        finally { CryptographicOperations.ZeroMemory(stream.GetBuffer()); }
    }
}
