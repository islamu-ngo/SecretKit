using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Run this class BEFORE EffectTests. It drives public SDK methods directly,
// without ImportPermissionEffects.Dispatch/Witness/Activate or the effect client.
public sealed class InfisicalImportPermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        InfisicalImportPermissionGateTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectSdkCalibratesAllActionsAndOriginalBoundaries(string operation, string variant, string boundary)
    {
        await using var fixture = new InfisicalImportPermissionFixture();
        var action = InfisicalImportPermissionGateTests.Action(operation, variant);
        using var env = fixture.Environment(action);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var root = fixture.Root(operation, action, boundary);
        ImportPermissionTrial? retained = null;
        using var capability = SecretMaterial.FromText("import-capability");
        try
        {
            var trial = await ImportPermissionTrial.OpenAsync(fixture.Source.CreateClient(), root, capability,
                t => retained = t, timeout.Token);
            await Witness(false);
            await trial.ArmAsync(timeout.Token);
            var issued = trial.Issued;
            bool create = operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
            ProjectRoleAction sdkAction = action switch
            {
                ImportPermissionAction.Read => ProjectRoleAction.Read,
                ImportPermissionAction.Create => ProjectRoleAction.Create,
                ImportPermissionAction.Edit => ProjectRoleAction.Edit,
                ImportPermissionAction.Delete => ProjectRoleAction.Delete,
                _ => throw new NativeCaseFailureException("missing-input")
            };
            ImportPermissionReceipt original;
            if (operation.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal))
            {
                var configuration = new ProjectTemplateConfiguration(
                    [new(issued.PolicySlug, issued.PolicySlug, [new(ProjectRoleSubject.SecretImports, sdkAction,
                        conditions: [new(RoleConditionField.Environment, ProjectTemplateStringClause.Literal("witness")),
                            new(RoleConditionField.SecretPath, ProjectTemplateStringClause.Literal("/"))])])],
                    ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
                    identities: ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues([new(root.Authorities.Runtime, [issued.PolicySlug])]));
                original = await Original(() => create ?
                    ProjectTemplateOperations.CreateProjectTemplate(root.Organization, issued.PolicySlug, configuration: configuration) :
                    ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.TemplateId, configuration: configuration));
            }
            else
            {
                ProjectRolePermission[] permissions = [new(ProjectRoleSubject.SecretImports, sdkAction,
                    conditions: [new(RoleConditionField.Environment, RoleStringClause.Literal("witness")),
                        new(RoleConditionField.SecretPath, RoleStringClause.Literal("/"))])];
                if (operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal))
                {
                    var change = new ProjectRoleChange(issued.PolicySlug, issued.PolicySlug, permissions: permissions);
                    original = await Original(() => create ?
                        RoleChangeOperations.CreateProjectRole(root.Organization, issued.Project, change) :
                        RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Project, issued.PolicyId, change));
                }
                else
                {
                    var selection = new LegacyPrivilegeSelection(root.Organization, issued.Project, issued.Slug,
                        root.Authorities.Runtime, issued.Membership);
                    var change = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), issued.PolicySlug);
                    original = await Original(() => create ?
                        IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, change) :
                        IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.PolicyId, change));
                }
            }
            await trial.SettleAsync(original, timeout.Token);
            await Assert.That(ReferenceEquals(trial.Original, original)).IsTrue();
            bool applied = boundary is not ("denied-authority" or "cancellation-boundary");
            await Assert.That(trial.Outcome).IsEqualTo(applied ? ImportPermissionOutcome.Applied : ImportPermissionOutcome.NonApplied);
            if (applied && operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal))
            {
                var client = env.CreateManagementClient();
                using var request = MembershipOperations.UpdateProjectIdentityRoles(root.Organization, issued.Project,
                    root.Authorities.Runtime, [new(issued.PolicySlug)]);
                var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization, issued.Project);
                var receipt = client.CreateReceipt(request);
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                    receipt, timeout.Token);
                await Assert.That(result.IsSuccess).IsTrue();
                trial.Activated(new(receipt, result.Status, false, request.Target.SecondaryId ?? ""));
            }
            if (applied && operation.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal))
            {
                var client = env.CreateManagementClient();
                using var request = ProjectOperations.CreateProject(root.Organization, issued.CopySlug, issued.CopySlug,
                    template: issued.PolicySlug, createDefaultEnvironments: false);
                var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization);
                var receipt = client.CreateReceipt(request);
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                    receipt, timeout.Token);
                await Assert.That(result.IsSuccess && result.Value.Id == issued.CopyProject).IsTrue();
                trial.Activated(new(receipt, result.Status, false, request.Target.SecondaryId ?? ""));
            }
            await Witness(true);
            await Assert.That(original.Native.Evidence).IsEqualTo(original.Evidence);

            async ValueTask<ImportPermissionReceipt> Original<T>(Func<ManagementRequest<T>> factory) where T : notnull
            {
                var client = env.CreateManagementClient();
                using var request = factory();
                var receipt = client.CreateReceipt(request);
                var role = boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
                var barrier = boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(role)) : null;
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
                var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), root.Organization,
                    request.Target.ProjectId);
                using var loss = boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancellation) : null;
                using var scope = loss?.Enter();
                Task? entered = barrier?.Entered;
                var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                    receipt, cancellation.Token).AsTask();
                SecretOutcome<T>? result = null; bool cancelled = false;
                try
                {
                    if (entered is not null) { await entered.WaitAsync(timeout.Token); cancellation.Cancel(); barrier!.Release(); }
                    try { result = await execution; }
                    catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !timeout.IsCancellationRequested)
                    { cancelled = true; }
                    await Assert.That(loss is null || loss.Reached).IsTrue();
                    return new(receipt, result?.Status, cancelled, request.Target.SecondaryId ?? "");
                }
                finally
                {
                    cancellation.Cancel(); barrier?.Release();
                    try { result ??= await execution; } catch (OperationCanceledException) { }
                    if (result is { IsSuccess: true } completed && completed.Value is IDisposable owned) owned.Dispose();
                }
            }
            async Task Witness(bool after)
            {
                await trial.BeginAsync(after, timeout.Token);
                var attempts = new List<ImportPermissionAttempt>();
                foreach (var row in trial.Rows(after))
                {
                    var role = row.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime :
                        row.Principal == root.Authorities.Setup ? NativeIdentityRole.Setup :
                        row.Principal == root.Authorities.Administrative ? NativeIdentityRole.Administrative :
                        row.Principal == root.Authorities.Denied ? NativeIdentityRole.Denied : NativeIdentityRole.Observer;
                    var tokens = new ImportPermissionTokens(env.Tokens(role));
                    await using var client = new InfisicalClient(env.Origin, tokens,
                        new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
                    var target = new SecretReference(client.Authority, new InfisicalImportAddress(row.Project, row.Environment, row.Path, row.FolderId.ToString(),
                        row.List || row.Action == ImportPermissionAction.Create ? null : row.Id.ToString()));
                    var selected = new ImportPermissionTokens(env.Tokens(role));
                    var authority = new InfisicalNativeAuthority(client.Authority, selected, row.Project, row.Environment, row.Path);
                    MutationReceipt? receipt = row.Action == ImportPermissionAction.Read ? null : new(target);
                    SecretStatus status; ImportPermissionValue[] values = []; bool complete = true;
                    // Direct public SDK calls; neither ImportPermissionClient nor effect helpers are used.
                    ImportPermissionValue Copy(InfisicalImport value) => new(Guid.Parse(value.Id), Guid.Parse(value.FolderId),
                        value.SourceEnvironment, value.SourcePath, value.SourceProjectId!, value.Position, value.IsReplication,
                        value.ReplicationReportedSuccessful, value.ReplicationStatus, value.LastReplicated);
                    if (row.List)
                    {
                        var result = await client.ListImportsAsync(target, cancellationToken: timeout.Token);
                        status = result.Status;
                        if (result.IsSuccess) { values = result.Value.Items.Select(Copy).ToArray(); complete = result.Value.IsComplete; }
                    }
                    else
                    {
                        var result = row.Action switch
                        {
                            ImportPermissionAction.Read => await client.GetImportAsync(target, timeout.Token),
                            ImportPermissionAction.Create => await client.CreateImportAsync(target, new("source-b", ImportPermissionContract.SourcePath(row, true), row.Project), false, authority, receipt!, timeout.Token),
                            ImportPermissionAction.Edit => await client.UpdateImportAsync(target, authority, receipt!, "source-b", ImportPermissionContract.SourcePath(row, true), 7.5, timeout.Token),
                            ImportPermissionAction.Delete => await client.DeleteImportAsync(target, authority, receipt!, cancellationToken: timeout.Token),
                            _ => throw new NativeCaseFailureException("missing-input")
                        };
                        status = result.Status;
                        if (result.IsSuccess) values = [Copy(result.Value)];
                    }
                    attempts.Add(new(row, row.Action == ImportPermissionAction.Read ? tokens.Hash : selected.Hash,
                        null, status, receipt?.Evidence, values, complete));
                }
                await trial.ObserveAsync(after, attempts.ToArray(), timeout.Token);
            }
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await fixture.DrainAsync();
        await Assert.That(fixture.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await Assert.That(fixture.Closes).IsEqualTo(1);
        await Assert.That(fixture.Remaining).IsEqualTo(0);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
        await Assert.That(fixture.BorrowedPreserved).IsTrue();
        await Assert.That(fixture.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }
}
