using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalMetadataPermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        InfisicalMetadataPermissionGateTests.Cases();

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectSdkCalibratesIndependentSourceBeforeEffects(string operation, string variant, string boundary)
    {
        await using var fixture = new InfisicalMetadataPermissionFixture();
        using var env = fixture.Environment();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var root = fixture.Root(operation, variant, boundary);
        MetadataPermissionTrial? retained = null;
        using var capability = SecretMaterial.FromText("metadata-capability");
        try
        {
            var trial = await MetadataPermissionTrial.OpenAsync(fixture.Source.CreateClient(), root, capability,
                t => retained = t, timeout.Token);
            await DirectWitness(false);
            await trial.ArmAsync(timeout.Token);
            bool create = operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
            var issued = trial.Issued;
            MetadataPermissionReceipt receipt;
            var metadata = new RoleMetadataMatch(RoleStringClause.Compare(equal: "team"), RoleStringClause.Compare(equal: "blue"));
            ProjectRolePermission[] permissions = [new(ProjectRoleSubject.DynamicSecrets, ProjectRoleAction.Lease,
                conditions: [new(RoleConditionField.Environment, RoleStringClause.Literal("witness")),
                    new(RoleConditionField.SecretPath, RoleStringClause.Literal("/"))], metadata: metadata)];
            if (operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal))
            {
                var change = new ProjectRoleChange(issued.PolicySlug, issued.PolicySlug, permissions: permissions);
                receipt = await Original(() => create ?
                    RoleChangeOperations.CreateProjectRole(root.Organization, issued.Project, change) :
                    RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Project, issued.PolicyId, change));
            }
            else if (operation.Contains(".IdentityPrivilegeChangeOperations.", StringComparison.Ordinal))
            {
                var selection = new LegacyPrivilegeSelection(root.Organization, issued.Project, issued.ProjectSlug,
                    root.Authorities.Runtime, issued.Membership);
                var change = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), issued.PolicySlug);
                receipt = await Original(() => create ?
                    IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, change) :
                    IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.PolicyId, change));
            }
            else
            {
                var configuration = new ProjectTemplateConfiguration(
                    [new(issued.PolicySlug, issued.PolicySlug,
                        [new(ProjectRoleSubject.DynamicSecrets, ProjectRoleAction.Lease,
                            conditions: [new(RoleConditionField.Environment, ProjectTemplateStringClause.Literal("witness")),
                                new(RoleConditionField.SecretPath, ProjectTemplateStringClause.Literal("/"))],
                            metadata: new(ProjectTemplateStringClause.Compare(equal: "team"),
                                ProjectTemplateStringClause.Compare(equal: "blue"))),
                         new(ProjectRoleSubject.DynamicSecrets, ProjectRoleAction.ReadRootCredential)])],
                    ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
                    identities: ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues([new(root.Authorities.Runtime, [issued.PolicySlug])]));
                receipt = await Original(() => create ?
                    ProjectTemplateOperations.CreateProjectTemplate(root.Organization, issued.PolicySlug, configuration: configuration) :
                    ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.TemplateId, configuration: configuration));
            }
            await Assert.That(receipt.Evidence).IsEqualTo(boundary == "cancellation-boundary" ? DispatchEvidence.NotDispatched :
                boundary == "lost-response-no-replay" ? DispatchEvidence.PossiblyDispatched :
                boundary == "denied-authority" ? DispatchEvidence.Rejected : DispatchEvidence.Applied);
            await trial.SettleAsync(receipt, timeout.Token);
            bool applied = boundary is not ("denied-authority" or "cancellation-boundary");
            await Assert.That(trial.Outcome).IsEqualTo(applied ? MetadataPermissionOutcome.Applied : MetadataPermissionOutcome.NonApplied);
            if (operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal) && applied)
            {
                var client = env.CreateManagementClient();
                using var request = MembershipOperations.UpdateProjectIdentityRoles(root.Organization, issued.Project,
                    root.Authorities.Runtime, [new(issued.PolicySlug)]);
                var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization, issued.Project);
                var original = client.CreateReceipt(request);
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                    original, timeout.Token);
                await Assert.That(result.IsSuccess && original.Evidence == DispatchEvidence.Applied).IsTrue();
                trial.Activated(new(original.Evidence, result.Status, false, request.Target.SecondaryId ?? ""));
            }
            if (operation.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal) && applied)
            {
                var client = env.CreateManagementClient();
                using var request = ProjectOperations.CreateProject(root.Organization, issued.CopySlug, issued.CopySlug,
                    createDefaultEnvironments: false, template: issued.PolicySlug);
                var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization);
                var original = client.CreateReceipt(request);
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                    original, timeout.Token);
                await Assert.That(result.IsSuccess && result.Value.Id == issued.CopyRows[0].Project &&
                    original.Evidence == DispatchEvidence.Applied).IsTrue();
                trial.Activated(new(original.Evidence, result.Status, false, request.Target.SecondaryId ?? ""));
            }
            await DirectWitness(true);

            async ValueTask<MetadataPermissionReceipt> Original<T>(Func<ManagementRequest<T>> factory) where T : notnull
            {
                var client = env.CreateManagementClient();
                using var request = factory();
                var original = client.CreateReceipt(request);
                var role = boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
                var barrier = boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(role)) : null;
                using var cancel = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
                var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), root.Organization,
                    request.Target.ProjectId);
                using var loss = boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancel) : null;
                using var scope = loss?.Enter();
                Task? entered = barrier?.Entered;
                var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                    original, cancel.Token).AsTask();
                SecretOutcome<T>? result = null;
                bool cancelled = false;
                try
                {
                    if (entered is not null) { await entered.WaitAsync(timeout.Token); cancel.Cancel(); barrier!.Release(); }
                    try { result = await execution; }
                    catch (OperationCanceledException) when (!timeout.IsCancellationRequested) { cancelled = true; }
                    await Assert.That(loss is null || loss.Reached).IsTrue();
                    return new(original.Evidence, result?.Status, cancelled, request.Target.SecondaryId ?? "");
                }
                finally
                {
                    cancel.Cancel(); barrier?.Release();
                    try { result ??= await execution; } catch (OperationCanceledException) { }
                    if (result is { IsSuccess: true } owned && owned.Value is IDisposable disposable) disposable.Dispose();
                }
            }
            async Task DirectWitness(bool after)
            {
                await trial.BeginAsync(after, timeout.Token);
                var attempts = new List<MetadataPermissionAttempt>();
                bool applied = after && boundary is not ("denied-authority" or "cancellation-boundary");
                var rows = applied && operation.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal) ?
                    trial.Issued.CopyRows : trial.Issued.Rows;
                foreach (var role in new[] { NativeIdentityRole.Runtime, NativeIdentityRole.Denied, NativeIdentityRole.Observer })
                {
                    var actor = role == NativeIdentityRole.Runtime ? root.Authorities.Runtime :
                        role == NativeIdentityRole.Denied ? root.Authorities.Denied : root.Authorities.Observer;
                    var tokenResult = await env.Tokens(role).GetTokenAsync(timeout.Token);
                    using var access = tokenResult.Value;
                    string tokenHash = MetadataPermissionContract.Hash(access.Material.Reveal());
                    foreach (var row in rows)
                    {
                        bool allowed = role == NativeIdentityRole.Observer || role == NativeIdentityRole.Runtime &&
                            applied && row.Name == "same-entry";
                        await using var client = new InfisicalDynamicClient(env.Origin, env.Tokens(role),
                            new(row.ProjectSlug, row.Environment, row.Path, row.Folder),
                            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
                        var target = client.Definition(row.Name);
                        var definition = await client.InspectDefinitionAsync(target, timeout.Token);
                        await Assert.That(definition.IsSuccess && definition.Value.Id == row.Definition).IsTrue();
                        var original = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.Acquire);
                        var acquired = await client.AcquireDatabaseAsync(definition.Value, original, cancellationToken: timeout.Token);
                        using var lease = acquired.IsSuccess ? acquired.Value : null;
                        await Assert.That(allowed ? acquired.IsSuccess && original.Evidence == DispatchEvidence.Applied :
                            acquired.Status == SecretStatus.Denied && original.Evidence == DispatchEvidence.Rejected).IsTrue();
                        Guid? id = null; string? material = null;
                        if (lease is not null)
                        {
                            using var copy = lease.CopyCredentials().Value;
                            string username = copy.RevealUsername(), password = copy.RevealPassword();
                            id = lease.Reference.Id; material = MetadataPermissionContract.MaterialHash(username, password);
                            foreach (var action in Enum.GetValues<MetadataPermissionAction>())
                                await trial.MeasureAsync(id.Value, username, password, actor, row.Project, action, after, timeout.Token);
                        }
                        attempts.Add(new(actor, tokenHash, row, allowed, id, material));
                    }
                }
                await trial.ObserveAsync(after, attempts.ToArray(), timeout.Token);
            }
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await fixture.DrainAsync();
        await Assert.That(fixture.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await Assert.That(fixture.Closes).IsEqualTo(1);
        await Assert.That(fixture.Remaining).IsEqualTo(0);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
        await Assert.That(fixture.BorrowedPreserved).IsTrue();
        await Assert.That(fixture.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }
}
