using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Run this class BEFORE EffectTests. It drives public SDK methods directly,
// without TagPermissionEffects.Dispatch/Witness/Activate or the effect client.
public sealed class InfisicalTagPermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        InfisicalTagPermissionGateTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectSdkCalibratesAllActionsAndOriginalBoundaries(string operation, string variant, string boundary)
    {
        await using var fixture = new InfisicalTagPermissionFixture();
        var action = InfisicalTagPermissionGateTests.Action(operation, variant);
        using var env = fixture.Environment(action);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var root = fixture.Root(operation, action, boundary);
        TagPermissionTrial? retained = null;
        using var capability = SecretMaterial.FromText("tag-capability");
        try
        {
            var trial = await TagPermissionTrial.OpenAsync(fixture.Source.CreateClient(), root, capability,
                t => retained = t, timeout.Token);
            await Witness(false);
            await trial.ArmAsync(timeout.Token);
            var issued = trial.Issued;
            bool create = operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
            ProjectRoleAction sdkAction = action switch
            {
                TagPermissionAction.Read => ProjectRoleAction.Read,
                TagPermissionAction.Create => ProjectRoleAction.Create,
                TagPermissionAction.Edit => ProjectRoleAction.Edit,
                TagPermissionAction.Delete => ProjectRoleAction.Delete,
                _ => throw new NativeCaseFailureException("missing-input")
            };
            TagPermissionReceipt original;
            if (operation.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal))
            {
                var configuration = new ProjectTemplateConfiguration(
                    [new(issued.PolicySlug, issued.PolicySlug, [new(ProjectRoleSubject.Tags, sdkAction)])],
                    ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
                    identities: ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues([new(root.Authorities.Runtime, [issued.PolicySlug])]));
                original = await Original(() => create ?
                    ProjectTemplateOperations.CreateProjectTemplate(root.Organization, issued.PolicySlug, configuration: configuration) :
                    ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.TemplateId, configuration: configuration));
            }
            else
            {
                ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Tags, sdkAction)];
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
            bool applied = boundary is not ("denied-authority" or "cancellation-boundary");
            await Assert.That(trial.Outcome).IsEqualTo(applied ? TagPermissionOutcome.Applied : TagPermissionOutcome.NonApplied);
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

            async ValueTask<TagPermissionReceipt> Original<T>(Func<ManagementRequest<T>> factory) where T : notnull
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
                var attempts = new List<TagPermissionAttempt>();
                foreach (var row in trial.Rows(after))
                {
                    var role = row.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime :
                        row.Principal == root.Authorities.Setup ? NativeIdentityRole.Setup :
                        row.Principal == root.Authorities.Administrative ? NativeIdentityRole.Administrative :
                        row.Principal == root.Authorities.Denied ? NativeIdentityRole.Denied : NativeIdentityRole.Observer;
                    var tokens = new TagPermissionTokens(env.Tokens(role));
                    await using var client = new InfisicalClient(env.Origin, tokens,
                        new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
                    var target = new SecretReference(client.Authority, new InfisicalTagAddress(row.Project, row.List ? null :
                        row.Action == TagPermissionAction.Create ? row.TagSlug : row.Id.ToString(),
                        row.Action == TagPermissionAction.Create ? InfisicalOrganizationSelector.Slug : InfisicalOrganizationSelector.Id));
                    var selected = new TagPermissionTokens(env.Tokens(role));
                    var authority = new InfisicalNativeAuthority(client.Authority, selected, row.Project);
                    MutationReceipt? receipt = row.Action == TagPermissionAction.Read ? null : new(target);
                    SecretStatus status; TagPermissionValue[] values = []; bool complete = true;
                    // Direct public SDK calls; neither TagPermissionClient nor effect helpers are used.
                    TagPermissionValue Copy(InfisicalTag value) => new(Guid.Parse(value.Id),
                        value.ProjectId, value.Name ?? "", value.Slug, value.Color ?? "");
                    if (row.List)
                    {
                        var result = await client.ListTagsAsync(target, cancellationToken: timeout.Token);
                        status = result.Status;
                        if (result.IsSuccess) { values = result.Value.Items.Select(Copy).ToArray(); complete = result.Value.IsComplete; }
                    }
                    else
                    {
                        var result = row.Action switch
                        {
                            TagPermissionAction.Read => await client.GetTagAsync(target, timeout.Token),
                            TagPermissionAction.Create => await client.CreateTagAsync(target, "#A1B2C3", authority, receipt!, timeout.Token),
                            TagPermissionAction.Edit => await client.UpdateTagAsync(target, row.TagSlug + "-changed", "#A1B2C3", authority, receipt!, timeout.Token),
                            TagPermissionAction.Delete => await client.DeleteTagAsync(target, authority, receipt!, cancellationToken: timeout.Token),
                            _ => throw new NativeCaseFailureException("missing-input")
                        };
                        status = result.Status;
                        if (result.IsSuccess) values = [Copy(result.Value)];
                    }
                    attempts.Add(new(row, row.Action == TagPermissionAction.Read ? tokens.Hash : selected.Hash,
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
