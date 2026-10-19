using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalProjectTypeCalibrationTests
{
    public static IEnumerable<(string Variant, string Boundary)> Cases()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        // Artifacts-isolated runs provide the same checkout path explicitly.
        root = System.Environment.GetEnvironmentVariable("SECRETKIT_PROJECT_TYPE_CHECKOUT") ?? root;
        using var inventory = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        var operation = inventory.RootElement.GetProperty("operations").EnumerateArray()
            .Single(o => o.GetProperty("id").GetString() == ProjectTypeContract.Operation);
        foreach (var variant in operation.GetProperty("variants").EnumerateArray())
            foreach (var boundary in operation.GetProperty("requiredCases").EnumerateArray())
                yield return (variant.GetString()!, boundary.GetString()!);
    }
    internal static NativeCaseDefinition Definition(string variant, string boundary) =>
        new(new("Infisical", ProjectTypeContract.Operation, variant, "local", boundary),
            InfisicalProjectFamilies.Bindings[ProjectTypeContract.Operation].Member);
    internal static ProjectTypeInput Input() => new(new(new("https://project-source.invalid/"),
        "source-capability-token", "controlled-project-type-source", 15),
        "private-project-type-capability", "controlled-deployment", "controlled-epoch", "controlled-project-v1", 15);
    internal static object Families() => new Dictionary<string, object>
    {
        ["C08-IM-Projects"] = Scope(),
        ["C08-IM-ManagementClient"] = Scope()
    };
    private static object Scope() => new
    {
        scopes = new
        {
            local = new
            {
                organizationId = InfisicalProjectTypeFixture.Org,
                setupIdentityId = InfisicalProjectTypeFixture.Authorities.Setup,
                runtimeIdentityId = InfisicalProjectTypeFixture.Authorities.Runtime,
                deniedIdentityId = InfisicalProjectTypeFixture.Authorities.Denied,
                administrativeIdentityId = InfisicalProjectTypeFixture.Authorities.Administrative,
                observerIdentityId = InfisicalProjectTypeFixture.Authorities.Observer,
                projectType = Input()
            }
        }
    };
    internal static ProjectTypeRoot Root(NativeEnvironment env, string variant, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), env.Origin.AbsoluteUri,
            InfisicalProjectTypeFixture.Org, ProjectTypeContract.Operation, variant, boundary, "local",
            "controlled-project-v1", "controlled-deployment", "controlled-epoch", "controlled-project-type-source",
            ProjectTypeSourceKind.ControlledFixture, InfisicalProjectTypeFixture.Authorities, ProjectTypeContract.Query(variant));

    [Test]
    public async Task RetainedInventoryHasTenVariantsAndFortyReadOnlyCases()
    {
        var cases = Cases().ToArray();
        await Assert.That(cases.Length).IsEqualTo(40);
        await Assert.That(cases.Select(c => c.Variant).Distinct().Count()).IsEqualTo(10);
        await Assert.That(cases.Any(c => c.Boundary == "lost-response-no-replay")).IsFalse();
        await Assert.That(cases.Select(c => c.Variant).Distinct().Order().SequenceEqual(ProjectTypeContract.Variants.Order())).IsTrue();
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectSdkCalibratesTypedInventoryBeforeEffects(string variant, string boundary)
    {
        await using var provider = new InfisicalProjectTypeFixture();
        using var env = provider.Environment(Families());
        await DirectAsync(provider, env, variant, boundary);
        await Assert.That(provider.Source.Opens).IsEqualTo(1);
        await Assert.That(provider.Source.Observations).IsEqualTo(2);
        await Assert.That(provider.RequestJournal.Count).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await Assert.That(provider.IssuanceJournal.Count).IsEqualTo(24);
        await Assert.That(provider.CleanupJournal.Count).IsEqualTo(24);
        await Assert.That(provider.StorageJournal.Count).IsEqualTo(2);
        await Assert.That(provider.AccessJournal.Count).IsEqualTo(10);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.Source.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }

    internal static async Task DirectAsync(InfisicalProjectTypeFixture provider, NativeEnvironment env,
        string variant, string boundary)
    {
        var root = Root(env, variant, boundary);
        ProjectTypeTrial? retained = null;
        using var capability = SecretMaterial.FromText("private-project-type-capability");
        try
        {
            var trial = await ProjectTypeTrial.OpenAsync(provider.Source.CreateClient(), root, capability, 15,
                t => retained = t, CancellationToken.None);
            await Witness("before");
            await trial.ArmAsync(CancellationToken.None);
            // Direct SDK factory arguments are calibrated independently of the
            // effect dispatcher. The provider parses literal wire vocabulary.
            ProjectType? selectedType = variant switch
            {
                "type.omitted" => null,
                "type.CertificateManager" => ProjectType.CertificateManager,
                "type.Kms" => ProjectType.Kms,
                "type.SecretScanning" => ProjectType.SecretScanning,
                "type.Pam" => ProjectType.Pam,
                "type.AgentVault" => ProjectType.AgentVault,
                _ => ProjectType.SecretManager
            };
            bool? roles = variant == "includeRoles.omitted" ? null : variant == "includeRoles.true";
            using var request = ProjectOperations.ListProjects(root.OrganizationId, selectedType, roles);
            var client = env.CreateManagementClient();
            var role = boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
            bool presend = boundary == "cancellation-boundary";
            var barrier = presend ? new ProjectTokenBarrier(env.Tokens(role)) : null;
            using var cancellation = new CancellationTokenSource();
            var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), root.OrganizationId);
            Task? entered = barrier?.Entered;
            var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                cancellationToken: cancellation.Token).AsTask();
            SecretOutcome<ManagementPage<ProjectSummary>>? outcome = null;
            bool cancelled = false;
            try
            {
                if (entered is not null)
                {
                    await entered.WaitAsync(TimeSpan.FromSeconds(15));
                    cancellation.Cancel(); barrier!.Release();
                }
                try { outcome = await execution; }
                catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { cancelled = true; }
                await Assert.That(!request.IsMutation && cancelled == presend &&
                    (presend || (boundary == "denied-authority" ? outcome?.Status == SecretStatus.Denied :
                        outcome is { IsSuccess: true } result && trial.OriginalPage(result.Value)))).IsTrue();
                await trial.SettleAsync(new(outcome?.Status, cancelled), CancellationToken.None);
            }
            finally
            {
                cancellation.Cancel(); barrier?.Release();
                try { await execution; }
                catch (OperationCanceledException) { }
            }
            await Witness("after");

            async Task Witness(string phase)
            {
                await trial.BeginAsync(phase, CancellationToken.None);
                var access = new List<ProjectTypeAccess>();
                var all = await Read(NativeIdentityRole.Observer, new(null, true), true);
                var selected = await Read(NativeIdentityRole.Observer, root.Query, true);
                var runtime = await Read(NativeIdentityRole.Runtime, root.Query, true);
                _ = await Read(NativeIdentityRole.Denied, root.Query, false);
                var recheck = await Read(NativeIdentityRole.Observer, root.Query, true);
                await trial.ObserveAsync(phase, all!, [selected!, runtime!, recheck!], access.ToArray(), CancellationToken.None);
                async Task<ManagementPage<ProjectSummary>?> Read(NativeIdentityRole role, ProjectTypeQuery query, bool allowed)
                {
                    using var transport = new ManagementTransport(env.Origin, allowLoopbackDevelopmentHttp: true);
                    var fresh = new ManagementClient(transport);
                    var auth = env.CreateManagementAuthority(fresh, role, root.OrganizationId);
                    using var list = ProjectOperations.ListProjects(root.OrganizationId, query.Type, query.IncludeRoles);
                    var result = await fresh.ExecuteAsync(list, auth, auth.IssueGrant(list.OperationId, list.Target));
                    await Assert.That(allowed ? result.IsSuccess && result.Value.IsComplete : result.Status == SecretStatus.Denied).IsTrue();
                    string actor = role switch
                    {
                        NativeIdentityRole.Observer => root.Authorities.Observer,
                        NativeIdentityRole.Runtime => root.Authorities.Runtime,
                        _ => root.Authorities.Denied
                    };
                    access.Add(new("", actor, root.OrganizationId, query, allowed));
                    return result.IsSuccess ? result.Value : null;
                }
            }
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
    }
}
