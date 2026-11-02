using System.Net;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureRoleFixtureProvisionerTests
{
    [Test]
    public async Task NativeProvisioningUsesRbacVaultAndExplicitVaultOnlyAssignment()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        var result = await fixture.Source.ProvisionAsync(plan, Material);
        await Assert.That(result.State).IsEqualTo(RoleFixtureProvisioner.State.Ready);
        await Assert.That(fixture.State.Rbac).IsTrue();
        await Assert.That(fixture.State.Principal).IsEqualTo(PrincipalId);
        await Assert.That(fixture.State.Definition).IsEqualTo(DefinitionPath);
        await Assert.That(fixture.State.AssignmentPath!.StartsWith(plan.VaultId + "/", StringComparison.Ordinal)).IsTrue();
        await Assert.That(fixture.State.Secret).IsEqualTo(Material);
        await Assert.That(plan.Receipts.Count).IsEqualTo(3);
        await Assert.That(plan.Receipts.All(r => r.Attempted && r.Terminated)).IsTrue();
        await Assert.That(plan.Receipts.All(r => r.NativeRequestId is not null)).IsTrue();
        await Assert.That(fixture.State.BeforeSendPersisted).IsTrue();
        await Assert.That(fixture.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
        await Assert.That(fixture.Backends.Where(b => b.Role.StartsWith("observe", StringComparison.Ordinal))
            .SelectMany(b => b.Requests).All(r => r.Method == HttpMethod.Get)).IsTrue();
    }

    [Test]
    public async Task PendingVaultHasSingleReadOnlyObservationAndNoSetupReplay()
    {
        using var fixture = new Fixture();
        fixture.State.VaultState = "Creating";
        var plan = fixture.Plan();
        var result = await fixture.Source.ProvisionAsync(plan, Material);
        await Assert.That(result.State).IsEqualTo(RoleFixtureProvisioner.State.Pending);
        await Assert.That(fixture.State.Secret).IsNull();
        await Assert.That(fixture.State.AssignmentPath).IsNull();
        int writes = fixture.WriteCount;
        fixture.State.VaultState = "Succeeded";
        var observed = await fixture.Source.ObserveAsync("owner", fixture.Selector);
        await Assert.That(observed.State).IsEqualTo(RoleFixtureProvisioner.State.Incomplete);
        await Assert.That(fixture.WriteCount).IsEqualTo(writes);
        await Assert.That(async () => await fixture.Source.ProvisionAsync(plan, Material))
            .Throws<InvalidOperationException>();
        var continued = await fixture.Source.ContinueAsync(plan, Material);
        await Assert.That(continued.State).IsEqualTo(RoleFixtureProvisioner.State.Ready);
        await Assert.That(fixture.Backends[0].Requests.Count(r => r.Method == HttpMethod.Put && r.Path == plan.VaultId)).IsEqualTo(1);
        int completedWrites = fixture.WriteCount;
        await fixture.Source.ContinueAsync(plan, Material);
        await Assert.That(fixture.WriteCount).IsEqualTo(completedWrites);
    }

    [Test]
    [Arguments("denied")]
    [Arguments("no-op")]
    [Arguments("lost")]
    public async Task FailedNativeSetupRetainsOwnershipWithoutReplay(string fault)
    {
        using var fixture = new Fixture();
        fixture.State.CreateFault = fault;
        var plan = fixture.Plan();
        var result = await fixture.Source.ProvisionAsync(plan, Material);
        await Assert.That(result.State).IsNotEqualTo(RoleFixtureProvisioner.State.Ready);
        await Assert.That(plan.Receipts.Single().Attempted).IsTrue();
        await Assert.That(plan.Receipts.Single().Terminated).IsTrue();
        await Assert.That(fixture.Read().Resources.Single(r => r.Id == plan.VaultId).CreateAttempted).IsTrue();
        await Assert.That(fixture.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsEqualTo(fault == "denied");
        await Assert.That(async () => await fixture.Source.ProvisionAsync(plan, Material))
            .Throws<InvalidOperationException>();
        await Assert.That(fixture.Backends[0].Requests.Count(r => r.Method == HttpMethod.Put)).IsEqualTo(1);
    }

    [Test]
    public async Task ReleaseWithoutReturnedLeasePreservesSoftDeletedVault()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        await fixture.Source.ProvisionAsync(plan, Material);
        var reopened = fixture.Reopen();
        var release = await reopened.ReleaseAsync("owner", fixture.Selector);
        await Assert.That(release.State).IsEqualTo(RoleFixtureProvisioner.State.SoftDeleted);
        await Assert.That(fixture.Read().Released).IsFalse();
        await Assert.That(fixture.State.VaultExists).IsFalse();
        await Assert.That(fixture.State.DeletedVaultExists).IsTrue();
        await Assert.That(fixture.State.AssignmentPath).IsNull();
        int writes = fixture.WriteCount;
        fixture.State.DeletedVaultExists = false; // Independent simulated retention expiry, not a source purge.
        var absent = await reopened.ReleaseAsync("owner", fixture.Selector);
        await Assert.That(absent.State).IsEqualTo(RoleFixtureProvisioner.State.Released);
        await Assert.That(fixture.Read().Released).IsTrue();
        await Assert.That(fixture.WriteCount).IsEqualTo(writes);
        await Assert.That(fixture.Backends.SelectMany(b => b.Requests).Any(r => r.Path.EndsWith("/purge", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task PartialSecretFailureDeletesOnlyAttemptedOwnedResources()
    {
        using var fixture = new Fixture();
        fixture.State.SecretDenied = true;
        var plan = fixture.Plan();
        var result = await fixture.Source.ProvisionAsync(plan, Material);
        await Assert.That(result.State).IsEqualTo(RoleFixtureProvisioner.State.Denied);
        await Assert.That(fixture.State.AssignmentPath).IsNull();
        await fixture.Source.ReleaseAsync("owner", fixture.Selector);
        await Assert.That(fixture.Backends[0].Requests.Where(r => r.Method == HttpMethod.Delete)
            .All(r => r.Path == plan.VaultId)).IsTrue();
        await Assert.That(fixture.Read().Resources.Single(r => r.Id == plan.AssignmentId).CreateAttempted).IsFalse();
    }

    [Test]
    public async Task CloseBeforePrepareTombstoneRejectsDelayedSetup()
    {
        using var fixture = new Fixture();
        var release = await fixture.Source.ReleaseAsync("owner", fixture.Selector);
        await Assert.That(release.State).IsEqualTo(RoleFixtureProvisioner.State.Released);
        await Assert.That(() => fixture.Plan()).Throws<InvalidOperationException>();
        await Assert.That(fixture.WriteCount).IsEqualTo(0);
    }

    [Test]
    public async Task BorrowedSelectionsRemainReadOnlyAndSeparatelyBound()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan(new(GroupAssignment, SubscriptionAssignment, [OtherDefinition]));
        var result = await fixture.Source.ProvisionAsync(plan, Material);
        await Assert.That(result.State).IsEqualTo(RoleFixtureProvisioner.State.Ready);
        await Assert.That(result.Borrowed.Count).IsEqualTo(4);
        var before = result.Borrowed.Select(r => (r.Id, r.Sha256)).ToArray();
        var after = await fixture.Source.ObserveAsync("owner", fixture.Selector);
        await Assert.That(after.Borrowed.Select(r => (r.Id, r.Sha256)).ToArray()).IsEquivalentTo(before);
        await fixture.Source.ReleaseAsync("owner", fixture.Selector);
        var borrowed = fixture.Read().Resources.Where(r => r.Borrowed).Select(r => r.Id).ToHashSet();
        await Assert.That(borrowed.Contains(GroupAssignmentPath)).IsTrue();
        await Assert.That(borrowed.Contains(SubscriptionAssignmentPath)).IsTrue();
        await Assert.That(fixture.Backends.SelectMany(b => b.Requests)
            .Where(r => borrowed.Contains(r.Path)).All(r => r.Method == HttpMethod.Get)).IsTrue();
    }

    private const string Material = "transient-controlled-fixture-canary";
    private static readonly Guid Subscription = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Tenant = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid PrincipalId = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly Guid DefinitionId = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly Guid GroupAssignment = Guid.Parse("55555555-5555-5555-5555-555555555555");
    private static readonly Guid SubscriptionAssignment = Guid.Parse("66666666-6666-6666-6666-666666666666");
    private static readonly Guid OtherDefinition = Guid.Parse("77777777-7777-7777-7777-777777777777");
    private static string SubscriptionPath => $"/subscriptions/{Subscription:D}";
    private static string GroupPath => SubscriptionPath + "/resourceGroups/fixture-group";
    private static string DefinitionPath => SubscriptionPath + $"/providers/Microsoft.Authorization/roleDefinitions/{DefinitionId:D}";
    private static string GroupAssignmentPath => GroupPath + $"/providers/Microsoft.Authorization/roleAssignments/{GroupAssignment:D}";
    private static string SubscriptionAssignmentPath => SubscriptionPath + $"/providers/Microsoft.Authorization/roleAssignments/{SubscriptionAssignment:D}";

    private sealed class Fixture : IDisposable
    {
        internal readonly string DirectoryPath = Path.Combine(Path.GetTempPath(), "role-provisioner-" + Guid.NewGuid().ToString("N"));
        internal FixtureSelector Selector = new(Guid.NewGuid(), "controlled", "role", "vault", "effect");
        internal readonly WireState State = new();
        internal readonly Backend[] Backends;
        internal readonly Credential[] Credentials;
        private readonly HttpClient[] clients;
        private readonly HttpClientTransport[] transports;
        internal readonly RoleFixtureJournal Journal;
        internal readonly RoleFixtureProvisioner Source;
        private readonly bool allowPurge;
        private readonly Azure.Core.Pipeline.HttpPipelineTransport? observeArmTransport;
        internal int WriteCount => Backends.SelectMany(b => b.Requests).Count(r => r.Method != HttpMethod.Get);
        internal Azure.Core.Pipeline.HttpPipelineTransport ArmObserverTransport => observeArmTransport ?? transports[2];

        internal Fixture(bool allowPurge = false, FixtureSelector? selector = null,
            Azure.Core.Pipeline.HttpPipelineTransport? observeArmTransport = null)
        {
            if (selector is not null) Selector = selector;
            this.allowPurge = allowPurge;
            this.observeArmTransport = observeArmTransport;
            Directory.CreateDirectory(DirectoryPath);
            Journal = new(DirectoryPath);
            Backends = new[] { "setup-arm", "setup-secret", "observe-arm", "observe-secret" }
                .Select(r => new Backend(r, State)).ToArray();
            Credentials = Backends.Select(b => new Credential(b.Role)).ToArray();
            clients = Backends.Select(b => new HttpClient(b)).ToArray();
            transports = clients.Select(c => new HttpClientTransport(c)).ToArray();
            State.BeforeMutation = id =>
            {
                var snapshot = Read();
                var row = snapshot.Resources.Single(r => r.Id == id);
                State.BeforeSendPersisted &= row.ActiveDispatch != Guid.Empty && (row.CreateAttempted || row.CleanupOnly);
            };
            Source = Reopen();
        }

        internal RoleFixtureProvisioner Reopen() => new(new RoleFixtureJournal(DirectoryPath),
            new(Subscription, "fixture-group", "eastus", Tenant, PrincipalId, DefinitionId, true, allowPurge),
            new("setup-arm", Credentials[0], transports[0]), new("setup-secret", Credentials[1], transports[1]),
            new("observe-arm", Credentials[2], observeArmTransport ?? transports[2]), new("observe-secret", Credentials[3], transports[3]),
            new(64 * 1024, TimeSpan.FromSeconds(10)));
        internal RoleFixtureProvisioner.Plan Plan(RoleFixtureProvisioner.BorrowedSelectors? borrowed = null) =>
            Source.PlanFixture("owner", Selector, borrowed ?? new(null, null, []), createAssignment: true);
        internal RoleFixtureJournal.Snapshot Read() => Journal.Read("owner", Selector);
        public void Dispose()
        {
            foreach (var client in clients) client.Dispose();
            Directory.Delete(DirectoryPath, true);
        }
    }

    private sealed class Credential(string role) : TokenCredential, IDisposable
    {
        internal bool Disposed;
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Disposed || context.Scopes.Length != 1 ||
                context.Scopes[0] != (role.EndsWith("arm", StringComparison.Ordinal)
                    ? "https://management.azure.com/.default" : "https://vault.azure.net/.default"))
                throw new InvalidOperationException("controlled-credential");
            return new(role, DateTimeOffset.MaxValue);
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(context, cancellationToken));
        public void Dispose() => Disposed = true;
    }
}
