using System.Net;
using System.Text.Json;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureRoleFixtureProvisionerTests
{
    [Test]
    public async Task NativeAsyncPurgeRequiresExplicitStatusSettlementBeforeAbsenceCanRelease()
    {
        using var fixture = new Fixture(allowPurge: true);
        var plan = fixture.Plan();
        await fixture.Source.ProvisionAsync(plan, Material);
        fixture.State.AsyncPurge = true;
        var pending = await fixture.Source.ReleaseAsync("owner", fixture.Selector, purge: true);
        await Assert.That(pending.State).IsEqualTo(RoleFixtureProvisioner.State.Pending);
        await Assert.That(fixture.Read().Released).IsFalse();
        var running = await fixture.Source.SettleAsync(plan);
        await Assert.That(running.State).IsEqualTo(RoleFixtureProvisioner.State.Pending);
        fixture.State.PurgeState = "Succeeded";
        var terminal = await fixture.Source.SettleAsync(plan);
        await Assert.That(terminal.State).IsEqualTo(RoleFixtureProvisioner.State.Ready);
        var released = await fixture.Source.ReleaseAsync("owner", fixture.Selector);
        await Assert.That(released.State).IsEqualTo(RoleFixtureProvisioner.State.Released);
        await Assert.That(fixture.Backends[0].Requests.Count(r => r.Method == HttpMethod.Post)).IsEqualTo(1);
        await Assert.That(plan.Receipts.Single(r => r.Action == RoleFixtureProvisioner.Action.PurgeVault).RemoteSettled).IsTrue();
    }

    [Test]
    public async Task ForeignNativeStatusLinkCannotAcquireCredentialsOrSettleCleanup()
    {
        using var fixture = new Fixture(allowPurge: true);
        var plan = fixture.Plan();
        await fixture.Source.ProvisionAsync(plan, Material);
        fixture.State.AsyncPurge = true;
        fixture.State.PurgeStatusOrigin = "https://foreign.invalid";
        var result = await fixture.Source.ReleaseAsync("owner", fixture.Selector, purge: true);
        await Assert.That(result.State).IsEqualTo(RoleFixtureProvisioner.State.Pending);
        await Assert.That(fixture.Read().Released).IsFalse();
        await Assert.That(fixture.Backends.SelectMany(b => b.Requests)
            .Any(r => r.Path.Contains("/operationResults/", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task ExplicitPurgeHasSeparateDurableAttemptAndIndependentAbsence()
    {
        using var fixture = new Fixture(allowPurge: true);
        var plan = fixture.Plan();
        await fixture.Source.ProvisionAsync(plan, Material);
        var result = await fixture.Source.ReleaseAsync("owner", fixture.Selector, purge: true);
        await Assert.That(result.State).IsEqualTo(RoleFixtureProvisioner.State.Released);
        await Assert.That(fixture.Read().Released).IsTrue();
        var purge = fixture.Read().Resources.Single(r => r.CleanupOnly);
        await Assert.That(purge.CreateAttempted).IsFalse();
        await Assert.That(purge.DeleteAttempted).IsTrue();
        await Assert.That(purge.ActiveDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(fixture.State.BeforeSendPersisted).IsTrue();
        await Assert.That(fixture.State.DeletedVaultExists).IsFalse();
        await Assert.That(fixture.State.VaultExists).IsFalse();
        await Assert.That(fixture.State.Secret).IsNull();
        await Assert.That(result.Receipts.Single(r => r.Action == RoleFixtureProvisioner.Action.PurgeVault).Terminated).IsTrue();
        int writes = fixture.WriteCount;
        await fixture.Reopen().ReleaseAsync("owner", fixture.Selector, purge: true);
        await Assert.That(fixture.WriteCount).IsEqualTo(writes);
    }

    [Test]
    [Arguments("denied")]
    [Arguments("no-op")]
    [Arguments("lost")]
    public async Task PurgeUncertaintyNeverReplaysNativeMutation(string fault)
    {
        using var fixture = new Fixture(allowPurge: true);
        var plan = fixture.Plan();
        await fixture.Source.ProvisionAsync(plan, Material);
        fixture.State.PurgeFault = fault;
        var result = await fixture.Source.ReleaseAsync("owner", fixture.Selector, purge: true);
        await Assert.That(result.State).IsEqualTo(fault == "lost"
            ? RoleFixtureProvisioner.State.Pending : RoleFixtureProvisioner.State.SoftDeleted);
        await Assert.That(fixture.Read().Released).IsFalse();
        int writes = fixture.WriteCount;
        await fixture.Reopen().ReleaseAsync("owner", fixture.Selector, purge: true);
        await Assert.That(fixture.WriteCount).IsEqualTo(writes);
        await Assert.That(fixture.Backends[0].Requests.Count(r => r.Method == HttpMethod.Post)).IsEqualTo(1);
        await Assert.That(fixture.Read().Resources.Single(r => r.CleanupOnly).DeleteAttempted).IsTrue();
    }

    [Test]
    public async Task PurgeRequiresBothHostOptInAndExplicitInvocation()
    {
        using var fixture = new Fixture();
        fixture.Plan();
        await Assert.That(async () => await fixture.Source.ReleaseAsync("owner", fixture.Selector, purge: true))
            .Throws<InvalidOperationException>();
        await Assert.That(fixture.WriteCount).IsEqualTo(0);
        using var optedIn = new Fixture(allowPurge: true);
        var plan = optedIn.Plan();
        await optedIn.Source.ProvisionAsync(plan, Material);
        await optedIn.Source.ReleaseAsync("owner", optedIn.Selector);
        await Assert.That(optedIn.State.DeletedVaultExists).IsTrue();
        await Assert.That(optedIn.Read().Resources.Single(r => r.CleanupOnly).DeleteAttempted).IsFalse();
    }

    [Test]
    public async Task ForeignDeletedVaultIdentityCannotBePurged()
    {
        using var fixture = new Fixture(allowPurge: true);
        var plan = fixture.Plan();
        await fixture.Source.ProvisionAsync(plan, Material);
        fixture.State.ForeignDeleted = true;
        var result = await fixture.Source.ReleaseAsync("owner", fixture.Selector, purge: true);
        await Assert.That(result.State).IsEqualTo(RoleFixtureProvisioner.State.Uncertain);
        await Assert.That(fixture.Backends[0].Requests.Any(r => r.Method == HttpMethod.Post)).IsFalse();
        await Assert.That(fixture.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("denied")]
    [Arguments("no-op")]
    [Arguments("lost")]
    public async Task DeleteFailuresRemainObservableWithoutReplay(string fault)
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        await fixture.Source.ProvisionAsync(plan, Material);
        fixture.State.DeleteFault = fault;
        var result = await fixture.Source.ReleaseAsync("owner", fixture.Selector);
        await Assert.That(result.State).IsNotEqualTo(RoleFixtureProvisioner.State.Released);
        await Assert.That(fixture.Read().Released).IsFalse();
        await Assert.That(fixture.Read().Resources.Single(r => r.Id == plan.VaultId).DeleteAttempted).IsTrue();
        int writes = fixture.WriteCount;
        await fixture.Reopen().ReleaseAsync("owner", fixture.Selector);
        await Assert.That(fixture.WriteCount).IsEqualTo(writes);
    }

    [Test]
    public async Task CancellationDoesNotEraseActiveInvocationBeforeActualTermination()
    {
        using var fixture = new Fixture();
        fixture.State.Applied = new(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.State.Terminate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var plan = fixture.Plan();
        using var cancellation = new CancellationTokenSource();
        Task<RoleFixtureProvisioner.Result> provision = fixture.Source.ProvisionAsync(plan, Material, cancellation.Token).AsTask();
        await fixture.State.Applied.Task.WaitAsync(TimeSpan.FromSeconds(10));
        try
        {
            cancellation.Cancel();
            var snapshot = fixture.Read();
            await Assert.That(snapshot.Resources.Single(r => r.Id == plan.VaultId).ActiveDispatch).IsNotEqualTo(Guid.Empty);
            var release = await fixture.Reopen().ReleaseAsync("owner", fixture.Selector);
            await Assert.That(release.State).IsEqualTo(RoleFixtureProvisioner.State.Pending);
            await Assert.That(fixture.Backends[0].Requests.Any(r => r.Method == HttpMethod.Delete)).IsFalse();
        }
        finally { fixture.State.Terminate.TrySetResult(); }
        await Assert.That(async () => await provision).Throws<OperationCanceledException>();
        await Assert.That(fixture.Read().Resources.Single(r => r.Id == plan.VaultId).ActiveDispatch).IsNotEqualTo(Guid.Empty);
        await Assert.That(plan.Receipts.Single().Terminated).IsTrue();
        var stillPending = await fixture.Reopen().ReleaseAsync("owner", fixture.Selector);
        await Assert.That(stillPending.State).IsEqualTo(RoleFixtureProvisioner.State.Pending);
        await Assert.That(fixture.State.VaultExists).IsTrue();
    }

    [Test]
    public async Task RestartedUnresolvedDispatchIsNotAssumedTerminated()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        Guid active = fixture.Journal.BeginDispatch("owner", fixture.Selector, plan.VaultId, false);
        var result = await fixture.Reopen().ReleaseAsync("owner", fixture.Selector);
        await Assert.That(result.State).IsEqualTo(RoleFixtureProvisioner.State.Pending);
        await Assert.That(fixture.Read().Resources.Single(r => r.Id == plan.VaultId).ActiveDispatch).IsEqualTo(active);
        await Assert.That(fixture.Backends.SelectMany(b => b.Requests).Any()).IsFalse();
    }

    [Test]
    public async Task AlreadyCanceledSetupNeverDispatchesAndCanStillBeReleased()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.That(async () => await fixture.Source.ProvisionAsync(plan, Material, cancellation.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(fixture.Read().Resources.All(r => !r.CreateAttempted)).IsTrue();
        var result = await fixture.Source.ReleaseAsync("owner", fixture.Selector);
        await Assert.That(result.State).IsEqualTo(RoleFixtureProvisioner.State.Released);
        await Assert.That(fixture.WriteCount).IsEqualTo(0);
    }

    [Test]
    public async Task IndependentObservationFailureCannotAcknowledgeCleanup()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        await fixture.Source.ProvisionAsync(plan, Material);
        fixture.State.ObservationDenied = true;
        var result = await fixture.Source.ReleaseAsync("owner", fixture.Selector);
        await Assert.That(result.State).IsEqualTo(RoleFixtureProvisioner.State.Uncertain);
        await Assert.That(fixture.Read().Released).IsFalse();
        await Assert.That(fixture.Read().Resources.All(r => !r.Absent)).IsTrue();
    }

    [Test]
    public async Task OversizedResponseStopsBeforeMutationAndHostsRemainOwned()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        fixture.State.Oversized = true;
        var result = await fixture.Source.ProvisionAsync(plan, Material);
        await Assert.That(result.State).IsEqualTo(RoleFixtureProvisioner.State.Uncertain);
        await Assert.That(fixture.WriteCount).IsEqualTo(0);
        await Assert.That(fixture.Backends.All(b => !b.Disposed)).IsTrue();
        await Assert.That(fixture.Credentials.All(c => !c.Disposed)).IsTrue();
    }

    [Test]
    public async Task SummariesAndDefaultSerializationContainNoMaterialOrCoordinates()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        var result = await fixture.Source.ProvisionAsync(plan, Material);
        string output = string.Join("|", fixture.Source, plan, result, plan.Receipts[0],
            JsonSerializer.Serialize(plan), JsonSerializer.Serialize(result), JsonSerializer.Serialize(plan.Receipts),
            JsonSerializer.Serialize(new RoleFixtureProvisioner.BorrowedSelectors(GroupAssignment, SubscriptionAssignment, [OtherDefinition])));
        await Assert.That(output.Contains(Material, StringComparison.Ordinal)).IsFalse();
        await Assert.That(output.Contains(Subscription.ToString(), StringComparison.Ordinal)).IsFalse();
        await Assert.That(output.Contains(plan.VaultName, StringComparison.Ordinal)).IsFalse();
        await Assert.That(result.CanaryVersion).IsEqualTo("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        await Assert.That(fixture.Backends.All(b => !b.Disposed)).IsTrue();
        await Assert.That(fixture.Credentials.All(c => !c.Disposed)).IsTrue();
    }
}
