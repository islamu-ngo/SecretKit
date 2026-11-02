using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments("selected-credential")]
    [Arguments("selected-send")]
    [Arguments("selected-body")]
    [Arguments("selected-sdk")]
    [Arguments("status-send")]
    [Arguments("status-body")]
    [Arguments("resource-body")]
    [Arguments("original-poll")]
    [Arguments("original-poll-body")]
    public async Task StatusDeniedVaultUpdateDisposalJoinsActualBorrowers(string barrier)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateVault,
            statusDeniedVaultUpdate: true);
        var lease = await f.PrepareAndBaseline();
        bool starting = barrier.StartsWith("selected", StringComparison.Ordinal);
        bool checking = barrier.StartsWith("original", StringComparison.Ordinal);
        ManagementOperation? handle = null;
        if (!starting) handle = (await f.Start(lease)).Value!;
        if (checking) await f.Observe(lease);
        f.Barrier = barrier;
        Task work = starting ? f.Start(lease) : checking
            ? f.Source.RunCheckStatusAsync(f.Native.Selector, handle!, default).AsTask()
            : f.Observe(lease).AsTask();
        Task? disposal = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            disposal = f.Source.DisposeAsync().AsTask();
            await Assert.That(f.Native.Read().Closing).IsTrue();
            await Assert.That(work.IsCompleted || disposal.IsCompleted).IsFalse();
            await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException or NativeCaseFailureException) { }
        await disposal!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("network")]
    [Arguments("ownership")]
    [Arguments("protection")]
    [Arguments("retention")]
    [Arguments("relationship")]
    public async Task StatusDeniedVaultUpdateCleanupRequiresFreshFullSelectedConfiguration(string fault)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateVault,
            statusDeniedVaultUpdate: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Denied);
        var vault = f.Native.Wire.Vault!;
        if (fault == "network") vault["properties"]!["publicNetworkAccess"] = "Disabled";
        if (fault == "ownership") vault["tags"]!["secretkit-fixture"] = Guid.NewGuid().ToString("N");
        if (fault == "protection") vault["properties"]!["enablePurgeProtection"] = true;
        if (fault == "retention") vault["properties"]!["softDeleteRetentionInDays"] = f.Baseline.RetentionDays + 1;
        if (fault == "relationship") vault["properties"]!["privateEndpointConnections"] = new System.Text.Json.Nodes.JsonArray(
            new System.Text.Json.Nodes.JsonObject { ["id"] = f.Plan().VaultId + "/privateEndpointConnections/foreign" });
        var release = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(release, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
    }

    [Test]
    [Arguments("missing")]
    [Arguments("epoch")]
    [Arguments("writers")]
    [Arguments("older")]
    [Arguments("reuse")]
    [Arguments("applied")]
    [Arguments("revoked")]
    public async Task StatusDeniedVaultUpdateRequiresOriginalExclusionBeforeSetup(string fault)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateVault,
            statusDeniedVaultUpdate: true);
        f.UnknownExclusion = fault != "missing";
        f.UnknownNoOlderInflight = fault != "older";
        f.UnknownNoNameReuse = fault != "reuse";
        f.UnknownNeverApplied = fault != "applied";
        if (fault == "revoked") f.UnknownContinuity.Cancel();
        await Assert.That(() => f.NewSource(notificationEpoch: fault == "epoch" ? Guid.Empty : f.UnknownEpoch,
            continuousWriterExclusion: fault != "writers")).Throws<InvalidOperationException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
        await Assert.That(f.SelectedUpdates + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedVaultUpdateLostContinuityCannotSettle(bool afterObservation)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateVault,
            statusDeniedVaultUpdate: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        if (afterObservation) await f.Observe(lease);
        f.UnknownContinuity.Cancel();
        try
        {
            if (afterObservation) await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
            else await f.Observe(lease);
        }
        catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException or NativeCaseFailureException) { }
        await f.Release();
        await Assert.That(f.Native.Read().CreateOrUpdateVault!.SettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusDeniedVaultUpdateFinalAbsenceRequiresDurableFlush()
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateVault,
            statusDeniedVaultUpdate: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Denied);
        f.BeforeDeniedFinalAbsence = () => f.Native.Journal.FailStatusDeniedVaultUpdateFlushOnce(
            Owner, f.Native.Selector, f.Native.Read().Revision + 1);
        var failed = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(failed, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Read().Released).IsTrue();
        long revision = f.Native.Read().Revision;
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(revision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedVaultUpdateJoinsOriginalTasksAndFullConfiguration(bool unauthorized)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateVault,
            statusDeniedVaultUpdate: true);
        if (unauthorized) f.Fault = "denied-selected-unauthorized";
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(1);
        await Assert.That(tap.Checks[0].Task.Result).IsEqualTo(SecretStatus.Denied);
        await Assert.That(ReferenceEquals(tap.Checks[0].Handle, tap.Start!.Result.Value)).IsTrue();
        await Assert.That(tap.Start.Result.Value.State).IsEqualTo(NativeProvisioningState.Failed);
        await Assert.That(tap.StartReceipt).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.SelectedDeletes + f.SelectedPurges + f.SelectedRecoveries).IsEqualTo(0);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.OriginalResourceReads).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.RecoveryRequest!.ContainsKey("tags")).IsFalse();
        var state = f.Native.Read();
        await Assert.That(state.Released && state.Closing && state.Idle && f.Prejournaled).IsTrue();
        await Assert.That(state.Resources.Length).IsEqualTo(3);
        await Assert.That(state.CreateOrUpdateVault!.SettledDispatch != Guid.Empty).IsTrue();
        await Assert.That(state.CreateOrUpdateVault.Baseline.PublicNetworkAccess).IsFalse();
        await Assert.That(state.CreateOrUpdateVault.Selected.PublicNetworkAccess).IsTrue();
    }

    [Test]
    [Arguments("denied-independent-pending")]
    [Arguments("denied-independent-failed")]
    [Arguments("denied-independent-canceled")]
    [Arguments("denied-independent-unknown")]
    [Arguments("denied-independent-denied")]
    [Arguments("denied-independent-malformed")]
    [Arguments("denied-independent-lost")]
    [Arguments("missing-tags")]
    [Arguments("foreign-tags")]
    [Arguments("unchanged")]
    [Arguments("deleted-present")]
    [Arguments("resource-denied")]
    [Arguments("resource-malformed")]
    [Arguments("lost")]
    [Arguments("no-target")]
    [Arguments("synchronous")]
    [Arguments("selected-malformed")]
    public async Task StatusDeniedVaultUpdateRequiresIndependentCompletionAndOwnedConfiguration(string fault)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateVault,
            statusDeniedVaultUpdate: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().CreateOrUpdateVault!.SettledDispatch).IsEqualTo(Guid.Empty);
    }

    [Test]
    public async Task StatusDeniedVaultUpdateForeignHandleCannotConsumeOriginalCheck()
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateVault,
            statusDeniedVaultUpdate: true);
        await using var other = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateVault,
            statusDeniedVaultUpdate: true);
        var lease = await f.PrepareAndBaseline();
        var original = await f.Start(lease);
        await f.Observe(lease);
        var foreign = await other.Start(await other.PrepareAndBaseline());
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, foreign.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, original.Value!, default))
            .IsEqualTo(SecretStatus.Denied);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedVaultUpdateObservationFlushRetryPreservesOriginalCandidate(bool releaseFirst)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateVault,
            statusDeniedVaultUpdate: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        f.Native.Journal.FailStatusDeniedVaultUpdateFlushOnce(Owner, f.Native.Selector, f.Native.Read().Revision + 2);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<IOException>();
        long revision = f.Native.Read().Revision;
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        if (!releaseFirst)
        {
            await Assert.That(f.Source.RetryStatusDeniedVaultUpdatePersistence(f.Native.Selector).Revision).IsEqualTo(revision);
            await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        }
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedVaultUpdateColdCleanupRequiresDurableSettlement(bool settled)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateVault,
            statusDeniedVaultUpdate: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        if (settled)
            await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
                .IsEqualTo(SecretStatus.Denied);
        await f.Source.DisposeAsync();
        await f.DrainParentAsync();
        await using var parent = f.ReopenProvisioner();
        await using var restarted = f.NewSource(cleanupOnly: true, parent: parent);
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(release.RemainingResourceIds.Length == 0).IsEqualTo(settled);
        await Assert.That(f.Native.Read().Released).IsEqualTo(settled);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(settled ? 1 : 0);
        await Assert.That(f.SetupPurges).IsEqualTo(settled ? 1 : 0);
    }
}
