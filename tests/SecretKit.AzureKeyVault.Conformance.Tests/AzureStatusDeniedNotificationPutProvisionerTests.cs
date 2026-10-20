using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedNotificationPutFactoriesRejectOppositeParentBeforeIo(bool cleanup)
    {
        await using var put = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateNotification,
            statusDeniedNotificationUpdate: true);
        await using var patch = new PurgeServiceFixture("denied-authority", ManagementMutation.UpdateNotification,
            statusDeniedNotificationUpdate: true);
        await using var putParent = put.ReopenProvisioner();
        await using var patchParent = patch.ReopenProvisioner();
        await Assert.That(() => put.NewSource(cleanupOnly: cleanup, parent: patchParent))
            .Throws<InvalidOperationException>();
        await Assert.That(() => patch.NewSource(cleanupOnly: cleanup, parent: putParent))
            .Throws<InvalidOperationException>();
        await Assert.That(() => putParent.CloseSelectedRoot(Owner, patch.Native.Selector))
            .Throws<InvalidOperationException>();
        await Assert.That(() => patchParent.CloseSelectedRoot(Owner, put.Native.Selector))
            .Throws<InvalidOperationException>();
        await Assert.That(() => putParent.OpenCleanupPlan(Owner, patch.Native.Selector))
            .Throws<InvalidOperationException>();
        await Assert.That(() => patchParent.OpenCleanupPlan(Owner, put.Native.Selector))
            .Throws<InvalidOperationException>();
        await Assert.That(File.Exists(put.Native.JournalPath) || File.Exists(patch.Native.JournalPath)).IsFalse();
        await Assert.That(put.NotificationResourceReads + patch.NotificationResourceReads +
            put.SelectedUpdates + patch.SelectedUpdates).IsEqualTo(0);
    }

    [Test]
    public async Task StatusDeniedNotificationPutColdNativeChildCleanupUsesAcceptedSettledRoot()
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateNotification,
            statusDeniedNotificationUpdate: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        await f.Source.DisposeAsync();
        await f.DrainParentAsync();
        await using var parent = f.ReopenProvisioner();
        await using var cleanup = f.NewSource(cleanupOnly: true, parent: parent);
        await using var native = f.NewNotificationCleanup(parent);
        var plan = parent.OpenCleanupPlan(Owner, f.Native.Selector);
        using var result = await native.ReleaseAsync(Owner, f.Native.Selector, plan.OwnedNotificationNames.Single());
        await Assert.That(result.State).IsEqualTo(NotificationFixtureProvisioner.State.Closing);
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
        await Assert.That(result.Journal.Resources.Single(r => r.SelectedAttempted).Absent).IsTrue();
    }

    [Test]
    public async Task StatusDeniedNotificationPutGenericJournalCannotSubstituteForActualDeniedCheck()
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateNotification,
            statusDeniedNotificationUpdate: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var before = f.Native.Read();
        var selected = before.Resources.Single(r => r.SelectedAttempted);
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector,
            selected.Id, selected.ActiveDispatch)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector,
            selected.Id, selected.ActiveDispatch)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Revision).IsEqualTo(before.Revision);
        await Assert.That(f.Native.Read().Resources.Single(r => r.SelectedAttempted).ActiveDispatch)
            .IsEqualTo(selected.ActiveDispatch);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Denied);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedNotificationPutColdCleanupCannotRecreateUnresolvedAuthority(bool settled)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateNotification,
            statusDeniedNotificationUpdate: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        if (settled)
        {
            await f.Observe(lease);
            await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
                .IsEqualTo(SecretStatus.Denied);
        }
        await f.Source.DisposeAsync();
        await f.DrainParentAsync();
        await using var parent = f.ReopenProvisioner();
        await using var cleanup = f.NewSource(cleanupOnly: true, parent: parent);
        var released = await f.NewObserver(cleanup).PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(f.NotificationDeletes).IsEqualTo(settled ? 1 : 0);
        await Assert.That(f.SetupDeletes).IsEqualTo(settled ? 1 : 0);
        await Assert.That(f.SetupPurges).IsEqualTo(settled ? 1 : 0);
        if (settled) RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts);
        else await Assert.That(() => RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(settled ? 1 : 0);
        await Assert.That(f.Native.Read().Released).IsEqualTo(settled);
    }

    [Test]
    [Arguments("missing")]
    [Arguments("epoch")]
    [Arguments("writers")]
    [Arguments("older")]
    [Arguments("reuse")]
    [Arguments("earlier")]
    [Arguments("revoked")]
    public async Task StatusDeniedNotificationPutRequiresOriginalExclusionBeforeSetup(string fault)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateNotification,
            statusDeniedNotificationUpdate: true);
        f.UnknownExclusion = fault != "missing";
        f.UnknownNoOlderInflight = fault != "older";
        f.UnknownNoNameReuse = fault != "reuse";
        f.UnknownNeverApplied = fault != "earlier";
        if (fault == "revoked") f.UnknownContinuity.Cancel();
        await Assert.That(() => f.NewSource(notificationEpoch: fault == "epoch" ? Guid.Empty : f.UnknownEpoch,
            continuousWriterExclusion: fault != "writers")).Throws<InvalidOperationException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
        await Assert.That(f.SelectedUpdates + f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedNotificationPutLostContinuityCannotReconstructRemoteSettlement(bool afterObservation)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateNotification,
            statusDeniedNotificationUpdate: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        if (afterObservation) await f.Observe(lease);
        f.UnknownContinuity.Cancel();
        try
        {
            if (afterObservation) await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
            else await f.Observe(lease);
        }
        catch (InvalidOperationException) { }
        catch (OperationCanceledException) { }
        catch (NativeCaseFailureException) { }
        var released = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Closing).IsTrue();
    }

    [Test]
    public async Task StatusDeniedNotificationPutStartFlushRetryCannotReplaySelectedMutation()
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateNotification,
            statusDeniedNotificationUpdate: true);
        var lease = await f.PrepareAndBaseline();
        f.Native.Journal.FailStatusDeniedNotificationUpdateFlushOnce(Owner, f.Native.Selector, f.Native.Read().Revision + 2);
        await Assert.That(async () => await f.Start(lease)).Throws<IOException>();
        long revision = f.Native.Read().Revision;
        int reads = f.NotificationResourceReads + f.ResourceReads;
        var retried = f.Source.RetryStatusDeniedNotificationUpdatePersistence(f.Native.Selector);
        await Assert.That(retried.Revision).IsEqualTo(revision);
        await Assert.That(f.NotificationResourceReads + f.ResourceReads).IsEqualTo(reads);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        var released = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusDeniedNotificationPutMalformedParentVetoesDestructionAfterChildCleanup()
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.CreateOrUpdateNotification,
            statusDeniedNotificationUpdate: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Denied);
        f.Fault = "unknown-parent-malformed";
        await f.Release();
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.All(r => !r.Absent)).IsTrue();
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }
}
