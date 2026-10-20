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
    public async Task StatusUnknownNotificationUpdateHistoricalFlushRetryClosesBeforeReleaseMeasurement(bool observation)
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.UpdateNotification,
            statusUnknownNotificationUpdate: true);
        var lease = await f.PrepareAndBaseline();
        if (observation)
        {
            var started = await f.Start(lease);
            await f.Observe(lease);
            f.Native.Journal.FailStatusUnknownNotificationUpdateFlushOnce(Owner, f.Native.Selector, f.Native.Read().Revision + 2);
            await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
                .Throws<IOException>();
        }
        else
        {
            f.Native.Journal.FailStatusUnknownNotificationUpdateFlushOnce(Owner, f.Native.Selector, f.Native.Read().Revision + 2);
            await Assert.That(async () => await f.Start(lease)).Throws<IOException>();
        }
        var released = await f.Release();
        await Assert.That(f.Native.Read().Closing).IsTrue();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(observation ? 1 : 0);
        if (observation)
        {
            RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts);
            await Assert.That(f.UnknownTerminalReads).IsEqualTo(1);
        }
        else
        {
            await Assert.That(f.Native.Read().Released).IsFalse();
            await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        }
    }

    [Test]
    [Arguments("missing")]
    [Arguments("epoch")]
    [Arguments("writers")]
    [Arguments("older")]
    [Arguments("reuse")]
    [Arguments("earlier")]
    [Arguments("revoked")]
    public async Task StatusUnknownNotificationUpdateExclusionPremisesRequiredBeforeSetup(string fault)
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.UpdateNotification,
            statusUnknownNotificationUpdate: true);
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
    public async Task StatusUnknownNotificationUpdateMalformedParent200RevokesAllAbsenceBeforeMutation()
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.UpdateNotification,
            statusUnknownNotificationUpdate: true);
        await ObserveOriginalUnknownNotification(f);
        f.Fault = "unknown-parent-malformed";
        await f.Release();
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.All(r => !r.Absent)).IsTrue();
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task StatusUnknownNotificationUpdateTerminalPostappendRetryCannotRepeatNativeRead()
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.UpdateNotification,
            statusUnknownNotificationUpdate: true);
        var lease = await ObserveOriginalUnknownNotification(f);
        var closed = f.Native.Journal.Close(Owner, f.Native.Selector);
        f.Native.Journal.FailStatusUnknownNotificationUpdateFlushOnce(Owner, f.Native.Selector, closed.Revision + 1);
        await Assert.That(async () => await f.Release())
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.UnknownTerminalReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        var released = await f.Release();
        await Assert.That(f.UnknownTerminalReads).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Single(r => r.SelectedAttempted).ActiveDispatch).IsEqualTo(Guid.Empty);
        RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts);
        await Assert.That(f.UnknownTerminalReads).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
    }

    [Test]
    public async Task StatusUnknownNotificationUpdateGenericJournalCannotSettleHistoricalUnknown()
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.UpdateNotification,
            statusUnknownNotificationUpdate: true);
        var lease = await ObserveOriginalUnknownNotification(f);
        var before = f.Native.Read();
        var selected = before.Resources.Single(r => r.SelectedAttempted);
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector,
            selected.Id, selected.ActiveDispatch)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector,
            selected.Id, selected.ActiveDispatch)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Revision).IsEqualTo(before.Revision);
        await Assert.That(f.Native.Read().Resources.Single(r => r.SelectedAttempted).ActiveDispatch)
            .IsEqualTo(selected.ActiveDispatch);
        var released = await f.Release();
        await Assert.That(f.UnknownTerminalReads).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Single(r => r.SelectedAttempted).ActiveDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Single(r => r.SelectedAttempted).Absent).IsTrue();
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts);
        await Assert.That(f.UnknownTerminalReads).IsEqualTo(1);
    }

    [Test]
    public async Task StatusUnknownNotificationUpdateOriginalCallerCancellationAfterLinkedDisposalVetoesCompletion()
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.UpdateNotification,
            statusUnknownNotificationUpdate: true);
        var lease = await f.PrepareAndBaseline();
        using var caller = new CancellationTokenSource();
        var started = await f.Start(lease, caller.Token);
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, caller.Token))
            .IsEqualTo(SecretStatus.Unknown);
        caller.Cancel();
        await f.Release();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Single(r => r.SelectedAttempted).ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }
}
