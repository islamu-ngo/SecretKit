using System.Text.Json;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedNotificationUpdateOriginalJoinsIndependentCompletionBeforeCleanup(bool unauthorized)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.UpdateNotification,
            statusDeniedNotificationUpdate: true) { Fault = unauthorized ? "original-unauthorized" : null };
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(1);
        await Assert.That(tap.Checks[0].Task.Result).IsEqualTo(SecretStatus.Denied);
        await Assert.That(ReferenceEquals(tap.Start!.Result.Value, tap.Checks[0].Handle)).IsTrue();
        await Assert.That(tap.Checks[0].Handle.State).IsEqualTo(NativeProvisioningState.Failed);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released && f.Native.Read().Idle).IsTrue();
        await Assert.That(JsonSerializer.Serialize(f.Native.Read()).Contains(Material, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("status-denied")]
    [Arguments("status-malformed")]
    [Arguments("status-future")]
    [Arguments("status-foreign-id")]
    [Arguments("status-foreign-name")]
    [Arguments("status-foreign-type")]
    [Arguments("status-foreign-topic")]
    [Arguments("status-foreign-label")]
    [Arguments("status-missing-label")]
    [Arguments("status-baseline")]
    public async Task StatusDeniedNotificationUpdateStatusOnlyFaultCannotBorrowValidNativeRead(string fault)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.UpdateNotification,
            statusDeniedNotificationUpdate: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("denied-native-malformed")]
    [Arguments("denied-native-absent")]
    [Arguments("denied-native-foreign-label")]
    public async Task StatusDeniedNotificationUpdateNativeReadFaultCannotBorrowValidStatus(string fault)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.UpdateNotification,
            statusDeniedNotificationUpdate: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.NotificationReadFaultsReached).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("original-success")]
    [Arguments("original-pending")]
    [Arguments("original-absent")]
    [Arguments("original-malformed")]
    [Arguments("original-lost")]
    public async Task StatusDeniedNotificationUpdateOtherSelectedResultCannotSettleOriginal(string fault)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.UpdateNotification,
            statusDeniedNotificationUpdate: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task StatusDeniedNotificationUpdateDisposalWaitsForActualDeniedBodyDrain()
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.UpdateNotification,
            statusDeniedNotificationUpdate: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        f.Barrier = "original-final-body";
        var check = f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default).AsTask();
        Task? disposing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            disposing = f.Source.DisposeAsync().AsTask();
            await Assert.That(check.IsCompleted || disposing.IsCompleted).IsFalse();
        }
        finally
        {
            f.Resume.TrySetResult();
            try { await check; }
            catch (OperationCanceledException) { }
            catch (InvalidOperationException) { }
            if (disposing is not null) await disposing.WaitAsync(TimeSpan.FromSeconds(10));
        }
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }
}
