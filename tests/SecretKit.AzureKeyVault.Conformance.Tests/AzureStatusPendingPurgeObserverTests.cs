using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Op = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task StatusPendingPurgeOriginalHandlerRetainsPendingAndUsesSameHandleForCleanup()
    {
        await using var f = new PurgeServiceFixture(statusPendingPurge: true);
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(1);
        await Assert.That(tap.Checks[0].Task.Result).IsEqualTo(SecretStatus.Pending);
        await Assert.That(ReferenceEquals(tap.Checks[0].Handle, tap.Start!.Result.Value)).IsTrue();
        await Assert.That(tap.Checks[0].Handle.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(tap.StartReceipt).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(3);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        var state = f.Native.Read();
        await Assert.That(state.Released && state.Idle && f.Prejournaled).IsTrue();
        await Assert.That(state.Resources.Length).IsEqualTo(3);
        await Assert.That(state.Resources.All(r => r.Absent && !r.Borrowed)).IsTrue();
        await Assert.That(state.PurgeDeletedVault!.PendingStage.ToString()).IsEqualTo("CleanupTerminal");
        await Assert.That(state.PurgeDeletedVault.InvocationDispatch).IsEqualTo(state.PurgeDeletedVault.SettledDispatch);
    }

    [Test]
    public async Task StatusPendingPurgeObservationKeepsOriginalMutationFenceUntilClosedCleanup()
    {
        await using var f = new PurgeServiceFixture(statusPendingPurge: true);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(f.Native.Read().PurgeDeletedVault!.PendingStage.ToString()).IsEqualTo("Prepared");
        long preparedRevision = f.Native.Read().Revision;
        await Assert.That(f.Source.RetryStatusPendingPurgePersistence(f.Native.Selector).Revision).IsEqualTo(preparedRevision);
        var started = await f.Start(lease);
        await Assert.That(started.IsSuccess).IsTrue();
        var original = f.Native.Read();
        await Assert.That(original.PurgeDeletedVault!.PendingStage.ToString()).IsEqualTo("OriginalDrained");
        await Assert.That(f.Source.RetryStatusPendingPurgePersistence(f.Native.Selector).Revision).IsEqualTo(original.Revision);
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Pending);
        var pending = f.Native.Read();
        await Assert.That(pending.PurgeDeletedVault!.PendingStage.ToString()).IsEqualTo("PendingObserved");
        await Assert.That(pending.Idle || pending.Closing).IsFalse();
        await Assert.That(pending.PurgeDeletedVault.InvocationDispatch).IsEqualTo(original.PurgeDeletedVault.InvocationDispatch);
        await Assert.That(pending.PurgeDeletedVault.SettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(pending.Resources.Single(r => r.Id == f.Plan().DeletedId).ActiveDispatch)
            .IsEqualTo(pending.PurgeDeletedVault.InvocationDispatch);
        long revision = pending.Revision;
        int requests = f.OriginalStatusReads + f.ResourceReads;
        await Assert.That(f.Source.RetryStatusPendingPurgePersistence(f.Native.Selector).Revision).IsEqualTo(revision);
        await Assert.That(f.OriginalStatusReads + f.ResourceReads).IsEqualTo(requests);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(started.Value!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.OriginalReceipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
    }

    [Test]
    [Arguments("pending")]
    [Arguments("denied")]
    [Arguments("lost")]
    [Arguments("malformed")]
    [Arguments("challenge")]
    public async Task StatusPendingPurgeUncertainCleanupNeverClearsFenceOrChecksAgain(string fault)
    {
        await using var f = new PurgeServiceFixture(statusPendingPurge: true) { Fault = "pending-cleanup-" + fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        var state = f.Native.Read();
        await Assert.That(state.Closing && !state.Idle && !state.Released).IsTrue();
        await Assert.That(state.PurgeDeletedVault!.PendingStage.ToString()).IsEqualTo("CleanupAdmitted");
        await Assert.That(state.PurgeDeletedVault.SettledDispatch).IsEqualTo(Guid.Empty);
        int checks = f.OriginalStatusReads;
        await f.Release();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(checks);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("cancellation-boundary")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    public async Task StatusPendingPurgeFactoryRejectsOtherCasesBeforeProvisioning(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, statusPendingPurge: true);
        await Assert.That(async () => await f.Observer.PostAsync<Op.Prepare, Op.Lease>(
            "operation/prepare", f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
        await Assert.That(f.Native.Wire.Vault).IsNull();
    }

    [Test]
    public async Task StatusPendingPurgeReconstructedOutstandingRootCannotUseNativeAbsenceToSettle()
    {
        await using var f = new PurgeServiceFixture(statusPendingPurge: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        f.Native.Wire.Deleted = false;
        await using var reconstructed = f.ReopenProvisioner();
        await reconstructed.ReleaseAsync(Owner, f.Native.Selector, purge: true);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusPendingPurgeGenericJournalPathsCannotSettleOriginalMutation()
    {
        await using var f = new PurgeServiceFixture(statusPendingPurge: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        var before = f.Native.Read();
        var row = before.Resources.Single(r => r.Id == f.Plan().DeletedId);
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch, nativeSettled: false))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.RecordAbsence(Owner, f.Native.Selector, row.Id))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.BeginDispatch(Owner, f.Native.Selector, row.Id, delete: true))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Revision).IsEqualTo(before.Revision);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusPendingPurgeCleanupBodyRemainsOutstandingUntilActualDrain()
    {
        await using var f = new PurgeServiceFixture(statusPendingPurge: true) { Barrier = "pending-cleanup-body" };
        var run = f.RunOriginal();
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var outstanding = f.Native.Read();
            await Assert.That(outstanding.Closing && !outstanding.Idle && !outstanding.Released).IsTrue();
            await Assert.That(outstanding.PurgeDeletedVault!.PendingStage.ToString()).IsEqualTo("CleanupAdmitted");
            await Assert.That(outstanding.PurgeDeletedVault.SettledDispatch).IsEqualTo(Guid.Empty);
            await Assert.That(f.SetupPurges).IsEqualTo(0);
        }
        finally { f.Barrier = null; f.Resume.TrySetResult(); }
        await Assert.That((await run.WaitAsync(TimeSpan.FromSeconds(10))).Passed).IsTrue();
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    public async Task StatusPendingPurgeCloseBeforeObservationCannotAdmitCleanupOrLateSelectedWork()
    {
        await using var f = new PurgeServiceFixture(statusPendingPurge: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Release();
        await Assert.That(f.Native.Read().Closing && !f.Native.Read().Idle && !f.Native.Read().Released).IsTrue();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await f.Release();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    public async Task StatusPendingPurgeLostPreparationReplyUsesOnlyTypedNeverSelectedCleanup(string fault)
    {
        await using var f = new PurgeServiceFixture(statusPendingPurge: true) { PrepareReplyFault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.SelectedPurges).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await f.Release();
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }
}
