using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Op = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task StatusPendingPurgeCancellationOriginalHandlerRetainsPendingAndUsesSameHandleForCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true);
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(2);
        await Assert.That(tap.Checks[0].Task.IsCanceled).IsTrue();
        await Assert.That(ReferenceEquals(tap.Checks[0].Handle, tap.Checks[1].Handle)).IsTrue();
        await Assert.That(tap.Checks[1].Task.Result).IsEqualTo(SecretStatus.Pending);
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
    public async Task StatusPendingPurgeCancellationObservationKeepsOriginalMutationFenceUntilClosedCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(f.Native.Read().PurgeDeletedVault!.PendingStage.ToString()).IsEqualTo("Prepared");
        long preparedRevision = f.Native.Read().Revision;
        await Assert.That(f.Source.RetryStatusPendingPurgeCancellationPersistence(f.Native.Selector).Revision).IsEqualTo(preparedRevision);
        var started = await f.Start(lease);
        await Assert.That(started.IsSuccess).IsTrue();
        var original = f.Native.Read();
        await Assert.That(original.PurgeDeletedVault!.PendingStage.ToString()).IsEqualTo("OriginalDrained");
        await Assert.That(f.Source.RetryStatusPendingPurgeCancellationPersistence(f.Native.Selector).Revision).IsEqualTo(original.Revision);
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
        await Assert.That(f.Source.RetryStatusPendingPurgeCancellationPersistence(f.Native.Selector).Revision).IsEqualTo(revision);
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
    public async Task StatusPendingPurgeCancellationUncertainCleanupNeverClearsFenceOrChecksAgain(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true) { Fault = "pending-cleanup-" + fault };
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
    [Arguments("independent-effect")]
    [Arguments("selected-contract")]
    [Arguments("denied-authority")]
    public async Task StatusPendingPurgeCancellationFactoryRejectsOtherCasesBeforeProvisioning(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, statusPendingPurgeCancellation: true);
        await Assert.That(async () => await f.Observer.PostAsync<Op.Prepare, Op.Lease>(
            "operation/prepare", f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
        await Assert.That(f.Native.Wire.Vault).IsNull();
    }

    [Test]
    public async Task StatusPendingPurgeCancellationReconstructedOutstandingRootCannotUseNativeAbsenceToSettle()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true);
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
    public async Task StatusPendingPurgeCancellationGenericJournalPathsCannotSettleOriginalMutation()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true);
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
    public async Task StatusPendingPurgeCancellationCleanupBodyRemainsOutstandingUntilActualDrain()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true) { Barrier = "pending-cleanup-body" };
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
    public async Task StatusPendingPurgeCancellationCloseBeforeObservationCannotAdmitCleanupOrLateSelectedWork()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true);
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
    public async Task StatusPendingPurgeCancellationLostPreparationReplyUsesOnlyTypedNeverSelectedCleanup(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true) { PrepareReplyFault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.SelectedPurges).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await f.Release();
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    public async Task StatusPendingPurgeCancellationFinalAbsenceFlushFailureCannotReportDurableRelease()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        long finalRevision = f.Native.Read().Revision + 4;
        f.Native.Journal.FailStatusPendingPurgeCancellationFlushOnce(Owner, f.Native.Selector, finalRevision);
        var uncertain = await f.Release();
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.Native.Read().Revision).IsEqualTo(finalRevision);
        await Assert.That(uncertain.ActiveDispatches).IsGreaterThan(0);
        await Assert.That(() => RoleFixtureRelease.Validate(uncertain, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(finalRevision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusPendingPurgeCancellationObservationFlushFailureRetainsExactPostimageWithoutReplay()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        long observedRevision = f.Native.Read().Revision + 1;
        f.Native.Journal.FailStatusPendingPurgeCancellationFlushOnce(Owner, f.Native.Selector, observedRevision);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<IOException>();
        await Assert.That(f.Native.Read().PurgeDeletedVault!.PendingStage.ToString()).IsEqualTo("PendingObserved");
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        await Assert.That(f.Source.RetryStatusPendingPurgeCancellationPersistence(f.Native.Selector).Revision)
            .IsEqualTo(observedRevision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
    }

    [Test]
    [Arguments("pending-independent-denied")]
    [Arguments("pending-independent-malformed")]
    [Arguments("pending-independent-lost")]
    [Arguments("pending-independent-succeeded")]
    [Arguments("deleted-foreign")]
    [Arguments("deleted-protected")]
    [Arguments("deleted-missing")]
    public async Task StatusPendingPurgeCancellationRequiresItsActualIndependentNonterminalWitness(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released || f.Native.Read().Idle).IsFalse();
    }

    [Test]
    public async Task StatusPendingPurgeCancellationTerminalFlushFailureRetriesWithoutAnotherNativeCheck()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        long terminalRevision = f.Native.Read().Revision + 3;
        f.Native.Journal.FailStatusPendingPurgeCancellationFlushOnce(Owner, f.Native.Selector, terminalRevision);
        try
        {
            var uncertain = await f.Release();
            await Assert.That(uncertain.ActiveDispatches).IsGreaterThan(0);
        }
        catch (NativeCaseFailureException) { }
        await Assert.That(f.Native.Read().PurgeDeletedVault!.PendingStage.ToString()).IsEqualTo("CleanupTerminal");
        await Assert.That(f.Native.Read().Released).IsFalse();
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        await Assert.That(f.Source.RetryStatusPendingPurgeCancellationPersistence(f.Native.Selector).Revision)
            .IsEqualTo(terminalRevision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(3);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusPendingPurgeCancellationPreappendSharingFailureRetainsActualObservation()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        long observedRevision = f.Native.Read().Revision + 1;
        f.Barrier = "original-poll-body";
        var check = f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default).AsTask();
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            using var blocked = new FileStream(f.Native.JournalPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            f.Resume.TrySetResult();
            await Assert.That(async () => await check.WaitAsync(TimeSpan.FromSeconds(10))).Throws<IOException>();
        }
        finally { f.Barrier = null; f.Resume.TrySetResult(); }
        await Assert.That(started.Value!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        await Assert.That(f.Source.RetryStatusPendingPurgeCancellationPersistence(f.Native.Selector).Revision)
            .IsEqualTo(observedRevision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusPendingPurgeCancellationCanceledOperandDisposalDoesNotPoisonNormalOrCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease, cancelPending: false);
        long before = f.Native.Read().Revision;
        using (var operand = new CancellationTokenSource())
        {
            operand.Cancel();
            await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector,
                started.Value!, operand.Token)).Throws<OperationCanceledException>();
        }
        await Assert.That(f.Native.Read().Revision).IsEqualTo(before + 1);
        await Assert.That(f.Native.Read().PurgeDeletedVault!.PendingStage.ToString()).IsEqualTo("SelectedAdmitted");
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Pending);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(3);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
    }

    [Test]
    public async Task StatusPendingPurgeCancellationAbandonedPairCannotBecomePendingObservationOrCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        await f.Observe(lease);
        var released = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Read().PurgeDeletedVault!.PendingStage.ToString()).IsEqualTo("SelectedAdmitted");
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusPendingPurgeCancellationPairAdmissionFlushRetryCannotReplayCanceledInvocation()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusPendingPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease, cancelPending: false);
        long admittedRevision = f.Native.Read().Revision + 1;
        f.Native.Journal.FailStatusPendingPurgeCancellationFlushOnce(Owner, f.Native.Selector, admittedRevision);
        using var operand = new CancellationTokenSource();
        operand.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, operand.Token))
            .Throws<IOException>();
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        await Assert.That(f.Source.RetryStatusPendingPurgeCancellationPersistence(f.Native.Selector).Revision)
            .IsEqualTo(admittedRevision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.Native.Read().PurgeDeletedVault!.PendingStage.ToString()).IsEqualTo("SelectedAdmitted");
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }
}
