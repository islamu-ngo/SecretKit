using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task StatusCanceledPurgeCancellationDisposedOperandDoesNotPoisonActualFailureOrCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true);
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
        await Assert.That(f.Native.Read().PurgeDeletedVault!.CanceledStage.ToString()).IsEqualTo("SelectedAdmitted");
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Unknown);
        await Assert.That(started.Value!.State).IsEqualTo(NativeProvisioningState.Canceled);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    public async Task StatusCanceledPurgeCancellationAbandonedPairCannotSettleFailureOrGrantCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        await f.Observe(lease);
        var released = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Read().PurgeDeletedVault!.CanceledStage.ToString()).IsEqualTo("SelectedAdmitted");
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusCanceledPurgeCancellationPairAdmissionFlushRetryCannotReplayCanceledInvocation()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease, cancelPending: false);
        long admittedRevision = f.Native.Read().Revision + 1;
        f.Native.Journal.FailStatusCanceledPurgeCancellationFlushOnce(Owner, f.Native.Selector, admittedRevision);
        using var operand = new CancellationTokenSource();
        operand.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, operand.Token))
            .Throws<IOException>();
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        await Assert.That(f.Source.RetryStatusCanceledPurgeCancellationPersistence(f.Native.Selector).Revision)
            .IsEqualTo(admittedRevision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.Native.Read().PurgeDeletedVault!.CanceledStage.ToString()).IsEqualTo("SelectedAdmitted");
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task StatusCanceledPurgeCancellationOriginalHandlerSettlesFailureThenUsesDistinctOwnedCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true);
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(2);
        await Assert.That(tap.Checks[0].Task.IsCanceled).IsTrue();
        await Assert.That(ReferenceEquals(tap.Checks[0].Handle, tap.Checks[1].Handle)).IsTrue();
        await Assert.That(tap.Checks[1].Task.Result).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(ReferenceEquals(tap.Checks[0].Handle, tap.Start!.Result.Value)).IsTrue();
        await Assert.That(tap.Checks[0].Handle.State).IsEqualTo(NativeProvisioningState.Canceled);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.FailedCleanupExtraReads).IsEqualTo(0);
        var state = f.Native.Read();
        await Assert.That(state.Released && state.Idle && f.Prejournaled).IsTrue();
        await Assert.That(state.Resources.Length).IsEqualTo(3);
        await Assert.That(state.Resources.All(r => r.Absent && !r.Borrowed)).IsTrue();
        await Assert.That(state.PurgeDeletedVault!.CanceledStage.ToString()).IsEqualTo("CleanupTerminal");
        await Assert.That(state.PurgeDeletedVault.PendingStage.ToString()).IsEqualTo("None");
        await Assert.That(state.PurgeDeletedVault.FailedStage.ToString()).IsEqualTo("None");
        await Assert.That(state.PurgeDeletedVault.Disposition.ToString()).IsEqualTo("None");
        await Assert.That(state.PurgeDeletedVault.InvocationDispatch).IsEqualTo(state.PurgeDeletedVault.SettledDispatch);
        await Assert.That(f.FailedCleanupDispatch != Guid.Empty &&
            f.FailedCleanupDispatch != state.PurgeDeletedVault.InvocationDispatch).IsTrue();
    }

    [Test]
    public async Task StatusCanceledPurgeCancellationOnlyActualTerminalCancellationSettlesOriginalDispatch()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var before = f.Native.Read();
        await Assert.That(before.Idle).IsFalse();
        await Assert.That(before.PurgeDeletedVault!.CanceledStage.ToString()).IsEqualTo("SelectedAdmitted");
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Unknown);
        var failed = f.Native.Read();
        await Assert.That(failed.Idle && !failed.Released).IsTrue();
        await Assert.That(failed.PurgeDeletedVault!.CanceledStage.ToString()).IsEqualTo("TerminalCanceled");
        await Assert.That(failed.PurgeDeletedVault.InvocationDispatch).IsEqualTo(failed.PurgeDeletedVault.SettledDispatch);
        await Assert.That(failed.Resources.Any(r => r.Absent)).IsFalse();
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(await started.Value!.CheckStatusAsync()).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        int requests = f.ResourceReads + f.OriginalStatusReads + f.SetupPurges;
        long releasedRevision = f.Native.Read().Revision;
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.SetupPurges).IsEqualTo(requests + 2);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(releasedRevision);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.FailedCleanupExtraReads).IsEqualTo(0);
    }

    [Test]
    [Arguments("canceled-independent-pending")]
    [Arguments("canceled-independent-succeeded")]
    [Arguments("canceled-independent-failed")]
    [Arguments("canceled-independent-unknown")]
    [Arguments("canceled-independent-denied")]
    [Arguments("canceled-independent-malformed")]
    [Arguments("canceled-independent-lost")]
    [Arguments("deleted-foreign")]
    [Arguments("deleted-protected")]
    [Arguments("deleted-missing")]
    public async Task StatusCanceledPurgeCancellationIndependentWitnessCannotBeReplaced(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("canceled-selected-pending")]
    [Arguments("canceled-selected-succeeded")]
    [Arguments("canceled-selected-failed")]
    [Arguments("canceled-selected-unknown")]
    [Arguments("canceled-selected-denied")]
    [Arguments("canceled-selected-malformed")]
    [Arguments("canceled-selected-lost")]
    public async Task StatusCanceledPurgeCancellationUnknownOrOtherStateCannotSettleFailure(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("canceled-cleanup-async")]
    [Arguments("canceled-cleanup-failed")]
    [Arguments("canceled-cleanup-denied")]
    [Arguments("canceled-cleanup-malformed")]
    [Arguments("canceled-cleanup-empty")]
    [Arguments("canceled-cleanup-lost")]
    [Arguments("canceled-cleanup-continuation")]
    public async Task StatusCanceledPurgeCancellationUncertainDistinctCleanupCannotReplayEvenAtAbsence(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        var before = f.Native.Read();
        await Assert.That(before.PurgeDeletedVault!.CanceledStage.ToString()).IsEqualTo("CleanupAdmitted");
        await Assert.That(before.PurgeDeletedVault.InvocationDispatch).IsEqualTo(before.PurgeDeletedVault.SettledDispatch);
        await Assert.That(before.Idle || before.Released).IsFalse();
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.FailedCleanupExtraReads).IsEqualTo(0);
        f.Fault = null;
        var released = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(released, f.Native.Selector, null))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.FailedCleanupExtraReads).IsEqualTo(0);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
    }

    [Test]
    public async Task StatusCanceledPurgeCancellationTerminalCancellationFlushRetryCannotPollCachedFailedHandle()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        long revision = f.Native.Read().Revision + 1;
        f.Native.Journal.FailStatusCanceledPurgeCancellationFlushOnce(Owner, f.Native.Selector, revision);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<IOException>();
        await Assert.That(started.Value!.State).IsEqualTo(NativeProvisioningState.Canceled);
        await Assert.That(f.Native.Read().PurgeDeletedVault!.CanceledStage.ToString()).IsEqualTo("TerminalCanceled");
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        await Assert.That(f.Source.RetryStatusCanceledPurgeCancellationPersistence(f.Native.Selector).Revision).IsEqualTo(revision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    public async Task StatusCanceledPurgeCancellationPreappendSharingFailureRetainsActualTerminalProof()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        long revision = f.Native.Read().Revision + 1;
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
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        await Assert.That(f.Source.RetryStatusCanceledPurgeCancellationPersistence(f.Native.Selector).Revision).IsEqualTo(revision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    public async Task StatusCanceledPurgeCancellationReadableFinalAbsenceCannotReplaceMandatoryFlush()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        long revision = f.Native.Read().Revision + 4;
        f.Native.Journal.FailStatusCanceledPurgeCancellationFlushOnce(Owner, f.Native.Selector, revision);
        var uncertain = await f.Release();
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.Native.Read().Revision).IsEqualTo(revision);
        await Assert.That(uncertain.ActiveDispatches).IsGreaterThan(0);
        await Assert.That(() => RoleFixtureRelease.Validate(uncertain, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(revision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    public async Task StatusCanceledPurgeCancellationFactoryRejectsOtherCasesBeforeSetup(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, statusCanceledPurgeCancellation: true);
        await Assert.That(async () => await f.PrepareAndBaseline()).Throws<NativeCaseFailureException>();
        await Assert.That(f.SetupDeletes + f.SetupPurges + f.SelectedPurges).IsEqualTo(0);
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
        await Assert.That(f.Native.Wire.Vault).IsNull();
    }

    [Test]
    public async Task StatusCanceledPurgeCancellationReconstructedTerminalCancellationCannotGrantSetupCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        f.Native.Wire.Deleted = false;
        await using var reconstructed = f.ReopenProvisioner();
        try { await reconstructed.ReleaseAsync(Owner, f.Native.Selector, purge: true); }
        catch (InvalidOperationException) { }
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().PurgeDeletedVault!.CanceledStage.ToString()).IsEqualTo("TerminalCanceled");
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
    }

    [Test]
    public async Task StatusCanceledPurgeCancellationGenericJournalCannotTurnNativeStartDrainIntoTerminalCancellation()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        await f.Observe(lease);
        var before = f.Native.Read();
        var row = before.Resources.Single(r => r.Id == f.Plan().DeletedId);
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch, nativeSettled: false))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Revision).IsEqualTo(before.Revision);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusCanceledPurgeCancellationRawPhaseCancellationAfterLinkedDisposalVetoesCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        using var caller = new CancellationTokenSource();
        var started = await f.Start(lease, caller.Token);
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, caller.Token))
            .IsEqualTo(SecretStatus.Unknown);
        caller.Cancel();
        bool revived = false;
        try
        {
            f.Source.RetryStatusCanceledPurgeCancellationPersistence(f.Native.Selector);
            revived = true;
        }
        catch (InvalidOperationException) { }
        catch (OperationCanceledException) { }
        await Assert.That(revived).IsFalse();
        try
        {
            var incomplete = await f.Release();
            await Assert.That(() => RoleFixtureRelease.Validate(incomplete, f.Native.Selector, lease.Facts))
                .Throws<NativeCaseFailureException>();
        }
        catch (NativeCaseFailureException) { }
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().PurgeDeletedVault!.CanceledStage.ToString()).IsEqualTo("TerminalCanceled");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusCanceledPurgeCancellationMalformedReappearanceRevokesDurableAbsence(bool deleted)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        f.Fault = "canceled-reappearance-malformed";
        if (deleted) f.Native.Wire.Deleted = true;
        else f.Native.Wire.Active = true;
        var incomplete = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(incomplete, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.CleanupFaultsReached).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.All(r => !r.Absent)).IsTrue();
        await Assert.That(f.Native.Read().PurgeDeletedVault!.CanceledStage.ToString()).IsEqualTo("CleanupTerminal");
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
    }

    [Test]
    public async Task StatusCanceledPurgeCancellationReappearanceRevokesAllAbsenceWithoutAnotherCleanupMutation()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusCanceledPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        f.Native.Wire.Active = true;
        var incomplete = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(incomplete, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.All(r => !r.Absent)).IsTrue();
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
    }
}
