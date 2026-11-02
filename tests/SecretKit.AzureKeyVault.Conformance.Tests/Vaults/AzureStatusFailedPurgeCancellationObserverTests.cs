using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task StatusFailedPurgeCancellationDisposedOperandDoesNotPoisonActualFailureOrCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true);
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
        await Assert.That(f.Native.Read().PurgeDeletedVault!.FailedStage.ToString()).IsEqualTo("SelectedAdmitted");
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Unknown);
        await Assert.That(started.Value!.State).IsEqualTo(NativeProvisioningState.Failed);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    public async Task StatusFailedPurgeCancellationAbandonedPairCannotSettleFailureOrGrantCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        await f.Observe(lease);
        var released = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Read().PurgeDeletedVault!.FailedStage.ToString()).IsEqualTo("SelectedAdmitted");
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusFailedPurgeCancellationPairAdmissionFlushRetryCannotReplayCanceledInvocation()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease, cancelPending: false);
        long admittedRevision = f.Native.Read().Revision + 1;
        f.Native.Journal.FailStatusFailedPurgeCancellationFlushOnce(Owner, f.Native.Selector, admittedRevision);
        using var operand = new CancellationTokenSource();
        operand.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, operand.Token))
            .Throws<IOException>();
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        await Assert.That(f.Source.RetryStatusFailedPurgeCancellationPersistence(f.Native.Selector).Revision)
            .IsEqualTo(admittedRevision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.Native.Read().PurgeDeletedVault!.FailedStage.ToString()).IsEqualTo("SelectedAdmitted");
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task StatusFailedPurgeCancellationOriginalHandlerSettlesFailureThenUsesDistinctOwnedCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true);
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(2);
        await Assert.That(tap.Checks[0].Task.IsCanceled).IsTrue();
        await Assert.That(ReferenceEquals(tap.Checks[0].Handle, tap.Checks[1].Handle)).IsTrue();
        await Assert.That(tap.Checks[1].Task.Result).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(ReferenceEquals(tap.Checks[0].Handle, tap.Start!.Result.Value)).IsTrue();
        await Assert.That(tap.Checks[0].Handle.State).IsEqualTo(NativeProvisioningState.Failed);
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
        await Assert.That(state.PurgeDeletedVault!.FailedStage.ToString()).IsEqualTo("CleanupTerminal");
        await Assert.That(state.PurgeDeletedVault.PendingStage.ToString()).IsEqualTo("None");
        await Assert.That(state.PurgeDeletedVault.Disposition.ToString()).IsEqualTo("None");
        await Assert.That(state.PurgeDeletedVault.InvocationDispatch).IsEqualTo(state.PurgeDeletedVault.SettledDispatch);
        await Assert.That(f.FailedCleanupDispatch != Guid.Empty &&
            f.FailedCleanupDispatch != state.PurgeDeletedVault.InvocationDispatch).IsTrue();
    }

    [Test]
    public async Task StatusFailedPurgeCancellationOnlyActualTerminalFailureSettlesOriginalDispatch()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var before = f.Native.Read();
        await Assert.That(before.Idle).IsFalse();
        await Assert.That(before.PurgeDeletedVault!.FailedStage.ToString()).IsEqualTo("SelectedAdmitted");
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Unknown);
        var failed = f.Native.Read();
        await Assert.That(failed.Idle && !failed.Released).IsTrue();
        await Assert.That(failed.PurgeDeletedVault!.FailedStage.ToString()).IsEqualTo("TerminalFailed");
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
    [Arguments("failed-independent-pending")]
    [Arguments("failed-independent-succeeded")]
    [Arguments("failed-independent-canceled")]
    [Arguments("failed-independent-unknown")]
    [Arguments("failed-independent-denied")]
    [Arguments("failed-independent-malformed")]
    [Arguments("failed-independent-lost")]
    [Arguments("deleted-foreign")]
    [Arguments("deleted-protected")]
    [Arguments("deleted-missing")]
    public async Task StatusFailedPurgeCancellationIndependentWitnessCannotBeReplaced(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("failed-selected-pending")]
    [Arguments("failed-selected-succeeded")]
    [Arguments("failed-selected-canceled")]
    [Arguments("failed-selected-unknown")]
    [Arguments("failed-selected-denied")]
    [Arguments("failed-selected-malformed")]
    [Arguments("failed-selected-lost")]
    public async Task StatusFailedPurgeCancellationUnknownOrOtherStateCannotSettleFailure(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("failed-cleanup-async")]
    [Arguments("failed-cleanup-failed")]
    [Arguments("failed-cleanup-denied")]
    [Arguments("failed-cleanup-malformed")]
    [Arguments("failed-cleanup-empty")]
    [Arguments("failed-cleanup-lost")]
    [Arguments("failed-cleanup-continuation")]
    public async Task StatusFailedPurgeCancellationUncertainDistinctCleanupCannotReplayEvenAtAbsence(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        var before = f.Native.Read();
        await Assert.That(before.PurgeDeletedVault!.FailedStage.ToString()).IsEqualTo("CleanupAdmitted");
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
    public async Task StatusFailedPurgeCancellationTerminalFailureFlushRetryCannotPollCachedFailedHandle()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        long revision = f.Native.Read().Revision + 1;
        f.Native.Journal.FailStatusFailedPurgeCancellationFlushOnce(Owner, f.Native.Selector, revision);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<IOException>();
        await Assert.That(started.Value!.State).IsEqualTo(NativeProvisioningState.Failed);
        await Assert.That(f.Native.Read().PurgeDeletedVault!.FailedStage.ToString()).IsEqualTo("TerminalFailed");
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        await Assert.That(f.Source.RetryStatusFailedPurgeCancellationPersistence(f.Native.Selector).Revision).IsEqualTo(revision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    public async Task StatusFailedPurgeCancellationPreappendSharingFailureRetainsActualTerminalProof()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true);
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
        await Assert.That(f.Source.RetryStatusFailedPurgeCancellationPersistence(f.Native.Selector).Revision).IsEqualTo(revision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    public async Task StatusFailedPurgeCancellationReadableFinalAbsenceCannotReplaceMandatoryFlush()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        long revision = f.Native.Read().Revision + 4;
        f.Native.Journal.FailStatusFailedPurgeCancellationFlushOnce(Owner, f.Native.Selector, revision);
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
    public async Task StatusFailedPurgeCancellationFactoryRejectsOtherCasesBeforeSetup(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, statusFailedPurgeCancellation: true);
        await Assert.That(async () => await f.PrepareAndBaseline()).Throws<NativeCaseFailureException>();
        await Assert.That(f.SetupDeletes + f.SetupPurges + f.SelectedPurges).IsEqualTo(0);
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
        await Assert.That(f.Native.Wire.Vault).IsNull();
    }

    [Test]
    public async Task StatusFailedPurgeCancellationReconstructedTerminalFailureCannotGrantSetupCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        f.Native.Wire.Deleted = false;
        await using var reconstructed = f.ReopenProvisioner();
        try { await reconstructed.ReleaseAsync(Owner, f.Native.Selector, purge: true); }
        catch (InvalidOperationException) { }
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().PurgeDeletedVault!.FailedStage.ToString()).IsEqualTo("TerminalFailed");
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
    }

    [Test]
    public async Task StatusFailedPurgeCancellationGenericJournalCannotTurnNativeStartDrainIntoTerminalFailure()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true);
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
    public async Task StatusFailedPurgeCancellationRawPhaseCancellationAfterLinkedDisposalVetoesCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true);
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
            f.Source.RetryStatusFailedPurgeCancellationPersistence(f.Native.Selector);
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
        await Assert.That(f.Native.Read().PurgeDeletedVault!.FailedStage.ToString()).IsEqualTo("TerminalFailed");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusFailedPurgeCancellationMalformedReappearanceRevokesDurableAbsence(bool deleted)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        f.Fault = "failed-reappearance-malformed";
        if (deleted) f.Native.Wire.Deleted = true;
        else f.Native.Wire.Active = true;
        var incomplete = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(incomplete, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.CleanupFaultsReached).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.All(r => !r.Absent)).IsTrue();
        await Assert.That(f.Native.Read().PurgeDeletedVault!.FailedStage.ToString()).IsEqualTo("CleanupTerminal");
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
    }

    [Test]
    public async Task StatusFailedPurgeCancellationReappearanceRevokesAllAbsenceWithoutAnotherCleanupMutation()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", statusFailedPurgeCancellation: true);
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
