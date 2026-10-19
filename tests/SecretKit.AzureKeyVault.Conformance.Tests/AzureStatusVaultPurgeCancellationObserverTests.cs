using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Service = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task StatusVaultPurgeCancellationRetainsCanceledThenNativeContinuationTasks()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary");
        var tap = new CancellationStatusTap(f.Source);
        var result = await f.RunOriginal(tap);
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(2);
        await Assert.That(tap.Checks[0].Canceled && tap.Checks[0].Task.IsCanceled).IsTrue();
        await Assert.That(tap.Checks[1].Canceled).IsFalse();
        await Assert.That(tap.Checks[1].Task.Result).IsEqualTo(SecretStatus.Success);
        await Assert.That(ReferenceEquals(tap.Checks[0].Task, tap.Checks[1].Task)).IsFalse();
        await Assert.That(tap.Checks.All(c => ReferenceEquals(c.Handle, tap.Start!.Result.Value))).IsTrue();
        await Assert.That(tap.StartReceipt).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(tap.StartReceipt);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(2);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.ResourceReads).IsEqualTo(4);
        await Assert.That(f.ActiveCounterpartReads).IsEqualTo(2);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SelectedDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released && f.Native.Read().Idle && f.Prejournaled).IsTrue();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(3);
    }

    [Test]
    [Arguments("lost")]
    [Arguments("no-target")]
    [Arguments("synchronous")]
    [Arguments("selected-malformed")]
    public async Task StatusVaultPurgeCancellationRequiresQualifiedOriginalStart(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary") { Fault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges + f.SelectedDeletes + f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    [Arguments("pending")]
    [Arguments("unknown")]
    [Arguments("failed")]
    [Arguments("canceled")]
    [Arguments("status-malformed")]
    [Arguments("status-denied")]
    public async Task StatusVaultPurgeCancellationRequiresIndependentTerminalStatus(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary") { Fault = fault };
        var tap = new CancellationStatusTap(f.Source);
        var result = await f.RunOriginal(tap);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(tap.Checks.Count).IsEqualTo(0);
        await Assert.That(f.SetupPurges + f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("purge-active-before", false)]
    [Arguments("purge-deleted-missing", false)]
    [Arguments("purge-deleted-foreign", false)]
    [Arguments("purge-deleted-protected", false)]
    [Arguments("purge-deleted-malformed", false)]
    [Arguments("purge-active-after", true)]
    [Arguments("purge-active-denied", true)]
    [Arguments("purge-deleted-after", true)]
    public async Task StatusVaultPurgeCancellationRequiresBothIndependentResourceWindows(string fault, bool started)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary") { Fault = fault };
        var tap = new CancellationStatusTap(f.Source);
        var result = await f.RunOriginal(tap);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.ResourceFaultsReached > 0).IsTrue();
        await Assert.That(f.SelectedPurges).IsEqualTo(started ? 1 : 0);
        await Assert.That(tap.Checks.Count + f.OriginalStatusReads).IsEqualTo(0);
        if (started)
        {
            await Assert.That(f.SetupPurges).IsEqualTo(0);
            await Assert.That(f.Native.Read().Released).IsFalse();
        }
    }

    [Test]
    [Arguments("check-1-pending")]
    [Arguments("check-1-failed")]
    [Arguments("check-1-canceled")]
    [Arguments("check-1-unknown")]
    [Arguments("check-1-denied")]
    [Arguments("check-1-malformed")]
    [Arguments("check-1-lost")]
    [Arguments("check-2-pending")]
    [Arguments("check-2-failed")]
    [Arguments("check-2-canceled")]
    [Arguments("check-2-unknown")]
    [Arguments("check-2-denied")]
    [Arguments("check-2-malformed")]
    [Arguments("check-2-lost")]
    public async Task StatusVaultPurgeCancellationRejectsEitherUnqualifiedSelectedContinuation(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary") { Fault = fault };
        var tap = new CancellationStatusTap(f.Source);
        var result = await f.RunOriginal(tap);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedStatusFaultsReached).IsEqualTo(1);
        await Assert.That(tap.Checks.Count).IsEqualTo(2);
        await Assert.That(tap.Checks[0].Task.IsCanceled).IsTrue();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    public async Task StatusVaultPurgeCancellationGenericSettlementCannotClearCanceledBorrowFence()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary");
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        var row = f.Native.Read().Resources.Single(r => r.Id == f.Plan().DeletedId);
        await Assert.That(row.ActiveDispatch != Guid.Empty && row.InvocationTerminated).IsTrue();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.CompleteStatusVaultPurgeCancellationRead(Owner, f.Native.Selector,
            lease.Facts.LeaseId, row.ActiveDispatch, new Service.StatusVaultPurgeCancellationSettlement(f.Source, row.ActiveDispatch)))
            .Throws<InvalidOperationException>();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Native.Read().Idle).IsTrue();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-credential")]
    [Arguments("selected-send")]
    [Arguments("selected-sdk")]
    [Arguments("status-credential")]
    [Arguments("status-send")]
    [Arguments("resource-body")]
    [Arguments("original-poll")]
    [Arguments("original-final")]
    [Arguments("original-poll-body")]
    [Arguments("original-final-body")]
    public async Task StatusVaultPurgeCancellationCloseDrainsActualBorrower(string barrier)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary");
        var lease = await f.PrepareAndBaseline();
        Task work;
        if (barrier.StartsWith("selected-", StringComparison.Ordinal))
        {
            f.Barrier = barrier;
            work = f.Start(lease);
        }
        else
        {
            var started = await f.Start(lease);
            if (barrier.StartsWith("original-", StringComparison.Ordinal))
            {
                await f.Observe(lease);
                using var stop = new CancellationTokenSource();
                stop.Cancel();
                await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
                    .Throws<OperationCanceledException>();
                f.Barrier = barrier;
                work = f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default).AsTask();
            }
            else
            {
                f.Barrier = barrier;
                work = f.Observe(lease).AsTask();
            }
        }
        Task? disposing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await f.Release();
            disposing = f.Source.DisposeAsync().AsTask();
            await Assert.That(work.IsCompleted || disposing.IsCompleted).IsFalse();
            await Assert.That(f.SetupPurges).IsEqualTo(0);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception ex) when (ex is OperationCanceledException or InvalidOperationException or NativeCaseFailureException) { }
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task StatusVaultPurgeCancellationRestartPreservesUnresolvedOrSettledCleanup(bool settled, bool reconstructParent)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary");
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        if (settled) await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        var row = f.Native.Read().Resources.Single(r => r.Id == f.Plan().DeletedId);
        await f.Source.DisposeAsync();
        await using var parent = reconstructParent ? f.ReopenProvisioner() : null;
        await using var restarted = f.NewSource(parent: parent);
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(f.Native.Read().Released).IsEqualTo(settled);
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == row.Id).ActiveDispatch).IsEqualTo(row.ActiveDispatch);
        if (settled) RoleFixtureRelease.Validate(release, f.Native.Selector, lease.Facts);
        else await Assert.That(release.ActiveDispatches > 0).IsTrue();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("cleanup-active-empty")]
    [Arguments("cleanup-active-malformed")]
    [Arguments("cleanup-active-forbidden")]
    [Arguments("cleanup-deleted-empty")]
    [Arguments("cleanup-deleted-malformed")]
    [Arguments("cleanup-deleted-forbidden")]
    public async Task StatusVaultPurgeCancellationCleanupRejectsUnqualifiedAbsence(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary");
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        f.Fault = fault;
        var release = await f.Release();
        await Assert.That(f.CleanupFaultsReached > 0).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(release.RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
    }

    [Test]
    public async Task StatusVaultPurgeCancellationFreshCleanupCannotDeleteActiveResurrection()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary");
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        f.Native.Wire.Active = true;
        var release = await f.Release();
        await Assert.That(release.RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Wire.Active).IsTrue();
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusVaultPurgeCancellationCloseBeforeLaterCheckLeavesSelectedFence()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary");
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        var row = f.Native.Read().Resources.Single(r => r.Id == f.Plan().DeletedId);
        f.Native.Journal.Close(Owner, f.Native.Selector);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await f.Release();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == row.Id).ActiveDispatch).IsEqualTo(row.ActiveDispatch);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.OriginalStatusReads + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
    }
}
