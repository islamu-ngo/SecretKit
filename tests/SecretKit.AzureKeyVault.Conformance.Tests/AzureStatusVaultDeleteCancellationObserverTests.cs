using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Op = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;
using Service = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task StatusVaultDeleteCancellationRetainsCanceledThenSuccessfulOriginalStatusCalls()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault);
        var tap = new CancellationStatusTap(f.Source);
        var result = await f.RunOriginal(tap);
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(tap.Start!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(2);
        await Assert.That(tap.Checks[0].Canceled && tap.Checks[0].Task.IsCanceled).IsTrue();
        await Assert.That(tap.Checks[1].Canceled).IsFalse();
        await Assert.That(tap.Checks[1].Task.Result).IsEqualTo(SecretStatus.Success);
        await Assert.That(ReferenceEquals(tap.Checks[0].Task, tap.Checks[1].Task)).IsFalse();
        await Assert.That(tap.Checks.All(c => ReferenceEquals(c.Handle, tap.Start.Result.Value))).IsTrue();
        await Assert.That(tap.StartReceipt).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(tap.StartReceipt);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads + f.SelectedPurges + f.SetupDeletes).IsEqualTo(0);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.ResourceReads).IsEqualTo(4);
        await Assert.That(f.DeletedResourceReads).IsEqualTo(2);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released && f.Native.Read().Idle && f.Prejournaled).IsTrue();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(3);
        await Assert.That(f.Native.Wire.Secret).IsNull();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("delete-202")]
    [Arguments("synchronous")]
    [Arguments("selected-malformed")]
    [Arguments("no-target")]
    public async Task StatusVaultDeleteCancellationCannotReplaceItsQualifiedOriginalStart(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault);
        f.Fault = fault;
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SelectedPurges + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
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
    public async Task StatusVaultDeleteCancellationRequiresIndependentTerminalStatusBeforeEitherCheck(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault);
        f.Fault = fault;
        var tap = new CancellationStatusTap(f.Source);
        var result = await f.RunOriginal(tap);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(tap.Checks.Count).IsEqualTo(0);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("deleted-missing")]
    [Arguments("deleted-foreign")]
    [Arguments("deleted-protected")]
    [Arguments("deleted-malformed")]
    [Arguments("active-reappeared")]
    public async Task StatusVaultDeleteCancellationRequiresBothIndependentResourceWindows(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault);
        f.Fault = fault;
        var tap = new CancellationStatusTap(f.Source);
        var result = await f.RunOriginal(tap);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.ResourceFaultsReached > 0).IsTrue();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(tap.Checks.Count).IsEqualTo(0);
        await Assert.That(f.OriginalStatusReads + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("selected-credential")]
    [Arguments("selected-send")]
    [Arguments("selected-sdk")]
    [Arguments("status-credential")]
    [Arguments("status-send")]
    [Arguments("resource-body")]
    public async Task StatusVaultDeleteCancellationCloseWaitsForTheActualBorrower(string barrier)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault);
        var lease = await f.PrepareAndBaseline();
        Task work;
        if (barrier.StartsWith("selected-", StringComparison.Ordinal))
        {
            f.Barrier = barrier;
            work = f.Start(lease);
        }
        else
        {
            await f.Start(lease);
            f.Barrier = barrier;
            work = f.Observe(lease).AsTask();
        }
        Task? disposing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await f.Release();
            disposing = f.Source.DisposeAsync().AsTask();
            await Assert.That(work.IsCompleted || disposing.IsCompleted).IsFalse();
            await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception ex) when (ex is OperationCanceledException or InvalidOperationException or NativeCaseFailureException) { }
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    public async Task StatusVaultDeleteCanceledBorrowCannotUseGenericSettlementBeforeTheLaterCheck()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        var row = f.Native.Read().Resources.Single(r => r.Id == f.Native.Wire.VaultId);
        await Assert.That(row.ActiveDispatch != Guid.Empty && row.InvocationTerminated).IsTrue();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.CompleteStatusVaultDeleteCancellationRead(Owner, f.Native.Selector,
            lease.Facts.LeaseId, row.ActiveDispatch, new Service.StatusVaultDeleteCancellationSettlement(f.Source, row.ActiveDispatch)))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == row.Id).ActiveDispatch).IsEqualTo(row.ActiveDispatch);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Native.Read().Idle).IsTrue();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads + f.SetupDeletes).IsEqualTo(0);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    public async Task StatusVaultDeleteCancellationCloseAfterCanceledBorrowRejectsLaterAdmission()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.DeleteVault);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        var row = f.Native.Read().Resources.Single(r => r.Id == f.Native.Wire.VaultId);
        f.Native.Journal.Close(Owner, f.Native.Selector);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await f.Release();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == row.Id).ActiveDispatch).IsEqualTo(row.ActiveDispatch);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.OriginalStatusReads + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
    }

    private sealed class CancellationStatusTap(Service source) : Op.SelectedInvocation
    {
        internal Task<SecretOutcome<ManagementOperation>>? Start;
        internal ManagementReceipt? Receipt;
        internal DispatchEvidence? StartReceipt;
        internal readonly List<(ManagementOperation Handle, Task<SecretStatus> Task, bool Canceled)> Checks = [];
        public async ValueTask<SecretOutcome<ManagementOperation>> RunStartAsync(FixtureSelector selector,
            VaultAdministration client, ManagementScope scope, ManagementMutation operation, Op.Input input,
            ManagementReceipt receipt, CancellationToken token)
        {
            Receipt = receipt;
            Start = source.RunStartAsync(selector, client, scope, operation, input, receipt, token).AsTask();
            var result = await Start;
            StartReceipt = receipt.Evidence;
            return result;
        }
        public ValueTask<SecretStatus> RunCheckStatusAsync(FixtureSelector selector, ManagementOperation handle,
            CancellationToken token)
        {
            var task = source.RunCheckStatusAsync(selector, handle, token).AsTask();
            Checks.Add((handle, task, token.IsCancellationRequested));
            return new(task);
        }
    }
}
