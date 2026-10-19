using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Service = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationFixtureObserverService;
using V = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task StatusVaultRecoverCancellationRestoresFullTrustedBaselineWithActualStatusTasks()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.RecoverVault);
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
        await Assert.That(f.SelectedRecoveries).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.OriginalResourceReads).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.ResourceReads).IsEqualTo(4);
        await Assert.That(f.DeletedResourceReads).IsEqualTo(2);
        await Assert.That(f.SetupDeletes).IsEqualTo(2);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released && f.Native.Read().Idle && f.Prejournaled).IsTrue();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(3);
        await Assert.That(V.SameConfiguration(f.Native.Read().StatusVaultRecoverCancellationBaseline!, f.Baseline)).IsTrue();
        await Assert.That(f.RecoveryRequest!.ContainsKey("tags")).IsFalse();
        await Assert.That(f.RecoveryRequest["properties"]!["createMode"]!.GetValue<string>()).IsEqualTo("recover");
    }

    [Test]
    [Arguments("location")]
    [Arguments("tenant")]
    [Arguments("sku")]
    [Arguments("rbac")]
    [Arguments("protection")]
    [Arguments("retention")]
    [Arguments("network")]
    [Arguments("policies")]
    public async Task StatusVaultRecoverCancellationCannotRewriteTrustedBaselineBeforeProvisioning(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.RecoverVault,
            c => fault switch
            {
                "location" or "tenant" => c,
                "sku" => c with { Sku = VaultSku.Standard },
                "rbac" => c with { Rbac = false },
                "protection" => c with { PurgeProtection = true },
                "retention" => c with { RetentionDays = 7 },
                "network" => c with { PublicNetworkAccess = false },
                _ => c with { Policies = [new(Tenant, Principal, [SecretPermission.Get], null)] }
            });
        if (fault == "location") f.input = f.input with { Location = "westus" };
        if (fault == "tenant") f.input = f.input with { TenantId = Guid.NewGuid() };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedRecoveries + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Wire.Vault).IsNull();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(0);
        await Assert.That(f.Native.Read().LeaseId).IsEqualTo(Guid.Empty);
        await Assert.That(f.Native.Read().StatusVaultRecoverCancellationBaseline).IsNull();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("no-target")]
    [Arguments("synchronous")]
    [Arguments("selected-malformed")]
    [Arguments("pending")]
    [Arguments("unknown")]
    [Arguments("failed")]
    [Arguments("canceled")]
    [Arguments("status-denied")]
    [Arguments("status-malformed")]
    [Arguments("resource-denied")]
    [Arguments("resource-malformed")]
    [Arguments("missing-tags")]
    [Arguments("foreign-tags")]
    [Arguments("configuration")]
    [Arguments("ownership-configuration")]
    [Arguments("deleted-present")]
    public async Task StatusVaultRecoverCancellationCannotReplaceOriginalOrIndependentEvidence(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.RecoverVault) { Fault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedRecoveries).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Plan().VaultId).ActiveDispatch != Guid.Empty).IsTrue();
    }

    [Test]
    [Arguments(1, "lost")]
    [Arguments(1, "denied")]
    [Arguments(1, "malformed")]
    [Arguments(1, "pending")]
    [Arguments(1, "failed")]
    [Arguments(1, "canceled")]
    [Arguments(1, "unknown")]
    [Arguments(2, "lost")]
    [Arguments(2, "denied")]
    [Arguments(2, "malformed")]
    [Arguments(2, "pending")]
    [Arguments(2, "failed")]
    [Arguments(2, "canceled")]
    [Arguments(2, "unknown")]
    public async Task StatusVaultRecoverCancellationRequiresBothActualContinuationAndFinalResource(int ordinal, string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.RecoverVault)
        { Fault = $"check-{ordinal}-{fault}" };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedStatusFaultsReached).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.OriginalResourceReads).IsEqualTo(ordinal - 1);
        await Assert.That(f.SelectedRecoveries).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task StatusVaultRecoverCancellationCanceledBorrowCannotUseGenericOrCopiedSettlement()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.RecoverVault);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        var row = f.Native.Read().Resources.Single(r => r.Id == f.Plan().VaultId);
        await Assert.That(row.ActiveDispatch != Guid.Empty && row.InvocationTerminated).IsTrue();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.CompleteStatusVaultRecoverCancellationRead(Owner, f.Native.Selector,
            lease.Facts.LeaseId, row.ActiveDispatch, new Service.StatusVaultRecoverCancellationSettlement(f.Source, row.ActiveDispatch)))
            .Throws<InvalidOperationException>();
        await Assert.That(f.OriginalStatusReads + f.OriginalResourceReads).IsEqualTo(0);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Native.Read().Idle).IsTrue();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedRecoveries).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(2);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    [Arguments("selected-credential")]
    [Arguments("selected-send")]
    [Arguments("selected-body")]
    [Arguments("selected-sdk")]
    [Arguments("status-credential")]
    [Arguments("status-send")]
    [Arguments("resource-body")]
    [Arguments("original-poll")]
    [Arguments("original-final")]
    [Arguments("original-poll-body")]
    [Arguments("original-final-body")]
    public async Task StatusVaultRecoverCancellationCloseDrainsActualBorrower(string barrier)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.RecoverVault);
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
            await Assert.That(f.SetupDeletes).IsEqualTo(1);
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
    public async Task StatusVaultRecoverCancellationCloseBeforeLaterCheckRetainsSelectedFence()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.RecoverVault);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        var row = f.Native.Read().Resources.Single(r => r.Id == f.Plan().VaultId);
        f.Native.Journal.Close(Owner, f.Native.Selector);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await f.Release();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == row.Id).ActiveDispatch).IsEqualTo(row.ActiveDispatch);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.OriginalStatusReads + f.OriginalResourceReads + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
    }

    [Test]
    [Arguments("cleanup-active-empty")]
    [Arguments("cleanup-active-malformed")]
    [Arguments("cleanup-active-forbidden")]
    [Arguments("cleanup-deleted-empty")]
    [Arguments("cleanup-deleted-malformed")]
    [Arguments("cleanup-deleted-forbidden")]
    [Arguments("missing-owner")]
    [Arguments("foreign-owner")]
    [Arguments("configuration")]
    [Arguments("counterpart-present")]
    public async Task StatusVaultRecoverCancellationCleanupRequiresFreshFullOwnershipAndQualifiedAbsence(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.RecoverVault);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        if (fault == "missing-owner") f.Native.Wire.Vault!.Remove("tags");
        else if (fault == "foreign-owner") f.Native.Wire.Vault!["tags"]!["secretkit-fixture"] = "foreign";
        else if (fault == "configuration") f.Native.Wire.Vault!["properties"]!["publicNetworkAccess"] = "Disabled";
        else if (fault == "counterpart-present") f.Native.Wire.Deleted = true;
        else f.Fault = fault;
        var release = await f.Release();
        if (fault.StartsWith("cleanup-", StringComparison.Ordinal))
            await Assert.That(f.CleanupFaultsReached > 0).IsTrue();
        await Assert.That(release.RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.SelectedRecoveries).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusVaultRecoverCancellationReconstructionRetainsBaselineButNotUnsettledAuthority(bool settled)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.RecoverVault);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        if (settled) await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        var row = f.Native.Read().Resources.Single(r => r.Id == f.Plan().VaultId);
        await f.Source.DisposeAsync();
        await using var parent = f.ReopenProvisioner();
        await using var restarted = f.NewSource(parent: parent);
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(f.Native.Read().Released).IsEqualTo(settled);
        if (settled) RoleFixtureRelease.Validate(release, f.Native.Selector, lease.Facts);
        else await Assert.That(f.Native.Read().Resources.Single(r => r.Id == row.Id).ActiveDispatch).IsEqualTo(row.ActiveDispatch);
        await Assert.That(V.SameConfiguration(f.Native.Read().StatusVaultRecoverCancellationBaseline!, f.Baseline)).IsTrue();
        await Assert.That(f.SelectedRecoveries).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(settled ? 2 : 1);
        await Assert.That(f.SetupPurges).IsEqualTo(settled ? 1 : 0);
    }
}
