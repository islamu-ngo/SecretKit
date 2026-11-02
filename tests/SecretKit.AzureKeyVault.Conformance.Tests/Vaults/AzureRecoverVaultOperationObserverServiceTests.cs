using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Op = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task CachedRecoveryHandleCannotReplaceCapturedOriginalNativeCompletion()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.RecoverVault);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        f.StatusCaptureBypass = true;
        try { await Assert.That(await started.Value!.CheckStatusAsync()).IsEqualTo(SecretStatus.Success); }
        finally { f.StatusCaptureBypass = false; }
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.OriginalResourceReads).IsEqualTo(1);
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Success);
        var release = await f.Release();
        await Assert.That(release.ActiveDispatches > 0).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    public async Task OriginalRecoveryJoinsOwnedNativeStateAndCleansWithoutReplay(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, ManagementMutation.RecoverVault);
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(f.SelectedRecoveries).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.OriginalResourceReads).IsEqualTo(1);
        await Assert.That(f.ResourceReads).IsEqualTo(2);
        await Assert.That(f.SetupDeletes).IsEqualTo(2); // preparation, then cleanup
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.Prejournaled && f.Native.Read().Released).IsTrue();
        await Assert.That(f.Native.Wire.Active || f.Native.Wire.Deleted).IsFalse();
        // This is the original installed Effects request, not a tagged rewrite.
        await Assert.That(f.RecoveryRequest!.ContainsKey("tags")).IsFalse();
        await Assert.That(f.RecoveryRequest["properties"]!["createMode"]!.GetValue<string>()).IsEqualTo("recover");
        await Assert.That(f.RecoveryRequest["properties"]!["accessPolicies"]!.AsArray().Count).IsEqualTo(0);
    }

    [Test]
    public async Task RecoveryUsesActiveUpdateFenceWithoutErasingPreparationHistory()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.RecoverVault);
        var lease = await f.PrepareAndBaseline();
        var plan = f.Plan();
        var rows = f.Native.Read().Resources;
        var active = rows.Single(r => r.Id == plan.VaultId);
        var deleted = rows.Single(r => r.Id == plan.DeletedId);
        await Assert.That(active.CreateAttempted && deleted.CreateAttempted).IsTrue();
        await Assert.That(active.DeleteAttempted || deleted.DeleteAttempted).IsFalse();
        await Assert.That(rows.Single(r => r.Id == plan.SecretId).CleanupOnly).IsTrue();
        var started = await f.Start(lease);
        rows = f.Native.Read().Resources;
        await Assert.That(rows.Single(r => r.Id == plan.VaultId).ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(rows.Single(r => r.Id == plan.DeletedId).ActiveDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(rows.All(r => !r.DeleteAttempted)).IsTrue();
        var measured = await f.Observe(lease);
        await Assert.That(measured.ResourceStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(measured.VaultConfiguration!.Rbac).IsTrue();
        await Assert.That(measured.VaultConfiguration.PublicNetworkAccess).IsTrue();
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default)).IsEqualTo(SecretStatus.Success);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
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
    [Arguments("lost")]
    [Arguments("no-target")]
    [Arguments("synchronous")]
    [Arguments("selected-malformed")]
    public async Task UncertainRecoveryCannotBecomeCleanupAuthority(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.RecoverVault) { Fault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedRecoveries).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1); // only prepared deletion
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Plan().VaultId).ActiveDispatch != Guid.Empty).IsTrue();
    }

    [Test]
    [Arguments("selected-credential")]
    [Arguments("selected-send")]
    [Arguments("selected-body")]
    [Arguments("selected-sdk")]
    [Arguments("status-credential")]
    [Arguments("status-send")]
    [Arguments("resource-body")]
    [Arguments("original-final")]
    public async Task RecoveryDisposalJoinsEveryOriginalAndIndependentBorrower(string barrier)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.RecoverVault);
        var lease = await f.PrepareAndBaseline();
        Task work;
        if (barrier.StartsWith("selected", StringComparison.Ordinal))
        {
            f.Barrier = barrier;
            work = f.Start(lease);
        }
        else
        {
            var started = await f.Start(lease);
            if (barrier == "original-final")
            {
                await f.Observe(lease);
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
            await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
            disposing = f.Source.DisposeAsync().AsTask();
            await Assert.That(work.IsCompleted || disposing.IsCompleted).IsFalse();
            await Assert.That(f.SetupDeletes).IsEqualTo(1);
            await Assert.That(f.SetupPurges).IsEqualTo(0);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or NativeCaseFailureException or InvalidOperationException) { }
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    public async Task RecoveryPreparationReplyLossRetainsOriginalCleanupAuthority(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.RecoverVault) { PrepareReplyFault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedRecoveries).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    public async Task RecoveryRestartCannotSettleFromOwnedPresence()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.RecoverVault) { Fault = "lost" };
        var lease = await f.PrepareAndBaseline();
        try { await f.Start(lease); } catch (InvalidOperationException) { }
        Guid dispatch = f.Native.Read().Resources.Single(r => r.Id == f.Plan().VaultId).ActiveDispatch;
        await f.Source.DisposeAsync();
        await using var restarted = f.NewSource();
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(release.ActiveDispatches > 0).IsTrue();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Plan().VaultId).ActiveDispatch).IsEqualTo(dispatch);
        await Assert.That(f.SelectedRecoveries).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("delete-lost")]
    [Arguments("delete-malformed")]
    [Arguments("purge-lost")]
    [Arguments("purge-malformed")]
    public async Task RecoveryCleanupLossRetainsItsOwnFenceWithoutRepeatingWrites(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.RecoverVault);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        if (fault.StartsWith("delete", StringComparison.Ordinal)) f.Native.Wire.DeleteFault = fault[7..];
        else f.Native.Wire.PurgeFault = fault[6..];
        var first = await f.Release();
        await Assert.That(first.ActiveDispatches > 0).IsTrue();
        int deletes = f.SetupDeletes, purges = f.SetupPurges;
        await f.Source.DisposeAsync();
        await using var restarted = f.NewSource();
        using var observer = f.NewObserver(restarted);
        var repeated = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(repeated.ActiveDispatches > 0).IsTrue();
        await Assert.That(f.SetupDeletes).IsEqualTo(deletes);
        await Assert.That(f.SetupPurges).IsEqualTo(purges);
        await Assert.That(f.SelectedRecoveries).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task DurablySettledRecoveryCanCleanupAfterCoordinateOnlyRestart()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.RecoverVault);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        await f.Source.DisposeAsync();
        await using var restarted = f.NewSource();
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        RoleFixtureRelease.Validate(release, f.Native.Selector, lease.Facts);
        await Assert.That(f.SetupDeletes).IsEqualTo(2);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.SelectedRecoveries).IsEqualTo(1);
    }

    [Test]
    [Arguments("missing-tags")]
    [Arguments("foreign-tags")]
    [Arguments("deleted-present")]
    public async Task SettledRecoveryStillRequiresFreshCleanupOwnership(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.RecoverVault);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        if (fault == "missing-tags") f.Native.Wire.Vault!.Remove("tags");
        else if (fault == "foreign-tags")
            f.Native.Wire.Vault!["tags"]!["secretkit-fixture"] = Guid.NewGuid().ToString("N");
        else f.Native.Wire.Deleted = true;
        var release = await f.Release();
        await Assert.That(release.RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Wire.Active).IsTrue();
    }

    [Test]
    [Arguments("denied-authority", ManagementMutation.RecoverVault)]
    [Arguments("selected-contract", ManagementMutation.DeleteVault)]
    [Arguments("selected-contract", ManagementMutation.CreateOrUpdateVault)]
    public async Task UnsupportedRecoverySelectionCannotProvision(string boundary, ManagementMutation operation)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.RecoverVault);
        var input = f.PrepareRequest();
        input = input with { Selection = input.Selection with { Case = boundary }, Operation = operation };
        await Assert.That(async () => await f.Observer.PostAsync<Op.Prepare, Op.Lease>(
            "operation/prepare", input, default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
        await Assert.That(f.Native.Wire.Vault).IsNull();
    }
}
