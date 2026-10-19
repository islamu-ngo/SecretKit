using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Op = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    public async Task OriginalDeleteHandlerRequiresIndependentTerminalStateBeforeCleanup(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, ManagementMutation.DeleteVault);
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SelectedPurges).IsEqualTo(0);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.ResourceReads).IsEqualTo(2);
        // The installed Delete200 path completes its original SDK handle from
        // cache. Only the separate reader supplies native terminal evidence.
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(0);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released && f.Prejournaled).IsTrue();
        await Assert.That(f.Native.Wire.Active || f.Native.Wire.Deleted).IsFalse();
    }

    [Test]
    [Arguments("pending")]
    [Arguments("unknown")]
    [Arguments("failed")]
    [Arguments("canceled")]
    [Arguments("status-malformed")]
    [Arguments("status-denied")]
    public async Task CachedDeleteHandleNeverReplacesIndependentNativeStatus(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteVault) { Fault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.ResourceReads).IsEqualTo(1);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("no-target")]
    [Arguments("synchronous")]
    [Arguments("selected-malformed")]
    [Arguments("delete-202")]
    [Arguments("resource-malformed")]
    [Arguments("resource-denied")]
    [Arguments("active-present")]
    public async Task UncertainOriginalDeleteIsNeverRetriedOrPurgedByCleanup(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteVault) { Fault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    public async Task LostDeletePreparationReplyKeepsExactOriginalCleanupAuthority(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteVault) { PrepareReplyFault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("selected-credential")]
    [Arguments("selected-send")]
    [Arguments("selected-body")]
    [Arguments("selected-sdk")]
    [Arguments("status-credential")]
    [Arguments("status-send")]
    [Arguments("resource-body")]
    public async Task DeleteServiceCannotCleanupOrDisposeThroughActualBorrowers(string barrier)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteVault);
        var lease = await f.PrepareAndBaseline();
        f.Barrier = barrier;
        Task work;
        if (barrier.StartsWith("selected", StringComparison.Ordinal)) work = f.Start(lease);
        else
        {
            await f.Start(lease);
            work = f.Observe(lease).AsTask();
        }
        Task? disposing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
            disposing = f.Source.DisposeAsync().AsTask();
            await Assert.That(work.IsCompleted || disposing.IsCompleted).IsFalse();
            await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or NativeCaseFailureException or InvalidOperationException) { }
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.SelectedDeletes).IsEqualTo(barrier == "selected-credential" ? 0 : 1);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task OriginalPurgeFinalReadKeepsItsTaskAndFenceUntilTermination()
    {
        await using var f = new PurgeServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        f.Barrier = "original-final";
        var checking = f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default).AsTask();
        Task? disposing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
            disposing = f.Source.DisposeAsync().AsTask();
            await Assert.That(checking.IsCompleted || disposing.IsCompleted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        try { await checking.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (OperationCanceledException) { }
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.OriginalStatusReads).IsEqualTo(2);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task RestartCannotConvertUnknownSelectedDeleteToCleanupDelete()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteVault) { Fault = "lost" };
        var lease = await f.PrepareAndBaseline();
        try { await f.Start(lease); } catch (InvalidOperationException) { }
        Guid dispatch = f.Native.Read().Resources.Single(r => r.Id == f.Plan().VaultId).ActiveDispatch;
        await f.Source.DisposeAsync();
        await using var restarted = f.NewSource();
        using var observer = f.NewObserver(restarted);
        var released = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(released.ActiveDispatches > 0).IsTrue();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Plan().VaultId).ActiveDispatch).IsEqualTo(dispatch);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task ActiveResurrectionAfterProvenDeletionNeverAuthorizesCleanupDelete()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteVault);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default)).IsEqualTo(SecretStatus.Success);
        f.Native.Wire.Active = true;
        var release = await f.Release();
        await Assert.That(release.RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Wire.Active).IsTrue();
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("lease")]
    [Arguments("subscription")]
    public async Task DeleteObservationBindingsCannotBorrowAnotherSession(string field)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteVault);
        var lease = await f.PrepareAndBaseline();
        var request = new ObserveLease(lease.Facts.LeaseId, lease.Facts.Nonce, "selected-state", f.Armed!.SubscriptionId);
        request = field switch
        {
            "nonce" => request with { Nonce = Guid.NewGuid() },
            "lease" => request with { LeaseId = Guid.NewGuid() },
            _ => request with { SubscriptionId = Guid.NewGuid() }
        };
        await Assert.That(async () => await f.Observer.PostAsync<ObserveLease, Op.Measurement>("operation/observe", request, default))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.IndependentStatusReads).IsEqualTo(0);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("operation.PurgeDeletedVault", ManagementMutation.DeleteVault)]
    [Arguments("operation.DeleteVault", ManagementMutation.PurgeDeletedVault)]
    [Arguments("operation.DeleteVault", ManagementMutation.CreateOrUpdateVault)]
    public async Task OperationVariantMismatchIsRejectedBeforeAnyPreparation(string variant, ManagementMutation operation)
    {
        await using var f = new PurgeServiceFixture();
        var input = f.PrepareRequest();
        input = input with { Selection = input.Selection with { Variant = variant }, Operation = operation };
        await Assert.That(async () => await f.Observer.PostAsync<Op.Prepare, Op.Lease>("operation/prepare", input, default))
            .Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
        await Assert.That(f.Native.Wire.Vault).IsNull();
    }

    [Test]
    [Arguments("tenant")]
    [Arguments("group")]
    [Arguments("subscription")]
    public async Task OperationServiceCannotDeclareDifferentProvisionerScope(string field)
    {
        await using var f = new PurgeServiceFixture();
        var scope = new VaultFixtureProvisioner.HostScope(Subscription, "fixture-group", "eastus", Tenant, true, true);
        scope = field switch
        {
            "tenant" => scope with { TenantId = Guid.NewGuid() },
            "group" => scope with { ResourceGroup = "foreign-group" },
            _ => scope with { SubscriptionId = Guid.NewGuid() }
        };
        await Assert.That(() => f.NewSource(declaredScope: scope)).Throws<InvalidOperationException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
        await Assert.That(f.Native.Wire.Vault).IsNull();
    }
}
