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
    public async Task OriginalActiveUpdateRequiresMeasuredNetworkContrastAndOwnership(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, ManagementMutation.CreateOrUpdateVault);
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.SelectedRecoveries).IsEqualTo(0);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.OriginalResourceReads).IsEqualTo(1);
        await Assert.That(f.ResourceReads).IsEqualTo(2);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released && f.Prejournaled).IsTrue();
        await Assert.That(f.RecoveryRequest!.ContainsKey("tags")).IsFalse();
        await Assert.That(f.RecoveryRequest["properties"]!["publicNetworkAccess"]!.GetValue<string>()).IsEqualTo("Enabled");
        await Assert.That(f.RecoveryRequest["properties"]!["accessPolicies"]!.AsArray().Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("pending")]
    [Arguments("status-denied")]
    [Arguments("status-malformed")]
    [Arguments("resource-denied")]
    [Arguments("resource-malformed")]
    [Arguments("missing-tags")]
    [Arguments("foreign-tags")]
    [Arguments("configuration")]
    [Arguments("ownership-configuration")]
    [Arguments("deleted-present")]
    [Arguments("unchanged")]
    [Arguments("lost")]
    [Arguments("no-target")]
    [Arguments("synchronous")]
    [Arguments("selected-malformed")]
    public async Task UncertainActiveUpdateCannotAuthorizeCleanupOrReplay(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.CreateOrUpdateVault) { Fault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Plan().VaultId).ActiveDispatch != Guid.Empty).IsTrue();
    }

    [Test]
    [Arguments("selected-send")]
    [Arguments("selected-body")]
    [Arguments("selected-sdk")]
    [Arguments("status-send")]
    [Arguments("resource-body")]
    [Arguments("original-final")]
    public async Task ActiveUpdateBorrowersRetainCleanupAndDisposalFence(string barrier)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.CreateOrUpdateVault);
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
            await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or NativeCaseFailureException or InvalidOperationException) { }
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task CachedActiveUpdateCannotReplaceOriginalCapturedCompletion()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.CreateOrUpdateVault);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        f.StatusCaptureBypass = true;
        try { await Assert.That(await started.Value!.CheckStatusAsync()).IsEqualTo(SecretStatus.Success); }
        finally { f.StatusCaptureBypass = false; }
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task ActiveUpdateRequiresContrastingOwnedBaselineBeforeDispatch()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.CreateOrUpdateVault);
        var lease = await f.Observer.PostAsync<Op.Prepare, Op.Lease>("operation/prepare", f.PrepareRequest(), default);
        var armed = await f.Observer.SubscribeAsync("operation", lease.Facts, default);
        f.Native.Wire.Vault!["properties"]!["publicNetworkAccess"] = "Enabled";
        await Assert.That(async () => await f.Observer.PostAsync<ObserveLease, Op.Measurement>("operation/observe",
            new(lease.Facts.LeaseId, lease.Facts.Nonce, "baseline-before-dispatch", armed.SubscriptionId), default))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.SelectedUpdates).IsEqualTo(0);
        await Assert.That(f.Native.Read().Resources.Any(r => r.SelectedAttempted)).IsFalse();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    public async Task ActiveUpdatePreparationReplyLossKeepsOriginalCleanupAuthority(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.CreateOrUpdateVault) { PrepareReplyFault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ActiveUpdateRestartRequiresDurableOriginalSettlement(bool settled)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.CreateOrUpdateVault);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        if (settled)
        {
            await f.Observe(lease);
            await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        }
        await f.Source.DisposeAsync();
        await using var restarted = f.NewSource();
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(f.Native.Read().Released).IsEqualTo(settled);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(settled ? 2 : 0);
        await Assert.That(release.ActiveDispatches > 0).IsEqualTo(!settled);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
    }
}
