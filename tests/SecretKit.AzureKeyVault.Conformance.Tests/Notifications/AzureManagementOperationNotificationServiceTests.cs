using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments(200)]
    [Arguments(204)]
    public async Task OriginalSynchronousNotificationDeletionServiceJoinsResponseProofAndOwnedAbsence(int status)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteNotification)
        { SelectedNotificationDeleteStatus = status };
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads + f.IndependentStatusReads + f.ResourceReads).IsEqualTo(0);
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(4);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.Prejournaled).IsTrue();
        await Assert.That(f.NotificationDeletes).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    [Arguments("nonempty")]
    [Arguments("continuation")]
    [Arguments("retry")]
    [Arguments("lost")]
    [Arguments("surviving")]
    [Arguments("read-denied")]
    [Arguments("read-malformed")]
    public async Task SynchronousNotificationDeletionCannotSubstituteCacheOrAbsenceForOriginalProof(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteNotification) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(0);
    }

    [Test]
    public async Task AsynchronousNotificationDeletionCannotBorrowSynchronousResponseAuthority()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteNotification)
        { SelectedNotificationDeleteStatus = 202 };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("denied-authority")]
    public async Task SynchronousNotificationDeletionRejectsUnadmittedCasesBeforeDeclaration(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, ManagementMutation.DeleteNotification);
        await Assert.That(async () => await f.Observer.PostAsync<
            ManagementOperationEffects.Prepare, ManagementOperationEffects.Lease>(
                "operation/prepare", f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    public async Task SynchronousNotificationDeletionPreparationReplyLossUsesOnlySetupCleanup(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteNotification) { PrepareReplyFault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(3);
    }

    [Test]
    [Arguments("selected-send")]
    [Arguments("notification-read")]
    public async Task SynchronousNotificationDeletionDisposalDrainsOriginalAndIndependentBorrowers(string barrier)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        Task work;
        if (barrier == "selected-send")
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
        Task? disposal = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
            disposal = f.Source.DisposeAsync().AsTask();
            await Assert.That(disposal.IsCompleted || work.IsCompleted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or NativeCaseFailureException or InvalidOperationException) { }
        await disposal!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SynchronousNotificationDeletionRestartCannotReconstructOriginalProof(bool complete)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        if (complete) await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        await f.Source.DisposeAsync();
        await using var restarted = f.NewSource(cleanupOnly: true);
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(release.ActiveDispatches == 0).IsEqualTo(complete);
        await Assert.That(f.Native.Read().Released).IsEqualTo(complete);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes).IsEqualTo(0);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(complete ? 2 : 0);
    }

    [Test]
    public async Task SynchronousNotificationDeletionRequiresItsExactOriginalHandle()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteNotification);
        await using var other = new PurgeServiceFixture(operation: ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        var foreignLease = await other.PrepareAndBaseline();
        var started = await f.Start(lease);
        var foreign = await other.Start(foreignLease);
        await f.Observe(lease);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, foreign.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Success);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That((await other.Release()).ActiveDispatches > 0).IsTrue();
    }

    [Test]
    public async Task SynchronousNotificationDeletionCachedCompletionStillRequiresIndependentAbsence()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await Assert.That(await started.Value!.CheckStatusAsync()).IsEqualTo(SecretStatus.Success);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        var measured = await f.Observe(lease);
        await Assert.That(measured.ResourceStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(measured.OperationState).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Success);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(0);
    }

    [Test]
    public async Task SynchronousNotificationDeletionHistoricalProofCannotReopenClosedRoot()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task SynchronousNotificationDeletionServiceNeverReplaysDeleteOnReappearingChild()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        var original = f.NotificationRow!.DeepClone().AsObject();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        f.NotificationRow = original;
        var release = await f.Release();
        await Assert.That(release.RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task OriginalOwnedNotificationPutServiceUsesOriginalPayloadAndCompleteCleanup()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.CreateOrUpdateNotification);
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.Prejournaled).IsTrue();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(4);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(3);
        await Assert.That(f.RecoveryRequest!["properties"]!.AsObject().Select(p => p.Key).ToArray())
            .IsEquivalentTo(["destination", "filter"]);
    }

    [Test]
    [Arguments("foreign-label")]
    [Arguments("missing-label")]
    [Arguments("foreign-topic")]
    [Arguments("hidden-configuration")]
    [Arguments("configuration")]
    [Arguments("unchanged")]
    [Arguments("absent")]
    [Arguments("malformed")]
    [Arguments("failed")]
    [Arguments("status-denied")]
    [Arguments("lost")]
    public async Task OwnedNotificationPutServiceCannotReplaceIndependentEvidence(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.CreateOrUpdateNotification) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task OwnedNotificationPutServiceCachedStatusCannotSettleDispatch()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.CreateOrUpdateNotification);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        f.StatusCaptureBypass = true;
        try { await Assert.That(await started.Value!.CheckStatusAsync()).IsEqualTo(SecretStatus.Success); }
        finally { f.StatusCaptureBypass = false; }
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Success);
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    public async Task OwnedNotificationPutServiceRejectsUnadmittedCasesBeforeDeclaration(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, ManagementMutation.CreateOrUpdateNotification);
        await Assert.That(async () => await f.Observer.PostAsync<
            ManagementOperationEffects.Prepare, ManagementOperationEffects.Lease>(
                "operation/prepare", f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    public async Task OwnedNotificationPutPreparationReplyLossCleansOriginalRows(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.CreateOrUpdateNotification) { PrepareReplyFault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.SelectedUpdates).IsEqualTo(0);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(3);
    }

    [Test]
    [Arguments("selected-send")]
    [Arguments("status-send")]
    [Arguments("notification-read")]
    [Arguments("original-final")]
    public async Task OwnedNotificationPutServiceDisposalDrainsActualBorrowers(string barrier)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.CreateOrUpdateNotification);
        var lease = await f.PrepareAndBaseline();
        Task work;
        if (barrier == "selected-send")
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
        Task? disposal = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
            disposal = f.Source.DisposeAsync().AsTask();
            await Assert.That(disposal.IsCompleted || work.IsCompleted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or NativeCaseFailureException or InvalidOperationException) { }
        await disposal!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OwnedNotificationPutRestartPreservesOriginalSettlement(bool complete)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.CreateOrUpdateNotification);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        if (complete) await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        await f.Source.DisposeAsync();
        await using var restarted = f.NewSource(cleanupOnly: true);
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(release.ActiveDispatches == 0).IsEqualTo(complete);
        await Assert.That(f.Native.Read().Released).IsEqualTo(complete);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(complete ? 3 : 0);
    }

    [Test]
    public async Task OriginalNotificationStatusServiceJoinsOwnedReadbackAndSingleNativeCompletion()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdateNotification);
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.ResourceReads).IsEqualTo(0);
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(4);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.Prejournaled).IsTrue();
        await Assert.That(f.RecoveryRequest!.ContainsKey("labels")).IsFalse();
    }

    [Test]
    [Arguments("foreign-label")]
    [Arguments("missing-label")]
    [Arguments("foreign-topic")]
    [Arguments("hidden-configuration")]
    [Arguments("configuration")]
    [Arguments("absent")]
    [Arguments("malformed")]
    [Arguments("failed")]
    [Arguments("status-denied")]
    [Arguments("lost")]
    public async Task NotificationServiceCannotSettleFromUnqualifiedSelectedEvidence(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdateNotification) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task NotificationServiceCachedCompletionCannotClearSelectedFence()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdateNotification);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(lease.NotificationName).IsNotNull();
        await Assert.That(lease.Facts.ApiRevision).IsEqualTo("2025-02-15");
        var started = await f.Start(lease);
        f.StatusCaptureBypass = true;
        try { await Assert.That(await started.Value!.CheckStatusAsync()).IsEqualTo(SecretStatus.Success); }
        finally { f.StatusCaptureBypass = false; }
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Success);
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    public async Task NotificationPreparationReplyLossCleansTheOriginalFourRows(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdateNotification) { PrepareReplyFault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(4);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.SelectedUpdates).IsEqualTo(0);
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    public async Task NotificationServiceRejectsUnadmittedCasesBeforeDeclaration(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, ManagementMutation.UpdateNotification);
        await Assert.That(async () => await f.Observer.PostAsync<
            ManagementOperationEffects.Prepare, ManagementOperationEffects.Lease>(
                "operation/prepare", f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
        await Assert.That(f.NotificationRow).IsNull();
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("lease")]
    [Arguments("subscription")]
    public async Task NotificationServiceRejectsForeignObservationBindingsBeforeReads(string field)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdateNotification);
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        var request = new ObserveLease(lease.Facts.LeaseId, lease.Facts.Nonce, "selected-state", f.Armed!.SubscriptionId);
        request = field switch
        {
            "nonce" => request with { Nonce = Guid.NewGuid() },
            "lease" => request with { LeaseId = Guid.NewGuid() },
            _ => request with { SubscriptionId = Guid.NewGuid() }
        };
        await Assert.That(async () => await f.Observer.PostAsync<ObserveLease, ManagementOperationEffects.Measurement>(
            "operation/observe", request, default)).Throws<NativeCaseFailureException>();
        await Assert.That(f.IndependentStatusReads).IsEqualTo(0);
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
    }

    [Test]
    [Arguments("selected-send")]
    [Arguments("status-send")]
    [Arguments("notification-read")]
    [Arguments("original-final")]
    public async Task NotificationServiceDisposalDrainsActualSelectedAndObserverBorrowers(string barrier)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdateNotification);
        var lease = await f.PrepareAndBaseline();
        Task work;
        if (barrier == "selected-send")
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
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or NativeCaseFailureException or InvalidOperationException) { }
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task RestartedNotificationServiceCannotAdoptLostSelectedDispatch()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdateNotification) { Fault = "lost" };
        var lease = await f.PrepareAndBaseline();
        try { await f.Start(lease); } catch (InvalidOperationException) { }
        var dispatch = f.Native.Read().Resources.Single(r => r.ActiveDispatch != Guid.Empty).ActiveDispatch;
        await f.Source.DisposeAsync();
        await using var restarted = f.NewSource();
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(release.ActiveDispatches > 0).IsTrue();
        await Assert.That(f.Native.Read().Resources.Single(r => r.ActiveDispatch != Guid.Empty).ActiveDispatch).IsEqualTo(dispatch);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("missing-source")]
    [Arguments("cleanup-only")]
    [Arguments("endpoint")]
    public async Task NotificationServiceRequiresExplicitReadyHostBaselineBeforeDeclaration(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdateNotification);
        await using var source = f.NewSource(cleanupOnly: fault == "cleanup-only",
            omitNotificationSource: fault == "missing-source");
        using var observer = f.NewObserver(source);
        var request = f.PrepareRequest();
        if (fault == "endpoint") request = request with { WebhookUrl = "https://foreign.example/webhook" };
        await Assert.That(async () => await observer.PostAsync<
            ManagementOperationEffects.Prepare, ManagementOperationEffects.Lease>(
                "operation/prepare", request, default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
        await Assert.That(f.NotificationRow).IsNull();
    }

    [Test]
    public async Task CleanupOnlyNotificationRestartReleasesOriginalUnselectedRootOnce()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdateNotification);
        var lease = await f.PrepareAndBaseline();
        string[] ids = f.Native.Read().Resources.Select(r => r.Id).ToArray();
        await f.Source.DisposeAsync();
        await using var source = f.NewSource(cleanupOnly: true);
        using var observer = f.NewObserver(source);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        RoleFixtureRelease.Validate(release, f.Native.Selector, lease.Facts);
        await Assert.That(f.Native.Read().Resources.Select(r => r.Id).ToArray()).IsEquivalentTo(ids);
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        RoleFixtureRelease.Validate(await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default), f.Native.Selector, lease.Facts);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(3);
    }

    [Test]
    public async Task NotificationSetupDisposalKeepsHostOwnedTransportAndRoot()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdateNotification)
        { Barrier = "notification-setup" };
        var preparation = f.Observer.PostAsync<ManagementOperationEffects.Prepare, ManagementOperationEffects.Lease>(
            "operation/prepare", f.PrepareRequest(), default).AsTask();
        Task? disposal = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            disposal = f.Source.DisposeAsync().AsTask();
            await Assert.That(disposal.IsCompleted || preparation.IsCompleted).IsFalse();
            await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        }
        finally { f.Resume.TrySetResult(); }
        await Assert.That(async () => await preparation.WaitAsync(TimeSpan.FromSeconds(10)))
            .Throws<NativeCaseFailureException>();
        await disposal!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        // Reuse host-owned authorities after service disposal. The uncertain
        // creation stays fenced rather than being replayed by the new service.
        await using var restarted = f.NewSource(cleanupOnly: true);
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(release.ActiveDispatches > 0).IsTrue();
    }
}
