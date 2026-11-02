using System.Text.Json.Nodes;
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
    [Arguments(200)]
    [Arguments(204)]
    public async Task StatusNotificationDeleteIndependentUsesOriginalAppliedHandleAndOneCachedCheck(int status)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification)
        { SelectedNotificationDeleteStatus = status };
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(1);
        await Assert.That(tap.Checks[0].Canceled).IsFalse();
        await Assert.That(tap.Checks[0].Task.Result).IsEqualTo(SecretStatus.Success);
        await Assert.That(ReferenceEquals(tap.Checks[0].Handle, tap.Start!.Result.Value)).IsTrue();
        await Assert.That(tap.StartReceipt).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads + f.IndependentStatusReads + f.ResourceReads).IsEqualTo(0);
        await Assert.That(f.NotificationDeletes).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        var state = f.Native.Read();
        await Assert.That(state.Released && state.Idle && f.Prejournaled).IsTrue();
        await Assert.That(state.Resources.Length).IsEqualTo(4);
        var child = state.Resources.Single(r => r.Id.Contains("/eventSubscriptions/", StringComparison.Ordinal));
        await Assert.That(child.SelectedAttempted && !child.DeleteAttempted && child.ActiveDispatch == Guid.Empty).IsTrue();
    }

    [Test]
    [Arguments("nonempty")]
    [Arguments("continuation")]
    [Arguments("retry")]
    [Arguments("lost")]
    [Arguments("surviving")]
    [Arguments("read-denied")]
    [Arguments("read-malformed")]
    public async Task StatusNotificationDeleteIndependentRequiresOriginalWireAndOwnedAbsence(string fault)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(0);
    }

    [Test]
    public async Task StatusNotificationDeleteIndependentRejectsAccepted202()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification)
        { SelectedNotificationDeleteStatus = 202 };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("empty")]
    [Arguments("malformed")]
    [Arguments("forbidden")]
    [Arguments("contradictory")]
    public async Task StatusNotificationDeleteIndependentRequiresNativeQualifiedNotFound(string fault)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification)
        { Fault = "read404-" + fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.NotificationReadFaultsReached > 0).IsTrue();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("label")]
    [Arguments("topic")]
    [Arguments("attributes")]
    [Arguments("endpoint")]
    [Arguments("events")]
    [Arguments("state")]
    public async Task StatusNotificationDeleteIndependentRequiresFullOwnedBaseline(string fault)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification);
        var lease = await f.Observer.PostAsync<Op.Prepare, Op.Lease>("operation/prepare", f.PrepareRequest(), default);
        var armed = await f.Observer.SubscribeAsync("operation", lease.Facts, default);
        var properties = f.NotificationRow!["properties"]!;
        switch (fault)
        {
            case "label": properties["labels"] = new JsonArray("foreign"); break;
            case "topic": properties["topic"] = f.Plan().VaultId + "-foreign"; break;
            case "attributes": properties["destination"]!["properties"]!.AsObject().Remove("deliveryAttributeMappings"); break;
            case "endpoint": properties["destination"]!["properties"]!["endpointUrl"] = "https://foreign.invalid/webhook"; break;
            case "events": properties["filter"]!["includedEventTypes"] = new JsonArray("Microsoft.KeyVault.SecretNewVersionCreated"); break;
            default: properties["provisioningState"] = "future-state"; break;
        }
        await Assert.That(async () => await f.Observer.PostAsync<ObserveLease, Op.Measurement>("operation/observe",
            new(lease.Facts.LeaseId, lease.Facts.Nonce, "baseline-before-dispatch", armed.SubscriptionId), default))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.SelectedDeletes).IsEqualTo(0);
        await Assert.That(f.Native.Read().Resources.Any(r => r.SelectedAttempted)).IsFalse();
    }

    [Test]
    public async Task StatusNotificationDeleteIndependentBlocksGenericAndCopiedSettlement()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(() => f.Native.Journal.BeginStatusNotificationDeleteIndependentInvocation(Owner,
            f.Native.Selector, lease.Facts.LeaseId, new Service.StatusNotificationDeleteIndependentAdmission(f.Source)))
            .Throws<InvalidOperationException>();
        var started = await f.Start(lease);
        var observed = await f.Observe(lease);
        await Assert.That(observed.ResourceStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(observed.OperationState).IsEqualTo(NativeProvisioningState.Succeeded);
        var row = f.Native.Read().Resources.Single(r => r.ActiveDispatch != Guid.Empty);
        await Assert.That(row.InvocationTerminated && row.SelectedAttempted && !row.DeleteAttempted && !row.Absent).IsTrue();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.CompleteStatusNotificationDeleteIndependentRead(Owner, f.Native.Selector,
            lease.Facts.LeaseId, row.ActiveDispatch, new Service.StatusNotificationDeleteIndependentSettlement(f.Source, row.ActiveDispatch)))
            .Throws<InvalidOperationException>();
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default)).IsEqualTo(SecretStatus.Success);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes).IsEqualTo(0);
    }

    [Test]
    [Arguments("notification-read")]
    [Arguments("notification-read-body")]
    public async Task StatusNotificationDeleteIndependentCanceledReleaseCannotFakeBorrowerDrain(string barrier)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        f.Barrier = barrier;
        var read = f.Observe(lease).AsTask();
        Task? disposal = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            using var stop = new CancellationTokenSource();
            stop.Cancel();
            var release = f.Observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
                "operation/release", f.Native.Selector, stop.Token).AsTask();
            await Assert.That(async () => await release.WaitAsync(TimeSpan.FromSeconds(10)))
                .Throws<OperationCanceledException>();
            await Assert.That(read.IsCompleted).IsFalse();
            await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
            disposal = f.Source.DisposeAsync().AsTask();
            await Assert.That(disposal.IsCompleted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        try { await read.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException or NativeCaseFailureException) { }
        await disposal!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task StatusNotificationDeleteIndependentForeignHandleCannotStealOnlyCheckSlot()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification);
        await using var other = new PurgeServiceFixture(operation: ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        var foreignLease = await other.PrepareAndBaseline();
        var started = await f.Start(lease);
        var foreign = await other.Start(foreignLease);
        await f.Observe(lease);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, foreign.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default)).IsEqualTo(SecretStatus.Success);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(0);
    }

    [Test]
    public async Task StatusNotificationDeleteIndependentCachedHandleAloneCannotSettle()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await Assert.That(await started.Value!.CheckStatusAsync()).IsEqualTo(SecretStatus.Success);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusNotificationDeleteIndependentJournalCannotBypassChildDependencyOrReplayDelete()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        var child = f.Native.Read().Resources.Single(r => r.Id.Contains("/eventSubscriptions/", StringComparison.Ordinal));
        f.Native.Journal.Close(Owner, f.Native.Selector);
        await Assert.That(() => f.Native.Journal.BeginDispatch(Owner, f.Native.Selector, f.Plan().VaultId, delete: true))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.BeginDispatch(Owner, f.Native.Selector, child.Id, delete: true))
            .Throws<InvalidOperationException>();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    [Arguments("selected-credential")]
    [Arguments("selected-send")]
    [Arguments("selected-body")]
    [Arguments("selected-sdk")]
    [Arguments("notification-read")]
    [Arguments("notification-read-body")]
    public async Task StatusNotificationDeleteIndependentCloseDrainsActualBorrower(string barrier)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification);
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
            await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception ex) when (ex is OperationCanceledException or InvalidOperationException or NativeCaseFailureException) { }
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    public async Task StatusNotificationDeleteIndependentCloseBeforeCheckRetainsFence()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var row = f.Native.Read().Resources.Single(r => r.ActiveDispatch != Guid.Empty);
        f.Native.Journal.Close(Owner, f.Native.Selector);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await f.Release();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == row.Id).ActiveDispatch).IsEqualTo(row.ActiveDispatch);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusNotificationDeleteIndependentReappearanceCannotAuthorizeAnotherDelete()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        var original = f.NotificationRow!.DeepClone().AsObject();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        f.NotificationRow = original;
        await Assert.That((await f.Release()).RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("empty")]
    [Arguments("malformed")]
    [Arguments("forbidden")]
    [Arguments("contradictory")]
    public async Task StatusNotificationDeleteIndependentCleanupRequiresNativeNotFound(string fault)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        f.Fault = "cleanup404-" + fault;
        await Assert.That((await f.Release()).RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.NotificationReadFaultsReached > 0).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusNotificationDeleteIndependentReconstructionCannotInventSettlement(bool settled)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        if (settled) await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        var row = f.Native.Read().Resources.Single(r => r.Id.Contains("/eventSubscriptions/", StringComparison.Ordinal));
        await f.Source.DisposeAsync();
        await using var parent = f.ReopenProvisioner();
        await using var restarted = f.NewSource(cleanupOnly: true, parent: parent);
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(f.Native.Read().Released).IsEqualTo(settled);
        if (settled) RoleFixtureRelease.Validate(release, f.Native.Selector, lease.Facts);
        else await Assert.That(f.Native.Read().Resources.Single(r => r.Id == row.Id).ActiveDispatch).IsEqualTo(row.ActiveDispatch);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes).IsEqualTo(0);
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(settled ? 2 : 0);
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    public async Task StatusNotificationDeleteIndependentNeverSelectedReplyLossUsesOnlySetupCleanup(string fault)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.DeleteNotification)
        { PrepareReplyFault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.SelectedDeletes).IsEqualTo(0);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(3);
    }
}
