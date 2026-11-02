using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Service = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task StatusNotificationCreateCancellationRetainsPendingReceiptAndOneActualNativeGet()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.CreateOrUpdateNotification);
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Start!.Result.Value.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(tap.StartReceipt).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(tap.Checks.Count).IsEqualTo(2);
        await Assert.That(tap.Checks[0].Canceled && tap.Checks[0].Task.IsCanceled).IsTrue();
        await Assert.That(tap.Checks[1].Canceled).IsFalse();
        await Assert.That(tap.Checks[1].Task.Result).IsEqualTo(SecretStatus.Success);
        await Assert.That(ReferenceEquals(tap.Checks[0].Task, tap.Checks[1].Task)).IsFalse();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.RecoveryRequest!["properties"]!.AsObject().Select(p => p.Key).ToArray())
            .IsEquivalentTo(["destination", "filter"]);
        await Assert.That(f.Prejournaled).IsTrue();
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        var root = f.Native.Read();
        await Assert.That(root.Released && root.Idle).IsTrue();
        await Assert.That(root.Resources.Length).IsEqualTo(4);
        await Assert.That(JsonSerializer.Serialize(root).Contains(Material, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("foreign-label")]
    [Arguments("missing-label")]
    [Arguments("foreign-topic")]
    [Arguments("hidden-configuration")]
    [Arguments("configuration")]
    [Arguments("absent")]
    [Arguments("malformed")]
    [Arguments("failed")]
    [Arguments("nonterminal")]
    public async Task StatusNotificationCreateCancellationCannotReplaceOriginalOrCompleteOwnedRead(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.CreateOrUpdateNotification)
        { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("original-denied")]
    [Arguments("original-malformed")]
    [Arguments("original-lost")]
    [Arguments("original-updating")]
    [Arguments("original-foreign-topic")]
    [Arguments("original-foreign-name")]
    public async Task StatusNotificationCreateCancellationRequiresActualNativeCompletion(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.CreateOrUpdateNotification)
        { Fault = fault };
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsFalse();
        await Assert.That(tap.Checks.Count).IsEqualTo(2);
        await Assert.That(tap.Checks[0].Task.IsCanceled).IsTrue();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("id")]
    [Arguments("name")]
    [Arguments("type")]
    [Arguments("properties.topic")]
    [Arguments("properties.provisioningState")]
    [Arguments("properties.labels")]
    [Arguments("properties.filter.includedEventTypes")]
    [Arguments("properties.filter.subjectBeginsWith")]
    [Arguments("properties.filter.subjectEndsWith")]
    [Arguments("properties.filter.isSubjectCaseSensitive")]
    [Arguments("properties.filter.advancedFilters")]
    [Arguments("properties.destination.endpointType")]
    [Arguments("properties.destination.properties.endpointUrl")]
    [Arguments("properties.destination.properties.deliveryAttributeMappings")]
    [Arguments("properties.destination.properties.maxEventsPerBatch")]
    [Arguments("properties.destination.properties.preferredBatchSizeInKilobytes")]
    public async Task StatusNotificationCreateCancellationRejectsMalformedCompleteBaselineAndAfter(string field)
    {
        foreach (bool after in new[] { false, true })
        {
            await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.CreateOrUpdateNotification);
            void Malformed(JsonObject row)
            {
                string[] parts = field.Split('.');
                var parent = row;
                foreach (string part in parts[..^1])
                {
                    if (parent[part] is null) parent[part] = new JsonObject();
                    parent = parent[part]!.AsObject();
                }
                parent[parts[^1]] = true;
            }
            if (after) f.NotificationPostTransform = Malformed;
            else f.NotificationBaselineTransform = Malformed;
            await Assert.That((await f.RunOriginal()).Passed).IsFalse();
            await Assert.That(f.SelectedUpdates).IsEqualTo(after ? 1 : 0);
            await Assert.That(after ? f.NotificationPostMutations : f.NotificationBaselineMutations).IsEqualTo(1);
            await Assert.That(f.NotificationDeletes).IsEqualTo(after ? 0 : 1);
            await Assert.That(f.Native.Read().Released).IsEqualTo(!after);
        }
    }

    [Test]
    [Arguments("id")]
    [Arguments("name")]
    [Arguments("topic")]
    [Arguments("label")]
    [Arguments("events")]
    public async Task StatusNotificationCreateCancellationCannotAdoptForeignOrUnexpectedConfiguration(string field)
    {
        foreach (bool after in new[] { false, true })
        {
            await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.CreateOrUpdateNotification);
            void Foreign(JsonObject row)
            {
                if (field == "id") row["id"] = row["id"]!.GetValue<string>() + "-foreign";
                if (field == "name") row["name"] = "foreign-subscription";
                if (field == "topic") row["properties"]!["topic"] =
                    row["properties"]!["topic"]!.GetValue<string>() + "-foreign";
                if (field == "label") row["properties"]!["labels"] = new JsonArray("foreign-owner");
                if (field == "events") row["properties"]!["filter"]!["includedEventTypes"] = new JsonArray(
                    after ? "Microsoft.KeyVault.SecretNearExpiry" : "Microsoft.KeyVault.SecretNewVersionCreated");
            }
            if (after) f.NotificationPostTransform = Foreign;
            else f.NotificationBaselineTransform = Foreign;
            await Assert.That((await f.RunOriginal()).Passed).IsFalse();
            await Assert.That(f.SelectedUpdates).IsEqualTo(after ? 1 : 0);
            await Assert.That(after ? f.NotificationPostMutations : f.NotificationBaselineMutations).IsEqualTo(1);
            await Assert.That(f.Native.Read().Released).IsEqualTo(!after);
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusNotificationCreateCancellationRejectsUnknownUnconsumedMetadata(bool after)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.CreateOrUpdateNotification);
        if (after) f.NotificationPostTransform = row => row["properties"]!["unestablished"] = "future";
        else f.NotificationBaselineTransform = row => row["unestablished"] = "future";
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(after ? 1 : 0);
        await Assert.That(after ? f.NotificationPostMutations : f.NotificationBaselineMutations).IsEqualTo(1);
    }

    [Test]
    public async Task StatusNotificationCreateCancellationCopiedAdmissionCannotSelectOwnedChild()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.CreateOrUpdateNotification);
        var lease = await f.PrepareAndBaseline();
        var forged = new Service.StatusNotificationCreateCancellationAdmission(f.Source);
        await Assert.That(() => f.Native.Journal.BeginStatusNotificationCreateInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, forged)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Resources.Any(r => r.SelectedAttempted)).IsFalse();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusNotificationCreateCancellationForgedSettlementAndGenericApisCannotClearFence()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.CreateOrUpdateNotification);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var child = f.Native.Read().Resources.Single(r => r.SelectedAttempted);
        var forged = new Service.StatusNotificationCreateCancellationSettlement(f.Source, child.ActiveDispatch);
        await Assert.That(() => f.Native.Journal.CompleteStatusNotificationCreateCancellationRead(Owner,
            f.Native.Selector, lease.Facts.LeaseId, child.ActiveDispatch, forged)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, child.Id,
            child.ActiveDispatch, true)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, child.Id,
            child.ActiveDispatch)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == child.Id).ActiveDispatch).IsEqualTo(child.ActiveDispatch);
        await FinishNotificationCreateCancellation(f, started.Value!);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusNotificationCreateCancellationInvalidFirstServiceCheckCannotStealSlot(bool independent)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.CreateOrUpdateNotification);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        if (independent) await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!,
            independent ? default : stop.Token)).Throws<InvalidOperationException>();
        if (independent)
        {
            await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
                .Throws<InvalidOperationException>();
            await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
                .Throws<InvalidOperationException>();
            await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
            await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        }
        else
        {
            await f.Observe(lease);
            await FinishNotificationCreateCancellation(f, started.Value!);
            await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
            RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusNotificationCreateCancellationReconstructsActualSourcesOnlyForSettledCleanup(bool settled)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.CreateOrUpdateNotification);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        if (settled) await FinishNotificationCreateCancellation(f, started.Value!);
        await f.Source.DisposeAsync();
        var parent = f.ReopenProvisioner();
        await using var restarted = f.NewSource(cleanupOnly: true, parent: parent);
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(f.Native.Read().Released).IsEqualTo(settled);
        await Assert.That(release.RemainingResourceIds.Length == 0).IsEqualTo(settled);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes).IsEqualTo(settled ? 1 : 0);
    }

    [Test]
    public async Task StatusNotificationCreateCancellationCloseBeforeLaterCheckRetainsFence()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.CreateOrUpdateNotification);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        f.Native.Journal.Close(Owner, f.Native.Selector);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-credential")]
    [Arguments("selected-body")]
    [Arguments("selected-sdk")]
    [Arguments("notification-read")]
    [Arguments("notification-read-body")]
    [Arguments("original-final")]
    [Arguments("notification-status-body")]
    public async Task StatusNotificationCreateCancellationDisposalDrainsActualBorrower(string barrier)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.CreateOrUpdateNotification);
        var lease = await f.PrepareAndBaseline();
        Task work;
        bool status = barrier is "original-final" or "notification-status-body";
        bool after = status || barrier is "notification-read" or "notification-read-body";
        ManagementOperation? handle = null;
        if (after) handle = (await f.Start(lease)).Value!;
        if (status)
        {
            await f.Observe(lease);
            using var stop = new CancellationTokenSource();
            stop.Cancel();
            await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, handle!, stop.Token))
                .Throws<OperationCanceledException>();
        }
        f.Barrier = barrier;
        work = status ? f.Source.RunCheckStatusAsync(f.Native.Selector, handle!, default).AsTask() :
            after ? f.Observe(lease).AsTask() : f.Start(lease);
        Task? closing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            closing = f.Source.DisposeAsync().AsTask();
            await Assert.That(f.Native.Read().Closing).IsTrue();
            await Assert.That(work.IsCompleted || closing.IsCompleted).IsFalse();
            await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException or NativeCaseFailureException) { }
        await closing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    private static async Task FinishNotificationCreateCancellation(PurgeServiceFixture f, ManagementOperation handle)
    {
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, handle, stop.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, handle, default))
            .IsEqualTo(SecretStatus.Success);
    }
}
