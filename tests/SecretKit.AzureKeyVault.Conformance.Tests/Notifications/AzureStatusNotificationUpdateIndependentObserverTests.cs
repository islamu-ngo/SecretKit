using System.Text.Json;
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
    [Arguments("selected-contract")]
    [Arguments("cancellation-boundary")]
    [Arguments("denied-authority")]
    public async Task StatusNotificationUpdateIndependentFactoryRejectsOtherCasesBeforeDeclaration(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, ManagementMutation.UpdateNotification,
            statusNotificationUpdateIndependent: true);
        await Assert.That(async () => await f.Observer.PostAsync<Op.Prepare, Op.Lease>(
            "operation/prepare", f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    public async Task StatusNotificationUpdateIndependentRetainsFourTransitionsAndReadOnlyPersistenceRetry()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification,
            statusNotificationUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        long ready = f.Native.Read().Revision;
        var started = await f.Start(lease);
        var drained = f.Native.Read();
        await Assert.That(drained.Revision).IsEqualTo(ready + 2);
        await Assert.That(f.OriginalReceipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        var retained = f.Source.RetryStatusNotificationUpdateIndependentPersistence(f.Native.Selector);
        await Assert.That(retained.Revision).IsEqualTo(drained.Revision);
        await f.Observe(lease);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(drained.Revision);
        int reads = f.IndependentStatusReads + f.ResourceReads;
        await FinishNotificationUpdateIndependent(f, started.Value!);
        var completed = f.Native.Read();
        await Assert.That(completed.Revision).IsEqualTo(ready + 4);
        await Assert.That(f.OriginalReceipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Source.RetryStatusNotificationUpdateIndependentPersistence(f.Native.Selector).Revision)
            .IsEqualTo(completed.Revision);
        await Assert.That(f.IndependentStatusReads + f.ResourceReads).IsEqualTo(reads);
        await Assert.That(f.OriginalStatusReads + f.OriginalResourceReads).IsEqualTo(1);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusNotificationUpdateIndependentObservationCallerRemainsAVetoAfterResponse()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification,
            statusNotificationUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        using var observation = new CancellationTokenSource();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://purge-observer.example/operation/observe");
        request.Headers.Authorization = new("Bearer", "private-purge-service-capability");
        request.Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(
            new ObserveLease(lease.Facts.LeaseId, lease.Facts.Nonce, "selected-state", f.Armed!.SubscriptionId),
            new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
        request.Content.Headers.ContentType = new("application/json");
        using var response = await f.Source.DispatchAsync(request, observation.Token);
        await Assert.That(response.IsSuccessStatusCode).IsTrue();
        observation.Cancel();
        long revision = f.Native.Read().Revision;
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Revision).IsEqualTo(revision);
        await f.Release();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
    }

    [Test]
    public async Task StatusNotificationUpdateIndependentRetainsPendingReceiptAndOneActualNativeGet()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification, statusNotificationUpdateIndependent: true);
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Start!.Result.Value.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(tap.StartReceipt).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(tap.Checks.Count).IsEqualTo(1);
        await Assert.That(tap.Checks[0].Canceled).IsFalse();
        await Assert.That(tap.Checks[0].Task.Result).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
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
    public async Task StatusNotificationUpdateIndependentCannotReplaceOriginalOrCompleteOwnedRead(string fault)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification, statusNotificationUpdateIndependent: true)
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
    public async Task StatusNotificationUpdateIndependentRequiresActualNativeCompletion(string fault)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification, statusNotificationUpdateIndependent: true)
        { Fault = fault };
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsFalse();
        await Assert.That(tap.Checks.Count).IsEqualTo(1);
        await Assert.That(tap.Checks[0].Task.IsCanceled).IsFalse();
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
    public async Task StatusNotificationUpdateIndependentRejectsMalformedCompleteBaselineAndAfter(string field)
    {
        foreach (bool after in new[] { false, true })
        {
            await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification, statusNotificationUpdateIndependent: true);
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
    public async Task StatusNotificationUpdateIndependentCannotAdoptForeignOrUnexpectedConfiguration(string field)
    {
        foreach (bool after in new[] { false, true })
        {
            await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification, statusNotificationUpdateIndependent: true);
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
    public async Task StatusNotificationUpdateIndependentRejectsUnknownUnconsumedMetadata(bool after)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification, statusNotificationUpdateIndependent: true);
        if (after) f.NotificationPostTransform = row => row["properties"]!["unestablished"] = "future";
        else f.NotificationBaselineTransform = row => row["unestablished"] = "future";
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(after ? 1 : 0);
        await Assert.That(after ? f.NotificationPostMutations : f.NotificationBaselineMutations).IsEqualTo(1);
    }

    [Test]
    public async Task StatusNotificationUpdateIndependentCopiedAdmissionCannotSelectOwnedChild()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification, statusNotificationUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var forged = new Service.StatusNotificationUpdateIndependentAdmission(f.Source);
        await Assert.That(() => f.Native.Journal.BeginStatusNotificationUpdateIndependentInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, forged)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Resources.Any(r => r.SelectedAttempted)).IsFalse();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusNotificationUpdateIndependentForgedSettlementAndGenericApisCannotClearFence()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification, statusNotificationUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var child = f.Native.Read().Resources.Single(r => r.SelectedAttempted);
        var forged = new Service.StatusNotificationUpdateIndependentSettlement(f.Source);
        await Assert.That(() => f.Native.Journal.CompleteStatusNotificationUpdateIndependentRead(Owner,
            f.Native.Selector, lease.Facts.LeaseId, child.ActiveDispatch, forged)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, child.Id,
            child.ActiveDispatch, true)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, child.Id,
            child.ActiveDispatch)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == child.Id).ActiveDispatch).IsEqualTo(child.ActiveDispatch);
        await FinishNotificationUpdateIndependent(f, started.Value!);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusNotificationUpdateIndependentReconstructsActualSourcesOnlyForSettledCleanup(bool settled)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification, statusNotificationUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        if (settled) await FinishNotificationUpdateIndependent(f, started.Value!);
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
    public async Task StatusNotificationUpdateIndependentCloseBeforeLaterCheckRetainsFence()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification, statusNotificationUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
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
    public async Task StatusNotificationUpdateIndependentDisposalDrainsActualBorrower(string barrier)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification, statusNotificationUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        Task work;
        bool status = barrier is "original-final" or "notification-status-body";
        bool after = status || barrier is "notification-read" or "notification-read-body";
        ManagementOperation? handle = null;
        if (after) handle = (await f.Start(lease)).Value!;
        if (status)
        {
            await f.Observe(lease);
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

    [Test]
    public async Task StatusNotificationUpdateIndependentRetainsPrecommitCompletionThroughSharingFailure()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification,
            statusNotificationUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        long before = f.Native.Read().Revision;
        f.Barrier = "original-final";
        var check = f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default).AsTask();
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            using var blocked = new FileStream(f.Native.JournalPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            f.Resume.TrySetResult();
            await Assert.That(async () => await check.WaitAsync(TimeSpan.FromSeconds(10))).Throws<IOException>();
        }
        finally { f.Resume.TrySetResult(); }
        await Assert.That(started.Value!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.OriginalReceipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        int reads = f.IndependentStatusReads + f.ResourceReads + f.OriginalStatusReads + f.OriginalResourceReads;
        var committed = f.Source.RetryStatusNotificationUpdateIndependentPersistence(f.Native.Selector);
        await Assert.That(committed.Revision).IsEqualTo(before + 2);
        await Assert.That(f.Source.RetryStatusNotificationUpdateIndependentPersistence(f.Native.Selector).Revision)
            .IsEqualTo(committed.Revision);
        await Assert.That(f.IndependentStatusReads + f.ResourceReads + f.OriginalStatusReads + f.OriginalResourceReads)
            .IsEqualTo(reads);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusNotificationUpdateIndependentReconstructedParentCannotUsePersistedChildAbsence()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification,
            statusNotificationUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishNotificationUpdateIndependent(f, started.Value!);
        f.Barrier = "parent-cleanup-read";
        var release = f.Release().AsTask();
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var state = f.Native.Read();
            await Assert.That(state.Idle && state.Resources.Single(r =>
                r.Id.Contains("/eventSubscriptions/", StringComparison.Ordinal)).Absent).IsTrue();
            f.Barrier = null;
            await using var reconstructed = f.ReopenProvisioner();
            int deletes = f.SetupDeletes, purges = f.SetupPurges;
            await reconstructed.ReleaseAsync(Owner, f.Native.Selector, purge: true);
            await Assert.That(f.SetupDeletes).IsEqualTo(deletes);
            await Assert.That(f.SetupPurges).IsEqualTo(purges);
        }
        finally { f.Resume.TrySetResult(); }
        await release.WaitAsync(TimeSpan.FromSeconds(10));
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task StatusNotificationUpdateIndependentFixtureRetryRetainsOriginalRequestVeto(bool child, bool cleanup)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdateNotification,
            statusNotificationUpdateIndependent: true);
        if (cleanup)
        {
            var lease = await f.PrepareAndBaseline();
            var started = await f.Start(lease);
            await f.Observe(lease);
            await FinishNotificationUpdateIndependent(f, started.Value!);
        }
        f.Barrier = cleanup
            ? child ? "notification-cleanup-body" : "parent-cleanup-body"
            : child ? "notification-setup-status-body" : "parent-setup";
        using var caller = new CancellationTokenSource();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://purge-observer.example/operation/" +
            (cleanup ? "release" : "prepare"));
        request.Headers.Authorization = new("Bearer", "private-purge-service-capability");
        var json = new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false };
        request.Content = new ByteArrayContent(cleanup
            ? JsonSerializer.SerializeToUtf8Bytes(f.Native.Selector, json)
            : JsonSerializer.SerializeToUtf8Bytes(f.PrepareRequest(), json));
        request.Content.Headers.ContentType = new("application/json");
        var work = f.Source.DispatchAsync(request, caller.Token);
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            using var blocked = new FileStream(f.Native.JournalPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            f.Resume.TrySetResult();
            using var response = await work.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(response.IsSuccessStatusCode).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        var before = f.Native.Read();
        var active = before.Resources.Single(r => r.ActiveDispatch != Guid.Empty);
        var (component, childPlan) = RetainedNotificationUpdateIndependentFixture(f.Source, f.Native.Selector.Nonce);
        await Assert.That(child ? childPlan.Receipts.Last().RemoteSettled : f.Plan().History.Last().RemoteSettled).IsTrue();
        caller.Cancel();
        try
        {
            if (child)
                using (await component.SettleAsync(Owner, f.Native.Selector, childPlan.Scope.SubscriptionName)) { }
            else await f.SettleParentAsync();
        }
        catch (InvalidOperationException) { }
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == active.Id).ActiveDispatch)
            .IsEqualTo(active.ActiveDispatch);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    private static (NotificationFixtureProvisioner Source, NotificationFixtureProvisioner.Plan Plan)
        RetainedNotificationUpdateIndependentFixture(Service source, Guid nonce)
    {
        var flags = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic |
            System.Reflection.BindingFlags.Public;
        // Read the actual retained objects; never replace source state or issue authority.
        var sessions = (System.Collections.IDictionary)typeof(Service).GetField("sessions", flags)!.GetValue(source)!;
        var session = sessions[nonce]!;
        return ((NotificationFixtureProvisioner)session.GetType().GetField("Notifications", flags)!.GetValue(session)!,
            (NotificationFixtureProvisioner.Plan)session.GetType().GetField("NotificationPlan", flags)!.GetValue(session)!);
    }

    private static async Task FinishNotificationUpdateIndependent(PurgeServiceFixture f, ManagementOperation handle)
    {
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, handle, default))
            .IsEqualTo(SecretStatus.Success);
    }
}
