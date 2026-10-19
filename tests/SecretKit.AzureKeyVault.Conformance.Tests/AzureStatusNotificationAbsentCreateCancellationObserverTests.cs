using System.Buffers.Binary;
using System.Security.Cryptography;
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
    [Arguments("absent")]
    [Arguments("empty")]
    public async Task StatusNotificationAbsentCreateUsesOriginalPutWithoutSetupOrFabricatedLabel(string labels)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary",
            ManagementMutation.CreateOrUpdateNotification, exclusiveNotificationCreation: true)
        { NotificationCreatedLabels = labels };
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(f.NotificationSetupPuts).IsEqualTo(0);
        await Assert.That(f.NotificationPreparationAbsences > 0).IsTrue();
        await Assert.That(f.NotificationArmedAbsences).IsEqualTo(1);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.Prejournaled).IsTrue();
        await Assert.That(f.RecoveryRequest!["properties"]!.AsObject().Select(p => p.Key).ToArray())
            .IsEquivalentTo(["destination", "filter"]);
        await Assert.That(tap.StartReceipt).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(tap.Start!.Result.Value.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(tap.Checks.Count).IsEqualTo(2);
        await Assert.That(tap.Checks[0].Task.IsCanceled).IsTrue();
        await Assert.That(tap.Checks[1].Task.Result).IsEqualTo(SecretStatus.Success);
        await Assert.That(ReferenceEquals(tap.Checks[0].Task, tap.Checks[1].Task)).IsFalse();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        var state = f.Native.Read();
        var creation = state.NotificationAbsentCreate!;
        await Assert.That(creation.NamespaceEpoch).IsEqualTo(f.NotificationNamespaceEpoch);
        await Assert.That(creation.InvocationDispatch != Guid.Empty &&
            creation.InvocationDispatch == creation.SettledDispatch).IsTrue();
        await Assert.That(new[] { creation.BaselineSha256, creation.StartSha256, creation.SelectedSha256,
            creation.CompletionSha256, creation.ConfigurationSha256 }.All(h => h is { Length: 64 })).IsTrue();
        await Assert.That(state.Released && state.Idle).IsTrue();
        await Assert.That(state.Resources.Length).IsEqualTo(4);
        await Assert.That(JsonSerializer.Serialize(state).Contains(Material, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("null")]
    [Arguments("nonce")]
    [Arguments("foreign")]
    public async Task StatusNotificationAbsentCreateRejectsAnyUnestablishedLabel(string labels)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary",
            ManagementMutation.CreateOrUpdateNotification, exclusiveNotificationCreation: true)
        { NotificationCreatedLabels = labels };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.NotificationSetupPuts).IsEqualTo(0);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("")]
    [Arguments("{")]
    [Arguments("""{"error":{"code":"Forbidden"}}""")]
    [Arguments("""{"error":{"code":"NotFound","details":[{"code":"Forbidden"}]}}""")]
    public async Task StatusNotificationAbsentCreateRequiresFreshNativeNotFoundBaseline(string body)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary",
            ManagementMutation.CreateOrUpdateNotification, exclusiveNotificationCreation: true)
        { NotificationAbsent404Body = body };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.NotificationArmedAbsences).IsEqualTo(1);
        await Assert.That(f.NotificationSetupPuts + f.SelectedUpdates).IsEqualTo(0);
        await Assert.That(f.NotificationDeletes).IsEqualTo(0);
    }

    [Test]
    [Arguments("lost")]
    [Arguments("absent")]
    [Arguments("malformed")]
    [Arguments("configuration")]
    [Arguments("hidden-configuration")]
    [Arguments("foreign-topic")]
    [Arguments("original-denied")]
    [Arguments("original-malformed")]
    [Arguments("original-lost")]
    [Arguments("original-updating")]
    public async Task StatusNotificationAbsentCreateCannotSettleWithoutCompleteOriginalAndIndependentEvidence(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary",
            ManagementMutation.CreateOrUpdateNotification, exclusiveNotificationCreation: true)
        { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.NotificationSetupPuts).IsEqualTo(0);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments(1, "response")]
    [Arguments(1, "stream")]
    [Arguments(1, "null-stream")]
    [Arguments(2, "response")]
    [Arguments(2, "stream")]
    [Arguments(2, "null-stream")]
    public async Task StatusNotificationAbsentCreateRejectsActualNativeParserSubstitution(int stage, string change)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary",
            ManagementMutation.CreateOrUpdateNotification, exclusiveNotificationCreation: true);
        var lease = await f.PrepareAndBaseline();
        f.NotificationParserReplacementStage = stage;
        f.NotificationParserReplacement = change;
        var started = await f.Start(lease);
        if (stage == 2)
        {
            await f.Observe(lease);
            using var stop = new CancellationTokenSource();
            stop.Cancel();
            await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
                .Throws<OperationCanceledException>();
            await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
                .Throws<InvalidOperationException>();
        }
        await Assert.That(f.NotificationParserReplacements).IsEqualTo(1);
        await Assert.That(f.Native.Read().NotificationAbsentCreate!.SettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusNotificationAbsentCreateDeclarationRequiresEpochAndContinuousExclusion(bool emptyEpoch)
    {
        await Assert.That(() => new NotificationFixtureProvisioner.ExclusiveCreationDeclaration(
            emptyEpoch ? Guid.Empty : Guid.NewGuid(), emptyEpoch)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("id")]
    [Arguments("name")]
    [Arguments("type")]
    [Arguments("properties.topic")]
    [Arguments("properties.provisioningState")]
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
    public async Task StatusNotificationAbsentCreateRequiresCompleteIndependentNativeConfiguration(string field)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary",
            ManagementMutation.CreateOrUpdateNotification, exclusiveNotificationCreation: true);
        f.NotificationPostTransform = row =>
        {
            string[] parts = field.Split('.');
            var parent = row;
            foreach (string part in parts[..^1])
            {
                if (parent[part] is null) parent[part] = new JsonObject();
                parent = parent[part]!.AsObject();
            }
            parent[parts[^1]] = true;
        };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.NotificationPostMutations).IsEqualTo(1);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("same", false)]
    [Arguments("same", true)]
    [Arguments("missing", true)]
    [Arguments("different", true)]
    public async Task StatusNotificationAbsentCreateReconstructsOnlySettledSameEpochCleanup(string epoch, bool settled)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary",
            ManagementMutation.CreateOrUpdateNotification, exclusiveNotificationCreation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        if (settled) await FinishNotificationCreateCancellation(f, started.Value!);
        await f.Source.DisposeAsync();
        await using var restarted = f.NewSource(cleanupOnly: true, parent: f.ReopenProvisioner(),
            omitExclusiveCreation: epoch == "missing",
            notificationEpoch: epoch == "different" ? Guid.NewGuid() : f.NotificationNamespaceEpoch);
        using var observer = f.NewObserver(restarted);
        bool accepted = settled && epoch == "same";
        try
        {
            await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
                "operation/release", f.Native.Selector, default);
        }
        catch (NativeCaseFailureException) when (!accepted) { }
        await Assert.That(f.Native.Read().Released).IsEqualTo(accepted);
        await Assert.That(f.NotificationDeletes).IsEqualTo(accepted ? 1 : 0);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.NotificationSetupPuts).IsEqualTo(0);
    }

    [Test]
    [Arguments("endpoint")]
    [Arguments("event")]
    [Arguments("label")]
    [Arguments("unknown")]
    public async Task StatusNotificationAbsentCreateCleanupCannotAdoptChangedOrForeignChild(string change)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary",
            ManagementMutation.CreateOrUpdateNotification, exclusiveNotificationCreation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishNotificationCreateCancellation(f, started.Value!);
        if (change == "endpoint")
            f.NotificationRow!["properties"]!["destination"]!["properties"]!["endpointUrl"] = "https://different.example/webhook";
        if (change == "event")
            f.NotificationRow!["properties"]!["filter"]!["includedEventTypes"] = new JsonArray("Microsoft.KeyVault.SecretNearExpiry");
        if (change == "label") f.NotificationRow!["properties"]!["labels"] = new JsonArray("foreign-owner");
        if (change == "unknown") f.NotificationRow!["properties"]!["future-field"] = true;
        await Assert.That((await f.Release()).RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusNotificationAbsentCreateInvalidFirstStatusAttemptCannotBeRetried(bool later)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary",
            ManagementMutation.CreateOrUpdateNotification, exclusiveNotificationCreation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        if (later)
            await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
                .Throws<OperationCanceledException>();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!,
            later ? stop.Token : default)).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
    }

    [Test]
    public async Task StatusNotificationAbsentCreateForgedTypedAndGenericSettlementCannotClearFence()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary",
            ManagementMutation.CreateOrUpdateNotification, exclusiveNotificationCreation: true);
        var lease = await f.PrepareAndBaseline();
        var copied = new Service.StatusNotificationCreateCancellationAdmission(f.Source);
        await Assert.That(() => f.Native.Journal.BeginStatusNotificationAbsentCreateInvocation(Owner,
            f.Native.Selector, lease.Facts.LeaseId, copied)).Throws<InvalidOperationException>();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var child = f.Native.Read().Resources.Single(r => r.SelectedAttempted);
        var forged = new Service.StatusNotificationCreateCancellationSettlement(f.Source, child.ActiveDispatch);
        await Assert.That(() => f.Native.Journal.CompleteStatusNotificationAbsentCreateCancellationRead(Owner,
            f.Native.Selector, lease.Facts.LeaseId, child.ActiveDispatch, forged)).Throws<InvalidOperationException>();
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
    public async Task StatusNotificationAbsentCreateCloseBeforeCompletionKeepsDurableFence(bool canceled)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary",
            ManagementMutation.CreateOrUpdateNotification, exclusiveNotificationCreation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        if (canceled)
            await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
                .Throws<OperationCanceledException>();
        f.Native.Journal.Close(Owner, f.Native.Selector);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!,
            canceled ? default : stop.Token)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().NotificationAbsentCreate!.SettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("remove")]
    [Arguments("epoch")]
    [Arguments("parent")]
    [Arguments("child")]
    [Arguments("version")]
    [Arguments("dispatch")]
    [Arguments("settlement")]
    [Arguments("configuration")]
    public async Task StatusNotificationAbsentCreateRejectsChecksummedProvenanceHistoryChanges(string change)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary",
            ManagementMutation.CreateOrUpdateNotification, exclusiveNotificationCreation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishNotificationCreateCancellation(f, started.Value!);
        await f.Source.DisposeAsync();
        await f.DrainParentAsync();
        var state = f.Native.Read();
        var creation = state.NotificationAbsentCreate!;
        var altered = state with
        {
            NotificationAbsentCreate = change switch
            {
                "remove" => null,
                "epoch" => creation with { NamespaceEpoch = Guid.NewGuid() },
                "parent" => creation with { ParentId = creation.ParentId + "-foreign" },
                "child" => creation with { ChildId = creation.ChildId + "-foreign" },
                "version" => creation with { ContractVersion = 2 },
                "dispatch" => creation with { InvocationDispatch = Guid.NewGuid() },
                "settlement" => creation with { SettledDispatch = Guid.Empty },
                _ => creation with { ConfigurationSha256 = new string('F', 64) }
            }
        };
        // A valid checksum cannot turn changed provenance into valid history.
        byte[] history = File.ReadAllBytes(f.Native.JournalPath);
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            sequence = state.Revision + 1,
            previous = Convert.ToHexString(history.AsSpan(history.Length - 32)),
            state = altered
        }, ManagementAdmission.Json);
        using (var file = new FileStream(f.Native.JournalPath, FileMode.Append, FileAccess.Write, FileShare.None))
        {
            byte[] length = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(length, payload.Length);
            file.Write(length);
            file.Write(payload);
            file.Write(SHA256.HashData(payload));
            file.Flush(true);
        }
        await Assert.That(() => f.Native.Read()).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("selected-credential")]
    [Arguments("selected-body")]
    [Arguments("selected-sdk")]
    [Arguments("notification-read")]
    [Arguments("notification-read-body")]
    [Arguments("original-final")]
    [Arguments("notification-status-body")]
    public async Task StatusNotificationAbsentCreateDisposalJoinsActualBorrowers(string barrier)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary",
            ManagementMutation.CreateOrUpdateNotification, exclusiveNotificationCreation: true);
        var lease = await f.PrepareAndBaseline();
        bool status = barrier is "original-final" or "notification-status-body";
        bool after = status || barrier is "notification-read" or "notification-read-body";
        ManagementOperation? handle = after ? (await f.Start(lease)).Value! : null;
        if (status)
        {
            await f.Observe(lease);
            using var stop = new CancellationTokenSource();
            stop.Cancel();
            await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, handle!, stop.Token))
                .Throws<OperationCanceledException>();
        }
        f.Barrier = barrier;
        Task work = status ? f.Source.RunCheckStatusAsync(f.Native.Selector, handle!, default).AsTask() :
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
}
