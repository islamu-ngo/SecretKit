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
    public async Task StatusPrivateUpdateIndependentReconstructedParentCannotUseSavedDependencyAbsence()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishPrivateUpdateIndependent(f, started.Value!);
        f.Barrier = "parent-cleanup-read";
        var release = f.Release().AsTask();
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var state = f.Native.Read();
            await Assert.That(state.Idle && state.PrivateEndpointAbsent && state.PrivateEndpoint!.Connection!.Absent).IsTrue();
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
    [Arguments("owner")]
    [Arguments("subnet")]
    [Arguments("nic")]
    [Arguments("target")]
    [Arguments("state")]
    [Arguments("extra-connection")]
    public async Task StatusPrivateUpdateIndependentRequiresCompleteApprovedEndpointAfterChildRead(string field)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        f.PrivateEndpointPostTransform = row =>
        {
            var properties = row["properties"]!;
            if (field == "owner") row["tags"] = new JsonObject { ["secretkit-fixture"] = "foreign" };
            if (field == "subnet") properties["subnet"]!["id"] = f.PrivateEndpoint!.Binding.SubnetId + "-foreign";
            if (field == "nic") properties["networkInterfaces"]![0]!["id"] = f.PrivateEndpoint!.Binding.NicId + "-foreign";
            var connections = properties["manualPrivateLinkServiceConnections"]!.AsArray();
            var connection = connections[0]!["properties"]!;
            if (field == "target") connection["privateLinkServiceId"] = f.PrivateEndpoint!.Binding.VaultId + "-foreign";
            if (field == "state") connection["privateLinkServiceConnectionState"]!["status"] = "Pending";
            if (field == "extra-connection") connections.Add(connections[0]!.DeepClone());
        };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.PrivateEndpointPostMutations).IsEqualTo(1);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(f.PrivateEndpoint!.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("cancellation-boundary")]
    [Arguments("denied-authority")]
    public async Task StatusPrivateUpdateIndependentFactoryRejectsOtherCases(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        await Assert.That(async () => await f.Observer.PostAsync<Op.Prepare, Op.Lease>(
            "operation/prepare", f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    public async Task StatusPrivateUpdateIndependentRetainsFourStagesAndPersistenceDoesNotReplayNativeWork()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        long ready = f.Native.Read().Revision;
        var started = await f.Start(lease);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(ready + 2);
        await Assert.That(f.Source.RetryStatusPrivateConnectionUpdateIndependentPersistence(f.Native.Selector).Revision)
            .IsEqualTo(ready + 2);
        await f.Observe(lease);
        int reads = f.ResourceReads;
        await FinishPrivateUpdateIndependent(f, started.Value!);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(ready + 4);
        await Assert.That(f.Source.RetryStatusPrivateConnectionUpdateIndependentPersistence(f.Native.Selector).Revision)
            .IsEqualTo(ready + 4);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.ResourceReads).IsEqualTo(reads);
        await Assert.That(f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(0);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusPrivateUpdateIndependentOriginalObservationCallerRemainsAVeto(bool after)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        var lease = after ? await f.PrepareAndBaseline() :
            await f.Observer.PostAsync<Op.Prepare, Op.Lease>("operation/prepare", f.PrepareRequest(), default);
        if (!after) f.Armed = await f.Observer.SubscribeAsync("operation", lease.Facts, default);
        var started = after ? await f.Start(lease) : default;
        using var caller = new CancellationTokenSource();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://purge-observer.example/operation/observe");
        request.Headers.Authorization = new("Bearer", "private-purge-service-capability");
        request.Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(
            new ObserveLease(lease.Facts.LeaseId, lease.Facts.Nonce, after ? "selected-state" : "baseline-before-dispatch",
                f.Armed!.SubscriptionId),
            new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
        request.Content.Headers.ContentType = new("application/json");
        using var response = await f.Source.DispatchAsync(request, caller.Token);
        await Assert.That(response.IsSuccessStatusCode).IsTrue();
        caller.Cancel();
        if (after)
            await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started!.Value!, default))
                .Throws<InvalidOperationException>();
        else await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedUpdates).IsEqualTo(after ? 1 : 0);
        await Assert.That(f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(0);
    }

    [Test]
    public async Task StatusPrivateUpdateIndependentJoinsOriginalTasksAndOwnedEndpointCleanup()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(1);
        await Assert.That(tap.Checks[0].Canceled).IsFalse();
        await Assert.That(tap.Checks[0].Task.Result).IsEqualTo(SecretStatus.Success);
        await Assert.That(tap.Checks.All(c => ReferenceEquals(c.Handle, tap.Start!.Result.Value))).IsTrue();
        await Assert.That(tap.StartReceipt).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(0);
        await Assert.That(f.PrivateChildResourceReads).IsEqualTo(2);
        await Assert.That(f.PrivateEndpoint!.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
        await Assert.That(f.PrivateEndpoint.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
        var root = f.Native.Read();
        await Assert.That(root.Released && root.PrivateEndpointAbsent && f.Prejournaled).IsTrue();
        await Assert.That(root.Resources.Length).IsEqualTo(5);
        await Assert.That(root.PrivateEndpoint!.ApprovalSettledDispatch != Guid.Empty).IsTrue();
        await Assert.That(root.PrivateEndpoint.Connection!.SelectedAttempted).IsTrue();
        await Assert.That(root.PrivateEndpoint.Connection.ActiveDispatch).IsEqualTo(Guid.Empty);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusPrivateUpdateIndependentPreservesCompleteOptionalNativeReadMetadata(bool nulls)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        void Metadata(JsonObject row)
        {
            row["etag"] = nulls ? null : "W/\"owned-version\"";
            row["tags"] = nulls ? null : new JsonObject { ["controlled"] = "owned" };
            row["systemData"] = nulls ? null : new JsonObject
            {
                ["createdBy"] = "owned-creator", ["createdByType"] = "Application",
                ["createdAt"] = "2026-10-17T00:00:00Z", ["lastModifiedBy"] = "owned-editor",
                ["lastModifiedByType"] = "Application", ["lastModifiedAt"] = "2026-10-18T00:00:00Z"
            };
            var state = row["properties"]!["privateLinkServiceConnectionState"]!;
            state["description"] = nulls ? null : "owned-approval";
            state["actionsRequired"] = nulls ? null : "None";
        }
        f.PrivateBaselineTransform = Metadata;
        f.PrivatePostTransform = Metadata;
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("approval-lost")]
    [Arguments("approval-initial-pending")]
    [Arguments("approval-initial-updating")]
    [Arguments("approval-wrong-endpoint")]
    [Arguments("approval-post-pending")]
    public async Task StatusPrivateUpdateIndependentCannotReplaceOriginalProofOrIndependentTransition(string fault)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true)
        { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.PrivateEndpoint!.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    [Arguments(201)]
    [Arguments(202)]
    [Arguments(403)]
    public async Task StatusPrivateUpdateIndependentRejectsUnqualifiedOriginalStatus(int status)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true)
        { PrivateStartStatus = status };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.PrivateEndpoint!.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    [Arguments("id")]
    [Arguments("name")]
    [Arguments("type")]
    [Arguments("location")]
    [Arguments("etag")]
    [Arguments("tags")]
    [Arguments("systemData.createdBy")]
    [Arguments("systemData.createdByType")]
    [Arguments("systemData.createdAt")]
    [Arguments("systemData.lastModifiedBy")]
    [Arguments("systemData.lastModifiedByType")]
    [Arguments("systemData.lastModifiedAt")]
    [Arguments("properties.provisioningState")]
    [Arguments("properties.privateEndpoint.id")]
    [Arguments("properties.privateLinkServiceConnectionState.status")]
    [Arguments("properties.privateLinkServiceConnectionState.description")]
    [Arguments("properties.privateLinkServiceConnectionState.actionsRequired")]
    public async Task StatusPrivateUpdateIndependentRejectsMalformedCompleteNativeReadMetadata(string field)
    {
        foreach (bool after in new[] { false, true })
        {
            await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
            void Malformed(JsonObject row)
            {
                var parts = field.Split('.');
                var parent = row;
                foreach (string part in parts[..^1])
                {
                    if (parent[part] is null) parent[part] = new JsonObject();
                    parent = parent[part]!.AsObject();
                }
                parent[parts[^1]] = true;
            }
            if (after) f.PrivatePostTransform = Malformed;
            else f.PrivateBaselineTransform = Malformed;
            await Assert.That((await f.RunOriginal()).Passed).IsFalse();
            await Assert.That(f.SelectedUpdates).IsEqualTo(after ? 1 : 0);
            await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
            await Assert.That(f.Native.Read().Resources.Any(r => r.SelectedAttempted)).IsFalse();
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusPrivateUpdateIndependentDoesNotDropUnknownMetadata(bool after)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        if (after) f.PrivatePostTransform = row => row["properties"]!["unestablished"] = "future";
        else f.PrivateBaselineTransform = row => row["unestablished"] = "future";
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(after ? 1 : 0);
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
    }

    [Test]
    [Arguments("id")]
    [Arguments("name")]
    [Arguments("endpoint")]
    [Arguments("location")]
    [Arguments("state")]
    public async Task StatusPrivateUpdateIndependentRejectsForeignOrNonterminalIndependentRead(string field)
    {
        foreach (bool after in new[] { false, true })
        {
            await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
            void Foreign(JsonObject row)
            {
                if (field == "id") row["id"] = row["id"]!.GetValue<string>() + "-foreign";
                if (field == "name") row["name"] = "foreign-connection";
                if (field == "endpoint") row["properties"]!["privateEndpoint"]!["id"] =
                    row["properties"]!["privateEndpoint"]!["id"]!.GetValue<string>() + "-foreign";
                if (field == "location") row["location"] = "westus";
                if (field == "state") row["properties"]!["provisioningState"] = "Updating";
            }
            if (after) f.PrivatePostTransform = Foreign;
            else f.PrivateBaselineTransform = Foreign;
            await Assert.That((await f.RunOriginal()).Passed).IsFalse();
            await Assert.That(f.SelectedUpdates).IsEqualTo(after ? 1 : 0);
            await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
        }
    }

    [Test]
    public async Task StatusPrivateUpdateIndependentCannotApproveAlreadyApprovedBaseline()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true)
        { Fault = "approval-baseline-approved" };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(0);
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.SelectedAttempted).IsFalse();
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    public async Task StatusPrivateUpdateIndependentCopiedAdmissionCannotSelectBoundChild()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var forged = new Service.StatusPrivateConnectionUpdateIndependentAdmission(f.Source);
        await Assert.That(() => f.Native.Journal.BeginStatusPrivateConnectionUpdateIndependentInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, forged)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.SelectedAttempted).IsFalse();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusPrivateUpdateIndependentCopiedSettlementAndGenericApisCannotClearFence()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var child = f.Native.Read().PrivateEndpoint!.Connection!;
        var forged = new Service.StatusPrivateConnectionUpdateIndependentSettlement(f.Source);
        await Assert.That(() => f.Native.Journal.CompleteStatusPrivateConnectionUpdateIndependentRead(Owner,
            f.Native.Selector, lease.Facts.LeaseId, child.ActiveDispatch, forged)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, child.Id,
            child.ActiveDispatch, true)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(child.ActiveDispatch);
        await FinishPrivateUpdateIndependent(f, started.Value!);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusPrivateUpdateIndependentActualParentAndEndpointRestartRequiresSettlement(bool settled)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        Guid dispatch = f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch;
        if (settled) await FinishPrivateUpdateIndependent(f, started.Value!);
        await f.Source.DisposeAsync();
        var parent = f.ReopenProvisioner();
        await using var restarted = f.NewSource(cleanupOnly: true, parent: parent);
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(f.Native.Read().Released).IsEqualTo(settled);
        await Assert.That(release.RemainingResourceIds.Length == 0).IsEqualTo(settled);
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch)
            .IsEqualTo(settled ? dispatch : Guid.Empty);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.PrivateEndpoint!.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(settled ? 1 : 0);
    }

    [Test]
    public async Task StatusPrivateUpdateIndependentCloseBeforeLaterCheckRetainsFence()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        f.Native.Journal.Close(Owner, f.Native.Selector);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(f.PrivateEndpoint!.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    [Arguments("")]
    [Arguments("{")]
    [Arguments("""{"error":{"code":"Forbidden"}}""")]
    [Arguments("""{"error":{"code":"ResourceNotFound"}}""")]
    [Arguments("""{"error":{"code":"NotFound","details":[]}}""")]
    public async Task StatusPrivateUpdateIndependentCleanupRequiresActualStrictNotFound(string body)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishPrivateUpdateIndependent(f, started.Value!);
        f.PrivateCleanup404Body = body;
        var release = await f.Release();
        await Assert.That(f.PrivateCleanup404Reached > 0).IsTrue();
        await Assert.That(release.RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("selected-credential")]
    [Arguments("private-start-body")]
    [Arguments("selected-sdk")]
    [Arguments("private-read")]
    [Arguments("private-read-body")]
    public async Task StatusPrivateUpdateIndependentDisposalDrainsActualBorrowers(string barrier)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        bool after = barrier is "private-read" or "private-read-body";
        if (after) await f.Start(lease);
        f.Barrier = barrier;
        Task work = after ? f.Observe(lease).AsTask() : f.Start(lease);
        Task? closing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            closing = f.Source.DisposeAsync().AsTask();
            await Assert.That(f.Native.Read().Closing).IsTrue();
            await Assert.That(work.IsCompleted || closing.IsCompleted).IsFalse();
            await Assert.That(f.PrivateEndpoint!.Requests.Any(r => r.Method == "DELETE")).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException or NativeCaseFailureException) { }
        await closing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
    }

    private static async Task FinishPrivateUpdateIndependent(PurgeServiceFixture f, ManagementOperation handle)
    {
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, handle, default))
            .IsEqualTo(SecretStatus.Success);
    }

    [Test]
    [Arguments("private-read")]
    [Arguments("private-read-body")]
    public async Task StatusPrivateUpdateIndependentReleaseCancellationDoesNotDetachBorrower(string barrier)
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        f.Barrier = barrier;
        var read = f.Observe(lease).AsTask();
        Task? disposal = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            using var stop = new CancellationTokenSource();
            var release = f.Observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
                "operation/release", f.Native.Selector, stop.Token).AsTask();
            stop.Cancel();
            await Assert.That(async () => await release.WaitAsync(TimeSpan.FromSeconds(10)))
                .Throws<OperationCanceledException>();
            await Assert.That(f.Native.Read().Closing).IsTrue();
            await Assert.That(read.IsCompleted).IsFalse();
            disposal = f.Source.DisposeAsync().AsTask();
            await Assert.That(disposal.IsCompleted).IsFalse();
            await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch != Guid.Empty).IsTrue();
            await Assert.That(f.PrivateEndpoint!.Requests.Any(r => r.Method == "DELETE")).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        try { await read.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException or NativeCaseFailureException) { }
        await disposal!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
    }
}
