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
    public async Task StatusPrivateUpdateCancellationJoinsOriginalTasksAndOwnedEndpointCleanup()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection);
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(2);
        await Assert.That(tap.Checks[0].Canceled && tap.Checks[0].Task.IsCanceled).IsTrue();
        await Assert.That(tap.Checks[1].Canceled).IsFalse();
        await Assert.That(tap.Checks[1].Task.Result).IsEqualTo(SecretStatus.Success);
        await Assert.That(ReferenceEquals(tap.Checks[0].Task, tap.Checks[1].Task)).IsFalse();
        await Assert.That(tap.Checks.All(c => ReferenceEquals(c.Handle, tap.Start!.Result.Value))).IsTrue();
        await Assert.That(tap.StartReceipt).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(0);
        await Assert.That(f.ResourceReads).IsEqualTo(2);
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
    public async Task StatusPrivateUpdateCancellationPreservesCompleteOptionalNativeReadMetadata(bool nulls)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection);
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
    public async Task StatusPrivateUpdateCancellationCannotReplaceOriginalProofOrIndependentTransition(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection)
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
    public async Task StatusPrivateUpdateCancellationRejectsUnqualifiedOriginalStatus(int status)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection)
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
    public async Task StatusPrivateUpdateCancellationRejectsMalformedCompleteNativeReadMetadata(string field)
    {
        foreach (bool after in new[] { false, true })
        {
            await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection);
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
    public async Task StatusPrivateUpdateCancellationDoesNotDropUnknownMetadata(bool after)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection);
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
    public async Task StatusPrivateUpdateCancellationRejectsForeignOrNonterminalIndependentRead(string field)
    {
        foreach (bool after in new[] { false, true })
        {
            await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection);
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
    public async Task StatusPrivateUpdateCancellationCannotApproveAlreadyApprovedBaseline()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection)
        { Fault = "approval-baseline-approved" };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(0);
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.SelectedAttempted).IsFalse();
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusPrivateUpdateCancellationInvalidFirstServiceCheckCannotStealSlot(bool independent)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        if (independent) await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!,
            independent ? default : stop.Token)).Throws<InvalidOperationException>();
        if (!independent) await f.Observe(lease);
        await FinishPrivateUpdateCancellation(f, started.Value!);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusPrivateUpdateCancellationRepeatedCancelCannotReplaceLaterSlot()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<InvalidOperationException>();
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Success);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusPrivateUpdateCancellationCopiedAdmissionCannotSelectBoundChild()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var forged = new Service.StatusPrivateConnectionUpdateCancellationAdmission(f.Source);
        await Assert.That(() => f.Native.Journal.BeginStatusPrivateConnectionUpdateInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, forged)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.SelectedAttempted).IsFalse();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusPrivateUpdateCancellationCopiedSettlementAndGenericApisCannotClearFence()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var child = f.Native.Read().PrivateEndpoint!.Connection!;
        var forged = new Service.StatusPrivateConnectionUpdateCancellationSettlement(f.Source, child.ActiveDispatch);
        await Assert.That(() => f.Native.Journal.CompleteStatusPrivateConnectionUpdateCancellationRead(Owner,
            f.Native.Selector, lease.Facts.LeaseId, child.ActiveDispatch, forged)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, child.Id,
            child.ActiveDispatch, true)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(child.ActiveDispatch);
        await FinishPrivateUpdateCancellation(f, started.Value!);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusPrivateUpdateCancellationActualParentAndEndpointRestartRequiresSettlement(bool settled)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        Guid dispatch = f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch;
        if (settled) await FinishPrivateUpdateCancellation(f, started.Value!);
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
    public async Task StatusPrivateUpdateCancellationCloseBeforeLaterCheckRetainsFence()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection);
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
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(f.PrivateEndpoint!.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    [Arguments("")]
    [Arguments("{")]
    [Arguments("""{"error":{"code":"Forbidden"}}""")]
    [Arguments("""{"error":{"code":"ResourceNotFound"}}""")]
    [Arguments("""{"error":{"code":"NotFound","details":[]}}""")]
    public async Task StatusPrivateUpdateCancellationCleanupRequiresActualStrictNotFound(string body)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishPrivateUpdateCancellation(f, started.Value!);
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
    public async Task StatusPrivateUpdateCancellationDisposalDrainsActualBorrowers(string barrier)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection);
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

    private static async Task FinishPrivateUpdateCancellation(PurgeServiceFixture f, ManagementOperation handle)
    {
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, handle, stop.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, handle, default))
            .IsEqualTo(SecretStatus.Success);
    }

    [Test]
    [Arguments("private-read")]
    [Arguments("private-read-body")]
    public async Task StatusPrivateUpdateCancellationReleaseCancellationDoesNotDetachBorrower(string barrier)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdatePrivateConnection);
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
