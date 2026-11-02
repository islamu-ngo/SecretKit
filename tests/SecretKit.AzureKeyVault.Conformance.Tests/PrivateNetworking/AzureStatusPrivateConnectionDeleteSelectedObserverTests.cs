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
    public async Task StatusPrivateDeleteSelectedJoinsOriginalTasksAndNoReplayCleanup()
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.DeletePrivateConnection);
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(1);
        await Assert.That(tap.Checks[0].Canceled).IsFalse();
        await Assert.That(tap.Checks[0].Task.Result).IsEqualTo(SecretStatus.Success);
        await Assert.That(tap.Checks.All(c => ReferenceEquals(c.Handle, tap.Start!.Result.Value))).IsTrue();
        await Assert.That(tap.Start!.Result.Value.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(tap.StartReceipt).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.SelectedUpdates + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(0);
        await Assert.That(f.ResourceReads).IsEqualTo(2);
        await Assert.That(f.PrivateEndpoint!.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
        await Assert.That(f.PrivateEndpoint.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
        var root = f.Native.Read();
        await Assert.That(root.Released && root.PrivateEndpointAbsent && f.Prejournaled).IsTrue();
        await Assert.That(root.Resources.Length).IsEqualTo(5);
        await Assert.That(root.PrivateEndpoint!.StatusDeleteSettledDispatch != Guid.Empty).IsTrue();
        await Assert.That(root.PrivateEndpoint.Connection is { SelectedAttempted: true, DeleteAttempted: true,
            InvocationTerminated: true, ActiveDispatch: var dispatch } && dispatch == Guid.Empty).IsTrue();
    }

    [Test]
    [Arguments("private-delete-lost")]
    [Arguments("private-delete-empty")]
    [Arguments("private-delete-pending")]
    [Arguments("private-delete-updating")]
    [Arguments("private-delete-wrong-endpoint")]
    [Arguments("private-delete-child-present")]
    [Arguments("private-delete-endpoint-pending")]
    [Arguments("private-delete-endpoint-subnet")]
    public async Task StatusPrivateDeleteSelectedRequiresOriginalAndIndependentConjunction(string fault)
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.DeletePrivateConnection)
        { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(f.PrivateEndpoint!.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    [Arguments(201)]
    [Arguments(202)]
    [Arguments(204)]
    [Arguments(403)]
    public async Task StatusPrivateDeleteSelectedRejectsUnqualifiedOriginalResponse(int status)
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.DeletePrivateConnection)
        { PrivateStartStatus = status };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().PrivateEndpoint!.StatusDeleteSettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(f.PrivateEndpoint!.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    [Arguments("")]
    [Arguments("{")]
    [Arguments("""{"error":{"code":"Forbidden"}}""")]
    [Arguments("""{"error":{"code":"Unknown"}}""")]
    [Arguments("""{"error":{"code":"NotFound","details":[]}}""")]
    [Arguments("""{"error":{"code":"NotFound","innererror":{}}}""")]
    [Arguments("""{"error":{"code":"NotFound","target":"foreign"}}""")]
    public async Task StatusPrivateDeleteSelectedRequiresStrictActualNativeAbsence(string body)
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.DeletePrivateConnection)
        { PrivateDeleteRead404Body = body };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.PrivateDeleteRead404Reached).IsEqualTo(1);
        await Assert.That(f.Native.Read().PrivateEndpoint!.StatusDeleteSettledDispatch).IsEqualTo(Guid.Empty);
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
    public async Task StatusPrivateDeleteSelectedRequiresCompleteNativeBaseline(string field)
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.DeletePrivateConnection);
        f.PrivateBaselineTransform = row =>
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
        await Assert.That(f.PrivateBaselineMutations).IsEqualTo(1);
        await Assert.That(f.SelectedDeletes).IsEqualTo(0);
        await Assert.That(f.Native.Read().PrivateEndpoint!.StatusDeleteSettledDispatch).IsEqualTo(Guid.Empty);
    }

    [Test]
    public async Task StatusPrivateDeleteSelectedCopiedCertificatesCannotSelectOrSettle()
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.DeletePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var admission = new Service.StatusPrivateConnectionDeleteSelectedAdmission(f.Source);
        await Assert.That(() => f.Native.Journal.BeginStatusPrivateConnectionDeleteSelectedInvocation(Owner,
            f.Native.Selector, lease.Facts.LeaseId, admission)).Throws<InvalidOperationException>();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var child = f.Native.Read().PrivateEndpoint!.Connection!;
        var settlement = new Service.StatusPrivateConnectionDeleteSelectedSettlement(f.Source, child.ActiveDispatch);
        await Assert.That(() => f.Native.Journal.CompleteStatusPrivateConnectionDeleteSelectedRead(Owner,
            f.Native.Selector, lease.Facts.LeaseId, child.ActiveDispatch, settlement)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, child.Id,
            child.ActiveDispatch, true)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(child.ActiveDispatch);
        await FinishPrivateDeleteSelected(f, started.Value!);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("private-read")]
    [Arguments("private-read-body")]
    public async Task StatusPrivateDeleteSelectedReleaseObservesCallerCancellationWithoutFakingDrain(string barrier)
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.DeletePrivateConnection);
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
            await Assert.That(read.IsCompleted).IsFalse();
            await Assert.That(f.PrivateEndpoint!.Requests.Any(r => r.Method == "DELETE")).IsFalse();
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
    public async Task StatusPrivateDeleteSelectedCanceledFirstAttemptCannotBecomeACompletionProof()
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.DeletePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        try { await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token); }
        catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException) { }
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().PrivateEndpoint!.StatusDeleteSettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
    }

    [Test]
    public async Task StatusPrivateDeleteSelectedWrongHandlePreflightCannotStealOwnedCheck()
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.DeletePrivateConnection);
        await using var other = new PurgeServiceFixture("selected-contract", ManagementMutation.DeletePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var foreignLease = await other.PrepareAndBaseline();
        var foreign = await other.Start(foreignLease);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, foreign.Value!, default))
            .Throws<InvalidOperationException>();
        await FinishPrivateDeleteSelected(f, started.Value!);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
    }

    [Test]
    public async Task StatusPrivateDeleteSelectedCompletedCheckCannotReplayOrMintAnotherAttempt()
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.DeletePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishPrivateDeleteSelected(f, started.Value!);
        var marker = f.Native.Read().PrivateEndpoint!.StatusDeleteSettledDispatch;
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().PrivateEndpoint!.StatusDeleteSettledDispatch).IsEqualTo(marker);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
    }

    [Test]
    [Arguments("NotFound")]
    [Arguments("ResourceNotFound")]
    public async Task StatusPrivateDeleteSelectedAcceptsOnlyEstablishedNativeAbsenceCodes(string code)
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.DeletePrivateConnection)
        { PrivateDeleteRead404Body = new JsonObject { ["error"] = new JsonObject { ["code"] = code } }.ToJsonString() };
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        await Assert.That(f.PrivateDeleteRead404Reached).IsEqualTo(1);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("selected-credential")]
    [Arguments("selected-send")]
    [Arguments("private-start-body")]
    [Arguments("selected-sdk")]
    [Arguments("private-read")]
    [Arguments("private-read-body")]
    public async Task StatusPrivateDeleteSelectedDisposalDrainsActualBorrowers(string barrier)
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.DeletePrivateConnection);
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
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusPrivateDeleteSelectedRestartRequiresDurableMarker(bool settled)
    {
        await using var f = new PurgeServiceFixture("selected-contract", ManagementMutation.DeletePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        if (settled) await FinishPrivateDeleteSelected(f, started.Value!);
        await f.Source.DisposeAsync();
        await using var restarted = f.NewSource(parent: f.ReopenProvisioner());
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(release.RemainingResourceIds.Length == 0).IsEqualTo(settled);
        await Assert.That(f.Native.Read().Released).IsEqualTo(settled);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.PrivateEndpoint!.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(settled ? 1 : 0);
    }

    private static async Task FinishPrivateDeleteSelected(PurgeServiceFixture f, ManagementOperation handle)
    {
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, handle, default))
            .IsEqualTo(SecretStatus.Success);
    }
}
