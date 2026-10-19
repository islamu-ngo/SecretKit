using System.Buffers.Binary;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Op = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;
using OpService = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RetainedOriginalApprovalCandidateRequiresAnIntactJournalBeforeLocalAppendRecovery(bool torn)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var dispatch = f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch;
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        int reads = f.ResourceReads, requests = f.PrivateEndpoint!.Requests.Count;
        // Controlled storage fault: discard only the final settlement frame.
        // Keep the actual source candidate and all original SDK/read tasks.
        byte[] journal = File.ReadAllBytes(f.Native.JournalPath);
        int offset = 0, final = 0;
        while (offset < journal.Length)
        {
            final = offset;
            offset += 36 + BinaryPrimitives.ReadInt32LittleEndian(journal.AsSpan(offset, 4));
        }
        await Assert.That(offset).IsEqualTo(journal.Length);
        using (var file = new FileStream(f.Native.JournalPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            file.SetLength(final + (torn ? 5 : 0));
        if (torn)
        {
            await Assert.That(() => f.Source.RetryPrivateConnectionApprovalSettlement(f.Native.Selector))
                .Throws<InvalidOperationException>();
            // Explicit controlled-host repair to a known intact prefix. The
            // production journal never silently repairs or skips a torn frame.
            using var file = new FileStream(f.Native.JournalPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            file.SetLength(final);
        }
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(dispatch);
        f.Source.RetryPrivateConnectionApprovalSettlement(f.Native.Selector);
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(dispatch);
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(f.ResourceReads).IsEqualTo(reads);
        await Assert.That(f.PrivateEndpoint.Requests.Count).IsEqualTo(requests);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task RetainedPrivateApprovalSettlementRetryOnlyReadsItsOriginalDurableMarker()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        var marker = f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch;
        int reads = f.ResourceReads, requests = f.PrivateEndpoint!.Requests.Count;
        using (var unavailable = new FileStream(f.Native.JournalPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            await Assert.That(() => f.Source.RetryPrivateConnectionApprovalSettlement(f.Native.Selector))
                .Throws<InvalidOperationException>();
        f.Source.RetryPrivateConnectionApprovalSettlement(f.Native.Selector);
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(marker);
        await Assert.That(f.ResourceReads).IsEqualTo(reads);
        await Assert.That(f.PrivateEndpoint.Requests.Count).IsEqualTo(requests);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PrivateApprovalClosureWaitsForActualOriginalSdkReturn(bool dispose)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        f.Barrier = "selected-sdk";
        var start = f.Start(lease);
        Task closing = Task.CompletedTask;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            closing = dispose ? f.Source.DisposeAsync().AsTask() : f.Release().AsTask();
            await Assert.That(f.Native.Read().Closing).IsTrue();
            await Assert.That(closing.IsCompleted).IsFalse();
            await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.InvocationTerminated).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        await Assert.That(async () => await start.WaitAsync(TimeSpan.FromSeconds(10)))
            .Throws<OperationCanceledException>();
        await closing.WaitAsync(TimeSpan.FromSeconds(10));
        var child = f.Native.Read().PrivateEndpoint!.Connection!;
        await Assert.That(child.InvocationTerminated && child.ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(f.PrivateEndpoint!.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    public async Task CopiedPrivateAdmissionCannotSelectTheOriginallyBoundChild()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var forged = new OpService.PrivateConnectionApprovalAdmission(f.Source);
        await Assert.That(() => f.Native.Journal.BeginPrivateConnectionApproval(Owner, f.Native.Selector,
            lease.Facts.LeaseId, forged)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.SelectedAttempted).IsFalse();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task EqualDispatchCannotForgePrivateApprovalSettlementOrGenericClearance()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        await f.Observe(lease);
        var child = f.Native.Read().PrivateEndpoint!.Connection!;
        var forged = new OpService.PrivateConnectionApprovalSettlement(f.Source, child.ActiveDispatch);
        await Assert.That(() => f.Native.Journal.SettlePrivateConnectionApproval(Owner, f.Native.Selector,
            lease.Facts.LeaseId, forged)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector,
            child.Id, child.ActiveDispatch, true)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(child.ActiveDispatch);
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RestartedPrivateApprovalCleanupRequiresOriginalDurableSettlement(bool settle)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var dispatch = f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch;
        if (settle)
            await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        await f.Source.DisposeAsync();
        await using var restarted = f.NewSource();
        using var observer = f.NewObserver(restarted);
        var measured = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(measured.RemainingResourceIds.Length == 0).IsEqualTo(settle);
        await Assert.That(f.Native.Read().Released).IsEqualTo(settle);
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch)
            .IsEqualTo(settle ? dispatch : Guid.Empty);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.PrivateEndpoint!.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(settle ? 1 : 0);
    }

    [Test]
    public async Task CachedPrivateSuccessOutsideOriginalStatusAdmissionCannotClearTheSelectedFence()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await Assert.That(await started.Value!.CheckStatusAsync()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(f.PrivateEndpoint!.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    public async Task MissingIndependentApprovalCannotAdmitOriginalCachedStatus()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
    }

    [Test]
    public async Task ClosingAfterApprovedPostReadRevokesLaterCachedStatusSettlement()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        f.Native.Journal.Close(Owner, f.Native.Selector);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
    }

    [Test]
    public async Task ActualPrivateApprovalHandlerJoinsOriginalBoundOwnershipAndReleasesEveryDependency()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection);
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.Prejournaled).IsTrue();
        await Assert.That(f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(0);
        var root = f.Native.Read();
        await Assert.That(root.PrivateEndpoint!.Connection!.SelectedAttempted).IsTrue();
        await Assert.That(root.PrivateEndpoint.Connection.ActiveDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(root.PrivateEndpointAbsent && root.Released).IsTrue();
        await Assert.That(f.PrivateEndpoint!.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
        await Assert.That(f.PrivateEndpoint.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
        await Assert.That(f.PrivateEndpoint.Requests.Where(r => r.Method != "GET").All(r => r.Path == f.PrivateEndpoint.Binding.EndpointId)).IsTrue();
    }

    [Test]
    public async Task PrivateApprovalPostReadPrecedesActualCachedStatusAndDurableSettlement()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        await Assert.That(lease.PrivateConnectionName).IsEqualTo("provider-assigned-connection");
        await Assert.That(lease.PrivateConnectionName == f.PrivateEndpoint!.Binding.ConnectionName).IsFalse();
        var started = await f.Start(lease);
        await Assert.That(started.Status).IsEqualTo(SecretStatus.Success);
        var beforeStatus = f.Native.Read().PrivateEndpoint!.Connection!;
        await Assert.That(beforeStatus.SelectedAttempted && beforeStatus.InvocationTerminated).IsTrue();
        await Assert.That(beforeStatus.ActiveDispatch != Guid.Empty).IsTrue();
        var observed = await f.Observe(lease);
        await Assert.That(observed.ResourceStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(observed.OperationState).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(observed.ResourceId).IsEqualTo(f.PrivateEndpoint.ConnectionId);
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(beforeStatus.ActiveDispatch);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(Guid.Empty);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("approval-lost")]
    [Arguments("approval-initial-pending")]
    [Arguments("approval-post-pending")]
    [Arguments("approval-wrong-endpoint")]
    public async Task UnprovedSelectedApprovalNeverBorrowsEndpointCleanupToManufactureItsEffect(string fault)
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection) { Fault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        var root = f.Native.Read();
        await Assert.That(root.PrivateEndpoint!.Connection!.SelectedAttempted).IsTrue();
        await Assert.That(root.PrivateEndpoint.Connection.ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(root.Released).IsFalse();
        await Assert.That(f.PrivateEndpoint!.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(0);
    }

    [Test]
    public async Task FreshAlreadyApprovedBaselineCannotAuthorizeAnotherPrivateApproval()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection)
        { Fault = "approval-baseline-approved" };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedUpdates).IsEqualTo(0);
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.SelectedAttempted).IsFalse();
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    public async Task OmittedExplicitPrivateEndpointConfigurationCannotProvision()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection);
        await using var source = f.NewSource(omitPrivateConnectionSource: true);
        using var observer = f.NewObserver(source);
        await Assert.That(async () => await observer.PostAsync<Op.Prepare, Op.Lease>(
            "operation/prepare", f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    public async Task PrivateApprovalServiceCannotAdoptAnotherSelectionBoundary(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, ManagementMutation.UpdatePrivateConnection);
        await Assert.That(async () => await f.Observer.PostAsync<Op.Prepare, Op.Lease>(
            "operation/prepare", f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    public async Task RootClosureDuringSelectedCredentialPreventsPrivateApprovalPut()
    {
        await using var f = new PurgeServiceFixture(operation: ManagementMutation.UpdatePrivateConnection);
        var lease = await f.PrepareAndBaseline();
        f.Barrier = "selected-credential";
        var start = f.Start(lease);
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            f.Native.Journal.Close(Owner, f.Native.Selector);
            await Assert.That(f.Native.Read().Closing).IsTrue();
        }
        finally { f.Resume.TrySetResult(); }
        await Assert.That((await start.WaitAsync(TimeSpan.FromSeconds(10))).Status).IsNotEqualTo(SecretStatus.Success);
        await Assert.That(f.SelectedUpdates).IsEqualTo(0);
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch != Guid.Empty).IsTrue();
        await f.Release();
        await Assert.That(f.PrivateEndpoint!.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(0);
    }
}
