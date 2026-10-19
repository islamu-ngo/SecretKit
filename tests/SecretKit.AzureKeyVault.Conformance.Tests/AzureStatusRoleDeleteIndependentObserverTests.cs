using System.Net;
using System.Text.Json.Nodes;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Op = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;
using RoleOp = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.RoleManagementOperationFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureRoleFixtureProvisionerTests
{
    [Test]
    [Arguments("selected-contract")]
    [Arguments("cancellation-boundary")]
    [Arguments("denied-authority")]
    public async Task StatusRoleDeleteIndependentFactoryRejectsOtherCasesBeforeDeclaration(string boundary)
    {
        await using var f = new RoleOperationServiceFixture(boundary, statusRoleDeleteIndependent: true);
        await Assert.That(async () => await f.Observer.PostAsync<Op.Prepare, Op.Lease>(
            "operation/prepare", f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(Directory.EnumerateFiles(f.Native.DirectoryPath).Any()).IsFalse();
    }

    [Test]
    public async Task StatusRoleDeleteIndependentRetainsExactFourTransitionsAndReadOnlyRetry()
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        var lease = await f.PrepareAndBaseline();
        long ready = f.Native.Read().Revision;
        var started = await f.Start(lease);
        var drained = f.Native.Read();
        await Assert.That(drained.Revision).IsEqualTo(ready + 2);
        var child = drained.Resources.Single(r => r.SelectedAttempted);
        await Assert.That(child.InvocationTerminated && child.ActiveDispatch != Guid.Empty).IsTrue();
        f.Source.RetryStatusRoleDeleteIndependentPersistence(f.Native.Selector);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(drained.Revision);
        await f.Observe(lease);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(drained.Revision);
        int reads = f.ResourceReads;
        await FinishRoleIndependent(f, started.Value!);
        var committed = f.Native.Read();
        await Assert.That(committed.Revision).IsEqualTo(ready + 4);
        await Assert.That(committed.Resources.Single(r => r.Id == child.Id).ActiveDispatch).IsEqualTo(Guid.Empty);
        f.Source.RetryStatusRoleDeleteIndependentPersistence(f.Native.Selector);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(committed.Revision);
        await Assert.That(f.ResourceReads).IsEqualTo(reads);
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusRoleDeleteIndependentForeignHandleCannotStealActualCheck()
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        await using var other = new RoleOperationServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var foreignLease = await other.PrepareAndBaseline();
        var started = await f.Start(lease);
        var foreign = await other.Start(foreignLease);
        await f.Observe(lease);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, foreign.Value!, default))
            .Throws<InvalidOperationException>();
        await FinishRoleIndependent(f, started.Value!);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusRoleDeleteIndependentJoinsActualStartAndCachedTaskWithoutStatusGets()
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        var tap = new RoleCancellationTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(1);
        await Assert.That(tap.Checks[0].Canceled).IsFalse();
        await Assert.That(tap.Checks[0].Task.Result).IsEqualTo(SecretStatus.Success);
        await Assert.That(tap.Checks.All(c => ReferenceEquals(c.Handle, tap.Start!.Result.Value))).IsTrue();
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
        await Assert.That(f.SelectedRequests.Single().Method).IsEqualTo(HttpMethod.Delete);
        await Assert.That(f.ResourceReads >= 2).IsTrue();
        var state = f.Native.Read();
        await Assert.That(state.Released && state.Idle && f.Native.State.BeforeSendPersisted).IsTrue();
        await Assert.That(state.Resources.Count(r => r.Borrowed)).IsEqualTo(1);
        await Assert.That(state.Resources.Count(r => !r.Borrowed)).IsEqualTo(4);
        await Assert.That(f.Native.Backends.SelectMany(b => b.Requests)
            .Count(r => r.Path.Contains("/roleAssignments/", StringComparison.Ordinal) &&
                r.Method == HttpMethod.Delete)).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusRoleDeleteIndependentPreservesCompleteOptionalNativeMetadata(bool nulls)
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        f.Native.State.AssignmentTransform = row =>
        {
            var p = row["properties"]!.AsObject();
            p["condition"] = nulls ? null : "@Resource[Microsoft.Storage/storageAccounts:name] StringEquals 'owned'";
            p["conditionVersion"] = nulls ? null : "2.0";
            p["createdOn"] = nulls ? null : "2026-10-17T00:00:00Z";
            p["updatedOn"] = nulls ? null : "2026-10-18T00:00:00Z";
            p["createdBy"] = nulls ? null : Tenant.ToString("D");
            p["updatedBy"] = nulls ? null : PrincipalId.ToString("D");
            p["delegatedManagedIdentityResourceId"] = nulls ? null :
                GroupPath + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/owned";
        };
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments(200)]
    [Arguments(202)]
    [Arguments(403)]
    public async Task StatusRoleDeleteIndependentRejectsUnqualifiedNativeStart(int status)
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        f.Native.State.SelectedDeleteStatus = status;
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("nonempty")]
    [Arguments("continuation")]
    [Arguments("retry")]
    [Arguments("no-op")]
    [Arguments("read-denied")]
    [Arguments("read-malformed")]
    public async Task StatusRoleDeleteIndependentCannotReplaceOriginalWireOrIndependentAbsence(string fault)
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true) { Fault = fault };
        if (fault is "lost" or "no-op") f.Native.State.SelectedDeleteFault = fault;
        if (fault == "nonempty") f.Native.State.SelectedDeleteBody = """{"status":"Succeeded"}""";
        if (fault is "continuation" or "retry")
            f.Native.State.SelectedDeleteHeader = fault == "retry" ? "Retry-After" : "Location";
        int setupWrites = 0;
        f.AfterPrepare = () => setupWrites = f.Native.WriteCount;
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.Native.WriteCount).IsEqualTo(setupWrites);
    }

    [Test]
    [Arguments("principal")]
    [Arguments("definition")]
    [Arguments("scope")]
    public async Task StatusRoleDeleteIndependentRejectsForeignOwnedBaseline(string fault)
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true) { BaselineFault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("scope")]
    [Arguments("roleDefinitionId")]
    [Arguments("principalId")]
    [Arguments("principalType")]
    [Arguments("description")]
    [Arguments("condition")]
    [Arguments("conditionVersion")]
    [Arguments("createdOn")]
    [Arguments("updatedOn")]
    [Arguments("createdBy")]
    [Arguments("updatedBy")]
    [Arguments("delegatedManagedIdentityResourceId")]
    public async Task StatusRoleDeleteIndependentRejectsMalformedFullBaselineBeforeSelection(string field)
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        f.BaselineTransform = row => row["properties"]![field] = true;
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(0);
        await Assert.That(f.Native.Read().Resources.Any(r => r.SelectedAttempted)).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusRoleDeleteIndependentDoesNotDropUnknownNativeMetadata(bool nested)
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        f.BaselineTransform = row => (nested ? row["properties"]!.AsObject() : row)["unestablished"] = "future";
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("")]
    [Arguments("{")]
    [Arguments("""{"error":{"code":"Forbidden"}}""")]
    [Arguments("""{"error":{"code":"NotFound"}}""")]
    [Arguments("""{"error":{"code":"ResourceNotFound","details":[{"code":"Forbidden"}]}}""")]
    public async Task StatusRoleDeleteIndependentRequiresActualStrictResourceNotFound(string body)
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        f.Native.State.MissingAssignmentBody = body;
        await Assert.That(async () => await f.Observe(lease)).Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task StatusRoleDeleteIndependentGenericSettlementCannotClearSelectedFence()
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var state = f.Native.Read();
        var row = state.Resources.Single(r => r.ActiveDispatch != Guid.Empty);
        await Assert.That(() => f.Native.Journal.EndDispatch("owner", f.Native.Selector, row.Id,
            row.ActiveDispatch, nativeSettled: true)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch("owner", f.Native.Selector, row.Id,
            row.ActiveDispatch)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == row.Id).ActiveDispatch)
            .IsEqualTo(row.ActiveDispatch);
        await FinishRoleIndependent(f, started.Value!);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusRoleDeleteIndependentJournalCannotBypassChildDependencyOrReplayDelete()
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishRoleIndependent(f, started.Value!);
        f.Native.Journal.Close("owner", f.Native.Selector);
        var state = f.Native.Read();
        var child = state.Resources.Single(r => r.SelectedAttempted);
        var vault = state.Resources.Single(r => !r.Borrowed && !r.CleanupOnly &&
            r.Id.Contains("/vaults/", StringComparison.Ordinal) && !r.Id.Contains("/secrets/", StringComparison.Ordinal) &&
            !r.Id.Contains("/providers/Microsoft.Authorization/", StringComparison.Ordinal));
        foreach (var row in new[] { child, vault })
            await Assert.That(() => f.Native.Journal.BeginDispatch("owner", f.Native.Selector, row.Id, delete: true))
                .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Resources.All(r => !r.DeleteAttempted)).IsTrue();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusRoleDeleteIndependentCloseBeforeLaterCheckRetainsFence()
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        f.Native.Journal.Close("owner", f.Native.Selector);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.State.VaultExists).IsTrue();
    }

    [Test]
    public async Task StatusRoleDeleteIndependentReappearanceBlocksReplayAndParentCleanup()
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        var lease = await f.PrepareAndBaseline();
        string? assignment = f.Native.State.AssignmentPath;
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishRoleIndependent(f, started.Value!);
        f.Native.State.AssignmentPath = assignment;
        int writes = f.Native.WriteCount;
        await Assert.That((await f.Release()).RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.Native.WriteCount).IsEqualTo(writes);
        await Assert.That(f.Native.State.VaultExists).IsTrue();
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("")]
    [Arguments("{")]
    [Arguments("""{"error":{"code":"Forbidden"}}""")]
    [Arguments("""{"error":{"code":"NotFound"}}""")]
    [Arguments("""{"error":{"code":"ResourceNotFound","details":[]}}""")]
    public async Task StatusRoleDeleteIndependentCleanupCannotUseUnqualifiedAbsence(string body)
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishRoleIndependent(f, started.Value!);
        f.Native.State.MissingAssignmentBody = body;
        int writes = f.Native.WriteCount;
        await Assert.That((await f.Release()).RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.Native.WriteCount).IsEqualTo(writes);
        await Assert.That(f.Native.State.VaultExists).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusRoleDeleteIndependentReconstructsActualParentOnlyForSettledCleanup(bool settled)
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        if (settled) await FinishRoleIndependent(f, started.Value!);
        await f.Source.DisposeAsync();
        var parent = f.Native.Reopen();
        await using var restarted = f.NewSource(parent, cleanupOnly: true);
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(f.Native.Read().Released).IsEqualTo(settled);
        await Assert.That(release.ActiveDispatches == 0).IsEqualTo(settled);
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusRoleDeleteIndependentLostParentCleanupCannotReplayMutation(bool purge)
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishRoleIndependent(f, started.Value!);
        if (purge) f.Native.State.PurgeFault = "lost";
        else f.Native.State.DeleteFault = "lost";
        await Assert.That((await f.Release()).RemainingResourceIds.Length > 0).IsTrue();
        int writes = f.Native.WriteCount;
        await f.Release();
        await Assert.That(f.Native.WriteCount).IsEqualTo(writes);
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("selected")]
    [Arguments("resource")]
    [Arguments("resource-body")]
    public async Task StatusRoleDeleteIndependentDisposalDrainsActualNativeBorrower(string barrier)
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        var lease = await f.PrepareAndBaseline();
        Task work;
        if (barrier == "selected")
        {
            f.Native.State.SelectedApplied = f.Entered;
            f.Native.State.SelectedTerminate = f.Resume;
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
            await Assert.That(work.IsCompleted || disposal.IsCompleted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or NativeCaseFailureException or InvalidOperationException) { }
        await disposal!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Credentials.All(c => !c.Disposed)).IsTrue();
    }

    [Test]
    public async Task StatusRoleDeleteIndependentReadProofCannotBeCopiedOrBorrowed()
    {
        using var f = new Fixture(allowPurge: true, selector: new(Guid.NewGuid(), "controlled",
            Op.Members[0].Operation, "operation.DeleteRoleAssignment", "independent-effect"));
        var plan = f.Source.PlanStatusRoleDeleteIndependentFixture("owner", f.Selector);
        await Assert.That((await f.Source.ProvisionAsync(plan, Material)).State).IsEqualTo(RoleFixtureProvisioner.State.Ready);
        Guid subscription = Guid.NewGuid();
        f.Source.ArmStatusRoleDeleteIndependentReads(plan, new("observe-arm", f.Credentials[2], f.ArmObserverTransport),
            subscription, DateTimeOffset.UtcNow);
        var proof = await f.Source.ObserveStatusRoleDeleteIndependentAsync(plan, Guid.Empty, default);
        await Assert.That(proof.NativeTask.IsCompletedSuccessfully && proof.Metadata is not null).IsTrue();
        await Assert.That(f.Source.OwnsStatusRoleDeleteIndependentRead(proof, plan, subscription, Guid.Empty)).IsTrue();
        var copy = new RoleFixtureProvisioner.StatusRoleDeleteIndependentReadProof(proof.Plan, proof.Slot, proof.Subscription,
            proof.SelectedDispatch, proof.Reader, proof.ArmedAt, proof.NativeTask, proof.NativeError, proof.HttpStatus,
            proof.Metadata! with { }, proof.RequestSha256, proof.ResponseSha256, proof.NativeRequestId,
            proof.StartedAt, proof.FinishedAt);
        await Assert.That(f.Source.OwnsStatusRoleDeleteIndependentRead(copy, plan, subscription, Guid.Empty)).IsFalse();
        await Assert.That(f.Source.OwnsStatusRoleDeleteIndependentRead(proof, plan, Guid.NewGuid(), Guid.Empty)).IsFalse();
        await Assert.That(f.Source.OwnsStatusRoleDeleteIndependentRead(proof, plan, subscription, Guid.NewGuid())).IsFalse();
        var clone = new RoleFixtureProvisioner.Plan(plan.Source, plan.Owner, plan.Selector, plan.LeaseId,
            plan.VaultId, plan.AssignmentId, plan.CreateAssignment)
        { Consumed = 1 };
        await Assert.That(f.Source.OwnsStatusRoleDeleteIndependentRead(proof, clone, subscription, Guid.Empty)).IsFalse();
        await Assert.That(f.Reopen().OwnsStatusRoleDeleteIndependentRead(proof, plan, subscription, Guid.Empty)).IsFalse();
        await Assert.That(async () => await f.Source.ObserveStatusRoleDeleteIndependentAsync(plan, Guid.Empty, default))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusRoleDeleteIndependentInvalidFirstReadConsumesItsSourceSlot(bool absent)
    {
        using var f = new Fixture(allowPurge: true, selector: new(Guid.NewGuid(), "controlled",
            Op.Members[0].Operation, "operation.DeleteRoleAssignment", "independent-effect"));
        var plan = f.Source.PlanStatusRoleDeleteIndependentFixture("owner", f.Selector);
        await Assert.That((await f.Source.ProvisionAsync(plan, Material)).State).IsEqualTo(RoleFixtureProvisioner.State.Ready);
        f.Source.ArmStatusRoleDeleteIndependentReads(plan, new("observe-arm", f.Credentials[2], f.ArmObserverTransport),
            Guid.NewGuid(), DateTimeOffset.UtcNow);
        string? assignment = f.State.AssignmentPath;
        if (absent) f.State.AssignmentPath = null;
        else f.State.AssignmentTransform = row => row["properties"]!["condition"] = true;
        await Assert.That(async () => await f.Source.ObserveStatusRoleDeleteIndependentAsync(plan, Guid.Empty, default))
            .Throws<InvalidOperationException>();
        f.State.AssignmentPath = assignment;
        f.State.AssignmentTransform = null;
        await Assert.That(async () => await f.Source.ObserveStatusRoleDeleteIndependentAsync(plan, Guid.Empty, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Read().Resources.Any(r => r.SelectedAttempted)).IsFalse();
    }

    [Test]
    public async Task StatusRoleDeleteIndependentDeniedSetupStatusCannotSettleOriginalMutation()
    {
        using var f = new Fixture(allowPurge: true, selector: new(Guid.NewGuid(), "controlled", Op.Members[0].Operation,
            "operation.DeleteRoleAssignment", "independent-effect"));
        f.State.CreateFault = "status-denied";
        var plan = f.Source.PlanStatusRoleDeleteIndependentFixture("owner", f.Selector);
        var result = await f.Source.ProvisionAsync(plan, "controlled-transient-canary");
        var receipt = result.Receipts.Single(r => r.Action == RoleFixtureProvisioner.Action.CreateVault);
        await Assert.That(receipt.NativeTask!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(receipt.StatusTask!.IsFaulted).IsTrue();
        await Assert.That(receipt.RemoteSettled).IsFalse();
        var row = f.Read().Resources.Single(r => r.Id == plan.VaultId);
        await Assert.That(row.InvocationTerminated && row.ActiveDispatch != Guid.Empty).IsTrue();
        int writes = f.WriteCount;
        int reads = f.Backends.SelectMany(b => b.Requests)
            .Count(r => r.Path.Contains("/operationResults/", StringComparison.Ordinal));
        await Assert.That(reads).IsEqualTo(1);
        await f.Source.ReleaseAsync("owner", f.Selector);
        await f.Source.ReleaseAsync("owner", f.Selector);
        await Assert.That(f.WriteCount).IsEqualTo(writes);
        await Assert.That(f.Backends.SelectMany(b => b.Requests)
            .Count(r => r.Path.Contains("/operationResults/", StringComparison.Ordinal))).IsEqualTo(reads);
        await Assert.That(f.Read().Released).IsFalse();
    }

    [Test]
    public async Task StatusRoleDeleteIndependentPendingPurgeStatusCannotSettleOriginalMutation()
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishRoleIndependent(f, started.Value!);
        f.Native.State.AsyncPurge = true;
        f.Native.State.PurgeState = "InProgress";
        await f.Release();
        var released = await f.Native.Source.ReleaseAsync("owner", f.Native.Selector);
        var receipt = released.Receipts.Single(r => r.Action == RoleFixtureProvisioner.Action.PurgeVault);
        await Assert.That(receipt.StatusTask!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(receipt.NativeOperation!.HasCompleted).IsFalse();
        await Assert.That(receipt.RemoteSettled).IsFalse();
        var row = f.Native.Read().Resources.Single(r => r.CleanupOnly);
        await Assert.That(row.InvocationTerminated && row.ActiveDispatch != Guid.Empty).IsTrue();
        int writes = f.Native.WriteCount;
        await f.Release();
        await Assert.That(f.Native.WriteCount).IsEqualTo(writes);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task StatusRoleDeleteIndependentObservationCallerRemainsAVetoAfterResponse()
    {
        await using var f = new RoleOperationServiceFixture("independent-effect", statusRoleDeleteIndependent: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        using var observation = new CancellationTokenSource();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://role-operation.fixture.invalid/operation/observe");
        request.Headers.Authorization = new("Bearer", "controlled-role-operation-capability");
        request.Content = new ByteArrayContent(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
            new ObserveLease(lease.Facts.LeaseId, lease.Facts.Nonce, "selected-state", f.Armed!.SubscriptionId),
            new System.Text.Json.JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
        request.Content.Headers.ContentType = new("application/json");
        using var response = await f.Source.DispatchAsync(request, observation.Token);
        await Assert.That(response.IsSuccessStatusCode).IsTrue();
        observation.Cancel();
        long revision = f.Native.Read().Revision;
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Revision).IsEqualTo(revision);
        int writes = f.Native.WriteCount;
        await f.Release();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.WriteCount).IsEqualTo(writes);
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
    }

    private static async Task FinishRoleIndependent(RoleOperationServiceFixture f, ManagementOperation handle)
    {
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, handle, default))
            .IsEqualTo(SecretStatus.Success);
    }
}
