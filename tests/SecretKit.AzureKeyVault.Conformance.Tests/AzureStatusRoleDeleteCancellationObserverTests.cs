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
    public async Task StatusRoleDeleteCancellationJoinsActualCanceledAndCachedTasksWithoutStatusGets()
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
        var tap = new RoleCancellationTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(2);
        await Assert.That(tap.Checks[0].Canceled && tap.Checks[0].Task.IsCanceled).IsTrue();
        await Assert.That(tap.Checks[1].Canceled).IsFalse();
        await Assert.That(tap.Checks[1].Task.Result).IsEqualTo(SecretStatus.Success);
        await Assert.That(ReferenceEquals(tap.Checks[0].Task, tap.Checks[1].Task)).IsFalse();
        await Assert.That(tap.Checks.All(c => ReferenceEquals(c.Handle, tap.Start!.Result.Value))).IsTrue();
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
        await Assert.That(f.SelectedRequests.Single().Method).IsEqualTo(HttpMethod.Delete);
        await Assert.That(f.ResourceReads).IsEqualTo(2);
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
    public async Task StatusRoleDeleteCancellationPreservesCompleteOptionalNativeMetadata(bool nulls)
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
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
    public async Task StatusRoleDeleteCancellationRejectsUnqualifiedNativeStart(int status)
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
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
    public async Task StatusRoleDeleteCancellationCannotReplaceOriginalWireOrIndependentAbsence(string fault)
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary") { Fault = fault };
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
    public async Task StatusRoleDeleteCancellationRejectsForeignOwnedBaseline(string fault)
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary") { BaselineFault = fault };
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
    public async Task StatusRoleDeleteCancellationRejectsMalformedFullBaselineBeforeSelection(string field)
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
        f.BaselineTransform = row => row["properties"]![field] = true;
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(0);
        await Assert.That(f.Native.Read().Resources.Any(r => r.SelectedAttempted)).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusRoleDeleteCancellationDoesNotDropUnknownNativeMetadata(bool nested)
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
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
    public async Task StatusRoleDeleteCancellationRequiresActualStrictResourceNotFound(string body)
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        f.Native.State.MissingAssignmentBody = body;
        await Assert.That(async () => await f.Observe(lease)).Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("noncanceled")]
    [Arguments("foreign-handle")]
    public async Task StatusRoleDeleteCancellationRejectsInvalidFirstCheckWithoutStealingActualSlot(string fault)
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await using var foreign = new RoleOperationServiceFixture("cancellation-boundary");
        var otherLease = await foreign.PrepareAndBaseline();
        var other = await foreign.Start(otherLease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector,
            fault == "foreign-handle" ? other.Value! : started.Value!,
            fault == "noncanceled" ? default : stop.Token)).Throws<InvalidOperationException>();
        await FinishRoleCancellation(f, started.Value!);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task StatusRoleDeleteCancellationGenericSettlementCannotClearSelectedFence()
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
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
        await FinishRoleCancellation(f, started.Value!);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task StatusRoleDeleteCancellationJournalCannotBypassChildDependencyOrReplayDelete()
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishRoleCancellation(f, started.Value!);
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
    public async Task StatusRoleDeleteCancellationCloseBeforeLaterCheckRetainsFence()
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, stop.Token))
            .Throws<OperationCanceledException>();
        f.Native.Journal.Close("owner", f.Native.Selector);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.State.VaultExists).IsTrue();
    }

    [Test]
    public async Task StatusRoleDeleteCancellationReappearanceBlocksReplayAndParentCleanup()
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
        var lease = await f.PrepareAndBaseline();
        string? assignment = f.Native.State.AssignmentPath;
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishRoleCancellation(f, started.Value!);
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
    public async Task StatusRoleDeleteCancellationCleanupCannotUseUnqualifiedAbsence(string body)
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishRoleCancellation(f, started.Value!);
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
    public async Task StatusRoleDeleteCancellationReconstructsActualParentOnlyForSettledCleanup(bool settled)
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        if (settled) await FinishRoleCancellation(f, started.Value!);
        await f.Source.DisposeAsync();
        var parent = f.Native.Reopen();
        await using var restarted = f.NewSource(parent);
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
    public async Task StatusRoleDeleteCancellationLostParentCleanupCannotReplayMutation(bool purge)
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await FinishRoleCancellation(f, started.Value!);
        if (purge) f.Native.State.PurgeFault = "lost";
        else f.Native.State.DeleteFault = "lost";
        await Assert.That((await f.Release()).RemainingResourceIds.Length > 0).IsTrue();
        int writes = f.Native.WriteCount;
        await f.Release();
        await Assert.That(f.Native.WriteCount).IsEqualTo(writes);
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task StatusRoleDeleteCancellationReadProofCannotBeCopiedOrBorrowed()
    {
        using var f = new Fixture(allowPurge: true, selector: new(Guid.NewGuid(), "controlled",
            Op.Members[0].Operation, "operation.DeleteRoleAssignment", "cancellation-boundary"));
        var plan = f.Plan();
        await Assert.That((await f.Source.ProvisionAsync(plan, Material)).State).IsEqualTo(RoleFixtureProvisioner.State.Ready);
        using var http = new HttpClient(new Backend("observe-arm", f.State));
        using var transport = new HttpClientTransport(http);
        Guid subscription = Guid.NewGuid();
        f.Source.ArmStatusRoleDeleteCancellationReads(plan, new("reader", f.Credentials[2], transport),
            subscription, DateTimeOffset.UtcNow);
        var proof = await f.Source.ObserveStatusRoleDeleteCancellationAsync(plan, Guid.Empty, default);
        await Assert.That(proof.NativeTask.IsCompletedSuccessfully && proof.Metadata is not null).IsTrue();
        await Assert.That(f.Source.OwnsStatusRoleDeleteRead(proof, plan, subscription, Guid.Empty)).IsTrue();
        var copy = new RoleFixtureProvisioner.StatusRoleDeleteReadProof(proof.Plan, proof.Slot, proof.Subscription,
            proof.SelectedDispatch, proof.Reader, proof.ArmedAt, proof.NativeTask, proof.NativeError, proof.HttpStatus,
            proof.Metadata! with { }, proof.RequestSha256, proof.ResponseSha256, proof.NativeRequestId,
            proof.StartedAt, proof.FinishedAt);
        await Assert.That(f.Source.OwnsStatusRoleDeleteRead(copy, plan, subscription, Guid.Empty)).IsFalse();
        await Assert.That(f.Source.OwnsStatusRoleDeleteRead(proof, plan, Guid.NewGuid(), Guid.Empty)).IsFalse();
        await Assert.That(f.Source.OwnsStatusRoleDeleteRead(proof, plan, subscription, Guid.NewGuid())).IsFalse();
        var clone = new RoleFixtureProvisioner.Plan(plan.Source, plan.Owner, plan.Selector, plan.LeaseId,
            plan.VaultId, plan.AssignmentId, plan.CreateAssignment) { Consumed = 1 };
        await Assert.That(f.Source.OwnsStatusRoleDeleteRead(proof, clone, subscription, Guid.Empty)).IsFalse();
        await Assert.That(f.Reopen().OwnsStatusRoleDeleteRead(proof, plan, subscription, Guid.Empty)).IsFalse();
        await Assert.That(async () => await f.Source.ObserveStatusRoleDeleteCancellationAsync(plan, Guid.Empty, default))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusRoleDeleteCancellationInvalidFirstReadConsumesItsSourceSlot(bool absent)
    {
        using var f = new Fixture(allowPurge: true, selector: new(Guid.NewGuid(), "controlled",
            Op.Members[0].Operation, "operation.DeleteRoleAssignment", "cancellation-boundary"));
        var plan = f.Plan();
        await Assert.That((await f.Source.ProvisionAsync(plan, Material)).State).IsEqualTo(RoleFixtureProvisioner.State.Ready);
        using var http = new HttpClient(new Backend("observe-arm", f.State));
        using var transport = new HttpClientTransport(http);
        f.Source.ArmStatusRoleDeleteCancellationReads(plan, new("reader", f.Credentials[2], transport),
            Guid.NewGuid(), DateTimeOffset.UtcNow);
        string? assignment = f.State.AssignmentPath;
        if (absent) f.State.AssignmentPath = null;
        else f.State.AssignmentTransform = row => row["properties"]!["condition"] = true;
        await Assert.That(async () => await f.Source.ObserveStatusRoleDeleteCancellationAsync(plan, Guid.Empty, default))
            .Throws<InvalidOperationException>();
        f.State.AssignmentPath = assignment;
        f.State.AssignmentTransform = null;
        await Assert.That(async () => await f.Source.ObserveStatusRoleDeleteCancellationAsync(plan, Guid.Empty, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Read().Resources.Any(r => r.SelectedAttempted)).IsFalse();
    }

    private static async Task FinishRoleCancellation(RoleOperationServiceFixture f, ManagementOperation handle)
    {
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, handle, stop.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, handle, default))
            .IsEqualTo(SecretStatus.Success);
    }

    [Test]
    [Arguments("selected")]
    [Arguments("resource")]
    [Arguments("resource-body")]
    public async Task StatusRoleDeleteCancellationDisposalDrainsActualNativeBorrower(string barrier)
    {
        await using var f = new RoleOperationServiceFixture("cancellation-boundary");
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

    private sealed class RoleCancellationBody(byte[] bytes, TaskCompletionSource entered,
        TaskCompletionSource resume) : Stream
    {
        private readonly MemoryStream inner = new(bytes, false);
        private bool paused;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => bytes.Length;
        public override long Position { get => inner.Position; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException("async-only");
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!paused)
            {
                paused = true;
                entered.TrySetResult();
                await resume.Task.ConfigureAwait(false);
            }
            return await inner.ReadAsync(buffer, CancellationToken.None).ConfigureAwait(false);
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    }

    private sealed class RoleCancellationTap(RoleOp source) : Op.SelectedInvocation
    {
        internal Task<SecretOutcome<ManagementOperation>>? Start;
        internal ManagementReceipt? Receipt;
        internal readonly List<(ManagementOperation Handle, Task<SecretStatus> Task, bool Canceled)> Checks = [];
        public async ValueTask<SecretOutcome<ManagementOperation>> RunStartAsync(FixtureSelector selector,
            VaultAdministration client, ManagementScope scope, ManagementMutation operation, Op.Input input,
            ManagementReceipt receipt, CancellationToken token)
        {
            Receipt = receipt;
            Start = source.RunStartAsync(selector, client, scope, operation, input, receipt, token).AsTask();
            return await Start;
        }
        public ValueTask<SecretStatus> RunCheckStatusAsync(FixtureSelector selector, ManagementOperation handle,
            CancellationToken token)
        {
            var task = source.RunCheckStatusAsync(selector, handle, token).AsTask();
            Checks.Add((handle, task, token.IsCancellationRequested));
            return new(task);
        }
    }
}
