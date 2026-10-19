using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Azure.ResourceManager.Authorization;
using Azure.ResourceManager.Authorization.Models;
using Azure.ResourceManager.KeyVault;
using Azure.ResourceManager.KeyVault.Models;
using Azure.Security.KeyVault.Secrets;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Service-local source component, not an HTTPS service or native qualification.
// The host exclusively controls this fixture namespace and supplies all rights.
// ARM vault create/update is not conditional-create: random names and preflight
// absence do not establish isolation from a competing authorized cloud writer.
internal sealed partial class RoleFixtureProvisioner
{
    private const string ArmOrigin = "https://management.azure.com";
    private const string VaultRevision = "2026-02-01";
    private const string RoleRevision = "2022-04-01";
    private const string SecretRevision = "2025-07-01";
    internal const string Canary = "canary";
    private const string OwnershipTag = "secretkit-fixture";
    internal enum State { Ready, Pending, Incomplete, Denied, Uncertain, Closing, SoftDeleted, Released }
    internal enum Action { CreateVault, SetCanary, CreateAssignment, DeleteAssignment, DeleteVault, PurgeVault }
    internal sealed record Limits(int MaximumResponseBytes, TimeSpan Timeout);
    internal sealed record HostScope(
        [property: JsonIgnore] Guid SubscriptionId,
        [property: JsonIgnore] string ResourceGroup,
        [property: JsonIgnore] string Location,
        [property: JsonIgnore] Guid TenantId,
        [property: JsonIgnore] Guid IntendedPrincipalId,
        [property: JsonIgnore] Guid IntendedRoleDefinitionId,
        bool ExclusiveFixtureNamespace, bool AllowPurge = false)
    {
        public override string ToString() => "[RoleFixtureHostScope]";
    }
    internal sealed record Authority(
        [property: JsonIgnore] string Label,
        [property: JsonIgnore] TokenCredential Credential,
        [property: JsonIgnore] HttpPipelineTransport Transport)
    {
        public override string ToString() => "[RoleFixtureAuthority]";
    }
    internal sealed record BorrowedSelectors(
        [property: JsonIgnore] Guid? GroupAssignmentId,
        [property: JsonIgnore] Guid? SubscriptionAssignmentId,
        [property: JsonIgnore] Guid[] AdditionalDefinitionIds)
    {
        public override string ToString() => "[RoleFixtureBorrowedSelectors]";
    }
    internal sealed record BorrowedReadback(
        [property: JsonIgnore] string Id, [property: JsonIgnore] string Sha256)
    {
        public override string ToString() => "[RoleFixtureBorrowedReadback]";
    }
    internal sealed class Receipt(Action action)
    {
        internal Action Action { get; } = action;
        internal bool Attempted { get; set; }
        internal bool Terminated { get; set; }
        internal bool RemoteSettled { get; set; }
        internal int? HttpStatus { get; set; }
        internal string? NativeRequestId { get; set; }
        internal State Outcome { get; set; } = State.Uncertain;
        internal Guid Dispatch { get; set; }
        // Retained native receipt, never serialized, logged, automatically polled,
        // or used as authority to replay the mutation.
        internal Operation? NativeOperation { get; set; }
        internal BoundaryTransport? StatusTransport { get; set; }
        internal Task? NativeTask { get; set; }
        internal Task? StatusTask { get; set; }
        public override string ToString() => "[RoleFixtureReceipt]";
    }
    internal sealed class Plan
    {
        internal Plan(object source, string owner, FixtureSelector selector, Guid leaseId,
            string vaultId, string assignmentId, bool createAssignment)
        {
            Source = source;
            Owner = owner;
            Selector = selector;
            LeaseId = leaseId;
            VaultId = vaultId;
            AssignmentId = assignmentId;
            CreateAssignment = createAssignment;
        }
        internal object Source { get; }
        internal string Owner { get; }
        internal FixtureSelector Selector { get; }
        internal Guid LeaseId { get; }
        internal string VaultId { get; }
        internal string AssignmentId { get; }
        internal bool CreateAssignment { get; }
        internal string VaultName => VaultId[(VaultId.LastIndexOf('/') + 1)..];
        internal string SecretId => VaultId + "/secrets/" + Canary;
        internal List<Receipt> History { get; } = [];
        internal IReadOnlyList<Receipt> Receipts { get { lock (History) return History.ToArray(); } }
        internal int Consumed;
        internal int Busy;
        internal string? CanaryVersion;
        internal RoleFixtureJournal.Snapshot? IndependentCommitted;
        internal RoleFixtureJournal.Snapshot? IndependentReady;
        internal bool IndependentRestored;
        internal CancellationToken IndependentCaller;
        public override string ToString() => "[RoleFixturePlan]";
    }
    internal sealed class Result
    {
        internal required State State { get; init; }
        internal IReadOnlyList<Receipt> Receipts { get; init; } = [];
        internal IReadOnlyList<BorrowedReadback> Borrowed { get; init; } = [];
        internal bool? VaultReady { get; init; }
        internal bool? AssignmentPresent { get; init; }
        internal bool? CanaryPresent { get; init; }
        internal string? CanarySha256 { get; init; }
        internal string? CanaryVersion { get; init; }
        internal RoleFixtureJournal.Snapshot? Journal { get; init; }
        public override string ToString() => "[RoleFixtureResult]";
    }

    private readonly RoleFixtureJournal journal;
    private readonly HostScope host;
    private readonly Authority setupArm;
    private readonly Authority setupSecret;
    private readonly Authority observeArm;
    private readonly Authority observeSecret;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly object source = new();
    private readonly Dictionary<Guid, Plan> plans = [];
    private readonly HashSet<Plan> prepared = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, StatusRoleReadSlots> statusRoleReads = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<StatusRoleDeleteReadProof> issuedStatusRoleReads = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Guid, (Plan Plan, Receipt Receipt)> selectedReceipts = [];
    private readonly HashSet<Plan> independentPlans = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, StatusRoleReadSlots> independentReads = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<StatusRoleDeleteIndependentReadProof> issuedIndependentReads = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusRoleDeleteIndependentFixtureAdmission,
        IndependentFixtureAdmission> independentAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusRoleDeleteIndependentFixtureDrain,
        IndependentFixtureDrain> independentDrains = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusRoleDeleteIndependentAbsence,
        IndependentAbsence> independentAbsences = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Receipt, StatusRoleDeleteIndependentFixtureDrain> independentPending = new(ReferenceEqualityComparer.Instance);
    internal HostScope Host => host;
    internal RoleFixtureJournal Journal => journal;
    internal static bool StatusRoleDeleteCancellationSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.DeleteRoleAssignment" && selector.Case == "cancellation-boundary";

    internal static bool StatusRoleDeleteIndependentSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.DeleteRoleAssignment" && selector.Case == "independent-effect";

    internal void ValidateStatusRoleDeleteIndependentAuthorities(ManagementOperationResourceCollector.Authority reader,
        HttpPipelineTransport selectedBackend) =>
        Require(reader is not null && ReferenceEquals(reader.Credential, observeArm.Credential) &&
            ReferenceEquals(reader.Transport, observeArm.Transport) && reader.Label == observeArm.Label &&
            selectedBackend is not null && new[] { setupArm, setupSecret, observeArm, observeSecret }
                .All(a => !ReferenceEquals(a.Transport, selectedBackend)));

    internal Plan PlanStatusRoleDeleteIndependentFixture(string owner, FixtureSelector selector)
    {
        Require(StatusRoleDeleteIndependentSelector(selector) && host.AllowPurge);
        var plan = PlanFixtureCore(owner, selector, new(null, null, []), true);
        lock (plans) independentPlans.Add(plan);
        return plan;
    }

    internal void ArmStatusRoleDeleteIndependentReads(Plan originalPlan,
        ManagementOperationResourceCollector.Authority reader, Guid subscription, DateTimeOffset armedAt)
    {
        lock (plans)
        {
            Require(independentPlans.Contains(originalPlan) && !originalPlan.IndependentRestored &&
                prepared.Contains(originalPlan) && ReferenceEquals(originalPlan.Source, source) &&
                originalPlan.IndependentReady is not null &&
                plans.TryGetValue(originalPlan.Selector.Nonce, out var retained) && ReferenceEquals(retained, originalPlan) &&
                ReferenceEquals(reader.Credential, observeArm.Credential) &&
                ReferenceEquals(reader.Transport, observeArm.Transport) && reader.Label == observeArm.Label &&
                subscription != Guid.Empty && !independentReads.ContainsKey(originalPlan));
            independentReads.Add(originalPlan, new(observeArm, subscription, armedAt));
        }
    }

    internal bool OwnsStatusRoleDeleteIndependentRead(StatusRoleDeleteIndependentReadProof proof, Plan originalPlan,
        Guid subscription, Guid selectedDispatch)
    {
        lock (plans)
            return proof is not null && issuedIndependentReads.Contains(proof) &&
                independentPlans.Contains(originalPlan) && !originalPlan.IndependentRestored &&
                ReferenceEquals(proof.Plan, originalPlan) && prepared.Contains(originalPlan) &&
                independentReads.TryGetValue(originalPlan, out var slots) &&
                proof.Subscription == subscription && slots.Subscription == subscription &&
                proof.SelectedDispatch == selectedDispatch &&
                ReferenceEquals(proof.Slot, selectedDispatch == Guid.Empty ? slots.BaselineSlot : slots.AfterSlot);
    }

    private static RoleFixtureJournal.Snapshot FreezeIndependent(RoleFixtureJournal.Snapshot state) =>
        state with { Selector = state.Selector with { }, Resources = state.Resources.ToArray() };

    internal sealed class StatusRoleDeleteIndependentFixtureAdmission(RoleFixtureProvisioner source)
    {
        internal string ResourceId => source.independentAdmissions.TryGetValue(this, out var f) ? f.Id : "";
        internal bool Delete => source.independentAdmissions.TryGetValue(this, out var f) &&
            f.Action is Action.DeleteAssignment or Action.DeleteVault or Action.PurgeVault;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            ReferenceEquals(source.journal, journal) && source.independentAdmissions.TryGetValue(this, out var f) &&
            !f.Token.IsCancellationRequested && !f.CallerToken.IsCancellationRequested &&
            RoleFixtureJournal.SameStatusRoleDeleteIndependentSnapshot(f.Preimage, state) &&
            f.Plan.Owner == state.Owner && f.Plan.Selector == state.Selector && f.Plan.LeaseId == state.LeaseId;
        public override string ToString() => "[StatusRoleDeleteIndependentFixtureAdmission]";
    }

    private sealed record IndependentFixtureAdmission(Plan Plan, RoleFixtureJournal.Snapshot Preimage,
        string Id, Action Action, CancellationToken Token, CancellationToken CallerToken);

    internal sealed class StatusRoleDeleteIndependentFixtureDrain(RoleFixtureProvisioner source)
    {
        internal string ResourceId => source.independentDrains.TryGetValue(this, out var f) ? f.Id : "";
        internal Guid Dispatch => source.independentDrains.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Settled => source.independentDrains.TryGetValue(this, out var f) && f.Settled;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateIndependentFixtureDrain(this, journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateIndependentFixtureDrain(this, journal, state, true);
        public override string ToString() => "[StatusRoleDeleteIndependentFixtureDrain]";
    }

    private sealed record IndependentFixtureDrain(Plan Plan, RoleFixtureJournal.Snapshot Preimage,
        string Id, Guid Dispatch, Task NativeTask, Task? StatusTask, bool Settled, CancellationToken Token, CancellationToken CallerToken);

    private bool ValidateIndependentFixtureDrain(StatusRoleDeleteIndependentFixtureDrain drain,
        RoleFixtureJournal owningJournal, RoleFixtureJournal.Snapshot state, bool postimage) =>
        ReferenceEquals(journal, owningJournal) && independentDrains.TryGetValue(drain, out var f) &&
        !f.Token.IsCancellationRequested && !f.CallerToken.IsCancellationRequested && f.NativeTask.IsCompleted &&
        (f.StatusTask is null || f.StatusTask.IsCompleted) &&
        RoleFixtureJournal.SameStatusRoleDeleteIndependentSnapshot(postimage ? IndependentFixturePostimage(f) : f.Preimage, state);

    private static RoleFixtureJournal.Snapshot IndependentFixturePostimage(IndependentFixtureDrain f) =>
        f.Preimage with
        {
            Revision = f.Preimage.Revision + 1,
            Resources = f.Preimage.Resources.Select(r => r.Id == f.Id
                ? r with { InvocationTerminated = true, ActiveDispatch = f.Settled ? Guid.Empty : f.Dispatch } : r).ToArray()
        };

    internal sealed class StatusRoleDeleteIndependentAbsence(RoleFixtureProvisioner source)
    {
        internal bool Final => source.independentAbsences.TryGetValue(this, out var f) && f.Final;
        internal string ResourceId => source.independentAbsences.TryGetValue(this, out var f) ? f.Plan.AssignmentId : "";
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            ReferenceEquals(source.journal, journal) && source.independentAbsences.TryGetValue(this, out var f) &&
            !f.Token.IsCancellationRequested && !f.CallerToken.IsCancellationRequested &&
            f.Role.Task.IsFaulted && f.Role.Error is { Status: 404, ErrorCode: "ResourceNotFound" } &&
            f.Role.Metadata is null && (!f.Final || f.Vault is { Absent: true } && f.Deleted is { Absent: true }) &&
            RoleFixtureJournal.SameStatusRoleDeleteIndependentSnapshot(f.Preimage, state);
        public override string ToString() => "[StatusRoleDeleteIndependentAbsence]";
    }

    private sealed record IndependentAbsence(Plan Plan, RoleFixtureJournal.Snapshot Preimage, StatusRoleRead Role,
        IndependentOwnedRead? Vault, IndependentOwnedRead? Deleted, bool Final,
        CancellationToken Token, CancellationToken CallerToken);

    private RoleFixtureJournal.Snapshot PersistIndependentFixture(StatusRoleDeleteIndependentFixtureDrain drain)
    {
        Require(independentDrains.TryGetValue(drain, out var f));
        try
        {
            var committed = journal.EndStatusRoleDeleteIndependentFixtureDispatch(f!.Plan.Owner, f.Plan.Selector,
                f.Plan.LeaseId, drain);
            f.Plan.IndependentCommitted = FreezeIndependent(committed);
            return committed;
        }
        catch (RoleFixtureJournal.StatusRoleDeleteIndependentHistoryException)
        {
            InvalidateIndependentFixture(drain);
            throw;
        }
        catch
        {
            // Only an exact preimage or postimage may survive an append failure.
            // Acceptance itself always happens inside End... under the journal lock.
            RoleFixtureJournal.Snapshot state;
            try { state = journal.Read(f!.Plan.Owner, f.Plan.Selector); }
            catch (RoleFixtureJournal.StatusRoleDeleteIndependentHistoryException)
            { InvalidateIndependentFixture(drain); throw; }
            if (!drain.Validate(journal, state) && !drain.AcceptPostimage(journal, state))
            {
                InvalidateIndependentFixture(drain);
                var row = state.Resources.Single(r => r.Id == f!.Id);
                if (row.ActiveDispatch == f!.Dispatch && !row.InvocationTerminated)
                    journal.EndDispatch(f.Plan.Owner, f.Plan.Selector, f.Id, f.Dispatch, nativeSettled: false);
            }
            throw;
        }
    }

    private void InvalidateIndependentFixture(StatusRoleDeleteIndependentFixtureDrain drain)
    {
        independentDrains.TryRemove(drain, out _);
        lock (plans)
            foreach (var receipt in independentPending.Where(pair => ReferenceEquals(pair.Value, drain))
                .Select(pair => pair.Key).ToArray())
                independentPending.Remove(receipt);
    }

    private sealed class StatusRoleReadSlots(Authority reader, Guid subscription, DateTimeOffset armedAt)
    {
        internal readonly Authority Reader = reader;
        internal readonly Guid Subscription = subscription;
        internal readonly DateTimeOffset ArmedAt = armedAt;
        internal readonly object BaselineSlot = new(), AfterSlot = new();
        internal bool Baseline, After;
    }

    internal void ArmStatusRoleDeleteCancellationReads(Plan originalPlan,
        ManagementOperationResourceCollector.Authority reader, Guid subscription, DateTimeOffset armedAt)
    {
        lock (plans)
        {
            Require(StatusRoleDeleteCancellationSelector(originalPlan.Selector) &&
                ReferenceEquals(originalPlan.Source, source) && prepared.Contains(originalPlan) &&
                plans.TryGetValue(originalPlan.Selector.Nonce, out var retained) && ReferenceEquals(retained, originalPlan) &&
                subscription != Guid.Empty && !statusRoleReads.ContainsKey(originalPlan));
            statusRoleReads.Add(originalPlan, new(new(reader.Label, reader.Credential, reader.Transport), subscription, armedAt));
        }
    }

    internal bool OwnsStatusRoleDeleteRead(StatusRoleDeleteReadProof proof, Plan originalPlan,
        Guid subscription, Guid selectedDispatch)
    {
        lock (plans)
            return proof is not null && issuedStatusRoleReads.Contains(proof) &&
                ReferenceEquals(proof.Plan, originalPlan) && ReferenceEquals(originalPlan.Source, source) &&
                prepared.Contains(originalPlan) && statusRoleReads.TryGetValue(originalPlan, out var slots) &&
                slots.Subscription == subscription && proof.Subscription == subscription &&
                ReferenceEquals(proof.Slot, selectedDispatch == Guid.Empty ? slots.BaselineSlot : slots.AfterSlot) &&
                proof.SelectedDispatch == selectedDispatch;
    }
    private string SubscriptionId => $"/subscriptions/{host.SubscriptionId:D}";
    private string GroupId => SubscriptionId + "/resourceGroups/" + host.ResourceGroup;
    private string DefinitionId => SubscriptionId + $"/providers/Microsoft.Authorization/roleDefinitions/{host.IntendedRoleDefinitionId:D}";

    internal RoleFixtureJournal.Snapshot CloseSelectedRoot(string owner, FixtureSelector selector) => journal.Close(owner, selector);
    internal Guid BeginSelectedDispatch(string owner, FixtureSelector selector, string id, bool delete)
    {
        var plan = Reconstruct(ReadPlan(owner, selector));
        Require(Same(plan.AssignmentId, id));
        Guid dispatch = journal.BeginSelectedDispatch(owner, selector, id, delete);
        var receipt = new Receipt(delete ? Action.DeleteAssignment : Action.CreateAssignment)
        {
            Dispatch = dispatch,
            Attempted = true
        };
        lock (plans)
        {
            lock (plan.History) plan.History.Add(receipt);
            selectedReceipts.Add(dispatch, (plan, receipt));
        }
        return dispatch;
    }
    internal void EndSelectedDispatch(string owner, FixtureSelector selector, string id, Guid dispatch, bool settled)
    {
        lock (plans)
        {
            if (!plans.TryGetValue(selector.Nonce, out var retained)) throw Failure();
            Require(retained.Owner == owner && retained.Selector == selector && Same(retained.AssignmentId, id));
            if (!selectedReceipts.TryGetValue(dispatch, out var admitted) ||
                !ReferenceEquals(admitted.Plan, retained)) throw Failure();
            // Only selected admission can supply this receipt. Retain actual
            // termination before persistence so contention cannot erase it.
            lock (retained.History)
            {
                var receipt = admitted.Receipt;
                Require(receipt.Dispatch == dispatch && receipt.Attempted && !receipt.Terminated);
                receipt.Terminated = true;
                receipt.RemoteSettled = settled;
                selectedReceipts.Remove(dispatch);
            }
        }
        journal.EndDispatch(owner, selector, id, dispatch, settled);
    }

    internal RoleFixtureProvisioner(RoleFixtureJournal journal, HostScope host, Authority setupArm,
        Authority setupSecret, Authority observeArm, Authority observeSecret, Limits limits, TimeProvider? time = null)
    {
        Authority[] authorities = [setupArm, setupSecret, observeArm, observeSecret];
        Require(journal is not null && host is not null && host.SubscriptionId != Guid.Empty &&
            host.ExclusiveFixtureNamespace && host.TenantId != Guid.Empty && host.IntendedPrincipalId != Guid.Empty &&
            host.IntendedRoleDefinitionId != Guid.Empty && Segment(host.ResourceGroup, 90) &&
            Segment(host.Location, 50) && authorities.All(a => a is not null && a.Credential is not null &&
                a.Transport is not null && !string.IsNullOrWhiteSpace(a.Label) && a.Label.Length <= 128) &&
            authorities.Select(a => a.Credential).Distinct(ReferenceEqualityComparer.Instance).Count() == 4 &&
            authorities.Select(a => a.Transport).Distinct(ReferenceEqualityComparer.Instance).Count() == 4 &&
            authorities.Select(a => a.Label).Distinct(StringComparer.Ordinal).Count() == 4 &&
            limits is not null && limits.MaximumResponseBytes is >= 1024 and <= 16 * 1024 * 1024 &&
            limits.Timeout > TimeSpan.Zero && limits.Timeout <= TimeSpan.FromMinutes(2));
        this.journal = journal!;
        this.host = host!;
        this.setupArm = setupArm;
        this.setupSecret = setupSecret;
        this.observeArm = observeArm;
        this.observeSecret = observeSecret;
        this.limits = limits!;
        this.time = time ?? TimeProvider.System;
    }

    // Distinct objects prevent accidental local aliasing only. Actual principal,
    // tenant and operational separation are host acquisition/qualification facts.

    // The returned plan is held before invocation, but recovery needs only the
    // authenticated owner and original full selector. All coordinates are saved
    // before even read-only native setup begins.
    internal Plan PlanFixture(string owner, FixtureSelector selector, BorrowedSelectors borrowed, bool createAssignment)
    {
        Require(!StatusRoleDeleteIndependentSelector(selector));
        return PlanFixtureCore(owner, selector, borrowed, createAssignment);
    }

    private Plan PlanFixtureCore(string owner, FixtureSelector selector, BorrowedSelectors borrowed, bool createAssignment)
    {
        Require(!StatusRoleDeleteCancellationSelector(selector) ||
            createAssignment && borrowed is
            {
                GroupAssignmentId: null, SubscriptionAssignmentId: null,
                AdditionalDefinitionIds.Length: 0
            });
        Require(borrowed is not null && borrowed.AdditionalDefinitionIds is { Length: <= 8 } &&
            borrowed.AdditionalDefinitionIds.All(g => g != Guid.Empty) &&
            borrowed.GroupAssignmentId != Guid.Empty && borrowed.SubscriptionAssignmentId != Guid.Empty);
        string vault = GroupId + "/providers/Microsoft.KeyVault/vaults/sk" + Guid.NewGuid().ToString("N")[..22];
        string assignment = vault + "/providers/Microsoft.Authorization/roleAssignments/" + Guid.NewGuid().ToString("D");
        List<RoleFixtureJournal.Resource> resources =
        [
            new(vault, false), new(vault + "/secrets/" + Canary, false), new(assignment, false),
            new(DeletedId(vault[(vault.LastIndexOf('/') + 1)..]), false, CleanupOnly: true)
        ];
        resources.Add(new(DefinitionId, true));
        if (borrowed!.GroupAssignmentId is { } group)
            resources.Add(new(GroupId + $"/providers/Microsoft.Authorization/roleAssignments/{group:D}", true));
        if (borrowed.SubscriptionAssignmentId is { } subscription)
            resources.Add(new(SubscriptionId + $"/providers/Microsoft.Authorization/roleAssignments/{subscription:D}", true));
        foreach (Guid definition in borrowed.AdditionalDefinitionIds)
            resources.Add(new(SubscriptionId + $"/providers/Microsoft.Authorization/roleDefinitions/{definition:D}", true));
        var state = journal.Prepare(owner, selector, resources.ToArray());
        var plan = new Plan(source, owner, selector, state.LeaseId, vault, assignment, createAssignment);
        if (StatusRoleDeleteIndependentSelector(selector)) plan.IndependentCommitted = FreezeIndependent(state);
        lock (plans) plans.Add(selector.Nonce, plan);
        return plan;
    }

    internal async ValueTask<Result> ProvisionAsync(Plan plan, string transientCanary, CancellationToken cancellationToken = default,
        CancellationToken? originalCallerToken = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Require(plan is not null && ReferenceEquals(plan.Source, source) &&
            transientCanary is { Length: > 0 and <= 4096 });
        if (Interlocked.Exchange(ref plan!.Consumed, 1) != 0) throw Failure();
        if (Interlocked.Exchange(ref plan.Busy, 1) != 0) throw Failure();
        if (StatusRoleDeleteIndependentSelector(plan.Selector))
        {
            lock (plans) Require(independentPlans.Contains(plan) && !plan.IndependentRestored);
            plan.IndependentCaller = originalCallerToken ?? cancellationToken;
        }
        using var deadline = new CancellationTokenSource(limits.Timeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        var borrowed = new List<BorrowedReadback>();
        try
        {
            var state = ReadPlan(plan.Owner, plan.Selector);
            Require(!state.Closing && state.LeaseId == plan.LeaseId && state.Resources.All(r => !r.CreateAttempted));
            await BorrowedAsync(state, borrowed, linked.Token).ConfigureAwait(false);
            var before = await ObserveVault(plan, linked.Token).ConfigureAwait(false);
            bool deleted = await DeletedExists(plan, linked.Token).ConfigureAwait(false);
            Require(before is null && !deleted);
            State created = await Mutation(plan, plan.VaultId, Action.CreateVault, async (transport, token) =>
            {
                var properties = new KeyVaultProperties(host.TenantId, new(KeyVaultSkuFamily.A, KeyVaultSkuName.Standard))
                {
                    EnableRbacAuthorization = true,
                    EnableSoftDelete = true,
                    EnablePurgeProtection = !host.AllowPurge,
                    SoftDeleteRetentionInDays = 7,
                    PublicNetworkAccess = "Enabled",
                    CreateMode = KeyVaultCreateMode.Default
                };
                var content = new KeyVaultCreateOrUpdateContent(host.Location, properties);
                content.Tags.Add(OwnershipTag, plan.Selector.Nonce.ToString("N"));
                return await Arm(setupArm, transport).GetResourceGroupResource(new(GroupId)).GetKeyVaults()
                    .CreateOrUpdateAsync(WaitUntil.Started, plan.VaultName, content, token).ConfigureAwait(false);
            }, linked.Token).ConfigureAwait(false);
            if (created is not (State.Ready or State.Pending)) return Finish(created, plan, borrowed);
            var vault = await ObserveVault(plan, linked.Token).ConfigureAwait(false);
            if (vault is null) return Finish(State.Uncertain, plan, borrowed);
            ValidateVault(plan, vault);
            if (!Succeeded(vault)) return Finish(State.Pending, plan, borrowed);
            SettleObservedVault(plan);

            return await Downstream(plan, transientCanary, borrowed, linked.Token).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            if (cancellationToken.IsCancellationRequested) throw new OperationCanceledException(cancellationToken);
            return Finish(exception is RequestFailedException { Status: 401 or 403 } ? State.Denied : State.Uncertain, plan, borrowed);
        }
        finally { Volatile.Write(ref plan.Busy, 0); }
    }

    // Explicit first-time downstream setup after an observed pending vault.
    // Persisted attempts are read, never reset; an attempted canary is independently
    // checked rather than set again. The original pre-held plan is required.
    internal async ValueTask<Result> ContinueAsync(Plan plan, string transientCanary, CancellationToken cancellationToken = default)
    {
        Require(!StatusRoleDeleteIndependentSelector(plan.Selector));
        cancellationToken.ThrowIfCancellationRequested();
        Require(plan is not null && ReferenceEquals(plan.Source, source) && plan.Consumed == 1 &&
            transientCanary is { Length: > 0 and <= 4096 });
        if (Interlocked.Exchange(ref plan!.Busy, 1) != 0) throw Failure();
        using var deadline = new CancellationTokenSource(limits.Timeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        var borrowed = new List<BorrowedReadback>();
        try
        {
            var state = ReadPlan(plan.Owner, plan.Selector);
            Require(!state.Closing && state.LeaseId == plan.LeaseId &&
                state.Resources.All(r => r.ActiveDispatch == Guid.Empty ||
                    r.Id == plan.VaultId && r.InvocationTerminated) &&
                state.Resources.Single(r => r.Id == plan.VaultId).CreateAttempted);
            await BorrowedAsync(state, borrowed, linked.Token).ConfigureAwait(false);
            var vault = await ObserveVault(plan, linked.Token).ConfigureAwait(false);
            Require(vault is not null);
            ValidateVault(plan, vault!);
            if (!Succeeded(vault!)) return Finish(State.Pending, plan, borrowed);
            SettleObservedVault(plan);
            return await Downstream(plan, transientCanary, borrowed, linked.Token).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            if (cancellationToken.IsCancellationRequested) throw new OperationCanceledException(cancellationToken);
            return Finish(exception is RequestFailedException { Status: 401 or 403 } ? State.Denied : State.Uncertain, plan, borrowed);
        }
        finally { Volatile.Write(ref plan.Busy, 0); }
    }

    private void SettleObservedVault(Plan plan)
    {
        // Called only after the independently read nonce-owned vault reports
        // Succeeded. Resource absence is never used to infer native settlement.
        var row = journal.Read(plan.Owner, plan.Selector).Resources.Single(r => r.Id == plan.VaultId);
        if (StatusRoleDeleteIndependentSelector(plan.Selector))
        {
            Require(row.ActiveDispatch == Guid.Empty && row.InvocationTerminated);
            return;
        }
        if (row.ActiveDispatch != Guid.Empty)
        {
            Require(row.InvocationTerminated);
            journal.SettleDispatch(plan.Owner, plan.Selector, row.Id, row.ActiveDispatch);
        }
    }

    private async Task<Result> Downstream(Plan plan, string transientCanary, List<BorrowedReadback> borrowed, CancellationToken token)
    {
        var state = ReadPlan(plan.Owner, plan.Selector);
        Require(!state.Closing);
        if (!state.Resources.Single(r => r.Id == plan.SecretId).CreateAttempted)
        {
            State secret = await Mutation(plan, plan.SecretId, Action.SetCanary, async (transport, ct) =>
            {
                var response = await Secret(setupSecret, plan, transport)
                    .SetSecretAsync(new KeyVaultSecret(Canary, transientCanary), ct).ConfigureAwait(false);
                using var raw = response.GetRawResponse();
                Require(response.Value.Name == Canary && response.Value.Properties.VaultUri == SecretOrigin(plan) &&
                    Version(response.Value.Properties.Version));
                plan.CanaryVersion = response.Value.Properties.Version;
                return null;
            }, token).ConfigureAwait(false);
            if (secret != State.Ready) return Finish(secret, plan, borrowed);
        }
        var canary = await ObserveCore(plan, borrowed, token).ConfigureAwait(false);
        if (canary.VaultReady != true || canary.CanarySha256 != Hash(transientCanary))
            return Finish(State.Uncertain, plan, borrowed);
        if (plan.CreateAssignment && !state.Resources.Single(r => r.Id == plan.AssignmentId).CreateAttempted)
        {
            State assignment = await Mutation(plan, plan.AssignmentId, Action.CreateAssignment, async (transport, ct) =>
                await Arm(setupArm, transport).GetRoleAssignments(new(plan.VaultId))
                    .CreateOrUpdateAsync(WaitUntil.Started, plan.AssignmentId[(plan.AssignmentId.LastIndexOf('/') + 1)..],
                        new RoleAssignmentCreateOrUpdateContent(new(DefinitionId), host.IntendedPrincipalId),
                        ct).ConfigureAwait(false), token).ConfigureAwait(false);
            if (assignment != State.Ready) return Finish(assignment, plan, borrowed);
        }
        var observed = await ObserveCore(plan, borrowed, token).ConfigureAwait(false);
        if (observed.CanarySha256 != Hash(transientCanary) || observed.AssignmentPresent != plan.CreateAssignment)
            return Finish(State.Uncertain, plan, borrowed);
        if (StatusRoleDeleteIndependentSelector(plan.Selector))
        {
            Require(plan.IndependentCommitted is not null && observed.Journal is not null &&
                RoleFixtureJournal.SameStatusRoleDeleteIndependentSnapshot(plan.IndependentCommitted, observed.Journal) &&
                observed.Journal.Resources.All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                    r.ActiveDispatch == Guid.Empty && (r.Borrowed || r.CleanupOnly
                        ? !r.CreateAttempted && !r.InvocationTerminated : r.CreateAttempted && r.InvocationTerminated)));
            plan.IndependentReady = FreezeIndependent(plan.IndependentCommitted!);
        }
        if (observed.VaultReady == true && observed.CanaryPresent == true)
            lock (plans) prepared.Add(plan);
        return new()
        {
            State = observed.VaultReady == true && observed.CanaryPresent == true ? State.Ready : State.Incomplete,
            Receipts = plan.Receipts,
            Borrowed = borrowed.AsReadOnly(),
            Journal = StatusRoleDeleteIndependentSelector(plan.Selector) ? plan.IndependentReady :
                journal.Read(plan.Owner, plan.Selector),
            VaultReady = observed.VaultReady,
            AssignmentPresent = observed.AssignmentPresent,
            CanaryPresent = observed.CanaryPresent,
            CanarySha256 = observed.CanarySha256,
            CanaryVersion = observed.CanaryVersion
        };
    }

    // One explicit read-only pass, not polling or a continuation of setup.
    internal async ValueTask<Result> ObserveAsync(string owner, FixtureSelector selector, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var snapshot = ReadPlan(owner, selector);
        var plan = Reconstruct(snapshot);
        using var deadline = new CancellationTokenSource(limits.Timeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        var borrowed = new List<BorrowedReadback>();
        try
        {
            if (snapshot.Resources.Any(r => r.ActiveDispatch != Guid.Empty && !r.InvocationTerminated))
                return Finish(State.Pending, plan, borrowed);
            await BorrowedAsync(snapshot, borrowed, linked.Token).ConfigureAwait(false);
            return await ObserveCore(plan, borrowed, linked.Token).ConfigureAwait(false);
        }
        catch
        {
            if (cancellationToken.IsCancellationRequested) throw new OperationCanceledException(cancellationToken);
            return Finish(State.Uncertain, plan, borrowed);
        }
    }

    // Close is durable even without a prepare reply. Active invocations cause a
    // bounded Pending result, not an inferred drain. A restarted active dispatch
    // remains unresolved. A subsequent call only sends never-attempted deletes.
    internal async ValueTask<Result> ReleaseAsync(string owner, FixtureSelector selector, bool purge = false,
        CancellationToken cancellationToken = default, CancellationToken? originalCallerToken = null)
    {
        if (StatusRoleDeleteIndependentSelector(selector))
            return await ReleaseIndependent(owner, selector, purge, cancellationToken,
                originalCallerToken ?? cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        Require(!purge || host.AllowPurge);
        var snapshot = journal.Close(owner, selector);
        if (snapshot.Resources.Length == 0) return new() { State = State.Released, Journal = snapshot };
        snapshot = ReadPlan(owner, selector);
        var plan = Reconstruct(snapshot);
        if (snapshot.Resources.Any(r => r.ActiveDispatch != Guid.Empty)) return Finish(State.Pending, plan, []);
        using var deadline = new CancellationTokenSource(limits.Timeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            var vault = await ObserveVault(plan, linked.Token).ConfigureAwait(false);
            if (vault is not null)
            {
                ValidateVault(plan, vault);
                if (!Terminal(vault)) return Finish(State.Pending, plan, []);
            }
            var assignment = await ObserveAssignment(plan.AssignmentId, linked.Token).ConfigureAwait(false);
            var ownedAssignment = snapshot.Resources.Single(r => r.Id == plan.AssignmentId);
            if (assignment is not null)
            {
                ValidateAssignment(plan, assignment);
                if (!ownedAssignment.CreateAttempted) return Finish(State.Uncertain, plan, []);
                if (ownedAssignment.SelectedAttempted &&
                    (selector.Operation == ManagementOperationEffects.Members[0].Operation &&
                        selector.Variant == "operation.DeleteRoleAssignment" ||
                        StatusRoleDeleteCancellationSelector(selector)))
                    return Finish(State.Uncertain, plan, []);
                if (!ownedAssignment.DeleteAttempted)
                    await Mutation(plan, plan.AssignmentId, Action.DeleteAssignment, async (transport, token) =>
                        await Arm(setupArm, transport).GetRoleAssignmentResource(new(plan.AssignmentId))
                            .DeleteAsync(WaitUntil.Started, cancellationToken: token).ConfigureAwait(false), linked.Token).ConfigureAwait(false);
            }
            var ownedVault = snapshot.Resources.Single(r => r.Id == plan.VaultId);
            if (vault is not null && ownedVault.CreateAttempted && !ownedVault.DeleteAttempted)
            {
                if (StatusRoleDeleteCancellationSelector(selector) &&
                    !await FreshStatusRoleAbsence(plan, linked.Token).ConfigureAwait(false))
                    return Finish(State.Uncertain, plan, []);
                await Mutation(plan, plan.VaultId, Action.DeleteVault, async (transport, token) =>
                    await Arm(setupArm, transport).GetKeyVaultResource(new(plan.VaultId))
                        .DeleteAsync(WaitUntil.Started, token).ConfigureAwait(false), linked.Token).ConfigureAwait(false);
            }
            bool active = await ObserveVault(plan, linked.Token).ConfigureAwait(false) is not null;
            var deletedVault = await ObserveDeleted(plan, linked.Token).ConfigureAwait(false);
            var purgeRow = snapshot.Resources.Single(r => r.CleanupOnly);
            if (purge && !active && deletedVault is not null && !purgeRow.DeleteAttempted)
            {
                Require(ownedVault.CreateAttempted &&
                    journal.Read(owner, selector).Resources.Single(r => r.Id == plan.VaultId).DeleteAttempted);
                ValidateDeleted(plan, deletedVault);
                Require(deletedVault.Properties.PurgeProtectionEnabled != true);
                if (StatusRoleDeleteCancellationSelector(selector) &&
                    !await FreshStatusRoleAbsence(plan, linked.Token).ConfigureAwait(false))
                    return Finish(State.Uncertain, plan, []);
                await Mutation(plan, purgeRow.Id, Action.PurgeVault, async (transport, token) =>
                    await Arm(setupArm, transport).GetDeletedKeyVaultResource(new(purgeRow.Id))
                        .PurgeDeletedAsync(WaitUntil.Started, token).ConfigureAwait(false), linked.Token).ConfigureAwait(false);
            }
            // Re-read after the final local native invocation has terminated. Even a
            // successful DELETE or an SDK terminal receipt cannot prove absence.
            snapshot = ReadPlan(owner, selector);
            if (snapshot.Resources.Any(r => r.ActiveDispatch != Guid.Empty)) return Finish(State.Pending, plan, []);
            bool assignmentAbsent = await ObserveAssignment(plan.AssignmentId, linked.Token).ConfigureAwait(false) is null;
            active = await ObserveVault(plan, linked.Token).ConfigureAwait(false) is not null;
            bool deleted = await DeletedExists(plan, linked.Token).ConfigureAwait(false);
            if (assignmentAbsent) journal.RecordAbsence(owner, selector, plan.AssignmentId);
            if (!deleted) journal.RecordAbsence(owner, selector, purgeRow.Id);
            if (!active && !deleted)
            {
                journal.RecordAbsence(owner, selector, plan.VaultId);
                // The logical canary belongs exclusively to this new vault.
                // Hard absence of both vault forms covers its retained contents;
                // no separate data-plane purge or borrowed mutation is authorized.
                journal.RecordAbsence(owner, selector, plan.SecretId);
            }
            snapshot = journal.Read(owner, selector);
            return new()
            {
                State = snapshot.Released ? State.Released : deleted ? State.SoftDeleted : State.Closing,
                Journal = snapshot,
                Receipts = plan.Receipts
            };
        }
        catch
        {
            if (cancellationToken.IsCancellationRequested) throw new OperationCanceledException(cancellationToken);
            return Finish(State.Uncertain, plan, []);
        }
    }

    private async Task<State> Mutation(Plan plan, string id, Action action,
        Func<BoundaryTransport, CancellationToken, Task<Operation?>> invoke, CancellationToken token)
    {
        if (StatusRoleDeleteIndependentSelector(plan.Selector))
            return await MutationIndependent(plan, id, action, invoke, token).ConfigureAwait(false);
        var receipt = new Receipt(action);
        lock (plan.History) plan.History.Add(receipt);
        bool delete = action is Action.DeleteAssignment or Action.DeleteVault or Action.PurgeVault;
        bool secret = action == Action.SetCanary;
        using var transport = new BoundaryTransport(secret ? setupSecret.Transport : setupArm.Transport,
            secret ? SecretOrigin(plan).AbsoluteUri.TrimEnd('/') : ArmOrigin,
            secret ? "/secrets/" + Canary : action == Action.PurgeVault ? id + "/purge" : id, secret ? SecretRevision : Revision(id),
            action == Action.PurgeVault ? RequestMethod.Post : delete ? RequestMethod.Delete : RequestMethod.Put,
            limits.MaximumResponseBytes, secret,
            () =>
            {
                receipt.Dispatch = journal.BeginDispatch(plan.Owner, plan.Selector, id, delete,
                    StatusRoleDeleteCancellationSelector(plan.Selector) && action is (Action.DeleteVault or Action.PurgeVault)
                        ? snapshot => StatusRoleParentDependency(snapshot, plan) : null);
                receipt.Attempted = true;
            });
        receipt.StatusTransport = transport;
        try
        {
            receipt.NativeOperation = await invoke(transport, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            Require(transport.Valid && transport.Status is >= 200 and < 300);
            receipt.Outcome = receipt.NativeOperation is { HasCompleted: false } ? State.Pending : State.Ready;
        }
        catch (Exception)
        {
            receipt.Outcome = transport.Valid && transport.Status is 401 or 403 ? State.Denied : State.Uncertain;
            if (token.IsCancellationRequested) throw new OperationCanceledException(token);
            // Retain uncertainty for parser failures and the pinned native role
            // delete 204 parser defect; independent absence remains authoritative.
        }
        finally
        {
            receipt.HttpStatus = transport.Status;
            receipt.NativeRequestId = transport.RequestId;
            receipt.Terminated = true;
            receipt.RemoteSettled = receipt.Outcome == State.Denied || receipt.NativeOperation?.HasCompleted == true ||
                transport.Valid && (secret && transport.Status is >= 200 and < 300 ||
                    delete && transport.Status == 204 || action == Action.PurgeVault && transport.Status == 200);
            if (receipt.Dispatch != Guid.Empty)
                journal.EndDispatch(plan.Owner, plan.Selector, id, receipt.Dispatch, receipt.RemoteSettled);
        }
        return receipt.Outcome;
    }

    private async Task<State> MutationIndependent(Plan plan, string id, Action action,
        Func<BoundaryTransport, CancellationToken, Task<Operation?>> invoke, CancellationToken token)
    {
        bool delete = action is Action.DeleteAssignment or Action.DeleteVault or Action.PurgeVault;
        bool secret = action == Action.SetCanary;
        if (!delete)
            lock (plans) Require(independentPlans.Contains(plan) && !plan.IndependentRestored);
        var preimage = plan.IndependentCommitted ?? throw Failure();
        var admission = new StatusRoleDeleteIndependentFixtureAdmission(this);
        Require(independentAdmissions.TryAdd(admission,
            new(plan, FreezeIndependent(preimage), id, action, token, plan.IndependentCaller)));
        var committed = journal.BeginStatusRoleDeleteIndependentFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, admission);
        plan.IndependentCommitted = FreezeIndependent(committed);
        var receipt = new Receipt(action)
        {
            Dispatch = committed.Resources.Single(r => r.Id == id).ActiveDispatch,
            Attempted = true
        };
        lock (plan.History) plan.History.Add(receipt);
        using var transport = new BoundaryTransport(secret ? setupSecret.Transport : setupArm.Transport,
            secret ? SecretOrigin(plan).AbsoluteUri.TrimEnd('/') : ArmOrigin,
            secret ? "/secrets/" + Canary : action == Action.PurgeVault ? id + "/purge" : id,
            secret ? SecretRevision : Revision(id),
            action == Action.PurgeVault ? RequestMethod.Post : delete ? RequestMethod.Delete : RequestMethod.Put,
            limits.MaximumResponseBytes, secret, () =>
            {
                Require(RoleFixtureJournal.SameStatusRoleDeleteIndependentSnapshot(committed,
                    ReadPlan(plan.Owner, plan.Selector)));
                token.ThrowIfCancellationRequested();
                plan.IndependentCaller.ThrowIfCancellationRequested();
            });
        bool statusAttempted = false;
        try
        {
            var task = invoke(transport, token);
            receipt.NativeTask = task;
            receipt.NativeOperation = await task.ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            Require(transport.Valid && transport.Status is >= 200 and < 300);
            if (receipt.NativeOperation is { HasCompleted: false })
            {
                statusAttempted = true;
                transport.BeginStatus(retainValidatedResponse: true);
                var statusTask = receipt.NativeOperation.UpdateStatusAsync(token).AsTask();
                receipt.StatusTask = statusTask;
                using var response = await statusTask.ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                plan.IndependentCaller.ThrowIfCancellationRequested();
                Require(transport.Valid && transport.Status is >= 200 and < 300);
            }
            receipt.Outcome = receipt.NativeOperation is { HasCompleted: false } ? State.Pending : State.Ready;
        }
        catch
        {
            receipt.Outcome = transport.Valid && transport.Status is 401 or 403 ? State.Denied : State.Uncertain;
            if (token.IsCancellationRequested) throw new OperationCanceledException(token);
        }
        finally
        {
            receipt.HttpStatus = transport.Status;
            receipt.NativeRequestId = transport.RequestId;
            receipt.RemoteSettled = statusAttempted
                ? receipt.Outcome == State.Ready && receipt.StatusTask is { IsCompletedSuccessfully: true } &&
                    receipt.NativeOperation?.HasCompleted == true && transport.Valid
                : receipt.Outcome == State.Denied ||
                receipt.Outcome == State.Ready && receipt.NativeTask is { IsCompletedSuccessfully: true } &&
                    (receipt.NativeOperation?.HasCompleted == true || transport.Valid &&
                        (secret && transport.Status is >= 200 and < 300 ||
                            delete && transport.Status == 204 || action == Action.PurgeVault && transport.Status == 200)) ||
                action == Action.DeleteAssignment && transport.Valid && transport.Status == 204 &&
                    receipt.NativeTask?.Exception?.InnerException is NullReferenceException;
            bool storageComplete = false;
            try { transport.Dispose(); storageComplete = true; }
            finally
            {
                receipt.Terminated = true;
                if (storageComplete && receipt.NativeTask is { IsCompleted: true } task &&
                    !token.IsCancellationRequested && !plan.IndependentCaller.IsCancellationRequested)
                {
                    var candidate = new StatusRoleDeleteIndependentFixtureDrain(this);
                    Require(independentDrains.TryAdd(candidate, new(plan, FreezeIndependent(committed), id, receipt.Dispatch,
                        task, receipt.StatusTask, receipt.RemoteSettled, token, plan.IndependentCaller)));
                    lock (plans) independentPending.Add(receipt, candidate);
                    PersistIndependentFixture(candidate);
                    lock (plans) independentPending.Remove(receipt);
                }
                else
                    journal.EndDispatch(plan.Owner, plan.Selector, id, receipt.Dispatch, nativeSettled: false);
            }
        }
        return receipt.Outcome;
    }

    private async ValueTask<Result> ReleaseIndependent(string owner, FixtureSelector selector, bool purge,
        CancellationToken callerToken, CancellationToken originalCallerToken)
    {
        callerToken.ThrowIfCancellationRequested();
        Require(!purge || host.AllowPurge);
        var closed = journal.Close(owner, selector);
        if (closed.Resources.Length == 0) return new() { State = State.Released, Journal = closed };
        var state = ReadPlan(owner, selector);
        var plan = Reconstruct(state);
        if (Interlocked.Exchange(ref plan.Busy, 1) != 0) return Finish(State.Pending, plan, []);
        plan.IndependentCaller = originalCallerToken;
        using var deadline = new CancellationTokenSource(limits.Timeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(callerToken, deadline.Token);
        try
        {
            if (!state.Idle) return Finish(State.Pending, plan, []);
            var vault = await ObserveVault(plan, linked.Token).ConfigureAwait(false);
            if (vault is not null && !Terminal(vault)) return Finish(State.Pending, plan, []);
            var assignmentPreimage = FreezeIndependent(ReadPlan(owner, selector));
            var assignment = await ReadArm(plan, observeArm, linked.Token).ConfigureAwait(false);
            var child = assignmentPreimage.Resources.Single(r => r.Id == plan.AssignmentId);
            if (assignment.Metadata is not null)
            {
                if (!child.CreateAttempted || child.SelectedAttempted || child.DeleteAttempted)
                    return Finish(State.Uncertain, plan, []);
                Require(RoleFixtureJournal.SameStatusRoleDeleteIndependentSnapshot(assignmentPreimage, ReadPlan(owner, selector)));
                plan.IndependentCommitted = assignmentPreimage;
                await Mutation(plan, plan.AssignmentId, Action.DeleteAssignment, async (transport, token) =>
                    await Arm(setupArm, transport).GetRoleAssignmentResource(new(plan.AssignmentId))
                        .DeleteAsync(WaitUntil.Started, cancellationToken: token).ConfigureAwait(false), linked.Token).ConfigureAwait(false);
                if (!ReadPlan(owner, selector).Idle) return Finish(State.Pending, plan, []);
            }
            var parent = ReadPlan(owner, selector).Resources.Single(r => r.Id == plan.VaultId);
            if (vault is not null && parent.CreateAttempted && !parent.DeleteAttempted)
            {
                if (!await RecordIndependentAbsence(plan, false, linked.Token, originalCallerToken).ConfigureAwait(false))
                    return Finish(State.Uncertain, plan, []);
                await Mutation(plan, plan.VaultId, Action.DeleteVault, async (transport, token) =>
                    await Arm(setupArm, transport).GetKeyVaultResource(new(plan.VaultId))
                        .DeleteAsync(WaitUntil.Started, token).ConfigureAwait(false), linked.Token).ConfigureAwait(false);
                if (!ReadPlan(owner, selector).Idle) return Finish(State.Pending, plan, []);
            }
            bool activeVault = await ObserveVault(plan, linked.Token).ConfigureAwait(false) is not null;
            var deleted = await ObserveDeleted(plan, linked.Token).ConfigureAwait(false);
            var marker = ReadPlan(owner, selector).Resources.Single(r => r.CleanupOnly);
            if (purge && !activeVault && deleted is not null && !marker.DeleteAttempted)
            {
                // An undeclared/preexisting deleted coordinate grants no purge.
                parent = ReadPlan(owner, selector).Resources.Single(r => r.Id == plan.VaultId);
                if (!parent.CreateAttempted || !parent.DeleteAttempted || !parent.InvocationTerminated)
                    return Finish(State.Uncertain, plan, []);
                if (!await RecordIndependentAbsence(plan, false, linked.Token, originalCallerToken).ConfigureAwait(false))
                    return Finish(State.Uncertain, plan, []);
                await Mutation(plan, marker.Id, Action.PurgeVault, async (transport, token) =>
                    await Arm(setupArm, transport).GetDeletedKeyVaultResource(new(marker.Id))
                        .PurgeDeletedAsync(WaitUntil.Started, token).ConfigureAwait(false), linked.Token).ConfigureAwait(false);
                if (!ReadPlan(owner, selector).Idle) return Finish(State.Pending, plan, []);
            }
            bool absent = await RecordIndependentAbsence(plan, true, linked.Token, originalCallerToken).ConfigureAwait(false);
            return Finish(absent ? State.Released : State.Closing, plan, []);
        }
        catch
        {
            if (callerToken.IsCancellationRequested) throw new OperationCanceledException(callerToken);
            return Finish(State.Uncertain, plan, []);
        }
        finally { Volatile.Write(ref plan.Busy, 0); }
    }

    private async Task<bool> RecordIndependentAbsence(Plan plan, bool final, CancellationToken token,
        CancellationToken callerToken)
    {
        var preimage = FreezeIndependent(ReadPlan(plan.Owner, plan.Selector));
        Require(preimage.Closing && preimage.Idle);
        var role = await ReadArm(plan, observeArm, token).ConfigureAwait(false);
        if (role.Metadata is not null) return false;
        IndependentOwnedRead? vault = null, deleted = null;
        if (final)
        {
            vault = await ReadIndependentOwned(plan, false, token).ConfigureAwait(false);
            deleted = await ReadIndependentOwned(plan, true, token).ConfigureAwait(false);
            if (!vault.Absent || !deleted.Absent) return false;
        }
        var absence = new StatusRoleDeleteIndependentAbsence(this);
        Require(independentAbsences.TryAdd(absence, new(plan, preimage, role, vault, deleted, final, token, callerToken)));
        var committed = journal.RecordStatusRoleDeleteIndependentAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence);
        plan.IndependentCommitted = FreezeIndependent(committed);
        return true;
    }

    // One explicitly requested native status update per retained operation, not
    // a wait loop. Local invocation termination does not establish remote drain.
    // No retained handle (including process loss) means no inferred settlement.
    internal async ValueTask SettleAsync(string owner, FixtureSelector selector, CancellationToken cancellationToken = default)
    {
        var snapshot = journal.Read(owner, selector);
        if (snapshot.Resources.Length != 0)
            await SettleAsync(Reconstruct(ReadPlan(owner, selector)), cancellationToken).ConfigureAwait(false);
    }

    internal async ValueTask<Result> SettleAsync(Plan plan, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Require(plan is not null && ReferenceEquals(plan.Source, source));
        if (Interlocked.Exchange(ref plan!.Busy, 1) != 0) throw Failure();
        if (StatusRoleDeleteIndependentSelector(plan.Selector))
        {
            try
            {
                foreach (var receipt in plan.Receipts)
                {
                    StatusRoleDeleteIndependentFixtureDrain? drain;
                    lock (plans) independentPending.TryGetValue(receipt, out drain);
                    if (drain is not null)
                    {
                        PersistIndependentFixture(drain);
                        lock (plans) independentPending.Remove(receipt);
                        continue;
                    }
                    if (!receipt.Terminated || receipt.Dispatch == Guid.Empty) continue;
                    var state = ReadPlan(plan.Owner, plan.Selector);
                    var row = state.Resources.SingleOrDefault(r => r.ActiveDispatch == receipt.Dispatch);
                    if (row is { InvocationTerminated: false })
                        journal.EndDispatch(plan.Owner, plan.Selector, row.Id, receipt.Dispatch, nativeSettled: false);
                }
                return Finish(ReadPlan(plan.Owner, plan.Selector).Idle ? State.Ready : State.Pending, plan, []);
            }
            finally { Volatile.Write(ref plan.Busy, 0); }
        }
        using var deadline = new CancellationTokenSource(limits.Timeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            foreach (var receipt in plan.Receipts)
            {
                if (receipt.Dispatch == Guid.Empty) continue;
                var snapshot = ReadPlan(plan.Owner, plan.Selector);
                var row = snapshot.Resources.SingleOrDefault(r => r.ActiveDispatch == receipt.Dispatch);
                if (row is null || !receipt.Terminated) continue;
                if (StatusRoleDeleteCancellationSelector(plan.Selector) && row.SelectedAttempted)
                {
                    if (!row.InvocationTerminated)
                        journal.EndDispatch(plan.Owner, plan.Selector, row.Id, receipt.Dispatch, nativeSettled: false);
                    continue;
                }
                if (!row.InvocationTerminated || receipt.RemoteSettled)
                {
                    journal.EndDispatch(plan.Owner, plan.Selector, row.Id, receipt.Dispatch, receipt.RemoteSettled);
                    if (receipt.RemoteSettled) continue;
                }
                if (receipt.Action == Action.CreateVault)
                {
                    var vault = await ObserveVault(plan, linked.Token).ConfigureAwait(false);
                    if (vault is not null)
                    {
                        ValidateVault(plan, vault);
                        if (Succeeded(vault))
                        {
                            receipt.RemoteSettled = true;
                            journal.SettleDispatch(plan.Owner, plan.Selector, row.Id, receipt.Dispatch);
                            continue;
                        }
                    }
                }
                if (receipt.NativeOperation is null ||
                    receipt.StatusTransport is null) continue;
                using (receipt.StatusTransport)
                {
                    receipt.StatusTransport.BeginStatus();
                    try { using var response = await receipt.NativeOperation.UpdateStatusAsync(linked.Token).ConfigureAwait(false); }
                    catch (Exception) when (!linked.IsCancellationRequested) { }
                    if (receipt.NativeOperation.HasCompleted && receipt.StatusTransport.Valid)
                    {
                        receipt.RemoteSettled = true;
                        journal.SettleDispatch(plan.Owner, plan.Selector, row.Id, receipt.Dispatch);
                        receipt.Outcome = State.Ready;
                    }
                }
            }
            return Finish(journal.Read(plan.Owner, plan.Selector).Resources.Any(r => r.ActiveDispatch != Guid.Empty)
                ? State.Pending : State.Ready, plan, []);
        }
        finally { Volatile.Write(ref plan.Busy, 0); }
    }

    private Result Finish(State state, Plan plan, IReadOnlyList<BorrowedReadback> borrowed) => new()
    {
        State = state,
        Receipts = plan.Receipts,
        Borrowed = borrowed,
        Journal = journal.Read(plan.Owner, plan.Selector)
    };

    private async Task<bool> FreshStatusRoleAbsence(Plan plan, CancellationToken token)
    {
        if (await ObserveAssignment(plan.AssignmentId, token).ConfigureAwait(false) is not null) return false;
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.AssignmentId);
        return true;
    }

    private static bool StatusRoleParentDependency(RoleFixtureJournal.Snapshot snapshot, Plan plan) =>
        RoleFixtureJournal.StatusRoleDeleteRoot(snapshot) && snapshot.Closing && snapshot.Idle &&
        snapshot.Owner == plan.Owner && snapshot.Selector == plan.Selector && snapshot.LeaseId == plan.LeaseId &&
        snapshot.Resources.Single(r => r.Id == plan.AssignmentId) is { Absent: true, ActiveDispatch: var dispatch } &&
        dispatch == Guid.Empty;

    private RoleFixtureJournal.Snapshot ReadPlan(string owner, FixtureSelector selector)
    {
        var snapshot = journal.Read(owner, selector);
        Require(!StatusRoleDeleteCancellationSelector(selector) || RoleFixtureJournal.StatusRoleDeleteRoot(snapshot));
        Require(!StatusRoleDeleteIndependentSelector(selector) || RoleFixtureJournal.StatusRoleDeleteIndependentRoot(snapshot));
        var owned = snapshot.Resources.Where(r => !r.Borrowed).ToArray();
        Require(owned.Length == 4 && owned.Count(r => r.CleanupOnly) == 1);
        string prefix = GroupId + "/providers/Microsoft.KeyVault/vaults/";
        string? vault = owned.Select(r => r.Id).SingleOrDefault(id => id.StartsWith(prefix, StringComparison.Ordinal) &&
            id[prefix.Length..] is { Length: 24 } name && name.StartsWith("sk", StringComparison.Ordinal) &&
            name[2..].All(char.IsAsciiHexDigit));
        Require(vault is not null && owned.Any(r => r.Id == vault + "/secrets/" + Canary && !r.CleanupOnly) &&
            owned.Any(r => r.CleanupOnly && r.Id == DeletedId(vault![(vault!.LastIndexOf('/') + 1)..])) &&
            owned.Count(r => r.Id.StartsWith(vault + "/providers/Microsoft.Authorization/roleAssignments/", StringComparison.Ordinal) &&
                Guid.TryParseExact(r.Id[(r.Id.LastIndexOf('/') + 1)..], "D", out var id) && id != Guid.Empty) == 1 &&
            snapshot.Resources.Any(r => r.Borrowed && r.Id == DefinitionId));
        foreach (var row in snapshot.Resources.Where(r => r.Borrowed))
            Require(BorrowedId(row.Id));
        return snapshot;
    }

    private Plan Reconstruct(RoleFixtureJournal.Snapshot snapshot)
    {
        lock (plans)
            if (plans.TryGetValue(snapshot.Selector.Nonce, out var retained))
            {
                Require(retained.Owner == snapshot.Owner && retained.Selector == snapshot.Selector &&
                    retained.LeaseId == snapshot.LeaseId);
                return retained;
            }
        string vault = snapshot.Resources.Single(r => !r.Borrowed && !r.CleanupOnly && !r.Id.Contains("/secrets/", StringComparison.Ordinal) &&
            !r.Id.Contains("/roleAssignments/", StringComparison.Ordinal)).Id;
        string assignment = snapshot.Resources.Single(r => !r.Borrowed && r.Id.Contains("/roleAssignments/", StringComparison.Ordinal)).Id;
        var plan = new Plan(source, snapshot.Owner, snapshot.Selector, snapshot.LeaseId, vault, assignment, true);
        if (StatusRoleDeleteIndependentSelector(snapshot.Selector))
        {
            plan.IndependentRestored = true;
            plan.IndependentCommitted = FreezeIndependent(snapshot);
        }
        lock (plans)
        {
            if (plans.TryGetValue(snapshot.Selector.Nonce, out var retained)) return retained;
            plans.Add(snapshot.Selector.Nonce, plan);
        }
        return plan;
    }

    private bool BorrowedId(string id) => new[]
        {
            SubscriptionId + "/providers/Microsoft.Authorization/roleDefinitions/",
            SubscriptionId + "/providers/Microsoft.Authorization/roleAssignments/",
            GroupId + "/providers/Microsoft.Authorization/roleAssignments/"
        }.Any(prefix => id.StartsWith(prefix, StringComparison.Ordinal) &&
            Guid.TryParseExact(id[prefix.Length..], "D", out var value) && value != Guid.Empty);
    private static bool Segment(string? value, int maximum) => value is { Length: > 0 } &&
        value.Length <= maximum && value is not ("." or "..") &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
    private static string Revision(string id) => id.Contains("/Microsoft.Authorization/", StringComparison.Ordinal) ? RoleRevision : VaultRevision;
    private static Uri SecretOrigin(Plan plan) => new($"https://{plan.VaultName}.vault.azure.net");
    private static bool Succeeded(KeyVaultData vault) => vault.Properties.ProvisioningState == KeyVaultProvisioningState.Succeeded;
    private static bool Terminal(KeyVaultData vault) => vault.Properties.ProvisioningState?.ToString() is "Succeeded" or "Failed" or "Canceled";
    private static void Require(bool condition) { if (!condition) throw Failure(); }
    private static InvalidOperationException Failure() => new("role-fixture-boundary");
    public override string ToString() => "[RoleFixtureProvisioner]";
}
