using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Azure.ResourceManager.EventGrid;
using Azure.ResourceManager.EventGrid.Models;
using SecretKit.AzureKeyVault.Management;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// One local provisioning source. The host selects either an exclusive borrowed
// vault or an original owned parent source, and owns webhook readiness,
// credentials and transport. Neither declaration qualifies
// rights, a namespace, a webhook handshake or runtime delivery. Preflight 404 is
// not conditional creation or isolation from another authorized writer.
internal sealed class NotificationFixtureProvisioner : IAsyncDisposable
{
    private const string Origin = "https://management.azure.com";
    private const string Revision = "2025-02-15";
    private const string ResourceType = "Microsoft.EventGrid/eventSubscriptions";
    internal enum Preparation { Present, Absent }
    internal enum State { Ready, Pending, Incomplete, Denied, Uncertain, Closing, Released }
    internal enum Action { CreateSubscription, DeleteSubscription }
    // Trusted host assertion, NOT an observed Azure lock. The same namespace
    // must exclude every other writer, old in-flight invocation and name reuse
    // from allocation through verified closure, including process downtime.
    // This includes principals, policies, automation, operators and recovery.
    // A local lease expiry cannot release the namespace while remote work may
    // survive. Journal-directory writer integrity is also a trusted premise;
    // its unkeyed hash chain is corruption detection, not host authentication.
    internal sealed class ExclusiveCreationDeclaration
    {
        internal ExclusiveCreationDeclaration(Guid namespaceEpoch, bool continuousWriterExclusion)
        {
            Require(namespaceEpoch != Guid.Empty && continuousWriterExclusion);
            NamespaceEpoch = namespaceEpoch;
            ContinuousWriterExclusion = continuousWriterExclusion;
        }
        internal Guid NamespaceEpoch { get; }
        internal bool ContinuousWriterExclusion { get; }
        public override string ToString() => "[ExclusiveCreationDeclaration]";
    }
    internal sealed class ExclusiveCreationRegistration(NotificationFixtureProvisioner source)
    {
        internal RoleFixtureJournal.NotificationAbsentCreateState State =>
            source.exclusiveRegistrations[this].State;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            ReferenceEquals(journal, source.journal) &&
            source.exclusiveRegistrations.TryGetValue(this, out var registration) &&
            snapshot.Owner == registration.Plan.Owner && snapshot.Selector == registration.Plan.Selector &&
            snapshot.LeaseId == registration.Plan.LeaseId && !snapshot.Closing &&
            registration.Rows.SequenceEqual(snapshot.Resources);
        public override string ToString() => "[ExclusiveCreationRegistration]";
    }
    internal static bool StatusNotificationDeleteCancellationSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.DeleteNotification" && selector.Case == "cancellation-boundary";
    internal static bool StatusNotificationDeleteIndependentSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.DeleteNotification" && selector.Case == "independent-effect";
    internal static bool StatusNotificationUpdateIndependentSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.UpdateNotification" && selector.Case == "independent-effect";

    internal static bool StatusNotificationCreateIndependentSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.CreateOrUpdateNotification" && selector.Case == "independent-effect";
    internal static bool StatusNotificationUpdateCancellationSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.UpdateNotification" && selector.Case == "cancellation-boundary";
    internal static bool StatusNotificationCreateCancellationSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.CreateOrUpdateNotification" && selector.Case == "cancellation-boundary";

    internal sealed class StatusNotificationCreateReadProof(Plan plan, Guid dispatch, Task nativeTask,
        string requestSha256, string responseSha256, string nativeRequestId, int httpStatus,
        bool present, string? nativeState, DateTimeOffset startedAt, DateTimeOffset finishedAt,
        string? rawLabels = null)
    {
        internal Plan Plan { get; } = plan;
        internal VaultFixtureProvisioner.Plan? Parent { get; } = plan.ObjectPlan;
        internal string Owner { get; } = plan.Owner;
        internal FixtureSelector Selector { get; } = plan.Selector;
        internal Guid LeaseId { get; } = plan.LeaseId;
        internal Guid SelectedDispatch { get; } = dispatch;
        internal string Phase => SelectedDispatch == Guid.Empty ? "baseline-before-dispatch" : "selected-state";
        internal Task NativeTask { get; } = nativeTask;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal int HttpStatus { get; } = httpStatus;
        internal bool Present { get; } = present;
        internal string? NativeState { get; } = nativeState;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        internal string? RawLabels { get; } = rawLabels;
        public override string ToString() => "[StatusNotificationCreateReadProof]";
    }

    internal sealed class StatusNotificationUpdateReadProof(Plan plan, Guid dispatch, Task nativeTask,
        string requestSha256, string responseSha256, string nativeRequestId, int httpStatus,
        string nativeState, DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Plan Plan { get; } = plan;
        internal VaultFixtureProvisioner.Plan? Parent { get; } = plan.ObjectPlan;
        internal string Owner { get; } = plan.Owner;
        internal FixtureSelector Selector { get; } = plan.Selector;
        internal Guid LeaseId { get; } = plan.LeaseId;
        internal Guid SelectedDispatch { get; } = dispatch;
        internal string Phase => SelectedDispatch == Guid.Empty ? "baseline-before-dispatch" : "selected-state";
        internal Task NativeTask { get; } = nativeTask;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal int HttpStatus { get; } = httpStatus;
        internal string NativeState { get; } = nativeState;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusNotificationUpdateReadProof]";
    }

    internal sealed class StatusNotificationUpdateIndependentReadProof(Plan plan, Guid dispatch, Task nativeTask,
        string requestSha256, string responseSha256, string nativeRequestId, int httpStatus,
        string nativeState, DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Plan Plan { get; } = plan;
        internal VaultFixtureProvisioner.Plan? Parent { get; } = plan.ObjectPlan;
        internal string Owner { get; } = plan.Owner;
        internal FixtureSelector Selector { get; } = plan.Selector;
        internal Guid LeaseId { get; } = plan.LeaseId;
        internal Guid SelectedDispatch { get; } = dispatch;
        internal string Phase => SelectedDispatch == Guid.Empty ? "baseline-before-dispatch" : "selected-state";
        internal Task NativeTask { get; } = nativeTask;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal int HttpStatus { get; } = httpStatus;
        internal string NativeState { get; } = nativeState;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusNotificationUpdateIndependentReadProof]";
    }

    internal sealed class StatusNotificationCreateIndependentReadProof(Plan plan, Guid dispatch, Task nativeTask,
        string requestSha256, string responseSha256, string nativeRequestId, int httpStatus,
        string nativeState, DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Plan Plan { get; } = plan;
        internal VaultFixtureProvisioner.Plan? Parent { get; } = plan.ObjectPlan;
        internal string Owner { get; } = plan.Owner;
        internal FixtureSelector Selector { get; } = plan.Selector;
        internal Guid LeaseId { get; } = plan.LeaseId;
        internal Guid SelectedDispatch { get; } = dispatch;
        internal string Phase => SelectedDispatch == Guid.Empty ? "baseline-before-dispatch" : "selected-state";
        internal Task NativeTask { get; } = nativeTask;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal int HttpStatus { get; } = httpStatus;
        internal string NativeState { get; } = nativeState;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusNotificationCreateIndependentReadProof]";
    }

    // Coordinates and a copied proof never confer original-reader authority.
    internal sealed class StatusNotificationDeleteReadProof(Plan plan, Guid dispatch, Task nativeTask,
        string requestSha256, string responseSha256, string nativeRequestId, int httpStatus,
        bool present, string? nativeState, DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Plan Plan { get; } = plan;
        internal VaultFixtureProvisioner.Plan? Parent { get; } = plan.ObjectPlan;
        internal string Owner { get; } = plan.Owner;
        internal FixtureSelector Selector { get; } = plan.Selector;
        internal Guid LeaseId { get; } = plan.LeaseId;
        internal Guid SelectedDispatch { get; } = dispatch;
        internal string Phase => SelectedDispatch == Guid.Empty ? "baseline-before-dispatch" : "selected-state";
        internal Task NativeTask { get; } = nativeTask;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal int HttpStatus { get; } = httpStatus;
        internal bool Present { get; } = present;
        internal string? NativeState { get; } = nativeState;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusNotificationDeleteReadProof]";
    }
    internal sealed class StatusNotificationDeleteIndependentReadProof(Plan plan, Guid dispatch, Task nativeTask,
        string requestSha256, string responseSha256, string nativeRequestId, int httpStatus,
        bool present, string? nativeState, DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Plan Plan { get; } = plan;
        internal VaultFixtureProvisioner.Plan? Parent { get; } = plan.ObjectPlan;
        internal string Owner { get; } = plan.Owner;
        internal FixtureSelector Selector { get; } = plan.Selector;
        internal Guid LeaseId { get; } = plan.LeaseId;
        internal Guid SelectedDispatch { get; } = dispatch;
        internal string Phase => SelectedDispatch == Guid.Empty ? "baseline-before-dispatch" : "selected-state";
        internal Task NativeTask { get; } = nativeTask;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal int HttpStatus { get; } = httpStatus;
        internal bool Present { get; } = present;
        internal string? NativeState { get; } = nativeState;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusNotificationDeleteIndependentReadProof]";
    }
    internal sealed record HostScope([property: JsonIgnore] VaultScope Vault,
        bool ExclusiveFixtureVault, bool HttpsWebhookReady)
    {
        public override string ToString() => "[NotificationFixtureHostScope]";
    }
    internal sealed record Authority([property: JsonIgnore] TokenCredential Credential,
        [property: JsonIgnore] HttpPipelineTransport Transport)
    {
        public override string ToString() => "[NotificationFixtureAuthority]";
    }
    internal sealed record Limits(int MaximumResponseBytes, int MaximumRequestBytes,
        int MaximumRowBytes, int MaximumDepth, int MaximumHeaders, int MaximumHeaderBytes, TimeSpan Timeout);
    internal sealed class Receipt(Action action)
    {
        internal Action Action { get; } = action;
        internal Guid Dispatch { get; set; }
        internal bool Attempted => Dispatch != Guid.Empty;
        internal bool Terminated { get; set; }
        internal bool RemoteSettled { get; set; }
        internal int? HttpStatus { get; set; }
        internal State Outcome { get; set; } = State.Uncertain;
        // Actual installed SDK tasks and operations, not synthetic completions.
        internal Task<ArmOperation<EventSubscriptionResource>>? CreateTask { get; set; }
        internal Task<ArmOperation>? DeleteTask { get; set; }
        internal Operation? NativeOperation { get; set; }
        internal Task<Response>? StatusTask { get; set; }
        internal BoundaryTransport? Boundary { get; set; }
        internal bool StatusAttempted { get; set; }
        internal bool StatusValidated { get; set; }
        public override string ToString() => "[NotificationFixtureReceipt]";
    }
    internal sealed class Plan(object source, string owner, FixtureSelector selector, Guid lease,
        NotificationScope scope, Preparation preparation, bool restored = false,
        VaultFixtureProvisioner.Plan? objectPlan = null, IEnumerable<RoleFixtureJournal.Resource>? manifest = null)
    {
        internal object Source { get; } = source;
        internal string Owner { get; } = owner;
        internal FixtureSelector Selector { get; } = selector;
        internal Guid LeaseId { get; } = lease;
        internal NotificationScope Scope { get; } = scope;
        internal string ResourceId => Scope.Vault.ExportResourceId() + "/providers/" + ResourceType + "/" + Scope.SubscriptionName;
        internal Preparation Preparation { get; } = preparation;
        internal bool Restored { get; } = restored;
        internal VaultFixtureProvisioner.Plan? ObjectPlan { get; } = objectPlan;
        internal IReadOnlyList<RoleFixtureJournal.Resource> Manifest { get; } = Array.AsReadOnly((manifest ?? [])
            .Select(r => new RoleFixtureJournal.Resource(r.Id, r.Borrowed, CleanupOnly: r.CleanupOnly)).ToArray());
        internal int Consumed;
        internal readonly SemaphoreSlim Gate = new(1, 1);
        internal readonly List<Receipt> History = [];
        internal IReadOnlyList<Receipt> Receipts { get { lock (History) return History.ToArray(); } }
        public override string ToString() => "[NotificationFixturePlan]";
    }
    internal sealed class Result : IDisposable
    {
        internal required State State { get; init; }
        internal required RoleFixtureJournal.Snapshot Journal { get; init; }
        internal IReadOnlyList<Receipt> Receipts { get; init; } = [];
        internal bool? Present { get; init; }
        // Caller-owned copy. Null means unrepresentable/unknown, not defaults
        // taken from the known request, full-URL action or header action reads.
        internal NotificationConfiguration? Configuration { get; init; }
        internal bool ConfigurationKnown => Configuration is not null;
        internal DateTimeOffset ObservedAt { get; init; }
        internal Plan? SelectedPlan { get; init; }
        internal Guid SelectedDispatch { get; init; }
        // Diagnostic observation only; this is not native settlement evidence.
        internal string? NativeState { get; init; }
        internal StatusNotificationDeleteReadProof? StatusDeleteRead { get; init; }
        internal StatusNotificationDeleteIndependentReadProof? StatusDeleteIndependentRead { get; init; }
        internal StatusNotificationUpdateIndependentReadProof? StatusUpdateIndependentRead { get; init; }
        internal StatusNotificationCreateIndependentReadProof? StatusCreateIndependentRead { get; init; }
        internal StatusNotificationUpdateReadProof? StatusUpdateRead { get; init; }
        internal StatusNotificationCreateReadProof? StatusCreateRead { get; init; }
        public void Dispose() => Configuration?.Dispose();
        public override string ToString() => "[NotificationFixtureResult]";
    }

    private enum NotificationUpdateFixtureStage { Admission, Drain, Absence }
    private sealed record NotificationUpdateFixtureFacts(Plan Plan, RoleFixtureJournal.Snapshot Preimage,
        RoleFixtureJournal.Snapshot Postimage, string ResourceId, Guid Dispatch, bool Delete, bool Settled, bool Final,
        NotificationUpdateFixtureStage Stage, CancellationToken[] Tokens, Task[] Tasks)
    {
        public override string ToString() => "[NotificationUpdateFixtureFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, NotificationUpdateFixtureFacts>
        notificationUpdateFixtureFacts = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Receipt, StatusNotificationUpdateIndependentFixtureDrain> notificationUpdatePending =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> notificationUpdateRevoked = new();

    internal sealed class StatusNotificationUpdateIndependentFixtureAdmission(NotificationFixtureProvisioner source)
    {
        internal string ResourceId => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationUpdateFixture(this, journal, state, NotificationUpdateFixtureStage.Admission);
        public override string ToString() => "[StatusNotificationUpdateIndependentFixtureAdmission]";
    }
    internal sealed class StatusNotificationUpdateIndependentFixtureDrain(NotificationFixtureProvisioner source)
    {
        internal string ResourceId => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Settled => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) && f.Settled;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationUpdateFixture(this, journal, state, NotificationUpdateFixtureStage.Drain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationUpdateFixture(this, journal, state, NotificationUpdateFixtureStage.Drain, true);
        public override string ToString() => "[StatusNotificationUpdateIndependentFixtureDrain]";
    }
    internal sealed class StatusNotificationUpdateIndependentAbsence(NotificationFixtureProvisioner source)
    {
        internal string ResourceId => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal bool Final => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) && f.Final;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationUpdateFixture(this, journal, state, NotificationUpdateFixtureStage.Absence);
        internal bool ValidateParentDependency(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state,
            VaultFixtureProvisioner.Plan parent) =>
            source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) &&
            ReferenceEquals(f.Plan.ObjectPlan, parent) && f.Preimage.Closing && f.Postimage.Closing &&
            source.ValidateNotificationUpdateFixture(this, journal, state, NotificationUpdateFixtureStage.Absence, true);
        public override string ToString() => "[StatusNotificationUpdateIndependentAbsence]";
    }
    private bool ValidateNotificationUpdateFixture(object capability, RoleFixtureJournal candidateJournal,
        RoleFixtureJournal.Snapshot state, NotificationUpdateFixtureStage stage, bool postimage = false) =>
        ReferenceEquals(journal, candidateJournal) && notificationUpdateFixtureFacts.TryGetValue(capability, out var f) &&
        !notificationUpdateRevoked.ContainsKey(f.Plan.Selector.Nonce) && !closed && f.Stage == stage &&
        f.Tokens.All(t => !t.IsCancellationRequested) && f.Tasks.All(t => t.IsCompleted) &&
        RoleFixtureJournal.SameStatusNotificationUpdateIndependentSnapshot(postimage ? f.Postimage : f.Preimage, state);

    private static RoleFixtureJournal.Snapshot FreezeNotificationUpdateFixture(RoleFixtureJournal.Snapshot state) =>
        state with { Selector = state.Selector with { }, Resources = state.Resources.Select(r => r with { }).ToArray() };

    private void RevokeNotificationUpdateFixture(FixtureSelector selector)
    {
        notificationUpdateRevoked.TryAdd(selector.Nonce, 0);
        foreach (var pair in notificationUpdateFixtureFacts)
            if (pair.Value.Plan.Selector == selector) notificationUpdateFixtureFacts.TryRemove(pair.Key, out _);
    }

    private RoleFixtureJournal.Snapshot BeginNotificationUpdateFixture(Plan plan, string id, bool delete,
        CancellationToken token, CancellationToken caller)
    {
        var preimage = FreezeNotificationUpdateFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(!notificationUpdateRevoked.ContainsKey(plan.Selector.Nonce) && !token.IsCancellationRequested &&
            !caller.IsCancellationRequested && !closed && RoleFixtureJournal.StatusNotificationUpdateIndependentRoot(preimage));
        Guid dispatch = Guid.NewGuid();
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            {
                CreateAttempted = r.CreateAttempted || !delete,
                DeleteAttempted = r.DeleteAttempted || delete,
                InvocationTerminated = false,
                ActiveDispatch = dispatch,
                Absent = false
            } : r with { Absent = false }).ToArray()
        };
        var capability = new StatusNotificationUpdateIndependentFixtureAdmission(this);
        Require(notificationUpdateFixtureFacts.TryAdd(capability, new(plan, preimage, postimage, id, dispatch,
            delete, false, false, NotificationUpdateFixtureStage.Admission, [token, caller], [])));
        try
        {
            var committed = journal.BeginStatusNotificationUpdateIndependentFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, capability);
            Require(RoleFixtureJournal.SameStatusNotificationUpdateIndependentSnapshot(postimage, committed));
            return FreezeNotificationUpdateFixture(committed);
        }
        finally { notificationUpdateFixtureFacts.TryRemove(capability, out _); }
    }

    private RoleFixtureJournal.Snapshot PersistNotificationUpdateFixture(StatusNotificationUpdateIndependentFixtureDrain drain)
    {
        Require(notificationUpdateFixtureFacts.TryGetValue(drain, out var f));
        try
        {
            var committed = journal.EndStatusNotificationUpdateIndependentFixtureDispatch(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, drain);
            lock (plans)
                foreach (var receipt in notificationUpdatePending.Where(p => ReferenceEquals(p.Value, drain)).Select(p => p.Key).ToArray())
                    notificationUpdatePending.Remove(receipt);
            return committed;
        }
        catch (IOException) { throw; }
        catch
        {
            RevokeNotificationUpdateFixture(f.Plan.Selector);
            // The actual invocation is drained, but invalid or closed history
            // can never become remote settlement authority.
            try { journal.EndDispatch(f.Plan.Owner, f.Plan.Selector, f.ResourceId, f.Dispatch, nativeSettled: false); }
            catch (InvalidOperationException) { }
            catch (IOException) { }
            throw;
        }
    }

    private void RetainNotificationUpdateFixtureDrain(Plan plan, Receipt receipt, RoleFixtureJournal.Snapshot committed,
        string id, Guid dispatch, bool settled, CancellationToken token, CancellationToken caller, params Task[] tasks)
    {
        Require(tasks.Length != 0 && tasks.All(t => t.IsCompleted) && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        var preimage = FreezeNotificationUpdateFixture(committed);
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            { InvocationTerminated = true, ActiveDispatch = settled ? Guid.Empty : dispatch } : r).ToArray()
        };
        var drain = new StatusNotificationUpdateIndependentFixtureDrain(this);
        Require(notificationUpdateFixtureFacts.TryAdd(drain, new(plan, preimage, postimage, id, dispatch,
            preimage.Closing, settled, false, NotificationUpdateFixtureStage.Drain, [token, caller], tasks.ToArray())));
        lock (plans) notificationUpdatePending.Add(receipt, drain);
        PersistNotificationUpdateFixture(drain);
    }

    private enum NotificationCreateIndependentFixtureStage { Admission, Drain, Absence }
    private sealed record NotificationCreateIndependentFixtureFacts(Plan Plan, RoleFixtureJournal.Snapshot Preimage,
        RoleFixtureJournal.Snapshot Postimage, string ResourceId, Guid Dispatch, bool Delete, bool Settled, bool Final,
        NotificationCreateIndependentFixtureStage Stage, CancellationToken[] Tokens, Task[] Tasks)
    {
        public override string ToString() => "[NotificationCreateIndependentFixtureFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, NotificationCreateIndependentFixtureFacts>
        notificationCreateIndependentFixtureFacts = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Receipt, StatusNotificationCreateIndependentFixtureDrain> notificationCreateIndependentPending =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> notificationCreateIndependentRevoked = new();

    internal sealed class StatusNotificationCreateIndependentFixtureAdmission(NotificationFixtureProvisioner source)
    {
        internal string ResourceId => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationCreateIndependentFixture(this, journal, state, NotificationCreateIndependentFixtureStage.Admission);
        public override string ToString() => "[StatusNotificationCreateIndependentFixtureAdmission]";
    }
    internal sealed class StatusNotificationCreateIndependentFixtureDrain(NotificationFixtureProvisioner source)
    {
        internal string ResourceId => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Settled => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) && f.Settled;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationCreateIndependentFixture(this, journal, state, NotificationCreateIndependentFixtureStage.Drain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationCreateIndependentFixture(this, journal, state, NotificationCreateIndependentFixtureStage.Drain, true);
        public override string ToString() => "[StatusNotificationCreateIndependentFixtureDrain]";
    }
    internal sealed class StatusNotificationCreateIndependentAbsence(NotificationFixtureProvisioner source)
    {
        internal string ResourceId => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal bool Final => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) && f.Final;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationCreateIndependentFixture(this, journal, state, NotificationCreateIndependentFixtureStage.Absence);
        internal bool ValidateParentDependency(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state,
            VaultFixtureProvisioner.Plan parent) =>
            source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) &&
            ReferenceEquals(f.Plan.ObjectPlan, parent) && f.Preimage.Closing && f.Postimage.Closing &&
            source.ValidateNotificationCreateIndependentFixture(this, journal, state, NotificationCreateIndependentFixtureStage.Absence, true);
        public override string ToString() => "[StatusNotificationCreateIndependentAbsence]";
    }
    private bool ValidateNotificationCreateIndependentFixture(object capability, RoleFixtureJournal candidateJournal,
        RoleFixtureJournal.Snapshot state, NotificationCreateIndependentFixtureStage stage, bool postimage = false) =>
        ReferenceEquals(journal, candidateJournal) && notificationCreateIndependentFixtureFacts.TryGetValue(capability, out var f) &&
        !notificationCreateIndependentRevoked.ContainsKey(f.Plan.Selector.Nonce) && !closed && f.Stage == stage &&
        f.Tokens.All(t => !t.IsCancellationRequested) && f.Tasks.All(t => t.IsCompleted) &&
        RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(postimage ? f.Postimage : f.Preimage, state);

    private static RoleFixtureJournal.Snapshot FreezeNotificationCreateIndependentFixture(RoleFixtureJournal.Snapshot state) =>
        state with { Selector = state.Selector with { }, Resources = state.Resources.Select(r => r with { }).ToArray() };

    private void RevokeNotificationCreateIndependentFixture(FixtureSelector selector)
    {
        notificationCreateIndependentRevoked.TryAdd(selector.Nonce, 0);
        foreach (var pair in notificationCreateIndependentFixtureFacts)
            if (pair.Value.Plan.Selector == selector) notificationCreateIndependentFixtureFacts.TryRemove(pair.Key, out _);
    }

    private RoleFixtureJournal.Snapshot BeginNotificationCreateIndependentFixture(Plan plan, string id, bool delete,
        CancellationToken token, CancellationToken caller)
    {
        var preimage = FreezeNotificationCreateIndependentFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(!notificationCreateIndependentRevoked.ContainsKey(plan.Selector.Nonce) && !token.IsCancellationRequested &&
            !caller.IsCancellationRequested && !closed && RoleFixtureJournal.StatusNotificationCreateIndependentRoot(preimage));
        Guid dispatch = Guid.NewGuid();
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            {
                CreateAttempted = r.CreateAttempted || !delete,
                DeleteAttempted = r.DeleteAttempted || delete,
                InvocationTerminated = false,
                ActiveDispatch = dispatch,
                Absent = false
            } : r with { Absent = false }).ToArray()
        };
        var capability = new StatusNotificationCreateIndependentFixtureAdmission(this);
        Require(notificationCreateIndependentFixtureFacts.TryAdd(capability, new(plan, preimage, postimage, id, dispatch,
            delete, false, false, NotificationCreateIndependentFixtureStage.Admission, [token, caller], [])));
        try
        {
            var committed = journal.BeginStatusNotificationCreateIndependentFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, capability);
            Require(RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(postimage, committed));
            return FreezeNotificationCreateIndependentFixture(committed);
        }
        finally { notificationCreateIndependentFixtureFacts.TryRemove(capability, out _); }
    }

    private RoleFixtureJournal.Snapshot PersistNotificationCreateIndependentFixture(StatusNotificationCreateIndependentFixtureDrain drain)
    {
        Require(notificationCreateIndependentFixtureFacts.TryGetValue(drain, out var f));
        try
        {
            var committed = journal.EndStatusNotificationCreateIndependentFixtureDispatch(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, drain);
            Require(RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(f.Postimage, committed));
            lock (plans)
                foreach (var receipt in notificationCreateIndependentPending.Where(p => ReferenceEquals(p.Value, drain)).Select(p => p.Key).ToArray())
                    notificationCreateIndependentPending.Remove(receipt);
            return committed;
        }
        catch (IOException) { throw; }
        catch
        {
            RevokeNotificationCreateIndependentFixture(f.Plan.Selector);
            // The actual invocation is drained, but invalid or closed history
            // can never become remote settlement authority.
            try { journal.EndDispatch(f.Plan.Owner, f.Plan.Selector, f.ResourceId, f.Dispatch, nativeSettled: false); }
            catch (InvalidOperationException) { }
            catch (IOException) { }
            throw;
        }
    }

    private void RetainNotificationCreateIndependentFixtureDrain(Plan plan, Receipt receipt, RoleFixtureJournal.Snapshot committed,
        string id, Guid dispatch, bool settled, CancellationToken token, CancellationToken caller, params Task[] tasks)
    {
        Require(tasks.Length != 0 && tasks.All(t => t.IsCompleted) && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        var preimage = FreezeNotificationCreateIndependentFixture(committed);
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            { InvocationTerminated = true, ActiveDispatch = settled ? Guid.Empty : dispatch } : r).ToArray()
        };
        var drain = new StatusNotificationCreateIndependentFixtureDrain(this);
        Require(notificationCreateIndependentFixtureFacts.TryAdd(drain, new(plan, preimage, postimage, id, dispatch,
            preimage.Closing, settled, false, NotificationCreateIndependentFixtureStage.Drain, [token, caller], tasks.ToArray())));
        lock (plans) notificationCreateIndependentPending.Add(receipt, drain);
        PersistNotificationCreateIndependentFixture(drain);
    }

    private readonly RoleFixtureJournal journal;
    private readonly HostScope host;
    private readonly Authority setup, observer;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly NotificationConfiguration? baselineConfiguration;
    private NotificationConfiguration baseline => baselineConfiguration ?? throw Failure();
    private readonly VaultFixtureProvisioner? ownedVaultSource;
    private readonly object source = new();
    private readonly Dictionary<(Guid Nonce, string Id), Plan> plans = [];
    private readonly HashSet<Plan> prepared = [];
    private readonly HashSet<StatusNotificationDeleteReadProof> statusDeleteReads = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<StatusNotificationDeleteIndependentReadProof> statusDeleteIndependentReads =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<StatusNotificationUpdateIndependentReadProof, (NotificationConfiguration Configuration, CancellationToken[] Tokens)>
        statusUpdateIndependentPending = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<StatusNotificationUpdateIndependentReadProof, CancellationToken[]> statusUpdateIndependentTokens =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<StatusNotificationUpdateIndependentReadProof, NotificationConfiguration> statusUpdateIndependentReads =
        new(ReferenceEqualityComparer.Instance);

    private readonly Dictionary<StatusNotificationCreateIndependentReadProof, (NotificationConfiguration Configuration, CancellationToken[] Tokens)>
        statusCreateIndependentPending = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<StatusNotificationCreateIndependentReadProof, CancellationToken[]> statusCreateIndependentTokens =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<StatusNotificationCreateIndependentReadProof, NotificationConfiguration> statusCreateIndependentReads =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<StatusNotificationUpdateReadProof, NotificationConfiguration> statusUpdateReads =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<StatusNotificationCreateReadProof, NotificationConfiguration?> statusCreateReads =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, ExclusiveCreationDeclaration> exclusivePlans = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<ExclusiveCreationRegistration,
        (Plan Plan, RoleFixtureJournal.NotificationAbsentCreateState State, IReadOnlyList<RoleFixtureJournal.Resource> Rows)>
        exclusiveRegistrations = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, ManagementOperationNativeCapture.StatusNotificationCreateCancellationStartProof>
        exclusiveStarts = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, (ManagementOperationNativeCapture Capture,
        ManagementOperationNativeCapture.Window Window, ManagementOperationNativeCapture.Binding Binding,
        StatusNotificationCreateReadProof Baseline, Guid Dispatch)> exclusiveDispatches = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, VaultFixtureProvisioner.Plan> ownedRoots = new();
    private Task? disposal;
    private bool closed;

    internal NotificationFixtureProvisioner(RoleFixtureJournal journal, HostScope host,
        NotificationConfiguration configuration, Authority setup, Authority observer,
        Limits limits, TimeProvider? time = null, VaultFixtureProvisioner? ownedVaultSource = null)
        : this(journal, host, configuration, setup, observer, limits, time, ownedVaultSource, cleanup: false) { }

    private NotificationFixtureProvisioner(RoleFixtureJournal journal, HostScope host,
        NotificationConfiguration? configuration, Authority setup, Authority observer,
        Limits limits, TimeProvider? time, VaultFixtureProvisioner? ownedVaultSource, bool cleanup)
    {
        Require(journal is not null && host is not null && host.Vault is not null &&
            host.ExclusiveFixtureVault && (cleanup || host.HttpsWebhookReady) &&
            setup is not null && observer is not null && setup.Credential is not null &&
            observer.Credential is not null && setup.Transport is not null && observer.Transport is not null &&
            !ReferenceEquals(setup.Credential, observer.Credential) &&
            !ReferenceEquals(setup.Transport, observer.Transport) && (cleanup || configuration is not null) &&
            (ownedVaultSource is null || ReferenceEquals(journal, ownedVaultSource.Journal)) &&
            limits is not null && limits.MaximumResponseBytes is >= 1024 and <= 16 * 1024 * 1024 &&
            limits.MaximumRequestBytes is >= 1024 and <= 1024 * 1024 &&
            limits.MaximumRowBytes is >= 1024 && limits.MaximumRowBytes <= limits.MaximumResponseBytes &&
            limits.MaximumDepth is >= 4 and <= 32 && limits.MaximumHeaders is >= 1 and <= 128 &&
            limits.MaximumHeaderBytes is >= 128 and <= 64 * 1024 &&
            limits.Timeout > TimeSpan.Zero && limits.Timeout <= TimeSpan.FromMinutes(2));
        baselineConfiguration = configuration is null ? null : Copy(configuration);
        this.ownedVaultSource = ownedVaultSource;
        this.journal = journal;
        this.host = host;
        this.setup = setup;
        this.observer = observer;
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
    }

    internal Plan PlanFixture(string owner, FixtureSelector selector, Preparation preparation)
    {
        Require(ownedVaultSource is null && baselineConfiguration is not null && Enum.IsDefined(preparation) &&
            !(StatusNotificationUpdateIndependentSelector(selector) || StatusNotificationCreateIndependentSelector(selector)));
        lock (plans)
        {
            Require(!closed);
            var scope = new NotificationScope(host.Vault, "skn-" + Guid.NewGuid().ToString("N"));
            string id = host.Vault.ExportResourceId() + "/providers/" + ResourceType + "/" + scope.SubscriptionName;
            // Both coordinates are durable before even the preflight GET.
            var snapshot = journal.Prepare(owner, selector,
                [new(id, false), new(host.Vault.ExportResourceId(), true)]);
            var plan = new Plan(source, owner, selector, snapshot.LeaseId, scope, preparation, manifest: snapshot.Resources);
            plans.Add((selector.Nonce, id), plan);
            return plan;
        }
    }

    internal Plan PlanDeclaredSubscription(VaultFixtureProvisioner.Plan originalParent, string notificationName,
        Preparation preparation)
    {
        lock (plans)
        {
            Require(!closed && baselineConfiguration is not null && ownedVaultSource is not null && Enum.IsDefined(preparation));
            Require(!(StatusNotificationUpdateIndependentSelector(originalParent.Selector) || StatusNotificationCreateIndependentSelector(originalParent.Selector)) ||
                preparation == Preparation.Present && originalParent.Preparation == VaultFixtureProvisioner.Preparation.Active &&
                !originalParent.Restored && !originalParent.SeedCanary && originalParent.PolicyChildren.Count == 0 &&
                originalParent.OwnedNotificationNames.Count == 1 && originalParent.PrivateEndpoint is null);
            ownedVaultSource.BindNotification(originalParent, journal, host.Vault, notificationName);
            var scope = new NotificationScope(host.Vault, notificationName);
            var plan = new Plan(source, originalParent.Owner, originalParent.Selector, originalParent.LeaseId,
                scope, preparation, objectPlan: originalParent, manifest: originalParent.Manifest);
            ownedRoots[originalParent.Selector.Nonce] = originalParent;
            plans.Add((plan.Selector.Nonce, plan.ResourceId), plan);
            return plan;
        }
    }

    internal void DeclareAbsentCreation(Plan plan, ExclusiveCreationDeclaration declaration)
    {
        lock (plans)
        {
            Check(plan);
            Require(declaration is { ContinuousWriterExclusion: true } && declaration.NamespaceEpoch != Guid.Empty &&
                plan is { Restored: false, Consumed: 0, Preparation: Preparation.Absent, ObjectPlan: not null } &&
                StatusNotificationCreateCancellationSelector(plan.Selector) && !exclusivePlans.ContainsKey(plan));
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            Require(RoleFixtureJournal.StatusNotificationCreateRoot(snapshot) && !snapshot.Closing &&
                snapshot.NotificationAbsentCreate is null && snapshot.Resources.All(r =>
                    !r.CreateAttempted && !r.SelectedAttempted && !r.DeleteAttempted &&
                    !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty));
            var state = new RoleFixtureJournal.NotificationAbsentCreateState(1, declaration.NamespaceEpoch,
                plan.ObjectPlan.VaultId, plan.ResourceId);
            var registration = new ExclusiveCreationRegistration(this);
            Require(exclusiveRegistrations.TryAdd(registration,
                (plan, state, Array.AsReadOnly(snapshot.Resources.ToArray()))));
            journal.DeclareNotificationAbsentCreate(plan.Owner, plan.Selector, plan.LeaseId, registration);
            exclusivePlans.Add(plan, declaration);
        }
    }

    internal bool OwnsExclusiveCreation(Plan plan, RoleFixtureJournal.Snapshot snapshot)
    {
        lock (plans)
            return !closed && ReferenceEquals(plan.Source, source) &&
                plans.TryGetValue((plan.Selector.Nonce, plan.ResourceId), out var retained) &&
                ReferenceEquals(retained, plan) && exclusivePlans.TryGetValue(plan, out var declaration) &&
                snapshot.NotificationAbsentCreate is { ContractVersion: 1 } state &&
                state.NamespaceEpoch == declaration.NamespaceEpoch && declaration.ContinuousWriterExclusion &&
                snapshot.Owner == plan.Owner && snapshot.Selector == plan.Selector && snapshot.LeaseId == plan.LeaseId &&
                state.ChildId == plan.ResourceId && state.ParentId == plan.ObjectPlan?.VaultId;
    }

    internal void BindAbsentCreationStart(Plan plan, StatusNotificationCreateReadProof baseline,
        ManagementOperationNativeCapture capture, ManagementOperationNativeCapture.Window window,
        ManagementOperationNativeCapture.Binding binding, VaultAdministration client, NotificationScope scope,
        ManagementReceipt receipt, Task startTask, ManagementOperation handle)
    {
        Require(OwnsStatusNotificationCreateRead(baseline, plan, Guid.Empty) && !baseline.Present);
        Require(capture.TryGetStatusNotificationCreateCancellationStart(window, binding, client, scope, receipt,
            startTask, handle, out var start));
        lock (plans)
        {
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            Require(OwnsExclusiveCreation(plan, snapshot) && snapshot.NotificationAbsentCreate is { } state &&
                exclusiveDispatches.TryGetValue(plan, out var original) &&
                ReferenceEquals(original.Capture, capture) && ReferenceEquals(original.Window, window) &&
                ReferenceEquals(original.Binding, binding) && ReferenceEquals(original.Baseline, baseline) &&
                original.Dispatch == state.InvocationDispatch &&
                state.InvocationDispatch != Guid.Empty && state.InvocationDispatch == start.SelectedDispatch &&
                state.SettledDispatch == Guid.Empty && start.NamespaceEpoch == state.NamespaceEpoch &&
                state.BaselineSha256 == ReadDigest(baseline) && !exclusiveStarts.ContainsKey(plan));
            exclusiveStarts.Add(plan, start);
        }
    }

    internal RoleFixtureJournal.NotificationAbsentCreateState BindAbsentCreationDispatch(Plan plan,
        StatusNotificationCreateReadProof baseline, Guid dispatch, ManagementOperationNativeCapture capture,
        ManagementOperationNativeCapture.Window window, ManagementOperationNativeCapture.Binding binding)
    {
        Require(OwnsStatusNotificationCreateRead(baseline, plan, Guid.Empty) &&
            baseline is { Present: false, HttpStatus: 404 } && baseline.NativeTask.IsFaulted);
        lock (plans)
        {
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            var creation = snapshot.NotificationAbsentCreate ?? throw Failure();
            Require(OwnsExclusiveCreation(plan, snapshot) && !snapshot.Closing &&
                dispatch != Guid.Empty &&
                creation.InvocationDispatch == dispatch && creation.SettledDispatch == Guid.Empty &&
                creation.BaselineSha256 == ReadDigest(baseline) &&
                snapshot.Resources.Single(r => r.Id == plan.ResourceId) is
                {
                    SelectedAttempted: true, CreateAttempted: true, InvocationTerminated: false,
                    DeleteAttempted: false, Absent: false
                } child && child.ActiveDispatch == dispatch &&
                !exclusiveDispatches.ContainsKey(plan));
            exclusiveDispatches.Add(plan, (capture, window, binding, baseline, dispatch));
            return creation;
        }
    }

    internal static string ReadDigest(StatusNotificationCreateReadProof proof) =>
        Digest(proof.RequestSha256, proof.ResponseSha256, proof.NativeRequestId,
            proof.HttpStatus.ToString(CultureInfo.InvariantCulture), proof.Present ? "present" : "absent",
            proof.NativeState ?? "", proof.SelectedDispatch.ToString("D"));

    internal static string Digest(params string[] values)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(values);
        try { return Convert.ToHexString(SHA256.HashData(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static string ConfigurationDigest(NotificationConfiguration configuration) =>
        Digest(configuration.Endpoint.Reveal(),
            string.Join(",", configuration.EventTypes.Order().Select(e => e.ToString())),
            // This profile admits known empty mappings only.
            configuration.DeliveryAttributes.Count == 0 ? "empty" : throw Failure());

    internal static NotificationFixtureProvisioner ForOwnedCleanup(VaultFixtureProvisioner vaultSource,
        string owner, FixtureSelector selector, Authority setup, Authority observer, Limits limits, TimeProvider? time = null,
        ExclusiveCreationDeclaration? exclusiveCreation = null)
    {
        Require(vaultSource is not null);
        // An empty close tombstone has no vault coordinates. Its caller handles
        // it directly; never invent a dummy vault or a replacement topology.
        var parent = vaultSource.OpenCleanupPlan(owner, selector);
        var scope = vaultSource.Scope(parent);
        Require(parent.OwnedNotificationNames.Count != 0);
        var snapshot = vaultSource.Journal.Read(owner, selector);
        if (snapshot.NotificationAbsentCreate is { } absent)
            Require(exclusiveCreation is { ContinuousWriterExclusion: true } &&
                exclusiveCreation.NamespaceEpoch == absent.NamespaceEpoch);
        var source = new NotificationFixtureProvisioner(vaultSource.Journal, new(scope, true, false),
            null, setup, observer, limits, time, vaultSource, cleanup: true);
        Require(source.ownedRoots.TryAdd(selector.Nonce, parent));
        foreach (string name in parent.OwnedNotificationNames)
        {
            var plan = new Plan(source.source, owner, selector, parent.LeaseId, new(scope, name),
                Preparation.Absent, restored: true, objectPlan: parent, manifest: parent.Manifest)
            { Consumed = 1 };
            source.plans.Add((selector.Nonce, plan.ResourceId), plan);
            if (snapshot.NotificationAbsentCreate is not null)
                source.exclusivePlans.Add(plan, exclusiveCreation!);
        }
        return source;
    }

    internal RoleFixtureJournal.Snapshot CloseSelectedRoot(string owner, FixtureSelector selector) =>
        journal.Close(owner, selector, snapshot => snapshot.Resources.Length == 0 || MatchesHost(snapshot));

    internal bool OwnsStatusNotificationDeleteRead(StatusNotificationDeleteReadProof proof,
        Plan originalPlan, Guid selectedDispatch)
    {
        lock (plans)
            return !closed && proof is not null && statusDeleteReads.Contains(proof) &&
                ReferenceEquals(proof.Plan, originalPlan) && ReferenceEquals(originalPlan.Source, source) &&
                ReferenceEquals(proof.Parent, originalPlan.ObjectPlan) && !originalPlan.Restored &&
                originalPlan.ObjectPlan is { Restored: false } &&
                plans.TryGetValue((originalPlan.Selector.Nonce, originalPlan.ResourceId), out var retained) &&
                ReferenceEquals(retained, originalPlan) && prepared.Contains(originalPlan) &&
                proof.SelectedDispatch == selectedDispatch && proof.NativeTask.IsCompleted &&
                StatusNotificationDeleteCancellationSelector(originalPlan.Selector);
    }

    internal bool OwnsStatusNotificationDeleteIndependentRead(StatusNotificationDeleteIndependentReadProof proof,
        Plan originalPlan, Guid selectedDispatch)
    {
        lock (plans)
            return !closed && proof is not null && statusDeleteIndependentReads.Contains(proof) &&
                ReferenceEquals(proof.Plan, originalPlan) && ReferenceEquals(originalPlan.Source, source) &&
                ReferenceEquals(proof.Parent, originalPlan.ObjectPlan) && !originalPlan.Restored &&
                originalPlan.ObjectPlan is { Restored: false } &&
                plans.TryGetValue((originalPlan.Selector.Nonce, originalPlan.ResourceId), out var retained) &&
                ReferenceEquals(retained, originalPlan) && prepared.Contains(originalPlan) &&
                proof.SelectedDispatch == selectedDispatch && proof.NativeTask.IsCompleted &&
                StatusNotificationDeleteIndependentSelector(originalPlan.Selector);
    }

    internal bool OwnsStatusNotificationUpdateRead(StatusNotificationUpdateReadProof proof,
        Plan originalPlan, Guid selectedDispatch)
    {
        lock (plans)
            return !closed && proof is not null && statusUpdateReads.ContainsKey(proof) &&
                ReferenceEquals(proof.Plan, originalPlan) && ReferenceEquals(originalPlan.Source, source) &&
                ReferenceEquals(proof.Parent, originalPlan.ObjectPlan) && !originalPlan.Restored &&
                originalPlan.ObjectPlan is { Restored: false, Preparation: VaultFixtureProvisioner.Preparation.Active } &&
                plans.TryGetValue((originalPlan.Selector.Nonce, originalPlan.ResourceId), out var retained) &&
                ReferenceEquals(retained, originalPlan) && prepared.Contains(originalPlan) &&
                proof.SelectedDispatch == selectedDispatch && proof.NativeTask.IsCompletedSuccessfully &&
                StatusNotificationUpdateCancellationSelector(originalPlan.Selector);
    }

    internal bool OwnsStatusNotificationUpdateIndependentRead(StatusNotificationUpdateIndependentReadProof proof,
        Plan originalPlan, Guid selectedDispatch)
    {
        lock (plans)
            return !closed && !notificationUpdateRevoked.ContainsKey(originalPlan.Selector.Nonce) &&
                originalPlan.Gate.CurrentCount == 1 && originalPlan.ObjectPlan?.Busy == 0 && proof is not null && statusUpdateIndependentReads.ContainsKey(proof) &&
                statusUpdateIndependentTokens.TryGetValue(proof, out var tokens) && tokens.All(t => !t.IsCancellationRequested) &&
                ReferenceEquals(proof.Plan, originalPlan) && ReferenceEquals(originalPlan.Source, source) &&
                ReferenceEquals(proof.Parent, originalPlan.ObjectPlan) && !originalPlan.Restored &&
                originalPlan.ObjectPlan is { Restored: false, Preparation: VaultFixtureProvisioner.Preparation.Active } &&
                plans.TryGetValue((originalPlan.Selector.Nonce, originalPlan.ResourceId), out var retained) &&
                ReferenceEquals(retained, originalPlan) && prepared.Contains(originalPlan) &&
                proof.SelectedDispatch == selectedDispatch && proof.NativeTask.IsCompletedSuccessfully &&
                StatusNotificationUpdateIndependentSelector(originalPlan.Selector);
    }


    internal bool OwnsStatusNotificationCreateIndependentRead(StatusNotificationCreateIndependentReadProof proof,
        Plan originalPlan, Guid selectedDispatch)
    {
        lock (plans)
            return !closed && !notificationCreateIndependentRevoked.ContainsKey(originalPlan.Selector.Nonce) &&
                originalPlan.Gate.CurrentCount == 1 && originalPlan.ObjectPlan?.Busy == 0 && proof is not null && statusCreateIndependentReads.ContainsKey(proof) &&
                statusCreateIndependentTokens.TryGetValue(proof, out var tokens) && tokens.All(t => !t.IsCancellationRequested) &&
                ReferenceEquals(proof.Plan, originalPlan) && ReferenceEquals(originalPlan.Source, source) &&
                ReferenceEquals(proof.Parent, originalPlan.ObjectPlan) && !originalPlan.Restored &&
                originalPlan.ObjectPlan is { Restored: false, Preparation: VaultFixtureProvisioner.Preparation.Active } &&
                plans.TryGetValue((originalPlan.Selector.Nonce, originalPlan.ResourceId), out var retained) &&
                ReferenceEquals(retained, originalPlan) && prepared.Contains(originalPlan) &&
                proof.SelectedDispatch == selectedDispatch && proof.NativeTask.IsCompletedSuccessfully &&
                StatusNotificationCreateIndependentSelector(originalPlan.Selector);
    }

    internal bool OwnsStatusNotificationCreateRead(StatusNotificationCreateReadProof proof,
        Plan originalPlan, Guid selectedDispatch)
    {
        lock (plans)
            return !closed && proof is not null && statusCreateReads.ContainsKey(proof) &&
                ReferenceEquals(proof.Plan, originalPlan) && ReferenceEquals(originalPlan.Source, source) &&
                ReferenceEquals(proof.Parent, originalPlan.ObjectPlan) && !originalPlan.Restored &&
                (originalPlan.Preparation == Preparation.Present || exclusivePlans.ContainsKey(originalPlan)) &&
                originalPlan.ObjectPlan is { Restored: false, Preparation: VaultFixtureProvisioner.Preparation.Active } &&
                plans.TryGetValue((originalPlan.Selector.Nonce, originalPlan.ResourceId), out var retained) &&
                ReferenceEquals(retained, originalPlan) && prepared.Contains(originalPlan) &&
                proof.SelectedDispatch == selectedDispatch &&
                (proof.NativeTask.IsCompletedSuccessfully &&
                    proof is { Present: true, HttpStatus: 200, NativeState: "Succeeded" } ||
                    selectedDispatch == Guid.Empty && exclusivePlans.ContainsKey(originalPlan) &&
                    proof.NativeTask.IsFaulted && proof is { Present: false, HttpStatus: 404, NativeState: null }) &&
                StatusNotificationCreateCancellationSelector(originalPlan.Selector);
    }

    internal async ValueTask<Result> ProvisionAsync(Plan plan, CancellationToken cancellationToken = default,
        CancellationToken? originalCallerToken = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Check(plan);
        Require(!plan.Restored && baselineConfiguration is not null && plan.Consumed == 0 &&
            (!StatusNotificationCreateCancellationSelector(plan.Selector) ||
                plan.ObjectPlan is not null && (plan.Preparation == Preparation.Present ||
                    OwnsExclusiveCreation(plan, ReadPlan(plan.Owner, plan.Selector)))));
        if (!Enter(plan, preparation: true)) return Finish(State.Pending, plan);
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            Require(Interlocked.CompareExchange(ref plan.Consumed, 1, 0) == 0);
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            Require(!snapshot.Closing && snapshot.Resources.All(r => r.ActiveDispatch == Guid.Empty) &&
                (plan.ObjectPlan is null ? snapshot.Resources.All(r => !r.CreateAttempted) :
                snapshot.Resources.Single(r => r.Id == plan.ResourceId) is { CreateAttempted: false, DeleteAttempted: false, SelectedAttempted: false, Absent: false }));
            using var before = await Read(plan, linked.Token).ConfigureAwait(false);
            Require(!before.Present); // Decline existing, even a same-nonce object.
            if (plan.Preparation == Preparation.Absent)
            {
                snapshot = ReadPlan(plan.Owner, plan.Selector);
                if (!snapshot.Closing && snapshot.Resources.All(r => r.ActiveDispatch == Guid.Empty))
                    lock (plans) prepared.Add(plan);
                return new()
                {
                    State = snapshot.Resources.Any(r => r.ActiveDispatch != Guid.Empty) ? State.Pending :
                        snapshot.Closing ? State.Closing : State.Ready,
                    Journal = snapshot,
                    Receipts = plan.Receipts,
                    Present = false,
                    ObservedAt = time.GetUtcNow()
                };
            }
            State state = await Mutate(plan, delete: false, linked.Token, originalCallerToken ?? cancellationToken).ConfigureAwait(false);
            if (state != State.Ready) return Finish(state, plan);
            var result = await ObserveCore(plan, linked.Token, completingPreparation: true,
                caller: originalCallerToken ?? cancellationToken).ConfigureAwait(false);
            if (result.State == State.Ready)
                lock (plans) prepared.Add(plan);
            return result;
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Finish(FailureState(exception), plan);
        }
        finally { Exit(plan); }
    }

    internal ValueTask<Result> ObserveAsync(string owner, FixtureSelector selector,
        CancellationToken cancellationToken = default, CancellationToken? originalCallerToken = null) =>
        RunRead(Reconstruct(ReadPlan(owner, selector)), cancellationToken, originalCallerToken);

    internal ValueTask<Result> ObserveAsync(string owner, FixtureSelector selector, string notificationName,
        CancellationToken cancellationToken = default, CancellationToken? originalCallerToken = null) =>
        RunRead(Reconstruct(ReadPlan(owner, selector), notificationName), cancellationToken, originalCallerToken);

    internal async ValueTask<Result> ObserveSelectedAsync(Plan plan, Guid dispatch,
        CancellationToken cancellationToken = default, CancellationToken? originalCallerToken = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        (originalCallerToken ?? cancellationToken).ThrowIfCancellationRequested();
        _ = SelectedSnapshot();
        if (!Enter(plan)) return Finish(State.Pending, plan);
        Readback? read = null;
        try
        {
            // Keep both borrowers until the actual SDK read and timer disposal
            // drain, even when the transport ignores cancellation.
            using (var deadline = new CancellationTokenSource(limits.Timeout, time))
            using (var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token))
            {
                _ = SelectedSnapshot();
                read = await Read(plan, linked.Token, () =>
                {
                    _ = SelectedSnapshot();
                    linked.Token.ThrowIfCancellationRequested();
                }, dispatch, originalCallerToken ?? cancellationToken).ConfigureAwait(false);
                linked.Token.ThrowIfCancellationRequested();
            }
            // The host clock can reenter and close either source.
            DateTimeOffset observedAt = time.GetUtcNow();
            cancellationToken.ThrowIfCancellationRequested();
            var snapshot = SelectedSnapshot();
            return new()
            {
                State = State.Pending,
                Journal = snapshot,
                Receipts = plan.Receipts,
                Present = read.Present,
                Configuration = read.Configuration is null ? null : Copy(read.Configuration),
                ObservedAt = observedAt,
                SelectedPlan = plan,
                SelectedDispatch = dispatch,
                NativeState = read.NativeState,
                StatusDeleteRead = read.StatusDeleteRead,
                StatusDeleteIndependentRead = read.StatusDeleteIndependentRead,
                StatusUpdateIndependentRead = read.StatusUpdateIndependentRead,
                StatusCreateIndependentRead = read.StatusCreateIndependentRead,
                StatusUpdateRead = read.StatusUpdateRead,
                StatusCreateRead = read.StatusCreateRead
            };
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Finish(FailureState(exception), plan);
        }
        finally
        {
            try { read?.Dispose(); }
            finally
            {
                Exit(plan);
                PublishNotificationUpdateIndependentRead(read?.StatusUpdateIndependentRead);
                PublishNotificationCreateIndependentRead(read?.StatusCreateIndependentRead);
            }
        }

        RoleFixtureJournal.Snapshot SelectedSnapshot()
        {
            lock (plans)
            {
                Check(plan);
                Require(!plan.Restored && (plan.Preparation == Preparation.Present ||
                    exclusiveStarts.ContainsKey(plan)) && prepared.Contains(plan) &&
                    plan.ObjectPlan is { Restored: false, Preparation: VaultFixtureProvisioner.Preparation.Active } &&
                    ownedVaultSource is not null && dispatch != Guid.Empty &&
                    plan.Selector.Operation == ManagementOperationEffects.Members[0].Operation &&
                    plan.Selector.Variant is "operation.UpdateNotification" or "operation.CreateOrUpdateNotification" or
                        "operation.DeleteNotification" &&
                    (plan.Selector.Case == "selected-contract" ||
                        StatusNotificationDeleteIndependentSelector(plan.Selector) ||
                        StatusNotificationDeleteCancellationSelector(plan.Selector) ||
                        (StatusNotificationUpdateCancellationSelector(plan.Selector) || (StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector))) ||
                        StatusNotificationCreateCancellationSelector(plan.Selector)));
                var parent = plan.ObjectPlan;
                var snapshot = ReadPlan(plan.Owner, plan.Selector);
                if (snapshot.NotificationAbsentCreate is { } creation)
                    Require(OwnsExclusiveCreation(plan, snapshot) && creation.InvocationDispatch == dispatch &&
                        creation.SettledDispatch == Guid.Empty && exclusiveStarts.TryGetValue(plan, out var start) &&
                        start.SelectedDispatch == dispatch && start.NamespaceEpoch == creation.NamespaceEpoch);
                Require(ownedVaultSource.MatchesOwnedPlan(parent, snapshot) &&
                    parent.Owner == plan.Owner && parent.Selector == plan.Selector &&
                    parent.LeaseId == plan.LeaseId && plan.LeaseId == snapshot.LeaseId &&
                    !parent.SeedCanary && parent.PolicyChildren.Count == 0 &&
                    parent.OwnedNotificationIds.Count == 1 && parent.OwnedNotificationIds[0] == plan.ResourceId &&
                    plan.Manifest.Count == snapshot.Resources.Length && plan.Manifest.All(m =>
                        snapshot.Resources.Count(r => r.Id == m.Id && r.Borrowed == m.Borrowed && r.CleanupOnly == m.CleanupOnly) == 1) &&
                    !snapshot.Closing && snapshot.Resources.Length == 4 && snapshot.Resources.All(r => !r.Borrowed) &&
                    snapshot.Resources.Single(r => r.Id == parent.VaultId) is { CleanupOnly: false } &&
                    snapshot.Resources.Single(r => r.Id == parent.SecretId) is { CleanupOnly: true } &&
                    snapshot.Resources.Single(r => r.Id == parent.DeletedId) is { CleanupOnly: true } &&
                    snapshot.Resources.Single(r => r.Id == plan.ResourceId) is { CleanupOnly: false, CreateAttempted: true, DeleteAttempted: false, SelectedAttempted: true, Absent: false, InvocationTerminated: true } selected &&
                    selected.ActiveDispatch == dispatch &&
                    snapshot.Resources.Where(r => r.Id != plan.ResourceId).All(r => r.ActiveDispatch == Guid.Empty));
                if (StatusNotificationDeleteCancellationSelector(plan.Selector) ||
                    StatusNotificationDeleteIndependentSelector(plan.Selector))
                    Require((StatusNotificationDeleteIndependentSelector(plan.Selector)
                            ? RoleFixtureJournal.StatusNotificationDeleteIndependentRoot(snapshot)
                            : RoleFixtureJournal.StatusNotificationDeleteRoot(snapshot)) &&
                        snapshot.Resources.Where(r => r.Id != plan.ResourceId).All(r => !r.SelectedAttempted &&
                            !r.DeleteAttempted && !r.Absent && (r.CleanupOnly
                                ? !r.CreateAttempted && !r.InvocationTerminated
                                : r.CreateAttempted && r.InvocationTerminated)));
                return snapshot;
            }
        }
    }

    private void PublishNotificationUpdateIndependentRead(StatusNotificationUpdateIndependentReadProof? proof)
    {
        if (proof is null) return;
        lock (plans)
        {
            Require(statusUpdateIndependentPending.TryGetValue(proof, out var pending) &&
                !closed && proof.Plan.Gate.CurrentCount == 1 && proof.Parent?.Busy == 0 &&
                pending.Tokens.All(t => !t.IsCancellationRequested) && !ReadPlan(proof.Owner, proof.Selector).Closing);
            statusUpdateIndependentReads.Add(proof, pending.Configuration);
            statusUpdateIndependentTokens.Add(proof, pending.Tokens);
            statusUpdateIndependentPending.Remove(proof);
        }
    }

    private void PublishNotificationCreateIndependentRead(StatusNotificationCreateIndependentReadProof? proof)
    {
        if (proof is null) return;
        lock (plans)
        {
            Require(statusCreateIndependentPending.TryGetValue(proof, out var pending) &&
                !closed && proof.Plan.Gate.CurrentCount == 1 && proof.Parent?.Busy == 0 &&
                pending.Tokens.All(t => !t.IsCancellationRequested) && !ReadPlan(proof.Owner, proof.Selector).Closing);
            statusCreateIndependentReads.Add(proof, pending.Configuration);
            statusCreateIndependentTokens.Add(proof, pending.Tokens);
            statusCreateIndependentPending.Remove(proof);
        }
    }

    private async ValueTask<Result> RunRead(Plan plan, CancellationToken cancellationToken,
        CancellationToken? originalCallerToken = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Check(plan);
        if (!Enter(plan)) return Finish(State.Pending, plan);
        Result? result = null;
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            if (plan.ObjectPlan is not null && ReadPlan(plan.Owner, plan.Selector).Resources.Any(r => r.ActiveDispatch != Guid.Empty))
                return Finish(State.Pending, plan);
            result = await ObserveCore(plan, linked.Token, caller: originalCallerToken ?? cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Finish(FailureState(exception), plan);
        }
        finally
        {
            Exit(plan);
            try
            {
                PublishNotificationUpdateIndependentRead(result?.StatusUpdateIndependentRead);
                PublishNotificationCreateIndependentRead(result?.StatusCreateIndependentRead);
            }
            catch { result?.Dispose(); throw; }
        }
    }

    internal async ValueTask<Result> ReleaseAsync(string owner, FixtureSelector selector,
        CancellationToken cancellationToken = default, CancellationToken? originalCallerToken = null)
    {
        Require(ownedVaultSource is null);
        cancellationToken.ThrowIfCancellationRequested();
        // Close first, including when a native invocation is still borrowing.
        var snapshot = CloseSelectedRoot(owner, selector);
        if (snapshot.Resources.Length == 0) return new()
        {
            State = State.Released,
            Journal = snapshot,
            ObservedAt = time.GetUtcNow()
        };
        var plan = Reconstruct(ReadPlan(owner, selector));
        return await ReleaseCore(plan, cancellationToken, originalCallerToken).ConfigureAwait(false);
    }

    internal ValueTask<Result> ReleaseAsync(string owner, FixtureSelector selector, string notificationName,
        CancellationToken cancellationToken = default, CancellationToken? originalCallerToken = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var plan = Reconstruct(ReadPlan(owner, selector), notificationName);
        CloseSelectedRoot(owner, selector);
        return ReleaseCore(plan, cancellationToken, originalCallerToken);
    }

    private RoleFixtureJournal.Snapshot RecordNotificationUpdateAbsence(Plan plan, Readback read,
        CancellationToken token, CancellationToken caller)
    {
        Require(read is { Present: false, ActualTask.IsFaulted: true, Drained: true, Preimage: not null } &&
            !token.IsCancellationRequested && !caller.IsCancellationRequested);
        var preimage = read.Preimage;
        Require(preimage.Closing && preimage.Idle);
        var absence = new StatusNotificationUpdateIndependentAbsence(this);
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == plan.ResourceId ? r with { Absent = true } : r).ToArray()
        };
        Require(notificationUpdateFixtureFacts.TryAdd(absence, new(plan, preimage, postimage, plan.ResourceId,
            Guid.Empty, false, false, false, NotificationUpdateFixtureStage.Absence, [token, caller], [read.ActualTask])));
        try
        {
            var committed = journal.RecordStatusNotificationUpdateIndependentAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence);
            ownedVaultSource!.RetainStatusNotificationUpdateIndependentAbsence(plan.ObjectPlan!, absence, committed);
            return committed;
        }
        catch (RoleFixtureJournal.StatusNotificationUpdateIndependentHistoryException) { RevokeNotificationUpdateFixture(plan.Selector); throw; }
        catch
        {
            notificationUpdateFixtureFacts.TryRemove(absence, out _);
            throw;
        }
    }

    private RoleFixtureJournal.Snapshot RecordNotificationCreateIndependentAbsence(Plan plan, Readback read,
        CancellationToken token, CancellationToken caller)
    {
        Require(read is { Present: false, ActualTask.IsFaulted: true, Drained: true, Preimage: not null } &&
            !token.IsCancellationRequested && !caller.IsCancellationRequested);
        var preimage = read.Preimage;
        Require(preimage.Closing && preimage.Idle);
        var absence = new StatusNotificationCreateIndependentAbsence(this);
        var postimage = preimage with
        {
            Revision = preimage.Revision + (preimage.Resources.Single(r => r.Id == plan.ResourceId).Absent ? 0 : 1),
            Resources = preimage.Resources.Select(r => r.Id == plan.ResourceId ? r with { Absent = true } : r).ToArray()
        };
        Require(notificationCreateIndependentFixtureFacts.TryAdd(absence, new(plan, preimage, postimage, plan.ResourceId,
            Guid.Empty, false, false, false, NotificationCreateIndependentFixtureStage.Absence, [token, caller], [read.ActualTask])));
        try
        {
            var committed = journal.RecordStatusNotificationCreateIndependentAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence);
            Require(RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(postimage, committed));
            ownedVaultSource!.RetainStatusNotificationCreateIndependentAbsence(plan.ObjectPlan!, absence, committed);
            return committed;
        }
        catch (RoleFixtureJournal.StatusNotificationCreateIndependentHistoryException) { RevokeNotificationCreateIndependentFixture(plan.Selector); throw; }
        catch
        {
            notificationCreateIndependentFixtureFacts.TryRemove(absence, out _);
            throw;
        }
    }

    private async ValueTask<Result> ReleaseCore(Plan plan, CancellationToken cancellationToken,
        CancellationToken? originalCallerToken = null)
    {
        string owner = plan.Owner;
        FixtureSelector selector = plan.Selector;
        if (!Enter(plan)) return Finish(State.Pending, plan);
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            var snapshot = ReadPlan(owner, selector);
            if (snapshot.Resources.Any(r => r.ActiveDispatch != Guid.Empty)) return Finish(State.Pending, plan);
            using var before = await Read(plan, linked.Token).ConfigureAwait(false);
            var row = snapshot.Resources.Single(r => r.Id == plan.ResourceId);
            if (before.Present)
            {
                Require(row.CreateAttempted && before.Owned);
                if (row.SelectedAttempted && selector.Operation == ManagementOperationEffects.Members[0].Operation &&
                    selector.Variant == "operation.DeleteNotification")
                    return Finish(State.Uncertain, plan, true);
                if (!before.Terminal) return Finish(State.Pending, plan, true);
                if (!row.DeleteAttempted)
                {
                    State deleted = await Mutate(plan, delete: true, linked.Token, originalCallerToken ?? cancellationToken).ConfigureAwait(false);
                    if (deleted != State.Ready) return Finish(deleted, plan);
                }
            }
            if (ReadPlan(owner, selector).Resources.Any(r => r.ActiveDispatch != Guid.Empty))
                return Finish(State.Pending, plan);
            // A fresh concrete owned GET 404 is the only absence evidence.
            using var after = await Read(plan, linked.Token).ConfigureAwait(false);
            if (!after.Present)
            {
                if (StatusNotificationCreateIndependentSelector(selector))
                    RecordNotificationCreateIndependentAbsence(plan, after, linked.Token, originalCallerToken ?? cancellationToken);
                else if (StatusNotificationUpdateIndependentSelector(selector))
                    RecordNotificationUpdateAbsence(plan, after, linked.Token, originalCallerToken ?? cancellationToken);
                else journal.RecordAbsence(owner, selector, plan.ResourceId);
            }
            return Finish(journal.Read(owner, selector).Released ? State.Released :
                plan.ObjectPlan is null ? State.Incomplete : State.Closing, plan, after.Present);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Finish(FailureState(exception), plan);
        }
        finally { Exit(plan); }
    }

    internal ValueTask<Result> SettleAsync(string owner, FixtureSelector selector,
        CancellationToken cancellationToken = default) =>
        SettleCore(Reconstruct(ReadPlan(owner, selector)), cancellationToken);

    internal ValueTask<Result> SettleAsync(string owner, FixtureSelector selector, string notificationName,
        CancellationToken cancellationToken = default) =>
        SettleCore(Reconstruct(ReadPlan(owner, selector), notificationName), cancellationToken);

    private async ValueTask<Result> SettleCore(Plan plan, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string owner = plan.Owner;
        FixtureSelector selector = plan.Selector;
        Check(plan);
        if (!Enter(plan)) return Finish(State.Pending, plan);
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            if (StatusNotificationCreateIndependentSelector(selector))
            {
                foreach (var receipt in plan.Receipts)
                {
                    StatusNotificationCreateIndependentFixtureDrain? drain;
                    lock (plans) notificationCreateIndependentPending.TryGetValue(receipt, out drain);
                    if (drain is null) continue;
                    PersistNotificationCreateIndependentFixture(drain);
                    cancellationToken.ThrowIfCancellationRequested();
                }
                return Finish(ReadPlan(owner, selector).Idle ? State.Incomplete : State.Pending, plan);
            }
            if (StatusNotificationUpdateIndependentSelector(selector))
            {
                foreach (var receipt in plan.Receipts)
                {
                    StatusNotificationUpdateIndependentFixtureDrain? drain;
                    lock (plans) notificationUpdatePending.TryGetValue(receipt, out drain);
                    if (drain is null) continue;
                    PersistNotificationUpdateFixture(drain);
                    cancellationToken.ThrowIfCancellationRequested();
                }
                return Finish(ReadPlan(owner, selector).Idle ? State.Incomplete : State.Pending, plan);
            }
            foreach (var receipt in plan.Receipts)
            {
                if (!receipt.Attempted || !receipt.Terminated) continue;
                var row = ReadPlan(owner, selector).Resources.Single(r => r.Id == plan.ResourceId);
                if (row.ActiveDispatch != receipt.Dispatch) continue;
                // Finalization evidence survives an earlier durable append failure.
                if (!row.InvocationTerminated || receipt.RemoteSettled)
                    journal.EndDispatch(owner, selector, plan.ResourceId, receipt.Dispatch, receipt.RemoteSettled);
                if (receipt.RemoteSettled) continue;
                await Status(plan, receipt, linked.Token).ConfigureAwait(false);
                if (receipt.RemoteSettled)
                    journal.SettleDispatch(owner, selector, plan.ResourceId, receipt.Dispatch);
                cancellationToken.ThrowIfCancellationRequested();
            }
            return Finish(ReadPlan(owner, selector).Resources.Any(r => r.ActiveDispatch != Guid.Empty)
                ? State.Pending : State.Incomplete, plan);
        }
        finally { Exit(plan); }
    }

    private async Task<State> Mutate(Plan plan, bool delete, CancellationToken token, CancellationToken caller = default)
    {
        var receipt = new Receipt(delete ? Action.DeleteSubscription : Action.CreateSubscription);
        bool independentCreate = StatusNotificationCreateIndependentSelector(plan.Selector);
        bool independent = StatusNotificationUpdateIndependentSelector(plan.Selector) || independentCreate;
        var committed = independentCreate ? BeginNotificationCreateIndependentFixture(plan, plan.ResourceId, delete, token, caller) :
            independent ? BeginNotificationUpdateFixture(plan, plan.ResourceId, delete, token, caller) : null;
        if (committed is not null) receipt.Dispatch = committed.Resources.Single(r => r.Id == plan.ResourceId).ActiveDispatch;
        lock (plan.History) plan.History.Add(receipt);
        var boundary = new BoundaryTransport(setup.Transport, plan, limits,
            delete ? RequestMethod.Delete : RequestMethod.Put, () =>
            {
                lock (plans)
                {
                    Require(!closed);
                    token.ThrowIfCancellationRequested();
                    if (independent)
                    {
                        Require(independentCreate
                            ? RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(committed!, ReadPlan(plan.Owner, plan.Selector))
                            : RoleFixtureJournal.SameStatusNotificationUpdateIndependentSnapshot(committed!, ReadPlan(plan.Owner, plan.Selector)));
                        return;
                    }
                    receipt.Dispatch = journal.BeginDispatch(plan.Owner, plan.Selector, plan.ResourceId, delete,
                        snapshot => snapshot.LeaseId == plan.LeaseId && snapshot.Resources.Length == plan.Manifest.Count &&
                            plan.Manifest.All(m => snapshot.Resources.Count(r =>
                                r.Id == m.Id && r.Borrowed == m.Borrowed && r.CleanupOnly == m.CleanupOnly) == 1));
                }
            }, () => Presence(plan), selectedUpdate: independent && committed!.Resources.Single(r => r.Id == plan.ResourceId).SelectedAttempted,
            exclusiveCreation: OwnsExclusiveCreation(plan, ReadPlan(plan.Owner, plan.Selector)));
        receipt.Boundary = boundary;
        bool returned = false;
        try
        {
            var client = Client(setup, boundary);
            if (delete)
            {
                receipt.DeleteTask = client.GetEventSubscriptionResource(new(plan.ResourceId))
                    .DeleteAsync(WaitUntil.Started, token);
                receipt.NativeOperation = await receipt.DeleteTask.ConfigureAwait(false);
            }
            else
            {
                var data = new EventGridSubscriptionData { Destination = Destination(), Filter = Filter() };
                data.Labels.Add(Label(plan));
                receipt.CreateTask = client.GetEventSubscriptions(new(plan.Scope.Vault.ExportResourceId()))
                    .CreateOrUpdateAsync(WaitUntil.Started, plan.Scope.SubscriptionName, data, token);
                receipt.NativeOperation = await receipt.CreateTask.ConfigureAwait(false);
                if (receipt.CreateTask.Result.HasCompleted && receipt.CreateTask.Result.HasValue)
                    ValidateNative(plan, receipt.CreateTask.Result.Value.Data, boundary);
            }
            token.ThrowIfCancellationRequested();
            Require(boundary.Valid && boundary.Status is >= 200 and < 300);
            returned = true;
            // An admitted native response may still be a lazy ARM operation. Give the actual
            // wrapper one status attempt; cached completion is not a wire read.
            if ((boundary.Status is 200 or 201 && boundary.Succeeded || delete && boundary.Status == 204) &&
                !receipt.NativeOperation.HasCompleted)
                await Status(plan, receipt, token).ConfigureAwait(false);
            receipt.RemoteSettled |= !token.IsCancellationRequested && boundary.Valid && !boundary.HasAsync &&
                boundary.Status is 200 or 201 or 204 && receipt.NativeOperation.HasCompleted &&
                (!receipt.StatusAttempted || receipt.StatusValidated) && (delete || boundary.Terminal);
            receipt.Outcome = receipt.RemoteSettled
                ? delete || boundary.Succeeded ? State.Ready : State.Uncertain : State.Pending;
        }
        catch (Exception)
        {
            receipt.Outcome = boundary.Valid && boundary.Status is 401 or 403 ? State.Denied : State.Uncertain;
            receipt.RemoteSettled = !token.IsCancellationRequested && receipt.Outcome == State.Denied;
            if (token.IsCancellationRequested) throw new OperationCanceledException(token);
        }
        finally
        {
            receipt.HttpStatus = boundary.Status;
            receipt.Terminated = true;
            if (!returned && !receipt.RemoteSettled) receipt.Outcome = State.Uncertain;
            // Do not clear buffers or owned configuration until actual native
            // create/delete/status tasks (including late transport work) finish.
            boundary.ClearBuffers();
            if (receipt.Attempted)
            {
                if (independent)
                {
                    Task? native = delete ? receipt.DeleteTask : receipt.CreateTask;
                    if (native is { IsCompleted: true } && boundary.FixtureDrainComplete &&
                        !token.IsCancellationRequested && !caller.IsCancellationRequested)
                    {
                        if (independentCreate)
                            RetainNotificationCreateIndependentFixtureDrain(plan, receipt, committed!, plan.ResourceId, receipt.Dispatch,
                                receipt.RemoteSettled && receipt.Outcome == State.Ready, token, caller,
                                receipt.StatusTask is null ? [native] : [native, receipt.StatusTask]);
                        else
                            RetainNotificationUpdateFixtureDrain(plan, receipt, committed!, plan.ResourceId, receipt.Dispatch,
                                receipt.RemoteSettled && receipt.Outcome == State.Ready, token, caller,
                                receipt.StatusTask is null ? [native] : [native, receipt.StatusTask]);
                    }
                    else journal.EndDispatch(plan.Owner, plan.Selector, plan.ResourceId, receipt.Dispatch, nativeSettled: false);
                }
                else journal.EndDispatch(plan.Owner, plan.Selector, plan.ResourceId, receipt.Dispatch, receipt.RemoteSettled);
            }
        }
        return receipt.Outcome;
    }

    private async Task Status(Plan plan, Receipt receipt, CancellationToken token)
    {
        if (receipt.StatusAttempted || receipt.NativeOperation is null ||
            receipt.Boundary is not { CanCheckStatus: true } boundary) return;
        receipt.StatusAttempted = true;
        boundary.BeginStatus();
        bool validated = false;
        bool cachedDelete = false;
        try
        {
            // The first update can initialize only the cached201 response.
            // Permit that initialization plus one actual resource GET, never
            // a second wire status read or a polling loop.
            for (int step = 0; step < 2; step++)
            {
                receipt.StatusTask = receipt.NativeOperation.UpdateStatusAsync(token).AsTask();
                using var response = await receipt.StatusTask.ConfigureAwait(false);
                if (receipt.CreateTask is { IsCompletedSuccessfully: true } task)
                {
                    Require(!task.Result.HasCompleted || task.Result.HasValue);
                    if (task.Result.HasCompleted && task.Result.HasValue)
                        ValidateNative(plan, task.Result.Value.Data, boundary);
                }
                if (boundary.StatusSent || receipt.NativeOperation.HasCompleted) break;
            }
            cachedDelete = receipt.DeleteTask is { IsCompletedSuccessfully: true } &&
                !boundary.StatusSent && !boundary.HasAsync && boundary.Status == 204;
            validated = !(StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector)) ||
                receipt.StatusTask is { IsCompletedSuccessfully: true } && receipt.NativeOperation.HasCompleted &&
                boundary.Valid && (boundary.Succeeded || cachedDelete);
            receipt.StatusValidated = validated;
        }
        catch (Exception) when (!token.IsCancellationRequested)
        {
            // A failed terminal native operation can throw. Only the validated
            // actual status response, not the thrown exception, can settle it.
            validated = !(StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector)) && boundary.Valid && boundary.StatusSent && boundary.Terminal && !boundary.Succeeded &&
                receipt.NativeOperation.HasCompleted;
        }
        finally
        {
            receipt.RemoteSettled = validated && !token.IsCancellationRequested && boundary.Valid &&
                (boundary.StatusSent || (StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector))) &&
                (boundary.Terminal || (StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector)) && cachedDelete) &&
                receipt.NativeOperation.HasCompleted;
            if (receipt.RemoteSettled) receipt.Outcome = boundary.Succeeded ? State.Ready : State.Uncertain;
            if (!(StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector))) boundary.ClearBuffers();
        }
    }

    private async Task<Result> ObserveCore(Plan plan, CancellationToken token, bool completingPreparation = false, CancellationToken caller = default)
    {
        using var read = await Read(plan, token, caller: caller).ConfigureAwait(false);
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        if (plan.ObjectPlan is not null && snapshot.Closing && !read.Present &&
            snapshot.Resources.All(r => r.ActiveDispatch == Guid.Empty))
            snapshot = StatusNotificationCreateIndependentSelector(plan.Selector)
                ? RecordNotificationCreateIndependentAbsence(plan, read, token, caller)
                : StatusNotificationUpdateIndependentSelector(plan.Selector)
                ? RecordNotificationUpdateAbsence(plan, read, token, caller)
                : journal.RecordAbsence(plan.Owner, plan.Selector, plan.ResourceId);
        bool componentPrepared;
        lock (plans) componentPrepared = plan.ObjectPlan is null || completingPreparation || prepared.Contains(plan);
        bool ready = !plan.Restored && componentPrepared && (plan.Preparation == Preparation.Absent
            ? !read.Present : snapshot.Resources.Single(r => r.Id == plan.ResourceId).CreateAttempted &&
                read.Present && read.Owned && read.Succeeded &&
                read.Configuration is not null && SameConfiguration(read.Configuration, baseline));
        return new()
        {
            State = snapshot.Resources.Any(r => r.ActiveDispatch != Guid.Empty) ? State.Pending :
                plan.ObjectPlan is not null && snapshot.Released ? State.Released :
                snapshot.Closing ? State.Closing : ready ? State.Ready : State.Incomplete,
            Journal = snapshot,
            Receipts = plan.Receipts,
            Present = read.Present,
            Configuration = read.Configuration is null ? null : Copy(read.Configuration),
            ObservedAt = time.GetUtcNow(),
            StatusDeleteRead = read.StatusDeleteRead,
            StatusDeleteIndependentRead = read.StatusDeleteIndependentRead,
            StatusUpdateIndependentRead = read.StatusUpdateIndependentRead,
            StatusCreateIndependentRead = read.StatusCreateIndependentRead,
            StatusUpdateRead = read.StatusUpdateRead,
            StatusCreateRead = read.StatusCreateRead,
            NativeState = read.StatusDeleteRead is null && read.StatusDeleteIndependentRead is null && read.StatusUpdateRead is null &&
                read.StatusCreateRead is null && read.StatusUpdateIndependentRead is null && read.StatusCreateIndependentRead is null ? null : read.NativeState
        };
    }

    private sealed class Readback : IDisposable
    {
        internal Task? ActualTask;
        internal bool Drained;
        internal RoleFixtureJournal.Snapshot? Preimage;
        internal bool Present, Owned, Terminal, Succeeded;
        internal NotificationConfiguration? Configuration;
        internal string? NativeState;
        internal StatusNotificationDeleteReadProof? StatusDeleteRead;
        internal StatusNotificationDeleteIndependentReadProof? StatusDeleteIndependentRead;
        internal StatusNotificationUpdateIndependentReadProof? StatusUpdateIndependentRead;
        internal StatusNotificationCreateIndependentReadProof? StatusCreateIndependentRead;
        internal StatusNotificationUpdateReadProof? StatusUpdateRead;
        internal StatusNotificationCreateReadProof? StatusCreateRead;
        public void Dispose() => Configuration?.Dispose();
    }
    private async Task<Readback> Read(Plan plan, CancellationToken token, System.Action? validateSelected = null,
        Guid selectedDispatch = default, CancellationToken caller = default)
    {
        var initial = ReadPlan(plan.Owner, plan.Selector);
        bool exclusive = initial.NotificationAbsentCreate is not null;
        if (exclusive) Require(OwnsExclusiveCreation(plan, initial));
        bool create = StatusNotificationCreateCancellationSelector(plan.Selector);
        bool update = create || (StatusNotificationUpdateCancellationSelector(plan.Selector) || (StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector)));
        bool independent = StatusNotificationDeleteIndependentSelector(plan.Selector);
        bool strict = update || independent || StatusNotificationDeleteCancellationSelector(plan.Selector);
        bool selectedUpdate = update && (selectedDispatch != Guid.Empty ||
            ReadPlan(plan.Owner, plan.Selector).Resources.Single(r => r.Id == plan.ResourceId).SelectedAttempted);
        DateTimeOffset startedAt = strict ? time.GetUtcNow() : default;
        using var boundary = new BoundaryTransport(observer.Transport, plan, limits, RequestMethod.Get,
            beforeSend: validateSelected, present: strict || validateSelected is null ? () => Presence(plan) : null,
            selectedUpdate: selectedUpdate, exclusiveCreation: exclusive);
        Task<Response<EventSubscriptionResource>>? nativeTask = null;
        Readback? result = null;
        try
        {
            try
            {
                nativeTask = Client(observer, boundary).GetEventSubscriptionResource(new(plan.ResourceId)).GetAsync(token);
                var response = await nativeTask.ConfigureAwait(false);
                using var raw = response.GetRawResponse();
                Require(boundary.Valid && boundary.Status == 200);
                if (strict) Require(boundary.ParserComplete);
                ValidateNative(plan, response.Value.Data, boundary);
                bool owned = !exclusive && response.Value.Data.Labels.Contains(Label(plan), StringComparer.Ordinal);
                if (exclusive)
                {
                    var snapshot = ReadPlan(plan.Owner, plan.Selector);
                    var creation = snapshot.NotificationAbsentCreate!;
                    Require(OwnsExclusiveCreation(plan, snapshot));
                    if (selectedDispatch != Guid.Empty)
                    {
                        lock (plans)
                            Require(!snapshot.Closing && creation.InvocationDispatch == selectedDispatch &&
                                creation.SettledDispatch == Guid.Empty && exclusiveStarts.TryGetValue(plan, out var start) &&
                                start.SelectedDispatch == selectedDispatch);
                    }
                    else
                    {
                        // Empty labels are never generic ownership. Only settled
                        // history plus continuity and a fresh complete digest match
                        // can authorize deletion; a candidate S remains unowned.
                        Require(snapshot.Closing && creation.SettledDispatch != Guid.Empty &&
                            creation.SettledDispatch == creation.InvocationDispatch &&
                            boundary.Configuration is not null &&
                            ConfigurationDigest(boundary.Configuration) == creation.ConfigurationSha256);
                        owned = true;
                    }
                }
                else Require(owned);
                if (strict)
                    Require(response.Value.Data.Labels.Count == (exclusive ? 0 : 1) && boundary.Succeeded &&
                        boundary.Configuration is not null &&
                        (baselineConfiguration is null || (selectedUpdate
                            ? boundary.Configuration.Endpoint.Reveal() == baseline.Endpoint.Reveal() &&
                                boundary.Configuration.EventTypes.SequenceEqual([VaultNotificationEvent.SecretNewVersionCreated]) &&
                                boundary.Configuration.DeliveryAttributes.Count == 0
                            : SameConfiguration(boundary.Configuration, baseline))));
                result = new()
                {
                    Present = true,
                    Owned = owned,
                    Terminal = boundary.Terminal,
                    Succeeded = boundary.Succeeded,
                    NativeState = boundary.NativeState,
                    Configuration = boundary.Configuration is null ? null : Copy(boundary.Configuration)
                };
            }
            catch (RequestFailedException exception) when (boundary.Valid && boundary.Status == 404 &&
                (!strict || exception.Status == 404 && exception.ErrorCode == "NotFound" && boundary.ParserComplete))
            { result = new(); }
            if (strict) token.ThrowIfCancellationRequested();
            // Storage disposal is part of the proof, not a later diagnostic.
            boundary.Dispose();
            if ((StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector)))
            {
                Require(nativeTask is { IsCompleted: true } && boundary.ParserComplete);
                result!.ActualTask = nativeTask;
                result.Drained = true;
                result.Preimage = StatusNotificationCreateIndependentSelector(plan.Selector)
                    ? FreezeNotificationCreateIndependentFixture(initial) : FreezeNotificationUpdateFixture(initial);
            }
            DateTimeOffset finishedAt = strict ? time.GetUtcNow() : default;
            if (strict) token.ThrowIfCancellationRequested();
            if (strict && !plan.Restored && plan.ObjectPlan is { Restored: false } &&
                nativeTask is { IsCompleted: true })
            {
                lock (plans)
                {
                    Require(!closed && finishedAt >= startedAt);
                    var snapshot = ReadPlan(plan.Owner, plan.Selector);
                    if (prepared.Contains(plan) && !snapshot.Closing)
                    {
                        if (create)
                        {
                            Require(RoleFixtureJournal.StatusNotificationCreateRoot(snapshot) &&
                                (exclusive && selectedDispatch == Guid.Empty
                                    ? plan.Preparation == Preparation.Absent &&
                                        snapshot.NotificationAbsentCreate!.InvocationDispatch == Guid.Empty &&
                                        result is { Present: false, Configuration: null } &&
                                        nativeTask.IsFaulted && boundary.Status == 404
                                    : result is { Present: true, Succeeded: true, Configuration: not null } &&
                                        nativeTask.IsCompletedSuccessfully && boundary.Status == 200 &&
                                        (plan.Preparation == Preparation.Present || exclusive && selectedDispatch != Guid.Empty)));
                            var proof = new StatusNotificationCreateReadProof(plan, selectedDispatch, nativeTask,
                                boundary.RequestSha256!, boundary.ResponseSha256!, boundary.NativeRequestId!,
                                boundary.Status!.Value, result!.Present, result.NativeState, startedAt, finishedAt,
                                boundary.RawLabels);
                            statusCreateReads.Add(proof, result.Configuration is null ? null : Copy(result.Configuration));
                            result.StatusCreateRead = proof;
                        }
                        else if (StatusNotificationCreateIndependentSelector(plan.Selector))
                        {
                            Require(RoleFixtureJournal.StatusNotificationCreateIndependentRoot(snapshot) &&
                                result is { Present: true, Succeeded: true, Configuration: not null } &&
                                nativeTask.IsCompletedSuccessfully && boundary.Status == 200);
                            var proof = new StatusNotificationCreateIndependentReadProof(plan, selectedDispatch, nativeTask,
                                boundary.RequestSha256!, boundary.ResponseSha256!, boundary.NativeRequestId!, 200,
                                result.NativeState!, startedAt, finishedAt);
                            statusCreateIndependentPending.Add(proof, (Copy(result.Configuration), [token, caller]));
                            result.StatusCreateIndependentRead = proof;
                        }
                        else if (StatusNotificationUpdateIndependentSelector(plan.Selector))
                        {
                            Require(RoleFixtureJournal.StatusNotificationUpdateIndependentRoot(snapshot) &&
                                result is { Present: true, Succeeded: true, Configuration: not null } &&
                                nativeTask.IsCompletedSuccessfully && boundary.Status == 200);
                            var proof = new StatusNotificationUpdateIndependentReadProof(plan, selectedDispatch, nativeTask,
                                boundary.RequestSha256!, boundary.ResponseSha256!, boundary.NativeRequestId!, 200,
                                result.NativeState!, startedAt, finishedAt);
                            statusUpdateIndependentPending.Add(proof, (Copy(result.Configuration), [token, caller]));
                            result.StatusUpdateIndependentRead = proof;
                        }
                        else if (update)
                        {
                            Require(RoleFixtureJournal.StatusNotificationUpdateRoot(snapshot) &&
                                result is { Present: true, Succeeded: true, Configuration: not null } &&
                                nativeTask.IsCompletedSuccessfully && boundary.Status == 200);
                            var proof = new StatusNotificationUpdateReadProof(plan, selectedDispatch, nativeTask,
                                boundary.RequestSha256!, boundary.ResponseSha256!, boundary.NativeRequestId!, 200,
                                result.NativeState!, startedAt, finishedAt);
                            statusUpdateReads.Add(proof, Copy(result.Configuration));
                            result.StatusUpdateRead = proof;
                        }
                        else if (independent)
                        {
                            Require(RoleFixtureJournal.StatusNotificationDeleteIndependentRoot(snapshot));
                            var proof = new StatusNotificationDeleteIndependentReadProof(plan, selectedDispatch, nativeTask,
                                boundary.RequestSha256!, boundary.ResponseSha256!, boundary.NativeRequestId!, boundary.Status!.Value,
                                result!.Present, result.NativeState, startedAt, finishedAt);
                            statusDeleteIndependentReads.Add(proof);
                            result.StatusDeleteIndependentRead = proof;
                        }
                        else
                        {
                            Require(RoleFixtureJournal.StatusNotificationDeleteRoot(snapshot));
                            var proof = new StatusNotificationDeleteReadProof(plan, selectedDispatch, nativeTask,
                                boundary.RequestSha256!, boundary.ResponseSha256!, boundary.NativeRequestId!, boundary.Status!.Value,
                                result!.Present, result.NativeState, startedAt, finishedAt);
                            statusDeleteReads.Add(proof);
                            result.StatusDeleteRead = proof;
                        }
                    }
                }
            }
            return result!;
        }
        catch { result?.Dispose(); throw; }

    }

    private void ValidateNative(Plan plan, EventGridSubscriptionData data, BoundaryTransport boundary)
    {
        if (StatusNotificationDeleteIndependentSelector(plan.Selector) || (StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector)))
            Require(data.Id?.ToString() == plan.ResourceId && data.Name == plan.Scope.SubscriptionName &&
                data.ResourceType.ToString() == ResourceType && data.Topic == plan.Scope.Vault.ExportResourceId());
        Require(Same(data.Id?.ToString(), plan.ResourceId) && Same(data.Name, plan.Scope.SubscriptionName) &&
            Same(data.Topic, plan.Scope.Vault.ExportResourceId()) &&
            (boundary.ExclusiveCreation ? data.Labels.Count == 0 : data.Labels.Contains(Label(plan), StringComparer.Ordinal)) &&
            data.ProvisioningState?.ToString() == boundary.NativeState &&
            data.Destination is WebHookEventSubscriptionDestination);
        if (boundary.RawEvents is { } raw)
            Require(data.Filter is not null && data.Filter.IncludedEventTypes.SequenceEqual(raw));
        if (boundary.Configuration is not { } configuration) return;
        Require(data.Destination is WebHookEventSubscriptionDestination webhook &&
            webhook.Endpoint?.OriginalString == configuration.Endpoint.Reveal() &&
            webhook.DeliveryAttributeMappings.Count == configuration.DeliveryAttributes.Count);
        var destination = (WebHookEventSubscriptionDestination)data.Destination;
        for (int i = 0; i < configuration.DeliveryAttributes.Count; i++)
        {
            var expected = configuration.DeliveryAttributes[i];
            var actual = destination.DeliveryAttributeMappings[i];
            Require(actual.Name == expected.Name && (actual switch
            {
                StaticDeliveryAttributeMapping s => expected.Kind == NotificationAttributeKind.Static &&
                    s.Value == expected.Value.Reveal() && s.IsSecret == expected.IsSecret,
                DynamicDeliveryAttributeMapping d => expected.Kind == NotificationAttributeKind.Dynamic &&
                    d.SourceField == expected.Value.Reveal(),
                _ => false
            }));
        }
    }

    private WebHookEventSubscriptionDestination Destination()
    {
        var value = new WebHookEventSubscriptionDestination { Endpoint = new(baseline.Endpoint.Reveal()) };
        value.DeliveryAttributeMappings.Clear();
        foreach (var a in baseline.DeliveryAttributes)
            value.DeliveryAttributeMappings.Add(a.Kind == NotificationAttributeKind.Static
                ? new StaticDeliveryAttributeMapping { Name = a.Name, Value = a.Value.Reveal(), IsSecret = a.IsSecret }
                : new DynamicDeliveryAttributeMapping { Name = a.Name, SourceField = a.Value.Reveal() });
        return value;
    }
    private EventSubscriptionFilter Filter()
    {
        var filter = new EventSubscriptionFilter();
        foreach (var e in baseline.EventTypes) filter.IncludedEventTypes.Add("Microsoft.KeyVault." + e);
        return filter;
    }
    private static NotificationConfiguration Copy(NotificationConfiguration configuration) =>
        new(configuration.Endpoint.Reveal(), configuration.EventTypes, configuration.DeliveryAttributes);
    private static bool SameConfiguration(NotificationConfiguration a, NotificationConfiguration b) =>
        a.Endpoint.Reveal() == b.Endpoint.Reveal() && a.EventTypes.Order().SequenceEqual(b.EventTypes.Order()) &&
        a.DeliveryAttributes.Count == b.DeliveryAttributes.Count &&
        a.DeliveryAttributes.All(x => b.DeliveryAttributes.Any(y => x.Name == y.Name && x.Kind == y.Kind &&
            x.IsSecret == y.IsSecret && x.Value.Reveal() == y.Value.Reveal()));
    private static string Label(Plan plan) => "secretkit-fixture-" + plan.Selector.Nonce.ToString("N");

    private ArmClient Client(Authority authority, BoundaryTransport boundary)
    {
        var options = new ArmClientOptions { Environment = new(new Uri(Origin), Origin), Transport = boundary };
        options.SetApiVersion(ResourceType, Revision);
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        return new(new AudienceCredential(authority.Credential), null, options);
    }
    private sealed class AudienceCredential(TokenCredential inner) : TokenCredential
    {
        private static void Check(TokenRequestContext context) =>
            Require(context.Scopes.Length == 1 && context.Scopes[0] == Origin + "/.default");
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken)
        {
            Check(context);
            return inner.GetToken(context, cancellationToken);
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken)
        {
            Check(context);
            return inner.GetTokenAsync(context, cancellationToken);
        }
    }
    private RoleFixtureJournal.Snapshot ReadPlan(string owner, FixtureSelector selector)
    {
        RoleFixtureJournal.Snapshot snapshot;
        try { snapshot = journal.Read(owner, selector); }
        catch (RoleFixtureJournal.StatusNotificationCreateIndependentHistoryException)
        { RevokeNotificationCreateIndependentFixture(selector); throw; }
        catch (RoleFixtureJournal.StatusNotificationUpdateIndependentHistoryException)
        { RevokeNotificationUpdateFixture(selector); throw; }
        Require(MatchesHost(snapshot) && (!StatusNotificationUpdateIndependentSelector(selector) ||
            !notificationUpdateRevoked.ContainsKey(selector.Nonce) && RoleFixtureJournal.StatusNotificationUpdateIndependentRoot(snapshot)) &&
            (!StatusNotificationCreateIndependentSelector(selector) || !notificationCreateIndependentRevoked.ContainsKey(selector.Nonce) &&
                RoleFixtureJournal.StatusNotificationCreateIndependentRoot(snapshot)));
        return snapshot;
    }
    private bool MatchesHost(RoleFixtureJournal.Snapshot snapshot)
    {
        if (ownedVaultSource is not null)
            return ownedRoots.TryGetValue(snapshot.Selector.Nonce, out var parent) &&
                parent.VaultId == host.Vault.ExportResourceId() && parent.Owner == snapshot.Owner &&
                parent.Selector == snapshot.Selector && parent.LeaseId == snapshot.LeaseId &&
                parent.Manifest.Count == snapshot.Resources.Length && parent.Manifest.All(m =>
                    snapshot.Resources.Count(r => r.Id == m.Id && r.Borrowed == m.Borrowed && r.CleanupOnly == m.CleanupOnly) == 1);
        string prefix = host.Vault.ExportResourceId() + "/providers/" + ResourceType + "/skn-";
        return snapshot.Resources.Length == 2 && snapshot.Resources.Count(r => r.Borrowed &&
            r.Id == host.Vault.ExportResourceId()) == 1 && snapshot.Resources.Count(r => !r.Borrowed &&
            !r.CleanupOnly && r.Id.StartsWith(prefix, StringComparison.Ordinal) &&
            r.Id[prefix.Length..] is { Length: 32 } suffix && suffix.All(char.IsAsciiHexDigit)) == 1;
    }
    private Plan Reconstruct(RoleFixtureJournal.Snapshot snapshot, string? notificationName = null)
    {
        lock (plans)
        {
            Require(!closed);
            Require((ownedVaultSource is null) == (notificationName is null));
            string id;
            if (ownedVaultSource is not null)
            {
                Require(notificationName is not null);
                Require(ownedRoots.TryGetValue(snapshot.Selector.Nonce, out var parent) &&
                    parent.OwnedNotificationNames.Contains(notificationName, StringComparer.Ordinal));
                id = parent.VaultId + VaultFixtureProvisioner.NotificationPrefix + notificationName;
            }
            else id = snapshot.Resources.Single(r => !r.Borrowed).Id;
            if (plans.TryGetValue((snapshot.Selector.Nonce, id), out var plan))
            {
                Require(plan.Owner == snapshot.Owner && plan.Selector == snapshot.Selector && plan.LeaseId == snapshot.LeaseId);
                return plan;
            }
            Require(ownedVaultSource is null); // Owned children are declared or explicitly restored by the factory.
            var restored = new Plan(source, snapshot.Owner, snapshot.Selector, snapshot.LeaseId,
                new(host.Vault, id[(id.LastIndexOf('/') + 1)..]), Preparation.Absent, restored: true, manifest: snapshot.Resources)
            { Consumed = 1 };
            plans.Add((snapshot.Selector.Nonce, id), restored);
            return restored; // Baseline and task history are deliberately unknown.
        }
    }
    private void Check(Plan plan)
    {
        lock (plans) Require(!closed && plan is not null && ReferenceEquals(plan.Source, source) &&
            plans.TryGetValue((plan.Selector.Nonce, plan.ResourceId), out var retained) && ReferenceEquals(retained, plan) &&
            (plan.ObjectPlan is null || ownedVaultSource is not null &&
                ownedRoots.TryGetValue(plan.Selector.Nonce, out var parent) && ReferenceEquals(parent, plan.ObjectPlan)));
    }
    private bool Enter(Plan plan, bool preparation = false)
    {
        // Acquiring a borrower and closing/draining use the same source lock.
        // A pre-close Check followed by an unlocked Wait would admit late work.
        lock (plans)
        {
            Check(plan);
            if (!plan.Gate.Wait(0)) return false;
            try
            {
                if (plan.ObjectPlan is null) return true;
                Require(ownedVaultSource is not null &&
                    ownedVaultSource.MatchesOwnedPlan(plan.ObjectPlan, ReadPlan(plan.Owner, plan.Selector)));
                if (ownedVaultSource.TryEnterNotification(plan.ObjectPlan, preparation)) return true;
                plan.Gate.Release();
                return false;
            }
            catch { plan.Gate.Release(); throw; }
        }
    }
    private void Exit(Plan plan)
    {
        try
        {
            if (plan.ObjectPlan is not null)
            {
                Require(ownedVaultSource is not null);
                ownedVaultSource.ExitNotification(plan.ObjectPlan);
            }
        }
        finally { plan.Gate.Release(); }
    }
    private void Presence(Plan plan)
    {
        if (journal.Read(plan.Owner, plan.Selector).Closing)
            journal.RecordPresence(plan.Owner, plan.Selector, plan.ResourceId);
    }
    private Result Finish(State state, Plan plan, bool? present = null) => new()
    {
        State = state,
        Journal = journal.Read(plan.Owner, plan.Selector),
        Receipts = plan.Receipts,
        Present = present,
        ObservedAt = time.GetUtcNow()
    };
    public ValueTask DisposeAsync()
    {
        TaskCompletionSource ready;
        Task task;
        lock (plans)
        {
            if (disposal is not null) return new(disposal);
            closed = true;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = disposal = ready.Task;
        }
        _ = DrainAndComplete();
        return new(task);

        async Task DrainAndComplete()
        {
            try
            {
                Plan[] retained;
                lock (plans) retained = plans.Values.ToArray();
                await Drain(retained).ConfigureAwait(false);
                ready.SetResult();
            }
            catch (Exception exception) { ready.SetException(exception); }
        }
    }
    private async Task Drain(Plan[] retained)
    {
        Exception? failure = null;
        // A failed close append must not skip draining already admitted native
        // borrowers, or clear the configuration underneath their SDK tasks.
        foreach (var plan in retained.DistinctBy(p => p.Selector.Nonce))
            try { CloseSelectedRoot(plan.Owner, plan.Selector); }
            catch (Exception exception) { failure ??= exception; }
        foreach (var plan in retained)
        {
            await plan.Gate.WaitAsync().ConfigureAwait(false);
            plan.Gate.Release();
        }
        try
        {
            baselineConfiguration?.Dispose();
            foreach (var pending in statusUpdateIndependentPending.Values) pending.Configuration.Dispose();
            foreach (var pending in statusCreateIndependentPending.Values) pending.Configuration.Dispose();
            foreach (var configuration in statusUpdateIndependentReads.Values) configuration.Dispose();
            foreach (var configuration in statusCreateIndependentReads.Values) configuration.Dispose();
            foreach (var configuration in statusUpdateReads.Values) configuration.Dispose();
            foreach (var configuration in statusCreateReads.Values) configuration?.Dispose();
        }
        finally
        {
            prepared.Clear();
            statusDeleteReads.Clear();
            statusDeleteIndependentReads.Clear();
            statusUpdateIndependentPending.Clear();
            statusCreateIndependentPending.Clear();
            statusUpdateIndependentTokens.Clear();
            statusCreateIndependentTokens.Clear();
            statusUpdateIndependentReads.Clear();
            statusCreateIndependentReads.Clear();
            notificationUpdateFixtureFacts.Clear();
            notificationCreateIndependentFixtureFacts.Clear();
            statusUpdateReads.Clear();
            statusCreateReads.Clear();
        }
        if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }
    private static State FailureState(Exception exception) =>
        exception is RequestFailedException { Status: 401 or 403 } ? State.Denied : State.Uncertain;
    private static bool Same(string? a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    private static void Require([DoesNotReturnIf(false)] bool value) { if (!value) throw Failure(); }
    private static InvalidOperationException Failure() => new("notification-fixture-boundary");
    public override string ToString() => "[NotificationFixtureProvisioner]";

    // Fixed source-selected resource only. No arbitrary polling URI, redirects,
    // action reads, paging, fallback credentials, retries or mutation replay.
    internal sealed class BoundaryTransport(HttpPipelineTransport inner, Plan plan, Limits limits,
        RequestMethod method, System.Action? beforeSend = null, System.Action? present = null,
        bool selectedUpdate = false, bool exclusiveCreation = false)
        : HttpPipelineTransport, IDisposable
    {
        internal bool ExclusiveCreation => exclusiveCreation;
        private readonly List<OwnedStream> buffers = [];
        private int sends;
        private bool statusMode;
        private readonly OwnedArmResponse.Storage parserStorage = new();
        private OwnedArmResponse.ParserCustody? parser;
        private readonly List<OwnedArmResponse.ParserCustody> fixtureParsers = [];
        private bool fixtureDisposed, fixtureDisposalFailed, fixtureEmpty;
        internal bool FixtureDrainComplete => (StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector)) &&
            fixtureDisposed && !fixtureDisposalFailed && Valid &&
            (fixtureEmpty && fixtureParsers.Count == 0 ||
                fixtureParsers.Count != 0 && fixtureParsers.All(p => p.Complete && !p.Invalid) ||
                // A lazy201 can be ignored by the SDK. Only its actual native
                // status GET may supply the downstream parse, never a readback.
                method == RequestMethod.Put && StatusSent && fixtureParsers is [var initial, var final] &&
                    !initial.Invalid && final.Complete && !final.Invalid);
        private System.Action? validateReadCompletion;
        internal bool ParserComplete
        {
            get { validateReadCompletion?.Invoke(); return parser is { Complete: true, Invalid: false }; }
        }
        internal string? RequestSha256 { get; private set; }
        internal string? ResponseSha256 { get; private set; }
        internal string? NativeRequestId { get; private set; }
        internal string? RawLabels { get; private set; }
        internal bool Valid { get; private set; }
        internal int? Status { get; private set; }
        internal bool HasAsync { get; private set; }
        internal bool StatusSent { get; private set; }
        internal string? NativeState { get; private set; }
        internal bool Terminal => NativeState is "Succeeded" or "Failed" or "Canceled" or "Cancelled";
        internal bool Succeeded => NativeState == "Succeeded";
        internal string[]? RawEvents { get; private set; }
        internal NotificationConfiguration? Configuration { get; private set; }
        // One actual resource status GET is permitted, never a foreign or
        // unbounded status endpoint. Unsupported native polling remains pending.
        internal bool CanCheckStatus => Valid && (Status is 200 or 201 or 204 || Status == 202 && HasAsync);
        internal void BeginStatus()
        {
            Require(!statusMode);
            statusMode = true;
            // Native lazy initialization can re-read the initial response
            // after its model materialization consumed this owned stream.
            foreach (var buffer in buffers) buffer.Position = 0;
        }
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw Failure();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            message.CancellationToken.ThrowIfCancellationRequested();
            var uri = message.Request.Uri.ToUri();
            Require(uri.Scheme == "https" && uri.IsDefaultPort && uri.UserInfo.Length == 0 &&
                uri.Fragment.Length == 0 && Same(uri.GetLeftPart(UriPartial.Authority), Origin) &&
                Same(uri.AbsolutePath, plan.ResourceId) && uri.Query == "?api-version=" + Revision &&
                message.Request.Method == (statusMode ? RequestMethod.Get : method) &&
                ++sends <= (statusMode ? 2 : 1));
            if (statusMode) { Require(!StatusSent); StatusSent = true; }
            Valid = false;
            Status = null;
            NativeState = null;
            RawEvents = null;
            Configuration?.Dispose();
            Configuration = null;
            if (message.Request.Content is { } content)
            {
                Require(!statusMode && method == RequestMethod.Put);
                Require(content.TryComputeLength(out long size) && size <= limits.MaximumRequestBytes && size >= 0);
                using var writer = new RequestBuffer(limits.MaximumRequestBytes);
                await content.WriteToAsync(writer, message.CancellationToken).ConfigureAwait(false);
                Require(writer.Length == size);
                var frozen = new OwnedStream(writer.Written.Span, leaveOpen: true);
                buffers.Add(frozen);
                message.Request.Content = RequestContent.Create(frozen.Bytes);
                content.Dispose();
            }
            else Require(statusMode || method != RequestMethod.Put);
            Headers(message.Request.Headers.Select(h => (h.Name, h.Value)));
            if (!statusMode) beforeSend?.Invoke();
            if ((StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector)) && method != RequestMethod.Get)
            {
                var fixtureRequest = message.Request;
                var fixtureHeaders = fixtureRequest.Headers.ToArray();
                var fixtureContent = fixtureRequest.Content;
                void CheckFixture()
                {
                    Require(ReferenceEquals(message.Request, fixtureRequest) && fixtureHeaders.SequenceEqual(fixtureRequest.Headers) &&
                        ReferenceEquals(fixtureRequest.Content, fixtureContent) && fixtureRequest.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri &&
                        fixtureRequest.Method == (statusMode ? RequestMethod.Get : method) &&
                        fixtureHeaders.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == fixtureHeaders.Length &&
                        fixtureRequest.Headers.TryGetValue("Authorization", out var auth) && auth.StartsWith("Bearer ", StringComparison.Ordinal) &&
                        auth.Length > 7 && !fixtureHeaders.Any(h => new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range", "Range" }
                            .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
                    message.CancellationToken.ThrowIfCancellationRequested();
                }
                CheckFixture();
                message.BufferResponse = false;
                try { await inner.ProcessAsync(message).ConfigureAwait(false); }
                finally { if (message.HasResponse) parserStorage.Own(message.Response); }
                CheckFixture();
                Status = message.Response.Status;
                if (method == RequestMethod.Delete && !statusMode)
                {
                    var response = message.Response;
                    var headers = response.Headers.ToArray();
                    Headers(headers.Select(h => (h.Name, h.Value)));
                    Require(Status is 200 or 204 && headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                        !headers.Any(h => new[] { "Location", "Azure-AsyncOperation", "Operation-Location", "Retry-After", "Content-Encoding", "Transfer-Encoding", "Content-Range" }
                            .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
                    var lengths = headers.Where(h => h.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)).Select(h => h.Value).ToArray();
                    Require(lengths.Length == 0 || lengths is ["0"]);
                    var stream = response.ContentStream;
                    if (stream is not null)
                    {
                        parserStorage.Own(stream);
                        byte[] one = new byte[1];
                        parserStorage.Own(one);
                        Require(await stream.ReadAsync(one, message.CancellationToken).ConfigureAwait(false) == 0);
                    }
                    CheckFixture();
                    Require(ReferenceEquals(message.Response, response) && ReferenceEquals(response.ContentStream, stream) &&
                        response.Status == Status && headers.SequenceEqual(response.Headers));
                    var empty = new MemoryStream([], writable: false);
                    parserStorage.Own(empty);
                    message.Response = new OwnedArmResponse(response.Status, response.ReasonPhrase, response.ClientRequestId, headers, empty);
                    fixtureEmpty = true;
                }
                else
                {
                    var response = message.Response;
                    var stream = response.ContentStream;
                    var body = await OwnedArmResponse.CaptureAsync(message, limits.MaximumResponseBytes, parserStorage, allowContinuation: !statusMode)
                        .ConfigureAwait(false);
                    CheckFixture();
                    Require(ReferenceEquals(response.ContentStream, stream) && body.Response.Status is 200 or 201 &&
                        body.Bytes.Length <= limits.MaximumRowBytes);
                    foreach (string name in new[] { "Location", "Azure-AsyncOperation", "Operation-Location" })
                        if (body.Response.Headers.TryGetValue(name, out var next))
                        {
                            Require(!statusMode && next == Origin + plan.ResourceId + "?api-version=" + Revision);
                            HasAsync = true;
                        }
                    using var json = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
                    Unique(json.RootElement);
                    Parse(json.RootElement);
                    Require(Configuration is not null && Succeeded);
                    parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, parserStorage,
                        requireRebuffer: false, requireDownstreamRead: true);
                    fixtureParsers.Add(parser);
                }
                Valid = true;
                return;
            }
            bool strict = method == RequestMethod.Get && (StatusNotificationDeleteCancellationSelector(plan.Selector) ||
                StatusNotificationDeleteIndependentSelector(plan.Selector) ||
                (StatusNotificationUpdateCancellationSelector(plan.Selector) || (StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector))) ||
                StatusNotificationCreateCancellationSelector(plan.Selector));
            var originalRequest = message.Request;
            var requestHeaders = strict ? message.Request.Headers.ToArray() : [];
            void CheckRequest()
            {
                if (!strict) return;
                if ((StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector)))
                    Require(requestHeaders.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == requestHeaders.Length &&
                        originalRequest.Headers.TryGetValue("Authorization", out var auth) &&
                        auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                        !originalRequest.Headers.Contains("Range") && uri.AbsoluteUri == Origin + plan.ResourceId + "?api-version=" + Revision &&
                        (!originalRequest.Headers.TryGetValue("Host", out var host) || host == "management.azure.com"));
                Require(ReferenceEquals(message.Request, originalRequest) &&
                    message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
                    message.Request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri &&
                    requestHeaders.SequenceEqual(message.Request.Headers) &&
                    !requestHeaders.Any(h => new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range" }
                        .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
                var lengths = requestHeaders.Where(h => h.Name.Equals("Content-Length",
                    StringComparison.OrdinalIgnoreCase)).Select(h => h.Value).ToArray();
                Require(lengths.Length == 0 || lengths is ["0"]);
            }
            CheckRequest();
            message.BufferResponse = false;
            try { await inner.ProcessAsync(message).ConfigureAwait(false); }
            finally
            {
                if (strict && message.HasResponse)
                {
                    parserStorage.Own(message.Response);
                    if ((StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector)) && message.Response.Status == 200)
                        present?.Invoke();
                }
            }
            Status = message.Response.Status;
            try
            {
                // Any positive concrete read invalidates previous absence before
                // parsing, even if its payload proves foreign or malformed.
                if (Status == 200) present?.Invoke();
                message.CancellationToken.ThrowIfCancellationRequested();
                if (strict)
                {
                    CheckRequest();
                    var originalResponse = message.Response;
                    int originalStatus = originalResponse.Status;
                    string originalReason = originalResponse.ReasonPhrase, originalClientId = originalResponse.ClientRequestId;
                    var originalHeaders = originalResponse.Headers.ToArray();
                    Stream? originalStream = originalResponse.ContentStream;
                    var body = await OwnedArmResponse.CaptureAsync(message, limits.MaximumResponseBytes,
                        parserStorage).ConfigureAwait(false);
                    CheckRequest();
                    void CheckResponse()
                    {
                        Require(originalResponse.Status == originalStatus &&
                            originalResponse.ReasonPhrase == originalReason &&
                            originalResponse.ClientRequestId == originalClientId &&
                            originalHeaders.SequenceEqual(originalResponse.Headers) &&
                            ReferenceEquals(originalResponse.ContentStream, originalStream));
                    }
                    CheckResponse();
                    Headers(body.Response.Headers.Select(h => (h.Name, h.Value)));
                    Require(Status == body.Response.Status && Status is 200 or 404 &&
                        body.Bytes.Length <= limits.MaximumRowBytes);
                    using var json = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
                    Unique(json.RootElement);
                    if (Status == 200)
                    {
                        Parse(json.RootElement);
                        Require(Succeeded && Configuration is not null &&
                            Configuration.EventTypes.SequenceEqual([selectedUpdate
                                ? VaultNotificationEvent.SecretNewVersionCreated : VaultNotificationEvent.SecretNearExpiry]) &&
                            Configuration.DeliveryAttributes.Count == 0);
                    }
                    else
                    {
                        var root = json.RootElement;
                        Require(root.ValueKind == JsonValueKind.Object &&
                            root.EnumerateObject().Count() == 1 && root.TryGetProperty("error", out _));
                        var error = root.GetProperty("error");
                        Require(error.ValueKind == JsonValueKind.Object &&
                            error.EnumerateObject().All(p => p.Name is "code" or "message") &&
                            Text(error, "code") == "NotFound");
                        if (error.TryGetProperty("message", out var text))
                            Require(text.ValueKind == JsonValueKind.String && text.GetString() is { Length: <= 4096 });
                    }
                    RequestSha256 = Convert.ToHexString(SHA256.HashData(
                        System.Text.Encoding.UTF8.GetBytes("GET " + uri.AbsoluteUri)));
                    ResponseSha256 = body.Sha256;
                    NativeRequestId = body.NativeRequestId;
                    parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes,
                        parserStorage, requireRebuffer: false, requireDownstreamRead: true);
                    validateReadCompletion = CheckResponse;
                    Valid = true;
                    return;
                }
                Require(Status is >= 200 and < 300 or >= 400 and < 600);
                Headers(message.Response.Headers.Select(h => (h.Name, h.Value)));
                foreach (string name in new[] { "Location", "Azure-AsyncOperation", "Operation-Location" })
                    if (message.Response.Headers.TryGetValues(name, out var links))
                    {
                        HasAsync = true;
                        var values = links.ToArray();
                        Require(values.Length == 1 && values[0] == Origin + plan.ResourceId + "?api-version=" + Revision);
                    }
                if (message.Response.Headers.TryGetValues("Content-Length", out var lengths))
                {
                    var values = lengths.ToArray();
                    Require(values.Length == 1 && long.TryParse(values[0], NumberStyles.None,
                        CultureInfo.InvariantCulture, out long size) && size >= 0 && size <= limits.MaximumResponseBytes);
                }
                using var writer = new RequestBuffer(limits.MaximumResponseBytes);
                byte[] chunk = new byte[4096];
                try
                {
                    using var input = message.Response.ContentStream;
                    if (input is not null)
                    {
                        int count;
                        while ((count = await input.ReadAsync(chunk.AsMemory(), message.CancellationToken).ConfigureAwait(false)) != 0)
                            writer.Write(chunk.AsSpan(0, count));
                    }
                }
                finally { CryptographicOperations.ZeroMemory(chunk); }
                Require(Status != 204 || writer.Length == 0);
                var frozen = new OwnedStream(writer.Written.Span, leaveOpen: true);
                buffers.Add(frozen);
                message.Response.ContentStream = frozen;
                if (writer.Length != 0)
                {
                    using var document = JsonDocument.Parse(frozen.Bytes,
                        new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
                    Unique(document.RootElement);
                    if (Status is 200 or 201)
                    {
                        Require(writer.Length <= limits.MaximumRowBytes);
                        Parse(document.RootElement);
                    }
                }
                else Require(Status is not (200 or 201));
                Valid = true;
            }
            catch { message.Response.Dispose(); throw; }
        }
        private void Headers(IEnumerable<(string Name, string Value)> headers)
        {
            int count = 0, bytes = 0;
            foreach (var header in headers)
            {
                bytes = checked(bytes + System.Text.Encoding.UTF8.GetByteCount(header.Name) +
                    System.Text.Encoding.UTF8.GetByteCount(header.Value));
                Require(++count <= limits.MaximumHeaders && bytes <= limits.MaximumHeaderBytes);
            }
        }
        private void Parse(JsonElement root)
        {
            if ((StatusNotificationUpdateCancellationSelector(plan.Selector) || (StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector))) ||
                StatusNotificationCreateCancellationSelector(plan.Selector) ||
                StatusNotificationDeleteIndependentSelector(plan.Selector))
                Require(root.ValueKind == JsonValueKind.Object &&
                    root.EnumerateObject().All(p => p.Name is "id" or "name" or "type" or "properties"));
            Require(Same(Text(root, "id"), plan.ResourceId) && Same(Text(root, "name"), plan.Scope.SubscriptionName) &&
                Text(root, "type") == ResourceType);
            var p = root.GetProperty("properties");
            if (StatusNotificationDeleteIndependentSelector(plan.Selector) || (StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector)))
                Require(Text(root, "id") == plan.ResourceId && Text(root, "name") == plan.Scope.SubscriptionName &&
                    Text(p, "topic") == plan.Scope.Vault.ExportResourceId());
            Require(Same(Text(p, "topic"), plan.Scope.Vault.ExportResourceId()) &&
                !root.TryGetProperty("nextLink", out _) && !p.TryGetProperty("error", out _) &&
                !p.TryGetProperty("errors", out _));
            NativeState = Text(p, "provisioningState");
            Require(NativeState is "Succeeded" or "Creating" or "Updating" or "Deleting" or
                "AwaitingManualAction" or "Failed" or "Canceled" or "Cancelled");
            if (exclusiveCreation)
            {
                Require(!p.TryGetProperty("labels", out var emptyLabels) ||
                    emptyLabels.ValueKind == JsonValueKind.Array && emptyLabels.GetArrayLength() == 0);
                RawLabels = p.TryGetProperty("labels", out _) ? "empty-array" : "absent";
            }
            else
            {
                var labels = p.GetProperty("labels");
                Require(labels.ValueKind == JsonValueKind.Array && labels.GetArrayLength() == 1 &&
                    labels[0].GetString() == Label(plan));
            }
            var destination = p.GetProperty("destination");
            Require(Text(destination, "endpointType") == "WebHook");
            if ((StatusNotificationUpdateCancellationSelector(plan.Selector) || (StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector))) ||
                StatusNotificationCreateCancellationSelector(plan.Selector) ||
                StatusNotificationDeleteIndependentSelector(plan.Selector))
                Require(destination.EnumerateObject().All(p => p.Name is "endpointType" or "properties"));
            var settings = destination.GetProperty("properties");
            var filter = p.GetProperty("filter");
            if (!filter.TryGetProperty("includedEventTypes", out var events) ||
                events.ValueKind != JsonValueKind.Array) return;
            Require(events.GetArrayLength() is >= 1 and <= 3);
            RawEvents = events.EnumerateArray().Select(e => e.GetString() ?? throw Failure()).ToArray();
            // Raw native strings are compared with native strings. Enum parsing
            // accepts exactly the three supported symbolic names, never numeric.
            VaultNotificationEvent[] supported = RawEvents.Select(e => e switch
            {
                "Microsoft.KeyVault.SecretNewVersionCreated" => VaultNotificationEvent.SecretNewVersionCreated,
                "Microsoft.KeyVault.SecretNearExpiry" => VaultNotificationEvent.SecretNearExpiry,
                "Microsoft.KeyVault.SecretExpired" => VaultNotificationEvent.SecretExpired,
                _ => throw Failure()
            }).ToArray();
            Require(supported.Distinct().Count() == supported.Length);
            if (!settings.TryGetProperty("endpointUrl", out var endpoint) || endpoint.ValueKind != JsonValueKind.String ||
                Masked(endpoint.GetString()) || !settings.TryGetProperty("deliveryAttributeMappings", out var attributes) ||
                attributes.ValueKind != JsonValueKind.Array) return;
            Require(attributes.GetArrayLength() <= 10);
            // Extra filtering/destination settings cannot be silently projected
            // into an apparently exact supported configuration.
            if (settings.EnumerateObject().Any(q => q.Name is not ("endpointUrl" or "endpointBaseUrl" or "deliveryAttributeMappings")) ||
                filter.EnumerateObject().Any(q => q.Name != "includedEventTypes" &&
                    !(q.Name == "advancedFilters" && q.Value.ValueKind == JsonValueKind.Array && q.Value.GetArrayLength() == 0)) ||
                p.EnumerateObject().Any(q => q.Name is not ("topic" or "provisioningState" or "labels" or "destination" or "filter")))
                return;
            List<NotificationDeliveryAttribute> rows = [];
            try
            {
                foreach (var row in attributes.EnumerateArray())
                {
                    string kind = Text(row, "type");
                    var properties = row.GetProperty("properties");
                    string field = kind == "Static" ? "value" : "sourceField";
                    Require(kind is "Static" or "Dynamic");
                    if (row.EnumerateObject().Any(q => q.Name is not ("name" or "type" or "properties")) ||
                        properties.EnumerateObject().Any(q => q.Name != field && (kind != "Static" || q.Name != "isSecret")))
                        return;
                    if (!properties.TryGetProperty(field, out var value) || value.ValueKind != JsonValueKind.String ||
                        Masked(value.GetString())) return;
                    bool secret = false;
                    if (kind == "Static")
                    {
                        if (!properties.TryGetProperty("isSecret", out var flag) ||
                            flag.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return;
                        secret = flag.GetBoolean();
                    }
                    else if (properties.TryGetProperty("isSecret", out _)) return;
                    rows.Add(new(Text(row, "name"), kind == "Static" ? NotificationAttributeKind.Static :
                        NotificationAttributeKind.Dynamic, value.GetString()!, secret));
                }
                Configuration = new(endpoint.GetString()!, supported, rows);
                if ((StatusNotificationUpdateCancellationSelector(plan.Selector) || (StatusNotificationUpdateIndependentSelector(plan.Selector) || StatusNotificationCreateIndependentSelector(plan.Selector))) ||
                    StatusNotificationCreateCancellationSelector(plan.Selector) ||
                    StatusNotificationDeleteIndependentSelector(plan.Selector))
                {
                    var full = new Uri(Configuration.Endpoint.Reveal(), UriKind.Absolute);
                    Require(full.Scheme == "https" && full.UserInfo.Length == 0 && full.Fragment.Length == 0);
                    if (settings.TryGetProperty("endpointBaseUrl", out var endpointBase))
                        Require(endpointBase.ValueKind == JsonValueKind.String &&
                            endpointBase.GetString() == full.GetLeftPart(UriPartial.Path));
                }
            }
            finally { foreach (var row in rows) row.Dispose(); }
        }
        private static bool Masked(string? text) => string.IsNullOrEmpty(text) ||
            text.Contains('*') || text is "[REDACTED]" or "<redacted>";
        private static string Text(JsonElement element, string name) =>
            element.GetProperty(name).GetString() is { Length: > 0 and <= 4096 } value ? value : throw Failure();
        private static void Unique(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var property in element.EnumerateObject()) { Require(names.Add(property.Name)); Unique(property.Value); }
            }
            else if (element.ValueKind == JsonValueKind.Array)
                foreach (var item in element.EnumerateArray()) Unique(item);
        }
        internal void ClearBuffers()
        {
            try { parserStorage.Dispose(); fixtureDisposed = true; }
            catch { fixtureDisposalFailed = true; throw; }
            finally
            {
                foreach (var buffer in buffers) buffer.Clear();
                buffers.Clear();
                Configuration?.Dispose();
                Configuration = null;
            }
        }
        public void Dispose() => ClearBuffers();
    }

    // Native Response.Content uses MemoryStream's whole-buffer contract when
    // materializing a cached response more than once. This storage has already
    // been bounded and drained; it is not the asynchronous ingress barrier.
    internal sealed class OwnedStream : MemoryStream
    {
        private readonly byte[] bytes;
        private readonly bool leaveOpen;
        private bool disposed;
        internal OwnedStream(ReadOnlySpan<byte> data, bool leaveOpen = false) : this(data.ToArray(), leaveOpen) { }
        private OwnedStream(byte[] data, bool leaveOpen) : base(data, 0, data.Length, writable: false, publiclyVisible: true)
        {
            bytes = data;
            this.leaveOpen = leaveOpen;
        }
        internal ReadOnlyMemory<byte> Bytes => bytes;
        protected override void Dispose(bool disposing)
        {
            if (disposing && !leaveOpen) Clear();
        }
        internal void Clear()
        {
            if (!disposed)
            {
                disposed = true;
                CryptographicOperations.ZeroMemory(bytes);
                base.Dispose(true);
            }
        }
    }
    internal sealed class RequestBuffer(int maximum) : Stream
    {
        private readonly byte[] bytes = new byte[maximum];
        private int length;
        internal ReadOnlyMemory<byte> Written => bytes.AsMemory(0, length);
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => length;
        public override long Position { get => length; set => throw Failure(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw Failure();
        public override long Seek(long offset, SeekOrigin origin) => throw Failure();
        public override void SetLength(long value) => throw Failure();
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Require(buffer.Length <= maximum - length);
            buffer.CopyTo(bytes.AsSpan(length));
            length += buffer.Length;
        }
        public override void WriteByte(byte value)
        {
            Require(length < maximum);
            bytes[length++] = value;
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer.AsSpan(offset, count));
            return Task.CompletedTask;
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) CryptographicOperations.ZeroMemory(bytes);
            base.Dispose(disposing);
        }
    }
}
