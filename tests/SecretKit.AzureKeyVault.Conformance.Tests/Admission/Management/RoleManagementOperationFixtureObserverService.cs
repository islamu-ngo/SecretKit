using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;
using E = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;
using R = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Original role DELETE only. The private empty-204 proof establishes native
// success; a separate resource GET establishes absence, never settlement.
// Credentials, transports, capability, provisioner and journal remain borrowed.
internal sealed class RoleManagementOperationFixtureObserverService : E.SelectedInvocation, IAsyncDisposable
{
    internal sealed record Limits(int MaximumRequestBytes, int MaximumReplyBytes, TimeSpan NativeTimeout)
    {
        public override string ToString() => "[RoleManagementOperationLimits]";
    }

    private const string Revision = "2022-04-01";
    private static readonly JsonSerializerOptions Json = new(ManagementAdmission.Json)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true
    };
    private readonly object gate = new();
    private readonly Uri origin;
    private readonly string owner, observerIdentity, resourceIdentity;
    private readonly SecretMaterial capability;
    private readonly RoleFixtureProvisioner.HostScope scope;
    private readonly RoleFixtureProvisioner provisioner;
    private readonly C capture;
    private readonly R before, after;
    private readonly R.Authority resourceReader;
    private readonly bool independentProfile, cleanupOnly;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, IndependentFacts> independentFacts =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusRoleDeleteCancellationSettlement,
        StatusRoleCompletion> statusRoleSettlements = new(ReferenceEqualityComparer.Instance);
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly Dictionary<Guid, Session> sessions = [];
    private readonly CancellationTokenSource lifetime = new();
    private readonly TaskCompletionSource drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TaskCompletionSource? disposal;
    private bool disposed;
    private int active;

    private sealed class Session(FixtureSelector selector)
    {
        internal readonly FixtureSelector Selector = selector;
        internal readonly CancellationTokenSource Stop = new();
        internal SecretMaterial? Canary;
        internal RoleFixtureProvisioner.Plan? Plan;
        internal E.Prepare? Preparation;
        internal E.Lease? Lease;
        internal C.Binding? Binding;
        internal C.Window? Capture;
        internal R.Window? Before, After;
        internal C.SynchronousDeleteProof? DeleteProof;
        internal C.StatusRoleDeleteCancellationStartProof? RoleDeleteProof;
        internal RoleFixtureProvisioner.StatusRoleDeleteReadProof? RoleBaseline, RoleAfter;
        internal RoleFixtureJournal.Resource[]? BaselineRows;
        internal Task<RoleFixtureProvisioner.StatusRoleDeleteReadProof>? BaselineTask, AfterTask;
        internal VaultAdministration? Client;
        internal RoleAssignmentScope? ActualScope;
        internal ManagementReceipt? Receipt;
        internal ManagementOperation? Handle;
        internal Task? StartTask, CanceledTask, StatusTask;
        internal Guid Subscription, Dispatch;
        internal DateTimeOffset ArmedAt, BaselineAt, StartedAt, IndependentAt;
        internal bool Closed, ArmClaimed, Armed, BaselineClaimed, BaselineReady;
        internal bool StartClaimed, StartFinished, StartSucceeded, AfterClaimed, IndependentReady;
        internal bool StatusClaimed, StatusSucceeded, Releasing;
        internal bool CancelClaimed, CancelFinished;
        internal int Active;
        internal RoleFixtureJournal.Snapshot? IndependentReadySnapshot, IndependentBegin, IndependentDrained, IndependentRead;
        internal RoleFixtureProvisioner.StatusRoleDeleteIndependentReadProof? IndependentBaseline, IndependentAfter;
        internal Task<RoleFixtureProvisioner.StatusRoleDeleteIndependentReadProof>? IndependentBaselineTask, IndependentAfterTask;
        internal C.StatusRoleDeleteIndependentStartProof? IndependentStart;
        internal StatusRoleDeleteIndependentStartDrain? IndependentStartDrain;
        internal StatusRoleDeleteIndependentSettlement? IndependentSettlement;
        internal readonly List<object> IndependentCapabilities = [];
        internal readonly List<CancellationToken> IndependentTokens = [];
        internal bool IndependentInvalid;
    }

    private enum IndependentStage { Begin, StartDrain, Read, Complete }
    private sealed record IndependentFacts(RoleFixtureJournal.Snapshot Preimage, string AssignmentId,
        Guid Dispatch, IndependentStage Stage, CancellationToken[] Tokens, Task[] Tasks);

    internal sealed class StatusRoleDeleteIndependentAdmission(RoleManagementOperationFixtureObserverService source)
    {
        internal string ResourceId => source.independentFacts.TryGetValue(this, out var f) ? f.AssignmentId : "";
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateIndependent(this, journal, state, IndependentStage.Begin);
        public override string ToString() => "[StatusRoleDeleteIndependentAdmission]";
    }

    internal sealed class StatusRoleDeleteIndependentStartDrain(RoleManagementOperationFixtureObserverService source)
    {
        internal Guid Dispatch => source.independentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateIndependent(this, journal, state, IndependentStage.StartDrain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateIndependent(this, journal, state, IndependentStage.StartDrain, true);
        public override string ToString() => "[StatusRoleDeleteIndependentStartDrain]";
    }

    internal sealed class StatusRoleDeleteIndependentReadAdmission(RoleManagementOperationFixtureObserverService source)
    {
        internal Guid Dispatch => source.independentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateIndependent(this, journal, state, IndependentStage.Read);
        public override string ToString() => "[StatusRoleDeleteIndependentReadAdmission]";
    }

    internal sealed class StatusRoleDeleteIndependentSettlement(RoleManagementOperationFixtureObserverService source)
    {
        internal Guid Dispatch => source.independentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateIndependent(this, journal, state, IndependentStage.Complete);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateIndependent(this, journal, state, IndependentStage.Complete, true);
        public override string ToString() => "[StatusRoleDeleteIndependentSettlement]";
    }

    private bool ValidateIndependent(object capability, RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state,
        IndependentStage stage, bool postimage = false) =>
        ReferenceEquals(journal, provisioner.Journal) && independentFacts.TryGetValue(capability, out var f) &&
        f.Stage == stage && f.Tokens.All(t => !t.IsCancellationRequested) && f.Tasks.All(t => t.IsCompletedSuccessfully) &&
        !state.Closing && RoleFixtureJournal.SameStatusRoleDeleteIndependentSnapshot(
            postimage ? IndependentPostimage(f) : f.Preimage, state);

    private static RoleFixtureJournal.Snapshot IndependentPostimage(IndependentFacts f) =>
        f.Preimage with
        {
            Revision = f.Preimage.Revision + 1,
            Resources = f.Preimage.Resources.Select(r => r.Id == f.AssignmentId ? r with
            {
                InvocationTerminated = true,
                ActiveDispatch = f.Stage == IndependentStage.Complete ? Guid.Empty : f.Dispatch
            } : r).ToArray()
        };

    private static RoleFixtureJournal.Snapshot FreezeIndependent(RoleFixtureJournal.Snapshot snapshot) =>
        snapshot with { Selector = snapshot.Selector with { }, Resources = snapshot.Resources.ToArray() };

    private void IssueIndependent(Session session, object capability, IndependentStage stage,
        RoleFixtureJournal.Snapshot snapshot, params Task[] tasks)
    {
        Require(!session.IndependentInvalid && !session.Closed && !disposed &&
            session.IndependentTokens.All(t => !t.IsCancellationRequested));
        Require(independentFacts.TryAdd(capability, new(FreezeIndependent(snapshot), session.Plan!.AssignmentId,
            session.Dispatch, stage, session.IndependentTokens.ToArray(), tasks)));
        session.IndependentCapabilities.Add(capability);
    }

    private void InvalidateIndependent(Session session)
    {
        session.IndependentInvalid = true;
        foreach (var capability in session.IndependentCapabilities) independentFacts.TryRemove(capability, out _);
    }

    internal static RoleManagementOperationFixtureObserverService ForStatusRoleDeleteIndependent(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, RoleFixtureProvisioner.HostScope scope,
        RoleFixtureProvisioner provisioner, R.Authority resourceReader, HttpPipelineTransport selectedBackend,
        Limits limits, TimeProvider? time = null) =>
        new(origin, owner, observerIdentity, capability, scope, provisioner, resourceReader, selectedBackend, limits, time, true, false);

    internal static RoleManagementOperationFixtureObserverService ForStatusRoleDeleteIndependentCleanup(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, RoleFixtureProvisioner.HostScope scope,
        RoleFixtureProvisioner provisioner, Limits limits, TimeProvider? time = null) =>
        new(origin, owner, observerIdentity, capability, scope, provisioner, null, null, limits, time, true, true);

    internal sealed class StatusRoleDeleteCancellationSettlement(RoleManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateStatusRoleSettlement(this, journal, snapshot);
        public override string ToString() => "[StatusRoleDeleteCancellationSettlement]";
    }

    private sealed record StatusRoleCompletion(string Owner, FixtureSelector Selector, Guid Lease, Guid Dispatch,
        string AssignmentId, RoleFixtureJournal.Resource[] Rows,
        RoleFixtureProvisioner.StatusRoleDeleteReadProof Baseline, RoleFixtureProvisioner.StatusRoleDeleteReadProof After,
        Task BaselineTask, Task AfterTask, Task StartTask, Task CanceledTask, Task StatusTask,
        CancellationToken Cancellation, CancellationToken CallerCancellation);

    private bool ValidateStatusRoleSettlement(StatusRoleDeleteCancellationSettlement candidate,
        RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
        ReferenceEquals(journal, provisioner.Journal) && statusRoleSettlements.TryGetValue(candidate, out var proof) &&
        candidate.Dispatch == proof.Dispatch && proof.Dispatch != Guid.Empty &&
        !proof.Cancellation.IsCancellationRequested && !proof.CallerCancellation.IsCancellationRequested &&
        proof.BaselineTask.IsCompletedSuccessfully && proof.AfterTask.IsCompletedSuccessfully &&
        proof.Baseline.NativeTask.IsCompletedSuccessfully && proof.After.NativeTask.IsFaulted &&
        proof.StartTask.IsCompletedSuccessfully && proof.CanceledTask.IsCanceled && proof.StatusTask.IsCompletedSuccessfully &&
        !ReferenceEquals(proof.CanceledTask, proof.StatusTask) &&
        snapshot.Owner == proof.Owner && snapshot.Selector == proof.Selector && snapshot.LeaseId == proof.Lease &&
        !snapshot.Closing && RoleFixtureJournal.StatusRoleDeleteRoot(snapshot) && proof.Rows.Length == 5 &&
        proof.Rows.All(b => snapshot.Resources.Count(r => r.Id == b.Id &&
            (r.Id == proof.AssignmentId ? r is
            {
                CreateAttempted: true, SelectedAttempted: true,
                DeleteAttempted: false, Absent: false, InvocationTerminated: false
            } &&
                r.ActiveDispatch == proof.Dispatch : r == b)) == 1);

    internal RoleManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, RoleFixtureProvisioner.HostScope scope, RoleFixtureProvisioner provisioner,
        R.Authority resourceReader, HttpPipelineTransport selectedBackend, Limits limits, TimeProvider? time = null)
        : this(origin, owner, observerIdentity, capability, scope, provisioner, resourceReader, selectedBackend,
            limits, time, false, false)
    { }

    private RoleManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, RoleFixtureProvisioner.HostScope scope, RoleFixtureProvisioner provisioner,
        R.Authority? resourceReader, HttpPipelineTransport? selectedBackend, Limits limits, TimeProvider? time,
        bool independentProfile, bool cleanupOnly)
    {
        Require(origin is
        {
            IsAbsoluteUri: true, Scheme: "https", AbsolutePath: "/",
            UserInfo.Length: 0, Query.Length: 0, Fragment.Length: 0
        } && Text(owner, 128) && Text(observerIdentity, 128) && capability is not null &&
            scope is not null && scope.ExclusiveFixtureNamespace && scope.AllowPurge &&
            scope.SubscriptionId != Guid.Empty && scope.TenantId != Guid.Empty &&
            scope.IntendedPrincipalId != Guid.Empty && scope.IntendedRoleDefinitionId != Guid.Empty &&
            Segment(scope.ResourceGroup, 90) && Segment(scope.Location, 50) &&
            provisioner is not null && provisioner.Host == scope &&
            (cleanupOnly || resourceReader is { Credential: not null, Transport: not null } && Text(resourceReader.Label, 128) &&
                selectedBackend is not null && !ReferenceEquals(resourceReader.Transport, selectedBackend)) &&
            limits is not null && limits.MaximumRequestBytes is >= 1024 and <= 1024 * 1024 &&
            limits.MaximumReplyBytes is >= 1024 and <= 1024 * 1024 &&
            limits.NativeTimeout > TimeSpan.Zero && limits.NativeTimeout <= TimeSpan.FromMinutes(2));
        this.origin = origin;
        this.owner = owner;
        this.observerIdentity = observerIdentity;
        this.capability = capability;
        this.scope = scope;
        this.provisioner = provisioner;
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
        this.independentProfile = independentProfile;
        this.cleanupOnly = cleanupOnly;
        if (cleanupOnly)
        {
            resourceIdentity = "";
            this.resourceReader = null!;
            capture = null!;
            before = after = null!;
            return;
        }
        if (independentProfile) provisioner.ValidateStatusRoleDeleteIndependentAuthorities(resourceReader!, selectedBackend!);
        resourceIdentity = resourceReader!.Label;
        this.resourceReader = resourceReader;
        capture = new(selectedBackend!, limits.MaximumReplyBytes);
        var resourceLimits = new R.Limits(limits.MaximumReplyBytes, limits.MaximumReplyBytes,
            4096, 16, 32, limits.NativeTimeout);
        before = new(resourceReader, resourceLimits, this.time, scope.TenantId);
        after = new(resourceReader, resourceLimits, this.time, scope.TenantId);
    }

    internal HttpPipelineTransport SelectedTransport => !cleanupOnly ? capture.SelectedTransport : throw Failure();

    internal async Task<HttpResponseMessage> DispatchAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!Authenticate(request)) return Error(HttpStatusCode.Unauthorized);
        if (request.Method != HttpMethod.Post || request.RequestUri is not { IsAbsoluteUri: true } uri ||
            uri.Scheme != "https" || uri.GetLeftPart(UriPartial.Authority) != origin.GetLeftPart(UriPartial.Authority) ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0)
            return Error(HttpStatusCode.BadRequest);
        lock (gate)
        {
            if (disposed) return Error(HttpStatusCode.ServiceUnavailable);
            active++;
        }
        try
        {
            using var deadline = new CancellationTokenSource(limits.NativeTimeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, deadline.Token);
            using var body = await ReadBody(request, linked.Token).ConfigureAwait(false);
            return uri.AbsolutePath switch
            {
                "/operation/prepare" => await Prepare(body.RootElement.Deserialize<E.Prepare>(Json) ?? throw Failure(),
                    linked.Token, cancellationToken).ConfigureAwait(false),
                "/operation/arm" => Arm(body.RootElement.Deserialize<ObserveLease>(Json) ?? throw Failure()),
                "/operation/observe" => await Observe(body.RootElement.Deserialize<ObserveLease>(Json) ?? throw Failure(),
                    linked.Token, cancellationToken).ConfigureAwait(false),
                "/operation/release" => await Release(body.RootElement.Deserialize<FixtureSelector>(Json) ?? throw Failure(),
                    linked.Token, cancellationToken).ConfigureAwait(false),
                _ => Error(HttpStatusCode.NotFound)
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { return Error(HttpStatusCode.ServiceUnavailable); }
        finally { Leave(null); }
    }

    private async Task<HttpResponseMessage> Prepare(E.Prepare input, CancellationToken token, CancellationToken callerToken)
    {
        ValidateSelector(input.Selection);
        Require(input.SubscriptionId == scope.SubscriptionId && input.ResourceGroup == scope.ResourceGroup &&
            input.Location == scope.Location && input.TenantId == scope.TenantId &&
            input.Operation == ManagementMutation.DeleteRoleAssignment);
        Session session;
        lock (gate)
        {
            Require(!disposed && sessions.Count < 32 && !sessions.ContainsKey(input.Selection.Nonce));
            session = new(input.Selection with { })
            {
                Active = 1,
                Preparation = input with { Selection = input.Selection with { } }
            };
            sessions.Add(input.Selection.Nonce, session);
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            byte[] entropy = RandomNumberGenerator.GetBytes(32);
            SecretMaterial canary;
            try { canary = SecretMaterial.FromText(Convert.ToHexString(entropy)); }
            finally { CryptographicOperations.ZeroMemory(entropy); }
            lock (gate)
            {
                if (disposed || session.Closed) { canary.Dispose(); throw Failure(); }
                session.Canary = canary;
                session.Plan = independentProfile
                    ? provisioner.PlanStatusRoleDeleteIndependentFixture(owner, session.Selector)
                    : provisioner.PlanFixture(owner, session.Selector, new(null, null, []), createAssignment: true);
                RequireTopology(session.Selector, provisioner.Journal.Read(owner, session.Selector), session.Plan);
            }
            // Retain both source-owned objects before setup can call host code,
            // including when setup or serialization loses its reply.
            var plan = session.Plan!;
            var prepared = await provisioner.ProvisionAsync(plan, canary.Reveal(), linked.Token,
                independentProfile ? callerToken : null).ConfigureAwait(false);
            Require(prepared.State == RoleFixtureProvisioner.State.Ready && prepared.VaultReady == true &&
                prepared.AssignmentPresent == true && prepared.CanaryPresent == true &&
                Text(prepared.CanaryVersion, 256) && prepared.CanaryVersion == plan.CanaryVersion &&
                prepared.CanarySha256 == CanaryHash(canary) && prepared.Journal is not null);
            RequireOpenJournal(session, prepared.Journal, selected: false);
            var observedAt = time.GetUtcNow();
            lock (gate)
            {
                Require(!disposed && !session.Closed && !linked.IsCancellationRequested);
                var snapshot = provisioner.Journal.Read(owner, session.Selector);
                RequireOpenJournal(session, snapshot, selected: false);
                if (independentProfile)
                {
                    Require(plan.IndependentReady is not null &&
                        RoleFixtureJournal.SameStatusRoleDeleteIndependentSnapshot(plan.IndependentReady, prepared.Journal!) &&
                        RoleFixtureJournal.SameStatusRoleDeleteIndependentSnapshot(prepared.Journal!, snapshot));
                    session.IndependentReadySnapshot = FreezeIndependent(prepared.Journal!);
                }
                session.Lease = new(new(session.Selector.Nonce, plan.LeaseId, observerIdentity,
                    R.ArmOrigin, Revision, observedAt, snapshot.Resources.Where(r => !r.Borrowed).Select(r => r.Id).ToArray()),
                    plan.VaultName, null, null, AssignmentId(plan), ManagementMutation.DeleteRoleAssignment,
                    NativeProvisioningState.Succeeded);
                return Reply(session.Lease);
            }
        }
        finally { LeaveSession(session); }
    }

    private HttpResponseMessage Arm(ObserveLease input)
    {
        Session session;
        lock (gate)
        {
            session = Find(input.Nonce, input.LeaseId);
            Require(!cleanupOnly);
            Require(!session.ArmClaimed && input.Phase == "subscribe-before-trigger" && input.SubscriptionId is null);
            RequireOpenJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: false);
            session.ArmClaimed = true;
            session.Active++;
        }
        try
        {
            var plan = session.Plan!;
            var resource = new RoleAssignmentScope(
                new VaultScope(new(new(scope.SubscriptionId), scope.ResourceGroup), plan.VaultName), AssignmentId(plan));
            var binding = new C.Binding(session.Selector, plan.LeaseId, resource,
                ManagementMutation.DeleteRoleAssignment, scope.Location, Revision);
            var native = capture.Arm(binding);
            // Separate source instances and original windows are armed before
            // the selected SDK invocation, never lazily after its response.
            bool roleCancellation = RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(session.Selector);
            var baseline = roleCancellation || independentProfile ? null : before.Arm(binding);
            var post = roleCancellation || independentProfile ? null : after.Arm(binding);
            var armedAt = time.GetUtcNow();
            lock (gate)
            {
                Require(!disposed && !session.Closed);
                RequireOpenJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: false);
                session.Binding = binding;
                session.Capture = native;
                session.Before = baseline;
                session.After = post;
                session.ArmedAt = armedAt;
                session.Subscription = Guid.NewGuid();
                if (roleCancellation)
                    provisioner.ArmStatusRoleDeleteCancellationReads(plan, resourceReader, session.Subscription, armedAt);
                if (independentProfile)
                    provisioner.ArmStatusRoleDeleteIndependentReads(plan, resourceReader, session.Subscription, armedAt);
                session.Armed = true;
                return Reply(new ObservationSubscription(plan.LeaseId, session.Selector.Nonce, session.Subscription, armedAt));
            }
        }
        finally { LeaveSession(session); }
    }

    private async Task<HttpResponseMessage> Observe(ObserveLease input, CancellationToken token, CancellationToken callerToken)
    {
        if (independentProfile) return await ObserveIndependent(input, token, callerToken).ConfigureAwait(false);
        bool roleCancellation;
        lock (gate) roleCancellation = sessions.TryGetValue(input.Nonce, out var roleSession) &&
            RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(roleSession.Selector);
        if (roleCancellation)
            return await ObserveStatusRole(input, token).ConfigureAwait(false);
        Session session;
        bool baseline = input.Phase == "baseline-before-dispatch";
        lock (gate)
        {
            session = Find(input.Nonce, input.LeaseId);
            Require(session.Armed && input.SubscriptionId == session.Subscription);
            if (baseline)
            {
                Require(!session.BaselineClaimed && !session.StartClaimed);
                session.BaselineClaimed = true;
            }
            else
            {
                Require(input.Phase == "selected-state" && session.StartFinished && session.StartSucceeded &&
                    session.StartTask is { IsCompletedSuccessfully: true } && !session.AfterClaimed);
                session.AfterClaimed = true;
            }
            RequireOpenJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: !baseline);
            session.Active++;
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            var binding = session.Binding!;
            if (baseline)
            {
                using var measured = await before.CollectAsync(session.Before!, binding, linked.Token).ConfigureAwait(false);
                Require(ResourceBound(measured, session, session.Before!) && measured.HttpStatus == 200 &&
                    measured.ResourceStatus == SecretStatus.Success && measured.PersistedStateEligible &&
                    measured.ResourceId == session.Plan!.AssignmentId &&
                    measured.RoleAssignment is { } assignment && assignment.Scope == session.Plan.VaultId &&
                    assignment.PrincipalId == scope.IntendedPrincipalId && assignment.RoleDefinitionId == DefinitionId &&
                    measured.VaultConfiguration is null && measured.ConnectionState is null &&
                    measured.NotificationConfiguration is null);
                lock (gate)
                {
                    Require(!disposed && !session.Closed && !linked.IsCancellationRequested && !session.StartClaimed);
                    RequireOpenJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: false);
                    session.BaselineAt = measured.FinishedAt;
                    session.BaselineReady = true;
                    return Reply(Project(session, measured.FinishedAt, NativeProvisioningState.Unknown, SecretStatus.Success));
                }
            }
            C.SynchronousDeleteProof proof;
            lock (gate)
            {
                Require(!disposed && !session.Closed);
                Require(capture.TryGetSynchronousDeleteProof(session.Capture!, binding, out var issued) &&
                    OwnsDeleteProof(session, issued));
                proof = issued;
            }
            using var resource = await after.CollectAsync(session.After!, binding, linked.Token).ConfigureAwait(false);
            Require(ResourceBound(resource, session, session.After!) && resource.StartedAt >= session.StartedAt &&
                resource.HttpStatus == 404 && resource.ResourceStatus == SecretStatus.Absent &&
                resource.ResourceId is null && resource.RoleAssignment is null && !resource.PersistedStateEligible &&
                resource.VaultConfiguration is null && resource.ConnectionState is null &&
                resource.NotificationConfiguration is null);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !linked.IsCancellationRequested && OwnsDeleteProof(session, proof));
                RequireOpenJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: true);
                session.DeleteProof = proof;
                session.IndependentAt = resource.FinishedAt;
                session.IndependentReady = true;
                return Reply(Project(session, resource.FinishedAt, NativeProvisioningState.Succeeded, SecretStatus.Absent));
            }
        }
        finally { LeaveSession(session); }
    }

    private async Task<HttpResponseMessage> ObserveStatusRole(ObserveLease input, CancellationToken token)
    {
        Session session;
        bool baseline = input.Phase == "baseline-before-dispatch";
        lock (gate)
        {
            session = Find(input.Nonce, input.LeaseId);
            Require(session.Armed && input.SubscriptionId == session.Subscription);
            if (baseline)
            {
                Require(!session.BaselineClaimed && !session.StartClaimed);
                session.BaselineClaimed = true;
            }
            else
            {
                Require(input.Phase == "selected-state" && session.StartFinished && session.StartSucceeded &&
                    session.StartTask is { IsCompletedSuccessfully: true } && !session.AfterClaimed &&
                    OwnsRoleStart(session, out _));
                session.AfterClaimed = true;
            }
            RequireOpenJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: !baseline);
            session.Active++;
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            var task = provisioner.ObserveStatusRoleDeleteCancellationAsync(session.Plan!,
                baseline ? Guid.Empty : session.Dispatch, linked.Token).AsTask();
            lock (gate)
            {
                if (baseline) session.BaselineTask = task;
                else session.AfterTask = task;
            }
            var read = await task.ConfigureAwait(false);
            Require(provisioner.OwnsStatusRoleDeleteRead(read, session.Plan!, session.Subscription,
                baseline ? Guid.Empty : session.Dispatch) && read.ArmedAt == session.ArmedAt &&
                read.Reader.Label == resourceIdentity && read.StartedAt >= session.ArmedAt &&
                read.FinishedAt >= read.StartedAt && (baseline
                    ? read.HttpStatus == 200 && read.NativeTask.IsCompletedSuccessfully && read.Metadata is not null
                    : read.HttpStatus == 404 && read.NativeTask.IsFaulted && read.Metadata is null &&
                        read.NativeError is { Status: 404, ErrorCode: "ResourceNotFound" } &&
                        read.StartedAt >= session.StartedAt));
            lock (gate)
            {
                Require(!disposed && !session.Closed && !linked.IsCancellationRequested);
                var snapshot = provisioner.Journal.Read(owner, session.Selector);
                RequireOpenJournal(session, snapshot, selected: !baseline);
                if (baseline)
                {
                    Require(!session.StartClaimed);
                    session.RoleBaseline = read;
                    session.BaselineRows = snapshot.Resources.ToArray();
                    session.BaselineAt = read.FinishedAt;
                    session.BaselineReady = true;
                }
                else
                {
                    Require(OwnsRoleStart(session, out var start));
                    session.RoleDeleteProof = start;
                    session.RoleAfter = read;
                    session.IndependentAt = read.FinishedAt;
                    session.IndependentReady = true;
                }
                return Reply(Project(session, read.FinishedAt, baseline ? NativeProvisioningState.Unknown :
                    NativeProvisioningState.Succeeded, baseline ? SecretStatus.Success : SecretStatus.Absent));
            }
        }
        finally { LeaveSession(session); }
    }

    private bool OwnsRoleStart(Session session,
        [NotNullWhen(true)] out C.StatusRoleDeleteCancellationStartProof? proof)
    {
        proof = null;
        return session.Client is { } client && session.ActualScope is { } actual &&
            session.Receipt is { } receipt && session.StartTask is { } start && session.Handle is { } handle &&
            capture.TryGetStatusRoleDeleteCancellationStart(session.Capture!, session.Binding!, client, actual,
                receipt, start, handle, out proof);
    }

    public async ValueTask<SecretOutcome<ManagementOperation>> RunStartAsync(FixtureSelector selector,
        VaultAdministration client, ManagementScope originalScope, ManagementMutation operation,
        E.Input input, ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        if (independentProfile)
            return await StartIndependent(selector, client, originalScope, operation, input, receipt, cancellationToken).ConfigureAwait(false);
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(client is not null && receipt is not null && receipt.Evidence == DispatchEvidence.NotDispatched &&
                originalScope is RoleAssignmentScope { Parent: VaultScope vault } role &&
                vault.ResourceGroup.Subscription.SubscriptionId == scope.SubscriptionId &&
                vault.ResourceGroup.ResourceGroup == scope.ResourceGroup && vault.VaultName == session.Plan!.VaultName &&
                role.AssignmentId == AssignmentId(session.Plan) && vault.ExportResourceId() == session.Plan.VaultId &&
                operation == ManagementMutation.DeleteRoleAssignment && session.Armed && session.BaselineReady &&
                !session.StartClaimed && InputMatches(session, input));
            RequireOpenJournal(session, provisioner.Journal.Read(owner, selector), selected: false);
            session.Client = client;
            session.ActualScope = (RoleAssignmentScope)originalScope;
            session.Receipt = receipt;
            // The provisioner privately retains this exact selected admission.
            // No time, credential, transport or selected SDK callback precedes
            // its durable fence. The SDK validates receipt/client/scope ownership
            // before its own callbacks and consumes the original receipt once.
            session.Dispatch = provisioner.BeginSelectedDispatch(owner, selector, session.Plan!.AssignmentId, delete: true);
            session.StartClaimed = true;
            session.Active++;
            active++;
        }
        try
        {
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineAt);
            using var deadline = new CancellationTokenSource(limits.NativeTimeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, session.Stop.Token, deadline.Token);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !linked.IsCancellationRequested);
                RequireOpenJournal(session, provisioner.Journal.Read(owner, selector), selected: true, invocationTerminated: false);
            }
            var result = await capture.StartAsync(session.Capture!, selector, client, originalScope, input, receipt, linked.Token,
                task => { lock (gate) session.StartTask = task; }).ConfigureAwait(false);
            lock (gate)
            {
                session.StartSucceeded = result.IsSuccess && session.StartTask is { IsCompletedSuccessfully: true };
                session.Handle = result.IsSuccess ? result.Value : null;
            }
            return result;
        }
        finally
        {
            try
            {
                // StartAsync drains the whole invocation and capture borrowers.
                // A completed wrapper alone never settles the native deletion.
                provisioner.EndSelectedDispatch(owner, selector, session.Plan!.AssignmentId, session.Dispatch, settled: false);
                lock (gate) session.StartFinished = true;
            }
            finally { Leave(session); }
        }
    }

    public async ValueTask<SecretStatus> RunCheckStatusAsync(FixtureSelector selector, ManagementOperation handle,
        CancellationToken cancellationToken)
    {
        if (independentProfile) return await CheckIndependent(selector, handle, cancellationToken).ConfigureAwait(false);
        if (RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(selector))
            return await RunStatusRoleCheck(selector, handle, cancellationToken).ConfigureAwait(false);
        Session session;
        C.SynchronousDeleteProof proof;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(session.StartFinished && session.StartSucceeded && session.IndependentReady &&
                !session.StatusClaimed && ReferenceEquals(handle, session.Handle) &&
                session.DeleteProof is not null && OwnsDeleteProof(session, session.DeleteProof));
            proof = session.DeleteProof;
            RequireOpenJournal(session, provisioner.Journal.Read(owner, selector), selected: true);
            provisioner.Journal.AdmitStatusRead(owner, selector, session.Plan!.LeaseId, session.Plan.AssignmentId, session.Dispatch);
            session.StatusClaimed = true;
            session.Active++;
            active++;
        }
        CancellationToken statusToken = cancellationToken;
        try
        {
            Require(time.GetUtcNow() >= session.IndependentAt);
            using var deadline = new CancellationTokenSource(limits.NativeTimeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, session.Stop.Token, deadline.Token);
            statusToken = linked.Token;
            lock (gate)
            {
                Require(!disposed && !session.Closed && !linked.IsCancellationRequested &&
                    ReferenceEquals(proof, session.DeleteProof) && OwnsDeleteProof(session, proof));
                RequireOpenJournal(session, provisioner.Journal.Read(owner, selector), selected: true, invocationTerminated: false);
            }
            // The cached SDK success may use zero GETs. Only the separately
            // owned original response proof and fresh independent read authorize
            // settlement here; OwnsNativeStatusCompletion remains false.
            var status = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !linked.IsCancellationRequested &&
                    ReferenceEquals(proof, session.DeleteProof) && OwnsDeleteProof(session, proof));
                RequireOpenJournal(session, provisioner.Journal.Read(owner, selector), selected: true, invocationTerminated: false);
                session.StatusSucceeded = status == SecretStatus.Success &&
                    handle.State == NativeProvisioningState.Succeeded && session.IndependentReady &&
                    session.StartTask is { IsCompletedSuccessfully: true } &&
                    session.StatusTask is { IsCompletedSuccessfully: true };
            }
            return status;
        }
        finally
        {
            try
            {
                lock (gate)
                {
                    bool settled = !disposed && !session.Closed && !statusToken.IsCancellationRequested &&
                        !lifetime.IsCancellationRequested && !session.Stop.IsCancellationRequested &&
                        session.StatusSucceeded && session.IndependentReady &&
                        ReferenceEquals(handle, session.Handle) && handle.State == NativeProvisioningState.Succeeded &&
                        session.StartTask is { IsCompletedSuccessfully: true } &&
                        session.StatusTask is { IsCompletedSuccessfully: true } &&
                        ReferenceEquals(proof, session.DeleteProof) && OwnsDeleteProof(session, proof);
                    if (settled)
                        RequireOpenJournal(session, provisioner.Journal.Read(owner, selector),
                            selected: true, invocationTerminated: false);
                    // Selected admission was consumed by EndSelectedDispatch.
                    // This is a status borrower on that same durable dispatch.
                    provisioner.Journal.EndDispatch(owner, selector, session.Plan!.AssignmentId, session.Dispatch, settled);
                }
            }
            finally { Leave(session); }
        }
    }

    private async ValueTask<SecretStatus> RunStatusRoleCheck(FixtureSelector selector, ManagementOperation handle,
        CancellationToken cancellationToken)
    {
        Session session;
        bool canceled;
        lock (gate)
        {
            session = OpenSelector(selector);
            canceled = !session.CancelClaimed;
            Require(session.StartFinished && session.StartSucceeded && session.IndependentReady &&
                ReferenceEquals(handle, session.Handle) && OwnsRoleStart(session, out var start) &&
                ReferenceEquals(start, session.RoleDeleteProof) && !session.StatusClaimed &&
                (canceled ? cancellationToken.IsCancellationRequested : !cancellationToken.IsCancellationRequested &&
                    session.CancelFinished && OwnsRoleCancel(session)));
            RequireOpenJournal(session, provisioner.Journal.Read(owner, selector), selected: true);
            provisioner.Journal.AdmitStatusRead(owner, selector, session.Plan!.LeaseId,
                session.Plan.AssignmentId, session.Dispatch);
            if (canceled) session.CancelClaimed = true;
            else session.StatusClaimed = true;
            session.Active++;
            active++;
        }
        try
        {
            Require(time.GetUtcNow() >= session.IndependentAt);
            using var deadline = new CancellationTokenSource(limits.NativeTimeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            if (canceled)
            {
                try
                {
                    return await capture.CheckCanceledStatusAsync(session.Capture!, selector, handle, linked.Token,
                        task => { lock (gate) session.CanceledTask = task; }).ConfigureAwait(false);
                }
                finally
                {
                    lock (gate) session.CancelFinished = OwnsRoleCancel(session);
                }
            }
            Require(!linked.IsCancellationRequested);
            var status = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !linked.IsCancellationRequested &&
                    status == SecretStatus.Success && OwnsRoleStart(session, out var start) &&
                    ReferenceEquals(start, session.RoleDeleteProof) && OwnsRoleCancel(session) &&
                    capture.OwnsStatusRoleDeleteCancellationCompletion(session.Capture!, session.Binding!, session.Client!,
                        session.ActualScope!, session.Receipt!, session.StartTask!, handle, session.CanceledTask!, session.StatusTask!) &&
                    session.RoleBaseline is { } baseline && session.RoleAfter is { } afterRead &&
                    session.BaselineTask is { IsCompletedSuccessfully: true } &&
                    session.AfterTask is { IsCompletedSuccessfully: true } &&
                    provisioner.OwnsStatusRoleDeleteRead(baseline, session.Plan!, session.Subscription, Guid.Empty) &&
                    provisioner.OwnsStatusRoleDeleteRead(afterRead, session.Plan!, session.Subscription, session.Dispatch));
                var candidate = new StatusRoleDeleteCancellationSettlement(this, session.Dispatch);
                var frozen = new StatusRoleCompletion(owner, selector, session.Plan!.LeaseId, session.Dispatch,
                    session.Plan.AssignmentId, session.BaselineRows!.ToArray(), session.RoleBaseline!, session.RoleAfter!,
                    session.BaselineTask!, session.AfterTask!, session.StartTask!, session.CanceledTask!, session.StatusTask!,
                    linked.Token, cancellationToken);
                Require(statusRoleSettlements.TryAdd(candidate, frozen));
                provisioner.Journal.CompleteStatusRoleDeleteCancellationRead(owner, selector, session.Plan.LeaseId,
                    session.Dispatch, candidate);
                session.StatusSucceeded = true;
            }
            return status;
        }
        finally
        {
            try
            {
                if (!session.StatusSucceeded)
                    provisioner.Journal.EndDispatch(owner, selector, session.Plan!.AssignmentId,
                        session.Dispatch, nativeSettled: false);
            }
            finally { Leave(session); }
        }
    }

    private async Task<HttpResponseMessage> ObserveIndependent(ObserveLease input, CancellationToken token,
        CancellationToken callerToken)
    {
        Session session;
        bool baseline = input.Phase == "baseline-before-dispatch";
        RoleFixtureJournal.Snapshot expected;
        lock (gate)
        {
            Require(!cleanupOnly);
            session = Find(input.Nonce, input.LeaseId);
            Require(session.Armed && input.SubscriptionId == session.Subscription && !session.IndependentInvalid);
            if (baseline)
            {
                Require(!session.BaselineClaimed && !session.StartClaimed);
                session.BaselineClaimed = true;
                expected = session.IndependentReadySnapshot!;
            }
            else
            {
                Require(input.Phase == "selected-state" && !session.AfterClaimed && session.StartFinished &&
                    session.StartSucceeded && OwnsIndependentStart(session, out _));
                session.AfterClaimed = true;
                expected = session.IndependentDrained!;
            }
            session.IndependentTokens.Add(token);
            session.IndependentTokens.Add(callerToken);
            session.Active++;
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            RequireIndependentSnapshot(session, expected);
            var task = provisioner.ObserveStatusRoleDeleteIndependentAsync(session.Plan!,
                baseline ? Guid.Empty : session.Dispatch, linked.Token).AsTask();
            lock (gate)
            {
                session.IndependentTokens.Add(linked.Token);
                if (baseline) session.IndependentBaselineTask = task;
                else session.IndependentAfterTask = task;
            }
            var read = await task.ConfigureAwait(false);
            Require(provisioner.OwnsStatusRoleDeleteIndependentRead(read, session.Plan!, session.Subscription,
                baseline ? Guid.Empty : session.Dispatch) && read.ArmedAt == session.ArmedAt &&
                read.Reader.Label == resourceIdentity && read.StartedAt >= session.ArmedAt &&
                read.FinishedAt >= read.StartedAt && (baseline
                    ? read.HttpStatus == 200 && read.NativeTask.IsCompletedSuccessfully && read.Metadata is not null
                    : read.HttpStatus == 404 && read.NativeTask.IsFaulted && read.Metadata is null &&
                        read.NativeError is { Status: 404, ErrorCode: "ResourceNotFound" } && read.StartedAt >= session.StartedAt));
            RequireIndependentSnapshot(session, expected);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !session.IndependentInvalid &&
                    session.IndependentTokens.All(t => !t.IsCancellationRequested));
                if (baseline)
                {
                    session.IndependentBaseline = read;
                    session.BaselineAt = read.FinishedAt;
                    session.BaselineReady = true;
                }
                else
                {
                    Require(OwnsIndependentStart(session, out var start));
                    session.IndependentStart = start;
                    session.IndependentAfter = read;
                    session.IndependentAt = read.FinishedAt;
                    session.IndependentReady = true;
                }
                return Reply(Project(session, read.FinishedAt, baseline ? NativeProvisioningState.Unknown :
                    NativeProvisioningState.Succeeded, baseline ? SecretStatus.Success : SecretStatus.Absent));
            }
        }
        catch
        {
            lock (gate) InvalidateIndependent(session);
            throw;
        }
        finally { LeaveSession(session); }
    }

    private bool OwnsIndependentStart(Session session,
        [NotNullWhen(true)] out C.StatusRoleDeleteIndependentStartProof? proof)
    {
        proof = null;
        return session.Client is { } client && session.ActualScope is { } actual && session.Receipt is { } receipt &&
            session.StartTask is { } start && session.Handle is { } handle &&
            capture.TryGetStatusRoleDeleteIndependentStart(session.Capture!, session.Binding!, client, actual,
                receipt, start, handle, out proof);
    }

    private void RequireIndependentSnapshot(Session session, RoleFixtureJournal.Snapshot expected)
    {
        try
        {
            Require(!session.IndependentInvalid && session.IndependentTokens.All(t => !t.IsCancellationRequested) &&
                RoleFixtureJournal.SameStatusRoleDeleteIndependentSnapshot(expected,
                    provisioner.Journal.Read(owner, session.Selector)));
        }
        catch
        {
            lock (gate) InvalidateIndependent(session);
            throw;
        }
    }

    private async ValueTask<SecretOutcome<ManagementOperation>> StartIndependent(FixtureSelector selector,
        VaultAdministration client, ManagementScope originalScope, ManagementMutation operation,
        E.Input input, ManagementReceipt receipt, CancellationToken callerToken)
    {
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(!session.IndependentInvalid && client is not null && receipt is not null &&
                receipt.Evidence == DispatchEvidence.NotDispatched &&
                originalScope is RoleAssignmentScope { Parent: VaultScope vault } role &&
                vault.ExportResourceId() == session.Plan!.VaultId && role.AssignmentId == AssignmentId(session.Plan) &&
                operation == ManagementMutation.DeleteRoleAssignment && session.Armed && session.BaselineReady &&
                !session.StartClaimed && InputMatches(session, input) && session.IndependentBaseline is not null &&
                session.IndependentBaselineTask is { IsCompletedSuccessfully: true });
            session.StartClaimed = true;
            session.Client = client;
            session.ActualScope = (RoleAssignmentScope)originalScope;
            session.Receipt = receipt;
            session.IndependentTokens.AddRange([callerToken, lifetime.Token, session.Stop.Token]);
            var admission = new StatusRoleDeleteIndependentAdmission(this);
            IssueIndependent(session, admission, IndependentStage.Begin, session.IndependentReadySnapshot!, session.IndependentBaselineTask!);
            var committed = provisioner.Journal.BeginStatusRoleDeleteIndependentInvocation(owner, selector,
                session.Plan!.LeaseId, admission);
            session.IndependentBegin = FreezeIndependent(committed);
            session.Dispatch = committed.Resources.Single(r => r.Id == session.Plan.AssignmentId).ActiveDispatch;
            session.Active++;
            active++;
        }
        try
        {
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineAt);
            using var deadline = new CancellationTokenSource(limits.NativeTimeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(callerToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            lock (gate) session.IndependentTokens.Add(linked.Token);
            RequireIndependentSnapshot(session, session.IndependentBegin!);
            var result = await capture.StartRoleDeleteIndependentAsync(session.Capture!, selector, client,
                session.ActualScope!, input, receipt, linked.Token,
                task => { lock (gate) session.StartTask = task; },
                () => RequireIndependentSnapshot(session, session.IndependentBegin!)).ConfigureAwait(false);
            lock (gate)
            {
                session.Handle = result.IsSuccess ? result.Value : null;
                session.StartSucceeded = result.IsSuccess && session.StartTask is { IsCompletedSuccessfully: true } &&
                    OwnsIndependentStart(session, out _);
            }
            return result;
        }
        finally
        {
            try
            {
                lock (gate)
                {
                    if (session.StartSucceeded && !session.IndependentInvalid && !session.Closed &&
                        session.IndependentTokens.All(t => !t.IsCancellationRequested))
                    {
                        var candidate = new StatusRoleDeleteIndependentStartDrain(this);
                        IssueIndependent(session, candidate, IndependentStage.StartDrain, session.IndependentBegin!,
                            session.IndependentBaselineTask!, session.StartTask!);
                        session.IndependentStartDrain = candidate;
                    }
                }
                if (session.IndependentStartDrain is not null) PersistIndependent(session, final: false);
                else DrainIndependent(session);
            }
            finally { Leave(session); }
        }
    }

    private async ValueTask<SecretStatus> CheckIndependent(FixtureSelector selector, ManagementOperation handle,
        CancellationToken callerToken)
    {
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            // A foreign handle cannot consume the original handle's one-use slot.
            Require(ReferenceEquals(handle, session.Handle));
            bool valid = !session.StatusClaimed && !session.IndependentInvalid && session.StartFinished &&
                session.StartSucceeded && session.IndependentAfter is not null &&
                session.IndependentAfterTask is { IsCompletedSuccessfully: true } &&
                !callerToken.IsCancellationRequested && session.IndependentTokens.All(t => !t.IsCancellationRequested) &&
                OwnsIndependentStart(session, out var start) && ReferenceEquals(start, session.IndependentStart);
            session.StatusClaimed = true;
            if (!valid) InvalidateIndependent(session);
            Require(valid);
            session.IndependentTokens.Add(callerToken);
            var admission = new StatusRoleDeleteIndependentReadAdmission(this);
            IssueIndependent(session, admission, IndependentStage.Read, session.IndependentDrained!,
                session.IndependentBaselineTask!, session.StartTask!, session.IndependentAfterTask!);
            var committed = provisioner.Journal.AdmitStatusRoleDeleteIndependentRead(owner, selector, session.Plan!.LeaseId,
                session.Dispatch, admission);
            session.IndependentRead = FreezeIndependent(committed);
            session.Active++;
            active++;
        }
        try
        {
            Require(time.GetUtcNow() >= session.IndependentAt);
            using var deadline = new CancellationTokenSource(limits.NativeTimeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(callerToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            lock (gate) session.IndependentTokens.Add(linked.Token);
            RequireIndependentSnapshot(session, session.IndependentRead!);
            var status = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            lock (gate)
            {
                Require(status == SecretStatus.Success && !session.Closed && !disposed && !session.IndependentInvalid &&
                    session.IndependentTokens.All(t => !t.IsCancellationRequested) &&
                    capture.TryGetStatusRoleDeleteIndependentCompletion(session.Capture!, session.Binding!, session.Client!,
                        session.ActualScope!, session.Receipt!, session.StartTask!, handle, session.StatusTask!, out var completed) &&
                    ReferenceEquals(completed.Start, session.IndependentStart) &&
                    provisioner.OwnsStatusRoleDeleteIndependentRead(session.IndependentBaseline!, session.Plan!, session.Subscription, Guid.Empty) &&
                    provisioner.OwnsStatusRoleDeleteIndependentRead(session.IndependentAfter!, session.Plan!, session.Subscription, session.Dispatch));
                var candidate = new StatusRoleDeleteIndependentSettlement(this);
                IssueIndependent(session, candidate, IndependentStage.Complete, session.IndependentRead!,
                    session.IndependentBaselineTask!, session.IndependentAfterTask!, session.StartTask!, session.StatusTask!);
                session.IndependentSettlement = candidate;
            }
            PersistIndependent(session, final: true);
            return status;
        }
        finally
        {
            try
            {
                // A valid retained append candidate must not be destroyed by a
                // generic drain append when local persistence alone failed.
                if (session.IndependentSettlement is null || session.IndependentInvalid) DrainIndependent(session);
            }
            finally { Leave(session); }
        }
    }

    internal void RetryStatusRoleDeleteIndependentPersistence(FixtureSelector selector)
    {
        Session session;
        lock (gate)
        {
            Require(independentProfile && !cleanupOnly);
            session = OpenSelector(selector);
            Require(session.Active == 0 && !session.IndependentInvalid &&
                (session.IndependentSettlement is not null || session.IndependentStartDrain is not null));
            session.Active++;
            active++;
        }
        try { PersistIndependent(session, session.IndependentSettlement is not null); }
        finally { Leave(session); }
    }

    private void PersistIndependent(Session session, bool final)
    {
        lock (gate)
            if (session.IndependentTokens.Any(t => t.IsCancellationRequested))
                InvalidateIndependent(session);
        try
        {
            var committed = final
                ? provisioner.Journal.CompleteStatusRoleDeleteIndependentRead(owner, session.Selector, session.Plan!.LeaseId,
                    session.Dispatch, session.IndependentSettlement!)
                : provisioner.Journal.EndStatusRoleDeleteIndependentStart(owner, session.Selector, session.Plan!.LeaseId,
                    session.Dispatch, session.IndependentStartDrain!);
            lock (gate)
            {
                if (final) session.StatusSucceeded = true;
                else
                {
                    session.IndependentDrained = FreezeIndependent(committed);
                    session.StartFinished = true;
                }
            }
        }
        catch (RoleFixtureJournal.StatusRoleDeleteIndependentHistoryException)
        {
            lock (gate) InvalidateIndependent(session);
            throw;
        }
        catch
        {
            RoleFixtureJournal.Snapshot current;
            try { current = provisioner.Journal.Read(owner, session.Selector); }
            catch (RoleFixtureJournal.StatusRoleDeleteIndependentHistoryException)
            { lock (gate) InvalidateIndependent(session); throw; }
            bool valid = final
                ? session.IndependentSettlement!.Validate(provisioner.Journal, current) ||
                    session.IndependentSettlement.AcceptPostimage(provisioner.Journal, current)
                : session.IndependentStartDrain!.Validate(provisioner.Journal, current) ||
                    session.IndependentStartDrain.AcceptPostimage(provisioner.Journal, current);
            if (!valid)
            {
                lock (gate) InvalidateIndependent(session);
                DrainIndependent(session);
            }
            throw;
        }
    }

    private void DrainIndependent(Session session)
    {
        // Called only after capture has joined its real invocation/finalizers.
        if (session.Dispatch == Guid.Empty) return;
        var snapshot = provisioner.Journal.Read(owner, session.Selector);
        var row = snapshot.Resources.Single(r => r.Id == session.Plan!.AssignmentId);
        if (row.ActiveDispatch == session.Dispatch && !row.InvocationTerminated)
            provisioner.Journal.EndDispatch(owner, session.Selector, row.Id, session.Dispatch, nativeSettled: false);
    }

    private bool OwnsRoleCancel(Session session) =>
        session.CanceledTask is { IsCanceled: true } task &&
        capture.OwnsRoleDeleteCanceledStatusAttempt(session.Capture!, session.Binding!, session.Client!,
            session.ActualScope!, session.Receipt!, session.StartTask!, session.Handle!, task);

    private async Task<HttpResponseMessage> Release(FixtureSelector selector, CancellationToken token, CancellationToken callerToken)
    {
        ValidateReleaseSelector(selector);
        if (independentProfile) Require(RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector));
        else Require(!RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector));
        Session session;
        RoleFixtureJournal.Snapshot snapshot;
        lock (gate)
        {
            Require(!disposed);
            if (!sessions.TryGetValue(selector.Nonce, out session!))
            {
                Require(sessions.Count < 32);
                session = new(selector with { });
                sessions.Add(selector.Nonce, session);
            }
            Require(session.Selector == selector);
            // Validate the original topology under the same durable journal lock
            // as Close, before any cancellation can end admitted work.
            snapshot = provisioner.Journal.Close(owner, selector, state =>
            {
                RequireTopology(selector, state, session.Plan);
                return true;
            });
            session.Closed = true;
            if (independentProfile) InvalidateIndependent(session);
        }
        session.Stop.Cancel();
        lock (gate)
        {
            if (session.Active != 0 || session.Releasing)
                return Reply(ReleaseMeasurement(session, snapshot, session.Releasing ? 1 : 0));
            session.Releasing = true;
        }
        try
        {
            if (session.Capture is not null) await capture.SealAsync(session.Capture).ConfigureAwait(false);
            snapshot = provisioner.Journal.Read(owner, selector);
            RequireTopology(selector, snapshot, session.Plan);
            if (snapshot.Resources.Length == 0) return Reply(ReleaseMeasurement(session, snapshot));
            // Only this process's retained original plan can recover actual
            // termination after a contended journal write. No receipt, handle or
            // service proof is reconstructed from persisted coordinates.
            if (session.Plan is { } plan && plan.Receipts.Any(r => r.Attempted && r.Terminated))
                snapshot = (await provisioner.SettleAsync(plan, token).ConfigureAwait(false)).Journal ?? throw Failure();
            if (snapshot.Resources.Any(r => r.ActiveDispatch != Guid.Empty))
                return Reply(ReleaseMeasurement(session, snapshot));
            snapshot = (await provisioner.ReleaseAsync(owner, selector, purge: true,
                cancellationToken: token, originalCallerToken: independentProfile ? callerToken : null).ConfigureAwait(false)).Journal ?? throw Failure();
            RequireTopology(selector, snapshot, session.Plan);
            return Reply(ReleaseMeasurement(session, snapshot));
        }
        finally { lock (gate) session.Releasing = false; }
    }

    private void RequireTopology(FixtureSelector selector, RoleFixtureJournal.Snapshot snapshot,
        RoleFixtureProvisioner.Plan? original)
    {
        Require(snapshot.Owner == owner && snapshot.Selector == selector);
        if (snapshot.Resources.Length == 0)
        {
            Require(original is null && snapshot.Closing && snapshot.LeaseId == Guid.Empty);
            return;
        }
        Require(snapshot.LeaseId != Guid.Empty && snapshot.Resources.Length == 5 &&
            snapshot.Resources.Count(r => r.Borrowed) == 1 &&
            snapshot.Resources.Single(r => r.Borrowed) is
            {
                CleanupOnly: false, CreateAttempted: false,
                DeleteAttempted: false, SelectedAttempted: false, ActiveDispatch: var borrowedDispatch
            } borrowed &&
            borrowedDispatch == Guid.Empty && borrowed.Id == DefinitionId);
        var owned = snapshot.Resources.Where(r => !r.Borrowed).ToArray();
        string prefix = $"/subscriptions/{scope.SubscriptionId:D}/resourceGroups/{scope.ResourceGroup}/providers/Microsoft.KeyVault/vaults/";
        var vault = owned.Single(r => r.Id.StartsWith(prefix, StringComparison.Ordinal) &&
            !r.Id[prefix.Length..].Contains('/'));
        string name = vault.Id[prefix.Length..];
        Require(name.Length == 24 && name.StartsWith("sk", StringComparison.Ordinal) &&
            name[2..].All(char.IsAsciiHexDigit) && !vault.CleanupOnly &&
            owned.Single(r => r.Id == vault.Id + "/secrets/" + RoleFixtureProvisioner.Canary) is { CleanupOnly: false } &&
            owned.Single(r => r.Id == DeletedId(name)) is { CleanupOnly: true } &&
            owned.Count(r => r.CleanupOnly) == 1);
        string assignmentPrefix = vault.Id + "/providers/Microsoft.Authorization/roleAssignments/";
        var assignment = owned.Single(r => r.Id.StartsWith(assignmentPrefix, StringComparison.Ordinal));
        Require(!assignment.CleanupOnly && Guid.TryParseExact(assignment.Id[assignmentPrefix.Length..], "D", out var id) &&
            id != Guid.Empty);
        if (original is not null)
            Require(original.Owner == owner && original.Selector == selector && original.LeaseId == snapshot.LeaseId &&
                original.CreateAssignment && original.VaultId == vault.Id && original.AssignmentId == assignment.Id &&
                original.SecretId == vault.Id + "/secrets/" + RoleFixtureProvisioner.Canary);
    }

    private void RequireOpenJournal(Session session, RoleFixtureJournal.Snapshot snapshot, bool selected,
        bool invocationTerminated = true)
    {
        var plan = session.Plan!;
        Require(plan is not null && plan.Consumed == 1);
        RequireTopology(session.Selector, snapshot, plan);
        Require(!snapshot.Closing &&
            snapshot.Resources.Where(r => !r.Borrowed && !r.CleanupOnly).All(r => r.CreateAttempted && !r.DeleteAttempted && !r.Absent) &&
            snapshot.Resources.Single(r => r.CleanupOnly) is { CreateAttempted: false, DeleteAttempted: false, SelectedAttempted: false } &&
            snapshot.Resources.Single(r => r.Id == plan.AssignmentId) is { } assignment &&
            assignment.SelectedAttempted == selected &&
            (selected ? session.Dispatch != Guid.Empty && assignment.ActiveDispatch == session.Dispatch &&
                assignment.InvocationTerminated == invocationTerminated : assignment.ActiveDispatch == Guid.Empty) &&
            snapshot.Resources.Where(r => r.Id != plan.AssignmentId).All(r => r.ActiveDispatch == Guid.Empty && !r.SelectedAttempted));
    }

    private bool OwnsDeleteProof(Session session, C.SynchronousDeleteProof proof) =>
        session.Client is { } client && session.ActualScope is { } actualScope &&
        session.Receipt is { } receipt && session.Handle is { } handle &&
        session.StartSucceeded && session.StartTask is { IsCompletedSuccessfully: true } &&
        proof.Binding == session.Binding && proof.HttpStatus == 204 && proof.ResponseBytes == 0 &&
        capture.TryGetSynchronousDeleteProof(session.Capture!, session.Binding!, out var issued) &&
        ReferenceEquals(proof, issued) &&
        capture.OwnsSynchronousDeleteProof(proof, session.Binding!, client, actualScope, receipt, handle);

    private bool ResourceBound(R.Measurement measurement, Session session, R.Window window) =>
        measurement.Binding == session.Binding && measurement.WindowId == window.Id &&
        measurement.ArmedAt == window.ArmedAt && measurement.ResponseComplete &&
        measurement.Identity == resourceIdentity && measurement.ApiRevision == Revision &&
        measurement.StartedAt >= session.ArmedAt && measurement.FinishedAt >= measurement.StartedAt &&
        Text(measurement.NativeRequestId, 256);

    private static bool InputMatches(Session session, E.Input input) =>
        input is not null && session.Preparation is { } prepared &&
        input.SubscriptionId == prepared.SubscriptionId && input.ResourceGroup == prepared.ResourceGroup &&
        input.Location == prepared.Location && input.TenantId == prepared.TenantId &&
        input.Sku == prepared.Sku && input.RetentionDays == prepared.RetentionDays &&
        input.WebhookUrl == prepared.WebhookUrl &&
        input.RoleAssignmentId == prepared.RoleAssignmentId;

    private E.Measurement Project(Session session, DateTimeOffset observedAt, NativeProvisioningState state,
        SecretStatus resourceStatus) =>
        new(session.Plan!.LeaseId, session.Selector.Nonce, observerIdentity, observedAt,
            ManagementMutation.DeleteRoleAssignment, state, session.Plan.AssignmentId, resourceStatus, null, null, null);

    private Session OpenSelector(FixtureSelector selector)
    {
        ValidateSelector(selector);
        Require(sessions.TryGetValue(selector.Nonce, out var session) && session.Selector == selector);
        return Find(selector.Nonce, session.Plan?.LeaseId ?? Guid.Empty);
    }

    private Session Find(Guid nonce, Guid lease)
    {
        Require(!disposed);
        Require(sessions.TryGetValue(nonce, out var session));
        Require(!session.Closed && session.Plan is not null && session.Lease is not null && session.Plan.LeaseId == lease);
        return session;
    }

    private RoleFixtureRelease.Measurement ReleaseMeasurement(Session session, RoleFixtureJournal.Snapshot snapshot, int extra = 0)
    {
        Require(snapshot.Owner == owner && snapshot.Selector == session.Selector && snapshot.Closing);
        string[] owned = snapshot.Resources.Where(r => !r.Borrowed).Select(r => r.Id).ToArray();
        string[] absent = snapshot.Resources.Where(r => !r.Borrowed && r.Absent && r.ActiveDispatch == Guid.Empty).Select(r => r.Id).ToArray();
        return new(session.Selector, true, session.Active + extra + snapshot.Resources.Count(r => r.ActiveDispatch != Guid.Empty),
            owned, snapshot.Resources.Where(r => r.Borrowed).Select(r => r.Id).ToArray(), absent,
            owned.Except(absent, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private string DefinitionId =>
        $"/subscriptions/{scope.SubscriptionId:D}/providers/Microsoft.Authorization/roleDefinitions/{scope.IntendedRoleDefinitionId:D}";
    private string DeletedId(string name) =>
        $"/subscriptions/{scope.SubscriptionId:D}/providers/Microsoft.KeyVault/locations/{scope.Location}/deletedVaults/{name}";
    private static Guid AssignmentId(RoleFixtureProvisioner.Plan plan) =>
        Guid.Parse(plan.AssignmentId[(plan.AssignmentId.LastIndexOf('/') + 1)..]);
    private static string CanaryHash(SecretMaterial canary)
    {
        char[] characters = canary.ExportCharacters();
        byte[] bytes = Encoding.UTF8.GetBytes(characters);
        try { return Convert.ToHexString(SHA256.HashData(bytes)); }
        finally { Array.Clear(characters); CryptographicOperations.ZeroMemory(bytes); }
    }

    private void ValidateSelector(FixtureSelector selector)
    {
        ValidateReleaseSelector(selector);
        Require(!cleanupOnly);
        if (independentProfile)
        {
            Require(RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector));
            return;
        }
        Require(selector.Variant == "operation.DeleteRoleAssignment" && selector.Case == "selected-contract" ||
            RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(selector));
    }

    private static void ValidateReleaseSelector(FixtureSelector selector) =>
        Require(selector is not null && selector.Nonce != Guid.Empty &&
            new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }.All(v => Text(v, 512)) &&
            selector.Operation == E.Members[0].Operation);
    private static bool Text([NotNullWhen(true)] string? value, int maximum) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximum && !value.Any(char.IsControl);
    private static bool Segment(string? value, int maximum) => Text(value, maximum) &&
        value is not ("." or "..") && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');

    private bool Authenticate(HttpRequestMessage request)
    {
        if (request.Headers.Authorization is not { Scheme: "Bearer", Parameter: { Length: > 0 and <= 8192 } supplied }) return false;
        char[] expected = capability.ExportCharacters();
        byte[] left = Encoding.UTF8.GetBytes(expected), right = Encoding.UTF8.GetBytes(supplied);
        try { return CryptographicOperations.FixedTimeEquals(SHA256.HashData(left), SHA256.HashData(right)); }
        finally { Array.Clear(expected); CryptographicOperations.ZeroMemory(left); CryptographicOperations.ZeroMemory(right); }
    }

    private async Task<JsonDocument> ReadBody(HttpRequestMessage request, CancellationToken token)
    {
        Require(request.Content is not null);
        int headers = 0, headerBytes = 0;
        foreach (var header in request.Headers.Concat(request.Content.Headers))
            foreach (string value in header.Value)
            {
                Require(++headers <= 64 && Text(header.Key, 128) && Text(value, 8192));
                headerBytes += Encoding.UTF8.GetByteCount(header.Key) + Encoding.UTF8.GetByteCount(value);
                Require(headerBytes <= 16384);
            }
        Require(request.Content.Headers.ContentLength is >= 0 &&
            request.Content.Headers.ContentLength <= limits.MaximumRequestBytes &&
            request.Content.Headers.ContentType?.MediaType == "application/json" &&
            request.Content.Headers.ContentEncoding.Count == 0);
        byte[] bytes = new byte[limits.MaximumRequestBytes + 1];
        try
        {
            var stream = await request.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            int length = 0, count;
            while (length < bytes.Length && (count = await stream.ReadAsync(bytes.AsMemory(length), token).ConfigureAwait(false)) != 0)
                length += count;
            Require(length <= limits.MaximumRequestBytes && length == request.Content.Headers.ContentLength);
            var reader = new Utf8JsonReader(bytes.AsSpan(0, length), new JsonReaderOptions { MaxDepth = 32 });
            var document = JsonDocument.ParseValue(ref reader);
            try { Require(!reader.Read()); Unique(document.RootElement); return document; }
            catch { document.Dispose(); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void Unique(JsonElement node)
    {
        if (node.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in node.EnumerateObject()) { Require(names.Add(property.Name)); Unique(property.Value); }
        }
        else if (node.ValueKind == JsonValueKind.Array)
            foreach (var item in node.EnumerateArray()) Unique(item);
    }

    private HttpResponseMessage Reply<T>(T value)
    {
        byte[] bytes = new byte[limits.MaximumReplyBytes];
        try
        {
            using var stream = new MemoryStream(bytes, 0, bytes.Length, writable: true);
            JsonSerializer.Serialize(stream, value, ManagementAdmission.Json);
            return new(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(bytes.AsSpan(0, checked((int)stream.Position)).ToArray())
                { Headers = { ContentType = new("application/json") } }
            };
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static HttpResponseMessage Error(HttpStatusCode status) => new(status)
    {
        Content = new StringContent("{\"error\":\"role-operation-source-unavailable\"}", Encoding.UTF8, "application/json")
    };
    private void LeaveSession(Session session) { lock (gate) session.Active--; }
    private void Leave(Session? session)
    {
        lock (gate)
        {
            if (session is not null) session.Active--;
            if (--active == 0 && disposed) drained.TrySetResult();
        }
    }

    public ValueTask DisposeAsync()
    {
        TaskCompletionSource completion;
        lock (gate)
        {
            if (disposal is not null) return new(disposal.Task);
            disposed = true;
            completion = disposal = new(TaskCreationOptions.RunContinuationsAsynchronously);
            if (active == 0) drained.TrySetResult();
        }
        _ = Drain(completion);
        return new(completion.Task);
    }

    private async Task Drain(TaskCompletionSource completion)
    {
        bool valid = true;
        Session[] owned;
        lock (gate)
        {
            owned = sessions.Values.ToArray();
            foreach (var session in owned)
            {
                session.Closed = true;
                if (independentProfile) InvalidateIndependent(session);
                try
                {
                    provisioner.Journal.Close(owner, session.Selector, snapshot =>
                    {
                        RequireTopology(session.Selector, snapshot, session.Plan);
                        return true;
                    });
                }
                catch (Exception) { valid = false; }
            }
        }
        foreach (var session in owned)
            try { session.Stop.Cancel(); }
            catch (Exception) { valid = false; }
        try { lifetime.Cancel(); }
        catch (Exception) { valid = false; }
        try
        {
            await drained.Task.ConfigureAwait(false);
            foreach (var session in owned)
            {
                try { if (session.Capture is not null) await capture.SealAsync(session.Capture).ConfigureAwait(false); }
                catch (Exception) { valid = false; }
                finally
                {
                    session.Canary?.Dispose();
                    session.Stop.Dispose();
                }
            }
            lifetime.Dispose();
            Require(valid);
            completion.TrySetResult();
        }
        catch (Exception) { completion.TrySetException(Failure()); }
    }

    private static void Require([DoesNotReturnIf(false)] bool condition) { if (!condition) throw Failure(); }
    private static InvalidOperationException Failure() => new("role-operation-source-unavailable");
    public override string ToString() => "[RoleManagementOperationFixtureObserverService]";
}
