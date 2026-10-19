using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;
using EP = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.PrivateEndpointFixtureProvisioner;
using ER = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.PrivateEndpointResourceCollector;
using J = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.RoleFixtureJournal;
using M = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationCollector;
using N = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultNetworkReadCollector;
using P = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureProvisioner;
using V = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal sealed partial class ManagementOperationFixtureObserverService
{
    internal sealed record PrivateConnectionUpdateSource(
        [property: JsonIgnore] P Provisioner,
        [property: JsonIgnore] PrivateConnectionSource Endpoint,
        [property: JsonIgnore] N.Authority PrivateRuntime,
        [property: JsonIgnore] N.Authority PublicRuntime,
        [property: JsonIgnore] N.Limits NetworkLimits,
        [property: JsonIgnore] HttpPipelineTransport SelectedBackend)
    {
        public override string ToString() => "[PrivateConnectionUpdateSource]";
    }

    private readonly PrivateConnectionUpdateSource? privateUpdateSource;
    private readonly string? privateUpdateConfiguration;
    private readonly Dictionary<Guid, PrivateConnectionUpdateSession> privateUpdateSessions = [];

    internal ManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, P.HostScope scope, PrivateConnectionUpdateSource source, Limits limits,
        TimeProvider? time = null)
        : this(origin, owner, observerIdentity, capability, scope, source.Provisioner, limits, time)
    {
        Require(source.Endpoint is not null && source.SelectedBackend is not null &&
            source.PrivateRuntime is { Credential: not null, Transport: not null } &&
            source.PublicRuntime is { Credential: not null, Transport: not null } && source.NetworkLimits is not null);
        var endpoint = source.Endpoint;
        _ = new EP(provisioner, endpoint.EndpointSetup, endpoint.EndpointReader, endpoint.VaultConnectionReader,
            endpoint.ResourceLimits, endpoint.InventoryLimits, this.time);
        _ = new N(source.PrivateRuntime, source.PublicRuntime, source.NetworkLimits, this.time);
        var baseline = provisioner.VaultReadBaseline(scope, endpoint.VaultConnectionReader, source.SelectedBackend);
        foreach (var authority in new M.Authority[]
        {
            new(endpoint.EndpointSetup.Label, endpoint.EndpointSetup.Credential, endpoint.EndpointSetup.Transport),
            new(endpoint.EndpointReader.Label, endpoint.EndpointReader.Credential, endpoint.EndpointReader.Transport),
            new(source.PrivateRuntime.Label, source.PrivateRuntime.Credential, source.PrivateRuntime.Transport),
            new(source.PublicRuntime.Label, source.PublicRuntime.Credential, source.PublicRuntime.Transport)
        })
            _ = provisioner.VaultReadBaseline(scope, authority, source.SelectedBackend);
        Require(baseline.PublicNetworkAccess && !baseline.PurgeProtection && Text(endpoint.BorrowedSubnetId, 2048));
        privateUpdateConfiguration = EncodeDeleteConfiguration(baseline);
        privateUpdateSource = source;
        privateConnectionSource = endpoint;
        profile = Profile.OriginalPrivateConnectionUpdate;
        nativeCapture = new(source.SelectedBackend, limits.MaximumReplyBytes);
    }

    internal static ManagementOperationFixtureObserverService ForPrivateConnectionUpdateCleanup(Uri origin,
        string owner, string observerIdentity, SecretMaterial capability, P.HostScope scope, P provisioner,
        PrivateConnectionSource endpoint, Limits limits, TimeProvider? time = null)
    {
        return new(origin, owner, observerIdentity, capability, scope, provisioner, endpoint, limits, time);
    }

    private ManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, P.HostScope scope, P provisioner, PrivateConnectionSource endpoint,
        Limits limits, TimeProvider? time)
        : this(origin, owner, observerIdentity, capability, scope, provisioner, limits, time)
    {
        Require(endpoint is not null);
        _ = new EP(provisioner, endpoint.EndpointSetup, endpoint.EndpointReader, endpoint.VaultConnectionReader,
            endpoint.ResourceLimits, endpoint.InventoryLimits, this.time);
        privateConnectionSource = endpoint;
        profile = Profile.PrivateConnectionUpdateCleanup;
    }

    private V.Configuration PrivateUpdateBaseline() =>
        JsonSerializer.Deserialize<V.Configuration>(privateUpdateConfiguration ?? throw Failure(), Json) ?? throw Failure();

    private sealed class PrivateConnectionUpdateSession(FixtureSelector selector) : OriginalVaultSession(selector)
    {
        internal P.Plan? Plan;
        internal EP? Endpoints;
        internal EP.Plan? EndpointPlan;
        internal P.PrivateConnectionUpdateLoan? Loan;
        internal V.Lease? Lease;
        internal string? ConnectionId;
        internal Guid Subscription, Dispatch;
        internal DateTimeOffset ArmedAt, StartedAt;
        internal bool Armed, BaselineClaimed, StartClaimed, StartFinished, PostClaimed, CheckClaimed;
        internal bool StartValid, Canceled, TerminationPersisted, Settled;
        internal PrivateConnectionState Requested;
        internal PrivateUpdatePhase? Baseline, Post;
        internal PrivateUpdateRoot? Root;
        internal PrivateConnectionUpdateAdmission? Admission;
        internal PrivateConnectionUpdateTermination? Termination;
        internal PrivateConnectionUpdateSettlement? Settlement;
        internal PrivateUpdateFinished? Finished;
        internal J.PrivateConnectionUpdateDisposition Disposition;
        internal VaultAdministration? Client;
        internal PrivateConnectionScope? Scope;
        internal ManagementReceipt? Receipt;
        internal ManagementOperation? Handle;
        internal SecretStatus? Outcome;
        internal C.Binding? Binding;
        internal C.Window? Window;
        internal C.PrivateConnectionUpdateStart? Native;
        internal Task? StartTask, CheckTask, Finalization;
        internal V.Measurement? Measurement;
        internal readonly List<PrivateUpdateReadTransport> Reads = [];
    }

    private sealed record PrivateUpdateRoot(J Journal, string Owner, FixtureSelector Selector, Guid Lease,
        string VaultId, string DeletedId, string ConnectionId, J.PrivateEndpointDeclaration Endpoint, string Configuration);
    private sealed record PrivateUpdatePhase(P.PrivateConnectionUpdateLoan Loan,
        Task<P.PrivateConnectionUpdateWitness> ParentTask, P.PrivateConnectionUpdateWitness Parent,
        M.Binding ChildBinding, M.Window ChildWindow, Task<M.Measurement> ChildTask, M.Measurement Child,
        ER.Binding EndpointBinding, ER.Window EndpointWindow, Task<ER.Measurement> EndpointTask, ER.Measurement Endpoint,
        N.Binding NetworkBinding, N.Window NetworkWindow, Task<N.Measurement> NetworkTask, N.Measurement Network,
        string ChildDigest, DateTimeOffset FinishedAt);
    private sealed record PrivateUpdateAdmissionEvidence(PrivateUpdateRoot Root, PrivateUpdatePhase Baseline,
        P.Plan Parent, EP Endpoints, EP.Plan EndpointPlan);
    private sealed record PrivateUpdateFinished(PrivateUpdateAdmissionEvidence Admission, Guid Dispatch,
        PrivateUpdatePhase Post, VaultAdministration Client, PrivateConnectionScope Scope, PrivateConnectionState Requested,
        ManagementReceipt Receipt, ManagementOperation? Handle, Task StartTask, Task? CheckTask,
        C.Binding Binding, C.Window Window, C.PrivateConnectionUpdateStart Native,
        J.PrivateConnectionUpdateDisposition Disposition);
    private readonly ConcurrentDictionary<PrivateConnectionUpdateAdmission, PrivateUpdateAdmissionEvidence> privateUpdateAdmissions =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<PrivateConnectionUpdateTermination, PrivateUpdateFinished> privateUpdateTerminations =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<PrivateConnectionUpdateSettlement, PrivateUpdateFinished> privateUpdateSettlements =
        new(ReferenceEqualityComparer.Instance);

    internal sealed class PrivateConnectionUpdateAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(J journal, J.Snapshot snapshot) =>
            source.privateUpdateAdmissions.TryGetValue(this, out var evidence) &&
            PrivateUpdateRootMatches(journal, snapshot, evidence.Root);
        public override string ToString() => "[PrivateConnectionUpdateAdmission]";
    }
    internal sealed class PrivateConnectionUpdateTermination(ManagementOperationFixtureObserverService source, Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(J journal, J.Snapshot snapshot) =>
            source.privateUpdateTerminations.TryGetValue(this, out var evidence) && evidence.Dispatch == Dispatch &&
            Dispatch != Guid.Empty && PrivateUpdateRootMatches(journal, snapshot, evidence.Admission.Root);
        public override string ToString() => "[PrivateConnectionUpdateTermination]";
    }
    internal sealed class PrivateConnectionUpdateSettlement(ManagementOperationFixtureObserverService source, Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal J.PrivateConnectionUpdateDisposition Disposition =>
            source.privateUpdateSettlements.TryGetValue(this, out var evidence) ? evidence.Disposition : throw Failure();
        internal bool Validate(J journal, J.Snapshot snapshot) =>
            source.privateUpdateSettlements.TryGetValue(this, out var evidence) && evidence.Dispatch == Dispatch &&
            Dispatch != Guid.Empty && evidence.Disposition != J.PrivateConnectionUpdateDisposition.None &&
            PrivateUpdateRootMatches(journal, snapshot, evidence.Admission.Root);
        public override string ToString() => "[PrivateConnectionUpdateSettlement]";
    }

    // Journal callbacks read only immutable private registrations. They never
    // acquire service/parent/native locks or consult clocks and host resources.
    private static bool PrivateUpdateRootMatches(J journal, J.Snapshot snapshot, PrivateUpdateRoot root) =>
        ReferenceEquals(journal, root.Journal) && snapshot.Owner == root.Owner && snapshot.Selector == root.Selector &&
        snapshot.LeaseId == root.Lease && snapshot.Settings is null && snapshot.DeleteVault is null &&
        snapshot.PurgeDeletedVault is null && snapshot.CreateOrUpdateVault is null && snapshot.RecoverVault is null &&
        snapshot.PrivateEndpoint is { OriginalUpdate: { } update } slot &&
        slot.Declaration == root.Endpoint && slot.Connection?.Id == root.ConnectionId &&
        slot.ApprovalSettledDispatch == Guid.Empty && EncodeDeleteConfiguration(update.Baseline) == root.Configuration &&
        update.Requested == Enum.Parse<PrivateConnectionState>(root.Selector.Variant.Split('.')[1]) &&
        snapshot.Resources.Length == 5 &&
        snapshot.Resources.Count(r => r.Id == root.VaultId && !r.Borrowed && !r.CleanupOnly) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.VaultId + "/secrets/" + P.Canary && !r.Borrowed && !r.CleanupOnly) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.DeletedId && !r.Borrowed && r.CleanupOnly &&
            !r.CreateAttempted && !r.SelectedAttempted) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.Endpoint.EndpointId && !r.Borrowed && !r.CleanupOnly) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.Endpoint.BorrowedSubnetId && r.Borrowed) == 1;

    private static void ValidatePrivateUpdateSelector(FixtureSelector selector) =>
        Require(selector is not null && selector.Nonce != Guid.Empty && P.PrivateConnectionUpdateSelector(selector) &&
            new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }.All(v => Text(v, 512)));

    private Task<HttpResponseMessage> DispatchPrivateConnectionUpdate(string path, JsonElement body, CancellationToken token) =>
        path switch
        {
            "/vault/prepare" when profile == Profile.OriginalPrivateConnectionUpdate =>
                PreparePrivateConnectionUpdate(body.Deserialize<V.Prepare>(Json) ?? throw Failure(), token),
            "/vault/arm" when profile == Profile.OriginalPrivateConnectionUpdate =>
                Task.FromResult(ArmPrivateConnectionUpdate(body.Deserialize<ObserveLease>(Json) ?? throw Failure())),
            "/vault/observe" when profile == Profile.OriginalPrivateConnectionUpdate =>
                ObservePrivateConnectionUpdate(body.Deserialize<ObserveLease>(Json) ?? throw Failure(), token),
            "/vault/release" => ReleasePrivateConnectionUpdate(body.Deserialize<FixtureSelector>(Json) ?? throw Failure(), token),
            _ => Task.FromResult(Error(HttpStatusCode.NotFound))
        };

    private async Task<HttpResponseMessage> PreparePrivateConnectionUpdate(V.Prepare input, CancellationToken token)
    {
        ValidatePrivateUpdateSelector(input.Selection);
        Require(input.SubscriptionId == scope.SubscriptionId && input.ResourceGroup == scope.ResourceGroup &&
            input.Configuration is not null && V.SameConfiguration(input.Configuration, PrivateUpdateBaseline()));
        PrivateConnectionUpdateSession session;
        lock (gate)
        {
            Require(!disposed && privateUpdateSessions.Count < 32 && !privateUpdateSessions.ContainsKey(input.Selection.Nonce));
            session = new(input.Selection with { }) { Active = 1,
                Requested = Enum.Parse<PrivateConnectionState>(input.Selection.Variant.Split('.')[1]) };
            privateUpdateSessions.Add(session.Selector.Nonce, session);
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            var endpoint = privateConnectionSource!;
            lock (gate)
            {
                Require(!disposed && !session.Closed);
                session.Plan = provisioner.PlanFixture(owner, session.Selector, P.Preparation.Active, [],
                    seedCanary: true, privateEndpoint: new(endpoint.BorrowedSubnetId));
                Require(session.Plan.OriginalPrivateConnectionUpdate);
            }
            using var canary = SecretMaterial.FromText(Guid.NewGuid().ToString("N"));
            var prepared = await provisioner.ProvisionAsync(session.Plan, canary, linked.Token).ConfigureAwait(false);
            Require(prepared.State == P.State.Ready && prepared.VaultPresent == true &&
                prepared.DeletedVaultPresent == false && prepared.CanaryPresent == true &&
                prepared.CanaryVersion is not null && prepared.CanarySha256 is not null &&
                prepared.Configuration is not null && V.SameConfiguration(prepared.Configuration, PrivateUpdateBaseline()));
            session.Endpoints = new(provisioner, endpoint.EndpointSetup, endpoint.EndpointReader,
                endpoint.VaultConnectionReader, endpoint.ResourceLimits, endpoint.InventoryLimits, time);
            session.EndpointPlan = session.Endpoints.PlanDeclaredEndpoint(session.Plan);
            var child = await session.Endpoints.ProvisionAsync(session.EndpointPlan, linked.Token).ConfigureAwait(false);
            Require(child.State == EP.State.Ready && child.ConnectionId is not null &&
                session.Endpoints.OwnsBoundPlan(session.EndpointPlan, session.Plan, child.ConnectionId));
            session.ConnectionId = child.ConnectionId;
            var snapshot = provisioner.Journal.Read(owner, session.Selector);
            DateTimeOffset observed = time.GetUtcNow();
            lock (gate)
            {
                Require(!disposed && !session.Closed && snapshot.Idle && !snapshot.Closing &&
                    snapshot.PrivateEndpoint?.OriginalUpdate is not null && snapshot.Resources.Length == 5);
                session.Lease = new(new(session.Selector.Nonce, session.Plan.LeaseId, observerIdentity,
                    M.ArmOrigin, M.Revision, observed, snapshot.Resources.Where(r => !r.Borrowed).Select(r => r.Id)
                        .Concat([child.ConnectionId, session.Plan.PrivateEndpoint!.ExpectedNicId]).ToArray()),
                    session.Plan.VaultName, child.ConnectionId.Split('/')[^1], P.Canary, prepared.CanarySha256,
                    PrivateUpdateBaseline(), PrivateConnectionState.Pending);
                return Reply(session.Lease);
            }
        }
        finally { LeaveOriginalVault(session); }
    }

    private PrivateConnectionUpdateSession FindPrivateUpdate(Guid nonce, Guid lease)
    {
        Require(!disposed);
        Require(privateUpdateSessions.TryGetValue(nonce, out var session));
        Require(!session.Closed && session.Plan is not null && session.Lease is not null &&
            session.Plan.LeaseId == lease);
        return session;
    }

    private HttpResponseMessage ArmPrivateConnectionUpdate(ObserveLease input)
    {
        lock (gate)
        {
            var session = FindPrivateUpdate(input.Nonce, input.LeaseId);
            Require(!session.Armed && input.Phase == "subscribe-before-trigger" && input.SubscriptionId is null);
            session.ArmedAt = time.GetUtcNow();
            session.Subscription = Guid.NewGuid();
            session.Armed = true;
            return Reply(new ObservationSubscription(input.LeaseId, input.Nonce, session.Subscription, session.ArmedAt));
        }
    }

    private async Task<HttpResponseMessage> ObservePrivateConnectionUpdate(ObserveLease input, CancellationToken token)
    {
        PrivateConnectionUpdateSession session;
        bool baseline = input.Phase == "baseline-before-dispatch";
        lock (gate)
        {
            session = FindPrivateUpdate(input.Nonce, input.LeaseId);
            Require(session.Armed && input.SubscriptionId == session.Subscription);
            if (baseline)
            {
                Require(!session.BaselineClaimed && !session.StartClaimed);
                session.BaselineClaimed = true;
            }
            else
            {
                Require(input.Phase == "post-operation" && session.StartFinished);
                if (session.Measurement is not null)
                {
                    RetryPrivateUpdatePersistence(session);
                    return Reply(session.Measurement);
                }
                Require(!session.PostClaimed);
                session.PostClaimed = true;
            }
            session.Active++;
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            if (baseline)
            {
                session.Loan = provisioner.EnterPrivateConnectionUpdate(session.Plan!, session.Endpoints!,
                    session.EndpointPlan!, session.ConnectionId!);
                var observed = await CollectPrivateUpdatePhase(session, linked.Token).ConfigureAwait(false);
                RequirePrivateUpdateState(observed, PrivateConnectionState.Pending);
                var root = new PrivateUpdateRoot(provisioner.Journal, owner, session.Selector, session.Plan!.LeaseId,
                    session.Plan.VaultId, session.Plan.DeletedId, session.ConnectionId!, session.Plan.PrivateEndpoint!,
                    privateUpdateConfiguration!);
                var admission = new PrivateConnectionUpdateAdmission(this);
                lock (gate)
                {
                    Require(!disposed && !session.Closed);
                    Require(privateUpdateAdmissions.TryAdd(admission, new(root, observed, session.Plan,
                        session.Endpoints!, session.EndpointPlan!)));
                    session.Root = root;
                    session.Baseline = observed;
                    session.Admission = admission;
                }
                return Reply(ProjectPrivateUpdate(session, observed));
            }
            bool keepForCompletion = false;
            try
            {
                session.Post = await CollectPrivateUpdatePhase(session, linked.Token).ConfigureAwait(false);
                var post = session.Post;
                bool invalid = session.Requested is not (PrivateConnectionState.Approved or PrivateConnectionState.Rejected);
                bool unchanged = invalid || session.Selector.Case == "denied-authority";
                if (unchanged)
                {
                    RequirePrivateUpdateState(post, PrivateConnectionState.Pending);
                    Require(post.Parent.ActiveDigest == session.Baseline!.Parent.ActiveDigest &&
                        post.ChildDigest == session.Baseline.ChildDigest);
                }
                else RequirePrivateUpdateState(post, session.Requested);
                session.Measurement = ProjectPrivateUpdate(session, post);
                if (OwnsPrivateUpdateStart(session) && session.StartValid && !session.Canceled)
                {
                    if (invalid && session.Native is { HttpStatus: null, Outcome: SecretStatus.Invalid } &&
                        session.Outcome == SecretStatus.Invalid && session.Handle is null &&
                        session.Receipt!.Evidence == DispatchEvidence.NotDispatched)
                        session.Disposition = J.PrivateConnectionUpdateDisposition.InvalidInput;
                    else if (session.Selector.Case == "denied-authority" &&
                        session.Native is { HttpStatus: 403, Outcome: SecretStatus.Denied } &&
                        session.Outcome == SecretStatus.Denied && session.Handle is null &&
                        session.Receipt!.Evidence == DispatchEvidence.Rejected)
                        session.Disposition = J.PrivateConnectionUpdateDisposition.Denied;
                    else if (session.Selector.Case is "selected-contract" or "independent-effect" &&
                        session.Native is { HttpStatus: 200, Outcome: SecretStatus.Success } &&
                        session.Native.EndpointId == session.Plan!.PrivateEndpoint!.EndpointId &&
                        session.Outcome == SecretStatus.Success && session.Handle?.State == NativeProvisioningState.Succeeded &&
                        session.Receipt!.Evidence == DispatchEvidence.Applied)
                        keepForCompletion = true;
                }
                linked.Token.ThrowIfCancellationRequested();
                if (!keepForCompletion) FreezePrivateUpdateDecision(session);
            }
            finally
            {
                if (!keepForCompletion) await FinalizePrivateUpdate(session).ConfigureAwait(false);
            }
            RetryPrivateUpdatePersistence(session);
            return Reply(session.Measurement ?? throw Failure());
        }
        finally { LeaveOriginalVault(session); }
    }

    public async ValueTask<SecretOutcome<ManagementOperation>> RunUpdatePrivateConnectionAsync(FixtureSelector selector,
        VaultAdministration client, PrivateConnectionScope originalScope, PrivateConnectionState state,
        ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        Require(profile == Profile.OriginalPrivateConnectionUpdate);
        ValidatePrivateUpdateSelector(selector);
        PrivateConnectionUpdateSession session;
        lock (gate)
        {
            Require(privateUpdateSessions.TryGetValue(selector.Nonce, out session!) && session.Selector == selector);
            _ = FindPrivateUpdate(selector.Nonce, session.Plan?.LeaseId ?? Guid.Empty);
            Require(session.Armed && session.Baseline is not null && session.Admission is not null &&
                session.Loan is not null && !session.StartClaimed && client is not null && originalScope is not null &&
                originalScope.Vault.ExportResourceId() + "/privateEndpointConnections/" + originalScope.ConnectionName ==
                    session.ConnectionId && state == session.Requested && receipt is not null);
            provisioner.CheckPrivateConnectionUpdateLoan(session.Loan);
            session.Dispatch = provisioner.Journal.BeginPrivateConnectionUpdateInvocation(owner, selector,
                session.Plan!.LeaseId, session.Admission);
            session.StartClaimed = true;
            session.Client = client;
            session.Scope = originalScope;
            session.Receipt = receipt;
            session.Active++;
            active++;
        }
        try
        {
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.Baseline!.FinishedAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, session.Stop.Token,
                lifetime.Token, deadline.Token);
            session.Binding = new(selector, session.Plan!.LeaseId, originalScope, ManagementMutation.UpdatePrivateConnection,
                scope.Location, M.Revision);
            session.Window = capture.ArmPrivateConnectionUpdate(session.Binding, state);
            var result = await capture.StartPrivateConnectionUpdateAsync(session.Window, selector, client, originalScope,
                state, receipt, linked.Token, task => session.StartTask = task, () =>
                {
                    provisioner.CheckPrivateConnectionUpdateLoan(session.Loan!);
                    provisioner.Journal.AdmitPrivateConnectionUpdateSend(owner, selector, session.Plan.LeaseId,
                        session.Dispatch, session.Admission!);
                }).ConfigureAwait(false);
            session.Outcome = result.Status;
            session.Handle = result.IsSuccess ? result.Value : null;
            session.StartValid = state is not (PrivateConnectionState.Approved or PrivateConnectionState.Rejected) ||
                !linked.IsCancellationRequested;
            if (capture.TryGetPrivateConnectionUpdateStart(session.Window, session.Binding, out var native) &&
                capture.OwnsPrivateConnectionUpdateStart(native, session.Window, session.Binding, client, originalScope,
                    state, receipt, session.StartTask!, session.Handle))
                session.Native = native;
            return result;
        }
        catch (OperationCanceledException) { session.Canceled = true; throw; }
        finally
        {
            lock (gate) session.StartFinished = true;
            LeaveOriginalVault(session, invocation: true);
        }
    }

    private bool OwnsPrivateUpdateStart(PrivateConnectionUpdateSession session) =>
        session.Native is not null && session.Window is not null && session.Binding is not null &&
        session.StartTask is not null && capture.OwnsPrivateConnectionUpdateStart(session.Native, session.Window,
            session.Binding, session.Client!, session.Scope!, session.Requested, session.Receipt!,
            session.StartTask, session.Handle);

    public async ValueTask<SecretStatus> CompleteUpdatePrivateConnectionAsync(FixtureSelector selector,
        ManagementOperation originalHandle, CancellationToken cancellationToken)
    {
        Require(profile == Profile.OriginalPrivateConnectionUpdate);
        ValidatePrivateUpdateSelector(selector);
        PrivateConnectionUpdateSession session;
        lock (gate)
        {
            Require(privateUpdateSessions.TryGetValue(selector.Nonce, out session!) && session.Selector == selector);
            _ = FindPrivateUpdate(selector.Nonce, session.Plan?.LeaseId ?? Guid.Empty);
            if (session.CheckClaimed && ReferenceEquals(session.Handle, originalHandle) &&
                session.Finished?.Disposition == J.PrivateConnectionUpdateDisposition.Updated &&
                session.Finalization is { IsCompletedSuccessfully: true })
            {
                RetryPrivateUpdatePersistence(session);
                Require(session.Settled);
                return SecretStatus.Success;
            }
            Require(session.Post is not null && session.Measurement is not null && session.StartFinished &&
                !session.CheckClaimed && session.Finalization is null &&
                ReferenceEquals(session.Handle, originalHandle) && OwnsPrivateUpdateStart(session) &&
                session.Native is { HttpStatus: 200, Outcome: SecretStatus.Success } &&
                session.Selector.Case is "selected-contract" or "independent-effect");
            session.CheckClaimed = true;
            session.Active++;
            active++;
        }
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, session.Stop.Token,
                lifetime.Token, deadline.Token);
            provisioner.CheckPrivateConnectionUpdateLoan(session.Loan!);
            var result = await capture.CheckStatusAsync(session.Window!, selector, originalHandle, linked.Token,
                task => session.CheckTask = task).ConfigureAwait(false);
            Require(result == SecretStatus.Success && capture.OwnsPrivateConnectionUpdateCompletion(session.Native!,
                session.Window!, session.Binding!, session.Client!, session.Scope!, session.Requested, session.Receipt!,
                session.StartTask!, originalHandle, session.CheckTask!));
            linked.Token.ThrowIfCancellationRequested();
            session.Disposition = J.PrivateConnectionUpdateDisposition.Updated;
            FreezePrivateUpdateDecision(session);
            await FinalizePrivateUpdate(session).ConfigureAwait(false);
            RetryPrivateUpdatePersistence(session);
            return result;
        }
        finally
        {
            try { await FinalizePrivateUpdate(session).ConfigureAwait(false); }
            finally { LeaveOriginalVault(session, invocation: true); }
        }
    }

    private async Task<PrivateUpdatePhase> CollectPrivateUpdatePhase(PrivateConnectionUpdateSession session, CancellationToken token)
    {
        var plan = session.Plan!;
        var loan = session.Loan!;
        var endpoint = privateConnectionSource!;
        var source = privateUpdateSource!;
        var parentTask = provisioner.ObservePrivateConnectionUpdateAsync(loan, token);
        var parent = await parentTask.ConfigureAwait(false);
        Require(provisioner.OwnsPrivateConnectionUpdateWitness(parent, loan, parentTask) &&
            parent.Result is { VaultPresent: true, DeletedVaultPresent: false, CanaryPresent: true, Configuration: not null } &&
            V.SameConfiguration(parent.Result.Configuration, PrivateUpdateBaseline()) &&
            parent.StartedAt >= (session.StartClaimed ? session.StartedAt : session.ArmedAt));
        var childBinding = new M.Binding(session.Selector, plan.LeaseId, M.QueryKind.UpdatePrivateConnection,
            M.DefaultRead(M.QueryKind.UpdatePrivateConnection), scope.SubscriptionId, scope.ResourceGroup,
            scope.Location, plan.VaultName, session.ConnectionId!.Split('/')[^1]);
        var childScope = new PrivateConnectionScope(provisioner.Scope(plan), childBinding.ConnectionName!);
        var childTransport = new PrivateUpdateReadTransport(this, session, endpoint.VaultConnectionReader.Transport,
            M.ArmOrigin + session.ConnectionId + "?api-version=" + M.Revision,
            endpoint.InventoryLimits.MaximumResponseBytes, childScope);
        session.Reads.Add(childTransport);
        var reader = new M(endpoint.VaultConnectionReader with { Transport = childTransport }, endpoint.InventoryLimits, time);
        var childWindow = reader.Arm(childBinding);
        var childTask = reader.CollectAsync(childWindow, childBinding, token).AsTask();
        var child = await childTask.ConfigureAwait(false);
        Require(child.ResponseComplete && child.Status == SecretStatus.Success && child.Connections.Count == 1 &&
            child.Binding == childBinding && child.WindowId == childWindow.Id &&
            child.StartedAt >= parent.FinishedAt && child.FinishedAt >= child.StartedAt &&
            childTransport.Parser is { Complete: true, Invalid: false } && childTransport.RawChild is not null &&
            child.Connections[0] == childTransport.RawChild &&
            child.Connections[0].ResourceId == session.ConnectionId &&
            child.Connections[0].PrivateEndpointId == plan.PrivateEndpoint!.EndpointId &&
            child.NativeRequestIds.Count == 1 && child.NativeRequestIds[0] == childTransport.RequestId &&
            childTransport.Digest is not null);
        var endpointBinding = provisioner.EndpointBinding(plan);
        var endpointTransport = new PrivateUpdateReadTransport(this, session, endpoint.EndpointReader.Transport,
            M.ArmOrigin + endpointBinding.EndpointId + "?api-version=" + ER.Revision,
            endpoint.ResourceLimits.MaximumResponseBytes);
        session.Reads.Add(endpointTransport);
        var endpointReader = new ER(endpoint.EndpointReader with { Transport = endpointTransport },
            endpoint.ResourceLimits, time);
        var endpointWindow = endpointReader.Arm(endpointBinding);
        var endpointTask = endpointReader.CollectAsync(endpointWindow, endpointBinding, token).AsTask();
        var measuredEndpoint = await endpointTask.ConfigureAwait(false);
        Require(measuredEndpoint.ResponseComplete && measuredEndpoint.ResourceStatus == SecretStatus.Success &&
            measuredEndpoint.HttpStatus == 200 && measuredEndpoint.Kind == ER.ReadKind.Endpoint &&
            measuredEndpoint.MatchesDeclarationConfiguration && measuredEndpoint.NativeState == "Succeeded" &&
            ReferenceEquals(measuredEndpoint.Binding, endpointBinding) && measuredEndpoint.WindowId == endpointWindow.Id &&
            measuredEndpoint.StartedAt >= child.FinishedAt && measuredEndpoint.FinishedAt >= measuredEndpoint.StartedAt &&
            Text(measuredEndpoint.NativeRequestId, 256));
        var networkBinding = new N.Binding(childBinding, P.Canary, parent.Result.CanaryVersion!,
            parent.Result.CanarySha256!, N.Revision);
        string secretUri = "https://" + plan.VaultName + ".vault.azure.net/secrets/" + P.Canary + "/" +
            networkBinding.CanaryVersion + "?api-version=" + N.Revision;
        var privateTransport = new PrivateUpdateReadTransport(this, session, source.PrivateRuntime.Transport,
            secretUri, source.NetworkLimits.MaximumResponseBytes);
        var publicTransport = new PrivateUpdateReadTransport(this, session, source.PublicRuntime.Transport,
            secretUri, source.NetworkLimits.MaximumResponseBytes);
        session.Reads.Add(privateTransport);
        session.Reads.Add(publicTransport);
        var networkReader = new N(source.PrivateRuntime with { Transport = privateTransport },
            source.PublicRuntime with { Transport = publicTransport }, source.NetworkLimits, time);
        var networkWindow = networkReader.Arm(networkBinding);
        var networkTask = networkReader.CollectAsync(networkWindow, networkBinding, token).AsTask();
        var network = await networkTask.ConfigureAwait(false);
        Require(ReferenceEquals(network.Binding, networkBinding) && network.WindowId == networkWindow.Id &&
            network.StartedAt >= measuredEndpoint.FinishedAt && network.FinishedAt >= network.StartedAt &&
            network.PrivateRead.Failure == N.Failure.None && network.PublicRead.Failure == N.Failure.None &&
            network.PublicRead.Status == SecretStatus.Success &&
            network.PublicRead.CanarySha256 == networkBinding.CanarySha256 &&
            network.PrivateRead.NativeRequestIds.Count == 1 && network.PublicRead.NativeRequestIds.Count == 1 &&
            Text(network.PrivateRead.NativeRequestIds[0], 256) && Text(network.PublicRead.NativeRequestIds[0], 256) &&
            (network.PrivateRead.Status == SecretStatus.Success
                ? network.PrivateRead.CanarySha256 == networkBinding.CanarySha256
                : network.PrivateRead.Status == SecretStatus.Denied && network.PrivateRead.CanarySha256 is null));
        token.ThrowIfCancellationRequested();
        provisioner.CheckPrivateConnectionUpdateLoan(loan);
        return new(loan, parentTask, parent, childBinding, childWindow, childTask, child,
            endpointBinding, endpointWindow, endpointTask, measuredEndpoint, networkBinding, networkWindow,
            networkTask, network, childTransport.Digest, network.FinishedAt);
    }

    private static void RequirePrivateUpdateState(PrivateUpdatePhase phase, PrivateConnectionState state) =>
        Require(phase.Child.Connections[0].State == state &&
            phase.Child.Connections[0].ProvisioningState == NativeProvisioningState.Succeeded &&
            phase.Endpoint.ManualConnectionState == state.ToString() &&
            phase.Network.PrivateRead.Status == (state == PrivateConnectionState.Approved ? SecretStatus.Success : SecretStatus.Denied));

    private V.Measurement ProjectPrivateUpdate(PrivateConnectionUpdateSession session, PrivateUpdatePhase phase)
    {
        var parent = phase.Parent.Result;
        var child = phase.Child.Connections[0];
        return new(session.Plan!.LeaseId, session.Selector.Nonce, observerIdentity, phase.FinishedAt,
            session.Plan.VaultId, SecretStatus.Success, SecretStatus.Absent, parent.Configuration,
            parent.Configuration!.Policies, child.State, SecretStatus.Success, [],
            new(child.Name, phase.Network.PrivateRead.Status, phase.Network.PublicRead.Status,
                phase.Network.PrivateRead.NativeRequestIds[0]), [], [], [new(child.Name, child.State, child.ProvisioningState)], [], null);
    }

    private void FreezePrivateUpdateDecision(PrivateConnectionUpdateSession session)
    {
        if (session.Disposition == J.PrivateConnectionUpdateDisposition.None) return;
        Require(session.Finished is null && session.Post is not null && OwnsPrivateUpdateStart(session) &&
            session.Reads.All(r => r.Complete && (r.Parser is null || r.Parser is { Complete: true, Invalid: false })));
        Require(privateUpdateAdmissions.TryGetValue(session.Admission!, out var admission));
        session.Finished = new(admission, session.Dispatch, session.Post, session.Client!, session.Scope!,
            session.Requested, session.Receipt!, session.Handle, session.StartTask!, session.CheckTask, session.Binding!,
            session.Window!, session.Native!, session.Disposition);
    }

    private Task FinalizePrivateUpdate(PrivateConnectionUpdateSession session)
    {
        lock (gate) return session.Finalization ??= Finish();
        async Task Finish()
        {
            try
            {
                if (session.Window is not null) await capture.SealAsync(session.Window).ConfigureAwait(false);
                bool failed = false;
                foreach (var read in session.Reads)
                    try { read.Storage.Dispose(); }
                    catch (Exception) { failed = true; }
                Require(!failed);
            }
            catch
            {
                session.Finished = null;
                throw;
            }
            finally
            {
                if (session.Loan is { } loan)
                {
                    provisioner.ExitPrivateConnectionUpdate(loan);
                    session.Loan = null;
                }
            }
        }
    }

    private void RetryPrivateUpdatePersistence(PrivateConnectionUpdateSession session)
    {
        if (session.Settled || session.Finished is not { } finished ||
            session.Finalization is not { IsCompletedSuccessfully: true }) return;
        var journal = provisioner.Journal;
        if (session.Termination is null)
            _ = journal.RegisterPrivateConnectionUpdateTermination(owner, session.Selector, session.Plan!.LeaseId,
                session.Dispatch, () =>
                {
                    var certificate = new PrivateConnectionUpdateTermination(this, session.Dispatch);
                    Require(privateUpdateTerminations.TryAdd(certificate, finished));
                    return session.Termination = certificate;
                });
        if (session.Termination is null) return;
        if (!session.TerminationPersisted)
        {
            journal.EndPrivateConnectionUpdateInvocation(owner, session.Selector, session.Plan!.LeaseId, session.Termination);
            session.TerminationPersisted = true;
        }
        if (session.Settlement is null)
            _ = journal.RegisterPrivateConnectionUpdateSettlement(owner, session.Selector, session.Plan!.LeaseId,
                session.Dispatch, () =>
                {
                    var certificate = new PrivateConnectionUpdateSettlement(this, session.Dispatch);
                    Require(privateUpdateSettlements.TryAdd(certificate, finished));
                    return session.Settlement = certificate;
                });
        if (session.Settlement is null) return;
        _ = journal.SettlePrivateConnectionUpdateInvocation(owner, session.Selector, session.Plan!.LeaseId, session.Settlement);
        session.Settled = true;
    }

    private async Task<HttpResponseMessage> ReleasePrivateConnectionUpdate(FixtureSelector selector, CancellationToken token)
    {
        ValidatePrivateUpdateSelector(selector);
        PrivateConnectionUpdateSession session;
        lock (gate)
        {
            Require(!disposed);
            if (!privateUpdateSessions.TryGetValue(selector.Nonce, out session!))
            {
                Require(privateUpdateSessions.Count < 32);
                privateUpdateSessions.Add(selector.Nonce, session = new(selector with { }));
            }
            Require(session.Selector == selector && !session.Releasing);
            session.Releasing = true;
        }
        try
        {
            J.Snapshot snapshot;
            try { snapshot = provisioner.CloseSelectedRoot(owner, selector); }
            finally
            {
                lock (gate)
                {
                    session.Closed = true;
                    if (session.Active == 0) session.Drained.TrySetResult();
                }
                try { session.Stop.Cancel(); }
                catch (Exception) { }
            }
            lock (gate)
                if (session.Active != 0) return Reply(PrivateUpdateReleaseMeasurement(session, snapshot));
            await FinalizePrivateUpdate(session).ConfigureAwait(false);
            RetryPrivateUpdatePersistence(session);
            snapshot = provisioner.Journal.Read(owner, selector);
            if (snapshot.Resources.Length != 0)
            {
                session.Plan ??= provisioner.OpenCleanupPlan(owner, selector);
                Require(session.Plan.OriginalPrivateConnectionUpdate);
                var endpoint = privateConnectionSource!;
                session.Endpoints ??= new(provisioner, endpoint.EndpointSetup, endpoint.EndpointReader,
                    endpoint.VaultConnectionReader, endpoint.ResourceLimits, endpoint.InventoryLimits, time);
                if (snapshot.PrivateEndpointCleanupEligible)
                {
                    var dependencies = await session.Endpoints.CleanupAsync(session.Plan, token).ConfigureAwait(false);
                    snapshot = dependencies.Journal;
                    if (dependencies.State == EP.CleanupState.DependenciesAbsent)
                        snapshot = (await provisioner.ReleaseAsync(owner, selector, purge: true,
                            cancellationToken: token, privateEndpointCleanup: session.Endpoints).ConfigureAwait(false)).Journal;
                }
            }
            return Reply(PrivateUpdateReleaseMeasurement(session, snapshot));
        }
        finally { lock (gate) session.Releasing = false; }
    }

    private static RoleFixtureRelease.Measurement PrivateUpdateReleaseMeasurement(
        PrivateConnectionUpdateSession session, J.Snapshot snapshot)
    {
        string[] owned = snapshot.Resources.Where(r => !r.Borrowed).Select(r => r.Id).ToArray();
        string[] absent = snapshot.Resources.Where(r => !r.Borrowed && r.Absent && r.ActiveDispatch == Guid.Empty)
            .Select(r => r.Id).ToArray();
        if (snapshot.PrivateEndpoint is { } slot)
        {
            string[] dependencies = slot.Connection is null ? [slot.Declaration.ExpectedNicId] :
                [slot.Declaration.ExpectedNicId, slot.Connection.Id];
            owned = [.. owned, .. dependencies];
            if (snapshot.PrivateEndpointAbsent) absent = [.. absent, .. dependencies];
        }
        return new(session.Selector, snapshot.Closing,
            session.Active + snapshot.Resources.Count(r => r.ActiveDispatch != Guid.Empty) +
                (snapshot.PrivateEndpoint?.Connection is { ActiveDispatch: var active } && active != Guid.Empty ? 1 : 0),
            owned, snapshot.Resources.Where(r => r.Borrowed).Select(r => r.Id).ToArray(), absent,
            owned.Except(absent, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private async Task DrainPrivateConnectionUpdate(TaskCompletionSource completion)
    {
        bool failed = false;
        PrivateConnectionUpdateSession[] owned;
        lock (gate) owned = privateUpdateSessions.Values.ToArray();
        foreach (var session in owned)
        {
            try { provisioner.CloseSelectedRoot(owner, session.Selector); }
            catch (Exception) { failed = true; }
            lock (gate)
            {
                session.Closed = true;
                if (session.Active == 0) session.Drained.TrySetResult();
            }
            try { session.Stop.Cancel(); }
            catch (Exception) { failed = true; }
        }
        try { lifetime.Cancel(); }
        catch (Exception) { failed = true; }
        await drained.Task.ConfigureAwait(false);
        foreach (var session in owned)
        {
            try
            {
                await session.Drained.Task.ConfigureAwait(false);
                await FinalizePrivateUpdate(session).ConfigureAwait(false);
                RetryPrivateUpdatePersistence(session);
            }
            catch (Exception) { failed = true; }
            if (session.Endpoints is not null)
                try { await session.Endpoints.DisposeAsync().ConfigureAwait(false); }
                catch (Exception) { failed = true; }
            session.Stop.Dispose();
        }
        lifetime.Dispose();
        if (failed) completion.TrySetException(Failure());
        else completion.TrySetResult();
    }

    // Outside the supplied transport: exact authenticated routes remain bound
    // to the live original loan even if credential acquisition outlives Close.
    private sealed class PrivateUpdateReadTransport(ManagementOperationFixtureObserverService source,
        PrivateConnectionUpdateSession session, HttpPipelineTransport backend, string exactUri, int maximum,
        PrivateConnectionScope? child = null) : HttpPipelineTransport
    {
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal OwnedArmResponse.ParserCustody? Parser;
        internal M.ConnectionRow? RawChild;
        internal string? Digest, RequestId;
        internal bool Complete;
        private readonly HashSet<Request> requests = new(ReferenceEqualityComparer.Instance);
        private int sends;
        public override Request CreateRequest()
        {
            source.provisioner.CheckPrivateConnectionUpdateLoan(session.Loan!);
            Require(requests.Count < 16);
            var request = backend.CreateRequest();
            requests.Add(request);
            return request;
        }
        public override void Process(HttpMessage message) => throw Failure();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            Require(++sends == 1 && requests.Contains(message.Request));
            Check(message);
            var request = message.Request;
            var headers = request.Headers.ToArray();
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (child is not null && message.HasResponse) Storage.Own(message.Response); }
            Check(message);
            Require(ReferenceEquals(request, message.Request) && headers.SequenceEqual(request.Headers));
            if (child is not null)
            {
                var body = await OwnedArmResponse.CaptureAsync(message, maximum, Storage).ConfigureAwait(false);
                Check(message);
                Require(ReferenceEquals(request, message.Request) && headers.SequenceEqual(request.Headers));
                RawChild = C.ParsePrivateConnectionResource(child, body.Bytes,
                    body.Response.Headers.Select(h => (h.Name, h.Value)).ToArray(), body.Response.Status);
                Digest = body.Sha256;
                RequestId = body.NativeRequestId;
                Parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, Storage,
                    requireRebuffer: true);
            }
            Complete = true;
        }
        private void Check(HttpMessage message)
        {
            source.provisioner.CheckPrivateConnectionUpdateLoan(session.Loan!);
            var headers = message.Request.Headers.ToArray();
            Require(message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
                message.Request.Uri.ToUri().OriginalString == exactUri &&
                message.Request.Headers.TryGetValue("Authorization", out var auth) &&
                auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                headers.Length <= 32 && headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
                headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                headers.All(h => h.Name.Length is > 0 and <= 128 && h.Value.Length <= 16384 &&
                    !h.Name.Any(char.IsControl) && !h.Value.Any(char.IsControl)) &&
                !message.Request.Headers.Contains("Content-Length") && !message.Request.Headers.Contains("Content-Encoding") &&
                !message.Request.Headers.Contains("Transfer-Encoding"));
            if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == new Uri(exactUri).Host);
            message.CancellationToken.ThrowIfCancellationRequested();
        }
    }
}
