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
    internal sealed record PrivateConnectionDeleteSource(
        [property: JsonIgnore] P Provisioner,
        [property: JsonIgnore] PrivateConnectionSource Endpoint,
        [property: JsonIgnore] N.Authority PrivateRuntime,
        [property: JsonIgnore] N.Authority PublicRuntime,
        [property: JsonIgnore] N.Limits NetworkLimits,
        [property: JsonIgnore] HttpPipelineTransport SelectedBackend)
    {
        public override string ToString() => "[PrivateConnectionDeleteSource]";
    }

    private readonly PrivateConnectionDeleteSource? privateDeleteSource;
    private readonly string? privateDeleteConfiguration;
    private readonly Dictionary<Guid, PrivateConnectionDeleteSession> privateDeleteSessions = [];

    internal ManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, P.HostScope scope, PrivateConnectionDeleteSource source, Limits limits,
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
        privateDeleteConfiguration = EncodeDeleteConfiguration(baseline);
        privateDeleteSource = source;
        privateConnectionSource = endpoint;
        profile = Profile.OriginalPrivateConnectionDelete;
        nativeCapture = new(source.SelectedBackend, limits.MaximumReplyBytes);
    }

    internal static ManagementOperationFixtureObserverService ForPrivateConnectionDeleteCleanup(Uri origin,
        string owner, string observerIdentity, SecretMaterial capability, P.HostScope scope, P provisioner,
        PrivateConnectionSource endpoint, Limits limits, TimeProvider? time = null) =>
        new(origin, owner, observerIdentity, capability, scope, provisioner, endpoint, limits,
            Profile.PrivateConnectionDeleteCleanup, time);

    private ManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, P.HostScope scope, P provisioner, PrivateConnectionSource endpoint,
        Limits limits, Profile cleanupProfile, TimeProvider? time)
        : this(origin, owner, observerIdentity, capability, scope, provisioner, endpoint, limits, time)
    {
        Require(cleanupProfile == Profile.PrivateConnectionDeleteCleanup);
        profile = cleanupProfile;
    }

    private V.Configuration PrivateDeleteBaseline() =>
        JsonSerializer.Deserialize<V.Configuration>(privateDeleteConfiguration ?? throw Failure(), Json) ?? throw Failure();

    private sealed class PrivateConnectionDeleteSession(FixtureSelector selector) : OriginalVaultSession(selector)
    {
        internal P.Plan? Plan;
        internal EP? Endpoints;
        internal EP.Plan? EndpointPlan;
        internal P.PrivateConnectionDeleteLoan? Loan;
        internal V.Lease? Lease;
        internal string? ConnectionId;
        internal Guid Subscription, Dispatch;
        internal DateTimeOffset ArmedAt, StartedAt;
        internal bool Armed, BaselineClaimed, StartClaimed, StartFinished, PostClaimed, PostFinished, CheckClaimed;
        internal bool StartValid, PostValid, Canceled, TerminationPersisted, Settled;
        internal PrivateDeletePhase? Baseline, Post;
        internal PrivateConnectionDeleteAdmission? Admission;
        internal PrivateConnectionDeleteTermination? Termination;
        internal PrivateConnectionDeleteSettlement? Settlement;
        internal PrivateConnectionDeleteCertificates? Certificates;
        internal PrivateDeleteFinished? Finished;
        internal PrivateDeleteDrained? DrainEvidence;
        internal VaultAdministration? Client;
        internal PrivateConnectionScope? Scope;
        internal ManagementReceipt? Receipt;
        internal ManagementOperation? Handle;
        internal SecretStatus? Outcome, Completion;
        internal DispatchEvidence? StartReceipt, CheckReceipt;
        internal C.Binding? Binding;
        internal C.Window? Window;
        internal Task? StartTask, CheckTask, Finalization;
        internal V.Measurement? Measurement;
        internal readonly List<PrivateDeleteReadTransport> Reads = [];
        internal readonly List<PrivateDeleteObservation> Observations = [];
    }

    // Retain partial observations as well as complete phases. A later failed
    // conjunct cannot erase which original read tasks actually ran.
    private sealed class PrivateDeleteObservation
    {
        internal Task<P.PrivateConnectionDeleteWitness>? Parent;
        internal M.Binding? ChildBinding;
        internal M.Window? ChildWindow;
        internal Task<M.Measurement>? Child;
        internal ER.Binding? EndpointBinding;
        internal ER.Window? EndpointWindow;
        internal Task<ER.Measurement>? Endpoint;
        internal N.Binding? NetworkBinding;
        internal N.Window? NetworkWindow;
        internal Task<N.Measurement>? Network;
    }

    private sealed record PrivateDeleteRoot(J Journal, string Owner, FixtureSelector Selector, Guid Lease,
        string VaultId, string DeletedId, string ConnectionId, J.PrivateEndpointDeclaration Endpoint, string Configuration);
    private sealed record PrivateDeletePhase(P.PrivateConnectionDeleteLoan Loan,
        Task<P.PrivateConnectionDeleteWitness> ParentTask, P.PrivateConnectionDeleteWitness Parent,
        M.Binding ChildBinding, M.Window ChildWindow, Task<M.Measurement> ChildTask, M.Measurement Child,
        ER.Binding EndpointBinding, ER.Window EndpointWindow, Task<ER.Measurement> EndpointTask, ER.Measurement Endpoint,
        N.Binding NetworkBinding, N.Window NetworkWindow, Task<N.Measurement> NetworkTask, N.Measurement Network,
        string ChildDigest, string EndpointDigest, DateTimeOffset FinishedAt);
    private sealed record PrivateDeleteAdmissionEvidence(PrivateDeleteRoot Root, PrivateDeletePhase Baseline,
        P.Plan Parent, EP Endpoints, EP.Plan EndpointPlan);
    private abstract record PrivateDeleteFinished(PrivateDeleteAdmissionEvidence Admission, Guid Dispatch)
    {
        internal sealed record Denied(PrivateDeleteAdmissionEvidence Admission, Guid Dispatch,
            PrivateDeletePhase Post, VaultAdministration Client, PrivateConnectionScope Scope, ManagementReceipt Receipt,
            Task StartTask, C.Binding Binding, C.Window Window, C.PrivateConnectionDeleteDenied Native)
            : PrivateDeleteFinished(Admission, Dispatch);
        internal sealed record Deleted(PrivateDeleteAdmissionEvidence Admission, Guid Dispatch,
            PrivateDeletePhase Baseline, PrivateDeletePhase Post, VaultAdministration Client,
            PrivateConnectionScope Scope, ManagementReceipt Receipt, Task StartTask, Task CheckTask,
            ManagementOperation Handle, DispatchEvidence StartReceipt, DispatchEvidence CheckReceipt,
            C.Binding Binding, C.Window Window, C.PrivateConnectionDeleteCandidate Candidate,
            C.PrivateConnectionDeleteCompletion Completion) : PrivateDeleteFinished(Admission, Dispatch);
    }
    private sealed record PrivateDeleteDrained(PrivateDeleteAdmissionEvidence Admission, Guid Dispatch,
        Task? StartTask, Task? CheckTask);
    internal sealed record PrivateConnectionDeleteCertificates(
        PrivateConnectionDeleteTermination Termination, PrivateConnectionDeleteSettlement Settlement);
    private sealed class PrivateDeleteCompletionRegistration
    {
        internal readonly PrivateDeleteDrained Drained;
        internal readonly PrivateDeleteFinished.Deleted Decision;
        internal readonly PrivateConnectionDeleteCertificates Certificates;
        internal PrivateDeleteCompletionRegistration(ManagementOperationFixtureObserverService source,
            PrivateDeleteDrained drained, PrivateDeleteFinished.Deleted decision)
        {
            Drained = drained;
            Decision = decision;
            Certificates = new(new(source, drained.Dispatch, this), new(source, drained.Dispatch, this));
        }
    }
    private readonly ConcurrentDictionary<PrivateConnectionDeleteAdmission, PrivateDeleteAdmissionEvidence> privateDeleteAdmissions =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<PrivateConnectionDeleteTermination, PrivateDeleteDrained> privateDeleteTerminations =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<PrivateConnectionDeleteSettlement, PrivateDeleteFinished> privateDeleteSettlements =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<object, PrivateDeleteCompletionRegistration> privateDeleteCompletions =
        new(ReferenceEqualityComparer.Instance);

    internal sealed class PrivateConnectionDeleteAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(J journal, J.Snapshot snapshot) =>
            source.privateDeleteAdmissions.TryGetValue(this, out var evidence) &&
            PrivateDeleteRootMatches(journal, snapshot, evidence.Root);
        public override string ToString() => "[PrivateConnectionDeleteAdmission]";
    }
    internal sealed class PrivateConnectionDeleteTermination(ManagementOperationFixtureObserverService source, Guid dispatch,
        object? registration = null)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Paired => registration is not null;
        internal bool Validate(J journal, J.Snapshot snapshot) =>
            registration is null
                ? source.privateDeleteTerminations.TryGetValue(this, out var evidence) &&
                    evidence.Dispatch == Dispatch && Dispatch != Guid.Empty &&
                    PrivateDeleteRootMatches(journal, snapshot, evidence.Admission.Root)
                : source.privateDeleteCompletions.TryGetValue(registration, out var completed) &&
                    ReferenceEquals(completed.Certificates.Termination, this) &&
                    completed.Drained.Dispatch == Dispatch && Dispatch != Guid.Empty &&
                    PrivateDeleteRootMatches(journal, snapshot, completed.Drained.Admission.Root);
        internal bool OwnsPair(PrivateConnectionDeleteCertificates pair) =>
            registration is not null && source.privateDeleteCompletions.TryGetValue(registration, out var completed) &&
            ReferenceEquals(completed.Certificates, pair) && ReferenceEquals(pair.Termination, this);
        public override string ToString() => "[PrivateConnectionDeleteTermination]";
    }
    internal sealed class PrivateConnectionDeleteSettlement(ManagementOperationFixtureObserverService source, Guid dispatch,
        object? registration = null)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal J.PrivateConnectionDeleteDisposition Disposition =>
            registration is null && source.privateDeleteSettlements.TryGetValue(this, out var decision) &&
                decision is PrivateDeleteFinished.Denied ? J.PrivateConnectionDeleteDisposition.Denied :
            registration is not null && source.privateDeleteCompletions.TryGetValue(registration, out var completed) &&
                ReferenceEquals(completed.Certificates.Settlement, this)
                ? J.PrivateConnectionDeleteDisposition.Deleted : throw Failure();
        internal bool Validate(J journal, J.Snapshot snapshot) =>
            registration is null
                ? source.privateDeleteSettlements.TryGetValue(this, out var evidence) &&
                    evidence is PrivateDeleteFinished.Denied && evidence.Dispatch == Dispatch && Dispatch != Guid.Empty &&
                    PrivateDeleteRootMatches(journal, snapshot, evidence.Admission.Root)
                : source.privateDeleteCompletions.TryGetValue(registration, out var completed) &&
                    ReferenceEquals(completed.Certificates.Settlement, this) &&
                    completed.Decision.Dispatch == Dispatch && Dispatch != Guid.Empty &&
                    PrivateDeleteRootMatches(journal, snapshot, completed.Decision.Admission.Root);
        public override string ToString() => "[PrivateConnectionDeleteSettlement]";
    }

    // Journal callbacks consult immutable reference registrations only, never
    // service/parent locks, clocks, host callbacks or recursive journal reads.
    private static bool PrivateDeleteRootMatches(J journal, J.Snapshot snapshot, PrivateDeleteRoot root) =>
        ReferenceEquals(journal, root.Journal) && snapshot.Owner == root.Owner && snapshot.Selector == root.Selector &&
        snapshot.LeaseId == root.Lease && snapshot.Settings is null && snapshot.DeleteVault is null &&
        snapshot.PurgeDeletedVault is null && snapshot.CreateOrUpdateVault is null && snapshot.RecoverVault is null &&
        snapshot.PrivateEndpoint is { OriginalDelete: { } deletion, OriginalUpdate: null } slot &&
        slot.Declaration == root.Endpoint && slot.Connection?.Id == root.ConnectionId &&
        slot.ApprovalSettledDispatch == Guid.Empty && EncodeDeleteConfiguration(deletion.Baseline) == root.Configuration &&
        snapshot.Resources.Length == 5 &&
        snapshot.Resources.Count(r => r.Id == root.VaultId && !r.Borrowed && !r.CleanupOnly) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.VaultId + "/secrets/" + P.Canary && !r.Borrowed && !r.CleanupOnly) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.DeletedId && !r.Borrowed && r.CleanupOnly &&
            !r.CreateAttempted && !r.SelectedAttempted) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.Endpoint.EndpointId && !r.Borrowed && !r.CleanupOnly) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.Endpoint.BorrowedSubnetId && r.Borrowed) == 1;

    private static void ValidatePrivateDeleteSelector(FixtureSelector selector) =>
        Require(selector is not null && selector.Nonce != Guid.Empty && P.PrivateConnectionDeleteSelector(selector) &&
            new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }.All(v => Text(v, 512)));

    private Task<HttpResponseMessage> DispatchPrivateConnectionDelete(string path, JsonElement body, CancellationToken token) =>
        path switch
        {
            "/vault/prepare" when profile == Profile.OriginalPrivateConnectionDelete =>
                PreparePrivateConnectionDelete(body.Deserialize<V.Prepare>(Json) ?? throw Failure(), token),
            "/vault/arm" when profile == Profile.OriginalPrivateConnectionDelete =>
                Task.FromResult(ArmPrivateConnectionDelete(body.Deserialize<ObserveLease>(Json) ?? throw Failure())),
            "/vault/observe" when profile == Profile.OriginalPrivateConnectionDelete =>
                ObservePrivateConnectionDelete(body.Deserialize<ObserveLease>(Json) ?? throw Failure(), token),
            "/vault/release" => ReleasePrivateConnectionDelete(body.Deserialize<FixtureSelector>(Json) ?? throw Failure(), token),
            _ => Task.FromResult(Error(HttpStatusCode.NotFound))
        };

    private async Task<HttpResponseMessage> PreparePrivateConnectionDelete(V.Prepare input, CancellationToken token)
    {
        ValidatePrivateDeleteSelector(input.Selection);
        Require(input.SubscriptionId == scope.SubscriptionId && input.ResourceGroup == scope.ResourceGroup &&
            input.Configuration is not null && V.SameConfiguration(input.Configuration, PrivateDeleteBaseline()));
        PrivateConnectionDeleteSession session;
        lock (gate)
        {
            Require(!disposed && privateDeleteSessions.Count < 32 && !privateDeleteSessions.ContainsKey(input.Selection.Nonce));
            session = new(input.Selection with { }) { Active = 1 };
            privateDeleteSessions.Add(session.Selector.Nonce, session);
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
                Require(session.Plan.OriginalPrivateConnectionDelete);
            }
            using var canary = SecretMaterial.FromText(Guid.NewGuid().ToString("N"));
            var prepared = await provisioner.ProvisionAsync(session.Plan, canary, linked.Token).ConfigureAwait(false);
            Require(prepared.State == P.State.Ready && prepared.VaultPresent == true &&
                prepared.DeletedVaultPresent == false && prepared.CanaryPresent == true &&
                prepared.CanaryVersion is not null && prepared.CanarySha256 is not null &&
                prepared.Configuration is not null && V.SameConfiguration(prepared.Configuration, PrivateDeleteBaseline()));
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
                    snapshot.PrivateEndpoint?.OriginalDelete is not null && snapshot.Resources.Length == 5);
                session.Lease = new(new(session.Selector.Nonce, session.Plan.LeaseId, observerIdentity,
                    M.ArmOrigin, M.Revision, observed, snapshot.Resources.Where(r => !r.Borrowed).Select(r => r.Id)
                        .Concat([child.ConnectionId, session.Plan.PrivateEndpoint!.ExpectedNicId]).ToArray()),
                    session.Plan.VaultName, child.ConnectionId.Split('/')[^1], P.Canary, prepared.CanarySha256,
                    PrivateDeleteBaseline(), PrivateConnectionState.Pending);
                return Reply(session.Lease);
            }
        }
        finally { LeaveOriginalVault(session); }
    }

    private PrivateConnectionDeleteSession FindPrivateDelete(Guid nonce, Guid lease)
    {
        Require(!disposed);
        Require(privateDeleteSessions.TryGetValue(nonce, out var session));
        Require(!session.Closed && session.Plan is not null && session.Lease is not null &&
            session.Plan.LeaseId == lease);
        return session;
    }

    private HttpResponseMessage ArmPrivateConnectionDelete(ObserveLease input)
    {
        lock (gate)
        {
            var session = FindPrivateDelete(input.Nonce, input.LeaseId);
            Require(!session.Armed && input.Phase == "subscribe-before-trigger" && input.SubscriptionId is null);
            session.ArmedAt = time.GetUtcNow();
            session.Subscription = Guid.NewGuid();
            session.Armed = true;
            return Reply(new ObservationSubscription(input.LeaseId, input.Nonce, session.Subscription, session.ArmedAt));
        }
    }

    private async Task<HttpResponseMessage> ObservePrivateConnectionDelete(ObserveLease input, CancellationToken token)
    {
        PrivateConnectionDeleteSession session;
        bool baseline = input.Phase == "baseline-before-dispatch";
        lock (gate)
        {
            session = FindPrivateDelete(input.Nonce, input.LeaseId);
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
                    Require(session.PostFinished);
                    RetryPrivateDeletePersistence(session);
                    return Reply(session.Measurement);
                }
                Require(!session.PostClaimed);
                session.PostClaimed = true;
            }
            session.Active++;
        }
        bool keepForCompletion = !baseline && session.Outcome == SecretStatus.Success && session.Handle is not null &&
            session.Selector.Case is "selected-contract" or "independent-effect";
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            if (baseline)
            {
                session.Loan = provisioner.EnterPrivateConnectionDelete(session.Plan!, session.Endpoints!,
                    session.EndpointPlan!, session.ConnectionId!);
                var observed = await CollectPrivateDeletePhase(session, linked.Token).ConfigureAwait(false);
                RequirePrivateDeletePending(observed);
                var root = new PrivateDeleteRoot(provisioner.Journal, owner, session.Selector, session.Plan!.LeaseId,
                    session.Plan.VaultId, session.Plan.DeletedId, session.ConnectionId!, session.Plan.PrivateEndpoint!,
                    privateDeleteConfiguration!);
                var admission = new PrivateConnectionDeleteAdmission(this);
                lock (gate)
                {
                    Require(!disposed && !session.Closed);
                    Require(privateDeleteAdmissions.TryAdd(admission, new(root, observed, session.Plan,
                        session.Endpoints!, session.EndpointPlan!)));
                    session.Baseline = observed;
                    session.Admission = admission;
                }
                return Reply(ProjectPrivateDelete(session, observed));
            }
            session.Post = await CollectPrivateDeletePhase(session, linked.Token).ConfigureAwait(false);
            session.Measurement = ProjectPrivateDelete(session, session.Post);
            if (session.Selector.Case == "denied-authority")
            {
                RequirePrivateDeletePending(session.Post);
                Require(session.Post.Parent.ActiveDigest == session.Baseline!.Parent.ActiveDigest &&
                    session.Post.ChildDigest == session.Baseline.ChildDigest &&
                    session.Post.EndpointDigest == session.Baseline.EndpointDigest);
                FreezePrivateDeleteDenial(session);
            }
            linked.Token.ThrowIfCancellationRequested();
            lock (gate) { session.PostValid = true; session.PostFinished = true; }
            if (!keepForCompletion)
            {
                await FinalizePrivateDelete(session).ConfigureAwait(false);
                RetryPrivateDeletePersistence(session);
            }
            return Reply(session.Measurement);
        }
        catch
        {
            if (session.Finalization is not { IsCompletedSuccessfully: true }) session.Finished = null;
            if (!baseline) lock (gate) session.PostFinished = true;
            // Even a failed post witness must not silently skip the original
            // successful start's one explicit check before client disposal.
            if (keepForCompletion && !session.CheckClaimed)
                await CompleteDeletePrivateConnectionAsync(session.Selector, session.Handle!, token).ConfigureAwait(false);
            throw;
        }
        finally
        {
            try
            {
                if (!baseline && !keepForCompletion) await FinalizePrivateDelete(session).ConfigureAwait(false);
            }
            finally { LeaveOriginalVault(session); }
        }
    }

    public async ValueTask<SecretOutcome<ManagementOperation>> RunDeletePrivateConnectionAsync(FixtureSelector selector,
        VaultAdministration client, PrivateConnectionScope originalScope, ManagementReceipt receipt,
        CancellationToken cancellationToken)
    {
        Require(profile == Profile.OriginalPrivateConnectionDelete);
        ValidatePrivateDeleteSelector(selector);
        PrivateConnectionDeleteSession session;
        lock (gate)
        {
            Require(privateDeleteSessions.TryGetValue(selector.Nonce, out session!) && session.Selector == selector);
            _ = FindPrivateDelete(selector.Nonce, session.Plan?.LeaseId ?? Guid.Empty);
            Require(session.Armed && session.Baseline is not null && session.Admission is not null &&
                session.Loan is not null && !session.StartClaimed && client is not null && originalScope is not null &&
                originalScope.Vault.ExportResourceId() + "/privateEndpointConnections/" + originalScope.ConnectionName ==
                    session.ConnectionId && receipt is not null);
            provisioner.CheckPrivateConnectionDeleteLoan(session.Loan);
            session.Dispatch = provisioner.Journal.BeginPrivateConnectionDeleteInvocation(owner, selector,
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
            session.Binding = new(selector, session.Plan!.LeaseId, originalScope, ManagementMutation.DeletePrivateConnection,
                scope.Location, M.Revision);
            session.Window = capture.ArmPrivateConnectionDelete(session.Binding);
            var result = await capture.StartPrivateConnectionDeleteAsync(session.Window, selector, client, originalScope,
                receipt, linked.Token, task => session.StartTask = task, () =>
                {
                    provisioner.CheckPrivateConnectionDeleteLoan(session.Loan!);
                    provisioner.Journal.AdmitPrivateConnectionDeleteSend(owner, selector, session.Plan.LeaseId,
                        session.Dispatch, session.Admission!);
                }).ConfigureAwait(false);
            session.Outcome = result.Status;
            session.StartReceipt = receipt.Evidence;
            session.Handle = result.IsSuccess ? result.Value : null;
            session.StartValid = !linked.IsCancellationRequested;
            return result;
        }
        catch (OperationCanceledException) { session.Canceled = true; throw; }
        finally
        {
            lock (gate) session.StartFinished = true;
            LeaveOriginalVault(session, invocation: true);
        }
    }

    public async ValueTask<SecretStatus> CompleteDeletePrivateConnectionAsync(FixtureSelector selector,
        ManagementOperation originalHandle, CancellationToken cancellationToken)
    {
        Require(profile == Profile.OriginalPrivateConnectionDelete);
        ValidatePrivateDeleteSelector(selector);
        PrivateConnectionDeleteSession session;
        lock (gate)
        {
            Require(privateDeleteSessions.TryGetValue(selector.Nonce, out session!) && session.Selector == selector);
            if (session.CheckClaimed && ReferenceEquals(session.Handle, originalHandle) &&
                session.Finished is PrivateDeleteFinished.Deleted &&
                session.Finalization is { IsCompletedSuccessfully: true })
            {
                RetryPrivateDeletePersistence(session);
                Require(session.Settled);
                return session.Completion!.Value;
            }
            _ = FindPrivateDelete(selector.Nonce, session.Plan?.LeaseId ?? Guid.Empty);
            Require(session.StartFinished && session.PostClaimed && session.PostFinished && !session.CheckClaimed &&
                session.Finalization is null && session.Outcome == SecretStatus.Success &&
                ReferenceEquals(session.Handle, originalHandle) && originalHandle is not null &&
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
            provisioner.CheckPrivateConnectionDeleteLoan(session.Loan!);
            var result = await capture.CheckStatusAsync(session.Window!, selector, originalHandle, linked.Token,
                task => session.CheckTask = task).ConfigureAwait(false);
            session.Completion = result;
            session.CheckReceipt = session.Receipt!.Evidence;
            if (!linked.IsCancellationRequested) FreezePrivateDeleteCompletion(session);
            return result;
        }
        catch (OperationCanceledException) { session.Canceled = true; throw; }
        finally
        {
            try
            {
                await FinalizePrivateDelete(session).ConfigureAwait(false);
                RetryPrivateDeletePersistence(session);
            }
            finally { LeaveOriginalVault(session, invocation: true); }
        }
    }

    private async Task<PrivateDeletePhase> CollectPrivateDeletePhase(PrivateConnectionDeleteSession session, CancellationToken token)
    {
        var plan = session.Plan!;
        var loan = session.Loan!;
        var endpoint = privateConnectionSource!;
        var source = privateDeleteSource!;
        var observation = new PrivateDeleteObservation();
        session.Observations.Add(observation);
        var parentTask = observation.Parent = provisioner.ObservePrivateConnectionDeleteAsync(loan, token);
        var parent = await parentTask.ConfigureAwait(false);
        Require(provisioner.OwnsPrivateConnectionDeleteWitness(parent, loan, parentTask) &&
            parent.Result is { VaultPresent: true, DeletedVaultPresent: false, CanaryPresent: true, Configuration: not null } &&
            V.SameConfiguration(parent.Result.Configuration, PrivateDeleteBaseline()) &&
            parent.StartedAt >= (session.StartClaimed ? session.StartedAt : session.ArmedAt));
        var childBinding = observation.ChildBinding = new M.Binding(session.Selector, plan.LeaseId, M.QueryKind.DeletePrivateConnection,
            M.DefaultRead(M.QueryKind.DeletePrivateConnection), scope.SubscriptionId, scope.ResourceGroup,
            scope.Location, plan.VaultName, session.ConnectionId!.Split('/')[^1]);
        var childScope = new PrivateConnectionScope(provisioner.Scope(plan), childBinding.ConnectionName!);
        var childTransport = new PrivateDeleteReadTransport(this, session, endpoint.VaultConnectionReader.Transport,
            M.ArmOrigin + session.ConnectionId + "?api-version=" + M.Revision,
            endpoint.InventoryLimits.MaximumResponseBytes, childScope);
        session.Reads.Add(childTransport);
        var reader = new M(endpoint.VaultConnectionReader with { Transport = childTransport }, endpoint.InventoryLimits, time);
        var childWindow = observation.ChildWindow = reader.Arm(childBinding);
        var childTask = observation.Child = reader.CollectAsync(childWindow, childBinding, token).AsTask();
        var child = await childTask.ConfigureAwait(false);
        Require(child.ResponseComplete && child.Binding == childBinding && child.WindowId == childWindow.Id &&
            child.StartedAt >= parent.FinishedAt && child.FinishedAt >= child.StartedAt &&
            childTransport.Parser is { Complete: true, Invalid: false } && childTransport.Digest is not null &&
            child.NativeRequestIds.Count == 1 && child.NativeRequestIds[0] == childTransport.RequestId &&
            (child.Status == SecretStatus.Success
                ? childTransport.HttpStatus == 200 && child.Connections.Count == 1 &&
                    child.Connections[0] == childTransport.RawChild &&
                    child.Connections[0].ResourceId == session.ConnectionId &&
                    child.Connections[0].PrivateEndpointId == plan.PrivateEndpoint!.EndpointId
                : child.Status == SecretStatus.Absent && childTransport.HttpStatus == 404 &&
                    child.Connections.Count == 0 && childTransport.RawChild is null));
        var endpointBinding = observation.EndpointBinding = provisioner.EndpointBinding(plan);
        var endpointTransport = new PrivateDeleteReadTransport(this, session, endpoint.EndpointReader.Transport,
            M.ArmOrigin + endpointBinding.EndpointId + "?api-version=" + ER.Revision,
            endpoint.ResourceLimits.MaximumResponseBytes);
        session.Reads.Add(endpointTransport);
        var endpointReader = new ER(endpoint.EndpointReader with { Transport = endpointTransport }, endpoint.ResourceLimits, time);
        var endpointWindow = observation.EndpointWindow = endpointReader.Arm(endpointBinding);
        var endpointTask = observation.Endpoint = endpointReader.CollectAsync(endpointWindow, endpointBinding, token).AsTask();
        var measuredEndpoint = await endpointTask.ConfigureAwait(false);
        Require(measuredEndpoint.ResponseComplete && measuredEndpoint.ResourceStatus == SecretStatus.Success &&
            measuredEndpoint.HttpStatus == 200 && measuredEndpoint.Kind == ER.ReadKind.Endpoint &&
            measuredEndpoint.MatchesDeclarationConfiguration && measuredEndpoint.NativeState == "Succeeded" &&
            ReferenceEquals(measuredEndpoint.Binding, endpointBinding) && measuredEndpoint.WindowId == endpointWindow.Id &&
            measuredEndpoint.StartedAt >= child.FinishedAt && measuredEndpoint.FinishedAt >= measuredEndpoint.StartedAt &&
            endpointTransport.HttpStatus == 200 && endpointTransport.Digest is not null &&
            measuredEndpoint.NativeRequestId == endpointTransport.RequestId);
        var networkBinding = observation.NetworkBinding = new N.Binding(childBinding, P.Canary, parent.Result.CanaryVersion!,
            parent.Result.CanarySha256!, N.Revision);
        string secretUri = "https://" + plan.VaultName + ".vault.azure.net/secrets/" + P.Canary + "/" +
            networkBinding.CanaryVersion + "?api-version=" + N.Revision;
        var privateTransport = new PrivateDeleteReadTransport(this, session, source.PrivateRuntime.Transport,
            secretUri, source.NetworkLimits.MaximumResponseBytes);
        var publicTransport = new PrivateDeleteReadTransport(this, session, source.PublicRuntime.Transport,
            secretUri, source.NetworkLimits.MaximumResponseBytes);
        session.Reads.Add(privateTransport);
        session.Reads.Add(publicTransport);
        var networkReader = new N(source.PrivateRuntime with { Transport = privateTransport },
            source.PublicRuntime with { Transport = publicTransport }, source.NetworkLimits, time);
        var networkWindow = observation.NetworkWindow = networkReader.Arm(networkBinding);
        var networkTask = observation.Network = networkReader.CollectAsync(networkWindow, networkBinding, token).AsTask();
        var network = await networkTask.ConfigureAwait(false);
        Require(ReferenceEquals(network.Binding, networkBinding) && network.WindowId == networkWindow.Id &&
            network.StartedAt >= measuredEndpoint.FinishedAt && network.FinishedAt >= network.StartedAt &&
            network.PrivateRead.Failure == N.Failure.None && network.PublicRead.Failure == N.Failure.None &&
            network.PrivateRead.Status == SecretStatus.Denied && network.PrivateRead.CanarySha256 is null &&
            network.PublicRead.Status == SecretStatus.Success &&
            network.PublicRead.CanarySha256 == networkBinding.CanarySha256 &&
            privateTransport.HttpStatus == 403 && publicTransport.HttpStatus == 200 &&
            network.PrivateRead.NativeRequestIds.Count == 1 && network.PublicRead.NativeRequestIds.Count == 1 &&
            network.PrivateRead.NativeRequestIds[0] == privateTransport.RequestId &&
            network.PublicRead.NativeRequestIds[0] == publicTransport.RequestId);
        token.ThrowIfCancellationRequested();
        provisioner.CheckPrivateConnectionDeleteLoan(loan);
        return new(loan, parentTask, parent, childBinding, childWindow, childTask, child, endpointBinding,
            endpointWindow, endpointTask, measuredEndpoint, networkBinding, networkWindow, networkTask,
            network, childTransport.Digest, endpointTransport.Digest, network.FinishedAt);
    }

    private static void RequirePrivateDeletePending(PrivateDeletePhase phase) =>
        Require(phase.Child.Status == SecretStatus.Success && phase.Child.Connections.Count == 1 &&
            phase.Child.Connections[0].State == PrivateConnectionState.Pending &&
            phase.Child.Connections[0].ProvisioningState == NativeProvisioningState.Succeeded &&
            phase.Endpoint.ManualConnectionState == "Pending");

    private V.Measurement ProjectPrivateDelete(PrivateConnectionDeleteSession session, PrivateDeletePhase phase)
    {
        var parent = phase.Parent.Result;
        var child = phase.Child.Connections.SingleOrDefault();
        string name = session.ConnectionId!.Split('/')[^1];
        return new(session.Plan!.LeaseId, session.Selector.Nonce, observerIdentity, phase.FinishedAt,
            session.Plan.VaultId, SecretStatus.Success, SecretStatus.Absent, parent.Configuration,
            parent.Configuration!.Policies, child?.State ?? PrivateConnectionState.Unknown, phase.Child.Status, [],
            new(name, phase.Network.PrivateRead.Status, phase.Network.PublicRead.Status,
                phase.Network.PrivateRead.NativeRequestIds[0]), [], [],
            child is null ? [] : [new(child.Name, child.State, child.ProvisioningState)], [], null);
    }

    private void FreezePrivateDeleteDenial(PrivateConnectionDeleteSession session)
    {
        if (!session.StartValid || session.Canceled || session.Outcome != SecretStatus.Denied ||
            session.Handle is not null || session.Receipt?.Evidence != DispatchEvidence.Rejected ||
            session.Window is null || session.Binding is null || session.StartTask is null ||
            !capture.TryGetPrivateConnectionDeleteDenied(session.Window, session.Binding, out var native) ||
            !capture.OwnsPrivateConnectionDeleteDenied(native, session.Window, session.Binding, session.Client!,
                session.Scope!, session.Receipt, session.StartTask)) return;
        Require(session.Finished is null && session.Post is not null &&
            session.Reads.All(r => r.Complete && (r.Parser is null || r.Parser is { Complete: true, Invalid: false })));
        Require(privateDeleteAdmissions.TryGetValue(session.Admission!, out var admission));
        session.Finished = new PrivateDeleteFinished.Denied(admission, session.Dispatch, session.Post, session.Client!, session.Scope!,
            session.Receipt, session.StartTask, session.Binding, session.Window, native);
    }

    private void FreezePrivateDeleteCompletion(PrivateConnectionDeleteSession session)
    {
        if (!session.StartValid || !session.PostValid || session.Canceled ||
            session.Selector.Case is not ("selected-contract" or "independent-effect") ||
            session.Outcome != SecretStatus.Success || session.Completion != SecretStatus.Success ||
            session.StartReceipt != DispatchEvidence.Pending || session.CheckReceipt != DispatchEvidence.Pending ||
            session.Receipt?.Evidence != DispatchEvidence.Pending ||
            session.Handle is not { State: NativeProvisioningState.Succeeded } ||
            session.Window is null || session.Binding is null || session.StartTask is null || session.CheckTask is null ||
            session.Baseline is not { } baseline || session.Post is not { } post || session.Loan is null ||
            !ReferenceEquals(baseline.Loan, post.Loan) || !ReferenceEquals(post.Loan, session.Loan) ||
            ReferenceEquals(baseline.ParentTask, post.ParentTask) ||
            ReferenceEquals(baseline.ChildTask, post.ChildTask) || ReferenceEquals(baseline.ChildWindow, post.ChildWindow) ||
            ReferenceEquals(baseline.EndpointTask, post.EndpointTask) || ReferenceEquals(baseline.EndpointWindow, post.EndpointWindow) ||
            ReferenceEquals(baseline.NetworkTask, post.NetworkTask) || ReferenceEquals(baseline.NetworkWindow, post.NetworkWindow) ||
            post.Child.Status != SecretStatus.Absent || post.Child.Connections.Count != 0 ||
            post.Endpoint.ManualConnectionState != "Disconnected" ||
            post.Parent.Result.CanaryVersion != baseline.Parent.Result.CanaryVersion ||
            post.Parent.Result.CanarySha256 != baseline.Parent.Result.CanarySha256 ||
            !session.Reads.All(r => r.Complete && (r.Parser is null || r.Parser is { Complete: true, Invalid: false })) ||
            !provisioner.OwnsPrivateConnectionDeleteAbsentRelationship(post.Parent, session.Loan, post.ParentTask) ||
            !capture.TryGetPrivateConnectionDeleteCandidate(session.Window, session.Binding, out var candidate) ||
            candidate.EndpointId != session.Plan!.PrivateEndpoint!.EndpointId ||
            !capture.OwnsPrivateConnectionDeleteCandidate(candidate, session.Window, session.Binding, session.Client!,
                session.Scope!, session.Receipt, session.StartTask, session.Handle) ||
            !capture.TryGetPrivateConnectionDeleteCompletion(candidate, session.Window, session.Binding, out var completion) ||
            !capture.OwnsPrivateConnectionDeleteCompletion(completion, session.Window, session.Binding, session.Client!,
                session.Scope!, session.Receipt, session.StartTask, session.Handle, session.CheckTask)) return;
        Require(session.Finished is null);
        Require(privateDeleteAdmissions.TryGetValue(session.Admission!, out var admission));
        Require(ReferenceEquals(admission.Baseline, baseline));
        session.Finished = new PrivateDeleteFinished.Deleted(admission, session.Dispatch, baseline, post,
            session.Client!, session.Scope!, session.Receipt, session.StartTask, session.CheckTask, session.Handle,
            session.StartReceipt.Value, session.CheckReceipt.Value, session.Binding, session.Window, candidate, completion);
    }

    private Task FinalizePrivateDelete(PrivateConnectionDeleteSession session)
    {
        TaskCompletionSource start;
        Task task;
        lock (gate)
        {
            if (session.Finalization is not null) return session.Finalization;
            start = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = session.Finalization = Finish(start.Task);
        }
        start.SetResult();
        return task;

        async Task Finish(Task ready)
        {
            await ready.ConfigureAwait(false);
            try
            {
                if (session.Window is not null) await capture.SealAsync(session.Window).ConfigureAwait(false);
                bool failed = false;
                foreach (var read in session.Reads)
                    try { read.Storage.Dispose(); }
                    catch (Exception) { failed = true; }
                Require(!failed);
            }
            catch { session.Finished = null; throw; }
            finally
            {
                if (session.Loan is { } loan)
                {
                    provisioner.ExitPrivateConnectionDelete(loan);
                    session.Loan = null;
                }
            }
            if (session.StartClaimed && session.StartFinished)
            {
                Require(session.StartTask is null || session.StartTask.IsCompleted);
                Require(session.CheckTask is null || session.CheckTask.IsCompleted);
                Require(privateDeleteAdmissions.TryGetValue(session.Admission!, out var admission));
                session.DrainEvidence = new(admission, session.Dispatch, session.StartTask, session.CheckTask);
            }
        }
    }

    private void RetryPrivateDeletePersistence(PrivateConnectionDeleteSession session)
    {
        if (session.Settled || session.DrainEvidence is not { } drained ||
            session.Finalization is not { IsCompletedSuccessfully: true }) return;
        var journal = provisioner.Journal;
        if (session.Finished is PrivateDeleteFinished.Deleted deleted && session.Certificates is null)
        {
            Require(ReferenceEquals(drained.Admission, deleted.Admission) && drained.Dispatch == deleted.Dispatch &&
                ReferenceEquals(drained.StartTask, deleted.StartTask) && ReferenceEquals(drained.CheckTask, deleted.CheckTask));
            PrivateDeleteCompletionRegistration? registration = null;
            PrivateConnectionDeleteCertificates? pair;
            try
            {
                pair = journal.RegisterPrivateConnectionDeleteCompletion(owner, session.Selector, session.Plan!.LeaseId,
                    session.Dispatch, () =>
                    {
                        registration = new(this, drained, deleted);
                        Require(privateDeleteCompletions.TryAdd(registration, registration));
                        return registration.Certificates;
                    });
            }
            catch
            {
                if (registration is not null) privateDeleteCompletions.TryRemove(registration, out _);
                throw;
            }
            if (pair is null) return;
            // Publish only the accepted pair, before either durable append.
            // Close may now win: these exact objects still own persistence retry.
            session.Certificates = pair;
            session.Termination = pair.Termination;
            session.Settlement = pair.Settlement;
        }
        if (session.Termination is null)
            _ = journal.RegisterPrivateConnectionDeleteTermination(owner, session.Selector, session.Plan!.LeaseId,
                session.Dispatch, () =>
                {
                    var certificate = new PrivateConnectionDeleteTermination(this, session.Dispatch);
                    Require(privateDeleteTerminations.TryAdd(certificate, drained));
                    return session.Termination = certificate;
                });
        if (session.Termination is null) return;
        if (!session.TerminationPersisted)
        {
            journal.EndPrivateConnectionDeleteInvocation(owner, session.Selector, session.Plan!.LeaseId, session.Termination);
            session.TerminationPersisted = true;
        }
        if (session.Finished is not { } finished) return;
        if (session.Settlement is null)
        {
            Require(finished is PrivateDeleteFinished.Denied);
            _ = journal.RegisterPrivateConnectionDeleteSettlement(owner, session.Selector, session.Plan!.LeaseId,
                session.Dispatch, () =>
                {
                    var certificate = new PrivateConnectionDeleteSettlement(this, session.Dispatch);
                    Require(privateDeleteSettlements.TryAdd(certificate, finished));
                    return session.Settlement = certificate;
                });
        }
        if (session.Settlement is null) return;
        _ = journal.SettlePrivateConnectionDeleteInvocation(owner, session.Selector, session.Plan!.LeaseId, session.Settlement);
        session.Settled = true;
    }

    private async Task<HttpResponseMessage> ReleasePrivateConnectionDelete(FixtureSelector selector, CancellationToken token)
    {
        ValidatePrivateDeleteSelector(selector);
        PrivateConnectionDeleteSession session;
        lock (gate)
        {
            Require(!disposed);
            if (!privateDeleteSessions.TryGetValue(selector.Nonce, out session!))
            {
                Require(privateDeleteSessions.Count < 32);
                privateDeleteSessions.Add(selector.Nonce, session = new(selector with { }));
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
                if (session.Active != 0) return Reply(PrivateDeleteReleaseMeasurement(session, snapshot));
            await FinalizePrivateDelete(session).ConfigureAwait(false);
            RetryPrivateDeletePersistence(session);
            snapshot = provisioner.Journal.Read(owner, selector);
            if (snapshot.Resources.Length != 0)
            {
                session.Plan ??= provisioner.OpenCleanupPlan(owner, selector);
                Require(session.Plan.OriginalPrivateConnectionDelete);
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
            return Reply(PrivateDeleteReleaseMeasurement(session, snapshot));
        }
        finally { lock (gate) session.Releasing = false; }
    }

    private static RoleFixtureRelease.Measurement PrivateDeleteReleaseMeasurement(
        PrivateConnectionDeleteSession session, J.Snapshot snapshot)
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

    private async Task DrainPrivateConnectionDelete(TaskCompletionSource completion)
    {
        bool failed = false;
        PrivateConnectionDeleteSession[] owned;
        lock (gate) owned = privateDeleteSessions.Values.ToArray();
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
                await FinalizePrivateDelete(session).ConfigureAwait(false);
                RetryPrivateDeletePersistence(session);
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

    private sealed class PrivateDeleteReadTransport(ManagementOperationFixtureObserverService source,
        PrivateConnectionDeleteSession session, HttpPipelineTransport backend, string exactUri, int maximum,
        PrivateConnectionScope? child = null) : HttpPipelineTransport
    {
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal OwnedArmResponse.ParserCustody? Parser;
        internal M.ConnectionRow? RawChild;
        internal string? Digest, RequestId;
        internal int HttpStatus;
        internal bool Complete;
        private readonly HashSet<Request> requests = new(ReferenceEqualityComparer.Instance);
        private int sends;
        public override Request CreateRequest()
        {
            source.provisioner.CheckPrivateConnectionDeleteLoan(session.Loan!);
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
            finally { if (message.HasResponse) Storage.Own(message.Response); }
            Check(message);
            Require(ReferenceEquals(request, message.Request) && headers.SequenceEqual(request.Headers));
            var body = await OwnedArmResponse.CaptureAsync(message, maximum, Storage).ConfigureAwait(false);
            Check(message);
            Require(ReferenceEquals(request, message.Request) && headers.SequenceEqual(request.Headers));
            HttpStatus = body.Response.Status;
            Digest = body.Sha256;
            RequestId = body.NativeRequestId;
            if (child is not null)
            {
                Require(HttpStatus is 200 or 404);
                if (HttpStatus == 200)
                    RawChild = C.ParsePrivateConnectionResource(child, body.Bytes,
                        body.Response.Headers.Select(h => (h.Name, h.Value)).ToArray(), HttpStatus);
                else
                    C.ValidatePrivateConnectionAbsentResponse(body.Bytes,
                        body.Response.Headers.Select(h => (h.Name, h.Value)).ToArray(), HttpStatus);
                // Collector and actual native error consumption independently
                // establish concrete 404; 204 is not accepted as absence here.
                Parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, Storage,
                    requireRebuffer: true);
            }
            Complete = true;
        }
        private void Check(HttpMessage message)
        {
            source.provisioner.CheckPrivateConnectionDeleteLoan(session.Loan!);
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
