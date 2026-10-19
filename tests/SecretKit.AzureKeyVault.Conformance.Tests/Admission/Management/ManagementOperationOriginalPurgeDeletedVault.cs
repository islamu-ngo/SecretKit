using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;
using Disposition = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.RoleFixtureJournal.PurgeDeletedVaultDisposition;
using P = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureProvisioner;
using S = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationStatusCollector;
using V = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal sealed partial class ManagementOperationFixtureObserverService
{
    internal sealed record PurgeDeletedVaultSource(
        [property: JsonIgnore] P Provisioner,
        [property: JsonIgnore] S.Authority StatusReader,
        [property: JsonIgnore] HttpPipelineTransport SelectedBackend,
        [property: JsonIgnore] S.Limits StatusLimits)
    {
        public override string ToString() => "[PurgeDeletedVaultSource]";
    }

    private readonly string? purgeConfiguration;
    private readonly Dictionary<Guid, PurgeSession> purgeSessions = [];

    internal ManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, P.HostScope scope, PurgeDeletedVaultSource source, Limits limits, TimeProvider? time = null)
        : this(origin, owner, observerIdentity, capability, scope, source.Provisioner, limits, time)
    {
        Require(source is not null && source.StatusReader is not null && source.SelectedBackend is not null &&
            source.StatusLimits is not null);
        purgeConfiguration = EncodeDeleteConfiguration(source.Provisioner.PurgeDeletedVaultBaseline(scope,
            source.StatusReader, source.SelectedBackend));
        profile = Profile.OriginalVaultPurge;
        nativeCapture = new(source.SelectedBackend, limits.MaximumReplyBytes);
        statusCollector = new(capture, new(source.StatusReader.Label, source.StatusReader.Credential,
            new OriginalVaultStatusTransport(this, source.StatusReader.Transport, source.StatusLimits.MaximumResponseBytes)),
            source.StatusLimits, this.time);
    }

    internal static ManagementOperationFixtureObserverService ForPurgeDeletedVaultCleanup(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, P.HostScope scope, P provisioner,
        Limits limits, TimeProvider? time = null) =>
        new(origin, owner, observerIdentity, capability, scope, provisioner, limits, time, Profile.PurgeDeletedVaultCleanup);

    private ManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, P.HostScope scope, P provisioner, Limits limits, TimeProvider? time, Profile profile)
        : this(origin, owner, observerIdentity, capability, scope, provisioner, limits, time) => this.profile = profile;

    internal sealed class PurgeDeletedVaultAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.purgeAdmissions.TryGetValue(this, out var evidence) && PurgeRoot(journal, snapshot, evidence.Root);
        public override string ToString() => "[PurgeDeletedVaultAdmission]";
    }

    internal sealed class PurgeDeletedVaultTermination(ManagementOperationFixtureObserverService source, Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.purgeTerminations.TryGetValue(this, out var evidence) && evidence.Dispatch == Dispatch &&
            Dispatch != Guid.Empty && PurgeRoot(journal, snapshot, evidence.Baseline.Root);
        public override string ToString() => "[PurgeDeletedVaultTermination]";
    }

    internal sealed class PurgeDeletedVaultSettlement(ManagementOperationFixtureObserverService source, Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal Disposition Disposition => source.purgeSettlements.TryGetValue(this, out var evidence)
            ? evidence.Decision.Disposition : throw Failure();
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.purgeSettlements.TryGetValue(this, out var evidence) && evidence.Finished.Dispatch == Dispatch &&
            Dispatch != Guid.Empty && PurgeRoot(journal, snapshot, evidence.Finished.Baseline.Root);
        public override string ToString() => "[PurgeDeletedVaultSettlement]";
    }

    private sealed record PurgeRootEvidence(RoleFixtureJournal Journal, string Owner, FixtureSelector Selector,
        Guid Lease, string VaultId, string DeletedId, string Configuration);
    private sealed record PurgeBaseline(PurgeRootEvidence Root, P.Plan Plan, P.PurgeDeletedVaultLoan Loan,
        Task<P.PurgeDeletedVaultWitness> Task, P.PurgeDeletedVaultWitness Witness, string DeletedDigest);
    private sealed record PurgeFinished(PurgeBaseline Baseline, Guid Dispatch, VaultAdministration? Client,
        DeletedVaultScope? Scope, ManagementReceipt? Receipt, Task? StartTask, Task? CheckTask,
        C.PurgeDeletedVaultStart? Native);
    private sealed record PurgeDecision(Task<P.PurgeDeletedVaultWitness> ParentTask, P.PurgeDeletedVaultWitness Parent,
        Task<S.Measurement>? StatusTask, S.Measurement? Status, Disposition Disposition);
    private sealed record PurgeCompleted(PurgeFinished Finished, PurgeDecision Decision);
    private readonly ConcurrentDictionary<PurgeDeletedVaultAdmission, PurgeBaseline> purgeAdmissions =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<PurgeDeletedVaultTermination, PurgeFinished> purgeTerminations =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<PurgeDeletedVaultSettlement, PurgeCompleted> purgeSettlements =
        new(ReferenceEqualityComparer.Instance);

    private sealed class PurgeSession(FixtureSelector selector) : OriginalVaultSession(selector)
    {
        internal P.Plan? Plan;
        internal P.PurgeDeletedVaultLoan? Loan;
        internal V.Lease? Lease;
        internal Guid Subscription, Dispatch;
        internal DateTimeOffset ArmedAt, StartedAt;
        internal bool Armed, BaselineClaimed, StartClaimed, StartFinished, PostClaimed, StartValid, Canceled;
        internal PurgeBaseline? Baseline;
        internal PurgeDeletedVaultAdmission? Admission;
        internal PurgeDeletedVaultTermination? Termination;
        internal PurgeDeletedVaultSettlement? Settlement;
        internal PurgeFinished? Finished;
        internal PurgeDecision? Decision;
        internal bool TerminationPersisted;
        internal C.Binding? Binding;
        internal C.Window? Window;
        internal C.PurgeDeletedVaultStart? Native;
        internal VaultAdministration? Client;
        internal DeletedVaultScope? Scope;
        internal ManagementReceipt? Receipt;
        internal ManagementOperation? Handle;
        internal Task? StartTask, CheckTask, Finalization;
        internal SecretStatus? Outcome;
        internal V.Measurement? Measurement;
    }

    private static bool PurgeRoot(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot, PurgeRootEvidence root) =>
        ReferenceEquals(journal, root.Journal) && snapshot.Owner == root.Owner && snapshot.Selector == root.Selector &&
        snapshot.LeaseId == root.Lease && snapshot.PurgeDeletedVault is { } purge &&
        purge.VaultId == root.VaultId && purge.DeletedVaultId == root.DeletedId &&
        EncodeDeleteConfiguration(purge.Baseline) == root.Configuration && snapshot.Settings is null &&
        snapshot.DeleteVault is null && snapshot.PrivateEndpoint is null && snapshot.Resources.Length == 3 &&
        snapshot.Resources.All(r => !r.Borrowed) &&
        snapshot.Resources.Count(r => r.Id == root.VaultId && !r.CleanupOnly && !r.SelectedAttempted && !r.DeleteAttempted) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.VaultId + "/secrets/" + P.Canary && r.CleanupOnly &&
            !r.CreateAttempted && !r.SelectedAttempted && !r.DeleteAttempted) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.DeletedId && !r.CleanupOnly) == 1;

    private V.Configuration PurgeConfiguration() =>
        JsonSerializer.Deserialize<V.Configuration>(purgeConfiguration ?? throw Failure(), Json) ?? throw Failure();

    private static void ValidatePurgeSelector(FixtureSelector selector) =>
        Require(selector is not null && selector.Nonce != Guid.Empty && P.PurgeDeletedVaultSelector(selector) &&
            new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }.All(v => Text(v, 512)));

    private Task<HttpResponseMessage> DispatchPurgeDeletedVault(string path, JsonElement body, CancellationToken token) =>
        path switch
        {
            "/vault/prepare" when profile == Profile.OriginalVaultPurge =>
                PreparePurgeDeletedVault(body.Deserialize<V.Prepare>(Json) ?? throw Failure(), token),
            "/vault/arm" when profile == Profile.OriginalVaultPurge =>
                Task.FromResult(ArmPurgeDeletedVault(body.Deserialize<ObserveLease>(Json) ?? throw Failure())),
            "/vault/observe" when profile == Profile.OriginalVaultPurge =>
                ObservePurgeDeletedVault(body.Deserialize<ObserveLease>(Json) ?? throw Failure(), token),
            "/vault/release" => ReleasePurgeDeletedVault(body.Deserialize<FixtureSelector>(Json) ?? throw Failure(), token),
            _ => Task.FromResult(Error(HttpStatusCode.NotFound))
        };

    private async Task<HttpResponseMessage> PreparePurgeDeletedVault(V.Prepare input, CancellationToken token)
    {
        ValidatePurgeSelector(input.Selection);
        Require(input.SubscriptionId == scope.SubscriptionId && input.ResourceGroup == scope.ResourceGroup &&
            input.Configuration is not null && V.SameConfiguration(input.Configuration, PurgeConfiguration()));
        PurgeSession session;
        lock (gate)
        {
            Require(!disposed && purgeSessions.Count < 32 && !purgeSessions.ContainsKey(input.Selection.Nonce));
            purgeSessions.Add(input.Selection.Nonce, session = new(input.Selection with { }) { Active = 1 });
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            lock (gate)
            {
                Require(!disposed && !session.Closed);
                session.Plan = provisioner.PlanFixture(owner, session.Selector, P.Preparation.Deleted, [], seedCanary: false);
            }
            var result = await provisioner.ProvisionAsync(session.Plan, cancellationToken: linked.Token).ConfigureAwait(false);
            Require(result.State == P.State.Ready && result.VaultPresent == false &&
                result.DeletedVaultPresent == true && result.Configuration is null && result.DeletedVault is not null);
            var snapshot = provisioner.Journal.Read(owner, session.Selector);
            lock (gate)
            {
                Require(!disposed && !session.Closed && snapshot.Idle && !snapshot.Closing &&
                    snapshot.PurgeDeletedVault is not null && snapshot.Resources.Length == 3);
                session.Lease = new(new(session.Selector.Nonce, session.Plan.LeaseId, observerIdentity,
                    S.ArmOrigin, "2026-02-01", time.GetUtcNow(), snapshot.Resources.Select(r => r.Id).ToArray()),
                    session.Plan.VaultName, null, P.Canary, "", PurgeConfiguration(), PrivateConnectionState.Unknown);
                return Reply(session.Lease);
            }
        }
        finally { LeaveOriginalVault(session); }
    }

    private PurgeSession FindPurge(Guid nonce, Guid lease)
    {
        Require(!disposed);
        Require(purgeSessions.TryGetValue(nonce, out var session));
        Require(!session.Closed &&
            session.Plan is not null && session.Lease is not null && session.Plan.LeaseId == lease);
        return session;
    }

    private HttpResponseMessage ArmPurgeDeletedVault(ObserveLease input)
    {
        lock (gate)
        {
            var session = FindPurge(input.Nonce, input.LeaseId);
            Require(!session.Armed && input.Phase == "subscribe-before-trigger" && input.SubscriptionId is null);
            session.ArmedAt = time.GetUtcNow();
            session.Subscription = Guid.NewGuid();
            session.Armed = true;
            return Reply(new ObservationSubscription(input.LeaseId, input.Nonce, session.Subscription, session.ArmedAt));
        }
    }

    private async Task<HttpResponseMessage> ObservePurgeDeletedVault(ObserveLease input, CancellationToken token)
    {
        PurgeSession session;
        bool baseline = input.Phase == "baseline-before-dispatch";
        lock (gate)
        {
            session = FindPurge(input.Nonce, input.LeaseId);
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
                    RetryPurgePersistence(session);
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
            if (!baseline) return await PostPurgeDeletedVault(session, linked.Token).ConfigureAwait(false);
            session.Loan = provisioner.EnterPurgeDeletedVault(session.Plan!);
            var task = provisioner.ObservePurgeDeletedVaultAsync(session.Loan, linked.Token);
            var witness = await task.ConfigureAwait(false);
            Require(provisioner.OwnsPurgeDeletedVaultWitness(witness, session.Loan, task) &&
                witness.Result.VaultPresent == false && witness.Result.DeletedVaultPresent == true &&
                witness.Result.Configuration is null && witness.DeletedDigest is not null &&
                witness.StartedAt >= session.ArmedAt);
            var root = new PurgeRootEvidence(provisioner.Journal, owner, session.Selector, session.Plan!.LeaseId,
                session.Plan.VaultId, session.Plan.DeletedId, purgeConfiguration!);
            var evidence = new PurgeBaseline(root, session.Plan, session.Loan, task, witness, witness.DeletedDigest);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !session.StartClaimed &&
                    !provisioner.Journal.Read(owner, session.Selector).Closing);
                var admission = new PurgeDeletedVaultAdmission(this);
                Require(purgeAdmissions.TryAdd(admission, evidence));
                session.Baseline = evidence;
                session.Admission = admission;
            }
            return Reply(ProjectPurge(session, witness));
        }
        finally { LeaveOriginalVault(session); }
    }

    public async ValueTask<SecretOutcome<ManagementOperation>> RunPurgeDeletedVaultAsync(FixtureSelector selector,
        VaultAdministration client, DeletedVaultScope originalScope, ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        Require(profile == Profile.OriginalVaultPurge);
        ValidatePurgeSelector(selector);
        PurgeSession session;
        lock (gate)
        {
            Require(purgeSessions.TryGetValue(selector.Nonce, out session!) && session.Selector == selector);
            _ = FindPurge(selector.Nonce, session.Plan?.LeaseId ?? Guid.Empty);
            Require(session.Armed && session.Baseline is not null && session.Admission is not null &&
                session.Loan is not null && !session.StartClaimed && client is not null && originalScope is not null &&
                originalScope.Subscription.SubscriptionId == scope.SubscriptionId && originalScope.Location == scope.Location &&
                originalScope.VaultName == session.Plan!.VaultName && receipt is not null);
            provisioner.CheckPurgeDeletedVaultLoan(session.Loan);
            session.Dispatch = provisioner.Journal.BeginPurgeDeletedVaultInvocation(owner, selector,
                session.Plan.LeaseId, session.Admission);
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
            Require(session.StartedAt >= session.Baseline!.Witness.FinishedAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, session.Stop.Token,
                lifetime.Token, deadline.Token);
            session.Binding = new(selector, session.Plan!.LeaseId, originalScope, ManagementMutation.PurgeDeletedVault,
                scope.Location, "2026-02-01");
            session.Window = capture.ArmPurgeDeletedVault(session.Binding);
            var result = await capture.StartPurgeDeletedVaultAsync(session.Window, selector, client, originalScope, receipt,
                linked.Token, task => session.StartTask = task,
                () => provisioner.Journal.AdmitPurgeDeletedVaultSend(owner, selector, session.Plan.LeaseId,
                    session.Dispatch, session.Admission!)).ConfigureAwait(false);
            session.Outcome = result.Status;
            session.Handle = result.IsSuccess ? result.Value : null;
            session.StartValid = !linked.IsCancellationRequested;
            if (capture.TryGetPurgeDeletedVaultStart(session.Window, session.Binding, out var native) &&
                capture.OwnsPurgeDeletedVaultStart(native, session.Window, session.Binding, client, originalScope,
                    receipt, session.StartTask!, session.Handle))
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

    private async Task<HttpResponseMessage> PostPurgeDeletedVault(PurgeSession session, CancellationToken token)
    {
        Task<S.Measurement>? statusTask = null;
        S.Measurement? status = null;
        try
        {
            Require(session.Loan is not null && session.Baseline is not null);
            var native = session.Native;
            bool positive = native is { HttpStatus: 202, Target: not null } && session.StartValid &&
                !session.Canceled && session.Outcome == SecretStatus.Success && session.Handle is not null &&
                session.Receipt!.Evidence == DispatchEvidence.Pending &&
                session.Selector.Case is "selected-contract" or "independent-effect";
            if (positive)
            {
                var read = new OriginalVaultStatusRead(native!.Target!);
                var previous = currentOriginalVaultStatus.Value;
                currentOriginalVaultStatus.Value = read;
                try
                {
                    var window = statuses.Arm(native.Target!, session.Binding!);
                    statusTask = statuses.CollectAsync(window, session.Binding!, token).AsTask();
                    status = await statusTask.ConfigureAwait(false);
                    Require(read.Complete && read.Sends == 1 && status.ResponseComplete && status.Terminal &&
                        status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
                        status.HttpStatus == 200 && Text(status.NativeRequestId, 256) &&
                        status.StartDispatch == native.Target!.StartDispatch &&
                        status.TargetSha256 == native.Target.TargetSha256 &&
                        status.StartResponseSha256 == native.Target.StartResponseSha256 &&
                        status.StartedAt >= session.StartedAt && status.FinishedAt >= status.StartedAt);
                }
                finally { currentOriginalVaultStatus.Value = previous; read.Storage.Dispose(); }
            }
            var parentTask = provisioner.ObservePurgeDeletedVaultAsync(session.Loan, token);
            var parent = await parentTask.ConfigureAwait(false);
            Require(provisioner.OwnsPurgeDeletedVaultWitness(parent, session.Loan, parentTask) &&
                parent.StartedAt >= (status?.FinishedAt ?? session.StartedAt));
            token.ThrowIfCancellationRequested();
            Disposition disposition = Disposition.None;
            if (positive && status is not null && parent.Result.VaultPresent == false &&
                parent.Result.DeletedVaultPresent == false)
            {
                Require(capture.OwnsPurgeDeletedVaultStart(native!, session.Window!, session.Binding!, session.Client!,
                    session.Scope!, session.Receipt!, session.StartTask!, session.Handle));
                var result = await capture.CheckStatusAsync(session.Window!, session.Selector, session.Handle!, token,
                    task => session.CheckTask = task).ConfigureAwait(false);
                Require(result == SecretStatus.Success && session.Receipt!.Evidence == DispatchEvidence.Pending &&
                    capture.OwnsPurgeDeletedVaultCompletion(native!, session.Window!, session.Binding!, session.Client!,
                        session.Scope!, session.Receipt!, session.StartTask!, session.Handle!, session.CheckTask!));
                disposition = Disposition.Purged;
            }
            else if (native is { HttpStatus: 403, Outcome: SecretStatus.Denied } && session.StartValid &&
                session.Selector.Case == "denied-authority" && session.Outcome == SecretStatus.Denied &&
                !session.Canceled && session.Handle is null && statusTask is null && session.CheckTask is null &&
                session.Receipt!.Evidence == DispatchEvidence.Rejected && parent.Result.VaultPresent == false &&
                parent.Result.DeletedVaultPresent == true && parent.Result.Configuration is null &&
                parent.DeletedDigest == session.Baseline.DeletedDigest)
            {
                Require(capture.OwnsPurgeDeletedVaultStart(native, session.Window!, session.Binding!, session.Client!,
                    session.Scope!, session.Receipt!, session.StartTask!, null));
                disposition = Disposition.Denied;
            }
            session.Measurement = ProjectPurge(session, parent);
            if (disposition != Disposition.None)
            {
                token.ThrowIfCancellationRequested();
                session.Decision = new(parentTask, parent, statusTask, status, disposition);
            }
        }
        finally { await FinalizePurgeBorrowers(session).ConfigureAwait(false); }
        token.ThrowIfCancellationRequested();
        lock (gate) RetryPurgePersistence(session);
        return Reply(session.Measurement ?? throw Failure());
    }

    private Task FinalizePurgeBorrowers(PurgeSession session)
    {
        lock (gate) return session.Finalization ??= Drain();
        async Task Drain()
        {
            try { if (session.Window is not null) await capture.SealAsync(session.Window).ConfigureAwait(false); }
            finally
            {
                if (session.Loan is { } loan)
                {
                    provisioner.ExitPurgeDeletedVault(loan);
                    session.Loan = null;
                }
            }
            if (session.Dispatch != Guid.Empty && session.Baseline is not null)
                session.Finished = new(session.Baseline, session.Dispatch, session.Client, session.Scope,
                    session.Receipt, session.StartTask, session.CheckTask, session.Native);
        }
    }

    // Actual borrower drainage is one-shot; all journal work is retryable and
    // uses the retained decision. A repeat never acquires credentials or reads.
    private void RetryPurgePersistence(PurgeSession session)
    {
        if (session.Finished is not { } finished) return;
        if (session.Termination is null)
        {
            if (disposed || session.Closed) return;
            session.Termination = provisioner.Journal.RegisterPurgeDeletedVaultTermination(owner,
                session.Selector, session.Plan!.LeaseId, session.Dispatch, () =>
                {
                    var termination = new PurgeDeletedVaultTermination(this, session.Dispatch);
                    Require(purgeTerminations.TryAdd(termination, finished));
                    return termination;
                });
            if (session.Termination is null) return;
        }
        if (!session.TerminationPersisted)
        {
            provisioner.Journal.EndPurgeDeletedVaultInvocation(owner, session.Selector, session.Plan!.LeaseId,
                session.Termination);
            session.TerminationPersisted = true;
        }
        if (session.Settlement is null && session.Decision is { } decision)
        {
            if (disposed || session.Closed || provisioner.Journal.Read(owner, session.Selector).Closing) return;
            var settlement = new PurgeDeletedVaultSettlement(this, session.Dispatch);
            Require(purgeSettlements.TryAdd(settlement, new(finished, decision)));
            session.Settlement = settlement;
        }
        if (session.Settlement is null) return;
        provisioner.Journal.RegisterPurgeDeletedVaultSettlement(owner, session.Selector, session.Plan!.LeaseId, session.Settlement);
        provisioner.Journal.SettlePurgeDeletedVaultInvocation(owner, session.Selector, session.Plan.LeaseId, session.Settlement);
    }

    private V.Measurement ProjectPurge(PurgeSession session, P.PurgeDeletedVaultWitness witness) =>
        new(session.Plan!.LeaseId, session.Selector.Nonce, observerIdentity, witness.FinishedAt, session.Plan.VaultId,
            witness.Result.VaultPresent == true ? SecretStatus.Success : SecretStatus.Absent,
            witness.Result.DeletedVaultPresent == true ? SecretStatus.Success : SecretStatus.Absent,
            witness.Result.Configuration, witness.Result.Configuration?.Policies ?? [], PrivateConnectionState.Unknown,
            witness.Result.VaultPresent == false ? SecretStatus.Absent : SecretStatus.Unknown,
            [], null, [], witness.Result.DeletedVault is { } deleted ? [deleted] : [], [], [], null);

    private async Task<HttpResponseMessage> ReleasePurgeDeletedVault(FixtureSelector selector, CancellationToken token)
    {
        ValidatePurgeSelector(selector);
        PurgeSession session;
        lock (gate)
        {
            Require(!disposed);
            if (!purgeSessions.TryGetValue(selector.Nonce, out session!))
            {
                Require(purgeSessions.Count < 32);
                purgeSessions.Add(selector.Nonce, session = new(selector with { }));
            }
            Require(session.Selector == selector && !session.Releasing);
            session.Releasing = true;
        }
        try
        {
            RoleFixtureJournal.Snapshot snapshot;
            try { snapshot = provisioner.CloseSelectedRoot(owner, selector); }
            finally { ClosePurgeSession(session); }
            lock (gate)
                if (session.Active != 0) return Reply(PurgeReleaseMeasurement(session, snapshot));
            await FinalizePurgeBorrowers(session).ConfigureAwait(false);
            lock (gate) RetryPurgePersistence(session);
            snapshot = provisioner.Journal.Read(owner, selector);
            if (snapshot.Idle && snapshot.Resources.Length != 0)
                snapshot = (await provisioner.ReleaseAsync(owner, selector, purge: true,
                    cancellationToken: token).ConfigureAwait(false)).Journal;
            return Reply(PurgeReleaseMeasurement(session, snapshot));
        }
        finally { lock (gate) session.Releasing = false; }
    }

    private static RoleFixtureRelease.Measurement PurgeReleaseMeasurement(PurgeSession session, RoleFixtureJournal.Snapshot snapshot)
    {
        string[] owned = snapshot.Resources.Where(r => !r.Borrowed).Select(r => r.Id).ToArray();
        string[] absent = snapshot.Resources.Where(r => !r.Borrowed && r.Absent && r.ActiveDispatch == Guid.Empty)
            .Select(r => r.Id).ToArray();
        return new(session.Selector, snapshot.Closing, session.Active + snapshot.Resources.Count(r => r.ActiveDispatch != Guid.Empty),
            owned, [], absent, owned.Except(absent, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private void ClosePurgeSession(PurgeSession session)
    {
        lock (gate)
        {
            session.Closed = true;
            if (session.Active == 0) session.Drained.TrySetResult();
        }
        try { session.Stop.Cancel(); }
        catch (Exception) { }
    }

    private async Task DrainPurgeDeletedVault(TaskCompletionSource completion)
    {
        bool failed = false;
        PurgeSession[] owned;
        lock (gate) owned = purgeSessions.Values.ToArray();
        foreach (var session in owned)
        {
            try { provisioner.CloseSelectedRoot(owner, session.Selector); }
            catch (Exception) { failed = true; }
            ClosePurgeSession(session);
        }
        try { lifetime.Cancel(); }
        catch (Exception) { failed = true; }
        await drained.Task.ConfigureAwait(false);
        foreach (var session in owned)
        {
            try
            {
                await session.Drained.Task.ConfigureAwait(false);
                await FinalizePurgeBorrowers(session).ConfigureAwait(false);
                lock (gate) RetryPurgePersistence(session);
            }
            catch (Exception) { failed = true; }
            session.Stop.Dispose();
        }
        lifetime.Dispose();
        if (failed) completion.TrySetException(Failure());
        else completion.TrySetResult();
    }
}
