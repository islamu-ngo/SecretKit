using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;
using J = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.RoleFixtureJournal;
using P = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureProvisioner;
using S = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationStatusCollector;
using V = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal sealed partial class ManagementOperationFixtureObserverService
{
    internal sealed record RecoverVaultSource(
        [property: JsonIgnore] P Provisioner,
        [property: JsonIgnore] S.Authority StatusReader,
        [property: JsonIgnore] HttpPipelineTransport SelectedBackend,
        [property: JsonIgnore] S.Limits StatusLimits)
    {
        public override string ToString() => "[RecoverVaultSource]";
    }

    private readonly string? recoverBaselineConfiguration, recoverSelectedConfiguration;
    private readonly Dictionary<Guid, RecoverVaultSession> recoverVaultSessions = [];

    internal ManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, P.HostScope scope, RecoverVaultSource source, Limits limits,
        TimeProvider? time = null)
        : this(origin, owner, observerIdentity, capability, scope, source.Provisioner, limits, time)
    {
        Require(source.StatusReader is not null && source.SelectedBackend is not null && source.StatusLimits is not null);
        var configurations = source.Provisioner.RecoverVaultConfigurations(scope, source.StatusReader, source.SelectedBackend);
        Require(V.ConfigurationVariants.Contains(configurations.Variant));
        recoverBaselineConfiguration = EncodeDeleteConfiguration(configurations.Baseline);
        recoverSelectedConfiguration = EncodeDeleteConfiguration(configurations.Selected);
        profile = Profile.OriginalVaultRecover;
        nativeCapture = new(source.SelectedBackend, limits.MaximumReplyBytes);
        statusCollector = new(capture, new(source.StatusReader.Label, source.StatusReader.Credential,
            new OriginalVaultStatusTransport(this, source.StatusReader.Transport, source.StatusLimits.MaximumResponseBytes)),
            source.StatusLimits, this.time);
    }

    internal static ManagementOperationFixtureObserverService ForRecoverVaultCleanup(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, P.HostScope scope, P provisioner, Limits limits,
        TimeProvider? time = null) =>
        new(origin, owner, observerIdentity, capability, scope, provisioner, limits, time, Profile.RecoverVaultCleanup);

    internal sealed class RecoverVaultAdmission(ManagementOperationFixtureObserverService source)
    {
        internal string DeletedDigest => source.recoverAdmissions.TryGetValue(this, out var evidence) ? evidence.Digest : throw Failure();
        internal bool Validate(J journal, J.Snapshot snapshot) =>
            source.recoverAdmissions.TryGetValue(this, out var evidence) && RecoverRoot(journal, snapshot, evidence.Root) &&
            (snapshot.RecoverVault!.InvocationDispatch == Guid.Empty ? snapshot.RecoverVault.DeletedBaselineSha256 is null :
                snapshot.RecoverVault.DeletedBaselineSha256 == evidence.Digest);
        public override string ToString() => "[RecoverVaultAdmission]";
    }
    internal sealed class RecoverVaultTermination(ManagementOperationFixtureObserverService source, Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(J journal, J.Snapshot snapshot) =>
            source.recoverTerminations.TryGetValue(this, out var evidence) && evidence.Dispatch == Dispatch &&
            Dispatch != Guid.Empty && RecoverRoot(journal, snapshot, evidence.Baseline.Root) &&
            snapshot.RecoverVault!.InvocationDispatch == Dispatch && snapshot.RecoverVault.DeletedBaselineSha256 == evidence.Baseline.Digest;
        public override string ToString() => "[RecoverVaultTermination]";
    }
    internal sealed class RecoverVaultSettlement(ManagementOperationFixtureObserverService source, Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal J.RecoverVaultDisposition Disposition =>
            source.recoverSettlements.TryGetValue(this, out var evidence) ? evidence.Decision.Disposition : throw Failure();
        internal V.Configuration Configuration =>
            source.recoverSettlements.TryGetValue(this, out var evidence)
                ? DecodeRecoverConfiguration(evidence.Decision.Configuration) : throw Failure();
        internal bool Validate(J journal, J.Snapshot snapshot) =>
            source.recoverSettlements.TryGetValue(this, out var evidence) && evidence.Finished.Dispatch == Dispatch &&
            Dispatch != Guid.Empty && RecoverRoot(journal, snapshot, evidence.Finished.Baseline.Root) &&
            snapshot.RecoverVault!.InvocationDispatch == Dispatch &&
            snapshot.RecoverVault.DeletedBaselineSha256 == evidence.Finished.Baseline.Digest;
        public override string ToString() => "[RecoverVaultSettlement]";
    }

    private sealed record RecoverRootEvidence(J Journal, string Owner, FixtureSelector Selector, Guid Lease,
        string VaultId, string DeletedId, string Baseline, string Selected);
    private sealed record RecoverBaseline(RecoverRootEvidence Root, P.Plan Plan, P.RecoverVaultLoan Loan,
        Task<P.RecoverVaultWitness> Task, P.RecoverVaultWitness Witness, string Digest);
    private sealed record RecoverFinished(RecoverBaseline Baseline, Guid Dispatch, VaultAdministration? Client,
        VaultScope? Scope, VaultConfiguration? Configuration, ManagementReceipt? Receipt, Task? StartTask,
        ManagementOperation? Handle, Task? CheckTask, C.RecoverVaultStart? Native);
    private sealed record RecoverDecision(Task<P.RecoverVaultWitness> ParentTask,
        P.RecoverVaultWitness Parent, Task<S.Measurement>? StatusTask, S.Measurement? Status,
        J.RecoverVaultDisposition Disposition, string Configuration);
    private sealed record RecoverCompleted(RecoverFinished Finished, RecoverDecision Decision);
    private readonly ConcurrentDictionary<RecoverVaultAdmission, RecoverBaseline> recoverAdmissions =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<RecoverVaultTermination, RecoverFinished> recoverTerminations =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<RecoverVaultSettlement, RecoverCompleted> recoverSettlements =
        new(ReferenceEqualityComparer.Instance);

    private sealed class RecoverVaultSession(ManagementOperationFixtureObserverService source, FixtureSelector selector)
        : ConfigurationVaultSession(selector)
    {
        internal P.RecoverVaultLoan? Loan;
        internal RecoverBaseline? Baseline;
        internal RecoverVaultAdmission? Admission;
        internal RecoverVaultTermination? Termination;
        internal RecoverVaultSettlement? Settlement;
        internal RecoverFinished? Finished;
        internal RecoverDecision? Decision;
        internal C.RecoverVaultStart? Native;
        internal Task<P.RecoverVaultWitness>? ParentTask;
        internal P.RecoverVaultWitness? Parent;
        internal override ManagementMutation Operation => ManagementMutation.RecoverVault;
        internal override DateTimeOffset BaselineFinishedAt => Baseline!.Witness.FinishedAt;
        internal override int? HttpStatus => Native?.HttpStatus;
        internal override SecretStatus? NativeOutcome => Native?.Outcome;
        internal override C.StatusTarget? Target => Native?.Target;
        internal override V.Configuration SelectedConfiguration => source.RecoverSelectedConfiguration();
        internal override bool ParentMatchesSelected => ParentTask is not null && Parent?.Result.VaultPresent == true &&
            Parent.Result.DeletedVaultPresent == false &&
            Parent.ActiveDigest is not null && Parent.Result.Configuration is { } configuration &&
            V.SameConfiguration(configuration, SelectedConfiguration);
        internal override bool DenialMatches => Parent?.DeletedDigest == Baseline!.Digest && Parent?.Result.VaultPresent == false &&
            Parent.Result.DeletedVaultPresent == true && Parent.Result.Configuration is null;
        internal override void Reserve()
        {
            Require(Baseline is not null && Admission is not null && Loan is not null);
            CheckLoan();
            Dispatch = source.provisioner.Journal.BeginRecoverVaultInvocation(source.owner, Selector, Plan!.LeaseId, Admission);
        }
        internal override void CheckLoan() => source.provisioner.CheckRecoverVaultLoan(Loan!);
        internal override async Task<SecretOutcome<ManagementOperation>> Start(CancellationToken token)
        {
            Window = source.capture.ArmRecoverVault(Binding!);
            var result = await source.capture.StartRecoverVaultAsync(Window, Selector, Client!, Scope!, Configuration!,
                Receipt!, token, task => StartTask = task,
                () => source.provisioner.Journal.AdmitRecoverVaultSend(source.owner, Selector, Plan!.LeaseId,
                    Dispatch, Admission!)).ConfigureAwait(false);
            Handle = result.IsSuccess ? result.Value : null;
            if (source.capture.TryGetRecoverVaultStart(Window, Binding!, out var native) &&
                source.capture.OwnsRecoverVaultStart(native, Window, Binding!, Client!, Scope!, Configuration!,
                    Receipt!, StartTask!, Handle)) Native = native;
            return result;
        }
        internal override bool OwnsStart() => source.capture.OwnsRecoverVaultStart(Native!, Window!, Binding!,
            Client!, Scope!, Configuration!, Receipt!, StartTask!, Handle);
        internal override bool OwnsCompletion() => source.capture.OwnsRecoverVaultCompletion(Native!, Window!, Binding!,
            Client!, Scope!, Configuration!, Receipt!, StartTask!, Handle!, CheckTask!);
        internal override async Task ObserveParent(CancellationToken token)
        {
            Require(Loan is not null && Baseline is not null);
            ParentTask = source.provisioner.ObserveRecoverVaultAsync(Loan, token);
            Parent = await ParentTask.ConfigureAwait(false);
            Require(source.provisioner.OwnsRecoverVaultWitness(Parent, Loan, ParentTask) &&
                Parent.StartedAt >= (Status?.FinishedAt ?? StartedAt));
            Measurement = source.ProjectRecoverVault(this, Parent);
        }
        internal override void Decide(bool positive) => Decision = new(ParentTask!, Parent!, StatusTask, Status,
            positive ? J.RecoverVaultDisposition.Recovered : J.RecoverVaultDisposition.Denied,
            positive ? source.recoverSelectedConfiguration! : source.recoverBaselineConfiguration!);
        internal override void ExitLoan()
        {
            if (Loan is not { } loan) return;
            source.provisioner.ExitRecoverVault(loan);
            Loan = null;
        }
        internal override void FreezeFinished()
        {
            if (Dispatch != Guid.Empty && Baseline is not null)
                Finished = new(Baseline, Dispatch, Client, Scope, Configuration, Receipt, StartTask, Handle, CheckTask, Native);
        }
        internal override void RetrySettlement() => source.RetryRecoverVaultSettlement(this);
    }

    private static V.Configuration DecodeRecoverConfiguration(string value) =>
        JsonSerializer.Deserialize<V.Configuration>(value, Json) ?? throw Failure();
    private V.Configuration RecoverBaselineConfiguration() => DecodeRecoverConfiguration(recoverBaselineConfiguration ?? throw Failure());
    private V.Configuration RecoverSelectedConfiguration() => DecodeRecoverConfiguration(recoverSelectedConfiguration ?? throw Failure());
    private static void ValidateRecoverSelector(FixtureSelector selector) =>
        Require(selector is not null && selector.Nonce != Guid.Empty && P.RecoverVaultSelector(selector) &&
            new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }.All(v => Text(v, 512)));

    private static bool RecoverRoot(J journal, J.Snapshot snapshot, RecoverRootEvidence root) =>
        ReferenceEquals(journal, root.Journal) && snapshot.Owner == root.Owner && snapshot.Selector == root.Selector &&
        snapshot.LeaseId == root.Lease && snapshot.RecoverVault is { } recovery &&
        recovery.VaultId == root.VaultId && recovery.DeletedVaultId == root.DeletedId &&
        EncodeDeleteConfiguration(recovery.Baseline) == root.Baseline &&
        EncodeDeleteConfiguration(recovery.Selected) == root.Selected &&
        snapshot.CreateOrUpdateVault is null && snapshot.Settings is null && snapshot.DeleteVault is null && snapshot.PurgeDeletedVault is null &&
        snapshot.PrivateEndpoint is null && snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed) &&
        snapshot.Resources.Count(r => r.Id == root.VaultId && !r.CleanupOnly) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.VaultId + "/secrets/" + P.Canary && r.CleanupOnly &&
            !r.CreateAttempted && !r.SelectedAttempted) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.DeletedId && !r.CleanupOnly && r.CreateAttempted &&
            r.InvocationTerminated && !r.SelectedAttempted) == 1;

    private Task<HttpResponseMessage> DispatchRecoverVault(string path, JsonElement body, CancellationToken token) =>
        path switch
        {
            "/vault/prepare" when profile == Profile.OriginalVaultRecover =>
                PrepareRecoverVault(body.Deserialize<V.Prepare>(Json) ?? throw Failure(), token),
            "/vault/arm" when profile == Profile.OriginalVaultRecover =>
                Task.FromResult(ArmRecoverVault(body.Deserialize<ObserveLease>(Json) ?? throw Failure())),
            "/vault/observe" when profile == Profile.OriginalVaultRecover =>
                ObserveRecoverVault(body.Deserialize<ObserveLease>(Json) ?? throw Failure(), token),
            "/vault/release" => ReleaseRecoverVault(body.Deserialize<FixtureSelector>(Json) ?? throw Failure(), token),
            _ => Task.FromResult(Error(HttpStatusCode.NotFound))
        };

    private async Task<HttpResponseMessage> PrepareRecoverVault(V.Prepare input, CancellationToken token)
    {
        ValidateRecoverSelector(input.Selection);
        Require(input.SubscriptionId == scope.SubscriptionId && input.ResourceGroup == scope.ResourceGroup &&
            input.Configuration is not null && V.SameConfiguration(input.Configuration, RecoverSelectedConfiguration()));
        RecoverVaultSession session;
        lock (gate)
        {
            Require(!disposed && recoverVaultSessions.Count < 32 && !recoverVaultSessions.ContainsKey(input.Selection.Nonce));
            session = new(this, input.Selection with { }) { Active = 1 };
            recoverVaultSessions.Add(session.Selector.Nonce, session);
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
            Require(result.State == P.State.Ready && result.VaultPresent == false && result.DeletedVaultPresent == true &&
                result.Configuration is null && result.DeletedVault is not null);
            var snapshot = provisioner.Journal.Read(owner, session.Selector);
            DateTimeOffset observed = time.GetUtcNow();
            lock (gate)
            {
                Require(!disposed && !session.Closed && snapshot.Idle && !snapshot.Closing && snapshot.RecoverVault is not null);
                session.Lease = new(new(session.Selector.Nonce, session.Plan.LeaseId, observerIdentity, S.ArmOrigin,
                    "2026-02-01", observed, snapshot.Resources.Select(r => r.Id).ToArray()),
                    session.Plan.VaultName, null, P.Canary, "", RecoverBaselineConfiguration(), PrivateConnectionState.Unknown);
                return Reply(session.Lease);
            }
        }
        finally { LeaveOriginalVault(session); }
    }

    private RecoverVaultSession FindRecoverVault(Guid nonce, Guid lease)
    {
        Require(!disposed);
        Require(recoverVaultSessions.TryGetValue(nonce, out var session));
        Require(!session.Closed && session.Plan is not null && session.Lease is not null && session.Plan.LeaseId == lease);
        return session;
    }
    private HttpResponseMessage ArmRecoverVault(ObserveLease input)
    {
        lock (gate)
        {
            var session = FindRecoverVault(input.Nonce, input.LeaseId);
            Require(!session.Armed && input.Phase == "subscribe-before-trigger" && input.SubscriptionId is null);
            session.ArmedAt = time.GetUtcNow();
            session.Subscription = Guid.NewGuid();
            session.Armed = true;
            return Reply(new ObservationSubscription(input.LeaseId, input.Nonce, session.Subscription, session.ArmedAt));
        }
    }

    private async Task<HttpResponseMessage> ObserveRecoverVault(ObserveLease input, CancellationToken token)
    {
        RecoverVaultSession session;
        bool baseline = input.Phase == "baseline-before-dispatch";
        lock (gate)
        {
            session = FindRecoverVault(input.Nonce, input.LeaseId);
            Require(session.Armed && input.SubscriptionId == session.Subscription);
            if (baseline)
            {
                Require(!session.BaselineClaimed && !session.StartClaimed);
                session.BaselineClaimed = true;
            }
            else
            {
                Require(input.Phase == "post-operation" && session.StartFinished);
                Require(session.Active == 0);
                if (session.Measurement is not null)
                {
                    RetryRecoverVaultSettlement(session);
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
            if (!baseline) return await PostConfigurationVault(session, linked.Token).ConfigureAwait(false);
            session.Loan = provisioner.EnterRecoverVault(session.Plan!);
            var task = provisioner.ObserveRecoverVaultAsync(session.Loan, linked.Token);
            var witness = await task.ConfigureAwait(false);
            Require(provisioner.OwnsRecoverVaultWitness(witness, session.Loan, task) &&
                witness.DeletedDigest is not null && witness.StartedAt >= session.ArmedAt &&
                witness.Result.VaultPresent == false && witness.Result.DeletedVaultPresent == true && witness.Result.Configuration is null);
            var root = new RecoverRootEvidence(provisioner.Journal, owner, session.Selector, session.Plan!.LeaseId,
                session.Plan.VaultId, session.Plan.DeletedId, recoverBaselineConfiguration!, recoverSelectedConfiguration!);
            var evidence = new RecoverBaseline(root, session.Plan, session.Loan, task, witness, witness.DeletedDigest);
            var admission = new RecoverVaultAdmission(this);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !session.StartClaimed && recoverAdmissions.TryAdd(admission, evidence));
                session.Baseline = evidence;
                session.Admission = admission;
            }
            return Reply(ProjectRecoverVault(session, witness));
        }
        finally { LeaveOriginalVault(session); }
    }

    public ValueTask<SecretOutcome<ManagementOperation>> RunRecoverVaultAsync(FixtureSelector selector,
        VaultAdministration client, VaultScope originalScope, VaultConfiguration configuration, ManagementReceipt receipt,
        CancellationToken cancellationToken)
    {
        Require(profile == Profile.OriginalVaultRecover);
        ValidateRecoverSelector(selector);
        RecoverVaultSession session;
        lock (gate)
        {
            Require(recoverVaultSessions.TryGetValue(selector.Nonce, out session!) && session.Selector == selector);
            _ = FindRecoverVault(selector.Nonce, session.Plan?.LeaseId ?? Guid.Empty);
        }
        return RunConfigurationVault(session, client, originalScope, configuration, receipt, cancellationToken);
    }

    public ValueTask<SecretStatus> CompleteRecoverVaultAsync(FixtureSelector selector,
        ManagementOperation originalHandle, CancellationToken cancellationToken)
    {
        Require(profile == Profile.OriginalVaultRecover);
        ValidateRecoverSelector(selector);
        RecoverVaultSession session;
        lock (gate)
        {
            Require(recoverVaultSessions.TryGetValue(selector.Nonce, out session!) && session.Selector == selector);
            _ = FindRecoverVault(selector.Nonce, session.Plan?.LeaseId ?? Guid.Empty);
        }
        return CompleteConfigurationVault(session, originalHandle, cancellationToken);
    }

    private void RetryRecoverVaultSettlement(RecoverVaultSession session)
    {
        lock (gate)
        {
            if (!session.Finalized || session.Finished is not { } finished) return;
            var journal = provisioner.Journal;
            session.Termination ??= journal.RegisterRecoverVaultTermination(owner, session.Selector, session.Plan!.LeaseId,
                session.Dispatch, () =>
                {
                    var certificate = new RecoverVaultTermination(this, session.Dispatch);
                    Require(recoverTerminations.TryAdd(certificate, finished));
                    return certificate;
                });
            if (session.Termination is null) return;
            if (!session.TerminationPersisted)
            {
                journal.EndRecoverVaultInvocation(owner, session.Selector, session.Plan!.LeaseId, session.Termination);
                session.TerminationPersisted = true;
            }
            if (session.Decision is not { } decision) return;
            session.Settlement ??= journal.RegisterRecoverVaultSettlement(owner, session.Selector, session.Plan!.LeaseId,
                session.Dispatch, () =>
                {
                    var certificate = new RecoverVaultSettlement(this, session.Dispatch);
                    Require(recoverSettlements.TryAdd(certificate, new(finished, decision)));
                    return certificate;
                });
            if (session.Settlement is null) return;
            journal.RegisterRecoverVaultSettlement(owner, session.Selector, session.Plan!.LeaseId, session.Settlement);
            journal.SettleRecoverVaultInvocation(owner, session.Selector, session.Plan.LeaseId, session.Settlement);
        }
    }

    private V.Measurement ProjectRecoverVault(RecoverVaultSession session, P.RecoverVaultWitness witness) =>
        new(session.Plan!.LeaseId, session.Selector.Nonce, observerIdentity, witness.FinishedAt, session.Plan.VaultId,
            witness.Result.VaultPresent == true ? SecretStatus.Success : SecretStatus.Absent,
            witness.Result.DeletedVaultPresent == true ? SecretStatus.Success : SecretStatus.Absent,
            witness.Result.Configuration, witness.Result.Configuration?.Policies ?? [],
            PrivateConnectionState.Unknown, SecretStatus.Absent, [], null, [], [], [], [], null);

    private async Task<HttpResponseMessage> ReleaseRecoverVault(FixtureSelector selector, CancellationToken token)
    {
        ValidateRecoverSelector(selector);
        RecoverVaultSession session;
        lock (gate)
        {
            Require(!disposed);
            if (!recoverVaultSessions.TryGetValue(selector.Nonce, out session!))
            {
                Require(recoverVaultSessions.Count < 32);
                recoverVaultSessions.Add(selector.Nonce, session = new(this, selector with { }));
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
                if (session.Active != 0) return Reply(RecoverVaultReleaseMeasurement(session, snapshot));
            await FinalizeConfigurationVault(session).ConfigureAwait(false);
            RetryRecoverVaultSettlement(session);
            snapshot = provisioner.Journal.Read(owner, selector);
            Require(snapshot.Resources.Length == 0 || snapshot.RecoverVault is not null);
            if (snapshot.Idle && snapshot.Resources.Length != 0)
                snapshot = (await provisioner.ReleaseAsync(owner, selector, purge: true, cancellationToken: token).ConfigureAwait(false)).Journal;
            return Reply(RecoverVaultReleaseMeasurement(session, snapshot));
        }
        finally { lock (gate) session.Releasing = false; }
    }

    private static RoleFixtureRelease.Measurement RecoverVaultReleaseMeasurement(RecoverVaultSession session, J.Snapshot snapshot)
    {
        string[] owned = snapshot.Resources.Where(r => !r.Borrowed).Select(r => r.Id).ToArray();
        string[] absent = snapshot.Resources.Where(r => !r.Borrowed && r.Absent && r.ActiveDispatch == Guid.Empty).Select(r => r.Id).ToArray();
        return new(session.Selector, snapshot.Closing, session.Active + snapshot.Resources.Count(r => r.ActiveDispatch != Guid.Empty),
            owned, [], absent, owned.Except(absent, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private Task DrainRecoverVault(TaskCompletionSource completion)
    {
        lock (gate) return DrainConfigurationVault(recoverVaultSessions.Values.ToArray(), completion);
    }
}
