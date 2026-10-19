using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;
using P = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureProvisioner;
using S = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationStatusCollector;
using V = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal sealed partial class ManagementOperationFixtureObserverService
{
    private enum Profile
    {
        StatusFamily, OriginalVaultDelete, DeleteVaultCleanup, OriginalVaultPurge, PurgeDeletedVaultCleanup,
        OriginalVaultCreateOrUpdate, CreateOrUpdateVaultCleanup, OriginalVaultRecover, RecoverVaultCleanup,
        OriginalPrivateConnectionUpdate, PrivateConnectionUpdateCleanup,
        OriginalPrivateConnectionDelete, PrivateConnectionDeleteCleanup
    }
    private readonly Profile profile;
    private readonly string? deleteConfiguration;
    private readonly Dictionary<Guid, DeleteSession> deleteSessions = [];
    private readonly AsyncLocal<OriginalVaultStatusRead?> currentOriginalVaultStatus = new();

    internal sealed record DeleteVaultSource(
        [property: JsonIgnore] P Provisioner,
        [property: JsonIgnore] S.Authority StatusReader,
        [property: JsonIgnore] HttpPipelineTransport SelectedBackend,
        [property: JsonIgnore] S.Limits StatusLimits)
    {
        public override string ToString() => "[DeleteVaultSource]";
    }

    internal ManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, P.HostScope scope, DeleteVaultSource source, Limits limits, TimeProvider? time = null)
        : this(origin, owner, observerIdentity, capability, scope, source.Provisioner, limits, time)
    {
        Require(source is not null && source.StatusReader is not null && source.SelectedBackend is not null &&
            source.StatusLimits is not null);
        deleteConfiguration = EncodeDeleteConfiguration(source.Provisioner.DeleteVaultBaseline(scope,
            source.StatusReader, source.SelectedBackend));
        profile = Profile.OriginalVaultDelete;
        nativeCapture = new(source.SelectedBackend, limits.MaximumReplyBytes);
        statusCollector = new(capture, new(source.StatusReader.Label, source.StatusReader.Credential,
            new OriginalVaultStatusTransport(this, source.StatusReader.Transport, source.StatusLimits.MaximumResponseBytes)),
            source.StatusLimits, this.time);
    }

    private ManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, P.HostScope scope, P provisioner, Limits limits, TimeProvider? time)
    {
        Require(origin is
        {
            IsAbsoluteUri: true, Scheme: "https", AbsolutePath: "/",
            UserInfo.Length: 0, Query.Length: 0, Fragment.Length: 0
        } && Text(owner, 128) && Text(observerIdentity, 128) && capability is not null &&
            scope is not null && scope.ExclusiveFixtureNamespace && scope.AllowPurge &&
            scope.SubscriptionId != Guid.Empty && scope.TenantId != Guid.Empty &&
            Segment(scope.ResourceGroup, 90) && Segment(scope.Location, 50) &&
            provisioner is not null && provisioner.Host == scope && limits is not null &&
            limits.MaximumBodyBytes is >= 1024 and <= 1024 * 1024 &&
            limits.MaximumReplyBytes is >= 1024 and <= 1024 * 1024 &&
            limits.Timeout > TimeSpan.Zero && limits.Timeout <= TimeSpan.FromMinutes(2));
        this.origin = origin;
        this.owner = owner;
        this.observerIdentity = observerIdentity;
        this.capability = capability;
        this.scope = scope;
        this.provisioner = provisioner;
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
        profile = Profile.DeleteVaultCleanup;
    }

    internal static ManagementOperationFixtureObserverService ForDeleteVaultCleanup(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, P.HostScope scope, P provisioner,
        Limits limits, TimeProvider? time = null) =>
        new(origin, owner, observerIdentity, capability, scope, provisioner, limits, time);

    // Journal validation only reads private reference-keyed immutable records.
    // No validator takes a service, capture, or parent lock or invokes a host.
    internal sealed class DeleteVaultAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.deleteAdmissions.TryGetValue(this, out var evidence) && DeleteRoot(journal, snapshot, evidence.Root);
        public override string ToString() => "[DeleteVaultAdmission]";
    }

    internal sealed class DeleteVaultTermination(ManagementOperationFixtureObserverService source, Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.deleteTerminations.TryGetValue(this, out var evidence) &&
            evidence.Dispatch == Dispatch && Dispatch != Guid.Empty && DeleteRoot(journal, snapshot, evidence.Root);
        public override string ToString() => "[DeleteVaultTermination]";
    }

    internal sealed class DeleteVaultSettlement(ManagementOperationFixtureObserverService source, Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal RoleFixtureJournal.DeleteVaultDisposition Disposition =>
            source.deleteSettlements.TryGetValue(this, out var evidence) ? evidence.Disposition : throw Failure();
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.deleteSettlements.TryGetValue(this, out var evidence) && evidence.Finished.Dispatch == Dispatch &&
            Dispatch != Guid.Empty && DeleteRoot(journal, snapshot, evidence.Finished.Root);
        public override string ToString() => "[DeleteVaultSettlement]";
    }

    private sealed record DeleteRootEvidence(RoleFixtureJournal Journal, string Owner, FixtureSelector Selector,
        Guid Lease, string VaultId, string DeletedId, string Configuration);
    private sealed record DeleteBaseline(DeleteRootEvidence Root, P.Plan Plan, P.DeleteVaultLoan Loan,
        Task<P.DeleteVaultWitness> Task, P.DeleteVaultWitness Witness, string ActiveDigest);
    private sealed record DeleteFinished(DeleteRootEvidence Root, Guid Dispatch, DeleteBaseline Baseline,
        VaultAdministration? Client, VaultScope? Scope, ManagementReceipt? Receipt,
        Task? StartTask, Task? CheckTask, C.DeleteVaultStart? Native);
    private sealed record DeleteCompleted(DeleteFinished Finished, Task<P.DeleteVaultWitness> ParentTask,
        P.DeleteVaultWitness Parent, Task<S.Measurement>? StatusTask, S.Measurement? Status,
        RoleFixtureJournal.DeleteVaultDisposition Disposition);
    private sealed record DeleteDecision(Task<P.DeleteVaultWitness> ParentTask, P.DeleteVaultWitness Parent,
        Task<S.Measurement>? StatusTask, S.Measurement? Status, RoleFixtureJournal.DeleteVaultDisposition Disposition);
    private readonly ConcurrentDictionary<DeleteVaultAdmission, DeleteBaseline> deleteAdmissions =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<DeleteVaultTermination, DeleteFinished> deleteTerminations =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<DeleteVaultSettlement, DeleteCompleted> deleteSettlements =
        new(ReferenceEqualityComparer.Instance);

    private abstract class OriginalVaultSession(FixtureSelector selector)
    {
        internal readonly FixtureSelector Selector = selector;
        internal readonly CancellationTokenSource Stop = new();
        internal readonly TaskCompletionSource Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int Active;
        internal bool Closed, Releasing;
    }

    private sealed class DeleteSession(FixtureSelector selector) : OriginalVaultSession(selector)
    {
        internal P.Plan? Plan;
        internal P.DeleteVaultLoan? Loan;
        internal V.Lease? Lease;
        internal Guid Subscription, Dispatch;
        internal DateTimeOffset ArmedAt, StartedAt;
        internal bool Armed, BaselineClaimed, StartClaimed, StartFinished, PostClaimed, Finalized;
        internal DeleteBaseline? Baseline;
        internal DeleteVaultAdmission? Admission;
        internal DeleteVaultTermination? Termination;
        internal DeleteVaultSettlement? Settlement;
        internal bool TerminationPersisted;
        internal DeleteDecision? Decision;
        internal C.Binding? Binding;
        internal C.Window? Window;
        internal C.DeleteVaultStart? Native;
        internal VaultAdministration? Client;
        internal VaultScope? Scope;
        internal ManagementReceipt? Receipt;
        internal ManagementOperation? Handle;
        internal Task? StartTask, CheckTask;
        internal SecretStatus? Outcome;
        internal bool Canceled, StartValid;
        internal Task<P.DeleteVaultWitness>? ParentTask;
        internal P.DeleteVaultWitness? Parent;
        internal Task<S.Measurement>? StatusTask;
        internal S.Measurement? Status;
        internal V.Measurement? Measurement;
        internal Task? Finalization;
    }

    private static bool DeleteRoot(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot, DeleteRootEvidence root) =>
        ReferenceEquals(journal, root.Journal) && snapshot.Owner == root.Owner && snapshot.Selector == root.Selector &&
        snapshot.LeaseId == root.Lease && snapshot.DeleteVault is { } deletion && deletion.VaultId == root.VaultId &&
        EncodeDeleteConfiguration(deletion.Baseline) == root.Configuration &&
        snapshot.Settings is null && snapshot.PrivateEndpoint is null && snapshot.Resources.Length == 3 &&
        snapshot.Resources.All(r => !r.Borrowed) &&
        snapshot.Resources.Count(r => r.Id == root.VaultId && !r.CleanupOnly) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.VaultId + "/secrets/" + P.Canary && r.CleanupOnly &&
            !r.CreateAttempted && !r.SelectedAttempted) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.DeletedId && r.CleanupOnly &&
            !r.CreateAttempted && !r.SelectedAttempted) == 1;

    private static string EncodeDeleteConfiguration(V.Configuration value) =>
        JsonSerializer.Serialize(value with
        { Policies = value.Policies.Select(p => p with { Permissions = p.Permissions.ToArray() }).ToArray() },
            ManagementAdmission.Json);
    private V.Configuration DeleteConfiguration() =>
        JsonSerializer.Deserialize<V.Configuration>(deleteConfiguration ?? throw Failure(), Json) ?? throw Failure();

    private static void ValidateDeleteSelector(FixtureSelector selector) =>
        Require(selector is not null && selector.Nonce != Guid.Empty && P.DeleteVaultSelector(selector) &&
            new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }.All(v => Text(v, 512)));

    private Task<HttpResponseMessage> DispatchDeleteVault(string path, JsonElement body, CancellationToken token) =>
        path switch
        {
            "/vault/prepare" when profile == Profile.OriginalVaultDelete =>
                PrepareDeleteVault(body.Deserialize<V.Prepare>(Json) ?? throw Failure(), token),
            "/vault/arm" when profile == Profile.OriginalVaultDelete =>
                Task.FromResult(ArmDeleteVault(body.Deserialize<ObserveLease>(Json) ?? throw Failure())),
            "/vault/observe" when profile == Profile.OriginalVaultDelete =>
                ObserveDeleteVault(body.Deserialize<ObserveLease>(Json) ?? throw Failure(), token),
            "/vault/release" =>
                ReleaseDeleteVault(body.Deserialize<FixtureSelector>(Json) ?? throw Failure(), token),
            _ => Task.FromResult(Error(HttpStatusCode.NotFound))
        };

    private async Task<HttpResponseMessage> PrepareDeleteVault(V.Prepare input, CancellationToken token)
    {
        ValidateDeleteSelector(input.Selection);
        Require(input.SubscriptionId == scope.SubscriptionId && input.ResourceGroup == scope.ResourceGroup &&
            input.Configuration is not null && V.SameConfiguration(input.Configuration, DeleteConfiguration()));
        DeleteSession session;
        lock (gate)
        {
            Require(!disposed && deleteSessions.Count < 32 && !deleteSessions.ContainsKey(input.Selection.Nonce));
            session = new(input.Selection with { }) { Active = 1 };
            deleteSessions.Add(session.Selector.Nonce, session);
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            lock (gate)
            {
                Require(!disposed && !session.Closed);
                session.Plan = provisioner.PlanFixture(owner, session.Selector, P.Preparation.Active, [], seedCanary: false);
            }
            var result = await provisioner.ProvisionAsync(session.Plan, cancellationToken: linked.Token).ConfigureAwait(false);
            Require(result.State == P.State.Ready && result.VaultPresent == true && result.DeletedVaultPresent == false &&
                result.Configuration is not null && V.SameConfiguration(result.Configuration, DeleteConfiguration()));
            var snapshot = provisioner.Journal.Read(owner, session.Selector);
            DateTimeOffset observed = time.GetUtcNow();
            lock (gate)
            {
                Require(!disposed && !session.Closed && snapshot.Idle && !snapshot.Closing &&
                    snapshot.DeleteVault is not null && snapshot.Resources.Length == 3 &&
                    snapshot.Resources.All(r => !r.Borrowed));
                session.Lease = new(new(session.Selector.Nonce, session.Plan.LeaseId, observerIdentity,
                    S.ArmOrigin, "2026-02-01", observed, snapshot.Resources.Select(r => r.Id).ToArray()),
                    session.Plan.VaultName, null, P.Canary, "", DeleteConfiguration(), PrivateConnectionState.Unknown);
                return Reply(session.Lease);
            }
        }
        finally { LeaveDelete(session); }
    }

    private DeleteSession FindDelete(Guid nonce, Guid lease)
    {
        Require(!disposed);
        Require(deleteSessions.TryGetValue(nonce, out var session));
        Require(!session.Closed &&
            session.Plan is not null && session.Lease is not null && session.Plan.LeaseId == lease);
        return session;
    }

    private HttpResponseMessage ArmDeleteVault(ObserveLease input)
    {
        lock (gate)
        {
            var session = FindDelete(input.Nonce, input.LeaseId);
            Require(!session.Armed && input.Phase == "subscribe-before-trigger" && input.SubscriptionId is null);
            session.ArmedAt = time.GetUtcNow();
            session.Subscription = Guid.NewGuid();
            session.Armed = true;
            return Reply(new ObservationSubscription(input.LeaseId, input.Nonce, session.Subscription, session.ArmedAt));
        }
    }

    private async Task<HttpResponseMessage> ObserveDeleteVault(ObserveLease input, CancellationToken token)
    {
        DeleteSession session;
        bool baseline = input.Phase == "baseline-before-dispatch";
        lock (gate)
        {
            session = FindDelete(input.Nonce, input.LeaseId);
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
                    RetryDeleteSettlement(session);
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
                session.Loan = provisioner.EnterDeleteVault(session.Plan!);
                var task = provisioner.ObserveDeleteVaultAsync(session.Loan, linked.Token);
                var witness = await task.ConfigureAwait(false);
                Require(provisioner.OwnsDeleteVaultWitness(witness, session.Loan, task) &&
                    witness.Result.VaultPresent == true && witness.Result.DeletedVaultPresent == false &&
                    witness.Result.Configuration is not null &&
                    V.SameConfiguration(witness.Result.Configuration, DeleteConfiguration()) &&
                    witness.ActiveDigest is not null && witness.StartedAt >= session.ArmedAt);
                var root = new DeleteRootEvidence(provisioner.Journal, owner, session.Selector,
                    session.Plan!.LeaseId, session.Plan.VaultId, session.Plan.DeletedId, deleteConfiguration!);
                var evidence = new DeleteBaseline(root, session.Plan, session.Loan, task, witness, witness.ActiveDigest);
                var admission = new DeleteVaultAdmission(this);
                lock (gate)
                {
                    Require(!disposed && !session.Closed && !session.StartClaimed);
                    Require(deleteAdmissions.TryAdd(admission, evidence));
                    session.Baseline = evidence;
                    session.Admission = admission;
                }
                return Reply(ProjectDelete(session, witness));
            }
            return await PostDeleteVault(session, linked.Token).ConfigureAwait(false);
        }
        finally { LeaveDelete(session); }
    }

    public async ValueTask<SecretOutcome<ManagementOperation>> RunDeleteVaultAsync(FixtureSelector selector,
        VaultAdministration client, VaultScope originalScope, ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        Require(profile == Profile.OriginalVaultDelete);
        ValidateDeleteSelector(selector);
        DeleteSession session;
        lock (gate)
        {
            Require(deleteSessions.TryGetValue(selector.Nonce, out session!) && session.Selector == selector);
            _ = FindDelete(selector.Nonce, session.Plan?.LeaseId ?? Guid.Empty);
            Require(session.Armed && session.Baseline is not null && session.Admission is not null &&
                session.Loan is not null && !session.StartClaimed && client is not null &&
                originalScope is not null && originalScope.ExportResourceId() == session.Plan!.VaultId && receipt is not null);
            provisioner.CheckDeleteVaultLoan(session.Loan);
            // Reserve before clocks, timers, credentials, capture or host hooks.
            session.Dispatch = provisioner.Journal.BeginDeleteVaultInvocation(owner, selector,
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
            session.Binding = new(selector, session.Plan!.LeaseId, originalScope, ManagementMutation.DeleteVault,
                scope.Location, "2026-02-01");
            session.Window = capture.ArmDeleteVault(session.Binding);
            var result = await capture.StartDeleteVaultAsync(session.Window, selector, client, originalScope, receipt,
                linked.Token, task => session.StartTask = task,
                () => provisioner.Journal.AdmitDeleteVaultSend(owner, selector, session.Plan.LeaseId,
                    session.Dispatch, session.Admission!)).ConfigureAwait(false);
            session.Outcome = result.Status;
            session.Handle = result.IsSuccess ? result.Value : null;
            session.StartValid = !linked.IsCancellationRequested;
            if (capture.TryGetDeleteVaultStart(session.Window, session.Binding, out var native) &&
                capture.OwnsDeleteVaultStart(native, session.Window, session.Binding, client, originalScope,
                    receipt, session.StartTask!, session.Handle))
                session.Native = native;
            return result;
        }
        catch (OperationCanceledException) { session.Canceled = true; throw; }
        finally
        {
            lock (gate) session.StartFinished = true;
            LeaveDelete(session, invocation: true);
        }
    }

    private async Task<HttpResponseMessage> PostDeleteVault(DeleteSession session, CancellationToken token)
    {
        bool eligible = false;
        RoleFixtureJournal.DeleteVaultDisposition disposition = RoleFixtureJournal.DeleteVaultDisposition.None;
        try
        {
            Require(session.Loan is not null && session.Baseline is not null);
            var native = session.Native;
            if (native is { HttpStatus: 200, Target: not null } && session.StartValid && !session.Canceled &&
                session.Outcome == SecretStatus.Success && session.Handle is not null &&
                session.Selector.Case is "selected-contract" or "independent-effect")
            {
                var read = new OriginalVaultStatusRead(native.Target);
                var previous = currentOriginalVaultStatus.Value;
                currentOriginalVaultStatus.Value = read;
                try
                {
                    var window = statuses.Arm(native.Target, session.Binding!);
                    session.StatusTask = statuses.CollectAsync(window, session.Binding!, token).AsTask();
                    session.Status = await session.StatusTask.ConfigureAwait(false);
                    var status = session.Status;
                    Require(read.Complete && read.Sends == 1 && status.ResponseComplete && status.Terminal &&
                        status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
                        status.HttpStatus == 200 && Text(status.NativeRequestId, 256) &&
                        status.StartDispatch == native.Target.StartDispatch &&
                        status.TargetSha256 == native.Target.TargetSha256 &&
                        status.StartResponseSha256 == native.Target.StartResponseSha256 &&
                        status.StartedAt >= session.StartedAt && status.FinishedAt >= status.StartedAt);
                }
                finally
                {
                    currentOriginalVaultStatus.Value = previous;
                    read.Storage.Dispose();
                }
            }
            session.ParentTask = provisioner.ObserveDeleteVaultAsync(session.Loan, token);
            session.Parent = await session.ParentTask.ConfigureAwait(false);
            var parent = session.Parent;
            Require(provisioner.OwnsDeleteVaultWitness(parent, session.Loan, session.ParentTask) &&
                parent.StartedAt >= (session.Status?.FinishedAt ?? session.StartedAt));
            token.ThrowIfCancellationRequested();
            if (native is { HttpStatus: 200 } && session.Status is not null &&
                parent.Result.VaultPresent == false && parent.Result.DeletedVaultPresent == true &&
                session.Handle is not null)
            {
                Require(capture.OwnsDeleteVaultStart(native, session.Window!, session.Binding!, session.Client!,
                    session.Scope!, session.Receipt!, session.StartTask!, session.Handle));
                var result = await capture.CheckStatusAsync(session.Window!, session.Selector, session.Handle, token,
                    task => session.CheckTask = task).ConfigureAwait(false);
                Require(result == SecretStatus.Success && capture.OwnsDeleteVaultCompletion(native, session.Window!,
                    session.Binding!, session.Client!, session.Scope!, session.Receipt!, session.StartTask!,
                    session.Handle, session.CheckTask!));
                disposition = RoleFixtureJournal.DeleteVaultDisposition.Deleted;
                eligible = true;
            }
            else if (native is { HttpStatus: 403, Outcome: SecretStatus.Denied } && session.StartValid &&
                session.Selector.Case == "denied-authority" &&
                session.Outcome == SecretStatus.Denied && !session.Canceled && session.Handle is null &&
                session.StatusTask is null && session.CheckTask is null &&
                session.Receipt!.Evidence == DispatchEvidence.Rejected &&
                parent.Result.VaultPresent == true && parent.Result.DeletedVaultPresent == false &&
                parent.ActiveDigest == session.Baseline.ActiveDigest && parent.Result.Configuration is not null &&
                V.SameConfiguration(parent.Result.Configuration, DeleteConfiguration()))
            {
                Require(capture.OwnsDeleteVaultStart(native, session.Window!, session.Binding!, session.Client!,
                    session.Scope!, session.Receipt!, session.StartTask!, null));
                disposition = RoleFixtureJournal.DeleteVaultDisposition.Denied;
                eligible = true;
            }
            // Uncertain canonical cases still return the fresh actual effect.
            // No handle/check/receipt is manufactured to erase their fence.
            session.Measurement = ProjectDelete(session, parent);
            if (eligible)
            {
                token.ThrowIfCancellationRequested();
                session.Decision = new(session.ParentTask, parent, session.StatusTask, session.Status, disposition);
            }
        }
        finally
        {
            await FinalizeDeleteVault(session).ConfigureAwait(false);
        }
        token.ThrowIfCancellationRequested();
        RetryDeleteSettlement(session);
        return Reply(session.Measurement ?? throw Failure());
    }

    private Task FinalizeDeleteVault(DeleteSession session)
    {
        lock (gate) return session.Finalization ??= Finish();
        async Task Finish()
        {
            try
            {
                if (session.Window is not null) await capture.SealAsync(session.Window).ConfigureAwait(false);
            }
            finally
            {
                if (session.Loan is { } loan)
                {
                    provisioner.ExitDeleteVault(loan);
                    session.Loan = null;
                }
            }
            session.Finalized = true;
            if (session.Dispatch == Guid.Empty || session.Baseline is null) return;
            var evidence = new DeleteFinished(session.Baseline.Root, session.Dispatch, session.Baseline,
                session.Client, session.Scope, session.Receipt, session.StartTask, session.CheckTask, session.Native);
            var termination = new DeleteVaultTermination(this, session.Dispatch);
            Require(deleteTerminations.TryAdd(termination, evidence));
            session.Termination = termination;
        }
    }

    private void RetryDeleteSettlement(DeleteSession session)
    {
        if (session.Termination is null) return;
        // Draining and storage release are one-shot. Local persistence can fail
        // independently and must not poison that completed ownership finalizer.
        if (!session.TerminationPersisted)
        {
            provisioner.Journal.EndDeleteVaultInvocation(owner, session.Selector, session.Plan!.LeaseId, session.Termination);
            session.TerminationPersisted = true;
        }
        if (session.Settlement is null && session.Decision is { } decision && !session.Closed && !disposed)
        {
            Require(deleteTerminations.TryGetValue(session.Termination, out var finished));
            var certificate = new DeleteVaultSettlement(this, session.Dispatch);
            Require(deleteSettlements.TryAdd(certificate, new(finished, decision.ParentTask, decision.Parent,
                decision.StatusTask, decision.Status, decision.Disposition)));
            session.Settlement = certificate;
        }
        if (session.Settlement is null) return;
        provisioner.Journal.RegisterDeleteVaultSettlement(owner, session.Selector, session.Plan!.LeaseId, session.Settlement);
        provisioner.Journal.SettleDeleteVaultInvocation(owner, session.Selector, session.Plan.LeaseId, session.Settlement);
    }

    private V.Measurement ProjectDelete(DeleteSession session, P.DeleteVaultWitness witness)
    {
        var result = witness.Result;
        return new(session.Plan!.LeaseId, session.Selector.Nonce, observerIdentity, witness.FinishedAt,
            session.Plan.VaultId, result.VaultPresent == true ? SecretStatus.Success : SecretStatus.Absent,
            result.DeletedVaultPresent == true ? SecretStatus.Success : SecretStatus.Absent,
            result.Configuration, result.Configuration?.Policies ?? [], PrivateConnectionState.Unknown,
            SecretStatus.Absent, [], null, [], result.DeletedVault is { } deleted ? [deleted] : [], [], [], null);
    }

    private async Task<HttpResponseMessage> ReleaseDeleteVault(FixtureSelector selector, CancellationToken token)
    {
        ValidateDeleteSelector(selector);
        DeleteSession session;
        lock (gate)
        {
            Require(!disposed);
            if (!deleteSessions.TryGetValue(selector.Nonce, out session!))
            {
                Require(deleteSessions.Count < 32);
                deleteSessions.Add(selector.Nonce, session = new(selector with { }));
            }
            Require(session.Selector == selector && !session.Releasing);
            session.Releasing = true;
        }
        try
        {
            RoleFixtureJournal.Snapshot snapshot;
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
            // A bounded release does not wait for an uncooperative borrower.
            // Dispose retains ownership and drains it; no timeout is drainage.
            lock (gate)
                if (session.Active != 0) return Reply(DeleteReleaseMeasurement(session, snapshot));
            await FinalizeDeleteVault(session).ConfigureAwait(false);
            RetryDeleteSettlement(session);
            snapshot = provisioner.Journal.Read(owner, selector);
            if (snapshot.Idle && snapshot.Resources.Length != 0)
                snapshot = (await provisioner.ReleaseAsync(owner, selector, purge: true,
                    cancellationToken: token).ConfigureAwait(false)).Journal;
            return Reply(DeleteReleaseMeasurement(session, snapshot));
        }
        finally { lock (gate) session.Releasing = false; }
    }

    private RoleFixtureRelease.Measurement DeleteReleaseMeasurement(DeleteSession session, RoleFixtureJournal.Snapshot snapshot)
    {
        string[] owned = snapshot.Resources.Where(r => !r.Borrowed).Select(r => r.Id).ToArray();
        string[] absent = snapshot.Resources.Where(r => !r.Borrowed && r.Absent && r.ActiveDispatch == Guid.Empty)
            .Select(r => r.Id).ToArray();
        return new(session.Selector, snapshot.Closing,
            session.Active + snapshot.Resources.Count(r => r.ActiveDispatch != Guid.Empty),
            owned, [], absent, owned.Except(absent, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private void LeaveDelete(DeleteSession session, bool invocation = false) => LeaveOriginalVault(session, invocation);

    private void LeaveOriginalVault(OriginalVaultSession session, bool invocation = false)
    {
        lock (gate)
        {
            session.Active--;
            if (session.Closed && session.Active == 0) session.Drained.TrySetResult();
            if (invocation && --active == 0 && disposed) drained.TrySetResult();
        }
    }

    private async Task DrainDeleteVault(TaskCompletionSource completion)
    {
        bool failed = false;
        DeleteSession[] owned;
        lock (gate) owned = deleteSessions.Values.ToArray();
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
                await FinalizeDeleteVault(session).ConfigureAwait(false);
                RetryDeleteSettlement(session);
            }
            catch (Exception) { failed = true; }
            session.Stop.Dispose();
        }
        lifetime.Dispose();
        if (failed) completion.TrySetException(Failure());
        else completion.TrySetResult();
    }

    private sealed class OriginalVaultStatusRead(C.StatusTarget target)
    {
        internal readonly C.StatusTarget Target = target;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly HashSet<Request> Requests = new(ReferenceEqualityComparer.Instance);
        internal int Sends;
        internal bool Complete;
    }

    private sealed class OriginalVaultStatusTransport(ManagementOperationFixtureObserverService source,
        HttpPipelineTransport backend, int maximumBytes) : HttpPipelineTransport
    {
        private OriginalVaultStatusRead Current => source.currentOriginalVaultStatus.Value ?? throw Failure();
        public override Request CreateRequest()
        {
            var read = Current;
            Require(read.Requests.Count == 0);
            var request = backend.CreateRequest();
            read.Requests.Add(request);
            return request;
        }
        public override void Process(HttpMessage message) => throw Failure();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            var read = Current;
            Require(++read.Sends == 1 && read.Requests.Contains(message.Request));
            Check();
            var original = message.Request;
            var headers = original.Headers.ToArray();
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) read.Storage.Own(message.Response); }
            Check();
            Require(ReferenceEquals(message.Request, original) && headers.SequenceEqual(original.Headers));
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes,
                read.Storage).ConfigureAwait(false);
            Check();
            Require(body.Response.Status == 200 && ReferenceEquals(message.Request, original) &&
                headers.SequenceEqual(original.Headers));
            read.Complete = true;
            void Check()
            {
                var uri = message.Request.Uri.ToUri();
                Require(message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
                    uri.OriginalString == read.Target.TargetUri.OriginalString &&
                    message.Request.Headers.TryGetValue("Authorization", out var auth) &&
                    auth.StartsWith("Bearer ", StringComparison.Ordinal) && Text(auth[7..], 16377) &&
                    !message.Request.Headers.Contains("Content-Length") &&
                    !message.Request.Headers.Contains("Content-Encoding") &&
                    !message.Request.Headers.Contains("Transfer-Encoding"));
                var all = message.Request.Headers.ToArray();
                Require(all.Length <= 32 && all.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
                    all.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == all.Length &&
                    all.All(h => Text(h.Name, 128) && Text(h.Value, 16384)));
                if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                message.CancellationToken.ThrowIfCancellationRequested();
            }
        }
    }
}
