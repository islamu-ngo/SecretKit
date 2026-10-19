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
    internal sealed record CreateOrUpdateVaultSource(
        [property: JsonIgnore] P Provisioner,
        [property: JsonIgnore] S.Authority StatusReader,
        [property: JsonIgnore] HttpPipelineTransport SelectedBackend,
        [property: JsonIgnore] S.Limits StatusLimits)
    {
        public override string ToString() => "[CreateOrUpdateVaultSource]";
    }

    private readonly string? createBaselineConfiguration, createSelectedConfiguration;
    private readonly Dictionary<Guid, CreateVaultSession> createVaultSessions = [];

    internal ManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, P.HostScope scope, CreateOrUpdateVaultSource source, Limits limits,
        TimeProvider? time = null)
        : this(origin, owner, observerIdentity, capability, scope, source.Provisioner, limits, time)
    {
        Require(source.StatusReader is not null && source.SelectedBackend is not null && source.StatusLimits is not null);
        var configurations = source.Provisioner.CreateOrUpdateVaultConfigurations(scope, source.StatusReader, source.SelectedBackend);
        Require(V.ConfigurationVariants.Contains(configurations.Variant));
        createBaselineConfiguration = EncodeDeleteConfiguration(configurations.Baseline);
        createSelectedConfiguration = EncodeDeleteConfiguration(configurations.Selected);
        profile = Profile.OriginalVaultCreateOrUpdate;
        nativeCapture = new(source.SelectedBackend, limits.MaximumReplyBytes);
        statusCollector = new(capture, new(source.StatusReader.Label, source.StatusReader.Credential,
            new OriginalVaultStatusTransport(this, source.StatusReader.Transport, source.StatusLimits.MaximumResponseBytes)),
            source.StatusLimits, this.time);
    }

    private ManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, P.HostScope scope, P provisioner, Limits limits, TimeProvider? time, bool createCleanup)
        : this(origin, owner, observerIdentity, capability, scope, provisioner, limits, time)
    {
        Require(createCleanup);
        profile = Profile.CreateOrUpdateVaultCleanup;
    }

    internal static ManagementOperationFixtureObserverService ForCreateOrUpdateVaultCleanup(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, P.HostScope scope, P provisioner, Limits limits,
        TimeProvider? time = null) =>
        new(origin, owner, observerIdentity, capability, scope, provisioner, limits, time, createCleanup: true);

    internal sealed class CreateOrUpdateVaultAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(J journal, J.Snapshot snapshot) =>
            source.createAdmissions.TryGetValue(this, out var evidence) && CreateRoot(journal, snapshot, evidence.Root);
        public override string ToString() => "[CreateOrUpdateVaultAdmission]";
    }
    internal sealed class CreateOrUpdateVaultTermination(ManagementOperationFixtureObserverService source, Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(J journal, J.Snapshot snapshot) =>
            source.createTerminations.TryGetValue(this, out var evidence) && evidence.Dispatch == Dispatch &&
            Dispatch != Guid.Empty && CreateRoot(journal, snapshot, evidence.Baseline.Root);
        public override string ToString() => "[CreateOrUpdateVaultTermination]";
    }
    internal sealed class CreateOrUpdateVaultSettlement(ManagementOperationFixtureObserverService source, Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal J.CreateOrUpdateVaultDisposition Disposition =>
            source.createSettlements.TryGetValue(this, out var evidence) ? evidence.Decision.Disposition : throw Failure();
        internal V.Configuration Configuration =>
            source.createSettlements.TryGetValue(this, out var evidence)
                ? DecodeCreateConfiguration(evidence.Decision.Configuration) : throw Failure();
        internal bool Validate(J journal, J.Snapshot snapshot) =>
            source.createSettlements.TryGetValue(this, out var evidence) && evidence.Finished.Dispatch == Dispatch &&
            Dispatch != Guid.Empty && CreateRoot(journal, snapshot, evidence.Finished.Baseline.Root);
        public override string ToString() => "[CreateOrUpdateVaultSettlement]";
    }

    private sealed record CreateRootEvidence(J Journal, string Owner, FixtureSelector Selector, Guid Lease,
        string VaultId, string DeletedId, string Baseline, string Selected);
    private sealed record CreateBaseline(CreateRootEvidence Root, P.Plan Plan, P.CreateOrUpdateVaultLoan Loan,
        Task<P.CreateOrUpdateVaultWitness> Task, P.CreateOrUpdateVaultWitness Witness, string Digest);
    private sealed record CreateFinished(CreateBaseline Baseline, Guid Dispatch, VaultAdministration? Client,
        VaultScope? Scope, VaultConfiguration? Configuration, ManagementReceipt? Receipt, Task? StartTask,
        ManagementOperation? Handle, Task? CheckTask, C.CreateOrUpdateVaultStart? Native);
    private sealed record CreateDecision(Task<P.CreateOrUpdateVaultWitness> ParentTask,
        P.CreateOrUpdateVaultWitness Parent, Task<S.Measurement>? StatusTask, S.Measurement? Status,
        J.CreateOrUpdateVaultDisposition Disposition, string Configuration);
    private sealed record CreateCompleted(CreateFinished Finished, CreateDecision Decision);
    private readonly ConcurrentDictionary<CreateOrUpdateVaultAdmission, CreateBaseline> createAdmissions =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<CreateOrUpdateVaultTermination, CreateFinished> createTerminations =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<CreateOrUpdateVaultSettlement, CreateCompleted> createSettlements =
        new(ReferenceEqualityComparer.Instance);

    // Scheduling and borrower lifetime are shared; proof registries and decisions
    // stay in the typed Create/Recover leaves. No caller supplies proof callbacks.
    private abstract class ConfigurationVaultSession(FixtureSelector selector) : OriginalVaultSession(selector)
    {
        internal P.Plan? Plan;
        internal V.Lease? Lease;
        internal Guid Subscription, Dispatch;
        internal DateTimeOffset ArmedAt, StartedAt;
        internal bool Armed, BaselineClaimed, StartClaimed, StartFinished, StartValid, Canceled, PostClaimed;
        internal bool Finalized, TerminationPersisted;
        internal C.Binding? Binding;
        internal C.Window? Window;
        internal VaultAdministration? Client;
        internal VaultScope? Scope;
        internal VaultConfiguration? Configuration;
        internal ManagementReceipt? Receipt;
        internal Task? StartTask, CheckTask;
        internal ManagementOperation? Handle;
        internal SecretStatus? Outcome;
        internal Task<S.Measurement>? StatusTask;
        internal S.Measurement? Status;
        internal V.Measurement? Measurement;
        internal Task<SecretStatus>? Completion;
        internal Task? Finalization;
        internal abstract ManagementMutation Operation { get; }
        internal abstract DateTimeOffset BaselineFinishedAt { get; }
        internal abstract int? HttpStatus { get; }
        internal abstract SecretStatus? NativeOutcome { get; }
        internal abstract C.StatusTarget? Target { get; }
        internal abstract bool ParentMatchesSelected { get; }
        internal abstract bool DenialMatches { get; }
        internal abstract V.Configuration SelectedConfiguration { get; }
        internal abstract void Reserve();
        internal abstract void CheckLoan();
        internal abstract Task<SecretOutcome<ManagementOperation>> Start(CancellationToken token);
        internal abstract bool OwnsStart();
        internal abstract bool OwnsCompletion();
        internal abstract Task ObserveParent(CancellationToken token);
        internal abstract void Decide(bool positive);
        internal abstract void ExitLoan();
        internal abstract void FreezeFinished();
        internal abstract void RetrySettlement();
    }

    private sealed class CreateVaultSession(ManagementOperationFixtureObserverService source, FixtureSelector selector)
        : ConfigurationVaultSession(selector)
    {
        internal P.CreateOrUpdateVaultLoan? Loan;
        internal CreateBaseline? Baseline;
        internal CreateOrUpdateVaultAdmission? Admission;
        internal CreateOrUpdateVaultTermination? Termination;
        internal CreateOrUpdateVaultSettlement? Settlement;
        internal CreateFinished? Finished;
        internal CreateDecision? Decision;
        internal C.CreateOrUpdateVaultStart? Native;
        internal Task<P.CreateOrUpdateVaultWitness>? ParentTask;
        internal P.CreateOrUpdateVaultWitness? Parent;
        internal override ManagementMutation Operation => ManagementMutation.CreateOrUpdateVault;
        internal override DateTimeOffset BaselineFinishedAt => Baseline!.Witness.FinishedAt;
        internal override int? HttpStatus => Native?.HttpStatus;
        internal override SecretStatus? NativeOutcome => Native?.Outcome;
        internal override C.StatusTarget? Target => Native?.Target;
        internal override V.Configuration SelectedConfiguration => source.CreateSelectedConfiguration();
        internal override bool ParentMatchesSelected => ParentTask is not null && Parent?.Result.Configuration is { } configuration &&
            V.SameConfiguration(configuration, SelectedConfiguration);
        internal override bool DenialMatches => Parent?.ActiveDigest == Baseline!.Digest && Parent?.Result.Configuration is { } configuration &&
            V.SameConfiguration(configuration, source.CreateBaselineConfiguration());
        internal override void Reserve()
        {
            Require(Baseline is not null && Admission is not null && Loan is not null);
            CheckLoan();
            Dispatch = source.provisioner.Journal.BeginCreateOrUpdateVaultInvocation(source.owner, Selector, Plan!.LeaseId, Admission);
        }
        internal override void CheckLoan() => source.provisioner.CheckCreateOrUpdateVaultLoan(Loan!);
        internal override async Task<SecretOutcome<ManagementOperation>> Start(CancellationToken token)
        {
            Window = source.capture.ArmCreateOrUpdateVault(Binding!);
            var result = await source.capture.StartCreateOrUpdateVaultAsync(Window, Selector, Client!, Scope!, Configuration!,
                Receipt!, token, task => StartTask = task,
                () => source.provisioner.Journal.AdmitCreateOrUpdateVaultSend(source.owner, Selector, Plan!.LeaseId,
                    Dispatch, Admission!)).ConfigureAwait(false);
            Handle = result.IsSuccess ? result.Value : null;
            if (source.capture.TryGetCreateOrUpdateVaultStart(Window, Binding!, out var native) &&
                source.capture.OwnsCreateOrUpdateVaultStart(native, Window, Binding!, Client!, Scope!, Configuration!,
                    Receipt!, StartTask!, Handle)) Native = native;
            return result;
        }
        internal override bool OwnsStart() => source.capture.OwnsCreateOrUpdateVaultStart(Native!, Window!, Binding!,
            Client!, Scope!, Configuration!, Receipt!, StartTask!, Handle);
        internal override bool OwnsCompletion() => source.capture.OwnsCreateOrUpdateVaultCompletion(Native!, Window!, Binding!,
            Client!, Scope!, Configuration!, Receipt!, StartTask!, Handle!, CheckTask!);
        internal override async Task ObserveParent(CancellationToken token)
        {
            Require(Loan is not null && Baseline is not null);
            ParentTask = source.provisioner.ObserveCreateOrUpdateVaultAsync(Loan, token);
            Parent = await ParentTask.ConfigureAwait(false);
            Require(source.provisioner.OwnsCreateOrUpdateVaultWitness(Parent, Loan, ParentTask) &&
                Parent.StartedAt >= (Status?.FinishedAt ?? StartedAt));
            Measurement = source.ProjectCreateVault(this, Parent);
        }
        internal override void Decide(bool positive) => Decision = new(ParentTask!, Parent!, StatusTask, Status,
            positive ? J.CreateOrUpdateVaultDisposition.Updated : J.CreateOrUpdateVaultDisposition.Denied,
            positive ? source.createSelectedConfiguration! : source.createBaselineConfiguration!);
        internal override void ExitLoan()
        {
            if (Loan is not { } loan) return;
            source.provisioner.ExitCreateOrUpdateVault(loan);
            Loan = null;
        }
        internal override void FreezeFinished()
        {
            if (Dispatch != Guid.Empty && Baseline is not null)
                Finished = new(Baseline, Dispatch, Client, Scope, Configuration, Receipt, StartTask, Handle, CheckTask, Native);
        }
        internal override void RetrySettlement() => source.RetryCreateVaultSettlement(this);
    }

    private static V.Configuration DecodeCreateConfiguration(string value) =>
        JsonSerializer.Deserialize<V.Configuration>(value, Json) ?? throw Failure();
    private V.Configuration CreateBaselineConfiguration() => DecodeCreateConfiguration(createBaselineConfiguration ?? throw Failure());
    private V.Configuration CreateSelectedConfiguration() => DecodeCreateConfiguration(createSelectedConfiguration ?? throw Failure());
    private static void ValidateCreateSelector(FixtureSelector selector) =>
        Require(selector is not null && selector.Nonce != Guid.Empty && P.CreateOrUpdateVaultSelector(selector) &&
            new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }.All(v => Text(v, 512)));

    private static bool CreateRoot(J journal, J.Snapshot snapshot, CreateRootEvidence root) =>
        ReferenceEquals(journal, root.Journal) && snapshot.Owner == root.Owner && snapshot.Selector == root.Selector &&
        snapshot.LeaseId == root.Lease && snapshot.CreateOrUpdateVault is { } creation &&
        creation.VaultId == root.VaultId && EncodeDeleteConfiguration(creation.Baseline) == root.Baseline &&
        EncodeDeleteConfiguration(creation.Selected) == root.Selected &&
        snapshot.Settings is null && snapshot.DeleteVault is null && snapshot.PurgeDeletedVault is null &&
        snapshot.PrivateEndpoint is null && snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed) &&
        snapshot.Resources.Count(r => r.Id == root.VaultId && !r.CleanupOnly) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.VaultId + "/secrets/" + P.Canary && r.CleanupOnly &&
            !r.CreateAttempted && !r.SelectedAttempted) == 1 &&
        snapshot.Resources.Count(r => r.Id == root.DeletedId && r.CleanupOnly &&
            !r.CreateAttempted && !r.SelectedAttempted) == 1;

    private Task<HttpResponseMessage> DispatchCreateOrUpdateVault(string path, JsonElement body, CancellationToken token) =>
        path switch
        {
            "/vault/prepare" when profile == Profile.OriginalVaultCreateOrUpdate =>
                PrepareCreateVault(body.Deserialize<V.Prepare>(Json) ?? throw Failure(), token),
            "/vault/arm" when profile == Profile.OriginalVaultCreateOrUpdate =>
                Task.FromResult(ArmCreateVault(body.Deserialize<ObserveLease>(Json) ?? throw Failure())),
            "/vault/observe" when profile == Profile.OriginalVaultCreateOrUpdate =>
                ObserveCreateVault(body.Deserialize<ObserveLease>(Json) ?? throw Failure(), token),
            "/vault/release" => ReleaseCreateVault(body.Deserialize<FixtureSelector>(Json) ?? throw Failure(), token),
            _ => Task.FromResult(Error(HttpStatusCode.NotFound))
        };

    private async Task<HttpResponseMessage> PrepareCreateVault(V.Prepare input, CancellationToken token)
    {
        ValidateCreateSelector(input.Selection);
        Require(input.SubscriptionId == scope.SubscriptionId && input.ResourceGroup == scope.ResourceGroup &&
            input.Configuration is not null && V.SameConfiguration(input.Configuration, CreateSelectedConfiguration()));
        CreateVaultSession session;
        lock (gate)
        {
            Require(!disposed && createVaultSessions.Count < 32 && !createVaultSessions.ContainsKey(input.Selection.Nonce));
            session = new(this, input.Selection with { }) { Active = 1 };
            createVaultSessions.Add(session.Selector.Nonce, session);
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
                result.Configuration is not null && V.SameConfiguration(result.Configuration, CreateBaselineConfiguration()));
            var snapshot = provisioner.Journal.Read(owner, session.Selector);
            DateTimeOffset observed = time.GetUtcNow();
            lock (gate)
            {
                Require(!disposed && !session.Closed && snapshot.Idle && !snapshot.Closing && snapshot.CreateOrUpdateVault is not null);
                session.Lease = new(new(session.Selector.Nonce, session.Plan.LeaseId, observerIdentity, S.ArmOrigin,
                    "2026-02-01", observed, snapshot.Resources.Select(r => r.Id).ToArray()),
                    session.Plan.VaultName, null, P.Canary, "", CreateBaselineConfiguration(), PrivateConnectionState.Unknown);
                return Reply(session.Lease);
            }
        }
        finally { LeaveOriginalVault(session); }
    }

    private CreateVaultSession FindCreateVault(Guid nonce, Guid lease)
    {
        Require(!disposed);
        Require(createVaultSessions.TryGetValue(nonce, out var session));
        Require(!session.Closed && session.Plan is not null && session.Lease is not null && session.Plan.LeaseId == lease);
        return session;
    }
    private HttpResponseMessage ArmCreateVault(ObserveLease input)
    {
        lock (gate)
        {
            var session = FindCreateVault(input.Nonce, input.LeaseId);
            Require(!session.Armed && input.Phase == "subscribe-before-trigger" && input.SubscriptionId is null);
            session.ArmedAt = time.GetUtcNow();
            session.Subscription = Guid.NewGuid();
            session.Armed = true;
            return Reply(new ObservationSubscription(input.LeaseId, input.Nonce, session.Subscription, session.ArmedAt));
        }
    }

    private async Task<HttpResponseMessage> ObserveCreateVault(ObserveLease input, CancellationToken token)
    {
        CreateVaultSession session;
        bool baseline = input.Phase == "baseline-before-dispatch";
        lock (gate)
        {
            session = FindCreateVault(input.Nonce, input.LeaseId);
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
                    RetryCreateVaultSettlement(session);
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
            session.Loan = provisioner.EnterCreateOrUpdateVault(session.Plan!);
            var task = provisioner.ObserveCreateOrUpdateVaultAsync(session.Loan, linked.Token);
            var witness = await task.ConfigureAwait(false);
            Require(provisioner.OwnsCreateOrUpdateVaultWitness(witness, session.Loan, task) &&
                witness.ActiveDigest is not null && witness.StartedAt >= session.ArmedAt &&
                witness.Result.Configuration is not null && V.SameConfiguration(witness.Result.Configuration, CreateBaselineConfiguration()));
            var root = new CreateRootEvidence(provisioner.Journal, owner, session.Selector, session.Plan!.LeaseId,
                session.Plan.VaultId, session.Plan.DeletedId, createBaselineConfiguration!, createSelectedConfiguration!);
            var evidence = new CreateBaseline(root, session.Plan, session.Loan, task, witness, witness.ActiveDigest);
            var admission = new CreateOrUpdateVaultAdmission(this);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !session.StartClaimed && createAdmissions.TryAdd(admission, evidence));
                session.Baseline = evidence;
                session.Admission = admission;
            }
            return Reply(ProjectCreateVault(session, witness));
        }
        finally { LeaveOriginalVault(session); }
    }

    public ValueTask<SecretOutcome<ManagementOperation>> RunCreateOrUpdateVaultAsync(FixtureSelector selector,
        VaultAdministration client, VaultScope originalScope, VaultConfiguration configuration, ManagementReceipt receipt,
        CancellationToken cancellationToken)
    {
        Require(profile == Profile.OriginalVaultCreateOrUpdate);
        ValidateCreateSelector(selector);
        CreateVaultSession session;
        lock (gate)
        {
            Require(createVaultSessions.TryGetValue(selector.Nonce, out session!) && session.Selector == selector);
            _ = FindCreateVault(selector.Nonce, session.Plan?.LeaseId ?? Guid.Empty);
        }
        return RunConfigurationVault(session, client, originalScope, configuration, receipt, cancellationToken);
    }

    private async ValueTask<SecretOutcome<ManagementOperation>> RunConfigurationVault(ConfigurationVaultSession session,
        VaultAdministration client, VaultScope originalScope, VaultConfiguration configuration, ManagementReceipt receipt,
        CancellationToken cancellationToken)
    {
        lock (gate)
        {
            Require(!disposed && !session.Closed && session.Armed && !session.StartClaimed && client is not null &&
                originalScope is not null && session.Plan is not null && session.Lease is not null &&
                originalScope.ExportResourceId() == session.Plan.VaultId && receipt is not null && configuration is not null &&
                V.SameConfiguration(C.CreateVaultConfiguration(configuration), session.SelectedConfiguration));
            // Typed reservation precedes timers, credentials and actual SDK work.
            session.Reserve();
            session.StartClaimed = true;
            session.Client = client;
            session.Scope = originalScope;
            session.Configuration = configuration;
            session.Receipt = receipt;
            session.Active++;
            active++;
        }
        try
        {
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineFinishedAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, session.Stop.Token, lifetime.Token, deadline.Token);
            session.Binding = new(session.Selector, session.Plan!.LeaseId, originalScope, session.Operation, scope.Location, "2026-02-01");
            var result = await session.Start(linked.Token).ConfigureAwait(false);
            session.Outcome = result.Status;
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

    private async Task<HttpResponseMessage> PostConfigurationVault(ConfigurationVaultSession session, CancellationToken token)
    {
        bool deferCompletion = false;
        try
        {
            if (session.HttpStatus == 201 && session.Target is { } target && session.StartValid && !session.Canceled &&
                session.Outcome == SecretStatus.Success && session.Handle is { State: NativeProvisioningState.Pending } &&
                session.Selector.Case is "selected-contract" or "independent-effect")
            {
                var read = new OriginalVaultStatusRead(target);
                var previous = currentOriginalVaultStatus.Value;
                currentOriginalVaultStatus.Value = read;
                try
                {
                    var window = statuses.Arm(target, session.Binding!);
                    session.StatusTask = statuses.CollectAsync(window, session.Binding!, token).AsTask();
                    session.Status = await session.StatusTask.ConfigureAwait(false);
                    var status = session.Status;
                    Require(read.Complete && read.Sends == 1 && status.ResponseComplete && status.Terminal &&
                        status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
                        status.HttpStatus == 200 && Text(status.NativeRequestId, 256) &&
                        status.StartDispatch == target.StartDispatch && status.TargetSha256 == target.TargetSha256 &&
                        status.StartResponseSha256 == target.StartResponseSha256 &&
                        status.StartedAt >= session.StartedAt && status.FinishedAt >= status.StartedAt);
                }
                finally { currentOriginalVaultStatus.Value = previous; read.Storage.Dispose(); }
            }
            await session.ObserveParent(token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (session.HttpStatus == 201 && session.Status is not null && session.ParentMatchesSelected &&
                session.Handle is { State: NativeProvisioningState.Pending } && session.Receipt!.Evidence == DispatchEvidence.Pending)
                deferCompletion = true;
            else if (session.HttpStatus == 403 && session.NativeOutcome == SecretStatus.Denied && session.StartValid &&
                !session.Canceled && session.Selector.Case == "denied-authority" && session.Outcome == SecretStatus.Denied &&
                session.Handle is null && session.StatusTask is null && session.CheckTask is null &&
                session.Receipt!.Evidence == DispatchEvidence.Rejected && session.DenialMatches && session.OwnsStart())
                session.Decide(positive: false);
        }
        finally
        {
            // Retain the Pending handle, loan and buffers through the handler's
            // assertion. Every positive variant then uses the same completion hook.
            if (!deferCompletion) await FinalizeConfigurationVault(session).ConfigureAwait(false);
        }
        session.RetrySettlement();
        return Reply(session.Measurement ?? throw Failure());
    }

    public ValueTask<SecretStatus> CompleteCreateOrUpdateVaultAsync(FixtureSelector selector,
        ManagementOperation originalHandle, CancellationToken cancellationToken)
    {
        Require(profile == Profile.OriginalVaultCreateOrUpdate);
        ValidateCreateSelector(selector);
        CreateVaultSession session;
        lock (gate)
        {
            Require(createVaultSessions.TryGetValue(selector.Nonce, out session!) && session.Selector == selector);
            _ = FindCreateVault(selector.Nonce, session.Plan?.LeaseId ?? Guid.Empty);
        }
        return CompleteConfigurationVault(session, originalHandle, cancellationToken);
    }

    private async ValueTask<SecretStatus> CompleteConfigurationVault(ConfigurationVaultSession session,
        ManagementOperation originalHandle, CancellationToken cancellationToken)
    {
        Task<SecretStatus> task;
        TaskCompletionSource<SecretStatus>? completion = null;
        lock (gate)
        {
            Require(!disposed && !session.Closed && session.Measurement is not null &&
                ReferenceEquals(session.Handle, originalHandle) && session.HttpStatus == 201 &&
                session.ParentMatchesSelected && session.Status is not null && session.Active == 0);
            session.Active++;
            active++;
            if (session.Completion is null)
            {
                completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
                session.Completion = completion.Task;
            }
            task = session.Completion;
        }
        try
        {
            if (completion is not null)
            {
                try { completion.TrySetResult(await CompleteConfigurationVaultCore(session, cancellationToken).ConfigureAwait(false)); }
                catch (Exception exception) { completion.TrySetException(exception); }
            }
            var result = await task.ConfigureAwait(false);
            session.RetrySettlement();
            return result;
        }
        finally { LeaveOriginalVault(session, invocation: true); }
    }

    private async Task<SecretStatus> CompleteConfigurationVaultCore(ConfigurationVaultSession session, CancellationToken token)
    {
        try
        {
            Require(session.Handle is { State: NativeProvisioningState.Pending } && session.ParentMatchesSelected && session.OwnsStart());
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token, lifetime.Token, deadline.Token);
            session.CheckLoan();
            var result = await capture.CheckStatusAsync(session.Window!, session.Selector, session.Handle, linked.Token,
                task => session.CheckTask = task).ConfigureAwait(false);
            Require(result == SecretStatus.Success && session.OwnsCompletion());
            linked.Token.ThrowIfCancellationRequested();
            session.Decide(positive: true);
            return result;
        }
        finally { await FinalizeConfigurationVault(session).ConfigureAwait(false); }
    }

    private Task FinalizeConfigurationVault(ConfigurationVaultSession session)
    {
        TaskCompletionSource completion;
        lock (gate)
        {
            if (session.Finalization is not null) return session.Finalization;
            completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
            session.Finalization = completion.Task;
        }
        _ = Finish();
        return completion.Task;
        async Task Finish()
        {
            try
            {
                try { if (session.Window is not null) await capture.SealAsync(session.Window).ConfigureAwait(false); }
                finally { session.ExitLoan(); }
                // A failed storage drain cannot publish either certificate.
                session.Finalized = true;
                session.FreezeFinished();
                completion.TrySetResult();
            }
            catch (Exception exception) { completion.TrySetException(exception); }
        }
    }

    private void RetryCreateVaultSettlement(CreateVaultSession session)
    {
        lock (gate)
        {
            if (!session.Finalized || session.Finished is not { } finished) return;
            var journal = provisioner.Journal;
            session.Termination ??= journal.RegisterCreateOrUpdateVaultTermination(owner, session.Selector, session.Plan!.LeaseId,
                session.Dispatch, () =>
                {
                    var certificate = new CreateOrUpdateVaultTermination(this, session.Dispatch);
                    Require(createTerminations.TryAdd(certificate, finished));
                    return certificate;
                });
            if (session.Termination is null) return;
            if (!session.TerminationPersisted)
            {
                journal.EndCreateOrUpdateVaultInvocation(owner, session.Selector, session.Plan!.LeaseId, session.Termination);
                session.TerminationPersisted = true;
            }
            if (session.Decision is not { } decision) return;
            session.Settlement ??= journal.RegisterCreateOrUpdateVaultSettlement(owner, session.Selector, session.Plan!.LeaseId,
                session.Dispatch, () =>
                {
                    var certificate = new CreateOrUpdateVaultSettlement(this, session.Dispatch);
                    Require(createSettlements.TryAdd(certificate, new(finished, decision)));
                    return certificate;
                });
            if (session.Settlement is null) return;
            journal.RegisterCreateOrUpdateVaultSettlement(owner, session.Selector, session.Plan!.LeaseId, session.Settlement);
            journal.SettleCreateOrUpdateVaultInvocation(owner, session.Selector, session.Plan.LeaseId, session.Settlement);
        }
    }

    private V.Measurement ProjectCreateVault(CreateVaultSession session, P.CreateOrUpdateVaultWitness witness) =>
        new(session.Plan!.LeaseId, session.Selector.Nonce, observerIdentity, witness.FinishedAt, session.Plan.VaultId,
            SecretStatus.Success, SecretStatus.Absent, witness.Result.Configuration, witness.Result.Configuration?.Policies ?? [],
            PrivateConnectionState.Unknown, SecretStatus.Absent, [], null, [], [], [], [], null);

    private async Task<HttpResponseMessage> ReleaseCreateVault(FixtureSelector selector, CancellationToken token)
    {
        ValidateCreateSelector(selector);
        CreateVaultSession session;
        lock (gate)
        {
            Require(!disposed);
            if (!createVaultSessions.TryGetValue(selector.Nonce, out session!))
            {
                Require(createVaultSessions.Count < 32);
                createVaultSessions.Add(selector.Nonce, session = new(this, selector with { }));
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
                if (session.Active != 0) return Reply(CreateVaultReleaseMeasurement(session, snapshot));
            await FinalizeConfigurationVault(session).ConfigureAwait(false);
            RetryCreateVaultSettlement(session);
            snapshot = provisioner.Journal.Read(owner, selector);
            Require(snapshot.Resources.Length == 0 || snapshot.CreateOrUpdateVault is not null);
            if (snapshot.Idle && snapshot.Resources.Length != 0)
                snapshot = (await provisioner.ReleaseAsync(owner, selector, purge: true, cancellationToken: token).ConfigureAwait(false)).Journal;
            return Reply(CreateVaultReleaseMeasurement(session, snapshot));
        }
        finally { lock (gate) session.Releasing = false; }
    }

    private static RoleFixtureRelease.Measurement CreateVaultReleaseMeasurement(CreateVaultSession session, J.Snapshot snapshot)
    {
        string[] owned = snapshot.Resources.Where(r => !r.Borrowed).Select(r => r.Id).ToArray();
        string[] absent = snapshot.Resources.Where(r => !r.Borrowed && r.Absent && r.ActiveDispatch == Guid.Empty).Select(r => r.Id).ToArray();
        return new(session.Selector, snapshot.Closing, session.Active + snapshot.Resources.Count(r => r.ActiveDispatch != Guid.Empty),
            owned, [], absent, owned.Except(absent, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private Task DrainCreateOrUpdateVault(TaskCompletionSource completion)
    {
        lock (gate) return DrainConfigurationVault(createVaultSessions.Values.ToArray(), completion);
    }

    private async Task DrainConfigurationVault(ConfigurationVaultSession[] owned, TaskCompletionSource completion)
    {
        bool failed = false;
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
                await FinalizeConfigurationVault(session).ConfigureAwait(false);
                session.RetrySettlement();
            }
            catch (Exception) { failed = true; }
            session.Stop.Dispose();
        }
        lifetime.Dispose();
        if (failed) completion.TrySetException(Failure());
        else completion.TrySetResult();
    }
}
