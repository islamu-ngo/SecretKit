using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using E = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;
using M = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationCollector;
using P = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureProvisioner;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal sealed partial class VaultFixtureObserverService
{
    internal sealed record SettingsSource(
        [property: JsonIgnore] RoleFixtureJournal Journal,
        [property: JsonIgnore] P Provisioner,
        [property: JsonIgnore] M.Authority Metadata,
        [property: JsonIgnore] M.Limits CollectorLimits,
        [property: JsonIgnore] HttpPipelineTransport SelectedTransport)
    {
        public override string ToString() => "[VaultSettingsSource]";
    }

    private readonly M? settingsMetadata;
    private readonly AsyncLocal<SettingsCall?> currentSettings = new();
    private readonly AsyncLocal<SettingsRead?> settingsRead = new();
    private readonly ConcurrentDictionary<SettingsAdmission, SettingsBaseline> settingsAdmissions =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<SettingsTermination, SettingsFinished> settingsTerminations =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<SettingsSettlement, SettingsCompleted> settingsSettlements =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<SettingsSettlement, SettingsCompleted> settingsRejections =
        new(ReferenceEqualityComparer.Instance);

    internal VaultFixtureObserverService(Uri origin, string owner, string observerIdentity, SecretMaterial capability,
        P.HostScope scope, E.Configuration baseline, SettingsSource source, Limits limits, TimeProvider? time = null)
    {
        Require(origin is
        {
            IsAbsoluteUri: true, Scheme: "https", AbsolutePath: "/",
            UserInfo.Length: 0, Query.Length: 0, Fragment.Length: 0
        } &&
            Text(owner, 128) && Text(observerIdentity, 128) && capability is not null &&
            scope is not null && scope.ExclusiveFixtureNamespace && scope.AllowPurge &&
            source is not null && source.Journal is not null && source.Provisioner is not null &&
            source.Metadata is not null && source.CollectorLimits is not null && source.SelectedTransport is not null &&
            limits is not null && limits.MaximumBodyBytes is >= 1024 and <= 1024 * 1024 &&
            limits.MaximumReplyBytes is >= 1024 and <= 1024 * 1024 &&
            limits.Timeout > TimeSpan.Zero && limits.Timeout <= TimeSpan.FromMinutes(2));
        this.baseline = Snapshot(source.Provisioner.SettingsBaseline(source.Journal, scope,
            source.Metadata, source.SelectedTransport));
        Require(E.SameConfiguration(this.baseline, Snapshot(baseline)));
        this.origin = origin;
        this.owner = owner;
        this.observerIdentity = observerIdentity;
        this.capability = capability;
        this.scope = scope;
        settingsSource = source;
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
        principals = [];
        settingsMetadata = new(new(source.Metadata.Label, source.Metadata.Credential,
            new SettingsMetadataTransport(this)), source.CollectorLimits, this.time);
        SelectedTransport = new SettingsTransport(this);
    }

    // Token constructors deliberately confer no authority. In particular, a
    // copied dispatch, substituted task or reopened process has no registry entry.
    internal sealed class SettingsAdmission(VaultFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.settingsAdmissions.TryGetValue(this, out var evidence) &&
            source.SettingsRoot(journal, snapshot, evidence) &&
            evidence.Before.CollectorTask.IsCompletedSuccessfully && evidence.Before.ParentTask.IsCompletedSuccessfully;
        public override string ToString() => "[VaultSettingsAdmission]";
    }

    internal sealed class SettingsTermination(VaultFixtureObserverService source, Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.settingsTerminations.TryGetValue(this, out var evidence) &&
            evidence.Dispatch == Dispatch && Dispatch != Guid.Empty &&
            (evidence.Task is null || evidence.Task.IsCompleted) &&
            (evidence.SendTask is null || evidence.SendTask.IsCompleted) &&
            source.SettingsRoot(journal, snapshot, evidence.Baseline);
        public override string ToString() => "[VaultSettingsTermination]";
    }

    internal sealed class SettingsSettlement(VaultFixtureObserverService source, Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal E.Configuration Configuration =>
            DecodeConfiguration(source.TrySettingsCompletion(this, out var evidence)
                ? evidence.Configuration : throw Failure());
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.TrySettingsCompletion(this, out var evidence) &&
            evidence.Finished.Dispatch == Dispatch && Dispatch != Guid.Empty &&
            evidence.Finished.Task is { IsCompleted: true } &&
            evidence.After.CollectorTask.IsCompletedSuccessfully && evidence.After.ParentTask.IsCompletedSuccessfully &&
            source.SettingsRoot(journal, snapshot, evidence.Finished.Baseline);
        public override string ToString() => "[VaultSettingsSettlement]";
    }

    // Registry values never reference a mutable completion flag or call back
    // into the service/provisioner. Task identity and all conclusions are frozen
    // only after the source itself awaited the actual task and disposed borrowers.
    private sealed record SettingsBaseline(P.Plan Plan, P.SettingsLoan Loan, SettingsObservation Before)
    {
        public override string ToString() => "[VaultSettingsBaseline]";
    }
    private sealed record SettingsObservation(M.Window Window, Task<M.Measurement> CollectorTask,
        M.Measurement Measurement, Task<P.SettingsWitness> ParentTask, P.SettingsWitness Parent,
        string Configuration, string UnchangedDigest, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[VaultSettingsObservation]";
    }
    private sealed record SettingsNative(int Status, string? Configuration, string UnchangedDigest,
        string RequestDigest, string ResponseDigest, string NativeRequestId, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[VaultSettingsNative]";
    }
    private sealed record SettingsFinished(SettingsBaseline Baseline, Guid Dispatch,
        VaultAdministration Client, VaultScope Scope, VaultSettingsPatch Patch, ManagementReceipt Receipt,
        Task<SecretOutcome<VaultObservation>>? Task, Task? SendTask, SecretOutcome<VaultObservation>? Outcome, SecretStatus? Status,
        VaultObservation? Value, bool Canceled, bool Rejected, bool Eligible, SettingsNative? Native,
        DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[VaultSettingsFinished]";
    }
    private sealed record SettingsCompleted(SettingsFinished Finished, SettingsObservation After, string Configuration)
    {
        public override string ToString() => "[VaultSettingsCompleted]";
    }

    private bool TrySettingsCompletion(SettingsSettlement candidate,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out SettingsCompleted? evidence)
    {
        if (settingsSettlements.TryGetValue(candidate, out evidence))
            return evidence.Finished is { Eligible: true, Rejected: false, Native: not null };
        if (settingsRejections.TryGetValue(candidate, out evidence))
            return evidence.Finished is
            {
                Eligible: true, Rejected: true, Native: null,
                Status: SecretStatus.Invalid, Task.IsCompletedSuccessfully: true
            };
        return false;
    }

    private bool SettingsRoot(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state, SettingsBaseline evidence)
    {
        var plan = evidence.Plan;
        return settingsSource is not null && ReferenceEquals(journal, settingsSource.Journal) &&
            ReferenceEquals(evidence.Loan.Plan, plan) && !plan.Restored && state.Owner == owner &&
            state.Selector == plan.Selector && state.LeaseId == plan.LeaseId &&
            state.Settings is { } settings && settings.VaultId == plan.VaultId &&
            E.SameConfiguration(settings.Baseline, DecodeConfiguration(evidence.Before.Configuration)) &&
            state.PrivateEndpoint is null && state.Resources.Length == 3 &&
            plan.Manifest.Count == 3 && plan.Manifest.All(m => state.Resources.Count(r =>
                r.Id == m.Id && r.Borrowed == m.Borrowed && r.CleanupOnly == m.CleanupOnly) == 1);
    }

    private sealed class SettingsStorage
    {
        internal readonly List<IDisposable> Items = [];
        internal readonly List<byte[]> Bytes = [];
        internal void Clear()
        {
            bool failed = false;
            foreach (var item in Items)
                try { item.Dispose(); }
                catch (Exception) { failed = true; }
            Items.Clear();
            foreach (var bytes in Bytes) CryptographicOperations.ZeroMemory(bytes);
            Bytes.Clear();
            Require(!failed);
        }
    }

    private sealed class SettingsCall(Session session, VaultAdministration client, VaultScope scope,
        VaultSettingsPatch patch, ManagementReceipt receipt, SettingsBaseline baseline, SettingsAdmission admission)
    {
        internal readonly Session Session = session;
        internal readonly VaultAdministration Client = client;
        internal readonly VaultScope Scope = scope;
        internal readonly VaultSettingsPatch Patch = patch;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly SettingsBaseline Baseline = baseline;
        internal readonly SettingsAdmission Admission = admission;
        internal readonly SettingsStorage Storage = new();
        internal Task<SecretOutcome<VaultObservation>>? Task;
        internal Task? SendTask;
        internal Request? Request;
        internal SettingsNative? Native;
        internal SettingsFinished? Finished;
        internal SettingsTermination? Termination;
        internal SettingsResponseStream? ResponseStream;
        internal byte[]? ResponseBytes;
        internal string? ResponseDigest;
        internal Guid Dispatch;
        internal int Sends;
        internal bool Attempted, ThroughSource, RequestClaimed;
    }

    private sealed class SettingsRead(Session session, E.Configuration expected)
    {
        internal readonly Session Session = session;
        internal readonly E.Configuration Expected = Snapshot(expected);
        internal readonly SettingsStorage Storage = new();
        internal SettingsResource? Raw;
        internal Request? Request;
        internal int Sends;
    }

    private static void ValidateSettingsSelector(FixtureSelector selector)
    {
        Require(selector is not null && selector.Nonce != Guid.Empty &&
            new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }.All(v => Text(v, 512)) &&
            selector.Operation == M.Operation(M.QueryKind.UpdateSettings) &&
            E.Members.Single(m => m.Operation == selector.Operation).Variants.Contains(selector.Variant) &&
            selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
                "cancellation-boundary" or "lost-response-no-replay");
    }

    private async Task<HttpResponseMessage> PrepareSettings(E.Prepare input, CancellationToken token)
    {
        ValidateSettingsSelector(input.Selection);
        Require(input.SubscriptionId == scope.SubscriptionId && input.ResourceGroup == scope.ResourceGroup &&
            E.SameConfiguration(Snapshot(input.Configuration), E.SettingsConfiguration(baseline, input.Selection.Variant)));
        if (input.Selection.Variant != "purgeProtection.false.rejected")
            Require(!E.SameConfiguration(baseline, E.SettingsConfiguration(baseline, input.Selection.Variant)));
        Session session;
        lock (gate)
        {
            Require(!disposed && sessions.Count < 32 && !sessions.ContainsKey(input.Selection.Nonce));
            session = new(input.Selection) { Active = 1 };
            sessions.Add(input.Selection.Nonce, session);
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            session.Plan = settingsSource!.Provisioner.PlanFixture(owner, session.Selector,
                P.Preparation.Active, [], seedCanary: false);
            var result = await settingsSource.Provisioner.ProvisionAsync(session.Plan,
                cancellationToken: linked.Token).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            Require(result.State == P.State.Ready && result.Configuration is not null &&
                E.SameConfiguration(result.Configuration, baseline));
            var journal = settingsSource.Journal.Read(owner, session.Selector);
            Require(!journal.Closing && journal.Idle && journal.Settings is not null && journal.Resources.Length == 3);
            lock (gate)
            {
                Require(!disposed && !session.Closed);
                session.Lease = new(new(session.Selector.Nonce, session.Plan.LeaseId, observerIdentity,
                    M.ArmOrigin, M.Revision, time.GetUtcNow(), journal.Resources.Select(r => r.Id).ToArray()),
                    session.Plan.VaultName, null, P.Canary, "", Snapshot(baseline), PrivateConnectionState.Unknown);
                return Reply(session.Lease);
            }
        }
        finally { Leave(session); }
    }

    private HttpResponseMessage ArmSettings(ObserveLease input)
    {
        lock (gate)
        {
            var session = Find(input.Nonce, input.LeaseId);
            Require(!session.ArmClaimed && input.SubscriptionId is null && input.Phase == "subscribe-before-trigger");
            session.ArmClaimed = session.Armed = true;
            session.Binding = new(session.Selector, session.Plan!.LeaseId, M.QueryKind.UpdateSettings,
                M.ReadKind.GetVault, scope.SubscriptionId, scope.ResourceGroup, scope.Location,
                session.Plan.VaultName, null);
            session.Subscription = Guid.NewGuid();
            session.ArmedAt = time.GetUtcNow();
            return Reply(new ObservationSubscription(session.Plan.LeaseId, session.Selector.Nonce,
                session.Subscription, session.ArmedAt));
        }
    }

    private async Task<HttpResponseMessage> ObserveSettings(ObserveLease input, CancellationToken token)
    {
        Session session;
        bool before = input.Phase == "baseline-before-dispatch";
        bool retry = false;
        lock (gate)
        {
            session = Find(input.Nonce, input.LeaseId);
            Require(session.Armed && session.Subscription == input.SubscriptionId && session.Active == 0);
            if (before)
            {
                Require(!session.BeforeClaimed && session.SettingsSelected is null);
                session.BeforeClaimed = true;
            }
            else
            {
                Require(input.Phase == "post-operation" && session.BaselineReady);
                // A lost reply or failed durable append may repeat only the
                // retained completed observation, never GET or PATCH.
                if (session.SettingsCompletion is not null)
                    retry = true;
                else
                {
                    Require(!session.AfterClaimed &&
                        (session.SettingsSelected is { Finished: { Eligible: true } } ||
                            session.Selector.Variant == "purgeProtection.false.rejected" && session.SettingsSelected is null));
                    session.AfterClaimed = true;
                }
            }
            session.Active++;
        }
        bool keepLoan = false;
        try
        {
            if (retry) return RetrySettingsReply(session);
            if (before) session.SettingsLoan = settingsSource!.Provisioner.EnterSettings(session.Plan!);
            Require(session.SettingsLoan is not null);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token, lifetime.Token);
            var finished = session.SettingsSelected?.Finished;
            E.Configuration expected = before || finished is null || finished.Rejected || finished.Native?.Status == 403
                ? baseline : E.SettingsConfiguration(baseline, session.Selector.Variant);
            var observation = await CollectSettings(session, expected, linked.Token).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            if (before)
            {
                lock (gate)
                {
                    Require(!disposed && !session.Closed);
                    session.SettingsBefore = observation;
                    session.BaselineAt = observation.FinishedAt;
                    session.BaselineReady = true;
                    keepLoan = true;
                }
            }
            else
            {
                Require(session.SettingsBefore is { } prior &&
                    observation.UnchangedDigest == prior.UnchangedDigest &&
                    observation.FinishedAt >= prior.FinishedAt);
                if (finished is not null)
                {
                    Require(finished.Eligible && finished.Task is { IsCompleted: true } &&
                        observation.Window.ArmedAt >= finished.FinishedAt &&
                        observation.Measurement.StartedAt >= finished.FinishedAt &&
                        (finished.Native is null || finished.Native.UnchangedDigest == observation.UnchangedDigest));
                    var completed = new SettingsCompleted(finished, observation, observation.Configuration);
                    SettingsSettlement certificate;
                    lock (gate)
                    {
                        Require(!disposed && !session.Closed);
                        certificate = new(this, finished.Dispatch);
                        // Actual Invalid/NotDispatched rejection has a separate
                        // registry; it never masquerades as a native response.
                        Require((finished.Rejected ? settingsRejections : settingsSettlements)
                            .TryAdd(certificate, completed));
                        session.SettingsCompletion = certificate;
                    }
                    // No service lock is held while the journal validates the
                    // immutable conjunction or writes the durable configuration.
                    RetrySettingsSettlement(session);
                }
            }
            lock (gate) Require(!disposed && !session.Closed);
            return Reply(SettingsMeasurement(session, observation));
        }
        finally
        {
            try
            {
                if (!keepLoan) ExitSettingsLoan(session);
            }
            finally { Leave(session); }
        }
    }

    private async Task<SettingsObservation> CollectSettings(Session session, E.Configuration expected, CancellationToken token)
    {
        var read = new SettingsRead(session, expected);
        var previous = settingsRead.Value;
        try
        {
            settingsSource!.Provisioner.CheckSettingsLoan(session.SettingsLoan!);
            settingsRead.Value = read;
            var window = settingsMetadata!.Arm(session.Binding!);
            var task = settingsMetadata.CollectAsync(window, session.Binding!, token).AsTask();
            var measured = await task.ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            Require(read.Raw is not null && measured.ResponseComplete && measured.Status == SecretStatus.Success &&
                ReferenceEquals(measured.Binding, session.Binding) && measured.WindowId == window.Id &&
                measured.Identity == settingsSource.Metadata.Label && measured.Vaults.Count == 1 &&
                measured.DeletedVaults.Count == 0 && measured.Connections.Count == 0 && measured.PrivateLinks.Count == 0 &&
                measured.NameAvailable is null && measured.NativeRequestIds.Count == 1 &&
                measured.Vaults[0].Configuration is { } configuration &&
                E.SameConfiguration(Project(configuration), expected) &&
                measured.Vaults[0].Row.ProvisioningState == NativeProvisioningState.Succeeded);
            // The collector keeps its original UpdateSettings/GetVault binding.
            // A distinct parent invocation obtains active AND deleted facts.
            var parentTask = settingsSource.Provisioner.ObserveSettingsAsync(session.SettingsLoan!, expected, token).AsTask();
            var parent = await parentTask.ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            Require(parent.Result.State == P.State.Ready && parent.Result.VaultPresent == true &&
                parent.Result.DeletedVaultPresent == false && parent.Result.Configuration is not null &&
                E.SameConfiguration(parent.Result.Configuration, expected) &&
                parent.UnchangedDigest == read.Raw.UnchangedDigest);
            return new(window, task, measured, parentTask, parent, EncodeConfiguration(expected),
                read.Raw.UnchangedDigest, time.GetUtcNow());
        }
        finally
        {
            settingsRead.Value = previous;
            read.Storage.Clear();
        }
    }

    private E.Measurement SettingsMeasurement(Session session, SettingsObservation observation)
    {
        var configuration = DecodeConfiguration(observation.Configuration);
        return new(session.Plan!.LeaseId, session.Selector.Nonce, observerIdentity, observation.FinishedAt,
            session.Plan.VaultId, SecretStatus.Success, SecretStatus.Absent, configuration, configuration.Policies,
            PrivateConnectionState.Unknown, SecretStatus.Absent, [], null,
            [new(session.Plan.VaultId, NativeProvisioningState.Succeeded, configuration.Rbac,
                configuration.PurgeProtection, configuration.RetentionDays)], [], [], [], null);
    }

    private HttpResponseMessage RetrySettingsReply(Session session)
    {
        // This method is called outside the admission lock by the retry route.
        RetrySettingsSettlement(session);
        Require(TrySettingsCompletion(session.SettingsCompletion!, out var completed));
        return Reply(SettingsMeasurement(session, completed.After));
    }

    private void RetrySettingsSettlement(Session session)
    {
        var call = session.SettingsSelected ?? throw Failure();
        Require(call.Termination is not null && session.SettingsCompletion is not null);
        var journal = settingsSource!.Journal.Read(owner, session.Selector);
        if (journal.Settings?.SettledDispatch != call.Dispatch)
            settingsSource.Journal.EndSettingsInvocation(owner, session.Selector, session.Plan!.LeaseId, call.Termination);
        settingsSource.Journal.RegisterSettingsSettlement(owner, session.Selector, session.Plan!.LeaseId,
            session.SettingsCompletion);
        settingsSource.Journal.SettleSettingsInvocation(owner, session.Selector, session.Plan!.LeaseId,
            session.SettingsCompletion);
    }

    public async ValueTask<SecretOutcome<VaultObservation>> RunUpdateSettingsAsync(FixtureSelector selector,
        VaultAdministration client, VaultScope scope, VaultSettingsPatch settings, ManagementReceipt receipt,
        CancellationToken cancellationToken)
    {
        Require(settingsSource is not null && client is not null && scope is not null && settings is not null &&
            receipt is not null && receipt.Evidence == DispatchEvidence.NotDispatched);
        ValidateSettingsSelector(selector);
        Require(selector.Variant != "purgeProtection.false.rejected" && MatchesSettingsPatch(selector, settings));
        Session session;
        SettingsCall call;
        lock (gate)
        {
            Require(sessions.TryGetValue(selector.Nonce, out session!) && !disposed && !session.Closed &&
                session.Selector == selector && session.Armed && session.BaselineReady &&
                session.SettingsBefore is not null && session.SettingsLoan is not null &&
                session.SettingsSelected is null && !session.AfterClaimed && session.Active == 0 &&
                scope.ExportResourceId() == session.Plan!.VaultId);
            var evidence = new SettingsBaseline(session.Plan, session.SettingsLoan, session.SettingsBefore);
            var admission = new SettingsAdmission(this);
            Require(settingsAdmissions.TryAdd(admission, evidence));
            call = new(session, client, scope, settings, receipt, evidence, admission);
            session.SettingsSelected = call;
            session.Active++;
            active++;
        }
        var previous = currentSettings.Value;
        SecretStatus? status = null;
        SecretOutcome<VaultObservation>? outcome = null;
        VaultObservation? value = null;
        bool canceled = false, clean = false, responseIntact = false, unread = false;
        CancellationTokenSource? deadline = null, linked = null;
        try
        {
            settingsSource.Provisioner.CheckSettingsLoan(call.Baseline.Loan);
            call.Dispatch = settingsSource.Journal.BeginSettingsInvocation(owner, selector, session.Plan!.LeaseId, call.Admission);
            // The owner and durable reservation already exist if timer creation
            // or linked-token registration throws.
            deadline = new(limits.Timeout, time);
            linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token,
                session.Stop.Token, lifetime.Token);
            linked.Token.ThrowIfCancellationRequested();
            currentSettings.Value = call;
            // Exactly one actual SDK task, with original object references.
            call.Task = client.UpdateSettingsAsync(scope, settings, receipt, linked.Token).AsTask();
            var result = await call.Task.ConfigureAwait(false);
            outcome = result;
            status = result.Status;
            value = result.IsSuccess ? result.Value : null;
            linked.Token.ThrowIfCancellationRequested();
            return result;
        }
        catch (OperationCanceledException)
        {
            canceled = call.Task is { IsCanceled: true } && cancellationToken.IsCancellationRequested &&
                !session.Stop.IsCancellationRequested && !lifetime.IsCancellationRequested &&
                deadline is { IsCancellationRequested: false };
            throw;
        }
        finally
        {
            currentSettings.Value = previous;
            try
            {
                responseIntact = call.ResponseBytes is not null && call.ResponseDigest is not null &&
                    Convert.ToHexString(SHA256.HashData(call.ResponseBytes)) == call.ResponseDigest;
                unread = call.ResponseStream is { Reads: 0 };
                try { call.Storage.Clear(); }
                finally
                {
                    try { linked?.Dispose(); }
                    finally { deadline?.Dispose(); }
                }
                clean = true;
            }
            finally
            {
                try
                {
                    bool rejected = clean && call.Task is { IsCompletedSuccessfully: true } &&
                        status == SecretStatus.Invalid && !call.RequestClaimed && call.Request is null &&
                        !call.ThroughSource && call.Sends == 0 && !call.Attempted &&
                        receipt.Evidence == DispatchEvidence.NotDispatched;
                    bool complete = clean && call.Task is { IsCompleted: true } && call.SendTask is { IsCompletedSuccessfully: true } &&
                        call.Sends == 1 && call.Attempted && call.Native is not null && responseIntact;
                    bool eligible = rejected || complete && (call.Native!.Status == 403
                        ? status == SecretStatus.Denied
                        : status == SecretStatus.Success && MatchesSettingsValue(value, scope,
                            E.SettingsConfiguration(baseline, selector.Variant)) ||
                            selector.Case == "cancellation-boundary" && canceled && unread ||
                            selector.Case == "lost-response-no-replay" && status == SecretStatus.Unknown && unread &&
                                receipt.Evidence == DispatchEvidence.PossiblyDispatched);
                    var finished = new SettingsFinished(call.Baseline, call.Dispatch, client, scope, settings, receipt,
                        call.Task, call.SendTask, outcome, status, value, canceled, rejected, eligible, call.Native, time.GetUtcNow());
                    call.Finished = finished;
                    if (call.Dispatch != Guid.Empty)
                    {
                        var termination = new SettingsTermination(this, call.Dispatch);
                        Require(settingsTerminations.TryAdd(termination, finished));
                        call.Termination = termination;
                        settingsSource.Journal.EndSettingsInvocation(owner, selector, session.Plan!.LeaseId, termination);
                    }
                }
                finally
                {
                    try { Leave(session); }
                    finally { EndRequest(); }
                }
            }
        }
    }

    private static bool MatchesSettingsValue(VaultObservation? value, VaultScope scope, E.Configuration expected) =>
        value is not null && ReferenceEquals(value.Scope, scope) &&
        value.ProvisioningState == NativeProvisioningState.Succeeded &&
        value.EnableRbacAuthorization == expected.Rbac && value.EnablePurgeProtection == expected.PurgeProtection &&
        value.RetentionDays == expected.RetentionDays && !value.RuntimeDeliveryProven;

    private static bool MatchesSettingsPatch(FixtureSelector selector, VaultSettingsPatch patch)
    {
        var (name, value) = SettingsField(selector.Variant);
        return patch.EnableRbacAuthorization == (name == "enableRbacAuthorization" ? (bool?)value : null) &&
            patch.EnablePurgeProtection == (name == "enablePurgeProtection" ? (bool?)value : null) &&
            patch.PublicNetworkAccess == (name == "publicNetworkAccess" ? (bool?)value : null);
    }

    private static (string Name, bool Value) SettingsField(string variant) => variant switch
    {
        "rbac.omitted" or "publicNetworkAccess.true" => ("publicNetworkAccess", true),
        "rbac.false" => ("enableRbacAuthorization", false),
        "rbac.true" or "purgeProtection.omitted" or "publicNetworkAccess.omitted" => ("enableRbacAuthorization", true),
        "purgeProtection.true" => ("enablePurgeProtection", true),
        "publicNetworkAccess.false" => ("publicNetworkAccess", false),
        "purgeProtection.false.rejected" => ("enablePurgeProtection", false),
        _ => throw Failure()
    };

    private sealed class SettingsTransport(VaultFixtureObserverService service) : HttpPipelineTransport
    {
        private SettingsCall Current => service.currentSettings.Value ?? throw Failure();
        public override Request CreateRequest()
        {
            var call = Current;
            Require(!call.RequestClaimed && call.Request is null && call.Dispatch != Guid.Empty);
            call.RequestClaimed = true;
            service.CheckSettingsCall(call);
            return call.Request = service.settingsSource!.SelectedTransport.CreateRequest();
        }
        public override void Process(HttpMessage message) => throw Failure();
        public override ValueTask ProcessAsync(HttpMessage message)
        {
            var call = Current;
            call.ThroughSource = true;
            Require(Interlocked.Increment(ref call.Sends) == 1);
            return service.SendSettings(call, message);
        }
    }

    private void CheckSettingsCall(SettingsCall call)
    {
        lock (gate)
            Require(!disposed && !call.Session.Closed && ReferenceEquals(call.Session.SettingsSelected, call) &&
                call.Finished is null);
        settingsSource!.Provisioner.CheckSettingsLoan(call.Baseline.Loan);
        var journal = settingsSource.Journal.Read(owner, call.Session.Selector);
        Require(!journal.Closing && journal.Settings?.InvocationDispatch == call.Dispatch &&
            journal.Resources.Single(r => r.Id == call.Session.Plan!.VaultId).ActiveDispatch == call.Dispatch);
    }

    private async ValueTask SendSettings(SettingsCall call, HttpMessage message)
    {
        ValidateSettingsRequest(call.Request, message, call.Session.Plan!.VaultId, RequestMethod.Patch);
        var original = message.Request.Content ?? throw Failure();
        call.Storage.Items.Add(original);
        using var captured = new RequestBuffer(limits.MaximumBodyBytes);
        Require(original.TryComputeLength(out long length) && length is > 0 && length <= limits.MaximumBodyBytes);
        Require(message.Request.Headers.TryGetValue("Content-Type", out var contentType) &&
            contentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
        if (message.Request.Headers.TryGetValue("Content-Length", out var declaredLength))
            Require(long.TryParse(declaredLength, NumberStyles.None, CultureInfo.InvariantCulture, out long declared) &&
                declared == length);
        await original.WriteToAsync(captured, message.CancellationToken).ConfigureAwait(false);
        Require(captured.Length == length);
        byte[] bytes = captured.Bytes.ToArray();
        call.Storage.Bytes.Add(bytes);
        using (var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 }))
        {
            var root = document.RootElement;
            Unique(root);
            var (name, value) = SettingsField(call.Session.Selector.Variant);
            Require(Only(root, "properties") && root.EnumerateObject().Count() == 1);
            var properties = root.GetProperty("properties");
            Require(Only(properties, name) && properties.EnumerateObject().Count() == 1);
            var actual = properties.GetProperty(name);
            Require(name == "publicNetworkAccess"
                ? actual.ValueKind == JsonValueKind.String && actual.GetString() == (value ? "Enabled" : "Disabled")
                : actual.ValueKind == (value ? JsonValueKind.True : JsonValueKind.False));
        }
        var frozen = new SettingsContent(bytes);
        call.Storage.Items.Add(frozen);
        string digest = Convert.ToHexString(SHA256.HashData(bytes));
        message.Request.Content = frozen;
        message.Request.Headers.SetValue("Content-Type", "application/json");
        message.Request.Headers.SetValue("Content-Length", length.ToString(CultureInfo.InvariantCulture));
        ValidateSettingsRequest(call.Request, message, call.Session.Plan.VaultId, RequestMethod.Patch);
        var headers = message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray();
        message.CancellationToken.ThrowIfCancellationRequested();
        CheckSettingsCall(call);
        // Authentication, body capture and validation precede this durable bit.
        // Close and this admission serialize in the journal, not through a host callback.
        settingsSource!.Journal.AdmitSettingsSend(owner, call.Session.Selector, call.Session.Plan.LeaseId,
            call.Dispatch, call.Admission);
        message.BufferResponse = false;
        call.Attempted = true;
        call.SendTask = settingsSource.SelectedTransport.ProcessAsync(message).AsTask();
        try { await call.SendTask.ConfigureAwait(false); }
        finally { if (message.HasResponse) call.Storage.Items.Add(message.Response); }
        ValidateSettingsRequest(call.Request, message, call.Session.Plan.VaultId, RequestMethod.Patch);
        Require(headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))) &&
            ReferenceEquals(message.Request.Content, frozen) && frozen.Digest == digest &&
            Convert.ToHexString(SHA256.HashData(bytes)) == digest && message.HasResponse);
        int status = message.Response.Status;
        Require(status is 200 or 201 or 403);
        byte[] response = await CaptureSettingsBody(message, call.Storage).ConfigureAwait(false);
        call.ResponseBytes = response;
        string responseDigest = call.ResponseDigest = Convert.ToHexString(SHA256.HashData(response));
        call.ResponseStream = new SettingsResponseStream(response);
        call.Storage.Items.Add(call.ResponseStream);
        message.Response.ContentStream = call.ResponseStream;
        var expected = status == 403 ? baseline : E.SettingsConfiguration(baseline, call.Session.Selector.Variant);
        string unchanged;
        using (var document = JsonDocument.Parse(response, new JsonDocumentOptions { MaxDepth = 32 }))
        {
            Unique(document.RootElement);
            if (status == 403)
            {
                ValidateDenied(document.RootElement);
                unchanged = call.Baseline.Before.UnchangedDigest;
            }
            else unchanged = ParseSettingsResource(call.Session.Plan, document.RootElement, expected).UnchangedDigest;
        }
        Require(unchanged == call.Baseline.Before.UnchangedDigest);
        ValidateSettingsRequest(call.Request, message, call.Session.Plan.VaultId, RequestMethod.Patch);
        Require(headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))) &&
            ReferenceEquals(message.Request.Content, frozen) && frozen.Digest == digest);
        message.CancellationToken.ThrowIfCancellationRequested();
        // Complete inner evidence precedes the outer canonical loss/cancel hook.
        Require(message.Response.Headers.TryGetValue("x-ms-request-id", out var requestId));
        call.Native = new(status, status == 403 ? null : EncodeConfiguration(expected), unchanged, digest,
            responseDigest, requestId, time.GetUtcNow());
    }

    private sealed class SettingsContent : RequestContent
    {
        private readonly byte[] bytes;
        internal SettingsContent(byte[] value) => bytes = value.ToArray();
        internal string Digest => Convert.ToHexString(SHA256.HashData(bytes));
        public override bool TryComputeLength(out long length) { length = bytes.Length; return true; }
        public override void WriteTo(Stream stream, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            byte[] copy = bytes.ToArray();
            try { stream.Write(copy); Require(copy.AsSpan().SequenceEqual(bytes)); }
            finally { CryptographicOperations.ZeroMemory(copy); }
        }
        public override async Task WriteToAsync(Stream stream, CancellationToken cancellationToken)
        {
            byte[] copy = bytes.ToArray();
            try
            {
                await stream.WriteAsync(copy, cancellationToken).ConfigureAwait(false);
                Require(copy.AsSpan().SequenceEqual(bytes));
            }
            finally { CryptographicOperations.ZeroMemory(copy); }
        }
        public override void Dispose() => CryptographicOperations.ZeroMemory(bytes);
    }

    private sealed class SettingsResponseStream(byte[] bytes) : MemoryStream(bytes, writable: false)
    {
        internal int Reads;
        public override int Read(byte[] buffer, int offset, int count)
        {
            Interlocked.Increment(ref Reads);
            return base.Read(buffer, offset, count);
        }
        public override int Read(Span<byte> buffer)
        {
            Interlocked.Increment(ref Reads);
            return base.Read(buffer);
        }
        public override int ReadByte()
        {
            Interlocked.Increment(ref Reads);
            return base.ReadByte();
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref Reads);
            return base.ReadAsync(buffer, cancellationToken);
        }
        public override void CopyTo(Stream destination, int bufferSize)
        {
            Interlocked.Increment(ref Reads);
            base.CopyTo(destination, bufferSize);
        }
        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref Reads);
            return base.CopyToAsync(destination, bufferSize, cancellationToken);
        }
    }

    private void ValidateSettingsRequest(Request? original, HttpMessage message, string id, RequestMethod method)
    {
        var uri = message.Request.Uri.ToUri();
        Require(ReferenceEquals(original, message.Request) && message.Request.Method == method &&
            uri.Scheme == "https" && uri.IsDefaultPort && uri.GetLeftPart(UriPartial.Authority) == M.ArmOrigin &&
            uri.AbsolutePath.Equals(id, StringComparison.OrdinalIgnoreCase) &&
            uri.Query == "?api-version=" + M.Revision && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
            message.Request.Headers.TryGetValue("Authorization", out var authorization) &&
            authorization.StartsWith("Bearer ", StringComparison.Ordinal) && Text(authorization[7..], 16377) &&
            !message.Request.Headers.Contains("Content-Encoding") && !message.Request.Headers.Contains("Transfer-Encoding"));
        var headers = message.Request.Headers.ToArray();
        Require(headers.Length <= 32 && headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
            headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
            headers.All(h => Text(h.Name, 128) && Text(h.Value, 16384)));
        if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
        if (method == RequestMethod.Get)
            Require(message.Request.Content is null && !message.Request.Headers.Contains("Content-Length"));
    }

    private async Task<byte[]> CaptureSettingsBody(HttpMessage message, SettingsStorage storage)
    {
        var response = message.Response;
        int status = response.Status;
        long? declared = ValidateResponseHeaders(response);
        var headers = response.Headers.Select(h => (h.Name, h.Value)).ToArray();
        byte[] buffer = new byte[limits.MaximumReplyBytes + 1];
        storage.Bytes.Add(buffer);
        int count = 0;
        if (message.Response.ContentStream is { } input)
        {
            storage.Items.Add(input);
            while (true)
            {
                int read = await input.ReadAsync(buffer.AsMemory(count), message.CancellationToken).ConfigureAwait(false);
                if (read == 0) break;
                count += read;
                Require(count <= limits.MaximumReplyBytes);
            }
        }
        Require(count > 0 && count <= limits.MaximumReplyBytes && (declared is null || declared == count));
        Require(ReferenceEquals(message.Response, response) && response.Status == status &&
            headers.SequenceEqual(response.Headers.Select(h => (h.Name, h.Value))));
        byte[] exact = buffer.AsSpan(0, count).ToArray();
        storage.Bytes.Add(exact);
        var stream = new MemoryStream(exact, writable: false);
        storage.Items.Add(stream);
        message.Response.ContentStream = stream;
        return exact;
    }

    private sealed class SettingsMetadataTransport(VaultFixtureObserverService service) : HttpPipelineTransport
    {
        private SettingsRead Current => service.settingsRead.Value ?? throw Failure();
        public override Request CreateRequest()
        {
            var read = Current;
            Require(read.Request is null);
            service.settingsSource!.Provisioner.CheckSettingsLoan(read.Session.SettingsLoan!);
            return read.Request = service.settingsSource.Metadata.Transport.CreateRequest();
        }
        public override void Process(HttpMessage message) => throw Failure();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            var read = Current;
            Require(Interlocked.Increment(ref read.Sends) == 1);
            service.ValidateSettingsRequest(read.Request, message, read.Session.Plan!.VaultId, RequestMethod.Get);
            service.settingsSource!.Provisioner.CheckSettingsLoan(read.Session.SettingsLoan!);
            var headers = message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray();
            message.BufferResponse = false;
            try { await service.settingsSource.Metadata.Transport.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) read.Storage.Items.Add(message.Response); }
            service.ValidateSettingsRequest(read.Request, message, read.Session.Plan.VaultId, RequestMethod.Get);
            Require(headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))) &&
                message.HasResponse && message.Response.Status == 200);
            byte[] bytes = await service.CaptureSettingsBody(message, read.Storage).ConfigureAwait(false);
            service.ValidateSettingsRequest(read.Request, message, read.Session.Plan.VaultId, RequestMethod.Get);
            Require(headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
            read.Raw = ParseSettingsResource(read.Session.Plan, document.RootElement, read.Expected);
        }
    }

    internal sealed record SettingsResource(string Configuration, string UnchangedDigest)
    {
        public override string ToString() => "[VaultSettingsResource]";
    }

    // A closed, complete native schema. Every admitted optional field participates
    // in the unchanged digest; no unvalidated extension can prove preservation.
    internal static SettingsResource ParseSettingsResource(P.Plan plan, JsonElement root, E.Configuration expected)
    {
        Unique(root);
        Require(Only(root, "id", "name", "type", "location", "tags", "properties") &&
            root.GetProperty("id").GetString()!.Equals(plan.VaultId, StringComparison.OrdinalIgnoreCase) &&
            root.GetProperty("name").GetString() == plan.VaultName &&
            root.GetProperty("type").GetString()!.Equals("Microsoft.KeyVault/vaults", StringComparison.OrdinalIgnoreCase) &&
            root.GetProperty("location").GetString() == expected.Location);
        var tags = root.GetProperty("tags");
        Require(Only(tags, "secretkit-fixture") && tags.EnumerateObject().Count() == 1 &&
            tags.GetProperty("secretkit-fixture").GetString() == plan.Selector.Nonce.ToString("N"));
        var properties = root.GetProperty("properties");
        Require(Only(properties, "tenantId", "sku", "accessPolicies", "vaultUri", "provisioningState",
            "enableRbacAuthorization", "enablePurgeProtection", "enableSoftDelete", "softDeleteRetentionInDays",
            "publicNetworkAccess", "createMode", "enabledForDeployment", "enabledForDiskEncryption",
            "enabledForTemplateDeployment"));
        Require(properties.GetProperty("tenantId").GetGuid() == expected.TenantId &&
            properties.GetProperty("enableSoftDelete").ValueKind == JsonValueKind.True &&
            properties.GetProperty("enableRbacAuthorization").GetBoolean() == expected.Rbac &&
            properties.GetProperty("enablePurgeProtection").GetBoolean() == expected.PurgeProtection &&
            properties.GetProperty("softDeleteRetentionInDays").GetInt32() == expected.RetentionDays &&
            properties.GetProperty("publicNetworkAccess").GetString() == (expected.PublicNetworkAccess ? "Enabled" : "Disabled") &&
            properties.GetProperty("provisioningState").GetString() == "Succeeded" &&
            Uri.TryCreate(properties.GetProperty("vaultUri").GetString(), UriKind.Absolute, out var vaultUri) &&
            vaultUri == new Uri("https://" + plan.VaultName + ".vault.azure.net") &&
            vaultUri.UserInfo.Length == 0 && vaultUri.Query.Length == 0 && vaultUri.Fragment.Length == 0);
        var sku = properties.GetProperty("sku");
        Require(Only(sku, "family", "name") && sku.GetProperty("family").GetString() == "A" &&
            string.Equals(sku.GetProperty("name").GetString(), expected.Sku.ToString(), StringComparison.OrdinalIgnoreCase));
        if (properties.TryGetProperty("createMode", out var mode)) Require(mode.GetString() == "default");
        foreach (string name in new[] { "enabledForDeployment", "enabledForDiskEncryption", "enabledForTemplateDeployment" })
            if (properties.TryGetProperty(name, out var value))
                Require(value.ValueKind is JsonValueKind.True or JsonValueKind.False);
        var policies = properties.GetProperty("accessPolicies");
        Require(policies.ValueKind == JsonValueKind.Array && policies.GetArrayLength() <= 16);
        Require(E.SamePolicies(policies.EnumerateArray().Select(p => ParsePolicy(p)).ToArray(), expected.Policies));
        var (changed, _) = SettingsField(plan.Selector.Variant);
        using var canonical = new MemoryStream();
        using (var writer = new Utf8JsonWriter(canonical)) WriteCanonical(root, writer, changed, false);
        byte[] bytes = canonical.ToArray();
        try { return new(EncodeConfiguration(expected), Convert.ToHexString(SHA256.HashData(bytes))); }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            if (canonical.TryGetBuffer(out var memory)) CryptographicOperations.ZeroMemory(memory.AsSpan());
        }
    }

    private static void WriteCanonical(JsonElement value, Utf8JsonWriter writer, string changed, bool properties)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            writer.WriteStartObject();
            foreach (var field in value.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
            {
                if (properties && field.Name == changed) continue;
                writer.WritePropertyName(field.Name);
                // ARM resource identity is case-insensitive; all other raw
                // values, optional presence and array contents remain bound.
                if (field.Name == "id") writer.WriteStringValue(field.Value.GetString()!.ToUpperInvariant());
                else WriteCanonical(field.Value, writer, changed, field.Name == "properties");
            }
            writer.WriteEndObject();
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            writer.WriteStartArray();
            foreach (var child in value.EnumerateArray()) WriteCanonical(child, writer, changed, false);
            writer.WriteEndArray();
        }
        else value.WriteTo(writer);
    }

    private static string EncodeConfiguration(E.Configuration configuration) =>
        JsonSerializer.Serialize(Snapshot(configuration), ManagementAdmission.Json);
    private static E.Configuration DecodeConfiguration(string configuration) =>
        Snapshot(JsonSerializer.Deserialize<E.Configuration>(configuration, Json) ?? throw Failure());

    private void ExitSettingsLoan(Session session)
    {
        var loan = session.SettingsLoan;
        if (loan is null) return;
        settingsSource!.Provisioner.ExitSettings(loan);
        session.SettingsLoan = null;
    }

    private async Task<HttpResponseMessage> ReleaseSettings(FixtureSelector selector, CancellationToken token)
    {
        ValidateSettingsSelector(selector);
        Session session;
        lock (gate)
        {
            Require(!disposed);
            if (!sessions.TryGetValue(selector.Nonce, out session!))
            {
                Require(sessions.Count < 32);
                sessions.Add(selector.Nonce, session = new(selector));
            }
            Require(session.Selector == selector && !session.Releasing);
            session.Releasing = true;
        }
        try
        {
            RoleFixtureJournal.Snapshot snapshot;
            try
            {
                // Durable revocation is first. A failed Close cannot reach cleanup.
                snapshot = settingsSource!.Provisioner.CloseSelectedRoot(owner, selector);
            }
            finally
            {
                lock (gate)
                {
                    session.Closed = true;
                    if (session.Active == 0) session.SettingsDrained.TrySetResult();
                }
                try { session.Stop.Cancel(); }
                finally { await session.SettingsDrained.Task.ConfigureAwait(false); }
            }
            ExitSettingsLoan(session);
            if (session.SettingsCompletion is not null) RetrySettingsSettlement(session);
            snapshot = settingsSource!.Journal.Read(owner, selector);
            if (snapshot.Idle && snapshot.Resources.Length != 0)
                snapshot = (await settingsSource.Provisioner.ReleaseAsync(owner, selector, purge: true,
                    cancellationToken: token).ConfigureAwait(false)).Journal;
            return Reply(ReleaseMeasurement(session, snapshot));
        }
        finally { lock (gate) session.Releasing = false; }
    }

    private async Task DrainSettings(TaskCompletionSource completion)
    {
        bool failed = false;
        Session[] owned;
        lock (gate) owned = sessions.Values.ToArray();
        foreach (var session in owned)
        {
            try { settingsSource!.Provisioner.CloseSelectedRoot(owner, session.Selector); }
            catch (Exception) { failed = true; }
            lock (gate)
            {
                session.Closed = true;
                if (session.Active == 0) session.SettingsDrained.TrySetResult();
            }
            try { session.Stop.Cancel(); }
            catch (Exception) { failed = true; }
        }
        try { lifetime.Cancel(); }
        catch (Exception) { failed = true; }
        await drained.Task.ConfigureAwait(false);
        foreach (var session in owned)
        {
            try { ExitSettingsLoan(session); }
            catch (Exception) { failed = true; }
            try { session.SettingsSelected?.Storage.Clear(); }
            catch (Exception) { failed = true; }
            try { session.Stop.Dispose(); }
            catch (Exception) { failed = true; }
        }
        settingsAdmissions.Clear();
        settingsTerminations.Clear();
        settingsSettlements.Clear();
        settingsRejections.Clear();
        try { lifetime.Dispose(); }
        catch (Exception) { failed = true; }
        if (failed) completion.TrySetException(Failure());
        else completion.TrySetResult();
    }
}
