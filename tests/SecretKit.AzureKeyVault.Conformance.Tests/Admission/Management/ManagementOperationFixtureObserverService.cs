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
using S = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationStatusCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Original-invocation owned vault, notification and bound approval composition. Local source evidence does not
// establish deployed authentication, native principal or egress qualification.
internal sealed partial class ManagementOperationFixtureObserverService : E.SelectedInvocation,
    VaultAdministrationEffects.DeleteSelectedInvocation, VaultAdministrationEffects.PurgeSelectedInvocation,
    VaultAdministrationEffects.CreateSelectedInvocation, VaultAdministrationEffects.RecoverSelectedInvocation,
    VaultAdministrationEffects.PrivateConnectionUpdateSelectedInvocation,
    VaultAdministrationEffects.PrivateConnectionDeleteSelectedInvocation, IAsyncDisposable
{
    internal sealed record Limits(int MaximumBodyBytes, int MaximumReplyBytes, TimeSpan Timeout);
    private bool statusPendingPurgeProfile, statusPendingPurgeCleanup;
    private sealed class StatusPendingPurgeIndependentProfile { }
    private StatusPendingPurgeIndependentProfile? pendingIndependentProfile;
    private sealed class StatusPendingPurgeCancellationProfile { }
    private StatusPendingPurgeCancellationProfile? pendingCancellationProfile;
    private bool PendingProfile => statusPendingPurgeProfile || pendingIndependentProfile is not null || pendingCancellationProfile is not null;
    private VaultAdministrationEffects.Configuration? pendingConfiguration;
    private C.StatusPendingPurgeClockBounds? pendingClockBounds;
    private R.Authority? pendingResourceAuthority;
    private R.Limits? pendingResourceLimits;
    private S.Authority? pendingStatusAuthority;
    private S.Limits? pendingStatusLimits;
    private sealed class PendingSession(StatusPendingPurgeIndependentProfile? profile, StatusPendingPurgeCancellationProfile? cancellationProfile)
    {
        internal readonly StatusPendingPurgeIndependentProfile? Profile = profile;
        internal readonly StatusPendingPurgeCancellationProfile? CancellationProfile = cancellationProfile;
        internal CancellationToken OriginalCaller, CanceledOperand;
        internal Task? CanceledTask;
        internal C.StatusPendingPurgeCancellationCanceledProof? CanceledProof;
        internal RoleFixtureJournal.Snapshot? SelectedAdmission;
        internal bool CanceledClaimed, CanceledDrained;
        internal readonly System.Collections.Concurrent.ConcurrentQueue<CancellationToken> Callers = new();
        internal C.StatusPendingPurgeClockWindow? Clock;
        internal DateTimeOffset StartedUtc, ExpiresAt;
        internal long StartedTimestamp;
        internal volatile bool Invalid;
        internal object? Persistence, LastPersistence;
        internal PendingPair? Baseline, Selected;
        internal Task<S.Measurement>? StatusRead;
        internal S.Window? StatusWindow;
        internal PendingStatusTransport? StatusTransport;
        internal PendingStatusWitness? StatusWitness;
        internal Task? CleanupTask;
        internal bool CleanupClaimed, SelectedRevoked, EpochCompleted, NeverSelectedClosed;
    }
    private sealed record PendingRead(R Collector, C.Binding Binding, R.Window Window,
        object Phase, Task<R.Measurement> Task, object Proof);
    private sealed record PendingPair(PendingRead Active, PendingRead Deleted, DateTimeOffset FinishedAt);
    private sealed record PendingStatusWitness(S Collector, S.Window Window, Task<S.Measurement> Task,
        C.StatusTarget Target, C.Binding Binding, PendingStatusTransport Transport, CancellationToken Token);
    private sealed class PendingStatusTransport(HttpPipelineTransport inner, Uri target, int maximum)
        : HttpPipelineTransport, IDisposable
    {
        private readonly OwnedArmResponse.Storage storage = new();
        private Azure.Core.Request? request;
        private OwnedArmResponse.ParserCustody? parser;
        private int sends;
        internal bool Drained { get; private set; }
        internal bool Valid => Drained && parser is { Complete: true, Invalid: false } && sends == 1;
        public override Azure.Core.Request CreateRequest()
        {
            Require(request is null);
            return request = inner.CreateRequest();
        }
        public override void Process(Azure.Core.HttpMessage message) => throw Failure();
        public override async ValueTask ProcessAsync(Azure.Core.HttpMessage message)
        {
            Require(++sends == 1);
            var headers = message.Request.Headers.ToArray();
            void Check()
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                Require(ReferenceEquals(request, message.Request) && headers.SequenceEqual(message.Request.Headers) &&
                    message.Request.Method == Azure.Core.RequestMethod.Get && message.Request.Content is null &&
                    message.Request.Uri.ToUri() == target);
            }
            Check();
            try { await inner.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) storage.Own(message.Response); }
            Check();
            var body = await OwnedArmResponse.CaptureAsync(message, maximum, storage).ConfigureAwait(false);
            Check();
            Require(body.Response.Status == 200);
            using var document = JsonDocument.Parse(body.Bytes);
            Unique(document.RootElement);
            Require(document.RootElement.TryGetProperty("status", out var status) &&
                status.ValueKind == JsonValueKind.String && status.GetString() == "InProgress");
            parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, storage,
                requireRebuffer: false, requireDownstreamRead: true);
        }
        public void Dispose()
        {
            storage.Dispose();
            Drained = true;
        }
    }
    private sealed record PendingFacts(Session Session, RoleFixtureJournal.Snapshot Before,
        RoleFixtureJournal.Snapshot After, CancellationToken[] Tokens, Task[] Tasks, object[] Proofs,
        bool Cleanup = false, bool DrainOnly = false)
    {
        internal volatile bool Invalid;
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeAdmission, PendingFacts>
        pendingAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeStartDrain, PendingFacts>
        pendingStartDrains = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeReadAdmission, PendingFacts>
        pendingReadAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeObservation, PendingFacts>
        pendingObservations = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeCleanupAdmission, PendingFacts>
        pendingCleanupAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeCleanupCompletion, PendingFacts>
        pendingCleanupCompletions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeInvocationDrain, PendingFacts>
        pendingInvocationDrains = new(ReferenceEqualityComparer.Instance);

    internal sealed class StatusPendingPurgeAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingAdmissions.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingAdmissions.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingAdmissions[this].After);
        public override string ToString() => "[StatusPendingPurgeAdmission]";
    }
    internal sealed class StatusPendingPurgeStartDrain(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingStartDrains.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingStartDrains.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingStartDrains[this].After);
        public override string ToString() => "[StatusPendingPurgeStartDrain]";
    }
    internal sealed class StatusPendingPurgeReadAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingReadAdmissions.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingReadAdmissions.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingReadAdmissions[this].After);
        public override string ToString() => "[StatusPendingPurgeReadAdmission]";
    }
    internal sealed class StatusPendingPurgeObservation(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingObservations.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingObservations.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingObservations[this].After);
        public override string ToString() => "[StatusPendingPurgeObservation]";
    }
    internal sealed class StatusPendingPurgeCleanupAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCleanupAdmissions.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCleanupAdmissions.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingCleanupAdmissions[this].After);
        public override string ToString() => "[StatusPendingPurgeCleanupAdmission]";
    }
    internal sealed class StatusPendingPurgeCleanupCompletion(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCleanupCompletions.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCleanupCompletions.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingCleanupCompletions[this].After);
        public override string ToString() => "[StatusPendingPurgeCleanupCompletion]";
    }
    internal sealed class StatusPendingPurgeInvocationDrain(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingInvocationDrains.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingInvocationDrains.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingInvocationDrains[this].After);
        public override string ToString() => "[StatusPendingPurgeInvocationDrain]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeIndependentAdmission, PendingFacts>
        pendingIndependentAdmissions = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusPendingPurgeIndependentAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingIndependentAdmissions.GetValueOrDefault(this), journal, state, false, independent: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingIndependentAdmissions.GetValueOrDefault(this), journal, state, true, independent: true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingIndependentAdmissions[this].After);
        public override string ToString() => "[StatusPendingPurgeIndependentAdmission]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeIndependentStartDrain, PendingFacts>
        pendingIndependentStartDrains = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusPendingPurgeIndependentStartDrain(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingIndependentStartDrains.GetValueOrDefault(this), journal, state, false, independent: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingIndependentStartDrains.GetValueOrDefault(this), journal, state, true, independent: true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingIndependentStartDrains[this].After);
        public override string ToString() => "[StatusPendingPurgeIndependentStartDrain]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeIndependentReadAdmission, PendingFacts>
        pendingIndependentReadAdmissions = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusPendingPurgeIndependentReadAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingIndependentReadAdmissions.GetValueOrDefault(this), journal, state, false, independent: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingIndependentReadAdmissions.GetValueOrDefault(this), journal, state, true, independent: true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingIndependentReadAdmissions[this].After);
        public override string ToString() => "[StatusPendingPurgeIndependentReadAdmission]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeIndependentObservation, PendingFacts>
        pendingIndependentObservations = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusPendingPurgeIndependentObservation(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingIndependentObservations.GetValueOrDefault(this), journal, state, false, independent: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingIndependentObservations.GetValueOrDefault(this), journal, state, true, independent: true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingIndependentObservations[this].After);
        public override string ToString() => "[StatusPendingPurgeIndependentObservation]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeIndependentCleanupAdmission, PendingFacts>
        pendingIndependentCleanupAdmissions = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusPendingPurgeIndependentCleanupAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingIndependentCleanupAdmissions.GetValueOrDefault(this), journal, state, false, independent: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingIndependentCleanupAdmissions.GetValueOrDefault(this), journal, state, true, independent: true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingIndependentCleanupAdmissions[this].After);
        public override string ToString() => "[StatusPendingPurgeIndependentCleanupAdmission]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeIndependentCleanupCompletion, PendingFacts>
        pendingIndependentCleanupCompletions = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusPendingPurgeIndependentCleanupCompletion(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingIndependentCleanupCompletions.GetValueOrDefault(this), journal, state, false, independent: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingIndependentCleanupCompletions.GetValueOrDefault(this), journal, state, true, independent: true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingIndependentCleanupCompletions[this].After);
        public override string ToString() => "[StatusPendingPurgeIndependentCleanupCompletion]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeIndependentInvocationDrain, PendingFacts>
        pendingIndependentInvocationDrains = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusPendingPurgeIndependentInvocationDrain(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingIndependentInvocationDrains.GetValueOrDefault(this), journal, state, false, independent: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingIndependentInvocationDrains.GetValueOrDefault(this), journal, state, true, independent: true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingIndependentInvocationDrains[this].After);
        public override string ToString() => "[StatusPendingPurgeIndependentInvocationDrain]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeCancellationAdmission, PendingFacts>
        pendingCancellationAdmissions = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusPendingPurgeCancellationAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCancellationAdmissions.GetValueOrDefault(this), journal, state, false, cancellation: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCancellationAdmissions.GetValueOrDefault(this), journal, state, true, cancellation: true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingCancellationAdmissions[this].After);
        public override string ToString() => "[StatusPendingPurgeCancellationAdmission]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeCancellationStartDrain, PendingFacts>
        pendingCancellationStartDrains = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusPendingPurgeCancellationStartDrain(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCancellationStartDrains.GetValueOrDefault(this), journal, state, false, cancellation: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCancellationStartDrains.GetValueOrDefault(this), journal, state, true, cancellation: true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingCancellationStartDrains[this].After);
        public override string ToString() => "[StatusPendingPurgeCancellationStartDrain]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeCancellationReadAdmission, PendingFacts>
        pendingCancellationReadAdmissions = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusPendingPurgeCancellationReadAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCancellationReadAdmissions.GetValueOrDefault(this), journal, state, false, cancellation: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCancellationReadAdmissions.GetValueOrDefault(this), journal, state, true, cancellation: true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingCancellationReadAdmissions[this].After);
        public override string ToString() => "[StatusPendingPurgeCancellationReadAdmission]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeCancellationObservation, PendingFacts>
        pendingCancellationObservations = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusPendingPurgeCancellationObservation(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCancellationObservations.GetValueOrDefault(this), journal, state, false, cancellation: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCancellationObservations.GetValueOrDefault(this), journal, state, true, cancellation: true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingCancellationObservations[this].After);
        public override string ToString() => "[StatusPendingPurgeCancellationObservation]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeCancellationCleanupAdmission, PendingFacts>
        pendingCancellationCleanupAdmissions = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusPendingPurgeCancellationCleanupAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCancellationCleanupAdmissions.GetValueOrDefault(this), journal, state, false, cancellation: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCancellationCleanupAdmissions.GetValueOrDefault(this), journal, state, true, cancellation: true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingCancellationCleanupAdmissions[this].After);
        public override string ToString() => "[StatusPendingPurgeCancellationCleanupAdmission]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeCancellationCleanupCompletion, PendingFacts>
        pendingCancellationCleanupCompletions = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusPendingPurgeCancellationCleanupCompletion(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCancellationCleanupCompletions.GetValueOrDefault(this), journal, state, false, cancellation: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCancellationCleanupCompletions.GetValueOrDefault(this), journal, state, true, cancellation: true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingCancellationCleanupCompletions[this].After);
        public override string ToString() => "[StatusPendingPurgeCancellationCleanupCompletion]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeCancellationInvocationDrain, PendingFacts>
        pendingCancellationInvocationDrains = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusPendingPurgeCancellationInvocationDrain(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCancellationInvocationDrains.GetValueOrDefault(this), journal, state, false, cancellation: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingValid(source.pendingCancellationInvocationDrains.GetValueOrDefault(this), journal, state, true, cancellation: true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingCancellationInvocationDrains[this].After);
        public override string ToString() => "[StatusPendingPurgeCancellationInvocationDrain]";
    }
    private bool PendingValid(PendingFacts? facts, RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state, bool post, bool independent = false,
        bool cancellation = false)
    {
        if (facts is null || facts.Invalid || !ReferenceEquals(journal, provisioner.Journal)) return false;
        var p = facts.Session.Pending!;
        if (cancellation ? pendingCancellationProfile is null || !ReferenceEquals(p.CancellationProfile, pendingCancellationProfile) ||
            !VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(facts.Session.Selector) :
            independent ? pendingIndependentProfile is null || !ReferenceEquals(p.Profile, pendingIndependentProfile) ||
            !VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(facts.Session.Selector) :
            !statusPendingPurgeProfile || p.Profile is not null || !VaultFixtureProvisioner.StatusPendingPurgeSelector(facts.Session.Selector))
            return false;
        bool live = facts.DrainOnly || !disposed && !p.Invalid && p.Clock is not null &&
            !p.Clock.Token.IsCancellationRequested && p.Callers.All(t => !t.IsCancellationRequested) &&
            facts.Tokens.All(t => !t.IsCancellationRequested) &&
            (facts.Cleanup ? facts.Session.Closed && p.SelectedRevoked : !facts.Session.Closed);
        bool before = RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.Before, state);
        bool after = RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.After, state);
        if (!live || !before && !after) facts.Invalid = true;
        return !facts.Invalid && facts.Tasks.All(t => t.IsCompleted) && (post ? after : before);
    }
    private void CheckPendingClock(Session session, bool sealedDrain = false)
    {
        var p = session.Pending!;
        bool valid = !disposed && !p.Invalid && p.Callers.All(t => !t.IsCancellationRequested);
        if (p.Clock is not null && !p.EpochCompleted && !p.NeverSelectedClosed)
        {
            var elapsed = TimeProvider.System.GetElapsedTime(p.StartedTimestamp);
            var utc = DateTimeOffset.UtcNow;
            valid &= (sealedDrain || p.Clock.IsValid() && !p.Clock.Token.IsCancellationRequested) &&
                elapsed >= TimeSpan.Zero && elapsed < limits.Timeout && utc >= p.StartedUtc &&
                utc <= p.StartedUtc + elapsed + pendingClockBounds!.MaxForwardUtcDeviation + pendingClockBounds.MaxAuthorizationDelay &&
                utc + pendingClockBounds.MaxAuthorizationDelay + TimeSpan.FromMinutes(5) < p.ExpiresAt;
        }
        if (!valid) p.Invalid = true;
        Require(valid);
    }
    internal static ManagementOperationFixtureObserverService ForStatusPendingPurge(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, S.Authority statusReader, R.Authority resourceReader,
        HttpPipelineTransport selectedBackend, S.Limits statusLimits, R.Limits resourceLimits, Limits limits,
        C.StatusPendingPurgeClockBounds clockBounds, TimeProvider time)
    {
        Require(ReferenceEquals(time, TimeProvider.System) && clockBounds is not null &&
            clockBounds.MaxForwardUtcDeviation >= TimeSpan.Zero && clockBounds.MaxAuthorizationDelay > TimeSpan.Zero &&
            typeof(Azure.Core.TokenCredential).Assembly.GetName().Version == new Version(1, 63, 0, 0) &&
            typeof(Azure.ResourceManager.ArmClient).Assembly.GetName().Version == new Version(1, 14, 0, 0) &&
            typeof(Azure.ResourceManager.KeyVault.KeyVaultResource).Assembly.GetName().Version == new Version(1, 4, 0, 0));
        _ = DateTimeOffset.UtcNow + limits.Timeout + clockBounds.MaxForwardUtcDeviation +
            clockBounds.MaxAuthorizationDelay + TimeSpan.FromMinutes(5);
        var configuration = provisioner.StatusPendingPurgeConfiguration(scope, statusReader, resourceReader, selectedBackend);
        return new(origin, owner, observerIdentity, capability, scope, provisioner, statusReader, resourceReader,
            selectedBackend, statusLimits, resourceLimits, limits, time)
        {
            statusPendingPurgeProfile = true, pendingConfiguration = configuration, pendingClockBounds = clockBounds,
            pendingResourceAuthority = resourceReader, pendingResourceLimits = resourceLimits,
            pendingStatusAuthority = statusReader, pendingStatusLimits = statusLimits
        };
    }
    internal static ManagementOperationFixtureObserverService ForStatusPendingPurgeCleanup(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, Limits limits, TimeProvider time)
    {
        Require(ReferenceEquals(time, TimeProvider.System));
        var configuration = provisioner.StatusPendingPurgeCleanupConfiguration(scope);
        return new(origin, owner, observerIdentity, capability, scope, provisioner, limits, time)
        { statusPendingPurgeProfile = true, statusPendingPurgeCleanup = true, pendingConfiguration = configuration };
    }

    internal static ManagementOperationFixtureObserverService ForStatusPendingPurgeIndependent(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, S.Authority statusReader, R.Authority resourceReader,
        HttpPipelineTransport selectedBackend, S.Limits statusLimits, R.Limits resourceLimits, Limits limits,
        C.StatusPendingPurgeClockBounds clockBounds, TimeProvider time)
    {
        Require(ReferenceEquals(time, TimeProvider.System) && clockBounds is not null &&
            clockBounds.MaxForwardUtcDeviation >= TimeSpan.Zero && clockBounds.MaxAuthorizationDelay > TimeSpan.Zero &&
            typeof(Azure.Core.TokenCredential).Assembly.GetName().Version == new Version(1, 63, 0, 0) &&
            typeof(Azure.ResourceManager.ArmClient).Assembly.GetName().Version == new Version(1, 14, 0, 0) &&
            typeof(Azure.ResourceManager.KeyVault.KeyVaultResource).Assembly.GetName().Version == new Version(1, 4, 0, 0));
        _ = DateTimeOffset.UtcNow + limits.Timeout + clockBounds.MaxForwardUtcDeviation +
            clockBounds.MaxAuthorizationDelay + TimeSpan.FromMinutes(5);
        var configuration = provisioner.StatusPendingPurgeIndependentConfiguration(scope, statusReader, resourceReader, selectedBackend);
        return new(origin, owner, observerIdentity, capability, scope, provisioner, statusReader, resourceReader,
            selectedBackend, statusLimits, resourceLimits, limits, time)
        {
            pendingIndependentProfile = new(), pendingConfiguration = configuration, pendingClockBounds = clockBounds,
            pendingResourceAuthority = resourceReader, pendingResourceLimits = resourceLimits,
            pendingStatusAuthority = statusReader, pendingStatusLimits = statusLimits
        };
    }
    internal static ManagementOperationFixtureObserverService ForStatusPendingPurgeIndependentCleanup(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, Limits limits, TimeProvider time)
    {
        Require(ReferenceEquals(time, TimeProvider.System));
        var configuration = provisioner.StatusPendingPurgeIndependentCleanupConfiguration(scope);
        return new(origin, owner, observerIdentity, capability, scope, provisioner, limits, time)
        { pendingIndependentProfile = new(), statusPendingPurgeCleanup = true, pendingConfiguration = configuration };
    }

    internal static ManagementOperationFixtureObserverService ForStatusPendingPurgeCancellation(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, S.Authority statusReader, R.Authority resourceReader,
        HttpPipelineTransport selectedBackend, S.Limits statusLimits, R.Limits resourceLimits, Limits limits,
        C.StatusPendingPurgeClockBounds clockBounds, TimeProvider time)
    {
        Require(ReferenceEquals(time, TimeProvider.System) && clockBounds is not null &&
            clockBounds.MaxForwardUtcDeviation >= TimeSpan.Zero && clockBounds.MaxAuthorizationDelay > TimeSpan.Zero &&
            typeof(Azure.Core.TokenCredential).Assembly.GetName().Version == new Version(1, 63, 0, 0) &&
            typeof(Azure.ResourceManager.ArmClient).Assembly.GetName().Version == new Version(1, 14, 0, 0) &&
            typeof(Azure.ResourceManager.KeyVault.KeyVaultResource).Assembly.GetName().Version == new Version(1, 4, 0, 0));
        _ = DateTimeOffset.UtcNow + limits.Timeout + clockBounds.MaxForwardUtcDeviation +
            clockBounds.MaxAuthorizationDelay + TimeSpan.FromMinutes(5);
        var configuration = provisioner.StatusPendingPurgeCancellationConfiguration(scope, statusReader, resourceReader, selectedBackend);
        return new(origin, owner, observerIdentity, capability, scope, provisioner, statusReader, resourceReader,
            selectedBackend, statusLimits, resourceLimits, limits, time)
        {
            pendingCancellationProfile = new(), pendingConfiguration = configuration, pendingClockBounds = clockBounds,
            pendingResourceAuthority = resourceReader, pendingResourceLimits = resourceLimits,
            pendingStatusAuthority = statusReader, pendingStatusLimits = statusLimits
        };
    }
    internal static ManagementOperationFixtureObserverService ForStatusPendingPurgeCancellationCleanup(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, Limits limits, TimeProvider time)
    {
        Require(ReferenceEquals(time, TimeProvider.System));
        var configuration = provisioner.StatusPendingPurgeCancellationCleanupConfiguration(scope);
        return new(origin, owner, observerIdentity, capability, scope, provisioner, limits, time)
        { pendingCancellationProfile = new(), statusPendingPurgeCleanup = true, pendingConfiguration = configuration };
    }

    private async Task<HttpResponseMessage> DispatchPendingPurge(string path, JsonElement body,
        CancellationToken token, CancellationToken caller)
    {
        if (path == "/operation/release")
            return await ReleasePendingPurge(body.Deserialize<FixtureSelector>(Json) ?? throw Failure(), token, caller).ConfigureAwait(false);
        Require(!statusPendingPurgeCleanup);
        if (path == "/operation/prepare")
        {
            var input = body.Deserialize<E.Prepare>(Json) ?? throw Failure();
            ValidateSelector(input.Selection);
            Require(input.Operation == ManagementMutation.PurgeDeletedVault && input.SubscriptionId == scope.SubscriptionId &&
                input.ResourceGroup == scope.ResourceGroup && pendingConfiguration is { } configuration &&
                VaultAdministrationEffects.SameConfiguration(configuration,
                    new(input.Location, input.TenantId, input.Sku, true, false, input.RetentionDays, true, [])));
            Session session;
            lock (gate)
            {
                Require(!disposed && sessions.Count < 32 && !sessions.ContainsKey(input.Selection.Nonce));
                session = new(input.Selection with { }) { Preparation = input, Pending = new(pendingIndependentProfile, pendingCancellationProfile), Active = 1 };
                session.Pending.Callers.Enqueue(caller);
                sessions.Add(input.Selection.Nonce, session);
            }
            try
            {
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
                session.Plan = provisioner.PlanFixture(owner, session.Selector, VaultFixtureProvisioner.Preparation.Deleted, [], seedCanary: false,
                    originalCallerToken: caller, preparationToken: linked.Token);
                var result = await provisioner.ProvisionAsync(session.Plan, cancellationToken: linked.Token,
                    originalCallerToken: caller).ConfigureAwait(false);
                Require(result.State == VaultFixtureProvisioner.State.Ready && result.VaultPresent == false && result.DeletedVaultPresent == true);
                linked.Token.ThrowIfCancellationRequested();
                CheckPendingClock(session);
                var snapshot = provisioner.Journal.Read(owner, session.Selector);
                Require(!snapshot.Closing && snapshot.Idle && !session.Closed);
                session.Lease = new(new(session.Selector.Nonce, session.Plan.LeaseId, observerIdentity,
                    S.ArmOrigin, "2026-02-01", time.GetUtcNow(), snapshot.Resources.Select(r => r.Id).ToArray()),
                    session.Plan.VaultName, null, null, null, ManagementMutation.PurgeDeletedVault, NativeProvisioningState.Pending);
                return Reply(session.Lease);
            }
            finally { LeaveSession(session); }
        }
        var request = body.Deserialize<ObserveLease>(Json) ?? throw Failure();
        Session selected;
        lock (gate)
        {
            selected = Find(request.Nonce, request.LeaseId);
            Require(selected.Pending is not null);
            token.ThrowIfCancellationRequested();
            selected.Pending.Callers.Enqueue(caller);
            CheckPendingClock(selected);
            selected.Active++;
        }
        try
        {
            if (path == "/operation/arm")
            {
                lock (gate)
                {
                    Require(!selected.ArmClaimed && request.Phase == "subscribe-before-trigger" && request.SubscriptionId is null);
                    selected.ArmClaimed = selected.Armed = true;
                    selected.Subscription = Guid.NewGuid();
                    selected.ArmedAt = time.GetUtcNow();
                    return Reply(new ObservationSubscription(selected.Plan!.LeaseId, selected.Selector.Nonce, selected.Subscription, selected.ArmedAt));
                }
            }
            Require(path == "/operation/observe");
            bool baseline = request.Phase == "baseline-before-dispatch";
            lock (gate)
            {
                Require(selected.Armed && request.SubscriptionId == selected.Subscription &&
                    (baseline ? !selected.BaselineClaimed && !selected.StartClaimed :
                        request.Phase == "selected-state" && selected.StartFinished && selected.StartSucceeded && !selected.AfterClaimed));
                if (baseline) selected.BaselineClaimed = true; else selected.AfterClaimed = true;
            }
            using var linked = selected.Pending.Clock is null
                ? CancellationTokenSource.CreateLinkedTokenSource(token, selected.Stop.Token)
                : CancellationTokenSource.CreateLinkedTokenSource(token, selected.Stop.Token, selected.Pending.Clock.Token);
            if (!baseline)
            {
                _ = PendingStartProof(selected);
                Require(capture.TryGetStatusTarget(selected.Capture!, selected.Binding!, out var target));
                using var boundary = new PendingStatusTransport(pendingStatusAuthority!.Transport, target!.TargetUri,
                    pendingStatusLimits!.MaximumResponseBytes);
                selected.Pending.StatusTransport = boundary;
                var independent = new S(capture, new(pendingStatusAuthority.Label, pendingStatusAuthority.Credential, boundary),
                    pendingStatusLimits, time);
                var window = independent.Arm(target, selected.Binding!);
                var task = independent.CollectAsync(window, selected.Binding!, linked.Token).AsTask();
                var measurement = await task.ConfigureAwait(false);
                Require(ReferenceEquals(measurement.Binding, selected.Binding) && measurement.WindowId == window.Id &&
                    measurement.HttpStatus == 200 && measurement.ResponseComplete && !measurement.Terminal &&
                    measurement.Status == SecretStatus.Pending && measurement.OperationState == NativeProvisioningState.Pending &&
                    measurement.ArmedAt == window.ArmedAt && measurement.ArmedAt >= selected.StartedAt &&
                    measurement.StartedAt >= measurement.ArmedAt && measurement.FinishedAt >= measurement.StartedAt &&
                    measurement.StartDispatch == target!.StartDispatch && measurement.TargetSha256 == target.TargetSha256 &&
                    measurement.StartResponseSha256 == target.StartResponseSha256 && Text(measurement.NativeRequestId, 256));
                selected.Pending.StatusRead = task;
                selected.Pending.StatusWindow = window;
                selected.Pending.StatusWitness = new(independent, window, task, target, selected.Binding!, boundary, caller);
                selected.Target = target;
            }
            Require(baseline || selected.Pending.StatusTransport is { Valid: true });
            var pair = await ReadPendingResources(selected, baseline, linked.Token).ConfigureAwait(false);
            CheckPendingClock(selected);
            Require(!selected.Closed && !linked.IsCancellationRequested);
            if (baseline)
            {
                selected.Pending.Baseline = pair;
                selected.BaselineReady = true;
                selected.BaselineAt = pair.FinishedAt;
            }
            else
            {
                selected.Pending.Selected = pair;
                selected.IndependentReady = true;
                selected.IndependentAt = pair.FinishedAt;
            }
            return Reply(Project(selected, pair.FinishedAt,
                baseline ? NativeProvisioningState.Unknown : NativeProvisioningState.Pending, SecretStatus.Success));
        }
        finally { LeaveSession(selected); }
    }

    private async Task<PendingPair> ReadPendingResources(Session session, bool baseline, CancellationToken token)
    {
        var activeBinding = new C.Binding(session.Selector, session.Plan!.LeaseId, provisioner.Scope(session.Plan),
            ManagementMutation.PurgeDeletedVault, scope.Location, "2026-02-01");
        var deletedBinding = new C.Binding(session.Selector, session.Plan.LeaseId,
            new DeletedVaultScope(new(scope.SubscriptionId), scope.Location, session.Plan.VaultName),
            ManagementMutation.PurgeDeletedVault, scope.Location, "2026-02-01");
        var a = new R(pendingResourceAuthority!, pendingResourceLimits!, time, scope.TenantId);
        var d = new R(pendingResourceAuthority!, pendingResourceLimits!, time, scope.TenantId);
        bool independent = IndependentPending(session);
        bool cancellation = CancellationPending(session);
        object ap = cancellation
            ? baseline ? R.StatusPendingPurgeCancellationReadPhase.BaselineActiveAbsent : R.StatusPendingPurgeCancellationReadPhase.SelectedActiveAbsent
            : independent
            ? baseline ? R.StatusPendingPurgeIndependentReadPhase.BaselineActiveAbsent : R.StatusPendingPurgeIndependentReadPhase.SelectedActiveAbsent
            : baseline ? R.StatusPendingPurgeReadPhase.BaselineActiveAbsent : R.StatusPendingPurgeReadPhase.SelectedActiveAbsent;
        object dp = cancellation
            ? baseline ? R.StatusPendingPurgeCancellationReadPhase.BaselineDeletedPresent : R.StatusPendingPurgeCancellationReadPhase.SelectedDeletedPresent
            : independent
            ? baseline ? R.StatusPendingPurgeIndependentReadPhase.BaselineDeletedPresent : R.StatusPendingPurgeIndependentReadPhase.SelectedDeletedPresent
            : baseline ? R.StatusPendingPurgeReadPhase.BaselineDeletedPresent : R.StatusPendingPurgeReadPhase.SelectedDeletedPresent;
        var aw = cancellation ? a.ArmStatusPendingPurgeCancellation(activeBinding, pendingConfiguration!, (R.StatusPendingPurgeCancellationReadPhase)ap)
            : independent ? a.ArmStatusPendingPurgeIndependent(activeBinding, pendingConfiguration!, (R.StatusPendingPurgeIndependentReadPhase)ap)
            : a.ArmStatusPendingPurge(activeBinding, pendingConfiguration!, (R.StatusPendingPurgeReadPhase)ap);
        var dw = cancellation ? d.ArmStatusPendingPurgeCancellation(deletedBinding, pendingConfiguration!, (R.StatusPendingPurgeCancellationReadPhase)dp)
            : independent ? d.ArmStatusPendingPurgeIndependent(deletedBinding, pendingConfiguration!, (R.StatusPendingPurgeIndependentReadPhase)dp)
            : d.ArmStatusPendingPurge(deletedBinding, pendingConfiguration!, (R.StatusPendingPurgeReadPhase)dp);
        var at = a.CollectAsync(aw, activeBinding, token).AsTask();
        using var av = await at.ConfigureAwait(false);
        CheckPendingClock(session);
        var dt = d.CollectAsync(dw, deletedBinding, token).AsTask();
        using var dv = await dt.ConfigureAwait(false);
        object aproof, dproof;
        if (cancellation)
        {
            Require(a.TryGetStatusPendingPurgeCancellationRead(aw, activeBinding, (R.StatusPendingPurgeCancellationReadPhase)ap, at, out var active));
            Require(d.TryGetStatusPendingPurgeCancellationRead(dw, deletedBinding, (R.StatusPendingPurgeCancellationReadPhase)dp, dt, out var deleted));
            Require(deleted!.OriginalVaultId == session.Plan.VaultId);
            aproof = active!; dproof = deleted;
        }
        else if (independent)
        {
            Require(a.TryGetStatusPendingPurgeIndependentRead(aw, activeBinding, (R.StatusPendingPurgeIndependentReadPhase)ap, at, out var active));
            Require(d.TryGetStatusPendingPurgeIndependentRead(dw, deletedBinding, (R.StatusPendingPurgeIndependentReadPhase)dp, dt, out var deleted));
            Require(deleted!.OriginalVaultId == session.Plan.VaultId);
            aproof = active!; dproof = deleted;
        }
        else
        {
            Require(a.TryGetStatusPendingPurgeRead(aw, activeBinding, (R.StatusPendingPurgeReadPhase)ap, at, out var active));
            Require(d.TryGetStatusPendingPurgeRead(dw, deletedBinding, (R.StatusPendingPurgeReadPhase)dp, dt, out var deleted));
            Require(deleted!.OriginalVaultId == session.Plan.VaultId);
            aproof = active!; dproof = deleted;
        }
        Require(av.StartedAt >= (baseline ? session.ArmedAt : session.Pending!.StatusRead!.Result.FinishedAt) &&
            dv.StartedAt >= av.FinishedAt);
        return new(new(a, activeBinding, aw, ap, at, aproof), new(d, deletedBinding, dw, dp, dt, dproof), dv.FinishedAt);
    }
    private static bool OwnsPendingPair(PendingPair pair) => Owns(pair.Active) && Owns(pair.Deleted);
    private static bool Owns(PendingRead read) => (read.Phase, read.Proof) switch
    {
        (R.StatusPendingPurgeIndependentReadPhase phase, R.StatusPendingPurgeIndependentReadProof proof) =>
            VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(read.Binding.Selector) &&
            read.Collector.OwnsStatusPendingPurgeIndependentRead(proof, read.Window, read.Binding, phase, read.Task),
        (R.StatusPendingPurgeCancellationReadPhase phase, R.StatusPendingPurgeCancellationReadProof proof) =>
            VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(read.Binding.Selector) &&
            read.Collector.OwnsStatusPendingPurgeCancellationRead(proof, read.Window, read.Binding, phase, read.Task),
        (R.StatusPendingPurgeReadPhase phase, R.StatusPendingPurgeReadProof proof) =>
            VaultFixtureProvisioner.StatusPendingPurgeSelector(read.Binding.Selector) &&
            read.Collector.OwnsStatusPendingPurgeRead(proof, read.Window, read.Binding, phase, read.Task),
        _ => false
    };

    private bool IndependentPending(Session session)
    {
        if (VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(session.Selector))
        {
            Require(CancellationPending(session));
            return false;
        }
        Require(session.Pending is not null && (pendingIndependentProfile is not null
            ? ReferenceEquals(session.Pending.Profile, pendingIndependentProfile) &&
                VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(session.Selector)
            : statusPendingPurgeProfile && session.Pending.Profile is null &&
                VaultFixtureProvisioner.StatusPendingPurgeSelector(session.Selector)));
        return pendingIndependentProfile is not null;
    }
    private bool CancellationPending(Session session)
    {
        if (!VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(session.Selector))
        {
            _ = IndependentPending(session);
            return false;
        }
        Require(session.Pending is not null && pendingCancellationProfile is not null &&
            ReferenceEquals(session.Pending.CancellationProfile, pendingCancellationProfile));
        return true;
    }
    private object PendingStartProof(Session session)
    {
        if (CancellationPending(session))
        {
            Require(capture.TryGetStatusPendingPurgeCancellationStart(session.Capture!, session.Binding!, session.Client!,
                session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, out var cancellation));
            return cancellation!;
        }
        if (IndependentPending(session))
        {
            Require(capture.TryGetStatusPendingPurgeIndependentStart(session.Capture!, session.Binding!, session.Client!,
                session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, out var proof));
            return proof!;
        }
        Require(capture.TryGetStatusPendingPurgeStart(session.Capture!, session.Binding!, session.Client!,
            session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, out var selected));
        return selected!;
    }
    private object PendingSelectedProof(Session session)
    {
        if (CancellationPending(session))
        {
            Require(capture.TryGetStatusPendingPurgeCancellationSelected(session.Capture!, session.Binding!, session.Client!,
                session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, session.Pending!.CanceledTask!, session.StatusTask!, out var cancellation));
            return cancellation!;
        }
        if (IndependentPending(session))
        {
            Require(capture.TryGetStatusPendingPurgeIndependentSelected(session.Capture!, session.Binding!, session.Client!,
                session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, session.StatusTask!, out var proof));
            return proof!;
        }
        Require(capture.TryGetStatusPendingPurgeSelected(session.Capture!, session.Binding!, session.Client!,
            session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, session.StatusTask!, out var selected));
        return selected!;
    }
    private object PendingCleanupProof(Session session)
    {
        if (CancellationPending(session))
        {
            Require(capture.TryGetStatusPendingPurgeCancellationCleanup(session.Capture!, session.Binding!, session.Client!,
                session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, session.Pending!.CanceledTask!, session.StatusTask!, session.Pending.CleanupTask!, out var cancellation));
            return cancellation!;
        }
        if (IndependentPending(session))
        {
            Require(capture.TryGetStatusPendingPurgeIndependentCleanup(session.Capture!, session.Binding!, session.Client!,
                session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, session.Pending!.CleanupTask!, out var proof));
            return proof!;
        }
        Require(capture.TryGetStatusPendingPurgeCleanup(session.Capture!, session.Binding!, session.Client!,
            session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, session.Pending!.CleanupTask!, out var selected));
        return selected!;
    }
    private object RegisterPending(PendingFacts facts)
    {
        bool independent = IndependentPending(facts.Session);
        object capability = CancellationPending(facts.Session) ? (facts.DrainOnly, facts.After.PurgeDeletedVault!.PendingStage) switch
        {
            (false, RoleFixtureJournal.StatusPendingPurgeStage.OriginalAdmitted) => new StatusPendingPurgeCancellationAdmission(this),
            (false, RoleFixtureJournal.StatusPendingPurgeStage.OriginalDrained) => new StatusPendingPurgeCancellationStartDrain(this),
            (false, RoleFixtureJournal.StatusPendingPurgeStage.SelectedAdmitted) => new StatusPendingPurgeCancellationReadAdmission(this),
            (false, RoleFixtureJournal.StatusPendingPurgeStage.PendingObserved) => new StatusPendingPurgeCancellationObservation(this),
            (false, RoleFixtureJournal.StatusPendingPurgeStage.CleanupAdmitted) => new StatusPendingPurgeCancellationCleanupAdmission(this),
            (false, RoleFixtureJournal.StatusPendingPurgeStage.CleanupTerminal) => new StatusPendingPurgeCancellationCleanupCompletion(this),
            (true, _) => new StatusPendingPurgeCancellationInvocationDrain(this),
            _ => throw Failure()
        } : (independent, facts.DrainOnly, facts.After.PurgeDeletedVault!.PendingStage) switch
        {
            (false, false, RoleFixtureJournal.StatusPendingPurgeStage.OriginalAdmitted) => new StatusPendingPurgeAdmission(this),
            (true, false, RoleFixtureJournal.StatusPendingPurgeStage.OriginalAdmitted) => new StatusPendingPurgeIndependentAdmission(this),
            (false, false, RoleFixtureJournal.StatusPendingPurgeStage.OriginalDrained) => new StatusPendingPurgeStartDrain(this),
            (true, false, RoleFixtureJournal.StatusPendingPurgeStage.OriginalDrained) => new StatusPendingPurgeIndependentStartDrain(this),
            (false, false, RoleFixtureJournal.StatusPendingPurgeStage.SelectedAdmitted) => new StatusPendingPurgeReadAdmission(this),
            (true, false, RoleFixtureJournal.StatusPendingPurgeStage.SelectedAdmitted) => new StatusPendingPurgeIndependentReadAdmission(this),
            (false, false, RoleFixtureJournal.StatusPendingPurgeStage.PendingObserved) => new StatusPendingPurgeObservation(this),
            (true, false, RoleFixtureJournal.StatusPendingPurgeStage.PendingObserved) => new StatusPendingPurgeIndependentObservation(this),
            (false, false, RoleFixtureJournal.StatusPendingPurgeStage.CleanupAdmitted) => new StatusPendingPurgeCleanupAdmission(this),
            (true, false, RoleFixtureJournal.StatusPendingPurgeStage.CleanupAdmitted) => new StatusPendingPurgeIndependentCleanupAdmission(this),
            (false, false, RoleFixtureJournal.StatusPendingPurgeStage.CleanupTerminal) => new StatusPendingPurgeCleanupCompletion(this),
            (true, false, RoleFixtureJournal.StatusPendingPurgeStage.CleanupTerminal) => new StatusPendingPurgeIndependentCleanupCompletion(this),
            (false, true, _) => new StatusPendingPurgeInvocationDrain(this),
            (true, true, _) => new StatusPendingPurgeIndependentInvocationDrain(this),
            _ => throw Failure()
        };
        Require(capability switch
        {
            StatusPendingPurgeAdmission value => pendingAdmissions.TryAdd(value, facts),
            StatusPendingPurgeIndependentAdmission value => pendingIndependentAdmissions.TryAdd(value, facts),
            StatusPendingPurgeCancellationAdmission value => pendingCancellationAdmissions.TryAdd(value, facts),
            StatusPendingPurgeStartDrain value => pendingStartDrains.TryAdd(value, facts),
            StatusPendingPurgeIndependentStartDrain value => pendingIndependentStartDrains.TryAdd(value, facts),
            StatusPendingPurgeCancellationStartDrain value => pendingCancellationStartDrains.TryAdd(value, facts),
            StatusPendingPurgeReadAdmission value => pendingReadAdmissions.TryAdd(value, facts),
            StatusPendingPurgeIndependentReadAdmission value => pendingIndependentReadAdmissions.TryAdd(value, facts),
            StatusPendingPurgeCancellationReadAdmission value => pendingCancellationReadAdmissions.TryAdd(value, facts),
            StatusPendingPurgeObservation value => pendingObservations.TryAdd(value, facts),
            StatusPendingPurgeIndependentObservation value => pendingIndependentObservations.TryAdd(value, facts),
            StatusPendingPurgeCancellationObservation value => pendingCancellationObservations.TryAdd(value, facts),
            StatusPendingPurgeCleanupAdmission value => pendingCleanupAdmissions.TryAdd(value, facts),
            StatusPendingPurgeIndependentCleanupAdmission value => pendingIndependentCleanupAdmissions.TryAdd(value, facts),
            StatusPendingPurgeCancellationCleanupAdmission value => pendingCancellationCleanupAdmissions.TryAdd(value, facts),
            StatusPendingPurgeCleanupCompletion value => pendingCleanupCompletions.TryAdd(value, facts),
            StatusPendingPurgeIndependentCleanupCompletion value => pendingIndependentCleanupCompletions.TryAdd(value, facts),
            StatusPendingPurgeCancellationCleanupCompletion value => pendingCancellationCleanupCompletions.TryAdd(value, facts),
            StatusPendingPurgeInvocationDrain value => pendingInvocationDrains.TryAdd(value, facts),
            StatusPendingPurgeIndependentInvocationDrain value => pendingIndependentInvocationDrains.TryAdd(value, facts),
            StatusPendingPurgeCancellationInvocationDrain value => pendingCancellationInvocationDrains.TryAdd(value, facts),
            _ => false
        });
        return capability;
    }

    private RoleFixtureJournal.Snapshot PendingImage(RoleFixtureJournal.Snapshot before,
        RoleFixtureJournal.StatusPendingPurgeStage stage, bool terminated, Guid dispatch, bool terminal = false) => before with
    {
        Revision = before.Revision + 1,
        Resources = before.Resources.Select((r, i) => i == 2 ? r with
        {
            SelectedAttempted = true, InvocationTerminated = terminated, ActiveDispatch = terminal ? Guid.Empty : dispatch
        } : r).ToArray(),
        PurgeDeletedVault = before.PurgeDeletedVault! with
        {
            PendingStage = stage, InvocationDispatch = dispatch,
            SettledDispatch = terminal ? dispatch : Guid.Empty,
            Disposition = terminal ? RoleFixtureJournal.PurgeDeletedVaultDisposition.Purged : RoleFixtureJournal.PurgeDeletedVaultDisposition.None
        }
    };
    private PendingFacts PendingFact(Session session, RoleFixtureJournal.Snapshot before,
        RoleFixtureJournal.StatusPendingPurgeStage stage, bool terminated, CancellationToken token,
        Task[] tasks, object[] proofs, bool cleanup = false, bool terminal = false, bool drain = false) =>
        new(session, RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(before),
            PendingImage(before, stage, terminated, session.Dispatch, terminal), [token], tasks, proofs, cleanup, drain);

    private async ValueTask<SecretOutcome<ManagementOperation>> StartPendingPurge(FixtureSelector selector,
        VaultAdministration client, ManagementScope originalScope, ManagementMutation operation, E.Input input,
        ManagementReceipt receipt, CancellationToken caller)
    {
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(!statusPendingPurgeCleanup && operation == ManagementMutation.PurgeDeletedVault &&
                input.StatusOperation == operation && InputMatches(session, input) && session.Pending?.Baseline is { } baseline &&
                OwnsPendingPair(baseline) && session.BaselineReady && !session.StartClaimed &&
                originalScope is DeletedVaultScope deleted && deleted.Subscription.SubscriptionId == scope.SubscriptionId &&
                deleted.Location == scope.Location && deleted.VaultName == session.Plan!.VaultName);
            session.StartClaimed = true;
            session.Pending.Callers.Enqueue(caller);
            session.Client = client; session.ActualDeletedVaultScope = (DeletedVaultScope)originalScope; session.Receipt = receipt;
            session.Binding = new(selector, session.Plan!.LeaseId, originalScope, operation, scope.Location, "2026-02-01");
            session.Capture = capture.Arm(session.Binding);
            session.Pending.StartedUtc = DateTimeOffset.UtcNow;
            session.Pending.StartedTimestamp = TimeProvider.System.GetTimestamp();
            session.Pending.ExpiresAt = input.Arm.Administrative.ExpiresAt;
            session.Pending.OriginalCaller = caller;
            session.Pending.Clock = CancellationPending(session)
                ? capture.EnrollStatusPendingPurgeCancellation(session.Capture, session.Binding, client,
                    session.ActualDeletedVaultScope, receipt, session.Pending.ExpiresAt, pendingClockBounds!, limits.Timeout, caller)
                : IndependentPending(session)
                ? capture.EnrollStatusPendingPurgeIndependent(session.Capture, session.Binding, client,
                    session.ActualDeletedVaultScope, receipt, session.Pending.ExpiresAt, pendingClockBounds!, limits.Timeout, caller)
                : capture.EnrollStatusPendingPurge(session.Capture, session.Binding, client,
                    session.ActualDeletedVaultScope, receipt, session.Pending.ExpiresAt, pendingClockBounds!, limits.Timeout, caller);
            session.Active++; active++;
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(caller, lifetime.Token,
                session.Stop.Token, session.Pending.Clock.Token);
            CheckPendingClock(session);
            var before = provisioner.Journal.Read(owner, selector);
            session.Dispatch = Guid.NewGuid();
            var pair = session.Pending.Baseline!;
            var candidate = RegisterPending(PendingFact(session, before,
                RoleFixtureJournal.StatusPendingPurgeStage.OriginalAdmitted, false, linked.Token,
                [pair.Active.Task, pair.Deleted.Task], [pair.Active.Proof, pair.Deleted.Proof]));
            if (CancellationPending(session)) provisioner.BindStatusPendingPurgeCancellationLifetime(session.Plan!, () => CheckPendingClock(session));
            else if (IndependentPending(session)) provisioner.BindStatusPendingPurgeIndependentLifetime(session.Plan!, () => CheckPendingClock(session));
            else provisioner.BindStatusPendingPurgeLifetime(session.Plan!, () => CheckPendingClock(session));
            session.Pending.Persistence = candidate;
            var admitted = RetryPendingPersistence(session);
            CheckPendingClock(session);
            session.StartedAt = time.GetUtcNow();
            var result = await (CancellationPending(session)
                ? capture.StartStatusPendingPurgeCancellationAsync(session.Capture!, selector, client, originalScope,
                    input, receipt, linked.Token, task => session.StartTask = task)
                : IndependentPending(session)
                ? capture.StartStatusPendingPurgeIndependentAsync(session.Capture!, selector, client, originalScope,
                    input, receipt, linked.Token, task => session.StartTask = task)
                : capture.StartStatusPendingPurgeAsync(session.Capture!, selector, client, originalScope,
                    input, receipt, linked.Token, task => session.StartTask = task)).ConfigureAwait(false);
            session.Handle = result.IsSuccess ? result.Value : null;
            Require(result.IsSuccess);
            var proof = PendingStartProof(session);
            CheckPendingClock(session);
            before = admitted;
            var drain = RegisterPending(PendingFact(session, before,
                RoleFixtureJournal.StatusPendingPurgeStage.OriginalDrained, true, linked.Token, [session.StartTask!], [proof]));
            session.Pending.Persistence = drain;
            RetryPendingPersistence(session);
            session.StartSucceeded = true;
            return result;
        }
        finally
        {
            try { DrainPendingInvocation(session); }
            finally { session.StartFinished = true; Leave(session); }
        }
    }

    private async ValueTask<SecretStatus> CheckPendingPurge(FixtureSelector selector, ManagementOperation handle, CancellationToken caller)
    {
        Session session;
        bool cancellation, canceledCall;
        lock (gate)
        {
            session = OpenSelector(selector);
            // Foreign references never claim either member of the C pair.
            Require(ReferenceEquals(handle, session.Handle) && session.StartFinished && session.StartSucceeded &&
                session.IndependentReady && session.Pending?.Selected is { } pair && OwnsPendingPair(pair));
            cancellation = CancellationPending(session);
            var p = session.Pending;
            canceledCall = cancellation && !p.CanceledClaimed;
            if (cancellation)
            {
                bool valid = !p.Invalid && session.Active == 0 && !session.StatusClaimed &&
                    (canceledCall ? caller.IsCancellationRequested : p.CanceledDrained && p.CanceledProof is not null &&
                        p.SelectedAdmission is not null && caller == p.OriginalCaller && !caller.IsCancellationRequested);
                if (!valid)
                {
                    p.Invalid = true;
                    capture.RevokeStatusPendingPurgeCancellationSelected(session.Capture!);
                    throw Failure();
                }
                if (canceledCall)
                {
                    p.CanceledClaimed = true;
                    p.CanceledOperand = caller;
                }
                else
                {
                    p.Callers.Enqueue(caller);
                }
            }
            else
            {
                Require(!session.StatusClaimed);
                session.StatusClaimed = true;
                p.Callers.Enqueue(caller);
            }
            session.Active++; active++;
        }
        bool preservePair = false;
        try
        {
            var p = session.Pending!;
            // The deliberately canceled operand is not a positive lifetime token.
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(canceledCall ? p.OriginalCaller : caller,
                lifetime.Token, session.Stop.Token, p.Clock!.Token);
            CheckPendingClock(session);
            var start = PendingStartProof(session);
            var before = provisioner.Journal.Read(owner, selector);
            var pair = p.Selected!;
            RoleFixtureJournal.Snapshot admitted;
            if (cancellation && !canceledCall)
            {
                Require(p.SelectedAdmission is not null && RoleFixtureJournal.SameStatusPendingPurgeSnapshot(p.SelectedAdmission, before) &&
                    p.CanceledDrained && p.CanceledOperand.IsCancellationRequested && p.CanceledTask is { IsCanceled: true } &&
                    p.CanceledProof is not null && capture.OwnsStatusPendingPurgeCancellationCanceled(p.CanceledProof,
                        session.Capture!, session.Binding!, session.Client!, session.ActualDeletedVaultScope!, session.Receipt!,
                        session.StartTask!, handle, p.CanceledTask));
                admitted = p.SelectedAdmission;
                lock (gate)
                {
                    Require(!session.Closed && !p.Invalid && !session.StatusClaimed);
                    session.StatusClaimed = true;
                }
            }
            else
            {
                var admission = RegisterPending(PendingFact(session, before,
                    RoleFixtureJournal.StatusPendingPurgeStage.SelectedAdmitted, false, linked.Token,
                    [session.StartTask!, p.StatusRead!, pair.Active.Task, pair.Deleted.Task],
                    [start, pair.Active.Proof, pair.Deleted.Proof, p.StatusWitness!]));
                p.Persistence = admission;
                admitted = RetryPendingPersistence(session);
                if (canceledCall) p.SelectedAdmission = RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(admitted);
            }
            if (canceledCall)
            {
                try
                {
                    await capture.CheckStatusPendingPurgeCancellationCanceledAsync(session.Capture!, selector, handle,
                        caller, task => p.CanceledTask = task).ConfigureAwait(false);
                    throw Failure();
                }
                catch (OperationCanceledException)
                {
                    Require(p.CanceledTask is { IsCanceled: true } && p.CanceledOperand.IsCancellationRequested);
                    Require(capture.TryGetStatusPendingPurgeCancellationCanceled(session.Capture!, session.Binding!, session.Client!,
                        session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, handle, p.CanceledTask, out var canceled));
                    CheckPendingClock(session);
                    Require(!session.Closed && !linked.IsCancellationRequested);
                    p.CanceledProof = canceled;
                    // C owns the physical task, hook and finalizer drain behind CX.
                    p.CanceledDrained = true;
                    preservePair = true;
                    throw;
                }
            }
            var result = await (cancellation
                ? capture.CheckStatusPendingPurgeCancellationAsync(session.Capture!, selector, handle, linked.Token, task => session.StatusTask = task)
                : IndependentPending(session)
                ? capture.CheckStatusPendingPurgeIndependentAsync(session.Capture!, selector, handle, linked.Token, task => session.StatusTask = task)
                : capture.CheckStatusPendingPurgeAsync(session.Capture!, selector, handle, linked.Token, task => session.StatusTask = task)).ConfigureAwait(false);
            Require(result == SecretStatus.Pending);
            var proof = PendingSelectedProof(session);
            CheckPendingClock(session);
            var observation = RegisterPending(PendingFact(session, admitted,
                RoleFixtureJournal.StatusPendingPurgeStage.PendingObserved, true, linked.Token,
                cancellation
                    ? [session.StartTask!, p.CanceledTask!, session.StatusTask!, p.StatusRead!, pair.Active.Task, pair.Deleted.Task]
                    : IndependentPending(session)
                    ? [session.StartTask!, session.StatusTask!, p.StatusRead!, pair.Active.Task, pair.Deleted.Task]
                    : [session.StartTask!, session.StatusTask!],
                cancellation
                    ? [start, p.CanceledProof!, proof, pair.Active.Proof, pair.Deleted.Proof, p.StatusWitness!]
                    : IndependentPending(session)
                    ? [start, proof, pair.Active.Proof, pair.Deleted.Proof, p.StatusWitness!]
                    : [proof]));
            p.Persistence = observation;
            RetryPendingPersistence(session);
            session.StatusSucceeded = true;
            return result;
        }
        catch (IOException) when (session.Pending!.Persistence is not null) { throw; }
        catch
        {
            if (cancellation && !preservePair)
            {
                session.Pending!.Invalid = true;
                capture.RevokeStatusPendingPurgeCancellationSelected(session.Capture!);
            }
            throw;
        }
        finally
        {
            try { if (!preservePair) DrainPendingInvocation(session); }
            finally { Leave(session); }
        }
    }

    internal RoleFixtureJournal.Snapshot RetryStatusPendingPurgePersistence(FixtureSelector selector)
    {
        Require(statusPendingPurgeProfile && VaultFixtureProvisioner.StatusPendingPurgeSelector(selector));
        return RetryPendingSelector(selector);
    }
    internal RoleFixtureJournal.Snapshot RetryStatusPendingPurgeIndependentPersistence(FixtureSelector selector)
    {
        Require(pendingIndependentProfile is not null && VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(selector));
        return RetryPendingSelector(selector);
    }
    internal RoleFixtureJournal.Snapshot RetryStatusPendingPurgeCancellationPersistence(FixtureSelector selector)
    {
        Require(pendingCancellationProfile is not null && VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(selector));
        return RetryPendingSelector(selector);
    }
    private RoleFixtureJournal.Snapshot RetryPendingSelector(FixtureSelector selector)
    {
        Session session;
        lock (gate)
        {
            Require(PendingProfile);
            Require(sessions.TryGetValue(selector.Nonce, out session!));
            Require(
                session.Selector == selector && session.Active == 0 && !session.Releasing && session.Pending is not null);
            session.Active++; active++;
        }
        try
        {
            if (session.Plan is null)
            {
                CheckPendingClock(session);
                return CancellationPending(session) ? provisioner.RetryStatusPendingPurgeCancellationPreparation(owner, selector) :
                    IndependentPending(session) ? provisioner.RetryStatusPendingPurgeIndependentPreparation(owner, selector) :
                    provisioner.RetryStatusPendingPurgePreparation(owner, selector);
            }
            bool fixturePersistence = CancellationPending(session)
                ? provisioner.HasStatusPendingPurgeCancellationPersistence(session.Plan)
                : IndependentPending(session)
                ? provisioner.HasStatusPendingPurgeIndependentPersistence(session.Plan)
                : provisioner.HasStatusPendingPurgePersistence(session.Plan);
            if (fixturePersistence)
            {
                CheckPendingClock(session);
                var fixture = CancellationPending(session) ? provisioner.RetryStatusPendingPurgeCancellationPersistence(session.Plan) :
                    IndependentPending(session) ? provisioner.RetryStatusPendingPurgeIndependentPersistence(session.Plan) :
                    provisioner.RetryStatusPendingPurgePersistence(session.Plan);
                CheckPendingClock(session);
                session.Pending!.LastPersistence = null;
                return fixture;
            }
            session.Pending!.Persistence ??= session.Pending.LastPersistence;
            return RetryPendingPersistence(session);
        }
        finally { Leave(session); }
    }
    private RoleFixtureJournal.Snapshot RetryPendingPersistence(Session session)
    {
        try { return PersistPendingImage(session); }
        catch (Exception exception) when (exception is InvalidOperationException or OperationCanceledException)
        {
            session.Pending!.Invalid = true;
            session.Pending.Persistence = null;
            throw;
        }
    }
    private RoleFixtureJournal.Snapshot PersistPendingImage(Session session)
    {
        CheckPendingClock(session);
        var p = session.Pending!;
        PendingFacts? facts = p.Persistence switch
        {
            StatusPendingPurgeIndependentAdmission value => pendingIndependentAdmissions.GetValueOrDefault(value),
            StatusPendingPurgeCancellationAdmission value => pendingCancellationAdmissions.GetValueOrDefault(value),
            StatusPendingPurgeIndependentStartDrain value => pendingIndependentStartDrains.GetValueOrDefault(value),
            StatusPendingPurgeCancellationStartDrain value => pendingCancellationStartDrains.GetValueOrDefault(value),
            StatusPendingPurgeIndependentReadAdmission value => pendingIndependentReadAdmissions.GetValueOrDefault(value),
            StatusPendingPurgeCancellationReadAdmission value => pendingCancellationReadAdmissions.GetValueOrDefault(value),
            StatusPendingPurgeIndependentObservation value => pendingIndependentObservations.GetValueOrDefault(value),
            StatusPendingPurgeCancellationObservation value => pendingCancellationObservations.GetValueOrDefault(value),
            StatusPendingPurgeIndependentCleanupAdmission value => pendingIndependentCleanupAdmissions.GetValueOrDefault(value),
            StatusPendingPurgeCancellationCleanupAdmission value => pendingCancellationCleanupAdmissions.GetValueOrDefault(value),
            StatusPendingPurgeIndependentCleanupCompletion value => pendingIndependentCleanupCompletions.GetValueOrDefault(value),
            StatusPendingPurgeCancellationCleanupCompletion value => pendingCancellationCleanupCompletions.GetValueOrDefault(value),
            StatusPendingPurgeIndependentInvocationDrain value => pendingIndependentInvocationDrains.GetValueOrDefault(value),
            StatusPendingPurgeCancellationInvocationDrain value => pendingCancellationInvocationDrains.GetValueOrDefault(value),
            StatusPendingPurgeAdmission value => pendingAdmissions.GetValueOrDefault(value),
            StatusPendingPurgeStartDrain value => pendingStartDrains.GetValueOrDefault(value),
            StatusPendingPurgeReadAdmission value => pendingReadAdmissions.GetValueOrDefault(value),
            StatusPendingPurgeObservation value => pendingObservations.GetValueOrDefault(value),
            StatusPendingPurgeCleanupAdmission value => pendingCleanupAdmissions.GetValueOrDefault(value),
            StatusPendingPurgeCleanupCompletion value => pendingCleanupCompletions.GetValueOrDefault(value),
            StatusPendingPurgeInvocationDrain value => pendingInvocationDrains.GetValueOrDefault(value),
            _ => null
        };
        if (facts is not null && !facts.DrainOnly)
        {
            bool owned = facts.Proofs.All(proof => proof switch
            {
                C.StatusPendingPurgeIndependentStartProof start => IndependentPending(session) && capture.OwnsStatusPendingPurgeIndependentStart(start, session.Capture!,
                    session.Binding!, session.Client!, session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!),
                C.StatusPendingPurgeIndependentSelectedProof selected => IndependentPending(session) && capture.OwnsStatusPendingPurgeIndependentSelected(selected, session.Capture!,
                    session.Binding!, session.Client!, session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, session.StatusTask!),
                C.StatusPendingPurgeIndependentCleanupProof cleanup => IndependentPending(session) && capture.OwnsStatusPendingPurgeIndependentCleanup(cleanup, session.Capture!,
                    session.Binding!, session.Client!, session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, p.CleanupTask!),
                R.StatusPendingPurgeIndependentReadProof resource => IndependentPending(session) && new[] { p.Baseline, p.Selected }.Any(pair => pair is not null &&
                    (ReferenceEquals(pair.Active.Proof, resource) || ReferenceEquals(pair.Deleted.Proof, resource)) && OwnsPendingPair(pair)),
                C.StatusPendingPurgeCancellationStartProof start => CancellationPending(session) && capture.OwnsStatusPendingPurgeCancellationStart(start, session.Capture!,
                    session.Binding!, session.Client!, session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!),
                C.StatusPendingPurgeCancellationSelectedProof selected => CancellationPending(session) && capture.OwnsStatusPendingPurgeCancellationSelected(selected, session.Capture!,
                    session.Binding!, session.Client!, session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, p.CanceledTask!, session.StatusTask!),
                C.StatusPendingPurgeCancellationCleanupProof cleanup => CancellationPending(session) && capture.OwnsStatusPendingPurgeCancellationCleanup(cleanup, session.Capture!,
                    session.Binding!, session.Client!, session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, p.CanceledTask!, session.StatusTask!, p.CleanupTask!),
                R.StatusPendingPurgeCancellationReadProof resource => CancellationPending(session) && new[] { p.Baseline, p.Selected }.Any(pair => pair is not null &&
                    (ReferenceEquals(pair.Active.Proof, resource) || ReferenceEquals(pair.Deleted.Proof, resource)) && OwnsPendingPair(pair)),
                C.StatusPendingPurgeCancellationCanceledProof canceled => CancellationPending(session) &&
                    ReferenceEquals(canceled, p.CanceledProof) && p.CanceledDrained && p.CanceledOperand.IsCancellationRequested &&
                    p.CanceledTask is { IsCanceled: true } && capture.OwnsStatusPendingPurgeCancellationCanceled(canceled, session.Capture!,
                        session.Binding!, session.Client!, session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, p.CanceledTask),
                C.StatusPendingPurgeStartProof start => !CancellationPending(session) && !IndependentPending(session) && capture.OwnsStatusPendingPurgeStart(start, session.Capture!,
                    session.Binding!, session.Client!, session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!),
                C.StatusPendingPurgeSelectedProof selected => !CancellationPending(session) && !IndependentPending(session) && capture.OwnsStatusPendingPurgeSelected(selected, session.Capture!,
                    session.Binding!, session.Client!, session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, session.StatusTask!),
                C.StatusPendingPurgeCleanupProof cleanup => !CancellationPending(session) && !IndependentPending(session) && capture.OwnsStatusPendingPurgeCleanup(cleanup, session.Capture!,
                    session.Binding!, session.Client!, session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, p.CleanupTask!),
                R.StatusPendingPurgeReadProof resource => !CancellationPending(session) && !IndependentPending(session) && new[] { p.Baseline, p.Selected }.Any(pair => pair is not null &&
                    (ReferenceEquals(pair.Active.Proof, resource) || ReferenceEquals(pair.Deleted.Proof, resource)) && OwnsPendingPair(pair)),
                PendingStatusWitness status => ReferenceEquals(status, p.StatusWitness) &&
                    ReferenceEquals(status.Task, p.StatusRead) && ReferenceEquals(status.Window, p.StatusWindow) &&
                    ReferenceEquals(status.Target, session.Target) && ReferenceEquals(status.Binding, session.Binding) &&
                    ReferenceEquals(status.Window.Target, status.Target) && ReferenceEquals(status.Window.Binding, status.Binding) &&
                    ReferenceEquals(status.Transport, p.StatusTransport) && status.Transport.Valid && !status.Token.IsCancellationRequested &&
                    status.Task is { IsCompletedSuccessfully: true } && status.Task.Result is
                        { HttpStatus: 200, ResponseComplete: true, Terminal: false, Status: SecretStatus.Pending,
                            OperationState: NativeProvisioningState.Pending } measurement &&
                    ReferenceEquals(measurement.Binding, status.Binding) && measurement.WindowId == status.Window.Id &&
                    measurement.StartDispatch == status.Target.StartDispatch && measurement.TargetSha256 == status.Target.TargetSha256 &&
                    measurement.StartResponseSha256 == status.Target.StartResponseSha256,
                _ => false
            });
            if (!owned) { facts.Invalid = true; p.Invalid = true; }
            Require(owned);
        }
        var j = provisioner.Journal;
        var selector = session.Selector;
        var lease = session.Plan!.LeaseId;
        var result = p.Persistence switch
        {
            StatusPendingPurgeIndependentAdmission value => j.BeginStatusPendingPurgeIndependentInvocation(owner, selector, lease, value),
            StatusPendingPurgeCancellationAdmission value => j.BeginStatusPendingPurgeCancellationInvocation(owner, selector, lease, value),
            StatusPendingPurgeIndependentStartDrain value => j.EndStatusPendingPurgeIndependentStart(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeCancellationStartDrain value => j.EndStatusPendingPurgeCancellationStart(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeIndependentReadAdmission value => j.AdmitStatusPendingPurgeIndependentRead(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeCancellationReadAdmission value => j.AdmitStatusPendingPurgeCancellationRead(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeIndependentObservation value => j.CompleteStatusPendingPurgeIndependentRead(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeCancellationObservation value => j.CompleteStatusPendingPurgeCancellationRead(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeIndependentCleanupAdmission value => j.AdmitStatusPendingPurgeIndependentCleanupRead(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeCancellationCleanupAdmission value => j.AdmitStatusPendingPurgeCancellationCleanupRead(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeIndependentCleanupCompletion value => j.CompleteStatusPendingPurgeIndependentCleanupRead(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeCancellationCleanupCompletion value => j.CompleteStatusPendingPurgeCancellationCleanupRead(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeIndependentInvocationDrain value => j.EndStatusPendingPurgeIndependentInvocation(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeCancellationInvocationDrain value => j.EndStatusPendingPurgeCancellationInvocation(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeAdmission value => j.BeginStatusPendingPurgeInvocation(owner, selector, lease, value),
            StatusPendingPurgeStartDrain value => j.EndStatusPendingPurgeStart(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeReadAdmission value => j.AdmitStatusPendingPurgeRead(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeObservation value => j.CompleteStatusPendingPurgeRead(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeCleanupAdmission value => j.AdmitStatusPendingPurgeCleanupRead(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeCleanupCompletion value => j.CompleteStatusPendingPurgeCleanupRead(owner, selector, lease, session.Dispatch, value),
            StatusPendingPurgeInvocationDrain value => j.EndStatusPendingPurgeInvocation(owner, selector, lease, session.Dispatch, value),
            null => CancellationPending(session) ? provisioner.RetryStatusPendingPurgeCancellationPersistence(session.Plan) :
                IndependentPending(session) ? provisioner.RetryStatusPendingPurgeIndependentPersistence(session.Plan) :
                provisioner.RetryStatusPendingPurgePersistence(session.Plan),
            _ => throw Failure()
        };
        CheckPendingClock(session);
        // A real Flush of the exact retained positive image restores only its
        // local completion flag; it never replays the native operation.
        if (p.Persistence is StatusPendingPurgeStartDrain or StatusPendingPurgeIndependentStartDrain or StatusPendingPurgeCancellationStartDrain)
            session.StartSucceeded = true;
        if (p.Persistence is StatusPendingPurgeObservation or StatusPendingPurgeIndependentObservation or StatusPendingPurgeCancellationObservation)
            session.StatusSucceeded = true;
        p.LastPersistence = p.Persistence;
        p.Persistence = null;
        return result;
    }
    private void DrainPendingInvocation(Session session)
    {
        var p = session.Pending!;
        // Preserve a retained positive image across transient persistence failure.
        if (p.Persistence is not null || session.Dispatch == Guid.Empty) return;
        Task? task = p.CleanupClaimed ? p.CleanupTask : session.StatusClaimed ? session.StatusTask :
            p.CanceledClaimed ? p.CanceledTask : session.StartTask;
        if (CancellationPending(session))
            task ??= p.CanceledTask ?? session.StartTask;
        if (task is not { IsCompleted: true }) return;
        var before = provisioner.Journal.Read(owner, session.Selector);
        if (before.Resources[2].InvocationTerminated || before.PurgeDeletedVault!.PendingStage is not
            (RoleFixtureJournal.StatusPendingPurgeStage.OriginalAdmitted or RoleFixtureJournal.StatusPendingPurgeStage.SelectedAdmitted or
                RoleFixtureJournal.StatusPendingPurgeStage.CleanupAdmitted)) return;
        var drain = RegisterPending(PendingFact(session, before, before.PurgeDeletedVault.PendingStage,
            true, default, [task], [], cleanup: session.Closed, drain: true));
        p.Persistence = drain;
        if (drain is StatusPendingPurgeCancellationInvocationDrain cancellation)
            provisioner.Journal.EndStatusPendingPurgeCancellationInvocation(owner, session.Selector, session.Plan!.LeaseId, session.Dispatch, cancellation);
        else if (drain is StatusPendingPurgeIndependentInvocationDrain independent)
            provisioner.Journal.EndStatusPendingPurgeIndependentInvocation(owner, session.Selector, session.Plan!.LeaseId, session.Dispatch, independent);
        else provisioner.Journal.EndStatusPendingPurgeInvocation(owner, session.Selector, session.Plan!.LeaseId, session.Dispatch,
            (StatusPendingPurgeInvocationDrain)drain);
        p.Persistence = null;
    }

    private async Task<HttpResponseMessage> ReleasePendingPurge(FixtureSelector selector, CancellationToken token, CancellationToken caller)
    {
        ValidateSelector(selector);
        Session session;
        lock (gate)
        {
            if (!sessions.TryGetValue(selector.Nonce, out session!))
            {
                Require(!disposed && sessions.Count < 32);
                session = new(selector with { }) { Pending = new(pendingIndependentProfile, pendingCancellationProfile) };
                sessions.Add(selector.Nonce, session);
            }
            Require(session.Selector == selector);
            if (session.Releasing) return Reply(ReleaseMeasurement(session, provisioner.Journal.Read(owner, selector), 1));
            session.Releasing = true;
        }
        try
        {
            var snapshot = provisioner.CloseSelectedRoot(owner, selector);
            session.Closed = true;
            var p = session.Pending!;
            p.NeverSelectedClosed = snapshot.PurgeDeletedVault is
                { PendingStage: RoleFixtureJournal.StatusPendingPurgeStage.Prepared, InvocationDispatch: var original } &&
                original == Guid.Empty;
            p.SelectedRevoked = true;
            if (session.Capture is not null && p.Clock is not null)
            {
                if (CancellationPending(session)) capture.RevokeStatusPendingPurgeCancellationSelected(session.Capture);
                else if (IndependentPending(session)) capture.RevokeStatusPendingPurgeIndependentSelected(session.Capture);
                else capture.RevokeStatusPendingPurgeSelected(session.Capture);
            }
            session.Stop.Cancel();
            p.Callers.Enqueue(caller);
            lock (gate) if (session.Active == 0) session.PrivateDrained.TrySetResult();
            await session.PrivateDrained.Task.ConfigureAwait(false);
            snapshot = provisioner.Journal.Read(owner, selector);
            if (snapshot.Resources.Length == 0) return Reply(ReleaseMeasurement(session, snapshot));
            session.Plan ??= provisioner.OpenCleanupPlan(owner, selector);
            if (CancellationPending(session) && session.Dispatch != Guid.Empty)
            {
                // Close abandons an incomplete pair. It is not a cancellation
                // witness, nor may a retained selected candidate cross Close.
                if (p.Persistence is not null and not StatusPendingPurgeCancellationCleanupAdmission and
                    not StatusPendingPurgeCancellationCleanupCompletion and not StatusPendingPurgeCancellationInvocationDrain ||
                    snapshot.PurgeDeletedVault!.PendingStage is RoleFixtureJournal.StatusPendingPurgeStage.OriginalAdmitted or
                        RoleFixtureJournal.StatusPendingPurgeStage.OriginalDrained or RoleFixtureJournal.StatusPendingPurgeStage.SelectedAdmitted)
                {
                    p.Invalid = true;
                    p.Persistence = null;
                    DrainPendingInvocation(session);
                    snapshot = provisioner.Journal.Read(owner, selector);
                }
            }
            if (snapshot.PurgeDeletedVault!.PendingStage == RoleFixtureJournal.StatusPendingPurgeStage.PendingObserved &&
                !statusPendingPurgeCleanup && session.StatusSucceeded && !p.CleanupClaimed && p.Persistence is null &&
                session.Capture is not null && p.Clock is not null)
            {
                p.CleanupClaimed = true;
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, lifetime.Token, p.Clock.Token);
                try
                {
                    CheckPendingClock(session);
                    var selected = PendingSelectedProof(session);
                    var admission = RegisterPending(PendingFact(session, snapshot,
                        RoleFixtureJournal.StatusPendingPurgeStage.CleanupAdmitted, false, linked.Token,
                        CancellationPending(session) ? [session.StartTask!, p.CanceledTask!, session.StatusTask!] :
                            [session.StartTask!, session.StatusTask!],
                        CancellationPending(session) ? [p.CanceledProof!, selected] : [selected], cleanup: true));
                    p.Persistence = admission;
                    var admitted = RetryPendingPersistence(session);
                    var result = await (CancellationPending(session)
                        ? capture.CheckStatusPendingPurgeCancellationCleanupAsync(session.Capture, selector, session.Handle!, linked.Token,
                            task => p.CleanupTask = task)
                        : IndependentPending(session)
                        ? capture.CheckStatusPendingPurgeIndependentCleanupAsync(session.Capture, selector, session.Handle!, linked.Token,
                            task => p.CleanupTask = task)
                        : capture.CheckStatusPendingPurgeCleanupAsync(session.Capture, selector, session.Handle!, linked.Token,
                            task => p.CleanupTask = task)).ConfigureAwait(false);
                    Require(result == SecretStatus.Success);
                    var proof = PendingCleanupProof(session);
                    CheckPendingClock(session);
                    snapshot = admitted;
                    var completion = RegisterPending(PendingFact(session, snapshot,
                        RoleFixtureJournal.StatusPendingPurgeStage.CleanupTerminal, true, linked.Token,
                        CancellationPending(session) ? [session.StartTask!, p.CanceledTask!, session.StatusTask!, p.CleanupTask!] :
                            [session.StartTask!, session.StatusTask!, p.CleanupTask!],
                        CancellationPending(session) ? [p.CanceledProof!, proof] : [proof], cleanup: true, terminal: true));
                    p.Persistence = completion;
                    RetryPendingPersistence(session);
                }
                finally { DrainPendingInvocation(session); }
            }
            snapshot = provisioner.Journal.Read(owner, selector);
            if (p.Persistence is not null) return Reply(ReleaseMeasurement(session, snapshot, 1));
            if (snapshot.Idle)
            {
                using var linked = p.Clock is null || p.EpochCompleted || p.NeverSelectedClosed
                    ? CancellationTokenSource.CreateLinkedTokenSource(token, lifetime.Token) :
                    CancellationTokenSource.CreateLinkedTokenSource(token, lifetime.Token, p.Clock.Token);
                CheckPendingClock(session);
                var released = await provisioner.ReleaseAsync(owner, selector, purge: true, cancellationToken: linked.Token,
                    originalCallerToken: caller).ConfigureAwait(false);
                snapshot = released.Journal;
                CheckPendingClock(session);
                if (released.State != VaultFixtureProvisioner.State.Released ||
                    (CancellationPending(session) ? provisioner.HasStatusPendingPurgeCancellationPersistence(session.Plan) :
                        IndependentPending(session) ? provisioner.HasStatusPendingPurgeIndependentPersistence(session.Plan) :
                        provisioner.HasStatusPendingPurgePersistence(session.Plan)))
                    return Reply(ReleaseMeasurement(session, snapshot, 1));
            }
            return Reply(ReleaseMeasurement(session, snapshot));
        }
        finally
        {
            // Seal joins actual native tasks/finalizers, never a timeout proxy.
            // A retained persistence image still owns its original capture.
            try
            {
                if (session.Capture is not null && session.Pending!.Persistence is null && !session.Pending.EpochCompleted &&
                    (session.Plan is null || !(CancellationPending(session) ? provisioner.HasStatusPendingPurgeCancellationPersistence(session.Plan) :
                        IndependentPending(session) ? provisioner.HasStatusPendingPurgeIndependentPersistence(session.Plan) :
                        provisioner.HasStatusPendingPurgePersistence(session.Plan))))
                {
                    await capture.SealAsync(session.Capture).ConfigureAwait(false);
                    if (provisioner.Journal.Read(owner, selector).Released)
                    {
                        CheckPendingClock(session, sealedDrain: true);
                        session.Pending.EpochCompleted = true;
                    }
                }
            }
            finally { lock (gate) session.Releasing = false; }
        }
    }
    internal sealed record NotificationSource(
        [property: JsonIgnore] NotificationFixtureProvisioner.Authority Setup,
        [property: JsonIgnore] NotificationFixtureProvisioner.Authority Observer,
        [property: JsonIgnore] NotificationFixtureProvisioner.Limits Limits,
        [property: JsonIgnore] NotificationConfiguration? Baseline,
        bool HttpsWebhookReady,
        [property: JsonIgnore] NotificationFixtureProvisioner.ExclusiveCreationDeclaration? ExclusiveCreation = null)
    {
        public override string ToString() => "[ManagementOperationNotificationSource]";
    }
    internal sealed record PrivateConnectionSource(
        [property: JsonIgnore] string BorrowedSubnetId,
        [property: JsonIgnore] R.Authority EndpointSetup,
        [property: JsonIgnore] R.Authority EndpointReader,
        [property: JsonIgnore] VaultAdministrationCollector.Authority VaultConnectionReader,
        [property: JsonIgnore] R.Limits ResourceLimits,
        [property: JsonIgnore] VaultAdministrationCollector.Limits InventoryLimits)
    {
        public override string ToString() => "[ManagementOperationPrivateConnectionSource]";
    }

    // Construction is not authority. Journal validators use only these private
    // reference-keyed registrations; they never enter service/parent/capture locks.
    internal sealed class PrivateConnectionApprovalAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidatePrivateAdmission(this, journal, snapshot);
        public override string ToString() => "[PrivateConnectionApprovalAdmission]";
    }
    internal sealed class PrivateConnectionApprovalSettlement(ManagementOperationFixtureObserverService source, Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidatePrivateSettlement(this, journal, snapshot);
        public override string ToString() => "[PrivateConnectionApprovalSettlement]";
    }
    internal sealed class StatusPrivateConnectionUpdateCancellationAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusPrivateAdmissions.TryGetValue(this, out var baseline) &&
            ReferenceEquals(journal, source.provisioner.Journal) &&
            MatchesStatusPrivateBaseline(baseline, snapshot) && !snapshot.Closing;
        public override string ToString() => "[StatusPrivateConnectionUpdateCancellationAdmission]";
    }
    internal sealed class StatusPrivateConnectionUpdateCancellationSettlement(ManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusPrivateSettlements.TryGetValue(this, out var completion) &&
            ReferenceEquals(journal, source.provisioner.Journal) && Dispatch == completion.Dispatch &&
            !snapshot.Closing && MatchesStatusPrivateBaseline(completion.Observation.Baseline, snapshot) &&
            snapshot.PrivateEndpoint!.Connection is { InvocationTerminated: false, ActiveDispatch: var active } &&
            active == Dispatch && completion.Observation.Baseline.Rows.SequenceEqual(snapshot.Resources);
        public override string ToString() => "[StatusPrivateConnectionUpdateCancellationSettlement]";
    }
    private sealed record StatusPrivateBaseline(VaultFixtureProvisioner.Plan Parent,
        PrivateEndpointFixtureProvisioner Endpoints, PrivateEndpointFixtureProvisioner.Plan Endpoint,
        RoleFixtureJournal.PrivateEndpointDeclaration Declaration, string ConnectionId,
        Guid Subscription, DateTimeOffset ArmedAt, R Reader, C.Binding Binding, R.Window Window,
        Task<R.Measurement> Task, R.StatusPrivateConnectionUpdateReadProof Proof,
        IReadOnlyList<RoleFixtureJournal.Resource> Rows)
    {
        public override string ToString() => "[StatusPrivateBaseline]";
    }
    private sealed record StatusPrivateObservation(StatusPrivateBaseline Baseline, R Reader, C.Binding Binding,
        R.Window Window, Task<R.Measurement> Task, R.StatusPrivateConnectionUpdateReadProof Proof,
        C.StatusPrivateConnectionUpdateCancellationStartProof Start)
    {
        public override string ToString() => "[StatusPrivateObservation]";
    }
    private sealed record StatusPrivateCompletion(StatusPrivateObservation Observation, Guid Dispatch,
        C.Window Window, VaultAdministration Client, PrivateConnectionScope Scope, ManagementReceipt Receipt,
        Task StartTask, ManagementOperation Handle, Task CanceledTask, Task StatusTask)
    {
        public override string ToString() => "[StatusPrivateCompletion]";
    }

    private static bool MatchesStatusPrivateBaseline(StatusPrivateBaseline baseline, RoleFixtureJournal.Snapshot snapshot) =>
        RoleFixtureJournal.StatusPrivateConnectionUpdateRoot(snapshot) &&
        baseline.Parent.Owner == snapshot.Owner && baseline.Parent.Selector == snapshot.Selector &&
        baseline.Parent.LeaseId == snapshot.LeaseId && baseline.Declaration == snapshot.PrivateEndpoint!.Declaration &&
        baseline.ConnectionId == snapshot.PrivateEndpoint.Connection?.Id &&
        baseline.Rows.SequenceEqual(snapshot.Resources);

    internal sealed class StatusPrivateConnectionDeleteCancellationAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusPrivateDeleteAdmissions.TryGetValue(this, out var baseline) &&
            ReferenceEquals(journal, source.provisioner.Journal) &&
            MatchesStatusPrivateDeleteBaseline(baseline, snapshot) && !snapshot.Closing;
        public override string ToString() => "[StatusPrivateConnectionDeleteCancellationAdmission]";
    }

    internal sealed class StatusPrivateConnectionDeleteCancellationSettlement(ManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusPrivateDeleteSettlements.TryGetValue(this, out var completion) &&
            ReferenceEquals(journal, source.provisioner.Journal) && Dispatch == completion.Dispatch &&
            !snapshot.Closing && MatchesStatusPrivateDeleteBaseline(completion.Observation.Baseline, snapshot) &&
            snapshot.PrivateEndpoint!.Connection is
            { SelectedAttempted: true, DeleteAttempted: true, InvocationTerminated: false, ActiveDispatch: var active } &&
            active == Dispatch;
        public override string ToString() => "[StatusPrivateConnectionDeleteCancellationSettlement]";
    }

    private sealed record StatusPrivateDeleteEndpointRead(PrivateEndpointResourceCollector Reader,
        PrivateEndpointResourceCollector.Binding Binding, PrivateEndpointResourceCollector.Window Window,
        Task<PrivateEndpointResourceCollector.Measurement> Task, PrivateEndpointResourceCollector.Measurement Measurement)
    {
        public override string ToString() => "[StatusPrivateDeleteEndpointRead]";
    }

    private sealed record StatusPrivateDeleteBaseline(VaultFixtureProvisioner.Plan Parent,
        PrivateEndpointFixtureProvisioner Endpoints, PrivateEndpointFixtureProvisioner.Plan Endpoint,
        RoleFixtureJournal.PrivateEndpointDeclaration Declaration, string ConnectionId,
        Guid Subscription, DateTimeOffset ArmedAt, R Reader, C.Binding Binding, R.Window Window,
        Task<R.Measurement> Task, R.StatusPrivateConnectionDeleteReadProof Proof,
        StatusPrivateDeleteEndpointRead EndpointRead, IReadOnlyList<RoleFixtureJournal.Resource> Rows)
    {
        public override string ToString() => "[StatusPrivateDeleteBaseline]";
    }

    private sealed record StatusPrivateDeleteObservation(StatusPrivateDeleteBaseline Baseline,
        R Reader, C.Binding Binding, R.Window Window, Task<R.Measurement> Task,
        R.StatusPrivateConnectionDeleteReadProof Proof, StatusPrivateDeleteEndpointRead EndpointRead,
        C.StatusPrivateConnectionDeleteCancellationStartProof Start)
    {
        public override string ToString() => "[StatusPrivateDeleteObservation]";
    }

    private sealed record StatusPrivateDeleteCompletion(StatusPrivateDeleteObservation Observation, Guid Dispatch,
        C.Window Window, VaultAdministration Client, PrivateConnectionScope Scope, ManagementReceipt Receipt,
        Task StartTask, ManagementOperation Handle, Task CanceledTask, Task StatusTask)
    {
        public override string ToString() => "[StatusPrivateDeleteCompletion]";
    }

    private static bool MatchesStatusPrivateDeleteBaseline(StatusPrivateDeleteBaseline baseline,
        RoleFixtureJournal.Snapshot snapshot) =>
        RoleFixtureJournal.StatusPrivateConnectionDeleteRoot(snapshot) &&
        baseline.Parent.Owner == snapshot.Owner && baseline.Parent.Selector == snapshot.Selector &&
        baseline.Parent.LeaseId == snapshot.LeaseId && baseline.Declaration == snapshot.PrivateEndpoint!.Declaration &&
        baseline.ConnectionId == snapshot.PrivateEndpoint.Connection?.Id &&
        baseline.Rows.SequenceEqual(snapshot.Resources);
    internal sealed class StatusPrivateConnectionDeleteSelectedAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusPrivateDeleteSelectedAdmissions.TryGetValue(this, out var baseline) &&
            ReferenceEquals(journal, source.provisioner.Journal) &&
            MatchesStatusPrivateDeleteSelectedBaseline(baseline, snapshot) && !snapshot.Closing;
        public override string ToString() => "[StatusPrivateConnectionDeleteSelectedAdmission]";
    }

    internal sealed class StatusPrivateConnectionDeleteSelectedSettlement(ManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusPrivateDeleteSelectedSettlements.TryGetValue(this, out var completion) &&
            ReferenceEquals(journal, source.provisioner.Journal) && Dispatch == completion.Dispatch &&
            !snapshot.Closing && MatchesStatusPrivateDeleteSelectedBaseline(completion.Observation.Baseline, snapshot) &&
            snapshot.PrivateEndpoint!.Connection is
            { SelectedAttempted: true, DeleteAttempted: true, InvocationTerminated: false, ActiveDispatch: var active } &&
            active == Dispatch;
        public override string ToString() => "[StatusPrivateConnectionDeleteSelectedSettlement]";
    }

    private sealed record StatusPrivateDeleteSelectedBaseline(VaultFixtureProvisioner.Plan Parent,
        PrivateEndpointFixtureProvisioner Endpoints, PrivateEndpointFixtureProvisioner.Plan Endpoint,
        RoleFixtureJournal.PrivateEndpointDeclaration Declaration, string ConnectionId,
        Guid Subscription, DateTimeOffset ArmedAt, R Reader, C.Binding Binding, R.Window Window,
        Task<R.Measurement> Task, R.StatusPrivateConnectionDeleteSelectedReadProof Proof,
        StatusPrivateDeleteEndpointRead EndpointRead, IReadOnlyList<RoleFixtureJournal.Resource> Rows)
    {
        public override string ToString() => "[StatusPrivateDeleteSelectedBaseline]";
    }

    private sealed record StatusPrivateDeleteSelectedObservation(StatusPrivateDeleteSelectedBaseline Baseline,
        R Reader, C.Binding Binding, R.Window Window, Task<R.Measurement> Task,
        R.StatusPrivateConnectionDeleteSelectedReadProof Proof, StatusPrivateDeleteEndpointRead EndpointRead,
        C.StatusPrivateConnectionDeleteSelectedStartProof Start)
    {
        public override string ToString() => "[StatusPrivateDeleteSelectedObservation]";
    }

    private sealed record StatusPrivateDeleteSelectedCompletion(StatusPrivateDeleteSelectedObservation Observation, Guid Dispatch,
        C.Window Window, VaultAdministration Client, PrivateConnectionScope Scope, ManagementReceipt Receipt,
        Task StartTask, ManagementOperation Handle, Task StatusTask,
        C.StatusPrivateConnectionDeleteSelectedCompletionProof NativeCompletion)
    {
        public override string ToString() => "[StatusPrivateDeleteSelectedCompletion]";
    }

    private static bool MatchesStatusPrivateDeleteSelectedBaseline(StatusPrivateDeleteSelectedBaseline baseline,
        RoleFixtureJournal.Snapshot snapshot) =>
        RoleFixtureJournal.StatusPrivateConnectionDeleteSelectedRoot(snapshot) &&
        baseline.Parent.Owner == snapshot.Owner && baseline.Parent.Selector == snapshot.Selector &&
        baseline.Parent.LeaseId == snapshot.LeaseId && baseline.Declaration == snapshot.PrivateEndpoint!.Declaration &&
        baseline.ConnectionId == snapshot.PrivateEndpoint.Connection?.Id &&
        baseline.Rows.SequenceEqual(snapshot.Resources);
    internal sealed class StatusPrivateConnectionDeleteIndependentAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusPrivateDeleteIndependentAdmissions.TryGetValue(this, out var baseline) &&
            ReferenceEquals(journal, source.provisioner.Journal) &&
            MatchesStatusPrivateDeleteIndependentBaseline(baseline, snapshot) && !snapshot.Closing;
        public override string ToString() => "[StatusPrivateConnectionDeleteIndependentAdmission]";
    }

    internal sealed class StatusPrivateConnectionDeleteIndependentSettlement(ManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusPrivateDeleteIndependentSettlements.TryGetValue(this, out var completion) &&
            ReferenceEquals(journal, source.provisioner.Journal) && Dispatch == completion.Dispatch &&
            !snapshot.Closing && MatchesStatusPrivateDeleteIndependentBaseline(completion.Observation.Baseline, snapshot) &&
            snapshot.PrivateEndpoint!.Connection is
            { SelectedAttempted: true, DeleteAttempted: true, InvocationTerminated: false, ActiveDispatch: var active } &&
            active == Dispatch;
        public override string ToString() => "[StatusPrivateConnectionDeleteIndependentSettlement]";
    }

    private sealed record StatusPrivateDeleteIndependentBaseline(VaultFixtureProvisioner.Plan Parent,
        PrivateEndpointFixtureProvisioner Endpoints, PrivateEndpointFixtureProvisioner.Plan Endpoint,
        RoleFixtureJournal.PrivateEndpointDeclaration Declaration, string ConnectionId,
        Guid Subscription, DateTimeOffset ArmedAt, R Reader, C.Binding Binding, R.Window Window,
        Task<R.Measurement> Task, R.StatusPrivateConnectionDeleteIndependentReadProof Proof,
        StatusPrivateDeleteEndpointRead EndpointRead, IReadOnlyList<RoleFixtureJournal.Resource> Rows)
    {
        public override string ToString() => "[StatusPrivateDeleteIndependentBaseline]";
    }

    private sealed record StatusPrivateDeleteIndependentObservation(StatusPrivateDeleteIndependentBaseline Baseline,
        R Reader, C.Binding Binding, R.Window Window, Task<R.Measurement> Task,
        R.StatusPrivateConnectionDeleteIndependentReadProof Proof, StatusPrivateDeleteEndpointRead EndpointRead,
        C.StatusPrivateConnectionDeleteIndependentStartProof Start)
    {
        public override string ToString() => "[StatusPrivateDeleteIndependentObservation]";
    }

    private sealed record StatusPrivateDeleteIndependentCompletion(StatusPrivateDeleteIndependentObservation Observation, Guid Dispatch,
        C.Window Window, VaultAdministration Client, PrivateConnectionScope Scope, ManagementReceipt Receipt,
        Task StartTask, ManagementOperation Handle, Task StatusTask,
        C.StatusPrivateConnectionDeleteIndependentCompletionProof NativeCompletion)
    {
        public override string ToString() => "[StatusPrivateDeleteIndependentCompletion]";
    }

    private static bool MatchesStatusPrivateDeleteIndependentBaseline(StatusPrivateDeleteIndependentBaseline baseline,
        RoleFixtureJournal.Snapshot snapshot) =>
        RoleFixtureJournal.StatusPrivateConnectionDeleteIndependentRoot(snapshot) &&
        baseline.Parent.Owner == snapshot.Owner && baseline.Parent.Selector == snapshot.Selector &&
        baseline.Parent.LeaseId == snapshot.LeaseId && baseline.Declaration == snapshot.PrivateEndpoint!.Declaration &&
        baseline.ConnectionId == snapshot.PrivateEndpoint.Connection?.Id &&
        baseline.Rows.SequenceEqual(snapshot.Resources);
    internal sealed class StatusPrivateConnectionDeleteIndependentReadAdmission(ManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusPrivateDeleteIndependentReadAdmissions.TryGetValue(this, out var observation) &&
            ReferenceEquals(journal, source.provisioner.Journal) && !snapshot.Closing &&
            MatchesStatusPrivateDeleteIndependentBaseline(observation.Baseline, snapshot) &&
            snapshot.PrivateEndpoint!.Connection is
            { SelectedAttempted: true, DeleteAttempted: true, InvocationTerminated: true, ActiveDispatch: var active } &&
            Dispatch != Guid.Empty && active == Dispatch;
        public override string ToString() => "[StatusPrivateConnectionDeleteIndependentReadAdmission]";
    }

    internal sealed class StatusVaultDeleteCancellationSettlement(ManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateStatusVaultDeleteCancellationSettlement(this, journal, snapshot);
        public override string ToString() => "[StatusVaultDeleteCancellationSettlement]";
    }
    internal sealed class StatusVaultPurgeCancellationSettlement(ManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateStatusVaultPurgeCancellationSettlement(this, journal, snapshot);
        public override string ToString() => "[StatusVaultPurgeCancellationSettlement]";
    }
    internal sealed class StatusVaultRecoverCancellationSettlement(ManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateStatusVaultRecoverCancellationSettlement(this, journal, snapshot);
        public override string ToString() => "[StatusVaultRecoverCancellationSettlement]";
    }
    internal sealed class StatusVaultUpdateCancellationSettlement(ManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateStatusVaultUpdateCancellationSettlement(this, journal, snapshot);
        public override string ToString() => "[StatusVaultUpdateCancellationSettlement]";
    }
    internal sealed class StatusNotificationCreateCancellationAdmission(ManagementOperationFixtureObserverService source)
    {
        internal RoleFixtureJournal.NotificationAbsentCreateState? AbsentCreate =>
            source.statusNotificationCreateAdmissions[this].AbsentCreate;
        internal string BaselineSha256 =>
            source.statusNotificationCreateAdmissions[this].BaselineSha256;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateStatusNotificationCreateAdmission(this, journal, snapshot);
        public override string ToString() => "[StatusNotificationCreateCancellationAdmission]";
    }
    internal sealed class StatusNotificationCreateCancellationSettlement(ManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal RoleFixtureJournal.NotificationAbsentCreateState? AbsentCreate =>
            source.statusNotificationCreateSettlements[this].AbsentCreate;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateStatusNotificationCreateSettlement(this, journal, snapshot);
        public override string ToString() => "[StatusNotificationCreateCancellationSettlement]";
    }
    private sealed record StatusNotificationCreateBaseline(StatusNotificationDeleteReadSlot Slot,
        Task<NotificationFixtureProvisioner.Result> Task,
        NotificationFixtureProvisioner.StatusNotificationCreateReadProof Proof,
        IReadOnlyList<RoleFixtureJournal.Resource> Rows, NotificationConfiguration? Configuration, DateTimeOffset FinishedAt,
        RoleFixtureJournal.NotificationAbsentCreateState? AbsentCreate, string BaselineSha256)
    {
        public override string ToString() => "[StatusNotificationCreateBaseline]";
    }
    private sealed record StatusNotificationCreateObservation(StatusNotificationCreateBaseline Baseline,
        StatusNotificationDeleteReadSlot Slot, Task<NotificationFixtureProvisioner.Result> Task,
        NotificationFixtureProvisioner.StatusNotificationCreateReadProof Proof, NotificationConfiguration Configuration,
        C.StatusNotificationCreateCancellationStartProof Start, C.StatusTarget Target,
        S.Window StatusWindow, Task<S.Measurement> StatusTask, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusNotificationCreateObservation]";
    }
    private sealed record StatusNotificationCreateCompletion(StatusNotificationCreateObservation Observation,
        Guid Dispatch, C.Window Window, VaultAdministration Client, NotificationScope Scope, ManagementReceipt Receipt,
        Task StartTask, ManagementOperation Handle, Task CanceledTask, Task StatusTask,
        CancellationToken Cancellation, CancellationToken CallerCancellation,
        RoleFixtureJournal.NotificationAbsentCreateState? AbsentCreate = null)
    {
        public override string ToString() => "[StatusNotificationCreateCompletion]";
    }
    internal sealed class StatusNotificationUpdateCancellationAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateStatusNotificationUpdateAdmission(this, journal, snapshot);
        public override string ToString() => "[StatusNotificationUpdateCancellationAdmission]";
    }
    internal sealed class StatusNotificationUpdateCancellationSettlement(ManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateStatusNotificationUpdateSettlement(this, journal, snapshot);
        public override string ToString() => "[StatusNotificationUpdateCancellationSettlement]";
    }
    private sealed record StatusNotificationUpdateBaseline(StatusNotificationDeleteReadSlot Slot,
        Task<NotificationFixtureProvisioner.Result> Task,
        NotificationFixtureProvisioner.StatusNotificationUpdateReadProof Proof,
        IReadOnlyList<RoleFixtureJournal.Resource> Rows, NotificationConfiguration Configuration, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusNotificationUpdateBaseline]";
    }
    private sealed record StatusNotificationUpdateObservation(StatusNotificationUpdateBaseline Baseline,
        StatusNotificationDeleteReadSlot Slot, Task<NotificationFixtureProvisioner.Result> Task,
        NotificationFixtureProvisioner.StatusNotificationUpdateReadProof Proof, NotificationConfiguration Configuration,
        C.StatusNotificationUpdateCancellationStartProof Start, C.StatusTarget Target,
        S.Window StatusWindow, Task<S.Measurement> StatusTask, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusNotificationUpdateObservation]";
    }
    private sealed record StatusNotificationUpdateCompletion(StatusNotificationUpdateObservation Observation,
        Guid Dispatch, C.Window Window, VaultAdministration Client, NotificationScope Scope, ManagementReceipt Receipt,
        Task StartTask, ManagementOperation Handle, Task CanceledTask, Task StatusTask,
        CancellationToken Cancellation, CancellationToken CallerCancellation)
    {
        public override string ToString() => "[StatusNotificationUpdateCompletion]";
    }
    internal sealed class StatusNotificationDeleteIndependentAdmission(ManagementOperationFixtureObserverService source)
    {
        internal string ResourceId => source.statusNotificationDeleteIndependentAdmissions[this].Slot.Child.ResourceId;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateStatusNotificationDeleteIndependentAdmission(this, journal, snapshot);
        public override string ToString() => "[StatusNotificationDeleteIndependentAdmission]";
    }
    internal sealed class StatusNotificationDeleteIndependentReadAdmission(ManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateStatusNotificationDeleteIndependentReadAdmission(this, journal, snapshot);
        public override string ToString() => "[StatusNotificationDeleteIndependentReadAdmission]";
    }
    internal sealed class StatusNotificationDeleteIndependentSettlement(ManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateStatusNotificationDeleteIndependentSettlement(this, journal, snapshot);
        public override string ToString() => "[StatusNotificationDeleteIndependentSettlement]";
    }
    private sealed record StatusNotificationDeleteIndependentReadSlot(NotificationFixtureProvisioner Source,
        NotificationFixtureProvisioner.Plan Child, VaultFixtureProvisioner.Plan Parent, C.Binding Binding,
        Guid Subscription, DateTimeOffset ArmedAt, bool Baseline, Guid Nonce)
    {
        public override string ToString() => "[StatusNotificationDeleteIndependentReadSlot]";
    }
    private sealed record StatusNotificationDeleteIndependentBaseline(StatusNotificationDeleteIndependentReadSlot Slot,
        Task<NotificationFixtureProvisioner.Result> Task,
        NotificationFixtureProvisioner.StatusNotificationDeleteIndependentReadProof Proof,
        IReadOnlyList<RoleFixtureJournal.Resource> Rows, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusNotificationDeleteIndependentBaseline]";
    }
    private sealed record StatusNotificationDeleteIndependentObservation(StatusNotificationDeleteIndependentBaseline Baseline,
        StatusNotificationDeleteIndependentReadSlot Slot, Task<NotificationFixtureProvisioner.Result> Task,
        NotificationFixtureProvisioner.StatusNotificationDeleteIndependentReadProof Proof,
        C.StatusNotificationDeleteIndependentStartProof Start, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusNotificationDeleteIndependentObservation]";
    }
    private sealed record StatusNotificationDeleteIndependentCompletion(StatusNotificationDeleteIndependentObservation Observation,
        Guid Dispatch, C.Window Window, VaultAdministration Client, NotificationScope Scope, ManagementReceipt Receipt,
        Task StartTask, ManagementOperation Handle, Task StatusTask,
        C.StatusNotificationDeleteIndependentCompletionProof Proof, CancellationToken Cancellation,
        CancellationToken CallerCancellation)
    {
        public override string ToString() => "[StatusNotificationDeleteIndependentCompletion]";
    }

    internal sealed class StatusNotificationDeleteCancellationSettlement(ManagementOperationFixtureObserverService source,
        Guid dispatch)
    {
        internal Guid Dispatch { get; } = dispatch;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateStatusNotificationDeleteCancellationSettlement(this, journal, snapshot);
        public override string ToString() => "[StatusNotificationDeleteCancellationSettlement]";
    }
    private sealed record StatusNotificationDeleteReadSlot(NotificationFixtureProvisioner Source,
        NotificationFixtureProvisioner.Plan Child, VaultFixtureProvisioner.Plan Parent, C.Binding Binding,
        Guid Subscription, DateTimeOffset ArmedAt, bool Baseline)
    {
        public override string ToString() => "[StatusNotificationDeleteReadSlot]";
    }
    private sealed record StatusNotificationDeleteCancellationBaseline(StatusNotificationDeleteReadSlot Slot,
        Task<NotificationFixtureProvisioner.Result> Task,
        NotificationFixtureProvisioner.StatusNotificationDeleteReadProof Proof,
        IReadOnlyList<RoleFixtureJournal.Resource> Rows, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusNotificationDeleteCancellationBaseline]";
    }
    private sealed record StatusNotificationDeleteCancellationObservation(StatusNotificationDeleteCancellationBaseline Baseline,
        StatusNotificationDeleteReadSlot Slot, Task<NotificationFixtureProvisioner.Result> Task,
        NotificationFixtureProvisioner.StatusNotificationDeleteReadProof Proof,
        C.StatusNotificationDeleteCancellationStartProof Start, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusNotificationDeleteCancellationObservation]";
    }
    private sealed record StatusNotificationDeleteCancellationCompletion(StatusNotificationDeleteCancellationObservation Observation,
        Guid Dispatch, C.Window Window, VaultAdministration Client, NotificationScope Scope, ManagementReceipt Receipt,
        Task StartTask, ManagementOperation Handle, Task CanceledTask, Task StatusTask,
        CancellationToken Cancellation, CancellationToken CallerCancellation)
    {
        public override string ToString() => "[StatusNotificationDeleteCancellationCompletion]";
    }
    private sealed record StatusVaultUpdateCancellationBaseline(string Owner, FixtureSelector Selector, Guid Lease,
        string VaultId, string SecretId, string DeletedId, VaultAdministrationEffects.Configuration Configuration,
        VaultAdministrationEffects.Configuration Selected, C.Binding Binding, C.Binding Counterpart,
        R.Window ActiveWindow, R.Window DeletedWindow, Task<R.Measurement> ActiveTask, Task<R.Measurement> DeletedTask,
        Task<VaultFixtureProvisioner.Result> OwnedTask, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusVaultUpdateCancellationBaseline]";
    }
    private sealed record StatusVaultUpdateCancellationObservation(StatusVaultUpdateCancellationBaseline Baseline,
        C.StatusTarget Target, S.Window StatusWindow, Task<S.Measurement> StatusTask,
        R.Window ActiveWindow, R.Window DeletedWindow, Task<R.Measurement> ActiveTask, Task<R.Measurement> DeletedTask,
        Task<VaultFixtureProvisioner.Result> OwnedTask, VaultAdministrationEffects.Configuration Configuration,
        DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusVaultUpdateCancellationObservation]";
    }
    private sealed record StatusVaultUpdateCancellationCompletion(StatusVaultUpdateCancellationObservation Observation,
        Guid Dispatch, C.Window Window, VaultAdministration Client, VaultScope Scope, ManagementReceipt Receipt,
        Task StartTask, ManagementOperation Handle, Task CanceledTask, Task StatusTask, CancellationToken Cancellation,
        CancellationToken CallerCancellation)
    {
        public override string ToString() => "[StatusVaultUpdateCancellationCompletion]";
    }
    private sealed record StatusVaultRecoverCancellationBaseline(string Owner, FixtureSelector Selector, Guid Lease,
        string VaultId, string SecretId, string DeletedId, VaultAdministrationEffects.Configuration Configuration,
        C.Binding Binding, C.Binding Counterpart, R.Window ActiveWindow, R.Window DeletedWindow,
        Task<R.Measurement> ActiveTask, Task<R.Measurement> DeletedTask,
        Task<VaultFixtureProvisioner.Result> OwnedTask, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusVaultRecoverCancellationBaseline]";
    }
    private sealed record StatusVaultRecoverCancellationObservation(StatusVaultRecoverCancellationBaseline Baseline,
        C.StatusTarget Target, S.Window StatusWindow, Task<S.Measurement> StatusTask,
        R.Window ActiveWindow, R.Window DeletedWindow, Task<R.Measurement> ActiveTask, Task<R.Measurement> DeletedTask,
        Task<VaultFixtureProvisioner.Result> OwnedTask, VaultAdministrationEffects.Configuration Configuration,
        DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusVaultRecoverCancellationObservation]";
    }
    private sealed record StatusVaultRecoverCancellationCompletion(StatusVaultRecoverCancellationObservation Observation,
        Guid Dispatch, C.Window Window, VaultAdministration Client, VaultScope Scope, ManagementReceipt Receipt,
        Task StartTask, ManagementOperation Handle, Task CanceledTask, Task StatusTask, CancellationToken Cancellation,
        CancellationToken CallerCancellation)
    {
        public override string ToString() => "[StatusVaultRecoverCancellationCompletion]";
    }
    private sealed record StatusVaultPurgeCancellationBaseline(string Owner, FixtureSelector Selector, Guid Lease,
        string VaultId, string SecretId, string DeletedId, C.Binding Binding, C.Binding Counterpart,
        R.Window ActiveWindow, R.Window DeletedWindow, Task<R.Measurement> ActiveTask, Task<R.Measurement> DeletedTask,
        DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusVaultPurgeCancellationBaseline]";
    }
    private sealed record StatusVaultPurgeCancellationObservation(StatusVaultPurgeCancellationBaseline Baseline,
        C.StatusTarget Target, S.Window StatusWindow, Task<S.Measurement> StatusTask,
        R.Window ActiveWindow, R.Window DeletedWindow, Task<R.Measurement> ActiveTask, Task<R.Measurement> DeletedTask,
        DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusVaultPurgeCancellationObservation]";
    }
    private sealed record StatusVaultPurgeCancellationCompletion(StatusVaultPurgeCancellationObservation Observation,
        Guid Dispatch, C.Window Window, VaultAdministration Client, DeletedVaultScope Scope, ManagementReceipt Receipt,
        Task StartTask, ManagementOperation Handle, Task CanceledTask, Task StatusTask, CancellationToken Cancellation,
        CancellationToken CallerCancellation)
    {
        public override string ToString() => "[StatusVaultPurgeCancellationCompletion]";
    }
    private sealed record StatusVaultDeleteCancellationBaseline(string Owner, FixtureSelector Selector, Guid Lease,
        string VaultId, string SecretId, string DeletedId, C.Binding Binding, C.Binding Counterpart,
        R.Window ActiveWindow, R.Window DeletedWindow, Task<R.Measurement> ActiveTask, Task<R.Measurement> DeletedTask,
        DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusVaultDeleteCancellationBaseline]";
    }
    private sealed record StatusVaultDeleteCancellationObservation(StatusVaultDeleteCancellationBaseline Baseline,
        C.StatusTarget Target, S.Window StatusWindow, Task<S.Measurement> StatusTask,
        R.Window ActiveWindow, R.Window DeletedWindow, Task<R.Measurement> ActiveTask, Task<R.Measurement> DeletedTask,
        DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusVaultDeleteCancellationObservation]";
    }
    private sealed record StatusVaultDeleteCancellationCompletion(StatusVaultDeleteCancellationObservation Observation,
        Guid Dispatch, C.Window Window, VaultAdministration Client, VaultScope Scope, ManagementReceipt Receipt,
        Task StartTask, ManagementOperation Handle, Task CanceledTask, Task StatusTask, CancellationToken Cancellation,
        CancellationToken CallerCancellation)
    {
        public override string ToString() => "[StatusVaultDeleteCancellationCompletion]";
    }
    private sealed record PrivateApprovalBaseline(Session Session, VaultFixtureProvisioner.Plan Parent,
        PrivateEndpointFixtureProvisioner.Plan EndpointPlan, RoleFixtureJournal.PrivateEndpointDeclaration Declaration,
        string ConnectionId, C.Binding Binding, R.Window Window, Task<R.Measurement> Task, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[PrivateApprovalBaseline]";
    }
    private sealed record PrivateApprovalPost(PrivateApprovalBaseline Baseline, C.Binding Binding, R.Window Window,
        Task<R.Measurement> Task, C.PrivateApprovalResponseProof Proof)
    {
        public override string ToString() => "[PrivateApprovalPost]";
    }
    private sealed record PrivateApprovalCompletion(PrivateApprovalBaseline Baseline, Guid Dispatch,
        C.Binding Binding, C.Window Window, VaultAdministration Client, PrivateConnectionScope Scope,
        ManagementReceipt Receipt, ManagementOperation Handle, Task StartTask, Task StatusTask,
        C.PrivateApprovalResponseProof Proof, R.Window PostWindow, Task<R.Measurement> PostTask,
        CancellationToken Cancellation)
    {
        public override string ToString() => "[PrivateApprovalCompletion]";
    }
    private static readonly JsonSerializerOptions Json = new(ManagementAdmission.Json)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true
    };
    private readonly object gate = new();
    private readonly Uri origin;
    private readonly string owner, observerIdentity;
    private readonly SecretMaterial capability;
    private readonly VaultFixtureProvisioner.HostScope scope;
    private readonly VaultFixtureProvisioner provisioner;
    private readonly C? nativeCapture;
    private C capture => nativeCapture ?? throw Failure();
    private readonly S? statusCollector;
    private S statuses => statusCollector ?? throw Failure();
    private readonly R? beforeCollector, afterCollector;
    private readonly R? statusCounterpartBeforeCollector, statusCounterpartAfterCollector;
    private R before => beforeCollector ?? throw Failure();
    private R after => afterCollector ?? throw Failure();
    private readonly Limits limits;
    private readonly TimeProvider time;
    private bool statusPrivateUpdateIndependentProfile, statusPrivateUpdateIndependentCleanup;
    private VaultAdministrationEffects.Configuration? statusPrivateUpdateIndependentConfiguration;
    private enum PrivateUpdateIndependentStage { Begin, StartDrain, Read, Complete }
    private sealed record PrivateUpdateIndependentFacts(RoleFixtureJournal.Snapshot Preimage,
        RoleFixtureJournal.Snapshot Postimage, string ResourceId, Guid Dispatch, PrivateUpdateIndependentStage Stage,
        CancellationToken[] Tokens, Task[] Tasks, VaultFixtureProvisioner.Plan Parent,
        PrivateEndpointFixtureProvisioner Endpoints, PrivateEndpointFixtureProvisioner.Plan Endpoint,
        PrivateUpdateIndependentRead Baseline, PrivateUpdateIndependentRead? Observation,
        C.StatusPrivateConnectionUpdateIndependentStartProof? StartProof, C.StatusPrivateConnectionUpdateIndependentCompletionProof? CompletionProof)
    {
        public override string ToString() => "[PrivateUpdateIndependentFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, PrivateUpdateIndependentFacts>
        privateUpdateIndependentFacts = new(ReferenceEqualityComparer.Instance);

    internal sealed class StatusPrivateConnectionUpdateIndependentAdmission(ManagementOperationFixtureObserverService source)
    {
        internal string ResourceId => source.privateUpdateIndependentFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.privateUpdateIndependentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidatePrivateUpdateIndependent(this, journal, state, PrivateUpdateIndependentStage.Begin);
        public override string ToString() => "[StatusPrivateConnectionUpdateIndependentAdmission]";
    }
    internal sealed class StatusPrivateConnectionUpdateIndependentStartDrain(ManagementOperationFixtureObserverService source)
    {
        internal Guid Dispatch => source.privateUpdateIndependentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidatePrivateUpdateIndependent(this, journal, state, PrivateUpdateIndependentStage.StartDrain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidatePrivateUpdateIndependent(this, journal, state, PrivateUpdateIndependentStage.StartDrain, true);
        public override string ToString() => "[StatusPrivateConnectionUpdateIndependentStartDrain]";
    }
    internal sealed class StatusPrivateConnectionUpdateIndependentReadAdmission(ManagementOperationFixtureObserverService source)
    {
        internal Guid Dispatch => source.privateUpdateIndependentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidatePrivateUpdateIndependent(this, journal, state, PrivateUpdateIndependentStage.Read);
        public override string ToString() => "[StatusPrivateConnectionUpdateIndependentReadAdmission]";
    }
    internal sealed class StatusPrivateConnectionUpdateIndependentSettlement(ManagementOperationFixtureObserverService source)
    {
        internal Guid Dispatch => source.privateUpdateIndependentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidatePrivateUpdateIndependent(this, journal, state, PrivateUpdateIndependentStage.Complete);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidatePrivateUpdateIndependent(this, journal, state, PrivateUpdateIndependentStage.Complete, true);
        public override string ToString() => "[StatusPrivateConnectionUpdateIndependentSettlement]";
    }
    private bool ValidatePrivateUpdateIndependent(object capability, RoleFixtureJournal journal,
        RoleFixtureJournal.Snapshot state, PrivateUpdateIndependentStage stage, bool postimage = false) =>
        !disposed && !lifetime.IsCancellationRequested && ReferenceEquals(journal, provisioner.Journal) && privateUpdateIndependentFacts.TryGetValue(capability, out var f) &&
        f.Stage == stage && !state.Closing && f.Parent.Owner == state.Owner && f.Parent.Selector == state.Selector &&
        f.Parent.LeaseId == state.LeaseId && (stage == PrivateUpdateIndependentStage.Begin ? f.StartProof is null : f.StartProof is not null) &&
        (stage != PrivateUpdateIndependentStage.Complete || f.CompletionProof is not null && ReferenceEquals(f.CompletionProof.Start, f.StartProof)) &&
        f.Tokens.All(t => !t.IsCancellationRequested) && f.Tasks.All(t => t.IsCompletedSuccessfully) && RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(
            postimage ? f.Postimage : f.Preimage, state);

    private static RoleFixtureJournal.Snapshot FreezePrivateUpdateIndependent(RoleFixtureJournal.Snapshot state) =>
        state with { Selector = state.Selector with { }, Resources = state.Resources.Select(r => r with { }).ToArray(),
            PrivateEndpoint = state.PrivateEndpoint! with { Declaration = state.PrivateEndpoint.Declaration with { },
                Connection = state.PrivateEndpoint.Connection is null ? null : state.PrivateEndpoint.Connection with { } } };

    private void IssuePrivateUpdateIndependent(Session session, object capability, PrivateUpdateIndependentStage stage,
        RoleFixtureJournal.Snapshot state, params Task[] tasks)
    {
        Require(!disposed && !session.Closed && !session.PrivateUpdateIndependentInvalid &&
            session.PrivateUpdateIndependentTokens.All(t => !t.IsCancellationRequested));
        C.StatusPrivateConnectionUpdateIndependentStartProof? startProof = null;
        C.StatusPrivateConnectionUpdateIndependentCompletionProof? completionProof = null;
        if (stage != PrivateUpdateIndependentStage.Begin) Require(OwnsPrivateUpdateIndependentStart(session, out startProof));
        if (stage == PrivateUpdateIndependentStage.Complete)
            Require(capture.TryGetStatusPrivateConnectionUpdateIndependentCompletion(session.Capture!, session.Binding!, session.Client!,
                session.ActualPrivateScope!, session.Receipt!, session.StartTask!, session.Handle!, session.StatusTask!, out completionProof));
        var preimage = FreezePrivateUpdateIndependent(state);
        string id = session.ConnectionId!;
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            PrivateEndpoint = preimage.PrivateEndpoint! with
            {
                ApprovalSettledDispatch = stage == PrivateUpdateIndependentStage.Complete ? session.Dispatch : Guid.Empty,
                Connection = preimage.PrivateEndpoint.Connection! with
                {
                    SelectedAttempted = true,
                    InvocationTerminated = stage is PrivateUpdateIndependentStage.StartDrain or PrivateUpdateIndependentStage.Complete,
                    ActiveDispatch = stage == PrivateUpdateIndependentStage.Complete ? Guid.Empty : session.Dispatch
                }
            }
        };
        Require(privateUpdateIndependentFacts.TryAdd(capability, new(preimage, postimage, id, session.Dispatch, stage,
            session.PrivateUpdateIndependentTokens.ToArray(), tasks.ToArray(), session.Plan!, session.Endpoints!, session.EndpointPlan!,
            session.PrivateUpdateIndependentBaseline!, session.PrivateUpdateIndependentObservation, startProof, completionProof)));
        session.PrivateUpdateIndependentCapabilities.Add(capability);
    }
    private void RevokePrivateUpdateIndependent(Session session)
    {
        session.PrivateUpdateIndependentInvalid = true;
        foreach (var capability in session.PrivateUpdateIndependentCapabilities)
            privateUpdateIndependentFacts.TryRemove(capability, out _);
    }

    private sealed record PrivateUpdateIndependentRead(R Reader, C.Binding Binding, R.Window Window, Task<R.Measurement> Task,
        R.StatusPrivateConnectionUpdateIndependentReadProof Proof, PrivateEndpointResourceCollector EndpointReader,
        PrivateEndpointResourceCollector.Binding EndpointBinding, PrivateEndpointResourceCollector.Window EndpointWindow,
        Task<PrivateEndpointResourceCollector.Measurement> EndpointTask, PrivateEndpointResourceCollector.Measurement Endpoint,
        Guid Subscription, DateTimeOffset ArmedAt)
    {
        public override string ToString() => "[PrivateUpdateIndependentRead]";
    }
    internal static ManagementOperationFixtureObserverService ForStatusPrivateConnectionUpdateIndependent(Uri origin,
        string owner, string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, S.Authority statusReader, R.Authority resourceReader,
        HttpPipelineTransport selectedBackend, S.Limits statusLimits, R.Limits resourceLimits, Limits limits,
        TimeProvider time, PrivateConnectionSource privateConnectionSource)
    {
        Require(privateConnectionSource is not null);
        var configuration = provisioner.StatusPrivateConnectionUpdateIndependentConfiguration(scope, resourceReader, selectedBackend);
        return new(origin, owner, observerIdentity, capability, scope, provisioner, statusReader, resourceReader,
            selectedBackend, statusLimits, resourceLimits, limits, time, privateConnectionSource: privateConnectionSource)
        { statusPrivateUpdateIndependentProfile = true, statusPrivateUpdateIndependentConfiguration = configuration };
    }
    internal static ManagementOperationFixtureObserverService ForStatusPrivateConnectionUpdateIndependentCleanup(Uri origin,
        string owner, string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, PrivateConnectionSource endpoint, Limits limits, TimeProvider? time = null) =>
        new(origin, owner, observerIdentity, capability, scope, provisioner, endpoint, limits, time, independent: true, independentUpdate: true);

    private bool PrivateUpdateIndependentLive(Session session) => !disposed && !session.Closed && !session.PrivateUpdateIndependentInvalid &&
        !lifetime.IsCancellationRequested && session.PrivateUpdateIndependentTokens.All(t => !t.IsCancellationRequested);
    private bool OwnsPrivateUpdateIndependentStart(Session session, [NotNullWhen(true)] out C.StatusPrivateConnectionUpdateIndependentStartProof? proof)
    {
        proof = null;
        return PrivateUpdateIndependentLive(session) && session.Client is not null && session.ActualPrivateScope is not null &&
            session.Receipt is not null && session.StartTask is not null && session.Handle is not null &&
            capture.TryGetStatusPrivateConnectionUpdateIndependentStart(session.Capture!, session.Binding!, session.Client,
                session.ActualPrivateScope, session.Receipt, session.StartTask, session.Handle, out proof) &&
            proof.EndpointId == session.Plan!.PrivateEndpoint!.EndpointId;
    }
    private RoleFixtureJournal.Snapshot PrivateUpdateIndependentSnapshot(Session session)
    {
        try
        {
            var state = provisioner.Journal.Read(owner, session.Selector);
            Require(RoleFixtureJournal.StatusPrivateConnectionUpdateIndependentRoot(state));
            return state;
        }
        catch (RoleFixtureJournal.StatusPrivateConnectionUpdateIndependentHistoryException)
        { RevokePrivateUpdateIndependent(session); throw; }
    }
    private async Task<HttpResponseMessage> ObservePrivateUpdateIndependent(Session session, bool baseline, CancellationToken token,
        CancellationToken caller)
    {
        var parent = session.Plan!;
        Require(provisioner.TryEnterPrivateConnection(parent, session.ConnectionId!));
        PrivateUpdateIndependentRead observation;
        try
        {
            Require(PrivateUpdateIndependentLive(session));
            RequireOriginalPrivateEndpoint(session);
            var preimage = baseline ? session.PrivateUpdateIndependentReady! : session.PrivateUpdateIndependentDrained!;
            Require(RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(preimage, PrivateUpdateIndependentSnapshot(session)));
            if (!baseline) Require(OwnsPrivateUpdateIndependentStart(session, out _));
            var reader = baseline ? before : after;
            var binding = session.Binding!;
            var window = baseline ? session.Before! : session.After!;
            var task = reader.CollectAsync(window, binding, token, caller).AsTask();
            using var result = await task.ConfigureAwait(false);
            Require(reader.TryGetStatusPrivateConnectionUpdateIndependentRead(window, binding, task, out var proof) &&
                reader.OwnsStatusPrivateConnectionUpdateIndependentRead(proof, window, binding, task) && proof.HttpStatus == 200 &&
                proof.Facts is { Provisioning: "Succeeded" } facts && facts.Id == session.ConnectionId && facts.EndpointId == parent.PrivateEndpoint!.EndpointId &&
                facts.State == (baseline ? "Pending" : "Approved") && proof.StartedAt >= (baseline ? session.ArmedAt : session.StartedAt) &&
                PrivateResourceMatches(session, result, binding, window, baseline ? PrivateConnectionState.Pending : PrivateConnectionState.Approved));
            var source = privateConnectionSource!;
            var endpointReader = new PrivateEndpointResourceCollector(source.EndpointReader, source.ResourceLimits, time);
            var endpointBinding = provisioner.EndpointBinding(parent);
            var endpointWindow = endpointReader.Arm(endpointBinding);
            var endpointTask = endpointReader.CollectAsync(endpointWindow, endpointBinding, token).AsTask();
            var endpoint = await endpointTask.ConfigureAwait(false);
            Require(endpoint is { ResponseComplete: true, HttpStatus: 200, ResourceStatus: SecretStatus.Success,
                Kind: PrivateEndpointResourceCollector.ReadKind.Endpoint, NativeState: "Succeeded", MatchesDeclarationConfiguration: true } &&
                endpoint.ManualConnectionState == (baseline ? "Pending" : "Approved") && ReferenceEquals(endpoint.Binding, endpointBinding) &&
                endpoint.WindowId == endpointWindow.Id && endpoint.StartedAt >= proof.FinishedAt && endpoint.FinishedAt >= endpoint.StartedAt);
            Require(PrivateUpdateIndependentLive(session) && RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(preimage, PrivateUpdateIndependentSnapshot(session)));
            observation = new(reader, binding, window, task, proof, endpointReader, endpointBinding, endpointWindow, endpointTask, endpoint,
                session.Subscription, session.ArmedAt);
        }
        finally { provisioner.ExitPrivateConnection(parent); }
        // Publication follows the actual parent borrower exit, not only the
        // child HTTP or native task completion.
        lock (gate)
        {
            Require(PrivateUpdateIndependentLive(session));
            if (baseline)
            { session.PrivateUpdateIndependentBaseline = observation; session.BaselineAt = observation.Endpoint.FinishedAt; session.BaselineReady = true; }
            else
            { session.PrivateUpdateIndependentObservation = observation; session.IndependentAt = observation.Endpoint.FinishedAt; session.IndependentReady = true; }
        }
        return Reply(ProjectPrivateConnection(session, observation.Endpoint.FinishedAt,
            baseline ? NativeProvisioningState.Unknown : NativeProvisioningState.Succeeded,
            baseline ? PrivateConnectionState.Pending : PrivateConnectionState.Approved));
    }
    private async ValueTask<SecretOutcome<ManagementOperation>> StartPrivateUpdateIndependent(FixtureSelector selector, VaultAdministration client,
        ManagementScope originalScope, ManagementMutation operation, E.Input input, ManagementReceipt receipt, CancellationToken caller)
    {
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(client is not null && receipt is not null && originalScope is PrivateConnectionScope connection &&
                connection.Vault.ExportResourceId() == session.Plan!.VaultId &&
                session.Plan.VaultId + "/privateEndpointConnections/" + connection.ConnectionName == session.ConnectionId &&
                operation == ManagementMutation.UpdatePrivateConnection);
            bool valid = InputMatches(session, input) && PrivateUpdateIndependentLive(session) && session.Armed && session.BaselineReady && !session.StartClaimed &&
                session.PrivateUpdateIndependentBaseline is not null && !caller.IsCancellationRequested;
            session.StartClaimed = true;
            if (!valid) RevokePrivateUpdateIndependent(session);
            Require(valid);
            session.PrivateUpdateIndependentTokens.Add(caller);
            session.Active++; active++;
        }
        bool entered = false;
        try
        {
            Require(entered = provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            RequireOriginalPrivateEndpoint(session);
            var baseline = session.PrivateUpdateIndependentBaseline!;
            Require(baseline.Subscription == session.Subscription && baseline.ArmedAt == session.ArmedAt &&
                baseline.Reader.OwnsStatusPrivateConnectionUpdateIndependentRead(baseline.Proof, baseline.Window, baseline.Binding, baseline.Task));
            session.Dispatch = Guid.NewGuid();
            session.Binding = new(selector, session.Plan!.LeaseId, originalScope, operation, scope.Location, "2026-02-01");
            session.Client = client; session.ActualPrivateScope = (PrivateConnectionScope)originalScope; session.Receipt = receipt;
            var admission = new StatusPrivateConnectionUpdateIndependentAdmission(this);
            IssuePrivateUpdateIndependent(session, admission, PrivateUpdateIndependentStage.Begin, session.PrivateUpdateIndependentReady!, baseline.Task, baseline.EndpointTask);
            var begin = provisioner.Journal.BeginStatusPrivateConnectionUpdateIndependentInvocation(owner, selector, session.Plan.LeaseId, admission);
            Require(RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(privateUpdateIndependentFacts[admission].Postimage, begin));
            session.PrivateUpdateIndependentBegin = FreezePrivateUpdateIndependent(begin);
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource([.. session.PrivateUpdateIndependentTokens, caller, lifetime.Token, session.Stop.Token, deadline.Token]);
            session.PrivateUpdateIndependentTokens.Add(linked.Token);
            session.Capture = capture.Arm(session.Binding);
            session.After = after.ArmStatusPrivateConnectionUpdateIndependent(session.Binding, R.StatusPrivateConnectionUpdateIndependentReadPhase.SelectedState);
            var result = await capture.StartPrivateConnectionUpdateIndependentAsync(session.Capture, selector, client, originalScope, input, receipt,
                linked.Token, task => session.StartTask = task, () =>
                {
                    Require(PrivateUpdateIndependentLive(session) && RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(
                        session.PrivateUpdateIndependentBegin, PrivateUpdateIndependentSnapshot(session)));
                }, caller).ConfigureAwait(false);
            session.Handle = result.IsSuccess ? result.Value : null;
            session.StartSucceeded = result.IsSuccess && OwnsPrivateUpdateIndependentStart(session, out _);
            if (!session.StartSucceeded) return result;
            var drain = new StatusPrivateConnectionUpdateIndependentStartDrain(this);
            IssuePrivateUpdateIndependent(session, drain, PrivateUpdateIndependentStage.StartDrain, session.PrivateUpdateIndependentBegin, session.StartTask!);
            session.PrivateUpdateIndependentStartDrain = drain;
            PersistPrivateUpdateIndependent(session);
            return result;
        }
        finally
        {
            session.StartFinished = true;
            if (session.PrivateUpdateIndependentStartDrain is null) RevokePrivateUpdateIndependent(session);
            DrainPrivateUpdateIndependent(session);
            if (entered) provisioner.ExitPrivateConnection(session.Plan!);
            Leave(session);
        }
    }
    private async ValueTask<SecretStatus> CheckPrivateUpdateIndependent(FixtureSelector selector, ManagementOperation handle, CancellationToken caller)
    {
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(ReferenceEquals(handle, session.Handle));
            bool valid = PrivateUpdateIndependentLive(session) && !session.StatusClaimed && session.StartFinished && session.StartSucceeded &&
                session.IndependentReady && session.PrivateUpdateIndependentObservation is not null && !caller.IsCancellationRequested;
            session.StatusClaimed = true;
            if (!valid) RevokePrivateUpdateIndependent(session);
            Require(valid);
            session.PrivateUpdateIndependentTokens.Add(caller);
            session.Active++; active++;
        }
        bool entered = false;
        try
        {
            Require(entered = provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            RequireOriginalPrivateEndpoint(session);
            var observed = session.PrivateUpdateIndependentObservation!;
            var baseline = session.PrivateUpdateIndependentBaseline!;
            Require(OwnsPrivateUpdateIndependentStart(session, out _) &&
                observed.Reader.OwnsStatusPrivateConnectionUpdateIndependentRead(observed.Proof, observed.Window, observed.Binding, observed.Task) &&
                baseline.Reader.OwnsStatusPrivateConnectionUpdateIndependentRead(baseline.Proof, baseline.Window, baseline.Binding, baseline.Task));
            var admission = new StatusPrivateConnectionUpdateIndependentReadAdmission(this);
            IssuePrivateUpdateIndependent(session, admission, PrivateUpdateIndependentStage.Read, session.PrivateUpdateIndependentDrained!, observed.Task, observed.EndpointTask);
            var admitted = provisioner.Journal.AdmitStatusPrivateConnectionUpdateIndependentRead(owner, selector, session.Plan!.LeaseId, session.Dispatch, admission);
            Require(RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(privateUpdateIndependentFacts[admission].Postimage, admitted));
            session.PrivateUpdateIndependentRead = FreezePrivateUpdateIndependent(admitted);
            Require(time.GetUtcNow() >= session.IndependentAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource([.. session.PrivateUpdateIndependentTokens, caller, lifetime.Token, session.Stop.Token, deadline.Token]);
            session.PrivateUpdateIndependentTokens.Add(linked.Token);
            var result = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token, task => session.StatusTask = task, caller).ConfigureAwait(false);
            Require(result == SecretStatus.Success && capture.TryGetStatusPrivateConnectionUpdateIndependentCompletion(session.Capture!, session.Binding!,
                session.Client!, session.ActualPrivateScope!, session.Receipt!, session.StartTask!, handle, session.StatusTask!, out var proof) &&
                capture.OwnsStatusPrivateConnectionUpdateIndependentCompletion(proof, session.Capture!, session.Binding!, session.Client!,
                    session.ActualPrivateScope!, session.Receipt!, session.StartTask!, handle, session.StatusTask!));
            var settlement = new StatusPrivateConnectionUpdateIndependentSettlement(this);
            IssuePrivateUpdateIndependent(session, settlement, PrivateUpdateIndependentStage.Complete, session.PrivateUpdateIndependentRead,
                baseline.Task, baseline.EndpointTask, session.StartTask!, observed.Task, observed.EndpointTask, session.StatusTask!);
            session.PrivateUpdateIndependentSettlement = settlement;
            session.StatusSucceeded = true;
            PersistPrivateUpdateIndependent(session);
            return result;
        }
        finally
        {
            if (session.PrivateUpdateIndependentSettlement is null) RevokePrivateUpdateIndependent(session);
            DrainPrivateUpdateIndependent(session);
            if (entered) provisioner.ExitPrivateConnection(session.Plan!);
            Leave(session);
        }
    }
    private void DrainPrivateUpdateIndependent(Session session)
    {
        if (session.Dispatch == Guid.Empty || session.PrivateUpdateIndependentSettlement is not null && !session.PrivateUpdateIndependentInvalid ||
            session.PrivateUpdateIndependentRead is null && session.PrivateUpdateIndependentStartDrain is not null && !session.PrivateUpdateIndependentInvalid) return;
        try
        {
            provisioner.Journal.EndDispatch(owner, session.Selector, session.ConnectionId!, session.Dispatch, nativeSettled: false);
        }
        catch (InvalidOperationException) { }
        catch (IOException) { }
    }
    private RoleFixtureJournal.Snapshot PersistPrivateUpdateIndependent(Session session)
    {
        Require(PrivateUpdateIndependentLive(session));
        try
        {
            object candidate;
            RoleFixtureJournal.Snapshot committed;
            if (session.PrivateUpdateIndependentSettlement is { } completion)
            {
                candidate = completion;
                committed = provisioner.Journal.CompleteStatusPrivateConnectionUpdateIndependentRead(owner, session.Selector, session.Plan!.LeaseId, session.Dispatch, completion);
            }
            else
            {
                var drain = session.PrivateUpdateIndependentStartDrain ?? throw Failure();
                candidate = drain;
                committed = provisioner.Journal.EndStatusPrivateConnectionUpdateIndependentStart(owner, session.Selector, session.Plan!.LeaseId, session.Dispatch, drain);
                session.PrivateUpdateIndependentDrained = FreezePrivateUpdateIndependent(committed);
            }
            Require(privateUpdateIndependentFacts.TryGetValue(candidate, out var facts) &&
                RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(facts.Postimage, committed));
            return committed;
        }
        catch (IOException) { throw; }
        catch { RevokePrivateUpdateIndependent(session); throw; }
    }
    internal RoleFixtureJournal.Snapshot RetryStatusPrivateConnectionUpdateIndependentPersistence(FixtureSelector selector, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        Session session;
        lock (gate) { session = OpenSelector(selector); Require(session.Active == 0); session.Active++; active++; }
        try { return PersistPrivateUpdateIndependent(session); }
        finally { Leave(session); }
    }

    private bool statusNotificationUpdateIndependentProfile, statusNotificationUpdateIndependentCleanup;
    private VaultAdministrationEffects.Configuration? statusNotificationUpdateIndependentConfiguration;
    private enum NotificationUpdateIndependentStage { Begin, StartDrain, Read, Complete }
    private sealed record NotificationUpdateIndependentFacts(RoleFixtureJournal.Snapshot Preimage,
        RoleFixtureJournal.Snapshot Postimage, string ResourceId, Guid Dispatch, NotificationUpdateIndependentStage Stage,
        CancellationToken[] Tokens, Task[] Tasks)
    {
        public override string ToString() => "[NotificationUpdateIndependentFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, NotificationUpdateIndependentFacts>
        notificationUpdateIndependentFacts = new(ReferenceEqualityComparer.Instance);

    internal sealed class StatusNotificationUpdateIndependentAdmission(ManagementOperationFixtureObserverService source)
    {
        internal string ResourceId => source.notificationUpdateIndependentFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.notificationUpdateIndependentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationUpdateIndependent(this, journal, state, NotificationUpdateIndependentStage.Begin);
        public override string ToString() => "[StatusNotificationUpdateIndependentAdmission]";
    }
    internal sealed class StatusNotificationUpdateIndependentStartDrain(ManagementOperationFixtureObserverService source)
    {
        internal Guid Dispatch => source.notificationUpdateIndependentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationUpdateIndependent(this, journal, state, NotificationUpdateIndependentStage.StartDrain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationUpdateIndependent(this, journal, state, NotificationUpdateIndependentStage.StartDrain, true);
        public override string ToString() => "[StatusNotificationUpdateIndependentStartDrain]";
    }
    internal sealed class StatusNotificationUpdateIndependentReadAdmission(ManagementOperationFixtureObserverService source)
    {
        internal Guid Dispatch => source.notificationUpdateIndependentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationUpdateIndependent(this, journal, state, NotificationUpdateIndependentStage.Read);
        public override string ToString() => "[StatusNotificationUpdateIndependentReadAdmission]";
    }
    internal sealed class StatusNotificationUpdateIndependentSettlement(ManagementOperationFixtureObserverService source)
    {
        internal Guid Dispatch => source.notificationUpdateIndependentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationUpdateIndependent(this, journal, state, NotificationUpdateIndependentStage.Complete);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationUpdateIndependent(this, journal, state, NotificationUpdateIndependentStage.Complete, true);
        public override string ToString() => "[StatusNotificationUpdateIndependentSettlement]";
    }
    private bool ValidateNotificationUpdateIndependent(object capability, RoleFixtureJournal journal,
        RoleFixtureJournal.Snapshot state, NotificationUpdateIndependentStage stage, bool postimage = false) =>
        ReferenceEquals(journal, provisioner.Journal) && notificationUpdateIndependentFacts.TryGetValue(capability, out var f) &&
        f.Stage == stage && !state.Closing && f.Tokens.All(t => !t.IsCancellationRequested) &&
        f.Tasks.All(t => t.IsCompletedSuccessfully) && RoleFixtureJournal.SameStatusNotificationUpdateIndependentSnapshot(
            postimage ? f.Postimage : f.Preimage, state);

    private static RoleFixtureJournal.Snapshot FreezeNotificationUpdateIndependent(RoleFixtureJournal.Snapshot state) =>
        state with { Selector = state.Selector with { }, Resources = state.Resources.Select(r => r with { }).ToArray() };

    private void IssueNotificationUpdateIndependent(Session session, object capability, NotificationUpdateIndependentStage stage,
        RoleFixtureJournal.Snapshot state, params Task[] tasks)
    {
        Require(!disposed && !session.Closed && !session.NotificationUpdateIndependentInvalid &&
            session.NotificationUpdateIndependentTokens.All(t => !t.IsCancellationRequested));
        var preimage = FreezeNotificationUpdateIndependent(state);
        string id = session.NotificationPlan!.ResourceId;
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            {
                SelectedAttempted = true,
                InvocationTerminated = stage is NotificationUpdateIndependentStage.StartDrain or NotificationUpdateIndependentStage.Complete,
                ActiveDispatch = stage == NotificationUpdateIndependentStage.Complete ? Guid.Empty : session.Dispatch
            } : r).ToArray()
        };
        Require(notificationUpdateIndependentFacts.TryAdd(capability, new(preimage, postimage, id, session.Dispatch, stage,
            session.NotificationUpdateIndependentTokens.ToArray(), tasks.ToArray())));
        session.NotificationUpdateIndependentCapabilities.Add(capability);
    }
    private void RevokeNotificationUpdateIndependent(Session session)
    {
        session.NotificationUpdateIndependentInvalid = true;
        foreach (var capability in session.NotificationUpdateIndependentCapabilities)
            notificationUpdateIndependentFacts.TryRemove(capability, out _);
    }

    private sealed record StatusNotificationUpdateIndependentReadSlot(NotificationFixtureProvisioner Source,
        NotificationFixtureProvisioner.Plan Child, VaultFixtureProvisioner.Plan Parent, C.Binding Binding,
        Guid Subscription, DateTimeOffset ArmedAt, bool Baseline, Guid Nonce)
    {
        public override string ToString() => "[StatusNotificationUpdateIndependentReadSlot]";
    }
    private sealed record StatusNotificationUpdateIndependentBaseline(StatusNotificationUpdateIndependentReadSlot Slot,
        Task<NotificationFixtureProvisioner.Result> Task, NotificationFixtureProvisioner.StatusNotificationUpdateIndependentReadProof Proof,
        IReadOnlyList<RoleFixtureJournal.Resource> Rows, NotificationConfiguration Configuration, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusNotificationUpdateIndependentBaseline]";
    }
    private sealed record StatusNotificationUpdateIndependentObservation(StatusNotificationUpdateIndependentBaseline Baseline,
        StatusNotificationUpdateIndependentReadSlot Slot, Task<NotificationFixtureProvisioner.Result> Task,
        NotificationFixtureProvisioner.StatusNotificationUpdateIndependentReadProof Proof, NotificationConfiguration Configuration,
        C.StatusNotificationUpdateIndependentStartProof Start, C.StatusTarget Target, S.Window StatusWindow,
        Task<S.Measurement> StatusTask, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusNotificationUpdateIndependentObservation]";
    }

    internal static ManagementOperationFixtureObserverService ForStatusNotificationUpdateIndependent(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, S.Authority statusReader, R.Authority resourceReader,
        HttpPipelineTransport selectedBackend, S.Limits statusLimits, R.Limits resourceLimits, Limits limits,
        TimeProvider time, NotificationSource notificationSource)
    {
        Require(notificationSource is { HttpsWebhookReady: true, Baseline: not null, ExclusiveCreation: null });
        var configuration = provisioner.StatusNotificationUpdateIndependentConfiguration(scope, statusReader, resourceReader, selectedBackend);
        return new(origin, owner, observerIdentity, capability, scope, provisioner, statusReader, resourceReader,
            selectedBackend, statusLimits, resourceLimits, limits, time, notificationSource)
        { statusNotificationUpdateIndependentProfile = true, statusNotificationUpdateIndependentConfiguration = configuration };
    }
    internal static ManagementOperationFixtureObserverService ForStatusNotificationUpdateIndependentCleanup(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, NotificationSource notificationSource, Limits limits, TimeProvider? time = null) =>
        new(origin, owner, observerIdentity, capability, scope, provisioner, notificationSource, limits, time);

    private bool statusNotificationCreateIndependentProfile, statusNotificationCreateIndependentCleanup;
    private VaultAdministrationEffects.Configuration? statusNotificationCreateIndependentConfiguration;
    private enum NotificationCreateIndependentStage { Begin, StartDrain, Read, Complete }
    private sealed record NotificationCreateIndependentFacts(RoleFixtureJournal.Snapshot Preimage,
        RoleFixtureJournal.Snapshot Postimage, string ResourceId, Guid Dispatch, NotificationCreateIndependentStage Stage,
        CancellationToken[] Tokens, Task[] Tasks)
    {
        public override string ToString() => "[NotificationCreateIndependentFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, NotificationCreateIndependentFacts>
        notificationCreateIndependentFacts = new(ReferenceEqualityComparer.Instance);

    internal sealed class StatusNotificationCreateIndependentAdmission(ManagementOperationFixtureObserverService source)
    {
        internal string ResourceId => source.notificationCreateIndependentFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.notificationCreateIndependentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationCreateIndependent(this, journal, state, NotificationCreateIndependentStage.Begin);
        public override string ToString() => "[StatusNotificationCreateIndependentAdmission]";
    }
    internal sealed class StatusNotificationCreateIndependentStartDrain(ManagementOperationFixtureObserverService source)
    {
        internal Guid Dispatch => source.notificationCreateIndependentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationCreateIndependent(this, journal, state, NotificationCreateIndependentStage.StartDrain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationCreateIndependent(this, journal, state, NotificationCreateIndependentStage.StartDrain, true);
        public override string ToString() => "[StatusNotificationCreateIndependentStartDrain]";
    }
    internal sealed class StatusNotificationCreateIndependentReadAdmission(ManagementOperationFixtureObserverService source)
    {
        internal Guid Dispatch => source.notificationCreateIndependentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationCreateIndependent(this, journal, state, NotificationCreateIndependentStage.Read);
        public override string ToString() => "[StatusNotificationCreateIndependentReadAdmission]";
    }
    internal sealed class StatusNotificationCreateIndependentSettlement(ManagementOperationFixtureObserverService source)
    {
        internal Guid Dispatch => source.notificationCreateIndependentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationCreateIndependent(this, journal, state, NotificationCreateIndependentStage.Complete);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationCreateIndependent(this, journal, state, NotificationCreateIndependentStage.Complete, true);
        public override string ToString() => "[StatusNotificationCreateIndependentSettlement]";
    }
    private bool ValidateNotificationCreateIndependent(object capability, RoleFixtureJournal journal,
        RoleFixtureJournal.Snapshot state, NotificationCreateIndependentStage stage, bool postimage = false) =>
        ReferenceEquals(journal, provisioner.Journal) && notificationCreateIndependentFacts.TryGetValue(capability, out var f) &&
        f.Stage == stage && !state.Closing && f.Tokens.All(t => !t.IsCancellationRequested) &&
        f.Tasks.All(t => t.IsCompletedSuccessfully) && RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(
            postimage ? f.Postimage : f.Preimage, state);

    private static RoleFixtureJournal.Snapshot FreezeNotificationCreateIndependent(RoleFixtureJournal.Snapshot state) =>
        state with { Selector = state.Selector with { }, Resources = state.Resources.Select(r => r with { }).ToArray() };

    private void IssueNotificationCreateIndependent(Session session, object capability, NotificationCreateIndependentStage stage,
        RoleFixtureJournal.Snapshot state, params Task[] tasks)
    {
        Require(!disposed && !session.Closed && !session.NotificationCreateIndependentInvalid &&
            session.NotificationCreateIndependentTokens.All(t => !t.IsCancellationRequested));
        var preimage = FreezeNotificationCreateIndependent(state);
        string id = session.NotificationPlan!.ResourceId;
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            {
                SelectedAttempted = true,
                InvocationTerminated = stage is NotificationCreateIndependentStage.StartDrain or NotificationCreateIndependentStage.Complete,
                ActiveDispatch = stage == NotificationCreateIndependentStage.Complete ? Guid.Empty : session.Dispatch
            } : r).ToArray()
        };
        Require(notificationCreateIndependentFacts.TryAdd(capability, new(preimage, postimage, id, session.Dispatch, stage,
            session.NotificationCreateIndependentTokens.ToArray(), tasks.ToArray())));
        session.NotificationCreateIndependentCapabilities.Add(capability);
    }
    private void RevokeNotificationCreateIndependent(Session session)
    {
        session.NotificationCreateIndependentInvalid = true;
        foreach (var capability in session.NotificationCreateIndependentCapabilities)
            notificationCreateIndependentFacts.TryRemove(capability, out _);
    }

    private sealed record StatusNotificationCreateIndependentReadSlot(NotificationFixtureProvisioner Source,
        NotificationFixtureProvisioner.Plan Child, VaultFixtureProvisioner.Plan Parent, C.Binding Binding,
        Guid Subscription, DateTimeOffset ArmedAt, bool Baseline, Guid Nonce)
    {
        public override string ToString() => "[StatusNotificationCreateIndependentReadSlot]";
    }
    private sealed record StatusNotificationCreateIndependentBaseline(StatusNotificationCreateIndependentReadSlot Slot,
        Task<NotificationFixtureProvisioner.Result> Task, NotificationFixtureProvisioner.StatusNotificationCreateIndependentReadProof Proof,
        IReadOnlyList<RoleFixtureJournal.Resource> Rows, NotificationConfiguration Configuration, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusNotificationCreateIndependentBaseline]";
    }
    private sealed record StatusNotificationCreateIndependentObservation(StatusNotificationCreateIndependentBaseline Baseline,
        StatusNotificationCreateIndependentReadSlot Slot, Task<NotificationFixtureProvisioner.Result> Task,
        NotificationFixtureProvisioner.StatusNotificationCreateIndependentReadProof Proof, NotificationConfiguration Configuration,
        C.StatusNotificationCreateIndependentStartProof Start, C.StatusTarget Target, S.Window StatusWindow,
        Task<S.Measurement> StatusTask, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[StatusNotificationCreateIndependentObservation]";
    }

    internal static ManagementOperationFixtureObserverService ForStatusNotificationCreateIndependent(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, S.Authority statusReader, R.Authority resourceReader,
        HttpPipelineTransport selectedBackend, S.Limits statusLimits, R.Limits resourceLimits, Limits limits,
        TimeProvider time, NotificationSource notificationSource)
    {
        Require(notificationSource is { HttpsWebhookReady: true, Baseline: not null, ExclusiveCreation: null });
        var configuration = provisioner.StatusNotificationCreateIndependentConfiguration(scope, statusReader, resourceReader, selectedBackend);
        return new(origin, owner, observerIdentity, capability, scope, provisioner, statusReader, resourceReader,
            selectedBackend, statusLimits, resourceLimits, limits, time, notificationSource)
        { statusNotificationCreateIndependentProfile = true, statusNotificationCreateIndependentConfiguration = configuration };
    }
    internal static ManagementOperationFixtureObserverService ForStatusNotificationCreateIndependentCleanup(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, NotificationSource notificationSource, Limits limits, TimeProvider? time = null) =>
        new(origin, owner, observerIdentity, capability, scope, provisioner, notificationSource, limits, time, notificationCreateIndependent: true);

    private ManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, VaultFixtureProvisioner.HostScope scope, VaultFixtureProvisioner provisioner,
        NotificationSource notification, Limits limits, TimeProvider? time, bool notificationCreateIndependent = false)
        : this(origin, owner, observerIdentity, capability, scope, provisioner, limits, time)
    {
        Require(notification is
        {
            Setup.Credential: not null, Setup.Transport: not null,
            Observer.Credential: not null, Observer.Transport: not null, Limits: not null, ExclusiveCreation: null
        } &&
            !ReferenceEquals(notification.Setup.Credential, notification.Observer.Credential) &&
            !ReferenceEquals(notification.Setup.Transport, notification.Observer.Transport));
        notificationSource = notification with { Baseline = null };
        profile = Profile.StatusFamily;
        if (notificationCreateIndependent)
            statusNotificationCreateIndependentProfile = statusNotificationCreateIndependentCleanup = true;
        else statusNotificationUpdateIndependentProfile = statusNotificationUpdateIndependentCleanup = true;
    }

    private readonly NotificationSource? notificationSource;
    private readonly PrivateConnectionSource? privateConnectionSource;
    private readonly bool statusPrivateReaderSeparated;
    private bool statusSucceededDeleteVaultProfile, statusSucceededDeleteVaultCleanup;
    private bool statusSucceededDeleteVaultCancellationProfile { get; init; }
    private bool statusSucceededDeleteVaultCancellationCleanup { get; init; }
    private VaultAdministrationEffects.Configuration? statusSucceededCancellationConfiguration;
    private bool statusSucceededDeleteVaultIndependentProfile { get; init; }
    private bool statusSucceededDeleteVaultIndependentCleanup { get; init; }
    private bool statusPrivateDeleteIndependentProfile, statusPrivateDeleteIndependentCleanup;
    private VaultAdministrationEffects.Configuration? statusSucceededConfiguration;
    private sealed record StatusSucceededBaseline(VaultFixtureProvisioner.Plan Plan, long Revision,
        IReadOnlyList<RoleFixtureJournal.Resource> Rows, VaultAdministrationEffects.Configuration Configuration,
        C.Binding Binding, C.Binding DeletedBinding,
        R.Window ActiveWindow, R.Window DeletedWindow, Task<R.Measurement> ActiveTask, Task<R.Measurement> DeletedTask,
        R.StatusSucceededDeleteVaultReadProof Active, R.StatusSucceededDeleteVaultReadProof Deleted,
        string Digest, CancellationToken Cancellation);
    private sealed record StatusSucceededObservation(StatusSucceededBaseline Baseline, Guid Dispatch, long Revision,
        C.StatusSucceededDeleteVaultStartProof Start, S.Window StatusWindow, Task<S.Measurement> StatusTask,
        R.Window ActiveWindow, R.Window DeletedWindow, Task<R.Measurement> ActiveTask, Task<R.Measurement> DeletedTask,
        R.StatusSucceededDeleteVaultReadProof Active, R.StatusSucceededDeleteVaultReadProof Deleted,
        CancellationToken Cancellation, CancellationToken StartCancellation);
    private sealed record StatusSucceededCompletion(StatusSucceededObservation Observation, long Revision,
        C.Window Window, VaultAdministration Client, VaultScope Scope, ManagementReceipt Receipt, Task StartTask,
        ManagementOperation Handle, Task StatusTask, C.StatusSucceededDeleteVaultCompletionProof Proof,
        CancellationToken Cancellation, CancellationToken CallerCancellation);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultAdmission, StatusSucceededBaseline>
        statusSucceededAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultReadAdmission, StatusSucceededObservation>
        statusSucceededReadAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultSettlement, StatusSucceededCompletion>
        statusSucceededSettlements = new(ReferenceEqualityComparer.Instance);

    internal sealed class StatusSucceededDeleteVaultAdmission(ManagementOperationFixtureObserverService source)
    {
        internal string BaselineSha256 => source.statusSucceededAdmissions.TryGetValue(this, out var b) ? b.Digest : "";
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededAdmissions.TryGetValue(this, out var b) && ReferenceEquals(journal, source.provisioner.Journal) &&
            !b.Cancellation.IsCancellationRequested && snapshot.Revision == b.Revision &&
            StatusSucceededRoot(b, snapshot) && b.Rows.SequenceEqual(snapshot.Resources);
        public override string ToString() => "[StatusSucceededDeleteVaultAdmission]";
    }
    internal sealed class StatusSucceededDeleteVaultReadAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededReadAdmissions.TryGetValue(this, out var o) && ReferenceEquals(journal, source.provisioner.Journal) &&
            !o.Cancellation.IsCancellationRequested && !o.StartCancellation.IsCancellationRequested &&
            snapshot.Revision == o.Revision &&
            StatusSucceededSelectedRoot(o, snapshot, terminated: true);
        public override string ToString() => "[StatusSucceededDeleteVaultReadAdmission]";
    }
    internal sealed class StatusSucceededDeleteVaultSettlement(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededSettlements.TryGetValue(this, out var c) && ReferenceEquals(journal, source.provisioner.Journal) &&
            !c.Cancellation.IsCancellationRequested && !c.CallerCancellation.IsCancellationRequested &&
            !c.Observation.Cancellation.IsCancellationRequested && !c.Observation.StartCancellation.IsCancellationRequested &&
            snapshot.Revision == c.Revision &&
            StatusSucceededSelectedRoot(c.Observation, snapshot, terminated: false);
        public override string ToString() => "[StatusSucceededDeleteVaultSettlement]";
    }
    private static bool StatusSucceededRoot(StatusSucceededBaseline b, RoleFixtureJournal.Snapshot snapshot) =>
        RoleFixtureJournal.StatusSucceededDeleteVaultRoot(snapshot) && !snapshot.Closing &&
        snapshot.Owner == b.Plan.Owner && snapshot.Selector == b.Plan.Selector && snapshot.LeaseId == b.Plan.LeaseId &&
        snapshot.StatusSucceededDeleteVault!.VaultId == b.Plan.VaultId &&
        snapshot.StatusSucceededDeleteVault.DeletedId == b.Plan.DeletedId &&
        VaultAdministrationEffects.SameConfiguration(snapshot.StatusSucceededDeleteVault.Baseline, b.Configuration) &&
        b.Plan.Manifest.Count == snapshot.Resources.Length && b.Plan.Manifest.All(m =>
            snapshot.Resources.Count(r => r.Id == m.Id && r.Borrowed == m.Borrowed && r.CleanupOnly == m.CleanupOnly) == 1);
    private static bool StatusSucceededSelectedRoot(StatusSucceededObservation o, RoleFixtureJournal.Snapshot snapshot,
        bool terminated) =>
        StatusSucceededRoot(o.Baseline, snapshot) && snapshot.StatusSucceededDeleteVault!.InvocationDispatch == o.Dispatch &&
        snapshot.StatusSucceededDeleteVault.SettledDispatch == Guid.Empty &&
        snapshot.StatusSucceededDeleteVault.BaselineSha256 == o.Baseline.Digest &&
        snapshot.Resources.Single(r => r.Id == o.Baseline.Plan.VaultId) is
        { CreateAttempted: true, SelectedAttempted: true, DeleteAttempted: false, Absent: false, ActiveDispatch: var dispatch } row &&
        dispatch == o.Dispatch && row.InvocationTerminated == terminated &&
        snapshot.Resources.Where(r => r.Id != o.Baseline.Plan.VaultId)
            .SequenceEqual(o.Baseline.Rows.Where(r => r.Id != o.Baseline.Plan.VaultId));
    private VaultAdministrationEffects.Configuration? statusSucceededIndependentConfiguration;
    private sealed record StatusSucceededCancellationBaseline(Session Session, VaultFixtureProvisioner.Plan Plan,
        RoleFixtureJournal.Snapshot Ready, C.Binding Binding, C.Binding DeletedBinding,
        R.Window ActiveWindow, R.Window DeletedWindow, Task<R.Measurement> ActiveTask, Task<R.Measurement> DeletedTask,
        R.StatusSucceededDeleteVaultCancellationReadProof Active, R.StatusSucceededDeleteVaultCancellationReadProof Deleted,
        string Digest, CancellationToken Cancellation, CancellationToken RequestCancellation);
    private sealed record StatusSucceededCancellationObservation(StatusSucceededCancellationBaseline Baseline,
        RoleFixtureJournal.Snapshot Drained, C.StatusSucceededDeleteVaultCancellationStartProof Start,
        S.Window StatusWindow, Task<S.Measurement> StatusTask, R.Window ActiveWindow, R.Window DeletedWindow,
        Task<R.Measurement> ActiveTask, Task<R.Measurement> DeletedTask,
        R.StatusSucceededDeleteVaultCancellationReadProof Active, R.StatusSucceededDeleteVaultCancellationReadProof Deleted,
        CancellationToken Cancellation, CancellationToken StartCancellation, CancellationToken RequestCancellation);
    private sealed record StatusSucceededCancellationCanceled(StatusSucceededCancellationObservation Observation,
        RoleFixtureJournal.Snapshot Admitted, C.Window Window, VaultAdministration Client, VaultScope Scope,
        ManagementReceipt Receipt, Task StartTask, ManagementOperation Handle, Task CanceledTask,
        C.StatusSucceededDeleteVaultCancellationCanceledProof Proof, CancellationToken IntentionalCancellation, CancellationToken Veto);
    private sealed record StatusSucceededCancellationCompletion(StatusSucceededCancellationCanceled Canceled,
        RoleFixtureJournal.Snapshot Admitted, Task StatusTask, C.StatusSucceededDeleteVaultCancellationCompletionProof Proof,
        CancellationToken Cancellation, CancellationToken CallerCancellation);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultCancellationAdmission,
        StatusSucceededCancellationBaseline> statusSucceededCancellationAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultCancellationCanceledReadAdmission,
        StatusSucceededCancellationObservation> statusSucceededCancellationCanceledAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultCancellationCanceledDrain,
        StatusSucceededCancellationCanceled> statusSucceededCancellationCanceledDrains = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultCancellationReadAdmission,
        StatusSucceededCancellationCanceled> statusSucceededCancellationReadAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultCancellationSettlement,
        StatusSucceededCancellationCompletion> statusSucceededCancellationSettlements = new(ReferenceEqualityComparer.Instance);

    internal sealed class StatusSucceededDeleteVaultCancellationAdmission(ManagementOperationFixtureObserverService source)
    {
        internal string BaselineSha256 => source.statusSucceededCancellationAdmissions.TryGetValue(this, out var b) ? b.Digest : "";
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededCancellationAdmissions.TryGetValue(this, out var b) &&
            ReferenceEquals(journal, source.provisioner.Journal) && source.StatusSucceededCancellationLive(b) &&
            RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(b.Ready, snapshot);
        public override string ToString() => "[StatusSucceededDeleteVaultCancellationAdmission]";
    }
    internal sealed class StatusSucceededDeleteVaultCancellationCanceledReadAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededCancellationCanceledAdmissions.TryGetValue(this, out var o) &&
            ReferenceEquals(journal, source.provisioner.Journal) && source.StatusSucceededCancellationLive(o) &&
            RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(o.Drained, snapshot);
        public override string ToString() => "[StatusSucceededDeleteVaultCancellationCanceledReadAdmission]";
    }
    internal sealed class StatusSucceededDeleteVaultCancellationCanceledDrain(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededCancellationCanceledDrains.TryGetValue(this, out var c) &&
            ReferenceEquals(journal, source.provisioner.Journal) && source.StatusSucceededCancellationLive(c) &&
            RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(c.Admitted, snapshot);
        public override string ToString() => "[StatusSucceededDeleteVaultCancellationCanceledDrain]";
    }
    internal sealed class StatusSucceededDeleteVaultCancellationReadAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededCancellationReadAdmissions.TryGetValue(this, out var c) &&
            ReferenceEquals(journal, source.provisioner.Journal) && source.StatusSucceededCancellationLive(c) &&
            RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(StatusSucceededCancellationDrainPostimage(c), snapshot);
        public override string ToString() => "[StatusSucceededDeleteVaultCancellationReadAdmission]";
    }
    internal sealed class StatusSucceededDeleteVaultCancellationSettlement(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededCancellationSettlements.TryGetValue(this, out var c) &&
            ReferenceEquals(journal, source.provisioner.Journal) && source.StatusSucceededCancellationLive(c) &&
            RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(c.Admitted, snapshot);
        public override string ToString() => "[StatusSucceededDeleteVaultCancellationSettlement]";
    }
    private bool StatusSucceededCancellationLive(StatusSucceededCancellationBaseline b) =>
        !disposed && !b.Session.Closed && !b.Session.StatusSucceededCancellationInvalid &&
        !lifetime.IsCancellationRequested && !b.Session.Stop.IsCancellationRequested && !b.Cancellation.IsCancellationRequested &&
        !b.RequestCancellation.IsCancellationRequested;
    private bool StatusSucceededCancellationLive(StatusSucceededCancellationObservation o) =>
        StatusSucceededCancellationLive(o.Baseline) && !o.Cancellation.IsCancellationRequested && !o.StartCancellation.IsCancellationRequested &&
        !o.RequestCancellation.IsCancellationRequested;
    private bool StatusSucceededCancellationLive(StatusSucceededCancellationCanceled c) =>
        StatusSucceededCancellationLive(c.Observation) && !c.Veto.IsCancellationRequested && c.IntentionalCancellation.IsCancellationRequested;
    private bool StatusSucceededCancellationLive(StatusSucceededCancellationCompletion c) =>
        StatusSucceededCancellationLive(c.Canceled) && !c.Cancellation.IsCancellationRequested && !c.CallerCancellation.IsCancellationRequested;
    private static RoleFixtureJournal.Snapshot FreezeStatusSucceededCancellationSnapshot(RoleFixtureJournal.Snapshot snapshot) =>
        snapshot with
        {
            Resources = snapshot.Resources.ToArray(),
            StatusSucceededDeleteVault = snapshot.StatusSucceededDeleteVault! with
            { Baseline = snapshot.StatusSucceededDeleteVault.Baseline with { Policies = [] } }
        };
    private static RoleFixtureJournal.Snapshot StatusSucceededCancellationDrainPostimage(StatusSucceededCancellationCanceled canceled) =>
        canceled.Admitted with
        {
            Revision = canceled.Admitted.Revision + 1,
            Resources = canceled.Admitted.Resources.Select(r => r.Id == canceled.Observation.Baseline.Plan.VaultId
                ? r with { InvocationTerminated = true } : r).ToArray()
        };
    private static RoleFixtureJournal.Snapshot StatusSucceededCancellationPostimage(StatusSucceededCancellationCompletion completion) =>
        completion.Admitted with
        {
            Revision = completion.Admitted.Revision + 1,
            Resources = completion.Admitted.Resources.Select(r => r.Id == completion.Canceled.Observation.Baseline.Plan.VaultId
                ? r with { InvocationTerminated = true, ActiveDispatch = Guid.Empty } : r).ToArray(),
            StatusSucceededDeleteVault = completion.Admitted.StatusSucceededDeleteVault! with
            { SettledDispatch = completion.Admitted.StatusSucceededDeleteVault.InvocationDispatch }
        };

    private sealed record StatusSucceededIndependentBaseline(VaultFixtureProvisioner.Plan Plan, long Revision,
        IReadOnlyList<RoleFixtureJournal.Resource> Rows, VaultAdministrationEffects.Configuration Configuration,
        C.Binding Binding, C.Binding DeletedBinding,
        R.Window ActiveWindow, R.Window DeletedWindow, Task<R.Measurement> ActiveTask, Task<R.Measurement> DeletedTask,
        R.StatusSucceededDeleteVaultIndependentReadProof Active, R.StatusSucceededDeleteVaultIndependentReadProof Deleted,
        string Digest, CancellationToken Cancellation);
    private sealed record StatusSucceededIndependentObservation(StatusSucceededIndependentBaseline Baseline, Guid Dispatch, long Revision,
        C.StatusSucceededDeleteVaultIndependentStartProof Start, S.Window StatusWindow, Task<S.Measurement> StatusTask,
        R.Window ActiveWindow, R.Window DeletedWindow, Task<R.Measurement> ActiveTask, Task<R.Measurement> DeletedTask,
        R.StatusSucceededDeleteVaultIndependentReadProof Active, R.StatusSucceededDeleteVaultIndependentReadProof Deleted,
        CancellationToken Cancellation, CancellationToken StartCancellation);
    private sealed record StatusSucceededIndependentCompletion(StatusSucceededIndependentObservation Observation, RoleFixtureJournal.Snapshot Admitted,
        C.Window Window, VaultAdministration Client, VaultScope Scope, ManagementReceipt Receipt, Task StartTask,
        ManagementOperation Handle, Task StatusTask, C.StatusSucceededDeleteVaultIndependentCompletionProof Proof,
        CancellationToken Cancellation, CancellationToken CallerCancellation);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultIndependentAdmission, StatusSucceededIndependentBaseline>
        statusSucceededIndependentAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultIndependentReadAdmission, StatusSucceededIndependentObservation>
        statusSucceededIndependentReadAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultIndependentSettlement, StatusSucceededIndependentCompletion>
        statusSucceededIndependentSettlements = new(ReferenceEqualityComparer.Instance);

    internal sealed class StatusSucceededDeleteVaultIndependentAdmission(ManagementOperationFixtureObserverService source)
    {
        internal string BaselineSha256 => source.statusSucceededIndependentAdmissions.TryGetValue(this, out var b) ? b.Digest : "";
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededIndependentAdmissions.TryGetValue(this, out var b) && ReferenceEquals(journal, source.provisioner.Journal) &&
            !b.Cancellation.IsCancellationRequested && snapshot.Revision == b.Revision &&
            StatusSucceededIndependentRoot(b, snapshot) && b.Rows.SequenceEqual(snapshot.Resources);
        public override string ToString() => "[StatusSucceededDeleteVaultIndependentAdmission]";
    }
    internal sealed class StatusSucceededDeleteVaultIndependentReadAdmission(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededIndependentReadAdmissions.TryGetValue(this, out var o) && ReferenceEquals(journal, source.provisioner.Journal) &&
            !o.Cancellation.IsCancellationRequested && !o.StartCancellation.IsCancellationRequested &&
            snapshot.Revision == o.Revision &&
            StatusSucceededIndependentSelectedRoot(o, snapshot, terminated: true);
        public override string ToString() => "[StatusSucceededDeleteVaultIndependentReadAdmission]";
    }
    internal sealed class StatusSucceededDeleteVaultIndependentSettlement(ManagementOperationFixtureObserverService source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededIndependentSettlements.TryGetValue(this, out var c) && ReferenceEquals(journal, source.provisioner.Journal) &&
            !c.Cancellation.IsCancellationRequested && !c.CallerCancellation.IsCancellationRequested &&
            !c.Observation.Cancellation.IsCancellationRequested && !c.Observation.StartCancellation.IsCancellationRequested &&
            snapshot.Revision == c.Admitted.Revision && c.Admitted.Resources.SequenceEqual(snapshot.Resources) &&
            StatusSucceededIndependentSelectedRoot(c.Observation, snapshot, terminated: false);
        public override string ToString() => "[StatusSucceededDeleteVaultIndependentSettlement]";
    }
    private static bool StatusSucceededIndependentRoot(StatusSucceededIndependentBaseline b, RoleFixtureJournal.Snapshot snapshot) =>
        RoleFixtureJournal.StatusSucceededDeleteVaultIndependentRoot(snapshot) && !snapshot.Closing &&
        snapshot.Owner == b.Plan.Owner && snapshot.Selector == b.Plan.Selector && snapshot.LeaseId == b.Plan.LeaseId &&
        snapshot.StatusSucceededDeleteVault!.VaultId == b.Plan.VaultId &&
        snapshot.StatusSucceededDeleteVault.DeletedId == b.Plan.DeletedId &&
        VaultAdministrationEffects.SameConfiguration(snapshot.StatusSucceededDeleteVault.Baseline, b.Configuration) &&
        b.Plan.Manifest.Count == snapshot.Resources.Length && b.Plan.Manifest.All(m =>
            snapshot.Resources.Count(r => r.Id == m.Id && r.Borrowed == m.Borrowed && r.CleanupOnly == m.CleanupOnly) == 1);
    private static bool StatusSucceededIndependentSelectedRoot(StatusSucceededIndependentObservation o, RoleFixtureJournal.Snapshot snapshot,
        bool terminated) =>
        StatusSucceededIndependentRoot(o.Baseline, snapshot) && snapshot.StatusSucceededDeleteVault!.InvocationDispatch == o.Dispatch &&
        snapshot.StatusSucceededDeleteVault.SettledDispatch == Guid.Empty &&
        snapshot.StatusSucceededDeleteVault.BaselineSha256 == o.Baseline.Digest &&
        snapshot.Resources.Single(r => r.Id == o.Baseline.Plan.VaultId) is
        { CreateAttempted: true, SelectedAttempted: true, DeleteAttempted: false, Absent: false, ActiveDispatch: var dispatch } row &&
        dispatch == o.Dispatch && row.InvocationTerminated == terminated &&
        snapshot.Resources.Where(r => r.Id != o.Baseline.Plan.VaultId)
            .SequenceEqual(o.Baseline.Rows.Where(r => r.Id != o.Baseline.Plan.VaultId));
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Session, PrivateApprovalBaseline>
        privateBaselines = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Session, PrivateApprovalPost>
        privatePosts = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<PrivateConnectionApprovalAdmission, PrivateApprovalBaseline>
        privateAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<PrivateConnectionApprovalSettlement, PrivateApprovalCompletion>
        privateSettlements = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPrivateConnectionUpdateCancellationAdmission,
        StatusPrivateBaseline> statusPrivateAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPrivateConnectionUpdateCancellationSettlement,
        StatusPrivateCompletion> statusPrivateSettlements = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPrivateConnectionDeleteCancellationAdmission,
        StatusPrivateDeleteBaseline> statusPrivateDeleteAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPrivateConnectionDeleteCancellationSettlement,
        StatusPrivateDeleteCompletion> statusPrivateDeleteSettlements = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPrivateConnectionDeleteSelectedAdmission,
        StatusPrivateDeleteSelectedBaseline> statusPrivateDeleteSelectedAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPrivateConnectionDeleteSelectedSettlement,
        StatusPrivateDeleteSelectedCompletion> statusPrivateDeleteSelectedSettlements = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPrivateConnectionDeleteIndependentAdmission,
        StatusPrivateDeleteIndependentBaseline> statusPrivateDeleteIndependentAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPrivateConnectionDeleteIndependentSettlement,
        StatusPrivateDeleteIndependentCompletion> statusPrivateDeleteIndependentSettlements = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPrivateConnectionDeleteIndependentReadAdmission,
        StatusPrivateDeleteIndependentObservation> statusPrivateDeleteIndependentReadAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Guid, Session> sessions = [];
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusVaultDeleteCancellationSettlement,
        StatusVaultDeleteCancellationCompletion> statusDeleteSettlements = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusVaultPurgeCancellationSettlement,
        StatusVaultPurgeCancellationCompletion> statusPurgeSettlements = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusVaultRecoverCancellationSettlement,
        StatusVaultRecoverCancellationCompletion> statusRecoverSettlements = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusVaultUpdateCancellationSettlement,
        StatusVaultUpdateCancellationCompletion> statusUpdateSettlements = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusNotificationDeleteCancellationSettlement,
        StatusNotificationDeleteCancellationCompletion> statusNotificationDeleteSettlements = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusNotificationDeleteIndependentAdmission,
        StatusNotificationDeleteIndependentBaseline> statusNotificationDeleteIndependentAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusNotificationDeleteIndependentReadAdmission,
        StatusNotificationDeleteIndependentObservation> statusNotificationDeleteIndependentReadAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusNotificationDeleteIndependentSettlement,
        StatusNotificationDeleteIndependentCompletion> statusNotificationDeleteIndependentSettlements = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusNotificationUpdateCancellationAdmission,
        StatusNotificationUpdateBaseline> statusNotificationUpdateAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusNotificationUpdateCancellationSettlement,
        StatusNotificationUpdateCompletion> statusNotificationUpdateSettlements = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusNotificationCreateCancellationAdmission,
        StatusNotificationCreateBaseline> statusNotificationCreateAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusNotificationCreateCancellationSettlement,
        StatusNotificationCreateCompletion> statusNotificationCreateSettlements = new(ReferenceEqualityComparer.Instance);
    private readonly CancellationTokenSource lifetime = new();
    private readonly TaskCompletionSource drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TaskCompletionSource? disposal;
    private volatile bool disposed;
    private int active;

    private sealed class Session(FixtureSelector selector)
    {
        internal PendingSession? Pending;
        internal PrivateUpdateIndependentRead? PrivateUpdateIndependentBaseline, PrivateUpdateIndependentObservation;
        internal RoleFixtureJournal.Snapshot? PrivateUpdateIndependentReady, PrivateUpdateIndependentBegin, PrivateUpdateIndependentDrained, PrivateUpdateIndependentRead;
        internal StatusPrivateConnectionUpdateIndependentStartDrain? PrivateUpdateIndependentStartDrain;
        internal StatusPrivateConnectionUpdateIndependentSettlement? PrivateUpdateIndependentSettlement;
        internal readonly List<object> PrivateUpdateIndependentCapabilities = [];
        internal readonly List<CancellationToken> PrivateUpdateIndependentTokens = [];
        internal bool PrivateUpdateIndependentInvalid;
        internal readonly FixtureSelector Selector = selector;
        internal readonly CancellationTokenSource Stop = new();
        internal VaultFixtureProvisioner.Plan? Plan;
        internal NotificationFixtureProvisioner? Notifications;
        internal NotificationFixtureProvisioner.Plan? NotificationPlan;
        internal PrivateEndpointFixtureProvisioner? Endpoints;
        internal PrivateEndpointFixtureProvisioner.Plan? EndpointPlan;
        internal string? ConnectionId;
        internal PrivateConnectionApprovalAdmission? PrivateAdmission;
        internal PrivateConnectionApprovalSettlement? PrivateSettlement;
        internal C.PrivateApprovalResponseProof? ApprovalProof;
        internal PrivateConnectionScope? ActualPrivateScope;
        internal bool ApprovalSettlementAttempted;
        internal StatusPrivateBaseline? StatusPrivateBaseline;
        internal StatusPrivateObservation? StatusPrivateObservation;
        internal StatusPrivateConnectionUpdateCancellationSettlement? StatusPrivateSettlement;
        internal Task<R.Measurement>? StatusPrivateBeforeTask, StatusPrivateAfterTask;
        internal StatusPrivateDeleteBaseline? StatusPrivateDeleteBaseline;
        internal StatusPrivateDeleteObservation? StatusPrivateDeleteObservation;
        internal StatusPrivateConnectionDeleteCancellationSettlement? StatusPrivateDeleteSettlement;
        internal Task<PrivateEndpointResourceCollector.Measurement>? StatusPrivateDeleteEndpointBefore, StatusPrivateDeleteEndpointAfter;
        internal bool StatusPrivateDeleteInvalid;
        internal Task<R.Measurement>? StatusPrivateSelectedBeforeTask, StatusPrivateSelectedAfterTask;
        internal StatusPrivateDeleteSelectedBaseline? StatusPrivateDeleteSelectedBaseline;
        internal StatusPrivateDeleteSelectedObservation? StatusPrivateDeleteSelectedObservation;
        internal StatusPrivateConnectionDeleteSelectedSettlement? StatusPrivateDeleteSelectedSettlement;
        internal Task<PrivateEndpointResourceCollector.Measurement>? StatusPrivateDeleteSelectedEndpointBefore, StatusPrivateDeleteSelectedEndpointAfter;
        internal bool StatusPrivateDeleteSelectedInvalid;
        internal Task<R.Measurement>? StatusPrivateIndependentBeforeTask, StatusPrivateIndependentAfterTask;
        internal StatusPrivateDeleteIndependentBaseline? StatusPrivateDeleteIndependentBaseline;
        internal StatusPrivateDeleteIndependentObservation? StatusPrivateDeleteIndependentObservation;
        internal StatusPrivateConnectionDeleteIndependentSettlement? StatusPrivateDeleteIndependentSettlement;
        internal Task<PrivateEndpointResourceCollector.Measurement>? StatusPrivateDeleteIndependentEndpointBefore, StatusPrivateDeleteIndependentEndpointAfter;
        internal bool StatusPrivateDeleteIndependentInvalid;
        internal readonly TaskCompletionSource PrivateDrained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal E.Lease? Lease;
        internal E.Prepare? Preparation;
        internal C.Binding? Binding;
        internal C.Binding? CounterpartBinding;
        internal C.Window? Capture;
        internal R.Window? Before, After;
        internal R.Window? CounterpartBefore, CounterpartAfter;
        internal StatusVaultDeleteCancellationBaseline? StatusDeleteBaseline;
        internal StatusVaultDeleteCancellationObservation? StatusDeleteObservation;
        internal StatusSucceededBaseline? StatusSucceededBaseline;
        internal StatusSucceededObservation? StatusSucceededObservation;
        internal CancellationToken StatusSucceededStartCancellation;
        internal StatusSucceededCancellationBaseline? StatusSucceededCancellationBaseline;
        internal StatusSucceededCancellationObservation? StatusSucceededCancellationObservation;
        internal RoleFixtureJournal.Snapshot? StatusSucceededCancellationBegin, StatusSucceededCancellationStartDrain,
            StatusSucceededCancellationCanceledCommitted;
        internal CancellationToken StatusSucceededCancellationStartCancellation;
        internal StatusSucceededDeleteVaultCancellationCanceledDrain? StatusSucceededCancellationCanceledDrain;
        internal StatusSucceededDeleteVaultCancellationSettlement? StatusSucceededCancellationSettlement;
        internal volatile bool StatusSucceededCancellationInvalid;
        internal StatusSucceededIndependentBaseline? StatusSucceededIndependentBaseline;
        internal StatusSucceededIndependentObservation? StatusSucceededIndependentObservation;
        internal CancellationToken StatusSucceededIndependentStartCancellation;
        internal StatusSucceededDeleteVaultIndependentSettlement? StatusSucceededIndependentSettlement;
        internal StatusVaultPurgeCancellationBaseline? StatusPurgeBaseline;
        internal StatusVaultPurgeCancellationObservation? StatusPurgeObservation;
        internal VaultAdministrationEffects.Configuration? StatusRecoverConfiguration;
        internal StatusVaultRecoverCancellationBaseline? StatusRecoverBaseline;
        internal StatusVaultRecoverCancellationObservation? StatusRecoverObservation;
        internal VaultAdministrationEffects.Configuration? StatusUpdateConfiguration;
        internal StatusVaultUpdateCancellationBaseline? StatusUpdateBaseline;
        internal StatusVaultUpdateCancellationObservation? StatusUpdateObservation;
        internal StatusNotificationDeleteReadSlot? StatusNotificationBefore, StatusNotificationAfter;
        internal StatusNotificationDeleteCancellationBaseline? StatusNotificationBaseline;
        internal StatusNotificationDeleteCancellationObservation? StatusNotificationObservation;
        internal StatusNotificationDeleteIndependentReadSlot? StatusNotificationIndependentBefore, StatusNotificationIndependentAfter;
        internal StatusNotificationDeleteIndependentBaseline? StatusNotificationIndependentBaseline;
        internal StatusNotificationDeleteIndependentObservation? StatusNotificationIndependentObservation;
        internal StatusNotificationUpdateBaseline? StatusNotificationUpdateBaseline;
        internal StatusNotificationUpdateObservation? StatusNotificationUpdateObservation;
        internal StatusNotificationCreateBaseline? StatusNotificationCreateBaseline;
        internal StatusNotificationCreateObservation? StatusNotificationCreateObservation;
        internal StatusNotificationUpdateIndependentReadSlot? NotificationUpdateIndependentBefore, NotificationUpdateIndependentAfter;
        internal StatusNotificationUpdateIndependentBaseline? NotificationUpdateIndependentBaseline;
        internal StatusNotificationUpdateIndependentObservation? NotificationUpdateIndependentObservation;
        internal RoleFixtureJournal.Snapshot? NotificationUpdateIndependentReady, NotificationUpdateIndependentBegin,
            NotificationUpdateIndependentDrained, NotificationUpdateIndependentRead;
        internal StatusNotificationUpdateIndependentStartDrain? NotificationUpdateIndependentStartDrain;
        internal StatusNotificationUpdateIndependentSettlement? NotificationUpdateIndependentSettlement;
        internal readonly List<object> NotificationUpdateIndependentCapabilities = [];
        internal readonly List<CancellationToken> NotificationUpdateIndependentTokens = [];
        internal bool NotificationUpdateIndependentInvalid;
        internal StatusNotificationCreateIndependentReadSlot? NotificationCreateIndependentBefore, NotificationCreateIndependentAfter;
        internal StatusNotificationCreateIndependentBaseline? NotificationCreateIndependentBaseline;
        internal StatusNotificationCreateIndependentObservation? NotificationCreateIndependentObservation;
        internal RoleFixtureJournal.Snapshot? NotificationCreateIndependentReady, NotificationCreateIndependentBegin,
            NotificationCreateIndependentDrained, NotificationCreateIndependentRead;
        internal StatusNotificationCreateIndependentStartDrain? NotificationCreateIndependentStartDrain;
        internal StatusNotificationCreateIndependentSettlement? NotificationCreateIndependentSettlement;
        internal readonly List<object> NotificationCreateIndependentCapabilities = [];
        internal readonly List<CancellationToken> NotificationCreateIndependentTokens = [];
        internal bool NotificationCreateIndependentInvalid;
        internal C.StatusTarget? Target;
        internal C.SynchronousDeleteProof? DeleteProof;
        internal VaultAdministration? Client;
        internal NotificationScope? ActualNotificationScope;
        internal VaultScope? ActualVaultScope;
        internal DeletedVaultScope? ActualDeletedVaultScope;
        internal ManagementReceipt? Receipt;
        internal ManagementOperation? Handle;
        internal Task? StartTask, StatusTask;
        internal Task? CanceledTask;
        internal bool CancelClaimed, CancelFinished;
        internal Guid Subscription, Dispatch;
        internal DateTimeOffset ArmedAt, BaselineAt, StartedAt, IndependentAt;
        internal volatile bool Closed;
        internal bool ArmClaimed, Armed, BaselineClaimed, BaselineReady;
        internal bool StartClaimed, StartFinished, StartSucceeded, AfterClaimed, IndependentReady, StatusClaimed;
        internal bool StatusSucceeded, Releasing;
        internal int Active;
    }

    internal ManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, VaultFixtureProvisioner.HostScope scope, VaultFixtureProvisioner provisioner,
        S.Authority statusReader, R.Authority resourceReader, HttpPipelineTransport selectedBackend,
        S.Limits statusLimits, R.Limits resourceLimits, Limits limits, TimeProvider time,
        NotificationSource? notificationSource = null, PrivateConnectionSource? privateConnectionSource = null)
    {
        Require(origin is
        {
            IsAbsoluteUri: true, Scheme: "https", AbsolutePath: "/",
            UserInfo.Length: 0, Query.Length: 0, Fragment.Length: 0
        } && Text(owner, 128) && Text(observerIdentity, 128) && capability is not null &&
            scope is not null && scope.ExclusiveFixtureNamespace && scope.AllowPurge &&
            scope.SubscriptionId != Guid.Empty && scope.TenantId != Guid.Empty &&
            Segment(scope.ResourceGroup, 90) && Segment(scope.Location, 50) &&
            provisioner is not null && provisioner.Host == scope &&
            statusReader is not null && resourceReader is not null &&
            selectedBackend is not null && limits is not null && time is not null &&
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
        this.time = time;
        nativeCapture = new(selectedBackend, limits.MaximumReplyBytes);
        statusCollector = new(capture, statusReader, statusLimits, time);
        beforeCollector = new(resourceReader, resourceLimits, time, scope.TenantId);
        afterCollector = new(resourceReader, resourceLimits, time, scope.TenantId);
        statusPrivateReaderSeparated = privateConnectionSource?.EndpointSetup is { } privateSetup &&
            !ReferenceEquals(resourceReader.Credential, privateSetup.Credential) &&
            !ReferenceEquals(resourceReader.Transport, privateSetup.Transport) &&
            resourceReader.Label != privateSetup.Label;
        statusCounterpartBeforeCollector = new(resourceReader, resourceLimits, time, scope.TenantId);
        statusCounterpartAfterCollector = new(resourceReader, resourceLimits, time, scope.TenantId);
        if (notificationSource is not null)
        {
            Require(notificationSource.Setup is { Credential: not null, Transport: not null } &&
                notificationSource.Observer is { Credential: not null, Transport: not null } &&
                notificationSource.Limits is not null &&
                !ReferenceEquals(notificationSource.Setup.Credential, notificationSource.Observer.Credential) &&
                !ReferenceEquals(notificationSource.Setup.Transport, notificationSource.Observer.Transport) &&
                !ReferenceEquals(notificationSource.Setup.Transport, selectedBackend) &&
                !ReferenceEquals(notificationSource.Observer.Transport, selectedBackend) &&
                !ReferenceEquals(statusReader.Transport, selectedBackend));
            this.notificationSource = notificationSource with
            {
                Baseline = notificationSource.Baseline is { } baseline
                    ? new(baseline.Endpoint.Reveal(), baseline.EventTypes, baseline.DeliveryAttributes) : null
            };
        }
        if (privateConnectionSource is not null)
        {
            Require(Text(privateConnectionSource.BorrowedSubnetId, 2048) &&
                privateConnectionSource.EndpointSetup is { Credential: not null, Transport: not null } &&
                privateConnectionSource.EndpointReader is { Credential: not null, Transport: not null } &&
                privateConnectionSource.VaultConnectionReader is { Credential: not null, Transport: not null } &&
                privateConnectionSource.ResourceLimits is not null && privateConnectionSource.InventoryLimits is not null &&
                !ReferenceEquals(privateConnectionSource.EndpointSetup.Transport, selectedBackend) &&
                !ReferenceEquals(privateConnectionSource.EndpointReader.Transport, selectedBackend) &&
                !ReferenceEquals(privateConnectionSource.VaultConnectionReader.Transport, selectedBackend) &&
                !ReferenceEquals(resourceReader.Transport, selectedBackend));
            // Validates the explicit source contracts without provider work.
            _ = new PrivateEndpointFixtureProvisioner(provisioner, privateConnectionSource.EndpointSetup,
                privateConnectionSource.EndpointReader, privateConnectionSource.VaultConnectionReader,
                privateConnectionSource.ResourceLimits, privateConnectionSource.InventoryLimits, time);
            this.privateConnectionSource = privateConnectionSource;
        }
    }

    internal HttpPipelineTransport SelectedTransport => capture.SelectedTransport;

    internal static ManagementOperationFixtureObserverService ForStatusPrivateConnectionDeleteIndependent(Uri origin,
        string owner, string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, S.Authority statusReader, R.Authority resourceReader,
        HttpPipelineTransport selectedBackend, S.Limits statusLimits, R.Limits resourceLimits, Limits limits,
        TimeProvider time, PrivateConnectionSource privateConnectionSource)
    {
        Require(privateConnectionSource is not null);
        return new(origin, owner, observerIdentity, capability, scope, provisioner, statusReader, resourceReader,
            selectedBackend, statusLimits, resourceLimits, limits, time, privateConnectionSource: privateConnectionSource)
        { statusPrivateDeleteIndependentProfile = true };
    }

    internal static ManagementOperationFixtureObserverService ForStatusPrivateConnectionDeleteIndependentCleanup(Uri origin,
        string owner, string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, PrivateConnectionSource endpoint, Limits limits, TimeProvider? time = null) =>
        new(origin, owner, observerIdentity, capability, scope, provisioner, endpoint, limits, time, independent: true);

    private ManagementOperationFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, VaultFixtureProvisioner.HostScope scope, VaultFixtureProvisioner provisioner,
        PrivateConnectionSource endpoint, Limits limits, TimeProvider? time, bool independent, bool independentUpdate = false)
        : this(origin, owner, observerIdentity, capability, scope, provisioner, limits, time)
    {
        Require(independent && endpoint is not null && Text(endpoint.BorrowedSubnetId, 2048));
        _ = new PrivateEndpointFixtureProvisioner(provisioner, endpoint.EndpointSetup, endpoint.EndpointReader,
            endpoint.VaultConnectionReader, endpoint.ResourceLimits, endpoint.InventoryLimits, this.time);
        privateConnectionSource = endpoint;
        profile = Profile.StatusFamily;
        if (independentUpdate) statusPrivateUpdateIndependentProfile = statusPrivateUpdateIndependentCleanup = true;
        else statusPrivateDeleteIndependentProfile = statusPrivateDeleteIndependentCleanup = true;
    }



    internal static ManagementOperationFixtureObserverService ForStatusSucceededDeleteVault(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, S.Authority statusReader, R.Authority resourceReader,
        HttpPipelineTransport selectedBackend, S.Limits statusLimits, R.Limits resourceLimits, Limits limits, TimeProvider time)
    {
        var configuration = provisioner.StatusSucceededDeleteVaultConfiguration(scope, statusReader, resourceReader, selectedBackend);
        return new(origin, owner, observerIdentity, capability, scope, provisioner, statusReader, resourceReader,
            selectedBackend, statusLimits, resourceLimits, limits, time)
        {
            statusSucceededDeleteVaultProfile = true,
            statusSucceededConfiguration = configuration
        };
    }

    internal static ManagementOperationFixtureObserverService ForStatusSucceededDeleteVaultCleanup(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, Limits limits, TimeProvider? time = null) =>
        new(origin, owner, observerIdentity, capability, scope, provisioner, limits, time)
        { statusSucceededDeleteVaultProfile = true, statusSucceededDeleteVaultCleanup = true };

    internal static ManagementOperationFixtureObserverService ForStatusSucceededDeleteVaultIndependent(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, S.Authority statusReader, R.Authority resourceReader,
        HttpPipelineTransport selectedBackend, S.Limits statusLimits, R.Limits resourceLimits, Limits limits, TimeProvider time)
    {
        var configuration = provisioner.StatusSucceededDeleteVaultIndependentConfiguration(scope, statusReader, resourceReader, selectedBackend);
        return new(origin, owner, observerIdentity, capability, scope, provisioner, statusReader, resourceReader,
            selectedBackend, statusLimits, resourceLimits, limits, time)
        {
            statusSucceededDeleteVaultIndependentProfile = true,
            statusSucceededIndependentConfiguration = configuration
        };
    }

    internal static ManagementOperationFixtureObserverService ForStatusSucceededDeleteVaultIndependentCleanup(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, Limits limits, TimeProvider? time = null) =>
        new(origin, owner, observerIdentity, capability, scope, provisioner, limits, time)
        { statusSucceededDeleteVaultIndependentProfile = true, statusSucceededDeleteVaultIndependentCleanup = true };

    internal static ManagementOperationFixtureObserverService ForStatusSucceededDeleteVaultCancellation(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, S.Authority statusReader, R.Authority resourceReader,
        HttpPipelineTransport selectedBackend, S.Limits statusLimits, R.Limits resourceLimits, Limits limits, TimeProvider time)
    {
        var configuration = provisioner.StatusSucceededDeleteVaultCancellationConfiguration(scope, statusReader, resourceReader, selectedBackend);
        return new(origin, owner, observerIdentity, capability, scope, provisioner, statusReader, resourceReader,
            selectedBackend, statusLimits, resourceLimits, limits, time)
        {
            statusSucceededDeleteVaultCancellationProfile = true,
            statusSucceededCancellationConfiguration = configuration
        };
    }

    internal static ManagementOperationFixtureObserverService ForStatusSucceededDeleteVaultCancellationCleanup(Uri origin, string owner,
        string observerIdentity, SecretMaterial capability, VaultFixtureProvisioner.HostScope scope,
        VaultFixtureProvisioner provisioner, Limits limits, TimeProvider? time = null) =>
        new(origin, owner, observerIdentity, capability, scope, provisioner, limits, time)
        { statusSucceededDeleteVaultCancellationProfile = true, statusSucceededDeleteVaultCancellationCleanup = true };

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
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, deadline.Token);
            using var body = await ReadBody(request, linked.Token).ConfigureAwait(false);
            if (PendingProfile)
                return await DispatchPendingPurge(uri.AbsolutePath, body.RootElement, linked.Token, cancellationToken).ConfigureAwait(false);
            if (statusNotificationUpdateIndependentCleanup || statusNotificationCreateIndependentCleanup)
                return uri.AbsolutePath == "/operation/release"
                    ? await Release(body.RootElement.Deserialize<FixtureSelector>(Json) ?? throw Failure(),
                        linked.Token, cancellationToken).ConfigureAwait(false)
                    : Error(HttpStatusCode.NotFound);
            if (statusPrivateUpdateIndependentCleanup)
                return uri.AbsolutePath == "/operation/release"
                    ? await Release(body.RootElement.Deserialize<FixtureSelector>(Json) ?? throw Failure(), linked.Token, cancellationToken).ConfigureAwait(false)
                    : Error(HttpStatusCode.NotFound);
            if (statusPrivateDeleteIndependentCleanup)
                return uri.AbsolutePath == "/operation/release"
                    ? await Release(body.RootElement.Deserialize<FixtureSelector>(Json) ?? throw Failure(), linked.Token).ConfigureAwait(false)
                    : Error(HttpStatusCode.NotFound);
            if (statusSucceededDeleteVaultCleanup || statusSucceededDeleteVaultIndependentCleanup || statusSucceededDeleteVaultCancellationCleanup)
                return uri.AbsolutePath == "/operation/release"
                    ? await Release(body.RootElement.Deserialize<FixtureSelector>(Json) ?? throw Failure(), linked.Token).ConfigureAwait(false)
                    : Error(HttpStatusCode.NotFound);
            if (profile is Profile.OriginalPrivateConnectionDelete or Profile.PrivateConnectionDeleteCleanup)
                return await DispatchPrivateConnectionDelete(uri.AbsolutePath, body.RootElement, linked.Token).ConfigureAwait(false);
            if (profile is Profile.OriginalPrivateConnectionUpdate or Profile.PrivateConnectionUpdateCleanup)
                return await DispatchPrivateConnectionUpdate(uri.AbsolutePath, body.RootElement, linked.Token).ConfigureAwait(false);
            if (profile is Profile.OriginalVaultRecover or Profile.RecoverVaultCleanup)
                return await DispatchRecoverVault(uri.AbsolutePath, body.RootElement, linked.Token).ConfigureAwait(false);
            if (profile is Profile.OriginalVaultCreateOrUpdate or Profile.CreateOrUpdateVaultCleanup)
                return await DispatchCreateOrUpdateVault(uri.AbsolutePath, body.RootElement, linked.Token).ConfigureAwait(false);
            if (profile is Profile.OriginalVaultPurge or Profile.PurgeDeletedVaultCleanup)
                return await DispatchPurgeDeletedVault(uri.AbsolutePath, body.RootElement, linked.Token).ConfigureAwait(false);
            if (profile != Profile.StatusFamily)
                return await DispatchDeleteVault(uri.AbsolutePath, body.RootElement, linked.Token).ConfigureAwait(false);
            return uri.AbsolutePath switch
            {
                "/operation/prepare" => await Prepare(body.RootElement.Deserialize<E.Prepare>(Json) ?? throw Failure(),
                    linked.Token, cancellationToken).ConfigureAwait(false),
                "/operation/arm" => Arm(body.RootElement.Deserialize<ObserveLease>(Json) ?? throw Failure(), linked.Token, cancellationToken),
                "/operation/observe" => await Observe(body.RootElement.Deserialize<ObserveLease>(Json) ?? throw Failure(),
                    linked.Token, cancellationToken).ConfigureAwait(false),
                "/operation/release" => await Release(body.RootElement.Deserialize<FixtureSelector>(Json) ?? throw Failure(),
                    linked.Token, cancellationToken).ConfigureAwait(false),
                _ => Error(HttpStatusCode.NotFound)
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception)
        {
            return Error(HttpStatusCode.ServiceUnavailable);
        }
        finally { Leave(null); }
    }

    private async Task<HttpResponseMessage> Prepare(E.Prepare input, CancellationToken token, CancellationToken requestCancellation = default)
    {
        ValidateSelector(input.Selection);
        if (statusPrivateUpdateIndependentProfile)
            Require(!statusPrivateUpdateIndependentCleanup && input.Operation == ManagementMutation.UpdatePrivateConnection &&
                statusPrivateUpdateIndependentConfiguration is { } privateParent && privateParent.Location == input.Location &&
                privateParent.TenantId == input.TenantId && privateParent.Sku == input.Sku && privateParent.RetentionDays == input.RetentionDays);
        if (statusNotificationUpdateIndependentProfile)
            Require(!statusNotificationUpdateIndependentCleanup && input.Operation == ManagementMutation.UpdateNotification &&
                statusNotificationUpdateIndependentConfiguration is { } expectedNotificationParent &&
                VaultAdministrationEffects.SameConfiguration(expectedNotificationParent,
                    new(input.Location, input.TenantId, input.Sku, true, false, input.RetentionDays, false, [])));
        if (statusNotificationCreateIndependentProfile)
            Require(!statusNotificationCreateIndependentCleanup && input.Operation == ManagementMutation.CreateOrUpdateNotification &&
                statusNotificationCreateIndependentConfiguration is { } expectedNotificationCreateParent &&
                VaultAdministrationEffects.SameConfiguration(expectedNotificationCreateParent,
                    new(input.Location, input.TenantId, input.Sku, true, false, input.RetentionDays, false, [])));
        if (statusSucceededDeleteVaultProfile)
            Require(!statusSucceededDeleteVaultCleanup && input.Operation == ManagementMutation.DeleteVault &&
                statusSucceededConfiguration is { } expected && expected.Location == input.Location &&
                expected.TenantId == input.TenantId && expected.Sku == input.Sku && expected.RetentionDays == input.RetentionDays);
        if (statusSucceededDeleteVaultCancellationProfile)
            Require(!statusSucceededDeleteVaultCancellationCleanup && input.Operation == ManagementMutation.DeleteVault &&
                statusSucceededCancellationConfiguration is { } cancellationExpected && cancellationExpected.Location == input.Location &&
                cancellationExpected.TenantId == input.TenantId && cancellationExpected.Sku == input.Sku && cancellationExpected.RetentionDays == input.RetentionDays);
        if (statusSucceededDeleteVaultIndependentProfile)
            Require(!statusSucceededDeleteVaultIndependentCleanup && input.Operation == ManagementMutation.DeleteVault &&
                statusSucceededIndependentConfiguration is { } independentExpected && independentExpected.Location == input.Location &&
                independentExpected.TenantId == input.TenantId && independentExpected.Sku == input.Sku && independentExpected.RetentionDays == input.RetentionDays);
        Require(input.SubscriptionId == scope.SubscriptionId && input.ResourceGroup == scope.ResourceGroup &&
            input.Location == scope.Location && input.TenantId == scope.TenantId && Enum.IsDefined(input.Sku) &&
            input.RetentionDays is >= 7 and <= 90 && input.Operation == SelectionOperation(input.Selection) &&
            Text(input.WebhookUrl, 2048));
        bool notification = IsNotification(input.Operation);
        bool privateApproval = input.Operation is ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection;
        VaultAdministrationEffects.Configuration? recoveryConfiguration = null;
        VaultAdministrationEffects.Configuration? updateConfiguration = null;
        if (VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(input.Selection))
        {
            updateConfiguration = provisioner.StatusVaultUpdateCancellationConfiguration(scope);
            var expected = new VaultAdministrationEffects.Configuration(input.Location, input.TenantId,
                input.Sku, true, false, input.RetentionDays, false, []);
            _ = expected.Build();
            Require(VaultAdministrationEffects.SameConfiguration(updateConfiguration, expected) &&
                VaultAdministrationEffects.SameConfiguration(updateConfiguration with { PublicNetworkAccess = true },
                    expected with { PublicNetworkAccess = true }));
        }
        if (VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(input.Selection))
        {
            recoveryConfiguration = provisioner.StatusVaultRecoverCancellationConfiguration(scope);
            var selected = new VaultAdministrationEffects.Configuration(input.Location, input.TenantId,
                input.Sku, true, false, input.RetentionDays, true, []);
            _ = selected.Build();
            Require(VaultAdministrationEffects.SameConfiguration(recoveryConfiguration, selected));
        }
        if (privateApproval) Require(privateConnectionSource is not null);
        if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(input.Selection) ||
            VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(input.Selection) ||
            VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(input.Selection) ||
            statusPrivateDeleteIndependentProfile || statusPrivateUpdateIndependentProfile)
            Require(statusPrivateReaderSeparated);
        if (notification)
        {
            Require(notificationSource is { HttpsWebhookReady: true, Baseline: not null });
            Require(notificationSource.ExclusiveCreation is null ||
                NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(input.Selection));
            Require(NotificationConfigurationMatches(notificationSource.Baseline, VaultNotificationEvent.SecretNearExpiry) &&
                input.WebhookUrl == notificationSource.Baseline.Endpoint.Reveal());
            if (statusNotificationUpdateIndependentProfile || statusNotificationCreateIndependentProfile ||
                NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(input.Selection) ||
                NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(input.Selection) ||
                NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(input.Selection) ||
                NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(input.Selection))
            {
                var source = notificationSource;
                Require(source.Setup is { Credential: not null, Transport: not null } &&
                    source.Observer is { Credential: not null, Transport: not null } &&
                    !ReferenceEquals(source.Setup.Credential, source.Observer.Credential) &&
                    !ReferenceEquals(source.Setup.Transport, source.Observer.Transport) &&
                    source.Limits is
                    {
                        MaximumResponseBytes: >= 1024 and <= 16 * 1024 * 1024,
                        MaximumRequestBytes: >= 1024 and <= 1024 * 1024, MaximumRowBytes: >= 1024,
                        MaximumDepth: >= 4 and <= 32, MaximumHeaders: >= 1 and <= 128,
                        MaximumHeaderBytes: >= 128 and <= 64 * 1024
                    } &&
                    source.Limits.MaximumRowBytes <= source.Limits.MaximumResponseBytes &&
                    source.Limits.Timeout > TimeSpan.Zero && source.Limits.Timeout <= TimeSpan.FromMinutes(2));
            }
        }
        Session session;
        lock (gate)
        {
            Require(!disposed && sessions.Count < 32 && !sessions.ContainsKey(input.Selection.Nonce));
            session = new(input.Selection with { })
            {
                Active = 1,
                Preparation = input with { Selection = input.Selection with { } },
                StatusRecoverConfiguration = recoveryConfiguration,
                StatusUpdateConfiguration = updateConfiguration
            };
            if (statusPrivateUpdateIndependentProfile)
                session.PrivateUpdateIndependentTokens.AddRange([token, requestCancellation]);
            if (statusNotificationUpdateIndependentProfile)
                session.NotificationUpdateIndependentTokens.AddRange([token, requestCancellation]);
            if (statusNotificationCreateIndependentProfile)
                session.NotificationCreateIndependentTokens.AddRange([token, requestCancellation]);
            sessions.Add(input.Selection.Nonce, session);
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            lock (gate)
            {
                Require(!session.Closed && !disposed);
                session.Plan = provisioner.PlanFixture(owner, session.Selector,
                    notification || privateApproval || input.Operation is ManagementMutation.DeleteVault or ManagementMutation.CreateOrUpdateVault
                        ? VaultFixtureProvisioner.Preparation.Active : VaultFixtureProvisioner.Preparation.Deleted,
                    [], seedCanary: false,
                    ownedNotificationNames: notification ? ["skn-" + Guid.NewGuid().ToString("N")] : [],
                    privateEndpoint: privateApproval ? new(privateConnectionSource!.BorrowedSubnetId) : null);
                Require(session.Plan.VaultId == VaultId(session.Plan.VaultName) &&
                    session.Plan.DeletedId == DeletedId(session.Plan.VaultName));
                if (notification)
                {
                    var source = notificationSource!;
                    session.Notifications = new(provisioner.Journal,
                        new(provisioner.Scope(session.Plan), true, source.HttpsWebhookReady),
                        source.Baseline!, source.Setup, source.Observer, source.Limits, time, provisioner);
                    session.NotificationPlan = session.Notifications.PlanDeclaredSubscription(session.Plan,
                        session.Plan.OwnedNotificationNames.Single(), source.ExclusiveCreation is null
                            ? NotificationFixtureProvisioner.Preparation.Present : NotificationFixtureProvisioner.Preparation.Absent);
                    if (source.ExclusiveCreation is { } declaration)
                        session.Notifications.DeclareAbsentCreation(session.NotificationPlan, declaration);
                }
            }
            var prepared = await provisioner.ProvisionAsync(session.Plan, cancellationToken: linked.Token,
                originalCallerToken: statusPrivateUpdateIndependentProfile || statusNotificationUpdateIndependentProfile || statusNotificationCreateIndependentProfile ? requestCancellation : null).ConfigureAwait(false);
            Require(prepared.State == VaultFixtureProvisioner.State.Ready &&
                prepared.DeletedVaultPresent == (!notification && !privateApproval && input.Operation is not (ManagementMutation.DeleteVault or ManagementMutation.CreateOrUpdateVault)) &&
                prepared.VaultPresent == (notification || privateApproval || input.Operation is ManagementMutation.DeleteVault or ManagementMutation.CreateOrUpdateVault));
            if (recoveryConfiguration is not null)
                Require(provisioner.OwnsStatusVaultRecoverCancellationPreparation(session.Plan));
            if (updateConfiguration is not null)
                Require(provisioner.OwnsStatusVaultUpdateCancellationPreparation(session.Plan));
            if (statusSucceededDeleteVaultProfile)
                Require(provisioner.OwnsStatusSucceededDeleteVaultPreparation(session.Plan) &&
                    prepared.Configuration is not null &&
                    VaultAdministrationEffects.SameConfiguration(prepared.Configuration, statusSucceededConfiguration!));
            if (statusSucceededDeleteVaultCancellationProfile)
                Require(provisioner.OwnsStatusSucceededDeleteVaultCancellationPreparation(session.Plan) &&
                    prepared.Configuration is not null &&
                    VaultAdministrationEffects.SameConfiguration(prepared.Configuration, statusSucceededCancellationConfiguration!));
            if (statusSucceededDeleteVaultIndependentProfile)
                Require(provisioner.OwnsStatusSucceededDeleteVaultIndependentPreparation(session.Plan) &&
                    prepared.Configuration is not null &&
                    VaultAdministrationEffects.SameConfiguration(prepared.Configuration, statusSucceededIndependentConfiguration!));
            if (statusPrivateUpdateIndependentProfile)
                Require(provisioner.OwnsPreparedPlan(session.Plan) && prepared.Configuration is not null &&
                    VaultAdministrationEffects.SameConfiguration(prepared.Configuration, statusPrivateUpdateIndependentConfiguration!));
            if (statusNotificationUpdateIndependentProfile)
                Require(provisioner.OwnsPreparedPlan(session.Plan) && prepared.Configuration is not null &&
                    VaultAdministrationEffects.SameConfiguration(prepared.Configuration, statusNotificationUpdateIndependentConfiguration!));
            if (statusNotificationCreateIndependentProfile)
                Require(provisioner.OwnsPreparedPlan(session.Plan) && prepared.Configuration is not null &&
                    VaultAdministrationEffects.SameConfiguration(prepared.Configuration, statusNotificationCreateIndependentConfiguration!));
            if (notification || privateApproval)
                Require(prepared.Configuration is { PurgeProtection: false } parentConfiguration &&
                    parentConfiguration.Location.Equals(input.Location, StringComparison.OrdinalIgnoreCase) &&
                    parentConfiguration.TenantId == input.TenantId && parentConfiguration.Sku == input.Sku &&
                    parentConfiguration.RetentionDays == input.RetentionDays);
            else if (input.Operation == ManagementMutation.CreateOrUpdateVault)
                Require(prepared.Configuration is not null &&
                    VaultAdministrationEffects.SameConfiguration(prepared.Configuration,
                        new(input.Location, input.TenantId, input.Sku, true, false, input.RetentionDays, false, [])));
            if (notification)
            {
                using var child = await session.Notifications!.ProvisionAsync(session.NotificationPlan!, linked.Token,
                    originalCallerToken: statusNotificationUpdateIndependentProfile || statusNotificationCreateIndependentProfile ? requestCancellation : null).ConfigureAwait(false);
                Require(child.State == NotificationFixtureProvisioner.State.Ready &&
                    (notificationSource!.ExclusiveCreation is null
                        ? child.Present == true && child.Configuration is not null &&
                            NotificationConfigurationMatches(child.Configuration, VaultNotificationEvent.SecretNearExpiry)
                        : child.Present == false && child.Configuration is null &&
                            session.Notifications.OwnsExclusiveCreation(session.NotificationPlan!, child.Journal)));
                RequireNotificationJournal(session, child.Journal, selected: false);
            }
            if (privateApproval)
            {
                var source = privateConnectionSource!;
                session.Endpoints = new(provisioner, source.EndpointSetup, source.EndpointReader,
                    source.VaultConnectionReader, source.ResourceLimits, source.InventoryLimits, time);
                session.EndpointPlan = session.Endpoints.PlanDeclaredEndpoint(session.Plan);
                var child = await session.Endpoints.ProvisionAsync(session.EndpointPlan, linked.Token,
                    statusPrivateUpdateIndependentProfile ? requestCancellation : null).ConfigureAwait(false);
                Require(child.State == PrivateEndpointFixtureProvisioner.State.Ready && child.ConnectionId is not null &&
                    session.Endpoints.OwnsBoundPlan(session.EndpointPlan, session.Plan, child.ConnectionId));
                session.ConnectionId = child.ConnectionId;
            }
            var observedAt = time.GetUtcNow();
            lock (gate)
            {
                Require(!session.Closed && !disposed);
                var snapshot = provisioner.Journal.Read(owner, session.Selector);
                Require(!snapshot.Closing && snapshot.LeaseId == session.Plan.LeaseId &&
                    snapshot.Resources.Length == (privateApproval ? 5 : notification ? 4 : 3) &&
                    snapshot.Resources.All(r => (privateApproval || !r.Borrowed) && r.ActiveDispatch == Guid.Empty) && snapshot.Idle);
                if (notification) RequireNotificationJournal(session, snapshot, selected: false);
                if (statusPrivateUpdateIndependentProfile) session.PrivateUpdateIndependentReady = FreezePrivateUpdateIndependent(snapshot);
                if (statusNotificationUpdateIndependentProfile) session.NotificationUpdateIndependentReady = FreezeNotificationUpdateIndependent(snapshot);
                if (statusNotificationCreateIndependentProfile) session.NotificationCreateIndependentReady = FreezeNotificationCreateIndependent(snapshot);
                if (privateApproval) RequirePrivateRoot(session, snapshot);
                session.Lease = new(new(session.Selector.Nonce, snapshot.LeaseId, observerIdentity,
                    S.ArmOrigin, notification ? "2025-02-15" : "2026-02-01", observedAt,
                    snapshot.Resources.Where(r => !r.Borrowed).Select(r => r.Id).Concat(privateApproval
                        ? [session.ConnectionId!, session.Plan.PrivateEndpoint!.ExpectedNicId] : []).ToArray()),
                    session.Plan.VaultName, privateApproval ? session.ConnectionId!.Split('/')[^1] : null,
                    session.NotificationPlan?.Scope.SubscriptionName, null, input.Operation, NativeProvisioningState.Succeeded);
                return Reply(session.Lease);
            }
        }
        finally { LeaveSession(session); }
    }

    private HttpResponseMessage Arm(ObserveLease input, CancellationToken token = default, CancellationToken originalCallerToken = default)
    {
        Session session;
        lock (gate)
        {
            session = Find(input.Nonce, input.LeaseId);
            if (statusPrivateUpdateIndependentProfile)
            {
                bool valid = PrivateUpdateIndependentLive(session) && !session.ArmClaimed && input.Phase == "subscribe-before-trigger" &&
                    input.SubscriptionId is null && !token.IsCancellationRequested && !originalCallerToken.IsCancellationRequested;
                session.ArmClaimed = true;
                if (!valid) RevokePrivateUpdateIndependent(session);
                Require(valid);
                session.PrivateUpdateIndependentTokens.AddRange([token, originalCallerToken]);
            }
            else
            {
                Require(!session.ArmClaimed && input.Phase == "subscribe-before-trigger" && input.SubscriptionId is null);
                session.ArmClaimed = true;
            }
            session.Active++;
        }
        try
        {
            var plan = session.Plan!;
            var operation = SelectionOperation(session.Selector);
            ManagementScope resource = IsNotification(operation) ? session.NotificationPlan!.Scope :
                operation is ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection
                ? new PrivateConnectionScope(provisioner.Scope(plan), session.Lease!.PrivateConnectionName!)
                :
                operation != ManagementMutation.PurgeDeletedVault
                ? new VaultScope(new(new(scope.SubscriptionId), scope.ResourceGroup), plan.VaultName)
                : new DeletedVaultScope(new(scope.SubscriptionId), scope.Location, plan.VaultName);
            var binding = new C.Binding(session.Selector, plan.LeaseId,
                resource, operation, scope.Location, IsNotification(operation) ? "2025-02-15" : "2026-02-01");
            // Private approval is armed with the actual caller's scope at start,
            // not this equal baseline-only scope.
            var native = statusSucceededDeleteVaultProfile || statusSucceededDeleteVaultIndependentProfile || statusSucceededDeleteVaultCancellationProfile || operation is ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection
                ? null : capture.Arm(binding);
            var baseline = statusPrivateUpdateIndependentProfile
                ? before.ArmStatusPrivateConnectionUpdateIndependent(binding, R.StatusPrivateConnectionUpdateIndependentReadPhase.Baseline)
                : statusPrivateDeleteIndependentProfile
                ? before.ArmStatusPrivateConnectionDeleteIndependent(binding, R.StatusPrivateConnectionDeleteIndependentReadPhase.Baseline)
                : statusSucceededDeleteVaultCancellationProfile
                ? before.ArmStatusSucceededDeleteVaultCancellation(binding, statusSucceededCancellationConfiguration!,
                    R.StatusSucceededDeleteVaultCancellationReadPhase.BaselineActive)
                : statusSucceededDeleteVaultIndependentProfile
                ? before.ArmStatusSucceededDeleteVaultIndependent(binding, statusSucceededIndependentConfiguration!,
                    R.StatusSucceededDeleteVaultIndependentReadPhase.BaselineActive)
                : statusSucceededDeleteVaultProfile
                ? before.ArmStatusSucceededDeleteVault(binding, statusSucceededConfiguration!, R.StatusSucceededDeleteVaultReadPhase.BaselineActive)
                : IsNotification(operation) ? null : before.Arm(binding,
                statusPrivateDeleteSelectedProfile: VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(binding.Selector));
            var post = statusSucceededDeleteVaultCancellationProfile
                ? after.ArmStatusSucceededDeleteVaultCancellation(binding, statusSucceededCancellationConfiguration!,
                    R.StatusSucceededDeleteVaultCancellationReadPhase.SelectedActive)
                : statusSucceededDeleteVaultIndependentProfile
                ? after.ArmStatusSucceededDeleteVaultIndependent(binding, statusSucceededIndependentConfiguration!,
                    R.StatusSucceededDeleteVaultIndependentReadPhase.SelectedActive)
                : statusSucceededDeleteVaultProfile
                ? after.ArmStatusSucceededDeleteVault(binding, statusSucceededConfiguration!, R.StatusSucceededDeleteVaultReadPhase.SelectedActive)
                : IsNotification(operation) ||
                operation is ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection
                ? null : after.Arm(binding);
            C.Binding? counterpartBinding = null;
            R.Window? counterpartBefore = null, counterpartAfter = null;
            if (statusSucceededDeleteVaultProfile || statusSucceededDeleteVaultIndependentProfile || statusSucceededDeleteVaultCancellationProfile ||
                VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(session.Selector) ||
                VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(session.Selector) ||
                VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(session.Selector) ||
                VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(session.Selector))
            {
                ManagementScope counterpart = operation != ManagementMutation.PurgeDeletedVault
                    ? new DeletedVaultScope(new(scope.SubscriptionId), scope.Location, plan.VaultName)
                    : new VaultScope(new(new(scope.SubscriptionId), scope.ResourceGroup), plan.VaultName);
                counterpartBinding = new(session.Selector, plan.LeaseId, counterpart,
                    operation, scope.Location, binding.ApiRevision);
                counterpartBefore = statusSucceededDeleteVaultCancellationProfile
                    ? statusCounterpartBeforeCollector!.ArmStatusSucceededDeleteVaultCancellation(counterpartBinding,
                        statusSucceededCancellationConfiguration!, R.StatusSucceededDeleteVaultCancellationReadPhase.BaselineDeleted)
                    : statusSucceededDeleteVaultIndependentProfile
                    ? statusCounterpartBeforeCollector!.ArmStatusSucceededDeleteVaultIndependent(counterpartBinding,
                        statusSucceededIndependentConfiguration!, R.StatusSucceededDeleteVaultIndependentReadPhase.BaselineDeleted)
                    : statusSucceededDeleteVaultProfile
                    ? statusCounterpartBeforeCollector!.ArmStatusSucceededDeleteVault(counterpartBinding, statusSucceededConfiguration!,
                        R.StatusSucceededDeleteVaultReadPhase.BaselineDeleted)
                    : statusCounterpartBeforeCollector!.Arm(counterpartBinding);
                counterpartAfter = statusSucceededDeleteVaultCancellationProfile
                    ? statusCounterpartAfterCollector!.ArmStatusSucceededDeleteVaultCancellation(counterpartBinding,
                        statusSucceededCancellationConfiguration!, R.StatusSucceededDeleteVaultCancellationReadPhase.SelectedDeleted)
                    : statusSucceededDeleteVaultIndependentProfile
                    ? statusCounterpartAfterCollector!.ArmStatusSucceededDeleteVaultIndependent(counterpartBinding,
                        statusSucceededIndependentConfiguration!, R.StatusSucceededDeleteVaultIndependentReadPhase.SelectedDeleted)
                    : statusSucceededDeleteVaultProfile
                    ? statusCounterpartAfterCollector!.ArmStatusSucceededDeleteVault(counterpartBinding, statusSucceededConfiguration!,
                        R.StatusSucceededDeleteVaultReadPhase.SelectedDeleted)
                    : statusCounterpartAfterCollector!.Arm(counterpartBinding);
            }
            var armedAt = time.GetUtcNow();
            lock (gate)
            {
                Require(!disposed && !session.Closed);
                session.Binding = binding;
                session.Capture = native;
                session.Before = baseline;
                session.After = post;
                session.CounterpartBinding = counterpartBinding;
                session.CounterpartBefore = counterpartBefore;
                session.CounterpartAfter = counterpartAfter;
                session.Subscription = Guid.NewGuid();
                session.ArmedAt = armedAt;
                if (statusNotificationUpdateIndependentProfile)
                {
                    session.NotificationUpdateIndependentBefore = new(session.Notifications!, session.NotificationPlan!, plan, binding,
                        session.Subscription, armedAt, true, Guid.NewGuid());
                    session.NotificationUpdateIndependentAfter = new(session.Notifications!, session.NotificationPlan!, plan, binding,
                        session.Subscription, armedAt, false, Guid.NewGuid());
                }
                if (statusNotificationCreateIndependentProfile)
                {
                    session.NotificationCreateIndependentBefore = new(session.Notifications!, session.NotificationPlan!, plan, binding,
                        session.Subscription, armedAt, true, Guid.NewGuid());
                    session.NotificationCreateIndependentAfter = new(session.Notifications!, session.NotificationPlan!, plan, binding,
                        session.Subscription, armedAt, false, Guid.NewGuid());
                }
                if (NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(session.Selector))
                {
                    session.StatusNotificationIndependentBefore = new(session.Notifications!, session.NotificationPlan!, plan,
                        binding, session.Subscription, armedAt, Baseline: true, Guid.NewGuid());
                    session.StatusNotificationIndependentAfter = new(session.Notifications!, session.NotificationPlan!, plan,
                        binding, session.Subscription, armedAt, Baseline: false, Guid.NewGuid());
                }
                if (NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(session.Selector) ||
                    NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(session.Selector) ||
                    NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(session.Selector))
                {
                    session.StatusNotificationBefore = new(session.Notifications!, session.NotificationPlan!, plan,
                        binding, session.Subscription, armedAt, Baseline: true);
                    session.StatusNotificationAfter = new(session.Notifications!, session.NotificationPlan!, plan,
                        binding, session.Subscription, armedAt, Baseline: false);
                }
                session.Armed = true;
                return Reply(new ObservationSubscription(plan.LeaseId, session.Selector.Nonce, session.Subscription, armedAt));
            }
        }
        finally { LeaveSession(session); }
    }

    private async Task<HttpResponseMessage> Observe(ObserveLease input, CancellationToken token,
        CancellationToken requestCancellation = default)
    {
        Session session;
        bool baseline = input.Phase == "baseline-before-dispatch";
        lock (gate)
        {
            session = Find(input.Nonce, input.LeaseId);
            Require(session.Armed && input.SubscriptionId == session.Subscription);
            if (statusPrivateUpdateIndependentProfile)
            {
                bool valid = PrivateUpdateIndependentLive(session) && !token.IsCancellationRequested && !requestCancellation.IsCancellationRequested &&
                    (baseline ? !session.BaselineClaimed && !session.StartClaimed : input.Phase == "selected-state" &&
                        session.StartFinished && session.StartSucceeded && session.PrivateUpdateIndependentDrained is not null && !session.AfterClaimed);
                if (baseline) session.BaselineClaimed = true; else session.AfterClaimed = true;
                if (!valid) RevokePrivateUpdateIndependent(session);
                Require(valid);
                session.PrivateUpdateIndependentTokens.AddRange([token, requestCancellation]);
            }
            else if (statusPrivateDeleteIndependentProfile)
            {
                bool valid = !session.StatusPrivateDeleteIndependentInvalid && (baseline
                    ? !session.BaselineClaimed && !session.StartClaimed
                    : input.Phase == "selected-state" && session.StartFinished && session.StartSucceeded &&
                        session.StartTask is { IsCompletedSuccessfully: true } && !session.AfterClaimed);
                if (baseline) session.BaselineClaimed = true;
                else session.AfterClaimed = true;
                session.StatusPrivateDeleteIndependentInvalid |= !valid;
                Require(valid);
            }
            else if (VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(session.Selector))
            {
                bool valid = !session.StatusPrivateDeleteSelectedInvalid && (baseline
                    ? !session.BaselineClaimed && !session.StartClaimed
                    : input.Phase == "selected-state" && session.StartFinished && session.StartSucceeded &&
                        session.StartTask is { IsCompletedSuccessfully: true } && !session.AfterClaimed);
                if (baseline) session.BaselineClaimed = true;
                else session.AfterClaimed = true;
                session.StatusPrivateDeleteSelectedInvalid |= !valid;
                Require(valid);
            }
            else if (VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(session.Selector))
            {
                bool valid = !session.StatusPrivateDeleteInvalid && (baseline
                    ? !session.BaselineClaimed && !session.StartClaimed
                    : input.Phase == "selected-state" && session.StartFinished && session.StartSucceeded &&
                        session.StartTask is { IsCompleted: true } && !session.AfterClaimed);
                if (baseline) session.BaselineClaimed = true;
                else session.AfterClaimed = true;
                session.StatusPrivateDeleteInvalid = !valid;
                Require(valid);
            }
            else if (statusNotificationCreateIndependentProfile)
            {
                bool valid = !session.NotificationCreateIndependentInvalid && !token.IsCancellationRequested &&
                    !requestCancellation.IsCancellationRequested && (baseline
                        ? !session.BaselineClaimed && !session.StartClaimed
                        : input.Phase == "selected-state" && session.StartFinished && session.StartSucceeded &&
                            session.StartTask is { IsCompletedSuccessfully: true } && !session.AfterClaimed);
                if (baseline) session.BaselineClaimed = true;
                else session.AfterClaimed = true;
                if (!valid) RevokeNotificationCreateIndependent(session);
                Require(valid);
            }
            else if (baseline)
            {
                Require(!session.BaselineClaimed && !session.StartClaimed);
                session.BaselineClaimed = true;
            }
            else
            {
                Require(input.Phase == "selected-state" && session.StartFinished && session.StartSucceeded &&
                    session.StartTask is { IsCompleted: true } && !session.AfterClaimed);
                session.AfterClaimed = true;
            }
            session.Active++;
        }
        try
        {
            using var linked = statusPrivateUpdateIndependentProfile
                ? CancellationTokenSource.CreateLinkedTokenSource([.. session.PrivateUpdateIndependentTokens, token, session.Stop.Token])
                : CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            var binding = session.Binding!;
            if (statusPrivateUpdateIndependentProfile)
            {
                session.PrivateUpdateIndependentTokens.Add(linked.Token);
                return await ObservePrivateUpdateIndependent(session, baseline, linked.Token, requestCancellation).ConfigureAwait(false);
            }
            if (statusSucceededDeleteVaultCancellationProfile)
                return await ObserveStatusSucceededDeleteVaultCancellation(session, baseline, linked.Token, requestCancellation).ConfigureAwait(false);
            if (statusSucceededDeleteVaultIndependentProfile)
                return await ObserveStatusSucceededDeleteVaultIndependent(session, baseline, linked.Token).ConfigureAwait(false);
            if (statusSucceededDeleteVaultProfile)
                return await ObserveStatusSucceededDeleteVault(session, baseline, linked.Token).ConfigureAwait(false);
            if (statusNotificationUpdateIndependentProfile)
            {
                lock (gate) session.NotificationUpdateIndependentTokens.AddRange([token, linked.Token, requestCancellation]);
                return await ObserveStatusNotificationUpdateIndependent(session, baseline, linked.Token).ConfigureAwait(false);
            }
            if (statusNotificationCreateIndependentProfile)
            {
                lock (gate) session.NotificationCreateIndependentTokens.AddRange([token, linked.Token, requestCancellation]);
                return await ObserveStatusNotificationCreateIndependent(session, baseline, linked.Token, requestCancellation).ConfigureAwait(false);
            }
            if (NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(session.Selector))
                return await ObserveStatusNotificationDeleteIndependent(session, baseline, linked.Token).ConfigureAwait(false);
            if (NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(session.Selector))
                return await ObserveStatusNotificationCreateCancellation(session, baseline, linked.Token).ConfigureAwait(false);
            if (NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(session.Selector))
                return await ObserveStatusNotificationUpdateCancellation(session, baseline, linked.Token).ConfigureAwait(false);
            if (NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(session.Selector))
                return await ObserveStatusNotificationDeleteCancellation(session, baseline, linked.Token).ConfigureAwait(false);
            if (VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(session.Selector))
                return await ObserveStatusVaultDeleteCancellation(session, baseline, linked.Token).ConfigureAwait(false);
            if (VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(session.Selector))
                return await ObserveStatusVaultPurgeCancellation(session, baseline, linked.Token).ConfigureAwait(false);
            if (VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(session.Selector))
                return await ObserveStatusVaultRecoverCancellation(session, baseline, linked.Token).ConfigureAwait(false);
            if (VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(session.Selector))
                return await ObserveStatusVaultUpdateCancellation(session, baseline, linked.Token).ConfigureAwait(false);
            if (binding.Operation is ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection)
            {
                if (statusPrivateDeleteIndependentProfile)
                    return await ObserveStatusPrivateConnectionDeleteIndependent(session, baseline, linked.Token).ConfigureAwait(false);
                if (VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(session.Selector))
                    return await ObserveStatusPrivateConnectionDeleteSelected(session, baseline, linked.Token).ConfigureAwait(false);
                if (VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(session.Selector))
                    return await ObserveStatusPrivateConnectionDelete(session, baseline, linked.Token).ConfigureAwait(false);
                if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(session.Selector))
                    return await ObserveStatusPrivateConnectionUpdate(session, baseline, linked.Token).ConfigureAwait(false);
                return await ObservePrivateConnection(session, baseline, linked.Token).ConfigureAwait(false);
            }
            if (baseline)
            {
                if (IsNotification(binding.Operation))
                {
                    using var measuredNotification = await session.Notifications!.ObserveAsync(owner, session.Selector,
                        session.NotificationPlan!.Scope.SubscriptionName, linked.Token).ConfigureAwait(false);
                    Require(measuredNotification.State == NotificationFixtureProvisioner.State.Ready &&
                        measuredNotification.Present == true && measuredNotification.Configuration is not null &&
                        NotificationConfigurationMatches(measuredNotification.Configuration, VaultNotificationEvent.SecretNearExpiry) &&
                        measuredNotification.ObservedAt >= session.ArmedAt);
                    RequireNotificationJournal(session, measuredNotification.Journal, selected: false);
                    lock (gate)
                    {
                        Require(!disposed && !session.Closed && !session.StartClaimed);
                        RequireNotificationJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: false);
                        session.BaselineAt = measuredNotification.ObservedAt;
                        session.BaselineReady = true;
                        return Reply(ProjectNotification(session, measuredNotification.ObservedAt,
                            NativeProvisioningState.Unknown, measuredNotification.Configuration));
                    }
                }
                using var measured = await before.CollectAsync(session.Before!, binding, linked.Token).ConfigureAwait(false);
                Require(ResourceBound(measured, session, session.Before!));
                var observedAt = measured.FinishedAt;
                VaultAdministrationEffects.Configuration? baselineConfiguration = null;
                if (binding.Operation == ManagementMutation.RecoverVault)
                {
                    Require(measured.ResourceStatus == SecretStatus.Absent && measured.HttpStatus == 404 &&
                        measured.ResourceId is null && measured.VaultConfiguration is null);
                    var owned = await provisioner.ObserveAsync(owner, session.Selector, linked.Token).ConfigureAwait(false);
                    Require(owned.State == VaultFixtureProvisioner.State.Ready && owned.VaultPresent == false &&
                        owned.DeletedVaultPresent == true && owned.Journal.LeaseId == session.Plan!.LeaseId);
                    observedAt = time.GetUtcNow();
                    Require(observedAt >= measured.FinishedAt);
                }
                else
                {
                    Require(measured.ResourceStatus == SecretStatus.Success && measured.PersistedStateEligible &&
                        measured.ResourceId is { } resourceId &&
                        resourceId.Equals(SelectedId(session), StringComparison.OrdinalIgnoreCase));
                    if (binding.Operation is ManagementMutation.DeleteVault or ManagementMutation.CreateOrUpdateVault)
                        Require("Succeeded".Equals(measured.NativeState, StringComparison.OrdinalIgnoreCase) &&
                            measured.VaultConfiguration is { PurgeProtection: false } vault && vault.TenantId == scope.TenantId &&
                            vault.CreateMode is null or "default" &&
                            vault.Location.Equals(scope.Location, StringComparison.OrdinalIgnoreCase) &&
                            vault.Sku == session.Preparation!.Sku && vault.RetentionDays == session.Preparation.RetentionDays);
                    else
                        Require(measured.DeletedVault is { PurgeProtected: false } deleted &&
                            deleted.OriginalResourceId.Equals(session.Plan!.VaultId, StringComparison.OrdinalIgnoreCase));
                    if (binding.Operation == ManagementMutation.CreateOrUpdateVault)
                    {
                        Require(measured.HttpStatus == 200);
                        var baselineVault = measured.VaultConfiguration!;
                        baselineConfiguration = new(baselineVault.Location, baselineVault.TenantId, baselineVault.Sku,
                            baselineVault.Rbac, baselineVault.PurgeProtection, baselineVault.RetentionDays, baselineVault.PublicNetworkAccess,
                            baselineVault.Policies.Select(p => new VaultAdministrationEffects.Policy(
                                p.TenantId, p.PrincipalId, p.Permissions.ToArray(), p.ApplicationId)).ToArray());
                        var prepared = session.Preparation!;
                        Require(VaultAdministrationEffects.SameConfiguration(baselineConfiguration,
                            new(prepared.Location, prepared.TenantId, prepared.Sku, true, false, prepared.RetentionDays, false, [])));
                        var owned = await provisioner.ObserveAsync(owner, session.Selector, linked.Token).ConfigureAwait(false);
                        Require(owned.State == VaultFixtureProvisioner.State.Ready && owned.VaultPresent == true &&
                            owned.DeletedVaultPresent == false && owned.Journal.LeaseId == session.Plan!.LeaseId &&
                            owned.Configuration is not null &&
                            VaultAdministrationEffects.SameConfiguration(owned.Configuration, baselineConfiguration));
                        observedAt = time.GetUtcNow();
                        Require(observedAt >= measured.FinishedAt);
                    }
                }
                lock (gate)
                {
                    Require(!disposed && !session.Closed && !session.StartClaimed);
                    session.BaselineAt = observedAt;
                    session.BaselineReady = true;
                    return Reply(Project(session, observedAt, NativeProvisioningState.Unknown, measured.ResourceStatus, baselineConfiguration));
                }
            }
            if (binding.Operation == ManagementMutation.DeleteNotification)
            {
                C.SynchronousDeleteProof proof;
                lock (gate)
                {
                    Require(!disposed && !session.Closed);
                    Require(capture.TryGetSynchronousDeleteProof(session.Capture!, binding, out var issued) &&
                        OwnsNotificationDeleteProof(session, issued));
                    proof = issued;
                    RequireNotificationJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: true);
                }
                using var measuredNotification = await session.Notifications!.ObserveSelectedAsync(
                    session.NotificationPlan!, session.Dispatch, linked.Token).ConfigureAwait(false);
                Require(measuredNotification.State == NotificationFixtureProvisioner.State.Pending &&
                    ReferenceEquals(measuredNotification.SelectedPlan, session.NotificationPlan) &&
                    measuredNotification.SelectedDispatch == session.Dispatch && measuredNotification.Present == false &&
                    measuredNotification.NativeState is null && measuredNotification.Configuration is null &&
                    measuredNotification.ObservedAt >= session.StartedAt);
                RequireNotificationJournal(session, measuredNotification.Journal, selected: true);
                lock (gate)
                {
                    Require(!disposed && !session.Closed && !linked.IsCancellationRequested &&
                        OwnsNotificationDeleteProof(session, proof));
                    RequireNotificationJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: true);
                    session.DeleteProof = proof;
                    session.IndependentAt = measuredNotification.ObservedAt;
                    session.IndependentReady = true;
                    // Native success belongs to the qualified original response;
                    // the separate owned GET establishes only child absence.
                    return Reply(Project(session, measuredNotification.ObservedAt,
                        NativeProvisioningState.Succeeded, SecretStatus.Absent));
                }
            }
            Require(capture.TryGetStatusTarget(session.Capture!, binding, out var target) &&
                capture.OwnsStatusTarget(target, binding));
            var window = statuses.Arm(target, binding);
            var status = await statuses.CollectAsync(window, binding, linked.Token).ConfigureAwait(false);
            Require(status.Binding == binding && status.WindowId == window.Id && status.ResponseComplete && status.Terminal &&
                status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
                status.StartDispatch == target.StartDispatch && status.TargetSha256 == target.TargetSha256 &&
                status.StartResponseSha256 == target.StartResponseSha256 && status.StartedAt >= session.StartedAt &&
                status.FinishedAt >= status.StartedAt && Text(status.NativeRequestId, 256));
            if (IsNotification(binding.Operation))
            {
                Require(status.HttpStatus == 200);
                // Separate controlled PUT/PATCH assumptions retain omitted labels
                // and mappings. Owned readback checks them; it does not
                // qualify native retention or authorize request rewriting.
                using var measuredNotification = await session.Notifications!.ObserveSelectedAsync(
                    session.NotificationPlan!, session.Dispatch, linked.Token).ConfigureAwait(false);
                Require(measuredNotification.State == NotificationFixtureProvisioner.State.Pending &&
                    ReferenceEquals(measuredNotification.SelectedPlan, session.NotificationPlan) &&
                    measuredNotification.SelectedDispatch == session.Dispatch && measuredNotification.Present == true &&
                    measuredNotification.NativeState == "Succeeded" && measuredNotification.Configuration is not null &&
                    NotificationConfigurationMatches(measuredNotification.Configuration, VaultNotificationEvent.SecretNewVersionCreated) &&
                    measuredNotification.ObservedAt >= status.FinishedAt);
                RequireNotificationJournal(session, measuredNotification.Journal, selected: true);
                lock (gate)
                {
                    Require(!disposed && !session.Closed);
                    RequireNotificationJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: true);
                    session.Target = target;
                    session.IndependentAt = measuredNotification.ObservedAt;
                    session.IndependentReady = true;
                    return Reply(ProjectNotification(session, measuredNotification.ObservedAt,
                        status.OperationState, measuredNotification.Configuration));
                }
            }
            using var resource = await after.CollectAsync(session.After!, binding, linked.Token).ConfigureAwait(false);
            Require(ResourceBound(resource, session, session.After!) && resource.StartedAt >= status.FinishedAt);
            VaultAdministrationEffects.Configuration? configuration = null;
            var independentAt = resource.FinishedAt;
            if (binding.Operation is ManagementMutation.RecoverVault or ManagementMutation.CreateOrUpdateVault)
            {
                Require(status.HttpStatus == 200 && resource.HttpStatus == 200 &&
                    resource.ResourceStatus == SecretStatus.Success && resource.PersistedStateEligible &&
                    resource.ResourceId is { } resourceId &&
                    resourceId.Equals(session.Plan!.VaultId, StringComparison.OrdinalIgnoreCase) &&
                    "Succeeded".Equals(resource.NativeState, StringComparison.OrdinalIgnoreCase) &&
                    resource.VaultConfiguration is not null);
                var vault = resource.VaultConfiguration;
                configuration = new(vault.Location, vault.TenantId, vault.Sku, vault.Rbac, vault.PurgeProtection,
                    vault.RetentionDays, vault.PublicNetworkAccess,
                    vault.Policies.Select(p => new VaultAdministrationEffects.Policy(
                        p.TenantId, p.PrincipalId, p.Permissions.ToArray(), p.ApplicationId)).ToArray());
                var prepared = session.Preparation!;
                Require(VaultAdministrationEffects.SameConfiguration(configuration,
                    new(prepared.Location, prepared.TenantId, prepared.Sku, true, false, prepared.RetentionDays, true, [])));
                // Controlled fixtures explicitly assume native ownership-tag retention.
                // Native retention when the selected request omits tags remains unverified.
                // This fresh observation validates tags; coordinates alone never confer ownership.
                var owned = await provisioner.ObserveAsync(owner, session.Selector, linked.Token).ConfigureAwait(false);
                Require(owned.State == VaultFixtureProvisioner.State.Pending && owned.VaultPresent == true &&
                    owned.DeletedVaultPresent == false && owned.Journal.LeaseId == session.Plan!.LeaseId &&
                    owned.Configuration is not null &&
                    VaultAdministrationEffects.SameConfiguration(owned.Configuration, configuration));
                independentAt = time.GetUtcNow();
                Require(independentAt >= resource.FinishedAt);
            }
            else
                Require(resource.ResourceStatus == SecretStatus.Absent &&
                    resource.HttpStatus == 404 && resource.ResourceId is null);
            lock (gate)
            {
                Require(!disposed && !session.Closed);
                session.Target = target;
                session.IndependentAt = independentAt;
                session.IndependentReady = true;
                return Reply(Project(session, independentAt, status.OperationState, resource.ResourceStatus, configuration));
            }
        }
        finally { LeaveSession(session); }
    }

    public async ValueTask<SecretOutcome<ManagementOperation>> RunStartAsync(FixtureSelector selector,
        VaultAdministration client, ManagementScope originalScope, ManagementMutation operation,
        E.Input input, ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        if (PendingProfile)
            return await StartPendingPurge(selector, client, originalScope, operation, input, receipt, cancellationToken).ConfigureAwait(false);
        Require(profile == Profile.StatusFamily && !statusPrivateDeleteIndependentCleanup && !statusNotificationUpdateIndependentCleanup && !statusNotificationCreateIndependentCleanup);
        Require(!statusPrivateUpdateIndependentCleanup);
        if (statusPrivateUpdateIndependentProfile)
            return await StartPrivateUpdateIndependent(selector, client, originalScope, operation, input, receipt, cancellationToken).ConfigureAwait(false);
        if (statusNotificationUpdateIndependentProfile)
            return await StartStatusNotificationUpdateIndependent(selector, client, originalScope, operation, input, receipt, cancellationToken).ConfigureAwait(false);
        if (statusNotificationCreateIndependentProfile)
            return await StartStatusNotificationCreateIndependent(selector, client, originalScope, operation, input, receipt, cancellationToken).ConfigureAwait(false);
        if (statusPrivateDeleteIndependentProfile)
        {
            ValidateSelector(selector);
            Require(operation == ManagementMutation.DeletePrivateConnection);
            return await StartStatusPrivateConnectionDeleteIndependent(selector, client, originalScope, input, receipt,
                cancellationToken).ConfigureAwait(false);
        }
        if (statusSucceededDeleteVaultCancellationProfile)
            return await StartStatusSucceededDeleteVaultCancellation(selector, client, originalScope, operation, input, receipt,
                cancellationToken).ConfigureAwait(false);
        if (statusSucceededDeleteVaultIndependentProfile)
            return await StartStatusSucceededDeleteVaultIndependent(selector, client, originalScope, operation, input, receipt,
                cancellationToken).ConfigureAwait(false);
        if (statusSucceededDeleteVaultProfile)
            return await StartStatusSucceededDeleteVault(selector, client, originalScope, operation, input, receipt,
                cancellationToken).ConfigureAwait(false);
        if (operation == ManagementMutation.DeletePrivateConnection)
        {
            if (VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(selector))
                return await StartStatusPrivateConnectionDeleteSelected(selector, client, originalScope, input, receipt,
                    cancellationToken).ConfigureAwait(false);
            Require(VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector));
            return await StartStatusPrivateConnectionDelete(selector, client, originalScope, input, receipt,
                cancellationToken).ConfigureAwait(false);
        }
        if (operation == ManagementMutation.UpdatePrivateConnection)
            return await StartPrivateConnection(selector, client, originalScope, input, receipt, cancellationToken).ConfigureAwait(false);
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            bool bound = originalScope switch
            {
                VaultScope vault => operation is ManagementMutation.DeleteVault or ManagementMutation.RecoverVault or ManagementMutation.CreateOrUpdateVault &&
                    vault.ResourceGroup.Subscription.SubscriptionId == scope.SubscriptionId &&
                    vault.ResourceGroup.ResourceGroup == scope.ResourceGroup && vault.VaultName == session.Plan!.VaultName,
                DeletedVaultScope deleted => operation == ManagementMutation.PurgeDeletedVault &&
                    deleted.Subscription.SubscriptionId == scope.SubscriptionId && deleted.Location == scope.Location &&
                    deleted.VaultName == session.Plan!.VaultName,
                NotificationScope notification => IsNotification(operation) &&
                    session.NotificationPlan is { } child && notification.SubscriptionName == child.Scope.SubscriptionName &&
                    notification.Vault.ExportResourceId() == session.Plan!.VaultId,
                _ => false
            };
            Require(session.Armed && session.BaselineReady && !session.StartClaimed &&
                operation == SelectionOperation(selector) && bound && InputMatches(session, input));
            // The durable fence precedes SDK, credential, transport and clock callbacks.
            if (IsNotification(operation))
                RequireNotificationJournal(session, provisioner.Journal.Read(owner, selector), selected: false);
            if (NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector))
                Require(session.StatusNotificationBaseline is { } baseline &&
                    MatchesStatusNotificationRoot(baseline, provisioner.Journal.Read(owner, selector)) &&
                    baseline.Task.IsCompletedSuccessfully &&
                    session.Notifications!.OwnsStatusNotificationDeleteRead(baseline.Proof, session.NotificationPlan!, Guid.Empty));
            if (VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(selector))
            {
                var root = provisioner.Journal.Read(owner, selector);
                Require(session.StatusPurgeBaseline is { } baseline &&
                    provisioner.MatchesOwnedPlan(session.Plan!, root) &&
                    MatchesStatusPurgeRoot(baseline, root) && !root.Closing && root.Idle &&
                    root.Resources.Single(r => r.Id == session.Plan!.DeletedId) is
                    { SelectedAttempted: false, InvocationTerminated: true });
            }
            if (VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector))
            {
                var root = provisioner.Journal.Read(owner, selector);
                Require(session.StatusRecoverBaseline is { } baseline &&
                    provisioner.OwnsStatusVaultRecoverCancellationPreparation(session.Plan!) &&
                    provisioner.MatchesOwnedPlan(session.Plan!, root) &&
                    MatchesStatusRecoverRoot(baseline, root) && !root.Closing && root.Idle &&
                    root.Resources.Single(r => r.Id == session.Plan!.VaultId) is
                    { SelectedAttempted: false, InvocationTerminated: true });
            }
            if (VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector))
            {
                var root = provisioner.Journal.Read(owner, selector);
                Require(session.StatusUpdateBaseline is { } baseline &&
                    provisioner.OwnsStatusVaultUpdateCancellationPreparation(session.Plan!) &&
                    provisioner.MatchesOwnedPlan(session.Plan!, root) &&
                    MatchesStatusUpdateRoot(baseline, root) && !root.Closing && root.Idle &&
                    root.Resources.Single(r => r.Id == session.Plan!.VaultId) is
                    { SelectedAttempted: false, InvocationTerminated: true });
            }
            if (NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(selector))
            {
                var baseline = session.StatusNotificationIndependentBaseline ?? throw Failure();
                Require(baseline.Task.IsCompletedSuccessfully &&
                    session.Notifications!.OwnsStatusNotificationDeleteIndependentRead(baseline.Proof, session.NotificationPlan!, Guid.Empty));
                var admission = new StatusNotificationDeleteIndependentAdmission(this);
                Require(statusNotificationDeleteIndependentAdmissions.TryAdd(admission, baseline));
                try
                {
                    session.Dispatch = provisioner.Journal.BeginStatusNotificationDeleteIndependentInvocation(owner, selector,
                        session.Plan!.LeaseId, admission);
                }
                finally { statusNotificationDeleteIndependentAdmissions.TryRemove(admission, out _); }
            }
            else if (NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector))
            {
                var baseline = session.StatusNotificationCreateBaseline ?? throw Failure();
                Require(baseline.Task.IsCompletedSuccessfully &&
                    session.Notifications!.OwnsStatusNotificationCreateRead(baseline.Proof, session.NotificationPlan!, Guid.Empty));
                var admission = new StatusNotificationCreateCancellationAdmission(this);
                Require(statusNotificationCreateAdmissions.TryAdd(admission, baseline));
                if (baseline.AbsentCreate is not null)
                {
                    session.Dispatch = provisioner.Journal.BeginStatusNotificationAbsentCreateInvocation(owner, selector,
                        session.Plan!.LeaseId, admission);
                    capture.BindNotificationAbsentCreation(session.Capture!, session.Binding!, session.Notifications!,
                        session.NotificationPlan!, baseline.Proof, session.Dispatch);
                }
                else
                    session.Dispatch = provisioner.Journal.BeginStatusNotificationCreateInvocation(owner, selector,
                        session.Plan!.LeaseId, admission);
            }
            else if (NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector))
            {
                var baseline = session.StatusNotificationUpdateBaseline ?? throw Failure();
                Require(baseline.Task.IsCompletedSuccessfully &&
                    session.Notifications!.OwnsStatusNotificationUpdateRead(baseline.Proof, session.NotificationPlan!, Guid.Empty));
                var admission = new StatusNotificationUpdateCancellationAdmission(this);
                Require(statusNotificationUpdateAdmissions.TryAdd(admission, baseline));
                session.Dispatch = provisioner.Journal.BeginStatusNotificationUpdateInvocation(owner, selector,
                    session.Plan!.LeaseId, admission);
            }
            else session.Dispatch = operation is ManagementMutation.UpdateNotification or ManagementMutation.CreateOrUpdateNotification or
                ManagementMutation.RecoverVault or ManagementMutation.CreateOrUpdateVault
                ? provisioner.Journal.BeginSelectedUpdate(owner, selector, SelectedId(session))
                : provisioner.Journal.BeginSelectedDispatch(owner, selector, SelectedId(session), delete: true);
            if (VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector))
                provisioner.RetainStatusVaultRecoverCancellationDispatch(session.Plan!, session.Dispatch);
            if (VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector))
                provisioner.RetainStatusVaultUpdateCancellationDispatch(session.Plan!, session.Dispatch);
            if (operation == ManagementMutation.DeleteNotification ||
                NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector) ||
                NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector) ||
                VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(selector) ||
                VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(selector) ||
                VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector) ||
                VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector))
            {
                session.Client = client;
                if (IsNotification(operation))
                    session.ActualNotificationScope = (NotificationScope)originalScope;
                else if (operation is ManagementMutation.DeleteVault or ManagementMutation.RecoverVault or ManagementMutation.CreateOrUpdateVault)
                    session.ActualVaultScope = (VaultScope)originalScope;
                else
                    session.ActualDeletedVaultScope = (DeletedVaultScope)originalScope;
                session.Receipt = receipt;
            }
            session.StartClaimed = true;
            session.Active++;
            active++;
        }
        try
        {
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, session.Stop.Token, deadline.Token);
            var result = await (NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(selector)
                ? capture.StartNotificationDeleteIndependentAsync(session.Capture!, selector, client, originalScope, input,
                    receipt, linked.Token, task => { lock (gate) session.StartTask = task; }, () =>
                    {
                        linked.Token.ThrowIfCancellationRequested();
                        Require(!disposed && !session.Closed);
                        RequireNotificationJournal(session, provisioner.Journal.Read(owner, selector),
                            selected: true, invocationTerminated: false);
                    })
                : capture.StartAsync(session.Capture!, selector, client, originalScope, input, receipt, linked.Token,
                    task => { lock (gate) session.StartTask = task; })).ConfigureAwait(false);
            lock (gate)
            {
                session.StartSucceeded = result.IsSuccess && session.StartTask is { IsCompleted: true };
                session.Handle = result.IsSuccess ? result.Value : null;
            }
            return result;
        }
        finally
        {
            try
            {
                provisioner.Journal.EndDispatch(owner, selector, SelectedId(session), session.Dispatch, nativeSettled: false);
                lock (gate) session.StartFinished = true;
            }
            finally { Leave(session); }
        }
    }

    public async ValueTask<SecretStatus> RunCheckStatusAsync(FixtureSelector selector, ManagementOperation handle,
        CancellationToken cancellationToken)
    {
        if (PendingProfile)
            return await CheckPendingPurge(selector, handle, cancellationToken).ConfigureAwait(false);
        Require(profile == Profile.StatusFamily && !statusPrivateDeleteIndependentCleanup && !statusNotificationUpdateIndependentCleanup && !statusNotificationCreateIndependentCleanup);
        Require(!statusPrivateUpdateIndependentCleanup);
        if (statusPrivateUpdateIndependentProfile)
            return await CheckPrivateUpdateIndependent(selector, handle, cancellationToken).ConfigureAwait(false);
        if (statusNotificationUpdateIndependentProfile)
            return await CheckStatusNotificationUpdateIndependent(selector, handle, cancellationToken).ConfigureAwait(false);
        if (statusNotificationCreateIndependentProfile)
            return await CheckStatusNotificationCreateIndependent(selector, handle, cancellationToken).ConfigureAwait(false);
        if (statusPrivateDeleteIndependentProfile)
        {
            ValidateSelector(selector);
            return await CheckStatusPrivateConnectionDeleteIndependent(selector, handle, cancellationToken).ConfigureAwait(false);
        }
        if (statusSucceededDeleteVaultCancellationProfile)
            return await CheckStatusSucceededDeleteVaultCancellation(selector, handle, cancellationToken).ConfigureAwait(false);
        if (statusSucceededDeleteVaultIndependentProfile)
            return await CheckStatusSucceededDeleteVaultIndependent(selector, handle, cancellationToken).ConfigureAwait(false);
        if (statusSucceededDeleteVaultProfile)
            return await CheckStatusSucceededDeleteVault(selector, handle, cancellationToken).ConfigureAwait(false);
        if (NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(selector))
            return await CheckStatusNotificationDeleteIndependent(selector, handle, cancellationToken).ConfigureAwait(false);
        if (VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(selector))
            return await CheckStatusPrivateConnectionDeleteSelected(selector, handle, cancellationToken).ConfigureAwait(false);
        if (VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector))
            return await CheckStatusPrivateConnectionDelete(selector, handle, cancellationToken).ConfigureAwait(false);
        if (VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(selector) ||
            VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(selector) ||
            VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector) ||
            VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector) ||
            NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector) ||
            NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector) ||
            NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector))
            return await CheckStatusVaultCancellation(selector, handle, cancellationToken).ConfigureAwait(false);
        if (selector.Variant == "operation.UpdatePrivateConnection")
            return await CheckPrivateConnection(selector, handle, cancellationToken).ConfigureAwait(false);
        Session session;
        C.SynchronousDeleteProof? deletionProof;
        bool deletion;
        lock (gate)
        {
            session = OpenSelector(selector);
            deletion = SelectionOperation(selector) == ManagementMutation.DeleteNotification;
            deletionProof = session.DeleteProof;
            Require(session.StartFinished && session.StartSucceeded && session.IndependentReady &&
                !session.StatusClaimed && ReferenceEquals(handle, session.Handle));
            if (deletion)
            {
                Require(deletionProof is not null && OwnsNotificationDeleteProof(session, deletionProof));
                RequireNotificationJournal(session, provisioner.Journal.Read(owner, selector), selected: true);
            }
            else
                Require(session.Target is not null && capture.OwnsStatusTarget(session.Target, session.Binding!));
            provisioner.Journal.AdmitStatusRead(owner, selector, session.Plan!.LeaseId, SelectedId(session), session.Dispatch);
            session.StatusClaimed = true;
            session.Active++;
            active++;
        }
        try
        {
            Require(time.GetUtcNow() >= session.IndependentAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, session.Stop.Token, deadline.Token);
            if (deletion)
            {
                lock (gate)
                {
                    Require(!disposed && !session.Closed && !linked.IsCancellationRequested &&
                        ReferenceEquals(deletionProof, session.DeleteProof) &&
                        OwnsNotificationDeleteProof(session, deletionProof!));
                    RequireNotificationJournal(session, provisioner.Journal.Read(owner, selector),
                        selected: true, invocationTerminated: false);
                }
            }
            var status = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            lock (gate)
            {
                if (deletion)
                {
                    Require(!disposed && !session.Closed && !linked.IsCancellationRequested &&
                        ReferenceEquals(deletionProof, session.DeleteProof) &&
                        OwnsNotificationDeleteProof(session, deletionProof!));
                    RequireNotificationJournal(session, provisioner.Journal.Read(owner, selector),
                        selected: true, invocationTerminated: false);
                    session.StatusSucceeded = status == SecretStatus.Success &&
                        handle.State == NativeProvisioningState.Succeeded &&
                        session.StatusTask is { IsCompleted: true } && session.StartTask is { IsCompleted: true };
                }
                else
                    session.StatusSucceeded = status == SecretStatus.Success &&
                        handle.State == NativeProvisioningState.Succeeded && session.StatusTask is { IsCompleted: true } &&
                        (!IsNotification(SelectionOperation(selector)) &&
                            SelectionOperation(selector) is not (ManagementMutation.RecoverVault or ManagementMutation.CreateOrUpdateVault) ||
                            capture.OwnsNativeStatusCompletion(session.Capture!, session.Binding!));
            }
            return status;
        }
        finally
        {
            try
            {
                if (deletion)
                {
                    lock (gate)
                    {
                        bool settled = !disposed && !session.Closed && !cancellationToken.IsCancellationRequested &&
                            session.StatusSucceeded && session.IndependentReady &&
                            session.StatusTask is { IsCompleted: true } && session.StartTask is { IsCompleted: true } &&
                            ReferenceEquals(deletionProof, session.DeleteProof) &&
                            OwnsNotificationDeleteProof(session, deletionProof!);
                        if (settled)
                            RequireNotificationJournal(session, provisioner.Journal.Read(owner, selector),
                                selected: true, invocationTerminated: false);
                        provisioner.Journal.EndDispatch(owner, selector, SelectedId(session), session.Dispatch, settled);
                    }
                }
                else
                {
                    bool settled;
                    lock (gate)
                    {
                        settled = session.StatusSucceeded && session.IndependentReady &&
                            session.StatusTask is { IsCompleted: true } && session.StartTask is { IsCompleted: true };
                    }
                    provisioner.Journal.EndDispatch(owner, selector, SelectedId(session), session.Dispatch, settled);
                }
            }
            finally { Leave(session); }
        }
    }

    private async Task<HttpResponseMessage> ObserveStatusSucceededDeleteVault(Session session, bool baseline, CancellationToken token)
    {
        var plan = session.Plan!;
        Require(plan.StatusSucceededDeleteVaultProfile && !plan.Restored &&
            provisioner.OwnsStatusSucceededDeleteVaultPreparation(plan));
        var binding = baseline ? session.Binding! : session.StatusSucceededBaseline!.Binding;
        var deletedBinding = session.CounterpartBinding!;
        C.StatusSucceededDeleteVaultStartProof? start = null;
        S.Window? statusWindow = null;
        Task<S.Measurement>? statusTask = null;
        DateTimeOffset earliest = session.ArmedAt;
        if (!baseline)
        {
            Require(session.StatusSucceededBaseline is not null &&
                capture.TryGetStatusSucceededDeleteVaultStart(session.Capture!, session.Binding!, session.Client!,
                    session.ActualVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, out start));
            Require(capture.TryGetStatusTarget(session.Capture!, session.Binding!, out var target) &&
                ReferenceEquals(start!.Target, target));
            statusWindow = statuses.Arm(target, session.Binding!);
            statusTask = statuses.CollectAsync(statusWindow, session.Binding!, token).AsTask();
            var status = await statusTask.ConfigureAwait(false);
            Require(ReferenceEquals(status.Binding, session.Binding) && status.WindowId == statusWindow.Id &&
                status.ArmedAt == statusWindow.ArmedAt && status.ArmedAt >= session.StartedAt &&
                status.StartedAt >= status.ArmedAt && status.FinishedAt >= status.StartedAt &&
                status.HttpStatus == 200 && status.ResponseComplete && status.Terminal &&
                status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
                status.StartDispatch == target.StartDispatch && status.TargetSha256 == target.TargetSha256 &&
                status.StartResponseSha256 == target.StartResponseSha256 && Text(status.NativeRequestId, 256));
            earliest = status.FinishedAt;
        }
        var activeReader = baseline ? before : after;
        var deletedReader = baseline ? statusCounterpartBeforeCollector! : statusCounterpartAfterCollector!;
        var activeWindow = baseline ? session.Before! : session.After!;
        var deletedWindow = baseline ? session.CounterpartBefore! : session.CounterpartAfter!;
        var activeTask = activeReader.CollectAsync(activeWindow, binding, token).AsTask();
        using var activeResult = await activeTask.ConfigureAwait(false);
        Require(activeReader.TryGetStatusSucceededDeleteVaultRead(activeWindow, binding, activeTask, out var activeProof) &&
            activeProof.StartedAt >= earliest && activeProof.FinishedAt >= activeProof.StartedAt &&
            activeProof.Phase == (baseline ? R.StatusSucceededDeleteVaultReadPhase.BaselineActive : R.StatusSucceededDeleteVaultReadPhase.SelectedActive) &&
            activeProof.HttpStatus == (baseline ? 200 : 404) &&
            (!baseline || activeProof.OriginalVaultId == plan.VaultId));
        var deletedTask = deletedReader.CollectAsync(deletedWindow, deletedBinding, token).AsTask();
        using var deletedResult = await deletedTask.ConfigureAwait(false);
        Require(deletedReader.TryGetStatusSucceededDeleteVaultRead(deletedWindow, deletedBinding, deletedTask, out var deletedProof) &&
            deletedProof.StartedAt >= activeProof.FinishedAt && deletedProof.FinishedAt >= deletedProof.StartedAt &&
            deletedProof.Phase == (baseline ? R.StatusSucceededDeleteVaultReadPhase.BaselineDeleted : R.StatusSucceededDeleteVaultReadPhase.SelectedDeleted) &&
            deletedProof.HttpStatus == (baseline ? 404 : 200) &&
            (baseline || deletedProof.OriginalVaultId == plan.VaultId));
        token.ThrowIfCancellationRequested();
        var snapshot = provisioner.Journal.Read(owner, session.Selector);
        Require(provisioner.MatchesOwnedPlan(plan, snapshot) && RoleFixtureJournal.StatusSucceededDeleteVaultRoot(snapshot) &&
            !snapshot.Closing);
        lock (gate)
        {
            Require(!disposed && !session.Closed && !token.IsCancellationRequested);
            if (baseline)
            {
                Require(!session.StartClaimed && snapshot.Idle && snapshot.StatusSucceededDeleteVault!.InvocationDispatch == Guid.Empty);
                string digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                    activeProof.ResponseSha256 + ":" + deletedProof.ResponseSha256)));
                session.StatusSucceededBaseline = new(plan, snapshot.Revision, Array.AsReadOnly(snapshot.Resources.ToArray()),
                    statusSucceededConfiguration! with { Policies = [] }, binding, deletedBinding,
                    activeWindow, deletedWindow, activeTask, deletedTask,
                    activeProof, deletedProof, digest, token);
                session.BaselineAt = deletedProof.FinishedAt;
                session.BaselineReady = true;
                return Reply(Project(session, session.BaselineAt, NativeProvisioningState.Unknown, SecretStatus.Success));
            }
            var observation = new StatusSucceededObservation(session.StatusSucceededBaseline!, session.Dispatch, snapshot.Revision,
                start!, statusWindow!, statusTask!, activeWindow, deletedWindow, activeTask, deletedTask,
                activeProof, deletedProof, token, session.StatusSucceededStartCancellation);
            Require(StatusSucceededSelectedRoot(observation, snapshot, terminated: true));
            session.StatusSucceededObservation = observation;
            session.Target = start!.Target;
            session.IndependentAt = deletedProof.FinishedAt;
            session.IndependentReady = true;
            return Reply(Project(session, session.IndependentAt, NativeProvisioningState.Succeeded, SecretStatus.Absent));
        }
    }

    private async Task<SecretOutcome<ManagementOperation>> StartStatusSucceededDeleteVault(FixtureSelector selector,
        VaultAdministration client, ManagementScope originalScope, ManagementMutation operation, E.Input input,
        ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(!statusSucceededDeleteVaultCleanup && operation == ManagementMutation.DeleteVault &&
                input.StatusOperation == ManagementMutation.DeleteVault && InputMatches(session, input) &&
                session.Armed && session.BaselineReady && !session.StartClaimed && originalScope is VaultScope vault &&
                vault.ExportResourceId() == session.Plan!.VaultId &&
                provisioner.OwnsStatusSucceededDeleteVaultPreparation(session.Plan) &&
                session.StatusSucceededBaseline is { } baseline &&
                before.TryGetStatusSucceededDeleteVaultRead(baseline.ActiveWindow, baseline.Binding, baseline.ActiveTask, out var activeProof) &&
                ReferenceEquals(activeProof, baseline.Active) &&
                statusCounterpartBeforeCollector!.TryGetStatusSucceededDeleteVaultRead(baseline.DeletedWindow,
                    baseline.DeletedBinding, baseline.DeletedTask, out var deletedProof) && ReferenceEquals(deletedProof, baseline.Deleted));
            var admission = new StatusSucceededDeleteVaultAdmission(this);
            Require(statusSucceededAdmissions.TryAdd(admission, session.StatusSucceededBaseline!));
            session.StartClaimed = true;
            try
            {
                session.Dispatch = provisioner.Journal.BeginStatusSucceededDeleteVaultInvocation(owner, selector,
                    session.Plan!.LeaseId, admission);
            }
            finally { statusSucceededAdmissions.TryRemove(admission, out _); }
            session.Client = client;
            session.Receipt = receipt;
            session.ActualVaultScope = (VaultScope)originalScope;
            session.StatusSucceededStartCancellation = cancellationToken;
            session.Active++;
            active++;
        }
        try
        {
            // Actual caller scope replaces only C's binding. B and the four R
            // windows retain their own original reference identities.
            session.Binding = new(selector, session.Plan!.LeaseId, originalScope, operation, scope.Location, "2026-02-01");
            session.Capture = capture.Arm(session.Binding);
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, session.Stop.Token, deadline.Token);
            var result = await capture.StartStatusSucceededDeleteVaultAsync(session.Capture, selector, client,
                (VaultScope)originalScope, input, receipt, linked.Token, task => { lock (gate) session.StartTask = task; },
                () =>
                {
                    linked.Token.ThrowIfCancellationRequested();
                    var current = provisioner.Journal.Read(owner, selector);
                    Require(StatusSucceededRoot(session.StatusSucceededBaseline!, current) &&
                        current.StatusSucceededDeleteVault!.InvocationDispatch == session.Dispatch &&
                        current.StatusSucceededDeleteVault.SettledDispatch == Guid.Empty &&
                        current.Resources.Single(r => r.Id == session.Plan.VaultId) is
                        { SelectedAttempted: true, DeleteAttempted: false, InvocationTerminated: false, ActiveDispatch: var dispatch } &&
                        dispatch == session.Dispatch);
                }).ConfigureAwait(false);
            lock (gate)
            {
                session.Handle = result.IsSuccess ? result.Value : null;
                session.StartSucceeded = result.IsSuccess && capture.TryGetStatusSucceededDeleteVaultStart(session.Capture,
                    session.Binding, client, (VaultScope)originalScope, receipt, session.StartTask!, session.Handle!, out _);
            }
            return result;
        }
        finally
        {
            try
            {
                provisioner.Journal.EndDispatch(owner, selector, session.Plan!.VaultId, session.Dispatch, nativeSettled: false);
                lock (gate) session.StartFinished = true;
            }
            finally { Leave(session); }
        }
    }

    private async Task<SecretStatus> CheckStatusSucceededDeleteVault(FixtureSelector selector, ManagementOperation handle,
        CancellationToken cancellationToken)
    {
        Session session;
        StatusSucceededObservation observation;
        long revision;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(!session.StatusClaimed && session.StartFinished && session.StartSucceeded && session.IndependentReady &&
                ReferenceEquals(handle, session.Handle) && session.StatusSucceededObservation is not null);
            session.StatusClaimed = true;
            cancellationToken.ThrowIfCancellationRequested();
            observation = session.StatusSucceededObservation;
            // Refresh every external proof outside the journal transaction.
            Require(capture.TryGetStatusSucceededDeleteVaultStart(session.Capture!, session.Binding!, session.Client!,
                    session.ActualVaultScope!, session.Receipt!, session.StartTask!, handle, out var start) &&
                ReferenceEquals(start, observation.Start) && observation.StatusTask.IsCompletedSuccessfully &&
                after.TryGetStatusSucceededDeleteVaultRead(observation.ActiveWindow, observation.Baseline.Binding,
                    observation.ActiveTask, out var activeProof) && ReferenceEquals(activeProof, observation.Active) &&
                statusCounterpartAfterCollector!.TryGetStatusSucceededDeleteVaultRead(observation.DeletedWindow,
                    observation.Baseline.DeletedBinding, observation.DeletedTask, out var deletedProof) &&
                ReferenceEquals(deletedProof, observation.Deleted));
            var admission = new StatusSucceededDeleteVaultReadAdmission(this);
            Require(statusSucceededReadAdmissions.TryAdd(admission, observation));
            try
            {
                provisioner.Journal.AdmitStatusSucceededDeleteVaultRead(owner, selector, session.Plan!.LeaseId,
                    session.Dispatch, admission);
            }
            finally { statusSucceededReadAdmissions.TryRemove(admission, out _); }
            revision = provisioner.Journal.Read(owner, selector).Revision;
            session.Active++;
            active++;
        }
        bool settled = false;
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, session.Stop.Token, deadline.Token);
            Require(time.GetUtcNow() >= session.IndependentAt);
            var result = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            Require(result == SecretStatus.Success);
            Require(capture.TryGetStatusSucceededDeleteVaultCompletion(session.Capture!, session.Binding!, session.Client!,
                    session.ActualVaultScope!, session.Receipt!, session.StartTask!, handle, session.StatusTask!, out var proof) &&
                ReferenceEquals(proof.Start, observation.Start));
            var completion = new StatusSucceededCompletion(observation, revision, session.Capture!, session.Client!,
                session.ActualVaultScope!, session.Receipt!, session.StartTask!, handle, session.StatusTask!, proof,
                linked.Token, cancellationToken);
            var certificate = new StatusSucceededDeleteVaultSettlement(this);
            Require(statusSucceededSettlements.TryAdd(certificate, completion));
            try
            {
                provisioner.Journal.CompleteStatusSucceededDeleteVaultRead(owner, selector, session.Plan!.LeaseId,
                    session.Dispatch, certificate);
                settled = true;
            }
            finally { statusSucceededSettlements.TryRemove(certificate, out _); }
            lock (gate) session.StatusSucceeded = true;
            return result;
        }
        finally
        {
            try
            {
                if (!settled) provisioner.Journal.EndDispatch(owner, selector, session.Plan!.VaultId, session.Dispatch, nativeSettled: false);
            }
            finally { Leave(session); }
        }
    }

    private async Task<HttpResponseMessage> ObserveStatusSucceededDeleteVaultCancellation(Session session, bool baseline, CancellationToken token,
        CancellationToken requestCancellation)
    {
        var plan = session.Plan!;
        Require(plan.StatusSucceededDeleteVaultCancellationProfile && !plan.Restored &&
            provisioner.OwnsStatusSucceededDeleteVaultCancellationPreparation(plan));
        var binding = baseline ? session.Binding! : session.StatusSucceededCancellationBaseline!.Binding;
        var deletedBinding = session.CounterpartBinding!;
        C.StatusSucceededDeleteVaultCancellationStartProof? start = null;
        S.Window? statusWindow = null;
        Task<S.Measurement>? statusTask = null;
        DateTimeOffset earliest = session.ArmedAt;
        if (!baseline)
        {
            Require(!session.StatusSucceededCancellationInvalid && session.StatusSucceededCancellationStartDrain is not null &&
                RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(session.StatusSucceededCancellationStartDrain,
                    provisioner.Journal.Read(owner, session.Selector)));
            Require(session.StatusSucceededCancellationBaseline is not null &&
                capture.TryGetStatusSucceededDeleteVaultCancellationStart(session.Capture!, session.Binding!, session.Client!,
                    session.ActualVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, out start));
            Require(capture.TryGetStatusTarget(session.Capture!, session.Binding!, out var target) &&
                ReferenceEquals(start!.Target, target));
            statusWindow = statuses.Arm(target, session.Binding!);
            statusTask = statuses.CollectAsync(statusWindow, session.Binding!, token).AsTask();
            var status = await statusTask.ConfigureAwait(false);
            Require(ReferenceEquals(status.Binding, session.Binding) && status.WindowId == statusWindow.Id &&
                status.ArmedAt == statusWindow.ArmedAt && status.ArmedAt >= session.StartedAt &&
                status.StartedAt >= status.ArmedAt && status.FinishedAt >= status.StartedAt &&
                status.HttpStatus == 200 && status.ResponseComplete && status.Terminal &&
                status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
                status.StartDispatch == target.StartDispatch && status.TargetSha256 == target.TargetSha256 &&
                status.StartResponseSha256 == target.StartResponseSha256 && Text(status.NativeRequestId, 256));
            earliest = status.FinishedAt;
        }
        var activeReader = baseline ? before : after;
        var deletedReader = baseline ? statusCounterpartBeforeCollector! : statusCounterpartAfterCollector!;
        var activeWindow = baseline ? session.Before! : session.After!;
        var deletedWindow = baseline ? session.CounterpartBefore! : session.CounterpartAfter!;
        var activeTask = activeReader.CollectAsync(activeWindow, binding, token).AsTask();
        using var activeResult = await activeTask.ConfigureAwait(false);
        Require(activeReader.TryGetStatusSucceededDeleteVaultCancellationRead(activeWindow, binding, activeTask, out var activeProof) &&
            activeProof.StartedAt >= earliest && activeProof.FinishedAt >= activeProof.StartedAt &&
            activeProof.Phase == (baseline ? R.StatusSucceededDeleteVaultCancellationReadPhase.BaselineActive : R.StatusSucceededDeleteVaultCancellationReadPhase.SelectedActive) &&
            activeProof.HttpStatus == (baseline ? 200 : 404) &&
            (!baseline || activeProof.OriginalVaultId == plan.VaultId));
        var deletedTask = deletedReader.CollectAsync(deletedWindow, deletedBinding, token).AsTask();
        using var deletedResult = await deletedTask.ConfigureAwait(false);
        Require(deletedReader.TryGetStatusSucceededDeleteVaultCancellationRead(deletedWindow, deletedBinding, deletedTask, out var deletedProof) &&
            deletedProof.StartedAt >= activeProof.FinishedAt && deletedProof.FinishedAt >= deletedProof.StartedAt &&
            deletedProof.Phase == (baseline ? R.StatusSucceededDeleteVaultCancellationReadPhase.BaselineDeleted : R.StatusSucceededDeleteVaultCancellationReadPhase.SelectedDeleted) &&
            deletedProof.HttpStatus == (baseline ? 404 : 200) &&
            (baseline || deletedProof.OriginalVaultId == plan.VaultId));
        token.ThrowIfCancellationRequested();
        var snapshot = provisioner.Journal.Read(owner, session.Selector);
        Require(provisioner.MatchesOwnedPlan(plan, snapshot) && RoleFixtureJournal.StatusSucceededDeleteVaultCancellationRoot(snapshot) &&
            !snapshot.Closing);
        lock (gate)
        {
            Require(!disposed && !session.Closed && !token.IsCancellationRequested);
            if (baseline)
            {
                Require(!session.StartClaimed && snapshot.Idle && snapshot.StatusSucceededDeleteVault!.InvocationDispatch == Guid.Empty);
                string digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                    activeProof.ResponseSha256 + ":" + deletedProof.ResponseSha256)));
                session.StatusSucceededCancellationBaseline = new(session, plan, FreezeStatusSucceededCancellationSnapshot(snapshot), binding, deletedBinding,
                    activeWindow, deletedWindow, activeTask, deletedTask,
                    activeProof, deletedProof, digest, token, requestCancellation);
                session.BaselineAt = deletedProof.FinishedAt;
                session.BaselineReady = true;
                return Reply(Project(session, session.BaselineAt, NativeProvisioningState.Unknown, SecretStatus.Success));
            }
            var observation = new StatusSucceededCancellationObservation(session.StatusSucceededCancellationBaseline!, FreezeStatusSucceededCancellationSnapshot(snapshot),
                start!, statusWindow!, statusTask!, activeWindow, deletedWindow, activeTask, deletedTask,
                activeProof, deletedProof, token, session.StatusSucceededCancellationStartCancellation, requestCancellation);
            Require(StatusSucceededCancellationLive(observation) && session.StatusSucceededCancellationStartDrain is not null &&
                RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(session.StatusSucceededCancellationStartDrain, snapshot));
            session.StatusSucceededCancellationObservation = observation;
            session.Target = start!.Target;
            session.IndependentAt = deletedProof.FinishedAt;
            session.IndependentReady = true;
            return Reply(Project(session, session.IndependentAt, NativeProvisioningState.Succeeded, SecretStatus.Absent));
        }
    }

    private async Task<SecretOutcome<ManagementOperation>> StartStatusSucceededDeleteVaultCancellation(FixtureSelector selector,
        VaultAdministration client, ManagementScope originalScope, ManagementMutation operation, E.Input input,
        ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(!statusSucceededDeleteVaultCancellationCleanup && operation == ManagementMutation.DeleteVault &&
                input.StatusOperation == ManagementMutation.DeleteVault && InputMatches(session, input) &&
                session.Armed && session.BaselineReady && !session.StartClaimed && originalScope is VaultScope vault &&
                vault.ExportResourceId() == session.Plan!.VaultId &&
                provisioner.OwnsStatusSucceededDeleteVaultCancellationPreparation(session.Plan) &&
                session.StatusSucceededCancellationBaseline is { } baseline &&
                before.TryGetStatusSucceededDeleteVaultCancellationRead(baseline.ActiveWindow, baseline.Binding, baseline.ActiveTask, out var activeProof) &&
                ReferenceEquals(activeProof, baseline.Active) &&
                statusCounterpartBeforeCollector!.TryGetStatusSucceededDeleteVaultCancellationRead(baseline.DeletedWindow,
                    baseline.DeletedBinding, baseline.DeletedTask, out var deletedProof) && ReferenceEquals(deletedProof, baseline.Deleted));
            var admission = new StatusSucceededDeleteVaultCancellationAdmission(this);
            Require(statusSucceededCancellationAdmissions.TryAdd(admission, session.StatusSucceededCancellationBaseline!));
            session.StartClaimed = true;
            try
            {
                var committed = provisioner.Journal.BeginStatusSucceededDeleteVaultCancellationInvocation(owner, selector,
                    session.Plan!.LeaseId, admission);
                session.Dispatch = committed.StatusSucceededDeleteVault!.InvocationDispatch;
                var ready = session.StatusSucceededCancellationBaseline!.Ready;
                var expected = ready with
                {
                    Revision = ready.Revision + 1,
                    Resources = ready.Resources.Select(r => r.Id == session.Plan.VaultId
                        ? r with { SelectedAttempted = true, ActiveDispatch = session.Dispatch, InvocationTerminated = false } : r).ToArray(),
                    StatusSucceededDeleteVault = ready.StatusSucceededDeleteVault! with
                    { InvocationDispatch = session.Dispatch, BaselineSha256 = admission.BaselineSha256 }
                };
                Require(RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(expected, committed));
                session.StatusSucceededCancellationBegin = FreezeStatusSucceededCancellationSnapshot(committed);
            }
            finally { statusSucceededCancellationAdmissions.TryRemove(admission, out _); }
            session.Client = client;
            session.Receipt = receipt;
            session.ActualVaultScope = (VaultScope)originalScope;
            session.StatusSucceededCancellationStartCancellation = cancellationToken;
            session.Active++;
            active++;
        }
        try
        {
            // Actual caller scope replaces only C's binding. B and the four R
            // windows retain their own original reference identities.
            session.Binding = new(selector, session.Plan!.LeaseId, originalScope, operation, scope.Location, "2026-02-01");
            session.Capture = capture.Arm(session.Binding);
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, session.Stop.Token, deadline.Token);
            var result = await capture.StartStatusSucceededDeleteVaultCancellationAsync(session.Capture, selector, client,
                (VaultScope)originalScope, input, receipt, linked.Token, task => { lock (gate) session.StartTask = task; },
                () =>
                {
                    linked.Token.ThrowIfCancellationRequested();
                    var current = provisioner.Journal.Read(owner, selector);
                    Require(StatusSucceededCancellationLive(session.StatusSucceededCancellationBaseline!) &&
                        session.StatusSucceededCancellationBegin is not null &&
                        RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(session.StatusSucceededCancellationBegin, current));
                }).ConfigureAwait(false);
            lock (gate)
            {
                session.Handle = result.IsSuccess ? result.Value : null;
                session.StartSucceeded = result.IsSuccess && capture.TryGetStatusSucceededDeleteVaultCancellationStart(session.Capture,
                    session.Binding, client, (VaultScope)originalScope, receipt, session.StartTask!, session.Handle!, out _);
            }
            return result;
        }
        finally
        {
            try
            {
                var committed = provisioner.Journal.EndDispatch(owner, selector, session.Plan!.VaultId, session.Dispatch, nativeSettled: false);
                var begin = session.StatusSucceededCancellationBegin!;
                var expected = begin with
                {
                    Revision = begin.Revision + 1,
                    Resources = begin.Resources.Select(r => r.Id == session.Plan.VaultId
                        ? r with { InvocationTerminated = true } : r).ToArray()
                };
                bool exact = RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(expected, committed);
                lock (gate)
                {
                    session.StatusSucceededCancellationInvalid |= !exact;
                    if (exact) session.StatusSucceededCancellationStartDrain = FreezeStatusSucceededCancellationSnapshot(committed);
                    session.StartFinished = true;
                }
                Require(exact);
            }
            finally { Leave(session); }
        }
    }

    private async Task<SecretStatus> CheckStatusSucceededDeleteVaultCancellation(FixtureSelector selector, ManagementOperation handle,
        CancellationToken cancellationToken)
    {
        Session session;
        StatusSucceededCancellationObservation observation;
        StatusSucceededCancellationCanceled? canceled = null;
        RoleFixtureJournal.Snapshot admitted;
        bool first;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(!statusSucceededDeleteVaultCancellationCleanup && ReferenceEquals(handle, session.Handle));
            first = !session.CancelClaimed;
            bool valid = !session.StatusSucceededCancellationInvalid && !session.StatusClaimed &&
                session.StartFinished && session.StartSucceeded && session.IndependentReady &&
                session.StatusSucceededCancellationObservation is not null && (first
                    ? cancellationToken.IsCancellationRequested
                    : !cancellationToken.IsCancellationRequested && session.CancelFinished &&
                        session.StatusSucceededCancellationCanceledCommitted is not null &&
                        session.StatusSucceededCancellationCanceledDrain is not null &&
                        statusSucceededCancellationCanceledDrains.TryGetValue(session.StatusSucceededCancellationCanceledDrain, out canceled));
            if (first) session.CancelClaimed = true;
            else session.StatusClaimed = true;
            session.StatusSucceededCancellationInvalid |= !valid;
            Require(valid);
            observation = session.StatusSucceededCancellationObservation!;
            Require(StatusSucceededCancellationLive(observation) &&
                capture.TryGetStatusSucceededDeleteVaultCancellationStart(session.Capture!, session.Binding!, session.Client!,
                    session.ActualVaultScope!, session.Receipt!, session.StartTask!, handle, out var start) &&
                ReferenceEquals(start, observation.Start) && observation.StatusTask.IsCompletedSuccessfully &&
                before.TryGetStatusSucceededDeleteVaultCancellationRead(observation.Baseline.ActiveWindow, observation.Baseline.Binding,
                    observation.Baseline.ActiveTask, out var baselineActive) && ReferenceEquals(baselineActive, observation.Baseline.Active) &&
                statusCounterpartBeforeCollector!.TryGetStatusSucceededDeleteVaultCancellationRead(observation.Baseline.DeletedWindow,
                    observation.Baseline.DeletedBinding, observation.Baseline.DeletedTask, out var baselineDeleted) &&
                ReferenceEquals(baselineDeleted, observation.Baseline.Deleted) &&
                after.TryGetStatusSucceededDeleteVaultCancellationRead(observation.ActiveWindow, observation.Baseline.Binding,
                    observation.ActiveTask, out var activeProof) && ReferenceEquals(activeProof, observation.Active) &&
                statusCounterpartAfterCollector!.TryGetStatusSucceededDeleteVaultCancellationRead(observation.DeletedWindow,
                    observation.Baseline.DeletedBinding, observation.DeletedTask, out var deletedProof) &&
                ReferenceEquals(deletedProof, observation.Deleted));
            if (first)
            {
                var admission = new StatusSucceededDeleteVaultCancellationCanceledReadAdmission(this);
                Require(statusSucceededCancellationCanceledAdmissions.TryAdd(admission, observation));
                try
                {
                    admitted = provisioner.Journal.AdmitStatusSucceededDeleteVaultCancellationCanceledRead(owner, selector,
                    session.Plan!.LeaseId, session.Dispatch, admission);
                }
                finally { statusSucceededCancellationCanceledAdmissions.TryRemove(admission, out _); }
            }
            else
            {
                Require(canceled is not null && StatusSucceededCancellationLive(canceled) &&
                    RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(StatusSucceededCancellationDrainPostimage(canceled),
                        session.StatusSucceededCancellationCanceledCommitted!) &&
                    capture.TryGetStatusSucceededDeleteVaultCancellationCanceled(session.Capture!, session.Binding!, session.Client!,
                        session.ActualVaultScope!, session.Receipt!, session.StartTask!, handle, session.CanceledTask!, out var proof) &&
                    ReferenceEquals(proof, canceled.Proof));
                var admission = new StatusSucceededDeleteVaultCancellationReadAdmission(this);
                Require(statusSucceededCancellationReadAdmissions.TryAdd(admission, canceled));
                try
                {
                    admitted = provisioner.Journal.AdmitStatusSucceededDeleteVaultCancellationRead(owner, selector,
                    session.Plan!.LeaseId, session.Dispatch, admission);
                }
                finally { statusSucceededCancellationReadAdmissions.TryRemove(admission, out _); }
            }
            var preimage = first ? observation.Drained : session.StatusSucceededCancellationCanceledCommitted!;
            var expected = preimage with
            {
                Revision = preimage.Revision + 1,
                Resources = preimage.Resources.Select(r => r.Id == session.Plan!.VaultId
                    ? r with { InvocationTerminated = false } : r).ToArray()
            };
            Require(RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(expected, admitted));
            admitted = FreezeStatusSucceededCancellationSnapshot(admitted);
            session.Active++;
            active++;
        }
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = first
                ? CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token, session.Stop.Token, deadline.Token)
                : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, session.Stop.Token, deadline.Token);
            linked.Token.ThrowIfCancellationRequested();
            Require(time.GetUtcNow() >= session.IndependentAt);
            if (first)
            {
                try
                {
                    await capture.CheckCanceledStatusAsync(session.Capture!, selector, handle, cancellationToken,
                        task => { lock (gate) session.CanceledTask = task; }).ConfigureAwait(false);
                    throw Failure();
                }
                catch (OperationCanceledException) when (session.CanceledTask is { IsCanceled: true })
                {
                    Require(capture.TryGetStatusSucceededDeleteVaultCancellationCanceled(session.Capture!, session.Binding!, session.Client!,
                        session.ActualVaultScope!, session.Receipt!, session.StartTask!, handle, session.CanceledTask, out var proof) &&
                        ReferenceEquals(proof.Start, observation.Start) && !linked.IsCancellationRequested);
                    var fact = new StatusSucceededCancellationCanceled(observation, admitted, session.Capture!, session.Client!,
                        session.ActualVaultScope!, session.Receipt!, session.StartTask!, handle, session.CanceledTask, proof,
                        cancellationToken, linked.Token);
                    var drain = new StatusSucceededDeleteVaultCancellationCanceledDrain(this);
                    Require(statusSucceededCancellationCanceledDrains.TryAdd(drain, fact));
                    lock (gate) session.StatusSucceededCancellationCanceledDrain = drain;
                    PersistStatusSucceededDeleteVaultCancellation(session);
                    throw;
                }
            }
            var result = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            Require(result == SecretStatus.Success);
            Require(capture.TryGetStatusSucceededDeleteVaultCancellationCompletion(session.Capture!, session.Binding!, session.Client!,
                    session.ActualVaultScope!, session.Receipt!, session.StartTask!, handle, session.CanceledTask!, session.StatusTask!, out var completionProof) &&
                ReferenceEquals(completionProof.Start, observation.Start) && ReferenceEquals(completionProof.Canceled, canceled!.Proof));
            var completion = new StatusSucceededCancellationCompletion(canceled!, admitted, session.StatusTask!, completionProof,
                linked.Token, cancellationToken);
            var certificate = new StatusSucceededDeleteVaultCancellationSettlement(this);
            Require(statusSucceededCancellationSettlements.TryAdd(certificate, completion));
            lock (gate) session.StatusSucceededCancellationSettlement = certificate;
            PersistStatusSucceededDeleteVaultCancellation(session);
            return result;
        }
        finally
        {
            try
            {
                bool retained = first
                    ? session.StatusSucceededCancellationCanceledDrain is { } drain &&
                        statusSucceededCancellationCanceledDrains.TryGetValue(drain, out var c) && StatusSucceededCancellationLive(c)
                    : session.StatusSucceededCancellationSettlement is { } completion &&
                        statusSucceededCancellationSettlements.TryGetValue(completion, out var f) && StatusSucceededCancellationLive(f);
                if (!retained)
                {
                    InvalidateStatusSucceededDeleteVaultCancellation(session);
                    DrainStatusSucceededDeleteVaultCancellation(session);
                }
            }
            finally { Leave(session); }
        }
    }

    internal void RetryStatusSucceededDeleteVaultCancellationPersistence(FixtureSelector selector)
    {
        Require(statusSucceededDeleteVaultCancellationProfile && !statusSucceededDeleteVaultCancellationCleanup &&
            VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationSelector(selector));
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(session.Active == 0 && !session.StatusSucceededCancellationInvalid &&
                (session.StatusSucceededCancellationCanceledDrain is not null || session.StatusSucceededCancellationSettlement is not null));
            session.Active++;
            active++;
        }
        try { PersistStatusSucceededDeleteVaultCancellation(session); }
        finally { Leave(session); }
    }

    private void PersistStatusSucceededDeleteVaultCancellation(Session session)
    {
        var final = session.StatusSucceededCancellationSettlement;
        var drain = session.StatusSucceededCancellationCanceledDrain;
        StatusSucceededCancellationCompletion? completion = null;
        StatusSucceededCancellationCanceled? canceled = null;
        Require(final is not null ? statusSucceededCancellationSettlements.TryGetValue(final, out completion) :
            drain is not null && statusSucceededCancellationCanceledDrains.TryGetValue(drain, out canceled));
        var expected = completion is not null ? StatusSucceededCancellationPostimage(completion) : StatusSucceededCancellationDrainPostimage(canceled!);
        RoleFixtureJournal.Snapshot current;
        try { current = provisioner.Journal.Read(owner, session.Selector); }
        catch (RoleFixtureJournal.StatusSucceededDeleteVaultCancellationHistoryException)
        { InvalidateStatusSucceededDeleteVaultCancellation(session); throw; }
        bool live = completion is not null ? StatusSucceededCancellationLive(completion) : StatusSucceededCancellationLive(canceled!);
        if (!live || !(RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(expected, current) ||
            (final is not null ? final.Validate(provisioner.Journal, current) : drain!.Validate(provisioner.Journal, current))))
        {
            InvalidateStatusSucceededDeleteVaultCancellation(session);
            DrainStatusSucceededDeleteVaultCancellation(session);
            throw Failure();
        }
        if (!RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(expected, current))
        {
            try
            {
                current = final is not null
                    ? provisioner.Journal.CompleteStatusSucceededDeleteVaultCancellationRead(owner, session.Selector, session.Plan!.LeaseId,
                        session.Dispatch, final)
                    : provisioner.Journal.EndStatusSucceededDeleteVaultCancellationCanceledRead(owner, session.Selector, session.Plan!.LeaseId,
                        session.Dispatch, drain!);
            }
            catch (RoleFixtureJournal.StatusSucceededDeleteVaultCancellationHistoryException)
            { InvalidateStatusSucceededDeleteVaultCancellation(session); throw; }
            Require(RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(expected, current));
        }
        lock (gate)
        {
            if (final is not null) session.StatusSucceeded = true;
            else
            {
                session.StatusSucceededCancellationCanceledCommitted = FreezeStatusSucceededCancellationSnapshot(current);
                session.CancelFinished = true;
            }
        }
    }

    private void InvalidateStatusSucceededDeleteVaultCancellation(Session session)
    {
        lock (gate)
        {
            session.StatusSucceededCancellationInvalid = true;
            if (session.StatusSucceededCancellationCanceledDrain is { } drain)
                statusSucceededCancellationCanceledDrains.TryRemove(drain, out _);
            if (session.StatusSucceededCancellationSettlement is { } completion)
                statusSucceededCancellationSettlements.TryRemove(completion, out _);
            session.StatusSucceededCancellationCanceledDrain = null;
            session.StatusSucceededCancellationSettlement = null;
        }
    }

    private void DrainStatusSucceededDeleteVaultCancellation(Session session)
    {
        if (session.Plan is null || session.Dispatch == Guid.Empty) return;
        var snapshot = provisioner.Journal.Read(owner, session.Selector);
        Require(RoleFixtureJournal.StatusSucceededDeleteVaultCancellationRoot(snapshot) && provisioner.MatchesOwnedPlan(session.Plan, snapshot));
        var row = snapshot.Resources.Single(r => r.Id == session.Plan.VaultId);
        if (row.ActiveDispatch == session.Dispatch && !row.InvocationTerminated)
            provisioner.Journal.EndDispatch(owner, session.Selector, row.Id, session.Dispatch, nativeSettled: false);
    }

    private async Task<HttpResponseMessage> ObserveStatusSucceededDeleteVaultIndependent(Session session, bool baseline, CancellationToken token)
    {
        var plan = session.Plan!;
        Require(plan.StatusSucceededDeleteVaultIndependentProfile && !plan.Restored &&
            provisioner.OwnsStatusSucceededDeleteVaultIndependentPreparation(plan));
        var binding = baseline ? session.Binding! : session.StatusSucceededIndependentBaseline!.Binding;
        var deletedBinding = session.CounterpartBinding!;
        C.StatusSucceededDeleteVaultIndependentStartProof? start = null;
        S.Window? statusWindow = null;
        Task<S.Measurement>? statusTask = null;
        DateTimeOffset earliest = session.ArmedAt;
        if (!baseline)
        {
            Require(session.StatusSucceededIndependentBaseline is not null &&
                capture.TryGetStatusSucceededDeleteVaultIndependentStart(session.Capture!, session.Binding!, session.Client!,
                    session.ActualVaultScope!, session.Receipt!, session.StartTask!, session.Handle!, out start));
            Require(capture.TryGetStatusTarget(session.Capture!, session.Binding!, out var target) &&
                ReferenceEquals(start!.Target, target));
            statusWindow = statuses.Arm(target, session.Binding!);
            statusTask = statuses.CollectAsync(statusWindow, session.Binding!, token).AsTask();
            var status = await statusTask.ConfigureAwait(false);
            Require(ReferenceEquals(status.Binding, session.Binding) && status.WindowId == statusWindow.Id &&
                status.ArmedAt == statusWindow.ArmedAt && status.ArmedAt >= session.StartedAt &&
                status.StartedAt >= status.ArmedAt && status.FinishedAt >= status.StartedAt &&
                status.HttpStatus == 200 && status.ResponseComplete && status.Terminal &&
                status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
                status.StartDispatch == target.StartDispatch && status.TargetSha256 == target.TargetSha256 &&
                status.StartResponseSha256 == target.StartResponseSha256 && Text(status.NativeRequestId, 256));
            earliest = status.FinishedAt;
        }
        var activeReader = baseline ? before : after;
        var deletedReader = baseline ? statusCounterpartBeforeCollector! : statusCounterpartAfterCollector!;
        var activeWindow = baseline ? session.Before! : session.After!;
        var deletedWindow = baseline ? session.CounterpartBefore! : session.CounterpartAfter!;
        var activeTask = activeReader.CollectAsync(activeWindow, binding, token).AsTask();
        using var activeResult = await activeTask.ConfigureAwait(false);
        Require(activeReader.TryGetStatusSucceededDeleteVaultIndependentRead(activeWindow, binding, activeTask, out var activeProof) &&
            activeProof.StartedAt >= earliest && activeProof.FinishedAt >= activeProof.StartedAt &&
            activeProof.Phase == (baseline ? R.StatusSucceededDeleteVaultIndependentReadPhase.BaselineActive : R.StatusSucceededDeleteVaultIndependentReadPhase.SelectedActive) &&
            activeProof.HttpStatus == (baseline ? 200 : 404) &&
            (!baseline || activeProof.OriginalVaultId == plan.VaultId));
        var deletedTask = deletedReader.CollectAsync(deletedWindow, deletedBinding, token).AsTask();
        using var deletedResult = await deletedTask.ConfigureAwait(false);
        Require(deletedReader.TryGetStatusSucceededDeleteVaultIndependentRead(deletedWindow, deletedBinding, deletedTask, out var deletedProof) &&
            deletedProof.StartedAt >= activeProof.FinishedAt && deletedProof.FinishedAt >= deletedProof.StartedAt &&
            deletedProof.Phase == (baseline ? R.StatusSucceededDeleteVaultIndependentReadPhase.BaselineDeleted : R.StatusSucceededDeleteVaultIndependentReadPhase.SelectedDeleted) &&
            deletedProof.HttpStatus == (baseline ? 404 : 200) &&
            (baseline || deletedProof.OriginalVaultId == plan.VaultId));
        token.ThrowIfCancellationRequested();
        var snapshot = provisioner.Journal.Read(owner, session.Selector);
        Require(provisioner.MatchesOwnedPlan(plan, snapshot) && RoleFixtureJournal.StatusSucceededDeleteVaultIndependentRoot(snapshot) &&
            !snapshot.Closing);
        lock (gate)
        {
            Require(!disposed && !session.Closed && !token.IsCancellationRequested);
            if (baseline)
            {
                Require(!session.StartClaimed && snapshot.Idle && snapshot.StatusSucceededDeleteVault!.InvocationDispatch == Guid.Empty);
                string digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                    activeProof.ResponseSha256 + ":" + deletedProof.ResponseSha256)));
                session.StatusSucceededIndependentBaseline = new(plan, snapshot.Revision, Array.AsReadOnly(snapshot.Resources.ToArray()),
                    statusSucceededIndependentConfiguration! with { Policies = [] }, binding, deletedBinding,
                    activeWindow, deletedWindow, activeTask, deletedTask,
                    activeProof, deletedProof, digest, token);
                session.BaselineAt = deletedProof.FinishedAt;
                session.BaselineReady = true;
                return Reply(Project(session, session.BaselineAt, NativeProvisioningState.Unknown, SecretStatus.Success));
            }
            var observation = new StatusSucceededIndependentObservation(session.StatusSucceededIndependentBaseline!, session.Dispatch, snapshot.Revision,
                start!, statusWindow!, statusTask!, activeWindow, deletedWindow, activeTask, deletedTask,
                activeProof, deletedProof, token, session.StatusSucceededIndependentStartCancellation);
            Require(StatusSucceededIndependentSelectedRoot(observation, snapshot, terminated: true));
            session.StatusSucceededIndependentObservation = observation;
            session.Target = start!.Target;
            session.IndependentAt = deletedProof.FinishedAt;
            session.IndependentReady = true;
            return Reply(Project(session, session.IndependentAt, NativeProvisioningState.Succeeded, SecretStatus.Absent));
        }
    }

    private async Task<SecretOutcome<ManagementOperation>> StartStatusSucceededDeleteVaultIndependent(FixtureSelector selector,
        VaultAdministration client, ManagementScope originalScope, ManagementMutation operation, E.Input input,
        ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(!statusSucceededDeleteVaultIndependentCleanup && operation == ManagementMutation.DeleteVault &&
                input.StatusOperation == ManagementMutation.DeleteVault && InputMatches(session, input) &&
                session.Armed && session.BaselineReady && !session.StartClaimed && originalScope is VaultScope vault &&
                vault.ExportResourceId() == session.Plan!.VaultId &&
                provisioner.OwnsStatusSucceededDeleteVaultIndependentPreparation(session.Plan) &&
                session.StatusSucceededIndependentBaseline is { } baseline &&
                before.TryGetStatusSucceededDeleteVaultIndependentRead(baseline.ActiveWindow, baseline.Binding, baseline.ActiveTask, out var activeProof) &&
                ReferenceEquals(activeProof, baseline.Active) &&
                statusCounterpartBeforeCollector!.TryGetStatusSucceededDeleteVaultIndependentRead(baseline.DeletedWindow,
                    baseline.DeletedBinding, baseline.DeletedTask, out var deletedProof) && ReferenceEquals(deletedProof, baseline.Deleted));
            var admission = new StatusSucceededDeleteVaultIndependentAdmission(this);
            Require(statusSucceededIndependentAdmissions.TryAdd(admission, session.StatusSucceededIndependentBaseline!));
            session.StartClaimed = true;
            try
            {
                session.Dispatch = provisioner.Journal.BeginStatusSucceededDeleteVaultIndependentInvocation(owner, selector,
                    session.Plan!.LeaseId, admission);
            }
            finally { statusSucceededIndependentAdmissions.TryRemove(admission, out _); }
            session.Client = client;
            session.Receipt = receipt;
            session.ActualVaultScope = (VaultScope)originalScope;
            session.StatusSucceededIndependentStartCancellation = cancellationToken;
            session.Active++;
            active++;
        }
        try
        {
            // Actual caller scope replaces only C's binding. B and the four R
            // windows retain their own original reference identities.
            session.Binding = new(selector, session.Plan!.LeaseId, originalScope, operation, scope.Location, "2026-02-01");
            session.Capture = capture.Arm(session.Binding);
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, session.Stop.Token, deadline.Token);
            var result = await capture.StartStatusSucceededDeleteVaultIndependentAsync(session.Capture, selector, client,
                (VaultScope)originalScope, input, receipt, linked.Token, task => { lock (gate) session.StartTask = task; },
                () =>
                {
                    linked.Token.ThrowIfCancellationRequested();
                    var current = provisioner.Journal.Read(owner, selector);
                    Require(StatusSucceededIndependentRoot(session.StatusSucceededIndependentBaseline!, current) &&
                        current.StatusSucceededDeleteVault!.InvocationDispatch == session.Dispatch &&
                        current.StatusSucceededDeleteVault.SettledDispatch == Guid.Empty &&
                        current.Resources.Single(r => r.Id == session.Plan.VaultId) is
                        { SelectedAttempted: true, DeleteAttempted: false, InvocationTerminated: false, ActiveDispatch: var dispatch } &&
                        dispatch == session.Dispatch);
                }).ConfigureAwait(false);
            lock (gate)
            {
                session.Handle = result.IsSuccess ? result.Value : null;
                session.StartSucceeded = result.IsSuccess && capture.TryGetStatusSucceededDeleteVaultIndependentStart(session.Capture,
                    session.Binding, client, (VaultScope)originalScope, receipt, session.StartTask!, session.Handle!, out _);
            }
            return result;
        }
        finally
        {
            try
            {
                provisioner.Journal.EndDispatch(owner, selector, session.Plan!.VaultId, session.Dispatch, nativeSettled: false);
                lock (gate) session.StartFinished = true;
            }
            finally { Leave(session); }
        }
    }

    private async Task<SecretStatus> CheckStatusSucceededDeleteVaultIndependent(FixtureSelector selector, ManagementOperation handle,
        CancellationToken cancellationToken)
    {
        Session session;
        StatusSucceededIndependentObservation observation;
        RoleFixtureJournal.Snapshot admitted;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(!session.StatusClaimed && session.StartFinished && session.StartSucceeded && session.IndependentReady &&
                ReferenceEquals(handle, session.Handle) && session.StatusSucceededIndependentObservation is not null);
            session.StatusClaimed = true;
            cancellationToken.ThrowIfCancellationRequested();
            observation = session.StatusSucceededIndependentObservation;
            // Refresh every external proof outside the journal transaction.
            Require(capture.TryGetStatusSucceededDeleteVaultIndependentStart(session.Capture!, session.Binding!, session.Client!,
                    session.ActualVaultScope!, session.Receipt!, session.StartTask!, handle, out var start) &&
                ReferenceEquals(start, observation.Start) && observation.StatusTask.IsCompletedSuccessfully &&
                after.TryGetStatusSucceededDeleteVaultIndependentRead(observation.ActiveWindow, observation.Baseline.Binding,
                    observation.ActiveTask, out var activeProof) && ReferenceEquals(activeProof, observation.Active) &&
                statusCounterpartAfterCollector!.TryGetStatusSucceededDeleteVaultIndependentRead(observation.DeletedWindow,
                    observation.Baseline.DeletedBinding, observation.DeletedTask, out var deletedProof) &&
                ReferenceEquals(deletedProof, observation.Deleted));
            var admission = new StatusSucceededDeleteVaultIndependentReadAdmission(this);
            Require(statusSucceededIndependentReadAdmissions.TryAdd(admission, observation));
            try
            {
                admitted = provisioner.Journal.AdmitStatusSucceededDeleteVaultIndependentRead(owner, selector, session.Plan!.LeaseId,
                    session.Dispatch, admission);
            }
            finally { statusSucceededIndependentReadAdmissions.TryRemove(admission, out _); }
            session.Active++;
            active++;
        }
        bool settled = false;
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, session.Stop.Token, deadline.Token);
            Require(time.GetUtcNow() >= session.IndependentAt);
            var result = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            Require(result == SecretStatus.Success);
            Require(capture.TryGetStatusSucceededDeleteVaultIndependentCompletion(session.Capture!, session.Binding!, session.Client!,
                    session.ActualVaultScope!, session.Receipt!, session.StartTask!, handle, session.StatusTask!, out var proof) &&
                ReferenceEquals(proof.Start, observation.Start));
            var completion = new StatusSucceededIndependentCompletion(observation, admitted, session.Capture!, session.Client!,
                session.ActualVaultScope!, session.Receipt!, session.StartTask!, handle, session.StatusTask!, proof,
                linked.Token, cancellationToken);
            var certificate = new StatusSucceededDeleteVaultIndependentSettlement(this);
            Require(statusSucceededIndependentSettlements.TryAdd(certificate, completion));
            lock (gate) session.StatusSucceededIndependentSettlement = certificate;
            SettleStatusSucceededDeleteVaultIndependent(session);
            settled = true;
            return result;
        }
        finally
        {
            try
            {
                if (!settled)
                {
                    bool retained;
                    lock (gate)
                    {
                        retained = !session.Closed && !disposed && !cancellationToken.IsCancellationRequested &&
                            session.StatusSucceededIndependentSettlement is { } candidate &&
                            statusSucceededIndependentSettlements.ContainsKey(candidate);
                        if (!retained && session.StatusSucceededIndependentSettlement is { } invalid)
                        {
                            statusSucceededIndependentSettlements.TryRemove(invalid, out _);
                            session.StatusSucceededIndependentSettlement = null;
                        }
                    }
                    // A retained candidate owns the exact admitted preimage. Do
                    // not append a drain and silently move its expected revision.
                    if (!retained) DrainStatusSucceededDeleteVaultIndependent(session);
                }
            }
            finally { Leave(session); }
        }
    }

    internal void RetryStatusSucceededDeleteVaultIndependentSettlement(FixtureSelector selector)
    {
        Require(statusSucceededDeleteVaultIndependentProfile && !statusSucceededDeleteVaultIndependentCleanup &&
            VaultFixtureProvisioner.StatusSucceededDeleteVaultIndependentSelector(selector));
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(session.Active == 0 && session.StatusSucceededIndependentSettlement is not null);
            session.Active++;
            active++;
        }
        try { SettleStatusSucceededDeleteVaultIndependent(session); }
        finally { Leave(session); }
    }

    private void SettleStatusSucceededDeleteVaultIndependent(Session session)
    {
        var certificate = session.StatusSucceededIndependentSettlement;
        Require(certificate is not null && statusSucceededIndependentSettlements.TryGetValue(certificate, out _));
        var completion = statusSucceededIndependentSettlements[certificate];
        RoleFixtureJournal.Snapshot snapshot;
        try { snapshot = provisioner.Journal.Read(owner, session.Selector); }
        catch (RoleFixtureJournal.StatusSucceededDeleteVaultIndependentHistoryException)
        {
            statusSucceededIndependentSettlements.TryRemove(certificate, out _);
            lock (gate) session.StatusSucceededIndependentSettlement = null;
            throw;
        }
        bool live = !disposed && !session.Closed && !completion.Cancellation.IsCancellationRequested &&
            !completion.CallerCancellation.IsCancellationRequested &&
            !completion.Observation.Cancellation.IsCancellationRequested &&
            !completion.Observation.StartCancellation.IsCancellationRequested;
        if (live && StatusSucceededIndependentPostimage(completion, snapshot))
        {
            lock (gate) session.StatusSucceeded = true;
            return;
        }
        if (!live || !certificate.Validate(provisioner.Journal, snapshot))
        {
            statusSucceededIndependentSettlements.TryRemove(certificate, out _);
            lock (gate) session.StatusSucceededIndependentSettlement = null;
            DrainStatusSucceededDeleteVaultIndependent(session);
            throw Failure();
        }
        // Keep this capability before append. File contention or an ambiguous
        // append may be retried against only this exact preimage/postimage.
        RoleFixtureJournal.Snapshot committed;
        try
        {
            committed = provisioner.Journal.CompleteStatusSucceededDeleteVaultIndependentRead(owner,
                session.Selector, session.Plan!.LeaseId, session.Dispatch, certificate);
        }
        catch (RoleFixtureJournal.StatusSucceededDeleteVaultIndependentHistoryException)
        {
            statusSucceededIndependentSettlements.TryRemove(certificate, out _);
            lock (gate) session.StatusSucceededIndependentSettlement = null;
            throw;
        }
        Require(StatusSucceededIndependentPostimage(completion, committed));
        lock (gate) session.StatusSucceeded = true;
    }

    private static bool StatusSucceededIndependentPostimage(StatusSucceededIndependentCompletion completion,
        RoleFixtureJournal.Snapshot snapshot)
    {
        var observation = completion.Observation;
        var expected = completion.Admitted;
        return snapshot.Revision == expected.Revision + 1 &&
            StatusSucceededIndependentRoot(observation.Baseline, snapshot) &&
            snapshot.StatusSucceededDeleteVault!.InvocationDispatch == observation.Dispatch &&
            snapshot.StatusSucceededDeleteVault.SettledDispatch == observation.Dispatch &&
            snapshot.StatusSucceededDeleteVault.BaselineSha256 == observation.Baseline.Digest &&
            snapshot.Resources.SequenceEqual(expected.Resources.Select(r => r.Id == observation.Baseline.Plan.VaultId
                ? r with { InvocationTerminated = true, ActiveDispatch = Guid.Empty } : r));
    }

    private void DrainStatusSucceededDeleteVaultIndependent(Session session)
    {
        var snapshot = provisioner.Journal.Read(owner, session.Selector);
        Require(RoleFixtureJournal.StatusSucceededDeleteVaultIndependentRoot(snapshot) &&
            provisioner.MatchesOwnedPlan(session.Plan!, snapshot));
        var row = snapshot.Resources.Single(r => r.Id == session.Plan!.VaultId);
        if (row.ActiveDispatch == session.Dispatch && !row.InvocationTerminated)
            provisioner.Journal.EndDispatch(owner, session.Selector, row.Id, session.Dispatch, nativeSettled: false);
    }

    private async Task<HttpResponseMessage> ObserveStatusNotificationCreateCancellation(Session session, bool baseline,
        CancellationToken token)
    {
        var slot = baseline ? session.StatusNotificationBefore : session.StatusNotificationAfter;
        Require(slot is not null && slot.Baseline == baseline && slot.Subscription == session.Subscription &&
            slot.ArmedAt == session.ArmedAt && ReferenceEquals(slot.Source, session.Notifications) &&
            ReferenceEquals(slot.Child, session.NotificationPlan) && ReferenceEquals(slot.Parent, session.Plan) &&
            ReferenceEquals(slot.Binding, session.Binding));
        bool absent = notificationSource!.ExclusiveCreation is not null;
        Require(slot.Child.Preparation == (absent ? NotificationFixtureProvisioner.Preparation.Absent :
            NotificationFixtureProvisioner.Preparation.Present));
        RequireNotificationJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: !baseline);
        C.StatusNotificationCreateCancellationStartProof? start = null;
        C.StatusTarget? target = null;
        S.Window? statusWindow = null;
        Task<S.Measurement>? statusTask = null;
        DateTimeOffset afterStatus = session.ArmedAt;
        if (!baseline)
        {
            Require(session.StatusNotificationCreateBaseline is not null && session.StartFinished &&
                session.StartTask is { IsCompletedSuccessfully: true } &&
                capture.TryGetStatusNotificationCreateCancellationStart(session.Capture!, session.Binding!,
                    session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask,
                    session.Handle!, out start) &&
                capture.TryGetStatusTarget(session.Capture!, session.Binding!, out target) &&
                capture.OwnsStatusTarget(target, session.Binding!));
            statusWindow = statuses.Arm(target, session.Binding!);
            statusTask = statuses.CollectAsync(statusWindow, session.Binding!, token).AsTask();
            var status = await statusTask.ConfigureAwait(false);
            Require(ReferenceEquals(status.Binding, session.Binding) && status.WindowId == statusWindow.Id &&
                status.ResponseComplete && status.Terminal && status.HttpStatus == 200 &&
                status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
                status.StartDispatch == target.StartDispatch && status.TargetSha256 == target.TargetSha256 &&
                status.StartResponseSha256 == target.StartResponseSha256 &&
                status.StartedAt >= session.StartedAt && status.FinishedAt >= status.StartedAt &&
                Text(status.NativeRequestId, 256));
            afterStatus = status.FinishedAt;
            if (absent)
                slot.Source.BindAbsentCreationStart(slot.Child, session.StatusNotificationCreateBaseline!.Proof,
                    capture, session.Capture!, session.Binding!, session.Client!, session.ActualNotificationScope!,
                    session.Receipt!, session.StartTask!, session.Handle!);
        }
        var task = baseline
            ? slot.Source.ObserveAsync(owner, session.Selector, slot.Child.Scope.SubscriptionName, token).AsTask()
            : slot.Source.ObserveSelectedAsync(slot.Child, session.Dispatch, token).AsTask();
        using var measured = await task.ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        var proof = measured.StatusCreateRead ?? throw Failure();
        Require(slot.Source.OwnsStatusNotificationCreateRead(proof, slot.Child, baseline ? Guid.Empty : session.Dispatch) &&
            proof.RequestSha256.Length == 64 && proof.ResponseSha256.Length == 64 && Text(proof.NativeRequestId, 256) &&
            proof.StartedAt >= afterStatus && proof.FinishedAt >= proof.StartedAt &&
            measured.ObservedAt >= proof.FinishedAt &&
            (absent && baseline
                ? proof.NativeTask.IsFaulted && proof is { Present: false, HttpStatus: 404, NativeState: null } &&
                    measured.Present == false && measured.Configuration is null &&
                    slot.Source.OwnsExclusiveCreation(slot.Child, measured.Journal)
                : proof.NativeTask.IsCompletedSuccessfully &&
                    proof is { Present: true, HttpStatus: 200, NativeState: "Succeeded" } &&
                    measured.Present == true && measured.Configuration is not null &&
                    NotificationConfigurationMatches(measured.Configuration,
                        baseline ? VaultNotificationEvent.SecretNearExpiry : VaultNotificationEvent.SecretNewVersionCreated)));
        RequireNotificationJournal(session, measured.Journal, selected: !baseline);
        var configuration = measured.Configuration is null ? null : new NotificationConfiguration(measured.Configuration.Endpoint.Reveal(),
            measured.Configuration.EventTypes, measured.Configuration.DeliveryAttributes);
        bool retained = false;
        try
        {
            lock (gate)
            {
                Require(!disposed && !session.Closed && !token.IsCancellationRequested);
                if (baseline)
                {
                    Require(!session.StartClaimed && session.StatusNotificationCreateBaseline is null &&
                        measured.State == NotificationFixtureProvisioner.State.Ready);
                    session.StatusNotificationCreateBaseline = new(slot, task, proof,
                        Array.AsReadOnly(measured.Journal.Resources.ToArray()), configuration, measured.ObservedAt,
                        measured.Journal.NotificationAbsentCreate, NotificationFixtureProvisioner.ReadDigest(proof));
                    session.BaselineAt = measured.ObservedAt;
                    session.BaselineReady = true;
                }
                else
                {
                    Require(session.StatusNotificationCreateObservation is null &&
                        measured.State == NotificationFixtureProvisioner.State.Pending &&
                        ReferenceEquals(measured.SelectedPlan, slot.Child) && measured.SelectedDispatch == session.Dispatch &&
                        proof.StartedAt >= session.StatusNotificationCreateBaseline!.FinishedAt &&
                        configuration is not null && configuration.DeliveryAttributes.Count == 0 &&
                        (absent
                            ? session.StatusNotificationCreateBaseline.Configuration is null &&
                                start!.NamespaceEpoch == session.StatusNotificationCreateBaseline.AbsentCreate!.NamespaceEpoch &&
                                start.SelectedDispatch == session.Dispatch
                            : session.StatusNotificationCreateBaseline.Configuration is { } before &&
                                configuration.Endpoint.Reveal() == before.Endpoint.Reveal() &&
                                !configuration.EventTypes.SequenceEqual(before.EventTypes) &&
                                before.DeliveryAttributes.Count == 0) &&
                        capture.TryGetStatusNotificationCreateCancellationStart(session.Capture!, session.Binding!,
                            session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!,
                            session.Handle!, out var issued) && ReferenceEquals(start, issued));
                    session.StatusNotificationCreateObservation = new(session.StatusNotificationCreateBaseline!, slot, task,
                        proof, configuration, start!, target!, statusWindow!, statusTask!, measured.ObservedAt);
                    session.Target = target;
                    session.IndependentAt = measured.ObservedAt;
                    session.IndependentReady = true;
                }
                retained = true;
            }
            return Reply(ProjectNotification(session, measured.ObservedAt,
                baseline ? NativeProvisioningState.Unknown : NativeProvisioningState.Succeeded, measured.Configuration));
        }
        finally { if (!retained) configuration?.Dispose(); }
    }

    private async Task<HttpResponseMessage> ObserveStatusNotificationUpdateIndependent(Session session, bool baseline,
        CancellationToken token)
    {
        var slot = baseline ? session.NotificationUpdateIndependentBefore : session.NotificationUpdateIndependentAfter;
        Require(slot is not null && slot.Nonce != Guid.Empty && slot.Baseline == baseline && slot.Subscription == session.Subscription &&
            slot.ArmedAt == session.ArmedAt && ReferenceEquals(slot.Source, session.Notifications) &&
            ReferenceEquals(slot.Child, session.NotificationPlan) && ReferenceEquals(slot.Parent, session.Plan) &&
            ReferenceEquals(slot.Binding, session.Binding));
        RequireNotificationJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: !baseline);
        C.StatusNotificationUpdateIndependentStartProof? start = null;
        C.StatusTarget? target = null;
        S.Window? statusWindow = null;
        Task<S.Measurement>? statusTask = null;
        DateTimeOffset afterStatus = session.ArmedAt;
        if (!baseline)
        {
            Require(session.NotificationUpdateIndependentBaseline is not null && session.StartFinished &&
                session.StartTask is { IsCompletedSuccessfully: true } &&
                capture.TryGetStatusNotificationUpdateIndependentStart(session.Capture!, session.Binding!,
                    session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask,
                    session.Handle!, out start) &&
                capture.TryGetStatusTarget(session.Capture!, session.Binding!, out target) &&
                capture.OwnsStatusTarget(target, session.Binding!));
            statusWindow = statuses.Arm(target, session.Binding!);
            statusTask = statuses.CollectAsync(statusWindow, session.Binding!, token).AsTask();
            var status = await statusTask.ConfigureAwait(false);
            Require(ReferenceEquals(status.Binding, session.Binding) && status.WindowId == statusWindow.Id &&
                status.ResponseComplete && status.Terminal && status.HttpStatus == 200 &&
                status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
                status.StartDispatch == target.StartDispatch && status.TargetSha256 == target.TargetSha256 &&
                status.StartResponseSha256 == target.StartResponseSha256 &&
                status.StartedAt >= session.StartedAt && status.FinishedAt >= status.StartedAt &&
                Text(status.NativeRequestId, 256));
            afterStatus = status.FinishedAt;
        }
        var task = baseline
            ? slot.Source.ObserveAsync(owner, session.Selector, slot.Child.Scope.SubscriptionName, token).AsTask()
            : slot.Source.ObserveSelectedAsync(slot.Child, session.Dispatch, token).AsTask();
        using var measured = await task.ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        var proof = measured.StatusUpdateIndependentRead ?? throw Failure();
        Require(slot.Source.OwnsStatusNotificationUpdateIndependentRead(proof, slot.Child, baseline ? Guid.Empty : session.Dispatch) &&
            proof.NativeTask.IsCompletedSuccessfully && proof.HttpStatus == 200 && proof.NativeState == "Succeeded" &&
            proof.RequestSha256.Length == 64 && proof.ResponseSha256.Length == 64 && Text(proof.NativeRequestId, 256) &&
            proof.StartedAt >= afterStatus && proof.FinishedAt >= proof.StartedAt &&
            measured.ObservedAt >= proof.FinishedAt && measured.Present == true &&
            measured.Configuration is not null && NotificationConfigurationMatches(measured.Configuration,
                baseline ? VaultNotificationEvent.SecretNearExpiry : VaultNotificationEvent.SecretNewVersionCreated));
        RequireNotificationJournal(session, measured.Journal, selected: !baseline);
        Require(RoleFixtureJournal.SameStatusNotificationUpdateIndependentSnapshot(baseline
            ? session.NotificationUpdateIndependentReady! : session.NotificationUpdateIndependentDrained!, measured.Journal));
        var configuration = new NotificationConfiguration(measured.Configuration.Endpoint.Reveal(),
            measured.Configuration.EventTypes, measured.Configuration.DeliveryAttributes);
        bool retained = false;
        try
        {
            lock (gate)
            {
                Require(!disposed && !session.Closed && !token.IsCancellationRequested &&
                    !session.NotificationUpdateIndependentInvalid && session.NotificationUpdateIndependentTokens.All(t => !t.IsCancellationRequested));
                if (baseline)
                {
                    Require(!session.StartClaimed && session.NotificationUpdateIndependentBaseline is null &&
                        measured.State == NotificationFixtureProvisioner.State.Ready);
                    session.NotificationUpdateIndependentBaseline = new(slot, task, proof,
                        Array.AsReadOnly(measured.Journal.Resources.ToArray()), configuration, measured.ObservedAt);
                    session.BaselineAt = measured.ObservedAt;
                    session.BaselineReady = true;
                }
                else
                {
                    Require(session.NotificationUpdateIndependentObservation is null &&
                        measured.State == NotificationFixtureProvisioner.State.Pending &&
                        ReferenceEquals(measured.SelectedPlan, slot.Child) && measured.SelectedDispatch == session.Dispatch &&
                        proof.StartedAt >= session.NotificationUpdateIndependentBaseline!.FinishedAt &&
                        capture.TryGetStatusNotificationUpdateIndependentStart(session.Capture!, session.Binding!,
                            session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!,
                            session.Handle!, out var issued) && ReferenceEquals(start, issued));
                    session.NotificationUpdateIndependentObservation = new(session.NotificationUpdateIndependentBaseline!, slot, task,
                        proof, configuration, start!, target!, statusWindow!, statusTask!, measured.ObservedAt);
                    session.Target = target;
                    session.IndependentAt = measured.ObservedAt;
                    session.IndependentReady = true;
                }
                retained = true;
            }
            return Reply(ProjectNotification(session, measured.ObservedAt,
                baseline ? NativeProvisioningState.Unknown : NativeProvisioningState.Succeeded, measured.Configuration));
        }
        finally { if (!retained) configuration.Dispose(); }
    }

    private async ValueTask<SecretOutcome<ManagementOperation>> StartStatusNotificationUpdateIndependent(
        FixtureSelector selector, VaultAdministration client, ManagementScope originalScope, ManagementMutation operation,
        E.Input input, ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        ValidateSelector(selector);
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(originalScope is NotificationScope notification && session.NotificationPlan is { } child &&
                notification.SubscriptionName == child.Scope.SubscriptionName && notification.Vault.ExportResourceId() == session.Plan!.VaultId &&
                operation == ManagementMutation.UpdateNotification && session.Armed && session.BaselineReady && !session.StartClaimed &&
                InputMatches(session, input));
            session.StartClaimed = true;
            session.NotificationUpdateIndependentTokens.AddRange([cancellationToken, lifetime.Token, session.Stop.Token]);
            var baseline = session.NotificationUpdateIndependentBaseline ?? throw Failure();
            Require(!session.NotificationUpdateIndependentInvalid && session.NotificationUpdateIndependentTokens.All(t => !t.IsCancellationRequested) &&
                session.Notifications!.OwnsStatusNotificationUpdateIndependentRead(baseline.Proof, session.NotificationPlan!, Guid.Empty));
            session.Dispatch = Guid.NewGuid();
            var admission = new StatusNotificationUpdateIndependentAdmission(this);
            IssueNotificationUpdateIndependent(session, admission, NotificationUpdateIndependentStage.Begin,
                session.NotificationUpdateIndependentReady!, baseline.Task, baseline.Proof.NativeTask);
            session.Client = client;
            session.ActualNotificationScope = (NotificationScope)originalScope;
            session.Receipt = receipt;
            try
            {
                session.NotificationUpdateIndependentBegin = FreezeNotificationUpdateIndependent(
                    provisioner.Journal.BeginStatusNotificationUpdateIndependentInvocation(owner, selector, session.Plan!.LeaseId, admission));
            }
            catch { RevokeNotificationUpdateIndependent(session); throw; }
            session.Active++;
            active++;
        }
        try
        {
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, session.Stop.Token, deadline.Token);
            lock (gate) session.NotificationUpdateIndependentTokens.Add(linked.Token);
            var result = await capture.StartNotificationUpdateIndependentAsync(session.Capture!, selector, client, originalScope,
                input, receipt, linked.Token, task => { lock (gate) session.StartTask = task; }, () =>
                {
                    linked.Token.ThrowIfCancellationRequested();
                    Require(!disposed && !session.Closed && RoleFixtureJournal.SameStatusNotificationUpdateIndependentSnapshot(
                        session.NotificationUpdateIndependentBegin!, provisioner.Journal.Read(owner, selector)));
                }).ConfigureAwait(false);
            lock (gate)
            {
                session.Handle = result.IsSuccess ? result.Value : null;
                session.StartSucceeded = result.IsSuccess && session.StartTask is { IsCompletedSuccessfully: true };
                Require(session.StartSucceeded && capture.TryGetStatusNotificationUpdateIndependentStart(session.Capture!, session.Binding!,
                    client, session.ActualNotificationScope!, receipt, session.StartTask!, session.Handle!, out _));
                var candidate = new StatusNotificationUpdateIndependentStartDrain(this);
                IssueNotificationUpdateIndependent(session, candidate, NotificationUpdateIndependentStage.StartDrain,
                    session.NotificationUpdateIndependentBegin!, session.StartTask!);
                session.NotificationUpdateIndependentStartDrain = candidate;
            }
            RetryStatusNotificationUpdateIndependentPersistence(selector, cancellationToken);
            return result;
        }
        catch (IOException) { throw; }
        catch { lock (gate) RevokeNotificationUpdateIndependent(session); throw; }
        finally
        {
            try
            {
                if (session.NotificationUpdateIndependentStartDrain is null)
                    provisioner.Journal.EndDispatch(owner, selector, SelectedId(session), session.Dispatch, nativeSettled: false);
            }
            finally { Leave(session); }
        }
    }

    private async ValueTask<SecretStatus> CheckStatusNotificationUpdateIndependent(FixtureSelector selector,
        ManagementOperation handle, CancellationToken cancellationToken)
    {
        ValidateSelector(selector);
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            // Foreign references do not acquire or burn an owned invocation slot.
            Require(ReferenceEquals(handle, session.Handle));
            bool valid = !session.StatusClaimed && session.Active == 0 && session.StartFinished && session.StartSucceeded &&
                session.IndependentReady && session.NotificationUpdateIndependentObservation is not null &&
                !session.NotificationUpdateIndependentInvalid && !cancellationToken.IsCancellationRequested &&
                session.NotificationUpdateIndependentTokens.All(t => !t.IsCancellationRequested);
            session.StatusClaimed = true;
            if (!valid) { RevokeNotificationUpdateIndependent(session); throw Failure(); }
            var observation = session.NotificationUpdateIndependentObservation!;
            Require(capture.TryGetStatusNotificationUpdateIndependentStart(session.Capture!, session.Binding!, session.Client!,
                session.ActualNotificationScope!, session.Receipt!, session.StartTask!, handle, out var proof) && ReferenceEquals(proof, observation.Start) &&
                session.Notifications!.OwnsStatusNotificationUpdateIndependentRead(observation.Baseline.Proof, session.NotificationPlan!, Guid.Empty) &&
                session.Notifications.OwnsStatusNotificationUpdateIndependentRead(observation.Proof, session.NotificationPlan!, session.Dispatch));
            session.NotificationUpdateIndependentTokens.Add(cancellationToken);
            var admission = new StatusNotificationUpdateIndependentReadAdmission(this);
            IssueNotificationUpdateIndependent(session, admission, NotificationUpdateIndependentStage.Read,
                session.NotificationUpdateIndependentDrained!, observation.Baseline.Task, observation.Baseline.Proof.NativeTask,
                observation.Task, observation.Proof.NativeTask, observation.StatusTask, session.StartTask!);
            try
            {
                session.NotificationUpdateIndependentRead = FreezeNotificationUpdateIndependent(
                    provisioner.Journal.AdmitStatusNotificationUpdateIndependentRead(owner, selector, session.Plan!.LeaseId, session.Dispatch, admission));
            }
            catch { RevokeNotificationUpdateIndependent(session); throw; }
            session.Active++;
            active++;
        }
        try
        {
            Require(time.GetUtcNow() >= session.IndependentAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, session.Stop.Token, deadline.Token);
            lock (gate) session.NotificationUpdateIndependentTokens.Add(linked.Token);
            var status = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            lock (gate)
            {
                Require(status == SecretStatus.Success && capture.TryGetStatusNotificationUpdateIndependentCompletion(session.Capture!, session.Binding!,
                    session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!, handle, session.StatusTask!, out var proof) &&
                    ReferenceEquals(proof.Start, session.NotificationUpdateIndependentObservation!.Start));
                var observation = session.NotificationUpdateIndependentObservation!;
                var candidate = new StatusNotificationUpdateIndependentSettlement(this);
                IssueNotificationUpdateIndependent(session, candidate, NotificationUpdateIndependentStage.Complete,
                    session.NotificationUpdateIndependentRead!, observation.Baseline.Task, observation.Baseline.Proof.NativeTask,
                    observation.Task, observation.Proof.NativeTask, observation.StatusTask, session.StartTask!, session.StatusTask!);
                session.NotificationUpdateIndependentSettlement = candidate;
            }
            RetryStatusNotificationUpdateIndependentPersistence(selector, cancellationToken);
            return status;
        }
        catch (IOException) { throw; }
        catch { lock (gate) RevokeNotificationUpdateIndependent(session); throw; }
        finally
        {
            try
            {
                if (session.NotificationUpdateIndependentSettlement is null)
                    provisioner.Journal.EndDispatch(owner, selector, SelectedId(session), session.Dispatch, nativeSettled: false);
            }
            finally { Leave(session); }
        }
    }

    internal RoleFixtureJournal.Snapshot RetryStatusNotificationUpdateIndependentPersistence(FixtureSelector selector,
        CancellationToken token = default)
    {
        ValidateSelector(selector);
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(!statusNotificationUpdateIndependentCleanup && !session.NotificationUpdateIndependentInvalid);
            if (token.IsCancellationRequested) { RevokeNotificationUpdateIndependent(session); token.ThrowIfCancellationRequested(); }
            try
            {
                RoleFixtureJournal.Snapshot committed;
                if (session.NotificationUpdateIndependentSettlement is { } completion)
                {
                    committed = provisioner.Journal.CompleteStatusNotificationUpdateIndependentRead(owner, selector,
                        session.Plan!.LeaseId, session.Dispatch, completion);
                    session.StatusSucceeded = true;
                }
                else
                {
                    var drain = session.NotificationUpdateIndependentStartDrain ?? throw Failure();
                    committed = provisioner.Journal.EndStatusNotificationUpdateIndependentStart(owner, selector,
                        session.Plan!.LeaseId, session.Dispatch, drain);
                    session.NotificationUpdateIndependentDrained = FreezeNotificationUpdateIndependent(committed);
                    session.StartFinished = true;
                }
                return committed;
            }
            catch (IOException) { throw; }
            catch { RevokeNotificationUpdateIndependent(session); throw; }
        }
    }

    private async Task<HttpResponseMessage> ObserveStatusNotificationCreateIndependent(Session session, bool baseline,
        CancellationToken token, CancellationToken originalCallerToken)
    {
        var slot = baseline ? session.NotificationCreateIndependentBefore : session.NotificationCreateIndependentAfter;
        Require(slot is not null && slot.Nonce != Guid.Empty && slot.Baseline == baseline && slot.Subscription == session.Subscription &&
            slot.ArmedAt == session.ArmedAt && ReferenceEquals(slot.Source, session.Notifications) &&
            ReferenceEquals(slot.Child, session.NotificationPlan) && ReferenceEquals(slot.Parent, session.Plan) &&
            ReferenceEquals(slot.Binding, session.Binding));
        RequireNotificationJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: !baseline);
        C.StatusNotificationCreateIndependentStartProof? start = null;
        C.StatusTarget? target = null;
        S.Window? statusWindow = null;
        Task<S.Measurement>? statusTask = null;
        DateTimeOffset afterStatus = session.ArmedAt;
        if (!baseline)
        {
            Require(session.NotificationCreateIndependentBaseline is not null && session.StartFinished &&
                session.StartTask is { IsCompletedSuccessfully: true } &&
                capture.TryGetStatusNotificationCreateIndependentStart(session.Capture!, session.Binding!,
                    session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask,
                    session.Handle!, out start) &&
                capture.TryGetStatusTarget(session.Capture!, session.Binding!, out target) &&
                capture.OwnsStatusTarget(target, session.Binding!));
            statusWindow = statuses.Arm(target, session.Binding!);
            statusTask = statuses.CollectAsync(statusWindow, session.Binding!, token).AsTask();
            var status = await statusTask.ConfigureAwait(false);
            Require(ReferenceEquals(status.Binding, session.Binding) && status.WindowId == statusWindow.Id &&
                status.ResponseComplete && status.Terminal && status.HttpStatus == 200 &&
                status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
                status.StartDispatch == target.StartDispatch && status.TargetSha256 == target.TargetSha256 &&
                status.StartResponseSha256 == target.StartResponseSha256 &&
                status.StartedAt >= session.StartedAt && status.FinishedAt >= status.StartedAt &&
                Text(status.NativeRequestId, 256));
            afterStatus = status.FinishedAt;
        }
        var task = baseline
            ? slot.Source.ObserveAsync(owner, session.Selector, slot.Child.Scope.SubscriptionName, token, originalCallerToken: originalCallerToken).AsTask()
            : slot.Source.ObserveSelectedAsync(slot.Child, session.Dispatch, token, originalCallerToken: originalCallerToken).AsTask();
        using var measured = await task.ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        var proof = measured.StatusCreateIndependentRead ?? throw Failure();
        Require(slot.Source.OwnsStatusNotificationCreateIndependentRead(proof, slot.Child, baseline ? Guid.Empty : session.Dispatch) &&
            proof.NativeTask.IsCompletedSuccessfully && proof.HttpStatus == 200 && proof.NativeState == "Succeeded" &&
            proof.RequestSha256.Length == 64 && proof.ResponseSha256.Length == 64 && Text(proof.NativeRequestId, 256) &&
            proof.StartedAt >= afterStatus && proof.FinishedAt >= proof.StartedAt &&
            measured.ObservedAt >= proof.FinishedAt && measured.Present == true &&
            measured.Configuration is not null && NotificationConfigurationMatches(measured.Configuration,
                baseline ? VaultNotificationEvent.SecretNearExpiry : VaultNotificationEvent.SecretNewVersionCreated));
        RequireNotificationJournal(session, measured.Journal, selected: !baseline);
        Require(RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(baseline
            ? session.NotificationCreateIndependentReady! : session.NotificationCreateIndependentDrained!, measured.Journal));
        var configuration = new NotificationConfiguration(measured.Configuration.Endpoint.Reveal(),
            measured.Configuration.EventTypes, measured.Configuration.DeliveryAttributes);
        bool retained = false;
        try
        {
            lock (gate)
            {
                Require(!disposed && !session.Closed && !token.IsCancellationRequested &&
                    !session.NotificationCreateIndependentInvalid && session.NotificationCreateIndependentTokens.All(t => !t.IsCancellationRequested));
                if (baseline)
                {
                    Require(!session.StartClaimed && session.NotificationCreateIndependentBaseline is null &&
                        measured.State == NotificationFixtureProvisioner.State.Ready);
                    session.NotificationCreateIndependentBaseline = new(slot, task, proof,
                        Array.AsReadOnly(measured.Journal.Resources.ToArray()), configuration, measured.ObservedAt);
                    session.BaselineAt = measured.ObservedAt;
                    session.BaselineReady = true;
                }
                else
                {
                    Require(session.NotificationCreateIndependentObservation is null &&
                        measured.State == NotificationFixtureProvisioner.State.Pending &&
                        ReferenceEquals(measured.SelectedPlan, slot.Child) && measured.SelectedDispatch == session.Dispatch &&
                        proof.StartedAt >= session.NotificationCreateIndependentBaseline!.FinishedAt &&
                        capture.TryGetStatusNotificationCreateIndependentStart(session.Capture!, session.Binding!,
                            session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!,
                            session.Handle!, out var issued) && ReferenceEquals(start, issued));
                    session.NotificationCreateIndependentObservation = new(session.NotificationCreateIndependentBaseline!, slot, task,
                        proof, configuration, start!, target!, statusWindow!, statusTask!, measured.ObservedAt);
                    session.Target = target;
                    session.IndependentAt = measured.ObservedAt;
                    session.IndependentReady = true;
                }
                retained = true;
            }
            return Reply(ProjectNotification(session, measured.ObservedAt,
                baseline ? NativeProvisioningState.Unknown : NativeProvisioningState.Succeeded, measured.Configuration));
        }
        finally { if (!retained) configuration.Dispose(); }
    }

    private async ValueTask<SecretOutcome<ManagementOperation>> StartStatusNotificationCreateIndependent(
        FixtureSelector selector, VaultAdministration client, ManagementScope originalScope, ManagementMutation operation,
        E.Input input, ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        ValidateSelector(selector);
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(originalScope is NotificationScope notification && session.NotificationPlan is { } child &&
                notification.SubscriptionName == child.Scope.SubscriptionName && notification.Vault.ExportResourceId() == session.Plan!.VaultId &&
                operation == ManagementMutation.CreateOrUpdateNotification && session.Armed && session.BaselineReady && !session.StartClaimed &&
                InputMatches(session, input));
            session.StartClaimed = true;
            session.NotificationCreateIndependentTokens.AddRange([cancellationToken, lifetime.Token, session.Stop.Token]);
            var baseline = session.NotificationCreateIndependentBaseline ?? throw Failure();
            Require(!session.NotificationCreateIndependentInvalid && session.NotificationCreateIndependentTokens.All(t => !t.IsCancellationRequested) &&
                session.Notifications!.OwnsStatusNotificationCreateIndependentRead(baseline.Proof, session.NotificationPlan!, Guid.Empty));
            session.Dispatch = Guid.NewGuid();
            var admission = new StatusNotificationCreateIndependentAdmission(this);
            IssueNotificationCreateIndependent(session, admission, NotificationCreateIndependentStage.Begin,
                session.NotificationCreateIndependentReady!, baseline.Task, baseline.Proof.NativeTask);
            session.Client = client;
            session.ActualNotificationScope = (NotificationScope)originalScope;
            session.Receipt = receipt;
            try
            {
                session.NotificationCreateIndependentBegin = FreezeNotificationCreateIndependent(
                    provisioner.Journal.BeginStatusNotificationCreateIndependentInvocation(owner, selector, session.Plan!.LeaseId, admission));
            }
            catch { RevokeNotificationCreateIndependent(session); throw; }
            session.Active++;
            active++;
        }
        try
        {
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, session.Stop.Token, deadline.Token);
            lock (gate) session.NotificationCreateIndependentTokens.Add(linked.Token);
            var result = await capture.StartNotificationCreateIndependentAsync(session.Capture!, selector, client, originalScope,
                input, receipt, linked.Token, task => { lock (gate) session.StartTask = task; }, () =>
                {
                    linked.Token.ThrowIfCancellationRequested();
                    Require(!disposed && !session.Closed && RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(
                        session.NotificationCreateIndependentBegin!, provisioner.Journal.Read(owner, selector)));
                }).ConfigureAwait(false);
            lock (gate)
            {
                session.Handle = result.IsSuccess ? result.Value : null;
                session.StartSucceeded = result.IsSuccess && session.StartTask is { IsCompletedSuccessfully: true };
                Require(session.StartSucceeded && capture.TryGetStatusNotificationCreateIndependentStart(session.Capture!, session.Binding!,
                    client, session.ActualNotificationScope!, receipt, session.StartTask!, session.Handle!, out _));
                var candidate = new StatusNotificationCreateIndependentStartDrain(this);
                IssueNotificationCreateIndependent(session, candidate, NotificationCreateIndependentStage.StartDrain,
                    session.NotificationCreateIndependentBegin!, session.StartTask!);
                session.NotificationCreateIndependentStartDrain = candidate;
            }
            RetryStatusNotificationCreateIndependentPersistence(selector, cancellationToken);
            return result;
        }
        catch (IOException) { throw; }
        catch { lock (gate) RevokeNotificationCreateIndependent(session); throw; }
        finally
        {
            try
            {
                if (session.NotificationCreateIndependentStartDrain is null)
                    provisioner.Journal.EndDispatch(owner, selector, SelectedId(session), session.Dispatch, nativeSettled: false);
            }
            finally { Leave(session); }
        }
    }

    private async ValueTask<SecretStatus> CheckStatusNotificationCreateIndependent(FixtureSelector selector,
        ManagementOperation handle, CancellationToken cancellationToken)
    {
        ValidateSelector(selector);
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            // Foreign references do not acquire or burn an owned invocation slot.
            Require(ReferenceEquals(handle, session.Handle));
            bool valid = !session.StatusClaimed && session.Active == 0 && session.StartFinished && session.StartSucceeded &&
                session.IndependentReady && session.NotificationCreateIndependentObservation is not null &&
                !session.NotificationCreateIndependentInvalid && !cancellationToken.IsCancellationRequested &&
                session.NotificationCreateIndependentTokens.All(t => !t.IsCancellationRequested);
            session.StatusClaimed = true;
            if (!valid) { RevokeNotificationCreateIndependent(session); throw Failure(); }
            var observation = session.NotificationCreateIndependentObservation!;
            Require(capture.TryGetStatusNotificationCreateIndependentStart(session.Capture!, session.Binding!, session.Client!,
                session.ActualNotificationScope!, session.Receipt!, session.StartTask!, handle, out var proof) && ReferenceEquals(proof, observation.Start) &&
                session.Notifications!.OwnsStatusNotificationCreateIndependentRead(observation.Baseline.Proof, session.NotificationPlan!, Guid.Empty) &&
                session.Notifications.OwnsStatusNotificationCreateIndependentRead(observation.Proof, session.NotificationPlan!, session.Dispatch));
            session.NotificationCreateIndependentTokens.Add(cancellationToken);
            var admission = new StatusNotificationCreateIndependentReadAdmission(this);
            IssueNotificationCreateIndependent(session, admission, NotificationCreateIndependentStage.Read,
                session.NotificationCreateIndependentDrained!, observation.Baseline.Task, observation.Baseline.Proof.NativeTask,
                observation.Task, observation.Proof.NativeTask, observation.StatusTask, session.StartTask!);
            try
            {
                session.NotificationCreateIndependentRead = FreezeNotificationCreateIndependent(
                    provisioner.Journal.AdmitStatusNotificationCreateIndependentRead(owner, selector, session.Plan!.LeaseId, session.Dispatch, admission));
            }
            catch { RevokeNotificationCreateIndependent(session); throw; }
            session.Active++;
            active++;
        }
        try
        {
            Require(time.GetUtcNow() >= session.IndependentAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, session.Stop.Token, deadline.Token);
            lock (gate) session.NotificationCreateIndependentTokens.Add(linked.Token);
            var status = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            lock (gate)
            {
                Require(status == SecretStatus.Success && capture.TryGetStatusNotificationCreateIndependentCompletion(session.Capture!, session.Binding!,
                    session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!, handle, session.StatusTask!, out var proof) &&
                    ReferenceEquals(proof.Start, session.NotificationCreateIndependentObservation!.Start));
                var observation = session.NotificationCreateIndependentObservation!;
                var candidate = new StatusNotificationCreateIndependentSettlement(this);
                IssueNotificationCreateIndependent(session, candidate, NotificationCreateIndependentStage.Complete,
                    session.NotificationCreateIndependentRead!, observation.Baseline.Task, observation.Baseline.Proof.NativeTask,
                    observation.Task, observation.Proof.NativeTask, observation.StatusTask, session.StartTask!, session.StatusTask!);
                session.NotificationCreateIndependentSettlement = candidate;
            }
            RetryStatusNotificationCreateIndependentPersistence(selector, cancellationToken);
            return status;
        }
        catch (IOException) { throw; }
        catch { lock (gate) RevokeNotificationCreateIndependent(session); throw; }
        finally
        {
            try
            {
                if (session.NotificationCreateIndependentSettlement is null)
                    provisioner.Journal.EndDispatch(owner, selector, SelectedId(session), session.Dispatch, nativeSettled: false);
            }
            finally { Leave(session); }
        }
    }

    internal RoleFixtureJournal.Snapshot RetryStatusNotificationCreateIndependentPersistence(FixtureSelector selector,
        CancellationToken token = default)
    {
        ValidateSelector(selector);
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(!statusNotificationCreateIndependentCleanup && !session.NotificationCreateIndependentInvalid);
            if (token.IsCancellationRequested) { RevokeNotificationCreateIndependent(session); token.ThrowIfCancellationRequested(); }
            try
            {
                RoleFixtureJournal.Snapshot committed;
                if (session.NotificationCreateIndependentSettlement is { } completion)
                {
                    committed = provisioner.Journal.CompleteStatusNotificationCreateIndependentRead(owner, selector,
                        session.Plan!.LeaseId, session.Dispatch, completion);
                    session.StatusSucceeded = true;
                }
                else
                {
                    var drain = session.NotificationCreateIndependentStartDrain ?? throw Failure();
                    committed = provisioner.Journal.EndStatusNotificationCreateIndependentStart(owner, selector,
                        session.Plan!.LeaseId, session.Dispatch, drain);
                    session.NotificationCreateIndependentDrained = FreezeNotificationCreateIndependent(committed);
                    session.StartFinished = true;
                }
                return committed;
            }
            catch (IOException) { throw; }
            catch { RevokeNotificationCreateIndependent(session); throw; }
        }
    }

    private async Task<HttpResponseMessage> ObserveStatusNotificationUpdateCancellation(Session session, bool baseline,
        CancellationToken token)
    {
        var slot = baseline ? session.StatusNotificationBefore : session.StatusNotificationAfter;
        Require(slot is not null && slot.Baseline == baseline && slot.Subscription == session.Subscription &&
            slot.ArmedAt == session.ArmedAt && ReferenceEquals(slot.Source, session.Notifications) &&
            ReferenceEquals(slot.Child, session.NotificationPlan) && ReferenceEquals(slot.Parent, session.Plan) &&
            ReferenceEquals(slot.Binding, session.Binding));
        RequireNotificationJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: !baseline);
        C.StatusNotificationUpdateCancellationStartProof? start = null;
        C.StatusTarget? target = null;
        S.Window? statusWindow = null;
        Task<S.Measurement>? statusTask = null;
        DateTimeOffset afterStatus = session.ArmedAt;
        if (!baseline)
        {
            Require(session.StatusNotificationUpdateBaseline is not null && session.StartFinished &&
                session.StartTask is { IsCompletedSuccessfully: true } &&
                capture.TryGetStatusNotificationUpdateCancellationStart(session.Capture!, session.Binding!,
                    session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask,
                    session.Handle!, out start) &&
                capture.TryGetStatusTarget(session.Capture!, session.Binding!, out target) &&
                capture.OwnsStatusTarget(target, session.Binding!));
            statusWindow = statuses.Arm(target, session.Binding!);
            statusTask = statuses.CollectAsync(statusWindow, session.Binding!, token).AsTask();
            var status = await statusTask.ConfigureAwait(false);
            Require(ReferenceEquals(status.Binding, session.Binding) && status.WindowId == statusWindow.Id &&
                status.ResponseComplete && status.Terminal && status.HttpStatus == 200 &&
                status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
                status.StartDispatch == target.StartDispatch && status.TargetSha256 == target.TargetSha256 &&
                status.StartResponseSha256 == target.StartResponseSha256 &&
                status.StartedAt >= session.StartedAt && status.FinishedAt >= status.StartedAt &&
                Text(status.NativeRequestId, 256));
            afterStatus = status.FinishedAt;
        }
        var task = baseline
            ? slot.Source.ObserveAsync(owner, session.Selector, slot.Child.Scope.SubscriptionName, token).AsTask()
            : slot.Source.ObserveSelectedAsync(slot.Child, session.Dispatch, token).AsTask();
        using var measured = await task.ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        var proof = measured.StatusUpdateRead ?? throw Failure();
        Require(slot.Source.OwnsStatusNotificationUpdateRead(proof, slot.Child, baseline ? Guid.Empty : session.Dispatch) &&
            proof.NativeTask.IsCompletedSuccessfully && proof.HttpStatus == 200 && proof.NativeState == "Succeeded" &&
            proof.RequestSha256.Length == 64 && proof.ResponseSha256.Length == 64 && Text(proof.NativeRequestId, 256) &&
            proof.StartedAt >= afterStatus && proof.FinishedAt >= proof.StartedAt &&
            measured.ObservedAt >= proof.FinishedAt && measured.Present == true &&
            measured.Configuration is not null && NotificationConfigurationMatches(measured.Configuration,
                baseline ? VaultNotificationEvent.SecretNearExpiry : VaultNotificationEvent.SecretNewVersionCreated));
        RequireNotificationJournal(session, measured.Journal, selected: !baseline);
        var configuration = new NotificationConfiguration(measured.Configuration.Endpoint.Reveal(),
            measured.Configuration.EventTypes, measured.Configuration.DeliveryAttributes);
        bool retained = false;
        try
        {
            lock (gate)
            {
                Require(!disposed && !session.Closed && !token.IsCancellationRequested);
                if (baseline)
                {
                    Require(!session.StartClaimed && session.StatusNotificationUpdateBaseline is null &&
                        measured.State == NotificationFixtureProvisioner.State.Ready);
                    session.StatusNotificationUpdateBaseline = new(slot, task, proof,
                        Array.AsReadOnly(measured.Journal.Resources.ToArray()), configuration, measured.ObservedAt);
                    session.BaselineAt = measured.ObservedAt;
                    session.BaselineReady = true;
                }
                else
                {
                    Require(session.StatusNotificationUpdateObservation is null &&
                        measured.State == NotificationFixtureProvisioner.State.Pending &&
                        ReferenceEquals(measured.SelectedPlan, slot.Child) && measured.SelectedDispatch == session.Dispatch &&
                        proof.StartedAt >= session.StatusNotificationUpdateBaseline!.FinishedAt &&
                        capture.TryGetStatusNotificationUpdateCancellationStart(session.Capture!, session.Binding!,
                            session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!,
                            session.Handle!, out var issued) && ReferenceEquals(start, issued));
                    session.StatusNotificationUpdateObservation = new(session.StatusNotificationUpdateBaseline!, slot, task,
                        proof, configuration, start!, target!, statusWindow!, statusTask!, measured.ObservedAt);
                    session.Target = target;
                    session.IndependentAt = measured.ObservedAt;
                    session.IndependentReady = true;
                }
                retained = true;
            }
            return Reply(ProjectNotification(session, measured.ObservedAt,
                baseline ? NativeProvisioningState.Unknown : NativeProvisioningState.Succeeded, measured.Configuration));
        }
        finally { if (!retained) configuration.Dispose(); }
    }

    private async Task<HttpResponseMessage> ObserveStatusNotificationDeleteIndependent(Session session, bool baseline,
        CancellationToken token)
    {
        var slot = baseline ? session.StatusNotificationIndependentBefore : session.StatusNotificationIndependentAfter;
        Require(slot is not null && slot.Nonce != Guid.Empty && slot.Baseline == baseline &&
            slot.Subscription == session.Subscription && slot.ArmedAt == session.ArmedAt &&
            ReferenceEquals(slot.Source, session.Notifications) && ReferenceEquals(slot.Child, session.NotificationPlan) &&
            ReferenceEquals(slot.Parent, session.Plan) && ReferenceEquals(slot.Binding, session.Binding));
        RequireNotificationJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: !baseline);
        C.StatusNotificationDeleteIndependentStartProof? start = null;
        if (!baseline)
            Require(session.StatusNotificationIndependentBaseline is not null && session.StartFinished &&
                session.StartTask is { IsCompletedSuccessfully: true } &&
                capture.TryGetStatusNotificationDeleteIndependentStart(session.Capture!, session.Binding!,
                    session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask,
                    session.Handle!, out start));
        var task = baseline
            ? slot.Source.ObserveAsync(owner, session.Selector, slot.Child.Scope.SubscriptionName, token).AsTask()
            : slot.Source.ObserveSelectedAsync(slot.Child, session.Dispatch, token).AsTask();
        using var measured = await task.ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        var proof = measured.StatusDeleteIndependentRead ?? throw Failure();
        Require(task.IsCompletedSuccessfully &&
            slot.Source.OwnsStatusNotificationDeleteIndependentRead(proof, slot.Child, baseline ? Guid.Empty : session.Dispatch) &&
            proof.RequestSha256.Length == 64 && proof.ResponseSha256.Length == 64 && Text(proof.NativeRequestId, 256) &&
            proof.StartedAt >= slot.ArmedAt && proof.FinishedAt >= proof.StartedAt && measured.ObservedAt >= proof.FinishedAt);
        if (baseline)
        {
            Require(measured.State == NotificationFixtureProvisioner.State.Ready && measured.Present == true &&
                measured.NativeState == "Succeeded" && measured.Configuration is not null &&
                NotificationConfigurationMatches(measured.Configuration, VaultNotificationEvent.SecretNearExpiry) &&
                proof is { HttpStatus: 200, Present: true, NativeState: "Succeeded" } &&
                proof.NativeTask.IsCompletedSuccessfully);
            RequireNotificationJournal(session, measured.Journal, selected: false);
            var frozen = new StatusNotificationDeleteIndependentBaseline(slot, task, proof,
                Array.AsReadOnly(measured.Journal.Resources.ToArray()), measured.ObservedAt);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !session.StartClaimed && !token.IsCancellationRequested &&
                    session.StatusNotificationIndependentBaseline is null);
                var snapshot = provisioner.Journal.Read(owner, session.Selector);
                RequireNotificationJournal(session, snapshot, selected: false);
                Require(MatchesStatusNotificationDeleteIndependentRoot(frozen, snapshot));
                session.StatusNotificationIndependentBaseline = frozen;
                session.BaselineAt = measured.ObservedAt;
                session.BaselineReady = true;
                return Reply(ProjectNotification(session, measured.ObservedAt, NativeProvisioningState.Unknown, measured.Configuration));
            }
        }
        Require(measured.State == NotificationFixtureProvisioner.State.Pending && measured.Present == false &&
            measured.NativeState is null && measured.Configuration is null &&
            ReferenceEquals(measured.SelectedPlan, slot.Child) && measured.SelectedDispatch == session.Dispatch &&
            proof is { HttpStatus: 404, Present: false, NativeState: null } && proof.NativeTask.IsFaulted &&
            proof.StartedAt >= session.StartedAt && proof.StartedAt >= session.StatusNotificationIndependentBaseline!.FinishedAt);
        RequireNotificationJournal(session, measured.Journal, selected: true);
        lock (gate)
        {
            Require(!disposed && !session.Closed && !token.IsCancellationRequested &&
                session.StatusNotificationIndependentObservation is null &&
                capture.TryGetStatusNotificationDeleteIndependentStart(session.Capture!, session.Binding!,
                    session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!,
                    session.Handle!, out var issued) && ReferenceEquals(start, issued));
            RequireNotificationJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: true);
            session.StatusNotificationIndependentObservation = new(session.StatusNotificationIndependentBaseline!, slot, task,
                proof, start!, measured.ObservedAt);
            session.IndependentAt = measured.ObservedAt;
            session.IndependentReady = true;
            return Reply(Project(session, measured.ObservedAt, NativeProvisioningState.Succeeded, SecretStatus.Absent));
        }
    }

    private async ValueTask<SecretStatus> CheckStatusNotificationDeleteIndependent(FixtureSelector selector,
        ManagementOperation handle, CancellationToken cancellationToken)
    {
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            // Foreign handles and premature calls never acquire the one check slot.
            Require(ReferenceEquals(handle, session.Handle) && session.StartFinished && session.StartSucceeded &&
                session.IndependentReady && session.StatusNotificationIndependentObservation is not null &&
                !session.StatusClaimed && session.Active == 0 && !cancellationToken.IsCancellationRequested);
            var observation = session.StatusNotificationIndependentObservation;
            Require(capture.TryGetStatusNotificationDeleteIndependentStart(session.Capture!, session.Binding!,
                session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!, handle, out var start) &&
                ReferenceEquals(start, observation.Start) &&
                observation.Slot.Source.OwnsStatusNotificationDeleteIndependentRead(observation.Baseline.Proof,
                    observation.Slot.Child, Guid.Empty) &&
                observation.Slot.Source.OwnsStatusNotificationDeleteIndependentRead(observation.Proof,
                    observation.Slot.Child, session.Dispatch));
            session.StatusClaimed = true;
            var admission = new StatusNotificationDeleteIndependentReadAdmission(this, session.Dispatch);
            Require(statusNotificationDeleteIndependentReadAdmissions.TryAdd(admission, observation));
            try
            {
                provisioner.Journal.AdmitStatusNotificationDeleteIndependentRead(owner, selector,
                    session.Plan!.LeaseId, session.Dispatch, admission);
            }
            finally { statusNotificationDeleteIndependentReadAdmissions.TryRemove(admission, out _); }
            session.Active++;
            active++;
        }
        bool settled = false;
        try
        {
            Require(time.GetUtcNow() >= session.IndependentAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            var status = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            C.StatusNotificationDeleteIndependentCompletionProof? proof = null;
            Require(status == SecretStatus.Success &&
                capture.TryGetStatusNotificationDeleteIndependentCompletion(session.Capture!, session.Binding!,
                    session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!, handle,
                    session.StatusTask!, out proof) &&
                ReferenceEquals(proof.Start, session.StatusNotificationIndependentObservation!.Start));
            var observation = session.StatusNotificationIndependentObservation!;
            Require(ReferenceEquals(observation.Slot, session.StatusNotificationIndependentAfter) &&
                ReferenceEquals(observation.Baseline.Slot, session.StatusNotificationIndependentBefore) &&
                observation.Slot.Source.OwnsStatusNotificationDeleteIndependentRead(observation.Baseline.Proof,
                    observation.Slot.Child, Guid.Empty) &&
                observation.Slot.Source.OwnsStatusNotificationDeleteIndependentRead(observation.Proof,
                    observation.Slot.Child, session.Dispatch));
            var completion = new StatusNotificationDeleteIndependentCompletion(observation, session.Dispatch,
                session.Capture!, session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!,
                handle, session.StatusTask!, proof!, linked.Token, cancellationToken);
            var candidate = new StatusNotificationDeleteIndependentSettlement(this, session.Dispatch);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !linked.IsCancellationRequested &&
                    statusNotificationDeleteIndependentSettlements.TryAdd(candidate, completion));
                try
                {
                    _ = provisioner.Journal.CompleteStatusNotificationDeleteIndependentRead(owner, selector,
                        session.Plan!.LeaseId, session.Dispatch, candidate);
                    settled = session.StatusSucceeded = true;
                }
                finally { statusNotificationDeleteIndependentSettlements.TryRemove(candidate, out _); }
            }
            return status;
        }
        finally
        {
            try
            {
                if (!settled)
                    provisioner.Journal.EndDispatch(owner, selector, SelectedId(session), session.Dispatch, nativeSettled: false);
            }
            finally { Leave(session); }
        }
    }

    private bool ValidateStatusNotificationDeleteIndependentAdmission(StatusNotificationDeleteIndependentAdmission candidate,
        RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
        ReferenceEquals(journal, provisioner.Journal) &&
        statusNotificationDeleteIndependentAdmissions.TryGetValue(candidate, out var baseline) &&
        ValidStatusNotificationDeleteIndependentBaseline(baseline) &&
        MatchesStatusNotificationDeleteIndependentRoot(baseline, snapshot) && !snapshot.Closing && snapshot.Idle &&
        baseline.Rows.SequenceEqual(snapshot.Resources);

    private bool ValidateStatusNotificationDeleteIndependentReadAdmission(StatusNotificationDeleteIndependentReadAdmission candidate,
        RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
        ReferenceEquals(journal, provisioner.Journal) &&
        statusNotificationDeleteIndependentReadAdmissions.TryGetValue(candidate, out var observation) &&
        ValidStatusNotificationDeleteIndependentObservation(observation, candidate.Dispatch) &&
        MatchesStatusNotificationDeleteIndependentRoot(observation.Baseline, snapshot) && !snapshot.Closing &&
        snapshot.Resources.Single(r => r.Id == observation.Slot.Child.ResourceId) is
        { SelectedAttempted: true, InvocationTerminated: true, ActiveDispatch: var dispatch } &&
        dispatch == candidate.Dispatch;

    private bool ValidateStatusNotificationDeleteIndependentSettlement(StatusNotificationDeleteIndependentSettlement candidate,
        RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
        ReferenceEquals(journal, provisioner.Journal) &&
        statusNotificationDeleteIndependentSettlements.TryGetValue(candidate, out var completion) &&
        candidate.Dispatch == completion.Dispatch &&
        !completion.Cancellation.IsCancellationRequested && !completion.CallerCancellation.IsCancellationRequested &&
        completion.StartTask.IsCompletedSuccessfully && completion.StatusTask.IsCompletedSuccessfully &&
        ReferenceEquals(completion.Proof.Start, completion.Observation.Start) &&
        ValidStatusNotificationDeleteIndependentObservation(completion.Observation, completion.Dispatch) &&
        MatchesStatusNotificationDeleteIndependentRoot(completion.Observation.Baseline, snapshot) && !snapshot.Closing &&
        snapshot.Resources.Single(r => r.Id == completion.Observation.Slot.Child.ResourceId) is
        { SelectedAttempted: true, InvocationTerminated: false, ActiveDispatch: var dispatch } &&
        dispatch == completion.Dispatch;

    private static bool ValidStatusNotificationDeleteIndependentBaseline(StatusNotificationDeleteIndependentBaseline baseline) =>
        baseline.Task.IsCompletedSuccessfully && baseline.Proof.NativeTask.IsCompletedSuccessfully &&
        baseline.Slot.Baseline && baseline.Slot.Nonce != Guid.Empty &&
        baseline.Proof is { HttpStatus: 200, Present: true, NativeState: "Succeeded", SelectedDispatch: var dispatch } &&
        dispatch == Guid.Empty && ReferenceEquals(baseline.Proof.Plan, baseline.Slot.Child) &&
        ReferenceEquals(baseline.Proof.Parent, baseline.Slot.Parent);

    private static bool ValidStatusNotificationDeleteIndependentObservation(StatusNotificationDeleteIndependentObservation observation,
        Guid dispatch) =>
        dispatch != Guid.Empty && ValidStatusNotificationDeleteIndependentBaseline(observation.Baseline) &&
        observation.Task.IsCompletedSuccessfully && observation.Proof.NativeTask.IsFaulted &&
        !observation.Slot.Baseline && observation.Slot.Nonce != Guid.Empty &&
        observation.Slot.Nonce != observation.Baseline.Slot.Nonce &&
        !ReferenceEquals(observation.Task, observation.Baseline.Task) &&
        !ReferenceEquals(observation.Proof.NativeTask, observation.Baseline.Proof.NativeTask) &&
        ReferenceEquals(observation.Slot.Source, observation.Baseline.Slot.Source) &&
        ReferenceEquals(observation.Slot.Child, observation.Baseline.Slot.Child) &&
        ReferenceEquals(observation.Slot.Parent, observation.Baseline.Slot.Parent) &&
        ReferenceEquals(observation.Slot.Binding, observation.Baseline.Slot.Binding) &&
        ReferenceEquals(observation.Start.Binding, observation.Slot.Binding) &&
        ReferenceEquals(observation.Proof.Plan, observation.Slot.Child) &&
        observation.Proof is { HttpStatus: 404, Present: false, NativeState: null } &&
        observation.Proof.SelectedDispatch == dispatch;

    private static bool MatchesStatusNotificationDeleteIndependentRoot(StatusNotificationDeleteIndependentBaseline baseline,
        RoleFixtureJournal.Snapshot snapshot) =>
        RoleFixtureJournal.StatusNotificationDeleteIndependentRoot(snapshot) &&
        snapshot.Owner == baseline.Slot.Child.Owner && snapshot.Selector == baseline.Slot.Child.Selector &&
        snapshot.LeaseId == baseline.Slot.Child.LeaseId && baseline.Rows.Count == 4 &&
        snapshot.Resources.All(r => !r.Absent) &&
        baseline.Rows.All(b => snapshot.Resources.Count(r => r.Id == b.Id &&
            (r.Id == baseline.Slot.Child.ResourceId
                ? !r.Borrowed && !r.CleanupOnly && r.CreateAttempted && !r.DeleteAttempted && !r.Absent
                : r == b)) == 1);

    private async Task<HttpResponseMessage> ObserveStatusNotificationDeleteCancellation(Session session, bool baseline,
        CancellationToken token)
    {
        var slot = baseline ? session.StatusNotificationBefore : session.StatusNotificationAfter;
        Require(slot is not null && slot.Baseline == baseline && slot.Subscription == session.Subscription &&
            slot.ArmedAt == session.ArmedAt && ReferenceEquals(slot.Source, session.Notifications) &&
            ReferenceEquals(slot.Child, session.NotificationPlan) && ReferenceEquals(slot.Parent, session.Plan) &&
            ReferenceEquals(slot.Binding, session.Binding));
        RequireNotificationJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: !baseline);
        C.StatusNotificationDeleteCancellationStartProof? start = null;
        if (!baseline)
            Require(session.StatusNotificationBaseline is not null && session.StartFinished &&
                session.StartTask is { IsCompletedSuccessfully: true } &&
                capture.TryGetStatusNotificationDeleteCancellationStart(session.Capture!, session.Binding!,
                    session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask,
                    session.Handle!, out start));
        var task = baseline
            ? slot.Source.ObserveAsync(owner, session.Selector, slot.Child.Scope.SubscriptionName, token).AsTask()
            : slot.Source.ObserveSelectedAsync(slot.Child, session.Dispatch, token).AsTask();
        using var measured = await task.ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        var proof = measured.StatusDeleteRead ?? throw new InvalidOperationException("operation-source-unavailable");
        Require(slot.Source.OwnsStatusNotificationDeleteRead(proof, slot.Child, baseline ? Guid.Empty : session.Dispatch) &&
            proof.NativeTask.IsCompleted && proof.RequestSha256.Length == 64 && proof.ResponseSha256.Length == 64 &&
            Text(proof.NativeRequestId, 256) && proof.StartedAt >= slot.ArmedAt &&
            proof.FinishedAt >= proof.StartedAt && measured.ObservedAt >= proof.FinishedAt);
        if (baseline)
        {
            Require(measured.State == NotificationFixtureProvisioner.State.Ready && measured.Present == true &&
                measured.NativeState == "Succeeded" && measured.Configuration is not null &&
                NotificationConfigurationMatches(measured.Configuration, VaultNotificationEvent.SecretNearExpiry) &&
                proof is { HttpStatus: 200, Present: true, NativeState: "Succeeded" } &&
                proof.NativeTask.IsCompletedSuccessfully);
            RequireNotificationJournal(session, measured.Journal, selected: false);
            var frozen = new StatusNotificationDeleteCancellationBaseline(slot, task, proof,
                Array.AsReadOnly(measured.Journal.Resources.ToArray()), measured.ObservedAt);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !session.StartClaimed && !token.IsCancellationRequested &&
                    session.StatusNotificationBaseline is null);
                var snapshot = provisioner.Journal.Read(owner, session.Selector);
                RequireNotificationJournal(session, snapshot, selected: false);
                Require(MatchesStatusNotificationRoot(frozen, snapshot));
                session.StatusNotificationBaseline = frozen;
                session.BaselineAt = measured.ObservedAt;
                session.BaselineReady = true;
                return Reply(ProjectNotification(session, measured.ObservedAt,
                    NativeProvisioningState.Unknown, measured.Configuration));
            }
        }
        Require(measured.State == NotificationFixtureProvisioner.State.Pending && measured.Present == false &&
            measured.NativeState is null && measured.Configuration is null &&
            ReferenceEquals(measured.SelectedPlan, slot.Child) && measured.SelectedDispatch == session.Dispatch &&
            proof is { HttpStatus: 404, Present: false, NativeState: null } && proof.NativeTask.IsFaulted &&
            proof.StartedAt >= session.StartedAt && proof.StartedAt >= session.StatusNotificationBaseline!.FinishedAt);
        RequireNotificationJournal(session, measured.Journal, selected: true);
        lock (gate)
        {
            Require(!disposed && !session.Closed && !token.IsCancellationRequested &&
                session.StatusNotificationObservation is null &&
                capture.TryGetStatusNotificationDeleteCancellationStart(session.Capture!, session.Binding!,
                    session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!,
                    session.Handle!, out var issued) && ReferenceEquals(start, issued));
            RequireNotificationJournal(session, provisioner.Journal.Read(owner, session.Selector), selected: true);
            session.StatusNotificationObservation = new(session.StatusNotificationBaseline!, slot, task, proof,
                start!, measured.ObservedAt);
            session.IndependentAt = measured.ObservedAt;
            session.IndependentReady = true;
            return Reply(Project(session, measured.ObservedAt, NativeProvisioningState.Succeeded, SecretStatus.Absent));
        }
    }

    private async Task<HttpResponseMessage> ObserveStatusVaultDeleteCancellation(Session session, bool baseline,
        CancellationToken token)
    {
        var plan = session.Plan!;
        var binding = session.Binding!;
        var counterpart = session.CounterpartBinding!;
        Require(!plan.Restored && plan.Preparation == VaultFixtureProvisioner.Preparation.Active &&
            !plan.SeedCanary && plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
            plan.PrivateEndpoint is null && plan.Manifest.Count == 3 &&
            counterpart.Resource is DeletedVaultScope deletedScope &&
            deletedScope.Subscription.SubscriptionId == scope.SubscriptionId && deletedScope.Location == scope.Location &&
            deletedScope.VaultName == plan.VaultName && counterpart.Selector == session.Selector &&
            counterpart.LeaseId == plan.LeaseId && counterpart.Operation == ManagementMutation.DeleteVault &&
            counterpart.ApiRevision == binding.ApiRevision);
        if (baseline)
        {
            var activeTask = before.CollectAsync(session.Before!, binding, token).AsTask();
            using var activeResult = await activeTask.ConfigureAwait(false);
            Require(StatusCancellationResourceBound(activeResult, session, binding, session.Before!) &&
                activeResult.HttpStatus == 200 && activeResult.ResourceStatus == SecretStatus.Success &&
                activeResult.PersistedStateEligible &&
                string.Equals(activeResult.ResourceId, plan.VaultId, StringComparison.OrdinalIgnoreCase) &&
                "Succeeded".Equals(activeResult.NativeState, StringComparison.OrdinalIgnoreCase) &&
                activeResult.VaultConfiguration is { PurgeProtection: false } vault &&
                vault.CreateMode is null or "default" && vault.TenantId == scope.TenantId &&
                vault.Location.Equals(scope.Location, StringComparison.OrdinalIgnoreCase) &&
                vault.Sku == session.Preparation!.Sku && vault.RetentionDays == session.Preparation.RetentionDays);
            var deletedTask = statusCounterpartBeforeCollector!.CollectAsync(session.CounterpartBefore!, counterpart, token).AsTask();
            using var deletedResult = await deletedTask.ConfigureAwait(false);
            Require(StatusCancellationResourceBound(deletedResult, session, counterpart, session.CounterpartBefore!) &&
                deletedResult.StartedAt >= activeResult.FinishedAt && deletedResult.HttpStatus == 404 &&
                deletedResult.ResourceStatus == SecretStatus.Absent && deletedResult.ResourceId is null &&
                deletedResult.DeletedVault is null);
            var frozen = new StatusVaultDeleteCancellationBaseline(owner, session.Selector, plan.LeaseId,
                plan.VaultId, plan.SecretId, plan.DeletedId, binding, counterpart, session.Before!, session.CounterpartBefore!,
                activeTask, deletedTask, deletedResult.FinishedAt);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !session.StartClaimed && !token.IsCancellationRequested);
                var snapshot = provisioner.Journal.Read(owner, session.Selector);
                Require(provisioner.MatchesOwnedPlan(plan, snapshot) && MatchesStatusDeleteRoot(frozen, snapshot) &&
                    !snapshot.Closing && snapshot.Idle &&
                    snapshot.Resources.Single(r => r.Id == plan.VaultId) is
                    { CreateAttempted: true, InvocationTerminated: true, SelectedAttempted: false, DeleteAttempted: false });
                session.StatusDeleteBaseline = frozen;
                session.BaselineAt = frozen.FinishedAt;
                session.BaselineReady = true;
                return Reply(Project(session, frozen.FinishedAt, NativeProvisioningState.Unknown, SecretStatus.Success));
            }
        }

        var baselineProof = session.StatusDeleteBaseline;
        Require(baselineProof is not null && session.StartTask is { IsCompletedSuccessfully: true });
        Require(capture.TryGetStatusTarget(session.Capture!, binding, out var target) &&
            capture.OwnsStatusTarget(target, binding) && ReferenceEquals(target.Binding, binding));
        var statusWindow = statuses.Arm(target, binding);
        var statusTask = statuses.CollectAsync(statusWindow, binding, token).AsTask();
        var status = await statusTask.ConfigureAwait(false);
        Require(ReferenceEquals(status.Binding, binding) && status.WindowId == statusWindow.Id &&
            status.ArmedAt == statusWindow.ArmedAt && status.StartedAt >= status.ArmedAt &&
            status.ArmedAt >= session.StartedAt && status.FinishedAt >= status.StartedAt &&
            status.HttpStatus == 200 && status.ResponseComplete && status.Terminal &&
            status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
            status.StartDispatch == target.StartDispatch && status.TargetSha256 == target.TargetSha256 &&
            status.StartResponseSha256 == target.StartResponseSha256 && Text(status.NativeRequestId, 256));
        var postTask = after.CollectAsync(session.After!, binding, token).AsTask();
        using var post = await postTask.ConfigureAwait(false);
        Require(StatusCancellationResourceBound(post, session, binding, session.After!) &&
            post.StartedAt >= status.FinishedAt && post.HttpStatus == 404 &&
            post.ResourceStatus == SecretStatus.Absent && post.ResourceId is null && post.VaultConfiguration is null);
        var deletedPostTask = statusCounterpartAfterCollector!.CollectAsync(session.CounterpartAfter!, counterpart, token).AsTask();
        using var deletedPost = await deletedPostTask.ConfigureAwait(false);
        Require(StatusCancellationResourceBound(deletedPost, session, counterpart, session.CounterpartAfter!) &&
            deletedPost.StartedAt >= post.FinishedAt && deletedPost.HttpStatus == 200 &&
            deletedPost.ResourceStatus == SecretStatus.Success && deletedPost.PersistedStateEligible &&
            string.Equals(deletedPost.ResourceId, plan.DeletedId, StringComparison.OrdinalIgnoreCase) &&
            deletedPost.DeletedVault is { PurgeProtected: false } deleted &&
            deleted.OriginalResourceId.Equals(plan.VaultId, StringComparison.OrdinalIgnoreCase));
        var observation = new StatusVaultDeleteCancellationObservation(baselineProof, target, statusWindow, statusTask,
            session.After!, session.CounterpartAfter!, postTask, deletedPostTask, deletedPost.FinishedAt);
        lock (gate)
        {
            Require(!disposed && !session.Closed && !token.IsCancellationRequested &&
                ReferenceEquals(baselineProof, session.StatusDeleteBaseline));
            var snapshot = provisioner.Journal.Read(owner, session.Selector);
            Require(MatchesStatusDeleteRoot(baselineProof, snapshot) && !snapshot.Closing &&
                snapshot.Resources.Single(r => r.Id == plan.VaultId) is
                { SelectedAttempted: true, InvocationTerminated: true, ActiveDispatch: var dispatch } &&
                dispatch == session.Dispatch && dispatch != Guid.Empty);
            session.StatusDeleteObservation = observation;
            session.Target = target;
            session.IndependentAt = observation.FinishedAt;
            session.IndependentReady = true;
            return Reply(Project(session, observation.FinishedAt, NativeProvisioningState.Succeeded, SecretStatus.Absent));
        }
    }

    private async Task<HttpResponseMessage> ObserveStatusVaultPurgeCancellation(Session session, bool baseline,
        CancellationToken token)
    {
        var plan = session.Plan!;
        var binding = session.Binding!;
        var counterpart = session.CounterpartBinding!;
        Require(!plan.Restored && plan.Preparation == VaultFixtureProvisioner.Preparation.Deleted &&
            !plan.SeedCanary && plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
            plan.PrivateEndpoint is null && plan.Manifest.Count == 3 &&
            binding.Resource is DeletedVaultScope selected &&
            selected.Subscription.SubscriptionId == scope.SubscriptionId && selected.Location == scope.Location &&
            selected.VaultName == plan.VaultName && binding.ApiRevision == "2026-02-01" &&
            counterpart.Resource is VaultScope activeScope && activeScope.ExportResourceId() == plan.VaultId &&
            counterpart.Selector == session.Selector && counterpart.LeaseId == plan.LeaseId &&
            counterpart.Operation == ManagementMutation.PurgeDeletedVault &&
            counterpart.ApiRevision == binding.ApiRevision && counterpart.Location == binding.Location);
        if (baseline)
        {
            var activeTask = statusCounterpartBeforeCollector!.CollectAsync(
                session.CounterpartBefore!, counterpart, token).AsTask();
            using var activeResult = await activeTask.ConfigureAwait(false);
            Require(StatusCancellationResourceBound(activeResult, session, counterpart, session.CounterpartBefore!) &&
                activeResult.HttpStatus == 404 && activeResult.ResourceStatus == SecretStatus.Absent &&
                activeResult.ResourceId is null && activeResult.VaultConfiguration is null);
            var deletedTask = before.CollectAsync(session.Before!, binding, token).AsTask();
            using var deletedResult = await deletedTask.ConfigureAwait(false);
            Require(StatusCancellationResourceBound(deletedResult, session, binding, session.Before!) &&
                deletedResult.StartedAt >= activeResult.FinishedAt && deletedResult.HttpStatus == 200 &&
                deletedResult.ResourceStatus == SecretStatus.Success && deletedResult.PersistedStateEligible &&
                string.Equals(deletedResult.ResourceId, plan.DeletedId, StringComparison.OrdinalIgnoreCase) &&
                deletedResult.DeletedVault is
                { PurgeProtected: false, DeletedOn: { } deletedOn, ScheduledPurgeOn: { } purgeOn } deleted &&
                deleted.OriginalResourceId.Equals(plan.VaultId, StringComparison.OrdinalIgnoreCase) &&
                purgeOn > deletedOn);
            var frozen = new StatusVaultPurgeCancellationBaseline(owner, session.Selector, plan.LeaseId,
                plan.VaultId, plan.SecretId, plan.DeletedId, binding, counterpart, session.CounterpartBefore!, session.Before!,
                activeTask, deletedTask, deletedResult.FinishedAt);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !session.StartClaimed && !token.IsCancellationRequested);
                var snapshot = provisioner.Journal.Read(owner, session.Selector);
                Require(provisioner.MatchesOwnedPlan(plan, snapshot) && MatchesStatusPurgeRoot(frozen, snapshot) &&
                    !snapshot.Closing && snapshot.Idle &&
                    snapshot.Resources.Single(r => r.Id == plan.DeletedId) is
                    { SelectedAttempted: false, InvocationTerminated: true });
                session.StatusPurgeBaseline = frozen;
                session.BaselineAt = frozen.FinishedAt;
                session.BaselineReady = true;
                return Reply(Project(session, frozen.FinishedAt, NativeProvisioningState.Unknown, SecretStatus.Success));
            }
        }

        var baselineProof = session.StatusPurgeBaseline;
        Require(baselineProof is not null && session.StartTask is { IsCompletedSuccessfully: true });
        Require(capture.TryGetStatusTarget(session.Capture!, binding, out var target) &&
            capture.OwnsStatusTarget(target, binding) && ReferenceEquals(target.Binding, binding));
        var statusWindow = statuses.Arm(target, binding);
        var statusTask = statuses.CollectAsync(statusWindow, binding, token).AsTask();
        var status = await statusTask.ConfigureAwait(false);
        Require(ReferenceEquals(status.Binding, binding) && status.WindowId == statusWindow.Id &&
            status.ArmedAt == statusWindow.ArmedAt && status.StartedAt >= status.ArmedAt &&
            status.ArmedAt >= session.StartedAt && status.FinishedAt >= status.StartedAt &&
            status.HttpStatus == 200 && status.ResponseComplete && status.Terminal &&
            status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
            status.StartDispatch == target.StartDispatch && status.TargetSha256 == target.TargetSha256 &&
            status.StartResponseSha256 == target.StartResponseSha256 && Text(status.NativeRequestId, 256));
        var deletedPostTask = after.CollectAsync(session.After!, binding, token).AsTask();
        using var deletedPost = await deletedPostTask.ConfigureAwait(false);
        Require(StatusCancellationResourceBound(deletedPost, session, binding, session.After!) &&
            deletedPost.StartedAt >= status.FinishedAt && deletedPost.HttpStatus == 404 &&
            deletedPost.ResourceStatus == SecretStatus.Absent && deletedPost.ResourceId is null &&
            deletedPost.DeletedVault is null);
        var activePostTask = statusCounterpartAfterCollector!.CollectAsync(
            session.CounterpartAfter!, counterpart, token).AsTask();
        using var activePost = await activePostTask.ConfigureAwait(false);
        Require(StatusCancellationResourceBound(activePost, session, counterpart, session.CounterpartAfter!) &&
            activePost.StartedAt >= deletedPost.FinishedAt && activePost.HttpStatus == 404 &&
            activePost.ResourceStatus == SecretStatus.Absent && activePost.ResourceId is null &&
            activePost.VaultConfiguration is null);
        var observation = new StatusVaultPurgeCancellationObservation(baselineProof, target, statusWindow, statusTask,
            session.CounterpartAfter!, session.After!, activePostTask, deletedPostTask, activePost.FinishedAt);
        lock (gate)
        {
            Require(!disposed && !session.Closed && !token.IsCancellationRequested &&
                ReferenceEquals(baselineProof, session.StatusPurgeBaseline));
            var snapshot = provisioner.Journal.Read(owner, session.Selector);
            Require(MatchesStatusPurgeRoot(baselineProof, snapshot) && !snapshot.Closing &&
                snapshot.Resources.Single(r => r.Id == plan.DeletedId) is
                { SelectedAttempted: true, InvocationTerminated: true, ActiveDispatch: var dispatch } &&
                dispatch == session.Dispatch && dispatch != Guid.Empty);
            session.StatusPurgeObservation = observation;
            session.Target = target;
            session.IndependentAt = observation.FinishedAt;
            session.IndependentReady = true;
            return Reply(Project(session, observation.FinishedAt, NativeProvisioningState.Succeeded, SecretStatus.Absent));
        }
    }

    private async Task<HttpResponseMessage> ObserveStatusVaultRecoverCancellation(Session session, bool baseline,
        CancellationToken token)
    {
        var plan = session.Plan!;
        var binding = session.Binding!;
        var counterpart = session.CounterpartBinding!;
        var expected = session.StatusRecoverConfiguration!;
        Require(expected is not null && !plan.Restored && !plan.OriginalRecover &&
            plan.Preparation == VaultFixtureProvisioner.Preparation.Deleted && !plan.SeedCanary &&
            plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
            plan.PrivateEndpoint is null && plan.Manifest.Count == 3 &&
            binding.Resource is VaultScope selected && selected.ExportResourceId() == plan.VaultId &&
            binding.Operation == ManagementMutation.RecoverVault && binding.ApiRevision == "2026-02-01" &&
            counterpart.Resource is DeletedVaultScope deletedScope &&
            deletedScope.Subscription.SubscriptionId == scope.SubscriptionId && deletedScope.Location == scope.Location &&
            deletedScope.VaultName == plan.VaultName && counterpart.Selector == session.Selector &&
            counterpart.LeaseId == plan.LeaseId && counterpart.Operation == binding.Operation &&
            counterpart.Location == binding.Location && counterpart.ApiRevision == binding.ApiRevision &&
            provisioner.OwnsStatusVaultRecoverCancellationPreparation(plan));
        if (baseline)
        {
            var activeTask = before.CollectAsync(session.Before!, binding, token).AsTask();
            using var activeResult = await activeTask.ConfigureAwait(false);
            Require(StatusCancellationResourceBound(activeResult, session, binding, session.Before!) &&
                activeResult.HttpStatus == 404 && activeResult.ResourceStatus == SecretStatus.Absent &&
                activeResult.ResourceId is null && activeResult.VaultConfiguration is null);
            var deletedTask = statusCounterpartBeforeCollector!.CollectAsync(session.CounterpartBefore!, counterpart, token).AsTask();
            using var deletedResult = await deletedTask.ConfigureAwait(false);
            Require(StatusCancellationResourceBound(deletedResult, session, counterpart, session.CounterpartBefore!) &&
                deletedResult.StartedAt >= activeResult.FinishedAt && deletedResult.HttpStatus == 200 &&
                deletedResult.ResourceStatus == SecretStatus.Success && deletedResult.PersistedStateEligible &&
                deletedResult.ResourceId == plan.DeletedId && deletedResult.DeletedVault is
                { PurgeProtected: false, DeletedOn: { }, ScheduledPurgeOn: { } } &&
                deletedResult.DeletedVault.OriginalResourceId == plan.VaultId &&
                deletedResult.DeletedVault.ScheduledPurgeOn - deletedResult.DeletedVault.DeletedOn ==
                    TimeSpan.FromDays(expected.RetentionDays));
            var ownedTask = provisioner.ObserveAsync(owner, session.Selector, token).AsTask();
            var owned = await ownedTask.ConfigureAwait(false);
            Require(owned.State == VaultFixtureProvisioner.State.Ready && owned.VaultPresent == false &&
                owned.DeletedVaultPresent == true && owned.Configuration is null &&
                owned.DeletedVault is { PurgeProtected: false } deleted &&
                deleted.SubscriptionId == scope.SubscriptionId && deleted.Location == scope.Location &&
                deleted.Name == plan.VaultName && deleted.DeletedOn == deletedResult.DeletedVault!.DeletedOn &&
                deleted.ScheduledPurgeOn == deletedResult.DeletedVault.ScheduledPurgeOn);
            DateTimeOffset finished = time.GetUtcNow();
            Require(finished >= deletedResult.FinishedAt);
            var frozen = new StatusVaultRecoverCancellationBaseline(owner, session.Selector, plan.LeaseId,
                plan.VaultId, plan.SecretId, plan.DeletedId,
                expected with { Policies = expected.Policies.Select(p => p with { Permissions = p.Permissions.ToArray() }).ToArray() },
                binding, counterpart, session.Before!, session.CounterpartBefore!, activeTask, deletedTask, ownedTask, finished);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !session.StartClaimed && !token.IsCancellationRequested &&
                    provisioner.OwnsStatusVaultRecoverCancellationPreparation(plan));
                var snapshot = provisioner.Journal.Read(owner, session.Selector);
                Require(provisioner.MatchesOwnedPlan(plan, snapshot) && MatchesStatusRecoverRoot(frozen, owned.Journal) &&
                    MatchesStatusRecoverRoot(frozen, snapshot) && !snapshot.Closing && snapshot.Idle &&
                    snapshot.Resources.Single(r => r.Id == plan.VaultId) is
                    { SelectedAttempted: false, InvocationTerminated: true });
                session.StatusRecoverBaseline = frozen;
                session.BaselineAt = finished;
                session.BaselineReady = true;
                return Reply(Project(session, finished, NativeProvisioningState.Unknown, SecretStatus.Absent));
            }
        }

        var baselineProof = session.StatusRecoverBaseline;
        Require(baselineProof is not null && session.StartTask is { IsCompletedSuccessfully: true });
        Require(capture.TryGetStatusTarget(session.Capture!, binding, out var target) &&
            capture.OwnsStatusTarget(target, binding) && ReferenceEquals(target.Binding, binding));
        var statusWindow = statuses.Arm(target, binding);
        var statusTask = statuses.CollectAsync(statusWindow, binding, token).AsTask();
        var status = await statusTask.ConfigureAwait(false);
        Require(ReferenceEquals(status.Binding, binding) && status.WindowId == statusWindow.Id &&
            status.ArmedAt == statusWindow.ArmedAt && status.StartedAt >= status.ArmedAt &&
            status.ArmedAt >= session.StartedAt && status.FinishedAt >= status.StartedAt &&
            status.HttpStatus == 200 && status.ResponseComplete && status.Terminal &&
            status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
            status.StartDispatch == target.StartDispatch && status.TargetSha256 == target.TargetSha256 &&
            status.StartResponseSha256 == target.StartResponseSha256 && Text(status.NativeRequestId, 256));
        var activePostTask = after.CollectAsync(session.After!, binding, token).AsTask();
        using var activePost = await activePostTask.ConfigureAwait(false);
        Require(StatusCancellationResourceBound(activePost, session, binding, session.After!) &&
            activePost.StartedAt >= status.FinishedAt && activePost.HttpStatus == 200 &&
            activePost.ResourceStatus == SecretStatus.Success && activePost.PersistedStateEligible &&
            activePost.ResourceId == plan.VaultId && activePost.NativeState == "Succeeded" &&
            activePost.VaultConfiguration is { CreateMode: null or "default" or "recover" });
        var vault = activePost.VaultConfiguration;
        var configuration = new VaultAdministrationEffects.Configuration(vault.Location, vault.TenantId,
            vault.Sku, vault.Rbac, vault.PurgeProtection, vault.RetentionDays, vault.PublicNetworkAccess,
            vault.Policies.Select(p => new VaultAdministrationEffects.Policy(
                p.TenantId, p.PrincipalId, p.Permissions.ToArray(), p.ApplicationId)).ToArray());
        Require(VaultAdministrationEffects.SameConfiguration(configuration, baselineProof.Configuration));
        var deletedPostTask = statusCounterpartAfterCollector!.CollectAsync(session.CounterpartAfter!, counterpart, token).AsTask();
        using var deletedPost = await deletedPostTask.ConfigureAwait(false);
        Require(StatusCancellationResourceBound(deletedPost, session, counterpart, session.CounterpartAfter!) &&
            deletedPost.StartedAt >= activePost.FinishedAt && deletedPost.HttpStatus == 404 &&
            deletedPost.ResourceStatus == SecretStatus.Absent && deletedPost.ResourceId is null && deletedPost.DeletedVault is null);
        var ownedPostTask = provisioner.ObserveAsync(owner, session.Selector, token).AsTask();
        var ownedPost = await ownedPostTask.ConfigureAwait(false);
        Require(ownedPost.State == VaultFixtureProvisioner.State.Pending && ownedPost.VaultPresent == true &&
            ownedPost.DeletedVaultPresent == false && ownedPost.DeletedVault is null &&
            ownedPost.Configuration is not null &&
            VaultAdministrationEffects.SameConfiguration(ownedPost.Configuration, configuration) &&
            MatchesStatusRecoverRoot(baselineProof, ownedPost.Journal));
        DateTimeOffset observed = time.GetUtcNow();
        Require(observed >= deletedPost.FinishedAt);
        var observation = new StatusVaultRecoverCancellationObservation(baselineProof, target, statusWindow, statusTask,
            session.After!, session.CounterpartAfter!, activePostTask, deletedPostTask, ownedPostTask, configuration, observed);
        lock (gate)
        {
            Require(!disposed && !session.Closed && !token.IsCancellationRequested &&
                ReferenceEquals(baselineProof, session.StatusRecoverBaseline));
            var snapshot = provisioner.Journal.Read(owner, session.Selector);
            Require(MatchesStatusRecoverRoot(baselineProof, snapshot) && !snapshot.Closing &&
                snapshot.Resources.Single(r => r.Id == plan.VaultId) is
                { SelectedAttempted: true, InvocationTerminated: true, ActiveDispatch: var dispatch } &&
                dispatch == session.Dispatch && dispatch != Guid.Empty);
            session.StatusRecoverObservation = observation;
            session.Target = target;
            session.IndependentAt = observed;
            session.IndependentReady = true;
            return Reply(Project(session, observed, NativeProvisioningState.Succeeded, SecretStatus.Success,
                configuration with
                {
                    Policies = configuration.Policies.Select(p =>
                    p with { Permissions = p.Permissions.ToArray() }).ToArray()
                }));
        }
    }

    private async Task<HttpResponseMessage> ObserveStatusVaultUpdateCancellation(Session session, bool baseline,
        CancellationToken token)
    {
        var plan = session.Plan!;
        var binding = session.Binding!;
        var counterpart = session.CounterpartBinding!;
        var expected = session.StatusUpdateConfiguration!;
        Require(expected is not null && !plan.Restored && !plan.OriginalCreate && !plan.OriginalRecover &&
            plan.Preparation == VaultFixtureProvisioner.Preparation.Active && !plan.SeedCanary &&
            plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
            plan.PrivateEndpoint is null && plan.Manifest.Count == 3 &&
            binding.Resource is VaultScope selected && selected.ExportResourceId() == plan.VaultId &&
            binding.Operation == ManagementMutation.CreateOrUpdateVault && binding.ApiRevision == "2026-02-01" &&
            counterpart.Resource is DeletedVaultScope deletedScope &&
            deletedScope.Subscription.SubscriptionId == scope.SubscriptionId && deletedScope.Location == scope.Location &&
            deletedScope.VaultName == plan.VaultName && counterpart.Selector == session.Selector &&
            counterpart.LeaseId == plan.LeaseId && counterpart.Operation == binding.Operation &&
            counterpart.Location == binding.Location && counterpart.ApiRevision == binding.ApiRevision &&
            new[] { session.Before!.Id, session.After!.Id, session.CounterpartBefore!.Id, session.CounterpartAfter!.Id }
                .Distinct().Count() == 4 && provisioner.OwnsStatusVaultUpdateCancellationPreparation(plan));
        if (baseline)
        {
            var activeTask = before.CollectAsync(session.Before!, binding, token).AsTask();
            using var activeResult = await activeTask.ConfigureAwait(false);
            Require(StatusCancellationResourceBound(activeResult, session, binding, session.Before!) &&
                activeResult.HttpStatus == 200 && activeResult.ResourceStatus == SecretStatus.Success &&
                activeResult.PersistedStateEligible && activeResult.ResourceId == plan.VaultId &&
                activeResult.NativeState == "Succeeded" && activeResult.VaultConfiguration is { CreateMode: null or "default" });
            var vault = activeResult.VaultConfiguration;
            var configuration = new VaultAdministrationEffects.Configuration(vault.Location, vault.TenantId,
                vault.Sku, vault.Rbac, vault.PurgeProtection, vault.RetentionDays, vault.PublicNetworkAccess,
                vault.Policies.Select(p => new VaultAdministrationEffects.Policy(
                    p.TenantId, p.PrincipalId, p.Permissions.ToArray(), p.ApplicationId)).ToArray());
            Require(VaultAdministrationEffects.SameConfiguration(configuration, expected));
            var deletedTask = statusCounterpartBeforeCollector!.CollectAsync(session.CounterpartBefore!, counterpart, token).AsTask();
            using var deletedResult = await deletedTask.ConfigureAwait(false);
            Require(StatusCancellationResourceBound(deletedResult, session, counterpart, session.CounterpartBefore!) &&
                deletedResult.StartedAt >= activeResult.FinishedAt && deletedResult.HttpStatus == 404 &&
                deletedResult.ResourceStatus == SecretStatus.Absent && deletedResult.ResourceId is null &&
                deletedResult.DeletedVault is null);
            var ownedTask = provisioner.ObserveAsync(owner, session.Selector, token).AsTask();
            var owned = await ownedTask.ConfigureAwait(false);
            Require(owned.State == VaultFixtureProvisioner.State.Ready && owned.VaultPresent == true &&
                owned.DeletedVaultPresent == false && owned.DeletedVault is null && owned.Configuration is not null &&
                VaultAdministrationEffects.SameConfiguration(owned.Configuration, expected));
            DateTimeOffset finished = time.GetUtcNow();
            Require(finished >= deletedResult.FinishedAt);
            var frozenConfiguration = configuration with
            { Policies = configuration.Policies.Select(p => p with { Permissions = p.Permissions.ToArray() }).ToArray() };
            var frozenSelected = frozenConfiguration with
            {
                PublicNetworkAccess = true,
                Policies = frozenConfiguration.Policies.Select(p => p with { Permissions = p.Permissions.ToArray() }).ToArray()
            };
            Require(!VaultAdministrationEffects.SameConfiguration(frozenConfiguration, frozenSelected));
            var frozen = new StatusVaultUpdateCancellationBaseline(owner, session.Selector, plan.LeaseId,
                plan.VaultId, plan.SecretId, plan.DeletedId, frozenConfiguration, frozenSelected,
                binding, counterpart, session.Before!, session.CounterpartBefore!, activeTask, deletedTask, ownedTask, finished);
            lock (gate)
            {
                Require(!disposed && !session.Closed && !session.StartClaimed && !token.IsCancellationRequested &&
                    provisioner.OwnsStatusVaultUpdateCancellationPreparation(plan));
                var snapshot = provisioner.Journal.Read(owner, session.Selector);
                Require(provisioner.MatchesOwnedPlan(plan, snapshot) && MatchesStatusUpdateRoot(frozen, owned.Journal) &&
                    MatchesStatusUpdateRoot(frozen, snapshot) && !snapshot.Closing && snapshot.Idle &&
                    snapshot.Resources.Single(r => r.Id == plan.VaultId) is
                    { SelectedAttempted: false, InvocationTerminated: true });
                session.StatusUpdateBaseline = frozen;
                session.BaselineAt = finished;
                session.BaselineReady = true;
                return Reply(Project(session, finished, NativeProvisioningState.Unknown, SecretStatus.Success,
                    frozenConfiguration with
                    {
                        Policies = frozenConfiguration.Policies.Select(p =>
                        p with { Permissions = p.Permissions.ToArray() }).ToArray()
                    }));
            }
        }

        var baselineProof = session.StatusUpdateBaseline;
        Require(baselineProof is not null && session.StartFinished && session.StartTask is { IsCompletedSuccessfully: true });
        Require(capture.TryGetStatusTarget(session.Capture!, binding, out var target) &&
            capture.OwnsStatusTarget(target, binding) && ReferenceEquals(target.Binding, binding));
        var statusWindow = statuses.Arm(target, binding);
        var statusTask = statuses.CollectAsync(statusWindow, binding, token).AsTask();
        var status = await statusTask.ConfigureAwait(false);
        Require(ReferenceEquals(status.Binding, binding) && status.WindowId == statusWindow.Id &&
            status.ArmedAt == statusWindow.ArmedAt && status.StartedAt >= status.ArmedAt &&
            status.ArmedAt >= session.StartedAt && status.FinishedAt >= status.StartedAt &&
            status.HttpStatus == 200 && status.ResponseComplete && status.Terminal &&
            status.Status == SecretStatus.Success && status.OperationState == NativeProvisioningState.Succeeded &&
            status.StartDispatch == target.StartDispatch && status.TargetSha256 == target.TargetSha256 &&
            status.StartResponseSha256 == target.StartResponseSha256 && Text(status.NativeRequestId, 256));
        var activePostTask = after.CollectAsync(session.After!, binding, token).AsTask();
        using var activePost = await activePostTask.ConfigureAwait(false);
        Require(StatusCancellationResourceBound(activePost, session, binding, session.After!) &&
            activePost.StartedAt >= status.FinishedAt && activePost.HttpStatus == 200 &&
            activePost.ResourceStatus == SecretStatus.Success && activePost.PersistedStateEligible &&
            activePost.ResourceId == plan.VaultId && activePost.NativeState == "Succeeded" &&
            activePost.VaultConfiguration is { CreateMode: null or "default" });
        var postVault = activePost.VaultConfiguration;
        var postConfiguration = new VaultAdministrationEffects.Configuration(postVault.Location, postVault.TenantId,
            postVault.Sku, postVault.Rbac, postVault.PurgeProtection, postVault.RetentionDays, postVault.PublicNetworkAccess,
            postVault.Policies.Select(p => new VaultAdministrationEffects.Policy(
                p.TenantId, p.PrincipalId, p.Permissions.ToArray(), p.ApplicationId)).ToArray());
        Require(VaultAdministrationEffects.SameConfiguration(postConfiguration, baselineProof.Selected) &&
            !VaultAdministrationEffects.SameConfiguration(postConfiguration, baselineProof.Configuration) &&
            VaultAdministrationEffects.SameConfiguration(baselineProof.Configuration with { PublicNetworkAccess = true },
                postConfiguration));
        var deletedPostTask = statusCounterpartAfterCollector!.CollectAsync(session.CounterpartAfter!, counterpart, token).AsTask();
        using var deletedPost = await deletedPostTask.ConfigureAwait(false);
        Require(StatusCancellationResourceBound(deletedPost, session, counterpart, session.CounterpartAfter!) &&
            deletedPost.StartedAt >= activePost.FinishedAt && deletedPost.HttpStatus == 404 &&
            deletedPost.ResourceStatus == SecretStatus.Absent && deletedPost.ResourceId is null && deletedPost.DeletedVault is null);
        var ownedPostTask = provisioner.ObserveAsync(owner, session.Selector, token).AsTask();
        var ownedPost = await ownedPostTask.ConfigureAwait(false);
        Require(ownedPost.State == VaultFixtureProvisioner.State.Pending && ownedPost.VaultPresent == true &&
            ownedPost.DeletedVaultPresent == false && ownedPost.DeletedVault is null &&
            ownedPost.Configuration is not null &&
            VaultAdministrationEffects.SameConfiguration(ownedPost.Configuration, postConfiguration) &&
            MatchesStatusUpdateRoot(baselineProof, ownedPost.Journal));
        DateTimeOffset observed = time.GetUtcNow();
        Require(observed >= deletedPost.FinishedAt);
        var observation = new StatusVaultUpdateCancellationObservation(baselineProof, target, statusWindow, statusTask,
            session.After!, session.CounterpartAfter!, activePostTask, deletedPostTask, ownedPostTask, postConfiguration, observed);
        lock (gate)
        {
            Require(!disposed && !session.Closed && !token.IsCancellationRequested &&
                ReferenceEquals(baselineProof, session.StatusUpdateBaseline));
            var snapshot = provisioner.Journal.Read(owner, session.Selector);
            Require(MatchesStatusUpdateRoot(baselineProof, snapshot) && !snapshot.Closing &&
                snapshot.Resources.Single(r => r.Id == plan.VaultId) is
                { SelectedAttempted: true, InvocationTerminated: true, ActiveDispatch: var dispatch } &&
                dispatch == session.Dispatch && dispatch != Guid.Empty);
            session.StatusUpdateObservation = observation;
            session.Target = target;
            session.IndependentAt = observed;
            session.IndependentReady = true;
            return Reply(Project(session, observed, NativeProvisioningState.Succeeded, SecretStatus.Success,
                postConfiguration with
                {
                    Policies = postConfiguration.Policies.Select(p =>
                    p with { Permissions = p.Permissions.ToArray() }).ToArray()
                }));
        }
    }

    private static bool StatusCancellationResourceBound(R.Measurement result, Session session, C.Binding binding,
        R.Window window) =>
        ReferenceEquals(result.Binding, binding) && ReferenceEquals(window.Binding, binding) &&
        result.WindowId == window.Id && result.ArmedAt == window.ArmedAt && window.ArmedAt <= session.ArmedAt &&
        result.ResponseComplete && result.StartedAt >= session.ArmedAt && result.FinishedAt >= result.StartedAt &&
        Text(result.NativeRequestId, 256);

    private async ValueTask<SecretStatus> CheckStatusVaultCancellation(FixtureSelector selector,
        ManagementOperation handle, CancellationToken cancellationToken)
    {
        Session session;
        bool canceled, purge = VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(selector);
        bool recover = VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector);
        bool update = VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector);
        bool notification = NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector);
        bool notificationUpdate = NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector);
        bool notificationCreate = NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector);
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(session.StartFinished && session.StartSucceeded && session.IndependentReady &&
                (notificationCreate ? session.StatusNotificationCreateObservation is not null :
                    notificationUpdate ? session.StatusNotificationUpdateObservation is not null :
                    notification ? session.StatusNotificationObservation is not null :
                    update ? session.StatusUpdateObservation is not null : recover ? session.StatusRecoverObservation is not null :
                    purge ? session.StatusPurgeObservation is not null : session.StatusDeleteObservation is not null) &&
                !session.StatusClaimed &&
                ReferenceEquals(handle, session.Handle) && session.Active == 0);
            canceled = !session.CancelClaimed;
            if (notificationUpdate || notificationCreate)
            {
                if (canceled) session.CancelClaimed = true;
                else session.StatusClaimed = true;
            }
            if (canceled)
                Require(cancellationToken.IsCancellationRequested);
            else
                Require(!cancellationToken.IsCancellationRequested && session.CancelFinished &&
                    (notificationCreate ? OwnsStatusNotificationCreateCancellation(session) :
                        notificationUpdate ? OwnsStatusNotificationUpdateCancellation(session) :
                        notification ? OwnsStatusNotificationCancellation(session) :
                        update ? OwnsStatusUpdateCancellation(session) : recover ? OwnsStatusRecoverCancellation(session) :
                        purge ? OwnsStatusPurgeCancellation(session) : OwnsStatusDeleteCancellation(session)));
            provisioner.Journal.AdmitStatusRead(owner, selector, session.Plan!.LeaseId, SelectedId(session), session.Dispatch);
            if (!notificationUpdate && !notificationCreate)
            {
                if (canceled) session.CancelClaimed = true;
                else session.StatusClaimed = true;
            }
            session.Active++;
            active++;
        }
        bool propagated = false, settled = false;
        try
        {
            Require(time.GetUtcNow() >= session.IndependentAt);
            if (canceled)
            {
                try
                {
                    return await capture.CheckCanceledStatusAsync(session.Capture!, selector, handle, cancellationToken,
                        task => { lock (gate) session.CanceledTask = task; }).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    propagated = notificationCreate ? OwnsStatusNotificationCreateCancellation(session) :
                        notificationUpdate ? OwnsStatusNotificationUpdateCancellation(session) :
                        notification ? OwnsStatusNotificationCancellation(session) :
                        update ? OwnsStatusUpdateCancellation(session) : recover ? OwnsStatusRecoverCancellation(session) :
                        purge ? OwnsStatusPurgeCancellation(session) : OwnsStatusDeleteCancellation(session);
                    throw;
                }
            }
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            var status = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            Require(status == SecretStatus.Success &&
                (notificationCreate ? capture.OwnsStatusNotificationCreateCancellationCompletion(session.Capture!, session.Binding!,
                    session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!, handle,
                    session.CanceledTask!, session.StatusTask!) :
                notificationUpdate ? capture.OwnsStatusNotificationUpdateCancellationCompletion(session.Capture!, session.Binding!,
                    session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!, handle,
                    session.CanceledTask!, session.StatusTask!) :
                notification ? capture.OwnsStatusNotificationDeleteCancellationCompletion(session.Capture!, session.Binding!,
                    session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!, handle,
                    session.CanceledTask!, session.StatusTask!) :
                update ? capture.OwnsStatusVaultUpdateCancellationCompletion(session.Capture!, session.Binding!,
                    session.Client!, session.ActualVaultScope!, session.Receipt!, session.StartTask!, handle,
                    session.CanceledTask!, session.StatusTask!) :
                recover ? capture.OwnsStatusVaultRecoverCancellationCompletion(session.Capture!, session.Binding!,
                    session.Client!, session.ActualVaultScope!, session.Receipt!, session.StartTask!, handle,
                    session.CanceledTask!, session.StatusTask!) :
                purge ? capture.OwnsStatusVaultPurgeCancellationCompletion(session.Capture!, session.Binding!,
                    session.Client!, session.ActualDeletedVaultScope!, session.Receipt!, session.StartTask!, handle,
                    session.CanceledTask!, session.StatusTask!) :
                capture.OwnsStatusVaultDeleteCancellationCompletion(session.Capture!, session.Binding!,
                    session.Client!, session.ActualVaultScope!, session.Receipt!, session.StartTask!, handle,
                    session.CanceledTask!, session.StatusTask!)));
            lock (gate)
            {
                Require(!disposed && !session.Closed && !linked.IsCancellationRequested && session.CancelFinished);
                // This journal transaction, not freezing the candidate, settles.
                if (notificationCreate)
                {
                    var observation = session.StatusNotificationCreateObservation!;
                    RoleFixtureJournal.NotificationAbsentCreateState? absentCreation = null;
                    if (observation.Baseline.AbsentCreate is { } declaration)
                    {
                        // Freeze material-free evidence before entering the journal
                        // transaction. Validate below only inspects frozen facts.
                        absentCreation = declaration with
                        {
                            InvocationDispatch = session.Dispatch,
                            SettledDispatch = session.Dispatch,
                            BaselineSha256 = observation.Baseline.BaselineSha256,
                            StartSha256 = NotificationFixtureProvisioner.Digest(observation.Start.RequestSha256,
                                observation.Start.ResponseSha256, observation.Start.NativeRequestId,
                                observation.Start.StartDispatch.ToString("D"), observation.Start.RawLabels!),
                            SelectedSha256 = NotificationFixtureProvisioner.Digest(
                                NotificationFixtureProvisioner.ReadDigest(observation.Proof),
                                observation.Target.TargetSha256, observation.StatusTask.Result.StartResponseSha256,
                                observation.StatusTask.Result.NativeRequestId!),
                            CompletionSha256 = capture.NotificationCreateCompletionDigest(session.Capture!, session.Binding!,
                                session.Client!, session.ActualNotificationScope!, session.Receipt!, session.StartTask!,
                                handle, session.CanceledTask!, session.StatusTask!),
                            ConfigurationSha256 = NotificationFixtureProvisioner.ConfigurationDigest(observation.Configuration)
                        };
                    }
                    var completion = new StatusNotificationCreateCompletion(session.StatusNotificationCreateObservation!,
                        session.Dispatch, session.Capture!, session.Client!, session.ActualNotificationScope!, session.Receipt!,
                        session.StartTask!, handle, session.CanceledTask!, session.StatusTask!, linked.Token, cancellationToken,
                        absentCreation);
                    var candidate = new StatusNotificationCreateCancellationSettlement(this, session.Dispatch);
                    Require(statusNotificationCreateSettlements.TryAdd(candidate, completion));
                    if (absentCreation is not null)
                        _ = provisioner.Journal.CompleteStatusNotificationAbsentCreateCancellationRead(owner, selector,
                            session.Plan!.LeaseId, session.Dispatch, candidate);
                    else
                        _ = provisioner.Journal.CompleteStatusNotificationCreateCancellationRead(owner, selector,
                            session.Plan!.LeaseId, session.Dispatch, candidate);
                }
                else if (notificationUpdate)
                {
                    var completion = new StatusNotificationUpdateCompletion(session.StatusNotificationUpdateObservation!,
                        session.Dispatch, session.Capture!, session.Client!, session.ActualNotificationScope!, session.Receipt!,
                        session.StartTask!, handle, session.CanceledTask!, session.StatusTask!, linked.Token, cancellationToken);
                    var candidate = new StatusNotificationUpdateCancellationSettlement(this, session.Dispatch);
                    Require(statusNotificationUpdateSettlements.TryAdd(candidate, completion));
                    _ = provisioner.Journal.CompleteStatusNotificationUpdateCancellationRead(owner, selector,
                        session.Plan!.LeaseId, session.Dispatch, candidate);
                }
                else if (notification)
                {
                    var completion = new StatusNotificationDeleteCancellationCompletion(session.StatusNotificationObservation!,
                        session.Dispatch, session.Capture!, session.Client!, session.ActualNotificationScope!, session.Receipt!,
                        session.StartTask!, handle, session.CanceledTask!, session.StatusTask!, linked.Token, cancellationToken);
                    var candidate = new StatusNotificationDeleteCancellationSettlement(this, session.Dispatch);
                    Require(statusNotificationDeleteSettlements.TryAdd(candidate, completion));
                    _ = provisioner.Journal.CompleteStatusNotificationDeleteCancellationRead(owner, selector,
                        session.Plan!.LeaseId, session.Dispatch, candidate);
                }
                else if (update)
                {
                    var completion = new StatusVaultUpdateCancellationCompletion(session.StatusUpdateObservation!,
                        session.Dispatch, session.Capture!, session.Client!, session.ActualVaultScope!, session.Receipt!,
                        session.StartTask!, handle, session.CanceledTask!, session.StatusTask!, linked.Token, cancellationToken);
                    var candidate = new StatusVaultUpdateCancellationSettlement(this, session.Dispatch);
                    Require(statusUpdateSettlements.TryAdd(candidate, completion));
                    _ = provisioner.Journal.CompleteStatusVaultUpdateCancellationRead(owner, selector, session.Plan!.LeaseId,
                        session.Dispatch, candidate);
                }
                else if (recover)
                {
                    var completion = new StatusVaultRecoverCancellationCompletion(session.StatusRecoverObservation!,
                        session.Dispatch, session.Capture!, session.Client!, session.ActualVaultScope!, session.Receipt!,
                        session.StartTask!, handle, session.CanceledTask!, session.StatusTask!, linked.Token, cancellationToken);
                    var candidate = new StatusVaultRecoverCancellationSettlement(this, session.Dispatch);
                    Require(statusRecoverSettlements.TryAdd(candidate, completion));
                    _ = provisioner.Journal.CompleteStatusVaultRecoverCancellationRead(owner, selector, session.Plan!.LeaseId,
                        session.Dispatch, candidate);
                }
                else if (purge)
                {
                    var completion = new StatusVaultPurgeCancellationCompletion(session.StatusPurgeObservation!,
                        session.Dispatch, session.Capture!, session.Client!, session.ActualDeletedVaultScope!, session.Receipt!,
                        session.StartTask!, handle, session.CanceledTask!, session.StatusTask!, linked.Token, cancellationToken);
                    var candidate = new StatusVaultPurgeCancellationSettlement(this, session.Dispatch);
                    Require(statusPurgeSettlements.TryAdd(candidate, completion));
                    _ = provisioner.Journal.CompleteStatusVaultPurgeCancellationRead(owner, selector, session.Plan!.LeaseId,
                        session.Dispatch, candidate);
                }
                else
                {
                    var completion = new StatusVaultDeleteCancellationCompletion(session.StatusDeleteObservation!,
                        session.Dispatch, session.Capture!, session.Client!, session.ActualVaultScope!, session.Receipt!,
                        session.StartTask!, handle, session.CanceledTask!, session.StatusTask!, linked.Token, cancellationToken);
                    var candidate = new StatusVaultDeleteCancellationSettlement(this, session.Dispatch);
                    Require(statusDeleteSettlements.TryAdd(candidate, completion));
                    _ = provisioner.Journal.CompleteStatusVaultDeleteCancellationRead(owner, selector, session.Plan!.LeaseId,
                        session.Dispatch, candidate);
                }
                settled = session.StatusSucceeded = true;
            }
            return status;
        }
        finally
        {
            try
            {
                if (!settled)
                    provisioner.Journal.EndDispatch(owner, selector, SelectedId(session), session.Dispatch,
                        nativeSettled: false);
                if (canceled && propagated)
                    lock (gate) session.CancelFinished = true;
            }
            finally { Leave(session); }
        }
    }

    private bool OwnsStatusNotificationCreateCancellation(Session session) =>
        session.Client is { } client && session.ActualNotificationScope is { } actualScope &&
        session.Receipt is { } receipt && session.StartTask is { } start && session.Handle is { } handle &&
        session.CanceledTask is { IsCanceled: true } canceled &&
        capture.OwnsNotificationCreateCanceledStatusAttempt(session.Capture!, session.Binding!, client, actualScope,
            receipt, start, handle, canceled);

    private bool ValidateStatusNotificationCreateAdmission(StatusNotificationCreateCancellationAdmission candidate,
        RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
        ReferenceEquals(journal, provisioner.Journal) &&
        statusNotificationCreateAdmissions.TryGetValue(candidate, out var baseline) &&
        baseline.Task.IsCompletedSuccessfully && ValidNotificationCreateBaseline(baseline) &&
        MatchesStatusNotificationCreateRoot(baseline, snapshot) && !snapshot.Closing && snapshot.Idle &&
        baseline.Rows.SequenceEqual(snapshot.Resources);

    private bool ValidateStatusNotificationCreateSettlement(StatusNotificationCreateCancellationSettlement candidate,
        RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
        ReferenceEquals(journal, provisioner.Journal) &&
        statusNotificationCreateSettlements.TryGetValue(candidate, out var completion) &&
        candidate.Dispatch == completion.Dispatch && completion.Dispatch != Guid.Empty &&
        !completion.Cancellation.IsCancellationRequested && !completion.CallerCancellation.IsCancellationRequested &&
        completion.StartTask.IsCompletedSuccessfully && completion.CanceledTask.IsCanceled &&
        completion.StatusTask.IsCompletedSuccessfully && !ReferenceEquals(completion.CanceledTask, completion.StatusTask) &&
        completion.Observation.Baseline.Task.IsCompletedSuccessfully && completion.Observation.Task.IsCompletedSuccessfully &&
        ValidNotificationCreateBaseline(completion.Observation.Baseline) &&
        completion.Observation.Proof.NativeTask.IsCompletedSuccessfully &&
        completion.Observation.StatusTask.IsCompletedSuccessfully &&
        MatchesStatusNotificationCreateRoot(completion.Observation.Baseline, snapshot) && !snapshot.Closing &&
        snapshot.Resources.Single(r => r.Id == completion.Observation.Slot.Child.ResourceId) is
        {
            SelectedAttempted: true, InvocationTerminated: false, DeleteAttempted: false, Absent: false,
            ActiveDispatch: var dispatch
        } && dispatch == completion.Dispatch;

    private static bool MatchesStatusNotificationCreateRoot(StatusNotificationCreateBaseline baseline,
        RoleFixtureJournal.Snapshot snapshot) =>
        RoleFixtureJournal.StatusNotificationCreateRoot(snapshot) &&
        (baseline.AbsentCreate is { } creation
            ? baseline.Slot.Child.Preparation == NotificationFixtureProvisioner.Preparation.Absent &&
                snapshot.NotificationAbsentCreate is { } retained &&
                retained.NamespaceEpoch == creation.NamespaceEpoch && retained.ContractVersion == creation.ContractVersion &&
                retained.ParentId == creation.ParentId && retained.ChildId == creation.ChildId
            : baseline.Slot.Child.Preparation == NotificationFixtureProvisioner.Preparation.Present &&
                snapshot.NotificationAbsentCreate is null) &&
        snapshot.Owner == baseline.Slot.Child.Owner && snapshot.Selector == baseline.Slot.Child.Selector &&
        snapshot.LeaseId == baseline.Slot.Child.LeaseId && baseline.Rows.Count == 4 &&
        snapshot.Resources.All(r => !r.Absent) &&
        baseline.Rows.All(b => snapshot.Resources.Count(r => r.Id == b.Id &&
            (r.Id == baseline.Slot.Child.ResourceId
                ? !r.Borrowed && !r.CleanupOnly &&
                    r.CreateAttempted == (baseline.AbsentCreate is null || r.SelectedAttempted) &&
                    !r.DeleteAttempted && !r.Absent
                : r == b)) == 1);

    private static bool ValidNotificationCreateBaseline(StatusNotificationCreateBaseline baseline) =>
        baseline.AbsentCreate is null
            ? baseline.Configuration is not null && baseline.Proof.NativeTask.IsCompletedSuccessfully &&
                baseline.Proof is { Present: true, HttpStatus: 200, NativeState: "Succeeded" }
            : baseline.Configuration is null && baseline.Proof.NativeTask.IsFaulted &&
                baseline.Proof is { Present: false, HttpStatus: 404, NativeState: null };

    private bool OwnsStatusNotificationUpdateCancellation(Session session) =>
        session.Client is { } client && session.ActualNotificationScope is { } actualScope &&
        session.Receipt is { } receipt && session.StartTask is { } start && session.Handle is { } handle &&
        session.CanceledTask is { IsCanceled: true } canceled &&
        capture.OwnsNotificationUpdateCanceledStatusAttempt(session.Capture!, session.Binding!, client, actualScope,
            receipt, start, handle, canceled);

    private bool ValidateStatusNotificationUpdateAdmission(StatusNotificationUpdateCancellationAdmission candidate,
        RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
        ReferenceEquals(journal, provisioner.Journal) &&
        statusNotificationUpdateAdmissions.TryGetValue(candidate, out var baseline) &&
        baseline.Task.IsCompletedSuccessfully && baseline.Proof.NativeTask.IsCompletedSuccessfully &&
        MatchesStatusNotificationUpdateRoot(baseline, snapshot) && !snapshot.Closing && snapshot.Idle &&
        baseline.Rows.SequenceEqual(snapshot.Resources);

    private bool ValidateStatusNotificationUpdateSettlement(StatusNotificationUpdateCancellationSettlement candidate,
        RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
        ReferenceEquals(journal, provisioner.Journal) &&
        statusNotificationUpdateSettlements.TryGetValue(candidate, out var completion) &&
        candidate.Dispatch == completion.Dispatch && completion.Dispatch != Guid.Empty &&
        !completion.Cancellation.IsCancellationRequested && !completion.CallerCancellation.IsCancellationRequested &&
        completion.StartTask.IsCompletedSuccessfully && completion.CanceledTask.IsCanceled &&
        completion.StatusTask.IsCompletedSuccessfully && !ReferenceEquals(completion.CanceledTask, completion.StatusTask) &&
        completion.Observation.Baseline.Task.IsCompletedSuccessfully && completion.Observation.Task.IsCompletedSuccessfully &&
        completion.Observation.Baseline.Proof.NativeTask.IsCompletedSuccessfully &&
        completion.Observation.Proof.NativeTask.IsCompletedSuccessfully &&
        completion.Observation.StatusTask.IsCompletedSuccessfully &&
        MatchesStatusNotificationUpdateRoot(completion.Observation.Baseline, snapshot) && !snapshot.Closing &&
        snapshot.Resources.Single(r => r.Id == completion.Observation.Slot.Child.ResourceId) is
        {
            SelectedAttempted: true, InvocationTerminated: false, DeleteAttempted: false, Absent: false,
            ActiveDispatch: var dispatch
        } && dispatch == completion.Dispatch;

    private static bool MatchesStatusNotificationUpdateRoot(StatusNotificationUpdateBaseline baseline,
        RoleFixtureJournal.Snapshot snapshot) =>
        RoleFixtureJournal.StatusNotificationUpdateRoot(snapshot) &&
        snapshot.Owner == baseline.Slot.Child.Owner && snapshot.Selector == baseline.Slot.Child.Selector &&
        snapshot.LeaseId == baseline.Slot.Child.LeaseId && baseline.Rows.Count == 4 &&
        snapshot.Resources.All(r => !r.Absent) &&
        baseline.Rows.All(b => snapshot.Resources.Count(r => r.Id == b.Id &&
            (r.Id == baseline.Slot.Child.ResourceId
                ? !r.Borrowed && !r.CleanupOnly && r.CreateAttempted && !r.DeleteAttempted && !r.Absent
                : r == b)) == 1);

    private bool OwnsStatusNotificationCancellation(Session session) =>
        session.Client is { } client && session.ActualNotificationScope is { } actualScope &&
        session.Receipt is { } receipt && session.StartTask is { } start && session.Handle is { } handle &&
        session.CanceledTask is { IsCanceled: true } canceled &&
        capture.OwnsNotificationDeleteCanceledStatusAttempt(session.Capture!, session.Binding!, client, actualScope,
            receipt, start, handle, canceled);

    private bool ValidateStatusNotificationDeleteCancellationSettlement(StatusNotificationDeleteCancellationSettlement candidate,
        RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
        ReferenceEquals(journal, provisioner.Journal) &&
        statusNotificationDeleteSettlements.TryGetValue(candidate, out var completion) &&
        candidate.Dispatch == completion.Dispatch && completion.Dispatch != Guid.Empty &&
        !completion.Cancellation.IsCancellationRequested && !completion.CallerCancellation.IsCancellationRequested &&
        completion.StartTask.IsCompletedSuccessfully && completion.CanceledTask.IsCanceled &&
        completion.StatusTask.IsCompletedSuccessfully && !ReferenceEquals(completion.CanceledTask, completion.StatusTask) &&
        completion.Observation.Baseline.Task.IsCompletedSuccessfully && completion.Observation.Task.IsCompletedSuccessfully &&
        completion.Observation.Baseline.Proof.NativeTask.IsCompletedSuccessfully &&
        completion.Observation.Proof.NativeTask.IsFaulted &&
        MatchesStatusNotificationRoot(completion.Observation.Baseline, snapshot) && !snapshot.Closing &&
        snapshot.Resources.Single(r => r.Id == completion.Observation.Slot.Child.ResourceId) is
        { SelectedAttempted: true, InvocationTerminated: false, ActiveDispatch: var dispatch } &&
        dispatch == completion.Dispatch;

    private static bool MatchesStatusNotificationRoot(StatusNotificationDeleteCancellationBaseline baseline,
        RoleFixtureJournal.Snapshot snapshot) =>
        RoleFixtureJournal.StatusNotificationDeleteRoot(snapshot) &&
        snapshot.Owner == baseline.Slot.Child.Owner && snapshot.Selector == baseline.Slot.Child.Selector &&
        snapshot.LeaseId == baseline.Slot.Child.LeaseId && baseline.Rows.Count == 4 &&
        snapshot.Resources.All(r => !r.Absent) &&
        baseline.Rows.All(b => snapshot.Resources.Count(r => r.Id == b.Id &&
            (r.Id == baseline.Slot.Child.ResourceId
                ? !r.Borrowed && !r.CleanupOnly && r.CreateAttempted && !r.DeleteAttempted && !r.Absent
                : r == b)) == 1);

    private bool OwnsStatusDeleteCancellation(Session session) =>
        session.Client is { } client && session.ActualVaultScope is { } actualScope &&
        session.Receipt is { } receipt && session.StartTask is { } start && session.Handle is { } handle &&
        session.CanceledTask is { IsCanceled: true } canceled &&
        capture.OwnsCanceledStatusAttempt(session.Capture!, session.Binding!, client, actualScope, receipt,
            start, handle, canceled);

    private bool OwnsStatusPurgeCancellation(Session session) =>
        session.Client is { } client && session.ActualDeletedVaultScope is { } actualScope &&
        session.Receipt is { } receipt && session.StartTask is { } start && session.Handle is { } handle &&
        session.CanceledTask is { IsCanceled: true } canceled &&
        capture.OwnsPurgeCanceledStatusAttempt(session.Capture!, session.Binding!, client, actualScope, receipt,
            start, handle, canceled);

    private bool OwnsStatusRecoverCancellation(Session session) =>
        session.Client is { } client && session.ActualVaultScope is { } actualScope &&
        session.Receipt is { } receipt && session.StartTask is { } start && session.Handle is { } handle &&
        session.CanceledTask is { IsCanceled: true } canceled &&
        capture.OwnsRecoverCanceledStatusAttempt(session.Capture!, session.Binding!, client, actualScope, receipt,
            start, handle, canceled);

    private bool OwnsStatusUpdateCancellation(Session session) =>
        session.Client is { } client && session.ActualVaultScope is { } actualScope &&
        session.Receipt is { } receipt && session.StartTask is { } start && session.Handle is { } handle &&
        session.CanceledTask is { IsCanceled: true } canceled &&
        capture.OwnsUpdateCanceledStatusAttempt(session.Capture!, session.Binding!, client, actualScope, receipt,
            start, handle, canceled);

    private bool ValidateStatusVaultUpdateCancellationSettlement(StatusVaultUpdateCancellationSettlement candidate,
        RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
        ReferenceEquals(journal, provisioner.Journal) &&
        statusUpdateSettlements.TryGetValue(candidate, out var completion) &&
        candidate.Dispatch == completion.Dispatch && completion.Dispatch != Guid.Empty &&
        !completion.Cancellation.IsCancellationRequested && !completion.CallerCancellation.IsCancellationRequested &&
        completion.StartTask.IsCompletedSuccessfully &&
        completion.CanceledTask.IsCanceled && completion.StatusTask.IsCompletedSuccessfully &&
        !ReferenceEquals(completion.CanceledTask, completion.StatusTask) &&
        completion.Observation.Baseline.ActiveTask.IsCompletedSuccessfully &&
        completion.Observation.Baseline.DeletedTask.IsCompletedSuccessfully &&
        completion.Observation.Baseline.OwnedTask.IsCompletedSuccessfully &&
        completion.Observation.StatusTask.IsCompletedSuccessfully && completion.Observation.ActiveTask.IsCompletedSuccessfully &&
        completion.Observation.DeletedTask.IsCompletedSuccessfully && completion.Observation.OwnedTask.IsCompletedSuccessfully &&
        VaultAdministrationEffects.SameConfiguration(completion.Observation.Configuration,
            completion.Observation.Baseline.Selected) &&
        MatchesStatusUpdateRoot(completion.Observation.Baseline, snapshot) &&
        !snapshot.Closing && snapshot.Resources.Single(r => r.Id == completion.Observation.Baseline.VaultId).ActiveDispatch ==
            completion.Dispatch;

    private static bool MatchesStatusUpdateRoot(StatusVaultUpdateCancellationBaseline baseline,
        RoleFixtureJournal.Snapshot snapshot) =>
        snapshot.Owner == baseline.Owner && snapshot.Selector == baseline.Selector && snapshot.LeaseId == baseline.Lease &&
        VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(snapshot.Selector) &&
        snapshot.StatusVaultUpdateCancellationBaseline is { } configuration &&
        VaultAdministrationEffects.SameConfiguration(configuration, baseline.Configuration) &&
        !VaultAdministrationEffects.SameConfiguration(baseline.Configuration, baseline.Selected) &&
        VaultAdministrationEffects.SameConfiguration(baseline.Configuration with { PublicNetworkAccess = true }, baseline.Selected) &&
        snapshot.StatusVaultRecoverCancellationBaseline is null && snapshot.PrivateEndpoint is null &&
        snapshot.Settings is null && snapshot.DeleteVault is null && snapshot.PurgeDeletedVault is null &&
        snapshot.CreateOrUpdateVault is null && snapshot.RecoverVault is null &&
        snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed && !r.Absent) &&
        snapshot.Resources.Count(r => r.Id == baseline.VaultId && !r.CleanupOnly && r.CreateAttempted &&
            !r.DeleteAttempted) == 1 &&
        snapshot.Resources.Count(r => r.Id == baseline.SecretId && r.CleanupOnly && !r.CreateAttempted &&
            !r.DeleteAttempted && !r.SelectedAttempted && !r.InvocationTerminated && r.ActiveDispatch == Guid.Empty) == 1 &&
        snapshot.Resources.Count(r => r.Id == baseline.DeletedId && r.CleanupOnly && !r.CreateAttempted &&
            !r.DeleteAttempted && !r.SelectedAttempted && !r.InvocationTerminated && r.ActiveDispatch == Guid.Empty) == 1;

    private bool ValidateStatusVaultRecoverCancellationSettlement(StatusVaultRecoverCancellationSettlement candidate,
        RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
        ReferenceEquals(journal, provisioner.Journal) &&
        statusRecoverSettlements.TryGetValue(candidate, out var completion) &&
        candidate.Dispatch == completion.Dispatch && completion.Dispatch != Guid.Empty &&
        !completion.Cancellation.IsCancellationRequested && !completion.CallerCancellation.IsCancellationRequested &&
        completion.StartTask.IsCompletedSuccessfully &&
        completion.CanceledTask.IsCanceled && completion.StatusTask.IsCompletedSuccessfully &&
        completion.Observation.Baseline.ActiveTask.IsCompletedSuccessfully &&
        completion.Observation.Baseline.DeletedTask.IsCompletedSuccessfully &&
        completion.Observation.Baseline.OwnedTask.IsCompletedSuccessfully &&
        completion.Observation.StatusTask.IsCompletedSuccessfully && completion.Observation.ActiveTask.IsCompletedSuccessfully &&
        completion.Observation.DeletedTask.IsCompletedSuccessfully && completion.Observation.OwnedTask.IsCompletedSuccessfully &&
        MatchesStatusRecoverRoot(completion.Observation.Baseline, snapshot) &&
        !snapshot.Closing && snapshot.Resources.Single(r => r.Id == completion.Observation.Baseline.VaultId).ActiveDispatch ==
            completion.Dispatch;

    private static bool MatchesStatusRecoverRoot(StatusVaultRecoverCancellationBaseline baseline,
        RoleFixtureJournal.Snapshot snapshot) =>
        snapshot.Owner == baseline.Owner && snapshot.Selector == baseline.Selector && snapshot.LeaseId == baseline.Lease &&
        VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(snapshot.Selector) &&
        snapshot.StatusVaultRecoverCancellationBaseline is { } configuration &&
        VaultAdministrationEffects.SameConfiguration(configuration, baseline.Configuration) &&
        snapshot.PrivateEndpoint is null && snapshot.Settings is null && snapshot.DeleteVault is null &&
        snapshot.PurgeDeletedVault is null && snapshot.CreateOrUpdateVault is null && snapshot.RecoverVault is null &&
        snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed && !r.Absent) &&
        snapshot.Resources.Count(r => r.Id == baseline.VaultId && !r.CleanupOnly && r.CreateAttempted &&
            !r.DeleteAttempted) == 1 &&
        snapshot.Resources.Count(r => r.Id == baseline.SecretId && r.CleanupOnly && !r.CreateAttempted &&
            !r.DeleteAttempted && !r.SelectedAttempted && !r.InvocationTerminated && r.ActiveDispatch == Guid.Empty) == 1 &&
        snapshot.Resources.Count(r => r.Id == baseline.DeletedId && !r.CleanupOnly && r.CreateAttempted &&
            r.InvocationTerminated && !r.DeleteAttempted && !r.SelectedAttempted && r.ActiveDispatch == Guid.Empty) == 1;

    private bool ValidateStatusVaultPurgeCancellationSettlement(StatusVaultPurgeCancellationSettlement candidate,
        RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
        ReferenceEquals(journal, provisioner.Journal) &&
        statusPurgeSettlements.TryGetValue(candidate, out var completion) &&
        candidate.Dispatch == completion.Dispatch && completion.Dispatch != Guid.Empty &&
        !completion.Cancellation.IsCancellationRequested && !completion.CallerCancellation.IsCancellationRequested &&
        completion.StartTask.IsCompletedSuccessfully &&
        completion.CanceledTask.IsCanceled && completion.StatusTask.IsCompletedSuccessfully &&
        completion.Observation.Baseline.ActiveTask.IsCompletedSuccessfully &&
        completion.Observation.Baseline.DeletedTask.IsCompletedSuccessfully &&
        completion.Observation.StatusTask.IsCompletedSuccessfully && completion.Observation.ActiveTask.IsCompletedSuccessfully &&
        completion.Observation.DeletedTask.IsCompletedSuccessfully &&
        MatchesStatusPurgeRoot(completion.Observation.Baseline, snapshot) &&
        !snapshot.Closing && snapshot.Resources.Single(r => r.Id == completion.Observation.Baseline.DeletedId).ActiveDispatch ==
            completion.Dispatch;

    private static bool MatchesStatusPurgeRoot(StatusVaultPurgeCancellationBaseline baseline,
        RoleFixtureJournal.Snapshot snapshot) =>
        snapshot.Owner == baseline.Owner && snapshot.Selector == baseline.Selector && snapshot.LeaseId == baseline.Lease &&
        VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(snapshot.Selector) &&
        snapshot.PrivateEndpoint is null && snapshot.Settings is null && snapshot.DeleteVault is null &&
        snapshot.PurgeDeletedVault is null && snapshot.CreateOrUpdateVault is null && snapshot.RecoverVault is null &&
        snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed) &&
        snapshot.Resources.Count(r => r.Id == baseline.VaultId && !r.CleanupOnly && r.CreateAttempted &&
            r.InvocationTerminated && !r.DeleteAttempted && !r.SelectedAttempted && r.ActiveDispatch == Guid.Empty) == 1 &&
        snapshot.Resources.Count(r => r.Id == baseline.SecretId && r.CleanupOnly && !r.CreateAttempted &&
            !r.DeleteAttempted && !r.SelectedAttempted && !r.InvocationTerminated && r.ActiveDispatch == Guid.Empty) == 1 &&
        snapshot.Resources.Count(r => r.Id == baseline.DeletedId && !r.CleanupOnly && r.CreateAttempted &&
            !r.DeleteAttempted) == 1;

    // Membership and frozen local evidence only: no source lock, I/O, capture
    // predicate, provider call or nested journal read inside its transaction.
    private bool ValidateStatusVaultDeleteCancellationSettlement(StatusVaultDeleteCancellationSettlement candidate,
        RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
        ReferenceEquals(journal, provisioner.Journal) &&
        statusDeleteSettlements.TryGetValue(candidate, out var completion) &&
        candidate.Dispatch == completion.Dispatch && completion.Dispatch != Guid.Empty &&
        !completion.Cancellation.IsCancellationRequested && !completion.CallerCancellation.IsCancellationRequested &&
        completion.StartTask.IsCompletedSuccessfully &&
        completion.CanceledTask.IsCanceled && completion.StatusTask.IsCompletedSuccessfully &&
        completion.Observation.Baseline.ActiveTask.IsCompletedSuccessfully &&
        completion.Observation.Baseline.DeletedTask.IsCompletedSuccessfully &&
        completion.Observation.StatusTask.IsCompletedSuccessfully && completion.Observation.ActiveTask.IsCompletedSuccessfully &&
        completion.Observation.DeletedTask.IsCompletedSuccessfully &&
        MatchesStatusDeleteRoot(completion.Observation.Baseline, snapshot) &&
        !snapshot.Closing && snapshot.Resources.Single(r => r.Id == completion.Observation.Baseline.VaultId).ActiveDispatch ==
            completion.Dispatch;

    private static bool MatchesStatusDeleteRoot(StatusVaultDeleteCancellationBaseline baseline,
        RoleFixtureJournal.Snapshot snapshot) =>
        snapshot.Owner == baseline.Owner && snapshot.Selector == baseline.Selector && snapshot.LeaseId == baseline.Lease &&
        snapshot.PrivateEndpoint is null && snapshot.Settings is null && snapshot.DeleteVault is null &&
        snapshot.PurgeDeletedVault is null && snapshot.CreateOrUpdateVault is null && snapshot.RecoverVault is null &&
        snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed) &&
        snapshot.Resources.Count(r => r.Id == baseline.VaultId && !r.CleanupOnly && r.CreateAttempted && !r.DeleteAttempted) == 1 &&
        snapshot.Resources.Count(r => r.Id == baseline.SecretId && r.CleanupOnly && !r.CreateAttempted &&
            !r.DeleteAttempted && !r.SelectedAttempted && !r.InvocationTerminated && r.ActiveDispatch == Guid.Empty) == 1 &&
        snapshot.Resources.Count(r => r.Id == baseline.DeletedId && r.CleanupOnly && !r.CreateAttempted &&
            !r.DeleteAttempted && !r.SelectedAttempted && !r.InvocationTerminated && r.ActiveDispatch == Guid.Empty) == 1;

    private async Task<HttpResponseMessage> ObserveStatusPrivateConnectionDeleteSelected(Session session, bool baseline,
        CancellationToken token)
    {
        var parent = session.Plan!;
        Require(provisioner.TryEnterPrivateConnection(parent, session.ConnectionId!));
        try
        {
            RequireOriginalPrivateEndpoint(session);
            RequirePrivateRoot(session, provisioner.Journal.Read(owner, session.Selector));
            var reader = baseline ? before : after;
            var binding = session.Binding!;
            var window = baseline ? session.Before! : session.After!;
            C.StatusPrivateConnectionDeleteSelectedStartProof? start = null;
            if (!baseline)
            {
                Require(session.StatusPrivateDeleteSelectedBaseline is not null && OwnsStatusPrivateDeleteSelectedStart(session, out start));
                RequirePrivateDispatch(session, invocationTerminated: true);
            }
            var task = reader.CollectAsync(window, binding, token).AsTask();
            lock (gate)
            {
                if (baseline) session.StatusPrivateSelectedBeforeTask = task;
                else session.StatusPrivateSelectedAfterTask = task;
            }
            using var measured = await task.ConfigureAwait(false);
            Require(reader.TryGetStatusPrivateConnectionDeleteSelectedRead(window, binding, task, out var proof) &&
                reader.OwnsStatusPrivateConnectionDeleteSelectedRead(proof, window, binding, task) &&
                ReferenceEquals(measured.Binding, binding) && measured.WindowId == window.Id &&
                measured.ResponseComplete && proof.StartedAt >= (baseline ? session.ArmedAt : session.StartedAt) &&
                proof.FinishedAt >= proof.StartedAt);
            Require(baseline
                ? proof.HttpStatus == 200 && proof.Facts is { State: "Pending", Provisioning: "Succeeded" } facts &&
                    facts.Id == session.ConnectionId && facts.EndpointId == parent.PrivateEndpoint!.EndpointId &&
                    PrivateResourceMatches(session, measured, binding, window, PrivateConnectionState.Pending)
                : proof.HttpStatus == 404 && proof.Facts is null && proof.ErrorCode is "NotFound" or "ResourceNotFound" &&
                    measured.ResourceStatus == SecretStatus.Absent && measured.ResourceId is null &&
                    measured.ConnectionState is null && measured.PrivateEndpointId is null);

            // This phase owns its fresh raw/GenericResourceData endpoint join.
            // It is separate from both the native child GET and endpoint setup.
            var source = privateConnectionSource!;
            var endpointReader = new PrivateEndpointResourceCollector(source.EndpointReader, source.ResourceLimits, time);
            var endpointBinding = provisioner.EndpointBinding(parent);
            var endpointWindow = endpointReader.Arm(endpointBinding);
            var endpointTask = endpointReader.CollectAsync(endpointWindow, endpointBinding, token).AsTask();
            lock (gate)
            {
                if (baseline) session.StatusPrivateDeleteSelectedEndpointBefore = endpointTask;
                else session.StatusPrivateDeleteSelectedEndpointAfter = endpointTask;
            }
            var endpoint = await endpointTask.ConfigureAwait(false);
            Require(endpoint is
            {
                Kind: PrivateEndpointResourceCollector.ReadKind.Endpoint,
                ResponseComplete: true, HttpStatus: 200, ResourceStatus: SecretStatus.Success,
                NativeState: "Succeeded", MatchesDeclarationConfiguration: true
            } &&
                ReferenceEquals(endpoint.Binding, endpointBinding) && endpoint.WindowId == endpointWindow.Id &&
                endpointBinding.Selector == session.Selector && endpointBinding.LeaseId == parent.LeaseId &&
                endpoint.ManualConnectionState == (baseline ? "Pending" : "Disconnected") &&
                endpoint.StartedAt >= proof.FinishedAt && endpoint.FinishedAt >= endpoint.StartedAt &&
                Text(endpoint.NativeRequestId, 256));
            var endpointRead = new StatusPrivateDeleteEndpointRead(endpointReader, endpointBinding, endpointWindow,
                endpointTask, endpoint);
            token.ThrowIfCancellationRequested();
            RequireOriginalPrivateEndpoint(session);
            var snapshot = provisioner.Journal.Read(owner, session.Selector);
            RequirePrivateRoot(session, snapshot);
            if (!baseline)
                Require(OwnsStatusPrivateDeleteSelectedStart(session, out var issued) && ReferenceEquals(start, issued) &&
                    start!.EndpointId == session.StatusPrivateDeleteSelectedBaseline!.Proof.Facts!.EndpointId &&
                    session.StatusPrivateDeleteSelectedBaseline.Rows.SequenceEqual(snapshot.Resources));
            lock (gate)
            {
                Require(!disposed && !session.Closed && !snapshot.Closing);
                if (baseline)
                {
                    Require(!session.StartClaimed && snapshot.Idle &&
                        snapshot.PrivateEndpoint!.Connection is { SelectedAttempted: false, DeleteAttempted: false });
                    session.StatusPrivateDeleteSelectedBaseline = new(parent, session.Endpoints!, session.EndpointPlan!,
                        parent.PrivateEndpoint!, session.ConnectionId!, session.Subscription, session.ArmedAt,
                        reader, binding, window, task, proof, endpointRead,
                        Array.AsReadOnly(snapshot.Resources.ToArray()));
                    session.BaselineAt = endpoint.FinishedAt;
                    session.BaselineReady = true;
                }
                else
                {
                    session.StatusPrivateDeleteSelectedObservation = new(session.StatusPrivateDeleteSelectedBaseline!, reader, binding,
                        window, task, proof, endpointRead, start!);
                    session.IndependentAt = endpoint.FinishedAt;
                    session.IndependentReady = true;
                }
            }
            return Reply(new E.Measurement(parent.LeaseId, session.Selector.Nonce, observerIdentity,
                endpoint.FinishedAt, ManagementMutation.DeletePrivateConnection,
                baseline ? NativeProvisioningState.Unknown : NativeProvisioningState.Succeeded,
                session.ConnectionId!, baseline ? SecretStatus.Success : SecretStatus.Absent,
                null, baseline ? PrivateConnectionState.Pending : null, null));
        }
        finally { provisioner.ExitPrivateConnection(parent); }
    }

    private bool OwnsStatusPrivateDeleteSelectedStart(Session session,
        [NotNullWhen(true)] out C.StatusPrivateConnectionDeleteSelectedStartProof? proof)
    {
        proof = null;
        return session.StartFinished && session.StartSucceeded && session.Client is { } client &&
            session.ActualPrivateScope is { } originalScope && session.Receipt is { } receipt &&
            session.StartTask is { } task && session.Handle is { } handle &&
            capture.TryGetStatusPrivateConnectionDeleteSelectedStart(session.Capture!, session.Binding!,
                client, originalScope, receipt, task, handle, out proof) &&
            proof.EndpointId == session.Plan!.PrivateEndpoint!.EndpointId;
    }

    private async ValueTask<SecretOutcome<ManagementOperation>> StartStatusPrivateConnectionDeleteSelected(
        FixtureSelector selector, VaultAdministration client, ManagementScope originalScope, E.Input input,
        ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(client is not null && receipt is not null && originalScope is PrivateConnectionScope connection &&
                connection.Vault.ExportResourceId() == session.Plan!.VaultId &&
                session.Plan.VaultId + "/privateEndpointConnections/" + connection.ConnectionName == session.ConnectionId);
            Require(!session.StartClaimed);
            session.StartClaimed = true;
            Require(!session.StatusPrivateDeleteSelectedInvalid && session.Armed && session.BaselineReady &&
                session.StatusPrivateDeleteSelectedBaseline is not null &&
                InputMatches(session, input));
            session.Active++;
            active++;
        }
        bool entered = false;
        try
        {
            Require(entered = provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            RequireOriginalPrivateEndpoint(session);
            var baseline = session.StatusPrivateDeleteSelectedBaseline!;
            Require(baseline.Subscription == session.Subscription && baseline.ArmedAt == session.ArmedAt &&
                ReferenceEquals(baseline.Parent, session.Plan) && ReferenceEquals(baseline.Endpoints, session.Endpoints) &&
                ReferenceEquals(baseline.Endpoint, session.EndpointPlan) &&
                ReferenceEquals(baseline.Task, session.StatusPrivateSelectedBeforeTask) &&
                ReferenceEquals(baseline.EndpointRead.Task, session.StatusPrivateDeleteSelectedEndpointBefore) &&
                baseline.Reader.OwnsStatusPrivateConnectionDeleteSelectedRead(baseline.Proof, baseline.Window,
                    baseline.Binding, baseline.Task));
            var admission = new StatusPrivateConnectionDeleteSelectedAdmission(this);
            Require(statusPrivateDeleteSelectedAdmissions.TryAdd(admission, baseline));
            session.Binding = new(selector, session.Plan!.LeaseId, originalScope,
                ManagementMutation.DeletePrivateConnection, scope.Location, "2026-02-01");
            session.Client = client;
            session.ActualPrivateScope = (PrivateConnectionScope)originalScope;
            session.Receipt = receipt;
            session.Dispatch = provisioner.Journal.BeginStatusPrivateConnectionDeleteSelectedInvocation(owner, selector,
                session.Plan.LeaseId, admission);
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            session.Capture = capture.Arm(session.Binding);
            session.After = after.Arm(session.Binding, statusPrivateDeleteSelectedProfile: true);
            var result = await capture.StartAsync(session.Capture, selector, client, originalScope, input, receipt,
                linked.Token, task => { lock (gate) session.StartTask = task; }, () =>
                {
                    linked.Token.ThrowIfCancellationRequested();
                    Require(!disposed && !session.Closed);
                    provisioner.Journal.CheckStatusPrivateConnectionDeleteSelectedInvocation(owner, selector,
                        session.Plan.LeaseId, session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
                }, statusPrivateDeleteSelectedProfile: true).ConfigureAwait(false);
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
                if (session.Dispatch != Guid.Empty)
                    provisioner.Journal.EndStatusPrivateConnectionDeleteSelectedInvocation(owner, selector,
                        session.Plan!.LeaseId, session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
                lock (gate) session.StartFinished = true;
            }
            finally
            {
                if (entered) provisioner.ExitPrivateConnection(session.Plan!);
                Leave(session);
            }
        }
    }

    private async Task<HttpResponseMessage> ObserveStatusPrivateConnectionDeleteIndependent(Session session, bool baseline,
        CancellationToken token)
    {
        var parent = session.Plan!;
        Require(provisioner.TryEnterPrivateConnection(parent, session.ConnectionId!));
        try
        {
            RequireOriginalPrivateEndpoint(session);
            RequirePrivateRoot(session, provisioner.Journal.Read(owner, session.Selector));
            var reader = baseline ? before : after;
            var binding = session.Binding!;
            var window = baseline ? session.Before! : session.After!;
            C.StatusPrivateConnectionDeleteIndependentStartProof? start = null;
            if (!baseline)
            {
                Require(session.StatusPrivateDeleteIndependentBaseline is not null && OwnsStatusPrivateDeleteIndependentStart(session, out start));
                RequirePrivateDispatch(session, invocationTerminated: true);
            }
            var task = reader.CollectAsync(window, binding, token).AsTask();
            lock (gate)
            {
                if (baseline) session.StatusPrivateIndependentBeforeTask = task;
                else session.StatusPrivateIndependentAfterTask = task;
            }
            using var measured = await task.ConfigureAwait(false);
            Require(reader.TryGetStatusPrivateConnectionDeleteIndependentRead(window, binding, task, out var proof) &&
                reader.OwnsStatusPrivateConnectionDeleteIndependentRead(proof, window, binding, task) &&
                ReferenceEquals(measured.Binding, binding) && measured.WindowId == window.Id &&
                measured.ResponseComplete && proof.Phase == (baseline
                    ? R.StatusPrivateConnectionDeleteIndependentReadPhase.Baseline
                    : R.StatusPrivateConnectionDeleteIndependentReadPhase.SelectedState) && proof.StartedAt >= (baseline ? session.ArmedAt : session.StartedAt) &&
                proof.FinishedAt >= proof.StartedAt);
            Require(baseline
                ? proof.HttpStatus == 200 && proof.Facts is { State: "Pending", Provisioning: "Succeeded" } facts &&
                    facts.Id == session.ConnectionId && facts.EndpointId == parent.PrivateEndpoint!.EndpointId &&
                    PrivateResourceMatches(session, measured, binding, window, PrivateConnectionState.Pending)
                : proof.HttpStatus == 404 && proof.Facts is null && proof.ErrorCode is "NotFound" or "ResourceNotFound" &&
                    measured.ResourceStatus == SecretStatus.Absent && measured.ResourceId is null &&
                    measured.ConnectionState is null && measured.PrivateEndpointId is null);

            // This phase owns its fresh raw/GenericResourceData endpoint join.
            // It is separate from both the native child GET and endpoint setup.
            var source = privateConnectionSource!;
            var endpointReader = new PrivateEndpointResourceCollector(source.EndpointReader, source.ResourceLimits, time);
            var endpointBinding = provisioner.EndpointBinding(parent);
            var endpointWindow = endpointReader.Arm(endpointBinding);
            var endpointTask = endpointReader.CollectAsync(endpointWindow, endpointBinding, token).AsTask();
            lock (gate)
            {
                if (baseline) session.StatusPrivateDeleteIndependentEndpointBefore = endpointTask;
                else session.StatusPrivateDeleteIndependentEndpointAfter = endpointTask;
            }
            var endpoint = await endpointTask.ConfigureAwait(false);
            Require(endpoint is
            {
                Kind: PrivateEndpointResourceCollector.ReadKind.Endpoint,
                ResponseComplete: true, HttpStatus: 200, ResourceStatus: SecretStatus.Success,
                NativeState: "Succeeded", MatchesDeclarationConfiguration: true
            } &&
                ReferenceEquals(endpoint.Binding, endpointBinding) && endpoint.WindowId == endpointWindow.Id &&
                endpointBinding.Selector == session.Selector && endpointBinding.LeaseId == parent.LeaseId &&
                endpoint.ManualConnectionState == (baseline ? "Pending" : "Disconnected") &&
                endpoint.StartedAt >= proof.FinishedAt && endpoint.FinishedAt >= endpoint.StartedAt &&
                Text(endpoint.NativeRequestId, 256));
            var endpointRead = new StatusPrivateDeleteEndpointRead(endpointReader, endpointBinding, endpointWindow,
                endpointTask, endpoint);
            token.ThrowIfCancellationRequested();
            RequireOriginalPrivateEndpoint(session);
            var snapshot = provisioner.Journal.Read(owner, session.Selector);
            RequirePrivateRoot(session, snapshot);
            if (!baseline)
                Require(OwnsStatusPrivateDeleteIndependentStart(session, out var issued) && ReferenceEquals(start, issued) &&
                    !ReferenceEquals(task, session.StatusPrivateDeleteIndependentBaseline!.Task) &&
                    !ReferenceEquals(window, session.StatusPrivateDeleteIndependentBaseline.Window) &&
                    !ReferenceEquals(endpointTask, session.StatusPrivateDeleteIndependentBaseline.EndpointRead.Task) &&
                    start!.EndpointId == session.StatusPrivateDeleteIndependentBaseline!.Proof.Facts!.EndpointId &&
                    session.StatusPrivateDeleteIndependentBaseline.Rows.SequenceEqual(snapshot.Resources));
            lock (gate)
            {
                Require(!disposed && !session.Closed && !snapshot.Closing);
                if (baseline)
                {
                    Require(!session.StartClaimed && snapshot.Idle &&
                        snapshot.PrivateEndpoint!.Connection is { SelectedAttempted: false, DeleteAttempted: false });
                    session.StatusPrivateDeleteIndependentBaseline = new(parent, session.Endpoints!, session.EndpointPlan!,
                        parent.PrivateEndpoint!, session.ConnectionId!, session.Subscription, session.ArmedAt,
                        reader, binding, window, task, proof, endpointRead,
                        Array.AsReadOnly(snapshot.Resources.ToArray()));
                    session.BaselineAt = endpoint.FinishedAt;
                    session.BaselineReady = true;
                }
                else
                {
                    session.StatusPrivateDeleteIndependentObservation = new(session.StatusPrivateDeleteIndependentBaseline!, reader, binding,
                        window, task, proof, endpointRead, start!);
                    session.IndependentAt = endpoint.FinishedAt;
                    session.IndependentReady = true;
                }
            }
            return Reply(new E.Measurement(parent.LeaseId, session.Selector.Nonce, observerIdentity,
                endpoint.FinishedAt, ManagementMutation.DeletePrivateConnection,
                baseline ? NativeProvisioningState.Unknown : NativeProvisioningState.Succeeded,
                session.ConnectionId!, baseline ? SecretStatus.Success : SecretStatus.Absent,
                null, baseline ? PrivateConnectionState.Pending : null, null));
        }
        finally { provisioner.ExitPrivateConnection(parent); }
    }

    private bool OwnsStatusPrivateDeleteIndependentStart(Session session,
        [NotNullWhen(true)] out C.StatusPrivateConnectionDeleteIndependentStartProof? proof)
    {
        proof = null;
        return session.StartFinished && session.StartSucceeded && session.Client is { } client &&
            session.ActualPrivateScope is { } originalScope && session.Receipt is { } receipt &&
            session.StartTask is { } task && session.Handle is { } handle &&
            capture.TryGetStatusPrivateConnectionDeleteIndependentStart(session.Capture!, session.Binding!,
                client, originalScope, receipt, task, handle, out proof) &&
            proof.EndpointId == session.Plan!.PrivateEndpoint!.EndpointId;
    }

    private async ValueTask<SecretOutcome<ManagementOperation>> StartStatusPrivateConnectionDeleteIndependent(
        FixtureSelector selector, VaultAdministration client, ManagementScope originalScope, E.Input input,
        ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(client is not null && receipt is not null && originalScope is PrivateConnectionScope connection &&
                connection.Vault.ExportResourceId() == session.Plan!.VaultId &&
                session.Plan.VaultId + "/privateEndpointConnections/" + connection.ConnectionName == session.ConnectionId);
            Require(!session.StartClaimed);
            session.StartClaimed = true;
            Require(!session.StatusPrivateDeleteIndependentInvalid && session.Armed && session.BaselineReady &&
                session.StatusPrivateDeleteIndependentBaseline is not null &&
                InputMatches(session, input));
            session.Active++;
            active++;
        }
        bool entered = false;
        try
        {
            Require(entered = provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            RequireOriginalPrivateEndpoint(session);
            var baseline = session.StatusPrivateDeleteIndependentBaseline!;
            Require(baseline.Subscription == session.Subscription && baseline.ArmedAt == session.ArmedAt &&
                ReferenceEquals(baseline.Parent, session.Plan) && ReferenceEquals(baseline.Endpoints, session.Endpoints) &&
                ReferenceEquals(baseline.Endpoint, session.EndpointPlan) &&
                ReferenceEquals(baseline.Task, session.StatusPrivateIndependentBeforeTask) &&
                ReferenceEquals(baseline.EndpointRead.Task, session.StatusPrivateDeleteIndependentEndpointBefore) &&
                baseline.Reader.OwnsStatusPrivateConnectionDeleteIndependentRead(baseline.Proof, baseline.Window,
                    baseline.Binding, baseline.Task));
            var admission = new StatusPrivateConnectionDeleteIndependentAdmission(this);
            Require(statusPrivateDeleteIndependentAdmissions.TryAdd(admission, baseline));
            session.Binding = new(selector, session.Plan!.LeaseId, originalScope,
                ManagementMutation.DeletePrivateConnection, scope.Location, "2026-02-01");
            session.Client = client;
            session.ActualPrivateScope = (PrivateConnectionScope)originalScope;
            session.Receipt = receipt;
            session.Dispatch = provisioner.Journal.BeginStatusPrivateConnectionDeleteIndependentInvocation(owner, selector,
                session.Plan.LeaseId, admission);
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            session.Capture = capture.Arm(session.Binding);
            session.After = after.ArmStatusPrivateConnectionDeleteIndependent(session.Binding,
                R.StatusPrivateConnectionDeleteIndependentReadPhase.SelectedState);
            var result = await capture.StartPrivateConnectionDeleteIndependentAsync(session.Capture, selector, client, originalScope, input, receipt,
                linked.Token, task => { lock (gate) session.StartTask = task; }, () =>
                {
                    linked.Token.ThrowIfCancellationRequested();
                    Require(!disposed && !session.Closed);
                    provisioner.Journal.CheckStatusPrivateConnectionDeleteIndependentInvocation(owner, selector,
                        session.Plan.LeaseId, session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
                }).ConfigureAwait(false);
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
                if (session.Dispatch != Guid.Empty)
                    provisioner.Journal.EndStatusPrivateConnectionDeleteIndependentInvocation(owner, selector,
                        session.Plan!.LeaseId, session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
                lock (gate) session.StartFinished = true;
            }
            finally
            {
                if (entered) provisioner.ExitPrivateConnection(session.Plan!);
                Leave(session);
            }
        }
    }

    private async Task<HttpResponseMessage> ObserveStatusPrivateConnectionDelete(Session session, bool baseline,
        CancellationToken token)
    {
        var parent = session.Plan!;
        Require(provisioner.TryEnterPrivateConnection(parent, session.ConnectionId!));
        try
        {
            RequireOriginalPrivateEndpoint(session);
            RequirePrivateRoot(session, provisioner.Journal.Read(owner, session.Selector));
            var reader = baseline ? before : after;
            var binding = session.Binding!;
            var window = baseline ? session.Before! : session.After!;
            C.StatusPrivateConnectionDeleteCancellationStartProof? start = null;
            if (!baseline)
            {
                Require(session.StatusPrivateDeleteBaseline is not null && OwnsStatusPrivateDeleteStart(session, out start));
                RequirePrivateDispatch(session, invocationTerminated: true);
            }
            var task = reader.CollectAsync(window, binding, token).AsTask();
            lock (gate)
            {
                if (baseline) session.StatusPrivateBeforeTask = task;
                else session.StatusPrivateAfterTask = task;
            }
            using var measured = await task.ConfigureAwait(false);
            Require(reader.TryGetStatusPrivateConnectionDeleteRead(window, binding, task, out var proof) &&
                reader.OwnsStatusPrivateConnectionDeleteRead(proof, window, binding, task) &&
                ReferenceEquals(measured.Binding, binding) && measured.WindowId == window.Id &&
                measured.ResponseComplete && proof.StartedAt >= (baseline ? session.ArmedAt : session.StartedAt) &&
                proof.FinishedAt >= proof.StartedAt);
            Require(baseline
                ? proof.HttpStatus == 200 && proof.Facts is { State: "Pending", Provisioning: "Succeeded" } facts &&
                    facts.Id == session.ConnectionId && facts.EndpointId == parent.PrivateEndpoint!.EndpointId &&
                    PrivateResourceMatches(session, measured, binding, window, PrivateConnectionState.Pending)
                : proof.HttpStatus == 404 && proof.Facts is null && proof.ErrorCode is "NotFound" or "ResourceNotFound" &&
                    measured.ResourceStatus == SecretStatus.Absent && measured.ResourceId is null &&
                    measured.ConnectionState is null && measured.PrivateEndpointId is null);

            // This phase owns its fresh raw/GenericResourceData endpoint join.
            // It is separate from both the native child GET and endpoint setup.
            var source = privateConnectionSource!;
            var endpointReader = new PrivateEndpointResourceCollector(source.EndpointReader, source.ResourceLimits, time);
            var endpointBinding = provisioner.EndpointBinding(parent);
            var endpointWindow = endpointReader.Arm(endpointBinding);
            var endpointTask = endpointReader.CollectAsync(endpointWindow, endpointBinding, token).AsTask();
            lock (gate)
            {
                if (baseline) session.StatusPrivateDeleteEndpointBefore = endpointTask;
                else session.StatusPrivateDeleteEndpointAfter = endpointTask;
            }
            var endpoint = await endpointTask.ConfigureAwait(false);
            Require(endpoint is
            {
                Kind: PrivateEndpointResourceCollector.ReadKind.Endpoint,
                ResponseComplete: true, HttpStatus: 200, ResourceStatus: SecretStatus.Success,
                NativeState: "Succeeded", MatchesDeclarationConfiguration: true
            } &&
                ReferenceEquals(endpoint.Binding, endpointBinding) && endpoint.WindowId == endpointWindow.Id &&
                endpointBinding.Selector == session.Selector && endpointBinding.LeaseId == parent.LeaseId &&
                endpoint.ManualConnectionState == (baseline ? "Pending" : "Disconnected") &&
                endpoint.StartedAt >= proof.FinishedAt && endpoint.FinishedAt >= endpoint.StartedAt &&
                Text(endpoint.NativeRequestId, 256));
            var endpointRead = new StatusPrivateDeleteEndpointRead(endpointReader, endpointBinding, endpointWindow,
                endpointTask, endpoint);
            token.ThrowIfCancellationRequested();
            RequireOriginalPrivateEndpoint(session);
            var snapshot = provisioner.Journal.Read(owner, session.Selector);
            RequirePrivateRoot(session, snapshot);
            if (!baseline)
                Require(OwnsStatusPrivateDeleteStart(session, out var issued) && ReferenceEquals(start, issued) &&
                    start!.EndpointId == session.StatusPrivateDeleteBaseline!.Proof.Facts!.EndpointId &&
                    session.StatusPrivateDeleteBaseline.Rows.SequenceEqual(snapshot.Resources));
            lock (gate)
            {
                Require(!disposed && !session.Closed && !snapshot.Closing);
                if (baseline)
                {
                    Require(!session.StartClaimed && snapshot.Idle &&
                        snapshot.PrivateEndpoint!.Connection is { SelectedAttempted: false, DeleteAttempted: false });
                    session.StatusPrivateDeleteBaseline = new(parent, session.Endpoints!, session.EndpointPlan!,
                        parent.PrivateEndpoint!, session.ConnectionId!, session.Subscription, session.ArmedAt,
                        reader, binding, window, task, proof, endpointRead,
                        Array.AsReadOnly(snapshot.Resources.ToArray()));
                    session.BaselineAt = endpoint.FinishedAt;
                    session.BaselineReady = true;
                }
                else
                {
                    session.StatusPrivateDeleteObservation = new(session.StatusPrivateDeleteBaseline!, reader, binding,
                        window, task, proof, endpointRead, start!);
                    session.IndependentAt = endpoint.FinishedAt;
                    session.IndependentReady = true;
                }
            }
            return Reply(new E.Measurement(parent.LeaseId, session.Selector.Nonce, observerIdentity,
                endpoint.FinishedAt, ManagementMutation.DeletePrivateConnection,
                baseline ? NativeProvisioningState.Unknown : NativeProvisioningState.Succeeded,
                session.ConnectionId!, baseline ? SecretStatus.Success : SecretStatus.Absent,
                null, baseline ? PrivateConnectionState.Pending : null, null));
        }
        finally { provisioner.ExitPrivateConnection(parent); }
    }

    private bool OwnsStatusPrivateDeleteStart(Session session,
        [NotNullWhen(true)] out C.StatusPrivateConnectionDeleteCancellationStartProof? proof)
    {
        proof = null;
        return session.StartFinished && session.StartSucceeded && session.Client is { } client &&
            session.ActualPrivateScope is { } originalScope && session.Receipt is { } receipt &&
            session.StartTask is { } task && session.Handle is { } handle &&
            capture.TryGetStatusPrivateConnectionDeleteCancellationStart(session.Capture!, session.Binding!,
                client, originalScope, receipt, task, handle, out proof) &&
            proof.EndpointId == session.Plan!.PrivateEndpoint!.EndpointId;
    }

    private async ValueTask<SecretOutcome<ManagementOperation>> StartStatusPrivateConnectionDelete(
        FixtureSelector selector, VaultAdministration client, ManagementScope originalScope, E.Input input,
        ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(client is not null && receipt is not null && originalScope is PrivateConnectionScope connection &&
                connection.Vault.ExportResourceId() == session.Plan!.VaultId &&
                session.Plan.VaultId + "/privateEndpointConnections/" + connection.ConnectionName == session.ConnectionId);
            Require(!session.StartClaimed);
            session.StartClaimed = true;
            Require(!session.StatusPrivateDeleteInvalid && session.Armed && session.BaselineReady &&
                session.StatusPrivateDeleteBaseline is not null &&
                InputMatches(session, input));
            session.Active++;
            active++;
        }
        bool entered = false;
        try
        {
            Require(entered = provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            RequireOriginalPrivateEndpoint(session);
            var baseline = session.StatusPrivateDeleteBaseline!;
            Require(baseline.Subscription == session.Subscription && baseline.ArmedAt == session.ArmedAt &&
                ReferenceEquals(baseline.Parent, session.Plan) && ReferenceEquals(baseline.Endpoints, session.Endpoints) &&
                ReferenceEquals(baseline.Endpoint, session.EndpointPlan) &&
                ReferenceEquals(baseline.Task, session.StatusPrivateBeforeTask) &&
                ReferenceEquals(baseline.EndpointRead.Task, session.StatusPrivateDeleteEndpointBefore) &&
                baseline.Reader.OwnsStatusPrivateConnectionDeleteRead(baseline.Proof, baseline.Window,
                    baseline.Binding, baseline.Task));
            var admission = new StatusPrivateConnectionDeleteCancellationAdmission(this);
            Require(statusPrivateDeleteAdmissions.TryAdd(admission, baseline));
            session.Binding = new(selector, session.Plan!.LeaseId, originalScope,
                ManagementMutation.DeletePrivateConnection, scope.Location, "2026-02-01");
            session.Client = client;
            session.ActualPrivateScope = (PrivateConnectionScope)originalScope;
            session.Receipt = receipt;
            session.Dispatch = provisioner.Journal.BeginStatusPrivateConnectionDeleteInvocation(owner, selector,
                session.Plan.LeaseId, admission);
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            session.Capture = capture.Arm(session.Binding);
            session.After = after.Arm(session.Binding);
            var result = await capture.StartAsync(session.Capture, selector, client, originalScope, input, receipt,
                linked.Token, task => { lock (gate) session.StartTask = task; }, () =>
                {
                    linked.Token.ThrowIfCancellationRequested();
                    Require(!disposed && !session.Closed);
                    provisioner.Journal.CheckStatusPrivateConnectionDeleteInvocation(owner, selector,
                        session.Plan.LeaseId, session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
                }).ConfigureAwait(false);
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
                if (session.Dispatch != Guid.Empty)
                    provisioner.Journal.EndStatusPrivateConnectionDeleteInvocation(owner, selector,
                        session.Plan!.LeaseId, session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
                lock (gate) session.StartFinished = true;
            }
            finally
            {
                if (entered) provisioner.ExitPrivateConnection(session.Plan!);
                Leave(session);
            }
        }
    }

    private async ValueTask<SecretStatus> CheckStatusPrivateConnectionDeleteSelected(FixtureSelector selector,
        ManagementOperation handle, CancellationToken cancellationToken)
    {
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(handle is not null && ReferenceEquals(handle, session.Handle));
            bool valid = !session.StatusPrivateDeleteSelectedInvalid && session.StartFinished && session.StartSucceeded &&
                session.IndependentReady && session.StatusPrivateDeleteSelectedObservation is not null &&
                !session.StatusClaimed && !cancellationToken.IsCancellationRequested;
            session.StatusClaimed = true;
            session.StatusPrivateDeleteSelectedInvalid |= !valid;
            Require(valid);
            session.Active++;
            active++;
        }
        bool entered = false, admitted = false, retainedCompletion = false;
        try
        {
            Require(entered = provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            RequireOriginalPrivateEndpoint(session);
            Require(OwnsStatusPrivateDeleteSelectedStart(session, out var start) &&
                ReferenceEquals(start, session.StatusPrivateDeleteSelectedObservation!.Start));
            provisioner.Journal.AdmitStatusPrivateConnectionDeleteSelectedRead(owner, selector, session.Plan!.LeaseId,
                session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
            admitted = true;
            Require(time.GetUtcNow() >= session.IndependentAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            var status = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            C.StatusPrivateConnectionDeleteSelectedCompletionProof? nativeCompletion = null;
            Require(status == SecretStatus.Success &&
                capture.TryGetStatusPrivateConnectionDeleteSelectedCompletion(session.Capture!, session.Binding!,
                    session.Client!, session.ActualPrivateScope!, session.Receipt!, session.StartTask!, handle,
                    session.StatusTask!, out nativeCompletion) &&
                capture.OwnsStatusPrivateConnectionDeleteSelectedCompletion(nativeCompletion, session.Capture!, session.Binding!,
                    session.Client!, session.ActualPrivateScope!, session.Receipt!, session.StartTask!, handle, session.StatusTask!) &&
                ReferenceEquals(nativeCompletion.Start, start));
            RequireOriginalPrivateEndpoint(session);
            var observation = session.StatusPrivateDeleteSelectedObservation!;
            var baseline = observation.Baseline;
            Require(ReferenceEquals(observation.Task, session.StatusPrivateSelectedAfterTask) &&
                ReferenceEquals(observation.Binding, session.Binding) && ReferenceEquals(observation.Window, session.After) &&
                ReferenceEquals(baseline.Task, session.StatusPrivateSelectedBeforeTask) &&
                ReferenceEquals(baseline.EndpointRead.Task, session.StatusPrivateDeleteSelectedEndpointBefore) &&
                ReferenceEquals(observation.EndpointRead.Task, session.StatusPrivateDeleteSelectedEndpointAfter) &&
                baseline.Subscription == session.Subscription && baseline.ArmedAt == session.ArmedAt &&
                baseline.Reader.OwnsStatusPrivateConnectionDeleteSelectedRead(baseline.Proof, baseline.Window,
                    baseline.Binding, baseline.Task) &&
                observation.Reader.OwnsStatusPrivateConnectionDeleteSelectedRead(observation.Proof, observation.Window,
                    observation.Binding, observation.Task));
            var completion = new StatusPrivateDeleteSelectedCompletion(observation, session.Dispatch, session.Capture!,
                session.Client!, session.ActualPrivateScope!, session.Receipt!, session.StartTask!, handle,
                session.StatusTask!, nativeCompletion);
            var candidate = new StatusPrivateConnectionDeleteSelectedSettlement(this, session.Dispatch);
            lock (gate)
            {
                linked.Token.ThrowIfCancellationRequested();
                Require(!disposed && !session.Closed && !session.StatusPrivateDeleteSelectedInvalid &&
                    statusPrivateDeleteSelectedSettlements.TryAdd(candidate, completion));
                session.StatusPrivateDeleteSelectedSettlement = candidate;
                session.StatusSucceeded = true;
                retainedCompletion = true;
            }
            SettleStatusPrivateConnectionDeleteSelected(session);
            admitted = false;
            return status;
        }
        finally
        {
            try
            {
                if (admitted && !retainedCompletion)
                    provisioner.Journal.EndStatusPrivateConnectionDeleteSelectedInvocation(owner, selector,
                        session.Plan!.LeaseId, session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
            }
            finally
            {
                if (entered) provisioner.ExitPrivateConnection(session.Plan!);
                Leave(session);
            }
        }
    }

    private void SettleStatusPrivateConnectionDeleteSelected(Session session)
    {
        Require(!disposed && !session.Closed && session.StatusPrivateDeleteSelectedSettlement is { });
        Require(statusPrivateDeleteSelectedSettlements.TryGetValue(session.StatusPrivateDeleteSelectedSettlement, out var completion) &&
            completion.Dispatch == session.Dispatch);
        session.ApprovalSettlementAttempted = true;
        var snapshot = provisioner.Journal.Read(owner, session.Selector);
        Require(!snapshot.Closing && MatchesStatusPrivateDeleteSelectedBaseline(completion.Observation.Baseline, snapshot));
        if (snapshot.PrivateEndpoint!.StatusDeleteSettledDispatch == session.Dispatch &&
            snapshot.PrivateEndpoint.Connection is { ActiveDispatch: var active, InvocationTerminated: true } &&
            active == Guid.Empty) return;
        _ = provisioner.Journal.CompleteStatusPrivateConnectionDeleteSelectedRead(owner, session.Selector,
            session.Plan!.LeaseId, session.Dispatch, session.StatusPrivateDeleteSelectedSettlement);
    }

    private async ValueTask<SecretStatus> CheckStatusPrivateConnectionDeleteIndependent(FixtureSelector selector,
        ManagementOperation handle, CancellationToken cancellationToken)
    {
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(handle is not null && ReferenceEquals(handle, session.Handle));
            bool valid = !session.StatusPrivateDeleteIndependentInvalid && session.StartFinished && session.StartSucceeded &&
                session.IndependentReady && session.StatusPrivateDeleteIndependentObservation is not null &&
                !session.StatusClaimed && !cancellationToken.IsCancellationRequested;
            session.StatusClaimed = true;
            session.StatusPrivateDeleteIndependentInvalid |= !valid;
            Require(valid);
            session.Active++;
            active++;
        }
        bool entered = false, admitted = false, retainedCompletion = false;
        try
        {
            Require(entered = provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            RequireOriginalPrivateEndpoint(session);
            Require(OwnsStatusPrivateDeleteIndependentStart(session, out var start) &&
                ReferenceEquals(start, session.StatusPrivateDeleteIndependentObservation!.Start));
            var readObservation = session.StatusPrivateDeleteIndependentObservation!;
            var readBaseline = readObservation.Baseline;
            Require(ReferenceEquals(readObservation.Task, session.StatusPrivateIndependentAfterTask) &&
                ReferenceEquals(readObservation.Binding, session.Binding) && ReferenceEquals(readObservation.Window, session.After) &&
                ReferenceEquals(readBaseline.Task, session.StatusPrivateIndependentBeforeTask) &&
                ReferenceEquals(readBaseline.EndpointRead.Task, session.StatusPrivateDeleteIndependentEndpointBefore) &&
                ReferenceEquals(readObservation.EndpointRead.Task, session.StatusPrivateDeleteIndependentEndpointAfter) &&
                readBaseline.Subscription == session.Subscription && readBaseline.ArmedAt == session.ArmedAt &&
                readBaseline.Proof.Phase == R.StatusPrivateConnectionDeleteIndependentReadPhase.Baseline &&
                readObservation.Proof.Phase == R.StatusPrivateConnectionDeleteIndependentReadPhase.SelectedState &&
                readBaseline.Reader.OwnsStatusPrivateConnectionDeleteIndependentRead(readBaseline.Proof, readBaseline.Window,
                    readBaseline.Binding, readBaseline.Task) &&
                readObservation.Reader.OwnsStatusPrivateConnectionDeleteIndependentRead(readObservation.Proof, readObservation.Window,
                    readObservation.Binding, readObservation.Task));
            var readAdmission = new StatusPrivateConnectionDeleteIndependentReadAdmission(this, session.Dispatch);
            Require(statusPrivateDeleteIndependentReadAdmissions.TryAdd(readAdmission, readObservation));
            provisioner.Journal.AdmitStatusPrivateConnectionDeleteIndependentRead(owner, selector, session.Plan!.LeaseId,
                session.Dispatch, readAdmission);
            admitted = true;
            Require(time.GetUtcNow() >= session.IndependentAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            var status = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            C.StatusPrivateConnectionDeleteIndependentCompletionProof? nativeCompletion = null;
            Require(status == SecretStatus.Success &&
                capture.TryGetStatusPrivateConnectionDeleteIndependentCompletion(session.Capture!, session.Binding!,
                    session.Client!, session.ActualPrivateScope!, session.Receipt!, session.StartTask!, handle,
                    session.StatusTask!, out nativeCompletion) &&
                capture.OwnsStatusPrivateConnectionDeleteIndependentCompletion(nativeCompletion, session.Capture!, session.Binding!,
                    session.Client!, session.ActualPrivateScope!, session.Receipt!, session.StartTask!, handle, session.StatusTask!) &&
                ReferenceEquals(nativeCompletion.Start, start));
            RequireOriginalPrivateEndpoint(session);
            var observation = session.StatusPrivateDeleteIndependentObservation!;
            var baseline = observation.Baseline;
            Require(ReferenceEquals(observation.Task, session.StatusPrivateIndependentAfterTask) &&
                ReferenceEquals(observation.Binding, session.Binding) && ReferenceEquals(observation.Window, session.After) &&
                ReferenceEquals(baseline.Task, session.StatusPrivateIndependentBeforeTask) &&
                ReferenceEquals(baseline.EndpointRead.Task, session.StatusPrivateDeleteIndependentEndpointBefore) &&
                ReferenceEquals(observation.EndpointRead.Task, session.StatusPrivateDeleteIndependentEndpointAfter) &&
                baseline.Subscription == session.Subscription && baseline.ArmedAt == session.ArmedAt &&
                baseline.Reader.OwnsStatusPrivateConnectionDeleteIndependentRead(baseline.Proof, baseline.Window,
                    baseline.Binding, baseline.Task) &&
                observation.Reader.OwnsStatusPrivateConnectionDeleteIndependentRead(observation.Proof, observation.Window,
                    observation.Binding, observation.Task));
            var completion = new StatusPrivateDeleteIndependentCompletion(observation, session.Dispatch, session.Capture!,
                session.Client!, session.ActualPrivateScope!, session.Receipt!, session.StartTask!, handle,
                session.StatusTask!, nativeCompletion);
            var candidate = new StatusPrivateConnectionDeleteIndependentSettlement(this, session.Dispatch);
            lock (gate)
            {
                linked.Token.ThrowIfCancellationRequested();
                Require(!disposed && !session.Closed && !session.StatusPrivateDeleteIndependentInvalid &&
                    statusPrivateDeleteIndependentSettlements.TryAdd(candidate, completion));
                session.StatusPrivateDeleteIndependentSettlement = candidate;
                session.StatusSucceeded = true;
                retainedCompletion = true;
            }
            SettleStatusPrivateConnectionDeleteIndependent(session);
            admitted = false;
            return status;
        }
        finally
        {
            try
            {
                if (admitted && !retainedCompletion)
                    provisioner.Journal.EndStatusPrivateConnectionDeleteIndependentInvocation(owner, selector,
                        session.Plan!.LeaseId, session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
            }
            finally
            {
                if (entered) provisioner.ExitPrivateConnection(session.Plan!);
                Leave(session);
            }
        }
    }

    private void SettleStatusPrivateConnectionDeleteIndependent(Session session)
    {
        Require(!disposed && !session.Closed && session.StatusPrivateDeleteIndependentSettlement is { });
        Require(statusPrivateDeleteIndependentSettlements.TryGetValue(session.StatusPrivateDeleteIndependentSettlement, out var completion) &&
            completion.Dispatch == session.Dispatch);
        session.ApprovalSettlementAttempted = true;
        var snapshot = provisioner.Journal.Read(owner, session.Selector);
        Require(!snapshot.Closing && MatchesStatusPrivateDeleteIndependentBaseline(completion.Observation.Baseline, snapshot));
        if (snapshot.PrivateEndpoint!.StatusDeleteSettledDispatch == session.Dispatch &&
            snapshot.PrivateEndpoint.Connection is { ActiveDispatch: var active, InvocationTerminated: true } &&
            active == Guid.Empty) return;
        _ = provisioner.Journal.CompleteStatusPrivateConnectionDeleteIndependentRead(owner, session.Selector,
            session.Plan!.LeaseId, session.Dispatch, session.StatusPrivateDeleteIndependentSettlement);
    }

    private async ValueTask<SecretStatus> CheckStatusPrivateConnectionDelete(FixtureSelector selector,
        ManagementOperation handle, CancellationToken cancellationToken)
    {
        Session session;
        bool canceled;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(handle is not null && ReferenceEquals(handle, session.Handle));
            Require(!session.StatusPrivateDeleteInvalid);
            canceled = !session.CancelClaimed;
            bool valid = session.StartFinished && session.StartSucceeded && session.IndependentReady &&
                session.StatusPrivateDeleteObservation is not null && (canceled
                    ? cancellationToken.IsCancellationRequested && !session.StatusClaimed
                    : session.CancelFinished && !session.StatusClaimed && !cancellationToken.IsCancellationRequested);
            if (canceled) session.CancelClaimed = true;
            else session.StatusClaimed = true;
            session.StatusPrivateDeleteInvalid = !valid;
            Require(valid);
            session.Active++;
            active++;
        }
        bool entered = false, admitted = false, retainedCompletion = false;
        try
        {
            Require(entered = provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            RequireOriginalPrivateEndpoint(session);
            Require(OwnsStatusPrivateDeleteStart(session, out var start) &&
                ReferenceEquals(start, session.StatusPrivateDeleteObservation!.Start));
            if (!canceled)
                Require(capture.OwnsPrivateConnectionDeleteCanceledStatusAttempt(session.Capture!, session.Binding!,
                    session.Client!, session.ActualPrivateScope!, session.Receipt!, session.StartTask!, handle,
                    session.CanceledTask!));
            provisioner.Journal.AdmitStatusPrivateConnectionDeleteRead(owner, selector, session.Plan!.LeaseId,
                session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
            admitted = true;
            if (canceled)
            {
                try
                {
                    return await capture.CheckCanceledStatusAsync(session.Capture!, selector, handle, cancellationToken,
                        task => { lock (gate) session.CanceledTask = task; }).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (session.CanceledTask is { IsCanceled: true })
                {
                    bool owned = capture.OwnsPrivateConnectionDeleteCanceledStatusAttempt(session.Capture!,
                        session.Binding!, session.Client!, session.ActualPrivateScope!, session.Receipt!,
                        session.StartTask!, handle, session.CanceledTask);
                    lock (gate) session.CancelFinished = owned;
                    throw;
                }
            }
            Require(time.GetUtcNow() >= session.IndependentAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            var status = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            Require(status == SecretStatus.Success &&
                capture.OwnsStatusPrivateConnectionDeleteCancellationCompletion(session.Capture!, session.Binding!,
                    session.Client!, session.ActualPrivateScope!, session.Receipt!, session.StartTask!, handle,
                    session.CanceledTask!, session.StatusTask!));
            RequireOriginalPrivateEndpoint(session);
            var observation = session.StatusPrivateDeleteObservation!;
            var baseline = observation.Baseline;
            Require(ReferenceEquals(observation.Task, session.StatusPrivateAfterTask) &&
                ReferenceEquals(observation.Binding, session.Binding) && ReferenceEquals(observation.Window, session.After) &&
                ReferenceEquals(baseline.EndpointRead.Task, session.StatusPrivateDeleteEndpointBefore) &&
                ReferenceEquals(observation.EndpointRead.Task, session.StatusPrivateDeleteEndpointAfter) &&
                baseline.Reader.OwnsStatusPrivateConnectionDeleteRead(baseline.Proof, baseline.Window,
                    baseline.Binding, baseline.Task) &&
                observation.Reader.OwnsStatusPrivateConnectionDeleteRead(observation.Proof, observation.Window,
                    observation.Binding, observation.Task));
            var completion = new StatusPrivateDeleteCompletion(observation, session.Dispatch, session.Capture!,
                session.Client!, session.ActualPrivateScope!, session.Receipt!, session.StartTask!, handle,
                session.CanceledTask!, session.StatusTask!);
            var candidate = new StatusPrivateConnectionDeleteCancellationSettlement(this, session.Dispatch);
            lock (gate)
            {
                linked.Token.ThrowIfCancellationRequested();
                Require(!disposed && !session.Closed && !session.StatusPrivateDeleteInvalid &&
                    statusPrivateDeleteSettlements.TryAdd(candidate, completion));
                session.StatusPrivateDeleteSettlement = candidate;
                session.StatusSucceeded = true;
                retainedCompletion = true;
            }
            SettleStatusPrivateConnectionDelete(session);
            admitted = false;
            return status;
        }
        finally
        {
            try
            {
                if (admitted && !retainedCompletion)
                    provisioner.Journal.EndStatusPrivateConnectionDeleteInvocation(owner, selector,
                        session.Plan!.LeaseId, session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
            }
            finally
            {
                if (entered) provisioner.ExitPrivateConnection(session.Plan!);
                Leave(session);
            }
        }
    }

    private void SettleStatusPrivateConnectionDelete(Session session)
    {
        Require(!disposed && !session.Closed && session.StatusPrivateDeleteSettlement is { });
        Require(statusPrivateDeleteSettlements.TryGetValue(session.StatusPrivateDeleteSettlement, out var completion) &&
            completion.Dispatch == session.Dispatch);
        session.ApprovalSettlementAttempted = true;
        var snapshot = provisioner.Journal.Read(owner, session.Selector);
        Require(!snapshot.Closing && MatchesStatusPrivateDeleteBaseline(completion.Observation.Baseline, snapshot));
        if (snapshot.PrivateEndpoint!.StatusDeleteSettledDispatch == session.Dispatch &&
            snapshot.PrivateEndpoint.Connection is { ActiveDispatch: var active, InvocationTerminated: true } &&
            active == Guid.Empty) return;
        _ = provisioner.Journal.CompleteStatusPrivateConnectionDeleteCancellationRead(owner, session.Selector,
            session.Plan!.LeaseId, session.Dispatch, session.StatusPrivateDeleteSettlement);
    }

    private async Task<HttpResponseMessage> ObserveStatusPrivateConnectionUpdate(Session session, bool baseline,
        CancellationToken token)
    {
        var parent = session.Plan!;
        Require(provisioner.TryEnterPrivateConnection(parent, session.ConnectionId!));
        try
        {
            RequireOriginalPrivateEndpoint(session);
            RequirePrivateRoot(session, provisioner.Journal.Read(owner, session.Selector));
            var reader = baseline ? before : after;
            var binding = session.Binding!;
            var window = baseline ? session.Before! : session.After!;
            C.StatusPrivateConnectionUpdateCancellationStartProof? start = null;
            if (!baseline)
            {
                Require(session.StatusPrivateBaseline is not null && OwnsStatusPrivateStart(session, out start));
                RequirePrivateDispatch(session, invocationTerminated: true);
            }
            var task = reader.CollectAsync(window, binding, token).AsTask();
            lock (gate)
            {
                if (baseline) session.StatusPrivateBeforeTask = task;
                else session.StatusPrivateAfterTask = task;
            }
            using var measured = await task.ConfigureAwait(false);
            Require(reader.TryGetStatusPrivateConnectionUpdateRead(window, binding, task, out var proof) &&
                reader.OwnsStatusPrivateConnectionUpdateRead(proof, window, binding, task) &&
                proof.HttpStatus == 200 && proof.Facts is { } facts && facts.Id == session.ConnectionId &&
                facts.EndpointId == parent.PrivateEndpoint!.EndpointId &&
                facts.State == (baseline ? "Pending" : "Approved") && facts.Provisioning == "Succeeded" &&
                proof.StartedAt >= (baseline ? session.ArmedAt : session.StartedAt) &&
                proof.FinishedAt >= proof.StartedAt &&
                PrivateResourceMatches(session, measured, binding, window,
                    baseline ? PrivateConnectionState.Pending : PrivateConnectionState.Approved));
            token.ThrowIfCancellationRequested();
            RequireOriginalPrivateEndpoint(session);
            var snapshot = provisioner.Journal.Read(owner, session.Selector);
            RequirePrivateRoot(session, snapshot);
            if (!baseline)
                Require(OwnsStatusPrivateStart(session, out var issued) && ReferenceEquals(start, issued) &&
                    start!.EndpointId == proof.Facts!.EndpointId &&
                    session.StatusPrivateBaseline!.Proof.Facts!.Id == proof.Facts.Id &&
                    session.StatusPrivateBaseline.Proof.Facts.EndpointId == proof.Facts.EndpointId &&
                    session.StatusPrivateBaseline.Rows.SequenceEqual(snapshot.Resources));
            lock (gate)
            {
                Require(!disposed && !session.Closed && !snapshot.Closing);
                if (baseline)
                {
                    Require(!session.StartClaimed && snapshot.Idle &&
                        snapshot.PrivateEndpoint!.Connection is { SelectedAttempted: false });
                    session.StatusPrivateBaseline = new(parent, session.Endpoints!, session.EndpointPlan!,
                        parent.PrivateEndpoint!, session.ConnectionId!, session.Subscription, session.ArmedAt,
                        reader, binding, window, task, proof, Array.AsReadOnly(snapshot.Resources.ToArray()));
                    session.BaselineAt = proof.FinishedAt;
                    session.BaselineReady = true;
                }
                else
                {
                    session.StatusPrivateObservation = new(session.StatusPrivateBaseline!, reader, binding, window,
                        task, proof, start!);
                    session.IndependentAt = proof.FinishedAt;
                    session.IndependentReady = true;
                }
            }
            return Reply(ProjectPrivateConnection(session, proof.FinishedAt,
                baseline ? NativeProvisioningState.Unknown : NativeProvisioningState.Succeeded,
                baseline ? PrivateConnectionState.Pending : PrivateConnectionState.Approved));
        }
        finally { provisioner.ExitPrivateConnection(parent); }
    }

    private bool OwnsStatusPrivateStart(Session session,
        [NotNullWhen(true)] out C.StatusPrivateConnectionUpdateCancellationStartProof? proof)
    {
        proof = null;
        return session.StartFinished && session.StartSucceeded && session.Client is { } client &&
            session.ActualPrivateScope is { } originalScope && session.Receipt is { } receipt &&
            session.StartTask is { } task && session.Handle is { } handle &&
            capture.TryGetStatusPrivateConnectionUpdateCancellationStart(session.Capture!, session.Binding!,
                client, originalScope, receipt, task, handle, out proof) &&
            proof.EndpointId == session.Plan!.PrivateEndpoint!.EndpointId;
    }

    private async ValueTask<SecretOutcome<ManagementOperation>> StartStatusPrivateConnectionUpdate(
        FixtureSelector selector, VaultAdministration client, ManagementScope originalScope, E.Input input,
        ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(session.Armed && session.BaselineReady && !session.StartClaimed &&
                session.StatusPrivateBaseline is not null && client is not null && receipt is not null &&
                originalScope is PrivateConnectionScope connection &&
                connection.Vault.ExportResourceId() == session.Plan!.VaultId &&
                session.Plan.VaultId + "/privateEndpointConnections/" + connection.ConnectionName == session.ConnectionId &&
                InputMatches(session, input));
            session.StartClaimed = true;
            session.Active++;
            active++;
        }
        bool entered = false;
        try
        {
            Require(entered = provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            RequireOriginalPrivateEndpoint(session);
            var baseline = session.StatusPrivateBaseline!;
            Require(baseline.Subscription == session.Subscription && baseline.ArmedAt == session.ArmedAt &&
                ReferenceEquals(baseline.Parent, session.Plan) && ReferenceEquals(baseline.Endpoints, session.Endpoints) &&
                ReferenceEquals(baseline.Endpoint, session.EndpointPlan) &&
                ReferenceEquals(baseline.Task, session.StatusPrivateBeforeTask) &&
                baseline.Reader.OwnsStatusPrivateConnectionUpdateRead(baseline.Proof, baseline.Window,
                    baseline.Binding, baseline.Task));
            var admission = new StatusPrivateConnectionUpdateCancellationAdmission(this);
            Require(statusPrivateAdmissions.TryAdd(admission, baseline));
            session.Binding = new(selector, session.Plan!.LeaseId, originalScope,
                ManagementMutation.UpdatePrivateConnection, scope.Location, "2026-02-01");
            session.Client = client;
            session.ActualPrivateScope = (PrivateConnectionScope)originalScope;
            session.Receipt = receipt;
            // Reserve the durable child fence before clocks, timers, credentials,
            // request factories, or retained-task hooks can invoke host code.
            session.Dispatch = provisioner.Journal.BeginStatusPrivateConnectionUpdateInvocation(owner, selector,
                session.Plan.LeaseId, admission);
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            session.Capture = capture.Arm(session.Binding);
            session.After = after.Arm(session.Binding);
            var result = await capture.StartAsync(session.Capture, selector, client, originalScope, input, receipt,
                linked.Token, task => { lock (gate) session.StartTask = task; }, () =>
                {
                    linked.Token.ThrowIfCancellationRequested();
                    Require(!disposed && !session.Closed);
                    provisioner.Journal.CheckStatusPrivateConnectionUpdateInvocation(owner, selector,
                        session.Plan.LeaseId, session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
                }).ConfigureAwait(false);
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
                if (session.Dispatch != Guid.Empty)
                    provisioner.Journal.EndStatusPrivateConnectionUpdateInvocation(owner, selector,
                        session.Plan!.LeaseId, session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
                lock (gate) session.StartFinished = true;
            }
            finally
            {
                if (entered) provisioner.ExitPrivateConnection(session.Plan!);
                Leave(session);
            }
        }
    }

    private async ValueTask<SecretStatus> CheckStatusPrivateConnectionUpdate(FixtureSelector selector,
        ManagementOperation handle, CancellationToken cancellationToken)
    {
        Session session;
        bool canceled;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(session.StartFinished && session.StartSucceeded && session.IndependentReady &&
                session.StatusPrivateObservation is not null && ReferenceEquals(handle, session.Handle));
            canceled = !session.CancelClaimed;
            if (canceled)
            {
                Require(cancellationToken.IsCancellationRequested && !session.StatusClaimed);
                session.CancelClaimed = true;
            }
            else
            {
                Require(session.CancelFinished && !session.StatusClaimed && !cancellationToken.IsCancellationRequested);
                session.StatusClaimed = true;
            }
            session.Active++;
            active++;
        }
        bool entered = false, admitted = false, retainedCompletion = false;
        try
        {
            Require(entered = provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            RequireOriginalPrivateEndpoint(session);
            Require(OwnsStatusPrivateStart(session, out var start) &&
                ReferenceEquals(start, session.StatusPrivateObservation!.Start));
            if (!canceled)
                Require(capture.OwnsPrivateConnectionUpdateCanceledStatusAttempt(session.Capture!, session.Binding!,
                    session.Client!, session.ActualPrivateScope!, session.Receipt!, session.StartTask!, handle,
                    session.CanceledTask!));
            provisioner.Journal.AdmitStatusPrivateConnectionUpdateRead(owner, selector, session.Plan!.LeaseId,
                session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
            admitted = true;
            if (canceled)
            {
                try
                {
                    // The caller's already-canceled token reaches the actual
                    // wrapper. No source-thrown cancellation fills this slot.
                    return await capture.CheckCanceledStatusAsync(session.Capture!, selector, handle, cancellationToken,
                        task => { lock (gate) session.CanceledTask = task; }).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (session.CanceledTask is { IsCanceled: true })
                {
                    bool owned = capture.OwnsPrivateConnectionUpdateCanceledStatusAttempt(session.Capture!,
                        session.Binding!, session.Client!, session.ActualPrivateScope!, session.Receipt!,
                        session.StartTask!, handle, session.CanceledTask);
                    lock (gate) session.CancelFinished = owned;
                    throw;
                }
            }
            Require(time.GetUtcNow() >= session.IndependentAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            var status = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            Require(status == SecretStatus.Success &&
                capture.OwnsStatusPrivateConnectionUpdateCancellationCompletion(session.Capture!, session.Binding!,
                    session.Client!, session.ActualPrivateScope!, session.Receipt!, session.StartTask!, handle,
                    session.CanceledTask!, session.StatusTask!));
            RequireOriginalPrivateEndpoint(session);
            var observation = session.StatusPrivateObservation!;
            var baseline = observation.Baseline;
            Require(ReferenceEquals(observation.Task, session.StatusPrivateAfterTask) &&
                ReferenceEquals(observation.Binding, session.Binding) && ReferenceEquals(observation.Window, session.After) &&
                baseline.Reader.OwnsStatusPrivateConnectionUpdateRead(baseline.Proof, baseline.Window,
                    baseline.Binding, baseline.Task) &&
                observation.Reader.OwnsStatusPrivateConnectionUpdateRead(observation.Proof, observation.Window,
                    observation.Binding, observation.Task));
            var completion = new StatusPrivateCompletion(observation, session.Dispatch, session.Capture!,
                session.Client!, session.ActualPrivateScope!, session.Receipt!, session.StartTask!, handle,
                session.CanceledTask!, session.StatusTask!);
            var candidate = new StatusPrivateConnectionUpdateCancellationSettlement(this, session.Dispatch);
            lock (gate)
            {
                linked.Token.ThrowIfCancellationRequested();
                Require(!disposed && !session.Closed && statusPrivateSettlements.TryAdd(candidate, completion));
                session.StatusPrivateSettlement = candidate;
                session.StatusSucceeded = true;
                retainedCompletion = true;
            }
            SettleStatusPrivateConnectionUpdate(session);
            admitted = false;
            return status;
        }
        finally
        {
            try
            {
                // A retained completion retries only its atomic append. Failed
                // persistence must not replace its required nonterminated frame.
                if (admitted && !retainedCompletion)
                    provisioner.Journal.EndStatusPrivateConnectionUpdateInvocation(owner, selector,
                        session.Plan!.LeaseId, session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
            }
            finally
            {
                if (entered) provisioner.ExitPrivateConnection(session.Plan!);
                Leave(session);
            }
        }
    }

    private void SettleStatusPrivateConnectionUpdate(Session session)
    {
        Require(!disposed && !session.Closed && session.StatusPrivateSettlement is { });
        Require(statusPrivateSettlements.TryGetValue(session.StatusPrivateSettlement, out var completion) &&
            completion.Dispatch == session.Dispatch);
        session.ApprovalSettlementAttempted = true;
        var snapshot = provisioner.Journal.Read(owner, session.Selector);
        Require(!snapshot.Closing && MatchesStatusPrivateBaseline(completion.Observation.Baseline, snapshot));
        if (snapshot.PrivateEndpoint!.ApprovalSettledDispatch == session.Dispatch &&
            snapshot.PrivateEndpoint.Connection is { ActiveDispatch: var active, InvocationTerminated: true } &&
            active == Guid.Empty) return;
        _ = provisioner.Journal.CompleteStatusPrivateConnectionUpdateCancellationRead(owner, session.Selector,
            session.Plan!.LeaseId, session.Dispatch, session.StatusPrivateSettlement);
    }

    private async Task<HttpResponseMessage> ObservePrivateConnection(Session session, bool baseline, CancellationToken token)
    {
        var parent = session.Plan!;
        Require(provisioner.TryEnterPrivateConnection(parent, session.ConnectionId!));
        try
        {
            RequireOriginalPrivateEndpoint(session);
            RequirePrivateRoot(session, provisioner.Journal.Read(owner, session.Selector));
            if (baseline)
            {
                var binding = session.Binding!;
                var window = session.Before!;
                var task = before.CollectAsync(window, binding, token).AsTask();
                using var measured = await task.ConfigureAwait(false);
                Require(PrivateResourceMatches(session, measured, binding, window, PrivateConnectionState.Pending) &&
                    measured.StartedAt >= session.ArmedAt);
                token.ThrowIfCancellationRequested();
                RequireOriginalPrivateEndpoint(session);
                var frozen = new PrivateApprovalBaseline(session, parent, session.EndpointPlan!, parent.PrivateEndpoint!,
                    session.ConnectionId!, binding, window, task, measured.FinishedAt);
                lock (gate)
                {
                    Require(!disposed && !session.Closed && !session.StartClaimed);
                    var snapshot = provisioner.Journal.Read(owner, session.Selector);
                    RequirePrivateRoot(session, snapshot);
                    Require(snapshot.Idle && snapshot.PrivateEndpoint!.Connection is { SelectedAttempted: false });
                    Require(privateBaselines.TryAdd(session, frozen));
                    session.BaselineAt = measured.FinishedAt;
                    session.BaselineReady = true;
                    return Reply(ProjectPrivateConnection(session, measured.FinishedAt,
                        NativeProvisioningState.Unknown, PrivateConnectionState.Pending));
                }
            }

            Require(privateBaselines.TryGetValue(session, out var baselineProof));
            Require(session.StartFinished && session.StartSucceeded &&
                session.StartTask is { IsCompletedSuccessfully: true });
            Require(capture.TryGetPrivateApprovalResponseProof(session.Capture!, session.Binding!, out var proof) &&
                OwnsPrivateResponse(session, proof));
            RequirePrivateDispatch(session, invocationTerminated: true);
            var postBinding = session.Binding!;
            var postWindow = session.After!;
            var postTask = after.CollectAsync(postWindow, postBinding, token).AsTask();
            using var post = await postTask.ConfigureAwait(false);
            Require(PrivateResourceMatches(session, post, postBinding, postWindow, PrivateConnectionState.Approved) &&
                post.StartedAt >= session.StartedAt);
            token.ThrowIfCancellationRequested();
            RequireOriginalPrivateEndpoint(session);
            Require(OwnsPrivateResponse(session, proof));
            lock (gate)
            {
                Require(!disposed && !session.Closed);
                RequirePrivateDispatch(session, invocationTerminated: true);
                Require(privatePosts.TryAdd(session, new(baselineProof, postBinding, postWindow, postTask, proof)));
                session.ApprovalProof = proof;
                session.IndependentAt = post.FinishedAt;
                session.IndependentReady = true;
                // This observation precedes the caller's actual cached CheckStatus.
                // No status request or hidden CheckStatus is made by this reader.
                return Reply(ProjectPrivateConnection(session, post.FinishedAt,
                    NativeProvisioningState.Succeeded, PrivateConnectionState.Approved));
            }
        }
        finally { provisioner.ExitPrivateConnection(parent); }
    }

    private async ValueTask<SecretOutcome<ManagementOperation>> StartPrivateConnection(FixtureSelector selector,
        VaultAdministration client, ManagementScope originalScope, E.Input input, ManagementReceipt receipt,
        CancellationToken cancellationToken)
    {
        if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(selector))
            return await StartStatusPrivateConnectionUpdate(selector, client, originalScope, input, receipt,
                cancellationToken).ConfigureAwait(false);
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(session.Armed && session.BaselineReady && !session.StartClaimed &&
                privateBaselines.ContainsKey(session) && client is not null && receipt is not null &&
                originalScope is PrivateConnectionScope connection &&
                connection.Vault.ExportResourceId() == session.Plan!.VaultId &&
                session.Plan.VaultId + "/privateEndpointConnections/" + connection.ConnectionName == session.ConnectionId &&
                InputMatches(session, input));
            Require(provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            session.StartClaimed = true;
            session.Active++;
            active++;
        }
        try
        {
            RequireOriginalPrivateEndpoint(session);
            RequirePrivateRoot(session, provisioner.Journal.Read(owner, selector));
            Require(privateBaselines.TryGetValue(session, out var baseline));
            var admission = new PrivateConnectionApprovalAdmission(this);
            Require(privateAdmissions.TryAdd(admission, baseline));
            session.PrivateAdmission = admission;
            // The actual caller-owned scope object is frozen, not the equal
            // temporary scope used for the independent baseline read.
            session.Binding = new(selector, session.Plan!.LeaseId, originalScope,
                ManagementMutation.UpdatePrivateConnection, scope.Location, "2026-02-01");
            session.Client = client;
            session.ActualPrivateScope = (PrivateConnectionScope)originalScope;
            session.Receipt = receipt;
            session.Dispatch = provisioner.Journal.BeginPrivateConnectionApproval(owner, selector,
                session.Plan.LeaseId, admission);
            session.StartedAt = time.GetUtcNow();
            Require(session.StartedAt >= session.BaselineAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            session.Capture = capture.Arm(session.Binding);
            session.After = after.Arm(session.Binding);
            var result = await capture.StartAsync(session.Capture, selector, client, originalScope, input, receipt,
                linked.Token, task => { lock (gate) session.StartTask = task; },
                () =>
                {
                    linked.Token.ThrowIfCancellationRequested();
                    Require(!disposed && !session.Closed);
                    provisioner.Journal.CheckPrivateConnectionApproval(owner, selector, session.Plan.LeaseId,
                        session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
                }).ConfigureAwait(false);
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
                if (session.Dispatch != Guid.Empty)
                    provisioner.Journal.EndPrivateConnectionApprovalInvocation(owner, selector, session.Plan!.LeaseId,
                        session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
                lock (gate) session.StartFinished = true;
            }
            finally
            {
                provisioner.ExitPrivateConnection(session.Plan!);
                Leave(session);
            }
        }
    }

    private async ValueTask<SecretStatus> CheckPrivateConnection(FixtureSelector selector, ManagementOperation handle,
        CancellationToken cancellationToken)
    {
        if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(selector))
            return await CheckStatusPrivateConnectionUpdate(selector, handle, cancellationToken).ConfigureAwait(false);
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(session.StartFinished && session.StartSucceeded && session.IndependentReady &&
                !session.StatusClaimed && ReferenceEquals(handle, session.Handle) && session.ApprovalProof is not null &&
                privatePosts.TryGetValue(session, out var post) && ReferenceEquals(post.Proof, session.ApprovalProof) &&
                OwnsPrivateResponse(session, session.ApprovalProof));
            Require(provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            session.StatusClaimed = true;
            session.Active++;
            active++;
        }
        bool admitted = false;
        try
        {
            RequireOriginalPrivateEndpoint(session);
            RequirePrivateDispatch(session, invocationTerminated: true);
            provisioner.Journal.AdmitPrivateConnectionApprovalStatus(owner, selector, session.Plan!.LeaseId,
                session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
            admitted = true;
            Require(time.GetUtcNow() >= session.IndependentAt);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token,
                session.Stop.Token, deadline.Token);
            var status = await capture.CheckStatusAsync(session.Capture!, selector, handle, linked.Token,
                task => { lock (gate) session.StatusTask = task; }).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            Require(status == SecretStatus.Success && handle.State == NativeProvisioningState.Succeeded &&
                OwnsPrivateCompletion(session));
            Require(privatePosts.TryGetValue(session, out var post) &&
                ReferenceEquals(post.Binding, session.Binding) && ReferenceEquals(post.Window, session.After) &&
                ReferenceEquals(post.Proof, session.ApprovalProof));
            RequireOriginalPrivateEndpoint(session);
            // Freeze the full conjunction before any local drain/settlement
            // append can fail. The retained candidate can retry both locally.
            var completion = new PrivateApprovalCompletion(post.Baseline, session.Dispatch, session.Binding!,
                session.Capture!, session.Client!, session.ActualPrivateScope!, session.Receipt!, handle,
                session.StartTask!, session.StatusTask!, post.Proof, post.Window, post.Task,
                linked.Token);
            var candidate = new PrivateConnectionApprovalSettlement(this, session.Dispatch);
            Require(privateSettlements.TryAdd(candidate, completion));
            session.PrivateSettlement = candidate;
            session.StatusSucceeded = true;
            SettlePrivateConnection(session);
            admitted = false;
            return status;
        }
        finally
        {
            try
            {
                if (admitted)
                {
                    var snapshot = provisioner.Journal.Read(owner, selector);
                    if (snapshot.PrivateEndpoint?.Connection?.ActiveDispatch == session.Dispatch)
                        provisioner.Journal.EndPrivateConnectionApprovalInvocation(owner, selector, session.Plan!.LeaseId,
                            session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
                }
            }
            finally
            {
                provisioner.ExitPrivateConnection(session.Plan!);
                Leave(session);
            }
        }
    }

    internal void RetryStatusPrivateConnectionDeleteSelectedSettlement(FixtureSelector selector)
    {
        Require(VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(selector));
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(session.Active == 0 && session.StatusPrivateDeleteSelectedSettlement is not null &&
                session.ApprovalSettlementAttempted);
            session.Active++;
            active++;
        }
        bool entered = false;
        try
        {
            Require(entered = provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            SettleStatusPrivateConnectionDeleteSelected(session);
        }
        finally
        {
            if (entered) provisioner.ExitPrivateConnection(session.Plan!);
            Leave(session);
        }
    }

    internal void RetryStatusPrivateConnectionDeleteIndependentSettlement(FixtureSelector selector)
    {
        Require(VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(selector));
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(session.Active == 0 && session.StatusPrivateDeleteIndependentSettlement is not null &&
                session.ApprovalSettlementAttempted);
            session.Active++;
            active++;
        }
        bool entered = false;
        try
        {
            Require(entered = provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            SettleStatusPrivateConnectionDeleteIndependent(session);
        }
        finally
        {
            if (entered) provisioner.ExitPrivateConnection(session.Plan!);
            Leave(session);
        }
    }

    // Retry only the retained local append, never PUT, CheckStatus, or a read.
    internal void RetryPrivateConnectionApprovalSettlement(FixtureSelector selector)
    {
        if (VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector))
        {
            Session retained;
            lock (gate)
            {
                retained = OpenSelector(selector);
                Require(retained.Active == 0 && retained.StatusPrivateDeleteSettlement is not null &&
                    retained.ApprovalSettlementAttempted);
                retained.Active++;
                active++;
            }
            bool entered = false;
            try
            {
                Require(entered = provisioner.TryEnterPrivateConnection(retained.Plan!, retained.ConnectionId!));
                SettleStatusPrivateConnectionDelete(retained);
            }
            finally
            {
                if (entered) provisioner.ExitPrivateConnection(retained.Plan!);
                Leave(retained);
            }
            return;
        }
        if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(selector))
        {
            Session retained;
            lock (gate)
            {
                retained = OpenSelector(selector);
                Require(retained.Active == 0 && retained.StatusPrivateSettlement is not null &&
                    retained.ApprovalSettlementAttempted);
                retained.Active++;
                active++;
            }
            bool entered = false;
            try
            {
                Require(entered = provisioner.TryEnterPrivateConnection(retained.Plan!, retained.ConnectionId!));
                SettleStatusPrivateConnectionUpdate(retained);
            }
            finally
            {
                if (entered) provisioner.ExitPrivateConnection(retained.Plan!);
                Leave(retained);
            }
            return;
        }
        Session session;
        lock (gate)
        {
            session = OpenSelector(selector);
            Require(session.Active == 0 && session.PrivateSettlement is not null && session.ApprovalSettlementAttempted);
            Require(provisioner.TryEnterPrivateConnection(session.Plan!, session.ConnectionId!));
            session.Active++;
            active++;
        }
        try { SettlePrivateConnection(session); }
        finally
        {
            provisioner.ExitPrivateConnection(session.Plan!);
            Leave(session);
        }
    }

    private void SettlePrivateConnection(Session session)
    {
        Require(!disposed && !session.Closed && session.PrivateSettlement is not null);
        session.ApprovalSettlementAttempted = true;
        var snapshot = provisioner.Journal.Read(owner, session.Selector);
        RequirePrivateRoot(session, snapshot);
        Require(!snapshot.Closing);
        // A flushed frame with a lost acknowledgement is recognized only by
        // this source's exact retained candidate and original dispatch.
        if (privateSettlements.TryGetValue(session.PrivateSettlement, out var retained) &&
            retained.Dispatch == session.Dispatch && snapshot.PrivateEndpoint!.ApprovalSettledDispatch == session.Dispatch &&
            snapshot.PrivateEndpoint.Connection is
            { SelectedAttempted: true, InvocationTerminated: true, ActiveDispatch: var activeDispatch } &&
            activeDispatch == Guid.Empty) return;
        if (!snapshot.PrivateEndpoint!.Connection!.InvocationTerminated)
            _ = provisioner.Journal.EndPrivateConnectionApprovalInvocation(owner, session.Selector, session.Plan!.LeaseId,
                session.Plan.PrivateEndpoint!, session.ConnectionId!, session.Dispatch);
        _ = provisioner.Journal.SettlePrivateConnectionApproval(owner, session.Selector, session.Plan!.LeaseId,
            session.PrivateSettlement);
    }

    private bool ValidatePrivateAdmission(PrivateConnectionApprovalAdmission candidate, RoleFixtureJournal journal,
        RoleFixtureJournal.Snapshot snapshot) =>
        !disposed && ReferenceEquals(journal, provisioner.Journal) &&
        privateAdmissions.TryGetValue(candidate, out var baseline) && !baseline.Session.Closed &&
        privateBaselines.TryGetValue(baseline.Session, out var original) && ReferenceEquals(original, baseline) &&
        baseline.Task.IsCompletedSuccessfully && MatchesPrivateRoot(baseline, snapshot);

    private bool ValidatePrivateSettlement(PrivateConnectionApprovalSettlement candidate, RoleFixtureJournal journal,
        RoleFixtureJournal.Snapshot snapshot) =>
        !disposed && ReferenceEquals(journal, provisioner.Journal) &&
        privateSettlements.TryGetValue(candidate, out var completion) && !completion.Baseline.Session.Closed &&
        !completion.Cancellation.IsCancellationRequested &&
        candidate.Dispatch == completion.Dispatch && completion.Dispatch != Guid.Empty &&
        completion.StartTask.IsCompletedSuccessfully && completion.StatusTask.IsCompletedSuccessfully &&
        completion.Baseline.Task.IsCompletedSuccessfully && completion.PostTask.IsCompletedSuccessfully &&
        MatchesPrivateRoot(completion.Baseline, snapshot) &&
        snapshot.PrivateEndpoint!.Connection!.ActiveDispatch == completion.Dispatch;

    private static bool MatchesPrivateRoot(PrivateApprovalBaseline baseline, RoleFixtureJournal.Snapshot snapshot) =>
        baseline.Parent.Owner == snapshot.Owner && baseline.Parent.Selector == snapshot.Selector &&
        baseline.Parent.LeaseId == snapshot.LeaseId && baseline.Declaration == snapshot.PrivateEndpoint?.Declaration &&
        snapshot.PrivateEndpoint is { } slot && slot.Connection?.Id == baseline.ConnectionId &&
        baseline.Parent.Manifest.Count == snapshot.Resources.Length && baseline.Parent.Manifest.All(m =>
            snapshot.Resources.Count(r => r.Id == m.Id && r.Borrowed == m.Borrowed && r.CleanupOnly == m.CleanupOnly) == 1);

    private void RequirePrivateRoot(Session session, RoleFixtureJournal.Snapshot snapshot) =>
        Require(session.Plan is { Restored: false, PrivateEndpoint: not null } parent &&
            parent.Owner == owner && parent.Selector == session.Selector && snapshot.Owner == owner &&
            snapshot.Selector == session.Selector && snapshot.LeaseId == parent.LeaseId &&
            snapshot.PrivateEndpoint is { } slot && slot.Declaration == parent.PrivateEndpoint &&
            slot.Connection?.Id == session.ConnectionId && parent.Manifest.Count == snapshot.Resources.Length &&
            parent.Manifest.All(m => snapshot.Resources.Count(r =>
                r.Id == m.Id && r.Borrowed == m.Borrowed && r.CleanupOnly == m.CleanupOnly) == 1) &&
            (!VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(session.Selector) ||
                RoleFixtureJournal.StatusPrivateConnectionDeleteIndependentRoot(snapshot)) &&
            (!VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(session.Selector) ||
                RoleFixtureJournal.StatusPrivateConnectionDeleteSelectedRoot(snapshot)) &&
            (!VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(session.Selector) ||
                RoleFixtureJournal.StatusPrivateConnectionDeleteRoot(snapshot)) &&
            (!VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(session.Selector) ||
                RoleFixtureJournal.StatusPrivateConnectionUpdateIndependentRoot(snapshot)) &&
            (!VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(session.Selector) ||
                RoleFixtureJournal.StatusPrivateConnectionUpdateRoot(snapshot)));

    private void RequireOriginalPrivateEndpoint(Session session) =>
        Require(session.Endpoints is not null && session.EndpointPlan is not null && session.Plan is not null &&
            session.ConnectionId is not null &&
            session.Endpoints.OwnsBoundPlan(session.EndpointPlan, session.Plan, session.ConnectionId));

    private void RequirePrivateDispatch(Session session, bool invocationTerminated)
    {
        var snapshot = provisioner.Journal.Read(owner, session.Selector);
        RequirePrivateRoot(session, snapshot);
        Require(!snapshot.Closing && snapshot.PrivateEndpoint is
        {
            CreationDispatch: var creation,
            DeletionDispatch: var deletion, ApprovalSettledDispatch: var approval, Connection: { } child
        } &&
            creation == Guid.Empty && deletion == Guid.Empty && approval == Guid.Empty &&
            snapshot.PrivateEndpoint!.StatusDeleteSettledDispatch == Guid.Empty &&
            child is { SelectedAttempted: true, CreateAttempted: true, Absent: false } &&
            child.DeleteAttempted == (VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(session.Selector) ||
                VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(session.Selector) ||
                VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(session.Selector)) &&
            child.ActiveDispatch == session.Dispatch && session.Dispatch != Guid.Empty &&
            child.InvocationTerminated == invocationTerminated &&
            snapshot.Resources.All(r => !r.SelectedAttempted && r.ActiveDispatch == Guid.Empty) &&
            snapshot.Resources.Single(r => r.Id == session.Plan!.PrivateEndpoint!.EndpointId) is
            { CreateAttempted: true, DeleteAttempted: false, InvocationTerminated: true, Absent: false });
    }

    private bool PrivateResourceMatches(Session session, R.Measurement measurement, C.Binding binding,
        R.Window window, PrivateConnectionState state) =>
        ReferenceEquals(measurement.Binding, binding) && measurement.WindowId == window.Id &&
        measurement.ResponseComplete && measurement.PersistedStateEligible && measurement.HttpStatus == 200 &&
        measurement.ResourceStatus == SecretStatus.Success && measurement.ResourceId == session.ConnectionId &&
        measurement.ConnectionState == state && measurement.NativeState == "Succeeded" &&
        string.Equals(measurement.PrivateEndpointId, session.Plan!.PrivateEndpoint!.EndpointId, StringComparison.OrdinalIgnoreCase) &&
        measurement.FinishedAt >= measurement.StartedAt && Text(measurement.NativeRequestId, 256);

    private bool OwnsPrivateResponse(Session session, C.PrivateApprovalResponseProof proof) =>
        session.Client is { } client && session.ActualPrivateScope is { } actualScope &&
        session.Receipt is { } receipt && session.Handle is { } handle && session.StartTask is { } start &&
        session.Binding is { } binding && session.Capture is { } window &&
        ReferenceEquals(binding.Resource, actualScope) &&
        string.Equals(proof.EndpointId, session.Plan!.PrivateEndpoint!.EndpointId, StringComparison.OrdinalIgnoreCase) &&
        capture.OwnsPrivateApprovalResponseProof(proof, window, binding, client, actualScope,
            receipt, handle, start);

    private bool OwnsPrivateCompletion(Session session) =>
        session.ApprovalProof is { } proof && OwnsPrivateResponse(session, proof) &&
        session.StatusTask is { } status &&
        capture.OwnsPrivateApprovalCompletion(proof, session.Capture!, session.Binding!, session.Client!,
            session.ActualPrivateScope!, session.Receipt!, session.Handle!, session.StartTask!, status);

    private E.Measurement ProjectPrivateConnection(Session session, DateTimeOffset observedAt,
        NativeProvisioningState state, PrivateConnectionState connectionState) =>
        new(session.Plan!.LeaseId, session.Selector.Nonce, observerIdentity, observedAt,
            ManagementMutation.UpdatePrivateConnection, state, session.ConnectionId!, SecretStatus.Success,
            null, connectionState, null);

    private async Task<HttpResponseMessage> Release(FixtureSelector selector, CancellationToken token,
        CancellationToken requestCancellation = default)
    {
        ValidateReleaseSelector(selector);
        Require(statusPrivateUpdateIndependentProfile == VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(selector));
        Require(statusNotificationUpdateIndependentProfile == NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector));
        Require(statusNotificationCreateIndependentProfile == NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector));
        Require(statusPrivateDeleteIndependentProfile == VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(selector));
        if (statusSucceededDeleteVaultProfile) Require(VaultFixtureProvisioner.StatusSucceededDeleteVaultSelector(selector));
        Require(statusSucceededDeleteVaultCancellationProfile ==
            VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationSelector(selector));
        Require(statusSucceededDeleteVaultIndependentProfile ==
            VaultFixtureProvisioner.StatusSucceededDeleteVaultIndependentSelector(selector));
        Session session;
        lock (gate)
        {
            if (!sessions.TryGetValue(selector.Nonce, out session!))
            {
                Require(sessions.Count < 32 && !disposed);
                session = new(selector with { });
                sessions.Add(selector.Nonce, session);
            }
            Require(session.Selector == selector);
            session.Closed = true;
        }
        RoleFixtureJournal.Snapshot snapshot;
        bool privateUpdateClosed = false, privateUpdateCorrupt = false;
        try { snapshot = provisioner.CloseSelectedRoot(owner, selector); privateUpdateClosed = true; }
        catch (RoleFixtureJournal.StatusPrivateConnectionUpdateIndependentHistoryException) { privateUpdateCorrupt = true; throw; }
        finally
        {
            if (statusPrivateUpdateIndependentProfile) lock (gate) RevokePrivateUpdateIndependent(session);
            if (statusNotificationUpdateIndependentProfile) lock (gate) RevokeNotificationUpdateIndependent(session);
            if (statusNotificationCreateIndependentProfile) lock (gate) RevokeNotificationCreateIndependent(session);
            if (!statusPrivateUpdateIndependentProfile || privateUpdateClosed || privateUpdateCorrupt) session.Stop.Cancel();
        }
        if (statusSucceededDeleteVaultCancellationProfile)
        {
            InvalidateStatusSucceededDeleteVaultCancellation(session);
            bool idle;
            lock (gate) idle = session.Active == 0;
            if (idle) DrainStatusSucceededDeleteVaultCancellation(session);
            snapshot = provisioner.Journal.Read(owner, selector);
        }
        if (statusSucceededDeleteVaultIndependentProfile && session.StatusSucceededIndependentSettlement is { } candidate)
        {
            statusSucceededIndependentSettlements.TryRemove(candidate, out _);
            lock (gate) session.StatusSucceededIndependentSettlement = null;
            DrainStatusSucceededDeleteVaultIndependent(session);
            snapshot = provisioner.Journal.Read(owner, selector);
        }
        if (selector.Variant is "operation.UpdatePrivateConnection" or "operation.DeletePrivateConnection")
        {
            lock (gate)
                if (session.Active == 0) session.PrivateDrained.TrySetResult();
            // A bounded release may stop waiting; disposal still owns the
            // admitted borrower and Close has already revoked settlement.
            if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(selector) ||
                VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector) ||
                VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(selector) ||
                statusPrivateDeleteIndependentProfile || statusPrivateUpdateIndependentProfile)
            {
                using var deadline = new CancellationTokenSource(limits.Timeout, time);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
                try { await session.PrivateDrained.Task.WaitAsync(linked.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (!token.IsCancellationRequested)
                {
                    return Reply(ReleaseMeasurement(session, snapshot));
                }
            }
            else await session.PrivateDrained.Task.WaitAsync(token).ConfigureAwait(false);
        }
        lock (gate)
        {
            if (session.Active != 0 || session.Releasing) return Reply(ReleaseMeasurement(session, snapshot, session.Releasing ? 1 : 0));
            session.Releasing = true;
        }
        try
        {
            if (session.Capture is not null)
            {
                var seal = capture.SealAsync(session.Capture);
                if (VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector) ||
                    VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(selector) ||
                    statusPrivateDeleteIndependentProfile || statusPrivateUpdateIndependentProfile || statusNotificationUpdateIndependentProfile || statusNotificationCreateIndependentProfile ||
                    NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector) ||
                    NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector))
                {
                    using var deadline = new CancellationTokenSource(limits.Timeout, time);
                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
                    try { await seal.WaitAsync(linked.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested)
                    { return Reply(ReleaseMeasurement(session, snapshot)); }
                }
                else await seal.ConfigureAwait(false);
            }
            snapshot = provisioner.Journal.Read(owner, selector);
            if (!snapshot.Idle) return Reply(ReleaseMeasurement(session, snapshot));
            if (snapshot.Resources.Length == 0) return Reply(ReleaseMeasurement(session, snapshot));
            if (snapshot.PrivateEndpoint is not null)
                return await ReleasePrivateConnection(session, snapshot, token, requestCancellation).ConfigureAwait(false);
            if (selector.Variant is "operation.UpdateNotification" or "operation.CreateOrUpdateNotification" or
                "operation.DeleteNotification" ||
                snapshot.Resources.Any(r => r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal)))
                return await ReleaseNotification(session, snapshot, token, requestCancellation).ConfigureAwait(false);
            bool selected = snapshot.Resources.Any(r => r.SelectedAttempted);
            // Selected purge admission does not set DeleteAttempted. Never use
            // ordinary purge cleanup after it, even following response loss.
            snapshot = (await provisioner.ReleaseAsync(owner, selector,
                purge: !selected || SelectionOperation(selector) != ManagementMutation.PurgeDeletedVault,
                cancellationToken: token,
                requireActiveVaultAbsent: selected &&
                    SelectionOperation(selector) is not (ManagementMutation.RecoverVault or ManagementMutation.CreateOrUpdateVault)).ConfigureAwait(false)).Journal;
            return Reply(ReleaseMeasurement(session, snapshot));
        }
        finally { lock (gate) session.Releasing = false; }
    }

    private E.Measurement Project(Session session, DateTimeOffset observedAt, NativeProvisioningState state,
        SecretStatus resourceStatus, VaultAdministrationEffects.Configuration? configuration = null) =>
        new(session.Plan!.LeaseId, session.Selector.Nonce, observerIdentity,
            observedAt, SelectionOperation(session.Selector), state, SelectedId(session), resourceStatus, configuration, null, null);

    private async Task<HttpResponseMessage> ReleasePrivateConnection(Session session, RoleFixtureJournal.Snapshot snapshot,
        CancellationToken token, CancellationToken requestCancellation = default)
    {
        var parent = session.Plan ?? provisioner.OpenCleanupPlan(owner, session.Selector);
        Require(parent.PrivateEndpoint is not null && provisioner.MatchesOwnedPlan(parent, snapshot));
        session.Plan = parent;
        if (session.Endpoints is null)
        {
            if (privateConnectionSource is not { } source) return Reply(ReleaseMeasurement(session, snapshot));
            session.Endpoints = new(provisioner, source.EndpointSetup, source.EndpointReader,
                source.VaultConnectionReader, source.ResourceLimits, source.InventoryLimits, time);
        }
        var endpoint = await session.Endpoints.CleanupAsync(parent, token, statusPrivateUpdateIndependentProfile ? requestCancellation : null).ConfigureAwait(false);
        if (endpoint.State != PrivateEndpointFixtureProvisioner.CleanupState.DependenciesAbsent)
            return Reply(ReleaseMeasurement(session, endpoint.Journal));
        var result = await provisioner.ReleaseAsync(owner, session.Selector, purge: true, cancellationToken: token,
            privateEndpointCleanup: session.Endpoints, originalCallerToken: statusPrivateUpdateIndependentProfile ? requestCancellation : null).ConfigureAwait(false);
        return Reply(ReleaseMeasurement(session, result.Journal));
    }

    private E.Measurement ProjectNotification(Session session, DateTimeOffset observedAt, NativeProvisioningState state,
        NotificationConfiguration? configuration) =>
        new(session.Plan!.LeaseId, session.Selector.Nonce, observerIdentity, observedAt,
            SelectionOperation(session.Selector), state, SelectedId(session),
            configuration is null ? SecretStatus.Absent : SecretStatus.Success, null, null,
            configuration is null ? null : new(configuration.Endpoint.Reveal(), configuration.EventTypes.ToArray(), []));

    private bool NotificationConfigurationMatches(NotificationConfiguration configuration, VaultNotificationEvent expected) =>
        notificationSource?.Baseline is { } baseline &&
        Uri.TryCreate(baseline.Endpoint.Reveal(), UriKind.Absolute, out var endpoint) &&
        endpoint.Scheme == "https" && endpoint.UserInfo.Length == 0 && endpoint.Fragment.Length == 0 &&
        configuration.Endpoint.Reveal() == baseline.Endpoint.Reveal() &&
        configuration.EventTypes.Count() == 1 && configuration.EventTypes.Single() == expected &&
        configuration.DeliveryAttributes.Count == 0;

    private bool OwnsNotificationDeleteProof(Session session, C.SynchronousDeleteProof proof) =>
        session.Client is { } client && session.ActualNotificationScope is { } actualScope &&
        session.Receipt is { } receipt && session.Handle is { } handle &&
        capture.TryGetSynchronousDeleteProof(session.Capture!, session.Binding!, out var issued) &&
        ReferenceEquals(proof, issued) &&
        capture.OwnsSynchronousDeleteProof(proof, session.Binding!, client, actualScope, receipt, handle);

    private void RequireNotificationJournal(Session session, RoleFixtureJournal.Snapshot snapshot, bool selected,
        bool invocationTerminated = true)
    {
        var parent = session.Plan!;
        var child = session.NotificationPlan!;
        bool absent = snapshot.NotificationAbsentCreate is not null;
        Require(session.Notifications is not null && !parent.Restored &&
            ReferenceEquals(child.ObjectPlan, parent) && child.Owner == owner && child.Selector == session.Selector &&
            child.LeaseId == parent.LeaseId && (absent
                ? child.Preparation == NotificationFixtureProvisioner.Preparation.Absent &&
                    session.Notifications.OwnsExclusiveCreation(child, snapshot)
                : child.Preparation == NotificationFixtureProvisioner.Preparation.Present) &&
            !child.Restored && parent.Preparation == VaultFixtureProvisioner.Preparation.Active &&
            !parent.SeedCanary && parent.PolicyChildren.Count == 0 &&
            parent.OwnedNotificationIds.Count == 1 && parent.OwnedNotificationIds[0] == child.ResourceId &&
            provisioner.MatchesOwnedPlan(parent, snapshot) && snapshot.Owner == owner &&
            snapshot.Selector == session.Selector && snapshot.LeaseId == parent.LeaseId && !snapshot.Closing &&
            snapshot.Resources.Length == 4 && snapshot.Resources.All(r => !r.Borrowed) &&
            snapshot.Resources.Single(r => r.Id == parent.VaultId) is { CleanupOnly: false } &&
            snapshot.Resources.Single(r => r.Id == parent.SecretId) is { CleanupOnly: true } &&
            snapshot.Resources.Single(r => r.Id == parent.DeletedId) is { CleanupOnly: true } &&
            snapshot.Resources.Single(r => r.Id == child.ResourceId) is { CleanupOnly: false, DeleteAttempted: false, Absent: false } row &&
            row.SelectedAttempted == selected && row.CreateAttempted == (!absent || selected) &&
            (selected ? session.Dispatch != Guid.Empty && row.ActiveDispatch == session.Dispatch &&
                row.InvocationTerminated == invocationTerminated :
                row.ActiveDispatch == Guid.Empty) &&
            snapshot.Resources.Where(r => r.Id != child.ResourceId).All(r => r.ActiveDispatch == Guid.Empty));
        if (NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(session.Selector) ||
            NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(session.Selector))
            Require((NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(session.Selector)
                    ? RoleFixtureJournal.StatusNotificationDeleteIndependentRoot(snapshot)
                    : RoleFixtureJournal.StatusNotificationDeleteRoot(snapshot)) &&
                child.Manifest.Count == 4 && child.Manifest.All(m => snapshot.Resources.Count(r =>
                    r.Id == m.Id && r.Borrowed == m.Borrowed && r.CleanupOnly == m.CleanupOnly) == 1) &&
                snapshot.Resources.Where(r => r.Id != child.ResourceId).All(r => !r.DeleteAttempted &&
                    !r.SelectedAttempted && !r.Absent && (r.CleanupOnly
                        ? !r.CreateAttempted && !r.InvocationTerminated : r.CreateAttempted && r.InvocationTerminated)) &&
                (selected || snapshot.Resources.Single(r => r.Id == child.ResourceId).InvocationTerminated));
        if (statusNotificationUpdateIndependentProfile)
            Require(RoleFixtureJournal.StatusNotificationUpdateIndependentRoot(snapshot) &&
                snapshot.Resources.Where(r => r.Id != child.ResourceId).All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                    (r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated : r.CreateAttempted && r.InvocationTerminated)) &&
                (selected || snapshot.Resources.Single(r => r.Id == child.ResourceId).InvocationTerminated));
        if (statusNotificationCreateIndependentProfile)
            Require(RoleFixtureJournal.StatusNotificationCreateIndependentRoot(snapshot) &&
                snapshot.Resources.Where(r => r.Id != child.ResourceId).All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                    (r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated : r.CreateAttempted && r.InvocationTerminated)) &&
                (selected || snapshot.Resources.Single(r => r.Id == child.ResourceId).InvocationTerminated));
        if (NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(session.Selector) ||
            NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(session.Selector))
            Require((NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(session.Selector)
                ? RoleFixtureJournal.StatusNotificationCreateRoot(snapshot) : RoleFixtureJournal.StatusNotificationUpdateRoot(snapshot)) &&
                child.Manifest.Count == 4 && child.Manifest.All(m => snapshot.Resources.Count(r =>
                    r.Id == m.Id && r.Borrowed == m.Borrowed && r.CleanupOnly == m.CleanupOnly) == 1) &&
                snapshot.Resources.Where(r => r.Id != child.ResourceId).All(r => !r.DeleteAttempted &&
                    !r.SelectedAttempted && !r.Absent && (r.CleanupOnly
                        ? !r.CreateAttempted && !r.InvocationTerminated : r.CreateAttempted && r.InvocationTerminated)) &&
                (selected || snapshot.Resources.Single(r => r.Id == child.ResourceId).InvocationTerminated == !absent));
    }

    private async Task<HttpResponseMessage> ReleaseNotification(Session session, RoleFixtureJournal.Snapshot snapshot,
        CancellationToken token, CancellationToken requestCancellation = default)
    {
        // Restore only the original journal topology. Current baseline and
        // webhook readiness are deliberately irrelevant to release authority.
        var parent = session.Plan ?? provisioner.OpenCleanupPlan(owner, session.Selector);
        Require(parent.Owner == owner && parent.Selector == session.Selector && parent.LeaseId == snapshot.LeaseId &&
            !parent.SeedCanary && parent.PolicyChildren.Count == 0 && parent.OwnedNotificationNames.Count == 1 &&
            snapshot.Resources.Length == 4 && snapshot.Resources.All(r => !r.Borrowed) &&
            snapshot.Resources.Single(r => r.Id == parent.VaultId) is { CleanupOnly: false } &&
            snapshot.Resources.Single(r => r.Id == parent.SecretId) is { CleanupOnly: true } &&
            snapshot.Resources.Single(r => r.Id == parent.DeletedId) is { CleanupOnly: true } &&
            snapshot.Resources.Single(r => r.Id == parent.OwnedNotificationIds[0]) is { CleanupOnly: false } &&
            provisioner.MatchesOwnedPlan(parent, snapshot));
        session.Plan = parent;
        if (session.Notifications is null)
        {
            if (notificationSource is null) return Reply(ReleaseMeasurement(session, snapshot));
            session.Notifications = NotificationFixtureProvisioner.ForOwnedCleanup(provisioner, owner, session.Selector,
                notificationSource.Setup, notificationSource.Observer, notificationSource.Limits, time,
                notificationSource.ExclusiveCreation);
        }
        string name = parent.OwnedNotificationNames[0];
        using (var released = await session.Notifications.ReleaseAsync(owner, session.Selector, name, token,
            originalCallerToken: statusNotificationUpdateIndependentProfile || statusNotificationCreateIndependentProfile ? requestCancellation : null).ConfigureAwait(false))
        {
            snapshot = released.Journal;
            if (!ChildCleanupReady(released)) return Reply(ReleaseMeasurement(session, snapshot));
        }
        var parentResult = await provisioner.ReleaseAsync(owner, session.Selector, purge: true,
            cancellationToken: token,
            originalCallerToken: statusNotificationUpdateIndependentProfile || statusNotificationCreateIndependentProfile ? requestCancellation : null).ConfigureAwait(false);
        snapshot = parentResult.Journal;
        if (!ParentCleanupReady(parentResult)) return Reply(ReleaseMeasurement(session, snapshot));
        using (var refreshed = await session.Notifications.ObserveAsync(owner, session.Selector, name, token,
            originalCallerToken: statusNotificationUpdateIndependentProfile || statusNotificationCreateIndependentProfile ? requestCancellation : null).ConfigureAwait(false))
        {
            snapshot = refreshed.Journal;
            if (!ChildCleanupReady(refreshed)) return Reply(ReleaseMeasurement(session, snapshot));
        }
        parentResult = await provisioner.ReleaseAsync(owner, session.Selector, purge: true,
            cancellationToken: token,
            originalCallerToken: statusNotificationUpdateIndependentProfile || statusNotificationCreateIndependentProfile ? requestCancellation : null).ConfigureAwait(false);
        snapshot = parentResult.Journal;
        if (!ParentCleanupReady(parentResult)) return Reply(ReleaseMeasurement(session, snapshot));
        using (var refreshed = await session.Notifications.ObserveAsync(owner, session.Selector, name, token,
            originalCallerToken: statusNotificationUpdateIndependentProfile || statusNotificationCreateIndependentProfile ? requestCancellation : null).ConfigureAwait(false))
        {
            snapshot = refreshed.Journal;
            if (!ChildCleanupReady(refreshed)) return Reply(ReleaseMeasurement(session, snapshot));
        }
        parentResult = await provisioner.ReleaseAsync(owner, session.Selector, purge: true,
            cancellationToken: token,
            originalCallerToken: statusNotificationUpdateIndependentProfile || statusNotificationCreateIndependentProfile ? requestCancellation : null).ConfigureAwait(false);
        return Reply(ReleaseMeasurement(session, parentResult.Journal));
    }

    private static bool ChildCleanupReady(NotificationFixtureProvisioner.Result result) =>
        result.State is NotificationFixtureProvisioner.State.Closing or NotificationFixtureProvisioner.State.Released &&
        result.Present == false && result.Journal.Resources.All(r => r.ActiveDispatch == Guid.Empty);
    private static bool ParentCleanupReady(VaultFixtureProvisioner.Result result) =>
        result.State is VaultFixtureProvisioner.State.Closing or VaultFixtureProvisioner.State.SoftDeleted or VaultFixtureProvisioner.State.Released &&
        result.Journal.Resources.All(r => r.ActiveDispatch == Guid.Empty);

    private ManagementMutation SelectionOperation(FixtureSelector selector) =>
        (statusPendingPurgeProfile && VaultFixtureProvisioner.StatusPendingPurgeSelector(selector) ||
            pendingIndependentProfile is not null && VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(selector) ||
            pendingCancellationProfile is not null && VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(selector))
            ? ManagementMutation.PurgeDeletedVault :
        statusSucceededDeleteVaultCancellationProfile && VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationSelector(selector)
            ? ManagementMutation.DeleteVault :
        statusSucceededDeleteVaultIndependentProfile && VaultFixtureProvisioner.StatusSucceededDeleteVaultIndependentSelector(selector)
            ? ManagementMutation.DeleteVault :
        statusSucceededDeleteVaultProfile && VaultFixtureProvisioner.StatusSucceededDeleteVaultSelector(selector)
            ? ManagementMutation.DeleteVault : selector.Variant switch
            {
                "operation.CreateOrUpdateVault" => ManagementMutation.CreateOrUpdateVault,
                "operation.DeleteVault" => ManagementMutation.DeleteVault,
                "operation.RecoverVault" => ManagementMutation.RecoverVault,
                "operation.PurgeDeletedVault" => ManagementMutation.PurgeDeletedVault,
                "operation.UpdateNotification" => ManagementMutation.UpdateNotification,
                "operation.CreateOrUpdateNotification" => ManagementMutation.CreateOrUpdateNotification,
                "operation.DeleteNotification" => ManagementMutation.DeleteNotification,
                "operation.UpdatePrivateConnection" => ManagementMutation.UpdatePrivateConnection,
                "operation.DeletePrivateConnection" => ManagementMutation.DeletePrivateConnection,
                _ => throw Failure()
            };
    private static bool IsNotification(ManagementMutation operation) =>
        operation is ManagementMutation.UpdateNotification or ManagementMutation.CreateOrUpdateNotification or ManagementMutation.DeleteNotification;
    private string SelectedId(Session session) => IsNotification(SelectionOperation(session.Selector))
        ? session.NotificationPlan!.ResourceId :
        SelectionOperation(session.Selector) is ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection
        ? session.ConnectionId! : SelectionOperation(session.Selector) != ManagementMutation.PurgeDeletedVault
        ? session.Plan!.VaultId : session.Plan!.DeletedId;

    private bool ResourceBound(R.Measurement measurement, Session session, R.Window window) =>
        measurement.Binding == session.Binding && measurement.WindowId == window.Id && measurement.ResponseComplete &&
        measurement.StartedAt >= session.ArmedAt && measurement.FinishedAt >= measurement.StartedAt &&
        Text(measurement.NativeRequestId, 256);
    private bool InputMatches(Session session, E.Input input) =>
        input is not null && session.Preparation is { } prepared &&
        input.SubscriptionId == prepared.SubscriptionId && input.ResourceGroup == prepared.ResourceGroup &&
        input.Location == prepared.Location && input.TenantId == prepared.TenantId && input.Sku == prepared.Sku &&
        input.RetentionDays == prepared.RetentionDays && input.WebhookUrl == prepared.WebhookUrl &&
        input.RoleAssignmentId == prepared.RoleAssignmentId;
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
        if (snapshot.PrivateEndpoint is { } slot)
        {
            string[] dependencies = slot.Connection is null ? [slot.Declaration.ExpectedNicId] :
                [slot.Declaration.ExpectedNicId, slot.Connection.Id];
            owned = [.. owned, .. dependencies];
            if (snapshot.PrivateEndpointAbsent) absent = [.. absent, .. dependencies];
        }
        return new(session.Selector, true, session.Active + extra + snapshot.Resources.Count(r => r.ActiveDispatch != Guid.Empty) +
            (snapshot.PrivateEndpoint?.Connection is { ActiveDispatch: var childDispatch } && childDispatch != Guid.Empty ? 1 : 0),
            owned, snapshot.Resources.Where(r => r.Borrowed).Select(r => r.Id).ToArray(), absent,
            owned.Except(absent, StringComparer.OrdinalIgnoreCase).ToArray());
    }
    private string VaultId(string name) =>
        $"/subscriptions/{scope.SubscriptionId:D}/resourceGroups/{scope.ResourceGroup}/providers/Microsoft.KeyVault/vaults/{name}";
    private string DeletedId(string name) =>
        $"/subscriptions/{scope.SubscriptionId:D}/providers/Microsoft.KeyVault/locations/{scope.Location}/deletedVaults/{name}";
    private void ValidateSelector(FixtureSelector selector) =>
        Require(selector is not null && selector.Nonce != Guid.Empty &&
            new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }.All(v => Text(v, 512)) &&
            selector.Operation == E.Members[0].Operation &&
            (pendingCancellationProfile is not null ? VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(selector) :
            pendingIndependentProfile is not null ? VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(selector) :
            statusPendingPurgeProfile ? VaultFixtureProvisioner.StatusPendingPurgeSelector(selector) :
            statusPrivateUpdateIndependentProfile ? VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(selector) :
            statusNotificationCreateIndependentProfile ? NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector) :
            statusNotificationUpdateIndependentProfile ? NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector) :
            statusPrivateDeleteIndependentProfile ? VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(selector) :
            statusSucceededDeleteVaultCancellationProfile ? VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationSelector(selector) :
            statusSucceededDeleteVaultIndependentProfile ? VaultFixtureProvisioner.StatusSucceededDeleteVaultIndependentSelector(selector) :
            statusSucceededDeleteVaultProfile ? VaultFixtureProvisioner.StatusSucceededDeleteVaultSelector(selector) :
            selector.Variant is "operation.PurgeDeletedVault" or "operation.DeleteVault" or "operation.RecoverVault" or "operation.CreateOrUpdateVault" &&
                selector.Case is "selected-contract" or "independent-effect" ||
             selector.Variant is "operation.UpdateNotification" or "operation.CreateOrUpdateNotification" or "operation.DeleteNotification" &&
                selector.Case == "selected-contract" ||
             selector.Variant == "operation.UpdatePrivateConnection" && selector.Case == "selected-contract" ||
             VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(selector) ||
             VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector) ||
             VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(selector) ||
             VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(selector) ||
             VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(selector) ||
             VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector) ||
             VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector) ||
             NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector) ||
             NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(selector) ||
             NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector) ||
             NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector)));
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
            request.Content.Headers.ContentLength <= limits.MaximumBodyBytes &&
            request.Content.Headers.ContentType?.MediaType == "application/json" &&
            request.Content.Headers.ContentEncoding.Count == 0);
        byte[] bytes = new byte[limits.MaximumBodyBytes + 1];
        try
        {
            var stream = await request.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            int length = 0, count;
            while (length < bytes.Length && (count = await stream.ReadAsync(bytes.AsMemory(length), token).ConfigureAwait(false)) != 0)
                length += count;
            Require(length <= limits.MaximumBodyBytes && length == request.Content.Headers.ContentLength);
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
        Content = new StringContent("{\"error\":\"operation-source-unavailable\"}", Encoding.UTF8, "application/json")
    };
    private void LeaveSession(Session session)
    {
        lock (gate)
        {
            session.Active--;
            if (session.Closed && session.Active == 0) session.PrivateDrained.TrySetResult();
        }
    }
    private void Leave(Session? session)
    {
        lock (gate)
        {
            if (session is not null)
            {
                session.Active--;
                if (session.Closed && session.Active == 0) session.PrivateDrained.TrySetResult();
            }
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
        _ = PendingProfile || statusSucceededDeleteVaultProfile || statusSucceededDeleteVaultIndependentProfile || statusSucceededDeleteVaultCancellationProfile ? Drain(completion) :
            profile is Profile.OriginalPrivateConnectionDelete or Profile.PrivateConnectionDeleteCleanup
            ? DrainPrivateConnectionDelete(completion) : profile is Profile.OriginalPrivateConnectionUpdate or Profile.PrivateConnectionUpdateCleanup
            ? DrainPrivateConnectionUpdate(completion) : profile is Profile.OriginalVaultRecover or Profile.RecoverVaultCleanup
            ? DrainRecoverVault(completion) : profile is Profile.OriginalVaultCreateOrUpdate or Profile.CreateOrUpdateVaultCleanup
            ? DrainCreateOrUpdateVault(completion) : profile == Profile.StatusFamily ? Drain(completion) :
            profile is Profile.OriginalVaultPurge or Profile.PurgeDeletedVaultCleanup
                ? DrainPurgeDeletedVault(completion) : DrainDeleteVault(completion);
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
                if (session.Pending is { } pending) pending.Invalid = true;
                if (statusPrivateUpdateIndependentProfile) RevokePrivateUpdateIndependent(session);
                if (statusNotificationUpdateIndependentProfile) RevokeNotificationUpdateIndependent(session);
                if (statusNotificationCreateIndependentProfile) RevokeNotificationCreateIndependent(session);
                try { provisioner.CloseSelectedRoot(owner, session.Selector); }
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
                try
                {
                    if (statusSucceededDeleteVaultCancellationProfile)
                    {
                        InvalidateStatusSucceededDeleteVaultCancellation(session);
                        DrainStatusSucceededDeleteVaultCancellation(session);
                    }
                    if (session.Pending is not null)
                    {
                        if (CancellationPending(session)) session.Pending.Persistence = null;
                        DrainPendingInvocation(session);
                    }
                    if (statusSucceededDeleteVaultIndependentProfile && session.StatusSucceededIndependentSettlement is { } candidate)
                    {
                        statusSucceededIndependentSettlements.TryRemove(candidate, out _);
                        session.StatusSucceededIndependentSettlement = null;
                        DrainStatusSucceededDeleteVaultIndependent(session);
                    }
                }
                catch (Exception) { valid = false; }
                try { if (session.Notifications is not null) await session.Notifications.DisposeAsync().ConfigureAwait(false); }
                catch (Exception) { valid = false; }
                try { if (session.Endpoints is not null) await session.Endpoints.DisposeAsync().ConfigureAwait(false); }
                catch (Exception) { valid = false; }
                finally
                {
                    session.NotificationUpdateIndependentBaseline?.Configuration.Dispose();
                    session.NotificationUpdateIndependentObservation?.Configuration.Dispose();
                    RevokeNotificationUpdateIndependent(session);
                    session.NotificationCreateIndependentBaseline?.Configuration.Dispose();
                    session.NotificationCreateIndependentObservation?.Configuration.Dispose();
                    RevokeNotificationCreateIndependent(session);
                    session.StatusNotificationUpdateBaseline?.Configuration.Dispose();
                    session.StatusNotificationUpdateObservation?.Configuration.Dispose();
                    session.StatusNotificationCreateBaseline?.Configuration?.Dispose();
                    session.StatusNotificationCreateObservation?.Configuration.Dispose();
                    session.Stop.Dispose();
                }
            }
            privateUpdateIndependentFacts.Clear();
            pendingIndependentAdmissions.Clear();
            pendingCancellationAdmissions.Clear();
            pendingIndependentStartDrains.Clear();
            pendingCancellationStartDrains.Clear();
            pendingIndependentReadAdmissions.Clear();
            pendingCancellationReadAdmissions.Clear();
            pendingIndependentObservations.Clear();
            pendingCancellationObservations.Clear();
            pendingIndependentCleanupAdmissions.Clear();
            pendingCancellationCleanupAdmissions.Clear();
            pendingIndependentCleanupCompletions.Clear();
            pendingCancellationCleanupCompletions.Clear();
            pendingIndependentInvocationDrains.Clear();
            pendingCancellationInvocationDrains.Clear();
            pendingAdmissions.Clear();
            pendingStartDrains.Clear();
            pendingReadAdmissions.Clear();
            pendingObservations.Clear();
            pendingCleanupAdmissions.Clear();
            pendingCleanupCompletions.Clear();
            pendingInvocationDrains.Clear();
            privateAdmissions.Clear();
            privateSettlements.Clear();
            privateBaselines.Clear();
            privatePosts.Clear();
            statusPrivateAdmissions.Clear();
            statusSucceededAdmissions.Clear();
            statusSucceededReadAdmissions.Clear();
            statusSucceededSettlements.Clear();
            statusSucceededCancellationAdmissions.Clear();
            statusSucceededCancellationCanceledAdmissions.Clear();
            statusSucceededCancellationCanceledDrains.Clear();
            statusSucceededCancellationReadAdmissions.Clear();
            statusSucceededCancellationSettlements.Clear();
            statusSucceededIndependentAdmissions.Clear();
            statusSucceededIndependentReadAdmissions.Clear();
            statusSucceededIndependentSettlements.Clear();
            statusPrivateSettlements.Clear();
            statusPrivateDeleteAdmissions.Clear();
            statusPrivateDeleteSettlements.Clear();
            statusPrivateDeleteSelectedAdmissions.Clear();
            statusPrivateDeleteSelectedSettlements.Clear();
            statusPrivateDeleteIndependentAdmissions.Clear();
            statusPrivateDeleteIndependentReadAdmissions.Clear();
            statusPrivateDeleteIndependentSettlements.Clear();
            statusDeleteSettlements.Clear();
            statusPurgeSettlements.Clear();
            statusRecoverSettlements.Clear();
            statusUpdateSettlements.Clear();
            statusNotificationDeleteIndependentAdmissions.Clear();
            statusNotificationDeleteIndependentReadAdmissions.Clear();
            statusNotificationDeleteIndependentSettlements.Clear();
            statusNotificationUpdateAdmissions.Clear();
            statusNotificationUpdateSettlements.Clear();
            statusNotificationCreateAdmissions.Clear();
            statusNotificationCreateSettlements.Clear();
            notificationSource?.Baseline?.Dispose();
            lifetime.Dispose();
            Require(valid);
            completion.TrySetResult();
        }
        catch (Exception) { completion.TrySetException(Failure()); }
    }
    private static void Require([DoesNotReturnIf(false)] bool condition) { if (!condition) throw Failure(); }
    private static InvalidOperationException Failure() => new("operation-source-unavailable");
    public override string ToString() => "[ManagementOperationFixtureObserverService]";
}
