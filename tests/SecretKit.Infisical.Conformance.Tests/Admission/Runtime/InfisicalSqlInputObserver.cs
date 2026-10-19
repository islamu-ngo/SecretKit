using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Client for an independently operated private source. This is not a native
// source implementation and offline acknowledgements cannot qualify a provider.
internal sealed class InfisicalSqlInputObserver : IInfisicalSqlInputObserver
{
    private readonly InfisicalLifecycleObservers channel;
    private readonly string sourceIdentity;
    private readonly SqlInputSource source;
    private readonly Dictionary<string, Session> sessions = new(StringComparer.Ordinal);
    private readonly HashSet<string> attempts = new(StringComparer.Ordinal);
    private readonly HashSet<string> registrations = new(StringComparer.Ordinal);
    private readonly HashSet<string> events = new(StringComparer.Ordinal);
    private readonly HashSet<string> requests = new(StringComparer.Ordinal);
    private readonly HashSet<string> roots = new(StringComparer.Ordinal);
    private bool busy;

    internal InfisicalSqlInputObserver(InfisicalLifecycleObservers channel, string sourceIdentity,
        SqlInputSource source = SqlInputSource.NativeProvider)
    {
        if (channel is null || !Text(sourceIdentity) || !Enum.IsDefined(source) ||
            sourceIdentity is "setup" or "runtime" or "denied" or "administrative" or "observer")
            throw new NativeCaseFailureException("missing-input");
        this.channel = channel;
        this.sourceIdentity = sourceIdentity;
        this.source = source;
    }

    internal static InfisicalSqlInputObserver? FromInputs(NativeEnvironment environment, string family)
    {
        JsonElement input = environment.RequireFamilyInput(family);
        if (!input.TryGetProperty("observer", out JsonElement settings)) return null;
        if (settings.ValueKind != JsonValueKind.Object ||
            settings.TryGetProperty("source", out JsonElement selected) &&
            !(selected.ValueKind == JsonValueKind.Number && selected.TryGetInt32(out int value) &&
                value == (int)SqlInputSource.NativeProvider ||
                selected.ValueKind == JsonValueKind.String && selected.GetString() == "NativeProvider") ||
            !settings.TryGetProperty("identity", out JsonElement identity) ||
            identity.ValueKind != JsonValueKind.String || !Text(identity.GetString()) ||
            !settings.TryGetProperty("endpoint", out JsonElement endpoint) ||
            endpoint.ValueKind != JsonValueKind.String ||
            !Uri.TryCreate(endpoint.GetString(), UriKind.Absolute, out Uri? uri) ||
            !settings.TryGetProperty("token", out JsonElement credential) ||
            credential.ValueKind != JsonValueKind.String || credential.GetString() is null ||
            !settings.TryGetProperty("timeoutSeconds", out JsonElement timeout) ||
            timeout.ValueKind != JsonValueKind.Number || !timeout.TryGetInt32(out int seconds))
            throw new NativeCaseFailureException("missing-input");
        return new(new(new(uri, credential.GetString()!, identity.GetString()!, seconds)), identity.GetString()!);
    }

    public async ValueTask<SqlInputBinding> OpenAsync(SqlInputRootAttempt attempt,
        SqlInputPrivateProfiles profiles, CancellationToken token)
    {
        if (!ValidRoot(attempt) || profiles is null || profiles.Engine != attempt.Engine)
            throw new NativeCaseFailureException("missing-input");
        Session session;
        lock (sessions)
        {
            if (busy || !attempts.Add(attempt.Id) || !roots.Add(attempt.RootNonce)) throw Unavailable();
            session = new(attempt, profiles);
            sessions.Add(attempt.Id, session);
            busy = true;
        }
        try
        {
            var facts = await Post<SqlInputBinding>(session, "open", writer =>
            {
                Write(writer, "attempt", attempt);
                profiles.Write(writer);
            }, token);
            if (facts.Attempt != attempt || !Unique(registrations, facts.RegistrationId) ||
                facts.SourceIdentity != sourceIdentity || !Text(facts.ClockAuthority) ||
                !Text(facts.ClockEpoch) || !Utc(facts.OpenedAt) || facts.Sequence < 0 ||
                !facts.OwnedRootCreated || !facts.RootInitiallyAbsent || !facts.BaselineAdminAccepted ||
                !facts.SelectedAdminAccepted || !facts.WrongAdminRejected || !facts.DistinctContrasts ||
                !facts.IndependentStorageQualified || !facts.AdminSessionCaptureQualified ||
                session.TlsRequired && !facts.TlsCaptureQualified ||
                session.RoutingRequired && !facts.RoutingCaptureQualified) throw Unavailable();
            facts = facts with { Attempt = attempt };
            session.Binding = facts;
            session.Sequence = facts.Sequence;
            session.Time = facts.OpenedAt;
            session.Unsettled = false;
            return facts;
        }
        catch (ObjectDisposedException) { throw new NativeCaseFailureException("missing-input"); }
        finally { Release(); }
    }

    public async ValueTask<SqlInputArm> ArmAsync(SqlInputAttempt attempt, CancellationToken token)
    {
        Session session = Acquire(attempt?.Binding);
        try
        {
            if (session.Arm is not null || attempt is null || !Text(attempt.Id) ||
                !Text(attempt.OriginalName) || attempt.DefinitionId == Guid.Empty ||
                !Text(attempt.Operation) || !Text(attempt.Variant) || !Text(attempt.Case) ||
                !Enum.IsDefined(attempt.Configuration) || !attempts.Add(attempt.Id) ||
                attempt.Configuration == SqlInputConfiguration.Selected &&
                (attempt.Operation != session.Operation ||
                    InfisicalDynamicClientEffects.NormalizeSqlVariant(attempt.Variant) != session.Variant))
                throw Unavailable();
            var arm = await Post<SqlInputArm>(session, "arm", writer => Write(writer, "attempt", attempt), token);
            if (arm.Attempt != attempt || !Bound(arm.Attempt?.Binding, attempt.Binding) ||
                !Unique(registrations, arm.RegistrationId) ||
                !Next(session, arm.Cursor, arm.ArmedAt) || !arm.CaptureArmed) throw Unavailable();
            arm = arm with { Attempt = attempt };
            session.Arm = arm;
            session.Unsettled = false;
            return arm;
        }
        finally { Release(); }
    }

    public async ValueTask<SqlInputFence> CompleteAsync(SqlInputArm arm, DispatchEvidence receipt, CancellationToken token)
    {
        Session session = Acquire(arm?.Attempt?.Binding);
        try
        {
            if (arm is null || !ReferenceEquals(arm, session.Arm) ||
                receipt is not (DispatchEvidence.NotDispatched or DispatchEvidence.Rejected or
                    DispatchEvidence.Applied or DispatchEvidence.PossiblyDispatched)) throw Unavailable();
            // Consume before sending; a lost or rejected completion never resumes.
            session.Arm = null;
            var facts = await Post<SqlInputFence>(session, "complete", writer =>
            {
                Write(writer, "arm", arm);
                Write(writer, "receipt", receipt);
            }, token);
            if (facts.Arm == arm && facts.OriginalAttemptSettled &&
                (facts.MatchedRequests > 1 || facts.MatchedCommits > 1 || !facts.NoReplay))
                throw new NativeCaseFailureException("effect-mismatch");
            if (facts.Arm != arm || !Bound(facts.Arm?.Attempt?.Binding, arm.Attempt.Binding) ||
                facts.Disposition != receipt || !Unique(events, facts.EventId) ||
                !Next(session, facts.Sequence, facts.SettledAt) ||
                !facts.OriginalAttemptSettled || !facts.ExcludesLateCommit || !facts.NoReplay ||
                !facts.IndependentStorageRead ||
                (receipt == DispatchEvidence.PossiblyDispatched ?
                    facts.MatchedRequests is < 0 or > 1 || facts.Applied && facts.MatchedRequests != 1 :
                    facts.MatchedRequests != (receipt == DispatchEvidence.NotDispatched ? 0 : 1)) ||
                facts.MatchedCommits != (facts.Applied ? 1 : 0) ||
                receipt is DispatchEvidence.NotDispatched or DispatchEvidence.Rejected && facts.Applied ||
                receipt == DispatchEvidence.Applied && !facts.Applied ||
                facts.MatchedRequests == 0 && facts.ProviderRequestId is not null ||
                facts.MatchedRequests == 1 && !Unique(requests, facts.ProviderRequestId) ||
                facts.DefinitionId == Guid.Empty ||
                arm.Attempt.DefinitionId is { } expected && facts.DefinitionId != expected ||
                facts.DefinitionId is null && !facts.DefinitionAbsent ||
                facts.Applied && !facts.DefinitionAbsent && facts.DefinitionId is null)
                throw Unavailable();
            session.Fence = facts;
            session.Unsettled = false;
            return facts;
        }
        finally { Release(); }
    }

    public async ValueTask<SqlInputObservation> ObserveAsync(SqlInputBinding binding, Guid definitionId,
        SqlInputConfiguration configuration, CancellationToken token)
    {
        Session session = Acquire(binding);
        try
        {
            if (definitionId == Guid.Empty || !Enum.IsDefined(configuration) || session.Arm is not null ||
                session.Fence is not { DefinitionAbsent: false } fence || fence.DefinitionId != definitionId ||
                configuration != (fence.Applied ? fence.Arm.Attempt.Configuration : SqlInputConfiguration.Baseline))
                throw Unavailable();
            string phase = fence.Arm.Attempt.Id;
            if (!session.Phases.Add(phase)) throw Unavailable();
            var facts = await Post<SqlInputObservation>(session, "observe", writer =>
            {
                Write(writer, "binding", binding);
                Write(writer, "definitionId", definitionId);
                Write(writer, "configuration", configuration);
                writer.WriteString("phase", phase);
            }, token);
            if (!Bound(facts.Binding, binding) || facts.DefinitionId != definitionId ||
                facts.Configuration != configuration || facts.Phase != phase ||
                !Unique(events, facts.EventId) || !Next(session, facts.Sequence, facts.ObservedAt) ||
                !facts.IndependentStorageRead || !facts.ActualAdminSessionCaptured ||
                !facts.FreshPublicLeaseObserved) throw Unavailable();
            if (!facts.PersistedMergeMatches || !facts.OptionsMatch ||
                !facts.AdminPrincipalMatches || !facts.AdminTargetMatches || !facts.WrongAdminRejected ||
                !facts.GatewayRouteMatches || !facts.EngineQualifiedTlsMatches || !facts.RetainedStatementsMatch ||
                (configuration == SqlInputConfiguration.Baseline ? session.BaselineCaRequired : session.SelectedCaRequired) &&
                (!facts.OwnedCaChain || !facts.InvalidTrustRejected))
                throw new NativeCaseFailureException("effect-mismatch");
            session.Unsettled = false;
            return facts;
        }
        finally { Release(); }
    }

    public async ValueTask<SqlInputCleanup> CloseAsync(SqlInputRootAttempt attempt, CancellationToken token)
    {
        Session session = Acquire(attempt, cleanup: true);
        try
        {
            session.Closed = true;
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            SqlInputCleanup facts;
            try
            {
                facts = await Post<SqlInputCleanup>(session, "close",
                    writer => Write(writer, "attempt", session.Attempt), deadline.Token);
            }
            catch (Exception error) when (error is NativeCaseFailureException or OperationCanceledException)
            { throw new NativeCaseFailureException("cleanup-incomplete"); }
            if (facts.Attempt != session.Attempt || !facts.Closed || !facts.OwnedRootRemoved ||
                !facts.BorrowedStatePreserved || !facts.DefinitionsAbsent || !facts.LeasesAbsent ||
                !facts.PrincipalsAbsent || !facts.PrivateProfilesDestroyed || !facts.OriginalAttemptsSettled ||
                !facts.LateCreationFenced || facts.RemainingRegistrations != 0 || facts.PendingDeliveries != 0)
                throw new NativeCaseFailureException("cleanup-incomplete");
            session.Unsettled = false;
            return facts;
        }
        finally { Release(); }
    }

    private bool ValidRoot(SqlInputRootAttempt? value) => value is not null &&
        Text(value.Id) && Text(value.CaseIdentity) && value.ProviderVersion == "v0.166.3" &&
        Text(value.DeploymentId) && Text(value.SourceProfile) && Text(value.RootNonce) &&
        Enum.IsDefined(value.Engine) && Guid.TryParseExact(value.ProjectId, "D", out Guid id) && id != Guid.Empty &&
        id.ToString("D") == value.ProjectId && Text(value.Environment) && Text(value.Folder) &&
        value.Folder.StartsWith('/') && value.Source == source;

    private Session Acquire(SqlInputBinding? binding)
    {
        Session session = Acquire(binding?.Attempt);
        if (binding is not null && ReferenceEquals(binding, session.Binding)) return session;
        Release();
        throw Unavailable();
    }

    private Session Acquire(SqlInputRootAttempt? attempt, bool cleanup = false)
    {
        lock (sessions)
        {
            if (attempt is null || !Text(attempt.Id) || !sessions.TryGetValue(attempt.Id, out Session? session) ||
                !ReferenceEquals(attempt, session.Attempt) || busy || session.Closed ||
                !cleanup && (session.Unsettled || session.Binding is null)) throw Unavailable();
            busy = true;
            return session;
        }
    }

    private void Release() { lock (sessions) busy = false; }
    private ValueTask<T> Post<T>(Session session, string route, Action<Utf8JsonWriter> fields,
        CancellationToken token) where T : notnull
    {
        session.Unsettled = true;
        return channel.PostAsync<T>("sql-input/" + route, fields, token);
    }
    private static void Write(Utf8JsonWriter writer, string name, object value)
    {
        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, InfisicalLifecycleFamilies.Options);
    }
    private static bool Bound(SqlInputBinding? value, SqlInputBinding expected) =>
        value == expected && value is not null && Utc(value.OpenedAt);
    private static bool Next(Session session, long sequence, DateTimeOffset time)
    {
        if (sequence <= session.Sequence || !Utc(time) || time < session.Time) return false;
        session.Sequence = sequence;
        session.Time = time;
        return true;
    }
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static bool Text(string? value) => !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 512 && !value.Any(char.IsControl);
    private static bool Unique(HashSet<string> set, string? value) => Text(value) && set.Add(value!);
    private static NativeCaseFailureException Unavailable() => new("observer-unavailable");
    public override string ToString() => "[InfisicalSqlInputObserver]";

    private sealed class Session(SqlInputRootAttempt attempt, SqlInputPrivateProfiles profiles)
    {
        internal SqlInputRootAttempt Attempt { get; } = attempt;
        internal string Operation { get; } = profiles.Operation;
        internal string Variant { get; } = profiles.Variant;
        internal bool BaselineCaRequired { get; } = profiles.BaselineCaRequired;
        internal bool SelectedCaRequired { get; } = profiles.SelectedCaRequired;
        internal bool TlsRequired { get; } = profiles.TlsRequired;
        internal bool RoutingRequired { get; } = profiles.RoutingRequired;
        internal SqlInputBinding? Binding { get; set; }
        internal SqlInputArm? Arm { get; set; }
        internal SqlInputFence? Fence { get; set; }
        internal HashSet<string> Phases { get; } = new(StringComparer.Ordinal);
        internal long Sequence { get; set; }
        internal DateTimeOffset Time { get; set; }
        internal bool Unsettled { get; set; }
        internal bool Closed { get; set; }
        public override string ToString() => "[SqlInputSourceSession]";
    }
}
