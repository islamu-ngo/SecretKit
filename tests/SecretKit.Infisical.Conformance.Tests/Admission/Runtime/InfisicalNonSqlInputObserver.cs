using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Private channel client only. Native qualification belongs to the independent source.
internal sealed class InfisicalNonSqlInputObserver : IInfisicalNonSqlInputObserver
{
    private readonly InfisicalLifecycleObservers channel;
    private readonly string identity;
    private readonly NonSqlInputSource source;
    private readonly Dictionary<string, Session> sessions = new(StringComparer.Ordinal);
    private readonly HashSet<string> roots = new(StringComparer.Ordinal);
    private readonly HashSet<string> registrations = new(StringComparer.Ordinal);
    private readonly HashSet<string> events = new(StringComparer.Ordinal);
    private readonly HashSet<string> requests = new(StringComparer.Ordinal);
    private readonly HashSet<string> attempts = new(StringComparer.Ordinal);
    private bool busy;

    internal InfisicalNonSqlInputObserver(InfisicalLifecycleObservers channel, string identity,
        NonSqlInputSource source = NonSqlInputSource.NativeProvider)
    {
        NonSqlInputEvidenceGuard.Require(channel is not null && NonSqlInputEvidenceGuard.Text(identity) &&
            identity is not ("setup" or "runtime" or "denied" or "administrative" or "observer") &&
            Enum.IsDefined(source), "missing-input");
        this.channel = channel!;
        this.identity = identity;
        this.source = source;
    }

    internal static InfisicalNonSqlInputObserver? FromInputs(NativeEnvironment environment, string family)
    {
        var input = environment.RequireFamilyInput(family);
        if (!input.TryGetProperty("observer", out var settings)) return null;
        NonSqlInputEvidenceGuard.Require(settings.ValueKind == JsonValueKind.Object, "missing-input");
        if (settings.TryGetProperty("source", out var selected))
            NonSqlInputEvidenceGuard.Require(
                selected.ValueKind == JsonValueKind.String && selected.GetString() == "NativeProvider" ||
                selected.ValueKind == JsonValueKind.Number && selected.TryGetInt32(out int value) &&
                    value == (int)NonSqlInputSource.NativeProvider, "missing-input");
        try
        {
            NonSqlInputEvidenceGuard.Require(
                settings.TryGetProperty("endpoint", out var endpoint) && endpoint.ValueKind == JsonValueKind.String &&
                Uri.TryCreate(endpoint.GetString(), UriKind.Absolute, out _) &&
                settings.TryGetProperty("token", out var credential) && credential.ValueKind == JsonValueKind.String &&
                settings.TryGetProperty("identity", out var label) && label.ValueKind == JsonValueKind.String &&
                settings.TryGetProperty("timeoutSeconds", out var timeout) && timeout.TryGetInt32(out _),
                "missing-input");
            string labelValue = settings.GetProperty("identity").GetString()!;
            return new(new(new(new(settings.GetProperty("endpoint").GetString()!),
                settings.GetProperty("token").GetString()!, labelValue,
                settings.GetProperty("timeoutSeconds").GetInt32())), labelValue);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or ArgumentException)
        { throw new NativeCaseFailureException("missing-input"); }
    }

    public async ValueTask<NonSqlInputBinding> OpenAsync(NonSqlInputRootAttempt attempt,
        NonSqlInputPrivateProfiles profiles, CancellationToken token)
    {
        NonSqlInputEvidenceGuard.Require(attempt is not null && NonSqlInputEvidenceGuard.ValidRoot(attempt) &&
            attempt.Source == source && profiles is not null && profiles.Provider == attempt.Provider, "missing-input");
        Session session;
        lock (sessions)
        {
            NonSqlInputEvidenceGuard.Require(!busy && !sessions.ContainsKey(attempt!.Id) && roots.Add(attempt.RootNonce));
            session = new(attempt!, profiles!);
            sessions.Add(attempt!.Id, session);
            busy = true;
        }
        try
        {
            var facts = await Post<NonSqlInputBinding>(session, "open", writer =>
            {
                Write(writer, "attempt", attempt);
                profiles!.Write(writer);
            }, token);
            NonSqlInputEvidenceGuard.Require(facts.Attempt == attempt);
            session.Guard.Open(facts with { Attempt = attempt }, identity);
            Unique(registrations, facts.RegistrationId);
            session.Unsettled = false;
            return session.Guard.Binding!;
        }
        catch (ObjectDisposedException) { throw new NativeCaseFailureException("missing-input"); }
        finally { Release(); }
    }

    public async ValueTask<NonSqlInputArm> ArmAsync(NonSqlInputAttempt attempt, CancellationToken token)
    {
        var session = Acquire(attempt.Binding);
        try
        {
            NonSqlInputEvidenceGuard.Require(session.Arm is null);
            Unique(attempts, attempt.Id);
            session.Guard.CheckAttempt(attempt);
            var facts = await Post<NonSqlInputArm>(session, "arm", writer => Write(writer, "attempt", attempt), token);
            var arm = session.Guard.Arm(attempt, facts) with { Attempt = attempt };
            Unique(registrations, arm.RegistrationId);
            session.Arm = arm;
            session.Unsettled = false;
            return arm;
        }
        finally { Release(); }
    }

    public async ValueTask<NonSqlInputFence> CompleteAsync(NonSqlInputArm arm, DispatchEvidence receipt, CancellationToken token)
    {
        var session = Acquire(arm.Attempt.Binding);
        try
        {
            NonSqlInputEvidenceGuard.Require(ReferenceEquals(arm, session.Arm));
            session.Arm = null;
            var facts = await Post<NonSqlInputFence>(session, "complete", writer =>
            {
                Write(writer, "arm", arm);
                Write(writer, "receipt", receipt);
            }, token);
            session.Guard.Complete(arm, receipt, facts);
            Unique(events, facts.EventId);
            if (facts.ProviderRequestId is not null) Unique(requests, facts.ProviderRequestId);
            session.Unsettled = false;
            return facts;
        }
        finally { Release(); }
    }

    public async ValueTask<NonSqlInputObservation> ObserveAsync(NonSqlInputBinding binding, Guid? definitionId,
        NonSqlInputConfiguration configuration, CancellationToken token)
    {
        var session = Acquire(binding);
        try
        {
            NonSqlInputEvidenceGuard.Require(session.Arm is null);
            session.Guard.CheckObservation(definitionId, configuration);
            var facts = await Post<NonSqlInputObservation>(session, "observe", writer =>
            {
                Write(writer, "binding", binding);
                Write(writer, "definitionId", definitionId);
                Write(writer, "configuration", configuration);
                Write(writer, "phase", session.Guard.Fence!.Arm.Attempt.Id);
            }, token);
            session.Guard.Observe(definitionId, configuration, facts);
            Unique(events, facts.EventId);
            session.Unsettled = false;
            return facts;
        }
        finally { Release(); }
    }

    public async ValueTask<NonSqlInputCleanup> CloseAsync(NonSqlInputRootAttempt attempt, CancellationToken token)
    {
        var session = Acquire(attempt, cleanup: true);
        session.Closed = true;
        try
        {
            // Original-root journal recovery never inherits a cancelled operation token.
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var facts = await Post<NonSqlInputCleanup>(session, "close",
                writer => Write(writer, "attempt", attempt), cleanup.Token);
            NonSqlInputEvidenceGuard.Cleanup(attempt, facts);
            return facts;
        }
        catch (Exception error) when (error is NativeCaseFailureException or OperationCanceledException)
        { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { Release(); }
    }

    private Session Acquire(NonSqlInputBinding binding)
    {
        var session = Acquire(binding.Attempt);
        if (ReferenceEquals(binding, session.Guard.Binding)) return session;
        Release();
        throw new NativeCaseFailureException("observer-unavailable");
    }
    private Session Acquire(NonSqlInputRootAttempt attempt, bool cleanup = false)
    {
        lock (sessions)
        {
            NonSqlInputEvidenceGuard.Require(sessions.TryGetValue(attempt.Id, out var session) &&
                ReferenceEquals(attempt, session.Attempt) && !busy && !session.Closed &&
                (cleanup || !session.Unsettled && session.Guard.Binding is not null));
            busy = true;
            return session!;
        }
    }
    private void Release() { lock (sessions) busy = false; }
    private ValueTask<T> Post<T>(Session session, string route, Action<Utf8JsonWriter> fields,
        CancellationToken token) where T : notnull
    {
        session.Unsettled = true;
        return channel.PostAsync<T>("nonsql-input/" + route, fields, token);
    }
    private static void Write(Utf8JsonWriter writer, string name, object? value)
    {
        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, InfisicalLifecycleFamilies.Options);
    }
    private static void Unique(HashSet<string> set, string value) =>
        NonSqlInputEvidenceGuard.Require(NonSqlInputEvidenceGuard.Text(value) && set.Add(value));
    public override string ToString() => "[InfisicalNonSqlInputObserver]";

    private sealed class Session(NonSqlInputRootAttempt attempt, NonSqlInputPrivateProfiles profiles)
    {
        internal NonSqlInputRootAttempt Attempt { get; } = attempt;
        internal NonSqlInputEvidenceGuard Guard { get; } = new(attempt, profiles);
        internal NonSqlInputArm? Arm { get; set; }
        internal bool Unsettled { get; set; } = true;
        internal bool Closed { get; set; }
        public override string ToString() => "[NonSqlInputSourceSession]";
    }
}
