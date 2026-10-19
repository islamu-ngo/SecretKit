using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// The channel witnesses provider events and brackets local reads. It does not
// manufacture access results or dispatch privilege mutations. Hour/day intervals
// are controlled-fixture authoring only, not native long-lived certification.
internal sealed class InfisicalPrivilegeExpiryObserver : IPrivilegeExpiryObserver
{
    private readonly InfisicalLifecycleObservers channel;
    private readonly string sourceIdentity;
    private readonly PrivilegeExpirySource source;
    private readonly Dictionary<string, Session> sessions = new(StringComparer.Ordinal);

    internal InfisicalPrivilegeExpiryObserver(InfisicalLifecycleObservers channel, string sourceIdentity,
        PrivilegeExpirySource source = PrivilegeExpirySource.NativeProvider)
    {
        if (!Text(sourceIdentity) || !Enum.IsDefined(source))
            throw new NativeCaseFailureException("missing-input");
        this.channel = channel;
        this.sourceIdentity = sourceIdentity;
        this.source = source;
    }

    internal static InfisicalPrivilegeExpiryObserver? FromInputs(NativeEnvironment environment, string family)
    {
        JsonElement input = environment.RequireFamilyInput(family);
        if (!input.TryGetProperty("observer", out JsonElement settings)) return null;
        // A native service configuration cannot opt into simulated authority.
        if (settings.ValueKind != JsonValueKind.Object ||
            settings.TryGetProperty("source", out JsonElement selected) &&
            !(selected.ValueKind == JsonValueKind.Number && selected.TryGetInt32(out int value) &&
                value == (int)PrivilegeExpirySource.NativeProvider ||
                selected.ValueKind == JsonValueKind.String && selected.GetString() == "NativeProvider") ||
            !settings.TryGetProperty("identity", out JsonElement identity) ||
            identity.ValueKind != JsonValueKind.String || !Text(identity.GetString()) ||
            !settings.TryGetProperty("endpoint", out JsonElement endpoint) ||
            endpoint.ValueKind != JsonValueKind.String ||
            !Uri.TryCreate(endpoint.GetString(), UriKind.Absolute, out _) ||
            !settings.TryGetProperty("token", out JsonElement credential) ||
            credential.ValueKind != JsonValueKind.String || credential.GetString() is null ||
            !settings.TryGetProperty("timeoutSeconds", out JsonElement timeout) ||
            timeout.ValueKind != JsonValueKind.Number || !timeout.TryGetInt32(out _))
            throw new NativeCaseFailureException("missing-input");
        var channel = new InfisicalLifecycleObservers(new(new(endpoint.GetString()!),
            credential.GetString()!, identity.GetString()!, timeout.GetInt32()));
        return new(channel, identity.GetString()!);
    }

    public async ValueTask<PrivilegeExpiryArm> ArmAsync(PrivilegeExpiryIntent intent, CancellationToken token)
    {
        if (!ValidIntent(intent)) throw new NativeCaseFailureException("missing-input");
        var session = new Session(intent) { Busy = true };
        lock (sessions)
        {
            if (!sessions.TryAdd(intent.Attempt.Id, session)) throw Unavailable();
        }
        try
        {
            PrivilegeExpiryArm arm = await Post<PrivilegeExpiryArm>("arm", "intent", intent, token);
            if (arm.Intent != intent || !Text(arm.RegistrationId) || arm.SourceIdentity != sourceIdentity ||
                !Text(arm.ClockAuthority) || !Text(arm.ClockEpoch) || !Utc(arm.ArmedAt) ||
                !Utc(arm.StartsAt) || !Utc(arm.EndsAt) || arm.StartsAt <= arm.ArmedAt ||
                arm.StartsAt - arm.ArmedAt != TimeSpan.FromSeconds(intent.ActivationLeadSeconds) ||
                arm.EndsAt - arm.StartsAt != TimeSpan.FromSeconds(DurationSeconds(intent.RelativeDuration)) ||
                arm.Cursor < 0 || !arm.CaptureArmed ||
                source == PrivilegeExpirySource.NativeProvider &&
                (arm.StartsAt <= DateTimeOffset.UtcNow || arm.ArmedAt > DateTimeOffset.UtcNow.AddSeconds(30) ||
                    arm.ArmedAt < DateTimeOffset.UtcNow.AddSeconds(-30)))
                throw Unavailable();
            session.Arm = arm;
            session.Sequence = arm.Cursor;
            return arm;
        }
        finally { Release(session); }
    }

    public async ValueTask<PrivilegeExpiryFence> CompleteAsync(PrivilegeExpiryArm arm, CancellationToken token)
    {
        if (arm?.Intent?.Attempt is null) throw Unavailable();
        Session session = Acquire(arm.Intent.Attempt);
        try
        {
            if (session.Arm != arm || session.Binding is not null) throw Unavailable();
            PrivilegeExpiryFence binding = await Post<PrivilegeExpiryFence>("complete", "arm", session.Arm, token);
            if (!ValidFence(binding, arm) || binding.Disposition == PrivilegeExpiryDisposition.NotDispatched)
                throw Unavailable();
            session.Binding = binding;
            session.Sequence = binding.Sequence;
            return binding;
        }
        finally { Release(session); }
    }

    public async ValueTask<PrivilegeExpiryObservation<T>> ObserveAsync<T>(PrivilegeExpiryFence binding,
        PrivilegeExpiryPhase phase, Func<CancellationToken, ValueTask<T>> sample, CancellationToken token)
    {
        if (binding?.Arm?.Intent?.Attempt is null) throw Unavailable();
        Session session = Acquire(binding.Arm.Intent.Attempt);
        try
        {
            if (sample is null || !Enum.IsDefined(phase) || (int)phase != session.NextPhase ||
                session.Arm != binding.Arm) throw Unavailable();
            if (session.Binding is null)
            {
                // Only the parent, using the actual token barrier receipt, may
                // construct this local fence. It never comes from /complete.
                if (binding.Disposition != PrivilegeExpiryDisposition.NotDispatched ||
                    !ValidFence(binding, session.Arm)) throw Unavailable();
                session.Binding = binding;
                session.Sequence = binding.Sequence;
            }
            if (session.Binding != binding) throw Unavailable();
            PrivilegeExpiryWindow opened = await channel.PostAsync<PrivilegeExpiryWindow>("privilege-expiry/open", writer =>
            {
                Write(writer, "binding", session.Binding);
                writer.WriteNumber("phase", (int)phase);
                writer.WriteNumber("priorSequence", session.Sequence);
            }, token);
            PrivilegeExpiryWindow closed;
            T sampled;
            try
            {
                if (!ValidWindow(opened, binding, phase) || opened.Sequence <= session.Sequence ||
                    opened.ClosedAt != opened.OpenedAt) throw Unavailable();
                session.Sequence = opened.Sequence;
                // Consume the phase before calling user code, including failure.
                session.NextPhase++;
                token.ThrowIfCancellationRequested();
                sampled = await sample(token);
            }
            finally
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                try
                {
                    closed = await Post<PrivilegeExpiryWindow>("close-window", "window", opened, cleanup.Token);
                    if (!ValidWindow(closed, binding, phase) || closed.WindowId != opened.WindowId ||
                        closed.EventId != opened.EventId || closed.OpenedAt != opened.OpenedAt ||
                        closed.Sequence <= Math.Max(session.Sequence, opened.Sequence) ||
                        closed.ClosedAt < closed.OpenedAt)
                        throw new NativeCaseFailureException("cleanup-incomplete");
                    session.Sequence = closed.Sequence;
                }
                catch (Exception error) when (error is NativeCaseFailureException or OperationCanceledException)
                {
                    throw new NativeCaseFailureException("cleanup-incomplete");
                }
            }
            return new(closed, sampled);
        }
        finally { Release(session); }
    }

    public async ValueTask<PrivilegeExpiryCleanup> CloseAsync(PrivilegeExpiryAttempt attempt, CancellationToken token)
    {
        Session session = Acquire(attempt);
        try
        {
            // Use the pinned client attempt, even when /arm committed but its
            // response was lost. The supplied token does not cancel cleanup.
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            PrivilegeExpiryCleanup facts;
            try { facts = await Post<PrivilegeExpiryCleanup>("close", "attempt", session.Intent.Attempt, cleanup.Token); }
            catch (Exception error) when (error is NativeCaseFailureException or OperationCanceledException)
            { throw new NativeCaseFailureException("cleanup-incomplete"); }
            if (facts.Attempt != session.Intent.Attempt || !facts.Closed || !facts.LateCreationFenced ||
                !facts.MutationSettled || !facts.InventoryComplete || facts.RemainingRegistrations != 0 ||
                facts.PendingDeliveries != 0)
                throw new NativeCaseFailureException("cleanup-incomplete");
            session.Closed = true;
            return facts;
        }
        finally { Release(session); }
    }

    private bool ValidIntent(PrivilegeExpiryIntent intent) =>
        intent is not null && intent.Attempt is { } attempt && Text(attempt.Id) && Text(attempt.CaseIdentity) &&
        Text(attempt.Operation) && Enum.IsDefined(attempt.Version) &&
        Text(attempt.OrganizationId) && Text(attempt.ProjectId) && Text(attempt.ProjectSlug) &&
        Text(attempt.IdentityId) && Text(attempt.MembershipId) && Text(attempt.PrivilegeSlug) &&
        (attempt.ExistingPrivilegeId is null || Text(attempt.ExistingPrivilegeId)) &&
        attempt.Source == source && DurationSeconds(intent.RelativeDuration) != 0 &&
        (source == PrivilegeExpirySource.ControlledFixture || intent.RelativeDuration == "1m") &&
        intent.ActivationLeadSeconds is > 0 and <= 300;

    private static int DurationSeconds(string duration) => duration switch
    {
        "1m" => 60,
        "1h" => 3600,
        "1d" => 86400,
        _ => 0
    };

    private static bool ValidFence(PrivilegeExpiryFence binding, PrivilegeExpiryArm arm)
    {
        if (binding.Arm != arm || !Utc(binding.Arm.ArmedAt) || !Utc(binding.Arm.StartsAt) ||
            !Utc(binding.Arm.EndsAt) || binding.Sequence <= arm.Cursor || !binding.ExcludesLateCommit ||
            binding.PrivilegeSlug != arm.Intent.Attempt.PrivilegeSlug ||
            !Enum.IsDefined(binding.Disposition)) return false;
        string? existing = arm.Intent.Attempt.ExistingPrivilegeId;
        return binding.Disposition switch
        {
            PrivilegeExpiryDisposition.Applied => Text(binding.ProviderRequestId) && Text(binding.PrivilegeId) &&
                (existing is null || binding.PrivilegeId == existing),
            PrivilegeExpiryDisposition.Rejected => Text(binding.ProviderRequestId) &&
                binding.PrivilegeId == existing,
            PrivilegeExpiryDisposition.NotDispatched => binding.ProviderRequestId is null &&
                binding.PrivilegeId == existing,
            _ => false
        };
    }

    private static bool ValidWindow(PrivilegeExpiryWindow window, PrivilegeExpiryFence binding,
        PrivilegeExpiryPhase phase) =>
        window.Binding == binding && ValidFence(window.Binding, binding.Arm) &&
        window.Phase == phase && Text(window.WindowId) && Text(window.EventId) &&
        window.Authoritative && window.EventObserved && Utc(window.OpenedAt) && Utc(window.ClosedAt) &&
        InPhase(window.OpenedAt, binding.Arm, phase) && InPhase(window.ClosedAt, binding.Arm, phase);

    private static bool InPhase(DateTimeOffset time, PrivilegeExpiryArm arm, PrivilegeExpiryPhase phase) =>
        phase switch
        {
            PrivilegeExpiryPhase.BeforeActivation => time >= arm.ArmedAt && time < arm.StartsAt,
            PrivilegeExpiryPhase.Active => time >= arm.StartsAt && time < arm.EndsAt,
            PrivilegeExpiryPhase.Expired => time >= arm.EndsAt,
            _ => false
        };

    private Session Acquire(PrivilegeExpiryAttempt attempt)
    {
        lock (sessions)
        {
            if (attempt is null || !Text(attempt.Id) || !sessions.TryGetValue(attempt.Id, out Session? session) ||
                session.Intent.Attempt != attempt || session.Busy || session.Closed) throw Unavailable();
            session.Busy = true;
            return session;
        }
    }

    private void Release(Session session)
    {
        lock (sessions) session.Busy = false;
    }

    private ValueTask<T> Post<T>(string route, string name, object value, CancellationToken token) where T : notnull =>
        channel.PostAsync<T>("privilege-expiry/" + route, writer => Write(writer, name, value), token);

    private static void Write(Utf8JsonWriter writer, string name, object value)
    {
        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, InfisicalLifecycleFamilies.Options);
    }

    private static bool Text(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static NativeCaseFailureException Unavailable() => new("observer-unavailable");
    public override string ToString() => "[InfisicalPrivilegeExpiryObserver]";

    private sealed class Session(PrivilegeExpiryIntent intent)
    {
        internal PrivilegeExpiryIntent Intent { get; } = intent;
        internal PrivilegeExpiryArm? Arm { get; set; }
        internal PrivilegeExpiryFence? Binding { get; set; }
        internal long Sequence { get; set; }
        internal int NextPhase { get; set; }
        internal bool Busy { get; set; }
        internal bool Closed { get; set; }
        public override string ToString() => "[PrivilegeExpirySession]";
    }
}
