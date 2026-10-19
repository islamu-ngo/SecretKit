using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// The channel witnesses provider events and brackets local reads. It does not
// manufacture access results or dispatch membership mutations. "1m" is the
// documented relative syntax, not a certified provider minimum.
internal sealed class InfisicalMembershipExpiryObserver : IMembershipExpiryObserver
{
    private readonly InfisicalLifecycleObservers channel;
    private readonly string sourceIdentity;
    private readonly MembershipExpirySource source;
    private readonly Dictionary<string, Session> sessions = new(StringComparer.Ordinal);

    internal InfisicalMembershipExpiryObserver(InfisicalLifecycleObservers channel, string sourceIdentity,
        MembershipExpirySource source = MembershipExpirySource.NativeProvider)
    {
        if (!Text(sourceIdentity) || !Enum.IsDefined(source))
            throw new NativeCaseFailureException("missing-input");
        this.channel = channel;
        this.sourceIdentity = sourceIdentity;
        this.source = source;
    }

    internal static InfisicalMembershipExpiryObserver? FromInputs(NativeEnvironment environment, string family)
    {
        JsonElement input = environment.RequireFamilyInput(family);
        if (!input.TryGetProperty("observer", out JsonElement settings)) return null;
        // A native service configuration cannot opt into simulated authority.
        if (settings.ValueKind != JsonValueKind.Object ||
            settings.TryGetProperty("source", out JsonElement selected) &&
            !(selected.ValueKind == JsonValueKind.Number && selected.TryGetInt32(out int value) &&
                value == (int)MembershipExpirySource.NativeProvider ||
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
        var channel = InfisicalLifecycleObservers.FromInputs(environment, family);
        return channel is null ? null : new(channel, identity.GetString()!);
    }

    public async ValueTask<MembershipExpiryArm> ArmAsync(MembershipExpiryIntent intent, CancellationToken token)
    {
        if (!ValidIntent(intent)) throw new NativeCaseFailureException("missing-input");
        var session = new Session(intent) { Busy = true };
        lock (sessions)
        {
            if (!sessions.TryAdd(intent.Attempt.Id, session)) throw Unavailable();
        }
        try
        {
            MembershipExpiryArm arm = await Post<MembershipExpiryArm>("arm", "intent", intent, token);
            if (arm.Intent != intent || !Text(arm.RegistrationId) || arm.SourceIdentity != sourceIdentity ||
                !Text(arm.ClockAuthority) || !Text(arm.ClockEpoch) || !Utc(arm.ArmedAt) ||
                !Utc(arm.StartsAt) || !Utc(arm.EndsAt) || arm.StartsAt <= arm.ArmedAt ||
                arm.StartsAt - arm.ArmedAt != TimeSpan.FromSeconds(intent.ActivationLeadSeconds) ||
                arm.EndsAt - arm.StartsAt != TimeSpan.FromSeconds(60) || arm.Cursor < 0 || !arm.CaptureArmed ||
                source == MembershipExpirySource.NativeProvider &&
                (arm.StartsAt <= DateTimeOffset.UtcNow || arm.ArmedAt > DateTimeOffset.UtcNow.AddSeconds(30) ||
                    arm.ArmedAt < DateTimeOffset.UtcNow.AddSeconds(-30)))
                throw Unavailable();
            session.Arm = arm;
            session.Sequence = arm.Cursor;
            return arm;
        }
        finally { Release(session); }
    }

    public async ValueTask<MembershipExpiryFence> CompleteAsync(MembershipExpiryArm arm, CancellationToken token)
    {
        if (arm?.Intent?.Attempt is null) throw Unavailable();
        Session session = Acquire(arm.Intent.Attempt);
        try
        {
            if (session.Arm != arm || session.Binding is not null) throw Unavailable();
            MembershipExpiryFence binding = await Post<MembershipExpiryFence>("complete", "arm", session.Arm, token);
            if (!ValidFence(binding, arm) || binding.Disposition == MembershipExpiryDisposition.NotDispatched)
                throw Unavailable();
            session.Binding = binding;
            session.Sequence = binding.Sequence;
            return binding;
        }
        finally { Release(session); }
    }

    public async ValueTask<MembershipExpiryObservation<T>> ObserveAsync<T>(MembershipExpiryFence binding,
        MembershipExpiryPhase phase, Func<CancellationToken, ValueTask<T>> sample, CancellationToken token)
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
                if (binding.Disposition != MembershipExpiryDisposition.NotDispatched ||
                    !ValidFence(binding, session.Arm)) throw Unavailable();
                session.Binding = binding;
                session.Sequence = binding.Sequence;
            }
            if (session.Binding != binding) throw Unavailable();
            MembershipExpiryWindow opened = await channel.PostAsync<MembershipExpiryWindow>("membership-expiry/open", writer =>
            {
                Write(writer, "binding", session.Binding);
                writer.WriteNumber("phase", (int)phase);
                writer.WriteNumber("priorSequence", session.Sequence);
            }, token);
            MembershipExpiryWindow closed;
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
                    closed = await Post<MembershipExpiryWindow>("close-window", "window", opened, cleanup.Token);
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

    public async ValueTask<MembershipExpiryCleanup> CloseAsync(MembershipExpiryAttempt attempt, CancellationToken token)
    {
        Session session = Acquire(attempt);
        try
        {
            // Use the pinned client attempt, even when /arm committed but its
            // response was lost. The supplied token does not cancel cleanup.
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            MembershipExpiryCleanup facts;
            try { facts = await Post<MembershipExpiryCleanup>("close", "attempt", session.Intent.Attempt, cleanup.Token); }
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

    private bool ValidIntent(MembershipExpiryIntent intent) =>
        intent is not null && intent.Attempt is { } attempt && Text(attempt.Id) && Text(attempt.CaseIdentity) &&
        Text(attempt.OrganizationId) && Text(attempt.ProjectId) && Enum.IsDefined(attempt.PrincipalKind) &&
        Text(attempt.PrincipalId) && Text(attempt.RuntimePrincipalId) &&
        (attempt.ExistingMembershipId is null || Text(attempt.ExistingMembershipId)) &&
        attempt.Source == source && intent.RelativeDuration == "1m" && intent.ActivationLeadSeconds is > 0 and <= 300;

    private static bool ValidFence(MembershipExpiryFence binding, MembershipExpiryArm arm)
    {
        if (binding.Arm != arm || binding.Sequence <= arm.Cursor || !binding.ExcludesLateCommit ||
            !Enum.IsDefined(binding.Disposition)) return false;
        string? existing = arm.Intent.Attempt.ExistingMembershipId;
        return binding.Disposition switch
        {
            MembershipExpiryDisposition.Applied => Text(binding.ProviderRequestId) && Text(binding.MembershipId) &&
                (existing is null || binding.MembershipId == existing) && Text(binding.AssignmentId),
            MembershipExpiryDisposition.Rejected => Text(binding.ProviderRequestId) &&
                binding.MembershipId == existing && binding.AssignmentId is null,
            MembershipExpiryDisposition.NotDispatched => binding.ProviderRequestId is null &&
                binding.MembershipId == existing && binding.AssignmentId is null,
            _ => false
        };
    }

    private static bool ValidWindow(MembershipExpiryWindow window, MembershipExpiryFence binding,
        MembershipExpiryPhase phase) =>
        window.Binding == binding && window.Phase == phase && Text(window.WindowId) && Text(window.EventId) &&
        window.Authoritative && window.EventObserved && Utc(window.OpenedAt) && Utc(window.ClosedAt) &&
        InPhase(window.OpenedAt, binding.Arm, phase) && InPhase(window.ClosedAt, binding.Arm, phase);

    private static bool InPhase(DateTimeOffset time, MembershipExpiryArm arm, MembershipExpiryPhase phase) =>
        phase switch
        {
            MembershipExpiryPhase.BeforeActivation => time >= arm.ArmedAt && time < arm.StartsAt,
            MembershipExpiryPhase.Active => time >= arm.StartsAt && time < arm.EndsAt,
            MembershipExpiryPhase.Expired => time >= arm.EndsAt,
            _ => false
        };

    private Session Acquire(MembershipExpiryAttempt attempt)
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
        channel.PostAsync<T>("membership-expiry/" + route, writer => Write(writer, name, value), token);

    private static void Write(Utf8JsonWriter writer, string name, object value)
    {
        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, InfisicalLifecycleFamilies.Options);
    }

    private static bool Text(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static NativeCaseFailureException Unavailable() => new("observer-unavailable");
    public override string ToString() => "[InfisicalMembershipExpiryObserver]";

    private sealed class Session(MembershipExpiryIntent intent)
    {
        internal MembershipExpiryIntent Intent { get; } = intent;
        internal MembershipExpiryArm? Arm { get; set; }
        internal MembershipExpiryFence? Binding { get; set; }
        internal long Sequence { get; set; }
        internal int NextPhase { get; set; }
        internal bool Busy { get; set; }
        internal bool Closed { get; set; }
        public override string ToString() => "[MembershipExpirySession]";
    }
}
