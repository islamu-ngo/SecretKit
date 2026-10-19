using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// A client for an independently qualified capture source, not native certification.
// MatchedIssuances/IssueEventObserved attest actual response capture and an
// authoritative credential-to-metadata join. Neither singleton metadata nor
// guessed JWT claims qualify. The host must check the domain-bound HMAC against
// its caller-owned credential in constant time; that proves equality under the
// private key, not source authenticity. Native deadline qualification is host-owned.
internal sealed class InfisicalAuthenticationExpiryObserver : IAuthenticationExpiryObserver
{
    private readonly InfisicalLifecycleObservers channel;
    private readonly string sourceIdentity;
    private readonly AuthenticationExpirySource source;
    private readonly Dictionary<string, Session> sessions = new(StringComparer.Ordinal);

    internal InfisicalAuthenticationExpiryObserver(InfisicalLifecycleObservers channel, string sourceIdentity,
        AuthenticationExpirySource source = AuthenticationExpirySource.NativeProvider)
    {
        if (channel is null || !Text(sourceIdentity) || !Enum.IsDefined(source) ||
            sourceIdentity is "setup" or "runtime" or "denied" or "administrative" or "observer")
            throw new NativeCaseFailureException("missing-input");
        this.channel = channel;
        this.sourceIdentity = sourceIdentity;
        this.source = source;
    }

    internal static InfisicalAuthenticationExpiryObserver? FromInputs(NativeEnvironment environment, string family)
    {
        JsonElement input = environment.RequireFamilyInput(family);
        if (!input.TryGetProperty("observer", out JsonElement settings)) return null;
        // Native configuration cannot opt into controlled authority.
        if (settings.ValueKind != JsonValueKind.Object ||
            settings.TryGetProperty("source", out JsonElement selected) &&
            !(selected.ValueKind == JsonValueKind.Number && selected.TryGetInt32(out int value) &&
                value == (int)AuthenticationExpirySource.NativeProvider ||
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

    public async ValueTask<AuthenticationExpiryArm> ArmAsync(AuthenticationExpiryAttempt attempt,
        ReadOnlyMemory<byte> correlationKey, CancellationToken token)
    {
        if (!ValidAttempt(attempt) || correlationKey.Length != 32)
            throw new NativeCaseFailureException("missing-input");
        var session = new Session(attempt) { Busy = true };
        lock (sessions)
        {
            if (!sessions.TryAdd(attempt.Id, session)) throw Unavailable();
        }
        try
        {
            AuthenticationExpiryArm arm = await channel.PostAsync<AuthenticationExpiryArm>("authentication-expiry/arm",
                writer =>
                {
                    Write(writer, "attempt", attempt);
                    writer.WriteBase64String("correlationKey", correlationKey.Span);
                }, token);
            if (arm.Attempt != attempt || !Text(arm.RegistrationId) || arm.SourceIdentity != sourceIdentity ||
                !Text(arm.ClockAuthority) || !Text(arm.ClockEpoch) || !Utc(arm.ArmedAt) ||
                arm.Cursor < 0 || !Text(arm.PolicyWitness) || !arm.CaptureArmed)
                throw Unavailable();
            session.Arm = arm;
            session.Sequence = arm.Cursor;
            return arm;
        }
        finally { Release(session); }
    }

    public async ValueTask<AuthenticationExpiryFence> CompleteAsync(AuthenticationExpiryArm arm,
        DispatchEvidence receipt, CancellationToken token)
    {
        if (arm?.Attempt is null) throw Unavailable();
        Session session = Acquire(arm.Attempt);
        try
        {
            if (!ReferenceEquals(session.Arm, arm) || session.CompletionStarted ||
                receipt != DispatchEvidence.Applied) throw Unavailable();
            // No replay, including after a committed operation loses its reply.
            session.CompletionStarted = true;
            AuthenticationExpiryFence binding = await channel.PostAsync<AuthenticationExpiryFence>(
                "authentication-expiry/complete", writer =>
                {
                    Write(writer, "arm", arm);
                    Write(writer, "receipt", receipt);
                }, token);
            if (!ValidFence(binding, arm)) throw Unavailable();
            session.Binding = binding;
            session.Sequence = binding.Sequence;
            return binding;
        }
        finally { Release(session); }
    }

    public async ValueTask<AuthenticationExpiryObservation<T>> ObserveAsync<T>(AuthenticationExpiryFence binding,
        AuthenticationExpiryPhase phase, Func<CancellationToken, ValueTask<T>> sample, CancellationToken token)
    {
        if (binding?.Arm?.Attempt is null) throw Unavailable();
        Session session = Acquire(binding.Arm.Attempt);
        try
        {
            if (!ReferenceEquals(session.Binding, binding) || sample is null || !Enum.IsDefined(phase) ||
                session.Failed || (int)phase != session.NextPhase) throw Unavailable();
            // Consume before dispatch so lost opens cannot be replayed.
            session.NextPhase++;
            AuthenticationExpiryWindow opened = await channel.PostAsync<AuthenticationExpiryWindow>(
                "authentication-expiry/open", writer =>
                {
                    Write(writer, "binding", binding);
                    Write(writer, "phase", phase);
                    writer.WriteNumber("priorSequence", session.Sequence);
                }, token);
            AuthenticationExpiryWindow closed;
            T sampled;
            try
            {
                if (!ValidWindow(opened, binding, phase) || opened.Sequence <= session.Sequence ||
                    opened.ClosedAt != opened.OpenedAt || opened.OpenedAt < session.LastClosedAt ||
                    !session.WindowIds.Add(opened.WindowId) || !session.EventIds.Add(opened.EventId))
                    throw Unavailable();
                session.Sequence = opened.Sequence;
                token.ThrowIfCancellationRequested();
                // Actual SDK access stays local, once, for the entire source window.
                sampled = await sample(token);
            }
            finally
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                try
                {
                    closed = await Post<AuthenticationExpiryWindow>("close-window", "window", opened, cleanup.Token);
                    if (!ValidWindow(closed, binding, phase) || closed.WindowId != opened.WindowId ||
                        closed.EventId != opened.EventId || closed.OpenedAt != opened.OpenedAt ||
                        closed.Sequence <= Math.Max(session.Sequence, opened.Sequence) ||
                        closed.ClosedAt < closed.OpenedAt)
                        throw new NativeCaseFailureException("cleanup-incomplete");
                    session.Sequence = closed.Sequence;
                    session.LastClosedAt = closed.ClosedAt;
                }
                catch (Exception error) when (error is NativeCaseFailureException or OperationCanceledException)
                { throw new NativeCaseFailureException("cleanup-incomplete"); }
            }
            return new(closed, sampled);
        }
        catch
        {
            session.Failed = true;
            throw;
        }
        finally { Release(session); }
    }

    public async ValueTask<AuthenticationExpiryCleanup> CloseAsync(AuthenticationExpiryAttempt attempt,
        CancellationToken token)
    {
        Session session = Acquire(attempt);
        try
        {
            // Original attempt remains pinned even after lost Arm/Complete replies.
            // Caller cancellation does not cancel this independently bounded cleanup.
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            AuthenticationExpiryCleanup facts;
            try { facts = await Post<AuthenticationExpiryCleanup>("close", "attempt", session.Attempt, cleanup.Token); }
            catch (Exception error) when (error is NativeCaseFailureException or OperationCanceledException)
            { throw new NativeCaseFailureException("cleanup-incomplete"); }
            if (facts.Attempt != session.Attempt || !facts.Closed || !facts.LateCreationFenced ||
                !facts.MutationSettled || !facts.InventoryComplete || !facts.CorrelationKeyDestroyed ||
                facts.RemainingRegistrations != 0 || facts.PendingDeliveries != 0)
                throw new NativeCaseFailureException("cleanup-incomplete");
            session.Closed = true;
            return facts;
        }
        finally { Release(session); }
    }

    private bool ValidAttempt(AuthenticationExpiryAttempt attempt) =>
        attempt is not null && Text(attempt.Id) && Text(attempt.CaseIdentity) && Text(attempt.DeploymentId) &&
        attempt.ProviderVersion == "v0.166.3" && Id(attempt.OrganizationId) && Id(attempt.IdentityId) &&
        attempt.Source == source && Text(attempt.AuthenticationMethod) && ValidPolicy(attempt.Policy) &&
        Positive(attempt.ExpectedExpiresIn) && Nonnegative(attempt.ExpectedReportedMaximumTtl) &&
        (attempt.Operation == InfisicalUniversalAuthenticationEffects.Operation &&
            attempt.Member == InfisicalUniversalAuthenticationEffects.Member &&
            attempt.AuthenticationMethod == "universal-auth" ||
            attempt.Operation == InfisicalProofAuthenticationEffects.Operation &&
            attempt.Member == InfisicalProofAuthenticationEffects.Member &&
            attempt.AuthenticationMethod is "alicloud-auth" or "aws-auth" or "azure-auth" or "gcp-auth" or
                "jwt-auth" or "kubernetes-auth" or "oidc-auth" or "spiffe-auth" or "ldap-auth" or "oci-auth" or "tls-cert-auth");

    private static bool ValidFence(AuthenticationExpiryFence binding, AuthenticationExpiryArm arm) =>
        binding is not null && binding.Arm == arm && Utc(binding.Arm.ArmedAt) &&
        binding.Disposition == DispatchEvidence.Applied &&
        Text(binding.ProviderRequestId) && Id(binding.TokenMetadataId) && Text(binding.CredentialHandle) &&
        Witness(binding.CredentialWitness) && binding.ObservedPolicy == arm.Attempt.Policy &&
        Positive(binding.ResponseExpiresIn) && Nonnegative(binding.ResponseMaximumTtl) &&
        binding.ResponseExpiresIn == arm.Attempt.ExpectedExpiresIn &&
        binding.ResponseMaximumTtl == arm.Attempt.ExpectedReportedMaximumTtl &&
        Utc(binding.IssuedAt) && Utc(binding.ExpiresAt) && binding.IssuedAt >= arm.ArmedAt &&
        binding.ExpiresAt > binding.IssuedAt && binding.Sequence > arm.Cursor &&
        binding.MatchedIssuances == 1 && binding.IssueEventObserved &&
        binding.NativeScheduleObserved && binding.ExcludesLateCommit;

    private static bool ValidWindow(AuthenticationExpiryWindow window, AuthenticationExpiryFence binding,
        AuthenticationExpiryPhase phase) =>
        window is not null && window.Binding == binding && ValidFence(window.Binding, binding.Arm) && window.Phase == phase &&
        Text(window.WindowId) && Text(window.EventId) && window.Authoritative && window.EventObserved &&
        window.NaturalExpiryObserved == (phase == AuthenticationExpiryPhase.Expired) &&
        window.PolicyUnchanged && window.IpPathUnchanged && window.NoRenewal && window.NoRevocation &&
        window.UseLimitNotExhausted && Utc(window.OpenedAt) && Utc(window.ClosedAt) &&
        InPhase(window.OpenedAt, binding, phase) && InPhase(window.ClosedAt, binding, phase);

    private static bool InPhase(DateTimeOffset time, AuthenticationExpiryFence binding, AuthenticationExpiryPhase phase) =>
        phase switch
        {
            AuthenticationExpiryPhase.Active => time >= binding.IssuedAt && time < binding.ExpiresAt,
            AuthenticationExpiryPhase.Expired => time >= binding.ExpiresAt,
            _ => false
        };

    private Session Acquire(AuthenticationExpiryAttempt attempt)
    {
        lock (sessions)
        {
            if (attempt is null || !Text(attempt.Id) || !sessions.TryGetValue(attempt.Id, out Session? session) ||
                session.Attempt != attempt || session.Busy || session.Closed) throw Unavailable();
            session.Busy = true;
            return session;
        }
    }

    private void Release(Session session)
    {
        lock (sessions) session.Busy = false;
    }

    private ValueTask<T> Post<T>(string route, string name, object value, CancellationToken token) where T : notnull =>
        channel.PostAsync<T>("authentication-expiry/" + route, writer => Write(writer, name, value), token);

    private static void Write(Utf8JsonWriter writer, string name, object value)
    {
        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, InfisicalLifecycleFamilies.Options);
    }

    private static bool Text(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
    private static bool Id(string? value) => Text(value) && Guid.TryParseExact(value, "D", out Guid id) && id != Guid.Empty;
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static bool Nonnegative(double value) => double.IsFinite(value) && value >= 0;
    private static bool Positive(double value) => double.IsFinite(value) && value > 0;
    private static bool ValidPolicy(AuthenticationExpiryPolicy? policy) => policy is not null &&
        Nonnegative(policy.Ttl) && Nonnegative(policy.MaximumTtl) && Nonnegative(policy.Period) && Nonnegative(policy.MaximumUses);
    private static bool Witness(string? value)
    {
        Span<byte> bytes = stackalloc byte[32];
        return value is { Length: 44 } && Convert.TryFromBase64String(value, bytes, out int count) && count == 32;
    }
    private static NativeCaseFailureException Unavailable() => new("observer-unavailable");
    public override string ToString() => "[InfisicalAuthenticationExpiryObserver]";

    private sealed class Session(AuthenticationExpiryAttempt attempt)
    {
        internal AuthenticationExpiryAttempt Attempt { get; } = attempt;
        internal AuthenticationExpiryArm? Arm { get; set; }
        internal AuthenticationExpiryFence? Binding { get; set; }
        internal long Sequence { get; set; }
        internal DateTimeOffset LastClosedAt { get; set; }
        internal int NextPhase { get; set; }
        internal bool CompletionStarted { get; set; }
        internal bool Failed { get; set; }
        internal bool Busy { get; set; }
        internal bool Closed { get; set; }
        internal HashSet<string> WindowIds { get; } = new(StringComparer.Ordinal);
        internal HashSet<string> EventIds { get; } = new(StringComparer.Ordinal);
        public override string ToString() => "[AuthenticationExpirySession]";
    }
}
