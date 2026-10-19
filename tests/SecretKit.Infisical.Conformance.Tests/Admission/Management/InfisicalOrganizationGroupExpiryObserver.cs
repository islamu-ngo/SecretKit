using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Witnesses authenticated provider context and brackets local SDK reads; it
// neither dispatches mutations nor certifies a selected metadata policy.
internal sealed class InfisicalOrganizationGroupExpiryObserver : IOrganizationGroupExpiryObserver
{
    private readonly InfisicalLifecycleObservers channel;
    private readonly string sourceIdentity;
    private readonly MembershipExpirySource source;
    private readonly Dictionary<string, Session> sessions = new(StringComparer.Ordinal);

    internal InfisicalOrganizationGroupExpiryObserver(InfisicalLifecycleObservers channel, string sourceIdentity,
        MembershipExpirySource source = MembershipExpirySource.NativeProvider)
    {
        if (!Text(sourceIdentity) || !Enum.IsDefined(source))
            throw new NativeCaseFailureException("missing-input");
        this.channel = channel;
        this.sourceIdentity = sourceIdentity;
        this.source = source;
    }

    internal static InfisicalOrganizationGroupExpiryObserver? FromInputs(NativeEnvironment environment, string family)
    {
        JsonElement input = environment.RequireFamilyInput(family);
        if (!input.TryGetProperty("observer", out JsonElement settings)) return null;
        // Controlled authority is available only through an explicit constructor.
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

    public async ValueTask<OrganizationGroupExpiryArm> ArmAsync(OrganizationGroupExpiryIntent intent, CancellationToken token)
    {
        if (!ValidIntent(intent)) throw new NativeCaseFailureException("missing-input");
        var session = new Session(intent) { Busy = true };
        lock (sessions)
        {
            if (!sessions.TryAdd(intent.Attempt.Id, session)) throw Unavailable();
        }
        try
        {
            OrganizationGroupExpiryArm arm = await Post<OrganizationGroupExpiryArm>("arm", "intent", intent, token);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (arm.Intent != intent || !Text(arm.RegistrationId) || arm.SourceIdentity != sourceIdentity ||
                !Text(arm.ClockAuthority) || !Text(arm.ClockEpoch) || !Utc(arm.ArmedAt) ||
                !Utc(arm.StartsAt) || !Utc(arm.EndsAt) || arm.StartsAt <= arm.ArmedAt ||
                arm.StartsAt - arm.ArmedAt != TimeSpan.FromSeconds(intent.ActivationLeadSeconds) ||
                arm.EndsAt - arm.StartsAt != TimeSpan.FromSeconds(60) || arm.Cursor < 0 || !arm.CaptureArmed ||
                !arm.AuthenticatedScopesObserved || arm.ObservedScopes != intent.Attempt.Scopes ||
                source == MembershipExpirySource.NativeProvider &&
                (arm.StartsAt <= now || arm.ArmedAt > now.AddSeconds(30) || arm.ArmedAt < now.AddSeconds(-30)))
                throw Unavailable();
            session.Arm = arm;
            session.Sequence = arm.Cursor;
            return arm;
        }
        finally { Release(session); }
    }

    public async ValueTask<OrganizationGroupExpiryFence> CompleteAsync(OrganizationGroupExpiryArm arm, CancellationToken token)
    {
        if (arm?.Intent?.Attempt is null) throw Unavailable();
        Session session = Acquire(arm.Intent.Attempt);
        try
        {
            if (session.Arm != arm || !Utc(arm.ArmedAt) || !Utc(arm.StartsAt) || !Utc(arm.EndsAt) ||
                session.Binding is not null) throw Unavailable();
            OrganizationGroupExpiryFence binding = await Post<OrganizationGroupExpiryFence>("complete", "arm", session.Arm, token);
            if (!ValidFence(binding, arm) || binding.Disposition == MembershipExpiryDisposition.NotDispatched)
                throw Unavailable();
            session.Binding = binding;
            session.Sequence = binding.Sequence;
            return binding;
        }
        finally { Release(session); }
    }

    public async ValueTask<OrganizationGroupExpiryObservation<T>> ObserveAsync<T>(OrganizationGroupExpiryFence binding,
        MembershipExpiryPhase phase, Func<CancellationToken, ValueTask<T>> sample, CancellationToken token)
    {
        if (binding?.Arm?.Intent?.Attempt is null) throw Unavailable();
        Session session = Acquire(binding.Arm.Intent.Attempt);
        try
        {
            if (sample is null || !Enum.IsDefined(phase) || (int)phase != session.NextPhase ||
                session.Arm != binding.Arm || !ValidFence(binding, session.Arm)) throw Unavailable();
            if (session.Binding is null)
            {
                // The parent supplies the actual pre-send token-barrier receipt.
                // /complete is never permitted to manufacture NotDispatched.
                if (binding.Disposition != MembershipExpiryDisposition.NotDispatched ||
                    !ValidFence(binding, session.Arm)) throw Unavailable();
                session.Binding = binding;
                session.Sequence = binding.Sequence;
            }
            if (session.Binding != binding) throw Unavailable();
            OrganizationGroupExpiryWindow opened = await channel.PostAsync<OrganizationGroupExpiryWindow>(
                "organization-group-expiry/open", writer =>
                {
                    Write(writer, "binding", session.Binding);
                    writer.WriteNumber("phase", (int)phase);
                    writer.WriteNumber("priorSequence", session.Sequence);
                }, token);
            OrganizationGroupExpiryWindow closed;
            T sampled;
            try
            {
                if (!ValidWindow(opened, binding, phase) || opened.Sequence <= session.Sequence ||
                    opened.ClosedAt != opened.OpenedAt || !session.WindowIds.Add(opened.WindowId) ||
                    !session.EventIds.Add(opened.EventId)) throw Unavailable();
                session.Sequence = opened.Sequence;
                session.NextPhase++;
                token.ThrowIfCancellationRequested();
                sampled = await sample(token);
            }
            finally
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                try
                {
                    closed = await Post<OrganizationGroupExpiryWindow>("close-window", "window", opened, cleanup.Token);
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

    public async ValueTask<OrganizationGroupExpiryCleanup> CloseAsync(OrganizationGroupExpiryAttempt attempt, CancellationToken token)
    {
        Session session = Acquire(attempt);
        try
        {
            // Retain the original attempt even if /arm committed and lost its reply.
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            OrganizationGroupExpiryCleanup facts;
            try { facts = await Post<OrganizationGroupExpiryCleanup>("close", "attempt", session.Intent.Attempt, cleanup.Token); }
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

    private bool ValidIntent(OrganizationGroupExpiryIntent intent) =>
        intent is not null && intent.Attempt is { } attempt && Text(attempt.Id) && Text(attempt.CaseIdentity) &&
        attempt.ProviderVersion == "v0.166.3" && ValidScopes(attempt.Scopes) && Id(attempt.GroupId) &&
        Text(attempt.OwnerMembershipId) && Text(attempt.RuntimeLinkId) && Text(attempt.RoleId) && Text(attempt.RoleSlug) &&
        (attempt.Operation switch
        {
            "i.management.MembershipOperations.AddOrganizationGroup" => attempt.ExistingTargetMembershipId is null,
            "i.management.MembershipOperations.UpdateOrganizationGroupRoles" =>
                Text(attempt.ExistingTargetMembershipId) && !SameId(attempt.ExistingTargetMembershipId, attempt.OwnerMembershipId),
            _ => false
        }) &&
        attempt.Source == source && Enum.IsDefined(attempt.ExpiredMetadata) &&
        intent.RelativeDuration == "1m" && intent.ActivationLeadSeconds is > 0 and <= 300;

    private static bool ValidScopes(OrganizationGroupExpiryScopes? scopes)
    {
        if (scopes is null || !Id(scopes.OwnerOrganizationId) || !Id(scopes.TargetOrganizationId) ||
            SameId(scopes.OwnerOrganizationId, scopes.TargetOrganizationId)) return false;
        string[] principals = [scopes.OwnerSetupIdentityId, scopes.OwnerObserverIdentityId,
            scopes.TargetSetupIdentityId, scopes.TargetAdministrativeIdentityId, scopes.TargetObserverIdentityId,
            scopes.TargetRuntimeIdentityId, scopes.TargetDeniedIdentityId];
        return principals.All(Id) && principals.Select(Guid.Parse).Distinct().Count() == 7;
    }

    private static bool ValidFence(OrganizationGroupExpiryFence binding, OrganizationGroupExpiryArm arm)
    {
        if (binding.Arm != arm || !Utc(binding.Arm.ArmedAt) || !Utc(binding.Arm.StartsAt) || !Utc(binding.Arm.EndsAt) ||
            binding.Sequence <= arm.Cursor || !binding.ExcludesLateCommit || !Enum.IsDefined(binding.Disposition))
            return false;
        OrganizationGroupExpiryAttempt attempt = arm.Intent.Attempt;
        string? existing = attempt.ExistingTargetMembershipId;
        if (binding.TargetMembershipId is not null && SameId(binding.TargetMembershipId, attempt.OwnerMembershipId))
            return false;
        return binding.Disposition switch
        {
            MembershipExpiryDisposition.Applied => Text(binding.ProviderRequestId) && Text(binding.TargetMembershipId) &&
                (existing is null || binding.TargetMembershipId == existing) && Text(binding.TemporaryAssignmentId) &&
                binding.MutationOrganizationId == attempt.Scopes.TargetOrganizationId &&
                binding.MutationIdentityId == attempt.Scopes.TargetAdministrativeIdentityId,
            MembershipExpiryDisposition.Rejected => Text(binding.ProviderRequestId) &&
                binding.TargetMembershipId == existing && binding.TemporaryAssignmentId is null &&
                binding.MutationOrganizationId == attempt.Scopes.TargetOrganizationId &&
                binding.MutationIdentityId == attempt.Scopes.TargetDeniedIdentityId,
            MembershipExpiryDisposition.NotDispatched => binding.ProviderRequestId is null &&
                binding.TargetMembershipId == existing && binding.TemporaryAssignmentId is null &&
                binding.MutationOrganizationId is null && binding.MutationIdentityId is null,
            _ => false
        };
    }

    private static bool ValidWindow(OrganizationGroupExpiryWindow window, OrganizationGroupExpiryFence binding,
        MembershipExpiryPhase phase) =>
        window.Binding == binding && ValidFence(window.Binding, binding.Arm) && window.Phase == phase &&
        Text(window.WindowId) && Text(window.EventId) && window.Authoritative && window.EventObserved &&
        window.RuntimeOrganizationId == binding.Arm.Intent.Attempt.Scopes.TargetOrganizationId &&
        window.RuntimeIdentityId == binding.Arm.Intent.Attempt.Scopes.TargetRuntimeIdentityId &&
        Utc(window.OpenedAt) && Utc(window.ClosedAt) &&
        InPhase(window.OpenedAt, binding.Arm, phase) && InPhase(window.ClosedAt, binding.Arm, phase);

    private static bool InPhase(DateTimeOffset time, OrganizationGroupExpiryArm arm, MembershipExpiryPhase phase) =>
        phase switch
        {
            MembershipExpiryPhase.BeforeActivation => time >= arm.ArmedAt && time < arm.StartsAt,
            MembershipExpiryPhase.Active => time >= arm.StartsAt && time < arm.EndsAt,
            MembershipExpiryPhase.Expired => time >= arm.EndsAt,
            _ => false
        };

    private Session Acquire(OrganizationGroupExpiryAttempt attempt)
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
        channel.PostAsync<T>("organization-group-expiry/" + route, writer => Write(writer, name, value), token);

    private static void Write(Utf8JsonWriter writer, string name, object value)
    {
        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, InfisicalLifecycleFamilies.Options);
    }

    private static bool Text(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
    private static bool Id(string? value) => Text(value) && Guid.TryParse(value, out Guid id) && id != Guid.Empty;
    private static bool SameId(string? left, string? right) => left == right ||
        Guid.TryParse(left, out Guid a) && Guid.TryParse(right, out Guid b) && a == b;
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static NativeCaseFailureException Unavailable() => new("observer-unavailable");
    public override string ToString() => "[InfisicalOrganizationGroupExpiryObserver]";

    private sealed class Session(OrganizationGroupExpiryIntent intent)
    {
        internal OrganizationGroupExpiryIntent Intent { get; } = intent;
        internal OrganizationGroupExpiryArm? Arm { get; set; }
        internal OrganizationGroupExpiryFence? Binding { get; set; }
        internal long Sequence { get; set; }
        internal int NextPhase { get; set; }
        internal bool Busy { get; set; }
        internal bool Closed { get; set; }
        internal HashSet<string> WindowIds { get; } = new(StringComparer.Ordinal);
        internal HashSet<string> EventIds { get; } = new(StringComparer.Ordinal);
        public override string ToString() => "[OrganizationGroupExpirySession]";
    }
}
