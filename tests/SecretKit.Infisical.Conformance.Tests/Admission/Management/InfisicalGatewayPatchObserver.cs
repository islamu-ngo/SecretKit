using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Channel authentication and original-object ownership are independent of facts.
internal sealed class InfisicalGatewayPatchObserver(InfisicalLifecycleObservers channel,
    string identity, GatewayPatchSource source = GatewayPatchSource.NativeProvider) : IGatewayPatchObserver
{
    private readonly Dictionary<string, GatewayPatchSessionObserver> sessions = [];
    private readonly HashSet<string> roots = [];

    internal static InfisicalGatewayPatchObserver? FromInputs(NativeEnvironment env)
    {
        var input = env.RequireFamilyInput("C08-IM-GatewayAdministration");
        if (!input.TryGetProperty("gatewayPatchObserver", out var settings)) return null;
        try
        {
            var config = settings.Deserialize<InfisicalLifecycleObservers.Settings>(InfisicalLifecycleFamilies.Options);
            if (config is null) throw new NativeCaseFailureException("missing-input");
            return new(new(config), config.Identity);
        }
        catch (JsonException) { throw new NativeCaseFailureException("missing-input"); }
    }
    public ValueTask<GatewayPatchBinding> OpenAsync(GatewayPatchRootAttempt attempt,
        GatewayPatchAuthenticationInput baseline, GatewayPatchAuthenticationInput selected, CancellationToken token)
    {
        GatewayPatchSessionObserver session;
        lock (sessions)
        {
            if (sessions.ContainsKey(attempt.Id) || !roots.Add(attempt.RootNonce))
                throw new NativeCaseFailureException("observer-unavailable");
            session = new(channel, identity, source);
            sessions.Add(attempt.Id, session);
        }
        return session.OpenAsync(attempt, baseline, selected, token);
    }
    public ValueTask<GatewayPatchArm> ArmAsync(GatewayPatchBinding binding, string attemptId, string operation,
        string variant, string boundary, string? id, CancellationToken token) =>
        Get(binding.Attempt).ArmAsync(binding, attemptId, operation, variant, boundary, id, token);
    public ValueTask<GatewayPatchFence> CompleteAsync(GatewayPatchArm arm, DispatchEvidence receipt, CancellationToken token) =>
        Get(arm.Binding.Attempt).CompleteAsync(arm, receipt, token);
    public ValueTask<GatewayPatchObservation> ObserveAsync(GatewayPatchBinding binding, GatewayPatchFence fence, CancellationToken token) =>
        Get(binding.Attempt).ObserveAsync(binding, fence, token);
    public async ValueTask<GatewayPatchCleanup> CloseAsync(GatewayPatchRootAttempt attempt, CancellationToken token)
    {
        var session = Get(attempt);
        try { return await session.CloseAsync(attempt, token); }
        finally { lock (sessions) sessions.Remove(attempt.Id); }
    }
    private GatewayPatchSessionObserver Get(GatewayPatchRootAttempt attempt)
    {
        lock (sessions)
            return sessions.GetValueOrDefault(attempt.Id) ?? throw new NativeCaseFailureException("observer-unavailable");
    }
}

internal sealed class GatewayPatchSessionObserver(InfisicalLifecycleObservers channel,
    string identity, GatewayPatchSource source) : IGatewayPatchObserver
{
    private GatewayPatchRootAttempt? root;
    private GatewayPatchBinding? binding;
    private GatewayPatchArm? arm;
    private GatewayPatchFence? fence;
    private bool busy, failed, closed, observed;
    private readonly HashSet<string> registrations = [], events = [], requests = [], attempts = [], roots = [];
    private long sequence;
    private DateTimeOffset time;

    public async ValueTask<GatewayPatchBinding> OpenAsync(GatewayPatchRootAttempt attempt,
        GatewayPatchAuthenticationInput baseline, GatewayPatchAuthenticationInput selected, CancellationToken token)
    {
        Require(root is null && !busy && Text(identity) &&
            identity is not ("setup" or "runtime" or "administrative" or "observer" or "denied") &&
            attempt.Source == source && roots.Add(attempt.RootNonce), "missing-input");
        root = attempt; // Before any channel side effect.
        Enter();
        try
        {
            using var profiles = new GatewayPatchPrivateProfiles(baseline, selected);
            var facts = await channel.PostAsync<GatewayPatchBinding>("gateway-patch/open", writer =>
            { Write(writer, "attempt", attempt); profiles.Write(writer); }, token);
            Require(facts.Attempt == attempt && facts.SourceIdentity == identity &&
                Unique(registrations, facts.RegistrationId) && facts.ClockAuthority == "provider-application-clock" &&
                Text(facts.ClockEpoch) && Utc(facts.OpenedAt) && facts.Sequence >= 0 &&
                facts.RootInitiallyAbsent && facts.OwnedRootCreated && facts.IndependentProtectedStorageQualified &&
                facts.EffectiveAuthenticationQualified && facts.DestinationValidationQualified &&
                facts.DistinctContrasts && facts.BorrowedStatePreserved);
            binding = facts;
            sequence = facts.Sequence; time = facts.OpenedAt;
            failed = false;
            return facts;
        }
        finally { busy = false; }
    }

    public async ValueTask<GatewayPatchArm> ArmAsync(GatewayPatchBinding original, string attemptId,
        string operation, string variant, string boundary, string? id, CancellationToken token)
    {
        Require(ReferenceEquals(original, binding) && !failed && arm is null && Unique(attempts, attemptId));
        Enter();
        try
        {
            var facts = await channel.PostAsync<GatewayPatchArm>("gateway-patch/arm", writer =>
            {
                Write(writer, "binding", original); writer.WriteString("attemptId", attemptId);
                writer.WriteString("operation", operation); writer.WriteString("variant", variant);
                writer.WriteString("case", boundary); writer.WriteString("gatewayId", id);
            }, token);
            Require(facts.Binding == original && facts.AttemptId == attemptId && facts.Operation == operation &&
                facts.Variant == variant && facts.Case == boundary && facts.GatewayId == id && facts.CaptureArmed &&
                Unique(registrations, facts.RegistrationId) && Next(facts.Cursor, facts.ArmedAt));
            arm = facts; fence = null; observed = false; failed = false;
            return facts;
        }
        finally { busy = false; }
    }
    public async ValueTask<GatewayPatchFence> CompleteAsync(GatewayPatchArm original,
        DispatchEvidence receipt, CancellationToken token)
    {
        Require(ReferenceEquals(original, arm) && !failed);
        Enter();
        arm = null;
        try
        {
            var facts = await channel.PostAsync<GatewayPatchFence>("gateway-patch/complete", writer =>
            { Write(writer, "arm", original); Write(writer, "receipt", receipt); }, token);
            bool any = facts.AuthenticationApplied || facts.NameApplied;
            Require(facts.Arm == original && facts.Disposition == receipt && Text(facts.GatewayId) &&
                (original.GatewayId is null || original.GatewayId == facts.GatewayId) &&
                Unique(events, facts.EventId) && Next(facts.Sequence, facts.SettledAt) &&
                facts.OriginalAttemptSettled && facts.ExcludesLateApplication && facts.NoReplay &&
                facts.ValidationActionsTerminal &&
                (receipt == DispatchEvidence.PossiblyDispatched ?
                    facts.MatchedRequests is >= 0 and <= 1 && (!any || facts.MatchedRequests == 1) :
                    facts.MatchedRequests == (receipt == DispatchEvidence.NotDispatched ? 0 : 1)) &&
                !(receipt == DispatchEvidence.NotDispatched && any) &&
                !(receipt == DispatchEvidence.Rejected && facts.NameApplied),
                "effect-mismatch");
            Require(facts.MatchedRequests == 0 ? facts.ProviderRequestId is null : Unique(requests, facts.ProviderRequestId));
            fence = facts; failed = false; return facts;
        }
        finally { busy = false; }
    }
    public async ValueTask<GatewayPatchObservation> ObserveAsync(GatewayPatchBinding original,
        GatewayPatchFence completed, CancellationToken token)
    {
        Require(ReferenceEquals(original, binding) && ReferenceEquals(completed, fence) && !failed && !observed);
        Require(completed.Disposition != DispatchEvidence.Applied ||
            completed.AuthenticationApplied == (completed.Arm.Operation == "Create" ||
                !GatewayPatchEffects.RetainsAuthentication(completed.Arm.Variant)) &&
            completed.NameApplied == (completed.Arm.Operation == "Create" || GatewayPatchEffects.Renames(completed.Arm.Variant)),
            "effect-mismatch");
        Enter();
        observed = true;
        try
        {
            var facts = await channel.PostAsync<GatewayPatchObservation>("gateway-patch/observe", writer =>
            { Write(writer, "binding", original); Write(writer, "fence", completed); }, token);
            Require(facts.Binding == original && facts.GatewayId == completed.GatewayId &&
                facts.Phase == completed.Arm.AttemptId && Unique(events, facts.EventId) &&
                Next(facts.Sequence, facts.ObservedAt));
            Require(facts.IndependentProtectedStorageRead && facts.MethodDefaultsAndOmissionsMatch &&
                facts.ReviewerRetentionOrDropMatches && facts.CaRetentionOrClearMatches && facts.AttachmentsMatch &&
                facts.ExactNameMatches && facts.EffectiveAuthenticationMatches && facts.WrongAuthorityRejected &&
                facts.ActualTokenReviewMatches && facts.BorrowedStatePreserved, "effect-mismatch");
            failed = false; return facts;
        }
        finally { busy = false; }
    }
    public async ValueTask<GatewayPatchCleanup> CloseAsync(GatewayPatchRootAttempt original, CancellationToken token)
    {
        Require(ReferenceEquals(original, root) && !closed);
        Enter();
        closed = true;
        try
        {
            var facts = await channel.PostAsync<GatewayPatchCleanup>("gateway-patch/close",
                writer => Write(writer, "attempt", original), token);
            Require(facts.Attempt == original && facts.Closed && facts.OwnedRootRemoved && facts.GatewaysAbsent &&
                facts.AgentsAndTokensAbsent && facts.PrivateCopiesDestroyed && facts.BorrowedAttachmentsPreserved &&
                facts.OriginalAttemptsSettled && facts.LateCreationFenced && facts.RemainingRegistrations == 0 &&
                facts.PendingDeliveries == 0, "cleanup-incomplete");
            return facts;
        }
        finally { busy = false; }
    }
    private void Enter() { Require(!busy && !closed); busy = true; failed = true; }
    private bool Next(long value, DateTimeOffset captured)
    {
        if (value <= sequence || !Utc(captured) || captured < time) return false;
        sequence = value; time = captured; return true;
    }
    private static void Write(Utf8JsonWriter writer, string name, object value)
    { writer.WritePropertyName(name); JsonSerializer.Serialize(writer, value, InfisicalLifecycleFamilies.Options); }
    private static bool Text(string? value) => value is { Length: > 0 and <= 512 } &&
        !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static bool Unique(HashSet<string> values, string? value) => Text(value) && values.Add(value!);
    private static void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) throw new NativeCaseFailureException(code); }
}
