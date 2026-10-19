using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Native-source client, not an implementation of the provider's private journal.
internal sealed class InfisicalProxyPatchObserver(InfisicalLifecycleObservers channel,
    string identity, ProxyPatchSource source = ProxyPatchSource.NativeProvider) : IProxyPatchObserver
{
    private readonly Dictionary<string, Session> sessions = new(StringComparer.Ordinal);
    private readonly HashSet<string> roots = new(StringComparer.Ordinal);
    private readonly HashSet<string> registrations = new(StringComparer.Ordinal);
    private readonly HashSet<string> events = new(StringComparer.Ordinal);
    private readonly HashSet<string> requests = new(StringComparer.Ordinal);
    private readonly HashSet<string> attempts = new(StringComparer.Ordinal);
    private bool busy;

    internal static InfisicalProxyPatchObserver? FromInputs(NativeEnvironment env)
    {
        const string family = "C08-IM-ProxiedServiceAdministration";
        var input = env.RequireFamilyInput(family);
        if (!input.TryGetProperty("observer", out var settings)) return null;
        Require(settings.ValueKind == JsonValueKind.Object &&
            (!settings.TryGetProperty("source", out var selected) ||
                selected.ValueKind == JsonValueKind.String && selected.GetString() == "NativeProvider" ||
                selected.ValueKind == JsonValueKind.Number && selected.TryGetInt32(out int code) && code == 0),
            "missing-input");
        try
        {
            string label = settings.GetProperty("identity").GetString()!;
            var endpoint = new Uri(settings.GetProperty("endpoint").GetString()!, UriKind.Absolute);
            var credential = settings.GetProperty("token").GetString()!;
            int seconds = settings.GetProperty("timeoutSeconds").GetInt32();
            Require(Text(label), "missing-input");
            return new(new(new(endpoint, credential, label, seconds)), label);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or ArgumentException or KeyNotFoundException)
        { throw new NativeCaseFailureException("missing-input"); }
    }

    public async ValueTask<ProxyPatchBinding> OpenAsync(ProxyPatchRootAttempt attempt, CancellationToken token)
    {
        Require(channel is not null && Text(identity) && Enum.IsDefined(source) &&
            identity is not ("setup" or "runtime" or "denied" or "administrative" or "observer") &&
            Text(attempt.Id) && Text(attempt.CaseIdentity) && attempt.ProviderVersion == "v0.166.3" &&
            Text(attempt.DeploymentId) && Text(attempt.SourceProfile) && Text(attempt.RootNonce) &&
            Text(attempt.OrganizationId) && Text(attempt.ProjectId) && Text(attempt.Environment) &&
            Text(attempt.OriginalName) && Text(attempt.Renamed) && attempt.OriginalName != attempt.Renamed &&
            attempt.Source == source && (source == ProxyPatchSource.ControlledFixture) ==
                (attempt.SourceProfile == "controlled-fixture"), "missing-input");
        Session session;
        lock (sessions)
        {
            Require(!busy && !sessions.ContainsKey(attempt.Id) && roots.Add(attempt.RootNonce));
            session = new(attempt);
            sessions.Add(attempt.Id, session);
            busy = true;
        }
        try
        {
            var facts = await Post<ProxyPatchBinding>(session, "open", writer => Write(writer, "attempt", attempt), token);
            Require(facts.Attempt == attempt && Unique(registrations, facts.RegistrationId) &&
                facts.SourceIdentity == identity && facts.ClockAuthority == "provider-application-clock" &&
                Text(facts.ClockEpoch) && Utc(facts.OpenedAt) && facts.Sequence >= 0 &&
                facts.RootInitiallyAbsent && facts.OwnedRootCreated && facts.IndependentStorageQualified &&
                facts.ReferenceValidationQualified && facts.RuntimeDeliveryQualified &&
                facts.DistinctContrasts && facts.BorrowedStatePreserved);
            session.Binding = facts with { Attempt = attempt };
            session.Sequence = facts.Sequence;
            session.Time = facts.OpenedAt;
            session.Unsettled = false;
            return session.Binding;
        }
        finally { Release(); }
    }

    public async ValueTask<ProxyPatchArm> ArmAsync(ProxyPatchBinding binding, string attemptId, string operation,
        string variant, string boundary, string? serviceId, CancellationToken token)
    {
        var session = Acquire(binding);
        try
        {
            Require(session.Arm is null && Text(attemptId) && Unique(attempts, attemptId) &&
                operation is "Create" or "Update" && Text(variant) && Text(boundary) &&
                (operation == "Create" ? serviceId is null : Text(serviceId)));
            var facts = await Post<ProxyPatchArm>(session, "arm", writer =>
            {
                Write(writer, "binding", binding);
                writer.WriteString("attemptId", attemptId);
                writer.WriteString("operation", operation);
                writer.WriteString("variant", variant);
                writer.WriteString("case", boundary);
                writer.WriteString("serviceId", serviceId);
            }, token);
            Require(facts.Binding == binding && facts.AttemptId == attemptId &&
                facts.Operation == operation && facts.Variant == variant && facts.Case == boundary &&
                facts.ServiceId == serviceId && Unique(registrations, facts.RegistrationId) &&
                facts.CaptureArmed && session.Next(facts.Cursor, facts.ArmedAt));
            session.Arm = facts with { Binding = binding };
            session.Fence = null;
            session.Observed = false;
            session.Unsettled = false;
            return session.Arm;
        }
        finally { Release(); }
    }

    public async ValueTask<ProxyPatchFence> CompleteAsync(ProxyPatchArm arm, DispatchEvidence receipt, CancellationToken token)
    {
        var session = Acquire(arm.Binding);
        try
        {
            Require(ReferenceEquals(session.Arm, arm));
            session.Arm = null;
            var facts = await Post<ProxyPatchFence>(session, "complete", writer =>
            {
                Write(writer, "arm", arm);
                Write(writer, "receipt", receipt);
            }, token);
            Require(facts.Arm == arm && facts.Disposition == receipt && Unique(events, facts.EventId) &&
                Text(facts.ServiceId) && (arm.ServiceId is null || arm.ServiceId == facts.ServiceId) &&
                session.Next(facts.Sequence, facts.SettledAt) && facts.OriginalAttemptSettled &&
                facts.ExcludesLateCommit);
            Require(facts.NoReplay && facts.PendingValidationActions == 0 &&
                (receipt == DispatchEvidence.PossiblyDispatched ?
                    facts.MatchedRequests is >= 0 and <= 1 && (!facts.Applied || facts.MatchedRequests == 1) :
                    facts.MatchedRequests == (receipt == DispatchEvidence.NotDispatched ? 0 : 1)) &&
                facts.MatchedCommits == (facts.Applied ? 1 : 0) &&
                !(receipt is DispatchEvidence.NotDispatched or DispatchEvidence.Rejected && facts.Applied) &&
                (receipt != DispatchEvidence.Applied || facts.Applied) &&
                (!facts.Applied || facts.OriginalReferencesValidated), "effect-mismatch");
            Require(facts.MatchedRequests == 0 ? facts.ProviderRequestId is null : Unique(requests, facts.ProviderRequestId));
            session.Fence = facts with { Arm = arm };
            session.Unsettled = false;
            return session.Fence;
        }
        finally { Release(); }
    }

    public async ValueTask<ProxyPatchObservation> ObserveAsync(ProxyPatchBinding binding, ProxyPatchFence fence, CancellationToken token)
    {
        var session = Acquire(binding);
        try
        {
            Require(ReferenceEquals(fence, session.Fence) && session.Arm is null && !session.Observed);
            var facts = await Post<ProxyPatchObservation>(session, "observe", writer =>
            {
                Write(writer, "binding", binding);
                Write(writer, "fence", fence);
            }, token);
            Require(facts.Binding == binding && facts.ServiceId == fence.ServiceId &&
                facts.Phase == fence.Arm.AttemptId && Unique(events, facts.EventId) &&
                session.Next(facts.Sequence, facts.ObservedAt));
            Require(facts.IndependentStorageRead && facts.ExactCredentialRowsMatch &&
                facts.SuppliedRowOptionalsMatch && facts.OmittedArrayRetained && facts.RemovedRowAbsent &&
                facts.RuntimeSubstitutionMatches && facts.WrongValueRejected && facts.DeniedDeliveryAbsent &&
                facts.ReferenceAuthorityMatches && facts.BorrowedStatePreserved, "effect-mismatch");
            session.Observed = true;
            session.Unsettled = false;
            return facts;
        }
        finally { Release(); }
    }

    public async ValueTask<ProxyPatchCleanup> CloseAsync(ProxyPatchRootAttempt attempt, CancellationToken token)
    {
        var session = Acquire(attempt, cleanup: true);
        session.Closed = true;
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var facts = await Post<ProxyPatchCleanup>(session, "close",
                writer => Write(writer, "attempt", attempt), deadline.Token);
            Require(facts.Attempt == attempt && facts.Closed && facts.OwnedRootRemoved &&
                facts.OwnedReferencesRemoved && facts.ServicesAbsent && facts.BorrowedStatePreserved &&
                facts.PrivateCopiesDestroyed && facts.OriginalAttemptsSettled && facts.LateCreationFenced &&
                facts.RemainingRegistrations == 0 && facts.PendingDeliveries == 0, "cleanup-incomplete");
            return facts;
        }
        catch (Exception error) when (error is NativeCaseFailureException or OperationCanceledException)
        { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { Release(); }
    }

    private Session Acquire(ProxyPatchBinding binding)
    {
        var session = Acquire(binding.Attempt);
        if (ReferenceEquals(session.Binding, binding)) return session;
        Release();
        throw new NativeCaseFailureException("observer-unavailable");
    }
    private Session Acquire(ProxyPatchRootAttempt attempt, bool cleanup = false)
    {
        lock (sessions)
        {
            Require(sessions.TryGetValue(attempt.Id, out var session) &&
                ReferenceEquals(session.Attempt, attempt) && !busy && !session.Closed &&
                (cleanup || !session.Unsettled && session.Binding is not null));
            busy = true;
            return session!;
        }
    }
    private ValueTask<T> Post<T>(Session session, string command, Action<Utf8JsonWriter> fields,
        CancellationToken token) where T : notnull
    {
        session.Unsettled = true;
        return channel.PostAsync<T>("proxy-patch/" + command, fields, token);
    }
    private void Release() { lock (sessions) busy = false; }
    private static void Write(Utf8JsonWriter writer, string name, object value)
    {
        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, InfisicalLifecycleFamilies.Options);
    }
    private static bool Text(string? value) => value is { Length: > 0 and <= 512 } &&
        !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static bool Unique(HashSet<string> values, string? value) => Text(value) && values.Add(value!);
    private static void Require([DoesNotReturnIf(false)] bool condition, string code = "observer-unavailable")
    {
        if (!condition) throw new NativeCaseFailureException(code);
    }
    public override string ToString() => "[InfisicalProxyPatchObserver]";
    private sealed class Session(ProxyPatchRootAttempt attempt)
    {
        internal ProxyPatchRootAttempt Attempt { get; } = attempt;
        internal ProxyPatchBinding? Binding { get; set; }
        internal ProxyPatchArm? Arm { get; set; }
        internal ProxyPatchFence? Fence { get; set; }
        internal long Sequence { get; set; }
        internal DateTimeOffset Time { get; set; }
        internal bool Unsettled { get; set; } = true;
        internal bool Observed { get; set; }
        internal bool Closed { get; set; }
        internal bool Next(long sequence, DateTimeOffset time)
        {
            if (sequence <= Sequence || !Utc(time) || time < Time) return false;
            Sequence = sequence;
            Time = time;
            return true;
        }
    }
}
