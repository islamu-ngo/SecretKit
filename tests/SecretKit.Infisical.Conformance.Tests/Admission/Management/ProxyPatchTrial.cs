using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// A direct injected observer is not a trust bypass. The host validates the
// original root and every terminal phase independently of the channel client.
internal sealed class ProxyPatchTrial : IAsyncDisposable
{
    private readonly IProxyPatchObserver source;
    private readonly ProxyPatchRootAttempt root;
    private readonly TimeSpan timeout;
    private readonly HashSet<string> registrations = new(StringComparer.Ordinal);
    private readonly HashSet<string> attempts = new(StringComparer.Ordinal);
    private readonly HashSet<string> events = new(StringComparer.Ordinal);
    private readonly HashSet<string> requests = new(StringComparer.Ordinal);
    private long sequence;
    private DateTimeOffset time;
    private ProxyPatchArm? arm;
    private bool observed;
    private bool unsettled;
    private bool closed;

    private ProxyPatchTrial(IProxyPatchObserver source, ProxyPatchRootAttempt root, int seconds)
    {
        this.source = source;
        this.root = root;
        timeout = TimeSpan.FromSeconds(seconds);
    }
    internal ProxyPatchBinding Binding { get; private set; } = null!;
    internal ProxyPatchFence? Fence { get; private set; }

    internal static async ValueTask<ProxyPatchTrial> OpenAsync(ProjectFamilyContext c,
        string environment, string name, string renamed, IProxyPatchObserver? injected,
        Action<ProxyPatchTrial> retain, CancellationToken token)
    {
        Require(c.Input.TryGetProperty("proxyPatchWitness", out var input), "missing-input");
        ProxyPatchWitnessInput settings;
        try
        {
            settings = input.Deserialize<ProxyPatchWitnessInput>(InfisicalLifecycleFamilies.Options) ??
                throw new NativeCaseFailureException("missing-input");
        }
        catch (JsonException) { throw new NativeCaseFailureException("missing-input"); }
        Require(settings.CaseTimeoutSeconds is >= 1 and <= 900 &&
            Text(settings.DeploymentId) && Text(settings.SourceProfile) && Text(settings.RootNonce), "missing-input");
        bool controlled = settings.SourceProfile == "controlled-fixture";
        Require(injected is null || controlled, "missing-input");
        Require(!controlled || injected is not null);
        var source = injected ?? InfisicalProxyPatchObserver.FromInputs(c.Environment);
        Require(source is not null);
        var root = new ProxyPatchRootAttempt(Guid.NewGuid().ToString("D"),
            c.Definition.Key.Operation + "/" + c.Variant + "/" + c.Definition.Key.Case,
            "v0.166.3", settings.DeploymentId, settings.SourceProfile, settings.RootNonce,
            c.OrganizationId, c.ProjectId, environment, name, renamed,
            controlled ? ProxyPatchSource.ControlledFixture : ProxyPatchSource.NativeProvider);
        var trial = new ProxyPatchTrial(source!, root, settings.CaseTimeoutSeconds);
        // Retain the original root before bootstrap, including a lost Open reply.
        // Its owner closes after context-owned project/resource cleanup.
        retain(trial);
        using var deadline = trial.Deadline(token);
        var facts = await source!.OpenAsync(root, deadline.Token);
        Require(facts.Attempt == root && Unique(trial.registrations, facts.RegistrationId) &&
            Text(facts.SourceIdentity) &&
            facts.SourceIdentity is not ("setup" or "runtime" or "denied" or "administrative" or "observer") &&
            facts.ClockAuthority == "provider-application-clock" && Text(facts.ClockEpoch) &&
            Utc(facts.OpenedAt) && facts.Sequence >= 0 && facts.OwnedRootCreated &&
            facts.RootInitiallyAbsent && facts.DistinctContrasts && facts.IndependentStorageQualified &&
            facts.ReferenceValidationQualified && facts.RuntimeDeliveryQualified && facts.BorrowedStatePreserved);
        trial.Binding = facts;
        trial.sequence = facts.Sequence;
        trial.time = facts.OpenedAt;
        return trial;
    }

    internal async ValueTask ArmAsync(string operation, string variant, string boundary,
        string? serviceId, CancellationToken token)
    {
        Require(!closed && !unsettled && arm is null);
        string attempt = Guid.NewGuid().ToString("D");
        Require(Unique(attempts, attempt));
        unsettled = true;
        using var deadline = Deadline(token);
        var facts = await source.ArmAsync(Binding, attempt, operation, variant, boundary, serviceId, deadline.Token);
        Require(facts.Binding == Binding && facts.AttemptId == attempt && facts.Operation == operation &&
            facts.Variant == variant && facts.Case == boundary && facts.ServiceId == serviceId &&
            facts.CaptureArmed && Unique(registrations, facts.RegistrationId) &&
            Next(facts.Cursor, facts.ArmedAt));
        arm = facts;
        Fence = null;
        observed = false;
        unsettled = false;
    }

    internal async ValueTask CompleteAsync(DispatchEvidence receipt, CancellationToken token)
    {
        Require(!closed && !unsettled && arm is not null);
        var original = arm!;
        arm = null;
        unsettled = true;
        using var deadline = Deadline(token);
        var facts = await source.CompleteAsync(original, receipt, deadline.Token);
        Require(facts.Arm == original && facts.Disposition == receipt && Text(facts.ServiceId) &&
            (original.ServiceId is null || original.ServiceId == facts.ServiceId) &&
            Unique(events, facts.EventId) && Next(facts.Sequence, facts.SettledAt) &&
            facts.OriginalAttemptSettled && facts.ExcludesLateCommit);
        Require(facts.NoReplay && facts.PendingValidationActions == 0 &&
            (receipt == DispatchEvidence.PossiblyDispatched ?
                facts.MatchedRequests is >= 0 and <= 1 && (!facts.Applied || facts.MatchedRequests == 1) :
                facts.MatchedRequests == (receipt == DispatchEvidence.NotDispatched ? 0 : 1)) &&
            facts.MatchedCommits == (facts.Applied ? 1 : 0) &&
            !(receipt is DispatchEvidence.NotDispatched or DispatchEvidence.Rejected && facts.Applied) &&
            (receipt != DispatchEvidence.Applied || facts.Applied) &&
            (!facts.Applied || facts.OriginalReferencesValidated), "effect-mismatch");
        Require(facts.MatchedRequests == 0 ? facts.ProviderRequestId is null : Unique(requests, facts.ProviderRequestId));
        Fence = facts;
        unsettled = false;
    }

    internal async ValueTask ObserveAsync(CancellationToken token)
    {
        Require(!closed && !unsettled && arm is null && Fence is not null && !observed);
        observed = true;
        unsettled = true;
        using var deadline = Deadline(token);
        var facts = await source.ObserveAsync(Binding, Fence!, deadline.Token);
        Require(facts.Binding == Binding && facts.ServiceId == Fence!.ServiceId &&
            facts.Phase == Fence.Arm.AttemptId && Unique(events, facts.EventId) &&
            Next(facts.Sequence, facts.ObservedAt));
        Require(facts.IndependentStorageRead && facts.ExactCredentialRowsMatch &&
            facts.SuppliedRowOptionalsMatch && facts.OmittedArrayRetained && facts.RemovedRowAbsent &&
            facts.RuntimeSubstitutionMatches && facts.WrongValueRejected && facts.DeniedDeliveryAbsent &&
            facts.ReferenceAuthorityMatches && facts.BorrowedStatePreserved, "effect-mismatch");
        unsettled = false;
    }

    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        closed = true;
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var facts = await source.CloseAsync(root, deadline.Token);
            Require(facts.Attempt == root && facts.Closed && facts.OwnedRootRemoved &&
                facts.OwnedReferencesRemoved && facts.ServicesAbsent && facts.BorrowedStatePreserved &&
                facts.PrivateCopiesDestroyed && facts.OriginalAttemptsSettled && facts.LateCreationFenced &&
                facts.RemainingRegistrations == 0 && facts.PendingDeliveries == 0, "cleanup-incomplete");
        }
        catch (Exception error) when (error is NativeCaseFailureException or OperationCanceledException)
        { throw new NativeCaseFailureException("cleanup-incomplete"); }
    }
    private CancellationTokenSource Deadline(CancellationToken token)
    {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(timeout);
        return deadline;
    }
    private bool Next(long cursor, DateTimeOffset captured)
    {
        if (cursor <= sequence || !Utc(captured) || captured < time) return false;
        sequence = cursor;
        time = captured;
        return true;
    }
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static bool Text(string? value) => value is { Length: > 0 and <= 512 } &&
        !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
    private static bool Unique(HashSet<string> values, string? value) => Text(value) && values.Add(value!);
    private static void Require(bool condition, string code = "observer-unavailable")
    {
        if (!condition) throw new NativeCaseFailureException(code);
    }
}
