using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Validation also applies to directly injected sources, not just channel replies.
internal sealed class GatewayPatchTrial(IGatewayPatchObserver source, GatewayPatchRootAttempt root,
    int seconds) : IAsyncDisposable
{
    private readonly HashSet<string> registrations = [];
    private readonly HashSet<string> attempts = [];
    private readonly HashSet<string> events = [];
    private readonly HashSet<string> requests = [];
    private GatewayPatchArm? arm;
    private long sequence;
    private DateTimeOffset time;
    private bool busy = true, observed, closed;
    internal GatewayPatchBinding Binding { get; private set; } = null!;
    internal GatewayPatchFence? Fence { get; private set; }
    internal bool CleanupSafe { get; private set; }
    internal void Dispatching() => CleanupSafe = false;

    internal static async ValueTask<GatewayPatchTrial> OpenAsync(IGatewayPatchObserver source,
        GatewayPatchRootAttempt root, GatewayPatchAuthenticationInput baseline,
        GatewayPatchAuthenticationInput selected, int seconds, Action<GatewayPatchTrial> retain,
        CancellationToken token)
    {
        Require(seconds is >= 1 and <= 900 && Text(root.Id) && Text(root.CaseIdentity) &&
            root.ProviderVersion == "v0.166.3" && Text(root.DeploymentId) && Text(root.RootNonce) &&
            Text(root.OrganizationId) && Text(root.OriginalName) && Text(root.Renamed) &&
            root.OriginalName != root.Renamed && Enum.IsDefined(root.Source) &&
            (root.Source == GatewayPatchSource.ControlledFixture) == (root.SourceProfile == "controlled-fixture"),
            "missing-input");
        var trial = new GatewayPatchTrial(source, root, seconds);
        retain(trial); // A lost bootstrap reply still has an exact root to close.
        using var deadline = trial.Deadline(token);
        var facts = await source.OpenAsync(root, baseline, selected, deadline.Token);
        Require(facts.Attempt == root && Unique(trial.registrations, facts.RegistrationId) &&
            Text(facts.SourceIdentity) &&
            facts.SourceIdentity is not ("setup" or "administrative" or "observer" or "runtime" or "denied") &&
            facts.ClockAuthority == "provider-application-clock" && Text(facts.ClockEpoch) &&
            Utc(facts.OpenedAt) && facts.Sequence >= 0 && facts.RootInitiallyAbsent &&
            facts.OwnedRootCreated && facts.IndependentProtectedStorageQualified &&
            facts.EffectiveAuthenticationQualified && facts.DestinationValidationQualified &&
            facts.DistinctContrasts && facts.BorrowedStatePreserved);
        trial.Binding = facts;
        trial.sequence = facts.Sequence;
        trial.time = facts.OpenedAt;
        trial.busy = false;
        trial.CleanupSafe = true;
        return trial;
    }

    internal async ValueTask ArmAsync(string operation, string variant, string boundary,
        string? id, CancellationToken token)
    {
        Require(!closed && !busy && arm is null && operation is "Create" or "Update" &&
            Text(variant) && Text(boundary) && (operation == "Create" ? id is null : Text(id)));
        busy = true;
        string attempt = Guid.NewGuid().ToString("D");
        Require(Unique(attempts, attempt));
        using var deadline = Deadline(token);
        var facts = await source.ArmAsync(Binding, attempt, operation, variant, boundary, id, deadline.Token);
        Require(facts.Binding == Binding && facts.AttemptId == attempt && facts.Operation == operation &&
            facts.Variant == variant && facts.Case == boundary && facts.GatewayId == id &&
            facts.CaptureArmed && Unique(registrations, facts.RegistrationId) && Next(facts.Cursor, facts.ArmedAt));
        arm = facts;
        Fence = null;
        observed = false;
        busy = false;
    }

    internal async ValueTask CompleteAsync(DispatchEvidence receipt, CancellationToken token)
    {
        Require(!closed && !busy && arm is not null);
        busy = true;
        var original = arm!;
        arm = null;
        using var deadline = Deadline(token);
        var facts = await source.CompleteAsync(original, receipt, deadline.Token);
        Require(facts.Arm == original && facts.Disposition == receipt && Text(facts.GatewayId) &&
            (original.GatewayId is null || facts.GatewayId == original.GatewayId) &&
            Unique(events, facts.EventId) && Next(facts.Sequence, facts.SettledAt) &&
            facts.OriginalAttemptSettled && facts.ExcludesLateApplication);
        CleanupSafe = facts.ValidationActionsTerminal && facts.NoReplay;
        bool any = facts.AuthenticationApplied || facts.NameApplied;
        Require(Enum.IsDefined(receipt) && facts.NoReplay && facts.ValidationActionsTerminal &&
            (receipt == DispatchEvidence.PossiblyDispatched ?
                facts.MatchedRequests is >= 0 and <= 1 && (!any || facts.MatchedRequests == 1) :
                facts.MatchedRequests == (receipt == DispatchEvidence.NotDispatched ? 0 : 1)) &&
            !(receipt == DispatchEvidence.NotDispatched && any) &&
            // Native auth precedes rename. Rejected can contain the auth half.
            !(receipt == DispatchEvidence.Rejected && facts.NameApplied) &&
            (receipt != DispatchEvidence.Applied ||
                (facts.AuthenticationApplied == (original.Operation == "Create" ||
                    !GatewayPatchEffects.RetainsAuthentication(original.Variant)) &&
                facts.NameApplied == (original.Operation == "Create" || GatewayPatchEffects.Renames(original.Variant)))),
            "effect-mismatch");
        Require(facts.MatchedRequests == 0 ? facts.ProviderRequestId is null : Unique(requests, facts.ProviderRequestId));
        Fence = facts;
        busy = false;
    }

    internal async ValueTask ObserveAsync(CancellationToken token)
    {
        Require(!closed && !busy && arm is null && Fence is not null && !observed);
        busy = true;
        observed = true;
        using var deadline = Deadline(token);
        var facts = await source.ObserveAsync(Binding, Fence!, deadline.Token);
        Require(facts.Binding == Binding && facts.GatewayId == Fence!.GatewayId &&
            facts.Phase == Fence.Arm.AttemptId && Unique(events, facts.EventId) &&
            Next(facts.Sequence, facts.ObservedAt));
        Require(facts.IndependentProtectedStorageRead && facts.MethodDefaultsAndOmissionsMatch &&
            facts.ReviewerRetentionOrDropMatches && facts.CaRetentionOrClearMatches &&
            facts.AttachmentsMatch && facts.ExactNameMatches && facts.EffectiveAuthenticationMatches &&
            facts.WrongAuthorityRejected && facts.ActualTokenReviewMatches && facts.BorrowedStatePreserved,
            "effect-mismatch");
        busy = false;
    }

    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        closed = true;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var facts = await source.CloseAsync(root, deadline.Token);
            Require(facts.Attempt == root && facts.Closed && facts.OwnedRootRemoved && facts.GatewaysAbsent &&
                facts.AgentsAndTokensAbsent && facts.PrivateCopiesDestroyed && facts.BorrowedAttachmentsPreserved &&
                facts.OriginalAttemptsSettled && facts.LateCreationFenced &&
                facts.RemainingRegistrations == 0 && facts.PendingDeliveries == 0, "cleanup-incomplete");
        }
        catch (Exception error) when (error is NativeCaseFailureException or OperationCanceledException)
        { throw new NativeCaseFailureException("cleanup-incomplete"); }
    }
    private CancellationTokenSource Deadline(CancellationToken token)
    {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(seconds));
        return deadline;
    }
    private bool Next(long value, DateTimeOffset captured)
    {
        if (value <= sequence || !Utc(captured) || captured < time) return false;
        sequence = value; time = captured; return true;
    }
    private static bool Text(string? value) => value is { Length: > 0 and <= 512 } &&
        !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static bool Unique(HashSet<string> values, string? value) => Text(value) && values.Add(value!);
    private static void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) throw new NativeCaseFailureException(code); }
}
