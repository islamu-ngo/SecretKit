using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Conformance.Tests;

internal enum MembershipExpirySource { NativeProvider, ControlledFixture }
internal enum MembershipExpiryPrincipal { Identity, Group, User }
internal enum MembershipExpiryPhase { BeforeActivation, Active, Expired }
internal enum MembershipExpiryDisposition { Applied, Rejected, NotDispatched }

internal sealed record MembershipExpiryAttempt(
    [property: JsonRequired] string Id,
    [property: JsonRequired] string CaseIdentity,
    [property: JsonRequired] string OrganizationId,
    [property: JsonRequired] string ProjectId,
    [property: JsonRequired] MembershipExpiryPrincipal PrincipalKind,
    [property: JsonRequired] string PrincipalId,
    [property: JsonRequired] string RuntimePrincipalId,
    [property: JsonRequired] string? ExistingMembershipId,
    [property: JsonRequired] MembershipExpirySource Source)
{
    public override string ToString() => "[MembershipExpiryAttempt]";
}

internal sealed record MembershipExpiryIntent(
    [property: JsonRequired] MembershipExpiryAttempt Attempt,
    [property: JsonRequired] string RelativeDuration,
    [property: JsonRequired] int ActivationLeadSeconds)
{
    public override string ToString() => "[MembershipExpiryIntent]";
}

internal sealed record MembershipExpiryArm(
    [property: JsonRequired] MembershipExpiryIntent Intent,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] string ClockAuthority,
    [property: JsonRequired] string ClockEpoch,
    [property: JsonRequired] DateTimeOffset ArmedAt,
    [property: JsonRequired] DateTimeOffset StartsAt,
    [property: JsonRequired] DateTimeOffset EndsAt,
    [property: JsonRequired] long Cursor,
    [property: JsonRequired] bool CaptureArmed)
{
    public override string ToString() => "[MembershipExpiryArm]";
}

internal sealed record MembershipExpiryFence(
    [property: JsonRequired] MembershipExpiryArm Arm,
    [property: JsonRequired] string? ProviderRequestId,
    [property: JsonRequired] MembershipExpiryDisposition Disposition,
    [property: JsonRequired] string? MembershipId,
    [property: JsonRequired] string? AssignmentId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] bool ExcludesLateCommit)
{
    public override string ToString() => "[MembershipExpiryFence]";
}

internal sealed record MembershipExpiryWindow(
    [property: JsonRequired] MembershipExpiryFence Binding,
    [property: JsonRequired] MembershipExpiryPhase Phase,
    [property: JsonRequired] string WindowId,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset OpenedAt,
    [property: JsonRequired] DateTimeOffset ClosedAt,
    [property: JsonRequired] bool Authoritative,
    [property: JsonRequired] bool EventObserved)
{
    public override string ToString() => "[MembershipExpiryWindow]";
}

internal sealed record MembershipExpiryObservation<T>(MembershipExpiryWindow Window, T Sample)
{
    public override string ToString() => "[MembershipExpiryObservation]";
}

internal sealed record MembershipExpiryCleanup(
    [property: JsonRequired] MembershipExpiryAttempt Attempt,
    [property: JsonRequired] bool Closed,
    [property: JsonRequired] bool LateCreationFenced,
    [property: JsonRequired] bool MutationSettled,
    [property: JsonRequired] bool InventoryComplete,
    [property: JsonRequired] int RemainingRegistrations,
    [property: JsonRequired] int PendingDeliveries)
{
    public override string ToString() => "[MembershipExpiryCleanup]";
}

// The source brackets local SDK reads; it cannot substitute its own access booleans.
// Cleanup uses the client-known attempt even when the arm reply was lost.
internal interface IMembershipExpiryObserver
{
    ValueTask<MembershipExpiryArm> ArmAsync(MembershipExpiryIntent intent, CancellationToken token);
    ValueTask<MembershipExpiryFence> CompleteAsync(MembershipExpiryArm arm, CancellationToken token);
    ValueTask<MembershipExpiryObservation<T>> ObserveAsync<T>(MembershipExpiryFence binding,
        MembershipExpiryPhase phase, Func<CancellationToken, ValueTask<T>> sample, CancellationToken token);
    ValueTask<MembershipExpiryCleanup> CloseAsync(MembershipExpiryAttempt attempt, CancellationToken token);
}
