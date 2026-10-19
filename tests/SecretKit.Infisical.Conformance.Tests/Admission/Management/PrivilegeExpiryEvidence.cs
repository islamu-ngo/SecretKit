using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Conformance.Tests;

internal enum PrivilegeExpirySource { NativeProvider, ControlledFixture }
internal enum PrivilegeExpiryVersion { LegacyV1, ProjectV2 }
internal enum PrivilegeExpiryPhase { BeforeActivation, Active, Expired }
internal enum PrivilegeExpiryDisposition { Applied, Rejected, NotDispatched }

// Privilege IDs and slugs are not membership assignment IDs. Every wire field
// is required, including nullable selectors and rejection evidence.
internal sealed record PrivilegeExpiryAttempt(
    [property: JsonRequired] string Id,
    [property: JsonRequired] string CaseIdentity,
    [property: JsonRequired] string Operation,
    [property: JsonRequired] PrivilegeExpiryVersion Version,
    [property: JsonRequired] string OrganizationId,
    [property: JsonRequired] string ProjectId,
    [property: JsonRequired] string ProjectSlug,
    [property: JsonRequired] string IdentityId,
    [property: JsonRequired] string MembershipId,
    [property: JsonRequired] string PrivilegeSlug,
    [property: JsonRequired] string? ExistingPrivilegeId,
    [property: JsonRequired] PrivilegeExpirySource Source)
{
    public override string ToString() => "[PrivilegeExpiryAttempt]";
}

internal sealed record PrivilegeExpiryIntent(
    [property: JsonRequired] PrivilegeExpiryAttempt Attempt,
    [property: JsonRequired] string RelativeDuration,
    [property: JsonRequired] int ActivationLeadSeconds)
{
    public override string ToString() => "[PrivilegeExpiryIntent]";
}

internal sealed record PrivilegeExpiryArm(
    [property: JsonRequired] PrivilegeExpiryIntent Intent,
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
    public override string ToString() => "[PrivilegeExpiryArm]";
}

internal sealed record PrivilegeExpiryFence(
    [property: JsonRequired] PrivilegeExpiryArm Arm,
    [property: JsonRequired] string? ProviderRequestId,
    [property: JsonRequired] PrivilegeExpiryDisposition Disposition,
    [property: JsonRequired] string? PrivilegeId,
    [property: JsonRequired] string PrivilegeSlug,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] bool ExcludesLateCommit)
{
    public override string ToString() => "[PrivilegeExpiryFence]";
}

internal sealed record PrivilegeExpiryWindow(
    [property: JsonRequired] PrivilegeExpiryFence Binding,
    [property: JsonRequired] PrivilegeExpiryPhase Phase,
    [property: JsonRequired] string WindowId,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset OpenedAt,
    [property: JsonRequired] DateTimeOffset ClosedAt,
    [property: JsonRequired] bool Authoritative,
    [property: JsonRequired] bool EventObserved)
{
    public override string ToString() => "[PrivilegeExpiryWindow]";
}

internal sealed record PrivilegeExpiryObservation<T>(PrivilegeExpiryWindow Window, T Sample)
{
    public override string ToString() => "[PrivilegeExpiryObservation]";
}

internal sealed record PrivilegeExpiryCleanup(
    [property: JsonRequired] PrivilegeExpiryAttempt Attempt,
    [property: JsonRequired] bool Closed,
    [property: JsonRequired] bool LateCreationFenced,
    [property: JsonRequired] bool MutationSettled,
    [property: JsonRequired] bool InventoryComplete,
    [property: JsonRequired] int RemainingRegistrations,
    [property: JsonRequired] int PendingDeliveries)
{
    public override string ToString() => "[PrivilegeExpiryCleanup]";
}

// Arm before the measured dispatch. The observer brackets the local SDK
// callback; it cannot supply permission results. Close the original attempt
// even if registration committed and the arm response was lost.
internal interface IPrivilegeExpiryObserver
{
    ValueTask<PrivilegeExpiryArm> ArmAsync(PrivilegeExpiryIntent intent, CancellationToken token);
    ValueTask<PrivilegeExpiryFence> CompleteAsync(PrivilegeExpiryArm arm, CancellationToken token);
    ValueTask<PrivilegeExpiryObservation<T>> ObserveAsync<T>(PrivilegeExpiryFence binding,
        PrivilegeExpiryPhase phase, Func<CancellationToken, ValueTask<T>> sample, CancellationToken token);
    ValueTask<PrivilegeExpiryCleanup> CloseAsync(PrivilegeExpiryAttempt attempt, CancellationToken token);
}
