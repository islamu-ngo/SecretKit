using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Conformance.Tests;

internal enum OrganizationGroupExpiredMetadata { RetainedInactive, RemovedAssignment }

// These are authenticated-context observations, not request Target echoes.
internal sealed record OrganizationGroupExpiryScopes(
    [property: JsonRequired] string OwnerOrganizationId,
    [property: JsonRequired] string OwnerSetupIdentityId,
    [property: JsonRequired] string OwnerObserverIdentityId,
    [property: JsonRequired] string TargetOrganizationId,
    [property: JsonRequired] string TargetSetupIdentityId,
    [property: JsonRequired] string TargetAdministrativeIdentityId,
    [property: JsonRequired] string TargetObserverIdentityId,
    [property: JsonRequired] string TargetRuntimeIdentityId,
    [property: JsonRequired] string TargetDeniedIdentityId)
{
    public override string ToString() => "[OrganizationGroupExpiryScopes]";
}

internal sealed record OrganizationGroupExpiryAttempt(
    [property: JsonRequired] string Id,
    [property: JsonRequired] string CaseIdentity,
    [property: JsonRequired] string Operation,
    [property: JsonRequired] string ProviderVersion,
    [property: JsonRequired] OrganizationGroupExpiryScopes Scopes,
    [property: JsonRequired] string GroupId,
    [property: JsonRequired] string OwnerMembershipId,
    [property: JsonRequired] string RuntimeLinkId,
    [property: JsonRequired] string RoleId,
    [property: JsonRequired] string RoleSlug,
    [property: JsonRequired] string? ExistingTargetMembershipId,
    [property: JsonRequired] MembershipExpirySource Source,
    [property: JsonRequired] OrganizationGroupExpiredMetadata ExpiredMetadata)
{
    public override string ToString() => "[OrganizationGroupExpiryAttempt]";
}

internal sealed record OrganizationGroupExpiryIntent(
    [property: JsonRequired] OrganizationGroupExpiryAttempt Attempt,
    [property: JsonRequired] string RelativeDuration,
    [property: JsonRequired] int ActivationLeadSeconds)
{
    public override string ToString() => "[OrganizationGroupExpiryIntent]";
}

internal sealed record OrganizationGroupExpiryArm(
    [property: JsonRequired] OrganizationGroupExpiryIntent Intent,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] string ClockAuthority,
    [property: JsonRequired] string ClockEpoch,
    [property: JsonRequired] DateTimeOffset ArmedAt,
    [property: JsonRequired] DateTimeOffset StartsAt,
    [property: JsonRequired] DateTimeOffset EndsAt,
    [property: JsonRequired] long Cursor,
    [property: JsonRequired] bool CaptureArmed,
    [property: JsonRequired] OrganizationGroupExpiryScopes ObservedScopes,
    [property: JsonRequired] bool AuthenticatedScopesObserved)
{
    public override string ToString() => "[OrganizationGroupExpiryArm]";
}

internal sealed record OrganizationGroupExpiryFence(
    [property: JsonRequired] OrganizationGroupExpiryArm Arm,
    [property: JsonRequired] string? ProviderRequestId,
    [property: JsonRequired] MembershipExpiryDisposition Disposition,
    [property: JsonRequired] string? TargetMembershipId,
    [property: JsonRequired] string? TemporaryAssignmentId,
    [property: JsonRequired] string? MutationOrganizationId,
    [property: JsonRequired] string? MutationIdentityId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] bool ExcludesLateCommit)
{
    public override string ToString() => "[OrganizationGroupExpiryFence]";
}

internal sealed record OrganizationGroupExpiryWindow(
    [property: JsonRequired] OrganizationGroupExpiryFence Binding,
    [property: JsonRequired] MembershipExpiryPhase Phase,
    [property: JsonRequired] string WindowId,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset OpenedAt,
    [property: JsonRequired] DateTimeOffset ClosedAt,
    [property: JsonRequired] bool Authoritative,
    [property: JsonRequired] bool EventObserved,
    [property: JsonRequired] string RuntimeOrganizationId,
    [property: JsonRequired] string RuntimeIdentityId)
{
    public override string ToString() => "[OrganizationGroupExpiryWindow]";
}

internal sealed record OrganizationGroupExpiryObservation<T>(OrganizationGroupExpiryWindow Window, T Sample)
{
    public override string ToString() => "[OrganizationGroupExpiryObservation]";
}

internal sealed record OrganizationGroupExpiryCleanup(
    [property: JsonRequired] OrganizationGroupExpiryAttempt Attempt,
    [property: JsonRequired] bool Closed,
    [property: JsonRequired] bool LateCreationFenced,
    [property: JsonRequired] bool MutationSettled,
    [property: JsonRequired] bool InventoryComplete,
    [property: JsonRequired] int RemainingRegistrations,
    [property: JsonRequired] int PendingDeliveries)
{
    public override string ToString() => "[OrganizationGroupExpiryCleanup]";
}

internal interface IOrganizationGroupExpiryObserver
{
    ValueTask<OrganizationGroupExpiryArm> ArmAsync(OrganizationGroupExpiryIntent intent, CancellationToken token);
    ValueTask<OrganizationGroupExpiryFence> CompleteAsync(OrganizationGroupExpiryArm arm, CancellationToken token);
    ValueTask<OrganizationGroupExpiryObservation<T>> ObserveAsync<T>(OrganizationGroupExpiryFence binding,
        MembershipExpiryPhase phase, Func<CancellationToken, ValueTask<T>> sample, CancellationToken token);
    ValueTask<OrganizationGroupExpiryCleanup> CloseAsync(OrganizationGroupExpiryAttempt attempt, CancellationToken token);
}
