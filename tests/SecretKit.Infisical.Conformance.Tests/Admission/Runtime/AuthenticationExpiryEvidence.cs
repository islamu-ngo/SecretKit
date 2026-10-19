using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal enum AuthenticationExpirySource { NativeProvider, ControlledFixture }
internal enum AuthenticationExpiryPhase { Active, Expired }

internal sealed record AuthenticationExpiryPolicy(
    [property: JsonRequired] double Ttl,
    [property: JsonRequired] double MaximumTtl,
    [property: JsonRequired] double Period,
    [property: JsonRequired] double MaximumUses)
{
    public override string ToString() => "[AuthenticationExpiryPolicy]";
}

internal sealed record AuthenticationExpiryAttempt(
    [property: JsonRequired] string Id,
    [property: JsonRequired] string CaseIdentity,
    [property: JsonRequired] string Operation,
    [property: JsonRequired] string Member,
    [property: JsonRequired] string ProviderVersion,
    [property: JsonRequired] string DeploymentId,
    [property: JsonRequired] string OrganizationId,
    [property: JsonRequired] string IdentityId,
    [property: JsonRequired] string AuthenticationMethod,
    [property: JsonRequired] AuthenticationExpiryPolicy Policy,
    [property: JsonRequired] double ExpectedExpiresIn,
    [property: JsonRequired] double ExpectedReportedMaximumTtl,
    [property: JsonRequired] AuthenticationExpirySource Source)
{
    public override string ToString() => "[AuthenticationExpiryAttempt]";
}

internal sealed record AuthenticationExpiryArm(
    [property: JsonRequired] AuthenticationExpiryAttempt Attempt,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] string ClockAuthority,
    [property: JsonRequired] string ClockEpoch,
    [property: JsonRequired] DateTimeOffset ArmedAt,
    [property: JsonRequired] long Cursor,
    [property: JsonRequired] string PolicyWitness,
    [property: JsonRequired] bool CaptureArmed)
{
    public override string ToString() => "[AuthenticationExpiryArm]";
}

internal sealed record AuthenticationExpiryFence(
    [property: JsonRequired] AuthenticationExpiryArm Arm,
    [property: JsonRequired] DispatchEvidence Disposition,
    [property: JsonRequired] string ProviderRequestId,
    [property: JsonRequired] string TokenMetadataId,
    [property: JsonRequired] string CredentialHandle,
    [property: JsonRequired] string CredentialWitness,
    [property: JsonRequired] AuthenticationExpiryPolicy ObservedPolicy,
    [property: JsonRequired] double ResponseExpiresIn,
    [property: JsonRequired] double ResponseMaximumTtl,
    [property: JsonRequired] DateTimeOffset IssuedAt,
    [property: JsonRequired] DateTimeOffset ExpiresAt,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] int MatchedIssuances,
    [property: JsonRequired] bool IssueEventObserved,
    [property: JsonRequired] bool NativeScheduleObserved,
    [property: JsonRequired] bool ExcludesLateCommit)
{
    public override string ToString() => "[AuthenticationExpiryFence]";
}

internal sealed record AuthenticationExpiryWindow(
    [property: JsonRequired] AuthenticationExpiryFence Binding,
    [property: JsonRequired] AuthenticationExpiryPhase Phase,
    [property: JsonRequired] string WindowId,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset OpenedAt,
    [property: JsonRequired] DateTimeOffset ClosedAt,
    [property: JsonRequired] bool Authoritative,
    [property: JsonRequired] bool EventObserved,
    [property: JsonRequired] bool NaturalExpiryObserved,
    [property: JsonRequired] bool PolicyUnchanged,
    [property: JsonRequired] bool IpPathUnchanged,
    [property: JsonRequired] bool NoRenewal,
    [property: JsonRequired] bool NoRevocation,
    [property: JsonRequired] bool UseLimitNotExhausted)
{
    public override string ToString() => "[AuthenticationExpiryWindow]";
}

internal sealed record AuthenticationExpiryObservation<T>(AuthenticationExpiryWindow Window, T Sample)
{
    public override string ToString() => "[AuthenticationExpiryObservation]";
}

internal sealed record AuthenticationExpiryCleanup(
    [property: JsonRequired] AuthenticationExpiryAttempt Attempt,
    [property: JsonRequired] bool Closed,
    [property: JsonRequired] bool LateCreationFenced,
    [property: JsonRequired] bool MutationSettled,
    [property: JsonRequired] bool InventoryComplete,
    [property: JsonRequired] bool CorrelationKeyDestroyed,
    [property: JsonRequired] int RemainingRegistrations,
    [property: JsonRequired] int PendingDeliveries)
{
    public override string ToString() => "[AuthenticationExpiryCleanup]";
}

// Key is private command material, never an evidence DTO property. The caller
// owns and clears it; an adapter must not retain it after ArmAsync completes.
internal interface IAuthenticationExpiryObserver
{
    ValueTask<AuthenticationExpiryArm> ArmAsync(AuthenticationExpiryAttempt attempt,
        ReadOnlyMemory<byte> correlationKey, CancellationToken token);
    ValueTask<AuthenticationExpiryFence> CompleteAsync(AuthenticationExpiryArm arm,
        DispatchEvidence receipt, CancellationToken token);
    ValueTask<AuthenticationExpiryObservation<T>> ObserveAsync<T>(AuthenticationExpiryFence binding,
        AuthenticationExpiryPhase phase, Func<CancellationToken, ValueTask<T>> sample, CancellationToken token);
    ValueTask<AuthenticationExpiryCleanup> CloseAsync(AuthenticationExpiryAttempt attempt, CancellationToken token);
}
