using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal enum PeriodicRenewalSourceKind { NativeProvider, ControlledFixture }
internal enum PeriodicRenewalOutcome { NonApplied, Applied, Partial }
internal enum PeriodicRenewalBoundary { None, RequestCaptured, ResponseWithheld }

internal sealed record PeriodicRenewalInput(
    [property: JsonRequired] string Deployment,
    [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] string Epoch,
    [property: JsonRequired] PeriodicRenewalSourceKind Source,
    [property: JsonRequired] string IdentityId,
    [property: JsonRequired] string TokenRow,
    [property: JsonRequired] string Capability,
    [property: JsonRequired] string AllowedKey,
    [property: JsonRequired] string DeniedKey)
{
    public override string ToString() => "[PeriodicRenewalInput]";
}

internal sealed record PeriodicRenewalLifetime(
    [property: JsonRequired] DateTimeOffset OriginalIssuedAt,
    [property: JsonRequired] DateTimeOffset ExpiresAt,
    [property: JsonRequired] InfisicalTokenLifetime Lifetime,
    [property: JsonRequired] TimeSpan ReportedMaximumTtl,
    [property: JsonRequired] TimeSpan? Period,
    [property: JsonRequired] DateTimeOffset? AbsoluteLifetimeLimit)
{
    internal static PeriodicRenewalLifetime From(InfisicalTokenLifetimeEvidence e) =>
        new(e.OriginalIssuedAt, e.ExpiresAt, e.Lifetime, e.ReportedMaximumTtl, e.Period, e.AbsoluteLifetimeLimit);
    public override string ToString() => "[PeriodicRenewalLifetime]";
}

// Local identity, never sent to the SDK/provider as a header or idempotency key.
internal sealed record PeriodicRenewalRoot(
    [property: JsonRequired] string Id,
    [property: JsonRequired] string Nonce,
    [property: JsonRequired] string CaseIdentity,
    [property: JsonRequired] string Operation,
    [property: JsonRequired] string Variant,
    [property: JsonRequired] string Case,
    [property: JsonRequired] string ProviderVersion,
    [property: JsonRequired] string Deployment,
    [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] string Epoch,
    [property: JsonRequired] PeriodicRenewalSourceKind Source,
    [property: JsonRequired] string IdentityId,
    [property: JsonRequired] string TokenRow,
    [property: JsonRequired] bool ExpectsRequest,
    [property: JsonRequired] PeriodicRenewalBoundary Boundary)
{
    public override string ToString() => "[PeriodicRenewalRoot]";
}

internal sealed record PeriodicRenewalStamp(
    [property: JsonRequired] PeriodicRenewalRoot Root,
    [property: JsonRequired] string Registration,
    [property: JsonRequired] string Event,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset At,
    [property: JsonRequired] string ClockAuthority)
{
    public override string ToString() => "[PeriodicRenewalStamp]";
}

internal sealed record PeriodicRenewalBinding(
    [property: JsonRequired] PeriodicRenewalStamp Stamp,
    [property: JsonRequired] string CredentialHandle,
    [property: JsonRequired] PeriodicRenewalLifetime Lifetime,
    [property: JsonRequired] bool ExactCredentialRowJoin,
    [property: JsonRequired] bool IndependentJournal,
    [property: JsonRequired] bool BorrowedIdentityAndGrants)
{
    public override string ToString() => "[PeriodicRenewalBinding]";
}

// ExclusiveOriginalWindow is a source qualification requirement, not a host
// mutex. The source must cover every ingress for this exact credential, forbid
// foreign requests, and own the response gate before acknowledging Arm.
internal sealed record PeriodicRenewalArm(
    [property: JsonRequired] PeriodicRenewalStamp Stamp,
    [property: JsonRequired] PeriodicRenewalBinding Binding,
    [property: JsonRequired] string Window,
    [property: JsonRequired] bool ExclusiveOriginalWindow,
    [property: JsonRequired] bool CaptureArmed,
    [property: JsonRequired] int PendingWork)
{
    public override string ToString() => "[PeriodicRenewalArm]";
}

internal sealed record PeriodicRenewalArrival(
    [property: JsonRequired] PeriodicRenewalStamp Stamp,
    [property: JsonRequired] string Window,
    [property: JsonRequired] string RequestId,
    [property: JsonRequired] string CredentialHandle,
    [property: JsonRequired] PeriodicRenewalBoundary Boundary,
    [property: JsonRequired] bool ResponseHeld)
{
    public override string ToString() => "[PeriodicRenewalArrival]";
}

internal sealed record PeriodicRenewalReceipt(
    [property: JsonRequired] InfisicalRenewalEvidence? Evidence,
    [property: JsonRequired] SecretStatus Status)
{
    public override string ToString() => "[PeriodicRenewalReceipt]";
}

internal sealed record PeriodicRenewalSettlement(
    [property: JsonRequired] PeriodicRenewalStamp Stamp,
    [property: JsonRequired] PeriodicRenewalArm Arm,
    [property: JsonRequired] PeriodicRenewalReceipt Receipt,
    [property: JsonRequired] string RequestId,
    [property: JsonRequired] string CredentialHandle,
    [property: JsonRequired] PeriodicRenewalOutcome Outcome,
    [property: JsonRequired] int OriginalRequests,
    [property: JsonRequired] int OriginalCommits,
    [property: JsonRequired] int ForeignRequests,
    [property: JsonRequired] int PendingWork,
    [property: JsonRequired] int PendingDeliveries,
    [property: JsonRequired] bool OriginalTerminal,
    [property: JsonRequired] bool ExcludesLateWork,
    [property: JsonRequired] bool CompleteInventory,
    [property: JsonRequired] bool NoReplay,
    [property: JsonRequired] bool BorrowedIdentityAndGrants,
    [property: JsonRequired] PeriodicRenewalLifetime OriginalLifetime,
    [property: JsonRequired] PeriodicRenewalLifetime? CapturedLifetime,
    [property: JsonRequired] string? CapturedTokenRow,
    [property: JsonRequired] string? CapturedCredentialHandle)
{
    public override string ToString() => "[PeriodicRenewalSettlement]";
}

internal sealed record PeriodicRenewalDelivery(
    [property: JsonRequired] PeriodicRenewalStamp Stamp,
    [property: JsonRequired] string Window,
    [property: JsonRequired] string TokenRow,
    [property: JsonRequired] string CredentialHandle,
    [property: JsonRequired] PeriodicRenewalLifetime Lifetime,
    [property: JsonRequired] bool ExactSuppliedCredential)
{
    public override string ToString() => "[PeriodicRenewalDelivery]";
}

internal sealed record PeriodicRenewalExpiry(
    [property: JsonRequired] PeriodicRenewalStamp Stamp,
    [property: JsonRequired] PeriodicRenewalLifetime Lifetime,
    [property: JsonRequired] bool NaturalExpiry,
    [property: JsonRequired] bool PolicyAndGrantsUnchanged,
    [property: JsonRequired] bool InjectedClock)
{
    public override string ToString() => "[PeriodicRenewalExpiry]";
}

internal sealed record PeriodicRenewalCleanup(
    [property: JsonRequired] PeriodicRenewalRoot Root,
    [property: JsonRequired] bool OriginalTerminal,
    [property: JsonRequired] bool ExcludesLateWork,
    [property: JsonRequired] bool CompleteInventory,
    [property: JsonRequired] bool BorrowedIdentityAndGrants,
    [property: JsonRequired] bool QualifiedLifetimePreserved,
    [property: JsonRequired] bool OwnedCapturedResourcesAbsent,
    [property: JsonRequired] bool PrivateCopiesDestroyed,
    [property: JsonRequired] int Registrations,
    [property: JsonRequired] int PendingWork,
    [property: JsonRequired] int PendingDeliveries)
{
    public override string ToString() => "[PeriodicRenewalCleanup]";
}

internal interface IInfisicalPeriodicRenewalSource
{
    ValueTask<PeriodicRenewalBinding> OpenAsync(PeriodicRenewalRoot root, SecretMaterial borrowed,
        SecretMaterial capability, CancellationToken token);
    ValueTask<PeriodicRenewalExpiry> ExpireAsync(PeriodicRenewalBinding binding, CancellationToken token);
    ValueTask<PeriodicRenewalArm> ArmAsync(PeriodicRenewalBinding binding, CancellationToken token);
    ValueTask<PeriodicRenewalArrival> AwaitBoundaryAsync(PeriodicRenewalArm arm, CancellationToken token);
    ValueTask<PeriodicRenewalSettlement> SettleAsync(PeriodicRenewalArm arm,
        PeriodicRenewalReceipt receipt, CancellationToken token);
    ValueTask<PeriodicRenewalDelivery> InspectDeliveryAsync(PeriodicRenewalArm arm,
        SecretMaterial actualSdkMaterial, CancellationToken token);
    ValueTask<PeriodicRenewalCleanup> CloseAsync(PeriodicRenewalRoot root, CancellationToken token);
}
