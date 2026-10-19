using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal enum RotationMutationOutcome { NonApplied, Applied, Partial }
internal enum RotationMutationEvent { None, OriginalManual, ScheduledOpportunity }

internal sealed record RotationMutationInput(
    [property: JsonRequired] RotationMaterialInput Material,
    [property: JsonRequired] bool Enabled,
    [property: JsonRequired] int MaximumOriginalDeliveries)
{
    public override string ToString() => "[RotationMutationInput]";
}

// This is a local attempt identity, never a vendor idempotency/job token.
// The root exists before Open, including recovery of a lost Open/arm reply.
internal sealed record RotationMutationRoot(
    [property: JsonRequired] RotationMaterialRoot Material,
    [property: JsonRequired] string AttemptId,
    [property: JsonRequired] InfisicalRotationAction Action,
    [property: JsonRequired] InfisicalRotationPrecondition Precondition)
{
    public override string ToString() => "[RotationMutationRoot]";
}

internal sealed record RotationMutationReceipt(
    [property: JsonRequired] string AttemptId,
    [property: JsonRequired] InfisicalRotationAction Action,
    [property: JsonRequired] InfisicalRotationDispatch Dispatch,
    [property: JsonRequired] InfisicalRotationEffect Effect,
    [property: JsonRequired] SecretStatus Status)
{
    internal static RotationMutationReceipt Capture(RotationMutationRoot root,
        InfisicalRotationReceipt receipt, SecretStatus status) =>
        new(root.AttemptId, receipt.Action, receipt.Dispatch, receipt.Effect, status);
    public override string ToString() => "[RotationMutationReceipt]";
}

internal sealed record RotationMutationStamp(
    [property: JsonRequired] RotationMutationRoot Root,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset At,
    [property: JsonRequired] string ClockAuthority)
{
    public override string ToString() => "[RotationMutationStamp]";
}

internal sealed record RotationMutationBinding(
    [property: JsonRequired] RotationMutationStamp Stamp,
    [property: JsonRequired] bool OwnedSetup,
    [property: JsonRequired] bool SetupSettled,
    [property: JsonRequired] bool ConfigurationAndMappingMatch,
    [property: JsonRequired] bool ExactMaterialKnown,
    [property: JsonRequired] bool CompleteBackendInventory,
    [property: JsonRequired] bool IndependentJournals,
    [property: JsonRequired] bool AdminAccepted,
    [property: JsonRequired] bool WrongAdminRejected,
    [property: JsonRequired] bool ValidAdminRechecked)
{
    public override string ToString() => "[RotationMutationBinding]";
}

internal sealed record RotationMutationArm(
    [property: JsonRequired] RotationMutationStamp Stamp,
    [property: JsonRequired] RotationMutationBinding Binding,
    [property: JsonRequired] bool CaptureArmed,
    [property: JsonRequired] bool ExclusiveOriginalWindow)
{
    public override string ToString() => "[RotationMutationArm]";
}

// A terminal attributable inventory, not a latest GET/status/job projection.
// Protected final material travels only on this private source channel.
internal sealed record RotationMutationSettlement(
    [property: JsonRequired] RotationMutationStamp Stamp,
    [property: JsonRequired] RotationMutationArm Arm,
    [property: JsonRequired] RotationMutationReceipt Receipt,
    [property: JsonRequired] RotationMutationOutcome Outcome,
    [property: JsonRequired] int OriginalRequests,
    [property: JsonRequired] int OriginalCommits,
    [property: JsonRequired] int OriginalBackendDeliveries,
    [property: JsonRequired] bool OriginalTerminal,
    [property: JsonRequired] bool ExcludesLateWork,
    [property: JsonRequired] bool CompleteDeliveryInventory,
    [property: JsonRequired] bool NoReplay,
    [property: JsonRequired] int PendingDeliveries,
    [property: JsonRequired] int PendingWork,
    [property: JsonRequired] bool ConfigurationMatchesOutcome,
    [property: JsonRequired] bool MappingPreserved,
    [property: JsonRequired] bool Enabled,
    [property: JsonRequired] RotationMutationEvent Event,
    [property: JsonRequired] string EventAttemptId,
    [property: JsonRequired] bool QualifiedOpportunity,
    [property: JsonRequired] bool InjectedClock,
    [property: JsonRequired] bool QueueTerminalBeforeOpportunity,
    [property: JsonRequired] int QueuedBackendDeliveries,
    [property: JsonRequired] long OpportunityBaselineGeneration,
    [property: JsonRequired] long Generation,
    [property: JsonRequired] RotationMaterialFieldInput[] Fields,
    [property: JsonRequired] bool CompleteCredentialHistory,
    [property: JsonRequired] bool PreviousActiveAccepted,
    [property: JsonRequired] bool OverwrittenRetired,
    [property: JsonRequired] bool IdentityRetirementQualified)
{
    public override string ToString() => "[RotationMutationSettlement]";
}

internal sealed record RotationMutationAuthentication(
    [property: JsonRequired] RotationMutationStamp Stamp,
    [property: JsonRequired] RotationMutationArm Arm,
    [property: JsonRequired] long Generation,
    [property: JsonRequired] bool ExactSuppliedMaterial,
    [property: JsonRequired] bool CoherentGeneration,
    [property: JsonRequired] bool FreshSessions,
    [property: JsonRequired] bool IndependentBackend,
    [property: JsonRequired] BackendAuthentication Valid,
    [property: JsonRequired] BackendAuthentication Wrong,
    [property: JsonRequired] BackendAuthentication Recheck,
    [property: JsonRequired] string[] AllowedActions,
    [property: JsonRequired] string[] DeniedActions)
{
    public override string ToString() => "[RotationMutationAuthentication]";
}

internal sealed record RotationMutationCleanup(
    [property: JsonRequired] RotationMutationRoot Root,
    [property: JsonRequired] bool OriginalTerminal,
    [property: JsonRequired] bool ExcludesLateWork,
    [property: JsonRequired] bool CompleteInventory,
    [property: JsonRequired] bool CapturedSetsRetired,
    [property: JsonRequired] bool OwnedIdentitiesAbsent,
    [property: JsonRequired] bool OwnedResourcesAbsent,
    [property: JsonRequired] bool NativeSetupAbsent,
    [property: JsonRequired] bool MappedSecretsAbsent,
    [property: JsonRequired] bool BorrowedPreserved,
    [property: JsonRequired] bool PrivateDestroyed,
    [property: JsonRequired] int Registrations,
    [property: JsonRequired] int PendingDeliveries,
    [property: JsonRequired] int PendingWork)
{
    public override string ToString() => "[RotationMutationCleanup]";
}

internal interface IInfisicalRotationMutationSource
{
    ValueTask<RotationMutationBinding> OpenAsync(RotationMutationRoot root, RotationMaterialPacket baseline,
        SecretMaterial setupCapability, CancellationToken token);
    ValueTask<RotationMutationArm> ArmAsync(RotationMutationBinding binding, CancellationToken token);
    ValueTask<RotationMutationSettlement> SettleAsync(RotationMutationArm arm,
        RotationMutationReceipt receipt, CancellationToken token);
    ValueTask<RotationMutationAuthentication> AuthenticateAsync(RotationMutationArm arm,
        RotationMaterialPacket actual, RotationMaterialPacket wrong, CancellationToken token);
    ValueTask<RotationMutationCleanup> CloseAsync(RotationMutationRoot root, CancellationToken token);
}
