using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal enum ProxyPatchSource { NativeProvider, ControlledFixture }

internal sealed record ProxyPatchWitnessInput(string DeploymentId, string SourceProfile,
    string RootNonce, int CaseTimeoutSeconds)
{
    public override string ToString() => "[ProxyPatchWitnessInput]";
}

internal sealed record ProxyPatchRootAttempt(
    [property: JsonRequired] string Id,
    [property: JsonRequired] string CaseIdentity,
    [property: JsonRequired] string ProviderVersion,
    [property: JsonRequired] string DeploymentId,
    [property: JsonRequired] string SourceProfile,
    [property: JsonRequired] string RootNonce,
    [property: JsonRequired] string OrganizationId,
    [property: JsonRequired] string ProjectId,
    [property: JsonRequired] string Environment,
    [property: JsonRequired] string OriginalName,
    [property: JsonRequired] string Renamed,
    [property: JsonRequired] ProxyPatchSource Source)
{
    public override string ToString() => "[ProxyPatchRootAttempt]";
}

internal sealed record ProxyPatchBinding(
    [property: JsonRequired] ProxyPatchRootAttempt Attempt,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] string ClockAuthority,
    [property: JsonRequired] string ClockEpoch,
    [property: JsonRequired] DateTimeOffset OpenedAt,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] bool RootInitiallyAbsent,
    [property: JsonRequired] bool OwnedRootCreated,
    [property: JsonRequired] bool IndependentStorageQualified,
    [property: JsonRequired] bool ReferenceValidationQualified,
    [property: JsonRequired] bool RuntimeDeliveryQualified,
    [property: JsonRequired] bool DistinctContrasts,
    [property: JsonRequired] bool BorrowedStatePreserved)
{
    public override string ToString() => "[ProxyPatchBinding]";
}

internal sealed record ProxyPatchArm(
    [property: JsonRequired] ProxyPatchBinding Binding,
    [property: JsonRequired] string AttemptId,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] string Operation,
    [property: JsonRequired] string Variant,
    [property: JsonRequired] string Case,
    [property: JsonRequired] string? ServiceId,
    [property: JsonRequired] long Cursor,
    [property: JsonRequired] DateTimeOffset ArmedAt,
    [property: JsonRequired] bool CaptureArmed)
{
    public override string ToString() => "[ProxyPatchArm]";
}

internal sealed record ProxyPatchFence(
    [property: JsonRequired] ProxyPatchArm Arm,
    [property: JsonRequired] DispatchEvidence Disposition,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] string? ProviderRequestId,
    [property: JsonRequired] string ServiceId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset SettledAt,
    [property: JsonRequired] int MatchedRequests,
    [property: JsonRequired] int MatchedCommits,
    [property: JsonRequired] bool Applied,
    [property: JsonRequired] bool OriginalAttemptSettled,
    [property: JsonRequired] bool ExcludesLateCommit,
    [property: JsonRequired] bool NoReplay,
    [property: JsonRequired] bool OriginalReferencesValidated,
    [property: JsonRequired] int PendingValidationActions)
{
    public override string ToString() => "[ProxyPatchFence]";
}

internal sealed record ProxyPatchObservation(
    [property: JsonRequired] ProxyPatchBinding Binding,
    [property: JsonRequired] string ServiceId,
    [property: JsonRequired] string Phase,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset ObservedAt,
    [property: JsonRequired] bool IndependentStorageRead,
    [property: JsonRequired] bool ExactCredentialRowsMatch,
    [property: JsonRequired] bool SuppliedRowOptionalsMatch,
    [property: JsonRequired] bool OmittedArrayRetained,
    [property: JsonRequired] bool RemovedRowAbsent,
    [property: JsonRequired] bool RuntimeSubstitutionMatches,
    [property: JsonRequired] bool WrongValueRejected,
    [property: JsonRequired] bool DeniedDeliveryAbsent,
    [property: JsonRequired] bool ReferenceAuthorityMatches,
    [property: JsonRequired] bool BorrowedStatePreserved)
{
    public override string ToString() => "[ProxyPatchObservation]";
}

internal sealed record ProxyPatchCleanup(
    [property: JsonRequired] ProxyPatchRootAttempt Attempt,
    [property: JsonRequired] bool Closed,
    [property: JsonRequired] bool OwnedRootRemoved,
    [property: JsonRequired] bool OwnedReferencesRemoved,
    [property: JsonRequired] bool ServicesAbsent,
    [property: JsonRequired] bool BorrowedStatePreserved,
    [property: JsonRequired] bool PrivateCopiesDestroyed,
    [property: JsonRequired] bool OriginalAttemptsSettled,
    [property: JsonRequired] bool LateCreationFenced,
    [property: JsonRequired] int RemainingRegistrations,
    [property: JsonRequired] int PendingDeliveries)
{
    public override string ToString() => "[ProxyPatchCleanup]";
}

internal interface IProxyPatchObserver
{
    ValueTask<ProxyPatchBinding> OpenAsync(ProxyPatchRootAttempt attempt, CancellationToken token);
    ValueTask<ProxyPatchArm> ArmAsync(ProxyPatchBinding binding, string attemptId, string operation,
        string variant, string boundary, string? serviceId, CancellationToken token);
    ValueTask<ProxyPatchFence> CompleteAsync(ProxyPatchArm arm, DispatchEvidence receipt, CancellationToken token);
    ValueTask<ProxyPatchObservation> ObserveAsync(ProxyPatchBinding binding, ProxyPatchFence fence, CancellationToken token);
    ValueTask<ProxyPatchCleanup> CloseAsync(ProxyPatchRootAttempt attempt, CancellationToken token);
}
