using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;

namespace SecretKit.Infisical.Conformance.Tests;

internal enum GatewayPatchSource { NativeProvider, ControlledFixture }
internal sealed record GatewayPatchAuthenticationInput(
    GatewayAuthenticationMethod Method,
    string? AllowedAccountIds = null, string? AllowedPrincipalArns = null,
    string? AllowedProjects = null, string? AllowedServiceAccounts = null,
    string? AllowedZones = null, GatewayGcpType? GcpType = null,
    string? AllowedNames = null, string? AllowedNamespaces = null, string? AllowedAudience = null,
    string? CaCertificate = null, string? KubernetesHost = null,
    string? TokenReviewerJwt = null, GatewayTokenReviewMode? TokenReviewMode = null,
    bool? VerifyTlsCertificate = null, string? GatewayId = null,
    string? GatewayPoolId = null, bool ClearGatewayId = false, bool ClearGatewayPoolId = false)
{
    internal GatewayAuthenticationInput Create()
    {
        using var reviewer = TokenReviewerJwt is null ? null : SecretMaterial.FromText(TokenReviewerJwt);
        return Method switch
        {
            GatewayAuthenticationMethod.Token => GatewayAuthenticationInput.Token(),
            GatewayAuthenticationMethod.Aws => GatewayAuthenticationInput.Aws(AllowedAccountIds, AllowedPrincipalArns),
            GatewayAuthenticationMethod.Gcp => GatewayAuthenticationInput.Gcp(AllowedProjects,
                AllowedServiceAccounts, AllowedZones, GcpType),
            GatewayAuthenticationMethod.Kubernetes => GatewayAuthenticationInput.Kubernetes(
                AllowedNames ?? throw new ArgumentException("Missing gateway allowed names."),
                AllowedNamespaces ?? throw new ArgumentException("Missing gateway allowed namespaces."),
                allowedAudience: AllowedAudience, caCertificate: CaCertificate,
                gatewayId: ClearGatewayId ? new(null) : GatewayId is null ? null : new(GatewayId),
                gatewayPoolId: ClearGatewayPoolId ? new(null) : GatewayPoolId is null ? null : new(GatewayPoolId),
                kubernetesHost: KubernetesHost, tokenReviewerJwt: reviewer,
                tokenReviewMode: TokenReviewMode, verifyTlsCertificate: VerifyTlsCertificate),
            _ => throw new ArgumentException("Invalid gateway authentication method.")
        };
    }
    public override string ToString() => "[GatewayPatchAuthenticationInput]";
}

internal sealed record GatewayPatchWitnessInput(string DeploymentId, string SourceProfile,
    string RootNonce, int CaseTimeoutSeconds, GatewayPatchAuthenticationInput Baseline,
    GatewayPatchAuthenticationInput Selected)
{
    public override string ToString() => "[GatewayPatchWitnessInput]";
}

internal sealed record GatewayPatchRootAttempt(
    [property: JsonRequired] string Id,
    [property: JsonRequired] string CaseIdentity,
    [property: JsonRequired] string ProviderVersion,
    [property: JsonRequired] string DeploymentId,
    [property: JsonRequired] string SourceProfile,
    [property: JsonRequired] string RootNonce,
    [property: JsonRequired] string OrganizationId,
    [property: JsonRequired] string OriginalName,
    [property: JsonRequired] string Renamed,
    [property: JsonRequired] GatewayPatchSource Source)
{
    public override string ToString() => "[GatewayPatchRootAttempt]";
}

internal sealed record GatewayPatchBinding(
    [property: JsonRequired] GatewayPatchRootAttempt Attempt,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] string ClockAuthority,
    [property: JsonRequired] string ClockEpoch,
    [property: JsonRequired] DateTimeOffset OpenedAt,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] bool RootInitiallyAbsent,
    [property: JsonRequired] bool OwnedRootCreated,
    [property: JsonRequired] bool IndependentProtectedStorageQualified,
    [property: JsonRequired] bool EffectiveAuthenticationQualified,
    [property: JsonRequired] bool DestinationValidationQualified,
    [property: JsonRequired] bool DistinctContrasts,
    [property: JsonRequired] bool BorrowedStatePreserved)
{
    public override string ToString() => "[GatewayPatchBinding]";
}

internal sealed record GatewayPatchArm(
    [property: JsonRequired] GatewayPatchBinding Binding,
    [property: JsonRequired] string AttemptId,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] string Operation,
    [property: JsonRequired] string Variant,
    [property: JsonRequired] string Case,
    [property: JsonRequired] string? GatewayId,
    [property: JsonRequired] long Cursor,
    [property: JsonRequired] DateTimeOffset ArmedAt,
    [property: JsonRequired] bool CaptureArmed)
{
    public override string ToString() => "[GatewayPatchArm]";
}

internal sealed record GatewayPatchFence(
    [property: JsonRequired] GatewayPatchArm Arm,
    [property: JsonRequired] DispatchEvidence Disposition,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] string? ProviderRequestId,
    [property: JsonRequired] string GatewayId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset SettledAt,
    [property: JsonRequired] int MatchedRequests,
    [property: JsonRequired] bool AuthenticationApplied,
    [property: JsonRequired] bool NameApplied,
    [property: JsonRequired] bool OriginalAttemptSettled,
    [property: JsonRequired] bool ExcludesLateApplication,
    [property: JsonRequired] bool NoReplay,
    [property: JsonRequired] bool ValidationActionsTerminal)
{
    public override string ToString() => "[GatewayPatchFence]";
}

internal sealed record GatewayPatchObservation(
    [property: JsonRequired] GatewayPatchBinding Binding,
    [property: JsonRequired] string GatewayId,
    [property: JsonRequired] string Phase,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset ObservedAt,
    [property: JsonRequired] bool IndependentProtectedStorageRead,
    [property: JsonRequired] bool MethodDefaultsAndOmissionsMatch,
    [property: JsonRequired] bool ReviewerRetentionOrDropMatches,
    [property: JsonRequired] bool CaRetentionOrClearMatches,
    [property: JsonRequired] bool AttachmentsMatch,
    [property: JsonRequired] bool ExactNameMatches,
    [property: JsonRequired] bool EffectiveAuthenticationMatches,
    [property: JsonRequired] bool WrongAuthorityRejected,
    [property: JsonRequired] bool ActualTokenReviewMatches,
    [property: JsonRequired] bool BorrowedStatePreserved)
{
    public override string ToString() => "[GatewayPatchObservation]";
}

internal sealed record GatewayPatchCleanup(
    [property: JsonRequired] GatewayPatchRootAttempt Attempt,
    [property: JsonRequired] bool Closed,
    [property: JsonRequired] bool OwnedRootRemoved,
    [property: JsonRequired] bool GatewaysAbsent,
    [property: JsonRequired] bool AgentsAndTokensAbsent,
    [property: JsonRequired] bool PrivateCopiesDestroyed,
    [property: JsonRequired] bool BorrowedAttachmentsPreserved,
    [property: JsonRequired] bool OriginalAttemptsSettled,
    [property: JsonRequired] bool LateCreationFenced,
    [property: JsonRequired] int RemainingRegistrations,
    [property: JsonRequired] int PendingDeliveries)
{
    public override string ToString() => "[GatewayPatchCleanup]";
}

internal interface IGatewayPatchObserver
{
    ValueTask<GatewayPatchBinding> OpenAsync(GatewayPatchRootAttempt attempt,
        GatewayPatchAuthenticationInput baseline, GatewayPatchAuthenticationInput selected, CancellationToken token);
    ValueTask<GatewayPatchArm> ArmAsync(GatewayPatchBinding binding, string attemptId, string operation,
        string variant, string boundary, string? gatewayId, CancellationToken token);
    ValueTask<GatewayPatchFence> CompleteAsync(GatewayPatchArm arm, DispatchEvidence receipt, CancellationToken token);
    ValueTask<GatewayPatchObservation> ObserveAsync(GatewayPatchBinding binding, GatewayPatchFence fence, CancellationToken token);
    ValueTask<GatewayPatchCleanup> CloseAsync(GatewayPatchRootAttempt attempt, CancellationToken token);
}
