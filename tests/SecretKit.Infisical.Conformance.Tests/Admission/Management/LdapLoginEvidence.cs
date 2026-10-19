using System.Security.Cryptography;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal enum LdapLoginSource { NativeProvider, ControlledFixture }
internal enum LdapServiceCredential { Original, Rotated }

internal sealed record LdapDirectoryAttempt(
    [property: JsonRequired] string Id,
    [property: JsonRequired] string CaseIdentity,
    [property: JsonRequired] string ProviderVersion,
    [property: JsonRequired] string DeploymentId,
    [property: JsonRequired] string OrganizationId,
    [property: JsonRequired] string RootNonce,
    [property: JsonRequired] string Url,
    [property: JsonRequired] string BindDn,
    [property: JsonRequired] string SearchBase,
    [property: JsonRequired] string Username,
    [property: JsonRequired] LdapLoginSource Source)
{
    public override string ToString() => "[LdapDirectoryAttempt]";
}

// Caller-owned private command material. Never put these values into evidence,
// report DTOs or formatted messages. The bridge must clear its private copies.
internal sealed class LdapDirectoryCredentials : IDisposable
{
    internal LdapDirectoryCredentials(SecretMaterial original, SecretMaterial rotated,
        SecretMaterial wrongService, SecretMaterial user, SecretMaterial wrongUser)
    {
        var copies = new List<SecretMaterial>(5);
        try
        {
            foreach (SecretMaterial input in new[] { original, rotated, wrongService, user, wrongUser })
                copies.Add(input.Copy());
            Original = copies[0];
            Rotated = copies[1];
            WrongService = copies[2];
            User = copies[3];
            WrongUser = copies[4];
            CorrelationKey = RandomNumberGenerator.GetBytes(32);
        }
        catch
        {
            foreach (SecretMaterial copy in copies) copy.Dispose();
            throw;
        }
    }
    internal SecretMaterial Original { get; }
    internal SecretMaterial Rotated { get; }
    internal SecretMaterial WrongService { get; }
    internal SecretMaterial User { get; }
    internal SecretMaterial WrongUser { get; }
    internal byte[] CorrelationKey { get; }
    public void Dispose()
    {
        Original.Dispose();
        Rotated.Dispose();
        WrongService.Dispose();
        User.Dispose();
        WrongUser.Dispose();
        CryptographicOperations.ZeroMemory(CorrelationKey);
    }
    public override string ToString() => "[LdapDirectoryCredentials]";
}

internal sealed record LdapDirectoryBinding(
    [property: JsonRequired] LdapDirectoryAttempt Attempt,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] string ClockAuthority,
    [property: JsonRequired] string ClockEpoch,
    [property: JsonRequired] DateTimeOffset OpenedAt,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] bool OwnedRootCreated,
    [property: JsonRequired] bool RootInitiallyAbsent,
    [property: JsonRequired] bool ServiceBindAccepted,
    [property: JsonRequired] bool WrongServiceBindRejected,
    [property: JsonRequired] bool UserBindAccepted,
    [property: JsonRequired] bool WrongUserBindRejected)
{
    public override string ToString() => "[LdapDirectoryBinding]";
}

internal sealed record LdapDirectoryRotation(
    [property: JsonRequired] LdapDirectoryBinding Binding,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] bool OriginalServiceRejected,
    [property: JsonRequired] bool RotatedServiceAccepted,
    [property: JsonRequired] bool UserCredentialUnchanged,
    [property: JsonRequired] bool OwnedRootOnly)
{
    public override string ToString() => "[LdapDirectoryRotation]";
}

internal sealed record LdapLoginAttempt(
    [property: JsonRequired] LdapDirectoryBinding Directory,
    [property: JsonRequired] string Id,
    [property: JsonRequired] string IdentityId,
    [property: JsonRequired] string MembershipId,
    [property: JsonRequired] string TemplateId,
    [property: JsonRequired] LdapServiceCredential ServiceCredential,
    [property: JsonRequired] bool WrongUser)
{
    public override string ToString() => "[LdapLoginAttempt]";
}

internal sealed record LdapLoginArm(
    [property: JsonRequired] LdapLoginAttempt Attempt,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] long Cursor,
    [property: JsonRequired] DateTimeOffset ArmedAt,
    [property: JsonRequired] bool CaptureArmed)
{
    public override string ToString() => "[LdapLoginArm]";
}

internal sealed record LdapLoginFence(
    [property: JsonRequired] LdapLoginArm Arm,
    [property: JsonRequired] DispatchEvidence Disposition,
    [property: JsonRequired] SecretStatus Status,
    [property: JsonRequired] string ProviderRequestId,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] bool ServiceBindAccepted,
    [property: JsonRequired] bool UserBindAttempted,
    [property: JsonRequired] bool UserBindAccepted,
    [property: JsonRequired] bool TokenIssued,
    [property: JsonRequired] string? TokenMetadataId,
    [property: JsonRequired] DateTimeOffset? LastLoginAt,
    [property: JsonRequired] string? LastLoginAuthMethod,
    [property: JsonRequired] int MatchedRequests,
    [property: JsonRequired] int MatchedIssuances,
    [property: JsonRequired] bool ProviderClockObserved,
    [property: JsonRequired] bool ExcludesLateCommit,
    [property: JsonRequired] string? CredentialWitness = null)
{
    public override string ToString() => "[LdapLoginFence]";
}

internal sealed record LdapLoginVisibility(
    [property: JsonRequired] LdapDirectoryBinding Directory,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] string Watermark,
    [property: JsonRequired] DateTimeOffset ClosedAt,
    [property: JsonRequired] int LoginEvents,
    [property: JsonRequired] bool Complete,
    [property: JsonRequired] bool NoFurtherLogins,
    [property: JsonRequired] bool SearchVisibilityEstablished)
{
    public override string ToString() => "[LdapLoginVisibility]";
}

internal sealed record LdapTemplateAttempt(
    [property: JsonRequired] LdapDirectoryBinding Directory,
    [property: JsonRequired] string Id,
    [property: JsonRequired] string Operation,
    [property: JsonRequired] string Member,
    [property: JsonRequired] string Variant,
    [property: JsonRequired] string Case,
    [property: JsonRequired] string TemplateName,
    [property: JsonRequired] string? TemplateId,
    [property: JsonRequired] LdapServiceCredential? SelectedCredential)
{
    public override string ToString() => "[LdapTemplateAttempt]";
}

internal sealed record LdapTemplateArm(
    [property: JsonRequired] LdapTemplateAttempt Attempt,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] long Cursor,
    [property: JsonRequired] bool CaptureArmed)
{
    public override string ToString() => "[LdapTemplateArm]";
}

internal sealed record LdapTemplateFence(
    [property: JsonRequired] LdapTemplateArm Arm,
    [property: JsonRequired] DispatchEvidence Disposition,
    [property: JsonRequired] string? TemplateId,
    [property: JsonRequired] string? ProviderRequestId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] int MatchedMutations,
    [property: JsonRequired] bool Applied,
    [property: JsonRequired] bool ExcludesLateCommit,
    [property: JsonRequired] bool NoReplay)
{
    public override string ToString() => "[LdapTemplateFence]";
}

internal sealed record LdapDirectoryCleanup(
    [property: JsonRequired] LdapDirectoryAttempt Attempt,
    [property: JsonRequired] bool Closed,
    [property: JsonRequired] bool OwnedRootRemoved,
    [property: JsonRequired] bool UnrelatedRootsPreserved,
    [property: JsonRequired] bool CredentialsDestroyed,
    [property: JsonRequired] bool MutationSettled,
    [property: JsonRequired] bool LateCreationFenced,
    [property: JsonRequired] int RemainingRegistrations,
    [property: JsonRequired] int PendingDeliveries)
{
    public override string ToString() => "[LdapDirectoryCleanup]";
}

internal interface ILdapLoginObserver
{
    ValueTask<LdapDirectoryBinding> OpenAsync(LdapDirectoryAttempt attempt,
        LdapDirectoryCredentials credentials, CancellationToken token);
    ValueTask<LdapDirectoryRotation> RotateAsync(LdapDirectoryBinding directory, CancellationToken token);
    ValueTask<LdapLoginArm> ArmAsync(LdapLoginAttempt attempt, CancellationToken token);
    ValueTask<LdapLoginFence> CompleteAsync(LdapLoginArm arm, DispatchEvidence receipt,
        SecretStatus status, CancellationToken token);
    ValueTask<LdapTemplateArm> ArmTemplateAsync(LdapTemplateAttempt attempt, CancellationToken token);
    ValueTask<LdapTemplateFence> CompleteTemplateAsync(LdapTemplateArm arm,
        DispatchEvidence receipt, CancellationToken token);
    ValueTask<LdapLoginVisibility> SealAsync(LdapDirectoryBinding directory, CancellationToken token);
    ValueTask<LdapDirectoryCleanup> CloseAsync(LdapDirectoryAttempt attempt, CancellationToken token);
}
