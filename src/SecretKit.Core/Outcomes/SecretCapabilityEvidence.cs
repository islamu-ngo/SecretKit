namespace SecretKit.Core;

/// <summary>Implementation support, independently of a caller's permissions or deployment conformance.</summary>
public enum CapabilityAvailability
{
    /// <summary>The adapter implements the capability; this does not grant access.</summary>
    Implemented,
    /// <summary>The capability or selected variant is not supported.</summary>
    Unsupported,
    /// <summary>A supported programmable contract has not been established.</summary>
    ContractNotEstablished
}

/// <summary>Permission evidence for the selected identity and scope, not a general access grant.</summary>
public enum PermissionEvidence
{
    /// <summary>No scoped permission check has established an answer.</summary>
    NotChecked,
    /// <summary>The scoped permission check allowed the operation.</summary>
    Allowed,
    /// <summary>The scoped permission check denied the operation.</summary>
    Denied
}

/// <summary>The kind of remote effect a capability can have.</summary>
public enum SecretEffect
{
    /// <summary>Observes state without requesting a mutation.</summary>
    ReadOnly,
    /// <summary>Can create a new secret version.</summary>
    VersionCreating,
    /// <summary>Can issue credentials with a separate remote lifetime.</summary>
    CredentialIssuing,
    /// <summary>Can change provider administration or access configuration.</summary>
    Administrative,
    /// <summary>Can remove or destroy remote state.</summary>
    Destructive
}

/// <summary>Implementation support is independent of scoped permission and remote conformance.</summary>
/// <param name="CapabilityId">The adapter's capability identifier.</param>
/// <param name="Availability">Whether a supported implementation contract exists.</param>
/// <param name="Effect">The effect category callers must consider before invoking the capability.</param>
/// <param name="Permission">Scoped permission evidence; defaults to unchecked.</param>
/// <param name="RemotelyVerified">Whether remote verification has been separately established.</param>
/// <remarks>Stores supplied evidence only; construction does not contact a provider or validate deployment claims.</remarks>
public sealed record SecretCapabilityEvidence(
    string CapabilityId,
    CapabilityAvailability Availability,
    SecretEffect Effect,
    PermissionEvidence Permission = PermissionEvidence.NotChecked,
    bool RemotelyVerified = false);
