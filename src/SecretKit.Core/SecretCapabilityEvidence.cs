namespace SecretKit.Core;

public enum CapabilityAvailability
{
    Implemented,
    Unsupported,
    ContractNotEstablished
}

public enum PermissionEvidence
{
    NotChecked,
    Allowed,
    Denied
}

public enum SecretEffect
{
    ReadOnly,
    VersionCreating,
    CredentialIssuing,
    Administrative,
    Destructive
}

/// <summary>Implementation support is independent of scoped permission and remote conformance.</summary>
public sealed record SecretCapabilityEvidence(
    string CapabilityId,
    CapabilityAvailability Availability,
    SecretEffect Effect,
    PermissionEvidence Permission = PermissionEvidence.NotChecked,
    bool RemotelyVerified = false);
