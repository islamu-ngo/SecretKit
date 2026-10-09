using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Product workflows whose supported programmable contract is not admitted.</summary>
public enum InfisicalUnestablishedContract
{
    ApprovalAdministration,
    AccessRequests,
    PointInTimeRecovery,
    Insights,
    WebhookAdministration
}

/// <summary>Static contract evidence, not permission, edition or remote conformance.</summary>
public static class InfisicalContractAvailability
{
    public static SecretCapabilityEvidence Describe(InfisicalUnestablishedContract contract)
    {
        if (!Enum.IsDefined(contract))
        {
            throw new ArgumentOutOfRangeException(nameof(contract));
        }

        return new SecretCapabilityEvidence($"infisical.{contract}",
            CapabilityAvailability.ContractNotEstablished, SecretEffect.Administrative,
            PermissionEvidence.NotChecked, RemotelyVerified: false);
    }
}
