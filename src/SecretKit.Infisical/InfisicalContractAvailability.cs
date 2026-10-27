using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Product workflows whose supported programmable contract is not admitted.</summary>
public enum InfisicalUnestablishedContract
{
    /// <summary>Approval administration has no admitted programmable contract.</summary>
    ApprovalAdministration,
    /// <summary>Access-request workflows have no admitted programmable contract.</summary>
    AccessRequests,
    /// <summary>Point-in-time recovery has no admitted programmable contract.</summary>
    PointInTimeRecovery,
    /// <summary>Insights have no admitted programmable contract.</summary>
    Insights,
    /// <summary>Webhook administration has no admitted programmable contract.</summary>
    WebhookAdministration
}

/// <summary>Static contract evidence, not permission, edition or remote conformance.</summary>
public static class InfisicalContractAvailability
{
    /// <summary>Returns ContractNotEstablished evidence without checking permissions or contacting the provider.</summary>
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
