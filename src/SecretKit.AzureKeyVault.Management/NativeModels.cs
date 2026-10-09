using System.Text.Json.Serialization;
using Azure.ResourceManager.KeyVault.Models;

namespace SecretKit.AzureKeyVault.Management;

public enum VaultSku { Standard, Premium }
public enum NativeProvisioningState { Unknown, Succeeded, Failed, Canceled, Pending }
public enum SecretPermission { Get, List, Set, Delete, Recover, Backup, Restore, Purge }
public enum AccessPolicyChange { Add, Replace, Remove }
public enum PrivateConnectionState { Unknown, Pending, Approved, Rejected, Disconnected }

/// <summary>Secret-only policy; no key, certificate or storage permissions.</summary>
public sealed class SecretAccessPolicy
{
    public SecretAccessPolicy(Guid tenantId, Guid objectId, IEnumerable<SecretPermission> permissions,
        Guid? applicationId = null)
    {
        TenantId = ManagementScope.Identifier(tenantId);
        ObjectId = ManagementScope.Identifier(objectId);
        ApplicationId = applicationId is null ? null : ManagementScope.Identifier(applicationId.Value);
        ArgumentNullException.ThrowIfNull(permissions);
        var values = permissions.Distinct().ToArray();
        if (values.Length > 8 || values.Any(p => !Enum.IsDefined(p)))
        {
            throw new ArgumentException("Invalid secret permissions.");
        }

        Permissions = Array.AsReadOnly(values);
    }

    [JsonIgnore]
    public Guid TenantId { get; }
    [JsonIgnore]
    public Guid ObjectId { get; }
    [JsonIgnore]
    public Guid? ApplicationId { get; }
    public IReadOnlyList<SecretPermission> Permissions { get; }
    internal KeyVaultAccessPolicy ToNative()
    {
        var permissions = new IdentityAccessPermissions();
        foreach (var permission in Permissions)
        {
            permissions.Secrets.Add(new IdentityAccessSecretPermission(permission.ToString().ToLowerInvariant()));
        }

        return new KeyVaultAccessPolicy(TenantId, ObjectId.ToString("D"), permissions)
        {
            ApplicationId = ApplicationId
        };
    }

    public override string ToString() => "[SecretAccessPolicy]";
}

/// <summary>Explicit replacement/create settings. No credential, raw SDK model or arbitrary JSON.</summary>
public sealed class VaultConfiguration
{
    public VaultConfiguration(string location, Guid tenantId, VaultSku sku, bool enableRbacAuthorization,
        bool enablePurgeProtection, int retentionDays, bool publicNetworkAccess,
        IEnumerable<SecretAccessPolicy>? accessPolicies = null)
    {
        Location = ManagementScope.Segment(location, 50);
        TenantId = ManagementScope.Identifier(tenantId);
        if (!Enum.IsDefined(sku) || retentionDays is < 7 or > 90)
        {
            throw new ArgumentException("Invalid vault configuration.");
        }

        Sku = sku;
        EnableRbacAuthorization = enableRbacAuthorization;
        EnablePurgeProtection = enablePurgeProtection;
        RetentionDays = retentionDays;
        PublicNetworkAccess = publicNetworkAccess;
        var policies = accessPolicies?.ToArray() ?? [];
        if (policies.Length > 16 || policies.Any(p => p is null) ||
            policies.Any(p => p.TenantId != TenantId) ||
            policies.Select(p => (p.ObjectId, p.ApplicationId)).Distinct().Count() != policies.Length)
        {
            throw new ArgumentException("Invalid access-policy selection.");
        }

        AccessPolicies = Array.AsReadOnly(policies);
    }

    [JsonIgnore]
    public string Location { get; }
    [JsonIgnore]
    public Guid TenantId { get; }
    public VaultSku Sku { get; }
    public bool EnableRbacAuthorization { get; }
    public bool EnablePurgeProtection { get; }
    public int RetentionDays { get; }
    public bool PublicNetworkAccess { get; }
    [JsonIgnore]
    public IReadOnlyList<SecretAccessPolicy> AccessPolicies { get; }
    internal KeyVaultCreateOrUpdateContent ToNative(bool recover)
    {
        var properties = new KeyVaultProperties(TenantId,
            new KeyVaultSku(KeyVaultSkuFamily.A,
                Sku == VaultSku.Standard ? KeyVaultSkuName.Standard : KeyVaultSkuName.Premium))
        {
            EnableRbacAuthorization = EnableRbacAuthorization,
            EnablePurgeProtection = EnablePurgeProtection,
            EnableSoftDelete = true,
            SoftDeleteRetentionInDays = RetentionDays,
            PublicNetworkAccess = PublicNetworkAccess ? "Enabled" : "Disabled",
            CreateMode = recover ? KeyVaultCreateMode.Recover : KeyVaultCreateMode.Default
        };
        foreach (var policy in AccessPolicies)
        {
            properties.AccessPolicies.Add(policy.ToNative());
        }

        return new KeyVaultCreateOrUpdateContent(Location, properties);
    }

    public override string ToString() => "[VaultConfiguration]";
}

/// <summary>Null means omitted, not reset. Purge protection cannot be disabled by this contract.</summary>
public sealed class VaultSettingsPatch
{
    public VaultSettingsPatch(bool? enableRbacAuthorization = null, bool? enablePurgeProtection = null,
        bool? publicNetworkAccess = null)
    {
        if (enablePurgeProtection == false ||
            (enableRbacAuthorization is null && enablePurgeProtection is null && publicNetworkAccess is null))
        {
            throw new ArgumentException("An explicit supported settings change is required.");
        }

        EnableRbacAuthorization = enableRbacAuthorization;
        EnablePurgeProtection = enablePurgeProtection;
        PublicNetworkAccess = publicNetworkAccess;
    }

    public bool? EnableRbacAuthorization { get; }
    public bool? EnablePurgeProtection { get; }
    public bool? PublicNetworkAccess { get; }
    internal KeyVaultPatch ToNative() => new()
    {
        Properties = new KeyVaultPatchProperties
        {
            EnableRbacAuthorization = EnableRbacAuthorization,
            EnablePurgeProtection = EnablePurgeProtection,
            PublicNetworkAccess = PublicNetworkAccess is null ? null : PublicNetworkAccess.Value ? "Enabled" : "Disabled"
        }
    };

    public override string ToString() => "[VaultSettingsPatch]";
}

public sealed class VaultObservation(VaultScope scope, NativeProvisioningState provisioningState,
    bool? enableRbacAuthorization, bool? enablePurgeProtection, int? retentionDays)
{
    [JsonIgnore]
    public VaultScope Scope { get; } = scope;
    public NativeProvisioningState ProvisioningState { get; } = provisioningState;
    public bool? EnableRbacAuthorization { get; } = enableRbacAuthorization;
    public bool? EnablePurgeProtection { get; } = enablePurgeProtection;
    public int? RetentionDays { get; } = retentionDays;
    public bool RuntimeDeliveryProven => false;
    public override string ToString() => "[VaultObservation]";
}

public sealed class DeletedVaultObservation(DeletedVaultScope scope, DateTimeOffset? deletedOn,
    DateTimeOffset? scheduledPurgeOn, bool? purgeProtected)
{
    [JsonIgnore]
    public DeletedVaultScope Scope { get; } = scope;
    public DateTimeOffset? DeletedOn { get; } = deletedOn;
    public DateTimeOffset? ScheduledPurgeOn { get; } = scheduledPurgeOn;
    public bool? PurgeProtected { get; } = purgeProtected;
    public override string ToString() => "[DeletedVaultObservation]";
}

public sealed class PrivateConnectionObservation(PrivateConnectionScope scope, PrivateConnectionState state,
    NativeProvisioningState provisioningState)
{
    [JsonIgnore]
    public PrivateConnectionScope Scope { get; } = scope;
    public PrivateConnectionState State { get; } = state;
    public NativeProvisioningState ProvisioningState { get; } = provisioningState;
    public override string ToString() => "[PrivateConnectionObservation]";
}

public sealed class PrivateLinkObservation
{
    internal PrivateLinkObservation(string name, string? groupId, IEnumerable<string> members, IEnumerable<string> zones)
    {
        Name = name;
        GroupId = groupId;
        RequiredMembers = Array.AsReadOnly(members.ToArray());
        RequiredZoneNames = Array.AsReadOnly(zones.ToArray());
    }

    [JsonIgnore]
    public string Name { get; }
    [JsonIgnore]
    public string? GroupId { get; }
    [JsonIgnore]
    public IReadOnlyList<string> RequiredMembers { get; }
    [JsonIgnore]
    public IReadOnlyList<string> RequiredZoneNames { get; }
    public override string ToString() => "[PrivateLinkObservation]";
}

public sealed class AccessPolicyObservation(IReadOnlyList<SecretAccessPolicy> policies)
{
    [JsonIgnore]
    public IReadOnlyList<SecretAccessPolicy> Policies { get; } = Array.AsReadOnly(policies.ToArray());
    public bool RuntimeDeliveryProven => false;
    public override string ToString() => "[AccessPolicyObservation]";
}

public sealed class VaultNameAvailability(bool? available)
{
    public bool? Available { get; } = available;
    public bool NameReserved => false;
    public override string ToString() => "[VaultNameAvailability]";
}
