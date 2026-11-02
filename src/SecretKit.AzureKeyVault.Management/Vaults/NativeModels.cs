using System.Text.Json.Serialization;
using Azure.ResourceManager.KeyVault.Models;

namespace SecretKit.AzureKeyVault.Management;

/// <summary>The native vault service tier requested by configuration.</summary>
public enum VaultSku
{
    /// <summary>Select the Standard service tier.</summary>
    Standard,
    /// <summary>Select the Premium service tier.</summary>
    Premium
}
/// <summary>Bounded native provisioning knowledge; success does not prove runtime access.</summary>
public enum NativeProvisioningState
{
    /// <summary>No recognized authoritative provisioning state was obtained.</summary>
    Unknown,
    /// <summary>The service reported completion.</summary>
    Succeeded,
    /// <summary>The service reported failure.</summary>
    Failed,
    /// <summary>The service reported cancellation, distinct from cancellation of local waiting.</summary>
    Canceled,
    /// <summary>The native operation has not established completion.</summary>
    Pending
}
/// <summary>Native secret-only access-policy permissions; these do not include key or certificate access.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1711", Justification = "Permission names the native access-policy concept, not a legacy code-access-security permission class.")]
public enum SecretPermission
{
    /// <summary>Read a secret value.</summary>
    Get,
    /// <summary>Enumerate secret metadata.</summary>
    List,
    /// <summary>Create a secret version.</summary>
    Set,
    /// <summary>Delete a secret.</summary>
    Delete,
    /// <summary>Recover a soft-deleted secret.</summary>
    Recover,
    /// <summary>Acquire a native encrypted backup.</summary>
    Backup,
    /// <summary>Restore a native backup.</summary>
    Restore,
    /// <summary>Permanently remove a deleted secret, subject to provider protections.</summary>
    Purge
}
/// <summary>The native operation applied to selected secret access policies.</summary>
public enum AccessPolicyChange
{
    /// <summary>Add the supplied policy entries.</summary>
    Add,
    /// <summary>Replace policies using the supplied entries.</summary>
    Replace,
    /// <summary>Remove the supplied policy entries.</summary>
    Remove
}
/// <summary>The provider-reported private-endpoint connection approval state.</summary>
public enum PrivateConnectionState
{
    /// <summary>No recognized state was reported.</summary>
    Unknown,
    /// <summary>Approval has not been established.</summary>
    Pending,
    /// <summary>The connection record is approved, without proof of network reachability.</summary>
    Approved,
    /// <summary>The connection record is rejected.</summary>
    Rejected,
    /// <summary>The provider reports the connection as disconnected.</summary>
    Disconnected
}

/// <summary>Secret-only policy; no key, certificate or storage permissions.</summary>
public sealed class SecretAccessPolicy
{
    /// <summary>Copies a distinct, bounded set of secret permissions for explicit native identity coordinates.</summary>
    /// <param name="tenantId">The nonempty tenant identifier.</param>
    /// <param name="objectId">The nonempty principal object identifier.</param>
    /// <param name="permissions">Secret permissions to copy and deduplicate.</param>
    /// <param name="applicationId">An optional nonempty application identifier.</param>
    /// <exception cref="ArgumentException">An identifier or permission selection is invalid.</exception>
    /// <exception cref="ArgumentNullException">The permissions sequence is null.</exception>
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

    /// <summary>Gets the protected policy tenant identifier.</summary>
    [JsonIgnore]
    public Guid TenantId { get; }
    /// <summary>Gets the protected principal object identifier.</summary>
    [JsonIgnore]
    public Guid ObjectId { get; }
    /// <summary>Gets the optional application constraint, not a selected credential.</summary>
    [JsonIgnore]
    public Guid? ApplicationId { get; }
    /// <summary>Gets the copied secret permission selection; effective permission is not proven.</summary>
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

    /// <summary>Returns a marker without identity coordinates.</summary>
    public override string ToString() => "[SecretAccessPolicy]";
}

/// <summary>Explicit replacement/create settings. No credential, raw SDK model or arbitrary JSON.</summary>
public sealed class VaultConfiguration
{
    /// <summary>Validates a complete selected vault configuration and copies its secret access policies.</summary>
    /// <param name="location">The native Azure location segment.</param>
    /// <param name="tenantId">The nonempty tenant identifier governing the vault.</param>
    /// <param name="sku">The selected native service tier.</param>
    /// <param name="enableRbacAuthorization">Whether the requested vault authorization mode is RBAC.</param>
    /// <param name="enablePurgeProtection">Whether native purge protection is requested.</param>
    /// <param name="retentionDays">The requested soft-delete retention period, from 7 through 90 days.</param>
    /// <param name="publicNetworkAccess">Whether public network access is requested.</param>
    /// <param name="accessPolicies">Up to 16 unique policies in the selected tenant; null selects an empty list.</param>
    /// <exception cref="ArgumentException">A coordinate, setting or policy selection is invalid.</exception>
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

    /// <summary>Gets the protected native location.</summary>
    [JsonIgnore]
    public string Location { get; }
    /// <summary>Gets the protected tenant identifier.</summary>
    [JsonIgnore]
    public Guid TenantId { get; }
    /// <summary>Gets the requested native service tier.</summary>
    public VaultSku Sku { get; }
    /// <summary>Gets whether RBAC authorization is requested.</summary>
    public bool EnableRbacAuthorization { get; }
    /// <summary>Gets whether native purge protection is requested.</summary>
    public bool EnablePurgeProtection { get; }
    /// <summary>Gets the requested soft-delete retention days.</summary>
    public int RetentionDays { get; }
    /// <summary>Gets whether public network access is requested, not observed reachability.</summary>
    public bool PublicNetworkAccess { get; }
    /// <summary>Gets the copied policy selection; this does not prove effective runtime permissions.</summary>
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

    /// <summary>Returns a marker without tenant, location or policy contents.</summary>
    public override string ToString() => "[VaultConfiguration]";
}

/// <summary>Null means omitted, not reset. Purge protection cannot be disabled by this contract.</summary>
public sealed class VaultSettingsPatch
{
    /// <summary>Creates a nonempty patch of the supported vault settings.</summary>
    /// <param name="enableRbacAuthorization">The RBAC mode to set, or null to omit it.</param>
    /// <param name="enablePurgeProtection">True to enable protection, or null to omit it; false is rejected.</param>
    /// <param name="publicNetworkAccess">The public-network setting to set, or null to omit it.</param>
    /// <exception cref="ArgumentException">The patch is empty or attempts to disable purge protection.</exception>
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

    /// <summary>Gets the requested RBAC mode, or null for omission.</summary>
    public bool? EnableRbacAuthorization { get; }
    /// <summary>Gets the requested enablement of purge protection, or null for omission.</summary>
    public bool? EnablePurgeProtection { get; }
    /// <summary>Gets the requested public-network mode, or null for omission.</summary>
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

    /// <summary>Returns a marker without patch contents.</summary>
    public override string ToString() => "[VaultSettingsPatch]";
}

/// <summary>Selected vault control-plane metadata, not proof that an intended identity can obtain secrets.</summary>
/// <param name="scope">The observed vault coordinates.</param>
/// <param name="provisioningState">The bounded native provisioning state.</param>
/// <param name="enableRbacAuthorization">Reported RBAC mode, or null when absent.</param>
/// <param name="enablePurgeProtection">Reported purge protection, or null when absent.</param>
/// <param name="retentionDays">Reported retention days, or null when absent.</param>
public sealed class VaultObservation(VaultScope scope, NativeProvisioningState provisioningState,
    bool? enableRbacAuthorization, bool? enablePurgeProtection, int? retentionDays)
{
    /// <summary>Gets the protected observed vault scope.</summary>
    [JsonIgnore]
    public VaultScope Scope { get; } = scope;
    /// <summary>Gets reported provisioning knowledge.</summary>
    public NativeProvisioningState ProvisioningState { get; } = provisioningState;
    /// <summary>Gets the reported RBAC mode, if present.</summary>
    public bool? EnableRbacAuthorization { get; } = enableRbacAuthorization;
    /// <summary>Gets the reported purge protection, if present.</summary>
    public bool? EnablePurgeProtection { get; } = enablePurgeProtection;
    /// <summary>Gets reported soft-delete retention days, if present.</summary>
    public int? RetentionDays { get; } = retentionDays;
    /// <summary>Always false: control-plane metadata does not establish intended-identity runtime delivery.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "The absence of runtime-delivery proof belongs to each vault observation's evidence contract.")]
    public bool RuntimeDeliveryProven => false;
    /// <summary>Returns a marker without vault coordinates.</summary>
    public override string ToString() => "[VaultObservation]";
}

/// <summary>Native soft-deleted vault metadata without a recovery or purge guarantee.</summary>
/// <param name="scope">The deleted-vault coordinates.</param>
/// <param name="deletedOn">The reported deletion time, if present.</param>
/// <param name="scheduledPurgeOn">The reported scheduled purge time, if present.</param>
/// <param name="purgeProtected">The reported protection setting, if present.</param>
public sealed class DeletedVaultObservation(DeletedVaultScope scope, DateTimeOffset? deletedOn,
    DateTimeOffset? scheduledPurgeOn, bool? purgeProtected)
{
    /// <summary>Gets the protected deleted-vault scope.</summary>
    [JsonIgnore]
    public DeletedVaultScope Scope { get; } = scope;
    /// <summary>Gets the reported deletion time.</summary>
    public DateTimeOffset? DeletedOn { get; } = deletedOn;
    /// <summary>Gets the reported purge schedule, not a guarantee of disappearance.</summary>
    public DateTimeOffset? ScheduledPurgeOn { get; } = scheduledPurgeOn;
    /// <summary>Gets reported purge protection, or null when absent.</summary>
    public bool? PurgeProtected { get; } = purgeProtected;
    /// <summary>Returns a marker without deleted-vault coordinates.</summary>
    public override string ToString() => "[DeletedVaultObservation]";
}

/// <summary>Control-plane private-connection state, not a connectivity test.</summary>
/// <param name="scope">The observed connection coordinates.</param>
/// <param name="state">The native approval state.</param>
/// <param name="provisioningState">The native provisioning state.</param>
public sealed class PrivateConnectionObservation(PrivateConnectionScope scope, PrivateConnectionState state,
    NativeProvisioningState provisioningState)
{
    /// <summary>Gets the protected private-connection scope.</summary>
    [JsonIgnore]
    public PrivateConnectionScope Scope { get; } = scope;
    /// <summary>Gets the reported approval state.</summary>
    public PrivateConnectionState State { get; } = state;
    /// <summary>Gets the reported provisioning state.</summary>
    public NativeProvisioningState ProvisioningState { get; } = provisioningState;
    /// <summary>Returns a marker without connection coordinates.</summary>
    public override string ToString() => "[PrivateConnectionObservation]";
}

/// <summary>Native private-link resource requirements; the SDK does not provision endpoints or DNS.</summary>
public sealed class PrivateLinkObservation
{
    internal PrivateLinkObservation(string name, string? groupId, IEnumerable<string> members, IEnumerable<string> zones)
    {
        Name = name;
        GroupId = groupId;
        RequiredMembers = Array.AsReadOnly(members.ToArray());
        RequiredZoneNames = Array.AsReadOnly(zones.ToArray());
    }

    /// <summary>Gets the protected private-link resource name.</summary>
    [JsonIgnore]
    public string Name { get; }
    /// <summary>Gets the provider's group identifier, if present.</summary>
    [JsonIgnore]
    public string? GroupId { get; }
    /// <summary>Gets the copied required member names.</summary>
    [JsonIgnore]
    public IReadOnlyList<string> RequiredMembers { get; }
    /// <summary>Gets the copied required DNS zone names, not verified DNS configuration.</summary>
    [JsonIgnore]
    public IReadOnlyList<string> RequiredZoneNames { get; }
    /// <summary>Returns a marker without private-link metadata.</summary>
    public override string ToString() => "[PrivateLinkObservation]";
}

/// <summary>Copied native access policies without effective-permission verification.</summary>
/// <param name="policies">The policy entries observed in the response.</param>
public sealed class AccessPolicyObservation(IReadOnlyList<SecretAccessPolicy> policies)
{
    /// <summary>Gets copied policy metadata; identities remain protected.</summary>
    [JsonIgnore]
    public IReadOnlyList<SecretAccessPolicy> Policies { get; } = Array.AsReadOnly(policies.ToArray());
    /// <summary>Always false: configured policy does not prove that an intended identity can read a value.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "The absence of runtime-delivery proof belongs to each policy observation's evidence contract.")]
    public bool RuntimeDeliveryProven => false;
    /// <summary>Returns a marker without policy contents.</summary>
    public override string ToString() => "[AccessPolicyObservation]";
}

/// <summary>A native name-availability observation that does not reserve the name.</summary>
/// <param name="available">The provider's availability value, or null when not established.</param>
public sealed class VaultNameAvailability(bool? available)
{
    /// <summary>Gets reported availability, which may change immediately after observation.</summary>
    public bool? Available { get; } = available;
    /// <summary>Always false: the check creates no reservation.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "Unreserved availability belongs to each name-check result, not a global provider capability.")]
    public bool NameReserved => false;
    /// <summary>Returns a marker without the requested name.</summary>
    public override string ToString() => "[VaultNameAvailability]";
}
