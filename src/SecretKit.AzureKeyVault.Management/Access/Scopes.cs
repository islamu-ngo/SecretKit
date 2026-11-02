using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management;

/// <summary>Validated coordinates, never an endpoint or an authority grant.</summary>
public abstract class ManagementScope : SecretAddress
{
    internal abstract string ResourceId { get; }

    internal static string Segment(string value, int maximum = 90)
    {
        if (string.IsNullOrWhiteSpace(value) || value is "." or ".." || value.Length > maximum ||
            !value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'))
        {
            throw new ArgumentException("Invalid scope segment.");
        }

        return value;
    }

    internal static Guid Identifier(Guid value) => value != Guid.Empty ? value :
        throw new ArgumentException("A nonempty identifier is required.");
}

/// <summary>Validated subscription coordinates, not proof of access.</summary>
/// <param name="subscriptionId">The nonempty Azure subscription identifier.</param>
public sealed class SubscriptionScope(Guid subscriptionId) : ManagementScope
{
    /// <summary>Gets the protected subscription identifier.</summary>
    [JsonIgnore]
    public Guid SubscriptionId { get; } = Identifier(subscriptionId);
    internal override string ResourceId => $"/subscriptions/{SubscriptionId:D}";
}

/// <summary>A resource group within an explicitly selected subscription.</summary>
/// <param name="subscription">The parent subscription coordinates.</param>
/// <param name="resourceGroup">A bounded native resource-group segment.</param>
public sealed class ResourceGroupScope(SubscriptionScope subscription, string resourceGroup) : ManagementScope
{
    /// <summary>Gets the parent subscription; no permissions are implied.</summary>
    [JsonIgnore]
    public SubscriptionScope Subscription { get; } = subscription ?? throw new ArgumentNullException(nameof(subscription));
    /// <summary>Gets the protected resource-group name.</summary>
    [JsonIgnore]
    public string ResourceGroup { get; } = Segment(resourceGroup);
    internal override string ResourceId => $"{Subscription.ResourceId}/resourceGroups/{ResourceGroup}";
}

/// <summary>Validated ARM vault coordinates, separate from the secret data-plane origin.</summary>
/// <param name="resourceGroup">The parent resource group.</param>
/// <param name="vaultName">The native 3–24 character vault name.</param>
public sealed class VaultScope(ResourceGroupScope resourceGroup, string vaultName) : ManagementScope
{
    /// <summary>Gets the parent resource group.</summary>
    [JsonIgnore]
    public ResourceGroupScope ResourceGroup { get; } = resourceGroup ?? throw new ArgumentNullException(nameof(resourceGroup));
    /// <summary>Gets the protected native vault name.</summary>
    [JsonIgnore]
    public string VaultName { get; } = ValidateName(vaultName);
    internal override string ResourceId => $"{ResourceGroup.ResourceId}/providers/Microsoft.KeyVault/vaults/{VaultName}";
    /// <summary>Explicitly exports protected coordinates into an ordinary managed string.</summary>
    /// <returns>The ARM resource identifier; the caller owns subsequent disclosure and retention.</returns>
    public string ExportResourceId() => ResourceId;

    internal static string ValidateName(string value)
    {
        if (value is null || value.Length is < 3 or > 24 || !char.IsAsciiLetter(value[0]) ||
            !char.IsAsciiLetterOrDigit(value[^1]) || value.Contains("--", StringComparison.Ordinal) ||
            !value.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'))
        {
            throw new ArgumentException("Invalid vault name.");
        }

        return value;
    }
}

/// <summary>Coordinates for a soft-deleted vault in a selected subscription and location.</summary>
/// <param name="subscription">The parent subscription.</param>
/// <param name="location">The native location segment, at most 50 characters.</param>
/// <param name="vaultName">The validated native vault name.</param>
public sealed class DeletedVaultScope(SubscriptionScope subscription, string location, string vaultName) : ManagementScope
{
    /// <summary>Gets the selected subscription.</summary>
    [JsonIgnore]
    public SubscriptionScope Subscription { get; } = subscription ?? throw new ArgumentNullException(nameof(subscription));
    /// <summary>Gets the protected location used to address the deleted vault.</summary>
    [JsonIgnore]
    public string Location { get; } = Segment(location, 50);
    /// <summary>Gets the protected deleted-vault name.</summary>
    [JsonIgnore]
    public string VaultName { get; } = VaultScope.ValidateName(vaultName);
    internal override string ResourceId =>
        $"{Subscription.ResourceId}/providers/Microsoft.KeyVault/locations/{Location}/deletedVaults/{VaultName}";
}

/// <summary>Coordinates for an existing vault private-endpoint connection, not the endpoint itself.</summary>
/// <param name="vault">The parent vault coordinates.</param>
/// <param name="connectionName">A bounded native connection name.</param>
public sealed class PrivateConnectionScope(VaultScope vault, string connectionName) : ManagementScope
{
    /// <summary>Gets the vault that owns this connection record.</summary>
    [JsonIgnore]
    public VaultScope Vault { get; } = vault ?? throw new ArgumentNullException(nameof(vault));
    /// <summary>Gets the protected connection name.</summary>
    [JsonIgnore]
    public string ConnectionName { get; } = Segment(connectionName, 128);
    internal override string ResourceId => $"{Vault.ResourceId}/privateEndpointConnections/{ConnectionName}";
}

/// <summary>Local, single-use evidence bound to this client, scope instance and native operation.</summary>
public sealed class ManagementReceipt
{
    private readonly MutationReceiptIssuer _issuer = new();

    internal ManagementReceipt(SecretAuthority authority, ManagementScope scope, ManagementMutation operation)
    {
        Authority = authority;
        Scope = scope;
        Operation = operation;
        Target = new SecretReference(authority, scope);
        Receipt = _issuer.Create(Target);
    }

    internal SecretAuthority Authority { get; }
    internal ManagementScope Scope { get; }
    internal ManagementMutation Operation { get; }
    internal SecretReference Target { get; }
    internal MutationReceipt Receipt { get; }
    internal void BeginDispatch() => _issuer.BeginDispatch(Receipt, Target);
    internal void Record(DispatchEvidence evidence) => _issuer.Record(Receipt, evidence);
    internal int Used;
    /// <summary>Gets synchronized local dispatch knowledge, not remote authorization or an audit attestation.</summary>
    public DispatchEvidence Evidence => Receipt.Evidence;
    /// <summary>Returns only the evidence category, omitting scope and client identity.</summary>
    public override string ToString() => $"[ManagementReceipt:{Evidence}]";
}

/// <summary>The native administrative mutation to bind to a prepared receipt.</summary>
public enum ManagementMutation
{
    /// <summary>Create or replace selected vault configuration.</summary>
    CreateOrUpdateVault,
    /// <summary>Recover a vault using the native recovery create mode.</summary>
    RecoverVault,
    /// <summary>Patch selected vault settings.</summary>
    UpdateVault,
    /// <summary>Delete a vault under the provider's retention policy.</summary>
    DeleteVault,
    /// <summary>Request permanent removal of a deleted vault.</summary>
    PurgeDeletedVault,
    /// <summary>Add selected native secret access policies.</summary>
    AddAccessPolicy,
    /// <summary>Replace native secret access policies.</summary>
    ReplaceAccessPolicy,
    /// <summary>Remove selected native secret access policies.</summary>
    RemoveAccessPolicy,
    /// <summary>Approve or reject an existing private connection.</summary>
    UpdatePrivateConnection,
    /// <summary>Delete an existing private-connection record.</summary>
    DeletePrivateConnection,
    /// <summary>Create a vault-scoped role assignment.</summary>
    CreateRoleAssignment,
    /// <summary>Delete a vault-scoped role assignment.</summary>
    DeleteRoleAssignment,
    /// <summary>Create or replace a vault Event Grid subscription.</summary>
    CreateOrUpdateNotification,
    /// <summary>Patch a vault Event Grid subscription.</summary>
    UpdateNotification,
    /// <summary>Delete a vault Event Grid subscription.</summary>
    DeleteNotification
}

/// <summary>Local page, item and cooperative time budgets for administrative enumeration.</summary>
public sealed class CollectionLimits
{
    /// <summary>Creates finite enumeration limits; these are not a transactional snapshot boundary.</summary>
    /// <param name="maximumPages">The page limit, from 1 through 100.</param>
    /// <param name="maximumItems">The item limit, from 1 through 10000.</param>
    /// <param name="timeout">A positive timeout up to two minutes; null selects 30 seconds.</param>
    /// <exception cref="ArgumentOutOfRangeException">A limit is outside its supported range.</exception>
    public CollectionLimits(int maximumPages = 4, int maximumItems = 100, TimeSpan? timeout = null)
    {
        if (maximumPages is < 1 or > 100 || maximumItems is < 1 or > 10000)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumPages));
        }

        MaximumPages = maximumPages;
        MaximumItems = maximumItems;
        Timeout = timeout ?? TimeSpan.FromSeconds(30);
        if (Timeout <= TimeSpan.Zero || Timeout > TimeSpan.FromMinutes(2))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }
    }

    /// <summary>Gets the maximum pages to request.</summary>
    public int MaximumPages { get; }
    /// <summary>Gets the maximum observations to retain.</summary>
    public int MaximumItems { get; }
    /// <summary>Gets the cooperative time budget; it cannot forcibly stop a host transport.</summary>
    public TimeSpan Timeout { get; }
}

/// <summary>Copied observations with explicit completeness and failure status; not proof of runtime delivery.</summary>
/// <typeparam name="T">The native observation type.</typeparam>
/// <param name="items">Observations to copy into a read-only collection.</param>
/// <param name="complete">Whether enumeration established completion within its bounds.</param>
/// <param name="status">The bounded outcome of enumeration.</param>
public sealed class ManagementInventory<T>(IReadOnlyList<T> items, bool complete, SecretStatus status) where T : notnull
{
    /// <summary>Gets retained observations, including any partial results identified by the status.</summary>
    [JsonIgnore]
    public IReadOnlyList<T> Items { get; } = Array.AsReadOnly(items.ToArray());
    /// <summary>Gets whether collection completed; false means callers must not assume exhaustive coverage.</summary>
    public bool Complete { get; } = complete;
    /// <summary>Gets the bounded enumeration status.</summary>
    public SecretStatus Status { get; } = status;
    /// <summary>Returns status and completeness without observation contents.</summary>
    public override string ToString() => $"[ManagementInventory:{Status}:{Complete}]";
}
