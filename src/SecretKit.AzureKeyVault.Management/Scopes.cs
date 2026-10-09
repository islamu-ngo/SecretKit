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

public sealed class SubscriptionScope(Guid subscriptionId) : ManagementScope
{
    [JsonIgnore]
    public Guid SubscriptionId { get; } = Identifier(subscriptionId);
    internal override string ResourceId => $"/subscriptions/{SubscriptionId:D}";
}

public sealed class ResourceGroupScope(SubscriptionScope subscription, string resourceGroup) : ManagementScope
{
    [JsonIgnore]
    public SubscriptionScope Subscription { get; } = subscription ?? throw new ArgumentNullException(nameof(subscription));
    [JsonIgnore]
    public string ResourceGroup { get; } = Segment(resourceGroup);
    internal override string ResourceId => $"{Subscription.ResourceId}/resourceGroups/{ResourceGroup}";
}

public sealed class VaultScope(ResourceGroupScope resourceGroup, string vaultName) : ManagementScope
{
    [JsonIgnore]
    public ResourceGroupScope ResourceGroup { get; } = resourceGroup ?? throw new ArgumentNullException(nameof(resourceGroup));
    [JsonIgnore]
    public string VaultName { get; } = ValidateName(vaultName);
    internal override string ResourceId => $"{ResourceGroup.ResourceId}/providers/Microsoft.KeyVault/vaults/{VaultName}";
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

public sealed class DeletedVaultScope(SubscriptionScope subscription, string location, string vaultName) : ManagementScope
{
    [JsonIgnore]
    public SubscriptionScope Subscription { get; } = subscription ?? throw new ArgumentNullException(nameof(subscription));
    [JsonIgnore]
    public string Location { get; } = Segment(location, 50);
    [JsonIgnore]
    public string VaultName { get; } = VaultScope.ValidateName(vaultName);
    internal override string ResourceId =>
        $"{Subscription.ResourceId}/providers/Microsoft.KeyVault/locations/{Location}/deletedVaults/{VaultName}";
}

public sealed class PrivateConnectionScope(VaultScope vault, string connectionName) : ManagementScope
{
    [JsonIgnore]
    public VaultScope Vault { get; } = vault ?? throw new ArgumentNullException(nameof(vault));
    [JsonIgnore]
    public string ConnectionName { get; } = Segment(connectionName, 128);
    internal override string ResourceId => $"{Vault.ResourceId}/privateEndpointConnections/{ConnectionName}";
}

/// <summary>Local, single-use evidence bound to this client, scope instance and native operation.</summary>
public sealed class ManagementReceipt
{
    internal ManagementReceipt(SecretAuthority authority, ManagementScope scope, ManagementMutation operation)
    {
        Authority = authority;
        Scope = scope;
        Operation = operation;
        Target = new SecretReference(authority, scope);
        Receipt = new MutationReceipt(Target);
    }

    internal SecretAuthority Authority { get; }
    internal ManagementScope Scope { get; }
    internal ManagementMutation Operation { get; }
    internal SecretReference Target { get; }
    internal MutationReceipt Receipt { get; }
    internal int Used;
    public DispatchEvidence Evidence => Receipt.Evidence;
    public override string ToString() => $"[ManagementReceipt:{Evidence}]";
}

public enum ManagementMutation
{
    CreateOrUpdateVault, RecoverVault, UpdateVault, DeleteVault, PurgeDeletedVault,
    AddAccessPolicy, ReplaceAccessPolicy, RemoveAccessPolicy, UpdatePrivateConnection, DeletePrivateConnection,
    CreateRoleAssignment, DeleteRoleAssignment,
    CreateOrUpdateNotification, UpdateNotification, DeleteNotification
}

public sealed class CollectionLimits
{
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

    public int MaximumPages { get; }
    public int MaximumItems { get; }
    public TimeSpan Timeout { get; }
}

public sealed class ManagementInventory<T>(IReadOnlyList<T> items, bool complete, SecretStatus status) where T : notnull
{
    [JsonIgnore]
    public IReadOnlyList<T> Items { get; } = Array.AsReadOnly(items.ToArray());
    public bool Complete { get; } = complete;
    public SecretStatus Status { get; } = status;
    public override string ToString() => $"[ManagementInventory:{Status}:{Complete}]";
}
