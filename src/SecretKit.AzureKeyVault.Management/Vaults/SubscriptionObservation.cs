using System.Text.Json.Serialization;
using Azure.Core;
using Azure.ResourceManager.Resources;

namespace SecretKit.AzureKeyVault.Management;

/// <summary>Validated subscription metadata visible to the selected administrative identity.</summary>
public sealed class SubscriptionObservation
{
    internal SubscriptionObservation(SubscriptionData data)
    {
        if (!Guid.TryParse(data.SubscriptionId, out var subscriptionId) || subscriptionId == Guid.Empty ||
            data.Id is null || !data.Id.ToString().Equals($"/subscriptions/{subscriptionId:D}", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(data.DisplayName) || data.DisplayName.Any(char.IsControl) ||
            data.TenantId == Guid.Empty)
            throw new ControlledTransport.BoundaryException();
        Id = data.Id;
        SubscriptionId = subscriptionId;
        DisplayName = data.DisplayName;
        State = data.State?.ToString();
        TenantId = data.TenantId;
    }

    /// <summary>Gets the protected native subscription resource identifier.</summary>
    [JsonIgnore] public ResourceIdentifier Id { get; }
    /// <summary>Gets the protected nonempty subscription identifier.</summary>
    [JsonIgnore] public Guid SubscriptionId { get; }
    /// <summary>Gets the protected subscription display name.</summary>
    [JsonIgnore] public string DisplayName { get; }
    /// <summary>Gets the native state, if returned; it does not prove effective authority.</summary>
    [JsonIgnore] public string? State { get; }
    /// <summary>Gets the protected tenant identifier, if returned.</summary>
    [JsonIgnore] public Guid? TenantId { get; }
    /// <summary>Returns a marker without subscription or tenant coordinates.</summary>
    public override string ToString() => "[SubscriptionObservation]";
}
