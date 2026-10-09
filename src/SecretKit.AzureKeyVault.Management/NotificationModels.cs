using System.Text.Json.Serialization;
using Azure.ResourceManager.EventGrid.Models;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management;

/// <summary>Exactly one named subscription on an explicitly selected vault.</summary>
public sealed class NotificationScope(VaultScope vault, string subscriptionName) : ManagementScope
{
    [JsonIgnore] public VaultScope Vault { get; } = vault ?? throw new ArgumentNullException(nameof(vault));
    [JsonIgnore] public string SubscriptionName { get; } = ValidateName(subscriptionName);
    internal override string ResourceId =>
        $"{Vault.ResourceId}/providers/Microsoft.EventGrid/eventSubscriptions/{SubscriptionName}";
    private static string ValidateName(string value) =>
        value is not null && value.Length is >= 3 and <= 64 &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c == '-')
            ? value : throw new ArgumentException("Invalid notification subscription name.");
}

public enum VaultNotificationEvent { SecretNewVersionCreated, SecretNearExpiry, SecretExpired }
public enum NotificationAttributeKind { Static, Dynamic }
public enum NotificationDestinationKind { Unknown, WebHook, Other }

/// <summary>Owned protected header value or dynamic source field. Dispose each returned row.</summary>
public sealed class NotificationDeliveryAttribute : IDisposable
{
    public NotificationDeliveryAttribute(string name, NotificationAttributeKind kind, string value, bool isSecret = true)
    {
        if (name is null || name.Length is < 1 or > 64 ||
            !name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') ||
            !Enum.IsDefined(kind) || string.IsNullOrEmpty(value) || value.Length > 4096 ||
            value.Any(char.IsControl))
            throw new ArgumentException("Invalid delivery attribute.");
        Name = name;
        Kind = kind;
        Value = SecretMaterial.FromText(value);
        IsSecret = kind == NotificationAttributeKind.Static && isSecret;
    }

    [JsonIgnore] public string Name { get; }
    public NotificationAttributeKind Kind { get; }
    [JsonIgnore] public SecretMaterial Value { get; }
    public bool IsSecret { get; }
    internal DeliveryAttributeMapping ToNative() => Kind == NotificationAttributeKind.Static
        ? new StaticDeliveryAttributeMapping { Name = Name, Value = Value.Reveal(), IsSecret = IsSecret }
        : new DynamicDeliveryAttributeMapping { Name = Name, SourceField = Value.Reveal() };
    public void Dispose() => Value.Dispose();
    public override string ToString() => "[NotificationDeliveryAttribute]";
}

/// <summary>
/// Only HTTPS webhook destination, three secret event types and at most ten static/dynamic headers.
/// Update replaces destination and filter; other native properties are omitted, not reset.
/// </summary>
public sealed class NotificationConfiguration : IDisposable
{
    public NotificationConfiguration(string endpointUrl, IEnumerable<VaultNotificationEvent> eventTypes,
        IEnumerable<NotificationDeliveryAttribute>? deliveryAttributes = null)
    {
        ValidateEndpoint(endpointUrl);
        ArgumentNullException.ThrowIfNull(eventTypes);
        var events = eventTypes.Take(4).ToArray();
        if (events.Length is < 1 or > 3 || events.Any(e => !Enum.IsDefined(e)) ||
            events.Distinct().Count() != events.Length)
            throw new ArgumentException("Select one to three distinct secret events.");
        var attributes = deliveryAttributes?.Take(11).ToArray() ?? [];
        if (attributes.Length > 10 || attributes.Any(a => a is null) ||
            attributes.Select(a => a.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != attributes.Length)
            throw new ArgumentException("Invalid delivery attributes.");
        // Validate all values before acquiring owned copies.
        var values = attributes.Select(a => a.Value.Reveal()).ToArray();
        Endpoint = SecretMaterial.FromText(endpointUrl);
        EventTypes = Array.AsReadOnly(events);
        DeliveryAttributes = Array.AsReadOnly(attributes.Select((a, i) =>
            new NotificationDeliveryAttribute(a.Name, a.Kind, values[i], a.IsSecret)).ToArray());
    }

    [JsonIgnore] public SecretMaterial Endpoint { get; }
    [JsonIgnore] public IReadOnlyList<VaultNotificationEvent> EventTypes { get; }
    [JsonIgnore] public IReadOnlyList<NotificationDeliveryAttribute> DeliveryAttributes { get; }
    internal WebHookEventSubscriptionDestination Destination()
    {
        var value = new WebHookEventSubscriptionDestination { Endpoint = new Uri(Endpoint.Reveal()) };
        foreach (var attribute in DeliveryAttributes) value.DeliveryAttributeMappings.Add(attribute.ToNative());
        return value;
    }
    internal EventSubscriptionFilter Filter()
    {
        var value = new EventSubscriptionFilter();
        foreach (var type in EventTypes) value.IncludedEventTypes.Add("Microsoft.KeyVault." + type);
        return value;
    }
    internal static void ValidateEndpoint(string? value)
    {
        if (value is null || value.Length is < 1 or > 4096 || value.Any(char.IsControl) ||
            !Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
            uri.Host.Length == 0 || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0)
            throw new ArgumentException("Invalid notification endpoint.");
    }
    public void Dispose()
    {
        Endpoint.Dispose();
        foreach (var attribute in DeliveryAttributes) attribute.Dispose();
    }
    public override string ToString() => "[NotificationConfiguration]";
}

/// <summary>Selected metadata only; destination variants and other native settings are not exported.</summary>
public sealed class NotificationObservation
{
    internal NotificationObservation(NotificationScope scope, NativeProvisioningState state,
        NotificationDestinationKind destination)
    {
        Scope = scope;
        ProvisioningState = state;
        Destination = destination;
    }
    [JsonIgnore] public NotificationScope Scope { get; }
    public NativeProvisioningState ProvisioningState { get; }
    public NotificationDestinationKind Destination { get; }
    public bool RuntimeDeliveryProven => false;
    public override string ToString() => "[NotificationObservation]";
}

/// <summary>Caller-owned full URL. Revealing it creates an ordinary plaintext string.</summary>
public sealed class NotificationFullUrl : IDisposable
{
    internal NotificationFullUrl(Uri? endpoint)
    {
        var value = endpoint?.OriginalString;
        NotificationConfiguration.ValidateEndpoint(value);
        Endpoint = SecretMaterial.FromText(value);
    }
    [JsonIgnore] public SecretMaterial Endpoint { get; }
    public void Dispose() => Endpoint.Dispose();
    public override string ToString() => "[NotificationFullUrl]";
}
