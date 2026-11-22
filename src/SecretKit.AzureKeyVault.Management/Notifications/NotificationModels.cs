using System.Text.Json.Serialization;
using Azure.ResourceManager.EventGrid;
using Azure.ResourceManager.EventGrid.Models;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management;

/// <summary>Exactly one named subscription on an explicitly selected vault.</summary>
/// <param name="vault">The parent vault scope.</param>
/// <param name="subscriptionName">A 3–64 character event-subscription name using ASCII letters, digits or hyphens.</param>
public sealed class NotificationScope(VaultScope vault, string subscriptionName) : ManagementScope
{
    /// <summary>Gets the vault that owns the Event Grid subscription.</summary>
    [JsonIgnore] public VaultScope Vault { get; } = vault ?? throw new ArgumentNullException(nameof(vault));
    /// <summary>Gets the protected native subscription name.</summary>
    [JsonIgnore] public string SubscriptionName { get; } = ValidateName(subscriptionName);
    internal override string ResourceId =>
        EventSubscriptionResource.CreateResourceIdentifier(Vault.ResourceId, SubscriptionName).ToString();
    private static string ValidateName(string value) =>
        value is not null && value.Length is >= 3 and <= 64 &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c == '-')
            ? value : throw new ArgumentException("Invalid notification subscription name.");
}

/// <summary>The supported native Key Vault secret event types.</summary>
public enum VaultNotificationEvent
{
    /// <summary>A new secret version was created.</summary>
    SecretNewVersionCreated,
    /// <summary>A secret is approaching its native expiry threshold.</summary>
    SecretNearExpiry,
    /// <summary>A secret reached its native expiry.</summary>
    SecretExpired
}
/// <summary>How Event Grid derives a delivery header value.</summary>
public enum NotificationAttributeKind
{
    /// <summary>Use an explicitly supplied fixed header value.</summary>
    Static,
    /// <summary>Read a value from the selected native event source field.</summary>
    Dynamic
}
/// <summary>The observed destination category without exposing endpoint details.</summary>
public enum NotificationDestinationKind
{
    /// <summary>The response did not establish a recognized destination.</summary>
    Unknown,
    /// <summary>The native destination is an HTTP webhook.</summary>
    WebHook,
    /// <summary>The native destination is a different provider-supported type.</summary>
    Other
}

/// <summary>Owned protected header value or dynamic source field. Dispose each returned row.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1711", Justification = "Delivery attribute is the native Event Grid contract term, not a CLR metadata attribute.")]
public sealed class NotificationDeliveryAttribute : IDisposable
{
    /// <summary>Copies a bounded delivery value or dynamic source field into owned protected material.</summary>
    /// <param name="name">A 1–64 character ASCII header name using letters, digits or hyphens.</param>
    /// <param name="kind">Whether the value is static material or a dynamic source-field selector.</param>
    /// <param name="value">Nonempty value/source field, at most 4096 characters without control characters.</param>
    /// <param name="isSecret">Whether a static value is marked secret in the native configuration; ignored for dynamic attributes.</param>
    /// <exception cref="ArgumentException">The name, kind or value is invalid.</exception>
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

    internal NotificationDeliveryAttribute(string name, NotificationAttributeKind kind, SecretMaterial copiedValue, bool isSecret)
    {
        Name = name;
        Kind = kind;
        Value = copiedValue;
        IsSecret = kind == NotificationAttributeKind.Static && isSecret;
    }

    /// <summary>Gets the protected header name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets whether this attribute is static or derived from the event.</summary>
    public NotificationAttributeKind Kind { get; }
    /// <summary>Gets material owned by this attribute; dispose the attribute after use.</summary>
    [JsonIgnore] public SecretMaterial Value { get; }
    /// <summary>Gets whether the static native header is marked secret; dynamic attributes return false.</summary>
    public bool IsSecret { get; }
    internal DeliveryAttributeMapping ToNative() => Kind == NotificationAttributeKind.Static
        ? new StaticDeliveryAttributeMapping { Name = Name, Value = Value.Reveal(), IsSecret = IsSecret }
        : new DynamicDeliveryAttributeMapping { Name = Name, SourceField = Value.Reveal() };
    /// <summary>Clears this attribute's owned material; previously revealed strings remain outside its control.</summary>
    public void Dispose() => Value.Dispose();
    /// <summary>Returns a marker without header names or values.</summary>
    public override string ToString() => "[NotificationDeliveryAttribute]";
}

/// <summary>Explicit Microsoft Entra tenant and application audience for webhook delivery.</summary>
public sealed class NotificationWebhookAuthentication
{
    /// <summary>Validates an explicit tenant and a bounded application identifier or URI.</summary>
    /// <param name="tenantId">The nonempty Microsoft Entra tenant identifier.</param>
    /// <param name="applicationIdOrUri">A nonempty GUID or absolute HTTPS, API or URN audience without wildcards, whitespace, user information, query or fragment.</param>
    /// <exception cref="ArgumentOutOfRangeException">The tenant identifier is empty.</exception>
    /// <exception cref="ArgumentException">The application identifier or URI is invalid.</exception>
    public NotificationWebhookAuthentication(Guid tenantId, string applicationIdOrUri)
    {
        ArgumentOutOfRangeException.ThrowIfEqual(tenantId, Guid.Empty);
        if (string.IsNullOrEmpty(applicationIdOrUri) || applicationIdOrUri.Length > 2048 ||
            applicationIdOrUri.Any(c => char.IsWhiteSpace(c) || char.IsControl(c) || c == '*'))
            throw new ArgumentException("Invalid webhook authentication audience.", nameof(applicationIdOrUri));
        bool valid = Guid.TryParse(applicationIdOrUri, out var applicationId)
            ? applicationId != Guid.Empty
            : Uri.TryCreate(applicationIdOrUri, UriKind.Absolute, out var uri) &&
                uri.Scheme is "https" or "api" or "urn" &&
                uri.UserInfo.Length == 0 && uri.Query.Length == 0 && uri.Fragment.Length == 0;
        if (!valid) throw new ArgumentException("Invalid webhook authentication audience.", nameof(applicationIdOrUri));
        TenantId = tenantId;
        ApplicationIdOrUri = applicationIdOrUri;
    }

    /// <summary>Gets the protected Microsoft Entra tenant identifier.</summary>
    [JsonIgnore] public Guid TenantId { get; }
    /// <summary>Gets the protected application identifier or audience URI.</summary>
    [JsonIgnore] public string ApplicationIdOrUri { get; }
    /// <summary>Returns a marker without tenant or audience coordinates.</summary>
    public override string ToString() => "[NotificationWebhookAuthentication]";
}

/// <summary>
/// Only HTTPS webhook destination, optional Entra authentication, three secret event types and at most ten static/dynamic headers.
/// Update replaces destination and filter; other native properties are omitted, not reset.
/// </summary>
public sealed class NotificationConfiguration : IDisposable
{
    /// <summary>Copies an HTTPS endpoint, distinct native events and independently owned delivery attributes.</summary>
    /// <param name="endpointUrl">A bounded public HTTPS URL on the default port, without user information or a fragment. Private and loopback IP literals are rejected; trusted DNS and egress remain operator responsibilities.</param>
    /// <param name="eventTypes">One to three distinct supported secret events.</param>
    /// <param name="deliveryAttributes">Up to ten uniquely named attributes to copy; original attributes remain caller-owned.</param>
    /// <param name="webhookAuthentication">The optional explicit Microsoft Entra delivery binding; null omits authentication fields.</param>
    /// <exception cref="ArgumentException">The endpoint, events or attributes are invalid.</exception>
    /// <exception cref="ArgumentNullException">The event sequence is null.</exception>
    /// <exception cref="ObjectDisposedException">An input attribute's material has been disposed.</exception>
    public NotificationConfiguration(string endpointUrl, IEnumerable<VaultNotificationEvent> eventTypes,
        IEnumerable<NotificationDeliveryAttribute>? deliveryAttributes = null,
        NotificationWebhookAuthentication? webhookAuthentication = null)
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
        // Copy attribute material before assigning owned properties; dispose partial copies if a later input is already disposed.
        var copies = new NotificationDeliveryAttribute?[attributes.Length];
        try
        {
            for (int index = 0; index < attributes.Length; index++)
            {
                NotificationDeliveryAttribute attribute = attributes[index];
                SecretMaterial copiedValue = attribute.Value.Copy();
                copies[index] = new NotificationDeliveryAttribute(attribute.Name, attribute.Kind, copiedValue, attribute.IsSecret);
            }
            Endpoint = SecretMaterial.FromText(endpointUrl);
            EventTypes = Array.AsReadOnly(events);
            DeliveryAttributes = Array.AsReadOnly(Array.ConvertAll(copies, static copy => copy!));
            WebhookAuthentication = webhookAuthentication;
        }
        catch
        {
            foreach (NotificationDeliveryAttribute? item in copies) item?.Dispose();
            throw;
        }
    }

    /// <summary>Gets protected endpoint material owned by this configuration.</summary>
    [JsonIgnore] public SecretMaterial Endpoint { get; }
    /// <summary>Gets the copied native event filter selection.</summary>
    [JsonIgnore] public IReadOnlyList<VaultNotificationEvent> EventTypes { get; }
    /// <summary>Gets copied attributes owned and disposed by this configuration.</summary>
    [JsonIgnore] public IReadOnlyList<NotificationDeliveryAttribute> DeliveryAttributes { get; }
    /// <summary>Gets the selected Microsoft Entra webhook delivery binding, if any.</summary>
    [JsonIgnore] public NotificationWebhookAuthentication? WebhookAuthentication { get; }
    internal WebHookEventSubscriptionDestination Destination()
    {
        var value = new WebHookEventSubscriptionDestination { Endpoint = new Uri(Endpoint.Reveal()) };
        if (WebhookAuthentication is { } authentication)
        {
            value.AzureActiveDirectoryTenantId = authentication.TenantId;
            value.UriOrAzureActiveDirectoryApplicationId = authentication.ApplicationIdOrUri;
        }
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
            !Uri.TryCreate(value, UriKind.Absolute, out var uri))
            throw new ArgumentException("Invalid notification endpoint.");
        SecretKit.Internal.OriginPolicy.ValidatePublicWebhookEndpoint(uri);
    }
    /// <summary>Disposes the owned endpoint and attribute copies; input objects remain caller-owned.</summary>
    public void Dispose()
    {
        Endpoint.Dispose();
        foreach (var attribute in DeliveryAttributes) attribute.Dispose();
    }
    /// <summary>Returns a marker without endpoint, filters or delivery material.</summary>
    public override string ToString() => "[NotificationConfiguration]";
}

/// <summary>Selected metadata only; destination variants and other native settings are not exported.</summary>
public sealed class NotificationObservation
{
    internal NotificationObservation(NotificationScope scope, NativeProvisioningState state,
        NotificationDestinationKind destination, NotificationWebhookAuthentication? webhookAuthentication = null)
    {
        Scope = scope;
        ProvisioningState = state;
        Destination = destination;
        WebhookAuthentication = webhookAuthentication;
    }
    /// <summary>Gets the protected subscription coordinates.</summary>
    [JsonIgnore] public NotificationScope Scope { get; }
    /// <summary>Gets the observed native provisioning state.</summary>
    public NativeProvisioningState ProvisioningState { get; }
    /// <summary>Gets the destination category without endpoint material.</summary>
    public NotificationDestinationKind Destination { get; }
    /// <summary>Gets the validated Microsoft Entra binding returned by Event Grid; absence proves no delivery authority.</summary>
    [JsonIgnore] public NotificationWebhookAuthentication? WebhookAuthentication { get; }
    /// <summary>Always false: configured notification metadata does not prove event delivery.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "Unproven runtime delivery belongs to each notification observation's evidence contract.")]
    public bool RuntimeDeliveryProven => false;
    /// <summary>Returns a marker without subscription details.</summary>
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
    /// <summary>Gets the protected full URL owned by this result.</summary>
    [JsonIgnore] public SecretMaterial Endpoint { get; }
    /// <summary>Clears this result's material; exported managed strings cannot be recalled.</summary>
    public void Dispose() => Endpoint.Dispose();
    /// <summary>Returns a marker without the full URL.</summary>
    public override string ToString() => "[NotificationFullUrl]";
}
