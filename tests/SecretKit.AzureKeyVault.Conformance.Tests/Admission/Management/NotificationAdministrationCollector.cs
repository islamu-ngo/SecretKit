using System.ClientModel.Primitives;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Azure.ResourceManager.EventGrid;
using Azure.ResourceManager.EventGrid.Models;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Independent native metadata only. The host owns credentials and transports.
// Labels, HTTP success and provisioning metadata qualify neither a principal nor
// egress, async mutation settlement, event filtering, exclusions or delivery.
internal sealed class NotificationAdministrationCollector
{
    internal const string ArmOrigin = "https://management.azure.com";
    internal const string Revision = "2025-02-15";
    internal enum ReadKind { Metadata, Configuration, Inventory, DeliveryAttributes, FullUrl }
    internal enum QueryKind
    {
        CreateOrUpdateNotification, DeleteNotification, GetNotification, GetNotificationDeliveryAttributes,
        GetNotificationFullUrl, ListNotifications, UpdateNotification,
        OperationCreateOrUpdateNotification, OperationUpdateNotification, OperationDeleteNotification
    }
    internal enum Access { Metadata, ProtectedConfiguration }
    internal enum Presence { Omitted, Null, Value }
    internal enum Failure { None, Boundary, Budget, Denied, Unavailable, ProviderError, Deadline }
    internal sealed record Limits(int MaximumPages, int MaximumItems, int MaximumResponseBytes,
        int MaximumRowBytes, int MaximumNodes, TimeSpan Timeout);
    internal sealed record Authority([property: JsonIgnore] string Label,
        [property: JsonIgnore] TokenCredential Credential, [property: JsonIgnore] HttpPipelineTransport Transport,
        [property: JsonIgnore] Access Access)
    {
        public override string ToString() => "[NotificationMetadataAuthority]";
    }
    internal sealed record Binding([property: JsonIgnore] FixtureSelector Selector,
        [property: JsonIgnore] Guid LeaseId, [property: JsonIgnore] QueryKind Query,
        [property: JsonIgnore] ReadKind Read, [property: JsonIgnore] ManagementScope Scope)
    {
        public override string ToString() => "[NotificationMetadataBinding]";
    }
    internal sealed class Window(Binding binding, DateTimeOffset armedAt)
    {
        internal Binding Binding { get; } = binding;
        internal DateTimeOffset ArmedAt { get; } = armedAt;
        internal Guid Id { get; } = Guid.NewGuid();
        public override string ToString() => "[NotificationMetadataWindow]";
    }
    internal sealed class AttributeObservation : IDisposable
    {
        internal required string Name { get; init; }
        internal required NotificationAttributeKind Kind { get; init; }
        internal required Presence ValuePresence { get; init; }
        internal required Presence SecretFlagPresence { get; init; }
        internal required bool? IsSecret { get; init; }
        internal required SecretMaterial? Value { get; init; }
        public void Dispose() => Value?.Dispose();
        public override string ToString() => "[NotificationAttributeMetadata]";
    }
    internal sealed class Configuration : IDisposable
    {
        internal required SecretMaterial Endpoint { get; init; }
        internal required IReadOnlyList<VaultNotificationEvent> Events { get; init; }
        internal required Presence AttributesPresence { get; init; }
        internal required IReadOnlyList<AttributeObservation>? Attributes { get; init; }
        public void Dispose()
        {
            Endpoint.Dispose();
            if (Attributes is not null) foreach (var attribute in Attributes) attribute.Dispose();
        }
        public override string ToString() => "[NotificationConfigurationMetadata]";
    }
    internal sealed class NotificationRow : IDisposable
    {
        internal required string ResourceId { get; init; }
        internal required string Name { get; init; }
        internal required string Topic { get; init; }
        internal required string? Version { get; init; }
        internal required string? NativeState { get; init; }
        internal required NativeProvisioningState ProvisioningState { get; init; }
        internal required NotificationDestinationKind Destination { get; init; }
        internal required Presence EventsPresence { get; init; }
        internal required IReadOnlyList<string> EventTypes { get; init; }
        internal required Presence AttributesPresence { get; init; }
        internal required IReadOnlyList<AttributeObservation> Attributes { get; init; }
        // Only a single protected metadata response can supply this projection.
        // Action reads never fill missing fields or establish version atomicity.
        internal required Configuration? Configuration { get; init; }
        public void Dispose()
        {
            Configuration?.Dispose();
            foreach (var attribute in Attributes) attribute.Dispose();
        }
        public override string ToString() => "[NotificationResourceMetadata]";
    }
    internal sealed class Measurement : IDisposable
    {
        internal required Binding Binding { get; init; }
        internal required Guid WindowId { get; init; }
        internal required DateTimeOffset ArmedAt { get; init; }
        internal required DateTimeOffset StartedAt { get; init; }
        internal required DateTimeOffset FinishedAt { get; init; }
        internal required string Identity { get; init; }
        internal required Access Access { get; init; }
        internal string ApiRevision => Revision;
        internal required Failure Failure { get; init; }
        internal required SecretStatus Status { get; init; }
        internal required int Pages { get; init; }
        internal required IReadOnlyList<string> NativeRequestIds { get; init; }
        internal required IReadOnlyList<NotificationRow> Notifications { get; init; }
        internal required IReadOnlyList<AttributeObservation> Attributes { get; init; }
        internal required SecretMaterial? FullUrl { get; init; }
        internal bool ResponseComplete => Failure == Failure.None;
        // Enumeration completeness does not turn hidden attribute values or
        // nullable secret flags into complete protected configuration.
        internal bool InventoryComplete => ResponseComplete && Status == SecretStatus.Success && IsInventory(Binding.Read);
        internal bool ProtectedValuesComplete => ResponseComplete && Status == SecretStatus.Success && (Binding.Read switch
        {
            ReadKind.FullUrl => FullUrl is not null,
            ReadKind.Configuration => Notifications.Count == 1 && Notifications[0].Configuration is not null,
            ReadKind.DeliveryAttributes => InventoryComplete && Attributes.All(a => a.Value is not null &&
                (a.Kind == NotificationAttributeKind.Dynamic ? a.SecretFlagPresence == Presence.Omitted :
                    a.SecretFlagPresence == Presence.Value && a.IsSecret is not null)),
            _ => false
        });
        internal bool? ResourceAbsent => ResponseComplete && IsConcrete(Binding.Read) ? Status == SecretStatus.Absent : null;
        internal bool PrincipalQualified => false;
        internal bool EgressQualified => false;
        internal bool AsyncSettlementProven => false;
        internal bool RuntimeDeliveryProven => false;
        public void Dispose()
        {
            foreach (var row in Notifications) row.Dispose();
            foreach (var attribute in Attributes) attribute.Dispose();
            FullUrl?.Dispose();
        }
        public override string ToString() => "[NotificationMetadataMeasurement]";
    }

    private sealed class Registration(long timestamp)
    {
        internal long Timestamp { get; } = timestamp;
        internal bool Consumed;
    }
    private readonly Authority metadata;
    private readonly Authority? protectedConfiguration;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly object gate = new();
    private readonly Dictionary<Window, Registration> windows = [];
    private readonly HashSet<Guid> nonces = [];

    internal NotificationAdministrationCollector(Authority metadata, Authority? protectedConfiguration,
        Limits limits, TimeProvider? time = null)
    {
        if (!ValidAuthority(metadata, Access.Metadata) ||
            protectedConfiguration is not null && !ValidAuthority(protectedConfiguration, Access.ProtectedConfiguration) ||
            limits is null || limits.MaximumPages is < 1 or > 100 || limits.MaximumItems is < 1 or > 10000 ||
            limits.MaximumResponseBytes is < 1024 or > 1024 * 1024 ||
            limits.MaximumRowBytes < 256 || limits.MaximumRowBytes > limits.MaximumResponseBytes ||
            limits.MaximumNodes is < 8 or > 65536 ||
            limits.Timeout <= TimeSpan.Zero || limits.Timeout > TimeSpan.FromMinutes(2))
            throw new ArgumentException("notification-metadata-input");
        this.metadata = metadata;
        this.protectedConfiguration = protectedConfiguration;
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
    }

    internal Window Arm(Binding binding)
    {
        ValidateBinding(binding);
        if (Protected(binding.Read) && protectedConfiguration is null)
            throw new InvalidOperationException("notification-protected-authority");
        lock (gate)
        {
            // Registrations are retained, bounded and reference-owned. An
            // identical caller-constructed window cannot acquire their authority.
            if (windows.Count >= 64 || !nonces.Add(binding.Selector.Nonce))
                throw new InvalidOperationException("notification-metadata-window");
            var window = new Window(binding, time.GetUtcNow());
            windows.Add(window, new(time.GetTimestamp()));
            return window;
        }
    }

    internal async ValueTask<Measurement> CollectAsync(Window window, Binding binding,
        CancellationToken cancellationToken = default)
    {
        Registration registration;
        lock (gate)
        {
            if (window is null || !windows.TryGetValue(window, out var found) || found.Consumed || window.Binding != binding)
                throw new InvalidOperationException("notification-metadata-window");
            registration = found;
            registration.Consumed = true;
        }
        cancellationToken.ThrowIfCancellationRequested();
        var authority = Protected(binding.Read) ? protectedConfiguration! : metadata;
        var budget = new Budget(time, window.ArmedAt, registration.Timestamp, limits.Timeout);
        DateTimeOffset started = window.ArmedAt;
        var notifications = new List<NotificationRow>();
        var attributes = new List<AttributeObservation>();
        var requestIds = new List<string>();
        var identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var visited = new HashSet<string>(StringComparer.Ordinal);
        SecretMaterial? fullUrl = null;
        int pages = 0;
        try { budget.Check(); started = budget.ObservedAt; }
        catch (Boundary failure) { return Finish(failure.Reason, SecretStatus.Unavailable); }
        using var deadline = new CancellationTokenSource(budget.Remaining, time);
        budget.Deadline = deadline;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        byte[] storage = new byte[limits.MaximumResponseBytes + 1];
        try
        {
            string path = Path(binding);
            string next = ArmOrigin + path + "?api-version=" + Revision;
            while (true)
            {
                budget.Check();
                linked.Token.ThrowIfCancellationRequested();
                if (pages >= limits.MaximumPages ||
                    IsInventory(binding.Read) && identities.Count >= limits.MaximumItems)
                    throw new Boundary(Failure.Budget);
                Require(visited.Add(next));
                var method = binding.Read is ReadKind.FullUrl or ReadKind.DeliveryAttributes ? RequestMethod.Post : RequestMethod.Get;
                // A new single-dispatch boundary per actual page also rejects an
                // authentication challenge replay; retries are disabled.
                var boundary = new ReadTransport(authority.Transport, new Uri(next), method, budget);
                var options = new ArmClientOptions { Transport = boundary };
                options.Retry.MaxRetries = 0;
                options.Diagnostics.IsLoggingEnabled = false;
                options.Diagnostics.IsLoggingContentEnabled = false;
                options.Diagnostics.IsDistributedTracingEnabled = false;
                var pipeline = HttpPipelineBuilder.Build(options,
                    new BearerTokenAuthenticationPolicy(new AudienceCredential(authority.Credential, budget), ArmOrigin + "/.default"));
                using var message = pipeline.CreateMessage();
                message.BufferResponse = false;
                message.Request.Method = method;
                message.Request.Uri.Reset(new Uri(next));
                await pipeline.SendAsync(message, linked.Token).ConfigureAwait(false);
                budget.Check();
                linked.Token.ThrowIfCancellationRequested();
                var response = message.Response;
                long? declared = ResponseHeaders(response, out string requestId);
                if (declared > limits.MaximumResponseBytes) throw new Boundary(Failure.Budget);
                int count = 0;
                if (response.ContentStream is { } input)
                {
                    while (true)
                    {
                        budget.Check();
                        int read = await input.ReadAsync(storage.AsMemory(count), linked.Token).ConfigureAwait(false);
                        budget.Check();
                        linked.Token.ThrowIfCancellationRequested();
                        if (read == 0) break;
                        count += read;
                        if (count > limits.MaximumResponseBytes) throw new Boundary(Failure.Budget);
                    }
                }
                Require(count > 0 && (declared is null || declared == count));
                Shape(storage.AsSpan(0, count));
                using var document = JsonDocument.Parse(storage.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = 16 });
                var root = document.RootElement;
                Require(root.ValueKind == JsonValueKind.Object && !root.TryGetProperty("status", out _) &&
                    !root.TryGetProperty("provisioningState", out _));
                bool error = root.TryGetProperty("error", out var providerError);
                if (error) Error(providerError);
                requestIds.Add(requestId);
                pages++;
                if (response.Status != 200)
                {
                    Require(response.Status >= 400 && error && root.EnumerateObject().All(p => p.Name == "error"));
                    if (response.Status is 401 or 403) return Finish(Failure.Denied, SecretStatus.Denied);
                    // A native resource GET 404 is absence only. It says nothing
                    // about settlement of an earlier asynchronous deletion.
                    if (response.Status == 404 && IsConcrete(binding.Read))
                        return Finish(Failure.None, SecretStatus.Absent);
                    return Finish(Failure.Unavailable, SecretStatus.Unavailable);
                }
                if (error || root.TryGetProperty("errors", out _)) throw new Boundary(Failure.ProviderError);
                Require(!root.TryGetProperty("partial", out _));
                string? continuation = null;
                if (IsInventory(binding.Read))
                {
                    Require(root.EnumerateObject().All(p => p.Name is "value" or "nextLink"));
                    var rows = Array(root, "value");
                    foreach (var row in rows.EnumerateArray())
                    {
                        budget.Check();
                        linked.Token.ThrowIfCancellationRequested();
                        if (identities.Count >= limits.MaximumItems) throw new Boundary(Failure.Budget);
                        if (binding.Read == ReadKind.Inventory)
                        {
                            ValidateResource(row, binding);
                            Require(identities.Add(Text(row, "id")));
                            notifications.Add(Resource(row, binding));
                        }
                        else
                        {
                            ValidateAttribute(row);
                            Require(identities.Add(Text(row, "name")));
                            attributes.Add(Attribute(row, true));
                        }
                    }
                    if (root.TryGetProperty("nextLink", out var link) && link.ValueKind != JsonValueKind.Null)
                    {
                        Require(link.ValueKind == JsonValueKind.String && rows.GetArrayLength() > 0);
                        continuation = Continuation(link.GetString()!, path);
                        Require(!visited.Contains(continuation));
                    }
                }
                else
                {
                    Require(!root.TryGetProperty("nextLink", out _) && !root.TryGetProperty("value", out _));
                    if (binding.Read == ReadKind.FullUrl)
                    {
                        string text = Text(root, "endpointUrl");
                        Require(ValidEndpoint(text) && root.EnumerateObject().All(p => p.Name == "endpointUrl"));
                        var native = Native<EventSubscriptionFullUri>(root);
                        Require(native.Endpoint?.OriginalString == text);
                        fullUrl = SecretMaterial.FromText(text);
                    }
                    else
                    {
                        ValidateResource(root, binding);
                        notifications.Add(Resource(root, binding));
                    }
                }
                budget.Check();
                linked.Token.ThrowIfCancellationRequested();
                if (continuation is null)
                    return Finish(Failure.None, notifications.Any(n => n.ProvisioningState == NativeProvisioningState.Unknown)
                        ? SecretStatus.Unknown : SecretStatus.Success);
                next = continuation;
            }
        }
        catch (Exception exception)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                DisposeMaterial();
                throw new OperationCanceledException(cancellationToken);
            }
            Failure failure = deadline.IsCancellationRequested ? Failure.Deadline :
                exception is Boundary b ? b.Reason : Failure.Unavailable;
            return Finish(failure, SecretStatus.Unavailable);
        }
        finally
        {
            // Actual credential, send and body tasks have terminated before this
            // runs. No cancellation callback or detached task clears live storage.
            // Native SDK/JSON strings are ordinary immutable strings, not erased.
            CryptographicOperations.ZeroMemory(storage);
        }

        Measurement Finish(Failure failure, SecretStatus status)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                DisposeMaterial();
                throw new OperationCanceledException(cancellationToken);
            }
            try { budget.Check(); }
            catch (Boundary boundary) { failure = boundary.Reason; status = SecretStatus.Unavailable; }
            if (failure != Failure.None)
            {
                fullUrl?.Dispose();
                fullUrl = null;
            }
            return new()
            {
                Binding = binding,
                WindowId = window.Id,
                ArmedAt = window.ArmedAt,
                StartedAt = started,
                FinishedAt = budget.ObservedAt,
                Identity = authority.Label,
                Access = authority.Access,
                Failure = failure,
                Status = status,
                Pages = pages,
                NativeRequestIds = requestIds.AsReadOnly(),
                Notifications = notifications.AsReadOnly(),
                Attributes = attributes.AsReadOnly(),
                FullUrl = fullUrl
            };
        }
        void DisposeMaterial()
        {
            foreach (var row in notifications) row.Dispose();
            foreach (var attribute in attributes) attribute.Dispose();
            fullUrl?.Dispose();
        }
    }

    private NotificationRow Resource(JsonElement row, Binding binding)
    {
        var p = row.GetProperty("properties");
        string? nativeState = OptionalText(p, "provisioningState");
        var state = Provisioning(nativeState);
        var (eventPresence, events) = Events(p);
        var destinationKind = NotificationDestinationKind.Unknown;
        var attributePresence = Presence.Omitted;
        var attributes = new List<AttributeObservation>();
        Configuration? configuration = null;
        try
        {
            if (p.TryGetProperty("destination", out var destination) && destination.ValueKind != JsonValueKind.Null)
            {
                Require(destination.ValueKind == JsonValueKind.Object);
                string type = Text(destination, "endpointType");
                destinationKind = type switch
                {
                    "WebHook" => NotificationDestinationKind.WebHook,
                    "AzureFunction" or "EventHub" or "HybridConnection" or "ServiceBusQueue" or "ServiceBusTopic" or
                        "StorageQueue" or "MonitorAlert" or "NamespaceTopic" => NotificationDestinationKind.Other,
                    _ => throw new Boundary()
                };
                if (destinationKind == NotificationDestinationKind.WebHook)
                {
                    var settings = Object(destination, "properties");
                    attributePresence = Field(settings, "deliveryAttributeMappings", out var mappings);
                    if (attributePresence == Presence.Value)
                    {
                        Require(mappings.ValueKind == JsonValueKind.Array && mappings.GetArrayLength() <= 10);
                        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        foreach (var attribute in mappings.EnumerateArray())
                        {
                            ValidateAttribute(attribute);
                            Require(names.Add(Text(attribute, "name")));
                            attributes.Add(Attribute(attribute, binding.Read == ReadKind.Configuration));
                        }
                    }
                    string? endpoint = OptionalText(settings, "endpointUrl");
                    bool exact = binding.Read == ReadKind.Configuration && ValidEndpoint(endpoint) &&
                        eventPresence == Presence.Value && events.Count is >= 1 and <= 3 &&
                        events.All(e => e is "Microsoft.KeyVault.SecretNewVersionCreated" or
                            "Microsoft.KeyVault.SecretNearExpiry" or "Microsoft.KeyVault.SecretExpired") &&
                        attributePresence == Presence.Value &&
                        attributes.All(a => a.Value is not null && (a.Kind == NotificationAttributeKind.Dynamic
                            ? a.SecretFlagPresence == Presence.Omitted : a.SecretFlagPresence == Presence.Value && a.IsSecret is not null)) &&
                        settings.EnumerateObject().All(q => q.Name is "endpointUrl" or "endpointBaseUrl" or "deliveryAttributeMappings") &&
                        p.GetProperty("filter").EnumerateObject().All(q => q.Name == "includedEventTypes" ||
                            q.Name == "advancedFilters" && q.Value.ValueKind == JsonValueKind.Array && q.Value.GetArrayLength() == 0);
                    if (exact)
                        configuration = new()
                        {
                            Endpoint = SecretMaterial.FromText(endpoint!),
                            Events = events.Select(Event).ToArray(),
                            AttributesPresence = attributePresence,
                            Attributes = attributePresence == Presence.Omitted ? null : attributes.AsReadOnly()
                        };
                }
            }
            // Native materialization is independent of SecretKit's selected
            // result projection, after bounded identity/shape validation.
            var native = Native<EventGridSubscriptionData>(row);
            Require(Same(native.Id?.ToString(), Text(row, "id")) && Same(native.Name, Text(row, "name")) &&
                Same(native.Topic, Text(p, "topic")) &&
                Same(native.ProvisioningState?.ToString(), nativeState) &&
                (eventPresence != Presence.Value || native.Filter is not null && native.Filter.IncludedEventTypes.SequenceEqual(events)) &&
                (destinationKind switch
                {
                    NotificationDestinationKind.WebHook => native.Destination is WebHookEventSubscriptionDestination,
                    NotificationDestinationKind.Unknown => native.Destination is null,
                    _ => native.Destination is not null and not WebHookEventSubscriptionDestination
                }));
            return new()
            {
                ResourceId = Text(row, "id"),
                Name = Text(row, "name"),
                Topic = Text(p, "topic"),
                Version = OptionalText(row, "etag"),
                NativeState = nativeState,
                ProvisioningState = state,
                Destination = destinationKind,
                EventsPresence = eventPresence,
                EventTypes = events.AsReadOnly(),
                AttributesPresence = attributePresence,
                Attributes = attributes.AsReadOnly(),
                Configuration = configuration
            };
        }
        catch
        {
            configuration?.Dispose();
            foreach (var attribute in attributes) attribute.Dispose();
            throw;
        }
    }

    private AttributeObservation Attribute(JsonElement row, bool retainMaterial)
    {
        string kind = Text(row, "type");
        var properties = Object(row, "properties");
        string field = kind == "Static" ? "value" : "sourceField";
        var valuePresence = Field(properties, field, out var value);
        var flagPresence = Field(properties, "isSecret", out var flag);
        string? text = valuePresence == Presence.Value ? String(value, 4096) : null;
        bool? secret = flagPresence == Presence.Value ? flag.GetBoolean() : null;
        var native = Native<DeliveryAttributeMapping>(row);
        Require(native.Name == Text(row, "name"));
        Require(kind == "Static"
            ? native is StaticDeliveryAttributeMapping s && s.Value == text && s.IsSecret == secret
            : native is DynamicDeliveryAttributeMapping d && d.SourceField == text);
        return new()
        {
            Name = native.Name,
            Kind = kind == "Static" ? NotificationAttributeKind.Static : NotificationAttributeKind.Dynamic,
            ValuePresence = valuePresence,
            SecretFlagPresence = flagPresence,
            IsSecret = secret,
            Value = retainMaterial && text is not null && !Masked(text) ? SecretMaterial.FromText(text) : null
        };
    }

    private void ValidateResource(JsonElement row, Binding binding)
    {
        CheckRowSize(row);
        Require(row.ValueKind == JsonValueKind.Object);
        string id = Text(row, "id"), name = Text(row, "name");
        var vault = binding.Scope is VaultScope v ? v : ((NotificationScope)binding.Scope).Vault;
        string prefix = vault.ExportResourceId() + "/providers/Microsoft.EventGrid/eventSubscriptions/";
        Require(Name(name) && Same(id, prefix + name) && Text(row, "type") == "Microsoft.EventGrid/eventSubscriptions");
        if (binding.Scope is NotificationScope concrete) Require(Same(name, concrete.SubscriptionName));
        var p = Object(row, "properties");
        Require(Same(Text(p, "topic"), vault.ExportResourceId()) &&
            !row.TryGetProperty("error", out _) && !p.TryGetProperty("error", out _) &&
            !p.TryGetProperty("errors", out _) && !p.TryGetProperty("status", out _) &&
            row.EnumerateObject().All(q => q.Name is "id" or "name" or "type" or "properties" or "systemData" or "etag"));
        _ = Provisioning(OptionalText(p, "provisioningState"));
        _ = Events(p);
        _ = OptionalText(row, "etag");
    }
    private void ValidateAttribute(JsonElement row)
    {
        CheckRowSize(row);
        Require(row.ValueKind == JsonValueKind.Object && HeaderName(Text(row, "name")));
        string kind = Text(row, "type");
        Require(kind is "Static" or "Dynamic");
        var p = Object(row, "properties");
        Require(p.EnumerateObject().All(q => kind == "Static" ? q.Name is "value" or "isSecret" : q.Name == "sourceField"));
        var flag = Field(p, "isSecret", out var isSecret);
        Require(flag != Presence.Value || isSecret.ValueKind is JsonValueKind.True or JsonValueKind.False);
        var value = Field(p, kind == "Static" ? "value" : "sourceField", out var text);
        if (value == Presence.Value) _ = String(text, 4096);
    }
    private (Presence Presence, List<string> Events) Events(JsonElement properties)
    {
        var presence = Field(properties, "filter", out var filter);
        if (presence != Presence.Value) return (presence, []);
        Require(filter.ValueKind == JsonValueKind.Object);
        presence = Field(filter, "includedEventTypes", out var values);
        if (presence != Presence.Value) return (presence, []);
        Require(values.ValueKind == JsonValueKind.Array);
        var result = new List<string>();
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in values.EnumerateArray())
        {
            string text = String(item, 128);
            Require(unique.Add(text));
            result.Add(text);
        }
        return (presence, result);
    }
    private static VaultNotificationEvent Event(string text) => text switch
    {
        "Microsoft.KeyVault.SecretNewVersionCreated" => VaultNotificationEvent.SecretNewVersionCreated,
        "Microsoft.KeyVault.SecretNearExpiry" => VaultNotificationEvent.SecretNearExpiry,
        "Microsoft.KeyVault.SecretExpired" => VaultNotificationEvent.SecretExpired,
        _ => throw new Boundary()
    };
    private static NativeProvisioningState Provisioning(string? text) => text?.ToLowerInvariant() switch
    {
        null or "unknown" => NativeProvisioningState.Unknown,
        "succeeded" => NativeProvisioningState.Succeeded,
        "creating" or "updating" or "deleting" or "awaitingmanualaction" or "inprogress" => NativeProvisioningState.Pending,
        "failed" => NativeProvisioningState.Failed,
        "canceled" or "cancelled" => NativeProvisioningState.Canceled,
        _ => throw new Boundary()
    };

    private T Native<T>(JsonElement row)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(row);
        try
        {
            if (bytes.Length > limits.MaximumRowBytes) throw new Boundary(Failure.Budget);
            return ModelReaderWriter.Read<T>(new BinaryData(bytes)) ?? throw new Boundary();
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private void CheckRowSize(JsonElement row)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(row);
        try { if (bytes.Length > limits.MaximumRowBytes) throw new Boundary(Failure.Budget); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private void Shape(ReadOnlySpan<byte> bytes)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = 16 });
        var containers = new Stack<HashSet<string>?>();
        int nodes = 0;
        while (reader.Read())
        {
            if (++nodes > limits.MaximumNodes) throw new Boundary(Failure.Budget);
            switch (reader.TokenType)
            {
                case JsonTokenType.PropertyName:
                    string name = reader.GetString()!;
                    Require(containers.Count > 0 && containers.Peek() is { } names && names.Add(name));
                    foreach (string reserved in ReservedNames)
                        if (name.Equals(reserved, StringComparison.OrdinalIgnoreCase)) Require(name == reserved);
                    break;
                case JsonTokenType.StartObject: containers.Push(new(StringComparer.OrdinalIgnoreCase)); break;
                case JsonTokenType.StartArray: containers.Push(null); break;
                case JsonTokenType.EndArray:
                case JsonTokenType.EndObject: containers.Pop(); break;
            }
        }
        Require(nodes > 0 && containers.Count == 0);
    }
    private static readonly string[] ReservedNames =
    [
        "id", "name", "type", "properties", "topic", "provisioningState", "destination", "endpointType",
        "endpointUrl", "endpointBaseUrl", "deliveryAttributeMappings", "filter", "includedEventTypes",
        "sourceField", "isSecret", "etag", "value", "nextLink", "error", "errors", "partial", "status"
    ];

    private static long? ResponseHeaders(Response response, out string requestId)
    {
        Headers(response.Headers);
        Require(response.Status is not (>= 300 and < 400) &&
            !response.Headers.Contains("Content-Encoding") && !response.Headers.Contains("Content-Range"));
        foreach (string name in new[] { "Location", "Azure-AsyncOperation", "Operation-Location" })
            Require(!response.Headers.Contains(name));
        string contentType = Single(response.Headers, "Content-Type");
        string[] pieces = contentType.Split(';', StringSplitOptions.TrimEntries);
        Require(pieces.Length is 1 or 2 && pieces[0].Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
            (pieces.Length == 1 || pieces[1].Equals("charset=utf-8", StringComparison.OrdinalIgnoreCase)));
        requestId = Single(response.Headers, "x-ms-request-id");
        Require(requestId.Length is > 0 and <= 128 &&
            requestId.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'));
        if (!response.Headers.Contains("Content-Length")) return null;
        string length = Single(response.Headers, "Content-Length");
        Require(long.TryParse(length, NumberStyles.None, CultureInfo.InvariantCulture, out long result) && result >= 0);
        return result;
    }
    private static string Single(ResponseHeaders headers, string name)
    {
        Require(headers.TryGetValues(name, out var source));
        var values = source.Take(2).ToArray();
        Require(values.Length == 1);
        return values[0];
    }
    private static void Headers(IEnumerable<HttpHeader> headers)
    {
        int count = 0, bytes = 0;
        foreach (var header in headers)
        {
            if (++count > 32 || header.Name.Length > 128 || header.Value.Length > 4096)
                throw new Boundary(Failure.Budget);
            Require(header.Name.Length > 0 && header.Name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') &&
                !header.Value.Any(c => !char.IsAscii(c) || char.IsControl(c) && c != '\t'));
            bytes += header.Name.Length + header.Value.Length;
            if (bytes > 16384) throw new Boundary(Failure.Budget);
        }
    }
    private static void Error(JsonElement error)
    {
        Require(error.ValueKind == JsonValueKind.Object);
        _ = String(error.GetProperty("code"), 256);
        if (error.TryGetProperty("message", out var message)) Require(message.ValueKind == JsonValueKind.String);
        if (error.TryGetProperty("details", out var details))
        {
            Require(details.ValueKind == JsonValueKind.Array);
            foreach (var child in details.EnumerateArray()) Error(child);
        }
    }
    private static string Continuation(string text, string path)
    {
        Require(text.Length is > 0 and <= 8192 && !text.Any(char.IsControl));
        Require(Uri.TryCreate(text, UriKind.Absolute, out var uri));
        Require(uri.Scheme == "https" && uri.IsDefaultPort &&
            uri.UserInfo.Length == 0 && !text.Contains('#') &&
            text.Split('?')[0] == ArmOrigin + path);
        var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string pair in uri.Query.TrimStart('?').Split('&'))
        {
            string[] values = pair.Split('=', 2);
            Require(values.Length == 2 && ValidEscapes(values[0]) && ValidEscapes(values[1]));
            string key = Uri.UnescapeDataString(values[0]), value = Uri.UnescapeDataString(values[1]);
            Require(key is "api-version" or "$skipToken" or "$skiptoken" &&
                value.Length is > 0 and <= 4096 && !value.Any(char.IsControl) && query.TryAdd(key, value));
        }
        Require(query.Count == 2 && query.TryGetValue("api-version", out string? revision) && revision == Revision &&
            query.ContainsKey("$skipToken"));
        return text;
    }
    private static bool ValidEscapes(string value)
    {
        for (int i = 0; i < value.Length; i++)
            if (value[i] == '%' && (i + 2 >= value.Length || !char.IsAsciiHexDigit(value[i + 1]) || !char.IsAsciiHexDigit(value[i + 2])))
                return false;
        return true;
    }
    private static string Path(Binding b)
    {
        string root = b.Scope is VaultScope vault ? vault.ExportResourceId() + "/providers/Microsoft.EventGrid/eventSubscriptions" :
            ((NotificationScope)b.Scope).Vault.ExportResourceId() + "/providers/Microsoft.EventGrid/eventSubscriptions/" +
            ((NotificationScope)b.Scope).SubscriptionName;
        return root + (b.Read switch
        {
            ReadKind.DeliveryAttributes => "/getDeliveryAttributes",
            ReadKind.FullUrl => "/getFullUrl",
            _ => ""
        });
    }
    private static void ValidateBinding(Binding b)
    {
        if (b is null || b.Selector is null || b.Selector.Nonce == Guid.Empty || b.LeaseId == Guid.Empty ||
            !Enum.IsDefined(b.Query) || !Enum.IsDefined(b.Read) ||
            new[] { b.Selector.Scope, b.Selector.Operation, b.Selector.Variant, b.Selector.Case }
                .Any(v => string.IsNullOrWhiteSpace(v) || v.Length > 512 || v.Any(char.IsControl)) ||
            (b.Read == ReadKind.Inventory ? b.Scope is not VaultScope : b.Scope is not NotificationScope))
            throw new ArgumentException("notification-metadata-binding");
        bool operation = b.Query >= QueryKind.OperationCreateOrUpdateNotification;
        string name = operation ? "a.management.ManagementOperation.CheckStatusAsync" :
            "a.management.VaultAdministration." + b.Query + "Async";
        var member = operation ? ManagementOperationEffects.Members[0] :
            NotificationAdministrationEffects.Members.Single(m => m.Operation == name);
        bool mutation = b.Query is QueryKind.CreateOrUpdateNotification or QueryKind.UpdateNotification or QueryKind.DeleteNotification;
        bool compatible = b.Query switch
        {
            QueryKind.ListNotifications => b.Read == ReadKind.Inventory,
            QueryKind.GetNotificationDeliveryAttributes => b.Read == ReadKind.DeliveryAttributes,
            QueryKind.GetNotificationFullUrl => b.Read == ReadKind.FullUrl,
            _ => b.Read is ReadKind.Metadata or ReadKind.Configuration
        };
        bool variant = operation
            ? b.Selector.Variant == "operation." + b.Query.ToString()["Operation".Length..] ||
                b.Selector.Variant.StartsWith("status.", StringComparison.Ordinal) &&
                member.Variants.Contains(b.Selector.Variant, StringComparer.Ordinal)
            : member.Variants.Contains(b.Selector.Variant, StringComparer.Ordinal);
        if (!compatible || !variant || b.Selector.Operation != name ||
            b.Selector.Case is not ("selected-contract" or "denied-authority" or "cancellation-boundary" or "independent-effect") &&
            !(mutation && b.Selector.Case == "lost-response-no-replay"))
            throw new ArgumentException("notification-metadata-binding");
    }
    private static bool ValidAuthority(Authority? authority, Access access) =>
        authority is not null && authority.Access == access && authority.Credential is not null && authority.Transport is not null &&
        !string.IsNullOrWhiteSpace(authority.Label) && authority.Label.Length <= 128 && !authority.Label.Any(char.IsControl);
    private static bool Protected(ReadKind read) => read is ReadKind.Configuration or ReadKind.DeliveryAttributes or ReadKind.FullUrl;
    private static bool IsInventory(ReadKind read) => read is ReadKind.Inventory or ReadKind.DeliveryAttributes;
    private static bool IsConcrete(ReadKind read) => read is ReadKind.Metadata or ReadKind.Configuration;
    private static bool Same(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    private static bool Name(string value) => value.Length is >= 3 and <= 64 && value.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');
    private static bool HeaderName(string value) => value.Length is >= 1 and <= 64 && value.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');
    private static bool Masked(string value) => value.All(c => c == '*') ||
        value.Equals("[redacted]", StringComparison.OrdinalIgnoreCase) || value.Equals("(redacted)", StringComparison.OrdinalIgnoreCase);
    private static bool ValidEndpoint(string? value) => value is { Length: > 0 and <= 4096 } &&
        !value.Any(char.IsControl) && !Masked(value) && Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        uri.Scheme == "https" && uri.Host.Length > 0 && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0;
    private static Presence Field(JsonElement parent, string name, out JsonElement value) =>
        !parent.TryGetProperty(name, out value) ? Presence.Omitted : value.ValueKind == JsonValueKind.Null ? Presence.Null : Presence.Value;
    private static string? OptionalText(JsonElement parent, string name) =>
        Field(parent, name, out var value) == Presence.Value ? String(value, 4096) : null;
    private static string Text(JsonElement parent, string name) => String(parent.GetProperty(name), 4096);
    private static string String(JsonElement element, int maximum)
    {
        Require(element.ValueKind == JsonValueKind.String);
        string value = element.GetString()!;
        Require(value.Length > 0 && value.Length <= maximum && !value.Any(char.IsControl));
        return value;
    }
    private static JsonElement Object(JsonElement parent, string name)
    {
        var value = parent.GetProperty(name);
        Require(value.ValueKind == JsonValueKind.Object);
        return value;
    }
    private static JsonElement Array(JsonElement parent, string name)
    {
        var value = parent.GetProperty(name);
        Require(value.ValueKind == JsonValueKind.Array);
        return value;
    }
    private static void Require([DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw new Boundary();
    }
    private sealed class Boundary(Failure reason = Failure.Boundary) : Exception("notification-metadata-boundary")
    {
        internal Failure Reason { get; } = reason;
    }

    private sealed class Budget(TimeProvider time, DateTimeOffset armedAt, long timestamp, TimeSpan timeout)
    {
        private readonly DateTimeOffset initialWall = armedAt;
        private readonly long initialTimestamp = timestamp;
        private readonly TimeSpan duration = timeout;
        private DateTimeOffset lastWall = armedAt;
        private long lastTimestamp = timestamp;
        internal DateTimeOffset ObservedAt => lastWall;
        internal CancellationTokenSource? Deadline { get; set; }
        internal TimeSpan Remaining { get; private set; } = timeout;
        internal void Check()
        {
            DateTimeOffset wall = time.GetUtcNow();
            long stamp = time.GetTimestamp();
            Require(wall >= lastWall && stamp >= lastTimestamp);
            TimeSpan elapsed = time.GetElapsedTime(initialTimestamp, stamp), wallElapsed = wall - initialWall;
            Require(elapsed >= TimeSpan.Zero && wallElapsed >= TimeSpan.Zero);
            lastWall = wall;
            lastTimestamp = stamp;
            Remaining = duration - (elapsed > wallElapsed ? elapsed : wallElapsed);
            if (Remaining <= TimeSpan.Zero) throw new Boundary(Failure.Deadline);
            Deadline?.CancelAfter(Remaining);
        }
    }
    private sealed class AudienceCredential(TokenCredential inner, Budget budget) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken) => throw new Boundary();
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken)
        {
            budget.Check();
            cancellationToken.ThrowIfCancellationRequested();
            Require(context.Scopes.Length == 1 && context.Scopes[0] == ArmOrigin + "/.default");
            // Await the real task, even when its host ignores cancellation.
            var token = await inner.GetTokenAsync(context, cancellationToken).ConfigureAwait(false);
            budget.Check();
            cancellationToken.ThrowIfCancellationRequested();
            return token;
        }
    }
    private sealed class ReadTransport(HttpPipelineTransport inner, Uri uri, RequestMethod method, Budget budget) : HttpPipelineTransport
    {
        private int sent;
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new Boundary();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            budget.Check();
            Require(Interlocked.Increment(ref sent) == 1);
            Validate(message);
            message.CancellationToken.ThrowIfCancellationRequested();
            message.BufferResponse = false;
            await inner.ProcessAsync(message).ConfigureAwait(false);
            budget.Check();
            Validate(message);
            message.CancellationToken.ThrowIfCancellationRequested();
        }
        private void Validate(HttpMessage message)
        {
            Require(message.Request.Method == method && message.Request.Content is null &&
                message.Request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri);
            Headers(message.Request.Headers);
            Require(message.Request.Headers.TryGetValue("Authorization", out var authorization) &&
                authorization.StartsWith("Bearer ", StringComparison.Ordinal) && authorization.Length > 7);
            if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
        }
    }
    public override string ToString() => "[NotificationAdministrationCollector]";
}
