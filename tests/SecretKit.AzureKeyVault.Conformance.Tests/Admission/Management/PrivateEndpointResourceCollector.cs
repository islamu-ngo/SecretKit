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
using Azure.ResourceManager.Resources;
using SecretKit.Core;
using Authority = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector.Authority;
using Failure = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector.Failure;
using Limits = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector.Limits;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// An independent resource fact, not provisioning, adoption, a journal binding,
// native operation completion, ownership, or principal/egress qualification.
internal sealed class PrivateEndpointResourceCollector
{
    internal const string Revision = "2026-01-01";
    private const string Origin = "https://management.azure.com";
    private const string EndpointType = "Microsoft.Network/privateEndpoints";
    private const string NicType = "Microsoft.Network/networkInterfaces";

    internal enum ReadKind { Endpoint, NicAbsence }

    internal sealed record Binding(
        [property: JsonIgnore] FixtureSelector Selector,
        [property: JsonIgnore] Guid LeaseId,
        [property: JsonIgnore] string EndpointId,
        [property: JsonIgnore] string VaultId,
        [property: JsonIgnore] string SubnetId,
        [property: JsonIgnore] string NicId,
        [property: JsonIgnore] string ConnectionName,
        [property: JsonIgnore] string Location,
        [property: JsonIgnore] string OwnerTagName,
        [property: JsonIgnore] string OwnerTagValue)
    {
        public override string ToString() => "[PrivateEndpointResourceBinding]";
    }

    internal sealed class Window
    {
        private Window(Binding binding, DateTimeOffset armedAt, ReadKind kind)
        {
            Binding = binding;
            ArmedAt = armedAt;
            Kind = kind;
        }
        [JsonIgnore] internal Binding Binding { get; }
        [JsonIgnore] internal ReadKind Kind { get; }
        [JsonIgnore] internal Guid Id { get; } = Guid.NewGuid();
        [JsonIgnore] internal DateTimeOffset ArmedAt { get; }
        internal static Window Create(Binding binding, DateTimeOffset armedAt, ReadKind kind = ReadKind.Endpoint) =>
            new(binding, armedAt, kind);
        public override string ToString() => "[PrivateEndpointResourceWindow]";
    }

    internal sealed class Measurement
    {
        [JsonIgnore] internal ReadKind Kind { get; init; }
        [JsonIgnore] internal required Binding Binding { get; init; }
        [JsonIgnore] internal required Guid WindowId { get; init; }
        [JsonIgnore] internal required DateTimeOffset ArmedAt { get; init; }
        [JsonIgnore] internal required DateTimeOffset StartedAt { get; init; }
        [JsonIgnore] internal required DateTimeOffset FinishedAt { get; init; }
        [JsonIgnore] internal required string Identity { get; init; }
        [JsonIgnore] internal required int? HttpStatus { get; init; }
        [JsonIgnore] internal required string? NativeRequestId { get; init; }
        [JsonIgnore] internal required SecretStatus ResourceStatus { get; init; }
        [JsonIgnore] internal required Failure Failure { get; init; }
        [JsonIgnore] internal required string? NativeState { get; init; }
        [JsonIgnore] internal required string? ManualConnectionState { get; init; }
        [JsonIgnore] internal required bool MatchesDeclaration { get; init; }
        [JsonIgnore] internal bool MatchesDeclarationConfiguration { get; init; }
        [JsonIgnore] internal bool ResponseComplete => Failure == Failure.None;
        [JsonIgnore] internal bool NativeSettlementProven => false;
        [JsonIgnore] internal bool OwnershipProven => false;
        [JsonIgnore] internal bool PrincipalQualified => false;
        [JsonIgnore] internal bool EgressQualified => false;
        public override string ToString() => "[PrivateEndpointResourceMeasurement]";
    }

    private sealed class Registration(long timestamp)
    {
        internal long Timestamp { get; } = timestamp;
        internal bool Consumed;
    }

    private readonly Authority authority;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly object gate = new();
    private readonly Dictionary<Window, Registration> windows = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<Guid> nonces = [], leases = [];

    internal PrivateEndpointResourceCollector(Authority authority, Limits limits, TimeProvider time)
    {
        if (authority is null || authority.Credential is null || authority.Transport is null ||
            !TextValue(authority.Label, 128) || limits is null || time is null ||
            limits.MaximumResponseBytes is < 1024 or > 1024 * 1024 ||
            limits.MaximumRowBytes < 256 || limits.MaximumRowBytes > limits.MaximumResponseBytes ||
            limits.MaximumNodes is < 8 or > 65536 || limits.MaximumRows is < 1 or > 4096 ||
            limits.MaximumDepth is < 2 or > 32 ||
            limits.Timeout <= TimeSpan.Zero || limits.Timeout > TimeSpan.FromMinutes(2))
            throw new ArgumentException("private-endpoint-resource-input");
        this.authority = authority;
        this.limits = limits;
        this.time = time;
    }

    internal Window Arm(Binding binding) => Arm(binding, ReadKind.Endpoint);

    internal Window ArmNicAbsence(Binding binding) => Arm(binding, ReadKind.NicAbsence);

    private Window Arm(Binding binding, ReadKind kind)
    {
        try { ValidateBinding(binding); }
        catch (Exception) { throw new ArgumentException("private-endpoint-resource-binding"); }
        lock (gate)
        {
            if (windows.Count >= 32 || nonces.Contains(binding.Selector.Nonce) || leases.Contains(binding.LeaseId))
                throw new InvalidOperationException("private-endpoint-resource-window");
            var window = Window.Create(binding, time.GetUtcNow(), kind);
            windows.Add(window, new(time.GetTimestamp()));
            nonces.Add(binding.Selector.Nonce);
            leases.Add(binding.LeaseId);
            return window;
        }
    }

    internal async ValueTask<Measurement> CollectAsync(Window window, Binding binding,
        CancellationToken cancellationToken = default)
    {
        Registration registration;
        lock (gate)
        {
            if (window is null || !windows.TryGetValue(window, out var found) || found.Consumed ||
                !ReferenceEquals(window.Binding, binding))
                throw new InvalidOperationException("private-endpoint-resource-window");
            registration = found;
            registration.Consumed = true;
        }
        cancellationToken.ThrowIfCancellationRequested();
        var budget = new Budget(time, window.ArmedAt, registration.Timestamp, limits.Timeout);
        DateTimeOffset started = window.ArmedAt;
        int? status = null;
        string? requestId = null, nativeState = null, manualState = null;
        bool matches = false, matchesConfiguration = false;
        byte[]? storage = null;
        CancellationTokenSource? deadline = null, linked = null;
        try
        {
            ValidateBinding(binding);
            budget.Check();
            started = budget.ObservedAt;
            // Timer/link construction is inside the cleanup boundary; no gate
            // remains held if an injected clock rejects timer construction.
            deadline = new CancellationTokenSource(budget.Remaining, time);
            budget.Deadline = deadline;
            linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            storage = new byte[limits.MaximumResponseBytes + 1];
            string resourceId = window.Kind == ReadKind.NicAbsence ? binding.NicId : binding.EndpointId;
            var uri = new Uri(Origin + resourceId + "?api-version=" + Revision);
            var options = new ArmClientOptions { Transport = new ReadTransport(authority.Transport, uri, budget) };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            var pipeline = HttpPipelineBuilder.Build(options,
                new BearerTokenAuthenticationPolicy(new ObserverCredential(authority.Credential, budget), Origin + "/.default"));
            using var message = pipeline.CreateMessage();
            message.BufferResponse = false;
            message.Request.Method = RequestMethod.Get;
            message.Request.Uri.Reset(uri);
            budget.Check();
            await pipeline.SendAsync(message, linked.Token).ConfigureAwait(false);
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            var response = message.Response;
            status = response.Status;
            long? length = ResponseHeaders(response, out var responseId);
            requestId = responseId;
            if (length > limits.MaximumResponseBytes) throw new Boundary(Failure.Budget);
            int count = 0;
            if (response.ContentStream is { } input)
                while (true)
                {
                    budget.Check();
                    linked.Token.ThrowIfCancellationRequested();
                    int read = await input.ReadAsync(storage.AsMemory(count), linked.Token).ConfigureAwait(false);
                    budget.Check();
                    linked.Token.ThrowIfCancellationRequested();
                    if (read == 0) break;
                    count += read;
                    if (count > limits.MaximumResponseBytes) throw new Boundary(Failure.Budget);
                }
            Require(count > 0 && (length is null || length == count));
            if (count > limits.MaximumRowBytes) throw new Boundary(Failure.Budget);
            Shape(storage.AsSpan(0, count), status == 200);
            using var document = JsonDocument.Parse(storage.AsMemory(0, count),
                new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
            var root = document.RootElement;
            Require(root.ValueKind == JsonValueKind.Object);
            if (status != 200)
            {
                Require(status >= 400 && root.EnumerateObject().Count() == 1 && root.TryGetProperty("error", out _));
                Error(root.GetProperty("error"));
                if (status is 401 or 403) return Finish(Failure.Denied, SecretStatus.Denied);
                if (status == 404) return Finish(Failure.None, SecretStatus.Absent);
                return Finish(Failure.Unavailable, SecretStatus.Unavailable);
            }
            Require(!root.TryGetProperty("status", out _));
            string id, name, type;
            string? location;
            try
            {
                id = Text(root, "id");
                name = Text(root, "name");
                type = Text(root, "type");
                _ = ResourcePath(id, "Microsoft.Network",
                    window.Kind == ReadKind.NicAbsence ? "networkInterfaces" : "privateEndpoints");
                Require(Same(id, resourceId) && Same(name, id.Split('/')[^1]) &&
                    Same(type, window.Kind == ReadKind.NicAbsence ? NicType : EndpointType));
                location = OptionalText(root, "location");
                if (location is not null) Require(Segment(location, 50));
                if (window.Kind == ReadKind.NicAbsence) Require(Same(location, binding.Location));
            }
            catch (Boundary) when (window.Kind == ReadKind.NicAbsence)
            {
                throw new Boundary(Failure.Unavailable);
            }
            var properties = OptionalObject(root, "properties");
            if (properties is { } p) Require(!p.TryGetProperty("status", out _));
            bool owner = Tags(root, binding, out var tags);
            bool configuration = false;
            if (window.Kind == ReadKind.Endpoint)
                configuration = Configuration(properties, binding, out nativeState, out manualState);
            else if (properties is { } nicProperties)
                nativeState = OptionalText(nicProperties, "provisioningState");
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            // The installed ARM model reads only after framing, structural and
            // input bounds. Its generic properties must agree with the raw JSON.
            var native = ModelReaderWriter.Read<GenericResourceData>(new BinaryData(storage.AsMemory(0, count)));
            if (native is null || !Same(native.Id?.ToString(), id) || !Same(native.Name, name) ||
                !Same(native.ResourceType.ToString(), type) || !Same(native.Location.Name, location))
                throw new Boundary(window.Kind == ReadKind.NicAbsence ? Failure.Unavailable : Failure.Boundary);
            Require(native.Tags.Count == tags.Count && tags.All(tag =>
                native.Tags.Keys.Contains(tag.Key, StringComparer.Ordinal) &&
                native.Tags.TryGetValue(tag.Key, out var value) && value == tag.Value));
            if (properties is null) Require(native.Properties is null);
            else
            {
                Require(native.Properties is not null);
                ReadOnlyMemory<byte> nativeBytes = native.Properties.ToMemory();
                if (nativeBytes.Length > limits.MaximumRowBytes) throw new Boundary(Failure.Budget);
                Shape(nativeBytes.Span, true);
                using var nativeDocument = JsonDocument.Parse(nativeBytes,
                    new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
                Require(JsonElement.DeepEquals(properties.Value, nativeDocument.RootElement));
            }
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            matchesConfiguration = window.Kind == ReadKind.Endpoint && owner &&
                Same(location, binding.Location) && configuration;
            matches = matchesConfiguration && nativeState == "Succeeded" && manualState == "Pending";
            return Finish(Failure.None, SecretStatus.Success);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Finish(deadline?.IsCancellationRequested == true ? Failure.Deadline :
                exception is Boundary b ? b.Reason : Failure.Unavailable, SecretStatus.Unavailable);
        }
        finally
        {
            // Direct awaits above drain ACTUAL credential, send and body tasks,
            // including uncooperative ones. Native reading is synchronous.
            // Native/JSON immutable strings cannot be erased by clearing storage.
            if (storage is not null) CryptographicOperations.ZeroMemory(storage);
            linked?.Dispose();
            deadline?.Dispose();
        }

        Measurement Finish(Failure failure, SecretStatus resourceStatus)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                budget.Check();
                if (deadline?.IsCancellationRequested == true) throw new Boundary(Failure.Deadline);
            }
            catch (Boundary b) { failure = b.Reason; resourceStatus = SecretStatus.Unavailable; }
            if (failure != Failure.None || resourceStatus != SecretStatus.Success)
            {
                nativeState = manualState = null;
                matches = false;
                matchesConfiguration = false;
            }
            return new()
            {
                Kind = window.Kind,
                Binding = binding,
                WindowId = window.Id,
                ArmedAt = window.ArmedAt,
                StartedAt = started,
                FinishedAt = budget.ObservedAt,
                Identity = authority.Label,
                HttpStatus = status,
                NativeRequestId = requestId,
                ResourceStatus = resourceStatus,
                Failure = failure,
                NativeState = nativeState,
                ManualConnectionState = manualState,
                MatchesDeclaration = matches,
                MatchesDeclarationConfiguration = matchesConfiguration
            };
        }
    }

    internal static void ValidateBinding(Binding b)
    {
        Require(b is not null && b.Selector is not null && b.Selector.Nonce != Guid.Empty && b.LeaseId != Guid.Empty &&
            new[] { b.Selector.Scope, b.Selector.Operation, b.Selector.Variant, b.Selector.Case }.All(s => TextValue(s, 512)) &&
            Segment(b.Location, 50) && Segment(b.ConnectionName, 256) &&
            TextValue(b.OwnerTagName, 512) && TextValue(b.OwnerTagValue, 256));
        var endpoint = ResourcePath(b.EndpointId, "Microsoft.Network", "privateEndpoints");
        var vault = ResourcePath(b.VaultId, "Microsoft.KeyVault", "vaults");
        var subnet = ResourcePath(b.SubnetId, "Microsoft.Network", "virtualNetworks", "subnets");
        var nic = ResourcePath(b.NicId, "Microsoft.Network", "networkInterfaces");
        Require(endpoint.Subscription == vault.Subscription && endpoint.Subscription == subnet.Subscription &&
            endpoint.Subscription == nic.Subscription && Same(endpoint.Group, nic.Group));
    }

    private static (Guid Subscription, string Group) ResourcePath(string? value, string provider, string type,
        string? childType = null)
    {
        Require(TextValue(value, 2048));
        string[] parts = value.Split('/');
        Require(parts.Length == (childType is null ? 9 : 11) && parts[0].Length == 0 &&
            Same(parts[1], "subscriptions") && Guid.TryParseExact(parts[2], "D", out _) &&
            Same(parts[3], "resourceGroups") && Segment(parts[4], 90) && Same(parts[5], "providers") &&
            Same(parts[6], provider) && Same(parts[7], type) && Segment(parts[8], 256));
        Guid subscription = Guid.ParseExact(parts[2], "D");
        Require(subscription != Guid.Empty && parts[2] == subscription.ToString("D"));
        if (childType is not null) Require(Same(parts[9], childType) && Segment(parts[10], 256));
        return (subscription, parts[4]);
    }

    private static bool Tags(JsonElement root, Binding binding, out Dictionary<string, string> tags)
    {
        tags = new(StringComparer.Ordinal);
        var source = OptionalObject(root, "tags");
        if (source is null) return false;
        foreach (var tag in source.Value.EnumerateObject())
        {
            Require(TextValue(tag.Name, 512));
            Require(tag.Value.ValueKind == JsonValueKind.String);
            string value = tag.Value.GetString()!;
            Require(value.Length <= 256 && !value.Any(char.IsControl));
            tags.Add(tag.Name, value);
        }
        return tags.TryGetValue(binding.OwnerTagName, out var owner) && owner == binding.OwnerTagValue;
    }

    private static bool Configuration(JsonElement? properties, Binding binding,
        out string? nativeState, out string? manualState)
    {
        nativeState = manualState = null;
        if (properties is not { } p) return false;
        nativeState = OptionalText(p, "provisioningState");
        var subnet = OptionalObject(p, "subnet");
        string? subnetId = subnet is { } s ? OptionalText(s, "id") : null;
        if (subnetId is not null) _ = ResourcePath(subnetId, "Microsoft.Network", "virtualNetworks", "subnets");
        var nics = OptionalArray(p, "networkInterfaces");
        bool nicMatch = false;
        if (nics is { } interfaces)
        {
            foreach (var nic in interfaces.EnumerateArray())
            {
                Require(nic.ValueKind == JsonValueKind.Object);
                string? nicId = OptionalText(nic, "id");
                if (nicId is not null) _ = ResourcePath(nicId, "Microsoft.Network", "networkInterfaces");
                if (interfaces.GetArrayLength() == 1) nicMatch = Same(nicId, binding.NicId);
            }
        }
        bool manualMatch = false;
        var manual = OptionalArray(p, "manualPrivateLinkServiceConnections");
        if (manual is { } connections)
        {
            foreach (var connection in connections.EnumerateArray())
            {
                bool match = Connection(connection, binding, out var state);
                if (connections.GetArrayLength() == 1)
                {
                    manualMatch = match;
                    manualState = state;
                }
            }
        }
        var automatic = OptionalArray(p, "privateLinkServiceConnections");
        if (automatic is { } others)
            foreach (var connection in others.EnumerateArray()) _ = Connection(connection, binding, out _);
        return Same(subnetId, binding.SubnetId) && nicMatch && manualMatch &&
            (!p.TryGetProperty("privateLinkServiceConnections", out _) ||
                automatic is { } declaredAutomatic && declaredAutomatic.GetArrayLength() == 0);
    }

    private static bool Connection(JsonElement connection, Binding binding, out string? state)
    {
        state = null;
        Require(connection.ValueKind == JsonValueKind.Object);
        string? name = OptionalText(connection, "name");
        if (name is not null) Require(Segment(name, 256));
        var properties = OptionalObject(connection, "properties");
        if (properties is not { } p) return false;
        string? target = OptionalText(p, "privateLinkServiceId");
        if (target is not null) _ = ResourcePath(target, "Microsoft.KeyVault", "vaults");
        var groups = OptionalArray(p, "groupIds");
        bool groupMatch = false;
        if (groups is { } ids)
        {
            foreach (var group in ids.EnumerateArray()) Require(Segment(String(group), 256));
            groupMatch = ids.GetArrayLength() == 1 && ids[0].GetString() == "vault";
        }
        var linkState = OptionalObject(p, "privateLinkServiceConnectionState");
        string? status = linkState is { } link ? OptionalText(link, "status") : null;
        if (status is "Pending" or "Approved" or "Rejected" or "Disconnected") state = status;
        return name == binding.ConnectionName && Same(target, binding.VaultId) && groupMatch;
    }

    private void Shape(ReadOnlySpan<byte> bytes, bool resource)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = limits.MaximumDepth });
        var stack = new Stack<(HashSet<string>? Names, bool Tags)>();
        bool pendingTags = false;
        int nodes = 0, rows = 0;
        while (reader.Read())
        {
            if (++nodes > limits.MaximumNodes) throw new Boundary(Failure.Budget);
            if (reader.TokenType == JsonTokenType.StartObject)
            {
                if (++rows > limits.MaximumRows) throw new Boundary(Failure.Budget);
                stack.Push((new(StringComparer.OrdinalIgnoreCase), pendingTags));
                pendingTags = false;
            }
            else if (reader.TokenType == JsonTokenType.StartArray)
            {
                stack.Push((null, false));
                pendingTags = false;
            }
            else if (reader.TokenType is JsonTokenType.EndObject or JsonTokenType.EndArray)
            {
                stack.Pop();
                pendingTags = false;
            }
            else if (reader.TokenType == JsonTokenType.PropertyName)
            {
                string name = reader.GetString()!;
                Require(stack.Count > 0 && stack.Peek().Names is { } names && names.Add(name));
                if (!stack.Peek().Tags)
                {
                    foreach (string reserved in Reserved)
                        if (name.Equals(reserved, StringComparison.OrdinalIgnoreCase)) Require(name == reserved);
                    Require(!resource || name is not ("error" or "errors" or "nextLink" or "value" or "partial"));
                }
                pendingTags = stack.Count == 1 && name == "tags";
            }
            else pendingTags = false;
        }
        Require(nodes > 0 && stack.Count == 0);
    }

    private static readonly string[] Reserved =
    [
        "id", "name", "type", "location", "tags", "properties", "provisioningState", "subnet", "networkInterfaces",
        "manualPrivateLinkServiceConnections", "privateLinkServiceConnections", "privateLinkServiceId", "groupIds",
        "privateLinkServiceConnectionState", "status", "error", "errors", "nextLink", "value", "partial",
        "code", "message", "details"
    ];

    private static long? ResponseHeaders(Response response, out string requestId)
    {
        Headers(response.Headers);
        Require(response.Status is not (>= 300 and < 400) && response.Status != 206);
        foreach (string name in new[] { "Content-Range", "Content-Encoding", "Location", "Azure-AsyncOperation", "Operation-Location", "Transfer-Encoding" })
            Require(!response.Headers.Contains(name));
        string[] pieces = Single(response.Headers, "Content-Type").Split(';', StringSplitOptions.TrimEntries);
        Require(pieces.Length is 1 or 2 && pieces[0].Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
            (pieces.Length == 1 || pieces[1].Equals("charset=utf-8", StringComparison.OrdinalIgnoreCase)));
        string id = Single(response.Headers, "x-ms-request-id");
        Require(Segment(id, 128));
        requestId = id;
        if (!response.Headers.Contains("Content-Length")) return null;
        Require(long.TryParse(Single(response.Headers, "Content-Length"), NumberStyles.None,
            CultureInfo.InvariantCulture, out long length) && length >= 0);
        return length;
    }

    private static string Single(ResponseHeaders headers, string name)
    {
        Require(headers.TryGetValues(name, out var source));
        string[] values = source.Take(2).ToArray();
        Require(values.Length == 1);
        return values[0];
    }

    private static void Headers(IEnumerable<HttpHeader> headers)
    {
        int count = 0, bytes = 0;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in headers)
        {
            if (++count > 32 || header.Name.Length > 128 || header.Value.Length > 4096)
                throw new Boundary(Failure.Budget);
            Require(names.Add(header.Name) && header.Name.Length > 0 &&
                header.Name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') &&
                !header.Value.Any(c => !char.IsAscii(c) || char.IsControl(c) && c != '\t'));
            bytes += header.Name.Length + header.Value.Length;
            if (bytes > 16384) throw new Boundary(Failure.Budget);
        }
    }

    private static void Error(JsonElement error)
    {
        Require(error.ValueKind == JsonValueKind.Object);
        foreach (var field in error.EnumerateObject())
            Require(field.Name is not ("errors" or "partial" or "nextLink" or "value" or "status" or "error"));
        _ = Text(error, "code");
        if (error.TryGetProperty("message", out var message)) Require(message.ValueKind == JsonValueKind.String);
        if (error.TryGetProperty("details", out var details))
        {
            Require(details.ValueKind == JsonValueKind.Array);
            foreach (var detail in details.EnumerateArray()) Error(detail);
        }
    }

    private static JsonElement? OptionalObject(JsonElement parent, string field) => Optional(parent, field, JsonValueKind.Object);
    private static JsonElement? OptionalArray(JsonElement parent, string field) => Optional(parent, field, JsonValueKind.Array);
    private static JsonElement? Optional(JsonElement parent, string field, JsonValueKind kind)
    {
        if (!parent.TryGetProperty(field, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        Require(value.ValueKind == kind);
        return value;
    }
    private static string Text(JsonElement parent, string field) => String(parent.GetProperty(field));
    private static string? OptionalText(JsonElement parent, string field) =>
        !parent.TryGetProperty(field, out var value) || value.ValueKind == JsonValueKind.Null ? null : String(value);
    private static string String(JsonElement value)
    {
        Require(value.ValueKind == JsonValueKind.String && TextValue(value.GetString(), 4096));
        return value.GetString()!;
    }
    private static bool Same(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    private static bool TextValue([NotNullWhen(true)] string? value, int maximum) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximum && !value.Any(char.IsControl);
    private static bool Segment(string? value, int maximum) => TextValue(value, maximum) &&
        value is not ("." or "..") && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
    private static void Require([DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw new Boundary();
    }
    private sealed class Boundary(Failure reason = Failure.Boundary) : Exception("private-endpoint-resource-boundary")
    {
        internal Failure Reason { get; } = reason;
    }

    private sealed class Budget(TimeProvider time, DateTimeOffset armedAt, long timestamp, TimeSpan timeout)
    {
        private DateTimeOffset lastWall = DateTimeOffset.MinValue;
        private long lastStamp = long.MinValue;
        internal DateTimeOffset ObservedAt => lastWall;
        internal TimeSpan Remaining { get; private set; }
        internal CancellationTokenSource? Deadline { get; set; }
        internal void Check()
        {
            DateTimeOffset wall = time.GetUtcNow();
            long stamp = time.GetTimestamp();
            Require(wall >= armedAt && stamp >= timestamp && wall >= lastWall && stamp >= lastStamp);
            TimeSpan monotonic = time.GetElapsedTime(timestamp, stamp), elapsedWall = wall - armedAt;
            Require(monotonic >= TimeSpan.Zero && elapsedWall >= TimeSpan.Zero);
            lastWall = wall;
            lastStamp = stamp;
            Remaining = timeout - (monotonic > elapsedWall ? monotonic : elapsedWall);
            if (Remaining <= TimeSpan.Zero) throw new Boundary(Failure.Deadline);
            Deadline?.CancelAfter(Remaining);
        }
    }

    private sealed class ObserverCredential(TokenCredential inner, Budget budget) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken) => throw new Boundary();
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken)
        {
            budget.Check();
            cancellationToken.ThrowIfCancellationRequested();
            Require(context.Scopes.Length == 1 && context.Scopes[0] == Origin + "/.default");
            var token = await inner.GetTokenAsync(context, cancellationToken).ConfigureAwait(false);
            budget.Check();
            cancellationToken.ThrowIfCancellationRequested();
            return token;
        }
    }

    private sealed class ReadTransport(HttpPipelineTransport inner, Uri uri, Budget budget) : HttpPipelineTransport
    {
        private int sends;
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new Boundary();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            budget.Check();
            Require(Interlocked.Increment(ref sends) == 1);
            Validate(message);
            var headers = message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray();
            message.CancellationToken.ThrowIfCancellationRequested();
            message.BufferResponse = false;
            await inner.ProcessAsync(message).ConfigureAwait(false);
            budget.Check();
            message.CancellationToken.ThrowIfCancellationRequested();
            Validate(message);
            Require(headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
        }
        private void Validate(HttpMessage message)
        {
            Require(message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
                message.Request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri);
            Headers(message.Request.Headers);
            Require(message.Request.Headers.TryGetValue("Authorization", out var authorization) &&
                authorization.StartsWith("Bearer ", StringComparison.Ordinal) && authorization.Length > 7);
            if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
        }
    }

    public override string ToString() => "[PrivateEndpointResourceCollector]";
}
