using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using Capture = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// One independent native status GET, not a selected SDK CheckStatus projection.
// This supplies no persisted-resource, cleanup, principal, permission or egress proof.
internal sealed class ManagementOperationStatusCollector
{
    internal const string ArmOrigin = "https://management.azure.com";
    internal enum Failure { None, Boundary, Budget, Denied, Unavailable, ProviderError, Deadline }
    internal sealed record Limits(int MaximumResponseBytes, int MaximumRowBytes, int MaximumRows, TimeSpan Timeout);
    internal sealed record Authority([property: JsonIgnore] string Label,
        [property: JsonIgnore] TokenCredential Credential, [property: JsonIgnore] HttpPipelineTransport Transport)
    {
        public override string ToString() => "[ManagementStatusAuthority]";
    }
    internal sealed class Window(Capture.StatusTarget target, Capture.Binding binding, DateTimeOffset armedAt)
    {
        internal Capture.StatusTarget Target { get; } = target;
        internal Capture.Binding Binding { get; } = binding;
        internal DateTimeOffset ArmedAt { get; } = armedAt;
        internal Guid Id { get; } = Guid.NewGuid();
        public override string ToString() => "[ManagementStatusWindow]";
    }
    internal sealed class Measurement
    {
        internal required Capture.Binding Binding { get; init; }
        internal required Guid WindowId { get; init; }
        internal required Guid StartDispatch { get; init; }
        internal required string TargetSha256 { get; init; }
        internal required string StartResponseSha256 { get; init; }
        internal required DateTimeOffset ArmedAt { get; init; }
        internal required DateTimeOffset StartedAt { get; init; }
        internal required DateTimeOffset FinishedAt { get; init; }
        internal required string Identity { get; init; }
        internal string ApiRevision => Binding.ApiRevision;
        internal required Failure Failure { get; init; }
        internal required SecretStatus Status { get; init; }
        internal required NativeProvisioningState OperationState { get; init; }
        internal required int? HttpStatus { get; init; }
        internal required string? NativeRequestId { get; init; }
        internal bool ResponseComplete => Failure == Failure.None;
        internal bool Terminal => ResponseComplete && OperationState is
            NativeProvisioningState.Succeeded or NativeProvisioningState.Failed or NativeProvisioningState.Canceled;
        public override string ToString() => "[ManagementStatusMeasurement]";
    }

    private sealed class Registration(long timestamp)
    {
        internal long Timestamp { get; } = timestamp;
        internal bool Consumed;
    }

    private readonly Capture source;
    private readonly Authority authority;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly object gate = new();
    private readonly Dictionary<Window, Registration> windows = [];
    private readonly HashSet<Guid> nonces = [], leases = [];

    internal ManagementOperationStatusCollector(Capture source, Authority authority, Limits limits, TimeProvider? time = null)
    {
        if (source is null || authority is null || authority.Credential is null || authority.Transport is null ||
            string.IsNullOrWhiteSpace(authority.Label) || authority.Label.Length > 128 || authority.Label.Any(char.IsControl) ||
            limits is null || limits.MaximumResponseBytes is < 1024 or > 1024 * 1024 ||
            limits.MaximumRowBytes < 256 || limits.MaximumRowBytes > limits.MaximumResponseBytes ||
            limits.MaximumRows is < 1 or > 4096 || limits.Timeout <= TimeSpan.Zero || limits.Timeout > TimeSpan.FromMinutes(2))
            throw new ArgumentException("management-status-input");
        this.source = source;
        this.authority = authority;
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
    }

    // Only the capture owner can qualify a target. Mutable Window fields are never
    // imported, and a caller-created copy of even an identical target has no authority.
    internal Window Arm(Capture.StatusTarget target, Capture.Binding binding)
    {
        if (!source.OwnsStatusTarget(target, binding)) throw new InvalidOperationException("management-status-target");
        try
        {
            Require(target.Kind != Capture.StatusTargetKind.EventGridDeleteAsyncOperation ||
                ReferenceEquals(target.Binding, binding));
            ValidateTarget(target);
        }
        catch (Exception) { throw new InvalidOperationException("management-status-target"); }
        lock (gate)
        {
            if (windows.Count >= 32 || nonces.Contains(binding.Selector.Nonce) || leases.Contains(binding.LeaseId))
                throw new InvalidOperationException("management-status-window");
            var window = new Window(target, binding, time.GetUtcNow());
            windows.Add(window, new(time.GetTimestamp()));
            nonces.Add(binding.Selector.Nonce);
            leases.Add(binding.LeaseId);
            return window;
        }
    }

    // No WaitAsync, background task, polling or second/final resource GET is needed
    // for this status-only evidence. The await owns the entire invocation lifetime,
    // including an uncooperative borrowed credential, send or response-body read.
    internal async ValueTask<Measurement> CollectAsync(Window window, Capture.Binding binding,
        CancellationToken cancellationToken = default)
    {
        Registration registration;
        lock (gate)
        {
            if (window is null || !windows.TryGetValue(window, out var found) || found.Consumed ||
                window.Binding != binding || !source.OwnsStatusTarget(window.Target, binding) ||
                window.Target.Kind == Capture.StatusTargetKind.EventGridDeleteAsyncOperation &&
                    (!ReferenceEquals(window.Binding, binding) || !ReferenceEquals(window.Target.Binding, binding)))
                throw new InvalidOperationException("management-status-window");
            registration = found;
            registration.Consumed = true;
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (window.Target.Kind == Capture.StatusTargetKind.EventGridDeleteAsyncOperation)
            ValidateTarget(window.Target);
        DateTimeOffset started = time.GetUtcNow();
        TimeSpan elapsed = time.GetElapsedTime(registration.Timestamp);
        int? httpStatus = null;
        string? requestId = null;
        if (started < window.ArmedAt || elapsed < TimeSpan.Zero)
            return Finish(Failure.Boundary, NativeProvisioningState.Unknown);
        TimeSpan wallElapsed = started - window.ArmedAt;
        if (elapsed >= limits.Timeout || wallElapsed >= limits.Timeout)
            return Finish(Failure.Deadline, NativeProvisioningState.Unknown);
        using var deadline = new CancellationTokenSource(limits.Timeout -
            (elapsed > wallElapsed ? elapsed : wallElapsed), time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        byte[] storage = new byte[limits.MaximumResponseBytes + 1];
        try
        {
            var boundary = new ReadTransport(authority.Transport, window.Target);
            var options = new ArmClientOptions { Transport = boundary };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            var pipeline = HttpPipelineBuilder.Build(options,
                new BearerTokenAuthenticationPolicy(new ScopeCredential(authority.Credential), ArmOrigin + "/.default"));
            using var message = pipeline.CreateMessage();
            message.BufferResponse = false;
            message.Request.Method = RequestMethod.Get;
            message.Request.Uri.Reset(window.Target.TargetUri);
            await pipeline.SendAsync(message, linked.Token).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            httpStatus = message.Response.Status;
            Headers(message.Response.Headers);
            Require(httpStatus is not (>= 300 and < 400));
            Require(!message.Response.Headers.Contains("Content-Range") && !message.Response.Headers.Contains("Content-Encoding"));
            Require(message.Response.Headers.TryGetValues("Content-Type", out var types));
            string[] mediaTypes = types.Take(2).ToArray();
            Require(mediaTypes.Length == 1 &&
                mediaTypes[0].Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
            foreach (string name in new[] { "Location", "Azure-AsyncOperation", "Operation-Location" })
                if (message.Response.Headers.TryGetValues(name, out var values))
                {
                    string[] entries = values.Take(2).ToArray();
                    Require(entries.Length == 1 && entries[0] == window.Target.TargetUri.AbsoluteUri);
                }
            if (message.Response.Headers.TryGetValues("x-ms-request-id", out var ids))
            {
                string[] entries = ids.Take(2).ToArray();
                Require(entries.Length == 1 && Segment(entries[0], 128));
                requestId = entries[0];
            }
            long? declared = null;
            if (message.Response.Headers.TryGetValues("Content-Length", out var lengths))
            {
                string[] entries = lengths.Take(2).ToArray();
                Require(entries.Length == 1 && long.TryParse(entries[0], NumberStyles.None,
                    CultureInfo.InvariantCulture, out _));
                declared = long.Parse(entries[0], CultureInfo.InvariantCulture);
                Require(declared >= 0);
                if (declared > limits.MaximumResponseBytes) throw new Boundary(Failure.Budget);
            }
            int count = 0;
            if (message.Response.ContentStream is { } input)
            {
                int read;
                while ((read = await input.ReadAsync(storage.AsMemory(count), linked.Token).ConfigureAwait(false)) != 0)
                {
                    count += read;
                    if (count > limits.MaximumResponseBytes) throw new Boundary(Failure.Budget);
                    linked.Token.ThrowIfCancellationRequested();
                }
            }
            linked.Token.ThrowIfCancellationRequested();
            Require(declared is null || declared == count);
            Require(count > 0);
            if (count > limits.MaximumRowBytes) throw new Boundary(Failure.Budget);
            Shape(storage.AsSpan(0, count), limits.MaximumRows);
            using var document = JsonDocument.Parse(storage.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = 16 });
            JsonElement root = document.RootElement;
            Require(root.ValueKind == JsonValueKind.Object && !root.TryGetProperty("nextLink", out _) &&
                !root.TryGetProperty("value", out _) && !root.TryGetProperty("partial", out _) && !root.TryGetProperty("errors", out _));
            foreach (var property in root.EnumerateObject())
                foreach (string reserved in new[] { "status", "error", "id", "name", "type", "properties", "nextLink", "value", "partial", "errors" })
                    if (property.Name.Equals(reserved, StringComparison.OrdinalIgnoreCase)) Require(property.Name == reserved);
            bool error = root.TryGetProperty("error", out var providerError);
            if (error) Error(providerError);
            if (httpStatus is 401 or 403) return Finish(Failure.Denied, NativeProvisioningState.Unknown);
            if (httpStatus >= 400)
            {
                Require(error);
                return Finish(Failure.Unavailable, NativeProvisioningState.Unknown);
            }
            // HTTP202 is acceptance, even if a contradictory body says Succeeded.
            // Only a complete HTTP200 native state can establish settlement here.
            if (httpStatus != 200) return Finish(Failure.Unavailable, NativeProvisioningState.Unknown);
            NativeProvisioningState state = ReadState(window.Target, root);
            if (error && state is not (NativeProvisioningState.Failed or NativeProvisioningState.Canceled))
                return Finish(Failure.ProviderError, NativeProvisioningState.Unknown);
            linked.Token.ThrowIfCancellationRequested();
            return Finish(Failure.None, state);
        }
        catch (Exception exception)
        {
            if (cancellationToken.IsCancellationRequested) throw new OperationCanceledException(cancellationToken);
            Failure failure = deadline.IsCancellationRequested ? Failure.Deadline :
                exception is Boundary b ? b.Reason :
                httpStatus is 401 or 403 ? Failure.Denied : Failure.Unavailable;
            return Finish(failure, NativeProvisioningState.Unknown);
        }
        finally
        {
            // This is reached only after the actual pipeline and parser terminate.
            // No send-return or cancellation callback erases a still-borrowed buffer.
            CryptographicOperations.ZeroMemory(storage);
        }

        Measurement Finish(Failure failure, NativeProvisioningState state)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DateTimeOffset finished = time.GetUtcNow();
            TimeSpan duration = time.GetElapsedTime(registration.Timestamp);
            if (failure == Failure.None && (finished < started || duration < TimeSpan.Zero))
                failure = Failure.Boundary;
            if (failure == Failure.None && duration >= limits.Timeout) failure = Failure.Deadline;
            if (failure == Failure.None && finished - window.ArmedAt >= limits.Timeout) failure = Failure.Deadline;
            if (failure != Failure.None) state = NativeProvisioningState.Unknown;
            return new()
            {
                Binding = binding,
                WindowId = window.Id,
                StartDispatch = window.Target.StartDispatch,
                TargetSha256 = window.Target.TargetSha256,
                StartResponseSha256 = window.Target.StartResponseSha256,
                ArmedAt = window.ArmedAt,
                StartedAt = started,
                FinishedAt = finished,
                Identity = authority.Label,
                Failure = failure,
                HttpStatus = httpStatus,
                NativeRequestId = requestId,
                OperationState = state,
                Status = failure == Failure.Denied ? SecretStatus.Denied : failure != Failure.None ? SecretStatus.Unavailable :
                    state == NativeProvisioningState.Succeeded ? SecretStatus.Success :
                    state == NativeProvisioningState.Pending ? SecretStatus.Pending : SecretStatus.Unknown
            };
        }
    }

    private static void ValidateTarget(Capture.StatusTarget target)
    {
        var binding = target.Binding;
        Uri uri = target.TargetUri;
        Require(target.StartDispatch != Guid.Empty && Hash(target.TargetSha256) && Hash(target.StartResponseSha256) &&
            uri.IsAbsoluteUri && uri.OriginalString.Length <= 2048 && uri.OriginalString == uri.AbsoluteUri &&
            uri.Scheme == "https" && uri.IsDefaultPort && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
            uri.GetLeftPart(UriPartial.Authority) == ArmOrigin && uri.Query == "?api-version=" + binding.ApiRevision);
        string revision = binding.Operation switch
        {
            ManagementMutation.CreateOrUpdateNotification or ManagementMutation.UpdateNotification or
                ManagementMutation.DeleteNotification => "2025-02-15",
            ManagementMutation.DeleteRoleAssignment => "2022-04-01",
            _ => "2026-02-01"
        };
        Require(binding.ApiRevision == revision && binding.LeaseId != Guid.Empty && binding.Selector.Nonce != Guid.Empty);
        if (target.Kind == Capture.StatusTargetKind.SelectedResource)
            Require(binding.Resource is NotificationScope n && binding.Operation is
                (ManagementMutation.CreateOrUpdateNotification or ManagementMutation.UpdateNotification or ManagementMutation.DeleteNotification) &&
                uri.AbsolutePath == n.Vault.ExportResourceId() + "/providers/Microsoft.EventGrid/eventSubscriptions/" + n.SubscriptionName);
        else if (target.Kind == Capture.StatusTargetKind.EventGridDeleteAsyncOperation)
        {
            Require(binding.Operation == ManagementMutation.DeleteNotification &&
                binding.Resource is NotificationScope &&
                binding.Selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
                    Variant: "operation.DeleteNotification", Case: "denied-authority" } &&
                !uri.OriginalString.Contains('%'));
            var notification = (NotificationScope)binding.Resource;
            var group = notification.Vault.ResourceGroup;
            string prefix = $"/subscriptions/{group.Subscription.SubscriptionId:D}/resourceGroups/{group.ResourceGroup}/providers/Microsoft.EventGrid/locations/";
            Require(uri.AbsolutePath.StartsWith(prefix, StringComparison.Ordinal));
            string[] tail = uri.AbsolutePath[prefix.Length..].Split('/');
            Require(tail.Length == 5 && tail[0].Length is > 0 and <= 50 &&
                tail[0].All(char.IsAsciiLetterOrDigit) && tail[1] == "operationResults" &&
                Guid.TryParseExact(tail[2], "D", out var id) && id != Guid.Empty &&
                tail[2] == id.ToString("D") && tail[3] == "Spring" && tail[4] == "default" &&
                uri.OriginalString == ArmOrigin + uri.AbsolutePath + "?api-version=2025-02-15");
        }
        else
        {
            Require(target.Kind == Capture.StatusTargetKind.Operation && Segment(binding.Location, 50));
            Guid subscription = binding.Resource switch
            {
                VaultScope v when binding.Operation is ManagementMutation.CreateOrUpdateVault or
                    ManagementMutation.RecoverVault or ManagementMutation.DeleteVault => v.ResourceGroup.Subscription.SubscriptionId,
                DeletedVaultScope d when binding.Operation == ManagementMutation.PurgeDeletedVault && d.Location == binding.Location =>
                    d.Subscription.SubscriptionId,
                PrivateConnectionScope c when binding.Operation is ManagementMutation.UpdatePrivateConnection or
                    ManagementMutation.DeletePrivateConnection => c.Vault.ResourceGroup.Subscription.SubscriptionId,
                _ => throw new Boundary()
            };
            string prefix = $"/subscriptions/{subscription:D}/providers/Microsoft.KeyVault/locations/{binding.Location}/";
            Require(uri.AbsolutePath.StartsWith(prefix, StringComparison.Ordinal));
            string[] tail = uri.AbsolutePath[prefix.Length..].Split('/');
            Require(tail.Length == 2 && tail[0] is "operations" or "operationResults" &&
                Guid.TryParseExact(tail[1], "D", out var id) && id != Guid.Empty);
        }
        byte[] coordinate = Encoding.UTF8.GetBytes(uri.AbsoluteUri);
        Span<byte> digest = stackalloc byte[32];
        try
        {
            SHA256.HashData(coordinate, digest);
            Require(Convert.ToHexString(digest) == target.TargetSha256);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(coordinate);
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private static NativeProvisioningState ReadState(Capture.StatusTarget target, JsonElement root)
    {
        if (target.Kind == Capture.StatusTargetKind.EventGridDeleteAsyncOperation)
        {
            // This is the issued operation envelope, not the selected child.
            // No resource state, error mixture or optional envelope fields qualify.
            Require(root.EnumerateObject().Count() == 1 &&
                root.TryGetProperty("status", out var status) && status.ValueKind == JsonValueKind.String);
            return root.GetProperty("status").GetString() switch
            {
                "Succeeded" => NativeProvisioningState.Succeeded,
                "InProgress" or "Deleting" => NativeProvisioningState.Pending,
                _ => NativeProvisioningState.Unknown
            };
        }
        string text;
        if (target.Kind == Capture.StatusTargetKind.Operation)
        {
            if (root.TryGetProperty("id", out var id))
                Require(id.ValueKind == JsonValueKind.String &&
                    (id.GetString() == target.TargetUri.AbsolutePath || id.GetString() == target.TargetUri.AbsoluteUri));
            if (root.TryGetProperty("name", out var name))
                Require(name.ValueKind == JsonValueKind.String && name.GetString() == target.TargetUri.Segments[^1]);
            Require(!root.TryGetProperty("properties", out var properties) ||
                properties.ValueKind == JsonValueKind.Object && !properties.EnumerateObject()
                    .Any(p => p.Name.Equals("provisioningState", StringComparison.OrdinalIgnoreCase)));
            Require(root.TryGetProperty("status", out var status) && status.ValueKind == JsonValueKind.String);
            text = status.GetString()!;
        }
        else
        {
            Require(target.Binding.Resource is NotificationScope);
            var notification = (NotificationScope)target.Binding.Resource;
            Require(!root.TryGetProperty("status", out _) &&
                root.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String && id.GetString() == target.TargetUri.AbsolutePath &&
                root.TryGetProperty("name", out var name) && name.ValueKind == JsonValueKind.String && name.GetString() == notification.SubscriptionName &&
                root.TryGetProperty("type", out var type) && type.ValueKind == JsonValueKind.String && type.GetString() == "Microsoft.EventGrid/eventSubscriptions" &&
                root.TryGetProperty("properties", out var properties) && properties.ValueKind == JsonValueKind.Object);
            // Identity fields are checked, but no destination/configuration is
            // projected as a separate persisted-state or permission observation.
            var p = root.GetProperty("properties");
            Require(p.TryGetProperty("topic", out var topic) && topic.ValueKind == JsonValueKind.String &&
                topic.GetString() == notification.Vault.ExportResourceId() &&
                p.TryGetProperty("provisioningState", out var state) && state.ValueKind == JsonValueKind.String);
            text = p.GetProperty("provisioningState").GetString()!;
        }
        Require(text.Length is > 0 and <= 128 && !text.Any(char.IsControl));
        // A still-present subscription's provisioning success is not successful
        // deletion. Only its explicit deleting state supplies pending evidence.
        if (target.Binding.Operation == ManagementMutation.DeleteNotification &&
            !text.Equals("Deleting", StringComparison.OrdinalIgnoreCase))
            return NativeProvisioningState.Unknown;
        return text.ToLowerInvariant() switch
        {
            "succeeded" => NativeProvisioningState.Succeeded,
            "failed" => NativeProvisioningState.Failed,
            "canceled" or "cancelled" => NativeProvisioningState.Canceled,
            "accepted" or "inprogress" or "running" or "creating" or "updating" or "deleting" => NativeProvisioningState.Pending,
            _ => NativeProvisioningState.Unknown
        };
    }

    // Preflight the whole bounded row before creating the document or result.
    // Case-folded duplicate names are ambiguous even when JSON itself allows them.
    private static void Shape(ReadOnlySpan<byte> bytes, int maximumRows)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = 16 });
        var objects = new Stack<HashSet<string>?>();
        int rows = 0;
        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.PropertyName:
                    Require(objects.Count > 0 && objects.Peek() is { } names && names.Add(reader.GetString()!));
                    break;
                case JsonTokenType.EndObject:
                case JsonTokenType.EndArray:
                    objects.Pop();
                    break;
                default:
                    if (++rows > maximumRows) throw new Boundary(Failure.Budget);
                    if (reader.TokenType == JsonTokenType.StartObject) objects.Push(new(StringComparer.OrdinalIgnoreCase));
                    if (reader.TokenType == JsonTokenType.StartArray) objects.Push(null);
                    break;
            }
        }
        Require(rows > 0 && objects.Count == 0);
    }

    private static void Error(JsonElement error)
    {
        Require(error.ValueKind == JsonValueKind.Object &&
            error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String &&
            code.GetString() is { Length: > 0 and <= 256 });
        if (error.TryGetProperty("message", out var message)) Require(message.ValueKind == JsonValueKind.String);
        if (error.TryGetProperty("target", out var target)) Require(target.ValueKind == JsonValueKind.String);
        if (error.TryGetProperty("details", out var details))
        {
            Require(details.ValueKind == JsonValueKind.Array);
            foreach (var detail in details.EnumerateArray()) Error(detail);
        }
        if (error.TryGetProperty("innererror", out var inner)) Require(inner.ValueKind == JsonValueKind.Object);
    }

    private static void Headers(IEnumerable<HttpHeader> headers)
    {
        int rows = 0, bytes = 0;
        foreach (var header in headers)
        {
            if (++rows > 32 || header.Name.Length > 128 || header.Value.Length > 4096) throw new Boundary(Failure.Budget);
            Require(header.Name.Length > 0 && header.Name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') &&
                !header.Value.Any(c => !char.IsAscii(c) || char.IsControl(c) && c != '\t'));
            bytes += header.Name.Length + header.Value.Length;
            if (bytes > 16384) throw new Boundary(Failure.Budget);
        }
    }

    private static bool Hash(string value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
    private static bool Segment(string value, int maximum) => value is { Length: > 0 } && value.Length <= maximum &&
        value is not ("." or "..") && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
    private static void Require([DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw new Boundary();
    }
    private sealed class Boundary(Failure reason = Failure.Boundary) : Exception("management-status-boundary")
    {
        internal Failure Reason { get; } = reason;
    }

    // No policy can change the closed GET after the credential has supplied its
    // explicit ARM audience. The host transport remains borrowed and unqualified.
    private sealed class ReadTransport(HttpPipelineTransport inner, Capture.StatusTarget target) : HttpPipelineTransport
    {
        private int sent;
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new Boundary();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            Require(Interlocked.Increment(ref sent) == 1 && message.Request.Method == RequestMethod.Get &&
                message.Request.Uri.ToUri().AbsoluteUri == target.TargetUri.AbsoluteUri && message.Request.Content is null);
            Headers(message.Request.Headers);
            Require(message.Request.Headers.TryGetValue("Authorization", out var authorization) &&
                authorization.StartsWith("Bearer ", StringComparison.Ordinal));
            if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
            message.CancellationToken.ThrowIfCancellationRequested();
            message.BufferResponse = false;
            await inner.ProcessAsync(message).ConfigureAwait(false);
            Require(message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
                message.Request.Uri.ToUri().AbsoluteUri == target.TargetUri.AbsoluteUri);
        }
    }
    private sealed class ScopeCredential(TokenCredential inner) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new Boundary();
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(requestContext.Scopes.Length == 1 && requestContext.Scopes[0] == ArmOrigin + "/.default");
            return inner.GetTokenAsync(requestContext, cancellationToken);
        }
    }

    public override string ToString() => "[ManagementOperationStatusCollector]";
}
