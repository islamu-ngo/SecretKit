using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using SecretKit.Core;
using M = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Independent versioned runtime reads, not ARM metadata or network attestation.
// The host explicitly declares each borrowed credential/transport pair. Sharing
// a credential is allowed; neither labels nor token contents prove a principal
// or an egress path. Nothing here changes permissions or connection state.
internal sealed class VaultNetworkReadCollector
{
    internal const string Revision = "2025-07-01";
    internal const string Audience = "https://vault.azure.net/.default";
    internal enum Failure { None, Boundary, Budget, Unavailable, Deadline }
    internal sealed record Limits(int MaximumResponseBytes, int MaximumRowBytes, int MaximumNodes,
        int MaximumRows, int MaximumDepth, TimeSpan Timeout);
    internal sealed record Authority([property: JsonIgnore] string Label,
        [property: JsonIgnore] TokenCredential Credential, [property: JsonIgnore] HttpPipelineTransport Transport)
    {
        public override string ToString() => "[VaultNetworkReadAuthority]";
    }
    internal sealed record Binding([property: JsonIgnore] M.Binding Original,
        [property: JsonIgnore] string CanaryName, [property: JsonIgnore] string CanaryVersion,
        [property: JsonIgnore] string CanarySha256, [property: JsonIgnore] string ApiRevision)
    {
        public override string ToString() => "[VaultNetworkReadBinding]";
    }
    internal sealed class Window
    {
        private Window(Binding binding, DateTimeOffset armedAt) { Binding = binding; ArmedAt = armedAt; }
        internal Binding Binding { get; }
        internal DateTimeOffset ArmedAt { get; }
        internal Guid Id { get; } = Guid.NewGuid();
        // Construction alone grants no ownership. Only reference membership in
        // the source's private registry can acquire this one-use window.
        internal static Window Create(Binding binding, DateTimeOffset armedAt) => new(binding, armedAt);
        public override string ToString() => "[VaultNetworkReadWindow]";
    }
    internal sealed class Read
    {
        internal required SecretStatus Status { get; init; }
        internal required Failure Failure { get; init; }
        internal required string Identity { get; init; }
        internal required IReadOnlyList<string> NativeRequestIds { get; init; }
        internal string? CanarySha256 { get; init; }
        public override string ToString() => "[VaultNetworkRead]";
    }
    internal sealed class Measurement
    {
        internal required Binding Binding { get; init; }
        internal required Guid WindowId { get; init; }
        internal required DateTimeOffset ArmedAt { get; init; }
        internal required DateTimeOffset StartedAt { get; init; }
        internal required DateTimeOffset FinishedAt { get; init; }
        internal string ApiRevision => Revision;
        internal required Read PrivateRead { get; init; }
        internal required Read PublicRead { get; init; }
        internal bool PrincipalQualified => false;
        internal bool EgressQualified => false;
        public override string ToString() => "[VaultNetworkReadMeasurement]";
    }
    private sealed class Registration(long timestamp)
    {
        internal long Timestamp { get; } = timestamp;
        internal bool Consumed;
    }
    private readonly Authority privateAuthority, publicAuthority;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly object gate = new();
    private readonly Dictionary<Window, Registration> windows = [];
    private readonly HashSet<Guid> nonces = [], leases = [];

    internal VaultNetworkReadCollector(Authority privateAuthority, Authority publicAuthority, Limits limits, TimeProvider time)
    {
        if (!ValidAuthority(privateAuthority) || !ValidAuthority(publicAuthority) || limits is null || time is null ||
            limits.MaximumResponseBytes is < 1024 or > 1024 * 1024 ||
            limits.MaximumRowBytes is < 256 || limits.MaximumRowBytes > limits.MaximumResponseBytes ||
            limits.MaximumNodes is < 8 or > 65536 || limits.MaximumRows is < 1 or > 4096 ||
            limits.MaximumDepth is < 2 or > 32 ||
            limits.Timeout <= TimeSpan.Zero || limits.Timeout > TimeSpan.FromMinutes(2))
            throw new ArgumentException("vault-network-read-input");
        this.privateAuthority = privateAuthority;
        this.publicAuthority = publicAuthority;
        this.limits = limits;
        this.time = time;
    }

    internal Window Arm(Binding binding)
    {
        try { ValidateBinding(binding); }
        catch (Exception) { throw new ArgumentException("vault-network-read-binding"); }
        lock (gate)
        {
            if (windows.Count >= 32 || nonces.Contains(binding.Original.Selector.Nonce) || leases.Contains(binding.Original.LeaseId))
                throw new InvalidOperationException("vault-network-read-window");
            var window = Window.Create(binding, time.GetUtcNow());
            windows.Add(window, new(time.GetTimestamp()));
            nonces.Add(binding.Original.Selector.Nonce);
            leases.Add(binding.Original.LeaseId);
            return window;
        }
    }

    internal async ValueTask<Measurement> CollectAsync(Window window, Binding binding, CancellationToken cancellationToken = default)
    {
        Registration registration;
        lock (gate)
        {
            if (window is null || !windows.TryGetValue(window, out var found) || found.Consumed || window.Binding != binding)
                throw new InvalidOperationException("vault-network-read-window");
            registration = found;
            registration.Consumed = true;
        }
        cancellationToken.ThrowIfCancellationRequested();
        var budget = new Budget(time, window.ArmedAt, registration.Timestamp, limits.Timeout);
        Read privateRead, publicRead;
        DateTimeOffset started = window.ArmedAt;
        try { budget.Check(); started = budget.ObservedAt; }
        catch (Boundary failure)
        {
            cancellationToken.ThrowIfCancellationRequested();
            privateRead = Unavailable(privateAuthority, failure.Reason);
            publicRead = Unavailable(publicAuthority, failure.Reason);
            return Finish();
        }
        using var deadline = new CancellationTokenSource(budget.Remaining, time);
        budget.Deadline = deadline;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        // Sequential calls bound retained SDK work to one actual task. A failed
        // public read cannot erase an already completed private observation.
        privateRead = await ReadAsync(privateAuthority, binding, budget, linked.Token, cancellationToken).ConfigureAwait(false);
        publicRead = await ReadAsync(publicAuthority, binding, budget, linked.Token, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        try { budget.Check(); }
        catch (Boundary failure) { publicRead = Unavailable(publicAuthority, failure.Reason); }
        cancellationToken.ThrowIfCancellationRequested();
        return Finish();

        Measurement Finish() => new()
        {
            Binding = window.Binding,
            WindowId = window.Id,
            ArmedAt = window.ArmedAt,
            StartedAt = started,
            FinishedAt = budget.ObservedAt,
            PrivateRead = privateRead,
            PublicRead = publicRead
        };
    }

    private async Task<Read> ReadAsync(Authority authority, Binding binding, Budget budget,
        CancellationToken token, CancellationToken caller)
    {
        // The transport owns all mutable response storage until this method's
        // actual SDK task has terminated, including SDK parsing/error handling.
        var credential = new BoundCredential(authority.Credential, budget);
        var boundary = new NativeTransport(authority, credential, binding, limits, budget);
        try
        {
            using (boundary)
            {
                try
                {
                    token.ThrowIfCancellationRequested();
                    budget.Check();
                    var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01) { Transport = boundary };
                    options.Retry.MaxRetries = 0;
                    options.Diagnostics.IsLoggingEnabled = false;
                    options.Diagnostics.IsLoggingContentEnabled = false;
                    options.Diagnostics.IsDistributedTracingEnabled = false;
                    // A cached SDK challenge may request authentication before
                    // transport dispatch. Both paths use this invocation's same
                    // declared authority; no discovery dispatch is admitted.
                    var client = new SecretClient(Origin(binding), credential, options);
                    Task<Response<KeyVaultSecret>> actual = client.GetSecretAsync(binding.CanaryName,
                        binding.CanaryVersion, cancellationToken: token);
                    var response = await actual.ConfigureAwait(false);
                    token.ThrowIfCancellationRequested();
                    budget.Check();
                    Require(boundary.Valid && boundary.Status == 200);
                    var secret = response.Value;
                    Require(secret.Id?.OriginalString == SecretId(binding) && secret.Name == binding.CanaryName &&
                        secret.Properties.Version == binding.CanaryVersion &&
                        secret.Properties.VaultUri == Origin(binding) && secret.Value is not null &&
                        Hash(secret.Value) == binding.CanarySha256 && secret.Properties.Enabled == true);
                    token.ThrowIfCancellationRequested();
                    budget.Check();
                    return Valid(SecretStatus.Success, binding.CanarySha256);
                }
                catch (RequestFailedException) when (boundary.Valid && boundary.Status is 403 or 404)
                {
                    caller.ThrowIfCancellationRequested();
                    if (token.IsCancellationRequested) return Unavailable(authority, Failure.Deadline);
                    budget.Check();
                    caller.ThrowIfCancellationRequested();
                    return Valid(boundary.Status == 403 ? SecretStatus.Denied : SecretStatus.Absent, null);
                }
            }
        }
        catch (Exception error)
        {
            caller.ThrowIfCancellationRequested();
            return Unavailable(authority, token.IsCancellationRequested ? Failure.Deadline :
                error is Boundary failure ? failure.Reason : Failure.Unavailable);
        }

        Read Valid(SecretStatus status, string? hash) => new()
        {
            Status = status,
            Failure = Failure.None,
            Identity = authority.Label,
            CanarySha256 = hash,
            NativeRequestIds = Array.AsReadOnly(new[] { boundary.RequestId! })
        };
    }

    private static Read Unavailable(Authority authority, Failure failure) => new()
    {
        Status = SecretStatus.Unavailable,
        Failure = failure,
        Identity = authority.Label,
        NativeRequestIds = Array.Empty<string>()
    };
    private static Uri Origin(Binding binding) => new("https://" + binding.Original.VaultName + ".vault.azure.net");
    private static string SecretId(Binding binding) => Origin(binding).GetLeftPart(UriPartial.Authority) +
        "/secrets/" + binding.CanaryName + "/" + binding.CanaryVersion;

    private static void ValidateBinding(Binding b)
    {
        Require(b is not null && b.Original is { } original && original.Selector is not null &&
            original.LeaseId != Guid.Empty && original.Selector.Nonce != Guid.Empty && original.SubscriptionId != Guid.Empty &&
            original.Query is M.QueryKind.GetPrivateConnection or M.QueryKind.UpdatePrivateConnection or
                M.QueryKind.DeletePrivateConnection or M.QueryKind.ListPrivateConnections or M.QueryKind.ListPrivateLinkResources &&
            original.Read == M.DefaultRead(original.Query) && original.Selector.Operation == M.Operation(original.Query) &&
            Segment(original.ResourceGroup, 90) && Segment(original.Location, 50) && Segment(original.ConnectionName, 256) &&
            original.VaultName is { Length: >= 3 and <= 24 } vault &&
            char.IsAsciiLetter(vault[0]) && char.IsAsciiLetterOrDigit(vault[^1]) &&
            vault.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') && !vault.Contains("--", StringComparison.Ordinal) &&
            Text(original.Selector.Scope, 512) &&
            original.Selector.Case is "selected-contract" or "denied-authority" or "cancellation-boundary" or
                "lost-response-no-replay" or "independent-effect" &&
            b.ApiRevision == Revision && Segment(b.CanaryName, 127) &&
            b.CanaryName.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') &&
            b.CanaryVersion is { Length: 32 } && b.CanaryVersion.All(char.IsAsciiHexDigit) &&
            b.CanarySha256 is { Length: 64 } && b.CanarySha256.All(c => char.IsAsciiHexDigit(c) && !char.IsAsciiLetterLower(c)));
        var member = VaultAdministrationEffects.Members.Single(m => m.Operation == b.Original.Selector.Operation);
        Require(member.Variants.Contains(b.Original.Selector.Variant, StringComparer.Ordinal));
    }

    private sealed class NativeTransport(Authority authority, BoundCredential credential, Binding binding, Limits limits, Budget budget)
        : HttpPipelineTransport, IDisposable
    {
        private readonly byte[] storage = new byte[limits.MaximumResponseBytes + 1];
        private Response? response;
        private Stream? input;
        private MemoryStream? buffered;
        private int sends;
        internal bool Valid { get; private set; }
        internal int Status { get; private set; }
        internal string? RequestId { get; private set; }
        public override Request CreateRequest() => authority.Transport.CreateRequest();
        public override void Process(HttpMessage message) => throw new Boundary();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            Check();
            Require(Interlocked.Increment(ref sends) == 1);
            ValidateRequest(message);
            // Await the real credential task, even when its implementation
            // ignores cancellation. No waiter task is mistaken for its exit.
            var token = credential.Issued ?? await credential.GetTokenAsync(new TokenRequestContext([Audience]),
                message.CancellationToken).ConfigureAwait(false);
            Check();
            Require(Text(token.Token, 16384) && token.ExpiresOn > budget.ObservedAt);
            message.Request.Headers.SetValue("Authorization", "Bearer " + token.Token);
            ValidateRequest(message);
            var headers = message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray();
            Check();
            message.BufferResponse = false;
            try { await authority.Transport.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) response = message.Response; }
            Check();
            ValidateRequest(message);
            Require(headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
            Require(response is not null);
            Status = response.Status;
            long? length = ResponseHeaders(response, out string requestId);
            Require(Status is 200 or 403 or 404);
            if (length > limits.MaximumResponseBytes) throw new Boundary(Failure.Budget);
            int count = 0;
            input = response.ContentStream;
            Require(input is not null);
            while (true)
            {
                Check();
                int read = await input.ReadAsync(storage.AsMemory(count), message.CancellationToken).ConfigureAwait(false);
                Check();
                if (read == 0) break;
                count += read;
                if (count > limits.MaximumResponseBytes) throw new Boundary(Failure.Budget);
            }
            Require(count > 0 && (length is null || length == count));
            if (count > limits.MaximumRowBytes) throw new Boundary(Failure.Budget);
            Shape(storage.AsSpan(0, count), limits);
            using (var document = JsonDocument.Parse(storage.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = limits.MaximumDepth }))
            {
                var root = document.RootElement;
                Require(root.ValueKind == JsonValueKind.Object);
                if (Status == 200) Secret(root, binding, budget.ObservedAt);
                else Error(root, Status);
            }
            Check();
            input.Dispose();
            input = null;
            // The installed SDK can obtain raw buffered content using the
            // MemoryStream whole-buffer path. It must see offset zero and the
            // exact payload length, not an exhausted read buffer or spare bytes.
            buffered = new(storage, 0, count, false, true);
            response.ContentStream = buffered;
            RequestId = requestId;
            Valid = true;

            void Check()
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                budget.Check();
            }
        }

        private void ValidateRequest(HttpMessage message)
        {
            Require(message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
                message.Request.Uri.ToUri().OriginalString == SecretId(binding) + "?api-version=" + Revision);
            int count = 0, bytes = 0;
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var header in message.Request.Headers)
            {
                Require(++count <= 32 && header.Name.Length is > 0 and <= 128 && header.Value.Length <= 16384 &&
                    names.Add(header.Name) && !header.Value.Any(c => !char.IsAscii(c) || char.IsControl(c)));
                bytes += header.Name.Length + header.Value.Length;
                Require(bytes <= 32768);
            }
            if (message.Request.Headers.TryGetValue("Host", out string? host))
                Require(host == Origin(binding).Host);
        }
        public void Dispose()
        {
            // Called only after GetSecretAsync's actual task ends. Borrowed
            // clients/transports/credentials are never disposed by this source.
            try
            {
                try { input?.Dispose(); }
                finally
                {
                    try { buffered?.Dispose(); }
                    finally { response?.Dispose(); }
                }
            }
            catch (Exception) { throw new Boundary(); }
            finally { CryptographicOperations.ZeroMemory(storage); }
        }
        public override string ToString() => "[VaultNetworkReadTransport]";
    }

    private static void Secret(JsonElement root, Binding binding, DateTimeOffset now)
    {
        Require(Only(root, "value", "id", "attributes", "contentType", "tags", "kid", "managed") &&
            root.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.String &&
            value.GetString() is { Length: > 0 and <= 4096 } material &&
            root.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String &&
            id.GetString() == SecretId(binding) && Hash(material) == binding.CanarySha256 &&
            root.TryGetProperty("attributes", out var attributes) &&
            Only(attributes, "enabled", "nbf", "exp", "created", "updated", "recoveryLevel", "recoverableDays") &&
            attributes.TryGetProperty("enabled", out var enabled) && enabled.ValueKind == JsonValueKind.True);
        var a = root.GetProperty("attributes");
        foreach (string date in new[] { "nbf", "exp", "created", "updated" })
        {
            if (!a.TryGetProperty(date, out var native)) continue;
            Require(native.ValueKind == JsonValueKind.Number && native.TryGetInt64(out _));
            var instant = DateTimeOffset.FromUnixTimeSeconds(native.GetInt64());
            if (date == "nbf") Require(instant <= now);
            if (date == "exp") Require(instant > now);
        }
        if (a.TryGetProperty("recoveryLevel", out var recovery))
            Require(recovery.ValueKind == JsonValueKind.String && recovery.GetString() is
                "Purgeable" or "Recoverable+Purgeable" or "Recoverable" or "Recoverable+ProtectedSubscription" or
                "CustomizedRecoverable+Purgeable" or "CustomizedRecoverable" or "CustomizedRecoverable+ProtectedSubscription");
        if (a.TryGetProperty("recoverableDays", out var days))
            Require(days.ValueKind == JsonValueKind.Number && days.TryGetInt32(out int count) && count is >= 7 and <= 90);
        foreach (string field in new[] { "contentType", "kid" })
            if (root.TryGetProperty(field, out var text)) Require(text.ValueKind == JsonValueKind.String && Text(text.GetString(), 4096));
        if (root.TryGetProperty("managed", out var managed)) Require(managed.ValueKind is JsonValueKind.True or JsonValueKind.False);
        if (root.TryGetProperty("tags", out var tags))
            Require(tags.ValueKind == JsonValueKind.Object && tags.EnumerateObject().All(p =>
                Text(p.Name, 256) && p.Value.ValueKind == JsonValueKind.String && p.Value.GetString()!.Length <= 256));
    }

    private static void Error(JsonElement root, int status)
    {
        Require(Only(root, "error") && root.TryGetProperty("error", out var error) &&
            Only(error, "code", "message", "innererror", "details") &&
            error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String &&
            code.GetString() == (status == 403 ? "Forbidden" : "SecretNotFound"));
        ValidateError(root.GetProperty("error"));
    }
    private static void ValidateError(JsonElement error)
    {
        Require(Only(error, "code", "message", "innererror", "details") &&
            error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String && Text(code.GetString(), 128));
        if (error.TryGetProperty("message", out var message)) Require(message.ValueKind == JsonValueKind.String);
        if (error.TryGetProperty("innererror", out var inner)) ValidateError(inner);
        if (error.TryGetProperty("details", out var details))
        {
            Require(details.ValueKind == JsonValueKind.Array);
            foreach (var detail in details.EnumerateArray()) ValidateError(detail);
        }
    }

    private static void Shape(ReadOnlySpan<byte> bytes, Limits limits)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = limits.MaximumDepth });
        var stack = new Stack<HashSet<string>?>();
        int nodes = 0, rows = 0;
        while (reader.Read())
        {
            if (++nodes > limits.MaximumNodes) throw new Boundary(Failure.Budget);
            if (reader.TokenType == JsonTokenType.StartObject)
            {
                if (++rows > limits.MaximumRows) throw new Boundary(Failure.Budget);
                stack.Push(new(StringComparer.OrdinalIgnoreCase));
            }
            else if (reader.TokenType == JsonTokenType.StartArray) stack.Push(null);
            else if (reader.TokenType is JsonTokenType.EndArray or JsonTokenType.EndObject) stack.Pop();
            else if (reader.TokenType == JsonTokenType.PropertyName)
            {
                string name = reader.GetString()!;
                Require(stack.Count > 0 && stack.Peek() is { } names && names.Add(name));
                foreach (string reserved in Reserved)
                    if (name.Equals(reserved, StringComparison.OrdinalIgnoreCase)) Require(name == reserved);
            }
        }
        Require(nodes > 0 && stack.Count == 0);
    }
    private static readonly string[] Reserved =
    [
        "value", "id", "attributes", "enabled", "nbf", "exp", "created", "updated", "recoveryLevel", "recoverableDays",
        "contentType", "tags", "kid", "managed", "error", "errors", "code", "message", "innererror", "details",
        "partial", "nextLink", "status"
    ];
    private static long? ResponseHeaders(Response response, out string requestId)
    {
        int count = 0, bytes = 0;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in response.Headers)
        {
            if (++count > 32 || header.Name.Length > 128 || header.Value.Length > 4096) throw new Boundary(Failure.Budget);
            Require(names.Add(header.Name) && header.Name.Length > 0 &&
                header.Name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') &&
                !header.Value.Any(c => !char.IsAscii(c) || char.IsControl(c) && c != '\t'));
            bytes += header.Name.Length + header.Value.Length;
            if (bytes > 16384) throw new Boundary(Failure.Budget);
        }
        foreach (string name in new[] { "Content-Range", "Content-Encoding", "Location", "Azure-AsyncOperation",
            "Operation-Location", "Transfer-Encoding" }) Require(!response.Headers.Contains(name));
        string type = Single(response, "Content-Type");
        string[] parts = type.Split(';', StringSplitOptions.TrimEntries);
        Require(parts.Length is 1 or 2 && parts[0].Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
            (parts.Length == 1 || parts[1].Equals("charset=utf-8", StringComparison.OrdinalIgnoreCase)));
        requestId = Single(response, "x-ms-request-id");
        Require(Segment(requestId, 128));
        if (!response.Headers.Contains("Content-Length")) return null;
        Require(long.TryParse(Single(response, "Content-Length"), NumberStyles.None, CultureInfo.InvariantCulture,
            out long length) && length >= 0);
        return length;
    }
    private static string Single(Response response, string name)
    {
        Require(response.Headers.TryGetValues(name, out var source));
        string[] values = source.Take(2).ToArray();
        Require(values.Length == 1);
        return values[0];
    }
    private static string Hash(string material)
    {
        byte[] bytes = new UTF8Encoding(false, true).GetBytes(material);
        try { return Convert.ToHexString(SHA256.HashData(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        // Immutable strings allocated by JSON/the native SDK cannot be erased.
    }
    private static bool Only(JsonElement value, params string[] names) => value.ValueKind == JsonValueKind.Object &&
        value.EnumerateObject().All(p => names.Contains(p.Name, StringComparer.Ordinal));
    private static bool Text([NotNullWhen(true)] string? value, int maximum) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximum && !value.Any(char.IsControl);
    private static bool Segment(string? value, int maximum) => Text(value, maximum) && value is not ("." or "..") &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
    private static bool ValidAuthority([NotNullWhen(true)] Authority? authority) =>
        authority is not null && Text(authority.Label, 128) && authority.Credential is not null && authority.Transport is not null;
    private static void Require([DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw new Boundary();
    }
    private sealed class Boundary(Failure reason = Failure.Boundary) : Exception("vault-network-read-boundary")
    {
        internal Failure Reason { get; } = reason;
    }
    private sealed class BoundCredential(TokenCredential inner, Budget budget) : TokenCredential
    {
        private int calls;
        internal AccessToken? Issued { get; private set; }
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new Boundary();
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            budget.Check();
            Require(requestContext.Scopes.Length == 1 && requestContext.Scopes[0] == Audience &&
                Interlocked.Increment(ref calls) == 1);
            // A process-cached challenge cannot select a tenant or claims for
            // the host's explicitly supplied authority.
            var token = await inner.GetTokenAsync(new TokenRequestContext([Audience]), cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            budget.Check();
            Require(Text(token.Token, 16384) && token.ExpiresOn > budget.ObservedAt);
            Issued = token;
            return token;
        }
    }
    private sealed class Budget(TimeProvider time, DateTimeOffset armedAt, long timestamp, TimeSpan timeout)
    {
        private DateTimeOffset lastWall = DateTimeOffset.MinValue;
        private long lastStamp = long.MinValue;
        private bool invalidClock;
        internal DateTimeOffset ObservedAt => lastWall;
        internal TimeSpan Remaining { get; private set; }
        internal CancellationTokenSource? Deadline { get; set; }
        internal void Check()
        {
            Require(!invalidClock);
            DateTimeOffset wall = time.GetUtcNow();
            long stamp = time.GetTimestamp();
            if (wall < armedAt || stamp < timestamp || wall < lastWall || stamp < lastStamp)
            {
                invalidClock = true;
                throw new Boundary();
            }
            TimeSpan monotonic = time.GetElapsedTime(timestamp, stamp), wallElapsed = wall - armedAt;
            Require(monotonic >= TimeSpan.Zero && wallElapsed >= TimeSpan.Zero);
            lastWall = wall;
            lastStamp = stamp;
            Remaining = timeout - (monotonic > wallElapsed ? monotonic : wallElapsed);
            if (Remaining <= TimeSpan.Zero) throw new Boundary(Failure.Deadline);
            Deadline?.CancelAfter(Remaining);
        }
    }
    public override string ToString() => "[VaultNetworkReadCollector]";
}
