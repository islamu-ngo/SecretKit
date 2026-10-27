using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault;

/// <summary>
/// Selected Key Vault reads and native writes. Credentials and injected transports stay host-owned.
/// Azure diagnostics and automatic retries are disabled; host instrumentation is independent.
/// </summary>
public sealed partial class AzureKeyVaultClient : ISecretReader, ISecretInventory
{
    private const string ApiRevision = "2025-07-01";
    private static readonly HttpPipelineTransport DefaultTransport =
        new HttpClientTransport(new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }));
    private readonly SecretClient _client;
    private readonly TimeProvider _time;
    private readonly Uri _vault;
    private readonly TokenCredential _credential;
    private readonly HttpPipelineTransport _transport;
    private readonly int _maximumResponseBytes;
    private static readonly ConditionalWeakTable<MutationReceipt, SecretReference> UsedReceipts = new();

    /// <summary>
    /// Accepts HTTPS vault origins in public, US government, or China Azure clouds.
    /// Private endpoints retain their normal vault DNS name and TLS validation.
    /// </summary>
    public AzureKeyVaultClient(Uri vaultUri, TokenCredential credential,
        HttpPipelineTransport? transport = null, TimeProvider? timeProvider = null,
        int maximumResponseBytes = 1024 * 1024)
    {
        ArgumentNullException.ThrowIfNull(vaultUri);
        ArgumentNullException.ThrowIfNull(credential);
        if (maximumResponseBytes is < 1024 or > 16 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumResponseBytes));
        }

        if (!vaultUri.IsAbsoluteUri || vaultUri.Scheme != Uri.UriSchemeHttps ||
            !vaultUri.IsDefaultPort || vaultUri.UserInfo.Length != 0 ||
            vaultUri.AbsolutePath != "/" || vaultUri.Query.Length != 0 || vaultUri.Fragment.Length != 0 ||
            !IsTrustedVault(vaultUri.Host))
        {
            throw new ArgumentException("A trusted HTTPS vault origin is required.", nameof(vaultUri));
        }

        _vault = vaultUri;
        _time = timeProvider ?? TimeProvider.System;
        _credential = credential;
        _transport = transport ?? DefaultTransport;
        _maximumResponseBytes = maximumResponseBytes;
        _client = CreateClient();
    }

    private SecretClient CreateClient(MutationReceipt? receipt = null, SecretReference? target = null,
        string? nativePath = null, RequestMethod? nativeMethod = null, bool clearTags = false)
    {
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01)
        {
            DisableChallengeResourceVerification = false,
            Transport = new OriginTransport(_vault, _transport, _maximumResponseBytes, receipt, target,
                nativePath, nativeMethod)
        };
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        options.Retry.MaxRetries = 0;
        if (clearTags)
        {
            options.AddPolicy(new EmptyTagsPolicy(), HttpPipelinePosition.PerCall);
        }
        return new SecretClient(_vault, _credential, options);
    }

    // The SDK omits an empty Tags dictionary. This selected update policy emits
    // the explicit empty object required to clear tags, without touching values.
    private sealed class EmptyTagsPolicy : HttpPipelineSynchronousPolicy
    {
        public override void OnSendingRequest(HttpMessage message)
        {
            using var source = new MemoryStream();
            message.Request.Content!.WriteTo(source, message.CancellationToken);
            source.Position = 0;
            using var document = JsonDocument.Parse(source);
            using var output = new MemoryStream();
            using (var writer = new Utf8JsonWriter(output))
            {
                writer.WriteStartObject();
                foreach (var property in document.RootElement.EnumerateObject())
                {
                    if (property.Name != "tags")
                        property.WriteTo(writer);
                }
                writer.WriteStartObject("tags");
                writer.WriteEndObject();
                writer.WriteEndObject();
            }
            message.Request.Content.Dispose();
            message.Request.Content = RequestContent.Create(output.ToArray());
        }
    }

    public SecretAuthority Authority { get; } = new();

    /// <summary>
    /// Creates a new native version. A receipt is single-use even when validation or cancellation
    /// prevents dispatch. Lost responses are never retried or reconciled as uniquely this caller's.
    /// The official SDK necessarily creates plaintext strings for its wire payload.
    /// </summary>
    public async ValueTask<SecretOutcome<AzureSetSecretResult>> SetSecretAsync(
        AzureSetSecretRequest request, MutationReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(receipt);
        if (!request.Target.BelongsTo(Authority) ||
            request.Target.Address is not AzureSecretAddress address || !receipt.IsFor(request.Target) ||
            receipt.Evidence != DispatchEvidence.NotDispatched)
        {
            return SecretOutcome<AzureSetSecretResult>.Failure(SecretStatus.Invalid);
        }

        lock (UsedReceipts)
        {
            if (UsedReceipts.TryGetValue(receipt, out _))
            {
                return SecretOutcome<AzureSetSecretResult>.Failure(SecretStatus.Invalid);
            }

            UsedReceipts.Add(receipt, request.Target);
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (!Enum.IsDefined(request.Precondition))
        {
            return SecretOutcome<AzureSetSecretResult>.Failure(SecretStatus.Invalid);
        }

        if (address.Version is not null || request.Precondition != AzureSetSecretPrecondition.None)
        {
            return SecretOutcome<AzureSetSecretResult>.Failure(SecretStatus.Unsupported);
        }

        try
        {
            string value = request.Material.Reveal();
            if (new UTF8Encoding(false, true).GetByteCount(value) > 25 * 1024)
            {
                return SecretOutcome<AzureSetSecretResult>.Failure(SecretStatus.Invalid);
            }

            var response = await CreateClient(receipt, request.Target)
                .SetSecretAsync(address.Name, value, cancellationToken).ConfigureAwait(false);
            SecretProperties properties = response.Value.Properties;
            if (properties.Id is null || !SameOrigin(_vault, properties.Id) ||
                !string.Equals(properties.Name, address.Name, StringComparison.OrdinalIgnoreCase) ||
                properties.Version is not { Length: 32 } version || !version.All(char.IsAsciiHexDigit) ||
                properties.Id.AbsolutePath != $"/secrets/{properties.Name}/{version}" ||
                properties.Id.Query.Length != 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return SecretOutcome<AzureSetSecretResult>.Failure(SecretStatus.Unknown);
            }

            var result = new AzureSetSecretResult(
                new SecretReference(Authority, new AzureSecretAddress(properties.Name, version)));
            receipt.Record(DispatchEvidence.Applied);
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<AzureSetSecretResult>.Success(result);
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<AzureSetSecretResult>.Failure(
                receipt.Evidence == DispatchEvidence.PossiblyDispatched ? SecretStatus.Unknown :
                exception is ObjectDisposedException or EncoderFallbackException ? SecretStatus.Invalid :
                Status(exception));
        }
    }

    public async ValueTask<SecretOutcome<SecretRead>> ReadAsync(
        SecretReference reference, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reference);
        cancellationToken.ThrowIfCancellationRequested();
        if (!reference.BelongsTo(Authority) || reference.Address is not AzureSecretAddress address)
        {
            return SecretOutcome<SecretRead>.Failure(SecretStatus.Invalid);
        }

        try
        {
            var response = await _client.GetSecretAsync(address.Name, address.Version, cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            SecretProperties properties = response.Value.Properties;
            if (properties.Id is null || !SameOrigin(_vault, properties.Id) ||
                !string.Equals(properties.Name, address.Name, StringComparison.OrdinalIgnoreCase) ||
                (address.Version is not null &&
                    (!string.Equals(properties.Version, address.Version, StringComparison.OrdinalIgnoreCase) ||
                        properties.Id.AbsolutePath != $"/secrets/{properties.Name}/{properties.Version}" ||
                        properties.Id.Query.Length != 0)))
            {
                return SecretOutcome<SecretRead>.Failure(SecretStatus.Invalid);
            }

            if (response.Value.Value is null)
            {
                return SecretOutcome<SecretRead>.Failure(SecretStatus.Unknown);
            }

            var observedAt = _time.GetUtcNow();
            var validity = Validity(response.Value.Properties, observedAt);
            if (validity != SecretValidity.Valid)
            {
                return SecretOutcome<SecretRead>.Failure(validity == SecretValidity.Expired
                    ? SecretStatus.Expired : SecretStatus.Invalid);
            }

            var observation = Observe(response.Value.Properties, observedAt, reference);
            return SecretOutcome<SecretRead>.Success(
                new SecretRead(SecretMaterial.FromText(response.Value.Value), observation));
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<SecretRead>.Failure(Status(exception));
        }
    }

    public async ValueTask<SecretOutcome<SecretInventory>> InspectAsync(
        SecretInventoryScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        cancellationToken.ThrowIfCancellationRequested();
        if (!scope.BelongsTo(Authority) || scope is not AzureInventoryScope limits)
        {
            return SecretOutcome<SecretInventory>.Failure(SecretStatus.Invalid);
        }

        var startedAt = _time.GetUtcNow();
        var items = new List<SecretObservation>();
        var pages = 0;
        var complete = false;
        try
        {
            await foreach (var page in _client.GetPropertiesOfSecretsAsync(cancellationToken)
                .AsPages(pageSizeHint: Math.Min(25, limits.MaximumItems)).ConfigureAwait(false))
            {
                cancellationToken.ThrowIfCancellationRequested();
                pages++;
                var remaining = limits.MaximumItems - items.Count;
                foreach (var properties in page.Values)
                {
                    if (properties.Id is null || !SameOrigin(_vault, properties.Id))
                    {
                        return SecretOutcome<SecretInventory>.Failure(SecretStatus.Invalid);
                    }

                    if (items.Count == limits.MaximumItems)
                    {
                        break;
                    }

                    items.Add(Observe(properties, _time.GetUtcNow()));
                }

                complete = page.ContinuationToken is null && page.Values.Count <= remaining;
                if (page.ContinuationToken is null || pages == limits.MaximumPages ||
                    items.Count == limits.MaximumItems)
                {
                    break;
                }

                if (!Uri.TryCreate(page.ContinuationToken, UriKind.Absolute, out var next) ||
                    !SameOrigin(_vault, next) || next.AbsolutePath.TrimEnd('/') != "/secrets" ||
                    !HasSelectedRevision(next))
                {
                    return SecretOutcome<SecretInventory>.Failure(SecretStatus.Invalid);
                }
            }

            return SecretOutcome<SecretInventory>.Success(new SecretInventory(
                items, startedAt, _time.GetUtcNow(), complete));
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<SecretInventory>.Failure(Status(exception));
        }
    }

    private SecretObservation Observe(SecretProperties properties, DateTimeOffset observedAt,
        SecretReference? requestedReference = null) =>
        new(requestedReference ?? new SecretReference(Authority, new AzureSecretAddress(properties.Name, properties.Version)),
            properties.Version, observedAt, Validity(properties, observedAt), properties.ExpiresOn);

    private static SecretValidity Validity(SecretProperties properties, DateTimeOffset now) =>
        properties.Enabled == false ? SecretValidity.Disabled :
        properties.NotBefore > now ? SecretValidity.NotYetValid :
        properties.ExpiresOn <= now ? SecretValidity.Expired :
        properties.Enabled is null ? SecretValidity.Unknown : SecretValidity.Valid;

    private static bool IsTrustedVault(string host) =>
        new[] { ".vault.azure.net", ".vault.usgovcloudapi.net", ".vault.azure.cn" }
            .Any(suffix => host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) &&
                host[..^suffix.Length].Length is >= 3 and <= 24 &&
                host[..^suffix.Length].All(c => char.IsAsciiLetterOrDigit(c) || c == '-'));

    private static bool SameOrigin(Uri vault, Uri request) =>
        request.Scheme == vault.Scheme && request.Host == vault.Host && request.Port == vault.Port &&
        request.UserInfo.Length == 0 && request.Fragment.Length == 0;

    private static bool HasSelectedRevision(Uri request)
    {
        string[] versions = request.Query.TrimStart('?').Split('&')
            .Where(part => part.StartsWith("api-version=", StringComparison.OrdinalIgnoreCase)).ToArray();
        return versions.Length == 1 && versions[0]["api-version=".Length..] == ApiRevision;
    }

    private static SecretStatus Status(Exception exception) => exception switch
    {
        ResponseBudgetExceededException or NativeCoordinateException => SecretStatus.Invalid,
        RequestFailedException { Status: 401 or 403 } => SecretStatus.Denied,
        RequestFailedException { Status: 404 } => SecretStatus.Absent,
        RequestFailedException { Status: 429 } => SecretStatus.Throttled,
        RequestFailedException { Status: 400 } => SecretStatus.Invalid,
        RequestFailedException { Status: 409 } => SecretStatus.Conflict,
        RequestFailedException { Status: >= 500 } => SecretStatus.Unavailable,
        HttpRequestException => SecretStatus.Unavailable,
        _ => SecretStatus.Unknown
    };

    private sealed class OriginTransport(Uri vault, HttpPipelineTransport inner, int maximumResponseBytes,
        MutationReceipt? receipt = null, SecretReference? target = null,
        string? nativePath = null, RequestMethod? nativeMethod = null) : HttpPipelineTransport
    {
        public override Request CreateRequest() => inner.CreateRequest();

        public override void Process(HttpMessage message)
        {
            Check(message);
            message.BufferResponse = false;
            BeginMutation(message);
            inner.Process(message);
            BoundResponse(message);
        }

        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            Check(message);
            message.BufferResponse = false;
            BeginMutation(message);
            await inner.ProcessAsync(message).ConfigureAwait(false);
            BoundResponse(message);
        }

        private void BoundResponse(HttpMessage message)
        {
            if (message.Response.Headers.TryGetValue("Content-Length", out string? length) &&
                long.TryParse(length, System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out long bytes) && bytes > maximumResponseBytes)
            {
                message.Response.Dispose();
                throw new ResponseBudgetExceededException();
            }

            if (message.Response.ContentStream is { } stream)
            {
                message.Response.ContentStream = new BoundedResponseStream(stream, maximumResponseBytes);
            }
        }

        private void Check(HttpMessage message)
        {
            if (!SameOrigin(vault, message.Request.Uri.ToUri()))
            {
                throw new InvalidOperationException("Untrusted request origin.");
            }

            if (target?.Address is AzureSecretAddress address &&
                (message.Request.Uri.ToUri().AbsolutePath.TrimEnd('/') != (nativePath ?? $"/secrets/{address.Name}") ||
                    !HasSelectedRevision(message.Request.Uri.ToUri()) ||
                    message.Request.Method != (nativeMethod ?? RequestMethod.Put)))
            {
                throw new InvalidOperationException("Unexpected mutation request.");
            }
        }

        private void BeginMutation(HttpMessage message)
        {
            message.CancellationToken.ThrowIfCancellationRequested();
            if (receipt is null)
            {
                return;
            }

            if (receipt.Evidence != DispatchEvidence.NotDispatched)
            {
                throw new InvalidOperationException("Mutation replay is not permitted.");
            }

            if (nativePath is not null && message.Request.Content is { } content &&
                (!content.TryComputeLength(out long bytes) || bytes > maximumResponseBytes))
            {
                throw new ResponseBudgetExceededException();
            }

            // Bodyless delete/recover/purge also mutate. Key Vault's unauthenticated challenge
            // cannot apply them; the verified authorized send is their dispatch boundary.
            if (message.Request.Content is not null ||
                (nativePath is not null && message.Request.Headers.Contains("Authorization")))
            {
                receipt.BeginDispatch(target!);
            }
        }
    }

    private sealed class ResponseBudgetExceededException : IOException
    {
        public ResponseBudgetExceededException() : base("Provider response exceeded its configured budget.")
        {
        }
    }

    private sealed class BoundedResponseStream(Stream inner, int maximumBytes) : Stream
    {
        private int _read;

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            int count = inner.Read(buffer[..Math.Min(buffer.Length, maximumBytes - _read + 1)]);
            if (_read + count > maximumBytes)
            {
                throw new ResponseBudgetExceededException();
            }

            _read += count;
            return count;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            int count = await inner.ReadAsync(buffer[..Math.Min(buffer.Length, maximumBytes - _read + 1)],
                cancellationToken).ConfigureAwait(false);
            if (_read + count > maximumBytes)
            {
                throw new ResponseBudgetExceededException();
            }

            _read += count;
            return count;
        }

        public override void Flush() => inner.Flush();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await inner.DisposeAsync().ConfigureAwait(false);
            GC.SuppressFinalize(this);
        }
    }
}
