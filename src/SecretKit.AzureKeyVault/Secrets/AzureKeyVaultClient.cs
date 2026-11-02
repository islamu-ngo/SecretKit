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
    private static readonly string[] VaultHostSuffixes = [".vault.azure.net", ".vault.usgovcloudapi.net", ".vault.azure.cn"];
    private static readonly HttpPipelineTransport DefaultTransport =
        new HttpClientTransport(new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }));
    private readonly SecretClient _client;
    private readonly TimeProvider _time;
    private readonly Uri _vault;
    private readonly TokenCredential _credential;
    private readonly HttpPipelineTransport _transport;
    private readonly int _maximumResponseBytes;
    private readonly MutationReceiptIssuer _receipts = new();
    private static readonly ConditionalWeakTable<MutationReceipt, SecretReference> UsedReceipts = new();

    /// <summary>
    /// Accepts HTTPS vault origins in public, US government, or China Azure clouds.
    /// Private endpoints retain their normal vault DNS name and TLS validation.
    /// </summary>
    /// <param name="vaultUri">A fixed trusted HTTPS vault origin without path, query or user information.</param>
    /// <param name="credential">The explicitly selected host-owned credential; construction does not acquire a token.</param>
    /// <param name="transport">An optional host-owned transport; its own instrumentation and retry policy remain host responsibility.</param>
    /// <param name="timeProvider">The clock used for validity observations, or the system clock.</param>
    /// <param name="maximumResponseBytes">The local response limit, from 1 KiB through 16 MiB.</param>
    /// <exception cref="ArgumentNullException">The vault URI or credential is null.</exception>
    /// <exception cref="ArgumentException">The vault URI is not an admitted origin.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The response limit is outside its supported range.</exception>
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
            Transport = new OriginTransport(_vault, _transport, _maximumResponseBytes, _receipts, receipt, target,
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

    /// <summary>Gets this client's local reference-binding authority; it grants no remote permissions.</summary>
    public SecretAuthority Authority { get; } = new();

    /// <summary>Issues read-only local evidence for one exact reference owned by this client.</summary>
    /// <param name="target">The secret reference whose mutation evidence the caller will retain.</param>
    /// <returns>Undispatched evidence; issuance performs no I/O and grants no provider authority.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="target"/> is null.</exception>
    /// <exception cref="ArgumentException">The reference does not belong to this client or is not an Azure secret.</exception>
    public MutationReceipt CreateReceipt(SecretReference target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (!target.BelongsTo(Authority) || target.Address is not AzureSecretAddress)
            throw new ArgumentException("The reference is outside this client's authority.", nameof(target));
        return _receipts.Create(target);
    }

    /// <summary>
    /// Creates a new native version. A receipt is single-use even when validation or cancellation
    /// prevents dispatch. Lost responses are never retried or reconciled as uniquely this caller's.
    /// The official SDK necessarily creates plaintext strings for its wire payload.
    /// </summary>
    /// <param name="request">An unversioned target and caller-owned material; only an unconditional write is supported.</param>
    /// <param name="receipt">Unused evidence issued by this client for the exact request target; retain it before awaiting.</param>
    /// <param name="cancellationToken">Cancels local waiting without proving that an already dispatched effect was undone.</param>
    /// <returns>The validated created version, or a bounded failure; a lost response retains uncertainty in the receipt.</returns>
    /// <exception cref="ArgumentNullException">The request or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Cancellation was observed; inspect the retained receipt before recovery.</exception>
    public async ValueTask<SecretOutcome<AzureSetSecretResult>> SetSecretAsync(
        AzureSetSecretRequest request, MutationReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(receipt);
        if (!request.Target.BelongsTo(Authority) ||
            request.Target.Address is not AzureSecretAddress address || !_receipts.Owns(receipt) || !receipt.IsFor(request.Target) ||
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
            _receipts.Record(receipt, DispatchEvidence.Applied);
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

    /// <summary>Reads independently owned material only when the returned secret is currently valid for consumption.</summary>
    /// <param name="reference">This client's current or exact-version secret reference.</param>
    /// <param name="cancellationToken">Cancels acquisition; cancellation is propagated.</param>
    /// <returns>A read the caller must dispose, or a bounded scope, validity or provider failure.</returns>
    /// <exception cref="ArgumentNullException">The reference is null.</exception>
    /// <exception cref="OperationCanceledException">Cancellation was observed.</exception>
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

    /// <summary>Collects bounded current-version metadata without reading values or proving permission to use them.</summary>
    /// <param name="scope">An Azure inventory scope bound to this client's authority.</param>
    /// <param name="cancellationToken">Cancels collection; cancellation is propagated.</param>
    /// <returns>Observations over a collection window, with explicit completeness, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The scope is null.</exception>
    /// <exception cref="OperationCanceledException">Cancellation was observed.</exception>
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
        VaultHostSuffixes
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
        MutationReceiptIssuer issuer,
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
                issuer.BeginDispatch(receipt, target!);
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

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA2215", Justification = "Direct Stream base has no owned resources; its default DisposeAsync calls our synchronous Dispose override and would dispose the inner stream twice instead of preserving its async disposal path.")]
        public override async ValueTask DisposeAsync()
        {
            await inner.DisposeAsync().ConfigureAwait(false);
            GC.SuppressFinalize(this);
        }
    }
}
