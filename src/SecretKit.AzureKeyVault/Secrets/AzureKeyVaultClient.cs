using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using SecretKit.Core;
using SecretKit.Internal;

namespace SecretKit.AzureKeyVault;

/// <summary>
/// Selected Key Vault reads and native writes. Credentials and injected transports stay host-owned.
/// Azure diagnostics and automatic retries are disabled; host instrumentation is independent.
/// </summary>
public sealed partial class AzureKeyVaultClient : ISecretReader, ISecretInventory
{
    // Local pre-reveal material limit and explicit origin admission, not service discovery.
    private const int MaximumSecretValueBytes = 25 * 1024;
    private static readonly string[] VaultHostSuffixes = [".vault.azure.net", ".vault.usgovcloudapi.net", ".vault.azure.cn"];
    // Matches the Infisical safe transport: no redirects, cookies or trace-header propagation,
    // and bounded connection lifetime so DNS changes are observed by the shared pool.
    private static readonly HttpPipelineTransport DefaultTransport =
        new HttpClientTransport(new HttpClient(SecretKitSocketsHandlerFactory.Create()));
    private readonly SecretClient _client;
    private readonly OriginTransport _originTransport;
    private readonly TimeProvider _time;
    private readonly Uri _vault;
    private readonly AsyncLocal<MutationContext?> _pendingMutation = new();
    private readonly TimeSpan? _operationTimeout;
    private readonly int _maximumResponseBytes;
    private readonly MutationReceiptIssuer _receipts = new();
    private static readonly ConditionalWeakTable<MutationReceipt, SecretReference> UsedReceipts = new();
    private static readonly Lock UsedReceiptsGate = new();

    /// <summary>
    /// Accepts HTTPS vault origins in public, US government, or China Azure clouds.
    /// Private endpoints retain their normal vault DNS name and TLS validation.
    /// </summary>
    /// <param name="vaultUri">A fixed trusted HTTPS vault origin without path, query or user information.</param>
    /// <param name="credential">The explicitly selected host-owned credential; construction does not acquire a token.</param>
    /// <param name="transport">An optional host-owned transport; its own instrumentation and retry policy remain host responsibility.</param>
    /// <param name="timeProvider">The clock used for validity observations, or the system clock.</param>
    /// <param name="maximumResponseBytes">The local response limit, from 1 KiB through 16 MiB.</param>
    /// <param name="operationTimeout">Optional cooperative deadline for one public operation.</param>
    /// <exception cref="ArgumentNullException">The vault URI or credential is null.</exception>
    /// <exception cref="ArgumentException">The vault URI is not an admitted origin.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The response limit is outside its supported range.</exception>
    public AzureKeyVaultClient(Uri vaultUri, TokenCredential credential,
        HttpPipelineTransport? transport = null, TimeProvider? timeProvider = null,
        int maximumResponseBytes = 1024 * 1024, TimeSpan? operationTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(vaultUri);
        ArgumentNullException.ThrowIfNull(credential);
        if (!TransferLimits.IsValidByteBudget(maximumResponseBytes))
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
        if (operationTimeout is { } timeout && !TransferLimits.IsValidTimeout(timeout))
            throw new ArgumentOutOfRangeException(nameof(operationTimeout));
        _operationTimeout = operationTimeout;
        _maximumResponseBytes = maximumResponseBytes;
        _originTransport = new OriginTransport(_vault, transport ?? DefaultTransport, maximumResponseBytes, _receipts);
        var options = new SecretClientOptions
        {
            DisableChallengeResourceVerification = false,
            Transport = _originTransport
        };
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        options.Retry.MaxRetries = 0;
        options.AddPolicy(new CaptureContextPolicy(_pendingMutation), HttpPipelinePosition.PerCall);
        options.AddPolicy(new EmptyTagsPolicy(maximumResponseBytes), HttpPipelinePosition.PerCall);
        _client = new SecretClient(_vault, credential, options);
    }

    private sealed class MutationContext(MutationReceipt receipt, SecretReference target, string path, RequestMethod method, bool clearTags) : IDisposable
    {
        internal MutationReceipt Receipt { get; } = receipt;
        internal SecretReference Target { get; } = target;
        internal string Path { get; } = path;
        internal RequestMethod Method { get; } = method;
        internal bool ClearTags { get; } = clearTags;
        internal int? DefinitiveStatus { get; set; }
        internal byte[]? PatchBuffer { get; set; }

        public void Dispose()
        {
            if (PatchBuffer is not { } buffer) return;
            PatchBuffer = null;
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async Task<T> SendMutationAsync<T>(MutationContext context, Func<Task<T>> send)
    {
        using (context)
        {
            if (_pendingMutation.Value is not null) throw new InvalidOperationException("Nested mutation capture.");
            _pendingMutation.Value = context;
            try { return await send().ConfigureAwait(false); }
            finally { _pendingMutation.Value = null; }
        }
    }

    private static MutationContext? Context(HttpMessage message) =>
        message.TryGetProperty(typeof(MutationContext), out var value) ? (MutationContext?)value : null;

    private sealed class CaptureContextPolicy(AsyncLocal<MutationContext?> pending) : HttpPipelineSynchronousPolicy
    {
        public override void OnSendingRequest(HttpMessage message)
        {
            if (pending.Value is not { } context) return;
            pending.Value = null;
            message.SetProperty(typeof(MutationContext), context);
        }
    }

    // Preserve the SDK's exact patch bytes. Insert one field only on explicit clear and
    // keep the buffer owned by this invocation through both challenge and authenticated send.
    private sealed class EmptyTagsPolicy(int maximum) : HttpPipelineSynchronousPolicy
    {
        public override void OnSendingRequest(HttpMessage message)
        {
            if (Context(message) is not { ClearTags: true } context) return;
            var content = message.Request.Content;
            if (content is null || !content.TryComputeLength(out long size) || size < 2 || size > maximum)
                throw new ResponseBudgetExceededException();
            var buffer = ArrayPool<byte>.Shared.Rent((int)size + 10);
            context.PatchBuffer = buffer;
            using var source = new MemoryStream(buffer, 0, (int)size, true, false);
            content.WriteTo(source, message.CancellationToken);
            if (source.Position != size) throw new ResponseBudgetExceededException();
            var reader = new Utf8JsonReader(buffer.AsSpan(0, (int)size));
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject || !reader.Read())
                throw new JsonException();
            bool empty = reader.TokenType == JsonTokenType.EndObject;
            int insert = (int)reader.TokenStartIndex;
            ReadOnlySpan<byte> field = empty ? "\"tags\":{}"u8 : "\"tags\":{},"u8;
            int length = (int)size + field.Length;
            if (length > maximum) throw new ResponseBudgetExceededException();
            buffer.AsSpan(insert, (int)size - insert).CopyTo(buffer.AsSpan(insert + field.Length));
            field.CopyTo(buffer.AsSpan(insert));
            message.Request.Content = RequestContent.Create(buffer.AsMemory(0, length));
            content.Dispose();
        }
    }

    private sealed class AzureBudget(TimeSpan timeout, TimeProvider time, CancellationToken caller) : OperationBudget(timeout, time, caller)
    {
        // A deadline racing publication must not leak an independently owned read or backup.
        internal void CheckPublication<T>(SecretOutcome<T> result) where T : notnull
        {
            if (!result.IsSuccess) return;
            try { Check(); }
            catch { (result.Value as IDisposable)?.Dispose(); throw; }
        }
    }

    private async ValueTask<SecretOutcome<T>> RunAsync<T>(AzureDiagnosticOperation operation,
        Func<CancellationToken, ValueTask<SecretOutcome<T>>> execute, MutationReceipt? receipt, CancellationToken caller) where T : notnull
    {
        using var observation = new AzureDiagnostics.Observation(operation, _time, caller, receipt);
        using var budget = _operationTimeout is { } timeout ? new AzureBudget(timeout, _time, caller) : null;
        try
        {
            var result = await execute(budget?.Token ?? caller).ConfigureAwait(false);
            budget?.CheckPublication(result);
            return observation.Record(result);
        }
        catch (OperationCanceledException) when (!caller.IsCancellationRequested && budget?.Expired == true)
        {
            observation.Cancel(deadline: true);
            return observation.Record(SecretOutcome<T>.Failure(receipt?.Evidence == DispatchEvidence.PossiblyDispatched
                ? SecretStatus.Unknown : SecretStatus.Unavailable, reason: SecretFailureReason.DeadlineExceeded));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel();
            throw new OperationCanceledException(caller);
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
        return await RunAsync(AzureDiagnosticOperation.SetSecret, token => SetSecretAsyncCore(request, receipt, token),
            receipt, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<SecretOutcome<AzureSetSecretResult>> SetSecretAsyncCore(
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

        lock (UsedReceiptsGate)
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

        MutationContext? context = null;
        try
        {
            // Budget and UTF-16 validity are checked on owned material; rejected values are never revealed.
            if (!WithinValueBudget(request.Material))
            {
                return SecretOutcome<AzureSetSecretResult>.Failure(SecretStatus.Invalid);
            }

            string value = request.Material.Reveal();

            context = new(receipt, request.Target, $"/secrets/{address.Name}", RequestMethod.Put, false);
            var response = await SendMutationAsync(context,
                () => _client.SetSecretAsync(address.Name, value, cancellationToken)).ConfigureAwait(false);
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
            return SecretOutcome<AzureSetSecretResult>.Failure(MutationFailure(receipt, context, exception));
        }
    }

    private static bool WithinValueBudget(SecretMaterial material)
    {
        try
        {
            return material.GetUtf8ByteCount() <= MaximumSecretValueBytes;
        }
        catch (ArgumentException)
        {
            return false;
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
        return await RunAsync(AzureDiagnosticOperation.Read, token => ReadAsyncCore(reference, token),
            null, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<SecretOutcome<SecretRead>> ReadAsyncCore(
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
            ValidateProperties(properties, address, true);

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
        return await RunAsync(AzureDiagnosticOperation.Inventory, token => InspectAsyncCore(scope, token),
            null, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<SecretOutcome<SecretInventory>> InspectAsyncCore(
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
                    ValidateProperties(properties, null, false);

                    if (items.Count < limits.MaximumItems)
                        items.Add(Observe(properties, _time.GetUtcNow()));
                }

                if (page.ContinuationToken is { } continuation &&
                    (!Uri.TryCreate(continuation, UriKind.Absolute, out var next) ||
                    !SameOrigin(_vault, next) || next.AbsolutePath.TrimEnd('/') != "/secrets" ||
                    !_originTransport.MatchesInitialRevision(next)))
                {
                    return SecretOutcome<SecretInventory>.Failure(SecretStatus.Invalid);
                }
                complete = page.ContinuationToken is null && page.Values.Count <= remaining;
                if (page.ContinuationToken is null || pages == limits.MaximumPages ||
                    items.Count == limits.MaximumItems)
                {
                    break;
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

    private static string? RequestRevision(Uri request)
    {
        if (request.Query.Length == 0) return null;
        string? revision = null;
        foreach (string parameter in request.Query[1..].Split('&'))
        {
            int separator = parameter.IndexOf('=');
            string key = separator < 0 ? parameter : parameter[..separator];
            if (!Uri.UnescapeDataString(key).Equals("api-version", StringComparison.OrdinalIgnoreCase)) continue;
            if (revision is not null || separator < 0 || separator == parameter.Length - 1) return null;
            revision = parameter[(separator + 1)..];
        }
        return revision;
    }

    private static SecretStatus Status(Exception exception) => exception switch
    {
        ResponseBudgetExceededException or NativeCoordinateException => SecretStatus.Invalid,
        RequestFailedException { InnerException: ResponseBudgetExceededException or NativeCoordinateException } => SecretStatus.Invalid,
        ArgumentException => SecretStatus.Invalid,
        _ => AzureFailureClassification.Status(exception)
    };

    private static SecretStatus MutationFailure(MutationReceipt receipt, MutationContext? context, Exception exception) =>
        receipt.Evidence == DispatchEvidence.PossiblyDispatched ? SecretStatus.Unknown :
        context?.DefinitiveStatus is { } observed ? AzureFailureClassification.Status(observed) :
        exception is ObjectDisposedException ? SecretStatus.Invalid : Status(exception);

    private sealed class OriginTransport(Uri vault, HttpPipelineTransport inner, int maximumResponseBytes,
        MutationReceiptIssuer issuer) : HttpPipelineTransport
    {
        // One immutable SDK options instance selects one wire revision. No public entry point
        // accepts a starting continuation; every next link must match before MoveNext sends it.
        private string? _initialRevision;

        internal bool MatchesInitialRevision(Uri next) => Volatile.Read(ref _initialRevision) is { } initial &&
            string.Equals(RequestRevision(next), initial, StringComparison.Ordinal);

        public override Request CreateRequest() => inner.CreateRequest();

        public override void Process(HttpMessage message)
        {
            Check(message);
            message.BufferResponse = false;
            BeginMutation(message);
            inner.Process(message);
            ObserveRejection(message);
            BoundResponse(message);
        }

        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            Check(message);
            message.BufferResponse = false;
            BeginMutation(message);
            await inner.ProcessAsync(message).ConfigureAwait(false);
            ObserveRejection(message);
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

            var context = Context(message);
            Uri uri = message.Request.Uri.ToUri();
            string revision = RequestRevision(uri) ?? throw new NativeCoordinateException();
            string? initial = Interlocked.CompareExchange(ref _initialRevision, revision, null);
            if (initial is not null && !string.Equals(initial, revision, StringComparison.Ordinal))
                throw new NativeCoordinateException();
            if (context is null)
            {
                // Backup is a read expressed as a POST. No other unbound write may pass.
                if (message.Request.Method != RequestMethod.Get &&
                    !(message.Request.Method == RequestMethod.Post && uri.AbsolutePath.TrimEnd('/').Split('/') is ["", "secrets", { Length: > 0 }, "backup"]))
                    throw new InvalidOperationException("Missing mutation binding.");
            }
            else if (uri.AbsolutePath.TrimEnd('/') != context.Path || message.Request.Method != context.Method)
                throw new InvalidOperationException("Unexpected mutation request.");
        }

        private void BeginMutation(HttpMessage message)
        {
            message.CancellationToken.ThrowIfCancellationRequested();
            if (Context(message) is not { } context) return;
            if (context.Receipt.Evidence != DispatchEvidence.NotDispatched)
                throw new InvalidOperationException("Mutation replay is not permitted.");
            if (message.Request.Content is { } content &&
                (!content.TryComputeLength(out long bytes) || bytes < 0 || bytes > maximumResponseBytes))
                throw new ResponseBudgetExceededException();
            bool authorized = message.Request.Headers.Contains("Authorization");
            if (!authorized && message.Request.Content is not null)
                throw new InvalidOperationException("Unauthenticated mutation content.");
            if (authorized) issuer.BeginDispatch(context.Receipt, context.Target);
        }

        private void ObserveRejection(HttpMessage message)
        {
            int status = message.Response.Status;
            if (Context(message) is { } context && context.Receipt.Evidence == DispatchEvidence.PossiblyDispatched &&
                AzureFailureClassification.IsDefinitiveMutationRejection(status))
            {
                context.DefinitiveStatus = status;
                issuer.Record(context.Receipt, status == (int)System.Net.HttpStatusCode.Conflict ?
                    DispatchEvidence.Conflict : DispatchEvidence.Rejected);
            }
        }
    }

}
