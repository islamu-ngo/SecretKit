using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>
/// Native v4 reads through one immutable origin and host-selected identity.
/// Owns its default transport; supplied token sources and transports remain host-owned.
/// </summary>
public sealed partial class InfisicalClient : ISecretReader, ISecretInventory, IAsyncDisposable
{
    private readonly Uri _origin;
    private readonly IInfisicalTokenSource _tokens;
    private readonly HttpClient _http;
    private readonly IInfisicalStaticWire _staticWire;
    private readonly TimeProvider _time;
    private readonly int _responseLimit;
    private readonly TimeSpan _shutdownTimeout;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly object _gate = new();
    private int _active;
    private bool _disposed;
    private TaskCompletionSource? _drained;
    private Task? _disposeTask;

    public InfisicalClient(Uri origin, IInfisicalTokenSource tokens,
        InfisicalNetworkOptions? network = null, TimeProvider? timeProvider = null)
        : this(origin, tokens, network ?? new InfisicalNetworkOptions(), timeProvider, null, true)
    {
    }

    /// <summary>The validated supplied transport remains host-owned.</summary>
    public InfisicalClient(Uri origin, SocketsHttpHandler hostTransport, IInfisicalTokenSource tokens,
        InfisicalNetworkOptions? network = null, TimeProvider? timeProvider = null)
        : this(origin, tokens, network ?? new(), timeProvider, ValidateReadTransport(hostTransport), false)
    {
    }

    internal InfisicalClient(Uri origin, IInfisicalTokenSource tokens,
        InfisicalNetworkOptions network, TimeProvider? timeProvider, HttpMessageHandler? testHandler)
        : this(origin, tokens, network, timeProvider, testHandler, true)
    {
    }

    private InfisicalClient(Uri origin, IInfisicalTokenSource tokens,
        InfisicalNetworkOptions network, TimeProvider? timeProvider, HttpMessageHandler? testHandler,
        bool ownsHandler)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(tokens);
        ArgumentNullException.ThrowIfNull(network);
        bool developmentHttp = network.AllowLoopbackDevelopmentHttp && origin.IsAbsoluteUri &&
            origin.IsLoopback && origin.Scheme == Uri.UriSchemeHttp;
        if (!origin.IsAbsoluteUri || (origin.Scheme != Uri.UriSchemeHttps && !developmentHttp) ||
            origin.UserInfo.Length != 0 || origin.AbsolutePath != "/" ||
            origin.Query.Length != 0 || origin.Fragment.Length != 0)
        {
            throw new ArgumentException("A trusted HTTPS origin is required.", nameof(origin));
        }

        if (network.MaximumResponseBytes is < 1024 or > 16 * 1024 * 1024 ||
            network.ShutdownTimeout <= TimeSpan.Zero || network.ShutdownTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentException("Invalid response or shutdown budget.", nameof(network));
        }

        _origin = origin;
        _tokens = tokens;
        _responseLimit = network.MaximumResponseBytes;
        _shutdownTimeout = network.ShutdownTimeout;
        _time = timeProvider ?? TimeProvider.System;
        _http = new HttpClient(testHandler ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            Proxy = network.Proxy,
            ActivityHeadersPropagator = null
        }, disposeHandler: ownsHandler)
        { Timeout = Timeout.InfiniteTimeSpan, BaseAddress = _origin };
        _staticWire = RestService.For<IInfisicalStaticWire>(_http);
    }

    private static SocketsHttpHandler ValidateReadTransport(SocketsHttpHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        if (handler.AllowAutoRedirect || handler.UseCookies || handler.ActivityHeadersPropagator is not null ||
            handler.SslOptions.RemoteCertificateValidationCallback is not null ||
            handler.SslOptions.CertificateChainPolicy is
            {
                VerificationFlags: not
                System.Security.Cryptography.X509Certificates.X509VerificationFlags.NoFlag
            })
            throw new ArgumentException("Transport must preserve TLS validation and disable redirects, cookies and activity propagation.");
        return handler;
    }

    public SecretAuthority Authority { get; } = new();

    public async ValueTask<SecretOutcome<SecretRead>> ReadAsync(
        SecretReference reference, CancellationToken cancellationToken = default)
    {
        SecretOutcome<AcquiredRead> outcome = await AcquireReadAsync(reference, false, cancellationToken)
            .ConfigureAwait(false);
        return outcome.IsSuccess
            ? SecretOutcome<SecretRead>.Success(new SecretRead(outcome.Value.Material, outcome.Value.Observation))
            : SecretOutcome<SecretRead>.Failure(outcome.Status, outcome.RetryAfter);
    }

    /// <summary>Qualifies only raw, non-imported reads; resolved material has no resource-only revision.</summary>
    public async ValueTask<SecretOutcome<InfisicalSecretRead>> ReadNativeAsync(
        SecretReference reference, CancellationToken cancellationToken = default)
    {
        SecretOutcome<AcquiredRead> outcome = await AcquireReadAsync(reference, true, cancellationToken)
            .ConfigureAwait(false);
        return outcome.IsSuccess
            ? SecretOutcome<InfisicalSecretRead>.Success(new InfisicalSecretRead(
                outcome.Value.Material, outcome.Value.Observation, outcome.Value.Revision!))
            : SecretOutcome<InfisicalSecretRead>.Failure(outcome.Status, outcome.RetryAfter);
    }

    private sealed record AcquiredRead(SecretMaterial Material, SecretObservation Observation,
        InfisicalSecretRevision? Revision);

    private async ValueTask<SecretOutcome<AcquiredRead>> AcquireReadAsync(
        SecretReference reference, bool qualifyRevision, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reference);
        cancellationToken.ThrowIfCancellationRequested();
        if (!reference.BelongsTo(Authority) || reference.Address is not InfisicalSecretAddress address ||
            qualifyRevision && (address.Resolution != InfisicalResolution.Raw || address.IncludeImports))
        {
            return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Invalid);
        }

        BeginOperation();
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
            using HttpRequestMessage request = await _staticWire.ReadAsync(address.Key, address.ProjectId,
                address.Environment, address.Folder, "true", "shared",
                Boolean(address.Resolution == InfisicalResolution.ExpandedReferences),
                Boolean(address.IncludeImports), address.Version, linked.Token).ConfigureAwait(false);
            SecretOutcome<JsonDocument> outcome = await ReadDocumentAsync(request, linked.Token).ConfigureAwait(false);
            if (!outcome.IsSuccess)
            {
                return SecretOutcome<AcquiredRead>.Failure(outcome.Status, outcome.RetryAfter);
            }

            using JsonDocument document = outcome.Value;
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("secret", out JsonElement secret) ||
                secret.ValueKind != JsonValueKind.Object ||
                !secret.TryGetProperty("secretValue", out JsonElement value) ||
                value.ValueKind != JsonValueKind.String)
            {
                return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Unknown);
            }

            if (!secret.TryGetProperty("secretKey", out JsonElement returnedKey) ||
                returnedKey.ValueKind != JsonValueKind.String)
            {
                return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Unknown);
            }

            if (!string.Equals(returnedKey.GetString(), address.Key, StringComparison.Ordinal))
            {
                return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Invalid);
            }

            if (!secret.TryGetProperty("secretValueHidden", out JsonElement hidden) ||
                hidden.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Unknown);
            }

            if (hidden.GetBoolean())
            {
                return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Denied);
            }

            SecretStatus provenance = ReadScope(secret, address.ProjectId, address.Environment,
                address.Folder, qualifyRevision);
            if (provenance != SecretStatus.Success)
                return SecretOutcome<AcquiredRead>.Failure(provenance);

            linked.Token.ThrowIfCancellationRequested();
            string? observedVersion = Version(secret);
            if (address.Version is { } requestedVersion &&
                observedVersion != requestedVersion.ToString(CultureInfo.InvariantCulture))
            {
                return SecretOutcome<AcquiredRead>.Failure(observedVersion is null
                    ? SecretStatus.Unknown : SecretStatus.Invalid);
            }

            InfisicalSecretRevision? revision = null;
            if (qualifyRevision)
            {
                string? resource = NativeString(secret, "id");
                if (string.IsNullOrWhiteSpace(resource) || resource.Length > 1024 ||
                    resource.Any(char.IsControl) || !secret.TryGetProperty("version", out JsonElement nativeVersion) ||
                    nativeVersion.ValueKind != JsonValueKind.Number ||
                    !nativeVersion.TryGetInt32(out int version) || version <= 0)
                    return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Unknown);
                revision = new(_origin, address.ProjectId, address.Environment, address.Folder, resource, version);
            }

            var observation = new SecretObservation(reference, observedVersion, _time.GetUtcNow(), SecretValidity.Valid);
            return SecretOutcome<AcquiredRead>.Success(new(
                SecretMaterial.FromText(value.GetString()!), observation, revision));
        }
        finally
        {
            EndOperation();
        }
    }

    public async ValueTask<SecretOutcome<SecretInventory>> InspectAsync(
        SecretInventoryScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        cancellationToken.ThrowIfCancellationRequested();
        if (!scope.BelongsTo(Authority) || scope is not InfisicalInventoryScope folder)
        {
            return SecretOutcome<SecretInventory>.Failure(SecretStatus.Invalid);
        }

        BeginOperation();
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
            DateTimeOffset startedAt = _time.GetUtcNow();
            using HttpRequestMessage request = await _staticWire.InspectAsync(folder.ProjectId,
                folder.Environment, folder.Folder, "false", "false", "false", "false", "false",
                linked.Token).ConfigureAwait(false);
            SecretOutcome<JsonDocument> outcome = await ReadDocumentAsync(request, linked.Token).ConfigureAwait(false);
            if (!outcome.IsSuccess)
            {
                return SecretOutcome<SecretInventory>.Failure(outcome.Status, outcome.RetryAfter);
            }

            using JsonDocument document = outcome.Value;
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("secrets", out JsonElement secrets) ||
                secrets.ValueKind != JsonValueKind.Array)
            {
                return SecretOutcome<SecretInventory>.Failure(SecretStatus.Unknown);
            }

            var observations = new List<SecretObservation>();
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonElement secret in secrets.EnumerateArray())
            {
                linked.Token.ThrowIfCancellationRequested();
                if (observations.Count == folder.MaximumItems)
                {
                    break;
                }

                if (secret.ValueKind != JsonValueKind.Object ||
                    !secret.TryGetProperty("secretKey", out JsonElement key) || key.ValueKind != JsonValueKind.String)
                {
                    return SecretOutcome<SecretInventory>.Failure(SecretStatus.Unknown);
                }

                string? name = key.GetString();
                if (string.IsNullOrWhiteSpace(name) || name is "." or "..")
                {
                    return SecretOutcome<SecretInventory>.Failure(SecretStatus.Unknown);
                }

                SecretStatus provenance = ReadScope(secret, folder.ProjectId, folder.Environment, folder.Folder, false);
                if (provenance != SecretStatus.Success || !names.Add(name))
                    return SecretOutcome<SecretInventory>.Failure(
                        provenance == SecretStatus.Success ? SecretStatus.Invalid : provenance);

                var address = new InfisicalSecretAddress(folder.ProjectId, folder.Environment, folder.Folder, name);
                observations.Add(new SecretObservation(new SecretReference(Authority, address), Version(secret),
                    _time.GetUtcNow(), SecretValidity.Unknown));
            }

            return SecretOutcome<SecretInventory>.Success(new SecretInventory(observations, startedAt,
                _time.GetUtcNow(), secrets.GetArrayLength() <= folder.MaximumItems));
        }
        finally
        {
            EndOperation();
        }
    }

    private async ValueTask<SecretOutcome<JsonDocument>> ReadDocumentAsync(HttpRequestMessage request,
        CancellationToken cancellationToken, MutationReceipt? receipt = null, SecretReference? target = null,
        IInfisicalTokenSource? nativeTokens = null)
    {
        SecretOutcome<InfisicalAccessToken> token;
        try
        {
            token = await (nativeTokens ?? _tokens).GetTokenAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (HttpRequestException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<JsonDocument>.Failure(SecretStatus.Unavailable);
        }
        catch (IOException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<JsonDocument>.Failure(SecretStatus.Unavailable);
        }
        if (!token.IsSuccess)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<JsonDocument>.Failure(token.Status, token.RetryAfter);
        }

        using InfisicalAccessToken access = token.Value;
        cancellationToken.ThrowIfCancellationRequested();
        if (access.ExpiresAt <= _time.GetUtcNow())
        {
            return SecretOutcome<JsonDocument>.Failure(SecretStatus.Expired);
        }

        string bearer = access.Material.Reveal();
        if (bearer.Length == 0 || !bearer.All(character => char.IsAsciiLetterOrDigit(character) ||
            character is '-' or '_' or '.' or '~' or '+' or '/' or '='))
        {
            return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
        }

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            receipt?.BeginDispatch(target!);
            using HttpResponseMessage response = await _http.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                TimeSpan? retryAfter = null;
                if (response.StatusCode == HttpStatusCode.TooManyRequests)
                {
                    retryAfter = response.Headers.RetryAfter?.Delta;
                    if (retryAfter is null && response.Headers.RetryAfter?.Date is { } date)
                    {
                        DateTimeOffset now = _time.GetUtcNow();
                        retryAfter = date > now ? date - now : TimeSpan.Zero;
                    }
                }

                SecretStatus status = Status(response.StatusCode);
                if (receipt is not null)
                {
                    if ((int)response.StatusCode is >= 400 and < 500)
                    {
                        receipt.Record(status == SecretStatus.Conflict ? DispatchEvidence.Conflict : DispatchEvidence.Rejected);
                    }
                    else
                    {
                        status = SecretStatus.Unknown;
                    }
                }

                return SecretOutcome<JsonDocument>.Failure(status, retryAfter);
            }

            if (response.Content.Headers.ContentLength > _responseLimit)
            {
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
            }

            await using Stream body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var collected = new MemoryStream();
            byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
            try
            {
                int count;
                while ((count = await body.ReadAsync(buffer.AsMemory(0, 8192), cancellationToken).ConfigureAwait(false)) > 0)
                {
                    if (collected.Length + count > _responseLimit)
                    {
                        return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
                    }

                    collected.Write(buffer, 0, count);
                }

                cancellationToken.ThrowIfCancellationRequested();
                collected.Position = 0;
                return SecretOutcome<JsonDocument>.Success(await JsonDocument.ParseAsync(collected,
                    new JsonDocumentOptions { MaxDepth = 32, AllowDuplicateProperties = false }, cancellationToken).ConfigureAwait(false));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
                if (collected.TryGetBuffer(out ArraySegment<byte> bytes))
                {
                    bytes.AsSpan().Clear();
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (HttpRequestException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<JsonDocument>.Failure(receipt?.Evidence == DispatchEvidence.PossiblyDispatched
                ? SecretStatus.Unknown : SecretStatus.Unavailable);
        }
        catch (IOException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<JsonDocument>.Failure(receipt?.Evidence == DispatchEvidence.PossiblyDispatched
                ? SecretStatus.Unknown : SecretStatus.Unavailable);
        }
        catch (JsonException)
        {
            return SecretOutcome<JsonDocument>.Failure(receipt?.Evidence == DispatchEvidence.PossiblyDispatched
                ? SecretStatus.Unknown : SecretStatus.Invalid);
        }
    }

    private static SecretStatus Status(HttpStatusCode status) => (int)status switch
    {
        400 or 422 => SecretStatus.Invalid,
        401 or 403 => SecretStatus.Denied,
        404 => SecretStatus.Absent,
        409 => SecretStatus.Conflict,
        429 => SecretStatus.Throttled,
        >= 500 => SecretStatus.Unavailable,
        >= 300 and < 400 => SecretStatus.Invalid,
        _ => SecretStatus.Unknown
    };

    private static string? Version(JsonElement secret) =>
        secret.TryGetProperty("version", out JsonElement version) && version.ValueKind == JsonValueKind.Number &&
            version.TryGetInt32(out int number)
            ? number.ToString(CultureInfo.InvariantCulture) : null;

    private static SecretStatus ReadScope(JsonElement secret, string project, string environment,
        string folder, bool required)
    {
        foreach ((string field, string expected) in new[]
        {
            ("workspace", project), ("environment", environment), ("secretPath", folder), ("type", "shared")
        })
        {
            if (!secret.TryGetProperty(field, out JsonElement value))
            {
                if (required) return SecretStatus.Unknown;
                continue;
            }
            if (value.ValueKind != JsonValueKind.String) return SecretStatus.Unknown;
            if (!string.Equals(value.GetString(), expected, StringComparison.Ordinal)) return SecretStatus.Invalid;
        }
        return SecretStatus.Success;
    }

    private static string Boolean(bool value) => value ? "true" : "false";

    private bool NativeTargetValid(SecretReference target, InfisicalNativeAuthority? authority,
        MutationReceipt? receipt = null) =>
        target.BelongsTo(Authority) && target.Address is InfisicalNativeAddress address &&
        (authority is null || authority.Matches(Authority, address)) &&
        (receipt is null || (authority is not null && receipt.IsFor(target) &&
            receipt.Evidence == DispatchEvidence.NotDispatched));

    private async ValueTask<SecretOutcome<JsonDocument>> NativeDocumentAsync(SecretReference target,
        string path, HttpMethod method, byte[]? payload, InfisicalNativeAuthority? authority,
        MutationReceipt? receipt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!NativeTargetValid(target, authority, receipt) ||
                (method != HttpMethod.Get && (authority is null || receipt is null)) ||
                payload?.Length > _responseLimit)
            {
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
            }
            BeginOperation();
            try
            {
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
                using HttpRequestMessage request = await BuildNativeRequestAsync((InfisicalNativeAddress)target.Address,
                    path, method, payload, linked.Token).ConfigureAwait(false);
                SecretOutcome<JsonDocument> outcome = await ReadDocumentAsync(request, linked.Token,
                    receipt, target, authority?.Tokens).ConfigureAwait(false);
                if (!outcome.IsSuccess && receipt?.Evidence == DispatchEvidence.PossiblyDispatched)
                {
                    return SecretOutcome<JsonDocument>.Failure(SecretStatus.Unknown);
                }
                return outcome;
            }
            finally
            {
                EndOperation();
            }
        }
        finally
        {
            if (payload is not null)
            {
                Array.Clear(payload);
            }
        }
    }

    private static string? NativeString(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out JsonElement value) &&
        value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static string Query(string project, string environment, string folder) =>
        $"?projectId={Uri.EscapeDataString(project)}&environment={Uri.EscapeDataString(environment)}&secretPath={Uri.EscapeDataString(folder)}";

    private void BeginOperation()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _active++;
        }
    }

    private void EndOperation()
    {
        lock (_gate)
        {
            _active--;
            if (_active == 0)
            {
                _drained?.TrySetResult();
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_disposeTask is not null)
            {
                return new ValueTask(_disposeTask);
            }

            _disposed = true;
            _drained = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            if (_active == 0)
            {
                _drained.SetResult();
            }

            _disposeTask = ShutdownAsync(_drained.Task);
            return new ValueTask(_disposeTask);
        }
    }

    private async Task ShutdownAsync(Task drained)
    {
        await _shutdown.CancelAsync().ConfigureAwait(false);
        try
        {
            await drained.WaitAsync(_shutdownTimeout).ConfigureAwait(false);
        }
        finally
        {
            _http.Dispose();
            _shutdown.Dispose();
        }
    }

    public override string ToString() => "[InfisicalClient]";
}
