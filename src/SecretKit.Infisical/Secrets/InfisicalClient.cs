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
public sealed partial class InfisicalClient : IInfisicalSecretReader, IAsyncDisposable
{
    private readonly Uri _origin;
    private readonly IInfisicalTokenSource _tokens;
    private readonly MutationReceiptIssuer _receipts = new();
    private readonly HttpClient _http;
    private readonly InfisicalTransportBinding _binding;
    private readonly IInfisicalStaticWire _staticWire;
    private readonly TimeProvider _time;
    private readonly int _responseLimit;
    private readonly int _requestLimit;
    private readonly TimeSpan _operationTimeout;
    private readonly TimeSpan _shutdownTimeout;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly object _gate = new();
    private int _active;
    private bool _disposed;
    private TaskCompletionSource? _drained;
    private Task? _disposeTask;

    /// <summary>Creates a fixed-origin client without acquiring credentials; token source and borrowed transport remain host-owned.</summary>
    public InfisicalClient(Uri origin, IInfisicalTokenSource tokens,
        InfisicalNetworkOptions? network = null, TimeProvider? timeProvider = null)
        : this(origin, tokens, network ?? new InfisicalNetworkOptions(), timeProvider, null, true)
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
        InfisicalTransportBinding.ValidateOrigin(origin, network);

        if (network.MaximumResponseBytes is < 1024 or > 16 * 1024 * 1024 ||
            network.ShutdownTimeout <= TimeSpan.Zero || network.ShutdownTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentException("Invalid response or shutdown budget.", nameof(network));
        }

        _origin = origin;
        _tokens = tokens;
        _responseLimit = network.MaximumResponseBytes;
        _requestLimit = network.MaximumRequestBytes;
        _operationTimeout = network.OperationTimeout;
        _shutdownTimeout = network.ShutdownTimeout;
        _time = timeProvider ?? TimeProvider.System;
        _binding = new(origin, network, testHandler, ownsHandler);
        _http = _binding.Client;
        _staticWire = RestService.ForGenerated<IInfisicalStaticWire>(_binding.Requests);
    }

    /// <summary>Exact local authority used to bind references; it grants no provider permissions.</summary>
    public SecretAuthority Authority { get; } = new();

    /// <summary>Creates read-only local evidence for a mutation owned by this client; performs no I/O.</summary>
    /// <param name="target">The exact reference retained for the mutation.</param>
    /// <returns>Caller-held evidence that only this client can advance.</returns>
    /// <exception cref="ArgumentException">The target belongs to another client or provider.</exception>
    /// <remarks>This receipt grants no provider permission and is not a remote idempotency key.</remarks>
    public MutationReceipt CreateReceipt(SecretReference target)
    {
        ArgumentNullException.ThrowIfNull(target);
        lock (_gate) ObjectDisposedException.ThrowIf(_disposed, this);
        if (!target.BelongsTo(Authority) || target.Address is not (InfisicalSecretAddress or InfisicalNativeAddress))
            throw new ArgumentException("The mutation target must belong to this client.", nameof(target));
        return _receipts.Create(target);
    }

    /// <summary>Reads caller-owned material using this client's selected identity; dispose a successful read.</summary>
    /// <remarks>Missing required evidence yields Unknown; contradictory coordinates yield Invalid.
    /// Unreturned optional scope is not fabricated. Cancellation propagates; no fallback or replay occurs.</remarks>
    public async ValueTask<SecretOutcome<SecretRead>> ReadAsync(
        SecretReference reference, CancellationToken cancellationToken = default)
    {
        lock (_gate) ObjectDisposedException.ThrowIf(_disposed, this);
        return await InfisicalOperationBudget.RunAsync(_operationTimeout, _time, cancellationToken,
            InfisicalOperation.Read, ExecuteAsync, shutdown: _shutdown.Token).ConfigureAwait(false);

        async ValueTask<SecretOutcome<SecretRead>> ExecuteAsync(CancellationToken operationToken)
        {
            SecretOutcome<AcquiredRead> outcome = await AcquireReadAsync(reference, false, operationToken)
                .ConfigureAwait(false);
            return outcome.IsSuccess
                ? SecretOutcome<SecretRead>.Success(new SecretRead(outcome.Value.Material, outcome.Value.Observation))
                : SecretOutcome<SecretRead>.Failure(outcome.Status, outcome.RetryAfter, outcome.Reason);
        }
    }

    /// <summary>Qualifies only raw, non-imported reads; resolved material has no resource-only revision.</summary>
    /// <remarks>The caller owns the successful read. Missing resource/scope/version evidence yields Unknown;
    /// contradictory returned scope yields Invalid. The revision proves no compare-and-swap capability.</remarks>
    public async ValueTask<SecretOutcome<InfisicalSecretRead>> ReadNativeAsync(
        SecretReference reference, CancellationToken cancellationToken = default)
    {
        lock (_gate) ObjectDisposedException.ThrowIf(_disposed, this);
        return await InfisicalOperationBudget.RunAsync(_operationTimeout, _time, cancellationToken,
            InfisicalOperation.Read, ExecuteAsync, shutdown: _shutdown.Token).ConfigureAwait(false);

        async ValueTask<SecretOutcome<InfisicalSecretRead>> ExecuteAsync(CancellationToken operationToken)
        {
            SecretOutcome<AcquiredRead> outcome = await AcquireReadAsync(reference, true, operationToken)
                .ConfigureAwait(false);
            return outcome.IsSuccess
                ? SecretOutcome<InfisicalSecretRead>.Success(new InfisicalSecretRead(
                    outcome.Value.Material, outcome.Value.Observation, outcome.Value.Revision!))
                : SecretOutcome<InfisicalSecretRead>.Failure(outcome.Status, outcome.RetryAfter, outcome.Reason);
        }
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
            return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Invalid, reason: SecretFailureReason.AuthorityMismatch);
        }

        using var linked = new InfisicalOperationBudget(_operationTimeout, _time, cancellationToken, _shutdown.Token);
        BeginOperation();
        try
        {
            using HttpRequestMessage request = await _staticWire.ReadAsync(address.Key, address.ProjectId,
                address.Environment, address.Folder, "true", "shared",
                Boolean(address.Resolution == InfisicalResolution.ExpandedReferences),
                Boolean(address.IncludeImports), address.Version, linked.Token).ConfigureAwait(false);
            SecretOutcome<JsonDocument> outcome = await ReadDocumentAsync(request, linked).ConfigureAwait(false);
            if (!outcome.IsSuccess)
            {
                return SecretOutcome<AcquiredRead>.Failure(outcome.Status, outcome.RetryAfter, outcome.Reason);
            }

            using JsonDocument document = outcome.Value;
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("secret", out JsonElement secret) ||
                secret.ValueKind != JsonValueKind.Object ||
                !secret.TryGetProperty("secretValue", out JsonElement value) ||
                value.ValueKind != JsonValueKind.String)
            {
                return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
            }

            if (!secret.TryGetProperty("secretKey", out JsonElement returnedKey) ||
                returnedKey.ValueKind != JsonValueKind.String)
            {
                return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
            }

            if (!string.Equals(returnedKey.GetString(), address.Key, StringComparison.Ordinal))
            {
                return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Invalid);
            }

            if (!secret.TryGetProperty("secretValueHidden", out JsonElement hidden) ||
                hidden.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
            }

            if (hidden.GetBoolean())
            {
                return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Denied);
            }

            SecretStatus provenance = ReadScope(secret, address.ProjectId, address.Environment,
                address.Folder, qualifyRevision);
            if (provenance != SecretStatus.Success)
                return SecretOutcome<AcquiredRead>.Failure(provenance);

            linked.Check();
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
                    return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
                revision = new(_origin, address.ProjectId, address.Environment, address.Folder, resource, version);
            }

            var observation = new SecretObservation(reference, observedVersion, _time.GetUtcNow(), SecretValidity.Valid);
            linked.Check();
            return SecretOutcome<AcquiredRead>.Success(new(
                SecretMaterial.FromText(value.GetString()!), observation, revision));
        }
        catch (OperationCanceledException)
        {
            return SecretOutcome<AcquiredRead>.Failure(SecretStatus.Unavailable, reason: linked.CancellationReason());
        }
        finally
        {
            EndOperation();
        }
    }

    /// <summary>Observes bounded direct-folder metadata without acquiring values or recursively resolving imports.</summary>
    /// <remarks>References belong to this exact authority. Completeness is local response coverage, not an atomic snapshot.</remarks>
    public async ValueTask<SecretOutcome<SecretInventory>> InspectAsync(
        SecretInventoryScope scope, CancellationToken cancellationToken = default)
    {
        return await InfisicalOperationBudget.RunAsync(_operationTimeout, _time, cancellationToken,
            InfisicalOperation.Inventory, ExecuteAsync, shutdown: _shutdown.Token).ConfigureAwait(false);

        async ValueTask<SecretOutcome<SecretInventory>> ExecuteAsync(CancellationToken operationToken)
        {
            ArgumentNullException.ThrowIfNull(scope);
            operationToken.ThrowIfCancellationRequested();
            if (!scope.BelongsTo(Authority) || scope is not InfisicalInventoryScope folder)
            {
                return SecretOutcome<SecretInventory>.Failure(SecretStatus.Invalid, reason: SecretFailureReason.AuthorityMismatch);
            }

            using var linked = new InfisicalOperationBudget(_operationTimeout, _time, operationToken, _shutdown.Token);
            BeginOperation();
            try
            {
                DateTimeOffset startedAt = _time.GetUtcNow();
                using HttpRequestMessage request = await _staticWire.InspectAsync(folder.ProjectId,
                    folder.Environment, folder.Folder, "false", "false", "false", "false", "false",
                    linked.Token).ConfigureAwait(false);
                SecretOutcome<JsonDocument> outcome = await ReadDocumentAsync(request, linked).ConfigureAwait(false);
                if (!outcome.IsSuccess)
                {
                    return SecretOutcome<SecretInventory>.Failure(outcome.Status, outcome.RetryAfter, outcome.Reason);
                }

                using JsonDocument document = outcome.Value;
                if (document.RootElement.ValueKind != JsonValueKind.Object ||
                    !document.RootElement.TryGetProperty("secrets", out JsonElement secrets) ||
                    secrets.ValueKind != JsonValueKind.Array)
                {
                    return SecretOutcome<SecretInventory>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
                }

                var observations = new List<SecretObservation>();
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (JsonElement secret in secrets.EnumerateArray())
                {
                    linked.Check();
                    if (observations.Count == folder.MaximumItems)
                    {
                        break;
                    }

                    if (secret.ValueKind != JsonValueKind.Object ||
                        !secret.TryGetProperty("secretKey", out JsonElement key) || key.ValueKind != JsonValueKind.String)
                    {
                        return SecretOutcome<SecretInventory>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
                    }

                    string? name = key.GetString();
                    if (string.IsNullOrWhiteSpace(name) || name is "." or "..")
                    {
                        return SecretOutcome<SecretInventory>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
                    }

                    SecretStatus provenance = ReadScope(secret, folder.ProjectId, folder.Environment, folder.Folder, false);
                    if (provenance != SecretStatus.Success || !names.Add(name))
                        return SecretOutcome<SecretInventory>.Failure(
                            provenance == SecretStatus.Success ? SecretStatus.Invalid : provenance);

                    var address = new InfisicalSecretAddress(folder.ProjectId, folder.Environment, folder.Folder, name);
                    observations.Add(new SecretObservation(new SecretReference(Authority, address), Version(secret),
                        _time.GetUtcNow(), SecretValidity.Unknown));
                }

                linked.Check();
                return SecretOutcome<SecretInventory>.Success(new SecretInventory(observations, startedAt,
                    _time.GetUtcNow(), secrets.GetArrayLength() <= folder.MaximumItems));
            }
            catch (OperationCanceledException)
            {
                return SecretOutcome<SecretInventory>.Failure(SecretStatus.Unavailable, reason: linked.CancellationReason());
            }
            finally
            {
                EndOperation();
            }
        }
    }

    private async ValueTask<SecretOutcome<JsonDocument>> ReadDocumentAsync(HttpRequestMessage request,
        InfisicalOperationBudget budget, MutationReceipt? receipt = null, SecretReference? target = null,
        IInfisicalTokenSource? nativeTokens = null, InfisicalBulkReceipt? bulkReceipt = null)
    {
        CancellationToken cancellationToken = budget.Token;
        try
        {
            _binding.BindRequest(request);
            budget.Check();
            SecretOutcome<InfisicalAccessToken> token = await (nativeTokens ?? _tokens)
                .GetTokenAsync(cancellationToken).ConfigureAwait(false);
            using InfisicalAccessToken? access = token.IsSuccess ? token.Value : null;
            budget.Check();
            if (!token.IsSuccess)
                return SecretOutcome<JsonDocument>.Failure(token.Status, token.RetryAfter,
                    token.Reason == SecretFailureReason.None ? SecretFailureReason.CredentialUnavailable : token.Reason);
            if (access!.ExpiresAt <= _time.GetUtcNow())
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Expired, reason: SecretFailureReason.CredentialUnavailable);
            string bearer = access.Material.Reveal();
            if (bearer.Length is < 1 or > 16384 || !bearer.All(character => char.IsAsciiLetterOrDigit(character) ||
                character is '-' or '_' or '.' or '~' or '+' or '/' or '='))
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid, reason: SecretFailureReason.CredentialUnavailable);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            budget.Check();
            if (bulkReceipt is not null) bulkReceipt.BeginDispatch(_receipts);
            else if (receipt is not null) _receipts.BeginDispatch(receipt, target!);
            using HttpResponseMessage response = await _http.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                SecretStatus status = Status(response.StatusCode);
                if (receipt is not null)
                {
                    if ((int)response.StatusCode is >= 400 and < 500)
                        _receipts.Record(receipt, status == SecretStatus.Conflict ? DispatchEvidence.Conflict : DispatchEvidence.Rejected);
                    else status = SecretStatus.Unknown;
                }
                budget.Check();
                return SecretOutcome<JsonDocument>.Failure(status,
                    status is SecretStatus.Throttled or SecretStatus.Unavailable
                        ? InfisicalOperationBudget.RetryAfter(response, _time) : null);
            }
            if (response.Content.Headers.ContentLength > _responseLimit)
                return DocumentFailure(SecretStatus.Invalid, SecretFailureReason.ResponseTooLarge, receipt);
            await using Stream body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var collected = new MemoryStream();
            byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
            try
            {
                int count;
                while ((count = await body.ReadAsync(buffer.AsMemory(0, 8192), cancellationToken).ConfigureAwait(false)) > 0)
                {
                    if (collected.Length + count > _responseLimit)
                        return DocumentFailure(SecretStatus.Invalid, SecretFailureReason.ResponseTooLarge, receipt);
                    collected.Write(buffer, 0, count);
                }
                // Parse a late acknowledgement to retain any actual effect. The
                // operation owner checks the budget again before publication.
                collected.Position = 0;
                return SecretOutcome<JsonDocument>.Success(JsonDocument.Parse(collected,
                    new JsonDocumentOptions { MaxDepth = 32, AllowDuplicateProperties = bulkReceipt is not null }));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
                if (collected.TryGetBuffer(out ArraySegment<byte> bytes)) bytes.AsSpan().Clear();
            }
        }
        catch (OperationCanceledException)
        {
            return DocumentFailure(SecretStatus.Unavailable, budget.CancellationReason(), receipt);
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
            budget.Check();
            return DocumentFailure(SecretStatus.Unavailable, SecretFailureReason.TransportFailure, receipt);
        }
        catch (JsonException)
        {
            budget.Check();
            return DocumentFailure(SecretStatus.Invalid, SecretFailureReason.InvalidResponse, receipt);
        }
    }

    private static SecretOutcome<JsonDocument> DocumentFailure(SecretStatus status, SecretFailureReason reason,
        MutationReceipt? receipt) => SecretOutcome<JsonDocument>.Failure(
            receipt?.Evidence == DispatchEvidence.PossiblyDispatched ? SecretStatus.Unknown : status, reason: reason);

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
            version.TryGetInt32(out int number) && number > 0
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
        (receipt is null || (authority is not null && _receipts.Owns(receipt) && receipt.IsFor(target) &&
            receipt.Evidence == DispatchEvidence.NotDispatched));

    private async ValueTask<SecretOutcome<JsonDocument>> NativeDocumentAsync(SecretReference target,
        InfisicalNativeOperation operation, Func<int, byte[]>? serialize, InfisicalNativeAuthority? authority,
        MutationReceipt? receipt, CancellationToken cancellationToken, InfisicalBulkReceipt? bulkReceipt = null)
    {
        ArgumentNullException.ThrowIfNull(target);
        using var budget = new InfisicalOperationBudget(_operationTimeout, _time, cancellationToken, _shutdown.Token);
        byte[]? payload = null;
        try
        {
            budget.Check();
            if (!NativeTargetValid(target, authority, receipt) ||
                (operation.Method != HttpMethod.Get && (authority is null || receipt is null)))
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid, reason: SecretFailureReason.AuthorityMismatch);
            payload = serialize?.Invoke(_requestLimit);
            budget.Check();
            if (payload is { Length: 0 })
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid, reason: SecretFailureReason.RequestTooLarge);
            BeginOperation();
            try
            {
                using HttpRequestMessage request = await BuildNativeRequestAsync((InfisicalNativeAddress)target.Address,
                    operation, payload, budget.Token).ConfigureAwait(false);
                return await ReadDocumentAsync(request, budget, receipt, target, authority?.Tokens, bulkReceipt)
                    .ConfigureAwait(false);
            }
            finally { EndOperation(); }
        }
        catch (OperationCanceledException)
        {
            return DocumentFailure(SecretStatus.Unavailable, budget.CancellationReason(), receipt);
        }
        finally { if (payload is not null) Array.Clear(payload); }
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

    /// <summary>Stops admission and shares one bounded shutdown result across callers.</summary>
    /// <remarks>Timeout may leave retained cleanup pending until callbacks and active operations finish.
    /// Borrowed transports and token sources are not disposed; remote effects are not rolled back.</remarks>
    /// <exception cref="TimeoutException">The original shutdown deadline elapsed; eventual cleanup remains owned.</exception>
    public ValueTask DisposeAsync()
    {
        TaskCompletionSource completion;
        Task drained;
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

            drained = _drained.Task;
            completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
            _disposeTask = completion.Task;
        }
        _ = ShutdownAsync(drained, completion);
        return new ValueTask(completion.Task);
    }

    private async Task ShutdownAsync(Task drained, TaskCompletionSource completion)
    {
        var cleanup = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<bool> bounded = cleanup.Task.WaitAsync(_shutdownTimeout, _time);
        _ = Task.Run(async () =>
        {
            bool succeeded = true;
            try
            {
                try { await _shutdown.CancelAsync().ConfigureAwait(false); }
                catch (Exception) { succeeded = false; }
            }
            finally
            {
                try
                {
                    await drained.ConfigureAwait(false);
                    _binding.Dispose();
                }
                catch (Exception) { succeeded = false; }
                finally
                {
                    _shutdown.Dispose();
                    cleanup.TrySetResult(succeeded);
                }
            }
        });
        try
        {
            if (await bounded.ConfigureAwait(false))
                completion.TrySetResult();
            else
                completion.TrySetException(new InvalidOperationException("Client shutdown failed."));
        }
        catch (TimeoutException)
        {
            completion.TrySetException(new TimeoutException("Client shutdown timed out."));
        }
    }

    /// <summary>Returns a fixed label without origin, identity or coordinates.</summary>
    public override string ToString() => "[InfisicalClient]";
}
