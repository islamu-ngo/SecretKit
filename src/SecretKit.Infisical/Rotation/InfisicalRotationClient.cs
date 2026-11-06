using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>
/// Native v2 rotation metadata and explicit controls. SDK-safe transport is the default.
/// Borrowed transport and token sources remain host-owned; arbitrary host-controlled pipeline
/// HTTP, TLS, retries and logging policy is not enforced by the SDK.
/// Construction performs no I/O. No polling, runtime refresh or consumer activation is performed.
/// </summary>
public sealed class InfisicalRotationClient : IDisposable, IAsyncDisposable
{
    private readonly Uri _origin;
    private readonly HttpClient _transport;
    private readonly InfisicalTransportBinding _binding;
    private readonly IInfisicalRotationApi _api;
    private readonly InfisicalNativeAuthority _administration;
    private readonly int _maximumResponseBytes;
    private readonly TimeSpan _operationTimeout;
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private readonly CancellationTokenSource _shutdown = new();
    private readonly TimeSpan _shutdownTimeout;
    private TaskCompletionSource? _drained;
    private Task? _disposeTask;
    private int _active;
    private bool _disposed;

    /// <summary>Creates a fixed-origin rotation client bound to explicit local and administrative authority, without I/O.</summary>
    public InfisicalRotationClient(Uri trustedOrigin,
        SecretAuthority authority, InfisicalNativeAuthority administration,
        InfisicalNetworkOptions? network = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(trustedOrigin);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(administration);
        network ??= new();
        InfisicalTransportBinding.ValidateOrigin(trustedOrigin, network);
        if (network.MaximumResponseBytes is < 1024 or > 16 * 1024 * 1024 ||
            network.ShutdownTimeout <= TimeSpan.Zero || network.ShutdownTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentException("Invalid native response budget.");
        }
        _origin = trustedOrigin;
        _binding = new(trustedOrigin, network);
        _transport = _binding.Client;
        _api = RestService.ForGenerated<IInfisicalRotationApi>(_binding.Requests, new RefitSettings
        {
            CaptureMethodArguments = false,
            CaptureRequestContent = false
        });
        Authority = authority;
        _administration = administration;
        _maximumResponseBytes = network.MaximumResponseBytes;
        _operationTimeout = network.OperationTimeout;
        _time = timeProvider ?? TimeProvider.System;
        _shutdownTimeout = network.ShutdownTimeout;
    }

    /// <summary>The exact local authority required by rotation references; not a server permission grant.</summary>
    public SecretAuthority Authority { get; }

    /// <summary>Closes admission immediately and schedules cleanup after accepted operations exit.</summary>
    /// <remarks>Does not block on host callbacks or revoke remote credentials. Borrowed resources remain host-owned.</remarks>
    public void Dispose() => _ = BeginShutdown();

    /// <summary>Closes admission and awaits the original bounded shutdown attempt.</summary>
    /// <remarks>Reserved operations may settle. A timeout ends only this wait; owned cleanup still awaits actual drain.</remarks>
    /// <exception cref="TimeoutException">The configured shutdown bound elapsed before cleanup finished.</exception>
    public ValueTask DisposeAsync() => new(BeginShutdown());

    private Task BeginShutdown()
    {
        TaskCompletionSource completion;
        Task drained;
        lock (_gate)
        {
            if (_disposeTask is not null) return _disposeTask;
            _disposed = true;
            _drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
            if (_active == 0) _drained.SetResult();
            drained = _drained.Task;
            completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
            _disposeTask = completion.Task;
        }
        _ = Task.Run(() => ShutdownAsync(drained, completion));
        return completion.Task;
    }

    private async Task ShutdownAsync(Task drained, TaskCompletionSource completion)
    {
        var cleanup = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        // Cleanup must not depend on successful or cooperative host timer creation.
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
            if (await cleanup.Task.WaitAsync(_shutdownTimeout, _time).ConfigureAwait(false)) completion.TrySetResult();
            else completion.TrySetException(new InvalidOperationException("Rotation client shutdown failed."));
        }
        catch (TimeoutException)
        {
            completion.TrySetException(new TimeoutException("Rotation client shutdown timed out."));
        }
        catch (Exception)
        {
            completion.TrySetException(new InvalidOperationException("Rotation client shutdown failed."));
        }
    }

    /// <summary>Observes bounded native rotation metadata for an explicitly authorized project scope.</summary>
    /// <remarks>Completeness reflects local response coverage; no pagination or operation completion is invented.</remarks>
    public async ValueTask<SecretOutcome<InfisicalNativeList<InfisicalRotationProgress>>> ListAsync(
        SecretReference scope, int maximumItems = 128, CancellationToken cancellationToken = default)
    {
        return await RunAsync(ExecuteAsync, cancellationToken: cancellationToken).ConfigureAwait(false);

        async ValueTask<SecretOutcome<InfisicalNativeList<InfisicalRotationProgress>>> ExecuteAsync(CancellationToken operationToken)
        {
            ArgumentNullException.ThrowIfNull(scope);
            operationToken.ThrowIfCancellationRequested();
            if (maximumItems is < 1 or > 4096 || scope.Address is not InfisicalRotationScope address ||
                !scope.BelongsTo(Authority) || !_administration.Matches(Authority, address))
            {
                return SecretOutcome<InfisicalNativeList<InfisicalRotationProgress>>.Failure(SecretStatus.Invalid);
            }
            var response = await SendAsync(address, null, scope, null, null,
                operationToken).ConfigureAwait(false);
            if (!response.IsSuccess)
            {
                return SecretOutcome<InfisicalNativeList<InfisicalRotationProgress>>.Failure(response.Status, response.RetryAfter, response.Reason);
            }
            using JsonDocument document = response.Value;
            if (!ObjectProperty(document.RootElement, "secretRotations", JsonValueKind.Array, out var items))
            {
                return SecretOutcome<InfisicalNativeList<InfisicalRotationProgress>>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
            }
            var result = new List<InfisicalRotationProgress>();
            var ids = new HashSet<string>(StringComparer.Ordinal);
            // This endpoint has no published paging inputs or continuation. Do not invent pagination.
            foreach (JsonElement item in items.EnumerateArray())
            {
                operationToken.ThrowIfCancellationRequested();
                if (result.Count == maximumItems)
                {
                    break;
                }
                if (!TryProgress(item, address.ProjectId, null, out var progress) ||
                    !ids.Add(progress!.Address.RotationId))
                {
                    return SecretOutcome<InfisicalNativeList<InfisicalRotationProgress>>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
                }
                result.Add(progress);
            }
            return SecretOutcome<InfisicalNativeList<InfisicalRotationProgress>>.Success(
                new(result, items.GetArrayLength() <= maximumItems));
        }
    }

    /// <summary>Observes the latest native state once, not an attributable operation completion.</summary>
    public ValueTask<SecretOutcome<InfisicalRotationProgress>> GetAsync(SecretReference target,
        CancellationToken cancellationToken = default) =>
        OperationAsync(target, null, null, InfisicalRotationPrecondition.None, cancellationToken);

    /// <summary>Triggers one native rotation with retained dispatch evidence; acceptance remains pending, not completion.</summary>
    /// <remarks>Cancellation or response loss preserves uncertainty. No automatic retry, polling or consumer activation occurs.</remarks>
    public ValueTask<SecretOutcome<InfisicalRotationProgress>> RotateSecretsAsync(SecretReference target,
        InfisicalRotationReceipt receipt, InfisicalRotationPrecondition precondition = InfisicalRotationPrecondition.None,
        CancellationToken cancellationToken = default) =>
        OperationAsync(target, InfisicalRotationAction.RotateSecrets, receipt, precondition, cancellationToken);

    /// <summary>Explicitly changes automatic rotation and requires the correlated response to report the requested setting.</summary>
    /// <remarks>Compare-and-swap and idempotency requirements are Unsupported; retain receipts rather than replaying uncertainty.</remarks>
    public ValueTask<SecretOutcome<InfisicalRotationProgress>> SetAutomaticRotationAsync(SecretReference target,
        bool enabled, InfisicalRotationReceipt receipt,
        InfisicalRotationPrecondition precondition = InfisicalRotationPrecondition.None,
        CancellationToken cancellationToken = default) =>
        OperationAsync(target, enabled ? InfisicalRotationAction.EnableAutomaticRotation :
            InfisicalRotationAction.DisableAutomaticRotation, receipt, precondition, cancellationToken);

    private async ValueTask<SecretOutcome<InfisicalRotationProgress>> OperationAsync(SecretReference target,
        InfisicalRotationAction? action, InfisicalRotationReceipt? receipt,
        InfisicalRotationPrecondition precondition, CancellationToken cancellationToken)
    {
        return await RunAsync(ExecuteAsync,
            () => receipt?.Dispatch switch { InfisicalRotationDispatch.ResponseUnknown => DispatchEvidence.PossiblyDispatched, InfisicalRotationDispatch.ResponseObserved => DispatchEvidence.Applied, InfisicalRotationDispatch.Rejected => DispatchEvidence.Rejected, _ => DispatchEvidence.NotDispatched },
            cancellationToken).ConfigureAwait(false);

        async ValueTask<SecretOutcome<InfisicalRotationProgress>> ExecuteAsync(CancellationToken operationToken)
        {
            ArgumentNullException.ThrowIfNull(target);
            operationToken.ThrowIfCancellationRequested();
            if (target.Address is not InfisicalRotationAddress address || !target.BelongsTo(Authority) ||
                !_administration.Matches(Authority, address) ||
                (action is { } selected && (receipt is null || !receipt.Available(target, selected))))
            {
                return SecretOutcome<InfisicalRotationProgress>.Failure(SecretStatus.Invalid, reason: SecretFailureReason.AuthorityMismatch);
            }
            if (!Enum.IsDefined(precondition))
            {
                return SecretOutcome<InfisicalRotationProgress>.Failure(SecretStatus.Invalid);
            }
            if (precondition != InfisicalRotationPrecondition.None)
            {
                return SecretOutcome<InfisicalRotationProgress>.Failure(SecretStatus.Unsupported, reason: SecretFailureReason.UnsupportedContract);
            }
            bool? enabled = action switch
            {
                InfisicalRotationAction.EnableAutomaticRotation => true,
                InfisicalRotationAction.DisableAutomaticRotation => false,
                _ => null
            };
            var outcome = await SendAsync(address, enabled, target, action, receipt, operationToken)
                .ConfigureAwait(false);
            if (!outcome.IsSuccess)
            {
                return SecretOutcome<InfisicalRotationProgress>.Failure(outcome.Status, outcome.RetryAfter, outcome.Reason);
            }
            using JsonDocument document = outcome.Value;
            if (!ObjectProperty(document.RootElement, "secretRotation", JsonValueKind.Object, out var rotation) ||
                !TryProgress(rotation, address.ProjectId, address, out var progress) ||
                (enabled is not null && progress!.AutoRotationEnabled != enabled))
            {
                return SecretOutcome<InfisicalRotationProgress>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
            }
            receipt?.Observe(progress!, enabled is null ? InfisicalRotationEffect.AcceptedPending :
                InfisicalRotationEffect.AutomaticRotationSettingApplied);
            return SecretOutcome<InfisicalRotationProgress>.Success(progress!);
        }
    }

    private async ValueTask<SecretOutcome<T>> RunAsync<T>(
        Func<CancellationToken, ValueTask<SecretOutcome<T>>> execute,
        Func<DispatchEvidence>? evidence = null, CancellationToken cancellationToken = default) where T : notnull
    {
        using var deferred = InfisicalDiagnostics.Defer();
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _active++;
        }
        try
        {
            // Shutdown applies to pre-dispatch admission only. Reserved sends keep their caller/deadline budget.
            return await InfisicalOperationBudget.RunAsync(_operationTimeout, _time, cancellationToken,
                InfisicalOperation.Rotation, execute, evidence).ConfigureAwait(false);
        }
        finally
        {
            lock (_gate)
            {
                if (--_active == 0) _drained?.TrySetResult();
            }
        }
    }

    private ValueTask<SecretOutcome<JsonDocument>> SendAsync(InfisicalNativeAddress address,
        bool? enabled, SecretReference target, InfisicalRotationAction? action,
        InfisicalRotationReceipt? receipt, CancellationToken cancellationToken)
    {
        return SendConstructedAsync(address, BuildAsync, target, action, receipt, cancellationToken);

        Task<HttpRequestMessage> BuildAsync(CancellationToken token)
        {
            if (address is InfisicalRotationScope scope)
                return _api.ListAsync(scope.ProjectId, token);
            var rotation = (InfisicalRotationAddress)address;
            string profile = WireProfile(rotation.Profile);
            return enabled is { } setting
                ? _api.SetAutomaticAsync(profile, rotation.RotationId, new(setting), token)
                : action is null
                    ? _api.GetAsync(profile, rotation.RotationId, token)
                    : _api.RotateAsync(profile, rotation.RotationId, token);
        }
    }

    internal async ValueTask<SecretOutcome<JsonDocument>> SendConstructedAsync(InfisicalNativeAddress address,
        Func<CancellationToken, Task<HttpRequestMessage>> build,
        SecretReference target, InfisicalRotationAction? action,
        InfisicalRotationReceipt? receipt, CancellationToken cancellationToken)
    {
        using var admission = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
        bool reserved = false;
        try
        {
            lock (_gate)
            {
                if (_disposed) return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
            }
            using HttpRequestMessage request = await build(admission.Token).ConfigureAwait(false);
            InfisicalNativeRequestIntent intent;
            const string collection = "/api/v2/secret-rotations";
            if (address is InfisicalRotationScope scope)
            {
                intent = new(HttpMethod.Get, collection,
                    new Dictionary<string, string> { ["projectId"] = scope.ProjectId });
            }
            else
            {
                var rotation = (InfisicalRotationAddress)address;
                string path = collection + "/" + Uri.EscapeDataString(WireProfile(rotation.Profile)) +
                    "/" + Uri.EscapeDataString(rotation.RotationId);
                HttpMethod method = action switch
                {
                    InfisicalRotationAction.RotateSecrets => HttpMethod.Post,
                    InfisicalRotationAction.EnableAutomaticRotation or InfisicalRotationAction.DisableAutomaticRotation => HttpMethod.Patch,
                    _ => HttpMethod.Get
                };
                intent = new(method, action == InfisicalRotationAction.RotateSecrets ? path + "/rotate-secrets" : path);
            }
            if (!intent.TryBind(request, _origin))
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
            cancellationToken.ThrowIfCancellationRequested();
            var tokenOutcome = await _administration.Tokens.GetTokenAsync(admission.Token).ConfigureAwait(false);
            if (!tokenOutcome.IsSuccess)
            {
                cancellationToken.ThrowIfCancellationRequested();
                lock (_gate)
                {
                    if (_disposed) return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
                }
                return SecretOutcome<JsonDocument>.Failure(tokenOutcome.Status, tokenOutcome.RetryAfter, tokenOutcome.Reason);
            }
            using var token = tokenOutcome.Value;
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_disposed) return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
            }
            if (token.ExpiresAt <= _time.GetUtcNow())
            {
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Expired);
            }
            string bearer = token.Material.Reveal();
            if (bearer.Length is < 1 or > 16384 ||
                !bearer.All(character => char.IsAsciiLetterOrDigit(character) ||
                    character is '-' or '_' or '.' or '~' or '+' or '/' or '='))
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_disposed || action is { } selected && !receipt!.Begin(target, selected))
                    return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
                reserved = true;
            }
            using var response = await _transport.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            if (response.RequestMessage?.RequestUri is { } final && final != request.RequestUri)
            {
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
            }
            SecretStatus status = (int)response.StatusCode switch
            {
                200 => SecretStatus.Success,
                400 or 422 => SecretStatus.Invalid,
                401 or 403 => SecretStatus.Denied,
                404 => SecretStatus.Absent,
                409 => SecretStatus.Conflict,
                429 => SecretStatus.Throttled,
                >= 500 => SecretStatus.Unavailable,
                _ => SecretStatus.Unknown
            };
            if (status != SecretStatus.Success)
            {
                if (action is not null && status is SecretStatus.Invalid or SecretStatus.Denied or
                    SecretStatus.Absent or SecretStatus.Conflict)
                {
                    receipt!.Reject();
                }
                if (receipt?.Dispatch == InfisicalRotationDispatch.ResponseUnknown) status = SecretStatus.Unknown;
                return SecretOutcome<JsonDocument>.Failure(status,
                    status is SecretStatus.Throttled or SecretStatus.Unavailable
                        ? InfisicalOperationBudget.RetryAfter(response, _time) : null);
            }
            if (response.Content.Headers.ContentLength > _maximumResponseBytes)
            {
                return SecretOutcome<JsonDocument>.Failure(action is null ? SecretStatus.Invalid : SecretStatus.Unknown,
                    reason: SecretFailureReason.ResponseTooLarge);
            }
            using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            byte[] bytes = new byte[_maximumResponseBytes + 1];
            try
            {
                int length = 0;
                while (length < bytes.Length)
                {
                    int read = await stream.ReadAsync(bytes.AsMemory(length), cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }
                    length += read;
                }
                if (length > _maximumResponseBytes)
                {
                    return SecretOutcome<JsonDocument>.Failure(action is null ? SecretStatus.Invalid : SecretStatus.Unknown,
                        reason: SecretFailureReason.ResponseTooLarge);
                }
                // Parse owns its backing bytes; disposing the document releases the unexported payload.
                using var input = new MemoryStream(bytes, 0, length, writable: false);
                var document = JsonDocument.Parse(input, new JsonDocumentOptions { MaxDepth = 32 });
                if (!UniqueProperties(document.RootElement))
                {
                    document.Dispose();
                    return SecretOutcome<JsonDocument>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
                }
                return SecretOutcome<JsonDocument>.Success(document);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        catch (OperationCanceledException) when (!reserved && !cancellationToken.IsCancellationRequested &&
            _shutdown.IsCancellationRequested)
        {
            return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException("Native rotation operation canceled.", cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or
            JsonException or FormatException or OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!reserved)
            {
                lock (_gate)
                {
                    if (_disposed) return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
                }
            }
            return SecretOutcome<JsonDocument>.Failure(SecretStatus.Unknown, reason: exception is JsonException
                    ? SecretFailureReason.InvalidResponse : SecretFailureReason.TransportFailure);
        }
    }

    private static bool UniqueProperties(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name) || !UniqueProperties(property.Value))
                {
                    return false;
                }
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray())
            {
                if (!UniqueProperties(item))
                {
                    return false;
                }
            }
        }
        return true;
    }

    private static bool TryProgress(JsonElement item, string project,
        InfisicalRotationAddress? expected, out InfisicalRotationProgress? progress)
    {
        progress = null;
        if (!Text(item, "id", out string? id) || !Guid.TryParseExact(id, "D", out _) ||
            !Text(item, "projectId", out string? returnedProject) || returnedProject != project ||
            !Text(item, "type", out string? type) || !TryProfile(type!, out var profile) ||
            !ObjectProperty(item, "environment", JsonValueKind.Object, out var environment) ||
            !Text(environment, "slug", out string? slug) ||
            !ObjectProperty(item, "folder", JsonValueKind.Object, out var folder) ||
            !Text(folder, "path", out string? path) ||
            !Text(item, "rotationStatus", out string? status) ||
            !Date(item, "lastRotationAttemptedAt", false, out var attempted) ||
            !Date(item, "lastRotatedAt", false, out var rotated) ||
            !Date(item, "nextRotationAt", true, out var next) ||
            !OptionalBoolean(item, "isAutoRotationEnabled", out var enabled) ||
            !OptionalBoolean(item, "isLastRotationManual", out var manual))
        {
            return false;
        }
        string? job = null;
        if (item.TryGetProperty("lastRotationJobId", out var jobValue) && jobValue.ValueKind != JsonValueKind.Null &&
            !Text(item, "lastRotationJobId", out job))
        {
            return false;
        }
        if (expected is not null && (id != expected.RotationId || profile != expected.Profile ||
            slug != expected.Environment || path != expected.Folder))
        {
            return false;
        }
        try
        {
            var address = new InfisicalRotationAddress(project, slug!, path!, profile, id!);
            progress = new(address, status!, enabled, manual, attempted!.Value, rotated!.Value, next, job);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool ObjectProperty(JsonElement parent, string name, JsonValueKind kind, out JsonElement value)
    {
        value = default;
        return parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out value) &&
            value.ValueKind == kind;
    }

    private static bool Text(JsonElement parent, string name, out string? text)
    {
        text = null;
        if (!ObjectProperty(parent, name, JsonValueKind.String, out var value))
        {
            return false;
        }
        text = value.GetString();
        return !string.IsNullOrWhiteSpace(text) && text.Length <= 1024 && !text.Any(char.IsControl);
    }

    private static bool OptionalBoolean(JsonElement parent, string name, out bool? value)
    {
        value = null;
        if (!parent.TryGetProperty(name, out var field))
        {
            return true;
        }
        if (field.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            return false;
        }
        value = field.GetBoolean();
        return true;
    }

    private static bool Date(JsonElement parent, string name, bool optional, out DateTimeOffset? value)
    {
        value = null;
        if (!parent.TryGetProperty(name, out var field) || field.ValueKind == JsonValueKind.Null)
        {
            return optional;
        }
        if (field.ValueKind != JsonValueKind.String || !field.TryGetDateTimeOffset(out var date))
        {
            return false;
        }
        value = date;
        return true;
    }

    internal static bool TryProfile(string wire, out InfisicalRotationProfile profile)
    {
        foreach (var candidate in Enum.GetValues<InfisicalRotationProfile>())
        {
            if (WireProfile(candidate) == wire)
            {
                profile = candidate;
                return true;
            }
        }
        profile = default;
        return false;
    }

    internal static string WireProfile(InfisicalRotationProfile profile) => profile switch
    {
        InfisicalRotationProfile.Auth0ClientSecret => "auth0-client-secret",
        InfisicalRotationProfile.AwsIamUserSecret => "aws-iam-user-secret",
        InfisicalRotationProfile.AzureClientSecret => "azure-client-secret",
        InfisicalRotationProfile.CloudflareApiToken => "cloudflare-api-token",
        InfisicalRotationProfile.CloudflareR2AccessKey => "cloudflare-r2-access-key",
        InfisicalRotationProfile.ConvexAccessKey => "convex-access-key",
        InfisicalRotationProfile.DatabricksServicePrincipalSecret => "databricks-service-principal-secret",
        InfisicalRotationProfile.DatadogApiKey => "datadog-api-key",
        InfisicalRotationProfile.DatadogApplicationKeySecret => "datadog-application-key-secret",
        InfisicalRotationProfile.DbtServiceToken => "dbt-service-token",
        InfisicalRotationProfile.FireworksApiKey => "fireworks-api-key",
        InfisicalRotationProfile.GcpServiceAccountKey => "gcp-service-account-key",
        InfisicalRotationProfile.HpIloLocalAccount => "hp-ilo-local-account",
        InfisicalRotationProfile.LdapPassword => "ldap-password",
        InfisicalRotationProfile.LitellmApiKey => "litellm-api-key",
        InfisicalRotationProfile.MongodbCredentials => "mongodb-credentials",
        InfisicalRotationProfile.MssqlCredentials => "mssql-credentials",
        InfisicalRotationProfile.MysqlCredentials => "mysql-credentials",
        InfisicalRotationProfile.OktaClientSecret => "okta-client-secret",
        InfisicalRotationProfile.OpenRouterApiKey => "open-router-api-key",
        InfisicalRotationProfile.OpenaiServiceAccount => "openai-service-account",
        InfisicalRotationProfile.OracledbCredentials => "oracledb-credentials",
        InfisicalRotationProfile.PostgresCredentials => "postgres-credentials",
        InfisicalRotationProfile.RedisCredentials => "redis-credentials",
        InfisicalRotationProfile.SalesforceOauthCredentials => "salesforce-oauth-credentials",
        InfisicalRotationProfile.SnowflakeUserKeyPair => "snowflake-user-key-pair",
        InfisicalRotationProfile.StripeApiKey => "stripe-api-key",
        InfisicalRotationProfile.SupabaseApiKey => "supabase-api-key",
        InfisicalRotationProfile.UnixLinuxLocalAccount => "unix-linux-local-account",
        InfisicalRotationProfile.WindowsLocalAccount => "windows-local-account",
        _ => throw new ArgumentException("Invalid native rotation profile.")
    };
}
