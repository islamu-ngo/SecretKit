using System.Security.Cryptography;
using System.Text.Json;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>
/// Native v2 rotation metadata and explicit controls. The host owns transport and token source,
/// including disabling redirects, retries, diagnostics containing coordinates, and cookies.
/// Construction performs no I/O. No polling, runtime refresh or consumer activation is performed.
/// </summary>
public sealed class InfisicalRotationClient
{
    private readonly Uri _origin;
    private readonly HttpClient _transport;
    private readonly InfisicalNativeAuthority _administration;
    private readonly int _maximumResponseBytes;

    public InfisicalRotationClient(Uri trustedOrigin, HttpClient transport,
        SecretAuthority authority, InfisicalNativeAuthority administration,
        int maximumResponseBytes = 1024 * 1024)
    {
        ArgumentNullException.ThrowIfNull(trustedOrigin);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(administration);
        if (!trustedOrigin.IsAbsoluteUri || trustedOrigin.Scheme != Uri.UriSchemeHttps ||
            trustedOrigin.UserInfo.Length != 0 || trustedOrigin.AbsolutePath != "/" ||
            trustedOrigin.Query.Length != 0 || trustedOrigin.Fragment.Length != 0)
        {
            throw new ArgumentException("A fixed trusted HTTPS origin is required.");
        }
        if (maximumResponseBytes is < 1024 or > 16 * 1024 * 1024)
        {
            throw new ArgumentException("Invalid native response budget.");
        }
        _origin = trustedOrigin;
        _transport = transport;
        Authority = authority;
        _administration = administration;
        _maximumResponseBytes = maximumResponseBytes;
    }

    public SecretAuthority Authority { get; }

    public async ValueTask<SecretOutcome<InfisicalNativeList<InfisicalRotationProgress>>> ListAsync(
        SecretReference scope, int maximumItems = 128, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        cancellationToken.ThrowIfCancellationRequested();
        if (maximumItems is < 1 or > 4096 || scope.Address is not InfisicalRotationScope address ||
            !scope.BelongsTo(Authority) || !_administration.Matches(Authority, address))
        {
            return SecretOutcome<InfisicalNativeList<InfisicalRotationProgress>>.Failure(SecretStatus.Invalid);
        }
        var response = await SendAsync(address, null, scope, null, null,
            cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccess)
        {
            return SecretOutcome<InfisicalNativeList<InfisicalRotationProgress>>.Failure(response.Status);
        }
        using JsonDocument document = response.Value;
        if (!ObjectProperty(document.RootElement, "secretRotations", JsonValueKind.Array, out var items))
        {
            return SecretOutcome<InfisicalNativeList<InfisicalRotationProgress>>.Failure(SecretStatus.Unknown);
        }
        var result = new List<InfisicalRotationProgress>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        // This endpoint has no published paging inputs or continuation. Do not invent pagination.
        foreach (JsonElement item in items.EnumerateArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (result.Count == maximumItems)
            {
                break;
            }
            if (!TryProgress(item, address.ProjectId, null, out var progress) ||
                !ids.Add(progress!.Address.RotationId))
            {
                return SecretOutcome<InfisicalNativeList<InfisicalRotationProgress>>.Failure(SecretStatus.Unknown);
            }
            result.Add(progress);
        }
        return SecretOutcome<InfisicalNativeList<InfisicalRotationProgress>>.Success(
            new(result, items.GetArrayLength() <= maximumItems));
    }

    /// <summary>Observes the latest native state once, not an attributable operation completion.</summary>
    public ValueTask<SecretOutcome<InfisicalRotationProgress>> GetAsync(SecretReference target,
        CancellationToken cancellationToken = default) =>
        OperationAsync(target, null, null, InfisicalRotationPrecondition.None, cancellationToken);

    public ValueTask<SecretOutcome<InfisicalRotationProgress>> RotateSecretsAsync(SecretReference target,
        InfisicalRotationReceipt receipt, InfisicalRotationPrecondition precondition = InfisicalRotationPrecondition.None,
        CancellationToken cancellationToken = default) =>
        OperationAsync(target, InfisicalRotationAction.RotateSecrets, receipt, precondition, cancellationToken);

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
        ArgumentNullException.ThrowIfNull(target);
        cancellationToken.ThrowIfCancellationRequested();
        if (target.Address is not InfisicalRotationAddress address || !target.BelongsTo(Authority) ||
            !_administration.Matches(Authority, address) ||
            (action is { } selected && (receipt is null || !receipt.Available(target, selected))))
        {
            return SecretOutcome<InfisicalRotationProgress>.Failure(SecretStatus.Invalid);
        }
        if (!Enum.IsDefined(precondition))
        {
            return SecretOutcome<InfisicalRotationProgress>.Failure(SecretStatus.Invalid);
        }
        if (precondition != InfisicalRotationPrecondition.None)
        {
            return SecretOutcome<InfisicalRotationProgress>.Failure(SecretStatus.Unsupported);
        }
        bool? enabled = action switch
        {
            InfisicalRotationAction.EnableAutomaticRotation => true,
            InfisicalRotationAction.DisableAutomaticRotation => false,
            _ => null
        };
        var outcome = await SendAsync(address, enabled, target, action, receipt, cancellationToken)
            .ConfigureAwait(false);
        if (!outcome.IsSuccess)
        {
            return SecretOutcome<InfisicalRotationProgress>.Failure(outcome.Status);
        }
        using JsonDocument document = outcome.Value;
        if (!ObjectProperty(document.RootElement, "secretRotation", JsonValueKind.Object, out var rotation) ||
            !TryProgress(rotation, address.ProjectId, address, out var progress) ||
            (enabled is not null && progress!.AutoRotationEnabled != enabled))
        {
            return SecretOutcome<InfisicalRotationProgress>.Failure(SecretStatus.Unknown);
        }
        cancellationToken.ThrowIfCancellationRequested();
        receipt?.Observe(progress!, enabled is null ? InfisicalRotationEffect.AcceptedPending :
            InfisicalRotationEffect.AutomaticRotationSettingApplied);
        return SecretOutcome<InfisicalRotationProgress>.Success(progress!);
    }

    private async ValueTask<SecretOutcome<JsonDocument>> SendAsync(InfisicalNativeAddress address,
        bool? enabled, SecretReference target, InfisicalRotationAction? action,
        InfisicalRotationReceipt? receipt, CancellationToken cancellationToken)
    {
        var tokenOutcome = await _administration.Tokens.GetTokenAsync(cancellationToken).ConfigureAwait(false);
        if (!tokenOutcome.IsSuccess)
        {
            return SecretOutcome<JsonDocument>.Failure(tokenOutcome.Status);
        }
        using var token = tokenOutcome.Value;
        if (token.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            return SecretOutcome<JsonDocument>.Failure(SecretStatus.Expired);
        }
        using var controlled = new HttpClient(new RequestBuilderOnlyHandler())
        {
            BaseAddress = _origin,
            Timeout = Timeout.InfiniteTimeSpan
        };
        try
        {
            // Do not let Refit manufacture ApiException objects retaining provider bodies.
            var api = RestService.For<IInfisicalRotationApi>(controlled, new RefitSettings
            {
                ExceptionFactory = _ => ValueTask.FromResult<Exception?>(null)
            });
            string authorization = "Bearer " + token.Material.Reveal();
            cancellationToken.ThrowIfCancellationRequested();
            HttpRequestMessage built;
            if (address is InfisicalRotationScope scope)
            {
                built = await api.ListAsync(scope.ProjectId, authorization, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                var rotation = (InfisicalRotationAddress)address;
                string profile = WireProfile(rotation.Profile);
                built = enabled is { } setting
                    ? await api.SetAutomaticAsync(profile, rotation.RotationId, new(setting), authorization,
                        cancellationToken).ConfigureAwait(false)
                    : action is null
                        ? await api.GetAsync(profile, rotation.RotationId, authorization, cancellationToken).ConfigureAwait(false)
                        : await api.RotateAsync(profile, rotation.RotationId, authorization, cancellationToken).ConfigureAwait(false);
            }
            using var request = built;
            Uri? uri = request.RequestUri;
            if (uri is null)
            {
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
            }
            if (!uri.IsAbsoluteUri)
            {
                uri = new Uri(_origin, uri);
                request.RequestUri = uri;
            }
            if (uri.Scheme != _origin.Scheme || uri.Host != _origin.Host || uri.Port != _origin.Port ||
                uri.UserInfo.Length != 0)
            {
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (action is { } selected && !receipt!.Begin(target, selected))
            {
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Invalid);
            }
            using var response = await _transport.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            if (response.RequestMessage?.RequestUri is { } final && final != uri)
            {
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Unknown);
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
                return SecretOutcome<JsonDocument>.Failure(status);
            }
            if (response.Content.Headers.ContentLength > _maximumResponseBytes)
            {
                return SecretOutcome<JsonDocument>.Failure(SecretStatus.Unknown);
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
                cancellationToken.ThrowIfCancellationRequested();
                if (length > _maximumResponseBytes)
                {
                    return SecretOutcome<JsonDocument>.Failure(SecretStatus.Unknown);
                }
                // Parse owns its backing bytes; disposing the document releases the unexported payload.
                using var input = new MemoryStream(bytes, 0, length, writable: false);
                var document = JsonDocument.Parse(input, new JsonDocumentOptions { MaxDepth = 32 });
                if (!UniqueProperties(document.RootElement))
                {
                    document.Dispose();
                    return SecretOutcome<JsonDocument>.Failure(SecretStatus.Unknown);
                }
                return SecretOutcome<JsonDocument>.Success(document);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException("Native rotation operation canceled.", cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or
            JsonException or FormatException or OperationCanceledException)
        {
            return SecretOutcome<JsonDocument>.Failure(SecretStatus.Unknown);
        }
    }

    // Refit's Task<HttpRequestMessage> seam performs construction only. Fail closed if it
    // attempts to dispatch; only the explicit host transport send above is authorized.
    private sealed class RequestBuilderOnlyHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            throw new HttpRequestException("The native Refit seam may only construct requests.");
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
