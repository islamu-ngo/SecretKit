using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>One explicit bootstrap attempt; no login worker or replay.</summary>
public sealed class InfisicalUniversalAuthentication : IDisposable
{
    private readonly HttpClient _transport;
    private readonly InfisicalTransportBinding _binding;
    private readonly IInfisicalUniversalAuthenticationApi _api;
    private readonly TimeProvider _time;
    private readonly int _responseLimit;
    private readonly int _requestLimit;
    private readonly TimeSpan _operationTimeout;
    private readonly Uri _origin;
    private readonly InfisicalAuthTransportLease _lease;

    /// <summary>Creates a fixed-origin bootstrap client without logging in; selected borrowed transports remain host-owned.</summary>
    public InfisicalUniversalAuthentication(Uri origin, InfisicalNetworkOptions? network = null,
        TimeProvider? timeProvider = null) : this(origin, network ?? new(), timeProvider, null, true) { }

    internal InfisicalUniversalAuthentication(Uri origin, HttpMessageHandler handler,
        InfisicalNetworkOptions? network = null, TimeProvider? timeProvider = null)
        : this(origin, network ?? new(), timeProvider, handler, false) { }

    private InfisicalUniversalAuthentication(Uri origin, InfisicalNetworkOptions network,
        TimeProvider? timeProvider, HttpMessageHandler? handler, bool ownsHandler)
    {
        ArgumentNullException.ThrowIfNull(origin);
        InfisicalTransportBinding.ValidateOrigin(origin, network);
        if (network.MaximumResponseBytes is < 1024 or > 16 * 1024 * 1024)
            throw new ArgumentException("Invalid authentication response budget.");
        _origin = origin;
        _responseLimit = network.MaximumResponseBytes;
        _requestLimit = network.MaximumRequestBytes;
        _operationTimeout = network.OperationTimeout;
        _time = timeProvider ?? TimeProvider.System;
        _binding = new(origin, network, handler, ownsHandler);
        _lease = new(_binding);
        _transport = _binding.Client;
        _api = RestService.ForGenerated<IInfisicalUniversalAuthenticationApi>(_binding.Requests,
            new RefitSettings { ExceptionFactory = _ => ValueTask.FromResult<Exception?>(null) });
    }

    /// <summary>Creates single-dispatch evidence bound to this authentication client before login.</summary>
    public InfisicalUniversalLoginReceipt CreateReceipt()
    {
        _lease.ThrowIfDisposed(this);
        return new(this);
    }

    /// <summary>Exchanges explicit borrowed bootstrap material once and returns a caller-owned login on success.</summary>
    /// <remarks>Retain the receipt after cancellation or Unknown; the bootstrap may have been consumed.
    /// Reported TTL is not original issuance proof. No retry, principal fallback or automatic worker is started.</remarks>
    public async ValueTask<SecretOutcome<InfisicalUniversalLogin>> LoginAsync(string clientId,
        SecretMaterial clientSecret, InfisicalUniversalLoginReceipt receipt,
        string? organizationSlug = null, CancellationToken cancellationToken = default)
    {
        _lease.BeginOperation(this, cancellationToken);
        try
        {
            return await InfisicalOperationBudget.RunAsync(_operationTimeout, _time, cancellationToken,
                InfisicalOperation.UniversalLogin, ExecuteAsync, () => receipt?.Evidence ?? DispatchEvidence.NotDispatched).ConfigureAwait(false);
        }
        finally
        {
            _lease.EndOperation();
        }

        async ValueTask<SecretOutcome<InfisicalUniversalLogin>> ExecuteAsync(CancellationToken operationToken)
        {
            ArgumentNullException.ThrowIfNull(clientSecret);
            ArgumentNullException.ThrowIfNull(receipt);
            operationToken.ThrowIfCancellationRequested();
            if (!ReferenceEquals(receipt.Owner, this) || receipt.Evidence != DispatchEvidence.NotDispatched)
                return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Invalid, reason: SecretFailureReason.AuthorityMismatch);
            if (string.IsNullOrWhiteSpace(clientId) || clientId.Length > 1024 ||
                clientId.AsSpan().ContainsAny(InfisicalOperationBudget.ControlCharacters) ||
                organizationSlug is not null && (organizationSlug.Length is < 1 or > 64 ||
                    organizationSlug.AsSpan().ContainsAny(InfisicalOperationBudget.ControlCharacters)))
                throw new ArgumentException("Invalid protected login selection.");

            byte[] payload = InfisicalOperationBudget.SerializeUniversalLogin(clientId, clientSecret, organizationSlug, _requestLimit);
            try
            {
                if (payload.Length == 0)
                    return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Invalid, reason: SecretFailureReason.RequestTooLarge);
                using var content = new ByteArrayContent(payload);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                using HttpRequestMessage request = await _api.Login(content, operationToken).ConfigureAwait(false);
                if (request.RequestUri is { IsAbsoluteUri: false } relative)
                    request.RequestUri = new Uri(_origin, relative);
                if (request.Method != HttpMethod.Post ||
                    request.RequestUri != new Uri(_origin, "/api/v1/auth/universal-auth/login"))
                    return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Invalid);
                operationToken.ThrowIfCancellationRequested();
                DateTimeOffset sentAt = _time.GetUtcNow();
                if (!receipt.TryBeginDispatch())
                    return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Invalid);
                using HttpResponseMessage response = await _transport.SendAsync(request,
                    HttpCompletionOption.ResponseHeadersRead, operationToken).ConfigureAwait(false);
                if (response.StatusCode != HttpStatusCode.OK)
                {
                    SecretStatus status = response.StatusCode switch
                    {
                        HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => SecretStatus.Denied,
                        HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity => SecretStatus.Invalid,
                        HttpStatusCode.TooManyRequests => SecretStatus.Throttled,
                        HttpStatusCode.ServiceUnavailable => SecretStatus.Unavailable,
                        _ => SecretStatus.Unknown
                    };
                    if ((int)response.StatusCode is >= 400 and < 500 && status != SecretStatus.Unknown)
                        receipt.Record(DispatchEvidence.Rejected);
                    return await InfisicalFailureResponse.ReadAsync<InfisicalUniversalLogin>(response,
                        _responseLimit, _time, status, resource: false, cancellationToken: operationToken).ConfigureAwait(false);
                }
                using var document = await InfisicalOperationBudget.ReadJsonAsync(
                    response, _responseLimit, 8, allowDuplicateProperties: false, cancellationToken: operationToken).ConfigureAwait(false);
                if (document is null)
                    return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.ResponseTooLarge);
                JsonElement root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object ||
                    !root.TryGetProperty("accessToken", out var token) || token.ValueKind != JsonValueKind.String ||
                    !root.TryGetProperty("tokenType", out var type) || type.ValueKind != JsonValueKind.String || type.GetString() != "Bearer" ||
                    !root.TryGetProperty("expiresIn", out var expires) || expires.ValueKind != JsonValueKind.Number || !expires.TryGetDouble(out double seconds) ||
                    !double.IsFinite(seconds) || seconds < 0.0000001 || seconds > 315360000 ||
                    !root.TryGetProperty("accessTokenMaxTTL", out var maximum) || maximum.ValueKind != JsonValueKind.Number || !maximum.TryGetDouble(out double max) ||
                    !double.IsFinite(max) || max < 0 || max > 315360000)
                    return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
                string text = token.GetString()!;
                if (text.Length is < 1 or > 16384 ||
                    text.AsSpan().ContainsAnyExcept(InfisicalOperationBudget.VisibleAsciiCharacters))
                    return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
                DateTimeOffset expiresAt = sentAt.AddSeconds(seconds);
                var result = new InfisicalUniversalLogin(new(SecretMaterial.FromText(text), expiresAt),
                    seconds, max, _origin, sentAt, _time);
                receipt.Record(DispatchEvidence.Applied);
                if (operationToken.IsCancellationRequested)
                {
                    result.Dispose();
                    operationToken.ThrowIfCancellationRequested();
                }
                return SecretOutcome<InfisicalUniversalLogin>.Success(result);
            }
            catch (OperationCanceledException)
            {
                throw new OperationCanceledException("Universal login canceled.", operationToken);
            }
            catch (Exception error) when (error is HttpRequestException or IOException or JsonException or
                InvalidOperationException or ArgumentOutOfRangeException)
            {
                return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Unknown, reason: error is HttpRequestException or IOException
                    ? SecretFailureReason.TransportFailure : SecretFailureReason.InvalidResponse);
            }
            catch (NotSupportedException)
            {
                return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Invalid, reason: SecretFailureReason.RequestTooLarge);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
            }
        }
    }

    /// <summary>Disposes owned transport resources without revoking issued tokens or disposing borrowed pipelines.</summary>
    public void Dispose() => _lease.Dispose();
    /// <summary>Returns a fixed label without origin or credential details.</summary>
    public override string ToString() => "[InfisicalUniversalAuthentication]";
}

/// <summary>Caller-held local evidence, not an idempotency key.</summary>
public sealed class InfisicalUniversalLoginReceipt
{
    internal InfisicalUniversalLoginReceipt(object owner) => Owner = owner;
    internal object Owner { get; }
    private int _evidence;
    /// <summary>Latest local dispatch evidence; PossiblyDispatched preserves uncertainty across failure.</summary>
    public DispatchEvidence Evidence => (DispatchEvidence)Volatile.Read(ref _evidence);
    internal bool TryBeginDispatch() => Interlocked.CompareExchange(ref _evidence,
        (int)DispatchEvidence.PossiblyDispatched, (int)DispatchEvidence.NotDispatched) == (int)DispatchEvidence.NotDispatched;
    internal void Record(DispatchEvidence evidence) => Volatile.Write(ref _evidence, (int)evidence);
    /// <summary>Returns dispatch evidence without bootstrap or token material.</summary>
    public override string ToString() => $"[InfisicalUniversalLoginReceipt:{Evidence}]";
}

internal interface IInfisicalUniversalAuthenticationApi
{
    [Post("/api/v1/auth/universal-auth/login")]
    Task<HttpRequestMessage> Login([Body] HttpContent content, CancellationToken cancellationToken);
}

/// <summary>Reported expiry only, never an inferred original finite ceiling.</summary>
public sealed class InfisicalUniversalLogin : IDisposable
{
    internal InfisicalUniversalLogin(InfisicalAccessToken token, double expiresIn, double maximum,
        Uri origin, DateTimeOffset requestStartedAt, TimeProvider timeProvider)
    {
        Token = token;
        ExpiresIn = TimeSpan.FromSeconds(expiresIn);
        AccessTokenMaxTtl = TimeSpan.FromSeconds(maximum);
        Origin = origin;
        RequestStartedAt = requestStartedAt;
        TimeProvider = timeProvider;
    }
    internal Uri Origin { get; }
    internal TimeProvider TimeProvider { get; }
    /// <summary>The token owned by this login; copy its material before independent retention.</summary>
    [JsonIgnore] public InfisicalAccessToken Token { get; }
    /// <summary>Provider-reported interval to expiry, conservatively measured from request start locally.</summary>
    public TimeSpan ExpiresIn { get; }
    /// <summary>Provider-reported maximum TTL; zero alone does not establish periodic semantics.</summary>
    public TimeSpan AccessTokenMaxTtl { get; }
    /// <summary>A conservative caller-observed bound, not proof of server issuance time.</summary>
    public DateTimeOffset RequestStartedAt { get; }

    /// <summary>
    /// Binds the host's independently verified token/deployment policy to this exact login.
    /// Preserves reported expiry and original timing; does not verify the policy itself.
    /// </summary>
    public InfisicalTokenLifetimeEvidence BindLifetimeEvidence(InfisicalTokenLifetimeEvidence verifiedEvidence)
    {
        ArgumentNullException.ThrowIfNull(verifiedEvidence);
        if (verifiedEvidence.Login is not null && !ReferenceEquals(verifiedEvidence.Login, this) ||
            verifiedEvidence.ExpiresAt != Token.ExpiresAt ||
            verifiedEvidence.OriginalIssuedAt > RequestStartedAt ||
            verifiedEvidence.ReportedMaximumTtl != AccessTokenMaxTtl)
            throw new ArgumentException("Lifetime evidence does not match this login.", nameof(verifiedEvidence));
        return new InfisicalTokenLifetimeEvidence
        {
            Login = this,
            OriginalIssuedAt = verifiedEvidence.OriginalIssuedAt,
            ExpiresAt = verifiedEvidence.ExpiresAt,
            Lifetime = verifiedEvidence.Lifetime,
            ReportedMaximumTtl = verifiedEvidence.ReportedMaximumTtl,
            Period = verifiedEvidence.Period,
            AbsoluteLifetimeLimit = verifiedEvidence.AbsoluteLifetimeLimit
        };
    }

    /// <summary>Disposes this login's token without stopping independent sessions or revoking the remote token.</summary>
    public void Dispose() => Token.Dispose();
    /// <summary>Returns a fixed label without token or deployment details.</summary>
    public override string ToString() => "[InfisicalUniversalLogin]";
}
