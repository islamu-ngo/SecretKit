using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>One explicit bootstrap attempt; no login worker or replay.</summary>
public sealed class InfisicalUniversalAuthentication : IDisposable
{
    private readonly HttpClient _transport;
    private readonly IInfisicalUniversalAuthenticationApi _api;
    private readonly TimeProvider _time;
    private readonly int _responseLimit;
    private readonly Uri _origin;
    private bool _disposed;

    public InfisicalUniversalAuthentication(Uri origin, InfisicalNetworkOptions? network = null,
        TimeProvider? timeProvider = null) : this(origin, network ?? new(), timeProvider, null, true) { }

    /// <summary>The validated supplied transport remains host-owned.</summary>
    public InfisicalUniversalAuthentication(Uri origin, SocketsHttpHandler hostTransport,
        InfisicalNetworkOptions? network = null, TimeProvider? timeProvider = null)
        : this(origin, network ?? new(), timeProvider, Validate(hostTransport), false) { }

    internal InfisicalUniversalAuthentication(Uri origin, HttpMessageHandler handler,
        InfisicalNetworkOptions? network = null, TimeProvider? timeProvider = null)
        : this(origin, network ?? new(), timeProvider, handler, false) { }

    private InfisicalUniversalAuthentication(Uri origin, InfisicalNetworkOptions network,
        TimeProvider? timeProvider, HttpMessageHandler? handler, bool ownsHandler)
    {
        ArgumentNullException.ThrowIfNull(origin);
        bool development = origin.IsAbsoluteUri && origin.IsLoopback && origin.Scheme == "http" &&
            network.AllowLoopbackDevelopmentHttp;
        if (!origin.IsAbsoluteUri || origin.Scheme != "https" && !development ||
            origin.UserInfo.Length != 0 || origin.AbsolutePath != "/" || origin.Query.Length != 0 ||
            origin.Fragment.Length != 0)
            throw new ArgumentException("A trusted HTTPS origin is required.");
        if (network.MaximumResponseBytes is < 1024 or > 16 * 1024 * 1024)
            throw new ArgumentException("Invalid authentication response budget.");
        _origin = origin;
        _responseLimit = network.MaximumResponseBytes;
        _time = timeProvider ?? TimeProvider.System;
        _transport = new HttpClient(handler ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ActivityHeadersPropagator = null,
            Proxy = network.Proxy
        }, disposeHandler: ownsHandler)
        { BaseAddress = origin, Timeout = Timeout.InfiniteTimeSpan };
        _api = RestService.For<IInfisicalUniversalAuthenticationApi>(_transport,
            new RefitSettings { ExceptionFactory = _ => ValueTask.FromResult<Exception?>(null) });
    }

    private static SocketsHttpHandler Validate(SocketsHttpHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        if (handler.AllowAutoRedirect || handler.UseCookies || handler.ActivityHeadersPropagator is not null)
            throw new ArgumentException("Transport must disable redirects, cookies and activity propagation.");
        return handler;
    }

    public InfisicalUniversalLoginReceipt CreateReceipt()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new(this);
    }

    public async ValueTask<SecretOutcome<InfisicalUniversalLogin>> LoginAsync(string clientId,
        SecretMaterial clientSecret, InfisicalUniversalLoginReceipt receipt,
        string? organizationSlug = null, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(clientSecret);
        ArgumentNullException.ThrowIfNull(receipt);
        cancellationToken.ThrowIfCancellationRequested();
        if (!ReferenceEquals(receipt.Owner, this) || receipt.Evidence != DispatchEvidence.NotDispatched)
            return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Invalid);
        if (string.IsNullOrWhiteSpace(clientId) || clientId.Length > 1024 || clientId.Any(char.IsControl) ||
            organizationSlug is not null && (organizationSlug.Length is < 1 or > 64 || organizationSlug.Any(char.IsControl)))
            throw new ArgumentException("Invalid protected login selection.");

        byte[] payload = new byte[64 * 1024];
        byte[] bytes = new byte[_responseLimit + 1];
        char[] characters = clientSecret.ExportCharacters();
        try
        {
            if (characters.Length is < 1 or > 16384 || characters.Any(char.IsControl))
                throw new ArgumentException("Invalid bootstrap credential.");
            using var stream = new MemoryStream(payload, writable: true);
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                writer.WriteString("clientId", clientId);
                writer.WriteString("clientSecret", characters.AsSpan());
                if (organizationSlug is not null) writer.WriteString("organizationSlug", organizationSlug);
                writer.WriteEndObject();
            }
            using var content = new ByteArrayContent(payload, 0, checked((int)stream.Position));
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using HttpRequestMessage request = await _api.Login(content, cancellationToken).ConfigureAwait(false);
            if (request.RequestUri is { IsAbsoluteUri: false } relative)
                request.RequestUri = new Uri(_origin, relative);
            if (request.Method != HttpMethod.Post ||
                request.RequestUri != new Uri(_origin, "/api/v1/auth/universal-auth/login"))
                return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Invalid);
            cancellationToken.ThrowIfCancellationRequested();
            DateTimeOffset sentAt = _time.GetUtcNow();
            if (!receipt.TryBeginDispatch())
                return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Invalid);
            using HttpResponseMessage response = await _transport.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                SecretStatus status = response.StatusCode switch
                {
                    HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => SecretStatus.Denied,
                    HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity => SecretStatus.Invalid,
                    HttpStatusCode.TooManyRequests => SecretStatus.Throttled,
                    _ => SecretStatus.Unknown
                };
                if (status != SecretStatus.Unknown) receipt.Record(DispatchEvidence.Rejected);
                return SecretOutcome<InfisicalUniversalLogin>.Failure(status);
            }
            if (response.Content.Headers.ContentLength > _responseLimit)
                return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Unknown);
            using Stream body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            int length = 0;
            while (length < bytes.Length)
            {
                int count = await body.ReadAsync(bytes.AsMemory(length), cancellationToken).ConfigureAwait(false);
                if (count == 0) break;
                length += count;
            }
            if (length > _responseLimit) return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Unknown);
            using var document = JsonDocument.Parse(bytes.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 8 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                root.EnumerateObject().Any(property => property.Name is not
                    ("accessToken" or "accessTokenMaxTTL" or "expiresIn" or "tokenType")) ||
                root.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != root.EnumerateObject().Count() ||
                !root.TryGetProperty("accessToken", out var token) || token.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("tokenType", out var type) || type.GetString() != "Bearer" ||
                !root.TryGetProperty("expiresIn", out var expires) || !expires.TryGetDouble(out double seconds) ||
                !double.IsFinite(seconds) || seconds <= 0 || seconds > 3153600000 ||
                !root.TryGetProperty("accessTokenMaxTTL", out var maximum) || !maximum.TryGetDouble(out double max) ||
                !double.IsFinite(max) || max < 0)
                return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Unknown);
            string text = token.GetString()!;
            if (text.Length is < 1 or > 16384 || text.Any(c => c <= ' ' || c >= 127))
                return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Unknown);
            DateTimeOffset expiresAt = sentAt.AddSeconds(seconds);
            var result = new InfisicalUniversalLogin(new(SecretMaterial.FromText(text), expiresAt),
                seconds, max, _origin, sentAt, _time);
            receipt.Record(DispatchEvidence.Applied);
            if (cancellationToken.IsCancellationRequested)
            {
                result.Dispose();
                cancellationToken.ThrowIfCancellationRequested();
            }
            return SecretOutcome<InfisicalUniversalLogin>.Success(result);
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException("Universal login canceled.", cancellationToken);
        }
        catch (Exception error) when (error is HttpRequestException or IOException or JsonException or
            InvalidOperationException or ArgumentOutOfRangeException)
        {
            return SecretOutcome<InfisicalUniversalLogin>.Failure(SecretStatus.Unknown);
        }
        catch (NotSupportedException) { throw new ArgumentException("Login input exceeds its byte budget."); }
        finally
        {
            Array.Clear(characters);
            Array.Clear(payload);
            Array.Clear(bytes);
        }
    }

    public void Dispose()
    {
        _disposed = true;
        _transport.Dispose();
    }
    public override string ToString() => "[InfisicalUniversalAuthentication]";
}

/// <summary>Caller-held local evidence, not an idempotency key.</summary>
public sealed class InfisicalUniversalLoginReceipt
{
    internal InfisicalUniversalLoginReceipt(object owner) => Owner = owner;
    internal object Owner { get; }
    private int _evidence;
    public DispatchEvidence Evidence => (DispatchEvidence)Volatile.Read(ref _evidence);
    internal bool TryBeginDispatch() => Interlocked.CompareExchange(ref _evidence,
        (int)DispatchEvidence.PossiblyDispatched, (int)DispatchEvidence.NotDispatched) == (int)DispatchEvidence.NotDispatched;
    internal void Record(DispatchEvidence evidence) => Volatile.Write(ref _evidence, (int)evidence);
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
        ExpiresIn = expiresIn;
        AccessTokenMaxTTL = maximum;
        Origin = origin;
        RequestStartedAt = requestStartedAt;
        TimeProvider = timeProvider;
    }
    internal Uri Origin { get; }
    internal TimeProvider TimeProvider { get; }
    [JsonIgnore] public InfisicalAccessToken Token { get; }
    public double ExpiresIn { get; }
    public double AccessTokenMaxTTL { get; }
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
            verifiedEvidence.ReportedMaximumTtl.TotalSeconds != AccessTokenMaxTTL)
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

    public void Dispose() => Token.Dispose();
    public override string ToString() => "[InfisicalUniversalLogin]";
}
