using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Closed, copied host proof. Disposal erases this copy, not host credentials.</summary>
public sealed class InfisicalLoginProof : IDisposable
{
    private readonly object _gate = new();
    private byte[]? _payload;
    internal string Strategy { get; }

    private InfisicalLoginProof(string strategy, string identityId, string? organizationSlug,
        Action<Utf8JsonWriter> fields)
    {
        ValidateText(identityId, 1024);
        if (organizationSlug is not null) ValidateText(organizationSlug, 64);
        Strategy = strategy;
        byte[] buffer = new byte[128 * 1024];
        try
        {
            using var stream = new MemoryStream(buffer, writable: true);
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                writer.WriteString("identityId", identityId);
                if (organizationSlug is not null) writer.WriteString("organizationSlug", organizationSlug);
                fields(writer);
                writer.WriteEndObject();
            }
            _payload = buffer.AsSpan(0, checked((int)stream.Position)).ToArray();
        }
        catch (NotSupportedException) { throw new ArgumentException("Proof exceeds its byte budget."); }
        finally { Array.Clear(buffer); }
    }

    /// <summary>Completed signed AliCloud GetCallerIdentity fields; no signing or key acquisition.</summary>
    public static InfisicalLoginProof AliCloud(string identityId, SecretMaterial accessKeyId,
        SecretMaterial signature, SecretMaterial signatureNonce, string timestamp, string version,
        string? organizationSlug = null)
    {
        ValidateText(timestamp, 1024);
        if (!DateTimeOffset.TryParse(timestamp, CultureInfo.InvariantCulture, DateTimeStyles.None, out _) ||
            !timestamp.Contains('T'))
            throw new ArgumentException("Invalid proof timestamp.");
        ValidateText(version, 1024);
        return new("alicloud", identityId, organizationSlug, writer =>
        {
            WriteMaterial(writer, "AccessKeyId", accessKeyId);
            writer.WriteString("Action", "GetCallerIdentity");
            writer.WriteString("Format", "JSON");
            WriteMaterial(writer, "Signature", signature);
            writer.WriteString("SignatureMethod", "HMAC-SHA1");
            WriteMaterial(writer, "SignatureNonce", signatureNonce);
            writer.WriteString("SignatureVersion", "1.0");
            writer.WriteString("Timestamp", timestamp);
            writer.WriteString("Version", version);
        });
    }

    /// <summary>Host-signed STS request body and headers in their native base64 representation.</summary>
    public static InfisicalLoginProof Aws(string identityId, SecretMaterial iamRequestBody,
        SecretMaterial iamRequestHeaders, string? iamHttpRequestMethod = null, string? organizationSlug = null)
    {
        if (iamHttpRequestMethod is not null) ValidateText(iamHttpRequestMethod, 1024);
        return new("aws", identityId, organizationSlug, writer =>
        {
            WriteMaterial(writer, "iamRequestBody", iamRequestBody);
            WriteMaterial(writer, "iamRequestHeaders", iamRequestHeaders);
            if (iamHttpRequestMethod is not null) writer.WriteString("iamHttpRequestMethod", iamHttpRequestMethod);
        });
    }

    public static InfisicalLoginProof Azure(string identityId, SecretMaterial jwt, string? organizationSlug = null) =>
        JwtProof("azure", identityId, jwt, organizationSlug);
    public static InfisicalLoginProof Gcp(string identityId, SecretMaterial jwt, string? organizationSlug = null) =>
        JwtProof("gcp", identityId, jwt, organizationSlug);
    public static InfisicalLoginProof Jwt(string identityId, SecretMaterial jwt, string? organizationSlug = null) =>
        JwtProof("jwt", identityId, jwt, organizationSlug);
    public static InfisicalLoginProof Kubernetes(string identityId, SecretMaterial jwt, string? organizationSlug = null) =>
        JwtProof("kubernetes", identityId, jwt, organizationSlug);
    public static InfisicalLoginProof Oidc(string identityId, SecretMaterial jwt, string? organizationSlug = null) =>
        JwtProof("oidc", identityId, jwt, organizationSlug);
    /// <summary>JWT-SVID only; this route does not accept X.509-SVID.</summary>
    public static InfisicalLoginProof Spiffe(string identityId, SecretMaterial jwt, string? organizationSlug = null) =>
        JwtProof("spiffe", identityId, jwt, organizationSlug);

    public static InfisicalLoginProof Ldap(string identityId, string username, SecretMaterial password,
        string? organizationSlug = null)
    {
        if (!Guid.TryParseExact(identityId, "D", out _)) throw new ArgumentException("Invalid LDAP identity selection.");
        ValidateText(username, 255);
        return new("ldap", identityId, organizationSlug, writer =>
        {
            writer.WriteString("username", username);
            WriteMaterial(writer, "password", password, 1024);
        });
    }

    /// <summary>Signed OCI headers remain JSON proof fields, never transport headers.</summary>
    public static InfisicalLoginProof Oci(string identityId, string userOcid, SecretMaterial authorization,
        string host, string? date = null, string? xDate = null, string? organizationSlug = null)
    {
        ValidateText(userOcid, 1024);
        ValidateText(host, 1024);
        if (date is not null) ValidateText(date, 1024);
        if (xDate is not null) ValidateText(xDate, 1024);
        return new("oci", identityId, organizationSlug, writer =>
        {
            writer.WriteString("userOcid", userOcid);
            writer.WriteStartObject("headers");
            WriteMaterial(writer, "authorization", authorization);
            writer.WriteString("host", host);
            if (date is not null) writer.WriteString("date", date);
            if (xDate is not null) writer.WriteString("x-date", xDate);
            writer.WriteEndObject();
        });
    }

    /// <summary>Identity selection only. The host configures and owns mTLS certificate presentation.</summary>
    public static InfisicalLoginProof TlsCertificate(string identityId, string? organizationSlug = null) =>
        new("tls-cert", identityId, organizationSlug, _ => { });

    private static InfisicalLoginProof JwtProof(string strategy, string identityId, SecretMaterial jwt,
        string? organizationSlug) => new(strategy, identityId, organizationSlug, writer => WriteMaterial(writer, "jwt", jwt));

    private static void ValidateText(string value, int maximum)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximum || value.Any(char.IsControl))
            throw new ArgumentException("Invalid protected proof field.");
    }

    private static void WriteMaterial(Utf8JsonWriter writer, string name, SecretMaterial material, int maximum = 16384)
    {
        ArgumentNullException.ThrowIfNull(material);
        char[] characters = material.ExportCharacters();
        try
        {
            if (characters.Length < 1 || characters.Length > maximum || characters.Any(char.IsControl))
                throw new ArgumentException("Invalid host proof material.");
            writer.WriteString(name, characters.AsSpan());
        }
        finally { Array.Clear(characters); }
    }

    internal byte[] CopyPayload()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_payload is null, this);
            return (byte[])_payload.Clone();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_payload is null) return;
            Array.Clear(_payload);
            _payload = null;
        }
    }
    public override string ToString() => "[InfisicalLoginProof]";
}

/// <summary>One explicit host-proof exchange. No principal acquisition, background login or replay.</summary>
public sealed partial class InfisicalProofAuthentication : IDisposable
{
    private readonly HttpClient _transport;
    private readonly IInfisicalProofAuthenticationWire _wire;
    private readonly Uri _origin;
    private readonly TimeProvider _time;
    private readonly int _responseLimit;
    private bool _disposed;

    public InfisicalProofAuthentication(Uri origin, InfisicalNetworkOptions? network = null,
        TimeProvider? timeProvider = null) : this(origin, network ?? new(), timeProvider, null, true) { }

    /// <summary>Host-owned controlled transport, including host-configured client certificates.</summary>
    public InfisicalProofAuthentication(Uri origin, SocketsHttpHandler hostTransport,
        InfisicalNetworkOptions? network = null, TimeProvider? timeProvider = null)
        : this(origin, network ?? new(), timeProvider, Validate(hostTransport), false) { }

    internal InfisicalProofAuthentication(Uri origin, HttpMessageHandler handler,
        InfisicalNetworkOptions? network = null, TimeProvider? timeProvider = null)
        : this(origin, network ?? new(), timeProvider, handler, false) { }

    private InfisicalProofAuthentication(Uri origin, InfisicalNetworkOptions network,
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
        _time = timeProvider ?? TimeProvider.System;
        _responseLimit = network.MaximumResponseBytes;
        _transport = new HttpClient(handler ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ActivityHeadersPropagator = null,
            Proxy = network.Proxy
        }, disposeHandler: ownsHandler)
        { BaseAddress = origin, Timeout = Timeout.InfiniteTimeSpan };
        _wire = RestService.For<IInfisicalProofAuthenticationWire>(_transport, new RefitSettings
        {
            CaptureRequestContent = false,
            CaptureMethodArguments = false,
            ExceptionFactory = _ => ValueTask.FromResult<Exception?>(null)
        });
    }

    private static SocketsHttpHandler Validate(SocketsHttpHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        if (handler.AllowAutoRedirect || handler.UseCookies || handler.ActivityHeadersPropagator is not null)
            throw new ArgumentException("Transport must disable redirects, cookies and activity propagation.");
        return handler;
    }

    public InfisicalProofLoginReceipt CreateReceipt()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new(this);
    }

    public async ValueTask<SecretOutcome<InfisicalProofLogin>> LoginAsync(InfisicalLoginProof proof,
        InfisicalProofLoginReceipt receipt, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(receipt);
        cancellationToken.ThrowIfCancellationRequested();
        if (!ReferenceEquals(receipt.Owner, this) || receipt.Evidence != DispatchEvidence.NotDispatched)
            return SecretOutcome<InfisicalProofLogin>.Failure(SecretStatus.Invalid);
        byte[] payload = proof.CopyPayload();
        byte[] bytes = new byte[_responseLimit + 1];
        try
        {
            using var content = new ByteArrayContent(payload);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using HttpRequestMessage request = await BuildRequestAsync(proof.Strategy, content, cancellationToken).ConfigureAwait(false);
            Uri destination = new(_origin, $"/api/v1/auth/{proof.Strategy}-auth/login");
            if (request.RequestUri is { IsAbsoluteUri: false } relative) request.RequestUri = new(_origin, relative);
            if (request.Method != HttpMethod.Post || request.RequestUri != destination)
                return SecretOutcome<InfisicalProofLogin>.Failure(SecretStatus.Invalid);
            cancellationToken.ThrowIfCancellationRequested();
            DateTimeOffset sentAt = _time.GetUtcNow();
            if (!receipt.TryBeginDispatch()) return SecretOutcome<InfisicalProofLogin>.Failure(SecretStatus.Invalid);
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
                return SecretOutcome<InfisicalProofLogin>.Failure(status);
            }
            if (response.Content.Headers.ContentLength > _responseLimit)
                return SecretOutcome<InfisicalProofLogin>.Failure(SecretStatus.Unknown);
            using Stream body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            int length = 0;
            while (length < bytes.Length)
            {
                int count = await body.ReadAsync(bytes.AsMemory(length), cancellationToken).ConfigureAwait(false);
                if (count == 0) break;
                length += count;
            }
            if (length > _responseLimit) return SecretOutcome<InfisicalProofLogin>.Failure(SecretStatus.Unknown);
            using var document = JsonDocument.Parse(bytes.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 8 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                root.EnumerateObject().Any(property => property.Name is not
                    ("accessToken" or "accessTokenMaxTTL" or "expiresIn" or "tokenType")) ||
                root.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != root.EnumerateObject().Count() ||
                !root.TryGetProperty("accessToken", out var token) || token.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("tokenType", out var type) || type.ValueKind != JsonValueKind.String || type.GetString() != "Bearer" ||
                !root.TryGetProperty("expiresIn", out var expires) || expires.ValueKind != JsonValueKind.Number ||
                !expires.TryGetDouble(out double seconds) || !double.IsFinite(seconds) || seconds <= 0 || seconds > 3153600000 ||
                !root.TryGetProperty("accessTokenMaxTTL", out var maximum) || maximum.ValueKind != JsonValueKind.Number ||
                !maximum.TryGetDouble(out double max) || !double.IsFinite(max) || max < 0)
                return SecretOutcome<InfisicalProofLogin>.Failure(SecretStatus.Unknown);
            string text = token.GetString()!;
            if (text.Length is < 1 or > 16384 || text.Any(c => c <= ' ' || c >= 127))
                return SecretOutcome<InfisicalProofLogin>.Failure(SecretStatus.Unknown);
            DateTimeOffset expiresAt = sentAt.AddSeconds(seconds);
            var result = new InfisicalProofLogin(new(SecretMaterial.FromText(text), expiresAt), seconds, max);
            receipt.Record(DispatchEvidence.Applied);
            if (cancellationToken.IsCancellationRequested)
            {
                result.Dispose();
                cancellationToken.ThrowIfCancellationRequested();
            }
            return SecretOutcome<InfisicalProofLogin>.Success(result);
        }
        catch (OperationCanceledException) { throw new OperationCanceledException("Proof login canceled.", cancellationToken); }
        catch (Exception error) when (error is HttpRequestException or IOException or JsonException or
            InvalidOperationException or ArgumentOutOfRangeException)
        {
            return SecretOutcome<InfisicalProofLogin>.Failure(SecretStatus.Unknown);
        }
        finally
        {
            Array.Clear(payload);
            Array.Clear(bytes);
        }
    }

    private Task<HttpRequestMessage> BuildRequestAsync(string strategy, HttpContent content,
        CancellationToken cancellationToken) => strategy switch
        {
            "alicloud" => _wire.AliCloudAsync(content, cancellationToken),
            "aws" => _wire.AwsAsync(content, cancellationToken),
            "azure" => _wire.AzureAsync(content, cancellationToken),
            "gcp" => _wire.GcpAsync(content, cancellationToken),
            "jwt" => _wire.JwtAsync(content, cancellationToken),
            "kubernetes" => _wire.KubernetesAsync(content, cancellationToken),
            "ldap" => _wire.LdapAsync(content, cancellationToken),
            "oci" => _wire.OciAsync(content, cancellationToken),
            "oidc" => _wire.OidcAsync(content, cancellationToken),
            "spiffe" => _wire.SpiffeAsync(content, cancellationToken),
            "tls-cert" => _wire.TlsCertificateAsync(content, cancellationToken),
            _ => throw new InvalidOperationException("Invalid proof login binding.")
        };

    public void Dispose()
    {
        _disposed = true;
        _transport.Dispose();
    }
    public override string ToString() => "[InfisicalProofAuthentication]";
}

/// <summary>Caller-held dispatch evidence, not an idempotency key or rollback promise.</summary>
public sealed class InfisicalProofLoginReceipt
{
    internal InfisicalProofLoginReceipt(object owner) => Owner = owner;
    internal object Owner { get; }
    private int _evidence;
    public DispatchEvidence Evidence => (DispatchEvidence)Volatile.Read(ref _evidence);
    internal bool TryBeginDispatch() => Interlocked.CompareExchange(ref _evidence,
        (int)DispatchEvidence.PossiblyDispatched, (int)DispatchEvidence.NotDispatched) == (int)DispatchEvidence.NotDispatched;
    internal void Record(DispatchEvidence evidence) => Volatile.Write(ref _evidence, (int)evidence);
    public override string ToString() => $"[InfisicalProofLoginReceipt:{Evidence}]";
}

/// <summary>Reported token lifetime; Max TTL is metadata, not an inferred original expiry ceiling.</summary>
public sealed class InfisicalProofLogin : IDisposable
{
    internal InfisicalProofLogin(InfisicalAccessToken token, double expiresIn, double maximum)
    {
        Token = token;
        ExpiresIn = expiresIn;
        AccessTokenMaxTTL = maximum;
    }
    [JsonIgnore] public InfisicalAccessToken Token { get; }
    public double ExpiresIn { get; }
    public double AccessTokenMaxTTL { get; }
    public void Dispose() => Token.Dispose();
    public override string ToString() => "[InfisicalProofLogin]";
}
