using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>
/// Host-owned fixed-origin transport. Clients never dispose it. No cookies,
/// redirects, certificate bypass, fallback identity, or application retry.
/// </summary>
public sealed class ManagementTransport : IDisposable
{
    private readonly HttpClient _http;
    private readonly ManagementRequestBuilder _requests;
    internal int ResponseLimit { get; }

    public ManagementTransport(Uri origin, int maximumResponseBytes = 1024 * 1024,
        IWebProxy? proxy = null, bool allowLoopbackDevelopmentHttp = false)
        : this(origin, maximumResponseBytes, proxy, allowLoopbackDevelopmentHttp, null)
    {
    }

    internal ManagementTransport(Uri origin, int maximumResponseBytes, IWebProxy? proxy,
        bool allowLoopbackDevelopmentHttp, HttpMessageHandler? handler)
    {
        ArgumentNullException.ThrowIfNull(origin);
        if (!origin.IsAbsoluteUri ||
            (origin.Scheme != "https" && !(allowLoopbackDevelopmentHttp &&
                origin.Scheme == "http" && origin.IsLoopback)) ||
            origin.UserInfo.Length != 0 || origin.AbsolutePath != "/" ||
            origin.Query.Length != 0 || origin.Fragment.Length != 0)
        {
            throw new ArgumentException("A fixed trusted HTTPS origin is required.");
        }
        if (maximumResponseBytes is < 1024 or > 16 * 1024 * 1024)
        {
            throw new ArgumentException("Invalid response byte budget.");
        }
        ResponseLimit = maximumResponseBytes;
        _http = new HttpClient(handler ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            Proxy = proxy,
            ActivityHeadersPropagator = null
        }, disposeHandler: true)
        { Timeout = Timeout.InfiniteTimeSpan, BaseAddress = origin };
        _requests = new ManagementRequestBuilder(_http);
    }

    internal Task<HttpRequestMessage> BuildAsync<T>(ManagementRequest<T> request,
        HttpContent? body, CancellationToken cancellationToken) where T : notnull =>
        _requests.BuildAsync(request, body, cancellationToken);

    internal Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

    public void Dispose() => _http.Dispose();
    public override string ToString() => "[ManagementTransport]";
}

/// <summary>Typed administrative execution; credentials and grants are explicit on every call.</summary>
public sealed class ManagementClient
{
    private readonly ManagementTransport _transport;
    private readonly TimeProvider _time;
    public SecretAuthority Authority { get; } = new();

    public ManagementClient(ManagementTransport transport, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        _transport = transport;
        _time = timeProvider ?? TimeProvider.System;
    }

    public ManagementReceipt CreateReceipt<T>(ManagementRequest<T> request) where T : notnull
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.IsMutation)
        {
            throw new ArgumentException("Only effectful requests have mutation receipts.");
        }
        return new ManagementReceipt(request, Authority);
    }

    public async ValueTask<SecretOutcome<T>> ExecuteAsync<T>(ManagementRequest<T> request,
        ManagementAuthority authority, ManagementGrant? grant, ManagementReceipt? receipt = null,
        CancellationToken cancellationToken = default) where T : notnull
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(authority);
        cancellationToken.ThrowIfCancellationRequested();
        if (grant is null || !grant.Matches(Authority, authority, request.OperationId, request.Target))
        {
            return SecretOutcome<T>.Failure(SecretStatus.Denied);
        }
        if (request.IsMutation && (receipt is null || !receipt.Matches(request, Authority) ||
            receipt.Evidence != DispatchEvidence.NotDispatched) || !request.IsMutation && receipt is not null)
        {
            return SecretOutcome<T>.Failure(SecretStatus.Invalid);
        }

        byte[]? body = request.CopyBody();
        byte[] responseBytes = new byte[_transport.ResponseLimit + 1];
        try
        {
            using var content = body is null ? null : new ByteArrayContent(body);
            if (content is not null) content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using HttpRequestMessage message = await _transport.BuildAsync(request, content, cancellationToken).ConfigureAwait(false);
            SecretOutcome<InfisicalAccessToken> tokenOutcome =
                await authority.Tokens.GetTokenAsync(cancellationToken).ConfigureAwait(false);
            if (!tokenOutcome.IsSuccess)
            {
                return SecretOutcome<T>.Failure(tokenOutcome.Status, tokenOutcome.RetryAfter);
            }
            using InfisicalAccessToken token = tokenOutcome.Value;
            cancellationToken.ThrowIfCancellationRequested();
            if (token.ExpiresAt is { } expiry && expiry <= _time.GetUtcNow())
            {
                return SecretOutcome<T>.Failure(SecretStatus.Expired);
            }
            string bearer = token.Material.Reveal();
            if (bearer.Length is 0 or > 16384 || bearer.Any(c => c <= ' ' || c >= 127))
            {
                return SecretOutcome<T>.Failure(SecretStatus.Invalid);
            }
            message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            cancellationToken.ThrowIfCancellationRequested();
            if (receipt is not null && !receipt.TryBeginDispatch())
            {
                return SecretOutcome<T>.Failure(SecretStatus.Invalid);
            }
            using HttpResponseMessage response = await _transport.SendAsync(message, cancellationToken).ConfigureAwait(false);
            bool credentialCheck = request.OperationId is
                "infisical.post.v2.secret.rotations.postgres.credentials.by.rotationId.check.credentials" or
                "infisical.post.v2.secret.rotations.mysql.credentials.by.rotationId.check.credentials" or
                "infisical.post.v2.secret.rotations.mssql.credentials.by.rotationId.check.credentials";
            if (credentialCheck && response.StatusCode == HttpStatusCode.NoContent)
            {
                T acknowledgement = request.Parse(JsonSerializer.SerializeToElement(""));
                receipt?.Record(DispatchEvidence.Applied);
                cancellationToken.ThrowIfCancellationRequested();
                return SecretOutcome<T>.Success(acknowledgement);
            }
            if (response.StatusCode == HttpStatusCode.Accepted)
            {
                receipt?.Record(DispatchEvidence.Pending);
                return SecretOutcome<T>.Failure(SecretStatus.Pending);
            }
            if (response.StatusCode != HttpStatusCode.OK || credentialCheck)
            {
                SecretStatus status = response.StatusCode switch
                {
                    HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity => SecretStatus.Invalid,
                    HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => SecretStatus.Denied,
                    HttpStatusCode.NotFound => SecretStatus.Absent,
                    HttpStatusCode.Conflict or HttpStatusCode.PreconditionFailed => SecretStatus.Conflict,
                    HttpStatusCode.TooManyRequests => SecretStatus.Throttled,
                    _ => SecretStatus.Unknown
                };
                if (status == SecretStatus.Conflict)
                {
                    receipt?.Record(DispatchEvidence.Conflict);
                }
                else if (status is SecretStatus.Invalid or SecretStatus.Denied or SecretStatus.Absent or SecretStatus.Throttled)
                {
                    receipt?.Record(DispatchEvidence.Rejected);
                }
                return SecretOutcome<T>.Failure(status);
            }
            if (response.Content.Headers.ContentLength > _transport.ResponseLimit)
            {
                return SecretOutcome<T>.Failure(SecretStatus.Unknown);
            }
            using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            int length = 0;
            while (length < responseBytes.Length)
            {
                int count = await stream.ReadAsync(responseBytes.AsMemory(length), cancellationToken).ConfigureAwait(false);
                if (count == 0)
                {
                    break;
                }
                length += count;
            }
            if (length > _transport.ResponseLimit)
            {
                return SecretOutcome<T>.Failure(SecretStatus.Unknown);
            }
            using JsonDocument document = JsonDocument.Parse(responseBytes.AsMemory(0, length),
                new JsonDocumentOptions { MaxDepth = 64 });
            RejectDuplicateProperties(document.RootElement);
            T result = request.Parse(document.RootElement);
            receipt?.Record(DispatchEvidence.Applied);
            // If cancellation wins after a complete response, preserve its known receipt,
            // but do not leak an owned material result that the caller cannot receive.
            if (cancellationToken.IsCancellationRequested)
            {
                (result as IDisposable)?.Dispose();
                cancellationToken.ThrowIfCancellationRequested();
            }
            return SecretOutcome<T>.Success(result);
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException("Management operation canceled.", cancellationToken);
        }
        catch (ManagementContractException error)
        {
            return SecretOutcome<T>.Failure(error.Status);
        }
        catch (Exception error) when (error is HttpRequestException or IOException or JsonException or
            InvalidOperationException or FormatException or ObjectDisposedException)
        {
            return SecretOutcome<T>.Failure(SecretStatus.Unknown);
        }
        finally
        {
            if (body is not null)
            {
                Array.Clear(body);
            }
            Array.Clear(responseBytes);
        }
    }

    private static void RejectDuplicateProperties(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in value.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new ManagementContractException(SecretStatus.Unknown);
                }
                RejectDuplicateProperties(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in value.EnumerateArray())
            {
                RejectDuplicateProperties(item);
            }
        }
    }

    public override string ToString() => "[ManagementClient]";
}
