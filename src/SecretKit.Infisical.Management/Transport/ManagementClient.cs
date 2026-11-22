using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Internal;

namespace SecretKit.Infisical.Management;

/// <summary>
/// Fixed-origin administrative transport disposed by its owner, never by clients.
/// Safe modes enforce network safeguards; an explicitly host-controlled pipeline
/// retains the host's policies and ownership.
/// </summary>
public sealed class ManagementTransport : IDisposable
{
    private readonly HttpClient _http;
    private readonly HttpTransportBinding _binding;
    private readonly ManagementRequestBuilder _requests;
    internal int ResponseLimit { get; }
    internal int RequestLimit { get; }
    internal TimeSpan OperationTimeout { get; }

    /// <summary>Creates a bounded transport for the selected origin and network policy; null selects safe defaults.</summary>
    public ManagementTransport(Uri origin, InfisicalNetworkOptions? network = null)
        : this(origin, network ?? new(), null)
    {
    }

    internal ManagementTransport(Uri origin, int maximumResponseBytes, IWebProxy? proxy,
        bool allowLoopbackDevelopmentHttp, HttpMessageHandler? handler)
        : this(origin, new InfisicalNetworkOptions
        {
            MaximumResponseBytes = maximumResponseBytes,
            Proxy = proxy,
            AllowLoopbackDevelopmentHttp = allowLoopbackDevelopmentHttp
        }, handler)
    {
    }

    private ManagementTransport(Uri origin, InfisicalNetworkOptions network, HttpMessageHandler? handler)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(network.Transport);
        var selection = new HttpTransportSettings(network.Transport.Client, network.Transport.Handler,
            network.Transport.CopyRoots, network.Proxy, network.AllowLoopbackDevelopmentHttp,
            network.MaximumRequestBytes, network.OperationTimeout);
        HttpTransportBinding.ValidateOrigin(origin, selection);
        if (!TransferLimits.IsValidByteBudget(network.MaximumResponseBytes))
        {
            throw new ArgumentException("Invalid response byte budget.");
        }
        ResponseLimit = network.MaximumResponseBytes;
        RequestLimit = network.MaximumRequestBytes;
        OperationTimeout = network.OperationTimeout;
        _binding = new(origin, selection, handler);
        _http = _binding.Client;
        _requests = new ManagementRequestBuilder(_binding.Requests);
    }

    internal Task<HttpRequestMessage> BuildAsync<T>(ManagementRequest<T> request,
        HttpContent? body, CancellationToken cancellationToken) where T : notnull =>
        _requests.BuildAsync(request, body, cancellationToken);

    internal Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

    /// <summary>Releases owned transport resources without disposing borrowed host clients or handlers.</summary>
    public void Dispose() => _binding.Dispose();
    /// <summary>Returns a redacted marker without origin or transport configuration.</summary>
    public override string ToString() => "[ManagementTransport]";
}

/// <summary>
/// Executes typed administrative requests using explicitly selected credentials
/// and exact host grants. Borrows its transport and never chooses a fallback identity.
/// </summary>
public sealed class ManagementClient
{
    private readonly ManagementTransport _transport;
    private readonly TimeProvider _time;
    /// <summary>Gets this client's local binding identity for grants and receipts, not proof of provider permissions.</summary>
    public SecretAuthority Authority { get; } = new();

    /// <summary>Creates a client borrowing the transport; a null clock uses system UTC time for token expiry checks.</summary>
    public ManagementClient(ManagementTransport transport, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        _transport = transport;
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Creates pre-dispatch evidence for this exact mutation request; retain it across cancellation or an unknown response.</summary>
    public ManagementReceipt CreateReceipt<T>(ManagementRequest<T> request) where T : notnull
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.IsMutation)
        {
            throw new ArgumentException("Only effectful requests have mutation receipts.");
        }
        return new ManagementReceipt(request, Authority);
    }

    /// <summary>
    /// Executes once after checking the selected authority, exact grant and mutation
    /// receipt. Null or mismatched grants deny access before token acquisition.
    /// Dispose successful material-bearing results and the caller-owned request.
    /// </summary>
    /// <remarks>
    /// Reads require no receipt; mutations require a fresh receipt from this client.
    /// Cancellation propagates and does not roll back remote effects. Keep the
    /// receipt when dispatch or response evidence is uncertain; execution never replays.
    /// </remarks>
    /// <exception cref="OperationCanceledException">The operation was canceled; inspect the retained receipt for known dispatch evidence.</exception>
    public async ValueTask<SecretOutcome<T>> ExecuteAsync<T>(ManagementRequest<T> request,
        ManagementAuthority authority, ManagementGrant? grant, ManagementReceipt? receipt = null,
        CancellationToken cancellationToken = default) where T : notnull
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(authority);
        using IDisposable export = InfisicalDiagnostics.Defer();
        var started = OperationTiming.Capture(_time);
        var observation = new OperationObservation();
        try
        {
            return await OperationBudget.RunAsync(_transport.OperationTimeout, _time,
                budget => ExecuteOnceAsync(request, authority, grant, receipt, budget.Token),
                observation,
                () => receipt?.Evidence ?? DispatchEvidence.NotDispatched,
                caller: cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (observation.Completion is { } completion)
                ManagementDiagnostics.Emit(request.OperationId, completion,
                    OperationTiming.Complete(started, _time));
        }
    }

    private async ValueTask<SecretOutcome<T>> ExecuteOnceAsync<T>(ManagementRequest<T> request,
        ManagementAuthority authority, ManagementGrant? grant, ManagementReceipt? receipt,
        CancellationToken cancellationToken) where T : notnull
    {
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

        byte[]? body = request.CopyBody(_transport.RequestLimit);
        if (body is { Length: 0 })
            return SecretOutcome<T>.Failure(SecretStatus.Invalid, reason: SecretFailureReason.RequestTooLarge);
        try
        {
            using var content = body is null ? null : new ByteArrayContent(body);
            if (content is not null) content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using HttpRequestMessage message = await _transport.BuildAsync(request, content, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            SecretOutcome<InfisicalAccessToken> tokenOutcome =
                await authority.Tokens.GetTokenAsync(cancellationToken).ConfigureAwait(false);
            if (!tokenOutcome.IsSuccess)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return tokenOutcome.ConvertFailure<T>();
            }
            using InfisicalAccessToken token = tokenOutcome.Value;
            cancellationToken.ThrowIfCancellationRequested();
            if (token.ExpiresAt is { } expiry && expiry <= _time.GetUtcNow())
            {
                return SecretOutcome<T>.Failure(SecretStatus.Expired);
            }
            if (BearerHeader.CreateHeader(token.Material) is not { } authorization)
            {
                return SecretOutcome<T>.Failure(SecretStatus.Invalid);
            }
            message.Headers.Authorization = authorization;
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
                using JsonDocument acknowledgementBody = JsonDocument.Parse("\"\"");
                T acknowledgement = request.Parse(acknowledgementBody.RootElement);
                receipt?.Record(DispatchEvidence.Applied);
                cancellationToken.ThrowIfCancellationRequested();
                return SecretOutcome<T>.Success(acknowledgement);
            }
            if (response.StatusCode == HttpStatusCode.Accepted)
            {
                receipt?.Record(DispatchEvidence.Pending);
                cancellationToken.ThrowIfCancellationRequested();
                return SecretOutcome<T>.Failure(SecretStatus.Pending);
            }
            if (response.StatusCode != HttpStatusCode.OK || credentialCheck)
            {
                SecretStatus status = response.StatusCode switch
                {
                    HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity => SecretStatus.Invalid,
                    HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => SecretStatus.Denied,
                    HttpStatusCode.NotFound => SecretStatus.Unknown,
                    HttpStatusCode.Conflict or HttpStatusCode.PreconditionFailed => SecretStatus.Conflict,
                    HttpStatusCode.TooManyRequests => SecretStatus.Throttled,
                    HttpStatusCode.ServiceUnavailable => SecretStatus.Unavailable,
                    _ => SecretStatus.Unknown
                };
                if (status == SecretStatus.Conflict)
                {
                    receipt?.Record(DispatchEvidence.Conflict);
                }
                else if (status is SecretStatus.Invalid or SecretStatus.Denied or SecretStatus.Throttled ||
                    response.StatusCode == HttpStatusCode.NotFound)
                {
                    receipt?.Record(DispatchEvidence.Rejected);
                }
                cancellationToken.ThrowIfCancellationRequested();
                return await HttpFailureResponse.ReadAsync<T>(response, _transport.ResponseLimit, _time,
                    status, InfisicalErrorResponse.Project<T>, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            using JsonDocument? document = await BoundedJson.ReadJsonAsync(
                response, _transport.ResponseLimit, 64, allowDuplicateProperties: false, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (document is null)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return SecretOutcome<T>.Failure(SecretStatus.Unknown);
            }
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
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<T>.Failure(error.Status);
        }
        catch (Exception error) when (error is HttpRequestException or IOException or JsonException or
            InvalidOperationException or FormatException or ObjectDisposedException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<T>.Failure(SecretStatus.Unknown);
        }
        finally
        {
            if (body is not null)
            {
                CryptographicOperations.ZeroMemory(body);
            }
        }
    }

    /// <summary>Returns a redacted marker without credentials or administrative scope.</summary>
    public override string ToString() => "[ManagementClient]";
}
