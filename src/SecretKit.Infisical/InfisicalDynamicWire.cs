using System.Net.Http.Headers;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical;

// Handwritten route declarations only. Bodies are privately constructed typed-profile content;
// Request builders preserve the controlled HttpClient send and bounded native parser seam.
internal interface IInfisicalDynamicWire
{
    [Get("/api/v1/dynamic-secrets")]
    Task<HttpRequestMessage> ListDefinitionsAsync(string projectSlug, string environmentSlug,
        [AliasAs("path")] string folder, CancellationToken cancellationToken);

    [Get("/api/v1/dynamic-secrets/{name}")]
    Task<HttpRequestMessage> InspectDefinitionAsync(string name, string projectSlug, string environmentSlug,
        [AliasAs("path")] string folder, CancellationToken cancellationToken);

    [Post("/api/v1/dynamic-secrets")]
    Task<HttpRequestMessage> CreateDefinitionAsync([Body] HttpContent content,
        [Property("SecretKit.DynamicReceipt")] InfisicalDynamicMutationReceipt receipt, CancellationToken cancellationToken);

    [Patch("/api/v1/dynamic-secrets/{name}")]
    Task<HttpRequestMessage> UpdateDefinitionAsync(string name, [Body] HttpContent content,
        [Property("SecretKit.DynamicReceipt")] InfisicalDynamicMutationReceipt receipt, CancellationToken cancellationToken);

    [Delete("/api/v1/dynamic-secrets/{name}")]
    Task<HttpRequestMessage> DeleteDefinitionAsync(string name, [Body] HttpContent content,
        [Property("SecretKit.DynamicReceipt")] InfisicalDynamicMutationReceipt receipt, CancellationToken cancellationToken);

    [Get("/api/v1/dynamic-secrets/{name}/leases")]
    Task<HttpRequestMessage> ListLeasesAsync(string name, string projectSlug, string environmentSlug,
        [AliasAs("path")] string folder, CancellationToken cancellationToken);

    [Get("/api/v1/dynamic-secrets/leases/{leaseId}")]
    Task<HttpRequestMessage> InspectLeaseAsync(Guid leaseId, string projectSlug, string environmentSlug,
        [AliasAs("path")] string folder, CancellationToken cancellationToken);

    [Post("/api/v1/dynamic-secrets/leases")]
    Task<HttpRequestMessage> AcquireAsync([Body] HttpContent content,
        [Property("SecretKit.DynamicReceipt")] InfisicalDynamicMutationReceipt receipt, CancellationToken cancellationToken);

    [Post("/api/v1/dynamic-secrets/leases/{leaseId}/renew")]
    Task<HttpRequestMessage> RenewAsync(Guid leaseId, [Body] HttpContent content,
        [Property("SecretKit.DynamicReceipt")] InfisicalDynamicMutationReceipt receipt, CancellationToken cancellationToken);

    [Delete("/api/v1/dynamic-secrets/leases/{leaseId}")]
    Task<HttpRequestMessage> RevokeAsync(Guid leaseId, [Body] HttpContent content,
        [Property("SecretKit.DynamicReceipt")] InfisicalDynamicMutationReceipt receipt, CancellationToken cancellationToken);
}

internal sealed class InfisicalDynamicDispatchHandler : DelegatingHandler
{
    private readonly Uri _origin;
    private readonly IInfisicalTokenSource _tokens;
    private readonly TimeProvider _time;
    private readonly bool _ownsTransport;
    internal InfisicalDynamicDispatchHandler(Uri origin, IInfisicalTokenSource tokens,
        TimeProvider time, HttpMessageHandler transport, bool ownsTransport) : base(transport)
    {
        _origin = origin;
        _tokens = tokens;
        _time = time;
        _ownsTransport = ownsTransport;
    }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (request.RequestUri is not { } uri ||
            uri.GetLeftPart(UriPartial.Authority) != _origin.GetLeftPart(UriPartial.Authority))
        {
            throw new InfisicalDynamicTransportFailure(SecretStatus.Invalid);
        }
        SecretOutcome<InfisicalAccessToken> supplied = await _tokens.GetTokenAsync(token).ConfigureAwait(false);
        if (!supplied.IsSuccess)
        {
            token.ThrowIfCancellationRequested();
            throw new InfisicalDynamicTransportFailure(supplied.Status);
        }
        using InfisicalAccessToken access = supplied.Value;
        token.ThrowIfCancellationRequested();
        if (access.ExpiresAt <= _time.GetUtcNow())
        {
            throw new InfisicalDynamicTransportFailure(SecretStatus.Expired);
        }
        string bearer = access.Material.Reveal();
        if (bearer.Length is < 1 or > 16384 ||
            !bearer.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '~' or '+' or '/' or '='))
        {
            throw new InfisicalDynamicTransportFailure(SecretStatus.Invalid);
        }
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        token.ThrowIfCancellationRequested();
        if (request.Options.TryGetValue(new HttpRequestOptionsKey<object>("SecretKit.DynamicReceipt"), out object? value) &&
            value is InfisicalDynamicMutationReceipt receipt && !receipt.Begin())
        {
            throw new InfisicalDynamicTransportFailure(SecretStatus.Invalid);
        }
        return await base.SendAsync(request, token).ConfigureAwait(false);
    }
    protected override void Dispose(bool disposing)
    {
        if (_ownsTransport)
        {
            base.Dispose(disposing);
        }
    }
}

internal sealed class InfisicalDynamicTransportFailure : Exception
{
    internal InfisicalDynamicTransportFailure(SecretStatus status) : base("Native lifecycle transport unavailable.") =>
        Status = status;
    internal SecretStatus Status { get; }
}
