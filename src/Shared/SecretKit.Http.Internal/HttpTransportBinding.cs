using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace SecretKit.Internal;

// Immutable selection for a borrowed pipeline or an SDK-owned safe transport.
internal sealed record HttpTransportSettings(
    HttpClient? Client,
    HttpMessageHandler? Handler,
    Func<X509Certificate2[]> CopyRoots,
    IWebProxy? Proxy,
    bool AllowLoopbackDevelopmentHttp,
    int MaximumRequestBytes,
    TimeSpan OperationTimeout)
{
    internal bool IsHostControlled => Client is not null || Handler is not null;
}

// Request builders never send. A distinct lifetime-scoped client performs the
// single SDK handoff, without mutating or wrapping a borrowed HttpClient.
internal class HttpTransportBinding : IDisposable
{
    internal HttpClient Client { get; }
    internal HttpClient Requests { get; }
    private readonly bool _ownsClient;
    private readonly X509Certificate2[] _roots;
    private readonly Uri _origin;

    internal static void ValidateOrigin(Uri origin, HttpTransportSettings network)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(network);
        if (!TransferLimits.IsValidByteBudget(network.MaximumRequestBytes) ||
            !TransferLimits.IsValidTimeout(network.OperationTimeout))
            throw new ArgumentException("Invalid request or operation budget.", nameof(network));
        OriginPolicy.ValidateProviderOrigin(origin, network.IsHostControlled,
            network.AllowLoopbackDevelopmentHttp);
        if (network.IsHostControlled && network.Proxy is not null)
            throw new ArgumentException("Explicit proxy selection requires SDK-safe transport.");
    }

    internal HttpTransportBinding(Uri origin, HttpTransportSettings network,
        HttpMessageHandler? testHandler = null, bool ownsTestHandler = true)
    {
        ValidateOrigin(origin, network);
        _origin = origin;
        _roots = network.CopyRoots();
        if (testHandler is not null)
        {
            Client = new HttpClient(testHandler, ownsTestHandler) { Timeout = Timeout.InfiniteTimeSpan };
            _ownsClient = true;
        }
        else if (network.Client is { } client)
            Client = client;
        else
        {
            HttpMessageHandler handler;
            bool ownsHandler;
            if (network.Handler is { } borrowed)
            {
                handler = borrowed;
                ownsHandler = false;
            }
            else
            {
                var safe = SecretKitSocketsHandlerFactory.Create(network.Proxy);
                if (_roots.Length != 0)
                {
                    var policy = new X509ChainPolicy
                    {
                        TrustMode = X509ChainTrustMode.CustomRootTrust,
                        // Match SocketsHttpHandler's default revocation policy.
                        // Issuer, validity, usage and hostname checks still apply.
                        RevocationMode = X509RevocationMode.NoCheck
                    };
                    policy.CustomTrustStore.AddRange(_roots);
                    safe.SslOptions.CertificateChainPolicy = policy;
                }
                handler = safe;
                ownsHandler = true;
            }
            Client = new HttpClient(handler, ownsHandler) { Timeout = Timeout.InfiniteTimeSpan };
            _ownsClient = true;
        }
        Requests = new HttpClient(new RequestBuilderOnlyHandler())
        {
            BaseAddress = origin,
            Timeout = Timeout.InfiniteTimeSpan
        };
    }

    internal void BindRequest(HttpRequestMessage request)
    {
        if (request.RequestUri is not { } selected)
            throw new InvalidOperationException("A selected request destination is required.");
        Uri absolute = new(_origin, selected);
        if (absolute.Scheme != _origin.Scheme || absolute.Host != _origin.Host ||
            absolute.Port != _origin.Port || absolute.UserInfo.Length != 0 || absolute.Fragment.Length != 0)
            throw new InvalidOperationException("The request must remain within the selected origin.");
        request.RequestUri = absolute;
    }

    public void Dispose()
    {
        Requests.Dispose();
        if (_ownsClient) Client.Dispose();
        foreach (X509Certificate2 root in _roots) root.Dispose();
    }

    private sealed class RequestBuilderOnlyHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Request builders cannot dispatch.");
    }
}
