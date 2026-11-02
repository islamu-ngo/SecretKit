using System.Security.Cryptography.X509Certificates;

namespace SecretKit.Infisical;

// Request builders never send. A distinct lifetime-scoped client performs the
// single SDK handoff, without mutating or wrapping a borrowed HttpClient.
internal sealed class InfisicalTransportBinding : IDisposable
{
    internal HttpClient Client { get; }
    internal HttpClient Requests { get; }
    private readonly bool _ownsClient;
    private readonly X509Certificate2[] _roots;
    private readonly Uri _origin;

    internal static void ValidateOrigin(Uri origin, InfisicalNetworkOptions network)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(network.Transport);
        if (network.MaximumRequestBytes is < 1024 or > 16 * 1024 * 1024 ||
            network.OperationTimeout <= TimeSpan.Zero || network.OperationTimeout > TimeSpan.FromMinutes(1))
            throw new ArgumentException("Invalid request or operation budget.", nameof(network));
        bool http = origin.IsAbsoluteUri && origin.Scheme == Uri.UriSchemeHttp &&
            (network.Transport.IsHostControlled || origin.IsLoopback && network.AllowLoopbackDevelopmentHttp);
        if (!origin.IsAbsoluteUri || origin.Scheme != Uri.UriSchemeHttps && !http ||
            origin.UserInfo.Length != 0 || origin.AbsolutePath != "/" ||
            origin.Query.Length != 0 || origin.Fragment.Length != 0)
            throw new ArgumentException("A fixed HTTP(S) origin with an admitted transport is required.");
        if (network.Transport.IsHostControlled && network.Proxy is not null)
            throw new ArgumentException("Explicit proxy selection requires SDK-safe transport.");
    }

    internal InfisicalTransportBinding(Uri origin, InfisicalNetworkOptions network,
        HttpMessageHandler? testHandler = null, bool ownsTestHandler = true)
    {
        ValidateOrigin(origin, network);
        _origin = origin;
        _roots = network.Transport.CopyRoots();
        if (testHandler is not null)
        {
            Client = new HttpClient(testHandler, ownsTestHandler) { Timeout = Timeout.InfiniteTimeSpan };
            _ownsClient = true;
        }
        else if (network.Transport.Client is { } client)
            Client = client;
        else
        {
            HttpMessageHandler handler;
            bool ownsHandler;
            if (network.Transport.Handler is { } borrowed)
            {
                handler = borrowed;
                ownsHandler = false;
            }
            else
            {
                var safe = new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    UseCookies = false,
                    UseProxy = network.Proxy is not null,
                    Proxy = network.Proxy,
                    ActivityHeadersPropagator = null,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(2)
                };
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
