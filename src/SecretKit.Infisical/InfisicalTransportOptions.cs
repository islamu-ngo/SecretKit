using System.Security.Cryptography.X509Certificates;

namespace SecretKit.Infisical;

/// <summary>Selects SDK-enforced networking or an explicitly host-controlled pipeline.</summary>
/// <remarks>Host-controlled pipelines may redirect, retry, log or relax TLS.
/// The SDK cannot enforce networking policy inside them. Supplied resources remain host-owned.</remarks>
public sealed class InfisicalTransportOptions
{
    private readonly byte[][] _roots;
    internal HttpClient? Client { get; }
    internal HttpMessageHandler? Handler { get; }
    internal bool IsHostControlled => Client is not null || Handler is not null;

    private InfisicalTransportOptions(HttpClient? client = null, HttpMessageHandler? handler = null,
        byte[][]? roots = null) => (Client, Handler, _roots) = (client, handler, roots ?? []);

    /// <summary>Uses normal system TLS trust, no redirects, cookies or ambient proxy.</summary>
    public static InfisicalTransportOptions SafeDefault { get; } = new();

    /// <summary>Uses only the selected private roots, retaining normal hostname and chain checks.</summary>
    /// <remarks>Copies public certificate data immediately. The caller retains certificate ownership.
    /// Replaces system roots and checks issuer, validity, usage and hostname. Revocation uses
    /// the handler default, NoCheck; this selection does not enable revocation checking.</remarks>
    public static InfisicalTransportOptions SafeWithPrivateTrust(params X509Certificate2[] roots)
    {
        ArgumentNullException.ThrowIfNull(roots);
        if (roots.Length == 0) throw new ArgumentException("Private trust requires at least one root.");
        return new(roots: roots.Select(root =>
        {
            ArgumentNullException.ThrowIfNull(root);
            return root.Export(X509ContentType.Cert);
        }).ToArray());
    }

    /// <summary>Borrows this client unchanged, including its networking and diagnostic policy.</summary>
    /// <remarks>HTTP, TLS, redirects, retries and logging are host-controlled, not SDK-enforced.
    /// Disposing an SDK consumer does not dispose this client.</remarks>
    public static InfisicalTransportOptions HostControlled(HttpClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        return new(client: client);
    }

    /// <summary>Borrows this handler through an SDK-owned client that does not dispose the handler.</summary>
    /// <remarks>The arbitrary host pipeline controls HTTP, TLS, retries and logging.
    /// Safe-mode restrictions cannot be enforced inside it.</remarks>
    public static InfisicalTransportOptions HostControlled(HttpMessageHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return new(handler: handler);
    }

    internal X509Certificate2[] CopyRoots() =>
        _roots.Select(data => X509CertificateLoader.LoadCertificate(data)).ToArray();

    /// <summary>Returns a material-free description, never pipeline or certificate details.</summary>
    public override string ToString() => "[InfisicalTransportOptions]";
}

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
