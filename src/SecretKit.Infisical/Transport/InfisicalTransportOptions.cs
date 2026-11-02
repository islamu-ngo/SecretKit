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
