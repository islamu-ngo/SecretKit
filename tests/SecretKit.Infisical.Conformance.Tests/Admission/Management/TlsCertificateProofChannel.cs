using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Closed host-owned TLS transport adapter. Its factory is injected only by a
// controlled host; ordinary registration never changes native server trust.
internal sealed class TlsCertificateProofChannel : IDisposable
{
    private readonly Uri origin;
    private readonly SocketsHttpHandler handler;

    internal TlsCertificateProofChannel(Uri origin, SocketsHttpHandler handler)
    {
        if (origin.Scheme != Uri.UriSchemeHttps)
            throw new NativeCaseFailureException("missing-input");
        this.origin = origin;
        this.handler = handler;
    }

    internal InfisicalProofAuthentication CreateAuthentication() => new(origin, handler);
    public void Dispose()
    {
        // Calls and their SDK wrapper have settled before this lease ends.
        handler.SslOptions.ClientCertificateContext = null;
        handler.Dispose();
    }
    public override string ToString() => "[TlsCertificateProofChannel]";
}

// Imported ephemeral private keys live across a complete configuration trial,
// never in management, runtime token, cleanup, or observer transports.
// ProofCertificatePair clears loader scratch and owns the imported keys. Each
// authentication call is awaited/disposed before its channel handler; both
// imported pairs are released after owner cleanup even when a probe fails.
// Original caller JSON/PFX/password strings and TLS/framework/socket copies
// cannot be promised erased. Input packets are borrowed, never disposed or
// mutated; no root/store registration, key persistence, or hidden worker occurs.
// .NET10 Create lifetime/chain facts (Tavily, 2026-10-14):
// https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslstreamcertificatecontext.create?view=net-10.0
internal sealed class ManagementTlsCertificates : IDisposable
{
    private readonly ProofCertificatePair selected;
    private readonly ProofCertificatePair? previous;
    private readonly X509Certificate2Collection selectedChain = [];
    private readonly X509Certificate2Collection previousChain = [];
    private readonly X509Certificate2Collection deniedChain = [];

    internal ManagementTlsCertificates(JsonElement issuer, bool contrast)
    {
        selected = ProofCertificatePair.Load(Packet(issuer, "allowed"), Packet(issuer, "denied"));
        try
        {
            LoadChain(issuer.GetProperty("allowed"), selectedChain);
            LoadChain(issuer.GetProperty("denied"), deniedChain);
            if (contrast)
            {
                previous = ProofCertificatePair.Load(Packet(issuer, "baselineAllowed"), Packet(issuer, "denied"));
                LoadChain(issuer.GetProperty("baselineAllowed"), previousChain);
            }
        }
        catch { Dispose(); throw; }
    }

    private static void LoadChain(JsonElement proof, X509Certificate2Collection certificates)
    {
        if (!proof.TryGetProperty("intermediatesPem", out JsonElement chain)) return;
        if (chain.ValueKind != JsonValueKind.Array || chain.GetArrayLength() is < 1 or > 8)
            throw new NativeCaseFailureException("missing-input");
        try
        {
            foreach (JsonElement encoded in chain.EnumerateArray())
            {
                if (encoded.ValueKind != JsonValueKind.String || encoded.GetString()!.Length is < 1 or > 10240)
                    throw new NativeCaseFailureException("missing-input");
                certificates.Add(X509Certificate2.CreateFromPem(encoded.GetString()!));
            }
        }
        catch (CryptographicException) { throw new NativeCaseFailureException("missing-input"); }
    }

    private static ProofCertificatePacket Packet(JsonElement issuer, string name)
    {
        JsonElement proof = issuer.GetProperty(name);
        if (proof.ValueKind != JsonValueKind.Object ||
            proof.EnumerateObject().Any(p => p.Name is not ("certificate" or "organizationSlug" or "intermediatesPem")) ||
            !proof.TryGetProperty("certificate", out JsonElement packet) || packet.ValueKind != JsonValueKind.Object ||
            packet.EnumerateObject().Count() != 2 ||
            packet.EnumerateObject().Any(p => p.Name is not ("pkcs12Base64" or "password")) ||
            packet.GetProperty("pkcs12Base64").ValueKind != JsonValueKind.String ||
            packet.GetProperty("password").ValueKind != JsonValueKind.String)
            throw new NativeCaseFailureException("missing-input");
        return new(packet.GetProperty("pkcs12Base64").GetString()!, packet.GetProperty("password").GetString()!);
    }

    internal TlsCertificateProofChannel Open(Uri origin, bool denied, bool baseline,
        Func<Uri, SocketsHttpHandler, TlsCertificateProofChannel>? factory)
    {
        SocketsHttpHandler handler = (baseline ? previous ?? selected : selected).CreateHandler(denied);
        try
        {
            X509Certificate2Collection chain = denied ? deniedChain : baseline ? previousChain : selectedChain;
            if (chain.Count != 0)
                handler.SslOptions.ClientCertificateContext = SslStreamCertificateContext.Create(
                    (X509Certificate2)handler.SslOptions.ClientCertificates![0], chain, offline: true);
            return factory is null ? new(origin, handler) : factory(origin, handler);
        }
        catch
        {
            handler.SslOptions.ClientCertificateContext = null;
            handler.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        previous?.Dispose();
        selected.Dispose();
        foreach (X509Certificate2 certificate in previousChain) certificate.Dispose();
        foreach (X509Certificate2 certificate in selectedChain) certificate.Dispose();
        foreach (X509Certificate2 certificate in deniedChain) certificate.Dispose();
    }
    public override string ToString() => "[ManagementTlsCertificates]";
}
