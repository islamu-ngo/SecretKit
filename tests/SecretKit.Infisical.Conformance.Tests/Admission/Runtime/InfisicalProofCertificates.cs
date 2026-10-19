using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed record ProofCertificatePacket(string Pkcs12Base64, string Password)
{
    public override string ToString() => "[ProofCertificatePacket]";
}

/// <summary>
/// Owns imported ephemeral keys. Callers dispose their handlers and complete calls
/// before disposing the pair. Clearing scratch copies does not erase input JSON strings.
/// </summary>
internal sealed class ProofCertificatePair : IDisposable
{
    private X509Certificate2? _accepted;
    private X509Certificate2? _denied;

    private ProofCertificatePair(X509Certificate2 accepted, X509Certificate2 denied)
    {
        _accepted = accepted;
        _denied = denied;
    }

    internal static ProofCertificatePair Load(ProofCertificatePacket accepted, ProofCertificatePacket denied)
    {
        X509Certificate2? first = null;
        X509Certificate2? second = null;
        try
        {
            first = LoadCertificate(accepted);
            second = LoadCertificate(denied);
            if (first.RawData.AsSpan().SequenceEqual(second.RawData))
                throw new NativeCaseFailureException("missing-input");
            return new(first, second);
        }
        catch
        {
            first?.Dispose();
            second?.Dispose();
            throw;
        }
    }

    private static X509Certificate2 LoadCertificate(ProofCertificatePacket packet)
    {
        byte[]? bytes = null;
        char[]? encoded = null;
        char[]? password = null;
        X509Certificate2? certificate = null;
        try
        {
            if (packet is null || packet.Pkcs12Base64 is null || packet.Password is null ||
                packet.Pkcs12Base64.Length is < 1 or > 90 * 1024 || packet.Password.Length > 1024)
                throw new NativeCaseFailureException("missing-input");
            encoded = packet.Pkcs12Base64.ToCharArray();
            password = packet.Password.ToCharArray();
            bytes = new byte[64 * 1024];
            if (!Convert.TryFromBase64Chars(encoded, bytes, out int length) || length == 0)
                throw new NativeCaseFailureException("missing-input");
            certificate = X509CertificateLoader.LoadPkcs12(bytes.AsSpan(0, length), password.AsSpan(),
                X509KeyStorageFlags.EphemeralKeySet, new Pkcs12LoaderLimits
                {
                    MaxCertificates = 1,
                    MaxKeys = 1,
                    MacIterationLimit = 100_000,
                    IndividualKdfIterationLimit = 100_000,
                    TotalKdfIterationLimit = 300_000
                });
            if (!certificate.HasPrivateKey)
                throw new NativeCaseFailureException("missing-input");
            return certificate;
        }
        catch (Exception error) when (error is CryptographicException or ArgumentException or NativeCaseFailureException)
        {
            certificate?.Dispose();
            throw new NativeCaseFailureException("missing-input");
        }
        finally
        {
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
            if (encoded is not null) Array.Clear(encoded);
            if (password is not null) Array.Clear(password);
        }
    }

    internal SocketsHttpHandler CreateHandler(bool denied)
    {
        ObjectDisposedException.ThrowIf(_accepted is null || _denied is null, this);
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ActivityHeadersPropagator = null,
            SslOptions = new()
            {
                ClientCertificates = new X509CertificateCollection { denied ? _denied : _accepted }
            }
        };
    }

    public void Dispose()
    {
        _accepted?.Dispose();
        _denied?.Dispose();
        _accepted = null;
        _denied = null;
    }
}
