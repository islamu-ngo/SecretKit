using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent controlled issuer. The native login, storage mutation, capture and
// response delivery are different events; closing a response never undoes issuance.
internal sealed class InfisicalAuthenticationIssuanceServer : IAsyncDisposable
{
    internal const string Identity = "a1111111-1111-4111-8111-111111111111";
    internal const string Organization = "b1111111-1111-4111-8111-111111111111";
    internal const string Metadata = "c1111111-1111-4111-8111-111111111111";
    internal const string Name = "sk-auth-a1111111111141118111111111111111";
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accepting;
    private readonly TcpListener? tlsListener;
    private readonly Task? acceptingTls;
    private readonly X509Certificate2? serverCertificate;
    private readonly X509Certificate2? allowedCertificate;
    private readonly X509Certificate2? deniedCertificate;
    private readonly TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource delivered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object state = new();
    private bool fenced;
    internal TaskCompletionSource Received { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource TransportArrived { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Uri Origin { get; }
    internal Uri ControlOrigin { get; }
    internal ConcurrentQueue<string> PeerCertificates { get; } = [];
    internal string AllowedCertificateHash => allowedCertificate!.GetCertHashString(HashAlgorithmName.SHA256);
    internal string DeniedCertificateHash => deniedCertificate!.GetCertHashString(HashAlgorithmName.SHA256);
    internal bool Exists { get; set; } = true;
    internal bool Applied { get; private set; }
    internal bool Apply { get; set; } = true;
    internal bool HoldResponse { get; set; } = true;
    internal bool HoldHeaders { get; set; }
    internal bool BlockIngress { get; set; }
    internal int MaximumTtl { get; set; } = 1200;
    internal bool Revoked { get; set; }
    internal int Logins { get; private set; }
    internal string Credential { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    internal string RequestId { get; private set; } = "";
    internal string Method { get; private set; } = "";
    internal string SelectedIdentity { get; private set; } = "";
    internal Action? Issued { get; set; }
    internal ConcurrentQueue<(string Request, string Credential, string Key, bool Allowed)> Reads { get; } = [];

    internal InfisicalAuthenticationIssuanceServer(bool tls = false)
    {
        listener.Start();
        ControlOrigin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Origin = ControlOrigin;
        accepting = AcceptAsync(listener, false);
        if (tls)
        {
            serverCertificate = Certificate("localhost", true);
            allowedCertificate = Certificate("allowed", false);
            deniedCertificate = Certificate("denied", false);
            tlsListener = new(IPAddress.Loopback, 0);
            tlsListener.Start();
            Origin = new($"https://127.0.0.1:{((IPEndPoint)tlsListener.LocalEndpoint).Port}/");
            acceptingTls = AcceptAsync(tlsListener, true);
        }
    }

    private static X509Certificate2 Certificate(string name, bool server)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new(server ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2")], true));
        if (server)
        {
            var names = new SubjectAlternativeNameBuilder(); names.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(names.Build());
        }
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
    internal ProofCertificatePacket Packet(bool denied)
    {
        byte[] bytes = (denied ? deniedCertificate! : allowedCertificate!).Export(X509ContentType.Pkcs12, "owned-fixture");
        try { return new(Convert.ToBase64String(bytes), "owned-fixture"); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal void TrustServer(SocketsHttpHandler handler) =>
        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
            certificate is not null && certificate.GetCertHashString(HashAlgorithmName.SHA256) ==
                serverCertificate!.GetCertHashString(HashAlgorithmName.SHA256);

    private async Task AcceptAsync(TcpListener selected, bool tls)
    {
        try
        {
            while (true) connections.Add(ServeAsync(await selected.AcceptTcpClientAsync(shutdown.Token), tls));
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
    }

    private async Task ServeAsync(TcpClient socket, bool tls)
    {
        using (socket)
        {
            byte[] header = new byte[32768], one = new byte[1], body = [], payload = [];
            bool login = false;
            try
            {
                using var encrypted = tls ? new SslStream(socket.GetStream(), false, (_, certificate, _, _) =>
                    certificate is not null && (certificate.GetCertHashString(HashAlgorithmName.SHA256) == AllowedCertificateHash ||
                        certificate.GetCertHashString(HashAlgorithmName.SHA256) == DeniedCertificateHash)) : null;
                if (encrypted is not null)
                    await encrypted.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = serverCertificate,
                        ClientCertificateRequired = true,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                    }, shutdown.Token);
                Stream stream = encrypted is null ? socket.GetStream() : encrypted;
                int count = 0;
                while (count < header.Length)
                {
                    if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                    header[count++] = one[0];
                    if (count >= 4 && header.AsSpan(count - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
                }
                if (count == header.Length) throw new InvalidOperationException("fixture-header-budget");
                string[] lines = Encoding.ASCII.GetString(header, 0, count).Split("\r\n");
                string[] first = lines[0].Split(' ');
                string authorization = lines.FirstOrDefault(l => l.StartsWith("Authorization:",
                    StringComparison.OrdinalIgnoreCase))?.Split(' ').Last() ?? "";
                int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:",
                    StringComparison.OrdinalIgnoreCase))?.Split(':')[1] ?? "0");
                if (length is < 0 or > 131072) throw new InvalidOperationException("fixture-body-budget");
                body = new byte[length];
                await stream.ReadExactlyAsync(body, shutdown.Token);
                using var json = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                string path = new Uri(Origin, first[1]).AbsolutePath;
                login = path.EndsWith("/login", StringComparison.Ordinal);
                if (login)
                {
                    if (encrypted?.RemoteCertificate is { } peer)
                        PeerCertificates.Enqueue(peer.GetCertHashString(HashAlgorithmName.SHA256));
                    TransportArrived.TrySetResult();
                    if (BlockIngress) await release.Task.WaitAsync(shutdown.Token);
                }
                var response = Handle(first[0], path, authorization, json.RootElement,
                    encrypted?.RemoteCertificate?.GetCertHashString(HashAlgorithmName.SHA256));
                payload = JsonSerializer.SerializeToUtf8Bytes(response.Body);
                if (login && HoldHeaders)
                {
                    await release.Task.WaitAsync(shutdown.Token);
                    return; // Independent original response loss, before headers.
                }
                byte[] responseHeader = Encoding.ASCII.GetBytes($"HTTP/1.1 {response.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {payload.Length}\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(responseHeader, shutdown.Token);
                if (login && HoldResponse) await release.Task.WaitAsync(shutdown.Token);
                else await stream.WriteAsync(payload, shutdown.Token);
            }
            catch (IOException) { }
            catch (AuthenticationException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            finally
            {
                CryptographicOperations.ZeroMemory(header);
                CryptographicOperations.ZeroMemory(body);
                CryptographicOperations.ZeroMemory(payload);
                if (login) delivered.TrySetResult();
            }
        }
    }

    private (int Status, object Body) Handle(string verb, string path, string credential, JsonElement body, string? peer)
    {
        if (path == "/api/v1/identities/" + Identity)
        {
            if (!Exists) return (404, new { });
            var identity = new
            {
                id = Identity,
                orgId = Organization,
                name = Name,
                hasDeleteProtection = false,
                createdAt = "2026-10-14T00:00:00Z",
                updatedAt = "2026-10-14T00:00:00Z"
            };
            if (verb == "DELETE")
            {
                if (credential != "administrative") return (403, new { });
                Exists = false; Revoked = true;
                return (200, new { identity });
            }
            return (200, new
            {
                identity = new
                {
                    id = Metadata,
                    orgId = Organization,
                    identityId = Identity,
                    role = "member",
                    createdAt = "2026-10-14T00:00:00Z",
                    updatedAt = "2026-10-14T00:00:00Z",
                    identity = new
                    {
                        id = Identity,
                        orgId = Organization,
                        name = Name,
                        hasDeleteProtection = false,
                        authMethods = Array.Empty<string>(),
                        activeLockoutAuthMethods = Array.Empty<string>()
                    }
                }
            });
        }
        if (path == "/api/v1/auth/token-auth/identities/" + Identity + "/tokens")
            return (200, new
            {
                tokens = Applied && Exists ? new[] { new { id = Metadata, identityId = SelectedIdentity,
                authMethod = Method, accessTokenTTL = 600, accessTokenMaxTTL = MaximumTtl, accessTokenPeriod = 0,
                accessTokenNumUses = 0, accessTokenNumUsesLimit = 0, isAccessTokenRevoked = Revoked,
                createdAt = "2026-10-14T00:00:00Z", updatedAt = "2026-10-14T00:00:00Z" } } : []
            });
        if (path.EndsWith("/login", StringComparison.Ordinal))
        {
            lock (state)
            {
                Logins++;
                if (fenced) return (403, new { });
                RequestId = Guid.NewGuid().ToString("N");
                Method = path.Split('/')[4];
                SelectedIdentity = body.TryGetProperty("identityId", out var selected) ? selected.GetString()! : Identity;
                Applied = Apply && Exists && !body.GetRawText().Contains("denied-proof", StringComparison.Ordinal) &&
                    (Method != "tls-cert-auth" || peer == AllowedCertificateHash);
                if (Applied) Issued?.Invoke();
                Received.TrySetResult();
                return Applied ? (200, new
                {
                    accessToken = Credential,
                    tokenType = "Bearer",
                    expiresIn = 600,
                    accessTokenMaxTTL = MaximumTtl
                }) : (403, new { });
            }
        }
        if (path.StartsWith("/api/v4/secrets/", StringComparison.Ordinal))
        {
            string key = path.Split('/').Last();
            bool allowed = credential is "observer" or "setup" or "runtime" ||
                credential == Credential && Applied && !Revoked && key == "ALLOWED";
            Reads.Enqueue((Guid.NewGuid().ToString("N"), credential, key, allowed));
            return allowed ? (200, new
            {
                secret = new
                {
                    secretKey = key,
                    version = 1,
                    secretValueHidden = false,
                    secretValue = "owned-material"
                }
            }) : (403, new { });
        }
        return (404, new { });
    }

    internal async ValueTask DrainAsync(CancellationToken token)
    {
        release.TrySetResult();
        if (TransportArrived.Task.IsCompleted) await delivered.Task.WaitAsync(token);
    }

    internal void FenceIssuance()
    {
        lock (state) fenced = true;
    }

    public async ValueTask DisposeAsync()
    {
        release.TrySetResult();
        await shutdown.CancelAsync();
        await accepting;
        if (acceptingTls is not null) await acceptingTls;
        listener.Stop();
        tlsListener?.Stop();
        await Task.WhenAll(connections);
        deniedCertificate?.Dispose(); allowedCertificate?.Dispose(); serverCertificate?.Dispose();
        shutdown.Dispose();
    }
}
