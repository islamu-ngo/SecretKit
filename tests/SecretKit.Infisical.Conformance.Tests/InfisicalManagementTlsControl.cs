using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecretKit.Infisical.Conformance.Tests;

// Independently journaled loopback control provider. It consumes SDK requests,
// maintains its own state and authorizes the actual TLS peer, not a proof label.
// Its success characterizes the host; it never qualifies a native source.
internal sealed class InfisicalManagementTlsControl : IAsyncDisposable
{
    private readonly Dictionary<string, JsonObject> configurations = [];
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly List<Task> connections = [];
    private readonly Task accepting;
    private readonly Func<string, JsonObject, JsonObject> issue;
    private readonly string fault;
    private readonly DateTimeOffset now = new(2026, 10, 14, 0, 0, 0, TimeSpan.Zero);
    internal X509Certificate2 Server { get; }
    internal X509Certificate2 Ca { get; }
    internal X509Certificate2 PreviousCa { get; }
    internal X509Certificate2 Accepted { get; }
    internal X509Certificate2 Previous { get; }
    internal X509Certificate2 PreviousSan { get; }
    internal X509Certificate2 OldCaLeaf { get; }
    internal X509Certificate2 Intermediate { get; }
    internal X509Certificate2 Chained { get; }
    internal X509Certificate2 Denied { get; }
    internal Uri Origin { get; }
    internal List<(string Method, string Identity, string Role, JsonObject Input)> Writes { get; } = [];
    internal List<(string Identity, string Leaf, bool Allowed)> Logins { get; } = [];
    internal int Count { get { lock (configurations) return configurations.Count; } }
    internal bool Leaked { get; private set; }

    internal InfisicalManagementTlsControl(Func<string, JsonObject, JsonObject> issue, string fault = "")
    {
        this.issue = issue;
        this.fault = fault;
        Ca = Authority("selected-ca");
        PreviousCa = Authority("previous-ca");
        Accepted = Leaf("selected", Ca);
        Previous = Leaf("previous", Ca, "selected.invalid");
        PreviousSan = Leaf("selected", Ca, "previous.invalid");
        OldCaLeaf = Leaf("selected", PreviousCa);
        using (RSA intermediateKey = RSA.Create(2048))
        {
            var intermediate = new CertificateRequest("CN=intermediate", intermediateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            intermediate.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            intermediate.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            using X509Certificate2 signed = intermediate.Create(Ca, now.AddHours(-12), now.AddHours(12),
                RandomNumberGenerator.GetBytes(16));
            Intermediate = signed.CopyWithPrivateKey(intermediateKey);
        }
        Chained = Leaf("selected", Intermediate);
        using (X509Certificate2 deniedCa = Authority("denied-ca"))
            Denied = Leaf("denied", deniedCa);
        using RSA key = RSA.Create(2048);
        var request = Request("localhost", key, true);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        Server = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
        listener.Start();
        Origin = new($"https://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        accepting = AcceptAsync();
    }

    internal bool Contains(string identity) { lock (configurations) return configurations.ContainsKey(identity); }
    internal void DeleteOwner(string identity) { lock (configurations) configurations.Remove(identity); }

    internal (int, JsonNode) Configuration(string method, string identity, JsonObject body, string role)
    {
        lock (configurations)
        {
            if (role == "denied") return (403, new JsonObject());
            if (method == "POST")
            {
                if (body["caCertificate"] is null) return (400, new JsonObject());
                configurations.Add(identity, new JsonObject
                {
                    ["id"] = Guid.NewGuid().ToString(),
                    ["identityId"] = identity,
                    ["createdAt"] = now.ToString("O"),
                    ["updatedAt"] = now.ToString("O"),
                    ["accessTokenTTL"] = 300,
                    ["accessTokenMaxTTL"] = 1200,
                    ["accessTokenNumUsesLimit"] = 1000,
                    ["allowedCommonNames"] = null,
                    ["allowedSubjectAltNames"] = null,
                    ["verifyClientCertificateChain"] = false,
                    ["encryptedCaCertificate"] = new JsonObject { ["opaque"] = "control-ciphertext" }
                });
            }
            if (!configurations.TryGetValue(identity, out JsonObject? state)) return (404, new JsonObject());
            if (method is "POST" or "PATCH")
            {
                Writes.Add((method, identity, role, body.DeepClone().AsObject()));
                foreach (var field in body)
                    if (!(method == "PATCH" && fault == "ignore-" + field.Key))
                        state[field.Key] = field.Value?.DeepClone();
            }
            var response = state.DeepClone().AsObject();
            // The native mutation contract is write-only for CA. Never echo
            // cleartext into Attach/Update/Delete and pretend it was read back.
            if (method != "GET") response.Remove("caCertificate");
            if (method == "GET" && fault == "ca-readback") response["caCertificate"] = PreviousCa.ExportCertificatePem();
            if (method == "DELETE") configurations.Remove(identity);
            return (200, new JsonObject { ["identityTlsCertAuth"] = response });
        }
    }

    private async Task AcceptAsync()
    {
        try
        {
            while (true)
            {
                TcpClient client = await listener.AcceptTcpClientAsync(shutdown.Token);
                connections.Add(ServeAsync(client));
            }
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
    }

    private async Task ServeAsync(TcpClient client)
    {
        using (client)
        using (var tls = new SslStream(client.GetStream(), false))
        {
            var presented = new X509Certificate2Collection();
            try
            {
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = Server,
                    ClientCertificateRequired = true,
                    AllowTlsResume = false,
                    EnabledSslProtocols = SslProtocols.Tls12,
                    // Isolated control listener admits all three exact leaves at
                    // transport, then independently checks application policy.
                    RemoteCertificateValidationCallback = (_, certificate, chain, _) =>
                    {
                        if (chain is not null)
                            foreach (X509ChainElement element in chain.ChainElements)
                                presented.Add(X509CertificateLoader.LoadCertificate(element.Certificate.RawData));
                        return certificate is not null && new[] { Accepted, Previous, PreviousSan, OldCaLeaf, Chained, Denied }
                            .Any(c => c.RawData.AsSpan().SequenceEqual(certificate.GetRawCertData()));
                    }
                }, shutdown.Token);
                using var peer = X509CertificateLoader.LoadCertificate(tls.RemoteCertificate!.GetRawCertData());
                using var reader = new StreamReader(tls, Encoding.UTF8, leaveOpen: true);
                string route = (await reader.ReadLineAsync(shutdown.Token))!;
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                string? line;
                while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(shutdown.Token)))
                {
                    int split = line.IndexOf(':');
                    headers.Add(line[..split], line[(split + 1)..].Trim());
                }
                int length = int.Parse(headers["Content-Length"], System.Globalization.CultureInfo.InvariantCulture);
                if (length is < 1 or > 2048) throw new InvalidOperationException("Invalid control body.");
                char[] chars = new char[length];
                JsonObject body;
                try
                {
                    await reader.ReadBlockAsync(chars, shutdown.Token);
                    body = JsonNode.Parse(new string(chars))!.AsObject();
                }
                finally { Array.Clear(chars); }
                Leaked |= route != "POST /api/v1/auth/tls-cert-auth/login HTTP/1.1" ||
                    body.Any(p => p.Key is not ("identityId" or "organizationSlug")) ||
                    headers.Keys.Any(h => h.Contains("cert", StringComparison.OrdinalIgnoreCase) ||
                        h.Contains("proof", StringComparison.OrdinalIgnoreCase) ||
                        new[] { "Authorization", "Cookie", "traceparent", "tracestate" }
                            .Contains(h, StringComparer.OrdinalIgnoreCase));
                string identity = body["identityId"]!.GetValue<string>();
                JsonObject? policy;
                lock (configurations) policy = configurations.GetValueOrDefault(identity)?.DeepClone().AsObject();
                bool allowed = policy is not null && Accepts(peer, policy, presented) && fault != "deny-valid";
                if (fault == "accept-denied" && policy is not null) allowed = true;
                lock (configurations) Logins.Add((identity, peer.GetCertHashString(HashAlgorithmName.SHA256), allowed));
                JsonObject response = allowed ? issue(identity, policy!) : new JsonObject();
                byte[] bytes = Encoding.UTF8.GetBytes(response.ToJsonString());
                try
                {
                    byte[] head = Encoding.ASCII.GetBytes($"HTTP/1.1 {(allowed ? 200 : 403)} Control\r\nContent-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n");
                    await tls.WriteAsync(head, shutdown.Token);
                    await tls.WriteAsync(bytes, shutdown.Token);
                }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            catch (Exception error) when (error is OperationCanceledException or IOException or AuthenticationException)
            { if (!shutdown.IsCancellationRequested) throw; }
            finally { foreach (X509Certificate2 certificate in presented) certificate.Dispose(); }
        }
    }

    private bool Accepts(X509Certificate2 peer, JsonObject policy, X509Certificate2Collection presented)
    {
        using X509Certificate2 authority = X509Certificate2.CreateFromPem(policy["caCertificate"]!.GetValue<string>());
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(authority);
        chain.ChainPolicy.ExtraStore.AddRange(presented);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = now.UtcDateTime;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        bool issued = chain.Build(peer);
        string commonName = peer.GetNameInfo(X509NameType.SimpleName, false);
        string dns = peer.GetNameInfo(X509NameType.DnsName, false);
        string? commonNames = policy["allowedCommonNames"]?.GetValue<string>();
        JsonArray? sans = policy["allowedSubjectAltNames"]?.AsArray();
        return issued && (policy["verifyClientCertificateChain"]!.GetValue<bool>() ||
                peer.IssuerName.RawData.AsSpan().SequenceEqual(authority.SubjectName.RawData)) &&
            (commonNames is null || commonNames.Split(',').Contains(commonName, StringComparer.Ordinal)) &&
            (sans is null || sans.Count == 0 || sans.Any(n => n!.GetValue<string>() == "DNS:" + dns));
    }

    private X509Certificate2 Authority(string name)
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
    }

    private X509Certificate2 Leaf(string name, X509Certificate2 authority, string? dns = null)
    {
        using RSA key = RSA.Create(2048);
        var request = Request(name, key, false);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(dns ?? name + ".invalid");
        request.CertificateExtensions.Add(names.Build());
        DateTimeOffset start = fault == "future-peer" && name == "selected" ? now.AddHours(1) : now.AddHours(-1);
        DateTimeOffset end = fault == "expired-peer" && name == "selected" ? now.AddMinutes(-1) : now.AddHours(2);
        using X509Certificate2 certificate = request.Create(authority, start, end,
            RandomNumberGenerator.GetBytes(16));
        return certificate.CopyWithPrivateKey(key);
    }

    private static CertificateRequest Request(string name, RSA key, bool server)
    {
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new(server ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") }, true));
        return request;
    }

    internal static JsonObject Packet(X509Certificate2 certificate)
    {
        byte[] bytes = certificate.Export(X509ContentType.Pkcs12, "control-password");
        try { return new() { ["pkcs12Base64"] = Convert.ToBase64String(bytes), ["password"] = "control-password" }; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public async ValueTask DisposeAsync()
    {
        shutdown.Cancel();
        listener.Stop();
        await accepting;
        await Task.WhenAll(connections);
        shutdown.Dispose();
        Server.Dispose();
        Accepted.Dispose();
        Previous.Dispose();
        PreviousSan.Dispose();
        OldCaLeaf.Dispose();
        Chained.Dispose();
        Intermediate.Dispose();
        Denied.Dispose();
        Ca.Dispose();
        PreviousCa.Dispose();
    }
}
