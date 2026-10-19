using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent local provider, issuer, HTTPS publisher and cache. There is no SDK
// implementation behind this server and no cache mutation in the source service.
internal sealed class InfisicalSpiffeRefreshFixture : IAsyncDisposable
{
    internal const string Org = "00000000-0000-0000-0000-000000000001";
    internal const string Identity = "00000000-0000-0000-0000-000000000011";
    internal const string Domain = "refresh.invalid";
    internal const string Subject = "spiffe://refresh.invalid/workload";
    internal const string Audience = "secretkit-refresh";
    internal static readonly DateTimeOffset Clock = new(2026, 10, 14, 0, 0, 0, TimeSpan.Zero);
    internal static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    { IgnoreReadOnlyProperties = false };
    private readonly object gate = new();
    private readonly RSA oldKey = RSA.Create(2048), newKey = RSA.Create(2048), wrongKey = RSA.Create(2048);
    private readonly RSA caKey = RSA.Create(2048), serverKey = RSA.Create(2048);
    private readonly X509Certificate2 ca, server;
    private readonly HttpListener provider = new();
    private readonly TcpListener publisher = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly Task providerLoop, publisherLoop;
    private readonly HttpClient distribution;
    private readonly InfisicalIdentityAuthenticationFamilyTests.Backend backend = new("good");
    private readonly HttpClient management;
    private readonly List<string> cache = [];
    private readonly Dictionary<string, RSA> verifierKeys = new(StringComparer.Ordinal);
    private bool overlap, fenced, armed, closed;
    private int pending;
    private string window = "";
    private string identity = Identity;
    private TaskCompletionSource terminal = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly string mode;
    internal Uri Origin { get; }
    internal Uri BundleOrigin { get; }
    internal string CaPem => ca.ExportCertificatePem();
    internal InfisicalSpiffeRefreshFixtureSource Source { get; }
    internal List<IssuerEntry> Issuer { get; } = [];
    internal List<BundleEntry> Bundles { get; } = [];
    internal List<CacheEntry> Cache { get; } = [];
    internal List<RequestEntry> Requests { get; } = [];
    internal List<string> Terminals { get; } = [];
    internal List<LoginEntry> Logins { get; } = [];
    internal List<string> Tokens { get; } = [];
    internal int ForeignRequests { get; private set; }
    internal bool BorrowedPreserved => true; // provider never writes the selected credentials
    internal bool Fenced { get { lock (gate) return fenced; } }
    internal int Pending { get { lock (gate) return pending; } }
    internal bool OwnedAbsent { get { lock (gate) return closed && cache.Count == 0 && Tokens.Count == 0; } }
    internal int OwnedManagementResources => backend.IdentityCount + backend.ProjectCount;
    internal sealed record IssuerEntry(string Key, string Proof, string Digest);
    internal sealed record BundleEntry(string Window, string Revision);
    internal sealed record CacheEntry(string Window, string Request, string Revision, string[] Keys);
    internal sealed record RequestEntry(string Window, string Id, bool Denied);
    internal sealed record LoginEntry(string Digest, bool Allowed, string? TokenId);

    internal InfisicalSpiffeRefreshFixture(string mode = "good")
    {
        this.mode = mode;
        management = new(new SocketsHttpHandler
        { AllowAutoRedirect = false, UseCookies = false, ActivityHeadersPropagator = null })
        { BaseAddress = backend.Origin, Timeout = Timeout.InfiniteTimeSpan };
        var caRequest = new CertificateRequest("CN=SecretKit refresh root", caKey, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
        var serverRequest = new CertificateRequest("CN=localhost", serverKey, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        san.AddDnsName("localhost");
        serverRequest.CertificateExtensions.Add(san.Build());
        serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        using var issued = serverRequest.Create(ca, DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        server = issued.CopyWithPrivateKey(serverKey);
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false };
        handler.SslOptions.CertificateChainPolicy = new()
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck
        };
        handler.SslOptions.CertificateChainPolicy.CustomTrustStore.Add(ca);
        distribution = new(handler) { Timeout = Timeout.InfiniteTimeSpan };
        publisher.Start();
        BundleOrigin = new($"https://127.0.0.1:{((IPEndPoint)publisher.LocalEndpoint).Port}/bundle");
        var reservation = new TcpListener(IPAddress.Loopback, 0);
        reservation.Start();
        int port = ((IPEndPoint)reservation.LocalEndpoint).Port;
        reservation.Stop();
        Origin = new($"http://127.0.0.1:{port}/");
        provider.Prefixes.Add(Origin.AbsoluteUri);
        provider.Start();
        Source = new(this);
        providerLoop = ProviderLoopAsync();
        publisherLoop = PublisherLoopAsync();
    }

    internal SpiffeRefreshInput Input()
    {
        using var old = Jwt("old");
        using var next = Jwt("new");
        using var wrong = Jwt("wrong-key");
        using var domain = Jwt("wrong-domain");
        using var audience = Jwt("wrong-audience");
        return new(new(new("https://source.invalid/private/"), "channel", "refresh-source", 20),
            "controlled-provider", "exclusive-capability", SpiffeRefreshSourceKind.ControlledFixture,
            "independent-local-functional-contract-1",
            BundleOrigin.AbsoluteUri, CaPem, Domain, Subject, Audience, old.Reveal(), next.Reveal(), wrong.Reveal(),
            domain.Reveal(), audience.Reveal());
    }

    internal SecretMaterial Jwt(string proof)
    {
        RSA key = proof == "new" ? newKey : proof == "wrong-key" ? wrongKey : oldKey;
        string kid = proof == "new" ? "new" : proof == "wrong-key" ? "wrong" : "old";
        string header = Encode(JsonSerializer.SerializeToUtf8Bytes(new { alg = "RS256", typ = "JWT", kid }));
        string payload = Encode(JsonSerializer.SerializeToUtf8Bytes(new
        {
            sub = proof == "wrong-domain" ? "spiffe://foreign.invalid/workload" : Subject,
            aud = new[] { proof == "wrong-audience" ? "foreign-audience" : Audience },
            iat = Clock.ToUnixTimeSeconds(),
            exp = Clock.AddMinutes(15).ToUnixTimeSeconds()
        }));
        byte[] signed = Encoding.ASCII.GetBytes(header + "." + payload);
        byte[] signature = key.SignData(signed, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        try
        {
            using var material = SecretMaterial.FromText(header + "." + payload + "." + Encode(signature));
            string digest = Digest(material.Reveal());
            lock (gate)
                if (!Issuer.Any(e => e.Digest == digest)) Issuer.Add(new(kid, proof, digest));
            return material.Copy();
        }
        finally { CryptographicOperations.ZeroMemory(signed); CryptographicOperations.ZeroMemory(signature); }
    }

    internal void SelectIdentity(string id)
    {
        lock (gate)
        {
            if (armed || identity != Identity && identity != id) throw new InvalidOperationException("fixture-owner");
            identity = id;
        }
    }
    internal void PublishAndArm(string selectedWindow)
    {
        lock (gate)
        {
            if (armed || cache.Count != 1 || cache[0] != "old") throw new InvalidOperationException("fixture-baseline");
            armed = true;
            overlap = true;
            window = selectedWindow;
        }
    }
    internal async ValueTask FenceAsync(CancellationToken token)
    {
        Task? draining;
        lock (gate)
        {
            fenced = true; // excludes all future refresh ingress before inspecting absence
            draining = pending == 0 ? null : terminal.Task;
        }
        if (draining is not null) await draining.WaitAsync(token);
    }
    internal void CloseOwned()
    {
        lock (gate)
        {
            if (!fenced || pending != 0) throw new InvalidOperationException("fixture-not-terminal");
            closed = true;
            cache.Clear();
            foreach (RSA key in verifierKeys.Values) key.Dispose();
            verifierKeys.Clear();
            backend.RetireProofTokens(Tokens);
            Tokens.Clear();
        }
    }
    internal bool HasKey(string key) { lock (gate) return cache.Contains(key); }
    internal LoginEntry InspectProof(string jwt)
    {
        lock (gate) return Logins.Last(l => l.Digest == Digest(jwt));
    }
    internal static string Digest(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') +
        new string('=', (4 - value.Length % 4) % 4));
    private object Jwk(RSA key, string kid)
    {
        RSAParameters p = key.ExportParameters(false);
        return new { kty = "RSA", kid, use = "jwt-svid", alg = "RS256", n = Encode(p.Modulus!), e = Encode(p.Exponent!) };
    }
    private async Task PublisherLoopAsync()
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                using TcpClient peer = await publisher.AcceptTcpClientAsync(stop.Token);
                await using var tls = new SslStream(peer.GetStream(), false);
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = server }, stop.Token);
                byte[] headers = new byte[8192];
                int used = 0;
                try
                {
                    while (used < headers.Length)
                    {
                        int read = await tls.ReadAsync(headers.AsMemory(used, 1), stop.Token);
                        if (read == 0) throw new IOException("publisher-disconnected");
                        used += read;
                        if (used >= 4 && headers.AsSpan(used - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
                    }
                    if (!headers.AsSpan(0, used).StartsWith("GET /bundle HTTP/"u8))
                        throw new IOException("publisher-route");
                    bool selected;
                    lock (gate)
                    {
                        selected = overlap;
                        Bundles.Add(new(window, selected ? "overlap" : "old"));
                    }
                    byte[] body = JsonSerializer.SerializeToUtf8Bytes(new
                    {
                        keys = selected ? new[] { Jwk(oldKey, "old"), Jwk(newKey, "new") } : new[] { Jwk(oldKey, "old") }
                    });
                    byte[] response = Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
                    await tls.WriteAsync(response, stop.Token);
                    await tls.WriteAsync(body, stop.Token);
                    await tls.FlushAsync(stop.Token);
                }
                finally { CryptographicOperations.ZeroMemory(headers); }
            }
        }
        catch (Exception e) when (stop.IsCancellationRequested &&
            e is OperationCanceledException or ObjectDisposedException or SocketException or IOException)
        { }
    }

    private async Task ProviderLoopAsync()
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                HttpListenerContext context = await provider.GetContextAsync().WaitAsync(stop.Token);
                try { await ServeAsync(context, stop.Token); }
                finally { context.Response.Close(); }
            }
        }
        catch (Exception e) when (stop.IsCancellationRequested &&
            e is OperationCanceledException or HttpListenerException or ObjectDisposedException)
        { }
    }
    private async Task ServeAsync(HttpListenerContext context, CancellationToken token)
    {
        var request = context.Request;
        string path = request.Url!.AbsolutePath;
        string auth = request.Headers["Authorization"] ?? "";
        if (path == "/api/v1/auth/spiffe-auth/login")
        {
            using var body = await JsonDocument.ParseAsync(request.InputStream, cancellationToken: token);
            string jwt = body.RootElement.GetProperty("jwt").GetString()!;
            bool accepted = body.RootElement.GetProperty("identityId").GetString() == identity && ValidateJwt(jwt);
            string? issued = null;
            lock (gate)
            {
                if (accepted)
                {
                    issued = backend.IssueProofToken(identity, "spiffe", new JsonObject
                    {
                        ["accessTokenTTL"] = 600,
                        ["accessTokenMaxTTL"] = 1800,
                        ["accessTokenNumUsesLimit"] = 2000
                    })["accessToken"]!.GetValue<string>();
                    Tokens.Add(issued);
                }
                Logins.Add(new(Digest(jwt), accepted, issued));
            }
            await ReplyAsync(context, accepted ? 200 : 403, accepted ? new
            { accessToken = issued!, expiresIn = 600, accessTokenMaxTTL = 1800, tokenType = "Bearer" } : new { }, token);
            return;
        }
        if (path == $"/api/v1/auth/spiffe-auth/identities/{identity}/refresh-bundle" && request.HttpMethod == "POST")
        {
            string id = Guid.NewGuid().ToString("N");
            bool denied = auth == "Bearer denied";
            lock (gate)
            {
                if (!armed || fenced || Requests.Count != 0)
                {
                    ForeignRequests++;
                    context.Response.StatusCode = 403;
                    return;
                }
                pending++;
                Requests.Add(new(window, id, denied));
            }
            try
            {
                if (!denied && mode != "ack-only") await FetchAsync(id, token);
                await ReplyAsync(context, denied ? 403 : 200, denied ? new { } : Configuration(), token);
            }
            finally
            {
                lock (gate)
                {
                    Terminals.Add(id);
                    pending--;
                    terminal.TrySetResult();
                }
            }
            return;
        }
        if (path == $"/api/v1/auth/spiffe-auth/identities/{identity}" && request.HttpMethod is "GET" or "POST")
        {
            if (request.HttpMethod == "POST" || cache.Count == 0) await FetchAsync("baseline", token);
            await ReplyAsync(context, auth == "Bearer denied" ? 403 : 200, Configuration(), token);
            return;
        }
        using var forwarded = new HttpRequestMessage(new HttpMethod(request.HttpMethod), path + request.Url.Query);
        if (auth.Length != 0) forwarded.Headers.TryAddWithoutValidation("Authorization", auth);
        byte[] bytes = [];
        byte[] responseBytes = [];
        try
        {
            if (request.HasEntityBody)
            {
                using var content = new MemoryStream();
                await request.InputStream.CopyToAsync(content, token);
                bytes = content.ToArray();
                forwarded.Content = new ByteArrayContent(bytes);
                forwarded.Content.Headers.TryAddWithoutValidation("Content-Type", request.ContentType);
            }
            using var response = await management.SendAsync(forwarded, token);
            responseBytes = await response.Content.ReadAsByteArrayAsync(token);
            context.Response.StatusCode = (int)response.StatusCode;
            context.Response.ContentType = response.Content.Headers.ContentType?.ToString() ?? "application/json";
            context.Response.ContentLength64 = responseBytes.Length;
            await context.Response.OutputStream.WriteAsync(responseBytes, token);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            CryptographicOperations.ZeroMemory(responseBytes);
        }
    }
    private async Task FetchAsync(string requestId, CancellationToken token)
    {
        using var response = await distribution.GetAsync(BundleOrigin, token);
        response.EnsureSuccessStatusCode();
        using var bundle = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(token));
        string[] keys = bundle.RootElement.GetProperty("keys").EnumerateArray()
            .Select(k => k.GetProperty("kid").GetString()!).ToArray();
        lock (gate)
        {
            cache.Clear();
            foreach (RSA key in verifierKeys.Values) key.Dispose();
            verifierKeys.Clear();
            foreach (JsonElement jwk in bundle.RootElement.GetProperty("keys").EnumerateArray())
            {
                var verifier = RSA.Create();
                verifier.ImportParameters(new()
                {
                    Modulus = Decode(jwk.GetProperty("n").GetString()!),
                    Exponent = Decode(jwk.GetProperty("e").GetString()!)
                });
                verifierKeys.Add(jwk.GetProperty("kid").GetString()!, verifier);
            }
            cache.AddRange(keys);
            if (mode == "wrong-cache" && requestId != "baseline")
            {
                foreach (RSA key in verifierKeys.Values) key.Dispose();
                verifierKeys.Clear();
                cache.Clear();
                cache.Add("wrong");
            }
            Cache.Add(new(window, requestId, overlap ? "overlap" : "old", cache.ToArray()));
        }
    }
    private bool ValidateJwt(string jwt)
    {
        try
        {
            string[] parts = jwt.Split('.');
            if (parts.Length != 3) return false;
            using var header = JsonDocument.Parse(Decode(parts[0]));
            using var claims = JsonDocument.Parse(Decode(parts[1]));
            string kid = header.RootElement.GetProperty("kid").GetString()!;
            lock (gate)
            {
                if (!verifierKeys.TryGetValue(kid, out RSA? key)) return false;
                return header.RootElement.GetProperty("alg").GetString() == "RS256" &&
                claims.RootElement.GetProperty("sub").GetString() == Subject &&
                claims.RootElement.GetProperty("aud").EnumerateArray().Any(a => a.GetString() == Audience) &&
                claims.RootElement.GetProperty("exp").GetInt64() > Clock.ToUnixTimeSeconds() &&
                key.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), Decode(parts[2]),
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
        catch (Exception e) when (e is JsonException or FormatException or KeyNotFoundException) { return false; }
    }
    private object Configuration() => new
    {
        identitySpiffeAuth = new
        {
            id = Identity,
            identityId = identity,
            trustDomain = Domain,
            allowedSpiffeIds = Subject,
            allowedAudiences = Audience,
            createdAt = Clock,
            updatedAt = Clock,
            accessTokenTTL = 600,
            accessTokenMaxTTL = 1800,
            accessTokenNumUsesLimit = 2000,
            trustBundleDistribution = new
            {
                profile = "https_web_bundle",
                endpointUrl = BundleOrigin.AbsoluteUri,
                caCert = CaPem,
                refreshHintSeconds = 3600,
                cachedBundleLastRefreshedAt = Clock
            }
        }
    };
    private static async Task ReplyAsync(HttpListenerContext context, int status, object body, CancellationToken token)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(body);
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";
        context.Response.ContentLength64 = bytes.Length;
        try { await context.Response.OutputStream.WriteAsync(bytes, token); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public async ValueTask DisposeAsync()
    {
        stop.Cancel();
        provider.Stop();
        publisher.Stop();
        try { await Task.WhenAll(providerLoop, publisherLoop); }
        finally
        {
            provider.Close();
            distribution.Dispose();
            management.Dispose();
            await backend.DisposeAsync();
            Source.Dispose();
            ca.Dispose();
            server.Dispose();
            oldKey.Dispose(); newKey.Dispose(); wrongKey.Dispose(); caKey.Dispose(); serverKey.Dispose();
            foreach (RSA key in verifierKeys.Values) key.Dispose();
            stop.Dispose();
        }
    }
}
