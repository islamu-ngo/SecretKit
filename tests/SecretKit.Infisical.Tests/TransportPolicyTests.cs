using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class TransportPolicyTests
{
    private static readonly TimeSpan Watchdog = TimeSpan.FromSeconds(15);
    private const string LoginResponse =
        """{"accessToken":"issued-loopback-token","tokenType":"Bearer","expiresIn":120,"accessTokenMaxTTL":0}""";

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SafeAuthenticationRejectsPermissiveCertificateCallbackBeforeCredentialExchange(bool wrongHostname)
    {
        using var certificates = new TestCertificates(wrongHostname);
        await using var backend = new LoopbackServer(certificates.Server);
        string canary = "bootstrap-" + Guid.NewGuid().ToString("N");
        using var secret = SecretMaterial.FromText(canary);
        using var deadline = new CancellationTokenSource(Watchdog);
        SecretStatus status = SecretStatus.Invalid;

        // The former supplied-safe seam leaked this canary in the RED run.
        // SafeDefault no longer admits an externally controlled handler.
        try
        {
            using var authentication = new InfisicalUniversalAuthentication(backend.Origin);
            var result = await authentication.LoginAsync("loopback-client", secret,
                authentication.CreateReceipt(), cancellationToken: deadline.Token);
            status = result.Status;
            if (result.IsSuccess) result.Value.Dispose();
        }
        catch (ArgumentException)
        {
            // Rejecting the unsafe selection at construction is also safe.
        }

        await backend.StopAsync();
        // Assert the independent backend observation first: no result-mapping
        // change can conceal a credential-bearing exchange.
        await Assert.That(backend.Requests.Any(request => request.Body.Contains(canary, StringComparison.Ordinal)))
            .IsFalse();
        await Assert.That(status == SecretStatus.Success).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ExplicitHostControlledAuthenticationAcceptsDeliberateTlsPolicy(bool wrongHostname)
    {
        using var certificates = new TestCertificates(wrongHostname);
        await using var backend = new LoopbackServer(certificates.Server);
        using var handler = NewHandler();
        handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        using var authentication = new InfisicalUniversalAuthentication(backend.Origin,
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(handler) });
        using var secret = SecretMaterial.FromText("explicit-host-bootstrap");
        using var deadline = new CancellationTokenSource(Watchdog);
        var result = await authentication.LoginAsync("loopback-client", secret,
            authentication.CreateReceipt(), cancellationToken: deadline.Token);
        if (result.IsSuccess) result.Value.Dispose();
        await backend.StopAsync();
        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(backend.Requests.Single().Body.Contains("explicit-host-bootstrap", StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    [Arguments("read", false, false)]
    [Arguments("read", true, false)]
    [Arguments("read", true, true)]
    [Arguments("proof", false, false)]
    [Arguments("proof", true, false)]
    [Arguments("proof", true, true)]
    [Arguments("renewal", false, false)]
    [Arguments("renewal", true, false)]
    [Arguments("renewal", true, true)]
    [Arguments("dynamic", false, false)]
    [Arguments("dynamic", true, false)]
    [Arguments("dynamic", true, true)]
    [Arguments("rotation", false, false)]
    [Arguments("rotation", true, false)]
    [Arguments("rotation", true, true)]
    public async Task NativeEntrypointsEnforceIssuerAndHostnameBeforeCredentialExchange(
        string entrypoint, bool trustRoot, bool wrongHostname)
    {
        using var certificates = new TestCertificates(wrongHostname);
        await using var backend = new LoopbackServer(certificates.Server);
        var network = new InfisicalNetworkOptions
        {
            Transport = trustRoot
                ? InfisicalTransportOptions.SafeWithPrivateTrust(certificates.Root)
                : InfisicalTransportOptions.SafeDefault
        };
        using var deadline = new CancellationTokenSource(Watchdog);
        const string canary = "native-transport-credential";
        var tokens = new FixedTokens(canary);
        switch (entrypoint)
        {
            case "read":
                await using (var client = new InfisicalClient(backend.Origin, tokens, network))
                {
                    var result = await client.ReadAsync(new(client.Authority,
                        new InfisicalSecretAddress("project", "environment", "/", "key")), deadline.Token);
                    if (result.IsSuccess) result.Value.Dispose();
                }
                break;
            case "proof":
                using (var proof = InfisicalLoginProof.TlsCertificate("identity"))
                using (var client = new InfisicalProofAuthentication(backend.Origin, network))
                {
                    var result = await client.LoginAsync(proof, client.CreateReceipt(), deadline.Token);
                    if (result.IsSuccess) result.Value.Dispose();
                }
                break;
            case "renewal":
                using (var material = SecretMaterial.FromText(canary))
                {
                    DateTimeOffset issued = DateTimeOffset.UtcNow;
                    await using var session = new InfisicalPeriodicTokenSession(backend.Origin, material,
                        new()
                        {
                            OriginalIssuedAt = issued,
                            ExpiresAt = issued.AddMinutes(2),
                            Lifetime = InfisicalTokenLifetime.Finite,
                            ReportedMaximumTtl = TimeSpan.FromMinutes(5)
                        }, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5), network);
                    await session.RenewAsync(deadline.Token);
                }
                break;
            case "dynamic":
                await using (var client = new InfisicalDynamicClient(backend.Origin, tokens,
                    new("project", "environment", "/", Guid.NewGuid()), network))
                    await client.ListDefinitionsAsync(deadline.Token);
                break;
            case "rotation":
                var authority = new SecretAuthority();
                using (var client = new InfisicalRotationClient(backend.Origin, authority,
                    new(authority, tokens, "project"), network))
                    await client.ListAsync(new(authority, new InfisicalRotationScope("project")),
                        cancellationToken: deadline.Token);
                break;
        }
        await backend.StopAsync();
        await Assert.That(backend.HandshakeAttempts > 0).IsTrue();
        await Assert.That(backend.Requests.IsEmpty).IsEqualTo(!trustRoot || wrongHostname);
        if (trustRoot && !wrongHostname)
        {
            CapturedRequest request = backend.Requests.Single();
            if (entrypoint is "read" or "dynamic" or "rotation")
                await Assert.That(request.Authorization).IsEqualTo("Bearer " + canary);
            else if (entrypoint == "renewal")
                await Assert.That(request.Body.Contains(canary, StringComparison.Ordinal)).IsTrue();
            else
                await Assert.That(request.Body.Contains("identity", StringComparison.Ordinal)).IsTrue();
        }
    }

    [Test]
    public async Task BorrowedClientSettingsAndLifetimeSurviveAuthentication()
    {
        await using var backend = new LoopbackServer();
        using var handler = NewHandler();
        using var host = new HttpClient(handler, disposeHandler: false)
        {
            BaseAddress = new Uri("https://unselected.invalid/base/"),
            Timeout = TimeSpan.FromSeconds(7)
        };
        host.DefaultRequestHeaders.Add("X-Host-Policy", "retained");
        using var secret = SecretMaterial.FromText("borrowed-bootstrap");
        using var deadline = new CancellationTokenSource(Watchdog);
        using (var client = new InfisicalUniversalAuthentication(backend.Origin,
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(host) }))
        {
            using var login = (await client.LoginAsync("client", secret, client.CreateReceipt(),
                cancellationToken: deadline.Token)).Value;
        }
        await Assert.That(host.BaseAddress!.AbsoluteUri).IsEqualTo("https://unselected.invalid/base/");
        await Assert.That(host.Timeout).IsEqualTo(TimeSpan.FromSeconds(7));
        await Assert.That(host.DefaultRequestHeaders.GetValues("X-Host-Policy").Single()).IsEqualTo("retained");
        using HttpResponseMessage response = await host.GetAsync(backend.Origin, deadline.Token);
        await backend.StopAsync();
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(backend.Requests.Count).IsEqualTo(2);
        await Assert.That(backend.Requests.First().StartLine)
            .IsEqualTo("POST /api/v1/auth/universal-auth/login HTTP/1.1");
    }

    private sealed class FixedTokens(string value) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText(value))));
        }
    }

    [Test]
    public async Task SafeModeIgnoresAmbientProxyInIsolatedProcess()
    {
        using var deadline = new CancellationTokenSource(Watchdog);
        if (Environment.GetEnvironmentVariable("SECRETKIT_PROXY_PROBE") == "1")
        {
            var origin = new Uri(Environment.GetEnvironmentVariable("SECRETKIT_PROXY_TARGET")!);
            // Positive control: the process's standard HttpClient really uses
            // the selected ambient proxy before the SDK-owned exchange.
            using var ordinary = new HttpClient();
            using HttpResponseMessage control = await ordinary.GetAsync(origin, deadline.Token);
            await Assert.That(control.StatusCode).IsEqualTo(HttpStatusCode.OK);
            using var authentication = new InfisicalUniversalAuthentication(origin,
                new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
            using var secret = SecretMaterial.FromText("ambient-proxy-canary");
            using var login = (await authentication.LoginAsync("client", secret,
                authentication.CreateReceipt(), cancellationToken: deadline.Token)).Value;
            return;
        }

        await using var proxy = new LoopbackServer();
        await using var target = new LoopbackServer();
        var start = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        start.ArgumentList.Add(typeof(TransportPolicyTests).Assembly.Location);
        start.ArgumentList.Add("--treenode-filter");
        start.ArgumentList.Add("/*/*/TransportPolicyTests/SafeModeIgnoresAmbientProxyInIsolatedProcess");
        start.ArgumentList.Add("--minimum-expected-tests");
        start.ArgumentList.Add("1");
        start.ArgumentList.Add("--zero-tests-policy");
        start.ArgumentList.Add("strict");
        start.Environment["SECRETKIT_PROXY_PROBE"] = "1";
        start.Environment["SECRETKIT_PROXY_TARGET"] = target.Origin.AbsoluteUri;
        foreach (string name in new[] { "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY" })
            start.Environment[name] = proxy.Origin.AbsoluteUri;
        start.Environment["NO_PROXY"] = "";
        start.Environment["no_proxy"] = "";
        using var child = Process.Start(start)!;
        Task<string> stdout = child.StandardOutput.ReadToEndAsync(deadline.Token);
        Task<string> stderr = child.StandardError.ReadToEndAsync(deadline.Token);
        try
        {
            await child.WaitForExitAsync(deadline.Token);
            await Task.WhenAll(stdout, stderr);
            await Assert.That(child.ExitCode).IsEqualTo(0);
            await proxy.StopAsync();
            await target.StopAsync();
            string controlRequest = $"GET {target.Origin.AbsoluteUri} HTTP/1.1";
            // The test runner can make unrelated HTTP requests. Correlate the
            // positive control to its exact destination rather than its traffic.
            await Assert.That(proxy.Requests.Count(request => request.StartLine == controlRequest)).IsEqualTo(1);
            await Assert.That(proxy.Requests.Any(request =>
                request.Body.Contains("ambient-proxy-canary", StringComparison.Ordinal))).IsFalse();
            await Assert.That(target.Requests.Single().Body.Contains("ambient-proxy-canary", StringComparison.Ordinal)).IsTrue();
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill(entireProcessTree: true);
                await child.WaitForExitAsync(CancellationToken.None);
            }
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DefaultAuthenticationDoesNotExchangeCredentialsWithInvalidCertificate(bool wrongHostname)
    {
        using var certificates = new TestCertificates(wrongHostname);
        await using var backend = new LoopbackServer(certificates.Server);
        using var authentication = new InfisicalUniversalAuthentication(backend.Origin);
        using var secret = SecretMaterial.FromText("untrusted-bootstrap");
        using var deadline = new CancellationTokenSource(Watchdog);

        var result = await authentication.LoginAsync("loopback-client", secret,
            authentication.CreateReceipt(), cancellationToken: deadline.Token);
        if (result.IsSuccess) result.Value.Dispose();
        await backend.StopAsync();

        await Assert.That(result.IsSuccess).IsFalse();
        await Assert.That(backend.Requests.IsEmpty).IsTrue();
        await Assert.That(backend.HandshakeAttempts > 0).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ExplicitPrivateTrustStillChecksHostname(bool wrongHostname)
    {
        using var certificates = new TestCertificates(wrongHostname);
        await using var backend = new LoopbackServer(certificates.Server);
        using var authentication = new InfisicalUniversalAuthentication(backend.Origin,
            new InfisicalNetworkOptions
            {
                Transport = InfisicalTransportOptions.SafeWithPrivateTrust(certificates.Root)
            });
        string canary = "private-root-" + Guid.NewGuid().ToString("N");
        using var secret = SecretMaterial.FromText(canary);
        using var deadline = new CancellationTokenSource(Watchdog);

        var result = await authentication.LoginAsync("loopback-client", secret,
            authentication.CreateReceipt(), cancellationToken: deadline.Token);
        if (result.IsSuccess) result.Value.Dispose();
        await backend.StopAsync();

        await Assert.That(result.IsSuccess).IsEqualTo(!wrongHostname);
        await Assert.That(backend.HandshakeAttempts > 0).IsTrue();
        if (wrongHostname)
            await Assert.That(backend.Requests.IsEmpty).IsTrue();
        else
        {
            CapturedRequest request = backend.Requests.Single();
            using var body = JsonDocument.Parse(request.Body);
            await Assert.That(body.RootElement.GetProperty("clientSecret").GetString()).IsEqualTo(canary);
            await Assert.That(request.StartLine).IsEqualTo("POST /api/v1/auth/universal-auth/login HTTP/1.1");
        }
    }

    [Test]
    public async Task SafeAuthenticationDoesNotFollowCredentialBearingRedirect()
    {
        await using var target = new LoopbackServer();
        await using var source = new LoopbackServer(redirect: target.Origin);
        using var authentication = new InfisicalUniversalAuthentication(source.Origin,
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        using var secret = SecretMaterial.FromText("redirect-bootstrap");
        using var deadline = new CancellationTokenSource(Watchdog);

        var result = await authentication.LoginAsync("loopback-client", secret,
            authentication.CreateReceipt(), cancellationToken: deadline.Token);
        if (result.IsSuccess) result.Value.Dispose();
        await source.StopAsync();
        await target.StopAsync();

        await Assert.That(source.Requests.Single().Body.Contains("redirect-bootstrap", StringComparison.Ordinal)).IsTrue();
        await Assert.That(target.Requests.IsEmpty).IsTrue();
        await Assert.That(result.IsSuccess).IsFalse();
    }

    [Test]
    public async Task SelectedProxyReceivesAbsoluteTargetAndBootstrapExchange()
    {
        await using var proxy = new LoopbackServer();
        // Nothing listens at this destination: a successful response must come
        // from the selected proxy, independently of the SDK's reported status.
        var selected = new Uri("http://127.0.0.1:1/");
        using var authentication = new InfisicalUniversalAuthentication(selected,
            new InfisicalNetworkOptions
            {
                AllowLoopbackDevelopmentHttp = true,
                Proxy = new SelectedProxy(proxy.Origin)
            });
        using var secret = SecretMaterial.FromText("proxy-bootstrap");
        using var deadline = new CancellationTokenSource(Watchdog);

        var result = await authentication.LoginAsync("loopback-client", secret,
            authentication.CreateReceipt(), cancellationToken: deadline.Token);
        if (result.IsSuccess) result.Value.Dispose();
        await proxy.StopAsync();

        await Assert.That(result.IsSuccess).IsTrue();
        CapturedRequest request = proxy.Requests.Single();
        await Assert.That(request.StartLine)
            .IsEqualTo("POST http://127.0.0.1:1/api/v1/auth/universal-auth/login HTTP/1.1");
        await Assert.That(request.Body.Contains("proxy-bootstrap", StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    public async Task LoopbackCaptureAndReleaseBarriersObserveActualWireCanary()
    {
        using var certificates = new TestCertificates(false);
        await using var backend = new LoopbackServer(certificates.Server, holdResponse: true);
        using var handler = NewHandler();
        handler.SslOptions.CertificateChainPolicy = PrivateTrust(certificates.Root);
        using var client = new HttpClient(handler, disposeHandler: false);
        using var deadline = new CancellationTokenSource(Watchdog);
        string canary = "capture-control-" + Guid.NewGuid().ToString("N");
        Task<CapturedRequest> observed = backend.RequestObserved;
        using var body = new StringContent(canary);
        Task<HttpResponseMessage> exchange = client.PostAsync(backend.Origin, body, deadline.Token);
        try
        {
            CapturedRequest request = await observed.WaitAsync(Watchdog);
            await Assert.That(request.Body).IsEqualTo(canary);
            await Assert.That(exchange.IsCompleted).IsFalse();
        }
        finally
        {
            backend.ReleaseResponse();
            using HttpResponseMessage response = await exchange.WaitAsync(Watchdog);
        }
    }

    [Test]
    public async Task SdkActivityCaptureHasPositiveControlAndDoesNotExposeBootstrapMaterial()
    {
        string canary = "diagnostic-bootstrap-" + Guid.NewGuid().ToString("N");
        string probe = Guid.NewGuid().ToString("N");
        var captured = new ConcurrentQueue<string>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name.StartsWith("SecretKit", StringComparison.Ordinal),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                captured.Enqueue(activity.DisplayName);
                foreach (var tag in activity.TagObjects) captured.Enqueue(tag.Value?.ToString() ?? "");
                foreach (var baggage in activity.Baggage) captured.Enqueue(baggage.Value ?? "");
            }
        };
        ActivitySource.AddActivityListener(listener);
        using (var control = new ActivitySource("SecretKit.TransportPolicyProbe"))
        using (Activity? activity = control.StartActivity("control"))
            activity?.SetTag("control", probe);
        await Assert.That(captured.Contains(probe)).IsTrue();

        await using var backend = new LoopbackServer();
        using var authentication = new InfisicalUniversalAuthentication(backend.Origin,
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        using var secret = SecretMaterial.FromText(canary);
        using var deadline = new CancellationTokenSource(Watchdog);
        var result = await authentication.LoginAsync("loopback-client", secret,
            authentication.CreateReceipt(), cancellationToken: deadline.Token);
        if (result.IsSuccess) result.Value.Dispose();
        await backend.StopAsync();

        await Assert.That(backend.Requests.Single().Body.Contains(canary, StringComparison.Ordinal)).IsTrue();
        await Assert.That(captured.Any(value => value.Contains(canary, StringComparison.Ordinal))).IsFalse();
        // Deliberately scoped to SecretKit ActivitySource tags/baggage. This says
        // nothing about runtime HTTP EventSource, profilers or host diagnostics.
    }

    private static SocketsHttpHandler NewHandler() => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false,
        ActivityHeadersPropagator = null
    };

    private static X509ChainPolicy PrivateTrust(X509Certificate2 root)
    {
        var policy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
            VerificationFlags = X509VerificationFlags.NoFlag
        };
        policy.CustomTrustStore.Add(root);
        return policy;
    }

    private sealed class SelectedProxy(Uri address) : IWebProxy
    {
        public ICredentials? Credentials { get; set; }
        public Uri GetProxy(Uri destination) => address;
        public bool IsBypassed(Uri host) => false;
    }

    private sealed class TestCertificates : IDisposable
    {
        internal X509Certificate2 Root { get; }
        internal X509Certificate2 Server { get; }

        internal TestCertificates(bool wrongHostname)
        {
            using RSA authorityKey = RSA.Create(2048);
            var authority = new CertificateRequest("CN=SecretKit Ephemeral Test CA",
                authorityKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            authority.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            authority.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            DateTimeOffset now = DateTimeOffset.UtcNow;
            Root = authority.CreateSelfSigned(now.AddDays(-1), now.AddDays(2));
            using RSA serverKey = RSA.Create(2048);
            var server = new CertificateRequest("CN=SecretKit Loopback", serverKey,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            server.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            server.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            server.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            var names = new SubjectAlternativeNameBuilder();
            if (wrongHostname) names.AddDnsName("wrong-host.invalid");
            else names.AddIpAddress(IPAddress.Loopback);
            server.CertificateExtensions.Add(names.Build());
            using X509Certificate2 issued = server.Create(Root, now.AddHours(-1), now.AddDays(1),
                RandomNumberGenerator.GetBytes(16));
            Server = issued.CopyWithPrivateKey(serverKey);
        }

        public void Dispose()
        {
            Server.Dispose();
            Root.Dispose();
        }
    }

    private sealed record CapturedRequest(string StartLine, string Body, string? Authorization);

    private sealed class LoopbackServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly X509Certificate2? _certificate;
        private readonly Uri? _redirect;
        private readonly TaskCompletionSource _responseRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<CapturedRequest> _observed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Task _accept;
        private readonly List<Task> _connections = [];
        private int _handshakeAttempts;
        internal Uri Origin { get; }
        internal ConcurrentQueue<CapturedRequest> Requests { get; } = new();
        internal Task<CapturedRequest> RequestObserved => _observed.Task;
        internal int HandshakeAttempts => Volatile.Read(ref _handshakeAttempts);

        internal LoopbackServer(X509Certificate2? certificate = null, Uri? redirect = null, bool holdResponse = false)
        {
            _certificate = certificate;
            _redirect = redirect;
            if (!holdResponse) ReleaseResponse();
            _listener.Start();
            Origin = new Uri($"{(certificate is null ? "http" : "https")}://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/");
            _accept = AcceptAsync();
        }

        internal void ReleaseResponse() => _responseRelease.TrySetResult();

        private async Task AcceptAsync()
        {
            try
            {
                while (true)
                {
                    TcpClient client = await _listener.AcceptTcpClientAsync(_stop.Token);
                    _connections.Add(ExchangeAsync(client));
                }
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        }

        private async Task ExchangeAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    using NetworkStream network = client.GetStream();
                    using var tls = _certificate is null ? null : new SslStream(network, leaveInnerStreamOpen: true);
                    if (tls is not null)
                    {
                        Interlocked.Increment(ref _handshakeAttempts);
                        await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                        {
                            ServerCertificate = _certificate,
                            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                        }, _stop.Token);
                    }
                    Stream stream = (Stream?)tls ?? network;
                    using var reader = new StreamReader(stream, Encoding.UTF8, false, 1024, leaveOpen: true);
                    string? start = await reader.ReadLineAsync(_stop.Token);
                    if (start is null) return;
                    int length = 0;
                    string? authorization = null;
                    while (await reader.ReadLineAsync(_stop.Token) is { Length: > 0 } line)
                    {
                        if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                            length = int.Parse(line["Content-Length:".Length..], System.Globalization.CultureInfo.InvariantCulture);
                        if (line.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))
                            authorization = line["Authorization:".Length..].Trim();
                    }
                    if (length is < 0 or > 65536) throw new InvalidOperationException("Unexpected fixture request size.");
                    char[] body = new char[length];
                    int read = 0;
                    while (read < length)
                    {
                        int count = await reader.ReadAsync(body.AsMemory(read), _stop.Token);
                        if (count == 0) throw new EndOfStreamException();
                        read += count;
                    }
                    var request = new CapturedRequest(start, new string(body), authorization);
                    Requests.Enqueue(request);
                    _observed.TrySetResult(request);
                    await _responseRelease.Task.WaitAsync(_stop.Token);
                    string response = _redirect is null
                        ? $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {Encoding.UTF8.GetByteCount(LoginResponse)}\r\nConnection: close\r\n\r\n{LoginResponse}"
                        : $"HTTP/1.1 307 Temporary Redirect\r\nLocation: {_redirect}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    await stream.WriteAsync(Encoding.UTF8.GetBytes(response), _stop.Token);
                    await stream.FlushAsync(_stop.Token);
                }
                catch (AuthenticationException) { }
                catch (IOException) { }
                catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
            }
        }

        internal async Task StopAsync()
        {
            ReleaseResponse();
            await _stop.CancelAsync();
            await _accept.WaitAsync(Watchdog);
            await Task.WhenAll(_connections).WaitAsync(Watchdog);
            _listener.Stop();
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                await StopAsync();
            }
            finally
            {
                _listener.Stop();
                _stop.Dispose();
            }
        }
    }
}
