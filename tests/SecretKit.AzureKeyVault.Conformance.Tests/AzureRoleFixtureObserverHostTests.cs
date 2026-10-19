using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureRoleFixtureObserverHostTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);

    [Test]
    public async Task NativeHttpsPreservesProtectedHeaderRouteAndBody()
    {
        // Given: only this ephemeral leaf is trusted by this client.
        using var certificate = Certificate();
        string? authorization = null;
        string? route = null;
        string? body = null;
        string? contentType = null;
        await using var host = RoleFixtureObserverHost.Start(certificate, Loopback(), async (request, token) =>
        {
            authorization = request.Headers.GetValues("Authorization").Single();
            route = request.RequestUri!.PathAndQuery;
            body = await request.Content!.ReadAsStringAsync(token);
            contentType = request.Content.Headers.GetValues("Content-Type").Single();
            var response = new HttpResponseMessage(HttpStatusCode.Accepted)
            {
                Content = new StringContent("{\"state\":\"controlled\"}", Encoding.UTF8, "application/json")
            };
            response.Headers.TryAddWithoutValidation("X-Observer-Result", "exact-result");
            return response;
        });
        using var client = Client(certificate);
        using var outbound = new HttpRequestMessage(HttpMethod.Post, new Uri(host.Origin, "/fixture/observe?revision=1"))
        {
            Content = new StringContent("{\"selector\":\"controlled\"}", Encoding.UTF8, "application/json")
        };
        outbound.Headers.TryAddWithoutValidation("Authorization", "Bearer protected-test-token");
        // When: the native HTTP stack negotiates actual TLS.
        using var reply = await client.SendAsync(outbound);
        // Then: dispatch and response preserve the exact protected inputs.
        await Assert.That(host.Origin.Scheme).IsEqualTo("https");
        await Assert.That(authorization).IsEqualTo("Bearer protected-test-token");
        await Assert.That(route).IsEqualTo("/fixture/observe?revision=1");
        await Assert.That(body).IsEqualTo("{\"selector\":\"controlled\"}");
        await Assert.That(contentType).IsEqualTo("application/json; charset=utf-8");
        await Assert.That(reply.StatusCode).IsEqualTo(HttpStatusCode.Accepted);
        await Assert.That(reply.Headers.GetValues("X-Observer-Result").Single()).IsEqualTo("exact-result");
        await Assert.That(await reply.Content.ReadAsStringAsync()).IsEqualTo("{\"state\":\"controlled\"}");
        await Assert.That(reply.Headers.ConnectionClose).IsTrue();
        await Assert.That(host.ToString()).IsEqualTo("RoleFixtureObserverHost([redacted])");
    }

    [Test]
    public async Task NativeClientRejectsUntrustedLeafBeforeDispatch()
    {
        // Given: no trust-store modification or permissive callback.
        using var certificate = Certificate();
        int dispatched = 0;
        await using var host = RoleFixtureObserverHost.Start(certificate, Loopback(), (_, _) =>
        {
            Interlocked.Increment(ref dispatched);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });
        using var client = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = Bound };
        // When / Then: certificate verification fails before any HTTP request.
        await Assert.That(async () => await client.GetAsync(host.Origin)).Throws<HttpRequestException>();
        await Assert.That(dispatched).IsEqualTo(0);
    }

    [Test]
    [Arguments("absolute")]
    [Arguments("authority")]
    [Arguments("method")]
    [Arguments("folded")]
    [Arguments("transfer")]
    [Arguments("length")]
    [Arguments("duplicate")]
    [Arguments("oversize")]
    [Arguments("headers")]
    [Arguments("utf8")]
    [Arguments("path")]
    [Arguments("line")]
    [Arguments("encoded")]
    [Arguments("control")]
    public async Task MalformedOrSmuggledRequestNeverReachesDelegate(string fault)
    {
        // Given: a raw TLS peer can send syntax the native HttpClient would refuse.
        using var certificate = Certificate();
        int dispatched = 0;
        await using var host = RoleFixtureObserverHost.Start(certificate, Loopback(), (_, _) =>
        {
            Interlocked.Increment(ref dispatched);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }, maximumHeaderBytes: 512, maximumBodyBytes: 16);
        string authority = host.Origin.Authority;
        string text = fault switch
        {
            "absolute" => $"GET https://{authority}/fixture HTTP/1.1\r\nHost: {authority}\r\n\r\n",
            "authority" => "GET /fixture HTTP/1.1\r\nHost: foreign.invalid\r\n\r\n",
            "method" => $"CONNECT /fixture HTTP/1.1\r\nHost: {authority}\r\n\r\n",
            "folded" => $"GET /fixture HTTP/1.1\r\nHost: {authority}\r\n Authorization: injected\r\n\r\n",
            "transfer" => $"POST /fixture HTTP/1.1\r\nHost: {authority}\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n",
            "length" => $"POST /fixture HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            "duplicate" => $"GET /fixture HTTP/1.1\r\nHost: {authority}\r\nAuthorization: first\r\nAuthorization: second\r\n\r\n",
            "oversize" => $"POST /fixture HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 17\r\n\r\n",
            "headers" => $"GET /fixture HTTP/1.1\r\nHost: {authority}\r\nX-Large: {new string('a', 512)}\r\n\r\n",
            "utf8" => $"POST /fixture HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 1\r\n\r\n",
            "path" => $"GET /fixture/../other HTTP/1.1\r\nHost: {authority}\r\n\r\n",
            "line" => $"GET /fixture HTTP/1.1\r\nHost: {authority}\r\nX-Test: one\nInjected: two\r\n\r\n",
            "encoded" => $"GET /fixture/%ff HTTP/1.1\r\nHost: {authority}\r\n\r\n",
            "control" => $"GET /fixture/%00 HTTP/1.1\r\nHost: {authority}\r\n\r\n",
            _ => throw new InvalidOperationException("Unknown controlled fault.")
        };
        byte[] bytes = Encoding.ASCII.GetBytes(text);
        if (fault == "utf8") bytes = [.. bytes, 0xff];
        // When: invalid framing, authority or encoding arrives.
        byte[] result = await ExchangeAsync(host.Origin, certificate, bytes);
        // Then: the transport closes without dispatch or response material.
        await Assert.That(result.Length).IsEqualTo(0);
        await Assert.That(dispatched).IsEqualTo(0);
    }

    [Test]
    [Arguments("body")]
    [Arguments("headers")]
    [Arguments("injection")]
    [Arguments("length")]
    public async Task InvalidResponseIsRejectedBeforeAnyBytesAreWritten(string fault)
    {
        // Given: response validation is a transport boundary as well.
        using var certificate = Certificate();
        await using var host = RoleFixtureObserverHost.Start(certificate, Loopback(), (_, _) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(new byte[fault == "body" ? 17 : 1])
            };
            if (fault == "headers") response.Headers.TryAddWithoutValidation("X-Large", new string('x', 512));
            if (fault == "injection") response.Headers.TryAddWithoutValidation("X-Result", "good\r\nInjected: bad");
            if (fault == "length") response.Content.Headers.ContentLength = 9;
            return Task.FromResult(response);
        }, maximumHeaderBytes: 512, maximumBodyBytes: 16);
        // When: a response exceeds a budget or has ambiguous framing.
        byte[] result = await ExchangeAsync(host.Origin, certificate,
            Encoding.ASCII.GetBytes($"GET /fixture HTTP/1.1\r\nHost: {host.Origin.Authority}\r\n\r\n"));
        // Then: not even a partial status line leaks.
        await Assert.That(result.Length).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ShutdownCancelsAndDrainsLateDelegateWithoutDisposingCertificate(bool callerCancellation)
    {
        // Given: cancellation acknowledgement and completion are separate events.
        using var certificate = Certificate();
        using var cancellation = new CancellationTokenSource();
        var entered = Signal();
        var cancelled = Signal();
        var release = Signal();
        var exited = Signal();
        var host = RoleFixtureObserverHost.Start(certificate, Loopback(), async (_, token) =>
        {
            using var registration = token.Register(() => cancelled.TrySetResult());
            entered.TrySetResult();
            try
            {
                await release.Task; // Deliberately late cooperative cancellation.
                token.ThrowIfCancellationRequested();
                return new HttpResponseMessage(HttpStatusCode.OK);
            }
            finally { exited.TrySetResult(); }
        }, cancellation.Token, maximumConcurrentRequests: 1);
        using var client = Client(certificate);
        Task<HttpResponseMessage> sending = client.GetAsync(new Uri(host.Origin, "/fixture"));
        await entered.Task.WaitAsync(Bound);
        Task? drain = null;
        try
        {
            // When: either explicit disposal or the caller stops the host.
            if (callerCancellation) cancellation.Cancel();
            drain = host.DisposeAsync().AsTask();
            await cancelled.Task.WaitAsync(Bound);
            // Then: disposal stays pending until the owned delegate actually exits.
            await Assert.That(drain.IsCompleted).IsFalse();
            await Assert.That(exited.Task.IsCompleted).IsFalse();
        }
        finally
        {
            release.TrySetResult();
            await host.DisposeAsync().AsTask().WaitAsync(Bound);
        }
        await exited.Task.WaitAsync(Bound);
        await Assert.That(drain!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(async () => await sending).Throws<HttpRequestException>();
        using RSA key = certificate.GetRSAPrivateKey()!;
        byte[] signature = key.SignData([1, 2, 3], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using RSA publicKey = certificate.GetRSAPublicKey()!;
        await Assert.That(publicKey.VerifyData(new byte[] { 1, 2, 3 }, signature,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)).IsTrue();
    }

    [Test]
    public async Task SingleConnectionCannotDispatchPipelinedSecondRequest()
    {
        // Given: one request per connection, even with a pipelined hostile peer.
        using var certificate = Certificate();
        int dispatched = 0;
        await using var host = RoleFixtureObserverHost.Start(certificate, Loopback(), (_, _) =>
        {
            Interlocked.Increment(ref dispatched);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });
        string request = $"GET /fixture HTTP/1.1\r\nHost: {host.Origin.Authority}\r\n\r\n";
        // When: two complete requests share one TLS connection.
        await ExchangeAsync(host.Origin, certificate, Encoding.ASCII.GetBytes(request + request));
        // Then: the second request cannot be smuggled to the delegate.
        await Assert.That(dispatched).IsEqualTo(1);
    }

    [Test]
    public async Task FixedWorkerBoundsConcurrentDispatch()
    {
        // Given: the only worker remains occupied behind an exact release barrier.
        using var certificate = Certificate();
        var entered = Signal();
        var release = Signal();
        int dispatched = 0;
        var host = RoleFixtureObserverHost.Start(certificate, Loopback(), async (_, token) =>
        {
            Interlocked.Increment(ref dispatched);
            entered.TrySetResult();
            await release.Task;
            token.ThrowIfCancellationRequested();
            return new HttpResponseMessage(HttpStatusCode.OK);
        }, maximumConcurrentRequests: 1);
        using var client = Client(certificate);
        Task<HttpResponseMessage> first = client.GetAsync(host.Origin);
        await entered.Task.WaitAsync(Bound);
        using var pending = new TcpClient();
        await pending.ConnectAsync(IPAddress.Loopback, host.Origin.Port).WaitAsync(Bound);
        // When: a second connected socket exists while the worker is occupied.
        Task drain = host.DisposeAsync().AsTask();
        try
        {
            // Then: the second connection cannot allocate a new dispatch task.
            await Assert.That(dispatched).IsEqualTo(1);
            await Assert.That(drain.IsCompleted).IsFalse();
        }
        finally
        {
            release.TrySetResult();
            await drain.WaitAsync(Bound);
        }
        await Assert.That(async () => await first).Throws<HttpRequestException>();
        await Assert.That(dispatched).IsEqualTo(1);
    }

    [Test]
    public async Task ConnectionDeadlineCancelsButStillDrainsLateDelegate()
    {
        // Given: elapsed time is the behavior under test; acknowledgement is an event.
        using var certificate = Certificate();
        var entered = Signal();
        var cancelled = Signal();
        var release = Signal();
        var host = RoleFixtureObserverHost.Start(certificate, Loopback(), async (_, token) =>
        {
            using var registration = token.Register(() => cancelled.TrySetResult());
            entered.TrySetResult();
            await release.Task;
            token.ThrowIfCancellationRequested();
            return new HttpResponseMessage(HttpStatusCode.OK);
        }, connectionDeadline: TimeSpan.FromSeconds(1));
        using var client = Client(certificate);
        Task<HttpResponseMessage> sending = client.GetAsync(host.Origin);
        Task? drain = null;
        try
        {
            // When: the connection deadline cancels an active request.
            await entered.Task.WaitAsync(Bound);
            await cancelled.Task.WaitAsync(Bound);
            drain = host.DisposeAsync().AsTask();
            // Then: the socket is closed but ownership still awaits the delegate.
            await Assert.That(drain.IsCompleted).IsFalse();
        }
        finally
        {
            release.TrySetResult();
            await host.DisposeAsync().AsTask().WaitAsync(Bound);
        }
        await Assert.That(drain!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(async () => await sending).Throws<HttpRequestException>();
    }

    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static IPEndPoint Loopback() => new(IPAddress.Loopback, 0);

    private static X509Certificate2 Certificate()
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
    }

    private static HttpClient Client(X509Certificate2 certificate) => new(new HttpClientHandler
    {
        UseProxy = false,
        AllowAutoRedirect = false,
        ServerCertificateCustomValidationCallback = (_, leaf, _, errors) => leaf is not null &&
            (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0 &&
            leaf.RawData.AsSpan().SequenceEqual(certificate.RawData)
    })
    { Timeout = Bound, DefaultRequestVersion = HttpVersion.Version11, DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact };

    private static async Task<byte[]> ExchangeAsync(Uri origin, X509Certificate2 certificate, byte[] request)
    {
        using var cancellation = new CancellationTokenSource(Bound);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, origin.Port, cancellation.Token);
        using var tls = new SslStream(client.GetStream(), false, (_, leaf, _, _) =>
            leaf is not null && leaf.GetRawCertData().AsSpan().SequenceEqual(certificate.RawData));
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            ApplicationProtocols = [SslApplicationProtocol.Http11]
        }, cancellation.Token);
        byte[] buffer = new byte[4096];
        using var response = new MemoryStream();
        try
        {
            await tls.WriteAsync(request, cancellation.Token);
            int read;
            while ((read = await tls.ReadAsync(buffer, cancellation.Token)) != 0)
            {
                if (response.Length + read > 4096) throw new InvalidOperationException("Controlled response exceeded bound.");
                response.Write(buffer, 0, read);
            }
            return response.ToArray();
        }
        catch (IOException) { return response.ToArray(); } // A rejected peer may receive TCP reset instead of EOF.
        finally
        {
            CryptographicOperations.ZeroMemory(request);
            CryptographicOperations.ZeroMemory(buffer);
            CryptographicOperations.ZeroMemory(response.GetBuffer());
        }
    }
}
