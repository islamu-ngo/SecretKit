using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using Host = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationWebhookHost;
using Webhook = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationWebhookDeliveryCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    private static Webhook.Limits HostedDeliveryLimits =>
        new(4096, 16, 16, 128, 8, 32, 8192, TimeSpan.FromSeconds(10));

    private static Host.Configuration HostedConfiguration =>
        new(IPAddress.Loopback, 0, WebhookEndpoint.AbsolutePath);

    private static Task<Host> StartWebhook(NotificationCaptureScope f, X509Certificate2 certificate,
        NotificationDeliveryAuthentication? authentication = null, Host.Configuration? configuration = null,
        Webhook.Limits? limits = null, CancellationToken cancellationToken = default) =>
        Host.StartAsync(configuration ?? HostedConfiguration, certificate, f.Fixture.Journal, Owner,
            f.Source, limits ?? HostedDeliveryLimits, f.Clock, authentication, cancellationToken);

    private static X509Certificate2 WebhookCertificate(string? publicName = null)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        names.AddDnsName("localhost");
        if (publicName is not null) names.AddDnsName(publicName);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(10));
    }

    private static RemoteCertificateValidationCallback WebhookCertificatePin(X509Certificate2 certificate)
    {
        string pin = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        return (_, presented, _, errors) => presented is not null &&
            (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) == 0 &&
            presented.GetCertHashString(HashAlgorithmName.SHA256) == pin;
    }

    private static HttpClient WebhookHttp(X509Certificate2 certificate) => new(new SocketsHttpHandler
    {
        UseProxy = false,
        AllowAutoRedirect = false,
        SslOptions = new() { RemoteCertificateValidationCallback = WebhookCertificatePin(certificate) }
    })
    {
        Timeout = TimeSpan.FromSeconds(10)
    };

    private static HttpRequestMessage HostedPacket(NotificationCaptureScope f, Host host, RSA? signing = null)
    {
        var request = Packet(f);
        request.RequestUri = host.ListenerEndpoint;
        request.Headers.Host = host.Endpoint.Authority;
        if (signing is not null)
            request.Headers.Authorization = new("Bearer", SignDelivery(signing, DeliveryClaims(f.Clock).ToJsonString()));
        return request;
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task HostedWebhookUsesActualTlsAndOriginalCaptureWithoutOwningBorrowedObjects(bool attachAfterDelivery)
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var certificate = WebhookCertificate();
        using var signing = RSA.Create(2048);
        var trust = DeliveryTrust(signing, f.Clock);
        await using var host = await StartWebhook(f, certificate, trust);
        using var client = WebhookHttp(certificate);
        await Assert.That(host.Endpoint.Port > 0).IsTrue();
        await Assert.That(host.Endpoint).IsEqualTo(host.ListenerEndpoint);

        using (var beforeArm = HostedPacket(f, host, signing))
        using (var denied = await client.SendAsync(beforeArm))
            await Assert.That(denied.StatusCode).IsEqualTo(HttpStatusCode.ServiceUnavailable);

        var binding = WebhookBinding(f);
        host.Arm(binding, ["x-correlation"]);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        // Subscription precedes the original native work, not just HTTP delivery.
        var linked = host.WaitForLinkedDeliveryAsync(deadline.Token);
        var capture = await Trigger(f);
        int nativeResponseDisposals = f.Tracking.DisposeAttempts;
        await Assert.That(nativeResponseDisposals > 0).IsTrue();
        if (!attachAfterDelivery) host.AttachCapture(capture);
        using (var packet = HostedPacket(f, host, signing))
        using (var accepted = await client.SendAsync(packet))
            await Assert.That(accepted.StatusCode).IsEqualTo(HttpStatusCode.OK);
        if (attachAfterDelivery)
        {
            await Assert.That(linked.IsCompleted).IsFalse();
            host.AttachCapture(capture);
        }
        await linked;
        var measured = await host.CloseAsync(deadline.Token);
        await Assert.That(measured.Available).IsTrue();
        await Assert.That(measured.Binding).IsEqualTo(binding);
        await Assert.That(measured.NativeTriggerRequestIds.Single()).IsEqualTo("native-original-write");
        await Assert.That(measured.Deliveries.Single().Headers.Single().Value).IsEqualTo("selected-correlation");
        await Assert.That(measured.ProviderIdentityEstablished || measured.NativeWindowClosureEstablished ||
            measured.NativeFilterExclusionEstablished).IsFalse();
        using (var closed = HostedPacket(f, host, signing))
        using (var denied = await client.SendAsync(closed))
            await Assert.That(denied.StatusCode).IsEqualTo(HttpStatusCode.Gone);

        using var stoppedPacket = HostedPacket(f, host, signing);
        await host.StopAsync().WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(async () =>
        {
            using var unexpected = await client.SendAsync(stoppedPacket);
        })
            .Throws<HttpRequestException>();
        // Validate against the same source and journal after receiver disposal.
        var original = f.Source.Read(capture, f.Binding);
        f.Source.ValidateMeasurement(f.Fixture.Journal, Owner, capture, f.Binding, original);
        await Assert.That(original.EmissionEstablished).IsFalse();
        await Assert.That(f.Credential.Disposed || f.Native.Disposed).IsFalse();
        await Assert.That(f.Tracking.DisposeAttempts).IsEqualTo(nativeResponseDisposals);
        await Assert.That(f.Fixture.Read().Closing).IsFalse();
        using var transportRequest = f.Tracking.CreateRequest();
        await Assert.That(() => host.Endpoint).Throws<InvalidOperationException>();
        await Assert.That(() => host.Arm(binding, [])).Throws<InvalidOperationException>();
        await Assert.That(() => host.AttachCapture(capture)).Throws<InvalidOperationException>();

        // The same supplied certificate, signing trust and capture can be borrowed
        // by another listener; no duplicate runtime write is synthesized.
        await using var another = await StartWebhook(f, certificate, trust);
        using var stillUsable = HostedPacket(f, another, signing);
        await Assert.That(await trust.AuthenticateAsync(stillUsable, default)).IsTrue();
        using var received = await client.SendAsync(stillUsable);
        await Assert.That(received.StatusCode).IsEqualTo(HttpStatusCode.ServiceUnavailable);
    }

    [Test]
    [Arguments("missing")]
    [Arguments("invalid")]
    public async Task HostedWebhookRejectsBearerBeforeRequestingAnyBody(string fault)
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var certificate = WebhookCertificate();
        using var signing = RSA.Create(2048);
        await using var host = await StartWebhook(f, certificate, DeliveryTrust(signing, f.Clock));
        host.Arm(WebhookBinding(f), []);
        await using var connection = await WebhookTlsConnection.Open(host.ListenerEndpoint, certificate);
        string extra = fault == "invalid" ? "Authorization: Bearer untrusted\r\n" : "";
        var response = connection.ReadStatus();
        await connection.SendHeaders(host.Endpoint, extra: extra);
        // No body bytes are sent. A premature body read would produce 100, not 401.
        await Assert.That(await response).IsEqualTo(401);
        var measured = await host.CloseAsync(default).WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(measured.Deliveries.Count).IsEqualTo(0);
        await Assert.That(measured.Available).IsFalse();
    }

    [Test]
    [Arguments("unarmed", 503)]
    [Arguments("host", 401)]
    [Arguments("path", 401)]
    [Arguments("query", 401)]
    [Arguments("escaped-path", 401)]
    [Arguments("absolute-target", 401)]
    [Arguments("method", 400)]
    public async Task HostedWebhookRejectsWrongRouteBeforeBodyAndIgnoresForwardedAuthority(string fault, int status)
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var certificate = WebhookCertificate();
        await using var host = await StartWebhook(f, certificate);
        if (fault != "unarmed") host.Arm(WebhookBinding(f), []);
        await using var connection = await WebhookTlsConnection.Open(host.ListenerEndpoint, certificate);
        string path = fault switch
        {
            "path" => host.Endpoint.AbsolutePath + "-foreign",
            "query" => host.Endpoint.AbsolutePath + "?ignored=true",
            "escaped-path" => host.Endpoint.AbsolutePath.Replace("/notification/", "/%6eotification/", StringComparison.Ordinal),
            "absolute-target" => host.Endpoint.AbsoluteUri,
            _ => host.Endpoint.AbsolutePath
        };
        var response = connection.ReadStatus();
        await connection.SendHeaders(host.Endpoint, target: path,
            authority: fault == "host" ? "foreign.example" : null,
            method: fault == "method" ? "PUT" : "POST",
            extra: $"Forwarded: proto=https;host={host.Endpoint.Authority}\r\n" +
                $"X-Forwarded-Host: {host.Endpoint.Authority}\r\nX-Forwarded-Proto: https\r\n");
        await Assert.That(await response).IsEqualTo(status);
    }

    [Test]
    public async Task HostedWebhookPublicAuthorityIsExplicitAndNeverSelectedByForwardedHeaders()
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var certificate = WebhookCertificate("receiver.example");
        var configuration = HostedConfiguration with { PublicAuthority = new("https://receiver.example:8443/") };
        await using var host = await StartWebhook(f, certificate, configuration: configuration);
        await Assert.That(host.Endpoint.Authority).IsEqualTo("receiver.example:8443");
        host.Arm(WebhookBinding(f), []);
        using var client = WebhookHttp(certificate);
        using (var forged = HostedPacket(f, host))
        {
            forged.Headers.Host = host.ListenerEndpoint.Authority;
            forged.Headers.Add("X-Forwarded-Host", host.Endpoint.Authority);
            using var rejected = await client.SendAsync(forged);
            await Assert.That(rejected.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        }
        using var configured = HostedPacket(f, host);
        configured.Headers.Add("X-Forwarded-Host", "untrusted.example");
        configured.Headers.Add("X-Forwarded-Proto", "http");
        using var accepted = await client.SendAsync(configured);
        await Assert.That(accepted.StatusCode).IsEqualTo(HttpStatusCode.OK);
        var measured = await host.CloseAsync(default).WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(measured.Available || measured.ProviderIdentityEstablished).IsFalse();
    }

    [Test]
    public async Task HostedWebhookPreservesValidationResponseWithoutFollowingValidationUrl()
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var certificate = WebhookCertificate();
        await using var host = await StartWebhook(f, certificate);
        host.Arm(WebhookBinding(f), []);
        using var client = WebhookHttp(certificate);
        using var packet = HostedPacket(f, host);
        var body = JsonNode.Parse(await packet.Content!.ReadAsStringAsync())!.AsArray();
        body[0]!["eventType"] = "Microsoft.EventGrid.SubscriptionValidationEvent";
        body[0]!["data"] = new JsonObject
        {
            ["validationCode"] = "selected-validation-code",
            ["validationUrl"] = "https://never-follow.example.invalid/validation"
        };
        packet.Content.Dispose();
        packet.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        packet.Headers.Remove("aeg-event-type");
        packet.Headers.Add("aeg-event-type", "SubscriptionValidation");
        using var response = await client.SendAsync(packet);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        var validation = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        await Assert.That(validation.ContainsKey("validationResponse")).IsTrue();
        await Assert.That(validation["validationResponse"]!.GetValue<string>())
            .IsEqualTo("selected-validation-code");
        var measured = await host.CloseAsync(default).WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(measured.Deliveries.Count).IsEqualTo(0);
        await Assert.That(measured.Available || measured.ProviderIdentityEstablished ||
            measured.NativeWindowClosureEstablished).IsFalse();
    }

    [Test]
    public async Task HostedWebhookTlsClientRejectsADifferentCertificatePin()
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var certificate = WebhookCertificate();
        using var foreign = WebhookCertificate();
        await using var host = await StartWebhook(f, certificate);
        using var client = WebhookHttp(foreign);
        using var packet = HostedPacket(f, host);
        await Assert.That(async () =>
        {
            using var unexpected = await client.SendAsync(packet);
        })
            .Throws<HttpRequestException>();
    }

    [Test]
    public async Task HostedWebhookBoundsChunkedBodyAndPreservesCollectorError()
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var certificate = WebhookCertificate();
        await using var host = await StartWebhook(f, certificate);
        host.Arm(WebhookBinding(f), []);
        using var client = WebhookHttp(certificate);
        using var packet = HostedPacket(f, host);
        packet.Content!.Dispose();
        packet.Content = new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes(new string(' ', 4097))));
        packet.Content.Headers.ContentType = new("application/json");
        packet.Headers.TransferEncodingChunked = true;
        using var response = await client.SendAsync(packet);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(await response.Content.ReadAsStringAsync())
            .IsEqualTo("{\"error\":\"notification-webhook-unavailable\"}");
        var measured = await host.CloseAsync(default).WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(measured.Failure).IsEqualTo(Webhook.Failure.Protocol);
        await Assert.That(measured.TaskDrained).IsTrue();
    }

    [Test]
    public async Task HostedWebhookConcurrentStopCancelsAndDrainsActualPendingBody()
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var certificate = WebhookCertificate();
        await using var host = await StartWebhook(f, certificate);
        host.Arm(WebhookBinding(f), []);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var waiting = host.WaitForLinkedDeliveryAsync(deadline.Token);
        await using var connection = await WebhookTlsConnection.Open(host.ListenerEndpoint, certificate);
        var admitted = connection.ReadStatus();
        await connection.SendHeaders(host.Endpoint);
        // Kestrel sends 100 only when the admitted collector starts reading.
        await Assert.That(await admitted).IsEqualTo(100);
        var response = connection.ReadStatus();
        Task first = host.StopAsync(), second = host.StopAsync(), third = host.DisposeAsync().AsTask();
        await Assert.That(await response).IsEqualTo(400);
        await Task.WhenAll(first, second, third).WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(() => waiting).Throws<InvalidOperationException>();
        await host.StopAsync();
        await Assert.That(() => host.ListenerEndpoint).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Disposed || f.Credential.Disposed).IsFalse();
    }

    [Test]
    public async Task HostedWebhookClientDisconnectDrainsWithoutRemoteClosureEvidence()
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var certificate = WebhookCertificate();
        await using var host = await StartWebhook(f, certificate);
        host.Arm(WebhookBinding(f), []);
        await using (var connection = await WebhookTlsConnection.Open(host.ListenerEndpoint, certificate))
        {
            var admitted = connection.ReadStatus();
            await connection.SendHeaders(host.Endpoint);
            await Assert.That(await admitted).IsEqualTo(100);
        }
        var measured = await host.CloseAsync(default).WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(measured.TaskDrained).IsTrue();
        await Assert.That(measured.Available || measured.NativeWindowClosureEstablished ||
            measured.NativeFilterExclusionEstablished || measured.ProviderIdentityEstablished).IsFalse();
    }

    [Test]
    public async Task HostedWebhookStopClosesAdmissionWhileActualArmCallbackIsStillRunning()
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var certificate = WebhookCertificate();
        await using var host = await StartWebhook(f, certificate);
        using var client = WebhookHttp(certificate);
        using var packet = HostedPacket(f, host);
        var entered = Signal();
        var release = Signal();
        f.Clock.Callback = () =>
        {
            entered.TrySetResult();
            release.Task.WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
        };
        Task armed = Task.Run(() => host.Arm(WebhookBinding(f), []));
        Task[] stops = [];
        Task? registration = null;
        Exception? armFailure = null;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            // Register on a second thread so calling a clock under the host
            // lock fails at a bounded signal rather than wedging the test.
            var registered = Signal();
            registration = Task.Run(() =>
            {
                stops = [host.StopAsync(), host.StopAsync(), host.DisposeAsync().AsTask()];
                registered.TrySetResult();
            });
            await registered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(stops.Any(task => task.IsCompleted)).IsFalse();
            using var denied = await client.SendAsync(packet);
            await Assert.That(denied.StatusCode).IsEqualTo(HttpStatusCode.Gone);
        }
        finally
        {
            release.TrySetResult();
            try { await armed.WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (Exception failure) { armFailure = failure; }
            finally
            {
                if (registration is not null) await registration.WaitAsync(TimeSpan.FromSeconds(10));
                await Task.WhenAll(stops).WaitAsync(TimeSpan.FromSeconds(10));
            }
        }
        // The arm cannot publish after admission was closed.
        await Assert.That(armFailure is InvalidOperationException).IsTrue();
    }

    [Test]
    public async Task HostedWebhookCanceledStopWaiterDoesNotAbandonSharedTeardown()
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var certificate = WebhookCertificate();
        await using var host = await StartWebhook(f, certificate);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.That(() => host.StopAsync(canceled.Token)).Throws<OperationCanceledException>();
        await Task.WhenAll(host.StopAsync(), host.DisposeAsync().AsTask()).WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(() => host.Endpoint).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task HostedWebhookStartupFailureAndCancellationPreserveBorrowedResources()
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var certificate = WebhookCertificate();
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.That(async () =>
        {
            await using var unexpected = await StartWebhook(f, certificate, cancellationToken: canceled.Token);
        })
            .Throws<OperationCanceledException>();
        // Collector validation happens after the actual listener port is known.
        await Assert.That(async () =>
        {
            await using var unexpected = await StartWebhook(f, certificate, limits: HostedDeliveryLimits with { MaximumNodes = 1 });
        })
            .Throws<InvalidOperationException>();
        await using var first = await StartWebhook(f, certificate);
        var occupied = HostedConfiguration with { Port = first.ListenerEndpoint.Port };
        await Assert.That(async () =>
        {
            await using var unexpected = await StartWebhook(f, certificate, configuration: occupied);
        })
            .Throws<InvalidOperationException>();
        // The failed second startup must not stop the first listener.
        using var client = WebhookHttp(certificate);
        using var packet = HostedPacket(f, first);
        using var response = await client.SendAsync(packet);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.ServiceUnavailable);
        await Assert.That(f.Native.Disposed || f.Credential.Disposed).IsFalse();
        await Assert.That(f.Tracking.DisposeAttempts).IsEqualTo(0);
    }

    private sealed class WebhookTlsConnection(TcpClient client, SslStream tls) : IAsyncDisposable
    {
        private readonly CancellationTokenSource deadline = new(TimeSpan.FromSeconds(10));
        private readonly StreamReader reader = new(tls, Encoding.ASCII, false, 1024, leaveOpen: true);

        internal static async Task<WebhookTlsConnection> Open(Uri listener, X509Certificate2 certificate)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var client = new TcpClient();
            SslStream? tls = null;
            try
            {
                await client.ConnectAsync(listener.Host, listener.Port, deadline.Token);
                tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = listener.Host,
                    RemoteCertificateValidationCallback = WebhookCertificatePin(certificate)
                }, deadline.Token);
                return new(client, tls);
            }
            catch
            {
                if (tls is not null) await tls.DisposeAsync();
                client.Dispose();
                throw;
            }
        }

        internal async Task SendHeaders(Uri endpoint, string? target = null, string? authority = null,
            string method = "POST", string extra = "")
        {
            string text = $"{method} {target ?? endpoint.AbsolutePath} HTTP/1.1\r\n" +
                $"Host: {authority ?? endpoint.Authority}\r\nContent-Type: application/json\r\n" +
                "Content-Length: 4096\r\nExpect: 100-continue\r\n" +
                "aeg-event-type: Notification\r\naeg-subscription-name: owned-notification\r\n" + extra + "\r\n";
            await tls.WriteAsync(Encoding.ASCII.GetBytes(text), deadline.Token);
            await tls.FlushAsync(deadline.Token);
        }

        internal async Task<int> ReadStatus()
        {
            string line = await reader.ReadLineAsync(deadline.Token) ??
                throw new InvalidOperationException("controlled-http-eof");
            if (!line.StartsWith("HTTP/1.1 ", StringComparison.Ordinal) ||
                !int.TryParse(line.AsSpan(9, 3), out int status))
                throw new InvalidOperationException("controlled-http-status");
            for (int count = 0; count < 32; count++)
            {
                line = await reader.ReadLineAsync(deadline.Token) ??
                    throw new InvalidOperationException("controlled-http-eof");
                if (line.Length == 0) return status;
                if (line.Length > 8192) break;
            }
            throw new InvalidOperationException("controlled-http-headers");
        }

        public async ValueTask DisposeAsync()
        {
            reader.Dispose();
            await tls.DisposeAsync();
            client.Dispose();
            deadline.Dispose();
        }
    }
}
