using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text.Json;

namespace SecretKit.Demo.Tests;

public sealed class DemoNetworkTests
{
    private const string Canary = "synthetic-network-credential-canary";

    [Test]
    public async Task RedirectCannotForwardTheSelectedCredentialToAnotherOrigin()
    {
        await using var foreign = new ControlledInfisicalServer(_ => new(200, "{}"));
        await using var selected = new ControlledInfisicalServer(_ =>
            new(302, Canary, Location: new Uri(foreign.Origin, "foreign")));
        DemoResult result = await new DemoProcess().ConsoleAsync(Input(selected.Origin), "read");
        await Assert.That(result.ExitCode).IsEqualTo(2);
        await Assert.That(selected.Requests.Count).IsEqualTo(1);
        await Assert.That(foreign.Requests.Count).IsEqualTo(0);
        await CleanAsync(result);
    }

    [Test]
    public async Task OversizedProviderResponseFailsWithoutEchoingOrRetryingIt()
    {
        await using var selected = new ControlledInfisicalServer(_ =>
            new(200, Canary + new string('x', 1024 * 1024)));
        DemoResult result = await new DemoProcess().ConsoleAsync(Input(selected.Origin), "read");
        await Assert.That(result.ExitCode).IsEqualTo(2);
        await Assert.That(selected.Requests.Count).IsEqualTo(1);
        await CleanAsync(result);
    }

    [Test]
    public async Task ProtectedOriginQueryFailsBeforeProviderOrTokenDispatch()
    {
        await using var selected = new ControlledInfisicalServer(_ => new(200, "{}"));
        DemoResult result = await new DemoProcess().ConsoleAsync(
            Input(new Uri(selected.Origin, "?query=" + Canary)), "read");
        await Assert.That(result.ExitCode).IsEqualTo(2);
        await Assert.That(selected.Requests.Count).IsEqualTo(0);
        await CleanAsync(result);
    }

    [Test]
    public async Task UntrustedCertificateDoesNotReceiveAnAuthenticatedHttpRequest()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=untrusted.invalid", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddMinutes(30));
        using var stop = new CancellationTokenSource();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var origin = new Uri($"https://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        bool observedHttp = false;
        Task connection = ServeAsync();
        try
        {
            DemoResult result = await new DemoProcess().ConsoleAsync(Input(origin), "read");
            await connection.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(result.ExitCode).IsEqualTo(4);
            await Assert.That(observedHttp).IsFalse();
            await CleanAsync(result);
        }
        finally
        {
            stop.Cancel();
            listener.Stop();
            await connection;
        }

        async Task ServeAsync()
        {
            try
            {
                using TcpClient client = await listener.AcceptTcpClientAsync(stop.Token);
                using var stream = new SslStream(client.GetStream());
                await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                }, stop.Token);
                observedHttp = await stream.ReadAsync(new byte[4096], stop.Token) != 0;
            }
            catch (AuthenticationException) { }
            catch (IOException) { }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
    }

    private static string Input(Uri origin) => JsonSerializer.Serialize(new
    {
        origin = origin.AbsoluteUri,
        project = "project",
        environment = "env",
        folder = "/",
        key = "key",
        token = Canary,
        allowLoopbackDevelopmentHttp = true
    });

    private static async Task CleanAsync(DemoResult result) =>
        await Assert.That((result.Output + result.Error).Contains(Canary, StringComparison.Ordinal)).IsFalse();
}
