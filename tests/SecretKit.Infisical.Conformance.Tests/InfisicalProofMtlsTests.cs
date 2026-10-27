using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Standalone public-seam infrastructure characterization, not native family admission
// or a preimplementation Red. NativeEnvironment has no custom server trust injection.
public sealed class InfisicalProofMtlsTests
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(15);
    private const string Identity = "8e8d7c09-4ee7-4e61-a8a8-1f6208920c58";

    [Test]
    [Arguments("malformed")]
    [Arguments("empty")]
    [Arguments("oversized-encoded")]
    [Arguments("oversized-decoded")]
    [Arguments("oversized-password")]
    [Arguments("wrong-password")]
    [Arguments("no-private-key")]
    [Arguments("duplicate-leaves")]
    [Arguments("multiple-certificates")]
    [Arguments("multiple-keys")]
    [Arguments("null-packet")]
    [Arguments("null-base64")]
    [Arguments("null-password")]
    public async Task InvalidPacketsFailWithOnlyBoundedMissingInput(string kind)
    {
        using var certificates = new Certificates();
        ProofCertificatePacket accepted = Packet(certificates.Accepted);
        ProofCertificatePacket denied = Packet(certificates.Denied);
        switch (kind)
        {
            case "malformed": accepted = new("not-base64", "private-password"); break;
            case "empty": accepted = new("", ""); break;
            case "oversized-encoded": accepted = new(new string('A', 90 * 1024 + 1), ""); break;
            case "oversized-decoded": accepted = new(Convert.ToBase64String(new byte[64 * 1024 + 1]), ""); break;
            case "oversized-password": accepted = accepted with { Password = new string('p', 1025) }; break;
            case "wrong-password": accepted = accepted with { Password = "wrong-private-password" }; break;
            case "no-private-key":
                using (var leaf = X509CertificateLoader.LoadCertificate(certificates.Accepted.RawData))
                    accepted = Packet(leaf);
                break;
            case "duplicate-leaves": denied = accepted; break;
            case "multiple-certificates":
                using (var leaf = X509CertificateLoader.LoadCertificate(certificates.Denied.RawData))
                    accepted = Packet(new X509Certificate2Collection(new[] { certificates.Accepted, leaf }));
                break;
            case "multiple-keys":
                accepted = Packet(new X509Certificate2Collection(new[] { certificates.Accepted, certificates.Denied }));
                break;
            case "null-packet": accepted = null!; break;
            case "null-base64": accepted = new(null!, ""); break;
            case "null-password": accepted = accepted with { Password = null! }; break;
            default: throw new InvalidOperationException("Unknown characterization.");
        }
        NativeCaseFailureException? failure = null;
        try
        {
            using var unexpected = ProofCertificatePair.Load(accepted, denied);
        }
        catch (NativeCaseFailureException error) { failure = error; }
        await Assert.That(failure is not null).IsTrue();
        await Assert.That(failure!.Message).IsEqualTo("missing-input");
        await Assert.That(failure.InnerException is null).IsTrue();
    }

    [Test]
    public async Task PairOwnsDistinctKeysButHandlersRemainHostOwnedAndTrustIsUnchanged()
    {
        using var certificates = new Certificates();
        ProofCertificatePacket packet = Packet(certificates.Accepted);
        await Assert.That(packet.ToString()).IsEqualTo("[ProofCertificatePacket]");
        using var pair = ProofCertificatePair.Load(packet, Packet(certificates.Denied));
        X509Certificate2 accepted;
        X509Certificate2 denied;
        using (SocketsHttpHandler first = pair.CreateHandler(false))
        using (SocketsHttpHandler fresh = pair.CreateHandler(false))
        using (SocketsHttpHandler other = pair.CreateHandler(true))
        {
            await Assert.That(ReferenceEquals(first, fresh)).IsFalse();
            foreach (SocketsHttpHandler handler in new[] { first, fresh, other })
            {
                await Assert.That(handler.AllowAutoRedirect || handler.UseCookies ||
                    handler.ActivityHeadersPropagator is not null).IsFalse();
                await Assert.That(handler.SslOptions.RemoteCertificateValidationCallback is null).IsTrue();
                await Assert.That(handler.SslOptions.CertificateChainPolicy is null).IsTrue();
                await Assert.That(handler.SslOptions.ClientCertificates!.Count).IsEqualTo(1);
            }
            accepted = (X509Certificate2)first.SslOptions.ClientCertificates![0];
            denied = (X509Certificate2)other.SslOptions.ClientCertificates![0];
            await Assert.That(ReferenceEquals(accepted, fresh.SslOptions.ClientCertificates![0])).IsTrue();
            await Assert.That(accepted.HasPrivateKey && denied.HasPrivateKey).IsTrue();
            await Assert.That(Leaf(accepted)).IsEqualTo(Leaf(certificates.Accepted));
            await Assert.That(Leaf(denied)).IsEqualTo(Leaf(certificates.Denied));
        }
        // Disposing host handlers did not release the pair's keys.
        await Assert.That(accepted.HasPrivateKey && denied.HasPrivateKey).IsTrue();
        pair.Dispose();
        pair.Dispose();
        await Assert.That(accepted.Handle == IntPtr.Zero && denied.Handle == IntPtr.Zero).IsTrue();
        await Assert.That(() => pair.CreateHandler(false)).Throws<ObjectDisposedException>();
        await Assert.That(certificates.Accepted.HasPrivateKey && certificates.Denied.HasPrivateKey).IsTrue();
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(false, true)]
    [Arguments(true, false)]
    [Arguments(true, true)]
    public async Task ActualTlsLeafSelectsLoginOrApplicationDenial(bool denied, bool organization)
    {
        using var certificates = new Certificates();
        using var pair = ProofCertificatePair.Load(Packet(certificates.Accepted), Packet(certificates.Denied));
        await using var server = new TlsServer(certificates);
        using SocketsHttpHandler handler = TrustedHandler(pair, denied, certificates);
        string? slug = organization ? "fixture-organization" : null;
        using var proof = InfisicalLoginProof.TlsCertificate(Identity, slug);
        for (int iteration = 0; iteration < 2; iteration++)
        {
            // The second SDK instance uses the very same host handler after the first
            // SDK instance is disposed, proving ownership through another TLS exchange.
            using var authentication = new InfisicalProofAuthentication(server.Origin,
                new() { Transport = InfisicalTransportOptions.HostControlled(handler) });
            var receipt = authentication.CreateReceipt();
            Exchange exchange = server.Arm(ResponseMode.Complete);
            Task<SecretOutcome<InfisicalProofLogin>> pending = authentication.LoginAsync(proof, receipt).AsTask();
            await ObserveAsync(exchange, certificates, denied, slug);
            await Assert.That(await exchange.Committed.Task.WaitAsync(Deadline)).IsEqualTo(!denied);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            exchange.ReleaseHeaders.SetResult();
            await exchange.HeadersReleased.Task.WaitAsync(Deadline);
            SecretOutcome<InfisicalProofLogin> outcome = await pending.WaitAsync(Deadline);
            using (InfisicalProofLogin? issued = outcome.IsSuccess ? outcome.Value : null)
            {
                await Assert.That(outcome.Status).IsEqualTo(denied ? SecretStatus.Denied : SecretStatus.Success);
                await Assert.That(receipt.Evidence).IsEqualTo(denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied);
                if (issued is not null)
                {
                    await Assert.That(issued.Token.Material.Reveal()).IsEqualTo("fixture-token");
                    await Assert.That(issued.ExpiresIn).IsEqualTo(600);
                }
            }
            if (outcome.IsSuccess)
                await Assert.That(() => outcome.Value.Token.Material.Reveal()).Throws<ObjectDisposedException>();
            await exchange.Finished.WaitAsync(Deadline);
            var replay = await authentication.LoginAsync(proof, receipt);
            using InfisicalProofLogin? unexpected = replay.IsSuccess ? replay.Value : null;
            await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(server.Requests).IsEqualTo(iteration + 1);
        }
    }

    [Test]
    [Arguments("cancel-before-headers")]
    [Arguments("cancel-after-headers")]
    [Arguments("lost-before-headers")]
    [Arguments("lost-after-headers")]
    public async Task CommittedLoginWithInterruptedResponseRetainsUncertaintyAndCannotReplay(string interruption)
    {
        using var certificates = new Certificates();
        using var pair = ProofCertificatePair.Load(Packet(certificates.Accepted), Packet(certificates.Denied));
        await using var server = new TlsServer(certificates);
        using SocketsHttpHandler handler = TrustedHandler(pair, false, certificates);
        using var authentication = new InfisicalProofAuthentication(server.Origin,
            new() { Transport = InfisicalTransportOptions.HostControlled(handler) });
        using var proof = InfisicalLoginProof.TlsCertificate(Identity);
        using var cancellation = new CancellationTokenSource();
        var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenRegistration registration = cancellation.Token.Register(() => canceled.TrySetResult());
        var receipt = authentication.CreateReceipt();
        bool cancel = interruption.StartsWith("cancel", StringComparison.Ordinal);
        bool afterHeaders = interruption.EndsWith("after-headers", StringComparison.Ordinal);
        Exchange exchange = server.Arm(afterHeaders ? ResponseMode.HoldBody : ResponseMode.Drop);
        Task<SecretOutcome<InfisicalProofLogin>> pending = authentication.LoginAsync(proof, receipt, cancellation.Token).AsTask();
        await ObserveAsync(exchange, certificates, false, null);
        await Assert.That(await exchange.Committed.Task.WaitAsync(Deadline)).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        if (afterHeaders)
        {
            exchange.ReleaseHeaders.SetResult();
            await exchange.HeadersReleased.Task.WaitAsync(Deadline);
        }
        if (cancel)
        {
            cancellation.Cancel();
            await canceled.Task.WaitAsync(Deadline);
            await Assert.That(async () =>
            {
                var unexpected = await pending.WaitAsync(Deadline);
                if (unexpected.IsSuccess) unexpected.Value.Dispose();
            }).Throws<OperationCanceledException>();
        }
        if (!afterHeaders) exchange.ReleaseHeaders.SetResult();
        exchange.Close.SetResult();
        await exchange.Finished.WaitAsync(Deadline);
        if (!cancel)
        {
            var outcome = await pending.WaitAsync(Deadline);
            using InfisicalProofLogin? unexpected = outcome.IsSuccess ? outcome.Value : null;
            await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Unknown);
        }
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        var replay = await authentication.LoginAsync(proof, receipt);
        using InfisicalProofLogin? replayToken = replay.IsSuccess ? replay.Value : null;
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(server.Requests).IsEqualTo(1);
        await Assert.That(server.Commits).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task TlsServerExplicitlyRejectsMissingAndUnexpectedLeaves(bool unexpected)
    {
        using var certificates = new Certificates();
        // Server certificate also has a key but is not either accepted client leaf.
        using var pair = ProofCertificatePair.Load(Packet(certificates.Server), Packet(certificates.Denied));
        await using var server = new TlsServer(certificates);
        using SocketsHttpHandler handler = TrustedHandler(pair, false, certificates);
        if (!unexpected) handler.SslOptions.ClientCertificates!.Clear();
        // Force presentation of the unexpected leaf regardless of its server-only EKU.
        if (unexpected)
            handler.SslOptions.LocalCertificateSelectionCallback = (_, _, _, _, _) => certificates.Server;
        using var authentication = new InfisicalProofAuthentication(server.Origin,
            new() { Transport = InfisicalTransportOptions.HostControlled(handler) });
        using var proof = InfisicalLoginProof.TlsCertificate(Identity);
        Exchange exchange = server.Arm(ResponseMode.Complete);
        var receipt = authentication.CreateReceipt();
        var outcome = await authentication.LoginAsync(proof, receipt).AsTask().WaitAsync(Deadline);
        using InfisicalProofLogin? token = outcome.IsSuccess ? outcome.Value : null;
        await exchange.Finished.WaitAsync(Deadline);
        await Assert.That(await exchange.TlsLeaf.Task.WaitAsync(Deadline))
            .IsEqualTo(unexpected ? Leaf(certificates.Server) : "<missing>");
        await Assert.That(exchange.TlsRejected).IsTrue();
        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(server.Requests).IsEqualTo(0);
        await Assert.That(server.Commits).IsEqualTo(0);
    }

    private static SocketsHttpHandler TrustedHandler(ProofCertificatePair pair, bool denied, Certificates certificates)
    {
        SocketsHttpHandler handler = pair.CreateHandler(denied);
        // Test-only exact leaf pin, never a production helper trust bypass.
        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
            certificate is not null && Leaf(certificate) == Leaf(certificates.Server);
        return handler;
    }

    private static async Task ObserveAsync(Exchange exchange, Certificates certificates, bool denied, string? slug)
    {
        await Assert.That(await exchange.TlsLeaf.Task.WaitAsync(Deadline))
            .IsEqualTo(Leaf(denied ? certificates.Denied : certificates.Accepted));
        RequestObservation request = await exchange.Consumed.Task.WaitAsync(Deadline);
        await Assert.That(request.Route).IsEqualTo("POST /api/v1/auth/tls-cert-auth/login HTTP/1.1");
        await Assert.That(request.Headers["Content-Type"]).IsEqualTo("application/json");
        await Assert.That(request.Headers.Keys.Any(name =>
            name.Contains("cert", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("proof", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Cookie", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("traceparent", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("tracestate", StringComparison.OrdinalIgnoreCase))).IsFalse();
        using JsonDocument json = JsonDocument.Parse(request.Body);
        await Assert.That(json.RootElement.EnumerateObject().Count()).IsEqualTo(slug is null ? 1 : 2);
        await Assert.That(json.RootElement.GetProperty("identityId").GetString()).IsEqualTo(Identity);
        if (slug is not null)
            await Assert.That(json.RootElement.GetProperty("organizationSlug").GetString()).IsEqualTo(slug);
    }

    private enum ResponseMode { Complete, Drop, HoldBody }

    private sealed record RequestObservation(string Route, Dictionary<string, string> Headers, byte[] Body);

    private sealed class Exchange
    {
        internal TaskCompletionSource<string> TlsLeaf { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<RequestObservation> Consumed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<bool> Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource ReleaseHeaders { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource HeadersReleased { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Close { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task Finished { get; set; } = Task.CompletedTask;
        internal bool TlsRejected { get; set; }
    }

    private sealed class TlsServer : IAsyncDisposable
    {
        private readonly Certificates _certificates;
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _shutdown = new();
        private readonly List<Task> _exchanges = [];
        internal int Requests { get; private set; }
        internal int Commits { get; private set; }
        internal Uri Origin { get; }

        internal TlsServer(Certificates certificates)
        {
            _certificates = certificates;
            _listener.Start();
            Origin = new Uri($"https://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/");
        }

        internal Exchange Arm(ResponseMode mode)
        {
            var exchange = new Exchange();
            exchange.Finished = ServeAsync(exchange, mode);
            _exchanges.Add(exchange.Finished);
            return exchange;
        }

        private async Task ServeAsync(Exchange exchange, ResponseMode mode)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token);
            deadline.CancelAfter(Deadline);
            CancellationToken token = deadline.Token;
            using TcpClient client = await _listener.AcceptTcpClientAsync(token);
            using var stream = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
            try
            {
                await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _certificates.Server,
                    ClientCertificateRequired = true,
                    AllowTlsResume = false,
                    EnabledSslProtocols = SslProtocols.Tls12,
                    RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                    {
                        string leaf = certificate is null ? "<missing>" : Leaf(certificate);
                        exchange.TlsLeaf.TrySetResult(leaf);
                        return certificate is not null &&
                            (leaf == Leaf(_certificates.Accepted) || leaf == Leaf(_certificates.Denied));
                    }
                }, token);
            }
            catch (AuthenticationException)
            {
                exchange.TlsRejected = true;
                return;
            }
            // ClientCertificateRequired only asks; verify again before reading HTTP.
            if (stream.RemoteCertificate is null ||
                Leaf(stream.RemoteCertificate) != Leaf(_certificates.Accepted) &&
                Leaf(stream.RemoteCertificate) != Leaf(_certificates.Denied))
                throw new InvalidOperationException("TLS admitted a missing or unexpected client.");
            RequestObservation request = await ReadRequestAsync(stream, token);
            Requests++;
            exchange.Consumed.SetResult(request);
            bool accepted = Leaf(stream.RemoteCertificate) == Leaf(_certificates.Accepted);
            if (accepted) Commits++;
            exchange.Committed.SetResult(accepted);
            await exchange.ReleaseHeaders.Task.WaitAsync(token);
            if (mode == ResponseMode.Drop) return;
            byte[] body = Encoding.UTF8.GetBytes(accepted
                ? """{"accessToken":"fixture-token","tokenType":"Bearer","expiresIn":600,"accessTokenMaxTTL":1200}"""
                : "{}");
            string status = accepted ? "200 OK" : "403 Forbidden";
            byte[] headers = Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(headers, token);
            await stream.FlushAsync(token);
            exchange.HeadersReleased.SetResult();
            if (mode == ResponseMode.HoldBody)
            {
                await exchange.Close.Task.WaitAsync(token);
                return;
            }
            await stream.WriteAsync(body, token);
            await stream.FlushAsync(token);
        }

        private static async Task<RequestObservation> ReadRequestAsync(SslStream stream, CancellationToken token)
        {
            var header = new List<byte>();
            byte[] next = new byte[1];
            while (header.Count < 8192)
            {
                await stream.ReadExactlyAsync(next, token);
                header.Add(next[0]);
                int count = header.Count;
                if (count >= 4 && header[count - 4] == 13 && header[count - 3] == 10 &&
                    header[count - 2] == 13 && header[count - 1] == 10) break;
            }
            if (header.Count == 8192) throw new InvalidOperationException("HTTP headers exceed fixture budget.");
            string[] lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n", StringSplitOptions.None);
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string line in lines.Skip(1).Where(line => line.Length > 0))
            {
                int separator = line.IndexOf(':');
                if (separator < 1) throw new InvalidOperationException("Invalid fixture HTTP header.");
                headers.Add(line[..separator], line[(separator + 1)..].Trim());
            }
            int length = int.Parse(headers["Content-Length"], CultureInfo.InvariantCulture);
            if (length is < 1 or > 1024) throw new InvalidOperationException("HTTP body exceeds fixture budget.");
            byte[] body = new byte[length];
            await stream.ReadExactlyAsync(body, token);
            return new(lines[0], headers, body);
        }

        public async ValueTask DisposeAsync()
        {
            _shutdown.Cancel();
            _listener.Stop();
            try { await Task.WhenAll(_exchanges).WaitAsync(Deadline); }
            catch (OperationCanceledException) when (_shutdown.IsCancellationRequested) { }
            finally { _shutdown.Dispose(); }
        }
    }

    private static string Leaf(X509Certificate certificate) => certificate.GetCertHashString(HashAlgorithmName.SHA256);

    private static ProofCertificatePacket Packet(X509Certificate2 certificate) =>
        Packet(new X509Certificate2Collection(certificate));

    private static ProofCertificatePacket Packet(X509Certificate2Collection certificates)
    {
        byte[] bytes = certificates.Export(X509ContentType.Pkcs12, "fixture-password")!;
        try { return new(Convert.ToBase64String(bytes), "fixture-password"); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private sealed class Certificates : IDisposable
    {
        internal X509Certificate2 Server { get; } = Create("server", server: true);
        internal X509Certificate2 Accepted { get; } = Create("accepted", server: false);
        internal X509Certificate2 Denied { get; } = Create("denied", server: false);

        private static X509Certificate2 Create(string name, bool server)
        {
            using RSA key = RSA.Create(2048);
            var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new(server ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") }, true));
            if (server)
            {
                var names = new SubjectAlternativeNameBuilder();
                names.AddIpAddress(IPAddress.Loopback);
                request.CertificateExtensions.Add(names.Build());
            }
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        }

        public void Dispose()
        {
            Server.Dispose();
            Accepted.Dispose();
            Denied.Dispose();
        }
    }
}
