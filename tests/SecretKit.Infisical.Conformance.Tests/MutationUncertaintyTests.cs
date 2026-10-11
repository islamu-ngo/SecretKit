using System.Net;
using System.Net.Sockets;
using System.Text;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class MutationUncertaintyTests
{
    [Test]
    public async Task RedirectResponseCannotDeliverMaterialFromASecondOrigin()
    {
        using var first = new TcpListener(IPAddress.Loopback, 0);
        using var second = new TcpListener(IPAddress.Loopback, 0);
        first.Start();
        second.Start();
        int firstPort = ((IPEndPoint)first.LocalEndpoint).Port;
        int secondPort = ((IPEndPoint)second.LocalEndpoint).Port;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var sinkCancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
        Task initial = RespondOnce(first,
            $"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{secondPort}/redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            deadline.Token);
        const string body = """{"secret":{"secretKey":"fixture","secretValue":"redirect-canary","secretValueHidden":false,"version":1}}""";
        Task sink = RespondOnce(second,
            $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {Encoding.ASCII.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}",
            sinkCancellation.Token);
        await using var client = new InfisicalClient(new Uri($"http://127.0.0.1:{firstPort}"), new FixtureTokens(),
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        try
        {
            var result = await client.ReadAsync(new SecretReference(client.Authority,
                new InfisicalSecretAddress("project", "dev", "/", "fixture")), deadline.Token);
            // The second origin would return valid material if the SDK followed the redirect.
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
            await initial;
        }
        finally
        {
            sinkCancellation.Cancel();
            try { await sink; }
            catch (OperationCanceledException) { }
        }

        static async Task RespondOnce(TcpListener listener, string response, CancellationToken cancellationToken)
        {
            using TcpClient connection = await listener.AcceptTcpClientAsync(cancellationToken);
            await using NetworkStream stream = connection.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            int budget = 16384;
            while (await reader.ReadLineAsync(cancellationToken) is { Length: > 0 } line)
            {
                budget -= line.Length;
                if (budget < 0) throw new InvalidOperationException("Owned redirect fixture exceeded its header budget.");
            }
            await stream.WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken);
        }
    }

    [Test]
    public async Task RealNativeEffectsRemainDistinctFromCanceledOrLostResponses() =>
        await IdentitySetupTests.RunAsync(OwnedConformanceScenario.DispatchEffects);

    internal static async Task VerifyAsync(Uri origin, IInfisicalTokenSource tokens, string project,
        CancellationToken cancellationToken)
    {
        await using var inspection = new InfisicalClient(origin, tokens,
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        using var material = SecretMaterial.FromText("owned-\u00e9\n\U0001f600-" + Guid.NewGuid().ToString("N"));
        foreach (bool cancelAfterCommit in new[] { true, false })
        {
            string key = "SDK_UNCERTAIN_" + Guid.NewGuid().ToString("N");
            using var proxy = new DropResponseProxy(origin, key);
            await using var client = new InfisicalClient(proxy.Origin, tokens,
                new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
            var target = new SecretReference(client.Authority, new InfisicalSecretAddress(project, "dev", "/", key));
            var receipt = new MutationReceipt(target);
            using var preCanceled = new CancellationTokenSource();
            preCanceled.Cancel();
            await Assert.That(async () => await client.CreateAsync(target, material, receipt, preCanceled.Token))
                .Throws<OperationCanceledException>();
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
            var inspectionTarget = new SecretReference(inspection.Authority,
                new InfisicalSecretAddress(project, "dev", "/", key));
            await Assert.That((await inspection.ReadAsync(inspectionTarget, cancellationToken)).Status)
                .IsEqualTo(SecretStatus.Absent);

            // Both signals exist before the mutation is triggered; no sleep or polling.
            Task committed = proxy.Committed.Task;
            Task wire = proxy.ForwardOneAsync(cancelAfterCommit, cancellationToken);
            using var cancel = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            Task<SecretOutcome<InfisicalStaticChange>> pending =
                client.CreateAsync(target, material, receipt, cancel.Token).AsTask();
            try
            {
                await committed.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken);
                if (cancelAfterCommit)
                {
                    cancel.Cancel();
                    await Assert.That(async () => await pending).Throws<OperationCanceledException>();
                }
                else await Assert.That((await pending).Status).IsEqualTo(SecretStatus.Unknown);
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
                var observed = await inspection.ReadAsync(inspectionTarget, cancellationToken);
                await Assert.That(observed.Status).IsEqualTo(SecretStatus.Success);
                using var read = observed.Value;
                // Plaintext is compared privately; an assertion failure never prints either value.
                await Assert.That(read.Material.Reveal() == material.Reveal()).IsTrue();
                await Assert.That((await client.CreateAsync(target, material, receipt, cancellationToken)).Status)
                    .IsEqualTo(SecretStatus.Invalid);
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
                await Assert.That(proxy.CommittedWrites).IsEqualTo(1);
            }
            finally
            {
                proxy.Release.TrySetResult();
                await wire;
            }
        }
        Console.WriteLine("OWNED_NATIVE_COMMIT_AND_DISPATCH_UNCERTAINTY_PASSED");
    }

    private sealed class FixtureTokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText(Guid.NewGuid().ToString("N")))));
        }
    }

    /// <summary>Test-only one-write loopback fault boundary, not an arbitrary SDK transport.</summary>
    private sealed class DropResponseProxy : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly Uri _upstream;
        private readonly string _path;
        internal DropResponseProxy(Uri upstream, string key)
        {
            if (upstream.Scheme != "http" || upstream.Host != "127.0.0.1")
                throw new InvalidOperationException("The fault target must be the owned loopback service.");
            _upstream = upstream;
            _path = "/api/v4/secrets/" + key;
            _listener.Start();
            Origin = new Uri($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}");
        }
        internal Uri Origin { get; }
        internal TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int CommittedWrites { get; private set; }

        internal async Task ForwardOneAsync(bool hold, CancellationToken cancellationToken)
        {
            byte[] headers = new byte[16384];
            byte[]? payload = null;
            try
            {
                using TcpClient connection = await _listener.AcceptTcpClientAsync(cancellationToken);
                await using NetworkStream stream = connection.GetStream();
                int length = 0;
                while (length < headers.Length)
                {
                    await stream.ReadExactlyAsync(headers.AsMemory(length, 1), cancellationToken);
                    length++;
                    if (length >= 4 && headers[length - 4] == '\r' && headers[length - 3] == '\n' &&
                        headers[length - 2] == '\r' && headers[length - 1] == '\n') break;
                }
                if (length == headers.Length) throw new InvalidOperationException("Fault request headers exceeded the budget.");
                string[] lines = Encoding.ASCII.GetString(headers, 0, length).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                string[] requestLine = lines[0].Split(' ');
                if (requestLine.Length != 3 || requestLine[0] != "POST" || requestLine[1] != _path)
                    throw new InvalidOperationException("Fault request did not match the selected native write.");
                string? authorization = null;
                int? contentLength = null;
                foreach (string line in lines.Skip(1))
                {
                    if (line.StartsWith("Authorization: ", StringComparison.OrdinalIgnoreCase)) authorization = line[15..];
                    if (line.StartsWith("Content-Length: ", StringComparison.OrdinalIgnoreCase) &&
                        int.TryParse(line[16..], out int size)) contentLength = size;
                }
                if (authorization is null || contentLength is not > 0 or > 65536)
                    throw new InvalidOperationException("Fault request lacked bounded selected input.");
                payload = new byte[contentLength.Value];
                await stream.ReadExactlyAsync(payload, cancellationToken);
                using var handler = new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    UseCookies = false,
                    ActivityHeadersPropagator = null
                };
                using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
                using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_upstream, _path));
                request.Headers.TryAddWithoutValidation("Authorization", authorization);
                request.Content = new ByteArrayContent(payload);
                request.Content.Headers.ContentType = new("application/json");
                using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new InvalidOperationException("Owned fault write did not return the expected native status.");
                CommittedWrites++;
                Committed.TrySetResult();
                if (hold) await Release.Task.WaitAsync(cancellationToken);
                // Intentionally omit the response after observing the upstream's applied acknowledgement.
            }
            catch (Exception error)
            {
                // No request, token, response body or remote exception text enters a test failure.
                Committed.TrySetException(new InvalidOperationException("Owned fault dispatch failed."));
                if (error is OperationCanceledException) throw new OperationCanceledException("Owned fault canceled.", cancellationToken);
                throw new InvalidOperationException("Owned fault dispatch failed.");
            }
            finally
            {
                Array.Clear(headers);
                if (payload is not null) Array.Clear(payload);
            }
        }
        public void Dispose() => _listener.Stop();
        public override string ToString() => "[OwnedDropResponseProxy]";
    }
}
