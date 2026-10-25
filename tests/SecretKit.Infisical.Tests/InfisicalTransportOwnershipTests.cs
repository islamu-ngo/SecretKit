using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class InfisicalTransportOwnershipTests
{
    [Test]
    [Arguments(200)]
    [Arguments(403)]
    [Arguments(500)]
    public async Task NativeHttpDiagnosticsCannotDiscloseProtectedCoordinatesOrMaterial(int code)
    {
        string canary = "synthetic-http-diagnostic-" + Guid.NewGuid().ToString("N");
        using var capture = new DiagnosticCapture();
        string probe = Guid.NewGuid().ToString("N");
        using (var source = new ActivitySource("SecretKitBoundaryProbe"))
        using (Activity? activity = source.StartActivity("probe"))
            activity?.SetTag("probe", probe);
        using (var meter = new Meter("SecretKitBoundaryProbe"))
            meter.CreateCounter<int>("probe").Add(1, new KeyValuePair<string, object?>("probe", probe));
        using (var diagnostic = new DiagnosticListener("SecretKitBoundaryProbe"))
        using (var request = new HttpRequestMessage(HttpMethod.Get, "https://probe.invalid/"))
        {
            request.Headers.Authorization = new("Bearer", probe);
            diagnostic.Write("probe", new { Probe = probe, Request = request });
        }
        await Assert.That(capture.Activities.Contains(probe)).IsTrue();
        await Assert.That(capture.Measurements.Contains(probe)).IsTrue();
        await Assert.That(capture.Events.Any(value => value.Contains(probe, StringComparison.Ordinal))).IsTrue();
        await Assert.That(capture.Events.Any(value => value.Contains("Bearer " + probe,
            StringComparison.Ordinal))).IsTrue();

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var origin = new Uri($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        string body = code == 200 ? JsonSerializer.Serialize(new
        {
            secret = new
            {
                id = canary,
                workspace = canary,
                environment = canary,
                secretPath = "/" + canary,
                type = "shared",
                secretKey = canary,
                version = 1,
                secretValue = canary,
                secretValueHidden = false
            }
        }) : JsonSerializer.Serialize(new { message = canary });
        Task<bool> response = RespondAsync(listener, $"{code} Result", body, deadline.Token);
        await using var client = new InfisicalClient(origin, new DiagnosticTokens(canary),
            new() { AllowLoopbackDevelopmentHttp = true });
        var result = await client.ReadAsync(new(client.Authority,
            new InfisicalSecretAddress(canary, canary, "/" + canary, canary)), deadline.Token);
        if (result.IsSuccess) result.Value.Dispose();
        await response;
        await Assert.That(result.Status).IsEqualTo(code switch
        {
            200 => SecretStatus.Success,
            403 => SecretStatus.Denied,
            _ => SecretStatus.Unavailable
        });
        foreach (string observation in capture.Activities.Concat(capture.Measurements).Concat(capture.Events))
        {
            await Assert.That(observation.Contains(canary, StringComparison.Ordinal)).IsFalse();
            await Assert.That(observation.Contains(origin.AbsoluteUri, StringComparison.Ordinal)).IsFalse();
        }
    }

    private sealed class DiagnosticTokens(string value) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText(value))));
        }
    }

    private sealed class DiagnosticCapture : IDisposable,
        IObserver<DiagnosticListener>, IObserver<KeyValuePair<string, object?>>
    {
        internal ConcurrentQueue<string> Activities { get; } = new();
        internal ConcurrentQueue<string> Measurements { get; } = new();
        internal ConcurrentQueue<string> Events { get; } = new();
        private readonly ConcurrentBag<IDisposable> _subscriptions = [];
        private readonly ActivityListener _activities;
        private readonly MeterListener _metrics = new();
        private readonly IDisposable _diagnostics;

        internal DiagnosticCapture()
        {
            _activities = new()
            {
                ShouldListenTo = _ => true,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStopped = activity =>
                {
                    foreach (var tag in activity.TagObjects)
                        Activities.Enqueue(tag.Value?.ToString() ?? "");
                    foreach (var baggage in activity.Baggage)
                        Activities.Enqueue(baggage.Value ?? "");
                }
            };
            ActivitySource.AddActivityListener(_activities);
            _metrics.InstrumentPublished = (instrument, listener) => listener.EnableMeasurementEvents(instrument);
            _metrics.SetMeasurementEventCallback<int>((_, _, tags, _) =>
            {
                foreach (var tag in tags) Measurements.Enqueue(tag.Value?.ToString() ?? "");
            });
            _metrics.SetMeasurementEventCallback<double>((_, _, tags, _) =>
            {
                foreach (var tag in tags) Measurements.Enqueue(tag.Value?.ToString() ?? "");
            });
            _metrics.SetMeasurementEventCallback<long>((_, _, tags, _) =>
            {
                foreach (var tag in tags) Measurements.Enqueue(tag.Value?.ToString() ?? "");
            });
            _metrics.Start();
            _diagnostics = DiagnosticListener.AllListeners.Subscribe(this);
        }

        public void OnNext(DiagnosticListener listener)
        {
            if (listener.Name is "HttpHandlerDiagnosticListener" or "SecretKitBoundaryProbe")
                _subscriptions.Add(listener.Subscribe(this));
        }
        public void OnNext(KeyValuePair<string, object?> value)
        {
            object? payload = value.Value;
            Events.Enqueue(payload?.ToString() ?? "");
            // Default HTTP event DTOs need not override ToString; inspect their public payload members.
            foreach (string member in new[] { "Request", "Response", "Exception" })
                if (payload?.GetType().GetProperty(member)?.GetValue(payload) is { } part)
                    Events.Enqueue(part.ToString() ?? "");
        }
        public void OnCompleted() { }
        public void OnError(Exception error) => throw new InvalidOperationException("Diagnostic capture failed.");
        public void Dispose()
        {
            _diagnostics.Dispose();
            foreach (IDisposable subscription in _subscriptions) subscription.Dispose();
            _activities.Dispose();
            _metrics.Dispose();
        }
    }

    [Test]
    [Arguments("redirect")]
    [Arguments("cookies")]
    [Arguments("activity")]
    [Arguments("certificate-callback")]
    [Arguments("chain-bypass")]
    public async Task UnsafeHostConfigurationIsRejectedBeforeCredentials(string fault)
    {
        using var handler = SafeHandler();
        switch (fault)
        {
            case "redirect": handler.AllowAutoRedirect = true; break;
            case "cookies": handler.UseCookies = true; break;
            case "activity": handler.ActivityHeadersPropagator = System.Diagnostics.DistributedContextPropagator.Current; break;
            case "certificate-callback": handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true; break;
            case "chain-bypass":
                handler.SslOptions.CertificateChainPolicy = new()
                {
                    VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority
                };
                break;
        }

        await Assert.That(() => new InfisicalClient(new("https://selected.test"), handler, new ForbiddenTokens()))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task HostTransportRemainsUsableAfterClientShutdown()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var origin = new Uri($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        using var handler = SafeHandler();
        var client = new InfisicalClient(origin, handler, new Tokens(),
            new() { AllowLoopbackDevelopmentHttp = true });
        Task<bool> firstServer = RespondAsync(listener, "200 OK", NativeBody, deadline.Token);
        using InfisicalSecretRead read = (await client.ReadNativeAsync(Reference(client), deadline.Token)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(await firstServer).IsTrue();
        await client.DisposeAsync();

        Task<bool> secondServer = RespondAsync(listener, "200 OK", "{}", deadline.Token);
        using var hostClient = new HttpClient(handler, disposeHandler: false);
        using HttpResponseMessage response = await hostClient.GetAsync(origin, deadline.Token);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(await secondServer).IsFalse();
        await client.DisposeAsync();
    }

    [Test]
    public async Task RedirectDoesNotForwardSelectedCredentials()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var foreign = new TcpListener(IPAddress.Loopback, 0);
        foreign.Start();
        string location = $"http://127.0.0.1:{((IPEndPoint)foreign.LocalEndpoint).Port}/foreign";
        using var foreignStop = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
        Task<TcpClient> foreignConnection = foreign.AcceptTcpClientAsync(foreignStop.Token).AsTask();
        Task<bool> server = RespondAsync(listener, "302 Found", "", deadline.Token, location);
        using var handler = SafeHandler();
        await using var client = new InfisicalClient(
            new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/"), handler, new Tokens(),
            new() { AllowLoopbackDevelopmentHttp = true });

        var result = await client.ReadAsync(Reference(client), deadline.Token);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(await server).IsTrue();
        await Assert.That(foreignConnection.IsCompleted).IsFalse();
        foreignStop.Cancel();
        await Assert.That(async () => await foreignConnection).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task CallerCancellationReachesStalledTokenAcquisition()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var caller = new CancellationTokenSource();
        await using var client = new InfisicalClient(new("https://selected.test"), new StalledTokens(entered),
            new(), null, new ForbiddenWire());
        Task<SecretOutcome<SecretRead>> pending = client.ReadAsync(Reference(client), caller.Token).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        caller.Cancel();
        await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)))
            .Throws<OperationCanceledException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CallerOrShutdownCancellationReachesStalledBody(bool shutdown)
    {
        using var caller = new CancellationTokenSource();
        var body = new StalledBody();
        var client = new InfisicalClient(new("https://selected.test"), new Tokens(), new(), null, new BodyWire(body));
        try
        {
            Task<SecretOutcome<InfisicalSecretRead>> pending = client.ReadNativeAsync(Reference(client), caller.Token).AsTask();
            await body.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            if (shutdown) await client.DisposeAsync();
            else caller.Cancel();
            await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)))
                .Throws<OperationCanceledException>();
            await Assert.That(body.Disposed).IsTrue();
        }
        finally
        {
            await client.DisposeAsync();
        }
    }

    private static SocketsHttpHandler SafeHandler() => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        ActivityHeadersPropagator = null,
        UseProxy = false
    };

    private const string NativeBody = """
        {"secret":{"id":"resource","workspace":"project","environment":"test","secretPath":"/","type":"shared","secretKey":"key","version":1,"secretValue":"material-canary","secretValueHidden":false}}
        """;

    private static SecretReference Reference(InfisicalClient client) =>
        new(client.Authority, new InfisicalSecretAddress("project", "test", "/", "key"));

    private static async Task<bool> RespondAsync(TcpListener listener, string status, string body,
        CancellationToken token, string? location = null)
    {
        using TcpClient connection = await listener.AcceptTcpClientAsync(token);
        using NetworkStream stream = connection.GetStream();
        using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
        bool authorized = false;
        while (await reader.ReadLineAsync(token) is { Length: > 0 } line)
            authorized |= line == "Authorization: Bearer token-canary";
        byte[] payload = Encoding.UTF8.GetBytes(body);
        string headers = $"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {payload.Length}\r\nConnection: close\r\n";
        if (location is not null) headers += $"Location: {location}\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(headers + "\r\n"), token);
        await stream.WriteAsync(payload, token);
        return authorized;
    }

    private sealed class ForbiddenTokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Unsafe configuration acquired credentials.");
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("token-canary"))));
    }

    private sealed class StalledTokens(TaskCompletionSource entered) : IInfisicalTokenSource
    {
        public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            var completion = new TaskCompletionSource<SecretOutcome<InfisicalAccessToken>>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            entered.TrySetResult();
            return await completion.Task.WaitAsync(cancellationToken);
        }
    }

    private sealed class ForbiddenWire : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Stalled credentials dispatched.");
    }

    private sealed class BodyWire(StalledBody body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(body) });
    }

    private sealed class StalledBody : Stream
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool Disposed { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var completion = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            Entered.TrySetResult();
            return await completion.Task.WaitAsync(cancellationToken);
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
}
