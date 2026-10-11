using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Extensions.Hosting;
using SecretKit.Infisical;

namespace SecretKit.Hosting.Tests;

public sealed class TokenMaintenanceTests
{
    private static readonly DateTimeOffset Epoch = new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ConcurrentRenewalUsesNativeBodyAndIndependentWaiterCancellation()
    {
        var time = new ManualTime(Epoch);
        var entered = Signal();
        var response = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        string? supplied = null;
        await using var session = Session(time, new Wire(async (request, token) =>
        {
            await Assert.That(request.Method).IsEqualTo(HttpMethod.Post);
            await Assert.That(request.RequestUri!.AbsolutePath).IsEqualTo("/api/v1/auth/token/renew");
            await Assert.That(request.Headers.Authorization).IsNull();
            using var body = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
            supplied = body.RootElement.GetProperty("accessToken").GetString();
            if (!entered.TrySetResult()) throw new InvalidOperationException("A duplicate request was dispatched.");
            return await response.Task.WaitAsync(token);
        }));
        using var waiter = new CancellationTokenSource();
        Task<SecretStatus> first = session.RenewAsync(waiter.Token).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var receipt = session.LastRenewal!;
        Task<SecretStatus> second = session.RenewAsync().AsTask();

        waiter.Cancel();
        await Assert.That(async () => await first).Throws<OperationCanceledException>();
        response.SetResult(Json("replacement"));
        await Assert.That(await second).IsEqualTo(SecretStatus.Success);

        await Assert.That(supplied).IsEqualTo("bootstrap-copy");
        await Assert.That(receipt.Evidence).IsEqualTo(InfisicalRenewalEvidence.Applied);
        using var copy1 = (await session.GetTokenAsync(CancellationToken.None)).Value;
        using var copy2 = (await session.GetTokenAsync(CancellationToken.None)).Value;
        copy1.Dispose();
        await Assert.That(copy2.Material.Reveal()).IsEqualTo("replacement");
    }

    [Test]
    public async Task IdlePeriodicSessionRenewsOnlyAfterExplicitStartBeyondReportedMaxTtl()
    {
        var time = new ManualTime(Epoch);
        await using var session = Session(time, new Wire((_, _) => Task.FromResult(Json("periodic"))),
            InfisicalTokenLifetime.Periodic);
        await using var helper = new InfisicalAuthenticationMaintenance(session, TimeSpan.FromSeconds(5));
        await Assert.That(helper.State).IsEqualTo(AuthenticationMaintenanceState.NotStarted);
        using var initial = (await session.GetTokenAsync(CancellationToken.None)).Value;
        await Assert.That(session.LastRenewal).IsNull();
        Task scheduled = time.WatchTimer(Epoch.AddSeconds(50));

        await helper.StartAsync(CancellationToken.None);
        await scheduled.WaitAsync(TimeSpan.FromSeconds(5));
        for (int due = 50; due <= 150; due += 50)
        {
            Task next = time.WatchTimer(Epoch.AddSeconds(due + 50));
            time.Advance(TimeSpan.FromSeconds(50));
            await next.WaitAsync(TimeSpan.FromSeconds(5));
        }

        using var current = (await session.GetTokenAsync(CancellationToken.None)).Value;
        await Assert.That(current.ExpiresAt).IsEqualTo(Epoch.AddSeconds(210));
        await Assert.That(current.Material.Reveal()).IsEqualTo("periodic");
        await Assert.That(helper.State).IsEqualTo(AuthenticationMaintenanceState.Ready);
    }

    [Test]
    public async Task FiniteLifetimeNeverResetsAtRenewal()
    {
        var time = new ManualTime(Epoch);
        await using var session = Session(time, new Wire((_, _) => Task.FromResult(Json("renewed", expiry: 90))));
        time.Advance(TimeSpan.FromSeconds(50));

        await Assert.That(await session.RenewAsync()).IsEqualTo(SecretStatus.Success);

        using var copy = (await session.GetTokenAsync(CancellationToken.None)).Value;
        await Assert.That(copy.ExpiresAt).IsEqualTo(Epoch.AddSeconds(120));
        time.Advance(TimeSpan.FromSeconds(70));
        await Assert.That((await session.GetTokenAsync(CancellationToken.None)).Status)
            .IsEqualTo(SecretStatus.RecoveryRequired);
        await Assert.That(await session.RenewAsync()).IsEqualTo(SecretStatus.RecoveryRequired);
    }

    [Test]
    [Arguments(HttpStatusCode.TooManyRequests)]
    [Arguments(HttpStatusCode.InternalServerError)]
    public async Task UnprovenRetrySafetyRequiresRecovery(HttpStatusCode status)
    {
        var time = new ManualTime(Epoch);
        await using var session = Session(time, new Wire((_, _) => Task.FromResult(new HttpResponseMessage(status))));

        await Assert.That(await session.RenewAsync()).IsEqualTo(SecretStatus.RecoveryRequired);

        var receipt = session.LastRenewal;
        await Assert.That(receipt!.Evidence).IsEqualTo(InfisicalRenewalEvidence.PossiblyDispatched);
        await Assert.That(await session.RenewAsync()).IsEqualTo(SecretStatus.RecoveryRequired);
        await Assert.That(session.LastRenewal).IsSameReferenceAs(receipt);
        await Assert.That((await session.GetTokenAsync(CancellationToken.None)).Status)
            .IsEqualTo(SecretStatus.RecoveryRequired);
    }

    [Test]
    public async Task LostResponseRetainsUncertaintyAndDoesNotRepeat()
    {
        var time = new ManualTime(Epoch);
        await using var session = Session(time, new Wire((_, _) => throw new HttpRequestException("protected-canary")));

        await Assert.That(await session.RenewAsync()).IsEqualTo(SecretStatus.RecoveryRequired);

        var receipt = session.LastRenewal!;
        await Assert.That(receipt.Evidence).IsEqualTo(InfisicalRenewalEvidence.PossiblyDispatched);
        await Assert.That(await session.RenewAsync()).IsEqualTo(SecretStatus.RecoveryRequired);
        await Assert.That(session.LastRenewal).IsSameReferenceAs(receipt);
        await Assert.That(session.ToString().Contains("protected-canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("{\"accessToken\":\"secret\",\"tokenType\":\"Basic\",\"expiresIn\":60,\"accessTokenMaxTTL\":120}")]
    [Arguments("{\"accessToken\":\"secret\",\"tokenType\":\"Bearer\",\"expiresIn\":60}")]
    [Arguments("{\"accessToken\":\"secret\",\"tokenType\":\"Bearer\",\"expiresIn\":60,\"accessTokenMaxTTL\":121}")]
    [Arguments("{\"accessToken\":\"secret\",\"tokenType\":\"Bearer\",\"expiresIn\":0,\"accessTokenMaxTTL\":120}")]
    [Arguments("{\"accessToken\":\"first\",\"accessToken\":\"second\",\"tokenType\":\"Bearer\",\"expiresIn\":60,\"accessTokenMaxTTL\":120}")]
    [Arguments("[]")]
    [Arguments("{\"accessToken\":\"secret\",\"tokenType\":\"Bearer\",\"expiresIn\":60,\"accessTokenMaxTTL\":120,\"notDeclared\":\"private-extra\"}")]
    public async Task UnestablishedResponseCannotPublishMaterial(string json)
    {
        var time = new ManualTime(Epoch);
        await using var session = Session(time, new Wire((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        })));

        await Assert.That(await session.RenewAsync()).IsEqualTo(SecretStatus.RecoveryRequired);

        await Assert.That((await session.GetTokenAsync(CancellationToken.None)).Status)
            .IsEqualTo(SecretStatus.RecoveryRequired);
        await Assert.That(session.LastRenewal!.Evidence).IsEqualTo(InfisicalRenewalEvidence.PossiblyDispatched);
    }

    [Test]
    public async Task UnknownMetadataCannotInferLifetimeOrUseConsumedBootstrap()
    {
        var time = new ManualTime(Epoch);
        await using var session = Session(time, new Wire((_, _) => throw new InvalidOperationException("No authority")),
            InfisicalTokenLifetime.Unknown);
        await using var helper = new InfisicalAuthenticationMaintenance(session, TimeSpan.FromSeconds(5));

        await helper.StartAsync(CancellationToken.None);

        await Assert.That(helper.State).IsEqualTo(AuthenticationMaintenanceState.RecoveryRequired);
        await Assert.That(await session.RenewAsync()).IsEqualTo(SecretStatus.RecoveryRequired);
        await Assert.That(session.LastRenewal).IsNull();
    }

    [Test]
    public async Task ExpiryDuringRenewalCannotReturnExpiredMaterial()
    {
        var time = new ManualTime(Epoch);
        var entered = Signal();
        var response = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var session = Session(time, new Wire(async (_, _) =>
        {
            entered.TrySetResult();
            return await response.Task;
        }));
        Task<SecretStatus> renewal = session.RenewAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        time.Advance(TimeSpan.FromSeconds(60));
        var outcome = await session.GetTokenAsync(CancellationToken.None);

        try
        {
            if (outcome.IsSuccess) outcome.Value.Dispose();
            await Assert.That(outcome.Status).IsEqualTo(SecretStatus.RecoveryRequired);
        }
        finally
        {
            response.TrySetResult(Json("renewed"));
            await renewal;
        }
    }

    [Test]
    public async Task ExplicitHostStopCancelsInFlightRenewal()
    {
        var time = new ManualTime(Epoch);
        var entered = Signal();
        var cancelled = Signal();
        var response = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var session = Session(time, new Wire(async (_, token) =>
        {
            entered.TrySetResult();
            try { return await response.Task.WaitAsync(token); }
            catch (OperationCanceledException)
            {
                cancelled.TrySetResult();
                throw;
            }
        }));
        await using var helper = new InfisicalAuthenticationMaintenance(session, TimeSpan.FromSeconds(5));
        await helper.StartAsync(CancellationToken.None);
        time.Advance(TimeSpan.FromSeconds(50));
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        await helper.StopAsync(CancellationToken.None);

        await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That(helper.State).IsEqualTo(AuthenticationMaintenanceState.Stopped);
        await Assert.That(session.LastRenewal!.Evidence).IsEqualTo(InfisicalRenewalEvidence.PossiblyDispatched);
    }

    [Test]
    public async Task RealLoopbackTransportUsesNativeRenewalWithoutRedirect()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = (IPEndPoint)listener.LocalEndpoint;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task<string> server = ExchangeAsync(listener, deadline.Token);
        var time = new ManualTime(Epoch);
        using var original = SecretMaterial.FromText("local-existing");
        await using var session = new InfisicalPeriodicTokenSession(
            new Uri($"http://127.0.0.1:{endpoint.Port}"), original, Evidence(),
            TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5),
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true }, time);

        await Assert.That(await session.RenewAsync(deadline.Token)).IsEqualTo(SecretStatus.Success);

        using var captured = JsonDocument.Parse(await server);
        await Assert.That(captured.RootElement.GetProperty("accessToken").GetString()).IsEqualTo("local-existing");
        using var token = (await session.GetTokenAsync(CancellationToken.None)).Value;
        await Assert.That(token.Material.Reveal()).IsEqualTo("wire-replacement");
        await Assert.That(original.Reveal()).IsEqualTo("local-existing");
    }

    private static async Task<string> ExchangeAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        using var connection = await listener.AcceptTcpClientAsync(cancellationToken);
        using NetworkStream stream = connection.GetStream();
        using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
        string? first = await reader.ReadLineAsync(cancellationToken);
        await Assert.That(first).IsEqualTo("POST /api/v1/auth/token/renew HTTP/1.1");
        int length = 0;
        while (await reader.ReadLineAsync(cancellationToken) is { Length: > 0 } line)
        {
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                length = int.Parse(line.AsSpan("Content-Length:".Length), System.Globalization.CultureInfo.InvariantCulture);
        }
        char[] body = new char[length];
        int received = 0;
        while (received < length)
        {
            int read = await reader.ReadAsync(body.AsMemory(received), cancellationToken);
            if (read == 0) throw new IOException("Fixture request incomplete.");
            received += read;
        }
        string response = "{\"accessToken\":\"wire-replacement\",\"tokenType\":\"Bearer\",\"expiresIn\":60,\"accessTokenMaxTTL\":120}";
        byte[] bytes = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n{response}");
        await stream.WriteAsync(bytes, cancellationToken);
        return new string(body);
    }

    [Test]
    public async Task RestartWithoutTokenAfterConsumedBootstrapRequiresRecovery()
    {
        var time = new ManualTime(Epoch);
        await using var session = new InfisicalPeriodicTokenSession(new Uri("https://fixture.invalid"), null,
            Evidence(), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5), timeProvider: time);
        await using var helper = new InfisicalAuthenticationMaintenance(session, TimeSpan.FromSeconds(5));

        await helper.StartAsync(CancellationToken.None);

        await Assert.That(helper.State).IsEqualTo(AuthenticationMaintenanceState.RecoveryRequired);
        await Assert.That((await session.GetTokenAsync(CancellationToken.None)).Status)
            .IsEqualTo(SecretStatus.RecoveryRequired);
        await Assert.That(session.LastRenewal).IsNull();
    }

    [Test]
    public async Task RequestDeadlineCancelsTransportAndRequiresRecovery()
    {
        var time = new ManualTime(Epoch);
        var entered = Signal();
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var session = Session(time, new Wire(async (_, token) =>
        {
            entered.TrySetResult();
            return await pending.Task.WaitAsync(token);
        }));
        Task<SecretStatus> renewal = session.RenewAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        time.Advance(TimeSpan.FromSeconds(60));

        await Assert.That(await renewal.WaitAsync(TimeSpan.FromSeconds(5))).IsEqualTo(SecretStatus.RecoveryRequired);
        await Assert.That(session.LastRenewal!.Evidence).IsEqualTo(InfisicalRenewalEvidence.PossiblyDispatched);
    }

    [Test]
    public async Task HostTransportAndCallerCopiesSurviveSessionDisposal()
    {
        var time = new ManualTime(Epoch);
        var wire = new Wire((_, _) => Task.FromResult(Json("replacement")));
        var session = Session(time, wire);
        using var copy = (await session.GetTokenAsync(CancellationToken.None)).Value;

        await session.DisposeAsync();
        await session.DisposeAsync();

        await Assert.That(wire.Disposed).IsFalse();
        await Assert.That(copy.Material.Reveal()).IsEqualTo("bootstrap-copy");
        await Assert.That(async () => await session.GetTokenAsync(CancellationToken.None))
            .Throws<ObjectDisposedException>();
        wire.Dispose();
    }

    [Test]
    [Arguments("http://untrusted.invalid", true)]
    [Arguments("http://127.0.0.1", false)]
    [Arguments("https://fixture.invalid/path", false)]
    public async Task UntrustedOriginsAreRejectedBeforeCredentials(string address, bool development)
    {
        using var original = SecretMaterial.FromText("protected");

        await Assert.That(() => new InfisicalPeriodicTokenSession(new Uri(address), original, Evidence(),
            TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5),
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = development }))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task OversizeRenewalResponseCannotPublishMaterial()
    {
        var time = new ManualTime(Epoch);
        await using var session = Session(time, new Wire((_, _) =>
            Task.FromResult(Json(new string('x', 1024 * 1024)))));

        await Assert.That(await session.RenewAsync()).IsEqualTo(SecretStatus.RecoveryRequired);

        await Assert.That(session.State).IsEqualTo(InfisicalTokenSessionState.RecoveryRequired);
    }

    [Test]
    public async Task PreviouslyRenewedPeriodicTokenCanStartWithOriginalIssueTime()
    {
        var time = new ManualTime(Epoch.AddSeconds(150));
        using var original = SecretMaterial.FromText("existing-periodic");
        await using var session = new InfisicalPeriodicTokenSession(new Uri("https://fixture.invalid"), original,
            new InfisicalTokenLifetimeEvidence
            {
                OriginalIssuedAt = Epoch,
                ExpiresAt = Epoch.AddSeconds(180),
                Lifetime = InfisicalTokenLifetime.Periodic,
                ReportedMaximumTtl = TimeSpan.FromSeconds(120),
                Period = TimeSpan.FromSeconds(60)
            }, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5), new InfisicalNetworkOptions(), time,
            new Wire((_, _) => Task.FromResult(Json("replacement"))), false);

        await Assert.That(await session.RenewAsync()).IsEqualTo(SecretStatus.Success);

        using var token = (await session.GetTokenAsync(CancellationToken.None)).Value;
        await Assert.That(token.ExpiresAt).IsEqualTo(Epoch.AddSeconds(210));
    }

    [Test]
    public async Task PreCancelledDemandDoesNotDispatchOrConsumeAuthority()
    {
        var time = new ManualTime(Epoch);
        await using var session = Session(time, new Wire((_, _) => throw new InvalidOperationException("Unexpected dispatch.")));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.That(async () => await session.RenewAsync(cancellation.Token)).Throws<OperationCanceledException>();

        await Assert.That(session.LastRenewal).IsNull();
        using var copy = (await session.GetTokenAsync(CancellationToken.None)).Value;
        await Assert.That(copy.Material.Reveal()).IsEqualTo("bootstrap-copy");
    }

    [Test]
    [Arguments(InfisicalTokenLifetime.Unknown, SecretStatus.RecoveryRequired)]
    [Arguments(InfisicalTokenLifetime.Finite, SecretStatus.RecoveryRequired)]
    [Arguments(InfisicalTokenLifetime.Periodic, SecretStatus.Success)]
    public async Task ZeroMaximumTtlRequiresIndependentPeriodicEvidence(InfisicalTokenLifetime lifetime,
        SecretStatus expected)
    {
        var time = new ManualTime(Epoch);
        using var original = SecretMaterial.FromText("existing-periodic");
        await using var session = new InfisicalPeriodicTokenSession(new Uri("https://fixture.invalid"), original,
            new InfisicalTokenLifetimeEvidence
            {
                OriginalIssuedAt = Epoch,
                ExpiresAt = Epoch.AddSeconds(60),
                Lifetime = lifetime,
                ReportedMaximumTtl = TimeSpan.Zero,
                Period = lifetime == InfisicalTokenLifetime.Periodic ? TimeSpan.FromSeconds(60) : null
            }, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5), new InfisicalNetworkOptions(), time,
            new Wire((_, _) => Task.FromResult(Json("replacement", maximum: 0))), false);

        await Assert.That(await session.RenewAsync()).IsEqualTo(expected);

        var outcome = await session.GetTokenAsync(CancellationToken.None);
        await Assert.That(outcome.Status).IsEqualTo(expected);
        if (expected == SecretStatus.Success)
        {
            using var copy = outcome.Value;
            await Assert.That(copy.Material.Reveal()).IsEqualTo("replacement");
        }
        else
            await Assert.That(session.LastRenewal).IsNull();
    }

    private static InfisicalTokenLifetimeEvidence Evidence() => new()
    {
        OriginalIssuedAt = Epoch,
        ExpiresAt = Epoch.AddSeconds(60),
        Lifetime = InfisicalTokenLifetime.Finite,
        ReportedMaximumTtl = TimeSpan.FromSeconds(120)
    };

    internal static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal static HttpResponseMessage Json(string token, double expiry = 60, double maximum = 120) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                accessToken = token,
                tokenType = "Bearer",
                expiresIn = expiry,
                accessTokenMaxTTL = maximum
            }), Encoding.UTF8, "application/json")
        };

    internal static InfisicalPeriodicTokenSession Session(ManualTime time, Wire transport,
        InfisicalTokenLifetime mode = InfisicalTokenLifetime.Finite)
    {
        using var material = SecretMaterial.FromText("bootstrap-copy");
        return new InfisicalPeriodicTokenSession(new Uri("https://fixture.invalid"), material,
            new InfisicalTokenLifetimeEvidence
            {
                OriginalIssuedAt = Epoch,
                ExpiresAt = Epoch.AddSeconds(60),
                Lifetime = mode,
                ReportedMaximumTtl = TimeSpan.FromSeconds(120),
                Period = mode == InfisicalTokenLifetime.Periodic ? TimeSpan.FromSeconds(60) : null
            }, TimeSpan.FromSeconds(10), TimeSpan.FromMinutes(1), new InfisicalNetworkOptions(),
            time, transport, false);
    }

    internal sealed class Wire(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send)
        : HttpMessageHandler
    {
        public bool Disposed { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) =>
            send(request, token);
        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    /// <summary>Exact one-shot and periodic BCL timers; callbacks run outside the clock lock.</summary>
    internal sealed class ManualTime(DateTimeOffset initial) : TimeProvider
    {
        private readonly object _gate = new();
        private readonly List<Timer> _timers = [];
        private readonly Dictionary<DateTimeOffset, TaskCompletionSource> _watches = [];
        private DateTimeOffset _now = initial;
        public override DateTimeOffset GetUtcNow() { lock (_gate) return _now; }

        public Task WatchTimer(DateTimeOffset due)
        {
            lock (_gate)
            {
                if (_timers.Any(timer => timer.Due == due)) return Task.CompletedTask;
                var watch = Signal();
                _watches.Add(due, watch);
                return watch.Task;
            }
        }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            lock (_gate)
            {
                var timer = new Timer(this, callback, state);
                _timers.Add(timer);
                timer.Change(dueTime, period);
                return timer;
            }
        }

        public void Advance(TimeSpan amount)
        {
            if (amount < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(amount));
            List<Timer> due;
            lock (_gate)
            {
                _now += amount;
                due = _timers.Where(timer => timer.Due <= _now).ToList();
                foreach (var timer in due)
                    timer.Due = timer.Period == Timeout.InfiniteTimeSpan ? DateTimeOffset.MaxValue : _now + timer.Period;
            }
            foreach (var timer in due) timer.Fire();
        }

        private sealed class Timer(ManualTime owner, TimerCallback callback, object? state) : ITimer
        {
            public DateTimeOffset Due { get; set; } = DateTimeOffset.MaxValue;
            public TimeSpan Period { get; private set; } = Timeout.InfiniteTimeSpan;
            private bool _disposed;
            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                lock (owner._gate)
                {
                    if (_disposed) return false;
                    Due = dueTime == Timeout.InfiniteTimeSpan ? DateTimeOffset.MaxValue : owner._now + dueTime;
                    Period = period;
                    if (owner._watches.Remove(Due, out var watch)) watch.TrySetResult();
                    return true;
                }
            }
            public void Fire()
            {
                lock (owner._gate) if (_disposed) return;
                callback(state);
            }
            public void Dispose()
            {
                lock (owner._gate)
                {
                    _disposed = true;
                    Due = DateTimeOffset.MaxValue;
                    owner._timers.Remove(this);
                }
            }
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
