using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecretKit.Core;
using SecretKit.Extensions.Hosting;
using SecretKit.Infisical;

namespace SecretKit.Hosting.Tests;

public sealed class HostingOptionsTests
{
    [Test]
    public async Task EagerOpenRetainsTheSuppliedAttemptEvidence()
    {
        using var wire = new Wire(HttpStatusCode.OK);
        var options = new InfisicalHostingOptions();
        Configure(options, wire);
        using var bootstrap = SecretMaterial.FromText("eager-bootstrap");
        var attempt = new InfisicalRuntimeOpenAttempt();
        var outcome = await InfisicalRuntimeSession.OpenUniversalAsync(options.Runtime!, bootstrap, attempt);
        await using var runtime = outcome.GetValueOrThrow();
        await Assert.That(runtime.OpeningAttempt).IsSameReferenceAs(attempt);
        await Assert.That(runtime.OpeningAttempt.LoginReceipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
    }

    [Test]
    public async Task BootstrapFactoryIsCoveredBySharedOperationDeadline()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var clock = new TokenMaintenanceTests.ManualTime(new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using var wire = new Wire(HttpStatusCode.OK);
        var options = new InfisicalHostingOptions();
        Configure(options, wire, clock: clock);
        CancellationToken factoryToken = default;
        var runtime = InfisicalRuntimeSession.CreateDeferred(options.Runtime!, async token =>
        {
            factoryToken = token;
            using var registration = token.Register(() => cancelled.TrySetResult());
            entered.TrySetResult();
            await cancelled.Task;
            token.ThrowIfCancellationRequested();
            return SecretMaterial.FromText("unreachable");
        });
        var authentication = runtime.EnsureAuthenticatedAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        try
        {
            clock.Advance(options.Runtime!.Network.OperationTimeout);
            await Assert.That(factoryToken.IsCancellationRequested).IsTrue();
            var result = await authentication.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unavailable);
            await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.DeadlineExceeded);
            await Assert.That((await runtime.EnsureAuthenticatedAsync()).Reason).IsEqualTo(SecretFailureReason.DeadlineExceeded);
            await Assert.That(wire.Requests).IsEqualTo(0);
        }
        finally
        {
            await runtime.StopAsync();
            try { await authentication; } catch (OperationCanceledException) { }
        }
    }

    [Test]
    public async Task WildcardKeyCannotRegisterFallbackCredentials()
    {
        var services = new ServiceCollection();
        await Assert.That(() => services.AddKeyedSecretKitInfisical(KeyedService.AnyKey, _ => { }))
            .Throws<ArgumentException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task LateSuccessAfterDeadlineCannotPublishOrReplay(bool lateLogin)
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var clock = new TokenMaintenanceTests.ManualTime(new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using var wire = new Wire(HttpStatusCode.OK)
        {
            BeforeResponse = lateLogin ? async _ => { entered.TrySetResult(); await release.Task; } : null
        };
        var options = new InfisicalHostingOptions();
        Configure(options, wire, clock: clock);
        SecretMaterial? bootstrap = null;
        await using var runtime = InfisicalRuntimeSession.CreateDeferred(options.Runtime!, async _ =>
        {
            if (!lateLogin) { entered.TrySetResult(); await release.Task; }
            return bootstrap = SecretMaterial.FromText("deadline-bootstrap");
        });
        var authentication = runtime.EnsureAuthenticatedAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        clock.Advance(options.Runtime!.Network.OperationTimeout);
        release.TrySetResult();
        var result = await authentication.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.DeadlineExceeded);
        await Assert.That(runtime.IsAuthenticated).IsFalse();
        await Assert.That(() => bootstrap!.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That((await runtime.EnsureAuthenticatedAsync()).Reason).IsEqualTo(SecretFailureReason.DeadlineExceeded);
        await Assert.That(wire.Requests).IsEqualTo(lateLogin ? 1 : 0);
    }

    [Test]
    public async Task ConcurrentAuthenticationSharesAttemptAndCallerCancellationOnlyEndsItsWait()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var wire = new Wire(HttpStatusCode.OK)
        {
            BeforeResponse = async _ => { entered.TrySetResult(); await release.Task; }
        };
        var options = new InfisicalHostingOptions();
        Configure(options, wire);
        SecretMaterial? bootstrap = null;
        int acquisitions = 0;
        await using var runtime = InfisicalRuntimeSession.CreateDeferred(options.Runtime!, _ =>
        {
            acquisitions++;
            bootstrap = SecretMaterial.FromText("single-use-bootstrap");
            return ValueTask.FromResult(bootstrap);
        });
        using var canceledWaiter = new CancellationTokenSource();
        var first = runtime.EnsureAuthenticatedAsync(canceledWaiter.Token).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var second = runtime.EnsureAuthenticatedAsync().AsTask();
        canceledWaiter.Cancel();
        try
        {
            await Assert.That(async () => await first).Throws<OperationCanceledException>();
            await Assert.That(second.IsCompleted).IsFalse();
        }
        finally { release.TrySetResult(); }
        await Assert.That((await second).IsSuccess).IsTrue();
        await Assert.That(acquisitions).IsEqualTo(1);
        await Assert.That(wire.Requests).IsEqualTo(1);
        await Assert.That(() => bootstrap!.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DisposalDuringLoginRejectsLatePublicationAndRetainsDispatchEvidence(bool transportHonorsCancellation)
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancellationObserved = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var wire = new Wire(HttpStatusCode.OK)
        {
            BeforeResponse = async cancellationToken =>
            {
                using var registration = cancellationToken.Register(() => cancellationObserved.TrySetResult());
                entered.TrySetResult();
                await release.Task;
                if (transportHonorsCancellation) cancellationToken.ThrowIfCancellationRequested();
            }
        };
        var options = new InfisicalHostingOptions();
        Configure(options, wire);
        var runtime = InfisicalRuntimeSession.CreateDeferred(options.Runtime!, options.ClientSecret!);
        var authentication = runtime.EnsureAuthenticatedAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Task stop = runtime.StopAsync();
        await cancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
        release.TrySetResult();
        await Assert.That(async () => await authentication).Throws<OperationCanceledException>();
        await stop;
        await Assert.That(runtime.IsAuthenticated).IsFalse();
        await Assert.That(runtime.OpeningAttempt.LoginReceipt!.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(async () => await runtime.EnsureAuthenticatedAsync()).Throws<ObjectDisposedException>();
        await Assert.That(wire.Disposed).IsFalse();
    }

    [Test]
    public async Task HealthChecksNeverAuthenticateAndDuplicateKeysAreRejected()
    {
        using var wire = new Wire(HttpStatusCode.OK);
        var builder = Host.CreateApplicationBuilder();
        builder.Services.AddSecretKitInfisical(options => Configure(options, wire)).WithHealthChecks();
        await Assert.That(() => builder.Services.AddSecretKitInfisical(options => Configure(options, wire)))
            .Throws<InvalidOperationException>();
        using var host = builder.Build();
        await host.StartAsync();
        var report = await host.Services.GetRequiredService<HealthCheckService>().CheckHealthAsync();
        await Assert.That(report.Status).IsEqualTo(HealthStatus.Unhealthy);
        await Assert.That(wire.Requests).IsEqualTo(0);
        await host.StopAsync();
    }

    [Test]
    public async Task DisposalDuringBootstrapClearsLateMaterialWithoutDispatch()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var wire = new Wire(HttpStatusCode.OK);
        var options = new InfisicalHostingOptions();
        Configure(options, wire);
        SecretMaterial? bootstrap = null;
        var runtime = InfisicalRuntimeSession.CreateDeferred(options.Runtime!, async _ =>
        {
            entered.TrySetResult();
            await release.Task;
            return bootstrap = SecretMaterial.FromText("late-bootstrap");
        });
        Task authentication = runtime.EnsureAuthenticatedAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Task stop = runtime.StopAsync();
        release.TrySetResult();
        await Assert.That(async () => await authentication).Throws<OperationCanceledException>();
        await stop;
        await Assert.That(() => bootstrap!.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(wire.Requests).IsEqualTo(0);
        await Assert.That(runtime.OpeningAttempt.LoginReceipt).IsNull();
    }

    [Test]
    public async Task HealthTracksLocalExpiryWithoutRenewalOrReauthentication()
    {
        using var wire = new Wire(HttpStatusCode.OK);
        var clock = new TestClock();
        var builder = Host.CreateApplicationBuilder();
        builder.Services.AddSecretKitInfisical(options => Configure(options, wire, clock: clock))
            .WithStartupAdmission().WithHealthChecks();
        using var host = builder.Build();
        await host.StartAsync();
        var health = host.Services.GetRequiredService<HealthCheckService>();
        await Assert.That((await health.CheckHealthAsync()).Status).IsEqualTo(HealthStatus.Healthy);
        clock.Now = clock.Now.AddSeconds(3550);
        await Assert.That((await health.CheckHealthAsync()).Status).IsEqualTo(HealthStatus.Degraded);
        clock.Now = clock.Now.AddSeconds(100);
        await Assert.That((await health.CheckHealthAsync()).Status).IsEqualTo(HealthStatus.Unhealthy);
        await Assert.That(wire.Requests).IsEqualTo(1);
        await host.StopAsync();
    }

    [Test]
    public async Task RegistrationAndStartupWithoutAdmissionDoNotAcquireCredentials()
    {
        using var wire = new Wire(HttpStatusCode.OK);
        int acquisitions = 0;
        var builder = Host.CreateApplicationBuilder();
        builder.Services.AddSecretKitInfisical(options =>
        {
            Configure(options, wire);
            options.ClientSecret = _ =>
            {
                Interlocked.Increment(ref acquisitions);
                return ValueTask.FromResult(SecretMaterial.FromText("canary-secret"));
            };
        }).WithDefaultScope("canary-project", "canary-env");
        using var host = builder.Build();
        await host.StartAsync();
        var runtime = host.Services.GetRequiredService<InfisicalRuntimeSession>();
        await Assert.That(host.Services.GetRequiredService<IInfisicalSecretReader>()).IsSameReferenceAs(runtime.Client);
        await Assert.That(host.Services.GetRequiredService<InfisicalSecretScope>()).IsNotNull();
        await Assert.That(acquisitions).IsEqualTo(0);
        await Assert.That(wire.Requests).IsEqualTo(0);
        await host.StopAsync();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task InvalidConfigurationFailsDuringHostStartupWithoutDispatch(bool insecureOrigin)
    {
        using var wire = new Wire(HttpStatusCode.OK);
        var builder = Host.CreateApplicationBuilder();
        builder.Services.AddSecretKitInfisical(options =>
        {
            Configure(options, wire, insecureOrigin);
            if (!insecureOrigin) options.ClientSecret = null;
        });
        using var host = builder.Build();
        await Assert.That(async () => await host.StartAsync()).Throws<OptionsValidationException>();
        await Assert.That(wire.Requests).IsEqualTo(0);
    }

    [Test]
    public async Task AdmissionFailureIsCoordinateFreeAndCannotReplayLogin()
    {
        using var wire = new Wire(HttpStatusCode.Unauthorized);
        var logs = new CaptureLogs();
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Logging.AddProvider(logs);
        builder.Services.AddSecretKitInfisical(options => Configure(options, wire)).WithStartupAdmission();
        using var host = builder.Build();
        await Assert.That(async () => await host.StartAsync()).Throws<SecretUnavailableException>();
        var runtime = host.Services.GetRequiredService<InfisicalRuntimeSession>();
        await Assert.That((await runtime.EnsureAuthenticatedAsync()).IsSuccess).IsFalse();
        await Assert.That(wire.Requests).IsEqualTo(1);
        foreach (string canary in new[] { "canary-origin", "canary-client", "canary-secret", "canary-project" })
            await Assert.That(string.Join("\n", logs.Entries).Contains(canary, StringComparison.Ordinal)).IsFalse();
        await Assert.That(logs.Entries.Count).IsGreaterThan(0);
    }

    [Test]
    public async Task KeyedRegistrationsHaveIndependentRuntimeAndScope()
    {
        using var firstWire = new Wire(HttpStatusCode.OK);
        using var secondWire = new Wire(HttpStatusCode.OK);
        var builder = Host.CreateApplicationBuilder();
        builder.Services.AddKeyedSecretKitInfisical("first", options => Configure(options, firstWire))
            .WithDefaultScope("first-project", "test").WithStartupAdmission();
        builder.Services.AddKeyedSecretKitInfisical("second", options => Configure(options, secondWire))
            .WithDefaultScope("second-project", "test").WithStartupAdmission();
        using var host = builder.Build();
        await host.StartAsync();
        var first = host.Services.GetRequiredKeyedService<InfisicalRuntimeSession>("first");
        var second = host.Services.GetRequiredKeyedService<InfisicalRuntimeSession>("second");
        await Assert.That(ReferenceEquals(first, second)).IsFalse();
        await Assert.That(ReferenceEquals(
            host.Services.GetRequiredKeyedService<InfisicalSecretScope>("first"),
            host.Services.GetRequiredKeyedService<InfisicalSecretScope>("second"))).IsFalse();
        await Assert.That(firstWire.Requests).IsEqualTo(1);
        await Assert.That(secondWire.Requests).IsEqualTo(1);
        await host.StopAsync();
        await Assert.That(firstWire.Disposed || secondWire.Disposed).IsFalse();
    }

    private static void Configure(InfisicalHostingOptions options, Wire wire, bool insecureOrigin = false,
        TimeProvider? clock = null)
    {
        options.Runtime = new()
        {
            Origin = new Uri(insecureOrigin ? "http://canary-origin.invalid" : "https://canary-origin.invalid"),
            ClientId = "canary-client",
            ProjectId = "canary-project",
            Lifetime = InfisicalTokenLifetime.Finite,
            OriginalIssuedAt = (clock ?? TimeProvider.System).GetUtcNow().AddSeconds(-1),
            TimeProvider = clock ?? TimeProvider.System,
            Network = new() { Transport = InfisicalTransportOptions.HostControlled(wire) }
        };
        options.ClientSecret = _ => ValueTask.FromResult(SecretMaterial.FromText("canary-secret"));
    }

    private sealed class TestClock : TimeProvider
    {
        internal DateTimeOffset Now { get; set; } = new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class Wire(HttpStatusCode status) : HttpMessageHandler
    {
        internal Func<CancellationToken, Task>? BeforeResponse { get; init; }
        internal int Requests { get; private set; }
        internal bool Disposed { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests++;
            if (BeforeResponse is not null) await BeforeResponse(cancellationToken);
            return new HttpResponseMessage(status)
            {
                Content = new StringContent("""{"accessToken":"test-token","expiresIn":3600,"accessTokenMaxTTL":7200,"tokenType":"Bearer"}""")
            };
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }

    private sealed class CaptureLogs : ILoggerProvider, ILogger
    {
        internal List<string> Entries { get; } = [];
        public ILogger CreateLogger(string categoryName) => this;
        public bool IsEnabled(LogLevel logLevel) => true;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public void Dispose() { }
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add(formatter(state, exception));
            Entries.Add(exception?.ToString() ?? string.Empty);
            if (state is IEnumerable<KeyValuePair<string, object?>> values)
                Entries.AddRange(values.Select(value => $"{value.Key}:{value.Value}"));
        }
    }
}
