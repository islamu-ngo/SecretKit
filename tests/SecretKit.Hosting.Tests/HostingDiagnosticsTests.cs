using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecretKit.Core;
using SecretKit.Extensions.Hosting;
using SecretKit.Infisical;

namespace SecretKit.Hosting.Tests;

[NotInParallel]
public sealed class HostingDiagnosticsTests
{
    private const string Source = "SecretKit.Extensions.Hosting";
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RegistrationAndResolutionStayInert(bool keyed)
    {
        using var wire = new Wire();
        var clock = new Clock();
        int credentials = 0;
        using var capture = new Capture();
        int published = capture.Published;
        var builder = Builder(wire, clock, keyed, () => credentials++);
        using var host = builder.Build();

        var runtime = Runtime(host, keyed);
        _ = host.Services.GetServices<IHostedService>().ToArray();

        await Assert.That(credentials).IsEqualTo(0);
        await Assert.That(wire.Entered.Task.IsCompleted).IsFalse();
        await Assert.That(runtime.IsAuthenticated).IsFalse();
        await Assert.That(capture.Spans.IsEmpty).IsTrue();
        await Assert.That(capture.Measurements.IsEmpty).IsTrue();
        await Assert.That(capture.Published).IsEqualTo(published);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task HostAdmissionCapturesHeldWorkAndOpaqueParent(bool keyed)
    {
        using var wire = new Wire { Hold = true };
        var clock = new Clock();
        using var parent = Parent();
        ActivityTraceId trace = parent.TraceId;
        ActivitySpanId parentSpan = parent.SpanId;
        using var capture = new Capture();
        using var host = Builder(wire, clock, keyed).Build();
        DateTime before = DateTime.UtcNow;
        var starting = host.StartAsync();
        await wire.Entered.Task.WaitAsync(Bound);
        DateTime entered = DateTime.UtcNow;
        await Assert.That(capture.Spans.IsEmpty).IsTrue();
        using var replacement = new Activity("replacement-canary").Start();
        parent.Dispose();
        Activity.Current = replacement;
        wire.Release.TrySetResult();
        await starting.WaitAsync(Bound);

        var admission = capture.Spans.Single(item => item.Operation == "Admission");
        await Assert.That(admission.Start >= before && admission.Start <= entered).IsTrue();
        await Assert.That(admission.Start + admission.Duration >= entered).IsTrue();
        await Assert.That(admission.Duration.TotalSeconds)
            .IsEqualTo(capture.Measurements.Single(item => item.Operation == "Admission").Duration);
        await Assert.That(admission.Trace).IsEqualTo(trace);
        await Assert.That(admission.Parent).IsEqualTo(parentSpan);
        await Assert.That(admission.Baggage).IsEqualTo(string.Empty);
        await Assert.That(admission.TraceState).IsNull();
        await Assert.That(admission.ParentObject).IsFalse();
        await Assert.That(ReferenceEquals(Activity.Current, replacement)).IsTrue();
        await Assert.That(admission.Tags["state"] as string).IsEqualTo("Authenticated");
        await Assert.That(admission.Tags["outcome"] as string).IsEqualTo("Success");
        using var copy = (await Runtime(host, keyed).TokenSession.GetTokenAsync(default)).Value;
        await host.StopAsync();
        await Assert.That(copy.Material.Reveal()).IsEqualTo("issued-canary");
        await Assert.That(wire.Disposed).IsFalse();
        await Assert.That(capture.Spans.Single(item => item.Operation == "AdmissionStop").Tags["state"] as string)
            .IsEqualTo("Stopped");
        await Assert.That(capture.Spans.SelectMany(item => item.Tags).All(pair =>
            pair.Key is "operation" or "outcome" or "reason" or "termination" or "state")).IsTrue();
        await Assert.That(string.Join(";", capture.Spans.SelectMany(item => item.Tags).Select(pair => pair.Value))
            .Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("denied", "Completed", "Denied", "None")]
    [Arguments("deadline", "DeadlineExceeded", "Unknown", "DeadlineExceeded")]
    [Arguments("caller", "CallerCanceled", "Unknown", "None")]
    public async Task AdmissionRetainsFailureAndCancellationEvidence(
        string cause, string termination, string status, string reason)
    {
        using var wire = new Wire
        {
            Hold = cause != "denied",
            Status = cause == "denied" ? HttpStatusCode.Forbidden : HttpStatusCode.OK
        };
        var clock = new Clock();
        using var caller = new CancellationTokenSource();
        using var capture = new Capture();
        using var host = Builder(wire, clock, false).Build();
        var starting = host.StartAsync(caller.Token);
        await wire.Entered.Task.WaitAsync(Bound);
        if (cause == "deadline") clock.Advance(TimeSpan.FromSeconds(31));
        if (cause == "caller") caller.Cancel();
        if (cause == "caller")
            await Assert.That(async () => await starting.WaitAsync(Bound)).Throws<OperationCanceledException>();
        else
            await Assert.That(async () => await starting.WaitAsync(Bound)).Throws<SecretUnavailableException>();
        wire.Release.TrySetResult();
        var observed = capture.Spans.Single(item => item.Operation == "Admission");
        await Assert.That(observed.Tags["termination"] as string).IsEqualTo(termination);
        await Assert.That(observed.Tags["outcome"] as string).IsEqualTo(status);
        await Assert.That(observed.Tags["reason"] as string).IsEqualTo(reason);
        await Runtime(host, false).StopAsync().WaitAsync(Bound);
    }

    [Test]
    public async Task MaintenanceIntervalEndsBeforeListenersAndAfterWorkerRelease()
    {
        var clock = new Clock();
        // Keep the handler admitted until explicit release so its cancellation
        // signal cannot be unregistered by the canceled await's continuation.
        using var wire = new Wire { Hold = true, IgnoreCancellation = true };
        using var original = SecretMaterial.FromText("original-canary");
        await using var session = Session(clock, wire, original, due: true);
        await using var helper = new InfisicalAuthenticationMaintenance(session, TimeSpan.FromSeconds(5));
        using var parent = Parent();
        var observed = Signal();
        Exception? callbackError = null;
        using var capture = new Capture(callback: (phase, operation) =>
        {
            if (operation != "Maintenance") return;
            clock.AdvanceElapsed(TimeSpan.FromSeconds(7));
            if (phase != "stop") return;
            try { helper.StopAsync(default).WaitAsync(Bound).GetAwaiter().GetResult(); }
            catch (Exception error) { callbackError = error; }
            finally { observed.TrySetResult(); }
        });
        DateTime start = clock.GetUtcNow().UtcDateTime;
        await helper.StartAsync(default);
        await wire.Entered.Task.WaitAsync(Bound);
        clock.Advance(TimeSpan.FromSeconds(2));
        var stopping = helper.StopAsync(default);
        await wire.Canceled.Task.WaitAsync(Bound);
        wire.Release.TrySetResult();
        await stopping.WaitAsync(Bound);
        await observed.Task.WaitAsync(Bound);

        var worker = capture.Spans.Single(item => item.Operation == "Maintenance");
        await Assert.That(worker.Start).IsEqualTo(start);
        await Assert.That(worker.Duration).IsEqualTo(TimeSpan.FromSeconds(2));
        await Assert.That(worker.Parent).IsEqualTo(parent.SpanId);
        await Assert.That(worker.Tags["termination"] as string).IsEqualTo("ShutdownCanceled");
        await Assert.That(callbackError).IsNull();
        await capture.WorkerMeasured.Task.WaitAsync(Bound);
        await Assert.That(capture.Measurements.Single(item => item.Operation == "Maintenance").Duration).IsEqualTo(2d);
        await Assert.That(helper.State).IsEqualTo(AuthenticationMaintenanceState.Stopped);
        await Assert.That(original.Reveal()).IsEqualTo("original-canary");
        await Assert.That(wire.Disposed).IsFalse();
    }

    [Test]
    [Arguments("sample")]
    [Arguments("start")]
    [Arguments("stop")]
    [Arguments("counter")]
    [Arguments("histogram")]
    public async Task HostileMaintenanceStartListenersCanJoinStopWithoutChangingOwnership(string phase)
    {
        var clock = new Clock();
        using var wire = new Wire();
        using var original = SecretMaterial.FromText("original-canary");
        await using var session = Session(clock, wire, original);
        using var copy = (await session.GetTokenAsync(default)).Value;
        await using var helper = new InfisicalAuthenticationMaintenance(session, TimeSpan.FromSeconds(5));
        using var parent = Parent();
        using var replacement = new Activity("replacement-canary").Start();
        replacement.AddBaggage("protected", "replacement-canary");
        Activity.Current = parent;
        Exception? error = null;
        bool called = false;
        using var capture = new Capture(callback: (callback, operation) =>
        {
            if (callback != phase || operation != "MaintenanceStart" || called) return;
            called = true;
            Activity.Current = replacement;
            parent.Dispose();
            try { helper.StopAsync(default).WaitAsync(Bound).GetAwaiter().GetResult(); }
            catch (Exception exception) { error = exception; }
            throw new InvalidOperationException("listener-canary");
        });

        await helper.StartAsync(default);

        await Assert.That(called).IsTrue();
        await Assert.That(error).IsNull();
        await Assert.That(helper.State).IsEqualTo(AuthenticationMaintenanceState.Stopped);
        await Assert.That(copy.Material.Reveal()).IsEqualTo("original-canary");
        await Assert.That(original.Reveal()).IsEqualTo("original-canary");
        await Assert.That(wire.Entered.Task.IsCompleted).IsFalse();
        await Assert.That(wire.Disposed).IsFalse();
        await Assert.That(ReferenceEquals(Activity.Current, parent)).IsTrue();
        await Assert.That(capture.MetricCanary).IsFalse();
    }

    [Test]
    public async Task SuppressedFlowPreservesCallerContextWhenListenerStopsItsParent()
    {
        var clock = new Clock();
        using var wire = new Wire();
        using var original = SecretMaterial.FromText("original-canary");
        await using var session = Session(clock, wire, original);
        await using var helper = new InfisicalAuthenticationMaintenance(session, TimeSpan.FromSeconds(5));
        using var parent = Parent();
        bool called = false;
        bool listenerSuppressed = false;
        using var capture = new Capture(callback: (phase, operation) =>
        {
            if (phase != "stop" || operation != "MaintenanceStart") return;
            called = true;
            listenerSuppressed = ExecutionContext.IsFlowSuppressed();
            parent.Dispose();
        });
        bool restored;
        bool stillSuppressed;

        using (ExecutionContext.SuppressFlow())
        {
            helper.StartAsync(default).GetAwaiter().GetResult();
            restored = ReferenceEquals(Activity.Current, parent);
            stillSuppressed = ExecutionContext.IsFlowSuppressed();
        }

        await Assert.That(called && listenerSuppressed && restored && stillSuppressed).IsTrue();
        await Assert.That(ExecutionContext.IsFlowSuppressed()).IsFalse();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(3)]
    public async Task SamplingKeepsMetricsAndExactMinimumInterval(int sampling)
    {
        var clock = new Clock();
        using var wire = new Wire();
        using var original = SecretMaterial.FromText("original-canary");
        await using var session = Session(clock, wire, original);
        await using var helper = new InfisicalAuthenticationMaintenance(session, TimeSpan.FromSeconds(5));
        using var parent = Parent();
        using var probe = new ActivitySource(Source);
        bool hostSamples = probe.HasListeners();
        using var capture = new Capture((ActivitySamplingResult)sampling);

        await helper.StartAsync(default);

        await Assert.That(capture.Measurements.Single(item => item.Operation == "MaintenanceStart").Duration)
            .IsEqualTo(TimeSpan.FromTicks(1).TotalSeconds);
        if (sampling == 0 && !hostSamples)
            await Assert.That(capture.Spans.IsEmpty).IsTrue();
        else if (!capture.Spans.IsEmpty)
        {
            var span = capture.Spans.Single(item => item.Operation == "MaintenanceStart");
            await Assert.That(span.Duration).IsEqualTo(TimeSpan.FromTicks(1));
            await Assert.That(span.Parent).IsEqualTo(parent.SpanId);
            await Assert.That(span.Baggage).IsEqualTo(string.Empty);
            await Assert.That(span.TraceState).IsNull();
            await Assert.That(span.ParentObject).IsFalse();
        }
    }

    [Test]
    public async Task CanceledMaintenanceStartDoesNotStartTheWorker()
    {
        var clock = new Clock();
        using var wire = new Wire();
        using var original = SecretMaterial.FromText("original-canary");
        await using var session = Session(clock, wire, original, due: true);
        await using var helper = new InfisicalAuthenticationMaintenance(session, TimeSpan.FromSeconds(5));
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        using var capture = new Capture();

        await Assert.That(() => helper.StartAsync(canceled.Token)).Throws<OperationCanceledException>();

        var span = capture.Spans.Single(item => item.Operation == "MaintenanceStart");
        await Assert.That(span.Tags["termination"] as string).IsEqualTo("CallerCanceled");
        await Assert.That(span.Tags["state"] as string).IsEqualTo("NotStarted");
        await Assert.That(helper.State).IsEqualTo(AuthenticationMaintenanceState.NotStarted);
        await Assert.That(wire.Entered.Task.IsCompleted).IsFalse();
    }

    [Test]
    public async Task CanceledStopWaiterCannotCancelOwnedShutdown()
    {
        var clock = new Clock();
        using var wire = new Wire { Hold = true, IgnoreCancellation = true };
        using var original = SecretMaterial.FromText("original-canary");
        await using var session = Session(clock, wire, original, due: true);
        await using var helper = new InfisicalAuthenticationMaintenance(session, TimeSpan.FromSeconds(5));
        using var capture = new Capture();
        await helper.StartAsync(default);
        await wire.Entered.Task.WaitAsync(Bound);
        using var caller = new CancellationTokenSource();
        var canceledWait = helper.StopAsync(caller.Token);
        await wire.Canceled.Task.WaitAsync(Bound);
        var survivingWait = helper.StopAsync(default);
        caller.Cancel();
        await Assert.That(async () => await canceledWait.WaitAsync(Bound)).Throws<OperationCanceledException>();
        bool pending = !survivingWait.IsCompleted;
        wire.Release.TrySetResult();
        await survivingWait.WaitAsync(Bound);
        await capture.StopCompleted.Task.WaitAsync(Bound);

        await Assert.That(pending).IsTrue();
        var stops = capture.Spans.Where(item => item.Operation == "MaintenanceStop").ToArray();
        await Assert.That(stops.Select(item => (string)item.Tags["termination"]!).ToArray())
            .IsEquivalentTo(["CallerCanceled", "Completed"]);
        await Assert.That(session.LastRenewal!.Evidence).IsEqualTo(InfisicalRenewalEvidence.PossiblyDispatched);
        await Assert.That(original.Reveal()).IsEqualTo("original-canary");
    }

    [Test]
    public async Task NativeRenewalListenerCanAlreadyJoinTheHostingWorker()
    {
        var clock = new Clock();
        using var wire = new Wire { Hold = true };
        using var original = SecretMaterial.FromText("original-canary");
        await using var session = Session(clock, wire, original, due: true);
        await using var helper = new InfisicalAuthenticationMaintenance(session, TimeSpan.FromSeconds(5));
        var exported = Signal();
        Exception? error = null;
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == "SecretKit.Infisical",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = activity =>
            {
                if ((string?)activity.GetTagItem("operation") != "Renewal") return;
                try { helper.StopAsync(default).WaitAsync(Bound).GetAwaiter().GetResult(); }
                catch (Exception exception) { error = exception; }
                finally { exported.TrySetResult(); }
            }
        };
        ActivitySource.AddActivityListener(listener);

        await helper.StartAsync(default);
        await wire.Entered.Task.WaitAsync(Bound);
        wire.Release.TrySetResult();
        await exported.Task.WaitAsync(Bound);

        await Assert.That(error).IsNull();
        await Assert.That(helper.State).IsEqualTo(AuthenticationMaintenanceState.Stopped);
        await Assert.That(session.LastRenewal!.Evidence).IsEqualTo(InfisicalRenewalEvidence.Applied);
        await Assert.That(original.Reveal()).IsEqualTo("original-canary");
        await Assert.That(wire.Disposed).IsFalse();
    }

    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static Activity Parent()
    {
        var parent = new Activity("parent-canary").SetIdFormat(ActivityIdFormat.W3C).Start();
        parent.AddBaggage("protected", "baggage-canary");
        parent.TraceStateString = "vendor=tracestate-canary";
        return parent;
    }

    private static HostApplicationBuilder Builder(Wire wire, Clock clock, bool keyed, Action? acquired = null)
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        void Configure(InfisicalHostingOptions options)
        {
            options.Runtime = new()
            {
                Origin = new("https://origin-canary.test"),
                ClientId = "identity-canary",
                ProjectId = "project-canary",
                Lifetime = InfisicalTokenLifetime.Finite,
                OriginalIssuedAt = clock.GetUtcNow(),
                RenewBefore = TimeSpan.FromSeconds(10),
                TimeProvider = clock,
                Network = new() { Transport = InfisicalTransportOptions.HostControlled(wire) }
            };
            options.ClientSecret = _ =>
            {
                acquired?.Invoke();
                return ValueTask.FromResult(SecretMaterial.FromText("bootstrap-canary"));
            };
        }
        if (keyed) builder.Services.AddKeyedSecretKitInfisical("key-canary", Configure).WithStartupAdmission();
        else builder.Services.AddSecretKitInfisical(Configure).WithStartupAdmission();
        return builder;
    }

    private static InfisicalRuntimeSession Runtime(IHost host, bool keyed) => keyed
        ? host.Services.GetRequiredKeyedService<InfisicalRuntimeSession>("key-canary")
        : host.Services.GetRequiredService<InfisicalRuntimeSession>();

    private static InfisicalPeriodicTokenSession Session(Clock time, Wire wire, SecretMaterial material, bool due = false) =>
        new(new("https://origin-canary.test"), material, new()
        {
            OriginalIssuedAt = time.GetUtcNow().AddSeconds(due ? -50 : 0),
            ExpiresAt = time.GetUtcNow().AddSeconds(due ? 10 : 60),
            Lifetime = InfisicalTokenLifetime.Finite,
            ReportedMaximumTtl = TimeSpan.FromSeconds(120)
        }, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30),
            new()
            {
                Transport = InfisicalTransportOptions.HostControlled(wire),
                ShutdownTimeout = TimeSpan.FromSeconds(5)
            }, time);

    private sealed class Clock : TimeProvider
    {
        private readonly TokenMaintenanceTests.ManualTime _time = new(new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero));
        private long _elapsed;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref _elapsed);
        public override DateTimeOffset GetUtcNow() => _time.GetUtcNow();
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            _time.CreateTimer(callback, state, dueTime, period);
        internal void AdvanceElapsed(TimeSpan amount) => Interlocked.Add(ref _elapsed, amount.Ticks);
        internal void Advance(TimeSpan amount) { AdvanceElapsed(amount); _time.Advance(amount); }
    }

    private sealed class Wire : HttpMessageHandler
    {
        internal TaskCompletionSource Entered { get; } = Signal();
        internal TaskCompletionSource Release { get; } = Signal();
        internal TaskCompletionSource Canceled { get; } = Signal();
        internal bool Hold { get; init; }
        internal bool IgnoreCancellation { get; init; }
        internal HttpStatusCode Status { get; init; } = HttpStatusCode.OK;
        internal bool Disposed { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            using var registration = token.Register(() => Canceled.TrySetResult());
            Entered.TrySetResult();
            if (Hold) await (IgnoreCancellation ? Release.Task : Release.Task.WaitAsync(token));
            token.ThrowIfCancellationRequested();
            return new(Status)
            {
                Content = new StringContent(
                    """{"accessToken":"issued-canary","tokenType":"Bearer","expiresIn":60,"accessTokenMaxTTL":120}""")
            };
        }
        protected override void Dispose(bool disposing) { Disposed = true; Release.TrySetResult(); base.Dispose(disposing); }
    }

    private sealed record Span(string Operation, DateTime Start, TimeSpan Duration, ActivityTraceId Trace,
        ActivitySpanId Parent, string Baggage, string? TraceState, bool ParentObject, Dictionary<string, object?> Tags);
    private sealed record Measurement(string Operation, double Duration, Dictionary<string, object?> Tags);

    private sealed class Capture : IDisposable
    {
        private readonly ActivityListener _listener;
        private readonly MeterListener _meter = new();
        internal ConcurrentQueue<Span> Spans { get; } = new();
        internal ConcurrentQueue<Measurement> Measurements { get; } = new();
        internal TaskCompletionSource WorkerMeasured { get; } = Signal();
        internal TaskCompletionSource StopCompleted { get; } = Signal();
        internal int Published;
        internal bool MetricCanary;

        internal Capture(ActivitySamplingResult sampling = ActivitySamplingResult.AllDataAndRecorded,
            Action<string, string>? callback = null)
        {
            _listener = new()
            {
                ShouldListenTo = source => source.Name == Source,
                Sample = (ref ActivityCreationOptions<ActivityContext> options) =>
                {
                    callback?.Invoke("sample", (string?)options.Tags?.First(pair => pair.Key == "operation").Value ?? "");
                    return sampling;
                },
                ActivityStarted = activity => callback?.Invoke("start", (string?)activity.GetTagItem("operation") ?? ""),
                ActivityStopped = activity =>
                {
                    string operation = (string?)activity.GetTagItem("operation") ?? "";
                    Spans.Enqueue(new(operation, activity.StartTimeUtc, activity.Duration, activity.TraceId,
                        activity.ParentSpanId, string.Join(";", activity.Baggage.Select(pair => pair.Value)),
                        activity.TraceStateString, activity.Parent is not null,
                        activity.TagObjects.ToDictionary(pair => pair.Key, pair => pair.Value)));
                    callback?.Invoke("stop", operation);
                }
            };
            ActivitySource.AddActivityListener(_listener);
            _meter.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name != Source) return;
                Interlocked.Increment(ref Published);
                listener.EnableMeasurementEvents(instrument);
            };
            _meter.SetMeasurementEventCallback<long>((_, _, tags, _) =>
            {
                MetricCanary |= Activity.Current?.Baggage.Any() == true;
                callback?.Invoke("counter", (string?)tags.ToArray().First(pair => pair.Key == "operation").Value ?? "");
            });
            _meter.SetMeasurementEventCallback<double>((_, value, tags, _) =>
            {
                MetricCanary |= Activity.Current?.Baggage.Any() == true;
                var fields = tags.ToArray().ToDictionary(pair => pair.Key, pair => pair.Value);
                string operation = (string)fields["operation"]!;
                Measurements.Enqueue(new(operation, value, fields));
                callback?.Invoke("histogram", operation);
                if (operation == "Maintenance") WorkerMeasured.TrySetResult();
                if (operation == "MaintenanceStop" && (string?)fields["termination"] == "Completed")
                    StopCompleted.TrySetResult();
            });
            _meter.Start();
        }

        public void Dispose() { _listener.Dispose(); _meter.Dispose(); }
    }
}
