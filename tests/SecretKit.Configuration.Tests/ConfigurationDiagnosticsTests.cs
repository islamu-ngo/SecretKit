using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;

namespace SecretKit.Configuration.Tests;

[NotInParallel]
public sealed class ConfigurationDiagnosticsTests
{
    private const string Source = "SecretKit.Extensions.Configuration";
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    [Test]
    public async Task CompletedCollectionFreezesTimeAndOpaqueParentBeforeHeldCallbacks()
    {
        var clock = new Clock();
        DateTime start = clock.GetUtcNow().UtcDateTime;
        var entered = Signal();
        var release = Signal();
        var listenerEntered = Signal();
        var listenerRelease = Signal();
        var reader = new Reader { Before = async _ => { entered.SetResult(); await release.Task; } };
        using var parent = Parent();
        using var capture = new Capture();
        capture.Callback = (stage, _) =>
        {
            if (stage == "start")
            {
                listenerEntered.TrySetResult();
                listenerRelease.Task.WaitAsync(Bound).GetAwaiter().GetResult();
            }
            clock.Advance(TimeSpan.FromSeconds(7));
        };
        using var loader = new SecretSnapshotLoader([reader.Select("key-canary")], clock);
        var pending = loader.RefreshAsync().AsTask();
        await entered.Task.WaitAsync(Bound);
        await Assert.That(capture.Spans.IsEmpty).IsTrue();
        clock.Advance(TimeSpan.FromSeconds(2));
        clock.JumpUtc(TimeSpan.FromDays(-2));
        release.SetResult();
        try
        {
            await Task.WhenAny(listenerEntered.Task, pending).WaitAsync(Bound);
            await Assert.That(listenerEntered.Task.IsCompleted).IsTrue();
            clock.Advance(TimeSpan.FromSeconds(11));
        }
        finally { listenerRelease.TrySetResult(); }
        await Assert.That((await pending.WaitAsync(Bound)).IsSuccess).IsTrue();
        var span = capture.Spans.Single();
        await Assert.That(span.StartTimeUtc).IsEqualTo(start);
        await Assert.That(span.Duration).IsEqualTo(TimeSpan.FromSeconds(2));
        await Assert.That(capture.Durations.Single().Value).IsEqualTo(2d);
        await Assert.That(span.ParentSpanId).IsEqualTo(parent.SpanId);
        await Assert.That(span.TraceId).IsEqualTo(parent.TraceId);
        await Assert.That(ReferenceEquals(Activity.Current, parent)).IsTrue();
        await Closed(capture);
    }

    [Test]
    public async Task PublicationAndRetirementDescribeActualWorkWithoutMaterialUseEvents()
    {
        var clock = new Clock();
        var reader = new Reader { Before = _ => { clock.Advance(TimeSpan.FromSeconds(2)); return Task.CompletedTask; } };
        var client = new Client { Dispose = () => { clock.Advance(TimeSpan.FromSeconds(3)); return ValueTask.CompletedTask; } };
        using var capture = new Capture();
        var owner = Coordinator(reader, clock, client);
        await Assert.That(capture.Spans.IsEmpty).IsTrue();
        var observation = await owner.EnableAsync();
        await Assert.That(observation.Active).IsTrue();
        await Assert.That(capture.Spans.Select(Operation).Order().ToArray())
            .IsEquivalentTo(new[] { "Collection", "Publication" });
        var publication = capture.Spans.Single(s => Operation(s) == "Publication");
        await Assert.That(publication.GetTagItem("state") as string).IsEqualTo("Fresh");
        var lease = owner.Acquire()!;
        await Assert.That(await lease.ExecuteAsync((borrowed, _) => ValueTask.FromResult(ReferenceEquals(client, borrowed)))).IsTrue();
        await Assert.That(capture.Spans.Count).IsEqualTo(2);
        await owner.DisableAsync();
        await Assert.That(client.Disposed).IsFalse();
        await lease.DisposeAsync();
        await Assert.That(client.Disposed).IsTrue();
        var retirement = capture.Spans.Single(s => Operation(s) == "Retirement");
        await Assert.That(retirement.Duration).IsEqualTo(TimeSpan.FromSeconds(3));
        await Assert.That(retirement.GetTagItem("state") as string).IsEqualTo("Retired");
        await owner.DisposeAsync();
        await Assert.That(capture.Spans.Count).IsEqualTo(3);
        await Closed(capture);
    }

    [Test]
    [Arguments("completed", "Completed", "Success")]
    [Arguments("denied", "Completed", "Denied")]
    [Arguments("dependency", "DependencyCanceled", "Unavailable")]
    [Arguments("fault", "Faulted", "Unavailable")]
    [Arguments("deadline", "DeadlineExceeded", "Unavailable")]
    [Arguments("caller", "CallerCanceled", "Unknown")]
    public async Task CollectionTerminationPreservesPublicOutcomeAndCancellationPrecedence(
        string mode, string termination, string outcome)
    {
        var clock = new Clock();
        using var caller = new CancellationTokenSource();
        var reader = new Reader
        {
            Before = _ =>
            {
                if (mode is "deadline" or "caller") clock.Advance(TimeSpan.FromSeconds(3));
                if (mode == "caller") caller.Cancel();
                if (mode is "deadline" or "caller" or "dependency") throw new OperationCanceledException("dependency-canary");
                if (mode == "fault") throw new InvalidOperationException("exception-canary");
                return Task.CompletedTask;
            },
            Failure = mode == "denied" ? SecretStatus.Denied : null
        };
        using var capture = new Capture();
        using var loader = new SecretSnapshotLoader([reader.Select("key-canary")], clock,
            new(collectionTimeout: TimeSpan.FromSeconds(2)));
        if (mode == "caller")
            await Assert.That(async () => await loader.RefreshAsync(caller.Token)).Throws<OperationCanceledException>();
        else
        {
            var result = await loader.RefreshAsync(caller.Token);
            await Assert.That(result.Status.ToString()).IsEqualTo(outcome);
            if (mode is "fault" or "dependency") await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.TransportFailure);
            if (mode == "deadline") await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.DeadlineExceeded);
        }
        var span = capture.Spans.Single();
        await Assert.That(span.GetTagItem("termination") as string).IsEqualTo(termination);
        await Assert.That(span.GetTagItem("outcome") as string).IsEqualTo(outcome);
        await Closed(capture);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OnlyChosenOrdinalFailureContributesDependencyCancellation(bool dependencyFirst)
    {
        var held = Signal();
        var later = Signal();
        var first = new Reader
        {
            Before = async _ =>
            {
                await held.Task;
                if (dependencyFirst) throw new OperationCanceledException("first-canary");
            },
            Failure = SecretStatus.Denied
        };
        var second = new Reader
        {
            Before = _ =>
            {
                later.SetResult();
                if (!dependencyFirst) throw new OperationCanceledException("later-canary");
                return Task.CompletedTask;
            },
            Failure = SecretStatus.Denied
        };
        using var capture = new Capture();
        using var loader = new SecretSnapshotLoader([first.Select("first"), second.Select("second")],
            options: new(maximumConcurrency: 2));
        var pending = loader.RefreshAsync().AsTask();
        await later.Task.WaitAsync(Bound);
        held.SetResult();
        var result = await pending.WaitAsync(Bound);
        await Assert.That(result.Status).IsEqualTo(dependencyFirst ? SecretStatus.Unavailable : SecretStatus.Denied);
        await Assert.That(capture.Spans.Single().GetTagItem("termination") as string)
            .IsEqualTo(dependencyFirst ? "DependencyCanceled" : "Completed");
    }

    [Test]
    [Arguments("sample")]
    [Arguments("start")]
    [Arguments("stop")]
    [Arguments("counter")]
    [Arguments("histogram")]
    public async Task HostileCollectionListenerReentersAfterStorageAndAdmissionAreReleased(string selected)
    {
        var reader = new Reader();
        using var parent = Parent();
        using var changed = new Activity("listener-canary");
        using var capture = new Capture();
        using var loader = new SecretSnapshotLoader([reader.Select("key-canary")]);
        bool called = false, cleaned = false, refreshed = false;
        capture.Callback = (stage, _) =>
        {
            if (stage != selected || called) return;
            called = true;
            try { reader.Delivered.Single().Reveal(); }
            catch (ObjectDisposedException) { cleaned = true; }
            refreshed = loader.RefreshAsync().AsTask().WaitAsync(Bound).GetAwaiter().GetResult().IsSuccess;
            Activity.Current = changed.Start();
            throw new InvalidOperationException("listener-canary");
        };
        var result = await loader.RefreshAsync();
        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(called && cleaned && refreshed).IsTrue();
        await Assert.That(ReferenceEquals(Activity.Current, parent)).IsTrue();
        // A throwing activity callback must not suppress independent measurements.
        if (selected is "sample" or "start" or "stop")
            await Assert.That(capture.Durations.Count).IsEqualTo(1);
        if (selected == "counter")
            await Assert.That(capture.Durations.Count).IsEqualTo(1);
        if (selected == "histogram")
            await Assert.That(capture.Counts.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RetirementListenerCanSynchronouslyJoinLeaseAndCoordinatorDisposal(bool operationPin)
    {
        var client = new Client();
        using var capture = new Capture();
        var owner = Coordinator(new Reader(), new Clock(), client);
        await owner.EnableAsync();
        var lease = owner.Acquire()!;
        await owner.DisableAsync();
        bool joined = false;
        capture.Callback = (stage, activity) =>
        {
            if (stage != "stop" || Operation(activity!) != "Retirement") return;
            bool disposed = client.Disposed;
            lease.DisposeAsync().AsTask().WaitAsync(Bound).GetAwaiter().GetResult();
            owner.DisposeAsync().AsTask().WaitAsync(Bound).GetAwaiter().GetResult();
            joined = disposed;
        };
        if (operationPin)
            await lease.ExecuteAsync(async (_, _) => { await lease.DisposeAsync(); return 1; });
        else await lease.DisposeAsync();
        await Assert.That(joined).IsTrue();
        await Assert.That(capture.Spans.Count(s => Operation(s) == "Retirement")).IsEqualTo(1);
        await owner.DisposeAsync();
    }

    [Test]
    [Arguments("healthy")]
    [Arguments("capture")]
    [Arguments("complete")]
    public async Task DiagnosticClockFailureCannotStrandRetiredClientOwnership(string fault)
    {
        var clock = new Clock();
        using var material = SecretMaterial.FromText("owned-client-canary");
        var client = new Client
        {
            Dispose = () =>
            {
                material.Dispose();
                if (fault == "complete") clock.ThrowTimestamp = true;
                return ValueTask.CompletedTask;
            }
        };
        var owner = Coordinator(new Reader(), clock, client);
        await owner.EnableAsync();
        var lease = owner.Acquire()!;
        await owner.DisableAsync();
        if (fault == "capture") clock.ThrowTimestamp = true;
        Exception? failure = null;

        try { await lease.DisposeAsync(); }
        catch (Exception error) { failure = error; }

        await Assert.That(client.Disposed).IsTrue();
        await Assert.That(() => material.Use(static value => value.Length)).Throws<ObjectDisposedException>();
        await owner.DisposeAsync().AsTask().WaitAsync(Bound);
        await Assert.That(failure).IsNull();
    }

    private static string Operation(Activity activity) => (string)activity.GetTagItem("operation")!;
    private static Activity Parent()
    {
        var parent = new Activity("caller-canary").SetIdFormat(ActivityIdFormat.W3C).Start();
        parent.AddBaggage("baggage-canary", "value-canary");
        parent.TraceStateString = "tenant=tracestate-canary";
        return parent;
    }

    private static SecretGenerationCoordinator<Client> Coordinator(Reader reader, TimeProvider clock, Client client,
        SecretGenerationStalePolicy policy = SecretGenerationStalePolicy.FailClosed) =>
        new(reader, new Dictionary<string, SecretReference> { ["key-canary"] = reader.Select("key-canary").Reference },
            (_, _) => ValueTask.FromResult(SecretOutcome<Client>.Success(client)), policy, TimeSpan.FromHours(1), clock);

    private static async Task Closed(Capture capture)
    {
        string[] keys = ["operation", "outcome", "reason", "termination", "state"];
        foreach (var activity in capture.Spans)
        {
            await Assert.That(activity.TagObjects.Select(t => t.Key).Order().ToArray()).IsEquivalentTo(keys);
            await Assert.That(activity.TagObjects.All(t => !(t.Value?.ToString()?.Contains("canary", StringComparison.Ordinal) ?? false))).IsTrue();
            await Assert.That(activity.Baggage.Any()).IsFalse();
            await Assert.That(activity.TraceStateString).IsNull();
            await Assert.That(activity.Parent).IsNull();
        }
        foreach (var measurement in capture.Counts.Concat(capture.Durations))
        {
            await Assert.That(measurement.Tags.Select(t => t.Key).Order().ToArray()).IsEquivalentTo(keys);
            await Assert.That(measurement.Tags.All(t => !(t.Value?.ToString()?.Contains("canary", StringComparison.Ordinal) ?? false))).IsTrue();
        }
    }

    private sealed record Measurement(double Value, KeyValuePair<string, object?>[] Tags);
    private sealed class Capture : IDisposable
    {
        private readonly ActivityListener _activities;
        private readonly MeterListener _meter = new();
        internal readonly ConcurrentQueue<Activity> Spans = new();
        internal readonly ConcurrentQueue<Measurement> Counts = new(), Durations = new();
        internal Action<string, Activity?>? Callback;
        internal Capture(ActivitySamplingResult sampling = ActivitySamplingResult.AllDataAndRecorded)
        {
            _activities = new ActivityListener
            {
                ShouldListenTo = source => source.Name == Source,
                Sample = (ref ActivityCreationOptions<ActivityContext> options) =>
                { Callback?.Invoke("sample", null); return sampling; },
                ActivityStarted = activity => Callback?.Invoke("start", activity),
                ActivityStopped = activity => { Spans.Enqueue(activity); Callback?.Invoke("stop", activity); }
            };
            ActivitySource.AddActivityListener(_activities);
            _meter.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == Source) listener.EnableMeasurementEvents(instrument);
            };
            _meter.SetMeasurementEventCallback<long>((_, value, tags, _) =>
            { Counts.Enqueue(new(value, tags.ToArray())); Callback?.Invoke("counter", null); });
            _meter.SetMeasurementEventCallback<double>((_, value, tags, _) =>
            { Durations.Enqueue(new(value, tags.ToArray())); Callback?.Invoke("histogram", null); });
            _meter.Start();
        }
        public void Dispose() { _activities.Dispose(); _meter.Dispose(); }
    }

    private sealed class Clock : TimeProvider
    {
        private readonly CollectionTime _timers = new();
        private long _timestamp, _utc;
        internal bool ThrowTimestamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => ThrowTimestamp
            ? throw new InvalidOperationException("diagnostic-clock-canary")
            : Interlocked.Read(ref _timestamp);
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddTicks(Interlocked.Read(ref _utc));
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            _timers.CreateTimer(callback, state, dueTime, period);
        internal void Advance(TimeSpan amount)
        {
            Interlocked.Add(ref _timestamp, amount.Ticks);
            Interlocked.Add(ref _utc, amount.Ticks);
            _timers.Advance(amount);
        }
        internal void JumpUtc(TimeSpan amount) => Interlocked.Add(ref _utc, amount.Ticks);
    }

    private sealed class Client : IAsyncDisposable
    {
        internal bool Disposed;
        internal Func<ValueTask>? Dispose;
        public async ValueTask DisposeAsync()
        {
            if (Dispose is not null) await Dispose();
            Disposed = true;
        }
    }
    private sealed class Address : SecretAddress;
    private sealed class Reader : ISecretReader
    {
        internal Func<CancellationToken, Task>? Before;
        internal SecretStatus? Failure;
        internal readonly ConcurrentBag<SecretMaterial> Delivered = new();
        public SecretAuthority Authority { get; } = new();
        internal SecretSelection Select(string key) => new(key, this, new(Authority, new Address()));
        public async ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference, CancellationToken cancellationToken = default)
        {
            if (Before is not null) await Before(cancellationToken);
            if (Failure is { } failure) return SecretOutcome<SecretRead>.Failure(failure);
            var material = SecretMaterial.FromText("material-canary");
            Delivered.Add(material);
            return SecretOutcome<SecretRead>.Success(new(material,
                new(reference, "version-canary", DateTimeOffset.UnixEpoch, SecretValidity.Valid)));
        }
    }
}
