using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Threading.Tasks.Sources;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

[NotInParallel]
public sealed class DiagnosticTimingTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);
    private const string ReadBody =
        """{"secret":{"secretKey":"key-canary","secretValueHidden":false,"secretValue":"value-canary"}}""";
    private const string LoginBody =
        """{"accessToken":"issued-canary","tokenType":"Bearer","expiresIn":120,"accessTokenMaxTTL":0}""";

    [Test]
    public async Task DiagnosticCompletionClockFailureCannotReplaceCallerCancellation()
    {
        var clock = new Clock();
        using var tokens = new CancellationTokens(true);
        using var wire = new HeldWire();
        using var caller = new CancellationTokenSource();
        await using var client = new InfisicalClient(new("https://api.test"), tokens,
            new() { Transport = InfisicalTransportOptions.HostControlled(wire) }, clock);
        var reading = client.ReadAsync(Reference(client), caller.Token).AsTask();
        await tokens.Registered.Task.WaitAsync(Bound);
        clock.FailTimestamp = true;
        caller.Cancel();
        try
        {
            await Assert.That(async () => await reading.WaitAsync(Bound)).Throws<OperationCanceledException>();
        }
        finally { clock.FailTimestamp = false; }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ShutdownListenerCanJoinDisposalAfterCredentialCancellation(bool asynchronous)
    {
        var clock = new Clock();
        using var tokens = new CancellationTokens(asynchronous);
        using var wire = new HeldWire();
        await using var client = new InfisicalClient(new("https://api.test"), tokens,
            new() { Transport = InfisicalTransportOptions.HostControlled(wire) }, clock);
        Exception? listenerFailure = null;
        bool joined = false;
        using var capture = new Capture(ActivitySamplingResult.AllData, (phase, activity) =>
        {
            if (phase != "stop" || (string?)activity?.GetTagItem("operation") != "Read") return;
            try
            {
                client.DisposeAsync().AsTask().WaitAsync(Bound).GetAwaiter().GetResult();
                joined = true;
            }
            catch (Exception error) { listenerFailure = error; }
        });
        var reading = client.ReadAsync(Reference(client)).AsTask();
        await tokens.Registered.Task.WaitAsync(Bound);

        var stopping = client.DisposeAsync().AsTask();

        await Assert.That(async () => await reading.WaitAsync(Bound + Bound)).Throws<OperationCanceledException>();
        await stopping.WaitAsync(Bound);
        await Assert.That(listenerFailure).IsNull();
        await Assert.That(joined).IsTrue();
        await Assert.That(tokens.Disposed).IsFalse();
        await Assert.That(wire.Entered.Task.IsCompleted).IsFalse();
    }

    private sealed class CancellationTokens(bool asynchronous) : IInfisicalTokenSource,
        IValueTaskSource<SecretOutcome<InfisicalAccessToken>>, IDisposable
    {
        private ManualResetValueTaskSourceCore<SecretOutcome<InfisicalAccessToken>> _completion =
            new() { RunContinuationsAsynchronously = asynchronous };
        private CancellationTokenRegistration _registration;
        internal TaskCompletionSource Registered { get; } = Signal();
        internal bool Disposed { get; private set; }

        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            _registration = cancellationToken.Register(() =>
                _completion.SetException(new OperationCanceledException(cancellationToken)));
            return new(this, _completion.Version);
        }

        public SecretOutcome<InfisicalAccessToken> GetResult(short token) => _completion.GetResult(token);
        public ValueTaskSourceStatus GetStatus(short token) => _completion.GetStatus(token);
        public void OnCompleted(Action<object?> continuation, object? state, short token,
            ValueTaskSourceOnCompletedFlags flags)
        {
            _completion.OnCompleted(continuation, state, token, flags);
            Registered.TrySetResult();
        }

        public void Dispose() { Disposed = true; _registration.Dispose(); }
    }

    [Test]
    public async Task CompletedIntervalExcludesHeldListenersAndUtcJumps()
    {
        var clock = new Clock();
        DateTime expectedStart = clock.GetUtcNow().UtcDateTime;
        using var wire = new HeldWire();
        using var parent = Parent();
        var entered = Signal();
        var release = Signal();
        using var capture = new Capture(ActivitySamplingResult.AllDataAndRecorded, (phase, _) =>
        {
            if (phase == "sample") clock.Advance(TimeSpan.FromSeconds(3));
            if (phase == "start")
            {
                entered.TrySetResult();
                release.Task.WaitAsync(Bound).GetAwaiter().GetResult();
            }
            if (phase == "stop") clock.Advance(TimeSpan.FromSeconds(5));
            if (phase == "counter") clock.Advance(TimeSpan.FromSeconds(7));
        });
        await using var client = Client(wire, clock);
        Task<SecretOutcome<SecretRead>> pending = client.ReadAsync(Reference(client)).AsTask();
        await wire.Entered.Task.WaitAsync(Bound);
        await Assert.That(capture.Spans.IsEmpty).IsTrue();
        clock.Advance(TimeSpan.FromSeconds(2));
        clock.JumpUtc(TimeSpan.FromDays(-2));
        wire.Release.TrySetResult();
        try
        {
            await entered.Task.WaitAsync(Bound);
            clock.Advance(TimeSpan.FromSeconds(11));
        }
        finally { release.TrySetResult(); }
        using SecretRead read = (await pending.WaitAsync(Bound)).Value;

        SpanObservation span = capture.Spans.Single();
        await Assert.That(span.Start).IsEqualTo(expectedStart);
        await Assert.That(span.Duration).IsEqualTo(TimeSpan.FromSeconds(2));
        await Assert.That(capture.Durations.Single()).IsEqualTo(2d);
        await Assert.That(span.ParentSpan).IsEqualTo(parent.SpanId);
        await Assert.That(read.Material.Reveal()).IsEqualTo("value-canary");
    }

    [Test]
    [Arguments(-1, "unchanged")]
    [Arguments(0, "unchanged")]
    [Arguments(1, "unchanged")]
    [Arguments(2, "unchanged")]
    [Arguments(3, "unchanged")]
    [Arguments(1, "absent")]
    [Arguments(3, "absent")]
    [Arguments(1, "changed")]
    [Arguments(3, "changed")]
    [Arguments(1, "disposed")]
    [Arguments(3, "disposed")]
    public async Task SamplingPreservesCapturedOpaqueParentWithoutAmbientMaterial(int sampling, string ambient)
    {
        var clock = new Clock();
        Activity? previous = Activity.Current;
        using Activity? parent = ambient == "absent" ? null : Parent();
        if (parent is null) Activity.Current = null;
        ActivityTraceId trace = parent?.TraceId ?? default;
        ActivitySpanId span = parent?.SpanId ?? default;
        using var replacement = new Activity("replacement-canary").SetIdFormat(ActivityIdFormat.W3C).Start();
        replacement.AddBaggage("replacement", "replacement-canary");
        Activity.Current = parent;
        using var wire = new HeldWire();
        using var probe = new ActivitySource("SecretKit.Infisical");
        bool hostSamples = probe.HasListeners();
        using var capture = new Capture(sampling < 0 ? null : (ActivitySamplingResult)sampling, (phase, _) =>
        {
            if (phase != "sample") return;
            Activity.Current = replacement;
        });
        await using var client = Client(wire, clock);
        try
        {
            var pending = client.ReadAsync(Reference(client)).AsTask();
            await wire.Entered.Task.WaitAsync(Bound);
            if (ambient == "changed") Activity.Current = replacement;
            if (ambient == "disposed") parent!.Dispose();
            Activity? expectedAmbient = Activity.Current;
            clock.Advance(TimeSpan.FromSeconds(1));
            wire.Release.TrySetResult();
            using SecretRead read = (await pending.WaitAsync(Bound)).Value;
            await Assert.That(ReferenceEquals(Activity.Current, expectedAmbient)).IsTrue();
            await Assert.That(capture.Durations.Single()).IsEqualTo(1d);
            // A drop vote cannot veto another host listener. The focused run
            // disables TUnit's HTML trace collector to exercise actual dropping;
            // the ordinary suite also preserves safety when that collector votes.
            if (sampling < 0 || sampling == 0 && !hostSamples)
            {
                await Assert.That(capture.Spans.IsEmpty).IsTrue();
                return;
            }
            if (sampling == 0 && capture.Spans.IsEmpty) return;
            SpanObservation observed = capture.Spans.Single();
            await Assert.That(observed.ParentSpan).IsEqualTo(span);
            if (parent is not null) await Assert.That(observed.Trace).IsEqualTo(trace);
            await Assert.That(observed.Baggage).IsEqualTo(string.Empty);
            await Assert.That(observed.TraceState).IsNull();
            await Assert.That(observed.HasParentObject).IsFalse();
            await Assert.That(capture.SampleParent.TraceState).IsNull();
            await Assert.That(capture.SampleAmbient).IsNull();
        }
        finally { Activity.Current = previous; }
    }

    [Test]
    public async Task SiblingOperationsKeepIndependentParentsAndCancellation()
    {
        var firstClock = new Clock();
        var secondClock = new Clock();
        using var firstWire = new HeldWire();
        using var secondWire = new HeldWire();
        using var caller = new CancellationTokenSource();
        using var capture = new Capture(ActivitySamplingResult.AllData);
        await using var firstClient = Client(firstWire, firstClock);
        await using var secondClient = Client(secondWire, secondClock);
        using var firstParent = Parent();
        var first = firstClient.ReadAsync(Reference(firstClient), caller.Token).AsTask();
        using var secondParent = new Activity("sibling").SetParentId(
            ActivityTraceId.CreateRandom(), ActivitySpanId.CreateRandom(), ActivityTraceFlags.None).Start();
        var second = secondClient.ReadAsync(Reference(secondClient)).AsTask();
        await Task.WhenAll(firstWire.Entered.Task, secondWire.Entered.Task).WaitAsync(Bound);
        firstClock.Advance(TimeSpan.FromSeconds(2));
        caller.Cancel();
        secondClock.Advance(TimeSpan.FromSeconds(3));
        secondWire.Release.TrySetResult();
        await Assert.That(async () => await first.WaitAsync(Bound)).Throws<OperationCanceledException>();
        using SecretRead read = (await second.WaitAsync(Bound)).Value;

        var canceled = capture.Spans.Single(span => span.ParentSpan == firstParent.SpanId);
        var settled = capture.Spans.Single(span => span.ParentSpan == secondParent.SpanId);
        await Assert.That(canceled.Tags["termination"] as string).IsEqualTo("CallerCanceled");
        await Assert.That(settled.Tags["termination"] as string).IsEqualTo("Completed");
        await Assert.That(canceled.Trace).IsEqualTo(firstParent.TraceId);
        await Assert.That(settled.Trace).IsEqualTo(secondParent.TraceId);
        await Assert.That(canceled.Duration).IsEqualTo(TimeSpan.FromSeconds(2));
        await Assert.That(settled.Duration).IsEqualTo(TimeSpan.FromSeconds(3));
        await Assert.That(capture.Spans.Count).IsEqualTo(2);
    }

    [Test]
    public async Task EscapingFailureCannotBeReportedAsSuccessfulSettlement()
    {
        var clock = new Clock();
        using var wire = new FailureEvidenceTests.Wire(_ => throw new InvalidOperationException("Unexpected dispatch."));
        using var capture = new Capture(ActivitySamplingResult.AllData);
        await using var client = Client(wire, clock);

        await Assert.That(async () => await client.ReadAsync(null!)).Throws<ArgumentNullException>();

        SpanObservation span = capture.Spans.Single();
        await Assert.That(span.Tags["termination"] as string).IsEqualTo("Faulted");
        await Assert.That(span.Tags["outcome"] as string).IsEqualTo("Unknown");
    }

    [Test]
    [Arguments(0, 1)]
    [Arguments(1, 1)]
    [Arguments(9, 1)]
    [Arguments(10, 1)]
    [Arguments(20, 2)]
    public async Task SubtickIntervalsUseTheSameDocumentedActivityFloor(int timestamps, int ticks)
    {
        var clock = new Clock(TimeSpan.TicksPerSecond * 10);
        using var wire = new FailureEvidenceTests.Wire(_ =>
        {
            clock.AdvanceTimestamp(timestamps);
            return new(HttpStatusCode.OK) { Content = new StringContent(ReadBody) };
        });
        using var capture = new Capture(ActivitySamplingResult.AllData);
        await using var client = Client(wire, clock);

        using SecretRead read = (await client.ReadAsync(Reference(client))).Value;

        await Assert.That(capture.Spans.Single().Duration).IsEqualTo(TimeSpan.FromTicks(ticks));
        await Assert.That(capture.Durations.Single()).IsEqualTo(TimeSpan.FromTicks(ticks).TotalSeconds);
    }

    [Test]
    [Arguments("sample")]
    [Arguments("start")]
    [Arguments("stop")]
    [Arguments("counter")]
    [Arguments("histogram")]
    public async Task HostileCallbacksPreserveReceiptMaterialAndAmbientState(string hostilePhase)
    {
        using var parent = Parent();
        using var replacement = new Activity("host-canary").SetIdFormat(ActivityIdFormat.W3C).Start();
        Activity.Current = parent;
        var clock = new Clock();
        using var wire = new FailureEvidenceTests.Wire(_ => new(HttpStatusCode.Conflict));
        await using var client = Client(wire, clock);
        bool reentered = false;
        Exception? error = null;
        using var capture = new Capture(ActivitySamplingResult.AllData, (phase, activity) =>
        {
            if (phase != hostilePhase || reentered) return;
            reentered = true;
            Activity.Current = replacement;
            parent.Dispose();
            try
            {
                var nested = client.ReadAsync(Reference(client)).AsTask().WaitAsync(Bound).GetAwaiter().GetResult();
                if (nested.Status != SecretStatus.Conflict)
                    error = new InvalidOperationException("Reentrant operation lost its result.");
                client.DisposeAsync().AsTask().WaitAsync(Bound).GetAwaiter().GetResult();
            }
            catch (Exception exception) { error = exception; }
            activity?.Dispose();
            throw new InvalidOperationException("listener-canary");
        });
        var reference = Reference(client);
        var receipt = client.CreateReceipt(reference);
        using var material = SecretMaterial.FromText("mutation-canary");

        var result = await client.CreateAsync(reference, material, receipt);

        await Assert.That(reentered).IsTrue();
        await Assert.That(error).IsNull();
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Conflict);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Conflict);
        await Assert.That(material.Reveal()).IsEqualTo("mutation-canary");
        await Assert.That(ReferenceEquals(Activity.Current, parent)).IsTrue();
        await Assert.That(capture.Durations.Count).IsEqualTo(1);
        await Assert.That(capture.MetricAmbientCanary).IsFalse();
    }

    [Test]
    [Arguments("caller", "CallerCanceled")]
    [Arguments("shutdown", "ShutdownCanceled")]
    [Arguments("deadline", "DeadlineExceeded")]
    [Arguments("dependency", "DependencyCanceled")]
    [Arguments("transport", "Completed")]
    [Arguments("caller-deadline", "CallerCanceled")]
    public async Task CancellationRetainsItsCauseWithoutInventingSuccess(string cause, string expected)
    {
        var clock = new Clock();
        using var caller = new CancellationTokenSource();
        using var wire = new HeldWire
        {
            Failure = cause == "dependency" ? new OperationCanceledException("dependency-canary") :
                cause == "transport" ? new HttpRequestException("transport-canary") : null
        };
        using var capture = new Capture(ActivitySamplingResult.AllData);
        await using var client = Client(wire, clock, TimeSpan.FromSeconds(2));
        var pending = client.ReadAsync(Reference(client), caller.Token).AsTask();
        await wire.Entered.Task.WaitAsync(Bound);
        Task? stopping = null;
        if (cause.StartsWith("caller", StringComparison.Ordinal)) caller.Cancel();
        if (cause == "shutdown")
        {
            stopping = client.DisposeAsync().AsTask();
            await wire.CancellationObserved.Task.WaitAsync(Bound);
        }
        if (cause.Contains("deadline", StringComparison.Ordinal)) clock.Advance(TimeSpan.FromSeconds(3));
        wire.Release.TrySetResult();
        if (cause is "caller" or "shutdown" or "caller-deadline")
            await Assert.That(async () => await pending.WaitAsync(Bound)).Throws<OperationCanceledException>();
        else
        {
            var result = await pending.WaitAsync(Bound);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unavailable);
            await Assert.That(result.Reason).IsEqualTo(cause == "deadline"
                ? SecretFailureReason.DeadlineExceeded : SecretFailureReason.TransportFailure);
        }
        if (stopping is not null) await stopping.WaitAsync(Bound);
        SpanObservation span = capture.Spans.Single();
        await Assert.That(span.Tags.GetValueOrDefault("termination") as string).IsEqualTo(expected);
        await Assert.That(span.Tags["outcome"] as string).IsNotEqualTo("Success");
        await Assert.That(capture.MeasurementTags.Single()["termination"] as string).IsEqualTo(expected);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NativeAuthenticationExportsAfterCorrespondingOwnershipReleases(bool deferredRead)
    {
        var clock = new Clock();
        using var wire = new FailureEvidenceTests.Wire(request =>
        {
            clock.Advance(TimeSpan.FromSeconds(1));
            return new(HttpStatusCode.OK)
            {
                Content = new StringContent(request.RequestUri!.AbsolutePath.Contains("login", StringComparison.Ordinal)
                    ? LoginBody : ReadBody)
            };
        });
        await using var runtime = InfisicalRuntimeSession.CreateDeferred(Options(wire, clock),
            _ => ValueTask.FromResult(SecretMaterial.FromText("bootstrap-canary")));
        Exception? callbackError = null;
        bool reentered = false;
        using var capture = new Capture(ActivitySamplingResult.AllData, (phase, _) =>
        {
            if (phase != "stop" || reentered) return;
            reentered = true;
            try
            {
                var authenticated = runtime.EnsureAuthenticatedAsync().AsTask().WaitAsync(Bound).GetAwaiter().GetResult();
                if (!authenticated.IsSuccess)
                    callbackError = new InvalidOperationException("Authentication was not published.");
                runtime.StopAsync().WaitAsync(Bound).GetAwaiter().GetResult();
            }
            catch (Exception exception) { callbackError = exception; }
        });
        if (deferredRead)
        {
            using SecretRead read = (await runtime.Client.ReadAsync(Reference(runtime.Client))).Value;
            await Assert.That(read.Material.Reveal()).IsEqualTo("value-canary");
        }
        else
        {
            var result = await runtime.EnsureAuthenticatedAsync();
            await Assert.That(result.IsSuccess).IsTrue();
        }
        await Assert.That(callbackError).IsNull();
        await Assert.That(reentered).IsTrue();
        await Assert.That(runtime.OpeningAttempt.LoginReceipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
    }

    [Test]
    public async Task NestedLoginKeepsItsOwnIntervalWhileOuterReadDefersExport()
    {
        var clock = new Clock();
        using var wire = new HeldWire { LoginImmediately = true, Clock = clock };
        using var capture = new Capture(ActivitySamplingResult.AllData);
        await using var runtime = InfisicalRuntimeSession.CreateDeferred(Options(wire, clock),
            _ => ValueTask.FromResult(SecretMaterial.FromText("bootstrap-canary")));
        var pending = runtime.Client.ReadAsync(Reference(runtime.Client)).AsTask();
        await wire.Entered.Task.WaitAsync(Bound);
        bool exportedUnderReadOwnership = !capture.Spans.IsEmpty;
        clock.Advance(TimeSpan.FromSeconds(4));
        wire.Release.TrySetResult();
        using SecretRead read = (await pending.WaitAsync(Bound)).Value;

        await Assert.That(exportedUnderReadOwnership).IsFalse();
        SpanObservation login = capture.Spans.Single(span => (string?)span.Tags["operation"] == "UniversalLogin");
        SpanObservation outer = capture.Spans.Single(span => (string?)span.Tags["operation"] == "Read");
        await Assert.That(login.Duration).IsEqualTo(TimeSpan.FromSeconds(1));
        await Assert.That(outer.Duration).IsEqualTo(TimeSpan.FromSeconds(5));
        await Assert.That(capture.Durations.ToArray()).IsEquivalentTo([1d, 5d]);
    }

    [Test]
    [Arguments("success", "Completed")]
    [Arguments("deadline", "DeadlineExceeded")]
    [Arguments("dependency", "DependencyCanceled")]
    [Arguments("shutdown", "ShutdownCanceled")]
    public async Task SharedRenewalPublishesAndReleasesBeforeExport(string cause, string expected)
    {
        var clock = new Clock();
        using var token = SecretMaterial.FromText("original-canary");
        using var wire = new HeldWire
        {
            Body = LoginBody,
            Failure = cause == "dependency" ? new OperationCanceledException("dependency-canary") : null
        };
        await using var session = new InfisicalPeriodicTokenSession(new("https://api.test"), token,
            new()
            {
                OriginalIssuedAt = clock.GetUtcNow(),
                ExpiresAt = clock.GetUtcNow().AddMinutes(2),
                Lifetime = InfisicalTokenLifetime.Periodic,
                Period = TimeSpan.FromMinutes(2),
                ReportedMaximumTtl = TimeSpan.Zero
            }, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(2),
            new() { Transport = InfisicalTransportOptions.HostControlled(wire) }, clock);
        Exception? callbackError = null;
        string? published = null;
        var exported = Signal();
        using var capture = new Capture(ActivitySamplingResult.AllData, (phase, _) =>
        {
            if (phase != "stop") return;
            try
            {
                if (cause == "success")
                {
                    using var copy = session.GetTokenAsync(default).Result.Value;
                    published = copy.Material.Reveal();
                }
                session.StopAsync().WaitAsync(Bound).GetAwaiter().GetResult();
            }
            catch (Exception exception) { callbackError = exception; }
            finally { exported.TrySetResult(); }
        });
        using var waiter = new CancellationTokenSource();
        Task<SecretStatus> canceledWait = session.RenewAsync(waiter.Token).AsTask();
        await wire.Entered.Task.WaitAsync(Bound);
        Task<SecretStatus> survivingWait = session.RenewAsync().AsTask();
        waiter.Cancel();
        await Assert.That(async () => await canceledWait).Throws<OperationCanceledException>();
        Task? stopping = cause == "shutdown" ? session.StopAsync() : null;
        clock.Advance(TimeSpan.FromSeconds(cause == "deadline" ? 3 : 1));
        wire.Release.TrySetResult();
        if (cause == "shutdown")
            await Assert.That(async () => await survivingWait.WaitAsync(Bound)).Throws<OperationCanceledException>();
        else
            await Assert.That(await survivingWait.WaitAsync(Bound)).IsEqualTo(
                cause == "success" ? SecretStatus.Success : SecretStatus.RecoveryRequired);
        await exported.Task.WaitAsync(Bound);
        if (stopping is not null) await stopping.WaitAsync(Bound);
        await Assert.That(callbackError).IsNull();
        await Assert.That(capture.Spans.Single().Tags.GetValueOrDefault("termination") as string).IsEqualTo(expected);
        await Assert.That(session.LastRenewal!.Evidence).IsEqualTo(cause == "success"
            ? InfisicalRenewalEvidence.Applied : InfisicalRenewalEvidence.PossiblyDispatched);
        if (cause == "success") await Assert.That(published).IsEqualTo("issued-canary");
        await Assert.That(token.Reveal()).IsEqualTo("original-canary");
    }

    private static Activity Parent()
    {
        var parent = new Activity("parent-canary").SetIdFormat(ActivityIdFormat.W3C).Start();
        parent.AddBaggage("material", "baggage-canary");
        parent.TraceStateString = "vendor=tracestate-canary";
        return parent;
    }

    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static SecretReference Reference(InfisicalClient client) => FailureEvidenceTests.Reference(client);
    private static InfisicalClient Client(HttpMessageHandler wire, TimeProvider clock, TimeSpan? timeout = null) =>
        new(new("https://api.test"), new FailureEvidenceTests.Tokens(),
            new()
            {
                Transport = InfisicalTransportOptions.HostControlled(wire),
                OperationTimeout = timeout ?? TimeSpan.FromMinutes(1)
            }, clock);

    private static InfisicalRuntimeOptions Options(HttpMessageHandler wire, TimeProvider clock) => new()
    {
        Origin = new("https://api.test"),
        ClientId = "client-canary",
        ProjectId = "project-canary",
        Lifetime = InfisicalTokenLifetime.Periodic,
        Period = TimeSpan.FromMinutes(2),
        OriginalIssuedAt = clock.GetUtcNow(),
        RenewBefore = TimeSpan.FromSeconds(10),
        TimeProvider = clock,
        Network = new() { Transport = InfisicalTransportOptions.HostControlled(wire) }
    };

    private sealed class Clock(long frequency = TimeSpan.TicksPerSecond) : TimeProvider
    {
        private readonly InfisicalTransportOwnershipTests.ShutdownClock _timers = new();
        private long _elapsed;
        private long _utc;
        internal bool FailTimestamp;
        private static readonly DateTimeOffset Origin = new(2026, 11, 5, 0, 0, 0, TimeSpan.Zero);
        public override long TimestampFrequency => frequency;
        public override long GetTimestamp() => FailTimestamp
            ? throw new InvalidOperationException("diagnostic-clock-canary") : Interlocked.Read(ref _elapsed);
        public override DateTimeOffset GetUtcNow() => Origin.AddTicks(Interlocked.Read(ref _utc));
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            _timers.CreateTimer(callback, state, dueTime, period);
        internal void JumpUtc(TimeSpan amount) => Interlocked.Add(ref _utc, amount.Ticks);
        internal void AdvanceTimestamp(long amount) => Interlocked.Add(ref _elapsed, amount);
        internal void Advance(TimeSpan amount)
        {
            AdvanceTimestamp(amount.Ticks * frequency / TimeSpan.TicksPerSecond);
            JumpUtc(amount);
            _timers.Advance(amount);
        }
    }

    private sealed class HeldWire : HttpMessageHandler
    {
        internal TaskCompletionSource Entered { get; } = Signal();
        internal TaskCompletionSource Release { get; } = Signal();
        internal TaskCompletionSource CancellationObserved { get; } = Signal();
        internal Exception? Failure { get; init; }
        internal string Body { get; init; } = ReadBody;
        internal bool LoginImmediately { get; init; }
        internal Clock? Clock { get; init; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (LoginImmediately && request.RequestUri!.AbsolutePath.Contains("login", StringComparison.Ordinal))
            {
                Clock!.Advance(TimeSpan.FromSeconds(1));
                return new(HttpStatusCode.OK) { Content = new StringContent(LoginBody) };
            }
            Entered.TrySetResult();
            try { await Release.Task.WaitAsync(token); }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                CancellationObserved.TrySetResult();
                throw;
            }
            if (Failure is not null) throw Failure;
            return new(HttpStatusCode.OK) { Content = new StringContent(Body) };
        }
        protected override void Dispose(bool disposing)
        {
            Release.TrySetResult();
            base.Dispose(disposing);
        }
    }

    private sealed record SpanObservation(DateTime Start, TimeSpan Duration, ActivityTraceId Trace,
        ActivitySpanId ParentSpan, string Baggage, string? TraceState, bool HasParentObject,
        Dictionary<string, object?> Tags);

    private sealed class Capture : IDisposable
    {
        private readonly ActivityListener? _listener;
        private readonly MeterListener _meter = new();
        internal ConcurrentQueue<SpanObservation> Spans { get; } = new();
        internal ConcurrentQueue<double> Durations { get; } = new();
        internal ConcurrentQueue<Dictionary<string, object?>> MeasurementTags { get; } = new();
        internal ActivityContext SampleParent { get; private set; }
        internal Activity? SampleAmbient { get; private set; }
        internal bool MetricAmbientCanary { get; private set; }

        internal Capture(ActivitySamplingResult? sampling, Action<string, Activity?>? callback = null)
        {
            if (sampling is { } selection)
            {
                _listener = new()
                {
                    ShouldListenTo = source => source.Name == "SecretKit.Infisical",
                    Sample = (ref ActivityCreationOptions<ActivityContext> options) =>
                    {
                        SampleParent = options.Parent;
                        SampleAmbient = Activity.Current;
                        callback?.Invoke("sample", null);
                        return selection;
                    },
                    ActivityStarted = activity => callback?.Invoke("start", activity),
                    ActivityStopped = activity =>
                    {
                        Spans.Enqueue(new(activity.StartTimeUtc, activity.Duration, activity.TraceId,
                            activity.ParentSpanId, string.Join(";", activity.Baggage.Select(pair => pair.Value)),
                            activity.TraceStateString, activity.Parent is not null,
                            activity.TagObjects.ToDictionary(pair => pair.Key, pair => pair.Value)));
                        callback?.Invoke("stop", activity);
                    }
                };
                ActivitySource.AddActivityListener(_listener);
            }
            _meter.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "SecretKit.Infisical") listener.EnableMeasurementEvents(instrument);
            };
            _meter.SetMeasurementEventCallback<long>((_, _, _, _) =>
            {
                MetricAmbientCanary |= Activity.Current?.Baggage.Any() == true;
                callback?.Invoke("counter", null);
            });
            _meter.SetMeasurementEventCallback<double>((_, duration, tags, _) =>
            {
                MetricAmbientCanary |= Activity.Current?.Baggage.Any() == true;
                Durations.Enqueue(duration);
                MeasurementTags.Enqueue(tags.ToArray().ToDictionary(pair => pair.Key, pair => pair.Value));
                callback?.Invoke("histogram", null);
            });
            _meter.Start();
        }

        public void Dispose()
        {
            _listener?.Dispose();
            _meter.Dispose();
        }
    }
}
