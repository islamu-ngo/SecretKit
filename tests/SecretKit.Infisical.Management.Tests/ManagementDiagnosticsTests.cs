using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ManagementDiagnosticsTests
{
    private const string Source = "SecretKit.Infisical.Management";
    private const string Organization = "11111111-1111-4111-8111-111111111111";
    private const string Group = "22222222-2222-4222-8222-222222222222";

    [Test]
    public async Task DiagnosticCompletionClockFailureCannotReplaceCallerCancellation()
    {
        using var probe = new Probe();
        using var caller = new CancellationTokenSource();
        probe.Wire.BeforeResponse = _ =>
        {
            probe.Time.FailTimestamp = true;
            caller.Cancel();
            return Task.CompletedTask;
        };
        try
        {
            await Assert.That(async () => await probe.ExecuteAsync(caller.Token))
                .Throws<OperationCanceledException>();
        }
        finally { probe.Time.FailTimestamp = false; }
    }

    [Test]
    public async Task CompletedIntervalRetainsOpaqueParentAndExcludesEveryListener()
    {
        using var parent = new Activity("caller-canary").SetIdFormat(ActivityIdFormat.W3C).Start();
        parent.TraceStateString = "tenant=tracestate-canary";
        parent.AddBaggage("principal", "baggage-canary");
        using var probe = new Probe();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        probe.Wire.BeforeResponse = async _ => { entered.SetResult(); await release.Task; };
        probe.Callback = stage =>
        {
            if (stage is "start" or "counter") probe.Time.Advance(TimeSpan.FromSeconds(10));
        };
        var pending = probe.ExecuteAsync().AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        probe.Time.Advance(TimeSpan.FromSeconds(2));
        release.SetResult();
        await Assert.That((await pending.WaitAsync(TimeSpan.FromSeconds(10))).IsSuccess).IsTrue();
        Activity span = probe.Spans.Single();
        await Assert.That(span.Duration).IsEqualTo(TimeSpan.FromSeconds(2));
        await Assert.That(probe.Durations.Single()).IsEqualTo(2d);
        await Assert.That(probe.Counts.Sum()).IsEqualTo(1);
        await Assert.That(span.TraceId).IsEqualTo(parent.TraceId);
        await Assert.That(span.ParentSpanId).IsEqualTo(parent.SpanId);
        await Assert.That(span.Parent).IsNull();
        await Assert.That(span.Baggage.Any()).IsFalse();
        await Assert.That(string.IsNullOrEmpty(span.TraceStateString)).IsTrue();
        await Assert.That(ReferenceEquals(Activity.Current, parent)).IsTrue();
        var allowed = new HashSet<string> { "operation", "outcome", "reason", "dispatch", "termination" };
        await Assert.That(span.TagObjects.Count()).IsEqualTo(allowed.Count);
        foreach (var tag in span.TagObjects)
        {
            await Assert.That(allowed.Contains(tag.Key)).IsTrue();
            await Assert.That(tag.Value?.ToString()?.Contains("canary", StringComparison.Ordinal) ?? false).IsFalse();
        }
        await Assert.That(span.GetTagItem("operation") as string).IsEqualTo("infisical.get.v1.groups.by.id");
    }

    [Test]
    [Arguments("sample")]
    [Arguments("start")]
    [Arguments("stop")]
    [Arguments("counter")]
    [Arguments("histogram")]
    public async Task ThrowingReentrantListenerCannotChangeResultOrOwnedCleanup(string selected)
    {
        using var parent = new Activity("caller").SetIdFormat(ActivityIdFormat.W3C).Start();
        using var listenerActivity = new Activity("listener-canary");
        using var probe = new Probe();
        bool entered = false;
        bool nestedSucceeded = false;
        bool materialDisposed = false;
        probe.Callback = stage =>
        {
            if (stage != selected || entered) return;
            entered = true;
            try { probe.Tokens.LastMaterial!.Reveal(); }
            catch (ObjectDisposedException) { materialDisposed = true; }
            nestedSucceeded = probe.ExecuteAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10))
                .GetAwaiter().GetResult().IsSuccess;
            Activity.Current = listenerActivity.Start();
            throw new InvalidOperationException("listener-canary");
        };
        var result = await probe.ExecuteAsync();
        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(entered).IsTrue();
        await Assert.That(nestedSucceeded).IsTrue();
        await Assert.That(materialDisposed).IsTrue();
        await Assert.That(ReferenceEquals(Activity.Current, parent)).IsTrue();
    }

    [Test]
    [Arguments("completed", "Completed")]
    [Arguments("denied", "Completed")]
    [Arguments("caller", "CallerCanceled")]
    [Arguments("deadline", "DeadlineExceeded")]
    [Arguments("dependency", "DependencyCanceled")]
    public async Task CompletionDistinguishesOrdinaryFailureFromCancellation(string mode, string termination)
    {
        using var probe = new Probe();
        using var caller = new CancellationTokenSource();
        probe.Tokens.Mode = mode;
        if (mode == "caller") probe.Tokens.BeforeAcquire = caller.Cancel;
        if (mode == "deadline")
            probe.Wire.BeforeResponse = _ => { probe.Time.Advance(TimeSpan.FromSeconds(31)); return Task.CompletedTask; };
        if (mode == "caller")
            await Assert.That(async () => await probe.ExecuteAsync(caller.Token)).Throws<OperationCanceledException>();
        else
        {
            var result = await probe.ExecuteAsync();
            await Assert.That(result.Status).IsEqualTo(mode switch
            {
                "completed" => SecretStatus.Success,
                "denied" => SecretStatus.Denied,
                _ => SecretStatus.Unavailable
            });
        }
        var span = probe.Spans.Single();
        await Assert.That(span.GetTagItem("termination") as string).IsEqualTo(termination);
        if (mode != "completed")
            await Assert.That(span.GetTagItem("outcome") as string).IsNotEqualTo("Success");
    }

    [Test]
    public async Task NestedNativeObserversRunAfterManagementIntervalIsFixed()
    {
        using var probe = new Probe();
        var selected = new AsyncLocal<bool> { Value = true };
        int nativeCallbacks = 0;
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == "SecretKit.Infisical",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = _ =>
            {
                if (!selected.Value) return;
                nativeCallbacks++;
                probe.Time.Advance(TimeSpan.FromSeconds(10));
            }
        };
        ActivitySource.AddActivityListener(listener);
        using var nativeWire = new Wire
        {
            Json = """{"secret":{"secretKey":"key-canary","secretValueHidden":false,"secretValue":"value-canary"}}"""
        };
        await using var native = new InfisicalClient(new("https://native-canary.invalid"), new Tokens(),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(nativeWire) }, probe.Time);
        probe.Tokens.BeforeAcquire = () =>
        {
            var read = native.ReadAsync(new(native.Authority,
                new InfisicalSecretAddress("project-canary", "test", "/", "key-canary")))
                .AsTask().WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
            using var value = read.Value;
        };
        probe.Wire.BeforeResponse = _ => { probe.Time.Advance(TimeSpan.FromSeconds(2)); return Task.CompletedTask; };
        await Assert.That((await probe.ExecuteAsync()).IsSuccess).IsTrue();
        await Assert.That(nativeCallbacks).IsEqualTo(1);
        await Assert.That(probe.Spans.Single().Duration).IsEqualTo(TimeSpan.FromSeconds(2));
        await Assert.That(probe.Durations.Single()).IsEqualTo(2d);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ObserversPreserveUnknownOrAppliedMutationEvidenceWithoutReplay(bool canceledAfterParse)
    {
        using var probe = new Probe();
        using var caller = new CancellationTokenSource();
        using var original = ScopedAccessOperations.CreateGroup(Organization, "group-canary", "group");
        byte[] body = original.CopyBody()!;
        using var request = new ManagementRequest<GroupMetadata>(original.OperationId, original.Build,
            original.Method, original.Path, original.Target, writer => writer.WriteRawValue(body),
            root =>
            {
                var value = original.Parse(root);
                if (canceledAfterParse) caller.Cancel();
                return value;
            });
        Array.Clear(body);
        var authority = new ManagementAuthority(probe.Client.Authority, probe.Tokens, Organization);
        var grant = authority.IssueGrant(request.OperationId,
            ScopedAccessOperations.GroupCreationTarget(Organization, "group-canary", "group"));
        var receipt = probe.Client.CreateReceipt(request);
        probe.Wire.LoseResponse = !canceledAfterParse;
        SecretStatus? replay = null;
        bool replayAttempted = false;
        probe.Callback = stage =>
        {
            if (stage == "stop" && !replayAttempted)
            {
                replayAttempted = true;
                replay = probe.Client.ExecuteAsync(request, authority, grant, receipt)
                    .AsTask().WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult().Status;
            }
        };
        if (canceledAfterParse)
            await Assert.That(async () => await probe.Client.ExecuteAsync(request, authority, grant, receipt, caller.Token))
                .Throws<OperationCanceledException>();
        else
            await Assert.That((await probe.Client.ExecuteAsync(request, authority, grant, receipt)).Status)
                .IsEqualTo(SecretStatus.Unknown);
        var evidence = canceledAfterParse ? DispatchEvidence.Applied : DispatchEvidence.PossiblyDispatched;
        await Assert.That(receipt.Evidence).IsEqualTo(evidence);
        await Assert.That(probe.Spans.Single().GetTagItem("dispatch") as string).IsEqualTo(evidence.ToString());
        await Assert.That(replay).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(probe.Wire.CreatedGroups.Count).IsEqualTo(1);
    }

    private sealed class Probe : IDisposable
    {
        private readonly AsyncLocal<bool> _selected = new() { Value = true };
        private readonly ActivityListener _activities;
        private readonly MeterListener _metrics = new();
        private readonly ManagementTransport _transport;
        internal Clock Time { get; } = new();
        internal Wire Wire { get; } = new();
        internal Tokens Tokens { get; } = new();
        internal List<Activity> Spans { get; } = [];
        internal List<long> Counts { get; } = [];
        internal List<double> Durations { get; } = [];
        internal Action<string>? Callback { get; set; }
        internal ManagementClient Client { get; }

        internal Probe()
        {
            _activities = new()
            {
                ShouldListenTo = source => source.Name == Source,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) =>
                {
                    if (!_selected.Value) return ActivitySamplingResult.None;
                    Callback?.Invoke("sample");
                    return ActivitySamplingResult.AllDataAndRecorded;
                },
                ActivityStarted = _ => { if (_selected.Value) Callback?.Invoke("start"); },
                ActivityStopped = activity =>
                {
                    if (!_selected.Value) return;
                    Spans.Add(activity);
                    Callback?.Invoke("stop");
                }
            };
            ActivitySource.AddActivityListener(_activities);
            _metrics.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == Source) listener.EnableMeasurementEvents(instrument);
            };
            _metrics.SetMeasurementEventCallback<long>((_, value, _, _) =>
            {
                if (!_selected.Value) return;
                Counts.Add(value);
                Callback?.Invoke("counter");
            });
            _metrics.SetMeasurementEventCallback<double>((_, value, _, _) =>
            {
                if (!_selected.Value) return;
                Durations.Add(value);
                Callback?.Invoke("histogram");
            });
            _metrics.Start();
            _transport = new(new("https://origin-canary.invalid"), new()
            {
                Transport = InfisicalTransportOptions.HostControlled(Wire)
            });
            Client = new(_transport, Time);
        }

        internal async ValueTask<SecretOutcome<GroupMetadata>> ExecuteAsync(CancellationToken cancellationToken = default)
        {
            var authority = new ManagementAuthority(Client.Authority, Tokens, Organization);
            using var request = ScopedAccessOperations.GetGroup(Organization, Group);
            return await Client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, new(Organization, resourceId: Group)),
                cancellationToken: cancellationToken);
        }

        public void Dispose()
        {
            _selected.Value = false;
            _metrics.Dispose();
            _activities.Dispose();
            _transport.Dispose();
            Wire.Dispose();
        }
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        internal string Mode { get; set; } = "";
        internal Action? BeforeAcquire { get; set; }
        internal SecretMaterial? LastMaterial { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken = default)
        {
            BeforeAcquire?.Invoke();
            if (Mode == "dependency") throw new OperationCanceledException(new CancellationToken(true));
            if (Mode == "denied")
                return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Failure(SecretStatus.Denied));
            LastMaterial = SecretMaterial.FromText("token-canary");
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(LastMaterial)));
        }
    }

    private sealed class Wire : HttpMessageHandler
    {
        internal Func<CancellationToken, Task>? BeforeResponse { get; set; }
        internal bool LoseResponse { get; set; }
        internal List<string> CreatedGroups { get; } = [];
        internal string Json { get; init; } = """
            {"id":"22222222-2222-4222-8222-222222222222","orgId":"11111111-1111-4111-8111-111111111111","name":"group-canary","slug":"group","customRoleSlug":null,"createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}
            """;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (BeforeResponse is not null) await BeforeResponse(cancellationToken);
            if (request.Method == HttpMethod.Post) CreatedGroups.Add("created");
            if (LoseResponse) throw new HttpRequestException("response-canary");
            string json = request.Method == HttpMethod.Post
                ? """
                    {"id":"22222222-2222-4222-8222-222222222222","orgId":"11111111-1111-4111-8111-111111111111","name":"group-canary","slug":"group","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}
                    """
                : Json;
            return new(HttpStatusCode.OK)
            {
                Content = new StringContent(json)
            };
        }
    }

    private sealed class Clock : TimeProvider
    {
        private long _elapsed;
        internal bool FailTimestamp;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch + TimeSpan.FromTicks(GetTimestamp());
        public override long GetTimestamp() => FailTimestamp
            ? throw new InvalidOperationException("diagnostic-clock-canary") : Interlocked.Read(ref _elapsed);
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        internal void Advance(TimeSpan elapsed) => Interlocked.Add(ref _elapsed, elapsed.Ticks);
    }
}
