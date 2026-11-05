using System.Diagnostics;
using System.Diagnostics.Metrics;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management.Tests;

[NotInParallel]
public sealed class AzureManagementDiagnosticsTests
{
    private const string Source = "SecretKit.AzureKeyVault.Management";

    [Test]
    public async Task DiagnosticCompletionClockFailureCannotReplaceTheSuccessfulPublicResult()
    {
        var time = new Clock();
        var backend = new WireBackend((_, _) =>
        {
            time.FailTimestamp = true;
            return Task.FromResult(WireBackend.Json(200, ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id)));
        });
        var client = new VaultAdministration(new Credential(), backend, timeProvider: time);

        var result = await client.GetVaultAsync(ScopeAuthorityTests.Scope());

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
    }

    [Test]
    public async Task AuditBatchObserverSeesAllRetainedProgressAfterPublication()
    {
        using var probe = new Probe();
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(403,
            """{"error":{"code":"protected-canary","message":"protected-body-canary"}}""")));
        var query = new AuditQuery(ScopeAuthorityTests.Scope(), DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch.AddHours(1));
        var progress = new AuditBatchProgress(2);
        bool published = false;
        probe.OnStop = () => published = progress.Results.All(r => r?.Status == SecretStatus.Denied);
        await new AuditDiagnostics(new Credential(), backend).QueryBatchAsync([query, query], progress,
            TimeSpan.FromSeconds(30));
        await Assert.That(published).IsTrue();
        await Assert.That(probe.Spans.Count).IsEqualTo(1);
        await CheckTags(probe.Spans[0], "Success", "Completed");
    }

    [Test]
    public async Task LocalDeadlineRemainsDistinctFromDependencyCancellation()
    {
        using var probe = new Probe();
        var time = new Clock();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var backend = new WireBackend(async (_, token) =>
        {
            var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var registration = token.Register(() => canceled.TrySetCanceled(token));
            entered.SetResult();
            await canceled.Task;
            return WireBackend.Json(200, "{}");
        });
        var pending = new VaultAdministration(new Credential(), backend, timeProvider: time)
            .GetVaultAsync(ScopeAuthorityTests.Scope()).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        time.Expire();
        await Assert.That((await pending).Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(probe.Spans.Count).IsEqualTo(1);
        await CheckTags(probe.Spans[0], "Unavailable", "DeadlineExceeded");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AdministrativeReadCapturesHeldIntervalParentAndSafeTags(bool zero)
    {
        using var caller = new Activity("caller").SetIdFormat(ActivityIdFormat.W3C).Start();
        caller.AddBaggage("protected-canary", "protected-canary");
        caller.TraceStateString = "protected=canary";
        using var probe = new Probe();
        var time = new Clock();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new VaultAdministration(new Credential(), new WireBackend(async (_, _) =>
        {
            entered.SetResult();
            await release.Task;
            return WireBackend.Json(200, ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id));
        }), timeProvider: time);
        int initializationCallbacks = probe.InitializationCallbacks;
        var pending = client.GetVaultAsync(ScopeAuthorityTests.Scope()).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(probe.Spans.Count).IsEqualTo(0);
        await Assert.That(probe.InitializationCallbacks).IsEqualTo(initializationCallbacks);
        long elapsedTicks = zero ? 0 : TimeSpan.FromSeconds(7).Ticks;
        time.Ticks = elapsedTicks;
        probe.OnStop = () => time.Ticks += TimeSpan.FromSeconds(100).Ticks;
        release.SetResult();
        await Assert.That((await pending).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(probe.Spans.Count).IsEqualTo(1);
        var span = probe.Spans[0];
        await Assert.That(span.ParentSpanId).IsEqualTo(caller.SpanId);
        await Assert.That(span.Duration).IsEqualTo(TimeSpan.FromTicks(zero ? 1 : elapsedTicks));
        await Assert.That(probe.Seconds.Single()).IsEqualTo(span.Duration.TotalSeconds);
        await Assert.That(probe.Measurements.Single().OrderBy(p => p.Key).ToArray())
            .IsEquivalentTo(span.TagObjects.OrderBy(p => p.Key).ToArray());
        await Assert.That(span.Baggage.Count()).IsEqualTo(0);
        await Assert.That(span.TraceStateString).IsNull();
        await Assert.That(ReferenceEquals(Activity.Current, caller)).IsTrue();
        await CheckTags(span, "Success", "Completed");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AdministrativeCancellationDistinguishesDependencyFromCaller(bool callerCanceled)
    {
        using var probe = new Probe();
        using var cancellation = new CancellationTokenSource();
        var client = new VaultAdministration(new Credential(), new WireBackend((_, _) =>
        {
            if (callerCanceled) cancellation.Cancel();
            throw new OperationCanceledException("protected-canary");
        }));
        if (callerCanceled)
            await Assert.That(async () => await client.GetVaultAsync(ScopeAuthorityTests.Scope(), cancellation.Token)).Throws<OperationCanceledException>();
        else
            await Assert.That((await client.GetVaultAsync(ScopeAuthorityTests.Scope())).Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(probe.Spans.Count).IsEqualTo(1);
        await CheckTags(probe.Spans[0], callerCanceled ? "Unknown" : "Unavailable", callerCanceled ? "CallerCanceled" : "DependencyCanceled");
    }

    [Test]
    public async Task RoleNotificationAndAuditFailuresEmitClosedObservations()
    {
        using var probe = new Probe();
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(403, """{"error":{"code":"protected-canary","message":"protected-body-canary"}}""")));
        var client = new VaultAdministration(new Credential(), backend);
        var vault = ScopeAuthorityTests.Scope();
        await Assert.That((await client.GetRoleAssignmentAsync(new RoleAssignmentScope(vault, Guid.Parse("33333333-3333-3333-3333-333333333333")))).Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That((await client.GetNotificationAsync(new NotificationScope(vault, "notification-canary"))).Status).IsEqualTo(SecretStatus.Denied);
        var query = new AuditQuery(vault, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddHours(1));
        await Assert.That((await new AuditDiagnostics(new Credential(), backend).QueryAsync(query)).Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(probe.Spans.Count).IsEqualTo(3);
        foreach (var span in probe.Spans) await CheckTags(span, "Denied", "Completed");
    }

    [Test]
    [Arguments("sample")]
    [Arguments("start")]
    [Arguments("stop")]
    [Arguments("metric")]
    public async Task HostileStatusListenersRunAfterOriginalHandleGateRelease(string hostile)
    {
        const string url = "https://management.azure.com/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.KeyVault/locations/eastus/operations/55555555-5555-5555-5555-555555555555?api-version=2026-02-01";
        var backend = new WireBackend((request, _) =>
        {
            if (request.Method == HttpMethod.Post)
            {
                var response = WireBackend.Json(202, "");
                response.Headers.TryAddWithoutValidation("Location", url);
                response.Headers.TryAddWithoutValidation("Azure-AsyncOperation", url);
                return Task.FromResult(response);
            }
            if (request.RequestUri!.AbsoluteUri != url) throw new InvalidOperationException("Foreign operation target.");
            return Task.FromResult(WireBackend.Json(200, """{"status":"InProgress"}"""));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = new DeletedVaultScope(ScopeAuthorityTests.Scope().ResourceGroup.Subscription, "eastus", "vault-canary");
        var receipt = client.PrepareReceipt(scope, ManagementMutation.PurgeDeletedVault);
        var result = await client.PurgeDeletedVaultAsync(scope, receipt);
        using var caller = new Activity("caller").Start();
        using var probe = new Probe { Hostile = hostile };
        probe.Reenter = () =>
        {
            probe.Reentered = result.Value.CheckStatusAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult() == SecretStatus.Pending;
        };
        await Assert.That(await result.Value.CheckStatusAsync()).IsEqualTo(SecretStatus.Pending);
        await Assert.That(probe.Reentered).IsTrue();
        await Assert.That(probe.Seconds.Count).IsEqualTo(1);
        await Assert.That(result.Value.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(ReferenceEquals(Activity.Current, caller)).IsTrue();
    }

    private static async Task CheckTags(Activity span, string outcome, string termination)
    {
        var tags = span.TagObjects.ToDictionary(p => p.Key, p => p.Value?.ToString());
        await Assert.That(tags.Keys.Order().ToArray()).IsEquivalentTo(new[] { "operation", "outcome", "reason", "dispatch", "termination" });
        await Assert.That(tags["outcome"]).IsEqualTo(outcome);
        await Assert.That(tags["termination"]).IsEqualTo(termination);
        await Assert.That(string.Join(" ", tags.Values).Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    private sealed class Clock : TimeProvider
    {
        internal long Ticks;
        internal bool FailTimestamp;
        private readonly List<Deadline> _deadlines = [];
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => FailTimestamp
            ? throw new InvalidOperationException("diagnostic-clock-canary") : Ticks;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new Deadline(callback, state);
            _deadlines.Add(timer);
            return timer;
        }
        internal void Expire()
        {
            Ticks += TimeSpan.FromSeconds(30).Ticks;
            foreach (var timer in _deadlines.ToArray()) timer.Fire();
        }
        private sealed class Deadline(TimerCallback callback, object? state) : ITimer
        {
            private bool _disposed;
            internal void Fire() { if (!_disposed) callback(state); }
            public bool Change(TimeSpan dueTime, TimeSpan period) => !_disposed;
            public void Dispose() => _disposed = true;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }

    private sealed class Probe : IDisposable
    {
        private static readonly AsyncLocal<Probe?> Active = new();
        private readonly ActivityListener _listener;
        private readonly MeterListener _meter;
        internal readonly List<Activity> Spans = [];
        internal readonly List<double> Seconds = [];
        internal string? Hostile;
        internal Action? Reenter;
        internal Action? OnStop;
        internal readonly List<KeyValuePair<string, object?>[]> Measurements = [];
        internal bool Reentered;
        internal int InitializationCallbacks;
        internal Probe()
        {
            Active.Value = this;
            _listener = new ActivityListener
            {
                ShouldListenTo = source =>
                {
                    if (source.Name != Source) return false;
                    if (ReferenceEquals(Active.Value, this)) InitializationCallbacks++;
                    return true;
                },
                Sample = (ref ActivityCreationOptions<ActivityContext> _) =>
                {
                    if (ReferenceEquals(Active.Value, this) && Hostile == "sample") Attack();
                    return ActivitySamplingResult.AllDataAndRecorded;
                },
                ActivityStarted = _ => { if (ReferenceEquals(Active.Value, this) && Hostile == "start") Attack(); },
                ActivityStopped = span =>
                {
                    if (!ReferenceEquals(Active.Value, this)) return;
                    Spans.Add(span);
                    OnStop?.Invoke();
                    if (Hostile == "stop") Attack();
                }
            };
            ActivitySource.AddActivityListener(_listener);
            _meter = new MeterListener
            {
                InstrumentPublished = (instrument, listener) =>
                {
                    if (instrument.Meter.Name == Source)
                    {
                        if (ReferenceEquals(Active.Value, this)) InitializationCallbacks++;
                        listener.EnableMeasurementEvents(instrument);
                    }
                }
            };
            _meter.SetMeasurementEventCallback<long>((_, _, _, _) =>
            {
                if (ReferenceEquals(Active.Value, this) && Hostile == "metric") Attack();
            });
            _meter.SetMeasurementEventCallback<double>((_, value, tags, _) =>
            {
                if (ReferenceEquals(Active.Value, this))
                {
                    Seconds.Add(value);
                    Measurements.Add(tags.ToArray());
                }
            });
            _meter.Start();
        }
        private void Attack()
        {
            Activity.Current = new Activity("host-replacement");
            Reenter?.Invoke();
            throw new InvalidOperationException("protected-listener-canary");
        }
        public void Dispose()
        {
            _meter.Dispose();
            _listener.Dispose();
            Active.Value = null;
        }
    }
}
