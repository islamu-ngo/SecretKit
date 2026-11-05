using System.Diagnostics;
using System.Diagnostics.Metrics;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Tests;

[NotInParallel]
public sealed class AzureDiagnosticsTests
{
    private const string Source = "SecretKit.AzureKeyVault";
    private const string Json = """{"value":"protected-material-canary","id":"https://unit.vault.azure.net/secrets/name-canary/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","attributes":{"enabled":true}}""";

    [Test]
    public async Task DiagnosticCompletionClockFailureCannotHideOwnedReadMaterial()
    {
        var time = new Clock();
        var wire = new WireTransport((_, _) =>
        {
            time.FailTimestamp = true;
            return Task.FromResult(WireTransport.Json(200, Json));
        });
        var client = new AzureKeyVaultClient(new Uri("https://unit.vault.azure.net"), new TestCredential(), wire, time);
        var target = new SecretReference(client.Authority, new AzureSecretAddress("name-canary"));

        var result = await client.ReadAsync(target);
        using var value = result.Value;

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(value.Material.Use(characters => characters.Length)).IsEqualTo("protected-material-canary".Length);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CompletedReadCapturesHeldIntervalParentAndSafeTags(bool zero)
    {
        using var caller = new Activity("caller").SetIdFormat(ActivityIdFormat.W3C).Start();
        caller.AddBaggage("protected-baggage-canary", "protected-value-canary");
        caller.TraceStateString = "protected=canary";
        using var probe = new Probe();
        var time = new Clock();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new AzureKeyVaultClient(new Uri("https://unit.vault.azure.net"), new TestCredential(),
            new WireTransport(async (_, _) =>
            {
                entered.SetResult();
                await release.Task;
                return WireTransport.Json(200, Json);
            }), time);
        var target = new SecretReference(client.Authority, new AzureSecretAddress("name-canary"));
        int initializationCallbacks = probe.InitializationCallbacks;
        var pending = client.ReadAsync(target).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(probe.Spans.Count).IsEqualTo(0);
        await Assert.That(probe.InitializationCallbacks).IsEqualTo(initializationCallbacks);
        long elapsedTicks = zero ? 0 : TimeSpan.FromSeconds(7).Ticks;
        time.Ticks = elapsedTicks;
        probe.OnStop = () => time.Ticks += TimeSpan.FromSeconds(100).Ticks;
        release.SetResult();
        using var value = (await pending).Value;
        await Assert.That(value.Material.Reveal()).IsEqualTo("protected-material-canary");
        await Assert.That(probe.Spans.Count).IsEqualTo(1);
        var span = probe.Spans[0];
        await Assert.That(span.ParentSpanId).IsEqualTo(caller.SpanId);
        await Assert.That(span.TraceId).IsEqualTo(caller.TraceId);
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
    public async Task CancellationDistinguishesCallerFromDependency(bool callerCanceled)
    {
        using var probe = new Probe();
        using var cancellation = new CancellationTokenSource();
        var client = new AzureKeyVaultClient(new Uri("https://unit.vault.azure.net"), new TestCredential(),
            new WireTransport((_, _) =>
            {
                if (callerCanceled) cancellation.Cancel();
                throw new OperationCanceledException("protected-exception-canary");
            }));
        var target = new SecretReference(client.Authority, new AzureSecretAddress("name-canary"));
        await Assert.That(async () => await client.ReadAsync(target, cancellation.Token)).Throws<OperationCanceledException>();
        await Assert.That(probe.Spans.Count).IsEqualTo(1);
        await CheckTags(probe.Spans[0], "Unknown", callerCanceled ? "CallerCanceled" : "DependencyCanceled");
    }

    [Test]
    [Arguments("sample")]
    [Arguments("start")]
    [Arguments("stop")]
    [Arguments("metric")]
    public async Task HostileCallbacksCannotReplaceResultsOrSuppressIndependentMeasurements(string hostile)
    {
        using var caller = new Activity("caller").Start();
        using var probe = new Probe { Hostile = hostile };
        var client = new AzureKeyVaultClient(new Uri("https://unit.vault.azure.net"), new TestCredential(),
            new WireTransport((request, _) => Task.FromResult(request.Headers.Authorization is null
                ? WireTransport.Challenge() : WireTransport.Json(200, Json))));
        var target = new SecretReference(client.Authority, new AzureSecretAddress("name-canary"));
        probe.Reenter = () =>
        {
            using var nested = client.ReadAsync(target).AsTask().GetAwaiter().GetResult().Value;
            probe.Reentered = nested.Material.Reveal() == "protected-material-canary";
        };
        using var material = SecretMaterial.FromText("protected-material-canary");
        var receipt = client.CreateReceipt(target);
        var result = await client.SetSecretAsync(new AzureSetSecretRequest(target, material), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(material.Reveal()).IsEqualTo("protected-material-canary");
        await Assert.That(probe.Reentered).IsTrue();
        await Assert.That(probe.Seconds.Count).IsEqualTo(1);
        await Assert.That(ReferenceEquals(Activity.Current, caller)).IsTrue();
    }

    [Test]
    public async Task InventoryAndNativeFailuresEmitWithoutPublishingMaterial()
    {
        using var probe = new Probe();
        var client = new AzureKeyVaultClient(new Uri("https://unit.vault.azure.net"), new TestCredential(),
            new WireTransport((_, _) => Task.FromResult(WireTransport.Json(403,
                """{"error":{"code":"protected-canary","message":"protected-body-canary"}}"""))));
        var target = new SecretReference(client.Authority, new AzureSecretAddress("name-canary", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        await Assert.That((await client.GetSecretVersionAsync(target)).Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That((await client.InspectAsync(new AzureInventoryScope(client.Authority))).Status).IsEqualTo(SecretStatus.Denied);
        var unversioned = new SecretReference(client.Authority, new AzureSecretAddress("name-canary"));
        var receipt = client.CreateReceipt(unversioned);
        await Assert.That((await client.StartDeleteSecretAsync(unversioned, receipt)).Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(probe.Spans.Count).IsEqualTo(3);
        foreach (var span in probe.Spans) await CheckTags(span, "Denied", "Completed");
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
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => FailTimestamp
            ? throw new InvalidOperationException("diagnostic-clock-canary") : Ticks;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch;
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
