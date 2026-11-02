using System.Diagnostics.Tracing;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureRoleAdministrationCollectorTests
{
    [Test]
    [Arguments("nonce")]
    [Arguments("lease")]
    [Arguments("selector")]
    [Arguments("vault")]
    [Arguments("subscription")]
    [Arguments("assignment")]
    [Arguments("definition")]
    [Arguments("secret")]
    [Arguments("version")]
    public async Task WindowRejectsReboundSelectorsBeforeDispatch(string change)
    {
        using var fixture = new Fixture();
        var collector = fixture.Collector();
        var binding = Binding();
        var window = collector.Arm(binding);
        var otherVault = change == "subscription" ? new VaultScope(new(new(OtherId), "collector-group"), "collector-vault") :
            new(Vault().ResourceGroup, "other-vault");
        var changed = change switch
        {
            "nonce" => binding with { Selector = binding.Selector with { Nonce = Guid.NewGuid() } },
            "lease" => binding with { LeaseId = Guid.NewGuid() },
            "selector" => binding with { Selector = binding.Selector with { Case = "selected-contract" } },
            "vault" or "subscription" => binding with { Vault = otherVault, Target = new(otherVault, AssignmentId) },
            "assignment" => binding with { Target = new(Vault(), OtherId) },
            "definition" => binding with { DefinitionId = OtherId },
            "secret" => binding with { SecretName = "other" },
            _ => binding with { SecretVersion = new string('b', 32) }
        };
        await Assert.That(async () => await collector.CollectAsync(window, changed, RoleAdministrationCollector.Phase.After))
            .Throws<InvalidOperationException>();
        await Assert.That(fixture.Arm.Requests.Count).IsEqualTo(0);
        var valid = await collector.CollectAsync(window, binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(valid.Complete).IsTrue();
        await Assert.That(valid.Binding.Selector).IsEqualTo(binding.Selector);
        await Assert.That(valid.Binding.LeaseId).IsEqualTo(binding.LeaseId);
    }

    [Test]
    public async Task PhasesAndCollectorOwnershipCannotBeReplayedOrRunConcurrently()
    {
        using var fixture = new Fixture();
        var first = fixture.Collector();
        var second = fixture.Collector();
        var binding = Binding();
        var window = first.Arm(binding);
        await Assert.That(async () => await second.CollectAsync(window, binding, RoleAdministrationCollector.Phase.After))
            .Throws<InvalidOperationException>();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var normal = fixture.Arm.Respond;
        fixture.Arm.Respond = async (request, token) =>
        {
            entered.TrySetResult();
            await release.Task.WaitAsync(token);
            return await normal(request, token);
        };
        Task<RoleAdministrationCollector.Measurement> baseline =
            first.CollectAsync(window, binding, RoleAdministrationCollector.Phase.Baseline).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        try
        {
            await Assert.That(async () => await first.CollectAsync(window, binding, RoleAdministrationCollector.Phase.After))
                .Throws<InvalidOperationException>();
        }
        finally { release.TrySetResult(); }
        var before = await baseline.WaitAsync(TimeSpan.FromSeconds(5));
        var after = await first.CollectAsync(window, binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(before.Complete && after.Complete).IsTrue();
        await Assert.That(after.Sequence).IsEqualTo(before.Sequence + 1);
        await Assert.That(after.Phase).IsEqualTo(RoleAdministrationCollector.Phase.After);
        await Assert.That(async () => await first.CollectAsync(window, binding, RoleAdministrationCollector.Phase.After))
            .Throws<InvalidOperationException>();
        await Assert.That(async () => await first.CollectAsync(window, binding, RoleAdministrationCollector.Phase.Baseline))
            .Throws<InvalidOperationException>();
        var independent = await first.CollectAsync(first.Arm(binding), binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(independent.WindowId).IsNotEqualTo(after.WindowId);
        await Assert.That(independent.Sequence).IsEqualTo(after.Sequence + 1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CallerCancellationPropagatesWithoutRetryOrMaterial(bool before)
    {
        using var fixture = new Fixture();
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Arm.Respond = async (_, token) =>
        {
            entered.TrySetResult();
            await new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously).Task.WaitAsync(token);
            throw new InvalidOperationException("unreachable");
        };
        var collector = fixture.Collector();
        var binding = Binding();
        var window = collector.Arm(binding);
        if (before) cancellation.Cancel();
        Task<RoleAdministrationCollector.Measurement> pending =
            collector.CollectAsync(window, binding, RoleAdministrationCollector.Phase.After, cancellation.Token).AsTask();
        if (!before)
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();
        }
        await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(5))).Throws<OperationCanceledException>();
        await Assert.That(fixture.Arm.Requests.Count).IsEqualTo(before ? 0 : 1);
        await Assert.That(fixture.Intended.Requests.Count).IsEqualTo(0);
        if (!before)
            await Assert.That(async () => await collector.CollectAsync(window, binding, RoleAdministrationCollector.Phase.After))
                .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task InjectedDeadlineIsBoundedWithoutSleepingOrPropagationPolling(bool expiredWindow)
    {
        using var fixture = new Fixture();
        var clock = new ManualClock();
        var collector = fixture.Collector(time: clock);
        var binding = Binding();
        var window = collector.Arm(binding);
        var normal = fixture.Arm.Respond;
        fixture.Arm.Respond = (request, token) =>
        {
            clock.Advance(TimeSpan.FromSeconds(11));
            return normal(request, token);
        };
        if (expiredWindow) clock.Advance(TimeSpan.FromSeconds(11));
        var result = await collector.CollectAsync(window, binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(result.Failure).IsEqualTo(RoleAdministrationCollector.Failure.Deadline);
        await Assert.That(result.TargetPresent).IsNull();
        await Assert.That(fixture.Arm.Requests.Count).IsEqualTo(expiredWindow ? 0 : 1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task BorrowedBindingsAreSnapshottedAndResponsesAreZeroedWithoutHostDisposal(bool invalidNative)
    {
        using var fixture = new Fixture();
        var parent = new SubscriptionScope(SubscriptionId);
        var borrowed = new RoleAssignmentScope(parent, OtherId);
        var binding = Binding() with { Target = borrowed, BorrowedAncestors = [borrowed] };
        var spy = new ResponseSpy(fixture.Transports[1]);
        if (invalidNative)
        {
            var normal = fixture.Intended.Respond;
            fixture.Intended.Respond = async (request, token) =>
            {
                var response = await normal(request, token);
                if (request.Headers.Authorization is not null)
                {
                    response.Content.Dispose();
                    response.Content = new StringContent(JsonSerializer.Serialize(new { id = SecretId + "/foreign", value = Material }));
                }
                return response;
            };
        }
        var collector = new RoleAdministrationCollector(
            new("arm", fixture.ArmCredential, fixture.Transports[0]), new("intended", fixture.IntendedCredential, spy),
            new("denied", fixture.DeniedCredential, fixture.Transports[2]),
            new("observer", fixture.ObserverCredential, fixture.Transports[3]), new(4, 100, 65536, TimeSpan.FromSeconds(10)));
        var window = collector.Arm(binding);
        binding.BorrowedAncestors[0] = new(parent, PrincipalId);
        await Assert.That(async () => await collector.CollectAsync(window, binding, RoleAdministrationCollector.Phase.After))
            .Throws<ArgumentException>();
        binding = binding with { BorrowedAncestors = [borrowed] };
        using var events = new CollectorEvents();
        var result = await collector.CollectAsync(window, binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(result.Complete).IsEqualTo(!invalidNative);
        if (invalidNative)
            await Assert.That(result.Intended.Sha256).IsNull();
        else
            await Assert.That(result.Intended.Sha256).IsNotNull();
        await Assert.That(spy.Responses.Count > 0).IsTrue();
        foreach (var response in spy.Responses)
        {
            var memory = response.ContentStream as MemoryStream;
            await Assert.That(memory).IsNotNull();
            await Assert.That(memory!.ToArray().All(b => b == 0)).IsTrue();
        }
        await Assert.That(events.Messages.Any(s => s.Contains(Material, StringComparison.Ordinal) ||
            s.Contains("protected-description", StringComparison.Ordinal) ||
            s.Contains("private-native-error", StringComparison.Ordinal))).IsFalse();
        await Assert.That(fixture.Intended.Disposed || fixture.IntendedCredential.Disposed).IsFalse();
        await Assert.That(JsonSerializer.Serialize(window)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(result.Observer)).IsEqualTo("{}");
    }

    private sealed class ResponseSpy(HttpPipelineTransport inner) : HttpPipelineTransport
    {
        internal readonly List<Azure.Response> Responses = [];
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            Responses.Add(message.Response);
        }
    }

    private sealed class CollectorEvents : EventListener
    {
        internal readonly System.Collections.Concurrent.ConcurrentQueue<string> Messages = new();
        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            if (eventSource.Name.StartsWith("Azure-", StringComparison.Ordinal))
                EnableEvents(eventSource, EventLevel.Verbose);
        }
        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            if (eventData.Payload is not null)
                Messages.Enqueue(string.Join("|", eventData.Payload.Select(v => v?.ToString())));
        }
    }

    private sealed class ManualClock : TimeProvider
    {
        private long ticks;
        private readonly List<ManualTimer> timers = [];
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => ticks;
        public override DateTimeOffset GetUtcNow() => new DateTimeOffset(2026, 10, 14, 0, 0, 0, TimeSpan.Zero).AddTicks(ticks);
        internal void Advance(TimeSpan duration)
        {
            ticks += duration.Ticks;
            foreach (var timer in timers.ToArray()) timer.Fire(ticks);
        }
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new ManualTimer(this, callback, state);
            timer.Change(dueTime, period);
            timers.Add(timer);
            return timer;
        }
        private sealed class ManualTimer(ManualClock owner, TimerCallback callback, object? state) : ITimer
        {
            private long due;
            private bool disposed;
            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                if (disposed) return false;
                due = dueTime == Timeout.InfiniteTimeSpan ? long.MaxValue : owner.ticks + dueTime.Ticks;
                return true;
            }
            internal void Fire(long now)
            {
                if (disposed || now < due) return;
                due = long.MaxValue;
                callback(state);
            }
            public void Dispose() => disposed = true;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
