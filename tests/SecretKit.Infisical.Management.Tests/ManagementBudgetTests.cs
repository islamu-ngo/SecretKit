using System.Net;
using System.Text;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ManagementBudgetTests
{
    private const string Organization = "11111111-1111-4111-8111-111111111111";
    private const string Group = "22222222-2222-4222-8222-222222222222";
    private const string GroupBody = """
        {"id":"22222222-2222-4222-8222-222222222222","orgId":"11111111-1111-4111-8111-111111111111","name":"created","slug":"created","customRoleSlug":null,"createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}
        """;

    [Test]
    public async Task SelectedExecutionLimitRejectsEncodedBodyBeforeCredentials()
    {
        using var wire = new Wire();
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Organization);
        using var password = SecretMaterial.FromText(new string('x', 2000));
        using var request = SharingOperations.AccessShare(Organization, "share", password);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId,
                SharingOperations.AccessShareTarget(Organization, "share", password)), receipt);
        await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.RequestTooLarge);
        await Assert.That(tokens.Material is null).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments("credentials", false, false)]
    [Arguments("send", false, false)]
    [Arguments("body", false, false)]
    [Arguments("credentials", true, false)]
    [Arguments("send", true, false)]
    [Arguments("body", true, false)]
    [Arguments("build", false, false)]
    [Arguments("build", true, false)]
    [Arguments("credentials", false, true)]
    [Arguments("send", false, true)]
    [Arguments("body", false, true)]
    public async Task OneBudgetRejectsLateCompletionAndPreservesCallerCancellation(string stage, bool cancelCaller, bool cooperative)
    {
        var clock = new Clock();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var wire = new Wire { Stage = stage, Entered = entered, Release = release, Cooperative = cooperative };
        var tokens = new Tokens { Entered = stage == "credentials" ? entered : null, Release = release, Cooperative = cooperative };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport, clock);
        var authority = new ManagementAuthority(client.Authority, tokens, Organization);
        using var original = ScopedAccessOperations.GetGroup(Organization, Group);
        using var request = new ManagementRequest<GroupMetadata>(original.OperationId, async (apis, body, token) =>
        {
            var message = await original.Build(apis, body, token);
            if (stage == "build")
            {
                entered.SetResult();
                await release.Task;
            }
            return message;
        }, original.Method, original.Path, original.Target, null, original.Parse, mutation: false);
        using var caller = new CancellationTokenSource();
        var pending = client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(Organization, resourceId: Group)),
            cancellationToken: caller.Token).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        clock.Advance(TimeSpan.FromSeconds(3));
        if (cancelCaller) caller.Cancel();
        release.SetResult();
        if (cancelCaller)
            await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(10)))
                .Throws<OperationCanceledException>();
        else
        {
            var result = await pending.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unavailable);
            await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.DeadlineExceeded);
        }
        if (stage == "build" || cooperative && stage == "credentials")
            await Assert.That(tokens.Material is null).IsTrue();
        else
            await Assert.That(() => tokens.Material!.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CommittedMutationWithLostResponseNeverReplaysAfterDeadlineOrCancellation(bool cancelCaller)
    {
        var clock = new Clock();
        using var wire = new Wire { Stage = "lost" };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport, clock);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Organization);
        using var request = ScopedAccessOperations.CreateGroup(Organization, "created", "created");
        var grant = authority.IssueGrant(request.OperationId,
            ScopedAccessOperations.GroupCreationTarget(Organization, "created", "created"));
        var receipt = client.CreateReceipt(request);
        using var caller = new CancellationTokenSource();
        var pending = client.ExecuteAsync(request, authority, grant, receipt, caller.Token).AsTask();
        await wire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        clock.Advance(TimeSpan.FromSeconds(3));
        if (cancelCaller) caller.Cancel();
        wire.Release.SetResult();
        if (cancelCaller)
            await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(10)))
                .Throws<OperationCanceledException>();
        else
        {
            var lost = await pending.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(lost.Status).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(lost.Reason).IsEqualTo(SecretFailureReason.DeadlineExceeded);
        }
        var replay = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(wire.CreatedGroups.ToArray()).IsEquivalentTo(new[] { "created" });
    }

    [Test]
    [Arguments(3600)]
    [Arguments(-3600)]
    public async Task UtcAdjustmentsDoNotConsumeRelativeOperationBudget(int seconds)
    {
        var clock = new Clock();
        using var wire = new Wire { Stage = "send" };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport, clock);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Organization);
        using var request = ScopedAccessOperations.GetGroup(Organization, Group);
        var pending = client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(Organization, resourceId: Group))).AsTask();
        await wire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        clock.UtcOffset = TimeSpan.FromSeconds(seconds);
        wire.Release.SetResult();
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(result.Value.Id).IsEqualTo(Group);
    }

    [Test]
    [Arguments(0, 1024, 1024)]
    [Arguments(61, 1024, 1024)]
    [Arguments(2, 1023, 1024)]
    [Arguments(2, 16777217, 1024)]
    [Arguments(2, 1024, 1023)]
    [Arguments(2, 1024, 16777217)]
    public async Task InvalidSelectedBudgetsRejectConstruction(int seconds, int request, int response)
    {
        await Assert.That(() => new ManagementTransport(new("https://management.test"), new()
        {
            OperationTimeout = TimeSpan.FromSeconds(seconds),
            MaximumRequestBytes = request,
            MaximumResponseBytes = response
        })).Throws<ArgumentException>();
    }

    private static ManagementTransport Transport(Wire wire) => new(new("https://management.test"), new()
    {
        Transport = InfisicalTransportOptions.HostControlled(wire),
        OperationTimeout = TimeSpan.FromSeconds(2),
        MaximumRequestBytes = 1024
    });

    private sealed class Tokens : IInfisicalTokenSource
    {
        internal bool Cooperative { get; init; }
        internal TaskCompletionSource? Entered { get; init; }
        internal TaskCompletionSource Release { get; init; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal SecretMaterial? Material { get; private set; }
        public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            if (Entered is not null)
            {
                Entered.SetResult();
                await Release.Task.WaitAsync(Cooperative ? cancellationToken : CancellationToken.None);
            }
            Material = SecretMaterial.FromText("token");
            return SecretOutcome<InfisicalAccessToken>.Success(new(Material));
        }
    }

    private sealed class Wire : HttpMessageHandler
    {
        internal bool Cooperative { get; init; }
        internal string Stage { get; init; } = "";
        internal TaskCompletionSource Entered { get; init; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; init; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal List<string> CreatedGroups { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Stage == "lost") CreatedGroups.Add("created");
            if (Stage is "send" or "lost")
            {
                Entered.SetResult();
                await Release.Task.WaitAsync(Cooperative ? cancellationToken : CancellationToken.None);
            }
            if (Stage == "lost") throw new HttpRequestException("Synthetic committed response loss.");
            return new(HttpStatusCode.OK)
            {
                Content = Stage == "body"
                    ? new StreamContent(new HeldBody(Entered, Release, Cooperative))
                    : new StringContent(GroupBody)
            };
        }
    }

    private sealed class HeldBody(TaskCompletionSource entered, TaskCompletionSource release, bool cooperative)
        : MemoryStream(Encoding.UTF8.GetBytes(GroupBody))
    {
        public override bool CanSeek => false;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            entered.TrySetResult();
            await release.Task.WaitAsync(cooperative ? cancellationToken : CancellationToken.None);
            return await base.ReadAsync(buffer, CancellationToken.None);
        }
    }

    private sealed class Clock : TimeProvider
    {
        private long _elapsed;
        private readonly List<ClockTimer> _timers = [];
        internal TimeSpan UtcOffset { get; set; }
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch + UtcOffset;
        public override long GetTimestamp() => _elapsed;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        internal void Advance(TimeSpan amount)
        {
            _elapsed += amount.Ticks;
            foreach (var timer in _timers.Where(timer => timer.Due <= _elapsed).ToArray())
            {
                timer.Due = long.MaxValue;
                timer.Fire();
            }
        }
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new ClockTimer(this, callback, state);
            _timers.Add(timer);
            timer.Change(dueTime, period);
            return timer;
        }
        private sealed class ClockTimer(Clock owner, TimerCallback callback, object? state) : ITimer
        {
            internal long Due { get; set; }
            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                Due = dueTime == Timeout.InfiniteTimeSpan ? long.MaxValue : owner._elapsed + dueTime.Ticks;
                return owner._timers.Contains(this);
            }
            internal void Fire() => callback(state);
            public void Dispose() => owner._timers.Remove(this);
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
