using SecretKit.Core;
using SecretKit.Extensions.Configuration;

namespace SecretKit.Configuration.Tests;

public sealed class SnapshotLoaderResilienceTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task InitializationFaultReleasesAdmission(bool timerFault)
    {
        var time = new FaultTime { FailCollectionStart = !timerFault, FailTimer = timerFault };
        using var reader = new SelectionReader();
        using var loader = new SecretSnapshotLoader([reader.Select("value")], time);

        await Assert.That(async () => await loader.RefreshAsync()).Throws<InvalidOperationException>();

        using var cancellation = new CancellationTokenSource(Bound);
        await Assert.That((await loader.RefreshAsync(cancellation.Token)).IsSuccess).IsTrue();
    }

    [Test]
    public async Task PostReadClockFaultDisposesDeliveredMaterial()
    {
        var time = new FaultTime();
        using var reader = new SelectionReader
        {
            Expiry = DateTimeOffset.UnixEpoch.AddDays(1),
            BeforeRead = _ => { time.FailNextRead = true; return Task.CompletedTask; }
        };
        using var loader = new SecretSnapshotLoader([reader.Select("value")], time);

        await Assert.That(async () => await loader.RefreshAsync()).Throws<InvalidOperationException>();

        await Assert.That(() => reader.Delivered.Single().Material.Reveal()).Throws<ObjectDisposedException>();
        reader.BeforeRead = null;
        using var cancellation = new CancellationTokenSource(Bound);
        await Assert.That((await loader.RefreshAsync(cancellation.Token)).IsSuccess).IsTrue();
    }

    [Test]
    public async Task FaultedSlotDrainsLaterDeliveryAndReleasesAdmission()
    {
        var time = new FaultTime();
        var faultEntered = Signal();
        var lateEntered = Signal();
        var releaseFault = Signal();
        var releaseLate = Signal();
        using var first = new SelectionReader();
        using var fault = new SelectionReader
        {
            Expiry = DateTimeOffset.UnixEpoch.AddDays(1),
            BeforeRead = async _ =>
            {
                faultEntered.SetResult();
                await releaseFault.Task;
                time.FailNextRead = true;
            }
        };
        using var late = new SelectionReader
        {
            BeforeRead = async _ => { lateEntered.SetResult(); await releaseLate.Task; }
        };
        using var loader = new SecretSnapshotLoader(
            [first.Select("first"), fault.Select("fault"), late.Select("late")], time,
            new SecretCollectionOptions(maximumConcurrency: 3));
        Task<SecretOutcome<long>> refresh = loader.RefreshAsync().AsTask();
        try
        {
            await Task.WhenAll(faultEntered.Task, lateEntered.Task).WaitAsync(Bound);
            releaseFault.SetResult();
            await time.ReadFaulted.Task.WaitAsync(Bound);
        }
        finally
        {
            releaseFault.TrySetResult();
            releaseLate.TrySetResult();
        }

        await Assert.That(async () => await refresh.WaitAsync(Bound)).Throws<InvalidOperationException>();
        await late.LastOperation!.WaitAsync(Bound);
        foreach (SecretRead read in first.Delivered.Concat(fault.Delivered).Concat(late.Delivered))
            await Assert.That(() => read.Material.Reveal()).Throws<ObjectDisposedException>();
        fault.BeforeRead = null;
        late.BeforeRead = null;
        using var cancellation = new CancellationTokenSource(Bound);
        await Assert.That((await loader.RefreshAsync(cancellation.Token)).IsSuccess).IsTrue();
    }

    private sealed class FaultTime : TimeProvider
    {
        private int _utcReads;
        public bool FailCollectionStart { get; set; }
        public bool FailTimer { get; set; }
        public bool FailNextRead { get; set; }
        public TaskCompletionSource ReadFaulted { get; } = Signal();

        public override DateTimeOffset GetUtcNow()
        {
            // Diagnostics captures the first UTC observation before admission.
            if ((++_utcReads == 2 && FailCollectionStart) || FailNextRead)
            {
                FailNextRead = false;
                ReadFaulted.TrySetResult();
                throw new InvalidOperationException("Clock unavailable.");
            }
            return DateTimeOffset.UnixEpoch;
        }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            if (FailTimer)
            {
                FailTimer = false;
                throw new InvalidOperationException("Timer unavailable.");
            }
            return base.CreateTimer(callback, state, dueTime, period);
        }
    }
}
