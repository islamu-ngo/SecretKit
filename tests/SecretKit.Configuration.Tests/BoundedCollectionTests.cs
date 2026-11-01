using SecretKit.Core;
using SecretKit.Extensions.Configuration;

namespace SecretKit.Configuration.Tests;

public sealed class BoundedCollectionTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    [Test]
    [Arguments(1)]
    [Arguments(2)]
    public async Task ElapsedEarlierDeliveryWinsOverLaterFailure(int concurrency)
    {
        var time = new CollectionTime();
        using var earlier = new SelectionReader { Expiry = time.GetUtcNow() };
        using var later = new SelectionReader { Status = SecretStatus.Denied };
        using var loader = new SecretSnapshotLoader([earlier.Select("first"), later.Select("second")],
            time, new SecretCollectionOptions(maximumConcurrency: concurrency));

        SecretOutcome<long> result = await loader.RefreshAsync();
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Expired);
        await Assert.That(loader.LastAttempt!.Status).IsEqualTo(SecretStatus.Expired);
        await Assert.That(() => loader.Acquire()).Throws<InvalidOperationException>();
        await Assert.That(() => earlier.Delivered.Single().Material.Reveal()).Throws<ObjectDisposedException>();
        if (concurrency == 1) await Assert.That(later.Reads).IsEqualTo(0);
    }

    [Test]
    public async Task ContiguousWindowCannotLaunchBehindStalledFirstOrdinal()
    {
        var entered = Signal();
        var release = Signal();
        var second = Signal();
        var first = new SelectionReader { BeforeRead = async _ => { entered.SetResult(); await release.Task; } };
        var later = new SelectionReader { BeforeRead = _ => { second.SetResult(); return Task.CompletedTask; } };
        var third = new SelectionReader();
        using var loader = new SecretSnapshotLoader([first.Select("0"), later.Select("1"), third.Select("2")],
            options: new SecretCollectionOptions(maximumConcurrency: 2));
        Task<SecretOutcome<long>> refresh = loader.RefreshAsync().AsTask();
        try
        {
            await Task.WhenAll(entered.Task, second.Task).WaitAsync(Bound);
            await Assert.That(third.Reads).IsEqualTo(0);
            await Assert.That(refresh.IsCompleted).IsFalse();
        }
        finally { release.TrySetResult(); }
        await Assert.That((await refresh.WaitAsync(Bound)).IsSuccess).IsTrue();
        await Assert.That(third.Reads).IsEqualTo(1);
        foreach (var read in first.Delivered.Concat(later.Delivered).Concat(third.Delivered))
            await Assert.That(() => read.Material.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task FailureIdentityAndAdviceFollowInputOrderNotCompletionOrder(bool reverse)
    {
        var entered0 = Signal();
        var entered1 = Signal();
        var release0 = Signal();
        var release1 = Signal();
        var first = new SelectionReader
        {
            Status = SecretStatus.Unavailable,
            Reason = SecretFailureReason.TransportFailure,
            RetryAfter = TimeSpan.FromSeconds(7),
            BeforeRead = async token => { entered0.SetResult(); await release0.Task.WaitAsync(token); }
        };
        var second = new SelectionReader
        {
            Status = SecretStatus.Denied,
            Reason = SecretFailureReason.CredentialUnavailable,
            BeforeRead = async token => { entered1.SetResult(); await release1.Task.WaitAsync(token); }
        };
        var third = new SelectionReader();
        using var loader = new SecretSnapshotLoader([first.Select("0"), second.Select("1"), third.Select("2")],
            options: new SecretCollectionOptions(maximumConcurrency: 2));
        Task<SecretOutcome<long>> refresh = loader.RefreshAsync().AsTask();
        await Task.WhenAll(entered0.Task, entered1.Task).WaitAsync(Bound);
        if (reverse)
        {
            release1.SetResult();
            await second.LastOperation!.WaitAsync(Bound);
        }
        else
        {
            release0.SetResult();
            await first.LastOperation!.WaitAsync(Bound);
        }
        release0.TrySetResult();
        release1.TrySetResult();
        SecretOutcome<long> result = await refresh.WaitAsync(Bound);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.Reason).IsEqualTo(first.Reason);
        await Assert.That(result.RetryAfter).IsEqualTo(first.RetryAfter);
        await Assert.That(third.Reads).IsEqualTo(0);
    }

    [Test]
    public async Task LaterTerminalFailureStopsAdmissionWithoutCancelingEarlierOrdinal()
    {
        var entered = Signal();
        var release = Signal();
        bool earlierCanceled = false;
        var first = new SelectionReader
        {
            BeforeRead = async token =>
            {
                using var registration = token.Register(() => earlierCanceled = true);
                entered.SetResult();
                await release.Task;
            }
        };
        var second = new SelectionReader { Status = SecretStatus.Denied };
        var third = new SelectionReader();
        using var loader = new SecretSnapshotLoader([first.Select("0"), second.Select("1"), third.Select("2")],
            options: new SecretCollectionOptions(maximumConcurrency: 2));
        Task<SecretOutcome<long>> refresh = loader.RefreshAsync().AsTask();
        await entered.Task.WaitAsync(Bound);
        await Assert.That(earlierCanceled).IsFalse();
        release.SetResult();
        await Assert.That((await refresh.WaitAsync(Bound)).Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(third.Reads).IsEqualTo(0);
        await Assert.That(earlierCanceled).IsFalse();
        await Assert.That(() => first.Delivered.Single().Material.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task EnumerationStopsAtFirstExcessSelectionWithoutReading()
    {
        var reader = new SelectionReader();
        int enumerated = 0;
        IEnumerable<SecretSelection> Selections()
        {
            for (int i = 0; i < 100; i++)
            {
                enumerated++;
                yield return reader.Select(i.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
        }
        await Assert.That(() => new SecretSnapshotLoader(Selections(),
            options: new SecretCollectionOptions(maximumSelections: 2))).Throws<ArgumentException>();
        await Assert.That(enumerated).IsEqualTo(3);
        await Assert.That(reader.Reads).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AggregateBudgetCountsUtf8BeforeRetentionAndDisposesAllDeliveries(bool reverse)
    {
        var release = Signal();
        var entered = Signal();
        var first = new SelectionReader { Text = new string('\u00e9', 300) };
        var second = new SelectionReader { Text = new string('\u00e9', 300) };
        (reverse ? first : second).BeforeRead = async _ => { entered.SetResult(); await release.Task; };
        using var loader = new SecretSnapshotLoader([first.Select("0"), second.Select("1")],
            options: new SecretCollectionOptions(maximumConcurrency: 2, maximumMaterialBytes: 1024));
        Task<SecretOutcome<long>> refresh = loader.RefreshAsync().AsTask();
        await entered.Task.WaitAsync(Bound);
        release.SetResult();
        SecretOutcome<long> result = await refresh.WaitAsync(Bound);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.CollectionLimitExceeded);
        await Assert.That(() => loader.Acquire()).Throws<InvalidOperationException>();
        foreach (var read in first.Delivered.Concat(second.Delivered))
            await Assert.That(() => read.Material.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task FinalClockRejectsEarlierValueThatExpiresWhileAnotherReadIsBlocked()
    {
        var time = new CollectionTime();
        var entered = Signal();
        var release = Signal();
        var first = new SelectionReader { Expiry = time.GetUtcNow().AddSeconds(1) };
        var second = new SelectionReader { BeforeRead = async _ => { entered.SetResult(); await release.Task; } };
        using var loader = new SecretSnapshotLoader([first.Select("0"), second.Select("1")], time,
            new SecretCollectionOptions(maximumConcurrency: 2));
        Task<SecretOutcome<long>> refresh = loader.RefreshAsync().AsTask();
        await entered.Task.WaitAsync(Bound);
        time.Advance(TimeSpan.FromSeconds(2));
        release.SetResult();
        await Assert.That((await refresh.WaitAsync(Bound)).Status).IsEqualTo(SecretStatus.Expired);
        await Assert.That(() => loader.Acquire()).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DeadlineDrainsLateIgnoringReaderAndCallerCancellationWins(bool cancelCaller)
    {
        var time = new CollectionTime();
        var entered = Signal();
        var cancellationObserved = Signal();
        var release = Signal();
        var reader = new SelectionReader
        {
            BeforeRead = async token =>
            {
                using var registration = token.Register(() => cancellationObserved.TrySetResult());
                entered.SetResult();
                await release.Task;
            }
        };
        using var caller = new CancellationTokenSource();
        using var loader = new SecretSnapshotLoader([reader.Select("value")], time,
            new SecretCollectionOptions(collectionTimeout: TimeSpan.FromSeconds(1)));
        Task<SecretOutcome<long>> refresh = loader.RefreshAsync(caller.Token).AsTask();
        await entered.Task.WaitAsync(Bound);
        time.Advance(TimeSpan.FromSeconds(1));
        await cancellationObserved.Task.WaitAsync(Bound);
        await Assert.That(refresh.IsCompleted).IsFalse();
        if (cancelCaller) caller.Cancel();
        release.SetResult();
        if (cancelCaller)
            await Assert.That(async () => await refresh.WaitAsync(Bound)).Throws<OperationCanceledException>();
        else
        {
            SecretOutcome<long> result = await refresh.WaitAsync(Bound);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unavailable);
            await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.DeadlineExceeded);
        }
        await Assert.That(() => reader.Delivered.Single().Material.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(() => loader.Acquire()).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task MalformedDeliveriesAndUnexpectedExceptionsAreSanitized(int fault)
    {
        var reader = new SelectionReader();
        if (fault == 0) reader.ForeignReference = new SecretReference(reader.Authority, new SelectionAddress());
        if (fault == 1) reader.DisposeBeforeDelivery = true;
        if (fault == 2) reader.Text = "\ud800";
        if (fault == 3) reader.BeforeRead = _ => throw new OperationCanceledException("private-canary");
        using var loader = new SecretSnapshotLoader([reader.Select("value")]);
        SecretOutcome<long> result = await loader.RefreshAsync();
        await Assert.That(result.Status).IsEqualTo(fault == 3 ? SecretStatus.Unavailable : SecretStatus.Invalid);
        await Assert.That(result.Reason).IsEqualTo(fault == 3 ? SecretFailureReason.TransportFailure :
            fault == 0 ? SecretFailureReason.AuthorityMismatch : SecretFailureReason.InvalidResponse);
        foreach (var read in reader.Delivered)
            await Assert.That(() => read.Material.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task OptionsEnforceDocumentedBounds()
    {
        var defaults = new SecretCollectionOptions();
        await Assert.That(defaults.MaximumConcurrency).IsEqualTo(1);
        await Assert.That(defaults.MaximumSelections).IsEqualTo(1000);
        await Assert.That(defaults.MaximumMaterialBytes).IsEqualTo(16 * 1024 * 1024);
        await Assert.That(defaults.CollectionTimeout).IsEqualTo(TimeSpan.FromMinutes(1));
        await Assert.That(() => new SecretCollectionOptions(maximumConcurrency: 0)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SecretCollectionOptions(maximumConcurrency: 33)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SecretCollectionOptions(maximumSelections: 10001)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SecretCollectionOptions(maximumMaterialBytes: 1023)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SecretCollectionOptions(maximumMaterialBytes: 64 * 1024 * 1024 + 1)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SecretCollectionOptions(collectionTimeout: TimeSpan.Zero)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SecretCollectionOptions(collectionTimeout: TimeSpan.FromMinutes(11))).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task RetiredLoaderDrainsAllStartedReadsAndHeldGenerationRemainsUsable()
    {
        var first = new SelectionReader();
        var second = new SelectionReader();
        using var loader = new SecretSnapshotLoader([first.Select("0"), second.Select("1")],
            options: new SecretCollectionOptions(maximumConcurrency: 2));
        await loader.RefreshAsync();
        using var held = loader.Acquire();
        var entered0 = Signal();
        var entered1 = Signal();
        var release = Signal();
        first.BeforeRead = async _ => { entered0.SetResult(); await release.Task; };
        second.BeforeRead = async _ => { entered1.SetResult(); await release.Task; };
        Task<SecretOutcome<long>> refresh = loader.RefreshAsync().AsTask();
        try
        {
            await Task.WhenAll(entered0.Task, entered1.Task).WaitAsync(Bound);
            loader.Dispose();
            await Assert.That(refresh.IsCompleted).IsFalse();
        }
        finally { release.TrySetResult(); }
        await Assert.That(async () => await refresh.WaitAsync(Bound)).Throws<ObjectDisposedException>();
        using SecretRead copy = held.Read("0");
        await Assert.That(copy.Material.Reveal()).IsEqualTo(first.Text);
        foreach (var read in first.Delivered.Concat(second.Delivered))
            await Assert.That(() => read.Material.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task CancelingQueuedRefreshDoesNotCancelAdmittedCollection()
    {
        var entered = Signal();
        var release = Signal();
        var reader = new SelectionReader
        {
            BeforeRead = async token =>
        {
            entered.SetResult();
            await release.Task.WaitAsync(token);
        }
        };
        using var loader = new SecretSnapshotLoader([reader.Select("value")]);
        Task<SecretOutcome<long>> admitted = loader.RefreshAsync().AsTask();
        await entered.Task.WaitAsync(Bound);
        using var cancellation = new CancellationTokenSource();
        Task<SecretOutcome<long>> queued = loader.RefreshAsync(cancellation.Token).AsTask();
        cancellation.Cancel();
        try
        {
            await Assert.That(async () => await queued.WaitAsync(Bound)).Throws<OperationCanceledException>();
            await Assert.That(admitted.IsCompleted).IsFalse();
            await Assert.That(reader.Reads).IsEqualTo(1);
        }
        finally { release.TrySetResult(); }
        await Assert.That((await admitted.WaitAsync(Bound)).IsSuccess).IsTrue();
    }
}

internal sealed class CollectionTime : TimeProvider
{
    private DateTimeOffset _now = DateTimeOffset.UnixEpoch;
    private readonly List<ManualTimer> _timers = [];
    public override DateTimeOffset GetUtcNow() => _now;
    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(this, callback, state);
        timer.Change(dueTime, period);
        _timers.Add(timer);
        return timer;
    }
    public void Advance(TimeSpan elapsed)
    {
        _now += elapsed;
        foreach (var timer in _timers.ToArray()) timer.Fire(_now);
    }
    private sealed class ManualTimer(CollectionTime time, TimerCallback callback, object? state) : ITimer
    {
        private DateTimeOffset? _due;
        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            _due = dueTime == Timeout.InfiniteTimeSpan ? null : time.GetUtcNow() + dueTime;
            return true;
        }
        public void Fire(DateTimeOffset now)
        {
            if (_due is not { } due || now < due) return;
            _due = null;
            callback(state);
        }
        public void Dispose() => _due = null;
        public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
    }
}
