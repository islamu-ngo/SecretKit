using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;

namespace SecretKit.Configuration.Tests;

public sealed class ConfigurationTests
{
    [Test]
    public async Task AcquiredGenerationAndCopiesSurviveReplacementAndOwnerDisposal()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var old = loader.Acquire();
        using SecretRead first = old.Read("first");
        using SecretRead second = old.Read("first");
        string original = first.Material.Reveal();
        first.Dispose();
        await Assert.That(second.Material.Reveal()).IsEqualTo(original);

        reader.Value = NewMaterial();
        await loader.RefreshAsync();
        using var current = loader.Acquire();
        await Assert.That(current.Generation).IsEqualTo(old.Generation + 1);
        using SecretRead replacement = current.Read("first");
        await Assert.That(replacement.Material.Reveal()).IsEqualTo(reader.Value);
        loader.Dispose();
        using SecretRead pinned = old.Read("first");
        await Assert.That(pinned.Material.Reveal()).IsEqualTo(original);
        old.Dispose();
        old.Dispose();
        await Assert.That(() => old.Read("first")).Throws<ObjectDisposedException>();
        await Assert.That(second.Material.Reveal()).IsEqualTo(original);
        await Assert.That(() => loader.Acquire()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task PartialCollectionNeverPublishesAndPreservesBoundedFailure()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var previous = loader.Acquire();
        reader.Value = NewMaterial();
        reader.FailureOnSecond = SecretStatus.Denied;
        SecretOutcome<long> result = await loader.RefreshAsync();
        using var current = loader.Acquire();
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(current.Generation).IsEqualTo(previous.Generation);
        using SecretRead read = current.Read("first");
        await Assert.That(read.Material.Reveal()).IsNotEqualTo(reader.Value);
        await Assert.That(loader.LastAttempt!.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(() => reader.LastDelivered!.Material.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task InFlightReplacementPinsOldGenerationUntilComplete()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var old = loader.Acquire();
        string original;
        using (SecretRead read = old.Read("first")) original = read.Material.Reveal();
        reader.Value = NewMaterial();
        reader.BlockSecond = true;
        Task<SecretOutcome<long>> refresh = loader.RefreshAsync().AsTask();
        await reader.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        using (var during = loader.Acquire())
        {
            await Assert.That(during.Generation).IsEqualTo(old.Generation);
        }
        reader.Release.TrySetResult();
        await refresh;
        using SecretRead oldSecond = old.Read("second");
        await Assert.That(oldSecond.Material.Reveal()).IsEqualTo(original);
        using var current = loader.Acquire();
        using SecretRead newFirst = current.Read("first");
        using SecretRead newSecond = current.Read("second");
        await Assert.That(newFirst.Material.Reveal()).IsEqualTo(newSecond.Material.Reveal());
        await Assert.That(newFirst.Material.Reveal()).IsEqualTo(reader.Value);
    }

    [Test]
    public async Task CancellationDuringCollectionKeepsPriorGenerationAndDisposesCandidate()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var old = loader.Acquire();
        reader.BlockSecond = true;
        using var cancellation = new CancellationTokenSource();
        Task<SecretOutcome<long>> refresh = loader.RefreshAsync(cancellation.Token).AsTask();
        await reader.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        await Assert.That(async () => await refresh).Throws<OperationCanceledException>();
        using var current = loader.Acquire();
        await Assert.That(current.Generation).IsEqualTo(old.Generation);
        await Assert.That(() => reader.LastDelivered!.Material.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task DisposalDuringCollectionPreventsPublicationWithoutInvalidatingHandles()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var old = loader.Acquire();
        reader.BlockSecond = true;
        Task<SecretOutcome<long>> refresh = loader.RefreshAsync().AsTask();
        await reader.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        loader.Dispose();
        reader.Release.TrySetResult();
        await Assert.That(async () => await refresh).Throws<ObjectDisposedException>();
        using SecretRead pinned = old.Read("first");
        await Assert.That(pinned.Material.Reveal()).IsEqualTo(reader.Value);
        await Assert.That(() => reader.LastDelivered!.Material.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task CollectionWindowAndObservedVersionRemainActualEvidence()
    {
        var time = new ManualTime();
        var reader = new ControlledReader { Time = time };
        using var loader = CreateLoader(reader, time);
        DateTimeOffset start = time.GetUtcNow();
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        using SecretRead read = handle.Read("first");
        await Assert.That(handle.CollectionStartedAt).IsEqualTo(start);
        await Assert.That(handle.CollectionCompletedAt).IsEqualTo(start.AddMinutes(2));
        await Assert.That(handle.RemoteSnapshotGuaranteed).IsFalse();
        await Assert.That(read.Observation.Version).IsEqualTo(reader.Version);
        await Assert.That(read.Observation.Reference.BelongsTo(reader.Authority)).IsTrue();
    }

    [Test]
    public async Task AuthorityMismatchAndDuplicateConsumerKeysFailBeforeReads()
    {
        var reader = new ControlledReader();
        var wrong = new SecretReference(new SecretAuthority(), new TestAddress());
        await Assert.That(() => new SecretSnapshotLoader([new("first", reader, wrong)]))
            .Throws<ArgumentException>();
        SecretSelection selection = Select("first", reader);
        await Assert.That(() => new SecretSnapshotLoader([selection, selection]))
            .Throws<ArgumentException>();
        await Assert.That(reader.LastDelivered is null).IsTrue();
    }

    [Test]
    public async Task CancellationBeforeCollectionAndNoGenerationFailClosed()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await Assert.That(() => loader.Acquire()).Throws<InvalidOperationException>();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.That(async () => await loader.RefreshAsync(cancellation.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(reader.LastDelivered is null).IsTrue();
        reader.FailureOnSecond = SecretStatus.Absent;
        await loader.RefreshAsync();
        await Assert.That(() => loader.Acquire()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ExpiredAndUnprovenValidityCannotBecomeRequiredGeneration()
    {
        var reader = new ControlledReader { Validity = SecretValidity.Expired };
        using var loader = CreateLoader(reader);
        await Assert.That((await loader.RefreshAsync()).Status).IsEqualTo(SecretStatus.Expired);
        reader.Validity = SecretValidity.Unknown;
        await Assert.That((await loader.RefreshAsync()).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(() => loader.Acquire()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ExportRejectsCaseInsensitiveMappingCollisionsBeforeReveal()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        await Assert.That(() => SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            handle, [new("first", "Service:Value"), new("second", "service:value")]))
            .Throws<ArgumentException>();
        handle.Dispose();
        // Collision validation precedes all material access, even on a closed handle.
        await Assert.That(() => SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            handle, [new("first", "Service:Value"), new("second", "service:value")]))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task FailedExportReplacementKeepsPreviousStringsAndDoesNotSignalReload()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            handle, [new("first", "Service:User"), new("second", "Service:Password")]);
        IConfigurationRoot configuration = new ConfigurationBuilder().Add(export).Build();
        var token = configuration.GetReloadToken();
        using var incomplete = new SecretSnapshotLoader([Select("first", reader)]);
        reader.Value = NewMaterial();
        await incomplete.RefreshAsync();
        using var next = incomplete.Acquire();
        await Assert.That(() => export.ReplaceAcknowledgingManagedStrings(next)).Throws<ArgumentException>();
        using SecretRead previous = handle.Read("first");
        await Assert.That(configuration["Service:User"]).IsEqualTo(previous.Material.Reveal());
        await Assert.That(token.HasChanged).IsFalse();
        (configuration as IDisposable)?.Dispose();
    }

    [Test]
    public async Task ProviderExceptionAndThrottleEvidenceRemainBounded()
    {
        var reader = new ControlledReader { ThrowOnSecond = true };
        using var loader = CreateLoader(reader);
        await Assert.That((await loader.RefreshAsync()).Status).IsEqualTo(SecretStatus.Unavailable);
        string json = JsonSerializer.Serialize(loader.LastAttempt);
        await Assert.That(json.Contains(reader.Value, StringComparison.Ordinal)).IsFalse();
        reader.ThrowOnSecond = false;
        reader.FailureOnSecond = SecretStatus.Throttled;
        SecretOutcome<long> result = await loader.RefreshAsync();
        await Assert.That(result.RetryAfter).IsEqualTo(TimeSpan.FromMinutes(1));
        await Assert.That(loader.LastAttempt!.RetryAfter).IsEqualTo(result.RetryAfter);
    }

    [Test]
    public async Task QueuedCollectionCancellationCannotReplaceInFlightGeneration()
    {
        var reader = new ControlledReader { BlockSecond = true };
        using var loader = CreateLoader(reader);
        Task<SecretOutcome<long>> first = loader.RefreshAsync().AsTask();
        await reader.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        using var cancellation = new CancellationTokenSource();
        Task<SecretOutcome<long>> queued = loader.RefreshAsync(cancellation.Token).AsTask();
        cancellation.Cancel();
        await Assert.That(async () => await queued).Throws<OperationCanceledException>();
        reader.Release.TrySetResult();
        await first;
        using var handle = loader.Acquire();
        await Assert.That(handle.Generation).IsEqualTo(1L);
    }

    [Test]
    public async Task ReaderIgnoringCancellationCannotPublishAndItsDeliveredMaterialIsDisposed()
    {
        var reader = new ControlledReader { BlockSecond = true, IgnoreBarrierCancellation = true };
        using var loader = CreateLoader(reader);
        using var cancellation = new CancellationTokenSource();
        Task<SecretOutcome<long>> refresh = loader.RefreshAsync(cancellation.Token).AsTask();
        await reader.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        reader.Release.TrySetResult();
        await Assert.That(async () => await refresh).Throws<OperationCanceledException>();
        await Assert.That(() => reader.LastDelivered!.Material.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(loader.LastAttempt!.WasCanceled).IsTrue();
        await Assert.That(() => loader.Acquire()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task SynchronousLoadCannotCollectAndDisposedConfigurationCannotBeRepublished()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            handle, [new("first", "Service:Value")]);
        string original = reader.Value;
        reader.Value = NewMaterial();
        IConfigurationRoot configuration = new ConfigurationBuilder().Add(export).Build();
        configuration.Reload();
        await Assert.That(configuration["Service:Value"]).IsEqualTo(original);
        (configuration as IDisposable)?.Dispose();
        await Assert.That(() => export.ReplaceAcknowledgingManagedStrings(handle))
            .Throws<ObjectDisposedException>();
        await Assert.That(configuration["Service:Value"] is null).IsTrue();
    }

    [Test]
    public async Task ValidityDeadlineReachedDuringCollectionFailsClosed()
    {
        var time = new ManualTime();
        var reader = new ControlledReader
        {
            Time = time,
            ExpiresAt = time.GetUtcNow().AddMinutes(2)
        };
        using var loader = CreateLoader(reader, time);
        await Assert.That((await loader.RefreshAsync()).Status).IsEqualTo(SecretStatus.Expired);
        await Assert.That(() => loader.Acquire()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ExplicitStringExportReloadsAndCannotEraseEscapedStrings()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            handle, [new("first", "Service:User"), new("second", "Service:Password")]);
        IConfigurationRoot configuration = new ConfigurationBuilder().Add(export).Build();
        string escaped = configuration["Service:Password"]!;
        await Assert.That(escaped).IsEqualTo(reader.Value);
        string oldValue = reader.Value;
        var reloaded = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var registration = configuration.GetReloadToken().RegisterChangeCallback(
            _ => reloaded.TrySetResult(), null);
        reader.Value = NewMaterial();
        await loader.RefreshAsync();
        using var next = loader.Acquire();
        export.ReplaceAcknowledgingManagedStrings(next);
        await reloaded.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(configuration["Service:Password"]).IsEqualTo(reader.Value);
        await Assert.That(configuration.GetSection("Service").GetChildren().Count()).IsEqualTo(2);
        export.Dispose();
        loader.Dispose();
        handle.Dispose();
        await Assert.That(escaped).IsEqualTo(oldValue);
        await Assert.That(configuration["Service:Password"] is null).IsTrue();
        await Assert.That(() => configuration["Service:User"] = NewMaterial())
            .Throws<NotSupportedException>();
        (configuration as IDisposable)?.Dispose();
    }

    [Test]
    public async Task DefaultFormattingSerializationAndRedactedDebugExcludeKeysAndMaterial()
    {
        var reader = new ControlledReader();
        string consumerKey = Guid.NewGuid().ToString("N");
        string exportKey = Guid.NewGuid().ToString("N");
        SecretSelection selection = Select(consumerKey, reader);
        using var loader = new SecretSnapshotLoader([selection]);
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        var mapping = new SecretConfigurationMapping(consumerKey, exportKey);
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(handle, [mapping]);
        object[] surfaces = [selection, loader, handle, mapping, export, loader.LastAttempt!];
        foreach (object surface in surfaces)
        {
            string rendered = surface + JsonSerializer.Serialize(surface, surface.GetType());
            await Assert.That(rendered.Contains(reader.Value, StringComparison.Ordinal)).IsFalse();
            await Assert.That(rendered.Contains(consumerKey, StringComparison.Ordinal)).IsFalse();
            await Assert.That(rendered.Contains(exportKey, StringComparison.Ordinal)).IsFalse();
        }
        string debug = export.GetRedactedDebugView();
        await Assert.That(debug.Contains(reader.Value, StringComparison.Ordinal)).IsFalse();
        await Assert.That(debug.Contains(exportKey, StringComparison.Ordinal)).IsFalse();
    }

    private static string NewMaterial() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private static SecretSelection Select(string key, ControlledReader reader) =>
        new(key, reader, new SecretReference(reader.Authority, new TestAddress()));
    private static SecretSnapshotLoader CreateLoader(ControlledReader reader, TimeProvider? time = null) =>
        new([Select("first", reader), Select("second", reader)], time);

    private sealed class TestAddress : SecretAddress;

    private sealed class ManualTime : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UnixEpoch;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance() => _now += TimeSpan.FromMinutes(1);
    }

    private sealed class ControlledReader : ISecretReader
    {
        private int _ordinal;
        public SecretAuthority Authority { get; } = new();
        public string Value { get; set; } = NewMaterial();
        public string Version { get; } = Guid.NewGuid().ToString("N");
        public SecretValidity Validity { get; set; } = SecretValidity.Valid;
        public SecretStatus? FailureOnSecond { get; set; }
        public bool ThrowOnSecond { get; set; }
        public DateTimeOffset? ExpiresAt { get; set; }
        public bool BlockSecond { get; set; }
        public bool IgnoreBarrierCancellation { get; set; }
        public ManualTime? Time { get; set; }
        public SecretRead? LastDelivered { get; private set; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<SecretOutcome<SecretRead>> ReadAsync(
            SecretReference reference, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool second = Interlocked.Increment(ref _ordinal) % 2 == 0;
            if (second && BlockSecond)
            {
                Entered.TrySetResult();
                await Release.Task.WaitAsync(IgnoreBarrierCancellation ? CancellationToken.None : cancellationToken);
            }
            Time?.Advance();
            if (second && ThrowOnSecond) throw new InvalidOperationException(Value);
            if (second && FailureOnSecond is { } failure)
                return SecretOutcome<SecretRead>.Failure(failure,
                    failure == SecretStatus.Throttled ? TimeSpan.FromMinutes(1) : null);
            LastDelivered = new SecretRead(SecretMaterial.FromText(Value),
                new SecretObservation(reference, Version, Time?.GetUtcNow() ?? DateTimeOffset.UnixEpoch,
                    Validity, ExpiresAt));
            return SecretOutcome<SecretRead>.Success(LastDelivered);
        }
    }
}
