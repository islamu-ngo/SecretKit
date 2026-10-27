using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;

namespace SecretKit.Configuration.Tests;

public sealed class ConfigurationTests
{
    [Test]
    public async Task DedicatedAuthorityExportNeverResolvesUnselectedLocalDefaults()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            handle, [new("first", "Service:User"), new("second", "Service:Password")]);
        IConfigurationRoot authorityOnly = new ConfigurationBuilder().Add(export).Build();
        using var configurationLifetime = (IDisposable)authorityOnly;
        IConfigurationRoot local = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["Service:Password"] = "local-must-not-repair-authority",
                ["Service:Unselected"] = "local-only"
            }).Build();
        using var localLifetime = (IDisposable)local;

        await Assert.That(authorityOnly["Service:Password"]).IsEqualTo(reader.Value);
        await Assert.That(authorityOnly["Service:Unselected"]).IsNull();
        await Assert.That(authorityOnly.AsEnumerable().Count(pair => pair.Value is not null)).IsEqualTo(2);
        await Assert.That(local["Service:Unselected"]).IsEqualTo("local-only");
    }

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

    [Test]
    public async Task SecondBuildRejectsWithoutDisposingWinningRoot()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            handle, [new("first", "Service:Value")]);
        IConfigurationRoot root = new ConfigurationBuilder().Add(export).Build();
        using var lifetime = (IDisposable)root;

        await Assert.That(() => new ConfigurationBuilder().Add(export).Build())
            .Throws<InvalidOperationException>();
        await Assert.That(root["Service:Value"]).IsEqualTo(reader.Value);
        reader.Value = NewMaterial();
        await loader.RefreshAsync();
        using var next = loader.Acquire();
        export.ReplaceAcknowledgingManagedStrings(next);
        await Assert.That(root["Service:Value"]).IsEqualTo(reader.Value);
    }

    [Test]
    public async Task ConcurrentBuildersHaveExactlyOneUsableWinner()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            handle, [new("first", "Service:Value")]);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int arrivals = 0;
        Task<(IConfigurationRoot? Root, Exception? Error)> BuildAsync() => Task.Run(async () =>
        {
            if (Interlocked.Increment(ref arrivals) == 2) ready.TrySetResult();
            await start.Task;
            try { return ((IConfigurationRoot?)new ConfigurationBuilder().Add(export).Build(), (Exception?)null); }
            catch (Exception error) { return ((IConfigurationRoot?)null, error); }
        });
        var first = BuildAsync();
        var second = BuildAsync();
        (IConfigurationRoot? Root, Exception? Error)[] results;
        try
        {
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(10));
            start.TrySetResult();
            results = await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally { start.TrySetResult(); }
        try
        {
            await Assert.That(results.Count(result => result.Root is not null)).IsEqualTo(1);
            await Assert.That(results.Count(result => result.Error is InvalidOperationException)).IsEqualTo(1);
            IConfigurationRoot winner = results.Single(result => result.Root is not null).Root!;
            await Assert.That(winner["Service:Value"]).IsEqualTo(reader.Value);
        }
        finally
        {
            foreach (var result in results) (result.Root as IDisposable)?.Dispose();
        }
    }

    [Test]
    public async Task LaterSiblingBuildFailureDoesNotReopenExportSlot()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            handle, [new("first", "Service:Value")]);
        await Assert.That(() => new ConfigurationBuilder().Add(export).Add(new FailingSource()).Build())
            .Throws<InvalidOperationException>();
        await Assert.That(() => new ConfigurationBuilder().Add(export).Build())
            .Throws<InvalidOperationException>();
        export.Dispose();
        await Assert.That(() => export.Build(new ConfigurationBuilder())).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task BuildAndSourceDisposalLinearizeWithoutRebuild(bool disposeFirst)
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            handle, [new("first", "Service:Value")]);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var disposed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var built = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<IConfigurationRoot?> build = Task.Run(async () =>
        {
            await start.Task;
            if (disposeFirst) await disposed.Task;
            try { return new ConfigurationBuilder().Add(export).Build(); }
            catch (ObjectDisposedException) { return null; }
            finally { built.TrySetResult(); }
        });
        Task dispose = Task.Run(async () =>
        {
            await start.Task;
            if (!disposeFirst) await built.Task;
            export.Dispose();
            disposed.TrySetResult();
        });
        start.TrySetResult();
        await Task.WhenAll(build, dispose).WaitAsync(TimeSpan.FromSeconds(10));
        IConfigurationRoot? root = await build;
        using var lifetime = root as IDisposable;
        await Assert.That(root is null).IsEqualTo(disposeFirst);
        if (root is not null) await Assert.That(root["Service:Value"]).IsNull();
        await Assert.That(() => export.Build(new ConfigurationBuilder())).Throws<ObjectDisposedException>();
        await Assert.That(() => export.ReplaceAcknowledgingManagedStrings(handle)).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ThrowingReloadCallbackCannotLeakPayloadOrRollBackCommittedValues(bool providerToken)
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            handle, [new("first", "Service:Value")]);
        IConfigurationRoot root = new ConfigurationBuilder().Add(export).Build();
        using var lifetime = (IDisposable)root;
        string escaped = root["Service:Value"]!;
        string payload = NewMaterial();
        string? observed = null;
        var token = providerToken ? root.Providers.Single().GetReloadToken() : root.GetReloadToken();
        using var registration = token.RegisterChangeCallback(_ =>
        {
            observed = root["Service:Value"];
            throw new InvalidOperationException(payload, new Exception(payload));
        }, null);
        reader.Value = NewMaterial();
        await loader.RefreshAsync();
        using var next = loader.Acquire();
        Exception? failure = null;
        try { export.ReplaceAcknowledgingManagedStrings(next); }
        catch (Exception error) { failure = error; }

        await Assert.That(observed).IsEqualTo(reader.Value);
        await Assert.That(root["Service:Value"]).IsEqualTo(reader.Value);
        await Assert.That(token.HasChanged).IsTrue();
        await Assert.That(escaped).IsNotEqualTo(reader.Value);
        await Assert.That(failure is InvalidOperationException).IsTrue();
        await Assert.That(failure!.InnerException).IsNull();
        await Assert.That(failure.ToString().Contains(payload, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task ReloadCallbackCanReadAndReplaceFromAnotherThreadOutsideBothGates()
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var initial = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            initial, [new("first", "Service:Value")]);
        IConfigurationRoot root = new ConfigurationBuilder().Add(export).Build();
        using var lifetime = (IDisposable)root;
        reader.Value = NewMaterial();
        await loader.RefreshAsync();
        using var next = loader.Acquire();
        string committed = reader.Value;
        reader.Value = NewMaterial();
        await loader.RefreshAsync();
        using var reentrant = loader.Acquire();
        string? observed = null;
        using var registration = root.GetReloadToken().RegisterChangeCallback(_ =>
        {
            Task.Run(() =>
            {
                observed = root["Service:Value"];
                export.ReplaceAcknowledgingManagedStrings(reentrant);
            }).WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
        }, null);

        await Task.Run(() => export.ReplaceAcknowledgingManagedStrings(next))
            .WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(observed).IsEqualTo(committed);
        await Assert.That(root["Service:Value"]).IsEqualTo(reader.Value);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DisposalDuringReloadPreventsReplacementAndResurrection(bool disposeRoot)
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            handle, [new("first", "Service:Value")]);
        IConfigurationRoot root = new ConfigurationBuilder().Add(export).Build();
        using var lifetime = (IDisposable)root;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        // Block before root propagation so root disposal need not wait for its own
        // in-flight framework registration. The provider has already committed.
        using var registration = root.Providers.Single().GetReloadToken().RegisterChangeCallback(_ =>
        {
            entered.TrySetResult();
            release.Task.WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
        }, null);
        reader.Value = NewMaterial();
        await loader.RefreshAsync();
        using var next = loader.Acquire();
        Task replace = Task.Run(() => export.ReplaceAcknowledgingManagedStrings(next));
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(root["Service:Value"]).IsEqualTo(reader.Value);
            await Task.Run(() =>
            {
                if (disposeRoot) ((IDisposable)root).Dispose();
                else export.Dispose();
            }).WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(() => export.ReplaceAcknowledgingManagedStrings(handle))
                .Throws<ObjectDisposedException>();
            await Assert.That(() => export.Build(new ConfigurationBuilder()))
                .Throws<InvalidOperationException>();
            await Assert.That(root["Service:Value"]).IsNull();
        }
        finally { release.TrySetResult(); }
        await replace.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(root["Service:Value"]).IsNull();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ReloadCallbackCanDisposeWithoutHoldingEitherGate(bool disposeRoot)
    {
        var reader = new ControlledReader();
        using var loader = CreateLoader(reader);
        await loader.RefreshAsync();
        using var handle = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            handle, [new("first", "Service:Value")]);
        IConfigurationRoot root = new ConfigurationBuilder().Add(export).Build();
        using var lifetime = (IDisposable)root;
        using var registration = root.GetReloadToken().RegisterChangeCallback(_ =>
        {
            // Root disposal unregisters the callback currently propagating reload;
            // reenter it on this thread rather than joining that framework wait.
            if (disposeRoot) ((IDisposable)root).Dispose();
            else Task.Run(export.Dispose).WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
        }, null);
        await Task.Run(() => export.ReplaceAcknowledgingManagedStrings(handle))
            .WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(root["Service:Value"]).IsNull();
        await Assert.That(() => export.ReplaceAcknowledgingManagedStrings(handle))
            .Throws<ObjectDisposedException>();
    }

    private sealed class FailingSource : IConfigurationSource
    {
        public IConfigurationProvider Build(IConfigurationBuilder builder) =>
            throw new InvalidOperationException("Synthetic sibling source failure.");
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
