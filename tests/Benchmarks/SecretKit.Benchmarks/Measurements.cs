using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;
using SecretKit.Samples.RuntimeConfiguration;

namespace SecretKit.Samples.Infisical;

// Nonpackable workload source. Only the generated quality consumer links this file.
// No provider, HTTP, credentials, benchmark dependency or SDK source reference.
internal static class Measurements
{
    private const int Keys = 8;
    private const int Warmup = 16;
    private const int Repetitions = 128;
    private const int LeasesPerBatch = 256;
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);

    internal static async Task<string> RunAsync()
    {
        var rows = new List<object>();
        await MeasureAsync("preparation", async () =>
        {
            var reader = new Reader();
            using var prepared = (await PreparedSecretConfiguration.PrepareAsync(
                Selections(reader), options: CollectionOptions())).Value;
            using SecretRead read = prepared.Read("key0");
            Require(read.Material.Reveal().Length == 256);
        });
        var refreshReader = new Reader();
        using (var loader = Loader(refreshReader))
        {
            Require((await loader.RefreshAsync()).IsSuccess);
            using var initial = loader.Acquire();
            using var export = SecretConfigurationExport.Create(initial, Mapping());
            IConfigurationProvider provider = export.Build(new ConfigurationBuilder());
            await MeasureAsync("refresh-export", async () =>
            {
                Require((await loader.RefreshAsync()).IsSuccess);
                using var handle = loader.Acquire();
                export.Replace(handle);
                Require(provider.TryGet("Work:0", out string? value) && value?.Length == 256);
            });
        }
        var resources = new Resources();
        await using (var coordinator = Coordinator(new Reader(), resources))
        {
            Require((await coordinator.EnableAsync()).Active);
            await MeasureAsync("request-lease-batch", async () =>
            {
                for (int i = 0; i < LeasesPerBatch; i++)
                {
                    await using var lease = coordinator.Acquire() ?? throw new InvalidOperationException();
                    Require(await lease.ExecuteAsync(static (client, token) => client.ExecuteAsync(token)) == "accepted");
                }
            });
            await MeasureAsync("handover", async () =>
            {
                await using var held = coordinator.Acquire() ?? throw new InvalidOperationException();
                long old = held.Revision;
                Require((await coordinator.EnableAsync()).Active);
                await using var next = coordinator.Acquire() ?? throw new InvalidOperationException();
                Require(next.Revision > old && await held.ExecuteAsync(static (client, token) => client.ExecuteAsync(token)) == "accepted");
            });
        }
        await MeasureAsync("cancellation", async () => { Require(await CancelAsync()); });
        await MeasureAsync("shutdown", async () =>
        {
            var owned = new Resources();
            var coordinator = Coordinator(new Reader(), owned);
            Require((await coordinator.EnableAsync()).Active);
            await coordinator.DisposeAsync();
            Require(owned.Live == 0 && owned.Created == owned.Disposed);
        });
        object invariants = await InvariantsAsync();
        object preparation = await PreparationAsync();
        return JsonSerializer.Serialize(new
        {
            kind = "controlled-local-overhead",
            runtime = RuntimeInformation.FrameworkDescription,
            os = RuntimeInformation.OSDescription,
            osVersion = Environment.OSVersion.VersionString,
            rid = RuntimeInformation.RuntimeIdentifier,
            architecture = RuntimeInformation.ProcessArchitecture.ToString(),
            processorCount = Environment.ProcessorCount,
            serverGc = System.Runtime.GCSettings.IsServerGC,
            stopwatchFrequency = Stopwatch.Frequency,
            keys = Keys,
            valueBytes = 256,
            warmup = Warmup,
            repetitions = Repetitions,
            leasesPerBatch = LeasesPerBatch,
            collection = CollectionOptions(),
            packages = new[]
            {
                typeof(SecretMaterial).Assembly.FullName,
                typeof(SecretSnapshotLoader).Assembly.FullName
            },
            rows,
            invariants,
            preparation
        });

        async Task MeasureAsync(string name, Func<Task> action)
        {
            for (int i = 0; i < Warmup; i++) await action();
            long[] ticks = new long[Repetitions];
            long[] allocated = new long[Repetitions];
            for (int i = 0; i < Repetitions; i++)
            {
                long before = GC.GetTotalAllocatedBytes(precise: true);
                long start = Stopwatch.GetTimestamp();
                await action();
                ticks[i] = Stopwatch.GetTimestamp() - start;
                allocated[i] = GC.GetTotalAllocatedBytes(precise: true) - before;
            }
            rows.Add(new { name, ticks, processAllocatedBytes = allocated });
        }
    }

    private static async Task<object> PreparationAsync()
    {
        var reader = new Reader();
        SecretSelection[] selections =
        [
            .. Selections(reader),
            new("optional", reader, new(reader.Authority, new Address(absent: true)),
                SecretPresencePolicy.Optional)
        ];
        using var prepared = (await PreparedSecretConfiguration.PrepareAsync(
            selections, options: CollectionOptions())).Value;
        using SecretRead copy = prepared.Read("key0");
        bool optionalAbsent = prepared.ReadOutcome("optional").Status == SecretStatus.Absent;
        IConfigurationRoot configuration = prepared.Export(
            [.. Mapping(), new("optional", "Work:Optional")]);
        bool preparedNullPresent = configuration.Providers.Single().TryGet("Work:Optional", out string? optional) &&
            optional is null;
        // IConfiguration chaining loses null presence. Compose the explicit export
        // source directly when proving precedence over a lower provider.
        using var maskLoader = new SecretSnapshotLoader(selections, options: CollectionOptions());
        Require((await maskLoader.RefreshAsync()).IsSuccess);
        using var maskHandle = maskLoader.Acquire();
        using var maskSource = SecretConfigurationExport.Create(
            maskHandle, [.. Mapping(), new("optional", "Work:Optional")]);
        IConfigurationRoot fallback = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Work:Optional"] = "fallback" })
            .Add(maskSource).Build();
        using var fallbackOwner = (IDisposable)fallback;
        bool absenceMasksFallback = preparedNullPresent && fallback["Work:Optional"] is null;
        prepared.Dispose();
        bool ownedCopySurvivesDisposal = copy.Material.Reveal().Length == 256;
        using SecretRead borrowed = (await reader.ReadAsync(
            new(reader.Authority, new Address()))).Value;
        return new
        {
            optionalAbsent,
            absenceMasksFallback,
            ownedCopySurvivesDisposal,
            borrowedReaderStillUsable = borrowed.Material.Reveal().Length == 256
        };
    }

    private static async Task<object> InvariantsAsync()
    {
        var owned = new Resources();
        var coordinator = Coordinator(new Reader(), owned);
        Require((await coordinator.EnableAsync()).Active);
        var held = coordinator.Acquire() ?? throw new InvalidOperationException();
        long revision = held.Revision;
        var live = new List<int>();
        for (int i = 0; i < 64; i++)
        {
            Require((await coordinator.EnableAsync()).Active);
            live.Add(owned.Live);
        }
        bool coherent = held.Revision == revision && await held.ExecuteAsync(static (client, token) => client.ExecuteAsync(token)) == "accepted";
        await held.DisposeAsync();
        int afterRelease = owned.Live;
        var final = coordinator.Acquire() ?? throw new InvalidOperationException();
        Task shutdown = coordinator.DisposeAsync().AsTask();
        // DisposeAsync marks the owner disposed before yielding; the pinned lease
        // owns the last reference. Completion cannot depend on scheduling luck.
        bool shutdownHeld = !shutdown.IsCompleted && owned.Live == 1;
        await final.DisposeAsync();
        await shutdown.WaitAsync(Bound);
        int finalLive = owned.Live;
        bool cancelled = await CancelAsync();
        return new
        {
            replacements = 64,
            liveAfterEachReplacement = live,
            peakLive = owned.Peak,
            afterRelease,
            finalLive,
            owned.Created,
            owned.Disposed,
            owned.DuplicateDisposals,
            coherent,
            shutdownHeld,
            cancellationPreservedGeneration = cancelled
        };
    }

    private static async Task<bool> CancelAsync()
    {
        var reader = new Reader();
        using var loader = Loader(reader);
        Require((await loader.RefreshAsync()).IsSuccess);
        using var old = loader.Acquire();
        reader.Block = true;
        using var cancellation = new CancellationTokenSource();
        Task<SecretOutcome<long>> pending = loader.RefreshAsync(cancellation.Token).AsTask();
        await reader.Entered.Task.WaitAsync(Bound);
        cancellation.Cancel();
        bool cancelled = false;
        try { await pending.WaitAsync(Bound); }
        catch (OperationCanceledException) { cancelled = true; }
        using var current = loader.Acquire();
        return cancelled && current.Generation == old.Generation && loader.LastAttempt!.WasCanceled;
    }

    private static SecretCollectionOptions CollectionOptions() => new(
        maximumConcurrency: 4, maximumSelections: 16, maximumMaterialBytes: 4096,
        collectionTimeout: Bound);

    private static SecretSnapshotLoader Loader(Reader reader) => new(
        Selections(reader), options: CollectionOptions());

    private static IEnumerable<SecretSelection> Selections(Reader reader) =>
        Enumerable.Range(0, Keys).Select(i => new SecretSelection("key" + i, reader,
            new SecretReference(reader.Authority, new Address())));

    private static IEnumerable<SecretConfigurationMapping> Mapping() =>
        Enumerable.Range(0, Keys).Select(i => new SecretConfigurationMapping("key" + i, "Work:" + i));

    private static SecretGenerationCoordinator<IRuntimeIntegrationClient> Coordinator(Reader reader, Resources resources) => new(reader,
        Enumerable.Range(0, Keys).ToDictionary(i => "key" + i,
            _ => new SecretReference(reader.Authority, new Address())),
        (candidate, token) =>
        {
            token.ThrowIfCancellationRequested();
            // Real owned copies and plaintext export at an explicit app boundary.
            using SecretRead read = candidate.Read("key0");
            Require(read.Material.Reveal().Length == 256);
            return ValueTask.FromResult(SecretOutcome<IRuntimeIntegrationClient>.Success(new Client(resources)));
        }, SecretGenerationStalePolicy.FailClosed, TimeSpan.FromHours(1), TimeProvider.System);

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Controlled workload invariant failed.");
    }

    private sealed class Address(bool absent = false) : SecretAddress
    {
        internal bool Absent { get; } = absent;
    }

    private sealed class Reader : ISecretReader
    {
        private readonly string _value = new('x', 256);
        public SecretAuthority Authority { get; } = new();
        internal bool Block { get; set; }
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (((Address)reference.Address).Absent)
                return SecretOutcome<SecretRead>.Failure(SecretStatus.Absent);
            if (Block)
            {
                Entered.TrySetResult();
                await _release.Task.WaitAsync(cancellationToken);
            }
            return SecretOutcome<SecretRead>.Success(new SecretRead(SecretMaterial.FromText(_value),
                new SecretObservation(reference, null, DateTimeOffset.UtcNow, SecretValidity.Valid)));
        }
    }

    private sealed class Resources
    {
        internal int Created;
        internal int Disposed;
        internal int DuplicateDisposals;
        internal int Peak;
        internal int Live => Created - Disposed;
    }

    private sealed class Client : IRuntimeIntegrationClient
    {
        private readonly Resources _resources;
        private bool _disposed;
        internal Client(Resources resources)
        {
            _resources = resources;
            resources.Created++;
            resources.Peak = Math.Max(resources.Peak, resources.Live);
        }
        public ValueTask<string> ExecuteAsync(CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult("accepted");
        }
        public ValueTask DisposeAsync()
        {
            if (_disposed) _resources.DuplicateDisposals++;
            else { _disposed = true; _resources.Disposed++; }
            return ValueTask.CompletedTask;
        }
    }
}
