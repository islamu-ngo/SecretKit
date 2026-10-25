using System.Diagnostics;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;

namespace SecretKit.Samples.RuntimeConfiguration;

public sealed record CompositionMeasurement(int SelectedReads, TimeSpan Elapsed);

/// <summary>Consumer policy: collect all required controlled values before constructing dependencies.</summary>
public static class BootstrapScenario
{
    /// <summary>Offline workload: two required keys collected twice and one optional key checked twice, then enabled.</summary>
    public static async Task<CompositionMeasurement> RunCompositionAsync()
    {
        var reader = new CompositionReader();
        var required = new Dictionary<string, SecretReference>
        {
            ["username"] = new(reader.Authority, new CompositionAddress(false)),
            ["password"] = new(reader.Authority, new CompositionAddress(false))
        };
        var watch = Stopwatch.StartNew();
        using var loader = new SecretSnapshotLoader(required.Select(pair =>
            new SecretSelection(pair.Key, reader, pair.Value)));
        if (!(await loader.RefreshAsync()).IsSuccess)
            throw new InvalidOperationException("Required bootstrap was not prepared.");
        using SecretSnapshotHandle operation = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(operation,
            [new("username", "Service:Username"), new("password", "Service:Password")]);
        // This dedicated configuration root has no local/environment fallback sources.
        IConfigurationRoot authorityOnly = new ConfigurationBuilder().Add(export).Build();
        using var configurationLifetime = (IDisposable)authorityOnly;
        string username = authorityOnly["Service:Username"]!;
        string password = authorityOnly["Service:Password"]!;
        Func<bool> applicationOwnedConsumer = () => username.Length > 0 && password.Length > 0;

        await using var optional = new RuntimeIntegrationCoordinator(reader,
            new Dictionary<string, SecretReference>
            {
                ["credential"] = new(reader.Authority, new CompositionAddress(true))
            },
            (candidate, _) =>
            {
                using SecretRead read = candidate.Read("credential");
                return ValueTask.FromResult(SecretOutcome<IRuntimeIntegrationClient>.Success(
                    new CompositionClient(read.Material.Reveal())));
            }, RuntimeStalePolicy.FailClosed, TimeSpan.FromMinutes(1), TimeProvider.System);
        RuntimeActivationObservation absent = await optional.CheckAgainAsync();
        if (absent.LastStatus != SecretStatus.Absent || !applicationOwnedConsumer())
            throw new InvalidOperationException("Optional absence affected required startup.");
        reader.OptionalAvailable = true;
        RuntimeActivationObservation checkedAgain = await optional.CheckAgainAsync();
        if (checkedAgain.Active || optional.Acquire() is not null)
            throw new InvalidOperationException("A capability check activated a consumer.");
        await optional.EnableAsync();
        await using RuntimeGenerationLease active = optional.Acquire()!;
        await active.ExecuteAsync();

        reader.RequiredValue = "offline-next";
        await loader.RefreshAsync();
        using SecretSnapshotHandle next = loader.Acquire();
        using SecretRead pinned = operation.Read("password");
        using SecretRead replacement = next.Read("password");
        if (pinned.Material.Reveal() != password || replacement.Material.Reveal() == password ||
            next.Generation <= operation.Generation)
            throw new InvalidOperationException("Logical operation lost its pinned generation.");
        watch.Stop();
        Console.WriteLine($"COMPOSITION_SERIAL_REQUIRED_KEYS_2_PASSES_2_OPTIONAL_KEYS_1_CHECKS_2_ENABLES_1_READS_{reader.Reads}_ELAPSED_MS_{watch.Elapsed.TotalMilliseconds:F3}");
        return new(reader.Reads, watch.Elapsed);
    }

    public static async ValueTask<SecretOutcome<BootstrapCandidate>> PrepareAsync(
        ISecretReader selected, IReadOnlyDictionary<string, SecretReference> required,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selected);
        ArgumentNullException.ThrowIfNull(required);
        cancellationToken.ThrowIfCancellationRequested();
        if (required.Count == 0)
        {
            return SecretOutcome<BootstrapCandidate>.Failure(SecretStatus.Invalid);
        }

        // Freeze mappings and validate the whole authority boundary before any I/O.
        KeyValuePair<string, SecretReference>[] bindings = required.ToArray();
        if (bindings.Any(binding => string.IsNullOrWhiteSpace(binding.Key) ||
            !binding.Value.BelongsTo(selected.Authority)) ||
            bindings.Select(binding => binding.Key).Distinct(StringComparer.OrdinalIgnoreCase).Count() != bindings.Length)
        {
            return SecretOutcome<BootstrapCandidate>.Failure(SecretStatus.Invalid);
        }

        using var loader = new SecretSnapshotLoader(bindings.Select(binding =>
            new SecretSelection(binding.Key, selected, binding.Value)));
        SecretOutcome<long> collection = await loader.RefreshAsync(cancellationToken);
        return collection.IsSuccess
            ? SecretOutcome<BootstrapCandidate>.Success(
                new BootstrapCandidate(loader.Acquire(), bindings.Select(binding => binding.Key).ToArray()))
            : SecretOutcome<BootstrapCandidate>.Failure(collection.Status, collection.RetryAfter);
    }

    private sealed class CompositionAddress(bool optional) : SecretAddress
    {
        internal bool Optional { get; } = optional;
    }

    private sealed class CompositionReader : ISecretReader
    {
        public SecretAuthority Authority { get; } = new();
        internal bool OptionalAvailable { get; set; }
        internal string RequiredValue { get; set; } = "offline-first";
        internal int Reads { get; private set; }

        public ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Reads++;
            var address = (CompositionAddress)reference.Address;
            return ValueTask.FromResult(address.Optional && !OptionalAvailable
                ? SecretOutcome<SecretRead>.Failure(SecretStatus.Absent)
                : SecretOutcome<SecretRead>.Success(new(
                    SecretMaterial.FromText(address.Optional ? "offline-optional" : RequiredValue),
                    new(reference, null, DateTimeOffset.UtcNow, SecretValidity.Valid))));
        }
    }

    private sealed class CompositionClient(string value) : IRuntimeIntegrationClient
    {
        private bool _disposed;
        public ValueTask<string> ExecuteAsync(CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(value);
        }
        public ValueTask DisposeAsync()
        {
            _disposed = true;
            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>One consumer-owned candidate; local coherence does not promise a remote transaction.</summary>
public sealed class BootstrapCandidate : IDisposable
{
    private readonly SecretSnapshotHandle _generation;
    private readonly string[] _keys;
    private bool _disposed;

    internal BootstrapCandidate(SecretSnapshotHandle generation, string[] keys)
    {
        _generation = generation;
        _keys = keys;
    }

    public SecretRead Read(string controlledKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        string key = _keys.First(key => string.Equals(key, controlledKey, StringComparison.OrdinalIgnoreCase));
        return _generation.Read(key);
    }

    /// <summary>Explicit ordinary-string boundary. Controlled keys override local values only on complete success.</summary>
    public IReadOnlyDictionary<string, string> ExportOver(IReadOnlyDictionary<string, string> localDefaults)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var exported = new Dictionary<string, string>(localDefaults, StringComparer.OrdinalIgnoreCase);
        foreach (string key in _keys)
        {
            using SecretRead read = _generation.Read(key);
            exported[key] = read.Material.Reveal();
        }

        return exported;
    }

    [JsonIgnore]
    public IReadOnlyList<SecretObservation> Observations => _keys.Select(key =>
    {
        using SecretRead read = Read(key);
        return read.Observation;
    }).ToArray();

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            _generation.Dispose();
        }
    }

    public override string ToString() => "[BootstrapCandidate]";
}
