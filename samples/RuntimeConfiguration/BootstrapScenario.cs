using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Samples.RuntimeConfiguration;

/// <summary>Consumer policy: collect all required controlled values before constructing dependencies.</summary>
public static class BootstrapScenario
{
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

        var reads = new Dictionary<string, SecretRead>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach ((string key, SecretReference reference) in bindings)
            {
                cancellationToken.ThrowIfCancellationRequested();
                SecretOutcome<SecretRead> outcome = await selected.ReadAsync(reference, cancellationToken);
                if (!outcome.IsSuccess)
                {
                    return SecretOutcome<BootstrapCandidate>.Failure(outcome.Status, outcome.RetryAfter);
                }

                reads.Add(key, outcome.Value);
            }

            cancellationToken.ThrowIfCancellationRequested();
            var candidate = new BootstrapCandidate(reads);
            reads = new(StringComparer.OrdinalIgnoreCase);
            return SecretOutcome<BootstrapCandidate>.Success(candidate);
        }
        finally
        {
            foreach (SecretRead read in reads.Values)
            {
                read.Dispose();
            }
        }
    }
}

/// <summary>One consumer-owned candidate; local coherence does not promise a remote transaction.</summary>
public sealed class BootstrapCandidate : IDisposable
{
    private readonly Dictionary<string, SecretRead> _reads;
    private bool _disposed;

    internal BootstrapCandidate(Dictionary<string, SecretRead> reads) => _reads = reads;

    public SecretRead Read(string controlledKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SecretRead stored = _reads[controlledKey];
        return new SecretRead(stored.Material.Copy(), stored.Observation);
    }

    /// <summary>Explicit ordinary-string boundary. Controlled keys override local values only on complete success.</summary>
    public IReadOnlyDictionary<string, string> ExportOver(IReadOnlyDictionary<string, string> localDefaults)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var exported = new Dictionary<string, string>(localDefaults, StringComparer.OrdinalIgnoreCase);
        foreach ((string key, SecretRead read) in _reads)
        {
            exported[key] = read.Material.Reveal();
        }

        return exported;
    }

    [JsonIgnore]
    public IReadOnlyList<SecretObservation> Observations => _reads.Values.Select(read => read.Observation).ToArray();

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            foreach (SecretRead read in _reads.Values)
            {
                read.Dispose();
            }
        }
    }

    public override string ToString() => "[BootstrapCandidate]";
}
