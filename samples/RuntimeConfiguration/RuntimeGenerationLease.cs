namespace SecretKit.Samples.RuntimeConfiguration;

/// <summary>Application-defined work; acceptance and client construction belong to the validator.</summary>
public interface IRuntimeIntegrationClient : IDisposable
{
    ValueTask<string> ExecuteAsync(CancellationToken cancellationToken = default);
}

/// <summary>Pins a client without exposing its shared disposable instance.</summary>
public sealed class RuntimeGenerationLease : IDisposable
{
    private readonly object _gate = new();
    private RuntimeClientGeneration? _generation;

    internal RuntimeGenerationLease(RuntimeClientGeneration generation) => _generation = generation;

    public async ValueTask<string> ExecuteAsync(CancellationToken cancellationToken = default)
    {
        RuntimeClientGeneration generation;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_generation is null, this);
            generation = _generation;
            generation.AddReference();
        }
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (generation.Time.GetUtcNow() >= generation.Deadline)
                throw new InvalidOperationException("The consumer generation deadline has elapsed.");
            return await generation.Client.ExecuteAsync(cancellationToken).ConfigureAwait(false);
        }
        finally { generation.Release(); }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _generation?.Release();
            _generation = null;
        }
    }
}

internal sealed class RuntimeClientGeneration(
    IRuntimeIntegrationClient client, long revision, DateTimeOffset collectedAt,
    DateTimeOffset deadline, TimeProvider time)
{
    private int _references = 1;
    internal IRuntimeIntegrationClient Client { get; } = client;
    internal long Revision { get; } = revision;
    internal DateTimeOffset CollectedAt { get; } = collectedAt;
    internal DateTimeOffset Deadline { get; } = deadline;
    internal TimeProvider Time { get; } = time;
    internal void AddReference() => Interlocked.Increment(ref _references);
    internal void Release()
    {
        if (Interlocked.Decrement(ref _references) == 0) Client.Dispose();
    }
}
