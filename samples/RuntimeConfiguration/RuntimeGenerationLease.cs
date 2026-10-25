namespace SecretKit.Samples.RuntimeConfiguration;

/// <summary>Application-defined work; acceptance and client construction belong to the validator.</summary>
public interface IRuntimeIntegrationClient : IAsyncDisposable
{
    ValueTask<string> ExecuteAsync(CancellationToken cancellationToken = default);
}

/// <summary>Pins a client without exposing its shared disposable instance.</summary>
public sealed class RuntimeGenerationLease : IAsyncDisposable
{
    private readonly object _gate = new();
    private RuntimeClientGeneration? _generation;
    private readonly long _revision;
    private TaskCompletionSource? _disposal;

    internal RuntimeGenerationLease(RuntimeClientGeneration generation)
    {
        _generation = generation;
        _revision = generation.Revision;
    }

    /// <summary>The local accepted revision pinned by this lease, not a remote snapshot version.</summary>
    public long Revision => _revision;

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
        finally { await generation.ReleaseAsync().ConfigureAwait(false); }
    }

    public async ValueTask DisposeAsync()
    {
        RuntimeClientGeneration? generation;
        TaskCompletionSource completion;
        bool ownsRelease;
        lock (_gate)
        {
            ownsRelease = _disposal is null;
            completion = _disposal ??= new(TaskCreationOptions.RunContinuationsAsynchronously);
            generation = _generation;
            _generation = null;
        }
        if (ownsRelease)
        {
            try
            {
                if (generation is not null) await generation.ReleaseAsync().ConfigureAwait(false);
                completion.TrySetResult();
            }
            catch (Exception)
            {
                completion.TrySetException(new InvalidOperationException("Application client retirement failed."));
            }
        }
        await completion.Task.ConfigureAwait(false);
    }
}

internal sealed class RuntimeClientGeneration(
    IRuntimeIntegrationClient client, long revision, DateTimeOffset collectedAt,
    DateTimeOffset deadline, TimeProvider time, Action<RuntimeClientGeneration, bool> retired)
{
    private int _references = 1;
    private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Task Completion => _completion.Task;
    internal IRuntimeIntegrationClient Client { get; } = client;
    internal long Revision { get; } = revision;
    internal DateTimeOffset CollectedAt { get; } = collectedAt;
    internal DateTimeOffset Deadline { get; } = deadline;
    internal TimeProvider Time { get; } = time;
    internal void AddReference() => Interlocked.Increment(ref _references);
    internal ValueTask ReleaseAsync()
    {
        return Interlocked.Decrement(ref _references) == 0 ? CompleteAsync() : ValueTask.CompletedTask;
    }

    private async ValueTask CompleteAsync()
    {
        bool failed = false;
        try { await Client.DisposeAsync().ConfigureAwait(false); }
        catch (Exception) { failed = true; }
        retired(this, failed);
        if (failed)
            _completion.TrySetException(new InvalidOperationException("Application client retirement failed."));
        else
            _completion.TrySetResult();
        await _completion.Task.ConfigureAwait(false);
    }
}
