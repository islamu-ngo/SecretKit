using SecretKit.Core;

namespace SecretKit.Extensions.Configuration;

/// <summary>Pins an application client for operations through a bounded callback lifetime.</summary>
/// <typeparam name="TClient">The independently owned client type.</typeparam>
public sealed class SecretGenerationLease<TClient> : IAsyncDisposable where TClient : class, IAsyncDisposable
{
    private readonly object _gate = new();
    private SecretClientGeneration<TClient>? _generation;
    private readonly long _revision;
    private TaskCompletionSource? _disposal;

    internal SecretGenerationLease(SecretClientGeneration<TClient> generation)
    {
        _generation = generation;
        _revision = generation.Revision;
    }

    /// <summary>The local accepted revision pinned by this lease, not a remote snapshot version.</summary>
    public long Revision => _revision;

    /// <summary>Runs an operation while retaining a pin even if this lease is concurrently disposed.</summary>
    /// <remarks>
    /// The callback borrows the client and must not retain or dispose it. Cancellation and callback
    /// exceptions propagate; client retirement failures expose only bounded diagnostics.
    /// Do not await coordinator disposal inside this callback, which still owns an operation pin.
    /// </remarks>
    public async ValueTask<TResult> ExecuteAsync<TResult>(
        Func<TClient, CancellationToken, ValueTask<TResult>> action, CancellationToken cancellationToken = default)
    {
        // No use event: only defer retirement triggered by the operation pin.
        using var diagnostics = ConfigurationDiagnostics.Defer();
        ArgumentNullException.ThrowIfNull(action);
        SecretClientGeneration<TClient> generation;
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
            return await action(generation.Client, cancellationToken).ConfigureAwait(false);
        }
        finally { await generation.ReleaseAsync().ConfigureAwait(false); }
    }

    /// <summary>Releases this lease once; already running operations retain their own client pins.</summary>
    public async ValueTask DisposeAsync()
    {
        using var diagnostics = ConfigurationDiagnostics.Defer();
        SecretClientGeneration<TClient>? generation;
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

internal sealed class SecretClientGeneration<TClient>(
    TClient client, long revision, DateTimeOffset collectedAt,
    DateTimeOffset deadline, TimeProvider time, Action<SecretClientGeneration<TClient>, bool> retired)
    where TClient : class, IAsyncDisposable
{
    private int _references = 1;
    private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Task Completion => _completion.Task;
    internal TClient Client { get; } = client;
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
        using var diagnostics = ConfigurationDiagnostics.Defer();
        var started = ConfigurationDiagnostics.Capture(Time);
        bool failed = false;
        var termination = ConfigurationTermination.Completed;
        try { await Client.DisposeAsync().ConfigureAwait(false); }
        catch (Exception error)
        {
            failed = true;
            termination = error is OperationCanceledException
                ? ConfigurationTermination.DependencyCanceled : ConfigurationTermination.Faulted;
        }
        retired(this, failed);
        if (failed)
            _completion.TrySetException(new InvalidOperationException("Application client retirement failed."));
        else
            _completion.TrySetResult();
        var interval = ConfigurationDiagnostics.Complete(started, Time);
        try { await _completion.Task.ConfigureAwait(false); }
        finally
        {
            ConfigurationDiagnostics.Emit(ConfigurationOperation.Retirement,
                failed ? SecretStatus.Unknown : SecretStatus.Success, SecretFailureReason.None, termination,
                failed ? ConfigurationState.RetirementFailed : ConfigurationState.Retired, interval);
        }
    }
}
