using SecretKit.Core;

namespace SecretKit.Extensions.Configuration;

/// <summary>
/// Caller-driven, asynchronous all-required collection. No TTL, worker, automatic refresh,
/// activation or stale-use policy is installed. Supplied readers remain caller-owned.
/// </summary>
public sealed class SecretSnapshotLoader : IDisposable
{
    private readonly object _gate = new();
    private readonly SemaphoreSlim _collection = new(1, 1);
    private readonly SecretSelection[] _selections;
    private readonly TimeProvider _time;
    private SecretSnapshotGeneration? _current;
    private SecretCollectionAttempt? _lastAttempt;
    private bool _disposed;
    private long _generation;

    public SecretSnapshotLoader(IEnumerable<SecretSelection> selections, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(selections);
        _selections = selections.ToArray();
        if (_selections.Length == 0)
            throw new ArgumentException("At least one required selection is needed.");
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (SecretSelection selection in _selections)
        {
            ArgumentNullException.ThrowIfNull(selection);
            if (!keys.Add(selection.ConsumerKey))
                throw new ArgumentException("Consumer keys must be unique.");
        }
        _time = timeProvider ?? TimeProvider.System;
    }

    public SecretCollectionAttempt? LastAttempt
    {
        get { lock (_gate) return _lastAttempt; }
    }

    public SecretSnapshotHandle Acquire()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_current is null) throw new InvalidOperationException("No generation has been published.");
            return _current.Acquire();
        }
    }

    /// <summary>
    /// Serializes collections; publishes once only after every required read succeeds with
    /// proven consumption validity. Failures preserve the old generation; cancellation propagates.
    /// </summary>
    public async ValueTask<SecretOutcome<long>> RefreshAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _collection.WaitAsync(cancellationToken).ConfigureAwait(false);
        var candidate = new Dictionary<string, SecretRead>(StringComparer.Ordinal);
        DateTimeOffset started = _time.GetUtcNow();
        try
        {
            lock (_gate) ObjectDisposedException.ThrowIf(_disposed, this);
            foreach (SecretSelection selection in _selections)
            {
                cancellationToken.ThrowIfCancellationRequested();
                SecretOutcome<SecretRead> outcome;
                try
                {
                    outcome = await selection.Reader.ReadAsync(selection.Reference, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception)
                {
                    // No provider exception or payload escapes the adapter boundary.
                    return Fail(SecretStatus.Unavailable);
                }
                if (!outcome.IsSuccess) return Fail(outcome.Status, outcome.RetryAfter);
                using SecretRead delivered = outcome.Value;
                cancellationToken.ThrowIfCancellationRequested();
                SecretValidity validity = delivered.Observation.Validity;
                if (validity != SecretValidity.Valid)
                    return Fail(validity == SecretValidity.Expired ? SecretStatus.Expired : SecretStatus.Invalid);
                if (!delivered.Observation.Reference.BelongsTo(selection.Reader.Authority))
                    return Fail(SecretStatus.Invalid);
                candidate.Add(selection.ConsumerKey,
                    new SecretRead(delivered.Material.Copy(), delivered.Observation));
            }

            DateTimeOffset completed = _time.GetUtcNow();
            if (candidate.Values.Any(read => read.Observation.ExpiresAt is { } expiry && expiry <= completed))
                return Fail(SecretStatus.Expired);
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                cancellationToken.ThrowIfCancellationRequested();
                var next = new SecretSnapshotGeneration(++_generation, candidate, started, completed);
                SecretSnapshotGeneration? old = _current;
                _current = next;
                candidate = new Dictionary<string, SecretRead>(StringComparer.Ordinal);
                _lastAttempt = new SecretCollectionAttempt(started, completed, SecretStatus.Success);
                old?.Release();
                return SecretOutcome<long>.Success(_generation);
            }
        }
        catch (OperationCanceledException)
        {
            lock (_gate)
                _lastAttempt = new SecretCollectionAttempt(started, _time.GetUtcNow(), SecretStatus.Unknown,
                    wasCanceled: true);
            throw;
        }
        finally
        {
            foreach (SecretRead read in candidate.Values) read.Dispose();
            _collection.Release();
        }

        SecretOutcome<long> Fail(SecretStatus status, TimeSpan? retryAfter = null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
                _lastAttempt = new SecretCollectionAttempt(started, _time.GetUtcNow(), status, retryAfter);
            return SecretOutcome<long>.Failure(status, retryAfter);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _current?.Release();
            _current = null;
        }
    }

    public override string ToString() => "[SecretSnapshotLoader]";
}
