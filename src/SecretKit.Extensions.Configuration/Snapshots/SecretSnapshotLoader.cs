using SecretKit.Core;

namespace SecretKit.Extensions.Configuration;

/// <summary>
/// Caller-driven bounded asynchronous collection. No worker, refresh, activation or stale-use
/// policy is installed. Readers remain borrowed and must cooperate with cancellation.
/// </summary>
public sealed class SecretSnapshotLoader : IDisposable
{
    private readonly object _gate = new();
    private readonly SemaphoreSlim _collection = new(1, 1);
    private readonly SecretSelection[] _selections;
    private readonly SecretCollectionOptions _options;
    private readonly TimeProvider _time;
    private SecretSnapshotGeneration? _current;
    private SecretCollectionAttempt? _lastAttempt;
    private bool _disposed;
    private long _generation;

    /// <summary>Freezes bounded nonempty selections and unique ordinal consumer keys without I/O.</summary>
    /// <remarks>Timeout begins after serialized admission. Readers are borrowed.</remarks>
    /// <exception cref="ArgumentException">Selections are empty, exceed the limit, or contain duplicate keys.</exception>
    public SecretSnapshotLoader(IEnumerable<SecretSelection> selections, TimeProvider? timeProvider = null,
        SecretCollectionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(selections);
        _options = options ?? new SecretCollectionOptions();
        var entries = new List<SecretSelection>();
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (SecretSelection selection in selections)
        {
            if (entries.Count == _options.MaximumSelections)
                throw new ArgumentException("Selection count exceeds the collection limit.");
            ArgumentNullException.ThrowIfNull(selection);
            if (!keys.Add(selection.ConsumerKey))
                throw new ArgumentException("Consumer keys must be unique.");
            entries.Add(selection);
        }
        if (entries.Count == 0)
            throw new ArgumentException("At least one selection is needed.");
        _selections = entries.ToArray();
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>The latest material-free collection evidence, or null before an attempt is recorded.</summary>
    public SecretCollectionAttempt? LastAttempt
    {
        get { lock (_gate) return _lastAttempt; }
    }

    /// <summary>Pins the latest complete local generation until the returned handle is disposed.</summary>
    /// <exception cref="InvalidOperationException">No successful generation has been published.</exception>
    /// <exception cref="ObjectDisposedException">The loader was disposed.</exception>
    public SecretSnapshotHandle Acquire()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_current is null) throw new InvalidOperationException("No generation has been published.");
            return _current.Acquire();
        }
    }

    /// <summary>Serializes bounded collections and publishes one complete valid generation.</summary>
    /// <remarks>
    /// Reduction and byte accounting follow input order. Started reads always settle; normal
    /// failure does not cancel earlier ordinals. The payload bound is not a process heap bound.
    /// A reader that ignores cancellation cannot be forcibly stopped.
    /// </remarks>
    /// <returns>The new local generation or the earliest input-order failure, with bounded detail.</returns>
    /// <exception cref="OperationCanceledException">The caller canceled collection or its admission wait.</exception>
    /// <exception cref="ObjectDisposedException">The loader was disposed before publication.</exception>
    public ValueTask<SecretOutcome<long>> RefreshAsync(CancellationToken cancellationToken = default) =>
        RefreshObservedAsync(new ConfigurationCollectionObservation(), cancellationToken);

    internal async ValueTask<SecretOutcome<long>> RefreshObservedAsync(ConfigurationCollectionObservation observation,
        CancellationToken cancellationToken)
    {
        using var diagnostics = ConfigurationDiagnostics.Defer();
        var started = ConfigurationDiagnostics.Capture(_time);
        SecretStatus status = SecretStatus.Unknown;
        SecretFailureReason reason = SecretFailureReason.None;
        try
        {
            var result = await RefreshCoreAsync(observation, cancellationToken).ConfigureAwait(false);
            status = result.Status;
            reason = result.Reason;
            return result;
        }
        catch (OperationCanceledException)
        {
            observation.Termination = cancellationToken.IsCancellationRequested
                ? ConfigurationTermination.CallerCanceled : ConfigurationTermination.DependencyCanceled;
            throw;
        }
        catch (Exception)
        {
            observation.Termination = ConfigurationTermination.Faulted;
            throw;
        }
        finally
        {
            // The core has drained delivered/candidate storage and released admission.
            var interval = ConfigurationDiagnostics.Complete(started, _time);
            ConfigurationDiagnostics.Emit(ConfigurationOperation.Collection, status, reason, observation.Termination,
                status == SecretStatus.Success ? ConfigurationState.Published : ConfigurationState.Rejected, interval);
        }
    }

    private async ValueTask<SecretOutcome<long>> RefreshCoreAsync(ConfigurationCollectionObservation observation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _collection.WaitAsync(cancellationToken).ConfigureAwait(false);
        var candidate = new Dictionary<string, SecretRead?>(StringComparer.Ordinal);
        var slots = new Task<(SecretOutcome<SecretRead> Outcome, ConfigurationTermination Termination)>?[_options.MaximumConcurrency];
        DateTimeOffset started = _time.GetUtcNow();
        using var deadline = new CancellationTokenSource(_options.CollectionTimeout, _time);
        using var collection = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        int terminal = 0;
        int admitted = 0;
        int reduced = 0;
        int materialBytes = 0;
        SecretOutcome<long>? failure = null;
        try
        {
            lock (_gate) ObjectDisposedException.ThrowIf(_disposed, this);
            while (admitted < _selections.Length && admitted < slots.Length &&
                   Volatile.Read(ref terminal) == 0 && !collection.IsCancellationRequested)
            {
                slots[admitted] = ReadAsync(_selections[admitted]);
                admitted++;
            }

            while (reduced < admitted)
            {
                int slot = reduced % slots.Length;
                SecretSelection selection = _selections[reduced];
                var delivery = await slots[slot]!.ConfigureAwait(false);
                SecretOutcome<SecretRead> outcome = delivery.Outcome;
                slots[slot] = null;
                reduced++;
                if (!outcome.IsSuccess)
                {
                    if (outcome.Status == SecretStatus.Absent && selection.PresencePolicy == SecretPresencePolicy.Optional)
                    {
                        if (failure is null) candidate.Add(selection.ConsumerKey, null);
                    }
                    else if (failure is null)
                    {
                        failure = SecretOutcome<long>.Failure(outcome.Status, outcome.RetryAfter, outcome.Reason);
                        observation.Termination = delivery.Termination;
                        Interlocked.Exchange(ref terminal, 1);
                    }
                }
                else
                {
                    using SecretRead delivered = outcome.Value;
                    if (failure is null && !collection.IsCancellationRequested)
                    {
                        try
                        {
                            int bytes = delivered.Material.GetUtf8ByteCount();
                            if (bytes > _options.MaximumMaterialBytes - materialBytes)
                            {
                                failure = SecretOutcome<long>.Failure(SecretStatus.Invalid,
                                    reason: SecretFailureReason.CollectionLimitExceeded);
                                Interlocked.Exchange(ref terminal, 1);
                            }
                            else
                            {
                                candidate.Add(selection.ConsumerKey,
                                    new SecretRead(delivered.Material.Copy(), delivered.Observation));
                                materialBytes += bytes;
                            }
                        }
                        catch (Exception error) when (error is ArgumentException or ObjectDisposedException)
                        {
                            failure = SecretOutcome<long>.Failure(SecretStatus.Invalid,
                                reason: SecretFailureReason.InvalidResponse);
                            Interlocked.Exchange(ref terminal, 1);
                        }
                    }
                }

                // Reuse only the slot just reduced. Later completions cannot move the window.
                if (admitted < _selections.Length && Volatile.Read(ref terminal) == 0 &&
                    !collection.IsCancellationRequested)
                {
                    slots[admitted % slots.Length] = ReadAsync(_selections[admitted]);
                    admitted++;
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (deadline.IsCancellationRequested)
                return Fail(SecretStatus.Unavailable, reason: SecretFailureReason.DeadlineExceeded);
            if (failure is not null) return Fail(failure.Status, failure.RetryAfter, failure.Reason);

            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                DateTimeOffset completed = _time.GetUtcNow();
                foreach (SecretSelection selection in _selections)
                {
                    SecretRead? read = candidate[selection.ConsumerKey];
                    if (read is null) continue;
                    if (!ReferenceEquals(read.Observation.Reference, selection.Reference))
                        return Fail(SecretStatus.Invalid, reason: SecretFailureReason.AuthorityMismatch);
                    if (read.Observation.Validity != SecretValidity.Valid)
                        return Fail(read.Observation.Validity == SecretValidity.Expired ?
                            SecretStatus.Expired : SecretStatus.Invalid);
                    if (read.Observation.ExpiresAt is { } expiry && expiry <= completed)
                        return Fail(SecretStatus.Expired);
                }
                cancellationToken.ThrowIfCancellationRequested();
                if (deadline.IsCancellationRequested)
                    return Fail(SecretStatus.Unavailable, reason: SecretFailureReason.DeadlineExceeded);
                var next = new SecretSnapshotGeneration(++_generation, candidate, started, completed);
                SecretSnapshotGeneration? old = _current;
                _current = next;
                candidate = new Dictionary<string, SecretRead?>(StringComparer.Ordinal);
                _lastAttempt = new SecretCollectionAttempt(started, completed, SecretStatus.Success);
                old?.Release();
                return SecretOutcome<long>.Success(_generation);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            lock (_gate)
                _lastAttempt = new SecretCollectionAttempt(started, _time.GetUtcNow(), SecretStatus.Unknown,
                    wasCanceled: true);
            throw;
        }
        finally
        {
            foreach (var slot in slots)
            {
                if (slot is null) continue;
                var delivery = await slot.ConfigureAwait(false);
                SecretOutcome<SecretRead> outcome = delivery.Outcome;
                if (outcome.IsSuccess) outcome.Value.Dispose();
            }
            foreach (SecretRead? read in candidate.Values) read?.Dispose();
            _collection.Release();
        }

        async Task<(SecretOutcome<SecretRead> Outcome, ConfigurationTermination Termination)> ReadAsync(SecretSelection selection)
        {
            SecretOutcome<SecretRead> outcome;
            var termination = ConfigurationTermination.Completed;
            try
            {
                outcome = await selection.Reader.ReadAsync(selection.Reference, collection.Token).ConfigureAwait(false);
                if (outcome is null)
                    outcome = SecretOutcome<SecretRead>.Failure(SecretStatus.Invalid,
                        reason: SecretFailureReason.InvalidResponse);
            }
            catch (Exception error)
            {
                // Caller/deadline precedence is applied after all started work has settled.
                termination = error is OperationCanceledException
                    ? ConfigurationTermination.DependencyCanceled : ConfigurationTermination.Faulted;
                outcome = SecretOutcome<SecretRead>.Failure(SecretStatus.Unavailable,
                    reason: SecretFailureReason.TransportFailure);
            }
            if (outcome.IsSuccess)
            {
                SecretRead read = outcome.Value;
                if (!ReferenceEquals(read.Observation.Reference, selection.Reference))
                {
                    read.Dispose();
                    outcome = SecretOutcome<SecretRead>.Failure(SecretStatus.Invalid,
                        reason: SecretFailureReason.AuthorityMismatch);
                }
                else
                {
                    bool expired = read.Observation.Validity == SecretValidity.Expired ||
                        (read.Observation.Validity == SecretValidity.Valid &&
                            read.Observation.ExpiresAt is { } expiry && expiry <= _time.GetUtcNow());
                    if (read.Observation.Validity != SecretValidity.Valid || expired)
                    {
                        read.Dispose();
                        outcome = SecretOutcome<SecretRead>.Failure(expired ? SecretStatus.Expired : SecretStatus.Invalid);
                    }
                }
            }
            if (!outcome.IsSuccess &&
                !(outcome.Status == SecretStatus.Absent && selection.PresencePolicy == SecretPresencePolicy.Optional))
                Interlocked.Exchange(ref terminal, 1);
            return (outcome, termination);
        }

        SecretOutcome<long> Fail(SecretStatus status, TimeSpan? retryAfter = null,
            SecretFailureReason reason = SecretFailureReason.None)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (deadline.IsCancellationRequested)
            {
                observation.Termination = ConfigurationTermination.DeadlineExceeded;
                status = SecretStatus.Unavailable;
                retryAfter = null;
                reason = SecretFailureReason.DeadlineExceeded;
            }
            lock (_gate)
                _lastAttempt = new SecretCollectionAttempt(started, _time.GetUtcNow(), status, retryAfter, reason: reason);
            return SecretOutcome<long>.Failure(status, retryAfter, reason);
        }
    }

    /// <summary>Prevents publication and releases current storage, without killing borrowed I/O or held handles.</summary>
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

    /// <summary>Returns a bounded description without selected keys, material or coordinates.</summary>
    public override string ToString() => "[SecretSnapshotLoader]";
}
