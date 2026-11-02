using SecretKit.Core;

namespace SecretKit.Extensions.Configuration;

/// <summary>Determines whether a failed collection immediately removes the active client.</summary>
public enum SecretGenerationStalePolicy
{
    /// <summary>Remove the active client when collection or validation fails.</summary>
    FailClosed,
    /// <summary>Retain the last accepted client only until its original deadline.</summary>
    BoundedLastKnown
}

/// <summary>Local freshness of the accepted client generation.</summary>
public enum SecretGenerationFreshness
{
    /// <summary>No client generation is active.</summary>
    None,
    /// <summary>The last collection succeeded and the deadline has not elapsed.</summary>
    Fresh,
    /// <summary>The last collection failed but the original deadline has not elapsed.</summary>
    Stale,
    /// <summary>The accepted generation can no longer be used.</summary>
    DeadlineElapsed
}

/// <summary>Local consumer evidence only; neither saved provider state nor fleet readiness.</summary>
public sealed record SecretGenerationObservation(
    long DesiredRevision, long ObservedRevision, bool DesiredEnabled, bool Active,
    SecretStatus LastStatus, SecretGenerationFreshness Freshness, DateTimeOffset? CollectedAt,
    DateTimeOffset? UsableUntil);

/// <summary>
/// Caller-driven consumer policy. Use an intended, uncached runtime reader; readers remain host-owned.
/// Every Check again/Enable creates a fresh loader collection; only Enable activates a client.
/// The app validator owns acceptance,
/// constructs a new independent client, and must not retain the borrowed candidate handle.
/// </summary>
/// <typeparam name="TClient">An independently owned application client.</typeparam>
/// <remarks>
/// Successful validation transfers client ownership to the coordinator. Never return a shared client.
/// Dispose leases before disposing this owner; owner disposal waits for all leases and operations.
/// Validators and client disposers must not await disposal of this coordinator from within a callback.
/// Activation and configuration export are separate operations, not one joint transaction.
/// </remarks>
public sealed class SecretGenerationCoordinator<TClient> : IAsyncDisposable where TClient : class, IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly SecretSelection[] _selections;
    private readonly Func<SecretSnapshotHandle, CancellationToken,
        ValueTask<SecretOutcome<TClient>>> _validate;
    private readonly TimeProvider _time;
    private readonly TimeSpan _maxAge;
    private readonly SecretGenerationStalePolicy _policy;
    private SecretClientGeneration<TClient>? _current;
    private long _desiredRevision;
    private long _observedRevision;
    private bool _enabled;
    private bool _disposed;
    private bool _retirementFailed;
    private readonly HashSet<SecretClientGeneration<TClient>> _generations = [];
    private readonly HashSet<Task> _collections = [];
    private TaskCompletionSource? _disposal;
    private SecretStatus _lastStatus = SecretStatus.Absent;

    /// <summary>Creates caller-driven collection and activation policy without performing reader I/O.</summary>
    /// <param name="intendedReader">The explicitly selected, borrowed reader.</param>
    /// <param name="requiredKeys">Nonempty required consumer keys and their authority-bound references.</param>
    /// <param name="validate">Validates a borrowed snapshot and returns a newly owned client.</param>
    /// <param name="stalePolicy">Treatment of the accepted generation when a new attempt fails.</param>
    /// <param name="maximumAge">Positive maximum lifetime, bounded further by secret expiry.</param>
    /// <param name="clock">Clock used for collection and operation admission.</param>
    public SecretGenerationCoordinator(ISecretReader intendedReader,
        IReadOnlyDictionary<string, SecretReference> requiredKeys,
        Func<SecretSnapshotHandle, CancellationToken,
            ValueTask<SecretOutcome<TClient>>> validate,
        SecretGenerationStalePolicy stalePolicy, TimeSpan maximumAge, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(intendedReader);
        ArgumentNullException.ThrowIfNull(requiredKeys);
        ArgumentNullException.ThrowIfNull(validate);
        ArgumentNullException.ThrowIfNull(clock);
        if (maximumAge <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(maximumAge));
        if (!Enum.IsDefined(stalePolicy)) throw new ArgumentOutOfRangeException(nameof(stalePolicy));
        _selections = requiredKeys.Select(pair =>
            new SecretSelection(pair.Key, intendedReader, pair.Value)).ToArray();
        // Validate the complete mapping before any read or application construction.
        using var mappingCheck = new SecretSnapshotLoader(_selections, clock);
        _validate = validate;
        _policy = stalePolicy;
        _maxAge = maximumAge;
        _time = clock;
    }

    /// <summary>Collects and validates fresh material, then activates only the latest requested revision.</summary>
    public ValueTask<SecretGenerationObservation> EnableAsync(CancellationToken cancellationToken = default) =>
        CollectAsync(enable: true, cancellationToken);

    /// <summary>Collects and validates fresh material without activating the candidate client.</summary>
    public ValueTask<SecretGenerationObservation> CheckAgainAsync(CancellationToken cancellationToken = default) =>
        CollectAsync(enable: false, cancellationToken);

    /// <summary>Stops new acquisition and retires the current client after existing pins are released.</summary>
    public async ValueTask<SecretGenerationObservation> DisableAsync()
    {
        SecretClientGeneration<TClient>? retired;
        SecretGenerationObservation observation;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _enabled = false;
            _observedRevision = ++_desiredRevision;
            retired = Detach();
            observation = ObserveLocked();
        }
        // Reserve the state before yielding; replica callers may hold their revision gate.
        await Task.Yield();
        if (retired is not null) await retired.ReleaseAsync().ConfigureAwait(false);
        return observation;
    }

    /// <summary>Returns material-free evidence for this local owner without performing reader I/O.</summary>
    public SecretGenerationObservation Observe()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return ObserveLocked();
        }
    }

    /// <summary>Pins the current usable client or returns null when local policy rejects acquisition.</summary>
    public SecretGenerationLease<TClient>? Acquire()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!ObserveLocked().Active) return null;
            _current!.AddReference();
            return new SecretGenerationLease<TClient>(_current);
        }
    }

    private async ValueTask<SecretGenerationObservation> CollectAsync(bool enable, CancellationToken cancellationToken)
    {
        long revision;
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            cancellationToken.ThrowIfCancellationRequested();
            if (enable) _enabled = true;
            revision = ++_desiredRevision;
            _collections.Add(finished.Task);
        }
        // Application readers/validators/disposers must not run under a caller's revision gate.
        await Task.Yield();
        TClient? client = null;
        SecretClientGeneration<TClient>? retired = null;
        SecretStatus status = SecretStatus.Unknown;
        DateTimeOffset collected = default;
        DateTimeOffset deadline = default;
        try
        {
            lock (_gate)
                if (_disposed || revision != _desiredRevision) return ObserveLocked();
            using var loader = new SecretSnapshotLoader(_selections, _time);
            SecretOutcome<long> collection = await loader.RefreshAsync(cancellationToken).ConfigureAwait(false);
            status = collection.Status;
            if (collection.IsSuccess)
            {
                using SecretSnapshotHandle candidate = loader.Acquire();
                collected = candidate.CollectionStartedAt;
                deadline = collected + _maxAge;
                foreach (SecretSelection selection in _selections)
                {
                    using SecretRead read = candidate.Read(selection.ConsumerKey);
                    if (read.Observation.ExpiresAt is { } expiry && expiry < deadline) deadline = expiry;
                }
                SecretOutcome<TClient> validation =
                    await _validate(candidate, cancellationToken).ConfigureAwait(false);
                status = validation.Status;
                if (validation.IsSuccess) client = validation.Value;
                cancellationToken.ThrowIfCancellationRequested();
                if (_time.GetUtcNow() >= deadline) status = SecretStatus.Expired;
            }
            lock (_gate)
            {
                if (!_disposed && revision == _desiredRevision)
                {
                    _lastStatus = status;
                    if (status == SecretStatus.Success && enable && _enabled)
                    {
                        SecretClientGeneration<TClient>? previous = _current;
                        _current = new SecretClientGeneration<TClient>(client!, revision, collected, deadline, _time,
                            ObserveRetirement);
                        _generations.Add(_current);
                        client = null;
                        _observedRevision = revision;
                        retired = previous;
                    }
                    else if (status != SecretStatus.Success && _policy == SecretGenerationStalePolicy.FailClosed) retired = Detach();
                }
            }
            SecretClientGeneration<TClient>? release = retired;
            retired = null;
            if (release is not null) await release.ReleaseAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (_gate)
            {
                if (!_disposed && revision == _desiredRevision)
                {
                    _lastStatus = SecretStatus.Unknown;
                    if (_policy == SecretGenerationStalePolicy.FailClosed) retired = Detach();
                }
            }
            if (retired is not null) await retired.ReleaseAsync().ConfigureAwait(false);
            throw;
        }
        catch (Exception)
        {
            lock (_gate)
            {
                if (!_disposed && revision == _desiredRevision)
                {
                    _lastStatus = SecretStatus.Unknown;
                    if (_policy == SecretGenerationStalePolicy.FailClosed) retired = Detach();
                }
            }
            if (retired is not null) await retired.ReleaseAsync().ConfigureAwait(false);
        }
        finally
        {
            try
            {
                if (client is not null) await client.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
                lock (_gate) { _retirementFailed = true; _lastStatus = SecretStatus.Unknown; }
            }
            finally
            {
                lock (_gate) _collections.Remove(finished.Task);
                finished.TrySetResult();
            }
        }
        // Rejected-candidate cleanup can change health; do not return a pre-cleanup snapshot.
        lock (_gate) return ObserveLocked();
    }

    private SecretGenerationObservation ObserveLocked()
    {
        SecretGenerationFreshness freshness = _current is null ? SecretGenerationFreshness.None :
            _time.GetUtcNow() >= _current.Deadline ? SecretGenerationFreshness.DeadlineElapsed :
            _lastStatus == SecretStatus.Success ? SecretGenerationFreshness.Fresh : SecretGenerationFreshness.Stale;
        return new(_desiredRevision, _observedRevision, _enabled,
            _enabled && !_retirementFailed && _current is not null && freshness != SecretGenerationFreshness.DeadlineElapsed,
            _lastStatus, freshness, _current?.CollectedAt, _current?.Deadline);
    }

    private SecretClientGeneration<TClient>? Detach()
    {
        SecretClientGeneration<TClient>? previous = _current;
        _current = null;
        return previous;
    }

    private void ObserveRetirement(SecretClientGeneration<TClient> generation, bool failed)
    {
        lock (_gate)
        {
            _generations.Remove(generation);
            if (failed) { _retirementFailed = true; _lastStatus = SecretStatus.Unknown; }
        }
    }

    /// <summary>Rejects new work and waits for collections, leases, and client retirement to complete.</summary>
    /// <exception cref="InvalidOperationException">A client could not be retired; details are suppressed.</exception>
    public async ValueTask DisposeAsync()
    {
        TaskCompletionSource completion;
        Task[] pending;
        SecretClientGeneration<TClient>? retired = null;
        bool ownsDisposal;
        lock (_gate)
        {
            ownsDisposal = _disposal is null;
            completion = _disposal ??= new(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!ownsDisposal) pending = [];
            else
            {
                _disposed = true;
                _enabled = false;
                ++_desiredRevision;
                retired = Detach();
                pending = _collections.Concat(_generations.Select(generation => generation.Completion)).ToArray();
            }
        }
        if (ownsDisposal)
        {
            await Task.Yield();
            try
            {
                Task release = retired?.ReleaseAsync().AsTask() ?? Task.CompletedTask;
                await Task.WhenAll(pending.Append(release)).ConfigureAwait(false);
                lock (_gate)
                {
                    if (_retirementFailed)
                        throw new InvalidOperationException("Application client retirement failed.");
                }
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
