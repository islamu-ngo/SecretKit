using SecretKit.Core;
using SecretKit.Extensions.Configuration;

namespace SecretKit.Samples.RuntimeConfiguration;

public enum RuntimeStalePolicy { FailClosed, BoundedLastKnown }
public enum RuntimeFreshness { None, Fresh, Stale, DeadlineElapsed }

/// <summary>Local consumer evidence only; neither saved provider state nor fleet readiness.</summary>
public sealed record RuntimeActivationObservation(
    long DesiredRevision, long ObservedRevision, bool DesiredEnabled, bool Active,
    SecretStatus LastStatus, RuntimeFreshness Freshness, DateTimeOffset? CollectedAt,
    DateTimeOffset? UsableUntil);

/// <summary>
/// Caller-driven consumer policy. Use an intended, uncached runtime reader; readers remain host-owned.
/// Every Check again/Enable creates a fresh loader collection; only Enable activates a client.
/// The app validator owns acceptance,
/// constructs a new independent client, and must not retain the borrowed candidate handle.
/// </summary>
public sealed class RuntimeIntegrationCoordinator : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly SecretSelection[] _selections;
    private readonly Func<SecretSnapshotHandle, CancellationToken,
        ValueTask<SecretOutcome<IRuntimeIntegrationClient>>> _validate;
    private readonly TimeProvider _time;
    private readonly TimeSpan _maxAge;
    private readonly RuntimeStalePolicy _policy;
    private RuntimeClientGeneration? _current;
    private long _desiredRevision;
    private long _observedRevision;
    private bool _enabled;
    private bool _disposed;
    private bool _retirementFailed;
    private readonly HashSet<RuntimeClientGeneration> _generations = [];
    private readonly HashSet<Task> _collections = [];
    private TaskCompletionSource? _disposal;
    private SecretStatus _lastStatus = SecretStatus.Absent;

    public RuntimeIntegrationCoordinator(ISecretReader intendedReader,
        IReadOnlyDictionary<string, SecretReference> requiredKeys,
        Func<SecretSnapshotHandle, CancellationToken,
            ValueTask<SecretOutcome<IRuntimeIntegrationClient>>> validate,
        RuntimeStalePolicy stalePolicy, TimeSpan maximumAge, TimeProvider clock)
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

    public ValueTask<RuntimeActivationObservation> EnableAsync(CancellationToken cancellationToken = default) =>
        CollectAsync(enable: true, cancellationToken);

    public ValueTask<RuntimeActivationObservation> CheckAgainAsync(CancellationToken cancellationToken = default) =>
        CollectAsync(enable: false, cancellationToken);

    public async ValueTask<RuntimeActivationObservation> DisableAsync()
    {
        RuntimeClientGeneration? retired;
        RuntimeActivationObservation observation;
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

    public RuntimeActivationObservation Observe()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return ObserveLocked();
        }
    }

    public RuntimeGenerationLease? Acquire()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!ObserveLocked().Active) return null;
            _current!.AddReference();
            return new RuntimeGenerationLease(_current);
        }
    }

    private async ValueTask<RuntimeActivationObservation> CollectAsync(bool enable, CancellationToken cancellationToken)
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
        IRuntimeIntegrationClient? client = null;
        RuntimeClientGeneration? retired = null;
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
                SecretOutcome<IRuntimeIntegrationClient> validation =
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
                        RuntimeClientGeneration? previous = _current;
                        _current = new RuntimeClientGeneration(client!, revision, collected, deadline, _time,
                            ObserveRetirement);
                        _generations.Add(_current);
                        client = null;
                        _observedRevision = revision;
                        retired = previous;
                    }
                    else if (status != SecretStatus.Success && _policy == RuntimeStalePolicy.FailClosed) retired = Detach();
                }
            }
            RuntimeClientGeneration? release = retired;
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
                    if (_policy == RuntimeStalePolicy.FailClosed) retired = Detach();
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
                    if (_policy == RuntimeStalePolicy.FailClosed) retired = Detach();
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

    private RuntimeActivationObservation ObserveLocked()
    {
        RuntimeFreshness freshness = _current is null ? RuntimeFreshness.None :
            _time.GetUtcNow() >= _current.Deadline ? RuntimeFreshness.DeadlineElapsed :
            _lastStatus == SecretStatus.Success ? RuntimeFreshness.Fresh : RuntimeFreshness.Stale;
        return new(_desiredRevision, _observedRevision, _enabled,
            _enabled && !_retirementFailed && _current is not null && freshness != RuntimeFreshness.DeadlineElapsed,
            _lastStatus, freshness, _current?.CollectedAt, _current?.Deadline);
    }

    private RuntimeClientGeneration? Detach()
    {
        RuntimeClientGeneration? previous = _current;
        _current = null;
        return previous;
    }

    private void ObserveRetirement(RuntimeClientGeneration generation, bool failed)
    {
        lock (_gate)
        {
            _generations.Remove(generation);
            if (failed) { _retirementFailed = true; _lastStatus = SecretStatus.Unknown; }
        }
    }

    public async ValueTask DisposeAsync()
    {
        TaskCompletionSource completion;
        Task[] pending;
        RuntimeClientGeneration? retired = null;
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
