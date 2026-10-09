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
/// Every Check again/Enable creates a fresh loader collection. The app validator owns acceptance,
/// constructs a new independent client, and must not retain the borrowed candidate handle.
/// </summary>
public sealed class RuntimeIntegrationCoordinator : IDisposable
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

    public RuntimeActivationObservation Disable()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _enabled = false;
            _observedRevision = ++_desiredRevision;
            Retire();
            return ObserveLocked();
        }
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
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            cancellationToken.ThrowIfCancellationRequested();
            if (enable) _enabled = true;
            revision = ++_desiredRevision;
        }
        IRuntimeIntegrationClient? client = null;
        SecretStatus status = SecretStatus.Unknown;
        DateTimeOffset collected = default;
        DateTimeOffset deadline = default;
        try
        {
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
                if (_disposed || revision != _desiredRevision)
                    return ObserveLocked();
                _lastStatus = status;
                if (status == SecretStatus.Success && _enabled)
                {
                    RuntimeClientGeneration? previous = _current;
                    _current = new RuntimeClientGeneration(client!, revision, collected, deadline, _time);
                    client = null;
                    _observedRevision = revision;
                    previous?.Release();
                }
                else if (_policy == RuntimeStalePolicy.FailClosed) Retire();
                return ObserveLocked();
            }
        }
        catch (OperationCanceledException)
        {
            lock (_gate)
            {
                if (!_disposed && revision == _desiredRevision)
                {
                    _lastStatus = SecretStatus.Unknown;
                    if (_policy == RuntimeStalePolicy.FailClosed) Retire();
                }
            }
            throw;
        }
        catch (Exception)
        {
            lock (_gate)
            {
                if (!_disposed && revision == _desiredRevision)
                {
                    _lastStatus = SecretStatus.Unknown;
                    if (_policy == RuntimeStalePolicy.FailClosed) Retire();
                }
                return ObserveLocked();
            }
        }
        finally { client?.Dispose(); }
    }

    private RuntimeActivationObservation ObserveLocked()
    {
        RuntimeFreshness freshness = _current is null ? RuntimeFreshness.None :
            _time.GetUtcNow() >= _current.Deadline ? RuntimeFreshness.DeadlineElapsed :
            _lastStatus == SecretStatus.Success ? RuntimeFreshness.Fresh : RuntimeFreshness.Stale;
        return new(_desiredRevision, _observedRevision, _enabled,
            _enabled && _current is not null && freshness != RuntimeFreshness.DeadlineElapsed,
            _lastStatus, freshness, _current?.CollectedAt, _current?.Deadline);
    }

    private void Retire()
    {
        RuntimeClientGeneration? previous = _current;
        _current = null;
        previous?.Release();
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _enabled = false;
            ++_desiredRevision;
            Retire();
        }
    }
}
