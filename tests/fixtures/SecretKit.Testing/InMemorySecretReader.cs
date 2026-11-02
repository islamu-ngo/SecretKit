using SecretKit.Core;

namespace SecretKit.Testing;

/// <summary>A test-only reader with explicit authority and independently owned read copies.</summary>
public class InMemorySecretReader : ISecretReader, IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<object, (SecretAddress Address, SecretMaterial Material)> _values = [];
    private readonly TimeProvider _clock;
    private SecretStatus? _failure;
    private bool _disposed;

    public InMemorySecretReader(TimeProvider? clock = null) => _clock = clock ?? TimeProvider.System;

    public SecretAuthority Authority { get; } = new();

    public SecretStatus? Failure
    {
        get { lock (_gate) return _failure; }
        set
        {
            if (value is { } status && (status == SecretStatus.Success || !Enum.IsDefined(status)))
                throw new ArgumentOutOfRangeException(nameof(value));
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                _failure = value;
            }
        }
    }

    public void Set(SecretAddress address, SecretMaterial material)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(material);
        object key = SelectKey(address) ?? throw new ArgumentException("Unsupported address type.", nameof(address));
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            SecretMaterial copy = material.Copy();
            if (_values.Remove(key, out var previous)) previous.Material.Dispose();
            _values.Add(key, (address, copy));
        }
    }

    public bool Remove(SecretAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        object key = SelectKey(address) ?? throw new ArgumentException("Unsupported address type.", nameof(address));
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_values.Remove(key, out var value)) return false;
            value.Material.Dispose();
            return true;
        }
    }

    public ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reference);
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            SecretStatus status = Find(reference, out SecretMaterial? value);
            return ValueTask.FromResult(status == SecretStatus.Success
                ? SecretOutcome<SecretRead>.Success(new(value!.Copy(), Observe(reference)))
                : SecretOutcome<SecretRead>.Failure(status));
        }
    }

    public ValueTask<SecretOutcome<SecretObservation>> InspectAsync(SecretReference reference,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reference);
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            SecretStatus status = Find(reference, out _);
            return ValueTask.FromResult(status == SecretStatus.Success
                ? SecretOutcome<SecretObservation>.Success(Observe(reference))
                : SecretOutcome<SecretObservation>.Failure(status));
        }
    }

    protected virtual object? SelectKey(SecretAddress address) => address;

    protected ValueTask<SecretOutcome<SecretInventory>> InspectCollection(SecretInventoryScope scope,
        Func<SecretAddress, bool> includes, int maximumItems, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!scope.BelongsTo(Authority))
                return ValueTask.FromResult(SecretOutcome<SecretInventory>.Failure(SecretStatus.Invalid));
            if (_failure is { } failure)
                return ValueTask.FromResult(SecretOutcome<SecretInventory>.Failure(failure));
            DateTimeOffset now = _clock.GetUtcNow();
            SecretObservation[] observations = _values.Values.Where(entry => includes(entry.Address))
                .Take(maximumItems + 1).Select(entry => Observe(new(Authority, entry.Address))).ToArray();
            return ValueTask.FromResult(SecretOutcome<SecretInventory>.Success(new(
                observations.Take(maximumItems), now, now, observations.Length <= maximumItems)));
        }
    }

    private SecretStatus Find(SecretReference reference, out SecretMaterial? value)
    {
        value = null;
        if (!reference.BelongsTo(Authority) || SelectKey(reference.Address) is not { } key)
            return SecretStatus.Invalid;
        if (_failure is { } status) return status;
        if (!_values.TryGetValue(key, out var entry)) return SecretStatus.Absent;
        value = entry.Material;
        return SecretStatus.Success;
    }

    private SecretObservation Observe(SecretReference reference) =>
        new(reference, null, _clock.GetUtcNow(), SecretValidity.Valid);

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            foreach (var entry in _values.Values) entry.Material.Dispose();
            _values.Clear();
        }
    }
}
