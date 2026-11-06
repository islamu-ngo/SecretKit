using SecretKit.Core;

namespace SecretKit.Infisical;

// Scalar authority shared by aliases and independent material copies. Never owns a material
// wrapper, reference, receipt or callback. The client registry holds only a weak reference.
internal sealed class InfisicalLeaseLifecycle
{
    internal object Gate { get; } = new();
    internal TimeProvider Time { get; }
    internal InfisicalDefinitionLifecycle Parent { get; }
    private readonly DateTimeOffset _createdAt;
    private DateTimeOffset _expiresAt;
    private decimal _version;
    private string? _nativeStatus;
    private InfisicalLeaseLocalState _state;
    private bool _mutation;

    internal InfisicalLeaseLifecycle(InfisicalDefinitionLifecycle parent, TimeProvider time, DateTimeOffset createdAt,
        DateTimeOffset expiresAt, decimal version, string? nativeStatus)
    {
        Time = time;
        Parent = parent;
        _createdAt = createdAt;
        _expiresAt = expiresAt;
        _version = version;
        _nativeStatus = nativeStatus;
        _state = nativeStatus is null ? InfisicalLeaseLocalState.Active : InfisicalLeaseLocalState.EffectUnknown;
    }

    // Caller holds Parent.Gate then Gate. Time is sampled before entering either lock.
    internal InfisicalLeaseLocalState StateAt(DateTimeOffset now)
    {
        if (_state == InfisicalLeaseLocalState.Revoked || Parent.MaterialState == InfisicalLeaseLocalState.Revoked)
            return InfisicalLeaseLocalState.Revoked;
        if (Parent.MaterialState == InfisicalLeaseLocalState.EffectUnknown)
            return InfisicalLeaseLocalState.EffectUnknown;
        return _state == InfisicalLeaseLocalState.Active && now >= _expiresAt
            ? InfisicalLeaseLocalState.Expired : _state;
    }

    internal bool CanUse(DateTimeOffset now) =>
        Parent.CanUse && !_mutation && StateAt(now) == InfisicalLeaseLocalState.Active;

    internal InfisicalLeaseObservation Observation(InfisicalLeaseReference reference)
    {
        lock (Gate) { return new(reference, _createdAt, _expiresAt, _version, _nativeStatus); }
    }

    internal void ObserveRead(InfisicalLeaseObservation observation)
    {
        lock (Gate)
        {
            if (_state == InfisicalLeaseLocalState.Revoked) return;
            if (observation.CreatedAt != _createdAt || observation.NativeStatus is not null)
                _state = InfisicalLeaseLocalState.EffectUnknown;
            _version = Math.Max(_version, observation.Version);
            // Reads can tighten the mutation baseline, but never extend usability or clear uncertainty.
        }
    }

    internal SecretStatus BeginMutation(bool renewal, DateTimeOffset now,
        out (DateTimeOffset CreatedAt, decimal Version) baseline)
    {
        lock (Parent.Gate)
            lock (Gate)
            {
                baseline = (_createdAt, _version);
                if (_mutation || _state == InfisicalLeaseLocalState.Revoked)
                    return SecretStatus.Conflict;
                if (renewal)
                {
                    InfisicalLeaseLocalState state = StateAt(now);
                    if (state == InfisicalLeaseLocalState.Expired) return SecretStatus.Expired;
                    if (state != InfisicalLeaseLocalState.Active) return SecretStatus.Conflict;
                }
                _mutation = true;
                return SecretStatus.Success;
            }
    }

    internal bool ApplyRenewal(InfisicalLeaseObservation observation,
        (DateTimeOffset CreatedAt, decimal Version) baseline, InfisicalDynamicMutationReceipt receipt)
    {
        lock (Gate)
        {
            if (observation.CreatedAt != baseline.CreatedAt ||
                observation.Version < Math.Max(baseline.Version, _version))
                return false;
            _expiresAt = observation.ExpiresAt;
            _version = observation.Version;
            _nativeStatus = observation.NativeStatus;
            if (_nativeStatus is not null) _state = InfisicalLeaseLocalState.EffectUnknown;
            receipt.Record(DispatchEvidence.Applied);
            return true;
        }
    }

    internal void FinishMutation(InfisicalDynamicMutationReceipt receipt, bool revoked)
    {
        lock (Gate)
        {
            if (receipt.Evidence == DispatchEvidence.PossiblyDispatched)
                _state = InfisicalLeaseLocalState.EffectUnknown;
            else if (revoked && receipt.Evidence == DispatchEvidence.Applied)
                _state = InfisicalLeaseLocalState.Revoked;
            _mutation = false;
        }
    }
}
