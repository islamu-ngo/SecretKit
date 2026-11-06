using SecretKit.Core;

namespace SecretKit.Infisical;

// One parent authority per client/definition UUID. Children retain this state; the
// parent never retains children or material. Permits span operations, not monitor locks.
internal sealed class InfisicalDefinitionLifecycle(string name)
{
    internal object Gate { get; } = new();
    private string _currentName = name;
    private int _activeChildPermits;
    private bool _exclusive;
    private InfisicalLeaseLocalState _materialState;

    // Caller holds Gate before consulting this state or a child's lease/material gate.
    internal InfisicalLeaseLocalState MaterialState => _materialState;
    internal bool CanUse => !_exclusive && _materialState == InfisicalLeaseLocalState.Active;

    internal SecretStatus Begin(string? selectedName, bool exclusive, bool cleanup = false)
    {
        lock (Gate)
        {
            if (selectedName is not null && selectedName != _currentName)
                return SecretStatus.Invalid;
            if (_materialState == InfisicalLeaseLocalState.Revoked)
                return SecretStatus.Invalid;
            if (_exclusive || (exclusive && _activeChildPermits != 0))
                return SecretStatus.Conflict;
            if (_materialState == InfisicalLeaseLocalState.EffectUnknown && !cleanup)
                return SecretStatus.Unknown;
            if (exclusive) _exclusive = true;
            else _activeChildPermits++;
            return SecretStatus.Success;
        }
    }

    internal void EndChild()
    {
        lock (Gate) { _activeChildPermits--; }
    }

    internal void EndExclusive(InfisicalDynamicMutationReceipt receipt, string? newName, bool deleted)
    {
        lock (Gate)
        {
            if (receipt.Evidence == DispatchEvidence.PossiblyDispatched)
                _materialState = InfisicalLeaseLocalState.EffectUnknown;
            else if (receipt.Evidence == DispatchEvidence.Applied)
            {
                if (deleted) _materialState = InfisicalLeaseLocalState.Revoked;
                else if (newName is not null) _currentName = newName;
            }
            _exclusive = false;
        }
    }
}
