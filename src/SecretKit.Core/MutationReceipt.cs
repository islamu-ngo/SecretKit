using System.Text.Json.Serialization;

namespace SecretKit.Core;

public enum DispatchEvidence
{
    NotDispatched,
    PossiblyDispatched,
    Applied,
    Pending,
    Rejected,
    Conflict
}

/// <summary>Caller-held local evidence. Its identifier is not a provider idempotency or query handle.</summary>
public sealed class MutationReceipt
{
    private readonly object _gate = new();
    private readonly SecretReference _target;
    private DispatchEvidence _evidence;

    public MutationReceipt(SecretReference target)
    {
        ArgumentNullException.ThrowIfNull(target);
        _target = target;
    }

    [JsonIgnore]
    public Guid LocalId { get; } = Guid.NewGuid();

    public DispatchEvidence Evidence
    {
        get
        {
            lock (_gate)
            {
                return _evidence;
            }
        }
    }

    /// <summary>Provider adapters validate before dispatch; receipts cannot be reassigned to another target.</summary>
    public bool IsFor(SecretReference target) => ReferenceEquals(_target, target);

    /// <summary>Called at the last controlled send boundary. Once begun, the receipt cannot be replayed.</summary>
    public void BeginDispatch(SecretReference target)
    {
        lock (_gate)
        {
            if (!IsFor(target) || _evidence != DispatchEvidence.NotDispatched)
            {
                throw new InvalidOperationException("Receipt is not available for this dispatch.");
            }

            _evidence = DispatchEvidence.PossiblyDispatched;
        }
    }

    /// <summary>Records authoritative operation evidence; uncertainty is preserved until known.</summary>
    public void Record(DispatchEvidence evidence)
    {
        if (evidence is not (DispatchEvidence.Applied or DispatchEvidence.Pending or
            DispatchEvidence.Rejected or DispatchEvidence.Conflict))
        {
            throw new ArgumentOutOfRangeException(nameof(evidence));
        }

        lock (_gate)
        {
            if (_evidence != DispatchEvidence.PossiblyDispatched)
            {
                throw new InvalidOperationException("No uncertain dispatched operation can be updated.");
            }

            _evidence = evidence;
        }
    }

    public override string ToString() => $"[MutationReceipt:{Evidence}]";
}
