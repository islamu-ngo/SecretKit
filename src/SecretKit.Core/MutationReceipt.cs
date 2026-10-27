using System.Text.Json.Serialization;

namespace SecretKit.Core;

/// <summary>Local knowledge of a mutation's dispatch and observed effect, not a rollback guarantee.</summary>
public enum DispatchEvidence
{
    /// <summary>The controlled send boundary has not been entered.</summary>
    NotDispatched,
    /// <summary>Dispatch began; a remote effect remains possible even after cancellation or transport loss.</summary>
    PossiblyDispatched,
    /// <summary>The operation's accepted response established an applied effect.</summary>
    Applied,
    /// <summary>The provider reported a pending native step rather than a completed effect.</summary>
    Pending,
    /// <summary>The dispatched operation was authoritatively rejected.</summary>
    Rejected,
    /// <summary>The dispatched operation returned conflict evidence.</summary>
    Conflict
}

/// <summary>Caller-held local evidence. Its identifier is not a provider idempotency or query handle.</summary>
public sealed class MutationReceipt
{
    private readonly object _gate = new();
    private readonly SecretReference _target;
    private DispatchEvidence _evidence;

    /// <summary>Creates undispatched evidence bound to the exact target object; retain it before awaiting a mutation.</summary>
    /// <param name="target">The reference instance this receipt will accompany.</param>
    /// <exception cref="ArgumentNullException"><paramref name="target"/> is null.</exception>
    public MutationReceipt(SecretReference target)
    {
        ArgumentNullException.ThrowIfNull(target);
        _target = target;
    }

    /// <summary>Gets a local correlation identifier, not a remote idempotency key or lookup handle.</summary>
    [JsonIgnore]
    public Guid LocalId { get; } = Guid.NewGuid();

    /// <summary>Gets the current synchronized evidence, which survives failure or cancellation of the operation.</summary>
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
    /// <param name="target">The reference to compare by object identity, not by coordinates.</param>
    /// <returns>True only for the exact reference supplied at construction.</returns>
    public bool IsFor(SecretReference target) => ReferenceEquals(_target, target);

    /// <summary>Called at the last controlled send boundary. Once begun, the receipt cannot be replayed.</summary>
    /// <param name="target">The exact reference instance bound to this receipt.</param>
    /// <remarks>Adapter transition: marks a possible effect before sending, not successful remote application.</remarks>
    /// <exception cref="InvalidOperationException">The target differs or dispatch has already begun.</exception>
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
    /// <param name="evidence">Applied, pending, rejected or conflict evidence obtained by the adapter.</param>
    /// <remarks>Only a possibly dispatched receipt can be settled; application code must not manufacture evidence.</remarks>
    /// <exception cref="ArgumentOutOfRangeException">The supplied evidence is not a known dispatch result.</exception>
    /// <exception cref="InvalidOperationException">The receipt is not in the possibly dispatched state.</exception>
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

    /// <summary>Returns the evidence category without the target or local correlation identifier.</summary>
    public override string ToString() => $"[MutationReceipt:{Evidence}]";
}
