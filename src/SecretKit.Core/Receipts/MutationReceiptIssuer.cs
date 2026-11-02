namespace SecretKit.Core;

/// <summary>Owns the capability to issue and update an adapter's local mutation evidence.</summary>
/// <remarks>Keep each adapter's instance private. Creating another issuer grants no access to
/// its receipts or provider permissions. This is not a sandbox against hostile host-process code.</remarks>
public sealed class MutationReceiptIssuer
{
    private readonly object _identity = new();

    /// <summary>Creates undispatched evidence for an exact reference, to retain before awaiting a mutation.</summary>
    /// <param name="target">The reference instance the adapter has validated.</param>
    /// <returns>Read-only local evidence owned by this issuer.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="target"/> is null.</exception>
    public MutationReceipt Create(SecretReference target) => new(_identity, target);

    /// <summary>Checks issuer identity without granting permission or changing evidence.</summary>
    /// <param name="receipt">The caller-held evidence to check.</param>
    /// <returns>True only if this issuer created the receipt.</returns>
    public bool Owns(MutationReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        return receipt.IsIssuedBy(_identity);
    }

    /// <summary>Atomically consumes owned evidence at the last controlled send boundary.</summary>
    /// <param name="receipt">The receipt issued by this instance.</param>
    /// <param name="target">The exact reference instance selected when issuing the receipt.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="InvalidOperationException">Issuer or target differs, or dispatch has begun.</exception>
    public void BeginDispatch(MutationReceipt receipt, SecretReference target)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(target);
        receipt.BeginDispatch(_identity, target);
    }

    /// <summary>Settles owned, possibly dispatched evidence using an authoritative observed response.</summary>
    /// <param name="receipt">The receipt issued by this instance.</param>
    /// <param name="evidence">Applied, pending, rejected or conflict evidence.</param>
    /// <exception cref="ArgumentNullException"><paramref name="receipt"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The result is not a known dispatch result.</exception>
    /// <exception cref="InvalidOperationException">Issuer differs or evidence cannot be settled.</exception>
    public void Record(MutationReceipt receipt, DispatchEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        receipt.Record(_identity, evidence);
    }
}
