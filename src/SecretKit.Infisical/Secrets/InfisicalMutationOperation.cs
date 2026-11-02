using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>A prepared static mutation retaining one receipt across pre-dispatch recovery.</summary>
/// <remarks>The receipt is local evidence, not a remote idempotency key. Once dispatch begins,
/// this operation cannot execute again, even after cancellation or an unknown outcome.
/// The client and input material remain caller-owned and must outlive execution.</remarks>
public sealed class InfisicalMutationOperation
{
    private readonly Func<MutationReceipt, CancellationToken, ValueTask<SecretOutcome<InfisicalStaticChange>>> _execute;
    private int _executing;

    internal InfisicalMutationOperation(MutationReceipt receipt,
        Func<MutationReceipt, CancellationToken, ValueTask<SecretOutcome<InfisicalStaticChange>>> execute)
    {
        Receipt = receipt;
        _execute = execute;
    }

    /// <summary>The single retained receipt; inspect it after failure or cancellation before considering recovery.</summary>
    public MutationReceipt Receipt { get; }

    /// <summary>Executes without concurrent dispatch or replay; a pre-dispatch failure permits explicit retry.</summary>
    /// <exception cref="InvalidOperationException">Another execution is active or dispatch has already begun.</exception>
    public async ValueTask<SecretOutcome<InfisicalStaticChange>> ExecuteAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.CompareExchange(ref _executing, 1, 0) != 0)
            throw new InvalidOperationException("Mutation execution is already active.");
        try
        {
            if (Receipt.Evidence != DispatchEvidence.NotDispatched)
                throw new InvalidOperationException("A dispatched mutation cannot be replayed.");
            return await _execute(Receipt, cancellationToken).ConfigureAwait(false);
        }
        finally { Volatile.Write(ref _executing, 0); }
    }

    /// <summary>Returns a fixed marker without coordinates, material or correlation identifiers.</summary>
    public override string ToString() => "[InfisicalMutationOperation]";
}

public sealed partial class InfisicalClient
{
    /// <summary>Prepares a create without I/O; keep the borrowed material alive until execution completes.</summary>
    [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCode(InfisicalOperationBudget.PayloadTrimmingMessage)]
    public InfisicalMutationOperation PrepareCreate(SecretReference target, SecretMaterial material)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(material);
        return new(CreateReceipt(target), (receipt, cancellationToken) => CreateAsync(target, material, receipt, cancellationToken));
    }

    /// <summary>Prepares an update without I/O; keep the borrowed material alive until execution completes.</summary>
    [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCode(InfisicalOperationBudget.PayloadTrimmingMessage)]
    public InfisicalMutationOperation PrepareUpdateValue(SecretReference target, SecretMaterial material)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(material);
        return new(CreateReceipt(target), (receipt, cancellationToken) => UpdateValueAsync(target, material, receipt, cancellationToken));
    }
}
