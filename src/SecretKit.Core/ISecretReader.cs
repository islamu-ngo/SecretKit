namespace SecretKit.Core;

/// <summary>
/// Reads only the selected authority. Successful observations retain the exact requested
/// <see cref="SecretReference"/> instance, not a reconstructed or same-authority reference.
/// There is no implicit cache or fallback.
/// </summary>
public interface ISecretReader
{
    /// <summary>Gets the instance identity to which this reader's references must belong.</summary>
    SecretAuthority Authority { get; }

    /// <summary>
    /// Returns independently owned material whose observation references <paramref name="reference"/>
    /// by object identity. The caller disposes a successful read.
    /// </summary>
    /// <param name="reference">The selected resource bound to <see cref="Authority"/>.</param>
    /// <param name="cancellationToken">Cancels the read; cancellation is not reported as an absent secret.</param>
    /// <returns>A successful owned read or a failure status without material.</returns>
    /// <exception cref="OperationCanceledException">The read was cancelled.</exception>
    ValueTask<SecretOutcome<SecretRead>> ReadAsync(
        SecretReference reference, CancellationToken cancellationToken = default);
}
