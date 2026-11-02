namespace SecretKit.Core;

/// <summary>Projects authority-bound reader outcomes without adding caching, fallback or retries.</summary>
public static class SecretReaderExtensions
{
    /// <summary>Reads independently owned material or throws a bounded failure.</summary>
    /// <param name="reader">The explicitly selected reader.</param>
    /// <param name="reference">The exact authority-bound resource to read.</param>
    /// <param name="cancellationToken">Cancels the read; cancellation propagates.</param>
    /// <returns>The successful read, which the caller must dispose.</returns>
    /// <exception cref="ArgumentNullException">The reader or reference is null.</exception>
    /// <exception cref="SecretUnavailableException">The operation did not succeed.</exception>
    public static async ValueTask<SecretRead> GetSecretAsync(this ISecretReader reader,
        SecretReference reference, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(reference);
        return (await reader.ReadAsync(reference, cancellationToken).ConfigureAwait(false)).GetValueOrThrow();
    }

    /// <summary>Reads independently owned material, returning null only for reported absence.</summary>
    /// <param name="reader">The explicitly selected reader.</param>
    /// <param name="reference">The exact authority-bound resource to read.</param>
    /// <param name="cancellationToken">Cancels the read; cancellation propagates.</param>
    /// <returns>The owned read or null for Absent; dispose a returned read.</returns>
    /// <exception cref="ArgumentNullException">The reader or reference is null.</exception>
    /// <exception cref="SecretUnavailableException">The operation failed for a reason other than absence.</exception>
    public static async ValueTask<SecretRead?> TryGetSecretAsync(this ISecretReader reader,
        SecretReference reference, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(reference);
        var outcome = await reader.ReadAsync(reference, cancellationToken).ConfigureAwait(false);
        return outcome.Status == SecretStatus.Absent ? null : outcome.GetValueOrThrow();
    }
}
