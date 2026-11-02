namespace SecretKit.Core;

/// <summary>A failed secret operation described only by closed status and failure evidence.</summary>
/// <remarks>No provider exception, material or coordinates are retained. Retry timing does not authorize replay.</remarks>
public sealed class SecretUnavailableException : Exception
{
    /// <summary>Creates an exception from validated, material-free outcome evidence.</summary>
    /// <param name="status">A defined non-success status.</param>
    /// <param name="failureReason">A defined failure reason.</param>
    /// <param name="retryAfter">Nonnegative timing advice, valid only for unavailability or throttling.</param>
    /// <exception cref="ArgumentException">The status, reason or advice violates the outcome contract.</exception>
    public SecretUnavailableException(SecretStatus status, SecretFailureReason failureReason = SecretFailureReason.None,
        TimeSpan? retryAfter = null)
        : base($"Secret operation did not succeed (Status: {status}, FailureReason: {failureReason}).")
    {
        if (status == SecretStatus.Success || !Enum.IsDefined(status))
            throw new ArgumentException("A failure requires a defined non-success status.", nameof(status));
        if (!Enum.IsDefined(failureReason))
            throw new ArgumentException("A failure requires a defined reason.", nameof(failureReason));
        if (retryAfter is not null &&
            (status is not (SecretStatus.Throttled or SecretStatus.Unavailable) || retryAfter < TimeSpan.Zero))
            throw new ArgumentException("Retry timing requires throttling or unavailability and nonnegative advice.", nameof(retryAfter));
        Status = status;
        FailureReason = failureReason;
        RetryAfter = retryAfter;
    }

    /// <summary>Gets the bounded failure category.</summary>
    public SecretStatus Status { get; }

    /// <summary>Gets closed failure detail without provider text.</summary>
    public SecretFailureReason FailureReason { get; }

    /// <summary>Gets optional timing advice, not an instruction to retry.</summary>
    public TimeSpan? RetryAfter { get; }
}
