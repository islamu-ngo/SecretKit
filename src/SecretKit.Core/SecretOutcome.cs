using System.Text.Json.Serialization;

namespace SecretKit.Core;

/// <summary>Bounded operation categories; provider mappings differ and cancellation propagates as an exception.</summary>
public enum SecretStatus
{
    /// <summary>A result value exists; application activation is separate.</summary>
    Success,
    /// <summary>The selected resource was reported absent, rather than inaccessible.</summary>
    Absent,
    /// <summary>Access or material visibility was denied.</summary>
    Denied,
    /// <summary>The operation could not complete through the selected dependency.</summary>
    Unavailable,
    /// <summary>Input, scope or returned evidence violates the operation contract.</summary>
    Invalid,
    /// <summary>The operation was rate-limited; optional retry timing does not authorize replay.</summary>
    Throttled,
    /// <summary>A provider conflict was observed; no automatic overwrite is implied.</summary>
    Conflict,
    /// <summary>A native step remains pending; the requested effect is not established as applied.</summary>
    Pending,
    /// <summary>Available evidence does not establish a safe result or effect.</summary>
    Unknown,
    /// <summary>The selected operation or variant is not supported.</summary>
    Unsupported,
    /// <summary>A supported programmable contract has not been established.</summary>
    ContractNotEstablished,
    /// <summary>The required provider entitlement is unavailable.</summary>
    EntitlementUnavailable,
    /// <summary>The current lifecycle needs explicit recovery before it can continue.</summary>
    RecoveryRequired,
    /// <summary>The material or credential lifetime has ended.</summary>
    Expired
}

/// <summary>A bounded outcome with no provider payload, exception or implicit successful value.</summary>
/// <typeparam name="T">The non-null successful result type.</typeparam>
/// <remarks>The outcome does not dispose its value. Callers retain responsibility for any owned result.</remarks>
public sealed class SecretOutcome<T> where T : notnull
{
    private readonly T? _value;

    private SecretOutcome(SecretStatus status, T? value, TimeSpan? retryAfter)
    {
        Status = status;
        _value = value;
        RetryAfter = retryAfter;
    }

    /// <summary>Gets the operation category; only Success permits value access.</summary>
    public SecretStatus Status { get; }

    /// <summary>Gets optional nonnegative throttling advice, not an automatic retry or replay instruction.</summary>
    public TimeSpan? RetryAfter { get; }

    /// <summary>Gets whether this outcome contains a successful value.</summary>
    public bool IsSuccess => Status == SecretStatus.Success;

    /// <summary>Gets the successful value without copying it or transferring it to a new owner.</summary>
    /// <exception cref="InvalidOperationException">This is a non-success outcome.</exception>
    [JsonIgnore]
    public T Value => IsSuccess ? _value! : throw new InvalidOperationException("Outcome has no successful value.");

    /// <summary>Wraps a non-null successful result without copying it.</summary>
    /// <param name="value">The result; its disposal remains the caller's responsibility when applicable.</param>
    /// <returns>A successful outcome containing the supplied value.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
    public static SecretOutcome<T> Success(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new(SecretStatus.Success, value, null);
    }

    /// <summary>Creates a non-success outcome with no value or provider payload.</summary>
    /// <param name="status">A defined category other than Success.</param>
    /// <param name="retryAfter">Optional nonnegative advice, valid only for Throttled.</param>
    /// <returns>A failure outcome whose Value cannot be accessed.</returns>
    /// <exception cref="ArgumentException">The status or retry timing violates these constraints.</exception>
    public static SecretOutcome<T> Failure(SecretStatus status, TimeSpan? retryAfter = null)
    {
        if (status == SecretStatus.Success || !Enum.IsDefined(status))
        {
            throw new ArgumentException("A failure requires a defined non-success status.", nameof(status));
        }

        if (retryAfter is not null && (status != SecretStatus.Throttled || retryAfter < TimeSpan.Zero))
        {
            throw new ArgumentException("Retry timing is only valid for throttled outcomes.", nameof(retryAfter));
        }

        return new(status, default, retryAfter);
    }

    /// <summary>Returns the status category without formatting the successful value.</summary>
    public override string ToString() => $"[SecretOutcome:{Status}]";
}
