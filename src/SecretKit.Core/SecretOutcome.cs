using System.Diagnostics.CodeAnalysis;
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

    private SecretOutcome(SecretStatus status, T? value, TimeSpan? retryAfter,
        SecretFailureReason reason = SecretFailureReason.None)
    {
        Status = status;
        _value = value;
        RetryAfter = retryAfter;
        Reason = reason;
    }

    /// <summary>Gets the operation category; only Success permits value access.</summary>
    public SecretStatus Status { get; }

    /// <summary>Gets optional nonnegative throttling or unavailability advice, not a retry or replay instruction.</summary>
    public TimeSpan? RetryAfter { get; }

    /// <summary>Gets closed failure detail without material, coordinates or provider text.</summary>
    public SecretFailureReason Reason { get; }

    /// <summary>Gets whether this outcome contains a successful value.</summary>
    public bool IsSuccess => Status == SecretStatus.Success;

    /// <summary>Gets the successful value without copying it or transferring it to a new owner.</summary>
    /// <exception cref="InvalidOperationException">This is a non-success outcome.</exception>
    [JsonIgnore]
    public T Value => IsSuccess ? _value! : throw new InvalidOperationException("Outcome has no successful value.");

    /// <summary>Projects the successful value without copying or disposing it.</summary>
    /// <param name="value">The existing value on success; otherwise the type's default value.</param>
    /// <returns>Whether the outcome contains a successful value.</returns>
    public bool TryGetValue([MaybeNullWhen(false)] out T value)
    {
        value = _value!;
        return IsSuccess;
    }

    /// <summary>Gets the successful value or throws a bounded, coordinate-free exception.</summary>
    /// <returns>The existing successful value, with unchanged ownership.</returns>
    /// <exception cref="SecretUnavailableException">The operation did not succeed.</exception>
    public T GetValueOrThrow() => IsSuccess ? _value! : throw new SecretUnavailableException(Status, Reason, RetryAfter);

    /// <summary>Projects success or closed failure evidence through the selected callback.</summary>
    /// <typeparam name="TResult">The projection result type.</typeparam>
    /// <param name="onSuccess">Receives the existing value without transferring or copying ownership.</param>
    /// <param name="onFailure">Receives status, reason and optional retry advice; advice never authorizes replay.</param>
    /// <returns>The selected callback's result.</returns>
    /// <exception cref="ArgumentNullException">Either callback is null.</exception>
    public TResult Match<TResult>(Func<T, TResult> onSuccess,
        Func<SecretStatus, SecretFailureReason, TimeSpan?, TResult> onFailure)
    {
        ArgumentNullException.ThrowIfNull(onSuccess);
        ArgumentNullException.ThrowIfNull(onFailure);
        return IsSuccess ? onSuccess(_value!) : onFailure(Status, Reason, RetryAfter);
    }

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
    /// <param name="retryAfter">Optional nonnegative advice, valid only for Throttled or Unavailable.</param>
    /// <param name="reason">Optional closed failure detail.</param>
    /// <returns>A failure outcome whose Value cannot be accessed.</returns>
    /// <exception cref="ArgumentException">The status or retry timing violates these constraints.</exception>
    public static SecretOutcome<T> Failure(SecretStatus status, TimeSpan? retryAfter = null,
        SecretFailureReason reason = SecretFailureReason.None)
    {
        if (status == SecretStatus.Success || !Enum.IsDefined(status))
        {
            throw new ArgumentException("A failure requires a defined non-success status.", nameof(status));
        }

        if (!Enum.IsDefined(reason))
        {
            throw new ArgumentException("A failure requires a defined reason.", nameof(reason));
        }

        if (retryAfter is not null &&
            (status is not (SecretStatus.Throttled or SecretStatus.Unavailable) || retryAfter < TimeSpan.Zero))
        {
            throw new ArgumentException("Retry timing requires throttling or unavailability and nonnegative advice.", nameof(retryAfter));
        }

        return new(status, default, retryAfter, reason);
    }

    /// <summary>Returns the status category without formatting the successful value.</summary>
    public override string ToString() => $"[SecretOutcome:{Status}]";
}
