using System.Text.Json.Serialization;

namespace SecretKit.Core;

public enum SecretStatus
{
    Success,
    Absent,
    Denied,
    Unavailable,
    Invalid,
    Throttled,
    Conflict,
    Pending,
    Unknown,
    Unsupported,
    ContractNotEstablished,
    EntitlementUnavailable,
    RecoveryRequired,
    Expired
}

/// <summary>A bounded outcome with no provider payload, exception or implicit successful value.</summary>
public sealed class SecretOutcome<T> where T : notnull
{
    private readonly T? _value;

    private SecretOutcome(SecretStatus status, T? value, TimeSpan? retryAfter)
    {
        Status = status;
        _value = value;
        RetryAfter = retryAfter;
    }

    public SecretStatus Status { get; }

    public TimeSpan? RetryAfter { get; }

    public bool IsSuccess => Status == SecretStatus.Success;

    [JsonIgnore]
    public T Value => IsSuccess ? _value! : throw new InvalidOperationException("Outcome has no successful value.");

    public static SecretOutcome<T> Success(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new(SecretStatus.Success, value, null);
    }

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

    /// <inheritdoc />
    public override string ToString() => $"[SecretOutcome:{Status}]";
}
