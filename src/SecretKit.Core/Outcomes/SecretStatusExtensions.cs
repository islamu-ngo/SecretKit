namespace SecretKit.Core;

/// <summary>Classifies bounded statuses without granting authority or authorizing retries.</summary>
public static class SecretStatusExtensions
{
    /// <summary>Tests whether a status permits successful value access.</summary>
    /// <param name="status">The status to classify.</param>
    /// <returns>True only for Success.</returns>
    public static bool IsSuccess(this SecretStatus status) => status == SecretStatus.Success;

    /// <summary>Identifies potentially transient dependency failures, without guaranteeing recovery.</summary>
    /// <param name="status">The status to classify.</param>
    /// <returns>True for Unavailable or Throttled; mutations still require their own dispatch evidence.</returns>
    public static bool IsTransientFailure(this SecretStatus status) => status is SecretStatus.Unavailable or SecretStatus.Throttled;

    /// <summary>Identifies expiry when interpreting an authentication outcome.</summary>
    /// <param name="status">The authentication outcome's status.</param>
    /// <returns>True only for Expired. Denial alone does not establish a credential failure.</returns>
    /// <remarks>For a material-read outcome, Expired can describe material instead of authentication.</remarks>
    public static bool RequiresReauthentication(this SecretStatus status) => status == SecretStatus.Expired;
}
