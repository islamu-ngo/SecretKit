using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Current native routing profiles, not implemented connector configuration schemas.</summary>
public enum InfisicalRotationProfile
{
    Auth0ClientSecret, AwsIamUserSecret, AzureClientSecret, CloudflareApiToken,
    CloudflareR2AccessKey, ConvexAccessKey, DatabricksServicePrincipalSecret,
    DatadogApiKey, DatadogApplicationKeySecret, DbtServiceToken, FireworksApiKey,
    GcpServiceAccountKey, HpIloLocalAccount, LdapPassword, LitellmApiKey,
    MongodbCredentials, MssqlCredentials, MysqlCredentials, OktaClientSecret,
    OpenRouterApiKey, OpenaiServiceAccount, OracledbCredentials, PostgresCredentials,
    RedisCredentials, SalesforceOauthCredentials, SnowflakeUserKeyPair, StripeApiKey,
    SupabaseApiKey, UnixLinuxLocalAccount, WindowsLocalAccount
}

public sealed class InfisicalRotationScope : InfisicalNativeAddress
{
    public InfisicalRotationScope(string projectId) : base(projectId) { }
}

public sealed class InfisicalRotationAddress : InfisicalNativeAddress
{
    public InfisicalRotationAddress(string projectId, string environment, string path,
        InfisicalRotationProfile profile, string rotationId) : base(projectId, environment, path)
    {
        if (!Enum.IsDefined(profile) || !Guid.TryParseExact(rotationId, "D", out _))
        {
            throw new ArgumentException("Invalid native rotation selection.");
        }
        Profile = profile;
        RotationId = rotationId;
    }

    [JsonIgnore]
    public InfisicalRotationProfile Profile { get; }
    [JsonIgnore]
    public string RotationId { get; }
}

/// <summary>
/// An owned metadata projection of one response. Native status is an open string in the
/// published contract; neither a job ID nor a timestamp establishes trigger attribution.
/// Configuration, credentials and provider messages are not retained.
/// </summary>
public sealed class InfisicalRotationProgress
{
    internal InfisicalRotationProgress(InfisicalRotationAddress address, string nativeStatus,
        bool? autoRotationEnabled, bool? lastRotationManual, DateTimeOffset attemptedAt,
        DateTimeOffset rotatedAt, DateTimeOffset? nextRotationAt, string? jobId)
    {
        Address = address;
        NativeStatus = nativeStatus;
        AutoRotationEnabled = autoRotationEnabled;
        LastRotationManual = lastRotationManual;
        LastAttemptedAt = attemptedAt;
        LastRotatedAt = rotatedAt;
        NextRotationAt = nextRotationAt;
        LastJobId = jobId;
    }

    [JsonIgnore]
    public InfisicalRotationAddress Address { get; }
    [JsonIgnore]
    public string NativeStatus { get; }
    [JsonIgnore]
    public bool? AutoRotationEnabled { get; }
    [JsonIgnore]
    public bool? LastRotationManual { get; }
    [JsonIgnore]
    public DateTimeOffset LastAttemptedAt { get; }
    [JsonIgnore]
    public DateTimeOffset LastRotatedAt { get; }
    [JsonIgnore]
    public DateTimeOffset? NextRotationAt { get; }
    [JsonIgnore]
    public string? LastJobId { get; }
    public bool ConsumerDeliveryVerified => false;
    public bool FleetConvergenceVerified => false;
    public override string ToString() => "[InfisicalRotationProgress]";
}

public enum InfisicalRotationAction { RotateSecrets, EnableAutomaticRotation, DisableAutomaticRotation }
public enum InfisicalRotationDispatch { NotDispatched, ResponseUnknown, ResponseObserved, Rejected }
public enum InfisicalRotationEffect { Unknown, AcceptedPending, AutomaticRotationSettingApplied }
public enum InfisicalRotationPrecondition { None, RequireCompareAndSwap, RequireIdempotency }

/// <summary>
/// Caller-held single-dispatch evidence tied to an exact reference and action. Local identity
/// is not a provider idempotency key. A later GET cannot reconcile this receipt.
/// </summary>
public sealed class InfisicalRotationReceipt
{
    private readonly object _gate = new();
    private readonly SecretReference _target;
    private InfisicalRotationDispatch _dispatch;
    private InfisicalRotationEffect _effect;
    private InfisicalRotationProgress? _progress;

    public InfisicalRotationReceipt(SecretReference target, InfisicalRotationAction action)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (target.Address is not InfisicalRotationAddress || !Enum.IsDefined(action))
        {
            throw new ArgumentException("A native rotation target and action are required.");
        }
        _target = target;
        Action = action;
    }

    public InfisicalRotationAction Action { get; }
    public InfisicalRotationDispatch Dispatch { get { lock (_gate) { return _dispatch; } } }
    public InfisicalRotationEffect Effect { get { lock (_gate) { return _effect; } } }
    [JsonIgnore]
    public InfisicalRotationProgress? ResponseProgress { get { lock (_gate) { return _progress; } } }

    internal bool Available(SecretReference target, InfisicalRotationAction action)
    {
        lock (_gate)
        {
            return ReferenceEquals(target, _target) && Action == action &&
                _dispatch == InfisicalRotationDispatch.NotDispatched;
        }
    }

    internal bool Begin(SecretReference target, InfisicalRotationAction action)
    {
        lock (_gate)
        {
            if (!Available(target, action))
            {
                return false;
            }
            _dispatch = InfisicalRotationDispatch.ResponseUnknown;
            return true;
        }
    }

    internal void Observe(InfisicalRotationProgress progress, InfisicalRotationEffect effect)
    {
        lock (_gate)
        {
            _progress = progress;
            _effect = effect;
            _dispatch = InfisicalRotationDispatch.ResponseObserved;
        }
    }

    internal void Reject()
    {
        lock (_gate) { _dispatch = InfisicalRotationDispatch.Rejected; }
    }

    public override string ToString() => $"[InfisicalRotationReceipt:{Dispatch}]";
}
