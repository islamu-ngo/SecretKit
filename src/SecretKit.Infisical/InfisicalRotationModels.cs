using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Current native routing profiles, not implemented connector configuration schemas.</summary>
public enum InfisicalRotationProfile
{
    /** <summary>Auth0 client secret rotation.</summary> */
    Auth0ClientSecret, /** <summary>AWS IAM user secret rotation.</summary> */ AwsIamUserSecret, /** <summary>Azure client secret rotation.</summary> */ AzureClientSecret, /** <summary>Cloudflare API token rotation.</summary> */ CloudflareApiToken,
    /** <summary>Cloudflare R2 access-key rotation.</summary> */
    CloudflareR2AccessKey, /** <summary>Convex access-key rotation.</summary> */ ConvexAccessKey, /** <summary>Databricks service-principal rotation.</summary> */ DatabricksServicePrincipalSecret,
    /** <summary>Datadog API key rotation.</summary> */
    DatadogApiKey, /** <summary>Datadog application-key rotation.</summary> */ DatadogApplicationKeySecret, /** <summary>dbt service-token rotation.</summary> */ DbtServiceToken, /** <summary>Fireworks API key rotation.</summary> */ FireworksApiKey,
    /** <summary>GCP service-account key rotation.</summary> */
    GcpServiceAccountKey, /** <summary>HP iLO account rotation.</summary> */ HpIloLocalAccount, /** <summary>LDAP password rotation.</summary> */ LdapPassword, /** <summary>LiteLLM API key rotation.</summary> */ LitellmApiKey,
    /** <summary>MongoDB credential rotation.</summary> */
    MongodbCredentials, /** <summary>SQL Server credential rotation.</summary> */ MssqlCredentials, /** <summary>MySQL credential rotation.</summary> */ MysqlCredentials, /** <summary>Okta client-secret rotation.</summary> */ OktaClientSecret,
    /** <summary>OpenRouter API key rotation.</summary> */
    OpenRouterApiKey, /** <summary>OpenAI service-account rotation.</summary> */ OpenaiServiceAccount, /** <summary>Oracle database credential rotation.</summary> */ OracledbCredentials, /** <summary>PostgreSQL credential rotation.</summary> */ PostgresCredentials,
    /** <summary>Redis credential rotation.</summary> */
    RedisCredentials, /** <summary>Salesforce OAuth credential rotation.</summary> */ SalesforceOauthCredentials, /** <summary>Snowflake user key-pair rotation.</summary> */ SnowflakeUserKeyPair, /** <summary>Stripe API key rotation.</summary> */ StripeApiKey,
    /** <summary>Supabase API key rotation.</summary> */
    SupabaseApiKey, /** <summary>Unix/Linux local-account rotation.</summary> */ UnixLinuxLocalAccount, /** <summary>Windows local-account rotation.</summary> */ WindowsLocalAccount
}

/// <summary>Protected project-wide rotation metadata scope.</summary>
public sealed class InfisicalRotationScope : InfisicalNativeAddress
{
    /// <summary>Selects the project for bounded native rotation listing.</summary>
    public InfisicalRotationScope(string projectId) : base(projectId) { }
}

/// <summary>Protected exact rotation coordinates and closed native routing profile.</summary>
public sealed class InfisicalRotationAddress : InfisicalNativeAddress
{
    /// <summary>Selects project/environment/path, profile and a canonical native rotation UUID.</summary>
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

    /// <summary>The closed routing profile; not a configuration schema.</summary>
    [JsonIgnore]
    public InfisicalRotationProfile Profile { get; }
    /// <summary>The protected native rotation UUID.</summary>
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

    /// <summary>The validated native rotation coordinates.</summary>
    [JsonIgnore]
    public InfisicalRotationAddress Address { get; }
    /// <summary>Protected open status text; not interpreted as attributable completion.</summary>
    [JsonIgnore]
    public string NativeStatus { get; }
    /// <summary>Reported automatic-rotation setting, or null if absent.</summary>
    [JsonIgnore]
    public bool? AutoRotationEnabled { get; }
    /// <summary>Reported manual flag for the last rotation, not trigger attribution.</summary>
    [JsonIgnore]
    public bool? LastRotationManual { get; }
    /// <summary>The returned last-attempt time, not proof of this caller's trigger.</summary>
    [JsonIgnore]
    public DateTimeOffset LastAttemptedAt { get; }
    /// <summary>The returned last-rotation time; does not prove consumer activation.</summary>
    [JsonIgnore]
    public DateTimeOffset LastRotatedAt { get; }
    /// <summary>The reported next-rotation time, if present; no local worker is started.</summary>
    [JsonIgnore]
    public DateTimeOffset? NextRotationAt { get; }
    /// <summary>The protected reported job identifier, not a receipt correlation key.</summary>
    [JsonIgnore]
    public string? LastJobId { get; }
    /// <summary>Always false: metadata observation does not verify consumer delivery.</summary>
    public bool ConsumerDeliveryVerified => false;
    /// <summary>Always false: metadata observation does not verify fleet convergence.</summary>
    public bool FleetConvergenceVerified => false;
    /// <summary>Returns a fixed label without coordinates or provider text.</summary>
    public override string ToString() => "[InfisicalRotationProgress]";
}

/// <summary>The exact native mutation selected for one receipt.</summary>
public enum InfisicalRotationAction { /** <summary>Request secret rotation.</summary> */ RotateSecrets, /** <summary>Enable native automatic rotation.</summary> */ EnableAutomaticRotation, /** <summary>Disable native automatic rotation.</summary> */ DisableAutomaticRotation }
/// <summary>Local sending and response evidence, separate from downstream effect.</summary>
public enum InfisicalRotationDispatch { /** <summary>No handoff occurred.</summary> */ NotDispatched, /** <summary>Handoff occurred; no validated response is known.</summary> */ ResponseUnknown, /** <summary>A correlated response was observed.</summary> */ ResponseObserved, /** <summary>The request was rejected.</summary> */ Rejected }
/// <summary>Evidence established by a correlated native mutation response.</summary>
public enum InfisicalRotationEffect { /** <summary>No effect established.</summary> */ Unknown, /** <summary>Trigger accepted, not completed.</summary> */ AcceptedPending, /** <summary>Requested automatic-rotation setting observed.</summary> */ AutomaticRotationSettingApplied }
/// <summary>Required mutation guarantees; unestablished guarantees are rejected as Unsupported before dispatch.</summary>
public enum InfisicalRotationPrecondition { /** <summary>Require no extra mutation guarantee.</summary> */ None, /** <summary>Require compare-and-swap, currently unsupported.</summary> */ RequireCompareAndSwap, /** <summary>Require idempotency, currently unsupported.</summary> */ RequireIdempotency }

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

    /// <summary>Binds caller-retained evidence to an exact reference object and native action before dispatch.</summary>
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

    /// <summary>The exact native action selected for this receipt.</summary>
    public InfisicalRotationAction Action { get; }
    /// <summary>The latest local handoff/response evidence, preserved across cancellation.</summary>
    public InfisicalRotationDispatch Dispatch { get { lock (_gate) { return _dispatch; } } }
    /// <summary>Established native effect, never inferred from a later unrelated GET.</summary>
    public InfisicalRotationEffect Effect { get { lock (_gate) { return _effect; } } }
    /// <summary>Correlated mutation response metadata, or null before such a response is validated.</summary>
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

    /// <summary>Returns dispatch state without target details.</summary>
    public override string ToString() => $"[InfisicalRotationReceipt:{Dispatch}]";
}
