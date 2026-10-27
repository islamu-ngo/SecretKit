using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Native JWT verification configuration selection.</summary>
public enum JwtAuthConfigurationType { /** <summary>Uses a remote JSON Web Key Set.</summary> */ Jwks, /** <summary>Uses explicitly supplied public keys.</summary> */ Static }
/// <summary>Native Kubernetes token-review routing.</summary>
public enum KubernetesTokenReviewMode { /** <summary>Reviews tokens through the Kubernetes API.</summary> */ Api, /** <summary>Reviews tokens through a selected gateway.</summary> */ Gateway }

/// <summary>A null argument omits; Null sends explicit JSON null.</summary>
public sealed class WorkloadAuthNullableText
{
    private WorkloadAuthNullableText(string? value) => Value = value;
    internal string? Value { get; }
    /// <summary>Selects an explicit JSON null rather than omission.</summary>
    public static WorkloadAuthNullableText Null() => new(null);
    /// <summary>Selects an explicit bounded string value, including an empty string when admitted.</summary>
    public static WorkloadAuthNullableText FromValue(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        WorkloadAuthJson.Text(value);
        return new(value);
    }
    /// <summary>Returns a marker without nullable input contents.</summary>
    public override string ToString() => "[WorkloadAuthNullableText]";
}

/// <summary>Native optional policy. Empty trusted-IP arrays and zero values remain explicit.</summary>
public sealed class WorkloadAuthTokenPolicy
{
    /// <summary>Copies optional token policy; null omits fields and an empty trusted-IP array stays explicit.</summary>
    public WorkloadAuthTokenPolicy(int? accessTokenTTL = null, int? accessTokenMaxTTL = null,
        long? accessTokenNumUsesLimit = null, IEnumerable<IdentityTrustedIp>? accessTokenTrustedIps = null)
    {
        AuthenticationJson.Number(accessTokenTTL, 0, 315360000);
        AuthenticationJson.Number(accessTokenMaxTTL, 0, 315360000);
        if (accessTokenNumUsesLimit < 0) throw new ArgumentException("Invalid use limit.");
        AccessTokenTTL = accessTokenTTL;
        AccessTokenMaxTTL = accessTokenMaxTTL;
        AccessTokenNumUsesLimit = accessTokenNumUsesLimit;
        if (accessTokenTrustedIps is not null)
        {
            var copy = accessTokenTrustedIps.Take(101).ToArray();
            if (copy.Length > 100 || copy.Any(ip => ip is null))
                throw new ArgumentException("Invalid trusted IP input budget.");
            AccessTokenTrustedIps = Array.AsReadOnly(copy);
        }
    }
    /// <summary>Gets selected TTL seconds, or null when omitted.</summary>
    [JsonIgnore] public int? AccessTokenTTL { get; }
    /// <summary>Gets selected maximum TTL seconds, or null when omitted.</summary>
    [JsonIgnore] public int? AccessTokenMaxTTL { get; }
    /// <summary>Gets the native use limit, or null when omitted.</summary>
    [JsonIgnore] public long? AccessTokenNumUsesLimit { get; }
    /// <summary>Gets copied trusted IPs; null omits, while an empty collection is explicit.</summary>
    [JsonIgnore] public IReadOnlyList<IdentityTrustedIp>? AccessTokenTrustedIps { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        AuthenticationJson.Number(writer, "accessTokenTTL", AccessTokenTTL);
        AuthenticationJson.Number(writer, "accessTokenMaxTTL", AccessTokenMaxTTL);
        if (AccessTokenNumUsesLimit is { } uses) writer.WriteNumber("accessTokenNumUsesLimit", uses);
        AuthenticationJson.Ips(writer, "accessTokenTrustedIps", AccessTokenTrustedIps);
    }
    /// <summary>Returns a marker without token-policy selectors.</summary>
    public override string ToString() => "[WorkloadAuthTokenPolicy]";
}

/// <summary>Both native discriminators retain every established optional field.</summary>
public sealed class JwtAuthConfigurationInput
{
    /// <summary>Copies JWT settings; JWKS requires an absolute URL and static mode requires public keys.</summary>
    public JwtAuthConfigurationInput(JwtAuthConfigurationType configurationType, string? jwksUrl = null,
        IEnumerable<string>? publicKeys = null, IReadOnlyDictionary<string, string>? boundClaims = null,
        string? jwksCaCert = null, string? boundIssuer = null, string? boundAudiences = null,
        string? boundSubject = null, WorkloadAuthTokenPolicy? policy = null)
    {
        if (!Enum.IsDefined(configurationType)) throw new ArgumentException("Invalid JWT configuration type.");
        ConfigurationType = configurationType;
        WorkloadAuthJson.Text(jwksUrl);
        WorkloadAuthJson.Text(jwksCaCert);
        WorkloadAuthJson.Text(boundIssuer);
        WorkloadAuthJson.Text(boundAudiences);
        WorkloadAuthJson.Text(boundSubject);
        PublicKeys = WorkloadAuthJson.Strings(publicKeys, configurationType == JwtAuthConfigurationType.Static);
        if (configurationType == JwtAuthConfigurationType.Jwks) WorkloadAuthJson.Uri(jwksUrl);
        else if (PublicKeys is null) throw new ArgumentException("Static JWT configuration requires public keys.");
        JwksUrl = jwksUrl;
        JwksCaCert = jwksCaCert;
        BoundIssuer = boundIssuer;
        BoundAudiences = boundAudiences;
        BoundSubject = boundSubject;
        BoundClaims = WorkloadAuthJson.Map(boundClaims);
        Policy = policy ?? new();
    }
    /// <summary>Gets the explicit JWKS/static discriminator.</summary>
    [JsonIgnore] public JwtAuthConfigurationType ConfigurationType { get; }
    /// <summary>Gets the selected JWKS URL, or null when omitted.</summary>
    [JsonIgnore] public string? JwksUrl { get; }
    /// <summary>Gets selected JWKS CA text, or null when omitted.</summary>
    [JsonIgnore] public string? JwksCaCert { get; }
    /// <summary>Gets copied public keys, or null when omitted.</summary>
    [JsonIgnore] public IReadOnlyList<string>? PublicKeys { get; }
    /// <summary>Gets copied bound claims; attachment requires presence, distinct from an empty map.</summary>
    [JsonIgnore] public IReadOnlyDictionary<string, string>? BoundClaims { get; }
    /// <summary>Gets the bound issuer, or null when omitted.</summary>
    [JsonIgnore] public string? BoundIssuer { get; }
    /// <summary>Gets native bound audiences, or null when omitted.</summary>
    [JsonIgnore] public string? BoundAudiences { get; }
    /// <summary>Gets the bound subject, or null when omitted.</summary>
    [JsonIgnore] public string? BoundSubject { get; }
    /// <summary>Gets selected token-policy fields, not provider defaults.</summary>
    [JsonIgnore] public WorkloadAuthTokenPolicy Policy { get; }
    internal void ValidateAttach()
    {
        if (BoundClaims is null) throw new ArgumentException("JWT attachment requires bound claims.");
    }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteString("configurationType", ConfigurationType == JwtAuthConfigurationType.Jwks ? "jwks" : "static");
        WorkloadAuthJson.String(writer, "jwksUrl", JwksUrl);
        WorkloadAuthJson.String(writer, "jwksCaCert", JwksCaCert);
        WorkloadAuthJson.Strings(writer, "publicKeys", PublicKeys);
        WorkloadAuthJson.Map(writer, "boundClaims", BoundClaims);
        WorkloadAuthJson.String(writer, "boundIssuer", BoundIssuer);
        WorkloadAuthJson.String(writer, "boundAudiences", BoundAudiences);
        WorkloadAuthJson.String(writer, "boundSubject", BoundSubject);
        Policy.Write(writer);
    }
    /// <summary>Returns a marker without JWT settings.</summary>
    public override string ToString() => "[JwtAuthConfigurationInput]";
}

/// <summary>Copied OIDC configuration fields with explicit nullable template selection.</summary>
public sealed class OidcAuthConfigurationInput
{
    /// <summary>Copies bounded OIDC fields; attachment validation is performed by its operation factory.</summary>
    public OidcAuthConfigurationInput(IReadOnlyDictionary<string, string>? boundClaims = null,
        string? oidcDiscoveryUrl = null, string? boundIssuer = null, string? boundAudiences = null,
        string? boundSubject = null, string? caCert = null,
        IReadOnlyDictionary<string, string>? claimMetadataMapping = null,
        WorkloadAuthNullableText? templateId = null, WorkloadAuthTokenPolicy? policy = null)
    {
        if (oidcDiscoveryUrl is not null) WorkloadAuthJson.Uri(oidcDiscoveryUrl);
        if (boundIssuer is not null && boundIssuer.Length == 0) throw new ArgumentException("Invalid bound issuer.");
        foreach (string? value in new[] { boundIssuer, boundAudiences, boundSubject, caCert })
            WorkloadAuthJson.Text(value);
        WorkloadAuthJson.Uuid(templateId);
        OidcDiscoveryUrl = oidcDiscoveryUrl;
        BoundIssuer = boundIssuer;
        BoundAudiences = boundAudiences;
        BoundSubject = boundSubject;
        CaCert = caCert;
        TemplateId = templateId;
        BoundClaims = WorkloadAuthJson.Map(boundClaims);
        ClaimMetadataMapping = WorkloadAuthJson.Map(claimMetadataMapping);
        Policy = policy ?? new();
    }
    /// <summary>Gets discovery URL selection, or null when omitted.</summary>
    [JsonIgnore] public string? OidcDiscoveryUrl { get; }
    /// <summary>Gets issuer selection, or null when omitted.</summary>
    [JsonIgnore] public string? BoundIssuer { get; }
    /// <summary>Gets audience selection, or null when omitted.</summary>
    [JsonIgnore] public string? BoundAudiences { get; }
    /// <summary>Gets subject selection, or null when omitted.</summary>
    [JsonIgnore] public string? BoundSubject { get; }
    /// <summary>Gets CA certificate text, or null when omitted.</summary>
    [JsonIgnore] public string? CaCert { get; }
    /// <summary>Gets template selection; null omits and a Null wrapper explicitly clears on update.</summary>
    [JsonIgnore] public WorkloadAuthNullableText? TemplateId { get; }
    /// <summary>Gets copied bound claims; null omits the map.</summary>
    [JsonIgnore] public IReadOnlyDictionary<string, string>? BoundClaims { get; }
    /// <summary>Gets copied claim-to-metadata mappings; null omits the map.</summary>
    [JsonIgnore] public IReadOnlyDictionary<string, string>? ClaimMetadataMapping { get; }
    /// <summary>Gets selected token-policy fields.</summary>
    [JsonIgnore] public WorkloadAuthTokenPolicy Policy { get; }
    internal void ValidateAttach()
    {
        if (BoundClaims is null) throw new ArgumentException("OIDC attachment requires bound claims.");
        if (TemplateId is { Value: null }) throw new ArgumentException("OIDC attachment does not accept null template ID.");
    }
    internal void Write(Utf8JsonWriter writer)
    {
        WorkloadAuthJson.String(writer, "oidcDiscoveryUrl", OidcDiscoveryUrl);
        WorkloadAuthJson.String(writer, "boundIssuer", BoundIssuer);
        WorkloadAuthJson.String(writer, "boundAudiences", BoundAudiences);
        WorkloadAuthJson.String(writer, "boundSubject", BoundSubject);
        WorkloadAuthJson.String(writer, "caCert", CaCert);
        WorkloadAuthJson.Nullable(writer, "templateId", TemplateId);
        WorkloadAuthJson.Map(writer, "boundClaims", BoundClaims);
        WorkloadAuthJson.Map(writer, "claimMetadataMapping", ClaimMetadataMapping);
        Policy.Write(writer);
    }
    /// <summary>Returns a marker without OIDC selectors.</summary>
    public override string ToString() => "[OidcAuthConfigurationInput]";
}

/// <summary>Host-selected reviewer or template configuration; owns a copy of reviewer material.</summary>
public sealed class KubernetesAuthConfigurationInput : IDisposable
{
    private readonly SecretMaterial? _reviewer;
    private bool _disposed;
    /// <summary>Copies optional reviewer material; caller retains the input material, and must dispose this independent copy.</summary>
    public KubernetesAuthConfigurationInput(string? allowedNames = null, string? allowedNamespaces = null,
        string? allowedAudience = null, string? caCert = null, WorkloadAuthNullableText? kubernetesHost = null,
        WorkloadAuthNullableText? gatewayId = null, WorkloadAuthNullableText? gatewayPoolId = null,
        WorkloadAuthNullableText? templateId = null, SecretMaterial? tokenReviewerJwt = null,
        bool clearTokenReviewerJwt = false, KubernetesTokenReviewMode? tokenReviewMode = null,
        bool? verifyTlsCertificate = null, WorkloadAuthTokenPolicy? policy = null)
    {
        foreach (string? value in new[] { allowedNames, allowedNamespaces, caCert }) WorkloadAuthJson.Text(value);
        WorkloadAuthJson.Text(allowedAudience, 1000);
        if (kubernetesHost?.Value is { } host && (host.Length is < 1 or > 255))
            throw new ArgumentException("Invalid Kubernetes host.");
        WorkloadAuthJson.Uuid(gatewayId);
        WorkloadAuthJson.Uuid(gatewayPoolId);
        WorkloadAuthJson.Uuid(templateId);
        if (tokenReviewMode is { } mode && !Enum.IsDefined(mode)) throw new ArgumentException("Invalid review mode.");
        if (clearTokenReviewerJwt && tokenReviewerJwt is not null) throw new ArgumentException("Conflicting reviewer inputs.");
        if (tokenReviewerJwt is not null) WorkloadAuthJson.Text(tokenReviewerJwt.Reveal());
        AllowedNames = allowedNames;
        AllowedNamespaces = allowedNamespaces;
        AllowedAudience = allowedAudience;
        CaCert = caCert;
        KubernetesHost = kubernetesHost;
        GatewayId = gatewayId;
        GatewayPoolId = gatewayPoolId;
        TemplateId = templateId;
        TokenReviewMode = tokenReviewMode;
        VerifyTlsCertificate = verifyTlsCertificate;
        ClearTokenReviewerJwt = clearTokenReviewerJwt;
        Policy = policy ?? new();
        _reviewer = tokenReviewerJwt?.Copy();
    }
    /// <summary>Gets allowed service-account names, or null when omitted.</summary>
    [JsonIgnore] public string? AllowedNames { get; }
    /// <summary>Gets allowed namespaces, or null when omitted.</summary>
    [JsonIgnore] public string? AllowedNamespaces { get; }
    /// <summary>Gets allowed audience, or null when omitted.</summary>
    [JsonIgnore] public string? AllowedAudience { get; }
    /// <summary>Gets CA certificate text, or null when omitted.</summary>
    [JsonIgnore] public string? CaCert { get; }
    /// <summary>Gets host selection; null omits and a Null wrapper sends JSON null.</summary>
    [JsonIgnore] public WorkloadAuthNullableText? KubernetesHost { get; }
    /// <summary>Gets gateway selection, retaining explicit null versus omission.</summary>
    [JsonIgnore] public WorkloadAuthNullableText? GatewayId { get; }
    /// <summary>Gets gateway-pool selection, retaining explicit null versus omission.</summary>
    [JsonIgnore] public WorkloadAuthNullableText? GatewayPoolId { get; }
    /// <summary>Gets template selection; explicit null is rejected on attachment.</summary>
    [JsonIgnore] public WorkloadAuthNullableText? TemplateId { get; }
    /// <summary>Gets review-mode selection, or null when omitted.</summary>
    [JsonIgnore] public KubernetesTokenReviewMode? TokenReviewMode { get; }
    /// <summary>Gets provider-side TLS-verification selection, or null when omitted; not the SDK transport policy.</summary>
    [JsonIgnore] public bool? VerifyTlsCertificate { get; }
    /// <summary>Gets whether update serialization explicitly clears the reviewer token.</summary>
    [JsonIgnore] public bool ClearTokenReviewerJwt { get; }
    /// <summary>Gets selected token-policy fields.</summary>
    [JsonIgnore] public WorkloadAuthTokenPolicy Policy { get; }
    internal void ValidateAttach()
    {
        if (AllowedNames is null || AllowedNamespaces is null)
            throw new ArgumentException("Kubernetes attachment requires names and namespaces.");
        if (TemplateId is { Value: null } || ClearTokenReviewerJwt)
            throw new ArgumentException("Kubernetes attachment does not accept null template or reviewer.");
    }
    internal void Write(Utf8JsonWriter writer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        WorkloadAuthJson.String(writer, "allowedNames", AllowedNames);
        WorkloadAuthJson.String(writer, "allowedNamespaces", AllowedNamespaces);
        WorkloadAuthJson.String(writer, "allowedAudience", AllowedAudience);
        WorkloadAuthJson.String(writer, "caCert", CaCert);
        WorkloadAuthJson.Nullable(writer, "kubernetesHost", KubernetesHost);
        WorkloadAuthJson.Nullable(writer, "gatewayId", GatewayId);
        WorkloadAuthJson.Nullable(writer, "gatewayPoolId", GatewayPoolId);
        WorkloadAuthJson.Nullable(writer, "templateId", TemplateId);
        if (_reviewer is not null) writer.WriteString("tokenReviewerJwt", _reviewer.Reveal());
        else if (ClearTokenReviewerJwt) writer.WriteNull("tokenReviewerJwt");
        if (TokenReviewMode is { } mode) writer.WriteString("tokenReviewMode", mode == KubernetesTokenReviewMode.Api ? "api" : "gateway");
        if (VerifyTlsCertificate is { } verify) writer.WriteBoolean("verifyTlsCertificate", verify);
        Policy.Write(writer);
    }
    /// <summary>Disposes the independent reviewer copy and prevents further serialization of this input.</summary>
    public void Dispose()
    {
        _disposed = true;
        _reviewer?.Dispose();
    }
    /// <summary>Returns a marker without reviewer material or selectors.</summary>
    public override string ToString() => "[KubernetesAuthConfigurationInput]";
}

/// <summary>Known native fields only, never a provider permission attestation.</summary>
public abstract class WorkloadAuthConfiguration
{
    private protected WorkloadAuthConfiguration(JsonElement value, string identityId)
    {
        ManagementJson.RequireEqual(value, "identityId", identityId);
        Id = ManagementJson.Required(value, "id");
        IdentityId = ManagementJson.Required(value, "identityId");
        AuthenticationJson.Uuid(Id);
        AuthenticationJson.Uuid(IdentityId);
        CreatedAt = AuthenticationJson.Date(value, "createdAt")!.Value;
        UpdatedAt = AuthenticationJson.Date(value, "updatedAt")!.Value;
        AccessTokenTTL = WorkloadAuthJson.Number(value, "accessTokenTTL");
        AccessTokenMaxTTL = WorkloadAuthJson.Number(value, "accessTokenMaxTTL");
        AccessTokenNumUsesLimit = WorkloadAuthJson.Number(value, "accessTokenNumUsesLimit");
        HasUnestablishedTrustedIpProjection = value.TryGetProperty("accessTokenTrustedIps", out _);
    }
    /// <summary>Gets the returned authentication-configuration identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned identity identifier matched to the selection.</summary>
    [JsonIgnore] public string IdentityId { get; }
    /// <summary>Gets the returned configuration creation time.</summary>
    [JsonIgnore] public DateTimeOffset CreatedAt { get; }
    /// <summary>Gets the returned configuration update time.</summary>
    [JsonIgnore] public DateTimeOffset UpdatedAt { get; }
    /// <summary>Gets reported TTL seconds, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenTTL { get; }
    /// <summary>Gets reported maximum TTL seconds, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenMaxTTL { get; }
    /// <summary>Gets reported token-use limit, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenNumUsesLimit { get; }
    /// <summary>Gets whether an unestablished trusted-IP node exists; does not interpret its values.</summary>
    [JsonIgnore] public bool HasUnestablishedTrustedIpProjection { get; }
    /// <summary>Returns a marker without identity configuration details.</summary>
    public override string ToString() => "[WorkloadAuthConfiguration]";
}

/// <summary>Returned JWT metadata; does not verify a workload proof.</summary>
public sealed class JwtAuthConfiguration : WorkloadAuthConfiguration
{
    internal JwtAuthConfiguration(JsonElement value, string identityId, bool deleted) : base(value, identityId)
    {
        ConfigurationType = ManagementJson.Required(value, "configurationType");
        JwksUrl = ManagementJson.Required(value, "jwksUrl");
        BoundIssuer = ManagementJson.Required(value, "boundIssuer");
        BoundAudiences = ManagementJson.Required(value, "boundAudiences");
        BoundSubject = ManagementJson.Required(value, "boundSubject");
        AccessTokenPeriod = WorkloadAuthJson.Number(value, "accessTokenPeriod");
        HasUnestablishedBoundClaimsProjection = value.TryGetProperty("boundClaims", out _);
        if (!deleted)
        {
            JwksCaCert = ManagementJson.Required(value, "jwksCaCert");
            PublicKeys = WorkloadAuthJson.ResponseStrings(value, "publicKeys");
        }
    }
    /// <summary>Gets the native returned verification discriminator.</summary>
    [JsonIgnore] public string ConfigurationType { get; }
    /// <summary>Gets the returned JWKS URL.</summary>
    [JsonIgnore] public string JwksUrl { get; }
    /// <summary>Gets returned JWKS CA text; deletion responses leave it null.</summary>
    [JsonIgnore] public string? JwksCaCert { get; }
    /// <summary>Gets returned public keys; deletion responses leave them null.</summary>
    [JsonIgnore] public IReadOnlyList<string>? PublicKeys { get; }
    /// <summary>Gets the returned issuer constraint.</summary>
    [JsonIgnore] public string BoundIssuer { get; }
    /// <summary>Gets the returned audience constraints.</summary>
    [JsonIgnore] public string BoundAudiences { get; }
    /// <summary>Gets the returned subject constraint.</summary>
    [JsonIgnore] public string BoundSubject { get; }
    /// <summary>Gets reported token period seconds, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenPeriod { get; }
    /// <summary>Gets whether a bound-claims node exists whose values are deliberately not projected.</summary>
    [JsonIgnore] public bool HasUnestablishedBoundClaimsProjection { get; }
}

/// <summary>Returned OIDC metadata without guessed bound-claim or mapping shapes.</summary>
public sealed class OidcAuthConfiguration : WorkloadAuthConfiguration
{
    internal OidcAuthConfiguration(JsonElement value, string identityId, bool deleted) : base(value, identityId)
    {
        OidcDiscoveryUrl = ManagementJson.Required(value, "oidcDiscoveryUrl");
        BoundIssuer = ManagementJson.Required(value, "boundIssuer");
        BoundAudiences = ManagementJson.Required(value, "boundAudiences");
        BoundSubject = WorkloadAuthJson.NullableResponse(value, "boundSubject");
        TemplateId = WorkloadAuthJson.NullableResponse(value, "templateId");
        AuthenticationJson.Uuid(TemplateId);
        HasUnestablishedBoundClaimsProjection = value.TryGetProperty("boundClaims", out _);
        HasUnestablishedClaimMetadataMappingProjection = value.TryGetProperty("claimMetadataMapping", out _);
        if (!deleted) CaCert = ManagementJson.Required(value, "caCert");
    }
    /// <summary>Gets the returned discovery URL.</summary>
    [JsonIgnore] public string OidcDiscoveryUrl { get; }
    /// <summary>Gets the returned issuer constraint.</summary>
    [JsonIgnore] public string BoundIssuer { get; }
    /// <summary>Gets the returned audience constraints.</summary>
    [JsonIgnore] public string BoundAudiences { get; }
    /// <summary>Gets subject presence, retaining omission and explicit null.</summary>
    [JsonIgnore] public ProjectField<string> BoundSubject { get; }
    /// <summary>Gets template presence, retaining omission and explicit null.</summary>
    [JsonIgnore] public ProjectField<string> TemplateId { get; }
    /// <summary>Gets returned CA text; deletion responses leave it null.</summary>
    [JsonIgnore] public string? CaCert { get; }
    /// <summary>Gets whether an unestablished bound-claims node was included.</summary>
    [JsonIgnore] public bool HasUnestablishedBoundClaimsProjection { get; }
    /// <summary>Gets whether an unestablished claim-mapping node was included.</summary>
    [JsonIgnore] public bool HasUnestablishedClaimMetadataMappingProjection { get; }
}

/// <summary>Reviewer material is protected and disposable, not an SDK credential source.</summary>
public sealed class KubernetesAuthConfiguration : WorkloadAuthConfiguration, IDisposable
{
    internal KubernetesAuthConfiguration(JsonElement value, string identityId, bool deleted) : base(value, identityId)
    {
        AllowedAudience = ManagementJson.Required(value, "allowedAudience");
        AllowedNames = ManagementJson.Required(value, "allowedNames");
        AllowedNamespaces = ManagementJson.Required(value, "allowedNamespaces");
        GatewayId = WorkloadAuthJson.NullableResponse(value, "gatewayId");
        GatewayPoolId = WorkloadAuthJson.NullableResponse(value, "gatewayPoolId");
        AuthenticationJson.Uuid(GatewayId);
        AuthenticationJson.Uuid(GatewayPoolId);
        KubernetesHost = WorkloadAuthJson.NullableResponse(value, "kubernetesHost");
        TemplateId = WorkloadAuthJson.NullableResponse(value, "templateId");
        AuthenticationJson.Uuid(TemplateId);
        TokenReviewMode = WorkloadAuthJson.OptionalResponse(value, "tokenReviewMode");
        VerifyTlsCertificate = AuthenticationJson.OptionalBoolean(value, "verifyTlsCertificate");
        IsTokenReviewerJwtTemplateSourced = AuthenticationJson.OptionalBoolean(value, "isTokenReviewerJwtTemplateSourced");
        if (!deleted)
        {
            CaCert = ManagementJson.Required(value, "caCert");
            var reviewer = WorkloadAuthJson.NullableResponse(value, "tokenReviewerJwt");
            TokenReviewerJwt = !reviewer.IsPresent ? default : reviewer.IsNull ? ProjectField<SecretMaterial>.Null()
                : ProjectField<SecretMaterial>.Present(SecretMaterial.FromText(reviewer.Value));
        }
    }
    /// <summary>Gets the returned audience constraint.</summary>
    [JsonIgnore] public string AllowedAudience { get; }
    /// <summary>Gets returned service-account name constraints.</summary>
    [JsonIgnore] public string AllowedNames { get; }
    /// <summary>Gets returned namespace constraints.</summary>
    [JsonIgnore] public string AllowedNamespaces { get; }
    /// <summary>Gets returned CA text; deletion responses leave it null.</summary>
    [JsonIgnore] public string? CaCert { get; }
    /// <summary>Gets gateway presence, preserving explicit null.</summary>
    [JsonIgnore] public ProjectField<string> GatewayId { get; }
    /// <summary>Gets gateway-pool presence, preserving explicit null.</summary>
    [JsonIgnore] public ProjectField<string> GatewayPoolId { get; }
    /// <summary>Gets Kubernetes host presence, preserving explicit null.</summary>
    [JsonIgnore] public ProjectField<string> KubernetesHost { get; }
    /// <summary>Gets template presence, preserving explicit null.</summary>
    [JsonIgnore] public ProjectField<string> TemplateId { get; }
    /// <summary>Gets the returned native review mode, or null when absent.</summary>
    [JsonIgnore] public string? TokenReviewMode { get; }
    /// <summary>Gets the returned provider-side TLS-verification flag, or null when absent.</summary>
    [JsonIgnore] public bool? VerifyTlsCertificate { get; }
    /// <summary>Gets the returned template-source flag, or null when absent.</summary>
    [JsonIgnore] public bool? IsTokenReviewerJwtTemplateSourced { get; }
    /// <summary>Gets reviewer-material presence; present nonnull material is owned by this result and must be disposed.</summary>
    [JsonIgnore] public ProjectField<SecretMaterial> TokenReviewerJwt { get; }
    /// <summary>Disposes returned reviewer material without revoking it or erasing exported plaintext strings.</summary>
    public void Dispose()
    {
        if (TokenReviewerJwt.IsPresent && !TokenReviewerJwt.IsNull) TokenReviewerJwt.Value.Dispose();
    }
}

internal static class WorkloadAuthJson
{
    internal static void Text(string? value, int maximum = 16384)
    {
        if (value is not null && value.Length > maximum) throw new ArgumentException("Workload input exceeds its text budget.");
    }
    internal static void Uri(string? value)
    {
        if (value is null || value.Length == 0 || !System.Uri.TryCreate(value, UriKind.Absolute, out _))
            throw new ArgumentException("Invalid workload configuration URI.");
        Text(value);
    }
    internal static void Uuid(WorkloadAuthNullableText? value)
    {
        if (value?.Value is { } text && !Guid.TryParseExact(text, "D", out _))
            throw new ArgumentException("Invalid workload configuration UUID.");
    }
    internal static IReadOnlyList<string>? Strings(IEnumerable<string>? values, bool nonempty)
    {
        if (values is null) return null;
        var copy = values.Take(101).ToArray();
        if (copy.Length > 100 || copy.Any(value => value is null || nonempty && value.Length == 0))
            throw new ArgumentException("Invalid workload string array.");
        foreach (string value in copy) Text(value);
        return Array.AsReadOnly(copy);
    }
    internal static IReadOnlyDictionary<string, string>? Map(IReadOnlyDictionary<string, string>? values)
    {
        if (values is null) return null;
        if (values.Count > 100) throw new ArgumentException("Workload map exceeds its budget.");
        var copy = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in values)
        {
            if (pair.Key is null || pair.Value is null) throw new ArgumentException("Invalid workload map.");
            Text(pair.Key);
            Text(pair.Value);
            copy.Add(pair.Key, pair.Value);
        }
        return new System.Collections.ObjectModel.ReadOnlyDictionary<string, string>(copy);
    }
    internal static void String(Utf8JsonWriter writer, string field, string? value)
    {
        if (value is not null) writer.WriteString(field, value);
    }
    internal static void Nullable(Utf8JsonWriter writer, string field, WorkloadAuthNullableText? value)
    {
        if (value is not null) writer.WriteString(field, value.Value);
    }
    internal static void Strings(Utf8JsonWriter writer, string field, IReadOnlyList<string>? values)
    {
        if (values is null) return;
        writer.WriteStartArray(field);
        foreach (string value in values) writer.WriteStringValue(value);
        writer.WriteEndArray();
    }
    internal static void Map(Utf8JsonWriter writer, string field, IReadOnlyDictionary<string, string>? values)
    {
        if (values is null) return;
        writer.WriteStartObject(field);
        foreach (var pair in values) writer.WriteString(pair.Key, pair.Value);
        writer.WriteEndObject();
    }
    internal static double? Number(JsonElement value, string field)
    {
        if (!value.TryGetProperty(field, out var child)) return null;
        if (child.ValueKind != JsonValueKind.Number || !child.TryGetDouble(out double number) || !double.IsFinite(number))
            throw new ManagementContractException(SecretStatus.Unknown);
        return number;
    }
    internal static string? OptionalResponse(JsonElement value, string field)
    {
        if (!value.TryGetProperty(field, out _)) return null;
        return ManagementJson.Required(value, field);
    }
    internal static ProjectField<string> NullableResponse(JsonElement value, string field) =>
        !value.TryGetProperty(field, out var child) ? default : child.ValueKind == JsonValueKind.Null
            ? ProjectField<string>.Null() : ProjectField<string>.Present(ManagementJson.Required(value, field));
    internal static IReadOnlyList<string> ResponseStrings(JsonElement value, string field)
    {
        var array = ManagementJson.Array(value, field);
        var copy = array.Select(item => item.ValueKind == JsonValueKind.String && item.GetString()!.Length <= 16384
            ? item.GetString()! : throw new ManagementContractException(SecretStatus.Unknown)).Take(101).ToArray();
        if (copy.Length > 100) throw new ManagementContractException(SecretStatus.Unknown);
        return Array.AsReadOnly(copy);
    }
}
