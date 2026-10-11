using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

public enum JwtAuthConfigurationType { Jwks, Static }
public enum KubernetesTokenReviewMode { Api, Gateway }

/// <summary>A null argument omits; Null sends explicit JSON null.</summary>
public sealed class WorkloadAuthNullableText
{
    private WorkloadAuthNullableText(string? value) => Value = value;
    internal string? Value { get; }
    public static WorkloadAuthNullableText Null() => new(null);
    public static WorkloadAuthNullableText FromValue(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        WorkloadAuthJson.Text(value);
        return new(value);
    }
    public override string ToString() => "[WorkloadAuthNullableText]";
}

/// <summary>Native optional policy. Empty trusted-IP arrays and zero values remain explicit.</summary>
public sealed class WorkloadAuthTokenPolicy
{
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
    [JsonIgnore] public int? AccessTokenTTL { get; }
    [JsonIgnore] public int? AccessTokenMaxTTL { get; }
    [JsonIgnore] public long? AccessTokenNumUsesLimit { get; }
    [JsonIgnore] public IReadOnlyList<IdentityTrustedIp>? AccessTokenTrustedIps { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        AuthenticationJson.Number(writer, "accessTokenTTL", AccessTokenTTL);
        AuthenticationJson.Number(writer, "accessTokenMaxTTL", AccessTokenMaxTTL);
        if (AccessTokenNumUsesLimit is { } uses) writer.WriteNumber("accessTokenNumUsesLimit", uses);
        AuthenticationJson.Ips(writer, "accessTokenTrustedIps", AccessTokenTrustedIps);
    }
    public override string ToString() => "[WorkloadAuthTokenPolicy]";
}

/// <summary>Both native discriminators retain every established optional field.</summary>
public sealed class JwtAuthConfigurationInput
{
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
    [JsonIgnore] public JwtAuthConfigurationType ConfigurationType { get; }
    [JsonIgnore] public string? JwksUrl { get; }
    [JsonIgnore] public string? JwksCaCert { get; }
    [JsonIgnore] public IReadOnlyList<string>? PublicKeys { get; }
    [JsonIgnore] public IReadOnlyDictionary<string, string>? BoundClaims { get; }
    [JsonIgnore] public string? BoundIssuer { get; }
    [JsonIgnore] public string? BoundAudiences { get; }
    [JsonIgnore] public string? BoundSubject { get; }
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
    public override string ToString() => "[JwtAuthConfigurationInput]";
}

public sealed class OidcAuthConfigurationInput
{
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
    [JsonIgnore] public string? OidcDiscoveryUrl { get; }
    [JsonIgnore] public string? BoundIssuer { get; }
    [JsonIgnore] public string? BoundAudiences { get; }
    [JsonIgnore] public string? BoundSubject { get; }
    [JsonIgnore] public string? CaCert { get; }
    [JsonIgnore] public WorkloadAuthNullableText? TemplateId { get; }
    [JsonIgnore] public IReadOnlyDictionary<string, string>? BoundClaims { get; }
    [JsonIgnore] public IReadOnlyDictionary<string, string>? ClaimMetadataMapping { get; }
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
    public override string ToString() => "[OidcAuthConfigurationInput]";
}

/// <summary>Host-selected reviewer or template configuration; owns a copy of reviewer material.</summary>
public sealed class KubernetesAuthConfigurationInput : IDisposable
{
    private readonly SecretMaterial? _reviewer;
    private bool _disposed;
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
    [JsonIgnore] public string? AllowedNames { get; }
    [JsonIgnore] public string? AllowedNamespaces { get; }
    [JsonIgnore] public string? AllowedAudience { get; }
    [JsonIgnore] public string? CaCert { get; }
    [JsonIgnore] public WorkloadAuthNullableText? KubernetesHost { get; }
    [JsonIgnore] public WorkloadAuthNullableText? GatewayId { get; }
    [JsonIgnore] public WorkloadAuthNullableText? GatewayPoolId { get; }
    [JsonIgnore] public WorkloadAuthNullableText? TemplateId { get; }
    [JsonIgnore] public KubernetesTokenReviewMode? TokenReviewMode { get; }
    [JsonIgnore] public bool? VerifyTlsCertificate { get; }
    [JsonIgnore] public bool ClearTokenReviewerJwt { get; }
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
    public void Dispose()
    {
        _disposed = true;
        _reviewer?.Dispose();
    }
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
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string IdentityId { get; }
    [JsonIgnore] public DateTimeOffset CreatedAt { get; }
    [JsonIgnore] public DateTimeOffset UpdatedAt { get; }
    [JsonIgnore] public double? AccessTokenTTL { get; }
    [JsonIgnore] public double? AccessTokenMaxTTL { get; }
    [JsonIgnore] public double? AccessTokenNumUsesLimit { get; }
    [JsonIgnore] public bool HasUnestablishedTrustedIpProjection { get; }
    public override string ToString() => "[WorkloadAuthConfiguration]";
}

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
    [JsonIgnore] public string ConfigurationType { get; }
    [JsonIgnore] public string JwksUrl { get; }
    [JsonIgnore] public string? JwksCaCert { get; }
    [JsonIgnore] public IReadOnlyList<string>? PublicKeys { get; }
    [JsonIgnore] public string BoundIssuer { get; }
    [JsonIgnore] public string BoundAudiences { get; }
    [JsonIgnore] public string BoundSubject { get; }
    [JsonIgnore] public double? AccessTokenPeriod { get; }
    [JsonIgnore] public bool HasUnestablishedBoundClaimsProjection { get; }
}

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
    [JsonIgnore] public string OidcDiscoveryUrl { get; }
    [JsonIgnore] public string BoundIssuer { get; }
    [JsonIgnore] public string BoundAudiences { get; }
    [JsonIgnore] public ProjectField<string> BoundSubject { get; }
    [JsonIgnore] public ProjectField<string> TemplateId { get; }
    [JsonIgnore] public string? CaCert { get; }
    [JsonIgnore] public bool HasUnestablishedBoundClaimsProjection { get; }
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
    [JsonIgnore] public string AllowedAudience { get; }
    [JsonIgnore] public string AllowedNames { get; }
    [JsonIgnore] public string AllowedNamespaces { get; }
    [JsonIgnore] public string? CaCert { get; }
    [JsonIgnore] public ProjectField<string> GatewayId { get; }
    [JsonIgnore] public ProjectField<string> GatewayPoolId { get; }
    [JsonIgnore] public ProjectField<string> KubernetesHost { get; }
    [JsonIgnore] public ProjectField<string> TemplateId { get; }
    [JsonIgnore] public string? TokenReviewMode { get; }
    [JsonIgnore] public bool? VerifyTlsCertificate { get; }
    [JsonIgnore] public bool? IsTokenReviewerJwtTemplateSourced { get; }
    [JsonIgnore] public ProjectField<SecretMaterial> TokenReviewerJwt { get; }
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
