using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Native GCP gateway authentication strategy.</summary>
public enum GatewayGcpType { /** <summary>Selects Compute Engine proof.</summary> */ Gce, /** <summary>Selects IAM proof.</summary> */ Iam }
/// <summary>Native Kubernetes gateway token-review route.</summary>
public enum GatewayTokenReviewMode { /** <summary>Uses direct API token review.</summary> */ Api, /** <summary>Uses gateway token review.</summary> */ Gateway }
/// <summary>Known gateway authentication response branches; identity is response-only in this input surface.</summary>
public enum GatewayAuthenticationMethod { /** <summary>AWS authentication configuration.</summary> */ Aws, /** <summary>GCP authentication configuration.</summary> */ Gcp, /** <summary>Kubernetes authentication configuration.</summary> */ Kubernetes, /** <summary>Enrollment-token authentication configuration.</summary> */ Token, /** <summary>Returned existing identity association.</summary> */ Identity }

/// <summary>Supplied nullable UUID. No wrapper means omission, not JSON null.</summary>
public sealed class GatewayNullableId
{
    /// <summary>Captures an explicit nullable UUID; no wrapper means omission.</summary>
    public GatewayNullableId(string? value)
    {
        if (value is not null) GatewayJson.UuidInput(value);
        Value = value;
    }
    /// <summary>Gets the selected UUID or explicit null.</summary>
    [JsonIgnore] public string? Value { get; }
    /// <summary>Returns a marker without UUID coordinates.</summary>
    public override string ToString() => "[GatewayNullableId]";
}

/// <summary>Copied, disposable, typed gateway authentication input. No identity request branch is published.</summary>
public sealed class GatewayAuthenticationInput : IDisposable
{
    private readonly object _gate = new();
    private byte[]? _body;
    private GatewayAuthenticationInput(Action<Utf8JsonWriter> write) => _body = GatewayJson.Serialize(write);

    // field-17354/17358 permit empty strings and omission independently; no SDK defaults.
    /// <summary>Copies AWS selector configuration; null omits and empty strings remain explicit.</summary>
    public static GatewayAuthenticationInput Aws(string? allowedAccountIds = null, string? allowedPrincipalArns = null)
    {
        GatewayJson.InputText(allowedAccountIds, 4096);
        GatewayJson.InputText(allowedPrincipalArns, 4096);
        return new(writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("method", "aws");
            if (allowedAccountIds is not null) writer.WriteString("allowedAccountIds", allowedAccountIds);
            if (allowedPrincipalArns is not null) writer.WriteString("allowedPrincipalArns", allowedPrincipalArns);
            writer.WriteEndObject();
        });
    }

    /// <summary>Copies GCP selectors and optional type without credential discovery.</summary>
    public static GatewayAuthenticationInput Gcp(string? allowedProjects = null, string? allowedServiceAccounts = null,
        string? allowedZones = null, GatewayGcpType? type = null)
    {
        foreach (string? value in new[] { allowedProjects, allowedServiceAccounts, allowedZones }) GatewayJson.InputText(value, 1024);
        string? wireType = type switch
        {
            null => null,
            GatewayGcpType.Gce => "gce",
            GatewayGcpType.Iam => "iam",
            _ => throw new ArgumentException("Invalid gateway GCP type.")
        };
        return new(writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("method", "gcp");
            if (allowedProjects is not null) writer.WriteString("allowedProjects", allowedProjects);
            if (allowedServiceAccounts is not null) writer.WriteString("allowedServiceAccounts", allowedServiceAccounts);
            if (allowedZones is not null) writer.WriteString("allowedZones", allowedZones);
            if (wireType is not null) writer.WriteString("type", wireType);
            writer.WriteEndObject();
        });
    }

    /// <summary>Copies Kubernetes reviewer material into the owned serialized body; caller retains the original token.</summary>
    public static GatewayAuthenticationInput Kubernetes(string allowedNames, string allowedNamespaces,
        string? allowedAudience = null, string? caCertificate = null, GatewayNullableId? gatewayId = null,
        GatewayNullableId? gatewayPoolId = null, string? kubernetesHost = null, SecretMaterial? tokenReviewerJwt = null,
        GatewayTokenReviewMode? tokenReviewMode = null, bool? verifyTlsCertificate = null)
    {
        ArgumentNullException.ThrowIfNull(allowedNames);
        ArgumentNullException.ThrowIfNull(allowedNamespaces);
        GatewayJson.InputText(allowedNames, 1024);
        GatewayJson.InputText(allowedNamespaces, 1024);
        GatewayJson.InputText(allowedAudience, 255);
        GatewayJson.InputText(caCertificate, 10240);
        GatewayJson.InputText(kubernetesHost, 255, 1);
        string? mode = tokenReviewMode switch
        {
            null => null,
            GatewayTokenReviewMode.Api => "api",
            GatewayTokenReviewMode.Gateway => "gateway",
            _ => throw new ArgumentException("Invalid gateway token review mode.")
        };
        char[]? jwt = tokenReviewerJwt?.ExportCharacters();
        try
        {
            if (jwt?.Length > 8192) throw new ArgumentException("Invalid gateway JWT budget.");
            return new(writer =>
            {
                writer.WriteStartObject();
                writer.WriteString("method", "kubernetes");
                writer.WriteString("allowedNames", allowedNames);
                writer.WriteString("allowedNamespaces", allowedNamespaces);
                if (allowedAudience is not null) writer.WriteString("allowedAudience", allowedAudience);
                if (caCertificate is not null) writer.WriteString("caCertificate", caCertificate);
                if (gatewayId is not null) writer.WriteString("gatewayId", gatewayId.Value);
                if (gatewayPoolId is not null) writer.WriteString("gatewayPoolId", gatewayPoolId.Value);
                if (kubernetesHost is not null) writer.WriteString("kubernetesHost", kubernetesHost);
                if (jwt is not null) writer.WriteString("tokenReviewerJwt", jwt.AsSpan());
                if (mode is not null) writer.WriteString("tokenReviewMode", mode);
                if (verifyTlsCertificate is { } verify) writer.WriteBoolean("verifyTlsCertificate", verify);
                writer.WriteEndObject();
            });
        }
        finally { if (jwt is not null) Array.Clear(jwt); }
    }

    /// <summary>Selects native token authentication without issuing an enrollment token.</summary>
    public static GatewayAuthenticationInput Token() => new(writer =>
    {
        writer.WriteStartObject();
        writer.WriteString("method", "token");
        writer.WriteEndObject();
    });

    internal void Write(Utf8JsonWriter writer)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_body is null, this);
            writer.WritePropertyName("authMethod");
            writer.WriteRawValue(_body);
        }
    }
    /// <summary>Clears the owned serialized authentication body and prevents further serialization.</summary>
    public void Dispose() { lock (_gate) { if (_body is not null) Array.Clear(_body); _body = null; } }
    /// <summary>Returns a marker without authentication settings or material.</summary>
    public override string ToString() => "[GatewayAuthenticationInput]";
}

/// <summary>Gateway creation settings borrowing an explicitly selected authentication input.</summary>
public sealed class GatewayCreation
{
    private readonly GatewayAuthenticationInput _authentication;
    /// <summary>Gets the selected gateway name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Captures the name and borrowed authentication input; keep it alive through request construction.</summary>
    public GatewayCreation(string name, GatewayAuthenticationInput authentication)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(authentication);
        GatewayJson.InputText(name, 64, 1);
        Name = name;
        _authentication = authentication;
    }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        writer.WriteString("name", Name);
        _authentication.Write(writer);
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without gateway creation settings.</summary>
    public override string ToString() => "[GatewayCreation]";
}

/// <summary>Optional native gateway patch fields; omitted fields remain omitted.</summary>
public sealed class GatewayUpdate
{
    private readonly string? _name;
    private readonly GatewayAuthenticationInput? _authentication;
    /// <summary>Captures an optional name and borrowed authentication input; null omits each field.</summary>
    public GatewayUpdate(string? name = null, GatewayAuthenticationInput? authentication = null)
    {
        GatewayJson.InputText(name, 64, 1);
        _name = name;
        _authentication = authentication;
    }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        if (_name is not null) writer.WriteString("name", _name);
        _authentication?.Write(writer);
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without patch settings.</summary>
    public override string ToString() => "[GatewayUpdate]";
}

/// <summary>Independently published success configuration. Open response strings remain strings, not input enums.</summary>
public sealed class GatewayAuthenticationSummary
{
    internal GatewayAuthenticationSummary(JsonElement value)
    {
        Method = ManagementJson.Required(value, "method") switch
        {
            "aws" => GatewayAuthenticationMethod.Aws,
            "gcp" => GatewayAuthenticationMethod.Gcp,
            "kubernetes" => GatewayAuthenticationMethod.Kubernetes,
            "token" => GatewayAuthenticationMethod.Token,
            "identity" => GatewayAuthenticationMethod.Identity,
            _ => throw new ManagementContractException(SecretStatus.Unknown)
        };
        JsonElement config = ManagementJson.Object(value, "config");
        if (Method is GatewayAuthenticationMethod.Aws or GatewayAuthenticationMethod.Gcp or GatewayAuthenticationMethod.Kubernetes)
        {
            Id = GatewayJson.Uuid(config, "id");
            CreatedAt = GatewayJson.Timestamp(config, "createdAt");
            UpdatedAt = GatewayJson.Timestamp(config, "updatedAt");
        }
        if (Method == GatewayAuthenticationMethod.Aws)
        {
            AllowedAccountIds = ManagementJson.Required(config, "allowedAccountIds");
            AllowedPrincipalArns = ManagementJson.Required(config, "allowedPrincipalArns");
        }
        if (Method == GatewayAuthenticationMethod.Gcp)
        {
            AllowedProjects = ManagementJson.Required(config, "allowedProjects");
            AllowedServiceAccounts = ManagementJson.Required(config, "allowedServiceAccounts");
            AllowedZones = ManagementJson.Required(config, "allowedZones");
            Type = ManagementJson.Required(config, "type");
        }
        if (Method == GatewayAuthenticationMethod.Identity)
        {
            IdentityId = ManagementJson.Required(config, "identityId");
            IdentityName = GatewayJson.Text(config, "identityName", true);
        }
        if (Method == GatewayAuthenticationMethod.Kubernetes)
        {
            AllowedAudience = ManagementJson.Required(config, "allowedAudience");
            AllowedNames = ManagementJson.Required(config, "allowedNames");
            AllowedNamespaces = ManagementJson.Required(config, "allowedNamespaces");
            CaCertificate = ManagementJson.Required(config, "caCertificate");
            GatewayId = GatewayJson.Text(config, "gatewayId", true);
            GatewayPoolId = GatewayJson.Text(config, "gatewayPoolId", true);
            HasTokenReviewerJwt = ManagementJson.Boolean(config, "hasTokenReviewerJwt");
            KubernetesHost = ManagementJson.Required(config, "kubernetesHost");
            TokenReviewMode = ManagementJson.Required(config, "tokenReviewMode");
            VerifyTlsCertificate = ManagementJson.Boolean(config, "verifyTlsCertificate");
        }
    }
    /// <summary>Gets the native returned authentication branch.</summary>
    [JsonIgnore] public GatewayAuthenticationMethod Method { get; }
    /// <summary>Gets configuration UUID for AWS, GCP or Kubernetes; other branches leave it null.</summary>
    [JsonIgnore] public string? Id { get; }
    /// <summary>Gets returned configuration creation time, or null when this branch has none.</summary>
    [JsonIgnore] public string? CreatedAt { get; }
    /// <summary>Gets returned configuration update time, or null when this branch has none.</summary>
    [JsonIgnore] public string? UpdatedAt { get; }
    /// <summary>Gets AWS account selectors; other branches leave this null.</summary>
    [JsonIgnore] public string? AllowedAccountIds { get; }
    /// <summary>Gets AWS principal ARN selectors; other branches leave this null.</summary>
    [JsonIgnore] public string? AllowedPrincipalArns { get; }
    /// <summary>Gets GCP project selectors; other branches leave this null.</summary>
    [JsonIgnore] public string? AllowedProjects { get; }
    /// <summary>Gets GCP service-account selectors; other branches leave this null.</summary>
    [JsonIgnore] public string? AllowedServiceAccounts { get; }
    /// <summary>Gets GCP zone selectors; other branches leave this null.</summary>
    [JsonIgnore] public string? AllowedZones { get; }
    /// <summary>Gets open native GCP type text without narrowing it to input enums.</summary>
    [JsonIgnore] public string? Type { get; }
    /// <summary>Gets returned identity coordinate for the identity branch.</summary>
    [JsonIgnore] public string? IdentityId { get; }
    /// <summary>Gets returned identity name, or null when absent or for another branch.</summary>
    [JsonIgnore] public string? IdentityName { get; }
    /// <summary>Gets Kubernetes audience constraint; other branches leave this null.</summary>
    [JsonIgnore] public string? AllowedAudience { get; }
    /// <summary>Gets Kubernetes service-account name constraints; other branches leave this null.</summary>
    [JsonIgnore] public string? AllowedNames { get; }
    /// <summary>Gets Kubernetes namespace constraints; other branches leave this null.</summary>
    [JsonIgnore] public string? AllowedNamespaces { get; }
    /// <summary>Gets Kubernetes CA certificate text; other branches leave this null.</summary>
    [JsonIgnore] public string? CaCertificate { get; }
    /// <summary>Gets returned Kubernetes gateway coordinate, or null for explicit null or another branch.</summary>
    [JsonIgnore] public string? GatewayId { get; }
    /// <summary>Gets returned Kubernetes gateway-pool coordinate, or null for explicit null or another branch.</summary>
    [JsonIgnore] public string? GatewayPoolId { get; }
    /// <summary>Gets reviewer-token presence metadata for Kubernetes; no token material is exported.</summary>
    [JsonIgnore] public bool? HasTokenReviewerJwt { get; }
    /// <summary>Gets Kubernetes host text; other branches leave this null.</summary>
    [JsonIgnore] public string? KubernetesHost { get; }
    /// <summary>Gets open native review-mode text; other branches leave this null.</summary>
    [JsonIgnore] public string? TokenReviewMode { get; }
    /// <summary>Gets reported provider-side TLS-verification state; other branches leave this null.</summary>
    [JsonIgnore] public bool? VerifyTlsCertificate { get; }
    /// <summary>Returns a marker without authentication configuration.</summary>
    public override string ToString() => "[GatewayAuthenticationSummary]";
}

/// <summary>Returned gateway configuration and heartbeat metadata, not deployment or current connectivity proof.</summary>
public sealed class GatewaySummary
{
    internal GatewaySummary(JsonElement value, string? id = null, string? name = null)
    {
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        if (name is not null) ManagementJson.RequireEqual(value, "name", name);
        Id = GatewayJson.Uuid(value, "id");
        Name = ManagementJson.Required(value, "name");
        CreatedAt = GatewayJson.Timestamp(value, "createdAt")!;
        UpdatedAt = GatewayJson.Timestamp(value, "updatedAt")!;
        CanRevoke = ManagementJson.Boolean(value, "canRevoke");
        Authentication = new(ManagementJson.Object(value, "authMethod"));
        HasDirectAddress = value.TryGetProperty("directAddress", out _);
        DirectAddress = GatewayJson.Text(value, "directAddress");
        HasDirectHeartbeat = value.TryGetProperty("directHeartbeat", out _);
        DirectHeartbeat = GatewayJson.Timestamp(value, "directHeartbeat", false, true);
        HasHeartbeat = value.TryGetProperty("heartbeat", out _);
        Heartbeat = GatewayJson.Timestamp(value, "heartbeat", false, true);
        HasHeartbeatTTL = value.TryGetProperty("heartbeatTTL", out var ttl);
        if (HasHeartbeatTTL && ttl.ValueKind != JsonValueKind.Null)
        {
            if (ttl.ValueKind != JsonValueKind.Number || !ttl.TryGetDouble(out double number) || !double.IsFinite(number))
                throw new ManagementContractException(SecretStatus.Unknown);
            HeartbeatTTL = number;
        }
        HasIdentityId = value.TryGetProperty("identityId", out _);
        IdentityId = GatewayJson.OptionalUuid(value, "identityId");
        HasRelayId = value.TryGetProperty("relayId", out _);
        RelayId = GatewayJson.OptionalUuid(value, "relayId");
    }
    /// <summary>Gets the returned gateway UUID matched to selection when requested.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned gateway name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the returned gateway creation timestamp.</summary>
    [JsonIgnore] public string CreatedAt { get; }
    /// <summary>Gets the returned gateway update timestamp.</summary>
    [JsonIgnore] public string UpdatedAt { get; }
    /// <summary>Gets the provider-authored revoke affordance; not an independent permission probe.</summary>
    [JsonIgnore] public bool CanRevoke { get; }
    /// <summary>Gets the typed returned authentication configuration.</summary>
    [JsonIgnore] public GatewayAuthenticationSummary Authentication { get; }
    /// <summary>Gets whether a direct-address field was returned, including explicit null.</summary>
    [JsonIgnore] public bool HasDirectAddress { get; }
    /// <summary>Gets direct-address text; use HasDirectAddress to distinguish omission.</summary>
    [JsonIgnore] public string? DirectAddress { get; }
    /// <summary>Gets whether direct-heartbeat time was returned, including explicit null.</summary>
    [JsonIgnore] public bool HasDirectHeartbeat { get; }
    /// <summary>Gets direct-heartbeat time; it does not establish current reachability.</summary>
    [JsonIgnore] public string? DirectHeartbeat { get; }
    /// <summary>Gets whether heartbeat time was returned, including explicit null.</summary>
    [JsonIgnore] public bool HasHeartbeat { get; }
    /// <summary>Gets reported heartbeat time; use HasHeartbeat to distinguish omission.</summary>
    [JsonIgnore] public string? Heartbeat { get; }
    /// <summary>Gets whether heartbeat TTL was returned, including explicit null.</summary>
    [JsonIgnore] public bool HasHeartbeatTTL { get; }
    /// <summary>Gets native heartbeat TTL without deriving a local liveness guarantee.</summary>
    [JsonIgnore] public double? HeartbeatTTL { get; }
    /// <summary>Gets whether an identity coordinate was returned, including explicit null.</summary>
    [JsonIgnore] public bool HasIdentityId { get; }
    /// <summary>Gets returned identity UUID; use HasIdentityId to distinguish omission.</summary>
    [JsonIgnore] public string? IdentityId { get; }
    /// <summary>Gets whether a relay coordinate was returned, including explicit null.</summary>
    [JsonIgnore] public bool HasRelayId { get; }
    /// <summary>Gets returned relay UUID; use HasRelayId to distinguish omission.</summary>
    [JsonIgnore] public string? RelayId { get; }
    /// <summary>Returns a marker without heartbeat or address details.</summary>
    public override string ToString() => "[GatewaySummary]";
}

/// <summary>Caller-owned enrollment material; disposal does not revoke it or enroll an agent.</summary>
public sealed class GatewayEnrollmentToken : IDisposable
{
    internal GatewayEnrollmentToken(JsonElement value)
    {
        ExpiresAt = GatewayJson.Timestamp(value, "expiresAt")!;
        Material = SecretMaterial.FromText(ManagementJson.Required(value, "token"));
    }
    /// <summary>Gets the provider-reported enrollment expiry timestamp.</summary>
    [JsonIgnore] public string ExpiresAt { get; }
    /// <summary>Gets owned enrollment material; revealing it creates ordinary plaintext.</summary>
    [JsonIgnore] public SecretMaterial Material { get; }
    /// <summary>Disposes enrollment material without revoking it or enrolling an agent.</summary>
    public void Dispose() => Material.Dispose();
    /// <summary>Returns a marker without enrollment material.</summary>
    public override string ToString() => "[GatewayEnrollmentToken]";
}
