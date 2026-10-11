using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

public enum GatewayGcpType { Gce, Iam }
public enum GatewayTokenReviewMode { Api, Gateway }
public enum GatewayAuthenticationMethod { Aws, Gcp, Kubernetes, Token, Identity }

/// <summary>Supplied nullable UUID. No wrapper means omission, not JSON null.</summary>
public sealed class GatewayNullableId
{
    public GatewayNullableId(string? value)
    {
        if (value is not null) GatewayJson.UuidInput(value);
        Value = value;
    }
    [JsonIgnore] public string? Value { get; }
    public override string ToString() => "[GatewayNullableId]";
}

/// <summary>Copied, disposable, typed gateway authentication input. No identity request branch is published.</summary>
public sealed class GatewayAuthenticationInput : IDisposable
{
    private readonly object _gate = new();
    private byte[]? _body;
    private GatewayAuthenticationInput(Action<Utf8JsonWriter> write) => _body = GatewayJson.Serialize(write);

    // field-17354/17358 permit empty strings and omission independently; no SDK defaults.
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
    public void Dispose() { lock (_gate) { if (_body is not null) Array.Clear(_body); _body = null; } }
    public override string ToString() => "[GatewayAuthenticationInput]";
}

public sealed class GatewayCreation
{
    private readonly GatewayAuthenticationInput _authentication;
    [JsonIgnore] public string Name { get; }
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
    public override string ToString() => "[GatewayCreation]";
}

public sealed class GatewayUpdate
{
    private readonly string? _name;
    private readonly GatewayAuthenticationInput? _authentication;
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
    [JsonIgnore] public GatewayAuthenticationMethod Method { get; }
    [JsonIgnore] public string? Id { get; }
    [JsonIgnore] public string? CreatedAt { get; }
    [JsonIgnore] public string? UpdatedAt { get; }
    [JsonIgnore] public string? AllowedAccountIds { get; }
    [JsonIgnore] public string? AllowedPrincipalArns { get; }
    [JsonIgnore] public string? AllowedProjects { get; }
    [JsonIgnore] public string? AllowedServiceAccounts { get; }
    [JsonIgnore] public string? AllowedZones { get; }
    [JsonIgnore] public string? Type { get; }
    [JsonIgnore] public string? IdentityId { get; }
    [JsonIgnore] public string? IdentityName { get; }
    [JsonIgnore] public string? AllowedAudience { get; }
    [JsonIgnore] public string? AllowedNames { get; }
    [JsonIgnore] public string? AllowedNamespaces { get; }
    [JsonIgnore] public string? CaCertificate { get; }
    [JsonIgnore] public string? GatewayId { get; }
    [JsonIgnore] public string? GatewayPoolId { get; }
    [JsonIgnore] public bool? HasTokenReviewerJwt { get; }
    [JsonIgnore] public string? KubernetesHost { get; }
    [JsonIgnore] public string? TokenReviewMode { get; }
    [JsonIgnore] public bool? VerifyTlsCertificate { get; }
    public override string ToString() => "[GatewayAuthenticationSummary]";
}

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
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string CreatedAt { get; }
    [JsonIgnore] public string UpdatedAt { get; }
    [JsonIgnore] public bool CanRevoke { get; }
    [JsonIgnore] public GatewayAuthenticationSummary Authentication { get; }
    [JsonIgnore] public bool HasDirectAddress { get; }
    [JsonIgnore] public string? DirectAddress { get; }
    [JsonIgnore] public bool HasDirectHeartbeat { get; }
    [JsonIgnore] public string? DirectHeartbeat { get; }
    [JsonIgnore] public bool HasHeartbeat { get; }
    [JsonIgnore] public string? Heartbeat { get; }
    [JsonIgnore] public bool HasHeartbeatTTL { get; }
    [JsonIgnore] public double? HeartbeatTTL { get; }
    [JsonIgnore] public bool HasIdentityId { get; }
    [JsonIgnore] public string? IdentityId { get; }
    [JsonIgnore] public bool HasRelayId { get; }
    [JsonIgnore] public string? RelayId { get; }
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
    [JsonIgnore] public string ExpiresAt { get; }
    [JsonIgnore] public SecretMaterial Material { get; }
    public void Dispose() => Material.Dispose();
    public override string ToString() => "[GatewayEnrollmentToken]";
}
