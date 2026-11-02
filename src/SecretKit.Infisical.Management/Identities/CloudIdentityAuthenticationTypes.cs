using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Management;

/// <summary>Native GCP identity authentication configuration strategies.</summary>
public enum GcpAuthConfigurationType { /** <summary>Selects IAM proof authentication.</summary> */ Iam, /** <summary>Selects Compute Engine proof authentication.</summary> */ Gce }

/// <summary>Optional native AWS settings; null omits a field rather than clearing it.</summary>
public sealed class AwsAuthConfigurationInput
{
    /// <summary>Captures optional AWS settings; null fields are omitted and a null policy supplies an all-omitted policy.</summary>
    public AwsAuthConfigurationInput(string? allowedPrincipalArns = null, string? allowedAccountIds = null,
        string? stsEndpoint = null, WorkloadAuthTokenPolicy? policy = null)
    {
        WorkloadAuthJson.Text(allowedPrincipalArns, 4096);
        WorkloadAuthJson.Text(allowedAccountIds, 4096);
        WorkloadAuthJson.Text(stsEndpoint);
        if (stsEndpoint is { Length: 0 }) throw new ArgumentException("STS endpoint must be nonempty.");
        AllowedPrincipalArns = allowedPrincipalArns;
        AllowedAccountIds = allowedAccountIds;
        StsEndpoint = stsEndpoint;
        Policy = policy ?? new();
    }
    /// <summary>Gets allowed principal ARNs, or null to leave the setting omitted.</summary>
    [JsonIgnore] public string? AllowedPrincipalArns { get; }
    /// <summary>Gets allowed account identifiers, or null to omit the setting.</summary>
    [JsonIgnore] public string? AllowedAccountIds { get; }
    /// <summary>Gets the selected STS endpoint, or null to omit it.</summary>
    [JsonIgnore] public string? StsEndpoint { get; }
    /// <summary>Gets the token policy whose individual null fields remain omitted.</summary>
    [JsonIgnore] public WorkloadAuthTokenPolicy Policy { get; }
    internal void ValidateAttach()
    {
        if (Policy.AccessTokenMaxTTL == 0) throw new ArgumentException("AWS attachment requires a positive maximum TTL.");
    }
    internal void Write(Utf8JsonWriter writer)
    {
        WorkloadAuthJson.String(writer, "allowedPrincipalArns", AllowedPrincipalArns);
        WorkloadAuthJson.String(writer, "allowedAccountIds", AllowedAccountIds);
        WorkloadAuthJson.String(writer, "stsEndpoint", StsEndpoint);
        Policy.Write(writer);
    }
    /// <summary>Returns a marker without cloud selectors.</summary>
    public override string ToString() => "[AwsAuthConfigurationInput]";
}

/// <summary>Attachment requires resource and tenant presence; update can omit them.</summary>
public sealed class AzureAuthConfigurationInput
{
    /// <summary>Captures optional Azure settings; attachment later requires tenant and resource presence.</summary>
    public AzureAuthConfigurationInput(string? tenantId = null, string? resource = null,
        string? allowedServicePrincipalIds = null, WorkloadAuthTokenPolicy? policy = null)
    {
        WorkloadAuthJson.Text(tenantId);
        WorkloadAuthJson.Text(resource);
        WorkloadAuthJson.Text(allowedServicePrincipalIds);
        TenantId = tenantId;
        Resource = resource;
        AllowedServicePrincipalIds = allowedServicePrincipalIds;
        Policy = policy ?? new();
    }
    /// <summary>Gets the tenant selector, or null to omit it on update.</summary>
    [JsonIgnore] public string? TenantId { get; }
    /// <summary>Gets the resource selector, or null to omit it on update.</summary>
    [JsonIgnore] public string? Resource { get; }
    /// <summary>Gets allowed service-principal selectors, or null to omit them.</summary>
    [JsonIgnore] public string? AllowedServicePrincipalIds { get; }
    /// <summary>Gets the explicit token-policy fields, with no inferred provider defaults.</summary>
    [JsonIgnore] public WorkloadAuthTokenPolicy Policy { get; }
    internal void ValidateAttach()
    {
        if (TenantId is null || Resource is null) throw new ArgumentException("Azure attachment requires tenant and resource.");
    }
    internal void Write(Utf8JsonWriter writer)
    {
        WorkloadAuthJson.String(writer, "tenantId", TenantId);
        WorkloadAuthJson.String(writer, "resource", Resource);
        WorkloadAuthJson.String(writer, "allowedServicePrincipalIds", AllowedServicePrincipalIds);
        Policy.Write(writer);
    }
    /// <summary>Returns a marker without tenant or resource selectors.</summary>
    public override string ToString() => "[AzureAuthConfigurationInput]";
}

/// <summary>Explicit IAM/GCE selection on attachment, never ambient credential discovery.</summary>
public sealed class GcpAuthConfigurationInput
{
    /// <summary>Captures GCP settings; a null type can be omitted on update, not attachment.</summary>
    public GcpAuthConfigurationInput(GcpAuthConfigurationType? type = null, string? allowedServiceAccounts = null,
        string? allowedProjects = null, string? allowedZones = null, WorkloadAuthTokenPolicy? policy = null)
    {
        if (type is { } selected && !Enum.IsDefined(selected)) throw new ArgumentException("Invalid GCP configuration type.");
        WorkloadAuthJson.Text(allowedServiceAccounts);
        WorkloadAuthJson.Text(allowedProjects);
        WorkloadAuthJson.Text(allowedZones);
        Type = type;
        AllowedServiceAccounts = allowedServiceAccounts;
        AllowedProjects = allowedProjects;
        AllowedZones = allowedZones;
        Policy = policy ?? new();
    }
    /// <summary>Gets the IAM/GCE discriminator, or null when omitted.</summary>
    [JsonIgnore] public GcpAuthConfigurationType? Type { get; }
    /// <summary>Gets allowed service-account selectors, or null when omitted.</summary>
    [JsonIgnore] public string? AllowedServiceAccounts { get; }
    /// <summary>Gets allowed project selectors, or null when omitted.</summary>
    [JsonIgnore] public string? AllowedProjects { get; }
    /// <summary>Gets allowed zone selectors, or null when omitted.</summary>
    [JsonIgnore] public string? AllowedZones { get; }
    /// <summary>Gets the token-policy field selections.</summary>
    [JsonIgnore] public WorkloadAuthTokenPolicy Policy { get; }
    internal void ValidateAttach()
    {
        if (Type is null) throw new ArgumentException("GCP attachment requires an explicit type.");
    }
    internal void Write(Utf8JsonWriter writer)
    {
        if (Type is { } type) writer.WriteString("type", type == GcpAuthConfigurationType.Iam ? "iam" : "gce");
        WorkloadAuthJson.String(writer, "allowedServiceAccounts", AllowedServiceAccounts);
        WorkloadAuthJson.String(writer, "allowedProjects", AllowedProjects);
        WorkloadAuthJson.String(writer, "allowedZones", AllowedZones);
        Policy.Write(writer);
    }
    /// <summary>Returns a marker without GCP selectors.</summary>
    public override string ToString() => "[GcpAuthConfigurationInput]";
}

/// <summary>Allowed ARNs remain required for both attachment and update.</summary>
public sealed class AliCloudAuthConfigurationInput
{
    /// <summary>Captures required nonempty allowed ARNs and optional token policy for AliCloud.</summary>
    public AliCloudAuthConfigurationInput(string allowedArns, WorkloadAuthTokenPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(allowedArns);
        WorkloadAuthJson.Text(allowedArns, 500);
        if (allowedArns.Length == 0) throw new ArgumentException("AliCloud requires nonempty allowed ARNs.");
        AllowedArns = allowedArns;
        Policy = policy ?? new();
    }
    /// <summary>Gets the explicitly selected allowed ARNs.</summary>
    [JsonIgnore] public string AllowedArns { get; }
    /// <summary>Gets the selected token-policy fields; null constructor policy omits them.</summary>
    [JsonIgnore] public WorkloadAuthTokenPolicy Policy { get; }
    internal void ValidateAttach()
    {
        if (Policy.AccessTokenMaxTTL == 0) throw new ArgumentException("AliCloud attachment requires a positive maximum TTL.");
    }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteString("allowedArns", AllowedArns);
        Policy.Write(writer);
    }
    /// <summary>Returns a marker without allowed ARNs.</summary>
    public override string ToString() => "[AliCloudAuthConfigurationInput]";
}

/// <summary>Known native response fields only. No request-to-response type inference.</summary>
public sealed class AwsAuthConfiguration : WorkloadAuthConfiguration
{
    internal AwsAuthConfiguration(JsonElement value, string identityId) : base(CloudAuthJson.Configuration(value), identityId)
    {
        Type = ManagementJson.Required(value, "type");
        AllowedPrincipalArns = ManagementJson.Required(value, "allowedPrincipalArns");
        AllowedAccountIds = ManagementJson.Required(value, "allowedAccountIds");
        StsEndpoint = ManagementJson.Required(value, "stsEndpoint");
        AccessTokenPeriod = WorkloadAuthJson.Number(value, "accessTokenPeriod");
    }
    /// <summary>Gets the native returned AWS authentication type.</summary>
    [JsonIgnore] public string Type { get; }
    /// <summary>Gets the returned allowed principal ARN selectors.</summary>
    [JsonIgnore] public string AllowedPrincipalArns { get; }
    /// <summary>Gets the returned allowed account selectors.</summary>
    [JsonIgnore] public string AllowedAccountIds { get; }
    /// <summary>Gets the returned STS endpoint.</summary>
    [JsonIgnore] public string StsEndpoint { get; }
    /// <summary>Gets the returned token period in seconds, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenPeriod { get; }
}

/// <summary>Returned Azure authentication settings, not proof that the identity can authenticate.</summary>
public sealed class AzureAuthConfiguration : WorkloadAuthConfiguration
{
    internal AzureAuthConfiguration(JsonElement value, string identityId) : base(CloudAuthJson.Configuration(value), identityId)
    {
        TenantId = ManagementJson.Required(value, "tenantId");
        Resource = ManagementJson.Required(value, "resource");
        AllowedServicePrincipalIds = ManagementJson.Required(value, "allowedServicePrincipalIds");
        AccessTokenPeriod = WorkloadAuthJson.Number(value, "accessTokenPeriod");
    }
    /// <summary>Gets the returned tenant identifier.</summary>
    [JsonIgnore] public string TenantId { get; }
    /// <summary>Gets the returned resource selector.</summary>
    [JsonIgnore] public string Resource { get; }
    /// <summary>Gets the returned allowed service-principal identifiers.</summary>
    [JsonIgnore] public string AllowedServicePrincipalIds { get; }
    /// <summary>Gets the returned token period in seconds, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenPeriod { get; }
}

/// <summary>Returned GCP authentication settings without request-derived defaults.</summary>
public sealed class GcpAuthConfiguration : WorkloadAuthConfiguration
{
    internal GcpAuthConfiguration(JsonElement value, string identityId) : base(CloudAuthJson.Configuration(value), identityId)
    {
        Type = ManagementJson.Required(value, "type");
        AllowedProjects = WorkloadAuthJson.NullableResponse(value, "allowedProjects");
        AllowedServiceAccounts = WorkloadAuthJson.NullableResponse(value, "allowedServiceAccounts");
        AllowedZones = WorkloadAuthJson.NullableResponse(value, "allowedZones");
        AccessTokenPeriod = WorkloadAuthJson.Number(value, "accessTokenPeriod");
    }
    /// <summary>Gets the native returned IAM/GCE type.</summary>
    [JsonIgnore] public string Type { get; }
    /// <summary>Gets allowed-project presence, preserving explicit null and omission.</summary>
    [JsonIgnore] public ProjectField<string> AllowedProjects { get; }
    /// <summary>Gets allowed-service-account presence, preserving explicit null and omission.</summary>
    [JsonIgnore] public ProjectField<string> AllowedServiceAccounts { get; }
    /// <summary>Gets allowed-zone presence, preserving explicit null and omission.</summary>
    [JsonIgnore] public ProjectField<string> AllowedZones { get; }
    /// <summary>Gets the returned token period in seconds, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenPeriod { get; }
}

/// <summary>Returned AliCloud authentication settings, not an effective authorization decision.</summary>
public sealed class AliCloudAuthConfiguration : WorkloadAuthConfiguration
{
    internal AliCloudAuthConfiguration(JsonElement value, string identityId) : base(CloudAuthJson.Configuration(value), identityId)
    {
        Type = ManagementJson.Required(value, "type");
        AllowedArns = ManagementJson.Required(value, "allowedArns");
    }
    /// <summary>Gets the native returned authentication type.</summary>
    [JsonIgnore] public string Type { get; }
    /// <summary>Gets the returned allowed ARN selectors.</summary>
    [JsonIgnore] public string AllowedArns { get; }
}

internal static class CloudAuthJson
{
    internal static JsonElement Configuration(JsonElement value)
    {
        // Check primitive kinds before the shared date parser calls TryGetDateTimeOffset.
        ManagementJson.Required(value, "createdAt");
        ManagementJson.Required(value, "updatedAt");
        return value;
    }
}
