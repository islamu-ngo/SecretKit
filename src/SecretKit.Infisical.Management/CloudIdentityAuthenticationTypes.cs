using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Management;

public enum GcpAuthConfigurationType { Iam, Gce }

/// <summary>Optional native AWS settings; null omits a field rather than clearing it.</summary>
public sealed class AwsAuthConfigurationInput
{
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
    [JsonIgnore] public string? AllowedPrincipalArns { get; }
    [JsonIgnore] public string? AllowedAccountIds { get; }
    [JsonIgnore] public string? StsEndpoint { get; }
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
    public override string ToString() => "[AwsAuthConfigurationInput]";
}

/// <summary>Attachment requires resource and tenant presence; update can omit them.</summary>
public sealed class AzureAuthConfigurationInput
{
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
    [JsonIgnore] public string? TenantId { get; }
    [JsonIgnore] public string? Resource { get; }
    [JsonIgnore] public string? AllowedServicePrincipalIds { get; }
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
    public override string ToString() => "[AzureAuthConfigurationInput]";
}

/// <summary>Explicit IAM/GCE selection on attachment, never ambient credential discovery.</summary>
public sealed class GcpAuthConfigurationInput
{
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
    [JsonIgnore] public GcpAuthConfigurationType? Type { get; }
    [JsonIgnore] public string? AllowedServiceAccounts { get; }
    [JsonIgnore] public string? AllowedProjects { get; }
    [JsonIgnore] public string? AllowedZones { get; }
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
    public override string ToString() => "[GcpAuthConfigurationInput]";
}

/// <summary>Allowed ARNs remain required for both attachment and update.</summary>
public sealed class AliCloudAuthConfigurationInput
{
    public AliCloudAuthConfigurationInput(string allowedArns, WorkloadAuthTokenPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(allowedArns);
        WorkloadAuthJson.Text(allowedArns, 500);
        if (allowedArns.Length == 0) throw new ArgumentException("AliCloud requires nonempty allowed ARNs.");
        AllowedArns = allowedArns;
        Policy = policy ?? new();
    }
    [JsonIgnore] public string AllowedArns { get; }
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
    [JsonIgnore] public string Type { get; }
    [JsonIgnore] public string AllowedPrincipalArns { get; }
    [JsonIgnore] public string AllowedAccountIds { get; }
    [JsonIgnore] public string StsEndpoint { get; }
    [JsonIgnore] public double? AccessTokenPeriod { get; }
}

public sealed class AzureAuthConfiguration : WorkloadAuthConfiguration
{
    internal AzureAuthConfiguration(JsonElement value, string identityId) : base(CloudAuthJson.Configuration(value), identityId)
    {
        TenantId = ManagementJson.Required(value, "tenantId");
        Resource = ManagementJson.Required(value, "resource");
        AllowedServicePrincipalIds = ManagementJson.Required(value, "allowedServicePrincipalIds");
        AccessTokenPeriod = WorkloadAuthJson.Number(value, "accessTokenPeriod");
    }
    [JsonIgnore] public string TenantId { get; }
    [JsonIgnore] public string Resource { get; }
    [JsonIgnore] public string AllowedServicePrincipalIds { get; }
    [JsonIgnore] public double? AccessTokenPeriod { get; }
}

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
    [JsonIgnore] public string Type { get; }
    [JsonIgnore] public ProjectField<string> AllowedProjects { get; }
    [JsonIgnore] public ProjectField<string> AllowedServiceAccounts { get; }
    [JsonIgnore] public ProjectField<string> AllowedZones { get; }
    [JsonIgnore] public double? AccessTokenPeriod { get; }
}

public sealed class AliCloudAuthConfiguration : WorkloadAuthConfiguration
{
    internal AliCloudAuthConfiguration(JsonElement value, string identityId) : base(CloudAuthJson.Configuration(value), identityId)
    {
        Type = ManagementJson.Required(value, "type");
        AllowedArns = ManagementJson.Required(value, "allowedArns");
    }
    [JsonIgnore] public string Type { get; }
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
