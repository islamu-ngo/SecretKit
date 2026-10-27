using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Management;

/// <summary>Protected integration authorization metadata, never credentials or effective permissions.</summary>
public sealed class ProjectConnectionAuthorization
{
    internal ProjectConnectionAuthorization(JsonElement value, string projectId)
    {
        ManagementJson.RequireEqual(value, "projectId", projectId);
        Id = ManagementJson.Required(value, "id");
        ProjectId = ManagementJson.Required(value, "projectId");
        Integration = ManagementJson.Required(value, "integration");
        TeamId = ManagementJson.Optional(value, "teamId");
        Url = ManagementJson.Optional(value, "url");
        Namespace = ManagementJson.Optional(value, "namespace");
        AccountId = ManagementJson.Optional(value, "accountId");
        CreatedAt = ManagementJson.Required(value, "createdAt");
        UpdatedAt = ManagementJson.Required(value, "updatedAt");
    }

    /// <summary>Gets the returned integration authorization identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned project identifier checked against the request.</summary>
    [JsonIgnore] public string ProjectId { get; }
    /// <summary>Gets the native integration discriminator.</summary>
    [JsonIgnore] public string Integration { get; }
    /// <summary>Gets returned team coordinate, or null when not supplied.</summary>
    [JsonIgnore] public string? TeamId { get; }
    /// <summary>Gets returned integration URL, or null when not supplied.</summary>
    [JsonIgnore] public string? Url { get; }
    /// <summary>Gets returned namespace selector, or null when not supplied.</summary>
    [JsonIgnore] public string? Namespace { get; }
    /// <summary>Gets returned account coordinate, or null when not supplied.</summary>
    [JsonIgnore] public string? AccountId { get; }
    /// <summary>Gets the returned authorization creation timestamp.</summary>
    [JsonIgnore] public string CreatedAt { get; }
    /// <summary>Gets the returned authorization update timestamp.</summary>
    [JsonIgnore] public string UpdatedAt { get; }
    /// <summary>Always true: this projection checks the returned project coordinate.</summary>
    public bool HasProjectScopeAttestation => true;
    /// <summary>Always false: no returned organization coordinate is attested.</summary>
    public bool HasOrganizationScopeAttestation => false;
    /// <summary>Always false: arbitrary integration metadata is not exported.</summary>
    public bool IncludesMetadata => false;
    /// <summary>Returns a marker without authorization coordinates.</summary>
    public override string ToString() => "[ProjectConnectionAuthorization]";
}

/// <summary>Environment coordinates returned with an integration, without project attestation.</summary>
public sealed class ProjectConnectionEnvironment
{
    internal ProjectConnectionEnvironment(JsonElement value, string environmentId)
    {
        ManagementJson.RequireEqual(value, "id", environmentId);
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Required(value, "name");
        Slug = ManagementJson.Required(value, "slug");
    }

    /// <summary>Gets the returned environment identifier matched to the integration.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned environment name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the native environment slug.</summary>
    [JsonIgnore] public string Slug { get; }
    /// <summary>Returns a marker without environment coordinates.</summary>
    public override string ToString() => "[ProjectConnectionEnvironment]";
}

/// <summary>
/// Protected native integration configuration/status metadata. Returned rows do not
/// attest project or organization scope, successful secret delivery, or credentials.
/// </summary>
public sealed class ProjectConnectionIntegration
{
    internal ProjectConnectionIntegration(JsonElement value)
    {
        Id = ManagementJson.Required(value, "id");
        IsActive = ManagementJson.Boolean(value, "isActive");
        Integration = ManagementJson.Required(value, "integration");
        AuthorizationId = ManagementJson.Required(value, "integrationAuthId");
        EnvironmentId = ManagementJson.Required(value, "envId");
        Environment = new(ManagementJson.Object(value, "environment"), EnvironmentId);
        CreatedAt = ManagementJson.Required(value, "createdAt");
        UpdatedAt = ManagementJson.Required(value, "updatedAt");
        Url = ManagementJson.Optional(value, "url");
        App = ManagementJson.Optional(value, "app");
        AppId = ManagementJson.Optional(value, "appId");
        TargetEnvironment = ManagementJson.Optional(value, "targetEnvironment");
        TargetEnvironmentId = ManagementJson.Optional(value, "targetEnvironmentId");
        TargetService = ManagementJson.Optional(value, "targetService");
        TargetServiceId = ManagementJson.Optional(value, "targetServiceId");
        Owner = ManagementJson.Optional(value, "owner");
        Path = ManagementJson.Optional(value, "path");
        Region = ManagementJson.Optional(value, "region");
        Scope = ManagementJson.Optional(value, "scope");
        SecretPath = ManagementJson.Optional(value, "secretPath", nullable: false);
        LastUsed = ManagementJson.Optional(value, "lastUsed");
        LastSyncJobId = ManagementJson.Optional(value, "lastSyncJobId");
        IsSynced = value.TryGetProperty("isSynced", out JsonElement synced) && synced.ValueKind != JsonValueKind.Null
            ? ManagementJson.Boolean(value, "isSynced") : null;
    }

    /// <summary>Gets the returned integration identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the reported active switch, not successful delivery evidence.</summary>
    [JsonIgnore] public bool IsActive { get; }
    /// <summary>Gets the native integration discriminator.</summary>
    [JsonIgnore] public string Integration { get; }
    /// <summary>Gets the referenced integration authorization identifier.</summary>
    [JsonIgnore] public string AuthorizationId { get; }
    /// <summary>Gets the referenced environment identifier.</summary>
    [JsonIgnore] public string EnvironmentId { get; }
    /// <summary>Gets returned environment metadata matched to the reference.</summary>
    [JsonIgnore] public ProjectConnectionEnvironment Environment { get; }
    /// <summary>Gets the returned creation timestamp.</summary>
    [JsonIgnore] public string CreatedAt { get; }
    /// <summary>Gets the returned update timestamp.</summary>
    [JsonIgnore] public string UpdatedAt { get; }
    /// <summary>Gets returned endpoint URL, or null when not supplied.</summary>
    [JsonIgnore] public string? Url { get; }
    /// <summary>Gets returned application name, or null when not supplied.</summary>
    [JsonIgnore] public string? App { get; }
    /// <summary>Gets returned application identifier, or null when not supplied.</summary>
    [JsonIgnore] public string? AppId { get; }
    /// <summary>Gets returned target environment name, or null when not supplied.</summary>
    [JsonIgnore] public string? TargetEnvironment { get; }
    /// <summary>Gets returned target environment identifier, or null when not supplied.</summary>
    [JsonIgnore] public string? TargetEnvironmentId { get; }
    /// <summary>Gets returned target service name, or null when not supplied.</summary>
    [JsonIgnore] public string? TargetService { get; }
    /// <summary>Gets returned target service identifier, or null when not supplied.</summary>
    [JsonIgnore] public string? TargetServiceId { get; }
    /// <summary>Gets returned owner selector, or null when not supplied.</summary>
    [JsonIgnore] public string? Owner { get; }
    /// <summary>Gets returned destination path, or null when not supplied.</summary>
    [JsonIgnore] public string? Path { get; }
    /// <summary>Gets returned region selector, or null when not supplied.</summary>
    [JsonIgnore] public string? Region { get; }
    /// <summary>Gets returned native scope text, not an authorization attestation.</summary>
    [JsonIgnore] public string? Scope { get; }
    /// <summary>Gets returned source secret path, or null when omitted.</summary>
    [JsonIgnore] public string? SecretPath { get; }
    /// <summary>Gets reported last-use text, or null when not supplied.</summary>
    [JsonIgnore] public string? LastUsed { get; }
    /// <summary>Gets reported last-sync job identifier without attributing it to a caller action.</summary>
    [JsonIgnore] public string? LastSyncJobId { get; }
    /// <summary>Gets reported sync state, or null when absent or explicitly null; not delivery proof.</summary>
    [JsonIgnore] public bool? IsSynced { get; }
    /// <summary>Always false: integration rows do not attest project scope.</summary>
    public bool HasProjectScopeAttestation => false;
    /// <summary>Always false: integration rows do not attest organization scope.</summary>
    public bool HasOrganizationScopeAttestation => false;
    /// <summary>Always false: arbitrary integration metadata is not exported.</summary>
    public bool IncludesMetadata => false;
    /// <summary>Always false: native sync-message contents are not exported.</summary>
    public bool IncludesSyncMessage => false;
    /// <summary>Returns a marker without integration coordinates or status details.</summary>
    public override string ToString() => "[ProjectConnectionIntegration]";
}

/// <summary>Constructs disposable read-only native project integration metadata requests, not a connector runtime.</summary>
public static class ProjectConnectionOperations
{
    // Public interface facts: https://app.infisical.com/api/docs/json, version 0.0.1,
    // retrieved 2026-10-09. Only projectId is an input; neither endpoint is paginated.
    /// <summary>Builds bounded unpaged authorization inventory with returned project correspondence checks.</summary>
    public static ManagementRequest<ManagementPage<ProjectConnectionAuthorization>> ListAuthorizations(
        string organizationId, string projectId) =>
        new("infisical.get.v1.projects.by.projectId.authorizations", HttpMethod.Get,
            ProjectOperations.ProjectPath(projectId) + "/authorizations", new(organizationId, projectId), null,
            root => new(ManagementJson.Array(root, "authorizations")
                .Select(value => new ProjectConnectionAuthorization(value, projectId)), true), false);

    /// <summary>Builds bounded unpaged integration metadata inventory; returned rows do not attest scope or delivery.</summary>
    public static ManagementRequest<ManagementPage<ProjectConnectionIntegration>> ListIntegrations(
        string organizationId, string projectId) =>
        new("infisical.get.v1.projects.by.projectId.integrations", HttpMethod.Get,
            ProjectOperations.ProjectPath(projectId) + "/integrations", new(organizationId, projectId), null,
            root => new(ManagementJson.Array(root, "integrations")
                .Select(value => new ProjectConnectionIntegration(value)), true), false);
}
