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

    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string ProjectId { get; }
    [JsonIgnore] public string Integration { get; }
    [JsonIgnore] public string? TeamId { get; }
    [JsonIgnore] public string? Url { get; }
    [JsonIgnore] public string? Namespace { get; }
    [JsonIgnore] public string? AccountId { get; }
    [JsonIgnore] public string CreatedAt { get; }
    [JsonIgnore] public string UpdatedAt { get; }
    public bool HasProjectScopeAttestation => true;
    public bool HasOrganizationScopeAttestation => false;
    public bool IncludesMetadata => false;
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

    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Slug { get; }
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

    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public bool IsActive { get; }
    [JsonIgnore] public string Integration { get; }
    [JsonIgnore] public string AuthorizationId { get; }
    [JsonIgnore] public string EnvironmentId { get; }
    [JsonIgnore] public ProjectConnectionEnvironment Environment { get; }
    [JsonIgnore] public string CreatedAt { get; }
    [JsonIgnore] public string UpdatedAt { get; }
    [JsonIgnore] public string? Url { get; }
    [JsonIgnore] public string? App { get; }
    [JsonIgnore] public string? AppId { get; }
    [JsonIgnore] public string? TargetEnvironment { get; }
    [JsonIgnore] public string? TargetEnvironmentId { get; }
    [JsonIgnore] public string? TargetService { get; }
    [JsonIgnore] public string? TargetServiceId { get; }
    [JsonIgnore] public string? Owner { get; }
    [JsonIgnore] public string? Path { get; }
    [JsonIgnore] public string? Region { get; }
    [JsonIgnore] public string? Scope { get; }
    [JsonIgnore] public string? SecretPath { get; }
    [JsonIgnore] public string? LastUsed { get; }
    [JsonIgnore] public string? LastSyncJobId { get; }
    [JsonIgnore] public bool? IsSynced { get; }
    public bool HasProjectScopeAttestation => false;
    public bool HasOrganizationScopeAttestation => false;
    public bool IncludesMetadata => false;
    public bool IncludesSyncMessage => false;
    public override string ToString() => "[ProjectConnectionIntegration]";
}

public static class ProjectConnectionOperations
{
    // Public interface facts: https://app.infisical.com/api/docs/json, version 0.0.1,
    // retrieved 2026-10-09. Only projectId is an input; neither endpoint is paginated.
    public static ManagementRequest<ManagementPage<ProjectConnectionAuthorization>> ListAuthorizations(
        string organizationId, string projectId) =>
        new("infisical.get.v1.projects.by.projectId.authorizations", HttpMethod.Get,
            ProjectOperations.ProjectPath(projectId) + "/authorizations", new(organizationId, projectId), null,
            root => new(ManagementJson.Array(root, "authorizations")
                .Select(value => new ProjectConnectionAuthorization(value, projectId)), true), false);

    public static ManagementRequest<ManagementPage<ProjectConnectionIntegration>> ListIntegrations(
        string organizationId, string projectId) =>
        new("infisical.get.v1.projects.by.projectId.integrations", HttpMethod.Get,
            ProjectOperations.ProjectPath(projectId) + "/integrations", new(organizationId, projectId), null,
            root => new(ManagementJson.Array(root, "integrations")
                .Select(value => new ProjectConnectionIntegration(value)), true), false);
}
