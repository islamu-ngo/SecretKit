using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Project identity and lifecycle metadata, not secret data or effective permissions.</summary>
public sealed class ProjectSummary
{
    internal ProjectSummary(JsonElement value, string organizationId, string? id = null, string? slug = null)
    {
        ManagementJson.RequireEqual(value, "orgId", organizationId);
        ManagementJson.RequireEqual(value, "type", "secret-manager");
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        if (slug is not null) ManagementJson.RequireEqual(value, "slug", slug);
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Required(value, "name");
        Slug = ManagementJson.Required(value, "slug");
        Description = ManagementJson.Optional(value, "description");
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Slug { get; }
    [JsonIgnore] public string? Description { get; }
    public override string ToString() => "[ProjectSummary]";
}

public sealed class ProjectEnvironment
{
    internal ProjectEnvironment(JsonElement value, string projectId, string? id = null, string? slug = null)
    {
        ManagementJson.RequireEqual(value, "projectId", projectId);
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        if (slug is not null) ManagementJson.RequireEqual(value, "slug", slug);
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Required(value, "name");
        Slug = ManagementJson.Required(value, "slug");
        Position = ManagementJson.Integer(value, "position");
        SoftDeletedAt = ManagementJson.Optional(value, "softDeletedAt");
        DeleteAfter = ManagementJson.Optional(value, "deleteAfter");
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Slug { get; }
    public int Position { get; }
    [JsonIgnore] public string? SoftDeletedAt { get; }
    [JsonIgnore] public string? DeleteAfter { get; }
    public override string ToString() => "[ProjectEnvironment]";
}

public sealed class ProjectTag
{
    internal ProjectTag(JsonElement value, string projectId, string? id = null, string? slug = null)
    {
        ManagementJson.RequireEqual(value, "projectId", projectId);
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        if (slug is not null) ManagementJson.RequireEqual(value, "slug", slug);
        Id = ManagementJson.Required(value, "id");
        Slug = ManagementJson.Required(value, "slug");
        Color = ManagementJson.Optional(value, "color");
        Name = ManagementJson.Optional(value, "name");
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Slug { get; }
    [JsonIgnore] public string? Color { get; }
    [JsonIgnore] public string? Name { get; }
    public override string ToString() => "[ProjectTag]";
}

public static class ProjectOperations
{
    public static ManagementRequest<ManagementPage<ProjectSummary>> ListProjects(string organizationId) =>
        new("infisical.get.v1.projects", HttpMethod.Get, "/api/v1/projects?type=secret-manager&includeRoles=false",
            new(organizationId), null, root => new(ManagementJson.Array(root, "projects")
                .Select(value => new ProjectSummary(value, organizationId)), true), false);

    public static ManagementRequest<ProjectSummary> GetProject(string organizationId, string projectId) =>
        new("infisical.get.v1.projects.by.projectId", HttpMethod.Get, ProjectPath(projectId),
            new(organizationId, projectId), null,
            root => new(ManagementJson.Object(root, "project"), organizationId, projectId), false);

    public static ManagementRequest<ProjectSummary> GetProjectBySlug(string organizationId, string projectSlug) =>
        new("infisical.get.v1.projects.slug.by.slug", HttpMethod.Get,
            "/api/v1/projects/slug/" + ManagementJson.Escape(projectSlug),
            new(organizationId, resourceId: projectSlug), null,
            root => new(root, organizationId, slug: projectSlug), false);

    public static ManagementRequest<ProjectSummary> CreateProject(string organizationId, string name, string slug,
        string? description = null, bool deleteProtection = false, bool createDefaultEnvironments = true,
        string? template = null, string? kmsKeyId = null)
    {
        ManagementJson.Text(name, 64);
        ManagementJson.Text(slug, 64);
        if (slug.Length < 5) throw new ArgumentException("Invalid project slug length.");
        if (description is not null) ManagementJson.Text(description);
        if (template is not null) ManagementJson.Text(template, 64);
        if (kmsKeyId is not null) ManagementJson.Text(kmsKeyId);
        return new("infisical.post.v1.projects", HttpMethod.Post, "/api/v1/projects",
            new(organizationId, resourceId: slug), writer =>
            {
                writer.WriteStartObject();
                writer.WriteString("projectName", name);
                writer.WriteString("slug", slug);
                writer.WriteString("type", "secret-manager");
                writer.WriteBoolean("hasDeleteProtection", deleteProtection);
                writer.WriteBoolean("shouldCreateDefaultEnvs", createDefaultEnvironments);
                if (description is not null) writer.WriteString("projectDescription", description);
                if (template is not null) writer.WriteString("template", template);
                if (kmsKeyId is not null) writer.WriteString("kmsKeyId", kmsKeyId);
                writer.WriteEndObject();
            }, root => new(ManagementJson.Object(root, "project"), organizationId, slug: slug));
    }

    public static ManagementRequest<ProjectSummary> UpdateProject(string organizationId, string projectId,
        string? name = null, string? slug = null, string? description = null, bool? deleteProtection = null,
        int? auditRetentionDays = null, bool? secretSharing = null, bool? autoCapitalization = null,
        bool? encryptedMetadata = null, int? pointInTimeVersionLimit = null, bool? showLegacySnapshots = null)
    {
        if (name is not null) ManagementJson.Text(name, 64);
        if (slug is not null) ManagementJson.Text(slug, 64);
        if (description is not null && (description.Length > 1024 || description.Any(char.IsControl)))
            throw new ArgumentException("Invalid project description.");
        if (auditRetentionDays is < 1 or > 365 || pointInTimeVersionLimit is < 1 or > 100)
            throw new ArgumentException("Invalid project retention bounds.");
        if (name is null && slug is null && description is null && deleteProtection is null &&
            auditRetentionDays is null && secretSharing is null && autoCapitalization is null &&
            encryptedMetadata is null && pointInTimeVersionLimit is null && showLegacySnapshots is null)
            throw new ArgumentException("A project change is required.");
        return new("infisical.patch.v1.projects.by.projectId", HttpMethod.Patch, ProjectPath(projectId),
            new(organizationId, projectId), writer =>
            {
                writer.WriteStartObject();
                if (name is not null) writer.WriteString("name", name);
                if (slug is not null) writer.WriteString("slug", slug);
                if (description is not null) writer.WriteString("description", description);
                if (deleteProtection is { } protection) writer.WriteBoolean("hasDeleteProtection", protection);
                if (auditRetentionDays is { } days) writer.WriteNumber("auditLogsRetentionDays", days);
                if (secretSharing is { } sharing) writer.WriteBoolean("secretSharing", sharing);
                if (autoCapitalization is { } caps) writer.WriteBoolean("autoCapitalization", caps);
                if (encryptedMetadata is { } encryption) writer.WriteBoolean("enforceEncryptedSecretManagerSecretMetadata", encryption);
                if (pointInTimeVersionLimit is { } versions) writer.WriteNumber("pitVersionLimit", versions);
                if (showLegacySnapshots is { } snapshots) writer.WriteBoolean("showSnapshotsLegacy", snapshots);
                writer.WriteEndObject();
            }, root => new(ManagementJson.Object(root, "project"), organizationId, projectId));
    }

    public static ManagementRequest<ProjectSummary> DeleteProject(string organizationId, string projectId) =>
        new("infisical.delete.v1.projects.by.projectId", HttpMethod.Delete, ProjectPath(projectId),
            new(organizationId, projectId), null,
            root => new(ManagementJson.Object(root, "project"), organizationId, projectId));

    public static ManagementRequest<ProjectEnvironment> CreateEnvironment(string organizationId, string projectId,
        string name, string slug, int? position = null)
    {
        EnvironmentFields(name, slug);
        if (position is < 1) throw new ArgumentException("Invalid environment position.");
        return new("infisical.post.v1.projects.by.projectId.environments", HttpMethod.Post,
            ProjectPath(projectId) + "/environments", new(organizationId, projectId, slug),
            writer => WriteEnvironment(writer, name, slug, position),
            root => EnvironmentResult(root, projectId, null, slug, true));
    }

    public static ManagementRequest<ProjectEnvironment> GetEnvironment(string organizationId, string projectId, string environmentId) =>
        new("infisical.get.v1.projects.by.projectId.environments.by.envId", HttpMethod.Get,
            EnvironmentPath(projectId, environmentId), new(organizationId, projectId, environmentId), null,
            root => EnvironmentResult(root, projectId, environmentId, null, false), false);

    public static ManagementRequest<ProjectEnvironment> GetEnvironmentBySlug(string organizationId, string projectId, string slug) =>
        new("infisical.get.v1.projects.by.projectId.environments.slug.by.envSlug", HttpMethod.Get,
            ProjectPath(projectId) + "/environments/slug/" + ManagementJson.Escape(slug),
            new(organizationId, projectId, slug), null,
            root => EnvironmentResult(root, projectId, null, slug, false), false);

    public static ManagementRequest<ProjectEnvironment> UpdateEnvironment(string organizationId, string projectId,
        string environmentId, string? name = null, string? slug = null, int? position = null)
    {
        EnvironmentFields(name, slug);
        if (name is null && slug is null && position is null) throw new ArgumentException("An environment change is required.");
        return new("infisical.patch.v1.projects.by.projectId.environments.by.id", HttpMethod.Patch,
            EnvironmentPath(projectId, environmentId), new(organizationId, projectId, environmentId),
            writer => WriteEnvironment(writer, name, slug, position),
            root => EnvironmentResult(root, projectId, environmentId, null, true));
    }

    public static ManagementRequest<ProjectEnvironment> DeleteEnvironment(string organizationId, string projectId,
        string environmentId, bool permanently = false) =>
        new("infisical.delete.v1.projects.by.projectId.environments.by.id", HttpMethod.Delete,
            EnvironmentPath(projectId, environmentId) + "?hardDelete=" + (permanently ? "true" : "false"),
            new(organizationId, projectId, environmentId, permanently ? "hard-delete" : "soft-delete"), null,
            root => EnvironmentResult(root, projectId, environmentId, null, true));

    public static ManagementRequest<ProjectEnvironment> RestoreEnvironment(string organizationId, string projectId, string environmentId) =>
        new("infisical.post.v1.projects.by.projectId.environments.by.id.restore", HttpMethod.Post,
            EnvironmentPath(projectId, environmentId) + "/restore", new(organizationId, projectId, environmentId), null,
            root => EnvironmentResult(root, projectId, environmentId, null, true));

    public static ManagementRequest<ManagementPage<ProjectTag>> ListTags(string organizationId, string projectId) =>
        new("infisical.get.v1.projects.by.projectId.tags", HttpMethod.Get, ProjectPath(projectId) + "/tags",
            new(organizationId, projectId), null, root => new(ManagementJson.Array(root, "tags")
                .Select(value => new ProjectTag(value, projectId)), true), false);

    public static ManagementRequest<ProjectTag> GetTag(string organizationId, string projectId, string tagId) =>
        new("infisical.get.v1.projects.by.projectId.tags.by.tagId", HttpMethod.Get, TagPath(projectId, tagId),
            new(organizationId, projectId, tagId), null,
            root => new(ManagementJson.Object(root, "tag"), projectId, tagId), false);

    public static ManagementRequest<ProjectTag> GetTagBySlug(string organizationId, string projectId, string slug) =>
        new("infisical.get.v1.projects.by.projectId.tags.slug.by.tagSlug", HttpMethod.Get,
            ProjectPath(projectId) + "/tags/slug/" + ManagementJson.Escape(slug), new(organizationId, projectId, slug), null,
            root => new(ManagementJson.Object(root, "tag"), projectId, slug: slug), false);

    public static ManagementRequest<ProjectTag> CreateTag(string organizationId, string projectId, string slug, string color)
    {
        ManagementJson.Text(slug, 64);
        ManagementJson.Text(color, 64);
        return new("infisical.post.v1.projects.by.projectId.tags", HttpMethod.Post, ProjectPath(projectId) + "/tags",
            new(organizationId, projectId, slug), writer => WriteTag(writer, slug, color),
            root => new(ManagementJson.Object(root, "tag"), projectId, slug: slug));
    }

    public static ManagementRequest<ProjectTag> UpdateTag(string organizationId, string projectId, string tagId, string slug, string color)
    {
        ManagementJson.Text(slug, 64);
        ManagementJson.Text(color, 64);
        return new("infisical.patch.v1.projects.by.projectId.tags.by.tagId", HttpMethod.Patch, TagPath(projectId, tagId),
            new(organizationId, projectId, tagId), writer => WriteTag(writer, slug, color),
            root => new(ManagementJson.Object(root, "tag"), projectId, tagId));
    }

    public static ManagementRequest<ProjectTag> DeleteTag(string organizationId, string projectId, string tagId) =>
        new("infisical.delete.v1.projects.by.projectId.tags.by.tagId", HttpMethod.Delete, TagPath(projectId, tagId),
            new(organizationId, projectId, tagId), null,
            root => new(ManagementJson.Object(root, "tag"), projectId, tagId));

    public static ManagementRequest<ManagementPage<RoleSummary>> ListProjectRoles(string organizationId, string projectId) =>
        new("infisical.get.v1.projects.by.projectId.roles", HttpMethod.Get, ProjectPath(projectId) + "/roles",
            new(organizationId, projectId), null, root => new(ManagementJson.Array(root, "roles")
                .Select(value => new RoleSummary(value, "projectId", projectId)), true), false);

    public static ManagementRequest<RoleSummary> GetProjectRole(string organizationId, string projectId, string roleId) =>
        new("infisical.get.v1.projects.roles.by.roleId", HttpMethod.Get,
            "/api/v1/projects/roles/" + ManagementJson.Escape(roleId), new(organizationId, projectId, roleId), null,
            root => new(ManagementJson.Object(root, "role"), "projectId", projectId, roleId), false);

    public static ManagementRequest<RoleSummary> GetProjectRoleBySlug(string organizationId, string projectId, string roleSlug) =>
        new("infisical.get.v1.projects.by.projectId.roles.slug.by.roleSlug", HttpMethod.Get,
            ProjectPath(projectId) + "/roles/slug/" + ManagementJson.Escape(roleSlug), new(organizationId, projectId, roleSlug), null,
            root => new(ManagementJson.Object(root, "role"), "projectId", projectId, slug: roleSlug), false);

    public static ManagementRequest<RoleSummary> DeleteProjectRole(string organizationId, string projectId, string roleId) =>
        new("infisical.delete.v1.projects.by.projectId.roles.by.roleId", HttpMethod.Delete,
            ProjectPath(projectId) + "/roles/" + ManagementJson.Escape(roleId), new(organizationId, projectId, roleId), null,
            root => new(ManagementJson.Object(root, "role"), "projectId", projectId, roleId));

    internal static string ProjectPath(string projectId) => "/api/v1/projects/" + ManagementJson.Escape(projectId);
    private static string EnvironmentPath(string projectId, string id) => ProjectPath(projectId) + "/environments/" + ManagementJson.Escape(id);
    private static string TagPath(string projectId, string id) => ProjectPath(projectId) + "/tags/" + ManagementJson.Escape(id);

    private static ProjectEnvironment EnvironmentResult(JsonElement root, string project, string? id, string? slug, bool mutation)
    {
        if (mutation) ManagementJson.RequireEqual(root, "projectId", project);
        return new(ManagementJson.Object(root, "environment"), project, id, slug);
    }

    private static void EnvironmentFields(string? name, string? slug)
    {
        if (name is not null) ManagementJson.Text(name, 255);
        if (slug is not null) ManagementJson.Text(slug, 64);
    }

    private static void WriteEnvironment(Utf8JsonWriter writer, string? name, string? slug, int? position)
    {
        writer.WriteStartObject();
        if (name is not null) writer.WriteString("name", name);
        if (slug is not null) writer.WriteString("slug", slug);
        if (position is { } order) writer.WriteNumber("position", order);
        writer.WriteEndObject();
    }

    private static void WriteTag(Utf8JsonWriter writer, string slug, string color)
    {
        writer.WriteStartObject();
        writer.WriteString("slug", slug);
        writer.WriteString("color", color);
        writer.WriteEndObject();
    }
}
