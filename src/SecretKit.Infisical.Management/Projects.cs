using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Project identity and lifecycle metadata, not secret data or effective permissions.</summary>
public sealed class ProjectSummary
{
    internal ProjectSummary(JsonElement value, string organizationId, string? id = null, string? slug = null,
        string? expectedType = "secret-manager", bool includesDetails = true, bool includesRoles = false, bool requiredDetails = false)
    {
        ManagementJson.RequireEqual(value, "orgId", organizationId);
        if (expectedType is not null) ManagementJson.RequireEqual(value, "type", expectedType);
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        if (slug is not null) ManagementJson.RequireEqual(value, "slug", slug);
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Required(value, "name");
        Slug = ManagementJson.Required(value, "slug");
        Description = ManagementJson.Optional(value, "description");
        DescriptionField = ProjectWire.StringField(value, "description", nullable: true);
        Type = ManagementJson.Required(value, "type");
        CreatedAt = ProjectWire.StringField(value, "createdAt");
        UpdatedAt = ProjectWire.StringField(value, "updatedAt");
        if (!CreatedAt.IsPresent || !UpdatedAt.IsPresent)
            throw new ManagementContractException(SecretStatus.Unknown);
        DefaultProduct = ProjectWire.StringField(value, "defaultProduct", nullable: true);
        UpgradeStatus = ProjectWire.StringField(value, "upgradeStatus", nullable: true);
        KmsCertificateKeyId = ProjectWire.StringField(value, "kmsCertificateKeyId", nullable: true);
        KmsSecretManagerKeyId = ProjectWire.StringField(value, "kmsSecretManagerKeyId", nullable: true);
        AuditLogsRetentionDays = ProjectWire.NumberField(value, "auditLogsRetentionDays", nullable: true);
        Version = ProjectWire.NumberField(value, "version");
        PitVersionLimit = ProjectWire.NumberField(value, "pitVersionLimit");
        AutoCapitalization = ProjectWire.BooleanField(value, "autoCapitalization", nullable: true);
        HasDeleteProtection = ProjectWire.BooleanField(value, "hasDeleteProtection", nullable: true);
        EnforceEncryptedSecretManagerSecretMetadata = ProjectWire.BooleanField(value, "enforceEncryptedSecretManagerSecretMetadata", nullable: true);
        IsLegacyAdditionalPrivilegesEnabled = ProjectWire.BooleanField(value, "isLegacyAdditionalPrivilegesEnabled");
        SecretBlindIndexEnabled = ProjectWire.BooleanField(value, "secretBlindIndexEnabled");
        SecretSharing = ProjectWire.BooleanField(value, "secretSharing");
        ShowSnapshotsLegacy = ProjectWire.BooleanField(value, "showSnapshotsLegacy");
        SecretDetectionIgnoreValues = ProjectWire.Collection(value, "secretDetectionIgnoreValues", ProjectWire.String, nullable: true);
        if (includesDetails)
        {
            NativeId = ProjectWire.StringField(value, "_id");
            Environments = ProjectWire.Collection(value, "environments", child => new ProjectEnvironmentReference(child));
            DeletedEnvironments = ProjectWire.Collection(value, "deletedEnvironments", child => new DeletedProjectEnvironment(child));
            if (requiredDetails && (!NativeId.IsPresent || !Environments.IsPresent || !DeletedEnvironments.IsPresent))
                throw new ManagementContractException(SecretStatus.Unknown);
        }
        if (includesRoles)
            Roles = ProjectWire.Collection(value, "roles", child => new ProjectRoleMetadata(child, Id));
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Slug { get; }
    [JsonIgnore] public string? Description { get; }
    [JsonIgnore] public ProjectField<string> DescriptionField { get; }
    [JsonIgnore] public string Type { get; }
    [JsonIgnore] public ProjectField<string> NativeId { get; }
    [JsonIgnore] public ProjectField<string> CreatedAt { get; }
    [JsonIgnore] public ProjectField<string> UpdatedAt { get; }
    [JsonIgnore] public ProjectField<string> DefaultProduct { get; }
    [JsonIgnore] public ProjectField<string> UpgradeStatus { get; }
    [JsonIgnore] public ProjectField<string> KmsCertificateKeyId { get; }
    [JsonIgnore] public ProjectField<string> KmsSecretManagerKeyId { get; }
    [JsonIgnore] public ProjectField<double> AuditLogsRetentionDays { get; }
    [JsonIgnore] public ProjectField<double> Version { get; }
    [JsonIgnore] public ProjectField<double> PitVersionLimit { get; }
    [JsonIgnore] public ProjectField<bool> AutoCapitalization { get; }
    [JsonIgnore] public ProjectField<bool> HasDeleteProtection { get; }
    [JsonIgnore] public ProjectField<bool> EnforceEncryptedSecretManagerSecretMetadata { get; }
    [JsonIgnore] public ProjectField<bool> IsLegacyAdditionalPrivilegesEnabled { get; }
    [JsonIgnore] public ProjectField<bool> SecretBlindIndexEnabled { get; }
    [JsonIgnore] public ProjectField<bool> SecretSharing { get; }
    [JsonIgnore] public ProjectField<bool> ShowSnapshotsLegacy { get; }
    [JsonIgnore] public ProjectField<IReadOnlyList<string>> SecretDetectionIgnoreValues { get; }
    [JsonIgnore] public ProjectField<IReadOnlyList<ProjectEnvironmentReference>> Environments { get; }
    [JsonIgnore] public ProjectField<IReadOnlyList<DeletedProjectEnvironment>> DeletedEnvironments { get; }
    [JsonIgnore] public ProjectField<IReadOnlyList<ProjectRoleMetadata>> Roles { get; }
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
        if (!value.TryGetProperty("position", out var position))
            throw new ManagementContractException(SecretStatus.Unknown);
        Position = ProjectWire.Number(position);
        SoftDeletedAt = ManagementJson.Optional(value, "softDeletedAt");
        DeleteAfter = ManagementJson.Optional(value, "deleteAfter");
        SoftDeletedAtField = ProjectWire.StringField(value, "softDeletedAt", nullable: true);
        DeleteAfterField = ProjectWire.StringField(value, "deleteAfter", nullable: true);
        CreatedAt = ProjectWire.StringField(value, "createdAt");
        UpdatedAt = ProjectWire.StringField(value, "updatedAt");
        DeletedByUserId = ProjectWire.StringField(value, "deletedByUserId", nullable: true);
        DeletedByIdentityId = ProjectWire.StringField(value, "deletedByIdentityId", nullable: true);
        if (!CreatedAt.IsPresent || !UpdatedAt.IsPresent)
            throw new ManagementContractException(SecretStatus.Unknown);
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Slug { get; }
    /// <summary>Finite IEEE 754 double subset of the provider number domain, without integer truncation.</summary>
    [JsonIgnore] public double Position { get; }
    [JsonIgnore] public string? SoftDeletedAt { get; }
    [JsonIgnore] public string? DeleteAfter { get; }
    [JsonIgnore] public ProjectField<string> SoftDeletedAtField { get; }
    [JsonIgnore] public ProjectField<string> DeleteAfterField { get; }
    [JsonIgnore] public ProjectField<string> CreatedAt { get; }
    [JsonIgnore] public ProjectField<string> UpdatedAt { get; }
    [JsonIgnore] public ProjectField<string> DeletedByUserId { get; }
    [JsonIgnore] public ProjectField<string> DeletedByIdentityId { get; }
    public override string ToString() => "[ProjectEnvironment]";
}

public sealed class ProjectTag
{
    internal ProjectTag(JsonElement value, string projectId, string? id = null, string? slug = null, bool inspection = false)
    {
        ManagementJson.RequireEqual(value, "projectId", projectId);
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        if (slug is not null) ManagementJson.RequireEqual(value, "slug", slug);
        Id = ManagementJson.Required(value, "id");
        Slug = ManagementJson.Required(value, "slug");
        Color = ManagementJson.Optional(value, "color");
        Name = ManagementJson.Optional(value, "name");
        if (inspection && Name is null) throw new ManagementContractException(SecretStatus.Unknown);
        ColorField = ProjectWire.StringField(value, "color", nullable: true);
        CreatedAt = ProjectWire.StringField(value, "createdAt");
        UpdatedAt = ProjectWire.StringField(value, "updatedAt");
        if (!CreatedAt.IsPresent || !UpdatedAt.IsPresent)
            throw new ManagementContractException(SecretStatus.Unknown);
        CreatedBy = ProjectWire.StringField(value, "createdBy", nullable: true);
        CreatedByActorType = ProjectWire.StringField(value, "createdByActorType");
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Slug { get; }
    [JsonIgnore] public string? Color { get; }
    [JsonIgnore] public string? Name { get; }
    [JsonIgnore] public ProjectField<string> ColorField { get; }
    [JsonIgnore] public ProjectField<string> CreatedAt { get; }
    [JsonIgnore] public ProjectField<string> UpdatedAt { get; }
    [JsonIgnore] public ProjectField<string> CreatedBy { get; }
    [JsonIgnore] public ProjectField<string> CreatedByActorType { get; }
    public override string ToString() => "[ProjectTag]";
}

public static class ProjectOperations
{
    public static ManagementRequest<ManagementPage<ProjectSummary>> ListProjects(string organizationId,
        ProjectType? type = ProjectType.SecretManager, bool? includeRoles = false)
    {
        string? typeName = type is { } selected ? ProjectWire.TypeName(selected) : null;
        string path = "/api/v1/projects";
        if (typeName is not null) path += "?type=" + typeName;
        if (includeRoles is { } roles) path += (typeName is null ? "?" : "&") + "includeRoles=" + (roles ? "true" : "false");
        return new("infisical.get.v1.projects", HttpMethod.Get, path,
            ProjectListTarget(organizationId, type, includeRoles), null, root => new(ManagementJson.Array(root, "projects")
                .Select(value => new ProjectSummary(value, organizationId, expectedType: typeName, includesRoles: true)), true), false);
    }

    public static ManagementTarget ProjectListTarget(string organizationId,
        ProjectType? type = ProjectType.SecretManager, bool? includeRoles = false) =>
        ProjectWire.Intent(organizationId, null, null, writer =>
        {
            writer.WriteStartObject();
            if (type is { } selected) writer.WriteString("type", ProjectWire.TypeName(selected));
            if (includeRoles is { } roles) writer.WriteBoolean("includeRoles", roles);
            writer.WriteEndObject();
        });

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
        if (description is not null && (description.Length > 1024 || description.Any(char.IsControl)))
            throw new ArgumentException("Invalid project description.");
        if (template is not null) ManagementJson.Text(template, 64);
        if (kmsKeyId is not null) ManagementJson.Text(kmsKeyId);
        void Write(Utf8JsonWriter writer)
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
        }
        return new("infisical.post.v1.projects", HttpMethod.Post, "/api/v1/projects",
            ProjectWire.Intent(organizationId, null, slug, Write), Write,
            root => new(ManagementJson.Object(root, "project"), organizationId, slug: slug, requiredDetails: true));
    }

    public static ManagementTarget ProjectCreateTarget(string organizationId, string name, string slug,
        string? description = null, bool deleteProtection = false, bool createDefaultEnvironments = true,
        string? template = null, string? kmsKeyId = null)
    {
        using var request = CreateProject(organizationId, name, slug, description, deleteProtection,
            createDefaultEnvironments, template, kmsKeyId);
        return request.Target;
    }

    /// <summary>Retention and version inputs retain the explicit bounded integer subset; ignore values permit omitted or empty arrays.</summary>
    public static ManagementRequest<ProjectSummary> UpdateProject(string organizationId, string projectId,
        string? name = null, string? slug = null, string? description = null, bool? deleteProtection = null,
        int? auditRetentionDays = null, bool? secretSharing = null, bool? autoCapitalization = null,
        bool? encryptedMetadata = null, int? pointInTimeVersionLimit = null, bool? showLegacySnapshots = null,
        IReadOnlyList<string>? secretDetectionIgnoreValues = null)
    {
        string[]? ignoreValues = ProjectWire.CopyStrings(secretDetectionIgnoreValues);
        if (name is not null) ManagementJson.Text(name, 64);
        if (slug is not null) ManagementJson.Text(slug, 64);
        if (description is not null && (description.Length > 1024 || description.Any(char.IsControl)))
            throw new ArgumentException("Invalid project description.");
        if (auditRetentionDays is < 1 or > 365 || pointInTimeVersionLimit is < 1 or > 100)
            throw new ArgumentException("Invalid project retention bounds.");
        if (name is null && slug is null && description is null && deleteProtection is null &&
            auditRetentionDays is null && secretSharing is null && autoCapitalization is null &&
            encryptedMetadata is null && pointInTimeVersionLimit is null && showLegacySnapshots is null && ignoreValues is null)
            throw new ArgumentException("A project change is required.");
        void Write(Utf8JsonWriter writer)
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
            if (ignoreValues is not null)
            {
                writer.WriteStartArray("secretDetectionIgnoreValues");
                foreach (string value in ignoreValues) writer.WriteStringValue(value);
                writer.WriteEndArray();
            }
            writer.WriteEndObject();
        }
        return new("infisical.patch.v1.projects.by.projectId", HttpMethod.Patch, ProjectPath(projectId),
            ProjectWire.Intent(organizationId, projectId, null, Write), Write,
            root => new(ManagementJson.Object(root, "project"), organizationId, projectId, includesDetails: false));
    }

    public static ManagementTarget ProjectUpdateTarget(string organizationId, string projectId,
        string? name = null, string? slug = null, string? description = null, bool? deleteProtection = null,
        int? auditRetentionDays = null, bool? secretSharing = null, bool? autoCapitalization = null,
        bool? encryptedMetadata = null, int? pointInTimeVersionLimit = null, bool? showLegacySnapshots = null,
        IReadOnlyList<string>? secretDetectionIgnoreValues = null)
    {
        using var request = UpdateProject(organizationId, projectId, name, slug, description, deleteProtection,
            auditRetentionDays, secretSharing, autoCapitalization, encryptedMetadata, pointInTimeVersionLimit,
            showLegacySnapshots, secretDetectionIgnoreValues);
        return request.Target;
    }

    public static ManagementRequest<ProjectSummary> DeleteProject(string organizationId, string projectId) =>
        new("infisical.delete.v1.projects.by.projectId", HttpMethod.Delete, ProjectPath(projectId),
            new(organizationId, projectId), null,
            root => new(ManagementJson.Object(root, "project"), organizationId, projectId, includesDetails: false));

    public static ManagementRequest<ProjectEnvironment> CreateEnvironment(string organizationId, string projectId,
        string name, string slug, double? position = null)
    {
        EnvironmentFields(name, slug);
        ProjectWire.Position(position, create: true);
        void Write(Utf8JsonWriter writer) => WriteEnvironment(writer, name, slug, position);
        return new("infisical.post.v1.projects.by.projectId.environments", HttpMethod.Post,
            ProjectPath(projectId) + "/environments", ProjectWire.Intent(organizationId, projectId, slug, Write),
            Write,
            root => EnvironmentResult(root, projectId, null, slug, true));
    }

    public static ManagementTarget EnvironmentCreateTarget(string organizationId, string projectId,
        string name, string slug, double? position = null)
    {
        using var request = CreateEnvironment(organizationId, projectId, name, slug, position);
        return request.Target;
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
        string environmentId, string? name = null, string? slug = null, double? position = null)
    {
        EnvironmentFields(name, slug);
        ProjectWire.Position(position, create: false);
        if (name is null && slug is null && position is null) throw new ArgumentException("An environment change is required.");
        void Write(Utf8JsonWriter writer) => WriteEnvironment(writer, name, slug, position);
        return new("infisical.patch.v1.projects.by.projectId.environments.by.id", HttpMethod.Patch,
            EnvironmentPath(projectId, environmentId), ProjectWire.Intent(organizationId, projectId, environmentId, Write),
            Write,
            root => EnvironmentResult(root, projectId, environmentId, null, true));
    }

    public static ManagementTarget EnvironmentUpdateTarget(string organizationId, string projectId,
        string environmentId, string? name = null, string? slug = null, double? position = null)
    {
        using var request = UpdateEnvironment(organizationId, projectId, environmentId, name, slug, position);
        return request.Target;
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
            root => new(ManagementJson.Object(root, "tag"), projectId, tagId, inspection: true), false);

    public static ManagementRequest<ProjectTag> GetTagBySlug(string organizationId, string projectId, string slug) =>
        new("infisical.get.v1.projects.by.projectId.tags.slug.by.tagSlug", HttpMethod.Get,
            ProjectPath(projectId) + "/tags/slug/" + ManagementJson.Escape(slug), new(organizationId, projectId, slug), null,
            root => new(ManagementJson.Object(root, "tag"), projectId, slug: slug, inspection: true), false);

    public static ManagementRequest<ProjectTag> CreateTag(string organizationId, string projectId, string slug, string color)
    {
        ManagementJson.Text(slug, 64);
        ManagementJson.Text(color, 64);
        void Write(Utf8JsonWriter writer) => WriteTag(writer, slug, color);
        return new("infisical.post.v1.projects.by.projectId.tags", HttpMethod.Post, ProjectPath(projectId) + "/tags",
            ProjectWire.Intent(organizationId, projectId, slug, Write), Write,
            root => new(ManagementJson.Object(root, "tag"), projectId, slug: slug));
    }

    public static ManagementRequest<ProjectTag> UpdateTag(string organizationId, string projectId, string tagId, string slug, string color)
    {
        ManagementJson.Text(slug, 64);
        ManagementJson.Text(color, 64);
        void Write(Utf8JsonWriter writer) => WriteTag(writer, slug, color);
        return new("infisical.patch.v1.projects.by.projectId.tags.by.tagId", HttpMethod.Patch, TagPath(projectId, tagId),
            ProjectWire.Intent(organizationId, projectId, tagId, Write), Write,
            root => new(ManagementJson.Object(root, "tag"), projectId, tagId));
    }

    public static ManagementTarget TagCreateTarget(string organizationId, string projectId, string slug, string color)
    {
        using var request = CreateTag(organizationId, projectId, slug, color);
        return request.Target;
    }

    public static ManagementTarget TagUpdateTarget(string organizationId, string projectId, string tagId, string slug, string color)
    {
        using var request = UpdateTag(organizationId, projectId, tagId, slug, color);
        return request.Target;
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
            "/api/v1/projects/roles/" + ManagementJson.Escape(ManagementJson.UuidInput(roleId)), new(organizationId, projectId, roleId), null,
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

    private static void WriteEnvironment(Utf8JsonWriter writer, string? name, string? slug, double? position)
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
