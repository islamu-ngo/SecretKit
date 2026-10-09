using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

public enum ProjectTemplateType
{
    SecretManager,
    CertificateManager,
    KeyManagement,
    SecretScanning,
    PrivilegedAccess,
    AgentVault
}

/// <summary>Protected template metadata, not its role configuration or effective permissions.</summary>
public sealed class ProjectTemplateSummary
{
    internal ProjectTemplateSummary(JsonElement value, string organizationId, string? id = null,
        string? name = null, string? type = null)
    {
        ManagementJson.RequireEqual(value, "orgId", organizationId);
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        if (name is not null) ManagementJson.RequireEqual(value, "name", name);
        // Type is optional in the public response schema. Do not manufacture a
        // returned attestation from a request filter or the schema's default.
        Type = ManagementJson.Optional(value, "type");
        if (type is not null && Type is not null && Type != type)
            throw new ManagementContractException(SecretStatus.Invalid);
        Id = ManagementJson.Required(value, "id");
        OrganizationId = ManagementJson.Required(value, "orgId");
        Name = ManagementJson.Required(value, "name");
        Description = ManagementJson.Optional(value, "description");
        CreatedAt = ManagementJson.Required(value, "createdAt");
        UpdatedAt = ManagementJson.Required(value, "updatedAt");
    }

    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string OrganizationId { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string? Description { get; }
    [JsonIgnore] public string? Type { get; }
    [JsonIgnore] public string CreatedAt { get; }
    [JsonIgnore] public string UpdatedAt { get; }
    public bool IncludesConfiguration => false;
    public override string ToString() => "[ProjectTemplateSummary]";
}

/// <summary>
/// Named template operations with metadata-only results. Optional roles,
/// environments and principal provisioning configurations are not exposed.
/// Administrative intent is local; returned organization coordinates are checked,
/// not interpreted as a provider permission grant.
/// </summary>
public static class ProjectTemplateOperations
{
    public static ManagementRequest<ManagementPage<ProjectTemplateSummary>> ListProjectTemplates(
        string organizationId, ProjectTemplateType type = ProjectTemplateType.SecretManager)
    {
        string nativeType = NativeType(type);
        return new("infisical.get.v1.project.templates", HttpMethod.Get,
            "/api/v1/project-templates?type=" + nativeType,
            new(organizationId, secondaryId: nativeType), null,
            root => new(ManagementJson.Array(root, "projectTemplates")
                .Select(value => new ProjectTemplateSummary(value, organizationId, type: nativeType)), true), false);
    }

    public static ManagementRequest<ProjectTemplateSummary> GetProjectTemplate(string organizationId, string templateId) =>
        new("infisical.get.v1.project.templates.by.templateId", HttpMethod.Get, TemplatePath(templateId),
            new(organizationId, resourceId: templateId), null,
            root => new(ManagementJson.Object(root, "projectTemplate"), organizationId, templateId), false);

    public static ManagementRequest<ProjectTemplateSummary> CreateProjectTemplate(string organizationId,
        string name, ProjectTemplateType type = ProjectTemplateType.SecretManager, string? description = null)
    {
        ManagementJson.Text(name, 64);
        Description(description);
        string nativeType = NativeType(type);
        return new("infisical.post.v1.project.templates", HttpMethod.Post, "/api/v1/project-templates",
            new(organizationId, resourceId: name, secondaryId: nativeType),
            writer => Write(writer, name, description, nativeType),
            root => new(ManagementJson.Object(root, "projectTemplate"), organizationId, name: name, type: nativeType));
    }

    public static ManagementRequest<ProjectTemplateSummary> UpdateProjectTemplate(string organizationId,
        string templateId, string? name = null, string? description = null)
    {
        if (name is not null) ManagementJson.Text(name, 64);
        Description(description);
        if (name is null && description is null) throw new ArgumentException("A project template change is required.");
        return new("infisical.patch.v1.project.templates.by.templateId", HttpMethod.Patch, TemplatePath(templateId),
            new(organizationId, resourceId: templateId), writer => Write(writer, name, description, null),
            root => new(ManagementJson.Object(root, "projectTemplate"), organizationId, templateId, name));
    }

    public static ManagementRequest<ProjectTemplateSummary> DeleteProjectTemplate(string organizationId, string templateId) =>
        new("infisical.delete.v1.project.templates.by.templateId", HttpMethod.Delete, TemplatePath(templateId),
            new(organizationId, resourceId: templateId), null,
            root => new(ManagementJson.Object(root, "projectTemplate"), organizationId, templateId));

    private static string TemplatePath(string templateId)
    {
        ManagementJson.Text(templateId);
        if (!Guid.TryParseExact(templateId, "D", out _)) throw new ArgumentException("Invalid project template identifier.");
        return "/api/v1/project-templates/" + ManagementJson.Escape(templateId);
    }

    private static string NativeType(ProjectTemplateType type) => type switch
    {
        ProjectTemplateType.SecretManager => "secret-manager",
        ProjectTemplateType.CertificateManager => "cert-manager",
        ProjectTemplateType.KeyManagement => "kms",
        ProjectTemplateType.SecretScanning => "secret-scanning",
        ProjectTemplateType.PrivilegedAccess => "pam",
        ProjectTemplateType.AgentVault => "agent-vault",
        _ => throw new ArgumentOutOfRangeException(nameof(type))
    };

    private static void Description(string? value)
    {
        if (value is not null && (value.Length > 256 || value.Any(char.IsControl)))
            throw new ArgumentException("Invalid project template description.");
    }

    private static void Write(Utf8JsonWriter writer, string? name, string? description, string? type)
    {
        writer.WriteStartObject();
        if (name is not null) writer.WriteString("name", name);
        if (type is not null) writer.WriteString("type", type);
        if (description is not null) writer.WriteString("description", description);
        writer.WriteEndObject();
    }
}
