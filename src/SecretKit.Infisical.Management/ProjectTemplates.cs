using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Native project-template product discriminators, not product entitlements.</summary>
public enum ProjectTemplateType
{
    /// <summary>Secret-management template.</summary>
    SecretManager,
    /// <summary>Certificate-management template.</summary>
    CertificateManager,
    /// <summary>Key-management template.</summary>
    KeyManagement,
    /// <summary>Secret-scanning template.</summary>
    SecretScanning,
    /// <summary>Privileged-access template.</summary>
    PrivilegedAccess,
    /// <summary>Agent Vault template.</summary>
    AgentVault
}

/// <summary>Protected native configuration metadata, never an effective-permission attestation.</summary>
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
        Type = ManagementJson.Optional(value, "type", nullable: false);
        if (type is not null && Type is not null && Type != type)
            throw new ManagementContractException(SecretStatus.Invalid);
        Id = ManagementJson.Required(value, "id");
        OrganizationId = ManagementJson.Required(value, "orgId");
        Name = ManagementJson.Required(value, "name");
        Description = ManagementJson.Optional(value, "description");
        CreatedAt = ManagementJson.Required(value, "createdAt");
        UpdatedAt = ManagementJson.Required(value, "updatedAt");
        Roles = Array.AsReadOnly(ManagementJson.Array(value, "roles").Select(v => new ProjectTemplateRoleSummary(v)).ToArray());
        Environments = ProjectTemplateWire.ParseCollection(value, "environments", ProjectTemplateEnvironment.Parse);
        Users = ProjectTemplateWire.ParseCollection(value, "users", v => new ProjectTemplateUser(v));
        Groups = ProjectTemplateWire.ParseCollection(value, "groups", v => new ProjectTemplateGroup(v));
        Identities = ProjectTemplateWire.ParseCollection(value, "identities", v => new ProjectTemplateIdentity(v));
        ProjectManagedIdentities = ProjectTemplateWire.ParseCollection(value, "projectManagedIdentities", v => new ProjectTemplateManagedIdentity(v));
    }

    /// <summary>Gets the returned template identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned organization coordinate matched to selection.</summary>
    [JsonIgnore] public string OrganizationId { get; }
    /// <summary>Gets the returned template name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets returned description, or null when absent or explicitly null.</summary>
    [JsonIgnore] public string? Description { get; }
    /// <summary>Gets returned product type, or null when omitted; never substitutes the requested filter.</summary>
    [JsonIgnore] public string? Type { get; }
    /// <summary>Gets the returned creation timestamp.</summary>
    [JsonIgnore] public string CreatedAt { get; }
    /// <summary>Gets the returned update timestamp.</summary>
    [JsonIgnore] public string UpdatedAt { get; }
    /// <summary>Gets returned role definitions without effective permission evaluation.</summary>
    [JsonIgnore] public IReadOnlyList<ProjectTemplateRoleSummary> Roles { get; }
    /// <summary>Gets returned environments; null is an explicit provider null, not an empty array.</summary>
    [JsonIgnore] public IReadOnlyList<ProjectTemplateEnvironment>? Environments { get; }
    /// <summary>Gets returned users; null is explicit provider null rather than an empty collection.</summary>
    [JsonIgnore] public IReadOnlyList<ProjectTemplateUser>? Users { get; }
    /// <summary>Gets returned groups; null differs from an empty collection.</summary>
    [JsonIgnore] public IReadOnlyList<ProjectTemplateGroup>? Groups { get; }
    /// <summary>Gets returned existing identities; null differs from an empty collection.</summary>
    [JsonIgnore] public IReadOnlyList<ProjectTemplateIdentity>? Identities { get; }
    /// <summary>Gets returned managed-identity definitions; null differs from an empty collection.</summary>
    [JsonIgnore] public IReadOnlyList<ProjectTemplateManagedIdentity>? ProjectManagedIdentities { get; }
    /// <summary>Always true: this summary includes typed native configuration.</summary>
    public bool IncludesConfiguration => true;
    /// <summary>Always false: unconstrained permission-condition values are not exported.</summary>
    public bool IncludesPermissionConditionValues => false;
    /// <summary>Returns a marker without template settings or assignments.</summary>
    public override string ToString() => "[ProjectTemplateSummary]";
}

/// <summary>
/// Named template operations with typed configuration inputs and protected result projections.
/// Administrative intent is local; returned organization coordinates are checked,
/// not interpreted as a provider permission grant.
/// </summary>
public static class ProjectTemplateOperations
{
    /// <summary>Builds bounded template inventory; null product type omits the filter and does not manufacture response type evidence.</summary>
    public static ManagementRequest<ManagementPage<ProjectTemplateSummary>> ListProjectTemplates(
        string organizationId, ProjectTemplateType? type = null)
    {
        string? nativeType = type is { } selected ? NativeType(selected) : null;
        return new("infisical.get.v1.project.templates", HttpMethod.Get,
            "/api/v1/project-templates" + (nativeType is null ? "" : "?type=" + nativeType),
            new(organizationId, secondaryId: nativeType), null,
            root => new(ManagementJson.Array(root, "projectTemplates")
                .Select(value => new ProjectTemplateSummary(value, organizationId, type: nativeType)), true), false);
    }

    /// <summary>Builds lookup of one exact template UUID under the selected organization.</summary>
    public static ManagementRequest<ProjectTemplateSummary> GetProjectTemplate(string organizationId, string templateId) =>
        new("infisical.get.v1.project.templates.by.templateId", HttpMethod.Get, TemplatePath(templateId),
            new(organizationId, resourceId: templateId), null,
            root => new(ManagementJson.Object(root, "projectTemplate"), organizationId, templateId), false);

    /// <summary>Builds template creation; nullable principal-collection clearing is rejected on creation.</summary>
    public static ManagementRequest<ProjectTemplateSummary> CreateProjectTemplate(string organizationId,
        string name, ProjectTemplateType type = ProjectTemplateType.SecretManager, string? description = null,
        ProjectTemplateConfiguration? configuration = null)
    {
        ManagementJson.Text(name, 64);
        Description(description);
        string nativeType = NativeType(type);
        configuration?.ValidateCreate();
        return new("infisical.post.v1.project.templates", HttpMethod.Post, "/api/v1/project-templates",
            ProjectTemplateCreateTarget(organizationId, name, type, description, configuration),
            writer => Write(writer, name, description, nativeType, configuration),
            root => new(ManagementJson.Object(root, "projectTemplate"), organizationId, name: name, type: nativeType));
    }

    /// <summary>Builds template update; omitted fields are retained and explicit nullable collections preserve clearing intent.</summary>
    public static ManagementRequest<ProjectTemplateSummary> UpdateProjectTemplate(string organizationId,
        string templateId, string? name = null, string? description = null, ProjectTemplateConfiguration? configuration = null)
    {
        if (name is not null) ManagementJson.Text(name, 64);
        Description(description);
        if (name is null && description is null && configuration?.HasFields != true)
            throw new ArgumentException("A project template change is required.");
        return new("infisical.patch.v1.project.templates.by.templateId", HttpMethod.Patch, TemplatePath(templateId),
            ProjectTemplateUpdateTarget(organizationId, templateId, name, description, configuration),
            writer => Write(writer, name, description, null, configuration),
            root => new(ManagementJson.Object(root, "projectTemplate"), organizationId, templateId, name));
    }

    /// <summary>Builds exact template deletion; does not delete projects created from the template.</summary>
    public static ManagementRequest<ProjectTemplateSummary> DeleteProjectTemplate(string organizationId, string templateId) =>
        new("infisical.delete.v1.project.templates.by.templateId", HttpMethod.Delete, TemplatePath(templateId),
            new(organizationId, resourceId: templateId), null,
            root => new(ManagementJson.Object(root, "projectTemplate"), organizationId, templateId));

    /// <summary>Host-owned approved fields, selected independently of an incoming request.</summary>
    public static ManagementTarget ProjectTemplateCreateTarget(string organizationId, string name,
        ProjectTemplateType type = ProjectTemplateType.SecretManager, string? description = null,
        ProjectTemplateConfiguration? configuration = null)
    {
        ManagementJson.Text(name, 64);
        Description(description);
        string nativeType = NativeType(type);
        configuration?.ValidateCreate();
        return ProjectTemplateWire.Intent(organizationId, name, writer => Write(writer, name, description, nativeType, configuration));
    }

    /// <summary>Builds independent approval for the complete selected update body, including absent/null/empty distinctions.</summary>
    public static ManagementTarget ProjectTemplateUpdateTarget(string organizationId, string templateId,
        string? name = null, string? description = null, ProjectTemplateConfiguration? configuration = null)
    {
        _ = TemplatePath(templateId);
        if (name is not null) ManagementJson.Text(name, 64);
        Description(description);
        if (name is null && description is null && configuration?.HasFields != true)
            throw new ArgumentException("A project template change is required.");
        return ProjectTemplateWire.Intent(organizationId, templateId, writer => Write(writer, name, description, null, configuration));
    }

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

    private static void Write(Utf8JsonWriter writer, string? name, string? description, string? type,
        ProjectTemplateConfiguration? configuration)
    {
        writer.WriteStartObject();
        if (name is not null) writer.WriteString("name", name);
        if (type is not null) writer.WriteString("type", type);
        if (description is not null) writer.WriteString("description", description);
        configuration?.Write(writer);
        writer.WriteEndObject();
    }
}
