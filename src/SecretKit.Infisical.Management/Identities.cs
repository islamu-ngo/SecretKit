using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Management;

public sealed class IdentityAttribute
{
    public IdentityAttribute(string key, string value)
    {
        ManagementJson.Text(key, 255);
        ManagementJson.Text(value, 4096);
        Key = key;
        Value = value;
    }
    [JsonIgnore] public string Key { get; }
    [JsonIgnore] public string Value { get; }
    public override string ToString() => "[IdentityAttribute]";
}

/// <summary>Identity metadata projection, not authentication material or permission evidence.</summary>
public sealed class IdentitySummary
{
    internal IdentitySummary(JsonElement value, string organizationId, string? projectId = null, string? id = null)
    {
        ManagementJson.RequireEqual(value, "orgId", organizationId);
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        // A project-specific identity must not be silently treated as organization-wide.
        string? returnedProject = ManagementJson.Optional(value, "projectId");
        if (returnedProject != projectId)
        {
            throw new ManagementContractException(Core.SecretStatus.Invalid);
        }
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Required(value, "name");
        ProjectId = returnedProject;
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string? ProjectId { get; }
    public override string ToString() => "[IdentitySummary]";
}

public sealed class IdentityOrganization
{
    internal IdentityOrganization(JsonElement root, string org)
    {
        JsonElement value = ManagementJson.Object(ManagementJson.Object(root, "identityDetails"), "organization");
        ManagementJson.RequireEqual(value, "id", org);
        Id = org;
        Name = ManagementJson.Required(value, "name");
        Slug = ManagementJson.Required(value, "slug");
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Slug { get; }
    public override string ToString() => "[IdentityOrganization]";
}

public static class IdentityOperations
{
    public static ManagementRequest<ManagementPage<IdentitySummary>> ListOrganizationIdentities(string organizationId) =>
        new("infisical.get.v1.identities", HttpMethod.Get,
            "/api/v1/identities?orgId=" + ManagementJson.Escape(organizationId), new(organizationId), null,
            root => new(ManagementJson.Array(root, "identities").Select(value =>
            {
                ManagementJson.RequireEqual(value, "orgId", organizationId);
                return new IdentitySummary(ManagementJson.Object(value, "identity"), organizationId);
            }), true), false);

    public static ManagementRequest<IdentitySummary> GetOrganizationIdentity(string organizationId, string identityId) =>
        new("infisical.get.v1.identities.by.identityId", HttpMethod.Get,
            "/api/v1/identities/" + ManagementJson.Escape(identityId), new(organizationId, resourceId: identityId), null,
            root =>
            {
                JsonElement membership = ManagementJson.Object(root, "identity");
                ManagementJson.RequireEqual(membership, "orgId", organizationId);
                ManagementJson.RequireEqual(membership, "identityId", identityId);
                return new(ManagementJson.Object(membership, "identity"), organizationId, id: identityId);
            }, false);

    public static ManagementRequest<IdentitySummary> CreateOrganizationIdentity(string organizationId, string name,
        string role, bool deleteProtection = false, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        IdentityChange(organizationId, null, null, name, role, deleteProtection, metadata);

    public static ManagementRequest<IdentitySummary> UpdateOrganizationIdentity(string organizationId, string identityId,
        string? name = null, string? role = null, bool? deleteProtection = null, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        IdentityChange(organizationId, null, identityId, name, role, deleteProtection, metadata);

    public static ManagementRequest<IdentitySummary> DeleteOrganizationIdentity(string organizationId, string identityId) =>
        new("infisical.delete.v1.identities.by.identityId", HttpMethod.Delete,
            "/api/v1/identities/" + ManagementJson.Escape(identityId), new(organizationId, resourceId: identityId), null,
            root => new(ManagementJson.Object(root, "identity"), organizationId, id: identityId));

    public static ManagementRequest<IdentityOrganization> GetSelectedIdentityOrganization(string organizationId) =>
        new("infisical.get.v1.identities.details", HttpMethod.Get, "/api/v1/identities/details", new(organizationId),
            null, root => new(root, organizationId), false);

    public static ManagementRequest<ManagementPage<IdentitySummary>> ListProjectIdentities(string organizationId,
        string projectId, int offset = 0, int limit = 100) =>
        new("infisical.get.v1.projects.by.projectId.identities", HttpMethod.Get,
            ProjectOperations.ProjectPath(projectId) + "/identities?" + ManagementJson.Paging(offset, limit),
            new(organizationId, projectId), null,
            root => ScopedAccessOperations.CountedPage(root, "identities",
                value => new IdentitySummary(value, organizationId, projectId), offset, limit), false);

    public static ManagementRequest<IdentitySummary> GetProjectIdentity(string organizationId, string projectId, string identityId) =>
        new("infisical.get.v1.projects.by.projectId.identities.by.identityId", HttpMethod.Get,
            IdentityPath(projectId, identityId), new(organizationId, projectId, identityId), null,
            root => new(ManagementJson.Object(root, "identity"), organizationId, projectId, identityId), false);

    public static ManagementRequest<IdentitySummary> CreateProjectIdentity(string organizationId, string projectId,
        string name, IReadOnlyList<MembershipRole> roles, bool deleteProtection = false,
        IReadOnlyList<IdentityAttribute>? metadata = null) =>
        IdentityChange(organizationId, projectId, null, name, null, deleteProtection, metadata, roles);

    public static ManagementRequest<IdentitySummary> UpdateProjectIdentity(string organizationId, string projectId,
        string identityId, string? name = null, bool? deleteProtection = null, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        IdentityChange(organizationId, projectId, identityId, name, null, deleteProtection, metadata);

    public static ManagementRequest<IdentitySummary> DeleteProjectIdentity(string organizationId, string projectId, string identityId) =>
        new("infisical.delete.v1.projects.by.projectId.identities.by.identityId", HttpMethod.Delete,
            IdentityPath(projectId, identityId), new(organizationId, projectId, identityId), null,
            root => new(ManagementJson.Object(root, "identity"), organizationId, projectId, identityId));

    private static ManagementRequest<IdentitySummary> IdentityChange(string org, string? project, string? identity,
        string? name, string? role, bool? deleteProtection, IReadOnlyList<IdentityAttribute>? metadata,
        IReadOnlyList<MembershipRole>? roles = null)
    {
        if (name is not null) ManagementJson.Text(name, 255);
        if (role is not null) ManagementJson.Text(role, 255);
        if (identity is null && name is null || identity is not null && name is null && role is null &&
            deleteProtection is null && metadata is null)
            throw new ArgumentException("An identity name or change is required.");
        IdentityAttribute[]? copy = metadata?.Take(101).ToArray();
        if (copy is not null && (copy.Length > 100 || copy.Any(item => item is null)))
            throw new ArgumentException("Invalid identity metadata budget.");
        MembershipRole[]? roleCopy = roles is null ? null : MembershipRole.Copy(roles);
        string prefix = project is null ? "v1.identities" : "v1.projects.by.projectId.identities";
        string path = project is null ? "/api/v1/identities" : ProjectOperations.ProjectPath(project) + "/identities";
        return new($"infisical.{(identity is null ? "post" : "patch")}.{prefix}" +
            (identity is null ? "" : ".by.identityId"), identity is null ? HttpMethod.Post : HttpMethod.Patch,
            path + (identity is null ? "" : "/" + ManagementJson.Escape(identity)),
            new(org, project, identity ?? name), writer =>
            {
                writer.WriteStartObject();
                if (project is null && identity is null) writer.WriteString("organizationId", org);
                if (name is not null) writer.WriteString("name", name);
                if (role is not null) writer.WriteString("role", role);
                if (deleteProtection is { } protect) writer.WriteBoolean("hasDeleteProtection", protect);
                if (copy is not null)
                {
                    writer.WriteStartArray("metadata");
                    foreach (IdentityAttribute item in copy)
                    {
                        writer.WriteStartObject();
                        writer.WriteString("key", item.Key);
                        writer.WriteString("value", item.Value);
                        writer.WriteEndObject();
                    }
                    writer.WriteEndArray();
                }
                if (roleCopy is not null) MembershipRole.Write(writer, roleCopy);
                writer.WriteEndObject();
            }, root => new(ManagementJson.Object(root, "identity"), org, project, identity));
    }

    private static string IdentityPath(string project, string identity) =>
        ProjectOperations.ProjectPath(project) + "/identities/" + ManagementJson.Escape(identity);
}
