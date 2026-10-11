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
    internal IdentitySummary(JsonElement value, string organizationId, string? projectId = null, string? id = null,
        bool organizationEchoRequired = true, JsonElement? membership = null, bool metadataNonempty = true,
        bool requireTimestamps = false, bool requireAuthMethods = false, bool requireMetadata = false,
        bool requireLockoutMethods = false)
    {
        if (organizationEchoRequired || value.TryGetProperty("orgId", out _))
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
        OrganizationIdField = IdentityMetadataWire.StringField(value, "orgId");
        ProjectIdField = IdentityMetadataWire.StringField(value, "projectId", nullable: true);
        AuthMethod = IdentityMetadataWire.StringField(value, "authMethod", nullable: true);
        AuthMethods = IdentityMetadataWire.Collection(value, "authMethods", IdentityMetadataWire.String);
        ActiveLockoutAuthMethods = IdentityMetadataWire.Collection(value, "activeLockoutAuthMethods", IdentityMetadataWire.String);
        HasDeleteProtection = IdentityMetadataWire.Field(value, "hasDeleteProtection",
            child => child.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? child.GetBoolean() : throw new ManagementContractException(Core.SecretStatus.Unknown));
        CreatedAt = IdentityMetadataWire.StringField(value, "createdAt");
        UpdatedAt = IdentityMetadataWire.StringField(value, "updatedAt");
        JsonElement metadataOwner = membership is { } outer && outer.TryGetProperty("metadata", out _)
            ? outer : value;
        Metadata = IdentityMetadataWire.Collection(metadataOwner, "metadata",
            child => new IdentityMetadataEntry(child, metadataNonempty));
        if (requireTimestamps && (!CreatedAt.IsPresent || !UpdatedAt.IsPresent) ||
            requireAuthMethods && !AuthMethods.IsPresent || requireMetadata && !Metadata.IsPresent ||
            requireLockoutMethods && !ActiveLockoutAuthMethods.IsPresent)
            throw new ManagementContractException(Core.SecretStatus.Unknown);
        if (membership is { } returnedMembership)
            Membership = IdentityField<IdentityMembershipMetadata>.Present(new(returnedMembership, Id));
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string? ProjectId { get; }
    [JsonIgnore] public IdentityField<string> OrganizationIdField { get; }
    [JsonIgnore] public IdentityField<string> ProjectIdField { get; }
    [JsonIgnore] public IdentityField<string> AuthMethod { get; }
    [JsonIgnore] public IdentityField<IReadOnlyList<string>> AuthMethods { get; }
    [JsonIgnore] public IdentityField<IReadOnlyList<string>> ActiveLockoutAuthMethods { get; }
    [JsonIgnore] public IdentityField<bool> HasDeleteProtection { get; }
    [JsonIgnore] public IdentityField<string> CreatedAt { get; }
    [JsonIgnore] public IdentityField<string> UpdatedAt { get; }
    [JsonIgnore] public IdentityField<IReadOnlyList<IdentityMetadataEntry>> Metadata { get; }
    [JsonIgnore] public IdentityField<IdentityMembershipMetadata> Membership { get; }
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
            root =>
            {
                IdentitySummary[] identities = ManagementJson.Array(root, "identities").Select(value =>
                {
                    ManagementJson.RequireEqual(value, "orgId", organizationId);
                    string identityId = ManagementJson.Required(value, "identityId");
                    return new IdentitySummary(ManagementJson.Object(value, "identity"), organizationId,
                        id: identityId, organizationEchoRequired: false, membership: value, requireAuthMethods: true);
                }).ToArray();
                int total = ManagementJson.Integer(root, "totalCount");
                if (total < identities.Length || total < 0)
                    throw new ManagementContractException(Core.SecretStatus.Unknown);
                // The endpoint exposes no paging inputs. Do not invent a continuation.
                return new(identities, total == identities.Length);
            }, false);

    public static ManagementRequest<IdentitySummary> GetOrganizationIdentity(string organizationId, string identityId) =>
        new("infisical.get.v1.identities.by.identityId", HttpMethod.Get,
            "/api/v1/identities/" + ManagementJson.Escape(identityId), new(organizationId, resourceId: identityId), null,
            root =>
            {
                JsonElement membership = ManagementJson.Object(root, "identity");
                ManagementJson.RequireEqual(membership, "orgId", organizationId);
                ManagementJson.RequireEqual(membership, "identityId", identityId);
                return new(ManagementJson.Object(membership, "identity"), organizationId, id: identityId,
                    membership: membership, metadataNonempty: true, requireAuthMethods: true,
                    requireLockoutMethods: true);
            }, false);

    public static ManagementRequest<IdentitySummary> CreateOrganizationIdentity(string organizationId, string name,
        string role, bool deleteProtection = false, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        IdentityChange(organizationId, null, null, name, role, deleteProtection, metadata);

    public static ManagementRequest<IdentitySummary> UpdateOrganizationIdentity(string organizationId, string identityId,
        string? name = null, string? role = null, bool? deleteProtection = null, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        IdentityChange(organizationId, null, identityId, name, role, deleteProtection, metadata);

    /// <summary>Independently approved complete organization identity creation body.</summary>
    public static ManagementTarget OrganizationIdentityCreateTarget(string organizationId, string name,
        string role, bool deleteProtection = false, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        MembershipRoleWire.Intent(organizationId, null, name,
            IdentityChangeBody(organizationId, null, null, name, role, deleteProtection, metadata));

    /// <summary>Independently approved complete change, preserving omitted fields and empty metadata.</summary>
    public static ManagementTarget OrganizationIdentityUpdateTarget(string organizationId, string identityId,
        string? name = null, string? role = null, bool? deleteProtection = null, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        MembershipRoleWire.Intent(organizationId, null, identityId,
            IdentityChangeBody(organizationId, null, identityId, name, role, deleteProtection, metadata));

    public static ManagementRequest<IdentitySummary> DeleteOrganizationIdentity(string organizationId, string identityId) =>
        new("infisical.delete.v1.identities.by.identityId", HttpMethod.Delete,
            "/api/v1/identities/" + ManagementJson.Escape(identityId), new(organizationId, resourceId: identityId), null,
            root => new(ManagementJson.Object(root, "identity"), organizationId, id: identityId,
                metadataNonempty: false, requireTimestamps: true));

    public static ManagementRequest<IdentityOrganization> GetSelectedIdentityOrganization(string organizationId) =>
        new("infisical.get.v1.identities.details", HttpMethod.Get, "/api/v1/identities/details", new(organizationId),
            null, root => new(root, organizationId), false);

    public static ManagementRequest<ManagementPage<IdentitySummary>> ListProjectIdentities(string organizationId,
        string projectId, int offset = 0, int limit = 100, string? search = null)
    {
        string query = ProjectIdentityQuery(offset, limit, search);
        return new("infisical.get.v1.projects.by.projectId.identities", HttpMethod.Get,
            ProjectOperations.ProjectPath(projectId) + "/identities?" + query,
            InventorySelectorWire.Intent(organizationId, projectId, query), null,
            root => ScopedAccessOperations.CountedPage(root, "identities",
                value => new IdentitySummary(value, organizationId, projectId, metadataNonempty: false,
                    requireTimestamps: true), offset, limit), false);
    }

    /// <summary>Independently selected complete inventory intent, including paging and omitted search.</summary>
    public static ManagementTarget ProjectIdentityListTarget(string organizationId, string projectId,
        int offset = 0, int limit = 100, string? search = null) =>
        InventorySelectorWire.Intent(organizationId, projectId, ProjectIdentityQuery(offset, limit, search));

    private static string ProjectIdentityQuery(int offset, int limit, string? search)
    {
        string query = ManagementJson.Paging(offset, limit);
        if (search is not null) query += "&search=" + InventorySelectorWire.Escape(search);
        return query;
    }

    public static ManagementRequest<IdentitySummary> GetProjectIdentity(string organizationId, string projectId, string identityId) =>
        new("infisical.get.v1.projects.by.projectId.identities.by.identityId", HttpMethod.Get,
            IdentityPath(projectId, identityId), new(organizationId, projectId, identityId), null,
            root => new(ManagementJson.Object(root, "identity"), organizationId, projectId, identityId,
                metadataNonempty: false, requireTimestamps: true), false);

    public static ManagementRequest<IdentitySummary> CreateProjectIdentity(string organizationId, string projectId,
        string name, IReadOnlyList<MembershipRole>? roles = null, bool deleteProtection = false,
        IReadOnlyList<IdentityAttribute>? metadata = null)
    {
        Action<Utf8JsonWriter> write = ProjectIdentityCreateBody(name, roles, deleteProtection, metadata);
        return new("infisical.post.v1.projects.by.projectId.identities", HttpMethod.Post,
            ProjectOperations.ProjectPath(projectId) + "/identities",
            MembershipRoleWire.Intent(organizationId, projectId, name, write), write,
            root => new(ManagementJson.Object(root, "identity"), organizationId, projectId,
                metadataNonempty: false, requireTimestamps: true));
    }

    /// <summary>Complete independently approved project identity creation fields.</summary>
    public static ManagementTarget ProjectIdentityCreateTarget(string organizationId, string projectId,
        string name, IReadOnlyList<MembershipRole>? roles = null, bool deleteProtection = false,
        IReadOnlyList<IdentityAttribute>? metadata = null) =>
        MembershipRoleWire.Intent(organizationId, projectId, name,
            ProjectIdentityCreateBody(name, roles, deleteProtection, metadata));

    private static Action<Utf8JsonWriter> ProjectIdentityCreateBody(string name, IReadOnlyList<MembershipRole>? roles,
        bool deleteProtection, IReadOnlyList<IdentityAttribute>? metadata)
    {
        ManagementJson.Text(name, 255);
        MembershipRole[]? roleCopy = roles is null ? null : MembershipRole.Copy(roles, allowEmpty: true);
        IdentityAttribute[]? copy = metadata?.Take(101).ToArray();
        if (copy is not null && (copy.Length > 100 || copy.Any(item => item is null)))
            throw new ArgumentException("Invalid identity metadata budget.");
        return writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("name", name);
            writer.WriteBoolean("hasDeleteProtection", deleteProtection);
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
        };
    }

    public static ManagementRequest<IdentitySummary> UpdateProjectIdentity(string organizationId, string projectId,
        string identityId, string? name = null, bool? deleteProtection = null, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        IdentityChange(organizationId, projectId, identityId, name, null, deleteProtection, metadata);

    /// <summary>Independently approved complete project identity change.</summary>
    public static ManagementTarget ProjectIdentityUpdateTarget(string organizationId, string projectId,
        string identityId, string? name = null, bool? deleteProtection = null, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        MembershipRoleWire.Intent(organizationId, projectId, identityId,
            IdentityChangeBody(organizationId, projectId, identityId, name, null, deleteProtection, metadata));

    public static ManagementRequest<IdentitySummary> DeleteProjectIdentity(string organizationId, string projectId, string identityId) =>
        new("infisical.delete.v1.projects.by.projectId.identities.by.identityId", HttpMethod.Delete,
            IdentityPath(projectId, identityId), new(organizationId, projectId, identityId), null,
            root => new(ManagementJson.Object(root, "identity"), organizationId, projectId, identityId,
                metadataNonempty: false, requireTimestamps: true));

    private static ManagementRequest<IdentitySummary> IdentityChange(string org, string? project, string? identity,
        string? name, string? role, bool? deleteProtection, IReadOnlyList<IdentityAttribute>? metadata)
    {
        Action<Utf8JsonWriter> write = IdentityChangeBody(org, project, identity, name, role, deleteProtection, metadata);
        string prefix = project is null ? "v1.identities" : "v1.projects.by.projectId.identities";
        string path = project is null ? "/api/v1/identities" : ProjectOperations.ProjectPath(project) + "/identities";
        return new($"infisical.{(identity is null ? "post" : "patch")}.{prefix}" +
            (identity is null ? "" : ".by.identityId"), identity is null ? HttpMethod.Post : HttpMethod.Patch,
            path + (identity is null ? "" : "/" + ManagementJson.Escape(identity)),
            MembershipRoleWire.Intent(org, project, identity ?? name!, write), write,
            root => new(ManagementJson.Object(root, "identity"), org, project, identity,
                metadataNonempty: false, requireTimestamps: true,
                requireAuthMethods: project is null && identity is null, requireMetadata: project is null));
    }

    private static Action<Utf8JsonWriter> IdentityChangeBody(string org, string? project, string? identity,
        string? name, string? role, bool? deleteProtection, IReadOnlyList<IdentityAttribute>? metadata)
    {
        if (name is not null) ManagementJson.Text(name, 255);
        if (role is not null) ManagementJson.Text(role, 255);
        if (identity is null && name is null || identity is not null && name is null && role is null &&
            deleteProtection is null && metadata is null)
            throw new ArgumentException("An identity name or change is required.");
        IdentityAttribute[]? copy = metadata?.Take(101).ToArray();
        if (copy is not null && (copy.Length > 100 || copy.Any(item => item is null)))
            throw new ArgumentException("Invalid identity metadata budget.");
        return writer =>
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
                writer.WriteEndObject();
            };
    }

    private static string IdentityPath(string project, string identity) =>
        ProjectOperations.ProjectPath(project) + "/identities/" + ManagementJson.Escape(identity);
}
