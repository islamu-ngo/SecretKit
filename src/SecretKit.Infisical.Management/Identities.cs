using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Management;

/// <summary>A bounded key/value entry supplied as identity metadata, not authentication material.</summary>
public sealed class IdentityAttribute
{
    /// <summary>Validates and captures one metadata pair without contacting the provider.</summary>
    public IdentityAttribute(string key, string value)
    {
        ManagementJson.Text(key, 255);
        ManagementJson.Text(value, 4096);
        Key = key;
        Value = value;
    }
    /// <summary>Gets the protected metadata key.</summary>
    [JsonIgnore] public string Key { get; }
    /// <summary>Gets the protected metadata value; exclude it from diagnostics.</summary>
    [JsonIgnore] public string Value { get; }
    /// <summary>Returns a marker without the key or value.</summary>
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
    /// <summary>Gets the returned identity identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned display name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the project coordinate, or null for an organization-level identity.</summary>
    [JsonIgnore] public string? ProjectId { get; }
    /// <summary>Gets returned organization presence without substituting the request coordinate.</summary>
    [JsonIgnore] public IdentityField<string> OrganizationIdField { get; }
    /// <summary>Gets project presence, preserving omission and explicit null.</summary>
    [JsonIgnore] public IdentityField<string> ProjectIdField { get; }
    /// <summary>Gets the optional singular authentication-method metadata, including explicit null.</summary>
    [JsonIgnore] public IdentityField<string> AuthMethod { get; }
    /// <summary>Gets returned authentication methods when present; metadata does not prove login capability.</summary>
    [JsonIgnore] public IdentityField<IReadOnlyList<string>> AuthMethods { get; }
    /// <summary>Gets returned locked-out methods when present, not an inferred lockout policy.</summary>
    [JsonIgnore] public IdentityField<IReadOnlyList<string>> ActiveLockoutAuthMethods { get; }
    /// <summary>Gets returned deletion-protection metadata when present.</summary>
    [JsonIgnore] public IdentityField<bool> HasDeleteProtection { get; }
    /// <summary>Gets returned creation time when present, without inventing a timestamp.</summary>
    [JsonIgnore] public IdentityField<string> CreatedAt { get; }
    /// <summary>Gets returned update time when present.</summary>
    [JsonIgnore] public IdentityField<string> UpdatedAt { get; }
    /// <summary>Gets returned metadata entries when present; absence differs from an empty collection.</summary>
    [JsonIgnore] public IdentityField<IReadOnlyList<IdentityMetadataEntry>> Metadata { get; }
    /// <summary>Gets outer membership metadata when returned, distinct from identity fields.</summary>
    [JsonIgnore] public IdentityField<IdentityMembershipMetadata> Membership { get; }
    /// <summary>Returns a marker without identity metadata.</summary>
    public override string ToString() => "[IdentitySummary]";
}

/// <summary>Organization metadata returned for the selected identity; does not establish token-to-principal binding.</summary>
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
    /// <summary>Gets the returned organization identifier matched to the selection.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the organization display name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the native organization slug.</summary>
    [JsonIgnore] public string Slug { get; }
    /// <summary>Returns a marker without organization coordinates.</summary>
    public override string ToString() => "[IdentityOrganization]";
}

/// <summary>Constructs disposable identity requests; execution requires independently approved grants and selected credentials.</summary>
public static class IdentityOperations
{
    /// <summary>Builds an organization identity-list request; count evidence may mark the unpaged result incomplete.</summary>
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

    /// <summary>Builds an exact organization identity lookup request with membership correspondence checks.</summary>
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

    /// <summary>Builds organization identity creation with copied optional metadata; null omits metadata.</summary>
    public static ManagementRequest<IdentitySummary> CreateOrganizationIdentity(string organizationId, string name,
        string role, bool deleteProtection = false, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        IdentityChange(organizationId, null, null, name, role, deleteProtection, metadata);

    /// <summary>Builds an organization identity change; null omits a field while empty metadata explicitly replaces it.</summary>
    public static ManagementRequest<IdentitySummary> UpdateOrganizationIdentity(string organizationId, string identityId,
        string? name = null, string? role = null, bool? deleteProtection = null, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        IdentityChange(organizationId, null, identityId ?? throw new ArgumentNullException(nameof(identityId)),
            name, role, deleteProtection, metadata);

    /// <summary>Independently approved complete organization identity creation body.</summary>
    public static ManagementTarget OrganizationIdentityCreateTarget(string organizationId, string name,
        string role, bool deleteProtection = false, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        MembershipRoleWire.Intent(organizationId, null, name,
            IdentityChangeBody(organizationId, null, null, name, role, deleteProtection, metadata));

    /// <summary>Independently approved complete change, preserving omitted fields and empty metadata.</summary>
    public static ManagementTarget OrganizationIdentityUpdateTarget(string organizationId, string identityId,
        string? name = null, string? role = null, bool? deleteProtection = null, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        MembershipRoleWire.Intent(organizationId, null, identityId ?? throw new ArgumentNullException(nameof(identityId)),
            IdentityChangeBody(organizationId, null, identityId, name, role, deleteProtection, metadata));

    /// <summary>Builds deletion of one organization identity; retain a client receipt across uncertain execution.</summary>
    public static ManagementRequest<IdentitySummary> DeleteOrganizationIdentity(string organizationId, string identityId) =>
        new("infisical.delete.v1.identities.by.identityId", HttpMethod.Delete,
            "/api/v1/identities/" + ManagementJson.Escape(identityId), new(organizationId, resourceId: identityId), null,
            root => new(ManagementJson.Object(root, "identity"), organizationId, id: identityId,
                metadataNonempty: false, requireTimestamps: true));

    /// <summary>Builds the selected identity organization lookup; returned metadata is not principal attestation.</summary>
    public static ManagementRequest<IdentityOrganization> GetSelectedIdentityOrganization(string organizationId) =>
        new("infisical.get.v1.identities.details", HttpMethod.Get, "/api/v1/identities/details", new(organizationId),
            null, root => new(root, organizationId), false);

    /// <summary>Builds a bounded project identity inventory request with exact paging and optional search intent.</summary>
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
        InventorySelectorWire.Intent(organizationId, projectId ?? throw new ArgumentNullException(nameof(projectId)),
            ProjectIdentityQuery(offset, limit, search));

    private static string ProjectIdentityQuery(int offset, int limit, string? search)
    {
        string query = ManagementJson.Paging(offset, limit);
        if (search is not null) query += "&search=" + InventorySelectorWire.Escape(search);
        return query;
    }

    /// <summary>Builds a lookup for the exact project identity, not an organization-wide fallback.</summary>
    public static ManagementRequest<IdentitySummary> GetProjectIdentity(string organizationId, string projectId, string identityId) =>
        new("infisical.get.v1.projects.by.projectId.identities.by.identityId", HttpMethod.Get,
            IdentityPath(projectId, identityId), new(organizationId, projectId, identityId), null,
            root => new(ManagementJson.Object(root, "identity"), organizationId, projectId, identityId,
                metadataNonempty: false, requireTimestamps: true), false);

    /// <summary>Builds project identity creation; null roles or metadata omit those fields, while empty collections are explicit.</summary>
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
        MembershipRoleWire.Intent(organizationId, projectId ?? throw new ArgumentNullException(nameof(projectId)), name,
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

    /// <summary>Builds a project identity change preserving omitted fields and explicit empty metadata.</summary>
    public static ManagementRequest<IdentitySummary> UpdateProjectIdentity(string organizationId, string projectId,
        string identityId, string? name = null, bool? deleteProtection = null, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        IdentityChange(organizationId, projectId ?? throw new ArgumentNullException(nameof(projectId)),
            identityId ?? throw new ArgumentNullException(nameof(identityId)), name, null, deleteProtection, metadata);

    /// <summary>Independently approved complete project identity change.</summary>
    public static ManagementTarget ProjectIdentityUpdateTarget(string organizationId, string projectId,
        string identityId, string? name = null, bool? deleteProtection = null, IReadOnlyList<IdentityAttribute>? metadata = null) =>
        MembershipRoleWire.Intent(organizationId, projectId ?? throw new ArgumentNullException(nameof(projectId)),
            identityId ?? throw new ArgumentNullException(nameof(identityId)),
            IdentityChangeBody(organizationId, projectId, identityId, name, null, deleteProtection, metadata));

    /// <summary>Builds deletion of the exact project identity; execution requires a fresh mutation receipt.</summary>
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
