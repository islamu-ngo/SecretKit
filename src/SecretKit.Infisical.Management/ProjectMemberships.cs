using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Native assignment metadata, not effective permissions.</summary>
public sealed class ProjectMembershipRole
{
    internal ProjectMembershipRole(JsonElement value, string? membershipId = null, bool groupMetadata = false)
    {
        if (membershipId is not null) ManagementJson.RequireEqual(value, "projectMembershipId", membershipId);
        Id = ManagementJson.Required(value, "id");
        Role = ManagementJson.Required(value, "role");
        CustomRoleId = ManagementJson.Optional(value, "customRoleId");
        if (membershipId is null)
        {
            CustomRoleName = ManagementJson.Optional(value, "customRoleName");
            CustomRoleSlug = ManagementJson.Optional(value, "customRoleSlug");
        }
        IsTemporary = value.TryGetProperty("isTemporary", out _)
            ? ManagementJson.Boolean(value, "isTemporary") : membershipId is null
                ? throw new ManagementContractException(SecretStatus.Unknown) : null;
        Mode = ManagementJson.Optional(value, "temporaryMode");
        Range = ManagementJson.Optional(value, "temporaryRange");
        StartsAt = ManagementJson.Optional(value, "temporaryAccessStartTime");
        EndsAt = ManagementJson.Optional(value, "temporaryAccessEndTime");
        CustomRoleIdField = ProjectWire.StringField(value, "customRoleId", nullable: true);
        ModeField = ProjectWire.StringField(value, "temporaryMode", nullable: true);
        RangeField = ProjectWire.StringField(value, "temporaryRange", nullable: true);
        StartsAtField = ProjectWire.StringField(value, "temporaryAccessStartTime", nullable: true);
        EndsAtField = ProjectWire.StringField(value, "temporaryAccessEndTime", nullable: true);
        if (membershipId is null)
        {
            CustomRoleNameField = ProjectWire.StringField(value, "customRoleName", nullable: true);
            CustomRoleSlugField = ProjectWire.StringField(value, "customRoleSlug", nullable: true);
        }
        if (groupMetadata)
        {
            CreatedAtField = ProjectWire.StringField(value, "createdAt");
            UpdatedAtField = ProjectWire.StringField(value, "updatedAt");
            CreatedAt = CreatedAtField.IsPresent ? CreatedAtField.Value : null;
            UpdatedAt = UpdatedAtField.IsPresent ? UpdatedAtField.Value : null;
        }
        if (membershipId is not null)
        {
            CreatedAt = ManagementJson.Required(value, "createdAt");
            UpdatedAt = ManagementJson.Required(value, "updatedAt");
            CreatedAtField = ProjectWire.StringField(value, "createdAt");
            UpdatedAtField = ProjectWire.StringField(value, "updatedAt");
        }
    }

    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Role { get; }
    [JsonIgnore] public string? CustomRoleId { get; }
    [JsonIgnore] public string? CustomRoleName { get; }
    [JsonIgnore] public string? CustomRoleSlug { get; }
    [JsonIgnore] public bool? IsTemporary { get; }
    [JsonIgnore] public string? Mode { get; }
    [JsonIgnore] public string? Range { get; }
    [JsonIgnore] public string? StartsAt { get; }
    [JsonIgnore] public string? EndsAt { get; }
    [JsonIgnore] public string? CreatedAt { get; }
    [JsonIgnore] public string? UpdatedAt { get; }
    [JsonIgnore] public ProjectField<string> CustomRoleIdField { get; }
    [JsonIgnore] public ProjectField<string> CustomRoleNameField { get; }
    [JsonIgnore] public ProjectField<string> CustomRoleSlugField { get; }
    [JsonIgnore] public ProjectField<string> ModeField { get; }
    [JsonIgnore] public ProjectField<string> RangeField { get; }
    [JsonIgnore] public ProjectField<string> StartsAtField { get; }
    [JsonIgnore] public ProjectField<string> EndsAtField { get; }
    [JsonIgnore] public ProjectField<string> CreatedAtField { get; }
    [JsonIgnore] public ProjectField<string> UpdatedAtField { get; }
    public override string ToString() => "[ProjectMembershipRole]";
}

/// <summary>Protected project user membership; no organization attestation is returned.</summary>
public sealed class ProjectMembershipSummary
{
    internal ProjectMembershipSummary(JsonElement value, string projectId, string? username = null)
    {
        ManagementJson.RequireEqual(value, "projectId", projectId);
        Id = ManagementJson.Required(value, "id");
        UserId = ManagementJson.Required(value, "userId");
        CreatedAt = ManagementJson.Optional(value, "createdAt");
        JsonElement user = ManagementJson.Object(value, "user");
        ManagementJson.RequireEqual(user, "id", UserId);
        if (username is not null) ManagementJson.RequireEqual(user, "username", username);
        User = new ProjectMembershipUser(user);
        Roles = ProjectMembershipOperations.ReadRoles(value);
    }

    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string UserId { get; }
    [JsonIgnore] public string? CreatedAt { get; }
    [JsonIgnore] public ProjectMembershipUser User { get; }
    [JsonIgnore] public IReadOnlyList<ProjectMembershipRole> Roles { get; }
    public bool IncludesPermissions => false;
    public override string ToString() => "[ProjectMembershipSummary]";
}

/// <summary>Project identity membership metadata, not credentials or delivery evidence.</summary>
public sealed class ProjectIdentityMembershipSummary
{
    internal ProjectIdentityMembershipSummary(JsonElement value, string organizationId, string projectId,
        string? identityId = null)
    {
        Id = ManagementJson.Required(value, "id");
        CreatedAt = ManagementJson.Required(value, "createdAt");
        UpdatedAt = ManagementJson.Required(value, "updatedAt");
        JsonElement identity = ManagementJson.Object(value, "identity");
        IdentityId = identityId is null ? ManagementJson.Required(value, "identityId") : ManagementJson.Required(identity, "id");
        if (identityId is not null) ManagementJson.RequireEqual(identity, "id", identityId);
        string? owner = ManagementJson.Optional(identity, "projectId");
        if (owner is not null && owner != projectId) throw new ManagementContractException(SecretStatus.Invalid);
        Identity = new IdentitySummary(identity, organizationId, owner, IdentityId);
        IdentityMetadata = new(identity, details: identityId is not null);
        if (identityId is not null)
        {
            LastLoginTime = ProjectWire.StringField(value, "lastLoginTime", nullable: true);
            LastLoginAuthMethod = ProjectWire.StringField(value, "lastLoginAuthMethod", nullable: true);
        }
        Roles = ProjectMembershipOperations.ReadRoles(value);
    }

    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string IdentityId { get; }
    [JsonIgnore] public string CreatedAt { get; }
    [JsonIgnore] public string UpdatedAt { get; }
    [JsonIgnore] public IdentitySummary Identity { get; }
    [JsonIgnore] public MembershipIdentityMetadata IdentityMetadata { get; }
    [JsonIgnore] public ProjectField<string> LastLoginTime { get; }
    [JsonIgnore] public ProjectField<string> LastLoginAuthMethod { get; }
    [JsonIgnore] public IReadOnlyList<ProjectMembershipRole> Roles { get; }
    public bool IncludesPermissions => false;
    public override string ToString() => "[ProjectIdentityMembershipSummary]";
}

public static class ProjectMembershipOperations
{
    /// <summary>Unpaginated native inventory, bounded to 1000 memberships without truncation.</summary>
    public static ManagementRequest<ManagementPage<ProjectMembershipSummary>> ListProjectMemberships(
        string organizationId, string projectId) =>
        new("infisical.get.v1.projects.by.projectId.memberships", HttpMethod.Get,
            Path(projectId), new(organizationId, projectId), null,
            root => new(ManagementJson.Array(root, "memberships").Select(value =>
            {
                ManagementJson.Required(value, "createdAt");
                return new ProjectMembershipSummary(value, projectId);
            }), true), false);

    public static ManagementRequest<ManagementPage<ProjectMembershipRole>> UpdateProjectMembershipRoles(
        string organizationId, string projectId, string membershipId, IReadOnlyList<MembershipRole> roles)
    {
        MembershipRole[] copy = MembershipRole.Copy(roles);
        return new("infisical.patch.v1.projects.by.projectId.memberships.by.membershipId", HttpMethod.Patch,
            Path(projectId) + "/" + ManagementJson.Escape(membershipId),
            MembershipOperations.RoleChangeTarget(organizationId, projectId, membershipId, copy), writer =>
            {
                writer.WriteStartObject();
                MembershipRole.Write(writer, copy);
                writer.WriteEndObject();
            }, root => new(ReadRoles(root, membershipId), true));
    }

    /// <summary>Native POST inspection: no mutation receipt or provisioning effect.</summary>
    public static ManagementRequest<ProjectMembershipSummary> InspectProjectMembershipByUsername(
        string organizationId, string projectId, string username)
    {
        ManagementJson.Text(username);
        return new("infisical.post.v1.projects.by.projectId.memberships.details", HttpMethod.Post,
            Path(projectId) + "/details", new(organizationId, projectId, username), writer =>
            {
                writer.WriteStartObject();
                writer.WriteString("username", username);
                writer.WriteEndObject();
            }, root => new(ManagementJson.Object(root, "membership"), projectId, username), false);
    }

    /// <summary>No total count is returned. A full page conservatively requires another explicit read.</summary>
    public static ManagementRequest<ManagementPage<AccessCandidate>> ListAvailableProjectIdentities(
        string organizationId, string projectId, int offset = 0, int limit = 20, string? identityName = null) =>
        new("infisical.get.v1.projects.by.projectId.memberships.available.identities", HttpMethod.Get,
            Path(projectId) + "/available-identities?" + Query(offset, limit, identityName),
            AvailableProjectIdentityListTarget(organizationId, projectId, offset, limit, identityName), null,
            root => ScopedAccessOperations.BoundedPage(ManagementJson.Array(root, "identities")
                .Select(value => new AccessCandidate(value)).ToArray(), offset, limit), false);

    public static ManagementRequest<ManagementPage<ProjectIdentityMembershipSummary>> ListProjectIdentityMemberships(
        string organizationId, string projectId, int offset = 0, int limit = 20,
        string? identityName = null, string? roles = null)
    {
        string query = Query(offset, limit, identityName);
        if (roles is not null) query += "&roles=" + InventorySelectorWire.Escape(roles);
        return new("infisical.get.v1.projects.by.projectId.memberships.identities", HttpMethod.Get,
            Path(projectId) + "/identities?" + query,
            InventorySelectorWire.Intent(organizationId, projectId, query), null,
            root => ScopedAccessOperations.CountedPage(root, "identityMemberships",
                value => new ProjectIdentityMembershipSummary(value, organizationId, projectId), offset, limit), false);
    }

    public static ManagementTarget AvailableProjectIdentityListTarget(string organizationId, string projectId,
        int offset = 0, int limit = 20, string? identityName = null) =>
        InventorySelectorWire.Intent(organizationId, projectId, Query(offset, limit, identityName));

    public static ManagementTarget ProjectIdentityMembershipListTarget(string organizationId, string projectId,
        int offset = 0, int limit = 20, string? identityName = null, string? roles = null)
    {
        string query = Query(offset, limit, identityName);
        if (roles is not null) query += "&roles=" + InventorySelectorWire.Escape(roles);
        return InventorySelectorWire.Intent(organizationId, projectId, query);
    }

    internal static IReadOnlyList<ProjectMembershipRole> ReadRoles(JsonElement value, string? membershipId = null) =>
        ReadRoleArray(ManagementJson.Array(value, "roles"), membershipId);

    internal static IReadOnlyList<ProjectMembershipRole> ReadRoleArray(JsonElement value, bool groupMetadata) =>
        ReadRoleArray(ManagementJson.Array(value), groupMetadata: groupMetadata);

    private static IReadOnlyList<ProjectMembershipRole> ReadRoleArray(JsonElement.ArrayEnumerator roles,
        string? membershipId = null, bool groupMetadata = false)
    {
        if (roles.Count() > 100) throw new ManagementContractException(SecretStatus.Unknown);
        return Array.AsReadOnly(roles.Select(role => new ProjectMembershipRole(role, membershipId, groupMetadata)).ToArray());
    }

    private static string Query(int offset, int limit, string? identityName)
    {
        string query = ManagementJson.Paging(offset, limit);
        if (identityName is not null) query += "&identityName=" + InventorySelectorWire.Escape(identityName);
        return query;
    }

    private static string Path(string projectId) => ProjectOperations.ProjectPath(projectId) + "/memberships";
}
