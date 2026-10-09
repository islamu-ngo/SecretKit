using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>A native permanent or relative-time role assignment, not an effective capability.</summary>
public sealed class MembershipRole
{
    public MembershipRole(string role, DateTimeOffset? startsAt = null, string? relativeDuration = null)
    {
        ManagementJson.Text(role, 255);
        if (startsAt.HasValue != (relativeDuration is not null))
            throw new ArgumentException("Relative role access requires both start and native duration.");
        if (relativeDuration is not null) ManagementJson.Text(relativeDuration, 64);
        Role = role;
        StartsAt = startsAt;
        RelativeDuration = relativeDuration;
    }
    [JsonIgnore] public string Role { get; }
    [JsonIgnore] public DateTimeOffset? StartsAt { get; }
    [JsonIgnore] public string? RelativeDuration { get; }
    public override string ToString() => "[MembershipRole]";

    internal static MembershipRole[] Copy(IReadOnlyList<MembershipRole> roles)
    {
        ArgumentNullException.ThrowIfNull(roles);
        MembershipRole[] copy = roles.Take(101).ToArray();
        if (copy.Length is < 1 or > 100 || copy.Any(item => item is null))
            throw new ArgumentException("One to one hundred role assignments are required.");
        return copy;
    }

    internal static void Write(Utf8JsonWriter writer, MembershipRole[] roles)
    {
        writer.WriteStartArray("roles");
        foreach (MembershipRole role in roles)
        {
            writer.WriteStartObject();
            writer.WriteString("role", role.Role);
            writer.WriteBoolean("isTemporary", role.StartsAt.HasValue);
            if (role.StartsAt is { } start)
            {
                writer.WriteString("temporaryAccessStartTime", start);
                writer.WriteString("temporaryMode", "relative");
                writer.WriteString("temporaryRange", role.RelativeDuration);
            }
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }
}

/// <summary>Membership identity projection. It does not report the effective role set.</summary>
public sealed class MembershipSummary
{
    internal MembershipSummary(JsonElement value, string principalField, string? principalId,
        string? scopeField = null, string? scopeId = null)
    {
        if (scopeField is not null) ManagementJson.RequireEqual(value, scopeField, scopeId!);
        if (principalId is not null) ManagementJson.RequireEqual(value, principalField, principalId);
        Id = ManagementJson.Required(value, "id");
        PrincipalId = ManagementJson.Required(value, principalField);
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string PrincipalId { get; }
    public bool IncludesRoles => false;
    public override string ToString() => "[MembershipSummary]";
}

public static class MembershipOperations
{
    public static ManagementRequest<ManagementPage<MembershipRoleMetadata>> UpdateProjectGroupRoles(
        string organizationId, string projectId, string groupId, string expectedMembershipId,
        IReadOnlyList<MembershipRole> roles)
    {
        ManagementJson.Text(expectedMembershipId);
        MembershipRole[] copy = MembershipRole.Copy(roles);
        return new("infisical.patch.v1.projects.by.projectId.memberships.groups.by.groupId", HttpMethod.Patch,
            ProjectGroupPath(projectId, groupId), new(organizationId, projectId, groupId, expectedMembershipId),
            writer => WriteRoles(writer, copy), root => new(ManagementJson.Array(root, "roles")
                .Select(value => new MembershipRoleMetadata(value, expectedMembershipId)), true));
    }

    public static ManagementRequest<MembershipSummary> AddProjectIdentity(string organizationId, string projectId,
        string identityId, IReadOnlyList<MembershipRole> roles) =>
        ChangeProjectIdentity(organizationId, projectId, identityId, roles, HttpMethod.Post);

    public static ManagementRequest<MembershipSummary> UpdateProjectIdentityRoles(string organizationId, string projectId,
        string identityId, IReadOnlyList<MembershipRole> roles) =>
        ChangeProjectIdentity(organizationId, projectId, identityId, roles, HttpMethod.Patch);

    public static ManagementRequest<MembershipSummary> RemoveProjectIdentity(string organizationId, string projectId,
        string identityId) => ChangeProjectIdentity(organizationId, projectId, identityId, null, HttpMethod.Delete);

    public static ManagementRequest<IdentitySummary> GetProjectIdentityMembership(string organizationId, string projectId, string identityId) =>
        new("infisical.get.v1.projects.by.projectId.memberships.identities.by.identityId", HttpMethod.Get,
            ProjectIdentityPath(projectId, identityId), new(organizationId, projectId, identityId), null,
            root =>
            {
                JsonElement value = ManagementJson.Object(ManagementJson.Object(root, "identityMembership"), "identity");
                // Organization identities can be members of a project without being project-owned.
                string? owner = ManagementJson.Optional(value, "projectId");
                if (owner is not null && owner != projectId) throw new ManagementContractException(SecretStatus.Invalid);
                return new(value, organizationId, owner, identityId);
            }, false);

    public static ManagementRequest<MembershipSummary> RemoveProjectGroup(string organizationId, string projectId, string groupId) =>
        new("infisical.delete.v1.projects.by.projectId.memberships.groups.by.groupId", HttpMethod.Delete,
            ProjectGroupPath(projectId, groupId), new(organizationId, projectId, groupId), null,
            root => new(ManagementJson.Object(root, "groupMembership"), "groupId", groupId, "projectId", projectId));

    public static ManagementRequest<MembershipSummary> GetProjectGroup(string organizationId, string projectId, string groupId) =>
        new("infisical.get.v1.projects.by.projectId.memberships.groups.by.groupId", HttpMethod.Get,
            ProjectGroupPath(projectId, groupId), new(organizationId, projectId, groupId), null,
            root => ParseGroupMembership(ManagementJson.Object(root, "groupMembership"), organizationId, projectId, groupId), false);

    public static ManagementRequest<MembershipSummary> AddProjectGroup(string organizationId, string projectId,
        string groupId, IReadOnlyList<MembershipRole> roles)
    {
        MembershipRole[] copy = MembershipRole.Copy(roles);
        return new("infisical.post.v1.projects.by.projectId.memberships.groups.by.groupId", HttpMethod.Post,
            ProjectGroupPath(projectId, groupId), new(organizationId, projectId, groupId),
            writer => WriteRoles(writer, copy),
            root => ParseGroupMembership(ManagementJson.Object(root, "groupMembership"), organizationId, projectId, groupId));
    }

    public static ManagementRequest<ManagementPage<MembershipSummary>> ListProjectGroups(string organizationId, string projectId) =>
        new("infisical.get.v1.projects.by.projectId.memberships.groups", HttpMethod.Get,
            ProjectOperations.ProjectPath(projectId) + "/memberships/groups", new(organizationId, projectId), null,
            root => new(ManagementJson.Array(root, "groupMemberships")
                .Select(value => ParseGroupMembership(value, organizationId, projectId, null)), true), false);

    public static ManagementRequest<MembershipSummary> RemoveOrganizationGroup(string organizationId, string groupId) =>
        new("infisical.delete.v1.organizations.memberships.groups.by.groupId", HttpMethod.Delete,
            OrganizationGroupPath(groupId), new(organizationId, resourceId: groupId), null,
            root => new(ManagementJson.Object(root, "groupMembership"), "groupId", groupId, "orgId", organizationId));

    public static ManagementRequest<MembershipSummary> GetOrganizationGroup(string organizationId, string groupId) =>
        new("infisical.get.v1.organizations.memberships.groups.by.groupId", HttpMethod.Get,
            OrganizationGroupPath(groupId), new(organizationId, resourceId: groupId), null,
            root => ParseGroupMembership(ManagementJson.Object(root, "groupMembership"), organizationId, null, groupId), false);

    public static ManagementRequest<MembershipSummary> AddOrganizationGroup(string organizationId, string groupId,
        IReadOnlyList<MembershipRole> roles) => ChangeOrganizationGroup(organizationId, groupId, roles, false);

    public static ManagementRequest<MembershipSummary> UpdateOrganizationGroupRoles(string organizationId, string groupId,
        IReadOnlyList<MembershipRole> roles) => ChangeOrganizationGroup(organizationId, groupId, roles, true);

    public static ManagementRequest<ManagementPage<MembershipSummary>> ListOrganizationGroups(string organizationId,
        int offset = 0, int limit = 100) =>
        new("infisical.get.v1.organizations.memberships.groups", HttpMethod.Get,
            "/api/v1/organizations/memberships/groups?" + ManagementJson.Paging(offset, limit), new(organizationId), null,
            root => ScopedAccessOperations.CountedPage(root, "groupMemberships",
                value => ParseGroupMembership(value, organizationId, null, null), offset, limit), false);

    private static ManagementRequest<MembershipSummary> ChangeOrganizationGroup(string org, string group,
        IReadOnlyList<MembershipRole> roles, bool update)
    {
        MembershipRole[] copy = MembershipRole.Copy(roles);
        return new(update ? "infisical.patch.v1.organizations.memberships.groups.by.groupId" :
            "infisical.post.v1.organizations.memberships.groups.by.groupId",
            update ? HttpMethod.Patch : HttpMethod.Post, OrganizationGroupPath(group), new(org, resourceId: group),
            writer => WriteRoles(writer, copy),
            root => ParseGroupMembership(ManagementJson.Object(root, "groupMembership"), org, null, group));
    }

    private static ManagementRequest<MembershipSummary> ChangeProjectIdentity(string org, string project, string identity,
        IReadOnlyList<MembershipRole>? roles, HttpMethod method)
    {
        MembershipRole[]? copy = roles is null ? null : MembershipRole.Copy(roles);
        return new($"infisical.{method.Method.ToLowerInvariant()}.v1.projects.by.projectId.memberships.identities.by.identityId",
            method, ProjectIdentityPath(project, identity), new(org, project, identity),
            copy is null ? null : writer => WriteRoles(writer, copy),
            root => new(ManagementJson.Object(root, "identityMembership"), "identityId", identity, "projectId", project));
    }

    private static MembershipSummary ParseGroupMembership(JsonElement value, string org, string? project, string? groupId)
    {
        JsonElement group = ManagementJson.Object(value, "group");
        string? returnedOrg = ManagementJson.Optional(group, "orgId");
        if (returnedOrg is not null && returnedOrg != org) throw new ManagementContractException(SecretStatus.Invalid);
        ManagementJson.RequireEqual(group, "id", ManagementJson.Required(value, "groupId"));
        return new(value, "groupId", groupId, project is null ? null : "projectId", project);
    }

    private static void WriteRoles(Utf8JsonWriter writer, MembershipRole[] roles)
    {
        writer.WriteStartObject();
        MembershipRole.Write(writer, roles);
        writer.WriteEndObject();
    }

    private static string ProjectIdentityPath(string project, string identity) =>
        ProjectOperations.ProjectPath(project) + "/memberships/identities/" + ManagementJson.Escape(identity);
    private static string ProjectGroupPath(string project, string group) =>
        ProjectOperations.ProjectPath(project) + "/memberships/groups/" + ManagementJson.Escape(group);
    private static string OrganizationGroupPath(string group) =>
        "/api/v1/organizations/memberships/groups/" + ManagementJson.Escape(group);
}

/// <summary>Native returned assignment metadata, not effective-permission evidence.</summary>
public sealed class MembershipRoleMetadata
{
    internal MembershipRoleMetadata(JsonElement value, string expectedMembershipId)
    {
        ManagementJson.RequireEqual(value, "projectMembershipId", expectedMembershipId);
        Id = ManagementJson.Required(value, "id");
        MembershipId = expectedMembershipId;
        Role = ManagementJson.Required(value, "role");
        CustomRoleId = ManagementJson.Optional(value, "customRoleId");
        IsTemporary = ManagementJson.Boolean(value, "isTemporary");
        StartsAt = ManagementJson.Optional(value, "temporaryAccessStartTime");
        EndsAt = ManagementJson.Optional(value, "temporaryAccessEndTime");
        Mode = ManagementJson.Optional(value, "temporaryMode");
        Range = ManagementJson.Optional(value, "temporaryRange");
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string MembershipId { get; }
    [JsonIgnore] public string Role { get; }
    [JsonIgnore] public string? CustomRoleId { get; }
    public bool IsTemporary { get; }
    [JsonIgnore] public string? StartsAt { get; }
    [JsonIgnore] public string? EndsAt { get; }
    [JsonIgnore] public string? Mode { get; }
    [JsonIgnore] public string? Range { get; }
    public override string ToString() => "[MembershipRoleMetadata]";
}
