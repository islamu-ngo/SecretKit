using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

public enum OrganizationGroupOrder { Name, Slug, Role }

/// <summary>Copied native scalar or array role filter. Null omits; an empty array is explicit intent.</summary>
public sealed class OrganizationGroupRoleFilter
{
    private readonly string[] _values;
    private OrganizationGroupRoleFilter(string[] values, bool array)
    {
        if (values.Length > 100) throw new ArgumentException("Invalid inventory role filter budget.");
        foreach (string value in values) InventorySelectorWire.Escape(value);
        _values = values;
        IsArray = array;
    }

    internal bool IsArray { get; }
    public static OrganizationGroupRoleFilter Scalar(string role) => new([role], false);
    public static OrganizationGroupRoleFilter Array(IReadOnlyList<string> roles)
    {
        ArgumentNullException.ThrowIfNull(roles);
        return new(roles.Take(101).ToArray(), true);
    }

    internal string Query => string.Concat(_values.Select(value => "&roles=" + InventorySelectorWire.Escape(value)));
    public override string ToString() => "[OrganizationGroupRoleFilter]";
}

/// <summary>A native permanent or relative-time role assignment, not an effective capability.</summary>
public sealed class MembershipRole
{
    public MembershipRole(string role, DateTimeOffset? startsAt = null, string? relativeDuration = null,
        bool omitPermanentDiscriminator = false)
    {
        ManagementJson.Text(role, 255);
        if (startsAt.HasValue != (relativeDuration is not null))
            throw new ArgumentException("Relative role access requires both start and native duration.");
        if (relativeDuration is not null) ManagementJson.Text(relativeDuration, 64);
        if (omitPermanentDiscriminator && startsAt is not null)
            throw new ArgumentException("Temporary roles require their discriminator.");
        Role = role;
        StartsAt = startsAt;
        RelativeDuration = relativeDuration;
        IsTemporary = startsAt.HasValue ? true : omitPermanentDiscriminator ? null : false;
    }
    [JsonIgnore] public string Role { get; }
    [JsonIgnore] public DateTimeOffset? StartsAt { get; }
    [JsonIgnore] public string? RelativeDuration { get; }
    [JsonIgnore] public bool? IsTemporary { get; }
    public override string ToString() => "[MembershipRole]";

    internal static MembershipRole[] Copy(IReadOnlyList<MembershipRole> roles, bool allowEmpty = false)
    {
        ArgumentNullException.ThrowIfNull(roles);
        MembershipRole[] copy = roles.Take(101).ToArray();
        if (copy.Length > 100 || !allowEmpty && copy.Length == 0 || copy.Any(item => item is null))
            throw new ArgumentException("Invalid role assignment budget.");
        return copy;
    }

    internal static void Write(Utf8JsonWriter writer, MembershipRole[] roles)
    {
        writer.WriteStartArray("roles");
        foreach (MembershipRole role in roles)
        {
            writer.WriteStartObject();
            writer.WriteString("role", role.Role);
            if (role.IsTemporary is { } temporary) writer.WriteBoolean("isTemporary", temporary);
            if (role.StartsAt is { } start)
            {
                writer.WriteString("temporaryAccessStartTime", start.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
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
        string? scopeField = null, string? scopeId = null, bool groupDetails = false)
    {
        if (scopeField is not null) ManagementJson.RequireEqual(value, scopeField, scopeId!);
        if (principalId is not null) ManagementJson.RequireEqual(value, principalField, principalId);
        Id = ManagementJson.Required(value, "id");
        PrincipalId = ManagementJson.Required(value, principalField);
        CreatedAt = ProjectWire.StringField(value, "createdAt");
        UpdatedAt = ProjectWire.StringField(value, "updatedAt");
        if (!CreatedAt.IsPresent || !UpdatedAt.IsPresent)
            throw new ManagementContractException(SecretStatus.Unknown);
        if (groupDetails)
        {
            Group = new(ManagementJson.Object(value, "group"));
            Roles = ProjectWire.Field(value, "roles", roles =>
                ProjectMembershipOperations.ReadRoleArray(roles, groupMetadata: true));
            if (!Roles.IsPresent) throw new ManagementContractException(SecretStatus.Unknown);
        }
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string PrincipalId { get; }
    [JsonIgnore] public ProjectField<string> CreatedAt { get; }
    [JsonIgnore] public ProjectField<string> UpdatedAt { get; }
    [JsonIgnore] public MembershipGroupDetails? Group { get; }
    [JsonIgnore] public ProjectField<IReadOnlyList<ProjectMembershipRole>> Roles { get; }
    public bool IncludesRoles => Roles.IsPresent;
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
            ProjectGroupPath(projectId, groupId), RoleChangeTarget(organizationId, projectId, groupId,
                copy, expectedMembershipId),
            writer => WriteRoles(writer, copy), root => new(ManagementJson.Array(root, "roles")
                .Select(value => new MembershipRoleMetadata(value, expectedMembershipId)), true));
    }

    public static ManagementRequest<MembershipSummary> AddProjectIdentity(string organizationId, string projectId,
        string identityId, IReadOnlyList<MembershipRole>? roles = null) =>
        AddProjectIdentity(organizationId, projectId, identityId, new MembershipRoleSelection(roles: roles));

    public static ManagementRequest<MembershipSummary> AddProjectIdentity(string organizationId, string projectId,
        string identityId, MembershipRoleSelection roles) =>
        ChangeProjectIdentity(organizationId, projectId, identityId, roles, HttpMethod.Post);

    public static ManagementRequest<MembershipSummary> UpdateProjectIdentityRoles(string organizationId, string projectId,
        string identityId, IReadOnlyList<MembershipRole> roles) =>
        ChangeProjectIdentity(organizationId, projectId, identityId, new MembershipRoleSelection(roles: roles), HttpMethod.Patch);

    public static ManagementRequest<MembershipSummary> RemoveProjectIdentity(string organizationId, string projectId,
        string identityId) => ChangeProjectIdentity(organizationId, projectId, identityId, null, HttpMethod.Delete);

    public static ManagementRequest<ProjectIdentityMembershipSummary> GetProjectIdentityMembership(string organizationId, string projectId, string identityId) =>
        new("infisical.get.v1.projects.by.projectId.memberships.identities.by.identityId", HttpMethod.Get,
            ProjectIdentityPath(projectId, identityId), new(organizationId, projectId, identityId), null,
            root =>
            {
                return new(ManagementJson.Object(root, "identityMembership"), organizationId, projectId,
                    identityId);
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
        string groupId, IReadOnlyList<MembershipRole>? roles = null) =>
        AddProjectGroup(organizationId, projectId, groupId, new MembershipRoleSelection(roles: roles));

    public static ManagementRequest<MembershipSummary> AddProjectGroup(string organizationId, string projectId,
        string groupId, MembershipRoleSelection roles)
    {
        ArgumentNullException.ThrowIfNull(roles);
        roles.Validate(scalarAllowed: true, omissionAllowed: true, emptyAllowed: true);
        return new("infisical.post.v1.projects.by.projectId.memberships.groups.by.groupId", HttpMethod.Post,
            ProjectGroupPath(projectId, groupId), RoleChangeTarget(organizationId, projectId, groupId, roles),
            roles.WriteObject,
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
        int offset = 0, int limit = 100, OrganizationGroupOrder? orderBy = null,
        ManagementListOrder? order = null, string? search = null, OrganizationGroupRoleFilter? roles = null)
    {
        string query = OrganizationGroupQuery(offset, limit, orderBy, order, search, roles);
        return new("infisical.get.v1.organizations.memberships.groups", HttpMethod.Get,
            "/api/v1/organizations/memberships/groups?" + query,
            InventorySelectorWire.Intent(organizationId, null, query, roles?.IsArray), null,
            root => ScopedAccessOperations.CountedPage(root, "groupMemberships",
                value => ParseGroupMembership(value, organizationId, null, null), offset, limit), false);
    }

    /// <summary>Independently selected complete inventory intent; role scalar, array and omission differ.</summary>
    public static ManagementTarget OrganizationGroupListTarget(string organizationId,
        int offset = 0, int limit = 100, OrganizationGroupOrder? orderBy = null,
        ManagementListOrder? order = null, string? search = null, OrganizationGroupRoleFilter? roles = null) =>
        InventorySelectorWire.Intent(organizationId, null,
            OrganizationGroupQuery(offset, limit, orderBy, order, search, roles), roles?.IsArray);

    private static string OrganizationGroupQuery(int offset, int limit, OrganizationGroupOrder? orderBy,
        ManagementListOrder? order, string? search, OrganizationGroupRoleFilter? roles)
    {
        string query = ManagementJson.Paging(offset, limit);
        if (orderBy is { } column)
            query += "&orderBy=" + (column switch
            {
                OrganizationGroupOrder.Name => "name",
                OrganizationGroupOrder.Slug => "slug",
                OrganizationGroupOrder.Role => "role",
                _ => throw new ArgumentOutOfRangeException(nameof(orderBy))
            });
        if (order is { } direction)
            query += "&orderDirection=" + (direction switch
            {
                ManagementListOrder.Ascending => "asc",
                ManagementListOrder.Descending => "desc",
                _ => throw new ArgumentOutOfRangeException(nameof(order))
            });
        if (search is not null) query += "&search=" + InventorySelectorWire.Escape(search);
        if (roles is not null) query += roles.Query;
        return query;
    }

    private static ManagementRequest<MembershipSummary> ChangeOrganizationGroup(string org, string group,
        IReadOnlyList<MembershipRole> roles, bool update)
    {
        MembershipRole[] copy = MembershipRole.Copy(roles);
        return new(update ? "infisical.patch.v1.organizations.memberships.groups.by.groupId" :
            "infisical.post.v1.organizations.memberships.groups.by.groupId",
            update ? HttpMethod.Patch : HttpMethod.Post, OrganizationGroupPath(group), RoleChangeTarget(org, null, group, copy),
            writer => WriteRoles(writer, copy),
            root => ParseGroupMembership(ManagementJson.Object(root, "groupMembership"), org, null, group));
    }

    private static ManagementRequest<MembershipSummary> ChangeProjectIdentity(string org, string project, string identity,
        MembershipRoleSelection? roles, HttpMethod method)
    {
        roles?.Validate(scalarAllowed: method == HttpMethod.Post, omissionAllowed: method == HttpMethod.Post,
            emptyAllowed: method == HttpMethod.Post);
        return new($"infisical.{method.Method.ToLowerInvariant()}.v1.projects.by.projectId.memberships.identities.by.identityId",
            method, ProjectIdentityPath(project, identity), roles is null ? new(org, project, identity) :
                RoleChangeTarget(org, project, identity, roles),
            roles is null ? null : roles.WriteObject,
            root => new(ManagementJson.Object(root, "identityMembership"), "identityId", identity, "projectId", project));
    }

    /// <summary>Build from independently approved fields, never from an incoming request's Target.
    /// The expected membership identifier is part of group-update intent.</summary>
    public static ManagementTarget RoleChangeTarget(string organizationId, string? projectId, string principalId,
        IReadOnlyList<MembershipRole> roles, string? expectedMembershipId = null) =>
        RoleChangeTarget(organizationId, projectId, principalId, new MembershipRoleSelection(roles: roles), expectedMembershipId);

    public static ManagementTarget RoleChangeTarget(string organizationId, string? projectId, string principalId,
        MembershipRoleSelection roles, string? expectedMembershipId = null)
    {
        ArgumentNullException.ThrowIfNull(roles);
        if (expectedMembershipId is not null) ManagementJson.Text(expectedMembershipId);
        return MembershipRoleWire.Intent(organizationId, projectId, principalId, roles.WriteObject, expectedMembershipId);
    }

    private static MembershipSummary ParseGroupMembership(JsonElement value, string org, string? project, string? groupId)
    {
        JsonElement group = ManagementJson.Object(value, "group");
        string? returnedOrg = ManagementJson.Optional(group, "orgId");
        // Organization membership details report the group's owner, which may be a parent organization.
        if (project is not null && returnedOrg is not null && returnedOrg != org)
            throw new ManagementContractException(SecretStatus.Invalid);
        ManagementJson.RequireEqual(group, "id", ManagementJson.Required(value, "groupId"));
        return new(value, "groupId", groupId, project is null ? null : "projectId", project, groupDetails: true);
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
        ProjectOperations.ProjectPath(project) + "/memberships/groups/" + ManagementJson.Escape(ManagementJson.UuidInput(group));
    private static string OrganizationGroupPath(string group) =>
        "/api/v1/organizations/memberships/groups/" + ManagementJson.Escape(ManagementJson.UuidInput(group));
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
        CustomRoleIdField = ProjectWire.StringField(value, "customRoleId", nullable: true);
        IsTemporary = value.TryGetProperty("isTemporary", out _) ? ManagementJson.Boolean(value, "isTemporary") : null;
        StartsAt = ManagementJson.Optional(value, "temporaryAccessStartTime");
        EndsAt = ManagementJson.Optional(value, "temporaryAccessEndTime");
        Mode = ManagementJson.Optional(value, "temporaryMode");
        Range = ManagementJson.Optional(value, "temporaryRange");
        StartsAtField = ProjectWire.StringField(value, "temporaryAccessStartTime", nullable: true);
        EndsAtField = ProjectWire.StringField(value, "temporaryAccessEndTime", nullable: true);
        ModeField = ProjectWire.StringField(value, "temporaryMode", nullable: true);
        RangeField = ProjectWire.StringField(value, "temporaryRange", nullable: true);
        CreatedAt = ProjectWire.StringField(value, "createdAt");
        UpdatedAt = ProjectWire.StringField(value, "updatedAt");
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string MembershipId { get; }
    [JsonIgnore] public string Role { get; }
    [JsonIgnore] public string? CustomRoleId { get; }
    [JsonIgnore] public ProjectField<string> CustomRoleIdField { get; }
    public bool? IsTemporary { get; }
    [JsonIgnore] public string? StartsAt { get; }
    [JsonIgnore] public string? EndsAt { get; }
    [JsonIgnore] public string? Mode { get; }
    [JsonIgnore] public string? Range { get; }
    [JsonIgnore] public ProjectField<string> StartsAtField { get; }
    [JsonIgnore] public ProjectField<string> EndsAtField { get; }
    [JsonIgnore] public ProjectField<string> ModeField { get; }
    [JsonIgnore] public ProjectField<string> RangeField { get; }
    [JsonIgnore] public ProjectField<string> CreatedAt { get; }
    [JsonIgnore] public ProjectField<string> UpdatedAt { get; }
    public override string ToString() => "[MembershipRoleMetadata]";
}
