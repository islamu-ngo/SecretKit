using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Native organization group inventory sort columns.</summary>
public enum OrganizationGroupOrder { /** <summary>Sorts by group display name.</summary> */ Name, /** <summary>Sorts by native group slug.</summary> */ Slug, /** <summary>Sorts by assigned role label.</summary> */ Role }

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
    /// <summary>Selects one scalar native role filter.</summary>
    public static OrganizationGroupRoleFilter Scalar(string role) => new([role], false);
    /// <summary>Copies a native role array; empty remains an explicit array selection.</summary>
    public static OrganizationGroupRoleFilter Array(IReadOnlyList<string> roles)
    {
        ArgumentNullException.ThrowIfNull(roles);
        return new(roles.Take(101).ToArray(), true);
    }

    internal string Query => string.Concat(_values.Select(value => "&roles=" + InventorySelectorWire.Escape(value)));
    /// <summary>Returns a marker without role filters.</summary>
    public override string ToString() => "[OrganizationGroupRoleFilter]";
}

/// <summary>A native permanent or relative-time role assignment, not an effective capability.</summary>
public sealed class MembershipRole
{
    /// <summary>Captures a permanent or relative assignment; temporary access requires both start time and native duration.</summary>
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
    /// <summary>Gets the explicit native role label.</summary>
    [JsonIgnore] public string Role { get; }
    /// <summary>Gets the selected start time, or null for a permanent assignment.</summary>
    [JsonIgnore] public DateTimeOffset? StartsAt { get; }
    /// <summary>Gets the native relative duration, or null for a permanent assignment.</summary>
    [JsonIgnore] public string? RelativeDuration { get; }
    /// <summary>Gets true for temporary, false for explicit permanent, or null for an omitted permanent discriminator.</summary>
    [JsonIgnore] public bool? IsTemporary { get; }
    /// <summary>Returns a marker without assigned-role details.</summary>
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
    /// <summary>Gets the returned membership identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned group or identity coordinate.</summary>
    [JsonIgnore] public string PrincipalId { get; }
    /// <summary>Gets required creation-time metadata with presence information.</summary>
    [JsonIgnore] public ProjectField<string> CreatedAt { get; }
    /// <summary>Gets required update-time metadata with presence information.</summary>
    [JsonIgnore] public ProjectField<string> UpdatedAt { get; }
    /// <summary>Gets group details when projected; identity membership responses leave this null.</summary>
    [JsonIgnore] public MembershipGroupDetails? Group { get; }
    /// <summary>Gets returned role metadata when present; omission differs from an empty array.</summary>
    [JsonIgnore] public ProjectField<IReadOnlyList<ProjectMembershipRole>> Roles { get; }
    /// <summary>Gets whether role metadata is included, not whether roles are effective.</summary>
    public bool IncludesRoles => Roles.IsPresent;
    /// <summary>Returns a marker without membership details.</summary>
    public override string ToString() => "[MembershipSummary]";
}

/// <summary>Constructs disposable membership requests; exact host approval does not establish provider permissions.</summary>
public static class MembershipOperations
{
    /// <summary>Builds project group-role replacement bound to both the group and expected membership identifier.</summary>
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

    /// <summary>Builds identity membership creation; null omits the role array and empty explicitly sends it.</summary>
    public static ManagementRequest<MembershipSummary> AddProjectIdentity(string organizationId, string projectId,
        string identityId, IReadOnlyList<MembershipRole>? roles = null) =>
        AddProjectIdentity(organizationId, projectId, identityId, new MembershipRoleSelection(roles: roles));

    /// <summary>Builds identity membership creation preserving independently selected scalar and array role fields.</summary>
    public static ManagementRequest<MembershipSummary> AddProjectIdentity(string organizationId, string projectId,
        string identityId, MembershipRoleSelection roles) =>
        ChangeProjectIdentity(organizationId, projectId, identityId, roles, HttpMethod.Post);

    /// <summary>Builds identity-role replacement with a nonempty explicit role array.</summary>
    public static ManagementRequest<MembershipSummary> UpdateProjectIdentityRoles(string organizationId, string projectId,
        string identityId, IReadOnlyList<MembershipRole> roles) =>
        ChangeProjectIdentity(organizationId, projectId, identityId, new MembershipRoleSelection(roles: roles), HttpMethod.Patch);

    /// <summary>Builds removal of one project identity membership; execution needs a fresh receipt.</summary>
    public static ManagementRequest<MembershipSummary> RemoveProjectIdentity(string organizationId, string projectId,
        string identityId) => ChangeProjectIdentity(organizationId, projectId, identityId, null, HttpMethod.Delete);

    /// <summary>Builds an exact identity-membership detail lookup without inferring lockout metadata.</summary>
    public static ManagementRequest<ProjectIdentityMembershipSummary> GetProjectIdentityMembership(string organizationId, string projectId, string identityId) =>
        new("infisical.get.v1.projects.by.projectId.memberships.identities.by.identityId", HttpMethod.Get,
            ProjectIdentityPath(projectId, identityId), new(organizationId, projectId, identityId), null,
            root =>
            {
                return new(ManagementJson.Object(root, "identityMembership"), organizationId, projectId,
                    identityId);
            }, false);

    /// <summary>Builds removal of the selected project group membership.</summary>
    public static ManagementRequest<MembershipSummary> RemoveProjectGroup(string organizationId, string projectId, string groupId) =>
        new("infisical.delete.v1.projects.by.projectId.memberships.groups.by.groupId", HttpMethod.Delete,
            ProjectGroupPath(projectId, groupId), new(organizationId, projectId, groupId), null,
            root => new(ManagementJson.Object(root, "groupMembership"), "groupId", groupId, "projectId", projectId));

    /// <summary>Builds a project group-membership detail lookup with group correspondence checks.</summary>
    public static ManagementRequest<MembershipSummary> GetProjectGroup(string organizationId, string projectId, string groupId) =>
        new("infisical.get.v1.projects.by.projectId.memberships.groups.by.groupId", HttpMethod.Get,
            ProjectGroupPath(projectId, groupId), new(organizationId, projectId, groupId), null,
            root => ParseGroupMembership(ManagementJson.Object(root, "groupMembership"), organizationId, projectId, groupId), false);

    /// <summary>Builds project group membership creation; null roles omit the array.</summary>
    public static ManagementRequest<MembershipSummary> AddProjectGroup(string organizationId, string projectId,
        string groupId, IReadOnlyList<MembershipRole>? roles = null) =>
        AddProjectGroup(organizationId, projectId, groupId, new MembershipRoleSelection(roles: roles));

    /// <summary>Builds project group creation preserving scalar, array, empty and omitted role intent.</summary>
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

    /// <summary>Builds a bounded unpaged project-group inventory request.</summary>
    public static ManagementRequest<ManagementPage<MembershipSummary>> ListProjectGroups(string organizationId, string projectId) =>
        new("infisical.get.v1.projects.by.projectId.memberships.groups", HttpMethod.Get,
            ProjectOperations.ProjectPath(projectId) + "/memberships/groups", new(organizationId, projectId), null,
            root => new(ManagementJson.Array(root, "groupMemberships")
                .Select(value => ParseGroupMembership(value, organizationId, projectId, null)), true), false);

    /// <summary>Builds removal of an organization group membership, not deletion of the group itself.</summary>
    public static ManagementRequest<MembershipSummary> RemoveOrganizationGroup(string organizationId, string groupId) =>
        new("infisical.delete.v1.organizations.memberships.groups.by.groupId", HttpMethod.Delete,
            OrganizationGroupPath(groupId), new(organizationId, resourceId: groupId), null,
            root => new(ManagementJson.Object(root, "groupMembership"), "groupId", groupId, "orgId", organizationId));

    /// <summary>Builds organization group-membership detail lookup; owner metadata may name a parent organization.</summary>
    public static ManagementRequest<MembershipSummary> GetOrganizationGroup(string organizationId, string groupId) =>
        new("infisical.get.v1.organizations.memberships.groups.by.groupId", HttpMethod.Get,
            OrganizationGroupPath(groupId), new(organizationId, resourceId: groupId), null,
            root => ParseGroupMembership(ManagementJson.Object(root, "groupMembership"), organizationId, null, groupId), false);

    /// <summary>Builds organization group membership creation with explicit nonempty role assignments.</summary>
    public static ManagementRequest<MembershipSummary> AddOrganizationGroup(string organizationId, string groupId,
        IReadOnlyList<MembershipRole> roles) => ChangeOrganizationGroup(organizationId, groupId, roles, false);

    /// <summary>Builds organization group-role replacement with explicit nonempty assignments.</summary>
    public static ManagementRequest<MembershipSummary> UpdateOrganizationGroupRoles(string organizationId, string groupId,
        IReadOnlyList<MembershipRole> roles) => ChangeOrganizationGroup(organizationId, groupId, roles, true);

    /// <summary>Builds count-validated organization group inventory; null sort or search selectors are omitted.</summary>
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

    /// <summary>Builds independent host approval for exact role-field shape and optional expected membership identity.</summary>
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
    /// <summary>Gets the returned assignment identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned project-membership identifier verified against host selection.</summary>
    [JsonIgnore] public string MembershipId { get; }
    /// <summary>Gets the returned role label.</summary>
    [JsonIgnore] public string Role { get; }
    /// <summary>Gets the custom-role identifier, or null when omitted or explicitly null.</summary>
    [JsonIgnore] public string? CustomRoleId { get; }
    /// <summary>Gets custom-role identifier presence, preserving explicit null.</summary>
    [JsonIgnore] public ProjectField<string> CustomRoleIdField { get; }
    /// <summary>Gets the returned temporary flag, or null when absent.</summary>
    public bool? IsTemporary { get; }
    /// <summary>Gets the temporary-access start time, or null when not supplied.</summary>
    [JsonIgnore] public string? StartsAt { get; }
    /// <summary>Gets the temporary-access end time, or null when not supplied.</summary>
    [JsonIgnore] public string? EndsAt { get; }
    /// <summary>Gets the temporary validity mode, or null when not supplied.</summary>
    [JsonIgnore] public string? Mode { get; }
    /// <summary>Gets the native validity duration, or null when not supplied.</summary>
    [JsonIgnore] public string? Range { get; }
    /// <summary>Gets start-time presence, distinguishing omission from explicit null.</summary>
    [JsonIgnore] public ProjectField<string> StartsAtField { get; }
    /// <summary>Gets end-time presence, distinguishing omission from explicit null.</summary>
    [JsonIgnore] public ProjectField<string> EndsAtField { get; }
    /// <summary>Gets validity-mode presence, distinguishing omission from explicit null.</summary>
    [JsonIgnore] public ProjectField<string> ModeField { get; }
    /// <summary>Gets duration presence, distinguishing omission from explicit null.</summary>
    [JsonIgnore] public ProjectField<string> RangeField { get; }
    /// <summary>Gets creation-time presence without manufacturing a timestamp.</summary>
    [JsonIgnore] public ProjectField<string> CreatedAt { get; }
    /// <summary>Gets update-time presence without manufacturing a timestamp.</summary>
    [JsonIgnore] public ProjectField<string> UpdatedAt { get; }
    /// <summary>Returns a marker without assignment details.</summary>
    public override string ToString() => "[MembershipRoleMetadata]";
}
