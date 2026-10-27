using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Management;

/// <summary>Native group identity assignment filter; omission remains a separate selection.</summary>
public enum GroupIdentityFilter { /** <summary>Selects assigned machine identities.</summary> */ Assigned, /** <summary>Selects unassigned machine identities.</summary> */ Unassigned }
/// <summary>Native group user-membership filter; omission remains a separate selection.</summary>
public enum GroupUserFilter { /** <summary>Selects existing user members.</summary> */ Members, /** <summary>Selects users not in the group.</summary> */ NonMembers }

/// <summary>Returned organization-group metadata without effective-permission evaluation.</summary>
public sealed class GroupMetadata
{
    internal GroupMetadata(JsonElement value, string organizationId, string? id = null, bool requireCustomRoleSlug = false)
    {
        ManagementJson.RequireEqual(value, "orgId", organizationId);
        if (id is not null)
        {
            ManagementJson.RequireEqual(value, "id", id);
        }
        Id = ManagementJson.Required(value, "id");
        OrganizationId = organizationId;
        Name = ManagementJson.Required(value, "name");
        Slug = ManagementJson.Required(value, "slug");
        Role = ManagementJson.Optional(value, "role");
        RoleId = ManagementJson.Optional(value, "roleId");
        if (value.TryGetProperty("customRoleSlug", out JsonElement customRole))
        {
            CustomRoleSlug = customRole.ValueKind == JsonValueKind.Null
                ? ProjectField<string>.Null()
                : ProjectField<string>.Present(ManagementJson.Required(value, "customRoleSlug"));
        }
        else if (requireCustomRoleSlug)
            throw new ManagementContractException(Core.SecretStatus.Unknown);
        CreatedAt = ManagementJson.Required(value, "createdAt");
        UpdatedAt = ManagementJson.Required(value, "updatedAt");
    }

    /// <summary>Gets the returned group identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned organization coordinate matched to selection.</summary>
    [JsonIgnore] public string OrganizationId { get; }
    /// <summary>Gets the returned group name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the native group slug.</summary>
    [JsonIgnore] public string Slug { get; }
    /// <summary>Gets returned role label, or null when absent or explicitly null.</summary>
    [JsonIgnore] public string? Role { get; }
    /// <summary>Gets returned role identifier, or null when absent or explicitly null.</summary>
    [JsonIgnore] public string? RoleId { get; }
    /// <summary>Gets custom-role slug presence, preserving explicit null.</summary>
    [JsonIgnore] public ProjectField<string> CustomRoleSlug { get; }
    /// <summary>Gets the returned creation timestamp.</summary>
    [JsonIgnore] public string CreatedAt { get; }
    /// <summary>Gets the returned update timestamp.</summary>
    [JsonIgnore] public string UpdatedAt { get; }
    /// <summary>Returns a marker without group metadata.</summary>
    public override string ToString() => "[GroupMetadata]";
}

/// <summary>Named access candidate; availability is not permission or membership evidence.</summary>
public sealed class AccessCandidate
{
    internal AccessCandidate(JsonElement value)
    {
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Required(value, "name");
        Slug = ManagementJson.Optional(value, "slug");
    }
    /// <summary>Gets the returned candidate identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned candidate name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the returned candidate slug, or null when not supplied.</summary>
    [JsonIgnore] public string? Slug { get; }
    /// <summary>Returns a marker without candidate coordinates.</summary>
    public override string ToString() => "[AccessCandidate]";
}

/// <summary>Returned machine-identity membership metadata, not a credential or access decision.</summary>
public sealed class GroupIdentity
{
    internal GroupIdentity(JsonElement value)
    {
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Required(value, "name");
        IsMember = ManagementJson.Boolean(value, "isPartOfGroup");
        JoinedAt = ManagementJson.RequiredNullableString(value, "joinedGroupAt");
    }
    /// <summary>Gets the returned machine-identity identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned identity name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets reported join time, or null when the provider explicitly reports no time.</summary>
    [JsonIgnore] public string? JoinedAt { get; }
    /// <summary>Gets the provider-reported group membership flag.</summary>
    public bool IsMember { get; }
    /// <summary>Returns a marker without identity metadata.</summary>
    public override string ToString() => "[GroupIdentity]";
}

/// <summary>Returned user metadata; mutation responses may omit membership attestation.</summary>
public sealed class GroupUser
{
    internal GroupUser(JsonElement value, bool membership)
    {
        Id = ManagementJson.Required(value, "id");
        Username = ManagementJson.Required(value, "username");
        Email = ManagementJson.Optional(value, "email");
        FirstName = ManagementJson.Optional(value, "firstName");
        LastName = ManagementJson.Optional(value, "lastName");
        IsMember = membership ? ManagementJson.Boolean(value, "isPartOfGroup") : null;
        JoinedAt = membership ? ManagementJson.RequiredNullableString(value, "joinedGroupAt") :
            ManagementJson.Optional(value, "joinedGroupAt");
    }
    /// <summary>Gets the returned user identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned native username.</summary>
    [JsonIgnore] public string Username { get; }
    /// <summary>Gets returned email, or null when absent or explicitly null.</summary>
    [JsonIgnore] public string? Email { get; }
    /// <summary>Gets returned given name, or null when absent or explicitly null.</summary>
    [JsonIgnore] public string? FirstName { get; }
    /// <summary>Gets returned family name, or null when absent or explicitly null.</summary>
    [JsonIgnore] public string? LastName { get; }
    /// <summary>Gets reported join time, or null when not supplied.</summary>
    [JsonIgnore] public string? JoinedAt { get; }
    /// <summary>Gets reported membership flag for inventory; mutations leave it null rather than inferring it.</summary>
    public bool? IsMember { get; }
    /// <summary>Returns a marker without user metadata.</summary>
    public override string ToString() => "[GroupUser]";
}

/// <summary>Native membership-identifier acknowledgement without inferred role or permission evidence.</summary>
public sealed class MembershipIdentifier
{
    internal MembershipIdentifier(string id) => Id = id;
    /// <summary>Gets the returned membership identifier, not the principal identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Returns a marker without membership coordinates.</summary>
    public override string ToString() => "[MembershipIdentifier]";
}

/// <summary>Role metadata projection, deliberately not an effective-permissions result.</summary>
public sealed class RoleSummary
{
    internal RoleSummary(JsonElement value, string scopeField, string scope, string? id = null, string? slug = null)
    {
        ManagementJson.RequireEqual(value, scopeField, scope);
        if (id is not null)
        {
            ManagementJson.RequireEqual(value, "id", id);
        }
        if (slug is not null)
        {
            ManagementJson.RequireEqual(value, "slug", slug);
        }
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Required(value, "name");
        Slug = ManagementJson.Required(value, "slug");
        Description = ManagementJson.Optional(value, "description");
        CreatedAt = NativeDate(value, "createdAt");
        UpdatedAt = NativeDate(value, "updatedAt");
        Permissions = RolePermissionSummary.Read(value);
    }
    /// <summary>Gets the returned role identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned role name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the native role slug.</summary>
    [JsonIgnore] public string Slug { get; }
    /// <summary>Gets returned description, or null when absent or explicitly null.</summary>
    [JsonIgnore] public string? Description { get; }
    /// <summary>Gets the validated returned creation timestamp.</summary>
    [JsonIgnore] public string CreatedAt { get; }
    /// <summary>Gets the validated returned update timestamp.</summary>
    [JsonIgnore] public string UpdatedAt { get; }
    /// <summary>Gets permission metadata, or null when the response omits the permissions field.</summary>
    [JsonIgnore] public IReadOnlyList<RolePermissionSummary>? Permissions { get; }
    /// <summary>Gets whether permission metadata was returned, not whether the role grants effective access.</summary>
    public bool IncludesPermissions => Permissions is not null;
    /// <summary>Returns a marker without role or permission details.</summary>
    public override string ToString() => "[RoleSummary]";

    private static string NativeDate(JsonElement value, string field)
    {
        string text = ManagementJson.Required(value, field);
        ManagementResponseDates.ValidateDateValue(value.GetProperty(field));
        return text;
    }
}

/// <summary>Constructs disposable native access-administration requests and independent approval targets.</summary>
public static class ScopedAccessOperations
{
    /// <summary>Builds count-validated mixed-member inventory; scalar and array member filters remain distinct.</summary>
    public static ManagementRequest<ManagementPage<GroupMemberMetadata>> ListGroupMembers(
        string organizationId, string groupId, int offset = 0, int limit = 100,
        string? search = null, ManagementListOrder order = ManagementListOrder.Ascending,
        GroupMemberFilter members = GroupMemberFilter.All, IReadOnlyList<GroupMemberFilter>? memberTypes = null)
    {
        string query = GroupMemberQuery(offset, limit, search, order, members, memberTypes);
        return new("infisical.get.v1.groups.by.id.members", HttpMethod.Get,
            "/api/v1/groups/" + ManagementJson.Escape(groupId) + "/members?" + query,
            InventorySelectorWire.Intent(organizationId, null, query, memberTypes is null ? null : true, groupId), null,
            root => CountedPage(root, "members", value => new GroupMemberMetadata(value), offset, limit), false);
    }

    /// <summary>Builds independent approval for exact group, paging, search, order and member-filter shape.</summary>
    public static ManagementTarget GroupMemberListTarget(string organizationId, string groupId,
        int offset = 0, int limit = 100, string? search = null,
        ManagementListOrder order = ManagementListOrder.Ascending,
        GroupMemberFilter members = GroupMemberFilter.All, IReadOnlyList<GroupMemberFilter>? memberTypes = null) =>
        InventorySelectorWire.Intent(organizationId, null,
            GroupMemberQuery(offset, limit, search, order, members, memberTypes), memberTypes is null ? null : true, groupId);

    private static string GroupMemberQuery(int offset, int limit, string? search, ManagementListOrder order,
        GroupMemberFilter members, IReadOnlyList<GroupMemberFilter>? memberTypes)
    {
        string? filter = members switch
        {
            GroupMemberFilter.All => null,
            GroupMemberFilter.Users => "users",
            GroupMemberFilter.MachineIdentities => "machineIdentities",
            _ => throw new ArgumentOutOfRangeException(nameof(members))
        };
        string query = GroupInventoryQuery(offset, limit, search, order);
        if (filter is not null) query += "&memberTypeFilter=" + filter;
        if (memberTypes is not null)
        {
            GroupMemberFilter[] copy = memberTypes.Take(101).ToArray();
            if (members != GroupMemberFilter.All || copy.Length > 100)
                throw new ArgumentException("Invalid mixed-member filter selection.");
            foreach (GroupMemberFilter item in copy)
                query += "&memberTypeFilter=" + (item switch
                {
                    GroupMemberFilter.Users => "users",
                    GroupMemberFilter.MachineIdentities => "machineIdentities",
                    _ => throw new ArgumentException("An array item must select a native member type.")
                });
        }
        return query;
    }

    /// <summary>Builds count-validated group-project inventory with an explicit assignment selection.</summary>
    public static ManagementRequest<ManagementPage<GroupProjectMetadata>> ListGroupProjects(
        string organizationId, string groupId, GroupProjectSelection selection,
        int offset = 0, int limit = 100, string? search = null,
        ManagementListOrder order = ManagementListOrder.Ascending)
    {
        string query = GroupProjectQuery(selection, offset, limit, search, order);
        return new("infisical.get.v1.groups.by.id.projects", HttpMethod.Get,
            "/api/v1/groups/" + ManagementJson.Escape(groupId) + "/projects?" + query,
            InventorySelectorWire.Intent(organizationId, null, query, resourceId: groupId), null,
            root => CountedPage(root, "projects", value => new GroupProjectMetadata(value), offset, limit), false);
    }

    /// <summary>Builds independent approval for exact project-assignment filter and all inventory selectors.</summary>
    public static ManagementTarget GroupProjectListTarget(string organizationId, string groupId,
        GroupProjectSelection selection, int offset = 0, int limit = 100, string? search = null,
        ManagementListOrder order = ManagementListOrder.Ascending) =>
        InventorySelectorWire.Intent(organizationId, null,
            GroupProjectQuery(selection, offset, limit, search, order), resourceId: groupId);

    private static string GroupProjectQuery(GroupProjectSelection selection, int offset, int limit,
        string? search, ManagementListOrder order)
    {
        string? filter = selection switch
        {
            GroupProjectSelection.Assigned => "assignedProjects",
            GroupProjectSelection.Unassigned => "unassignedProjects",
            GroupProjectSelection.OrganizationAll => null,
            _ => throw new ArgumentOutOfRangeException(nameof(selection))
        };
        string query = GroupInventoryQuery(offset, limit, search, order);
        if (filter is not null) query += "&filter=" + filter;
        return query;
    }

    private static string GroupInventoryQuery(int offset, int limit, string? search, ManagementListOrder order)
    {
        string direction = order switch
        {
            ManagementListOrder.Ascending => "asc",
            ManagementListOrder.Descending => "desc",
            _ => throw new ArgumentOutOfRangeException(nameof(order))
        };
        string query = ManagementJson.Paging(offset, limit) + "&orderBy=name&orderDirection=" + direction;
        if (search is not null) query += "&search=" + InventorySelectorWire.Escape(search);
        return query;
    }

    /// <summary>Builds bounded unpaged organization-group inventory.</summary>
    public static ManagementRequest<ManagementPage<GroupMetadata>> ListGroups(string organizationId) =>
        new("infisical.get.v1.groups", HttpMethod.Get, "/api/v1/groups",
            new(organizationId), null, root => new(ManagementJson.Array(root)
                .Select(value => new GroupMetadata(value, organizationId)), true), false);

    /// <summary>Builds exact group inspection requiring returned custom-role slug presence.</summary>
    public static ManagementRequest<GroupMetadata> GetGroup(string organizationId, string groupId) =>
        new("infisical.get.v1.groups.by.id", HttpMethod.Get, "/api/v1/groups/" + ManagementJson.Escape(groupId),
            new(organizationId, resourceId: groupId), null,
            root => new(root, organizationId, groupId, requireCustomRoleSlug: true), false);

    /// <summary>Builds group creation; null optional slug and role remain omitted.</summary>
    public static ManagementRequest<GroupMetadata> CreateGroup(string organizationId, string name,
        string? slug = null, string? role = null)
    {
        ValidateGroupFields(name, slug, role);
        return new("infisical.post.v1.groups", HttpMethod.Post, "/api/v1/groups",
            GroupCreationTarget(organizationId, name, slug, role), writer => WriteGroup(writer, name, slug, role),
            root => new(root, organizationId));
    }

    /// <summary>Builds group update; null fields omit changes and an entirely empty change is invalid.</summary>
    public static ManagementRequest<GroupMetadata> UpdateGroup(string organizationId, string groupId,
        string? name = null, string? slug = null, string? role = null)
    {
        if (name is null && slug is null && role is null)
        {
            throw new ArgumentException("A group change is required.");
        }
        ValidateGroupFields(name, slug, role);
        return new("infisical.patch.v1.groups.by.id", HttpMethod.Patch,
            "/api/v1/groups/" + ManagementJson.Escape(groupId), GroupUpdateTarget(organizationId, groupId, name, slug, role),
            writer => WriteGroup(writer, name, slug, role), root => new(root, organizationId, groupId));
    }

    /// <summary>Builds independent group-creation approval from trusted name, optional slug and role.</summary>
    public static ManagementTarget GroupCreationTarget(string organizationId, string name,
        string? slug = null, string? role = null)
    {
        ArgumentNullException.ThrowIfNull(name);
        ValidateGroupFields(name, slug, role);
        return GroupIntent(organizationId, slug ?? name, name, slug, role);
    }

    /// <summary>Builds independent group-update approval binding the exact group and complete changes.</summary>
    public static ManagementTarget GroupUpdateTarget(string organizationId, string groupId,
        string? name = null, string? slug = null, string? role = null)
    {
        if (name is null && slug is null && role is null)
            throw new ArgumentException("A group change is required.");
        ValidateGroupFields(name, slug, role);
        return GroupIntent(organizationId, groupId, name, slug, role);
    }

    private static ManagementTarget GroupIntent(string organizationId, string groupId,
        string? name, string? slug, string? role)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new { name, slug, role });
        try
        {
            return new(organizationId, resourceId: groupId,
                secondaryId: Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)));
        }
        finally { Array.Clear(bytes); }
    }

    /// <summary>Builds exact group deletion; retain the mutation receipt across uncertain execution.</summary>
    public static ManagementRequest<GroupMetadata> DeleteGroup(string organizationId, string groupId) =>
        new("infisical.delete.v1.groups.by.id", HttpMethod.Delete,
            "/api/v1/groups/" + ManagementJson.Escape(groupId), new(organizationId, resourceId: groupId),
            null, root => new(root, organizationId, groupId));

    /// <summary>Builds count-validated machine-identity inventory with optional assignment and search selectors.</summary>
    public static ManagementRequest<ManagementPage<GroupIdentity>> ListGroupIdentities(
        string organizationId, string groupId, int offset = 0, int limit = 100,
        GroupIdentityFilter? filter = null, string? search = null)
    {
        string query = GroupIdentityQuery(offset, limit, filter, search);
        return new("infisical.get.v1.groups.by.id.machine.identities", HttpMethod.Get,
            "/api/v1/groups/" + ManagementJson.Escape(groupId) + "/machine-identities?" +
            query, InventorySelectorWire.Intent(organizationId, null, query, resourceId: groupId), null,
            root => CountedPage(root, "machineIdentities", value => new GroupIdentity(value), offset, limit), false);
    }

    /// <summary>Builds independent machine-identity inventory approval preserving filter and search omission.</summary>
    public static ManagementTarget GroupIdentityListTarget(string organizationId, string groupId,
        int offset = 0, int limit = 100, GroupIdentityFilter? filter = null, string? search = null) =>
        InventorySelectorWire.Intent(organizationId, null, GroupIdentityQuery(offset, limit, filter, search), resourceId: groupId);

    private static string GroupIdentityQuery(int offset, int limit, GroupIdentityFilter? filter, string? search)
    {
        string query = ManagementJson.Paging(offset, limit);
        if (filter is { } selected)
            query += "&filter=" + (selected switch
            {
                GroupIdentityFilter.Assigned => "assignedMachineIdentities",
                GroupIdentityFilter.Unassigned => "nonAssignedMachineIdentities",
                _ => throw new ArgumentOutOfRangeException(nameof(filter))
            });
        if (search is not null) query += "&search=" + InventorySelectorWire.Escape(search);
        return query;
    }

    /// <summary>Builds explicit addition of one machine identity to the selected group.</summary>
    public static ManagementRequest<MembershipIdentifier> AddGroupIdentity(
        string organizationId, string groupId, string identityId) =>
        GroupIdentityChange(organizationId, groupId, identityId, true);

    /// <summary>Builds explicit removal of one machine identity from the selected group.</summary>
    public static ManagementRequest<MembershipIdentifier> RemoveGroupIdentity(
        string organizationId, string groupId, string identityId) =>
        GroupIdentityChange(organizationId, groupId, identityId, false);

    /// <summary>Builds count-validated user inventory with exact optional membership, search and username selectors.</summary>
    public static ManagementRequest<ManagementPage<GroupUser>> ListGroupUsers(
        string organizationId, string groupId, int offset = 0, int limit = 100,
        GroupUserFilter? filter = null, string? search = null, string? username = null)
    {
        string query = GroupUserQuery(offset, limit, filter, search, username);
        return new("infisical.get.v1.groups.by.id.users", HttpMethod.Get,
            "/api/v1/groups/" + ManagementJson.Escape(groupId) + "/users?" + query,
            InventorySelectorWire.Intent(organizationId, null, query, resourceId: groupId), null,
            root => CountedPage(root, "users", value => new GroupUser(value, true), offset, limit), false);
    }

    /// <summary>Builds independent user inventory approval including every selector and paging field.</summary>
    public static ManagementTarget GroupUserListTarget(string organizationId, string groupId,
        int offset = 0, int limit = 100, GroupUserFilter? filter = null, string? search = null, string? username = null) =>
        InventorySelectorWire.Intent(organizationId, null, GroupUserQuery(offset, limit, filter, search, username), resourceId: groupId);

    private static string GroupUserQuery(int offset, int limit, GroupUserFilter? filter, string? search, string? username)
    {
        string query = ManagementJson.Paging(offset, limit);
        if (filter is { } selected)
            query += "&filter=" + (selected switch
            {
                GroupUserFilter.Members => "existingMembers",
                GroupUserFilter.NonMembers => "nonMembers",
                _ => throw new ArgumentOutOfRangeException(nameof(filter))
            });
        if (search is not null) query += "&search=" + InventorySelectorWire.Escape(search);
        if (username is not null) query += "&username=" + InventorySelectorWire.Escape(username);
        return query;
    }

    /// <summary>Builds user membership addition by exact username; returned metadata need not attest membership.</summary>
    public static ManagementRequest<GroupUser> AddGroupUser(string organizationId, string groupId, string username) =>
        GroupUserChange(organizationId, groupId, username, true);

    /// <summary>Builds user membership removal by exact username; retain mutation evidence during execution.</summary>
    public static ManagementRequest<GroupUser> RemoveGroupUser(string organizationId, string groupId, string username) =>
        GroupUserChange(organizationId, groupId, username, false);

    /// <summary>Builds bounded available-group inventory; availability is not authorization or membership proof.</summary>
    public static ManagementRequest<ManagementPage<AccessCandidate>> AvailableGroups(string organizationId) =>
        new("infisical.get.v1.organization.available.groups", HttpMethod.Get, "/api/v1/organization/available-groups",
            new(organizationId), null, root => new(ManagementJson.Array(root, "groups")
                .Select(value => new AccessCandidate(value)), true), false);

    /// <summary>Builds bounded available-identity inventory; a full page requires another explicit read.</summary>
    public static ManagementRequest<ManagementPage<AccessCandidate>> AvailableIdentities(string organizationId,
        int offset = 0, int limit = 100, string? identityName = null)
    {
        string query = AvailableIdentityQuery(offset, limit, identityName);
        return new("infisical.get.v1.organization.available.identities", HttpMethod.Get,
            "/api/v1/organization/available-identities?" + query,
            InventorySelectorWire.Intent(organizationId, null, query), null, root =>
            {
                AccessCandidate[] items = ManagementJson.Array(root, "identities")
                    .Select(value => new AccessCandidate(value)).ToArray();
                return BoundedPage(items, offset, limit);
            }, false);
    }

    /// <summary>Builds independent available-identity inventory approval with exact paging and optional name.</summary>
    public static ManagementTarget AvailableIdentityListTarget(string organizationId,
        int offset = 0, int limit = 100, string? identityName = null) =>
        InventorySelectorWire.Intent(organizationId, null, AvailableIdentityQuery(offset, limit, identityName));

    private static string AvailableIdentityQuery(int offset, int limit, string? identityName) =>
        ManagementJson.Paging(offset, limit) + (identityName is null ? "" : "&identityName=" + InventorySelectorWire.Escape(identityName));

    /// <summary>Builds bounded organization-role inventory with native metadata projections.</summary>
    public static ManagementRequest<ManagementPage<RoleSummary>> ListOrganizationRoles(string organizationId) =>
        new("infisical.get.v1.organization.roles", HttpMethod.Get, "/api/v1/organization/roles",
            new(organizationId), null, root => new(ManagementJson.Array(root, "roles")
                .Select(value => new RoleSummary(value, "orgId", organizationId)), true), false);

    /// <summary>Builds exact organization-role lookup by identifier.</summary>
    public static ManagementRequest<RoleSummary> GetOrganizationRole(string organizationId, string roleId) =>
        OrganizationRole(organizationId, roleId, false, false);

    /// <summary>Builds exact organization-role lookup by native slug.</summary>
    public static ManagementRequest<RoleSummary> GetOrganizationRoleBySlug(string organizationId, string roleSlug) =>
        OrganizationRole(organizationId, roleSlug, true, false);

    /// <summary>Builds exact organization-role deletion; construction performs no provider mutation.</summary>
    public static ManagementRequest<RoleSummary> DeleteOrganizationRole(string organizationId, string roleId) =>
        OrganizationRole(organizationId, roleId, false, true);

    private static ManagementRequest<RoleSummary> OrganizationRole(string org, string key, bool slug, bool delete) =>
        new(delete ? "infisical.delete.v1.organization.roles.by.roleId" :
            slug ? "infisical.get.v1.organization.roles.slug.by.roleSlug" : "infisical.get.v1.organization.roles.by.roleId",
            delete ? HttpMethod.Delete : HttpMethod.Get,
            "/api/v1/organization/roles/" + (slug ? "slug/" : "") + ManagementJson.Escape(key),
            new(org, resourceId: key), null,
            root => new(ManagementJson.Object(root, "role"), "orgId", org, slug ? null : key, slug ? key : null), delete);

    private static ManagementRequest<MembershipIdentifier> GroupIdentityChange(string org, string group, string identity, bool add) =>
        new(add ? "infisical.post.v1.groups.by.id.machine.identities.by.machineIdentityId" :
            "infisical.delete.v1.groups.by.id.machine.identities.by.machineIdentityId",
            add ? HttpMethod.Post : HttpMethod.Delete,
            "/api/v1/groups/" + ManagementJson.Escape(group) + "/machine-identities/" + ManagementJson.Escape(identity),
            new(org, resourceId: group, secondaryId: identity), null,
            root => new(ManagementJson.Required(root, "id")));

    private static ManagementRequest<GroupUser> GroupUserChange(string org, string group, string username, bool add) =>
        new(add ? "infisical.post.v1.groups.by.id.users.by.username" : "infisical.delete.v1.groups.by.id.users.by.username",
            add ? HttpMethod.Post : HttpMethod.Delete,
            "/api/v1/groups/" + ManagementJson.Escape(group) + "/users/" + ManagementJson.Escape(username),
            new(org, resourceId: group, secondaryId: username), null, root =>
            {
                ManagementJson.RequireEqual(root, "username", username);
                return new(root, false);
            });

    private static void ValidateGroupFields(string? name, string? slug, string? role)
    {
        if (name is not null) ManagementJson.Text(name, 255);
        if (role is not null) ManagementJson.Text(role, 255);
        if (slug is not null)
        {
            ManagementJson.Text(slug, 255);
            if (slug.Length < 5) throw new ArgumentException("Invalid group slug length.");
        }
    }

    private static void WriteGroup(Utf8JsonWriter writer, string? name, string? slug, string? role)
    {
        writer.WriteStartObject();
        if (name is not null) writer.WriteString("name", name);
        if (slug is not null) writer.WriteString("slug", slug);
        if (role is not null) writer.WriteString("role", role);
        writer.WriteEndObject();
    }

    internal static ManagementPage<T> BoundedPage<T>(T[] items, int offset, int limit) where T : notnull
    {
        if (items.Length > limit) throw new ManagementContractException(Core.SecretStatus.Unknown);
        return new(items, items.Length < limit, items.Length == limit ? offset + items.Length : null);
    }

    internal static ManagementPage<T> CountedPage<T>(JsonElement root, string field, Func<JsonElement, T> parse,
        int offset, int limit) where T : notnull
    {
        T[] items = ManagementJson.Array(root, field).Select(parse).ToArray();
        int count = ManagementJson.Integer(root, "totalCount");
        if (count < 0 || items.Length != Math.Min(limit, Math.Max(0, count - offset)))
        {
            throw new ManagementContractException(Core.SecretStatus.Unknown);
        }
        bool complete = offset + items.Length >= count;
        return new(items, complete, complete ? null : offset + items.Length);
    }
}

/// <summary>Native list ordering direction used in exact inventory intent.</summary>
public enum ManagementListOrder { /** <summary>Orders from lowest to highest native sort value.</summary> */ Ascending, /** <summary>Orders from highest to lowest native sort value.</summary> */ Descending }
/// <summary>Native mixed group-member kind selector.</summary>
public enum GroupMemberFilter { /** <summary>Omits the scalar member-kind filter.</summary> */ All, /** <summary>Selects user members.</summary> */ Users, /** <summary>Selects machine-identity members.</summary> */ MachineIdentities }
/// <summary>Explicit native group-project assignment selection.</summary>
public enum GroupProjectSelection { /** <summary>Selects projects assigned to the group.</summary> */ Assigned, /** <summary>Selects projects not assigned to the group.</summary> */ Unassigned, /** <summary>Omits assignment filtering and selects the organization-wide inventory view.</summary> */ OrganizationAll }
/// <summary>Known principal kinds in mixed group inventory.</summary>
public enum GroupMemberKind { /** <summary>A user principal.</summary> */ User, /** <summary>A machine-identity principal.</summary> */ MachineIdentity }

/// <summary>Project inventory returned for a group; not effective permission or delivery evidence.</summary>
public sealed class GroupProjectMetadata
{
    internal GroupProjectMetadata(JsonElement value)
    {
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Required(value, "name");
        Slug = ManagementJson.Required(value, "slug");
        Type = ManagementJson.Required(value, "type");
        Description = ManagementJson.Optional(value, "description");
        JoinedAt = ManagementJson.RequiredNullableString(value, "joinedGroupAt");
    }

    /// <summary>Gets the returned project identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned project name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the native project slug.</summary>
    [JsonIgnore] public string Slug { get; }
    /// <summary>Gets the returned native product type.</summary>
    [JsonIgnore] public string Type { get; }
    /// <summary>Gets returned project description, or null when absent or explicitly null.</summary>
    [JsonIgnore] public string? Description { get; }
    /// <summary>Gets reported group join time, or null when explicitly absent.</summary>
    [JsonIgnore] public string? JoinedAt { get; }
    /// <summary>Returns a marker without project inventory details.</summary>
    public override string ToString() => "[GroupProjectMetadata]";
}

/// <summary>Native mixed membership metadata; the principal and membership IDs are distinct.</summary>
public sealed class GroupMemberMetadata
{
    internal GroupMemberMetadata(JsonElement value)
    {
        Id = ManagementJson.Required(value, "id");
        JoinedAt = ManagementJson.RequiredNullableString(value, "joinedGroupAt");
        Kind = ManagementJson.Required(value, "type") switch
        {
            "user" => GroupMemberKind.User,
            "machineIdentity" => GroupMemberKind.MachineIdentity,
            _ => throw new ManagementContractException(SecretKit.Core.SecretStatus.Unsupported)
        };
        JsonElement principal = ManagementJson.Object(value,
            Kind == GroupMemberKind.User ? "user" : "machineIdentity");
        PrincipalId = ManagementJson.Required(principal, "id");
        Name = ManagementJson.Required(principal, Kind == GroupMemberKind.User ? "username" : "name");
        if (Kind == GroupMemberKind.User)
        {
            Email = ManagementJson.Optional(principal, "email");
            FirstName = ManagementJson.Optional(principal, "firstName");
            LastName = ManagementJson.Optional(principal, "lastName");
        }
    }

    /// <summary>Gets the returned principal kind.</summary>
    public GroupMemberKind Kind { get; }
    /// <summary>Gets the returned membership identifier, distinct from the principal identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the nested principal identifier.</summary>
    [JsonIgnore] public string PrincipalId { get; }
    /// <summary>Gets the returned username or machine-identity name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets reported group join time, or null when explicitly absent.</summary>
    [JsonIgnore] public string? JoinedAt { get; }
    /// <summary>Gets user email, or null for missing user metadata or machine identities.</summary>
    [JsonIgnore] public string? Email { get; }
    /// <summary>Gets user given name, or null for missing user metadata or machine identities.</summary>
    [JsonIgnore] public string? FirstName { get; }
    /// <summary>Gets user family name, or null for missing user metadata or machine identities.</summary>
    [JsonIgnore] public string? LastName { get; }
    /// <summary>Returns a marker without principal or membership details.</summary>
    public override string ToString() => "[GroupMemberMetadata]";
}
