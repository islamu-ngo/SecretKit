using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Management;

public sealed class GroupMetadata
{
    internal GroupMetadata(JsonElement value, string organizationId, string? id = null)
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
        CreatedAt = ManagementJson.Required(value, "createdAt");
        UpdatedAt = ManagementJson.Required(value, "updatedAt");
    }

    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string OrganizationId { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Slug { get; }
    [JsonIgnore] public string? Role { get; }
    [JsonIgnore] public string? RoleId { get; }
    [JsonIgnore] public string CreatedAt { get; }
    [JsonIgnore] public string UpdatedAt { get; }
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
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string? Slug { get; }
    public override string ToString() => "[AccessCandidate]";
}

public sealed class GroupIdentity
{
    internal GroupIdentity(JsonElement value)
    {
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Required(value, "name");
        IsMember = ManagementJson.Boolean(value, "isPartOfGroup");
        JoinedAt = ManagementJson.Optional(value, "joinedGroupAt");
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string? JoinedAt { get; }
    public bool IsMember { get; }
    public override string ToString() => "[GroupIdentity]";
}

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
        JoinedAt = ManagementJson.Optional(value, "joinedGroupAt");
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Username { get; }
    [JsonIgnore] public string? Email { get; }
    [JsonIgnore] public string? FirstName { get; }
    [JsonIgnore] public string? LastName { get; }
    [JsonIgnore] public string? JoinedAt { get; }
    public bool? IsMember { get; }
    public override string ToString() => "[GroupUser]";
}

public sealed class MembershipIdentifier
{
    internal MembershipIdentifier(string id) => Id = id;
    [JsonIgnore] public string Id { get; }
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
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Slug { get; }
    [JsonIgnore] public string? Description { get; }
    public bool IncludesPermissions => false;
    public override string ToString() => "[RoleSummary]";
}

public static class ScopedAccessOperations
{
    public static ManagementRequest<ManagementPage<GroupMemberMetadata>> ListGroupMembers(
        string organizationId, string groupId, int offset = 0, int limit = 100,
        string? search = null, ManagementListOrder order = ManagementListOrder.Ascending,
        GroupMemberFilter members = GroupMemberFilter.All)
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
        return new("infisical.get.v1.groups.by.id.members", HttpMethod.Get,
            "/api/v1/groups/" + ManagementJson.Escape(groupId) + "/members?" + query,
            new(organizationId, resourceId: groupId), null,
            root => CountedPage(root, "members", value => new GroupMemberMetadata(value), offset, limit), false);
    }

    public static ManagementRequest<ManagementPage<GroupProjectMetadata>> ListGroupProjects(
        string organizationId, string groupId, GroupProjectSelection selection,
        int offset = 0, int limit = 100, string? search = null,
        ManagementListOrder order = ManagementListOrder.Ascending)
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
        return new("infisical.get.v1.groups.by.id.projects", HttpMethod.Get,
            "/api/v1/groups/" + ManagementJson.Escape(groupId) + "/projects?" + query,
            new(organizationId, resourceId: groupId, secondaryId: filter ?? "allProjects"), null,
            root => CountedPage(root, "projects", value => new GroupProjectMetadata(value), offset, limit), false);
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
        if (search is not null) query += "&search=" + ManagementJson.Escape(search);
        return query;
    }

    public static ManagementRequest<ManagementPage<GroupMetadata>> ListGroups(string organizationId) =>
        new("infisical.get.v1.groups", HttpMethod.Get, "/api/v1/groups",
            new(organizationId), null, root => new(ManagementJson.Array(root)
                .Select(value => new GroupMetadata(value, organizationId)), true), false);

    public static ManagementRequest<GroupMetadata> GetGroup(string organizationId, string groupId) =>
        new("infisical.get.v1.groups.by.id", HttpMethod.Get, "/api/v1/groups/" + ManagementJson.Escape(groupId),
            new(organizationId, resourceId: groupId), null,
            root => new(root, organizationId, groupId), false);

    public static ManagementRequest<GroupMetadata> CreateGroup(string organizationId, string name,
        string? slug = null, string? role = null)
    {
        ValidateGroupFields(name, slug, role);
        return new("infisical.post.v1.groups", HttpMethod.Post, "/api/v1/groups",
            new(organizationId, resourceId: slug ?? name), writer => WriteGroup(writer, name, slug, role),
            root => new(root, organizationId));
    }

    public static ManagementRequest<GroupMetadata> UpdateGroup(string organizationId, string groupId,
        string? name = null, string? slug = null, string? role = null)
    {
        if (name is null && slug is null && role is null)
        {
            throw new ArgumentException("A group change is required.");
        }
        ValidateGroupFields(name, slug, role);
        return new("infisical.patch.v1.groups.by.id", HttpMethod.Patch,
            "/api/v1/groups/" + ManagementJson.Escape(groupId), new(organizationId, resourceId: groupId),
            writer => WriteGroup(writer, name, slug, role), root => new(root, organizationId, groupId));
    }

    public static ManagementRequest<GroupMetadata> DeleteGroup(string organizationId, string groupId) =>
        new("infisical.delete.v1.groups.by.id", HttpMethod.Delete,
            "/api/v1/groups/" + ManagementJson.Escape(groupId), new(organizationId, resourceId: groupId),
            null, root => new(root, organizationId, groupId));

    public static ManagementRequest<ManagementPage<GroupIdentity>> ListGroupIdentities(
        string organizationId, string groupId, int offset = 0, int limit = 100) =>
        new("infisical.get.v1.groups.by.id.machine.identities", HttpMethod.Get,
            "/api/v1/groups/" + ManagementJson.Escape(groupId) + "/machine-identities?" +
            ManagementJson.Paging(offset, limit), new(organizationId, resourceId: groupId), null,
            root => CountedPage(root, "machineIdentities", value => new GroupIdentity(value), offset, limit), false);

    public static ManagementRequest<MembershipIdentifier> AddGroupIdentity(
        string organizationId, string groupId, string identityId) =>
        GroupIdentityChange(organizationId, groupId, identityId, true);

    public static ManagementRequest<MembershipIdentifier> RemoveGroupIdentity(
        string organizationId, string groupId, string identityId) =>
        GroupIdentityChange(organizationId, groupId, identityId, false);

    public static ManagementRequest<ManagementPage<GroupUser>> ListGroupUsers(
        string organizationId, string groupId, int offset = 0, int limit = 100) =>
        new("infisical.get.v1.groups.by.id.users", HttpMethod.Get,
            "/api/v1/groups/" + ManagementJson.Escape(groupId) + "/users?" + ManagementJson.Paging(offset, limit),
            new(organizationId, resourceId: groupId), null,
            root => CountedPage(root, "users", value => new GroupUser(value, true), offset, limit), false);

    public static ManagementRequest<GroupUser> AddGroupUser(string organizationId, string groupId, string username) =>
        GroupUserChange(organizationId, groupId, username, true);

    public static ManagementRequest<GroupUser> RemoveGroupUser(string organizationId, string groupId, string username) =>
        GroupUserChange(organizationId, groupId, username, false);

    public static ManagementRequest<ManagementPage<AccessCandidate>> AvailableGroups(string organizationId) =>
        new("infisical.get.v1.organization.available.groups", HttpMethod.Get, "/api/v1/organization/available-groups",
            new(organizationId), null, root => new(ManagementJson.Array(root, "groups")
                .Select(value => new AccessCandidate(value)), true), false);

    public static ManagementRequest<ManagementPage<AccessCandidate>> AvailableIdentities(string organizationId,
        int offset = 0, int limit = 100) =>
        new("infisical.get.v1.organization.available.identities", HttpMethod.Get,
            "/api/v1/organization/available-identities?" + ManagementJson.Paging(offset, limit),
            new(organizationId), null, root =>
            {
                AccessCandidate[] items = ManagementJson.Array(root, "identities")
                    .Select(value => new AccessCandidate(value)).ToArray();
                return BoundedPage(items, offset, limit);
            }, false);

    public static ManagementRequest<ManagementPage<RoleSummary>> ListOrganizationRoles(string organizationId) =>
        new("infisical.get.v1.organization.roles", HttpMethod.Get, "/api/v1/organization/roles",
            new(organizationId), null, root => new(ManagementJson.Array(root, "roles")
                .Select(value => new RoleSummary(value, "orgId", organizationId)), true), false);

    public static ManagementRequest<RoleSummary> GetOrganizationRole(string organizationId, string roleId) =>
        OrganizationRole(organizationId, roleId, false, false);

    public static ManagementRequest<RoleSummary> GetOrganizationRoleBySlug(string organizationId, string roleSlug) =>
        OrganizationRole(organizationId, roleSlug, true, false);

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
        if (count < 0 || items.Length > limit || (items.Length == 0 && count > offset))
        {
            throw new ManagementContractException(Core.SecretStatus.Unknown);
        }
        bool complete = offset + items.Length >= count;
        return new(items, complete, complete ? null : offset + items.Length);
    }
}

public enum ManagementListOrder { Ascending, Descending }
public enum GroupMemberFilter { All, Users, MachineIdentities }
public enum GroupProjectSelection { Assigned, Unassigned, OrganizationAll }
public enum GroupMemberKind { User, MachineIdentity }

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
        JoinedAt = ManagementJson.Optional(value, "joinedGroupAt");
    }

    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Slug { get; }
    [JsonIgnore] public string Type { get; }
    [JsonIgnore] public string? Description { get; }
    [JsonIgnore] public string? JoinedAt { get; }
    public override string ToString() => "[GroupProjectMetadata]";
}

/// <summary>Native mixed membership metadata; the principal and membership IDs are distinct.</summary>
public sealed class GroupMemberMetadata
{
    internal GroupMemberMetadata(JsonElement value)
    {
        Id = ManagementJson.Required(value, "id");
        JoinedAt = ManagementJson.Optional(value, "joinedGroupAt");
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

    public GroupMemberKind Kind { get; }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string PrincipalId { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string? JoinedAt { get; }
    [JsonIgnore] public string? Email { get; }
    [JsonIgnore] public string? FirstName { get; }
    [JsonIgnore] public string? LastName { get; }
    public override string ToString() => "[GroupMemberMetadata]";
}
