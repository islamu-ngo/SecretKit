using System.Text.Json;
using System.Text.Json.Serialization;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

[Flags]
public enum IdentitySearchScope { Organization = 1, Projects = 2 }
public enum IdentitySearchOrder { Name, Role, LastLogin }

/// <summary>Native string operators. Inputs are copied and bounded; no arbitrary query JSON.</summary>
public sealed class IdentitySearchText
{
    public IdentitySearchText(string? equal = null, string? contains = null, IReadOnlyList<string>? anyOf = null)
    {
        if (equal is not null) ValidateText(equal);
        if (contains is not null) ValidateText(contains);
        string[]? copy = anyOf?.Take(101).ToArray();
        if (copy is not null)
        {
            if (copy.Length > 100) throw new ArgumentException("Invalid search item budget.");
            foreach (string item in copy) ValidateText(item);
        }
        Equal = equal;
        Contains = contains;
        AnyOf = copy is null ? null : Array.AsReadOnly(copy);
    }
    [JsonIgnore] public string? Equal { get; }
    [JsonIgnore] public string? Contains { get; }
    [JsonIgnore] public IReadOnlyList<string>? AnyOf { get; }
    [JsonIgnore] public string? ShorthandValue { get; private init; }

    public static IdentitySearchText Shorthand(string value)
    {
        ValidateText(value);
        return new() { ShorthandValue = value };
    }

    private static void ValidateText(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length != 0) ManagementJson.Text(value, 255);
    }

    internal void Write(Utf8JsonWriter writer)
    {
        if (ShorthandValue is not null)
        {
            writer.WriteStringValue(ShorthandValue);
            return;
        }
        writer.WriteStartObject();
        if (Equal is not null) writer.WriteString("$eq", Equal);
        if (Contains is not null) writer.WriteString("$contains", Contains);
        if (AnyOf is not null)
        {
            writer.WriteStartArray("$in");
            foreach (string item in AnyOf) writer.WriteStringValue(item);
            writer.WriteEndArray();
        }
        writer.WriteEndObject();
    }
    public override string ToString() => "[IdentitySearchText]";
}

public sealed class IdentitySearchClause
{
    public IdentitySearchClause(IdentitySearchText? name = null, IdentitySearchText? role = null)
    {
        Name = name;
        Role = role;
    }
    [JsonIgnore] public IdentitySearchText? Name { get; }
    [JsonIgnore] public IdentitySearchText? Role { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        if (Name is not null) { writer.WritePropertyName("name"); Name.Write(writer); }
        if (Role is not null) { writer.WritePropertyName("role"); Role.Write(writer); }
    }
    public override string ToString() => "[IdentitySearchClause]";
}

public sealed class IdentitySearchFilter
{
    public IdentitySearchFilter(IdentitySearchClause? all = null, IReadOnlyList<IdentitySearchClause>? anyOf = null)
    {
        IdentitySearchClause[]? copy = anyOf?.Take(6).ToArray();
        if (copy is not null && (copy.Length > 5 || copy.Any(item => item is null)))
            throw new ArgumentException("Invalid search clause budget.");
        All = all;
        AnyOf = copy is null ? null : Array.AsReadOnly(copy);
    }
    [JsonIgnore] public IdentitySearchClause? All { get; }
    [JsonIgnore] public IReadOnlyList<IdentitySearchClause>? AnyOf { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        All?.Write(writer);
        if (AnyOf is not null)
        {
            writer.WriteStartArray("$or");
            foreach (IdentitySearchClause clause in AnyOf)
            {
                writer.WriteStartObject();
                clause.Write(writer);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
        }
        writer.WriteEndObject();
    }
    public override string ToString() => "[IdentitySearchFilter]";
}

/// <summary>Known search project metadata; not project access evidence.</summary>
public sealed class IdentitySearchProject
{
    internal IdentitySearchProject(JsonElement value, string projectId)
    {
        ManagementJson.RequireEqual(value, "id", projectId);
        Id = projectId;
        Name = IdentityMetadataWire.RequiredString(value, "name");
        Slug = IdentityMetadataWire.RequiredString(value, "slug");
        Type = IdentityMetadataWire.RequiredString(value, "type");
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Slug { get; }
    [JsonIgnore] public string Type { get; }
    public override string ToString() => "[IdentitySearchProject]";
}

/// <summary>Search assignment metadata, including nullable custom-role description; not permissions.</summary>
public sealed class IdentitySearchRole
{
    private readonly ProjectMembershipRole _assignment;
    internal IdentitySearchRole(JsonElement value)
    {
        _assignment = new(value);
        CustomRoleDescription = IdentityMetadataWire.StringField(value, "customRoleDescription", nullable: true);
    }
    [JsonIgnore] public string Id => _assignment.Id;
    [JsonIgnore] public string Role => _assignment.Role;
    [JsonIgnore] public string? CustomRoleId => _assignment.CustomRoleId;
    [JsonIgnore] public string? CustomRoleName => _assignment.CustomRoleName;
    [JsonIgnore] public string? CustomRoleSlug => _assignment.CustomRoleSlug;
    [JsonIgnore] public bool? IsTemporary => _assignment.IsTemporary;
    [JsonIgnore] public string? Mode => _assignment.Mode;
    [JsonIgnore] public string? Range => _assignment.Range;
    [JsonIgnore] public string? StartsAt => _assignment.StartsAt;
    [JsonIgnore] public string? EndsAt => _assignment.EndsAt;
    [JsonIgnore] public ProjectField<string> CustomRoleIdField => _assignment.CustomRoleIdField;
    [JsonIgnore] public ProjectField<string> CustomRoleNameField => _assignment.CustomRoleNameField;
    [JsonIgnore] public ProjectField<string> CustomRoleSlugField => _assignment.CustomRoleSlugField;
    [JsonIgnore] public ProjectField<string> ModeField => _assignment.ModeField;
    [JsonIgnore] public ProjectField<string> RangeField => _assignment.RangeField;
    [JsonIgnore] public ProjectField<string> StartsAtField => _assignment.StartsAtField;
    [JsonIgnore] public ProjectField<string> EndsAtField => _assignment.EndsAtField;
    [JsonIgnore] public IdentityField<string> CustomRoleDescription { get; }
    public override string ToString() => "[IdentitySearchRole]";
}

/// <summary>Membership search metadata, not an effective-permission or authentication result.</summary>
public sealed class IdentitySearchSummary
{
    internal IdentitySearchSummary(JsonElement value, string organizationId, IdentitySearchScope scope)
    {
        ManagementJson.RequireEqual(value, "orgId", organizationId);
        Scope = ManagementJson.Required(value, "scope") switch
        {
            "organization" => IdentitySearchScope.Organization,
            "project" => IdentitySearchScope.Projects,
            _ => throw new ManagementContractException(SecretStatus.Unknown)
        };
        if ((scope & Scope) == 0) throw new ManagementContractException(SecretStatus.Invalid);
        ProjectId = ManagementJson.Optional(value, "projectId");
        if ((Scope == IdentitySearchScope.Organization && ProjectId is not null) ||
            (Scope == IdentitySearchScope.Projects && string.IsNullOrEmpty(ProjectId)))
            throw new ManagementContractException(SecretStatus.Invalid);
        Project = IdentityMetadataWire.Field(value, "project", project =>
        {
            if (ProjectId is null) throw new ManagementContractException(SecretStatus.Invalid);
            return new IdentitySearchProject(project, ProjectId);
        }, nullable: true);
        MembershipId = ManagementJson.Required(value, "id");
        string identityId = ManagementJson.Required(value, "identityId");
        Identity = new IdentitySummary(ManagementJson.Object(value, "identity"), organizationId, id: identityId,
            requireAuthMethods: true, requireLockoutMethods: true);
        CreatedAt = ManagementJson.Required(value, "createdAt");
        UpdatedAt = ManagementJson.Required(value, "updatedAt");
        LastLoginAuthMethod = IdentityMetadataWire.StringField(value, "lastLoginAuthMethod", nullable: true);
        LastLoginTime = IdentityMetadataWire.Field(value, "lastLoginTime", child =>
        {
            string text = IdentityMetadataWire.String(child);
            ManagementResponseDates.ValidateDateValue(child);
            return text;
        }, nullable: true);
        JsonElement.ArrayEnumerator roles = ManagementJson.Array(value, "roles");
        if (roles.Count() > 100) throw new ManagementContractException(SecretStatus.Unknown);
        Roles = Array.AsReadOnly(roles.Select(role => new IdentitySearchRole(role)).ToArray());
    }
    public IdentitySearchScope Scope { get; }
    [JsonIgnore] public string MembershipId { get; }
    [JsonIgnore] public string? ProjectId { get; }
    [JsonIgnore] public IdentitySummary Identity { get; }
    [JsonIgnore] public string CreatedAt { get; }
    [JsonIgnore] public string UpdatedAt { get; }
    [JsonIgnore] public IdentityField<string> LastLoginAuthMethod { get; }
    [JsonIgnore] public IdentityField<string> LastLoginTime { get; }
    [JsonIgnore] public IdentityField<IdentitySearchProject> Project { get; }
    [JsonIgnore] public IReadOnlyList<IdentitySearchRole> Roles { get; }
    public bool IncludesPermissions => false;
    public override string ToString() => "[IdentitySearchSummary]";
}

public sealed class IdentitySearchCounts
{
    internal IdentitySearchCounts(JsonElement root, IdentitySearchScope scope)
    {
        JsonElement counts = ManagementJson.Object(root, "counts");
        if ((scope & IdentitySearchScope.Organization) != 0)
            Organization = ManagementJson.Integer(counts, "organization");
        if ((scope & IdentitySearchScope.Projects) != 0)
            Projects = ManagementJson.Integer(counts, "project");
        if (Organization is < 0 || Projects is < 0) throw new ManagementContractException(SecretStatus.Unknown);
    }
    [JsonIgnore] public int? Organization { get; }
    [JsonIgnore] public int? Projects { get; }
    public override string ToString() => "[IdentitySearchCounts]";
}

public static class IdentitySearchOperations
{
    public static ManagementRequest<ManagementPage<IdentitySearchSummary>> SearchIdentities(
        string organizationId, IdentitySearchScope scope, IdentitySearchFilter? filter = null,
        int offset = 0, int limit = 50, IdentitySearchOrder order = IdentitySearchOrder.Name,
        ManagementListOrder direction = ManagementListOrder.Ascending)
    {
        Action<Utf8JsonWriter> write = SearchBody(scope, filter, offset, limit, order, direction);
        return new("infisical.post.v2.identities.search", HttpMethod.Post, "/api/v2/identities/search",
            MembershipRoleWire.Intent(organizationId, null, Selection(scope), write), write,
            root => ScopedAccessOperations.CountedPage(root, "identities",
                row => new IdentitySearchSummary(row, organizationId, scope), offset, limit), false);
    }

    /// <summary>Independently selected full search body, including filter shape, paging and order.</summary>
    public static ManagementTarget IdentitySearchTarget(string organizationId, IdentitySearchScope scope,
        IdentitySearchFilter? filter = null, int offset = 0, int limit = 50,
        IdentitySearchOrder order = IdentitySearchOrder.Name, ManagementListOrder direction = ManagementListOrder.Ascending) =>
        MembershipRoleWire.Intent(organizationId, null, Selection(scope),
            SearchBody(scope, filter, offset, limit, order, direction));

    private static Action<Utf8JsonWriter> SearchBody(IdentitySearchScope scope, IdentitySearchFilter? filter,
        int offset, int limit, IdentitySearchOrder order, ManagementListOrder direction)
    {
        Selection(scope);
        ManagementJson.Paging(offset, limit);
        if (!Enum.IsDefined(order) || !Enum.IsDefined(direction)) throw new ArgumentException("Invalid search order.");
        return writer =>
            {
                WriteSearch(writer, scope, filter, false);
                writer.WriteNumber("offset", offset);
                writer.WriteNumber("limit", limit);
                writer.WriteString("orderBy", order switch
                {
                    IdentitySearchOrder.Role => "role",
                    IdentitySearchOrder.LastLogin => "lastLogin",
                    _ => "name"
                });
                writer.WriteString("orderDirection", direction == ManagementListOrder.Ascending ? "asc" : "desc");
                writer.WriteEndObject();
            };
    }

    public static ManagementRequest<IdentitySearchCounts> CountIdentities(
        string organizationId, IdentitySearchScope scope, IdentitySearchFilter? filter = null)
    {
        string selection = Selection(scope);
        Action<Utf8JsonWriter> write = writer => WriteSearch(writer, scope, filter, true);
        return new("infisical.post.v2.identities.search.count", HttpMethod.Post, "/api/v2/identities/search/count",
            MembershipRoleWire.Intent(organizationId, null, selection, write), write, root => new(root, scope), false);
    }

    /// <summary>Independently approved complete count body; filter omission is distinct from an empty object.</summary>
    public static ManagementTarget IdentityCountTarget(string organizationId, IdentitySearchScope scope,
        IdentitySearchFilter? filter = null) =>
        MembershipRoleWire.Intent(organizationId, null, Selection(scope),
            writer => WriteSearch(writer, scope, filter, true));

    private static string Selection(IdentitySearchScope scope) => scope switch
    {
        IdentitySearchScope.Organization => "organization",
        IdentitySearchScope.Projects => "project",
        IdentitySearchScope.Organization | IdentitySearchScope.Projects => "organization,project",
        _ => throw new ArgumentException("An explicit search scope is required.")
    };

    private static void WriteSearch(Utf8JsonWriter writer, IdentitySearchScope scope, IdentitySearchFilter? filter, bool end)
    {
        writer.WriteStartObject();
        writer.WriteStartArray("scope");
        if ((scope & IdentitySearchScope.Organization) != 0) writer.WriteStringValue("organization");
        if ((scope & IdentitySearchScope.Projects) != 0) writer.WriteStringValue("project");
        writer.WriteEndArray();
        if (filter is not null) { writer.WritePropertyName("search"); filter.Write(writer); }
        if (end) writer.WriteEndObject();
    }
}

internal interface IIdentitySearchApi
{
    [Post("/api/v2/identities/search")]
    Task<HttpRequestMessage> Search([Body] HttpContent body, CancellationToken cancellationToken);
    [Post("/api/v2/identities/search/count")]
    Task<HttpRequestMessage> Count([Body] HttpContent body, CancellationToken cancellationToken);
}
