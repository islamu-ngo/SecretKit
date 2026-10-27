using System.Text.Json;
using System.Text.Json.Serialization;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Explicit membership search scopes; flags may select organization and project memberships together.</summary>
[Flags]
public enum IdentitySearchScope { /** <summary>Includes organization memberships.</summary> */ Organization = 1, /** <summary>Includes project memberships.</summary> */ Projects = 2 }
/// <summary>Native membership search sort columns.</summary>
public enum IdentitySearchOrder { /** <summary>Sorts by identity name.</summary> */ Name, /** <summary>Sorts by assigned role.</summary> */ Role, /** <summary>Sorts by reported last-login time.</summary> */ LastLogin }

/// <summary>Native string operators. Inputs are copied and bounded; no arbitrary query JSON.</summary>
public sealed class IdentitySearchText
{
    /// <summary>Copies bounded native text predicates; null omits an operator and empty strings remain explicit.</summary>
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
    /// <summary>Gets the equality operand, or null when omitted.</summary>
    [JsonIgnore] public string? Equal { get; }
    /// <summary>Gets the substring operand, or null when omitted.</summary>
    [JsonIgnore] public string? Contains { get; }
    /// <summary>Gets copied membership operands, or null when omitted; empty remains explicit.</summary>
    [JsonIgnore] public IReadOnlyList<string>? AnyOf { get; }
    /// <summary>Gets the scalar shorthand operand, or null for operator-object form.</summary>
    [JsonIgnore] public string? ShorthandValue { get; private init; }

    /// <summary>Selects native scalar shorthand instead of an operator object.</summary>
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
    /// <summary>Returns a marker without search operands.</summary>
    public override string ToString() => "[IdentitySearchText]";
}

/// <summary>An optional conjunction of name and role predicates within one search clause.</summary>
public sealed class IdentitySearchClause
{
    /// <summary>Captures optional name and role predicates without evaluating permissions.</summary>
    public IdentitySearchClause(IdentitySearchText? name = null, IdentitySearchText? role = null)
    {
        Name = name;
        Role = role;
    }
    /// <summary>Gets name predicates, or null when omitted.</summary>
    [JsonIgnore] public IdentitySearchText? Name { get; }
    /// <summary>Gets role predicates, or null when omitted.</summary>
    [JsonIgnore] public IdentitySearchText? Role { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        if (Name is not null) { writer.WritePropertyName("name"); Name.Write(writer); }
        if (Role is not null) { writer.WritePropertyName("role"); Role.Write(writer); }
    }
    /// <summary>Returns a marker without clause operands.</summary>
    public override string ToString() => "[IdentitySearchClause]";
}

/// <summary>Bounded native search composition with optional conjunction and at most five alternative clauses.</summary>
public sealed class IdentitySearchFilter
{
    /// <summary>Copies alternative clauses; null omits the operator while an empty array stays explicit.</summary>
    public IdentitySearchFilter(IdentitySearchClause? all = null, IReadOnlyList<IdentitySearchClause>? anyOf = null)
    {
        IdentitySearchClause[]? copy = anyOf?.Take(6).ToArray();
        if (copy is not null && (copy.Length > 5 || copy.Any(item => item is null)))
            throw new ArgumentException("Invalid search clause budget.");
        All = all;
        AnyOf = copy is null ? null : Array.AsReadOnly(copy);
    }
    /// <summary>Gets the conjunctive clause, or null when omitted.</summary>
    [JsonIgnore] public IdentitySearchClause? All { get; }
    /// <summary>Gets copied alternative clauses, or null when omitted.</summary>
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
    /// <summary>Returns a marker without search clauses.</summary>
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
    /// <summary>Gets the returned project identifier matched to the membership.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned project name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the returned native project slug.</summary>
    [JsonIgnore] public string Slug { get; }
    /// <summary>Gets the returned native project-type label.</summary>
    [JsonIgnore] public string Type { get; }
    /// <summary>Returns a marker without project coordinates.</summary>
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
    /// <summary>Gets the returned assignment identifier.</summary>
    [JsonIgnore] public string Id => _assignment.Id;
    /// <summary>Gets the returned role label.</summary>
    [JsonIgnore] public string Role => _assignment.Role;
    /// <summary>Gets custom-role identifier, or null when absent or explicitly null.</summary>
    [JsonIgnore] public string? CustomRoleId => _assignment.CustomRoleId;
    /// <summary>Gets custom-role name, or null when absent or explicitly null.</summary>
    [JsonIgnore] public string? CustomRoleName => _assignment.CustomRoleName;
    /// <summary>Gets custom-role slug, or null when absent or explicitly null.</summary>
    [JsonIgnore] public string? CustomRoleSlug => _assignment.CustomRoleSlug;
    /// <summary>Gets the reported temporary flag, or null when omitted.</summary>
    [JsonIgnore] public bool? IsTemporary => _assignment.IsTemporary;
    /// <summary>Gets the reported validity mode, or null when not supplied.</summary>
    [JsonIgnore] public string? Mode => _assignment.Mode;
    /// <summary>Gets the native duration expression, or null when not supplied.</summary>
    [JsonIgnore] public string? Range => _assignment.Range;
    /// <summary>Gets the reported access start time, or null when not supplied.</summary>
    [JsonIgnore] public string? StartsAt => _assignment.StartsAt;
    /// <summary>Gets the reported access end time, or null when not supplied.</summary>
    [JsonIgnore] public string? EndsAt => _assignment.EndsAt;
    /// <summary>Gets custom-role identifier presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> CustomRoleIdField => _assignment.CustomRoleIdField;
    /// <summary>Gets custom-role name presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> CustomRoleNameField => _assignment.CustomRoleNameField;
    /// <summary>Gets custom-role slug presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> CustomRoleSlugField => _assignment.CustomRoleSlugField;
    /// <summary>Gets validity-mode presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> ModeField => _assignment.ModeField;
    /// <summary>Gets duration presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> RangeField => _assignment.RangeField;
    /// <summary>Gets access-start presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> StartsAtField => _assignment.StartsAtField;
    /// <summary>Gets access-end presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> EndsAtField => _assignment.EndsAtField;
    /// <summary>Gets description presence, preserving omission and explicit null.</summary>
    [JsonIgnore] public IdentityField<string> CustomRoleDescription { get; }
    /// <summary>Returns a marker without role metadata.</summary>
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
    /// <summary>Gets the returned organization or project membership scope.</summary>
    public IdentitySearchScope Scope { get; }
    /// <summary>Gets the returned membership identifier.</summary>
    [JsonIgnore] public string MembershipId { get; }
    /// <summary>Gets the project identifier; organization membership results leave it null.</summary>
    [JsonIgnore] public string? ProjectId { get; }
    /// <summary>Gets returned nested identity metadata with matching identifier.</summary>
    [JsonIgnore] public IdentitySummary Identity { get; }
    /// <summary>Gets the returned membership creation timestamp.</summary>
    [JsonIgnore] public string CreatedAt { get; }
    /// <summary>Gets the returned membership update timestamp.</summary>
    [JsonIgnore] public string UpdatedAt { get; }
    /// <summary>Gets last-login method presence, retaining explicit null.</summary>
    [JsonIgnore] public IdentityField<string> LastLoginAuthMethod { get; }
    /// <summary>Gets last-login timestamp presence, retaining explicit null.</summary>
    [JsonIgnore] public IdentityField<string> LastLoginTime { get; }
    /// <summary>Gets nested project metadata presence; omission and explicit null remain distinct.</summary>
    [JsonIgnore] public IdentityField<IdentitySearchProject> Project { get; }
    /// <summary>Gets bounded returned assignment metadata, not effective permissions.</summary>
    [JsonIgnore] public IReadOnlyList<IdentitySearchRole> Roles { get; }
    /// <summary>Always false: search results do not include effective permissions.</summary>
    public bool IncludesPermissions => false;
    /// <summary>Returns a marker without membership or identity details.</summary>
    public override string ToString() => "[IdentitySearchSummary]";
}

/// <summary>Returned counts for explicitly selected search scopes; unselected scopes remain null.</summary>
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
    /// <summary>Gets organization count, or null when organization scope was not selected.</summary>
    [JsonIgnore] public int? Organization { get; }
    /// <summary>Gets project-membership count, or null when project scope was not selected.</summary>
    [JsonIgnore] public int? Projects { get; }
    /// <summary>Returns a marker without search count values.</summary>
    public override string ToString() => "[IdentitySearchCounts]";
}

/// <summary>Constructs disposable search and count requests with independently approved whole-body intent.</summary>
public static class IdentitySearchOperations
{
    /// <summary>Builds a count-validated search page; null filter omits search rather than sending an empty object.</summary>
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

    /// <summary>Builds a read-only count request for exact selected scopes and optional filter; acquires no credentials.</summary>
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
