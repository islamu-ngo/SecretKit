using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>A supplied nullable collection. A null argument omits; Null emits JSON null.</summary>
public sealed class ProjectTemplateCollection<T> where T : class
{
    private ProjectTemplateCollection(T[]? values) => Values = values;
    internal T[]? Values { get; }
    /// <summary>Selects an explicit JSON null collection rather than omission.</summary>
    public static ProjectTemplateCollection<T> Null() => new(null);
    /// <summary>Copies a bounded collection; an empty list remains an explicit empty array.</summary>
    public static ProjectTemplateCollection<T> FromValues(IReadOnlyList<T> values) =>
        new(ProjectTemplateWire.Copy(values));
    /// <summary>Returns a marker without collection contents.</summary>
    public override string ToString() => "[ProjectTemplateCollection]";
}

/// <summary>Native literal or comparison object, including an explicit empty comparison or inclusion array.</summary>
public sealed class ProjectTemplateStringClause
{
    private readonly string? _literal;
    private readonly string? _equal;
    private readonly string? _notEqual;
    private readonly string? _glob;
    private readonly string[]? _included;
    private ProjectTemplateStringClause(string? literal, string? equal, string? notEqual, string? glob,
        IReadOnlyList<string>? included)
    {
        if (literal is not null) RolePermissionWire.Text(literal, 16384, allowEmpty: true);
        foreach (string? value in new[] { equal, notEqual, glob })
            if (value is not null) ProjectTemplateWire.Text(value);
        _literal = literal;
        _equal = equal;
        _notEqual = notEqual;
        _glob = glob;
        _included = included is null ? null : ProjectTemplateWire.Copy(included);
        if (_included is not null)
            foreach (string value in _included) ProjectTemplateWire.Text(value);
    }
    /// <summary>Selects a literal string, including an explicit empty value.</summary>
    public static ProjectTemplateStringClause Literal(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new(value, null, null, null, null);
    }
    /// <summary>Copies native comparison operands; all omitted operands produce an explicit empty comparison object.</summary>
    public static ProjectTemplateStringClause Compare(string? equal = null, string? notEqual = null,
        IReadOnlyList<string>? included = null, string? glob = null) => new(null, equal, notEqual, glob, included);
    // Validate operator applicability through the native peer, replacing only empty shapes
    // that that peer's narrower input contract cannot represent.
    internal RoleStringClause ValidationClause => _literal is not null ? RoleStringClause.Literal(_literal) :
        _equal is null && _notEqual is null && _glob is null && _included is null
            ? RoleStringClause.Compare(equal: "shape")
            : RoleStringClause.Compare(_equal, _notEqual,
                _included is { Length: 0 } ? ["shape"] : _included, _glob);
    internal void Write(Utf8JsonWriter writer)
    {
        if (_literal is not null) { writer.WriteStringValue(_literal); return; }
        writer.WriteStartObject();
        if (_equal is not null) writer.WriteString("$eq", _equal);
        if (_notEqual is not null) writer.WriteString("$ne", _notEqual);
        if (_included is not null) ProjectTemplateWire.Array(writer, "$in", _included, (w, v) => w.WriteStringValue(v));
        if (_glob is not null) writer.WriteString("$glob", _glob);
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without comparison operands.</summary>
    public override string ToString() => "[ProjectTemplateStringClause]";
}

/// <summary>A typed native template condition, not arbitrary condition JSON.</summary>
public sealed class ProjectTemplateCondition
{
    /// <summary>Binds one known condition field to an explicit literal or comparison clause.</summary>
    public ProjectTemplateCondition(RoleConditionField field, ProjectTemplateStringClause clause)
    {
        if (!Enum.IsDefined(field)) throw new ArgumentOutOfRangeException(nameof(field));
        ArgumentNullException.ThrowIfNull(clause);
        Field = field;
        Clause = clause;
    }
    internal RoleConditionField Field { get; }
    internal ProjectTemplateStringClause Clause { get; }
    /// <summary>Returns a marker without condition operands.</summary>
    public override string ToString() => "[ProjectTemplateCondition]";
}

/// <summary>Native secret-tag predicates preserving absent and explicit empty operator arrays.</summary>
public sealed class ProjectTemplateSecretTags
{
    private readonly string[]? _included;
    private readonly string[]? _all;
    /// <summary>Copies optional inclusion and all-tag selections; null omits each operator.</summary>
    public ProjectTemplateSecretTags(IReadOnlyList<string>? included = null, IReadOnlyList<string>? all = null)
    {
        _included = included is null ? null : ProjectTemplateWire.Copy(included);
        _all = all is null ? null : ProjectTemplateWire.Copy(all);
        foreach (string value in (_included ?? []).Concat(_all ?? [])) ProjectTemplateWire.Text(value);
    }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("secretTags");
        if (_included is not null) ProjectTemplateWire.Array(writer, "$in", _included, (w, v) => w.WriteStringValue(v));
        if (_all is not null) ProjectTemplateWire.Array(writer, "$all", _all, (w, v) => w.WriteStringValue(v));
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without tag selectors.</summary>
    public override string ToString() => "[ProjectTemplateSecretTags]";
}

/// <summary>Comparisons on one metadata entry; empty elemMatch and empty key/value objects are native alternatives.</summary>
public sealed class ProjectTemplateMetadataMatch
{
    private readonly ProjectTemplateStringClause? _key;
    private readonly ProjectTemplateStringClause? _value;
    /// <summary>Selects comparisons on one metadata entry; omitted key and value retain an explicit empty elemMatch.</summary>
    public ProjectTemplateMetadataMatch(ProjectTemplateStringClause? key = null, ProjectTemplateStringClause? value = null)
    {
        _key = key;
        _value = value;
        _ = ValidationMatch;
    }
    internal RoleMetadataMatch ValidationMatch => new(
        _key?.ValidationClause ?? (_value is null ? RoleStringClause.Compare(equal: "shape") : null),
        _value?.ValidationClause);
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("metadata");
        writer.WriteStartObject("$elemMatch");
        if (_key is not null) { writer.WritePropertyName("key"); _key.Write(writer); }
        if (_value is not null) { writer.WritePropertyName("value"); _value.Write(writer); }
        writer.WriteEndObject();
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without metadata predicates.</summary>
    public override string ToString() => "[ProjectTemplateMetadataMatch]";
}

/// <summary>Active project permission alternatives with native scalar/array and absent/empty distinctions.</summary>
public sealed class ProjectTemplatePermission
{
    private readonly ProjectRoleSubject _subject;
    private readonly ProjectRoleAction[] _actions;
    private readonly bool _scalar;
    private readonly bool? _inverted;
    private readonly ProjectTemplateCondition[]? _conditions;
    private readonly ProjectTemplateSecretTags? _tags;
    private readonly ProjectTemplateMetadataMatch? _metadata;
    /// <summary>Captures a scalar native action with copied optional conditions and nullable inversion.</summary>
    public ProjectTemplatePermission(ProjectRoleSubject subject, ProjectRoleAction action, bool? inverted = null,
        IReadOnlyList<ProjectTemplateCondition>? conditions = null, ProjectTemplateSecretTags? secretTags = null,
        ProjectTemplateMetadataMatch? metadata = null)
        : this(subject, [action], inverted, conditions, secretTags, metadata) => _scalar = true;
    /// <summary>Copies an action array and optional conditions; empty supported conditions remain explicit, not omitted.</summary>
    public ProjectTemplatePermission(ProjectRoleSubject subject, IReadOnlyList<ProjectRoleAction> actions,
        bool? inverted = null, IReadOnlyList<ProjectTemplateCondition>? conditions = null,
        ProjectTemplateSecretTags? secretTags = null, ProjectTemplateMetadataMatch? metadata = null)
    {
        ArgumentNullException.ThrowIfNull(actions);
        _actions = actions.Take(101).ToArray();
        _conditions = conditions is null ? null : ProjectTemplateWire.Copy(conditions);
        _ = new ProjectRolePermission(subject, _actions, inverted,
            _conditions is { Length: > 0 }
                ? _conditions.Select(c => new RoleCondition(c.Field, c.Clause.ValidationClause)).ToArray() : null,
            secretTags is null ? null : new RoleSecretTags(included: ["shape"]), metadata?.ValidationMatch);
        if (_conditions is { Length: 0 } && !SupportsConditions(subject))
            throw new ArgumentException("Conditions are not supported for this template permission subject.");
        _subject = subject;
        _inverted = inverted;
        _tags = secretTags;
        _metadata = metadata;
    }
    private static bool SupportsConditions(ProjectRoleSubject subject) => subject is
        ProjectRoleSubject.Secrets or ProjectRoleSubject.SecretFolders or ProjectRoleSubject.SecretImports or
        ProjectRoleSubject.DynamicSecrets or ProjectRoleSubject.Identity or ProjectRoleSubject.PkiSubscribers or
        ProjectRoleSubject.CertificateTemplates or ProjectRoleSubject.SecretRotation or ProjectRoleSubject.SecretSyncs or
        ProjectRoleSubject.PkiSyncs or ProjectRoleSubject.SecretEventSubscriptions or ProjectRoleSubject.CertificateProfiles or
        ProjectRoleSubject.CertificatePolicies or ProjectRoleSubject.CertificateAuthorities or ProjectRoleSubject.Certificates or
        ProjectRoleSubject.Member or ProjectRoleSubject.Groups or ProjectRoleSubject.Commits or ProjectRoleSubject.AppConnections or
        ProjectRoleSubject.HoneyTokens or ProjectRoleSubject.ProxiedServices or ProjectRoleSubject.ProjectFolderGrant;
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        writer.WriteString("subject", RolePermissionWire.Name(_subject));
        if (_scalar) writer.WriteString("action", RolePermissionWire.Name(_actions[0]));
        else ProjectTemplateWire.Array(writer, "action", _actions, (w, v) => w.WriteStringValue(RolePermissionWire.Name(v)));
        if (_inverted is { } inverted) writer.WriteBoolean("inverted", inverted);
        if (_conditions is not null || _tags is not null || _metadata is not null)
        {
            writer.WriteStartObject("conditions");
            foreach (var condition in _conditions ?? [])
            {
                string name = condition.Field.ToString();
                writer.WritePropertyName(char.ToLowerInvariant(name[0]) + name[1..]);
                condition.Clause.Write(writer);
            }
            _tags?.Write(writer);
            _metadata?.Write(writer);
            writer.WriteEndObject();
        }
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without permission conditions.</summary>
    public override string ToString() => "[ProjectTemplatePermission]";
}

/// <summary>Template role authoring with bounded copied permissions, not effective-permission evaluation.</summary>
public sealed class ProjectTemplateRole
{
    private readonly string _name;
    private readonly string _slug;
    private readonly ProjectTemplatePermission[] _permissions;
    /// <summary>Captures role name/slug and copies bounded permission selections, including explicit empty permissions.</summary>
    public ProjectTemplateRole(string name, string slug, IReadOnlyList<ProjectTemplatePermission> permissions)
    {
        ProjectTemplateWire.Text(name);
        ProjectTemplateWire.Text(slug, 64);
        _name = name;
        _slug = slug;
        _permissions = ProjectTemplateWire.Copy(permissions);
    }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        writer.WriteString("name", _name);
        writer.WriteString("slug", _slug);
        writer.WriteStartArray("permissions");
        foreach (var permission in _permissions) permission.Write(writer);
        writer.WriteEndArray();
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without role or permission fields.</summary>
    public override string ToString() => "[ProjectTemplateRole]";
}

/// <summary>Native template environment definition preserving numeric position without rounding.</summary>
public sealed class ProjectTemplateEnvironment
{
    /// <summary>Captures environment name/slug and a finite position of at least one.</summary>
    public ProjectTemplateEnvironment(string name, string slug, double position)
    {
        ProjectTemplateWire.Text(name);
        ProjectTemplateWire.Text(slug, 64);
        if (!double.IsFinite(position) || position < 1)
            throw new ArgumentException("Invalid project template environment position.");
        Name = name;
        Slug = slug;
        Position = position;
    }
    /// <summary>Gets the selected or returned environment name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the native environment slug.</summary>
    [JsonIgnore] public string Slug { get; }
    /// <summary>Gets the finite native position without integer truncation.</summary>
    [JsonIgnore] public double Position { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        writer.WriteString("name", Name);
        writer.WriteString("slug", Slug);
        writer.WriteNumber("position", Position);
        writer.WriteEndObject();
    }
    private ProjectTemplateEnvironment(JsonElement value)
    {
        Name = ProjectTemplateWire.Required(value, "name", 16384, false);
        Slug = ProjectTemplateWire.Required(value, "slug", 64, false);
        if (!value.TryGetProperty("position", out var position) || position.ValueKind != JsonValueKind.Number ||
            !position.TryGetDouble(out double number) || !double.IsFinite(number) || number < 1)
            throw new ManagementContractException(SecretStatus.Unknown);
        Position = number;
    }
    internal static ProjectTemplateEnvironment Parse(JsonElement value) => new(value);
    /// <summary>Returns a marker without environment coordinates.</summary>
    public override string ToString() => "[ProjectTemplateEnvironment]";
}

/// <summary>Template user assignment with explicit copied role slugs.</summary>
public sealed class ProjectTemplateUser
{
    /// <summary>Captures a username and copies a nonempty bounded role selection.</summary>
    public ProjectTemplateUser(string username, IReadOnlyList<string> roles)
    {
        ProjectTemplateWire.Text(username);
        Username = username;
        Roles = Array.AsReadOnly(ProjectTemplateWire.RoleNames(roles));
    }
    internal ProjectTemplateUser(JsonElement value)
    {
        Username = ProjectTemplateWire.Required(value, "username", 16384, false);
        Roles = ProjectTemplateWire.Strings(value, "roles");
    }
    /// <summary>Gets the selected or returned username.</summary>
    [JsonIgnore] public string Username { get; }
    /// <summary>Gets copied native role slugs, not an effective role set.</summary>
    [JsonIgnore] public IReadOnlyList<string> Roles { get; }
    internal void Write(Utf8JsonWriter writer) => ProjectTemplateWire.Principal(writer, "username", Username, Roles);
    /// <summary>Returns a marker without user assignments.</summary>
    public override string ToString() => "[ProjectTemplateUser]";
}

/// <summary>Template group assignment selected by native group slug.</summary>
public sealed class ProjectTemplateGroup
{
    /// <summary>Captures a group slug and copies a nonempty bounded role selection.</summary>
    public ProjectTemplateGroup(string groupSlug, IReadOnlyList<string> roles)
    {
        ProjectTemplateWire.Text(groupSlug);
        GroupSlug = groupSlug;
        Roles = Array.AsReadOnly(ProjectTemplateWire.RoleNames(roles));
    }
    internal ProjectTemplateGroup(JsonElement value)
    {
        GroupSlug = ProjectTemplateWire.Required(value, "groupSlug");
        Roles = ProjectTemplateWire.Strings(value, "roles");
    }
    /// <summary>Gets the selected or returned group slug.</summary>
    [JsonIgnore] public string GroupSlug { get; }
    /// <summary>Gets copied native role slugs without evaluating permissions.</summary>
    [JsonIgnore] public IReadOnlyList<string> Roles { get; }
    internal void Write(Utf8JsonWriter writer) => ProjectTemplateWire.Principal(writer, "groupSlug", GroupSlug, Roles);
    /// <summary>Returns a marker without group assignments.</summary>
    public override string ToString() => "[ProjectTemplateGroup]";
}

/// <summary>Template existing-machine-identity assignment with explicit role selection.</summary>
public sealed class ProjectTemplateIdentity
{
    /// <summary>Captures an identity UUID and copies nonempty role slugs; does not infer an identity name.</summary>
    public ProjectTemplateIdentity(string identityId, IReadOnlyList<string> roles)
    {
        if (!Guid.TryParseExact(identityId, "D", out _))
            throw new ArgumentException("Invalid project template identity identifier.");
        IdentityId = identityId;
        Roles = Array.AsReadOnly(ProjectTemplateWire.RoleNames(roles));
    }
    internal ProjectTemplateIdentity(JsonElement value)
    {
        IdentityId = ProjectTemplateWire.Required(value, "identityId");
        if (!Guid.TryParseExact(IdentityId, "D", out _))
            throw new ManagementContractException(SecretStatus.Unknown);
        IdentityName = ProjectTemplateWire.Required(value, "identityName");
        Roles = ProjectTemplateWire.Strings(value, "roles");
    }
    /// <summary>Gets the selected or returned identity UUID.</summary>
    [JsonIgnore] public string IdentityId { get; }
    /// <summary>Returned metadata only; never inferred from an input ID.</summary>
    [JsonIgnore] public string? IdentityName { get; }
    /// <summary>Gets copied native role slugs, not runtime authorization evidence.</summary>
    [JsonIgnore] public IReadOnlyList<string> Roles { get; }
    internal void Write(Utf8JsonWriter writer) => ProjectTemplateWire.Principal(writer, "identityId", IdentityId, Roles);
    /// <summary>Returns a marker without identity assignments.</summary>
    public override string ToString() => "[ProjectTemplateIdentity]";
}

/// <summary>Template-managed identity definition, not an already provisioned runtime identity.</summary>
public sealed class ProjectTemplateManagedIdentity
{
    /// <summary>Captures a managed-identity name and copies a nonempty bounded role selection.</summary>
    public ProjectTemplateManagedIdentity(string name, IReadOnlyList<string> roles)
    {
        ProjectTemplateWire.Text(name);
        Name = name;
        Roles = Array.AsReadOnly(ProjectTemplateWire.RoleNames(roles));
    }
    internal ProjectTemplateManagedIdentity(JsonElement value)
    {
        Name = ProjectTemplateWire.Required(value, "name", 16384, false);
        Roles = ProjectTemplateWire.Strings(value, "roles");
    }
    /// <summary>Gets the selected or returned managed-identity name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets copied native role slugs, not effective access.</summary>
    [JsonIgnore] public IReadOnlyList<string> Roles { get; }
    internal void Write(Utf8JsonWriter writer) => ProjectTemplateWire.Principal(writer, "name", Name, Roles);
    /// <summary>Returns a marker without managed-identity assignments.</summary>
    public override string ToString() => "[ProjectTemplateManagedIdentity]";
}

/// <summary>Immutable optional native inputs. Defaults are left to the provider.</summary>
public sealed class ProjectTemplateConfiguration
{
    private readonly ProjectTemplateRole[]? _roles;
    private readonly ProjectTemplateCollection<ProjectTemplateEnvironment>? _environments;
    private readonly ProjectTemplateCollection<ProjectTemplateUser>? _users;
    private readonly ProjectTemplateCollection<ProjectTemplateGroup>? _groups;
    private readonly ProjectTemplateCollection<ProjectTemplateIdentity>? _identities;
    private readonly ProjectTemplateCollection<ProjectTemplateManagedIdentity>? _managed;
    /// <summary>Copies optional roles and retains immutable nullable collections; null arguments omit and wrappers can explicitly clear.</summary>
    public ProjectTemplateConfiguration(IReadOnlyList<ProjectTemplateRole>? roles = null,
        ProjectTemplateCollection<ProjectTemplateEnvironment>? environments = null,
        ProjectTemplateCollection<ProjectTemplateUser>? users = null,
        ProjectTemplateCollection<ProjectTemplateGroup>? groups = null,
        ProjectTemplateCollection<ProjectTemplateIdentity>? identities = null,
        ProjectTemplateCollection<ProjectTemplateManagedIdentity>? projectManagedIdentities = null)
    {
        _roles = roles is null ? null : ProjectTemplateWire.Copy(roles);
        _environments = environments;
        _users = users;
        _groups = groups;
        _identities = identities;
        _managed = projectManagedIdentities;
    }
    internal bool HasFields => _roles is not null || _environments is not null || _users is not null ||
        _groups is not null || _identities is not null || _managed is not null;
    internal void ValidateCreate()
    {
        if (_users is { Values: null } || _groups is { Values: null } ||
            _identities is { Values: null } || _managed is { Values: null })
            throw new ArgumentException("Null principal collections are only supported in project template updates.");
    }
    internal void Write(Utf8JsonWriter writer)
    {
        if (_roles is not null) ProjectTemplateWire.Array(writer, "roles", _roles, (w, v) => v.Write(w));
        ProjectTemplateWire.Collection(writer, "environments", _environments, (w, v) => v.Write(w));
        ProjectTemplateWire.Collection(writer, "users", _users, (w, v) => v.Write(w));
        ProjectTemplateWire.Collection(writer, "groups", _groups, (w, v) => v.Write(w));
        ProjectTemplateWire.Collection(writer, "identities", _identities, (w, v) => v.Write(w));
        ProjectTemplateWire.Collection(writer, "projectManagedIdentities", _managed, (w, v) => v.Write(w));
    }
    /// <summary>Returns a marker without template configuration.</summary>
    public override string ToString() => "[ProjectTemplateConfiguration]";
}

/// <summary>Preserves the native scalar versus array selection, including an empty returned array.</summary>
public sealed class ProjectTemplatePermissionSelection
{
    internal ProjectTemplatePermissionSelection(JsonElement value)
    {
        IsScalar = value.ValueKind == JsonValueKind.String;
        if (IsScalar)
        {
            string scalar = ProjectTemplateWire.String(value, 16384, false);
            Values = Array.AsReadOnly(new[] { scalar });
        }
        else
            Values = Array.AsReadOnly(ManagementJson.Array(value).Select(v => ProjectTemplateWire.String(v)).ToArray());
    }
    /// <summary>Gets whether the response used a scalar string rather than an array.</summary>
    public bool IsScalar { get; }
    /// <summary>Gets the returned scalar as one value or the exact returned array, including an empty array.</summary>
    [JsonIgnore] public IReadOnlyList<string> Values { get; }
    /// <summary>Returns a marker without permission selection values.</summary>
    public override string ToString() => "[ProjectTemplatePermissionSelection]";
}

/// <summary>Native metadata, not effective permission. The provider leaves conditions unconstrained.</summary>
public sealed class ProjectTemplatePermissionSummary
{
    internal ProjectTemplatePermissionSummary(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty("action", out var action))
            throw new ManagementContractException(SecretStatus.Unknown);
        Action = new(action);
        if (value.TryGetProperty("subject", out var subject)) Subject = new(subject);
        if (value.TryGetProperty("inverted", out _)) Inverted = ManagementJson.Boolean(value, "inverted");
        HasConditions = value.TryGetProperty("conditions", out _);
    }
    /// <summary>Gets the returned scalar or array action selection.</summary>
    [JsonIgnore] public ProjectTemplatePermissionSelection Action { get; }
    /// <summary>Gets returned subject selection, or null when the subject field is omitted.</summary>
    [JsonIgnore] public ProjectTemplatePermissionSelection? Subject { get; }
    /// <summary>Gets returned inversion, or null when omitted rather than defaulting to false.</summary>
    [JsonIgnore] public bool? Inverted { get; }
    /// <summary>Gets whether a conditions node exists without interpreting its unconstrained shape.</summary>
    public bool HasConditions { get; }
    /// <summary>Always false: condition-node values are deliberately not projected.</summary>
    public bool IncludesConditionValues => false;
    /// <summary>Returns a marker without permission metadata.</summary>
    public override string ToString() => "[ProjectTemplatePermissionSummary]";
}

/// <summary>Returned template-role configuration metadata, not an effective-permission decision.</summary>
public sealed class ProjectTemplateRoleSummary
{
    internal ProjectTemplateRoleSummary(JsonElement value)
    {
        Name = ProjectTemplateWire.Required(value, "name", 16384, false);
        Slug = ProjectTemplateWire.Required(value, "slug", 64, false);
        Permissions = Array.AsReadOnly(ManagementJson.Array(value, "permissions")
            .Select(v => new ProjectTemplatePermissionSummary(v)).ToArray());
    }
    /// <summary>Gets the returned role name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the returned native role slug.</summary>
    [JsonIgnore] public string Slug { get; }
    /// <summary>Gets bounded returned permission summaries without condition values.</summary>
    [JsonIgnore] public IReadOnlyList<ProjectTemplatePermissionSummary> Permissions { get; }
    /// <summary>Returns a marker without role configuration.</summary>
    public override string ToString() => "[ProjectTemplateRoleSummary]";
}

internal static class ProjectTemplateWire
{
    internal static void Text(string value, int maximum = 16384) => RolePermissionWire.Text(value, maximum);
    internal static T[] Copy<T>(IReadOnlyList<T> values) where T : class
    {
        ArgumentNullException.ThrowIfNull(values);
        T[] copy = values.Take(1001).ToArray();
        if (copy.Length > 1000 || copy.Any(v => v is null))
            throw new ArgumentException("Invalid project template collection.");
        return copy;
    }
    internal static string[] RoleNames(IReadOnlyList<string> roles)
    {
        string[] copy = Copy(roles);
        if (copy.Length == 0) throw new ArgumentException("At least one template principal role is required.");
        foreach (string role in copy) Text(role);
        return copy;
    }
    internal static void Principal(Utf8JsonWriter writer, string field, string value, IReadOnlyList<string> roles)
    {
        writer.WriteStartObject();
        writer.WriteString(field, value);
        Array(writer, "roles", roles, (w, v) => w.WriteStringValue(v));
        writer.WriteEndObject();
    }
    internal static void Array<T>(Utf8JsonWriter writer, string field, IReadOnlyList<T> values, Action<Utf8JsonWriter, T> write)
    {
        writer.WriteStartArray(field);
        foreach (var value in values) write(writer, value);
        writer.WriteEndArray();
    }
    internal static void Collection<T>(Utf8JsonWriter writer, string field, ProjectTemplateCollection<T>? values,
        Action<Utf8JsonWriter, T> write) where T : class
    {
        if (values is null) return;
        if (values.Values is null) writer.WriteNull(field);
        else Array(writer, field, values.Values, write);
    }
    internal static IReadOnlyList<T>? ParseCollection<T>(JsonElement value, string field, Func<JsonElement, T> parse)
    {
        if (!value.TryGetProperty(field, out var array))
            throw new ManagementContractException(SecretStatus.Unknown);
        return array.ValueKind == JsonValueKind.Null ? null :
            System.Array.AsReadOnly(ManagementJson.Array(array).Select(parse).ToArray());
    }
    internal static string String(JsonElement value, int maximum = 16384, bool allowEmpty = true)
    {
        if (value.ValueKind != JsonValueKind.String)
            throw new ManagementContractException(SecretStatus.Unknown);
        string result = value.GetString()!;
        if (result.Length > maximum || (!allowEmpty && result.Length == 0))
            throw new ManagementContractException(SecretStatus.Unknown);
        return result;
    }
    internal static string Required(JsonElement value, string field, int maximum = 16384, bool allowEmpty = true)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(field, out var child))
            throw new ManagementContractException(SecretStatus.Unknown);
        return String(child, maximum, allowEmpty);
    }
    internal static IReadOnlyList<string> Strings(JsonElement value, string field) =>
        System.Array.AsReadOnly(ManagementJson.Array(value, field).Select(v => String(v)).ToArray());
    internal static ManagementTarget Intent(string organizationId, string resourceId, Action<Utf8JsonWriter> write)
    {
        byte[] storage = new byte[64 * 1024];
        try
        {
            using var stream = new MemoryStream(storage, writable: true);
            using (var writer = new Utf8JsonWriter(stream)) write(writer);
            return new(organizationId, resourceId: resourceId,
                secondaryId: Convert.ToHexString(SHA256.HashData(storage.AsSpan(0, (int)stream.Position))));
        }
        catch (NotSupportedException) { throw new ArgumentException("The project template input exceeds its byte budget."); }
        finally { System.Array.Clear(storage); }
    }
}
