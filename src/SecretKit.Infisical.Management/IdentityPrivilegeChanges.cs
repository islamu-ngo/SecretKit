using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace SecretKit.Infisical.Management;

/// <summary>Native scalar actions for v1 privilege authoring, not v2 role actions.</summary>
public enum LegacyPrivilegeAction { /** <summary>Selects value-reading permission.</summary> */ Read, /** <summary>Selects resource-creation permission.</summary> */ Create, /** <summary>Selects resource-editing permission.</summary> */ Edit, /** <summary>Selects resource-deletion permission.</summary> */ Delete }
/// <summary>Native interpretation of temporary privilege validity.</summary>
public enum PrivilegeTemporaryMode { /** <summary>Interprets validity as a duration from the selected start time.</summary> */ Relative }

/// <summary>V1 conditions: literal environment and a secret-path glob only.</summary>
public sealed class LegacyPrivilegeConditions
{
    private readonly string? _environment;
    private readonly string? _path;
    internal bool HasEnvironment => _environment is not null;

    /// <summary>Captures optional environment and path-glob conditions; null omits each condition.</summary>
    public LegacyPrivilegeConditions(string? environment = null, string? secretPathGlob = null)
    {
        if (environment is not null) RolePermissionWire.Text(environment, 1024, allowEmpty: true);
        if (secretPathGlob is not null) RolePermissionWire.Text(secretPathGlob, 1024);
        _environment = environment;
        _path = secretPathGlob;
    }

    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("conditions");
        if (_environment is not null) writer.WriteString("environment", _environment);
        if (_path is not null)
        {
            writer.WriteStartObject("secretPath");
            writer.WriteString("$glob", _path);
            writer.WriteEndObject();
        }
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without environment or path conditions.</summary>
    public override string ToString() => "[LegacyPrivilegeConditions]";
}

/// <summary>V1 scalar CRUD dialect; it is not a project-role permission.</summary>
public sealed class LegacyPrivilegePermission
{
    private readonly string _subject;
    private readonly string _action;
    private readonly LegacyPrivilegeConditions? _conditions;

    /// <summary>Captures a native subject/action pair and optional conditions without granting access.</summary>
    public LegacyPrivilegePermission(ProjectRoleSubject subject, LegacyPrivilegeAction action,
        LegacyPrivilegeConditions? conditions = null)
    {
        _subject = RolePermissionWire.Name(subject);
        _action = RolePermissionWire.Name(action);
        _conditions = conditions;
    }

    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        writer.WriteString("subject", _subject);
        writer.WriteString("action", _action);
        _conditions?.Write(writer);
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without permission conditions.</summary>
    public override string ToString() => "[LegacyPrivilegePermission]";
}

/// <summary>Native v1 privilegePermission alternative: secrets, CRUD actions and required environment.</summary>
public sealed class LegacySecretPrivilegePermission
{
    private readonly string[] _actions;
    private readonly LegacyPrivilegeConditions _conditions;

    /// <summary>Copies selected secret CRUD actions and requires an explicit environment condition.</summary>
    public LegacySecretPrivilegePermission(IReadOnlyList<LegacyPrivilegeAction> actions,
        LegacyPrivilegeConditions conditions)
    {
        ArgumentNullException.ThrowIfNull(conditions);
        if (!conditions.HasEnvironment) throw new ArgumentException("An environment condition is required.");
        _actions = RolePermissionWire.Actions(actions, "read create edit delete");
        _conditions = conditions;
    }

    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("privilegePermission");
        writer.WriteString("subject", "secrets");
        RolePermissionWire.Strings(writer, "actions", _actions);
        _conditions.Write(writer);
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without secret permission selectors.</summary>
    public override string ToString() => "[LegacySecretPrivilegePermission]";
}

/// <summary>Explicit native relative access. The SDK accepts positive minute, hour or day ranges.</summary>
public sealed class PrivilegeLifetime
{
    private readonly string? _range;
    private readonly DateTimeOffset? _start;
    internal bool IsTemporary => _range is not null;
    private PrivilegeLifetime(string? range, DateTimeOffset? start) { _range = range; _start = start; }
    /// <summary>Selects permanent validity without temporary timestamps or duration.</summary>
    public static PrivilegeLifetime Permanent() => new(null, null);
    /// <summary>Selects positive minute, hour or day validity from an explicit start time.</summary>
    public static PrivilegeLifetime Temporary(string range, DateTimeOffset startsAt)
    {
        IdentityPrivilegeChangeOperations.Range(range);
        return new(range, startsAt);
    }
    internal void Write(Utf8JsonWriter writer, bool includeDiscriminator)
    {
        if (includeDiscriminator) writer.WriteBoolean("isTemporary", IsTemporary);
        if (_range is not null)
        {
            writer.WriteString("temporaryMode", "relative");
            writer.WriteString("temporaryRange", _range);
            writer.WriteString("temporaryAccessStartTime", _start!.Value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
        }
    }
    /// <summary>Returns a marker without validity details.</summary>
    public override string ToString() => "[PrivilegeLifetime]";
}

/// <summary>V1 optional fields. Null arguments omit fields; native inputs do not accept explicit null.</summary>
public sealed class LegacyPrivilegeChange
{
    private readonly LegacyPrivilegePermission[]? _permissions;
    private readonly LegacySecretPrivilegePermission? _permission;
    private readonly bool? _temporary;
    private readonly PrivilegeTemporaryMode? _mode;
    private readonly string? _range;
    private readonly DateTimeOffset? _start;
    internal string? Slug { get; }
    internal bool HasTemporalFields => _temporary is not null || _mode is not null || _range is not null || _start is not null;

    /// <summary>Captures optional v1 change fields; creation validity belongs to the separate lifetime selection.</summary>
    public LegacyPrivilegeChange(string? slug = null, IReadOnlyList<LegacyPrivilegePermission>? permissions = null,
        LegacySecretPrivilegePermission? privilegePermission = null, bool? isTemporary = null,
        PrivilegeTemporaryMode? temporaryMode = null, string? temporaryRange = null,
        DateTimeOffset? temporaryAccessStartTime = null)
    {
        if (slug is not null) ManagementJson.Text(slug, 60);
        if (temporaryMode is { } mode && !Enum.IsDefined(mode)) throw new ArgumentOutOfRangeException(nameof(temporaryMode));
        if (temporaryRange is not null) IdentityPrivilegeChangeOperations.Range(temporaryRange);
        if (isTemporary == true && (temporaryMode is null || temporaryRange is null || temporaryAccessStartTime is null))
            throw new ArgumentException("Temporary access requires mode, range and start time.");
        if (isTemporary == false && (temporaryMode is not null || temporaryRange is not null || temporaryAccessStartTime is not null))
            throw new ArgumentException("Permanent access cannot include temporary validity.");
        Slug = slug;
        _permissions = permissions is null ? null : RoleChangeOperations.Copy(permissions);
        _permission = privilegePermission;
        _temporary = isTemporary;
        _mode = temporaryMode;
        _range = temporaryRange;
        _start = temporaryAccessStartTime;
    }

    internal void WriteFields(Utf8JsonWriter writer)
    {
        if (Slug is not null) writer.WriteString("slug", Slug);
        if (_permissions is not null)
        {
            writer.WriteStartArray("permissions");
            foreach (var permission in _permissions) permission.Write(writer);
            writer.WriteEndArray();
        }
        _permission?.Write(writer);
        if (_temporary is { } temporary) writer.WriteBoolean("isTemporary", temporary);
        if (_mode is not null) writer.WriteString("temporaryMode", "relative");
        if (_range is not null) writer.WriteString("temporaryRange", _range);
        if (_start is { } start) writer.WriteString("temporaryAccessStartTime", start.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
    }
    /// <summary>Returns a marker without privilege changes.</summary>
    public override string ToString() => "[LegacyPrivilegeChange]";
}

/// <summary>Copied v2 project permissions and explicit lifetime for a privilege change.</summary>
public sealed class ProjectPrivilegeChange
{
    private readonly ProjectRolePermission[] _permissions;
    private readonly PrivilegeLifetime _lifetime;
    internal string? Slug { get; }

    /// <summary>Copies permission intent and required lifetime; null slug omits the slug field.</summary>
    public ProjectPrivilegeChange(IReadOnlyList<ProjectRolePermission> permissions, PrivilegeLifetime lifetime,
        string? slug = null)
    {
        ArgumentNullException.ThrowIfNull(permissions);
        ArgumentNullException.ThrowIfNull(lifetime);
        if (slug is not null) ManagementJson.Text(slug, 60);
        _permissions = RoleChangeOperations.Copy(permissions);
        _lifetime = lifetime;
        Slug = slug;
    }
    internal void WriteFields(Utf8JsonWriter writer)
    {
        if (Slug is not null) writer.WriteString("slug", Slug);
        writer.WriteStartArray("permissions");
        foreach (var permission in _permissions) permission.Write(writer);
        writer.WriteEndArray();
        writer.WriteStartObject("type");
        _lifetime.Write(writer, true);
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without permissions or validity.</summary>
    public override string ToString() => "[ProjectPrivilegeChange]";
}

/// <summary>
/// Native privilege authoring and inspection. Host selection binds canonical scope,
/// native slug and exact change intent; responses never attest effective permissions.
/// </summary>
public static class IdentityPrivilegeChangeOperations
{
    /// <summary>Builds a v1 update request for the selected slug and exact change body.</summary>
    public static ManagementRequest<IdentityPrivilegeSummary> UpdateLegacyPrivilege(
        LegacyPrivilegeSelection selection, string privilegeSlug, LegacyPrivilegeChange change) =>
        Legacy(selection, change, privilegeSlug, null);

    /// <summary>Builds permanent v1 creation; temporal change fields cannot override the selected lifetime.</summary>
    public static ManagementRequest<IdentityPrivilegeSummary> CreatePermanentLegacyPrivilege(
        LegacyPrivilegeSelection selection, LegacyPrivilegeChange change) =>
        Legacy(selection, change, null, PrivilegeLifetime.Permanent());

    /// <summary>Builds temporary v1 creation with an explicitly temporary lifetime.</summary>
    public static ManagementRequest<IdentityPrivilegeSummary> CreateTemporaryLegacyPrivilege(
        LegacyPrivilegeSelection selection, LegacyPrivilegeChange change, PrivilegeLifetime lifetime)
    {
        ArgumentNullException.ThrowIfNull(lifetime);
        if (!lifetime.IsTemporary) throw new ArgumentException("Temporary creation requires temporary validity.");
        return Legacy(selection, change, null, lifetime);
    }

    /// <summary>Builds v2 privilege creation with exact copied permissions and lifetime.</summary>
    public static ManagementRequest<IdentityPrivilegeSummary> CreateProjectPrivilege(
        LegacyPrivilegeSelection selection, ProjectPrivilegeChange change) => Project(selection, change, null);

    /// <summary>Builds v2 privilege update; the replacement slug must be explicit in the change.</summary>
    public static ManagementRequest<IdentityPrivilegeSummary> UpdateProjectPrivilege(
        LegacyPrivilegeSelection selection, string privilegeId, ProjectPrivilegeChange change)
    {
        ManagementJson.Text(privilegeId);
        ArgumentNullException.ThrowIfNull(change);
        if (change.Slug is null) throw new ArgumentException("Update requires a privilege slug.");
        return Project(selection, change, privilegeId);
    }

    /// <summary>Builds a v2 lookup by native privilege slug without inventing missing scope evidence.</summary>
    public static ManagementRequest<IdentityPrivilegeSummary> GetProjectPrivilegeBySlug(
        LegacyPrivilegeSelection selection, string privilegeSlug)
    {
        ArgumentNullException.ThrowIfNull(selection);
        return new("infisical.get.v2.identity.project.additional.privilege.slug.by.privilegeSlug", HttpMethod.Get,
            "/api/v2/identity-project-additional-privilege/slug/" + ManagementJson.Escape(privilegeSlug) +
            "?identityId=" + ManagementJson.Escape(selection.IdentityId) +
            "&projectSlug=" + ManagementJson.Escape(selection.ProjectSlug),
            selection.GrantTarget(privilegeSlug), null, root => Response(root, selection, false, null, privilegeSlug), false);
    }

    /// <summary>Construct only from independent host selection and approved changes, not a request's Target.</summary>
    public static ManagementTarget LegacyChangeTarget(LegacyPrivilegeSelection selection, LegacyPrivilegeChange change,
        string? privilegeSlug = null, PrivilegeLifetime? creationLifetime = null)
    {
        ValidateLegacy(selection, change, privilegeSlug, creationLifetime);
        return Intent(selection, privilegeSlug, writer => WriteLegacy(writer, selection, change, privilegeSlug, creationLifetime));
    }

    /// <summary>Builds independent host approval intent for v2 creation or update; null identifier selects creation.</summary>
    public static ManagementTarget ProjectChangeTarget(LegacyPrivilegeSelection selection, ProjectPrivilegeChange change,
        string? privilegeId = null)
    {
        ArgumentNullException.ThrowIfNull(selection);
        ArgumentNullException.ThrowIfNull(change);
        if (privilegeId is not null)
        {
            ManagementJson.Text(privilegeId);
            if (change.Slug is null) throw new ArgumentException("Update requires a privilege slug.");
        }
        return Intent(selection, privilegeId, writer => WriteProject(writer, selection, change, privilegeId is null));
    }

    private static ManagementRequest<IdentityPrivilegeSummary> Legacy(LegacyPrivilegeSelection selection,
        LegacyPrivilegeChange change, string? slug, PrivilegeLifetime? lifetime)
    {
        ManagementTarget target = LegacyChangeTarget(selection, change, slug, lifetime);
        string operation = slug is not null ? "infisical.patch.v1.additional.privilege.identity" :
            lifetime!.IsTemporary ? "infisical.post.v1.additional.privilege.identity.temporary" :
            "infisical.post.v1.additional.privilege.identity.permanent";
        string path = "/api/v1/additional-privilege/identity" +
            (slug is not null ? "" : lifetime!.IsTemporary ? "/temporary" : "/permanent");
        return new(operation, slug is not null ? HttpMethod.Patch : HttpMethod.Post, path, target,
            writer => WriteLegacy(writer, selection, change, slug, lifetime),
            root => Response(root, selection, true, null, change.Slug ?? slug));
    }

    private static ManagementRequest<IdentityPrivilegeSummary> Project(LegacyPrivilegeSelection selection,
        ProjectPrivilegeChange change, string? id) =>
        new(id is null ? "infisical.post.v2.identity.project.additional.privilege" :
                "infisical.patch.v2.identity.project.additional.privilege.by.id",
            id is null ? HttpMethod.Post : HttpMethod.Patch,
            "/api/v2/identity-project-additional-privilege" + (id is null ? "" : "/" + ManagementJson.Escape(id)),
            ProjectChangeTarget(selection, change, id), writer => WriteProject(writer, selection, change, id is null),
            root => Response(root, selection, false, id, change.Slug));

    private static void ValidateLegacy(LegacyPrivilegeSelection selection, LegacyPrivilegeChange change,
        string? slug, PrivilegeLifetime? lifetime)
    {
        ArgumentNullException.ThrowIfNull(selection);
        ArgumentNullException.ThrowIfNull(change);
        if (slug is not null) ManagementJson.Text(slug);
        if ((slug is null) == (lifetime is null)) throw new ArgumentException("Select an update or creation intent.");
        if (lifetime is not null && change.HasTemporalFields)
            throw new ArgumentException("Creation validity belongs to the selected lifetime.");
    }

    private static void WriteLegacy(Utf8JsonWriter writer, LegacyPrivilegeSelection selection,
        LegacyPrivilegeChange change, string? slug, PrivilegeLifetime? lifetime)
    {
        writer.WriteStartObject();
        writer.WriteString("identityId", selection.IdentityId);
        writer.WriteString("projectSlug", selection.ProjectSlug);
        if (slug is not null)
        {
            writer.WriteString("privilegeSlug", slug);
            writer.WriteStartObject("privilegeDetails");
        }
        change.WriteFields(writer);
        lifetime?.Write(writer, false);
        if (slug is not null) writer.WriteEndObject();
        writer.WriteEndObject();
    }

    private static void WriteProject(Utf8JsonWriter writer, LegacyPrivilegeSelection selection,
        ProjectPrivilegeChange change, bool create)
    {
        writer.WriteStartObject();
        if (create)
        {
            writer.WriteString("identityId", selection.IdentityId);
            writer.WriteString("projectId", selection.ProjectId);
        }
        change.WriteFields(writer);
        writer.WriteEndObject();
    }

    private static ManagementTarget Intent(LegacyPrivilegeSelection selection, string? resource,
        Action<Utf8JsonWriter> write)
    {
        byte[] storage = new byte[64 * 1024];
        try
        {
            using var stream = new MemoryStream(storage, writable: true);
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartArray();
                writer.WriteStringValue(selection.ProjectSlug);
                writer.WriteStringValue(selection.MembershipId);
                writer.WriteStringValue(resource);
                write(writer);
                writer.WriteEndArray();
            }
            return new(selection.OrganizationId, selection.ProjectId, selection.IdentityId,
                Convert.ToHexString(SHA256.HashData(storage.AsSpan(0, (int)stream.Position))));
        }
        catch (NotSupportedException) { throw new ArgumentException("The privilege input exceeds its byte budget."); }
        finally { Array.Clear(storage); }
    }

    private static IdentityPrivilegeSummary Response(JsonElement root, LegacyPrivilegeSelection selection,
        bool legacy, string? id, string? slug)
    {
        JsonElement value = ManagementJson.Object(root, "privilege");
        if (legacy) ManagementJson.RequireEqual(value, "projectMembershipId", selection.MembershipId);
        if (slug is not null) ManagementJson.RequireEqual(value, "slug", slug);
        ManagementJson.Required(value, "createdAt");
        ManagementJson.Required(value, "updatedAt");
        ManagementJson.Array(value, "permissions");
        // V2 does not supply project, identity or membership: do not manufacture scope attestation.
        return new(value, id);
    }

    internal static void Range(string range)
    {
        RolePermissionWire.Text(range, 32);
        if (range.Length < 2 || range[0] is < '1' or > '9' || range[^1] is not ('m' or 'h' or 'd') ||
            range.AsSpan(0, range.Length - 1).ContainsAnyExceptInRange('0', '9') ||
            !ulong.TryParse(range.AsSpan(0, range.Length - 1), NumberStyles.None, CultureInfo.InvariantCulture, out _))
            throw new ArgumentException("A positive minute, hour or day range is required.");
    }
}
