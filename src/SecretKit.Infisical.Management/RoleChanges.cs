using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>A supplied nullable description. A null change argument means absent, not clearing.</summary>
public sealed class RoleDescription
{
    public RoleDescription(string? value)
    {
        if (value is not null) RolePermissionWire.Text(value, 4096, allowEmpty: true);
        Value = value;
    }
    [JsonIgnore] public string? Value { get; }
    public override string ToString() => "[RoleDescription]";
}

public sealed class OrganizationRoleChange
{
    private readonly string? _name;
    private readonly RoleDescription? _description;
    private readonly OrganizationRolePermission[]? _permissions;
    internal string? Slug { get; }
    internal bool CanCreate => _name is { Length: > 0 } && Slug is not null && _permissions is not null;

    public OrganizationRoleChange(string? name = null, string? slug = null,
        RoleDescription? description = null, IReadOnlyList<OrganizationRolePermission>? permissions = null)
    {
        RoleChangeOperations.Fields(name, slug, description, permissions is not null);
        _name = name;
        Slug = slug;
        _description = description;
        _permissions = permissions is null ? null : RoleChangeOperations.Copy(permissions);
    }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        RoleChangeOperations.WriteFields(writer, _name, Slug, _description);
        if (_permissions is not null)
        {
            writer.WriteStartArray("permissions");
            foreach (OrganizationRolePermission permission in _permissions) permission.Write(writer);
            writer.WriteEndArray();
        }
        writer.WriteEndObject();
    }
    public override string ToString() => "[OrganizationRoleChange]";
}

public sealed class ProjectRoleChange
{
    private readonly string? _name;
    private readonly RoleDescription? _description;
    private readonly ProjectRolePermission[]? _permissions;
    internal string? Slug { get; }
    internal bool CanCreate => _name is { Length: > 0 } && Slug is not null && _permissions is not null;

    public ProjectRoleChange(string? name = null, string? slug = null,
        RoleDescription? description = null, IReadOnlyList<ProjectRolePermission>? permissions = null)
    {
        RoleChangeOperations.Fields(name, slug, description, permissions is not null);
        _name = name;
        Slug = slug;
        _description = description;
        _permissions = permissions is null ? null : RoleChangeOperations.Copy(permissions);
    }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        RoleChangeOperations.WriteFields(writer, _name, Slug, _description);
        if (_permissions is not null)
        {
            writer.WriteStartArray("permissions");
            foreach (ProjectRolePermission permission in _permissions) permission.Write(writer);
            writer.WriteEndArray();
        }
        writer.WriteEndObject();
    }
    public override string ToString() => "[ProjectRoleChange]";
}

public static class RoleChangeOperations
{
    public static ManagementRequest<RoleSummary> CreateOrganizationRole(string organizationId, OrganizationRoleChange change)
    {
        ArgumentNullException.ThrowIfNull(change);
        if (!change.CanCreate) throw new ArgumentException("Creation requires name, slug and permissions.");
        return new("infisical.post.v1.organization.roles", HttpMethod.Post, "/api/v1/organization/roles",
            OrganizationCreationTarget(organizationId, change), change.Write,
            root => Response(root, organizationId, null, null, change.Slug));
    }

    public static ManagementRequest<RoleSummary> UpdateOrganizationRole(string organizationId, string roleId,
        OrganizationRoleChange change)
    {
        ArgumentNullException.ThrowIfNull(change);
        return new("infisical.patch.v1.organization.roles.by.roleId", HttpMethod.Patch,
            "/api/v1/organization/roles/" + ManagementJson.Escape(roleId),
            OrganizationUpdateTarget(organizationId, roleId, change), change.Write,
            root => Response(root, organizationId, null, roleId, change.Slug));
    }

    public static ManagementRequest<RoleSummary> CreateProjectRole(string organizationId, string projectId,
        ProjectRoleChange change)
    {
        ArgumentNullException.ThrowIfNull(change);
        if (!change.CanCreate) throw new ArgumentException("Creation requires name, slug and permissions.");
        return new("infisical.post.v1.projects.by.projectId.roles", HttpMethod.Post,
            ProjectOperations.ProjectPath(projectId) + "/roles",
            ProjectCreationTarget(organizationId, projectId, change), change.Write,
            root => Response(root, organizationId, projectId, null, change.Slug));
    }

    public static ManagementRequest<RoleSummary> UpdateProjectRole(string organizationId, string projectId,
        string roleId, ProjectRoleChange change)
    {
        ArgumentNullException.ThrowIfNull(change);
        return new("infisical.patch.v1.projects.by.projectId.roles.by.roleId", HttpMethod.Patch,
            ProjectOperations.ProjectPath(projectId) + "/roles/" + ManagementJson.Escape(roleId),
            ProjectUpdateTarget(organizationId, projectId, roleId, change), change.Write,
            root => Response(root, organizationId, projectId, roleId, change.Slug));
    }

    /// <summary>Host intent from independent scope and changes, never from an incoming request target.</summary>
    public static ManagementTarget OrganizationCreationTarget(string organizationId, OrganizationRoleChange change)
    {
        ArgumentNullException.ThrowIfNull(change);
        if (!change.CanCreate) throw new ArgumentException("Creation requires name, slug and permissions.");
        return Intent(organizationId, null, change.Slug!, change.Write);
    }

    public static ManagementTarget OrganizationUpdateTarget(string organizationId, string roleId,
        OrganizationRoleChange change)
    {
        ArgumentNullException.ThrowIfNull(change);
        return Intent(organizationId, null, roleId, change.Write);
    }

    public static ManagementTarget ProjectCreationTarget(string organizationId, string projectId, ProjectRoleChange change)
    {
        ArgumentNullException.ThrowIfNull(change);
        if (!change.CanCreate) throw new ArgumentException("Creation requires name, slug and permissions.");
        return Intent(organizationId, projectId, change.Slug!, change.Write);
    }

    public static ManagementTarget ProjectUpdateTarget(string organizationId, string projectId, string roleId,
        ProjectRoleChange change)
    {
        ArgumentNullException.ThrowIfNull(change);
        return Intent(organizationId, projectId, roleId, change.Write);
    }

    private static ManagementTarget Intent(string org, string? project, string role, Action<Utf8JsonWriter> write)
    {
        byte[] storage = new byte[64 * 1024];
        try
        {
            using var stream = new MemoryStream(storage, writable: true);
            using (var writer = new Utf8JsonWriter(stream)) write(writer);
            // The bounded canonical wire body binds scalar/array actions, ordering,
            // inversion, every constraint, and absent/null/empty update distinctions.
            string digest = Convert.ToHexString(SHA256.HashData(storage.AsSpan(0, (int)stream.Position)));
            return new(org, project, role, digest);
        }
        catch (NotSupportedException)
        {
            throw new ArgumentException("The role input exceeds its byte budget.");
        }
        finally { Array.Clear(storage); }
    }

    private static RoleSummary Response(JsonElement root, string org, string? project, string? role, string? slug)
    {
        JsonElement value = ManagementJson.Object(root, "role");
        if (project is not null && ManagementJson.Optional(value, "orgId") is { } returnedOrg && returnedOrg != org)
            throw new ManagementContractException(SecretStatus.Invalid);
        _ = ManagementJson.Required(value, "createdAt");
        _ = ManagementJson.Required(value, "updatedAt");
        _ = ManagementJson.Array(value, "permissions");
        return new(value, project is null ? "orgId" : "projectId", project ?? org, role, slug);
    }

    internal static void Fields(string? name, string? slug, RoleDescription? description, bool permissions)
    {
        if (name is null && slug is null && description is null && !permissions)
            throw new ArgumentException("A role change is required.");
        if (name is not null) RolePermissionWire.Text(name, 255, allowEmpty: true);
        if (slug is not null) RolePermissionWire.Text(slug, 64);
    }

    internal static T[] Copy<T>(IReadOnlyList<T> values) where T : class
    {
        T[] copy = values.Take(129).ToArray();
        if (copy.Length > 128 || copy.Any(value => value is null))
            throw new ArgumentException("Invalid role permission budget.");
        return copy;
    }

    internal static void WriteFields(Utf8JsonWriter writer, string? name, string? slug, RoleDescription? description)
    {
        if (name is not null) writer.WriteString("name", name);
        if (slug is not null) writer.WriteString("slug", slug);
        if (description is not null) writer.WriteString("description", description.Value);
    }
}
