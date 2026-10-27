using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Native project product discriminators; selection does not establish product entitlement.</summary>
public enum ProjectType
{
    /// <summary>Secret-management project.</summary>
    SecretManager,
    /// <summary>Certificate-management project.</summary>
    CertificateManager,
    /// <summary>Key-management project.</summary>
    Kms,
    /// <summary>Secret-scanning project.</summary>
    SecretScanning,
    /// <summary>Privileged-access-management project.</summary>
    Pam,
    /// <summary>Agent Vault project.</summary>
    AgentVault
}

/// <summary>Returned field presence, including explicit null. Values never participate in implicit serialization.</summary>
public readonly struct ProjectField<T> where T : notnull
{
    private readonly T? _value;
    private ProjectField(T? value, bool isNull)
    {
        _value = value;
        IsPresent = true;
        IsNull = isNull;
    }
    /// <summary>Gets whether the response included this field; false differs from explicit null.</summary>
    public bool IsPresent { get; }
    /// <summary>Gets whether the included field was explicitly null.</summary>
    public bool IsNull { get; }
    /// <summary>Gets the returned value; throws for absence or explicit null.</summary>
    [JsonIgnore]
    public T Value => IsPresent && !IsNull
        ? _value! : throw new InvalidOperationException("The project field has no value.");
    internal static ProjectField<T> Present(T value) => new(value, false);
    internal static ProjectField<T> Null() => new(default, true);
    /// <summary>Returns a marker without exporting the field value.</summary>
    public override string ToString() => "[ProjectField]";
}

/// <summary>Project-embedded environment coordinates, not the richer environment endpoint schema.</summary>
public sealed class ProjectEnvironmentReference
{
    internal ProjectEnvironmentReference(JsonElement value)
    {
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Required(value, "name");
        Slug = ManagementJson.Required(value, "slug");
    }
    /// <summary>Gets the returned embedded environment identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned embedded environment name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the native environment slug.</summary>
    [JsonIgnore] public string Slug { get; }
    /// <summary>Returns a marker without environment coordinates.</summary>
    public override string ToString() => "[ProjectEnvironmentReference]";
}

/// <summary>Known actor kinds returned for soft-deleted environments.</summary>
public enum ProjectDeletedByType { /** <summary>A user performed the deletion.</summary> */ User, /** <summary>A machine identity performed the deletion.</summary> */ Identity }

/// <summary>Returned deletion actor metadata; optional fields depend on the native actor kind.</summary>
public sealed class ProjectDeletedBy
{
    internal ProjectDeletedBy(JsonElement value)
    {
        Type = ManagementJson.Required(value, "type") switch
        {
            "user" => ProjectDeletedByType.User,
            "identity" => ProjectDeletedByType.Identity,
            _ => throw new ManagementContractException(SecretStatus.Unknown)
        };
        Id = ManagementJson.Required(value, "id");
        if (Type == ProjectDeletedByType.Identity) Name = ManagementJson.Required(value, "name");
        else
        {
            Email = ProjectWire.RequiredNullableString(value, "email");
            Username = ProjectWire.RequiredNullableString(value, "username");
            FirstName = ProjectWire.RequiredNullableString(value, "firstName");
            LastName = ProjectWire.RequiredNullableString(value, "lastName");
        }
    }
    /// <summary>Gets the returned actor kind.</summary>
    public ProjectDeletedByType Type { get; }
    /// <summary>Gets the returned actor identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets machine-identity name; user actors leave this null.</summary>
    [JsonIgnore] public string? Name { get; }
    /// <summary>Gets user email, or null for a null user field or a machine identity.</summary>
    [JsonIgnore] public string? Email { get; }
    /// <summary>Gets username, or null for a null user field or a machine identity.</summary>
    [JsonIgnore] public string? Username { get; }
    /// <summary>Gets given name, or null for a null user field or a machine identity.</summary>
    [JsonIgnore] public string? FirstName { get; }
    /// <summary>Gets family name, or null for a null user field or a machine identity.</summary>
    [JsonIgnore] public string? LastName { get; }
    /// <summary>Returns a marker without deletion-actor details.</summary>
    public override string ToString() => "[ProjectDeletedBy]";
}

/// <summary>Returned soft-deleted environment metadata, not a deletion command or recovery guarantee.</summary>
public sealed class DeletedProjectEnvironment
{
    internal DeletedProjectEnvironment(JsonElement value)
    {
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Required(value, "name");
        Slug = ManagementJson.Required(value, "slug");
        DeleteAfter = ManagementJson.Required(value, "deleteAfter");
        SoftDeletedAt = ManagementJson.Required(value, "softDeletedAt");
        if (!value.TryGetProperty("deletedBy", out var actor))
            throw new ManagementContractException(SecretStatus.Unknown);
        if (actor.ValueKind != JsonValueKind.Null) DeletedBy = new(actor);
    }
    /// <summary>Gets the returned environment identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned environment name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the native environment slug.</summary>
    [JsonIgnore] public string Slug { get; }
    /// <summary>Gets the provider-reported scheduled deletion timestamp.</summary>
    [JsonIgnore] public string DeleteAfter { get; }
    /// <summary>Gets the reported soft-deletion timestamp.</summary>
    [JsonIgnore] public string SoftDeletedAt { get; }
    /// <summary>Gets the returned deletion actor, or null when the provider explicitly returns no actor.</summary>
    [JsonIgnore] public ProjectDeletedBy? DeletedBy { get; }
    /// <summary>Returns a marker without deletion metadata.</summary>
    public override string ToString() => "[DeletedProjectEnvironment]";
}

/// <summary>List-embedded role metadata. The published permissions node has no established value schema.</summary>
public sealed class ProjectRoleMetadata
{
    internal ProjectRoleMetadata(JsonElement value, string projectId)
    {
        ManagementJson.RequireEqual(value, "projectId", projectId);
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Required(value, "name");
        Slug = ManagementJson.Required(value, "slug");
        Description = ProjectWire.StringField(value, "description", nullable: true);
        CreatedAt = ManagementJson.Required(value, "createdAt");
        UpdatedAt = ManagementJson.Required(value, "updatedAt");
        Version = ProjectWire.NumberField(value, "version");
        HasPermissions = value.TryGetProperty("permissions", out var permissions);
        PermissionsIsNull = HasPermissions && permissions.ValueKind == JsonValueKind.Null;
    }
    /// <summary>Gets the returned embedded role identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned role name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the native role slug.</summary>
    [JsonIgnore] public string Slug { get; }
    /// <summary>Gets description presence, preserving omission and explicit null.</summary>
    [JsonIgnore] public ProjectField<string> Description { get; }
    /// <summary>Gets the returned creation timestamp.</summary>
    [JsonIgnore] public string CreatedAt { get; }
    /// <summary>Gets the returned update timestamp.</summary>
    [JsonIgnore] public string UpdatedAt { get; }
    /// <summary>Gets returned version presence without inferring an omitted version.</summary>
    [JsonIgnore] public ProjectField<double> Version { get; }
    /// <summary>Gets whether a permissions node was returned, not whether permissions are effective.</summary>
    public bool HasPermissions { get; }
    /// <summary>Gets whether the returned permissions node was explicitly null.</summary>
    public bool PermissionsIsNull { get; }
    /// <summary>Always false: embedded permission-node values are deliberately not exported.</summary>
    public bool IncludesPermissionValues => false;
    /// <summary>Returns a marker without role metadata.</summary>
    public override string ToString() => "[ProjectRoleMetadata]";
}

internal static class ProjectWire
{
    internal static string TypeName(ProjectType type) => type switch
    {
        ProjectType.SecretManager => "secret-manager",
        ProjectType.CertificateManager => "cert-manager",
        ProjectType.Kms => "kms",
        ProjectType.SecretScanning => "secret-scanning",
        ProjectType.Pam => "pam",
        ProjectType.AgentVault => "agent-vault",
        _ => throw new ArgumentOutOfRangeException(nameof(type))
    };

    internal static ProjectField<T> Field<T>(JsonElement value, string field, Func<JsonElement, T> parse,
        bool nullable = false) where T : notnull
    {
        if (value.ValueKind != JsonValueKind.Object)
            throw new ManagementContractException(SecretStatus.Unknown);
        if (!value.TryGetProperty(field, out var child)) return default;
        if (child.ValueKind != JsonValueKind.Null) return ProjectField<T>.Present(parse(child));
        if (nullable) return ProjectField<T>.Null();
        throw new ManagementContractException(SecretStatus.Unknown);
    }
    internal static ProjectField<string> StringField(JsonElement value, string field, bool nullable = false) =>
        Field(value, field, String, nullable);
    internal static ProjectField<double> NumberField(JsonElement value, string field, bool nullable = false) =>
        Field(value, field, Number, nullable);
    internal static ProjectField<bool> BooleanField(JsonElement value, string field, bool nullable = false) =>
        Field(value, field, child => child.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? child.GetBoolean() : throw new ManagementContractException(SecretStatus.Unknown), nullable);
    internal static string String(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.String || value.GetString()!.Length > 16384)
            throw new ManagementContractException(SecretStatus.Unknown);
        return value.GetString()!;
    }
    internal static string? RequiredNullableString(JsonElement value, string field)
    {
        var result = StringField(value, field, nullable: true);
        if (!result.IsPresent) throw new ManagementContractException(SecretStatus.Unknown);
        return result.IsNull ? null : result.Value;
    }
    internal static double Number(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetDouble(out double number) || !double.IsFinite(number))
            throw new ManagementContractException(SecretStatus.Unknown);
        return number;
    }
    internal static ProjectField<IReadOnlyList<T>> Collection<T>(JsonElement value, string field,
        Func<JsonElement, T> parse, bool nullable = false) where T : notnull =>
        Field<IReadOnlyList<T>>(value, field,
            child => Array.AsReadOnly(ManagementJson.Array(child).Select(parse).ToArray()), nullable);
    internal static string[]? CopyStrings(IReadOnlyList<string>? values)
    {
        if (values is null) return null;
        string[] copy = values.Take(1001).ToArray();
        if (copy.Length > 1000 || copy.Any(value => value is null || value.Length > 16384))
            throw new ArgumentException("Invalid project string collection.");
        return copy;
    }
    internal static void Position(double? position, bool create)
    {
        if (position is { } number && (!double.IsFinite(number) || (create && number < 1)))
            throw new ArgumentException("Invalid environment position.");
    }
    internal static ManagementTarget Intent(string organizationId, string? projectId, string? resourceId,
        Action<Utf8JsonWriter> write)
    {
        byte[] storage = new byte[64 * 1024];
        try
        {
            using var stream = new MemoryStream(storage, writable: true);
            using (var writer = new Utf8JsonWriter(stream)) write(writer);
            return new(organizationId, projectId, resourceId,
                Convert.ToHexString(SHA256.HashData(storage.AsSpan(0, (int)stream.Position))));
        }
        catch (NotSupportedException) { throw new ArgumentException("The project input exceeds its byte budget."); }
        finally { Array.Clear(storage); }
    }
}
