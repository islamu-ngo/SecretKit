using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

public enum ProjectType
{
    SecretManager,
    CertificateManager,
    Kms,
    SecretScanning,
    Pam,
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
    public bool IsPresent { get; }
    public bool IsNull { get; }
    [JsonIgnore]
    public T Value => IsPresent && !IsNull
        ? _value! : throw new InvalidOperationException("The project field has no value.");
    internal static ProjectField<T> Present(T value) => new(value, false);
    internal static ProjectField<T> Null() => new(default, true);
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
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Slug { get; }
    public override string ToString() => "[ProjectEnvironmentReference]";
}

public enum ProjectDeletedByType { User, Identity }

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
    public ProjectDeletedByType Type { get; }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string? Name { get; }
    [JsonIgnore] public string? Email { get; }
    [JsonIgnore] public string? Username { get; }
    [JsonIgnore] public string? FirstName { get; }
    [JsonIgnore] public string? LastName { get; }
    public override string ToString() => "[ProjectDeletedBy]";
}

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
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Slug { get; }
    [JsonIgnore] public string DeleteAfter { get; }
    [JsonIgnore] public string SoftDeletedAt { get; }
    [JsonIgnore] public ProjectDeletedBy? DeletedBy { get; }
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
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Slug { get; }
    [JsonIgnore] public ProjectField<string> Description { get; }
    [JsonIgnore] public string CreatedAt { get; }
    [JsonIgnore] public string UpdatedAt { get; }
    [JsonIgnore] public ProjectField<double> Version { get; }
    public bool HasPermissions { get; }
    public bool PermissionsIsNull { get; }
    public bool IncludesPermissionValues => false;
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
