using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Returned presence, including explicit null; no inferred defaults or implicit value export.</summary>
public readonly struct IdentityField<T> where T : notnull
{
    private readonly T? _value;
    private IdentityField(T? value, bool isNull)
    {
        _value = value;
        IsPresent = true;
        IsNull = isNull;
    }
    public bool IsPresent { get; }
    public bool IsNull { get; }
    [JsonIgnore]
    public T Value => IsPresent && !IsNull
        ? _value! : throw new InvalidOperationException("The identity field has no value.");
    internal static IdentityField<T> Present(T value) => new(value, false);
    internal static IdentityField<T> Null() => new(default, true);
    public override string ToString() => "[IdentityField]";
}

/// <summary>Returned metadata entry, independently copied from the response, not request metadata.</summary>
public sealed class IdentityMetadataEntry
{
    internal IdentityMetadataEntry(JsonElement value, bool nonempty)
    {
        Id = IdentityMetadataWire.RequiredString(value, "id", nonempty);
        Key = IdentityMetadataWire.RequiredString(value, "key", nonempty);
        Value = IdentityMetadataWire.RequiredString(value, "value", nonempty);
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Key { get; }
    [JsonIgnore] public string Value { get; }
    public override string ToString() => "[IdentityMetadataEntry]";
}

/// <summary>Known custom-role metadata. The unspecified permissions node is deliberately unexported.</summary>
public sealed class IdentityCustomRoleMetadata
{
    internal IdentityCustomRoleMetadata(JsonElement value)
    {
        Id = IdentityMetadataWire.RequiredString(value, "id");
        Name = IdentityMetadataWire.RequiredString(value, "name");
        Slug = IdentityMetadataWire.RequiredString(value, "slug");
        Description = IdentityMetadataWire.StringField(value, "description", nullable: true);
        HasPermissions = value.TryGetProperty("permissions", out var permissions);
        PermissionsIsNull = HasPermissions && permissions.ValueKind == JsonValueKind.Null;
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Slug { get; }
    [JsonIgnore] public IdentityField<string> Description { get; }
    public bool HasPermissions { get; }
    public bool PermissionsIsNull { get; }
    public bool IncludesPermissionValues => false;
    public override string ToString() => "[IdentityCustomRoleMetadata]";
}

/// <summary>Outer membership metadata kept separate from the nested identity.</summary>
public sealed class IdentityMembershipMetadata
{
    internal IdentityMembershipMetadata(JsonElement value, string identityId)
    {
        Id = IdentityMetadataWire.RequiredString(value, "id");
        if (value.TryGetProperty("identityId", out _))
            ManagementJson.RequireEqual(value, "identityId", identityId);
        IdentityId = identityId;
        CreatedAt = IdentityField<string>.Present(IdentityMetadataWire.RequiredString(value, "createdAt"));
        UpdatedAt = IdentityField<string>.Present(IdentityMetadataWire.RequiredString(value, "updatedAt"));
        Role = IdentityField<string>.Present(IdentityMetadataWire.RequiredString(value, "role"));
        RoleId = IdentityMetadataWire.StringField(value, "roleId", nullable: true);
        LastLoginAuthMethod = IdentityMetadataWire.StringField(value, "lastLoginAuthMethod", nullable: true);
        LastLoginTime = IdentityMetadataWire.StringField(value, "lastLoginTime", nullable: true);
        CustomRole = IdentityMetadataWire.Field(value, "customRole", child => new IdentityCustomRoleMetadata(child));
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string IdentityId { get; }
    [JsonIgnore] public IdentityField<string> CreatedAt { get; }
    [JsonIgnore] public IdentityField<string> UpdatedAt { get; }
    [JsonIgnore] public IdentityField<string> Role { get; }
    [JsonIgnore] public IdentityField<string> RoleId { get; }
    [JsonIgnore] public IdentityField<string> LastLoginAuthMethod { get; }
    [JsonIgnore] public IdentityField<string> LastLoginTime { get; }
    [JsonIgnore] public IdentityField<IdentityCustomRoleMetadata> CustomRole { get; }
    public bool IncludesPermissions => false;
    public override string ToString() => "[IdentityMembershipMetadata]";
}

internal static class IdentityMetadataWire
{
    internal static IdentityField<T> Field<T>(JsonElement value, string field, Func<JsonElement, T> parse,
        bool nullable = false) where T : notnull
    {
        if (value.ValueKind != JsonValueKind.Object)
            throw new ManagementContractException(SecretStatus.Unknown);
        if (!value.TryGetProperty(field, out var child)) return default;
        if (child.ValueKind != JsonValueKind.Null) return IdentityField<T>.Present(parse(child));
        if (nullable) return IdentityField<T>.Null();
        throw new ManagementContractException(SecretStatus.Unknown);
    }
    internal static IdentityField<string> StringField(JsonElement value, string field, bool nullable = false) =>
        Field(value, field, String, nullable);
    internal static string String(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.String || value.GetString()!.Length > 16384)
            throw new ManagementContractException(SecretStatus.Unknown);
        return value.GetString()!;
    }
    internal static string RequiredString(JsonElement value, string field, bool nonempty = false)
    {
        var result = StringField(value, field);
        if (!result.IsPresent || nonempty && result.Value.Length == 0)
            throw new ManagementContractException(SecretStatus.Unknown);
        return result.Value;
    }
    internal static IdentityField<IReadOnlyList<T>> Collection<T>(JsonElement value, string field,
        Func<JsonElement, T> parse) where T : notnull =>
        Field<IReadOnlyList<T>>(value, field,
            child => Array.AsReadOnly(ManagementJson.Array(child).Select(parse).ToArray()));
}
