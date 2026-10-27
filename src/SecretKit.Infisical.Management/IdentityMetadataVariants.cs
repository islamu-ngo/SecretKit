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
    /// <summary>Gets whether the response included this field; false differs from explicit null.</summary>
    public bool IsPresent { get; }
    /// <summary>Gets whether a present field was explicitly null.</summary>
    public bool IsNull { get; }
    /// <summary>Gets the returned value; throws when absent or explicitly null.</summary>
    [JsonIgnore]
    public T Value => IsPresent && !IsNull
        ? _value! : throw new InvalidOperationException("The identity field has no value.");
    internal static IdentityField<T> Present(T value) => new(value, false);
    internal static IdentityField<T> Null() => new(default, true);
    /// <summary>Returns a marker without exporting the field value.</summary>
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
    /// <summary>Gets the returned metadata-entry identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned metadata key.</summary>
    [JsonIgnore] public string Key { get; }
    /// <summary>Gets the returned metadata value; do not include it in logs.</summary>
    [JsonIgnore] public string Value { get; }
    /// <summary>Returns a marker without metadata contents.</summary>
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
    /// <summary>Gets the custom-role identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned role display name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the native custom-role slug.</summary>
    [JsonIgnore] public string Slug { get; }
    /// <summary>Gets description presence, preserving omitted and explicitly null descriptions.</summary>
    [JsonIgnore] public IdentityField<string> Description { get; }
    /// <summary>Gets whether a permissions node was returned, not whether permissions are effective.</summary>
    public bool HasPermissions { get; }
    /// <summary>Gets whether the returned permissions node was explicitly null.</summary>
    public bool PermissionsIsNull { get; }
    /// <summary>Always false: permission-node values are deliberately not projected.</summary>
    public bool IncludesPermissionValues => false;
    /// <summary>Returns a marker without role metadata.</summary>
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
    /// <summary>Gets the outer membership identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the identity coordinate bound to this membership.</summary>
    [JsonIgnore] public string IdentityId { get; }
    /// <summary>Gets the returned membership creation timestamp with presence information.</summary>
    [JsonIgnore] public IdentityField<string> CreatedAt { get; }
    /// <summary>Gets the returned membership update timestamp with presence information.</summary>
    [JsonIgnore] public IdentityField<string> UpdatedAt { get; }
    /// <summary>Gets the returned membership role label, not an effective-access decision.</summary>
    [JsonIgnore] public IdentityField<string> Role { get; }
    /// <summary>Gets role-identifier presence, including explicit null.</summary>
    [JsonIgnore] public IdentityField<string> RoleId { get; }
    /// <summary>Gets last-login method presence; omission is not evidence of no login.</summary>
    [JsonIgnore] public IdentityField<string> LastLoginAuthMethod { get; }
    /// <summary>Gets last-login time presence, including explicit null.</summary>
    [JsonIgnore] public IdentityField<string> LastLoginTime { get; }
    /// <summary>Gets custom-role metadata when returned; absence is retained.</summary>
    [JsonIgnore] public IdentityField<IdentityCustomRoleMetadata> CustomRole { get; }
    /// <summary>Always false: this metadata does not export effective permissions.</summary>
    public bool IncludesPermissions => false;
    /// <summary>Returns a marker without membership or identity coordinates.</summary>
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
