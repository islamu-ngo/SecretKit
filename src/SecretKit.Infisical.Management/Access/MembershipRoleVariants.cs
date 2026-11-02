using System.Security.Cryptography;
using System.Text.Json;

namespace SecretKit.Infisical.Management;

/// <summary>Copied native role fields. Null omits; an empty array is explicit.
/// Scalar and array fields may coexist only on membership creation endpoints.</summary>
public sealed class MembershipRoleSelection
{
    private readonly string? _role;
    private readonly MembershipRole[]? _roles;

    /// <summary>Copies native scalar and array role selections; null omits, while an empty array remains explicit.</summary>
    public MembershipRoleSelection(string? role = null, IReadOnlyList<MembershipRole>? roles = null)
    {
        if (role is not null) ManagementJson.Text(role, 255);
        _role = role;
        _roles = roles is null ? null : MembershipRole.Copy(roles, allowEmpty: true);
    }

    internal void Validate(bool scalarAllowed, bool omissionAllowed, bool emptyAllowed)
    {
        if (!scalarAllowed && _role is not null || !omissionAllowed && _roles is null ||
            !emptyAllowed && _roles is { Length: 0 })
            throw new ArgumentException("The role selection is not admitted by this endpoint.");
    }

    internal void Write(Utf8JsonWriter writer)
    {
        if (_role is not null) writer.WriteString("role", _role);
        if (_roles is not null) MembershipRole.Write(writer, _roles);
    }

    internal void WriteObject(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        Write(writer);
        writer.WriteEndObject();
    }

    /// <summary>Returns a marker without role assignments.</summary>
    public override string ToString() => "[MembershipRoleSelection]";
}

internal static class MembershipRoleWire
{
    internal static ManagementTarget Intent(string organizationId, string? projectId, string resourceId,
        Action<Utf8JsonWriter> write, string? expectedMembershipId = null)
    {
        byte[] storage = new byte[64 * 1024];
        try
        {
            using var stream = new MemoryStream(storage, writable: true);
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartArray();
                writer.WriteStringValue(expectedMembershipId);
                write(writer);
                writer.WriteEndArray();
            }
            return new(organizationId, projectId, resourceId,
                Convert.ToHexString(SHA256.HashData(storage.AsSpan(0, (int)stream.Position))));
        }
        catch (NotSupportedException)
        {
            throw new ArgumentException("The role input exceeds its byte budget.");
        }
        finally { Array.Clear(storage); }
    }
}
