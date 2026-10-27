using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Gateway configuration and enrollment only; no agent deployment or authentication effects.</summary>
public static class GatewayAdministrationOperations
{
    // Original registry wire-facts-0983 through 0987; request and success unions are independent.
    private const string Path = "/api/v3/gateways";

    /// <summary>Builds disposable gateway configuration creation; does not deploy or authenticate an agent.</summary>
    public static ManagementRequest<GatewaySummary> Create(string organizationId, GatewayCreation creation)
    {
        ArgumentNullException.ThrowIfNull(creation);
        return new("infisical.post.v3.gateways", HttpMethod.Post, Path,
            CreationTarget(organizationId, creation), creation.Write,
            root => new(root, name: creation.Name));
    }

    /// <summary>Builds independently approved gateway name and complete authentication-body intent.</summary>
    public static ManagementTarget CreationTarget(string organizationId, GatewayCreation creation)
    {
        ArgumentNullException.ThrowIfNull(creation);
        return GatewayJson.BodyTarget(organizationId, null, creation.Name, creation.Write);
    }

    /// <summary>Builds lookup of one exact gateway UUID without performing agent health checks.</summary>
    public static ManagementRequest<GatewaySummary> Get(string organizationId, string gatewayId) =>
        new("infisical.get.v3.gateways.by.gatewayId", HttpMethod.Get, GatewayPath(gatewayId),
            new(organizationId, resourceId: gatewayId), null, root => new(root, gatewayId), false);

    /// <summary>Known PATCH inputs/results, not a merge, clearing or persistence guarantee.</summary>
    public static ManagementRequest<GatewaySummary> Update(string organizationId, string gatewayId, GatewayUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        return new("infisical.patch.v3.gateways.by.gatewayId", HttpMethod.Patch, GatewayPath(gatewayId),
            UpdateTarget(organizationId, gatewayId, update), update.Write, root => new(root, gatewayId));
    }

    /// <summary>Builds independent approval intent for the exact gateway and complete patch body.</summary>
    public static ManagementTarget UpdateTarget(string organizationId, string gatewayId, GatewayUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        GatewayJson.UuidInput(gatewayId);
        return GatewayJson.BodyTarget(organizationId, null, gatewayId, update.Write);
    }

    /// <summary>Builds receipt-bearing enrollment-token issuance; dispose returned material after use and retain uncertainty evidence.</summary>
    public static ManagementRequest<GatewayEnrollmentToken> GenerateEnrollmentToken(string organizationId, string gatewayId) =>
        new("infisical.post.v3.gateways.by.gatewayId.token.auth.generate.enrollment.token", HttpMethod.Post,
            GatewayPath(gatewayId) + "/token-auth/generate-enrollment-token",
            new(organizationId, resourceId: gatewayId), null, root => new(root));

    private static string GatewayPath(string id)
    {
        GatewayJson.UuidInput(id);
        return Path + "/" + id;
    }
}

internal static class GatewayJson
{
    internal static byte[] Serialize(Action<Utf8JsonWriter> write)
    {
        byte[] storage = new byte[64 * 1024];
        try
        {
            using var stream = new MemoryStream(storage, writable: true);
            using (var writer = new Utf8JsonWriter(stream)) write(writer);
            return storage.AsSpan(0, (int)stream.Position).ToArray();
        }
        catch (NotSupportedException) { throw new ArgumentException("The protected input exceeds its byte budget."); }
        finally { Array.Clear(storage); }
    }

    internal static ManagementTarget BodyTarget(string org, string? project, string resource, Action<Utf8JsonWriter> write)
    {
        byte[] body = Serialize(write);
        try { return new(org, project, resource, Convert.ToHexString(SHA256.HashData(body))); }
        finally { Array.Clear(body); }
    }

    internal static void InputText(string? text, int maximum, int minimum = 0)
    {
        if (text is not null && (text.Length < minimum || text.Length > maximum))
            throw new ArgumentException("Invalid protected text budget.");
    }

    internal static void UuidInput(string id)
    {
        if (!Guid.TryParseExact(id, "D", out _)) throw new ArgumentException("Invalid protected resource ID.");
    }

    internal static string Uuid(JsonElement value, string field)
    {
        string id = ManagementJson.Required(value, field);
        if (!Guid.TryParseExact(id, "D", out _)) throw new ManagementContractException(SecretStatus.Unknown);
        return id;
    }

    internal static string? Text(JsonElement value, string field, bool required = false, bool nullable = true)
    {
        bool present = value.TryGetProperty(field, out var child);
        if (required && !present || present && !nullable && child.ValueKind == JsonValueKind.Null)
            throw new ManagementContractException(SecretStatus.Unknown);
        return ManagementJson.Optional(value, field);
    }

    internal static string? Timestamp(JsonElement value, string field, bool required = true, bool nullable = false)
    {
        string? text = Text(value, field, required, nullable);
        if (text is not null && !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind, out _)) throw new ManagementContractException(SecretStatus.Unknown);
        return text;
    }

    internal static string? OptionalUuid(JsonElement value, string field)
    {
        string? id = Text(value, field);
        if (id is not null && !Guid.TryParseExact(id, "D", out _)) throw new ManagementContractException(SecretStatus.Unknown);
        return id;
    }
}
