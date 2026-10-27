using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Typed mssql-credentials configuration. NativeRotation owns existing enablement, trigger and progress facets.</summary>
public static class MsSqlSecretRotationOperations
{
    // Frozen request/success facts: 0564, 0835/0836/0838/0840/0841, 0919/0921, 0918/0920/0922, 0831/0939.
    internal const string Path = "/api/v2/secret-rotations/mssql-credentials";
    private const string IdPrefix = "infisical.";
    private const string Profile = "v2.secret.rotations.mssql.credentials";

    /// <summary>Builds a disposable native rotation inventory request for one project; successful lists own their items.</summary>
    public static ManagementRequest<MsSqlSecretRotationList> List(string organizationId, string projectId)
    {
        ManagementJson.Text(projectId);
        return new(IdPrefix + "get." + Profile, HttpMethod.Get, Path + "?projectId=" + Uri.EscapeDataString(projectId),
            new(organizationId, projectId), null, root => ReadList(root, projectId, false), false);
    }

    /// <summary>Builds exact rotation inspection using the profile-specific address; successful results require disposal.</summary>
    public static ManagementRequest<MsSqlSecretRotationSummary> Get(string organizationId, InfisicalRotationAddress address) =>
        new(IdPrefix + "get." + Profile + ".by.rotationId", HttpMethod.Get, RotationPath(address),
            SelectionTarget(organizationId, address), null,
            root => Read(root, address), false);

    /// <summary>Builds rotation lookup by name with exact project, environment and path correspondence.</summary>
    public static ManagementRequest<MsSqlSecretRotationSummary> GetByName(string organizationId, string projectId,
        string environment, string secretPath, string rotationName)
    {
        string query = NameQuery(projectId, environment, secretPath);
        return new(IdPrefix + "get." + Profile + ".rotation.name.by.rotationName", HttpMethod.Get,
            Path + "/rotation-name/" + ManagementJson.Escape(rotationName) + query,
            NameTarget(organizationId, projectId, environment, secretPath, rotationName), null,
            root => new(RotationObject(root), projectId, name: rotationName,
                environment: environment, secretPath: secretPath), false);
    }

    /// <summary>Builds independent approval intent for the selected native name and coordinates.</summary>
    public static ManagementTarget NameTarget(string organizationId, string projectId, string environment,
        string secretPath, string rotationName) =>
        new(organizationId, projectId, rotationName, NameQuery(projectId, environment, secretPath));

    /// <summary>Builds rotation configuration creation; does not create a database connection or execute SQL locally.</summary>
    public static ManagementRequest<MsSqlSecretRotationSummary> Create(string organizationId, MsSqlSecretRotationCreation creation)
    {
        ArgumentNullException.ThrowIfNull(creation);
        return new(IdPrefix + "post." + Profile, HttpMethod.Post, Path, CreationTarget(organizationId, creation), creation.Write,
            root => new(RotationObject(root), creation.ProjectId, name: creation.Name,
                environment: creation.Environment, secretPath: creation.SecretPath, connectionId: creation.ConnectionId));
    }

    /// <summary>Builds independent host approval for the complete serialized creation body.</summary>
    public static ManagementTarget CreationTarget(string organizationId, MsSqlSecretRotationCreation creation)
    {
        ArgumentNullException.ThrowIfNull(creation);
        return BodyTarget(organizationId, creation.ProjectId, creation.Name, "", creation.Write);
    }

    /// <summary>Builds rotation configuration update; null fields remain omitted and empty patches remain explicit.</summary>
    public static ManagementRequest<MsSqlSecretRotationSummary> Update(string organizationId, InfisicalRotationAddress address,
        MsSqlSecretRotationUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        return new(IdPrefix + "patch." + Profile + ".by.rotationId", HttpMethod.Patch, RotationPath(address),
            UpdateTarget(organizationId, address, update), update.Write, root => Read(root, address));
    }

    /// <summary>Builds independent approval for the exact existing address and complete update body.</summary>
    public static ManagementTarget UpdateTarget(string organizationId, InfisicalRotationAddress address,
        MsSqlSecretRotationUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        RotationPath(address);
        return BodyTarget(organizationId, address.ProjectId, address.RotationId, Coordinates(address), update.Write);
    }

    /// <summary>Configuration deletion flags retain omission/true/false. Revocation effects require native verification.</summary>
    public static ManagementRequest<MsSqlSecretRotationSummary> Delete(string organizationId, InfisicalRotationAddress address,
        bool? deleteSecrets = null, bool? revokeGeneratedCredentials = null) =>
        new(IdPrefix + "delete." + Profile + ".by.rotationId", HttpMethod.Delete,
            RotationPath(address) + DeleteQuery(deleteSecrets, revokeGeneratedCredentials),
            DeletionTarget(organizationId, address, deleteSecrets, revokeGeneratedCredentials), null,
            root => Read(root, address));

    /// <summary>Builds independent deletion intent preserving omission, true and false for both deletion flags.</summary>
    public static ManagementTarget DeletionTarget(string organizationId, InfisicalRotationAddress address,
        bool? deleteSecrets = null, bool? revokeGeneratedCredentials = null)
    {
        RotationPath(address);
        return new(organizationId, address.ProjectId, address.RotationId,
            Coordinates(address) + DeleteQuery(deleteSecrets, revokeGeneratedCredentials));
    }

    /// <summary>Builds a receipt-bearing native credential-check request; a 204 acknowledgement does not prove convergence.</summary>
    public static ManagementRequest<MsSqlCredentialCheckAcknowledgement> CheckCredentials(string organizationId,
        InfisicalRotationAddress address) =>
        new(IdPrefix + "post." + Profile + ".by.rotationId.check.credentials", HttpMethod.Post,
            RotationPath(address) + "/check-credentials", SelectionTarget(organizationId, address), null,
            root => root.ValueKind == JsonValueKind.String && root.GetString() == ""
                ? new() : throw new ManagementContractException(SecretStatus.Unknown));

    /// <summary>Builds generated-credential retrieval; dispose the successful material-bearing result and protect explicit plaintext exports.</summary>
    public static ManagementRequest<MsSqlGeneratedCredentials> GetGeneratedCredentials(string organizationId,
        InfisicalRotationAddress address) =>
        new(IdPrefix + "get." + Profile + ".by.rotationId.generated.credentials", HttpMethod.Get,
            RotationPath(address) + "/generated-credentials", SelectionTarget(organizationId, address), null,
            root => new(root, address.RotationId), false);

    /// <summary>Builds a rotation move to exact selected destination coordinates.</summary>
    public static ManagementRequest<MsSqlSecretRotationSummary> Move(string organizationId, InfisicalRotationAddress address,
        MsSqlSecretRotationMove move)
    {
        ArgumentNullException.ThrowIfNull(move);
        return new(IdPrefix + "post." + Profile + ".by.rotationId.move", HttpMethod.Post, RotationPath(address) + "/move",
            MoveTarget(organizationId, address, move), move.Write,
            root => new(RotationObject(root), address.ProjectId, address.RotationId,
                environment: move.DestinationEnvironment, secretPath: move.DestinationSecretPath));
    }

    /// <summary>Builds independent approval intent binding both source address and complete destination body.</summary>
    public static ManagementTarget MoveTarget(string organizationId, InfisicalRotationAddress address, MsSqlSecretRotationMove move)
    {
        ArgumentNullException.ThrowIfNull(move);
        RotationPath(address);
        return BodyTarget(organizationId, address.ProjectId, address.RotationId, Coordinates(address), move.Write);
    }

    /// <summary>Independent target for selected reads/checks. Existing native trigger receipts are not management receipts.</summary>
    public static ManagementTarget SelectionTarget(string organizationId, InfisicalRotationAddress address)
    {
        RotationPath(address);
        return new(organizationId, address.ProjectId, address.RotationId, Coordinates(address));
    }

    /// <summary>Explicitly Microsoft SQL Server-only projection of the mixed shared catalog.</summary>
    public static ManagementRequest<MsSqlSecretRotationList> ListMsSqlSubset(string organizationId, string projectId)
    {
        ManagementJson.Text(projectId);
        return new("infisical.get.v2.secret.rotations", HttpMethod.Get,
            "/api/v2/secret-rotations?projectId=" + Uri.EscapeDataString(projectId),
            new(organizationId, projectId, secondaryId: "mssql-credentials-subset"), null,
            root => ReadList(root, projectId, true), false);
    }

    /// <summary>Builds a profile-only options projection from the mixed catalog; successful results own protected statement templates.</summary>
    public static ManagementRequest<MsSqlSecretRotationOptions> MsSqlOptionsSubset(string organizationId) =>
        new("infisical.get.v2.secret.rotations.options", HttpMethod.Get, "/api/v2/secret-rotations/options",
            new(organizationId, secondaryId: "mssql-credentials-subset"), null, root =>
            {
                Only(root, "secretRotationOptions");
                var result = new List<MsSqlSecretRotationOption>();
                try
                {
                    foreach (var item in ManagementJson.Array(root, "secretRotationOptions"))
                        if (ManagementJson.Required(item, "type") == "mssql-credentials") result.Add(new(item));
                    return new(result);
                }
                catch { foreach (var item in result) item.Dispose(); throw; }
            }, false);

    private static MsSqlSecretRotationList ReadList(JsonElement root, string projectId, bool subset)
    {
        Only(root, "secretRotations");
        var result = new List<MsSqlSecretRotationSummary>();
        try
        {
            foreach (var item in ManagementJson.Array(root, "secretRotations"))
                if (!subset || ManagementJson.Required(item, "type") == "mssql-credentials") result.Add(new(item, projectId));
            return new(result, !subset);
        }
        catch { foreach (var item in result) item.Dispose(); throw; }
    }
    private static MsSqlSecretRotationSummary Read(JsonElement root, InfisicalRotationAddress address) =>
        new(RotationObject(root), address.ProjectId, address.RotationId,
            environment: address.Environment, secretPath: address.Folder);

    private static JsonElement RotationObject(JsonElement root)
    {
        Only(root, "secretRotation");
        return ManagementJson.Object(root, "secretRotation");
    }

    internal static void Only(JsonElement value, params string[] fields)
    {
        if (value.ValueKind != JsonValueKind.Object)
            throw new ManagementContractException(SecretStatus.Unknown);
        foreach (var property in value.EnumerateObject())
            if (!fields.Contains(property.Name, StringComparer.Ordinal))
                throw new ManagementContractException(SecretStatus.Unknown);
    }

    private static string RotationPath(InfisicalRotationAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.Profile != InfisicalRotationProfile.MssqlCredentials)
            throw new ArgumentException("A Microsoft SQL Server rotation address is required.");
        return Path + "/" + address.RotationId;
    }
    private static string Coordinates(InfisicalRotationAddress address) =>
        "environment=" + Uri.EscapeDataString(address.Environment!) + "&secretPath=" + Uri.EscapeDataString(address.Folder!);
    private static string NameQuery(string projectId, string environment, string secretPath)
    {
        ManagementJson.Text(projectId);
        ManagementJson.Text(environment);
        ManagementJson.Text(secretPath);
        return "?projectId=" + Uri.EscapeDataString(projectId) + "&environment=" + Uri.EscapeDataString(environment) +
            "&secretPath=" + Uri.EscapeDataString(secretPath);
    }
    private static string DeleteQuery(bool? secrets, bool? revoke)
    {
        var parts = new List<string>();
        if (secrets is { } delete) parts.Add("deleteSecrets=" + (delete ? "true" : "false"));
        if (revoke is { } credentials) parts.Add("revokeGeneratedCredentials=" + (credentials ? "true" : "false"));
        return parts.Count == 0 ? "" : "?" + string.Join("&", parts);
    }
    private static ManagementTarget BodyTarget(string organizationId, string projectId, string resourceId,
        string coordinates, Action<Utf8JsonWriter> write)
    {
        byte[] storage = new byte[64 * 1024];
        try
        {
            using var stream = new MemoryStream(storage, writable: true);
            using (var writer = new Utf8JsonWriter(stream)) write(writer);
            return new(organizationId, projectId, resourceId,
                coordinates + ":" + Convert.ToHexString(SHA256.HashData(storage.AsSpan(0, (int)stream.Position))));
        }
        catch (NotSupportedException) { throw new ArgumentException("The Microsoft SQL Server rotation input exceeds its byte budget."); }
        finally { Array.Clear(storage); }
    }
    internal static void InputUuid(string value)
    {
        if (!Guid.TryParseExact(value, "D", out _)) throw new ArgumentException("Invalid Microsoft SQL Server rotation UUID.");
    }
    internal static string Uuid(JsonElement value, string field)
    {
        string text = ManagementJson.Required(value, field);
        if (!Guid.TryParseExact(text, "D", out _)) throw new ManagementContractException(SecretStatus.Unknown);
        return text;
    }
    internal static void InputNumber(double value, double minimum, double maximum = double.MaxValue)
    {
        if (!double.IsFinite(value) || value < minimum || value > maximum)
            throw new ArgumentException("Invalid Microsoft SQL Server rotation number.");
    }
    internal static double Number(JsonElement value, string field,
        double minimum = -double.MaxValue, double maximum = double.MaxValue)
    {
        double result = ManagementJson.Number(value, field);
        return result >= minimum && result <= maximum ? result : throw new ManagementContractException(SecretStatus.Unknown);
    }
}
