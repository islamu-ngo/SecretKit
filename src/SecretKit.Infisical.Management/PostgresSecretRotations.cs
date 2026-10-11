using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Typed postgres-credentials configuration. NativeRotation owns existing enablement, trigger and progress facets.</summary>
public static class PostgresSecretRotationOperations
{
    // Frozen request/success facts: 0564, 0835/0836/0838/0840/0841, 0919/0921, 0943/0944/0945.
    internal const string Path = "/api/v2/secret-rotations/postgres-credentials";
    private const string IdPrefix = "infisical.";
    private const string Profile = "v2.secret.rotations.postgres.credentials";

    public static ManagementRequest<PostgresSecretRotationList> List(string organizationId, string projectId)
    {
        ManagementJson.Text(projectId);
        return new(IdPrefix + "get." + Profile, HttpMethod.Get, Path + "?projectId=" + Uri.EscapeDataString(projectId),
            new(organizationId, projectId), null, root => ReadList(root, projectId, false), false);
    }

    public static ManagementRequest<PostgresSecretRotationSummary> Get(string organizationId, InfisicalRotationAddress address) =>
        new(IdPrefix + "get." + Profile + ".by.rotationId", HttpMethod.Get, RotationPath(address),
            SelectionTarget(organizationId, address), null,
            root => Read(root, address), false);

    public static ManagementRequest<PostgresSecretRotationSummary> GetByName(string organizationId, string projectId,
        string environment, string secretPath, string rotationName)
    {
        string query = NameQuery(projectId, environment, secretPath);
        return new(IdPrefix + "get." + Profile + ".rotation.name.by.rotationName", HttpMethod.Get,
            Path + "/rotation-name/" + ManagementJson.Escape(rotationName) + query,
            NameTarget(organizationId, projectId, environment, secretPath, rotationName), null,
            root => new(ManagementJson.Object(root, "secretRotation"), projectId, name: rotationName,
                environment: environment, secretPath: secretPath), false);
    }

    public static ManagementTarget NameTarget(string organizationId, string projectId, string environment,
        string secretPath, string rotationName) =>
        new(organizationId, projectId, rotationName, NameQuery(projectId, environment, secretPath));

    public static ManagementRequest<PostgresSecretRotationSummary> Create(string organizationId, PostgresSecretRotationCreation creation)
    {
        ArgumentNullException.ThrowIfNull(creation);
        return new(IdPrefix + "post." + Profile, HttpMethod.Post, Path, CreationTarget(organizationId, creation), creation.Write,
            root => new(ManagementJson.Object(root, "secretRotation"), creation.ProjectId, name: creation.Name,
                environment: creation.Environment, secretPath: creation.SecretPath, connectionId: creation.ConnectionId));
    }

    public static ManagementTarget CreationTarget(string organizationId, PostgresSecretRotationCreation creation)
    {
        ArgumentNullException.ThrowIfNull(creation);
        return BodyTarget(organizationId, creation.ProjectId, creation.Name, "", creation.Write);
    }

    public static ManagementRequest<PostgresSecretRotationSummary> Update(string organizationId, InfisicalRotationAddress address,
        PostgresSecretRotationUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        return new(IdPrefix + "patch." + Profile + ".by.rotationId", HttpMethod.Patch, RotationPath(address),
            UpdateTarget(organizationId, address, update), update.Write, root => Read(root, address));
    }

    public static ManagementTarget UpdateTarget(string organizationId, InfisicalRotationAddress address,
        PostgresSecretRotationUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        RotationPath(address);
        return BodyTarget(organizationId, address.ProjectId, address.RotationId, Coordinates(address), update.Write);
    }

    /// <summary>Configuration deletion flags retain omission/true/false. Revocation effects require native verification.</summary>
    public static ManagementRequest<PostgresSecretRotationSummary> Delete(string organizationId, InfisicalRotationAddress address,
        bool? deleteSecrets = null, bool? revokeGeneratedCredentials = null) =>
        new(IdPrefix + "delete." + Profile + ".by.rotationId", HttpMethod.Delete,
            RotationPath(address) + DeleteQuery(deleteSecrets, revokeGeneratedCredentials),
            DeletionTarget(organizationId, address, deleteSecrets, revokeGeneratedCredentials), null,
            root => Read(root, address));

    public static ManagementTarget DeletionTarget(string organizationId, InfisicalRotationAddress address,
        bool? deleteSecrets = null, bool? revokeGeneratedCredentials = null)
    {
        RotationPath(address);
        return new(organizationId, address.ProjectId, address.RotationId,
            Coordinates(address) + DeleteQuery(deleteSecrets, revokeGeneratedCredentials));
    }

    public static ManagementRequest<PostgresCredentialCheckAcknowledgement> CheckCredentials(string organizationId,
        InfisicalRotationAddress address) =>
        new(IdPrefix + "post." + Profile + ".by.rotationId.check.credentials", HttpMethod.Post,
            RotationPath(address) + "/check-credentials", SelectionTarget(organizationId, address), null,
            root => root.ValueKind == JsonValueKind.String && root.GetString() == ""
                ? new() : throw new ManagementContractException(SecretStatus.Unknown));

    public static ManagementRequest<PostgresGeneratedCredentials> GetGeneratedCredentials(string organizationId,
        InfisicalRotationAddress address) =>
        new(IdPrefix + "get." + Profile + ".by.rotationId.generated.credentials", HttpMethod.Get,
            RotationPath(address) + "/generated-credentials", SelectionTarget(organizationId, address), null,
            root => new(root, address.RotationId), false);

    public static ManagementRequest<PostgresSecretRotationSummary> Move(string organizationId, InfisicalRotationAddress address,
        PostgresSecretRotationMove move)
    {
        ArgumentNullException.ThrowIfNull(move);
        return new(IdPrefix + "post." + Profile + ".by.rotationId.move", HttpMethod.Post, RotationPath(address) + "/move",
            MoveTarget(organizationId, address, move), move.Write,
            root => new(ManagementJson.Object(root, "secretRotation"), address.ProjectId, address.RotationId,
                environment: move.DestinationEnvironment, secretPath: move.DestinationSecretPath));
    }

    public static ManagementTarget MoveTarget(string organizationId, InfisicalRotationAddress address, PostgresSecretRotationMove move)
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

    /// <summary>Explicitly PostgreSQL-only projection of the mixed shared catalog.</summary>
    public static ManagementRequest<PostgresSecretRotationList> ListPostgresSubset(string organizationId, string projectId)
    {
        ManagementJson.Text(projectId);
        return new("infisical.get.v2.secret.rotations", HttpMethod.Get,
            "/api/v2/secret-rotations?projectId=" + Uri.EscapeDataString(projectId),
            new(organizationId, projectId, secondaryId: "postgres-credentials-subset"), null,
            root => ReadList(root, projectId, true), false);
    }

    public static ManagementRequest<PostgresSecretRotationOptions> PostgresOptionsSubset(string organizationId) =>
        new("infisical.get.v2.secret.rotations.options", HttpMethod.Get, "/api/v2/secret-rotations/options",
            new(organizationId, secondaryId: "postgres-credentials-subset"), null, root =>
            {
                var result = new List<PostgresSecretRotationOption>();
                try
                {
                    foreach (var item in ManagementJson.Array(root, "secretRotationOptions"))
                        if (ManagementJson.Required(item, "type") == "postgres-credentials") result.Add(new(item));
                    return new(result);
                }
                catch { foreach (var item in result) item.Dispose(); throw; }
            }, false);

    private static PostgresSecretRotationList ReadList(JsonElement root, string projectId, bool subset)
    {
        var result = new List<PostgresSecretRotationSummary>();
        try
        {
            foreach (var item in ManagementJson.Array(root, "secretRotations"))
                if (!subset || ManagementJson.Required(item, "type") == "postgres-credentials") result.Add(new(item, projectId));
            return new(result, !subset);
        }
        catch { foreach (var item in result) item.Dispose(); throw; }
    }
    private static PostgresSecretRotationSummary Read(JsonElement root, InfisicalRotationAddress address) =>
        new(ManagementJson.Object(root, "secretRotation"), address.ProjectId, address.RotationId,
            environment: address.Environment, secretPath: address.Folder);

    private static string RotationPath(InfisicalRotationAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.Profile != InfisicalRotationProfile.PostgresCredentials)
            throw new ArgumentException("A PostgreSQL rotation address is required.");
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
        catch (NotSupportedException) { throw new ArgumentException("The PostgreSQL rotation input exceeds its byte budget."); }
        finally { Array.Clear(storage); }
    }
    internal static void InputUuid(string value)
    {
        if (!Guid.TryParseExact(value, "D", out _)) throw new ArgumentException("Invalid PostgreSQL rotation UUID.");
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
            throw new ArgumentException("Invalid PostgreSQL rotation number.");
    }
    internal static double Number(JsonElement value, string field,
        double minimum = -double.MaxValue, double maximum = double.MaxValue)
    {
        double result = ManagementJson.Number(value, field);
        return result >= minimum && result <= maximum ? result : throw new ManagementContractException(SecretStatus.Unknown);
    }
}
