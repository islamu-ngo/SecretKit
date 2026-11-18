using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

// The single implementation behind the three native SQL credential rotation families.
// Dialects differ only by fixed wire constants, so requests, intent binding and strict
// response parsing are identical for PostgreSQL, MySQL and Microsoft SQL Server.
internal sealed class SqlSecretRotationFamily
{
    private const string IdPrefix = "infisical.";

    internal static readonly SqlSecretRotationFamily Postgres =
        new("postgres", "PostgreSQL", InfisicalRotationProfile.PostgresCredentials);
    internal static readonly SqlSecretRotationFamily MySql =
        new("mysql", "MySQL", InfisicalRotationProfile.MysqlCredentials);
    internal static readonly SqlSecretRotationFamily MsSql =
        new("mssql", "Microsoft SQL Server", InfisicalRotationProfile.MssqlCredentials);

    private readonly string _label;
    private readonly string _operationProfile;
    private readonly InfisicalRotationProfile _profile;

    private SqlSecretRotationFamily(string app, string label, InfisicalRotationProfile profile)
    {
        App = app;
        CredentialType = app + "-credentials";
        OptionName = label + " Credentials";
        Path = "/api/v2/secret-rotations/" + CredentialType;
        _label = label;
        _operationProfile = "v2.secret.rotations." + app + ".credentials";
        _profile = profile;
    }

    internal string App { get; }
    internal string CredentialType { get; }
    internal string OptionName { get; }
    internal string Path { get; }

    internal ManagementRequest<SqlSecretRotationList> List(string organizationId, string projectId)
    {
        ManagementJson.Text(projectId);
        return new(IdPrefix + "get." + _operationProfile,
            (apis, _, token) => apis.SqlRotations.List(CredentialType, projectId, token),
            HttpMethod.Get, Path + "?projectId=" + Uri.EscapeDataString(projectId),
            new(organizationId, projectId), null, root => ReadList(root, projectId, false), false);
    }

    internal ManagementRequest<SqlSecretRotationSummary> Get(string organizationId, InfisicalRotationAddress address) =>
        new(IdPrefix + "get." + _operationProfile + ".by.rotationId",
            (apis, _, token) => apis.SqlRotations.Get(CredentialType, address.RotationId, token),
            HttpMethod.Get, RotationPath(address),
            SelectionTarget(organizationId, address), null,
            root => Read(root, address), false);

    internal ManagementRequest<SqlSecretRotationSummary> GetByName(string organizationId, string projectId,
        string environment, string secretPath, string rotationName)
    {
        string query = NameQuery(projectId, environment, secretPath);
        return new(IdPrefix + "get." + _operationProfile + ".rotation.name.by.rotationName",
            (apis, _, token) => apis.SqlRotations.GetByName(CredentialType, rotationName, projectId, environment,
                secretPath, token),
            HttpMethod.Get,
            Path + "/rotation-name/" + ManagementJson.Escape(rotationName) + query,
            NameTarget(organizationId, projectId, environment, secretPath, rotationName), null,
            root => new(RotationObject(root), this, projectId, name: rotationName,
                environment: environment, secretPath: secretPath), false);
    }

    internal static ManagementTarget NameTarget(string organizationId, string projectId, string environment,
        string secretPath, string rotationName) =>
        new(organizationId, projectId, rotationName, NameQuery(projectId, environment, secretPath));

    internal ManagementRequest<SqlSecretRotationSummary> Create(string organizationId, SqlSecretRotationCreation creation)
    {
        ArgumentNullException.ThrowIfNull(creation);
        return new(IdPrefix + "post." + _operationProfile,
            (apis, body, token) => apis.SqlRotations.Create(CredentialType, body!, token),
            HttpMethod.Post, Path, CreationTarget(organizationId, creation), creation.Write,
            root => new(RotationObject(root), this, creation.ProjectId, name: creation.Name,
                environment: creation.Environment, secretPath: creation.SecretPath, connectionId: creation.ConnectionId));
    }

    internal ManagementTarget CreationTarget(string organizationId, SqlSecretRotationCreation creation)
    {
        ArgumentNullException.ThrowIfNull(creation);
        return BodyTarget(organizationId, creation.ProjectId, creation.Name, "", creation.Write);
    }

    internal ManagementRequest<SqlSecretRotationSummary> Update(string organizationId, InfisicalRotationAddress address,
        SqlSecretRotationUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        return new(IdPrefix + "patch." + _operationProfile + ".by.rotationId",
            (apis, body, token) => apis.SqlRotations.Update(CredentialType, address.RotationId, body!, token),
            HttpMethod.Patch, RotationPath(address),
            UpdateTarget(organizationId, address, update), update.Write, root => Read(root, address));
    }

    internal ManagementTarget UpdateTarget(string organizationId, InfisicalRotationAddress address,
        SqlSecretRotationUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        RotationPath(address);
        return BodyTarget(organizationId, address.ProjectId, address.RotationId, Coordinates(address), update.Write);
    }

    internal ManagementRequest<SqlSecretRotationSummary> Delete(string organizationId, InfisicalRotationAddress address,
        bool? deleteSecrets, bool? revokeGeneratedCredentials) =>
        new(IdPrefix + "delete." + _operationProfile + ".by.rotationId",
            (apis, _, token) => apis.SqlRotations.Delete(CredentialType, address.RotationId,
                Flag(deleteSecrets), Flag(revokeGeneratedCredentials), token),
            HttpMethod.Delete,
            RotationPath(address) + DeleteQuery(deleteSecrets, revokeGeneratedCredentials),
            DeletionTarget(organizationId, address, deleteSecrets, revokeGeneratedCredentials), null,
            root => Read(root, address));

    internal ManagementTarget DeletionTarget(string organizationId, InfisicalRotationAddress address,
        bool? deleteSecrets, bool? revokeGeneratedCredentials)
    {
        RotationPath(address);
        return new(organizationId, address.ProjectId, address.RotationId,
            Coordinates(address) + DeleteQuery(deleteSecrets, revokeGeneratedCredentials));
    }

    internal ManagementRequest<SqlCredentialCheckAcknowledgement> CheckCredentials(string organizationId,
        InfisicalRotationAddress address) =>
        new(IdPrefix + "post." + _operationProfile + ".by.rotationId.check.credentials",
            (apis, _, token) => apis.SqlRotations.CheckCredentials(CredentialType, address.RotationId, token),
            HttpMethod.Post,
            RotationPath(address) + "/check-credentials", SelectionTarget(organizationId, address), null,
            static root => root.ValueKind == JsonValueKind.String && root.GetString() == ""
                ? new() : throw new ManagementContractException(SecretStatus.Unknown));

    internal ManagementRequest<SqlGeneratedCredentials> GetGeneratedCredentials(string organizationId,
        InfisicalRotationAddress address) =>
        new(IdPrefix + "get." + _operationProfile + ".by.rotationId.generated.credentials",
            (apis, _, token) => apis.SqlRotations.GeneratedCredentials(CredentialType, address.RotationId, token),
            HttpMethod.Get,
            RotationPath(address) + "/generated-credentials", SelectionTarget(organizationId, address), null,
            root => new(root, this, address.RotationId), false);

    internal ManagementRequest<SqlSecretRotationSummary> Move(string organizationId, InfisicalRotationAddress address,
        SqlSecretRotationMove move)
    {
        ArgumentNullException.ThrowIfNull(move);
        return new(IdPrefix + "post." + _operationProfile + ".by.rotationId.move",
            (apis, body, token) => apis.SqlRotations.Move(CredentialType, address.RotationId, body!, token),
            HttpMethod.Post, RotationPath(address) + "/move",
            MoveTarget(organizationId, address, move), move.Write,
            root => new(RotationObject(root), this, address.ProjectId, address.RotationId,
                environment: move.DestinationEnvironment, secretPath: move.DestinationSecretPath));
    }

    internal ManagementTarget MoveTarget(string organizationId, InfisicalRotationAddress address, SqlSecretRotationMove move)
    {
        ArgumentNullException.ThrowIfNull(move);
        RotationPath(address);
        return BodyTarget(organizationId, address.ProjectId, address.RotationId, Coordinates(address), move.Write);
    }

    internal ManagementTarget SelectionTarget(string organizationId, InfisicalRotationAddress address)
    {
        RotationPath(address);
        return new(organizationId, address.ProjectId, address.RotationId, Coordinates(address));
    }

    internal ManagementRequest<SqlSecretRotationList> ListSubset(string organizationId, string projectId)
    {
        ManagementJson.Text(projectId);
        return new("infisical.get.v2.secret.rotations",
            (apis, _, token) => apis.SqlRotations.ListCatalog(projectId, token),
            HttpMethod.Get,
            "/api/v2/secret-rotations?projectId=" + Uri.EscapeDataString(projectId),
            new(organizationId, projectId, secondaryId: CredentialType + "-subset"), null,
            root => ReadList(root, projectId, true), false);
    }

    internal ManagementRequest<SqlSecretRotationOptions> OptionsSubset(string organizationId) =>
        new("infisical.get.v2.secret.rotations.options", static (apis, _, token) => apis.SqlRotations.Options(token),
            HttpMethod.Get, "/api/v2/secret-rotations/options",
            new(organizationId, secondaryId: CredentialType + "-subset"), null, root =>
            {
                SqlSecretRotationShared.Only(root, "secretRotationOptions");
                var result = new List<SqlSecretRotationOption>();
                try
                {
                    foreach (var item in ManagementJson.Array(root, "secretRotationOptions"))
                        if (ManagementJson.Required(item, "type") == CredentialType) result.Add(new(item, this));
                    return new(result);
                }
                catch { foreach (var item in result) item.Dispose(); throw; }
            }, false);

    private SqlSecretRotationList ReadList(JsonElement root, string projectId, bool subset)
    {
        SqlSecretRotationShared.Only(root, "secretRotations");
        var result = new List<SqlSecretRotationSummary>();
        try
        {
            foreach (var item in ManagementJson.Array(root, "secretRotations"))
                if (!subset || ManagementJson.Required(item, "type") == CredentialType) result.Add(new(item, this, projectId));
            return new(result, !subset);
        }
        catch { foreach (var item in result) item.Dispose(); throw; }
    }

    private SqlSecretRotationSummary Read(JsonElement root, InfisicalRotationAddress address) =>
        new(RotationObject(root), this, address.ProjectId, address.RotationId,
            environment: address.Environment, secretPath: address.Folder);

    private static JsonElement RotationObject(JsonElement root)
    {
        SqlSecretRotationShared.Only(root, "secretRotation");
        return ManagementJson.Object(root, "secretRotation");
    }

    private string RotationPath(InfisicalRotationAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.Profile != _profile)
            throw new ArgumentException($"A {_label} rotation address is required.");
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

    private static string? Flag(bool? value) => value is { } selected ? selected ? "true" : "false" : null;

    private static string DeleteQuery(bool? secrets, bool? revoke)
    {
        var parts = new List<string>(2);
        if (Flag(secrets) is { } delete) parts.Add("deleteSecrets=" + delete);
        if (Flag(revoke) is { } credentials) parts.Add("revokeGeneratedCredentials=" + credentials);
        return parts.Count == 0 ? "" : "?" + string.Join("&", parts);
    }

    private ManagementTarget BodyTarget(string organizationId, string projectId, string resourceId,
        string coordinates, Action<Utf8JsonWriter> write) =>
        new(organizationId, projectId, resourceId,
            coordinates + ":" + ManagementJson.IntentFingerprint(write, _label + " rotation"));
}
