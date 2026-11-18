namespace SecretKit.Infisical.Management;

/// <summary>Typed postgres-credentials configuration. NativeRotation owns existing enablement, trigger and progress facets.</summary>
/// <remarks>Requests and results use the shared <c>Sql*</c> rotation models; responses are parsed with strict unknown-field rejection.</remarks>
public static class PostgresSecretRotationOperations
{
    // Frozen request/success facts: 0564, 0835/0836/0838/0840/0841, 0919/0921, 0943/0944/0945.
    private static SqlSecretRotationFamily Family => SqlSecretRotationFamily.Postgres;

    /// <summary>Builds a disposable native rotation inventory request for one project; successful lists own their items.</summary>
    public static ManagementRequest<SqlSecretRotationList> List(string organizationId, string projectId) =>
        Family.List(organizationId, projectId);

    /// <summary>Builds exact rotation inspection using the profile-specific address; successful results require disposal.</summary>
    public static ManagementRequest<SqlSecretRotationSummary> Get(string organizationId, InfisicalRotationAddress address) =>
        Family.Get(organizationId, address);

    /// <summary>Builds rotation lookup by name with exact project, environment and path correspondence.</summary>
    public static ManagementRequest<SqlSecretRotationSummary> GetByName(string organizationId, string projectId,
        string environment, string secretPath, string rotationName) =>
        Family.GetByName(organizationId, projectId, environment, secretPath, rotationName);

    /// <summary>Builds independent approval intent for the selected native name and coordinates.</summary>
    public static ManagementTarget NameTarget(string organizationId, string projectId, string environment,
        string secretPath, string rotationName) =>
        SqlSecretRotationFamily.NameTarget(organizationId, projectId, environment, secretPath, rotationName);

    /// <summary>Builds rotation configuration creation; does not create a database connection or execute SQL locally.</summary>
    public static ManagementRequest<SqlSecretRotationSummary> Create(string organizationId, SqlSecretRotationCreation creation) =>
        Family.Create(organizationId, creation);

    /// <summary>Builds independent host approval for the complete serialized creation body.</summary>
    public static ManagementTarget CreationTarget(string organizationId, SqlSecretRotationCreation creation) =>
        Family.CreationTarget(organizationId, creation);

    /// <summary>Builds rotation configuration update; null fields remain omitted and empty patches remain explicit.</summary>
    public static ManagementRequest<SqlSecretRotationSummary> Update(string organizationId, InfisicalRotationAddress address,
        SqlSecretRotationUpdate update) =>
        Family.Update(organizationId, address, update);

    /// <summary>Builds independent approval for the exact existing address and complete update body.</summary>
    public static ManagementTarget UpdateTarget(string organizationId, InfisicalRotationAddress address,
        SqlSecretRotationUpdate update) =>
        Family.UpdateTarget(organizationId, address, update);

    /// <summary>Configuration deletion flags retain omission/true/false. Revocation effects require native verification.</summary>
    public static ManagementRequest<SqlSecretRotationSummary> Delete(string organizationId, InfisicalRotationAddress address,
        bool? deleteSecrets = null, bool? revokeGeneratedCredentials = null) =>
        Family.Delete(organizationId, address, deleteSecrets, revokeGeneratedCredentials);

    /// <summary>Builds independent deletion intent preserving omission, true and false for both deletion flags.</summary>
    public static ManagementTarget DeletionTarget(string organizationId, InfisicalRotationAddress address,
        bool? deleteSecrets = null, bool? revokeGeneratedCredentials = null) =>
        Family.DeletionTarget(organizationId, address, deleteSecrets, revokeGeneratedCredentials);

    /// <summary>Builds a receipt-bearing native credential-check request; a 204 acknowledgement does not prove convergence.</summary>
    public static ManagementRequest<SqlCredentialCheckAcknowledgement> CheckCredentials(string organizationId,
        InfisicalRotationAddress address) =>
        Family.CheckCredentials(organizationId, address);

    /// <summary>Builds generated-credential retrieval; dispose the successful material-bearing result and protect explicit plaintext exports.</summary>
    public static ManagementRequest<SqlGeneratedCredentials> GetGeneratedCredentials(string organizationId,
        InfisicalRotationAddress address) =>
        Family.GetGeneratedCredentials(organizationId, address);

    /// <summary>Builds a rotation move to exact selected destination coordinates.</summary>
    public static ManagementRequest<SqlSecretRotationSummary> Move(string organizationId, InfisicalRotationAddress address,
        SqlSecretRotationMove move) =>
        Family.Move(organizationId, address, move);

    /// <summary>Builds independent approval intent binding both source address and complete destination body.</summary>
    public static ManagementTarget MoveTarget(string organizationId, InfisicalRotationAddress address,
        SqlSecretRotationMove move) =>
        Family.MoveTarget(organizationId, address, move);

    /// <summary>Independent target for selected reads/checks. Existing native trigger receipts are not management receipts.</summary>
    public static ManagementTarget SelectionTarget(string organizationId, InfisicalRotationAddress address) =>
        Family.SelectionTarget(organizationId, address);

    /// <summary>Explicitly PostgreSQL-only projection of the mixed shared catalog.</summary>
    public static ManagementRequest<SqlSecretRotationList> ListPostgresSubset(string organizationId, string projectId) =>
        Family.ListSubset(organizationId, projectId);

    /// <summary>Builds a profile-only options projection from the mixed catalog; successful results own protected statement templates.</summary>
    public static ManagementRequest<SqlSecretRotationOptions> PostgresOptionsSubset(string organizationId) =>
        Family.OptionsSubset(organizationId);
}
