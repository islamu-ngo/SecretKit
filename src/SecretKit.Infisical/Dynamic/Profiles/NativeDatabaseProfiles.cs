using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Dynamic;

/// <summary>Shared protected database-definition inputs with provider-specific typed construction and no local driver.</summary>
public abstract class NativeDatabaseDefinitionProfile : InfisicalDynamicProfile
{
    private protected NativeDatabaseDefinitionProfile(InfisicalDynamicProvider provider, string host, int port,
        string username, string? password, string? database, string creation, string revocation,
        string? renewal, string? ca) : base(provider)
    {
        Text("host", host); Number("port", port, 1, 65535); Text("username", username);
        Optional("password", password); Optional("database", database);
        Text("creationStatement", creation, allowEmpty: true); Text("revocationStatement", revocation, allowEmpty: true);
        Optional("renewStatement", renewal); Optional("ca", ca);
    }
}
/// <summary>Owned ClickHouse native definition fields, including optional gateway and password policy.</summary>
public sealed class NativeClickhouseDefinitionProfile : NativeDatabaseDefinitionProfile
{
    /// <summary>Copies connection coordinates, credentials, lifecycle statements and selected nested options.</summary>
    public NativeClickhouseDefinitionProfile(string host, int port, string username, string password,
        string database, string creation, string revocation, string? renewal = null, string? ca = null,
        NativeGatewayOptions? gateway = null, NativePasswordRequirements? passwordRequirements = null)
        : base(InfisicalDynamicProvider.Clickhouse, host, port, username, password, database, creation, revocation, renewal, ca)
    {
        Options(gateway); PasswordRequirements(passwordRequirements);
    }
}
/// <summary>Owned Cassandra definition fields with explicit local data center and optional keyspace.</summary>
public sealed class NativeCassandraDefinitionProfile : NativeDatabaseDefinitionProfile
{
    /// <summary>Copies credentials, statements and data-center/keyspace/TLS inputs without contacting Cassandra.</summary>
    public NativeCassandraDefinitionProfile(string host, int port, string username, string password,
        string localDataCenter, string creation, string revocation, string? keyspace = null,
        string? renewal = null, string? ca = null)
        : base(InfisicalDynamicProvider.Cassandra, host, port, username, password, null, creation, revocation, renewal, ca)
    {
        Text("localDataCenter", localDataCenter); Optional("keyspace", keyspace);
    }
}
/// <summary>Owned SAP ASE definition fields for provider-side lifecycle statements.</summary>
public sealed class NativeSapAseDefinitionProfile : NativeDatabaseDefinitionProfile
{
    /// <summary>Copies explicit connection, credential, creation and revocation inputs.</summary>
    public NativeSapAseDefinitionProfile(string host, int port, string username, string password,
        string database, string creation, string revocation)
        : base(InfisicalDynamicProvider.SapAse, host, port, username, password, database, creation, revocation, null, null) { }
}
/// <summary>Owned SAP HANA definition fields with optional renewal and CA inputs.</summary>
public sealed class NativeSapHanaDefinitionProfile : NativeDatabaseDefinitionProfile
{
    /// <summary>Copies connection credentials and native lifecycle statements; no database action occurs locally.</summary>
    public NativeSapHanaDefinitionProfile(string host, int port, string username, string password,
        string creation, string revocation, string? renewal = null, string? ca = null)
        : base(InfisicalDynamicProvider.SapHana, host, port, username, password, null, creation, revocation, renewal, ca) { }
}
/// <summary>Owned Redis definition fields with explicitly optional password, renewal and CA.</summary>
public sealed class NativeRedisDefinitionProfile : NativeDatabaseDefinitionProfile
{
    /// <summary>Copies Redis connection and statement inputs without inventing absent credentials.</summary>
    public NativeRedisDefinitionProfile(string host, int port, string username, string creation,
        string revocation, string? password = null, string? renewal = null, string? ca = null)
        : base(InfisicalDynamicProvider.Redis, host, port, username, password, null, creation, revocation, renewal, ca) { }
}
/// <summary>Owned Vertica definition fields and optional copied gateway/password requirements.</summary>
public sealed class NativeVerticaDefinitionProfile : NativeDatabaseDefinitionProfile
{
    /// <summary>Copies Vertica credentials, database and lifecycle statements; callers retain original options.</summary>
    public NativeVerticaDefinitionProfile(string host, int port, string username, string password,
        string database, string creation, string revocation, NativeGatewayOptions? gateway = null,
        NativePasswordRequirements? passwordRequirements = null)
        : base(InfisicalDynamicProvider.Vertica, host, port, username, password, database, creation, revocation, null, null)
    {
        Options(gateway); PasswordRequirements(passwordRequirements);
    }
}
/// <summary>Owned native Azure SQL definition inputs, separate from Azure Key Vault or local database access.</summary>
public sealed class NativeAzureSqlDefinitionProfile : NativeDatabaseDefinitionProfile
{
    /// <summary>Copies database/master creation statements, credentials and explicitly selected TLS/gateway/password options.</summary>
    public NativeAzureSqlDefinitionProfile(string host, int port, string username, string password,
        string database, string creation, string masterCreation, string revocation,
        string? masterDatabase = null, string? renewal = null, string? ca = null,
        NativeGatewayOptions? gateway = null, NativePasswordRequirements? passwordRequirements = null,
        bool? sslEnabled = null)
        : base(InfisicalDynamicProvider.AzureSqlDatabase, host, port, username, password, database, creation, revocation, renewal, ca)
    {
        Text("masterCreationStatement", masterCreation, allowEmpty: true); Optional("masterDatabase", masterDatabase);
        Options(gateway); PasswordRequirements(passwordRequirements);
        if (sslEnabled is { } enabled) Flag("sslEnabled", enabled);
    }
}
/// <summary>Owned Snowflake native account and lifecycle statement inputs.</summary>
public sealed class NativeSnowflakeDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies explicit account/organization, credentials and statements without executing them locally.</summary>
    public NativeSnowflakeDefinitionProfile(string accountId, string organizationId, string username, string password,
        string creation, string revocation, string? renewal = null) : base(InfisicalDynamicProvider.Snowflake)
    {
        Text("accountId", accountId); Text("orgId", organizationId); Text("username", username);
        Text("password", password); Text("creationStatement", creation); Text("revocationStatement", revocation);
        Optional("renewStatement", renewal);
    }
}
/// <summary>Owned Milvus connection inputs with copied native privilege and gateway options.</summary>
public sealed class NativeMilvusDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies credentials and selected database/CA/gateway/privileges; selection does not grant permissions locally.</summary>
    public NativeMilvusDefinitionProfile(string host, int port, string username, string password,
        string? database = null, string? ca = null, NativeGatewayOptions? gateway = null,
        IReadOnlyList<NativeMilvusPrivilege>? privileges = null) : base(InfisicalDynamicProvider.Milvus)
    {
        Text("host", host); Number("port", port, 1, 65535); Text("username", username); Text("password", password);
        Optional("database", database); Optional("ca", ca);
        Options(gateway); ObjectOptions("privileges", privileges);
    }
}
/// <summary>Owned MongoDB definition fields with explicit omitted-versus-cleared port/CA semantics.</summary>
public sealed class NativeMongoDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies credentials, database and roles; rejects a value combined with a clear flag for the same field.</summary>
    public NativeMongoDefinitionProfile(string host, string username, string password, string database,
        IReadOnlyList<string> roles, int? port = null, string? ca = null,
        bool clearPort = false, bool clearCa = false) : base(InfisicalDynamicProvider.MongoDb)
    {
        if (clearPort && port is not null || clearCa && ca is not null)
            throw new ArgumentException("Contradictory native Mongo clearing.");
        Text("host", host); Text("username", username); Text("password", password); Text("database", database);
        Strings("roles", roles); Optional("ca", ca);
        if (port is { } value) { Number("port", value, 1, 65535); }
        if (clearPort) Null("port");
        if (clearCa) Null("ca");
    }
}
/// <summary>Owned Elasticsearch definition inputs with distinct API-key and user authentication branches.</summary>
public sealed class NativeElasticsearchDefinitionProfile : InfisicalDynamicProfile
{
    private NativeElasticsearchDefinitionProfile(string host, int port, IReadOnlyList<string> roles,
        string apiKeyId, string apiKey, string? ca) : base(InfisicalDynamicProvider.ElasticSearch)
    {
        Text("host", host); Number("port", port, 1, 65535); Text("auth.type", "api-key");
        Text("auth.apiKeyId", apiKeyId, allowEmpty: true); Text("auth.apiKey", apiKey, allowEmpty: true);
        Strings("roles", roles); Optional("ca", ca);
    }
    /// <summary>Copies API-key authority, roles and optional CA without sending an Elasticsearch request.</summary>
    public static NativeElasticsearchDefinitionProfile ForApiKey(string host, int port, string apiKeyId,
        string apiKey, IReadOnlyList<string> roles, string? ca = null) => new(host, port, roles, apiKeyId, apiKey, ca);
    /// <summary>Copies explicit user credentials, roles and optional CA for the native user branch.</summary>
    public NativeElasticsearchDefinitionProfile(string host, int port, string username, string password,
        IReadOnlyList<string> roles, string? ca = null) : base(InfisicalDynamicProvider.ElasticSearch)
    {
        Text("host", host); Number("port", port, 1, 65535); Text("auth.type", "user");
        Text("auth.username", username, allowEmpty: true); Text("auth.password", password, allowEmpty: true);
        Strings("roles", roles); Optional("ca", ca);
    }
}
/// <summary>Owned Couchbase cluster/role inputs with copied bucket and password requirements.</summary>
public sealed class NativeCouchbaseDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies API authority and cluster selectors; validates the stricter native Couchbase password requirements.</summary>
    public NativeCouchbaseDefinitionProfile(string url, string apiKey, string organizationId, string projectId,
        string clusterId, IReadOnlyList<string> roles, NativeCouchbaseBuckets? buckets = null,
        NativePasswordRequirements? passwordRequirements = null) : base(InfisicalDynamicProvider.Couchbase)
    {
        SafeUri("url", url); Text("auth.apiKey", apiKey); Text("orgId", organizationId);
        Text("projectId", projectId); Text("clusterId", clusterId); Strings("roles", roles);
        Options(buckets); PasswordRequirements(passwordRequirements, couchbase: true);
    }
}
/// <summary>Protected Atlas role/scope coordinates; no public dictionary accepts additional fields.</summary>
public sealed class NativeAtlasRole
{
    /// <summary>Selects protected database/role and optional collection coordinates.</summary>
    public NativeAtlasRole(string databaseName, string roleName, string? collectionName = null)
    {
        InfisicalNativeAddress.NativeText(databaseName); InfisicalNativeAddress.NativeText(roleName);
        if (collectionName is not null) { InfisicalNativeAddress.NativeText(collectionName); }
        DatabaseName = databaseName; RoleName = roleName; CollectionName = collectionName;
    }
    /// <summary>The protected database name.</summary>
    [JsonIgnore] public string DatabaseName { get; }
    /// <summary>The selected native role name; not a local grant.</summary>
    [JsonIgnore] public string RoleName { get; }
    /// <summary>The optional protected collection name.</summary>
    [JsonIgnore] public string? CollectionName { get; }
    /// <summary>Returns a fixed label without role coordinates.</summary>
    public override string ToString() => "[NativeAtlasRole]";
}
/// <summary>Protected Atlas scope selectors, excluded from default serialization.</summary>
public sealed class NativeAtlasScope
{
    /// <summary>Selects a bounded nonempty native scope name and type.</summary>
    public NativeAtlasScope(string name, string type)
    {
        InfisicalNativeAddress.NativeText(name); InfisicalNativeAddress.NativeText(type);
        Name = name; Type = type;
    }
    /// <summary>The protected native scope name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>The protected native scope type.</summary>
    [JsonIgnore] public string Type { get; }
    /// <summary>Returns a fixed label without scope fields.</summary>
    public override string ToString() => "[NativeAtlasScope]";
}
/// <summary>Owned MongoDB Atlas definition credentials and frozen typed role/scope selections.</summary>
public sealed class NativeAtlasDefinitionProfile : InfisicalDynamicProfile
{
    private readonly NativeAtlasRole[] _roles;
    private readonly NativeAtlasScope[] _scopes;
    /// <summary>Copies administrative keys and group ID, freezing bounded role/scope lists without issuing credentials.</summary>
    public NativeAtlasDefinitionProfile(string adminPublicKey, string adminPrivateKey, string groupId,
        IReadOnlyList<NativeAtlasRole> roles, IReadOnlyList<NativeAtlasScope> scopes)
        : base(InfisicalDynamicProvider.MongoDbAtlas)
    {
        ArgumentNullException.ThrowIfNull(roles); ArgumentNullException.ThrowIfNull(scopes);
        if (roles.Count is < 1 or > 128 || scopes.Count > 128 ||
            roles.Any(value => value is null) || scopes.Any(value => value is null))
        {
            throw new ArgumentException("Invalid native Atlas array budget.");
        }
        _roles = roles.ToArray(); _scopes = scopes.ToArray();
        Text("adminPublicKey", adminPublicKey); Text("adminPrivateKey", adminPrivateKey); Text("groupId", groupId);
    }
    private protected override void WriteAdditional(Utf8JsonWriter writer, string prefix)
    {
        if (prefix.Length != 0) { return; }
        writer.WriteStartArray("roles");
        foreach (NativeAtlasRole role in _roles)
        {
            writer.WriteStartObject(); writer.WriteString("databaseName", role.DatabaseName);
            writer.WriteString("roleName", role.RoleName);
            if (role.CollectionName is not null) { writer.WriteString("collectionName", role.CollectionName); }
            writer.WriteEndObject();
        }
        writer.WriteEndArray(); writer.WriteStartArray("scopes");
        foreach (NativeAtlasScope scope in _scopes)
        {
            writer.WriteStartObject(); writer.WriteString("name", scope.Name); writer.WriteString("type", scope.Type);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }
}
