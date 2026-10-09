using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>
/// Independently authored definition inputs. Each profile owns copies; disposal performs no I/O.
/// No profile accepts arbitrary field names, endpoints, JSON or public object maps.
/// </summary>
public abstract class InfisicalDynamicProfile : IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<string, SecretMaterial> _text = new(StringComparer.Ordinal);
    private readonly Dictionary<string, decimal> _numbers = new(StringComparer.Ordinal);
    private readonly Dictionary<string, bool> _booleans = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SecretMaterial[]> _arrays = new(StringComparer.Ordinal);
    private bool _disposed;
    private protected InfisicalDynamicProfile(InfisicalDynamicProvider provider) => Provider = provider;
    public InfisicalDynamicProvider Provider { get; }
    internal string WireType => Provider switch
    {
        InfisicalDynamicProvider.SqlDatabase => "sql-database",
        InfisicalDynamicProvider.Clickhouse => "clickhouse",
        InfisicalDynamicProvider.Cassandra => "cassandra",
        InfisicalDynamicProvider.SapAse => "sap-ase",
        InfisicalDynamicProvider.AwsIam => "aws-iam",
        InfisicalDynamicProvider.Redis => "redis",
        InfisicalDynamicProvider.SapHana => "sap-hana",
        InfisicalDynamicProvider.AwsElasticache => "aws-elasticache",
        InfisicalDynamicProvider.AwsMemorydb => "aws-memorydb",
        InfisicalDynamicProvider.MongoDbAtlas => "mongo-db-atlas",
        InfisicalDynamicProvider.ElasticSearch => "elastic-search",
        InfisicalDynamicProvider.MongoDb => "mongo-db",
        InfisicalDynamicProvider.RabbitMq => "rabbit-mq",
        InfisicalDynamicProvider.AzureEntraId => "azure-entra-id",
        InfisicalDynamicProvider.AzureSqlDatabase => "azure-sql-database",
        InfisicalDynamicProvider.Ldap => "ldap",
        InfisicalDynamicProvider.Snowflake => "snowflake",
        InfisicalDynamicProvider.Totp => "totp",
        InfisicalDynamicProvider.Kubernetes => "kubernetes",
        InfisicalDynamicProvider.Vertica => "vertica",
        InfisicalDynamicProvider.GcpIam => "gcp-iam",
        InfisicalDynamicProvider.Github => "github",
        InfisicalDynamicProvider.Couchbase => "couchbase",
        InfisicalDynamicProvider.Milvus => "milvus",
        InfisicalDynamicProvider.Ssh => "ssh",
        InfisicalDynamicProvider.IbmApiConnect => "ibm-api-connect",
        InfisicalDynamicProvider.Tailscale => "tailscale",
        InfisicalDynamicProvider.Oauth2 => "oauth2",
        _ => throw new InvalidOperationException("No admitted native profile.")
    };
    internal static InfisicalDynamicProvider? ProviderFor(string? wire) => wire switch
    {
        "sql-database" => InfisicalDynamicProvider.SqlDatabase,
        "clickhouse" => InfisicalDynamicProvider.Clickhouse,
        "cassandra" => InfisicalDynamicProvider.Cassandra,
        "sap-ase" => InfisicalDynamicProvider.SapAse,
        "aws-iam" => InfisicalDynamicProvider.AwsIam,
        "redis" => InfisicalDynamicProvider.Redis,
        "sap-hana" => InfisicalDynamicProvider.SapHana,
        "aws-elasticache" => InfisicalDynamicProvider.AwsElasticache,
        "aws-memorydb" => InfisicalDynamicProvider.AwsMemorydb,
        "mongo-db-atlas" => InfisicalDynamicProvider.MongoDbAtlas,
        "elastic-search" => InfisicalDynamicProvider.ElasticSearch,
        "mongo-db" => InfisicalDynamicProvider.MongoDb,
        "rabbit-mq" => InfisicalDynamicProvider.RabbitMq,
        "azure-entra-id" => InfisicalDynamicProvider.AzureEntraId,
        "azure-sql-database" => InfisicalDynamicProvider.AzureSqlDatabase,
        "ldap" => InfisicalDynamicProvider.Ldap,
        "snowflake" => InfisicalDynamicProvider.Snowflake,
        "totp" => InfisicalDynamicProvider.Totp,
        "kubernetes" => InfisicalDynamicProvider.Kubernetes,
        "vertica" => InfisicalDynamicProvider.Vertica,
        "gcp-iam" => InfisicalDynamicProvider.GcpIam,
        "github" => InfisicalDynamicProvider.Github,
        "couchbase" => InfisicalDynamicProvider.Couchbase,
        "milvus" => InfisicalDynamicProvider.Milvus,
        "ssh" => InfisicalDynamicProvider.Ssh,
        "ibm-api-connect" => InfisicalDynamicProvider.IbmApiConnect,
        "tailscale" => InfisicalDynamicProvider.Tailscale,
        "oauth2" => InfisicalDynamicProvider.Oauth2,
        _ => null
    };

    private protected void Text(string field, string value, int maximum = 65536, bool allowEmpty = false)
    {
        if (value is null || value.Length > maximum || (!allowEmpty && value.Length == 0))
        {
            Dispose();
            throw new ArgumentException("Invalid protected profile field.");
        }
        _text.Add(field, SecretMaterial.FromText(value));
    }
    private protected void Optional(string field, string? value, int maximum = 65536)
    {
        if (value is not null)
        {
            Text(field, value, maximum, true);
        }
    }
    private protected void Number(string field, decimal value, decimal minimum, decimal maximum)
    {
        if (value < minimum || value > maximum)
        {
            Dispose();
            throw new ArgumentException("Invalid native numeric field.");
        }
        _numbers.Add(field, value);
    }
    private protected void Flag(string field, bool value) => _booleans.Add(field, value);
    private protected void Strings(string field, IReadOnlyList<string> values, bool allowEmptyArray = false)
    {
        if (values is null)
        {
            Dispose();
            throw new ArgumentException("Required native array is missing.");
        }
        if (values.Count > 128 || (!allowEmptyArray && values.Count == 0) ||
            values.Any(value => value is null || value.Length is < 1 or > 4096))
        {
            Dispose();
            throw new ArgumentException("Invalid native array budget.");
        }
        _arrays.Add(field, values.Select(value => SecretMaterial.FromText(value)).ToArray());
    }
    private protected void SafeUri(string field, string value, int maximum = 2048)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) || uri.UserInfo.Length != 0)
        {
            Dispose();
            throw new ArgumentException("Invalid protected native URI.");
        }
        Text(field, value, maximum);
    }
    internal void WriteInputs(Utf8JsonWriter writer)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            WriteFields(writer, "");
        }
    }
    // Dot paths are private implementation details, supplied only by handwritten typed constructors.
    private void WriteFields(Utf8JsonWriter writer, string prefix)
    {
        foreach ((string name, SecretMaterial value) in _text)
        {
            if (name.StartsWith(prefix, StringComparison.Ordinal) && !name[prefix.Length..].Contains('.'))
            {
                writer.WriteString(name[prefix.Length..], value.Reveal());
            }
        }
        foreach ((string name, decimal value) in _numbers)
        {
            if (name.StartsWith(prefix, StringComparison.Ordinal) && !name[prefix.Length..].Contains('.'))
            {
                writer.WriteNumber(name[prefix.Length..], value);
            }
        }
        foreach ((string name, bool value) in _booleans)
        {
            if (name.StartsWith(prefix, StringComparison.Ordinal) && !name[prefix.Length..].Contains('.'))
            {
                writer.WriteBoolean(name[prefix.Length..], value);
            }
        }
        foreach ((string name, SecretMaterial[] values) in _arrays)
        {
            if (name.StartsWith(prefix, StringComparison.Ordinal) && !name[prefix.Length..].Contains('.'))
            {
                writer.WriteStartArray(name[prefix.Length..]);
                foreach (SecretMaterial value in values)
                {
                    writer.WriteStringValue(value.Reveal());
                }
                writer.WriteEndArray();
            }
        }
        IEnumerable<string> fields = _text.Keys.Concat(_numbers.Keys).Concat(_booleans.Keys).Concat(_arrays.Keys);
        foreach (string child in fields.Where(name => name.StartsWith(prefix, StringComparison.Ordinal))
            .Select(name => name[prefix.Length..]).Where(name => name.Contains('.'))
            .Select(name => name[..name.IndexOf('.')]).Distinct(StringComparer.Ordinal))
        {
            writer.WriteStartObject(child);
            WriteFields(writer, prefix + child + ".");
            writer.WriteEndObject();
        }
        WriteAdditional(writer, prefix);
    }
    private protected virtual void WriteAdditional(Utf8JsonWriter writer, string prefix) { }
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            foreach (SecretMaterial value in _text.Values.Concat(_arrays.Values.SelectMany(values => values)))
            {
                value.Dispose();
            }
            DisposeAdditional();
        }
    }
    private protected virtual void DisposeAdditional() { }
    public sealed override string ToString() => "[InfisicalDynamicProfile]";
}

public enum NativeSqlEngine { Postgres, Mysql, Oracle, SqlServer, SapAse, Vertica }

public sealed class NativeSqlDefinitionProfile : InfisicalDynamicProfile
{
    public NativeSqlDefinitionProfile(NativeSqlEngine engine, string host, int port, string username,
        string password, string database, string creationStatement, string revocationStatement,
        string? renewalStatement = null) : base(InfisicalDynamicProvider.SqlDatabase)
    {
        Text("client", engine switch
        {
            NativeSqlEngine.Postgres => "postgres",
            NativeSqlEngine.Mysql => "mysql2",
            NativeSqlEngine.Oracle => "oracledb",
            NativeSqlEngine.SqlServer => "mssql",
            NativeSqlEngine.SapAse => "sap-ase",
            NativeSqlEngine.Vertica => "vertica",
            _ => throw new ArgumentException("Unknown native SQL engine.")
        });
        Text("host", host); Number("port", port, 1, 65535); Text("username", username);
        Text("password", password); Text("database", database);
        Text("creationStatement", creationStatement, allowEmpty: true);
        Text("revocationStatement", revocationStatement, allowEmpty: true);
        Optional("renewStatement", renewalStatement);
    }
}

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
public sealed class NativeClickhouseDefinitionProfile : NativeDatabaseDefinitionProfile
{
    public NativeClickhouseDefinitionProfile(string host, int port, string username, string password,
        string database, string creation, string revocation, string? renewal = null, string? ca = null)
        : base(InfisicalDynamicProvider.Clickhouse, host, port, username, password, database, creation, revocation, renewal, ca) { }
}
public sealed class NativeCassandraDefinitionProfile : NativeDatabaseDefinitionProfile
{
    public NativeCassandraDefinitionProfile(string host, int port, string username, string password,
        string localDataCenter, string creation, string revocation, string? keyspace = null,
        string? renewal = null, string? ca = null)
        : base(InfisicalDynamicProvider.Cassandra, host, port, username, password, null, creation, revocation, renewal, ca)
    {
        Text("localDataCenter", localDataCenter); Optional("keyspace", keyspace);
    }
}
public sealed class NativeSapAseDefinitionProfile : NativeDatabaseDefinitionProfile
{
    public NativeSapAseDefinitionProfile(string host, int port, string username, string password,
        string database, string creation, string revocation)
        : base(InfisicalDynamicProvider.SapAse, host, port, username, password, database, creation, revocation, null, null) { }
}
public sealed class NativeSapHanaDefinitionProfile : NativeDatabaseDefinitionProfile
{
    public NativeSapHanaDefinitionProfile(string host, int port, string username, string password,
        string creation, string revocation, string? renewal = null, string? ca = null)
        : base(InfisicalDynamicProvider.SapHana, host, port, username, password, null, creation, revocation, renewal, ca) { }
}
public sealed class NativeRedisDefinitionProfile : NativeDatabaseDefinitionProfile
{
    public NativeRedisDefinitionProfile(string host, int port, string username, string creation,
        string revocation, string? password = null, string? renewal = null, string? ca = null)
        : base(InfisicalDynamicProvider.Redis, host, port, username, password, null, creation, revocation, renewal, ca) { }
}
public sealed class NativeVerticaDefinitionProfile : NativeDatabaseDefinitionProfile
{
    public NativeVerticaDefinitionProfile(string host, int port, string username, string password,
        string database, string creation, string revocation)
        : base(InfisicalDynamicProvider.Vertica, host, port, username, password, database, creation, revocation, null, null) { }
}
public sealed class NativeAzureSqlDefinitionProfile : NativeDatabaseDefinitionProfile
{
    public NativeAzureSqlDefinitionProfile(string host, int port, string username, string password,
        string database, string creation, string masterCreation, string revocation,
        string? masterDatabase = null, string? renewal = null, string? ca = null)
        : base(InfisicalDynamicProvider.AzureSqlDatabase, host, port, username, password, database, creation, revocation, renewal, ca)
    {
        Text("masterCreationStatement", masterCreation, allowEmpty: true); Optional("masterDatabase", masterDatabase);
    }
}
public sealed class NativeSnowflakeDefinitionProfile : InfisicalDynamicProfile
{
    public NativeSnowflakeDefinitionProfile(string accountId, string organizationId, string username, string password,
        string creation, string revocation, string? renewal = null) : base(InfisicalDynamicProvider.Snowflake)
    {
        Text("accountId", accountId); Text("orgId", organizationId); Text("username", username);
        Text("password", password); Text("creationStatement", creation); Text("revocationStatement", revocation);
        Optional("renewStatement", renewal);
    }
}
public enum NativeAwsCredentialKind { IamUser, Temporary }
public sealed class NativeAwsIamDefinitionProfile : InfisicalDynamicProfile
{
    private enum RoleMethod { AssumeRole, Irsa }
    private NativeAwsIamDefinitionProfile(RoleMethod method, string region, string? roleArn,
        NativeAwsCredentialKind credentialKind) : base(InfisicalDynamicProvider.AwsIam)
    {
        if (!Enum.IsDefined(credentialKind))
        {
            throw new ArgumentException("Unknown native AWS credential kind.");
        }
        Text("method", method == RoleMethod.AssumeRole ? "assume-role" : "irsa"); Text("region", region);
        if (method == RoleMethod.AssumeRole) { Text("roleArn", roleArn!); }
        Text("credentialType", credentialKind == NativeAwsCredentialKind.IamUser ? "iam-user" : "temporary-credentials");
    }
    public static NativeAwsIamDefinitionProfile ForAssumeRole(string roleArn, string region,
        NativeAwsCredentialKind credentialKind = NativeAwsCredentialKind.IamUser) =>
        new(RoleMethod.AssumeRole, region, roleArn, credentialKind);
    public static NativeAwsIamDefinitionProfile ForIrsa(string region,
        NativeAwsCredentialKind credentialKind = NativeAwsCredentialKind.IamUser) =>
        new(RoleMethod.Irsa, region, null, credentialKind);
    public NativeAwsIamDefinitionProfile(string accessKey, string secretAccessKey, string region,
        NativeAwsCredentialKind credentialKind = NativeAwsCredentialKind.IamUser)
        : base(InfisicalDynamicProvider.AwsIam)
    {
        if (!Enum.IsDefined(credentialKind))
        {
            throw new ArgumentException("Unknown native AWS credential kind.");
        }
        Text("method", "access-key"); Text("accessKey", accessKey); Text("secretAccessKey", secretAccessKey);
        Text("region", region); Text("credentialType", credentialKind switch
        {
            NativeAwsCredentialKind.IamUser => "iam-user",
            NativeAwsCredentialKind.Temporary => "temporary-credentials",
            _ => throw new ArgumentException("Unknown native AWS credential kind.")
        });
    }
}
public sealed class NativeAwsElasticacheDefinitionProfile : InfisicalDynamicProfile
{
    public NativeAwsElasticacheDefinitionProfile(string accessKeyId, string secretAccessKey, string region,
        string clusterName, string creation, string revocation) : base(InfisicalDynamicProvider.AwsElasticache)
    {
        Text("accessKeyId", accessKeyId); Text("secretAccessKey", secretAccessKey); Text("region", region);
        Text("clusterName", clusterName); Text("creationStatement", creation, allowEmpty: true);
        Text("revocationStatement", revocation, allowEmpty: true);
    }
}
public sealed class NativeAwsMemorydbDefinitionProfile : InfisicalDynamicProfile
{
    public NativeAwsMemorydbDefinitionProfile(string accessKeyId, string secretAccessKey, string region,
        string clusterName, string creation, string revocation) : base(InfisicalDynamicProvider.AwsMemorydb)
    {
        Text("auth.type", "iam"); Text("auth.accessKeyId", accessKeyId); Text("auth.secretAccessKey", secretAccessKey);
        Text("region", region); Text("clusterName", clusterName);
        Text("creationStatement", creation, allowEmpty: true); Text("revocationStatement", revocation, allowEmpty: true);
    }
}
public sealed class NativeAzureEntraDefinitionProfile : InfisicalDynamicProfile
{
    public NativeAzureEntraDefinitionProfile(string tenantId, string applicationId, string clientSecret,
        string userId, string email) : base(InfisicalDynamicProvider.AzureEntraId)
    {
        Text("tenantId", tenantId); Text("applicationId", applicationId); Text("clientSecret", clientSecret);
        Text("userId", userId); Text("email", email);
    }
}
public sealed class NativeGcpIamDefinitionProfile : InfisicalDynamicProfile
{
    public NativeGcpIamDefinitionProfile(string serviceAccountEmail, IReadOnlyList<string>? tokenScopes = null)
        : base(InfisicalDynamicProvider.GcpIam)
    {
        if (!serviceAccountEmail.Contains('@'))
        {
            throw new ArgumentException("A native service-account email is required.");
        }
        Text("serviceAccountEmail", serviceAccountEmail, 128);
        if (tokenScopes is not null) { Strings("tokenScopes", tokenScopes); }
    }
}
public sealed class NativeGithubDefinitionProfile : InfisicalDynamicProfile
{
    public NativeGithubDefinitionProfile(long applicationId, long installationId, string privateKey)
        : base(InfisicalDynamicProvider.Github)
    {
        Number("appId", applicationId, 1, long.MaxValue); Number("installationId", installationId, 1, long.MaxValue);
        Text("privateKey", privateKey);
    }
}
public sealed class NativeMilvusDefinitionProfile : InfisicalDynamicProfile
{
    public NativeMilvusDefinitionProfile(string host, int port, string username, string password,
        string? database = null, string? ca = null) : base(InfisicalDynamicProvider.Milvus)
    {
        Text("host", host); Number("port", port, 1, 65535); Text("username", username); Text("password", password);
        Optional("database", database); Optional("ca", ca);
    }
}
public sealed class NativeMongoDefinitionProfile : InfisicalDynamicProfile
{
    public NativeMongoDefinitionProfile(string host, string username, string password, string database,
        IReadOnlyList<string> roles, int? port = null, string? ca = null) : base(InfisicalDynamicProvider.MongoDb)
    {
        Text("host", host); Text("username", username); Text("password", password); Text("database", database);
        Strings("roles", roles); Optional("ca", ca);
        if (port is { } value) { Number("port", value, 1, 65535); }
    }
}
public sealed class NativeElasticsearchDefinitionProfile : InfisicalDynamicProfile
{
    private NativeElasticsearchDefinitionProfile(string host, int port, string apiKeyId, string apiKey,
        IReadOnlyList<string> roles) : base(InfisicalDynamicProvider.ElasticSearch)
    {
        Text("host", host); Number("port", port, 1, 65535); Text("auth.type", "api-key");
        Text("auth.apiKeyId", apiKeyId, allowEmpty: true); Text("auth.apiKey", apiKey, allowEmpty: true);
        Strings("roles", roles);
    }
    public static NativeElasticsearchDefinitionProfile ForApiKey(string host, int port, string apiKeyId,
        string apiKey, IReadOnlyList<string> roles) => new(host, port, apiKeyId, apiKey, roles);
    public NativeElasticsearchDefinitionProfile(string host, int port, string username, string password,
        IReadOnlyList<string> roles, string? ca = null) : base(InfisicalDynamicProvider.ElasticSearch)
    {
        Text("host", host); Number("port", port, 1, 65535); Text("auth.type", "user");
        Text("auth.username", username, allowEmpty: true); Text("auth.password", password, allowEmpty: true);
        Strings("roles", roles); Optional("ca", ca);
    }
}
public sealed class NativeRabbitDefinitionProfile : InfisicalDynamicProfile
{
    public NativeRabbitDefinitionProfile(string host, int port, string username, string password,
        string virtualHost, string configurePermission, string writePermission, string readPermission,
        IReadOnlyList<string>? tags = null, string? ca = null) : base(InfisicalDynamicProvider.RabbitMq)
    {
        Text("host", host); Number("port", port, 1, 65535); Text("username", username); Text("password", password);
        Text("virtualHost.name", virtualHost); Text("virtualHost.permissions.configure", configurePermission);
        Text("virtualHost.permissions.write", writePermission); Text("virtualHost.permissions.read", readPermission);
        Optional("ca", ca); if (tags is not null) { Strings("tags", tags, true); }
    }
}
public sealed class NativeKubernetesDefinitionProfile : InfisicalDynamicProfile
{
    private NativeKubernetesDefinitionProfile(string nameSpace, string serviceAccountName,
        IReadOnlyList<string> audiences, string clusterToken, string url, string? ca)
        : base(InfisicalDynamicProvider.Kubernetes)
    {
        Text("credentialType", "static"); Text("namespace", nameSpace); Text("serviceAccountName", serviceAccountName);
        Strings("audiences", audiences, true); Text("clusterToken", clusterToken); SafeUri("url", url);
        Optional("ca", ca); Flag("sslRejectUnauthorized", true);
    }
    public static NativeKubernetesDefinitionProfile ForStaticAccount(string nameSpace, string serviceAccountName,
        IReadOnlyList<string> audiences, string clusterToken, string url, string? ca = null) =>
        new(nameSpace, serviceAccountName, audiences, clusterToken, url, ca);
    public NativeKubernetesDefinitionProfile(string nameSpace, string role, bool clusterRole,
        IReadOnlyList<string> audiences, string clusterToken, string url, string? ca = null)
        : base(InfisicalDynamicProvider.Kubernetes)
    {
        Text("credentialType", "dynamic"); Text("namespace", nameSpace); Text("role", role);
        Text("roleType", clusterRole ? "cluster-role" : "role"); Strings("audiences", audiences, true);
        Text("clusterToken", clusterToken); SafeUri("url", url); Optional("ca", ca);
        Flag("sslRejectUnauthorized", true);
    }
}
public sealed class NativeLdapDefinitionProfile : InfisicalDynamicProfile
{
    private NativeLdapDefinitionProfile(string url, string bindDn, string bindPassword,
        string rotationLdif, string? ca) : base(InfisicalDynamicProvider.Ldap)
    {
        Text("credentialType", "static"); Text("url", url); Text("binddn", bindDn);
        Text("bindpass", bindPassword); Text("rotationLdif", rotationLdif); Optional("ca", ca);
    }
    public static NativeLdapDefinitionProfile ForStaticAccount(string url, string bindDn, string bindPassword,
        string rotationLdif, string? ca = null) => new(url, bindDn, bindPassword, rotationLdif, ca);
    public NativeLdapDefinitionProfile(string url, string bindDn, string bindPassword, string creationLdif,
        string revocationLdif, string? rollbackLdif = null, string? ca = null) : base(InfisicalDynamicProvider.Ldap)
    {
        Text("credentialType", "dynamic"); Text("url", url); Text("binddn", bindDn); Text("bindpass", bindPassword);
        Text("creationLdif", creationLdif); Text("revocationLdif", revocationLdif);
        Optional("rollbackLdif", rollbackLdif); Optional("ca", ca);
    }
}
public enum NativeTotpAlgorithm { Sha1, Sha256, Sha512 }
public sealed class NativeTotpDefinitionProfile : InfisicalDynamicProfile
{
    private NativeTotpDefinitionProfile(string secret, NativeTotpAlgorithm algorithm, int? digits, int? period)
        : base(InfisicalDynamicProvider.Totp)
    {
        string wireAlgorithm = algorithm switch
        {
            NativeTotpAlgorithm.Sha1 => "sha1",
            NativeTotpAlgorithm.Sha256 => "sha256",
            NativeTotpAlgorithm.Sha512 => "sha512",
            _ => throw new ArgumentException("Unknown native TOTP algorithm.")
        };
        Text("configType", "manual"); Text("secret", secret); Text("algorithm", wireAlgorithm);
        if (digits is { } digitCount) { Number("digits", digitCount, 1, int.MaxValue); }
        if (period is { } seconds) { Number("period", seconds, 1, int.MaxValue); }
    }
    public static NativeTotpDefinitionProfile ForManualSecret(string secret,
        NativeTotpAlgorithm algorithm = NativeTotpAlgorithm.Sha1, int? digits = null, int? period = null) =>
        new(secret, algorithm, digits, period);
    public NativeTotpDefinitionProfile(string provisioningUrl) : base(InfisicalDynamicProvider.Totp)
    {
        Text("configType", "url"); SafeUri("url", provisioningUrl);
    }
}
public sealed class NativeSshDefinitionProfile : InfisicalDynamicProfile
{
    public NativeSshDefinitionProfile(IReadOnlyList<string> principals) : base(InfisicalDynamicProvider.Ssh) =>
        Strings("principals", principals);
}
public sealed class NativeIbmApiDefinitionProfile : InfisicalDynamicProfile
{
    public NativeIbmApiDefinitionProfile(string apiKey, string applicationId, string clientId, string clientSecret,
        string organizationId, string catalogId, string consumerOrganizationId, string instanceUrl)
        : base(InfisicalDynamicProvider.IbmApiConnect)
    {
        Text("apiKey", apiKey); Text("appId", applicationId); Text("clientId", clientId); Text("clientSecret", clientSecret);
        Text("orgId", organizationId); Text("catalogId", catalogId); Text("consumerOrgId", consumerOrganizationId);
        SafeUri("instanceUrl", instanceUrl);
    }
}
public enum NativeOauthClientAuthentication { Basic, Post }
public sealed class NativeOauthDefinitionProfile : InfisicalDynamicProfile
{
    public NativeOauthDefinitionProfile(string clientId, string clientSecret, NativeOauthClientAuthentication method,
        string tokenUrl, string revocationUrl, string? scope = null) : base(InfisicalDynamicProvider.Oauth2)
    {
        if (!Enum.IsDefined(method))
        {
            throw new ArgumentException("Unknown native OAuth client authentication.");
        }
        Text("grantType", "client-credentials"); Text("clientId", clientId, 1024);
        Text("clientAuth.clientSecret", clientSecret, 4096); Text("clientAuth.method", method switch
        {
            NativeOauthClientAuthentication.Basic => "client_secret_basic",
            NativeOauthClientAuthentication.Post => "client_secret_post",
            _ => throw new ArgumentException("Unknown native OAuth client authentication.")
        });
        SafeUri("tokenUrl", tokenUrl); SafeUri("revocationUrl", revocationUrl); Optional("scope", scope, 2048);
    }
}
public sealed class NativeTailscaleDefinitionProfile : InfisicalDynamicProfile
{
    private NativeTailscaleDefinitionProfile(string authType, string? apiKey, string? clientId,
        string? clientSecret, string? issuer, string? subject, IReadOnlyList<string>? scopes)
        : base(InfisicalDynamicProvider.Tailscale)
    {
        if ((authType != "auth_keys" && scopes is null) ||
            (authType == "federated_keys" && (issuer is null || subject is null)))
        {
            throw new ArgumentException("Required native Tailscale fields are missing.");
        }
        Text("authType", authType);
        if (apiKey is not null)
        {
            Text("auth.method", "api_key"); Text("auth.apiKey", apiKey);
        }
        else
        {
            Text("auth.method", "oauth"); Text("auth.clientId", clientId!); Text("auth.clientSecret", clientSecret!);
        }
        if (issuer is not null) { Text("issuer", issuer); }
        if (subject is not null) { Text("subject", subject); }
        if (scopes is not null) { Strings("scopes", scopes); }
    }
    public static NativeTailscaleDefinitionProfile ForOAuthAuthority(string clientId, string clientSecret) =>
        new("auth_keys", null, clientId, clientSecret, null, null, null);
    public static NativeTailscaleDefinitionProfile ForFederatedApiKey(string apiKey, string issuer, string subject,
        IReadOnlyList<string> scopes) => new("federated_keys", apiKey, null, null, issuer, subject, scopes);
    public static NativeTailscaleDefinitionProfile ForFederatedOAuth(string clientId, string clientSecret,
        string issuer, string subject, IReadOnlyList<string> scopes) =>
        new("federated_keys", null, clientId, clientSecret, issuer, subject, scopes);
    public static NativeTailscaleDefinitionProfile ForOAuthKeyApiKey(string apiKey, IReadOnlyList<string> scopes) =>
        new("oauth_keys", apiKey, null, null, null, null, scopes);
    public static NativeTailscaleDefinitionProfile ForOAuthKeyOAuth(string clientId, string clientSecret,
        IReadOnlyList<string> scopes) => new("oauth_keys", null, clientId, clientSecret, null, null, scopes);
    public NativeTailscaleDefinitionProfile(string apiKey, string? tailnet = null, bool reusable = false,
        bool preauthorized = false, IReadOnlyList<string>? tags = null, string? description = null)
        : base(InfisicalDynamicProvider.Tailscale)
    {
        Text("authType", "auth_keys"); Text("auth.method", "api_key"); Text("auth.apiKey", apiKey);
        Optional("tailnet", tailnet); Flag("reusable", reusable); Flag("preauthorized", preauthorized);
        Optional("description", description, 50); if (tags is not null) { Strings("tags", tags, true); }
    }
}
public sealed class NativeCouchbaseDefinitionProfile : InfisicalDynamicProfile
{
    public NativeCouchbaseDefinitionProfile(string url, string apiKey, string organizationId, string projectId,
        string clusterId, IReadOnlyList<string> roles) : base(InfisicalDynamicProvider.Couchbase)
    {
        SafeUri("url", url); Text("auth.apiKey", apiKey); Text("orgId", organizationId);
        Text("projectId", projectId); Text("clusterId", clusterId); Strings("roles", roles);
    }
}
/// <summary>Protected Atlas role/scope coordinates; no public dictionary accepts additional fields.</summary>
public sealed class NativeAtlasRole
{
    public NativeAtlasRole(string databaseName, string roleName, string? collectionName = null)
    {
        InfisicalNativeAddress.NativeText(databaseName); InfisicalNativeAddress.NativeText(roleName);
        if (collectionName is not null) { InfisicalNativeAddress.NativeText(collectionName); }
        DatabaseName = databaseName; RoleName = roleName; CollectionName = collectionName;
    }
    [JsonIgnore] public string DatabaseName { get; }
    [JsonIgnore] public string RoleName { get; }
    [JsonIgnore] public string? CollectionName { get; }
    public override string ToString() => "[NativeAtlasRole]";
}
public sealed class NativeAtlasScope
{
    public NativeAtlasScope(string name, string type)
    {
        InfisicalNativeAddress.NativeText(name); InfisicalNativeAddress.NativeText(type);
        Name = name; Type = type;
    }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string Type { get; }
    public override string ToString() => "[NativeAtlasScope]";
}
public sealed class NativeAtlasDefinitionProfile : InfisicalDynamicProfile
{
    private readonly NativeAtlasRole[] _roles;
    private readonly NativeAtlasScope[] _scopes;
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
