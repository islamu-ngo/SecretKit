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
    private readonly List<NativeProfileOptionData> _options = [];
    private readonly HashSet<string> _nulls = new(StringComparer.Ordinal);
    private bool _disposed;
    private protected InfisicalDynamicProfile(InfisicalDynamicProvider provider) => Provider = provider;
    /// <summary>The closed native provider discriminator; typed inputs do not imply live qualification or issuance support.</summary>
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
    private protected void Null(string field) => _nulls.Add(field);
    private protected void Options(NativeProfileOptions? options)
    {
        if (options is null) return;
        try { _options.Add(options.Copy()); }
        catch { Dispose(); throw; }
    }
    private protected void ObjectOptions<T>(string field, IReadOnlyList<T>? values, int maximum = 128)
        where T : NativeProfileOptions
    {
        if (values is null) return;
        if (values.Count > maximum || values.Any(value => value is null))
        {
            Dispose(); throw new ArgumentException("Invalid native object array budget.");
        }
        var data = new NativeProfileOptionData();
        var copies = new List<NativeProfileOptionData>();
        try
        {
            foreach (var value in values) copies.Add(value.Copy());
            data.Objects.Add(field, copies.ToArray());
            _options.Add(data);
        }
        catch
        {
            foreach (var copy in copies) copy.Dispose();
            Dispose(); throw;
        }
    }
    private protected void PasswordRequirements(NativePasswordRequirements? policy, bool couchbase = false)
    {
        if (policy is null) return;
        if (couchbase && (policy.Length is < 8 or > 128 ||
            policy.Lowercase < 1 || policy.Uppercase < 1 || policy.Digits < 1 || policy.Symbols < 1))
        {
            Dispose(); throw new ArgumentException("Invalid native Couchbase password requirements.");
        }
        try
        {
            SecretMaterial? symbols = policy.CopyAllowedSymbols();
            if (symbols is not null) _text.Add("passwordRequirements.allowedSymbols", symbols);
            Number("passwordRequirements.length", policy.Length, 1, couchbase ? 128 : 250);
            Number("passwordRequirements.required.lowercase", policy.Lowercase, 0, 250);
            Number("passwordRequirements.required.uppercase", policy.Uppercase, 0, 250);
            Number("passwordRequirements.required.digits", policy.Digits, 0, 250);
            Number("passwordRequirements.required.symbols", policy.Symbols, 0, 250);
        }
        catch { Dispose(); throw; }
    }
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
        if (prefix.Length == 0)
        {
            foreach (string field in _nulls) writer.WriteNull(field);
            foreach (var options in _options) options.Write(writer);
        }
        WriteAdditional(writer, prefix);
    }
    private protected virtual void WriteAdditional(Utf8JsonWriter writer, string prefix) { }
    /// <summary>Erases this profile's owned field and nested-option copies without provider I/O.</summary>
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
            foreach (var options in _options) options.Dispose();
            DisposeAdditional();
        }
    }
    private protected virtual void DisposeAdditional() { }
    /// <summary>Returns a fixed label without native inputs, credentials or coordinates.</summary>
    public sealed override string ToString() => "[InfisicalDynamicProfile]";
}

/// <summary>Closed SQL engine selection for provider-side dynamic definition inputs; no database driver is included.</summary>
public enum NativeSqlEngine { /** <summary>PostgreSQL.</summary> */ Postgres, /** <summary>MySQL; not MariaDB qualification.</summary> */ Mysql, /** <summary>Oracle Database.</summary> */ Oracle, /** <summary>SQL Server.</summary> */ SqlServer, /** <summary>SAP ASE.</summary> */ SapAse, /** <summary>Vertica.</summary> */ Vertica }

/// <summary>Bounded whole-number native password generation requirements, not a local generator.</summary>
public sealed class NativePasswordRequirements : IDisposable
{
    private readonly object _gate = new();
    private readonly SecretMaterial? _allowedSymbols;
    private bool _disposed;
    /// <summary>Validates length/count budgets and copies optional allowed symbols; requirements are sent to the provider, not executed locally.</summary>
    public NativePasswordRequirements(int length, int lowercase, int uppercase, int digits, int symbols,
        string? allowedSymbols = null)
    {
        if (length is < 1 or > 250 || lowercase < 0 || uppercase < 0 || digits < 0 || symbols < 0 ||
            (long)lowercase + uppercase + digits + symbols > length || allowedSymbols?.Length > 4096)
            throw new ArgumentException("Invalid bounded password requirements.");
        Length = length;
        Lowercase = lowercase;
        Uppercase = uppercase;
        Digits = digits;
        Symbols = symbols;
        _allowedSymbols = allowedSymbols is null ? null : SecretMaterial.FromText(allowedSymbols);
    }
    /// <summary>Requested whole password length, between 1 and 250.</summary>
    [JsonIgnore] public int Length { get; }
    /// <summary>Required lowercase character count.</summary>
    [JsonIgnore] public int Lowercase { get; }
    /// <summary>Required uppercase character count.</summary>
    [JsonIgnore] public int Uppercase { get; }
    /// <summary>Required digit count.</summary>
    [JsonIgnore] public int Digits { get; }
    /// <summary>Required symbol count; total required counts cannot exceed length.</summary>
    [JsonIgnore] public int Symbols { get; }
    /// <summary>Explicit plaintext export, excluded from default serialization.</summary>
    [JsonIgnore]
    public string? AllowedSymbols
    {
        get
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                return _allowedSymbols?.Reveal();
            }
        }
    }
    internal SecretMaterial? CopyAllowedSymbols()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _allowedSymbols?.Copy();
        }
    }
    /// <summary>Erases the owned allowed-symbol buffer, not earlier plaintext exports or profile copies.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true; _allowedSymbols?.Dispose();
        }
    }
    /// <summary>Returns a fixed label without password-policy contents.</summary>
    public override string ToString() => "[NativePasswordRequirements]";
}

/// <summary>Copied SQL definition inputs for provider-side execution; does not connect to a database.</summary>
public sealed class NativeSqlDefinitionProfile : InfisicalDynamicProfile
{
    private readonly bool _clearGatewayId;
    private readonly bool _clearGatewayPoolId;
    /// <summary>Copies explicit engine, credentials, statements and TLS/gateway inputs; statements are never executed locally.</summary>
    /// <remarks>Nested password requirements are copied. The caller retains all original strings/options;
    /// disposal erases only SDK-owned copies, not the caller's strings.</remarks>
    public NativeSqlDefinitionProfile(NativeSqlEngine engine, string host, int port, string username,
        string password, string database, string creationStatement, string revocationStatement,
        string? renewalStatement = null, string? ca = null, bool? sslEnabled = null,
        string? gatewayId = null, string? gatewayPoolId = null,
        NativePasswordRequirements? passwordRequirements = null,
        bool clearGatewayId = false, bool clearGatewayPoolId = false) : base(InfisicalDynamicProvider.SqlDatabase)
    {
        if (clearGatewayId && gatewayId is not null || clearGatewayPoolId && gatewayPoolId is not null)
            throw new ArgumentException("Contradictory native gateway selection.");
        _clearGatewayId = clearGatewayId;
        _clearGatewayPoolId = clearGatewayPoolId;
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
        Optional("ca", ca);
        if (sslEnabled is { } enabled) Flag("sslEnabled", enabled);
        Optional("gatewayId", gatewayId);
        Optional("gatewayPoolId", gatewayPoolId);
        PasswordRequirements(passwordRequirements);
    }
    private protected override void WriteAdditional(Utf8JsonWriter writer, string prefix)
    {
        if (prefix.Length != 0) return;
        if (_clearGatewayId) writer.WriteNull("gatewayId");
        if (_clearGatewayPoolId) writer.WriteNull("gatewayPoolId");
    }
}

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
/// <summary>The native AWS credential shape requested by an IAM definition.</summary>
public enum NativeAwsCredentialKind { /** <summary>IAM user credentials.</summary> */ IamUser, /** <summary>Temporary credentials.</summary> */ Temporary }
/// <summary>Owned AWS IAM definition inputs with explicit access-key, assume-role or IRSA authority selection.</summary>
public sealed class NativeAwsIamDefinitionProfile : InfisicalDynamicProfile
{
    private enum RoleMethod { AssumeRole, Irsa }
    private NativeAwsIamDefinitionProfile(RoleMethod method, string region, string? roleArn,
        NativeAwsCredentialKind credentialKind, NativeAwsIamOptions? options) : base(InfisicalDynamicProvider.AwsIam)
    {
        if (method != RoleMethod.AssumeRole && options?.HasSessionPolicy == true)
            throw new ArgumentException("Session policies require native assume-role authentication.");
        if (!Enum.IsDefined(credentialKind))
        {
            throw new ArgumentException("Unknown native AWS credential kind.");
        }
        Text("method", method == RoleMethod.AssumeRole ? "assume-role" : "irsa"); Text("region", region);
        if (method == RoleMethod.AssumeRole) { Text("roleArn", roleArn!); }
        Text("credentialType", credentialKind == NativeAwsCredentialKind.IamUser ? "iam-user" : "temporary-credentials");
        Options(options);
    }
    /// <summary>Copies assume-role selectors and optional session policy; does not assume a role locally.</summary>
    public static NativeAwsIamDefinitionProfile ForAssumeRole(string roleArn, string region,
        NativeAwsCredentialKind credentialKind = NativeAwsCredentialKind.IamUser, NativeAwsIamOptions? options = null) =>
        new(RoleMethod.AssumeRole, region, roleArn, credentialKind, options);
    /// <summary>Selects provider-side IRSA with copied region/options; session policy inputs are not admitted on this branch.</summary>
    public static NativeAwsIamDefinitionProfile ForIrsa(string region,
        NativeAwsCredentialKind credentialKind = NativeAwsCredentialKind.IamUser, NativeAwsIamOptions? options = null) =>
        new(RoleMethod.Irsa, region, null, credentialKind, options);
    /// <summary>Copies explicit access-key credentials and native options; session policies require the assume-role branch.</summary>
    public NativeAwsIamDefinitionProfile(string accessKey, string secretAccessKey, string region,
        NativeAwsCredentialKind credentialKind = NativeAwsCredentialKind.IamUser, NativeAwsIamOptions? options = null)
        : base(InfisicalDynamicProvider.AwsIam)
    {
        if (options?.HasSessionPolicy == true)
            throw new ArgumentException("Session policies require native assume-role authentication.");
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
        Options(options);
    }
}
/// <summary>Owned AWS ElastiCache credentials, cluster selectors and native lifecycle statements.</summary>
public sealed class NativeAwsElasticacheDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies AWS credentials and explicit cluster/statement inputs without acquiring a remote lease.</summary>
    public NativeAwsElasticacheDefinitionProfile(string accessKeyId, string secretAccessKey, string region,
        string clusterName, string creation, string revocation) : base(InfisicalDynamicProvider.AwsElasticache)
    {
        Text("accessKeyId", accessKeyId); Text("secretAccessKey", secretAccessKey); Text("region", region);
        Text("clusterName", clusterName); Text("creationStatement", creation, allowEmpty: true);
        Text("revocationStatement", revocation, allowEmpty: true);
    }
}
/// <summary>Owned AWS MemoryDB definition inputs using the native IAM authentication shape.</summary>
public sealed class NativeAwsMemorydbDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies IAM keys, region, cluster and lifecycle statements without provider I/O.</summary>
    public NativeAwsMemorydbDefinitionProfile(string accessKeyId, string secretAccessKey, string region,
        string clusterName, string creation, string revocation) : base(InfisicalDynamicProvider.AwsMemorydb)
    {
        Text("auth.type", "iam"); Text("auth.accessKeyId", accessKeyId); Text("auth.secretAccessKey", secretAccessKey);
        Text("region", region); Text("clusterName", clusterName);
        Text("creationStatement", creation, allowEmpty: true); Text("revocationStatement", revocation, allowEmpty: true);
    }
}
/// <summary>Owned native Entra ID definition inputs with explicit application and user coordinates.</summary>
public sealed class NativeAzureEntraDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies tenant/application credentials and user/email selectors; does not run an identity flow.</summary>
    public NativeAzureEntraDefinitionProfile(string tenantId, string applicationId, string clientSecret,
        string userId, string email) : base(InfisicalDynamicProvider.AzureEntraId)
    {
        Text("tenantId", tenantId); Text("applicationId", applicationId); Text("clientSecret", clientSecret);
        Text("userId", userId); Text("email", email);
    }
}
/// <summary>Owned GCP IAM definition selectors; no host credential discovery is performed.</summary>
public sealed class NativeGcpIamDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies service-account email and optional token scopes for provider-side execution.</summary>
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
/// <summary>Owned GitHub application/installation selectors and private-key input.</summary>
public sealed class NativeGithubDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Validates positive native IDs and copies the private key without minting a GitHub token.</summary>
    public NativeGithubDefinitionProfile(long applicationId, long installationId, string privateKey)
        : base(InfisicalDynamicProvider.Github)
    {
        Number("appId", applicationId, 1, long.MaxValue); Number("installationId", installationId, 1, long.MaxValue);
        Text("privateKey", privateKey);
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
/// <summary>Owned RabbitMQ connection and virtual-host permission inputs, not a local authorization policy.</summary>
public sealed class NativeRabbitDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies credentials, explicit configure/write/read permissions, tags and optional CA.</summary>
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
/// <summary>Owned Kubernetes definition inputs for explicit static-service-account or dynamic-role selection.</summary>
public sealed class NativeKubernetesDefinitionProfile : InfisicalDynamicProfile
{
    private NativeKubernetesDefinitionProfile(string nameSpace, string serviceAccountName,
        IReadOnlyList<string> audiences, string? clusterToken, string? url, string? ca,
        NativeKubernetesAuthentication? authentication, NativeGatewayOptions? gateway, bool? sslEnabled)
        : base(InfisicalDynamicProvider.Kubernetes)
    {
        Text("credentialType", "static"); Text("namespace", nameSpace); Text("serviceAccountName", serviceAccountName);
        Strings("audiences", audiences, true); ClusterAuthority(clusterToken, url, authentication, gateway, sslEnabled);
        Optional("ca", ca); Flag("sslRejectUnauthorized", true);
    }
    /// <summary>Copies service-account/audience and optional cluster/gateway/TLS inputs without reading host cluster credentials.</summary>
    public static NativeKubernetesDefinitionProfile ForStaticAccount(string nameSpace, string serviceAccountName,
        IReadOnlyList<string> audiences, string? clusterToken = null, string? url = null, string? ca = null,
        NativeKubernetesAuthentication? authentication = null, NativeGatewayOptions? gateway = null, bool? sslEnabled = null) =>
        new(nameSpace, serviceAccountName, audiences, clusterToken, url, ca, authentication, gateway, sslEnabled);
    /// <summary>Copies dynamic role or cluster-role selectors and explicit native authentication inputs.</summary>
    public NativeKubernetesDefinitionProfile(string nameSpace, string role, bool clusterRole,
        IReadOnlyList<string> audiences, string? clusterToken = null, string? url = null, string? ca = null,
        NativeKubernetesAuthentication? authentication = null, NativeGatewayOptions? gateway = null, bool? sslEnabled = null)
        : base(InfisicalDynamicProvider.Kubernetes)
    {
        Text("credentialType", "dynamic"); Text("namespace", nameSpace); Text("role", role);
        Text("roleType", clusterRole ? "cluster-role" : "role"); Strings("audiences", audiences, true);
        ClusterAuthority(clusterToken, url, authentication, gateway, sslEnabled); Optional("ca", ca);
        Flag("sslRejectUnauthorized", true);
    }
    private void ClusterAuthority(string? clusterToken, string? url, NativeKubernetesAuthentication? authentication,
        NativeGatewayOptions? gateway, bool? sslEnabled)
    {
        if (authentication is { } invalid && !Enum.IsDefined(invalid))
        {
            Dispose(); throw new ArgumentException("Unknown native Kubernetes authentication.");
        }
        if (authentication is { } method)
            Text("authMethod", method switch
            {
                NativeKubernetesAuthentication.Api => "api",
                NativeKubernetesAuthentication.Gateway => "gateway",
                _ => throw new ArgumentException("Unknown native Kubernetes authentication.")
            });
        Optional("clusterToken", clusterToken);
        if (url is not null)
        {
            if (url.Length == 0) Optional("url", url);
            else SafeUri("url", url);
        }
        Options(gateway);
        if (sslEnabled is { } enabled) Flag("sslEnabled", enabled);
    }
}
/// <summary>Owned LDAP definition inputs with distinct static rotation and dynamic lifecycle forms.</summary>
public sealed class NativeLdapDefinitionProfile : InfisicalDynamicProfile
{
    private NativeLdapDefinitionProfile(string url, string bindDn, string bindPassword,
        string rotationLdif, string? ca) : base(InfisicalDynamicProvider.Ldap)
    {
        Text("credentialType", "static"); Text("url", url); Text("binddn", bindDn);
        Text("bindpass", bindPassword); Text("rotationLdif", rotationLdif); Optional("ca", ca);
    }
    /// <summary>Copies static-account bind credentials and rotation LDIF; LDIF is not executed locally.</summary>
    public static NativeLdapDefinitionProfile ForStaticAccount(string url, string bindDn, string bindPassword,
        string rotationLdif, string? ca = null) => new(url, bindDn, bindPassword, rotationLdif, ca);
    /// <summary>Copies dynamic-account creation/revocation and optional rollback LDIF plus bind/TLS inputs.</summary>
    public NativeLdapDefinitionProfile(string url, string bindDn, string bindPassword, string creationLdif,
        string revocationLdif, string? rollbackLdif = null, string? ca = null) : base(InfisicalDynamicProvider.Ldap)
    {
        Text("credentialType", "dynamic"); Text("url", url); Text("binddn", bindDn); Text("bindpass", bindPassword);
        Text("creationLdif", creationLdif); Text("revocationLdif", revocationLdif);
        Optional("rollbackLdif", rollbackLdif); Optional("ca", ca);
    }
}
/// <summary>Closed native TOTP digest selection; the SDK does not generate an OTP locally.</summary>
public enum NativeTotpAlgorithm { /** <summary>SHA-1.</summary> */ Sha1, /** <summary>SHA-256.</summary> */ Sha256, /** <summary>SHA-512.</summary> */ Sha512 }
/// <summary>Owned TOTP definition inputs using an explicit manual secret or provisioning URL.</summary>
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
    /// <summary>Copies a manual secret and selected digest, with optional positive digit count and period.</summary>
    public static NativeTotpDefinitionProfile ForManualSecret(string secret,
        NativeTotpAlgorithm algorithm = NativeTotpAlgorithm.Sha1, int? digits = null, int? period = null) =>
        new(secret, algorithm, digits, period);
    /// <summary>Copies an absolute provisioning URL without URI user-info; no URL is fetched locally.</summary>
    public NativeTotpDefinitionProfile(string provisioningUrl) : base(InfisicalDynamicProvider.Totp)
    {
        Text("configType", "url"); SafeUri("url", provisioningUrl);
    }
}
/// <summary>Owned SSH principal and optional key-algorithm inputs; no local key generation or issuance.</summary>
public sealed class NativeSshDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Validates closed algorithms and copies a bounded nonempty principal list.</summary>
    public NativeSshDefinitionProfile(IReadOnlyList<string> principals, NativeSshKeyAlgorithm? keyAlgorithm = null,
        NativeSshKeyAlgorithm? caKeyAlgorithm = null) : base(InfisicalDynamicProvider.Ssh)
    {
        // Validate both enum values before allocating protected principals.
        string? key = keyAlgorithm is { } algorithm ? Algorithm(algorithm) : null;
        string? ca = caKeyAlgorithm is { } caAlgorithm ? Algorithm(caAlgorithm) : null;
        Strings("principals", principals); Optional("keyAlgorithm", key); Optional("caKeyAlgorithm", ca);
    }
    private static string Algorithm(NativeSshKeyAlgorithm value) => value switch
    {
        NativeSshKeyAlgorithm.Rsa2048 => "RSA_2048",
        NativeSshKeyAlgorithm.Rsa4096 => "RSA_4096",
        NativeSshKeyAlgorithm.EcPrime256v1 => "EC_prime256v1",
        NativeSshKeyAlgorithm.EcSecp384r1 => "EC_secp384r1",
        NativeSshKeyAlgorithm.Ed25519 => "ED25519",
        _ => throw new ArgumentException("Unknown native SSH key algorithm.")
    };
}
/// <summary>Owned IBM API Connect authority and resource selectors with optional copied gateway options.</summary>
public sealed class NativeIbmApiDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies API/client credentials and explicit organization/catalog/application coordinates without I/O.</summary>
    public NativeIbmApiDefinitionProfile(string apiKey, string applicationId, string clientId, string clientSecret,
        string organizationId, string catalogId, string consumerOrganizationId, string instanceUrl,
        NativeGatewayOptions? gateway = null)
        : base(InfisicalDynamicProvider.IbmApiConnect)
    {
        Text("apiKey", apiKey); Text("appId", applicationId); Text("clientId", clientId); Text("clientSecret", clientSecret);
        Text("orgId", organizationId); Text("catalogId", catalogId); Text("consumerOrgId", consumerOrganizationId);
        SafeUri("instanceUrl", instanceUrl);
        Options(gateway);
    }
}
/// <summary>Explicit native OAuth client-secret authentication method.</summary>
public enum NativeOauthClientAuthentication { /** <summary>Client secret via HTTP Basic.</summary> */ Basic, /** <summary>Client secret in POST fields.</summary> */ Post }
/// <summary>Owned native client-credentials OAuth definition, not a host-side OAuth client.</summary>
public sealed class NativeOauthDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies client authority, absolute token/revocation URLs and at most 20 typed extra parameters.</summary>
    public NativeOauthDefinitionProfile(string clientId, string clientSecret, NativeOauthClientAuthentication method,
        string tokenUrl, string revocationUrl, string? scope = null,
        IReadOnlyList<NativeOauthExtraParameter>? extraParameters = null) : base(InfisicalDynamicProvider.Oauth2)
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
        ObjectOptions("extraParams", extraParameters, 20);
    }
}
/// <summary>Owned Tailscale inputs with explicit authority and auth-key, federated-key or OAuth-key branches.</summary>
public sealed class NativeTailscaleDefinitionProfile : InfisicalDynamicProfile
{
    private NativeTailscaleDefinitionProfile(string authType, string? apiKey, string? clientId,
        string? clientSecret, string? issuer, string? subject, IReadOnlyList<string>? scopes, NativeTailscaleOptions? options)
        : base(InfisicalDynamicProvider.Tailscale)
    {
        if (options?.HasAuthKeyFlags == true && authType != "auth_keys" ||
            options?.HasAudience == true && authType != "federated_keys")
            throw new ArgumentException("Unsupported native Tailscale branch options.");
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
        Options(options);
    }
    /// <summary>Copies OAuth authority for native auth-key creation, including optional auth-key flags.</summary>
    public static NativeTailscaleDefinitionProfile ForOAuthAuthority(string clientId, string clientSecret,
        NativeTailscaleOptions? options = null) =>
        new("auth_keys", null, clientId, clientSecret, null, null, null, options);
    /// <summary>Copies API-key authority and explicit issuer/subject/scopes for native federated keys.</summary>
    public static NativeTailscaleDefinitionProfile ForFederatedApiKey(string apiKey, string issuer, string subject,
        IReadOnlyList<string> scopes, NativeTailscaleOptions? options = null) =>
        new("federated_keys", apiKey, null, null, issuer, subject, scopes, options);
    /// <summary>Copies OAuth authority and issuer/subject/scopes for native federated keys.</summary>
    public static NativeTailscaleDefinitionProfile ForFederatedOAuth(string clientId, string clientSecret,
        string issuer, string subject, IReadOnlyList<string> scopes, NativeTailscaleOptions? options = null) =>
        new("federated_keys", null, clientId, clientSecret, issuer, subject, scopes, options);
    /// <summary>Copies API-key authority and scopes for native OAuth-key creation.</summary>
    public static NativeTailscaleDefinitionProfile ForOAuthKeyApiKey(string apiKey, IReadOnlyList<string> scopes,
        NativeTailscaleOptions? options = null) =>
        new("oauth_keys", apiKey, null, null, null, null, scopes, options);
    /// <summary>Copies OAuth authority and scopes for native OAuth-key creation.</summary>
    public static NativeTailscaleDefinitionProfile ForOAuthKeyOAuth(string clientId, string clientSecret,
        IReadOnlyList<string> scopes, NativeTailscaleOptions? options = null) =>
        new("oauth_keys", null, clientId, clientSecret, null, null, scopes, options);
    /// <summary>Copies API-key authority and explicit auth-key selectors/flags; no key is created by construction.</summary>
    public NativeTailscaleDefinitionProfile(string apiKey, string? tailnet = null, bool reusable = false,
        bool preauthorized = false, IReadOnlyList<string>? tags = null, string? description = null)
        : base(InfisicalDynamicProvider.Tailscale)
    {
        Text("authType", "auth_keys"); Text("auth.method", "api_key"); Text("auth.apiKey", apiKey);
        Optional("tailnet", tailnet); Flag("reusable", reusable); Flag("preauthorized", preauthorized);
        Optional("description", description, 50); if (tags is not null) { Strings("tags", tags, true); }
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
