using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Dynamic;

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
        GC.SuppressFinalize(this);
    }
    private protected virtual void DisposeAdditional() { }
    /// <summary>Returns a fixed label without native inputs, credentials or coordinates.</summary>
    public sealed override string ToString() => "[InfisicalDynamicProfile]";
}
