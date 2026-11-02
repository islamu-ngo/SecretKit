using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Dynamic;

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
