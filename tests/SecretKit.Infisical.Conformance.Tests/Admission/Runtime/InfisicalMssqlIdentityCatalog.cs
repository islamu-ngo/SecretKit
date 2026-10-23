using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Complete native identity observations only, not authentication or settlement.
internal sealed class InfisicalMssqlIdentityCatalog : IInfisicalRotationIdentityCatalogObserver
{
    internal delegate Task<(int ExitCode, string Output)> QueryProcess(string query,
        IReadOnlyList<string> arguments, IReadOnlyDictionary<string, string> environment, CancellationToken token);

    private readonly (string Host, int Port, string Database) binding;
    private readonly string username, password, serverIdentity;
    private readonly int timeoutSeconds;
    private readonly QueryProcess run;
    private static readonly Encoding Utf16 = new UnicodeEncoding(false, false, true);

    internal InfisicalMssqlIdentityCatalog(JsonElement input, QueryProcess? process = null)
    {
        try
        {
            Fields(input, "host", "port", "database", "username", "password", "serverIdentity", "timeoutSeconds");
            string host = input.GetProperty("host").GetString()!;
            int port = input.GetProperty("port").GetInt32();
            string database = input.GetProperty("database").GetString()!;
            username = input.GetProperty("username").GetString()!;
            password = input.GetProperty("password").GetString()!;
            serverIdentity = input.GetProperty("serverIdentity").GetString()!;
            timeoutSeconds = input.GetProperty("timeoutSeconds").GetInt32();
            bool ip = host is not null && IPAddress.TryParse(host, out _) &&
                host.All(c => char.IsAsciiHexDigit(c) || c is '.' or ':');
            bool dns = host is { Length: > 0 and <= 253 } && Uri.CheckHostName(host) == UriHostNameType.Dns &&
                host.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.');
            if ((!ip && !dns) || port is < 1 or > 65535 || !Name(database) || !Name(username) ||
                database.StartsWith('-') || username.StartsWith('-') ||
                !Name(serverIdentity) || password is not { Length: > 0 and <= 4096 } ||
                password.Any(char.IsControl) || timeoutSeconds is < 1 or > 60)
                throw Unavailable();
            binding = (host!, port, database);
        }
        catch (Exception error) when (error is NativeCaseFailureException or InvalidOperationException or
            KeyNotFoundException or FormatException or ArgumentException)
        {
            throw new NativeCaseFailureException("missing-input");
        }
        run = process ?? (static (query, arguments, environment, token) =>
            OwnedProcess.RunAsync("/opt/mssql-tools18/bin/sqlcmd", arguments, AppContext.BaseDirectory, environment, token, query));
    }

    public async ValueTask<RotationIdentityCatalogFacts> InspectIdentityCatalogAsync(RotationBackendCoordinate coordinate,
        IReadOnlyList<string> usernames, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        string[] requested = usernames?.Take(3).ToArray() ?? [];
        if (coordinate is null || coordinate.Profile != InfisicalRotationProfile.MssqlCredentials ||
            (coordinate.Host, coordinate.Port, coordinate.Database) != binding || !Name(coordinate.Account) ||
            requested.Length != 2 || requested.Distinct(StringComparer.Ordinal).Count() != 2 || requested.Any(n => !Name(n)))
            throw Unavailable();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
        try
        {
            var logins = new List<MssqlRotationLoginFacts>();
            var users = new List<MssqlRotationUserFacts>();
            (string Version, int Edition, string Sid)? source = null;
            foreach (bool server in new[] { true, false })
            {
                string database = server ? "master" : binding.Database;
                string view = server ? "sys.server_principals" : "sys.database_principals";
                string rowColumns = server
                    ? """
                        CONVERT(varchar(max), CONVERT(varbinary(max), p.type_desc), 2) AS [type],
                        l.is_policy_checked AS [policy], l.is_expiration_checked AS [expiration], p.is_disabled AS [disabled]
                        """
                    : """
                        CONVERT(varchar(max), CONVERT(varbinary(max), p.type_desc), 2) AS [type],
                        CONVERT(varchar(max), CONVERT(varbinary(max), p.authentication_type_desc), 2) AS [authentication]
                        """;
                // Subject data is UTF-16 bytes, never SQL text. Column collation wins
                // native matches; pair equality explicitly uses the observed catalog.
                string query = $$"""
                    SET NOCOUNT ON;
                    DECLARE @a nvarchar(128) = CONVERT(nvarchar(128), 0x{{Convert.ToHexString(Utf16.GetBytes(requested[0]))}}),
                            @b nvarchar(128) = CONVERT(nvarchar(128), 0x{{Convert.ToHexString(Utf16.GetBytes(requested[1]))}});
                    DECLARE @column nvarchar(128) = (SELECT collation_name FROM sys.all_columns
                        WHERE object_id = OBJECT_ID(N'{{view}}') AND name = N'name');
                    DECLARE @catalog nvarchar(128) = CONVERT(nvarchar(128),
                        SQL_VARIANT_PROPERTY(CAST(N'' COLLATE CATALOG_DEFAULT AS nvarchar(128)), 'Collation'));
                    DECLARE @json nvarchar(max) = (
                        SELECT
                        CONVERT(varchar(max), CONVERT(varbinary(max), CONVERT(nvarchar(128), SERVERPROPERTY('ServerName'))), 2) AS [serverIdentity],
                        CONVERT(varchar(max), CONVERT(varbinary(max), CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion'))), 2) AS [productVersion],
                        CONVERT(int, SERVERPROPERTY('EngineEdition')) AS [engineEdition],
                        CONVERT(varchar(max), CONVERT(varbinary(max), DB_NAME()), 2) AS [database],
                        CONVERT(varchar(max), CONVERT(varbinary(max), ORIGINAL_LOGIN()), 2) AS [originalLogin],
                        CONVERT(varchar(max), SUSER_SID(ORIGINAL_LOGIN()), 2) AS [originalSid],
                        CONVERT(varchar(max), CONVERT(varbinary(max), SUSER_SNAME()), 2) AS [currentLogin],
                        CONVERT(varchar(max), SUSER_SID(), 2) AS [currentSid],
                        CONVERT(varchar(max), CONVERT(varbinary(max), USER_NAME()), 2) AS [databaseUser],
                        IS_SRVROLEMEMBER(N'sysadmin') AS [sysadmin],
                        CONVERT(varchar(max), CONVERT(varbinary(max), @column), 2) AS [columnCollation],
                        CONVERT(varchar(max), CONVERT(varbinary(max), @catalog), 2) AS [catalogCollation],
                        CAST(CASE WHEN @a COLLATE CATALOG_DEFAULT = @b COLLATE CATALOG_DEFAULT THEN 0 ELSE 1 END AS bit) AS [namesDistinct],
                        JSON_QUERY((SELECT CONVERT(varchar(max), CONVERT(varbinary(max), p.name), 2) AS [name],
                            CONVERT(varchar(max), p.sid, 2) AS [sid], {{rowColumns}}
                            FROM {{view}} AS p
                            {{(server ? "LEFT JOIN sys.sql_logins AS l ON l.principal_id = p.principal_id" : "")}}
                            WHERE p.name = @a OR p.name = @b
                            FOR JSON PATH, INCLUDE_NULL_VALUES)) AS [principals]
                        FOR JSON PATH, INCLUDE_NULL_VALUES, WITHOUT_ARRAY_WRAPPER);
                    IF @json IS NULL OR DATALENGTH(@json) > 96000
                        THROW 50000, 'Catalog evidence exceeds budget.', 1;
                    SELECT @json;

                    """;
                string host = binding.Host.Contains(':', StringComparison.Ordinal) ? "[" + binding.Host + "]" : binding.Host;
                string[] arguments = ["-S", "tcp:" + host + "," + binding.Port.ToString(CultureInfo.InvariantCulture),
                    "-U", username, "-d", database, "-Nm", "-h", "-1", "-y", "0", "-w", "60000", "-b", "-r", "1", "-x",
                    "-l", timeoutSeconds.ToString(CultureInfo.InvariantCulture)];
                var environment = new Dictionary<string, string>(StringComparer.Ordinal) { ["SQLCMDPASSWORD"] = password };
                linked.Token.ThrowIfCancellationRequested();
                // Await the actual query, including its cancellation cleanup, before
                // propagating cancellation or starting the other catalog.
                var result = await run(query, arguments, environment, linked.Token).ConfigureAwait(false);
                linked.Token.ThrowIfCancellationRequested();
                if (result.ExitCode != 0 || result.Output is null || result.Output.Length > 48000) throw Unavailable();
                using JsonDocument document = JsonDocument.Parse(result.Output,
                    new JsonDocumentOptions { MaxDepth = 4, AllowDuplicateProperties = false });
                JsonElement observed = document.RootElement;
                Fields(observed, "serverIdentity", "productVersion", "engineEdition", "database", "originalLogin",
                    "originalSid", "currentLogin", "currentSid", "databaseUser", "sysadmin", "columnCollation",
                    "catalogCollation", "namesDistinct", "principals");
                string version = Text(observed.GetProperty("productVersion"));
                int edition = observed.GetProperty("engineEdition").GetInt32();
                byte[] sid = Sid(observed.GetProperty("originalSid"));
                string column = Text(observed.GetProperty("columnCollation"));
                if (Text(observed.GetProperty("serverIdentity")) != serverIdentity ||
                    Text(observed.GetProperty("database")) != database ||
                    Text(observed.GetProperty("originalLogin")) != username ||
                    Text(observed.GetProperty("currentLogin")) != username ||
                    sid.Length == 0 || !sid.AsSpan().SequenceEqual(Sid(observed.GetProperty("currentSid"))) ||
                    Text(observed.GetProperty("databaseUser")) != "dbo" ||
                    observed.GetProperty("sysadmin").GetInt32() != 1 || edition is not (2 or 3 or 4) ||
                    column != Text(observed.GetProperty("catalogCollation")) ||
                    !observed.GetProperty("namesDistinct").GetBoolean())
                    throw Unavailable();
                var identity = (version, edition, Convert.ToHexString(sid));
                if (source is not null && source.Value != identity) throw Unavailable();
                source = identity;
                JsonElement rows = observed.GetProperty("principals");
                if (rows.ValueKind != JsonValueKind.Array || rows.GetArrayLength() > 2) throw Unavailable();
                foreach (JsonElement row in rows.EnumerateArray())
                {
                    if (server) Fields(row, "name", "sid", "type", "policy", "expiration", "disabled");
                    else Fields(row, "name", "sid", "type", "authentication");
                    string name = Text(row.GetProperty("name"));
                    if (!requested.Contains(name, StringComparer.Ordinal)) throw Unavailable();
                    byte[] principalSid = Sid(row.GetProperty("sid"));
                    string type = Text(row.GetProperty("type"));
                    if (server)
                        logins.Add(new(name, principalSid, type, Flag(row.GetProperty("policy")),
                            Flag(row.GetProperty("expiration")), row.GetProperty("disabled").GetBoolean()));
                    else
                        users.Add(new(name, principalSid, type, Text(row.GetProperty("authentication"))));
                }
            }
            var facts = new RotationIdentityCatalogFacts(coordinate, requested, null,
                new(binding.Database, true, true, logins.ToArray(), users.ToArray()));
            if (!RotationSqlIdentityEvidence.Bound(facts, coordinate, requested)) throw Unavailable();
            return facts;
        }
        catch (OperationCanceledException)
        {
            token.ThrowIfCancellationRequested();
            throw new NativeCaseFailureException(deadline.IsCancellationRequested ? "deadline-exceeded" : "observer-unavailable");
        }
        catch (Exception error) when (error is JsonException or IOException or Win32Exception or InvalidOperationException or
            KeyNotFoundException or UnauthorizedAccessException or ArgumentException or FormatException or OverflowException)
        {
            token.ThrowIfCancellationRequested();
            throw Unavailable();
        }
    }

    private static void Fields(JsonElement value, params string[] fields)
    {
        if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Count() != fields.Length ||
            !value.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(fields))
            throw Unavailable();
    }

    private static string Text(JsonElement value)
    {
        string? hex = value.GetString();
        if (hex is null || hex.Length is 0 or > 512 || hex.Length % 4 != 0) throw Unavailable();
        string text = Utf16.GetString(Convert.FromHexString(hex));
        if (!Name(text)) throw Unavailable();
        return text;
    }

    private static byte[] Sid(JsonElement value)
    {
        string? hex = value.GetString();
        if (hex is null || hex.Length > 170) throw Unavailable();
        return Convert.FromHexString(hex);
    }

    private static bool? Flag(JsonElement value) => value.ValueKind == JsonValueKind.Null ? null : value.GetBoolean();
    private static bool Name(string? value)
    {
        if (value is not { Length: > 0 and <= 128 } || value.Any(char.IsControl)) return false;
        try { return Utf16.GetByteCount(value) > 0; }
        catch (EncoderFallbackException) { return false; }
    }
    private static NativeCaseFailureException Unavailable() => new("observer-unavailable");
    public override string ToString() => "[MssqlIdentityCatalog]";
}
