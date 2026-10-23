using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Native account/policy observations only; no authentication or settlement proof.
internal sealed class InfisicalMysqlIdentityCatalog : IInfisicalRotationIdentityCatalogObserver
{
    internal delegate Task<(int ExitCode, string Output)> QueryProcess(string query,
        IReadOnlyList<string> arguments, IReadOnlyDictionary<string, string> environment, CancellationToken token);

    private readonly (string Host, int Port, string Database) binding;
    private readonly string username, password, principal, rootCertificate;
    private readonly int timeoutSeconds;
    private readonly QueryProcess run;

    internal InfisicalMysqlIdentityCatalog(JsonElement input, QueryProcess? process = null)
    {
        try
        {
            string[] fields = ["host", "port", "database", "username", "password", "principal", "rootCertificate", "timeoutSeconds"];
            if (input.ValueKind != JsonValueKind.Object || input.EnumerateObject().Count() != fields.Length ||
                !input.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(fields))
                throw new NativeCaseFailureException("missing-input");
            string host = input.GetProperty("host").GetString()!;
            int port = input.GetProperty("port").GetInt32();
            string database = input.GetProperty("database").GetString()!;
            username = input.GetProperty("username").GetString()!;
            password = input.GetProperty("password").GetString()!;
            principal = input.GetProperty("principal").GetString()!;
            rootCertificate = input.GetProperty("rootCertificate").GetString()!;
            timeoutSeconds = input.GetProperty("timeoutSeconds").GetInt32();
            bool ip = host is not null && IPAddress.TryParse(host, out _) &&
                host.All(c => char.IsAsciiHexDigit(c) || c is '.' or ':');
            bool dns = host is { Length: > 0 and <= 253 } && Uri.CheckHostName(host) == UriHostNameType.Dns &&
                host.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.');
            if ((!ip && !dns) || port is < 1 or > 65535 || !Identifier(database, 64) ||
                !Identifier(username, 32) ||
                password is not { Length: > 0 and <= 4096 } || password.Any(char.IsControl) ||
                principal is not { Length: > 0 and <= 288 } || principal.Any(char.IsControl) ||
                !principal.StartsWith(username + "@", StringComparison.Ordinal) || principal.Length == username.Length + 1 ||
                rootCertificate is not { Length: > 0 and <= 4096 } || rootCertificate.Any(char.IsControl) ||
                !Path.IsPathFullyQualified(rootCertificate) || timeoutSeconds is < 1 or > 60)
                throw new NativeCaseFailureException("missing-input");
            binding = (host!, port, database);
        }
        catch (Exception error) when (error is InvalidOperationException or KeyNotFoundException or FormatException or ArgumentException)
        {
            throw new NativeCaseFailureException("missing-input");
        }
        run = process ?? (static (query, arguments, environment, token) =>
            OwnedProcess.RunAsync("mysql", arguments, AppContext.BaseDirectory, environment, token, query));
    }

    public async ValueTask<RotationIdentityCatalogFacts> InspectIdentityCatalogAsync(RotationBackendCoordinate coordinate,
        IReadOnlyList<string> usernames, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        string[] requested = usernames?.Take(3).ToArray() ?? [];
        if (coordinate is null || coordinate.Profile != InfisicalRotationProfile.MysqlCredentials ||
            (coordinate.Host, coordinate.Port, coordinate.Database) != binding || !Identifier(coordinate.Account, 128) ||
            requested.Length != 2 || requested.Distinct(StringComparer.Ordinal).Count() != 2 ||
            requested.Any(n => !Identifier(n, 32)))
            throw Unavailable();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
        byte[] data = JsonSerializer.SerializeToUtf8Bytes(requested);
        string query;
        try
        {
            query = """
                SELECT JSON_OBJECT('principal', CURRENT_USER(), 'database', DATABASE(),
                  'accounts', (SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT('username', u.User, 'host', u.Host,
                    'authenticationPlugin', u.plugin)), JSON_ARRAY()) FROM mysql.user AS u
                    JOIN JSON_TABLE(CONVERT(UNHEX('
                """.TrimEnd() + Convert.ToHexString(data) + """
                ') USING utf8mb4), '$[*]' COLUMNS(name VARCHAR(32) PATH '$')) AS q
                    ON CAST(u.User AS BINARY) = CAST(q.name AS BINARY)),
                  'plugins', (SELECT COALESCE(JSON_ARRAYAGG(PLUGIN_NAME), JSON_ARRAY())
                    FROM information_schema.PLUGINS WHERE PLUGIN_TYPE = 'VALIDATE PASSWORD' AND PLUGIN_STATUS = 'ACTIVE'),
                  'components', (SELECT COALESCE(JSON_ARRAYAGG(component_urn), JSON_ARRAY()) FROM mysql.component),
                  'variables', (SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT('name', VARIABLE_NAME, 'value', VARIABLE_VALUE)), JSON_ARRAY())
                    FROM performance_schema.global_variables WHERE LEFT(VARIABLE_NAME, 18) = 'validate_password.'
                      OR LEFT(VARIABLE_NAME, 18) = 'validate_password_'));

                """;
        }
        finally { CryptographicOperations.ZeroMemory(data); }
        try
        {
            DirectoryInfo home = Directory.CreateTempSubdirectory("secretkit-mysql-catalog-");
            try
            {
                string[] arguments = ["--no-defaults", "--no-login-paths", "--protocol=TCP", "--ssl-mode=VERIFY_IDENTITY",
                    "--ssl-ca=" + rootCertificate, "--host=" + binding.Host, "--port=" + binding.Port.ToString(CultureInfo.InvariantCulture),
                    "--database=" + binding.Database, "--user=" + username, "--batch", "--raw", "--skip-column-names",
                    "--skip-reconnect", "--local-infile=0", "--binary-mode", "--skip-auto-rehash",
                    "--default-character-set=utf8mb4", "--connect-timeout=" + timeoutSeconds.ToString(CultureInfo.InvariantCulture)];
                var environment = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["HOME"] = home.FullName,
                    ["APPDATA"] = home.FullName,
                    ["MYSQL_PWD"] = password,
                    ["MYSQL_TEST_LOGIN_FILE"] = Path.Combine(home.FullName, "unused-login-file")
                };
                linked.Token.ThrowIfCancellationRequested();
                var result = await run(query, arguments, environment, linked.Token).ConfigureAwait(false);
                linked.Token.ThrowIfCancellationRequested();
                if (result.ExitCode != 0 || result.Output is null || result.Output.Length > 65536) throw Unavailable();
                using JsonDocument document = JsonDocument.Parse(result.Output,
                    new JsonDocumentOptions { MaxDepth = 5, AllowDuplicateProperties = false });
                JsonElement root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 6 ||
                    root.GetProperty("principal").GetString() != principal || root.GetProperty("database").GetString() != binding.Database)
                    throw Unavailable();
                string[] plugins = Strings(root.GetProperty("plugins"));
                string[] components = Strings(root.GetProperty("components"));
                bool plugin = plugins.SequenceEqual(["validate_password"]) && components.Length == 0;
                bool component = plugins.Length == 0 && components.SequenceEqual(["file://component_validate_password"]);
                bool none = plugins.Length == 0 && components.Length == 0;
                if (!plugin && !component && !none) throw Unavailable();
                JsonElement rows = root.GetProperty("accounts");
                if (rows.ValueKind != JsonValueKind.Array || rows.GetArrayLength() > 128) throw Unavailable();
                var accounts = new List<MysqlRotationAccountFacts>();
                foreach (JsonElement row in rows.EnumerateArray())
                {
                    if (row.ValueKind != JsonValueKind.Object || row.EnumerateObject().Count() != 3) throw Unavailable();
                    accounts.Add(new(row.GetProperty("username").GetString()!, row.GetProperty("host").GetString()!,
                        row.GetProperty("authenticationPlugin").GetString()!));
                }
                JsonElement variables = root.GetProperty("variables");
                if (variables.ValueKind != JsonValueKind.Array || variables.GetArrayLength() > 16) throw Unavailable();
                var values = new Dictionary<string, string>(StringComparer.Ordinal);
                string prefix = component ? "validate_password." : "validate_password_";
                foreach (JsonElement variable in variables.EnumerateArray())
                {
                    if (variable.ValueKind != JsonValueKind.Object || variable.EnumerateObject().Count() != 2) throw Unavailable();
                    string name = variable.GetProperty("name").GetString()!;
                    string value = variable.GetProperty("value").GetString()!;
                    if (name is null || value is null || !name.StartsWith(prefix, StringComparison.Ordinal) ||
                        !values.TryAdd(name[prefix.Length..], value)) throw Unavailable();
                }
                string[] required = ["policy", "length", "check_user_name", "mixed_case_count", "number_count", "special_char_count", "dictionary_file"];
                if (none ? values.Count != 0 : !values.Keys.ToHashSet(StringComparer.Ordinal)
                    .SetEquals(component ? [.. required, "changed_characters_percentage"] : required))
                    throw Unavailable();
                int Number(string key) => int.TryParse(values[key], NumberStyles.None, CultureInfo.InvariantCulture, out int n) && n >= 0
                    ? n : throw Unavailable();
                int? policy = none ? null : values["policy"] switch
                {
                    "0" or "LOW" => 0,
                    "1" or "MEDIUM" => 1,
                    "2" or "STRONG" => 2,
                    _ => throw Unavailable()
                };
                bool? checkUser = none ? null : values["check_user_name"] switch
                {
                    "ON" or "1" => true,
                    "OFF" or "0" => false,
                    _ => throw Unavailable()
                };
                var passwordPolicy = new MysqlPasswordPolicyFacts(true, plugins, components, policy,
                    none ? null : Number("length"), checkUser, none ? null : Number("mixed_case_count"),
                    none ? null : Number("number_count"), none ? null : Number("special_char_count"),
                    none ? null : values["dictionary_file"], component ? Number("changed_characters_percentage") : null);
                var facts = new RotationIdentityCatalogFacts(coordinate, requested,
                    new(binding.Database, true, accounts.ToArray(), passwordPolicy), null);
                if (!RotationSqlIdentityEvidence.Bound(facts, coordinate, requested) || !RotationSqlIdentityEvidence.PolicyEstablished(facts))
                    throw Unavailable();
                return facts;
            }
            finally { home.Delete(recursive: true); }
        }
        catch (OperationCanceledException)
        {
            token.ThrowIfCancellationRequested();
            throw new NativeCaseFailureException(deadline.IsCancellationRequested ? "deadline-exceeded" : "observer-unavailable");
        }
        catch (Exception error) when (error is JsonException or IOException or Win32Exception or InvalidOperationException or
            KeyNotFoundException or UnauthorizedAccessException or ArgumentException)
        {
            token.ThrowIfCancellationRequested();
            throw Unavailable();
        }
    }

    private static string[] Strings(JsonElement array)
    {
        if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() > 64) throw Unavailable();
        string[] values = array.EnumerateArray().Select(v => v.GetString()!).ToArray();
        if (values.Any(string.IsNullOrEmpty) || values.Distinct(StringComparer.Ordinal).Count() != values.Length) throw Unavailable();
        return values;
    }

    private static bool Identifier(string? value, int length) => value is { Length: > 0 } && value.Length <= length &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.');
    private static NativeCaseFailureException Unavailable() => new("observer-unavailable");
    public override string ToString() => "[MysqlIdentityCatalog]";
}
