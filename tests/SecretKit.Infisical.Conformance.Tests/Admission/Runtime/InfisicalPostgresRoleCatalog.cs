using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Collects role presence only. Authentication, ownership and settlement require
// their own independently selected witnesses.
internal sealed class InfisicalPostgresRoleCatalog : IInfisicalDynamicUsernameObserver
{
    internal delegate Task<(int ExitCode, string Output)> QueryProcess(string query,
        IReadOnlyDictionary<string, string> environment, CancellationToken token);

    private readonly DynamicUsernameCoordinate binding;
    private readonly string username, password, rootCertificate;
    private readonly int timeoutSeconds;
    private readonly QueryProcess run;

    internal InfisicalPostgresRoleCatalog(JsonElement input, QueryProcess? process = null)
    {
        try
        {
            string[] fields = ["host", "port", "database", "username", "password", "timeoutSeconds", "rootCertificate"];
            if (input.ValueKind != JsonValueKind.Object ||
                input.EnumerateObject().Count() != fields.Length ||
                !input.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(fields))
                throw new NativeCaseFailureException("missing-input");
            string host = input.GetProperty("host").GetString()!;
            string database = input.GetProperty("database").GetString()!;
            username = input.GetProperty("username").GetString()!;
            password = input.GetProperty("password").GetString()!;
            rootCertificate = input.GetProperty("rootCertificate").GetString()!;
            int port = input.GetProperty("port").GetInt32();
            timeoutSeconds = input.GetProperty("timeoutSeconds").GetInt32();
            bool ip = host is not null && IPAddress.TryParse(host, out _) &&
                host.All(c => char.IsAsciiHexDigit(c) || c is '.' or ':');
            bool dns = host is { Length: > 0 and <= 253 } &&
                Uri.CheckHostName(host) == UriHostNameType.Dns &&
                host.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.');
            if ((!ip && !dns) || port is < 1 or > 65535 || !Identifier(database) || !Identifier(username) ||
                password is not { Length: > 0 and <= 4096 } || password.Any(char.IsControl) ||
                rootCertificate is not { Length: > 0 and <= 4096 } ||
                rootCertificate.Any(char.IsControl) || !Path.IsPathFullyQualified(rootCertificate) ||
                timeoutSeconds is < 1 or > 60)
                throw new NativeCaseFailureException("missing-input");
            binding = new(NativeSqlEngine.Postgres, host!, port, database);
        }
        catch (Exception error) when (error is InvalidOperationException or KeyNotFoundException or
            FormatException or ArgumentException)
        {
            throw new NativeCaseFailureException("missing-input");
        }
        run = process ?? (static (query, environment, token) => OwnedProcess.RunAsync("psql",
            ["--no-psqlrc", "--no-password", "--quiet", "--tuples-only", "--no-align",
                "--set=ON_ERROR_STOP=on", "--dbname=require_auth=scram-sha-256"],
            AppContext.BaseDirectory, environment, token, query));
    }

    public async ValueTask<DynamicUsernameFacts> InspectUsernamesAsync(DynamicUsernameCoordinate coordinate,
        IReadOnlyList<string> usernames, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        string[] requested = usernames?.Take(65).ToArray() ?? [];
        if (coordinate != binding || requested.Length is < 1 or > 64 ||
            requested.Any(n => string.IsNullOrWhiteSpace(n) || n.Any(char.IsControl) || Encoding.UTF8.GetByteCount(n) > 63) ||
            requested.Distinct(StringComparer.Ordinal).Count() != requested.Length)
            throw Unavailable();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
        byte[] data = JsonSerializer.SerializeToUtf8Bytes(requested);
        string query;
        try
        {
            query = """
                SELECT jsonb_build_object('user', session_user, 'rows',
                    jsonb_agg(jsonb_build_object('name', q.name, 'exists',
                        EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS r
                            WHERE r.rolname::text COLLATE "C" = q.name COLLATE "C"))
                        ORDER BY q.ordinality))
                FROM jsonb_array_elements_text(convert_from(decode('
                """.TrimEnd() + Convert.ToHexString(data) + """
                ', 'hex'), 'UTF8')::jsonb) WITH ORDINALITY AS q(name, ordinality);

                """;
        }
        finally { CryptographicOperations.ZeroMemory(data); }
        try
        {
            DirectoryInfo home = Directory.CreateTempSubdirectory("secretkit-pg-catalog-");
            try
            {
                var environment = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["HOME"] = home.FullName,
                    ["APPDATA"] = home.FullName,
                    ["PGHOST"] = binding.Host,
                    ["PGPORT"] = binding.Port.ToString(CultureInfo.InvariantCulture),
                    ["PGDATABASE"] = binding.Database,
                    ["PGUSER"] = username,
                    ["PGPASSWORD"] = password,
                    ["PGCONNECT_TIMEOUT"] = timeoutSeconds.ToString(CultureInfo.InvariantCulture),
                    ["PGCLIENTENCODING"] = "UTF8",
                    ["PGSSLMODE"] = "verify-full",
                    ["PGSSLROOTCERT"] = rootCertificate,
                    ["PGSSLCERT"] = Path.Combine(home.FullName, "unused-client-cert"),
                    ["PGSSLKEY"] = Path.Combine(home.FullName, "unused-client-key"),
                    ["PGSSLCRL"] = Path.Combine(home.FullName, "unused-crl"),
                    ["PGPASSFILE"] = Path.Combine(home.FullName, "unused-password-file"),
                    ["PGGSSENCMODE"] = "disable",
                    ["PGCHANNELBINDING"] = "require",
                    ["PGOPTIONS"] = "-c search_path=pg_catalog -c default_transaction_read_only=on -c statement_timeout=" +
                        (timeoutSeconds * 1000).ToString(CultureInfo.InvariantCulture)
                };
                linked.Token.ThrowIfCancellationRequested();
                var result = await run(query, environment, linked.Token).ConfigureAwait(false);
                linked.Token.ThrowIfCancellationRequested();
                if (result.ExitCode != 0 || result.Output is null || result.Output.Length > 65536)
                    throw Unavailable();
                using JsonDocument document = JsonDocument.Parse(result.Output,
                    new JsonDocumentOptions { MaxDepth = 4, AllowDuplicateProperties = false });
                JsonElement root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 2 ||
                    root.GetProperty("user").ValueKind != JsonValueKind.String ||
                    root.GetProperty("user").GetString() != username ||
                    root.GetProperty("rows").ValueKind != JsonValueKind.Array ||
                    root.GetProperty("rows").GetArrayLength() != requested.Length)
                    throw Unavailable();
                var existing = new List<string>();
                int index = 0;
                foreach (JsonElement row in root.GetProperty("rows").EnumerateArray())
                {
                    if (row.ValueKind != JsonValueKind.Object || row.EnumerateObject().Count() != 2 ||
                        row.GetProperty("name").ValueKind != JsonValueKind.String ||
                        row.GetProperty("name").GetString() != requested[index] ||
                        row.GetProperty("exists").ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                        throw Unavailable();
                    if (row.GetProperty("exists").GetBoolean()) existing.Add(requested[index]);
                    index++;
                }
                return new(binding, requested, existing.ToArray(), true);
            }
            finally { home.Delete(recursive: true); }
        }
        catch (OperationCanceledException)
        {
            token.ThrowIfCancellationRequested();
            throw new NativeCaseFailureException(deadline.IsCancellationRequested ? "deadline-exceeded" : "observer-unavailable");
        }
        catch (Exception error) when (error is JsonException or IOException or Win32Exception or
            InvalidOperationException or KeyNotFoundException or UnauthorizedAccessException or ArgumentException)
        {
            token.ThrowIfCancellationRequested();
            throw Unavailable();
        }
    }

    private static bool Identifier(string? value) => value is { Length: > 0 and <= 63 } &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.');
    private static NativeCaseFailureException Unavailable() => new("observer-unavailable");
    public override string ToString() => "[PostgresRoleCatalog]";
}
