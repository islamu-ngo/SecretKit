using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// This is a wire store, not a request-to-expected-response factory. Configuration,
// encrypted-column stand-in, mappings, accounts and job completion have separate journals.
internal sealed class InfisicalSqlRotationPatchFixture : IDatabaseFixtureFactory, IAsyncDisposable
{
    internal const string Organization = "00000000-0000-0000-0000-000000000001";
    internal const string Date = "2026-10-13T12:00:00.000Z";
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly object gate = new();
    internal readonly Dictionary<string, JsonObject> Projects = [];
    internal readonly Dictionary<string, JsonObject> Configurations = [];
    internal readonly Dictionary<string, string> Statements = [];
    internal readonly Dictionary<(string Project, string Key), string> Mappings = [];
    internal readonly Dictionary<string, string> Accounts = [];
    internal readonly Dictionary<string, Lease> Leases = [];
    internal readonly Dictionary<string, int> Attempts = [];
    internal readonly Dictionary<string, int> Pending = [];
    internal readonly Dictionary<string, TaskCompletionSource> Completion = [];
    internal readonly List<JsonObject> SetupParameters = [];
    internal readonly List<JsonObject> Patches = [];
    internal readonly List<InfisicalSqlRotationPatchSource> Sources = [];
    internal string Mode { get; }
    internal Uri Origin { get; }
    internal int Residual => Configurations.Count + Statements.Count + Mappings.Count + Accounts.Count +
        Pending.Values.Sum() + Leases.Count;
    internal bool BorrowedIntact { get; private set; } = true;
    internal InfisicalSqlRotationPatchFixture(string mode = "good")
    {
        Mode = mode;
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        accept = AcceptAsync();
    }

    public ValueTask<IDatabaseOwnedFixture> CreateAsync(NativeEnvironment environment, NativeCaseDefinition definition,
        string project, JsonElement input, string name, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (gate)
        {
            var lease = new Lease(this, project, name, definition);
            Leases.Add(project, lease);
            Sources.Add(lease.Source);
            return ValueTask.FromResult<IDatabaseOwnedFixture>(lease);
        }
    }

    internal static NativeCaseDefinition Definition(string profile, string variant, string boundary = "independent-effect")
    {
        string operation = $"i.management.{profile}SecretRotationOperations.Update";
        return new(new("Infisical", operation, variant, "local", boundary),
            InfisicalDatabaseFamilies.Bindings[operation].Member);
    }

    internal NativeEnvironment Environment()
    {
        var families = new Dictionary<string, object>();
        foreach (string profile in new[] { "Postgres", "MySql", "MsSql" })
            families.Add($"C08-IM-{profile}SecretRotations", new
            {
                scopes = new Dictionary<string, object>
                {
                    ["local"] = new
                    {
                        organizationId = Organization,
                        administrativeIdentityId = "00000000-0000-0000-0000-000000000002",
                        observerIdentityId = "00000000-0000-0000-0000-000000000003",
                        runtimeIdentityId = "00000000-0000-0000-0000-000000000004"
                    }
                }
            });
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            administrative = "administrative",
            observer = "observer",
            runtime = "runtime",
            denied = "denied",
            families
        }));
    }

    internal async Task<NativeCaseResult> RunAsync(NativeCaseDefinition definition)
    {
        using var environment = Environment();
        var registry = new NativeCaseRegistry();
        InfisicalDatabaseFamilies.Register(registry, environment, [definition], this);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }

    private async Task AcceptAsync()
    {
        try
        {
            while (!shutdown.IsCancellationRequested)
                connections.Add(ServeAsync(await listener.AcceptTcpClientAsync(shutdown.Token)));
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
    }

    private async Task ServeAsync(TcpClient socket)
    {
        using (socket)
        {
            try
            {
                var stream = socket.GetStream();
                List<byte> header = [];
                byte[] one = new byte[1];
                while (header.Count < 32768)
                {
                    if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                    header.Add(one[0]);
                    if (header.Count >= 4 && header[^4] == 13 && header[^3] == 10 &&
                        header[^2] == 13 && header[^1] == 10) break;
                }
                string[] lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n");
                string[] request = lines[0].Split(' ');
                string role = lines.Single(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase)).Split(' ').Last();
                int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?.Split(':')[1] ?? "0");
                if (length is < 0 or > 65536) throw new InvalidOperationException("fixture-input");
                byte[] bytes = new byte[length];
                await stream.ReadExactlyAsync(bytes, shutdown.Token);
                JsonObject body = length == 0 ? new() : JsonNode.Parse(bytes)!.AsObject();
                (int Status, JsonNode Payload) response;
                lock (gate) response = Handle(request[0], new Uri(Origin, request[1]), role, body);
                byte[] payload = Encoding.UTF8.GetBytes(response.Payload.ToJsonString());
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {response.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {payload.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                await stream.WriteAsync(payload, shutdown.Token);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        }
    }

    private static string Text(JsonNode node, string field) => node[field]!.GetValue<string>();
    private static JsonObject Wrap(string field, JsonNode value) => new() { [field] = value.DeepClone() };
    private (int, JsonNode) Handle(string method, Uri uri, string role, JsonObject body)
    {
        if (role == "denied") return (403, new JsonObject());
        string[] path = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var query = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2)).ToDictionary(p => p[0], p => Uri.UnescapeDataString(p[1]));
        if (path[2] == "projects")
        {
            if (path.Length == 3 && method == "POST")
            {
                string id = Guid.NewGuid().ToString();
                var project = new JsonObject
                {
                    ["id"] = id,
                    ["_id"] = id,
                    ["orgId"] = Organization,
                    ["name"] = body["projectName"]!.DeepClone(),
                    ["slug"] = body["slug"]!.DeepClone(),
                    ["type"] = "secret-manager",
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["hasDeleteProtection"] = false,
                    ["environments"] = new JsonArray(),
                    ["deletedEnvironments"] = new JsonArray()
                };
                Projects.Add(id, project);
                return (200, Wrap("project", project));
            }
            if (path[3] == "slug")
            {
                var project = Projects.Values.SingleOrDefault(p => Text(p, "slug") == path[4]);
                return project is null ? (404, new JsonObject()) : (200, project.DeepClone());
            }
            if (!Projects.TryGetValue(path[3], out var selected)) return (404, new JsonObject());
            if (path.Length > 4 && path[4] == "memberships")
                return (200, new JsonObject
                {
                    ["identityMembership"] = new JsonObject
                    {
                        ["id"] = Guid.NewGuid().ToString(),
                        ["identityId"] = path[6],
                        ["projectId"] = path[3],
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date
                    }
                });
            var result = (JsonObject)selected.DeepClone();
            if (method == "DELETE")
            {
                Projects.Remove(path[3]);
                foreach (string field in new[] { "_id", "environments", "deletedEnvironments" }) result.Remove(field);
            }
            return (200, Wrap("project", result));
        }
        if (path[2] == "secrets")
        {
            if (!Mappings.TryGetValue((query["projectId"], Uri.UnescapeDataString(path[^1])), out string? value))
                return (404, new JsonObject());
            return (200, new JsonObject
            {
                ["secret"] = new JsonObject
                {
                    ["id"] = Guid.NewGuid().ToString(),
                    ["secretKey"] = Uri.UnescapeDataString(path[^1]),
                    ["secretValue"] = value,
                    ["workspace"] = query["projectId"],
                    ["environment"] = query["environment"],
                    ["version"] = 1,
                    ["secretValueHidden"] = false
                }
            });
        }
        if (path[2] != "secret-rotations") return (404, new JsonObject());
        if (path.Length == 4 && method == "POST")
        {
            string id = Guid.NewGuid().ToString(), project = Text(body, "projectId");
            Lease lease = Leases[project];
            var row = (JsonObject)body.DeepClone();
            row["id"] = id; row["type"] = path[3];
            row["environment"] = new JsonObject { ["id"] = lease.EnvironmentId, ["name"] = "Owned", ["slug"] = lease.Environment };
            row["folderId"] = lease.FolderId;
            row["folder"] = new JsonObject { ["id"] = lease.FolderId, ["path"] = lease.SourcePath };
            row.Remove("secretPath");
            row["connection"] = new JsonObject { ["id"] = lease.ConnectionId, ["app"] = path[3].Replace("-credentials", "", StringComparison.Ordinal), ["name"] = "Owned" };
            row["createdAt"] = Date; row["updatedAt"] = Date; row["lastRotatedAt"] = Date;
            row["lastRotationAttemptedAt"] = Date; row["rotationStatus"] = "success"; row["activeIndex"] = 0;
            row["isAutoRotationEnabled"] ??= false;
            row["rotateAtUtc"] ??= new JsonObject { ["hours"] = 0, ["minutes"] = 0 };
            if (!row.ContainsKey("description")) row["description"] = null;
            SetupParameters.Add((JsonObject)row["parameters"]!.DeepClone());
            StoreStatement(id, row);
            Configurations.Add(id, row);
            Attempts[id] = 0; Pending[id] = 0;
            Completion[id] = new(TaskCreationOptions.RunContinuationsAsynchronously);
            Accounts[lease.Username1] = lease.Password;
            Accounts[lease.Username2] = lease.Password;
            StoreMappings(row, lease);
            if (Mode == "bootstrap-loss") throw new IOException("bootstrap-reply-loss");
            return (200, Wrap("secretRotation", Projection(id)));
        }
        if (!Configurations.TryGetValue(path[4], out var rotation)) return (404, new JsonObject());
        Lease owner = Leases[Text(rotation, "projectId")];
        if (path.Length > 5 && path[5] == "generated-credentials")
            return (200, new JsonObject
            {
                ["type"] = path[3],
                ["rotationId"] = path[4],
                ["activeIndex"] = 0,
                ["generatedCredentials"] = new JsonArray(new JsonObject
                { ["username"] = owner.Username1, ["password"] = owner.Password })
            });
        if (method == "PATCH")
        {
            if (!ValidPatch(body)) return (400, new JsonObject());
            Patches.Add((JsonObject)body.DeepClone());
            Attempts[path[4]]++;
            Pending[path[4]]++;
            foreach (var (key, value) in body)
            {
                if (Mode is "ignored-patch" or "echo-only") continue;
                if (Mode == "deep-merge" && value is JsonObject nested && rotation[key] is JsonObject existing)
                {
                    if (key == "parameters" && Statements.TryGetValue(path[4], out string? retained))
                        existing["rotationStatement"] = retained;
                    foreach (var (child, supplied) in nested)
                    {
                        if (child == "passwordRequirements" && supplied is JsonObject policy &&
                            existing[child] is JsonObject oldPolicy)
                        {
                            foreach (var (member, replacement) in policy) oldPolicy[member] = replacement?.DeepClone();
                        }
                        else existing[child] = supplied?.DeepClone();
                    }
                }
                else rotation[key] = value?.DeepClone();
            }
            if (body.ContainsKey("parameters")) StoreStatement(path[4], rotation);
            StoreMappings(rotation, owner);
            if (Mode != "unsettled")
            {
                Pending[path[4]] = 0;
                Completion[path[4]].TrySetResult();
            }
            if (Mode == "borrowed-damage") BorrowedIntact = false;
        }
        return (200, Wrap("secretRotation", Projection(path[4])));
    }

    internal static bool ValidPatch(JsonObject patch)
    {
        if (patch.ContainsKey("parameters"))
        {
            if (patch["parameters"] is not JsonObject p || p["username1"] is null || p["username2"] is null) return false;
            if (p.ContainsKey("rotationStatement") && (p["rotationStatement"] is null ||
                string.IsNullOrEmpty(p["rotationStatement"]!.GetValue<string>()))) return false;
            if (p.ContainsKey("passwordRequirements"))
            {
                if (p["passwordRequirements"] is not JsonObject r || r["length"] is null ||
                    r["required"] is not JsonObject required ||
                    new[] { "digits", "lowercase", "symbols", "uppercase" }.Any(k => required[k] is null)) return false;
            }
        }
        if (patch.ContainsKey("secretsMapping") && (patch["secretsMapping"] is not JsonObject m ||
            m["username"] is null || m["password"] is null)) return false;
        if (patch.ContainsKey("rotateAtUtc") && (patch["rotateAtUtc"] is not JsonObject t ||
            t["hours"] is null || t["minutes"] is null)) return false;
        return true;
    }

    private void StoreStatement(string id, JsonObject row)
    {
        var parameters = row["parameters"]!.AsObject();
        if (parameters["rotationStatement"] is not null)
            Statements[id] = Text(parameters, "rotationStatement");
        else Statements.Remove(id);
        parameters.Remove("rotationStatement");
    }

    internal JsonObject Projection(string id)
    {
        var row = (JsonObject)Configurations[id].DeepClone();
        if (Statements.TryGetValue(id, out string? statement)) row["parameters"]!["rotationStatement"] = statement;
        return row;
    }

    private void StoreMappings(JsonObject row, Lease owner)
    {
        foreach (var key in Mappings.Keys.Where(k => k.Project == owner.Project).ToArray()) Mappings.Remove(key);
        Mappings[(owner.Project, Text(row["secretsMapping"]!, "username"))] = owner.Username1;
        Mappings[(owner.Project, Text(row["secretsMapping"]!, "password"))] = owner.Password;
    }

    public async ValueTask DisposeAsync()
    {
        await shutdown.CancelAsync();
        try { await accept; }
        finally { listener.Stop(); }
        await Task.WhenAll(connections);
        shutdown.Dispose();
    }

    internal sealed class Lease : IDatabaseOwnedFixture, IDatabaseBackendObserver
    {
        internal readonly InfisicalSqlRotationPatchFixture Owner;
        internal readonly string Project;
        internal readonly NativeCaseDefinition Definition;
        internal readonly string EnvironmentId = Guid.NewGuid().ToString();
        internal readonly string FolderId = Guid.NewGuid().ToString();
        internal readonly string Password = "Aa11!!bbCC22@@dd";
        internal readonly InfisicalSqlRotationPatchSource Source;
        internal Lease(InfisicalSqlRotationPatchFixture owner, string project, string name, NativeCaseDefinition definition)
        {
            Owner = owner; Project = project; Name = name; Definition = definition;
            Source = new(this);
            var binding = new SqlRotationPatchBinding(definition, Guid.NewGuid().ToString("N"),
                Organization, project, name, SourcePath, BackendCoordinate,
                "v0.166.3", "offline-deployment", "committed-journals", "injected-clock", 7);
            SqlRotationPatch = owner.Mode == "source-absent" ? null : new(binding, Source);
        }
        public SqlRotationPatchTrial? SqlRotationPatch { get; }
        public string Name { get; }
        public string Environment => "owned";
        public string SourcePath => "/" + Name;
        public string DestinationEnvironment => "destination";
        public string DestinationPath => "/" + Name + "-moved";
        public string ConnectionId { get; } = Guid.NewGuid().ToString();
        public string Username1 => Name + "a";
        public string Username2 => Name + "b";
        public string UsernameKey => Name + "_USER";
        public string PasswordKey => Name + "_PASSWORD";
        public string UpdatedUsername1 => Name + "c";
        public string UpdatedUsername2 => Name + "d";
        public string UpdatedUsernameKey => Name + "_NEWUSER";
        public string UpdatedPasswordKey => Name + "_NEWPASSWORD";
        public SecretMaterial RotationStatement { get; } = SecretMaterial.FromText("owned-original-statement");
        public SecretMaterial UpdatedRotationStatement { get; } = SecretMaterial.FromText("owned-updated-statement");
        public string[] AllowedActions => ["select"];
        public string[] DeniedActions => ["write"];
        public string PrimaryShapeRevision => "offline-v0.166.3";
        public DatabaseConfiguration CreationDefaults => new(Name, ConnectionId, Environment, SourcePath,
            Username1, Username2, UsernameKey, PasswordKey, 2, 0, 0, false, true, null, null);
        public DatabaseConfiguration ExpectedPatchConfiguration => CreationDefaults;
        public SecretMaterial? ExpectedPatchStatement => RotationStatement;
        public bool? DefaultDeleteSecrets => true;
        public bool? DefaultRevokeCredentials => true;
        public IDatabaseBackendObserver Backend => this;
        public DatabaseBackendCoordinate BackendCoordinate => new(
            Definition.Key.Operation.Contains("Postgres", StringComparison.Ordinal) ? InfisicalRotationProfile.PostgresCredentials :
            Definition.Key.Operation.Contains("MySql", StringComparison.Ordinal) ? InfisicalRotationProfile.MysqlCredentials :
                InfisicalRotationProfile.MssqlCredentials, "database.invalid", 5432, "owned", ConnectionId);
        private DatabaseAuthenticationMeasurement Measure(DatabaseAuthentication selected) =>
            new(BackendCoordinate, selected, DatabaseAuthentication.Rejected, AllowedActions, DeniedActions,
                DateTimeOffset.Parse(Date));
        public ValueTask<DatabaseAuthenticationMeasurement> MeasureAuthorityAsync(CancellationToken token) =>
            ValueTask.FromResult(Measure(DatabaseAuthentication.Accepted));
        public ValueTask<DatabaseAuthenticationMeasurement> AuthenticateAsync(SecretMaterial username, SecretMaterial password,
            CancellationToken token)
        {
            string user = username.Reveal();
            return ValueTask.FromResult(Measure(Owner.Accounts.TryGetValue(user, out string? expected) &&
                password.Reveal() == expected ? DatabaseAuthentication.Accepted : DatabaseAuthentication.Rejected));
        }
        public ValueTask<IDatabaseRejectionSubscription> SubscribeRejectionAsync(SecretMaterial username,
            SecretMaterial password, CancellationToken token) => throw new InvalidOperationException("not-a-delete-trial");
        public ValueTask<DatabaseCatalogMeasurement> ObserveCatalogAsync(bool options, CancellationToken token) =>
            throw new InvalidOperationException("not-a-catalog-trial");
        public ValueTask CleanupAsync(CancellationToken token)
        {
            lock (Owner.gate)
            {
                foreach (string id in Owner.Configurations.Where(r => Text(r.Value, "projectId") == Project).Select(r => r.Key).ToArray())
                {
                    if (Owner.Pending[id] != 0) throw new NativeCaseFailureException("cleanup-incomplete");
                    Owner.Configurations.Remove(id); Owner.Statements.Remove(id);
                    Owner.Attempts.Remove(id); Owner.Pending.Remove(id); Owner.Completion.Remove(id);
                }
                foreach (var key in Owner.Mappings.Keys.Where(k => k.Project == Project).ToArray()) Owner.Mappings.Remove(key);
                Owner.Accounts.Remove(Username1); Owner.Accounts.Remove(Username2);
                Owner.Leases.Remove(Project);
            }
            return ValueTask.CompletedTask;
        }
        public ValueTask<DatabaseCleanupMeasurement> ObserveCleanupAsync(CancellationToken token) =>
            ValueTask.FromResult(new DatabaseCleanupMeasurement(Owner.Accounts.Count, Owner.Mappings.Count, Owner.Configurations.Count));
        public ValueTask DisposeAsync()
        {
            RotationStatement.Dispose(); UpdatedRotationStatement.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
