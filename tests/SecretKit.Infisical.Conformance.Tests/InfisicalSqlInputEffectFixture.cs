using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent controlled provider: SDK responses contain metadata, while storage,
// administrative sessions, and issued principals have separate lifetimes.
internal sealed class InfisicalSqlInputEffectFixture : IAsyncDisposable, IInfisicalDynamicBackendObserver
{
    internal static readonly DateTimeOffset Epoch = new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);
    internal const string EnvironmentId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    internal const string ProjectId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Dictionary<string, (string Name, string Path)> folders = [];
    private readonly Dictionary<string, Definition> definitions = [];
    private readonly Dictionary<Guid, Issued> leases = [];
    private readonly Dictionary<string, Issued> principals = [];
    private readonly Task accept;
    private readonly string mode;
    private long sequence;
    internal Uri Origin { get; }
    internal NativeSqlEngine Engine { get; }
    internal DynamicSqlInput Baseline { get; }
    internal DynamicSqlInput Selected { get; }
    internal List<Session> Sessions { get; } = [];
    internal List<Issued> Issuances { get; } = [];
    internal List<Mutation> Mutations { get; } = [];
    internal bool BorrowedRootIntact { get; private set; } = true;
    internal int ResidualCount { get { lock (folders) return definitions.Count + folders.Count + leases.Count + principals.Count; } }
    internal int RuntimeMutations => Mutations.Count(m => m.Role == "runtime");
    internal string Mode => mode;
    internal long Sequence { get { lock (folders) return sequence; } }
    internal long Tick() { lock (folders) return ++sequence; }
    internal int DefinitionCount { get { lock (folders) return definitions.Count; } }
    internal int LeaseCount { get { lock (folders) return leases.Count; } }
    internal int PrincipalCount { get { lock (folders) return principals.Count; } }
    internal InfisicalSqlInputEffectSource Source { get; }

    internal InfisicalSqlInputEffectFixture(NativeSqlEngine engine, string mode = "good")
    {
        Engine = engine;
        this.mode = mode;
        Baseline = new(engine, "baseline.invalid", 5432, "baseline-db", "baseline-admin",
            "baseline-admin-secret", "create-baseline", "revoke-baseline", "renew-baseline",
            "owned-baseline-ca", false, "baseline-gateway", "baseline-pool");
        Selected = new(engine, "selected.invalid", 6543, "selected-db", "selected-admin",
            "selected-admin-secret", "create-selected", "revoke-selected", "renew-selected",
            "owned-selected-ca", true, "selected-gateway", "selected-pool",
            new(24, 1, 1, 1, 1, "!"), new(32, 8, 8, 8, 8, "!"));
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this);
        accept = AcceptAsync();
    }

    internal JsonObject Input(bool witness = true)
    {
        var input = JsonSerializer.SerializeToNode(new InfisicalDynamicClientEffects.DynamicInput(
            new(ProjectId, "project-slug", "env", EnvironmentId, "/borrowed"),
            Selected, 60, 300, 120, "owned-selected", [new("marker", "selected")],
            ["select"], ["write"]), InfisicalSqlInputEffectTests.Options)!.AsObject();
        if (witness) input["sqlInputWitness"] = new JsonObject
        {
            ["deploymentId"] = "controlled-sql",
            ["sourceProfile"] = "controlled-fixture",
            ["rootNonce"] = Guid.NewGuid().ToString("N"),
            ["caseTimeoutSeconds"] = 15,
            ["baseline"] = JsonSerializer.SerializeToNode(Baseline, InfisicalSqlInputEffectTests.Options)
        };
        return input;
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
                var headers = new List<byte>();
                byte[] one = new byte[1];
                while (headers.Count < 32768)
                {
                    if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                    headers.Add(one[0]);
                    if (headers.Count >= 4 && headers.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) break;
                }
                string[] lines = Encoding.ASCII.GetString(headers.ToArray()).Split("\r\n");
                string[] request = lines[0].Split(' ');
                string role = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?
                    .Split(' ').Last() ?? "";
                int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?
                    .Split(':')[1] ?? "0");
                if (length is < 0 or > 1048576) throw new InvalidOperationException("offline-budget");
                byte[] bytes = new byte[length];
                await stream.ReadExactlyAsync(bytes, shutdown.Token);
                var body = length == 0 ? new JsonObject() : JsonNode.Parse(bytes)!.AsObject();
                (int Status, object Payload) result;
                lock (folders) result = Handle(request[0], new(Origin, request[1]), role, body);
                Array.Clear(bytes);
                byte[] response = JsonSerializer.SerializeToUtf8Bytes(result.Payload);
                await stream.WriteAsync(Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"),
                    shutdown.Token);
                await stream.WriteAsync(response, shutdown.Token);
                Array.Clear(response);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        }
    }

    private (int, object) Handle(string method, Uri uri, string role, JsonObject body)
    {
        string path = uri.AbsolutePath;
        bool mutation = path.StartsWith("/api/v1/dynamic-secrets", StringComparison.Ordinal) && method is "POST" or "PATCH";
        if (role == "denied")
        {
            if (mutation)
            {
                string rejectedName = method == "POST" ? Text(body, "name") :
                    Uri.UnescapeDataString(path.Split('/').Last());
                Mutations.Add(new(++sequence, role, false, rejectedName, ""));
            }
            return (403, new { });
        }
        if (path == "/api/v1/secret-validation-rules/dynamic-secrets")
            return (200, new { secretValidationRules = Array.Empty<object>() });
        if (path.StartsWith("/api/v2/folders", StringComparison.Ordinal))
        {
            if (method == "POST")
            {
                string id = Guid.NewGuid().ToString();
                folders.Add(id, (Text(body, "name"), Text(body, "path").TrimEnd('/') + "/" + Text(body, "name")));
                return (200, new { folder = Folder(id) });
            }
            if (path == "/api/v2/folders") return (200, new { folders = folders.Keys.Select(Folder).ToArray() });
            string selector = Uri.UnescapeDataString(path.Split('/').Last());
            string? found = folders.Keys.SingleOrDefault(id => id == selector || folders[id].Name == selector);
            if (found is null) return (404, new { });
            object folder = Folder(found);
            if (method == "DELETE")
            {
                folders.Remove(found);
                if (mode == "borrowed-root-damage") BorrowedRootIntact = false;
            }
            return (200, new { folder });
        }
        if (!path.StartsWith("/api/v1/dynamic-secrets", StringComparison.Ordinal)) return (404, new { });
        if (path == "/api/v1/dynamic-secrets")
        {
            if (method == "GET") return (200, new { dynamicSecrets = definitions.Values.Select(Projection).ToArray() });
            string name = Text(body, "name");
            var inputs = body["provider"]!["inputs"]!.DeepClone().AsObject();
            if (!Capture(inputs, "save", Guid.Empty)) return (400, new { });
            var definition = new Definition(Guid.NewGuid(), name,
                folders.Single(f => f.Value.Path == Text(body, "path")).Key,
                Text(body, "defaultTTL"), Text(body, "maxTTL"), inputs,
                body["metadata"]?.DeepClone(), body["usernameTemplate"]?.DeepClone());
            definitions.Add(name, definition);
            Mutations.Add(new(++sequence, role, true, name, definition.Id.ToString()));
            return (200, new { dynamicSecret = Projection(definition) });
        }
        if (path == "/api/v1/dynamic-secrets/leases")
        {
            var definition = definitions[Text(body, "dynamicSecretName")];
            if (!Capture(definition.Inputs, "issue", definition.Id)) return (400, new { });
            Guid id = Guid.NewGuid();
            string password = mode != "password-policy-ignored" &&
                definition.Inputs["passwordRequirements"] is JsonObject requirements ?
                "aA1!" + new string('a', requirements["length"]!.GetValue<int>() - 4) : "issued-" + id.ToString("N");
            var issued = new Issued(id, definition.Id, "owned-" + id.ToString("N"),
                password, Engine, Text(definition.Inputs, "host"),
                definition.Inputs["port"]!.GetValue<int>(), Text(definition.Inputs, "database"),
                Epoch.AddSeconds(121), Text(definition.Inputs, "creationStatement"));
            leases.Add(id, issued);
            principals.Add(issued.User, issued);
            Issuances.Add(issued);
            return (200, new
            {
                dynamicSecret = Projection(definition),
                lease = Lease(issued),
                data = new { DB_USERNAME = issued.User, DB_PASSWORD = issued.Password }
            });
        }
        string[] segments = path.Split('/');
        if (segments[4] == "leases")
        {
            Guid id = Guid.Parse(segments[5]);
            if (!leases.TryGetValue(id, out var issued)) return (404, new { });
            if (method == "DELETE")
            {
                var definition = definitions.Values.Single(d => d.Id == issued.Definition);
                Capture(definition.Inputs, "revoke", definition.Id);
                leases.Remove(id);
                if (mode != "cleanup-orphan") principals.Remove(issued.User);
            }
            return (200, new { lease = Lease(issued) });
        }
        string selectedName = Uri.UnescapeDataString(segments[4]);
        if (!definitions.TryGetValue(selectedName, out var selected)) return (404, new { });
        if (segments.Length > 5)
            return (200, new { leases = leases.Values.Where(l => l.Definition == selected.Id).Select(Lease).ToArray() });
        if (method == "PATCH")
        {
            var data = body["data"]!.AsObject();
            var merged = selected.Inputs.DeepClone().AsObject();
            if (data["inputs"] is JsonObject patch && mode != "ignored-patch")
                foreach (var pair in patch) merged[pair.Key] = pair.Value?.DeepClone();
            if (!Capture(merged, "save", selected.Id)) return (400, new { });
            if (mode != "echo-only")
            {
                selected = selected with
                {
                    Inputs = merged,
                    DefaultTtl = data["defaultTTL"]?.GetValue<string>() ?? selected.DefaultTtl,
                    Metadata = data.ContainsKey("metadata") ? data["metadata"]?.DeepClone() : selected.Metadata,
                    UsernameTemplate = data.ContainsKey("usernameTemplate") ?
                        data["usernameTemplate"]?.DeepClone() : selected.UsernameTemplate
                };
                definitions[selectedName] = selected;
            }
            Mutations.Add(new(++sequence, role, true, selected.Name, selected.Id.ToString()));
            if (mode == "replay") Mutations.Add(new(++sequence, role, true, selected.Name, selected.Id.ToString()));
        }
        if (method == "DELETE") definitions.Remove(selectedName);
        return (200, new { dynamicSecret = Projection(selected) });
    }

    // A session is derived solely from provider committed inputs. Wrong admin and
    // trust controls consult the provisioned targets, not requested observations.
    private bool Capture(JsonObject inputs, string phase, Guid definition)
    {
        string host = Text(inputs, "host");
        DynamicSqlInput? target = host == Baseline.Host ? Baseline : host == Selected.Host ? Selected : null;
        bool accepted = target is not null && Text(inputs, "username") == target.Username &&
            Text(inputs, "password") == target.Password && Text(inputs, "database") == target.Database &&
            inputs["port"]!.GetValue<int>() == target.Port &&
            (Text(inputs, "ca") == "" || TrustAccepted(host, Text(inputs, "ca"))) &&
            RouteAccepted(host, Text(inputs, "gatewayId"), Text(inputs, "gatewayPoolId"));
        string admin = mode == "admin-path-wrong" ? Baseline.Username : Text(inputs, "username");
        Sessions.Add(new(++sequence, phase, definition, host, admin,
            Text(inputs, "ca"), Text(inputs, "gatewayId"), Text(inputs, "gatewayPoolId"),
            Engine == NativeSqlEngine.SqlServer && inputs["sslEnabled"]?.GetValue<bool>() == true,
            accepted, Text(inputs, phase == "issue" ? "creationStatement" :
                phase == "revoke" ? "revocationStatement" : "renewStatement")));
        return accepted;
    }

    internal JsonObject Snapshot(Guid definition)
    {
        lock (folders)
        {
            var record = definitions.Values.Single(d => d.Id == definition);
            return new()
            {
                ["committedInputs"] = record.Inputs.DeepClone(),
                ["metadata"] = record.Metadata?.DeepClone(),
                ["usernameTemplate"] = record.UsernameTemplate?.DeepClone(),
                ["sessions"] = JsonSerializer.SerializeToNode(Sessions.Where(s => s.Definition == definition)),
                ["settled"] = mode != "unsettled",
                ["commitCount"] = Mutations.Count(m => m.Definition == definition.ToString() && m.Applied),
                ["borrowedRootPreserved"] = BorrowedRootIntact,
                ["principalCount"] = principals.Count
            };
        }
    }

    internal bool AdminAccepted(DynamicSqlInput target, string password) =>
        (target == Baseline || target == Selected) && target.Password == password;

    internal bool TrustAccepted(string host, string chain) =>
        (host == Baseline.Host || host == Selected.Host) &&
        (chain == Baseline.Ca || chain == Selected.Ca);

    internal bool RouteAccepted(string host, string gateway, string pool) =>
        (host == Baseline.Host || host == Selected.Host) &&
        (gateway == "" || gateway == Baseline.GatewayId || gateway == Selected.GatewayId) &&
        (pool == "" || pool == Baseline.GatewayPoolId || pool == Selected.GatewayPoolId);

    internal ValueTask<SecretStatus> QueryAsync(DynamicBackendCoordinate coordinate, SecretMaterial username,
        SecretMaterial password, string action, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (folders)
        {
            bool authenticated = principals.TryGetValue(username.Reveal(), out var principal) &&
                principal.Password == password.Reveal() && principal.Id == coordinate.LeaseId &&
                principal.Definition == coordinate.DefinitionId && principal.Engine == coordinate.Engine &&
                principal.Host == coordinate.Host && principal.Port == coordinate.Port && principal.Database == coordinate.Database;
            return ValueTask.FromResult(authenticated && action == "select" ? SecretStatus.Success : SecretStatus.Denied);
        }
    }

    public ValueTask<DynamicBackendFacts> MeasureAsync(DynamicBackendCoordinate coordinate,
        SecretMaterial username, SecretMaterial password, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (folders)
        {
            bool accepted = principals.TryGetValue(username.Reveal(), out var principal) &&
                principal.Password == password.Reveal() && principal.Id == coordinate.LeaseId &&
                principal.Definition == coordinate.DefinitionId && principal.Engine == coordinate.Engine &&
                principal.Host == coordinate.Host && principal.Port == coordinate.Port && principal.Database == coordinate.Database;
            return ValueTask.FromResult(new DynamicBackendFacts(coordinate,
                accepted ? BackendAuthentication.Accepted : BackendAuthentication.Rejected,
                accepted ? ["select"] : [], accepted ? ["write"] : [], accepted ? principal!.Expires : null));
        }
    }

    private object Folder(string id) => new
    {
        id,
        envId = EnvironmentId,
        name = folders[id].Name,
        path = folders[id].Path,
        projectId = ProjectId,
        environment = new { envSlug = "env" },
        createdAt = Epoch,
        updatedAt = Epoch
    };
    private static object Projection(Definition definition) => new
    {
        id = definition.Id,
        name = definition.Name,
        folderId = definition.FolderId,
        type = "sql-database",
        defaultTTL = definition.DefaultTtl,
        maxTTL = definition.MaximumTtl,
        version = 1,
        createdAt = Epoch,
        updatedAt = Epoch,
        status = (string?)null
    };
    private static object Lease(Issued issued) => new
    {
        id = issued.Id,
        dynamicSecretId = issued.Definition,
        createdAt = Epoch.AddSeconds(1),
        expireAt = issued.Expires,
        updatedAt = Epoch.AddSeconds(1),
        version = 1,
        externalEntityId = issued.User,
        status = (string?)null
    };
    private static string Text(JsonObject json, string field) => json[field]?.GetValue<string>() ?? "";

    public async ValueTask DisposeAsync()
    {
        await shutdown.CancelAsync();
        try { await accept; }
        finally { listener.Stop(); }
        await Task.WhenAll(connections);
        shutdown.Dispose();
    }

    private sealed record Definition(Guid Id, string Name, string FolderId, string DefaultTtl,
        string MaximumTtl, JsonObject Inputs, JsonNode? Metadata, JsonNode? UsernameTemplate);
    internal sealed record Issued(Guid Id, Guid Definition, string User, string Password, NativeSqlEngine Engine,
        string Host, int Port, string Database, DateTimeOffset Expires, string CreationStatement)
    {
        public override string ToString() => "[Issued]";
    }
    internal sealed record Session(long Sequence, string Phase, Guid Definition, string Host, string Admin,
        string Ca, string Gateway, string Pool, bool MssqlEncryption, bool Accepted, string Statement)
    {
        public override string ToString() => "[Session]";
    }
    internal sealed record Mutation(long Sequence, string Role, bool Applied, string Name, string Definition);
}
