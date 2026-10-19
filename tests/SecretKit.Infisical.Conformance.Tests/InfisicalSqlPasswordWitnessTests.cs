using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalSqlPasswordWitnessTests
{
    private static readonly DateTimeOffset Epoch = new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private const string EnvironmentId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private const string PasswordA = "aaaaaaAAAAAA111111!!!!!!";
    private const string PasswordB = "aaaaaaaaAAAAAAAA11111111!!!!!!!!";
    private static readonly JsonSerializerOptions Options = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };

    [Test]
    [Arguments("CreateDefinitionAsync", "passwordRequirements.value")]
    [Arguments("CreateDefinitionAsync", "NativeSqlDefinitionProfile.passwordRequirements.value")]
    [Arguments("UpdateDefinitionAsync", "passwordRequirements.value")]
    [Arguments("UpdateDefinitionAsync", "NativeSqlDefinitionProfile.passwordRequirements.value")]
    public async Task BothAliasesMeasureActualIssuedPasswordsAndIndependentBackend(string method, string variant)
    {
        foreach (string boundary in new[] { "independent-effect", "denied-authority",
            "cancellation-boundary", "lost-response-no-replay" })
        {
            await using var wire = new PasswordWire();
            var result = await RunAsync(wire, method, variant, boundary);
            await Assert.That(result.ReasonCode).IsEqualTo("observed").Because(boundary);
            await Assert.That(result.Passed).IsTrue();
            await Assert.That(wire.RuntimeMutations).IsEqualTo(
                boundary is "denied-authority" or "cancellation-boundary" ? 0 : 1);
            await Assert.That(wire.RecordCount).IsEqualTo(0);
            await Assert.That(wire.CredentialCount).IsEqualTo(0);
            if (method == "UpdateDefinitionAsync")
            {
                await Assert.That(wire.IssuedPasswords.Contains(PasswordA)).IsTrue();
                await Assert.That(wire.IssuedPasswords.Contains(
                    boundary is "denied-authority" or "cancellation-boundary" ? PasswordA : PasswordB)).IsTrue();
                await Assert.That(wire.RejectedUsers.Count).IsEqualTo(wire.IssuedPasswords.Count);
            }
        }
    }

    [Test]
    [Arguments("CreateDefinitionAsync", "wrong-shape", "effect-mismatch")]
    [Arguments("UpdateDefinitionAsync", "wrong-shape", "effect-mismatch")]
    [Arguments("CreateDefinitionAsync", "reject-auth", "effect-mismatch")]
    [Arguments("UpdateDefinitionAsync", "reject-auth", "effect-mismatch")]
    [Arguments("UpdateDefinitionAsync", "ignore-update", "effect-mismatch")]
    [Arguments("CreateDefinitionAsync", "unavailable", "observer-unavailable")]
    [Arguments("UpdateDefinitionAsync", "unavailable", "observer-unavailable")]
    [Arguments("UpdateDefinitionAsync", "retain-a", "cleanup-incomplete")]
    [Arguments("UpdateDefinitionAsync", "retain-b", "cleanup-incomplete")]
    [Arguments("CreateDefinitionAsync", "wrong-coordinate", "effect-mismatch")]
    [Arguments("CreateDefinitionAsync", "wrong-actions", "effect-mismatch")]
    [Arguments("CreateDefinitionAsync", "wrong-expiry", "effect-mismatch")]
    [Arguments("CreateDefinitionAsync", "wrong-symbol", "effect-mismatch")]
    public async Task AcknowledgementsCannotCertifyPolicyAuthenticationOrCleanup(string method, string mode, string reason)
    {
        await using var wire = new PasswordWire(method == "UpdateDefinitionAsync" &&
            mode is "wrong-shape" or "reject-auth" ? "update-" + mode : mode);
        var result = await RunAsync(wire, method);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(wire.RecordCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("CreateDefinitionAsync", "active")]
    [Arguments("CreateDefinitionAsync", "unknown-active")]
    [Arguments("CreateDefinitionAsync", "incomplete")]
    [Arguments("UpdateDefinitionAsync", "active")]
    [Arguments("UpdateDefinitionAsync", "unknown-active")]
    [Arguments("UpdateDefinitionAsync", "incomplete")]
    public async Task MatchingOverridesAndIncompleteNativeReadsCannotCertifyPasswordPolicy(string method, string mode)
    {
        await using var wire = new PasswordWire(mode);
        var result = await RunAsync(wire, method);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(wire.ValidationReads).IsGreaterThan(0);
        await Assert.That(wire.ValidationCoordinatesValid).IsTrue();
        await Assert.That(wire.RecordCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("missing")]
    [Arguments("same-length")]
    [Arguments("open-counts")]
    [Arguments("wrong-symbols")]
    public async Task UpdateRequiresExplicitDistinctClosedBaselineBeforeDispatch(string shape)
    {
        await using var wire = new PasswordWire();
        var input = Input("UpdateDefinitionAsync");
        var baseline = input["profile"]!["baselinePasswordRequirements"]!;
        switch (shape)
        {
            case "missing": input["profile"]!.AsObject().Remove("baselinePasswordRequirements"); break;
            case "same-length":
                input["profile"]!["baselinePasswordRequirements"] =
                input["profile"]!["passwordRequirements"]!.DeepClone(); break;
            case "open-counts": baseline["lowercase"] = 5; break;
            case "wrong-symbols": baseline["allowedSymbols"] = "?"; break;
        }
        var result = await RunAsync(wire, "UpdateDefinitionAsync", input: input);
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(wire.RuntimeMutations).IsEqualTo(0);
        await Assert.That(wire.RecordCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("Mysql")]
    [Arguments("SqlServer")]
    [Arguments("nonclosed")]
    [Arguments("symbols")]
    [Arguments("length")]
    public async Task OtherTypedPasswordShapesRemainObserverUnavailable(string shape)
    {
        await using var wire = new PasswordWire();
        var input = Input("CreateDefinitionAsync");
        var profile = input["profile"]!;
        switch (shape)
        {
            case "Mysql": profile["engine"] = "Mysql"; break;
            case "SqlServer": profile["engine"] = "SqlServer"; break;
            case "nonclosed": profile["passwordRequirements"]!["lowercase"] = 5; break;
            case "symbols": profile["passwordRequirements"]!["allowedSymbols"] = "?"; break;
            case "length":
                profile["passwordRequirements"] = JsonSerializer.SerializeToNode(new DynamicPasswordInput(16, 4, 4, 4, 4, "!"), Options);
                break;
        }
        var result = await RunAsync(wire, "CreateDefinitionAsync", input: input);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(wire.RecordCount).IsEqualTo(0);
    }

    private static JsonObject Input(string method) => JsonSerializer.SerializeToNode(
        new InfisicalDynamicClientEffects.DynamicInput(
            new("project", "project-slug", "env", EnvironmentId, "/owned"),
            new(NativeSqlEngine.Postgres, "backend.invalid", 5432, "database", "admin", "private-password",
                "create-role", "revoke-role", "renew-role", null, false, null, null,
                method == "UpdateDefinitionAsync" ? new(32, 8, 8, 8, 8, "!") : new(24, 6, 6, 6, 6, "!"),
                new(24, 6, 6, 6, 6, "!")),
            60, 300, 120, null, [], ["select"], ["write"]), Options)!.AsObject();

    private static async Task<NativeCaseResult> RunAsync(PasswordWire wire, string method,
        string variant = "passwordRequirements.value", string boundary = "independent-effect",
        JsonObject? input = null)
    {
        var admission = InfisicalLifecycleFamilies.Catalog.Single(a =>
            a.Operation == "i.runtime.InfisicalDynamicClient." + method);
        var row = new NativeCaseDefinition(new("Infisical", admission.Operation, variant, "offline", boundary),
            admission.Member);
        var families = new JsonObject
        {
            [InfisicalDynamicClientEffects.Family] = new JsonObject
            {
                ["scopes"] = new JsonObject
                {
                    ["offline"] = new JsonObject
                    {
                        [admission.Operation] = new JsonObject
                        {
                            [variant] = new JsonObject { [boundary] = input ?? Input(method) }
                        }
                    }
                }
            }
        };
        using var environment = NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = wire.Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families
        }, Options));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, environment, [row], wire);
        return (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
    }

    // Provider records and downstream credentials are separate stores. The selected
    // policy changes provider state; fixed independent passwords exercise the SDK parser.
    private sealed class PasswordWire : IAsyncDisposable, IInfisicalDynamicBackendObserver
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Dictionary<string, (string Name, string Path)> folders = [];
        private readonly Dictionary<string, Definition> definitions = [];
        private readonly Dictionary<Guid, Lease> leases = [];
        private readonly Dictionary<string, Lease> credentials = [];
        private readonly string mode;
        private readonly Task accept;
        internal Uri Origin { get; }
        internal int RuntimeMutations { get; private set; }
        internal int ValidationReads { get; private set; }
        internal bool ValidationCoordinatesValid { get; private set; } = true;
        internal List<string> IssuedPasswords { get; } = [];
        internal HashSet<string> RejectedUsers { get; } = [];
        internal int RecordCount { get { lock (folders) return folders.Count + definitions.Count + leases.Count; } }
        internal int CredentialCount { get { lock (folders) return credentials.Count; } }

        internal PasswordWire(string mode = "good")
        {
            this.mode = mode;
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            accept = AcceptAsync();
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
                    byte[] body = new byte[length];
                    await stream.ReadExactlyAsync(body, shutdown.Token);
                    using var json = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                    (int Status, object Payload) result;
                    lock (folders) result = Handle(request[0], new(Origin, request[1]), role, json.RootElement);
                    byte[] response = JsonSerializer.SerializeToUtf8Bytes(result.Payload);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"),
                        shutdown.Token);
                    await stream.WriteAsync(response, shutdown.Token);
                }
                catch (IOException) { }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            }
        }

        private (int, object) Handle(string method, Uri uri, string role, JsonElement body)
        {
            if (role == "denied") return (403, new { });
            string path = uri.AbsolutePath;
            if (path == "/api/v1/secret-validation-rules/dynamic-secrets")
            {
                ValidationReads++;
                ValidationCoordinatesValid &= role == "observer" && uri.Query == "?projectId=project";
                object rule = new
                {
                    id = Guid.NewGuid(),
                    projectId = "project",
                    name = "matching-override",
                    type = "dynamic-secrets",
                    secretPath = "/",
                    environment = (object?)null,
                    createdAt = Epoch,
                    updatedAt = Epoch,
                    isActive = mode == "unknown-active" ? (bool?)null : true,
                    passwordConstraints = new { minLength = 24, maxLength = 32 },
                    providers = new[] { "sql-database" }
                };
                return (200, new
                {
                    secretValidationRules = mode == "incomplete" ? Enumerable.Repeat(rule, 1001).ToArray() :
                        mode is "active" or "unknown-active" ? new[] { rule } : Array.Empty<object>()
                });
            }
            if (path.StartsWith("/api/v2/folders", StringComparison.Ordinal))
            {
                if (method == "POST")
                {
                    string id = Guid.NewGuid().ToString("D");
                    folders[id] = (body.GetProperty("name").GetString()!,
                        body.GetProperty("path").GetString()!.TrimEnd('/') + "/" + body.GetProperty("name").GetString());
                    return (200, new { folder = Folder(id) });
                }
                if (path == "/api/v2/folders") return (200, new { folders = folders.Keys.Select(Folder).ToArray() });
                string selector = Uri.UnescapeDataString(path.Split('/').Last());
                string? found = folders.Keys.SingleOrDefault(id => id == selector || folders[id].Name == selector);
                if (found is null) return (404, new { });
                object folder = Folder(found);
                if (method == "DELETE") folders.Remove(found);
                return (200, new { folder });
            }
            if (!path.StartsWith("/api/v1/dynamic-secrets", StringComparison.Ordinal)) return (404, new { });
            if (role == "runtime" && method is "POST" or "PATCH") RuntimeMutations++;
            if (path == "/api/v1/dynamic-secrets")
            {
                if (method == "GET") return (200, new { dynamicSecrets = definitions.Values.Select(DefinitionJson).ToArray() });
                string name = body.GetProperty("name").GetString()!;
                var inputs = body.GetProperty("provider").GetProperty("inputs");
                definitions[name] = new(Guid.NewGuid(), name,
                    folders.Single(f => f.Value.Path == body.GetProperty("path").GetString()).Key,
                    body.GetProperty("defaultTTL").GetString()!, body.GetProperty("maxTTL").GetString()!,
                    PolicyLength(inputs), 1);
                return (200, new { dynamicSecret = DefinitionJson(definitions[name]) });
            }
            if (path == "/api/v1/dynamic-secrets/leases")
            {
                var definition = definitions[body.GetProperty("dynamicSecretName").GetString()!];
                Guid id = Guid.NewGuid();
                string password = definition.Length == 32 ? PasswordB : PasswordA;
                if (mode == "wrong-shape" || mode == "update-wrong-shape" && definition.Length == 32)
                    password = "zzzzzzzzzzzzzzzzzzzzzzzz";
                if (mode == "wrong-symbol") password = "aaaaaaAAAAAA111111??????";
                var lease = new Lease(id, definition.Id, "user-" + id.ToString("N"), password);
                leases[id] = lease;
                credentials[lease.User] = lease;
                IssuedPasswords.Add(password);
                return (200, new
                {
                    dynamicSecret = DefinitionJson(definition),
                    lease = LeaseJson(lease),
                    data = new { DB_USERNAME = lease.User, DB_PASSWORD = password }
                });
            }
            string[] segments = path.Split('/');
            if (segments[4] == "leases")
            {
                Guid id = Guid.Parse(segments[5]);
                if (!leases.TryGetValue(id, out var lease)) return (404, new { });
                if (method == "DELETE")
                {
                    leases.Remove(id);
                    if (!(mode == "retain-a" && lease.Password == PasswordA ||
                        mode == "retain-b" && lease.Password == PasswordB)) credentials.Remove(lease.User);
                }
                return (200, new { lease = LeaseJson(lease) });
            }
            string nameSelected = Uri.UnescapeDataString(segments[4]);
            if (!definitions.TryGetValue(nameSelected, out var selected)) return (404, new { });
            if (segments.Length > 5) return (200, new
            {
                leases = leases.Values.Where(l =>
                l.DefinitionId == selected.Id).Select(LeaseJson).ToArray()
            });
            if (method == "PATCH")
            {
                var data = body.GetProperty("data");
                selected = selected with
                {
                    DefaultTtl = data.GetProperty("defaultTTL").GetString()!,
                    Length = mode == "ignore-update" ? selected.Length : PolicyLength(data.GetProperty("inputs")),
                    Version = selected.Version + 1
                };
                definitions[nameSelected] = selected;
            }
            if (method == "DELETE") definitions.Remove(nameSelected);
            return (200, new { dynamicSecret = DefinitionJson(selected) });
        }

        private static int PolicyLength(JsonElement inputs) =>
            inputs.TryGetProperty("passwordRequirements", out var policy) ? policy.GetProperty("length").GetInt32() : 0;
        private object Folder(string id) => new
        {
            id,
            envId = EnvironmentId,
            name = folders[id].Name,
            path = folders[id].Path,
            projectId = "project",
            environment = new { envSlug = "env" },
            createdAt = Epoch,
            updatedAt = Epoch
        };
        private static object DefinitionJson(Definition definition) => new
        {
            id = definition.Id,
            name = definition.Name,
            folderId = definition.FolderId,
            type = "sql-database",
            defaultTTL = definition.DefaultTtl,
            maxTTL = definition.MaximumTtl,
            version = definition.Version,
            createdAt = Epoch,
            updatedAt = Epoch,
            status = (string?)null
        };
        private static object LeaseJson(Lease lease) => new
        {
            id = lease.Id,
            dynamicSecretId = lease.DefinitionId,
            createdAt = Epoch.AddSeconds(1),
            expireAt = Epoch.AddSeconds(121),
            updatedAt = Epoch.AddSeconds(1),
            version = 1,
            externalEntityId = lease.User,
            status = (string?)null
        };

        public ValueTask<DynamicBackendFacts> MeasureAsync(DynamicBackendCoordinate coordinate,
            SecretMaterial username, SecretMaterial password, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (folders)
            {
                bool accepted = credentials.TryGetValue(username.Reveal(), out var lease) &&
                    lease.Password == password.Reveal() && lease.Id == coordinate.LeaseId &&
                    lease.DefinitionId == coordinate.DefinitionId && coordinate.Engine == NativeSqlEngine.Postgres &&
                    coordinate.Host == "backend.invalid" && coordinate.Port == 5432 && coordinate.Database == "database";
                bool reject = accepted && (mode == "reject-auth" ||
                    mode == "update-reject-auth" && lease!.Password == PasswordB);
                if (!accepted) RejectedUsers.Add(username.Reveal());
                return ValueTask.FromResult(new DynamicBackendFacts(
                    mode == "wrong-coordinate" && accepted ? coordinate with { Database = "other" } : coordinate,
                    mode == "unavailable" && accepted ? BackendAuthentication.Unavailable :
                        accepted && !reject ? BackendAuthentication.Accepted : BackendAuthentication.Rejected,
                    accepted ? mode == "wrong-actions" ? ["insert"] : ["select"] : [],
                    accepted ? ["write"] : [],
                    accepted ? Epoch.AddSeconds(mode == "wrong-expiry" ? 122 : 121) : null));
            }
        }

        public async ValueTask DisposeAsync()
        {
            await shutdown.CancelAsync();
            try { await accept; }
            finally { listener.Stop(); }
            await Task.WhenAll(connections);
            shutdown.Dispose();
        }

        private sealed record Definition(Guid Id, string Name, string FolderId, string DefaultTtl,
            string MaximumTtl, int Length, int Version);
        private sealed record Lease(Guid Id, Guid DefinitionId, string User, string Password);
    }
}
