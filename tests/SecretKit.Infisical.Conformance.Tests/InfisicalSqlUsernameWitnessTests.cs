using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalSqlUsernameWitnessTests
{
    private static readonly DateTimeOffset Epoch = new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private const string EnvironmentId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private const string A = "sk_u_0123456789abcdef_a";
    private const string B = "sk_u_0123456789abcdef_b";
    private static readonly JsonSerializerOptions Options = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };

    [Test]
    public async Task FixtureRejectsDuplicateRolesAndSeparatesRecordsFromActualIssuance()
    {
        // Given the same strict backend used by the SDK witnesses.
        await using var wire = new UsernameWire();
        // When issuance is duplicated, records are deleted and a role is revoked.
        // Then independent authentication and inventory retain their own state.
        await wire.VerifyStorageContractAsync();
    }

    [Test]
    [Arguments("CreateDefinitionAsync", "independent-effect")]
    [Arguments("CreateDefinitionAsync", "selected-contract")]
    [Arguments("CreateDefinitionAsync", "denied-authority")]
    [Arguments("CreateDefinitionAsync", "cancellation-boundary")]
    [Arguments("CreateDefinitionAsync", "lost-response-no-replay")]
    [Arguments("UpdateDefinitionAsync", "independent-effect")]
    [Arguments("UpdateDefinitionAsync", "selected-contract")]
    [Arguments("UpdateDefinitionAsync", "denied-authority")]
    [Arguments("UpdateDefinitionAsync", "cancellation-boundary")]
    [Arguments("UpdateDefinitionAsync", "lost-response-no-replay")]
    public async Task SelectedUsernameRequiresFreshAuthenticationAndIndependentRoleCleanup(string method, string boundary)
    {
        // Given a strict CREATE ROLE backend and independently held issuance history.
        await using var wire = new UsernameWire();
        // When the public SDK executes the selected case.
        var result = await RunAsync(wire, method, boundary);
        // Then neither an acknowledgement nor a provider record certifies a role.
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(result.Passed).IsTrue();
        bool negative = boundary is "denied-authority" or "cancellation-boundary";
        await Assert.That(wire.RuntimeMutations).IsEqualTo(negative ? 0 : 1);
        await Assert.That(wire.RecordCount).IsEqualTo(0);
        await Assert.That(wire.RoleCount).IsEqualTo(0);
        await Assert.That(wire.InventoryBeforeOwnership).IsTrue();
        await Assert.That(wire.DuplicateAcquisitions).IsEqualTo(0);
        await Assert.That(wire.Issued.Count).IsEqualTo(method == "UpdateDefinitionAsync" ? 2 : negative ? 0 : 1);
        await Assert.That(wire.Issued.All(l => wire.Accepted.Contains(l.Id) && wire.Rejected.Contains(l.Id))).IsTrue();
        await Assert.That(wire.AbsentInventories.Any(s => s.Contains(A) && s.Contains(B))).IsTrue();
        if (method == "UpdateDefinitionAsync")
        {
            await Assert.That(wire.Issued[0].User).IsEqualTo(A);
            await Assert.That(wire.Issued[1].User).IsEqualTo(negative ? A : B);
            await Assert.That(wire.BaselineRemeasuredAfterMutation).IsTrue();
            if (negative)
                await Assert.That(wire.BaselineRejectedAndAbsentBeforeReissue).IsTrue();
            else
            {
                await Assert.That(wire.BaselineHeldDuringSelectedIssuance).IsTrue();
                await Assert.That(wire.BaselineAcceptedAfterSelectedIssuance).IsTrue();
            }
        }
    }

    [Test]
    [Arguments("CreateDefinitionAsync", "wrong-username", "effect-mismatch")]
    [Arguments("UpdateDefinitionAsync", "wrong-username", "effect-mismatch")]
    [Arguments("CreateDefinitionAsync", "reject-auth", "effect-mismatch")]
    [Arguments("UpdateDefinitionAsync", "reject-auth", "effect-mismatch")]
    [Arguments("UpdateDefinitionAsync", "ignore-update", "effect-mismatch")]
    [Arguments("CreateDefinitionAsync", "unavailable", "observer-unavailable")]
    [Arguments("UpdateDefinitionAsync", "unavailable", "observer-unavailable")]
    [Arguments("CreateDefinitionAsync", "wrong-coordinate", "effect-mismatch")]
    [Arguments("CreateDefinitionAsync", "wrong-actions", "effect-mismatch")]
    [Arguments("CreateDefinitionAsync", "wrong-expiry", "effect-mismatch")]
    [Arguments("UpdateDefinitionAsync", "retain-a", "cleanup-incomplete")]
    [Arguments("CreateDefinitionAsync", "retain-b", "cleanup-incomplete")]
    [Arguments("UpdateDefinitionAsync", "retain-b", "cleanup-incomplete")]
    [Arguments("UpdateDefinitionAsync", "premature-revoke", "effect-mismatch")]
    public async Task ProviderAcknowledgementsCannotCertifyUsernameEffects(string method, string mode, string reason)
    {
        // Given an independently observable fault, selected issuance only for updates.
        await using var wire = new UsernameWire(mode);
        // When the public SDK performs the witness.
        var result = await RunAsync(wire, method);
        // Then the fault is classified and provider records are reconciled.
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(wire.RecordCount).IsEqualTo(0);
        await Assert.That(wire.InventoryReads).IsGreaterThan(0);
        await Assert.That(wire.Issued.Count).IsGreaterThan(0);
        if (mode is not "retain-a" and not "retain-b")
        {
            await Assert.That(wire.RoleCount).IsEqualTo(0);
            await Assert.That(wire.Issued.All(l => wire.Rejected.Contains(l.Id))).IsTrue();
        }
        else
            await Assert.That(wire.RoleCount).IsGreaterThan(0);
    }

    [Test]
    [Arguments("CreateDefinitionAsync", "preexisting-a", "missing-prerequisite")]
    [Arguments("CreateDefinitionAsync", "preexisting-b", "missing-prerequisite")]
    [Arguments("UpdateDefinitionAsync", "preexisting-a", "missing-prerequisite")]
    [Arguments("UpdateDefinitionAsync", "preexisting-b", "missing-prerequisite")]
    [Arguments("CreateDefinitionAsync", "incomplete", "observer-unavailable")]
    [Arguments("UpdateDefinitionAsync", "unbound", "observer-unavailable")]
    [Arguments("CreateDefinitionAsync", "null-inventory", "observer-unavailable")]
    public async Task RoleInventoryMustBeCompleteBoundAndAbsentBeforeOwnership(string method, string mode, string reason)
    {
        // Given an occupied cluster or an unusable independent inventory.
        await using var wire = new UsernameWire(mode);
        // When a witness requests ownership.
        var result = await RunAsync(wire, method);
        // Then no provider mutation or issuance is allowed.
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.ProviderMutations).IsEqualTo(0);
        await Assert.That(wire.Issued.Count).IsEqualTo(0);
        await Assert.That(wire.RoleCount).IsEqualTo(mode.StartsWith("preexisting-", StringComparison.Ordinal) ? 1 : 0);
    }

    [Test]
    [Arguments("missing")]
    [Arguments("invalid")]
    [Arguments("equal")]
    [Arguments("different-token")]
    public async Task UpdateRequiresDistinctSameTokenBaselineBeforeOwnership(string shape)
    {
        // Given a selected B with no supported distinct baseline A.
        await using var wire = new UsernameWire();
        var input = Input();
        input["baselineUsernameTemplate"] = shape switch
        {
            "missing" => null,
            "invalid" => "not-a-role",
            "equal" => B,
            "different-token" => "sk_u_fedcba9876543210_a",
            _ => throw new ArgumentOutOfRangeException(nameof(shape))
        };
        // When the update witness is selected.
        var result = await RunAsync(wire, "UpdateDefinitionAsync", input: input);
        // Then rejection precedes fixture ownership.
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(wire.ProviderMutations).IsEqualTo(0);
        await Assert.That(wire.Issued.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("Mysql")]
    [Arguments("SqlServer")]
    [Arguments("expression")]
    [Arguments("uppercase")]
    [Arguments("short-token")]
    [Arguments("suffix")]
    public async Task UnsupportedEnginesAndUsernameShapesRemainUnavailable(string shape)
    {
        // Given only literal Postgres names are admitted by this witness.
        await using var wire = new UsernameWire();
        var input = Input();
        if (shape is "Mysql" or "SqlServer") input["profile"]!["engine"] = shape;
        else input["usernameTemplate"] = shape switch
        {
            "expression" => "{{random}}",
            "uppercase" => "sk_u_0123456789ABCDEF_b",
            "short-token" => "sk_u_0123456789abcde_b",
            "suffix" => "sk_u_0123456789abcdef_c",
            _ => throw new ArgumentOutOfRangeException(nameof(shape))
        };
        // When the create witness is requested.
        var result = await RunAsync(wire, "CreateDefinitionAsync", input: input);
        // Then no unsupported SQL role is created.
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(wire.ProviderMutations).IsEqualTo(0);
        await Assert.That(wire.Issued.Count).IsEqualTo(0);
    }

    private static JsonObject Input() => JsonSerializer.SerializeToNode(
        new InfisicalDynamicClientEffects.DynamicInput(
            new("project", "project-slug", "env", EnvironmentId, "/owned"),
            new(NativeSqlEngine.Postgres, "backend.invalid", 5432, "database", "admin", "private-password",
                "create-role", "revoke-role", "renew-role", null, false, null, null),
            60, 300, 120, B, [], ["select"], ["write"], BaselineUsernameTemplate: A), Options)!.AsObject();

    private static async Task<NativeCaseResult> RunAsync(UsernameWire wire, string method,
        string boundary = "independent-effect", JsonObject? input = null)
    {
        var admission = InfisicalLifecycleFamilies.Catalog.Single(a =>
            a.Operation == "i.runtime.InfisicalDynamicClient." + method);
        var row = new NativeCaseDefinition(new("Infisical", admission.Operation, "usernameTemplate.value", "offline", boundary),
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
                            ["usernameTemplate.value"] = new JsonObject { [boundary] = input ?? Input() }
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

    // Roles and immutable issuance history are downstream state, not derived from
    // provider lease records. A second CREATE ROLE never reuses an existing role.
    private sealed class UsernameWire : IAsyncDisposable, IInfisicalDynamicBackendObserver,
        IInfisicalDynamicUsernameObserver
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Dictionary<string, (string Name, string Path)> folders = [];
        private readonly Dictionary<string, Definition> definitions = [];
        private readonly Dictionary<Guid, Issuance> leases = [];
        private readonly Dictionary<string, Issuance?> roles = [];
        private readonly string mode;
        private readonly Task accept;
        private bool selectedAttempt;
        private bool baselineAbsentAfterRejection;
        private readonly Dictionary<Guid, int> acceptedMeasurements = [];
        internal Uri Origin { get; }
        internal int RuntimeMutations { get; private set; }
        internal int ProviderMutations { get; private set; }
        internal int InventoryReads { get; private set; }
        internal int DuplicateAcquisitions { get; private set; }
        internal bool InventoryBeforeOwnership { get; private set; }
        internal bool BaselineRemeasuredAfterMutation { get; private set; }
        internal bool BaselineRejectedAndAbsentBeforeReissue { get; private set; }
        internal bool BaselineHeldDuringSelectedIssuance { get; private set; }
        internal bool BaselineAcceptedAfterSelectedIssuance { get; private set; }
        internal List<Issuance> Issued { get; } = [];
        internal HashSet<Guid> Accepted { get; } = [];
        internal HashSet<Guid> Rejected { get; } = [];
        internal List<string[]> AbsentInventories { get; } = [];
        internal int RecordCount { get { lock (folders) return folders.Count + definitions.Count + leases.Count; } }
        internal int RoleCount { get { lock (folders) return roles.Count; } }

        internal UsernameWire(string mode = "good")
        {
            this.mode = mode;
            if (mode == "preexisting-a") roles[A] = null;
            if (mode == "preexisting-b") roles[B] = null;
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

        private (int, object) Handle(string method, Uri uri, string principal, JsonElement body)
        {
            string path = uri.AbsolutePath;
            if (principal == "denied")
            {
                selectedAttempt = true;
                return (403, new { });
            }
            if (method is "POST" or "PATCH" or "DELETE") ProviderMutations++;
            if (path == "/api/v1/secret-validation-rules/dynamic-secrets")
                return (200, new { secretValidationRules = Array.Empty<object>() });
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
            if (principal == "runtime" && method is "POST" or "PATCH")
            {
                RuntimeMutations++;
                selectedAttempt = true;
            }
            if (path == "/api/v1/dynamic-secrets")
            {
                if (method == "GET") return (200, new { dynamicSecrets = definitions.Values.Select(DefinitionJson).ToArray() });
                string name = body.GetProperty("name").GetString()!;
                definitions[name] = new(Guid.NewGuid(), name,
                    folders.Single(f => f.Value.Path == body.GetProperty("path").GetString()).Key,
                    body.GetProperty("defaultTTL").GetString()!, body.GetProperty("maxTTL").GetString()!,
                    body.TryGetProperty("usernameTemplate", out var template) ? template.GetString() : null, 1);
                return (200, new { dynamicSecret = DefinitionJson(definitions[name]) });
            }
            if (path == "/api/v1/dynamic-secrets/leases")
            {
                var definition = definitions[body.GetProperty("dynamicSecretName").GetString()!];
                string user = definition.Template ?? "default-user";
                if (mode == "wrong-username" && user == B) user = "unexpected-user";
                if (roles.ContainsKey(user))
                {
                    DuplicateAcquisitions++;
                    return (409, new { });
                }
                if (user == A && Issued.Any(l => l.User == A))
                    BaselineRejectedAndAbsentBeforeReissue = baselineAbsentAfterRejection;
                if (user == B && roles.TryGetValue(A, out var baseline) && baseline is not null)
                    BaselineHeldDuringSelectedIssuance = Accepted.Contains(baseline.Id);
                var issuance = new Issuance(Guid.NewGuid(), definition.Id, user, "password-" + Guid.NewGuid().ToString("N"));
                leases[issuance.Id] = issuance;
                roles[user] = issuance;
                Issued.Add(issuance);
                return (200, new
                {
                    dynamicSecret = DefinitionJson(definition),
                    lease = LeaseJson(issuance),
                    data = new { DB_USERNAME = issuance.User, DB_PASSWORD = issuance.Password }
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
                    if (!(mode == "retain-a" && lease.User == A || mode == "retain-b" && lease.User == B))
                        roles.Remove(lease.User);
                }
                return (200, new { lease = LeaseJson(lease) });
            }
            string selectedName = Uri.UnescapeDataString(segments[4]);
            if (!definitions.TryGetValue(selectedName, out var selected)) return (404, new { });
            if (segments.Length > 5)
                return (200, new { leases = leases.Values.Where(l => l.DefinitionId == selected.Id).Select(LeaseJson).ToArray() });
            if (method == "PATCH")
            {
                var data = body.GetProperty("data");
                selected = selected with
                {
                    DefaultTtl = data.GetProperty("defaultTTL").GetString()!,
                    Template = mode == "ignore-update" ? selected.Template :
                        data.TryGetProperty("usernameTemplate", out var template) ? template.GetString() : selected.Template,
                    Version = selected.Version + 1
                };
                definitions[selectedName] = selected;
                if (mode == "premature-revoke") roles.Remove(A);
            }
            // Removing native records cannot erase downstream SQL roles.
            if (method == "DELETE") definitions.Remove(selectedName);
            return (200, new { dynamicSecret = DefinitionJson(selected) });
        }

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
        private static object LeaseJson(Issuance lease) => new
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

        public ValueTask<DynamicUsernameFacts> InspectUsernamesAsync(DynamicUsernameCoordinate coordinate,
            IReadOnlyList<string> usernames, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (folders)
            {
                InventoryReads++;
                bool bound = coordinate == new DynamicUsernameCoordinate(NativeSqlEngine.Postgres, "backend.invalid", 5432, "database");
                string[] existing = usernames.Where(roles.ContainsKey).ToArray();
                if (ProviderMutations == 0 && bound && usernames.Contains(A) && usernames.Contains(B) && existing.Length == 0)
                    InventoryBeforeOwnership = true;
                if (bound && existing.Length == 0)
                {
                    AbsentInventories.Add(usernames.ToArray());
                    if (usernames.Contains(A) && Issued.Any(l => l.User == A && Rejected.Contains(l.Id)))
                        baselineAbsentAfterRejection = true;
                }
                return ValueTask.FromResult(mode == "null-inventory" ? null! : new DynamicUsernameFacts(
                    mode == "unbound" ? coordinate with { Database = "other" } : coordinate,
                    mode == "unbound" ? [] : usernames.ToArray(), existing, bound && mode != "incomplete"));
            }
        }

        public ValueTask<DynamicBackendFacts> MeasureAsync(DynamicBackendCoordinate coordinate,
            SecretMaterial username, SecretMaterial password, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (folders)
            {
                // Match the immutable actual issuance, not a potentially erased lease record.
                var issued = Issued.SingleOrDefault(l => l.Id == coordinate.LeaseId && l.DefinitionId == coordinate.DefinitionId &&
                    l.User == username.Reveal() && l.Password == password.Reveal());
                bool bound = coordinate.Engine == NativeSqlEngine.Postgres && coordinate.Host == "backend.invalid" &&
                    coordinate.Port == 5432 && coordinate.Database == "database";
                bool active = issued is not null && roles.TryGetValue(issued.User, out var role) && role == issued && bound;
                bool accepted = active && !(mode == "reject-auth" && issued!.User == B);
                if (issued is not null)
                {
                    if (accepted)
                    {
                        Accepted.Add(issued.Id);
                        acceptedMeasurements[issued.Id] = acceptedMeasurements.GetValueOrDefault(issued.Id) + 1;
                    }
                    else Rejected.Add(issued.Id);
                    if (accepted && issued.User == A && (selectedAttempt || acceptedMeasurements[issued.Id] > 1))
                        BaselineRemeasuredAfterMutation = true;
                    if (accepted && issued.User == A && Issued.Any(l => l.User == B))
                        BaselineAcceptedAfterSelectedIssuance = true;
                }
                return ValueTask.FromResult(new DynamicBackendFacts(
                    mode == "wrong-coordinate" && active ? coordinate with { Database = "other" } : coordinate,
                    mode == "unavailable" && active ? BackendAuthentication.Unavailable :
                        accepted ? BackendAuthentication.Accepted : BackendAuthentication.Rejected,
                    active ? mode == "wrong-actions" ? ["insert"] : ["select"] : [],
                    active ? ["write"] : [],
                    active ? Epoch.AddSeconds(mode == "wrong-expiry" ? 122 : 121) : null));
            }
        }

        internal async Task VerifyStorageContractAsync()
        {
            var definition = new Definition(Guid.NewGuid(), "fixture", "folder", "60s", "300s", A, 1);
            definitions[definition.Name] = definition;
            using var body = JsonDocument.Parse("""{"dynamicSecretName":"fixture"}""");
            var acquisition = new Uri(Origin, "/api/v1/dynamic-secrets/leases");
            await Assert.That(Handle("POST", acquisition, "setup", body.RootElement).Item1).IsEqualTo(200);
            var first = Issued.Single();
            await Assert.That(Handle("POST", acquisition, "setup", body.RootElement).Item1).IsEqualTo(409);
            var coordinate = new DynamicBackendCoordinate(NativeSqlEngine.Postgres, "backend.invalid", 5432,
                "database", definition.Id, first.Id);
            using var user = SecretMaterial.FromText(first.User);
            using var password = SecretMaterial.FromText(first.Password);
            await Assert.That((await MeasureAsync(coordinate, user, password, CancellationToken.None)).Authentication)
                .IsEqualTo(BackendAuthentication.Accepted);
            Handle("DELETE", new(Origin, "/api/v1/dynamic-secrets/fixture"), "administrative", body.RootElement);
            await Assert.That(RoleCount).IsEqualTo(1);
            await Assert.That((await MeasureAsync(coordinate, user, password, CancellationToken.None)).Authentication)
                .IsEqualTo(BackendAuthentication.Accepted);
            Handle("DELETE", new(Origin, "/api/v1/dynamic-secrets/leases/" + first.Id), "administrative", body.RootElement);
            await Assert.That((await MeasureAsync(coordinate, user, password, CancellationToken.None)).Authentication)
                .IsEqualTo(BackendAuthentication.Rejected);
            var inventory = await InspectUsernamesAsync(new(NativeSqlEngine.Postgres, "backend.invalid", 5432, "database"),
                [A, B], CancellationToken.None);
            await Assert.That(inventory.ExistingUsernames.Length).IsEqualTo(0);
            definitions[definition.Name] = definition;
            await Assert.That(Handle("POST", acquisition, "setup", body.RootElement).Item1).IsEqualTo(200);
            var second = Issued[1];
            await Assert.That(second.Id == first.Id || second.Password == first.Password).IsFalse();
            await Assert.That((await MeasureAsync(coordinate, user, password, CancellationToken.None)).Authentication)
                .IsEqualTo(BackendAuthentication.Rejected);
            Handle("DELETE", new(Origin, "/api/v1/dynamic-secrets/leases/" + second.Id), "administrative", body.RootElement);
            Handle("DELETE", new(Origin, "/api/v1/dynamic-secrets/fixture"), "administrative", body.RootElement);
            await Assert.That(RecordCount).IsEqualTo(0);
            await Assert.That(RoleCount).IsEqualTo(0);
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
            string MaximumTtl, string? Template, int Version);
        internal sealed record Issuance(Guid Id, Guid DefinitionId, string User, string Password);
    }
}
