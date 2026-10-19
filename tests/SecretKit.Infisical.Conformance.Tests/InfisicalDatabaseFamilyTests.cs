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

public sealed class InfisicalDatabaseFamilyTests
{
    private const string Org = "00000000-0000-0000-0000-000000000001";
    private const string Date = "2026-10-12T00:00:00.000Z";

    [Test]
    public async Task OwnedProjectFixtureMatchesPublicSetupAndCleanupSeams()
    {
        await using var wire = new Backend("good");
        using var env = Environment(wire.Origin);
        var d = Definition("ProjectConnection", "ListAuthorizations", "collection.bounded");
        var c = new ProjectFamilyContext(env, "ProjectConnections", d, new NativeCaseProbe());
        string name = ProjectFamilyContext.FreshName();
        var created = await c.ExecuteAsync(() => ProjectOperations.CreateProject(Org, name, name,
            createDefaultEnvironments: false), NativeIdentityRole.Setup, CancellationToken.None);
        await Assert.That(created.Status).IsEqualTo(SecretStatus.Success);
        var found = await c.ExecuteAsync(() => ProjectOperations.GetProjectBySlug(Org, name),
            NativeIdentityRole.Observer, CancellationToken.None);
        await Assert.That(found.Status).IsEqualTo(SecretStatus.Success);
        var deleted = await c.ExecuteAsync(() => ProjectOperations.DeleteProject(Org, created.Value.Id),
            NativeIdentityRole.Setup, CancellationToken.None);
        await Assert.That(deleted.Status).IsEqualTo(SecretStatus.Success);
        var absent = await c.ExecuteAsync(() => ProjectOperations.GetProject(Org, created.Value.Id),
            NativeIdentityRole.Observer, CancellationToken.None);
        await Assert.That(absent.Status).IsEqualTo(SecretStatus.Absent);
        await Assert.That(wire.ProjectCount).IsEqualTo(0);
    }

    [Test]
    public async Task ExactCompilerBindingsAndUnavailableDenominator()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using var inventory = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root,
            "docs/internal/releases/admission/infisical.json")));
        var expected = inventory.RootElement.GetProperty("operations").EnumerateArray()
            .Where(o => InfisicalDatabaseFamilies.Owns(o.GetProperty("id").GetString()!))
            .SelectMany(o => o.GetProperty("variants").EnumerateArray().SelectMany(v =>
                o.GetProperty("requiredCases").EnumerateArray().Select(c => new NativeCaseDefinition(
                    new("Infisical", o.GetProperty("id").GetString()!, v.GetString()!, "local", c.GetString()!),
                    o.GetProperty("member").GetString()!)))).ToArray();
        await Assert.That(expected.Length).IsEqualTo(1067);
        await Assert.That(expected.All(InfisicalDatabaseFamilies.Valid)).IsTrue();
        await Assert.That(expected.Select(d => (d.Key.Operation, d.Key.Variant)).Distinct().Count()).IsEqualTo(218);
        await Assert.That(expected.Count(d => InfisicalDatabaseFamilies.UnavailableReason(d) is not null)).IsEqualTo(45);
        using var environment = Environment(new Uri("http://127.0.0.1:1/"), inputs: false);
        var registry = new NativeCaseRegistry();
        InfisicalDatabaseFamilies.Register(registry, environment, expected);
        var results = await NativeCaseRunner.RunAsync(registry, expected, CancellationToken.None);
        await Assert.That(results.All(r => !r.Passed && !r.EffectObserved)).IsTrue();
        await Assert.That(results.Count(r => r.ReasonCode == "observer-unavailable")).IsEqualTo(1059);
        await Assert.That(results.Count(r => r.ReasonCode == "missing-input")).IsEqualTo(8);
    }

    [Test]
    [Arguments("Postgres")]
    [Arguments("MySql")]
    [Arguments("MsSql")]
    [Arguments("ProjectConnection")]
    public async Task EveryExecutableVariantAndCaseUsesOwnedMeasuredState(string profile)
    {
        await using var wire = new Backend("good");
        using var env = Environment(wire.Origin);
        var definitions = Definitions(profile).Where(d => InfisicalDatabaseFamilies.UnavailableReason(d) is null).ToArray();
        foreach (var definition in definitions)
        {
            var result = await RunAsync(env, definition, wire);
            await Assert.That((definition.Key.Operation, definition.Key.Variant, definition.Key.Case, result.ReasonCode))
                .IsEqualTo((definition.Key.Operation, definition.Key.Variant, definition.Key.Case, "observed"));
            await Assert.That(result.EffectObserved).IsTrue();
            await Assert.That(wire.ProjectCount).IsEqualTo(0);
            await Assert.That(wire.RotationCount).IsEqualTo(0);
            await Assert.That(wire.MappingCount).IsEqualTo(0);
        }
        await Assert.That(wire.LeaseNames.Distinct().Count()).IsEqualTo(wire.LeaseNames.Count);
        await Assert.That(wire.MaximumAdministrativeMutationsPerLease).IsLessThanOrEqualTo(1);
    }

    [Test]
    [Arguments("backend-unavailable", "observer-unavailable")]
    [Arguments("backend-denied", "effect-mismatch")]
    [Arguments("denied-accepted", "effect-mismatch")]
    [Arguments("privilege-drift", "effect-mismatch")]
    [Arguments("backend-coordinate-drift", "effect-mismatch")]
    [Arguments("primary-unestablished", "observer-unavailable")]
    [Arguments("native-drift", "effect-mismatch")]
    [Arguments("mapping-drift", "effect-mismatch")]
    [Arguments("cleanup", "cleanup-incomplete")]
    [Arguments("dispose-failure", "cleanup-incomplete")]
    public async Task AcknowledgementCannotSubstituteForBackendOrReadback(string mode, string reason)
    {
        await using var wire = new Backend(mode);
        using var env = Environment(wire.Origin);
        var definition = mode == "mapping-drift" ?
            Definition("Postgres", "GetGeneratedCredentials", "selector.exact") :
            Definition("Postgres", "CheckCredentials", "input.organizationId-address");
        var result = await RunAsync(env, definition, wire);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(wire.ProjectCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("Postgres")]
    [Arguments("MySql")]
    [Arguments("MsSql")]
    public async Task OmittedDeletionDefaultsAndPatchContractCannotBeGuessed(string profile)
    {
        foreach (string method in new[] { "Delete", "Update" })
        {
            await using var wire = new Backend("unknown-defaults");
            using var env = Environment(wire.Origin);
            string variant = method == "Delete" ? "deleteSecrets.omitted.revokeGeneratedCredentials.omitted" : "patch.empty";
            var result = await RunAsync(env, Definition(profile, method, variant), wire);
            await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
            await Assert.That(wire.AdministrativeMutations).IsEqualTo(0);
            await Assert.That(wire.ProjectCount).IsEqualTo(0);
        }
    }

    [Test]
    [Arguments("member")]
    [Arguments("variant")]
    [Arguments("case")]
    [Arguments("provider")]
    public async Task CorruptBindingFailsBeforeFixtureOrNetwork(string corruption)
    {
        await using var wire = new Backend("good");
        using var env = Environment(wire.Origin);
        var d = Definition("Postgres", "Get", "selector.exact");
        d = corruption switch
        {
            "member" => d with { Member = d.Member + ".wrong" },
            "variant" => d with { Key = d.Key with { Variant = "unknown" } },
            "provider" => d with { Key = d.Key with { Provider = "wrong" } },
            _ => d with { Key = d.Key with { Case = "unknown" } }
        };
        var result = await RunAsync(env, d, wire);
        await Assert.That(result.ReasonCode).IsEqualTo("contract-mismatch");
        await Assert.That(wire.LeaseNames.Count).IsEqualTo(0);
        await Assert.That(wire.ProjectCount).IsEqualTo(0);
    }

    [Test]
    public async Task LostResponseAndCancellationKeepExactReceiptBoundaries()
    {
        foreach (string caseName in new[] { "lost-response-no-replay", "cancellation-boundary", "denied-authority" })
        {
            await using var wire = new Backend("good");
            using var env = Environment(wire.Origin);
            var result = await RunAsync(env, Definition("Postgres", "Delete",
                "deleteSecrets.true.revokeGeneratedCredentials.true", caseName), wire);
            await Assert.That(result.ReasonCode).IsEqualTo("observed");
            await Assert.That(wire.AdministrativeMutations).IsEqualTo(caseName == "lost-response-no-replay" ? 1 : 0);
            await Assert.That(wire.RejectionSubscriptionsBeforeDelete).IsEqualTo(caseName == "lost-response-no-replay" ? 1 : 0);
        }
    }

    [Test]
    [Arguments("Postgres", "parameters")]
    [Arguments("Postgres", "secretsMapping")]
    [Arguments("MySql", "parameters")]
    [Arguments("MySql", "secretsMapping")]
    [Arguments("MsSql", "parameters")]
    [Arguments("MsSql", "secretsMapping")]
    public async Task IgnoredNestedPatchCannotPassReadback(string profile, string field)
    {
        await using var wire = new Backend("patch-drift");
        using var env = Environment(wire.Origin);
        var result = await RunAsync(env, Definition(profile, "Update",
            profile + "SecretRotationUpdate." + field + ".value"), wire);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("contract-mismatch");
        await Assert.That(wire.ProjectCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("ListPostgresSubset", "collection.bounded")]
    [Arguments("PostgresOptionsSubset", "catalog.Postgres-only.partial")]
    public async Task PartialCatalogRequiresIndependentUnfilteredData(string method, string variant)
    {
        await using var wire = new Backend("catalog-drift");
        using var env = Environment(wire.Origin);
        var result = await RunAsync(env, Definition("Postgres", method, variant), wire);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("contract-mismatch");
        await Assert.That(wire.ProjectCount).IsEqualTo(0);
    }

    [Test]
    public async Task MeasurementFormattingAndSerializationContainNoMaterial()
    {
        var measured = new DatabaseAuthenticationMeasurement(new(InfisicalRotationProfile.PostgresCredentials,
            "private-host", 5432, "private-database", "private-connection"), DatabaseAuthentication.Accepted,
            DatabaseAuthentication.Rejected, ["private-action"], ["private-denial"], DateTimeOffset.UtcNow);
        await Assert.That(JsonSerializer.Serialize(measured)).IsEqualTo("{}");
        await Assert.That(measured.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
    }

    private static NativeCaseDefinition Definition(string profile, string method, string variant, string caseName = "independent-effect")
    {
        string operation = "i.management." + profile + (profile == "ProjectConnection" ? "Operations." : "SecretRotationOperations.") + method;
        return new(new("Infisical", operation, variant, "local", caseName), InfisicalDatabaseFamilies.Bindings[operation].Member);
    }
    private static IEnumerable<NativeCaseDefinition> Definitions(string profile)
    {
        string prefix = "i.management." + profile + (profile == "ProjectConnection" ? "Operations." : "SecretRotationOperations.");
        foreach (var (operation, binding) in InfisicalDatabaseFamilies.Bindings.Where(b => b.Key.StartsWith(prefix, StringComparison.Ordinal)))
            foreach (string variant in binding.Variants)
                foreach (string caseName in binding.Mutation ?
                    new[] { "selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay" } :
                    ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect"])
                    yield return new(new("Infisical", operation, variant, "local", caseName), binding.Member);
    }
    private static async Task<NativeCaseResult> RunAsync(NativeEnvironment env, NativeCaseDefinition definition, IDatabaseFixtureFactory factory)
    {
        var registry = new NativeCaseRegistry();
        InfisicalDatabaseFamilies.Register(registry, env, [definition], factory);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }
    private static NativeEnvironment Environment(Uri origin, bool inputs = true)
    {
        var families = new Dictionary<string, object>();
        if (inputs)
            foreach (string family in new[] { "ProjectConnections", "PostgresSecretRotations", "MySqlSecretRotations", "MsSqlSecretRotations" })
                families.Add("C08-IM-" + family, new
                {
                    scopes = new Dictionary<string, object>
                    {
                        ["local"] = new
                        {
                            organizationId = Org,
                            administrativeIdentityId = "00000000-0000-0000-0000-000000000002",
                            observerIdentityId = "00000000-0000-0000-0000-000000000003",
                            runtimeIdentityId = "00000000-0000-0000-0000-000000000004"
                        }
                    }
                });
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            administrative = "administrative",
            observer = "observer",
            runtime = "runtime",
            denied = "denied",
            families
        }));
    }

    // Loopback characterization only: no native report producer and no live provider access.
    private sealed class Backend : IDatabaseFixtureFactory, IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Dictionary<string, JsonObject> projects = [];
        private readonly Dictionary<string, JsonObject> rotations = [];
        private readonly Dictionary<(string Project, string Environment, string Path, string Key), string> mappings = [];
        private readonly Dictionary<string, Lease> leases = [];
        private readonly Task accept;
        internal readonly string Mode;
        internal Uri Origin { get; }
        internal List<string> LeaseNames { get; } = [];
        internal int AdministrativeMutations { get; private set; }
        internal int RejectionSubscriptionsBeforeDelete { get; private set; }
        internal int MaximumAdministrativeMutationsPerLease { get; private set; }
        internal int ProjectCount { get { lock (projects) return projects.Count; } }
        internal int RotationCount { get { lock (projects) return rotations.Count; } }
        internal int MappingCount { get { lock (projects) return mappings.Count; } }
        internal Backend(string mode)
        {
            Mode = mode;
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            accept = AcceptAsync();
        }
        public ValueTask<IDatabaseOwnedFixture> CreateAsync(NativeEnvironment env, NativeCaseDefinition definition,
            string projectId, JsonElement input, string name, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (projects)
            {
                var lease = new Lease(this, projectId, name, definition);
                leases.Add(projectId, lease);
                LeaseNames.Add(name);
                return ValueTask.FromResult<IDatabaseOwnedFixture>(lease);
            }
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
                    var header = new List<byte>();
                    byte[] one = new byte[1];
                    while (header.Count < 32768)
                    {
                        if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                        header.Add(one[0]);
                        if (header.Count >= 4 && header[^4] == 13 && header[^3] == 10 && header[^2] == 13 && header[^1] == 10) break;
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
                    lock (projects) response = Handle(request[0], new Uri(Origin, request[1]), role, body);
                    byte[] payload = response.Status == 204 ? [] : Encoding.UTF8.GetBytes(response.Payload.ToJsonString());
                    await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {response.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {payload.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                    await stream.WriteAsync(payload, shutdown.Token);
                }
                catch (IOException) { }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            }
        }
        private static string Text(JsonNode body, string name) => body[name]!.GetValue<string>();
        private static JsonObject Wrap(string field, JsonNode value) => new() { [field] = value.DeepClone() };
        private static Dictionary<string, string> Query(Uri uri) => uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2)).ToDictionary(pair => pair[0], pair => Uri.UnescapeDataString(pair[1]));
        private (int, JsonNode) Handle(string method, Uri uri, string role, JsonObject body)
        {
            if (role == "denied") return (403, new JsonObject());
            string[] path = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var query = Query(uri);
            if (path.Length >= 3 && path[2] == "projects")
            {
                if (path.Length == 3 && method == "POST")
                {
                    string id = Guid.NewGuid().ToString();
                    var p = new JsonObject
                    {
                        ["id"] = id,
                        ["_id"] = id,
                        ["orgId"] = Org,
                        ["name"] = body["projectName"]!.DeepClone(),
                        ["slug"] = body["slug"]!.DeepClone(),
                        ["type"] = "secret-manager",
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date,
                        ["hasDeleteProtection"] = false,
                        ["environments"] = new JsonArray(),
                        ["deletedEnvironments"] = new JsonArray()
                    };
                    projects.Add(id, p);
                    return (200, Wrap("project", p));
                }
                if (path[3] == "slug")
                {
                    var p = projects.Values.SingleOrDefault(p => Text(p, "slug") == path[4]);
                    return p is null ? (404, new JsonObject()) : (200, p.DeepClone());
                }
                string projectId = path[3];
                if (!projects.TryGetValue(projectId, out var owner)) return (404, new JsonObject());
                if (path.Length == 4)
                {
                    JsonObject result = (JsonObject)owner.DeepClone();
                    if (method == "DELETE")
                    {
                        projects.Remove(projectId);
                        foreach (string field in new[] { "_id", "environments", "deletedEnvironments" })
                            result.Remove(field);
                    }
                    return (200, Wrap("project", result));
                }
                if (path[4] == "memberships") return (200, new JsonObject
                {
                    ["identityMembership"] = new JsonObject
                    { ["id"] = Guid.NewGuid().ToString(), ["identityId"] = path[6], ["projectId"] = projectId, ["createdAt"] = Date, ["updatedAt"] = Date }
                });
                if (path[4] is "authorizations" or "integrations") return (200, new JsonObject { [path[4]] = new JsonArray() });
            }
            if (path.Length >= 3 && path[2] == "secrets")
            {
                var key = (query["projectId"], query["environment"], query["secretPath"], Uri.UnescapeDataString(path[^1]));
                if (!mappings.TryGetValue(key, out string? value)) return (404, new JsonObject());
                if (Mode == "mapping-drift" && role == "runtime") value = "not-the-observed-credential";
                return (200, new JsonObject
                {
                    ["secret"] = new JsonObject
                    {
                        ["id"] = Guid.NewGuid().ToString(),
                        ["secretKey"] = key.Item4,
                        ["secretValue"] = value,
                        ["workspace"] = key.Item1,
                        ["environment"] = key.Item2,
                        ["version"] = 1,
                        ["secretValueHidden"] = false
                    }
                });
            }
            if (path.Length < 3 || path[2] != "secret-rotations") return (404, new JsonObject());
            if (path.Length == 3) return (200, new JsonObject
            {
                ["secretRotations"] = new JsonArray(rotations.Values
                .Where(r => Text(r, "projectId") == query["projectId"]).Select(r => r.DeepClone()).Append(new JsonObject { ["id"] = "other", ["type"] = "other-profile" }).ToArray())
            });
            if (path[3] == "options") return (200, new JsonObject { ["secretRotationOptions"] = Options() });
            string profile = path[3];
            if (path.Length == 4 && method == "POST")
            {
                string project = Text(body, "projectId");
                Lease f = leases[project];
                string id = Guid.NewGuid().ToString();
                var row = (JsonObject)body.DeepClone();
                row["id"] = id; row["type"] = profile;
                row["environment"] = new JsonObject { ["id"] = f.EnvironmentId, ["name"] = "Owned", ["slug"] = f.Environment };
                row["folderId"] = f.FolderId;
                row["folder"] = new JsonObject { ["id"] = f.FolderId, ["path"] = f.SourcePath };
                row.Remove("secretPath");
                row["connection"] = new JsonObject { ["id"] = f.ConnectionId, ["app"] = profile.Replace("-credentials", "", StringComparison.Ordinal), ["name"] = "Owned" };
                row["createdAt"] = Date; row["updatedAt"] = Date; row["lastRotatedAt"] = Date;
                row["lastRotationAttemptedAt"] = Date; row["rotationStatus"] = "success"; row["activeIndex"] = 0;
                row["isAutoRotationEnabled"] ??= false;
                row["rotateAtUtc"] ??= new JsonObject { ["hours"] = 0, ["minutes"] = 0 };
                if (!row.ContainsKey("description")) row["description"] = null;
                rotations.Add(id, row);
                if (role == "setup") f.PrepareExpected(row);
                if (role == "administrative") Mutation(f);
                StoreMapping(row, f);
                return (200, Wrap("secretRotation", row));
            }
            if (path.Length == 4) return (200, new JsonObject
            {
                ["secretRotations"] = new JsonArray(rotations.Values
                .Where(r => Text(r, "type") == profile && Text(r, "projectId") == query["projectId"]).Select(r => r.DeepClone()).ToArray())
            });
            JsonObject? selected = path[4] == "rotation-name" ? rotations.Values.SingleOrDefault(r => Text(r, "name") == Uri.UnescapeDataString(path[5]) &&
                Text(r, "projectId") == query["projectId"] && Text(r["environment"]!, "slug") == query["environment"] &&
                Text(r["folder"]!, "path") == query["secretPath"]) : rotations.GetValueOrDefault(path[4]);
            if (selected is null) return (404, new JsonObject());
            Lease fixture = leases[Text(selected, "projectId")];
            if (path.Length > 5 && path[5] == "generated-credentials") return (200, new JsonObject
            {
                ["type"] = profile,
                ["rotationId"] = selected["id"]!.DeepClone(),
                ["activeIndex"] = 0,
                ["generatedCredentials"] = new JsonArray(new JsonObject { ["username"] = selected["parameters"]!["username1"]!.DeepClone(), ["password"] = fixture.Password })
            });
            if (role == "administrative" && method != "GET") Mutation(fixture);
            if (path.Length > 5 && path[5] == "check-credentials")
            {
                if (Mode == "native-drift") selected["rotationInterval"] = 999;
                return (204, new JsonObject());
            }
            if (method == "PATCH" && Mode != "patch-drift")
            {
                foreach (var (key, value) in body) selected[key] = value?.DeepClone();
                RemoveMappings(fixture.ProjectId);
                StoreMapping(selected, fixture);
            }
            if (method == "DELETE")
            {
                bool revoke = query.GetValueOrDefault("revokeGeneratedCredentials") != "false";
                bool delete = query.GetValueOrDefault("deleteSecrets") != "false";
                if (fixture.Rejection is not null) RejectionSubscriptionsBeforeDelete++;
                if (revoke)
                {
                    fixture.Revoked = true;
                    fixture.Rejection?.TrySetResult(fixture.Measure(DatabaseAuthentication.Rejected));
                }
                if (delete) RemoveMappings(fixture.ProjectId);
                rotations.Remove(Text(selected, "id"));
            }
            if (path.Length > 5 && path[5] == "move")
            {
                RemoveMappings(fixture.ProjectId);
                selected["environment"]!["slug"] = body["destinationEnvironment"]!.DeepClone();
                selected["folder"]!["path"] = body["destinationSecretPath"]!.DeepClone();
                StoreMapping(selected, fixture);
            }
            return (200, Wrap("secretRotation", selected));
        }
        private void Mutation(Lease f)
        {
            AdministrativeMutations++;
            f.AdministrativeMutations++;
            MaximumAdministrativeMutationsPerLease = Math.Max(MaximumAdministrativeMutationsPerLease, f.AdministrativeMutations);
        }
        private void StoreMapping(JsonObject row, Lease f)
        {
            string env = Text(row["environment"]!, "slug"), path = Text(row["folder"]!, "path");
            mappings[(f.ProjectId, env, path, Text(row["secretsMapping"]!, "username"))] = Text(row["parameters"]!, "username1");
            mappings[(f.ProjectId, env, path, Text(row["secretsMapping"]!, "password"))] = f.Password;
        }
        private void RemoveMappings(string project)
        {
            foreach (var key in mappings.Keys.Where(k => k.Project == project).ToArray()) mappings.Remove(key);
        }
        private static JsonArray Options() => new(new[] { ("postgres", "PostgreSQL"), ("mysql", "MySQL"), ("mssql", "Microsoft SQL Server") }
            .Select(p => new JsonObject
            {
                ["type"] = p.Item1 + "-credentials",
                ["connection"] = p.Item1,
                ["name"] = p.Item2 + " Credentials",
                ["template"] = new JsonObject
                {
                    ["secretsMapping"] = new JsonObject { ["username"] = "USER", ["password"] = "PASSWORD" },
                    ["createUserStatement"] = "owned-create",
                    ["rotationStatement"] = "owned-rotate"
                }
            }).ToArray());
        public async ValueTask DisposeAsync()
        {
            shutdown.Cancel();
            try { await accept; }
            finally { listener.Stop(); }
            await Task.WhenAll(connections);
            shutdown.Dispose();
        }

        private sealed class Lease : IDatabaseOwnedFixture, IDatabaseBackendObserver
        {
            private readonly Backend owner;
            private readonly NativeCaseDefinition definition;
            internal readonly string ProjectId;
            internal readonly string EnvironmentId = Guid.NewGuid().ToString();
            internal readonly string FolderId = Guid.NewGuid().ToString();
            internal readonly string Password = "owned-password";
            internal bool Revoked;
            internal int AdministrativeMutations;
            internal TaskCompletionSource<DatabaseAuthenticationMeasurement>? Rejection;
            private DatabaseConfiguration? expected;
            private SecretMaterial? expectedStatement;
            internal Lease(Backend owner, string project, string name, NativeCaseDefinition definition)
            { this.owner = owner; ProjectId = project; Name = name; this.definition = definition; }
            public string Name { get; }
            public string Environment => "owned";
            public string SourcePath => "/" + Name;
            public string DestinationEnvironment => "owned-destination";
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
            public string[] AllowedActions => ["owned-select"];
            public string[] DeniedActions => ["owned-denied-write"];
            public string? PrimaryShapeRevision => owner.Mode == "primary-unestablished" ? null : "offline-characterization";
            public DatabaseConfiguration CreationDefaults => new(Name, ConnectionId, Environment, SourcePath, Username1, Username2,
                UsernameKey, PasswordKey, 2, 0, 0, false, true, null, null);
            public DatabaseConfiguration? ExpectedPatchConfiguration => owner.Mode == "unknown-defaults" ? null : expected ?? CreationDefaults;
            public SecretMaterial? ExpectedPatchStatement => expectedStatement;
            public bool? DefaultDeleteSecrets => owner.Mode == "unknown-defaults" ? null : true;
            public bool? DefaultRevokeCredentials => owner.Mode == "unknown-defaults" ? null : true;
            public IDatabaseBackendObserver Backend => this;
            public DatabaseBackendCoordinate BackendCoordinate => new(
                definition.Key.Operation.Contains("Postgres", StringComparison.Ordinal) ? InfisicalRotationProfile.PostgresCredentials :
                definition.Key.Operation.Contains("MySql", StringComparison.Ordinal) ? InfisicalRotationProfile.MysqlCredentials :
                    InfisicalRotationProfile.MssqlCredentials, "owned-backend", 5432, "owned-database", ConnectionId);
            internal void PrepareExpected(JsonObject row)
            {
                JsonObject changed = (JsonObject)row.DeepClone();
                string v = definition.Key.Variant;
                if (v.EndsWith("name.value", StringComparison.Ordinal)) changed["name"] = Name + "-updated";
                if (v.EndsWith("description.value", StringComparison.Ordinal)) changed["description"] = Name + "-updated";
                if (v == "description.null") changed["description"] = null;
                if (v.EndsWith("isAutoRotationEnabled.true", StringComparison.Ordinal)) changed["isAutoRotationEnabled"] = true;
                if (v.EndsWith("isAutoRotationEnabled.false", StringComparison.Ordinal)) changed["isAutoRotationEnabled"] = false;
                if (v.EndsWith("rotationInterval.value", StringComparison.Ordinal)) changed["rotationInterval"] = 3;
                if (v == "rotationInterval.fractional-number") changed["rotationInterval"] = 2.5;
                if (v.EndsWith("rotateAtUtc.value", StringComparison.Ordinal)) changed["rotateAtUtc"] = new JsonObject { ["hours"] = 4, ["minutes"] = 5 };
                if (v == "rotateAtUtc.fractional-number") changed["rotateAtUtc"] = new JsonObject { ["hours"] = 2.5, ["minutes"] = 3.5 };
                if (v.EndsWith("secretsMapping.value", StringComparison.Ordinal)) changed["secretsMapping"] = new JsonObject { ["username"] = UpdatedUsernameKey, ["password"] = UpdatedPasswordKey };
                if (v.Contains("RotationParameters.", StringComparison.Ordinal) || v.Contains("RotationPasswordRequirements.", StringComparison.Ordinal) ||
                    v == "passwordRequirements.fractional-number" || v.EndsWith("parameters.value", StringComparison.Ordinal))
                {
                    changed["parameters"]!["username1"] = UpdatedUsername1;
                    changed["parameters"]!["username2"] = UpdatedUsername2;
                    if (changed["parameters"]!["rotationStatement"] is not null) changed["parameters"]!["rotationStatement"] = "owned-updated-statement";
                }
                expected = Capture(changed);
                string? statement = changed["parameters"]!["rotationStatement"]?.GetValue<string>();
                if (statement is not null) expectedStatement = SecretMaterial.FromText(statement);
            }
            private static DatabaseConfiguration Capture(JsonObject row)
            {
                JsonNode parameters = row["parameters"]!, mapping = row["secretsMapping"]!, time = row["rotateAtUtc"]!;
                JsonNode? requirements = parameters["passwordRequirements"];
                DatabasePasswordRequirements? r = requirements is null ? null : new(Number(requirements["length"]!),
                    Number(requirements["required"]!["digits"]!), Number(requirements["required"]!["lowercase"]!),
                    Number(requirements["required"]!["symbols"]!), Number(requirements["required"]!["uppercase"]!),
                    requirements["allowedSymbols"]?.GetValue<string>());
                return new(Text(row, "name"), Text(row, "connectionId"), Text(row["environment"]!, "slug"), Text(row["folder"]!, "path"),
                    Text(parameters, "username1"), Text(parameters, "username2"), Text(mapping, "username"), Text(mapping, "password"),
                    Number(row["rotationInterval"]!), Number(time["hours"]!), Number(time["minutes"]!),
                    row["isAutoRotationEnabled"]!.GetValue<bool>(), row.ContainsKey("description"), row["description"]?.GetValue<string>(), r);
            }
            private static double Number(JsonNode value) => JsonSerializer.SerializeToElement(value).GetDouble();
            internal DatabaseAuthenticationMeasurement Measure(DatabaseAuthentication selected) => new(
                owner.Mode == "backend-coordinate-drift" ? BackendCoordinate with { Database = "substituted" } : BackendCoordinate, selected,
                owner.Mode == "denied-accepted" ? DatabaseAuthentication.Accepted : DatabaseAuthentication.Rejected,
                owner.Mode == "privilege-drift" ? ["wrong-privilege"] : AllowedActions, DeniedActions, DateTimeOffset.UtcNow);
            public ValueTask<DatabaseAuthenticationMeasurement> MeasureAuthorityAsync(CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                return ValueTask.FromResult(Measure(owner.Mode == "backend-unavailable" ? DatabaseAuthentication.Unavailable :
                    owner.Mode == "backend-denied" ? DatabaseAuthentication.Rejected : DatabaseAuthentication.Accepted));
            }
            public ValueTask<DatabaseAuthenticationMeasurement> AuthenticateAsync(SecretMaterial username, SecretMaterial password, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                lock (owner.projects)
                {
                    using var expectedPassword = SecretMaterial.FromText(Password);
                    bool matches = InfisicalDatabaseFamilies.SameMaterial(password, expectedPassword);
                    char[] chars = username.ExportCharacters();
                    try { matches &= new[] { Username1, UpdatedUsername1 }.Any(u => chars.AsSpan().SequenceEqual(u)); }
                    finally { Array.Clear(chars); }
                    var selected = owner.Mode == "backend-unavailable" ? DatabaseAuthentication.Unavailable :
                        owner.Mode == "backend-denied" || Revoked || !matches ? DatabaseAuthentication.Rejected : DatabaseAuthentication.Accepted;
                    return ValueTask.FromResult(Measure(selected));
                }
            }
            public ValueTask<IDatabaseRejectionSubscription> SubscribeRejectionAsync(SecretMaterial username, SecretMaterial password, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                Rejection = new(TaskCreationOptions.RunContinuationsAsynchronously);
                return ValueTask.FromResult<IDatabaseRejectionSubscription>(new Subscription(Rejection.Task));
            }
            public ValueTask<DatabaseCatalogMeasurement> ObserveCatalogAsync(bool options, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                lock (owner.projects)
                {
                    if (owner.Mode == "catalog-drift")
                        return ValueTask.FromResult(new DatabaseCatalogMeasurement([new("other", "other-profile")], []));
                    if (!options) return ValueTask.FromResult(new DatabaseCatalogMeasurement(owner.rotations.Values
                        .Where(r => Text(r, "projectId") == ProjectId).Select(r => new DatabaseCatalogRow(Text(r, "id"), Text(r, "type")))
                        .Append(new("other", "other-profile")).ToArray(), []));
                    return ValueTask.FromResult(new DatabaseCatalogMeasurement([], Options().Select(o => new DatabaseCatalogOption(Text(o!, "type"),
                        Text(o!["template"]!["secretsMapping"]!, "username"), Text(o["template"]!["secretsMapping"]!, "password"),
                        SecretMaterial.FromText(Text(o["template"]!, "createUserStatement")), SecretMaterial.FromText(Text(o["template"]!, "rotationStatement")))).ToArray()));
                }
            }
            public ValueTask CleanupAsync(CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                lock (owner.projects)
                {
                    foreach (string id in owner.rotations.Where(r => Text(r.Value, "projectId") == ProjectId).Select(r => r.Key).ToArray()) owner.rotations.Remove(id);
                    owner.RemoveMappings(ProjectId); Revoked = true;
                }
                return ValueTask.CompletedTask;
            }
            public ValueTask<DatabaseCleanupMeasurement> ObserveCleanupAsync(CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                return ValueTask.FromResult(new DatabaseCleanupMeasurement(owner.Mode == "cleanup" ? 1 : 0, 0, 0));
            }
            public ValueTask DisposeAsync()
            {
                RotationStatement.Dispose(); UpdatedRotationStatement.Dispose(); expectedStatement?.Dispose();
                if (owner.Mode == "dispose-failure") throw new InvalidOperationException("fixture-dispose");
                return ValueTask.CompletedTask;
            }
            public override string ToString() => "[OwnedDatabaseFixture]";
            private sealed class Subscription(Task<DatabaseAuthenticationMeasurement> rejected) : IDatabaseRejectionSubscription
            {
                public Task<DatabaseAuthenticationMeasurement> Rejected => rejected;
                public ValueTask DisposeAsync() => ValueTask.CompletedTask;
            }
        }
    }
}
