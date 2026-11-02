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

public sealed class InfisicalIdentitySearchEffectTests
{
    [Test]
    [Arguments("good", "selected-contract")]
    [Arguments("good", "independent-effect")]
    [Arguments("good", "denied-authority")]
    [Arguments("good", "cancellation-boundary")]
    [Arguments("paged", "independent-effect")]
    public async Task LdapLastLoginRequiresIssuedTokensCanariesAndBothDirections(string mode, string caseName)
    {
        await using var fixture = new LdapIdentityFixture(mode);
        var result = await fixture.RunAsync("SearchIdentities", "order.LastLogin", caseName);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(fixture.Source.SuccessfulIdentityCount).IsEqualTo(2);
        await Assert.That(fixture.LoginNamesOpposeOrder).IsTrue();
        await Assert.That(fixture.AscendingSearches > 0 && fixture.DescendingSearches > 0).IsTrue();
        await Assert.That(fixture.ProjectFallbackRows > 0).IsTrue();
        await Assert.That(fixture.Source.Sealed).IsTrue();
        await Assert.That(fixture.AllowedReads >= 2 && fixture.DeniedReads >= 2).IsTrue();
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
        if (mode == "paged")
            await Assert.That(fixture.AscendingSearches > 1 && fixture.DescendingSearches > 1).IsTrue();
    }

    [Test]
    [Arguments("name-sorted")]
    [Arguments("reversed")]
    [Arguments("null-first")]
    [Arguments("tie-reversed")]
    [Arguments("project-fallback-poison")]
    [Arguments("omitted-authmethod")]
    [Arguments("source-timestamp-poison")]
    [Arguments("duplicate")]
    [Arguments("missing-membership")]
    [Arguments("pages")]
    [Arguments("inventory-incomplete")]
    [Arguments("no-visibility")]
    [Arguments("login-wronguser")]
    [Arguments("canary-bypass")]
    [Arguments("same-authority-substitution")]
    public async Task LdapLastLoginRejectsPoisonedSourceAndFullResults(string mode)
    {
        await using var fixture = new LdapIdentityFixture(mode);
        var result = await fixture.RunAsync("SearchIdentities", "order.LastLogin");
        await Assert.That(result.Passed).IsFalse();
        // Unavailability alone is not a regression oracle: the qualified profile must be exercised.
        await Assert.That(fixture.Source.Opened).IsTrue();
        await Assert.That(fixture.Source.SuccessfulIdentityCount >= 1).IsTrue();
    }

    private const string Org = "00000000-0000-0000-0000-000000000001";
    private const string Date = "2026-10-12T00:00:00.000Z";

    [Test]
    public async Task FixtureSetupUsesValidNativeShapes()
    {
        await using var backend = new Backend("good");
        using var environment = Environment(backend.Origin);
        var definition = new NativeCaseDefinition(new("Infisical", Operation("SearchIdentities"), "name.eq", "local", "independent-effect"),
            InfisicalIdentityFamilies.Bindings[Operation("SearchIdentities")].Member);
        var c = new ProjectFamilyContext(environment, "IdentitySearch", definition, new());
        var project = await c.ExecuteAsync(() => ProjectOperations.CreateProject(Org, "fixture", "fixture",
            createDefaultEnvironments: false), NativeIdentityRole.Setup, CancellationToken.None);
        await Assert.That(project.Status).IsEqualTo(SecretStatus.Success);
        var member = await c.ExecuteAsync(() => MembershipOperations.AddProjectIdentity(Org, project.Value.Id,
            c.Required("observerIdentityId"), new MembershipRoleSelection(roles: [new("viewer")])),
            NativeIdentityRole.Setup, CancellationToken.None);
        await Assert.That(member.Status).IsEqualTo(SecretStatus.Success);
        var identity = await c.ExecuteAsync(() => IdentityOperations.CreateOrganizationIdentity(Org, "identity", "member"),
            NativeIdentityRole.Setup, CancellationToken.None);
        await Assert.That(identity.Status).IsEqualTo(SecretStatus.Success);
        var read = await c.ExecuteAsync(() => IdentityOperations.GetOrganizationIdentity(Org, identity.Value.Id),
            NativeIdentityRole.Observer, CancellationToken.None);
        await Assert.That(read.Status).IsEqualTo(SecretStatus.Success);
    }

    [Test]
    [Arguments("duplicate", "scope.Organization")]
    [Arguments("drop-owned", "order.Name")]
    [Arguments("ignore-filter", "name.eq")]
    [Arguments("ignore-filter", "name.contains")]
    [Arguments("ignore-filter", "role.eq")]
    [Arguments("ignore-filter", "role.contains")]
    [Arguments("first-in", "name.in")]
    [Arguments("first-in", "role.in")]
    [Arguments("first-or", "filter.anyOf.clauses")]
    [Arguments("ignore-name", "filter.all")]
    [Arguments("ignore-role", "filter.all")]
    [Arguments("name-order", "order.Role")]
    [Arguments("duplicate", "scope.Projects")]
    [Arguments("drop-project", "scope.Organization-Projects")]
    [Arguments("wrong-role", "scope.Projects")]
    [Arguments("duplicate-role", "scope.Projects")]
    [Arguments("search-incomplete", "scope.Organization")]
    [Arguments("search-incomplete", "scope.Projects")]
    [Arguments("read-name", "name.eq")]
    [Arguments("ignore-role-update", "order.Role")]
    [Arguments("contains-as-eq", "name.contains")]
    [Arguments("contains-as-eq", "role.contains")]
    public async Task SearchCannotCertifyPoisonedResults(string mode, string variant)
    {
        await using var backend = new Backend(mode);
        using var environment = Environment(backend.Origin);
        var result = await RunAsync(environment, "SearchIdentities", variant);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode is "effect-mismatch" or "contract-mismatch").IsTrue();
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("duplicate", "filter.omitted")]
    [Arguments("drop-owned", "filter.omitted")]
    [Arguments("ignore-filter", "name.eq")]
    [Arguments("first-in", "role.in")]
    public async Task CountsCannotUsePoisonedSearchAsTheirOracle(string mode, string variant)
    {
        await using var backend = new Backend(mode);
        using var environment = Environment(backend.Origin);
        var result = await RunAsync(environment, "CountIdentities", variant);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode is "effect-mismatch" or "contract-mismatch").IsTrue();
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("inventory-incomplete", "filter.omitted")]
    [Arguments("inventory-duplicate", "filter.omitted")]
    [Arguments("inventory-drop-owned", "filter.omitted")]
    [Arguments("project-inventory-incomplete", "scope.Projects")]
    [Arguments("project-inventory-duplicate", "scope.Projects")]
    public async Task UnreliableIndependentInventoriesCannotPass(string mode, string variant)
    {
        await using var backend = new Backend(mode);
        using var environment = Environment(backend.Origin);
        var result = await RunAsync(environment, "SearchIdentities", variant);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode is "observer-unavailable" or "effect-mismatch").IsTrue();
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    public async Task AllSearchVariantsPreserveCasesAndAcceptLegitimateUnownedMatches()
    {
        foreach (string operation in new[] { "SearchIdentities", "CountIdentities" })
            foreach (string variant in InfisicalIdentityFamilies.Bindings[Operation(operation)].Variants)
                foreach (string caseName in new[] { "selected-contract", "independent-effect", "denied-authority", "cancellation-boundary" })
                {
                    await using var backend = new Backend("good");
                    using var environment = Environment(backend.Origin);
                    var result = await RunAsync(environment, operation, variant, caseName);
                    string expected = variant == "order.LastLogin" ? "observer-unavailable" : "observed";
                    if (result.ReasonCode != expected)
                        throw new InvalidOperationException(operation + "|" + variant + "|" + caseName + "|" + result.ReasonCode);
                    await Assert.That(backend.OwnedCount).IsEqualTo(0);
                    await Assert.That(backend.UnownedPresent).IsTrue();
                }
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    public async Task LastLoginWithoutNativeWitnessesIsUnavailable(string caseName)
    {
        await using var backend = new Backend("name-order");
        using var environment = Environment(backend.Origin);
        var result = await RunAsync(environment, "SearchIdentities", "order.LastLogin", caseName);
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("updatedIdentityRole", "order.Role")]
    [Arguments("updatedIdentityRole", "role.eq")]
    [Arguments("identitySearchExcludedRole", "role.in")]
    [Arguments("organizationId", "order.LastLogin")]
    public async Task MissingSearchInputsRemainMissingInput(string input, string variant)
    {
        await using var backend = new Backend("good");
        using var environment = Environment(backend.Origin, missing: input);
        var result = await RunAsync(environment, "SearchIdentities", variant);
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    public async Task EqualConfiguredRoleWitnessesAreMissingInput()
    {
        await using var backend = new Backend("good");
        using var environment = Environment(backend.Origin, alternateRole: "member");
        var result = await RunAsync(environment, "SearchIdentities", "order.Role");
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    public async Task SearchDenominatorAndMissingInputClassificationRemainIntact()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using JsonDocument inventory = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        var expected = inventory.RootElement.GetProperty("operations").EnumerateArray()
            .Where(o => o.GetProperty("id").GetString()!.StartsWith("i.management.IdentitySearchOperations.", StringComparison.Ordinal))
            .SelectMany(o => o.GetProperty("variants").EnumerateArray().SelectMany(v =>
                o.GetProperty("requiredCases").EnumerateArray().Select(c => new NativeCaseDefinition(
                    new("Infisical", o.GetProperty("id").GetString()!, v.GetString()!, "local", c.GetString()!),
                    o.GetProperty("member").GetString()!)))).ToArray();
        await Assert.That(expected.Length).IsEqualTo(156);
        await Assert.That(expected.All(InfisicalIdentityFamilies.Valid)).IsTrue();
        await Assert.That(expected.Count(d => InfisicalIdentityFamilies.UnavailableReason(d) is not null)).IsEqualTo(4);
        using var environment = Environment(new("http://127.0.0.1:1/"), missing: "organizationId");
        var registry = new NativeCaseRegistry();
        InfisicalIdentityFamilies.Register(registry, environment, expected);
        var results = await NativeCaseRunner.RunAsync(registry, expected, CancellationToken.None);
        await Assert.That(results.All(r => !r.Passed && r.ReasonCode == "missing-input")).IsTrue();
    }

    private static string Operation(string operation) => "i.management.IdentitySearchOperations." + operation;

    private static async Task<NativeCaseResult> RunAsync(NativeEnvironment environment,
        string operation, string variant, string caseName = "independent-effect")
    {
        var definition = new NativeCaseDefinition(new("Infisical", Operation(operation), variant, "local", caseName),
            InfisicalIdentityFamilies.Bindings[Operation(operation)].Member);
        var registry = new NativeCaseRegistry();
        InfisicalIdentityFamilies.Register(registry, environment, [definition]);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }

    private static NativeEnvironment Environment(Uri origin, string? missing = null, string alternateRole = "admin")
    {
        var input = new Dictionary<string, string>
        {
            ["organizationId"] = Org,
            ["administrativeIdentityId"] = "00000000-0000-0000-0000-000000000002",
            ["observerIdentityId"] = "00000000-0000-0000-0000-000000000003",
            ["runtimeIdentityId"] = "00000000-0000-0000-0000-000000000004",
            ["identityRole"] = "member",
            ["updatedIdentityRole"] = alternateRole,
            ["identitySearchExcludedRole"] = "no-access",
            ["projectIdentityRole"] = "viewer"
        };
        if (missing is not null) input.Remove(missing);
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            administrative = "administrative",
            observer = "observer",
            runtime = "runtime",
            denied = "denied",
            families = new Dictionary<string, object>
            {
                ["C08-IM-IdentitySearch"] = new { scopes = new Dictionary<string, object> { ["local"] = input } }
            }
        }));
    }

    // Separate native-shaped state and SDK HTTP transport, not a replacement for live evidence.
    internal sealed class Backend : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        internal readonly Dictionary<string, JsonObject> identities = [];
        internal readonly Dictionary<string, JsonObject> projects = [];
        internal readonly Dictionary<(string Project, string Identity), JsonObject> memberships = [];
        internal LdapIdentityFixture? Ldap { get; set; }
        private readonly string mode;
        private readonly Task accept;
        private bool searched;
        private bool inventoryPoisoned;
        private const string Unowned = "00000000-0000-0000-0000-000000000099";
        internal Uri Origin { get; }
        internal int OwnedCount
        {
            get
            {
                lock (identities) return identities.Count - 1 +
                    projects.Keys.Count(p => Ldap?.IsPreprovisionedCanaryProject(p) != true);
            }
        }
        internal bool UnownedPresent { get { lock (identities) return identities.ContainsKey(Unowned); } }

        internal Backend(string mode)
        {
            this.mode = mode;
            identities[Unowned] = Identity(Unowned, "unrelated", "member");
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
                    string role = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?.Split(' ').Last() ?? "";
                    int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?.Split(':')[1] ?? "0");
                    if (length is < 0 or > 65536) throw new InvalidOperationException("fixture-budget");
                    byte[] bytes = new byte[length];
                    await stream.ReadExactlyAsync(bytes, shutdown.Token);
                    JsonObject body = length == 0 ? new() : JsonNode.Parse(bytes)!.AsObject();
                    (int Status, JsonNode Payload) response;
                    lock (identities) response = Handle(request[0], new Uri(Origin, request[1]), role, body);
                    byte[] payload = Encoding.UTF8.GetBytes(response.Payload.ToJsonString());
                    await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {response.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {payload.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                    await stream.WriteAsync(payload, shutdown.Token);
                }
                catch (IOException) { }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            }
        }

        private (int, JsonNode) Handle(string method, Uri uri, string role, JsonObject body)
        {
            if (Ldap?.Handle(method, uri, role, body) is { } ldapResponse) return ldapResponse;
            if (role == "denied") return (403, new JsonObject());
            string[] path = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (path[1] == "v2") return Search(path[^1] == "count", body);
            if (path[2] == "identities")
            {
                if (path.Length == 3 && method == "GET")
                {
                    var rows = identities.Values.Select(i => OrganizationMembership(i, list: true)).ToList();
                    // Corrupt the audit read, not the later cleanup ownership discovery.
                    if (!searched && !inventoryPoisoned)
                    {
                        inventoryPoisoned = true;
                        if (mode == "inventory-incomplete") return Page("identities", rows, rows.Count + 1);
                        if (mode == "inventory-duplicate") rows.Add((JsonObject)rows[^1].DeepClone());
                        if (mode == "inventory-drop-owned" && rows.Count > 2) rows.RemoveAt(rows.Count - 1);
                    }
                    return Page("identities", rows);
                }
                string id = path.Length == 3 ? Guid.NewGuid().ToString() : path[^1];
                if (method == "POST") identities[id] = Identity(id, Text(body, "name"), Text(body, "role"));
                if (!identities.TryGetValue(id, out var identity)) return (404, new JsonObject());
                if (method == "PATCH")
                {
                    if (body["role"] is { } changed && mode != "ignore-role-update") identity["fixtureRole"] = changed.DeepClone();
                    if (body["hasDeleteProtection"] is { } protection) identity["hasDeleteProtection"] = protection.DeepClone();
                }
                if (method == "DELETE")
                {
                    identities.Remove(id);
                    Ldap?.RemoveIdentity(id);
                    foreach (var key in memberships.Keys.Where(k => k.Identity == id).ToArray()) memberships.Remove(key);
                }
                var returnedIdentity = method == "GET" ? OrganizationMembership(identity) : PublicIdentity(identity);
                if (method == "GET" && mode == "read-name") returnedIdentity["identity"]!["name"] = "mismatched";
                if (method != "GET")
                {
                    returnedIdentity.Remove("activeLockoutAuthMethods");
                    if (method is "PATCH" or "DELETE") returnedIdentity.Remove("authMethods");
                    if (method == "DELETE") returnedIdentity.Remove("metadata");
                }
                return (200, new JsonObject { ["identity"] = returnedIdentity });
            }
            if (path[2] != "projects") return (404, new JsonObject());
            if (path.Length == 3)
            {
                if (method == "GET") return (200, new JsonObject { ["projects"] = new JsonArray(projects.Values.Select(p => p.DeepClone()).ToArray()) });
                string id = Guid.NewGuid().ToString();
                projects[id] = new()
                {
                    ["id"] = id,
                    ["_id"] = id,
                    ["orgId"] = Org,
                    ["type"] = "secret-manager",
                    ["name"] = body["projectName"]!.DeepClone(),
                    ["slug"] = body["slug"]!.DeepClone(),
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["hasDeleteProtection"] = false,
                    ["environments"] = new JsonArray(),
                    ["deletedEnvironments"] = new JsonArray()
                };
                return (200, new JsonObject { ["project"] = projects[id].DeepClone() });
            }
            string? projectId = path[3] == "slug" ? projects.Values.SingleOrDefault(p => Text(p, "slug") == path[4])?["id"]?.GetValue<string>() : path[3];
            if (projectId is null || !projects.TryGetValue(projectId, out var project)) return (404, new JsonObject());
            if (path.Length >= 5 && path[4] == "memberships")
            {
                if (path.Length == 6 && path[5] == "identities")
                {
                    var rows = memberships.Where(m => m.Key.Project == projectId && identities.ContainsKey(m.Key.Identity))
                        .Select(m => MembershipRead(m.Value, list: true)).ToList();
                    if (mode == "project-inventory-duplicate") rows.Add((JsonObject)rows[^1].DeepClone());
                    return Page("identityMemberships", rows, rows.Count + (mode == "project-inventory-incomplete" ? 1 : 0));
                }
                string identityId = path[^1];
                var key = (projectId, identityId);
                if (method == "POST")
                    memberships[key] = new()
                    {
                        ["id"] = Guid.NewGuid().ToString(),
                        ["identityId"] = identityId,
                        ["projectId"] = projectId,
                        ["orgId"] = Org,
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date,
                        ["roles"] = new JsonArray(body["roles"]!.AsArray().Select(r => (JsonNode)new JsonObject
                        {
                            ["id"] = Guid.NewGuid().ToString(),
                            ["role"] = r!["role"]!.DeepClone(),
                            ["isTemporary"] = false
                        }).ToArray())
                    };
                if (!memberships.TryGetValue(key, out var member)) return (404, new JsonObject());
                var returnedMember = method == "GET" ? MembershipRead(member) : (JsonObject)member.DeepClone();
                if (method != "GET")
                {
                    returnedMember.Remove("roles");
                    returnedMember.Remove("orgId");
                }
                return (200, new JsonObject { ["identityMembership"] = returnedMember });
            }
            if (method == "DELETE")
            {
                projects.Remove(projectId);
                foreach (var key in memberships.Keys.Where(k => k.Project == projectId).ToArray()) memberships.Remove(key);
            }
            var returned = (JsonObject)project.DeepClone();
            if (method == "DELETE")
                foreach (string field in new[] { "_id", "environments", "deletedEnvironments" }) returned.Remove(field);
            return (200, path[3] == "slug" ? returned : new JsonObject { ["project"] = returned });
        }

        private static JsonObject Identity(string id, string name, string role) => new()
        {
            ["id"] = id,
            ["orgId"] = Org,
            ["name"] = name,
            ["fixtureRole"] = role,
            ["createdAt"] = Date,
            ["updatedAt"] = Date,
            ["hasDeleteProtection"] = false,
            ["authMethods"] = new JsonArray(),
            ["activeLockoutAuthMethods"] = new JsonArray(),
            ["metadata"] = new JsonArray()
        };

        private static JsonObject PublicIdentity(JsonObject identity)
        {
            var value = (JsonObject)identity.DeepClone();
            value.Remove("fixtureRole");
            return value;
        }

        private JsonObject OrganizationMembership(JsonObject identity, bool list = false)
        {
            var member = new JsonObject
            {
                ["id"] = Text(identity, "id"),
                ["identityId"] = Text(identity, "id"),
                ["orgId"] = Org,
                ["role"] = Text(identity, "fixtureRole"),
                ["createdAt"] = Date,
                ["updatedAt"] = Date,
                ["identity"] = list ? Only(identity, "id", "name", "hasDeleteProtection", "authMethods") :
                    Only(identity, "id", "name", "orgId", "hasDeleteProtection", "authMethods", "activeLockoutAuthMethods")
            };
            if (!list) member["metadata"] = new JsonArray();
            Ldap?.AddLoginFields(member, Text(identity, "id"));
            return member;
        }

        private JsonObject MembershipRead(JsonObject membership, bool list = false)
        {
            var value = Only(membership, "id", "createdAt", "updatedAt", "roles");
            if (list) value["identityId"] = membership["identityId"]!.DeepClone();
            var identity = identities[Text(membership, "identityId")];
            value["identity"] = list ? Only(identity, "id", "name", "orgId", "authMethods", "activeLockoutAuthMethods")
                : Only(identity, "id", "name", "orgId", "authMethods", "metadata");
            if (!list) Ldap?.AddLoginFields(value, Text(identity, "id"));
            return value;
        }

        private (int, JsonNode) Search(bool count, JsonObject body)
        {
            searched = true;
            var rows = new List<JsonObject>();
            string[] scopes = body["scope"]!.AsArray().Select(s => s!.GetValue<string>()).ToArray();
            foreach (var identity in identities.Values)
            {
                if (scopes.Contains("organization")) rows.Add(SearchRow(identity, OrganizationMembership(identity), null));
                if (scopes.Contains("project"))
                    foreach (var member in memberships.Where(m => m.Key.Identity == Text(identity, "id")))
                        rows.Add(SearchRow(identity, member.Value, member.Key.Project));
            }
            rows = rows.Where(r => mode == "ignore-filter" || Matches(r, body["search"] as JsonObject)).ToList();
            if (mode == "duplicate" && rows.Count != 0) rows.Add((JsonObject)rows[0].DeepClone());
            if (mode == "drop-owned")
            {
                string? id = identities.Keys.Where(i => i != Unowned).Skip(1).FirstOrDefault();
                rows.RemoveAll(r => Text(r, "identityId") == id);
            }
            if (mode == "drop-project") rows.RemoveAll(r => Text(r, "scope") == "project");
            if (mode == "wrong-role")
                foreach (var row in rows) row["roles"]![0]!["role"] = "forged";
            if (mode == "duplicate-role")
                foreach (var row in rows) row["roles"]!.AsArray().Add(row["roles"]![0]!.DeepClone());
            if (count) return (200, new JsonObject
            {
                ["counts"] = new JsonObject
                {
                    ["organization"] = rows.Count(r => Text(r, "scope") == "organization"),
                    ["project"] = rows.Count(r => Text(r, "scope") == "project")
                }
            });
            rows = (Text(body, "orderBy") == "role" && mode != "name-order"
                ? rows.OrderBy(r => Text(r["roles"]![0]!.AsObject(), "role"), StringComparer.Ordinal)
                : rows.OrderBy(r => Text(r["identity"]!.AsObject(), "name"), StringComparer.Ordinal)).ToList();
            if (Text(body, "orderDirection") == "desc") rows.Reverse();
            if (Ldap is not null) rows = Ldap.SearchRows(rows, body);
            if (Ldap?.Mode == "paged")
                return Page("identities", rows.Skip(body["offset"]!.GetValue<int>()).Take(2).ToList(), rows.Count);
            return Page("identities", rows, rows.Count + (mode == "search-incomplete" ? 1 : 0));
        }

        private static JsonObject SearchRow(JsonObject identity, JsonObject membership, string? project) => new()
        {
            ["id"] = membership["id"]!.DeepClone(),
            ["identityId"] = Text(identity, "id"),
            ["orgId"] = Org,
            ["scope"] = project is null ? "organization" : "project",
            ["projectId"] = project,
            ["createdAt"] = Date,
            ["updatedAt"] = Date,
            ["identity"] = Only(identity, "id", "name", "orgId", "hasDeleteProtection", "authMethods", "activeLockoutAuthMethods"),
            ["roles"] = membership["roles"]?.DeepClone() ?? new JsonArray(new JsonObject
            {
                ["id"] = Text(membership, "id"),
                ["role"] = membership["role"]!.DeepClone(),
                ["isTemporary"] = false
            })
        };

        private bool Matches(JsonObject row, JsonObject? filter)
        {
            if (filter is null) return true;
            bool Field(string field, JsonNode? condition)
            {
                if (condition is null || mode == "ignore-" + field) return true;
                string value = field == "name" ? Text(row["identity"]!.AsObject(), "name") : Text(row["roles"]![0]!.AsObject(), "role");
                if (condition is JsonValue scalar) return value == scalar.GetValue<string>();
                var operators = condition.AsObject();
                return (!operators.ContainsKey("$eq") || value == Text(operators, "$eq")) &&
                    (!operators.ContainsKey("$contains") || (mode == "contains-as-eq"
                        ? value == Text(operators, "$contains")
                        : value.Contains(Text(operators, "$contains"), StringComparison.Ordinal))) &&
                    (operators["$in"] is not JsonArray alternatives ||
                        (mode == "first-in" ? alternatives.Take(1) : alternatives).Any(n => n!.GetValue<string>() == value));
            }
            bool Clause(JsonObject clause) => Field("name", clause["name"]) && Field("role", clause["role"]);
            return Clause(filter) && (filter["$or"] is not JsonArray clauses ||
                (mode == "first-or" ? clauses.Take(1) : clauses).Any(n => Clause(n!.AsObject())));
        }

        private static (int, JsonNode) Page(string field, List<JsonObject> rows, int? total = null) =>
            (200, new JsonObject { [field] = new JsonArray(rows.Select(r => (JsonNode)r).ToArray()), ["totalCount"] = total ?? rows.Count });

        private static string Text(JsonObject value, string field) => value[field]!.GetValue<string>();

        private static JsonObject Only(JsonObject value, params string[] fields) => new(value
            .Where(p => fields.Contains(p.Key)).Select(p => new KeyValuePair<string, JsonNode?>(p.Key, p.Value?.DeepClone())));

        public async ValueTask DisposeAsync()
        {
            shutdown.Cancel();
            try { await accept; }
            finally { listener.Stop(); }
            await Task.WhenAll(connections);
            shutdown.Dispose();
        }
    }
}
