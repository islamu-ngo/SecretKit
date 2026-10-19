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

public sealed class InfisicalIdentityFamilyTests
{
    private const string Org = "00000000-0000-0000-0000-000000000001";
    private const string Date = "2026-10-12T00:00:00.000Z";

    [Test]
    [Arguments("CreateOrganizationIdentity")]
    [Arguments("CreateProjectIdentity")]
    public async Task CleanupRejectsIdentityIdSubstitution(string operation)
    {
        await using var backend = new Backend("identity-substitution");
        using var environment = Environment(backend.Origin);
        var result = await RunAsync(environment,
            Definition("IdentityOperations." + operation, "metadata.value", "independent-effect"));
        await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete").Because(result.ReasonCode);
        await Assert.That(backend.ForeignIdentityPresent).IsTrue();
        await Assert.That(backend.ForeignMutations).IsEqualTo(0);
    }

    [Test]
    [Arguments("UpdateOrganizationIdentity", "deleteProtection.false", "ignore-clear")]
    [Arguments("UpdateProjectIdentity", "deleteProtection.false", "ignore-clear")]
    [Arguments("UpdateOrganizationIdentity", "deleteProtection.omitted", "clear-omitted")]
    [Arguments("UpdateProjectIdentity", "deleteProtection.omitted", "clear-omitted")]
    public async Task ProtectionUpdatesRequireContrastingAndPreservedState(string operation, string variant, string mode)
    {
        foreach (string caseName in new[] { "selected-contract", "independent-effect", "lost-response-no-replay" })
        {
            await using var backend = new Backend(mode);
            using var environment = Environment(backend.Origin);
            var result = await RunAsync(environment, Definition("IdentityOperations." + operation, variant, caseName));
            await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch").Because(result.ReasonCode);
            await Assert.That(backend.OwnedCount).IsEqualTo(0);
        }
    }

    [Test]
    [Arguments("ListOrganizationIdentities", "collection.bounded", "duplicate-list", "effect-mismatch")]
    [Arguments("ListProjectIdentities", "search.omitted", "incomplete-list", "effect-mismatch")]
    [Arguments("ListProjectIdentities", "search.value", "ignore-list-search", "contract-mismatch")]
    public async Task LifecycleListsRequireUniqueCompleteMatchingFixtures(string operation, string variant, string mode, string reason)
    {
        await using var backend = new Backend(mode);
        using var environment = Environment(backend.Origin);
        var result = await RunAsync(environment, Definition("IdentityOperations." + operation, variant, "independent-effect"));
        await Assert.That(result.ReasonCode).IsEqualTo(reason).Because(result.ReasonCode);
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    public async Task FixtureIdentityReadsAndCleanupUseValidNativeShapes()
    {
        await using var backend = new Backend("good");
        using var environment = Environment(backend.Origin);
        var c = new ProjectFamilyContext(environment, "Identities",
            Definition("IdentityOperations.CreateOrganizationIdentity", "metadata.omitted", "selected-contract"), new());
        var created = await c.ExecuteAsync(() => IdentityOperations.CreateOrganizationIdentity(Org, "fixture", "member"),
            NativeIdentityRole.Setup, CancellationToken.None);
        await Assert.That(created.Status).IsEqualTo(SecretStatus.Success);
        var listed = await c.ExecuteAsync(() => IdentityOperations.ListOrganizationIdentities(Org),
            NativeIdentityRole.Observer, CancellationToken.None);
        await Assert.That(listed.Status).IsEqualTo(SecretStatus.Success);
        var read = await c.ExecuteAsync(() => IdentityOperations.GetOrganizationIdentity(Org, created.Value.Id),
            NativeIdentityRole.Observer, CancellationToken.None);
        await Assert.That(read.Status).IsEqualTo(SecretStatus.Success);
        var clear = await c.ExecuteAsync(() => IdentityOperations.UpdateOrganizationIdentity(Org, created.Value.Id,
            deleteProtection: false), NativeIdentityRole.Setup, CancellationToken.None);
        await Assert.That(clear.Status).IsEqualTo(SecretStatus.Success);
        var deleted = await c.ExecuteAsync(() => IdentityOperations.DeleteOrganizationIdentity(Org, created.Value.Id),
            NativeIdentityRole.Setup, CancellationToken.None);
        await Assert.That(deleted.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    public async Task ExactAdmissionDenominatorBindsWithoutLiveInputs()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using JsonDocument inventory = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        var expected = inventory.RootElement.GetProperty("operations").EnumerateArray()
            .Where(o => InfisicalIdentityFamilies.Owns(o.GetProperty("id").GetString()!))
            .SelectMany(o => o.GetProperty("variants").EnumerateArray().SelectMany(v =>
                o.GetProperty("requiredCases").EnumerateArray().Select(c => new NativeCaseDefinition(
                    new("Infisical", o.GetProperty("id").GetString()!, v.GetString()!, "local", c.GetString()!),
                    o.GetProperty("member").GetString()!)))).ToArray();
        await Assert.That(expected.Length).IsEqualTo(832);
        await Assert.That(expected.Select(d => d.Key.Operation).Distinct().Count()).IsEqualTo(25);
        await Assert.That(expected.Select(d => (d.Key.Operation, d.Key.Variant)).Distinct().Count()).IsEqualTo(178);
        await Assert.That(expected.All(InfisicalIdentityFamilies.Valid)).IsTrue();
        await Assert.That(expected.Count(d => InfisicalIdentityFamilies.UnavailableReason(d) is not null)).IsEqualTo(28);
        using NativeEnvironment environment = Environment(new("http://127.0.0.1:1/"), false);
        var registry = new NativeCaseRegistry();
        InfisicalIdentityFamilies.Register(registry, environment, expected);
        var results = await NativeCaseRunner.RunAsync(registry, expected, CancellationToken.None);
        await Assert.That(results.All(r => !r.Passed && r.ReasonCode == "missing-input")).IsTrue();
    }

    [Test]
    public async Task EveryExecutableVariantAndCaseUsesOwnedStateThroughPublicSdk()
    {
        foreach ((string operation, var binding) in InfisicalIdentityFamilies.Bindings)
            foreach (string variant in binding.Variants)
                foreach (string caseName in binding.Mutation
                    ? new[] { "selected-contract", "independent-effect", "denied-authority", "cancellation-boundary", "lost-response-no-replay" }
                    : ["selected-contract", "independent-effect", "denied-authority", "cancellation-boundary"])
                {
                    await using var backend = new Backend("good");
                    using NativeEnvironment environment = Environment(backend.Origin, variant: variant);
                    var definition = new NativeCaseDefinition(new("Infisical", operation, variant, "local", caseName), binding.Member);
                    var result = await RunAsync(environment, definition);
                    string expected = InfisicalIdentityFamilies.UnavailableReason(definition) is null ? "observed" : "observer-unavailable";
                    // Only material-free machine labels are assertion context.
                    if (result.ReasonCode != expected)
                        throw new InvalidOperationException(operation + "|" + variant + "|" + caseName + "|" + result.ReasonCode);
                    await Assert.That(backend.OwnedCount).IsEqualTo(0);
                    await Assert.That(backend.AdministrativeMutations).IsLessThanOrEqualTo(
                        caseName is "denied-authority" or "cancellation-boundary" ? 0 : 1);
                }
    }

    [Test]
    [Arguments("member")]
    [Arguments("variant")]
    [Arguments("case")]
    [Arguments("scope")]
    public async Task ExactBindingRejectsTamperingBeforeSetup(string corruption)
    {
        var definition = Definition("IdentityOperations.CreateOrganizationIdentity", "metadata.value", "independent-effect");
        definition = corruption switch
        {
            "member" => definition with { Member = "wrong" },
            "variant" => definition with { Key = definition.Key with { Variant = "wrong" } },
            "case" => definition with { Key = definition.Key with { Case = "wrong" } },
            _ => definition with { Key = definition.Key with { Scope = "wrong" } }
        };
        await using var backend = new Backend("good");
        using var environment = Environment(backend.Origin);
        var result = await RunAsync(environment, definition);
        await Assert.That(result.ReasonCode).IsEqualTo(corruption == "scope" ? "missing-input" : "contract-mismatch");
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("drift", "effect-mismatch")]
    [Arguments("coordinate", "contract-mismatch")]
    [Arguments("cleanup", "cleanup-incomplete")]
    public async Task AcknowledgementDoesNotHideDriftScopeEscapeOrCleanupFailure(string mode, string reason)
    {
        await using var backend = new Backend(mode);
        using var environment = Environment(backend.Origin);
        var result = await RunAsync(environment,
            Definition("IdentityOperations.CreateOrganizationIdentity", "metadata.value", "independent-effect"));
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(result.Passed).IsFalse();
        if (mode != "cleanup") await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    private static NativeCaseDefinition Definition(string operation, string variant, string caseName)
    {
        string id = "i.management." + operation;
        return new(new("Infisical", id, variant, "local", caseName), InfisicalIdentityFamilies.Bindings[id].Member);
    }
    private static async Task<NativeCaseResult> RunAsync(NativeEnvironment environment, NativeCaseDefinition definition)
    {
        var registry = new NativeCaseRegistry();
        InfisicalIdentityFamilies.Register(registry, environment, [definition]);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }
    private static NativeEnvironment Environment(Uri origin, bool inputs = true, string? variant = null)
    {
        var families = new Dictionary<string, object>();
        if (inputs)
            foreach (string family in new[] { "Identities", "IdentitySearch", "IdentityTemplates", "IdentityTemplateVariants" })
                families["C08-IM-" + family] = new
                {
                    scopes = new Dictionary<string, object>
                    {
                        ["local"] = new
                        {
                            organizationId = Org,
                            administrativeIdentityId = "00000000-0000-0000-0000-000000000002",
                            observerIdentityId = "00000000-0000-0000-0000-000000000003",
                            runtimeIdentityId = "00000000-0000-0000-0000-000000000004",
                            identityRole = "member",
                            updatedIdentityRole = "admin",
                            identitySearchExcludedRole = "viewer",
                            projectIdentityRole = "viewer",
                            roleStartsAt = Date,
                            roleDuration = "1h",
                            oidcDiscoveryUrl = "https://issuer.invalid",
                            baselineOidcDiscoveryUrl = "https://baseline-issuer.invalid",
                            boundIssuer = "fixture-issuer",
                            baselineBoundIssuer = "baseline-issuer",
                            boundSubject = "fixture-subject",
                            boundAudiences = "fixture-audience",
                            caCertificate = "fixture-ca",
                            ldapCaCertificate = "fixture-ldap-ca",
                            ldapUrl = "ldaps://ldap.invalid",
                            baselineLdapUrl = "ldaps://baseline-ldap.invalid",
                            bindDn = "fixture-dn",
                            baselineBindDn = "baseline-dn",
                            bindPassword = "fixture-password",
                            searchBase = "fixture-base",
                            baselineSearchBase = "baseline-base",
                            baselineTokenReviewMode = variant == "IdentityTemplateKubernetesFields.tokenReviewMode.Gateway"
                                ? "api" : "gateway",
                            kubernetesHost = "https://kubernetes.invalid",
                            gatewayId = "00000000-0000-0000-0000-000000000005",
                            gatewayPoolId = "00000000-0000-0000-0000-000000000006",
                            tokenReviewerJwt = "fixture-reviewer",
                            allowedAudience = "fixture-audience",
                            allowedNames = "fixture-name",
                            allowedNamespaces = "fixture-namespace"
                        }
                    }
                };
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

    // Offline stateful characterization only; this server cannot issue native evidence.
    private sealed class Backend : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Dictionary<string, JsonObject> identities = [];
        private readonly Dictionary<string, JsonObject> projects = [];
        private readonly Dictionary<string, JsonObject> templates = [];
        private readonly Dictionary<(string Project, string Identity), JsonObject> memberships = [];
        private readonly Dictionary<string, JsonObject> auth = [];
        private readonly Task accept;
        private readonly string mode;
        private const string ForeignId = "00000000-0000-0000-0000-000000000099";
        private bool identityObserved;
        private bool inventoryCorrupted;
        internal Uri Origin { get; }
        internal int AdministrativeMutations { get; private set; }
        internal int ForeignMutations { get; private set; }
        internal bool ForeignIdentityPresent { get { lock (identities) return identities.ContainsKey(ForeignId); } }
        internal int OwnedCount { get { lock (identities) return identities.Count + projects.Count + templates.Count + auth.Count; } }
        internal Backend(string mode)
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
                        if (headers.Count >= 4 && headers[^4] == 13 && headers[^3] == 10 && headers[^2] == 13 && headers[^1] == 10) break;
                    }
                    string[] lines = Encoding.ASCII.GetString(headers.ToArray()).Split("\r\n");
                    string[] request = lines[0].Split(' ');
                    string role = lines.Single(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase)).Split(' ').Last();
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
            if (role == "denied") return (403, new JsonObject());
            string[] path = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            Dictionary<string, string> query = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(q => q.Split('=', 2)).ToDictionary(q => q[0], q => Uri.UnescapeDataString(q[1]));
            if (role == "administrative" && method != "GET" && !uri.AbsolutePath.Contains("/search", StringComparison.Ordinal))
                AdministrativeMutations++;
            if (path[1] == "v2") return Search(path[^1] == "count", body);
            if (path[2] == "auth") return Authentication(method, path, body);
            if (path[2] == "identity-templates") return Template(method, path, query, body);
            if (path[2] == "identities") return Identity(method, path, role, query, body, null);
            if (path[2] == "projects")
            {
                if (path.Length == 3 && method == "GET")
                    return (200, new JsonObject
                    { ["projects"] = new JsonArray(projects.Values.Select(p => p.DeepClone()).ToArray()) });
                if (path.Length == 3 && method == "POST")
                {
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
                    if (path.Length == 6 && path[5] == "identities" && method == "GET")
                    {
                        var rows = memberships.Where(m => m.Key.Project == projectId && identities.ContainsKey(m.Key.Identity))
                            .Select(m =>
                            {
                                var row = Only(m.Value, "id", "identityId", "createdAt", "updatedAt", "roles");
                                row["identity"] = Only(identities[m.Key.Identity], "id", "name", "orgId",
                                    "authMethods", "activeLockoutAuthMethods");
                                return (JsonNode)row;
                            }).ToArray();
                        return (200, new JsonObject
                        { ["identityMemberships"] = new JsonArray(rows), ["totalCount"] = rows.Length });
                    }
                    string identity = path[^1];
                    var key = (projectId, identity);
                    if (method == "POST")
                        memberships[key] = Membership(projectId, identity, body["roles"]?.AsArray() ?? new JsonArray());
                    if (!memberships.TryGetValue(key, out var membership)) return (404, new JsonObject());
                    var returned = method == "GET"
                        ? Only(membership, "id", "createdAt", "updatedAt", "roles")
                        : Only(membership, "id", "identityId", "projectId", "createdAt", "updatedAt");
                    if (method == "GET" && identities.TryGetValue(identity, out var selected))
                        returned["identity"] = Only(selected, "id", "name", "orgId", "projectId", "authMethods", "metadata");
                    return (200, new JsonObject { ["identityMembership"] = returned });
                }
                if (path.Length >= 5 && path[4] == "identities")
                    return Identity(method, path, role, query, body, projectId);
                if (method == "DELETE")
                {
                    projects.Remove(projectId);
                    foreach (var key in memberships.Keys.Where(k => k.Project == projectId).ToArray()) memberships.Remove(key);
                }
                var returnedProject = (JsonObject)project.DeepClone();
                if (method == "DELETE")
                    foreach (string field in new[] { "_id", "environments", "deletedEnvironments" }) returnedProject.Remove(field);
                return (200, path[3] == "slug" ? returnedProject : new JsonObject { ["project"] = returnedProject });
            }
            return (404, new JsonObject());
        }

        private (int, JsonNode) Identity(string method, string[] path, string role,
            Dictionary<string, string> query, JsonObject body, string? project)
        {
            if (path[^1] == "details")
                return (200, new JsonObject
                {
                    ["identityDetails"] = new JsonObject
                    { ["organization"] = new JsonObject { ["id"] = Org, ["name"] = "fixture", ["slug"] = "fixture" } }
                });
            bool collection = project is null ? path.Length == 3 : path.Length == 5;
            if (collection && method == "GET")
            {
                var rows = identities.Values.Where(i => i["projectId"]?.GetValue<string>() == project &&
                    (mode == "ignore-list-search" && role == "administrative" ||
                    !query.TryGetValue("search", out string? search) || Text(i, "name").Contains(search, StringComparison.Ordinal)))
                    .Select(i => project is null ? OrganizationMembership(i, list: true) : (JsonNode)i.DeepClone()).ToArray();
                if (!inventoryCorrupted && role == "observer" && rows.Length > 1 &&
                    mode is "duplicate-list" or "incomplete-list")
                {
                    inventoryCorrupted = true;
                    rows = mode == "duplicate-list" ? [.. rows, rows[0].DeepClone()] : rows[..^1];
                }
                if (mode == "identity-substitution" && identityObserved)
                {
                    if (!identities.ContainsKey(ForeignId)) rows = [];
                    else
                        foreach (JsonNode row in rows)
                            if (project is null) { row["identityId"] = ForeignId; row["identity"]!["id"] = ForeignId; }
                            else row["id"] = ForeignId;
                }
                return (200, new JsonObject { ["identities"] = new JsonArray(rows), ["totalCount"] = rows.Length });
            }
            string id = collection ? Guid.NewGuid().ToString() : path[^1];
            if (method == "POST")
            {
                identities[id] = new()
                {
                    ["id"] = id,
                    ["orgId"] = Org,
                    ["projectId"] = project,
                    ["name"] = body["name"]!.DeepClone(),
                    ["hasDeleteProtection"] = body["hasDeleteProtection"]?.DeepClone() ?? JsonValue.Create(false),
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["authMethods"] = new JsonArray(),
                    ["activeLockoutAuthMethods"] = new JsonArray(),
                    ["metadata"] = Metadata(body["metadata"]?.AsArray())
                };
                if (project is null) identities[id]["fixtureRole"] = body["role"]?.DeepClone() ?? JsonValue.Create("member");
                else memberships[(project, id)] = Membership(project, id, body["roles"]?.AsArray() ?? new JsonArray());
                if (mode == "identity-substitution")
                {
                    identities[ForeignId] = (JsonObject)identities[id].DeepClone();
                    identities[ForeignId]["id"] = ForeignId;
                    identities[ForeignId]["name"] = "unrelated";
                }
            }
            if (!identities.TryGetValue(id, out var identity)) return (404, new JsonObject());
            if (id == ForeignId && method is "PATCH" or "DELETE") ForeignMutations++;
            if (mode == "identity-substitution" && role == "observer" && method == "GET" && id != ForeignId)
                identityObserved = true;
            if (method == "PATCH")
            {
                foreach (string field in new[] { "name", "hasDeleteProtection" })
                    if (body.ContainsKey(field) && !(mode == "ignore-clear" && role == "administrative" &&
                        field == "hasDeleteProtection" && body[field]!.GetValue<bool>() == false))
                        identity[field] = body[field]?.DeepClone();
                if (mode == "clear-omitted" && role == "administrative" && !body.ContainsKey("hasDeleteProtection"))
                    identity["hasDeleteProtection"] = false;
                if (body.ContainsKey("role")) identity["fixtureRole"] = body["role"]?.DeepClone();
                if (body.ContainsKey("metadata")) identity["metadata"] = Metadata(body["metadata"]!.AsArray());
            }
            if (method == "DELETE" && mode != "cleanup")
            {
                identities.Remove(id);
                auth.Remove(id);
                foreach (var key in memberships.Keys.Where(k => k.Identity == id).ToArray()) memberships.Remove(key);
            }
            JsonObject value = (JsonObject)identity.DeepClone();
            value.Remove("fixtureRole");
            if (project is null && method != "GET")
            {
                value.Remove("activeLockoutAuthMethods");
                if (method is "PATCH" or "DELETE") value.Remove("authMethods");
                if (method == "DELETE") value.Remove("metadata");
            }
            if (method == "GET" && mode == "drift") value["metadata"] = new JsonArray();
            if (role == "administrative" && mode == "coordinate") value["orgId"] = "wrong";
            // Organization GET uses an outer membership; mutations return the native identity.
            return (200, new JsonObject
            {
                ["identity"] = project is null && method == "GET"
                ? OrganizationMembership(value, Text(identity, "fixtureRole")) : value
            });
        }
        private static JsonArray Metadata(JsonArray? source) => new((source ?? []).Select(item =>
            (JsonNode)new JsonObject
            {
                ["id"] = Guid.NewGuid().ToString(),
                ["key"] = item!["key"]!.DeepClone(),
                ["value"] = item["value"]!.DeepClone()
            }).ToArray());
        private static JsonObject OrganizationMembership(JsonObject identity, string? role = null, bool list = false)
        {
            JsonObject value = (JsonObject)identity.DeepClone();
            string selectedRole = role ?? value["fixtureRole"]?.GetValue<string>() ?? "member";
            value.Remove("fixtureRole");
            JsonObject result = new()
            {
                ["id"] = Text(value, "id"),
                ["identityId"] = Text(value, "id"),
                ["orgId"] = Org,
                ["role"] = selectedRole,
                ["createdAt"] = Date,
                ["updatedAt"] = Date,
                ["identity"] = list ? Only(value, "id", "name", "hasDeleteProtection", "authMethods")
                    : Only(value, "id", "name", "orgId", "hasDeleteProtection", "authMethods", "activeLockoutAuthMethods")
            };
            if (!list) result["metadata"] = value["metadata"]!.DeepClone();
            return result;
        }
        private static JsonObject Membership(string project, string identity, JsonArray roles) => new()
        {
            ["id"] = Guid.NewGuid().ToString(),
            ["identityId"] = identity,
            ["projectId"] = project,
            ["orgId"] = Org,
            ["createdAt"] = Date,
            ["updatedAt"] = Date,
            ["roles"] = new JsonArray(roles.Select(r => (JsonNode)new JsonObject
            {
                ["id"] = Guid.NewGuid().ToString(),
                ["role"] = r!["role"]!.DeepClone(),
                ["isTemporary"] = r["isTemporary"]?.DeepClone() ?? JsonValue.Create(false),
                ["temporaryMode"] = r["temporaryMode"]?.DeepClone(),
                ["temporaryRange"] = r["temporaryRange"]?.DeepClone(),
                ["temporaryAccessStartTime"] = r["temporaryAccessStartTime"]?.DeepClone()
            }).ToArray())
        };

        private (int, JsonNode) Template(string method, string[] path, Dictionary<string, string> query, JsonObject body)
        {
            if (path.Length == 3 && method == "POST")
            {
                string id = Guid.NewGuid().ToString();
                JsonObject fields = (JsonObject)body["templateFields"]!.DeepClone();
                string authMethod = Text(body, "authMethod");
                Normalize(fields, authMethod);
                templates[id] = new()
                {
                    ["id"] = id,
                    ["orgId"] = Org,
                    ["name"] = body["name"]!.DeepClone(),
                    ["authMethod"] = authMethod,
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["templateFields"] = fields
                };
                return (200, TemplateRead(templates[id]));
            }
            if (path.Length == 3 || path[^1] == "search")
            {
                var rows = templates.Values.Where(t =>
                    (!query.TryGetValue("authMethod", out string? methodFilter) || Text(t, "authMethod") == methodFilter) &&
                    (!query.TryGetValue("search", out string? search) || Text(t, "name").Contains(search, StringComparison.Ordinal)))
                    .Select(t => (JsonNode)TemplateRead(t)).ToArray();
                return (200, path.Length == 3 ? new JsonArray(rows)
                    : new JsonObject { ["templates"] = new JsonArray(rows), ["totalCount"] = rows.Length });
            }
            if (!templates.TryGetValue(path[3], out var template)) return (404, new JsonObject());
            if (path.Length > 4)
            {
                string id = path[3];
                string[] selected = body["identityIds"]?.AsArray().Select(n => n!.GetValue<string>()).ToArray() ?? [];
                var usages = auth.Where(a => Text(a.Value, "templateId") == id &&
                    (method == "GET" || selected.Contains(a.Key))).ToArray();
                JsonArray result = new(usages.Select(a => (JsonNode)new JsonObject
                {
                    ["identityId"] = a.Key,
                    ["identityName"] = identities[a.Key]["name"]!.DeepClone(),
                    ["authId"] = a.Value["id"]!.DeepClone()
                }).ToArray());
                if (method == "GET") foreach (var row in result) row!.AsObject().Remove("authId");
                if (method != "GET") foreach (var item in usages) auth.Remove(item.Key);
                return (200, result);
            }
            if (method == "PATCH")
            {
                if (body.ContainsKey("name")) template["name"] = body["name"]!.DeepClone();
                if (body["templateFields"] is JsonObject patch)
                {
                    var stored = template["templateFields"]!.AsObject();
                    foreach (var pair in patch) stored[pair.Key] = pair.Value?.DeepClone();
                    Normalize(stored, Text(template, "authMethod"));
                }
            }
            if (method == "DELETE")
            {
                templates.Remove(path[3]);
                return (200, new JsonObject { ["message"] = "deleted" });
            }
            return (200, TemplateRead(template));
        }
        private static void Normalize(JsonObject fields, string method)
        {
            if (method == "ldap")
            {
                if (fields.ContainsKey("bindPass")) { fields["hasBindPass"] = true; fields.Remove("bindPass"); }
                fields["hasBindPass"] ??= false;
            }
            if (method == "kubernetes")
            {
                fields["hasTokenReviewerJwt"] = fields["tokenReviewerJwt"]?.GetValue<string>().Length > 0 ||
                    fields["hasTokenReviewerJwt"]?.GetValue<bool>() == true;
                // Keep reviewer in separate fixture state for downstream consumer reads, not template response.
            }
        }
        private (int, JsonNode) Authentication(string method, string[] path, JsonObject body)
        {
            string identity = path[^1];
            string kind = path[3].Replace("-auth", "", StringComparison.Ordinal);
            string envelope = kind switch { "oidc" => "identityOidcAuth", "ldap" => "identityLdapAuth", _ => "identityKubernetesAuth" };
            if (method == "POST")
            {
                string template = Text(body, "templateId");
                if (!templates.TryGetValue(template, out var source)) return (404, new JsonObject());
                JsonObject fields = source["templateFields"]!.AsObject();
                var value = new JsonObject
                {
                    ["id"] = Guid.NewGuid().ToString(),
                    ["identityId"] = identity,
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["templateId"] = template
                };
                if (kind == "oidc")
                {
                    foreach (string field in new[] { "oidcDiscoveryUrl", "boundIssuer", "boundAudiences", "caCert" })
                        value[field] = fields[field]?.DeepClone() ?? JsonValue.Create("");
                }
                else if (kind == "ldap")
                {
                    foreach (string field in new[] { "url", "bindDN", "searchBase", "ldapCaCertificate" })
                        value[field] = fields[field]?.DeepClone() ?? JsonValue.Create("");
                    value["searchFilter"] = "fixture";
                }
                else
                {
                    foreach (string field in new[] { "allowedAudience", "caCert" })
                        value[field] = fields[field]?.DeepClone() ?? JsonValue.Create("");
                    foreach (string field in new[] { "kubernetesHost", "gatewayId", "gatewayPoolId", "tokenReviewerJwt", "tokenReviewMode", "verifyTlsCertificate" })
                        if (fields.ContainsKey(field)) value[field] = fields[field]?.DeepClone();
                    value["allowedNames"] = body["allowedNames"]!.DeepClone();
                    value["allowedNamespaces"] = body["allowedNamespaces"]!.DeepClone();
                }
                auth[identity] = value;
            }
            if (!auth.TryGetValue(identity, out var config)) return (404, new JsonObject());
            JsonObject returned = (JsonObject)config.DeepClone();
            if (kind == "ldap" && method != "GET") { returned.Remove("bindDN"); returned.Remove("ldapCaCertificate"); }
            return (200, new JsonObject { [envelope] = returned });
        }

        private (int, JsonNode) Search(bool count, JsonObject body)
        {
            var rows = new List<JsonObject>();
            string[] scopes = body["scope"]!.AsArray().Select(s => s!.GetValue<string>()).ToArray();
            foreach (var identity in identities.Values.Where(i => i["projectId"] is null))
            {
                if (scopes.Contains("organization"))
                    rows.Add(SearchRow(identity, OrganizationMembership(identity), null));
                if (scopes.Contains("project"))
                    foreach (var member in memberships.Where(m => m.Key.Identity == Text(identity, "id")))
                        rows.Add(SearchRow(identity, member.Value, member.Key.Project));
            }
            rows = rows.Where(r => MatchesFilter(r, body["search"]?.AsObject())).ToList();
            if (count) return (200, new JsonObject
            {
                ["counts"] = new JsonObject
                { ["organization"] = rows.Count(r => Text(r, "scope") == "organization"), ["project"] = rows.Count(r => Text(r, "scope") == "project") }
            });
            rows = Text(body, "orderBy") == "role" ? rows.OrderBy(r => Text(r["roles"]!.AsArray()[0]!.AsObject(), "role")).ToList()
                : rows.OrderBy(r => Text(r["identity"]!.AsObject(), "name")).ToList();
            if (Text(body, "orderDirection") == "desc") rows.Reverse();
            return (200, new JsonObject { ["identities"] = new JsonArray(rows.Select(r => (JsonNode)r).ToArray()), ["totalCount"] = rows.Count });
        }
        private static JsonObject SearchRow(JsonObject identity, JsonObject membership, string? project)
        {
            JsonObject value = (JsonObject)identity.DeepClone();
            value.Remove("fixtureRole");
            return new()
            {
                ["id"] = membership["id"]!.DeepClone(),
                ["orgId"] = Org,
                ["identityId"] = identity["id"]!.DeepClone(),
                ["scope"] = project is null ? "organization" : "project",
                ["projectId"] = project,
                ["createdAt"] = Date,
                ["updatedAt"] = Date,
                ["identity"] = Only(value, "id", "name", "orgId", "hasDeleteProtection", "authMethods", "activeLockoutAuthMethods"),
                ["roles"] = membership["roles"]?.DeepClone() ?? new JsonArray(new JsonObject
                { ["id"] = Text(identity, "id"), ["role"] = membership["role"]!.DeepClone(), ["isTemporary"] = false })
            };
        }
        private static bool MatchesFilter(JsonObject row, JsonObject? filter)
        {
            if (filter is null) return true;
            bool Field(string key, JsonNode? condition)
            {
                if (condition is null) return true;
                string value = key == "name" ? Text(row["identity"]!.AsObject(), "name")
                    : Text(row["roles"]!.AsArray()[0]!.AsObject(), "role");
                if (condition is JsonValue scalar) return value == scalar.GetValue<string>();
                var operators = condition.AsObject();
                return (!operators.ContainsKey("$eq") || value == Text(operators, "$eq")) &&
                    (!operators.ContainsKey("$contains") || value.Contains(Text(operators, "$contains"), StringComparison.Ordinal)) &&
                    (!operators.ContainsKey("$in") || operators["$in"]!.AsArray().Any(n => n!.GetValue<string>() == value));
            }
            bool Clause(JsonObject clause) => Field("name", clause["name"]) && Field("role", clause["role"]);
            return Clause(filter) && (filter["$or"] is not JsonArray any || any.Any(n => Clause(n!.AsObject())));
        }
        private static string Text(JsonObject value, string field) => value[field]!.GetValue<string>();
        private static JsonObject Only(JsonObject source, params string[] fields) => new(source
            .Where(pair => fields.Contains(pair.Key)).Select(pair =>
                new KeyValuePair<string, JsonNode?>(pair.Key, pair.Value?.DeepClone())));
        private static JsonObject TemplateRead(JsonObject source)
        {
            var result = (JsonObject)source.DeepClone();
            result["templateFields"]!.AsObject().Remove("tokenReviewerJwt");
            return result;
        }
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
