using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalScopedAccessEffectTests
{
    private const string Org = "00000000-0000-0000-0000-000000000001";
    private const string Runtime = "00000000-0000-0000-0000-000000000004";
    private const string User = "00000000-0000-0000-0000-000000000007";
    private const string OtherUser = "00000000-0000-0000-0000-000000000008";
    private const string Date = "2026-10-12T00:00:00.000Z";

    [Test]
    [Arguments("ListGroups", "collection.bounded", "duplicate")]
    [Arguments("AvailableGroups", "selector.exact", "duplicate")]
    [Arguments("AvailableIdentities", "identityName.value", "duplicate")]
    [Arguments("ListGroupIdentities", "filter.Assigned", "duplicate")]
    [Arguments("ListGroupUsers", "filter.Members", "duplicate")]
    [Arguments("ListGroupMembers", "members.All", "duplicate")]
    [Arguments("ListGroupProjects", "selection.Assigned", "duplicate")]
    [Arguments("ListGroups", "collection.bounded", "drop-last")]
    [Arguments("AvailableGroups", "selector.exact", "drop-last")]
    [Arguments("ListGroupProjects", "selection.OrganizationAll", "assigned-only")]
    [Arguments("ListGroupIdentities", "filter.Unassigned", "empty")]
    [Arguments("ListGroupUsers", "filter.NonMembers", "empty")]
    [Arguments("ListGroupIdentities", "search.value", "ignore-search")]
    [Arguments("ListGroupUsers", "search.value", "ignore-search")]
    [Arguments("ListGroupUsers", "username.value", "ignore-search")]
    [Arguments("ListGroupMembers", "search.value", "ignore-search")]
    [Arguments("ListGroupMembers", "memberTypes.value", "first-type")]
    [Arguments("ListGroupMembers", "order.Descending", "ascending")]
    [Arguments("ListGroupProjects", "search.value", "ignore-search")]
    [Arguments("ListGroupProjects", "order.Descending", "ascending")]
    [Arguments("AvailableIdentities", "identityName.value", "ignore-search")]
    [Arguments("ListGroupMembers", "members.All", "duplicate-principal")]
    [Arguments("ListGroupMembers", "members.All", "incomplete")]
    [Arguments("ListGroupIdentities", "filter.omitted", "incomplete")]
    [Arguments("ListGroupUsers", "filter.omitted", "incomplete")]
    [Arguments("ListGroupProjects", "selection.OrganizationAll", "incomplete")]
    [Arguments("ListGroupProjects", "selection.OrganizationAll", "drop-last")]
    public async Task SelectedInventoriesCannotCertifyPoisonedRows(string operation, string variant, string mode)
    {
        await using var backend = new Backend(mode);
        var result = await RunAsync(backend, operation, variant);
        await Assert.That(result.Passed).IsFalse().Because(operation + "|" + variant);
        await Assert.That(result.ReasonCode is "contract-mismatch" or "effect-mismatch").IsTrue()
            .Because(result.ReasonCode);
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("GetGroup", "selector.exact", "replace-group")]
    [Arguments("UpdateGroup", "name.value", "replace-group")]
    [Arguments("CreateGroup", "slug.value", "replace-group")]
    [Arguments("UpdateGroup", "role.value", "replace-role")]
    public async Task CleanupCannotDeleteReusedCoordinates(string operation, string variant, string mode)
    {
        await using var backend = new Backend(mode);
        var result = await RunAsync(backend, operation, variant);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(backend.ReplacementDeleted).IsFalse();
        await Assert.That(backend.ReplacementPresent).IsTrue();
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task CreateAndRenameRetainBoundaryCleanup(string caseName)
    {
        foreach (var (operation, variant) in new[] { ("CreateGroup", "slug.value"), ("UpdateGroup", "name.value") })
        {
            await using var backend = new Backend("good");
            var result = await RunAsync(backend, operation, variant, caseName);
            await Assert.That(result.Passed).IsTrue().Because(operation + "|" + result.ReasonCode);
            await Assert.That(backend.OwnedCount).IsEqualTo(0);
        }
    }

    [Test]
    public async Task EveryScopedInventoryVariantRetainsItsCases()
    {
        foreach (var (operation, binding) in InfisicalPermissionFamilies.Bindings.Where(p =>
            p.Key.StartsWith("i.management.ScopedAccessOperations.", StringComparison.Ordinal) &&
            (p.Key.Contains(".ListGroup", StringComparison.Ordinal) || p.Key.Contains(".Available", StringComparison.Ordinal))))
            foreach (string variant in binding.Variants)
                foreach (string caseName in new[] { "selected-contract", "independent-effect", "denied-authority", "cancellation-boundary" })
                {
                    await using var backend = new Backend("good");
                    var result = await RunAsync(backend, operation.Split('.').Last(), variant, caseName);
                    await Assert.That(result.Passed).IsTrue().Because(operation + "|" + variant + "|" + caseName + "|" + result.ReasonCode);
                    await Assert.That(backend.OwnedCount).IsEqualTo(0);
                }
    }

    [Test]
    [Arguments("ListGroupUsers", "filter.NonMembers", "scopedAccessUnassignedUserId")]
    [Arguments("ListGroupMembers", "memberTypes.value", "scopedAccessUserId")]
    public async Task MissingExplicitUserWitnessIsMissingInput(string operation, string variant, string missing)
    {
        await using var backend = new Backend("good");
        var result = await RunAsync(backend, operation, variant, missing: missing);
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    public async Task InactiveNativeUserWitnessIsUnavailable()
    {
        await using var backend = new Backend("inactive-user");
        var result = await RunAsync(backend, "ListGroupMembers", "memberTypes.value");
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("setup-lost-group", "name.value")]
    [Arguments("setup-lost-role", "role.value")]
    public async Task LostSetupAcknowledgementStillRecoversOwnedCoordinates(string mode, string variant)
    {
        await using var backend = new Backend(mode);
        var result = await RunAsync(backend, "UpdateGroup", variant);
        await Assert.That(result.ReasonCode).IsEqualTo("missing-prerequisite");
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    private static async Task<NativeCaseResult> RunAsync(Backend backend, string operation, string variant,
        string caseName = "independent-effect", string? missing = null)
    {
        var input = new Dictionary<string, string>
        {
            ["organizationId"] = Org,
            ["setupIdentityId"] = "00000000-0000-0000-0000-000000000006",
            ["administrativeIdentityId"] = "00000000-0000-0000-0000-000000000002",
            ["observerIdentityId"] = "00000000-0000-0000-0000-000000000003",
            ["runtimeIdentityId"] = Runtime,
            ["deniedIdentityId"] = "00000000-0000-0000-0000-000000000005",
            ["runtimeUserId"] = Runtime,
            ["runtimeUsername"] = "runtime-user",
            ["scopedAccessUserId"] = User,
            ["scopedAccessUsername"] = "zulu-user",
            ["scopedAccessUnassignedUserId"] = OtherUser,
            ["scopedAccessUnassignedUsername"] = "other-user"
        };
        if (missing is not null) input.Remove(missing);
        using var environment = NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = backend.Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            administrative = "administrative",
            observer = "observer",
            runtime = "runtime",
            denied = "denied",
            families = new Dictionary<string, object>
            {
                ["C08-IM-ScopedAccess"] = new { scopes = new Dictionary<string, object> { ["local"] = input } }
            }
        }));
        string key = "i.management.ScopedAccessOperations." + operation;
        var definition = new NativeCaseDefinition(new("Infisical", key, variant, "local", caseName),
            InfisicalPermissionFamilies.Bindings[key].Member);
        var registry = new NativeCaseRegistry();
        InfisicalPermissionFamilies.Register(registry, environment, [definition]);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }

    // Native-shaped HTTP state, including independently held organization eligibility.
    // Selected response corruption never changes the observer's state or authority.
    private sealed class Backend : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Dictionary<string, JsonObject> groups = [];
        private readonly Dictionary<string, JsonObject> projects = [];
        private readonly Dictionary<string, JsonObject> roles = [];
        private readonly Dictionary<string, JsonObject> identities = [];
        private readonly Dictionary<string, string> users = new() { [Runtime] = "runtime-user", [User] = "zulu-user", [OtherUser] = "other-user" };
        private readonly HashSet<(string Group, string Principal, bool User)> groupMembers = [];
        private readonly HashSet<(string Project, string Group)> projectGroups = [];
        private readonly Dictionary<(string Project, string Key), string> secrets = [];
        private readonly string mode;
        private readonly Task accept;
        private bool selected;
        private bool replaced;
        private const string Replacement = "00000000-0000-0000-0000-000000000099";
        internal Uri Origin { get; }
        internal bool ReplacementDeleted { get; private set; }
        internal bool ReplacementPresent => groups.ContainsKey(Replacement) || roles.ContainsKey(Replacement);
        internal int OwnedCount => groups.Count + projects.Count + roles.Count + identities.Count - 1;

        internal Backend(string mode)
        {
            this.mode = mode;
            identities[Runtime] = Identity(Runtime, "alpha-runtime");
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
                    NetworkStream stream = socket.GetStream();
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
                    string credential = lines.Single(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase)).Split(' ').Last();
                    int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?.Split(':')[1] ?? "0");
                    if (length is < 0 or > 65536) throw new InvalidOperationException("fixture-budget");
                    byte[] bytes = new byte[length];
                    await stream.ReadExactlyAsync(bytes, shutdown.Token);
                    JsonObject body = length == 0 ? new() : JsonNode.Parse(bytes)!.AsObject();
                    (int Status, JsonNode Body) response;
                    lock (groups) response = Respond(request[0], new Uri(Origin, request[1]), credential, body);
                    byte[] content = Encoding.UTF8.GetBytes(response.Body.ToJsonString());
                    await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {response.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {content.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                    await stream.WriteAsync(content, shutdown.Token);
                }
                catch (IOException) { }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            }
        }

        private (int, JsonNode) Respond(string method, Uri uri, string credential, JsonObject body)
        {
            string[] p = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(Uri.UnescapeDataString).ToArray();
            var q = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries).Select(s => s.Split('=', 2))
                .ToLookup(s => s[0], s => Uri.UnescapeDataString(s[1]));
            if (credential == "denied") return (403, new JsonObject());
            if (credential == "administrative") selected = true;
            bool poison = credential == "administrative";
            if (p[2] == "organizations")
                return (200, new JsonObject
                {
                    ["users"] = new JsonArray(users.Select(u => (JsonNode)new JsonObject
                    {
                        ["id"] = Guid.NewGuid().ToString(),
                        ["orgId"] = Org,
                        ["userId"] = u.Key,
                        ["role"] = "member",
                        ["status"] = "accepted",
                        ["isActive"] = mode != "inactive-user",
                        ["user"] = new JsonObject { ["id"] = u.Key, ["username"] = u.Value }
                    }).ToArray())
                });
            if (p[2] == "identities")
            {
                if (p.Length == 3 && method == "GET") return Page("identities", identities.Values.Select(i => IdentityMembership(i, false)));
                string id = p.Length == 3 ? Guid.NewGuid().ToString() : p[3];
                if (method == "POST") identities[id] = Identity(id, Text(body, "name"));
                if (!identities.TryGetValue(id, out var identity)) return (404, new JsonObject());
                if (method == "DELETE") identities.Remove(id);
                return (200, Wrap("identity", method == "GET" ? IdentityMembership(identity, true) :
                    method == "POST" ? Without(identity, "activeLockoutAuthMethods") : Fields(identity, "id", "orgId", "name", "createdAt", "updatedAt")));
            }
            if (p[2] == "organization" && p[3].StartsWith("available-", StringComparison.Ordinal))
            {
                bool group = p[3] == "available-groups";
                IEnumerable<JsonObject> rows = group ? groups.Values : identities.Values;
                if (q["identityName"].FirstOrDefault() is { } search && !(poison && mode == "ignore-search"))
                    rows = rows.Where(i => Text(i, "name").Contains(search, StringComparison.OrdinalIgnoreCase));
                return (200, new JsonObject { [group ? "groups" : "identities"] = Array(Corrupt(rows.Select(i => Fields(i, "id", "name", "slug")), poison)) });
            }
            if (p[2] == "organization" && p[3] == "roles")
            {
                if (selected && !replaced && mode == "replace-role" && method == "GET")
                {
                    replaced = true;
                    var old = roles.Single();
                    roles.Remove(old.Key);
                    old.Value["id"] = Replacement;
                    roles[Replacement] = old.Value;
                }
                string? id = p.Length == 4 ? null : p[4] == "slug" ?
                    roles.Keys.SingleOrDefault(i => Text(roles[i], "slug") == p[5]) : p[4];
                if (method == "POST")
                {
                    id = Guid.NewGuid().ToString();
                    roles[id] = Stamp(new JsonObject
                    {
                        ["id"] = id,
                        ["orgId"] = Org,
                        ["name"] = body["name"]!.DeepClone(),
                        ["slug"] = body["slug"]!.DeepClone(),
                        ["permissions"] = body["permissions"]!.DeepClone()
                    });
                }
                if (id is null || !roles.TryGetValue(id, out var role)) return (404, new JsonObject());
                if (method == "POST" && mode == "setup-lost-role") return (500, new JsonObject());
                if (method == "DELETE") { roles.Remove(id); ReplacementDeleted |= id == Replacement; }
                return (200, Wrap("role", role));
            }
            if (p[2] == "groups") return Group(method, p, q, credential, body, poison);
            if (p[2] == "secrets")
            {
                string project = method == "GET" ? q["projectId"].Single() : Text(body, "projectId");
                if (credential == "runtime" && !projectGroups.Any(g => g.Project == project &&
                    groupMembers.Any(m => m.Group == g.Group && m.Principal == Runtime))) return (403, new JsonObject());
                string key = p[3];
                if (method == "POST") secrets[(project, key)] = Text(body, "secretValue");
                if (!secrets.TryGetValue((project, key), out string? value)) return (404, new JsonObject());
                return (200, Wrap("secret", new JsonObject
                {
                    ["id"] = key,
                    ["secretKey"] = key,
                    ["secretValue"] = value,
                    ["workspace"] = project,
                    ["environment"] = "witness",
                    ["version"] = 1,
                    ["secretValueHidden"] = false
                }));
            }
            if (p[2] != "projects") return (404, new JsonObject());
            if (p.Length == 3)
            {
                string id = Guid.NewGuid().ToString();
                projects[id] = Stamp(new JsonObject
                {
                    ["id"] = id,
                    ["_id"] = id,
                    ["orgId"] = Org,
                    ["name"] = body["projectName"]!.DeepClone(),
                    ["slug"] = body["slug"]!.DeepClone(),
                    ["type"] = "secret-manager",
                    ["hasDeleteProtection"] = false,
                    ["environments"] = new JsonArray(),
                    ["deletedEnvironments"] = new JsonArray()
                });
                return (200, Wrap("project", projects[id]));
            }
            string? projectId = p[3] == "slug" ? projects.Keys.SingleOrDefault(i => Text(projects[i], "slug") == p[4]) : p[3];
            if (projectId is null || !projects.TryGetValue(projectId, out var owner)) return (404, new JsonObject());
            if (p[3] == "slug") return (200, owner.DeepClone());
            if (p.Length == 4)
            {
                if (method == "DELETE") projects.Remove(projectId);
                return (200, Wrap("project", method == "DELETE" ? Without(owner, "_id", "environments", "deletedEnvironments") : owner));
            }
            if (p[4] == "environments") return (200, new JsonObject
            {
                ["projectId"] = projectId,
                ["environment"] = Stamp(new JsonObject
                {
                    ["id"] = Guid.NewGuid().ToString(),
                    ["projectId"] = projectId,
                    ["name"] = body["name"]!.DeepClone(),
                    ["slug"] = body["slug"]!.DeepClone(),
                    ["position"] = 1
                })
            });
            string principal = p[^1];
            if (p[5] == "groups")
            {
                projectGroups.Add((projectId, principal));
                var assigned = (JsonArray)body["roles"]!.DeepClone();
                foreach (var r in assigned) { r!["id"] = Guid.NewGuid().ToString(); r["isTemporary"] = false; }
                return (200, Wrap("groupMembership", Stamp(new JsonObject
                {
                    ["id"] = Guid.NewGuid().ToString(),
                    ["groupId"] = principal,
                    ["projectId"] = projectId,
                    ["roles"] = assigned,
                    ["group"] = Fields(groups[principal], "id", "name", "slug", "orgId")
                })));
            }
            return (200, Wrap("identityMembership", Stamp(new JsonObject
            {
                ["id"] = Guid.NewGuid().ToString(),
                ["identityId"] = principal,
                ["projectId"] = projectId
            })));
        }

        private (int, JsonNode) Group(string method, string[] p, ILookup<string, string> q, string credential, JsonObject body, bool poison)
        {
            if (credential == "runtime" && !groupMembers.Any(m => m.Principal == Runtime &&
                groups.TryGetValue(m.Group, out var g) && g["customRoleSlug"] is not null)) return (403, new JsonObject());
            if (p.Length == 3)
            {
                if (method == "GET")
                {
                    // Swap only at cleanup discovery, after the exact observer read.
                    if (selected && !replaced && mode == "replace-group")
                    {
                        replaced = true;
                        var old = groups.First();
                        groups.Remove(old.Key);
                        old.Value["id"] = Replacement;
                        groups[Replacement] = old.Value;
                    }
                    return (200, Array(Corrupt(groups.Values.Select(g => Without(g, "customRoleSlug")), poison)));
                }
                string id = Guid.NewGuid().ToString();
                string role = body["role"]?.GetValue<string>() ?? "no-access";
                groups[id] = Stamp(new JsonObject
                {
                    ["id"] = id,
                    ["orgId"] = Org,
                    ["name"] = body["name"]!.DeepClone(),
                    ["slug"] = body["slug"]?.DeepClone() ?? body["name"]!.DeepClone(),
                    ["role"] = role,
                    ["customRoleSlug"] = role == "no-access" ? null : role
                });
                if (credential == "setup" && mode == "setup-lost-group") return (500, new JsonObject());
                return (200, Without(groups[id], "role", "customRoleSlug"));
            }
            string group = p[3];
            if (!groups.TryGetValue(group, out var value)) return (404, new JsonObject());
            if (p.Length == 4)
            {
                if (method == "PATCH")
                {
                    foreach (var (key, item) in body) value[key] = item?.DeepClone();
                    if (body["role"] is not null) value["customRoleSlug"] = body["role"]!.DeepClone();
                }
                if (method == "DELETE")
                {
                    groups.Remove(group);
                    groupMembers.RemoveWhere(m => m.Group == group);
                    ReplacementDeleted |= group == Replacement;
                }
                return (200, method == "GET" ? value.DeepClone() : Without(value, "role", "customRoleSlug"));
            }
            if (p.Length == 6)
            {
                bool user = p[4] == "users";
                string principal = user ? users.Single(u => u.Value == p[5]).Key : p[5];
                if (method == "POST") groupMembers.Add((group, principal, user));
                else groupMembers.Remove((group, principal, user));
                return (200, user ? new JsonObject { ["id"] = principal, ["username"] = p[5] } :
                    new JsonObject { ["id"] = Guid.NewGuid().ToString() });
            }
            var rows = new List<JsonObject>();
            string field = p[4] == "machine-identities" ? "machineIdentities" : p[4];
            string? filter = q["filter"].FirstOrDefault();
            if (field == "projects")
            {
                foreach (var (id, project) in projects)
                {
                    bool assigned = projectGroups.Contains((id, group));
                    if ((filter == "assignedProjects" || poison && mode == "assigned-only") && !assigned ||
                        filter == "unassignedProjects" && assigned) continue;
                    var row = Fields(project, "id", "name", "slug", "type");
                    row["joinedGroupAt"] = assigned ? Date : null;
                    rows.Add(row);
                }
            }
            else if (field == "members")
            {
                string[] types = q["memberTypeFilter"].ToArray();
                if (poison && mode == "first-type") types = types.Take(1).ToArray();
                foreach (var m in groupMembers.Where(m => m.Group == group))
                {
                    if (types.Length != 0 && !types.Contains(m.User ? "users" : "machineIdentities")) continue;
                    rows.Add(new JsonObject
                    {
                        ["id"] = m.Principal,
                        ["joinedGroupAt"] = Date,
                        ["type"] = m.User ? "user" : "machineIdentity",
                        [m.User ? "user" : "machineIdentity"] =
                            new JsonObject
                            {
                                ["id"] = m.Principal,
                                [m.User ? "username" : "name"] =
                                m.User ? users[m.Principal] : Text(identities[m.Principal], "name")
                            }
                    });
                }
            }
            else
            {
                bool user = field == "users";
                foreach (var (id, name) in user ? users : identities.ToDictionary(i => i.Key, i => Text(i.Value, "name")))
                {
                    bool member = groupMembers.Contains((group, id, user));
                    if (filter is "nonMembers" or "nonAssignedMachineIdentities" && member ||
                        filter is "existingMembers" or "assignedMachineIdentities" && !member) continue;
                    rows.Add(new JsonObject
                    {
                        ["id"] = id,
                        [user ? "username" : "name"] = name,
                        ["isPartOfGroup"] = member,
                        ["joinedGroupAt"] = member ? Date : null
                    });
                }
            }
            string Name(JsonObject r) => field == "members" ?
                r["user"]?["username"]?.GetValue<string>() ?? r["machineIdentity"]!["name"]!.GetValue<string>() :
                r["username"]?.GetValue<string>() ?? Text(r, "name");
            if (!(poison && mode == "ignore-search"))
            {
                if (q["search"].FirstOrDefault() is { } search) rows.RemoveAll(r => !Name(r).Contains(search, StringComparison.OrdinalIgnoreCase));
                if (q["username"].FirstOrDefault() is { } username) rows.RemoveAll(r => Name(r) != username);
            }
            rows = rows.OrderBy(Name, StringComparer.Ordinal).ToList();
            if (q["orderDirection"].FirstOrDefault() == "desc" && !(poison && mode == "ascending")) rows.Reverse();
            if (poison && mode == "duplicate-principal" && rows.Count != 0)
            {
                var duplicate = (JsonObject)rows[0].DeepClone();
                duplicate["id"] = Guid.NewGuid().ToString();
                rows.Add(duplicate);
            }
            var page = Page(field, Corrupt(rows, poison));
            if (poison && mode == "incomplete") page.Item2["totalCount"] = rows.Count + 1;
            return page;
        }

        private IEnumerable<JsonObject> Corrupt(IEnumerable<JsonObject> source, bool poison)
        {
            var rows = source.ToList();
            if (!poison) return rows;
            if (mode == "duplicate" && rows.Count != 0) rows.Add(rows[0]);
            if (mode == "empty") rows.Clear();
            if (mode == "drop-last" && rows.Count > 1) rows.RemoveAt(rows.Count - 1);
            return rows;
        }

        private static JsonObject Identity(string id, string name) => Stamp(new JsonObject
        {
            ["id"] = id,
            ["orgId"] = Org,
            ["name"] = name,
            ["authMethods"] = new JsonArray(),
            ["activeLockoutAuthMethods"] = new JsonArray(),
            ["metadata"] = new JsonArray()
        });
        private static JsonObject IdentityMembership(JsonObject identity, bool details)
        {
            var result = Stamp(new JsonObject
            {
                ["id"] = Text(identity, "id"),
                ["identityId"] = identity["id"]!.DeepClone(),
                ["orgId"] = Org,
                ["role"] = "no-access",
                ["identity"] = details ? Fields(identity, "id", "name", "orgId", "authMethods", "activeLockoutAuthMethods") :
                    Fields(identity, "id", "name", "authMethods")
            });
            if (details) result["metadata"] = new JsonArray();
            return result;
        }
        private static (int, JsonNode) Page(string field, IEnumerable<JsonObject> source)
        {
            JsonArray rows = Array(source);
            return (200, new JsonObject { [field] = rows, ["totalCount"] = rows.Count });
        }
        private static JsonArray Array(IEnumerable<JsonObject> rows) => new(rows.Select(r => r.DeepClone()).ToArray());
        private static JsonObject Stamp(JsonObject value) { value["createdAt"] = Date; value["updatedAt"] = Date; return value; }
        private static JsonObject Fields(JsonObject value, params string[] fields) => new(value.Where(p => fields.Contains(p.Key))
            .Select(p => new KeyValuePair<string, JsonNode?>(p.Key, p.Value?.DeepClone())));
        private static JsonObject Without(JsonObject value, params string[] fields)
        {
            var result = (JsonObject)value.DeepClone();
            foreach (string field in fields) result.Remove(field);
            return result;
        }
        private static JsonObject Wrap(string field, JsonNode value) => new() { [field] = value.DeepClone() };
        private static string Text(JsonObject value, string field) => value[field]!.GetValue<string>();
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
