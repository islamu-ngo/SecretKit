using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Stateful authenticated provider. Wire policy, configuration persistence,
// issuance and the SQL credential verifier are independent of effect expectations.
internal sealed class InfisicalRotationPermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal const string Date = "2026-10-14T00:00:00Z";
    internal static RotationPermissionAuthorities Authorities { get; } = new(
        "20000000-0000-0000-0000-000000000001", "20000000-0000-0000-0000-000000000002",
        "20000000-0000-0000-0000-000000000003", "20000000-0000-0000-0000-000000000004",
        "20000000-0000-0000-0000-000000000005");
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<RotationPermissionJournal, RotationPermissionWriter> writers = [];
    private readonly InfisicalRotationPermissionSqlFixture sql;
    private readonly Dictionary<string, string> hostTokens = new()
    {
        [Authorities.Setup] = "setup",
        [Authorities.Runtime] = "runtime",
        [Authorities.Denied] = "denied",
        [Authorities.Administrative] = "administrative",
        [Authorities.Observer] = "observer"
    };
    private readonly RotationPermissionBorrowed[] borrowed;
    private readonly List<RotationPermissionOwned> enrolled = [];
    private readonly Dictionary<string, RotationPermissionOwned> resources = [];
    private readonly Dictionary<Guid, Stored> definitions = [];
    private readonly List<RotationPermissionSigned<RotationPermissionIngress>> ingress = [];
    private readonly List<RotationPermissionSigned<RotationPermissionCommit>> commits = [];
    private readonly List<RotationPermissionSigned<RotationPermissionDecision>> decisions = [];
    private readonly List<RotationPermissionSigned<RotationPermissionChange>> changes = [];
    private readonly List<RotationPermissionSigned<RotationPermissionMaterial>> materials = [];
    private readonly List<RotationPermissionSigned<RotationPermissionBackend>> backend = [];
    private readonly Dictionary<string, RotationPermissionPolicy> policyInventory = [];
    private readonly HashSet<Guid> measured = [];
    private sealed record Policy(string Subject, string[] Actions, string Principal, string Environment, string Path, string Connection);
    private sealed class Pair(string username, string password) : IDisposable
    {
        internal SecretMaterial Username { get; } = SecretMaterial.FromText(username);
        internal SecretMaterial Password { get; } = SecretMaterial.FromText(password);
        internal string Hash => RotationPermissionContract.MaterialHash(Username.Reveal(), Password.Reveal());
        public void Dispose() { Username.Dispose(); Password.Dispose(); }
    }
    private sealed class Stored(RotationPermissionRow row, JsonObject config) : IDisposable
    {
        internal RotationPermissionRow Row { get; } = row;
        internal JsonObject Configuration { get; } = config;
        internal int Version = 1, Generation = 1;
        internal Pair[] Pairs = [];
        public void Dispose() { foreach (var pair in Pairs) pair.Dispose(); Pairs = []; Configuration.Clear(); }
    }
    private RotationPermissionRoot? root;
    private RotationPermissionIssued? issued;
    private Policy? policy, template, copy;
    private string revision = "policy-1", window = "";
    private int stage;
    private bool closed, closing, armed, sealedDispatch, assigned, copied;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal RotationPermissionProfile Profile { get; }
    internal InfisicalRotationPermissionFixtureSource Source { get; }
    internal RotationPermissionRuntime Runtime { get; }
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    internal int Originals { get; private set; }
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Registrations => root is not null && !closed ? 1 : 0;
    internal int Remaining => resources.Count + definitions.Count + policyInventory.Count + sql.Remaining;
    internal bool BorrowedPreserved => borrowed.SequenceEqual(Borrowed()) && sql.BorrowedPreserved;
    internal InfisicalRotationPermissionFixture(string fault = "",
        InfisicalRotationProfile profile = InfisicalRotationProfile.PostgresCredentials)
    {
        Fault = fault; borrowed = Borrowed(); sql = new(fault);
        foreach (var j in Enum.GetValues<RotationPermissionJournal>().Where(j => j != RotationPermissionJournal.Backend))
            writers.Add(j, new(j, "rotation-" + j));
        Profile = new("controlled-rotation", "controlled-epoch", "controlled-v1",
            profile, writers.Values.Select(w => w.Pin).Append(sql.Pin).ToArray());
        listener.Start(); Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this);
        Runtime = new(new("https://rotation-controlled.invalid/"), new(new RuntimeTransport(this)));
        accept = AcceptAsync();
    }
    internal RotationPermissionInput Input(RotationPermissionAction action) =>
        new(new(new("https://rotation-source.invalid/"), "coordinator-token", "rotation-coordinator", 30),
            "rotation-capability", Profile, action, 60);
    internal NativeEnvironment Environment(RotationPermissionAction action, InfisicalRotationProfile? profile = null)
    {
        var scope = new
        {
            scopes = new
            {
                local = new
                {
                    organizationId = Organization,
                    setupIdentityId = Authorities.Setup,
                    runtimeIdentityId = Authorities.Runtime,
                    deniedIdentityId = Authorities.Denied,
                    administrativeIdentityId = Authorities.Administrative,
                    observerIdentityId = Authorities.Observer,
                    rotationPermission = Input(action) with
                    { Profile = Profile with { SqlProfile = profile ?? Profile.SqlProfile } }
                }
            }
        };
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = Fault == "wrong-credential" ? "unissued-runtime" : "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families = new Dictionary<string, object>
            {
                ["C08-IM-IdentityPrivilegeChanges"] = scope,
                ["C08-IM-RoleChanges"] = scope,
                ["C08-IM-ProjectTemplates"] = scope,
                ["C08-IM-ManagementClient"] = scope
            }
        }, RotationPermissionContract.Options));
    }
    internal RotationPermissionRoot Root(string operation, RotationPermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization, operation,
            RotationPermissionContract.Variant(action), boundary, "local", "rotation-coordinator",
            RotationPermissionSourceKind.ControlledFixture, action, Authorities, Profile);
    private RotationPermissionSigned<T> Sign<T>(RotationPermissionJournal j, string selectedWindow, T content) =>
        writers[j].Sign(root!, selectedWindow, content);
    internal RotationPermissionSigned<RotationPermissionSeal> Seal(RotationPermissionJournal j, string selectedWindow,
        RotationPermissionSeal content) => j == RotationPermissionJournal.Backend ?
        sql.Seal(root!, selectedWindow, content) : Sign(j, selectedWindow, content);
    private RotationPermissionBorrowed[] Borrowed() => hostTokens.Select(p =>
        new RotationPermissionBorrowed("host-token", p.Key, RotationPermissionContract.Hash(p.Value))).ToArray();
    private void Enroll(string kind, string id)
    {
        RotationPermissionContract.Require(root is not null && !enrolled.Any(e => e.Kind == kind && e.Id == id) &&
            !borrowed.Any(b => b.Kind == kind && b.Id == id));
        enrolled.Add(new(kind, id, root!.Id, root.Nonce));
    }
    private void Create(string kind, string id)
    {
        RotationPermissionContract.Require(!closed);
        resources.Add(kind + "/" + id, enrolled.Single(e => e.Kind == kind && e.Id == id));
    }
    private void Reserve(RotationPermissionRoot selected)
    {
        RotationPermissionContract.Require(root is null && selected.Origin == Origin.AbsoluteUri &&
            selected.Organization == Organization && selected.Authorities == Authorities &&
            RotationPermissionContract.Hash(selected.Profile) == RotationPermissionContract.Hash(Profile));
        root = selected;
        if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
        string project = Guid.NewGuid().ToString(), controlProject = Guid.NewGuid().ToString(), copyProject = Guid.NewGuid().ToString();
        string connection = Guid.NewGuid().ToString(), controlConnection = Guid.NewGuid().ToString();
        var rows = new List<RotationPermissionRow>();
        foreach (string phase in new[] { "before", "after", "copy" })
        {
            foreach (var action in Enum.GetValues<RotationPermissionAction>())
                foreach (string principal in Authorities.All)
                    foreach (string control in principal == Authorities.Runtime ?
                        new[] { "selected", "project", "environment", "path", "connection" } : ["selected"])
                        Add(action, principal, control, false);
            foreach (string principal in Authorities.All)
                foreach (string control in principal == Authorities.Runtime ? new[] { "selected", "project" } : ["selected"])
                    Add(RotationPermissionAction.Read, principal, control, true);
            void Add(RotationPermissionAction action, string principal, string control, bool list)
            {
                rows.Add(new(Guid.NewGuid(), control == "project" ? controlProject : phase == "copy" ? copyProject : project,
                    control == "environment" ? "outside" : "witness", control == "path" ? "/outside" : "/owned",
                    Guid.NewGuid(), Guid.NewGuid(), control == "connection" ? controlConnection : connection,
                    "rotation-" + rows.Count, principal, control, phase, action, list,
                    Fault == "profile-mismatch" ? InfisicalRotationProfile.PostgresCredentials : Profile.SqlProfile));
            }
        }
        issued = new(project, "project" + selected.Id, controlProject, copyProject, "copy" + selected.Id,
            Guid.NewGuid().ToString(), "role" + selected.Id, Guid.NewGuid().ToString(), Guid.NewGuid().ToString(),
            connection, controlConnection, revision, rows.ToArray());
        foreach (string id in new[] { project, controlProject, copyProject }) Enroll("project", id);
        foreach (string id in new[] { connection, controlConnection }) Enroll("connection", id);
        foreach (var row in rows)
            foreach (string kind in new[] { "rotation", "material", "sql-account-a", "sql-account-b", "mapping" })
                Enroll(kind, row.Id.ToString());
        Enroll("policy", issued.PolicyId); Enroll("template", issued.TemplateId);
        Enroll("membership", issued.Membership); Enroll("dispatch-work", selected.Id); Enroll("issuer-work", selected.Id);
        Enroll("sql-protected-row", selected.Id);
        if (!selected.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal))
        {
            string baseline = (((int)selected.Action + 1) % 6) switch
            { 0 => "read", 1 => "read-generated-credentials", 2 => "create", 3 => "edit", 4 => "delete", _ => "rotate-secrets" };
            policy = new("secret-rotation", [baseline], Authorities.Runtime, "witness", "/owned", connection);
            policyInventory.Add(issued.PolicyId, PolicyState(issued.PolicyId, policy, project, null));
            if (selected.Operation.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal))
            {
                template = policy;
                policyInventory.Add(issued.TemplateId, PolicyState(issued.TemplateId, policy, project, null));
            }
        }
        assigned = !selected.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal);
    }
    internal RotationPermissionPacket Step(RotationPermissionRoot selected, RotationPermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == RotationPermissionStep.Reserve)
            { RotationPermissionContract.Require(capability == "rotation-capability"); Reserve(selected); }
            RotationPermissionContract.Require(root is not null && !closed &&
                RotationPermissionContract.Hash(root) == RotationPermissionContract.Hash(selected) &&
                (step == RotationPermissionStep.Close || stage == (int)step));
            if (step != RotationPermissionStep.Close) stage++;
            switch (step)
            {
                case RotationPermissionStep.Open:
                    Opens++;
                    Create("sql-protected-row", root!.Id); sql.Bootstrap();
                    foreach (var e in enrolled.Where(e => e.Kind is "project" or "connection" or "membership" or "dispatch-work" or "issuer-work")
                        .Where(e => e.Id != issued!.CopyProject))
                    {
                        Create(e.Kind, e.Id);
                        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
                    }
                    if (policy is not null) Create("policy", issued!.PolicyId);
                    if (template is not null) Create("template", issued!.TemplateId);
                    foreach (var row in issued!.Rows.Where(r => r.Window != "copy" || r.Control == "project")) Bootstrap(row);
                    if (Fault == "lost-open") throw new NativeCaseFailureException("observer-unavailable");
                    break;
                case RotationPermissionStep.Before: window = "before"; ClearActions(); break;
                case RotationPermissionStep.After: window = "after"; ClearActions(); break;
                case RotationPermissionStep.Arm: window = ""; armed = true; break;
                case RotationPermissionStep.Settle: sealedDispatch = true; break;
                case RotationPermissionStep.ObserveBefore:
                case RotationPermissionStep.ObserveAfter: window = ""; break;
                case RotationPermissionStep.Close:
                    Closes++; closed = closing = sealedDispatch = true; armed = false; window = "";
                    foreach (var value in definitions.Values) value.Dispose();
                    definitions.Clear();
                    if (Fault != "backend-cleanup") sql.Clear();
                    if (Fault != "cleanup") resources.Clear();
                    if (Fault != "policy-cleanup") { policyInventory.Clear(); policy = template = copy = null; }
                    if (Fault == "borrowed-change") hostTokens[Authorities.Runtime] = "changed";
                    break;
            }
            bool observe = step is RotationPermissionStep.ObserveBefore or RotationPermissionStep.ObserveAfter;
            string selectedWindow = step == RotationPermissionStep.Settle ? "original" :
                step == RotationPermissionStep.ObserveBefore ? "before" : "after";
            var owner = new RotationPermissionOwner(step, true, true, true,
                sealedDispatch || step == RotationPermissionStep.Close, sql.Remaining < 0 ? 1 : 0, Registrations,
                step is RotationPermissionStep.Reserve or RotationPermissionStep.Close ? null : issued,
                enrolled.ToArray(), resources.Values.ToArray(), Borrowed());
            var packet = new RotationPermissionPacket(Sign(RotationPermissionJournal.Ownership, step.ToString(), owner),
                step == RotationPermissionStep.Settle || observe ? ingress.Where(i => i.Payload.Header.Window == selectedWindow).ToArray() : [],
                step is RotationPermissionStep.Settle or RotationPermissionStep.ObserveAfter ?
                    commits.Where(c => c.Payload.Header.Window == selectedWindow).ToArray() : [],
                observe ? decisions.ToArray() : [], observe ? changes.ToArray() : [],
                observe ? materials.ToArray() : [], observe ? backend.ToArray() : [],
                Sign(RotationPermissionJournal.Policy, step.ToString(),
                    step == RotationPermissionStep.Reserve ? [] : policyInventory.Values.OrderBy(p => p.Resource).ToArray()),
                Sign(RotationPermissionJournal.Resources, step.ToString(), definitions.Values.Select(State).OrderBy(s => s.Id).ToArray()),
                Sign(RotationPermissionJournal.Issuance, step.ToString(), new RotationPermissionStoreInventory(
                    definitions.Values.Sum(s => s.Pairs.Length), 0, 0, true)),
                sql.Inventory(root!, step.ToString()), []);
            return packet with
            {
                Seals = Enum.GetValues<RotationPermissionJournal>().Select(j =>
            {
                var content = RotationPermissionContract.Contents(packet, j);
                return Seal(j, step.ToString(), new(RotationPermissionContract.Hash(content), content.Length, true, 0));
            }).ToArray()
            };
        }
    }
    private void ClearActions() { decisions.Clear(); changes.Clear(); materials.Clear(); backend.Clear(); measured.Clear(); }
    private void Bootstrap(RotationPermissionRow row)
    {
        if (row.Action == RotationPermissionAction.Create) return;
        Store(row, InitialBody(row));
    }
    private static JsonObject InitialBody(RotationPermissionRow row) => new()
    {
        ["name"] = row.Name,
        ["projectId"] = row.Project,
        ["connectionId"] = row.Connection,
        ["environment"] = row.Environment,
        ["secretPath"] = row.Path,
        ["rotationInterval"] = 2d,
        ["rotateAtUtc"] = new JsonObject { ["hours"] = 3d, ["minutes"] = 4d },
        ["description"] = "owned",
        ["isAutoRotationEnabled"] = false,
        ["parameters"] = new JsonObject
        {
            ["username1"] = row.Username1,
            ["username2"] = row.Username2,
            ["rotationStatement"] = row.SqlProfile switch
            {
                InfisicalRotationProfile.PostgresCredentials => "ALTER USER {{username}} WITH PASSWORD '{{password}}';",
                InfisicalRotationProfile.MysqlCredentials => "ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';",
                InfisicalRotationProfile.MssqlCredentials => "ALTER LOGIN [{{username}}] WITH PASSWORD = '{{password}}';",
                _ => throw new NativeCaseFailureException("missing-input")
            },
            ["passwordRequirements"] = new JsonObject
            {
                ["length"] = 24d,
                ["allowedSymbols"] = "!@",
                ["required"] = new JsonObject { ["digits"] = 2d, ["lowercase"] = 2d, ["symbols"] = 2d, ["uppercase"] = 2d }
            }
        },
        ["secretsMapping"] = new JsonObject { ["username"] = row.UsernameKey, ["password"] = row.PasswordKey }
    };
    private Stored Store(RotationPermissionRow row, JsonObject body)
    {
        var value = new Stored(row, body);
        definitions.Add(row.Id, value);
        foreach (string kind in new[] { "rotation", "material", "sql-account-a", "sql-account-b", "mapping" }) Create(kind, row.Id.ToString());
        Issue(value); return value;
    }
    private void Issue(Stored value)
    {
        foreach (var p in value.Pairs) p.Dispose();
        var p1 = new Pair(Text(value.Configuration["parameters"]!, "username1"), Password(value));
        var p2 = new Pair(Text(value.Configuration["parameters"]!, "username2"), Password(value));
        value.Pairs = [p1, p2];
        if (Fault != "ignored-backend") foreach (var p in value.Pairs) sql.Set(p.Username, p.Password);
    }
    private static string Password(Stored value)
    {
        var c = Configuration(value);
        char[] chars = new char[(int)c.Length];
        int offset = 0;
        foreach (var group in new[] { ("0123456789", c.Digits), ("abcdefghijklmnopqrstuvwxyz", c.Lowercase),
            (c.AllowedSymbols, c.Symbols), ("ABCDEFGHIJKLMNOPQRSTUVWXYZ", c.Uppercase) })
            for (int i = 0; i < group.Item2; i++) chars[offset++] = group.Item1[RandomNumberGenerator.GetInt32(group.Item1.Length)];
        const string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        while (offset < chars.Length) chars[offset++] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        try { return new string(chars); }
        finally { Array.Clear(chars); }
    }
    private static bool MeetsRequirements(Stored value, Pair pair)
    {
        var c = Configuration(value); char[] chars = pair.Password.ExportCharacters();
        try
        {
            return chars.Length == c.Length && chars.Count(char.IsDigit) >= c.Digits &&
            chars.Count(char.IsLower) >= c.Lowercase && chars.Count(char.IsUpper) >= c.Uppercase &&
            chars.Count(ch => c.AllowedSymbols.Contains(ch)) >= c.Symbols;
        }
        finally { Array.Clear(chars); }
    }
    private static string Text(JsonNode node, string field) => node[field]!.GetValue<string>();
    private static RotationPermissionConfiguration Configuration(Stored value)
    {
        var c = value.Configuration; var p = c["parameters"]!; var requirements = p["passwordRequirements"]!;
        var required = requirements["required"]!; var mapping = c["secretsMapping"]!; var time = c["rotateAtUtc"]!;
        return new(value.Row.Id.ToString(), Text(c, "projectId"), Text(c, "environment"), Text(c, "secretPath"),
            Text(c, "connectionId"), Text(c, "name"), Text(p, "username1"), Text(p, "username2"),
            Text(mapping, "username"), Text(mapping, "password"), c["rotationInterval"]!.GetValue<double>(),
            time["hours"]!.GetValue<double>(), time["minutes"]!.GetValue<double>(), c["isAutoRotationEnabled"]!.GetValue<bool>(),
            c.ContainsKey("description"), c["description"]?.GetValue<string>(),
            requirements["length"]!.GetValue<double>(), required["digits"]!.GetValue<double>(),
            required["lowercase"]!.GetValue<double>(), required["symbols"]!.GetValue<double>(),
            required["uppercase"]!.GetValue<double>(), Text(requirements, "allowedSymbols"),
            RotationPermissionContract.Hash(Text(p, "rotationStatement")), value.Row.EnvironmentId.ToString(),
            value.Row.FolderId.ToString(), value.Row.SqlProfile);
    }
    private static RotationPermissionState State(Stored value) =>
        new(value.Row.Id, true, value.Version, Configuration(value), value.Generation,
            RotationPermissionContract.Hash(value.Pairs.Select(p => p.Hash).ToArray()));
    private RotationPermissionState State(Guid id) => definitions.TryGetValue(id, out var s) ? State(s) : new(id, false, 0, null, 0, "");
    private static object Projection(Stored value)
    {
        var row = value.Row;
        var result = (JsonObject)value.Configuration.DeepClone();
        string app = row.SqlProfile switch
        {
            InfisicalRotationProfile.PostgresCredentials => "postgres",
            InfisicalRotationProfile.MysqlCredentials => "mysql",
            InfisicalRotationProfile.MssqlCredentials => "mssql",
            _ => throw new NativeCaseFailureException("missing-input")
        };
        result["id"] = row.Id.ToString(); result["type"] = app + "-credentials";
        result["connection"] = new JsonObject { ["id"] = Text(result, "connectionId"), ["app"] = app, ["name"] = "Owned" };
        result["environment"] = new JsonObject { ["id"] = row.EnvironmentId, ["name"] = "Owned", ["slug"] = row.Environment };
        result.Remove("secretPath"); result["folderId"] = row.FolderId;
        result["folder"] = new JsonObject { ["id"] = row.FolderId, ["path"] = row.Path };
        result["createdAt"] = Date; result["updatedAt"] = Date; result["lastRotatedAt"] = Date;
        result["lastRotationAttemptedAt"] = Date; result["rotationStatus"] = "success"; result["activeIndex"] = value.Generation % 2;
        return result;
    }
    private void Ingress(string request, string principal, string bearer, string method, string path, byte[] body,
        string intent, Guid? rotation, bool allowed, string selectedWindow) =>
        ingress.Add(Sign(RotationPermissionJournal.Ingress, selectedWindow, new RotationPermissionIngress(request,
            principal, RotationPermissionContract.Hash(bearer), method,
            Fault == "wrong-route" && rotation is not null ? "/api/v4/secrets/raw/ordinary" : path, RotationPermissionContract.RawHash(body),
            intent, rotation, false, allowed)));
    private (int, object) Rotations(string method, Uri uri, string principal, string bearer, JsonElement body, byte[] bytes)
    {
        if (window is not ("before" or "after") || principal == "unknown") return (403, new { });
        var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 4 || segments[3] != (Profile.SqlProfile switch
        {
            InfisicalRotationProfile.PostgresCredentials => "postgres-credentials",
            InfisicalRotationProfile.MysqlCredentials => "mysql-credentials",
            InfisicalRotationProfile.MssqlCredentials => "mssql-credentials",
            _ => ""
        })) return (404, new { });
        bool list = method == "GET" && segments.Length == 4;
        var selectedAction = list ? RotationPermissionAction.Read : segments.Last() == "generated-credentials" ?
            RotationPermissionAction.ReadGeneratedCredentials : segments.Last() == "rotate-secrets" ?
            RotationPermissionAction.RotateSecrets : method switch
            {
                "GET" => RotationPermissionAction.Read,
                "POST" => RotationPermissionAction.Create,
                "PATCH" => RotationPermissionAction.Edit,
                _ => RotationPermissionAction.Delete
            };
        string selectedWindow = window == "after" && copied ? "copy" : window;
        string project = list ? Uri.UnescapeDataString(uri.Query.Split('=', 2).Last()) :
            selectedAction == RotationPermissionAction.Create ? body.GetProperty("projectId").GetString()! : "";
        var row = issued!.Rows.SingleOrDefault(r => r.Window == selectedWindow && r.Principal == principal &&
            r.Action == selectedAction && r.List == list &&
            (list ? r.Project == project : selectedAction == RotationPermissionAction.Create ?
                r.Project == project && r.Name == body.GetProperty("name").GetString() : r.Id.ToString() == segments[4]));
        if (row is null || !resources.ContainsKey("project/" + row.Project)) return (404, new { });
        if (selectedAction == RotationPermissionAction.Delete &&
            uri.Query != "?deleteSecrets=true&revokeGeneratedCredentials=true") return (400, new { });
        if (!measured.Add(row.Id)) return (409, new { });
        var effective = row.Project == issued.CopyProject ? copy : policy;
        string action = selectedAction switch
        {
            RotationPermissionAction.Read => "read",
            RotationPermissionAction.ReadGeneratedCredentials => "read-generated-credentials",
            RotationPermissionAction.Create => "create",
            RotationPermissionAction.Edit => "edit",
            RotationPermissionAction.Delete => "delete",
            _ => "rotate-secrets"
        };
        bool allowed = principal == Authorities.Setup || principal == Authorities.Observer ||
            effective is not null && assigned && effective.Principal == principal && effective.Subject == "secret-rotation" &&
            effective.Actions.Contains(action) && (row.Project == issued.Project || row.Project == issued.CopyProject) &&
            (list || row.Environment == effective.Environment && row.Path == effective.Path && row.Connection == effective.Connection);
        if (Fault == "action-leak" && revision == "policy-2" && principal == Authorities.Runtime) allowed = true;
        if (Fault == "scope-leak" && revision == "policy-2" && principal == Authorities.Runtime && effective?.Actions.Contains(action) == true) allowed = true;
        string actor = Fault == "wrong-principal" && principal == Authorities.Runtime && allowed ? Authorities.Observer : principal;
        string request = Guid.NewGuid().ToString("N");
        Ingress(request, actor, bearer, method, uri.AbsolutePath, bytes, "", row.Id, allowed, window);
        decisions.Add(Sign(RotationPermissionJournal.Policy, window, new RotationPermissionDecision(request, actor,
            RotationPermissionContract.Hash(bearer), row.Id, row.Project, row.Environment, row.Path, row.Connection,
            selectedAction, revision, allowed)));
        var previous = State(row.Id); object response = new { }; Pair[] retired = [];
        if (allowed)
        {
            if (list)
            {
                var values = definitions.Values.Where(v => v.Row.Project == row.Project &&
                    (principal != Authorities.Runtime || effective is not null && v.Row.Environment == effective.Environment &&
                        v.Row.Path == effective.Path && v.Row.Connection == effective.Connection)).Select(Projection).ToArray();
                response = new { secretRotations = Fault == "incomplete-list" ? values.Skip(1).ToArray() : values };
            }
            else
            {
                Stored value;
                if (selectedAction == RotationPermissionAction.Create)
                {
                    var supplied = JsonNode.Parse(bytes)!.AsObject();
                    value = Store(row, Fault == "ignored-config" ? InitialBody(row) : supplied);
                }
                else value = definitions[row.Id];
                if (selectedAction == RotationPermissionAction.Edit)
                {
                    if (Fault != "ignored-config")
                        foreach (var (name, replacement) in JsonNode.Parse(bytes)!.AsObject())
                            value.Configuration[name] = replacement?.DeepClone();
                    value.Version++;
                }
                if (selectedAction == RotationPermissionAction.RotateSecrets && Fault != "ignored-rotation")
                {
                    value.Generation++; value.Version++; Issue(value);
                }
                response = new { secretRotation = Projection(value) };
                if (selectedAction == RotationPermissionAction.ReadGeneratedCredentials)
                    response = new
                    {
                        type = value.Row.SqlProfile switch
                        {
                            InfisicalRotationProfile.PostgresCredentials => "postgres-credentials",
                            InfisicalRotationProfile.MysqlCredentials => "mysql-credentials",
                            InfisicalRotationProfile.MssqlCredentials => "mssql-credentials",
                            _ => ""
                        },
                        rotationId = row.Id.ToString(),
                        activeIndex = value.Generation % 2,
                        generatedCredentials = value.Pairs.Select(p => new
                        {
                            username = p.Username.Reveal(),
                            password = Fault == "wrong-material" ? "wrong" : p.Password.Reveal()
                        }).ToArray()
                    };
                if (selectedAction == RotationPermissionAction.Delete)
                {
                    retired = value.Pairs; value.Pairs = [];
                    foreach (var pair in retired) sql.Revoke(pair.Username);
                    definitions.Remove(row.Id); value.Dispose();
                    foreach (string kind in new[] { "rotation", "material", "sql-account-a", "sql-account-b", "mapping" })
                        resources.Remove(kind + "/" + row.Id);
                }
                var pairs = selectedAction == RotationPermissionAction.Delete ? retired : value.Pairs;
                foreach (var pair in pairs)
                {
                    if (selectedAction != RotationPermissionAction.Delete)
                        materials.Add(Sign(RotationPermissionJournal.Issuance, window, new RotationPermissionMaterial(request,
                            row.Id, value.Generation, RotationPermissionContract.Hash(pair.Username.Reveal()),
                            RotationPermissionContract.Hash(pair.Password.Reveal()), pair.Hash, MeetsRequirements(value, pair))));
                    backend.Add(sql.Measure(root!, window, request, row.Id, pair.Username, pair.Password));
                }
                foreach (var pair in retired) pair.Dispose();
            }
        }
        changes.Add(Sign(RotationPermissionJournal.Resources, window, new RotationPermissionChange(request, previous, State(row.Id))));
        return (allowed ? 200 : 403, response);
    }
    private static Policy ParsePolicy(JsonElement permissions, string principal)
    {
        RotationPermissionContract.Require(permissions.GetArrayLength() == 1);
        var p = permissions[0]; var a = p.GetProperty("action"); var c = p.GetProperty("conditions");
        RotationPermissionContract.Require(!p.TryGetProperty("inverted", out _));
        return new(p.GetProperty("subject").GetString()!,
            a.ValueKind == JsonValueKind.Array ? a.EnumerateArray().Select(x => x.GetString()!).ToArray() : [a.GetString()!],
            principal, c.GetProperty("environment").GetString()!, c.GetProperty("secretPath").GetString()!,
            c.GetProperty("connectionId").GetString()!);
    }
    private static string PolicyHash(Policy p) => p.Actions.Length == 1 ?
        RotationPermissionContract.Hash(new[] { p.Subject, p.Actions[0], p.Environment, p.Path, p.Connection }) : "partial";
    private RotationPermissionPolicy PolicyState(string resource, Policy p, string project, string? source) =>
        new(resource, p.Principal, project, revision, PolicyHash(p), source);
    private (int, object) Handle(string method, Uri uri, string bearer, JsonElement body, byte[] bytes)
    {
        if (root is null || issued is null || closed || closing) return (403, new { });
        string principal = hostTokens.SingleOrDefault(p => p.Value == bearer).Key ?? "unknown";
        if (uri.AbsolutePath.StartsWith("/api/v2/secret-rotations/", StringComparison.Ordinal))
            return Rotations(method, uri, principal, bearer, body, bytes);
        if (method == "POST" && uri.AbsolutePath == "/api/v1/projects") return CopyProject(principal, bearer, body, bytes);
        if (method == "PATCH" && uri.AbsolutePath == "/api/v1/projects/" + issued.Project + "/memberships/identities/" + Authorities.Runtime)
        {
            if (principal != Authorities.Setup || !sealedDispatch || policy is null || assigned ||
                body.GetProperty("roles").GetArrayLength() != 1 ||
                body.GetProperty("roles")[0].GetProperty("role").GetString() != issued.PolicySlug) return (403, new { });
            assigned = Fault != "assignment-echo";
            string request = Guid.NewGuid().ToString("N");
            Ingress(request, principal, bearer, method, uri.AbsolutePath, bytes,
                RotationPermissionContract.Hash(new object?[] { null, body }), null, true, "after");
            commits.Add(Sign(RotationPermissionJournal.Policy, "after", new RotationPermissionCommit(request, "unassigned",
                PolicyState(issued.Membership, assigned ? policy : policy with { Actions = [] }, issued.Project, revision))));
            return (200, new
            {
                identityMembership = new
                {
                    id = issued.Membership,
                    identityId = Authorities.Runtime,
                    projectId = issued.Project,
                    createdAt = Date,
                    updatedAt = Date
                }
            });
        }
        bool create = root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        bool isTemplate = root.Operation.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal);
        bool role = root.Operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal);
        string path = isTemplate ? "/api/v1/project-templates" + (create ? "" : "/" + issued.TemplateId) :
            role ? "/api/v1/projects/" + issued.Project + "/roles" + (create ? "" : "/" + issued.PolicyId) :
            "/api/v2/identity-project-additional-privilege" + (create ? "" : "/" + issued.PolicyId);
        if (uri.AbsolutePath != path || method != (create ? "POST" : "PATCH")) return (404, new { });
        if (!armed || sealedDispatch || Originals != 0) return (409, new { });
        Originals++;
        string id = Guid.NewGuid().ToString("N"), intent = RotationPermissionContract.RawHash(bytes);
        if (!role && !isTemplate)
            intent = RotationPermissionContract.Hash(new object?[] { issued.Slug, issued.Membership, create ? null : issued.PolicyId, body });
        bool authorized = principal == Authorities.Administrative;
        Ingress(id, principal, bearer, method, uri.AbsolutePath, bytes, intent, null, authorized, "original");
        if (!authorized) return (403, new { });
        var permissions = isTemplate ? body.GetProperty("roles")[0].GetProperty("permissions") : body.GetProperty("permissions");
        string selectedPrincipal = isTemplate ? body.GetProperty("identities")[0].GetProperty("identityId").GetString()! :
            body.TryGetProperty("identityId", out var identity) ? identity.GetString()! : Authorities.Runtime;
        var stored = ParsePolicy(permissions, selectedPrincipal);
        if (Fault is not ("ignored-policy" or "lost-nonapplied"))
        {
            if (Fault == "partial") stored = stored with { Actions = [] };
            string kind = isTemplate ? "template" : "policy", resource = isTemplate ? issued.TemplateId : issued.PolicyId;
            if (!resources.ContainsKey(kind + "/" + resource)) Create(kind, resource);
            if (isTemplate) template = stored; else policy = stored;
            string old = revision; revision = "policy-2";
            var state = PolicyState(resource, stored, issued.Project, null);
            policyInventory[resource] = state;
            commits.Add(Sign(RotationPermissionJournal.Policy, "original", new RotationPermissionCommit(id, old, state)));
        }
        var result = new JsonObject
        {
            ["id"] = isTemplate ? issued.TemplateId : issued.PolicyId,
            ["slug"] = issued.PolicySlug,
            ["createdAt"] = Date,
            ["updatedAt"] = Date,
            ["permissions"] = JsonNode.Parse(permissions.GetRawText())
        };
        if (isTemplate)
        {
            result.Remove("slug"); result.Remove("permissions"); result["name"] = issued.PolicySlug;
            result["orgId"] = Organization; result["type"] = "secret-manager"; result["users"] = new JsonArray();
            result["groups"] = new JsonArray(); result["projectManagedIdentities"] = new JsonArray();
            foreach (string name in new[] { "roles", "environments", "identities" })
                result[name] = JsonNode.Parse(body.GetProperty(name).GetRawText());
            foreach (var r in result["identities"]!.AsArray()) r!["identityName"] = "runtime";
        }
        else if (role) { result["name"] = issued.PolicySlug; result["projectId"] = issued.Project; }
        else result["isTemporary"] = false;
        return (200, new JsonObject { [isTemplate ? "projectTemplate" : role ? "role" : "privilege"] = result });
    }
    private (int, object) CopyProject(string principal, string bearer, JsonElement body, byte[] bytes)
    {
        if (principal != Authorities.Setup || !sealedDispatch || copied || template is null ||
            body.GetProperty("template").GetString() != issued!.PolicySlug ||
            body.GetProperty("slug").GetString() != issued.CopySlug) return (403, new { });
        copied = true; copy = Fault == "template-echo" ? null : template with { Actions = template.Actions.ToArray() };
        Create("project", issued.CopyProject);
        foreach (var row in issued.Rows.Where(r => r.Window == "copy" && r.Control != "project")) Bootstrap(row);
        var state = PolicyState(issued.CopyProject, copy ?? template with { Actions = [] }, issued.CopyProject, revision);
        if (copy is not null) policyInventory[issued.CopyProject] = state;
        string request = Guid.NewGuid().ToString("N");
        Ingress(request, principal, bearer, "POST", "/api/v1/projects", bytes, RotationPermissionContract.RawHash(bytes), null, true, "after");
        commits.Add(Sign(RotationPermissionJournal.Policy, "after", new RotationPermissionCommit(request, "absent", state)));
        return (200, new
        {
            project = new
            {
                id = issued.CopyProject,
                _id = issued.CopyProject,
                orgId = Organization,
                name = issued.CopySlug,
                slug = issued.CopySlug,
                type = "secret-manager",
                createdAt = Date,
                updatedAt = Date,
                environments = Array.Empty<object>(),
                deletedEnvironments = Array.Empty<object>()
            }
        });
    }
    private async Task AcceptAsync()
    {
        try { while (!shutdown.IsCancellationRequested) connections.Add(ServeAsync(await listener.AcceptTcpClientAsync(shutdown.Token))); }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
    }
    private async Task ServeAsync(TcpClient socket)
    {
        using (socket)
        {
            byte[] header = new byte[32768], body = [], response = [];
            Copies.Add(header);
            try
            {
                var stream = socket.GetStream(); int count = 0;
                while (count < header.Length)
                {
                    if (await stream.ReadAsync(header.AsMemory(count, 1), shutdown.Token) == 0) return;
                    count++;
                    if (count >= 4 && header.AsSpan(count - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
                }
                string[] lines = Encoding.ASCII.GetString(header, 0, count).Split("\r\n");
                string[] request = lines[0].Split(' ');
                int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?.Split(':')[1] ?? "0");
                RotationPermissionContract.Require(length is >= 0 and <= 131072);
                body = new byte[length]; Copies.Add(body); await stream.ReadExactlyAsync(body, shutdown.Token);
                string bearer = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?.Split(' ').Last() ?? "";
                using var json = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                (int Status, object Body) result;
                lock (gate) result = Handle(request[0], new Uri(Origin, request[1]), bearer, json.RootElement, body);
                response = JsonSerializer.SerializeToUtf8Bytes(result.Body); Copies.Add(response);
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                await stream.WriteAsync(response, shutdown.Token);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            finally { CryptographicOperations.ZeroMemory(header); CryptographicOperations.ZeroMemory(body); CryptographicOperations.ZeroMemory(response); }
        }
    }
    private sealed class RuntimeTransport(InfisicalRotationPermissionFixture fixture) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            RotationPermissionContract.Require(request.RequestUri!.GetLeftPart(UriPartial.Authority) == "https://rotation-controlled.invalid");
            byte[] bytes = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(token);
            fixture.Copies.Add(bytes);
            try
            {
                using var json = JsonDocument.Parse(bytes.Length == 0 ? "{}"u8.ToArray() : bytes);
                (int Status, object Body) result;
                lock (fixture.gate) result = fixture.Handle(request.Method.Method, request.RequestUri,
                    request.Headers.Authorization?.Parameter ?? "", json.RootElement, bytes);
                byte[] response = JsonSerializer.SerializeToUtf8Bytes(result.Body); fixture.Copies.Add(response);
                return new((HttpStatusCode)result.Status) { RequestMessage = request, Content = new ClearingContent(response) };
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }
    internal sealed class ClearingContent : ByteArrayContent
    {
        private readonly byte[] bytes;
        internal ClearingContent(byte[] bytes) : base(bytes) => this.bytes = bytes;
        protected override void Dispose(bool disposing)
        { base.Dispose(disposing); if (disposing) CryptographicOperations.ZeroMemory(bytes); }
    }
    internal async Task SealAndDrainAsync()
    { lock (gate) { closing = true; sealedDispatch = true; armed = false; } await DrainAsync(); }
    internal Task DrainAsync() => Task.WhenAll(connections);
    public async ValueTask DisposeAsync()
    {
        shutdown.Cancel(); listener.Stop();
        try { await accept; } catch (SocketException) when (shutdown.IsCancellationRequested) { }
        await Task.WhenAll(connections);
        foreach (var value in definitions.Values) value.Dispose();
        Runtime.Transport.Dispose(); Source.Dispose(); sql.Dispose();
        foreach (var writer in writers.Values) writer.Dispose();
        shutdown.Dispose();
    }
}
