using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent controlled HTTP provider: actual SDK wire bodies select persisted
// policy. No effect implementation is called to authorize, commit, or issue.
// Setup inspection and measured action are independently authenticated here.
internal sealed class InfisicalDynamicPermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static DynamicPermissionAuthorities Authorities { get; } =
        new("20000000-0000-0000-0000-000000000001", "20000000-0000-0000-0000-000000000002",
            "20000000-0000-0000-0000-000000000003", "20000000-0000-0000-0000-000000000004",
            "20000000-0000-0000-0000-000000000005");
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<DynamicPermissionJournal, DynamicPermissionWriter> writers = [];
    private readonly InfisicalDynamicPermissionSqlBackend backend;
    private readonly Dictionary<string, string> hostTokens = new()
    {
        [Authorities.Setup] = "setup",
        [Authorities.Runtime] = "runtime",
        [Authorities.Denied] = "denied",
        [Authorities.Administrative] = "administrative",
        [Authorities.Observer] = "observer"
    };
    private readonly DynamicPermissionBorrowed[] borrowed;
    private readonly List<DynamicPermissionResource> enrolled = [];
    private readonly Dictionary<string, DynamicPermissionResource> resources = [];
    private readonly Dictionary<Guid, StoredDefinition> definitions = [];
    private readonly List<DynamicPermissionSigned<DynamicPermissionIngress>> ingress = [];
    private readonly List<DynamicPermissionSigned<DynamicPermissionCommit>> commits = [];
    private readonly List<DynamicPermissionSigned<DynamicPermissionDecision>> decisions = [];
    private readonly List<DynamicPermissionSigned<DynamicPermissionChange>> changes = [];
    private readonly List<DynamicPermissionSigned<DynamicPermissionLease>> leases = [];
    private readonly HashSet<Guid> bootstrapped = [], measured = [];
    private sealed record StoredDefinition(DynamicPermissionRow Row, DynamicPermissionSqlProfile Sql, int Ttl, int Version);
    private sealed record Policy(string Subject, string[] Actions, string Environment, string Path, string Principal);
    private DynamicPermissionRoot? root;
    private DynamicPermissionIssued? issued;
    private Policy? policy, template, copy;
    private string revision = "policy-1", window = "";
    private string policyRevision = "policy-1", templateRevision = "policy-1", copyRevision = "";
    private int stage;
    private bool closed, closing, armed, sealedDispatch, assigned, copied;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal DynamicPermissionProfile Profile { get; }
    internal InfisicalDynamicPermissionFixtureSource Source { get; }
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    internal int Originals { get; private set; }
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Remaining
    {
        get
        {
            lock (gate) return resources.Count + definitions.Count + backend.Remaining +
                (policy is null ? 0 : 1) + (template is null ? 0 : 1) + (copy is null ? 0 : 1);
        }
    }
    internal int Registrations => root is not null && !closed ? 1 : 0;
    internal bool BorrowedPreserved => borrowed.SequenceEqual(Borrowed());
    internal InfisicalDynamicPermissionFixture(string fault = "")
    {
        Fault = fault; borrowed = Borrowed(); backend = new(fault);
        foreach (var journal in Enum.GetValues<DynamicPermissionJournal>().Where(j => j != DynamicPermissionJournal.Backend))
            writers.Add(journal, new(journal, journal + "-writer"));
        Profile = new("controlled-dynamic", "controlled-epoch", "controlled-v1",
            writers.Values.Select(w => w.Pin).Append(backend.Pin).ToArray());
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this); accept = AcceptAsync();
    }
    internal DynamicPermissionInput Input(DynamicPermissionAction action) =>
        new(new(new("https://dynamic-source.invalid/"), "coordinator-token", "dynamic-coordinator", 30),
            "dynamic-capability", Profile, action, 30);
    internal NativeEnvironment Environment(DynamicPermissionAction action = DynamicPermissionAction.Read)
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
                    dynamicPermission = Input(action)
                }
            }
        };
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
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
        }, DynamicPermissionContract.Options));
    }
    internal DynamicPermissionRoot Root(string operation, DynamicPermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization,
            operation, DynamicPermissionContract.Variant(operation, action), boundary, "local", "dynamic-coordinator",
            DynamicPermissionSourceKind.ControlledFixture, action, Authorities, Profile);
    private DynamicPermissionSigned<T> Sign<T>(DynamicPermissionJournal journal, string selectedWindow, T value) =>
        writers[journal].Sign(root!, selectedWindow, value);
    private DynamicPermissionBorrowed[] Borrowed() => hostTokens.Select(p =>
        new DynamicPermissionBorrowed("host-token", p.Key, DynamicPermissionContract.Hash(p.Value))).ToArray();
    private void Enroll(string kind, string id)
    {
        DynamicPermissionContract.Require(root is not null && !closed);
        var entry = new DynamicPermissionResource(kind, id, root!.Id, root.Nonce);
        DynamicPermissionContract.Require(!enrolled.Any(e => e.Kind == kind && e.Id == id) &&
            !borrowed.Any(e => e.Kind == kind && e.Id == id));
        enrolled.Add(entry);
    }
    private void Create(string kind, string id)
    {
        DynamicPermissionContract.Require(!closed);
        var entry = enrolled.Single(e => e.Kind == kind && e.Id == id);
        resources.Add(kind + "/" + id, entry);
    }
    private void Reserve(DynamicPermissionRoot selected)
    {
        DynamicPermissionContract.Require(root is null && selected.Origin == Origin.AbsoluteUri &&
            selected.Organization == Organization && selected.Authorities == Authorities &&
            DynamicPermissionContract.Hash(selected.Profile) == DynamicPermissionContract.Hash(Profile));
        root = selected; // collision failures still retain original-root recovery
        if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
        string project = Guid.NewGuid().ToString(), control = Guid.NewGuid().ToString(), copyProject = Guid.NewGuid().ToString();
        string slug = "dynamic" + selected.Id, copySlug = "copy" + selected.Id;
        var rows = new List<DynamicPermissionRow>();
        foreach (string phase in new[] { "before", "after", "copy" })
            foreach (var action in Enum.GetValues<DynamicPermissionAction>())
                foreach (var principal in new[] { Authorities.Runtime, Authorities.Denied, Authorities.Observer })
                    foreach (string boundary in principal == Authorities.Runtime ? new[] { "selected", "project", "environment", "path" } : ["selected"])
                    {
                        bool outside = boundary == "project", copiedProject = phase == "copy";
                        rows.Add(new("d" + rows.Count, outside ? control : copiedProject ? copyProject : project,
                            outside ? "outside" + selected.Id : copiedProject ? copySlug : slug,
                            boundary == "environment" ? "outside" : "witness", boundary == "path" ? "/outside" : "/",
                            Guid.NewGuid(), Guid.NewGuid(), phase, principal, boundary, action));
                    }
        issued = new(project, slug, control, copyProject, copySlug, Guid.NewGuid().ToString(), "role" + selected.Id,
            Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), revision, backend.ProtectedHash, rows.ToArray(),
            new(NativeSqlEngine.Postgres, "controlled.invalid", 5432, "root",
                Convert.ToHexString(RandomNumberGenerator.GetBytes(32)), "controlled", "CREATE {{username}}", "DROP {{username}}"));
        foreach (string id in new[] { project, control, copyProject }) Enroll("project", id);
        foreach (var row in rows) { Enroll("definition", row.Definition.ToString()); Enroll("folder", row.Folder.ToString()); }
        Enroll("policy", issued.PolicyId); Enroll("template", issued.TemplateId);
        Enroll("membership", issued.Membership); Enroll("sql-root", selected.Id); Enroll("issuer-work", selected.Id);
        // Complete plan, including future copying and issuer work, precedes Open.
        if (!selected.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal))
        {
            string baseline = (((int)selected.Action + 1) % 5) switch
            {
                0 => "read-root-credential",
                1 => "create-root-credential",
                2 => "edit-root-credential",
                3 => "delete-root-credential",
                _ => "lease"
            };
            policy = new("dynamic-secrets", [baseline], "witness", "/", Authorities.Runtime);
            if (selected.Operation.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal)) template = policy;
        }
        assigned = !selected.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal);
    }
    internal DynamicPermissionPacket Step(DynamicPermissionRoot selected, DynamicPermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == DynamicPermissionStep.Reserve)
            {
                DynamicPermissionContract.Require(capability == "dynamic-capability");
                Reserve(selected);
            }
            DynamicPermissionContract.Require(root is not null && DynamicPermissionContract.Hash(root) == DynamicPermissionContract.Hash(selected) &&
                !closed && (step == DynamicPermissionStep.Close || stage == (int)step));
            if (step != DynamicPermissionStep.Close) stage++;
            switch (step)
            {
                case DynamicPermissionStep.Open:
                    Opens++;
                    foreach (var entry in enrolled.Where(e => e.Kind != "definition" && e.Kind != "folder" &&
                        (e.Kind != "policy" || policy is not null) && (e.Kind != "template" || template is not null) &&
                        e.Id != issued!.CopyProject))
                    {
                        Create(entry.Kind, entry.Id);
                        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
                    }
                    backend.Bootstrap();
                    foreach (var row in issued!.Rows.Where(r => r.Window != "copy" || r.Control == "project"))
                        Bootstrap(row);
                    if (Fault == "lost-open") throw new NativeCaseFailureException("observer-unavailable");
                    break;
                case DynamicPermissionStep.Before: window = "before"; ClearActions(); break;
                case DynamicPermissionStep.After: window = "after"; ClearActions(); break;
                case DynamicPermissionStep.Arm: window = ""; armed = true; break;
                case DynamicPermissionStep.Settle: sealedDispatch = true; break;
                case DynamicPermissionStep.ObserveBefore:
                case DynamicPermissionStep.ObserveAfter: window = ""; break;
                case DynamicPermissionStep.Close:
                    Closes++; closed = closing = sealedDispatch = true; armed = false; window = "";
                    backend.Clear();
                    foreach (var entry in resources.Values.ToArray())
                        if (Fault != "cleanup" || entry.Kind != "definition") resources.Remove(entry.Kind + "/" + entry.Id);
                    if (Fault != "cleanup") definitions.Clear();
                    if (Fault == "borrowed-change") hostTokens[Authorities.Runtime] = "changed";
                    if (Fault != "policy-cleanup") policy = template = copy = null;
                    break;
            }
            bool observe = step is DynamicPermissionStep.ObserveBefore or DynamicPermissionStep.ObserveAfter;
            string selectedWindow = step == DynamicPermissionStep.Settle ? "original" : "after";
            var owner = new DynamicPermissionOwner(step, true, true, true,
                step is DynamicPermissionStep.Settle or DynamicPermissionStep.Close, 0, closed ? 0 : 1,
                step == DynamicPermissionStep.Open ? issued : null, enrolled.ToArray(), resources.Values.ToArray(), Borrowed());
            var packet = new DynamicPermissionPacket(Sign(DynamicPermissionJournal.Ownership, step.ToString(), owner),
                observe ? ingress.Where(i => i.Payload.Header.Window == (step == DynamicPermissionStep.ObserveBefore ? "before" : "after")).ToArray() :
                    step == DynamicPermissionStep.Settle ? ingress.Where(i => i.Payload.Header.Window == "original").ToArray() : [],
                step is DynamicPermissionStep.Settle or DynamicPermissionStep.ObserveAfter ?
                    commits.Where(c => c.Payload.Header.Window == selectedWindow).ToArray() : [],
                observe ? decisions.ToArray() : [], observe ? changes.ToArray() : [], observe ? leases.ToArray() : [],
                Sign(DynamicPermissionJournal.Policy, step.ToString(), PolicyInventory()),
                Sign(DynamicPermissionJournal.Resources, step.ToString(), definitions.Values.Select(State).OrderBy(s => s.Definition).ToArray()),
                backend.Snapshot(root!, step.ToString()), []);
            return packet with
            {
                Seals = new[] { DynamicPermissionJournal.Ingress, DynamicPermissionJournal.Policy,
                    DynamicPermissionJournal.Resources, DynamicPermissionJournal.Issuance }.Select(j =>
                {
                    var content = DynamicPermissionContract.Contents(packet, j);
                    return Sign(j, step.ToString(), new DynamicPermissionSeal(content.Hash, content.Headers.Length, true, 0));
                }).ToArray()
            };
        }
    }
    private void Bootstrap(DynamicPermissionRow row)
    {
        Create("folder", row.Folder.ToString());
        if (row.Action == DynamicPermissionAction.Create) return;
        Create("definition", row.Definition.ToString());
        definitions.Add(row.Definition, new(row, issued!.Sql, 300, 1));
    }
    private void ClearActions() { decisions.Clear(); changes.Clear(); leases.Clear(); bootstrapped.Clear(); measured.Clear(); }
    internal DynamicPermissionSigned<DynamicPermissionSql> Measure(DynamicPermissionRoot selected, Guid lease,
        string username, string password, DynamicPermissionSqlAction action)
    {
        lock (gate)
        {
            DynamicPermissionContract.Require(!closed && window is "before" or "after" &&
                DynamicPermissionContract.Hash(selected) == DynamicPermissionContract.Hash(root));
            return backend.Measure(selected, window, lease, username, password, action);
        }
    }
    internal async Task SealAndDrainAsync()
    {
        lock (gate) { closing = true; sealedDispatch = true; armed = false; }
        await DrainAsync();
    }
    private async Task AcceptAsync()
    {
        try
        {
            while (!shutdown.IsCancellationRequested) connections.Add(ServeAsync(await listener.AcceptTcpClientAsync(shutdown.Token)));
        }
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
                int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?
                    .Split(':')[1].Trim() ?? "0");
                DynamicPermissionContract.Require(length is >= 0 and <= 131072);
                body = new byte[length]; Copies.Add(body); await stream.ReadExactlyAsync(body, shutdown.Token);
                string bearer = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?
                    .Split(' ').Last() ?? "";
                using var json = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                (int Status, object Body) result;
                lock (gate) result = Handle(request[0], new Uri(Origin, request[1]), bearer, json.RootElement, body);
                response = JsonSerializer.SerializeToUtf8Bytes(result.Body); Copies.Add(response);
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                await stream.WriteAsync(response, shutdown.Token);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            finally
            {
                CryptographicOperations.ZeroMemory(header); CryptographicOperations.ZeroMemory(body);
                CryptographicOperations.ZeroMemory(response);
            }
        }
    }
    private (int, object) Handle(string method, Uri uri, string bearer, JsonElement body, byte[] bytes)
    {
        if (root is null || issued is null || closed || closing) return (403, new { });
        string principal = hostTokens.SingleOrDefault(p => p.Value == bearer).Key ?? "unknown";
        if (uri.AbsolutePath.StartsWith("/api/v1/dynamic-secrets", StringComparison.Ordinal))
            return Dynamic(method, uri, principal, bearer, body, bytes);
        if (method == "POST" && uri.AbsolutePath == "/api/v1/projects") return CopyProject(principal, bearer, body, bytes);
        if (method == "PATCH" && uri.AbsolutePath == "/api/v1/projects/" + issued.Project + "/memberships/identities/" + Authorities.Runtime)
        {
            if (principal != Authorities.Setup || !sealedDispatch || policy is null || assigned ||
                body.GetProperty("roles").GetArrayLength() != 1 ||
                body.GetProperty("roles")[0].GetProperty("role").GetString() != issued.PolicySlug) return (403, new { });
            assigned = Fault != "assignment-echo";
            string request = Guid.NewGuid().ToString("N");
            byte[] intent = JsonSerializer.SerializeToUtf8Bytes(new object?[] { null, body });
            try
            {
                Ingress(request, principal, bearer, method, uri.AbsolutePath, bytes,
                DynamicPermissionContract.RawHash(intent), null, false, true, "after");
            }
            finally { CryptographicOperations.ZeroMemory(intent); }
            commits.Add(Sign(DynamicPermissionJournal.Policy, "after", new DynamicPermissionCommit(request, issued.Membership,
                "unassigned", "assigned", assigned ? PolicyHash(policy) : "empty", Authorities.Runtime, issued.Project, revision)));
            return (200, new
            {
                identityMembership = new
                {
                    id = issued.Membership,
                    identityId = Authorities.Runtime,
                    projectId = issued.Project,
                    createdAt = "2026-01-01T00:00:00Z",
                    updatedAt = "2026-01-01T00:00:01Z"
                }
            });
        }
        bool create = root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        bool isTemplate = root.Operation.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal);
        bool role = root.Operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal);
        string originalPath = isTemplate ? "/api/v1/project-templates" + (create ? "" : "/" + issued.TemplateId) :
            role ? "/api/v1/projects/" + issued.Project + "/roles" + (create ? "" : "/" + issued.PolicyId) :
            "/api/v2/identity-project-additional-privilege" + (create ? "" : "/" + issued.PolicyId);
        if (uri.AbsolutePath != originalPath || method != (create ? "POST" : "PATCH")) return (404, new { });
        if (!armed || sealedDispatch || Originals != 0) return (409, new { });
        Originals++;
        string requestId = Guid.NewGuid().ToString("N"), intentHash = DynamicPermissionContract.RawHash(bytes);
        if (!role && !isTemplate)
        {
            byte[] intent = JsonSerializer.SerializeToUtf8Bytes(new object?[]
                { issued.Slug, issued.Membership, create ? null : issued.PolicyId, body });
            try { intentHash = DynamicPermissionContract.RawHash(intent); }
            finally { CryptographicOperations.ZeroMemory(intent); }
        }
        bool authorized = principal == Authorities.Administrative;
        Ingress(requestId, principal, bearer, method, uri.AbsolutePath, bytes, intentHash, null, false, authorized, "original");
        if (!authorized) return (403, new { });
        var permissions = isTemplate ? body.GetProperty("roles")[0].GetProperty("permissions") : body.GetProperty("permissions");
        string selectedPrincipal = isTemplate ? body.GetProperty("identities")[0].GetProperty("identityId").GetString()! :
            body.TryGetProperty("identityId", out var identity) ? identity.GetString()! : Authorities.Runtime;
        var stored = ParsePolicy(permissions, selectedPrincipal);
        if (Fault is not ("ignored-policy" or "lost-nonapplied"))
        {
            if (Fault == "partial") stored = stored with { Actions = [] };
            string kind = isTemplate ? "template" : "policy", id = isTemplate ? issued.TemplateId : issued.PolicyId;
            if (!resources.ContainsKey(kind + "/" + id)) Create(kind, id);
            if (isTemplate) { template = stored; templateRevision = "policy-2"; }
            else { policy = stored; policyRevision = "policy-2"; }
            string previous = revision; revision = "policy-2";
            commits.Add(Sign(DynamicPermissionJournal.Policy, "original", new DynamicPermissionCommit(requestId,
                isTemplate ? issued.TemplateId : issued.PolicyId, previous, revision, PolicyHash(stored),
                selectedPrincipal, issued.Project, null)));
        }
        // Echo only acknowledges metadata; decisions read persisted policy above.
        var row = new JsonObject
        {
            ["id"] = isTemplate ? issued.TemplateId : issued.PolicyId,
            ["slug"] = issued.PolicySlug,
            ["createdAt"] = "2026-01-01T00:00:00Z",
            ["updatedAt"] = "2026-01-01T00:00:01Z",
            ["permissions"] = JsonNode.Parse(permissions.GetRawText())
        };
        if (isTemplate)
        {
            row.Remove("slug"); row.Remove("permissions"); row["name"] = issued.PolicySlug;
            row["orgId"] = Organization; row["type"] = "secret-manager"; row["users"] = new JsonArray();
            row["groups"] = new JsonArray(); row["projectManagedIdentities"] = new JsonArray();
            foreach (string name in new[] { "roles", "environments", "identities" })
                row[name] = JsonNode.Parse(body.GetProperty(name).GetRawText());
            foreach (var identityRow in row["identities"]!.AsArray()) identityRow!["identityName"] = "runtime";
        }
        else if (role) { row["name"] = issued.PolicySlug; row["projectId"] = issued.Project; }
        else row["isTemporary"] = false;
        return (200, new JsonObject { [isTemplate ? "projectTemplate" : role ? "role" : "privilege"] = row });
    }
    private (int, object) CopyProject(string principal, string bearer, JsonElement body, byte[] bytes)
    {
        if (principal != Authorities.Setup || !sealedDispatch || copied || template is null ||
            body.GetProperty("template").GetString() != issued!.PolicySlug ||
            body.GetProperty("slug").GetString() != issued.CopySlug) return (403, new { });
        copied = true; copy = Fault == "template-echo" ? null : template with { Actions = template.Actions.ToArray() };
        copyRevision = templateRevision;
        Create("project", issued.CopyProject);
        foreach (var row in issued.Rows.Where(r => r.Window == "copy" && r.Control != "project")) Bootstrap(row);
        string request = Guid.NewGuid().ToString("N");
        Ingress(request, principal, bearer, "POST", "/api/v1/projects", bytes, DynamicPermissionContract.RawHash(bytes),
            null, false, true, "after");
        commits.Add(Sign(DynamicPermissionJournal.Policy, "after", new DynamicPermissionCommit(request, issued.CopyProject,
            "absent", "copied", copy is null ? "empty" : PolicyHash(copy), template.Principal, issued.CopyProject, revision)));
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
                createdAt = "2026-01-01T00:00:00Z",
                updatedAt = "2026-01-01T00:00:00Z",
                environments = Array.Empty<object>(),
                deletedEnvironments = Array.Empty<object>()
            }
        });
    }
    private void Ingress(string request, string principal, string bearer, string method, string path, byte[] body,
        string intent, Guid? definition, bool bootstrap, bool allowed, string selectedWindow) =>
        ingress.Add(Sign(DynamicPermissionJournal.Ingress, selectedWindow, new DynamicPermissionIngress(request,
            principal, DynamicPermissionContract.Hash(bearer), method, path, DynamicPermissionContract.RawHash(body),
            intent, definition, bootstrap, allowed)));
    private (int, object) Dynamic(string method, Uri uri, string principal, string bearer, JsonElement body, byte[] bytes)
    {
        if (window is not ("before" or "after") || principal == "unknown") return (403, new { });
        string name, slug, environment, path;
        if (method == "GET")
        {
            var query = uri.Query.TrimStart('?').Split('&').Select(s => s.Split('=', 2))
                .ToDictionary(s => s[0], s => Uri.UnescapeDataString(s[1]));
            name = Uri.UnescapeDataString(uri.Segments.Last()); slug = query["projectSlug"];
            environment = query["environmentSlug"]; path = query["path"];
        }
        else
        {
            slug = body.GetProperty("projectSlug").GetString()!; environment = body.GetProperty("environmentSlug").GetString()!;
            path = body.GetProperty("path").GetString()!;
            name = uri.AbsolutePath.EndsWith("/leases", StringComparison.Ordinal) ? body.GetProperty("dynamicSecretName").GetString()! :
                method == "POST" ? body.GetProperty("name").GetString()! : Uri.UnescapeDataString(uri.Segments.Last());
        }
        var row = issued!.Rows.SingleOrDefault(r => r.Name == name && r.Slug == slug && r.Environment == environment && r.Path == path);
        if (row is null || !resources.ContainsKey("folder/" + row.Folder) || !resources.ContainsKey("project/" + row.Project))
            return (404, new { });
        bool bootstrap = principal == Authorities.Setup;
        string request = Guid.NewGuid().ToString("N");
        if (bootstrap)
        {
            bool accepted = method == "GET" && !measured.Contains(row.Definition) &&
                bootstrapped.Add(row.Definition) && definitions.ContainsKey(row.Definition);
            Ingress(request, principal, bearer, method, uri.AbsolutePath, bytes, "", row.Definition, true, accepted, window);
            return accepted ? (200, new { dynamicSecret = Definition(definitions[row.Definition]) }) : (403, new { });
        }
        DynamicPermissionAction action = method switch
        {
            "GET" => DynamicPermissionAction.Read,
            "PATCH" => DynamicPermissionAction.Edit,
            "DELETE" => DynamicPermissionAction.Delete,
            "POST" when uri.AbsolutePath.EndsWith("/leases", StringComparison.Ordinal) => DynamicPermissionAction.Lease,
            _ => DynamicPermissionAction.Create
        };
        if (!measured.Add(row.Definition) || row.Action != action) return (409, new { });
        var effective = row.Project == issued.CopyProject ? copy : policy;
        string wire = action switch
        {
            DynamicPermissionAction.Read => "read-root-credential",
            DynamicPermissionAction.Create => "create-root-credential",
            DynamicPermissionAction.Edit => "edit-root-credential",
            DynamicPermissionAction.Delete => "delete-root-credential",
            _ => "lease"
        };
        bool allowed = principal == Authorities.Observer || effective is not null && principal == effective.Principal &&
            assigned && (row.Project == issued.Project || row.Project == issued.CopyProject) &&
            effective.Subject == "dynamic-secrets" && effective.Environment == row.Environment && effective.Path == row.Path &&
            effective.Actions.Contains(wire);
        if (Fault == "action-leak" && revision == "policy-2" && principal == Authorities.Runtime) allowed = true;
        if (Fault == "scope-leak" && revision == "policy-2" && principal == Authorities.Runtime &&
            effective is not null && effective.Actions.Contains(wire)) allowed = true;
        string journalPrincipal = Fault == "wrong-principal" && allowed && principal == Authorities.Runtime ? Authorities.Observer : principal;
        Ingress(request, journalPrincipal, bearer, method, uri.AbsolutePath, bytes, "", row.Definition, false, allowed, window);
        var decision = Sign(DynamicPermissionJournal.Policy, window, new DynamicPermissionDecision(request, journalPrincipal,
            DynamicPermissionContract.Hash(bearer), row.Project, row.Definition, revision, action, allowed));
        decisions.Add(decision);
        var previous = State(row.Definition);
        object result = new { };
        if (allowed)
        {
            switch (action)
            {
                case DynamicPermissionAction.Read: result = new { dynamicSecret = Definition(definitions[row.Definition]) }; break;
                case DynamicPermissionAction.Create:
                    var provider = body.GetProperty("provider"); var inputs = provider.GetProperty("inputs");
                    DynamicPermissionContract.Require(provider.GetProperty("type").GetString() == "sql-database" &&
                        inputs.GetProperty("client").GetString() == "postgres" && body.GetProperty("defaultTTL").GetString() == "300s");
                    var sql = new DynamicPermissionSqlProfile(NativeSqlEngine.Postgres, inputs.GetProperty("host").GetString()!,
                        inputs.GetProperty("port").GetInt32(), inputs.GetProperty("username").GetString()!, inputs.GetProperty("password").GetString()!,
                        inputs.GetProperty("database").GetString()!, inputs.GetProperty("creationStatement").GetString()!,
                        inputs.GetProperty("revocationStatement").GetString()!);
                    Create("definition", row.Definition.ToString());
                    definitions.Add(row.Definition, new(row, sql, 300, 1));
                    result = new { dynamicSecret = Definition(definitions[row.Definition]) }; break;
                case DynamicPermissionAction.Edit:
                    DynamicPermissionContract.Require(body.GetProperty("data").GetProperty("defaultTTL").GetString() == "240s");
                    var old = definitions[row.Definition];
                    definitions[row.Definition] = old with { Ttl = 240, Version = old.Version + 1 };
                    result = new { dynamicSecret = Definition(definitions[row.Definition]) }; break;
                case DynamicPermissionAction.Delete:
                    result = new { dynamicSecret = Definition(definitions[row.Definition]) };
                    definitions.Remove(row.Definition); resources.Remove("definition/" + row.Definition); break;
                case DynamicPermissionAction.Lease:
                    Guid lease = Guid.NewGuid();
                    string username = "u" + Guid.NewGuid().ToString("N"), password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
                    string material = DynamicPermissionContract.MaterialHash(username, password);
                    // Issuer work was pre-enrolled at Reserve. Each concrete result is
                    // enrolled under the same transaction lock BEFORE material creation.
                    Enroll("lease", lease.ToString()); Enroll("credential", material);
                    Create("lease", lease.ToString()); Create("credential", material);
                    backend.Issue(lease, material, principal, row.Project);
                    leases.Add(Sign(DynamicPermissionJournal.Issuance, window, new DynamicPermissionLease(request,
                        decision.Payload.Header.Event, principal, row.Project, row.Definition, revision, lease, material)));
                    DateTimeOffset now = DateTimeOffset.UtcNow;
                    result = new
                    {
                        dynamicSecret = Definition(definitions[row.Definition]),
                        lease = new
                        {
                            id = lease,
                            dynamicSecretId = row.Definition,
                            version = 1,
                            createdAt = now,
                            updatedAt = now,
                            expireAt = now.AddMinutes(5),
                            externalEntityId = username
                        },
                        data = new { DB_USERNAME = username, DB_PASSWORD = Fault == "lease-bytes" ? password + "-substituted" : password }
                    };
                    break;
            }
        }
        changes.Add(Sign(DynamicPermissionJournal.Resources, window, new DynamicPermissionChange(request, previous, State(row.Definition))));
        return (allowed ? 200 : 403, result);
    }
    private static Policy ParsePolicy(JsonElement permissions, string principal)
    {
        DynamicPermissionContract.Require(permissions.GetArrayLength() == 1);
        var p = permissions[0]; var action = p.GetProperty("action"); var conditions = p.GetProperty("conditions");
        return new(p.GetProperty("subject").GetString()!,
            action.ValueKind == JsonValueKind.Array ? action.EnumerateArray().Select(a => a.GetString()!).ToArray() : [action.GetString()!],
            conditions.GetProperty("environment").GetString()!, conditions.GetProperty("secretPath").GetString()!, principal);
    }
    private static string PolicyHash(Policy p) => p.Actions.Length == 1 ?
        DynamicPermissionContract.Hash(new[] { p.Subject, p.Actions[0], p.Environment, p.Path }) : "partial";
    private DynamicPermissionPolicyState[] PolicyInventory()
    {
        var result = new List<DynamicPermissionPolicyState>();
        if (policy is not null && resources.ContainsKey("project/" + issued!.Project))
            result.Add(new(issued!.PolicyId, policy.Principal, issued.Project, policyRevision, PolicyHash(policy)));
        if (template is not null && (resources.ContainsKey("template/" + issued!.TemplateId) || closed && Fault == "policy-cleanup"))
            result.Add(new(issued!.TemplateId, template.Principal, issued.Project, templateRevision, PolicyHash(template)));
        if (copy is not null) result.Add(new(issued!.CopyProject, copy.Principal, issued.CopyProject, copyRevision, PolicyHash(copy)));
        if (closed && Fault == "policy-cleanup" && policy is not null)
            result.Add(new(issued!.PolicyId, policy.Principal, issued.Project, policyRevision, PolicyHash(policy)));
        return result.OrderBy(p => p.Resource).ToArray();
    }
    private DynamicPermissionState State(Guid id) => definitions.TryGetValue(id, out var value) ? State(value) : new(id, false, 0, "");
    private static DynamicPermissionState State(StoredDefinition value) => new(value.Row.Definition, true, value.Version,
        DynamicPermissionContract.Hash(new { Sql = value.Sql, Ttl = value.Ttl }));
    private static object Definition(StoredDefinition value) => new
    {
        id = value.Row.Definition,
        name = value.Row.Name,
        folderId = value.Row.Folder,
        type = "sql-database",
        defaultTTL = value.Ttl + "s",
        maxTTL = "600s",
        version = value.Version,
        createdAt = "2026-01-01T00:00:00Z",
        updatedAt = "2026-01-01T00:00:00Z"
    };
    internal Task DrainAsync() => Task.WhenAll(connections);
    public async ValueTask DisposeAsync()
    {
        shutdown.Cancel(); listener.Stop();
        try { await accept; } catch (SocketException) when (shutdown.IsCancellationRequested) { }
        await Task.WhenAll(connections);
        Source.Dispose(); backend.Dispose(); foreach (var writer in writers.Values) writer.Dispose();
        shutdown.Dispose();
    }
}
