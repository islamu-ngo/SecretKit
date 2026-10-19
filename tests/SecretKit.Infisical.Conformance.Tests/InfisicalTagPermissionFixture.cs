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
// policy. Authorization/storage never call the effect oracle. Setup-known owned
// coordinates do not confer read. All five host identities authenticate at ingress.
internal sealed class InfisicalTagPermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static TagPermissionAuthorities Authorities { get; } =
        new("20000000-0000-0000-0000-000000000001", "20000000-0000-0000-0000-000000000002",
            "20000000-0000-0000-0000-000000000003", "20000000-0000-0000-0000-000000000004",
            "20000000-0000-0000-0000-000000000005");
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<TagPermissionJournal, TagPermissionWriter> writers = [];
    private readonly Dictionary<string, string> hostTokens = new()
    {
        [Authorities.Setup] = "setup",
        [Authorities.Runtime] = "runtime",
        [Authorities.Denied] = "denied",
        [Authorities.Administrative] = "administrative",
        [Authorities.Observer] = "observer"
    };
    private readonly TagPermissionBorrowed[] borrowed;
    private readonly List<TagPermissionResource> enrolled = [];
    private readonly Dictionary<string, TagPermissionResource> resources = [];
    private readonly Dictionary<Guid, StoredDefinition> definitions = [];
    private readonly List<TagPermissionSigned<TagPermissionIngress>> ingress = [];
    private readonly List<TagPermissionSigned<TagPermissionCommit>> commits = [];
    private readonly List<TagPermissionSigned<TagPermissionDecision>> decisions = [];
    private readonly List<TagPermissionSigned<TagPermissionChange>> changes = [];
    private readonly HashSet<Guid> measured = [];
    private sealed record StoredDefinition(TagPermissionRow Row, TagPermissionValue Value, int Version);
    private sealed record Policy(string Subject, string[] Actions, string Principal);
    private TagPermissionRoot? root;
    private TagPermissionIssued? issued;
    private Policy? policy, template, copy;
    private string revision = "policy-1", window = "";
    private string policyRevision = "policy-1", templateRevision = "policy-1", copyRevision = "";
    private int stage;
    private bool closed, closing, armed, sealedDispatch, assigned, copied;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal TagPermissionProfile Profile { get; }
    internal InfisicalTagPermissionFixtureSource Source { get; }
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    internal int Originals { get; private set; }
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Remaining
    {
        get
        {
            lock (gate) return resources.Count + definitions.Count +
                (policy is null ? 0 : 1) + (template is null ? 0 : 1) + (copy is null ? 0 : 1);
        }
    }
    internal int Registrations => root is not null && !closed ? 1 : 0;
    internal bool BorrowedPreserved => borrowed.SequenceEqual(Borrowed());
    internal InfisicalTagPermissionFixture(string fault = "")
    {
        Fault = fault; borrowed = Borrowed();
        foreach (var journal in Enum.GetValues<TagPermissionJournal>())
            writers.Add(journal, new(journal, journal + "-writer"));
        Profile = new("controlled-tag", "controlled-epoch", "controlled-v1",
            writers.Values.Select(w => w.Pin).ToArray());
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this); accept = AcceptAsync();
    }
    internal TagPermissionInput Input(TagPermissionAction action) =>
        new(new(new("https://tag-source.invalid/"), "coordinator-token", "tag-coordinator", 30),
            "tag-capability", Profile, action, 30);
    internal NativeEnvironment Environment(TagPermissionAction action = TagPermissionAction.Read)
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
                    tagPermission = Input(action)
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
        }, TagPermissionContract.Options));
    }
    internal TagPermissionRoot Root(string operation, TagPermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization,
            operation, TagPermissionContract.Variant(operation, action), boundary, "local", "tag-coordinator",
            TagPermissionSourceKind.ControlledFixture, action, Authorities, Profile);
    private TagPermissionSigned<T> Sign<T>(TagPermissionJournal journal, string selectedWindow, T value) =>
        writers[journal].Sign(root!, selectedWindow, value);
    private TagPermissionBorrowed[] Borrowed() => hostTokens.Select(p =>
        new TagPermissionBorrowed("host-token", p.Key, TagPermissionContract.Hash(p.Value))).ToArray();
    private void Enroll(string kind, string id)
    {
        TagPermissionContract.Require(root is not null && !closed);
        var entry = new TagPermissionResource(kind, id, root!.Id, root.Nonce);
        TagPermissionContract.Require(!enrolled.Any(e => e.Kind == kind && e.Id == id) &&
            !borrowed.Any(e => e.Kind == kind && e.Id == id));
        enrolled.Add(entry);
    }
    private void Create(string kind, string id)
    {
        TagPermissionContract.Require(!closed);
        var entry = enrolled.Single(e => e.Kind == kind && e.Id == id);
        resources.Add(kind + "/" + id, entry);
    }
    private void Reserve(TagPermissionRoot selected)
    {
        TagPermissionContract.Require(root is null && selected.Origin == Origin.AbsoluteUri &&
            selected.Organization == Organization && selected.Authorities == Authorities &&
            TagPermissionContract.Hash(selected.Profile) == TagPermissionContract.Hash(Profile));
        root = selected; // collision failures still retain original-root recovery
        if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
        string project = Guid.NewGuid().ToString(), control = Guid.NewGuid().ToString(), copyProject = Guid.NewGuid().ToString();
        string slug = "tag" + selected.Id, copySlug = "copy" + selected.Id;
        var rows = new List<TagPermissionRow>();

        foreach (string phase in new[] { "before", "after", "copy" })
            foreach (var probe in new[] { (TagPermissionAction.Read, false), (TagPermissionAction.Create, false),
                (TagPermissionAction.Edit, false), (TagPermissionAction.Delete, false), (TagPermissionAction.Read, true) })
                foreach (var principal in new[] { Authorities.Runtime, Authorities.Setup, Authorities.Denied, Authorities.Administrative, Authorities.Observer })
                    foreach (string boundary in principal == Authorities.Runtime ? new[] { "selected", "project" } : ["selected"])
                    {
                        bool outside = boundary == "project", copiedProject = phase == "copy";
                        string selectedProject = outside ? control : copiedProject ? copyProject : project;
                        rows.Add(new("name-" + rows.Count, selectedProject,
                            outside ? "outside" + selected.Id : copiedProject ? copySlug : slug,
                            "slug-" + rows.Count, "#" + (rows.Count + 1).ToString("X6"),
                            Guid.NewGuid(), phase, principal, boundary, probe.Item1, probe.Item2));
                    }
        issued = new(project, slug, control, copyProject, copySlug, Guid.NewGuid().ToString(), "role" + selected.Id,
            Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), revision, rows.ToArray());
        foreach (string id in new[] { project, control, copyProject }) Enroll("project", id);
        foreach (var row in rows) Enroll("tag", row.Id.ToString());
        Enroll("policy", issued.PolicyId); Enroll("template", issued.TemplateId);
        Enroll("membership", issued.Membership); Enroll("dispatch-work", selected.Id); Enroll("issuer-work", selected.Id);
        // Complete plan, including future copying and issuer work, precedes Open.
        if (!selected.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal))
        {
            string baseline = (((int)selected.Action + 1) % 4) switch
            {
                0 => "read",
                1 => "create",
                2 => "edit",
                3 => "delete",
                _ => "delete"
            };
            policy = new("tags", [baseline], Authorities.Runtime);
            if (selected.Operation.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal)) template = policy;
        }
        assigned = !selected.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal);
    }
    internal TagPermissionPacket Step(TagPermissionRoot selected, TagPermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == TagPermissionStep.Reserve)
            {
                TagPermissionContract.Require(capability == "tag-capability");
                Reserve(selected);
            }
            TagPermissionContract.Require(root is not null && TagPermissionContract.Hash(root) == TagPermissionContract.Hash(selected) &&
                !closed && (step == TagPermissionStep.Close || stage == (int)step));
            if (step != TagPermissionStep.Close) stage++;
            switch (step)
            {
                case TagPermissionStep.Open:
                    Opens++;
                    foreach (var entry in enrolled.Where(e => e.Kind != "tag" &&
                        (e.Kind != "policy" || policy is not null) && (e.Kind != "template" || template is not null) &&
                        e.Id != issued!.CopyProject))
                    {
                        Create(entry.Kind, entry.Id);
                        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
                    }
                    foreach (var row in issued!.Rows.Where(r => r.Window != "copy" || r.Control == "project"))
                        Bootstrap(row);
                    if (Fault == "lost-open") throw new NativeCaseFailureException("observer-unavailable");
                    break;
                case TagPermissionStep.Before: window = "before"; ClearActions(); break;
                case TagPermissionStep.After: window = "after"; ClearActions(); break;
                case TagPermissionStep.Arm: window = ""; armed = true; break;
                case TagPermissionStep.Settle: sealedDispatch = true; break;
                case TagPermissionStep.ObserveBefore:
                case TagPermissionStep.ObserveAfter: window = ""; break;
                case TagPermissionStep.Close:
                    Closes++; closed = closing = sealedDispatch = true; armed = false; window = "";
                    foreach (var entry in resources.Values.ToArray())
                        if (Fault != "cleanup" || entry.Kind != "tag") resources.Remove(entry.Kind + "/" + entry.Id);
                    if (Fault != "cleanup") definitions.Clear();
                    if (Fault == "borrowed-change") hostTokens[Authorities.Runtime] = "changed";
                    if (Fault != "policy-cleanup") policy = template = copy = null;
                    break;
            }
            bool observe = step is TagPermissionStep.ObserveBefore or TagPermissionStep.ObserveAfter;
            string selectedWindow = step == TagPermissionStep.Settle ? "original" : "after";
            var owner = new TagPermissionOwner(step, true, true, true,
                step is TagPermissionStep.Settle or TagPermissionStep.Close, 0, closed ? 0 : 1,
                step == TagPermissionStep.Open ? issued : null, enrolled.ToArray(), resources.Values.ToArray(), Borrowed());
            var packet = new TagPermissionPacket(Sign(TagPermissionJournal.Ownership, step.ToString(), owner),
                observe ? ingress.Where(i => i.Payload.Header.Window == (step == TagPermissionStep.ObserveBefore ? "before" : "after")).ToArray() :
                    step == TagPermissionStep.Settle ? ingress.Where(i => i.Payload.Header.Window == "original").ToArray() : [],
                step is TagPermissionStep.Settle or TagPermissionStep.ObserveAfter ?
                    commits.Where(c => c.Payload.Header.Window == selectedWindow).ToArray() : [],
                observe ? decisions.ToArray() : [], observe ? changes.ToArray() : [],
                Sign(TagPermissionJournal.Policy, step.ToString(), PolicyInventory()),
                Sign(TagPermissionJournal.Resources, step.ToString(), Inventory(step)),
                []);
            return packet with
            {
                Seals = new[] { TagPermissionJournal.Ingress, TagPermissionJournal.Policy,
                    TagPermissionJournal.Resources, TagPermissionJournal.Issuance }.Select(j =>
                {
                    var content = TagPermissionContract.Contents(packet, j);
                    return Sign(j, step.ToString(), new TagPermissionSeal(content.Hash, content.Headers.Length, true, 0));
                }).ToArray()
            };
        }
    }
    private void Bootstrap(TagPermissionRow row)
    {
        if (row.Action == TagPermissionAction.Create) return;
        Create("tag", row.Id.ToString());
        definitions.Add(row.Id, new(row, new(row.Id, row.Project, row.Name, row.TagSlug, row.Color), 1));
    }
    private TagPermissionState[] Inventory(TagPermissionStep step)
    {
        var rows = definitions.Values.Select(State).OrderBy(s => s.Tag).ToArray();
        if (step != TagPermissionStep.Open) return rows;
        return Fault switch
        {
            "missing-inventory" => rows.Skip(1).ToArray(),
            "duplicate-inventory" => rows.Concat(rows.Take(1)).ToArray(),
            _ => rows
        };
    }
    private void ClearActions() { decisions.Clear(); changes.Clear(); measured.Clear(); }
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
                TagPermissionContract.Require(length is >= 0 and <= 131072);
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
        if (uri.AbsolutePath.StartsWith("/api/v1/projects/", StringComparison.Ordinal) &&
            uri.AbsolutePath.Contains("/tags", StringComparison.Ordinal))
            return Tags(method, uri, principal, bearer, body, bytes);
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
                TagPermissionContract.RawHash(intent), null, false, true, "after");
            }
            finally { CryptographicOperations.ZeroMemory(intent); }
            commits.Add(Sign(TagPermissionJournal.Policy, "after", new TagPermissionCommit(request, issued.Membership,
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
        string requestId = Guid.NewGuid().ToString("N"), intentHash = TagPermissionContract.RawHash(bytes);
        if (!role && !isTemplate)
        {
            byte[] intent = JsonSerializer.SerializeToUtf8Bytes(new object?[]
                { issued.Slug, issued.Membership, create ? null : issued.PolicyId, body });
            try { intentHash = TagPermissionContract.RawHash(intent); }
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
            commits.Add(Sign(TagPermissionJournal.Policy, "original", new TagPermissionCommit(requestId,
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
        Ingress(request, principal, bearer, "POST", "/api/v1/projects", bytes, TagPermissionContract.RawHash(bytes),
            null, false, true, "after");
        commits.Add(Sign(TagPermissionJournal.Policy, "after", new TagPermissionCommit(request, issued.CopyProject,
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
        string intent, Guid? tag, bool bootstrap, bool allowed, string selectedWindow) =>
        ingress.Add(Sign(TagPermissionJournal.Ingress, selectedWindow, new TagPermissionIngress(request,
            principal, TagPermissionContract.Hash(bearer), method, path, TagPermissionContract.RawHash(body),
            intent, tag, bootstrap, allowed)));
    private (int, object) Tags(string method, Uri uri, string principal, string bearer, JsonElement body, byte[] bytes)
    {
        if (window is not ("before" or "after") || principal == "unknown") return (403, new { });
        string[] segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length is not (5 or 6) || segments[4] != "tags") return (404, new { });
        string project = segments[3]; bool list = method == "GET" && segments.Length == 5;
        string selectedWindow = window == "after" && copied ? "copy" : window;
        TagPermissionRow? row = list ? issued!.Rows.SingleOrDefault(r => r.List && r.Principal == principal &&
            r.Project == project && r.Window == selectedWindow) : method == "POST" ?
            issued!.Rows.SingleOrDefault(r => r.Project == project && r.TagSlug == body.GetProperty("slug").GetString()) :
            issued!.Rows.SingleOrDefault(r => r.Id.ToString() == segments.Last() && r.Project == project);
        if (row is null || !resources.ContainsKey("project/" + project)) return (404, new { });
        var action = method switch
        {
            "GET" => TagPermissionAction.Read,
            "PATCH" => TagPermissionAction.Edit,
            "DELETE" => TagPermissionAction.Delete,
            _ => TagPermissionAction.Create
        };
        if (!measured.Add(row.Id) || row.Action != action || row.List != list || row.Principal != principal ||
            row.Window != selectedWindow) return (409, new { });
        var effective = project == issued!.CopyProject ? copy : policy;
        string wire = method switch { "GET" => "read", "POST" => "create", "PATCH" => "edit", _ => "delete" };
        bool allowed = principal == Authorities.Setup || principal == Authorities.Observer || effective is not null &&
            principal == effective.Principal && assigned && (project == issued.Project || project == issued.CopyProject) &&
            effective.Subject == "tags" && effective.Actions.Contains(wire);
        if (Fault == "action-leak" && revision == "policy-2" && principal == Authorities.Runtime) allowed = true;
        if (Fault == "scope-leak" && revision == "policy-2" && principal == Authorities.Runtime &&
            (copy ?? policy ?? template)?.Actions.Contains(wire) == true) allowed = true;
        string actor = Fault == "wrong-principal" && allowed && principal == Authorities.Runtime ? Authorities.Observer : principal;
        string request = Guid.NewGuid().ToString("N");
        Ingress(request, actor, bearer, method, uri.AbsolutePath, bytes, "", row.Id, false, allowed, window);
        decisions.Add(Sign(TagPermissionJournal.Policy, window, new TagPermissionDecision(request, actor,
            TagPermissionContract.Hash(bearer), project, row.Id, revision, action, allowed)));
        var previous = State(row.Id); object result = new { };
        if (allowed)
        {
            switch (action)
            {
                case TagPermissionAction.Read:
                    if (list)
                    {
                        object[] items = definitions.Values.Where(v => v.Row.Project == project).Select(Tag).ToArray();
                        if (Fault == "incomplete-list") items = items.Skip(1).ToArray();
                        if (Fault == "duplicate-list") items = items.Concat(items.Take(1)).ToArray();
                        if (Fault == "substituted-list") items = items.Select((v, i) => i == 0 ? items[1] : v).ToArray();
                        result = new { tags = items };
                    }
                    else result = new { tag = Tag(definitions[row.Id]) };
                    break;
                case TagPermissionAction.Create:
                    Create("tag", row.Id.ToString());
                    definitions.Add(row.Id, new(row, new(row.Id, project, row.Name,
                        body.GetProperty("slug").GetString()!, body.GetProperty("color").GetString()!), 1));
                    result = new { tag = Tag(definitions[row.Id]) }; break;
                case TagPermissionAction.Edit:
                    var old = definitions[row.Id];
                    definitions[row.Id] = old with
                    {
                        Value = old.Value with { Slug = body.GetProperty("slug").GetString()!, Color = body.GetProperty("color").GetString()! },
                        Version = old.Version + 1
                    };
                    result = new { tag = Tag(definitions[row.Id]) }; break;
                case TagPermissionAction.Delete:
                    result = new { tag = Tag(definitions[row.Id]) };
                    definitions.Remove(row.Id); resources.Remove("tag/" + row.Id); break;
            }
            if (Fault == "wrong-tag" && !list) result = new { tag = Tag(definitions.Values.First(v => v.Row.Id != row.Id)) };
            if (Fault == "missing-name" && !list)
                result = new
                {
                    tag = new
                    {
                        id = row.Id,
                        projectId = project,
                        slug = row.TagSlug,
                        color = row.Color,
                        createdAt = "2026-01-01T00:00:00Z",
                        updatedAt = "2026-01-01T00:00:00Z"
                    }
                };
        }
        changes.Add(Sign(TagPermissionJournal.Resources, window, new TagPermissionChange(request, previous, State(row.Id))));
        return (allowed ? 200 : 403, result);
    }
    private static Policy ParsePolicy(JsonElement permissions, string principal)
    {
        TagPermissionContract.Require(permissions.GetArrayLength() == 1);
        var p = permissions[0]; var action = p.GetProperty("action");
        TagPermissionContract.Require(!p.TryGetProperty("conditions", out _) && !p.TryGetProperty("inverted", out _));
        return new(p.GetProperty("subject").GetString()!,
            action.ValueKind == JsonValueKind.Array ? action.EnumerateArray().Select(a => a.GetString()!).ToArray() : [action.GetString()!],
            principal);
    }
    private static string PolicyHash(Policy p) => p.Actions.Length == 1 ?
        TagPermissionContract.Hash(new[] { p.Subject, p.Actions[0] }) : "partial";
    private TagPermissionPolicyState[] PolicyInventory()
    {
        var result = new List<TagPermissionPolicyState>();
        if (policy is not null && resources.ContainsKey("project/" + issued!.Project))
            result.Add(new(issued!.PolicyId, policy.Principal, issued.Project, policyRevision, PolicyHash(policy)));
        if (template is not null && (resources.ContainsKey("template/" + issued!.TemplateId) || closed && Fault == "policy-cleanup"))
            result.Add(new(issued!.TemplateId, template.Principal, issued.Project, templateRevision, PolicyHash(template)));
        if (copy is not null) result.Add(new(issued!.CopyProject, copy.Principal, issued.CopyProject, copyRevision, PolicyHash(copy)));
        if (closed && Fault == "policy-cleanup" && policy is not null)
            result.Add(new(issued!.PolicyId, policy.Principal, issued.Project, policyRevision, PolicyHash(policy)));
        return result.OrderBy(p => p.Resource).ToArray();
    }
    private TagPermissionState State(Guid id) => definitions.TryGetValue(id, out var value) ? State(value) : new(id, false, 0, null);
    private static TagPermissionState State(StoredDefinition value) => new(value.Row.Id, true, value.Version, value.Value);
    private static object Tag(StoredDefinition value) => new
    {
        id = value.Value.Id,
        projectId = value.Value.Project,
        name = value.Value.Name,
        slug = value.Value.Slug,
        color = value.Value.Color,
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
        Source.Dispose(); foreach (var writer in writers.Values) writer.Dispose();
        shutdown.Dispose();
    }
}
