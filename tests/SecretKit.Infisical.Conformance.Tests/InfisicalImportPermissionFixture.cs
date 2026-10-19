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
internal sealed class InfisicalImportPermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static ImportPermissionAuthorities Authorities { get; } =
        new("20000000-0000-0000-0000-000000000001", "20000000-0000-0000-0000-000000000002",
            "20000000-0000-0000-0000-000000000003", "20000000-0000-0000-0000-000000000004",
            "20000000-0000-0000-0000-000000000005");
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<ImportPermissionJournal, ImportPermissionWriter> writers = [];
    private readonly Dictionary<string, string> hostTokens = new()
    {
        [Authorities.Setup] = "setup",
        [Authorities.Runtime] = "runtime",
        [Authorities.Denied] = "denied",
        [Authorities.Administrative] = "administrative",
        [Authorities.Observer] = "observer"
    };
    private readonly ImportPermissionBorrowed[] borrowed;
    private readonly Dictionary<Guid, ImportPermissionValue> borrowedImports = [];
    private readonly Dictionary<Guid, byte[]> borrowedSources = [];
    private readonly Dictionary<Guid, ImportPermissionReceiver> borrowedReceivers = [];
    private readonly List<ImportPermissionResource> enrolled = [];
    private readonly Dictionary<string, ImportPermissionResource> resources = [];
    private readonly Dictionary<Guid, StoredDefinition> definitions = [];
    private readonly Dictionary<string, byte[]> sourceMaterial = [];
    private readonly List<ImportPermissionSourceState> sources = [];
    private readonly List<ImportPermissionReceiver> receivers = [];
    private readonly List<ImportPermissionSigned<ImportPermissionIngress>> ingress = [];
    private readonly List<ImportPermissionSigned<ImportPermissionCommit>> commits = [];
    private readonly List<ImportPermissionSigned<ImportPermissionDecision>> decisions = [];
    private readonly List<ImportPermissionSigned<ImportPermissionChange>> changes = [];
    private readonly HashSet<Guid> measured = [];
    private sealed record StoredDefinition(ImportPermissionRow Row, ImportPermissionValue Value, int Version);
    private sealed record Policy(string Subject, string[] Actions, string Environment, string Path, string Principal);
    private ImportPermissionRoot? root;
    private ImportPermissionIssued? issued;
    private Policy? policy, template, copy;
    private string revision = "policy-1", window = "";
    private string policyRevision = "policy-1", templateRevision = "policy-1", copyRevision = "";
    private int stage;
    private bool closed, closing, armed, sealedDispatch, assigned, copied;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal ImportPermissionProfile Profile { get; }
    internal InfisicalImportPermissionFixtureSource Source { get; }
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    internal int Originals { get; private set; }
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Remaining
    {
        get
        {
            lock (gate) return resources.Count + definitions.Count + sourceMaterial.Count + receivers.Count +
                (policy is null ? 0 : 1) + (template is null ? 0 : 1) + (copy is null ? 0 : 1);
        }
    }
    internal int Registrations => root is not null && !closed ? 1 : 0;
    internal bool BorrowedPreserved => borrowed.SequenceEqual(Borrowed());
    internal InfisicalImportPermissionFixture(string fault = "")
    {
        Fault = fault;
        var borrowedId = Guid.NewGuid(); var borrowedFolder = Guid.NewGuid(); var borrowedSource = Guid.NewGuid();
        borrowedImports.Add(borrowedId, new(borrowedId, borrowedFolder, "borrowed", "/borrowed", Organization,
            99, false, false, "idle", null));
        borrowedReceivers.Add(borrowedFolder, new(borrowedFolder, Organization, "borrowed", "/borrowed"));
        borrowedSources.Add(borrowedSource, Encoding.UTF8.GetBytes("host-owned-borrowed-source"));
        borrowed = Borrowed();
        foreach (var journal in Enum.GetValues<ImportPermissionJournal>())
            writers.Add(journal, new(journal, journal + "-writer"));
        Profile = new("controlled-import", "controlled-epoch", "controlled-v1",
            writers.Values.Select(w => w.Pin).ToArray());
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this); accept = AcceptAsync();
    }
    internal ImportPermissionInput Input(ImportPermissionAction action) =>
        new(new(new("https://import-source.invalid/"), "coordinator-token", "import-coordinator", 30),
            "import-capability", Profile, action, 30);
    internal NativeEnvironment Environment(ImportPermissionAction action = ImportPermissionAction.Read)
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
                    importPermission = Input(action)
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
        }, ImportPermissionContract.Options));
    }
    internal ImportPermissionRoot Root(string operation, ImportPermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization,
            operation, ImportPermissionContract.Variant(operation, action), boundary, "local", "import-coordinator",
            ImportPermissionSourceKind.ControlledFixture, action, Authorities, Profile);
    private ImportPermissionSigned<T> Sign<T>(ImportPermissionJournal journal, string selectedWindow, T value) =>
        writers[journal].Sign(root!, selectedWindow, value);
    private ImportPermissionBorrowed[] Borrowed() => hostTokens.Select(p =>
        new ImportPermissionBorrowed("host-token", p.Key, ImportPermissionContract.Hash(p.Value)))
        .Concat(borrowedImports.Select(p => new ImportPermissionBorrowed("import", p.Key.ToString(), ImportPermissionContract.Hash(p.Value))))
        .Concat(borrowedSources.Select(p => new ImportPermissionBorrowed("source", p.Key.ToString(), ImportPermissionContract.RawHash(p.Value))))
        .Concat(borrowedReceivers.Select(p => new ImportPermissionBorrowed("receiver", p.Key.ToString(), ImportPermissionContract.Hash(p.Value))))
        .ToArray();
    private void Enroll(string kind, string id)
    {
        ImportPermissionContract.Require(root is not null && !closed);
        var entry = new ImportPermissionResource(kind, id, root!.Id, root.Nonce);
        ImportPermissionContract.Require(!enrolled.Any(e => e.Kind == kind && e.Id == id) &&
            !borrowed.Any(e => e.Kind == kind && e.Id == id));
        enrolled.Add(entry);
    }
    private void Create(string kind, string id)
    {
        ImportPermissionContract.Require(!closed);
        var entry = enrolled.Single(e => e.Kind == kind && e.Id == id);
        resources.Add(kind + "/" + id, entry);
    }
    private void Reserve(ImportPermissionRoot selected)
    {
        ImportPermissionContract.Require(root is null && selected.Origin == Origin.AbsoluteUri &&
            selected.Organization == Organization && selected.Authorities == Authorities &&
            ImportPermissionContract.Hash(selected.Profile) == ImportPermissionContract.Hash(Profile));
        root = selected; // collision failures still retain original-root recovery
        if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
        string project = Guid.NewGuid().ToString(), control = Guid.NewGuid().ToString(), copyProject = Guid.NewGuid().ToString();
        string slug = "folder" + selected.Id, copySlug = "copy" + selected.Id;
        var rows = new List<ImportPermissionRow>();
        var environments = new Dictionary<string, Guid>();
        var folders = new Dictionary<string, Guid>();
        foreach (string phase in new[] { "before", "after", "copy" })
            foreach (var probe in new[] { (ImportPermissionAction.Read, false), (ImportPermissionAction.Create, false),
                (ImportPermissionAction.Edit, false), (ImportPermissionAction.Delete, false), (ImportPermissionAction.Read, true) })
                foreach (var principal in new[] { Authorities.Runtime, Authorities.Setup, Authorities.Denied, Authorities.Administrative, Authorities.Observer })
                    foreach (string boundary in principal == Authorities.Runtime ? new[] { "selected", "project", "environment", "path" } : ["selected"])
                    {
                        bool outside = boundary == "project", copiedProject = phase == "copy";
                        string selectedProject = outside ? control : copiedProject ? copyProject : project;
                        string selectedEnvironment = boundary == "environment" ? "outside" : "witness";
                        string key = selectedProject + "/" + selectedEnvironment;
                        if (!environments.TryGetValue(key, out var envId)) environments.Add(key, envId = Guid.NewGuid());
                        string receiverKey = key + (boundary == "path" ? "/outside" : "/");
                        if (!folders.TryGetValue(receiverKey, out var folderId)) folders.Add(receiverKey, folderId = Guid.NewGuid());
                        rows.Add(new("i" + rows.Count, selectedProject,
                            outside ? "outside" + selected.Id : copiedProject ? copySlug : slug,
                            boundary == "environment" ? "outside" : "witness", boundary == "path" ? "/outside" : "/",
                            envId, Guid.NewGuid(), phase, principal, boundary, probe.Item1, probe.Item2, folderId,
                            Guid.NewGuid(), Guid.NewGuid()));
                    }
        issued = new(project, slug, control, copyProject, copySlug, Guid.NewGuid().ToString(), "role" + selected.Id,
            Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), revision, rows.ToArray());
        foreach (string id in new[] { project, control, copyProject }) Enroll("project", id);
        foreach (var row in rows)
        {
            Enroll("import", row.Id.ToString());
            Enroll("source", row.Id + ":a"); Enroll("source", row.Id + ":b");
            Enroll("source-folder", row.SourceFolderId.ToString()); Enroll("source-folder", row.ChangedSourceFolderId.ToString());
        }
        foreach (var folder in folders.Values) Enroll("receiver", folder.ToString());
        foreach (string principal in Authorities.All) Enroll("credential-use", principal);
        foreach (var envId in environments.Values) Enroll("environment", envId.ToString());
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
            policy = new("secret-imports", [baseline], "witness", "/", Authorities.Runtime);
            if (selected.Operation.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal)) template = policy;
        }
        assigned = !selected.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal);
    }
    internal ImportPermissionPacket Step(ImportPermissionRoot selected, ImportPermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == ImportPermissionStep.Reserve)
            {
                ImportPermissionContract.Require(capability == "import-capability");
                Reserve(selected);
            }
            ImportPermissionContract.Require(root is not null && ImportPermissionContract.Hash(root) == ImportPermissionContract.Hash(selected) &&
                !closed && (step == ImportPermissionStep.Close || stage == (int)step));
            if (step != ImportPermissionStep.Close) stage++;
            switch (step)
            {
                case ImportPermissionStep.Open:
                    Opens++;
                    foreach (var entry in enrolled.Where(e => e.Kind is not ("import" or "source" or "source-folder" or "receiver") &&
                        (e.Kind != "policy" || policy is not null) && (e.Kind != "template" || template is not null) &&
                        e.Id != issued!.CopyProject))
                    {
                        Create(entry.Kind, entry.Id);
                        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
                    }
                    foreach (var row in issued!.Rows)
                    {
                        if (!receivers.Any(r => r.FolderId == row.FolderId))
                        {
                            Create("receiver", row.FolderId.ToString());
                            receivers.Add(new(row.FolderId, row.Project, row.Environment, row.Path));
                        }
                        foreach (bool changed in new[] { false, true })
                        {
                            Create("source", row.Id + (changed ? ":b" : ":a"));
                            Create("source-folder", (changed ? row.ChangedSourceFolderId : row.SourceFolderId).ToString());
                            byte[] material = Encoding.UTF8.GetBytes(root!.Nonce + ":" + row.Id + ":" + (changed ? "source-b" : "source-a"));
                            Copies.Add(material);
                            sourceMaterial.Add(ImportPermissionContract.SourcePath(row, changed), material);
                            sources.Add(new(changed ? row.ChangedSourceFolderId : row.SourceFolderId, row.Project,
                                changed ? "source-b" : "source-a", ImportPermissionContract.SourcePath(row, changed),
                                "IMPORTED", ImportPermissionContract.RawHash(material), root!.Id, root.Nonce));
                        }
                        if (row.Window != "copy" || row.Control == "project") Bootstrap(row);
                    }
                    if (Fault == "lost-open") throw new NativeCaseFailureException("observer-unavailable");
                    break;
                case ImportPermissionStep.Before: window = "before"; ClearActions(); break;
                case ImportPermissionStep.After: window = "after"; ClearActions(); break;
                case ImportPermissionStep.Arm: window = ""; armed = true; break;
                case ImportPermissionStep.Settle: sealedDispatch = true; break;
                case ImportPermissionStep.ObserveBefore:
                case ImportPermissionStep.ObserveAfter: window = ""; break;
                case ImportPermissionStep.Close:
                    Closes++; closed = closing = sealedDispatch = true; armed = false; window = "";
                    foreach (var entry in resources.Values.ToArray())
                        if (Fault != "cleanup" || entry.Kind != "import") resources.Remove(entry.Kind + "/" + entry.Id);
                    if (Fault != "cleanup") definitions.Clear();
                    foreach (var material in sourceMaterial.Values) CryptographicOperations.ZeroMemory(material);
                    if (Fault != "source-cleanup") { sourceMaterial.Clear(); sources.Clear(); }
                    if (Fault != "receiver-cleanup") receivers.Clear();
                    if (Fault == "borrowed-change") hostTokens[Authorities.Runtime] = "changed";
                    if (Fault != "policy-cleanup") policy = template = copy = null;
                    break;
            }
            bool observe = step is ImportPermissionStep.ObserveBefore or ImportPermissionStep.ObserveAfter;
            string selectedWindow = step == ImportPermissionStep.Settle ? "original" : "after";
            var owner = new ImportPermissionOwner(step, true, true, true,
                step is ImportPermissionStep.Settle or ImportPermissionStep.Close, 0, closed ? 0 : 1,
                step == ImportPermissionStep.Open ? issued : null, enrolled.ToArray(), resources.Values.ToArray(), Borrowed());
            var packet = new ImportPermissionPacket(Sign(ImportPermissionJournal.Ownership, step.ToString(), owner),
                observe ? ingress.Where(i => i.Payload.Header.Window == (step == ImportPermissionStep.ObserveBefore ? "before" : "after")).ToArray() :
                    step == ImportPermissionStep.Settle ? ingress.Where(i => i.Payload.Header.Window == "original").ToArray() : [],
                step is ImportPermissionStep.Settle or ImportPermissionStep.ObserveAfter ?
                    commits.Where(c => c.Payload.Header.Window == selectedWindow).ToArray() : [],
                observe ? decisions.ToArray() : [], observe ? changes.ToArray() : [],
                Sign(ImportPermissionJournal.Policy, step.ToString(), PolicyInventory()),
                Sign(ImportPermissionJournal.Resources, step.ToString(), definitions.Values.Select(State).OrderBy(s => s.Folder).ToArray()),
                Sign(ImportPermissionJournal.Resources, step.ToString(), Fault == "incomplete-source-inventory" && step == ImportPermissionStep.Open ?
                    sources.Skip(1).OrderBy(s => s.Path).ToArray() : Fault == "duplicate-source-inventory" && step == ImportPermissionStep.Open ?
                    sources.Concat(sources.Take(1)).OrderBy(s => s.Path).ToArray() : sources.OrderBy(s => s.Path).ToArray()),
                Sign(ImportPermissionJournal.Resources, step.ToString(), receivers.OrderBy(r => r.FolderId).ToArray()),
                []);
            return packet with
            {
                Seals = new[] { ImportPermissionJournal.Ingress, ImportPermissionJournal.Policy,
                    ImportPermissionJournal.Resources, ImportPermissionJournal.Issuance }.Select(j =>
                {
                    var content = ImportPermissionContract.Contents(packet, j);
                    return Sign(j, step.ToString(), new ImportPermissionSeal(content.Hash, content.Headers.Length, true, 0));
                }).ToArray()
            };
        }
    }
    private void Bootstrap(ImportPermissionRow row)
    {
        if (row.Action == ImportPermissionAction.Create) return;
        Create("import", row.Id.ToString());
        definitions.Add(row.Id, new(row, new(row.Id, row.FolderId, "source-a", ImportPermissionContract.SourcePath(row, false),
            row.Project, 1, false, false, "idle", null), 1));
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
                ImportPermissionContract.Require(length is >= 0 and <= 131072);
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
        if (method == "GET" && uri.AbsolutePath == "/api/v4/secrets/IMPORTED") return DeliveredSecret(principal, uri);
        if (uri.AbsolutePath == "/api/v2/secret-imports/secrets") return ImportedSecrets(principal, uri);
        if (uri.AbsolutePath.StartsWith("/api/v2/secret-imports", StringComparison.Ordinal))
            return Imports(method, uri, principal, bearer, body, bytes);
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
                ImportPermissionContract.RawHash(intent), null, false, true, "after");
            }
            finally { CryptographicOperations.ZeroMemory(intent); }
            commits.Add(Sign(ImportPermissionJournal.Policy, "after", new ImportPermissionCommit(request, issued.Membership,
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
        string requestId = Guid.NewGuid().ToString("N"), intentHash = ImportPermissionContract.RawHash(bytes);
        if (!role && !isTemplate)
        {
            byte[] intent = JsonSerializer.SerializeToUtf8Bytes(new object?[]
                { issued.Slug, issued.Membership, create ? null : issued.PolicyId, body });
            try { intentHash = ImportPermissionContract.RawHash(intent); }
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
            commits.Add(Sign(ImportPermissionJournal.Policy, "original", new ImportPermissionCommit(requestId,
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
        Ingress(request, principal, bearer, "POST", "/api/v1/projects", bytes, ImportPermissionContract.RawHash(bytes),
            null, false, true, "after");
        commits.Add(Sign(ImportPermissionJournal.Policy, "after", new ImportPermissionCommit(request, issued.CopyProject,
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
        string intent, Guid? folder, bool bootstrap, bool allowed, string selectedWindow) =>
        ingress.Add(Sign(ImportPermissionJournal.Ingress, selectedWindow, new ImportPermissionIngress(request,
            principal, ImportPermissionContract.Hash(bearer), method, path, ImportPermissionContract.RawHash(body),
            intent, folder, bootstrap, allowed)));
    private (int, object) Imports(string method, Uri uri, string principal, string bearer, JsonElement body, byte[] bytes)
    {
        if (window is not ("before" or "after") || principal == "unknown") return (403, new { });
        bool list = method == "GET" && uri.AbsolutePath == "/api/v2/secret-imports";
        ImportPermissionRow? row;
        if (list)
        {
            var query = Query(uri);
            row = issued!.Rows.SingleOrDefault(r => r.List && r.Principal == principal &&
                r.Project == query["projectId"] && r.Environment == query["environment"] && r.Path == query["path"] &&
                r.Window == (window == "after" && copied ? "copy" : window));
        }
        else if (method == "POST")
            row = issued!.Rows.SingleOrDefault(r => ImportPermissionContract.SourcePath(r, true) == body.GetProperty("import").GetProperty("path").GetString() &&
                r.Project == body.GetProperty("projectId").GetString() && r.Environment == body.GetProperty("environment").GetString() &&
                r.Path == body.GetProperty("path").GetString());
        else row = issued!.Rows.SingleOrDefault(r => r.Id.ToString() == Uri.UnescapeDataString(uri.Segments.Last()));
        if (row is null || !resources.ContainsKey("environment/" + row.EnvironmentId) ||
            !resources.ContainsKey("project/" + row.Project) || !receivers.Any(r => r.FolderId == row.FolderId)) return (404, new { });
        if (method is "PATCH" or "DELETE" && (body.GetProperty("projectId").GetString() != row.Project ||
            body.GetProperty("environment").GetString() != row.Environment || body.GetProperty("path").GetString() != row.Path)) return (403, new { });
        var action = method switch
        {
            "GET" => ImportPermissionAction.Read,
            "PATCH" => ImportPermissionAction.Edit,
            "DELETE" => ImportPermissionAction.Delete,
            _ => ImportPermissionAction.Create
        };
        if (!measured.Add(row.Id) || row.Action != action || row.List != list) return (409, new { });
        var effective = row.Project == issued!.CopyProject ? copy : policy;
        string wire = method switch { "GET" => "read", "POST" => "create", "PATCH" => "edit", _ => "delete" };
        bool allowed = principal == Authorities.Setup || principal == Authorities.Observer || effective is not null && principal == effective.Principal &&
            assigned && (row.Project == issued.Project || row.Project == issued.CopyProject) && effective.Subject == "secret-imports" &&
            effective.Environment == row.Environment && effective.Path == row.Path && effective.Actions.Contains(wire);
        if (Fault == "action-leak" && revision == "policy-2" && principal == Authorities.Runtime) allowed = true;
        if (Fault == "scope-leak" && revision == "policy-2" && principal == Authorities.Runtime && effective is not null && effective.Actions.Contains(wire)) allowed = true;
        string actor = Fault == "wrong-principal" && allowed && principal == Authorities.Runtime ? Authorities.Observer : principal;
        string request = Guid.NewGuid().ToString("N");
        Ingress(request, actor, bearer, method, uri.AbsolutePath, bytes, "", row.Id, false, allowed, window);
        decisions.Add(Sign(ImportPermissionJournal.Policy, window, new ImportPermissionDecision(request, actor,
            ImportPermissionContract.Hash(bearer), row.Project, row.Id, revision, action, allowed)));
        var previous = State(row.Id); object result = new { };
        if (allowed)
        {
            switch (action)
            {
                case ImportPermissionAction.Read:
                    if (list)
                    {
                        object[] items = definitions.Values.Where(v => v.Row.Project == row.Project && v.Row.Environment == row.Environment && v.Row.Path == row.Path).Select(Import).ToArray();
                        if (Fault == "incomplete-list") items = items.Skip(1).ToArray();
                        if (Fault == "duplicate-list") items = items.Concat(items.Take(1)).ToArray();
                        result = new { secretImports = items };
                    }
                    else result = new { secretImport = Import(definitions[row.Id]) };
                    break;
                case ImportPermissionAction.Create:
                    var incoming = body.GetProperty("import");
                    string environment = incoming.GetProperty("environment").GetString()!, path = incoming.GetProperty("path").GetString()!;
                    string project = incoming.GetProperty("sourceProjectId").GetString()!;
                    if (!sources.Any(s => s.Project == project && s.Environment == environment && s.Path == path)) return (404, new { });
                    Create("import", row.Id.ToString());
                    definitions.Add(row.Id, new(row, new(row.Id, row.FolderId, environment, path, project, 1,
                        body.GetProperty("isReplication").GetBoolean(), false, "idle", null), 1));
                    result = new { secretImport = Import(definitions[row.Id]) }; break;
                case ImportPermissionAction.Edit:
                    var old = definitions[row.Id]; var patch = body.GetProperty("import");
                    var next = old.Value with
                    {
                        SourceEnvironment = patch.GetProperty("environment").GetString()!,
                        SourcePath = patch.GetProperty("path").GetString()!,
                        Position = patch.GetProperty("position").GetDouble()
                    };
                    if (Fault == "ignored-linkage") next = old.Value;
                    if (Fault == "ignored-source") next = next with { SourcePath = old.Value.SourcePath };
                    if (Fault == "ignored-environment") next = next with { SourceEnvironment = old.Value.SourceEnvironment };
                    definitions[row.Id] = old with { Value = next, Version = old.Version + 1 };
                    result = new { secretImport = Import(definitions[row.Id]) }; break;
                case ImportPermissionAction.Delete:
                    result = new { secretImport = Import(definitions[row.Id]) };
                    definitions.Remove(row.Id); resources.Remove("import/" + row.Id); break;
            }
            if (Fault == "wrong-linkage" && !list)
                result = new { secretImport = Import(definitions.Values.First(v => v.Row.Id != row.Id)) };
        }
        changes.Add(Sign(ImportPermissionJournal.Resources, window, new ImportPermissionChange(request, previous, State(row.Id))));
        return (allowed ? 200 : 403, result);
    }
    private static Dictionary<string, string> Query(Uri uri) => uri.Query.TrimStart('?').Split('&')
        .Select(s => s.Split('=', 2)).ToDictionary(s => s[0], s => Uri.UnescapeDataString(s[1]));
    // Independent source store, never an effect-produced value. Secret-read admission
    // under setup/observer is a controlled prerequisite, UNQUALIFIED natively.
    private (int, object) ImportedSecrets(string principal, Uri uri)
    {
        if (principal != Authorities.Setup && principal != Authorities.Observer) return (403, new { });
        var query = Query(uri);
        var links = definitions.Values.Where(v => v.Row.Project == query["projectId"] && v.Row.Environment == query["environment"] && v.Row.Path == query["path"]);
        return (200, new
        {
            secrets = links.Select(v => new
            {
                environment = v.Value.SourceEnvironment,
                secretPath = v.Value.SourcePath,
                folderId = sources.Single(s => s.Path == v.Value.SourcePath).FolderId,
                secrets = sources.Where(s => s.Project == v.Value.SourceProject && s.Environment == v.Value.SourceEnvironment && s.Path == v.Value.SourcePath).Select(s => new
                {
                    secretKey = s.Key,
                    secretValue = Encoding.UTF8.GetString(sourceMaterial[Fault == "wrong-material" ? sources.First(t => t.Path != s.Path).Path : s.Path]),
                    workspace = s.Project,
                    environment = s.Environment,
                    type = "shared",
                    version = 1
                }).ToArray()
            }).ToArray()
        });
    }
    private (int, object) DeliveredSecret(string principal, Uri uri)
    {
        // This is a separately admitted setup/observer secret-read contract, not
        // permission.SecretImports.read. Neither runtime nor admin gets it.
        if (principal != Authorities.Setup && principal != Authorities.Observer) return (403, new { });
        var query = Query(uri);
        if (query["includeImports"] != "true") return (404, new { });
        var link = definitions.Values.Where(v => v.Row.Project == query["projectId"] &&
            v.Row.Environment == query["environment"] && v.Row.Path == query["secretPath"])
            .OrderByDescending(v => v.Value.Position).FirstOrDefault();
        if (link is null) return (404, new { });
        var source = sources.Single(s => s.Project == link.Value.SourceProject &&
            s.Environment == link.Value.SourceEnvironment && s.Path == link.Value.SourcePath);
        return (200, new
        {
            secret = new
            {
                secretKey = source.Key,
                secretValue = Encoding.UTF8.GetString(sourceMaterial[source.Path]),
                secretValueHidden = false,
                version = 1
            }
        });
    }
    private static Policy ParsePolicy(JsonElement permissions, string principal)
    {
        ImportPermissionContract.Require(permissions.GetArrayLength() == 1);
        var p = permissions[0]; var action = p.GetProperty("action"); var conditions = p.GetProperty("conditions");
        return new(p.GetProperty("subject").GetString()!,
            action.ValueKind == JsonValueKind.Array ? action.EnumerateArray().Select(a => a.GetString()!).ToArray() : [action.GetString()!],
            conditions.GetProperty("environment").GetString()!, conditions.GetProperty("secretPath").GetString()!, principal);
    }
    private static string PolicyHash(Policy p) => p.Actions.Length == 1 ?
        ImportPermissionContract.Hash(new[] { p.Subject, p.Actions[0], p.Environment, p.Path }) : "partial";
    private ImportPermissionPolicyState[] PolicyInventory()
    {
        var result = new List<ImportPermissionPolicyState>();
        if (policy is not null && resources.ContainsKey("project/" + issued!.Project))
            result.Add(new(issued!.PolicyId, policy.Principal, issued.Project, policyRevision, PolicyHash(policy)));
        if (template is not null && (resources.ContainsKey("template/" + issued!.TemplateId) || closed && Fault == "policy-cleanup"))
            result.Add(new(issued!.TemplateId, template.Principal, issued.Project, templateRevision, PolicyHash(template)));
        if (copy is not null) result.Add(new(issued!.CopyProject, copy.Principal, issued.CopyProject, copyRevision, PolicyHash(copy)));
        if (closed && Fault == "policy-cleanup" && policy is not null)
            result.Add(new(issued!.PolicyId, policy.Principal, issued.Project, policyRevision, PolicyHash(policy)));
        return result.OrderBy(p => p.Resource).ToArray();
    }
    private ImportPermissionState State(Guid id) => definitions.TryGetValue(id, out var value) ? State(value) : new(id, false, 0, null);
    private static ImportPermissionState State(StoredDefinition value) => new(value.Row.Id, true, value.Version, value.Value);
    private static object Import(StoredDefinition value) => new
    {
        id = value.Value.Id,
        folderId = value.Value.FolderId,
        importEnv = new { id = "source-environment", slug = value.Value.SourceEnvironment, name = value.Value.SourceEnvironment, projectId = value.Value.SourceProject },
        importPath = value.Value.SourcePath,
        position = value.Value.Position,
        isReplication = value.Value.Replication,
        isReplicationSuccess = value.Value.ReplicationSuccess,
        replicationStatus = value.Value.ReplicationStatus,
        lastReplicated = value.Value.LastReplicated,
        projectId = value.Row.Project,
        secretPath = value.Row.Path,
        environment = new { slug = value.Row.Environment },
        createdAt = "2026-01-01T00:00:00Z",
        updatedAt = "2026-01-01T00:00:00Z"
    };
    internal Task DrainAsync() => Task.WhenAll(connections);
    public async ValueTask DisposeAsync()
    {
        shutdown.Cancel(); listener.Stop();
        try { await accept; } catch (SocketException) when (shutdown.IsCancellationRequested) { }
        await Task.WhenAll(connections);
        foreach (var bytes in sourceMaterial.Values.Concat(borrowedSources.Values)) CryptographicOperations.ZeroMemory(bytes);
        Source.Dispose(); foreach (var writer in writers.Values) writer.Dispose();
        shutdown.Dispose();
    }
}
