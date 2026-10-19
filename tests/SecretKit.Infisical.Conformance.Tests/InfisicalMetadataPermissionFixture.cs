using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled provider. Native SDK HTTP writes change persisted policy state;
// acquisition evaluates that state against independently provisioned metadata.
// Coordinator gets signed copies only. Backend owns a separate key and catalog.
internal sealed class InfisicalMetadataPermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static MetadataPermissionAuthorities Authorities { get; } =
        new("20000000-0000-0000-0000-000000000001", "20000000-0000-0000-0000-000000000002",
            "20000000-0000-0000-0000-000000000003", "20000000-0000-0000-0000-000000000004",
            "20000000-0000-0000-0000-000000000005");
    private readonly object gate = new();
    private readonly string fault;
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<MetadataPermissionJournal, ECDsa> writers = [];
    private readonly Dictionary<MetadataPermissionJournal, long> sequences = [];
    private readonly InfisicalMetadataPermissionSqlBackend backend;
    private readonly Dictionary<string, MetadataPermissionResource> resources = [];
    private readonly List<MetadataPermissionResource> enrolled = [];
    private readonly Dictionary<Guid, MetadataPermissionRow> metadataRows = [];
    private readonly List<MetadataPermissionSigned<MetadataPermissionIngress>> ingress = [];
    private readonly List<MetadataPermissionSigned<MetadataPermissionCommit>> commits = [];
    private readonly List<MetadataPermissionSigned<MetadataPermissionDecision>> decisions = [];
    private readonly List<MetadataPermissionSigned<MetadataPermissionLease>> leases = [];
    private readonly Dictionary<string, string> hostTokens = new()
    {
        [Authorities.Setup] = "setup",
        [Authorities.Runtime] = "runtime",
        [Authorities.Denied] = "denied",
        [Authorities.Administrative] = "administrative",
        [Authorities.Observer] = "observer"
    };
    private readonly MetadataPermissionBorrowed[] borrowed;
    private MetadataPermissionRoot? root;
    private MetadataPermissionIssued? issued;
    private JsonElement? policy, templatePolicy, copiedPolicy;
    private string revision = "baseline-1", window = "";
    private int stage;
    private bool closed, dispatchSealed, armed, copied;
    private bool roleAssigned;
    private string? policyPrincipal, templatePrincipal, copiedPrincipal;
    internal Uri Origin { get; }
    internal MetadataPermissionProfile Profile { get; }
    internal InfisicalMetadataPermissionFixtureSource Source { get; }
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    internal int Originals { get; private set; }
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Remaining { get { lock (gate) return resources.Count + metadataRows.Count + backend.Remaining; } }
    internal int Registrations => root is not null && !closed ? 1 : 0;
    internal bool BorrowedPreserved => borrowed.SequenceEqual(Borrowed());
    internal string Fault => fault;

    internal InfisicalMetadataPermissionFixture(string fault = "")
    {
        this.fault = fault;
        borrowed = Borrowed();
        backend = new(fault);
        var pins = new List<MetadataPermissionPin>();
        foreach (var journal in Enum.GetValues<MetadataPermissionJournal>().Where(j => j != MetadataPermissionJournal.Backend))
        {
            var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            writers.Add(journal, key);
            pins.Add(new(journal, journal + "-writer", journal + "-channel", "metadata-v1",
                Convert.ToBase64String(key.ExportSubjectPublicKeyInfo())));
        }
        pins.Add(backend.Pin);
        Profile = new("controlled-metadata", "controlled-epoch", "controlled-provider-v1", pins.ToArray());
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this);
        accept = AcceptAsync();
    }
    internal MetadataPermissionInput Input(MetadataPermissionOperator op = MetadataPermissionOperator.Equal,
        MetadataPermissionSubject subject = MetadataPermissionSubject.DynamicSecrets) =>
        new(new(new("https://metadata-source.invalid/"), "coordinator-token", "metadata-coordinator", 15),
            "metadata-capability", Profile, subject, op, 15);
    internal object Families(MetadataPermissionOperator op = MetadataPermissionOperator.Equal,
        MetadataPermissionSubject subject = MetadataPermissionSubject.DynamicSecrets)
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
                    metadataPermission = Input(op, subject)
                }
            }
        };
        return new Dictionary<string, object>
        {
            ["C08-IM-IdentityPrivilegeChanges"] = scope,
            ["C08-IM-RoleChanges"] = scope,
            ["C08-IM-ProjectTemplates"] = scope,
            ["C08-IM-ManagementClient"] = scope
        };
    }
    internal NativeEnvironment Environment(MetadataPermissionOperator op = MetadataPermissionOperator.Equal,
        MetadataPermissionSubject subject = MetadataPermissionSubject.DynamicSecrets) =>
        NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families = Families(op, subject)
        }, MetadataPermissionContract.Options));
    internal MetadataPermissionRoot Root(string operation, string variant, string boundary,
        MetadataPermissionOperator op = MetadataPermissionOperator.Equal) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization,
            operation, variant, boundary, "local", "metadata-coordinator", MetadataPermissionSourceKind.ControlledFixture,
            MetadataPermissionSubject.DynamicSecrets, op, Authorities, Profile);

    private MetadataPermissionHeader Header(MetadataPermissionJournal journal, string selectedWindow)
    {
        var pin = Profile.Pins.Single(p => p.Journal == journal);
        sequences[journal] = sequences.GetValueOrDefault(journal) + 1;
        return new(MetadataPermissionContract.Hash(root), journal, pin.Writer, pin.Channel, pin.Schema,
            Convert.ToHexString(SHA256.HashData(writers[journal].ExportSubjectPublicKeyInfo())),
            Guid.NewGuid().ToString("N"), sequences[journal], selectedWindow);
    }
    private MetadataPermissionSigned<T> Sign<T>(T value) where T : IMetadataPermissionEvidence
    {
        byte[] bytes = MetadataPermissionContract.Bytes(value);
        try
        {
            return new(value, Convert.ToBase64String(writers[value.Header.Journal].SignData(bytes,
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private void Enroll(string kind, string id)
    {
        MetadataPermissionContract.Require(root is not null && !closed);
        var resource = new MetadataPermissionResource(kind, id, root!.Id, root.Nonce);
        MetadataPermissionContract.Require(!enrolled.Contains(resource));
        enrolled.Add(resource);
    }
    private void Create(string kind, string id)
    {
        MetadataPermissionContract.Require(!closed);
        var resource = enrolled.Single(e => e.Kind == kind && e.Id == id);
        resources.Add(kind + "/" + id, resource);
        if (kind == "definition")
        {
            var plan = issued!.Rows.Concat(issued.CopyRows).DistinctBy(r => r.Definition).Single(r => r.Definition.ToString() == id);
            metadataRows.Add(plan.Definition, plan with { Metadata = plan.Metadata.ToArray() });
        }
        if (kind == "sql-root") backend.Bootstrap();
    }
    private void Reserve(MetadataPermissionRoot selected)
    {
        MetadataPermissionContract.Require(root is null && fault != "collision" &&
            MetadataPermissionContract.Hash(selected.Profile) == MetadataPermissionContract.Hash(Profile) &&
            selected.Authorities == Authorities && selected.Origin == Origin.AbsoluteUri &&
            selected.Organization == Organization);
        root = selected;
        string project = Guid.NewGuid().ToString(), control = Guid.NewGuid().ToString(), copy = Guid.NewGuid().ToString();
        string slug = "meta" + selected.Id, copySlug = "copy" + selected.Id;
        Guid controlFolder = Guid.NewGuid();
        MetadataPermissionRow[] Rows(string id, string projectSlug)
        {
            Guid folder = Guid.NewGuid();
            return new[] { "same-entry", "split-entry", "key-only", "value-only", "cross-scope", "empty" }.Select(name =>
                new MetadataPermissionRow(name, name == "cross-scope" ? control : id,
                    name == "cross-scope" ? "control" + selected.Id : projectSlug,
                    name == "cross-scope" ? "outside" : "witness", "/", name == "cross-scope" ? controlFolder : folder,
                    Guid.NewGuid(), "metadata-1",
                    name switch
                    {
                        "same-entry" or "cross-scope" => [new("team", "blue")],
                        "split-entry" => [new("team", "red"), new("other", "blue")],
                        "key-only" => [new("team", "red")],
                        "value-only" => [new("other", "blue")],
                        _ => []
                    })).ToArray();
        }
        var originalRows = Rows(project, slug);
        var copyRows = Rows(copy, copySlug).Select(r => r.Name == "cross-scope" ?
            originalRows.Single(o => o.Name == "cross-scope") : r).ToArray();
        issued = new(project, slug, control, Guid.NewGuid().ToString(), Guid.NewGuid().ToString(),
            "role" + selected.Id, Guid.NewGuid().ToString(), copySlug, revision, backend.ProtectedRowHash,
            originalRows, copyRows);
        roleAssigned = selected.Operation.EndsWith(".UpdateProjectRole", StringComparison.Ordinal);
        policyPrincipal = Authorities.Runtime;
        foreach (string id in new[] { project, control, copy }) Enroll("project", id);
        Enroll("membership", issued.Membership); Enroll("policy", issued.PolicyId);
        Enroll("template", issued.TemplateId); Enroll("sql-root", selected.Id);
        foreach (var row in issued.Rows.Concat(issued.CopyRows).DistinctBy(r => r.Definition))
            Enroll("definition", row.Definition.ToString());
        foreach (Guid folder in issued.Rows.Concat(issued.CopyRows).Select(r => r.Folder).Distinct())
            Enroll("folder", folder.ToString());
        // Entire creation plan exists before Open, including future copied project
        // and dynamic resources. Runtime credential/lease enrollment is atomic below.
    }
    internal MetadataPermissionPacket Step(MetadataPermissionRoot selected, MetadataPermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == MetadataPermissionStep.Reserve)
            {
                MetadataPermissionContract.Require(capability == "metadata-capability");
                Reserve(selected);
            }
            MetadataPermissionContract.Require(root is not null && MetadataPermissionContract.Hash(root) ==
                MetadataPermissionContract.Hash(selected) && !closed &&
                (step == MetadataPermissionStep.Close || (int)step == stage));
            if (step != MetadataPermissionStep.Close) stage++;
            switch (step)
            {
                case MetadataPermissionStep.Open:
                    Opens++;
                    foreach (var resource in enrolled.Where(e => e.Id != issued!.CopyRows[0].Project &&
                        !issued.CopyRows.Any(r => r.Project != issued.ControlProject &&
                            (r.Definition.ToString() == e.Id || r.Folder.ToString() == e.Id))))
                    {
                        Create(resource.Kind, resource.Id);
                        if (fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
                    }
                    if (fault == "lost-open") throw new NativeCaseFailureException("observer-unavailable");
                    break;
                case MetadataPermissionStep.Before:
                    window = "before"; decisions.Clear(); leases.Clear(); break;
                case MetadataPermissionStep.After:
                    window = "after"; decisions.Clear(); leases.Clear();
                    if (copied)
                    {
                        foreach (var row in issued!.CopyRows.Where(r => r.Project != issued.ControlProject))
                            Create("definition", row.Definition.ToString());
                        Create("folder", issued!.CopyRows[0].Folder.ToString());
                    }
                    break;
                case MetadataPermissionStep.Arm:
                    window = ""; armed = true; break;
                case MetadataPermissionStep.Settle:
                    dispatchSealed = true; break;
                case MetadataPermissionStep.ObserveBefore:
                case MetadataPermissionStep.ObserveAfter:
                    window = ""; break;
                case MetadataPermissionStep.Close:
                    Closes++; closed = dispatchSealed = true; armed = false; window = "";
                    backend.Clear();
                    foreach (var resource in resources.Values.ToArray())
                        if (fault != "cleanup" || resource.Kind != "definition")
                        {
                            resources.Remove(resource.Kind + "/" + resource.Id);
                            if (resource.Kind == "definition") metadataRows.Remove(Guid.Parse(resource.Id));
                        }
                    if (fault == "borrowed-change") hostTokens[Authorities.Runtime] = "changed-runtime";
                    break;
            }
            bool observation = step is MetadataPermissionStep.ObserveBefore or MetadataPermissionStep.ObserveAfter;
            var remaining = resources.Values.ToList();
            if (closed && backend.Remaining != 0 && !remaining.Any(r => r.Kind == "sql-root"))
                remaining.Add(enrolled.Single(r => r.Kind == "sql-root"));
            var owner = new MetadataPermissionOwner(Header(MetadataPermissionJournal.Ownership, step.ToString()), step,
                true, true, true, step is MetadataPermissionStep.Settle or MetadataPermissionStep.Close,
                0, closed ? 0 : 1, step == MetadataPermissionStep.Open ? issued : null,
                enrolled.ToArray(), remaining.ToArray(), Borrowed());
            var packet = new MetadataPermissionPacket(Sign(owner),
                step == MetadataPermissionStep.Settle ? ingress.Where(i => i.Content.Header.Window == "original").ToArray() :
                step == MetadataPermissionStep.ObserveAfter ? ingress.Where(i => i.Content.Header.Window == "after").ToArray() : [],
                step == MetadataPermissionStep.Settle ? commits.Where(c => c.Content.Header.Window == "original").ToArray() :
                step == MetadataPermissionStep.ObserveAfter ? commits.Where(c => c.Content.Header.Window == "after").ToArray() : [],
                observation ? decisions.ToArray() : [], observation ? leases.ToArray() : [], []);
            return packet with
            {
                Seals = new[] { MetadataPermissionJournal.Ingress, MetadataPermissionJournal.Storage,
                    MetadataPermissionJournal.Policy, MetadataPermissionJournal.Issuance }.Select(j =>
                {
                    var content = MetadataPermissionContract.Contents(packet, j);
                    return Sign(new MetadataPermissionSeal(Header(j, step.ToString()), content.Hash,
                        content.Headers.Length, true, 0));
                }).ToArray()
            };
        }
    }
    internal MetadataPermissionSigned<MetadataPermissionBackend> Measure(MetadataPermissionRoot selected, Guid lease,
        string username, string password, MetadataPermissionAction action)
    {
        lock (gate)
        {
            MetadataPermissionContract.Require(!closed && window is "before" or "after" &&
                MetadataPermissionContract.Hash(selected) == MetadataPermissionContract.Hash(root));
            return backend.Measure(selected, window, lease, username, password, action);
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
            byte[] header = new byte[32768], body = [], response = [];
            Copies.Add(header);
            try
            {
                var stream = socket.GetStream();
                int length = 0;
                while (length < header.Length)
                {
                    if (await stream.ReadAsync(header.AsMemory(length, 1), shutdown.Token) == 0) return;
                    length++;
                    if (length >= 4 && header.AsSpan(length - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
                }
                string[] lines = Encoding.ASCII.GetString(header, 0, length).Split("\r\n");
                string[] request = lines[0].Split(' ');
                int size = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?
                    .Split(':')[1].Trim() ?? "0");
                MetadataPermissionContract.Require(size is >= 0 and <= 131072);
                body = new byte[size]; Copies.Add(body);
                await stream.ReadExactlyAsync(body, shutdown.Token);
                string bearer = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?
                    .Split(' ').Last() ?? "";
                using var document = JsonDocument.Parse(size == 0 ? "{}"u8.ToArray() : body);
                (int Status, object Body) result;
                lock (gate) result = Handle(request[0], new Uri(Origin, request[1]), bearer, document.RootElement, body);
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
    private MetadataPermissionBorrowed[] Borrowed() => hostTokens.Select(p =>
        new MetadataPermissionBorrowed("host-token", p.Key, MetadataPermissionContract.Hash(p.Value))).ToArray();
    private string Actor(string bearer) => hostTokens.SingleOrDefault(p => p.Value == bearer).Key ?? "unknown";
    private (int, object) Handle(string method, Uri uri, string bearer, JsonElement body, byte[] bytes)
    {
        if (root is null || issued is null || closed) return (403, new { });
        string actor = Actor(bearer);
        if (uri.AbsolutePath.StartsWith("/api/v1/dynamic-secrets", StringComparison.Ordinal))
            return Dynamic(method, uri, bearer, actor, body);
        if (uri.AbsolutePath == "/api/v1/projects" && method == "POST")
            return CopyProject(actor, body, bytes);
        if (uri.AbsolutePath == "/api/v1/projects/" + issued.Project + "/memberships/identities/" + Authorities.Runtime &&
            method == "PATCH")
        {
            if (actor != Authorities.Setup || !dispatchSealed || policy is null ||
                body.GetProperty("roles").GetArrayLength() != 1 ||
                body.GetProperty("roles")[0].GetProperty("role").GetString() != issued.PolicySlug)
                return (403, new { });
            roleAssigned = true;
            string assignment = Guid.NewGuid().ToString("N");
            byte[] assignmentIntent = JsonSerializer.SerializeToUtf8Bytes(new object?[] { null, body });
            string assignmentHash;
            try { assignmentHash = Convert.ToHexString(SHA256.HashData(assignmentIntent)); }
            finally { CryptographicOperations.ZeroMemory(assignmentIntent); }
            ingress.Add(Sign(new MetadataPermissionIngress(Header(MetadataPermissionJournal.Ingress, "after"),
                assignment, actor, method, uri.AbsolutePath, assignmentHash, true)));
            commits.Add(Sign(new MetadataPermissionCommit(Header(MetadataPermissionJournal.Storage, "after"),
                assignment, issued.Membership, "no-access", "assigned-2", PolicyHash(policy.Value),
                Authorities.Runtime, issued.Project, revision)));
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
        if (uri.AbsolutePath != MetadataPermissionEffects.OriginalPath(root, issued) || method is not ("POST" or "PATCH"))
            return (404, new { });
        if (!armed || dispatchSealed || Originals != 0) return (409, new { });
        Originals++;
        string requestId = Guid.NewGuid().ToString("N");
        string intent = Convert.ToHexString(SHA256.HashData(bytes));
        if (root.Operation.Contains(".IdentityPrivilegeChangeOperations.", StringComparison.Ordinal))
        {
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartArray(); writer.WriteStringValue(issued.ProjectSlug); writer.WriteStringValue(issued.Membership);
                if (MetadataPermissionContract.Create(root.Operation)) writer.WriteNullValue(); else writer.WriteStringValue(issued.PolicyId);
                body.WriteTo(writer); writer.WriteEndArray();
            }
            intent = Convert.ToHexString(SHA256.HashData(stream.GetBuffer().AsSpan(0, (int)stream.Length)));
            CryptographicOperations.ZeroMemory(stream.GetBuffer());
        }
        bool authorized = actor == Authorities.Administrative;
        ingress.Add(Sign(new MetadataPermissionIngress(Header(MetadataPermissionJournal.Ingress, "original"),
            requestId, actor, method, uri.AbsolutePath, intent, authorized)));
        if (!authorized) return (403, new { });
        bool template = MetadataPermissionContract.Template(root.Operation);
        JsonElement permissions = template ? body.GetProperty("roles")[0].GetProperty("permissions") : body.GetProperty("permissions");
        if (template) templatePrincipal = body.GetProperty("identities")[0].GetProperty("identityId").GetString();
        else if (body.TryGetProperty("identityId", out var selectedIdentity))
            policyPrincipal = selectedIdentity.GetString();
        if (fault is not ("ignored-permissions" or "lost-nonapplied"))
        {
            JsonElement stored = permissions.Clone();
            if (fault == "partial")
                stored = JsonSerializer.SerializeToElement(new[] { new { subject = "dynamic-secrets", action = "lease" } });
            if (template) templatePolicy = stored; else policy = stored;
            string previous = revision; revision = "configuration-2";
            commits.Add(Sign(new MetadataPermissionCommit(Header(MetadataPermissionJournal.Storage, "original"), requestId,
                template ? issued.TemplateId : issued.PolicyId, previous, revision, PolicyHash(stored),
                template ? templatePrincipal! : policyPrincipal!, issued.Project, null)));
        }
        var row = new JsonObject
        {
            ["id"] = template ? issued.TemplateId : issued.PolicyId,
            ["slug"] = issued.PolicySlug,
            ["createdAt"] = "2026-01-01T00:00:00Z",
            ["updatedAt"] = "2026-01-01T00:00:01Z",
            ["permissions"] = JsonNode.Parse(permissions.GetRawText())
        };
        if (template)
        {
            row.Remove("slug"); row.Remove("permissions");
            row["name"] = issued.PolicySlug; row["orgId"] = Organization;
            row["type"] = "secret-manager";
            row["users"] = new JsonArray(); row["groups"] = new JsonArray();
            row["projectManagedIdentities"] = new JsonArray();
            foreach (string name in new[] { "roles", "environments", "identities" })
                row[name] = JsonNode.Parse(body.GetProperty(name).GetRawText());
            foreach (var identity in row["identities"]!.AsArray())
                identity!["identityName"] = "metadata-runtime";
        }
        else if (root.Operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal))
        { row["name"] = issued.PolicySlug; row["projectId"] = issued.Project; }
        else row["isTemporary"] = false;
        return (200, new JsonObject
        {
            [template ? "projectTemplate" : root.Operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal) ?
                "role" : "privilege"] = row
        });
    }
    private (int, object) CopyProject(string actor, JsonElement body, byte[] bytes)
    {
        if (actor != Authorities.Setup || !dispatchSealed || copied || templatePolicy is null ||
            body.GetProperty("template").GetString() != issued!.PolicySlug ||
            body.GetProperty("slug").GetString() != issued.CopySlug) return (403, new { });
        copied = true;
        copiedPolicy = fault == "template-echo" ? null : templatePolicy.Value.Clone();
        copiedPrincipal = templatePrincipal;
        string project = issued.CopyRows[0].Project;
        Create("project", project);
        string request = Guid.NewGuid().ToString("N");
        ingress.Add(Sign(new MetadataPermissionIngress(Header(MetadataPermissionJournal.Ingress, "after"),
            request, actor, "POST", "/api/v1/projects", Convert.ToHexString(SHA256.HashData(bytes)), true)));
        commits.Add(Sign(new MetadataPermissionCommit(Header(MetadataPermissionJournal.Storage, "after"),
            request, project, "absent", "copy-1",
            copiedPolicy is null ? "empty" : PolicyHash(copiedPolicy.Value), copiedPrincipal!, project, revision)));
        return (200, new
        {
            project = new
            {
                id = project,
                _id = project,
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
    private (int, object) Dynamic(string method, Uri uri, string bearer, string actor, JsonElement body)
    {
        if (window is not ("before" or "after") || actor == "unknown") return (403, new { });
        var configured = issued ?? throw new NativeCaseFailureException("observer-unavailable");
        var rows = metadataRows.Values;
        string name, project, environment, path;
        if (method == "GET")
        {
            var query = uri.Query.TrimStart('?').Split('&').Select(s => s.Split('=', 2))
                .ToDictionary(s => s[0], s => Uri.UnescapeDataString(s[1]));
            name = uri.Segments.Last(); project = query["projectSlug"]; environment = query["environmentSlug"]; path = query["path"];
        }
        else
        {
            name = body.GetProperty("dynamicSecretName").GetString()!; project = body.GetProperty("projectSlug").GetString()!;
            environment = body.GetProperty("environmentSlug").GetString()!; path = body.GetProperty("path").GetString()!;
        }
        var row = rows.SingleOrDefault(r => r.Name == name && r.ProjectSlug == project && r.Environment == environment && r.Path == path);
        if (row is null || !resources.ContainsKey("project/" + row.Project) ||
            !resources.ContainsKey("folder/" + row.Folder)) return (404, new { });
        if (method == "GET") return (200, new { dynamicSecret = Definition(row) });
        if (method != "POST" || uri.AbsolutePath != "/api/v1/dynamic-secrets/leases") return (404, new { });
        string request = Guid.NewGuid().ToString("N");
        JsonElement? effective = copied && window == "after" ? copiedPolicy : policy;
        string? principal = copied && window == "after" ? copiedPrincipal : policyPrincipal;
        string policyProject = copied && window == "after" ? configured.CopyRows[0].Project : configured.Project;
        bool membership = !root!.Operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal) || roleAssigned;
        bool allowed = actor == Authorities.Observer || actor == principal && membership && row.Project == policyProject &&
            effective is { } selected && Allows(selected, row);
        if (fault == "wrong-principal" && allowed && actor == Authorities.Runtime) actor = Authorities.Observer;
        var decision = Sign(new MetadataPermissionDecision(Header(MetadataPermissionJournal.Policy, window),
            request, actor, row.Project, row.Definition, revision, row.MetadataRevision, "lease",
            MetadataPermissionContract.Hash(bearer), allowed));
        decisions.Add(decision);
        if (!allowed) return (403, new { });
        Guid lease = Guid.NewGuid();
        string username = "u" + Guid.NewGuid().ToString("N"), password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        string material = MetadataPermissionContract.MaterialHash(username, password);
        Enroll("lease", lease.ToString()); Enroll("credential", material);
        // Enrollment and credential creation occur under one provider transaction lock.
        Create("lease", lease.ToString()); Create("credential", material);
        backend.Issue(lease, material, actor, row.Project);
        leases.Add(Sign(new MetadataPermissionLease(Header(MetadataPermissionJournal.Issuance, window),
            request, decision.Content.Header.Event, actor, row.Project, row.Definition, revision, row.MetadataRevision, lease, material)));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return (200, new
        {
            dynamicSecret = Definition(row),
            lease = new
            {
                id = lease,
                dynamicSecretId = row.Definition,
                createdAt = now,
                updatedAt = now,
                expireAt = now.AddMinutes(5),
                version = 1,
                externalEntityId = username
            },
            data = new { DB_USERNAME = username, DB_PASSWORD = password }
        });
    }
    private static object Definition(MetadataPermissionRow row) => new
    {
        id = row.Definition,
        name = row.Name,
        folderId = row.Folder,
        type = "sql-database",
        defaultTTL = "300s",
        maxTTL = "600s",
        version = 1,
        createdAt = "2026-01-01T00:00:00Z",
        updatedAt = "2026-01-01T00:00:00Z"
    };
    private bool Allows(JsonElement permissions, MetadataPermissionRow row)
    {
        foreach (var permission in permissions.EnumerateArray())
        {
            if (permission.GetProperty("subject").GetString() != "dynamic-secrets" ||
                permission.GetProperty("action").GetString() != "lease") continue;
            if (!permission.TryGetProperty("conditions", out var conditions)) return true;
            if (conditions.GetProperty("environment").GetString() != row.Environment ||
                conditions.GetProperty("secretPath").GetString() != row.Path) continue;
            var match = conditions.GetProperty("metadata").GetProperty("$elemMatch");
            if (fault == "split-entry")
                return (!match.TryGetProperty("key", out var key) || row.Metadata.Any(e => Compare(key, e.Key))) &&
                    (!match.TryGetProperty("value", out var value) || row.Metadata.Any(e => Compare(value, e.Value)));
            return row.Metadata.Any(e => (!match.TryGetProperty("key", out var k) || Compare(k, e.Key)) &&
                (!match.TryGetProperty("value", out var v) || Compare(v, e.Value)));
        }
        return false;
    }
    private static bool Compare(JsonElement clause, string value) => clause.EnumerateObject().All(p => p.Name switch
    {
        "$eq" => p.Value.GetString() == value,
        "$ne" => p.Value.GetString() != value,
        "$in" => p.Value.EnumerateArray().Any(v => v.GetString() == value),
        _ => false
    });
    private static string PolicyHash(JsonElement permissions)
    {
        var permission = permissions.EnumerateArray().Single(p => p.GetProperty("action").GetString() == "lease");
        if (!permission.TryGetProperty("conditions", out var conditions)) return "partial-policy";
        var match = conditions.GetProperty("metadata").GetProperty("$elemMatch");
        static MetadataPermissionOperand? Operand(JsonElement match, string name)
        {
            if (!match.TryGetProperty(name, out var clause)) return null;
            MetadataPermissionContract.Require(clause.EnumerateObject().All(p => p.Name is "$eq" or "$ne" or "$in"));
            return new(clause.TryGetProperty("$eq", out var equal) ? equal.GetString() : null,
                clause.TryGetProperty("$ne", out var ne) ? ne.GetString() : null,
                clause.TryGetProperty("$in", out var included) ? included.EnumerateArray().Select(v => v.GetString()!).ToArray() : null);
        }
        return MetadataPermissionContract.Hash(new MetadataPermissionPolicy(permission.GetProperty("subject").GetString(),
            permission.GetProperty("action").GetString(), conditions.GetProperty("environment").GetString(),
            conditions.GetProperty("secretPath").GetString(), Operand(match, "key"), Operand(match, "value")));
    }
    public async ValueTask DisposeAsync()
    {
        shutdown.Cancel(); listener.Stop();
        try { await accept; } catch (SocketException) when (shutdown.IsCancellationRequested) { }
        await Task.WhenAll(connections);
        Source.Dispose(); backend.Dispose();
        foreach (var key in writers.Values) key.Dispose();
        shutdown.Dispose();
    }
    internal Task DrainAsync() => Task.WhenAll(connections);
}
