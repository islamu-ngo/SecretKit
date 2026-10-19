using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled provider: authentication uses bearer material, authorization reads
// persisted policy and assignments. No result is decided from row.Control.
// Native IDs are generated ONLY in CommitCreation, inside the commit lock.
internal sealed class InfisicalProjectTemplatePermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static MemberPermissionAuthorities Authorities => InfisicalMemberPermissionFixture.Authorities;
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<ProjectTemplatePermissionJournal, InfisicalProjectTemplatePermissionWriter> writers = [];
    private readonly Dictionary<string, string> hostTokens = new()
    {
        [Authorities.Setup] = "setup",
        [Authorities.Runtime] = "runtime",
        [Authorities.Denied] = "denied",
        [Authorities.Administrative] = "administrative",
        [Authorities.Observer] = "observer"
    };
    private readonly Dictionary<string, string> borrowedObjects = new()
    {
        ["30000000-0000-0000-0000-000000000001"] = "borrowed-template",
        ["30000000-0000-0000-0000-000000000002"] = "borrowed-user",
        ["30000000-0000-0000-0000-000000000003"] = "borrowed-machine",
        ["30000000-0000-0000-0000-000000000004"] = "borrowed-membership"
    };
    private readonly Dictionary<string, ProjectTemplatePermissionCredential> tokens = [];
    private readonly List<ProjectTemplatePermissionCredential> credentials = [];
    private readonly List<ProjectTemplatePermissionBinding> issuanceBindings = [], storageBindings = [];
    private readonly Dictionary<string, ProjectTemplatePermissionResource> resources = [];
    private readonly Dictionary<string, ProjectTemplatePermissionState> states = [];
    private readonly List<ProjectTemplatePermissionIngress> ingress = [];
    private readonly List<ProjectTemplatePermissionCommit> commits = [];
    private readonly List<ProjectTemplatePermissionAccess> decisions = [];
    private readonly List<ProjectTemplatePermissionChange> changes = [];
    private readonly List<byte[]> privateBuffers = [];
    private readonly MemberPermissionBorrowed[] borrowed;
    private ProjectTemplatePermissionRoot? root;
    private ProjectTemplatePermissionPlan? plan;
    private ProjectTemplatePermissionActor[] actors = [];
    private ProjectTemplatePermissionPolicy? policy;
    private ECDsa? ownedKey;
    private string revision = "policy-1", window = "";
    private string assignedRoleId = "", assignedRoleSlug = "no-access";
    private int stage;
    private bool closed, closing, armed, settled, assigned;
    private Task? delayed;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal ProjectTemplatePermissionProfile Profile { get; }
    internal InfisicalProjectTemplatePermissionFixtureSource Source { get; }
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    internal TaskCompletionSource OpenEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource OpenRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource CloseEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal int Originals { get; private set; }
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Generated => storageBindings.Count;
    internal int Registrations => root is not null && !closed ? 1 : 0;
    internal int Remaining => resources.Count + states.Count + credentials.Count + (policy is null ? 0 : 1) + (ownedKey is null ? 0 : 1);
    internal bool BorrowedPreserved => Borrowed().SequenceEqual(borrowed);
    internal InfisicalProjectTemplatePermissionFixture(string fault = "")
    {
        Fault = fault;
        foreach (var journal in Enum.GetValues<ProjectTemplatePermissionJournal>()) writers.Add(journal, new(journal));
        Profile = new("controlled-project-templates", "controlled-epoch", "controlled-v1", writers.Values.Select(w => w.Pin).ToArray());
        borrowed = Borrowed(); listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/"); Source = new(this); accept = AcceptAsync();
    }
    internal ProjectTemplatePermissionInput Input(string operation, ProjectTemplatePermissionAction action) =>
        new(new(new("https://project-template-source.invalid/"), "coordinator-token", "project-template-coordinator", 30), "project-template-capability", Profile,
            ProjectTemplatePermissionContract.Scope(operation), ProjectTemplatePermissionContract.ActorKind(operation), action, 30);
    internal NativeEnvironment Environment(string operation, ProjectTemplatePermissionAction action, bool configured = true)
    {
        var scope = JsonSerializer.SerializeToNode(new
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
                    projectTemplatePermission = Input(operation, action)
                }
            }
        }, ProjectTemplatePermissionContract.Options)!;
        if (!configured) scope["scopes"]!["local"]!.AsObject().Remove("projectTemplatePermission");
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
        }, ProjectTemplatePermissionContract.Options));
    }
    internal ProjectTemplatePermissionRoot Root(string operation, ProjectTemplatePermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization, operation,
            ProjectTemplatePermissionContract.Variant(action), boundary, "local", "project-template-coordinator", MemberPermissionSourceKind.ControlledFixture,
            ProjectTemplatePermissionContract.Scope(operation), ProjectTemplatePermissionContract.ActorKind(operation), action, Authorities, Profile);
    private MemberPermissionBorrowed[] Borrowed() => hostTokens.Select(p => new MemberPermissionBorrowed("host-credential", p.Key, ProjectTemplatePermissionContract.Hash(p.Value)))
        .Concat(writers.Values.Select(w => new MemberPermissionBorrowed("host-key", w.Pin.Writer, ProjectTemplatePermissionContract.Hash(w.Pin.Spki))))
        .Concat(borrowedObjects.Select(p => new MemberPermissionBorrowed(p.Value, p.Key, ProjectTemplatePermissionContract.Hash(p.Value)))).ToArray();
    private ProjectTemplatePermissionIssued Issued => new(actors, storageBindings.ToArray());
    private string Id(string key) => Issued.Id(key);
    private string CommitCreation(string key, string? request = null, bool admitted = false)
    {
        ProjectTemplatePermissionContract.Require(root is not null && plan is not null && !closed && (!closing || admitted) && !resources.ContainsKey(key) &&
            !storageBindings.Any(b => b.Intent == key));
        var intent = plan!.Intents.Single(i => i.Key == key);
        ProjectTemplatePermissionContract.Require(Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0));
        // There is deliberately no ID-generation path in Reserve or plan construction.
        string canonical = Guid.NewGuid().ToString();
        var binding = new ProjectTemplatePermissionBinding(key, ProjectTemplatePermissionContract.Hash(intent), intent.Work, intent.Kind, Id(intent.Scope),
            ProjectTemplatePermissionPlan.InputHash(intent, Id), canonical, request ?? Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"));
        issuanceBindings.Add(binding); storageBindings.Add(binding); resources.Add(key, new(key, canonical));
        return canonical;
    }
    private ProjectTemplatePermissionActor IssueActor(int i)
    {
        string key = plan!.ActorKey(i), scope = Id(plan.ActorScope(i)); var kind = plan.ActorKind(i);
        bool owned = !key.StartsWith("@", StringComparison.Ordinal);
        if (owned && Id(key).Length == 0) CommitCreation(key);
        string principal = Id(key); ProjectTemplatePermissionCredential credential; byte[] bytes;
        if (owned)
        {
            (credential, bytes) = IssueCredential("actor-credential-" + i, principal, kind, scope);
        }
        else
        {
            bytes = Encoding.UTF8.GetBytes(hostTokens[principal]);
            credential = new("host-" + principal, principal, kind, scope, ProjectTemplatePermissionContract.RawHash(bytes), false);
            CryptographicOperations.ZeroMemory(bytes); bytes = [];
            if (!credentials.Any(c => c.Id == credential.Id)) credentials.Add(credential);
        }
        CommitCreation(plan.ActorMembership(i));
        return new(principal, kind, scope, credential.Id, credential.Hash, bytes, owned);
    }
    private (ProjectTemplatePermissionCredential Credential, byte[] Bytes) IssueCredential(string key, string principal, MemberPermissionActorKind kind, string scope)
    {
        string id = CommitCreation(key);
        byte[] random = RandomNumberGenerator.GetBytes(32), bytes;
        try { bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(random)); } finally { CryptographicOperations.ZeroMemory(random); }
        privateBuffers.Add(bytes); Copies.Add(bytes);
        var credential = new ProjectTemplatePermissionCredential(id, principal, kind, scope, ProjectTemplatePermissionContract.RawHash(bytes), true);
        credentials.Add(credential); tokens.Add(Encoding.ASCII.GetString(bytes), credential); return (credential, bytes);
    }
    private void Open()
    {
        Opens++; CommitCreation(ProjectTemplatePermissionPlan.OtherOrganization);
        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
        foreach (string key in new[] { "issuer-work", "dispatch-work", "registration", "canary", "owned-key" }) CommitCreation(key);
        ownedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        actors = Enumerable.Range(0, 4).Select(IssueActor).ToArray();
        foreach (var row in plan!.Rows.Where(plan.InitiallyPresent))
        { CommitCreation(row.Template); states.Add(row.Key, plan.Initial(row, Issued)); }
        assigned = !root!.Operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal);
        if (assigned)
        {
            CommitCreation(plan.PolicyKey);
            string[] actions = ["read", "create", "edit", "delete"];
            string baseline = actions[(Array.IndexOf(actions, ProjectTemplatePermissionContract.Wire(root.Action)) + 1) % 4];
            policy = new(Id(plan.PolicyKey), revision, actors[0].Principal, MemberPermissionActorKind.User, Organization, "", "project-templates", [baseline], [], plan.Slug);
            assignedRoleId = Id(plan.PolicyKey); assignedRoleSlug = Fault == "wrong-role-binding" ? "foreign-role" : plan.Slug;
        }
        if (Fault == "delayed-issuer") { delayed = IssueDelayedAsync(); throw new NativeCaseFailureException("observer-unavailable"); }
        if (Fault == "lost-open") throw new NativeCaseFailureException("observer-unavailable");
    }
    private async Task IssueDelayedAsync()
    {
        IssuerEntered.TrySetResult(); await IssuerRelease.Task.WaitAsync(shutdown.Token);
        lock (gate) CommitCreation(ProjectTemplatePermissionPlan.Deferred, admitted: true);
    }
    internal ProjectTemplatePermissionPacket Step(ProjectTemplatePermissionRoot selected, ProjectTemplatePermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == ProjectTemplatePermissionStep.Reserve)
            {
                ProjectTemplatePermissionContract.Require(root is null && capability == "project-template-capability" && selected.Origin == Origin.AbsoluteUri &&
                    selected.Organization == Organization && selected.Authorities == Authorities && ProjectTemplatePermissionContract.Hash(Profile) == ProjectTemplatePermissionContract.Hash(selected.Profile));
                root = selected; plan = new(selected);
                if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
            }
            ProjectTemplatePermissionContract.Require(root is not null && ProjectTemplatePermissionContract.Hash(root) == ProjectTemplatePermissionContract.Hash(selected) && !closed &&
                (step == ProjectTemplatePermissionStep.Close || stage == (int)step));
            if (step != ProjectTemplatePermissionStep.Close) stage++;
            switch (step)
            {
                case ProjectTemplatePermissionStep.Open: Open(); break;
                case ProjectTemplatePermissionStep.Before: Clear(); window = "before"; break;
                case ProjectTemplatePermissionStep.Arm: Clear(); window = ""; armed = true; break;
                case ProjectTemplatePermissionStep.Settle: settled = true; break;
                case ProjectTemplatePermissionStep.After:
                    ingress.RemoveAll(e => e.Phase != "activation"); commits.RemoveAll(c => !ingress.Any(e => e.Request == c.Request));
                    decisions.Clear(); changes.Clear(); window = "after"; break;
                case ProjectTemplatePermissionStep.ObserveBefore:
                case ProjectTemplatePermissionStep.ObserveAfter: window = ""; break;
                case ProjectTemplatePermissionStep.Close:
                    Closes++;
                    ProjectTemplatePermissionContract.Require(closing && (delayed is null || delayed.IsCompletedSuccessfully));
                    // Reconcile native IDs from original-root issuance AND storage, not the Open reply.
                    ProjectTemplatePermissionContract.Require(issuanceBindings.SequenceEqual(storageBindings));
                    foreach (var binding in storageBindings)
                        ProjectTemplatePermissionContract.Require(binding.IntentHash == ProjectTemplatePermissionContract.Hash(plan!.Intents.Single(i => i.Key == binding.Intent)) &&
                            !borrowed.Any(b => b.Id == binding.CanonicalId));
                    foreach (var binding in storageBindings)
                    {
                        var native = resources.SingleOrDefault(r => r.Value.CanonicalId == binding.CanonicalId);
                        if (native.Key is null) continue; // A witnessed downstream delete may already have removed it.
                        ProjectTemplatePermissionContract.Require(native.Value.Intent == binding.Intent);
                        resources.Remove(native.Key);
                    }
                    states.Clear(); credentials.Clear(); tokens.Clear(); policy = null;
                    assigned = false; assignedRoleId = ""; assignedRoleSlug = "no-access";
                    foreach (var bytes in privateBuffers) CryptographicOperations.ZeroMemory(bytes);
                    ownedKey?.Dispose(); ownedKey = null; closed = settled = true; armed = false; window = "";
                    if (Fault == "cleanup") resources.Add("residual", new("canary", Id("canary")));
                    if (Fault == "borrowed-change") borrowedObjects[borrowedObjects.Keys.First()] = "modified";
                    break;
            }
            return Packet(step);
        }
    }
    private void Clear() { ingress.Clear(); commits.Clear(); decisions.Clear(); changes.Clear(); }
    private ProjectTemplatePermissionSigned<T> Sign<T>(ProjectTemplatePermissionStep step, ProjectTemplatePermissionJournal journal, T content) => writers[journal].Sign(root!, step, content);
    private ProjectTemplatePermissionJoin[] Joins() => closed ? [] : actors.Select((a, i) => new ProjectTemplatePermissionJoin(a.Principal,
        a.Kind == MemberPermissionActorKind.User ? "user" : "machine", a.Organization, Id(plan!.ActorMembership(i)), i == 0 && assigned,
        i == 0 ? assignedRoleId : "", i == 0 ? assignedRoleSlug : "no-access", true, "accepted")).ToArray();
    private ProjectTemplatePermissionPacket Packet(ProjectTemplatePermissionStep step)
    {
        bool open = step == ProjectTemplatePermissionStep.Open, observe = step is ProjectTemplatePermissionStep.ObserveBefore or ProjectTemplatePermissionStep.ObserveAfter;
        var issue = issuanceBindings.ToArray(); var storage = storageBindings.ToArray();
        if (open && issue.Length > 1)
        {
            switch (Fault)
            {
                case "binding-substitution": storage[0] = storage[0] with { CanonicalId = Guid.NewGuid().ToString() }; break;
                case "binding-duplicate": issue[1] = issue[1] with { CanonicalId = issue[0].CanonicalId }; storage = issue.ToArray(); break;
                case "binding-work": issue[0] = issue[0] with { Work = "foreign-work" }; storage = issue.ToArray(); break;
                case "binding-input": issue[0] = issue[0] with { InputHash = "foreign-input" }; storage = issue.ToArray(); break;
                case "binding-scope": issue[0] = issue[0] with { Scope = "foreign-scope" }; storage = issue.ToArray(); break;
                case "binding-borrowed": issue[0] = issue[0] with { CanonicalId = borrowedObjects.Keys.First() }; storage = issue.ToArray(); break;
                case "binding-missing": issue = issue.Skip(1).ToArray(); break;
            }
        }
        var credentialRows = credentials.ToArray(); var joins = Joins(); var inventory = states.Values.OrderBy(s => s.Row).ToArray();
        if (open && Fault == "actor-kind") credentialRows[0] = credentialRows[0] with { Kind = credentialRows[0].Kind == MemberPermissionActorKind.User ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User };
        if (open && Fault == "credential-wrong-actor") credentialRows[0] = credentialRows[0] with { Principal = Authorities.Observer };
        if (open && Fault == "membership-wrong-member") joins[0] = joins[0] with { Principal = Authorities.Observer };
        if (open && Fault == "missing-inventory") inventory = inventory.Skip(1).ToArray();
        var allPolicies = new[] { policy }.OfType<ProjectTemplatePermissionPolicy>().OrderBy(p => p.Resource).ToArray();
        var committed = observe || step == ProjectTemplatePermissionStep.Settle ? commits.ToArray() : [];
        if (step == ProjectTemplatePermissionStep.Settle && Fault == "wrong-policy-target" && committed.Length == 1)
        { committed[0] = committed[0] with { Policy = committed[0].Policy with { Resource = Guid.NewGuid().ToString() } }; allPolicies = [committed[0].Policy]; }
        var intents = plan!.Intents.ToArray();
        if (open && Fault == "intent-mutation") intents[0] = intents[0] with { Input = "changed" };
        var packet = new ProjectTemplatePermissionPacket(
            Sign(step, ProjectTemplatePermissionJournal.Ownership, new ProjectTemplatePermissionOwner(intents, resources.Values.ToArray(), Borrowed(), true, true,
                settled || closed, settled || closed, open && Fault == "pending-issuer" ? 1 : 0, closed ? 0 : 1, open ? actors : [])),
            Sign(step, ProjectTemplatePermissionJournal.Ingress, observe || step == ProjectTemplatePermissionStep.Settle ? ingress.ToArray() : []),
            Sign(step, ProjectTemplatePermissionJournal.Policy, new ProjectTemplatePermissionPolicies(allPolicies, committed)),
            Sign(step, ProjectTemplatePermissionJournal.Storage, new ProjectTemplatePermissionStorage(storage, inventory, observe ? changes.ToArray() : [])),
            Sign(step, ProjectTemplatePermissionJournal.Issuer, new ProjectTemplatePermissionIssuance(issue, credentialRows)),
            Sign(step, ProjectTemplatePermissionJournal.Membership, joins), Sign(step, ProjectTemplatePermissionJournal.Access, observe ? decisions.ToArray() : []), []);
        var seals = new List<ProjectTemplatePermissionSigned<MemberPermissionSeal>>();
        Add(ProjectTemplatePermissionJournal.Ownership, packet.Owner.Payload); Add(ProjectTemplatePermissionJournal.Ingress, packet.Ingress.Payload);
        Add(ProjectTemplatePermissionJournal.Policy, packet.Policy.Payload); Add(ProjectTemplatePermissionJournal.Storage, packet.Storage.Payload);
        Add(ProjectTemplatePermissionJournal.Issuer, packet.Issuer.Payload); Add(ProjectTemplatePermissionJournal.Membership, packet.Membership.Payload); Add(ProjectTemplatePermissionJournal.Access, packet.Access.Payload);
        return packet with { Seals = open && Fault == "missing-seal" ? seals.Skip(1).ToArray() : seals.ToArray() };
        void Add<T>(ProjectTemplatePermissionJournal journal, T payload) => seals.Add(Sign(step, journal,
            new MemberPermissionSeal(ProjectTemplatePermissionContract.Hash(payload), !(open && Fault == "nonterminal"), 0, 1)));
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
                ProjectTemplatePermissionContract.Require(length is >= 0 and <= 131072);
                body = new byte[length]; Copies.Add(body); await stream.ReadExactlyAsync(body, shutdown.Token);
                string bearer = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?.Split(' ').Last() ?? "";
                using var document = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
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
                CryptographicOperations.ZeroMemory(header); CryptographicOperations.ZeroMemory(body); CryptographicOperations.ZeroMemory(response);
            }
        }
    }
    private ProjectTemplatePermissionCredential Authenticate(string bearer)
    {
        if (tokens.TryGetValue(bearer, out var credential)) return credential;
        string principal = hostTokens.SingleOrDefault(p => p.Value == bearer).Key ?? "unknown";
        byte[] bytes = Encoding.UTF8.GetBytes(bearer);
        try { return new("host-" + principal, principal, MemberPermissionActorKind.Machine, Organization, ProjectTemplatePermissionContract.RawHash(bytes), false); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private void Record(string request, ProjectTemplatePermissionCredential actor, string method, string path, byte[] bytes, string intent, bool allowed, string phase) =>
        ingress.Add(new(request, actor.Principal, actor.Kind, actor.Hash, actor.Organization, method, path, ProjectTemplatePermissionContract.RawHash(bytes), intent, allowed, phase));
    private (int, object) Handle(string method, Uri uri, string bearer, JsonElement body, byte[] bytes)
    {
        if (root is null || actors.Length == 0 || closed || closing) return (403, new { });
        var actor = Authenticate(bearer); string path = uri.AbsolutePath;
        bool create = root.Operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal);
        string originalPath = "/api/v1/organization/roles" + (create ? "" : "/" + Id(plan!.PolicyKey));
        if (path == originalPath && method == (create ? "POST" : "PATCH"))
        {
            if (!armed || settled || Originals != 0) return (409, new { });
            Originals++; string request = Guid.NewGuid().ToString("N");
            bool allowed = actor.Principal == Authorities.Administrative && actor.Kind == MemberPermissionActorKind.Machine && actor.Organization == Organization;
            Record(request, actor, method, path, bytes, ProjectTemplatePermissionContract.RawHash(bytes), allowed, "original");
            if (!allowed) return (403, new { });
            var permissions = body.GetProperty("permissions"); var permission = permissions.EnumerateArray().Single();
            var action = permission.GetProperty("action"); string[] selected = action.ValueKind == JsonValueKind.Array ?
                action.EnumerateArray().Select(v => v.GetString()!).ToArray() : [action.GetString()!];
            if (body.GetProperty("name").GetString() != plan!.Slug || body.GetProperty("slug").GetString() != plan.Slug) return (400, new { });
            if (Fault is not ("ignored-policy" or "lost-nonapplied"))
            {
                if (create) CommitCreation(plan.PolicyKey, request);
                string old = revision; revision = "policy-2";
                policy = new(Id(plan.PolicyKey), revision, actors[0].Principal, MemberPermissionActorKind.User, Organization, "",
                    permission.GetProperty("subject").GetString()!, Fault == "partial" ? [] : selected,
                    Fault == "wrong-condition" ? ["forged-condition"] : [], Fault == "incomplete-policy" ? "" : plan.Slug);
                commits.Add(new(request, old, policy));
            }
            return (200, new
            {
                role = new
                {
                    id = Id(plan.PolicyKey),
                    orgId = Organization,
                    name = plan.Slug,
                    slug = plan.Slug,
                    permissions = JsonNode.Parse(permissions.GetRawText()),
                    createdAt = "2026-01-01T00:00:00Z",
                    updatedAt = "2026-01-01T00:00:01Z"
                }
            });
        }
        if (settled && actor.Principal == Authorities.Setup && actor.Kind == MemberPermissionActorKind.Machine && policy is not null &&
            path == "/api/v2/organizations/" + Organization + "/memberships/" + Id(plan!.ActorMembership(0)) && method == "PATCH")
        {
            if (assigned || body.GetProperty("role").GetString() != plan!.Slug) return (403, new { });
            assigned = Fault != "assignment-echo"; string request = Guid.NewGuid().ToString("N");
            if (assigned)
            { assignedRoleId = Id(plan.PolicyKey); assignedRoleSlug = Fault == "wrong-role-binding" ? "foreign-role" : body.GetProperty("role").GetString()!; }
            Record(request, actor, method, path, bytes, ProjectTemplatePermissionContract.RawHash(bytes), true, "activation"); commits.Add(new(request, revision, policy));
            return (200, new
            {
                membership = new
                {
                    id = Id(plan.ActorMembership(0)),
                    userId = actors[0].Principal,
                    orgId = Organization,
                    role = plan.Slug,
                    isActive = true,
                    status = "accepted",
                    createdAt = "2026-01-01T00:00:00Z",
                    updatedAt = "2026-01-01T00:00:00Z"
                }
            });
        }
        if (path == "/api/v1/project-templates" && method == "GET" && actor.Principal == Authorities.Observer)
            return (200, new { projectTemplates = states.Values.Where(s => s.Organization == Organization).Select(TemplateRow).ToArray() });
        return TemplateAction(actor, method, path, body, bytes);
    }
    private (int, object) TemplateAction(ProjectTemplatePermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        if (window is not ("before" or "after")) return (403, new { });
        var action = method switch
        {
            "GET" => ProjectTemplatePermissionAction.Read,
            "POST" => ProjectTemplatePermissionAction.Create,
            "PATCH" => ProjectTemplatePermissionAction.Edit,
            "DELETE" => ProjectTemplatePermissionAction.Delete,
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        if (!path.StartsWith("/api/v1/project-templates", StringComparison.Ordinal)) return (404, new { });
        string template = method == "POST" ? "" : path.Split('/').Last();
        var row = method == "POST" ? plan!.Rows.SingleOrDefault(r => r.Name == body.GetProperty("name").GetString() && Id(r.Organization) == actor.Organization) :
            plan!.Rows.SingleOrDefault(r => Id(r.Template) == template);
        if (row is null) return (404, new { });
        string organization = Id(row.Organization), wire = action.ToString().ToLowerInvariant();
        bool allowed = assigned && policy is not null && policy.Subject == "project-templates" && policy.Actor == actor.Principal && policy.Kind == actor.Kind &&
            actor.Organization == organization && policy.Organization == organization && policy.Actions.Contains(wire) &&
            Joins().Any(j => j.Principal == actor.Principal && j.Kind == "user" && j.Organization == organization && j.Assigned &&
                j.RoleId == policy.Resource && j.RoleSlug == policy.Role && j.Active && j.Status == "accepted");
        if (Fault == "action-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && organization == Organization) allowed = true;
        if (Fault == "scope-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && policy?.Actions.Contains(wire) == true) allowed = true;
        string request = Guid.NewGuid().ToString("N"); var recorded = Fault == "wrong-actor" ? actor with { Principal = Authorities.Observer } : actor;
        if (Fault == "wrong-credential") recorded = recorded with { Hash = "wrong" };
        Record(request, recorded, method, path, bytes, "", allowed, "action");
        var previous = states.GetValueOrDefault(row.Key); object response = new { };
        if (allowed)
        {
            switch (action)
            {
                case ProjectTemplatePermissionAction.Create:
                    CommitCreation(row.Template, request);
                    states.Add(row.Key, Persist(row, body, 1)); response = new { projectTemplate = TemplateRow(states[row.Key]) }; break;
                case ProjectTemplatePermissionAction.Edit:
                    states[row.Key] = Persist(row, body, 2); response = new { projectTemplate = TemplateRow(states[row.Key]) }; break;
                case ProjectTemplatePermissionAction.Delete:
                    response = new { projectTemplate = TemplateRow(previous!) }; states.Remove(row.Key); resources.Remove(row.Template); break;
                case ProjectTemplatePermissionAction.Read:
                    response = new { projectTemplate = TemplateRow(previous!) }; break;
            }
            if (Fault == "wrong-template" && states.TryGetValue(row.Key, out var wrong)) states[row.Key] = wrong with { Template = Guid.NewGuid().ToString() };
        }
        decisions.Add(new(request, recorded.Principal, recorded.Kind, recorded.Id, recorded.Hash, organization, Id(row.Template), revision, action, allowed));
        changes.Add(new(request, row.Key, previous, states.GetValueOrDefault(row.Key)));
        return (allowed ? 200 : 403, response);
    }
    private ProjectTemplatePermissionState Persist(ProjectTemplatePermissionRow row, JsonElement body, int version)
    {
        var config = new JsonObject();
        foreach (string key in new[] { "roles", "environments", "users", "groups", "identities", "projectManagedIdentities" })
            config[key] = JsonNode.Parse(body.GetProperty(key).GetRawText());
        if (Fault == "wrong-input-config") config["roles"]![0]!["slug"] = "foreign-slug";
        if (Fault == "null-config") config["users"] = null;
        string type = version == 1 ? body.GetProperty("type").GetString()! : states[row.Key].Type;
        return new(row.Key, Id(row.Template), Id(row.Organization), body.GetProperty("name").GetString()!, body.GetProperty("description").GetString()!,
            type, config.ToJsonString(), version);
    }
    private static object TemplateRow(ProjectTemplatePermissionState state)
    {
        var value = JsonNode.Parse(state.Configuration)!.AsObject();
        value["id"] = state.Template; value["orgId"] = state.Organization; value["name"] = state.Name; value["description"] = state.Description;
        value["type"] = state.Type; value["createdAt"] = "2026-01-01T00:00:00Z"; value["updatedAt"] = "2026-01-01T00:00:01Z";
        return value;
    }
    internal async Task SealAndDrainAsync()
    {
        lock (gate) { closing = true; settled = true; armed = false; CloseEntered.TrySetResult(); }
        if (delayed is not null) await delayed;
        await Task.WhenAll(connections);
    }
    internal Task DrainAsync() => Task.WhenAll(connections);
    public async ValueTask DisposeAsync()
    {
        OpenRelease.TrySetResult(); IssuerRelease.TrySetResult();
        if (delayed is not null) await delayed;
        shutdown.Cancel(); listener.Stop();
        try { await accept; } catch (SocketException) when (shutdown.IsCancellationRequested) { }
        await Task.WhenAll(connections);
        foreach (var bytes in privateBuffers) CryptographicOperations.ZeroMemory(bytes);
        ownedKey?.Dispose(); Source.Dispose(); foreach (var writer in writers.Values) writer.Dispose(); shutdown.Dispose();
    }
}
