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
internal sealed class InfisicalGroupPermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static MemberPermissionAuthorities Authorities => InfisicalMemberPermissionFixture.Authorities;
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<GroupPermissionJournal, InfisicalGroupPermissionWriter> writers = [];
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
        ["30000000-0000-0000-0000-000000000001"] = "borrowed-group",
        ["30000000-0000-0000-0000-000000000002"] = "borrowed-user",
        ["30000000-0000-0000-0000-000000000003"] = "borrowed-machine",
        ["30000000-0000-0000-0000-000000000004"] = "borrowed-membership"
    };
    private readonly Dictionary<string, GroupPermissionCredential> tokens = [];
    private readonly List<GroupPermissionCredential> credentials = [];
    private readonly List<GroupPermissionBinding> issuanceBindings = [], storageBindings = [];
    private readonly Dictionary<string, GroupPermissionResource> resources = [];
    private readonly Dictionary<string, GroupPermissionState> states = [];
    private readonly List<GroupPermissionIngress> ingress = [];
    private readonly List<GroupPermissionCommit> commits = [];
    private readonly List<GroupPermissionAccess> decisions = [];
    private readonly List<GroupPermissionChange> changes = [];
    private readonly List<byte[]> privateBuffers = [];
    private readonly MemberPermissionBorrowed[] borrowed;
    private GroupPermissionRoot? root;
    private GroupPermissionPlan? plan;
    private GroupPermissionActor[] actors = [];
    private GroupPermissionPolicy? policy, copiedPolicy;
    private ECDsa? ownedKey;
    private string revision = "policy-1", window = "";
    private int stage;
    private bool closed, closing, armed, settled, assigned, copied;
    private Task? delayed;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal GroupPermissionProfile Profile { get; }
    internal InfisicalGroupPermissionFixtureSource Source { get; }
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
    internal int Remaining => resources.Count + states.Count + credentials.Count + (policy is null ? 0 : 1) + (copiedPolicy is null ? 0 : 1) + (ownedKey is null ? 0 : 1);
    internal bool BorrowedPreserved => Borrowed().SequenceEqual(borrowed);
    internal InfisicalGroupPermissionFixture(string fault = "")
    {
        Fault = fault;
        foreach (var journal in Enum.GetValues<GroupPermissionJournal>()) writers.Add(journal, new(journal));
        Profile = new("controlled-groups", "controlled-epoch", "controlled-v1", writers.Values.Select(w => w.Pin).ToArray());
        borrowed = Borrowed(); listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/"); Source = new(this); accept = AcceptAsync();
    }
    internal GroupPermissionInput Input(string operation, GroupPermissionAction action) =>
        new(new(new("https://group-source.invalid/"), "coordinator-token", "group-coordinator", 30), "group-capability", Profile,
            GroupPermissionContract.Scope(operation), GroupPermissionContract.ActorKind(operation), action, 30);
    internal NativeEnvironment Environment(string operation, GroupPermissionAction action, bool configured = true)
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
                    groupPermission = Input(operation, action)
                }
            }
        }, GroupPermissionContract.Options)!;
        if (!configured) scope["scopes"]!["local"]!.AsObject().Remove("groupPermission");
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
        }, GroupPermissionContract.Options));
    }
    internal GroupPermissionRoot Root(string operation, GroupPermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization, operation,
            GroupPermissionContract.Variant(action), boundary, "local", "group-coordinator", MemberPermissionSourceKind.ControlledFixture,
            GroupPermissionContract.Scope(operation), GroupPermissionContract.ActorKind(operation), action, Authorities, Profile);
    private MemberPermissionBorrowed[] Borrowed() => hostTokens.Select(p => new MemberPermissionBorrowed("host-credential", p.Key, GroupPermissionContract.Hash(p.Value)))
        .Concat(writers.Values.Select(w => new MemberPermissionBorrowed("host-key", w.Pin.Writer, GroupPermissionContract.Hash(w.Pin.Spki))))
        .Concat(borrowedObjects.Select(p => new MemberPermissionBorrowed(p.Value, p.Key, GroupPermissionContract.Hash(p.Value)))).ToArray();
    private GroupPermissionIssued Issued => new(actors, storageBindings.ToArray());
    private string Id(string key) => Issued.Id(key);
    private string CommitCreation(string key, string? request = null, bool admitted = false)
    {
        GroupPermissionContract.Require(root is not null && plan is not null && !closed && (!closing || admitted) && !resources.ContainsKey(key) &&
            !storageBindings.Any(b => b.Intent == key));
        var intent = plan!.Intents.Single(i => i.Key == key);
        GroupPermissionContract.Require(Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0));
        // There is deliberately no ID-generation path in Reserve or plan construction.
        string canonical = Guid.NewGuid().ToString();
        var binding = new GroupPermissionBinding(key, GroupPermissionContract.Hash(intent), intent.Work, intent.Kind, Id(intent.Scope),
            GroupPermissionPlan.InputHash(intent, Id), canonical, request ?? Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"));
        issuanceBindings.Add(binding); storageBindings.Add(binding); resources.Add(key, new(key, canonical));
        return canonical;
    }
    private GroupPermissionActor IssueActor(int i)
    {
        string key = plan!.ActorKey(i), scope = Id(plan.ActorScope(i)); var kind = plan.ActorKind(i);
        bool owned = !key.StartsWith("@", StringComparison.Ordinal);
        if (owned && Id(key).Length == 0) CommitCreation(key);
        string principal = Id(key); GroupPermissionCredential credential; byte[] bytes;
        if (owned)
        {
            (credential, bytes) = IssueCredential("actor-credential-" + i, principal, kind, scope);
        }
        else
        {
            bytes = Encoding.UTF8.GetBytes(hostTokens[principal]);
            credential = new("host-" + principal, principal, kind, scope, GroupPermissionContract.RawHash(bytes), false);
            CryptographicOperations.ZeroMemory(bytes); bytes = [];
            if (!credentials.Any(c => c.Id == credential.Id)) credentials.Add(credential);
        }
        CommitCreation(plan.ActorMembership(i));
        return new(principal, kind, scope, credential.Id, credential.Hash, bytes, owned);
    }
    private (GroupPermissionCredential Credential, byte[] Bytes) IssueCredential(string key, string principal, MemberPermissionActorKind kind, string scope)
    {
        string id = CommitCreation(key);
        byte[] random = RandomNumberGenerator.GetBytes(32), bytes;
        try { bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(random)); } finally { CryptographicOperations.ZeroMemory(random); }
        privateBuffers.Add(bytes); Copies.Add(bytes);
        var credential = new GroupPermissionCredential(id, principal, kind, scope, GroupPermissionContract.RawHash(bytes), true);
        credentials.Add(credential); tokens.Add(Encoding.ASCII.GetString(bytes), credential); return (credential, bytes);
    }
    private void Open()
    {
        Opens++; CommitCreation(GroupPermissionPlan.OtherOrganization);
        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
        CommitCreation(GroupPermissionPlan.Project); CommitCreation(GroupPermissionPlan.OtherProject); CommitCreation(GroupPermissionPlan.AssignedRole);
        foreach (string key in new[] { "issuer-work", "dispatch-work", "registration", "canary", "owned-key" }) CommitCreation(key);
        ownedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        actors = Enumerable.Range(0, root!.ScopeProfile == GroupPermissionScope.Organization ? 4 : 3).Select(IssueActor).ToArray();
        foreach (var row in plan!.Rows)
        {
            CommitCreation(row.User); CommitCreation(row.Identity);
            _ = IssueCredential(row.User + "-credential", Id(row.User), MemberPermissionActorKind.User, Id(row.Organization));
            _ = IssueCredential(row.Identity + "-credential", Id(row.Identity), MemberPermissionActorKind.Machine, Id(row.Organization));
            if (root.ScopeProfile == GroupPermissionScope.Project || row.Action != GroupPermissionAction.Create)
            {
                CommitCreation(row.Group);
                if (row.Action != GroupPermissionAction.AddMembers) CommitCreation(row.UserLink);
                if (row.Action != GroupPermissionAction.AddIdentities) CommitCreation(row.IdentityLink);
            }
            if (row.Window != "copy") Bootstrap(row);
        }
        assigned = !root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        if (assigned)
        {
            CommitCreation(plan.PolicyKey);
            string[] actions = root.ScopeProfile == GroupPermissionScope.Project ? ["read", "create", "delete", "assign-role"] :
                ["read", "create", "edit", "delete", "grant-privileges", "add-identities", "add-members", "remove-members", "remove-identities"];
            string baseline = actions[(Array.IndexOf(actions, GroupPermissionContract.Wire(root.Action)) + 1) % actions.Length];
            policy = new(Id(plan.PolicyKey), revision, actors[0].Principal, actors[0].Kind, Organization,
                root.ScopeProfile == GroupPermissionScope.Project ? Id(GroupPermissionPlan.Project) : "", "groups", [baseline],
                baseline == "assign-role" ? plan.Rows.Where(r => r.Control == "selected").Select(r => r.Name).ToArray() : [], baseline == "assign-role" ? plan.Role : "");
        }
        if (Fault == "delayed-issuer")
        {
            delayed = IssueDelayedAsync(); throw new NativeCaseFailureException("observer-unavailable");
        }
        if (Fault == "lost-open") throw new NativeCaseFailureException("observer-unavailable");
    }
    private async Task IssueDelayedAsync()
    {
        IssuerEntered.TrySetResult(); await IssuerRelease.Task.WaitAsync(shutdown.Token);
        lock (gate) CommitCreation(GroupPermissionPlan.Template, admitted: true);
    }
    private void Bootstrap(GroupPermissionRow row)
    {
        if (row.Action == GroupPermissionAction.Create) return;
        CommitCreation(row.Membership);
        states.Add(row.Key, plan!.Initial(row, Issued));
    }
    internal GroupPermissionPacket Step(GroupPermissionRoot selected, GroupPermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == GroupPermissionStep.Reserve)
            {
                GroupPermissionContract.Require(root is null && capability == "group-capability" && selected.Origin == Origin.AbsoluteUri &&
                    selected.Organization == Organization && selected.Authorities == Authorities && GroupPermissionContract.Hash(Profile) == GroupPermissionContract.Hash(selected.Profile));
                root = selected; plan = new(selected);
                if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
            }
            GroupPermissionContract.Require(root is not null && GroupPermissionContract.Hash(root) == GroupPermissionContract.Hash(selected) && !closed &&
                (step == GroupPermissionStep.Close || stage == (int)step));
            if (step != GroupPermissionStep.Close) stage++;
            switch (step)
            {
                case GroupPermissionStep.Open: Open(); break;
                case GroupPermissionStep.Before: Clear(); window = "before"; break;
                case GroupPermissionStep.Arm: Clear(); window = ""; armed = true; break;
                case GroupPermissionStep.Settle: settled = true; break;
                case GroupPermissionStep.After:
                    ingress.RemoveAll(e => e.Phase != "activation"); commits.RemoveAll(c => !ingress.Any(e => e.Request == c.Request));
                    decisions.Clear(); changes.Clear(); window = "after"; break;
                case GroupPermissionStep.ObserveBefore:
                case GroupPermissionStep.ObserveAfter: window = ""; break;
                case GroupPermissionStep.Close:
                    Closes++;
                    GroupPermissionContract.Require(closing && (delayed is null || delayed.IsCompletedSuccessfully));
                    // Reconcile native IDs from original-root issuance AND storage, not the Open reply.
                    GroupPermissionContract.Require(issuanceBindings.SequenceEqual(storageBindings));
                    foreach (var binding in storageBindings)
                        GroupPermissionContract.Require(binding.IntentHash == GroupPermissionContract.Hash(plan!.Intents.Single(i => i.Key == binding.Intent)) &&
                            !borrowed.Any(b => b.Id == binding.CanonicalId));
                    foreach (var binding in storageBindings)
                    {
                        var native = resources.SingleOrDefault(r => r.Value.CanonicalId == binding.CanonicalId);
                        if (native.Key is null) continue; // A witnessed downstream delete may already have removed it.
                        GroupPermissionContract.Require(native.Value.Intent == binding.Intent);
                        resources.Remove(native.Key);
                    }
                    states.Clear(); credentials.Clear(); tokens.Clear(); policy = copiedPolicy = null;
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
    private GroupPermissionSigned<T> Sign<T>(GroupPermissionStep step, GroupPermissionJournal journal, T content) => writers[journal].Sign(root!, step, content);
    private GroupPermissionJoin[] Joins()
    {
        if (closed) return [];
        var list = new List<GroupPermissionJoin>();
        foreach (var row in plan!.Rows)
            foreach (var pair in new[] { (row.UserLink, row.User, "user"), (row.IdentityLink, row.Identity, "machine"), (row.Membership, row.Group, "group") })
                if (resources.ContainsKey(pair.Item1)) list.Add(new(Id(pair.Item2), pair.Item3, Id(row.Organization), pair.Item3 == "group" ? Id(row.Project) : "",
                    Id(row.Group), Id(pair.Item1), false));
        for (int i = 0; i < actors.Length; i++) list.Add(new(actors[i].Principal, actors[i].Kind == MemberPermissionActorKind.User ? "user" : "machine",
            actors[i].Organization, root!.ScopeProfile == GroupPermissionScope.Project ? Id(GroupPermissionPlan.Project) : "", "", Id(plan.ActorMembership(i)),
            i == 0 && (!GroupPermissionContract.Create(root.Operation) || assigned && !copied)));
        if (copied) list.Add(new(actors[0].Principal, "user", Organization, Id(GroupPermissionPlan.CopyProject), "", Id(plan.ActorMembership(0, true)), true));
        return list.ToArray();
    }
    private GroupPermissionPacket Packet(GroupPermissionStep step)
    {
        bool open = step == GroupPermissionStep.Open, observe = step is GroupPermissionStep.ObserveBefore or GroupPermissionStep.ObserveAfter;
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
        var allPolicies = new[] { policy, copiedPolicy }.OfType<GroupPermissionPolicy>().OrderBy(p => p.Resource).ToArray();
        var committed = observe || step == GroupPermissionStep.Settle ? commits.ToArray() : [];
        if (step == GroupPermissionStep.Settle && Fault == "wrong-policy-target" && committed.Length == 1)
        { committed[0] = committed[0] with { Policy = committed[0].Policy with { Resource = Guid.NewGuid().ToString() } }; allPolicies = [committed[0].Policy]; }
        var intents = plan!.Intents.ToArray();
        if (open && Fault == "intent-mutation") intents[0] = intents[0] with { Input = "changed" };
        var packet = new GroupPermissionPacket(
            Sign(step, GroupPermissionJournal.Ownership, new GroupPermissionOwner(intents, resources.Values.ToArray(), Borrowed(), true, true,
                settled || closed, settled || closed, open && Fault == "pending-issuer" ? 1 : 0, closed ? 0 : 1, open ? actors : [])),
            Sign(step, GroupPermissionJournal.Ingress, observe || step == GroupPermissionStep.Settle ? ingress.ToArray() : []),
            Sign(step, GroupPermissionJournal.Policy, new GroupPermissionPolicies(allPolicies, committed)),
            Sign(step, GroupPermissionJournal.Storage, new GroupPermissionStorage(storage, inventory, observe ? changes.ToArray() : [])),
            Sign(step, GroupPermissionJournal.Issuer, new GroupPermissionIssuance(issue, credentialRows)),
            Sign(step, GroupPermissionJournal.Membership, joins), Sign(step, GroupPermissionJournal.Access, observe ? decisions.ToArray() : []), []);
        var seals = new List<GroupPermissionSigned<MemberPermissionSeal>>();
        Add(GroupPermissionJournal.Ownership, packet.Owner.Payload); Add(GroupPermissionJournal.Ingress, packet.Ingress.Payload);
        Add(GroupPermissionJournal.Policy, packet.Policy.Payload); Add(GroupPermissionJournal.Storage, packet.Storage.Payload);
        Add(GroupPermissionJournal.Issuer, packet.Issuer.Payload); Add(GroupPermissionJournal.Membership, packet.Membership.Payload); Add(GroupPermissionJournal.Access, packet.Access.Payload);
        return packet with { Seals = open && Fault == "missing-seal" ? seals.Skip(1).ToArray() : seals.ToArray() };
        void Add<T>(GroupPermissionJournal journal, T payload) => seals.Add(Sign(step, journal,
            new MemberPermissionSeal(GroupPermissionContract.Hash(payload), !(open && Fault == "nonterminal"), 0, 1)));
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
                GroupPermissionContract.Require(length is >= 0 and <= 131072);
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
    private GroupPermissionCredential Authenticate(string bearer)
    {
        if (tokens.TryGetValue(bearer, out var credential)) return credential;
        string principal = hostTokens.SingleOrDefault(p => p.Value == bearer).Key ?? "unknown";
        byte[] bytes = Encoding.UTF8.GetBytes(bearer);
        try { return new("host-" + principal, principal, MemberPermissionActorKind.Machine, Organization, GroupPermissionContract.RawHash(bytes), false); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private void Record(string request, GroupPermissionCredential actor, string method, string path, byte[] bytes, string intent, bool allowed, string phase) =>
        ingress.Add(new(request, actor.Principal, actor.Kind, actor.Hash, actor.Organization, method, path, GroupPermissionContract.RawHash(bytes), intent, allowed, phase));
    private (int, object) Handle(string method, Uri uri, string bearer, JsonElement body, byte[] bytes)
    {
        if (root is null || actors.Length == 0 || closed || closing) return (403, new { });
        var actor = Authenticate(bearer); string path = uri.AbsolutePath;
        bool template = root.Operation.Contains("ProjectTemplate", StringComparison.Ordinal), organization = root.Operation.EndsWith("OrganizationRole", StringComparison.Ordinal),
            privilege = root.Operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal), create = root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        string originalPath = (template ? "/api/v1/project-templates" : organization ? "/api/v1/organization/roles" : privilege ?
            "/api/v2/identity-project-additional-privilege" : "/api/v1/projects/" + Id(GroupPermissionPlan.Project) + "/roles") + (create ? "" : "/" + Id(plan!.PolicyKey));
        if (path == originalPath && method == (create ? "POST" : "PATCH"))
        {
            if (!armed || settled || Originals != 0) return (409, new { });
            Originals++; string request = Guid.NewGuid().ToString("N"), intent = GroupPermissionContract.RawHash(bytes);
            if (privilege) intent = WireHash(new object?[] { plan!.ProjectSlug, Id(plan.ActorMembership(0)), create ? null : Id(plan.PolicyKey), body });
            bool allowed = actor.Principal == Authorities.Administrative && actor.Kind == MemberPermissionActorKind.Machine && actor.Organization == Organization;
            Record(request, actor, method, path, bytes, intent, allowed, "original");
            if (!allowed) return (403, new { });
            var permissions = template ? body.GetProperty("roles")[0].GetProperty("permissions") : body.GetProperty("permissions");
            var permission = permissions.EnumerateArray().Single();
            var actions = permission.GetProperty("action");
            string[] selected = actions.ValueKind == JsonValueKind.Array ? actions.EnumerateArray().Select(a => a.GetString()!).ToArray() : [actions.GetString()!];
            string principal = privilege && create ? body.GetProperty("identityId").GetString()! : actors[0].Principal;
            if (template && body.GetProperty("users")[0].GetProperty("username").GetString() != plan!.Username(plan.ActorKey(0))) return (400, new { });
            string[] names = permission.TryGetProperty("conditions", out var conditions) ? conditions.GetProperty("groupName").GetProperty("$in")
                .EnumerateArray().Select(n => n.GetString()!).ToArray() : [];
            string role = conditions.ValueKind == JsonValueKind.Object ? conditions.GetProperty("assignableRole").GetString()! : "";
            if (Fault is not ("ignored-policy" or "lost-nonapplied"))
            {
                if (create) CommitCreation(plan!.PolicyKey, request);
                string old = revision; revision = "policy-2";
                policy = new(Id(plan!.PolicyKey), revision, principal, actors[0].Kind, Organization, organization ? "" : Id(GroupPermissionPlan.Project),
                    permission.GetProperty("subject").GetString()!, Fault == "partial" ? [] : selected, names, role);
                commits.Add(new(request, old, policy)); if (privilege) assigned = true;
            }
            var result = new JsonObject
            {
                ["id"] = Id(plan!.PolicyKey),
                ["slug"] = plan.Slug,
                ["createdAt"] = "2026-01-01T00:00:00Z",
                ["updatedAt"] = "2026-01-01T00:00:01Z",
                ["permissions"] = JsonNode.Parse(permissions.GetRawText())
            };
            if (template)
            {
                result.Remove("slug"); result.Remove("permissions"); result["name"] = plan.Slug; result["orgId"] = Organization; result["type"] = "secret-manager";
                result["groups"] = new JsonArray(); result["identities"] = new JsonArray(); result["projectManagedIdentities"] = new JsonArray();
                foreach (string property in new[] { "roles", "environments", "users" }) result[property] = JsonNode.Parse(body.GetProperty(property).GetRawText());
            }
            else if (privilege) result["isTemporary"] = false;
            else { result["name"] = plan.Slug; result[organization ? "orgId" : "projectId"] = organization ? Organization : Id(GroupPermissionPlan.Project); }
            return (200, new JsonObject { [template ? "projectTemplate" : privilege ? "privilege" : "role"] = result });
        }
        if (settled && actor.Principal == Authorities.Setup && actor.Kind == MemberPermissionActorKind.Machine && policy is not null &&
            (path == "/api/v1/projects" || path.EndsWith("/" + Id(plan!.ActorMembership(0)), StringComparison.Ordinal)))
            return Activate(actor, method, path, body, bytes);
        return GroupAction(actor, method, path, body, bytes);
    }
    private (int, object) Activate(GroupPermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        string request = Guid.NewGuid().ToString("N");
        if (path == "/api/v1/projects")
        {
            if (copied || method != "POST" || body.GetProperty("template").GetString() != plan!.Slug || body.GetProperty("slug").GetString() != plan.CopySlug) return (403, new { });
            CommitCreation(GroupPermissionPlan.CopyProject, request); CommitCreation(plan.ActorMembership(0, true));
            copied = true; assigned = true;
            foreach (var row in plan.Rows.Where(r => r.Window == "copy")) Bootstrap(row);
            copiedPolicy = policy! with
            {
                Resource = Id(GroupPermissionPlan.CopyProject),
                Project = Id(GroupPermissionPlan.CopyProject),
                Actions = Fault == "template-echo" ? [] : policy.Actions
            };
            Record(request, actor, method, path, bytes, GroupPermissionContract.RawHash(bytes), true, "activation");
            commits.Add(new(request, revision, copiedPolicy));
            return (200, new
            {
                project = new
                {
                    id = Id(GroupPermissionPlan.CopyProject),
                    _id = Id(GroupPermissionPlan.CopyProject),
                    orgId = Organization,
                    name = plan.CopySlug,
                    slug = plan.CopySlug,
                    type = "secret-manager",
                    createdAt = "2026-01-01T00:00:00Z",
                    updatedAt = "2026-01-01T00:00:00Z",
                    environments = Array.Empty<object>(),
                    deletedEnvironments = Array.Empty<object>()
                }
            });
        }
        if (assigned || method != "PATCH") return (403, new { });
        bool org = path.StartsWith("/api/v2/organizations/", StringComparison.Ordinal);
        string selected = org ? body.GetProperty("role").GetString()! : body.GetProperty("roles")[0].GetProperty("role").GetString()!;
        if (selected != plan!.Slug) return (403, new { });
        assigned = Fault != "assignment-echo";
        Record(request, actor, method, path, bytes, org ? GroupPermissionContract.RawHash(bytes) : WireHash(new object?[] { null, body }), true, "activation");
        commits.Add(new(request, revision, policy!));
        return org ? (200, new
        {
            membership = new
            {
                id = Id(plan.ActorMembership(0)),
                userId = actors[0].Principal,
                orgId = Organization,
                role = selected,
                isActive = true,
                status = "accepted",
                createdAt = "2026-01-01T00:00:00Z",
                updatedAt = "2026-01-01T00:00:00Z"
            }
        }) :
            (200, new { roles = new[] { Role(Id(plan.ActorMembership(0)), selected) } });
    }
    private (int, object) GroupAction(GroupPermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        if (window is not ("before" or "after")) return (403, new { });
        string[] parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        bool projectScope = parts.Length >= 7 && parts[2] == "projects" && parts[4] == "memberships" && parts[5] == "groups";
        string project = projectScope ? parts[3] : "", group = projectScope ? parts[6] : parts.Length > 3 ? parts[3] : "";
        GroupPermissionAction action = method switch
        {
            "GET" => GroupPermissionAction.Read,
            "POST" => parts.Contains("users") ? GroupPermissionAction.AddMembers : parts.Contains("machine-identities") ? GroupPermissionAction.AddIdentities : GroupPermissionAction.Create,
            "DELETE" => parts.Contains("users") ? GroupPermissionAction.RemoveMembers : parts.Contains("machine-identities") ? GroupPermissionAction.RemoveIdentities : GroupPermissionAction.Delete,
            "PATCH" => projectScope ? GroupPermissionAction.AssignRole : body.TryGetProperty("role", out _) ? GroupPermissionAction.GrantPrivileges : GroupPermissionAction.Edit,
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        var row = action == GroupPermissionAction.Create && !projectScope ? plan!.Rows.SingleOrDefault(r => r.Name == body.GetProperty("name").GetString() && Id(r.Organization) == actor.Organization) :
            plan!.Rows.SingleOrDefault(r => Id(r.Group) == group && Id(r.Project) == project);
        if (row is null) return (404, new { });
        string org = Id(row.Organization), user = Id(row.User), identity = Id(row.Identity);
        if (parts.Contains("users") && Uri.UnescapeDataString(parts.Last()) != plan.Username(row.User) || parts.Contains("machine-identities") && parts.Last() != identity) return (404, new { });
        var effective = project == Id(GroupPermissionPlan.CopyProject) && copied ? copiedPolicy : policy;
        string wire = GroupPermissionContract.Wire(action);
        string selectedRole = action == GroupPermissionAction.AssignRole ? body.GetProperty("roles")[0].GetProperty("role").GetString()! : "";
        bool allowed = assigned && effective is not null && effective.Subject == "groups" && effective.Actor == actor.Principal && effective.Kind == actor.Kind &&
            actor.Organization == org && effective.Organization == org && effective.Project == project && effective.Actions.Contains(wire) &&
            (action != GroupPermissionAction.AssignRole || effective.Names.Contains(row.Name) && effective.Role == selectedRole);
        if (Fault == "action-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && org == Organization &&
            project == (root!.ScopeProfile == GroupPermissionScope.Organization ? "" : copied ? Id(GroupPermissionPlan.CopyProject) : Id(GroupPermissionPlan.Project))) allowed = true;
        if (Fault == "scope-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && policy?.Actions.Contains(wire) == true) allowed = true;
        string request = Guid.NewGuid().ToString("N"); var recorded = Fault == "wrong-actor" ? actor with { Principal = Authorities.Observer } : actor;
        if (Fault == "wrong-credential") recorded = recorded with { Hash = "wrong" };
        Record(request, recorded, method, path, bytes, "", allowed, "action");
        var previous = states.GetValueOrDefault(row.Key); object response = new { };
        if (allowed)
        {
            switch (action)
            {
                case GroupPermissionAction.Create:
                    if (projectScope)
                    {
                        if (body.GetProperty("role").GetString() != "no-access") return (400, new { });
                        CommitCreation(row.Membership, request);
                    }
                    else
                    {
                        if (body.GetProperty("slug").GetString() != row.Name || body.GetProperty("role").GetString() != "no-access") return (400, new { });
                        CommitCreation(row.Group, request); CommitCreation(row.Membership);
                    }
                    states.Add(row.Key, plan.Initial(row, Issued));
                    response = projectScope ? new { groupMembership = ProjectRow(states[row.Key]) } : GroupRow(states[row.Key]); break;
                case GroupPermissionAction.Delete:
                    response = projectScope ? new { groupMembership = ProjectDeletedRow(previous!) } : GroupRow(previous!);
                    states.Remove(row.Key); resources.Remove(row.Membership);
                    if (!projectScope) { resources.Remove(row.Group); resources.Remove(row.UserLink); resources.Remove(row.IdentityLink); }
                    break;
                case GroupPermissionAction.Edit:
                    states[row.Key] = previous! with { Name = body.GetProperty("name").GetString()!, Version = previous.Version + 1 };
                    response = GroupRow(states[row.Key]); break;
                case GroupPermissionAction.GrantPrivileges:
                case GroupPermissionAction.AssignRole:
                    states[row.Key] = previous! with { Role = projectScope ? selectedRole : body.GetProperty("role").GetString()!, Version = previous.Version + 1 };
                    response = projectScope ? new { roles = new[] { Role(previous!.Membership, selectedRole) } } : GroupRow(states[row.Key]); break;
                case GroupPermissionAction.AddMembers:
                    CommitCreation(row.UserLink, request); states[row.Key] = previous! with { UserLink = Id(row.UserLink), Version = previous.Version + 1 };
                    response = new { id = user, username = plan.Username(row.User) }; break;
                case GroupPermissionAction.RemoveMembers:
                    resources.Remove(row.UserLink); states[row.Key] = previous! with { UserLink = "", Version = previous.Version + 1 };
                    response = new { id = user, username = plan.Username(row.User) }; break;
                case GroupPermissionAction.AddIdentities:
                    CommitCreation(row.IdentityLink, request); states[row.Key] = previous! with { IdentityLink = Id(row.IdentityLink), Version = previous.Version + 1 };
                    response = new { id = Id(row.IdentityLink) }; break;
                case GroupPermissionAction.RemoveIdentities:
                    resources.Remove(row.IdentityLink); states[row.Key] = previous! with { IdentityLink = "", Version = previous.Version + 1 };
                    response = new { id = previous!.IdentityLink }; break;
                case GroupPermissionAction.Read:
                    response = projectScope ? new { groupMembership = ProjectRow(previous!) } : GroupRow(previous!, read: true); break;
            }
            if (Fault == "wrong-group" && states.TryGetValue(row.Key, out var changed)) states[row.Key] = changed with { Group = Guid.NewGuid().ToString() };
            if (Fault == "wrong-member" && states.TryGetValue(row.Key, out var member)) states[row.Key] = member with { User = Guid.NewGuid().ToString() };
        }
        decisions.Add(new(request, recorded.Principal, recorded.Kind, recorded.Id, recorded.Hash, org, project, Id(row.Group), Id(row.Membership), user, identity, revision, action, allowed));
        changes.Add(new(request, row.Key, previous, states.GetValueOrDefault(row.Key)));
        return (allowed ? 200 : 403, response);
    }
    private object Role(string membership, string role) => new
    {
        id = Id(GroupPermissionPlan.AssignedRole),
        projectMembershipId = membership,
        role,
        isTemporary = false,
        createdAt = "2026-01-01T00:00:00Z",
        updatedAt = "2026-01-01T00:00:01Z"
    };
    private object ProjectRow(GroupPermissionState state) => new
    {
        id = state.Membership,
        groupId = state.Group,
        projectId = state.Project,
        group = new { id = state.Group, orgId = state.Organization, name = state.Name, slug = state.Name },
        roles = new[] { new { id = Id(GroupPermissionPlan.AssignedRole), role = state.Role, isTemporary = false } },
        createdAt = "2026-01-01T00:00:00Z",
        updatedAt = "2026-01-01T00:00:01Z"
    };
    private static object ProjectDeletedRow(GroupPermissionState state) => new
    {
        id = state.Membership,
        groupId = state.Group,
        projectId = state.Project,
        createdAt = "2026-01-01T00:00:00Z",
        updatedAt = "2026-01-01T00:00:01Z"
    };
    private static object GroupRow(GroupPermissionState state, bool read = false)
    {
        var value = new Dictionary<string, object?>
        {
            ["id"] = state.Group,
            ["orgId"] = state.Organization,
            ["name"] = state.Name,
            ["slug"] = state.Name,
            ["createdAt"] = "2026-01-01T00:00:00Z",
            ["updatedAt"] = "2026-01-01T00:00:01Z"
        };
        if (read) value["customRoleSlug"] = null;
        return value;
    }
    private static string WireHash(object value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        try { return GroupPermissionContract.RawHash(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
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
