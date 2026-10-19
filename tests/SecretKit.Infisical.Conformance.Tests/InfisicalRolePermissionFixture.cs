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
internal sealed class InfisicalRolePermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static MemberPermissionAuthorities Authorities => InfisicalMemberPermissionFixture.Authorities;
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<RolePermissionJournal, InfisicalRolePermissionWriter> writers = [];
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
        ["30000000-0000-0000-0000-000000000001"] = "borrowed-target-role",
        ["30000000-0000-0000-0000-000000000002"] = "borrowed-user",
        ["30000000-0000-0000-0000-000000000003"] = "borrowed-machine",
        ["30000000-0000-0000-0000-000000000004"] = "borrowed-membership",
        ["30000000-0000-0000-0000-000000000005"] = "borrowed-policy-role"
    };
    private readonly Dictionary<string, RolePermissionCredential> tokens = [];
    private readonly List<RolePermissionCredential> credentials = [];
    private readonly List<RolePermissionBinding> issuanceBindings = [], storageBindings = [];
    private readonly Dictionary<string, RolePermissionResource> resources = [];
    private readonly Dictionary<string, RolePermissionState> states = [];
    private readonly List<RolePermissionIngress> ingress = [];
    private readonly List<RolePermissionCommit> commits = [];
    private readonly List<RolePermissionAccess> decisions = [];
    private readonly List<RolePermissionChange> changes = [];
    private readonly List<byte[]> privateBuffers = [];
    private readonly MemberPermissionBorrowed[] borrowed;
    private RolePermissionRoot? root;
    private RolePermissionPlan? plan;
    private RolePermissionActor[] actors = [];
    private RolePermissionPolicy? policy, copiedPolicy;
    private ECDsa? ownedKey;
    private string revision = "policy-1", window = "";
    private int stage;
    private bool closed, closing, armed, settled, assigned, copied;
    private Task? delayed;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal RolePermissionProfile Profile { get; }
    internal InfisicalRolePermissionFixtureSource Source { get; }
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
    internal InfisicalRolePermissionFixture(string fault = "")
    {
        Fault = fault;
        foreach (var journal in Enum.GetValues<RolePermissionJournal>()) writers.Add(journal, new(journal));
        Profile = new("controlled-roles", "controlled-epoch", "controlled-v1", writers.Values.Select(w => w.Pin).ToArray());
        borrowed = Borrowed(); listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/"); Source = new(this); accept = AcceptAsync();
    }
    internal RolePermissionInput Input(string operation, RolePermissionAction action) =>
        new(new(new("https://role-source.invalid/"), "coordinator-token", "role-coordinator", 30), "role-capability", Profile,
            RolePermissionContract.Scope(operation), RolePermissionContract.ActorKind(operation), action, 30);
    internal NativeEnvironment Environment(string operation, RolePermissionAction action, bool configured = true)
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
                    rolePermission = Input(operation, action)
                }
            }
        }, RolePermissionContract.Options)!;
        if (!configured) scope["scopes"]!["local"]!.AsObject().Remove("rolePermission");
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
        }, RolePermissionContract.Options));
    }
    internal RolePermissionRoot Root(string operation, RolePermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization, operation,
            RolePermissionContract.Variant(action), boundary, "local", "role-coordinator", MemberPermissionSourceKind.ControlledFixture,
            RolePermissionContract.Scope(operation), RolePermissionContract.ActorKind(operation), action, Authorities, Profile);
    private MemberPermissionBorrowed[] Borrowed() => hostTokens.Select(p => new MemberPermissionBorrowed("host-credential", p.Key, RolePermissionContract.Hash(p.Value)))
        .Concat(writers.Values.Select(w => new MemberPermissionBorrowed("host-key", w.Pin.Writer, RolePermissionContract.Hash(w.Pin.Spki))))
        .Concat(borrowedObjects.Select(p => new MemberPermissionBorrowed(p.Value, p.Key, RolePermissionContract.Hash(p.Value)))).ToArray();
    private RolePermissionIssued Issued => new(actors, storageBindings.ToArray());
    private string Id(string key) => Issued.Id(key);
    private string CommitCreation(string key, string? request = null, bool admitted = false)
    {
        RolePermissionContract.Require(root is not null && plan is not null && !closed && (!closing || admitted) && !resources.ContainsKey(key) &&
            !storageBindings.Any(b => b.Intent == key));
        var intent = plan!.Intents.Single(i => i.Key == key);
        RolePermissionContract.Require(Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0));
        // There is deliberately no ID-generation path in Reserve or plan construction.
        string canonical = Guid.NewGuid().ToString();
        var binding = new RolePermissionBinding(key, RolePermissionContract.Hash(intent), intent.Work, intent.Kind, Id(intent.Scope),
            RolePermissionPlan.InputHash(intent, Id), canonical, request ?? Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"));
        issuanceBindings.Add(binding); storageBindings.Add(binding); resources.Add(key, new(key, canonical));
        return canonical;
    }
    private RolePermissionActor IssueActor(int i)
    {
        string key = plan!.ActorKey(i), scope = Id(plan.ActorScope(i)); var kind = plan.ActorKind(i);
        bool owned = !key.StartsWith("@", StringComparison.Ordinal);
        if (owned && Id(key).Length == 0) CommitCreation(key);
        string principal = Id(key); RolePermissionCredential credential; byte[] bytes;
        if (owned)
        {
            (credential, bytes) = IssueCredential("actor-credential-" + i, principal, kind, scope);
        }
        else
        {
            bytes = Encoding.UTF8.GetBytes(hostTokens[principal]);
            credential = new("host-" + principal, principal, kind, scope, RolePermissionContract.RawHash(bytes), false);
            CryptographicOperations.ZeroMemory(bytes); bytes = [];
            if (!credentials.Any(c => c.Id == credential.Id)) credentials.Add(credential);
        }
        CommitCreation(plan.ActorMembership(i));
        return new(principal, kind, scope, credential.Id, credential.Hash, bytes, owned);
    }
    private (RolePermissionCredential Credential, byte[] Bytes) IssueCredential(string key, string principal, MemberPermissionActorKind kind, string scope)
    {
        string id = CommitCreation(key);
        byte[] random = RandomNumberGenerator.GetBytes(32), bytes;
        try { bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(random)); } finally { CryptographicOperations.ZeroMemory(random); }
        privateBuffers.Add(bytes); Copies.Add(bytes);
        var credential = new RolePermissionCredential(id, principal, kind, scope, RolePermissionContract.RawHash(bytes), true);
        credentials.Add(credential); tokens.Add(Encoding.ASCII.GetString(bytes), credential); return (credential, bytes);
    }
    private void Open()
    {
        Opens++; CommitCreation(RolePermissionPlan.OtherOrganization);
        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
        CommitCreation(RolePermissionPlan.Project); CommitCreation(RolePermissionPlan.OtherProject);
        foreach (string key in new[] { "issuer-work", "dispatch-work", "registration", "canary", "owned-key" }) CommitCreation(key);
        ownedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        actors = Enumerable.Range(0, root!.ScopeProfile == RolePermissionScope.Organization ? 4 : 3).Select(IssueActor).ToArray();
        foreach (var row in plan!.Rows.Where(r => r.Window != "copy")) Bootstrap(row);
        assigned = !root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        if (assigned)
        {
            CommitCreation(plan.PolicyKey);
            string[] actions = ["read", "create", "edit", "delete"];
            string baseline = actions[(Array.IndexOf(actions, RolePermissionContract.Wire(root.Action)) + 1) % actions.Length];
            policy = new(Id(plan.PolicyKey), revision, actors[0].Principal, actors[0].Kind, Organization,
                root.ScopeProfile == RolePermissionScope.Project ? Id(RolePermissionPlan.Project) : "", "role", [baseline], [], plan.Slug);
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
        lock (gate) CommitCreation(RolePermissionPlan.Deferred, admitted: true);
    }
    private void Bootstrap(RolePermissionRow row)
    {
        if (row.Action == RolePermissionAction.Create) return;
        CommitCreation(row.Target);
        states.Add(row.Key, plan!.Initial(row, Issued));
    }
    internal RolePermissionPacket Step(RolePermissionRoot selected, RolePermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == RolePermissionStep.Reserve)
            {
                RolePermissionContract.Require(root is null && capability == "role-capability" && selected.Origin == Origin.AbsoluteUri &&
                    selected.Organization == Organization && selected.Authorities == Authorities && RolePermissionContract.Hash(Profile) == RolePermissionContract.Hash(selected.Profile));
                root = selected; plan = new(selected);
                if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
            }
            RolePermissionContract.Require(root is not null && RolePermissionContract.Hash(root) == RolePermissionContract.Hash(selected) && !closed &&
                (step == RolePermissionStep.Close || stage == (int)step));
            if (step != RolePermissionStep.Close) stage++;
            switch (step)
            {
                case RolePermissionStep.Open: Open(); break;
                case RolePermissionStep.Before: Clear(); window = "before"; break;
                case RolePermissionStep.Arm: Clear(); window = ""; armed = true; break;
                case RolePermissionStep.Settle: settled = true; break;
                case RolePermissionStep.After:
                    ingress.RemoveAll(e => e.Phase != "activation"); commits.RemoveAll(c => !ingress.Any(e => e.Request == c.Request));
                    decisions.Clear(); changes.Clear(); window = "after"; break;
                case RolePermissionStep.ObserveBefore:
                case RolePermissionStep.ObserveAfter: window = ""; break;
                case RolePermissionStep.Close:
                    Closes++;
                    RolePermissionContract.Require(closing && (delayed is null || delayed.IsCompletedSuccessfully));
                    // Reconcile native IDs from original-root issuance AND storage, not the Open reply.
                    RolePermissionContract.Require(issuanceBindings.SequenceEqual(storageBindings));
                    foreach (var binding in storageBindings)
                        RolePermissionContract.Require(binding.IntentHash == RolePermissionContract.Hash(plan!.Intents.Single(i => i.Key == binding.Intent)) &&
                            !borrowed.Any(b => b.Id == binding.CanonicalId));
                    foreach (var binding in storageBindings)
                    {
                        var native = resources.SingleOrDefault(r => r.Value.CanonicalId == binding.CanonicalId);
                        if (native.Key is null) continue; // A witnessed downstream delete may already have removed it.
                        RolePermissionContract.Require(native.Value.Intent == binding.Intent);
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
    private RolePermissionSigned<T> Sign<T>(RolePermissionStep step, RolePermissionJournal journal, T content) => writers[journal].Sign(root!, step, content);
    private RolePermissionJoin[] Joins()
    {
        if (closed) return [];
        var joins = actors.Select((actor, i) => new RolePermissionJoin(actor.Principal,
            actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization,
            root!.ScopeProfile == RolePermissionScope.Project ? Id(RolePermissionPlan.Project) : "", Id(plan!.ActorMembership(i)),
            i == 0 && (!RolePermissionContract.Create(root.Operation) || assigned && !copied), i == 0 && (!RolePermissionContract.Create(root.Operation) || assigned && !copied) ? Id(plan.PolicyKey) : "",
            i == 0 && (!RolePermissionContract.Create(root.Operation) || assigned && !copied) ? Fault == "wrong-role-binding" ? "foreign-role" : plan.Slug : "no-access", true, "accepted")).ToList();
        if (copied) joins.Add(new(actors[0].Principal, "user", Organization, Id(RolePermissionPlan.CopyProject), Id(plan!.ActorMembership(0, true)),
            true, Id(RolePermissionPlan.CopiedRole), Fault == "wrong-role-binding" ? "foreign-role" : plan.Slug, true, "accepted"));
        return joins.ToArray();
    }
    private RolePermissionPacket Packet(RolePermissionStep step)
    {
        bool open = step == RolePermissionStep.Open, observe = step is RolePermissionStep.ObserveBefore or RolePermissionStep.ObserveAfter;
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
        var allPolicies = new[] { policy, copiedPolicy }.OfType<RolePermissionPolicy>().OrderBy(p => p.Resource).ToArray();
        var committed = observe || step == RolePermissionStep.Settle ? commits.ToArray() : [];
        if (step == RolePermissionStep.Settle && Fault == "wrong-policy-target" && committed.Length == 1)
        { committed[0] = committed[0] with { Policy = committed[0].Policy with { Resource = Guid.NewGuid().ToString() } }; allPolicies = [committed[0].Policy]; }
        var intents = plan!.Intents.ToArray();
        if (open && Fault == "intent-mutation") intents[0] = intents[0] with { Input = "changed" };
        var packet = new RolePermissionPacket(
            Sign(step, RolePermissionJournal.Ownership, new RolePermissionOwner(intents, resources.Values.ToArray(), Borrowed(), true, true,
                settled || closed, settled || closed, open && Fault == "pending-issuer" ? 1 : 0, closed ? 0 : 1, open ? actors : [])),
            Sign(step, RolePermissionJournal.Ingress, observe || step == RolePermissionStep.Settle ? ingress.ToArray() : []),
            Sign(step, RolePermissionJournal.Policy, new RolePermissionPolicies(allPolicies, committed)),
            Sign(step, RolePermissionJournal.Storage, new RolePermissionStorage(storage, inventory, observe ? changes.ToArray() : [])),
            Sign(step, RolePermissionJournal.Issuer, new RolePermissionIssuance(issue, credentialRows)),
            Sign(step, RolePermissionJournal.Membership, joins), Sign(step, RolePermissionJournal.Access, observe ? decisions.ToArray() : []), []);
        var seals = new List<RolePermissionSigned<MemberPermissionSeal>>();
        Add(RolePermissionJournal.Ownership, packet.Owner.Payload); Add(RolePermissionJournal.Ingress, packet.Ingress.Payload);
        Add(RolePermissionJournal.Policy, packet.Policy.Payload); Add(RolePermissionJournal.Storage, packet.Storage.Payload);
        Add(RolePermissionJournal.Issuer, packet.Issuer.Payload); Add(RolePermissionJournal.Membership, packet.Membership.Payload); Add(RolePermissionJournal.Access, packet.Access.Payload);
        return packet with { Seals = open && Fault == "missing-seal" ? seals.Skip(1).ToArray() : seals.ToArray() };
        void Add<T>(RolePermissionJournal journal, T payload) => seals.Add(Sign(step, journal,
            new MemberPermissionSeal(RolePermissionContract.Hash(payload), !(open && Fault == "nonterminal"), 0, 1)));
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
                RolePermissionContract.Require(length is >= 0 and <= 131072);
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
    private RolePermissionCredential Authenticate(string bearer)
    {
        if (tokens.TryGetValue(bearer, out var credential)) return credential;
        string principal = hostTokens.SingleOrDefault(p => p.Value == bearer).Key ?? "unknown";
        byte[] bytes = Encoding.UTF8.GetBytes(bearer);
        try { return new("host-" + principal, principal, MemberPermissionActorKind.Machine, Organization, RolePermissionContract.RawHash(bytes), false); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private void Record(string request, RolePermissionCredential actor, string method, string path, byte[] bytes, string intent, bool allowed, string phase) =>
        ingress.Add(new(request, actor.Principal, actor.Kind, actor.Hash, actor.Organization, method, path, RolePermissionContract.RawHash(bytes), intent, allowed, phase));
    private (int, object) Handle(string method, Uri uri, string bearer, JsonElement body, byte[] bytes)
    {
        if (root is null || actors.Length == 0 || closed || closing) return (403, new { });
        var actor = Authenticate(bearer); string path = uri.AbsolutePath;
        bool template = root.Operation.Contains("ProjectTemplate", StringComparison.Ordinal), organization = root.Operation.EndsWith("OrganizationRole", StringComparison.Ordinal),
            privilege = root.Operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal), create = root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        string originalPath = (template ? "/api/v1/project-templates" : organization ? "/api/v1/organization/roles" : privilege ?
            "/api/v2/identity-project-additional-privilege" : "/api/v1/projects/" + Id(RolePermissionPlan.Project) + "/roles") + (create ? "" : "/" + Id(plan!.PolicyKey));
        if (path == originalPath && method == (create ? "POST" : "PATCH") &&
            (template || privilege || body.TryGetProperty("slug", out var policySlug) && policySlug.GetString() == plan!.Slug))
        {
            if (!armed || settled || Originals != 0) return (409, new { });
            Originals++; string request = Guid.NewGuid().ToString("N"), intent = RolePermissionContract.RawHash(bytes);
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
            string[] names = permission.TryGetProperty("conditions", out _) ? ["unprojected-condition"] : [];
            string role = plan!.Slug;
            if (Fault is not ("ignored-policy" or "lost-nonapplied"))
            {
                if (create) CommitCreation(plan!.PolicyKey, request);
                string old = revision; revision = "policy-2";
                policy = new(Id(plan!.PolicyKey), revision, principal, actors[0].Kind, Organization, organization ? "" : Id(RolePermissionPlan.Project),
                    permission.GetProperty("subject").GetString()!, Fault == "partial" ? [] : selected, Fault == "wrong-condition" ? ["forged-condition"] : names, Fault == "incomplete-policy" ? "" : role);
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
            else { result["name"] = plan.Slug; result[organization ? "orgId" : "projectId"] = organization ? Organization : Id(RolePermissionPlan.Project); }
            return (200, new JsonObject { [template ? "projectTemplate" : privilege ? "privilege" : "role"] = result });
        }
        if (settled && actor.Principal == Authorities.Setup && actor.Kind == MemberPermissionActorKind.Machine && policy is not null &&
            (path == "/api/v1/projects" || path.EndsWith("/" + Id(plan!.ActorMembership(0)), StringComparison.Ordinal)))
            return Activate(actor, method, path, body, bytes);
        return TargetAction(actor, method, path, body, bytes);
    }
    private (int, object) Activate(RolePermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        string request = Guid.NewGuid().ToString("N");
        if (path == "/api/v1/projects")
        {
            if (copied || method != "POST" || body.GetProperty("template").GetString() != plan!.Slug || body.GetProperty("slug").GetString() != plan.CopySlug) return (403, new { });
            CommitCreation(RolePermissionPlan.CopyProject, request); CommitCreation(RolePermissionPlan.CopiedRole); CommitCreation(plan.ActorMembership(0, true));
            copied = true; assigned = true;
            foreach (var row in plan.Rows.Where(r => r.Window == "copy")) Bootstrap(row);
            copiedPolicy = policy! with
            {
                Resource = Id(RolePermissionPlan.CopiedRole),
                Project = Id(RolePermissionPlan.CopyProject),
                Actions = Fault == "template-echo" ? [] : policy.Actions
            };
            Record(request, actor, method, path, bytes, RolePermissionContract.RawHash(bytes), true, "activation");
            commits.Add(new(request, revision, copiedPolicy));
            return (200, new
            {
                project = new
                {
                    id = Id(RolePermissionPlan.CopyProject),
                    _id = Id(RolePermissionPlan.CopyProject),
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
        if (!org && assigned) CommitCreation(RolePermissionPlan.Assignment, request);
        Record(request, actor, method, path, bytes, org ? RolePermissionContract.RawHash(bytes) : WireHash(new object?[] { null, body }), true, "activation");
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
    private (int, object) TargetAction(RolePermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        string[] parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        bool projectScope = parts.Length >= 4 && parts[2] == "projects";
        string project = projectScope && parts[3] != "roles" ? parts[3] : "";
        if (actor.Principal == Authorities.Observer && method == "GET")
        {
            if (parts.Last() == "roles")
            {
                var inventory = states.Values.Where(s => projectScope ? s.Project == project : s.Organization == Organization && s.Project == "");
                // Native collection shape omits permissions. It is metadata only.
                return (200, new { roles = inventory.Select(s => TargetRow(s, true)).ToArray() });
            }
            bool slug = parts.Contains("slug");
            var stored = states.Values.SingleOrDefault(s => slug ? s.Slug == parts.Last() && s.Project == project : s.Target == parts.Last());
            return stored is null ? (404, new { }) : (200, new { role = TargetRow(stored) });
        }
        if (window is not ("before" or "after")) return (403, new { });
        var action = method switch
        {
            "GET" => RolePermissionAction.Read,
            "POST" => RolePermissionAction.Create,
            "PATCH" => RolePermissionAction.Edit,
            "DELETE" => RolePermissionAction.Delete,
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        bool validPath = projectScope ? path.StartsWith("/api/v1/projects/", StringComparison.Ordinal) : path.StartsWith("/api/v1/organization/roles", StringComparison.Ordinal);
        if (!validPath) return (404, new { });
        string target = action == RolePermissionAction.Create ? "" : parts.Last();
        var row = action == RolePermissionAction.Create ? plan!.Rows.SingleOrDefault(r => r.Slug == body.GetProperty("slug").GetString() && Id(r.Project) == project) :
            plan!.Rows.SingleOrDefault(r => Id(r.Target) == target);
        if (row is null) return (404, new { });
        string org = Id(row.Organization); project = Id(row.Project);
        var effective = project == Id(RolePermissionPlan.CopyProject) && copied ? copiedPolicy : policy;
        string wire = RolePermissionContract.Wire(action);
        bool allowed = assigned && effective is not null && effective.Subject == "role" && effective.Actor == actor.Principal && effective.Kind == actor.Kind &&
            actor.Organization == org && effective.Organization == org && effective.Project == project && effective.Actions.Contains(wire) && effective.Names.Length == 0 &&
            Joins().Any(j => j.Principal == actor.Principal && j.Kind == (actor.Kind == MemberPermissionActorKind.User ? "user" : "machine") &&
                j.Organization == org && j.Project == project && j.Assigned && j.RoleId == effective.Resource && j.RoleSlug == effective.Role && j.Active && j.Status == "accepted");
        if (Fault == "action-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && org == Organization &&
            project == (root!.ScopeProfile == RolePermissionScope.Organization ? "" : copied ? Id(RolePermissionPlan.CopyProject) : Id(RolePermissionPlan.Project))) allowed = true;
        if (Fault == "scope-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && policy?.Actions.Contains(wire) == true) allowed = true;
        string request = Guid.NewGuid().ToString("N"); var recorded = Fault == "wrong-actor" ? actor with { Principal = Authorities.Observer } : actor;
        if (Fault == "wrong-credential") recorded = recorded with { Hash = "wrong" };
        Record(request, recorded, method, path, bytes, "", allowed, "action");
        var previous = states.GetValueOrDefault(row.Key); object response = new { };
        if (allowed)
        {
            switch (action)
            {
                case RolePermissionAction.Create:
                    CommitCreation(row.Target, request); states.Add(row.Key, Persist(row, body, 1)); response = new { role = TargetRow(states[row.Key]) }; break;
                case RolePermissionAction.Edit:
                    states[row.Key] = Persist(row, body, 2); response = new { role = TargetRow(states[row.Key]) }; break;
                case RolePermissionAction.Delete:
                    response = new { role = TargetRow(previous!) }; states.Remove(row.Key); resources.Remove(row.Target); break;
                case RolePermissionAction.Read:
                    response = new { role = TargetRow(previous!) }; break;
            }
            if (Fault == "wrong-target-role" && states.TryGetValue(row.Key, out var wrong)) states[row.Key] = wrong with { Target = Guid.NewGuid().ToString() };
            if (Fault == "self-policy-overwrite" && policy is not null) policy = policy with { Actions = ["delete"] };
        }
        decisions.Add(new(request, recorded.Principal, recorded.Kind, recorded.Id, recorded.Hash, org, project, Id(row.Target), revision, action, allowed));
        changes.Add(new(request, row.Key, previous, states.GetValueOrDefault(row.Key)));
        return (allowed ? 200 : 403, response);
    }
    private RolePermissionState Persist(RolePermissionRow row, JsonElement body, int version)
    {
        string permissions = body.GetProperty("permissions").GetRawText();
        if (Fault == "wrong-permissions") permissions = "[{\"subject\":\"role\",\"action\":\"read\"}]";
        if (Fault == "unprojected-conditions") permissions = "[{\"subject\":\"role\",\"action\":\"read\",\"conditions\":{}}]";
        return new(row.Key, Id(row.Target), Id(row.Organization), Id(row.Project), body.GetProperty("name").GetString()!,
            Fault == "wrong-slug" ? "foreign-slug" : body.GetProperty("slug").GetString()!,
            Fault == "wrong-description" ? "foreign-description" : body.GetProperty("description").GetString()!, permissions, version);
    }
    private static object TargetRow(RolePermissionState state, bool inventory = false)
    {
        var value = new Dictionary<string, object?>
        {
            ["id"] = state.Target,
            [state.Project.Length == 0 ? "orgId" : "projectId"] = state.Project.Length == 0 ? state.Organization : state.Project,
            ["name"] = state.Name,
            ["slug"] = state.Slug,
            ["description"] = state.Description,
            ["createdAt"] = "2026-01-01T00:00:00Z",
            ["updatedAt"] = "2026-01-01T00:00:01Z"
        };
        if (!inventory) value["permissions"] = JsonNode.Parse(state.Permissions);
        return value;
    }
    private object Role(string membership, string role) => new
    {
        id = Id(RolePermissionPlan.Assignment),
        projectMembershipId = membership,
        role,
        isTemporary = false,
        createdAt = "2026-01-01T00:00:00Z",
        updatedAt = "2026-01-01T00:00:01Z"
    };
    private static string WireHash(object value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        try { return RolePermissionContract.RawHash(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
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
