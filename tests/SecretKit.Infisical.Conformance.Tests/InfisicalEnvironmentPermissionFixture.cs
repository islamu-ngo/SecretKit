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
internal sealed class InfisicalEnvironmentPermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static MemberPermissionAuthorities Authorities => InfisicalMemberPermissionFixture.Authorities;
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<EnvironmentPermissionJournal, InfisicalEnvironmentPermissionWriter> writers = [];
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
        ["30000000-0000-0000-0000-000000000001"] = "borrowed-environment",
        ["30000000-0000-0000-0000-000000000002"] = "borrowed-user",
        ["30000000-0000-0000-0000-000000000003"] = "borrowed-machine",
        ["30000000-0000-0000-0000-000000000004"] = "borrowed-membership",
        ["30000000-0000-0000-0000-000000000005"] = "borrowed-policy-role",
        ["30000000-0000-0000-0000-000000000006"] = "borrowed-project",
        ["30000000-0000-0000-0000-000000000007"] = "borrowed-template",
        ["30000000-0000-0000-0000-000000000008"] = "borrowed-development-settings",
        ["30000000-0000-0000-0000-000000000009"] = "borrowed-deleted-environment"
    };
    private readonly Dictionary<string, EnvironmentPermissionCredential> tokens = [];
    private readonly List<EnvironmentPermissionCredential> credentials = [];
    private readonly List<EnvironmentPermissionBinding> issuanceBindings = [], storageBindings = [];
    private readonly Dictionary<string, EnvironmentPermissionResource> resources = [];
    private readonly Dictionary<string, EnvironmentPermissionState> states = [];
    private readonly List<EnvironmentPermissionIngress> ingress = [];
    private readonly List<EnvironmentPermissionCommit> commits = [];
    private readonly List<EnvironmentPermissionAccess> decisions = [];
    private readonly List<EnvironmentPermissionChange> changes = [];
    private readonly List<byte[]> privateBuffers = [];
    private readonly MemberPermissionBorrowed[] borrowed;
    private EnvironmentPermissionRoot? root;
    private EnvironmentPermissionPlan? plan;
    private EnvironmentPermissionActor[] actors = [];
    private EnvironmentPermissionPolicy? policy, copiedPolicy;
    private ECDsa? ownedKey;
    private string revision = "policy-1", window = "";
    private int stage;
    private bool closed, closing, armed, settled, assigned, copied;
    private Task? delayed;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal EnvironmentPermissionProfile Profile { get; }
    internal InfisicalEnvironmentPermissionFixtureSource Source { get; }
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
    internal InfisicalEnvironmentPermissionFixture(string fault = "")
    {
        Fault = fault;
        foreach (var journal in Enum.GetValues<EnvironmentPermissionJournal>()) writers.Add(journal, new(journal));
        Profile = new("controlled-environments", "controlled-epoch", "controlled-v1", writers.Values.Select(w => w.Pin).ToArray());
        borrowed = Borrowed(); listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/"); Source = new(this); accept = AcceptAsync();
    }
    internal EnvironmentPermissionInput Input(string operation, EnvironmentPermissionAction action) =>
        new(new(new("https://environment-source.invalid/"), "coordinator-token", "environment-coordinator", 30), "environment-capability", Profile,
            EnvironmentPermissionContract.Scope(operation), EnvironmentPermissionContract.ActorKind(operation), action, 30);
    internal NativeEnvironment Environment(string operation, EnvironmentPermissionAction action, bool configured = true)
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
                    environmentPermission = Input(operation, action)
                }
            }
        }, EnvironmentPermissionContract.Options)!;
        if (!configured) scope["scopes"]!["local"]!.AsObject().Remove("environmentPermission");
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
        }, EnvironmentPermissionContract.Options));
    }
    internal EnvironmentPermissionRoot Root(string operation, EnvironmentPermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization, operation,
            EnvironmentPermissionContract.Variant(action), boundary, "local", "environment-coordinator", MemberPermissionSourceKind.ControlledFixture,
            EnvironmentPermissionContract.Scope(operation), EnvironmentPermissionContract.ActorKind(operation), action, Authorities, Profile);
    private MemberPermissionBorrowed[] Borrowed() => hostTokens.Select(p => new MemberPermissionBorrowed("host-credential", p.Key, EnvironmentPermissionContract.Hash(p.Value)))
        .Concat(writers.Values.Select(w => new MemberPermissionBorrowed("host-key", w.Pin.Writer, EnvironmentPermissionContract.Hash(w.Pin.Spki))))
        .Concat(borrowedObjects.Select(p => new MemberPermissionBorrowed(p.Value, p.Key, EnvironmentPermissionContract.Hash(p.Value)))).ToArray();
    private EnvironmentPermissionIssued Issued => new(actors, storageBindings.ToArray());
    private string Id(string key) => Issued.Id(key);
    private string CommitCreation(string key, string? request = null, bool admitted = false)
    {
        EnvironmentPermissionContract.Require(root is not null && plan is not null && !closed && (!closing || admitted) && !resources.ContainsKey(key) &&
            !storageBindings.Any(b => b.Intent == key));
        var intent = plan!.Intents.Single(i => i.Key == key);
        EnvironmentPermissionContract.Require(Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0));
        // There is deliberately no ID-generation path in Reserve or plan construction.
        string canonical = Guid.NewGuid().ToString();
        var binding = new EnvironmentPermissionBinding(key, EnvironmentPermissionContract.Hash(intent), intent.Work, intent.Kind, Id(intent.Scope),
            EnvironmentPermissionPlan.InputHash(intent, Id), canonical, request ?? Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"));
        issuanceBindings.Add(binding); storageBindings.Add(binding); resources.Add(key, new(key, canonical));
        return canonical;
    }
    private EnvironmentPermissionActor IssueActor(int i)
    {
        string key = plan!.ActorKey(i), scope = Id(plan.ActorScope(i)); var kind = plan.ActorKind(i);
        bool owned = !key.StartsWith("@", StringComparison.Ordinal);
        if (owned && Id(key).Length == 0) CommitCreation(key);
        string principal = Id(key); EnvironmentPermissionCredential credential; byte[] bytes;
        if (owned)
        {
            (credential, bytes) = IssueCredential("actor-credential-" + i, principal, kind, scope);
        }
        else
        {
            bytes = Encoding.UTF8.GetBytes(hostTokens[principal]);
            credential = new("host-" + principal, principal, kind, scope, EnvironmentPermissionContract.RawHash(bytes), false);
            CryptographicOperations.ZeroMemory(bytes); bytes = [];
            if (!credentials.Any(c => c.Id == credential.Id)) credentials.Add(credential);
        }
        CommitCreation(plan.ActorMembership(i));
        return new(principal, kind, scope, credential.Id, credential.Hash, bytes, owned);
    }
    private (EnvironmentPermissionCredential Credential, byte[] Bytes) IssueCredential(string key, string principal, MemberPermissionActorKind kind, string scope)
    {
        string id = CommitCreation(key);
        byte[] random = RandomNumberGenerator.GetBytes(32), bytes;
        try { bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(random)); } finally { CryptographicOperations.ZeroMemory(random); }
        privateBuffers.Add(bytes); Copies.Add(bytes);
        var credential = new EnvironmentPermissionCredential(id, principal, kind, scope, EnvironmentPermissionContract.RawHash(bytes), true);
        credentials.Add(credential); tokens.Add(Encoding.ASCII.GetString(bytes), credential); return (credential, bytes);
    }
    private void Open()
    {
        Opens++; CommitCreation(EnvironmentPermissionPlan.OtherOrganization);
        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
        CommitCreation(EnvironmentPermissionPlan.Project); CommitCreation(EnvironmentPermissionPlan.OtherProject);
        foreach (string key in new[] { "issuer-work", "dispatch-work", "registration", "canary", "owned-key" }) CommitCreation(key);
        ownedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        actors = Enumerable.Range(0, root!.ScopeProfile == EnvironmentPermissionScope.Organization ? 4 : 3).Select(IssueActor).ToArray();
        foreach (var row in plan!.Rows.Where(r => r.Window != "copy")) Bootstrap(row);
        var deleted = plan.DeletedEnvironment; CommitCreation(deleted.Target);
        states.Add(deleted.Key, plan.Initial(deleted, Issued) with { Deleted = true, SoftDeletedAt = "2026-01-01T00:00:00Z", DeleteAfter = "2026-02-01T00:00:00Z", DeletedBy = "identity:" + Authorities.Setup });
        assigned = !root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        if (assigned)
        {
            CommitCreation(plan.PolicyKey);
            string[] actions = ["read", "create", "edit", "delete"];
            string baseline = actions[(Array.IndexOf(actions, EnvironmentPermissionContract.Wire(root.Action)) + 1) % actions.Length];
            policy = new(Id(plan.PolicyKey), revision, actors[0].Principal, actors[0].Kind, Organization,
                root.ScopeProfile == EnvironmentPermissionScope.Project ? Id(EnvironmentPermissionPlan.Project) : "", "environments", [baseline], [], plan.Slug, "bootstrap-policy");
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
        lock (gate) CommitCreation(EnvironmentPermissionPlan.Deferred, admitted: true);
    }
    private void Bootstrap(EnvironmentPermissionRow row)
    {
        if (row.Action == EnvironmentPermissionAction.Create) return;
        CommitCreation(row.Target);
        states.Add(row.Key, plan!.Initial(row, Issued));
    }
    internal EnvironmentPermissionPacket Step(EnvironmentPermissionRoot selected, EnvironmentPermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == EnvironmentPermissionStep.Reserve)
            {
                EnvironmentPermissionContract.Require(root is null && capability == "environment-capability" && selected.Origin == Origin.AbsoluteUri &&
                    selected.Organization == Organization && selected.Authorities == Authorities && EnvironmentPermissionContract.Hash(Profile) == EnvironmentPermissionContract.Hash(selected.Profile));
                root = selected; plan = new(selected);
                if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
            }
            EnvironmentPermissionContract.Require(root is not null && EnvironmentPermissionContract.Hash(root) == EnvironmentPermissionContract.Hash(selected) && !closed &&
                (step == EnvironmentPermissionStep.Close || stage == (int)step));
            if (step != EnvironmentPermissionStep.Close) stage++;
            switch (step)
            {
                case EnvironmentPermissionStep.Open: Open(); break;
                case EnvironmentPermissionStep.Before: Clear(); window = "before"; break;
                case EnvironmentPermissionStep.Arm: Clear(); window = ""; armed = true; break;
                case EnvironmentPermissionStep.Settle: settled = true; break;
                case EnvironmentPermissionStep.After:
                    ingress.RemoveAll(e => e.Phase != "activation"); commits.RemoveAll(c => !ingress.Any(e => e.Request == c.Request));
                    decisions.Clear(); changes.Clear(); window = "after"; break;
                case EnvironmentPermissionStep.ObserveBefore:
                case EnvironmentPermissionStep.ObserveAfter: window = ""; break;
                case EnvironmentPermissionStep.Close:
                    Closes++;
                    EnvironmentPermissionContract.Require(closing && (delayed is null || delayed.IsCompletedSuccessfully));
                    // Reconcile native IDs from original-root issuance AND storage, not the Open reply.
                    EnvironmentPermissionContract.Require(issuanceBindings.SequenceEqual(storageBindings));
                    foreach (var binding in storageBindings)
                        EnvironmentPermissionContract.Require(binding.IntentHash == EnvironmentPermissionContract.Hash(plan!.Intents.Single(i => i.Key == binding.Intent)) &&
                            !borrowed.Any(b => b.Id == binding.CanonicalId));
                    foreach (var binding in storageBindings)
                    {
                        var native = resources.SingleOrDefault(r => r.Value.CanonicalId == binding.CanonicalId);
                        if (native.Key is null) continue; // A witnessed downstream delete may already have removed it.
                        EnvironmentPermissionContract.Require(native.Value.Intent == binding.Intent);
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
    private EnvironmentPermissionSigned<T> Sign<T>(EnvironmentPermissionStep step, EnvironmentPermissionJournal journal, T content) => writers[journal].Sign(root!, step, content);
    private EnvironmentPermissionJoin[] Joins()
    {
        if (closed) return [];
        var joins = actors.Select((actor, i) => new EnvironmentPermissionJoin(actor.Principal,
            actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization,
            root!.ScopeProfile == EnvironmentPermissionScope.Project ? Id(EnvironmentPermissionPlan.Project) : "", Id(plan!.ActorMembership(i)),
            i == 0 && (!EnvironmentPermissionContract.Create(root.Operation) || assigned && !copied), i == 0 && (!EnvironmentPermissionContract.Create(root.Operation) || assigned && !copied) ? Id(plan.PolicyKey) : "",
            i == 0 && (!EnvironmentPermissionContract.Create(root.Operation) || assigned && !copied) ? Fault == "wrong-role-binding" ? "foreign-role" : plan.Slug : "no-access", true, "accepted")).ToList();
        if (copied) joins.Add(new(actors[0].Principal, "user", Organization, Id(EnvironmentPermissionPlan.CopyProject), Id(plan!.ActorMembership(0, true)),
            true, Id(EnvironmentPermissionPlan.CopiedRole), Fault == "wrong-role-binding" ? "foreign-role" : plan.Slug, true, "accepted"));
        return joins.ToArray();
    }
    private EnvironmentPermissionPacket Packet(EnvironmentPermissionStep step)
    {
        bool open = step == EnvironmentPermissionStep.Open, observe = step is EnvironmentPermissionStep.ObserveBefore or EnvironmentPermissionStep.ObserveAfter;
        var issue = issuanceBindings.ToArray(); var storage = storageBindings.ToArray();
        if (open && issue.Length > 1)
        {
            switch (Fault)
            {
                case "binding-substitution": storage[0] = storage[0] with { CanonicalId = Guid.NewGuid().ToString() }; break;
                case "binding-duplicate": issue[1] = issue[1] with { CanonicalId = issue[0].CanonicalId }; storage = issue.ToArray(); break;
                case "binding-work": issue[0] = issue[0] with { Work = "foreign-work" }; storage = issue.ToArray(); break;
                case "binding-input": issue[0] = issue[0] with { InputHash = "foreign-input" }; storage = issue.ToArray(); break;
                case "input-position":
                    int selected = Array.FindIndex(issue, b => b.Kind == "target-environment");
                    issue[selected] = issue[selected] with { InputHash = EnvironmentPermissionContract.Hash(new { Position = 9.25 }) }; storage = issue.ToArray(); break;
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
        var allPolicies = new[] { policy, copiedPolicy }.OfType<EnvironmentPermissionPolicy>().OrderBy(p => p.Resource).ToArray();
        var committed = observe || step == EnvironmentPermissionStep.Settle ? commits.ToArray() : [];
        if (step == EnvironmentPermissionStep.Settle && Fault == "wrong-policy-target" && committed.Length == 1)
        { committed[0] = committed[0] with { Policy = committed[0].Policy with { Resource = Guid.NewGuid().ToString() } }; allPolicies = [committed[0].Policy]; }
        var intents = plan!.Intents.ToArray();
        if (open && Fault == "intent-mutation") intents[0] = intents[0] with { Input = "changed" };
        var packet = new EnvironmentPermissionPacket(
            Sign(step, EnvironmentPermissionJournal.Ownership, new EnvironmentPermissionOwner(intents, resources.Values.ToArray(), Borrowed(), true, true,
                settled || closed, settled || closed, open && Fault == "pending-issuer" ? 1 : 0, closed ? 0 : 1, open ? actors : [])),
            Sign(step, EnvironmentPermissionJournal.Ingress, observe || step == EnvironmentPermissionStep.Settle ? ingress.ToArray() : []),
            Sign(step, EnvironmentPermissionJournal.Policy, new EnvironmentPermissionPolicies(allPolicies, committed)),
            Sign(step, EnvironmentPermissionJournal.Storage, new EnvironmentPermissionStorage(storage, inventory, observe ? changes.ToArray() : [])),
            Sign(step, EnvironmentPermissionJournal.Issuer, new EnvironmentPermissionIssuance(issue, credentialRows)),
            Sign(step, EnvironmentPermissionJournal.Membership, joins), Sign(step, EnvironmentPermissionJournal.Access, observe ? decisions.ToArray() : []), []);
        var seals = new List<EnvironmentPermissionSigned<MemberPermissionSeal>>();
        Add(EnvironmentPermissionJournal.Ownership, packet.Owner.Payload); Add(EnvironmentPermissionJournal.Ingress, packet.Ingress.Payload);
        Add(EnvironmentPermissionJournal.Policy, packet.Policy.Payload); Add(EnvironmentPermissionJournal.Storage, packet.Storage.Payload);
        Add(EnvironmentPermissionJournal.Issuer, packet.Issuer.Payload); Add(EnvironmentPermissionJournal.Membership, packet.Membership.Payload); Add(EnvironmentPermissionJournal.Access, packet.Access.Payload);
        return packet with { Seals = open && Fault == "missing-seal" ? seals.Skip(1).ToArray() : seals.ToArray() };
        void Add<T>(EnvironmentPermissionJournal journal, T payload) => seals.Add(Sign(step, journal,
            new MemberPermissionSeal(EnvironmentPermissionContract.Hash(payload), !(open && Fault == "nonterminal"), 0, 1)));
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
                EnvironmentPermissionContract.Require(length is >= 0 and <= 131072);
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
    private EnvironmentPermissionCredential Authenticate(string bearer)
    {
        if (tokens.TryGetValue(bearer, out var credential)) return credential;
        string principal = hostTokens.SingleOrDefault(p => p.Value == bearer).Key ?? "unknown";
        byte[] bytes = Encoding.UTF8.GetBytes(bearer);
        try { return new("host-" + principal, principal, MemberPermissionActorKind.Machine, Organization, EnvironmentPermissionContract.RawHash(bytes), false); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private void Record(string request, EnvironmentPermissionCredential actor, string method, string path, byte[] bytes, string intent, bool allowed, string phase) =>
        ingress.Add(new(request, actor.Principal, actor.Kind, actor.Hash, actor.Organization, method, path, EnvironmentPermissionContract.RawHash(bytes), intent, allowed, phase));
    private (int, object) Handle(string method, Uri uri, string bearer, JsonElement body, byte[] bytes)
    {
        if (root is null || actors.Length == 0 || closed || closing) return (403, new { });
        var actor = Authenticate(bearer); string path = uri.AbsolutePath;
        bool template = root.Operation.Contains("ProjectTemplate", StringComparison.Ordinal), organization = root.Operation.EndsWith("OrganizationRole", StringComparison.Ordinal),
            privilege = root.Operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal), create = root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        string originalPath = (template ? "/api/v1/project-templates" : organization ? "/api/v1/organization/roles" : privilege ?
            "/api/v2/identity-project-additional-privilege" : "/api/v1/projects/" + Id(EnvironmentPermissionPlan.Project) + "/roles") + (create ? "" : "/" + Id(plan!.PolicyKey));
        if (path == originalPath && method == (create ? "POST" : "PATCH") &&
            (template || privilege || body.TryGetProperty("slug", out var policySlug) && policySlug.GetString() == plan!.Slug))
        {
            if (!armed || settled || Originals != 0) return (409, new { });
            Originals++; string request = Guid.NewGuid().ToString("N"), intent = EnvironmentPermissionContract.RawHash(bytes);
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
                policy = new(Id(plan!.PolicyKey), revision, principal, actors[0].Kind, Organization, organization ? "" : Id(EnvironmentPermissionPlan.Project),
                    permission.GetProperty("subject").GetString()!, Fault == "partial" ? [] : selected, Fault == "wrong-condition" ? ["forged-condition"] : names, Fault == "incomplete-policy" ? "" : role, Fault == "wrong-configuration" ? "foreign-configuration" : EnvironmentPermissionContract.RawHash(bytes));
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
            else { result["name"] = plan.Slug; result[organization ? "orgId" : "projectId"] = organization ? Organization : Id(EnvironmentPermissionPlan.Project); }
            return (200, new JsonObject { [template ? "projectTemplate" : privilege ? "privilege" : "role"] = result });
        }
        if (settled && actor.Principal == Authorities.Setup && actor.Kind == MemberPermissionActorKind.Machine && policy is not null &&
            (path == "/api/v1/projects" || path.EndsWith("/" + Id(plan!.ActorMembership(0)), StringComparison.Ordinal)))
            return Activate(actor, method, path, body, bytes);
        return TargetAction(actor, method, uri.PathAndQuery, body, bytes);
    }
    private (int, object) Activate(EnvironmentPermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        string request = Guid.NewGuid().ToString("N");
        if (path == "/api/v1/projects")
        {
            if (copied || method != "POST" || body.GetProperty("template").GetString() != plan!.Slug || body.GetProperty("slug").GetString() != plan.CopySlug) return (403, new { });
            CommitCreation(EnvironmentPermissionPlan.CopyProject, request); CommitCreation(EnvironmentPermissionPlan.CopiedRole); CommitCreation(plan.ActorMembership(0, true));
            copied = true; assigned = true;
            foreach (var row in plan.Rows.Where(r => r.Window == "copy")) Bootstrap(row);
            var config = plan.ConfigurationEnvironment; CommitCreation(config.Target); states.Add(config.Key, plan.Initial(config, Issued));
            if (Fault == "template-environment-echo") states[config.Key] = states[config.Key] with { Position = 9.5 };
            copiedPolicy = policy! with
            {
                Resource = Id(EnvironmentPermissionPlan.CopiedRole),
                Project = Id(EnvironmentPermissionPlan.CopyProject),
                Actions = Fault == "template-echo" ? [] : policy.Actions,
                Configuration = Fault == "template-configuration-echo" ? "foreign-configuration" : policy.Configuration
            };
            Record(request, actor, method, path, bytes, EnvironmentPermissionContract.RawHash(bytes), true, "activation");
            commits.Add(new(request, revision, copiedPolicy));
            return (200, new
            {
                project = new
                {
                    id = Id(EnvironmentPermissionPlan.CopyProject),
                    _id = Id(EnvironmentPermissionPlan.CopyProject),
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
        if (!org && assigned) CommitCreation(EnvironmentPermissionPlan.Assignment, request);
        Record(request, actor, method, path, bytes, org ? EnvironmentPermissionContract.RawHash(bytes) : WireHash(new object?[] { null, body }), true, "activation");
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
    private (int, object) TargetAction(EnvironmentPermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        string plain = path.Split('?')[0]; string[] parts = plain.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 4 || parts[2] != "projects") return (404, new { });
        string project = parts[3];
        if (actor.Principal == Authorities.Observer && method == "GET")
        {
            var inventory = states.Values.Where(s => s.Project == project).ToArray();
            if (parts.Length == 4)
            {
                string[] ids = new[] { EnvironmentPermissionPlan.Project, EnvironmentPermissionPlan.OtherProject, EnvironmentPermissionPlan.CopyProject }.Select(Id).ToArray();
                if (!ids.Contains(project)) return (404, new { });
                return (200, new
                {
                    project = new
                    {
                        id = project,
                        _id = project,
                        orgId = Organization,
                        name = "Closed project",
                        slug = "closed-project",
                        type = "secret-manager",
                        createdAt = "2026-01-01T00:00:00Z",
                        updatedAt = "2026-01-01T00:00:01Z",
                        environments = inventory.Where(s => !s.Deleted).Select(s => new { id = s.Target, name = s.Name, slug = s.Slug }).ToArray(),
                        deletedEnvironments = inventory.Where(s => s.Deleted && Fault != "missing-deleted-record").Select(s => new
                        {
                            id = s.Target,
                            name = s.Name,
                            slug = s.Slug,
                            softDeletedAt = s.SoftDeletedAt,
                            deleteAfter = s.DeleteAfter,
                            deletedBy = new { type = "identity", id = Authorities.Setup, name = "Setup machine" }
                        }).ToArray()
                    }
                });
            }
            bool slug = parts.Contains("slug");
            var stored = inventory.SingleOrDefault(s => !s.Deleted && (slug ? s.Slug == parts.Last() : s.Target == parts.Last()));
            return stored is null ? (404, new { }) : (200, new { environment = TargetRow(stored) });
        }
        if (window is not ("before" or "after") || parts.Length < 5 || parts[4] != "environments") return (403, new { });
        var action = method switch
        {
            "GET" => EnvironmentPermissionAction.Read,
            "POST" => EnvironmentPermissionAction.Create,
            "PATCH" => EnvironmentPermissionAction.Edit,
            "DELETE" => EnvironmentPermissionAction.Delete,
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        if (action == EnvironmentPermissionAction.Delete && !path.EndsWith("?hardDelete=true", StringComparison.Ordinal)) return (400, new { });
        string target = action == EnvironmentPermissionAction.Create ? "" : parts.Last();
        var row = action == EnvironmentPermissionAction.Create ? plan!.Rows.SingleOrDefault(r => r.Slug == body.GetProperty("slug").GetString() && Id(r.Project) == project) :
            plan!.Rows.SingleOrDefault(r => Id(r.Target) == target && Id(r.Project) == project);
        if (row is null) return (404, new { });
        string org = Id(row.Organization);
        var effective = project == Id(EnvironmentPermissionPlan.CopyProject) && copied ? copiedPolicy : policy;
        string wire = EnvironmentPermissionContract.Wire(action);
        bool allowed = assigned && effective is not null && effective.Subject == "environments" && effective.Actor == actor.Principal && effective.Kind == actor.Kind &&
            actor.Organization == org && effective.Organization == org && effective.Project == project && effective.Actions.Contains(wire) && effective.Names.Length == 0 &&
            Joins().Any(j => j.Principal == actor.Principal && j.Kind == (actor.Kind == MemberPermissionActorKind.User ? "user" : "machine") &&
                j.Organization == org && j.Project == project && j.Assigned && j.RoleId == effective.Resource && j.RoleSlug == effective.Role && j.Active && j.Status == "accepted");
        if (Fault == "action-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && org == Organization &&
            project == (copied ? Id(EnvironmentPermissionPlan.CopyProject) : Id(EnvironmentPermissionPlan.Project))) allowed = true;
        if (Fault == "scope-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && policy?.Actions.Contains(wire) == true) allowed = true;
        string request = Guid.NewGuid().ToString("N"); var recorded = Fault == "wrong-actor" ? actor with { Principal = Authorities.Observer } : actor;
        if (Fault == "wrong-credential") recorded = recorded with { Hash = "wrong" };
        Record(request, recorded, method, path, bytes, "", allowed, "action");
        var previous = states.GetValueOrDefault(row.Key); object response = new { };
        if (allowed)
        {
            switch (action)
            {
                case EnvironmentPermissionAction.Create:
                    CommitCreation(row.Target, request); states.Add(row.Key, Persist(row, body, 1)); response = new { projectId = project, environment = TargetRow(states[row.Key]) }; break;
                case EnvironmentPermissionAction.Edit:
                    states[row.Key] = Persist(row, body, 2); response = new { projectId = project, environment = TargetRow(states[row.Key]) }; break;
                case EnvironmentPermissionAction.Delete:
                    response = new { projectId = project, environment = TargetRow(previous!) }; states.Remove(row.Key); resources.Remove(row.Target); break;
                case EnvironmentPermissionAction.Read:
                    response = new { environment = TargetRow(previous!) }; break;
            }
            if (states.TryGetValue(row.Key, out var wrong))
                states[row.Key] = Fault switch
                {
                    "wrong-environment" => wrong with { Target = Guid.NewGuid().ToString() },
                    "wrong-name" => wrong with { Name = "foreign-name" },
                    "wrong-slug" => wrong with { Slug = "foreign-slug" },
                    "wrong-position" => wrong with { Position = 9.25 },
                    "wrong-deletion-flag" => wrong with { Deleted = true },
                    "stale-environment-scope" => wrong with { Project = Id(EnvironmentPermissionPlan.OtherProject) },
                    _ => wrong
                };
            if (Fault == "self-policy-overwrite" && policy is not null) policy = policy with { Actions = ["delete"] };
        }
        decisions.Add(new(request, recorded.Principal, recorded.Kind, recorded.Id, recorded.Hash,
            Fault == "wrong-organization" ? Id(EnvironmentPermissionPlan.OtherOrganization) : org,
            Fault == "wrong-project" ? Id(EnvironmentPermissionPlan.OtherProject) : project,
            Id(row.Target), revision, action, allowed));
        changes.Add(new(request, row.Key, previous, states.GetValueOrDefault(row.Key)));
        return (allowed ? 200 : 403, response);
    }
    private EnvironmentPermissionState Persist(EnvironmentPermissionRow row, JsonElement body, int version) =>
        new(row.Key, Id(row.Target), Id(row.Organization), Id(row.Project), body.GetProperty("name").GetString()!,
            body.GetProperty("slug").GetString()!, body.GetProperty("position").GetDouble(), false, version);
    private static object TargetRow(EnvironmentPermissionState state) => new
    {
        id = state.Target,
        projectId = state.Project,
        name = state.Name,
        slug = state.Slug,
        position = state.Position,
        createdAt = "2026-01-01T00:00:00Z",
        updatedAt = "2026-01-01T00:00:01Z",
        softDeletedAt = state.Deleted ? "2026-01-01T00:00:00Z" : (string?)null,
        deleteAfter = state.Deleted ? "2026-02-01T00:00:00Z" : (string?)null,
        deletedByUserId = (string?)null,
        deletedByIdentityId = (string?)null
    };
    private object Role(string membership, string role) => new
    {
        id = Id(EnvironmentPermissionPlan.Assignment),
        projectMembershipId = membership,
        role,
        isTemporary = false,
        createdAt = "2026-01-01T00:00:00Z",
        updatedAt = "2026-01-01T00:00:01Z"
    };
    private static string WireHash(object value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        try { return EnvironmentPermissionContract.RawHash(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
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
