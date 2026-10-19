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
internal sealed class InfisicalWorkspacePermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static MemberPermissionAuthorities Authorities => InfisicalMemberPermissionFixture.Authorities;
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<WorkspacePermissionJournal, InfisicalWorkspacePermissionWriter> writers = [];
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
    private readonly Dictionary<string, WorkspacePermissionCredential> tokens = [];
    private readonly List<WorkspacePermissionCredential> credentials = [];
    private readonly List<WorkspacePermissionBinding> issuanceBindings = [], storageBindings = [];
    private readonly Dictionary<string, WorkspacePermissionResource> resources = [];
    private readonly Dictionary<string, WorkspacePermissionState> states = [];
    private readonly List<WorkspacePermissionIngress> ingress = [];
    private readonly List<WorkspacePermissionCommit> commits = [];
    private readonly List<WorkspacePermissionAccess> decisions = [];
    private readonly List<WorkspacePermissionChange> changes = [];
    private readonly List<WorkspacePermissionCascade> cascades = [];
    private readonly List<byte[]> privateBuffers = [];
    private readonly MemberPermissionBorrowed[] borrowed;
    private WorkspacePermissionRoot? root;
    private WorkspacePermissionPlan? plan;
    private WorkspacePermissionActor[] actors = [];
    private WorkspacePermissionPolicy? policy, copiedPolicy;
    private ECDsa? ownedKey;
    private string revision = "policy-1", window = "";
    private int stage;
    private bool closed, closing, armed, settled, assigned, copied;
    private Task? delayed;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal WorkspacePermissionProfile Profile { get; }
    internal InfisicalWorkspacePermissionFixtureSource Source { get; }
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    internal TaskCompletionSource OpenEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource OpenRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource CloseEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource DispatchEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource DispatchRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal int Originals { get; private set; }
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Generated => storageBindings.Count;
    internal int Registrations => root is not null && !closed ? 1 : 0;
    internal int Remaining => resources.Count + states.Count + credentials.Count + (policy is null ? 0 : 1) + (copiedPolicy is null ? 0 : 1) + (ownedKey is null ? 0 : 1);
    internal bool BorrowedPreserved => Borrowed().SequenceEqual(borrowed);
    internal InfisicalWorkspacePermissionFixture(string fault = "")
    {
        Fault = fault;
        foreach (var journal in Enum.GetValues<WorkspacePermissionJournal>()) writers.Add(journal, new(journal));
        Profile = new("controlled-roles", "controlled-epoch", "controlled-v1", writers.Values.Select(w => w.Pin).ToArray());
        borrowed = Borrowed(); listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/"); Source = new(this); accept = AcceptAsync();
    }
    internal WorkspacePermissionInput Input(string operation, WorkspacePermissionAction action) =>
        new(new(new("https://workspace-source.invalid/"), "coordinator-token", "workspace-coordinator", 30), "workspace-capability", Profile,
            WorkspacePermissionContract.Scope(operation), WorkspacePermissionContract.ActorKind(operation), action, 30);
    internal NativeEnvironment Environment(string operation, WorkspacePermissionAction action, bool configured = true)
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
                    workspacePermission = Input(operation, action)
                }
            }
        }, WorkspacePermissionContract.Options)!;
        if (!configured) scope["scopes"]!["local"]!.AsObject().Remove("workspacePermission");
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
        }, WorkspacePermissionContract.Options));
    }
    internal WorkspacePermissionRoot Root(string operation, WorkspacePermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization, operation,
            WorkspacePermissionContract.Variant(action), boundary, "local", "workspace-coordinator", MemberPermissionSourceKind.ControlledFixture,
            WorkspacePermissionContract.Scope(operation), WorkspacePermissionContract.ActorKind(operation), action, Authorities, Profile);
    private MemberPermissionBorrowed[] Borrowed() => hostTokens.Select(p => new MemberPermissionBorrowed("host-credential", p.Key, WorkspacePermissionContract.Hash(p.Value)))
        .Concat(writers.Values.Select(w => new MemberPermissionBorrowed("host-key", w.Pin.Writer, WorkspacePermissionContract.Hash(w.Pin.Spki))))
        .Concat(borrowedObjects.Select(p => new MemberPermissionBorrowed(p.Value, p.Key, WorkspacePermissionContract.Hash(p.Value)))).ToArray();
    private WorkspacePermissionIssued Issued => new(actors, storageBindings.ToArray());
    private string Id(string key) => Issued.Id(key);
    private string CommitCreation(string key, string? request = null, bool admitted = false)
    {
        WorkspacePermissionContract.Require(root is not null && plan is not null && !closed && (!closing || admitted) && !resources.ContainsKey(key) &&
            !storageBindings.Any(b => b.Intent == key));
        var intent = plan!.Intents.Single(i => i.Key == key);
        WorkspacePermissionContract.Require(Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0));
        // There is deliberately no ID-generation path in Reserve or plan construction.
        string canonical = Guid.NewGuid().ToString();
        var binding = new WorkspacePermissionBinding(key, WorkspacePermissionContract.Hash(intent), intent.Work, intent.Kind, Id(intent.Scope),
            WorkspacePermissionPlan.InputHash(intent, Id), canonical, request ?? Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"));
        issuanceBindings.Add(binding); storageBindings.Add(binding); resources.Add(key, new(key, canonical));
        return canonical;
    }
    private WorkspacePermissionActor IssueActor(int i)
    {
        string key = plan!.ActorKey(i), scope = Id(plan.ActorScope(i)); var kind = plan.ActorKind(i);
        bool owned = !key.StartsWith("@", StringComparison.Ordinal);
        if (owned && Id(key).Length == 0) CommitCreation(key);
        string principal = Id(key); WorkspacePermissionCredential credential; byte[] bytes;
        if (owned)
        {
            (credential, bytes) = IssueCredential("actor-credential-" + i, principal, kind, scope);
        }
        else
        {
            bytes = Encoding.UTF8.GetBytes(hostTokens[principal]);
            credential = new("host-" + principal, principal, kind, scope, WorkspacePermissionContract.RawHash(bytes), false);
            CryptographicOperations.ZeroMemory(bytes); bytes = [];
            if (!credentials.Any(c => c.Id == credential.Id)) credentials.Add(credential);
        }
        CommitCreation(plan.ActorMembership(i));
        return new(principal, kind, scope, credential.Id, credential.Hash, bytes, owned);
    }
    private (WorkspacePermissionCredential Credential, byte[] Bytes) IssueCredential(string key, string principal, MemberPermissionActorKind kind, string scope)
    {
        string id = CommitCreation(key);
        byte[] random = RandomNumberGenerator.GetBytes(32), bytes;
        try { bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(random)); } finally { CryptographicOperations.ZeroMemory(random); }
        privateBuffers.Add(bytes); Copies.Add(bytes);
        var credential = new WorkspacePermissionCredential(id, principal, kind, scope, WorkspacePermissionContract.RawHash(bytes), true);
        credentials.Add(credential); tokens.Add(Encoding.ASCII.GetString(bytes), credential); return (credential, bytes);
    }
    private void Open()
    {
        Opens++; CommitCreation(WorkspacePermissionPlan.OtherOrganization);
        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
        if (root!.ScopeProfile == WorkspacePermissionScope.Project) { CommitCreation(WorkspacePermissionPlan.Project); CommitCreation(WorkspacePermissionPlan.OtherProject); }
        foreach (string key in new[] { "issuer-work", "dispatch-work", "registration", "canary", "owned-key" }) CommitCreation(key);
        ownedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        actors = Enumerable.Range(0, root!.ScopeProfile == WorkspacePermissionScope.Organization ? 4 : 3).Select(IssueActor).ToArray();
        foreach (var row in plan!.Rows.Where(r => r.Window != "copy").DistinctBy(r => r.Target)) Bootstrap(row);
        assigned = !root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        if (assigned)
        {
            CommitCreation(plan.PolicyKey);
            policy = new(Id(plan.PolicyKey), revision, actors[0].Principal, actors[0].Kind, Organization,
                root.ScopeProfile == WorkspacePermissionScope.Project && !WorkspacePermissionContract.Template(root.Operation) ? Id(WorkspacePermissionPlan.Project) : "", "workspace", [], [], plan.Slug);
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
        lock (gate) CommitCreation(WorkspacePermissionPlan.Deferred, admitted: true);
    }
    private void Bootstrap(WorkspacePermissionRow row)
    {
        if (row.Action == WorkspacePermissionAction.Create) return;
        if (Id(row.Target).Length == 0) CommitCreation(row.Target);
        states.TryAdd(row.Target, plan!.Initial(row, Issued));
    }
    internal WorkspacePermissionPacket Step(WorkspacePermissionRoot selected, WorkspacePermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == WorkspacePermissionStep.Reserve)
            {
                WorkspacePermissionContract.Require(root is null && capability == "workspace-capability" && selected.Origin == Origin.AbsoluteUri &&
                    selected.Organization == Organization && selected.Authorities == Authorities && WorkspacePermissionContract.Hash(Profile) == WorkspacePermissionContract.Hash(selected.Profile));
                root = selected; plan = new(selected);
                if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
            }
            WorkspacePermissionContract.Require(root is not null && WorkspacePermissionContract.Hash(root) == WorkspacePermissionContract.Hash(selected) && !closed &&
                (step == WorkspacePermissionStep.Close || stage == (int)step));
            if (step != WorkspacePermissionStep.Close) stage++;
            switch (step)
            {
                case WorkspacePermissionStep.Open: Open(); break;
                case WorkspacePermissionStep.Before: Clear(); window = "before"; break;
                case WorkspacePermissionStep.Arm: Clear(); window = ""; armed = true; break;
                case WorkspacePermissionStep.Settle: settled = true; break;
                case WorkspacePermissionStep.After:
                    ingress.RemoveAll(e => e.Phase != "activation"); commits.RemoveAll(c => !ingress.Any(e => e.Request == c.Request));
                    decisions.Clear(); changes.Clear(); cascades.Clear(); window = "after"; break;
                case WorkspacePermissionStep.ObserveBefore:
                case WorkspacePermissionStep.ObserveAfter: window = ""; break;
                case WorkspacePermissionStep.Close:
                    Closes++;
                    WorkspacePermissionContract.Require(closing && (delayed is null || delayed.IsCompletedSuccessfully));
                    // Reconcile native IDs from original-root issuance AND storage, not the Open reply.
                    WorkspacePermissionContract.Require(issuanceBindings.SequenceEqual(storageBindings));
                    foreach (var binding in storageBindings)
                        WorkspacePermissionContract.Require(binding.IntentHash == WorkspacePermissionContract.Hash(plan!.Intents.Single(i => i.Key == binding.Intent)) &&
                            !borrowed.Any(b => b.Id == binding.CanonicalId));
                    foreach (var binding in storageBindings)
                    {
                        var native = resources.SingleOrDefault(r => r.Value.CanonicalId == binding.CanonicalId);
                        if (native.Key is null) continue; // A witnessed downstream delete may already have removed it.
                        WorkspacePermissionContract.Require(native.Value.Intent == binding.Intent);
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
    private void Clear() { ingress.Clear(); commits.Clear(); decisions.Clear(); changes.Clear(); cascades.Clear(); }
    private WorkspacePermissionSigned<T> Sign<T>(WorkspacePermissionStep step, WorkspacePermissionJournal journal, T content) => writers[journal].Sign(root!, step, content);
    private WorkspacePermissionJoin[] Joins()
    {
        if (closed) return [];
        bool originalAssigned = !WorkspacePermissionContract.Template(root!.Operation) &&
            (!WorkspacePermissionContract.Create(root.Operation) || assigned);
        var joins = actors.Select((actor, i) => new WorkspacePermissionJoin(actor.Principal,
            actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization,
            root!.ScopeProfile == WorkspacePermissionScope.Project ? Id(WorkspacePermissionPlan.Project) : "", Id(plan!.ActorMembership(i)),
            i == 0 && originalAssigned, i == 0 && originalAssigned ? Id(plan.PolicyKey) : "",
            i == 0 && originalAssigned ? Fault == "wrong-role-binding" ? "foreign-role" : plan.Slug : "no-access", true, "accepted")).ToList();
        if (copied) joins.Add(new(actors[0].Principal, "user", Organization, Id(WorkspacePermissionPlan.CopyProject), Id(plan!.ActorMembership(0, true)),
            true, Id(WorkspacePermissionPlan.CopiedRole), Fault == "wrong-role-binding" ? "foreign-role" : plan.Slug, true, "accepted"));
        return joins.Where(j => resources.Values.Any(r => r.CanonicalId == j.Membership)).ToArray();
    }
    private WorkspacePermissionPacket Packet(WorkspacePermissionStep step)
    {
        bool open = step == WorkspacePermissionStep.Open, observe = step is WorkspacePermissionStep.ObserveBefore or WorkspacePermissionStep.ObserveAfter;
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
        if (step == WorkspacePermissionStep.ObserveAfter && cascades.Count > 0)
        {
            string deleted = cascades[0].Project;
            if (Fault == "lost-tombstone") { issue = issue.Where(b => b.CanonicalId != deleted).ToArray(); storage = storage.Where(b => b.CanonicalId != deleted).ToArray(); }
            if (Fault == "recycled-scope") { int index = Array.FindIndex(issue, b => b.CanonicalId == deleted); issue[index] = issue[index] with { CanonicalId = Guid.NewGuid().ToString() }; storage = issue.ToArray(); }
        }
        var credentialRows = credentials.ToArray(); var joins = Joins(); var inventory = states.Values.OrderBy(s => s.Row).ToArray();
        var remaining = resources.Values.ToArray();
        if (open && Fault == "lost-membership-binding")
        {
            var missing = storage.Where(b => b.Kind == "membership").Select(b => b.CanonicalId).ToHashSet();
            issue = issue.Where(b => !missing.Contains(b.CanonicalId)).ToArray();
            storage = storage.Where(b => !missing.Contains(b.CanonicalId)).ToArray();
            remaining = remaining.Where(r => !missing.Contains(r.CanonicalId)).ToArray();
            joins = joins.Select(j => j with { Membership = "" }).ToArray();
        }
        if (open && Fault == "actor-kind") credentialRows[0] = credentialRows[0] with { Kind = credentialRows[0].Kind == MemberPermissionActorKind.User ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User };
        if (open && Fault == "credential-wrong-actor") credentialRows[0] = credentialRows[0] with { Principal = Authorities.Observer };
        if (open && Fault == "membership-wrong-member") joins[0] = joins[0] with { Principal = Authorities.Observer };
        if (open && Fault == "missing-inventory") inventory = inventory.Skip(1).ToArray();
        var allPolicies = new[] { policy, copiedPolicy }.OfType<WorkspacePermissionPolicy>().OrderBy(p => p.Resource).ToArray();
        if (open && Fault == "lost-policy-binding")
        {
            string missing = Id(plan!.PolicyKey);
            issue = issue.Where(b => b.CanonicalId != missing).ToArray();
            storage = storage.Where(b => b.CanonicalId != missing).ToArray();
            remaining = remaining.Where(r => r.CanonicalId != missing).ToArray();
            allPolicies = allPolicies.Select(p => p with { Resource = "" }).ToArray();
            joins = joins.Select(j => j.RoleId == missing ? j with { RoleId = "" } : j).ToArray();
        }
        var committed = observe || step == WorkspacePermissionStep.Settle ? commits.ToArray() : [];
        if (step == WorkspacePermissionStep.Settle && Fault == "wrong-policy-target" && committed.Length == 1)
        { committed[0] = committed[0] with { Policy = committed[0].Policy with { Resource = Guid.NewGuid().ToString() } }; allPolicies = [committed[0].Policy]; }
        var intents = plan!.Intents.ToArray();
        if (open && Fault == "intent-mutation") intents[0] = intents[0] with { Input = "changed" };
        var packet = new WorkspacePermissionPacket(
            Sign(step, WorkspacePermissionJournal.Ownership, new WorkspacePermissionOwner(intents, remaining, Borrowed(), true, true,
                settled || closed, settled || closed, open && Fault == "pending-issuer" ? 1 : 0, closed ? 0 : 1, open ? actors : [])),
            Sign(step, WorkspacePermissionJournal.Ingress, observe || step == WorkspacePermissionStep.Settle ? ingress.ToArray() : []),
            Sign(step, WorkspacePermissionJournal.Policy, new WorkspacePermissionPolicies(allPolicies, committed)),
            Sign(step, WorkspacePermissionJournal.Storage, new WorkspacePermissionStorage(storage, inventory, observe ? changes.ToArray() : [], observe ? cascades.ToArray() : [])),
            Sign(step, WorkspacePermissionJournal.Issuer, new WorkspacePermissionIssuance(issue, credentialRows)),
            Sign(step, WorkspacePermissionJournal.Membership, joins), Sign(step, WorkspacePermissionJournal.Access, observe ? decisions.ToArray() : []), []);
        var seals = new List<WorkspacePermissionSigned<MemberPermissionSeal>>();
        Add(WorkspacePermissionJournal.Ownership, packet.Owner.Payload); Add(WorkspacePermissionJournal.Ingress, packet.Ingress.Payload);
        Add(WorkspacePermissionJournal.Policy, packet.Policy.Payload); Add(WorkspacePermissionJournal.Storage, packet.Storage.Payload);
        Add(WorkspacePermissionJournal.Issuer, packet.Issuer.Payload); Add(WorkspacePermissionJournal.Membership, packet.Membership.Payload); Add(WorkspacePermissionJournal.Access, packet.Access.Payload);
        return packet with { Seals = open && Fault == "missing-seal" ? seals.Skip(1).ToArray() : seals.ToArray() };
        void Add<T>(WorkspacePermissionJournal journal, T payload) => seals.Add(Sign(step, journal,
            new MemberPermissionSeal(WorkspacePermissionContract.Hash(payload), !(open && Fault == "nonterminal"), 0, 1)));
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
                WorkspacePermissionContract.Require(length is >= 0 and <= 131072);
                body = new byte[length]; Copies.Add(body); await stream.ReadExactlyAsync(body, shutdown.Token);
                string bearer = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?.Split(' ').Last() ?? "";
                using var document = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                (int Status, object Body) result; bool hold;
                lock (gate)
                {
                    result = Handle(request[0], new Uri(Origin, request[1]), bearer, document.RootElement, body);
                    hold = Fault == "delayed-dispatch" && armed && !settled && Originals == 1;
                }
                if (hold) { DispatchEntered.TrySetResult(); await DispatchRelease.Task.WaitAsync(shutdown.Token); }
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
    private WorkspacePermissionCredential Authenticate(string bearer)
    {
        if (tokens.TryGetValue(bearer, out var credential)) return credential;
        string principal = hostTokens.SingleOrDefault(p => p.Value == bearer).Key ?? "unknown";
        byte[] bytes = Encoding.UTF8.GetBytes(bearer);
        try { return new("host-" + principal, principal, MemberPermissionActorKind.Machine, Organization, WorkspacePermissionContract.RawHash(bytes), false); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private void Record(string request, WorkspacePermissionCredential actor, string method, string path, byte[] bytes, string intent, bool allowed, string phase) =>
        ingress.Add(new(request, actor.Principal, actor.Kind, actor.Hash, actor.Organization, method, path, WorkspacePermissionContract.RawHash(bytes), intent, allowed, phase));
    private (int, object) Handle(string method, Uri uri, string bearer, JsonElement body, byte[] bytes)
    {
        if (root is null || actors.Length == 0 || closed || closing) return (403, new { });
        var actor = Authenticate(bearer); string path = uri.AbsolutePath;
        bool template = root.Operation.Contains("ProjectTemplate", StringComparison.Ordinal), organization = root.Operation.EndsWith("OrganizationRole", StringComparison.Ordinal),
            privilege = root.Operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal), create = root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        string originalPath = (template ? "/api/v1/project-templates" : organization ? "/api/v1/organization/roles" : privilege ?
            "/api/v2/identity-project-additional-privilege" : "/api/v1/projects/" + Id(WorkspacePermissionPlan.Project) + "/roles") + (create ? "" : "/" + Id(plan!.PolicyKey));
        if (path == originalPath && method == (create ? "POST" : "PATCH") &&
            (template || privilege || body.TryGetProperty("slug", out var policySlug) && policySlug.GetString() == plan!.Slug))
        {
            if (!armed || settled || Originals != 0) return (409, new { });
            Originals++; string request = Guid.NewGuid().ToString("N"), intent = WorkspacePermissionContract.RawHash(bytes);
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
                policy = new(Id(plan!.PolicyKey), revision, principal, actors[0].Kind, Organization, organization || template ? "" : Id(WorkspacePermissionPlan.Project),
                    permission.GetProperty("subject").GetString()!, Fault == "partial" ? [] : selected, Fault == "wrong-condition" ? ["forged-condition"] : names, Fault == "incomplete-policy" ? "" : role);
                if (template)
                {
                    var persisted = new JsonObject();
                    foreach (string field in new[] { "roles", "environments", "users", "groups", "identities", "projectManagedIdentities" })
                        persisted[field] = JsonNode.Parse(body.GetProperty(field).GetRawText());
                    if (Fault == "template-settings") persisted["environments"] = new JsonArray("unexpected");
                    policy = policy with { TemplateConfiguration = persisted.ToJsonString() };
                }
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
            else { result["name"] = plan.Slug; result[organization ? "orgId" : "projectId"] = organization ? Organization : Id(WorkspacePermissionPlan.Project); }
            return (200, new JsonObject { [template ? "projectTemplate" : privilege ? "privilege" : "role"] = result });
        }
        if (settled && actor.Principal == Authorities.Setup && actor.Kind == MemberPermissionActorKind.Machine && policy is not null &&
            (path == "/api/v1/projects" || path.EndsWith("/" + Id(plan!.ActorMembership(0)), StringComparison.Ordinal)))
            return Activate(actor, method, path, body, bytes);
        return TargetAction(actor, method, path, body, bytes);
    }
    private (int, object) Activate(WorkspacePermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        string request = Guid.NewGuid().ToString("N");
        if (path == "/api/v1/projects")
        {
            if (copied || method != "POST" || body.GetProperty("template").GetString() != plan!.Slug || body.GetProperty("slug").GetString() != plan.CopySlug) return (403, new { });
            CommitCreation(WorkspacePermissionPlan.CopyProject, request); CommitCreation(WorkspacePermissionPlan.CopiedRole); CommitCreation(plan.ActorMembership(0, true));
            copied = true; assigned = true;
            foreach (var row in plan.Rows.Where(r => r.Window == "copy").DistinctBy(r => r.Target)) Bootstrap(row);
            copiedPolicy = policy! with
            {
                Resource = Id(WorkspacePermissionPlan.CopiedRole),
                Project = Id(WorkspacePermissionPlan.CopyProject),
                Actions = Fault == "template-echo" ? [] : policy.Actions
            };
            var installed = JsonNode.Parse(policy.TemplateConfiguration)!.AsObject();
            if (Fault == "template-copy-configuration") installed["users"] = new JsonArray();
            copiedPolicy = copiedPolicy with { TemplateConfiguration = installed.ToJsonString() };
            Record(request, actor, method, path, bytes, WorkspacePermissionContract.RawHash(bytes), true, "activation");
            commits.Add(new(request, revision, copiedPolicy));
            return (200, new
            {
                project = new
                {
                    id = Id(WorkspacePermissionPlan.CopyProject),
                    _id = Id(WorkspacePermissionPlan.CopyProject),
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
        if (!org && assigned) CommitCreation(WorkspacePermissionPlan.Assignment, request);
        Record(request, actor, method, path, bytes, org ? WorkspacePermissionContract.RawHash(bytes) : WireHash(new object?[] { null, body }), true, "activation");
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
    private (int, object) TargetAction(WorkspacePermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        if (actor.Principal == Authorities.Observer && method == "GET")
        {
            if (path == "/api/v1/projects") return (200, new { projects = states.Values.Select(s => ProjectRow(s)).ToArray() });
            bool slug = path.StartsWith("/api/v1/projects/slug/", StringComparison.Ordinal);
            var value = states.Values.SingleOrDefault(s => slug ? s.Slug == path.Split('/').Last() : s.Target == path.Split('/').Last());
            return value is null ? (404, new { }) : slug ? (200, ProjectRow(value)) : (200, new { project = ProjectRow(value) });
        }
        if (window is not ("before" or "after")) return (403, new { });
        var action = method switch
        {
            "POST" => WorkspacePermissionAction.Create,
            "PATCH" => WorkspacePermissionAction.Edit,
            "DELETE" => WorkspacePermissionAction.Delete,
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        var rows = plan!.Rows.Where(r => r.Window == (window == "after" && copied ? "copy" : window)).ToArray();
        if (decisions.Count >= rows.Length) return (409, new { });
        // Row identity associates the observed request with its immutable intent.
        // Authorization below does not use the row's control or expected outcome.
        var row = rows[decisions.Count];
        string target = action == WorkspacePermissionAction.Create ? "" : path.Split('/').Last();
        if (path != "/api/v1/projects" + (action == WorkspacePermissionAction.Create ? "" : "/" + Id(row.Target)) || row.Action != action ||
            action == WorkspacePermissionAction.Create && body.GetProperty("slug").GetString() != row.Slug) return (404, new { });
        string org = Id(row.Organization), project = action == WorkspacePermissionAction.Create ? "" : target;
        if (Fault == "self-policy-overwrite" && window == "after" && policy is not null) policy = policy with { Actions = [] };
        var effective = copied && project == Id(WorkspacePermissionPlan.CopyProject) ? copiedPolicy : policy;
        var join = Joins().SingleOrDefault(j => j.Principal == actor.Principal && j.Organization == org && j.Project == project);
        string wire = action.ToString().ToLowerInvariant();
        bool allowed = action != WorkspacePermissionAction.Edit && effective is not null && effective.Subject == "workspace" && effective.Actor == actor.Principal && effective.Kind == actor.Kind &&
            actor.Organization == org && effective.Organization == org && effective.Project == project && effective.Actions.Contains(wire) && effective.Names.Length == 0 &&
            join is { Assigned: true, Active: true, Status: "accepted" } && join.RoleId == effective.Resource && join.RoleSlug == effective.Role &&
            join.Kind == (actor.Kind == MemberPermissionActorKind.User ? "user" : "machine");
        if (Fault == "action-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && org == Organization && project == effective?.Project) allowed = true;
        if (Fault == "scope-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && policy?.Actions.Contains(wire) == true) allowed = true;
        string request = Guid.NewGuid().ToString("N"); var recorded = Fault == "wrong-actor" ? actor with { Principal = Authorities.Observer } : actor;
        if (Fault == "wrong-credential") recorded = recorded with { Hash = "wrong" };
        Record(request, recorded, method, path, bytes, "", allowed, "action");
        var previous = states.GetValueOrDefault(row.Target); object response = new { };
        if (allowed)
        {
            if (action == WorkspacePermissionAction.Create)
            {
                CommitCreation(row.Target, request); states.Add(row.Target, Persist(row, body, 1)); response = new { project = ProjectRow(states[row.Target]) };
            }
            else if (action == WorkspacePermissionAction.Edit)
            {
                states[row.Target] = Persist(row, body, 2); response = new { project = ProjectRow(states[row.Target], false) };
            }
            else
            {
                response = new { project = ProjectRow(previous!, false) };
                string deletedTarget = Fault == "wrong-target-project" ? Id(WorkspacePermissionPlan.OtherProject) : target;
                var closure = resources.Values.Where(r => r.CanonicalId == deletedTarget || storageBindings.Any(b => b.CanonicalId == r.CanonicalId && b.Scope == deletedTarget)).ToArray();
                var retained = resources.Values.Except(closure).ToArray();
                if (Fault != "acknowledged-not-deleted")
                {
                    states.Remove(Fault == "wrong-target-project" ? WorkspacePermissionPlan.OtherProject : row.Target);
                    foreach (var resource in closure)
                        if (Fault != "omitted-cascade" || resource.CanonicalId == target) resources.Remove(resource.Intent);
                    if (policy?.Project == deletedTarget) policy = null;
                    if (copiedPolicy?.Project == deletedTarget) copiedPolicy = null;
                }
                cascades.Add(new(request, deletedTarget, WorkspacePermissionContract.Hash(effective), WorkspacePermissionContract.Hash(join), actor.Id, actor.Hash,
                    Fault == "wrong-cascade" ? closure.Skip(1).ToArray() : closure, retained));
                if (Fault == "retained-corruption") resources.Remove("canary");
            }
            if (action != WorkspacePermissionAction.Delete && Fault == "wrong-target-project" && states.TryGetValue(row.Target, out var wrong)) states[row.Target] = wrong with { Target = Guid.NewGuid().ToString() };
        }
        decisions.Add(new(request, recorded.Principal, recorded.Kind, recorded.Id, recorded.Hash, org, project, Id(row.Target), revision, action, allowed));
        changes.Add(new(request, row.Key, previous, states.GetValueOrDefault(row.Target)));
        return (allowed ? 200 : 403, response);
    }
    private WorkspacePermissionState Persist(WorkspacePermissionRow row, JsonElement body, int version)
    {
        bool edit = version == 2;
        // Persist the actual typed payload, never the witness's expected object.
        var config = new JsonObject
        {
            ["hasDeleteProtection"] = body.GetProperty("hasDeleteProtection").GetBoolean(),
            ["auditLogsRetentionDays"] = edit ? body.GetProperty("auditLogsRetentionDays").GetInt32() : 7,
            ["secretSharing"] = edit && body.GetProperty("secretSharing").GetBoolean(),
            ["autoCapitalization"] = edit && body.GetProperty("autoCapitalization").GetBoolean(),
            ["enforceEncryptedSecretManagerSecretMetadata"] = edit && body.GetProperty("enforceEncryptedSecretManagerSecretMetadata").GetBoolean(),
            ["pitVersionLimit"] = edit ? body.GetProperty("pitVersionLimit").GetInt32() : 10,
            ["showSnapshotsLegacy"] = edit && body.GetProperty("showSnapshotsLegacy").GetBoolean(),
            ["secretDetectionIgnoreValues"] = edit ? JsonNode.Parse(body.GetProperty("secretDetectionIgnoreValues").GetRawText()) : new JsonArray(),
            ["environments"] = new JsonArray(),
            ["deletedEnvironments"] = new JsonArray()
        };
        if (!edit && body.GetProperty("shouldCreateDefaultEnvs").GetBoolean() || Fault == "wrong-defaults") config["environments"] = new JsonArray("development");
        if (Fault == "wrong-settings") config["auditLogsRetentionDays"] = 365;
        if (Fault == "omitted-settings") config.Remove("secretSharing");
        return new(row.Target, Id(row.Target), Id(row.Organization), Id(row.Project), body.GetProperty(edit ? "name" : "projectName").GetString()!,
            Fault == "wrong-slug" ? "foreign-slug" : body.GetProperty("slug").GetString()!,
            Fault == "wrong-description" ? "foreign-description" : body.GetProperty(edit ? "description" : "projectDescription").GetString()!, config.ToJsonString(), version);
    }
    private static object ProjectRow(WorkspacePermissionState state, bool details = true)
    {
        var value = JsonNode.Parse(state.Configuration)!.AsObject();
        value["id"] = state.Target; value["_id"] = state.Target; value["orgId"] = state.Organization;
        value["name"] = state.Name; value["slug"] = state.Slug; value["description"] = state.Description; value["type"] = "secret-manager";
        value["createdAt"] = "2026-01-01T00:00:00Z"; value["updatedAt"] = "2026-01-01T00:00:01Z";
        if (!details) { value.Remove("_id"); value.Remove("environments"); value.Remove("deletedEnvironments"); }
        return value;
    }
    private object Role(string membership, string role) => new
    {
        id = Id(WorkspacePermissionPlan.Assignment),
        projectMembershipId = membership,
        role,
        isTemporary = false,
        createdAt = "2026-01-01T00:00:00Z",
        updatedAt = "2026-01-01T00:00:01Z"
    };
    private static string WireHash(object value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        try { return WorkspacePermissionContract.RawHash(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
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
        OpenRelease.TrySetResult(); IssuerRelease.TrySetResult(); DispatchRelease.TrySetResult();
        if (delayed is not null) await delayed;
        shutdown.Cancel(); listener.Stop();
        try { await accept; } catch (SocketException) when (shutdown.IsCancellationRequested) { }
        await Task.WhenAll(connections);
        foreach (var bytes in privateBuffers) CryptographicOperations.ZeroMemory(bytes);
        ownedKey?.Dispose(); Source.Dispose(); foreach (var writer in writers.Values) writer.Dispose(); shutdown.Dispose();
    }
}
