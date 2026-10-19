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
internal sealed class InfisicalGatewayPermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static MemberPermissionAuthorities Authorities => InfisicalMemberPermissionFixture.Authorities;
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<GatewayPermissionJournal, InfisicalGatewayPermissionWriter> writers = [];
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
        ["30000000-0000-0000-0000-000000000001"] = "borrowed-gateway",
        ["30000000-0000-0000-0000-000000000002"] = "borrowed-user",
        ["30000000-0000-0000-0000-000000000003"] = "borrowed-machine",
        ["30000000-0000-0000-0000-000000000004"] = "borrowed-membership",
        ["30000000-0000-0000-0000-000000000005"] = "borrowed-policy-role",
        ["30000000-0000-0000-0000-000000000006"] = "borrowed-config"
    };
    private readonly Dictionary<string, GatewayPermissionCredential> tokens = [];
    private readonly List<GatewayPermissionCredential> credentials = [];
    private readonly List<GatewayPermissionBinding> issuanceBindings = [], storageBindings = [];
    private readonly Dictionary<string, GatewayPermissionResource> resources = [];
    private readonly Dictionary<string, GatewayPermissionState> states = [];
    private readonly List<GatewayPermissionIngress> ingress = [];
    private readonly List<GatewayPermissionCommit> commits = [];
    private readonly List<GatewayPermissionAccess> decisions = [];
    private readonly List<GatewayPermissionChange> changes = [];
    private readonly List<byte[]> privateBuffers = [];
    private readonly MemberPermissionBorrowed[] borrowed;
    private GatewayPermissionRoot? root;
    private GatewayPermissionPlan? plan;
    private GatewayPermissionActor[] actors = [];
    private GatewayPermissionPolicy? policy;
    private readonly Dictionary<string, GatewayPermissionState> configurations = [];
    private readonly List<GatewayPermissionConfigurationChange> configurationHistory = [], storageHistory = [];
    private readonly List<GatewayPermissionRetirement> retiredConfigurations = [];
    internal bool RetainConfigId { get; }
    private ECDsa? ownedKey;
    private string revision = "policy-1", window = "";
    private int stage;
    private bool closed, closing, armed, settled, assigned;
    private Task? delayed;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal GatewayPermissionProfile Profile { get; }
    internal InfisicalGatewayPermissionFixtureSource Source { get; }
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
    internal int Remaining => resources.Count + states.Count + credentials.Count + (policy is null ? 0 : 1) + configurations.Count + (ownedKey is null ? 0 : 1);
    internal bool BorrowedPreserved => Borrowed().SequenceEqual(borrowed);
    internal InfisicalGatewayPermissionFixture(string fault = "", bool retainConfigId = true)
    {
        Fault = fault; RetainConfigId = retainConfigId;
        foreach (var journal in Enum.GetValues<GatewayPermissionJournal>()) writers.Add(journal, new(journal));
        Profile = new("controlled-gateways", "controlled-epoch", "controlled-v1", writers.Values.Select(w => w.Pin).ToArray());
        borrowed = Borrowed(); listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/"); Source = new(this); accept = AcceptAsync();
    }
    internal GatewayPermissionInput Input(string operation, GatewayPermissionAction action) =>
        new(new(new("https://gateway-source.invalid/"), "coordinator-token", "gateway-coordinator", 30), "gateway-capability", Profile,
            GatewayPermissionContract.Scope(operation), GatewayPermissionContract.ActorKind(operation), action, 30);
    internal NativeEnvironment Environment(string operation, GatewayPermissionAction action, bool configured = true)
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
                    gatewayPermission = Input(operation, action)
                }
            }
        }, GatewayPermissionContract.Options)!;
        if (!configured) scope["scopes"]!["local"]!.AsObject().Remove("gatewayPermission");
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
        }, GatewayPermissionContract.Options));
    }
    internal GatewayPermissionRoot Root(string operation, GatewayPermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization, operation,
            GatewayPermissionContract.Variant(action), boundary, "local", "gateway-coordinator", MemberPermissionSourceKind.ControlledFixture,
            GatewayPermissionContract.Scope(operation), GatewayPermissionContract.ActorKind(operation), action, Authorities, Profile);
    private MemberPermissionBorrowed[] Borrowed() => hostTokens.Select(p => new MemberPermissionBorrowed("host-credential", p.Key, GatewayPermissionContract.Hash(p.Value)))
        .Concat(writers.Values.Select(w => new MemberPermissionBorrowed("host-key", w.Pin.Writer, GatewayPermissionContract.Hash(w.Pin.Spki))))
        .Concat(borrowedObjects.Select(p => new MemberPermissionBorrowed(p.Value, p.Key, GatewayPermissionContract.Hash(p.Value)))).ToArray();
    private GatewayPermissionIssued Issued => new(actors, storageBindings.ToArray());
    private string Id(string key) => Issued.Id(key);
    private string CommitCreation(string key, string? request = null, bool admitted = false)
    {
        GatewayPermissionContract.Require(root is not null && plan is not null && !closed && (!closing || admitted) && !resources.ContainsKey(key) &&
            !storageBindings.Any(b => b.Intent == key));
        var intent = plan!.Intents.Single(i => i.Key == key);
        GatewayPermissionContract.Require(Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0));
        // There is deliberately no ID-generation path in Reserve or plan construction.
        string canonical = Guid.NewGuid().ToString();
        var binding = new GatewayPermissionBinding(key, GatewayPermissionContract.Hash(intent), intent.Work, intent.Kind, Id(intent.Scope),
            GatewayPermissionPlan.InputHash(intent, Id), canonical, request ?? Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"));
        issuanceBindings.Add(binding); storageBindings.Add(binding); resources.Add(key, new(key, canonical));
        return canonical;
    }
    private GatewayPermissionActor IssueActor(int i)
    {
        string key = plan!.ActorKey(i), scope = Id(plan.ActorScope(i)); var kind = plan.ActorKind(i);
        bool owned = !key.StartsWith("@", StringComparison.Ordinal);
        if (owned && Id(key).Length == 0) CommitCreation(key);
        string principal = Id(key); GatewayPermissionCredential credential; byte[] bytes;
        if (owned)
        {
            (credential, bytes) = IssueCredential("actor-credential-" + i, principal, kind, scope);
        }
        else
        {
            bytes = Encoding.UTF8.GetBytes(hostTokens[principal]);
            credential = new("host-" + principal, principal, kind, scope, GatewayPermissionContract.RawHash(bytes), false);
            CryptographicOperations.ZeroMemory(bytes); bytes = [];
            if (!credentials.Any(c => c.Id == credential.Id)) credentials.Add(credential);
        }
        CommitCreation(plan.ActorMembership(i));
        return new(principal, kind, scope, credential.Id, credential.Hash, bytes, owned);
    }
    private (GatewayPermissionCredential Credential, byte[] Bytes) IssueCredential(string key, string principal, MemberPermissionActorKind kind, string scope)
    {
        string id = CommitCreation(key);
        byte[] random = RandomNumberGenerator.GetBytes(32), bytes;
        try { bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(random)); } finally { CryptographicOperations.ZeroMemory(random); }
        privateBuffers.Add(bytes); Copies.Add(bytes);
        var credential = new GatewayPermissionCredential(id, principal, kind, scope, GatewayPermissionContract.RawHash(bytes), true);
        credentials.Add(credential); tokens.Add(Encoding.ASCII.GetString(bytes), credential); return (credential, bytes);
    }
    private void Open()
    {
        Opens++; CommitCreation(GatewayPermissionPlan.OtherOrganization);
        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
        foreach (string key in new[] { "issuer-work", "dispatch-work", "registration", "canary", "owned-key" }) CommitCreation(key);
        ownedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        actors = Enumerable.Range(0, root!.ScopeProfile == GatewayPermissionScope.Organization ? 4 : 3).Select(IssueActor).ToArray();
        foreach (var row in plan!.Rows.Where(r => r.Window != "copy")) Bootstrap(row);
        assigned = !root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        if (assigned)
        {
            CommitCreation(plan.PolicyKey);
            string[] actions = ["create-gateways", "edit-gateways"];
            string baseline = actions[(Array.IndexOf(actions, GatewayPermissionContract.Wire(root.Action)) + 1) % actions.Length];
            policy = new(Id(plan.PolicyKey), revision, actors[0].Principal, actors[0].Kind, Organization,
                "", "gateway", [baseline], [], plan.Slug);
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
        lock (gate) CommitCreation(GatewayPermissionPlan.Deferred, admitted: true);
    }
    private void Bootstrap(GatewayPermissionRow row)
    {
        if (row.Action == GatewayPermissionAction.Create) return;
        CommitCreation(row.Target);
        var state = NewState(row, row.Name, GatewayPermissionPlan.Accounts(1), GatewayPermissionPlan.Principals(1), 1);
        states.Add(row.Key, state);
        RecordConfiguration(storageBindings.Single(b => b.Intent == row.Target).Request, null, state);
    }
    internal GatewayPermissionPacket Step(GatewayPermissionRoot selected, GatewayPermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == GatewayPermissionStep.Reserve)
            {
                GatewayPermissionContract.Require(root is null && capability == "gateway-capability" && selected.Origin == Origin.AbsoluteUri &&
                    selected.Organization == Organization && selected.Authorities == Authorities && GatewayPermissionContract.Hash(Profile) == GatewayPermissionContract.Hash(selected.Profile));
                root = selected; plan = new(selected);
                if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
            }
            GatewayPermissionContract.Require(root is not null && GatewayPermissionContract.Hash(root) == GatewayPermissionContract.Hash(selected) && !closed &&
                (step == GatewayPermissionStep.Close || stage == (int)step));
            if (step != GatewayPermissionStep.Close) stage++;
            switch (step)
            {
                case GatewayPermissionStep.Open: Open(); break;
                case GatewayPermissionStep.Before: Clear(); window = "before"; break;
                case GatewayPermissionStep.Arm: Clear(); window = ""; armed = true; break;
                case GatewayPermissionStep.Settle: settled = true; break;
                case GatewayPermissionStep.After:
                    ingress.RemoveAll(e => e.Phase != "activation"); commits.RemoveAll(c => !ingress.Any(e => e.Request == c.Request));
                    decisions.Clear(); changes.Clear(); window = "after"; break;
                case GatewayPermissionStep.ObserveBefore:
                case GatewayPermissionStep.ObserveAfter: window = ""; break;
                case GatewayPermissionStep.Close:
                    Closes++;
                    GatewayPermissionContract.Require(closing && (delayed is null || delayed.IsCompletedSuccessfully));
                    // Reconcile native IDs from original-root issuance AND storage, not the Open reply.
                    GatewayPermissionContract.Require(issuanceBindings.SequenceEqual(storageBindings));
                    foreach (var binding in storageBindings)
                        GatewayPermissionContract.Require(binding.IntentHash == GatewayPermissionContract.Hash(plan!.Intents.Single(i => i.Key == binding.Intent)) &&
                            !borrowed.Any(b => b.Id == binding.CanonicalId));
                    foreach (var binding in storageBindings)
                    {
                        var native = resources.SingleOrDefault(r => r.Value.CanonicalId == binding.CanonicalId);
                        if (native.Key is null) continue; // A witnessed downstream delete may already have removed it.
                        GatewayPermissionContract.Require(native.Value.Intent == binding.Intent);
                        resources.Remove(native.Key);
                    }
                    foreach (var state in configurations.Values.ToArray()) RecordConfiguration(root!.Id + ":close:" + state.Target, state, null);
                    states.Clear(); credentials.Clear(); tokens.Clear(); policy = null;
                    foreach (var bytes in privateBuffers) CryptographicOperations.ZeroMemory(bytes);
                    ownedKey?.Dispose(); ownedKey = null; closed = settled = true; armed = false; window = "";
                    if (Fault == "cleanup") resources.Add("residual", new("canary", Id("canary")));
                    if (Fault == "borrowed-change") borrowedObjects[borrowedObjects.Keys.First()] = "modified";
                    if (Fault == "borrowed-config-change") borrowedObjects[borrowedObjects.Keys.Last()] = "modified";
                    break;
            }
            return Packet(step);
        }
    }
    private void Clear() { ingress.Clear(); commits.Clear(); decisions.Clear(); changes.Clear(); }
    private GatewayPermissionSigned<T> Sign<T>(GatewayPermissionStep step, GatewayPermissionJournal journal, T content) => writers[journal].Sign(root!, step, content);
    private GatewayPermissionJoin[] Joins() => closed ? [] : actors.Select((actor, i) => new GatewayPermissionJoin(actor.Principal,
        actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization, "", Id(plan!.ActorMembership(i)),
        i == 0 && assigned, i == 0 && assigned ? Id(plan.PolicyKey) : "",
        i == 0 && assigned ? Fault == "wrong-role-binding" ? "foreign-role" : plan.Slug : "no-access", true, "accepted")).ToArray();
    private GatewayPermissionPacket Packet(GatewayPermissionStep step)
    {
        bool open = step == GatewayPermissionStep.Open, observe = step is GatewayPermissionStep.ObserveBefore or GatewayPermissionStep.ObserveAfter;
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
        var allPolicies = new[] { policy }.OfType<GatewayPermissionPolicy>().OrderBy(p => p.Resource).ToArray();
        var committed = observe || step == GatewayPermissionStep.Settle ? commits.ToArray() : [];
        if (step == GatewayPermissionStep.Settle && Fault == "wrong-policy-target" && committed.Length == 1)
        { committed[0] = committed[0] with { Policy = committed[0].Policy with { Resource = Guid.NewGuid().ToString() } }; allPolicies = [committed[0].Policy]; }
        var intents = plan!.Intents.ToArray();
        if (open && Fault == "intent-mutation") intents[0] = intents[0] with { Input = "changed" };
        var packet = new GatewayPermissionPacket(
            Sign(step, GatewayPermissionJournal.Ownership, new GatewayPermissionOwner(intents, resources.Values.ToArray(), Borrowed(), true, true,
                settled || closed, settled || closed, open && Fault == "pending-issuer" ? 1 : 0, closed ? 0 : 1, open ? actors : [])),
            Sign(step, GatewayPermissionJournal.Ingress, observe || step == GatewayPermissionStep.Settle ? ingress.ToArray() : []),
            Sign(step, GatewayPermissionJournal.Policy, new GatewayPermissionPolicies(allPolicies, committed)),
            Sign(step, GatewayPermissionJournal.Storage, new GatewayPermissionStorage(storage, inventory, observe ? changes.ToArray() : [], storageHistory.ToArray())),
            Sign(step, GatewayPermissionJournal.Issuer, new GatewayPermissionIssuance(issue, credentialRows)),
            Sign(step, GatewayPermissionJournal.Membership, joins), Sign(step, GatewayPermissionJournal.Access, observe ? decisions.ToArray() : []),
            Sign(step, GatewayPermissionJournal.Configuration, Configurations(step)), []);
        var seals = new List<GatewayPermissionSigned<MemberPermissionSeal>>();
        Add(GatewayPermissionJournal.Ownership, packet.Owner.Payload); Add(GatewayPermissionJournal.Ingress, packet.Ingress.Payload);
        Add(GatewayPermissionJournal.Policy, packet.Policy.Payload); Add(GatewayPermissionJournal.Storage, packet.Storage.Payload);
        Add(GatewayPermissionJournal.Issuer, packet.Issuer.Payload); Add(GatewayPermissionJournal.Membership, packet.Membership.Payload); Add(GatewayPermissionJournal.Access, packet.Access.Payload); Add(GatewayPermissionJournal.Configuration, packet.Configuration.Payload);
        return packet with { Seals = open && Fault == "missing-seal" ? seals.Skip(1).ToArray() : seals.ToArray() };
        void Add<T>(GatewayPermissionJournal journal, T payload) => seals.Add(Sign(step, journal,
            new MemberPermissionSeal(GatewayPermissionContract.Hash(payload), !(open && Fault == "nonterminal"), 0, 1)));
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
                GatewayPermissionContract.Require(length is >= 0 and <= 131072);
                body = new byte[length]; Copies.Add(body); await stream.ReadExactlyAsync(body, shutdown.Token);
                string bearer = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?.Split(' ').Last() ?? "";
                using var document = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                (int Status, object Body) result;
                lock (gate) result = Handle(request[0], new Uri(Origin, request[1]), bearer, document.RootElement, body);
                if (Fault == "delayed-dispatch" && request[0] == "PATCH" && request[1].StartsWith("/api/v3/gateways/", StringComparison.Ordinal))
                {
                    DispatchEntered.TrySetResult();
                    await DispatchRelease.Task.WaitAsync(shutdown.Token);
                }
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
    private GatewayPermissionCredential Authenticate(string bearer)
    {
        if (tokens.TryGetValue(bearer, out var credential)) return credential;
        string principal = hostTokens.SingleOrDefault(p => p.Value == bearer).Key ?? "unknown";
        byte[] bytes = Encoding.UTF8.GetBytes(bearer);
        try { return new("host-" + principal, principal, MemberPermissionActorKind.Machine, Organization, GatewayPermissionContract.RawHash(bytes), false); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private void Record(string request, GatewayPermissionCredential actor, string method, string path, byte[] bytes, string intent, bool allowed, string phase) =>
        ingress.Add(new(request, actor.Principal, actor.Kind, actor.Hash, actor.Organization, method, path, GatewayPermissionContract.RawHash(bytes), intent, allowed, phase));
    private (int, object) Handle(string method, Uri uri, string bearer, JsonElement body, byte[] bytes)
    {
        if (root is null || actors.Length == 0 || closed || closing) return (403, new { });
        var actor = Authenticate(bearer); string path = uri.AbsolutePath;
        bool create = GatewayPermissionContract.Create(root.Operation);
        string originalPath = "/api/v1/organization/roles" + (create ? "" : "/" + Id(plan!.PolicyKey));
        if (path == originalPath && method == (create ? "POST" : "PATCH") && body.GetProperty("slug").GetString() == plan!.Slug)
        {
            if (!armed || settled || Originals != 0) return (409, new { });
            Originals++; string request = Guid.NewGuid().ToString("N");
            bool allowed = actor.Principal == Authorities.Administrative && actor.Kind == MemberPermissionActorKind.Machine && actor.Organization == Organization;
            Record(request, actor, method, path, bytes, GatewayPermissionContract.RawHash(bytes), allowed, "original");
            if (!allowed) return (403, new { });
            var permissions = body.GetProperty("permissions"); var permission = permissions.EnumerateArray().Single();
            var actions = permission.GetProperty("action");
            string[] selected = actions.ValueKind == JsonValueKind.Array ? actions.EnumerateArray().Select(a => a.GetString()!).ToArray() : [actions.GetString()!];
            string[] names = permission.TryGetProperty("conditions", out _) ? ["unprojected-condition"] : [];
            if (Fault is not ("ignored-policy" or "lost-nonapplied"))
            {
                if (create) CommitCreation(plan.PolicyKey, request);
                string old = revision; revision = "policy-2";
                policy = new(Id(plan.PolicyKey), revision, actors[0].Principal, actors[0].Kind, Organization, "",
                    permission.GetProperty("subject").GetString()!, Fault == "partial" ? [] : selected,
                    Fault == "wrong-condition" ? ["forged-condition"] : names, Fault == "incomplete-policy" ? "" : plan.Slug);
                commits.Add(new(request, old, policy));
            }
            return (200, new
            {
                role = new
                {
                    id = Id(plan.PolicyKey),
                    name = plan.Slug,
                    slug = plan.Slug,
                    orgId = Organization,
                    createdAt = "2026-01-01T00:00:00Z",
                    updatedAt = "2026-01-01T00:00:01Z",
                    permissions = JsonNode.Parse(permissions.GetRawText())
                }
            });
        }
        if (settled && actor.Principal == Authorities.Setup && actor.Kind == MemberPermissionActorKind.Machine && policy is not null &&
            path == "/api/v2/organizations/" + Organization + "/memberships/" + Id(plan!.ActorMembership(0)))
        {
            if (assigned || method != "PATCH" || body.GetProperty("role").GetString() != plan!.Slug) return (403, new { });
            string request = Guid.NewGuid().ToString("N"); assigned = Fault != "assignment-echo";
            Record(request, actor, method, path, bytes, GatewayPermissionContract.RawHash(bytes), true, "activation");
            commits.Add(new(request, revision, policy));
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
        return TargetAction(actor, method, path, body, bytes);
    }
    private (int, object) TargetAction(GatewayPermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        if (actor.Principal == Authorities.Observer && method == "GET" && path.StartsWith("/api/v3/gateways/", StringComparison.Ordinal))
        {
            var stored = states.Values.SingleOrDefault(s => s.Target == path.Split('/').Last());
            if (stored is null) return (404, new { });
            return (200, TargetRow(Fault == "readback-mismatch" ? stored with { Accounts = "333333333333" } : stored));
        }
        if (window is not ("before" or "after")) return (403, new { });
        var action = method == "POST" ? GatewayPermissionAction.Create : GatewayPermissionAction.Edit;
        if (method is not ("POST" or "PATCH") || (method == "POST" ? path != "/api/v3/gateways" : !path.StartsWith("/api/v3/gateways/", StringComparison.Ordinal))) return (404, new { });
        var row = action == GatewayPermissionAction.Create ? plan!.Rows.SingleOrDefault(r => r.Name == body.GetProperty("name").GetString()) :
            plan!.Rows.SingleOrDefault(r => Id(r.Target) == path.Split('/').Last());
        if (row is null) return (404, new { });
        string org = Id(row.Organization), wire = GatewayPermissionContract.Wire(action);
        bool allowed = assigned && policy is not null && policy.Subject == "gateway" && policy.Actor == actor.Principal && policy.Kind == actor.Kind &&
            actor.Organization == org && policy.Organization == org && policy.Actions.Contains(wire) && policy.Names.Length == 0 &&
            Joins().Any(j => j.Principal == actor.Principal && j.Kind == (actor.Kind == MemberPermissionActorKind.User ? "user" : "machine") &&
                j.Organization == org && j.Assigned && j.RoleId == policy.Resource && j.RoleSlug == policy.Role && j.Active && j.Status == "accepted");
        if (Fault == "action-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && org == Organization) allowed = true;
        if (Fault == "scope-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && policy?.Actions.Contains(wire) == true) allowed = true;
        string request = Guid.NewGuid().ToString("N"); var recorded = Fault == "wrong-actor" ? actor with { Principal = Authorities.Observer } : actor;
        if (Fault == "wrong-credential") recorded = recorded with { Hash = "wrong" };
        Record(request, recorded, method, path, bytes, GatewayPermissionContract.RawHash(bytes), allowed, "action");
        var previous = states.GetValueOrDefault(row.Key); object response = new { };
        if (allowed)
        {
            if (action == GatewayPermissionAction.Create) CommitCreation(row.Target, request);
            var auth = body.GetProperty("authMethod");
            if (auth.GetProperty("method").GetString() != "aws") return (400, new { });
            int version = action == GatewayPermissionAction.Edit ? 2 : 1;
            var next = NewState(row, body.GetProperty("name").GetString()!, auth.GetProperty("allowedAccountIds").GetString()!,
                auth.GetProperty("allowedPrincipalArns").GetString()!, version, previous);
            states[row.Key] = next; RecordConfiguration(request, previous, next); response = TargetRow(next);
            if (Fault == "wrong-gateway") states[row.Key] = next with { Target = Guid.NewGuid().ToString() };
            if (Fault == "persistence-echo") states[row.Key] = previous ?? next with { Accounts = "333333333333" };
            if (Fault == "self-policy-overwrite" && policy is not null) policy = policy with { Actions = ["delete-gateways"] };
        }
        decisions.Add(new(request, recorded.Principal, recorded.Kind, recorded.Id, recorded.Hash, org, "", Id(row.Target), revision, action, allowed));
        changes.Add(new(request, row.Key, previous, states.GetValueOrDefault(row.Key)));
        return (allowed ? 200 : 403, response);
    }
    private GatewayPermissionState NewState(GatewayPermissionRow row, string name, string accounts, string principals, int version, GatewayPermissionState? before = null) =>
        new(row.Key, Id(row.Target), Id(row.Organization), "", Fault == "wrong-name" && version == 2 ? "wrong" : name,
            before is not null && RetainConfigId ? before.ConfigId : Guid.NewGuid().ToString(), Guid.NewGuid().ToString(),
            Fault == "wrong-auth" && version == 2 ? "333333333333" : accounts, principals, version,
            "2026-01-01T00:00:00Z", version == 1 ? "2026-01-01T00:00:00Z" : "2026-01-01T00:00:01Z");
    private void RecordConfiguration(string request, GatewayPermissionState? before, GatewayPermissionState? after)
    {
        var retirement = before is null ? null : new GatewayPermissionRetirement(before.Target, before.ConfigId, before.ConfigRevision, request,
            after is null ? "root-close" : before.ConfigId == after.ConfigId ? "retained-id" : "replaced-id");
        var change = new GatewayPermissionConfigurationChange(root!.Id, root.Nonce, request, before, after, retirement);
        storageHistory.Add(change); configurationHistory.Add(change);
        if (retirement is not null) retiredConfigurations.Add(retirement);
        if (before is not null && !(Fault == "orphan-replaced-config" && after is not null && before.ConfigId != after.ConfigId))
            configurations.Remove(before.ConfigId);
        if (after is not null) configurations[after.ConfigId] = after;
    }
    private GatewayPermissionConfigurations Configurations(GatewayPermissionStep step)
    {
        var history = configurationHistory.ToArray(); var inventory = configurations.Values.ToArray(); var retired = retiredConfigurations.ToArray();
        if (step is GatewayPermissionStep.ObserveBefore or GatewayPermissionStep.ObserveAfter && history.Length > 0)
        {
            var last = history[^1];
            history[^1] = Fault switch
            {
                "config-parent" => last with { After = last.After! with { Target = Guid.NewGuid().ToString() } },
                "config-request" => last with { Request = "foreign-request" },
                "config-id-history" => last with { After = last.After! with { ConfigId = Guid.NewGuid().ToString() } },
                "config-revision" => last with { After = last.After! with { ConfigRevision = history[0].After!.ConfigRevision } },
                "config-root" => last with { Nonce = "foreign-nonce" },
                _ => last
            };
            if (Fault == "config-inventory") inventory = inventory.Skip(1).ToArray();
        }
        if (Fault == "unaccounted-retirement" && retired.Length > 0) retired = retired.Skip(1).ToArray();
        if (Fault == "config-cleanup" && step == GatewayPermissionStep.Close && history.Length > 0) inventory = [history[0].After!];
        return new(inventory, history, retired);
    }
    private object TargetRow(GatewayPermissionState state)
    {
        var result = new JsonObject
        {
            ["id"] = state.Target,
            ["name"] = state.Name,
            ["createdAt"] = "2026-01-01T00:00:00Z",
            ["updatedAt"] = state.ConfigUpdatedAt,
            ["canRevoke"] = true,
            ["authMethod"] = new JsonObject
            {
                ["method"] = "aws",
                ["config"] = new JsonObject
                {
                    ["id"] = Fault == "response-config-id" ? Guid.NewGuid().ToString() : state.ConfigId,
                    ["allowedAccountIds"] = state.Accounts,
                    ["allowedPrincipalArns"] = state.Principals,
                    ["createdAt"] = state.ConfigCreatedAt,
                    ["updatedAt"] = state.ConfigUpdatedAt
                }
            }
        };
        if (Fault == "omitted-auth") result.Remove("authMethod");
        if (Fault == "omitted-name") result.Remove("name");
        return result;
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
