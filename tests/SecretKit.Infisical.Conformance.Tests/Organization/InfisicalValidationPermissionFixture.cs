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
internal sealed class InfisicalValidationPermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static MemberPermissionAuthorities Authorities => InfisicalMemberPermissionFixture.Authorities;
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly CancellationTokenSource ingressStop = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<ValidationPermissionJournal, InfisicalValidationPermissionWriter> writers = [];
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
    private readonly Dictionary<string, ValidationPermissionCredential> tokens = [];
    private readonly List<ValidationPermissionCredential> credentials = [];
    private readonly List<ValidationPermissionBinding> issuanceBindings = [], storageBindings = [];
    private readonly Dictionary<string, ValidationPermissionResource> resources = [];
    private readonly Dictionary<string, ValidationPermissionState> states = [];
    private readonly List<ValidationPermissionIngress> ingress = [], ingressHistory = [];
    private readonly List<ValidationPermissionCommit> commitHistory = [];
    private readonly List<ValidationPermissionChange> changeHistory = [];
    private readonly List<ValidationPermissionAccess> accessHistory = [];
    private readonly List<ValidationPermissionAuthorization> authorizationHistory = [];
    private readonly List<ValidationPermissionCredential> credentialHistory = [];
    private readonly List<ValidationPermissionCommit> commits = [];
    private readonly List<ValidationPermissionAccess> decisions = [];
    private readonly List<ValidationPermissionAuthorization> writeDecisions = [];
    private readonly InfisicalValidationPermissionEnforcer enforcer;
    private readonly InfisicalValidationPermissionBackend backend;
    private readonly List<ValidationPermissionWriteGrant> writeGrants = [];
    private readonly List<ValidationPermissionChange> changes = [];
    private readonly List<byte[]> privateBuffers = [];
    private readonly byte[] borrowedMaterial = "borrowed-backend-secret"u8.ToArray();
    private readonly MemberPermissionBorrowed[] borrowed;
    private ValidationPermissionRoot? root;
    private ValidationPermissionPlan? plan;
    private ValidationPermissionActor[] actors = [];
    private ValidationPermissionPolicy? policy, copiedPolicy;
    private ECDsa? ownedKey;
    private JsonElement templateConfiguration;
    private ValidationPermissionCopiedEnvironment[] copiedEnvironments = [];
    private string revision = "policy-1", window = "";
    private int stage;
    private bool closed, closing, armed, settled, assigned, copied;
    private Task? delayed;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal ValidationPermissionProfile Profile { get; }
    internal InfisicalValidationPermissionFixtureSource Source { get; }
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    internal TaskCompletionSource OpenEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource OpenRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource CloseEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource PipelineEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource PipelineRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource TransportAccepted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal int Originals { get; private set; }
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal ValidationPermissionPacket? ClosedPacket { get; private set; }
    internal IEnumerable<byte[]> BackendBuffers => backend.Buffers;
    internal int Generated => storageBindings.Count;
    internal int ConnectionCount => connections.Count;
    internal string Progress => $"stage={stage};opens={Opens};closing={closing};closed={closed};connections={connections.Count};active={connections.Count(t => !t.IsCompleted)};writes={authorizationHistory.Count}";
    internal int Registrations => root is not null && !closed ? 1 : 0;
    internal int Remaining => backend.Remaining + resources.Count + states.Count + credentials.Count + (policy is null ? 0 : 1) + (copiedPolicy is null ? 0 : 1) + (ownedKey is null ? 0 : 1);
    internal bool BorrowedPreserved => Borrowed().SequenceEqual(borrowed);
    internal InfisicalValidationPermissionFixture(string fault = "")
    {
        Fault = fault;
        foreach (var journal in Enum.GetValues<ValidationPermissionJournal>().Where(j => j is not (ValidationPermissionJournal.Enforcement or ValidationPermissionJournal.Backend))) writers.Add(journal, new(journal));
        enforcer = new(() => states.Values.ToArray(), fault); backend = new(fault, borrowedMaterial);
        Profile = new("controlled-validation", "controlled-epoch", "controlled-v1", [.. writers.Values.Select(w => w.Pin), enforcer.Pin, backend.Pin]);
        borrowed = Borrowed(); listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/"); Source = new(this); accept = AcceptAsync();
    }
    internal ValidationPermissionInput Input(string operation, ValidationPermissionAction action) =>
        new(new(new("https://environment-source.invalid/"), "coordinator-token", "validation-coordinator", 30), "validation-capability", Profile,
            ValidationPermissionContract.Scope(operation), ValidationPermissionContract.ActorKind(operation), action, 30);
    internal NativeEnvironment Environment(string operation, ValidationPermissionAction action, bool configured = true)
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
                    validationPermission = Input(operation, action)
                }
            }
        }, ValidationPermissionContract.Options)!;
        if (!configured) scope["scopes"]!["local"]!.AsObject().Remove("validationPermission");
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
        }, ValidationPermissionContract.Options));
    }
    internal ValidationPermissionRoot Root(string operation, ValidationPermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization, operation,
            ValidationPermissionContract.Variant(action), boundary, "local", "validation-coordinator", MemberPermissionSourceKind.ControlledFixture,
            ValidationPermissionContract.Scope(operation), ValidationPermissionContract.ActorKind(operation), action, Authorities, Profile);
    private MemberPermissionBorrowed[] Borrowed() => hostTokens.Select(p => new MemberPermissionBorrowed("host-credential", p.Key, ValidationPermissionContract.Hash(p.Value)))
        .Concat(writers.Values.Select(w => w.Pin).Concat([enforcer.Pin, backend.Pin])
            .Select(pin => new MemberPermissionBorrowed("host-key", pin.Writer, ValidationPermissionContract.Hash(pin.Spki))))
        .Concat(borrowedObjects.Select(p => new MemberPermissionBorrowed(p.Value, p.Key, ValidationPermissionContract.Hash(p.Value))))
        .Concat(backend.Borrowed).ToArray();
    private ValidationPermissionIssued Issued => new(actors, storageBindings.ToArray());
    private string Id(string key) => Issued.Id(key);
    private string CommitCreation(string key, string? request = null, bool admitted = false, string? nativeId = null, string? commitId = null)
    {
        ValidationPermissionContract.Require(root is not null && plan is not null && !closed && (!closing || admitted) && !resources.ContainsKey(key) &&
            !storageBindings.Any(b => b.Intent == key));
        var intent = plan!.Intents.Single(i => i.Key == key);
        ValidationPermissionContract.Require(Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0));
        // There is deliberately no ID-generation path in Reserve or plan construction.
        string canonical = nativeId ?? Guid.NewGuid().ToString();
        var binding = new ValidationPermissionBinding(key, ValidationPermissionContract.Hash(intent), intent.Work, intent.Kind, Id(intent.Scope),
            ValidationPermissionPlan.InputHash(intent, Id), canonical, request ?? Guid.NewGuid().ToString("N"), commitId ?? Guid.NewGuid().ToString("N"));
        issuanceBindings.Add(binding); storageBindings.Add(binding); resources.Add(key, new(key, canonical));
        return canonical;
    }
    private ValidationPermissionActor IssueActor(int i)
    {
        string key = plan!.ActorKey(i), scope = Id(plan.ActorScope(i)); var kind = plan.ActorKind(i);
        bool owned = !key.StartsWith("@", StringComparison.Ordinal);
        if (owned && Id(key).Length == 0) CommitCreation(key);
        string principal = Id(key); ValidationPermissionCredential credential; byte[] bytes;
        if (owned)
        {
            (credential, bytes) = IssueCredential("actor-credential-" + i, principal, kind, scope);
        }
        else
        {
            bytes = Encoding.UTF8.GetBytes(hostTokens[principal]);
            credential = new("host-" + principal, principal, kind, scope, ValidationPermissionContract.RawHash(bytes), false);
            CryptographicOperations.ZeroMemory(bytes); bytes = [];
            if (!credentials.Any(c => c.Id == credential.Id)) { credentials.Add(credential); credentialHistory.Add(credential); }
        }
        CommitCreation(plan.ActorMembership(i));
        return new(principal, kind, scope, credential.Id, credential.Hash, bytes, owned);
    }
    private (ValidationPermissionCredential Credential, byte[] Bytes) IssueCredential(string key, string principal, MemberPermissionActorKind kind, string scope)
    {
        string id = CommitCreation(key);
        byte[] random = RandomNumberGenerator.GetBytes(32), bytes;
        try { bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(random)); } finally { CryptographicOperations.ZeroMemory(random); }
        privateBuffers.Add(bytes); Copies.Add(bytes);
        var credential = new ValidationPermissionCredential(id, principal, kind, scope, ValidationPermissionContract.RawHash(bytes), true);
        credentials.Add(credential); credentialHistory.Add(credential); tokens.Add(Encoding.ASCII.GetString(bytes), credential); return (credential, bytes);
    }
    private void Open()
    {
        Opens++; CommitCreation(ValidationPermissionPlan.OtherOrganization);
        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
        CommitCreation(ValidationPermissionPlan.Project); CommitCreation(ValidationPermissionPlan.OtherProject);
        foreach (string key in new[] { "issuer-work", "dispatch-work", "enforcement-work", "backend-work", "registration", "canary", "owned-key" }) CommitCreation(key);
        ownedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        actors = Enumerable.Range(0, 4).Select(IssueActor).ToArray();
        foreach (var row in plan!.Rows.Where(r => r.Window != "copy")) Bootstrap(row);
        Grants(ValidationPermissionPlan.Project); Grants(ValidationPermissionPlan.OtherProject);
        assigned = !root!.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        if (assigned)
        {
            CommitCreation(plan.PolicyKey);
            string[] actions = ["read", "create", "edit", "delete"];
            string baseline = actions[(Array.IndexOf(actions, ValidationPermissionContract.Wire(root.Action)) + 1) % actions.Length];
            policy = new(Id(plan.PolicyKey), revision, actors[0].Principal, actors[0].Kind, Organization,
                root.ScopeProfile == ValidationPermissionScope.Project ? Id(ValidationPermissionPlan.Project) : "", "secret-validation-rules", [baseline], [], plan.Slug, "bootstrap-policy");
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
        lock (gate) CommitCreation(ValidationPermissionPlan.Deferred, admitted: true);
    }
    private void Grants(string project)
    {
        CommitCreation("write-grant-" + project); CommitCreation("write-membership-" + project);
        writeGrants.Add(new(Id("write-grant-" + project), "write-1", actors[3].Principal, Organization, Id(project), Id("write-membership-" + project), ["create", "edit"]));
    }
    private void Bootstrap(ValidationPermissionRow row)
    {
        if (row.Action != ValidationPermissionAction.Create) { CommitCreation(row.Target); states.Add(row.Key, plan!.Initial(row, Issued)); }
        foreach (var probe in new[] { false, true }.SelectMany(after => ValidationPermissionPlan.Probes(row, after)).Where(p => p.Update))
        {
            var seeded = backend.Seed(probe, Id(row.Project)); CommitCreation(probe.Key, nativeId: seeded.Id);
        }
    }
    internal ValidationPermissionPacket Step(ValidationPermissionRoot selected, ValidationPermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == ValidationPermissionStep.Reserve)
            {
                ValidationPermissionContract.Require(root is null && capability == "validation-capability" && selected.Origin == Origin.AbsoluteUri &&
                    selected.Organization == Organization && selected.Authorities == Authorities && ValidationPermissionContract.Hash(Profile) == ValidationPermissionContract.Hash(selected.Profile));
                root = selected; plan = new(selected);
                if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
            }
            ValidationPermissionContract.Require(root is not null && ValidationPermissionContract.Hash(root) == ValidationPermissionContract.Hash(selected) && !closed &&
                (step == ValidationPermissionStep.Close || stage == (int)step));
            if (step != ValidationPermissionStep.Close) stage++;
            switch (step)
            {
                case ValidationPermissionStep.Open: Open(); break;
                case ValidationPermissionStep.Before: Clear(); window = "before"; break;
                case ValidationPermissionStep.Arm: Clear(); window = ""; armed = true; break;
                case ValidationPermissionStep.Settle: settled = true; break;
                case ValidationPermissionStep.After:
                    ingress.RemoveAll(e => e.Phase != "activation"); commits.RemoveAll(c => !ingress.Any(e => e.Request == c.Request));
                    decisions.Clear(); writeDecisions.Clear(); changes.Clear(); window = "after"; break;
                case ValidationPermissionStep.ObserveBefore:
                case ValidationPermissionStep.ObserveAfter: window = ""; break;
                case ValidationPermissionStep.Close:
                    Closes++;
                    ValidationPermissionContract.Require(closing && (delayed is null || delayed.IsCompletedSuccessfully));
                    // Reconcile native IDs from original-root issuance AND storage, not the Open reply.
                    ValidationPermissionContract.Require(issuanceBindings.SequenceEqual(storageBindings));
                    foreach (var binding in storageBindings)
                        ValidationPermissionContract.Require(binding.IntentHash == ValidationPermissionContract.Hash(plan!.Intents.Single(i => i.Key == binding.Intent)) &&
                            !borrowed.Any(b => b.Id == binding.CanonicalId));
                    foreach (var binding in storageBindings)
                    {
                        var native = resources.SingleOrDefault(r => r.Value.CanonicalId == binding.CanonicalId);
                        if (native.Key is null) continue; // A witnessed downstream delete may already have removed it.
                        ValidationPermissionContract.Require(native.Value.Intent == binding.Intent);
                        resources.Remove(native.Key);
                    }
                    states.Clear(); credentials.Clear(); tokens.Clear(); policy = copiedPolicy = null; writeGrants.Clear(); copiedEnvironments = []; backend.Clear();
                    foreach (var bytes in privateBuffers) CryptographicOperations.ZeroMemory(bytes);
                    ownedKey?.Dispose(); ownedKey = null; closed = settled = true; armed = false; window = "";
                    if (Fault == "cleanup") resources.Add("residual", new("canary", Id("canary")));
                    if (Fault == "borrowed-change") borrowedObjects[borrowedObjects.Keys.First()] = "modified";
                    break;
            }
            var packet = Packet(step);
            if (step == ValidationPermissionStep.Close) ClosedPacket = packet;
            return packet;
        }
    }
    private void Clear() { ingress.Clear(); commits.Clear(); decisions.Clear(); writeDecisions.Clear(); changes.Clear(); }
    private ValidationPermissionSigned<T> Sign<T>(ValidationPermissionStep step, ValidationPermissionJournal journal, T content) => writers[journal].Sign(root!, step, content);
    private ValidationPermissionJoin[] Joins()
    {
        if (closed) return [];
        var joins = actors.Take(3).Select((actor, i) => new ValidationPermissionJoin(actor.Principal,
            actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization,
            root!.ScopeProfile == ValidationPermissionScope.Project ? Id(ValidationPermissionPlan.Project) : "", Id(plan!.ActorMembership(i)),
            i == 0 && (!ValidationPermissionContract.Create(root.Operation) || assigned && !copied), i == 0 && (!ValidationPermissionContract.Create(root.Operation) || assigned && !copied) ? Id(plan.PolicyKey) : "",
            i == 0 && (!ValidationPermissionContract.Create(root.Operation) || assigned && !copied) ? Fault == "wrong-role-binding" ? "foreign-role" : plan.Slug : "no-access", true, "accepted")).ToList();
        if (copied) joins.Add(new(actors[0].Principal, "user", Organization, Id(ValidationPermissionPlan.CopyProject), Id(plan!.ActorMembership(0, true)),
            true, Id(ValidationPermissionPlan.CopiedRole), Fault == "wrong-role-binding" ? "foreign-role" : plan.Slug, true, "accepted"));
        joins.AddRange(writeGrants.Select(g => new ValidationPermissionJoin(actors[3].Principal, "machine", Organization, g.Project, g.Membership, true, g.Resource, "static-writer", true, "accepted")));
        return joins.ToArray();
    }
    private ValidationPermissionPacket Packet(ValidationPermissionStep step)
    {
        bool open = step == ValidationPermissionStep.Open, observe = step is ValidationPermissionStep.ObserveBefore or ValidationPermissionStep.ObserveAfter;
        var issue = issuanceBindings.ToArray(); var storage = storageBindings.ToArray();
        if (open && issue.Length > 1)
        {
            switch (Fault)
            {
                case "binding-substitution": storage[0] = storage[0] with { CanonicalId = Guid.NewGuid().ToString() }; break;
                case "binding-duplicate": issue[1] = issue[1] with { CanonicalId = issue[0].CanonicalId }; storage = issue.ToArray(); break;
                case "binding-work": issue[0] = issue[0] with { Work = "foreign-work" }; storage = issue.ToArray(); break;
                case "binding-input": issue[0] = issue[0] with { InputHash = "foreign-input" }; storage = issue.ToArray(); break;
                case "input-constraint":
                    int selected = Array.FindIndex(issue, b => b.Kind == "validation-rule");
                    issue[selected] = issue[selected] with { InputHash = ValidationPermissionContract.Hash(new { RequiredPrefix = "OTHER_" }) }; storage = issue.ToArray(); break;
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
        var allPolicies = new[] { policy, copiedPolicy }.OfType<ValidationPermissionPolicy>().OrderBy(p => p.Resource).ToArray();
        var committed = observe || step == ValidationPermissionStep.Settle ? commits.ToArray() : [];
        if (step == ValidationPermissionStep.Settle && Fault == "wrong-policy-target" && committed.Length == 1)
        { committed[0] = committed[0] with { Policy = committed[0].Policy with { Resource = Guid.NewGuid().ToString() } }; allPolicies = [committed[0].Policy]; }
        var intents = plan!.Intents.ToArray();
        if (open && Fault == "intent-mutation") intents[0] = intents[0] with { Input = "changed" };
        var packet = new ValidationPermissionPacket(
            Sign(step, ValidationPermissionJournal.Ownership, new ValidationPermissionOwner(intents, resources.Values.ToArray(), Borrowed(), true, true,
                settled || closed, settled || closed, open && Fault == "pending-issuer" ? 1 : 0, closed ? 0 : 1, open ? actors : [], settled || closed, settled || closed)),
            Sign(step, ValidationPermissionJournal.Ingress, new ValidationPermissionIngresses(observe || step == ValidationPermissionStep.Settle ? ingress.ToArray() : [], ingressHistory.ToArray())),
            Sign(step, ValidationPermissionJournal.Policy, new ValidationPermissionPolicies(allPolicies, committed, writeGrants.ToArray(), commitHistory.ToArray())),
            Sign(step, ValidationPermissionJournal.Storage, new ValidationPermissionStorage(storage, inventory, observe ? changes.ToArray() : [], copiedEnvironments, changeHistory.ToArray())),
            Sign(step, ValidationPermissionJournal.Issuer, new ValidationPermissionIssuance(issue, credentialRows, credentialHistory.ToArray())),
            Sign(step, ValidationPermissionJournal.Membership, joins), Sign(step, ValidationPermissionJournal.Access, new ValidationPermissionAccesses(observe ? decisions.ToArray() : [], observe ? writeDecisions.ToArray() : [], accessHistory.ToArray(), authorizationHistory.ToArray())),
            enforcer.Publish(root!, step), backend.Publish(root!, step), []);
        var seals = new List<ValidationPermissionSigned<MemberPermissionSeal>>();
        Add(ValidationPermissionJournal.Ownership, packet.Owner.Payload); Add(ValidationPermissionJournal.Ingress, packet.Ingress.Payload);
        Add(ValidationPermissionJournal.Policy, packet.Policy.Payload); Add(ValidationPermissionJournal.Storage, packet.Storage.Payload);
        Add(ValidationPermissionJournal.Issuer, packet.Issuer.Payload); Add(ValidationPermissionJournal.Membership, packet.Membership.Payload); Add(ValidationPermissionJournal.Access, packet.Access.Payload);
        seals.Add(enforcer.Seal(root!, step, packet.Enforcement.Payload)); seals.Add(backend.Seal(root!, step, packet.Backend.Payload));
        return packet with { Seals = open && Fault == "missing-seal" ? seals.Skip(1).ToArray() : seals.ToArray() };
        void Add<T>(ValidationPermissionJournal journal, T payload) => seals.Add(Sign(step, journal,
            new MemberPermissionSeal(ValidationPermissionContract.Hash(payload), !(open && Fault == "nonterminal"), 0, 1)));
    }
    private async Task AcceptAsync()
    {
        try
        {
            while (!shutdown.IsCancellationRequested)
            {
                var socket = await listener.AcceptTcpClientAsync(shutdown.Token);
                connections.Add(ServeAsync(socket));
                TransportAccepted.TrySetResult();
            }
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
    }
    private async Task ServeAsync(TcpClient socket)
    {
        using (socket)
        {
            var stream = socket.GetStream();
            while (!ingressStop.IsCancellationRequested)
            {
                byte[] header = new byte[32768], body = [], response = [];
                Copies.Add(header);
                try
                {
                    int count = 0;
                    while (count < header.Length)
                    {
                        if (await stream.ReadAsync(header.AsMemory(count, 1), ingressStop.Token) == 0) return;
                        count++;
                        if (count >= 4 && header.AsSpan(count - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
                    }
                    string[] lines = Encoding.ASCII.GetString(header, 0, count).Split("\r\n");
                    string[] request = lines[0].Split(' ');
                    int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?
                        .Split(':')[1].Trim() ?? "0");
                    ValidationPermissionContract.Require(length is >= 0 and <= 131072);
                    body = new byte[length]; Copies.Add(body); await stream.ReadExactlyAsync(body, ingressStop.Token);
                    string bearer = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?.Split(' ').Last() ?? "";
                    using var document = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                    bool admitted;
                    lock (gate) admitted = !closing && !closed;
                    if (admitted && Fault == "delayed-dispatch" && request[0] == "POST" && request[1].StartsWith("/api/v4/secrets/", StringComparison.Ordinal))
                    {
                        PipelineEntered.TrySetResult();
                        await PipelineRelease.Task.WaitAsync(shutdown.Token);
                    }
                    (int Status, object Body) result;
                    lock (gate) result = Handle(request[0], new Uri(Origin, request[1]), bearer, document.RootElement, body, admitted);
                    response = JsonSerializer.SerializeToUtf8Bytes(result.Body); Copies.Add(response);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\n\r\n"), shutdown.Token);
                    await stream.WriteAsync(response, shutdown.Token);
                }
                catch (IOException) { return; }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested || ingressStop.IsCancellationRequested) { return; }
                finally
                {
                    CryptographicOperations.ZeroMemory(header); CryptographicOperations.ZeroMemory(body); CryptographicOperations.ZeroMemory(response);
                }
            }
        }
    }
    private ValidationPermissionCredential Authenticate(string bearer)
    {
        if (tokens.TryGetValue(bearer, out var credential)) return credential;
        string principal = hostTokens.SingleOrDefault(p => p.Value == bearer).Key ?? "unknown";
        byte[] bytes = Encoding.UTF8.GetBytes(bearer);
        try { return new("host-" + principal, principal, MemberPermissionActorKind.Machine, Organization, ValidationPermissionContract.RawHash(bytes), false); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private void Record(string request, ValidationPermissionCredential actor, string method, string path, byte[] bytes, string intent, bool allowed, string phase) =>
        RecordIngress(new(request, actor.Principal, actor.Kind, actor.Hash, actor.Organization, method, path, ValidationPermissionContract.RawHash(bytes), intent, allowed, phase));
    private void RecordIngress(ValidationPermissionIngress value) { ingress.Add(value); ingressHistory.Add(value); }
    private void CommitPolicy(ValidationPermissionCommit value) { commits.Add(value); commitHistory.Add(value); }
    private (int, object) Handle(string method, Uri uri, string bearer, JsonElement body, byte[] bytes, bool admitted)
    {
        if (root is null || actors.Length == 0 || closed || closing && !admitted) return (403, new { });
        var actor = Authenticate(bearer); string path = uri.AbsolutePath;
        bool template = root.Operation.Contains("ProjectTemplate", StringComparison.Ordinal), organization = root.Operation.EndsWith("OrganizationRole", StringComparison.Ordinal),
            privilege = root.Operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal), create = root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        string originalPath = (template ? "/api/v1/project-templates" : organization ? "/api/v1/organization/roles" : privilege ?
            "/api/v2/identity-project-additional-privilege" : "/api/v1/projects/" + Id(ValidationPermissionPlan.Project) + "/roles") + (create ? "" : "/" + Id(plan!.PolicyKey));
        if (path == originalPath && method == (create ? "POST" : "PATCH") &&
            (template || privilege || body.TryGetProperty("slug", out var policySlug) && policySlug.GetString() == plan!.Slug))
        {
            if (!armed || settled || Originals != 0) return (409, new { });
            Originals++; string request = Guid.NewGuid().ToString("N"), intent = ValidationPermissionContract.RawHash(bytes);
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
                policy = new(Id(plan!.PolicyKey), revision, principal, actors[0].Kind, Organization, organization ? "" : Id(ValidationPermissionPlan.Project),
                    permission.GetProperty("subject").GetString()!, Fault == "partial" ? [] : selected, Fault == "wrong-condition" ? ["forged-condition"] : names, Fault == "incomplete-policy" ? "" : role, Fault == "wrong-configuration" ? "foreign-configuration" : ValidationPermissionContract.RawHash(bytes));
                if (template) templateConfiguration = body.Clone();
                CommitPolicy(new(request, old, policy)); if (privilege) assigned = true;
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
            else { result["name"] = plan.Slug; result[organization ? "orgId" : "projectId"] = organization ? Organization : Id(ValidationPermissionPlan.Project); }
            return (200, new JsonObject { [template ? "projectTemplate" : privilege ? "privilege" : "role"] = result });
        }
        if (settled && actor.Principal == Authorities.Setup && actor.Kind == MemberPermissionActorKind.Machine && policy is not null &&
            (path == "/api/v1/projects" || path.EndsWith("/" + Id(plan!.ActorMembership(0)), StringComparison.Ordinal)))
            return Activate(actor, method, path, body, bytes);
        if (actor.Principal == Authorities.Observer && method == "GET" && path.StartsWith("/api/v1/projects/", StringComparison.Ordinal))
        {
            var c = copiedEnvironments.SingleOrDefault(e => path.Contains(e.Project, StringComparison.Ordinal));
            if (c is null) return (404, new { });
            if (path.EndsWith("/environments/slug/" + c.Slug, StringComparison.Ordinal)) return (200, new
            {
                environment = new
                {
                    id = c.Id,
                    projectId = c.Project,
                    name = c.Name,
                    slug = c.Slug,
                    position = c.Position,
                    createdAt = "2026-01-01T00:00:00Z",
                    updatedAt = "2026-01-01T00:00:00Z",
                    softDeletedAt = (string?)null,
                    deleteAfter = (string?)null,
                    deletedByUserId = (string?)null,
                    deletedByIdentityId = (string?)null
                }
            });
            return (200, new
            {
                project = new
                {
                    id = c.Project,
                    _id = c.Project,
                    orgId = Organization,
                    name = plan!.CopySlug,
                    slug = plan.CopySlug,
                    type = "secret-manager",
                    createdAt = "2026-01-01T00:00:00Z",
                    updatedAt = "2026-01-01T00:00:00Z",
                    environments = new[] { new { id = c.Id, name = c.Name, slug = c.Slug } },
                    deletedEnvironments = Array.Empty<object>()
                }
            });
        }
        if (path.StartsWith("/api/v4/secrets/", StringComparison.Ordinal)) return SecretAction(actor, method, uri, body, bytes);
        return TargetAction(actor, method, uri, body, bytes);
    }
    private (int, object) Activate(ValidationPermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        string request = Guid.NewGuid().ToString("N");
        if (path == "/api/v1/projects")
        {
            if (copied || method != "POST" || body.GetProperty("template").GetString() != plan!.Slug || body.GetProperty("slug").GetString() != plan.CopySlug) return (403, new { });
            CommitCreation(ValidationPermissionPlan.CopyProject, request); CommitCreation(ValidationPermissionPlan.CopiedRole); CommitCreation(plan.ActorMembership(0, true));
            copied = true; assigned = true;
            foreach (var row in plan.Rows.Where(r => r.Window == "copy")) Bootstrap(row);
            Grants(ValidationPermissionPlan.CopyProject);
            var environment = templateConfiguration.GetProperty("environments")[0]; CommitCreation("template-environment");
            copiedEnvironments = [new(Id(ValidationPermissionPlan.CopyProject), Id("template-environment"), environment.GetProperty("name").GetString()!,
                environment.GetProperty("slug").GetString()!, Fault == "template-environment-echo" ? 9.5 : environment.GetProperty("position").GetDouble(), Id(plan.PolicyKey), policy!.Configuration)];
            copiedPolicy = policy! with
            {
                Resource = Id(ValidationPermissionPlan.CopiedRole),
                Project = Id(ValidationPermissionPlan.CopyProject),
                Actions = Fault == "template-echo" ? [] : policy.Actions,
                Configuration = Fault == "template-configuration-echo" ? "foreign-configuration" : policy.Configuration
            };
            Record(request, actor, method, path, bytes, ValidationPermissionContract.RawHash(bytes), true, "activation");
            CommitPolicy(new(request, revision, copiedPolicy));
            return (200, new
            {
                project = new
                {
                    id = Id(ValidationPermissionPlan.CopyProject),
                    _id = Id(ValidationPermissionPlan.CopyProject),
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
        if (!org && assigned) CommitCreation(ValidationPermissionPlan.Assignment, request);
        Record(request, actor, method, path, bytes, org ? ValidationPermissionContract.RawHash(bytes) : WireHash(new object?[] { null, body }), true, "activation");
        CommitPolicy(new(request, revision, policy!));
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
    private (int, object) TargetAction(ValidationPermissionCredential actor, string method, Uri uri, JsonElement body, byte[] bytes)
    {
        string path = uri.AbsolutePath; const string collection = "/api/v1/secret-validation-rules/static-secrets";
        if (!path.StartsWith(collection, StringComparison.Ordinal)) return (404, new { });
        if (actor.Principal == Authorities.Observer && method == "GET")
        {
            if (path == collection)
            {
                string project = Query(uri, "projectId");
                return (200, new { secretValidationRules = states.Values.Where(s => s.Project == project).Select(TargetRow).ToArray() });
            }
            var state = states.Values.SingleOrDefault(s => s.Target == path.Split('/').Last());
            return state is null ? (404, new { }) : (200, new { secretValidationRule = TargetRow(state) });
        }
        if (window is not ("before" or "after")) return (403, new { });
        var action = method switch
        {
            "GET" => ValidationPermissionAction.Read,
            "POST" => ValidationPermissionAction.Create,
            "PATCH" => ValidationPermissionAction.Edit,
            "DELETE" => ValidationPermissionAction.Delete,
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        var row = action == ValidationPermissionAction.Create ? plan!.Rows.SingleOrDefault(r => r.Name == body.GetProperty("name").GetString() && Id(r.Project) == body.GetProperty("projectId").GetString()) :
            plan!.Rows.SingleOrDefault(r => Id(r.Target) == path.Split('/').Last());
        if (row is null) return (404, new { });
        string projectId = Id(row.Project), org = Id(row.Organization);
        var effective = projectId == Id(ValidationPermissionPlan.CopyProject) && copied ? copiedPolicy : policy;
        bool allowed = assigned && effective is not null && effective.Subject == "secret-validation-rules" && effective.Actor == actor.Principal && effective.Kind == actor.Kind &&
            actor.Organization == org && effective.Organization == org && effective.Project == projectId && effective.Actions.Contains(ValidationPermissionContract.Wire(action)) && effective.Names.Length == 0 &&
            Joins().Any(j => j.Principal == actor.Principal && j.Kind == (actor.Kind == MemberPermissionActorKind.User ? "user" : "machine") && j.Project == projectId && j.Assigned &&
                j.RoleId == effective.Resource && j.RoleSlug == effective.Role && j.Active && j.Status == "accepted");
        if (Fault == "action-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && projectId == (copied ? Id(ValidationPermissionPlan.CopyProject) : Id(ValidationPermissionPlan.Project))) allowed = true;
        if (Fault == "scope-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && policy?.Actions.Contains(ValidationPermissionContract.Wire(action)) == true) allowed = true;
        string request = Guid.NewGuid().ToString("N"); var recorded = Fault == "wrong-actor" ? actor with { Principal = Authorities.Observer } : actor;
        if (Fault == "wrong-credential") recorded = recorded with { Hash = "wrong" };
        Record(request, recorded, method, path, bytes, "", allowed, "action"); var previous = states.GetValueOrDefault(row.Key); object response = new { };
        if (allowed)
        {
            switch (action)
            {
                case ValidationPermissionAction.Create:
                    CommitCreation(row.Target, request); states.Add(row.Key, Persist(row, body, 1)); response = new { secretValidationRule = TargetRow(states[row.Key]) }; break;
                case ValidationPermissionAction.Edit:
                    states[row.Key] = Persist(row, body, 2); response = new { secretValidationRule = TargetRow(states[row.Key]) }; break;
                case ValidationPermissionAction.Delete:
                    response = new { secretValidationRule = TargetRow(previous!) }; states.Remove(row.Key); resources.Remove(row.Target); break;
                default: response = new { secretValidationRule = TargetRow(previous!) }; break;
            }
            if (states.TryGetValue(row.Key, out var wrong)) states[row.Key] = Fault switch
            {
                "wrong-rule" => wrong with { Target = Guid.NewGuid().ToString() },
                "wrong-name" => wrong with { Name = "foreign-name" },
                "wrong-description" => wrong with { Description = "foreign-description" },
                "wrong-path" => wrong with { Path = "/foreign" },
                "wrong-active" => wrong with { Active = !wrong.Active },
                "wrong-constraint" => wrong with { Value = wrong.Value! with { RequiredPrefix = "OTHER_" } },
                "stale-rule-scope" => wrong with { Project = Id(ValidationPermissionPlan.OtherProject) },
                _ => wrong
            };
            if (Fault == "self-policy-overwrite" && policy is not null) policy = policy with { Actions = ["delete"] };
        }
        decisions.Add(new(request, recorded.Principal, recorded.Kind, recorded.Id, recorded.Hash, Fault == "wrong-organization" ? Id(ValidationPermissionPlan.OtherOrganization) : org,
            Fault == "wrong-project" ? Id(ValidationPermissionPlan.OtherProject) : projectId, Id(row.Target), revision, action, allowed));
        accessHistory.Add(decisions[^1]);
        changes.Add(new(request, row.Key, previous, states.GetValueOrDefault(row.Key))); changeHistory.Add(changes[^1]);
        return (allowed ? 200 : 403, response);
    }
    private ValidationPermissionState Persist(ValidationPermissionRow row, JsonElement body, int version) => new(row.Key, Id(row.Target), Id(row.Organization), Id(row.Project),
        body.GetProperty("name").GetString()!, body.GetProperty("description").GetString(), body.GetProperty("environment").GetString(), body.GetProperty("secretPath").GetString()!,
        body.GetProperty("isActive").GetBoolean(), version, Constraints(body.GetProperty("keyConstraints")), Constraints(body.GetProperty("valueConstraints")));
    private static ValidationPermissionConstraints Constraints(JsonElement e) => new(e.GetProperty("minLength").GetInt32(), e.GetProperty("maxLength").GetInt32(),
        e.GetProperty("regexPattern").GetString(), e.GetProperty("requiredPrefix").GetString(), e.GetProperty("requiredSuffix").GetString(), null, null);
    private static object TargetRow(ValidationPermissionState s) => new
    {
        id = s.Target,
        projectId = s.Project,
        type = "static-secrets",
        name = s.Name,
        description = s.Description,
        environment = new { id = "10000000-0000-0000-0000-000000000099", name = "Development", slug = s.Environment },
        secretPath = s.Path,
        isActive = s.Active,
        keyConstraints = ConstraintWire(s.Key!),
        valueConstraints = ConstraintWire(s.Value!),
        createdAt = "2026-01-01T00:00:00Z",
        updatedAt = "2026-01-01T00:00:01Z"
    };
    private static object ConstraintWire(ValidationPermissionConstraints c) => new
    {
        minLength = c.MinimumLength,
        maxLength = c.MaximumLength,
        regexPattern = c.RegexPattern,
        requiredPrefix = c.RequiredPrefix,
        requiredSuffix = c.RequiredSuffix,
        uniqueAcrossLastVersions = c.UniqueAcrossLastVersions,
        uniqueWithinScope = c.UniqueWithinScope
    };
    private static string Query(Uri uri, string key) => uri.Query.TrimStart('?').Split('&').Select(s => s.Split('=', 2)).Where(p => p.Length == 2 && p[0] == key).Select(p => Uri.UnescapeDataString(p[1])).SingleOrDefault() ?? "";
    private (int, object) SecretAction(ValidationPermissionCredential actor, string method, Uri uri, JsonElement body, byte[] bytes)
    {
        string name = Uri.UnescapeDataString(uri.AbsolutePath.Split('/').Last());
        if (method == "GET")
        {
            if (actor.Principal != Authorities.Observer) return (403, new { });
            var found = backend.Read(Query(uri, "projectId"), Query(uri, "environment"), Query(uri, "secretPath"), name);
            return found is null ? (404, new { }) : (200, new { secret = found });
        }
        if (window is not ("before" or "after")) return (403, new { });
        string project = body.GetProperty("projectId").GetString()!, environment = body.GetProperty("environment").GetString()!, path = body.GetProperty("secretPath").GetString()!;
        var probe = plan!.Rows.Where(r => Id(r.Project) == project).SelectMany(r => new[] { false, true }.SelectMany(a => ValidationPermissionPlan.Probes(r, a)))
            .Single(p => p.Name == name && p.Path == path && p.Environment == environment);
        var grant = writeGrants.SingleOrDefault(g => g.Project == project && g.Principal == actor.Principal && g.Organization == actor.Organization &&
            g.Actions.Contains(method == "POST" ? "create" : "edit") && Joins().Any(j => j.Principal == actor.Principal && j.Kind == "machine" && j.Membership == g.Membership && j.Assigned && j.Active));
        bool allowed = grant is not null && actor.Kind == MemberPermissionActorKind.Machine;
        string request = Guid.NewGuid().ToString("N"), hash = ValidationPermissionContract.RawHash(bytes);
        var authorization = new ValidationPermissionAuthorization(request, actor.Principal, actor.Kind, actor.Id, actor.Hash, actor.Organization, project, environment, path, name, method, hash,
            grant?.Resource ?? "", grant?.Revision ?? "", allowed);
        if (Fault == "enforcement-actor") authorization = authorization with { Actor = Authorities.Observer };
        if (Fault == "enforcement-credential") authorization = authorization with { CredentialHash = "foreign" };
        if (Fault == "enforcement-authority") authorization = authorization with { Grant = "foreign" };
        Record(request, actor, method, uri.AbsolutePath, bytes, "", allowed, "write"); writeDecisions.Add(authorization); authorizationHistory.Add(authorization);
        var decision = enforcer.Decide(authorization, bytes); var change = backend.Apply(authorization, decision, probe, bytes);
        if (change.After is not null && Id(probe.Key).Length == 0) CommitCreation(probe.Key, request, admitted: closing, nativeId: change.After.Id, commitId: change.Commit);
        bool accepted = allowed && decision.Decision == ValidationPermissionConstraintDecision.Allowed;
        return (!allowed ? 403 : accepted ? 200 : 400, accepted ? new { secret = new { secretKey = name, workspace = project, environment, version = change.After?.Version ?? 1 } } : new object());
    }
    private object Role(string membership, string role) => new
    {
        id = Id(ValidationPermissionPlan.Assignment),
        projectMembershipId = membership,
        role,
        isTemporary = false,
        createdAt = "2026-01-01T00:00:00Z",
        updatedAt = "2026-01-01T00:00:01Z"
    };
    private static string WireHash(object value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        try { return ValidationPermissionContract.RawHash(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal async Task SealAndDrainAsync()
    {
        lock (gate) { closing = true; settled = true; armed = false; CloseEntered.TrySetResult(); }
        // Partial transports have not entered provider dispatch. Cancel those reads;
        // already admitted operations retain shutdown.Token and must finish.
        ingressStop.Cancel();
        if (delayed is not null) await delayed;
        await Task.WhenAll(connections);
        lock (gate) { enforcer.Fence(); backend.Fence(); }
    }
    internal Task DrainAsync() => Task.WhenAll(connections);
    public async ValueTask DisposeAsync()
    {
        OpenRelease.TrySetResult(); IssuerRelease.TrySetResult(); PipelineRelease.TrySetResult();
        if (delayed is not null) await delayed;
        ingressStop.Cancel(); shutdown.Cancel(); listener.Stop();
        try { await accept; } catch (SocketException) when (shutdown.IsCancellationRequested) { }
        await Task.WhenAll(connections);
        foreach (var bytes in privateBuffers) CryptographicOperations.ZeroMemory(bytes);
        ownedKey?.Dispose(); enforcer.Dispose(); backend.Dispose(); Source.Dispose(); foreach (var writer in writers.Values) writer.Dispose(); ingressStop.Dispose(); shutdown.Dispose();
        // Test runners may retain completed async state machines. Erasure and
        // releasing owned captures are separate obligations; keep neither the
        // full response history nor its cleared backing arrays after disposal.
        Copies.Clear(); privateBuffers.Clear(); connections.Clear();
        ingress.Clear(); ingressHistory.Clear(); commits.Clear(); commitHistory.Clear(); decisions.Clear(); accessHistory.Clear();
        writeDecisions.Clear(); authorizationHistory.Clear(); changes.Clear(); changeHistory.Clear(); credentials.Clear(); credentialHistory.Clear();
        issuanceBindings.Clear(); storageBindings.Clear(); resources.Clear(); states.Clear(); tokens.Clear(); writeGrants.Clear();
        actors = []; root = null; plan = null; ClosedPacket = null; copiedEnvironments = []; policy = copiedPolicy = null;
    }
}
