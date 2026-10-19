using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled provider: authentication uses bearer material, authorization reads
// persisted policy and assignments. No result is decided from row.Control.
// Native IDs are generated ONLY in CommitCreation, inside the commit lock.
internal sealed class InfisicalIdentityPermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static MemberPermissionAuthorities Authorities => InfisicalMemberPermissionFixture.Authorities;
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<IdentityPermissionJournal, InfisicalIdentityPermissionWriter> writers = [];
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
    private readonly Dictionary<string, IdentityPermissionCredential> tokens = [];
    private readonly List<IdentityPermissionCredential> credentials = [];
    private readonly List<IdentityPermissionBinding> issuanceBindings = [], storageBindings = [];
    private readonly Dictionary<string, IdentityPermissionResource> resources = [];
    private readonly Dictionary<string, IdentityPermissionState> states = [];
    private readonly List<IdentityPermissionIngress> ingress = [];
    private readonly List<IdentityPermissionCommit> commits = [];
    private readonly List<IdentityPermissionAccess> decisions = [];
    private readonly List<IdentityPermissionChange> changes = [];
    private readonly List<byte[]> privateBuffers = [];
    private readonly List<IdentityPermissionTokenIssue> tokenIssues = [];
    private readonly Dictionary<string, IdentityPermissionReadPolicy> targetReads = [];
    private readonly Dictionary<string, IdentityPermissionToken> tokenStates = [];
    private readonly Dictionary<string, byte[]> tokenMaterial = [];
    private readonly List<IdentityPermissionCapture> captures = [];
    private readonly List<IdentityPermissionAuthenticationEvent> authentication = [];
    private readonly Dictionary<string, int> probeCounts = [];
    private Task? deferredCapture;
    internal TaskCompletionSource CaptureEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource CaptureRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly MemberPermissionBorrowed[] borrowed;
    private IdentityPermissionRoot? root;
    private IdentityPermissionPlan? plan;
    private IdentityPermissionActor[] actors = [];
    private IdentityPermissionPolicy? policy, copiedPolicy;
    private ECDsa? ownedKey;
    private string revision = "policy-1", window = "";
    private int stage;
    private bool closed, closing, armed, settled, assigned, copied;
    private Task? delayed;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal IdentityPermissionProfile Profile { get; }
    internal InfisicalIdentityPermissionFixtureSource Source { get; }
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
    internal int Remaining => resources.Count + states.Count + tokens.Count + targetReads.Count + (policy is null ? 0 : 1) + (copiedPolicy is null ? 0 : 1) + (ownedKey is null ? 0 : 1);
    internal bool BorrowedPreserved => Borrowed().SequenceEqual(borrowed);
    internal InfisicalIdentityPermissionFixture(string fault = "")
    {
        Fault = fault;
        foreach (var journal in Enum.GetValues<IdentityPermissionJournal>()) writers.Add(journal, new(journal));
        Profile = new("controlled-identities", "controlled-epoch", "controlled-v1", writers.Values.Select(w => w.Pin).ToArray());
        borrowed = Borrowed(); listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/"); Source = new(this); accept = AcceptAsync();
    }
    internal IdentityPermissionInput Input(string operation, IdentityPermissionAction action) =>
        new(new(new("https://identity-source.invalid/"), "coordinator-token", "identity-coordinator", 30), "identity-capability", Profile,
            IdentityPermissionContract.Scope(operation), IdentityPermissionContract.ActorKind(operation), action, 30);
    internal NativeEnvironment Environment(string operation, IdentityPermissionAction action, bool configured = true)
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
                    identityPermission = Input(operation, action)
                }
            }
        }, IdentityPermissionContract.Options)!;
        if (!configured) scope["scopes"]!["local"]!.AsObject().Remove("identityPermission");
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
        }, IdentityPermissionContract.Options));
    }
    internal IdentityPermissionRoot Root(string operation, IdentityPermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization, operation,
            IdentityPermissionContract.Variant(action), boundary, "local", "identity-coordinator", MemberPermissionSourceKind.ControlledFixture,
            IdentityPermissionContract.Scope(operation), IdentityPermissionContract.ActorKind(operation), action, Authorities, Profile);
    private MemberPermissionBorrowed[] Borrowed() => hostTokens.Select(p => new MemberPermissionBorrowed("host-credential", p.Key, IdentityPermissionContract.Hash(p.Value)))
        .Concat(writers.Values.Select(w => new MemberPermissionBorrowed("host-key", w.Pin.Writer, IdentityPermissionContract.Hash(w.Pin.Spki))))
        .Concat(borrowedObjects.Select(p => new MemberPermissionBorrowed(p.Value, p.Key, IdentityPermissionContract.Hash(p.Value)))).ToArray();
    private IdentityPermissionIssued Issued => new(actors, storageBindings.ToArray(), tokenIssues.Where(t => plan!.Rows.Single(r => r.Key == t.Row).Action != IdentityPermissionAction.CreateToken)
        .Select(t => new IdentityPermissionTarget(t.Row, t.Token, tokenMaterial[t.Token])).ToArray());
    private string Id(string key) => Issued.Id(key);
    private string CommitCreation(string key, string? request = null, bool admitted = false)
    {
        IdentityPermissionContract.Require(root is not null && plan is not null && !closed && (!closing || admitted) && !resources.ContainsKey(key) &&
            !storageBindings.Any(b => b.Intent == key));
        var intent = plan!.Intents.Single(i => i.Key == key);
        IdentityPermissionContract.Require(Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0));
        // There is deliberately no ID-generation path in Reserve or plan construction.
        string canonical = Guid.NewGuid().ToString();
        var binding = new IdentityPermissionBinding(key, IdentityPermissionContract.Hash(intent), intent.Work, intent.Kind, Id(intent.Scope),
            IdentityPermissionPlan.InputHash(intent, Id), canonical, request ?? Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"));
        issuanceBindings.Add(binding); storageBindings.Add(binding); resources.Add(key, new(key, canonical));
        return canonical;
    }
    private IdentityPermissionActor IssueActor(int i)
    {
        string key = plan!.ActorKey(i), scope = Id(plan.ActorScope(i)); var kind = plan.ActorKind(i);
        bool owned = !key.StartsWith("@", StringComparison.Ordinal);
        if (owned && Id(key).Length == 0) CommitCreation(key);
        string principal = Id(key); IdentityPermissionCredential credential; byte[] bytes;
        if (owned)
        {
            (credential, bytes) = IssueCredential("actor-credential-" + i, principal, kind, scope);
        }
        else
        {
            bytes = Encoding.UTF8.GetBytes(hostTokens[principal]);
            credential = new("host-" + principal, principal, kind, scope, IdentityPermissionContract.RawHash(bytes), false);
            CryptographicOperations.ZeroMemory(bytes); bytes = [];
            if (!credentials.Any(c => c.Id == credential.Id)) credentials.Add(credential);
        }
        CommitCreation(plan.ActorMembership(i));
        return new(principal, kind, scope, credential.Id, credential.Hash, bytes, owned);
    }
    private (IdentityPermissionCredential Credential, byte[] Bytes) IssueCredential(string key, string principal, MemberPermissionActorKind kind, string scope)
    {
        string id = CommitCreation(key);
        byte[] random = RandomNumberGenerator.GetBytes(32), bytes;
        try { bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(random)); } finally { CryptographicOperations.ZeroMemory(random); }
        privateBuffers.Add(bytes); Copies.Add(bytes);
        var credential = new IdentityPermissionCredential(id, principal, kind, scope, IdentityPermissionContract.RawHash(bytes), true);
        credentials.Add(credential); tokens.Add(Encoding.ASCII.GetString(bytes), credential); return (credential, bytes);
    }
    private void Open()
    {
        Opens++; CommitCreation(IdentityPermissionPlan.OtherOrganization);
        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
        CommitCreation(IdentityPermissionPlan.Project); CommitCreation(IdentityPermissionPlan.OtherProject); CommitCreation(IdentityPermissionPlan.AssignedRole);
        foreach (string key in new[] { "issuer-work", "dispatch-work", "registration", "canary", "owned-key" }) CommitCreation(key);
        ownedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        actors = Enumerable.Range(0, root!.ScopeProfile == IdentityPermissionScope.Organization ? 4 : 3).Select(IssueActor).ToArray();
        foreach (var row in plan!.Rows)
        {
            if (row.Window == "copy")
            {
                if (!Managed(row)) CommitCreation(row.Identity);
                continue;
            }
            Bootstrap(row);
        }
        assigned = !root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        if (assigned)
        {
            CommitCreation(plan.PolicyKey);
            string[] actions = root.ScopeProfile == IdentityPermissionScope.Project ?
                ["read", "create", "edit", "delete", "assign-role", "assign-additional-privileges", "revoke-auth", "edit-auth", "create-token", "get-token", "delete-token"] :
                ["read", "create", "edit", "delete", "grant-privileges", "revoke-auth", "edit-auth", "create-token", "get-token", "delete-token"];
            string baseline = actions[(Array.IndexOf(actions, IdentityPermissionContract.Wire(root.Action)) + 1) % actions.Length];
            policy = new(Id(plan.PolicyKey), revision, actors[0].Principal, actors[0].Kind, Organization,
                root.ScopeProfile == IdentityPermissionScope.Project ? Id(IdentityPermissionPlan.Project) : "", "identity", [baseline],
                baseline is "assign-role" or "assign-additional-privileges" ? plan.Rows.Where(r => r.Control == "selected" && IdentityPermissionContract.Wire(r.Action) == baseline).Select(r => Id(r.Identity)).Where(id => id.Length > 0).ToArray() : [],
                baseline == "assign-role" ? plan.Role : baseline == "assign-additional-privileges" ? "identity:read" : "");
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
        lock (gate) CommitCreation(IdentityPermissionPlan.Template, admitted: true);
    }
    private static bool Managed(IdentityPermissionRow row) => row.Action == IdentityPermissionAction.Edit || IdentityPermissionContract.TokenAction(row.Action);
    private void Bootstrap(IdentityPermissionRow row)
    {
        if (row.Action == IdentityPermissionAction.Create && root!.ScopeProfile == IdentityPermissionScope.Organization) return;
        if (Id(row.Identity).Length == 0) CommitCreation(row.Identity);
        if (row.Action == IdentityPermissionAction.Create) return;
        CommitCreation(row.Membership);
        if (IdentityPermissionContract.TokenAction(row.Action))
        {
            CommitCreation(row.Auth); CommitCreation(row.Canary); CommitCreation(row.ReadPolicy);
            targetReads.Add(Id(row.ReadPolicy), new(Id(row.ReadPolicy), Fault == "target-read-policy-actor" ? actors[0].Principal : Id(row.Identity), Id(row.Organization),
                Id(row.Project), Id(row.Canary), "identity", "read"));
            if (row.Action != IdentityPermissionAction.CreateToken) IssueTarget(row, "bootstrap-" + Guid.NewGuid().ToString("N"));
        }
        states.Add(row.Key, plan!.Initial(row, Issued));
    }
    private IdentityPermissionTokenIssue IssueTarget(IdentityPermissionRow row, string request)
    {
        string id = CommitCreation(row.Token, request); var binding = storageBindings.Single(b => b.CanonicalId == id);
        byte[] random = RandomNumberGenerator.GetBytes(32), bytes;
        try { bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(random)); } finally { CryptographicOperations.ZeroMemory(random); }
        privateBuffers.Add(bytes); Copies.Add(bytes); tokenMaterial.Add(id, bytes);
        var issue = new IdentityPermissionTokenIssue(row.Key, binding.IntentHash, id, Id(row.Identity), Id(row.Organization), Id(row.Project),
            Id(row.Auth), request, binding.Commit, IdentityPermissionContract.RawHash(bytes));
        tokenIssues.Add(issue); tokenStates.Add(id, new(id, request, false, ""));
        if (row.Action != IdentityPermissionAction.CreateToken) captures.Add(new(row.Key, id, request, issue.Hash, false));
        return issue;
    }
    internal async Task CaptureAsync(IdentityPermissionRoot selected, string row, string tokenId, string material, CancellationToken token)
    {
        lock (gate)
        {
            IdentityPermissionContract.Require(!closing && !closed && root is not null && IdentityPermissionContract.Hash(root) == IdentityPermissionContract.Hash(selected));
            var issue = tokenIssues.Single(t => t.Row == row && t.Token == tokenId);
            byte[] bytes = Encoding.UTF8.GetBytes(material); Copies.Add(bytes);
            try { IdentityPermissionContract.Require(IdentityPermissionContract.RawHash(bytes) == issue.Hash && !captures.Any(c => c.Token == tokenId)); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
            if (Fault == "deferred-capture") deferredCapture = CompleteCaptureAsync(issue);
            else captures.Add(new(row, tokenId, issue.Request, Fault == "capture-substitution" ? "wrong" : issue.Hash, false));
        }
        if (deferredCapture is not null) await deferredCapture.WaitAsync(token);
    }
    private async Task CompleteCaptureAsync(IdentityPermissionTokenIssue issue)
    {
        CaptureEntered.TrySetResult(); await CaptureRelease.Task.WaitAsync(shutdown.Token);
        lock (gate) captures.Add(new(issue.Row, issue.Token, issue.Request, issue.Hash, false));
    }
    internal IdentityPermissionPacket Step(IdentityPermissionRoot selected, IdentityPermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == IdentityPermissionStep.Reserve)
            {
                IdentityPermissionContract.Require(root is null && capability == "identity-capability" && selected.Origin == Origin.AbsoluteUri &&
                    selected.Organization == Organization && selected.Authorities == Authorities && IdentityPermissionContract.Hash(Profile) == IdentityPermissionContract.Hash(selected.Profile));
                root = selected; plan = new(selected);
                if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
            }
            IdentityPermissionContract.Require(root is not null && IdentityPermissionContract.Hash(root) == IdentityPermissionContract.Hash(selected) && !closed &&
                (step == IdentityPermissionStep.Close || stage == (int)step));
            if (step != IdentityPermissionStep.Close) stage++;
            switch (step)
            {
                case IdentityPermissionStep.Open: Open(); break;
                case IdentityPermissionStep.Before: Clear(); window = "before"; break;
                case IdentityPermissionStep.Arm: Clear(); window = ""; armed = true; break;
                case IdentityPermissionStep.Settle: settled = true; break;
                case IdentityPermissionStep.After:
                    ingress.RemoveAll(e => e.Phase != "activation"); commits.RemoveAll(c => !ingress.Any(e => e.Request == c.Request));
                    decisions.Clear(); changes.Clear(); authentication.Clear(); probeCounts.Clear(); window = "after"; break;
                case IdentityPermissionStep.ObserveBefore:
                case IdentityPermissionStep.ObserveAfter: window = ""; break;
                case IdentityPermissionStep.Close:
                    Closes++;
                    IdentityPermissionContract.Require(closing && (delayed is null || delayed.IsCompletedSuccessfully));
                    // Reconcile native IDs from original-root issuance AND storage, not the Open reply.
                    IdentityPermissionContract.Require(issuanceBindings.SequenceEqual(storageBindings));
                    foreach (var binding in storageBindings)
                        IdentityPermissionContract.Require(binding.IntentHash == IdentityPermissionContract.Hash(plan!.Intents.Single(i => i.Key == binding.Intent)) &&
                            !borrowed.Any(b => b.Id == binding.CanonicalId));
                    foreach (var binding in storageBindings)
                    {
                        var native = resources.SingleOrDefault(r => r.Value.CanonicalId == binding.CanonicalId);
                        if (native.Key is null) continue; // A witnessed downstream delete may already have removed it.
                        IdentityPermissionContract.Require(native.Value.Intent == binding.Intent);
                        resources.Remove(native.Key);
                    }
                    states.Clear(); tokens.Clear(); targetReads.Clear(); policy = copiedPolicy = null;
                    for (int i = 0; i < captures.Count; i++) captures[i] = captures[i] with { Released = true };
                    foreach (var bytes in privateBuffers) CryptographicOperations.ZeroMemory(bytes);
                    ownedKey?.Dispose(); ownedKey = null; closed = settled = true; armed = false; window = "";
                    if (Fault == "cleanup") resources.Add("residual", new("canary", Id("canary")));
                    if (Fault == "borrowed-change") borrowedObjects[borrowedObjects.Keys.First()] = "modified";
                    break;
            }
            return Packet(step);
        }
    }
    private void Clear() { ingress.Clear(); commits.Clear(); decisions.Clear(); changes.Clear(); authentication.Clear(); probeCounts.Clear(); }
    private IdentityPermissionSigned<T> Sign<T>(IdentityPermissionStep step, IdentityPermissionJournal journal, T content) => writers[journal].Sign(root!, step, content);
    private IdentityPermissionJoin[] Joins()
    {
        if (closed) return [];
        var list = new List<IdentityPermissionJoin>();
        foreach (var row in plan!.Rows)
            if (resources.ContainsKey(row.Membership)) list.Add(new(Id(row.Identity), "machine", Id(row.Organization), Id(row.Project), Id(row.Membership), false));
        for (int i = 0; i < actors.Length; i++) list.Add(new(actors[i].Principal, actors[i].Kind == MemberPermissionActorKind.User ? "user" : "machine",
            actors[i].Organization, root!.ScopeProfile == IdentityPermissionScope.Project ? Id(IdentityPermissionPlan.Project) : "", Id(plan.ActorMembership(i)),
            i == 0 && (!IdentityPermissionContract.Create(root.Operation) || assigned && !copied)));
        if (copied) list.Add(new(actors[0].Principal, "user", Organization, Id(IdentityPermissionPlan.CopyProject), Id(plan.ActorMembership(0, true)), true));
        return list.ToArray();
    }
    private IdentityPermissionPacket Packet(IdentityPermissionStep step)
    {
        bool open = step == IdentityPermissionStep.Open, observe = step is IdentityPermissionStep.ObserveBefore or IdentityPermissionStep.ObserveAfter;
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
        var credentialRows = credentials.ToArray();
        if (observe && Fault == "actor-inventory-mutated") credentialRows[0] = credentialRows[0] with { Hash = "changed" }; var joins = Joins(); var inventory = states.Values.OrderBy(s => s.Row).ToArray();
        if (open && Fault == "actor-kind") credentialRows[0] = credentialRows[0] with { Kind = credentialRows[0].Kind == MemberPermissionActorKind.User ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User };
        if (open && Fault == "credential-wrong-actor") credentialRows[0] = credentialRows[0] with { Principal = Authorities.Observer };
        if (open && Fault == "membership-wrong-membership") joins[0] = joins[0] with { Principal = Authorities.Observer };
        if (open && Fault == "missing-inventory") inventory = inventory.Skip(1).ToArray();
        var allPolicies = new[] { policy, copiedPolicy }.OfType<IdentityPermissionPolicy>().OrderBy(p => p.Resource).ToArray();
        var committed = observe || step == IdentityPermissionStep.Settle ? commits.ToArray() : [];
        if (step == IdentityPermissionStep.Settle && Fault == "wrong-policy-target" && committed.Length == 1)
        { committed[0] = committed[0] with { Policy = committed[0].Policy with { Resource = Guid.NewGuid().ToString() } }; allPolicies = [committed[0].Policy]; }
        var intents = plan!.Intents.ToArray();
        if (open && Fault == "intent-mutation") intents[0] = intents[0] with { Input = "changed" };
        var packet = new IdentityPermissionPacket(
            Sign(step, IdentityPermissionJournal.Ownership, new IdentityPermissionOwner(intents, resources.Values.ToArray(), Borrowed(), true, true,
                settled || closed, settled || closed, open && Fault == "pending-issuer" ? 1 : 0, closed ? 0 : 1, open ? actors : [], open ? Issued.Targets : step == IdentityPermissionStep.After && copied ? Issued.Targets.Where(t => plan.Rows.Single(r => r.Key == t.Row).Window == "copy").ToArray() : [], settled || closed, settled || closed)),
            Sign(step, IdentityPermissionJournal.Ingress, observe || step is IdentityPermissionStep.Settle or IdentityPermissionStep.Close ? ingress.ToArray() : []),
            Sign(step, IdentityPermissionJournal.Policy, new IdentityPermissionPolicies(allPolicies, committed,
                targetReads.Values.ToArray())),
            Sign(step, IdentityPermissionJournal.Storage, new IdentityPermissionStorage(storage, inventory, observe ? changes.ToArray() : [], tokenStates.Values.ToArray())),
            Sign(step, IdentityPermissionJournal.Issuer, new IdentityPermissionIssuance(issue, credentialRows, tokenIssues.ToArray())),
            Sign(step, IdentityPermissionJournal.Membership, joins),
            Sign(step, IdentityPermissionJournal.Access, new IdentityPermissionAccessJournal(observe ? decisions.ToArray() : [],
                observe || step == IdentityPermissionStep.Close ? authentication.ToArray() : [])),
            Sign(step, IdentityPermissionJournal.Capture, captures.ToArray()),
            Sign(step, IdentityPermissionJournal.TokenState, new IdentityPermissionTokenJournal(tokenStates.Values.ToArray(),
                observe || step == IdentityPermissionStep.Close ? authentication.ToArray() : [], true, deferredCapture is null || deferredCapture.IsCompletedSuccessfully, true)), []);
        if (observe && Fault == "token-state-mismatch" && packet.TokenState.Payload.Content.Inventory.Length > 0)
        {
            var changed = packet.TokenState.Payload.Content.Inventory.ToArray(); changed[0] = changed[0] with { Revoked = !changed[0].Revoked };
            packet = packet with { TokenState = Sign(step, IdentityPermissionJournal.TokenState, packet.TokenState.Payload.Content with { Inventory = changed }) };
        }
        if (observe && Fault == "omitted-capture") packet = packet with { Capture = Sign(step, IdentityPermissionJournal.Capture, Array.Empty<IdentityPermissionCapture>()) };
        if (observe && Fault == "authentication-substitution" && authentication.Count > 0)
        {
            var substituted = authentication.ToArray(); substituted[0] = substituted[0] with { Identity = Authorities.Runtime };
            packet = packet with
            {
                Access = Sign(step, IdentityPermissionJournal.Access,
                packet.Access.Payload.Content with { Authentication = substituted })
            };
        }
        if (observe && Fault == "token-owner" && tokenIssues.Count > 0)
        {
            var changed = tokenIssues.ToArray(); changed[0] = changed[0] with { Identity = Authorities.Runtime };
            packet = packet with { Issuer = Sign(step, IdentityPermissionJournal.Issuer, packet.Issuer.Payload.Content with { Tokens = changed }) };
        }
        var seals = new List<IdentityPermissionSigned<MemberPermissionSeal>>();
        Add(IdentityPermissionJournal.Ownership, packet.Owner.Payload); Add(IdentityPermissionJournal.Ingress, packet.Ingress.Payload);
        Add(IdentityPermissionJournal.Policy, packet.Policy.Payload); Add(IdentityPermissionJournal.Storage, packet.Storage.Payload);
        Add(IdentityPermissionJournal.Issuer, packet.Issuer.Payload); Add(IdentityPermissionJournal.Membership, packet.Membership.Payload); Add(IdentityPermissionJournal.Access, packet.Access.Payload);
        Add(IdentityPermissionJournal.Capture, packet.Capture.Payload); Add(IdentityPermissionJournal.TokenState, packet.TokenState.Payload);
        return packet with { Seals = open && Fault == "missing-seal" ? seals.Skip(1).ToArray() : seals.ToArray() };
        void Add<T>(IdentityPermissionJournal journal, T payload) => seals.Add(Sign(step, journal,
            new MemberPermissionSeal(IdentityPermissionContract.Hash(payload), !(open && Fault == "nonterminal"), 0, 1)));
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
                IdentityPermissionContract.Require(length is >= 0 and <= 131072);
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
    private IdentityPermissionCredential Authenticate(string bearer)
    {
        if (tokens.TryGetValue(bearer, out var credential)) return credential;
        string principal = hostTokens.SingleOrDefault(p => p.Value == bearer).Key ?? "unknown";
        byte[] bytes = Encoding.UTF8.GetBytes(bearer);
        try { return new("host-" + principal, principal, MemberPermissionActorKind.Machine, Organization, IdentityPermissionContract.RawHash(bytes), false); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private void Record(string request, IdentityPermissionCredential actor, string method, string path, byte[] bytes, string intent, bool allowed, string phase) =>
        ingress.Add(new(request, actor.Principal, actor.Kind, actor.Hash, actor.Organization, method, path, IdentityPermissionContract.RawHash(bytes), intent, allowed, phase));
    private (int, object) Handle(string method, Uri uri, string bearer, JsonElement body, byte[] bytes)
    {
        if (root is null || actors.Length == 0 || closed) return (403, new { });
        if (tokenMaterial.Any(p => Encoding.ASCII.GetString(p.Value) == bearer)) return AuthenticateTarget(method, uri.AbsolutePath, bearer);
        var actor = Authenticate(bearer); string path = uri.AbsolutePath;
        bool template = root.Operation.Contains("ProjectTemplate", StringComparison.Ordinal), organization = root.Operation.EndsWith("OrganizationRole", StringComparison.Ordinal),
            privilege = root.Operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal), create = root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        string originalPath = (template ? "/api/v1/project-templates" : organization ? "/api/v1/organization/roles" : privilege ?
            "/api/v2/identity-project-additional-privilege" : "/api/v1/projects/" + Id(IdentityPermissionPlan.Project) + "/roles") + (create ? "" : "/" + Id(plan!.PolicyKey));
        if (path == originalPath && method == (create ? "POST" : "PATCH") && window.Length == 0 && !settled)
        {
            if (!armed || settled || Originals != 0) return (409, new { });
            Originals++; string request = Guid.NewGuid().ToString("N"), intent = IdentityPermissionContract.RawHash(bytes);
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
            string[] names = permission.TryGetProperty("conditions", out var conditions) ? conditions.GetProperty("identityId").GetProperty("$in")
                .EnumerateArray().Select(n => n.GetString()!).ToArray() : [];
            string role = conditions.ValueKind != JsonValueKind.Object ? "" : conditions.TryGetProperty("assignableRole", out var assignable) ? assignable.GetString()! :
                conditions.GetProperty("assignableSubject").GetString() + ":" + conditions.GetProperty("assignableAction").GetString();
            if (Fault is not ("ignored-policy" or "lost-nonapplied"))
            {
                if (create) CommitCreation(plan!.PolicyKey, request);
                string old = revision; revision = "policy-2";
                policy = new(Id(plan!.PolicyKey), revision, principal, actors[0].Kind, Organization, organization ? "" : Id(IdentityPermissionPlan.Project),
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
            else { result["name"] = plan.Slug; result[organization ? "orgId" : "projectId"] = organization ? Organization : Id(IdentityPermissionPlan.Project); }
            return (200, new JsonObject { [template ? "projectTemplate" : privilege ? "privilege" : "role"] = result });
        }
        if (settled && actor.Principal == Authorities.Setup && actor.Kind == MemberPermissionActorKind.Machine && policy is not null &&
            (path == "/api/v1/projects" || path.EndsWith("/" + Id(plan!.ActorMembership(0)), StringComparison.Ordinal)))
            return Activate(actor, method, path, body, bytes);
        if (closing && actor.Principal == Authorities.Setup && path.StartsWith("/api/v1/auth/token-auth/tokens/", StringComparison.Ordinal))
        {
            var issue = tokenIssues.Single(t => path == "/api/v1/auth/token-auth/tokens/" + t.Token + "/revoke");
            string request = Guid.NewGuid().ToString("N"); Record(request, actor, method, path, bytes, "", true, "cleanup");
            if (!tokenStates[issue.Token].Revoked) tokenStates[issue.Token] = tokenStates[issue.Token] with { Revoked = true, Transition = request };
            return (200, new { message = "revoked" });
        }
        if (closing) return (403, new { });
        return IdentityAction(actor, method, path, body, bytes);
    }
    private (int, object) Activate(IdentityPermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        string request = Guid.NewGuid().ToString("N");
        if (path == "/api/v1/projects")
        {
            if (copied || method != "POST" || body.GetProperty("template").GetString() != plan!.Slug || body.GetProperty("slug").GetString() != plan.CopySlug) return (403, new { });
            CommitCreation(IdentityPermissionPlan.CopyProject, request); CommitCreation(plan.ActorMembership(0, true));
            copied = true; assigned = true;
            foreach (var row in plan.Rows.Where(r => r.Window == "copy")) Bootstrap(row);
            copiedPolicy = policy! with
            {
                Resource = Id(IdentityPermissionPlan.CopyProject),
                Project = Id(IdentityPermissionPlan.CopyProject),
                Actions = Fault == "template-echo" ? [] : policy.Actions
            };
            Record(request, actor, method, path, bytes, IdentityPermissionContract.RawHash(bytes), true, "activation");
            commits.Add(new(request, revision, copiedPolicy));
            return (200, new
            {
                project = new
                {
                    id = Id(IdentityPermissionPlan.CopyProject),
                    _id = Id(IdentityPermissionPlan.CopyProject),
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
        Record(request, actor, method, path, bytes, org ? IdentityPermissionContract.RawHash(bytes) : WireHash(new object?[] { null, body }), true, "activation");
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
    private (int, object) IdentityAction(IdentityPermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        if (window is not ("before" or "after")) return (403, new { });
        string[] parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        bool auth = path.StartsWith("/api/v1/auth/token-auth/", StringComparison.Ordinal);
        bool additional = path == "/api/v2/identity-project-additional-privilege";
        bool projectScope = parts.Length > 4 && parts[2] == "projects";
        bool membership = projectScope && parts[4] == "memberships";
        string project = projectScope ? parts[3] : "";
        string identity = additional ? body.GetProperty("identityId").GetString()! : auth && parts[4] == "tokens" ?
            tokenIssues.Single(t => t.Token == parts[5]).Identity : auth ? parts[5] : projectScope ? parts.Last() : parts.Length > 3 ? parts[3] : "";
        IdentityPermissionAction action = auth ? method switch
        {
            "GET" => IdentityPermissionAction.GetToken,
            "POST" => parts[4] == "tokens" ? IdentityPermissionAction.DeleteToken : IdentityPermissionAction.CreateToken,
            "PATCH" => IdentityPermissionAction.EditAuth,
            _ => IdentityPermissionAction.RevokeAuth
        } : additional ? IdentityPermissionAction.AssignAdditionalPrivileges : method switch
        {
            "GET" => IdentityPermissionAction.Read,
            "POST" => IdentityPermissionAction.Create,
            "DELETE" => IdentityPermissionAction.Delete,
            "PATCH" => membership ? IdentityPermissionAction.AssignRole : body.TryGetProperty("role", out _) ? IdentityPermissionAction.GrantPrivileges : IdentityPermissionAction.Edit,
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        var row = action == IdentityPermissionAction.Create && !projectScope ? plan!.Rows.SingleOrDefault(r =>
            r.Name == body.GetProperty("name").GetString() && Id(r.Organization) == actor.Organization) :
            plan!.Rows.SingleOrDefault(r => Id(r.Identity) == identity);
        if (row is null) return (404, new { });
        // Native ownership, not the request's scope labels, governs auth routes.
        if (auth || additional) project = Id(row.Project);
        if (project != Id(row.Project) || action != row.Action) return (404, new { });
        string org = Id(row.Organization);
        var effective = project == Id(IdentityPermissionPlan.CopyProject) && copied ? copiedPolicy : policy;
        string wire = IdentityPermissionContract.Wire(action);
        string selectedRole = action == IdentityPermissionAction.AssignRole ? body.GetProperty("roles")[0].GetProperty("role").GetString()! : "";
        string delegated = additional ? body.GetProperty("permissions")[0].GetProperty("subject").GetString() + ":" +
            body.GetProperty("permissions")[0].GetProperty("action").GetString() : "";
        bool allowed = assigned && effective is not null && effective.Subject == "identity" && effective.Actor == actor.Principal && effective.Kind == actor.Kind &&
            actor.Organization == org && effective.Organization == org && effective.Project == project && effective.Actions.Contains(wire) &&
            (action != IdentityPermissionAction.AssignRole || effective.Names.Contains(identity) && effective.Role == selectedRole) &&
            (action != IdentityPermissionAction.AssignAdditionalPrivileges || effective.Names.Contains(identity) && effective.Role == delegated);
        if (Fault == "action-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && org == Organization &&
            project == (root!.ScopeProfile == IdentityPermissionScope.Organization ? "" : copied ? Id(IdentityPermissionPlan.CopyProject) : Id(IdentityPermissionPlan.Project))) allowed = true;
        if (Fault == "scope-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && policy?.Actions.Contains(wire) == true) allowed = true;
        string request = Guid.NewGuid().ToString("N"); var recorded = Fault == "wrong-actor" ? actor with { Principal = Authorities.Observer } : actor;
        if (Fault == "wrong-credential") recorded = recorded with { Hash = "wrong" };
        string intent = action switch
        {
            IdentityPermissionAction.CreateToken => WireHash(new object?[] { "create-token", body }),
            IdentityPermissionAction.EditAuth => WireHash(new object?[] { "patch-token", body }),
            IdentityPermissionAction.Create or IdentityPermissionAction.Edit or IdentityPermissionAction.AssignRole or IdentityPermissionAction.GrantPrivileges => WireHash(new object?[] { null, body }),
            IdentityPermissionAction.AssignAdditionalPrivileges => WireHash(new object?[] { plan.ProjectSlug, Id(row.Membership), null, body }),
            _ => ""
        };
        Record(request, recorded, method, path, bytes, intent, allowed, "action");
        var previous = states.GetValueOrDefault(row.Key); object response = new { };
        if (allowed)
        {
            switch (action)
            {
                case IdentityPermissionAction.Create:
                    if (projectScope)
                    {
                        if (body.GetProperty("role").GetString() != "no-access") return (400, new { });
                        CommitCreation(row.Membership, request);
                    }
                    else
                    {
                        if (body.GetProperty("organizationId").GetString() != org || body.GetProperty("role").GetString() != "no-access") return (400, new { });
                        CommitCreation(row.Identity, request); CommitCreation(row.Membership);
                    }
                    states.Add(row.Key, plan.Initial(row, Issued));
                    response = projectScope ? new { identityMembership = MembershipRow(states[row.Key]) } : new { identity = IdentityRow(states[row.Key]) }; break;
                case IdentityPermissionAction.Delete:
                    response = projectScope ? new { identityMembership = MembershipRow(previous!) } : new { identity = IdentityRow(previous!, view: "delete") };
                    states.Remove(row.Key); resources.Remove(row.Membership); if (!projectScope) resources.Remove(row.Identity); break;
                case IdentityPermissionAction.Edit:
                    states[row.Key] = previous! with { Name = body.GetProperty("name").GetString()!, Version = previous.Version + 1 };
                    response = new { identity = IdentityRow(states[row.Key], projectScope, "edit") }; break;
                case IdentityPermissionAction.GrantPrivileges:
                case IdentityPermissionAction.AssignRole:
                    states[row.Key] = previous! with { Role = projectScope ? selectedRole : body.GetProperty("role").GetString()!, Version = previous.Version + 1 };
                    response = projectScope ? new { identityMembership = MembershipRow(states[row.Key]) } : new { identity = IdentityRow(states[row.Key], view: "edit") }; break;
                case IdentityPermissionAction.AssignAdditionalPrivileges:
                    CommitCreation(row.Privilege, request); states[row.Key] = previous! with
                    {
                        Privilege = Id(row.Privilege),
                        DelegatedPermission = delegated,
                        Version = previous.Version + 1
                    };
                    response = new
                    {
                        privilege = new
                        {
                            id = Id(row.Privilege),
                            slug = row.Name,
                            isTemporary = false,
                            permissions = JsonNode.Parse(body.GetProperty("permissions").GetRawText()),
                            createdAt = Stamp,
                            updatedAt = Stamp
                        }
                    }; break;
                case IdentityPermissionAction.EditAuth:
                    states[row.Key] = previous! with { Ttl = body.GetProperty("accessTokenTTL").GetInt32(), Version = previous.Version + 1 };
                    response = new { identityTokenAuth = AuthRow(states[row.Key]) }; break;
                case IdentityPermissionAction.RevokeAuth:
                    response = new { identityTokenAuth = AuthRow(previous!) };
                    states[row.Key] = previous! with { Auth = "", Version = previous.Version + 1 }; resources.Remove(row.Auth);
                    if (Fault != "revoke-ack-only") tokenStates[Id(row.Token)] = tokenStates[Id(row.Token)] with { Revoked = true, Transition = request }; break;
                case IdentityPermissionAction.CreateToken:
                    var issue = IssueTarget(row, request);
                    if (Fault == "invalidated-token") tokenStates[issue.Token] = tokenStates[issue.Token] with { Revoked = true, Transition = request };
                    response = new
                    {
                        tokenData = TokenRow(issue),
                        accessToken = Encoding.ASCII.GetString(tokenMaterial[Fault == "replayed-token" ? tokenIssues.First().Token : issue.Token]),
                        tokenType = "Bearer",
                        expiresIn = 600,
                        accessTokenMaxTTL = 600
                    }; break;
                case IdentityPermissionAction.GetToken:
                    response = new { tokens = new[] { TokenRow(tokenIssues.Single(t => t.Row == row.Key)) } }; break;
                case IdentityPermissionAction.DeleteToken:
                    if (Fault != "revoke-ack-only") tokenStates[Id(row.Token)] = tokenStates[Id(row.Token)] with { Revoked = true, Transition = request };
                    response = new { message = "revoked" }; break;
                case IdentityPermissionAction.Read:
                    response = projectScope ? new { identityMembership = MembershipRow(previous!, true) } :
                        new
                        {
                            identity = new
                            {
                                id = previous!.Membership,
                                orgId = org,
                                identityId = identity,
                                role = previous.Role,
                                createdAt = Stamp,
                                updatedAt = Stamp,
                                metadata = Array.Empty<object>(),
                                identity = IdentityRow(previous, view: "read")
                            }
                        }; break;
            }
            if (Fault == "wrong-identity" && states.TryGetValue(row.Key, out var changed)) states[row.Key] = changed with { Identity = Guid.NewGuid().ToString() };
            if (Fault == "wrong-membership" && states.TryGetValue(row.Key, out var member)) states[row.Key] = member with { Membership = Guid.NewGuid().ToString() };
        }
        decisions.Add(new(request, recorded.Principal, recorded.Kind, recorded.Id, recorded.Hash, org, project, Id(row.Identity), Id(row.Membership), revision, action, allowed));
        changes.Add(new(request, row.Key, previous, states.GetValueOrDefault(row.Key)));
        return (allowed ? 200 : 403, response);
    }
    private (int, object) AuthenticateTarget(string method, string path, string bearer)
    {
        var issue = tokenIssues.Single(t => Encoding.ASCII.GetString(tokenMaterial[t.Token]) == bearer);
        var row = plan!.Rows.Single(r => r.Key == issue.Row);
        string expected = issue.Project.Length == 0 ? "/api/v1/identities/" + Id(row.Canary) : "/api/v1/projects/" + issue.Project + "/identities/" + Id(row.Canary);
        bool invalid = tokenStates[issue.Token].Revoked;
        var readPolicy = targetReads.GetValueOrDefault(Id(row.ReadPolicy));
        bool authorized = method == "GET" && path == expected && resources.ContainsKey(row.Canary) &&
            readPolicy == new IdentityPermissionReadPolicy(Id(row.ReadPolicy), issue.Identity, issue.Organization, issue.Project,
                Id(row.Canary), "identity", "read");
        int count = probeCounts.GetValueOrDefault(issue.Token); probeCounts[issue.Token] = count + 1;
        string phase = closing ? "cleanup" : row.Action == IdentityPermissionAction.CreateToken || count > 0 ? "after" : "before";
        var result = invalid ? IdentityPermissionAuthentication.InvalidToken : authorized ? IdentityPermissionAuthentication.Authenticated : IdentityPermissionAuthentication.ScopeDenied;
        if (Fault == "scope403-not-invalid" && invalid) result = IdentityPermissionAuthentication.ScopeDenied;
        int status = result == IdentityPermissionAuthentication.InvalidToken ? 401 : result == IdentityPermissionAuthentication.ScopeDenied ? 403 : 200;
        authentication.Add(new(Guid.NewGuid().ToString("N"), issue.Token, issue.Hash, issue.Identity, issue.Organization, issue.Project,
            Id(row.Canary), Id(row.ReadPolicy), phase, result, status));
        var canary = new IdentityPermissionState(row.Canary, Id(row.Canary), "", issue.Organization, issue.Project, row.Canary, "no-access", "", 0, "", 1);
        return status != 200 ? (status, new { }) : issue.Project.Length > 0 ? (200, new { identity = IdentityRow(canary, true) }) :
            (200, new
            {
                identity = new
                {
                    id = Id(row.ReadPolicy),
                    orgId = issue.Organization,
                    identityId = Id(row.Canary),
                    role = "no-access",
                    createdAt = Stamp,
                    updatedAt = Stamp,
                    metadata = Array.Empty<object>(),
                    identity = IdentityRow(canary, view: "read")
                }
            });
    }
    private const string Stamp = "2026-01-01T00:00:00Z";
    private object Role(string membership, string role) => new
    {
        id = Id(IdentityPermissionPlan.AssignedRole),
        projectMembershipId = membership,
        role,
        isTemporary = false,
        createdAt = Stamp,
        updatedAt = Stamp
    };
    private object MembershipRow(IdentityPermissionState state, bool detail = false)
    {
        var value = new Dictionary<string, object?>
        {
            ["id"] = state.Membership,
            ["identityId"] = state.Identity,
            ["projectId"] = state.Project,
            ["createdAt"] = Stamp,
            ["updatedAt"] = Stamp
        };
        if (detail)
        {
            value.Remove("identityId"); value.Remove("projectId");
            value["identity"] = IdentityRow(state, view: "member");
            value["roles"] = new[] { new { id = Id(IdentityPermissionPlan.AssignedRole), role = state.Role, isTemporary = false } };
        }
        return value;
    }
    private static object IdentityRow(IdentityPermissionState state, bool managed = false, string view = "create")
    {
        var value = new Dictionary<string, object?>
        {
            ["id"] = state.Identity,
            ["orgId"] = state.Organization,
            ["name"] = state.Name,
            ["createdAt"] = Stamp,
            ["updatedAt"] = Stamp,
            ["hasDeleteProtection"] = false,
            ["authMethods"] = new[] { "token-auth" },
            ["activeLockoutAuthMethods"] = Array.Empty<string>(),
            ["metadata"] = Array.Empty<object>()
        };
        if (managed) value["projectId"] = state.Project;
        else if (view is "read" or "member")
        {
            value.Remove("createdAt"); value.Remove("updatedAt");
            if (view == "read") value.Remove("metadata");
            else { value.Remove("hasDeleteProtection"); value.Remove("activeLockoutAuthMethods"); }
        }
        else
        {
            value.Remove("activeLockoutAuthMethods");
            if (view != "create") value.Remove("authMethods");
            if (view == "delete") value.Remove("metadata");
        }
        return value;
    }
    private static object AuthRow(IdentityPermissionState state) => new
    {
        id = state.Auth,
        identityId = state.Identity,
        createdAt = Stamp,
        updatedAt = Stamp,
        accessTokenTTL = state.Ttl,
        accessTokenMaxTTL = 900,
        accessTokenNumUsesLimit = 0
    };
    private object TokenRow(IdentityPermissionTokenIssue issue) => new
    {
        id = issue.Token,
        identityId = issue.Identity,
        authMethod = "token-auth",
        createdAt = Stamp,
        updatedAt = Stamp,
        accessTokenTTL = 600,
        accessTokenMaxTTL = 600,
        accessTokenNumUsesLimit = 0,
        isAccessTokenRevoked = tokenStates[issue.Token].Revoked
    };
    private static string WireHash(object value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        try { return IdentityPermissionContract.RawHash(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal async Task SealAndDrainAsync()
    {
        lock (gate) { closing = true; settled = true; armed = false; CloseEntered.TrySetResult(); }
        if (delayed is not null) await delayed;
        if (deferredCapture is not null) await deferredCapture;
        await Task.WhenAll(connections);
        lock (gate)
        {
            ingress.Clear(); authentication.Clear(); probeCounts.Clear();
            foreach (var issue in tokenIssues.Where(t => !captures.Any(c => c.Token == t.Token)))
                captures.Add(new(issue.Row, issue.Token, issue.Request, issue.Hash, false));
        }
        if (root is null || tokenIssues.Count == 0) return;
        using var env = Environment(root.Operation, root.Action);
        foreach (var issue in tokenIssues)
        {
            var client = env.CreateManagementClient();
            using var request = IdentityAuthenticationOperations.RevokeToken(issue.Organization, issue.Token);
            var authority = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Setup), issue.Organization);
            var receipt = client.CreateReceipt(request);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, shutdown.Token);
            IdentityPermissionContract.Require(result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied);
            var row = plan!.Rows.Single(r => r.Key == issue.Row);
            await IdentityPermissionClient.ProbeAsync(env, issue.Organization, issue.Project, Id(row.Canary), tokenMaterial[issue.Token], shutdown.Token);
        }
        await Task.WhenAll(connections);
    }
    internal Task DrainAsync() => Task.WhenAll(connections);
    public async ValueTask DisposeAsync()
    {
        OpenRelease.TrySetResult(); IssuerRelease.TrySetResult(); CaptureRelease.TrySetResult();
        if (delayed is not null) await delayed;
        if (deferredCapture is not null) await deferredCapture;
        shutdown.Cancel(); listener.Stop();
        try { await accept; } catch (SocketException) when (shutdown.IsCancellationRequested) { }
        await Task.WhenAll(connections);
        foreach (var bytes in privateBuffers) CryptographicOperations.ZeroMemory(bytes);
        ownedKey?.Dispose(); Source.Dispose(); foreach (var writer in writers.Values) writer.Dispose(); shutdown.Dispose();
    }
}
