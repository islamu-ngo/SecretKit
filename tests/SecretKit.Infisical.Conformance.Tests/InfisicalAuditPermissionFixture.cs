using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Globalization;
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
internal sealed partial class InfisicalAuditPermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static MemberPermissionAuthorities Authorities => InfisicalMemberPermissionFixture.Authorities;
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<AuditPermissionJournal, InfisicalAuditPermissionWriter> writers = [];
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
        ["30000000-0000-0000-0000-000000000005"] = "borrowed-policy-role",
        ["30000000-0000-0000-0000-000000000006"] = "immutable-borrowed-audit-history"
    };
    private readonly Dictionary<string, AuditPermissionCredential> tokens = [];
    private readonly List<AuditPermissionCredential> credentials = [];
    private readonly List<AuditPermissionBinding> issuanceBindings = [], storageBindings = [];
    private readonly Dictionary<string, AuditPermissionResource> resources = [];
    private readonly List<AuditPermissionState> states = [];
    private readonly List<AuditPermissionSeedCommit> seedCommits = [];
    private readonly List<AuditPermissionEvent> publications = [];
    private readonly Queue<(AuditPermissionSeedCommit Commit, AuditPermissionCredential Actor, DateTimeOffset At)> outbox = [];
    private readonly List<AuditPermissionCredential> credentialHistory = [];
    private bool producerFence = true, publicationFence = true;
    private Task? publishing;
    private readonly List<AuditPermissionIngress> ingress = [];
    private readonly List<AuditPermissionCommit> commits = [];
    private readonly List<AuditPermissionAccess> decisions = [];
    private readonly List<byte[]> privateBuffers = [];
    private readonly MemberPermissionBorrowed[] borrowed;
    private AuditPermissionRoot? root;
    private AuditPermissionPlan? plan;
    private AuditPermissionActor[] actors = [];
    private AuditPermissionPolicy? policy, copiedPolicy;
    private JsonObject? templateConfiguration, copiedConfiguration;
    private ECDsa? ownedKey;
    private string revision = "policy-1", window = "";
    private int stage;
    private bool closed, closing, armed, settled, assigned, copied;
    private Task? delayed;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal AuditPermissionProfile Profile { get; }
    internal InfisicalAuditPermissionFixtureSource Source { get; }
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    internal TaskCompletionSource OpenEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource OpenRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource CloseEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource PublisherEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource PublisherRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal int Originals { get; private set; }
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Generated => storageBindings.Count;
    internal int Registrations => root is not null && !closed ? 1 : 0;
    internal int HistoricalRows => states.Count;
    internal int PendingPublication => outbox.Count;
    internal int Remaining => resources.Count + credentials.Count + (policy is null ? 0 : 1) + (copiedPolicy is null ? 0 : 1) + (ownedKey is null ? 0 : 1);
    internal bool BorrowedPreserved => Borrowed().SequenceEqual(borrowed);
    internal InfisicalAuditPermissionFixture(string fault = "")
    {
        Fault = fault;
        foreach (var journal in Enum.GetValues<AuditPermissionJournal>()) writers.Add(journal, new(journal));
        borrowed = Borrowed();
        Profile = new("controlled-audit", "controlled-epoch", "controlled-v1", writers.Values.Select(w => w.Pin).ToImmutableArray(), AuditPermissionContract.Hash(borrowed));
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/"); Source = new(this); accept = AcceptAsync();
    }
    internal AuditPermissionInput Input(string operation, AuditPermissionAction action) =>
        new(new(new("https://role-source.invalid/"), "coordinator-token", "audit-coordinator", 30), "audit-capability", Profile,
            AuditPermissionContract.Scope(operation), AuditPermissionContract.ActorKind(operation), action, 30, DateTimeOffset.Parse("2026-10-14T12:00:00Z", CultureInfo.InvariantCulture),
            DateTimeOffset.Parse("2026-10-14T12:05:00Z", CultureInfo.InvariantCulture), DateTimeOffset.Parse("2026-10-15T12:05:00Z", CultureInfo.InvariantCulture));
    internal NativeEnvironment Environment(string operation, AuditPermissionAction action, bool configured = true)
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
                    auditPermission = Input(operation, action)
                }
            }
        }, AuditPermissionContract.Options)!;
        if (!configured) scope["scopes"]!["local"]!.AsObject().Remove("auditPermission");
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
        }, AuditPermissionContract.Options));
    }
    internal AuditPermissionRoot Root(string operation, AuditPermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization, operation,
            AuditPermissionContract.Variant(action), boundary, "local", "audit-coordinator", MemberPermissionSourceKind.ControlledFixture,
            AuditPermissionContract.Scope(operation), AuditPermissionContract.ActorKind(operation), action, Authorities, Profile, Input(operation, action).From, Input(operation, action).Until, Input(operation, action).RetainUntil);
    private MemberPermissionBorrowed[] Borrowed() => hostTokens.Select(p => new MemberPermissionBorrowed("host-credential", p.Key, AuditPermissionContract.Hash(p.Value)))
        .Concat(writers.Values.Select(w => new MemberPermissionBorrowed("host-key", w.Pin.Writer, AuditPermissionContract.Hash(w.Pin.Spki))))
        .Concat(borrowedObjects.Select(p => new MemberPermissionBorrowed(p.Value, p.Key, AuditPermissionContract.Hash(p.Value)))).ToArray();
    private AuditPermissionIssued Issued => new(actors, storageBindings.ToArray());
    private string Id(string key) => Issued.Id(key);
    private string CommitCreation(string key, string? request = null, bool admitted = false)
    {
        AuditPermissionContract.Require(root is not null && plan is not null && !closed && (!closing || admitted) && !resources.ContainsKey(key) &&
            !storageBindings.Any(b => b.Intent == key));
        var intent = plan!.Intents.Single(i => i.Key == key);
        AuditPermissionContract.Require(Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0));
        // There is deliberately no ID-generation path in Reserve or plan construction.
        string canonical = Guid.NewGuid().ToString();
        var binding = new AuditPermissionBinding(key, AuditPermissionContract.Hash(intent), intent.Work, intent.Kind, Id(intent.Scope),
            AuditPermissionPlan.InputHash(intent, Id), canonical, request ?? Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"));
        issuanceBindings.Add(binding); storageBindings.Add(binding);
        if (intent.Kind != "audit-row") resources.Add(key, new(key, canonical));
        return canonical;
    }
    private AuditPermissionActor IssueActor(int i)
    {
        string key = plan!.ActorKey(i), scope = Id(plan.ActorScope(i)); var kind = plan.ActorKind(i);
        bool owned = !key.StartsWith("@", StringComparison.Ordinal);
        if (owned && Id(key).Length == 0) CommitCreation(key);
        string principal = Id(key); AuditPermissionCredential credential; byte[] bytes;
        if (owned)
        {
            (credential, bytes) = IssueCredential("actor-credential-" + i, principal, kind, scope);
        }
        else
        {
            bytes = Encoding.UTF8.GetBytes(hostTokens[principal]);
            credential = new("host-" + principal, principal, kind, scope, AuditPermissionContract.RawHash(bytes), false);
            CryptographicOperations.ZeroMemory(bytes); bytes = [];
            if (!credentials.Any(c => c.Id == credential.Id)) { credentials.Add(credential); credentialHistory.Add(credential); }
        }
        CommitCreation(plan.ActorMembership(i));
        return new(principal, kind, scope, credential.Id, credential.Hash, bytes, owned);
    }
    private (AuditPermissionCredential Credential, byte[] Bytes) IssueCredential(string key, string principal, MemberPermissionActorKind kind, string scope)
    {
        string id = CommitCreation(key);
        byte[] random = RandomNumberGenerator.GetBytes(32), bytes;
        try { bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(random)); } finally { CryptographicOperations.ZeroMemory(random); }
        privateBuffers.Add(bytes); Copies.Add(bytes);
        var credential = new AuditPermissionCredential(id, principal, kind, scope, AuditPermissionContract.RawHash(bytes), true);
        credentials.Add(credential); credentialHistory.Add(credential); tokens.Add(Encoding.ASCII.GetString(bytes), credential); return (credential, bytes);
    }
    private void Open()
    {
        Opens++; CommitCreation(AuditPermissionPlan.OtherOrganization);
        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
        CommitCreation(AuditPermissionPlan.Project); CommitCreation(AuditPermissionPlan.OtherProject);
        foreach (string key in new[] { "issuer-work", "dispatch-work", "producer-work", "publication-work", "registration", "owned-key" }) CommitCreation(key);
        ownedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        foreach (var host in hostTokens)
        {
            byte[] material = Encoding.UTF8.GetBytes(host.Value);
            try { var c = new AuditPermissionCredential("host-" + host.Key, host.Key, MemberPermissionActorKind.Machine, Organization, AuditPermissionContract.RawHash(material), false); credentials.Add(c); credentialHistory.Add(c); }
            finally { CryptographicOperations.ZeroMemory(material); }
        }
        actors = Enumerable.Range(0, root!.ScopeProfile == AuditPermissionScope.Organization ? 4 : 3).Select(IssueActor).ToArray();
        assigned = !root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        if (assigned)
        {
            CommitCreation(plan!.PolicyKey);
            policy = new(Id(plan.PolicyKey), revision, actors[0].Principal, actors[0].Kind, Organization,
                root.ScopeProfile == AuditPermissionScope.Project ? Id(AuditPermissionPlan.Project) : "", "audit-logs", [], [], plan.Slug, AuditPermissionContract.Template(root.Operation) ? plan.Configuration : "");
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
        lock (gate) CommitCreation(AuditPermissionPlan.Deferred, admitted: true);
    }
    internal AuditPermissionPacket Step(AuditPermissionRoot selected, AuditPermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == AuditPermissionStep.Reserve)
            {
                AuditPermissionContract.Require(root is null && capability == "audit-capability" && selected.Origin == Origin.AbsoluteUri &&
                    selected.Organization == Organization && selected.Authorities == Authorities && AuditPermissionContract.Hash(Profile) == AuditPermissionContract.Hash(selected.Profile));
                root = selected; plan = new(selected);
                if (Fault is "collision" or "lost-reserve") throw new NativeCaseFailureException("observer-unavailable");
            }
            AuditPermissionContract.Require(root is not null && AuditPermissionContract.Hash(root) == AuditPermissionContract.Hash(selected) && !closed &&
                (step == AuditPermissionStep.Close || stage == (int)step));
            if (step != AuditPermissionStep.Close) stage++;
            switch (step)
            {
                case AuditPermissionStep.Open: Open(); break;
                case AuditPermissionStep.SeedBefore:
                case AuditPermissionStep.SeedAfter: producerFence = publicationFence = false; window = step == AuditPermissionStep.SeedBefore ? "seed-before" : "seed-after"; break;
                case AuditPermissionStep.PublishedBefore:
                case AuditPermissionStep.PublishedAfter: AuditPermissionContract.Require(producerFence && publicationFence && outbox.Count == 0); window = ""; break;
                case AuditPermissionStep.Before: window = "before"; break;
                case AuditPermissionStep.Arm: window = ""; armed = true; break;
                case AuditPermissionStep.Settle: settled = true; break;
                case AuditPermissionStep.After: window = "after"; break;
                case AuditPermissionStep.ObserveBefore:
                case AuditPermissionStep.ObserveAfter: window = ""; break;
                case AuditPermissionStep.Close:
                    Closes++;
                    AuditPermissionContract.Require(closing && producerFence && publicationFence && outbox.Count == 0 && (delayed is null || delayed.IsCompletedSuccessfully));
                    AuditPermissionContract.Require(issuanceBindings.SequenceEqual(storageBindings));
                    foreach (var binding in storageBindings)
                    {
                        AuditPermissionContract.Require(binding.IntentHash == AuditPermissionContract.Hash(plan!.Intents.Single(i => i.Key == binding.Intent)) && !borrowed.Any(b => b.Id == binding.CanonicalId));
                        if (binding.Kind == "audit-row") continue; // Immutable historical residue: never issue audit DELETE.
                        var native = resources.Single(r => r.Value.CanonicalId == binding.CanonicalId);
                        AuditPermissionContract.Require(native.Value.Intent == binding.Intent); resources.Remove(native.Key);
                    }
                    credentials.Clear(); tokens.Clear(); policy = copiedPolicy = null; templateConfiguration = copiedConfiguration = null;
                    foreach (var bytes in privateBuffers) CryptographicOperations.ZeroMemory(bytes);
                    ownedKey?.Dispose(); ownedKey = null; closed = settled = true; armed = false; window = "";
                    if (Fault == "cleanup") resources.Add("residual", new("owned-key", Id("owned-key")));
                    if (Fault is "borrowed-change" or "borrowed-history") borrowedObjects[borrowedObjects.Keys.Last()] = "modified";
                    if (Fault == "history-rewrite" && states.Count > 0) states[0] = states[0] with { InputHash = "rewritten" };
                    break;
            }
            return Packet(step);
        }
    }
}
