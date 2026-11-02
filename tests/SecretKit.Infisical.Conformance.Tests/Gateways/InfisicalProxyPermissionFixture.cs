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
internal sealed partial class InfisicalProxyPermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static MemberPermissionAuthorities Authorities => InfisicalMemberPermissionFixture.Authorities;
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<ProxyPermissionJournal, InfisicalProxyPermissionWriter> writers = [];
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
        ["30000000-0000-0000-0000-000000000009"] = "borrowed-credential"
    };
    private readonly Dictionary<string, ProxyPermissionCredential> tokens = [];
    private readonly List<ProxyPermissionCredential> credentials = [];
    private readonly List<ProxyPermissionBinding> issuanceBindings = [], storageBindings = [];
    private readonly Dictionary<string, ProxyPermissionResource> resources = [];
    private readonly Dictionary<string, ProxyPermissionState> states = [];
    private readonly List<ProxyPermissionIngress> ingress = [];
    private readonly List<ProxyPermissionCommit> commits = [];
    private readonly List<ProxyPermissionAccess> decisions = [];
    private readonly List<ProxyPermissionChange> changes = [];
    private readonly List<ProxyPermissionCollectionChange> collectionHistory = [];
    private readonly List<ProxyPermissionCollectionDispatch> collectionDispatches = [];
    private readonly InfisicalProxyPermissionCollectionStore collections = new();
    private readonly Dictionary<string, JsonElement> configurations = [];
    private ProxyPermissionTemplate[] templates = [];
    private JsonElement templateConfiguration;
    private readonly bool retainIds;
    private readonly List<byte[]> privateBuffers = [];
    private readonly MemberPermissionBorrowed[] borrowed;
    private ProxyPermissionRoot? root;
    private ProxyPermissionPlan? plan;
    private ProxyPermissionActor[] actors = [];
    private ProxyPermissionPolicy? policy, copiedPolicy;
    private ECDsa? ownedKey;
    private string revision = "policy-1", window = "";
    private int stage;
    private bool closed, closing, armed, settled, assigned, copied;
    private Task? delayed;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal ProxyPermissionProfile Profile { get; }
    internal InfisicalProxyPermissionFixtureSource Source { get; }
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    internal TaskCompletionSource OpenEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource OpenRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource DispatchEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource DispatchRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource CloseEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal int Originals { get; private set; }
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Generated => storageBindings.Count;
    internal int Registrations => root is not null && !closed ? 1 : 0;
    internal int Remaining => resources.Count + states.Count + collections.Count + credentials.Count + (policy is null ? 0 : 1) + (copiedPolicy is null ? 0 : 1) + (ownedKey is null ? 0 : 1);
    internal bool BorrowedPreserved => Borrowed().SequenceEqual(borrowed);
    internal InfisicalProxyPermissionFixture(string fault = "", bool retainIds = false)
    {
        Fault = fault; this.retainIds = retainIds;
        foreach (var journal in Enum.GetValues<ProxyPermissionJournal>()) writers.Add(journal, new(journal));
        Profile = new("controlled-proxy-configuration", "controlled-epoch", "controlled-v1", writers.Values.Select(w => w.Pin).ToArray());
        borrowed = Borrowed(); listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/"); Source = new(this); accept = AcceptAsync();
    }
    internal ProxyPermissionInput Input(string operation, ProxyPermissionAction action) =>
        new(new(new("https://proxy-source.invalid/"), "coordinator-token", "proxy-coordinator", 30), "proxy-capability", Profile,
            ProxyPermissionContract.Scope(operation), ProxyPermissionContract.ActorKind(operation), action, 30);
    internal NativeEnvironment Environment(string operation, ProxyPermissionAction action, bool configured = true)
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
                    proxyPermission = Input(operation, action)
                }
            }
        }, ProxyPermissionContract.Options)!;
        if (!configured) scope["scopes"]!["local"]!.AsObject().Remove("proxyPermission");
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
        }, ProxyPermissionContract.Options));
    }
    internal ProxyPermissionRoot Root(string operation, ProxyPermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization, operation,
            ProxyPermissionContract.Variant(action), boundary, "local", "proxy-coordinator", MemberPermissionSourceKind.ControlledFixture,
            ProxyPermissionContract.Scope(operation), ProxyPermissionContract.ActorKind(operation), action, Authorities, Profile);
    private MemberPermissionBorrowed[] Borrowed() => hostTokens.Select(p => new MemberPermissionBorrowed("host-credential", p.Key, ProxyPermissionContract.Hash(p.Value)))
        .Concat(writers.Values.Select(w => new MemberPermissionBorrowed("host-key", w.Pin.Writer, ProxyPermissionContract.Hash(w.Pin.Spki))))
        .Concat(borrowedObjects.Select(p => new MemberPermissionBorrowed(p.Value, p.Key, ProxyPermissionContract.Hash(p.Value)))).ToArray();
    private ProxyPermissionIssued Issued => new(actors, storageBindings.ToArray());
    private string Id(string key) => Issued.Id(key);
    private string CommitCreation(string key, string? request = null, bool admitted = false)
    {
        ProxyPermissionContract.Require(root is not null && plan is not null && !closed && (!closing || admitted) && !resources.ContainsKey(key) &&
            !storageBindings.Any(b => b.Intent == key));
        var intent = plan!.Intents.Single(i => i.Key == key);
        ProxyPermissionContract.Require(Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0));
        // There is deliberately no ID-generation path in Reserve or plan construction.
        string canonical = Guid.NewGuid().ToString();
        var binding = new ProxyPermissionBinding(key, ProxyPermissionContract.Hash(intent), intent.Work, intent.Kind, Id(intent.Scope),
            ProxyPermissionPlan.InputHash(intent, Id), canonical, request ?? Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"));
        issuanceBindings.Add(binding); storageBindings.Add(binding); resources.Add(key, new(key, canonical));
        return canonical;
    }
    private ProxyPermissionActor IssueActor(int i)
    {
        string key = plan!.ActorKey(i), scope = Id(plan.ActorScope(i)); var kind = plan.ActorKind(i);
        bool owned = !key.StartsWith("@", StringComparison.Ordinal);
        if (owned && Id(key).Length == 0) CommitCreation(key);
        string principal = Id(key); ProxyPermissionCredential credential; byte[] bytes;
        if (owned)
        {
            (credential, bytes) = IssueCredential("actor-credential-" + i, principal, kind, scope);
        }
        else
        {
            bytes = Encoding.UTF8.GetBytes(hostTokens[principal]);
            credential = new("host-" + principal, principal, kind, scope, ProxyPermissionContract.RawHash(bytes), false);
            CryptographicOperations.ZeroMemory(bytes); bytes = [];
            if (!credentials.Any(c => c.Id == credential.Id)) credentials.Add(credential);
        }
        CommitCreation(plan.ActorMembership(i));
        return new(principal, kind, scope, credential.Id, credential.Hash, bytes, owned);
    }
    private (ProxyPermissionCredential Credential, byte[] Bytes) IssueCredential(string key, string principal, MemberPermissionActorKind kind, string scope)
    {
        string id = CommitCreation(key);
        byte[] random = RandomNumberGenerator.GetBytes(32), bytes;
        try { bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(random)); } finally { CryptographicOperations.ZeroMemory(random); }
        privateBuffers.Add(bytes); Copies.Add(bytes);
        var credential = new ProxyPermissionCredential(id, principal, kind, scope, ProxyPermissionContract.RawHash(bytes), true);
        credentials.Add(credential); tokens.Add(Encoding.ASCII.GetString(bytes), credential); return (credential, bytes);
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
