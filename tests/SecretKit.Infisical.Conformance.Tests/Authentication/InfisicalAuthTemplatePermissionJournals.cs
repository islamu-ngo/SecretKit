using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecretKit.Infisical.Conformance.Tests;

// The coordinator has no signing primitive. Each subsystem owns its key, enrolled
// root, immutable serialized events, sequence and terminal head. Publish accepts
// only a root/step, never a coordinator-provided snapshot. Native deployments must
// enroll analogous taps under separate operational authority; offline keys cannot
// qualify that deployment obligation.
internal abstract class InfisicalAuthTemplatePermissionJournal : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly List<byte[]> events = [];
    private readonly object admission = new();
    private int pending;
    private string rootHash = "", head = "";
    private long publications;
    protected AuthTemplatePermissionRoot Root { get; private set; } = null!;
    protected AuthTemplatePermissionPlan Plan { get; private set; } = null!;
    internal AuthTemplatePermissionPin Pin { get; }
    internal bool Fenced { get; private set; }
    internal int Pending { get { lock (admission) return pending; } }
    internal InfisicalAuthTemplatePermissionJournal(AuthTemplatePermissionJournal journal) =>
        Pin = new(journal, journal + "-writer", journal + "-capture", "auth-template-history-v1", Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    internal void Enroll(AuthTemplatePermissionRoot root)
    {
        AuthTemplatePermissionContract.Require(rootHash.Length == 0);
        byte[] bytes = AuthTemplatePermissionContract.Bytes(root);
        try { Root = JsonSerializer.Deserialize<AuthTemplatePermissionRoot>(bytes, AuthTemplatePermissionContract.Options)!; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        Plan = new(Root); rootHash = AuthTemplatePermissionContract.Hash(Root); Append("enroll", rootHash);
    }
    protected void Append<T>(string kind, T value)
    {
        AuthTemplatePermissionContract.Require(rootHash.Length != 0);
        var entry = new AuthTemplatePermissionEvent(events.Count + 1, head, kind, JsonSerializer.SerializeToElement(value, AuthTemplatePermissionContract.Options));
        head = AuthTemplatePermissionContract.Hash(entry); events.Add(AuthTemplatePermissionContract.Bytes(entry));
    }
    internal void Fence()
    {
        lock (admission) { AuthTemplatePermissionContract.Require(pending == 0); Fenced = true; }
    }
    protected void Accept() { lock (admission) AuthTemplatePermissionContract.Require(!Fenced); }
    protected IDisposable Admit()
    {
        lock (admission) { AuthTemplatePermissionContract.Require(!Fenced); pending++; }
        return new Work(this);
    }
    private sealed class Work(InfisicalAuthTemplatePermissionJournal owner) : IDisposable
    {
        private bool disposed;
        public void Dispose()
        {
            lock (owner.admission) { if (disposed) return; disposed = true; owner.pending--; }
        }
    }
    internal AuthTemplatePermissionSigned Publish(AuthTemplatePermissionRoot root, AuthTemplatePermissionStep step)
    {
        AuthTemplatePermissionContract.Require(rootHash == AuthTemplatePermissionContract.Hash(root));
        var history = events.Select(b => JsonSerializer.Deserialize<AuthTemplatePermissionEvent>(b, AuthTemplatePermissionContract.Options)!).ToArray();
        var content = new AuthTemplatePermissionPublication(rootHash, Pin.Journal, Pin.Writer, Pin.Channel, Pin.Schema,
            AuthTemplatePermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()), step, ++publications, history.Length, head,
            Pending == 0, Fenced, Pending, history);
        byte[] bytes = AuthTemplatePermissionContract.Bytes(content);
        try { return new(content, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal byte[][] ReleaseCaptures()
    {
        AuthTemplatePermissionContract.Require(Fenced);
        var buffers = events.ToArray();
        foreach (var bytes in buffers) CryptographicOperations.ZeroMemory(bytes);
        events.Clear(); return buffers;
    }
    public virtual void Dispose()
    {
        foreach (var bytes in events) CryptographicOperations.ZeroMemory(bytes);
        events.Clear(); key.Dispose();
    }
}

internal sealed class InfisicalAuthTemplatePermissionStorage(string fault) : InfisicalAuthTemplatePermissionJournal(AuthTemplatePermissionJournal.Storage)
{
    private readonly List<AuthTemplatePermissionBinding> bindings = [];
    private readonly Dictionary<string, AuthTemplatePermissionBinding> live = [];
    private readonly Dictionary<string, AuthTemplatePermissionState> states = [];
    internal event Action<AuthTemplatePermissionBinding>? Created;
    internal event Action<AuthTemplatePermissionRetirement>? Retired;
    internal AuthTemplatePermissionBinding[] Bindings => bindings.ToArray();
    internal AuthTemplatePermissionState[] States => states.Values.ToArray();
    internal int Remaining => live.Count;
    internal IDisposable AdmitStorage() => Admit();
    internal string Id(string name) => name.StartsWith('@') ? name[1..] : bindings.SingleOrDefault(b => b.Intent == name)?.CanonicalId ?? "";
    internal AuthTemplatePermissionBinding? Find(string id) => bindings.SingleOrDefault(b => b.CanonicalId == id);
    internal AuthTemplatePermissionBinding Create(string name, string? request = null, string? raw = null)
    {
        Accept(); var intent = Plan.Intents.Single(i => i.Key == name);
        AuthTemplatePermissionContract.Require(intent.Kind != "credential" && Id(name).Length == 0 && Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0));
        string input = AuthTemplatePermissionPlan.InputHash(intent, Id);
        var binding = new AuthTemplatePermissionBinding(name, AuthTemplatePermissionContract.Hash(intent), intent.Kind, Id(intent.Scope), input,
            Guid.NewGuid().ToString(), request ?? "setup:" + Guid.NewGuid().ToString("N"), raw ?? input, Guid.NewGuid().ToString("N"),
            intent.Scope.StartsWith('@') ? Root.Id : bindings.Single(b => b.Intent == intent.Scope).Commit);
        Add(binding); return binding;
    }
    internal void ObserveIssuer(InfisicalAuthTemplatePermissionIssuer issuer)
    {
        issuer.Created += binding => { AuthTemplatePermissionContract.Require(issuer.Find(binding.CanonicalId) == binding && binding.Kind == "credential"); Add(binding); };
    }
    private void Add(AuthTemplatePermissionBinding binding)
    {
        AuthTemplatePermissionContract.Require(!bindings.Any(b => b.CanonicalId == binding.CanonicalId || b.Intent == binding.Intent));
        bindings.Add(binding); live.Add(binding.CanonicalId, binding); Append("bind", binding); Created?.Invoke(binding);
    }
    internal void Seed(string name)
    {
        Accept(); var b = Create(name);
        var state = new AuthTemplatePermissionState(b.CanonicalId, b.Scope, Plan.Name(name), "kubernetes", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 1,
            new("api", "https://kubernetes.example.invalid", "", false, "baseline", false, "", null, null));
        states.Add(state.Id, state); Append("change", new AuthTemplatePermissionChange("bootstrap", "", "", b.Commit, state.Id, null, state));
    }
    internal AuthTemplatePermissionState? Apply(AuthTemplatePermissionRequest r, AuthTemplatePermissionDecision d,
        InfisicalAuthTemplatePermissionIngress ingress, InfisicalAuthTemplatePermissionAccess access, byte[] bytes)
    {
        Accept(); AuthTemplatePermissionContract.Require(ingress.Contains(r) && access.Contains(d) && d.Request == r.Id && r.BodyHash == AuthTemplatePermissionContract.RawHash(bytes));
        bool create = r.Method == "POST", edit = r.Method == "PATCH";
        string target = create ? Id(AuthTemplatePermissionPlan.Created) : Id(AuthTemplatePermissionPlan.Selected);
        var before = states.GetValueOrDefault(target); AuthTemplatePermissionState? intended = before;
        bool apply = d.Allowed && fault != "authorized-uncommitted" || fault == "unauthorized-commit" && !d.Allowed;
        if (create && (d.Allowed || apply))
        {
            using var document = JsonDocument.Parse(bytes); var body = document.RootElement; var fields = body.GetProperty("templateFields");
            if (target.Length == 0) target = Create(AuthTemplatePermissionPlan.Created, r.Id, r.BodyHash).CanonicalId;
            intended = new(target, r.Organization, body.GetProperty("name").GetString()!, body.GetProperty("authMethod").GetString()!,
                "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 1, new(fields.GetProperty("tokenReviewMode").GetString()!,
                    fields.GetProperty("kubernetesHost").GetString()!, fields.GetProperty("caCert").GetString()!, fields.GetProperty("verifyTlsCertificate").GetBoolean(),
                    fields.GetProperty("allowedAudience").GetString()!, false, "", null, null));
        }
        else if (edit && before is not null)
        {
            using var document = JsonDocument.Parse(bytes); var body = document.RootElement;
            intended = before with
            {
                Name = body.GetProperty("name").GetString()!,
                UpdatedAt = "2026-01-01T00:00:01Z",
                Revision = before.Revision + 1,
                Configuration = before.Configuration with { Audience = body.GetProperty("templateFields").GetProperty("allowedAudience").GetString()! }
            };
        }
        else if (!create && !edit) intended = null;
        var after = apply ? intended : before;
        if (apply && fault == "wrong-state") after = intended is null ? before : intended with { Name = "substituted" };
        if (after is null) states.Remove(target); else states[target] = after;
        Append("change", new AuthTemplatePermissionChange(r.Id, AuthTemplatePermissionContract.Hash(d), r.BodyHash,
            apply ? create ? Find(target)!.Commit : Guid.NewGuid().ToString() : "", target, before, after));
        if (d.Allowed && fault == "peer-change")
        {
            var peer = states[Id(AuthTemplatePermissionPlan.Peer)]; var changed = peer with { Name = "collateral" }; states[peer.Id] = changed;
            Append("change", new AuthTemplatePermissionChange(r.Id, AuthTemplatePermissionContract.Hash(d), r.BodyHash, Guid.NewGuid().ToString(), peer.Id, peer, changed));
        }
        return fault == "authorized-uncommitted" ? intended : after;
    }
    internal void Clear()
    {
        AuthTemplatePermissionContract.Require(Fenced);
        foreach (var b in bindings.AsEnumerable().Reverse())
        {
            if (fault == "cleanup" && b.Intent == AuthTemplatePermissionPlan.OtherOrganization) continue;
            live.Remove(b.CanonicalId); var retired = new AuthTemplatePermissionRetirement(b.CanonicalId, AuthTemplatePermissionContract.Hash(b));
            Append("retire", retired); Retired?.Invoke(retired);
        }
        foreach (var state in states.Values) Append("change", new AuthTemplatePermissionChange("cleanup", "", "", "", state.Id, state, null));
        states.Clear();
    }
    public override void Dispose() { states.Clear(); live.Clear(); bindings.Clear(); base.Dispose(); }
}

internal sealed class InfisicalAuthTemplatePermissionIssuer : InfisicalAuthTemplatePermissionJournal
{
    private readonly InfisicalAuthTemplatePermissionStorage storage;
    private readonly Dictionary<string, AuthTemplatePermissionCredential> credentials = [];
    private readonly Dictionary<string, byte[]> material = [];
    private readonly Dictionary<string, AuthTemplatePermissionBinding> bindings = [];
    internal event Action<AuthTemplatePermissionBinding>? Created;
    internal IEnumerable<byte[]> Buffers => material.Values;
    internal InfisicalAuthTemplatePermissionIssuer(InfisicalAuthTemplatePermissionStorage storage) : base(AuthTemplatePermissionJournal.Issuer)
    {
        this.storage = storage;
        storage.Created += b =>
        {
            AuthTemplatePermissionContract.Require(storage.Find(b.CanonicalId) == b);
            if (bindings.ContainsKey(b.CanonicalId)) return; // The credential issuer already captured its own commit.
            bindings.Add(b.CanonicalId, b); Append("bind", b);
        };
        storage.Retired += r =>
        {
            AuthTemplatePermissionContract.Require(bindings.TryGetValue(r.Id, out var b) && r.BindingHash == AuthTemplatePermissionContract.Hash(b));
            if (material.TryGetValue(r.Id, out var bytes)) CryptographicOperations.ZeroMemory(bytes);
            credentials.Remove(r.Id); Append("retire", r);
        };
    }
    internal AuthTemplatePermissionBinding? Find(string id) => bindings.GetValueOrDefault(id);
    internal IDisposable AdmitProvisioning() => Admit();
    internal AuthTemplatePermissionCredential Host(string principal, string token)
    {
        Accept(); string id = "host-" + principal;
        if (credentials.TryGetValue(id, out var existing)) return existing;
        byte[] bytes = Encoding.ASCII.GetBytes(token);
        try
        {
            var c = new AuthTemplatePermissionCredential(id, principal, MemberPermissionActorKind.Machine, Root.Organization,
                AuthTemplatePermissionContract.RawHash(bytes), false);
            credentials.Add(id, c); Append("credential", c); return c;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal AuthTemplatePermissionActor Issue(int actor)
    {
        Accept(); string principal = storage.Id(Plan.ActorKey(actor));
        var intent = Plan.Intents.Single(i => i.Key == "credential-" + actor);
        string input = AuthTemplatePermissionPlan.InputHash(intent, storage.Id);
        var binding = new AuthTemplatePermissionBinding(intent.Key, AuthTemplatePermissionContract.Hash(intent), "credential",
            storage.Id(Plan.OrganizationKey(actor)), input, Guid.NewGuid().ToString(), "setup:" + Guid.NewGuid().ToString("N"), input, Guid.NewGuid().ToString("N"), intent.Scope.StartsWith('@') ? Root.Id : storage.Find(storage.Id(intent.Scope))!.Commit);
        bindings.Add(binding.CanonicalId, binding); Append("bind", binding); Created?.Invoke(binding);
        byte[] random = RandomNumberGenerator.GetBytes(32), bytes;
        try { bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(random)); } finally { CryptographicOperations.ZeroMemory(random); }
        var c = new AuthTemplatePermissionCredential(binding.CanonicalId, principal, Plan.ActorKind(actor), storage.Id(Plan.OrganizationKey(actor)),
            AuthTemplatePermissionContract.RawHash(bytes), true);
        credentials.Add(c.Id, c); material.Add(c.Id, bytes); Append("credential", c);
        return new(c, bytes);
    }
    internal AuthTemplatePermissionCredential Authenticate(ReadOnlySpan<byte> bytes)
    {
        Accept(); string hash = AuthTemplatePermissionContract.RawHash(bytes);
        return credentials.Values.Single(c => c.Hash == hash);
    }
    public override void Dispose()
    {
        foreach (var bytes in material.Values) CryptographicOperations.ZeroMemory(bytes);
        material.Clear(); credentials.Clear(); bindings.Clear(); base.Dispose();
    }
}

internal sealed class InfisicalAuthTemplatePermissionOwnership : InfisicalAuthTemplatePermissionJournal
{
    private AuthTemplatePermissionOwner? baseline;
    internal InfisicalAuthTemplatePermissionOwnership(InfisicalAuthTemplatePermissionStorage storage) : base(AuthTemplatePermissionJournal.Ownership)
    {
        storage.Created += binding => { AuthTemplatePermissionContract.Require(storage.Find(binding.CanonicalId) == binding); Append("bind", binding); };
        storage.Retired += retired => Append("retire", retired);
    }
    internal void Reserve(MemberPermissionBorrowed[] borrowed)
    {
        AuthTemplatePermissionContract.Require(baseline is null);
        baseline = new(Plan.Intents, borrowed, true); Append("reserve", baseline);
    }
    internal void Close(MemberPermissionBorrowed[] borrowed)
    {
        AuthTemplatePermissionContract.Require(Fenced && baseline is not null);
        Append("close", baseline! with { Borrowed = borrowed });
    }
}

internal sealed class InfisicalAuthTemplatePermissionIngress(InfisicalAuthTemplatePermissionIssuer issuer)
    : InfisicalAuthTemplatePermissionJournal(AuthTemplatePermissionJournal.Ingress)
{
    private readonly Dictionary<string, AuthTemplatePermissionRequest> requests = [];
    internal IDisposable AdmitDispatch() => Admit();
    internal AuthTemplatePermissionRequest Capture(byte[] credential, string method, string path, byte[] body, string intent, string phase)
    {
        Accept(); var actor = issuer.Authenticate(credential);
        var request = new AuthTemplatePermissionRequest(Guid.NewGuid().ToString("N"), actor.Principal, actor.Kind, actor.Id, actor.Hash,
            actor.Organization, method, path, AuthTemplatePermissionContract.RawHash(body), intent, phase);
        requests.Add(request.Id, request); Append("request", request); return request;
    }
    internal bool Contains(AuthTemplatePermissionRequest r) => requests.GetValueOrDefault(r.Id) == r;
    public override void Dispose() { requests.Clear(); base.Dispose(); }
}

internal sealed class InfisicalAuthTemplatePermissionMembership : InfisicalAuthTemplatePermissionJournal
{
    private readonly Dictionary<string, AuthTemplatePermissionMember> members = [];
    internal InfisicalAuthTemplatePermissionMembership() : base(AuthTemplatePermissionJournal.Membership) { }
    internal AuthTemplatePermissionMember[] Inventory => members.Values.ToArray();
    internal void Assign(string request, AuthTemplatePermissionMember member)
    {
        Accept(); var before = members.GetValueOrDefault(member.Id); members[member.Id] = member;
        Append("change", new AuthTemplatePermissionMemberChange(request, before, member));
    }
    internal void Clear()
    {
        AuthTemplatePermissionContract.Require(Fenced);
        foreach (var before in members.Values) Append("change", new AuthTemplatePermissionMemberChange("cleanup", before, null));
        members.Clear();
    }
    public override void Dispose() { members.Clear(); base.Dispose(); }
}
