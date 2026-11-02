using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecretKit.Infisical.Conformance.Tests;

// The coordinator has no signing primitive. Each subsystem owns its key, enrolled
// root, immutable serialized events, sequence and terminal head. Publish accepts
// only a root/step, never a coordinator-provided snapshot. Native deployments must
// enroll analogous taps under separate operational authority; offline keys cannot
// qualify that deployment obligation.
internal abstract class InfisicalIntegrationPermissionJournal : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly List<byte[]> events = [];
    private readonly object admission = new();
    private int pending;
    private string rootHash = "", head = "";
    private long publications;
    protected IntegrationPermissionRoot Root { get; private set; } = null!;
    protected IntegrationPermissionPlan Plan { get; private set; } = null!;
    internal IntegrationPermissionPin Pin { get; }
    internal bool Fenced { get; private set; }
    internal int Pending { get { lock (admission) return pending; } }
    internal InfisicalIntegrationPermissionJournal(IntegrationPermissionJournal journal) =>
        Pin = new(journal, journal + "-writer", journal + "-capture", "integration-history-v1", Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    internal void Enroll(IntegrationPermissionRoot root)
    {
        IntegrationPermissionContract.Require(rootHash.Length == 0);
        byte[] bytes = IntegrationPermissionContract.Bytes(root);
        try { Root = JsonSerializer.Deserialize<IntegrationPermissionRoot>(bytes, IntegrationPermissionContract.Options)!; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        Plan = new(Root); rootHash = IntegrationPermissionContract.Hash(Root); Append("enroll", rootHash);
    }
    protected void Append<T>(string kind, T value)
    {
        IntegrationPermissionContract.Require(rootHash.Length != 0);
        var entry = new IntegrationPermissionEvent(events.Count + 1, head, kind, JsonSerializer.SerializeToElement(value, IntegrationPermissionContract.Options));
        head = IntegrationPermissionContract.Hash(entry); events.Add(IntegrationPermissionContract.Bytes(entry));
    }
    internal void Fence()
    {
        lock (admission) { IntegrationPermissionContract.Require(pending == 0); Fenced = true; }
    }
    protected void Accept() { lock (admission) IntegrationPermissionContract.Require(!Fenced); }
    protected IDisposable Admit()
    {
        lock (admission) { IntegrationPermissionContract.Require(!Fenced); pending++; }
        return new Work(this);
    }
    private sealed class Work(InfisicalIntegrationPermissionJournal owner) : IDisposable
    {
        private bool disposed;
        public void Dispose()
        {
            lock (owner.admission) { if (disposed) return; disposed = true; owner.pending--; }
        }
    }
    internal IntegrationPermissionSigned Publish(IntegrationPermissionRoot root, IntegrationPermissionStep step)
    {
        IntegrationPermissionContract.Require(rootHash == IntegrationPermissionContract.Hash(root));
        var history = events.Select(b => JsonSerializer.Deserialize<IntegrationPermissionEvent>(b, IntegrationPermissionContract.Options)!).ToArray();
        var content = new IntegrationPermissionPublication(rootHash, Pin.Journal, Pin.Writer, Pin.Channel, Pin.Schema,
            IntegrationPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()), step, ++publications, history.Length, head,
            Pending == 0, Fenced, Pending, history);
        byte[] bytes = IntegrationPermissionContract.Bytes(content);
        try { return new(content, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal byte[][] ReleaseCaptures()
    {
        IntegrationPermissionContract.Require(Fenced);
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

internal sealed class InfisicalIntegrationPermissionStorage(string fault) : InfisicalIntegrationPermissionJournal(IntegrationPermissionJournal.Storage)
{
    private readonly List<IntegrationPermissionBinding> bindings = [];
    private readonly Dictionary<string, IntegrationPermissionBinding> live = [];
    private readonly List<IntegrationPermissionStored> rows = [];
    internal event Action<IntegrationPermissionBinding>? Created;
    internal event Action<IntegrationPermissionRetirement>? Retired;
    internal IntegrationPermissionBinding[] Bindings => bindings.ToArray();
    internal IntegrationPermissionStored[] Rows => rows.ToArray();
    internal int Remaining => live.Count;
    internal string Id(string name) => name.StartsWith('@') ? name[1..] : bindings.SingleOrDefault(b => b.Intent == name)?.CanonicalId ?? "";
    internal IntegrationPermissionBinding? Find(string id) => bindings.SingleOrDefault(b => b.CanonicalId == id);
    internal IntegrationPermissionBinding Create(string name, string? request = null, string? requestInput = null)
    {
        Accept();
        var intent = Plan.Intents.Single(i => i.Key == name);
        IntegrationPermissionContract.Require(intent.Kind != "credential" && Id(name).Length == 0 &&
            Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0));
        string input = IntegrationPermissionPlan.InputHash(intent, Id);
        var binding = new IntegrationPermissionBinding(name, IntegrationPermissionContract.Hash(intent), intent.Kind, Id(intent.Scope),
            input, Guid.NewGuid().ToString(), request ?? "setup:" + Guid.NewGuid().ToString("N"), requestInput ?? input,
            Guid.NewGuid().ToString("N"), intent.Scope.StartsWith('@') ? Root.Id : bindings.Single(b => b.Intent == intent.Scope).Commit);
        Add(binding); return binding;
    }
    internal void ObserveIssuer(InfisicalIntegrationPermissionIssuer issuer)
    {
        issuer.Created += binding =>
        {
            IntegrationPermissionContract.Require(issuer.Find(binding.CanonicalId) == binding && binding.Kind == "credential");
            Add(binding);
        };
    }
    private void Add(IntegrationPermissionBinding binding)
    {
        IntegrationPermissionContract.Require(!bindings.Any(b => b.CanonicalId == binding.CanonicalId || b.Intent == binding.Intent));
        bindings.Add(binding); live.Add(binding.CanonicalId, binding); Append("bind", binding); Created?.Invoke(binding);
    }
    internal void Seed(string project)
    {
        Accept(); Create(project + "-env"); Create(project + "-authorization");
        for (int i = 0; i < 2; i++)
        {
            Create(project + "-row-" + i);
            // Setup is authorized to provision metadata canaries. No SDK CRUD or
            // sync/delivery claim is invented by this private setup interface.
            var value = new IntegrationPermissionMetadata(Id(project + "-row-" + i), i == 0, "controlled-metadata-" + i,
                Id(project + "-authorization"), Id(project + "-env"), "Development", "dev",
                "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z",
                i == 0 ? "https://metadata.invalid/" + Root.Nonce : null, i == 0 ? "app-" + Root.Nonce : null,
                i == 0 ? "app-id" : null, i == 0 ? "preview" : null, i == 0 ? "target-env" : null,
                i == 0 ? "service" : null, i == 0 ? "service-id" : null, i == 0 ? "owner" : null,
                i == 0 ? "/metadata" : null, i == 0 ? "region" : null, i == 0 ? "scope" : null,
                i == 0 ? "/secrets" : null, i == 0 ? "2026-01-01T00:00:02Z" : null, i == 0 ? "unqualified-job" : null, i == 0 ? false : null);
            if (fault == "metadata-storage" && i == 0) value = value with { TargetServiceId = "substituted" };
            var row = new IntegrationPermissionStored(Root.Organization, Id(project), value);
            rows.Add(row); Append("row", row);
        }
    }
    internal void Copy(IntegrationPermissionRequest request, IntegrationPermissionPolicy template, JsonElement configuration,
        InfisicalIntegrationPermissionPolicy policies, InfisicalIntegrationPermissionMembership memberships, IntegrationPermissionActor actor)
    {
        Accept();
        var environment = configuration.GetProperty("environments").EnumerateArray().Single();
        var user = configuration.GetProperty("users").EnumerateArray().Single();
        IntegrationPermissionContract.Require(environment.GetProperty("name").GetString() == "Development" &&
            environment.GetProperty("slug").GetString() == "dev" && environment.GetProperty("position").GetDouble() == 1.5 &&
            user.GetProperty("username").GetString() == Plan.Username(0) && user.GetProperty("roles")[0].GetString() == Plan.Slug);
        var project = Create(IntegrationPermissionPlan.CopyProject, request.Id, request.BodyHash);
        var role = Create(IntegrationPermissionPlan.CopyPolicy, request.Id, request.BodyHash);
        var member = Create("copy-member", request.Id, request.BodyHash);
        var assignment = Create("copy-assignment", request.Id, request.BodyHash);
        Seed(IntegrationPermissionPlan.CopyProject);
        policies.Copy(request, template, role.CanonicalId, project.CanonicalId);
        memberships.Assign(request.Id, new(member.CanonicalId, actor.Identity.Principal, actor.Identity.Kind, Root.Organization,
            project.CanonicalId, role.CanonicalId, Plan.Slug, true, "accepted", assignment.CanonicalId));
        Append("copy", new IntegrationPermissionCopy(request.Id, template.Id, fault == "copy-configuration" ? "foreign" : template.Configuration,
            project.CanonicalId, role.CanonicalId, Id(IntegrationPermissionPlan.CopyProject + "-env"), environment.GetProperty("name").GetString()!,
            environment.GetProperty("slug").GetString()!, fault == "copy-environment" ? 9.5 : environment.GetProperty("position").GetDouble(),
            member.CanonicalId, user.GetProperty("username").GetString()!, project.Commit));
    }
    internal void Clear()
    {
        IntegrationPermissionContract.Require(Fenced);
        foreach (var binding in bindings.AsEnumerable().Reverse())
        {
            if (fault == "cleanup" && binding.Intent == IntegrationPermissionPlan.Project) continue;
            live.Remove(binding.CanonicalId);
            var retired = new IntegrationPermissionRetirement(binding.CanonicalId, IntegrationPermissionContract.Hash(binding));
            Append("retire", retired); Retired?.Invoke(retired);
        }
        rows.Clear();
    }
    public override void Dispose() { rows.Clear(); live.Clear(); bindings.Clear(); base.Dispose(); }
}

internal sealed class InfisicalIntegrationPermissionIssuer : InfisicalIntegrationPermissionJournal
{
    private readonly InfisicalIntegrationPermissionStorage storage;
    private readonly Dictionary<string, IntegrationPermissionCredential> credentials = [];
    private readonly Dictionary<string, byte[]> material = [];
    private readonly Dictionary<string, IntegrationPermissionBinding> bindings = [];
    internal event Action<IntegrationPermissionBinding>? Created;
    internal IEnumerable<byte[]> Buffers => material.Values;
    internal InfisicalIntegrationPermissionIssuer(InfisicalIntegrationPermissionStorage storage) : base(IntegrationPermissionJournal.Issuer)
    {
        this.storage = storage;
        storage.Created += b =>
        {
            IntegrationPermissionContract.Require(storage.Find(b.CanonicalId) == b);
            if (bindings.ContainsKey(b.CanonicalId)) return; // The credential issuer already captured its own commit.
            bindings.Add(b.CanonicalId, b); Append("bind", b);
        };
        storage.Retired += r =>
        {
            IntegrationPermissionContract.Require(bindings.TryGetValue(r.Id, out var b) && r.BindingHash == IntegrationPermissionContract.Hash(b));
            if (material.TryGetValue(r.Id, out var bytes)) CryptographicOperations.ZeroMemory(bytes);
            credentials.Remove(r.Id); Append("retire", r);
        };
    }
    internal IntegrationPermissionBinding? Find(string id) => bindings.GetValueOrDefault(id);
    internal IDisposable AdmitProvisioning() => Admit();
    internal IntegrationPermissionCredential Host(string principal, string token)
    {
        Accept(); string id = "host-" + principal;
        if (credentials.TryGetValue(id, out var existing)) return existing;
        byte[] bytes = Encoding.ASCII.GetBytes(token);
        try
        {
            var c = new IntegrationPermissionCredential(id, principal, MemberPermissionActorKind.Machine, Root.Organization,
                IntegrationPermissionContract.RawHash(bytes), false);
            credentials.Add(id, c); Append("credential", c); return c;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal IntegrationPermissionActor Issue(int actor)
    {
        Accept(); string principal = storage.Id(Plan.ActorKey(actor));
        var intent = Plan.Intents.Single(i => i.Key == "credential-" + actor);
        string input = IntegrationPermissionPlan.InputHash(intent, storage.Id);
        var binding = new IntegrationPermissionBinding(intent.Key, IntegrationPermissionContract.Hash(intent), "credential",
            Root.Organization, input, Guid.NewGuid().ToString(), "setup:" + Guid.NewGuid().ToString("N"), input, Guid.NewGuid().ToString("N"), Root.Id);
        bindings.Add(binding.CanonicalId, binding); Append("bind", binding); Created?.Invoke(binding);
        byte[] random = RandomNumberGenerator.GetBytes(32), bytes;
        try { bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(random)); } finally { CryptographicOperations.ZeroMemory(random); }
        var c = new IntegrationPermissionCredential(binding.CanonicalId, principal, Plan.ActorKind(actor), Root.Organization,
            IntegrationPermissionContract.RawHash(bytes), true);
        credentials.Add(c.Id, c); material.Add(c.Id, bytes); Append("credential", c);
        return new(c, bytes);
    }
    internal IntegrationPermissionCredential Authenticate(ReadOnlySpan<byte> bytes)
    {
        Accept(); string hash = IntegrationPermissionContract.RawHash(bytes);
        return credentials.Values.Single(c => c.Hash == hash);
    }
    public override void Dispose()
    {
        foreach (var bytes in material.Values) CryptographicOperations.ZeroMemory(bytes);
        material.Clear(); credentials.Clear(); bindings.Clear(); base.Dispose();
    }
}

internal sealed class InfisicalIntegrationPermissionOwnership : InfisicalIntegrationPermissionJournal
{
    private IntegrationPermissionOwner? baseline;
    internal InfisicalIntegrationPermissionOwnership(InfisicalIntegrationPermissionStorage storage) : base(IntegrationPermissionJournal.Ownership)
    {
        storage.Created += binding => { IntegrationPermissionContract.Require(storage.Find(binding.CanonicalId) == binding); Append("bind", binding); };
        storage.Retired += retired => Append("retire", retired);
    }
    internal void Reserve(MemberPermissionBorrowed[] borrowed)
    {
        IntegrationPermissionContract.Require(baseline is null);
        baseline = new(Plan.Intents, borrowed, true); Append("reserve", baseline);
    }
    internal void Close(MemberPermissionBorrowed[] borrowed)
    {
        IntegrationPermissionContract.Require(Fenced && baseline is not null);
        Append("close", baseline! with { Borrowed = borrowed });
    }
}

internal sealed class InfisicalIntegrationPermissionIngress(InfisicalIntegrationPermissionIssuer issuer)
    : InfisicalIntegrationPermissionJournal(IntegrationPermissionJournal.Ingress)
{
    private readonly Dictionary<string, IntegrationPermissionRequest> requests = [];
    internal IDisposable AdmitDispatch() => Admit();
    internal IntegrationPermissionRequest Capture(byte[] credential, string method, string path, byte[] body, string intent, string phase)
    {
        Accept(); var actor = issuer.Authenticate(credential);
        var request = new IntegrationPermissionRequest(Guid.NewGuid().ToString("N"), actor.Principal, actor.Kind, actor.Id, actor.Hash,
            actor.Organization, method, path, IntegrationPermissionContract.RawHash(body), intent, phase);
        requests.Add(request.Id, request); Append("request", request); return request;
    }
    internal bool Contains(IntegrationPermissionRequest r) => requests.GetValueOrDefault(r.Id) == r;
    public override void Dispose() { requests.Clear(); base.Dispose(); }
}

internal sealed class InfisicalIntegrationPermissionPolicy(InfisicalIntegrationPermissionStorage storage, InfisicalIntegrationPermissionIngress ingress, string fault)
    : InfisicalIntegrationPermissionJournal(IntegrationPermissionJournal.Policy)
{
    private readonly Dictionary<string, IntegrationPermissionPolicy> policies = [];
    private JsonElement configuration;
    internal IntegrationPermissionPolicy[] Inventory => policies.Values.ToArray();
    internal JsonElement Configuration => configuration;
    internal void Bootstrap(IntegrationPermissionActor actor)
    {
        if (IntegrationPermissionContract.Create(Root.Operation)) return;
        var binding = storage.Create(Plan.PolicyKey);
        Commit("bootstrap", new(binding.CanonicalId, "policy-1", actor.Identity.Principal, actor.Identity.Kind, Root.Organization,
            IntegrationPermissionContract.Template(Root.Operation) ? "" : storage.Id(IntegrationPermissionPlan.Project), "integrations", ["edit"], Plan.Slug, "bootstrap", ""));
    }
    internal void Apply(IntegrationPermissionRequest r, byte[] bytes, IntegrationPermissionActor actor)
    {
        Accept(); IntegrationPermissionContract.Require(ingress.Contains(r) && r.BodyHash == IntegrationPermissionContract.RawHash(bytes));
        using var document = JsonDocument.Parse(bytes); var body = document.RootElement;
        bool template = IntegrationPermissionContract.Template(Root.Operation);
        var permission = (template ? body.GetProperty("roles")[0].GetProperty("permissions") : body.GetProperty("permissions")).EnumerateArray().Single();
        if (fault is "ignored-policy" or "lost-nonapplied") return;
        if (storage.Id(Plan.PolicyKey).Length == 0) storage.Create(Plan.PolicyKey, r.Id, r.BodyHash);
        var action = permission.GetProperty("action");
        string[] actions = action.ValueKind == JsonValueKind.Array ? action.EnumerateArray().Select(a => a.GetString()!).ToArray() : [action.GetString()!];
        var policy = new IntegrationPermissionPolicy(storage.Id(Plan.PolicyKey), "policy-2", actor.Identity.Principal, actor.Identity.Kind,
            Root.Organization, template ? "" : storage.Id(IntegrationPermissionPlan.Project), permission.GetProperty("subject").GetString()!,
            fault == "partial" ? [] : actions, Plan.Slug, r.BodyHash, "");
        if (permission.TryGetProperty("conditions", out _) || fault == "wrong-subject") policy = policy with { Subject = "not-integrations" };
        if (fault == "wrong-actor") policy = policy with { Actor = Root.Authorities.Observer };
        if (fault == "wrong-scope") policy = policy with { Project = storage.Id(IntegrationPermissionPlan.OtherProject) };
        if (fault == "wrong-configuration") policy = policy with { Configuration = "foreign" };
        if (template) configuration = body.Clone();
        Commit(r.Id, policy);
    }
    internal void Copy(IntegrationPermissionRequest r, IntegrationPermissionPolicy template, string id, string project)
    {
        Accept(); IntegrationPermissionContract.Require(ingress.Contains(r) && policies.GetValueOrDefault(template.Id) == template);
        Commit(r.Id, template with { Id = id, Project = project, Template = template.Id, Actions = fault == "copy-policy" ? [] : template.Actions });
    }
    private void Commit(string request, IntegrationPermissionPolicy value)
    {
        var before = policies.GetValueOrDefault(value.Id);
        policies[value.Id] = value;
        Append("change", new IntegrationPermissionPolicyChange(request, IntegrationPermissionContract.Hash(before), before, value));
    }
    internal void Clear()
    {
        IntegrationPermissionContract.Require(Fenced);
        foreach (var before in policies.Values) Append("change", new IntegrationPermissionPolicyChange("cleanup", IntegrationPermissionContract.Hash(before), before, null));
        policies.Clear(); configuration = default;
    }
    public override void Dispose() { policies.Clear(); configuration = default; base.Dispose(); }
}

internal sealed class InfisicalIntegrationPermissionMembership : InfisicalIntegrationPermissionJournal
{
    private readonly Dictionary<string, IntegrationPermissionMember> members = [];
    internal InfisicalIntegrationPermissionMembership() : base(IntegrationPermissionJournal.Membership) { }
    internal IntegrationPermissionMember[] Inventory => members.Values.ToArray();
    internal void Assign(string request, IntegrationPermissionMember member)
    {
        Accept(); var before = members.GetValueOrDefault(member.Id); members[member.Id] = member;
        Append("change", new IntegrationPermissionMemberChange(request, before, member));
    }
    internal void Clear()
    {
        IntegrationPermissionContract.Require(Fenced);
        foreach (var before in members.Values) Append("change", new IntegrationPermissionMemberChange("cleanup", before, null));
        members.Clear();
    }
    public override void Dispose() { members.Clear(); base.Dispose(); }
}

internal sealed class InfisicalIntegrationPermissionAccess(InfisicalIntegrationPermissionIngress ingress,
    InfisicalIntegrationPermissionPolicy policies, InfisicalIntegrationPermissionMembership memberships, string fault)
    : InfisicalIntegrationPermissionJournal(IntegrationPermissionJournal.Access)
{
    private readonly Dictionary<string, IntegrationPermissionDecision> decisions = [];
    internal bool Contains(IntegrationPermissionDecision d) => decisions.GetValueOrDefault(d.Request) == d;
    internal IntegrationPermissionDecision Decide(IntegrationPermissionRequest r, string project)
    {
        Accept(); IntegrationPermissionContract.Require(ingress.Contains(r) && !decisions.ContainsKey(r.Id));
        var policy = policies.Inventory.SingleOrDefault(p => p.Project == project && p.Actor == r.Actor && p.Kind == r.Kind &&
            p.Organization == r.Organization && p.Subject == "integrations" && p.Actions.SequenceEqual(["read"]));
        var member = policy is null ? null : memberships.Inventory.SingleOrDefault(m => m.Project == project && m.Principal == r.Actor &&
            m.Kind == r.Kind && m.Organization == r.Organization && m.Role == policy.Id && m.Slug == policy.Role && m.Active && m.Status == "accepted");
        bool allowed = r.Phase == "read" ? policy is not null && member is not null :
            r.Kind == MemberPermissionActorKind.Machine && r.Organization == Root.Organization &&
            r.Actor == (r.Phase == "original" ? Root.Authorities.Administrative : Root.Authorities.Setup);
        if (fault == "scope-leak" && r.Phase == "read" && policies.Inventory.Any(p => p.Actor == r.Actor && p.Actions.Contains("read"))) allowed = true;
        if (fault == "actor-leak" && r.Phase == "read" && policies.Inventory.Any(p => p.Actions.Contains("read"))) allowed = true;
        var decision = new IntegrationPermissionDecision(r.Id, IntegrationPermissionContract.Hash(r), r.CredentialHash,
            r.Organization, project, "integrations", r.Phase == "read" ? "read" : r.Phase,
            policy is null ? "" : IntegrationPermissionContract.Hash(policy), member is null ? "" : IntegrationPermissionContract.Hash(member), allowed);
        if (fault == "wrong-credential" && r.Phase == "read") decision = decision with { CredentialHash = "foreign" };
        decisions.Add(r.Id, decision); Append("decision", decision); return decision;
    }
    public override void Dispose() { decisions.Clear(); base.Dispose(); }
}

internal sealed class InfisicalIntegrationPermissionCollection(InfisicalIntegrationPermissionStorage storage,
    InfisicalIntegrationPermissionAccess access, string fault) : InfisicalIntegrationPermissionJournal(IntegrationPermissionJournal.Collection)
{
    private readonly HashSet<string> requests = [];
    internal IntegrationPermissionCollection Read(IntegrationPermissionDecision decision)
    {
        Accept(); IntegrationPermissionContract.Require(access.Contains(decision) && requests.Add(decision.Request));
        var rows = decision.Allowed ? storage.Rows.Where(r => r.Project == decision.Project && r.Organization == decision.Organization).Select(r => r.Value).ToArray() : [];
        if (decision.Allowed)
        {
            if (fault == "missing-row") rows = rows.Skip(1).ToArray();
            if (fault == "duplicate-row") rows = [.. rows, rows[0]];
            if (fault == "reordered-row") Array.Reverse(rows);
            if (fault == "foreign-row") rows[0] = storage.Rows.First(r => r.Project != decision.Project).Value;
            if (fault == "optional-field") rows[0] = rows[0] with { LastSyncJobId = null };
        }
        var result = new IntegrationPermissionCollection(decision.Request, IntegrationPermissionContract.Hash(decision),
            decision.Organization, decision.Project, fault != "incomplete", rows);
        Append("read", result); return result;
    }
    public override void Dispose() { requests.Clear(); base.Dispose(); }
}
