using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecretKit.Infisical.Conformance.Tests;

// The coordinator has no signing primitive. Each subsystem owns its key, enrolled
// root, immutable serialized events, sequence and terminal head. Publish accepts
// only a root/step, never a coordinator-provided snapshot. Native deployments must
// enroll analogous taps under separate operational authority; offline keys cannot
// qualify that deployment obligation.
internal abstract class InfisicalSettingsPermissionJournal : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly List<byte[]> events = [];
    private readonly object admission = new();
    private int pending;
    private string rootHash = "", head = "";
    private long publications;
    protected SettingsPermissionRoot Root { get; private set; } = null!;
    protected SettingsPermissionPlan Plan { get; private set; } = null!;
    internal SettingsPermissionPin Pin { get; }
    internal bool Fenced { get; private set; }
    internal int Pending { get { lock (admission) return pending; } }
    internal InfisicalSettingsPermissionJournal(SettingsPermissionJournal journal) =>
        Pin = new(journal, journal + "-writer", journal + "-capture", "settings-history-v1", Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    internal void Enroll(SettingsPermissionRoot root)
    {
        SettingsPermissionContract.Require(rootHash.Length == 0);
        byte[] bytes = SettingsPermissionContract.Bytes(root);
        try { Root = JsonSerializer.Deserialize<SettingsPermissionRoot>(bytes, SettingsPermissionContract.Options)!; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        Plan = new(Root); rootHash = SettingsPermissionContract.Hash(Root); Append("enroll", rootHash);
    }
    protected void Append<T>(string kind, T value)
    {
        SettingsPermissionContract.Require(rootHash.Length != 0);
        var entry = new SettingsPermissionEvent(events.Count + 1, head, kind, JsonSerializer.SerializeToElement(value, SettingsPermissionContract.Options));
        head = SettingsPermissionContract.Hash(entry); events.Add(SettingsPermissionContract.Bytes(entry));
    }
    internal void Fence()
    {
        lock (admission) { SettingsPermissionContract.Require(pending == 0); Fenced = true; }
    }
    protected void Accept() { lock (admission) SettingsPermissionContract.Require(!Fenced); }
    protected IDisposable Admit()
    {
        lock (admission) { SettingsPermissionContract.Require(!Fenced); pending++; }
        return new Work(this);
    }
    private sealed class Work(InfisicalSettingsPermissionJournal owner) : IDisposable
    {
        private bool disposed;
        public void Dispose()
        {
            lock (owner.admission) { if (disposed) return; disposed = true; owner.pending--; }
        }
    }
    internal SettingsPermissionSigned Publish(SettingsPermissionRoot root, SettingsPermissionStep step)
    {
        SettingsPermissionContract.Require(rootHash == SettingsPermissionContract.Hash(root));
        var history = events.Select(b => JsonSerializer.Deserialize<SettingsPermissionEvent>(b, SettingsPermissionContract.Options)!).ToArray();
        var content = new SettingsPermissionPublication(rootHash, Pin.Journal, Pin.Writer, Pin.Channel, Pin.Schema,
            SettingsPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()), step, ++publications, history.Length, head,
            Pending == 0, Fenced, Pending, history);
        byte[] bytes = SettingsPermissionContract.Bytes(content);
        try { return new(content, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal byte[][] ReleaseCaptures()
    {
        SettingsPermissionContract.Require(Fenced);
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

internal sealed class InfisicalSettingsPermissionStorage(string fault) : InfisicalSettingsPermissionJournal(SettingsPermissionJournal.Storage)
{
    private readonly List<SettingsPermissionBinding> bindings = [];
    private readonly Dictionary<string, SettingsPermissionBinding> live = [];
    private readonly Dictionary<string, SettingsPermissionState> states = [];
    internal event Action<SettingsPermissionBinding>? Created;
    internal event Action<SettingsPermissionRetirement>? Retired;
    internal SettingsPermissionBinding[] Bindings => bindings.ToArray();
    internal SettingsPermissionState[] States => states.Values.ToArray();
    internal IDisposable AdmitStorage() => Admit();
    internal int Remaining => live.Count;
    internal string Id(string name) => name.StartsWith('@') ? name[1..] : bindings.SingleOrDefault(b => b.Intent == name)?.CanonicalId ?? "";
    internal SettingsPermissionBinding? Find(string id) => bindings.SingleOrDefault(b => b.CanonicalId == id);
    internal SettingsPermissionBinding Create(string name, string? request = null, string? requestInput = null)
    {
        Accept();
        var intent = Plan.Intents.Single(i => i.Key == name);
        SettingsPermissionContract.Require(intent.Kind != "credential" && Id(name).Length == 0 &&
            Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0));
        string input = SettingsPermissionPlan.InputHash(intent, Id);
        var binding = new SettingsPermissionBinding(name, SettingsPermissionContract.Hash(intent), intent.Kind, Id(intent.Scope),
            input, Guid.NewGuid().ToString(), request ?? "setup:" + Guid.NewGuid().ToString("N"), requestInput ?? input,
            Guid.NewGuid().ToString("N"), intent.Scope.StartsWith('@') ? Root.Id : bindings.Single(b => b.Intent == intent.Scope).Commit);
        Add(binding); return binding;
    }
    internal void ObserveIssuer(InfisicalSettingsPermissionIssuer issuer)
    {
        issuer.Created += binding =>
        {
            SettingsPermissionContract.Require(issuer.Find(binding.CanonicalId) == binding && binding.Kind == "credential");
            Add(binding);
        };
    }
    private void Add(SettingsPermissionBinding binding)
    {
        SettingsPermissionContract.Require(!bindings.Any(b => b.CanonicalId == binding.CanonicalId || b.Intent == binding.Intent));
        bindings.Add(binding); live.Add(binding.CanonicalId, binding); Append("bind", binding); Created?.Invoke(binding);
    }
    internal void Seed(string project, SettingsPermissionRequest? request = null)
    {
        Accept(); Create(project + "-env", request?.Id, request?.BodyHash);
        string name = project == SettingsPermissionPlan.CopyProject ? Plan.CopySlug : project == SettingsPermissionPlan.Project ? Plan.ProjectSlug : "other-" + Plan.ProjectSlug;
        var state = new SettingsPermissionState(Id(project), Root.Organization, name, name, "baseline " + Root.Nonce,
            "secret-manager", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 1,
            new(false, false, false, false, false, true, false, 30, 10, 3, "secret-manager", null, null, null,
                SettingsPermissionContract.Hash(Array.Empty<string>()), SettingsPermissionContract.Hash("owned-empty-workflows"),
                SettingsPermissionContract.Hash("owned-unselected-configuration"), Id(project + "-env"), "Development", "dev", 1.5,
                SettingsPermissionContract.Hash(Array.Empty<string>())));
        states.Add(state.Id, state);
        Append("change", new SettingsPermissionChange(request?.Id ?? "bootstrap", "", request?.BodyHash ?? "",
            Find(state.Id)!.Commit, null, state));
    }
    internal SettingsPermissionState Apply(SettingsPermissionRequest request, SettingsPermissionDecision decision,
        InfisicalSettingsPermissionIngress ingress, InfisicalSettingsPermissionAccess access, byte[] bytes)
    {
        Accept(); SettingsPermissionContract.Require(ingress.Contains(request) && access.Contains(decision) &&
            decision.Request == request.Id && decision.RequestHash == SettingsPermissionContract.Hash(request) &&
            request.BodyHash == SettingsPermissionContract.RawHash(bytes) && request.Path == "/api/v1/projects/" + decision.Project);
        using var body = JsonDocument.Parse(bytes); var input = body.RootElement;
        SettingsPermissionContract.Require(input.EnumerateObject().Select(p => p.Name).Order().SequenceEqual(new[] { "description", "name", "slug" }));
        var before = states[decision.Project];
        var intended = before with
        {
            Name = input.GetProperty("name").GetString()!,
            Slug = input.GetProperty("slug").GetString()!,
            Description = input.GetProperty("description").GetString()!,
            UpdatedAt = "2026-01-01T00:00:01Z",
            Revision = before.Revision + 1
        };
        bool apply = decision.Allowed;
        if (fault == "authorized-uncommitted") apply = false;
        if (fault == "unauthorized-commit") apply = true;
        var after = apply ? intended : before;
        if (apply) after = fault switch
        {
            "wrong-name" => after with { Name = "substituted" },
            "wrong-slug" => after with { Slug = "substituted" },
            "wrong-description" => after with { Description = "substituted" },
            "wrong-project" => after with { Id = Guid.NewGuid().ToString() },
            "unselected-change" => after with { Fixed = after.Fixed with { DeleteProtection = true } },
            "unprojected-change" => after with { Fixed = after.Fixed with { WorkflowHash = "substituted" } },
            "revision-change" => after with { Revision = after.Revision + 1 },
            _ => after
        };
        states[decision.Project] = after;
        Append("change", new SettingsPermissionChange(request.Id, SettingsPermissionContract.Hash(decision), request.BodyHash,
            apply ? Guid.NewGuid().ToString() : "", before, after));
        // A forged success body never changes independently persisted state.
        return fault == "authorized-uncommitted" && decision.Allowed ? intended : after;
    }
    internal void Copy(SettingsPermissionRequest request, SettingsPermissionPolicy template, JsonElement configuration,
        InfisicalSettingsPermissionPolicy policies, InfisicalSettingsPermissionMembership memberships, SettingsPermissionActor actor)
    {
        Accept();
        var environment = configuration.GetProperty("environments").EnumerateArray().Single();
        var user = configuration.GetProperty("users").EnumerateArray().Single();
        SettingsPermissionContract.Require(environment.GetProperty("name").GetString() == "Development" &&
            environment.GetProperty("slug").GetString() == "dev" && environment.GetProperty("position").GetDouble() == 1.5 &&
            user.GetProperty("username").GetString() == Plan.Username(0) && user.GetProperty("roles")[0].GetString() == Plan.Slug);
        var project = Create(SettingsPermissionPlan.CopyProject, request.Id, request.BodyHash);
        var role = Create(SettingsPermissionPlan.CopyPolicy, request.Id, request.BodyHash);
        var member = Create("copy-member", request.Id, request.BodyHash);
        var assignment = Create("copy-assignment", request.Id, request.BodyHash);
        Seed(SettingsPermissionPlan.CopyProject, request);
        policies.Copy(request, template, role.CanonicalId, project.CanonicalId);
        memberships.Assign(request.Id, new(member.CanonicalId, actor.Identity.Principal, actor.Identity.Kind, Root.Organization,
            project.CanonicalId, role.CanonicalId, Plan.Slug, true, "accepted", assignment.CanonicalId));
        Append("copy", new SettingsPermissionCopy(request.Id, template.Id, fault == "copy-configuration" ? "foreign" : template.Configuration,
            project.CanonicalId, role.CanonicalId, Id(SettingsPermissionPlan.CopyProject + "-env"), environment.GetProperty("name").GetString()!,
            environment.GetProperty("slug").GetString()!, fault == "copy-environment" ? 9.5 : environment.GetProperty("position").GetDouble(),
            member.CanonicalId, user.GetProperty("username").GetString()!, project.Commit));
    }
    internal void Clear()
    {
        SettingsPermissionContract.Require(Fenced);
        foreach (var binding in bindings.AsEnumerable().Reverse())
        {
            if (fault == "cleanup" && binding.Intent == SettingsPermissionPlan.Project) continue;
            live.Remove(binding.CanonicalId);
            var retired = new SettingsPermissionRetirement(binding.CanonicalId, SettingsPermissionContract.Hash(binding));
            Append("retire", retired); Retired?.Invoke(retired);
        }
        foreach (var state in states.Values) Append("change", new SettingsPermissionChange("cleanup", "", "", "", state, null));
        states.Clear();
    }
    public override void Dispose() { states.Clear(); live.Clear(); bindings.Clear(); base.Dispose(); }
}

internal sealed class InfisicalSettingsPermissionIssuer : InfisicalSettingsPermissionJournal
{
    private readonly InfisicalSettingsPermissionStorage storage;
    private readonly Dictionary<string, SettingsPermissionCredential> credentials = [];
    private readonly Dictionary<string, byte[]> material = [];
    private readonly Dictionary<string, SettingsPermissionBinding> bindings = [];
    internal event Action<SettingsPermissionBinding>? Created;
    internal IEnumerable<byte[]> Buffers => material.Values;
    internal InfisicalSettingsPermissionIssuer(InfisicalSettingsPermissionStorage storage) : base(SettingsPermissionJournal.Issuer)
    {
        this.storage = storage;
        storage.Created += b =>
        {
            SettingsPermissionContract.Require(storage.Find(b.CanonicalId) == b);
            if (bindings.ContainsKey(b.CanonicalId)) return; // The credential issuer already captured its own commit.
            bindings.Add(b.CanonicalId, b); Append("bind", b);
        };
        storage.Retired += r =>
        {
            SettingsPermissionContract.Require(bindings.TryGetValue(r.Id, out var b) && r.BindingHash == SettingsPermissionContract.Hash(b));
            if (material.TryGetValue(r.Id, out var bytes)) CryptographicOperations.ZeroMemory(bytes);
            credentials.Remove(r.Id); Append("retire", r);
        };
    }
    internal SettingsPermissionBinding? Find(string id) => bindings.GetValueOrDefault(id);
    internal IDisposable AdmitProvisioning() => Admit();
    internal SettingsPermissionCredential Host(string principal, string token)
    {
        Accept(); string id = "host-" + principal;
        if (credentials.TryGetValue(id, out var existing)) return existing;
        byte[] bytes = Encoding.ASCII.GetBytes(token);
        try
        {
            var c = new SettingsPermissionCredential(id, principal, MemberPermissionActorKind.Machine, Root.Organization,
                SettingsPermissionContract.RawHash(bytes), false);
            credentials.Add(id, c); Append("credential", c); return c;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal SettingsPermissionActor Issue(int actor)
    {
        Accept(); string principal = storage.Id(Plan.ActorKey(actor));
        var intent = Plan.Intents.Single(i => i.Key == "credential-" + actor);
        string input = SettingsPermissionPlan.InputHash(intent, storage.Id);
        var binding = new SettingsPermissionBinding(intent.Key, SettingsPermissionContract.Hash(intent), "credential",
            Root.Organization, input, Guid.NewGuid().ToString(), "setup:" + Guid.NewGuid().ToString("N"), input, Guid.NewGuid().ToString("N"), Root.Id);
        bindings.Add(binding.CanonicalId, binding); Append("bind", binding); Created?.Invoke(binding);
        byte[] random = RandomNumberGenerator.GetBytes(32), bytes;
        try { bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(random)); } finally { CryptographicOperations.ZeroMemory(random); }
        var c = new SettingsPermissionCredential(binding.CanonicalId, principal, Plan.ActorKind(actor), Root.Organization,
            SettingsPermissionContract.RawHash(bytes), true);
        credentials.Add(c.Id, c); material.Add(c.Id, bytes); Append("credential", c);
        return new(c, bytes);
    }
    internal SettingsPermissionCredential Authenticate(ReadOnlySpan<byte> bytes)
    {
        Accept(); string hash = SettingsPermissionContract.RawHash(bytes);
        return credentials.Values.Single(c => c.Hash == hash);
    }
    public override void Dispose()
    {
        foreach (var bytes in material.Values) CryptographicOperations.ZeroMemory(bytes);
        material.Clear(); credentials.Clear(); bindings.Clear(); base.Dispose();
    }
}

internal sealed class InfisicalSettingsPermissionOwnership : InfisicalSettingsPermissionJournal
{
    private SettingsPermissionOwner? baseline;
    internal InfisicalSettingsPermissionOwnership(InfisicalSettingsPermissionStorage storage) : base(SettingsPermissionJournal.Ownership)
    {
        storage.Created += binding => { SettingsPermissionContract.Require(storage.Find(binding.CanonicalId) == binding); Append("bind", binding); };
        storage.Retired += retired => Append("retire", retired);
    }
    internal void Reserve(MemberPermissionBorrowed[] borrowed)
    {
        SettingsPermissionContract.Require(baseline is null);
        baseline = new(Plan.Intents, borrowed, true); Append("reserve", baseline);
    }
    internal void Close(MemberPermissionBorrowed[] borrowed)
    {
        SettingsPermissionContract.Require(Fenced && baseline is not null);
        Append("close", baseline! with { Borrowed = borrowed });
    }
}

internal sealed class InfisicalSettingsPermissionIngress(InfisicalSettingsPermissionIssuer issuer)
    : InfisicalSettingsPermissionJournal(SettingsPermissionJournal.Ingress)
{
    private readonly Dictionary<string, SettingsPermissionRequest> requests = [];
    internal IDisposable AdmitDispatch() => Admit();
    internal SettingsPermissionRequest Capture(byte[] credential, string method, string path, byte[] body, string intent, string phase)
    {
        Accept(); var actor = issuer.Authenticate(credential);
        var request = new SettingsPermissionRequest(Guid.NewGuid().ToString("N"), actor.Principal, actor.Kind, actor.Id, actor.Hash,
            actor.Organization, method, path, SettingsPermissionContract.RawHash(body), intent, phase);
        requests.Add(request.Id, request); Append("request", request); return request;
    }
    internal bool Contains(SettingsPermissionRequest r) => requests.GetValueOrDefault(r.Id) == r;
    public override void Dispose() { requests.Clear(); base.Dispose(); }
}

internal sealed class InfisicalSettingsPermissionPolicy(InfisicalSettingsPermissionStorage storage, InfisicalSettingsPermissionIngress ingress, string fault)
    : InfisicalSettingsPermissionJournal(SettingsPermissionJournal.Policy)
{
    private readonly Dictionary<string, SettingsPermissionPolicy> policies = [];
    private JsonElement configuration;
    internal SettingsPermissionPolicy[] Inventory => policies.Values.ToArray();
    internal JsonElement Configuration => configuration;
    internal void Bootstrap(SettingsPermissionActor actor)
    {
        if (SettingsPermissionContract.Create(Root.Operation)) return;
        var binding = storage.Create(Plan.PolicyKey);
        Commit("bootstrap", new(binding.CanonicalId, "policy-1", actor.Identity.Principal, actor.Identity.Kind, Root.Organization,
            SettingsPermissionContract.Template(Root.Operation) ? "" : storage.Id(SettingsPermissionPlan.Project), "settings", ["read"], Plan.Slug, "bootstrap", ""));
    }
    internal void Apply(SettingsPermissionRequest r, byte[] bytes, SettingsPermissionActor actor)
    {
        Accept(); SettingsPermissionContract.Require(ingress.Contains(r) && r.BodyHash == SettingsPermissionContract.RawHash(bytes));
        using var document = JsonDocument.Parse(bytes); var body = document.RootElement;
        bool template = SettingsPermissionContract.Template(Root.Operation);
        var permission = (template ? body.GetProperty("roles")[0].GetProperty("permissions") : body.GetProperty("permissions")).EnumerateArray().Single();
        if (fault is "ignored-policy" or "lost-nonapplied") return;
        if (storage.Id(Plan.PolicyKey).Length == 0) storage.Create(Plan.PolicyKey, r.Id, r.BodyHash);
        var action = permission.GetProperty("action");
        string[] actions = action.ValueKind == JsonValueKind.Array ? action.EnumerateArray().Select(a => a.GetString()!).ToArray() : [action.GetString()!];
        var policy = new SettingsPermissionPolicy(storage.Id(Plan.PolicyKey), "policy-2", actor.Identity.Principal, actor.Identity.Kind,
            Root.Organization, template ? "" : storage.Id(SettingsPermissionPlan.Project), permission.GetProperty("subject").GetString()!,
            fault == "partial" ? [] : actions, Plan.Slug, r.BodyHash, "");
        if (permission.TryGetProperty("conditions", out _) || fault == "wrong-subject") policy = policy with { Subject = "workspace" };
        if (fault == "wrong-actor") policy = policy with { Actor = Root.Authorities.Observer };
        if (fault == "wrong-scope") policy = policy with { Project = storage.Id(SettingsPermissionPlan.OtherProject) };
        if (fault == "wrong-configuration") policy = policy with { Configuration = "foreign" };
        if (template) configuration = body.Clone();
        Commit(r.Id, policy);
    }
    internal void Copy(SettingsPermissionRequest r, SettingsPermissionPolicy template, string id, string project)
    {
        Accept(); SettingsPermissionContract.Require(ingress.Contains(r) && policies.GetValueOrDefault(template.Id) == template);
        Commit(r.Id, template with { Id = id, Project = project, Template = template.Id, Actions = fault == "copy-policy" ? [] : template.Actions });
    }
    private void Commit(string request, SettingsPermissionPolicy value)
    {
        var before = policies.GetValueOrDefault(value.Id);
        policies[value.Id] = value;
        Append("change", new SettingsPermissionPolicyChange(request, SettingsPermissionContract.Hash(before), before, value));
    }
    internal void Clear()
    {
        SettingsPermissionContract.Require(Fenced);
        foreach (var before in policies.Values) Append("change", new SettingsPermissionPolicyChange("cleanup", SettingsPermissionContract.Hash(before), before, null));
        policies.Clear(); configuration = default;
    }
    public override void Dispose() { policies.Clear(); configuration = default; base.Dispose(); }
}

internal sealed class InfisicalSettingsPermissionMembership : InfisicalSettingsPermissionJournal
{
    private readonly Dictionary<string, SettingsPermissionMember> members = [];
    internal InfisicalSettingsPermissionMembership() : base(SettingsPermissionJournal.Membership) { }
    internal SettingsPermissionMember[] Inventory => members.Values.ToArray();
    internal void Assign(string request, SettingsPermissionMember member)
    {
        Accept(); var before = members.GetValueOrDefault(member.Id); members[member.Id] = member;
        Append("change", new SettingsPermissionMemberChange(request, before, member));
    }
    internal void Clear()
    {
        SettingsPermissionContract.Require(Fenced);
        foreach (var before in members.Values) Append("change", new SettingsPermissionMemberChange("cleanup", before, null));
        members.Clear();
    }
    public override void Dispose() { members.Clear(); base.Dispose(); }
}

internal sealed class InfisicalSettingsPermissionAccess(InfisicalSettingsPermissionIngress ingress,
    InfisicalSettingsPermissionPolicy policies, InfisicalSettingsPermissionMembership memberships, string fault)
    : InfisicalSettingsPermissionJournal(SettingsPermissionJournal.Access)
{
    private readonly Dictionary<string, SettingsPermissionDecision> decisions = [];
    internal bool Contains(SettingsPermissionDecision d) => decisions.GetValueOrDefault(d.Request) == d;
    internal SettingsPermissionDecision Decide(SettingsPermissionRequest r, string project)
    {
        Accept(); SettingsPermissionContract.Require(ingress.Contains(r) && !decisions.ContainsKey(r.Id));
        var policy = policies.Inventory.SingleOrDefault(p => p.Project == project && p.Actor == r.Actor && p.Kind == r.Kind &&
            p.Organization == r.Organization && p.Subject == "settings" && p.Actions.SequenceEqual(["edit"]));
        var member = policy is null ? null : memberships.Inventory.SingleOrDefault(m => m.Project == project && m.Principal == r.Actor &&
            m.Kind == r.Kind && m.Organization == r.Organization && m.Role == policy.Id && m.Slug == policy.Role && m.Active && m.Status == "accepted");
        bool allowed = r.Phase == "patch" ? policy is not null && member is not null :
            r.Kind == MemberPermissionActorKind.Machine && r.Organization == Root.Organization &&
            r.Actor == (r.Phase == "original" ? Root.Authorities.Administrative : r.Phase == "observer" ? Root.Authorities.Observer : Root.Authorities.Setup);
        if (fault == "scope-leak" && r.Phase == "patch" && policies.Inventory.Any(p => p.Actor == r.Actor && p.Actions.Contains("edit"))) allowed = true;
        if (fault == "actor-leak" && r.Phase == "patch" && policies.Inventory.Any(p => p.Actions.Contains("edit"))) allowed = true;
        var decision = new SettingsPermissionDecision(r.Id, SettingsPermissionContract.Hash(r), r.CredentialHash,
            r.Organization, project, "settings", r.Phase == "patch" ? "edit" : r.Phase,
            policy is null ? "" : SettingsPermissionContract.Hash(policy), member is null ? "" : SettingsPermissionContract.Hash(member), allowed);
        if (fault == "wrong-credential" && r.Phase == "patch") decision = decision with { CredentialHash = "foreign" };
        decisions.Add(r.Id, decision); Append("decision", decision); return decision;
    }
    public override void Dispose() { decisions.Clear(); base.Dispose(); }
}
