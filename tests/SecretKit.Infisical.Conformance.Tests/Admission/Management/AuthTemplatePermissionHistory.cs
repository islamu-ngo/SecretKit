using System.Security.Cryptography;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Every publication contains the writer's whole history, including empty windows,
// intermediate revisions, retired credentials and deleted objects. A terminal
// signature commits the exact count, order and head. Prefix checks alone are not
// enough: joins below reject unmatched intermediate events even after lost Open.
internal sealed class AuthTemplatePermissionVerifier : IDisposable
{
    private readonly AuthTemplatePermissionRoot root;
    private readonly AuthTemplatePermissionPlan plan;
    private readonly Dictionary<AuthTemplatePermissionJournal, (AuthTemplatePermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<AuthTemplatePermissionJournal, AuthTemplatePermissionPublication> prior = [];
    private MemberPermissionBorrowed[]? borrowed;
    internal AuthTemplatePermissionBinding[] Bindings { get; private set; } = [];
    internal AuthTemplatePermissionCredential[] Credentials { get; private set; } = [];
    internal AuthTemplatePermissionState[] Inventory { get; private set; } = [];
    internal AuthTemplatePermissionPolicy[] Policies { get; private set; } = [];
    internal AuthTemplatePermissionMember[] Members { get; private set; } = [];
    internal AuthTemplatePermissionRequest[] Requests { get; private set; } = [];
    internal AuthTemplatePermissionDecision[] Decisions { get; private set; } = [];
    internal AuthTemplatePermissionChange[] Changes { get; private set; } = [];
    internal AuthTemplatePermissionPolicyChange[] PolicyChanges { get; private set; } = [];
    internal AuthTemplatePermissionCollection[] Collections { get; private set; } = [];
    internal AuthTemplatePermissionVerifier(AuthTemplatePermissionRoot root)
    {
        Validate(root.Profile); this.root = root; plan = new(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    internal static void Validate(AuthTemplatePermissionProfile profile)
    {
        Require(profile.Pins.Length == 8 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 8 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && MemberPermissionContract.Text(p.Writer) &&
                MemberPermissionContract.Text(p.Channel) && p.Schema == "auth-template-history-v1") &&
            profile.Pins.Select(p => p.Writer).Distinct().Count() == 8 && profile.Pins.Select(p => p.Channel).Distinct().Count() == 8 &&
            new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(MemberPermissionContract.Text));
        var hashes = new HashSet<string>();
        foreach (var pin in profile.Pins)
        {
            using var key = ECDsa.Create(); byte[] bytes = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(bytes, out int used);
            Require(used == bytes.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                hashes.Add(AuthTemplatePermissionContract.RawHash(key.ExportSubjectPublicKeyInfo())));
        }
    }
    internal void Check(AuthTemplatePermissionPacket packet, AuthTemplatePermissionStep step)
    {
        Require(packet.Journals.Length == 8 && packet.Journals.Select(j => j.Content.Journal).Distinct().Count() == 8);
        foreach (var signed in packet.Journals)
        {
            var p = signed.Content; Require(keys.ContainsKey(p.Journal));
            var (pin, key) = keys[p.Journal]; byte[] bytes = AuthTemplatePermissionContract.Bytes(p); bool valid;
            try { valid = key.VerifyData(bytes, Convert.FromBase64String(signed.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
            catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
            finally { CryptographicOperations.ZeroMemory(bytes); }
            Require(valid && p.RootHash == AuthTemplatePermissionContract.Hash(root) && p.Writer == pin.Writer && p.Channel == pin.Channel &&
                p.Schema == pin.Schema && p.KeyHash == AuthTemplatePermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
                p.Step == step && p.Terminal && p.Pending == 0 && p.Count == p.Events.Length && p.Events.Length > 0 &&
                (step != AuthTemplatePermissionStep.Close || p.Fenced));
            string head = "";
            for (int i = 0; i < p.Events.Length; i++)
            {
                var e = p.Events[i]; Require(e.Sequence == i + 1 && e.Previous == head && Allowed(p.Journal, e.Kind));
                head = AuthTemplatePermissionContract.Hash(e);
            }
            Require(p.Head == head && p.Events[0].Kind == "enroll" &&
                p.Events[0].Value.GetString() == AuthTemplatePermissionContract.Hash(root) &&
                p.Events.Count(e => e.Kind == "enroll") == 1);
            if (prior.TryGetValue(p.Journal, out var old))
                Require(p.Publication > old.Publication && p.Count >= old.Count &&
                    AuthTemplatePermissionContract.Hash(p.Events.Take(old.Count)) == AuthTemplatePermissionContract.Hash(old.Events));
        }
        CheckBindings(packet, step);
        CheckState(packet, step);
        CheckRequests(packet);
        foreach (var signed in packet.Journals) prior[signed.Content.Journal] = signed.Content;
    }
    private static bool Allowed(AuthTemplatePermissionJournal journal, string kind) => kind == "enroll" || journal switch
    {
        AuthTemplatePermissionJournal.Ownership => kind is "reserve" or "bind" or "retire" or "close",
        AuthTemplatePermissionJournal.Issuer => kind is "bind" or "credential" or "retire",
        AuthTemplatePermissionJournal.Storage => kind is "bind" or "change" or "retire",
        AuthTemplatePermissionJournal.Policy => kind is "change",
        AuthTemplatePermissionJournal.Membership => kind is "change",
        AuthTemplatePermissionJournal.Ingress => kind is "request",
        AuthTemplatePermissionJournal.Access => kind is "decision",
        AuthTemplatePermissionJournal.Collection => kind is "read",
        _ => false
    };
    private void CheckBindings(AuthTemplatePermissionPacket packet, AuthTemplatePermissionStep step)
    {
        var owners = packet.Values<AuthTemplatePermissionOwner>(AuthTemplatePermissionJournal.Ownership, "reserve");
        Require(owners.Length == 1);
        var owner = owners[0];
        Require(owner.Exclusive && AuthTemplatePermissionContract.Hash(owner.Intents) == AuthTemplatePermissionContract.Hash(plan.Intents) &&
            owner.Borrowed.Select(b => b.Id).Distinct().Count() == owner.Borrowed.Length &&
            (borrowed is null || owner.Borrowed.SequenceEqual(borrowed)));
        borrowed ??= owner.Borrowed.ToArray();
        var storage = packet.Values<AuthTemplatePermissionBinding>(AuthTemplatePermissionJournal.Storage, "bind");
        var issuer = packet.Values<AuthTemplatePermissionBinding>(AuthTemplatePermissionJournal.Issuer, "bind");
        var owned = packet.Values<AuthTemplatePermissionBinding>(AuthTemplatePermissionJournal.Ownership, "bind");
        Require(Same(storage, issuer) && Same(storage, owned) &&
            storage.Select(b => b.Intent).Distinct().Count() == storage.Length &&
            storage.Select(b => b.CanonicalId).Distinct().Count() == storage.Length &&
            storage.Select(b => b.Commit).Distinct().Count() == storage.Length);
        var resolved = new Dictionary<string, AuthTemplatePermissionBinding>();
        string Id(string key) => key.StartsWith('@') ? key[1..] : resolved.GetValueOrDefault(key)?.CanonicalId ?? "";
        foreach (var binding in storage)
        {
            var intent = plan.Intents.SingleOrDefault(i => i.Key == binding.Intent);
            Require(intent is not null && intent.Root == root.Id && intent.Nonce == root.Nonce &&
                binding.IntentHash == AuthTemplatePermissionContract.Hash(intent) && binding.Kind == intent.Kind &&
                Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0) &&
                binding.Scope == Id(intent.Scope) && binding.InputHash == AuthTemplatePermissionPlan.InputHash(intent, Id) &&
                binding.ParentCommit == (intent.Scope.StartsWith('@') ? root.Id : resolved[intent.Scope].Commit) &&
                Guid.TryParse(binding.CanonicalId, out _) && MemberPermissionContract.Text(binding.Request) &&
                MemberPermissionContract.Text(binding.RequestInputHash) && MemberPermissionContract.Text(binding.Commit) &&
                !owner.Borrowed.Any(b => b.Id == binding.CanonicalId));
            if (binding.Request.StartsWith("setup:", StringComparison.Ordinal)) Require(binding.RequestInputHash == binding.InputHash);
            resolved.Add(binding.Intent, binding);
        }
        Bindings = storage;
        var retired = packet.Values<AuthTemplatePermissionRetirement>(AuthTemplatePermissionJournal.Storage, "retire");
        Require(Same(retired, packet.Values<AuthTemplatePermissionRetirement>(AuthTemplatePermissionJournal.Issuer, "retire")) &&
            Same(retired, packet.Values<AuthTemplatePermissionRetirement>(AuthTemplatePermissionJournal.Ownership, "retire")) &&
            retired.Select(r => r.Id).Distinct().Count() == retired.Length &&
            retired.All(r => storage.Any(b => b.CanonicalId == r.Id && r.BindingHash == AuthTemplatePermissionContract.Hash(b))));
        var allCredentials = packet.Values<AuthTemplatePermissionCredential>(AuthTemplatePermissionJournal.Issuer, "credential");
        Require(allCredentials.Select(c => c.Id).Distinct().Count() == allCredentials.Length &&
            allCredentials.Select(c => c.Hash).Distinct().Count() == allCredentials.Length);
        foreach (var c in allCredentials.Where(c => c.Owned))
            Require(storage.Any(b => b.CanonicalId == c.Id && b.Kind == "credential") &&
                storage.Any(b => b.CanonicalId == c.Principal && b.Kind == (c.Kind == MemberPermissionActorKind.User ? "user" : "machine")));
        Credentials = allCredentials.Where(c => !retired.Any(r => r.Id == c.Id)).ToArray();
        if (step == AuthTemplatePermissionStep.Reserve) Require(storage.Length == 0 && allCredentials.Length == 0);
        if (step == AuthTemplatePermissionStep.Close)
        {
            Require(retired.Length == storage.Length && Credentials.All(c => !c.Owned));
            var closes = packet.Values<AuthTemplatePermissionOwner>(AuthTemplatePermissionJournal.Ownership, "close");
            Require(closes.Length == 1 && Same(owner, closes[0]));
        }
    }
    private void CheckState(AuthTemplatePermissionPacket packet, AuthTemplatePermissionStep step)
    {
        PolicyChanges = packet.Values<AuthTemplatePermissionPolicyChange>(AuthTemplatePermissionJournal.Policy, "change");
        Changes = packet.Values<AuthTemplatePermissionChange>(AuthTemplatePermissionJournal.Storage, "change");
        var policies = new Dictionary<string, AuthTemplatePermissionPolicy>();
        foreach (var c in PolicyChanges)
        {
            string id = c.After?.Id ?? c.Before?.Id ?? "";
            Require(id.Length > 0 && Same(policies.GetValueOrDefault(id), c.Before) && c.PreviousHash == AuthTemplatePermissionContract.Hash(c.Before));
            Require(c.Request != "bootstrap" || !AuthTemplatePermissionContract.Create(root.Operation) && c.Before is null && c.After!.Actions.Length == 0);
            Require(c.Request != "cleanup" || step == AuthTemplatePermissionStep.Close && c.After is null);
            if (c.After is null) policies.Remove(id); else policies[id] = c.After;
        }
        Policies = policies.Values.ToArray();
        var members = new Dictionary<string, AuthTemplatePermissionMember>();
        foreach (var c in packet.Values<AuthTemplatePermissionMemberChange>(AuthTemplatePermissionJournal.Membership, "change"))
        {
            string id = c.After?.Id ?? c.Before?.Id ?? "";
            Require(id.Length > 0 && members.GetValueOrDefault(id) == c.Before);
            Require(c.Request != "bootstrap" || c.Before is null && c.After!.Role == "");
            Require(c.Request != "cleanup" || step == AuthTemplatePermissionStep.Close && c.After is null);
            if (c.After is not null && c.After.Role.Length > 0)
                Require(Bindings.Any(b => b.CanonicalId == c.After.Assignment && b.Kind == "role-assignment" && b.Scope == c.After.Organization));
            if (c.After is null) members.Remove(id); else members[id] = c.After;
        }
        Members = members.Values.ToArray();
        var states = new Dictionary<string, AuthTemplatePermissionState>();
        foreach (var c in Changes)
        {
            Require(Same(states.GetValueOrDefault(c.Target), c.Before));
            if (c.Request == "bootstrap")
            {
                var b = Bindings.SingleOrDefault(b => b.CanonicalId == c.Target);
                Require(b is not null && b.Kind == "template" && b.Intent != AuthTemplatePermissionPlan.Created &&
                    c.Before is null && c.Commit == b.Commit && Same(c.After, plan.Initial(b.Intent, Id)));
            }
            if (c.Request == "cleanup") Require(step == AuthTemplatePermissionStep.Close && c.After is null);
            if (c.After is null) states.Remove(c.Target); else states[c.Target] = c.After;
        }
        Inventory = states.Values.ToArray();
        if (step == AuthTemplatePermissionStep.Close) Require(Inventory.Length == 0 && Policies.Length == 0 && Members.Length == 0);
    }
    private void CheckRequests(AuthTemplatePermissionPacket packet)
    {
        Requests = packet.Values<AuthTemplatePermissionRequest>(AuthTemplatePermissionJournal.Ingress, "request");
        Decisions = packet.Values<AuthTemplatePermissionDecision>(AuthTemplatePermissionJournal.Access, "decision");
        Collections = packet.Values<AuthTemplatePermissionCollection>(AuthTemplatePermissionJournal.Collection, "read");
        var members = packet.Values<AuthTemplatePermissionMemberChange>(AuthTemplatePermissionJournal.Membership, "change");
        var credentials = packet.Values<AuthTemplatePermissionCredential>(AuthTemplatePermissionJournal.Issuer, "credential");
        Require(Requests.Select(r => r.Id).Distinct().Count() == Requests.Length &&
            Requests.Select(r => r.Id).SequenceEqual(Decisions.Select(d => d.Request)) &&
            Requests.Where(r => r.Method == "GET").Select(r => r.Id).SequenceEqual(Collections.Select(c => c.Request)));
        var ps = new Dictionary<string, AuthTemplatePermissionPolicy>();
        var ms = new Dictionary<string, AuthTemplatePermissionMember>();
        var ss = new Dictionary<string, AuthTemplatePermissionState>();
        Apply("bootstrap");
        var usedPolicies = new List<AuthTemplatePermissionPolicyChange>(PolicyChanges.Where(c => c.Request == "bootstrap"));
        var usedMembers = new List<AuthTemplatePermissionMemberChange>(members.Where(c => c.Request == "bootstrap"));
        var usedChanges = new List<AuthTemplatePermissionChange>(Changes.Where(c => c.Request == "bootstrap"));
        foreach (var b in Bindings.Where(b => !b.Request.StartsWith("setup:", StringComparison.Ordinal)))
            Require(Requests.Any(r => r.Id == b.Request && r.BodyHash == b.RequestInputHash) && Decisions.Single(d => d.Request == b.Request).Allowed);
        for (int i = 0; i < Requests.Length; i++)
        {
            var r = Requests[i]; var d = Decisions[i];
            Require(d.RequestHash == AuthTemplatePermissionContract.Hash(r) && d.Request == r.Id && d.CredentialHash == r.CredentialHash &&
                d.Organization == r.Organization && credentials.Any(c => c.Id == r.CredentialId && c.Hash == r.CredentialHash &&
                    c.Principal == r.Actor && c.Kind == r.Kind && c.Organization == r.Organization));
            var pc = PolicyChanges.Where(c => c.Request == r.Id).ToArray();
            var mc = members.Where(c => c.Request == r.Id).ToArray();
            var sc = Changes.Where(c => c.Request == r.Id).ToArray();
            if (r.Phase is "original" or "activation" or "observer")
            {
                string actor = r.Phase == "original" ? root.Authorities.Administrative : r.Phase == "activation" ? root.Authorities.Setup : root.Authorities.Observer;
                Require(d.Action == r.Phase && d.Allowed == (r.Actor == actor && r.Kind == MemberPermissionActorKind.Machine && r.Organization == root.Organization));
                Require(sc.Length == 0);
                if (r.Phase == "original")
                {
                    Require(r.Path == "/api/v1/organization/roles" + (AuthTemplatePermissionContract.Create(root.Operation) ? "" : "/" + Id(AuthTemplatePermissionPlan.Policy)) &&
                        r.Method == (AuthTemplatePermissionContract.Create(root.Operation) ? "POST" : "PATCH") && r.IntentHash == r.BodyHash && mc.Length == 0 && pc.Length <= 1 && (d.Allowed || pc.Length == 0));
                    foreach (var c in pc) Require(c.After is not null && c.After.Configuration == r.BodyHash && c.After.Id == Id(AuthTemplatePermissionPlan.Policy));
                }
                else if (r.Phase == "activation")
                {
                    Require(d.Allowed && r.Method == "PATCH" && r.Path == "/api/v2/organizations/" + root.Organization + "/memberships/" + Id("member-0") && pc.Length == 0 && mc.Length == 1);
                    var p = ps.Values.SingleOrDefault(); var m = mc.Single().After;
                    Require(p is not null && m is not null && m.Role == p.Id && m.Slug == p.Slug && m.Principal == p.Actor && m.Kind == p.Kind && m.Organization == p.Organization);
                }
                else
                {
                    Require(r.Method == "GET" && r.BodyHash == AuthTemplatePermissionContract.RawHash([]) && pc.Length == 0 && mc.Length == 0);
                    string target = r.Path[(r.Path.LastIndexOf('/') + 1)..];
                    Require(r.Path == AuthTemplatePermissionContract.Path + "/" + target);
                    var state = ss.GetValueOrDefault(target);
                    CheckCollection(r, d, d.Allowed && state is not null && state.Organization == r.Organization ? [state] : []);
                }
            }
            else
            {
                Require(r.Phase is "template" or "template-get" or "template-usage" && pc.Length == 0 && mc.Length == 0);
                var action = AuthTemplatePermissionContract.Supported.SingleOrDefault(a => AuthTemplatePermissionContract.Wire(a) == d.Action);
                string expectedPath = r.Phase == "template" ? plan.RequestPath(action, Id) :
                    AuthTemplatePermissionContract.Path + "/" + Id(AuthTemplatePermissionPlan.Selected) + (r.Phase == "template-usage" ? "/usage" : "");
                Require(AuthTemplatePermissionContract.Wire(action) == d.Action && d.Subject == AuthTemplatePermissionContract.Subject &&
                    r.Method == AuthTemplatePermissionPlan.Method(action) && r.Path == expectedPath && r.BodyHash == plan.BodyHash(action) &&
                    (r.Phase == "template" || action == AuthTemplatePermissionAction.List));
                var policy = ps.Values.SingleOrDefault(p => p.Actor == r.Actor && p.Kind == r.Kind && p.Organization == r.Organization &&
                    p.Subject == d.Subject && p.Actions.Contains(d.Action));
                var member = policy is null ? null : ms.Values.SingleOrDefault(m => m.Principal == r.Actor && m.Kind == r.Kind &&
                    m.Organization == r.Organization && m.Role == policy.Id && m.Slug == policy.Slug && m.Active && m.Status == "accepted");
                Require(d.Allowed == (policy is not null && member is not null) && d.PolicyHash == (policy is null ? "" : AuthTemplatePermissionContract.Hash(policy)) &&
                    d.MembershipHash == (member is null ? "" : AuthTemplatePermissionContract.Hash(member)));
                if (r.Method == "GET")
                {
                    Require(sc.Length == 0);
                    var rows = ss.Values.Where(s => s.Organization == r.Organization && (action != AuthTemplatePermissionAction.Attach || s.Method == "kubernetes")).ToArray();
                    if (r.Phase != "template") rows = rows.Where(s => s.Id == Id(AuthTemplatePermissionPlan.Selected)).ToArray();
                    CheckCollection(r, d, d.Allowed ? rows : []);
                    if (d.Allowed) Require(rows.Any(s => s.Id == Id(AuthTemplatePermissionPlan.Selected)));
                }
                else
                {
                    Require(sc.Length == 1); var c = sc[0];
                    string target = action == AuthTemplatePermissionAction.Create ?
                        d.Allowed || ss.ContainsKey(Id(AuthTemplatePermissionPlan.Created)) ? Id(AuthTemplatePermissionPlan.Created) : "" :
                        Id(AuthTemplatePermissionPlan.Selected);
                    var before = ss.GetValueOrDefault(target);
                    AuthTemplatePermissionState? expected = !d.Allowed ? before : action switch
                    {
                        AuthTemplatePermissionAction.Create => plan.Initial(AuthTemplatePermissionPlan.Created, Id),
                        AuthTemplatePermissionAction.Edit => plan.Changed(before!),
                        AuthTemplatePermissionAction.Delete => null,
                        _ => throw new NativeCaseFailureException("observer-unavailable")
                    };
                    Require(c.Target == target && Same(c.Before, before) && Same(c.After, expected) &&
                        c.InputHash == r.BodyHash && c.DecisionHash == AuthTemplatePermissionContract.Hash(d) &&
                        (d.Allowed ? Guid.TryParse(c.Commit, out _) : c.Commit.Length == 0));
                    if (d.Allowed && action == AuthTemplatePermissionAction.Create)
                        Require(Bindings.Any(b => b.CanonicalId == target && b.Request == r.Id && b.RequestInputHash == r.BodyHash && b.Commit == c.Commit));
                }
            }
            Apply(r.Id); usedPolicies.AddRange(pc); usedMembers.AddRange(mc); usedChanges.AddRange(sc);
        }
        Require(Same(usedPolicies.ToArray(), PolicyChanges.Where(c => c.Request != "cleanup").ToArray()) &&
            Same(usedMembers.ToArray(), members.Where(c => c.Request != "cleanup").ToArray()) &&
            Same(usedChanges.ToArray(), Changes.Where(c => c.Request != "cleanup").ToArray()) &&
            Changes.Where(c => c.Commit.Length > 0).Select(c => c.Commit).Distinct().Count() == Changes.Count(c => c.Commit.Length > 0));
        void Apply(string request)
        {
            foreach (var c in PolicyChanges.Where(c => c.Request == request))
            {
                string id = c.After?.Id ?? c.Before!.Id; Require(Same(ps.GetValueOrDefault(id), c.Before));
                if (c.After is null) ps.Remove(id); else ps[id] = c.After;
            }
            foreach (var c in members.Where(c => c.Request == request))
            {
                string id = c.After?.Id ?? c.Before!.Id; Require(ms.GetValueOrDefault(id) == c.Before);
                if (c.After is null) ms.Remove(id); else ms[id] = c.After;
            }
            foreach (var c in Changes.Where(c => c.Request == request))
            {
                Require(Same(ss.GetValueOrDefault(c.Target), c.Before));
                if (c.After is null) ss.Remove(c.Target); else ss[c.Target] = c.After;
            }
        }
    }
    private void CheckCollection(AuthTemplatePermissionRequest r, AuthTemplatePermissionDecision d, AuthTemplatePermissionState[] expected)
    {
        var collection = Collections.Single(c => c.Request == r.Id);
        Require(collection.DecisionHash == AuthTemplatePermissionContract.Hash(d) && collection.Organization == r.Organization &&
            collection.Operation == r.Path && collection.Complete && Same(collection.Rows, expected));
    }
    private string Id(string key) => key.StartsWith('@') ? key[1..] : Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
    internal static bool Same<T>(T left, T right) => AuthTemplatePermissionContract.Hash(left) == AuthTemplatePermissionContract.Hash(right);
    private static void Require(bool condition) => AuthTemplatePermissionContract.Require(condition);
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
