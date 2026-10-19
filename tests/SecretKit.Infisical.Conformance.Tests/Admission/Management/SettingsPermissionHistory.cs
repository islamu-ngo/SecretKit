using System.Security.Cryptography;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Every publication contains the writer's whole history, including empty windows,
// intermediate revisions, retired credentials and deleted objects. A terminal
// signature commits the exact count, order and head. Prefix checks alone are not
// enough: joins below reject unmatched intermediate events even after lost Open.
internal sealed class SettingsPermissionVerifier : IDisposable
{
    private readonly SettingsPermissionRoot root;
    private readonly SettingsPermissionPlan plan;
    private readonly Dictionary<SettingsPermissionJournal, (SettingsPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<SettingsPermissionJournal, SettingsPermissionPublication> prior = [];
    private MemberPermissionBorrowed[]? borrowed;
    internal SettingsPermissionBinding[] Bindings { get; private set; } = [];
    internal SettingsPermissionCredential[] Credentials { get; private set; } = [];
    internal SettingsPermissionState[] Inventory { get; private set; } = [];
    internal SettingsPermissionPolicy[] Policies { get; private set; } = [];
    internal SettingsPermissionMember[] Members { get; private set; } = [];
    internal SettingsPermissionRequest[] Requests { get; private set; } = [];
    internal SettingsPermissionDecision[] Decisions { get; private set; } = [];
    internal SettingsPermissionChange[] Changes { get; private set; } = [];
    internal SettingsPermissionPolicyChange[] PolicyChanges { get; private set; } = [];
    internal SettingsPermissionCopy[] Copies { get; private set; } = [];
    internal SettingsPermissionVerifier(SettingsPermissionRoot root)
    {
        Validate(root.Profile); this.root = root; plan = new(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    internal static void Validate(SettingsPermissionProfile profile)
    {
        Require(profile.Pins.Length == 7 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 7 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && MemberPermissionContract.Text(p.Writer) &&
                MemberPermissionContract.Text(p.Channel) && p.Schema == "settings-history-v1") &&
            profile.Pins.Select(p => p.Writer).Distinct().Count() == 7 && profile.Pins.Select(p => p.Channel).Distinct().Count() == 7 &&
            new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(MemberPermissionContract.Text));
        var hashes = new HashSet<string>();
        foreach (var pin in profile.Pins)
        {
            using var key = ECDsa.Create(); byte[] bytes = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(bytes, out int used);
            Require(used == bytes.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                hashes.Add(SettingsPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo())));
        }
    }
    internal void Check(SettingsPermissionPacket packet, SettingsPermissionStep step)
    {
        Require(packet.Journals.Length == 7 && packet.Journals.Select(j => j.Content.Journal).Distinct().Count() == 7);
        foreach (var signed in packet.Journals)
        {
            var p = signed.Content; Require(keys.ContainsKey(p.Journal));
            var (pin, key) = keys[p.Journal]; byte[] bytes = SettingsPermissionContract.Bytes(p); bool valid;
            try { valid = key.VerifyData(bytes, Convert.FromBase64String(signed.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
            catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
            finally { CryptographicOperations.ZeroMemory(bytes); }
            Require(valid && p.RootHash == SettingsPermissionContract.Hash(root) && p.Writer == pin.Writer && p.Channel == pin.Channel &&
                p.Schema == pin.Schema && p.KeyHash == SettingsPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
                p.Step == step && p.Terminal && p.Pending == 0 && p.Count == p.Events.Length && p.Events.Length > 0 &&
                (step != SettingsPermissionStep.Close || p.Fenced));
            string head = "";
            for (int i = 0; i < p.Events.Length; i++)
            {
                var e = p.Events[i]; Require(e.Sequence == i + 1 && e.Previous == head && Allowed(p.Journal, e.Kind));
                head = SettingsPermissionContract.Hash(e);
            }
            Require(p.Head == head && p.Events[0].Kind == "enroll" &&
                p.Events[0].Value.GetString() == SettingsPermissionContract.Hash(root) &&
                p.Events.Count(e => e.Kind == "enroll") == 1);
            if (prior.TryGetValue(p.Journal, out var old))
                Require(p.Publication > old.Publication && p.Count >= old.Count &&
                    SettingsPermissionContract.Hash(p.Events.Take(old.Count)) == SettingsPermissionContract.Hash(old.Events));
        }
        CheckBindings(packet, step);
        CheckState(packet, step);
        CheckRequests(packet);
        foreach (var signed in packet.Journals) prior[signed.Content.Journal] = signed.Content;
    }
    private static bool Allowed(SettingsPermissionJournal journal, string kind) => kind == "enroll" || journal switch
    {
        SettingsPermissionJournal.Ownership => kind is "reserve" or "bind" or "retire" or "close",
        SettingsPermissionJournal.Issuer => kind is "bind" or "credential" or "retire",
        SettingsPermissionJournal.Storage => kind is "bind" or "change" or "copy" or "retire",
        SettingsPermissionJournal.Policy => kind is "change",
        SettingsPermissionJournal.Membership => kind is "change",
        SettingsPermissionJournal.Ingress => kind is "request",
        SettingsPermissionJournal.Access => kind is "decision",
        _ => false
    };
    private void CheckBindings(SettingsPermissionPacket packet, SettingsPermissionStep step)
    {
        var owners = packet.Values<SettingsPermissionOwner>(SettingsPermissionJournal.Ownership, "reserve");
        Require(owners.Length == 1);
        var owner = owners[0];
        Require(owner.Exclusive && SettingsPermissionContract.Hash(owner.Intents) == SettingsPermissionContract.Hash(plan.Intents) &&
            owner.Borrowed.Select(b => b.Id).Distinct().Count() == owner.Borrowed.Length &&
            (borrowed is null || owner.Borrowed.SequenceEqual(borrowed)));
        borrowed ??= owner.Borrowed.ToArray();
        var storage = packet.Values<SettingsPermissionBinding>(SettingsPermissionJournal.Storage, "bind");
        var issuer = packet.Values<SettingsPermissionBinding>(SettingsPermissionJournal.Issuer, "bind");
        var owned = packet.Values<SettingsPermissionBinding>(SettingsPermissionJournal.Ownership, "bind");
        Require(Same(storage, issuer) && Same(storage, owned) &&
            storage.Select(b => b.Intent).Distinct().Count() == storage.Length &&
            storage.Select(b => b.CanonicalId).Distinct().Count() == storage.Length &&
            storage.Select(b => b.Commit).Distinct().Count() == storage.Length);
        var resolved = new Dictionary<string, SettingsPermissionBinding>();
        string Id(string key) => key.StartsWith('@') ? key[1..] : resolved.GetValueOrDefault(key)?.CanonicalId ?? "";
        foreach (var binding in storage)
        {
            var intent = plan.Intents.SingleOrDefault(i => i.Key == binding.Intent);
            Require(intent is not null && intent.Root == root.Id && intent.Nonce == root.Nonce &&
                binding.IntentHash == SettingsPermissionContract.Hash(intent) && binding.Kind == intent.Kind &&
                Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0) &&
                binding.Scope == Id(intent.Scope) && binding.InputHash == SettingsPermissionPlan.InputHash(intent, Id) &&
                binding.ParentCommit == (intent.Scope.StartsWith('@') ? root.Id : resolved[intent.Scope].Commit) &&
                Guid.TryParse(binding.CanonicalId, out _) && MemberPermissionContract.Text(binding.Request) &&
                MemberPermissionContract.Text(binding.RequestInputHash) && MemberPermissionContract.Text(binding.Commit) &&
                !owner.Borrowed.Any(b => b.Id == binding.CanonicalId));
            if (binding.Request.StartsWith("setup:", StringComparison.Ordinal)) Require(binding.RequestInputHash == binding.InputHash);
            resolved.Add(binding.Intent, binding);
        }
        Bindings = storage;
        var retired = packet.Values<SettingsPermissionRetirement>(SettingsPermissionJournal.Storage, "retire");
        Require(Same(retired, packet.Values<SettingsPermissionRetirement>(SettingsPermissionJournal.Issuer, "retire")) &&
            Same(retired, packet.Values<SettingsPermissionRetirement>(SettingsPermissionJournal.Ownership, "retire")) &&
            retired.Select(r => r.Id).Distinct().Count() == retired.Length &&
            retired.All(r => storage.Any(b => b.CanonicalId == r.Id && r.BindingHash == SettingsPermissionContract.Hash(b))));
        var allCredentials = packet.Values<SettingsPermissionCredential>(SettingsPermissionJournal.Issuer, "credential");
        Require(allCredentials.Select(c => c.Id).Distinct().Count() == allCredentials.Length &&
            allCredentials.Select(c => c.Hash).Distinct().Count() == allCredentials.Length);
        foreach (var c in allCredentials.Where(c => c.Owned))
            Require(storage.Any(b => b.CanonicalId == c.Id && b.Kind == "credential") &&
                storage.Any(b => b.CanonicalId == c.Principal && b.Kind == (c.Kind == MemberPermissionActorKind.User ? "user" : "machine")));
        Credentials = allCredentials.Where(c => !retired.Any(r => r.Id == c.Id)).ToArray();
        if (step == SettingsPermissionStep.Reserve) Require(storage.Length == 0 && allCredentials.Length == 0);
        if (step == SettingsPermissionStep.Close)
        {
            Require(retired.Length == storage.Length && Credentials.All(c => !c.Owned));
            var closes = packet.Values<SettingsPermissionOwner>(SettingsPermissionJournal.Ownership, "close");
            Require(closes.Length == 1 && Same(owner, closes[0]));
        }
    }
    private void CheckState(SettingsPermissionPacket packet, SettingsPermissionStep step)
    {
        var policies = new Dictionary<string, SettingsPermissionPolicy>();
        PolicyChanges = packet.Values<SettingsPermissionPolicyChange>(SettingsPermissionJournal.Policy, "change");
        Require(PolicyChanges.Count(c => c.Request == "bootstrap") <= 1 &&
            PolicyChanges.Where(c => c.Request == "bootstrap").All(c => !SettingsPermissionContract.Create(root.Operation) && c.Before is null && c.After?.Revision == "policy-1") &&
            PolicyChanges.Where(c => c.Request == "cleanup").All(c => step == SettingsPermissionStep.Close && c.After is null));
        foreach (var change in PolicyChanges)
        {
            string id = change.After?.Id ?? change.Before?.Id ?? "";
            Require(id.Length > 0 && Same(policies.GetValueOrDefault(id), change.Before) &&
                change.PreviousHash == SettingsPermissionContract.Hash(change.Before));
            if (change.After is null) policies.Remove(id); else policies[id] = change.After;
        }
        Policies = policies.Values.ToArray();
        var members = new Dictionary<string, SettingsPermissionMember>();
        foreach (var change in packet.Values<SettingsPermissionMemberChange>(SettingsPermissionJournal.Membership, "change"))
        {
            Require(change.Request != "bootstrap" || change.Before is null);
            Require(change.Request != "cleanup" || step == SettingsPermissionStep.Close && change.After is null);
            string id = change.After?.Id ?? change.Before?.Id ?? "";
            Require(id.Length > 0 && members.GetValueOrDefault(id) == change.Before);
            if (change.After is null) members.Remove(id); else members[id] = change.After;
        }
        Members = members.Values.ToArray();
        foreach (var member in packet.Values<SettingsPermissionMemberChange>(SettingsPermissionJournal.Membership, "change")
            .Select(c => c.After).OfType<SettingsPermissionMember>().Where(m => m.Kind == MemberPermissionActorKind.User && m.Role.Length > 0))
            Require(Bindings.Any(b => b.CanonicalId == member.Assignment && b.Kind == "role-assignment" && b.Scope == member.Project));
        var retired = packet.Values<SettingsPermissionRetirement>(SettingsPermissionJournal.Storage, "retire").Select(r => r.Id).ToHashSet();
        Changes = packet.Values<SettingsPermissionChange>(SettingsPermissionJournal.Storage, "change");
        var states = new Dictionary<string, SettingsPermissionState>();
        foreach (var change in Changes)
        {
            string id = change.After?.Id ?? change.Before?.Id ?? "";
            Require(id.Length > 0 && Same(states.GetValueOrDefault(id), change.Before));
            if (change.Before is null)
            {
                var binding = Bindings.SingleOrDefault(b => b.CanonicalId == id);
                Require(binding is not null && binding.Kind == "project" && change.Commit == binding.Commit &&
                    (change.Request == "bootstrap" ? binding.Request.StartsWith("setup:", StringComparison.Ordinal) : binding.Request == change.Request));
                string Id(string key) => key.StartsWith('@') ? key[1..] : Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
                Require(Same(change.After, plan.Initial(binding!.Intent, Id)));
            }
            if (change.After is null) Require(change.Request == "cleanup" && step == SettingsPermissionStep.Close);
            if (change.After is null) states.Remove(id); else states[id] = change.After;
        }
        Inventory = states.Values.ToArray();
        Require(Inventory.All(s => !retired.Contains(s.Id)));
        Copies = packet.Values<SettingsPermissionCopy>(SettingsPermissionJournal.Storage, "copy");
        Require(Copies.Length <= 1);
        foreach (var copy in Copies)
        {
            var template = PolicyChanges.Select(c => c.After).OfType<SettingsPermissionPolicy>().SingleOrDefault(p => p.Id == copy.Template && p.Configuration == copy.Configuration);
            var project = Bindings.SingleOrDefault(b => b.CanonicalId == copy.Project);
            Require(template is not null && template.Subject == "settings" && template.Actions.SequenceEqual(["edit"]) &&
                project is not null && project.Intent == SettingsPermissionPlan.CopyProject && project.Request == copy.Request &&
                copy.ParentCommit == project.Commit && copy.Username == plan.Username(0) &&
                copy.EnvironmentName == "Development" && copy.EnvironmentSlug == "dev" && copy.EnvironmentPosition == 1.5 &&
                Bindings.Any(b => b.CanonicalId == copy.Environment && b.Intent == SettingsPermissionPlan.CopyProject + "-env") &&
                PolicyChanges.Any(c => c.Request == copy.Request && c.After is not null && c.After.Id == copy.Policy &&
                    c.After.Project == copy.Project && c.After.Template == copy.Template && c.After.Configuration == copy.Configuration) &&
                packet.Values<SettingsPermissionMemberChange>(SettingsPermissionJournal.Membership, "change").Any(c =>
                    c.Request == copy.Request && c.After?.Id == copy.Membership && c.After.Project == copy.Project && c.After.Role == copy.Policy));
        }
        if (step == SettingsPermissionStep.Close)
            Require(Inventory.Length == 0 && Policies.Length == 0 && Members.Length == 0);
    }
    private void CheckRequests(SettingsPermissionPacket packet)
    {
        Requests = packet.Values<SettingsPermissionRequest>(SettingsPermissionJournal.Ingress, "request");
        Decisions = packet.Values<SettingsPermissionDecision>(SettingsPermissionJournal.Access, "decision");

        Require(Requests.Select(r => r.Id).Distinct().Count() == Requests.Length &&
            Requests.Select(r => r.Id).SequenceEqual(Decisions.Select(d => d.Request)) &&
            Requests.Where(r => r.Phase == "patch").Select(r => r.Id).SequenceEqual(Changes.Where(c => c.DecisionHash.Length > 0).Select(c => c.Request)));
        var creds = packet.Values<SettingsPermissionCredential>(SettingsPermissionJournal.Issuer, "credential");
        var memberChanges = packet.Values<SettingsPermissionMemberChange>(SettingsPermissionJournal.Membership, "change");
        Require(PolicyChanges.Where(c => c.Request is not ("bootstrap" or "cleanup")).GroupBy(c => c.Request).All(g => g.Count() == 1) &&
            memberChanges.Where(c => c.Request is not ("bootstrap" or "cleanup")).GroupBy(c => c.Request).All(g => g.Count() == 1));
        var policyState = new Dictionary<string, SettingsPermissionPolicy>();
        var memberState = new Dictionary<string, SettingsPermissionMember>();
        var configurationState = new Dictionary<string, SettingsPermissionState>();
        Apply("bootstrap");
        foreach (var b in Bindings.Where(b => !b.Request.StartsWith("setup:", StringComparison.Ordinal)))
            Require(Requests.Any(r => r.Id == b.Request && r.BodyHash == b.RequestInputHash) &&
                Decisions.Single(d => d.Request == b.Request).Allowed);
        var consumedPolicies = new List<SettingsPermissionPolicyChange>(PolicyChanges.Where(c => c.Request == "bootstrap"));
        var consumedMembers = new List<SettingsPermissionMemberChange>(memberChanges.Where(c => c.Request == "bootstrap"));
        var consumedChanges = new List<SettingsPermissionChange>(Changes.Where(c => c.Request == "bootstrap"));
        for (int i = 0; i < Requests.Length; i++)
        {
            var r = Requests[i]; var d = Decisions[i];
            Require(d.RequestHash == SettingsPermissionContract.Hash(r) && r.CredentialHash == d.CredentialHash &&
                r.Organization == d.Organization && creds.Any(c => c.Id == r.CredentialId && c.Hash == r.CredentialHash &&
                    c.Principal == r.Actor && c.Kind == r.Kind && c.Organization == r.Organization));
            if (r.Phase != "patch")
            {
                Require(r.Phase is "original" or "activation" or "observer" && d.Action == r.Phase &&
                    d.Allowed == (r.Kind == MemberPermissionActorKind.Machine && r.Organization == root.Organization &&
                        r.Actor == (r.Phase == "original" ? root.Authorities.Administrative : r.Phase == "observer" ? root.Authorities.Observer : root.Authorities.Setup)));
                if (r.Phase == "observer") Require(r.Method == "GET" && r.BodyHash == SettingsPermissionContract.RawHash([]) &&
                    (r.Path == "/api/v1/projects/" + d.Project || configurationState.Values.Any(s => s.Id == d.Project && r.Path == "/api/v1/projects/slug/" + s.Slug)) &&
                    !PolicyChanges.Any(c => c.Request == r.Id) && !memberChanges.Any(c => c.Request == r.Id) && !Changes.Any(c => c.Request == r.Id));
                Apply(r.Id);
                consumedPolicies.AddRange(PolicyChanges.Where(c => c.Request == r.Id));
                consumedMembers.AddRange(memberChanges.Where(c => c.Request == r.Id));
                consumedChanges.AddRange(Changes.Where(c => c.Request == r.Id));
                continue;
            }
            Require(r.Method == "PATCH" && r.Path == "/api/v1/projects/" + d.Project &&
                r.BodyHash == plan.PatchHash && r.IntentHash == plan.PatchHash && d.Subject == "settings" && d.Action == "edit");
            var p = policyState.Values.SingleOrDefault(p => p.Actor == r.Actor && p.Kind == r.Kind && p.Organization == r.Organization &&
                p.Project == d.Project && p.Subject == d.Subject && p.Actions.SequenceEqual(["edit"]));
            var m = p is null ? null : memberState.Values.SingleOrDefault(m => m.Principal == r.Actor && m.Kind == r.Kind &&
                m.Organization == r.Organization && m.Project == d.Project && m.Role == p.Id && m.Slug == p.Role && m.Active && m.Status == "accepted");
            Require(d.Allowed == (p is not null && m is not null) &&
                d.PolicyHash == (p is null ? "" : SettingsPermissionContract.Hash(p)) &&
                d.MembershipHash == (m is null ? "" : SettingsPermissionContract.Hash(m)));
            if (d.Allowed)
            {
                Require(p is not null && m is not null && p.Actor == r.Actor && p.Kind == r.Kind && p.Organization == r.Organization &&
                    p.Project == d.Project && p.Subject == d.Subject && p.Actions.SequenceEqual(["edit"]) &&
                    m.Principal == r.Actor && m.Kind == r.Kind && m.Organization == r.Organization && m.Project == d.Project &&
                    m.Role == p.Id && m.Slug == p.Role && m.Active && m.Status == "accepted");
            }
            var change = Changes.Single(c => c.Request == r.Id);
            var before = configurationState.GetValueOrDefault(d.Project);
            Require(before is not null && Same(change.Before, before) && change.DecisionHash == SettingsPermissionContract.Hash(d) &&
                change.InputHash == r.BodyHash && Same(change.After, d.Allowed ? plan.Changed(before!) : before) &&
                (d.Allowed ? Guid.TryParse(change.Commit, out _) : change.Commit.Length == 0));
            Apply(r.Id); consumedChanges.Add(change);
        }
        foreach (var c in PolicyChanges.Where(c => c.Request != "bootstrap" && c.Request != "cleanup"))
            Require(Requests.Any(r => r.Id == c.Request && r.Phase is "original" or "activation") &&
                Decisions.Single(d => d.Request == c.Request).Allowed);
        Require(Same(consumedPolicies.ToArray(), PolicyChanges.Where(c => c.Request != "cleanup").ToArray()) &&
            Same(consumedMembers.ToArray(), memberChanges.Where(c => c.Request != "cleanup").ToArray()));
        Require(Same(consumedChanges.ToArray(), Changes.Where(c => c.Request != "cleanup").ToArray()) &&
            Changes.Where(c => c.Commit.Length > 0).Select(c => c.Commit).Distinct().Count() == Changes.Count(c => c.Commit.Length > 0));
        foreach (var c in memberChanges.Where(c => c.Request is not ("bootstrap" or "cleanup")))
            Require(Requests.Any(r => r.Id == c.Request && r.Phase is "original" or "activation") &&
                Decisions.Single(d => d.Request == c.Request).Allowed);
        void Apply(string request)
        {
            foreach (var c in Changes.Where(c => c.Request == request))
            {
                string id = c.After?.Id ?? c.Before!.Id; Require(Same(configurationState.GetValueOrDefault(id), c.Before));
                if (c.After is null) configurationState.Remove(id); else configurationState[id] = c.After;
            }
            foreach (var c in PolicyChanges.Where(c => c.Request == request))
            {
                string id = c.After?.Id ?? c.Before!.Id; Require(Same(policyState.GetValueOrDefault(id), c.Before));
                if (c.After is null) policyState.Remove(id); else policyState[id] = c.After;
            }
            foreach (var c in memberChanges.Where(c => c.Request == request))
            {
                string id = c.After?.Id ?? c.Before!.Id; Require(memberState.GetValueOrDefault(id) == c.Before);
                if (c.After is null) memberState.Remove(id); else memberState[id] = c.After;
            }
        }
    }
    internal static bool Same<T>(T left, T right) => SettingsPermissionContract.Hash(left) == SettingsPermissionContract.Hash(right);
    private static void Require(bool condition) => SettingsPermissionContract.Require(condition);
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
