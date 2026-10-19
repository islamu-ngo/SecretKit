using System.Security.Cryptography;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Every publication contains the writer's whole history, including empty windows,
// intermediate revisions, retired credentials and deleted objects. A terminal
// signature commits the exact count, order and head. Prefix checks alone are not
// enough: joins below reject unmatched intermediate events even after lost Open.
internal sealed class IntegrationPermissionVerifier : IDisposable
{
    private readonly IntegrationPermissionRoot root;
    private readonly IntegrationPermissionPlan plan;
    private readonly Dictionary<IntegrationPermissionJournal, (IntegrationPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<IntegrationPermissionJournal, IntegrationPermissionPublication> prior = [];
    private MemberPermissionBorrowed[]? borrowed;
    internal IntegrationPermissionBinding[] Bindings { get; private set; } = [];
    internal IntegrationPermissionCredential[] Credentials { get; private set; } = [];
    internal IntegrationPermissionStored[] Inventory { get; private set; } = [];
    internal IntegrationPermissionPolicy[] Policies { get; private set; } = [];
    internal IntegrationPermissionMember[] Members { get; private set; } = [];
    internal IntegrationPermissionRequest[] Requests { get; private set; } = [];
    internal IntegrationPermissionDecision[] Decisions { get; private set; } = [];
    internal IntegrationPermissionCollection[] Collections { get; private set; } = [];
    internal IntegrationPermissionPolicyChange[] PolicyChanges { get; private set; } = [];
    internal IntegrationPermissionCopy[] Copies { get; private set; } = [];
    internal IntegrationPermissionVerifier(IntegrationPermissionRoot root)
    {
        Validate(root.Profile); this.root = root; plan = new(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    internal static void Validate(IntegrationPermissionProfile profile)
    {
        Require(profile.Pins.Length == 8 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 8 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && MemberPermissionContract.Text(p.Writer) &&
                MemberPermissionContract.Text(p.Channel) && p.Schema == "integration-history-v1") &&
            profile.Pins.Select(p => p.Writer).Distinct().Count() == 8 && profile.Pins.Select(p => p.Channel).Distinct().Count() == 8 &&
            new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(MemberPermissionContract.Text));
        var hashes = new HashSet<string>();
        foreach (var pin in profile.Pins)
        {
            using var key = ECDsa.Create(); byte[] bytes = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(bytes, out int used);
            Require(used == bytes.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                hashes.Add(IntegrationPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo())));
        }
    }
    internal void Check(IntegrationPermissionPacket packet, IntegrationPermissionStep step)
    {
        Require(packet.Journals.Length == 8 && packet.Journals.Select(j => j.Content.Journal).Distinct().Count() == 8);
        foreach (var signed in packet.Journals)
        {
            var p = signed.Content; Require(keys.ContainsKey(p.Journal));
            var (pin, key) = keys[p.Journal]; byte[] bytes = IntegrationPermissionContract.Bytes(p); bool valid;
            try { valid = key.VerifyData(bytes, Convert.FromBase64String(signed.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
            catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
            finally { CryptographicOperations.ZeroMemory(bytes); }
            Require(valid && p.RootHash == IntegrationPermissionContract.Hash(root) && p.Writer == pin.Writer && p.Channel == pin.Channel &&
                p.Schema == pin.Schema && p.KeyHash == IntegrationPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
                p.Step == step && p.Terminal && p.Pending == 0 && p.Count == p.Events.Length && p.Events.Length > 0 &&
                (step != IntegrationPermissionStep.Close || p.Fenced));
            string head = "";
            for (int i = 0; i < p.Events.Length; i++)
            {
                var e = p.Events[i]; Require(e.Sequence == i + 1 && e.Previous == head && Allowed(p.Journal, e.Kind));
                head = IntegrationPermissionContract.Hash(e);
            }
            Require(p.Head == head && p.Events[0].Kind == "enroll" &&
                p.Events[0].Value.GetString() == IntegrationPermissionContract.Hash(root) &&
                p.Events.Count(e => e.Kind == "enroll") == 1);
            if (prior.TryGetValue(p.Journal, out var old))
                Require(p.Publication > old.Publication && p.Count >= old.Count &&
                    IntegrationPermissionContract.Hash(p.Events.Take(old.Count)) == IntegrationPermissionContract.Hash(old.Events));
        }
        CheckBindings(packet, step);
        CheckState(packet, step);
        CheckRequests(packet);
        foreach (var signed in packet.Journals) prior[signed.Content.Journal] = signed.Content;
    }
    private static bool Allowed(IntegrationPermissionJournal journal, string kind) => kind == "enroll" || journal switch
    {
        IntegrationPermissionJournal.Ownership => kind is "reserve" or "bind" or "retire" or "close",
        IntegrationPermissionJournal.Issuer => kind is "bind" or "credential" or "retire",
        IntegrationPermissionJournal.Storage => kind is "bind" or "row" or "copy" or "retire",
        IntegrationPermissionJournal.Policy => kind is "change",
        IntegrationPermissionJournal.Membership => kind is "change",
        IntegrationPermissionJournal.Ingress => kind is "request",
        IntegrationPermissionJournal.Access => kind is "decision",
        IntegrationPermissionJournal.Collection => kind is "read",
        _ => false
    };
    private void CheckBindings(IntegrationPermissionPacket packet, IntegrationPermissionStep step)
    {
        var owners = packet.Values<IntegrationPermissionOwner>(IntegrationPermissionJournal.Ownership, "reserve");
        Require(owners.Length == 1);
        var owner = owners[0];
        Require(owner.Exclusive && IntegrationPermissionContract.Hash(owner.Intents) == IntegrationPermissionContract.Hash(plan.Intents) &&
            owner.Borrowed.Select(b => b.Id).Distinct().Count() == owner.Borrowed.Length &&
            (borrowed is null || owner.Borrowed.SequenceEqual(borrowed)));
        borrowed ??= owner.Borrowed.ToArray();
        var storage = packet.Values<IntegrationPermissionBinding>(IntegrationPermissionJournal.Storage, "bind");
        var issuer = packet.Values<IntegrationPermissionBinding>(IntegrationPermissionJournal.Issuer, "bind");
        var owned = packet.Values<IntegrationPermissionBinding>(IntegrationPermissionJournal.Ownership, "bind");
        Require(Same(storage, issuer) && Same(storage, owned) &&
            storage.Select(b => b.Intent).Distinct().Count() == storage.Length &&
            storage.Select(b => b.CanonicalId).Distinct().Count() == storage.Length &&
            storage.Select(b => b.Commit).Distinct().Count() == storage.Length);
        var resolved = new Dictionary<string, IntegrationPermissionBinding>();
        string Id(string key) => key.StartsWith('@') ? key[1..] : resolved.GetValueOrDefault(key)?.CanonicalId ?? "";
        foreach (var binding in storage)
        {
            var intent = plan.Intents.SingleOrDefault(i => i.Key == binding.Intent);
            Require(intent is not null && intent.Root == root.Id && intent.Nonce == root.Nonce &&
                binding.IntentHash == IntegrationPermissionContract.Hash(intent) && binding.Kind == intent.Kind &&
                Id(intent.Scope).Length > 0 && intent.Dependencies.All(d => Id(d).Length > 0) &&
                binding.Scope == Id(intent.Scope) && binding.InputHash == IntegrationPermissionPlan.InputHash(intent, Id) &&
                binding.ParentCommit == (intent.Scope.StartsWith('@') ? root.Id : resolved[intent.Scope].Commit) &&
                Guid.TryParse(binding.CanonicalId, out _) && MemberPermissionContract.Text(binding.Request) &&
                MemberPermissionContract.Text(binding.RequestInputHash) && MemberPermissionContract.Text(binding.Commit) &&
                !owner.Borrowed.Any(b => b.Id == binding.CanonicalId));
            if (binding.Request.StartsWith("setup:", StringComparison.Ordinal)) Require(binding.RequestInputHash == binding.InputHash);
            resolved.Add(binding.Intent, binding);
        }
        Bindings = storage;
        var retired = packet.Values<IntegrationPermissionRetirement>(IntegrationPermissionJournal.Storage, "retire");
        Require(Same(retired, packet.Values<IntegrationPermissionRetirement>(IntegrationPermissionJournal.Issuer, "retire")) &&
            Same(retired, packet.Values<IntegrationPermissionRetirement>(IntegrationPermissionJournal.Ownership, "retire")) &&
            retired.Select(r => r.Id).Distinct().Count() == retired.Length &&
            retired.All(r => storage.Any(b => b.CanonicalId == r.Id && r.BindingHash == IntegrationPermissionContract.Hash(b))));
        var allCredentials = packet.Values<IntegrationPermissionCredential>(IntegrationPermissionJournal.Issuer, "credential");
        Require(allCredentials.Select(c => c.Id).Distinct().Count() == allCredentials.Length &&
            allCredentials.Select(c => c.Hash).Distinct().Count() == allCredentials.Length);
        foreach (var c in allCredentials.Where(c => c.Owned))
            Require(storage.Any(b => b.CanonicalId == c.Id && b.Kind == "credential") &&
                storage.Any(b => b.CanonicalId == c.Principal && b.Kind == (c.Kind == MemberPermissionActorKind.User ? "user" : "machine")));
        Credentials = allCredentials.Where(c => !retired.Any(r => r.Id == c.Id)).ToArray();
        if (step == IntegrationPermissionStep.Reserve) Require(storage.Length == 0 && allCredentials.Length == 0);
        if (step == IntegrationPermissionStep.Close)
        {
            Require(retired.Length == storage.Length && Credentials.All(c => !c.Owned));
            var closes = packet.Values<IntegrationPermissionOwner>(IntegrationPermissionJournal.Ownership, "close");
            Require(closes.Length == 1 && Same(owner, closes[0]));
        }
    }
    private void CheckState(IntegrationPermissionPacket packet, IntegrationPermissionStep step)
    {
        var policies = new Dictionary<string, IntegrationPermissionPolicy>();
        PolicyChanges = packet.Values<IntegrationPermissionPolicyChange>(IntegrationPermissionJournal.Policy, "change");
        foreach (var change in PolicyChanges)
        {
            string id = change.After?.Id ?? change.Before?.Id ?? "";
            Require(id.Length > 0 && Same(policies.GetValueOrDefault(id), change.Before) &&
                change.PreviousHash == IntegrationPermissionContract.Hash(change.Before));
            if (change.After is null) policies.Remove(id); else policies[id] = change.After;
        }
        Policies = policies.Values.ToArray();
        var members = new Dictionary<string, IntegrationPermissionMember>();
        foreach (var change in packet.Values<IntegrationPermissionMemberChange>(IntegrationPermissionJournal.Membership, "change"))
        {
            string id = change.After?.Id ?? change.Before?.Id ?? "";
            Require(id.Length > 0 && members.GetValueOrDefault(id) == change.Before);
            if (change.After is null) members.Remove(id); else members[id] = change.After;
        }
        Members = members.Values.ToArray();
        foreach (var member in packet.Values<IntegrationPermissionMemberChange>(IntegrationPermissionJournal.Membership, "change")
            .Select(c => c.After).OfType<IntegrationPermissionMember>().Where(m => m.Kind == MemberPermissionActorKind.User && m.Role.Length > 0))
            Require(Bindings.Any(b => b.CanonicalId == member.Assignment && b.Kind == "role-assignment" && b.Scope == member.Project));
        var retired = packet.Values<IntegrationPermissionRetirement>(IntegrationPermissionJournal.Storage, "retire").Select(r => r.Id).ToHashSet();
        var rows = packet.Values<IntegrationPermissionStored>(IntegrationPermissionJournal.Storage, "row");
        Require(rows.Select(r => r.Value.Id).Distinct().Count() == rows.Length);
        foreach (var row in rows)
        {
            var binding = Bindings.SingleOrDefault(b => b.CanonicalId == row.Value.Id);
            Require(binding is not null && binding.Kind == "integration" && binding.Scope == row.Project && row.Organization == root.Organization);
            string project = binding!.Intent[..binding.Intent.LastIndexOf("-row-", StringComparison.Ordinal)];
            int index = int.Parse(binding.Intent[^1..], System.Globalization.CultureInfo.InvariantCulture);
            string Id(string key) => key.StartsWith('@') ? key[1..] : Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
            Require(index is 0 or 1 && row.Value == plan.Metadata(project, index, Id));
        }
        Inventory = rows.Where(r => !retired.Contains(r.Value.Id)).ToArray();
        Copies = packet.Values<IntegrationPermissionCopy>(IntegrationPermissionJournal.Storage, "copy");
        Require(Copies.Length <= 1);
        foreach (var copy in Copies)
        {
            var template = PolicyChanges.Select(c => c.After).OfType<IntegrationPermissionPolicy>().SingleOrDefault(p => p.Id == copy.Template && p.Configuration == copy.Configuration);
            var project = Bindings.SingleOrDefault(b => b.CanonicalId == copy.Project);
            Require(template is not null && template.Subject == "integrations" && template.Actions.SequenceEqual(["read"]) &&
                project is not null && project.Intent == IntegrationPermissionPlan.CopyProject && project.Request == copy.Request &&
                copy.ParentCommit == project.Commit && copy.Username == plan.Username(0) &&
                copy.EnvironmentName == "Development" && copy.EnvironmentSlug == "dev" && copy.EnvironmentPosition == 1.5 &&
                Bindings.Any(b => b.CanonicalId == copy.Environment && b.Intent == IntegrationPermissionPlan.CopyProject + "-env") &&
                PolicyChanges.Any(c => c.Request == copy.Request && c.After is not null && c.After.Id == copy.Policy &&
                    c.After.Project == copy.Project && c.After.Template == copy.Template && c.After.Configuration == copy.Configuration) &&
                packet.Values<IntegrationPermissionMemberChange>(IntegrationPermissionJournal.Membership, "change").Any(c =>
                    c.Request == copy.Request && c.After?.Id == copy.Membership && c.After.Project == copy.Project && c.After.Role == copy.Policy));
        }
        if (step == IntegrationPermissionStep.Close)
            Require(Inventory.Length == 0 && Policies.Length == 0 && Members.Length == 0);
    }
    private void CheckRequests(IntegrationPermissionPacket packet)
    {
        Requests = packet.Values<IntegrationPermissionRequest>(IntegrationPermissionJournal.Ingress, "request");
        Decisions = packet.Values<IntegrationPermissionDecision>(IntegrationPermissionJournal.Access, "decision");
        Collections = packet.Values<IntegrationPermissionCollection>(IntegrationPermissionJournal.Collection, "read");
        Require(Requests.Select(r => r.Id).Distinct().Count() == Requests.Length &&
            Requests.Select(r => r.Id).SequenceEqual(Decisions.Select(d => d.Request)) &&
            Requests.Where(r => r.Phase == "read").Select(r => r.Id).SequenceEqual(Collections.Select(c => c.Request)));
        var creds = packet.Values<IntegrationPermissionCredential>(IntegrationPermissionJournal.Issuer, "credential");
        var memberChanges = packet.Values<IntegrationPermissionMemberChange>(IntegrationPermissionJournal.Membership, "change");
        Require(PolicyChanges.Where(c => c.Request is not ("bootstrap" or "cleanup")).GroupBy(c => c.Request).All(g => g.Count() == 1) &&
            memberChanges.Where(c => c.Request is not ("bootstrap" or "cleanup")).GroupBy(c => c.Request).All(g => g.Count() == 1));
        var policyState = new Dictionary<string, IntegrationPermissionPolicy>();
        var memberState = new Dictionary<string, IntegrationPermissionMember>();
        Apply("bootstrap");
        foreach (var b in Bindings.Where(b => !b.Request.StartsWith("setup:", StringComparison.Ordinal)))
            Require(Requests.Any(r => r.Id == b.Request && r.BodyHash == b.RequestInputHash) &&
                Decisions.Single(d => d.Request == b.Request).Allowed);
        var consumedPolicies = new List<IntegrationPermissionPolicyChange>(PolicyChanges.Where(c => c.Request == "bootstrap"));
        var consumedMembers = new List<IntegrationPermissionMemberChange>(memberChanges.Where(c => c.Request == "bootstrap"));
        for (int i = 0; i < Requests.Length; i++)
        {
            var r = Requests[i]; var d = Decisions[i];
            Require(d.RequestHash == IntegrationPermissionContract.Hash(r) && r.CredentialHash == d.CredentialHash &&
                r.Organization == d.Organization && creds.Any(c => c.Id == r.CredentialId && c.Hash == r.CredentialHash &&
                    c.Principal == r.Actor && c.Kind == r.Kind && c.Organization == r.Organization));
            if (r.Phase != "read")
            {
                Require(r.Phase is "original" or "activation" && d.Action == r.Phase &&
                    d.Allowed == (r.Kind == MemberPermissionActorKind.Machine && r.Organization == root.Organization &&
                        r.Actor == (r.Phase == "original" ? root.Authorities.Administrative : root.Authorities.Setup)));
                Apply(r.Id);
                consumedPolicies.AddRange(PolicyChanges.Where(c => c.Request == r.Id));
                consumedMembers.AddRange(memberChanges.Where(c => c.Request == r.Id));
                continue;
            }
            Require(r.Method == "GET" && r.Path == "/api/v1/projects/" + d.Project + "/integrations" &&
                r.BodyHash == IntegrationPermissionContract.RawHash([]) && d.Subject == "integrations" && d.Action == "read");
            var p = policyState.Values.SingleOrDefault(p => p.Actor == r.Actor && p.Kind == r.Kind && p.Organization == r.Organization &&
                p.Project == d.Project && p.Subject == d.Subject && p.Actions.SequenceEqual(["read"]));
            var m = p is null ? null : memberState.Values.SingleOrDefault(m => m.Principal == r.Actor && m.Kind == r.Kind &&
                m.Organization == r.Organization && m.Project == d.Project && m.Role == p.Id && m.Slug == p.Role && m.Active && m.Status == "accepted");
            Require(d.Allowed == (p is not null && m is not null) &&
                d.PolicyHash == (p is null ? "" : IntegrationPermissionContract.Hash(p)) &&
                d.MembershipHash == (m is null ? "" : IntegrationPermissionContract.Hash(m)));
            if (d.Allowed)
            {
                Require(p is not null && m is not null && p.Actor == r.Actor && p.Kind == r.Kind && p.Organization == r.Organization &&
                    p.Project == d.Project && p.Subject == d.Subject && p.Actions.SequenceEqual(["read"]) &&
                    m.Principal == r.Actor && m.Kind == r.Kind && m.Organization == r.Organization && m.Project == d.Project &&
                    m.Role == p.Id && m.Slug == p.Role && m.Active && m.Status == "accepted");
            }
            var collection = Collections.Single(c => c.Request == r.Id);
            Require(collection.DecisionHash == IntegrationPermissionContract.Hash(d) && collection.Organization == r.Organization &&
                collection.Project == d.Project && collection.Complete &&
                collection.Rows.Select(v => v.Id).Distinct().Count() == collection.Rows.Length);
            var allRows = packet.Values<IntegrationPermissionStored>(IntegrationPermissionJournal.Storage, "row").Where(s => s.Project == d.Project).Select(s => s.Value).ToArray();
            Require(collection.Rows.SequenceEqual(d.Allowed ? allRows : []) && (!d.Allowed || allRows.Length == 2));
        }
        foreach (var c in PolicyChanges.Where(c => c.Request != "bootstrap" && c.Request != "cleanup"))
            Require(Requests.Any(r => r.Id == c.Request && r.Phase is "original" or "activation") &&
                Decisions.Single(d => d.Request == c.Request).Allowed);
        Require(Same(consumedPolicies.ToArray(), PolicyChanges.Where(c => c.Request != "cleanup").ToArray()) &&
            Same(consumedMembers.ToArray(), memberChanges.Where(c => c.Request != "cleanup").ToArray()));
        foreach (var c in memberChanges.Where(c => c.Request is not ("bootstrap" or "cleanup")))
            Require(Requests.Any(r => r.Id == c.Request && r.Phase is "original" or "activation") &&
                Decisions.Single(d => d.Request == c.Request).Allowed);
        void Apply(string request)
        {
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
    internal static bool Same<T>(T left, T right) => IntegrationPermissionContract.Hash(left) == IntegrationPermissionContract.Hash(right);
    private static void Require(bool condition) => IntegrationPermissionContract.Require(condition);
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
