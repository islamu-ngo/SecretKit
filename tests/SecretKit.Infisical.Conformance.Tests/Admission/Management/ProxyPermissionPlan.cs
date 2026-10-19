using System.Text.Json;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Immutable enrollment is reproducible from the original root even if Reserve or
// Open never returns. No value here is a proposed native role/membership ID.
internal sealed class ProxyPermissionPlan
{
    internal const string Project = "project", OtherProject = "other-project", CopyProject = "copy-project",
        OtherOrganization = "other-organization", Policy = "policy", Template = "template", CopiedRole = "copied-policy-role",
        Assignment = "policy-assignment", Deferred = "deferred-resource";
    internal ProxyPermissionRoot Root { get; }
    internal ProxyPermissionIntent[] Intents { get; }
    internal ProxyPermissionRow[] Rows { get; }
    internal string Slug => "proxy-policy-" + Root.Nonce;
    internal string ProjectSlug => "proxy-project-" + Root.Nonce;
    internal string CopySlug => "proxy-copy-" + Root.Nonce;
    internal string PolicyKey => ProxyPermissionContract.Template(Root.Operation) ? Template : Policy;
    internal string ActorKey(int i) => i == 3 ? ActorKey(0) : Root.ActorKind == MemberPermissionActorKind.Machine ?
        i == 0 ? "@" + Root.Authorities.Runtime : i == 1 ? "@" + Root.Authorities.Denied : "actor-2" :
        i == 2 ? "@" + Root.Authorities.Runtime : "actor-" + i;
    internal MemberPermissionActorKind ActorKind(int i) => i == 3 ? Root.ActorKind : i == 2 ?
        Root.ActorKind == MemberPermissionActorKind.User ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User : Root.ActorKind;
    internal string ActorScope(int i) => i == 3 ? OtherOrganization : "@" + Root.Organization;
    internal string ActorMembership(int i, bool copy = false) => "actor-membership-" + i + (copy ? "-copy" : "");
    internal ProxyPermissionPlan(ProxyPermissionRoot root)
    {
        Root = root;
        var intents = new List<ProxyPermissionIntent>(); var rows = new List<ProxyPermissionRow>();
        Add(OtherOrganization, "organization", "@" + root.Organization, "isolated-organization");
        Add(Project, "project", "@" + root.Organization, ProjectSlug);
        Add(OtherProject, "project", "@" + root.Organization, "other-" + ProjectSlug);
        Add(CopyProject, "project", "@" + root.Organization, CopySlug + ":template-name=" + Slug, Template);
        Add(Policy, root.ActorKind == MemberPermissionActorKind.Machine ? "privilege" : "role",
            root.ScopeProfile == ProxyPermissionScope.Project ? Project : "@" + root.Organization, Slug);
        Add(Template, "template", "@" + root.Organization, Slug);
        Add(CopiedRole, "role", CopyProject, Slug, CopyProject);
        Add(Assignment, "role-assignment", Project, Slug, Policy, ActorKey(0));
        foreach (string key in new[] { "issuer-work", "dispatch-work", "registration", "canary", "owned-key", Deferred })
            Add(key, key, "@" + root.Organization, root.Id + ":" + key);
        for (int i = 0; i < 4; i++)
        {
            string key = ActorKey(i), scope = ActorScope(i);
            if (i < 3 && !key.StartsWith("@", StringComparison.Ordinal)) Add(key, "user", scope, Username(key));
            if (!key.StartsWith("@", StringComparison.Ordinal)) Add("actor-credential-" + i, "credential", scope, "credential:" + key, key);
            Add(ActorMembership(i), "membership", scope, "actor:" + key, key);
            Add(ActorMembership(i, true), "membership", CopyProject, "actor:" + key, key);
        }
        foreach (string window in ProxyPermissionContract.Template(root.Operation) ? new[] { "before", "after", "copy" } : ["before", "after"])
            foreach (var action in ProxyPermissionContract.Supported(root.ScopeProfile))
                foreach (string control in action == root.Action ? ProxyPermissionContract.Controls(action) : ["selected"])
                {
                    string key = window + "-" + ProxyPermissionContract.Wire(action) + "-" + control;
                    string org = control == "scope" && root.ScopeProfile == ProxyPermissionScope.Organization ? OtherOrganization : "@" + root.Organization;
                    string project = root.ScopeProfile == ProxyPermissionScope.Organization ? "" : control == "scope" ? OtherProject : window == "copy" ? CopyProject : Project;
                    var row = new ProxyPermissionRow(key, window, control, action, org, project, "target-proxy-" + key,
                        "p-" + root.Nonce[..8] + "-" + key, "r-" + root.Nonce[..8] + "-" + key,
                        control is "actor" or "credential" ? 1 : control == "kind" ? 2 : control == "scope" && root.ScopeProfile == ProxyPermissionScope.Organization ? 3 : 0,
                        control == "environment" ? "other" : "witness", control == "path" ? "/other" : "/closed",
                        "folder-" + project + "-" + (control is "environment" or "path" ? control : "selected"));
                    rows.Add(row);
                    if (!intents.Any(i => i.Key == row.Folder)) Add(row.Folder, "folder", project,
                        ProxyPermissionContract.Hash(new { row.Environment, row.SecretPath }));
                    Add(row.Target, "service", project, ExpectedInput(row, 1), row.Folder);
                }
        Intents = intents.ToArray(); Rows = rows.ToArray();
        void Add(string key, string kind, string scope, string input, params string[] dependencies) =>
            intents.Add(new(key, root.Id, root.Nonce, kind, scope, input, dependencies, root.Id + ":work:" + key));
    }
    internal string Username(string key) => key + "-" + Root.Nonce + "@example.invalid";
    internal static string InputHash(ProxyPermissionIntent intent, Func<string, string> resolve) =>
        ProxyPermissionContract.Hash(new
        {
            intent.Kind,
            Scope = resolve(intent.Scope),
            intent.Input,
            Dependencies = intent.Dependencies.Select(resolve).ToArray()
        });
    internal ProxyPermissionRow[] Window(bool after, ProxyPermissionOutcome outcome) => Rows.Where(r => r.Window == (!after ? "before" :
        ProxyPermissionContract.Template(Root.Operation) && outcome == ProxyPermissionOutcome.Applied ? "copy" : "after")).ToArray();
    internal static string Placeholder(ProxyPermissionRoot root, ProxyPermissionRow row, int version, int slot) =>
        ProxyPermissionContract.Hash(new { root.Id, root.Nonce, row.Key, version, slot });
    internal static string Host(int version) => "api-v" + version + ".example.invalid";
    internal static string CredentialFingerprint(string secretKey, string placeholderKey, string placeholderHash, string surfaces) =>
        ProxyPermissionContract.Hash(new
        {
            Role = "credential-substitution",
            SecretKey = secretKey,
            PlaceholderKey = placeholderKey,
            PlaceholderHash = placeholderHash,
            Surfaces = surfaces,
            DynamicSecretName = (string?)null,
            DynamicSecretField = (string?)null,
            HeaderName = (string?)null,
            HeaderPrefix = (string?)null,
            HeaderPurpose = (string?)null
        });
    internal string Fingerprint(ProxyPermissionRow row, int version, int slot) => CredentialFingerprint("TARGET_" + slot + "_V" + version,
        "TOKEN_" + slot, ProxyPermissionContract.Hash(Placeholder(Root, row, version, slot)), "header,query");
    internal string ExpectedInput(ProxyPermissionRow row, int version) => ProxyPermissionContract.Hash(new
    {
        Name = row.Name + (version == 2 ? "-v2" : ""),
        Host = Host(version),
        row.Environment,
        row.SecretPath,
        Enabled = version == 1,
        First = Fingerprint(row, version, 0),
        Second = Fingerprint(row, version, 1)
    });
    internal bool Matches(ProxyPermissionRow row, ProxyPermissionIssued issued, ProxyPermissionState state, int version) =>
        state.Row == row.Key && state.Target == issued.Id(row.Target) && state.Organization == issued.Id(row.Organization) &&
        state.Project == issued.Id(row.Project) && state.Name == row.Name + (version == 2 ? "-v2" : "") && state.Host == Host(version) &&
        state.Environment == row.Environment && state.SecretPath == row.SecretPath && state.Folder == issued.Id(row.Folder) &&
        state.Enabled == (version == 1) && state.Version == version &&
        state.First.Slot == 0 && state.Second.Slot == 1 && state.First.ServiceId == state.Target && state.Second.ServiceId == state.Target &&
        state.First.Fingerprint == Fingerprint(row, version, 0) && state.Second.Fingerprint == Fingerprint(row, version, 1);
    internal bool InitiallyPresent(ProxyPermissionRow row) => row.Action != ProxyPermissionAction.Create;
    internal ProxyPermissionState Snapshot(ProxyPermissionRow row, ProxyPermissionIssued issued, ProxiedServiceSummary value, int version)
    {
        ProxyPermissionContract.Require(value.HasIsEnabled && value.IsEnabled is not null && value.HasCredentials && value.Credentials.Count == 2, "effect-mismatch");
        ProxyPermissionCredentialState Credential(int slot)
        {
            var c = value.Credentials[slot];
            ProxyPermissionContract.Require(c.Role == "credential-substitution" && c.ServiceId == value.Id &&
                c.HasSecretKey && c.SecretKey is not null && c.HasPlaceholderKey && c.PlaceholderKey is not null &&
                c.HasPlaceholderValue && c.PlaceholderValue is not null && c.HasSubstitutionSurfaces && c.SubstitutionSurfaces is not null &&
                c.HasDynamicSecretName && c.DynamicSecretName is null && c.HasDynamicSecretField && c.DynamicSecretField is null &&
                c.HasHeaderName && c.HeaderName is null && c.HasHeaderPrefix && c.HeaderPrefix is null && c.HasHeaderPurpose && c.HeaderPurpose is null, "effect-mismatch");
            return new(slot, c.Id, c.ServiceId, CredentialFingerprint(c.SecretKey!, c.PlaceholderKey!,
                ProxyPermissionContract.Hash(c.PlaceholderValue!.Reveal()), string.Join(",", c.SubstitutionSurfaces!)));
        }
        return new(row.Key, value.Id, issued.Id(row.Organization), issued.Id(row.Project), value.Name, value.HostPattern,
            row.Environment, row.SecretPath, value.FolderId, value.IsEnabled!.Value, version, Credential(0), Credential(1));
    }
}

// The two source journals must agree on the entire binding, not just an ID or HMAC.
// Existing bindings are append-only; IDs and issuer requests are injective. Scope,
// exact resolved inputs, dependencies, work and root-bound intent are all joined.
// A lost Open is recoverable because this proof needs the root, not returned IDs.
internal sealed class ProxyPermissionOwnership(ProxyPermissionRoot root, ProxyPermissionPlan plan)
{
    private ProxyPermissionBinding[] history = [];
    private readonly ProxyPermissionCollectionHistory collection = new(root, plan);
    private MemberPermissionBorrowed[]? borrowed;
    internal void Check(ProxyPermissionPacket packet, ProxyPermissionStep step)
    {
        var owner = packet.Owner.Payload.Content;
        var issuance = packet.Issuer.Payload.Content;
        var stored = packet.Storage.Payload.Content.Bindings;
        ProxyPermissionContract.Require(ProxyPermissionContract.Hash(owner.Intents) == ProxyPermissionContract.Hash(plan.Intents) &&
            owner.CollisionChecked && owner.Exclusive && owner.Pending == 0 && owner.Borrowed.SequenceEqual(owner.BorrowedBaseline) &&
            owner.Borrowed.Select(b => b.Id).Distinct().Count() == owner.Borrowed.Length &&
            (borrowed is null || owner.Borrowed.SequenceEqual(borrowed)) &&
            issuance.Bindings.SequenceEqual(stored) && stored.Length >= history.Length &&
            stored.Take(history.Length).SequenceEqual(history) &&
            stored.Select(b => b.Intent).Distinct().Count() == stored.Length &&
            stored.Select(b => b.CanonicalId).Distinct().Count() == stored.Length &&
            stored.Select(b => b.Request).Distinct().Count() == stored.Length &&
            stored.Select(b => b.Commit).Distinct().Count() == stored.Length);
        borrowed ??= owner.Borrowed.ToArray();
        var resolved = new Dictionary<string, string>();
        foreach (var binding in stored)
        {
            var intent = plan.Intents.SingleOrDefault(i => i.Key == binding.Intent);
            ProxyPermissionContract.Require(intent is not null && intent.Root == root.Id && intent.Nonce == root.Nonce &&
                binding.IntentHash == ProxyPermissionContract.Hash(intent) && binding.Work == intent.Work && binding.Kind == intent.Kind &&
                Guid.TryParse(binding.CanonicalId, out _) && !owner.Borrowed.Any(b => b.Id == binding.CanonicalId) &&
                MemberPermissionContract.Text(binding.Request) && MemberPermissionContract.Text(binding.Commit));
            string Resolve(string key) => key.Length == 0 ? "" : key.StartsWith("@", StringComparison.Ordinal) ? key[1..] : resolved.GetValueOrDefault(key) ?? "";
            ProxyPermissionContract.Require(Resolve(intent!.Scope).Length > 0 && intent.Dependencies.All(d => Resolve(d).Length > 0) &&
                binding.Scope == Resolve(intent.Scope) && binding.InputHash == ProxyPermissionPlan.InputHash(intent, Resolve));
            resolved.Add(binding.Intent, binding.CanonicalId);
        }
        ProxyPermissionContract.Require(owner.Remaining.Select(r => r.Intent).Distinct().Count() == owner.Remaining.Length &&
            owner.Remaining.All(r => resolved.GetValueOrDefault(r.Intent) == r.CanonicalId));
        if (step == ProxyPermissionStep.Reserve)
            ProxyPermissionContract.Require(stored.Length == 0 && owner.Remaining.Length == 0 && issuance.Credentials.Length == 0 && owner.Actors.Length == 0);
        if (step is ProxyPermissionStep.Settle or ProxyPermissionStep.Close)
            ProxyPermissionContract.Require(owner.IssuerFence && owner.IngressFence);
        if (step == ProxyPermissionStep.Close)
            ProxyPermissionContract.Require(owner.Registrations == 0 && owner.Remaining.Length == 0 &&
                issuance.Credentials.Length == 0 && packet.Storage.Payload.Content.Inventory.Length == 0 &&
                packet.Policy.Payload.Content.Inventory.Length == 0 && packet.Membership.Payload.Content.Length == 0, "cleanup-incomplete");
        collection.Check(packet, step);
        history = stored.ToArray();
    }
}
