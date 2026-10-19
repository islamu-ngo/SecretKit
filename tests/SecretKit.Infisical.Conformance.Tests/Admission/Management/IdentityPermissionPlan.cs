using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Immutable enrollment is reproducible from the original root even if Reserve or
// Open never returns. No value here is a proposed native identity/membership ID.
internal sealed class IdentityPermissionPlan
{
    internal const string Project = "project", OtherProject = "other-project", CopyProject = "copy-project",
        OtherOrganization = "other-organization", Policy = "policy", Template = "template", AssignedRole = "assigned-role";
    internal IdentityPermissionRoot Root { get; }
    internal IdentityPermissionIntent[] Intents { get; }
    internal IdentityPermissionRow[] Rows { get; }
    internal string Slug => "identity-policy-" + Root.Nonce;
    internal string ProjectSlug => "identity-project-" + Root.Nonce;
    internal string CopySlug => "identity-copy-" + Root.Nonce;
    internal string Role => "identity-reader-" + Root.Nonce;
    internal string PolicyKey => IdentityPermissionContract.Template(Root.Operation) ? Template : Policy;
    internal string ActorKey(int i) => i == 3 ? ActorKey(0) : Root.ActorKind == MemberPermissionActorKind.Machine ?
        i == 0 ? "@" + Root.Authorities.Runtime : i == 1 ? "@" + Root.Authorities.Denied : "actor-2" :
        i == 2 ? "@" + Root.Authorities.Runtime : "actor-" + i;
    internal MemberPermissionActorKind ActorKind(int i) => i == 3 ? Root.ActorKind : i == 2 ?
        Root.ActorKind == MemberPermissionActorKind.User ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User : Root.ActorKind;
    internal string ActorScope(int i) => i == 3 ? OtherOrganization : "@" + Root.Organization;
    internal string ActorMembership(int i, bool copy = false) => "actor-membership-" + i + (copy ? "-copy" : "");
    internal IdentityPermissionPlan(IdentityPermissionRoot root)
    {
        Root = root;
        var intents = new List<IdentityPermissionIntent>(); var rows = new List<IdentityPermissionRow>();
        Add(OtherOrganization, "organization", "@" + root.Organization, "isolated-organization");
        Add(Project, "project", "@" + root.Organization, ProjectSlug);
        Add(OtherProject, "project", "@" + root.Organization, "other-" + ProjectSlug);
        Add(CopyProject, "project", "@" + root.Organization, CopySlug + ":template-name=" + Slug, Template);
        Add(AssignedRole, "role", "@" + root.Organization, Role);
        Add(Policy, root.ActorKind == MemberPermissionActorKind.Machine ? "privilege" : "role",
            root.ScopeProfile == IdentityPermissionScope.Project ? Project : "@" + root.Organization, Slug);
        Add(Template, "template", "@" + root.Organization, Slug);
        foreach (string key in new[] { "issuer-work", "dispatch-work", "registration", "canary", "owned-key" })
            Add(key, key, "@" + root.Organization, root.Id + ":" + key);
        for (int i = 0; i < 4; i++)
        {
            string key = ActorKey(i), scope = ActorScope(i);
            if (i < 3 && !key.StartsWith("@", StringComparison.Ordinal)) Add(key, "user", scope, Username(key));
            if (!key.StartsWith("@", StringComparison.Ordinal)) Add("actor-credential-" + i, "credential", scope, "credential:" + key, key);
            Add(ActorMembership(i), "membership", scope, "actor:" + key, key);
            Add(ActorMembership(i, true), "membership", CopyProject, "actor:" + key, key);
        }
        foreach (string window in IdentityPermissionContract.Template(root.Operation) ? new[] { "before", "after", "copy" } : ["before", "after"])
            foreach (var action in IdentityPermissionContract.Supported(root.ScopeProfile))
                foreach (string control in action == root.Action ? IdentityPermissionContract.Controls(action) : ["selected"])
                {
                    string key = window + "-" + IdentityPermissionContract.Wire(action) + "-" + control;
                    string org = control == "scope" && root.ScopeProfile == IdentityPermissionScope.Organization ? OtherOrganization : "@" + root.Organization;
                    string project = root.ScopeProfile == IdentityPermissionScope.Organization ? "" : control == "scope" ? OtherProject : window == "copy" ? CopyProject : Project;
                    var row = new IdentityPermissionRow(key, window, control, action, org, project, "identity-" + key,
                        "identity-" + root.Nonce + "-" + rows.Count, "membership-" + key, "auth-" + key, "token-" + key,
                        "canary-" + key, "read-policy-" + key, "privilege-" + key,
                        control is "actor" or "credential" ? 1 : control == "kind" ? 2 : control == "scope" && root.ScopeProfile == IdentityPermissionScope.Organization ? 3 : 0);
                    rows.Add(row);
                    // Project creation/deletion use an organization identity membership;
                    // details/auth actions use a project-managed machine identity.
                    Add(row.Identity, "machine", org, row.Name + ":owner=" + project);
                    Add(row.Membership, "membership", org, "identity:no-access:project=" + project, row.Identity);
                    Add(row.Auth, "auth-config", org, "token-auth:ttl=600", row.Identity);
                    Add(row.Canary, "identity-canary", org, row.Canary + ":project=" + project);
                    Add(row.ReadPolicy, "target-read-policy", org, "identity:read:canary=" + row.Canary, row.Identity, row.Canary);
                    Add(row.Token, "target-token", org, "token:" + row.Name, row.Identity, row.Auth);
                    Add(row.Privilege, "target-privilege", org, "identity:read", row.Identity, row.Membership);
                }
        Intents = intents.ToArray(); Rows = rows.ToArray();
        void Add(string key, string kind, string scope, string input, params string[] dependencies) =>
            intents.Add(new(key, root.Id, root.Nonce, kind, scope, input, dependencies, root.Id + ":work:" + key));
    }
    internal string Username(string key) => key + "-" + Root.Nonce + "@example.invalid";
    internal static string InputHash(IdentityPermissionIntent intent, Func<string, string> resolve) =>
        IdentityPermissionContract.Hash(new
        {
            intent.Kind,
            Scope = resolve(intent.Scope),
            intent.Input,
            Dependencies = intent.Dependencies.Select(resolve).ToArray()
        });
    internal IdentityPermissionRow[] Window(bool after, IdentityPermissionOutcome outcome) => Rows.Where(r => r.Window == (!after ? "before" :
        IdentityPermissionContract.Template(Root.Operation) && outcome == IdentityPermissionOutcome.Applied ? "copy" : "after")).ToArray();
    internal IdentityPermissionState Initial(IdentityPermissionRow row, IdentityPermissionIssued issued) => new(row.Key,
        issued.Id(row.Identity), issued.Id(row.Membership), issued.Id(row.Organization), issued.Id(row.Project), row.Name, "no-access",
        issued.Id(row.Auth), 600, "", 1);
    internal bool InitiallyPresent(IdentityPermissionRow row) => row.Action != IdentityPermissionAction.Create;
}

// The two source journals must agree on the entire binding, not just an ID or HMAC.
// Existing bindings are append-only; IDs and issuer requests are injective. Scope,
// exact resolved inputs, dependencies, work and root-bound intent are all joined.
// A lost Open is recoverable because this proof needs the root, not returned IDs.
internal sealed class IdentityPermissionOwnership(IdentityPermissionRoot root, IdentityPermissionPlan plan)
{
    private IdentityPermissionBinding[] history = [];
    private MemberPermissionBorrowed[]? borrowed;
    internal void Check(IdentityPermissionPacket packet, IdentityPermissionStep step)
    {
        var owner = packet.Owner.Payload.Content;
        var issuance = packet.Issuer.Payload.Content;
        var stored = packet.Storage.Payload.Content.Bindings;
        IdentityPermissionContract.Require(IdentityPermissionContract.Hash(owner.Intents) == IdentityPermissionContract.Hash(plan.Intents) &&
            owner.CollisionChecked && owner.Exclusive && owner.Pending == 0 &&
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
            IdentityPermissionContract.Require(intent is not null && intent.Root == root.Id && intent.Nonce == root.Nonce &&
                binding.IntentHash == IdentityPermissionContract.Hash(intent) && binding.Work == intent.Work && binding.Kind == intent.Kind &&
                (intent.Kind == "target-token" ? MemberPermissionContract.Text(binding.CanonicalId) : Guid.TryParse(binding.CanonicalId, out _)) &&
                !owner.Borrowed.Any(b => b.Id == binding.CanonicalId) &&
                MemberPermissionContract.Text(binding.Request) && MemberPermissionContract.Text(binding.Commit));
            string Resolve(string key) => key.Length == 0 ? "" : key.StartsWith("@", StringComparison.Ordinal) ? key[1..] : resolved.GetValueOrDefault(key) ?? "";
            IdentityPermissionContract.Require(Resolve(intent!.Scope).Length > 0 && intent.Dependencies.All(d => Resolve(d).Length > 0) &&
                binding.Scope == Resolve(intent.Scope) && binding.InputHash == IdentityPermissionPlan.InputHash(intent, Resolve));
            resolved.Add(binding.Intent, binding.CanonicalId);
        }
        IdentityPermissionContract.Require(owner.Remaining.Select(r => r.Intent).Distinct().Count() == owner.Remaining.Length &&
            owner.Remaining.All(r => resolved.GetValueOrDefault(r.Intent) == r.CanonicalId));
        if (step == IdentityPermissionStep.Reserve)
            IdentityPermissionContract.Require(stored.Length == 0 && owner.Remaining.Length == 0 && issuance.Credentials.Length == 0 && issuance.Tokens.Length == 0 && owner.Actors.Length == 0 && owner.Targets.Length == 0);
        if (step is IdentityPermissionStep.Settle or IdentityPermissionStep.Close)
            IdentityPermissionContract.Require(owner.IssuerFence && owner.IngressFence && owner.CaptureFence && owner.AccessFence);
        if (step == IdentityPermissionStep.Close)
            IdentityPermissionContract.Require(owner.Registrations == 0 && owner.Remaining.Length == 0 &&
                packet.Storage.Payload.Content.Inventory.Length == 0 && packet.Storage.Payload.Content.Tokens.All(t => t.Revoked) &&
                packet.Policy.Payload.Content.Inventory.Length == 0 && packet.Policy.Payload.Content.TargetReads.Length == 0 &&
                packet.Membership.Payload.Content.Length == 0, "cleanup-incomplete");
        history = stored.ToArray();
    }
}
