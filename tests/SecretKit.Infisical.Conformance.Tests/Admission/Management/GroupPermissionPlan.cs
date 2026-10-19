using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Immutable enrollment is reproducible from the original root even if Reserve or
// Open never returns. No value here is a proposed native group/membership ID.
internal sealed class GroupPermissionPlan
{
    internal const string Project = "project", OtherProject = "other-project", CopyProject = "copy-project",
        OtherOrganization = "other-organization", Policy = "policy", Template = "template", AssignedRole = "assigned-role";
    internal GroupPermissionRoot Root { get; }
    internal GroupPermissionIntent[] Intents { get; }
    internal GroupPermissionRow[] Rows { get; }
    internal string Slug => "group-policy-" + Root.Nonce;
    internal string ProjectSlug => "group-project-" + Root.Nonce;
    internal string CopySlug => "group-copy-" + Root.Nonce;
    internal string Role => "group-reader-" + Root.Nonce;
    internal string PolicyKey => GroupPermissionContract.Template(Root.Operation) ? Template : Policy;
    internal string ActorKey(int i) => i == 3 ? ActorKey(0) : Root.ActorKind == MemberPermissionActorKind.Machine ?
        i == 0 ? "@" + Root.Authorities.Runtime : i == 1 ? "@" + Root.Authorities.Denied : "actor-2" :
        i == 2 ? "@" + Root.Authorities.Runtime : "actor-" + i;
    internal MemberPermissionActorKind ActorKind(int i) => i == 3 ? Root.ActorKind : i == 2 ?
        Root.ActorKind == MemberPermissionActorKind.User ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User : Root.ActorKind;
    internal string ActorScope(int i) => i == 3 ? OtherOrganization : "@" + Root.Organization;
    internal string ActorMembership(int i, bool copy = false) => "actor-membership-" + i + (copy ? "-copy" : "");
    internal GroupPermissionPlan(GroupPermissionRoot root)
    {
        Root = root;
        var intents = new List<GroupPermissionIntent>(); var rows = new List<GroupPermissionRow>();
        Add(OtherOrganization, "organization", "@" + root.Organization, "isolated-organization");
        Add(Project, "project", "@" + root.Organization, ProjectSlug);
        Add(OtherProject, "project", "@" + root.Organization, "other-" + ProjectSlug);
        Add(CopyProject, "project", "@" + root.Organization, CopySlug + ":template-name=" + Slug, Template);
        Add(AssignedRole, "role", "@" + root.Organization, Role);
        Add(Policy, root.ActorKind == MemberPermissionActorKind.Machine ? "privilege" : "role",
            root.ScopeProfile == GroupPermissionScope.Project ? Project : "@" + root.Organization, Slug);
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
        foreach (string window in GroupPermissionContract.Template(root.Operation) ? new[] { "before", "after", "copy" } : ["before", "after"])
            foreach (var action in GroupPermissionContract.Supported(root.ScopeProfile))
                foreach (string control in action == root.Action ? GroupPermissionContract.Controls(action) : ["selected"])
                {
                    string key = window + "-" + GroupPermissionContract.Wire(action) + "-" + control;
                    string org = control == "scope" && root.ScopeProfile == GroupPermissionScope.Organization ? OtherOrganization : "@" + root.Organization;
                    string project = root.ScopeProfile == GroupPermissionScope.Organization ? "" : control == "scope" ? OtherProject : window == "copy" ? CopyProject : Project;
                    var row = new GroupPermissionRow(key, window, control, action, org, project, "group-" + key,
                        "group-" + root.Nonce + "-" + key, "membership-" + key, "user-" + key, "identity-" + key,
                        "user-link-" + key, "identity-link-" + key,
                        control is "actor" or "credential" ? 1 : control == "kind" ? 2 : control == "scope" && root.ScopeProfile == GroupPermissionScope.Organization ? 3 : 0);
                    rows.Add(row);
                    Add(row.Group, "group", org, row.Name + ":no-access");
                    Add(row.User, "user", org, Username(row.User)); Add(row.Identity, "machine", org, row.Identity);
                    Add(row.User + "-credential", "credential", org, row.User, row.User);
                    Add(row.Identity + "-credential", "credential", org, row.Identity, row.Identity);
                    Add(row.Membership, "membership", project.Length == 0 ? org : project, "group:no-access", row.Group);
                    Add(row.UserLink, "membership", org, "group-user", row.Group, row.User);
                    Add(row.IdentityLink, "membership", org, "group-machine", row.Group, row.Identity);
                }
        Intents = intents.ToArray(); Rows = rows.ToArray();
        void Add(string key, string kind, string scope, string input, params string[] dependencies) =>
            intents.Add(new(key, root.Id, root.Nonce, kind, scope, input, dependencies, root.Id + ":work:" + key));
    }
    internal string Username(string key) => key + "-" + Root.Nonce + "@example.invalid";
    internal static string InputHash(GroupPermissionIntent intent, Func<string, string> resolve) =>
        GroupPermissionContract.Hash(new
        {
            intent.Kind,
            Scope = resolve(intent.Scope),
            intent.Input,
            Dependencies = intent.Dependencies.Select(resolve).ToArray()
        });
    internal GroupPermissionRow[] Window(bool after, GroupPermissionOutcome outcome) => Rows.Where(r => r.Window == (!after ? "before" :
        GroupPermissionContract.Template(Root.Operation) && outcome == GroupPermissionOutcome.Applied ? "copy" : "after")).ToArray();
    internal GroupPermissionState Initial(GroupPermissionRow row, GroupPermissionIssued issued) => new(row.Key,
        issued.Id(row.Group), issued.Id(row.Membership), issued.Id(row.Organization), issued.Id(row.Project), row.Name, "no-access",
        issued.Id(row.User), issued.Id(row.Identity), issued.Id(row.UserLink), issued.Id(row.IdentityLink), 1);
    internal bool InitiallyPresent(GroupPermissionRow row) => row.Action != GroupPermissionAction.Create;
}

// The two source journals must agree on the entire binding, not just an ID or HMAC.
// Existing bindings are append-only; IDs and issuer requests are injective. Scope,
// exact resolved inputs, dependencies, work and root-bound intent are all joined.
// A lost Open is recoverable because this proof needs the root, not returned IDs.
internal sealed class GroupPermissionOwnership(GroupPermissionRoot root, GroupPermissionPlan plan)
{
    private GroupPermissionBinding[] history = [];
    private MemberPermissionBorrowed[]? borrowed;
    internal void Check(GroupPermissionPacket packet, GroupPermissionStep step)
    {
        var owner = packet.Owner.Payload.Content;
        var issuance = packet.Issuer.Payload.Content;
        var stored = packet.Storage.Payload.Content.Bindings;
        GroupPermissionContract.Require(GroupPermissionContract.Hash(owner.Intents) == GroupPermissionContract.Hash(plan.Intents) &&
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
            GroupPermissionContract.Require(intent is not null && intent.Root == root.Id && intent.Nonce == root.Nonce &&
                binding.IntentHash == GroupPermissionContract.Hash(intent) && binding.Work == intent.Work && binding.Kind == intent.Kind &&
                Guid.TryParse(binding.CanonicalId, out _) && !owner.Borrowed.Any(b => b.Id == binding.CanonicalId) &&
                MemberPermissionContract.Text(binding.Request) && MemberPermissionContract.Text(binding.Commit));
            string Resolve(string key) => key.Length == 0 ? "" : key.StartsWith("@", StringComparison.Ordinal) ? key[1..] : resolved.GetValueOrDefault(key) ?? "";
            GroupPermissionContract.Require(Resolve(intent!.Scope).Length > 0 && intent.Dependencies.All(d => Resolve(d).Length > 0) &&
                binding.Scope == Resolve(intent.Scope) && binding.InputHash == GroupPermissionPlan.InputHash(intent, Resolve));
            resolved.Add(binding.Intent, binding.CanonicalId);
        }
        GroupPermissionContract.Require(owner.Remaining.Select(r => r.Intent).Distinct().Count() == owner.Remaining.Length &&
            owner.Remaining.All(r => resolved.GetValueOrDefault(r.Intent) == r.CanonicalId));
        if (step == GroupPermissionStep.Reserve)
            GroupPermissionContract.Require(stored.Length == 0 && owner.Remaining.Length == 0 && issuance.Credentials.Length == 0 && owner.Actors.Length == 0);
        if (step is GroupPermissionStep.Settle or GroupPermissionStep.Close)
            GroupPermissionContract.Require(owner.IssuerFence && owner.IngressFence);
        if (step == GroupPermissionStep.Close)
            GroupPermissionContract.Require(owner.Registrations == 0 && owner.Remaining.Length == 0 &&
                issuance.Credentials.Length == 0 && packet.Storage.Payload.Content.Inventory.Length == 0 &&
                packet.Policy.Payload.Content.Inventory.Length == 0 && packet.Membership.Payload.Content.Length == 0, "cleanup-incomplete");
        history = stored.ToArray();
    }
}
