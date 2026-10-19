using System.Collections.Immutable;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Only immutable logical intents exist before Reserve. Canonical identifiers are
// appended by independent issuance/storage commits, never selected by a caller.
internal sealed class AuditPermissionPlan
{
    internal const string Project = "project", OtherProject = "other-project", CopyProject = "copy-project",
        OtherOrganization = "other-organization", Policy = "policy", Template = "template", CopiedRole = "copied-policy-role",
        Assignment = "policy-assignment", Deferred = "deferred-resource";
    internal AuditPermissionRoot Root { get; }
    internal ImmutableArray<AuditPermissionIntent> Intents { get; }
    internal ImmutableArray<AuditPermissionRow> Rows { get; }
    internal ImmutableArray<AuditPermissionSeed> Seeds { get; }
    internal string Slug => "audit-policy-" + Root.Nonce;
    internal string ProjectSlug => "audit-project-" + Root.Nonce;
    internal string CopySlug => "audit-copy-" + Root.Nonce;
    internal string PolicyKey => AuditPermissionContract.Template(Root.Operation) ? Template : Policy;
    internal string ActorKey(int i) => i == 3 ? ActorKey(0) : Root.ActorKind == MemberPermissionActorKind.Machine ?
        i == 0 ? "@" + Root.Authorities.Runtime : i == 1 ? "@" + Root.Authorities.Denied : "actor-2" :
        i == 2 ? "@" + Root.Authorities.Runtime : "actor-" + i;
    internal MemberPermissionActorKind ActorKind(int i) => i == 3 ? Root.ActorKind : i == 2 ?
        Root.ActorKind == MemberPermissionActorKind.User ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User : Root.ActorKind;
    internal string ActorScope(int i) => i == 3 ? OtherOrganization : "@" + Root.Organization;
    internal string ActorMembership(int i, bool copy = false) => "actor-membership-" + i + (copy ? "-copy" : "");
    internal string Username(string key) => key + "-" + Root.Nonce + "@example.invalid";
    internal AuditPermissionPlan(AuditPermissionRoot root)
    {
        Root = root;
        var intents = new List<AuditPermissionIntent>(); var rows = new List<AuditPermissionRow>(); var seeds = new List<AuditPermissionSeed>();
        Add(OtherOrganization, "organization", "@" + root.Organization, "isolated-organization");
        Add(Project, "project", "@" + root.Organization, ProjectSlug);
        Add(OtherProject, "project", "@" + root.Organization, "other-" + ProjectSlug);
        Add(CopyProject, "project", "@" + root.Organization, CopySlug + ":template-name=" + Slug, Template);
        Add(Policy, root.ActorKind == MemberPermissionActorKind.Machine ? "privilege" : "role",
            root.ScopeProfile == AuditPermissionScope.Project ? Project : "@" + root.Organization, Slug);
        Add(Template, "template", "@" + root.Organization, Slug);
        Add(CopiedRole, "role", CopyProject, Slug, CopyProject);
        Add(Assignment, "role-assignment", Project, Slug, Policy, ActorKey(0));
        foreach (string key in new[] { "issuer-work", "dispatch-work", "producer-work", "publication-work", "registration", "owned-key", Deferred })
            Add(key, key, "@" + root.Organization, root.Id + ":" + key);
        for (int i = 0; i < (root.ScopeProfile == AuditPermissionScope.Organization ? 4 : 3); i++)
        {
            string key = ActorKey(i), scope = ActorScope(i);
            if (i < 3 && !key.StartsWith("@", StringComparison.Ordinal)) Add(key, "user", scope, Username(key));
            if (!key.StartsWith("@", StringComparison.Ordinal)) Add("actor-credential-" + i, "credential", scope, "credential:" + key, key);
            Add(ActorMembership(i), "membership", scope, "actor:" + key, key);
            Add(ActorMembership(i, true), "membership", CopyProject, "actor:" + key, key);
        }
        foreach (string window in AuditPermissionContract.Template(root.Operation) ? new[] { "before", "after", "copy" } : ["before", "after"])
        {
            string selectedProject = root.ScopeProfile == AuditPermissionScope.Organization ? "" : window == "copy" ? CopyProject : Project;
            foreach (string control in AuditPermissionContract.Controls(root.Action))
                rows.Add(new(window + "-" + control, window, control, AuditPermissionAction.Read,
                    control == "scope" && root.ScopeProfile == AuditPermissionScope.Organization ? OtherOrganization : "@" + root.Organization,
                    control == "scope" && root.ScopeProfile == AuditPermissionScope.Project ? OtherProject : selectedProject,
                    control is "actor" or "credential" ? 1 : control == "kind" ? 2 : control == "scope" && root.ScopeProfile == AuditPermissionScope.Organization ? 3 : 0));
            foreach (string project in root.ScopeProfile == AuditPermissionScope.Organization ? new[] { "" } : new[] { selectedProject, OtherProject })
                for (int i = 0; i < 2; i++)
                {
                    string key = window + "-" + (project.Length == 0 ? "organization" : project) + "-" + i;
                    var seed = new AuditPermissionSeed(key, window, "@" + root.Organization, project, "closed-" + root.Nonce + "-" + key, "s-" + root.Nonce[..8] + "-" + key);
                    seeds.Add(seed);
                    Add(seed.Target, "seed-role", project.Length == 0 ? seed.Organization : project, SeedInput(seed));
                    Add(seed.Audit, "audit-row", project.Length == 0 ? seed.Organization : project,
                        AuditPermissionContract.Hash(new { seed.Key, Type = EventType, Class = AuditEventClass.Management, root.From, root.Until, root.RetainUntil }), seed.Target);
                }
        }
        Intents = intents.ToImmutableArray(); Rows = rows.ToImmutableArray(); Seeds = seeds.ToImmutableArray();
        void Add(string key, string kind, string scope, string input, params string[] dependencies) =>
            intents.Add(new(key, root.Id, root.Nonce, kind, scope, input, dependencies.ToImmutableArray(), root.Id + ":work:" + key));
    }
    internal string EventType => Root.ScopeProfile == AuditPermissionScope.Organization ? "create-org-role" : "create-project-role";
    internal static string SeedInput(AuditPermissionSeed seed) => AuditPermissionContract.Hash(new { seed.Name, seed.Slug, Description = "closed-seed", Permissions = "[]" });
    internal static string InputHash(AuditPermissionIntent intent, Func<string, string> resolve) => AuditPermissionContract.Hash(new
    { intent.Kind, Scope = resolve(intent.Scope), intent.Input, Dependencies = intent.Dependencies.Select(resolve).ToArray() });
    internal string Window(bool after, AuditPermissionOutcome outcome) => !after ? "before" : AuditPermissionContract.Template(Root.Operation) && outcome == AuditPermissionOutcome.Applied ? "copy" : "after";
    internal AuditPermissionRow[] WindowRows(bool after, AuditPermissionOutcome outcome) => Rows.Where(r => r.Window == Window(after, outcome)).ToArray();
    internal AuditPermissionSeed[] WindowSeeds(bool after, AuditPermissionOutcome outcome) => Seeds.Where(s => s.Window == Window(after, outcome)).ToArray();
    internal string Configuration => AuditPermissionContract.Hash(new { Roles = new[] { new { Name = Slug, Slug } }, Environments = new[] { new { Name = "Witness", Slug = "witness", Position = 1 } }, Users = new[] { new { Username = Username(ActorKey(0)), Role = Slug } } });
}

internal sealed class AuditPermissionOwnership(AuditPermissionRoot root, AuditPermissionPlan plan)
{
    private AuditPermissionBinding[] history = [];
    internal void Check(AuditPermissionPacket packet, AuditPermissionStep step)
    {
        var owner = packet.Owner.Payload.Content; var issuance = packet.Issuer.Payload.Content;
        var stored = packet.Storage.Payload.Content.Bindings;
        AuditPermissionContract.Require(AuditPermissionContract.Hash(owner.Intents) == AuditPermissionContract.Hash(plan.Intents) &&
            owner.CollisionChecked && owner.Exclusive && owner.Pending == 0 && owner.Borrowed.Select(b => b.Id).Distinct().Count() == owner.Borrowed.Length &&
            AuditPermissionContract.Hash(owner.Borrowed) == root.Profile.BorrowedHash &&
            issuance.Bindings.SequenceEqual(stored) && stored.Length >= history.Length && stored.Take(history.Length).SequenceEqual(history) &&
            stored.Select(b => b.Intent).Distinct().Count() == stored.Length && stored.Select(b => b.CanonicalId).Distinct().Count() == stored.Length &&
            stored.Select(b => b.Commit).Distinct().Count() == stored.Length && stored.Select(b => b.Request).Distinct().Count() == stored.Length);
        var resolved = new Dictionary<string, string>();
        foreach (var binding in stored)
        {
            var intent = plan.Intents.SingleOrDefault(i => i.Key == binding.Intent);
            AuditPermissionContract.Require(intent is not null && intent.Root == root.Id && intent.Nonce == root.Nonce &&
                binding.IntentHash == AuditPermissionContract.Hash(intent) && binding.Work == intent.Work && binding.Kind == intent.Kind &&
                Guid.TryParse(binding.CanonicalId, out _) && !owner.Borrowed.Any(b => b.Id == binding.CanonicalId) &&
                MemberPermissionContract.Text(binding.Request) && MemberPermissionContract.Text(binding.Commit));
            string Resolve(string key) => key.Length == 0 ? "" : key.StartsWith("@", StringComparison.Ordinal) ? key[1..] : resolved.GetValueOrDefault(key) ?? "";
            AuditPermissionContract.Require(Resolve(intent!.Scope).Length > 0 && intent.Dependencies.All(d => Resolve(d).Length > 0) &&
                binding.Scope == Resolve(intent.Scope) && binding.InputHash == AuditPermissionPlan.InputHash(intent, Resolve));
            resolved.Add(binding.Intent, binding.CanonicalId);
        }
        var live = stored.Where(b => b.Kind != "audit-row").Select(b => new AuditPermissionResource(b.Intent, b.CanonicalId)).ToArray();
        AuditPermissionContract.Require(owner.Remaining.Select(r => r.Intent).Distinct().Count() == owner.Remaining.Length &&
            owner.Remaining.All(r => resolved.GetValueOrDefault(r.Intent) == r.CanonicalId));
        if (step != AuditPermissionStep.Close)
            AuditPermissionContract.Require(owner.Remaining.OrderBy(r => r.Intent).SequenceEqual(live.OrderBy(r => r.Intent)));
        if (step == AuditPermissionStep.Reserve)
            AuditPermissionContract.Require(stored.Length == 0 && issuance.Credentials.Length == 0 && owner.Actors.Length == 0);
        if (step == AuditPermissionStep.Settle)
            AuditPermissionContract.Require(owner.IssuerFence && owner.IngressFence);
        if (step == AuditPermissionStep.Close)
            AuditPermissionContract.Require(owner.IssuerFence && owner.IngressFence && owner.ProducerFence && owner.PublicationFence &&
                owner.Registrations == 0 && owner.Remaining.Length == 0 && issuance.Credentials.Length == 0 &&
                packet.Policy.Payload.Content.Inventory.Length == 0 && packet.Membership.Payload.Content.Length == 0 &&
                owner.RetainUntil == root.RetainUntil && owner.ResidueHash == AuditPermissionContract.Hash(packet.Storage.Payload.Content.Inventory), "cleanup-incomplete");
        history = stored.ToArray();
    }
}
