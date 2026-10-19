using System.Text.Json;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Immutable enrollment is reproducible from the original root even if Reserve or
// Open never returns. No value here is a proposed native role/membership ID.
internal sealed class EnvironmentPermissionPlan
{
    internal const string Project = "project", OtherProject = "other-project", CopyProject = "copy-project",
        OtherOrganization = "other-organization", Policy = "policy", Template = "template", CopiedRole = "copied-policy-role",
        Assignment = "policy-assignment", Deferred = "deferred-resource";
    internal EnvironmentPermissionRoot Root { get; }
    internal EnvironmentPermissionIntent[] Intents { get; }
    internal EnvironmentPermissionRow[] Rows { get; }
    internal string Slug => "environment-policy-" + Root.Nonce;
    internal string ProjectSlug => "environment-project-" + Root.Nonce;
    internal string CopySlug => "environment-copy-" + Root.Nonce;
    internal EnvironmentPermissionRow ConfigurationEnvironment => new("template-environment", "copy", "configuration", EnvironmentPermissionAction.Read,
        "@" + Root.Organization, CopyProject, "template-environment", "Witness", "witness", 0);
    internal EnvironmentPermissionRow DeletedEnvironment => new("deleted-environment", "before", "retained", EnvironmentPermissionAction.Read,
        "@" + Root.Organization, Project, "deleted-environment", "Retained deleted canary", "deleted-" + Root.Nonce, 0);
    internal string PolicyKey => EnvironmentPermissionContract.Template(Root.Operation) ? Template : Policy;
    internal string ActorKey(int i) => i == 3 ? ActorKey(0) : Root.ActorKind == MemberPermissionActorKind.Machine ?
        i == 0 ? "@" + Root.Authorities.Runtime : i == 1 ? "@" + Root.Authorities.Denied : "actor-2" :
        i == 2 ? "@" + Root.Authorities.Runtime : "actor-" + i;
    internal MemberPermissionActorKind ActorKind(int i) => i == 3 ? Root.ActorKind : i == 2 ?
        Root.ActorKind == MemberPermissionActorKind.User ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User : Root.ActorKind;
    internal string ActorScope(int i) => i == 3 ? OtherOrganization : "@" + Root.Organization;
    internal string ActorMembership(int i, bool copy = false) => "actor-membership-" + i + (copy ? "-copy" : "");
    internal EnvironmentPermissionPlan(EnvironmentPermissionRoot root)
    {
        Root = root;
        var intents = new List<EnvironmentPermissionIntent>(); var rows = new List<EnvironmentPermissionRow>();
        Add(OtherOrganization, "organization", "@" + root.Organization, "isolated-organization");
        Add(Project, "project", "@" + root.Organization, ProjectSlug);
        Add(OtherProject, "project", "@" + root.Organization, "other-" + ProjectSlug);
        Add(CopyProject, "project", "@" + root.Organization, CopySlug + ":template-name=" + Slug, Template);
        Add(Policy, root.ActorKind == MemberPermissionActorKind.Machine ? "privilege" : "role",
            root.ScopeProfile == EnvironmentPermissionScope.Project ? Project : "@" + root.Organization, Slug);
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
        foreach (string window in EnvironmentPermissionContract.Template(root.Operation) ? new[] { "before", "after", "copy" } : ["before", "after"])
            foreach (var action in EnvironmentPermissionContract.Supported(root.ScopeProfile))
                foreach (string control in action == root.Action ? EnvironmentPermissionContract.Controls(action) : ["selected"])
                {
                    string key = window + "-" + EnvironmentPermissionContract.Wire(action) + "-" + control;
                    string org = control == "scope" && root.ScopeProfile == EnvironmentPermissionScope.Organization ? OtherOrganization : "@" + root.Organization;
                    string project = root.ScopeProfile == EnvironmentPermissionScope.Organization ? "" : control == "scope" ? OtherProject : window == "copy" ? CopyProject : Project;
                    var row = new EnvironmentPermissionRow(key, window, control, action, org, project, "target-environment-" + key,
                        "closed-" + root.Nonce + "-" + key, "r-" + root.Nonce[..8] + "-" + key,
                        control is "actor" or "credential" ? 1 : control == "kind" ? 2 : control == "scope" && root.ScopeProfile == EnvironmentPermissionScope.Organization ? 3 : 0);
                    rows.Add(row);
                    Add(row.Target, "target-environment", project,
                        EnvironmentPermissionContract.Hash(new { row.Name, row.Slug, Position = 1.5, Deleted = false }));
                }
        Add("deleted-environment", "target-environment", Project,
            EnvironmentPermissionContract.Hash(new { Name = DeletedEnvironment.Name, Slug = DeletedEnvironment.Slug, Position = 1.5, Deleted = true }));
        Add("template-environment", "target-environment", CopyProject,
            EnvironmentPermissionContract.Hash(new { Name = "Witness", Slug = "witness", Position = 1.5, Deleted = false }), CopyProject);
        Intents = intents.ToArray(); Rows = rows.ToArray();
        void Add(string key, string kind, string scope, string input, params string[] dependencies) =>
            intents.Add(new(key, root.Id, root.Nonce, kind, scope, input, dependencies, root.Id + ":work:" + key));
    }
    internal string Username(string key) => key + "-" + Root.Nonce + "@example.invalid";
    internal static string InputHash(EnvironmentPermissionIntent intent, Func<string, string> resolve) =>
        EnvironmentPermissionContract.Hash(new
        {
            intent.Kind,
            Scope = resolve(intent.Scope),
            intent.Input,
            Dependencies = intent.Dependencies.Select(resolve).ToArray()
        });
    internal EnvironmentPermissionRow[] Window(bool after, EnvironmentPermissionOutcome outcome) => Rows.Where(r => r.Window == (!after ? "before" :
        EnvironmentPermissionContract.Template(Root.Operation) && outcome == EnvironmentPermissionOutcome.Applied ? "copy" : "after")).ToArray();
    internal EnvironmentPermissionState Initial(EnvironmentPermissionRow row, EnvironmentPermissionIssued issued) => new(row.Key,
        issued.Id(row.Target), issued.Id(row.Organization), issued.Id(row.Project), row.Name, row.Slug, 1.5, false, 1);
    internal bool InitiallyPresent(EnvironmentPermissionRow row) => row.Action != EnvironmentPermissionAction.Create;
    internal EnvironmentPermissionState Snapshot(EnvironmentPermissionRow row, EnvironmentPermissionIssued issued, ProjectEnvironment value, int version)
    {
        EnvironmentPermissionContract.Require(value.SoftDeletedAtField.IsPresent && value.DeleteAfterField.IsPresent &&
            value.DeletedByUserId.IsPresent && value.DeletedByIdentityId.IsPresent, "effect-mismatch");
        return new(row.Key, value.Id, issued.Id(row.Organization), issued.Id(row.Project), value.Name, value.Slug, value.Position,
            value.SoftDeletedAt is not null || value.DeleteAfter is not null || !value.DeletedByUserId.IsNull || !value.DeletedByIdentityId.IsNull, version);
    }
}

// The two source journals must agree on the entire binding, not just an ID or HMAC.
// Existing bindings are append-only; IDs and issuer requests are injective. Scope,
// exact resolved inputs, dependencies, work and root-bound intent are all joined.
// A lost Open is recoverable because this proof needs the root, not returned IDs.
internal sealed class EnvironmentPermissionOwnership(EnvironmentPermissionRoot root, EnvironmentPermissionPlan plan)
{
    private EnvironmentPermissionBinding[] history = [];
    private MemberPermissionBorrowed[]? borrowed;
    internal void Check(EnvironmentPermissionPacket packet, EnvironmentPermissionStep step)
    {
        var owner = packet.Owner.Payload.Content;
        var issuance = packet.Issuer.Payload.Content;
        var stored = packet.Storage.Payload.Content.Bindings;
        EnvironmentPermissionContract.Require(EnvironmentPermissionContract.Hash(owner.Intents) == EnvironmentPermissionContract.Hash(plan.Intents) &&
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
            EnvironmentPermissionContract.Require(intent is not null && intent.Root == root.Id && intent.Nonce == root.Nonce &&
                binding.IntentHash == EnvironmentPermissionContract.Hash(intent) && binding.Work == intent.Work && binding.Kind == intent.Kind &&
                Guid.TryParse(binding.CanonicalId, out _) && !owner.Borrowed.Any(b => b.Id == binding.CanonicalId) &&
                MemberPermissionContract.Text(binding.Request) && MemberPermissionContract.Text(binding.Commit));
            string Resolve(string key) => key.Length == 0 ? "" : key.StartsWith("@", StringComparison.Ordinal) ? key[1..] : resolved.GetValueOrDefault(key) ?? "";
            EnvironmentPermissionContract.Require(Resolve(intent!.Scope).Length > 0 && intent.Dependencies.All(d => Resolve(d).Length > 0) &&
                binding.Scope == Resolve(intent.Scope) && binding.InputHash == EnvironmentPermissionPlan.InputHash(intent, Resolve));
            resolved.Add(binding.Intent, binding.CanonicalId);
        }
        EnvironmentPermissionContract.Require(owner.Remaining.Select(r => r.Intent).Distinct().Count() == owner.Remaining.Length &&
            owner.Remaining.All(r => resolved.GetValueOrDefault(r.Intent) == r.CanonicalId));
        if (step == EnvironmentPermissionStep.Reserve)
            EnvironmentPermissionContract.Require(stored.Length == 0 && owner.Remaining.Length == 0 && issuance.Credentials.Length == 0 && owner.Actors.Length == 0);
        if (step is EnvironmentPermissionStep.Settle or EnvironmentPermissionStep.Close)
            EnvironmentPermissionContract.Require(owner.IssuerFence && owner.IngressFence);
        if (step == EnvironmentPermissionStep.Close)
            EnvironmentPermissionContract.Require(owner.Registrations == 0 && owner.Remaining.Length == 0 &&
                issuance.Credentials.Length == 0 && packet.Storage.Payload.Content.Inventory.Length == 0 &&
                packet.Policy.Payload.Content.Inventory.Length == 0 && packet.Membership.Payload.Content.Length == 0, "cleanup-incomplete");
        history = stored.ToArray();
    }
}
