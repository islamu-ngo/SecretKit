using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// No proposed native IDs: all future rule, actor, credential and secret resources
// are enrolled under the immutable root before Reserve/Open. Binding history survives delete.
internal sealed class ValidationPermissionPlan
{
    internal const string Project = "project", OtherProject = "other-project", CopyProject = "copy-project",
        OtherOrganization = "other-organization", Policy = "policy", Template = "template", CopiedRole = "copied-policy-role",
        Assignment = "policy-assignment", Deferred = "deferred-resource";
    internal ValidationPermissionRoot Root { get; }
    internal ValidationPermissionIntent[] Intents { get; }
    internal ValidationPermissionRow[] Rows { get; }
    internal string Slug => "validation-policy-" + Root.Nonce;
    internal string ProjectSlug => "validation-project-" + Root.Nonce;
    internal string CopySlug => "validation-copy-" + Root.Nonce;
    internal string PolicyKey => ValidationPermissionContract.Template(Root.Operation) ? Template : Policy;
    internal string ActorKey(int i) => i == 3 ? "enforcement-machine" : Root.ActorKind == MemberPermissionActorKind.Machine ?
        i == 0 ? "@" + Root.Authorities.Runtime : i == 1 ? "@" + Root.Authorities.Denied : "actor-2" :
        i == 2 ? "@" + Root.Authorities.Runtime : "actor-" + i;
    internal MemberPermissionActorKind ActorKind(int i) => i == 3 ? MemberPermissionActorKind.Machine : i == 2 ?
        Root.ActorKind == MemberPermissionActorKind.User ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User : Root.ActorKind;
    internal string ActorScope(int i) => "@" + Root.Organization;
    internal string ActorMembership(int i, bool copy = false) => "actor-membership-" + i + (copy ? "-copy" : "");
    internal ValidationPermissionPlan(ValidationPermissionRoot root)
    {
        Root = root; var intents = new List<ValidationPermissionIntent>(); var rows = new List<ValidationPermissionRow>();
        Add(OtherOrganization, "organization", "@" + root.Organization, "isolated-organization");
        Add(Project, "project", "@" + root.Organization, ProjectSlug);
        Add(OtherProject, "project", "@" + root.Organization, "other-" + ProjectSlug);
        Add(CopyProject, "project", "@" + root.Organization, CopySlug + ":template-name=" + Slug, Template);
        Add(Policy, root.ActorKind == MemberPermissionActorKind.Machine ? "privilege" : "role", Project, Slug);
        Add(Template, "template", "@" + root.Organization, Slug);
        Add(CopiedRole, "role", CopyProject, Slug, CopyProject);
        Add("template-environment", "environment", CopyProject, "Development:dev:1.5", CopyProject);
        Add(Assignment, "role-assignment", Project, Slug, Policy, ActorKey(0));
        foreach (string key in new[] { "issuer-work", "dispatch-work", "enforcement-work", "backend-work", "registration", "canary", "owned-key", Deferred })
            Add(key, key, "@" + root.Organization, root.Id + ":" + key);
        for (int i = 0; i < 4; i++)
        {
            string key = ActorKey(i), scope = ActorScope(i);
            if (!key.StartsWith("@", StringComparison.Ordinal))
            {
                Add(key, ActorKind(i) == MemberPermissionActorKind.User ? "user" : "machine", scope, Username(key));
                Add("actor-credential-" + i, "credential", scope, "credential:" + key, key);
            }
            Add(ActorMembership(i), "membership", Project, "actor:" + key, key);
            Add(ActorMembership(i, true), "membership", CopyProject, "actor:" + key, key);
        }
        foreach (string project in new[] { Project, OtherProject, CopyProject })
        {
            Add("write-grant-" + project, "write-grant", project, "secrets:create,edit:" + ActorKey(3), ActorKey(3));
            Add("write-membership-" + project, "membership", project, "actor:" + ActorKey(3), ActorKey(3));
        }
        foreach (string window in ValidationPermissionContract.Template(root.Operation) ? new[] { "before", "after", "copy" } : ["before", "after"])
            foreach (var action in Enum.GetValues<ValidationPermissionAction>())
                foreach (string control in action == root.Action ? ValidationPermissionContract.Controls(action) : ["selected"])
                {
                    string key = window + "-" + ValidationPermissionContract.Wire(action) + "-" + control;
                    string project = control == "scope" ? OtherProject : window == "copy" ? CopyProject : Project;
                    var row = new ValidationPermissionRow(key, window, control, action, "@" + root.Organization, project, "rule-" + key,
                        "rule-" + root.Nonce[..8] + "-" + key, "/w/" + root.Nonce[..8] + "/" + key,
                        control is "actor" or "credential" ? 1 : control == "kind" ? 2 : 0);
                    rows.Add(row); Add(row.Target, "validation-rule", project, ValidationPermissionContract.Hash(Configuration(row, "", "", "", false)));
                    foreach (bool after in new[] { false, true })
                        foreach (var probe in Probes(row, after)) Add(probe.Key, "secret", project,
                            ValidationPermissionContract.Hash(new { probe.Environment, probe.Path, probe.Name, probe.Update }));
                }
        Intents = intents.ToArray(); Rows = rows.ToArray();
        void Add(string key, string kind, string scope, string input, params string[] dependencies) =>
            intents.Add(new(key, root.Id, root.Nonce, kind, scope, input, dependencies, root.Id + ":work:" + key));
    }
    internal string Username(string key) => key + "-" + Root.Nonce + "@example.invalid";
    internal static string InputHash(ValidationPermissionIntent intent, Func<string, string> resolve) =>
        ValidationPermissionContract.Hash(new { intent.Kind, Scope = resolve(intent.Scope), intent.Input, Dependencies = intent.Dependencies.Select(resolve).ToArray() });
    internal ValidationPermissionRow[] Window(bool after, ValidationPermissionOutcome outcome) => Rows.Where(r => r.Window == (!after ? "before" :
        ValidationPermissionContract.Template(Root.Operation) && outcome == ValidationPermissionOutcome.Applied ? "copy" : "after")).ToArray();
    internal bool InitiallyPresent(ValidationPermissionRow row) => row.Action != ValidationPermissionAction.Create;
    internal ValidationPermissionState Initial(ValidationPermissionRow row, ValidationPermissionIssued issued) => Configuration(row, issued.Id(row.Target), issued.Id(row.Organization), issued.Id(row.Project), false);
    internal static ValidationPermissionState Configuration(ValidationPermissionRow row, string id, string org, string project, bool edit) =>
        new(row.Key, id, org, project, row.Name + (edit ? "-v2" : ""), edit ? "changed constraint" : "closed constraint", "dev", row.Slug,
            !edit, edit ? 2 : 1, new(5, 80, "^KEY_[A-Z0-9_]+_X$", "KEY_", "_X", null, null),
            new(8, 40, edit ? "^NEXT_[A-Z0-9_]+_OK$" : "^PASS_[A-Z0-9_]+_OK$", edit ? "NEXT_" : "PASS_", "_OK", null, null));
    internal static ValidationPermissionState Snapshot(ValidationPermissionRow row, string org, InfisicalValidationRule value, int version)
    {
        ValidationPermissionContract.Require(value.Kind == InfisicalValidationKind.StaticSecrets && value.IsActive is not null && value.PasswordConstraints is null && value.Providers is null, "effect-mismatch");
        return new(row.Key, value.Id, org, value.ProjectId, value.Name, value.Description, value.Environment, value.SecretPath,
            value.IsActive!.Value, version, ValidationPermissionConstraints.From(value.KeyConstraints), ValidationPermissionConstraints.From(value.ValueConstraints));
    }
    internal static ValidationPermissionProbe[] Probes(ValidationPermissionRow row, bool after) =>
        Enumerable.Range(0, 8).Select(i => new ValidationPermissionProbe(row.Key + (after ? "-post-" : "-pre-") + i, row.Key, after,
            i == 7 ? 0 : 3, i == 5 ? "other" : "dev", i == 6 ? row.Slug + "-outside" : row.Slug,
            (i == 4 ? "BAD_" : "KEY_") + (after ? "POST_" : "PRE_") + i + "_X", i is 2 or 3, i is 1 or 3 or 4 or 5 or 6 ? "FAIL_123_OK" : "PASS_123_OK")).ToArray();
}

// The two source journals must agree on the entire binding, not just an ID or HMAC.
// Existing bindings are append-only; IDs and issuer requests are injective. Scope,
// exact resolved inputs, dependencies, work and root-bound intent are all joined.
// A lost Open is recoverable because this proof needs the root, not returned IDs.
internal sealed class ValidationPermissionOwnership(ValidationPermissionRoot root, ValidationPermissionPlan plan)
{
    private ValidationPermissionBinding[] history = [];
    private MemberPermissionBorrowed[]? borrowed;
    internal void Check(ValidationPermissionPacket packet, ValidationPermissionStep step)
    {
        var owner = packet.Owner.Payload.Content;
        var issuance = packet.Issuer.Payload.Content;
        var stored = packet.Storage.Payload.Content.Bindings;
        ValidationPermissionContract.Require(ValidationPermissionContract.Hash(owner.Intents) == ValidationPermissionContract.Hash(plan.Intents) &&
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
            ValidationPermissionContract.Require(intent is not null && intent.Root == root.Id && intent.Nonce == root.Nonce &&
                binding.IntentHash == ValidationPermissionContract.Hash(intent) && binding.Work == intent.Work && binding.Kind == intent.Kind &&
                Guid.TryParse(binding.CanonicalId, out _) && !owner.Borrowed.Any(b => b.Id == binding.CanonicalId) &&
                MemberPermissionContract.Text(binding.Request) && MemberPermissionContract.Text(binding.Commit));
            string Resolve(string key) => key.Length == 0 ? "" : key.StartsWith("@", StringComparison.Ordinal) ? key[1..] : resolved.GetValueOrDefault(key) ?? "";
            ValidationPermissionContract.Require(Resolve(intent!.Scope).Length > 0 && intent.Dependencies.All(d => Resolve(d).Length > 0) &&
                binding.Scope == Resolve(intent.Scope) && binding.InputHash == ValidationPermissionPlan.InputHash(intent, Resolve));
            resolved.Add(binding.Intent, binding.CanonicalId);
        }
        ValidationPermissionContract.Require(owner.Remaining.Select(r => r.Intent).Distinct().Count() == owner.Remaining.Length &&
            owner.Remaining.All(r => resolved.GetValueOrDefault(r.Intent) == r.CanonicalId));
        if (step != ValidationPermissionStep.Close)
        {
            var deleted = packet.Storage.Payload.Content.History.Where(c => c.Before is not null && c.After is null).Select(c => c.Before!.Target).ToHashSet();
            ValidationPermissionContract.Require(owner.Remaining.Select(r => r.CanonicalId).Order().SequenceEqual(
                stored.Where(b => !deleted.Contains(b.CanonicalId)).Select(b => b.CanonicalId).Order()));
        }
        if (step == ValidationPermissionStep.Reserve)
            ValidationPermissionContract.Require(stored.Length == 0 && owner.Remaining.Length == 0 && issuance.Credentials.Length == 0 && owner.Actors.Length == 0);
        if (step is ValidationPermissionStep.Settle or ValidationPermissionStep.Close)
            ValidationPermissionContract.Require(owner.IssuerFence && owner.IngressFence && owner.EnforcementFence && owner.BackendFence);
        if (step == ValidationPermissionStep.Close)
            ValidationPermissionContract.Require(owner.Registrations == 0 && owner.Remaining.Length == 0 &&
                issuance.Credentials.Length == 0 && packet.Storage.Payload.Content.Inventory.Length == 0 &&
                packet.Policy.Payload.Content.Inventory.Length == 0 && packet.Policy.Payload.Content.WriteGrants.Length == 0 && packet.Membership.Payload.Content.Length == 0 &&
                packet.Backend.Payload.Content.Inventory.Length == 0 && packet.Storage.Payload.Content.Configurations.Length == 0, "cleanup-incomplete");
        history = stored.ToArray();
    }
}
