using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class ProjectTemplatePermissionPlan
{
    internal const string OtherOrganization = "other-organization", Policy = "policy", Deferred = "deferred-resource";
    internal ProjectTemplatePermissionRoot Root { get; }
    internal ProjectTemplatePermissionIntent[] Intents { get; }
    internal ProjectTemplatePermissionRow[] Rows { get; }
    internal string Slug => "template-policy-" + Root.Nonce;
    internal string PolicyKey => Policy;
    internal string ActorKey(int i) => i == 2 ? "@" + Root.Authorities.Runtime : i == 3 ? ActorKey(0) : "actor-" + i;
    internal MemberPermissionActorKind ActorKind(int i) => i == 2 ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User;
    internal string ActorScope(int i) => i == 3 ? OtherOrganization : "@" + Root.Organization;
    internal string ActorMembership(int i) => "actor-membership-" + i;
    internal string Username(string key) => key + "-" + Root.Nonce + "@example.invalid";
    internal ProjectTemplatePermissionPlan(ProjectTemplatePermissionRoot root)
    {
        Root = root; var intents = new List<ProjectTemplatePermissionIntent>(); var rows = new List<ProjectTemplatePermissionRow>();
        Add(OtherOrganization, "organization", "@" + root.Organization, "isolated-organization");
        Add(Policy, "role", "@" + root.Organization, Slug);
        foreach (string key in new[] { "issuer-work", "dispatch-work", "registration", "canary", "owned-key", Deferred })
            Add(key, key, "@" + root.Organization, root.Id + ":" + key);
        for (int i = 0; i < 4; i++)
        {
            string key = ActorKey(i), scope = ActorScope(i);
            if (i < 2) Add(key, "user", scope, Username(key));
            if (i != 2) Add("actor-credential-" + i, "credential", scope, "credential:" + key, key);
            Add(ActorMembership(i), "membership", scope, "actor:" + key, key);
        }
        int ordinal = 0;
        foreach (string window in new[] { "before", "after" })
            foreach (var action in Enum.GetValues<ProjectTemplatePermissionAction>())
                foreach (string control in action == root.Action ? ProjectTemplatePermissionContract.Controls(action) : ["selected"])
                {
                    string key = window + "-" + ProjectTemplatePermissionContract.Wire(action) + "-" + control;
                    string org = control == "scope" ? OtherOrganization : "@" + root.Organization;
                    var row = new ProjectTemplatePermissionRow(key, window, control, action, org, "template-" + key,
                        "canary-" + root.Nonce + "-" + ordinal++, control is "actor" or "credential" ? 1 : control == "kind" ? 2 : control == "scope" ? 3 : 0);
                    rows.Add(row);
                    Add(row.Template, "template", org, ProjectTemplatePermissionContract.Hash(new { row.Name, Description = "closed-v1", Type = "secret-manager", Configuration = Configuration(1) }));
                }
        Intents = intents.ToArray(); Rows = rows.ToArray();
        void Add(string key, string kind, string scope, string input, params string[] dependencies) =>
            intents.Add(new(key, root.Id, root.Nonce, kind, scope, input, dependencies, root.Id + ":work:" + key));
    }
    internal static string InputHash(ProjectTemplatePermissionIntent intent, Func<string, string> resolve) =>
        ProjectTemplatePermissionContract.Hash(new { intent.Kind, Scope = resolve(intent.Scope), intent.Input, Dependencies = intent.Dependencies.Select(resolve).ToArray() });
    internal ProjectTemplatePermissionRow[] Window(bool after, ProjectTemplatePermissionOutcome outcome) => Rows.Where(r => r.Window == (after ? "after" : "before")).ToArray();
    internal bool InitiallyPresent(ProjectTemplatePermissionRow row) => row.Action != ProjectTemplatePermissionAction.Create;
    internal ProjectTemplatePermissionState Initial(ProjectTemplatePermissionRow row, ProjectTemplatePermissionIssued issued) =>
        new(row.Key, issued.Id(row.Template), issued.Id(row.Organization), row.Name, "closed-v1", "secret-manager", Configuration(1), 1);
    internal string RoleSlug(int version) => "closed-" + Root.Nonce[..8] + "-" + version;
    internal string Configuration(int version) => JsonSerializer.Serialize(new
    {
        roles = new[] { new { name = "Closed " + version, slug = RoleSlug(version), permissions = Array.Empty<object>() } },
        environments = new[] { new { name = "Canary " + version, slug = "canary-" + version, position = (double)version } },
        users = Array.Empty<object>(),
        groups = Array.Empty<object>(),
        identities = Array.Empty<object>(),
        projectManagedIdentities = Array.Empty<object>()
    });
    internal ProjectTemplateConfiguration NativeConfiguration(int version) => new(
        [new("Closed " + version, RoleSlug(version), [])],
        ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Canary " + version, "canary-" + version, version)]),
        ProjectTemplateCollection<ProjectTemplateUser>.FromValues([]), ProjectTemplateCollection<ProjectTemplateGroup>.FromValues([]),
        ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues([]), ProjectTemplateCollection<ProjectTemplateManagedIdentity>.FromValues([]));
    internal ProjectTemplatePermissionState Snapshot(ProjectTemplatePermissionRow row, ProjectTemplateSummary value, int version)
    {
        ProjectTemplatePermissionContract.Require(value.Type is not null && value.Description is not null && value.Environments is not null &&
            value.Users is not null && value.Groups is not null && value.Identities is not null && value.ProjectManagedIdentities is not null &&
            value.Roles.All(r => r.Permissions.Count == 0) && value.Users.Count == 0 && value.Groups.Count == 0 && value.Identities.Count == 0 && value.ProjectManagedIdentities.Count == 0, "effect-mismatch");
        string config = JsonSerializer.Serialize(new
        {
            roles = value.Roles.Select(r => new { name = r.Name, slug = r.Slug, permissions = Array.Empty<object>() }).ToArray(),
            environments = value.Environments!.Select(e => new { name = e.Name, slug = e.Slug, position = e.Position }).ToArray(),
            users = Array.Empty<object>(),
            groups = Array.Empty<object>(),
            identities = Array.Empty<object>(),
            projectManagedIdentities = Array.Empty<object>()
        });
        return new(row.Key, value.Id, value.OrganizationId, value.Name, value.Description!, value.Type!, config, version);
    }
}

// The two source journals must agree on the entire binding, not just an ID or HMAC.
// Existing bindings are append-only; IDs and issuer requests are injective. Scope,
// exact resolved inputs, dependencies, work and root-bound intent are all joined.
// A lost Open is recoverable because this proof needs the root, not returned IDs.
internal sealed class ProjectTemplatePermissionOwnership(ProjectTemplatePermissionRoot root, ProjectTemplatePermissionPlan plan)
{
    private ProjectTemplatePermissionBinding[] history = [];
    private MemberPermissionBorrowed[]? borrowed;
    internal void Check(ProjectTemplatePermissionPacket packet, ProjectTemplatePermissionStep step)
    {
        var owner = packet.Owner.Payload.Content;
        var issuance = packet.Issuer.Payload.Content;
        var stored = packet.Storage.Payload.Content.Bindings;
        ProjectTemplatePermissionContract.Require(ProjectTemplatePermissionContract.Hash(owner.Intents) == ProjectTemplatePermissionContract.Hash(plan.Intents) &&
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
            ProjectTemplatePermissionContract.Require(intent is not null && intent.Root == root.Id && intent.Nonce == root.Nonce &&
                binding.IntentHash == ProjectTemplatePermissionContract.Hash(intent) && binding.Work == intent.Work && binding.Kind == intent.Kind &&
                Guid.TryParse(binding.CanonicalId, out _) && !owner.Borrowed.Any(b => b.Id == binding.CanonicalId) &&
                MemberPermissionContract.Text(binding.Request) && MemberPermissionContract.Text(binding.Commit));
            string Resolve(string key) => key.Length == 0 ? "" : key.StartsWith("@", StringComparison.Ordinal) ? key[1..] : resolved.GetValueOrDefault(key) ?? "";
            ProjectTemplatePermissionContract.Require(Resolve(intent!.Scope).Length > 0 && intent.Dependencies.All(d => Resolve(d).Length > 0) &&
                binding.Scope == Resolve(intent.Scope) && binding.InputHash == ProjectTemplatePermissionPlan.InputHash(intent, Resolve));
            resolved.Add(binding.Intent, binding.CanonicalId);
        }
        ProjectTemplatePermissionContract.Require(owner.Remaining.Select(r => r.Intent).Distinct().Count() == owner.Remaining.Length &&
            owner.Remaining.All(r => resolved.GetValueOrDefault(r.Intent) == r.CanonicalId));
        if (step == ProjectTemplatePermissionStep.Reserve)
            ProjectTemplatePermissionContract.Require(stored.Length == 0 && owner.Remaining.Length == 0 && issuance.Credentials.Length == 0 && owner.Actors.Length == 0);
        if (step is ProjectTemplatePermissionStep.Settle or ProjectTemplatePermissionStep.Close)
            ProjectTemplatePermissionContract.Require(owner.IssuerFence && owner.IngressFence);
        if (step == ProjectTemplatePermissionStep.Close)
            ProjectTemplatePermissionContract.Require(owner.Registrations == 0 && owner.Remaining.Length == 0 &&
                issuance.Credentials.Length == 0 && packet.Storage.Payload.Content.Inventory.Length == 0 &&
                packet.Policy.Payload.Content.Inventory.Length == 0 && packet.Membership.Payload.Content.Length == 0, "cleanup-incomplete");
        history = stored.ToArray();
    }
}
