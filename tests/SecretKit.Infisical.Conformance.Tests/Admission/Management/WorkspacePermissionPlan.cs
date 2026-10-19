using System.Text.Json;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Immutable enrollment is reproducible from the original root even if Reserve or
// Open never returns. No value here is a proposed native role/membership ID.
internal sealed class WorkspacePermissionPlan
{
    internal const string Project = "project", OtherProject = "other-project", CopyProject = "copy-project",
        OtherOrganization = "other-organization", Policy = "policy", Template = "template", CopiedRole = "copied-policy-role",
        Assignment = "policy-assignment", Deferred = "deferred-resource";
    internal WorkspacePermissionRoot Root { get; }
    internal WorkspacePermissionIntent[] Intents { get; }
    internal WorkspacePermissionRow[] Rows { get; }
    internal string Slug => "role-policy-" + Root.Nonce;
    internal string ProjectSlug => "role-project-" + Root.Nonce;
    internal string CopySlug => "role-copy-" + Root.Nonce;
    internal string PolicyKey => WorkspacePermissionContract.Template(Root.Operation) ? Template : Policy;
    internal string ActorKey(int i) => i == 3 ? ActorKey(0) : Root.ActorKind == MemberPermissionActorKind.Machine ?
        i == 0 ? "@" + Root.Authorities.Runtime : i == 1 ? "@" + Root.Authorities.Denied : "actor-2" :
        i == 2 ? "@" + Root.Authorities.Runtime : "actor-" + i;
    internal MemberPermissionActorKind ActorKind(int i) => i == 3 ? Root.ActorKind : i == 2 ?
        Root.ActorKind == MemberPermissionActorKind.User ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User : Root.ActorKind;
    internal string ActorScope(int i) => i == 3 ? OtherOrganization : "@" + Root.Organization;
    internal string ActorMembership(int i, bool copy = false) => "actor-membership-" + i + (copy ? "-copy" : "");
    internal WorkspacePermissionPlan(WorkspacePermissionRoot root)
    {
        Root = root;
        var intents = new List<WorkspacePermissionIntent>(); var rows = new List<WorkspacePermissionRow>();
        Add(OtherOrganization, "organization", "@" + root.Organization, "isolated-organization");
        Add(Project, "project", "@" + root.Organization, ProjectSlug);
        Add(OtherProject, "project", "@" + root.Organization, "other-" + ProjectSlug);
        Add(CopyProject, "project", "@" + root.Organization, CopySlug + ":template-name=" + Slug, Template);
        Add(Policy, root.ActorKind == MemberPermissionActorKind.Machine ? "privilege" : "role",
            root.ScopeProfile == WorkspacePermissionScope.Project ? Project : "@" + root.Organization, Slug);
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
            Add(ActorMembership(i), "membership", root.ScopeProfile == WorkspacePermissionScope.Project ? Project : scope, "actor:" + key, key);
            Add(ActorMembership(i, true), "membership", CopyProject, "actor:" + key, key);
        }
        foreach (string window in WorkspacePermissionContract.Template(root.Operation) ? new[] { "before", "after", "copy" } : ["before", "after"])
            foreach (var action in WorkspacePermissionContract.Actions(root.ScopeProfile))
                foreach (string control in action == root.Action ? WorkspacePermissionContract.Controls(action) : ["selected"])
                {
                    string key = window + "-" + WorkspacePermissionContract.Wire(action) + "-" + control;
                    string org = control == "scope" && root.ScopeProfile == WorkspacePermissionScope.Organization ? OtherOrganization : "@" + root.Organization;
                    string project = root.ScopeProfile == WorkspacePermissionScope.Organization ? "" : control == "scope" ? OtherProject : window == "copy" ? CopyProject : Project;
                    var row = new WorkspacePermissionRow(key, window, control, action, org, project, action == WorkspacePermissionAction.Create ? "target-" + key : project,
                        action == WorkspacePermissionAction.Create ? "ws-" + root.Nonce[..8] + "-" + key : project == OtherProject ? "other-" + ProjectSlug : project == CopyProject ? CopySlug : ProjectSlug,
                        action == WorkspacePermissionAction.Create ? "ws-" + root.Nonce[..8] + "-" + key : project == OtherProject ? "other-" + ProjectSlug : project == CopyProject ? CopySlug : ProjectSlug,
                        control is "actor" or "credential" ? 1 : control == "kind" ? 2 : control == "scope" && root.ScopeProfile == WorkspacePermissionScope.Organization ? 3 : 0);
                    rows.Add(row);
                    if (action == WorkspacePermissionAction.Create) Add(row.Target, "project", org, row.Slug + ":no-default-environments");
                }
        Intents = intents.ToArray(); Rows = rows.OrderBy(r => r.Action == WorkspacePermissionAction.Delete && r.Control == "selected" ? 1 : 0).ToArray();
        void Add(string key, string kind, string scope, string input, params string[] dependencies) =>
            intents.Add(new(key, root.Id, root.Nonce, kind, scope, input, dependencies, root.Id + ":work:" + key));
    }
    internal string Username(string key) => key + "-" + Root.Nonce + "@example.invalid";
    internal string TemplateConfiguration() => JsonSerializer.Serialize(new
    {
        roles = new[] { new { name = Slug, slug = Slug, permissions = new[] { new { subject = "workspace", action = WorkspacePermissionContract.Wire(Root.Action) } } } },
        environments = Array.Empty<object>(),
        users = new[] { new { username = Username(ActorKey(0)), roles = new[] { Slug } } },
        groups = Array.Empty<object>(),
        identities = Array.Empty<object>(),
        projectManagedIdentities = Array.Empty<object>()
    });
    internal static string InputHash(WorkspacePermissionIntent intent, Func<string, string> resolve) =>
        WorkspacePermissionContract.Hash(new
        {
            intent.Kind,
            Scope = resolve(intent.Scope),
            intent.Input,
            Dependencies = intent.Dependencies.Select(resolve).ToArray()
        });
    internal WorkspacePermissionRow[] Window(bool after, WorkspacePermissionOutcome outcome) => Rows.Where(r => r.Window == (!after ? "before" :
        WorkspacePermissionContract.Template(Root.Operation) && outcome == WorkspacePermissionOutcome.Applied ? "copy" : "after")).ToArray();
    internal WorkspacePermissionState Initial(WorkspacePermissionRow row, WorkspacePermissionIssued issued) => new(row.Target,
        issued.Id(row.Target), issued.Id(row.Organization), issued.Id(row.Project), row.Name, row.Slug, "closed-v1", Configuration(false), 1);
    internal bool InitiallyPresent(WorkspacePermissionRow row) => row.Action != WorkspacePermissionAction.Create;
    // Only this complete bounded settings update is certified, not all variants.
    internal static string Configuration(bool edited) => JsonSerializer.Serialize(new
    {
        hasDeleteProtection = false,
        auditLogsRetentionDays = edited ? 17 : 7,
        secretSharing = edited,
        autoCapitalization = edited,
        enforceEncryptedSecretManagerSecretMetadata = edited,
        pitVersionLimit = edited ? 23 : 10,
        showSnapshotsLegacy = edited,
        secretDetectionIgnoreValues = Array.Empty<string>(),
        environments = Array.Empty<string>(),
        deletedEnvironments = Array.Empty<string>()
    });
    internal WorkspacePermissionState Snapshot(WorkspacePermissionRow row, WorkspacePermissionIssued issued, ProjectSummary value, int version)
    {
        WorkspacePermissionContract.Require(value.Type == "secret-manager" && value.DescriptionField.IsPresent && !value.DescriptionField.IsNull &&
            value.HasDeleteProtection.IsPresent && !value.HasDeleteProtection.IsNull && value.AuditLogsRetentionDays.IsPresent && !value.AuditLogsRetentionDays.IsNull &&
            value.SecretSharing.IsPresent && !value.SecretSharing.IsNull && value.AutoCapitalization.IsPresent && !value.AutoCapitalization.IsNull &&
            value.EnforceEncryptedSecretManagerSecretMetadata.IsPresent && !value.EnforceEncryptedSecretManagerSecretMetadata.IsNull &&
            value.PitVersionLimit.IsPresent && value.ShowSnapshotsLegacy.IsPresent && value.SecretDetectionIgnoreValues.IsPresent &&
            !value.SecretDetectionIgnoreValues.IsNull && value.SecretDetectionIgnoreValues.Value.Count == 0, "effect-mismatch");
        string config = JsonSerializer.Serialize(new
        {
            hasDeleteProtection = value.HasDeleteProtection.Value,
            auditLogsRetentionDays = value.AuditLogsRetentionDays.Value,
            secretSharing = value.SecretSharing.Value,
            autoCapitalization = value.AutoCapitalization.Value,
            enforceEncryptedSecretManagerSecretMetadata = value.EnforceEncryptedSecretManagerSecretMetadata.Value,
            pitVersionLimit = value.PitVersionLimit.Value,
            showSnapshotsLegacy = value.ShowSnapshotsLegacy.Value,
            secretDetectionIgnoreValues = Array.Empty<string>(),
            environments = Array.Empty<string>(),
            deletedEnvironments = Array.Empty<string>()
        });
        return new(row.Target, value.Id, issued.Id(row.Organization), issued.Id(row.Project), value.Name, value.Slug, value.Description!, config, version);
    }
}

// Immutable append-only bindings survive native deletion as tombstones.
internal sealed class WorkspacePermissionOwnership(WorkspacePermissionRoot root, WorkspacePermissionPlan plan)
{
    private WorkspacePermissionBinding[] history = [];
    private MemberPermissionBorrowed[]? borrowed;
    internal void Check(WorkspacePermissionPacket packet, WorkspacePermissionStep step)
    {
        var owner = packet.Owner.Payload.Content;
        var issuance = packet.Issuer.Payload.Content;
        var stored = packet.Storage.Payload.Content.Bindings;
        WorkspacePermissionContract.Require(WorkspacePermissionContract.Hash(owner.Intents) == WorkspacePermissionContract.Hash(plan.Intents) &&
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
            WorkspacePermissionContract.Require(intent is not null && intent.Root == root.Id && intent.Nonce == root.Nonce &&
                binding.IntentHash == WorkspacePermissionContract.Hash(intent) && binding.Work == intent.Work && binding.Kind == intent.Kind &&
                Guid.TryParse(binding.CanonicalId, out _) && !owner.Borrowed.Any(b => b.Id == binding.CanonicalId) &&
                MemberPermissionContract.Text(binding.Request) && MemberPermissionContract.Text(binding.Commit));
            string Resolve(string key) => key.Length == 0 ? "" : key.StartsWith("@", StringComparison.Ordinal) ? key[1..] : resolved.GetValueOrDefault(key) ?? "";
            WorkspacePermissionContract.Require(Resolve(intent!.Scope).Length > 0 && intent.Dependencies.All(d => Resolve(d).Length > 0) &&
                binding.Scope == Resolve(intent.Scope) && binding.InputHash == WorkspacePermissionPlan.InputHash(intent, Resolve));
            resolved.Add(binding.Intent, binding.CanonicalId);
        }
        WorkspacePermissionContract.Require(owner.Remaining.Select(r => r.Intent).Distinct().Count() == owner.Remaining.Length &&
            owner.Remaining.All(r => resolved.GetValueOrDefault(r.Intent) == r.CanonicalId));
        if (step == WorkspacePermissionStep.Reserve)
            WorkspacePermissionContract.Require(stored.Length == 0 && owner.Remaining.Length == 0 && issuance.Credentials.Length == 0 && owner.Actors.Length == 0);
        if (step is WorkspacePermissionStep.Settle or WorkspacePermissionStep.Close)
            WorkspacePermissionContract.Require(owner.IssuerFence && owner.IngressFence);
        if (step == WorkspacePermissionStep.Close)
            WorkspacePermissionContract.Require(owner.Registrations == 0 && owner.Remaining.Length == 0 &&
                issuance.Credentials.Length == 0 && packet.Storage.Payload.Content.Inventory.Length == 0 &&
                packet.Policy.Payload.Content.Inventory.Length == 0 && packet.Membership.Payload.Content.Length == 0, "cleanup-incomplete");
        history = stored.ToArray();
    }
}
