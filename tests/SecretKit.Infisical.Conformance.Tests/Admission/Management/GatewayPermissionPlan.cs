using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class GatewayPermissionPlan
{
    internal const string OtherOrganization = "other-organization", Policy = "policy", Deferred = "deferred-resource";
    internal GatewayPermissionRoot Root { get; }
    internal GatewayPermissionIntent[] Intents { get; }
    internal GatewayPermissionRow[] Rows { get; }
    internal string Slug => "gateway-policy-" + Root.Nonce;
    internal string PolicyKey => Policy;
    internal string ActorKey(int i) => i == 3 ? ActorKey(0) : i == 2 ? "@" + Root.Authorities.Runtime : "actor-" + i;
    internal MemberPermissionActorKind ActorKind(int i) => i == 2 ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User;
    internal string ActorScope(int i) => i == 3 ? OtherOrganization : "@" + Root.Organization;
    internal string ActorMembership(int i) => "actor-membership-" + i;
    internal GatewayPermissionPlan(GatewayPermissionRoot root)
    {
        Root = root;
        var intents = new List<GatewayPermissionIntent>(); var rows = new List<GatewayPermissionRow>();
        Add(OtherOrganization, "organization", "@" + root.Organization, "isolated-organization");
        Add(Policy, "role", "@" + root.Organization, Slug);
        foreach (string key in new[] { "issuer-work", "dispatch-work", "registration", "canary", "owned-key", Deferred })
            Add(key, key, "@" + root.Organization, root.Id + ":" + key);
        for (int i = 0; i < 4; i++)
        {
            string key = ActorKey(i), scope = ActorScope(i);
            if (i < 3 && !key.StartsWith("@", StringComparison.Ordinal)) Add(key, "user", scope, key + "-" + root.Nonce + "@example.invalid");
            if (!key.StartsWith("@", StringComparison.Ordinal)) Add("actor-credential-" + i, "credential", scope, "credential:" + key, key);
            Add(ActorMembership(i), "membership", scope, "actor:" + key, key);
        }
        foreach (string window in new[] { "before", "after" })
            foreach (var action in GatewayPermissionContract.Supported(root.ScopeProfile))
                foreach (string control in action == root.Action ? GatewayPermissionContract.Controls(action) : ["selected"])
                {
                    string key = window + "-" + action.ToString().ToLowerInvariant() + "-" + control;
                    string org = control == "scope" ? OtherOrganization : "@" + root.Organization;
                    var row = new GatewayPermissionRow(key, window, control, action, org, "", "target-gateway-" + key,
                        "gw-" + root.Nonce[..8] + "-" + key,
                        control is "actor" or "credential" ? 1 : control == "kind" ? 2 : control == "scope" ? 3 : 0);
                    rows.Add(row);
                    Add(row.Target, "gateway", org, GatewayPermissionContract.Hash(new { row.Name, Method = "aws", Accounts = Accounts(1), Principals = Principals(1) }));
                }
        Intents = intents.ToArray(); Rows = rows.ToArray();
        void Add(string key, string kind, string scope, string input, params string[] dependencies) =>
            intents.Add(new(key, root.Id, root.Nonce, kind, scope, input, dependencies, root.Id + ":work:" + key));
    }
    internal static string Accounts(int version) => version == 1 ? "111111111111" : "222222222222";
    internal static string Principals(int version) => "arn:aws:iam::" + Accounts(version) + ":role/closed-witness-v" + version;
    internal static string InputHash(GatewayPermissionIntent intent, Func<string, string> resolve) =>
        GatewayPermissionContract.Hash(new { intent.Kind, Scope = resolve(intent.Scope), intent.Input, Dependencies = intent.Dependencies.Select(resolve).ToArray() });
    internal GatewayPermissionRow[] Window(bool after, GatewayPermissionOutcome outcome) => Rows.Where(r => r.Window == (after ? "after" : "before")).ToArray();
    internal bool InitiallyPresent(GatewayPermissionRow row) => row.Action == GatewayPermissionAction.Edit;
    internal bool Matches(GatewayPermissionRow row, GatewayPermissionIssued issued, GatewayPermissionState state, int version) =>
        state.Row == row.Key && state.Target == issued.Id(row.Target) && state.Organization == issued.Id(row.Organization) && state.Project == "" &&
        state.Name == row.Name + (version == 2 ? "-edited" : "") && state.Accounts == Accounts(version) && state.Principals == Principals(version) && state.Version == version;
    internal GatewayPermissionState Snapshot(GatewayPermissionRow row, GatewayPermissionIssued issued, GatewaySummary value, int version)
    {
        GatewayPermissionContract.Require(value.Authentication.Method == GatewayAuthenticationMethod.Aws, "effect-mismatch");
        return new(row.Key, value.Id, issued.Id(row.Organization), "", value.Name, value.Authentication.Id!, "",
            value.Authentication.AllowedAccountIds!, value.Authentication.AllowedPrincipalArns!, version,
            value.Authentication.CreatedAt!, value.Authentication.UpdatedAt!);
    }
}

// The two source journals must agree on the entire binding, not just an ID or HMAC.
// Existing bindings are append-only; IDs and issuer requests are injective. Scope,
// exact resolved inputs, dependencies, work and root-bound intent are all joined.
// A lost Open is recoverable because this proof needs the root, not returned IDs.
internal sealed class GatewayPermissionOwnership(GatewayPermissionRoot root, GatewayPermissionPlan plan)
{
    private GatewayPermissionBinding[] history = [];
    private readonly GatewayPermissionConfigurationHistory configuration = new(root);
    private MemberPermissionBorrowed[]? borrowed;
    internal void Check(GatewayPermissionPacket packet, GatewayPermissionStep step)
    {
        var owner = packet.Owner.Payload.Content;
        var issuance = packet.Issuer.Payload.Content;
        var stored = packet.Storage.Payload.Content.Bindings;
        GatewayPermissionContract.Require(GatewayPermissionContract.Hash(owner.Intents) == GatewayPermissionContract.Hash(plan.Intents) &&
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
            GatewayPermissionContract.Require(intent is not null && intent.Root == root.Id && intent.Nonce == root.Nonce &&
                binding.IntentHash == GatewayPermissionContract.Hash(intent) && binding.Work == intent.Work && binding.Kind == intent.Kind &&
                Guid.TryParse(binding.CanonicalId, out _) && !owner.Borrowed.Any(b => b.Id == binding.CanonicalId) &&
                MemberPermissionContract.Text(binding.Request) && MemberPermissionContract.Text(binding.Commit));
            string Resolve(string key) => key.Length == 0 ? "" : key.StartsWith("@", StringComparison.Ordinal) ? key[1..] : resolved.GetValueOrDefault(key) ?? "";
            GatewayPermissionContract.Require(Resolve(intent!.Scope).Length > 0 && intent.Dependencies.All(d => Resolve(d).Length > 0) &&
                binding.Scope == Resolve(intent.Scope) && binding.InputHash == GatewayPermissionPlan.InputHash(intent, Resolve));
            resolved.Add(binding.Intent, binding.CanonicalId);
        }
        GatewayPermissionContract.Require(owner.Remaining.Select(r => r.Intent).Distinct().Count() == owner.Remaining.Length &&
            owner.Remaining.All(r => resolved.GetValueOrDefault(r.Intent) == r.CanonicalId));
        if (step == GatewayPermissionStep.Reserve)
            GatewayPermissionContract.Require(stored.Length == 0 && owner.Remaining.Length == 0 && issuance.Credentials.Length == 0 && owner.Actors.Length == 0);
        if (step is GatewayPermissionStep.Settle or GatewayPermissionStep.Close)
            GatewayPermissionContract.Require(owner.IssuerFence && owner.IngressFence);
        if (step == GatewayPermissionStep.Close)
            GatewayPermissionContract.Require(owner.Registrations == 0 && owner.Remaining.Length == 0 &&
                issuance.Credentials.Length == 0 && packet.Storage.Payload.Content.Inventory.Length == 0 &&
                packet.Policy.Payload.Content.Inventory.Length == 0 && packet.Membership.Payload.Content.Length == 0, "cleanup-incomplete");
        configuration.Check(packet, step);
        history = stored.ToArray();
    }
}
