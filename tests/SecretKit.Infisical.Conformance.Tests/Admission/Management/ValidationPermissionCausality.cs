using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed record ValidationPermissionProbe(string Key, string Row, bool After, int Actor, string Environment, string Path, string Name, bool Update, string Value)
{
    public override string ToString() => "[ValidationPermissionProbe]";
}
internal sealed record ValidationPermissionWriteGrant(string Resource, string Revision, string Principal, string Organization, string Project, string Membership, string[] Actions);
internal sealed record ValidationPermissionAuthorization(string Request, string Actor, MemberPermissionActorKind Kind, string CredentialId, string CredentialHash,
    string Organization, string Project, string Environment, string Path, string Name, string Method, string InputHash, string Grant, string Revision, bool Allowed);
internal sealed record ValidationPermissionAccesses(ValidationPermissionAccess[] Rules, ValidationPermissionAuthorization[] Writes, ValidationPermissionAccess[] RuleHistory, ValidationPermissionAuthorization[] WriteHistory);
internal enum ValidationPermissionConstraintDecision { NotEvaluated, Allowed, Violated }
internal sealed record ValidationPermissionEnforcement(string Request, string AuthorizationHash, string InputHash, string RuleInventoryHash,
    ValidationPermissionState[] Rules, ValidationPermissionConstraintDecision Decision);
internal sealed record ValidationPermissionEnforcementHistory(ValidationPermissionEnforcement[] Decisions, bool Fenced, int Pending);
internal sealed record ValidationPermissionSecret(string Key, string Id, string Project, string Environment, string Path, string Name, string ValueHash, int Version);
internal sealed record ValidationPermissionBackendChange(string Request, string EnforcementHash, string InputHash, string Commit,
    ValidationPermissionSecret? Before, ValidationPermissionSecret? After);
internal sealed record ValidationPermissionBackendHistory(ValidationPermissionSecret[] Seeds, ValidationPermissionBackendChange[] Changes,
    ValidationPermissionSecret[] Inventory, MemberPermissionBorrowed[] Borrowed, bool Fenced, int Pending);
internal sealed record ValidationPermissionWriteAttempt(ValidationPermissionProbe Probe, string InputHash, SecretStatus Status, MutationReceipt Receipt,
    DispatchEvidence Evidence, string? Version, SecretStatus ReadStatus, string? ReadHash, string? ReadVersion);

// A verifier joins independently authored decisions, never recomputes provider regex.
// Expected outcomes are fixed canaries for a bounded profile, not SDK enforcement.
internal sealed class ValidationPermissionCausality
{
    private ValidationPermissionEnforcement[] history = [];
    private ValidationPermissionBackendChange[] commits = [];
    private readonly Dictionary<string, ValidationPermissionSecret> states = [];
    private readonly HashSet<string> requests = [];
    private ValidationPermissionWriteGrant[] grants = [];
    internal void Open(ValidationPermissionPacket packet, ValidationPermissionPlan plan, ValidationPermissionIssued issued)
    {
        CheckGrants(packet, plan, issued, false);
        foreach (var row in plan.Rows.Where(r => r.Window != "copy"))
            foreach (var probe in new[] { false, true }.SelectMany(after => ValidationPermissionPlan.Probes(row, after)).Where(p => p.Update))
                states.Add(probe.Key, new(probe.Key, issued.Id(probe.Key), issued.Id(row.Project), probe.Environment, probe.Path, probe.Name, ValidationPermissionContract.Hash("PASS_BASE_OK"), 1));
        ValidationPermissionContract.Require(packet.Backend.Payload.Content.Seeds.OrderBy(s => s.Key).SequenceEqual(states.Values.OrderBy(s => s.Key)));
        Inventory(packet);
    }
    internal void CheckGrants(ValidationPermissionPacket packet, ValidationPermissionPlan plan, ValidationPermissionIssued issued, bool copy)
    {
        var actor = issued.Actors[3]; var projects = new[] { ValidationPermissionPlan.Project, ValidationPermissionPlan.OtherProject }
            .Concat(copy ? new[] { ValidationPermissionPlan.CopyProject } : []);
        var expected = projects.Select(p => new ValidationPermissionWriteGrant(issued.Id("write-grant-" + p), "write-1", actor.Principal,
            actor.Organization, issued.Id(p), issued.Id("write-membership-" + p), ["create", "edit"])).ToArray();
        ValidationPermissionContract.Require(ValidationPermissionContract.Hash(packet.Policy.Payload.Content.WriteGrants) == ValidationPermissionContract.Hash(expected) &&
            expected.All(g => packet.Membership.Payload.Content.Any(j => j.Principal == actor.Principal && j.Kind == "machine" && j.Organization == actor.Organization &&
                j.Project == g.Project && j.Membership == g.Membership && j.Assigned && j.Active && j.Status == "accepted" && j.RoleId == g.Resource && j.RoleSlug == "static-writer")), "effect-mismatch");
        grants = expected;
    }
    internal void CopySeeds(ValidationPermissionPacket packet, ValidationPermissionPlan plan, ValidationPermissionIssued issued)
    {
        CheckGrants(packet, plan, issued, true);
        foreach (var row in plan.Rows.Where(r => r.Window == "copy"))
            foreach (var p in new[] { false, true }.SelectMany(a => ValidationPermissionPlan.Probes(row, a)).Where(p => p.Update))
                states.Add(p.Key, new(p.Key, issued.Id(p.Key), issued.Id(row.Project), p.Environment, p.Path, p.Name, ValidationPermissionContract.Hash("PASS_BASE_OK"), 1));
    }
    internal void Observe(ValidationPermissionPacket packet, ValidationPermissionIssued issued, ValidationPermissionRow row,
        IEnumerable<ValidationPermissionState> ruleStates, ValidationPermissionWriteAttempt[] attempts, bool after)
    {
        var all = packet.Enforcement.Payload.Content.Decisions; var backend = packet.Backend.Payload.Content.Changes;
        ValidationPermissionContract.Require(all.Length >= history.Length && backend.Length >= commits.Length &&
            ValidationPermissionContract.Hash(all.Take(history.Length)) == ValidationPermissionContract.Hash(history) &&
            backend.Take(commits.Length).SequenceEqual(commits), "effect-mismatch");
        var expectedProbes = ValidationPermissionPlan.Probes(row, after);
        ValidationPermissionContract.Require(attempts.Select(a => a.Probe).SequenceEqual(expectedProbes), "effect-mismatch");
        var inventory = ruleStates.OrderBy(r => r.Row).ToArray();
        for (int n = 0; n < attempts.Length; n++)
        {
            var a = attempts[n]; var p = a.Probe; var actor = issued.Actors[p.Actor];
            int index = history.Length; ValidationPermissionContract.Require(index < all.Length && index < backend.Length, "effect-mismatch");
            var decision = all[index]; var change = backend[index];
            var auth = packet.Access.Payload.Content.Writes.SingleOrDefault(e => e.Request == decision.Request);
            var ingress = packet.Ingress.Payload.Content.Events.SingleOrDefault(e => e.Request == decision.Request);
            string project = issued.Id(row.Project); bool authorized = p.Actor == 3;
            var grant = grants.Single(g => g.Project == project);
            var matched = inventory.Where(r => r.Project == project && r.Environment == p.Environment && r.Path == p.Path).ToArray();
            bool passes = !matched.Any(r => r.Active) || p.Value.StartsWith("PASS_", StringComparison.Ordinal) && p.Name.StartsWith("KEY_", StringComparison.Ordinal);
            var expected = !authorized ? ValidationPermissionConstraintDecision.NotEvaluated : passes ? ValidationPermissionConstraintDecision.Allowed : ValidationPermissionConstraintDecision.Violated;
            ValidationPermissionContract.Require(requests.Add(decision.Request) && auth is not null && ingress is not null &&
                auth.Actor == actor.Principal && auth.Kind == actor.Kind && auth.CredentialId == actor.CredentialId && auth.CredentialHash == actor.CredentialHash &&
                auth.Organization == actor.Organization && auth.Project == project && auth.Environment == p.Environment && auth.Path == p.Path && auth.Name == p.Name &&
                auth.Method == (p.Update ? "PATCH" : "POST") && auth.InputHash == a.InputHash && auth.Allowed == authorized &&
                auth.Grant == (authorized ? grant.Resource : "") && auth.Revision == (authorized ? grant.Revision : "") &&
                ingress.Phase == "write" && ingress.Actor == auth.Actor && ingress.Kind == auth.Kind && ingress.CredentialHash == auth.CredentialHash &&
                ingress.Organization == auth.Organization && ingress.Method == auth.Method && ingress.Path == "/api/v4/secrets/" + p.Name &&
                ingress.BodyHash == a.InputHash && ingress.Authorized == authorized &&
                decision.AuthorizationHash == ValidationPermissionContract.Hash(auth) && decision.InputHash == a.InputHash &&
                decision.RuleInventoryHash == ValidationPermissionContract.Hash(inventory) &&
                ValidationPermissionContract.Hash(decision.Rules) == ValidationPermissionContract.Hash(matched) && decision.Decision == expected, "effect-mismatch");
            bool applied = expected == ValidationPermissionConstraintDecision.Allowed;
            var before = states.GetValueOrDefault(p.Key);
            var next = !applied ? before : new ValidationPermissionSecret(p.Key, issued.Id(p.Key), project, p.Environment, p.Path, p.Name,
                ValidationPermissionContract.Hash(p.Value), (before?.Version ?? 0) + 1);
            ValidationPermissionContract.Require(change.Request == decision.Request && change.EnforcementHash == ValidationPermissionContract.Hash(decision) &&
                change.InputHash == a.InputHash && change.Before == before && change.After == next &&
                (applied ? Guid.TryParse(change.Commit, out _) && !commits.Any(c => c.Commit == change.Commit) : change.Commit.Length == 0) &&
                a.Status == (!authorized ? SecretStatus.Denied : applied ? SecretStatus.Success : SecretStatus.Invalid) &&
                a.Evidence == (applied ? DispatchEvidence.Applied : DispatchEvidence.Rejected) && a.Receipt.Evidence == a.Evidence &&
                a.Version == (applied ? next!.Version.ToString(System.Globalization.CultureInfo.InvariantCulture) : null) &&
                a.ReadStatus == (next is null ? SecretStatus.Absent : SecretStatus.Success) && a.ReadHash == next?.ValueHash &&
                a.ReadVersion == next?.Version.ToString(System.Globalization.CultureInfo.InvariantCulture), "effect-mismatch");
            if (next is not null) states[p.Key] = next;
            if (applied && before is null)
            {
                var binding = issued.Bindings.Single(b => b.Intent == p.Key);
                ValidationPermissionContract.Require(binding.CanonicalId == next!.Id && binding.Request == decision.Request && binding.Commit == change.Commit, "effect-mismatch");
            }
            history = [.. history, decision]; commits = [.. commits, change];
        }
    }
    internal void Complete(ValidationPermissionPacket packet, int writes)
    {
        ValidationPermissionContract.Require(packet.Enforcement.Payload.Content.Decisions.Length == history.Length && packet.Backend.Payload.Content.Changes.Length == commits.Length &&
            packet.Access.Payload.Content.Writes.Length == writes && packet.Ingress.Payload.Content.Events.Count(e => e.Phase == "write") == writes, "effect-mismatch");
        Inventory(packet);
    }
    internal void Close(ValidationPermissionPacket packet)
    {
        ValidationPermissionContract.Require(packet.Enforcement.Payload.Content.Fenced && packet.Enforcement.Payload.Content.Pending == 0 &&
            packet.Backend.Payload.Content.Fenced && packet.Backend.Payload.Content.Pending == 0 && packet.Backend.Payload.Content.Inventory.Length == 0 &&
            ValidationPermissionContract.Hash(packet.Enforcement.Payload.Content.Decisions.Take(history.Length)) == ValidationPermissionContract.Hash(history) &&
            packet.Backend.Payload.Content.Changes.Take(commits.Length).SequenceEqual(commits), "cleanup-incomplete");
    }
    private void Inventory(ValidationPermissionPacket packet) => ValidationPermissionContract.Require(
        packet.Backend.Payload.Content.Inventory.OrderBy(s => s.Key).SequenceEqual(states.Values.OrderBy(s => s.Key)), "effect-mismatch");
}
