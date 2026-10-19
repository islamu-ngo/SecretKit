namespace SecretKit.Infisical.Conformance.Tests;

// All histories survive window changes, response loss, deleted rules and Close.
// Recovery can audit a suffix even when the caller never received its attempt.
internal sealed class ValidationPermissionHistory
{
    private ValidationPermissionIngress[] ingress = [];
    private ValidationPermissionAccess[] rules = [];
    private ValidationPermissionAuthorization[] writes = [];
    private ValidationPermissionChange[] changes = [];
    private ValidationPermissionCommit[] policies = [];
    private ValidationPermissionCredential[] credentials = [];
    private ValidationPermissionEnforcement[] enforcement = [];
    private ValidationPermissionBackendChange[] backend = [];
    private MemberPermissionBorrowed[]? borrowed;

    internal void Check(ValidationPermissionPacket packet, ValidationPermissionStep step)
    {
        Append(ref ingress, packet.Ingress.Payload.Content.History);
        Append(ref rules, packet.Access.Payload.Content.RuleHistory);
        Append(ref writes, packet.Access.Payload.Content.WriteHistory);
        Append(ref changes, packet.Storage.Payload.Content.History);
        Append(ref policies, packet.Policy.Payload.Content.History);
        Append(ref credentials, packet.Issuer.Payload.Content.History);
        Append(ref enforcement, packet.Enforcement.Payload.Content.Decisions);
        Append(ref backend, packet.Backend.Payload.Content.Changes);
        var baseline = packet.Backend.Payload.Content.Borrowed;
        Require(baseline.Length == 1 && (borrowed is null || baseline.SequenceEqual(borrowed)) &&
            baseline.All(packet.Owner.Payload.Content.Borrowed.Contains));
        borrowed ??= baseline.ToArray();
        Require(ingress.Select(e => e.Request).Distinct().Count() == ingress.Length &&
            rules.Select(e => e.Request).Distinct().Count() == rules.Length &&
            writes.Select(e => e.Request).Distinct().Count() == writes.Length &&
            credentials.Select(c => c.Id).Distinct().Count() == credentials.Length &&
            rules.Length == changes.Length && writes.Length == enforcement.Length && writes.Length == backend.Length &&
            ingress.Count(e => e.Phase == "action") == rules.Length && ingress.Count(e => e.Phase == "write") == writes.Length);
        foreach (var rule in rules)
        {
            var entry = ingress.SingleOrDefault(e => e.Request == rule.Request);
            var change = changes.SingleOrDefault(e => e.Request == rule.Request);
            Require(entry is not null && change is not null && entry.Phase == "action" &&
                entry.Actor == rule.Actor && entry.Kind == rule.Kind && entry.CredentialHash == rule.CredentialHash &&
                entry.Authorized == rule.Allowed && credentials.Any(c => c.Id == rule.CredentialId && c.Principal == rule.Actor &&
                    c.Kind == rule.Kind && c.Hash == rule.CredentialHash) &&
                (rule.Allowed || change.Before == change.After));
        }
        for (int i = 0; i < writes.Length; i++)
        {
            var auth = writes[i]; var decision = enforcement[i]; var commit = backend[i];
            var entry = ingress.SingleOrDefault(e => e.Request == auth.Request);
            Require(entry is not null && entry.Phase == "write" && entry.Actor == auth.Actor &&
                entry.Kind == auth.Kind && entry.CredentialHash == auth.CredentialHash && entry.Organization == auth.Organization &&
                entry.Authorized == auth.Allowed && entry.BodyHash == auth.InputHash && entry.Method == auth.Method &&
                entry.Path == "/api/v4/secrets/" + auth.Name && credentials.Any(c => c.Id == auth.CredentialId &&
                    c.Principal == auth.Actor && c.Kind == auth.Kind && c.Hash == auth.CredentialHash && c.Organization == auth.Organization) &&
                decision.Request == auth.Request && decision.AuthorizationHash == ValidationPermissionContract.Hash(auth) &&
                decision.InputHash == auth.InputHash && commit.Request == auth.Request && commit.InputHash == auth.InputHash &&
                commit.EnforcementHash == ValidationPermissionContract.Hash(decision));
            bool applied = auth.Allowed && decision.Decision == ValidationPermissionConstraintDecision.Allowed;
            Require(auth.Allowed || decision.Decision == ValidationPermissionConstraintDecision.NotEvaluated);
            Require(applied ? commit.After is not null && commit.After.Version == (commit.Before?.Version ?? 0) + 1 &&
                commit.After.Project == auth.Project && commit.After.Environment == auth.Environment && commit.After.Path == auth.Path &&
                commit.After.Name == auth.Name && Guid.TryParse(commit.Commit, out _) :
                commit.Commit.Length == 0 && commit.Before == commit.After);
        }
        Require(backend.Where(c => c.Commit.Length != 0).Select(c => c.Commit).Distinct().Count() == backend.Count(c => c.Commit.Length != 0));
        foreach (var policy in policies)
        {
            var entry = ingress.SingleOrDefault(e => e.Request == policy.Request);
            Require(entry is not null && entry.Authorized && entry.Phase is "original" or "activation");
        }
        if (step == ValidationPermissionStep.Close)
            Require(packet.Owner.Payload.Content.IssuerFence && packet.Owner.Payload.Content.IngressFence &&
                packet.Enforcement.Payload.Content.Fenced && packet.Backend.Payload.Content.Fenced &&
                packet.Enforcement.Payload.Content.Pending == 0 && packet.Backend.Payload.Content.Pending == 0);
    }
    private static void Append<T>(ref T[] prior, T[] next)
    {
        Require(next.Length >= prior.Length &&
            ValidationPermissionContract.Hash(next.Take(prior.Length)) == ValidationPermissionContract.Hash(prior));
        prior = next.ToArray();
    }
    private static void Require(bool condition) => ValidationPermissionContract.Require(condition, "observer-unavailable");
}
