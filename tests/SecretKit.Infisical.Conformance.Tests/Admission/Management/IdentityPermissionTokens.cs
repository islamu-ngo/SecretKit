using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// The actor issuer snapshot never absorbs target tokens. Issue history is
// append-only; mutable validity is accepted only with an exact causal transition
// and a fresh independently authenticated request, never from an acknowledgement.
internal sealed class IdentityPermissionTokens(IdentityPermissionRoot root, IdentityPermissionPlan plan)
{
    private IdentityPermissionTokenIssue[] issues = [];
    private IdentityPermissionToken[] inventory = [];
    private readonly HashSet<string> authenticationRequests = [];
    internal void Check(IdentityPermissionPacket packet, IdentityPermissionStep step, IdentityPermissionIssued issued,
        IdentityPermissionAttempt[]? attempts = null)
    {
        var next = packet.Issuer.Payload.Content.Tokens;
        var journal = packet.TokenState.Payload.Content;
        var captured = packet.Capture.Payload.Content;
        IdentityPermissionContract.Require(journal.Access.SequenceEqual(packet.Access.Payload.Content.Authentication));
        var reads = packet.Policy.Payload.Content.TargetReads;
        var expectedReads = step == IdentityPermissionStep.Close ? [] : plan.Rows
            .Where(r => IdentityPermissionContract.TokenAction(r.Action) && issued.Id(r.ReadPolicy).Length > 0)
            .Select(r => new IdentityPermissionReadPolicy(issued.Id(r.ReadPolicy), issued.Id(r.Identity), issued.Id(r.Organization),
                issued.Id(r.Project), issued.Id(r.Canary), "identity", "read")).ToArray();
        IdentityPermissionContract.Require(reads.OrderBy(p => p.Id).SequenceEqual(expectedReads.OrderBy(p => p.Id)) &&
            reads.All(p => !issued.Actors.Any(a => a.Principal == p.Principal)));
        IdentityPermissionContract.Require(next.Length >= issues.Length && next.Take(issues.Length).SequenceEqual(issues) &&
            next.Select(t => t.Token).Distinct().Count() == next.Length && next.Select(t => t.Hash).Distinct().Count() == next.Length &&
            next.Select(t => t.Row).Distinct().Count() == next.Length && journal.IssuerDrained && journal.CaptureDrained && journal.AccessDrained &&
            journal.Inventory.SequenceEqual(packet.Storage.Payload.Content.Tokens) && journal.Inventory.Length == next.Length &&
            journal.Inventory.Select(t => t.Id).Distinct().Count() == next.Length && captured.Length == next.Length);
        foreach (var issue in next)
        {
            var row = plan.Rows.SingleOrDefault(r => r.Key == issue.Row);
            var binding = issued.Bindings.SingleOrDefault(b => b.CanonicalId == issue.Token);
            IdentityPermissionContract.Require(row is not null && IdentityPermissionContract.TokenAction(row.Action) &&
                issue.Identity == issued.Id(row.Identity) && issue.Organization == issued.Id(row.Organization) && issue.Project == issued.Id(row.Project) &&
                issue.Auth == issued.Id(row.Auth) && binding is not null && binding.Intent == row.Token && binding.Kind == "target-token" &&
                issue.Intent == binding.IntentHash && issue.Request == binding.Request && issue.Commit == binding.Commit &&
                !packet.Issuer.Payload.Content.Credentials.Any(c => c.Id == issue.Token || c.Hash == issue.Hash));
            if (row!.Action != IdentityPermissionAction.CreateToken && step != IdentityPermissionStep.Close)
            {
                var material = issued.Targets.SingleOrDefault(t => t.Row == row.Key);
                IdentityPermissionContract.Require(material is not null && material.Token == issue.Token && IdentityPermissionContract.RawHash(material.Material) == issue.Hash);
            }
            var capture = captured.SingleOrDefault(c => c.Token == issue.Token);
            IdentityPermissionContract.Require(capture is not null && capture.Row == issue.Row && capture.Request == issue.Request &&
                capture.Hash == issue.Hash && capture.Released == (step == IdentityPermissionStep.Close));
            var state = journal.Inventory.Single(t => t.Id == issue.Token);
            IdentityPermissionContract.Require(state.Issue == issue.Request);
            var old = inventory.SingleOrDefault(t => t.Id == issue.Token);
            if (old is not null && old.Revoked) IdentityPermissionContract.Require(state == old);
            if (step == IdentityPermissionStep.Close)
            {
                // Recovery may never have observed the original action response.
                // A fresh exact SDK revoke plus fresh authentication rejection
                // closes that gap without rewriting the historical transition.
                IdentityPermissionContract.Require(packet.Ingress.Payload.Content.Any(e => e.Phase == "cleanup" &&
                    e.Actor == root.Authorities.Setup && e.Kind == MemberPermissionActorKind.Machine && e.Authorized &&
                    e.Method == "POST" && e.Path == "/api/v1/auth/token-auth/tokens/" + issue.Token + "/revoke"));
            }
            else if (state.Revoked && old?.Revoked != true)
            {
                var causal = packet.Ingress.Payload.Content.SingleOrDefault(e => e.Request == state.Transition);
                IdentityPermissionContract.Require(causal is not null && causal.Authorized &&
                    causal.Phase == "action" && packet.Access.Payload.Content.Decisions.Any(a => a.Request == causal.Request && a.Allowed &&
                        a.Identity == issue.Identity && a.Action is IdentityPermissionAction.DeleteToken or IdentityPermissionAction.RevokeAuth));
            }
            if (!issues.Contains(issue) && step == IdentityPermissionStep.After)
                IdentityPermissionContract.Require(IdentityPermissionContract.Template(root.Operation) &&
                    row.Window == "copy" && row.Action != IdentityPermissionAction.CreateToken);
            if (!issues.Contains(issue) && step is not (IdentityPermissionStep.Open or IdentityPermissionStep.After or IdentityPermissionStep.Close))
            {
                var decision = packet.Access.Payload.Content.Decisions.SingleOrDefault(a => a.Request == issue.Request);
                IdentityPermissionContract.Require(decision is not null && decision.Allowed && decision.Action == IdentityPermissionAction.CreateToken &&
                    decision.Identity == issue.Identity && decision.Organization == issue.Organization && decision.Project == issue.Project);
            }
        }
        foreach (var access in journal.Access)
        {
            var issue = next.SingleOrDefault(t => t.Token == access.Token);
            IdentityPermissionContract.Require(issue is not null && authenticationRequests.Add(access.Request) && access.Hash == issue.Hash &&
                access.Identity == issue.Identity && access.Organization == issue.Organization && access.Project == issue.Project);
            var row = plan.Rows.Single(r => r.Key == issue!.Row);
            IdentityPermissionContract.Require(access.Canary == issued.Id(row.Canary) && access.Policy == issued.Id(row.ReadPolicy) &&
                access.HttpStatus == (access.Result == IdentityPermissionAuthentication.Authenticated ? 200 :
                    access.Result == IdentityPermissionAuthentication.InvalidToken ? 401 : 403));
        }
        if (attempts is not null)
        {
            int count = 0;
            foreach (var attempt in attempts.Where(a => IdentityPermissionContract.TokenAction(a.Row.Action)))
            {
                bool create = attempt.Row.Action == IdentityPermissionAction.CreateToken;
                bool allowed = attempt.Status == Core.SecretStatus.Success;
                var issue = next.SingleOrDefault(i => i.Row == attempt.Row.Key);
                if (create && !allowed) { IdentityPermissionContract.Require(issue is null); continue; }
                IdentityPermissionContract.Require(issue is not null);
                var events = journal.Access.Where(a => a.Token == issue!.Token).ToArray();
                IdentityPermissionContract.Require(events.Length == (create ? 1 : 2)); count += events.Length;
                if (!create) CheckEvent(events[0], "before", false);
                bool invalid = allowed && attempt.Row.Action is IdentityPermissionAction.DeleteToken or IdentityPermissionAction.RevokeAuth;
                CheckEvent(events[^1], "after", invalid);
                IdentityPermissionContract.Require(journal.Inventory.Single(t => t.Id == issue!.Token).Revoked == invalid);
            }
            IdentityPermissionContract.Require(journal.Access.Length == count);
        }
        if (step == IdentityPermissionStep.Close)
        {
            IdentityPermissionContract.Require(journal.Access.Length == next.Length && journal.Inventory.All(t => t.Revoked));
            foreach (var issue in next) CheckEvent(journal.Access.Single(a => a.Token == issue.Token), "cleanup", true);
        }
        issues = next.ToArray(); inventory = journal.Inventory.ToArray();
        static void CheckEvent(IdentityPermissionAuthenticationEvent value, string phase, bool invalid) => IdentityPermissionContract.Require(
            value.Phase == phase && value.Result == (invalid ? IdentityPermissionAuthentication.InvalidToken : IdentityPermissionAuthentication.Authenticated));
    }
}
