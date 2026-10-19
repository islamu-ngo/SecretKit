using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class GatewayPermissionTrial : IAsyncDisposable
{
    private readonly IGatewayPermissionSource source;
    private readonly GatewayPermissionRoot root;
    private readonly GatewayPermissionVerifier verifier;
    private readonly GatewayPermissionOwnership ownership;
    private readonly Dictionary<string, GatewayPermissionState> states = [];
    private readonly HashSet<string> requests = [];
    private GatewayPermissionIssued? issued;
    private GatewayPermissionCredential[] credentials = [];
    private GatewayPermissionPolicy[] policies = [];
    private string revision = "policy-1";
    private int stage;
    private bool closed, failed, busy;
    private GatewayPermissionReceipt? activation;
    internal GatewayPermissionPlan Plan { get; }
    internal GatewayPermissionIssued Issued => issued ?? throw new NativeCaseFailureException("observer-unavailable");
    internal GatewayPermissionReceipt? Original { get; private set; }
    internal GatewayPermissionOutcome Outcome { get; private set; }
    private GatewayPermissionTrial(IGatewayPermissionSource source, GatewayPermissionRoot root)
    { this.source = source; this.root = root; Plan = new(root); verifier = new(root); ownership = new(root, Plan); }
    internal static async ValueTask<GatewayPermissionTrial> OpenAsync(IGatewayPermissionSource source, GatewayPermissionRoot root,
        SecretMaterial capability, Action<GatewayPermissionTrial> retain, CancellationToken token)
    {
        GatewayPermissionContract.Require(source.Identity == root.Source && source.Kind == root.Kind && Enum.IsDefined(root.Kind) &&
            GatewayPermissionContract.Operations.Contains(root.Operation) && root.ScopeProfile == GatewayPermissionContract.Scope(root.Operation) &&
            root.ActorKind == GatewayPermissionContract.ActorKind(root.Operation) && GatewayPermissionContract.Actions(root.ScopeProfile).Contains(root.Action) &&
            GatewayPermissionContract.Gate(root.ScopeProfile, root.Action) is null && root.Variant == GatewayPermissionContract.Variant(root.Action) &&
            GatewayPermissionContract.Boundaries.Contains(root.Boundary) && root.Authorities.All.Distinct().Count() == 5 &&
            root.Authorities.All.All(MemberPermissionContract.Text) && !root.Authorities.All.Contains(root.Source) &&
            root.Profile.Pins.All(p => p.Writer != root.Source && !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(MemberPermissionContract.Text), "missing-input");
        var trial = new GatewayPermissionTrial(source, root);
        retain(trial); // Root recovery exists BEFORE enrollment or any creation can fail.
        _ = await trial.StepAsync(GatewayPermissionStep.Reserve, capability, token);
        var packet = await trial.StepAsync(GatewayPermissionStep.Open, null, token);
        var v = trial.Issued; var p = trial.Plan;
        trial.Require(v.Actors.Length == (root.ScopeProfile == GatewayPermissionScope.Organization ? 4 : 3));
        trial.credentials = packet.Issuer.Payload.Content.Credentials;
        trial.Require(trial.credentials.Select(c => c.Id).Distinct().Count() == trial.credentials.Length);
        for (int i = 0; i < v.Actors.Length; i++)
        {
            var actor = v.Actors[i];
            trial.Require(actor.Principal == v.Id(p.ActorKey(i)) && actor.Kind == p.ActorKind(i) && actor.Organization == v.Id(p.ActorScope(i)) &&
                actor.Owned == !p.ActorKey(i).StartsWith("@", StringComparison.Ordinal) &&
                (actor.Owned ? actor.Credential.Length > 0 && GatewayPermissionContract.RawHash(actor.Credential) == actor.CredentialHash &&
                    actor.CredentialId == v.Id("actor-credential-" + i) : actor.Credential.Length == 0 && root.Authorities.All.Contains(actor.Principal)) &&
                trial.credentials.Contains(new(actor.CredentialId, actor.Principal, actor.Kind, actor.Organization, actor.CredentialHash, actor.Owned)));
        }
        foreach (var credential in trial.credentials.Where(c => c.Owned))
        {
            var binding = v.Bindings.SingleOrDefault(b => b.CanonicalId == credential.Id);
            var principal = v.Bindings.SingleOrDefault(b => b.CanonicalId == credential.Principal);
            trial.Require(binding is not null && binding.Kind == "credential" && binding.Scope == credential.Organization && principal is not null &&
                principal.Kind == (credential.Kind == MemberPermissionActorKind.User ? "user" : "machine"));
        }
        trial.Require(trial.credentials.Count(c => c.Owned) == packet.Owner.Payload.Content.Remaining.Count(r =>
            v.Bindings.Any(b => b.Intent == r.Intent && b.Kind == "credential")));
        foreach (var row in p.Rows.Where(p.InitiallyPresent))
        {
            var state = packet.Storage.Payload.Content.Inventory.SingleOrDefault(s => s.Row == row.Key);
            trial.Require(state is not null && p.Matches(row, v, state, 1));
            trial.states.Add(row.Key, state!);
        }
        trial.policies = packet.Policy.Payload.Content.Inventory;
        trial.Require(trial.policies.Length == (GatewayPermissionContract.Create(root.Operation) ? 0 : 1));
        foreach (var policy in trial.policies) trial.Require(trial.PolicyMatches(policy, GatewayPermissionContract.Baseline(root)));
        trial.CheckState(packet); trial.CheckJoins(packet, false);
        return trial;
    }
    internal GatewayPermissionRow[] Rows(bool after) => Plan.Window(after, Outcome);
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        var packet = await StepAsync(after ? GatewayPermissionStep.After : GatewayPermissionStep.Before, null, token);
        CheckState(packet);
    }
    internal async ValueTask ArmAsync(CancellationToken token)
    {
        var packet = await StepAsync(GatewayPermissionStep.Arm, null, token); CheckState(packet); CheckPolicies(packet);
    }
    internal async ValueTask SettleAsync(GatewayPermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Native.Evidence == receipt.Evidence, "effect-mismatch"); Original = receipt;
        string originalPath = GatewayPermissionEffects.OriginalPath(root, Plan, Issued);
        var packet = await StepAsync(GatewayPermissionStep.Settle, null, token);
        bool cancel = root.Boundary == "cancellation-boundary", denied = root.Boundary == "denied-authority", lost = root.Boundary == "lost-response-no-replay";
        var ingress = packet.Ingress.Payload.Content; var commits = packet.Policy.Payload.Content.Commits;
        Require(ingress.Length == (cancel ? 0 : 1) && commits.Length <= 1 && (!(cancel || denied) || commits.Length == 0) &&
            packet.Storage.Payload.Content.Changes.Length == 0 && packet.Access.Payload.Content.Length == 0 &&
            receipt.Evidence == (cancel ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected : lost ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancel || lost) && (receipt.Cancelled ? receipt.Status is null : receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var entry in ingress)
            Require(requests.Add(entry.Request) && entry.Phase == "original" && entry.Actor == (denied ? root.Authorities.Denied : root.Authorities.Administrative) &&
                entry.Kind == MemberPermissionActorKind.Machine && entry.Organization == root.Organization && entry.Authorized == !denied &&
                entry.IntentHash == receipt.IntentHash && entry.Path == originalPath && entry.Method == (GatewayPermissionContract.Create(root.Operation) ? "POST" : "PATCH"), "effect-mismatch");
        Outcome = GatewayPermissionOutcome.NonApplied;
        if (commits.Length == 1)
        {
            var commit = commits[0];
            Require(commit.Request == ingress.Single().Request && commit.PreviousRevision == revision && commit.Policy.Revision != revision &&
                commit.Policy.Resource == Issued.Id(Plan.PolicyKey), "effect-mismatch");
            if (GatewayPermissionContract.Create(root.Operation))
                Require(Issued.Bindings.Single(b => b.Intent == Plan.PolicyKey).Request == commit.Request, "effect-mismatch");
            revision = commit.Policy.Revision; policies = [commit.Policy];
            Outcome = PolicyMatches(commit.Policy, root.Action) ? GatewayPermissionOutcome.Applied : GatewayPermissionOutcome.Partial;
        }
        Require(lost || (cancel || denied ? Outcome == GatewayPermissionOutcome.NonApplied : Outcome == GatewayPermissionOutcome.Applied), "effect-mismatch");
        CheckState(packet); CheckPolicies(packet); Require(receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
    }
    internal void Activated(GatewayPermissionReceipt receipt)
    {
        Require(stage == 6 && !failed && activation is null && receipt.Evidence == DispatchEvidence.Applied && receipt.Native.Evidence == receipt.Evidence &&
            receipt.Status == SecretStatus.Success && !receipt.Cancelled, "effect-mismatch"); activation = receipt;
    }
    internal async ValueTask ObserveAsync(bool after, GatewayPermissionAttempt[] attempts, CancellationToken token)
    {
        // Preserve the original request selectors before newly committed IDs arrive.
        var prior = Issued;
        var packet = await StepAsync(after ? GatewayPermissionStep.ObserveAfter : GatewayPermissionStep.ObserveBefore, null, token);
        var ingress = packet.Ingress.Payload.Content; var decisions = packet.Access.Payload.Content; var changes = packet.Storage.Payload.Content.Changes;
        bool activate = after && Outcome == GatewayPermissionOutcome.Applied && GatewayPermissionContract.Create(root.Operation);
        Require(attempts.Select(a => a.Row).SequenceEqual(Rows(after)) && decisions.Length == attempts.Length && changes.Length == attempts.Length &&
            ingress.Length == attempts.Length + (activate ? 1 : 0) && packet.Policy.Payload.Content.Commits.Length == (activate ? 1 : 0), "effect-mismatch");
        foreach (var entry in ingress) Require(requests.Add(entry.Request), "effect-mismatch");
        if (activate)
        {
            var commit = packet.Policy.Payload.Content.Commits.Single(); var entry = ingress.Single(e => e.Request == commit.Request);
            Require(activation is not null && entry.Phase == "activation" && entry.Actor == root.Authorities.Setup && entry.Kind == MemberPermissionActorKind.Machine &&
                entry.Authorized && entry.IntentHash == activation.IntentHash && commit.PreviousRevision == revision && commit.Policy.Revision == revision &&
                PolicyMatches(commit.Policy, root.Action), "effect-mismatch");
            policies = [commit.Policy];
        }
        for (int i = 0; i < attempts.Length; i++)
        {
            var attempt = attempts[i]; var row = attempt.Row; var decision = decisions[i]; var actor = Issued.Actors[row.Actor];
            bool allowed = GatewayPermissionContract.Allowed(root, row, after, Outcome);
            Require(attempt.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) && attempt.Complete &&
                attempt.CredentialHash == actor.CredentialHash && attempt.Evidence == (allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected), "effect-mismatch");
            var entry = ingress.SingleOrDefault(e => e.Request == decision.Request);
            Require(entry is not null && entry.Phase == "action" && entry.Actor == actor.Principal && entry.Kind == actor.Kind &&
                entry.CredentialHash == actor.CredentialHash && entry.Organization == actor.Organization && entry.Authorized == allowed &&
                entry.BodyHash == attempt.InputHash && entry.Method == GatewayPermissionClient.Method(row.Action) && entry.Path == GatewayPermissionClient.Path(root, Plan, prior, row), "effect-mismatch");
            Require(decision.Actor == actor.Principal && decision.Kind == actor.Kind && decision.CredentialId == actor.CredentialId &&
                decision.CredentialHash == actor.CredentialHash && decision.Organization == Issued.Id(row.Organization) && decision.Project == Issued.Id(row.Project) &&
                decision.Target == Issued.Id(row.Target) && decision.Revision == revision && decision.Action == row.Action && decision.Allowed == allowed, "effect-mismatch");
            var before = states.GetValueOrDefault(row.Key);
            var expected = changes[i].After;
            Require(changes[i].Request == decision.Request && changes[i].Row == row.Key && changes[i].Before == before &&
                (!allowed ? expected == before : expected is not null && Plan.Matches(row, Issued, expected, row.Action == GatewayPermissionAction.Edit ? 2 : 1)), "effect-mismatch");
            if (expected is null) states.Remove(row.Key); else states[row.Key] = expected;
            if (!allowed) { Require(attempt.Value is null, "effect-mismatch"); continue; }
            if (row.Action == GatewayPermissionAction.Create)
                Require(Issued.Bindings.Single(b => b.Intent == row.Target).Request == decision.Request, "effect-mismatch");
            Require(attempt.Value == expected! with { ConfigRevision = "" }, "effect-mismatch");
        }
        CheckState(packet); CheckPolicies(packet); CheckJoins(packet, after);
        if (after) Require(Original is not null && Original.Native.Evidence == Original.Evidence, "effect-mismatch");
    }
    private bool PolicyMatches(GatewayPermissionPolicy policy, GatewayPermissionAction action) =>
        policy.Actor == Issued.Actors[0].Principal && policy.Kind == MemberPermissionActorKind.User && policy.Organization == root.Organization &&
        policy.Project == "" && policy.Subject == "gateway" && policy.Actions.SequenceEqual([GatewayPermissionContract.Wire(action)]) &&
        policy.Names.Length == 0 && policy.Role == Plan.Slug;
    private void CheckState(GatewayPermissionPacket packet)
    {
        Require(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Row).SequenceEqual(states.Values.OrderBy(s => s.Row)), "effect-mismatch");
        foreach (var state in states.Values)
            Require(packet.Owner.Payload.Content.Remaining.Any(r => r.CanonicalId == state.Target) &&
                state.Target != Issued.Id(Plan.PolicyKey), "effect-mismatch");
    }
    private void CheckPolicies(GatewayPermissionPacket packet) => Require(GatewayPermissionContract.Hash(packet.Policy.Payload.Content.Inventory.OrderBy(p => p.Resource)) ==
        GatewayPermissionContract.Hash(policies.OrderBy(p => p.Resource)), "effect-mismatch");
    private void CheckJoins(GatewayPermissionPacket packet, bool after)
    {
        bool assigned = !GatewayPermissionContract.Create(root.Operation) || after && Outcome == GatewayPermissionOutcome.Applied;
        var expected = Issued.Actors.Select((actor, i) => new GatewayPermissionJoin(actor.Principal,
            actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization, "", Issued.Id(Plan.ActorMembership(i)),
            i == 0 && assigned, i == 0 && assigned ? Issued.Id(Plan.PolicyKey) : "", i == 0 && assigned ? Plan.Slug : "no-access", true, "accepted")).ToArray();
        var actual = packet.Membership.Payload.Content;
        Require(actual.Length == expected.Length && actual.Distinct().Count() == actual.Length && expected.All(actual.Contains), "effect-mismatch");
    }
    private async ValueTask<GatewayPermissionPacket> StepAsync(GatewayPermissionStep step, SecretMaterial? capability, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step); busy = failed = true; stage++;
        try
        {
            var packet = await source.StepAsync(root, step, capability, token);
            if (step == GatewayPermissionStep.Open) issued = new(packet.Owner.Payload.Content.Actors, []);
            verifier.Check(packet, step); ownership.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
            if (step is not (GatewayPermissionStep.Reserve or GatewayPermissionStep.Open))
                Require(packet.Issuer.Payload.Content.Credentials.SequenceEqual(credentials));
            failed = false; return packet;
        }
        finally { busy = false; }
    }
    public async ValueTask DisposeAsync()
    {
        if (closed) return; closed = true;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var packet = await source.StepAsync(root, GatewayPermissionStep.Close, null, deadline.Token);
            verifier.Check(packet, GatewayPermissionStep.Close); ownership.Check(packet, GatewayPermissionStep.Close);
        }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { issued?.Erase(); verifier.Dispose(); }
    }
    private void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) failed = true; GatewayPermissionContract.Require(condition, code); }
}
