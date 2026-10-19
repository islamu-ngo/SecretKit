using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class ProxyPermissionTrial : IAsyncDisposable
{
    private readonly IProxyPermissionSource source;
    private readonly ProxyPermissionRoot root;
    private readonly ProxyPermissionVerifier verifier;
    private readonly ProxyPermissionOwnership ownership;
    private readonly Dictionary<string, ProxyPermissionState> states = [];
    private readonly HashSet<string> requests = [];
    private ProxyPermissionIssued? issued;
    private ProxyPermissionCredential[] credentials = [];
    private ProxyPermissionPolicy[] policies = [];
    private string revision = "policy-1";
    private int stage;
    private bool closed, failed, busy;
    private ProxyPermissionReceipt? activation;
    internal IEnumerable<ProxyPermissionState> States => states.Values;
    internal ProxyPermissionPlan Plan { get; }
    internal ProxyPermissionIssued Issued => issued ?? throw new NativeCaseFailureException("observer-unavailable");
    internal ProxyPermissionReceipt? Original { get; private set; }
    internal ProxyPermissionOutcome Outcome { get; private set; }
    private ProxyPermissionTrial(IProxyPermissionSource source, ProxyPermissionRoot root)
    { this.source = source; this.root = root; Plan = new(root); verifier = new(root); ownership = new(root, Plan); }
    internal static async ValueTask<ProxyPermissionTrial> OpenAsync(IProxyPermissionSource source, ProxyPermissionRoot root,
        SecretMaterial capability, Action<ProxyPermissionTrial> retain, CancellationToken token)
    {
        ProxyPermissionContract.Require(source.Identity == root.Source && source.Kind == root.Kind && Enum.IsDefined(root.Kind) &&
            ProxyPermissionContract.Operations.Contains(root.Operation) && root.ScopeProfile == ProxyPermissionContract.Scope(root.Operation) &&
            root.ActorKind == ProxyPermissionContract.ActorKind(root.Operation) && ProxyPermissionContract.Actions(root.ScopeProfile).Contains(root.Action) &&
            ProxyPermissionContract.Gate(root.ScopeProfile, root.Action) is null && root.Variant == ProxyPermissionContract.Variant(root.Action) &&
            ProxyPermissionContract.Boundaries.Contains(root.Boundary) && root.Authorities.All.Distinct().Count() == 5 &&
            root.Authorities.All.All(MemberPermissionContract.Text) && !root.Authorities.All.Contains(root.Source) &&
            root.Profile.Pins.All(p => p.Writer != root.Source && !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(MemberPermissionContract.Text), "missing-input");
        var trial = new ProxyPermissionTrial(source, root);
        retain(trial); // Root recovery exists BEFORE enrollment or any creation can fail.
        _ = await trial.StepAsync(ProxyPermissionStep.Reserve, capability, token);
        var packet = await trial.StepAsync(ProxyPermissionStep.Open, null, token);
        var v = trial.Issued; var p = trial.Plan;
        trial.Require(v.Actors.Length == (root.ScopeProfile == ProxyPermissionScope.Organization ? 4 : 3));
        trial.credentials = packet.Issuer.Payload.Content.Credentials;
        trial.Require(trial.credentials.Select(c => c.Id).Distinct().Count() == trial.credentials.Length);
        for (int i = 0; i < v.Actors.Length; i++)
        {
            var actor = v.Actors[i];
            trial.Require(actor.Principal == v.Id(p.ActorKey(i)) && actor.Kind == p.ActorKind(i) && actor.Organization == v.Id(p.ActorScope(i)) &&
                actor.Owned == !p.ActorKey(i).StartsWith("@", StringComparison.Ordinal) &&
                (actor.Owned ? actor.Credential.Length > 0 && ProxyPermissionContract.RawHash(actor.Credential) == actor.CredentialHash &&
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
        foreach (var row in p.Rows.Where(r => r.Window != "copy" && p.InitiallyPresent(r)))
        {
            var state = packet.Storage.Payload.Content.Inventory.SingleOrDefault(s => s.Row == row.Key);
            trial.Require(state is not null && p.Matches(row, v, state, 1), "effect-mismatch"); trial.states.Add(row.Key, state!);
        }
        trial.policies = packet.Policy.Payload.Content.Inventory;
        trial.Require(trial.policies.Length == (ProxyPermissionContract.Create(root.Operation) ? 0 : 1));
        foreach (var policy in trial.policies) trial.Require(trial.PolicyMatches(policy, ProxyPermissionContract.Baseline(root)));
        trial.CheckState(packet); trial.CheckJoins(packet, false);
        return trial;
    }
    internal ProxyPermissionRow[] Rows(bool after) => Plan.Window(after, Outcome);
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        var packet = await StepAsync(after ? ProxyPermissionStep.After : ProxyPermissionStep.Before, null, token);
        if (after && ProxyPermissionContract.Template(root.Operation) && Outcome == ProxyPermissionOutcome.Applied)
        {
            foreach (var row in Rows(true).Where(Plan.InitiallyPresent))
            {
                var state = packet.Storage.Payload.Content.Inventory.SingleOrDefault(s => s.Row == row.Key);
                Require(state is not null && Plan.Matches(row, Issued, state, 1), "effect-mismatch"); states.Add(row.Key, state!);
            }
            var template = packet.Storage.Payload.Content.Templates.SingleOrDefault();
            Require(template is not null && template.Project == Issued.Id(ProxyPermissionPlan.CopyProject) &&
                template.Environment == "witness" && template.Position == 1.5 && template.Configuration == policies.Single().Configuration, "effect-mismatch");
        }
        CheckState(packet);
    }
    internal async ValueTask ArmAsync(CancellationToken token)
    {
        var packet = await StepAsync(ProxyPermissionStep.Arm, null, token); CheckState(packet); CheckPolicies(packet);
    }
    internal async ValueTask SettleAsync(ProxyPermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Native.Evidence == receipt.Evidence, "effect-mismatch"); Original = receipt;
        string originalPath = ProxyPermissionEffects.OriginalPath(root, Plan, Issued);
        var packet = await StepAsync(ProxyPermissionStep.Settle, null, token);
        bool cancel = root.Boundary == "cancellation-boundary", denied = root.Boundary == "denied-authority", lost = root.Boundary == "lost-response-no-replay";
        var ingress = packet.Ingress.Payload.Content.Window; var commits = packet.Policy.Payload.Content.Commits;
        Require(ingress.Length == (cancel ? 0 : 1) && commits.Length <= 1 && (!(cancel || denied) || commits.Length == 0) &&
            packet.Storage.Payload.Content.Changes.Length == 0 && packet.Access.Payload.Content.Length == 0 &&
            receipt.Evidence == (cancel ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected : lost ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancel || lost) && (receipt.Cancelled ? receipt.Status is null : receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var entry in ingress)
            Require(requests.Add(entry.Request) && entry.Phase == "original" && entry.Actor == (denied ? root.Authorities.Denied : root.Authorities.Administrative) &&
                entry.Kind == MemberPermissionActorKind.Machine && entry.Organization == root.Organization && entry.Authorized == !denied &&
                entry.IntentHash == receipt.IntentHash && entry.Path == originalPath && entry.Method == (ProxyPermissionContract.Create(root.Operation) ? "POST" : "PATCH"), "effect-mismatch");
        Outcome = ProxyPermissionOutcome.NonApplied;
        if (commits.Length == 1)
        {
            var commit = commits[0];
            Require(commit.Request == ingress.Single().Request && commit.PreviousRevision == revision && commit.Policy.Revision != revision &&
                commit.Policy.Resource == Issued.Id(Plan.PolicyKey) && commit.Policy.Configuration == ingress.Single().BodyHash, "effect-mismatch");
            if (ProxyPermissionContract.Create(root.Operation))
                Require(Issued.Bindings.Single(b => b.Intent == Plan.PolicyKey).Request == commit.Request, "effect-mismatch");
            revision = commit.Policy.Revision; policies = [commit.Policy];
            Outcome = PolicyMatches(commit.Policy, root.Action) ? ProxyPermissionOutcome.Applied : ProxyPermissionOutcome.Partial;
        }
        Require(lost || (cancel || denied ? Outcome == ProxyPermissionOutcome.NonApplied : Outcome == ProxyPermissionOutcome.Applied), "effect-mismatch");
        CheckState(packet); CheckPolicies(packet); Require(receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
    }
    internal void Activated(ProxyPermissionReceipt receipt)
    {
        Require(stage == 6 && !failed && activation is null && receipt.Evidence == DispatchEvidence.Applied && receipt.Native.Evidence == receipt.Evidence &&
            receipt.Status == SecretStatus.Success && !receipt.Cancelled, "effect-mismatch"); activation = receipt;
    }
    internal async ValueTask ObserveAsync(bool after, ProxyPermissionAttempt[] attempts, CancellationToken token)
    {
        // Preserve the original request selectors before newly committed IDs arrive.
        var prior = Issued;
        var packet = await StepAsync(after ? ProxyPermissionStep.ObserveAfter : ProxyPermissionStep.ObserveBefore, null, token);
        var ingress = packet.Ingress.Payload.Content.Window; var decisions = packet.Access.Payload.Content; var changes = packet.Storage.Payload.Content.Changes;
        bool activate = after && Outcome == ProxyPermissionOutcome.Applied && (ProxyPermissionContract.Template(root.Operation) ||
            root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal) || root.Operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal));
        Require(attempts.Select(a => a.Row).SequenceEqual(Rows(after)) && decisions.Length == attempts.Length && changes.Length == attempts.Length &&
            ingress.Length == attempts.Length + (activate ? 1 : 0) && packet.Policy.Payload.Content.Commits.Length == (activate ? 1 : 0), "effect-mismatch");
        foreach (var entry in ingress) Require(requests.Add(entry.Request), "effect-mismatch");
        if (activate)
        {
            var commit = packet.Policy.Payload.Content.Commits.Single(); var entry = ingress.Single(e => e.Request == commit.Request);
            Require(activation is not null && entry.Phase == "activation" && entry.Actor == root.Authorities.Setup && entry.Kind == MemberPermissionActorKind.Machine &&
                entry.Authorized && entry.IntentHash == activation.IntentHash && commit.PreviousRevision == revision && commit.Policy.Revision == revision &&
                PolicyMatches(commit.Policy, root.Action) && commit.Policy.Configuration == policies.Single().Configuration, "effect-mismatch");
            policies = ProxyPermissionContract.Template(root.Operation) ? [.. policies, commit.Policy] : [commit.Policy];
        }
        for (int i = 0; i < attempts.Length; i++)
        {
            var attempt = attempts[i]; var row = attempt.Row; var decision = decisions[i]; var actor = Issued.Actors[row.Actor];
            bool allowed = ProxyPermissionContract.Allowed(root, row, after, Outcome), read = row.Action == ProxyPermissionAction.Read;
            Require(attempt.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) && attempt.Complete &&
                attempt.CredentialHash == actor.CredentialHash && attempt.Evidence == (read ? null : allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected), "effect-mismatch");
            var entry = ingress.SingleOrDefault(e => e.Request == decision.Request);
            Require(entry is not null && entry.Phase == "action" && entry.Actor == actor.Principal && entry.Kind == actor.Kind &&
                entry.CredentialHash == actor.CredentialHash && entry.Organization == actor.Organization && entry.Authorized == allowed &&
                entry.BodyHash == attempt.InputHash && entry.Method == ProxyPermissionClient.Method(row.Action) && entry.Path == ProxyPermissionClient.Path(root, Plan, prior, row), "effect-mismatch");
            Require(decision.Actor == actor.Principal && decision.Kind == actor.Kind && decision.CredentialId == actor.CredentialId &&
                decision.CredentialHash == actor.CredentialHash && decision.Organization == Issued.Id(row.Organization) && decision.Project == Issued.Id(row.Project) &&
                decision.Target == Issued.Id(row.Target) && decision.Revision == revision && decision.Action == row.Action && decision.Allowed == allowed, "effect-mismatch");
            var before = states.GetValueOrDefault(row.Key);
            var expected = changes[i].After;
            Require(changes[i].Request == decision.Request && changes[i].Row == row.Key && changes[i].Before == before &&
                (!allowed || read ? expected == before : row.Action == ProxyPermissionAction.Delete ? expected is null :
                    expected is not null && Plan.Matches(row, Issued, expected, row.Action == ProxyPermissionAction.Edit ? 2 : 1)), "effect-mismatch");
            if (expected is null) states.Remove(row.Key); else states[row.Key] = expected;
            if (!allowed) { Require(attempt.Value is null, "effect-mismatch"); continue; }
            if (row.Action == ProxyPermissionAction.Create)
                Require(Issued.Bindings.Single(b => b.Intent == row.Target).Request == decision.Request, "effect-mismatch");
            Require(attempt.Value == (row.Action == ProxyPermissionAction.Delete ? null : expected), "effect-mismatch");
        }
        CheckState(packet); CheckPolicies(packet); CheckJoins(packet, after);
        if (after) Require(Original is not null && Original.Native.Evidence == Original.Evidence, "effect-mismatch");
    }
    private bool PolicyMatches(ProxyPermissionPolicy policy, ProxyPermissionAction action) =>
        policy.Actor == Issued.Actors[0].Principal && policy.Kind == root.ActorKind && policy.Organization == root.Organization &&
        policy.Project == (root.ScopeProfile == ProxyPermissionScope.Organization ? "" :
            policy.Resource == Issued.Id(ProxyPermissionPlan.CopiedRole) ? Issued.Id(ProxyPermissionPlan.CopyProject) : Issued.Id(ProxyPermissionPlan.Project)) &&
        policy.Subject == "proxied-services" && policy.Actions.SequenceEqual([ProxyPermissionContract.Wire(action)]) && policy.Names.SequenceEqual(["witness", "/closed"]) && policy.Role == Plan.Slug;
    private void CheckState(ProxyPermissionPacket packet)
    {
        Require(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Row).SequenceEqual(states.Values.OrderBy(s => s.Row)), "effect-mismatch");
        foreach (var state in states.Values)
            Require(packet.Owner.Payload.Content.Remaining.Any(r => r.CanonicalId == state.Target) &&
                state.Target != Issued.Id(Plan.PolicyKey) && state.Target != Issued.Id(ProxyPermissionPlan.CopiedRole), "effect-mismatch");
    }
    private void CheckPolicies(ProxyPermissionPacket packet) => Require(ProxyPermissionContract.Hash(packet.Policy.Payload.Content.Inventory.OrderBy(p => p.Resource)) ==
        ProxyPermissionContract.Hash(policies.OrderBy(p => p.Resource)), "effect-mismatch");
    private void CheckJoins(ProxyPermissionPacket packet, bool after)
    {
        bool copy = after && ProxyPermissionContract.Template(root.Operation) && Outcome == ProxyPermissionOutcome.Applied;
        bool assigned = !ProxyPermissionContract.Create(root.Operation) || after && Outcome == ProxyPermissionOutcome.Applied && !copy;
        var expected = Issued.Actors.Select((actor, i) => new ProxyPermissionJoin(actor.Principal,
            actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization,
            root.ScopeProfile == ProxyPermissionScope.Project ? Issued.Id(ProxyPermissionPlan.Project) : "", Issued.Id(Plan.ActorMembership(i)),
            i == 0 && assigned, i == 0 && assigned ? Issued.Id(Plan.PolicyKey) : "", i == 0 && assigned ? Plan.Slug : "no-access", true, "accepted")).ToList();
        if (copy) expected.Add(new(Issued.Actors[0].Principal, "user", root.Organization, Issued.Id(ProxyPermissionPlan.CopyProject),
            Issued.Id(Plan.ActorMembership(0, true)), true, Issued.Id(ProxyPermissionPlan.CopiedRole), Plan.Slug, true, "accepted"));
        var actual = packet.Membership.Payload.Content;
        Require(actual.Length == expected.Count && actual.Distinct().Count() == actual.Length && expected.All(actual.Contains), "effect-mismatch");
    }
    private async ValueTask<ProxyPermissionPacket> StepAsync(ProxyPermissionStep step, SecretMaterial? capability, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step); busy = failed = true; stage++;
        try
        {
            var packet = await source.StepAsync(root, step, capability, token);
            if (step == ProxyPermissionStep.Open) issued = new(packet.Owner.Payload.Content.Actors, []);
            verifier.Check(packet, step); ownership.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
            if (step is not (ProxyPermissionStep.Reserve or ProxyPermissionStep.Open))
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
            var packet = await source.StepAsync(root, ProxyPermissionStep.Close, null, deadline.Token);
            verifier.Check(packet, ProxyPermissionStep.Close); ownership.Check(packet, ProxyPermissionStep.Close);
        }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { issued?.Erase(); verifier.Dispose(); }
    }
    private void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) failed = true; ProxyPermissionContract.Require(condition, code); }
}
