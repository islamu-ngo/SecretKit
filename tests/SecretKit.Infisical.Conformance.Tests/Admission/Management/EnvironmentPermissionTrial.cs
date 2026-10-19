using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class EnvironmentPermissionTrial : IAsyncDisposable
{
    private readonly IEnvironmentPermissionSource source;
    private readonly EnvironmentPermissionRoot root;
    private readonly EnvironmentPermissionVerifier verifier;
    private readonly EnvironmentPermissionOwnership ownership;
    private readonly Dictionary<string, EnvironmentPermissionState> states = [];
    private readonly HashSet<string> requests = [];
    private EnvironmentPermissionIssued? issued;
    private EnvironmentPermissionCredential[] credentials = [];
    private EnvironmentPermissionPolicy[] policies = [];
    private string revision = "policy-1";
    private int stage;
    private bool closed, failed, busy;
    private EnvironmentPermissionReceipt? activation;
    internal IEnumerable<EnvironmentPermissionState> States => states.Values;
    internal EnvironmentPermissionPlan Plan { get; }
    internal EnvironmentPermissionIssued Issued => issued ?? throw new NativeCaseFailureException("observer-unavailable");
    internal EnvironmentPermissionReceipt? Original { get; private set; }
    internal EnvironmentPermissionOutcome Outcome { get; private set; }
    private EnvironmentPermissionTrial(IEnvironmentPermissionSource source, EnvironmentPermissionRoot root)
    { this.source = source; this.root = root; Plan = new(root); verifier = new(root); ownership = new(root, Plan); }
    internal static async ValueTask<EnvironmentPermissionTrial> OpenAsync(IEnvironmentPermissionSource source, EnvironmentPermissionRoot root,
        SecretMaterial capability, Action<EnvironmentPermissionTrial> retain, CancellationToken token)
    {
        EnvironmentPermissionContract.Require(source.Identity == root.Source && source.Kind == root.Kind && Enum.IsDefined(root.Kind) &&
            EnvironmentPermissionContract.Operations.Contains(root.Operation) && root.ScopeProfile == EnvironmentPermissionContract.Scope(root.Operation) &&
            root.ActorKind == EnvironmentPermissionContract.ActorKind(root.Operation) && EnvironmentPermissionContract.Actions(root.ScopeProfile).Contains(root.Action) &&
            EnvironmentPermissionContract.Gate(root.ScopeProfile, root.Action) is null && root.Variant == EnvironmentPermissionContract.Variant(root.Action) &&
            EnvironmentPermissionContract.Boundaries.Contains(root.Boundary) && root.Authorities.All.Distinct().Count() == 5 &&
            root.Authorities.All.All(MemberPermissionContract.Text) && !root.Authorities.All.Contains(root.Source) &&
            root.Profile.Pins.All(p => p.Writer != root.Source && !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(MemberPermissionContract.Text), "missing-input");
        var trial = new EnvironmentPermissionTrial(source, root);
        retain(trial); // Root recovery exists BEFORE enrollment or any creation can fail.
        _ = await trial.StepAsync(EnvironmentPermissionStep.Reserve, capability, token);
        var packet = await trial.StepAsync(EnvironmentPermissionStep.Open, null, token);
        var v = trial.Issued; var p = trial.Plan;
        trial.Require(v.Actors.Length == (root.ScopeProfile == EnvironmentPermissionScope.Organization ? 4 : 3));
        trial.credentials = packet.Issuer.Payload.Content.Credentials;
        trial.Require(trial.credentials.Select(c => c.Id).Distinct().Count() == trial.credentials.Length);
        for (int i = 0; i < v.Actors.Length; i++)
        {
            var actor = v.Actors[i];
            trial.Require(actor.Principal == v.Id(p.ActorKey(i)) && actor.Kind == p.ActorKind(i) && actor.Organization == v.Id(p.ActorScope(i)) &&
                actor.Owned == !p.ActorKey(i).StartsWith("@", StringComparison.Ordinal) &&
                (actor.Owned ? actor.Credential.Length > 0 && EnvironmentPermissionContract.RawHash(actor.Credential) == actor.CredentialHash &&
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
        foreach (var row in p.Rows.Where(r => r.Window != "copy" && p.InitiallyPresent(r))) trial.states.Add(row.Key, p.Initial(row, v));
        var deleted = p.DeletedEnvironment;
        var tombstone = packet.Storage.Payload.Content.Inventory.Single(s => s.Row == deleted.Key);
        trial.Require(tombstone with { Deleted = false, SoftDeletedAt = null, DeleteAfter = null, DeletedBy = null } == p.Initial(deleted, v) && tombstone.Deleted &&
            DateTimeOffset.TryParse(tombstone.SoftDeletedAt, out _) && DateTimeOffset.TryParse(tombstone.DeleteAfter, out _) &&
            tombstone.DeletedBy == "identity:" + root.Authorities.Setup, "effect-mismatch");
        trial.states.Add(deleted.Key, tombstone);
        trial.policies = packet.Policy.Payload.Content.Inventory;
        trial.Require(trial.policies.Length == (EnvironmentPermissionContract.Create(root.Operation) ? 0 : 1));
        foreach (var policy in trial.policies) trial.Require(trial.PolicyMatches(policy, EnvironmentPermissionContract.Baseline(root)));
        trial.CheckState(packet); trial.CheckJoins(packet, false);
        return trial;
    }
    internal EnvironmentPermissionRow[] Rows(bool after) => Plan.Window(after, Outcome);
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        var packet = await StepAsync(after ? EnvironmentPermissionStep.After : EnvironmentPermissionStep.Before, null, token);
        if (after && EnvironmentPermissionContract.Template(root.Operation) && Outcome == EnvironmentPermissionOutcome.Applied)
        {
            foreach (var row in Rows(true).Where(Plan.InitiallyPresent)) states.Add(row.Key, Plan.Initial(row, Issued));
            var config = Plan.ConfigurationEnvironment; states.Add(config.Key, Plan.Initial(config, Issued));
        }
        CheckState(packet);
    }
    internal async ValueTask ArmAsync(CancellationToken token)
    {
        var packet = await StepAsync(EnvironmentPermissionStep.Arm, null, token); CheckState(packet); CheckPolicies(packet);
    }
    internal async ValueTask SettleAsync(EnvironmentPermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Native.Evidence == receipt.Evidence, "effect-mismatch"); Original = receipt;
        string originalPath = EnvironmentPermissionEffects.OriginalPath(root, Plan, Issued);
        var packet = await StepAsync(EnvironmentPermissionStep.Settle, null, token);
        bool cancel = root.Boundary == "cancellation-boundary", denied = root.Boundary == "denied-authority", lost = root.Boundary == "lost-response-no-replay";
        var ingress = packet.Ingress.Payload.Content; var commits = packet.Policy.Payload.Content.Commits;
        Require(ingress.Length == (cancel ? 0 : 1) && commits.Length <= 1 && (!(cancel || denied) || commits.Length == 0) &&
            packet.Storage.Payload.Content.Changes.Length == 0 && packet.Access.Payload.Content.Length == 0 &&
            receipt.Evidence == (cancel ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected : lost ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancel || lost) && (receipt.Cancelled ? receipt.Status is null : receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var entry in ingress)
            Require(requests.Add(entry.Request) && entry.Phase == "original" && entry.Actor == (denied ? root.Authorities.Denied : root.Authorities.Administrative) &&
                entry.Kind == MemberPermissionActorKind.Machine && entry.Organization == root.Organization && entry.Authorized == !denied &&
                entry.IntentHash == receipt.IntentHash && entry.Path == originalPath && entry.Method == (EnvironmentPermissionContract.Create(root.Operation) ? "POST" : "PATCH"), "effect-mismatch");
        Outcome = EnvironmentPermissionOutcome.NonApplied;
        if (commits.Length == 1)
        {
            var commit = commits[0];
            Require(commit.Request == ingress.Single().Request && commit.PreviousRevision == revision && commit.Policy.Revision != revision &&
                commit.Policy.Resource == Issued.Id(Plan.PolicyKey) && commit.Policy.Configuration == ingress.Single().BodyHash, "effect-mismatch");
            if (EnvironmentPermissionContract.Create(root.Operation))
                Require(Issued.Bindings.Single(b => b.Intent == Plan.PolicyKey).Request == commit.Request, "effect-mismatch");
            revision = commit.Policy.Revision; policies = [commit.Policy];
            Outcome = PolicyMatches(commit.Policy, root.Action) ? EnvironmentPermissionOutcome.Applied : EnvironmentPermissionOutcome.Partial;
        }
        Require(lost || (cancel || denied ? Outcome == EnvironmentPermissionOutcome.NonApplied : Outcome == EnvironmentPermissionOutcome.Applied), "effect-mismatch");
        CheckState(packet); CheckPolicies(packet); Require(receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
    }
    internal void Activated(EnvironmentPermissionReceipt receipt)
    {
        Require(stage == 6 && !failed && activation is null && receipt.Evidence == DispatchEvidence.Applied && receipt.Native.Evidence == receipt.Evidence &&
            receipt.Status == SecretStatus.Success && !receipt.Cancelled, "effect-mismatch"); activation = receipt;
    }
    internal async ValueTask ObserveAsync(bool after, EnvironmentPermissionAttempt[] attempts, CancellationToken token)
    {
        // Preserve the original request selectors before newly committed IDs arrive.
        var prior = Issued;
        var packet = await StepAsync(after ? EnvironmentPermissionStep.ObserveAfter : EnvironmentPermissionStep.ObserveBefore, null, token);
        var ingress = packet.Ingress.Payload.Content; var decisions = packet.Access.Payload.Content; var changes = packet.Storage.Payload.Content.Changes;
        bool activate = after && Outcome == EnvironmentPermissionOutcome.Applied && (EnvironmentPermissionContract.Template(root.Operation) ||
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
            policies = EnvironmentPermissionContract.Template(root.Operation) ? [.. policies, commit.Policy] : [commit.Policy];
        }
        for (int i = 0; i < attempts.Length; i++)
        {
            var attempt = attempts[i]; var row = attempt.Row; var decision = decisions[i]; var actor = Issued.Actors[row.Actor];
            bool allowed = EnvironmentPermissionContract.Allowed(root, row, after, Outcome), read = row.Action == EnvironmentPermissionAction.Read;
            Require(attempt.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) && attempt.Complete &&
                attempt.CredentialHash == actor.CredentialHash && attempt.Evidence == (read ? null : allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected), "effect-mismatch");
            var entry = ingress.SingleOrDefault(e => e.Request == decision.Request);
            Require(entry is not null && entry.Phase == "action" && entry.Actor == actor.Principal && entry.Kind == actor.Kind &&
                entry.CredentialHash == actor.CredentialHash && entry.Organization == actor.Organization && entry.Authorized == allowed &&
                entry.Method == EnvironmentPermissionClient.Method(row.Action) && entry.Path == EnvironmentPermissionClient.Path(root, Plan, prior, row), "effect-mismatch");
            Require(decision.Actor == actor.Principal && decision.Kind == actor.Kind && decision.CredentialId == actor.CredentialId &&
                decision.CredentialHash == actor.CredentialHash && decision.Organization == Issued.Id(row.Organization) && decision.Project == Issued.Id(row.Project) &&
                decision.Target == Issued.Id(row.Target) && decision.Revision == revision && decision.Action == row.Action && decision.Allowed == allowed, "effect-mismatch");
            var before = states.GetValueOrDefault(row.Key);
            var expected = !allowed ? before : row.Action switch
            {
                EnvironmentPermissionAction.Create => Plan.Initial(row, Issued),
                EnvironmentPermissionAction.Delete => null,
                EnvironmentPermissionAction.Edit => before! with { Name = row.Name + "-edited", Slug = row.Slug + "-v2", Position = 2.75, Deleted = false, Version = 2 },
                _ => before
            };
            Require(changes[i] == new EnvironmentPermissionChange(decision.Request, row.Key, before, expected), "effect-mismatch");
            if (expected is null) states.Remove(row.Key); else states[row.Key] = expected;
            if (!allowed) { Require(attempt.Value is null, "effect-mismatch"); continue; }
            if (row.Action == EnvironmentPermissionAction.Create)
                Require(Issued.Bindings.Single(b => b.Intent == row.Target).Request == decision.Request, "effect-mismatch");
            Require(attempt.Value == (row.Action == EnvironmentPermissionAction.Delete ? before : expected), "effect-mismatch");
        }
        CheckState(packet); CheckPolicies(packet); CheckJoins(packet, after);
        if (after) Require(Original is not null && Original.Native.Evidence == Original.Evidence, "effect-mismatch");
    }
    private bool PolicyMatches(EnvironmentPermissionPolicy policy, EnvironmentPermissionAction action) =>
        policy.Actor == Issued.Actors[0].Principal && policy.Kind == root.ActorKind && policy.Organization == root.Organization &&
        policy.Project == (root.ScopeProfile == EnvironmentPermissionScope.Organization ? "" :
            policy.Resource == Issued.Id(EnvironmentPermissionPlan.CopiedRole) ? Issued.Id(EnvironmentPermissionPlan.CopyProject) : Issued.Id(EnvironmentPermissionPlan.Project)) &&
        policy.Subject == "environments" && policy.Actions.SequenceEqual([EnvironmentPermissionContract.Wire(action)]) && policy.Names.Length == 0 && policy.Role == Plan.Slug;
    private void CheckState(EnvironmentPermissionPacket packet)
    {
        Require(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Row).SequenceEqual(states.Values.OrderBy(s => s.Row)), "effect-mismatch");
        foreach (var state in states.Values)
            Require(packet.Owner.Payload.Content.Remaining.Any(r => r.CanonicalId == state.Target) &&
                state.Target != Issued.Id(Plan.PolicyKey) && state.Target != Issued.Id(EnvironmentPermissionPlan.CopiedRole), "effect-mismatch");
    }
    private void CheckPolicies(EnvironmentPermissionPacket packet) => Require(EnvironmentPermissionContract.Hash(packet.Policy.Payload.Content.Inventory.OrderBy(p => p.Resource)) ==
        EnvironmentPermissionContract.Hash(policies.OrderBy(p => p.Resource)), "effect-mismatch");
    private void CheckJoins(EnvironmentPermissionPacket packet, bool after)
    {
        bool copy = after && EnvironmentPermissionContract.Template(root.Operation) && Outcome == EnvironmentPermissionOutcome.Applied;
        bool assigned = !EnvironmentPermissionContract.Create(root.Operation) || after && Outcome == EnvironmentPermissionOutcome.Applied && !copy;
        var expected = Issued.Actors.Select((actor, i) => new EnvironmentPermissionJoin(actor.Principal,
            actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization,
            root.ScopeProfile == EnvironmentPermissionScope.Project ? Issued.Id(EnvironmentPermissionPlan.Project) : "", Issued.Id(Plan.ActorMembership(i)),
            i == 0 && assigned, i == 0 && assigned ? Issued.Id(Plan.PolicyKey) : "", i == 0 && assigned ? Plan.Slug : "no-access", true, "accepted")).ToList();
        if (copy) expected.Add(new(Issued.Actors[0].Principal, "user", root.Organization, Issued.Id(EnvironmentPermissionPlan.CopyProject),
            Issued.Id(Plan.ActorMembership(0, true)), true, Issued.Id(EnvironmentPermissionPlan.CopiedRole), Plan.Slug, true, "accepted"));
        var actual = packet.Membership.Payload.Content;
        Require(actual.Length == expected.Count && actual.Distinct().Count() == actual.Length && expected.All(actual.Contains), "effect-mismatch");
    }
    private async ValueTask<EnvironmentPermissionPacket> StepAsync(EnvironmentPermissionStep step, SecretMaterial? capability, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step); busy = failed = true; stage++;
        try
        {
            var packet = await source.StepAsync(root, step, capability, token);
            if (step == EnvironmentPermissionStep.Open) issued = new(packet.Owner.Payload.Content.Actors, []);
            verifier.Check(packet, step); ownership.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
            if (step is not (EnvironmentPermissionStep.Reserve or EnvironmentPermissionStep.Open))
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
            var packet = await source.StepAsync(root, EnvironmentPermissionStep.Close, null, deadline.Token);
            verifier.Check(packet, EnvironmentPermissionStep.Close); ownership.Check(packet, EnvironmentPermissionStep.Close);
        }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { issued?.Erase(); verifier.Dispose(); }
    }
    private void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) failed = true; EnvironmentPermissionContract.Require(condition, code); }
}
