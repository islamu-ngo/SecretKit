using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class ValidationPermissionTrial : IAsyncDisposable
{
    private readonly IValidationPermissionSource source;
    private readonly ValidationPermissionRoot root;
    private readonly ValidationPermissionVerifier verifier;
    private readonly ValidationPermissionOwnership ownership;
    private readonly Dictionary<string, ValidationPermissionState> states = [];
    private readonly HashSet<string> requests = [];
    private readonly ValidationPermissionCausality causal = new();
    private readonly ValidationPermissionHistory history = new();
    private ValidationPermissionIssued? issued;
    private ValidationPermissionCredential[] credentials = [];
    private ValidationPermissionPolicy[] policies = [];
    private string revision = "policy-1";
    private int stage;
    private bool closed, failed, busy;
    private ValidationPermissionReceipt? activation;
    internal IEnumerable<ValidationPermissionState> States => states.Values;
    internal ValidationPermissionPlan Plan { get; }
    internal ValidationPermissionIssued Issued => issued ?? throw new NativeCaseFailureException("observer-unavailable");
    internal ValidationPermissionReceipt? Original { get; private set; }
    internal ValidationPermissionOutcome Outcome { get; private set; }
    private ValidationPermissionTrial(IValidationPermissionSource source, ValidationPermissionRoot root)
    { this.source = source; this.root = root; Plan = new(root); verifier = new(root); ownership = new(root, Plan); }
    internal static async ValueTask<ValidationPermissionTrial> OpenAsync(IValidationPermissionSource source, ValidationPermissionRoot root,
        SecretMaterial capability, Action<ValidationPermissionTrial> retain, CancellationToken token)
    {
        ValidationPermissionContract.Require(source.Identity == root.Source && source.Kind == root.Kind && Enum.IsDefined(root.Kind) &&
            ValidationPermissionContract.Operations.Contains(root.Operation) && root.ScopeProfile == ValidationPermissionContract.Scope(root.Operation) &&
            root.ActorKind == ValidationPermissionContract.ActorKind(root.Operation) && ValidationPermissionContract.Actions(root.ScopeProfile).Contains(root.Action) &&
            ValidationPermissionContract.Gate(root.ScopeProfile, root.Action) is null && root.Variant == ValidationPermissionContract.Variant(root.Action) &&
            ValidationPermissionContract.Boundaries.Contains(root.Boundary) && root.Authorities.All.Distinct().Count() == 5 &&
            root.Authorities.All.All(MemberPermissionContract.Text) && !root.Authorities.All.Contains(root.Source) &&
            root.Profile.Pins.All(p => p.Writer != root.Source && !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(MemberPermissionContract.Text), "missing-input");
        var trial = new ValidationPermissionTrial(source, root);
        retain(trial); // Root recovery exists BEFORE enrollment or any creation can fail.
        _ = await trial.StepAsync(ValidationPermissionStep.Reserve, capability, token);
        var packet = await trial.StepAsync(ValidationPermissionStep.Open, null, token);
        var v = trial.Issued; var p = trial.Plan;
        trial.Require(v.Actors.Length == 4);
        trial.credentials = packet.Issuer.Payload.Content.Credentials;
        trial.Require(trial.credentials.Select(c => c.Id).Distinct().Count() == trial.credentials.Length);
        for (int i = 0; i < v.Actors.Length; i++)
        {
            var actor = v.Actors[i];
            trial.Require(actor.Principal == v.Id(p.ActorKey(i)) && actor.Kind == p.ActorKind(i) && actor.Organization == v.Id(p.ActorScope(i)) &&
                actor.Owned == !p.ActorKey(i).StartsWith("@", StringComparison.Ordinal) &&
                (actor.Owned ? actor.Credential.Length > 0 && ValidationPermissionContract.RawHash(actor.Credential) == actor.CredentialHash &&
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
        trial.policies = packet.Policy.Payload.Content.Inventory;
        trial.Require(trial.policies.Length == (ValidationPermissionContract.Create(root.Operation) ? 0 : 1));
        foreach (var policy in trial.policies) trial.Require(trial.PolicyMatches(policy, ValidationPermissionContract.Baseline(root)));
        trial.CheckState(packet); trial.CheckJoins(packet, false); trial.causal.Open(packet, p, v);
        return trial;
    }
    internal ValidationPermissionRow[] Rows(bool after) => Plan.Window(after, Outcome);
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        var packet = await StepAsync(after ? ValidationPermissionStep.After : ValidationPermissionStep.Before, null, token);
        if (after && ValidationPermissionContract.Template(root.Operation) && Outcome == ValidationPermissionOutcome.Applied)
        {
            foreach (var row in Rows(true).Where(Plan.InitiallyPresent)) states.Add(row.Key, Plan.Initial(row, Issued));
            causal.CopySeeds(packet, Plan, Issued);
            Require(packet.Storage.Payload.Content.Configurations.SequenceEqual([new ValidationPermissionCopiedEnvironment(Issued.Id(ValidationPermissionPlan.CopyProject), Issued.Id("template-environment"),
                "Development", "dev", 1.5, Issued.Id(Plan.PolicyKey), policies.Single().Configuration)]), "effect-mismatch");
        }
        CheckState(packet);
    }
    internal async ValueTask ArmAsync(CancellationToken token)
    {
        var packet = await StepAsync(ValidationPermissionStep.Arm, null, token); CheckState(packet); CheckPolicies(packet);
    }
    internal async ValueTask SettleAsync(ValidationPermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Native.Evidence == receipt.Evidence, "effect-mismatch"); Original = receipt;
        string originalPath = ValidationPermissionEffects.OriginalPath(root, Plan, Issued);
        var packet = await StepAsync(ValidationPermissionStep.Settle, null, token);
        bool cancel = root.Boundary == "cancellation-boundary", denied = root.Boundary == "denied-authority", lost = root.Boundary == "lost-response-no-replay";
        var ingress = packet.Ingress.Payload.Content.Events; var commits = packet.Policy.Payload.Content.Commits;
        Require(ingress.Length == (cancel ? 0 : 1) && commits.Length <= 1 && (!(cancel || denied) || commits.Length == 0) &&
            packet.Storage.Payload.Content.Changes.Length == 0 && packet.Access.Payload.Content.Rules.Length == 0 && packet.Access.Payload.Content.Writes.Length == 0 &&
            receipt.Evidence == (cancel ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected : lost ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancel || lost) && (receipt.Cancelled ? receipt.Status is null : receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var entry in ingress)
            Require(requests.Add(entry.Request) && entry.Phase == "original" && entry.Actor == (denied ? root.Authorities.Denied : root.Authorities.Administrative) &&
                entry.Kind == MemberPermissionActorKind.Machine && entry.Organization == root.Organization && entry.Authorized == !denied &&
                entry.IntentHash == receipt.IntentHash && entry.Path == originalPath && entry.Method == (ValidationPermissionContract.Create(root.Operation) ? "POST" : "PATCH"), "effect-mismatch");
        Outcome = ValidationPermissionOutcome.NonApplied;
        if (commits.Length == 1)
        {
            var commit = commits[0];
            Require(commit.Request == ingress.Single().Request && commit.PreviousRevision == revision && commit.Policy.Revision != revision &&
                commit.Policy.Resource == Issued.Id(Plan.PolicyKey) && commit.Policy.Configuration == ingress.Single().BodyHash, "effect-mismatch");
            if (ValidationPermissionContract.Create(root.Operation))
                Require(Issued.Bindings.Single(b => b.Intent == Plan.PolicyKey).Request == commit.Request, "effect-mismatch");
            revision = commit.Policy.Revision; policies = [commit.Policy];
            Outcome = PolicyMatches(commit.Policy, root.Action) ? ValidationPermissionOutcome.Applied : ValidationPermissionOutcome.Partial;
        }
        Require(lost || (cancel || denied ? Outcome == ValidationPermissionOutcome.NonApplied : Outcome == ValidationPermissionOutcome.Applied), "effect-mismatch");
        CheckState(packet); CheckPolicies(packet); Require(receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
    }
    internal void Activated(ValidationPermissionReceipt receipt)
    {
        Require(stage == 6 && !failed && activation is null && receipt.Evidence == DispatchEvidence.Applied && receipt.Native.Evidence == receipt.Evidence &&
            receipt.Status == SecretStatus.Success && !receipt.Cancelled, "effect-mismatch"); activation = receipt;
    }
    internal async ValueTask ObserveAsync(bool after, ValidationPermissionAttempt[] attempts, CancellationToken token)
    {
        // Preserve the original request selectors before newly committed IDs arrive.
        var prior = Issued;
        var packet = await StepAsync(after ? ValidationPermissionStep.ObserveAfter : ValidationPermissionStep.ObserveBefore, null, token);
        var ingress = packet.Ingress.Payload.Content.Events; var decisions = packet.Access.Payload.Content.Rules; var changes = packet.Storage.Payload.Content.Changes;
        bool activate = after && Outcome == ValidationPermissionOutcome.Applied && (ValidationPermissionContract.Template(root.Operation) ||
            root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal) || root.Operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal));
        Require(attempts.Select(a => a.Row).SequenceEqual(Rows(after)) && decisions.Length == attempts.Length && changes.Length == attempts.Length &&
            ingress.Length == attempts.Length * 17 + (activate ? 1 : 0) && packet.Policy.Payload.Content.Commits.Length == (activate ? 1 : 0), "effect-mismatch");
        foreach (var entry in ingress) Require(requests.Add(entry.Request), "effect-mismatch");
        if (activate)
        {
            var commit = packet.Policy.Payload.Content.Commits.Single(); var entry = ingress.Single(e => e.Request == commit.Request);
            Require(activation is not null && entry.Phase == "activation" && entry.Actor == root.Authorities.Setup && entry.Kind == MemberPermissionActorKind.Machine &&
                entry.Authorized && entry.IntentHash == activation.IntentHash && commit.PreviousRevision == revision && commit.Policy.Revision == revision &&
                PolicyMatches(commit.Policy, root.Action) && commit.Policy.Configuration == policies.Single().Configuration, "effect-mismatch");
            policies = ValidationPermissionContract.Template(root.Operation) ? [.. policies, commit.Policy] : [commit.Policy];
        }
        for (int i = 0; i < attempts.Length; i++)
        {
            var attempt = attempts[i]; var row = attempt.Row; var decision = decisions[i]; var actor = Issued.Actors[row.Actor];
            bool allowed = ValidationPermissionContract.Allowed(root, row, after, Outcome), read = row.Action == ValidationPermissionAction.Read;
            Require(attempt.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) && attempt.Complete &&
                attempt.CredentialHash == actor.CredentialHash && attempt.Evidence == (read ? null : allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected), "effect-mismatch");
            var entry = ingress.SingleOrDefault(e => e.Request == decision.Request);
            Require(entry is not null && entry.Phase == "action" && entry.Actor == actor.Principal && entry.Kind == actor.Kind &&
                entry.CredentialHash == actor.CredentialHash && entry.Organization == actor.Organization && entry.Authorized == allowed &&
                entry.Method == ValidationPermissionClient.Method(row.Action) && entry.Path == ValidationPermissionClient.Path(root, Plan, prior, row) &&
                entry.BodyHash == attempt.InputHash, "effect-mismatch");
            Require(decision.Actor == actor.Principal && decision.Kind == actor.Kind && decision.CredentialId == actor.CredentialId &&
                decision.CredentialHash == actor.CredentialHash && decision.Organization == Issued.Id(row.Organization) && decision.Project == Issued.Id(row.Project) &&
                decision.Target == Issued.Id(row.Target) && decision.Revision == revision && decision.Action == row.Action && decision.Allowed == allowed, "effect-mismatch");
            causal.Observe(packet, Issued, row, states.Values, attempt.Before, false);
            var before = states.GetValueOrDefault(row.Key);
            var expected = !allowed ? before : row.Action switch
            {
                ValidationPermissionAction.Create => Plan.Initial(row, Issued),
                ValidationPermissionAction.Delete => null,
                ValidationPermissionAction.Edit => ValidationPermissionPlan.Configuration(row, before!.Target, before.Organization, before.Project, true),
                _ => before
            };
            Require(changes[i] == new ValidationPermissionChange(decision.Request, row.Key, before, expected), "effect-mismatch");
            if (expected is null) states.Remove(row.Key); else states[row.Key] = expected;
            causal.Observe(packet, Issued, row, states.Values, attempt.After, true);
            if (!allowed) { Require(attempt.Value is null, "effect-mismatch"); continue; }
            if (row.Action == ValidationPermissionAction.Create)
                Require(Issued.Bindings.Single(b => b.Intent == row.Target).Request == decision.Request, "effect-mismatch");
            Require(attempt.Value == (row.Action == ValidationPermissionAction.Delete ? before : expected), "effect-mismatch");
        }
        causal.Complete(packet, attempts.Length * 16);
        CheckState(packet); CheckPolicies(packet); CheckJoins(packet, after);
        if (after) Require(Original is not null && Original.Native.Evidence == Original.Evidence, "effect-mismatch");
    }
    private bool PolicyMatches(ValidationPermissionPolicy policy, ValidationPermissionAction action) =>
        policy.Actor == Issued.Actors[0].Principal && policy.Kind == root.ActorKind && policy.Organization == root.Organization &&
        policy.Project == (root.ScopeProfile == ValidationPermissionScope.Organization ? "" :
            policy.Resource == Issued.Id(ValidationPermissionPlan.CopiedRole) ? Issued.Id(ValidationPermissionPlan.CopyProject) : Issued.Id(ValidationPermissionPlan.Project)) &&
        policy.Subject == "secret-validation-rules" && policy.Actions.SequenceEqual([ValidationPermissionContract.Wire(action)]) && policy.Names.Length == 0 && policy.Role == Plan.Slug;
    private void CheckState(ValidationPermissionPacket packet)
    {
        Require(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Row).SequenceEqual(states.Values.OrderBy(s => s.Row)), "effect-mismatch");
        foreach (var state in states.Values)
            Require(packet.Owner.Payload.Content.Remaining.Any(r => r.CanonicalId == state.Target) &&
                state.Target != Issued.Id(Plan.PolicyKey) && state.Target != Issued.Id(ValidationPermissionPlan.CopiedRole), "effect-mismatch");
    }
    private void CheckPolicies(ValidationPermissionPacket packet) => Require(ValidationPermissionContract.Hash(packet.Policy.Payload.Content.Inventory.OrderBy(p => p.Resource)) ==
        ValidationPermissionContract.Hash(policies.OrderBy(p => p.Resource)), "effect-mismatch");
    private void CheckJoins(ValidationPermissionPacket packet, bool after)
    {
        bool copy = after && ValidationPermissionContract.Template(root.Operation) && Outcome == ValidationPermissionOutcome.Applied;
        bool assigned = !ValidationPermissionContract.Create(root.Operation) || after && Outcome == ValidationPermissionOutcome.Applied && !copy;
        var expected = Issued.Actors.Take(3).Select((actor, i) => new ValidationPermissionJoin(actor.Principal,
            actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization,
            root.ScopeProfile == ValidationPermissionScope.Project ? Issued.Id(ValidationPermissionPlan.Project) : "", Issued.Id(Plan.ActorMembership(i)),
            i == 0 && assigned, i == 0 && assigned ? Issued.Id(Plan.PolicyKey) : "", i == 0 && assigned ? Plan.Slug : "no-access", true, "accepted")).ToList();
        if (copy) expected.Add(new(Issued.Actors[0].Principal, "user", root.Organization, Issued.Id(ValidationPermissionPlan.CopyProject),
            Issued.Id(Plan.ActorMembership(0, true)), true, Issued.Id(ValidationPermissionPlan.CopiedRole), Plan.Slug, true, "accepted"));
        var actual = packet.Membership.Payload.Content.Where(j => j.Principal != Issued.Actors[3].Principal).ToArray();
        Require(actual.Length == expected.Count && actual.Distinct().Count() == actual.Length && expected.All(actual.Contains), "effect-mismatch");
        causal.CheckGrants(packet, Plan, Issued, copy);
    }
    private async ValueTask<ValidationPermissionPacket> StepAsync(ValidationPermissionStep step, SecretMaterial? capability, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step); busy = failed = true; stage++;
        try
        {
            var packet = await source.StepAsync(root, step, capability, token);
            if (step == ValidationPermissionStep.Open) issued = new(packet.Owner.Payload.Content.Actors, []);
            verifier.Check(packet, step); ownership.Check(packet, step); history.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
            if (step is not (ValidationPermissionStep.Reserve or ValidationPermissionStep.Open))
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
            var packet = await source.StepAsync(root, ValidationPermissionStep.Close, null, deadline.Token);
            verifier.Check(packet, ValidationPermissionStep.Close); ownership.Check(packet, ValidationPermissionStep.Close); history.Check(packet, ValidationPermissionStep.Close); causal.Close(packet);
        }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { issued?.Erase(); verifier.Dispose(); }
    }
    private void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) failed = true; ValidationPermissionContract.Require(condition, code); }
}
