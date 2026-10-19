using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class IdentityPermissionTrial : IAsyncDisposable
{
    private readonly IIdentityPermissionSource source;
    private readonly IdentityPermissionRoot root;
    private readonly IdentityPermissionVerifier verifier;
    private readonly IdentityPermissionOwnership ownership;
    private readonly IdentityPermissionTokens targetTokens;
    private readonly Dictionary<string, IdentityPermissionState> states = [];
    private readonly HashSet<string> requests = [];
    private IdentityPermissionIssued? issued;
    private IdentityPermissionCredential[] credentials = [];
    private IdentityPermissionPolicy[] policies = [];
    private string revision = "policy-1";
    private int stage;
    private bool closed, failed, busy;
    private IdentityPermissionReceipt? activation;
    internal IdentityPermissionPlan Plan { get; }
    internal IdentityPermissionIssued Issued => issued ?? throw new NativeCaseFailureException("observer-unavailable");
    internal IdentityPermissionReceipt? Original { get; private set; }
    internal IdentityPermissionOutcome Outcome { get; private set; }
    private IdentityPermissionTrial(IIdentityPermissionSource source, IdentityPermissionRoot root)
    { this.source = source; this.root = root; Plan = new(root); verifier = new(root); ownership = new(root, Plan); targetTokens = new(root, Plan); }
    internal static async ValueTask<IdentityPermissionTrial> OpenAsync(IIdentityPermissionSource source, IdentityPermissionRoot root,
        SecretMaterial capability, Action<IdentityPermissionTrial> retain, CancellationToken token)
    {
        IdentityPermissionContract.Require(source.Identity == root.Source && source.Kind == root.Kind && Enum.IsDefined(root.Kind) &&
            IdentityPermissionContract.Operations.Contains(root.Operation) && root.ScopeProfile == IdentityPermissionContract.Scope(root.Operation) &&
            root.ActorKind == IdentityPermissionContract.ActorKind(root.Operation) && IdentityPermissionContract.Actions(root.ScopeProfile).Contains(root.Action) &&
            IdentityPermissionContract.Gate(root.ScopeProfile, root.Action) is null && root.Variant == IdentityPermissionContract.Variant(root.Action) &&
            IdentityPermissionContract.Boundaries.Contains(root.Boundary) && root.Authorities.All.Distinct().Count() == 5 &&
            root.Authorities.All.All(MemberPermissionContract.Text) && !root.Authorities.All.Contains(root.Source) &&
            root.Profile.Pins.All(p => p.Writer != root.Source && !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(MemberPermissionContract.Text), "missing-input");
        var trial = new IdentityPermissionTrial(source, root);
        retain(trial); // Root recovery exists BEFORE enrollment or any creation can fail.
        _ = await trial.StepAsync(IdentityPermissionStep.Reserve, capability, token);
        var packet = await trial.StepAsync(IdentityPermissionStep.Open, null, token);
        var v = trial.Issued; var p = trial.Plan;
        trial.Require(v.Actors.Length == (root.ScopeProfile == IdentityPermissionScope.Organization ? 4 : 3));
        trial.credentials = packet.Issuer.Payload.Content.Credentials;
        trial.Require(trial.credentials.Select(c => c.Id).Distinct().Count() == trial.credentials.Length);
        for (int i = 0; i < v.Actors.Length; i++)
        {
            var actor = v.Actors[i];
            trial.Require(actor.Principal == v.Id(p.ActorKey(i)) && actor.Kind == p.ActorKind(i) && actor.Organization == v.Id(p.ActorScope(i)) &&
                actor.Owned == !p.ActorKey(i).StartsWith("@", StringComparison.Ordinal) &&
                (actor.Owned ? actor.Credential.Length > 0 && IdentityPermissionContract.RawHash(actor.Credential) == actor.CredentialHash &&
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
        trial.Require(trial.policies.Length == (IdentityPermissionContract.Create(root.Operation) ? 0 : 1));
        foreach (var policy in trial.policies) trial.Require(trial.PolicyMatches(policy, IdentityPermissionContract.Baseline(root)));
        trial.CheckState(packet); trial.CheckJoins(packet, false); trial.targetTokens.Check(packet, IdentityPermissionStep.Open, trial.Issued);
        return trial;
    }
    internal ValueTask CaptureAsync(IdentityPermissionRow row, string tokenId, SecretMaterial material, CancellationToken token) =>
        source.CaptureAsync(root, row.Key, tokenId, material, token);
    internal IdentityPermissionRow[] Rows(bool after) => Plan.Window(after, Outcome);
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        var packet = await StepAsync(after ? IdentityPermissionStep.After : IdentityPermissionStep.Before, null, token);
        if (after && IdentityPermissionContract.Template(root.Operation) && Outcome == IdentityPermissionOutcome.Applied)
            foreach (var row in Rows(true).Where(Plan.InitiallyPresent)) states.Add(row.Key, Plan.Initial(row, Issued));
        CheckState(packet);
        if (after) targetTokens.Check(packet, IdentityPermissionStep.After, Issued);
    }
    internal async ValueTask ArmAsync(CancellationToken token)
    {
        var packet = await StepAsync(IdentityPermissionStep.Arm, null, token); CheckState(packet); CheckPolicies(packet);
    }
    internal async ValueTask SettleAsync(IdentityPermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Native.Evidence == receipt.Evidence, "effect-mismatch"); Original = receipt;
        string originalPath = IdentityPermissionEffects.OriginalPath(root, Plan, Issued);
        var packet = await StepAsync(IdentityPermissionStep.Settle, null, token);
        bool cancel = root.Boundary == "cancellation-boundary", denied = root.Boundary == "denied-authority", lost = root.Boundary == "lost-response-no-replay";
        var ingress = packet.Ingress.Payload.Content; var commits = packet.Policy.Payload.Content.Commits;
        Require(ingress.Length == (cancel ? 0 : 1) && commits.Length <= 1 && (!(cancel || denied) || commits.Length == 0) &&
            packet.Storage.Payload.Content.Changes.Length == 0 && packet.Access.Payload.Content.Decisions.Length == 0 &&
            receipt.Evidence == (cancel ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected : lost ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancel || lost) && (receipt.Cancelled ? receipt.Status is null : receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var entry in ingress)
            Require(requests.Add(entry.Request) && entry.Phase == "original" && entry.Actor == (denied ? root.Authorities.Denied : root.Authorities.Administrative) &&
                entry.Kind == MemberPermissionActorKind.Machine && entry.Organization == root.Organization && entry.Authorized == !denied &&
                entry.IntentHash == receipt.IntentHash && entry.Path == originalPath && entry.Method == (IdentityPermissionContract.Create(root.Operation) ? "POST" : "PATCH"), "effect-mismatch");
        Outcome = IdentityPermissionOutcome.NonApplied;
        if (commits.Length == 1)
        {
            var commit = commits[0];
            Require(commit.Request == ingress.Single().Request && commit.PreviousRevision == revision && commit.Policy.Revision != revision &&
                commit.Policy.Resource == Issued.Id(Plan.PolicyKey), "effect-mismatch");
            if (IdentityPermissionContract.Create(root.Operation))
                Require(Issued.Bindings.Single(b => b.Intent == Plan.PolicyKey).Request == commit.Request, "effect-mismatch");
            revision = commit.Policy.Revision; policies = [commit.Policy];
            Outcome = PolicyMatches(commit.Policy, root.Action) ? IdentityPermissionOutcome.Applied : IdentityPermissionOutcome.Partial;
        }
        Require(lost || (cancel || denied ? Outcome == IdentityPermissionOutcome.NonApplied : Outcome == IdentityPermissionOutcome.Applied), "effect-mismatch");
        CheckState(packet); CheckPolicies(packet); Require(receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
    }
    internal void Activated(IdentityPermissionReceipt receipt)
    {
        Require(stage == 6 && !failed && activation is null && receipt.Evidence == DispatchEvidence.Applied && receipt.Native.Evidence == receipt.Evidence &&
            receipt.Status == SecretStatus.Success && !receipt.Cancelled, "effect-mismatch"); activation = receipt;
    }
    internal async ValueTask ObserveAsync(bool after, IdentityPermissionAttempt[] attempts, CancellationToken token)
    {
        // Preserve the original request selectors before newly committed IDs arrive.
        var prior = Issued;
        var packet = await StepAsync(after ? IdentityPermissionStep.ObserveAfter : IdentityPermissionStep.ObserveBefore, null, token);
        var ingress = packet.Ingress.Payload.Content; var decisions = packet.Access.Payload.Content.Decisions; var changes = packet.Storage.Payload.Content.Changes;
        bool activate = after && Outcome == IdentityPermissionOutcome.Applied && (IdentityPermissionContract.Template(root.Operation) ||
            root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal) || root.Operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal));
        Require(attempts.Select(a => a.Row).SequenceEqual(Rows(after)) && decisions.Length == attempts.Length && changes.Length == attempts.Length &&
            ingress.Length == attempts.Length + (activate ? 1 : 0) && packet.Policy.Payload.Content.Commits.Length == (activate ? 1 : 0), "effect-mismatch");
        foreach (var entry in ingress) Require(requests.Add(entry.Request), "effect-mismatch");
        if (activate)
        {
            var commit = packet.Policy.Payload.Content.Commits.Single(); var entry = ingress.Single(e => e.Request == commit.Request);
            Require(activation is not null && entry.Phase == "activation" && entry.Actor == root.Authorities.Setup && entry.Kind == MemberPermissionActorKind.Machine &&
                entry.Authorized && entry.IntentHash == activation.IntentHash && commit.PreviousRevision == revision && commit.Policy.Revision == revision &&
                PolicyMatches(commit.Policy, root.Action), "effect-mismatch");
            policies = IdentityPermissionContract.Template(root.Operation) ? [.. policies, commit.Policy] : [commit.Policy];
        }
        for (int i = 0; i < attempts.Length; i++)
        {
            var attempt = attempts[i]; var row = attempt.Row; var decision = decisions[i]; var actor = Issued.Actors[row.Actor];
            bool allowed = IdentityPermissionContract.Allowed(root, row, after, Outcome), read = row.Action is IdentityPermissionAction.Read or IdentityPermissionAction.GetToken;
            Require(attempt.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) && attempt.Complete &&
                attempt.CredentialHash == actor.CredentialHash && attempt.Evidence == (read ? null : allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected), "effect-mismatch");
            var entry = ingress.SingleOrDefault(e => e.Request == decision.Request);
            Require(entry is not null && entry.Phase == "action" && entry.Actor == actor.Principal && entry.Kind == actor.Kind &&
                entry.CredentialHash == actor.CredentialHash && entry.Organization == actor.Organization && entry.Authorized == allowed &&
                entry.Method == IdentityPermissionClient.Method(row.Action) && entry.Path == IdentityPermissionClient.Path(root, Plan, prior, row) &&
                entry.IntentHash == attempt.IntentHash, "effect-mismatch");
            Require(decision.Actor == actor.Principal && decision.Kind == actor.Kind && decision.CredentialId == actor.CredentialId &&
                decision.CredentialHash == actor.CredentialHash && decision.Organization == Issued.Id(row.Organization) && decision.Project == Issued.Id(row.Project) &&
                decision.Identity == Issued.Id(row.Identity) && decision.Membership == Issued.Id(row.Membership) && decision.Revision == revision && decision.Action == row.Action && decision.Allowed == allowed, "effect-mismatch");
            var before = states.GetValueOrDefault(row.Key);
            var expected = !allowed ? before : row.Action switch
            {
                IdentityPermissionAction.Create => Plan.Initial(row, Issued),
                IdentityPermissionAction.Delete => null,
                IdentityPermissionAction.Edit => before! with { Name = row.Name + "-edited", Version = before.Version + 1 },
                IdentityPermissionAction.AssignRole or IdentityPermissionAction.GrantPrivileges => before! with { Role = Plan.Role, Version = before.Version + 1 },
                IdentityPermissionAction.AssignAdditionalPrivileges => before! with
                {
                    Privilege = Issued.Id(row.Privilege),
                    DelegatedPermission = "identity:read",
                    Version = before.Version + 1
                },
                IdentityPermissionAction.EditAuth => before! with { Ttl = 900, Version = before.Version + 1 },
                IdentityPermissionAction.RevokeAuth => before! with { Auth = "", Version = before.Version + 1 },
                _ => before
            };
            Require(changes[i] == new IdentityPermissionChange(decision.Request, row.Key, before, expected), "effect-mismatch");
            if (expected is null) states.Remove(row.Key); else states[row.Key] = expected;
            if (!allowed) continue;
            string? created = row.Action switch
            {
                IdentityPermissionAction.Create => root.ScopeProfile == IdentityPermissionScope.Project ? row.Membership : row.Identity,
                IdentityPermissionAction.AssignAdditionalPrivileges => row.Privilege,
                IdentityPermissionAction.CreateToken => row.Token,
                _ => null
            };
            if (created is not null) Require(Issued.Bindings.Single(b => b.Intent == created).Request == decision.Request, "effect-mismatch");
            var value = row.Action == IdentityPermissionAction.Delete ? before! : expected!;
            Require(attempt.Identity == value.Identity, "effect-mismatch");
            if (row.Action is IdentityPermissionAction.Read or IdentityPermissionAction.Create or IdentityPermissionAction.Delete or IdentityPermissionAction.AssignRole)
            {
                if (root.ScopeProfile == IdentityPermissionScope.Project) Require(attempt.Membership == value.Membership, "effect-mismatch");
                else Require(attempt.Name == value.Name, "effect-mismatch");
            }
            if (row.Action == IdentityPermissionAction.Edit) Require(attempt.Name == value.Name, "effect-mismatch");
            if (row.Action == IdentityPermissionAction.CreateToken || row.Action == IdentityPermissionAction.GetToken)
                Require(attempt.Value == Issued.Id(row.Token), "effect-mismatch");
            if (row.Action == IdentityPermissionAction.AssignAdditionalPrivileges) Require(attempt.Value == value.Privilege, "effect-mismatch");
        }
        targetTokens.Check(packet, after ? IdentityPermissionStep.ObserveAfter : IdentityPermissionStep.ObserveBefore, Issued, attempts);
        CheckState(packet); CheckPolicies(packet); CheckJoins(packet, after);
    }
    private bool PolicyMatches(IdentityPermissionPolicy policy, IdentityPermissionAction action) =>
        policy.Actor == Issued.Actors[0].Principal && policy.Kind == root.ActorKind && policy.Organization == root.Organization &&
        policy.Project == (root.ScopeProfile == IdentityPermissionScope.Organization ? "" :
            policy.Resource == Issued.Id(IdentityPermissionPlan.CopyProject) ? Issued.Id(IdentityPermissionPlan.CopyProject) : Issued.Id(IdentityPermissionPlan.Project)) &&
        policy.Subject == "identity" && policy.Actions.SequenceEqual([IdentityPermissionContract.Wire(action)]) &&
        policy.Names.Order().SequenceEqual((action is IdentityPermissionAction.AssignRole or IdentityPermissionAction.AssignAdditionalPrivileges ? Plan.Rows.Where(r => r.Control == "selected" && r.Action == action).Select(r => Issued.Id(r.Identity)).Where(id => id.Length > 0) : []).Order()) &&
        policy.Role == (action == IdentityPermissionAction.AssignRole ? Plan.Role : action == IdentityPermissionAction.AssignAdditionalPrivileges ? "identity:read" : "");
    private void CheckState(IdentityPermissionPacket packet)
    {
        Require(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Row).SequenceEqual(states.Values.OrderBy(s => s.Row)), "effect-mismatch");
        foreach (var state in states.Values)
            Require(packet.Owner.Payload.Content.Remaining.Any(r => r.CanonicalId == state.Identity) &&
                (root.ScopeProfile == IdentityPermissionScope.Organization || packet.Owner.Payload.Content.Remaining.Any(r => r.CanonicalId == state.Membership)), "effect-mismatch");
    }
    private void CheckPolicies(IdentityPermissionPacket packet) => Require(IdentityPermissionContract.Hash(packet.Policy.Payload.Content.Inventory.OrderBy(p => p.Resource)) ==
        IdentityPermissionContract.Hash(policies.OrderBy(p => p.Resource)), "effect-mismatch");
    private void CheckJoins(IdentityPermissionPacket packet, bool after)
    {
        var remaining = packet.Owner.Payload.Content.Remaining; var expected = new List<IdentityPermissionJoin>();
        foreach (var row in Plan.Rows)
            if (remaining.Any(r => r.Intent == row.Membership)) expected.Add(new(Issued.Id(row.Identity), "machine", Issued.Id(row.Organization),
                Issued.Id(row.Project), Issued.Id(row.Membership), false));
        bool copy = after && IdentityPermissionContract.Template(root.Operation) && Outcome == IdentityPermissionOutcome.Applied;
        for (int i = 0; i < Issued.Actors.Length; i++)
        {
            var actor = Issued.Actors[i];
            expected.Add(new(actor.Principal, actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization,
                root.ScopeProfile == IdentityPermissionScope.Organization ? "" : Issued.Id(IdentityPermissionPlan.Project), Issued.Id(Plan.ActorMembership(i)),
                i == 0 && (!IdentityPermissionContract.Create(root.Operation) || after && Outcome == IdentityPermissionOutcome.Applied && !copy)));
        }
        if (copy) expected.Add(new(Issued.Actors[0].Principal, "user", root.Organization, Issued.Id(IdentityPermissionPlan.CopyProject),
            Issued.Id(Plan.ActorMembership(0, true)), true));
        var actual = packet.Membership.Payload.Content;
        Require(actual.Length == expected.Count && actual.Distinct().Count() == actual.Length && expected.All(actual.Contains), "effect-mismatch");
    }
    private async ValueTask<IdentityPermissionPacket> StepAsync(IdentityPermissionStep step, SecretMaterial? capability, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step); busy = failed = true; stage++;
        try
        {
            var packet = await source.StepAsync(root, step, capability, token);
            if (step == IdentityPermissionStep.Open) issued = new(packet.Owner.Payload.Content.Actors, [], packet.Owner.Payload.Content.Targets);
            else if (issued is not null && packet.Owner.Payload.Content.Targets.Length > 0)
                issued = issued with { Targets = [.. issued.Targets, .. packet.Owner.Payload.Content.Targets] };
            verifier.Check(packet, step); ownership.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
            if (step is not (IdentityPermissionStep.Reserve or IdentityPermissionStep.Open))
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
            var packet = await source.StepAsync(root, IdentityPermissionStep.Close, null, deadline.Token);
            verifier.Check(packet, IdentityPermissionStep.Close); ownership.Check(packet, IdentityPermissionStep.Close);
            var recovered = new IdentityPermissionIssued(issued?.Actors ?? [], packet.Storage.Payload.Content.Bindings, issued?.Targets ?? []);
            if (credentials.Length > 0) Require(packet.Issuer.Payload.Content.Credentials.SequenceEqual(credentials));
            targetTokens.Check(packet, IdentityPermissionStep.Close, recovered);
        }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { issued?.Erase(); verifier.Dispose(); }
    }
    private void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) failed = true; IdentityPermissionContract.Require(condition, code); }
}
