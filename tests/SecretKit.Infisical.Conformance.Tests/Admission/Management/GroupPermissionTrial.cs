using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class GroupPermissionTrial : IAsyncDisposable
{
    private readonly IGroupPermissionSource source;
    private readonly GroupPermissionRoot root;
    private readonly GroupPermissionVerifier verifier;
    private readonly GroupPermissionOwnership ownership;
    private readonly Dictionary<string, GroupPermissionState> states = [];
    private readonly HashSet<string> requests = [];
    private GroupPermissionIssued? issued;
    private GroupPermissionCredential[] credentials = [];
    private GroupPermissionPolicy[] policies = [];
    private string revision = "policy-1";
    private int stage;
    private bool closed, failed, busy;
    private GroupPermissionReceipt? activation;
    internal GroupPermissionPlan Plan { get; }
    internal GroupPermissionIssued Issued => issued ?? throw new NativeCaseFailureException("observer-unavailable");
    internal GroupPermissionReceipt? Original { get; private set; }
    internal GroupPermissionOutcome Outcome { get; private set; }
    private GroupPermissionTrial(IGroupPermissionSource source, GroupPermissionRoot root)
    { this.source = source; this.root = root; Plan = new(root); verifier = new(root); ownership = new(root, Plan); }
    internal static async ValueTask<GroupPermissionTrial> OpenAsync(IGroupPermissionSource source, GroupPermissionRoot root,
        SecretMaterial capability, Action<GroupPermissionTrial> retain, CancellationToken token)
    {
        GroupPermissionContract.Require(source.Identity == root.Source && source.Kind == root.Kind && Enum.IsDefined(root.Kind) &&
            GroupPermissionContract.Operations.Contains(root.Operation) && root.ScopeProfile == GroupPermissionContract.Scope(root.Operation) &&
            root.ActorKind == GroupPermissionContract.ActorKind(root.Operation) && GroupPermissionContract.Actions(root.ScopeProfile).Contains(root.Action) &&
            GroupPermissionContract.Gate(root.ScopeProfile, root.Action) is null && root.Variant == GroupPermissionContract.Variant(root.Action) &&
            GroupPermissionContract.Boundaries.Contains(root.Boundary) && root.Authorities.All.Distinct().Count() == 5 &&
            root.Authorities.All.All(MemberPermissionContract.Text) && !root.Authorities.All.Contains(root.Source) &&
            root.Profile.Pins.All(p => p.Writer != root.Source && !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(MemberPermissionContract.Text), "missing-input");
        var trial = new GroupPermissionTrial(source, root);
        retain(trial); // Root recovery exists BEFORE enrollment or any creation can fail.
        _ = await trial.StepAsync(GroupPermissionStep.Reserve, capability, token);
        var packet = await trial.StepAsync(GroupPermissionStep.Open, null, token);
        var v = trial.Issued; var p = trial.Plan;
        trial.Require(v.Actors.Length == (root.ScopeProfile == GroupPermissionScope.Organization ? 4 : 3));
        trial.credentials = packet.Issuer.Payload.Content.Credentials;
        trial.Require(trial.credentials.Select(c => c.Id).Distinct().Count() == trial.credentials.Length);
        for (int i = 0; i < v.Actors.Length; i++)
        {
            var actor = v.Actors[i];
            trial.Require(actor.Principal == v.Id(p.ActorKey(i)) && actor.Kind == p.ActorKind(i) && actor.Organization == v.Id(p.ActorScope(i)) &&
                actor.Owned == !p.ActorKey(i).StartsWith("@", StringComparison.Ordinal) &&
                (actor.Owned ? actor.Credential.Length > 0 && GroupPermissionContract.RawHash(actor.Credential) == actor.CredentialHash &&
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
        trial.Require(trial.policies.Length == (GroupPermissionContract.Create(root.Operation) ? 0 : 1));
        foreach (var policy in trial.policies) trial.Require(trial.PolicyMatches(policy, GroupPermissionContract.Baseline(root)));
        trial.CheckState(packet); trial.CheckJoins(packet, false);
        return trial;
    }
    internal GroupPermissionRow[] Rows(bool after) => Plan.Window(after, Outcome);
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        var packet = await StepAsync(after ? GroupPermissionStep.After : GroupPermissionStep.Before, null, token);
        if (after && GroupPermissionContract.Template(root.Operation) && Outcome == GroupPermissionOutcome.Applied)
            foreach (var row in Rows(true).Where(Plan.InitiallyPresent)) states.Add(row.Key, Plan.Initial(row, Issued));
        CheckState(packet);
    }
    internal async ValueTask ArmAsync(CancellationToken token)
    {
        var packet = await StepAsync(GroupPermissionStep.Arm, null, token); CheckState(packet); CheckPolicies(packet);
    }
    internal async ValueTask SettleAsync(GroupPermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Native.Evidence == receipt.Evidence, "effect-mismatch"); Original = receipt;
        string originalPath = GroupPermissionEffects.OriginalPath(root, Plan, Issued);
        var packet = await StepAsync(GroupPermissionStep.Settle, null, token);
        bool cancel = root.Boundary == "cancellation-boundary", denied = root.Boundary == "denied-authority", lost = root.Boundary == "lost-response-no-replay";
        var ingress = packet.Ingress.Payload.Content; var commits = packet.Policy.Payload.Content.Commits;
        Require(ingress.Length == (cancel ? 0 : 1) && commits.Length <= 1 && (!(cancel || denied) || commits.Length == 0) &&
            packet.Storage.Payload.Content.Changes.Length == 0 && packet.Access.Payload.Content.Length == 0 &&
            receipt.Evidence == (cancel ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected : lost ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancel || lost) && (receipt.Cancelled ? receipt.Status is null : receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var entry in ingress)
            Require(requests.Add(entry.Request) && entry.Phase == "original" && entry.Actor == (denied ? root.Authorities.Denied : root.Authorities.Administrative) &&
                entry.Kind == MemberPermissionActorKind.Machine && entry.Organization == root.Organization && entry.Authorized == !denied &&
                entry.IntentHash == receipt.IntentHash && entry.Path == originalPath && entry.Method == (GroupPermissionContract.Create(root.Operation) ? "POST" : "PATCH"), "effect-mismatch");
        Outcome = GroupPermissionOutcome.NonApplied;
        if (commits.Length == 1)
        {
            var commit = commits[0];
            Require(commit.Request == ingress.Single().Request && commit.PreviousRevision == revision && commit.Policy.Revision != revision &&
                commit.Policy.Resource == Issued.Id(Plan.PolicyKey), "effect-mismatch");
            if (GroupPermissionContract.Create(root.Operation))
                Require(Issued.Bindings.Single(b => b.Intent == Plan.PolicyKey).Request == commit.Request, "effect-mismatch");
            revision = commit.Policy.Revision; policies = [commit.Policy];
            Outcome = PolicyMatches(commit.Policy, root.Action) ? GroupPermissionOutcome.Applied : GroupPermissionOutcome.Partial;
        }
        Require(lost || (cancel || denied ? Outcome == GroupPermissionOutcome.NonApplied : Outcome == GroupPermissionOutcome.Applied), "effect-mismatch");
        CheckState(packet); CheckPolicies(packet); Require(receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
    }
    internal void Activated(GroupPermissionReceipt receipt)
    {
        Require(stage == 6 && !failed && activation is null && receipt.Evidence == DispatchEvidence.Applied && receipt.Native.Evidence == receipt.Evidence &&
            receipt.Status == SecretStatus.Success && !receipt.Cancelled, "effect-mismatch"); activation = receipt;
    }
    internal async ValueTask ObserveAsync(bool after, GroupPermissionAttempt[] attempts, CancellationToken token)
    {
        // Preserve the original request selectors before newly committed IDs arrive.
        var prior = Issued;
        var packet = await StepAsync(after ? GroupPermissionStep.ObserveAfter : GroupPermissionStep.ObserveBefore, null, token);
        var ingress = packet.Ingress.Payload.Content; var decisions = packet.Access.Payload.Content; var changes = packet.Storage.Payload.Content.Changes;
        bool activate = after && Outcome == GroupPermissionOutcome.Applied && (GroupPermissionContract.Template(root.Operation) ||
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
            policies = GroupPermissionContract.Template(root.Operation) ? [.. policies, commit.Policy] : [commit.Policy];
        }
        for (int i = 0; i < attempts.Length; i++)
        {
            var attempt = attempts[i]; var row = attempt.Row; var decision = decisions[i]; var actor = Issued.Actors[row.Actor];
            bool allowed = GroupPermissionContract.Allowed(root, row, after, Outcome), read = row.Action == GroupPermissionAction.Read;
            Require(attempt.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) && attempt.Complete &&
                attempt.CredentialHash == actor.CredentialHash && attempt.Evidence == (read ? null : allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected), "effect-mismatch");
            var entry = ingress.SingleOrDefault(e => e.Request == decision.Request);
            Require(entry is not null && entry.Phase == "action" && entry.Actor == actor.Principal && entry.Kind == actor.Kind &&
                entry.CredentialHash == actor.CredentialHash && entry.Organization == actor.Organization && entry.Authorized == allowed &&
                entry.Method == GroupPermissionClient.Method(row.Action) && entry.Path == GroupPermissionClient.Path(root, Plan, prior, row), "effect-mismatch");
            Require(decision.Actor == actor.Principal && decision.Kind == actor.Kind && decision.CredentialId == actor.CredentialId &&
                decision.CredentialHash == actor.CredentialHash && decision.Organization == Issued.Id(row.Organization) && decision.Project == Issued.Id(row.Project) &&
                decision.Group == Issued.Id(row.Group) && decision.Membership == Issued.Id(row.Membership) && decision.User == Issued.Id(row.User) &&
                decision.Identity == Issued.Id(row.Identity) && decision.Revision == revision && decision.Action == row.Action && decision.Allowed == allowed, "effect-mismatch");
            var before = states.GetValueOrDefault(row.Key);
            var expected = !allowed ? before : row.Action switch
            {
                GroupPermissionAction.Create => Plan.Initial(row, Issued),
                GroupPermissionAction.Delete => null,
                GroupPermissionAction.Edit => before! with { Name = row.Name + "-edited", Version = before.Version + 1 },
                GroupPermissionAction.AssignRole or GroupPermissionAction.GrantPrivileges => before! with { Role = Plan.Role, Version = before.Version + 1 },
                GroupPermissionAction.AddMembers => before! with { UserLink = Issued.Id(row.UserLink), Version = before.Version + 1 },
                GroupPermissionAction.AddIdentities => before! with { IdentityLink = Issued.Id(row.IdentityLink), Version = before.Version + 1 },
                GroupPermissionAction.RemoveMembers => before! with { UserLink = "", Version = before.Version + 1 },
                GroupPermissionAction.RemoveIdentities => before! with { IdentityLink = "", Version = before.Version + 1 },
                _ => before
            };
            Require(changes[i] == new GroupPermissionChange(decision.Request, row.Key, before, expected), "effect-mismatch");
            if (expected is null) states.Remove(row.Key); else states[row.Key] = expected;
            if (!allowed) continue;
            string? created = row.Action switch
            {
                GroupPermissionAction.Create => root.ScopeProfile == GroupPermissionScope.Project ? row.Membership : row.Group,
                GroupPermissionAction.AddMembers => row.UserLink,
                GroupPermissionAction.AddIdentities => row.IdentityLink,
                _ => null
            };
            if (created is not null) Require(Issued.Bindings.Single(b => b.Intent == created).Request == decision.Request, "effect-mismatch");
            var value = row.Action == GroupPermissionAction.Delete ? before! : expected!;
            Require(attempt.Group == value.Group, "effect-mismatch");
            if (root.ScopeProfile == GroupPermissionScope.Project)
            {
                Require(attempt.Membership == value.Membership, "effect-mismatch");
                if (row.Action == GroupPermissionAction.AssignRole) Require(attempt.Role == value.Role, "effect-mismatch");
            }
            else if (row.Action is GroupPermissionAction.AddMembers or GroupPermissionAction.RemoveMembers)
                Require(attempt.Member == value.User && attempt.Name == Plan.Username(row.User), "effect-mismatch");
            else if (row.Action is GroupPermissionAction.AddIdentities or GroupPermissionAction.RemoveIdentities)
                Require(attempt.Membership == (row.Action == GroupPermissionAction.RemoveIdentities ? before!.IdentityLink : value.IdentityLink), "effect-mismatch");
            else Require(attempt.Name == value.Name, "effect-mismatch");
        }
        CheckState(packet); CheckPolicies(packet); CheckJoins(packet, after);
    }
    private bool PolicyMatches(GroupPermissionPolicy policy, GroupPermissionAction action) =>
        policy.Actor == Issued.Actors[0].Principal && policy.Kind == root.ActorKind && policy.Organization == root.Organization &&
        policy.Project == (root.ScopeProfile == GroupPermissionScope.Organization ? "" :
            policy.Resource == Issued.Id(GroupPermissionPlan.CopyProject) ? Issued.Id(GroupPermissionPlan.CopyProject) : Issued.Id(GroupPermissionPlan.Project)) &&
        policy.Subject == "groups" && policy.Actions.SequenceEqual([GroupPermissionContract.Wire(action)]) &&
        policy.Names.Order().SequenceEqual((action == GroupPermissionAction.AssignRole ? Plan.Rows.Where(r => r.Control == "selected").Select(r => r.Name) : []).Order()) &&
        policy.Role == (action == GroupPermissionAction.AssignRole ? Plan.Role : "");
    private void CheckState(GroupPermissionPacket packet)
    {
        Require(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Row).SequenceEqual(states.Values.OrderBy(s => s.Row)), "effect-mismatch");
        foreach (var state in states.Values)
            Require(packet.Owner.Payload.Content.Remaining.Any(r => r.CanonicalId == state.Group) &&
                (root.ScopeProfile == GroupPermissionScope.Organization || packet.Owner.Payload.Content.Remaining.Any(r => r.CanonicalId == state.Membership)), "effect-mismatch");
    }
    private void CheckPolicies(GroupPermissionPacket packet) => Require(GroupPermissionContract.Hash(packet.Policy.Payload.Content.Inventory.OrderBy(p => p.Resource)) ==
        GroupPermissionContract.Hash(policies.OrderBy(p => p.Resource)), "effect-mismatch");
    private void CheckJoins(GroupPermissionPacket packet, bool after)
    {
        var remaining = packet.Owner.Payload.Content.Remaining; var expected = new List<GroupPermissionJoin>();
        foreach (var row in Plan.Rows)
        {
            foreach (var pair in new[] { (row.UserLink, row.User, "user"), (row.IdentityLink, row.Identity, "machine"), (row.Membership, row.Group, "group") })
                if (remaining.Any(r => r.Intent == pair.Item1)) expected.Add(new(Issued.Id(pair.Item2), pair.Item3, Issued.Id(row.Organization),
                    pair.Item3 == "group" ? Issued.Id(row.Project) : "", Issued.Id(row.Group), Issued.Id(pair.Item1), false));
        }
        bool copy = after && GroupPermissionContract.Template(root.Operation) && Outcome == GroupPermissionOutcome.Applied;
        for (int i = 0; i < Issued.Actors.Length; i++)
        {
            var actor = Issued.Actors[i];
            expected.Add(new(actor.Principal, actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization,
                root.ScopeProfile == GroupPermissionScope.Organization ? "" : Issued.Id(GroupPermissionPlan.Project), "", Issued.Id(Plan.ActorMembership(i)),
                i == 0 && (!GroupPermissionContract.Create(root.Operation) || after && Outcome == GroupPermissionOutcome.Applied && !copy)));
        }
        if (copy) expected.Add(new(Issued.Actors[0].Principal, "user", root.Organization, Issued.Id(GroupPermissionPlan.CopyProject), "",
            Issued.Id(Plan.ActorMembership(0, true)), true));
        var actual = packet.Membership.Payload.Content;
        Require(actual.Length == expected.Count && actual.Distinct().Count() == actual.Length && expected.All(actual.Contains), "effect-mismatch");
    }
    private async ValueTask<GroupPermissionPacket> StepAsync(GroupPermissionStep step, SecretMaterial? capability, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step); busy = failed = true; stage++;
        try
        {
            var packet = await source.StepAsync(root, step, capability, token);
            if (step == GroupPermissionStep.Open) issued = new(packet.Owner.Payload.Content.Actors, []);
            verifier.Check(packet, step); ownership.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
            if (step is not (GroupPermissionStep.Reserve or GroupPermissionStep.Open))
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
            var packet = await source.StepAsync(root, GroupPermissionStep.Close, null, deadline.Token);
            verifier.Check(packet, GroupPermissionStep.Close); ownership.Check(packet, GroupPermissionStep.Close);
        }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { issued?.Erase(); verifier.Dispose(); }
    }
    private void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) failed = true; GroupPermissionContract.Require(condition, code); }
}
