using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class WorkspacePermissionTrial : IAsyncDisposable
{
    private readonly IWorkspacePermissionSource source;
    private readonly WorkspacePermissionRoot root;
    private readonly WorkspacePermissionVerifier verifier;
    private readonly WorkspacePermissionOwnership ownership;
    private readonly Dictionary<string, WorkspacePermissionState> states = [];
    private readonly HashSet<string> requests = [];
    private WorkspacePermissionIssued? issued;
    private WorkspacePermissionCredential[] credentials = [];
    private WorkspacePermissionPolicy[] policies = [];
    private string revision = "policy-1";
    private int stage;
    private bool closed, failed, busy;
    private WorkspacePermissionReceipt? activation;
    private WorkspacePermissionPacket? predispatch;
    private readonly HashSet<string> deletedProjects = [];
    internal WorkspacePermissionPlan Plan { get; }
    internal WorkspacePermissionState[] Inventory => states.Values.ToArray();
    internal WorkspacePermissionIssued Issued => issued ?? throw new NativeCaseFailureException("observer-unavailable");
    internal WorkspacePermissionReceipt? Original { get; private set; }
    internal WorkspacePermissionOutcome Outcome { get; private set; }
    private WorkspacePermissionTrial(IWorkspacePermissionSource source, WorkspacePermissionRoot root)
    { this.source = source; this.root = root; Plan = new(root); verifier = new(root); ownership = new(root, Plan); }
    internal static async ValueTask<WorkspacePermissionTrial> OpenAsync(IWorkspacePermissionSource source, WorkspacePermissionRoot root,
        SecretMaterial capability, Action<WorkspacePermissionTrial> retain, CancellationToken token)
    {
        WorkspacePermissionContract.Require(source.Identity == root.Source && source.Kind == root.Kind && Enum.IsDefined(root.Kind) &&
            WorkspacePermissionContract.Operations.Contains(root.Operation) && root.ScopeProfile == WorkspacePermissionContract.Scope(root.Operation) &&
            root.ActorKind == WorkspacePermissionContract.ActorKind(root.Operation) && WorkspacePermissionContract.Actions(root.ScopeProfile).Contains(root.Action) &&
            WorkspacePermissionContract.Gate(root.ScopeProfile, root.Action) is null && root.Variant == WorkspacePermissionContract.Variant(root.Action) &&
            WorkspacePermissionContract.Boundaries.Contains(root.Boundary) && root.Authorities.All.Distinct().Count() == 5 &&
            root.Authorities.All.All(MemberPermissionContract.Text) && !root.Authorities.All.Contains(root.Source) &&
            root.Profile.Pins.All(p => p.Writer != root.Source && !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(MemberPermissionContract.Text), "missing-input");
        var trial = new WorkspacePermissionTrial(source, root);
        retain(trial); // Root recovery exists BEFORE enrollment or any creation can fail.
        _ = await trial.StepAsync(WorkspacePermissionStep.Reserve, capability, token);
        var packet = await trial.StepAsync(WorkspacePermissionStep.Open, null, token);
        var v = trial.Issued; var p = trial.Plan;
        trial.Require(v.Actors.Length == (root.ScopeProfile == WorkspacePermissionScope.Organization ? 4 : 3));
        trial.credentials = packet.Issuer.Payload.Content.Credentials;
        trial.Require(trial.credentials.Select(c => c.Id).Distinct().Count() == trial.credentials.Length);
        for (int i = 0; i < v.Actors.Length; i++)
        {
            var actor = v.Actors[i];
            trial.Require(actor.Principal == v.Id(p.ActorKey(i)) && actor.Kind == p.ActorKind(i) && actor.Organization == v.Id(p.ActorScope(i)) &&
                actor.Owned == !p.ActorKey(i).StartsWith("@", StringComparison.Ordinal) &&
                (actor.Owned ? actor.Credential.Length > 0 && WorkspacePermissionContract.RawHash(actor.Credential) == actor.CredentialHash &&
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
        foreach (var row in p.Rows.Where(r => r.Window != "copy" && p.InitiallyPresent(r)).DistinctBy(r => r.Target)) trial.states.Add(row.Target, p.Initial(row, v));
        trial.policies = packet.Policy.Payload.Content.Inventory;
        trial.Require(trial.policies.Length == (WorkspacePermissionContract.Create(root.Operation) ? 0 : 1));
        foreach (var policy in trial.policies) trial.Require(trial.PolicyMatches(policy, null));
        trial.CheckState(packet); trial.CheckJoins(packet, false);
        return trial;
    }
    internal WorkspacePermissionRow[] Rows(bool after) => Plan.Window(after, Outcome);
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        var packet = await StepAsync(after ? WorkspacePermissionStep.After : WorkspacePermissionStep.Before, null, token);
        if (after && WorkspacePermissionContract.Template(root.Operation) && Outcome == WorkspacePermissionOutcome.Applied)
            foreach (var row in Rows(true).Where(Plan.InitiallyPresent).DistinctBy(r => r.Target)) states.TryAdd(row.Target, Plan.Initial(row, Issued));
        CheckState(packet); CheckJoins(packet, after);
        if (after && WorkspacePermissionContract.Template(root.Operation) && Outcome == WorkspacePermissionOutcome.Applied)
        {
            var copied = packet.Policy.Payload.Content.Inventory.SingleOrDefault(p => p.Resource == Issued.Id(WorkspacePermissionPlan.CopiedRole));
            Require(copied is not null && PolicyMatches(copied, root.Action), "effect-mismatch");
            Require(WorkspacePermissionContract.Hash(packet.Policy.Payload.Content.Inventory.OrderBy(p => p.Resource)) ==
                WorkspacePermissionContract.Hash(policies.Append(copied!).OrderBy(p => p.Resource)), "effect-mismatch");
        }
        else CheckPolicies(packet);
        predispatch = packet;
    }
    internal async ValueTask ArmAsync(CancellationToken token)
    {
        var packet = await StepAsync(WorkspacePermissionStep.Arm, null, token); CheckState(packet); CheckPolicies(packet);
    }
    internal async ValueTask SettleAsync(WorkspacePermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Native.Evidence == receipt.Evidence, "effect-mismatch"); Original = receipt;
        string originalPath = WorkspacePermissionEffects.OriginalPath(root, Plan, Issued);
        var packet = await StepAsync(WorkspacePermissionStep.Settle, null, token);
        bool cancel = root.Boundary == "cancellation-boundary", denied = root.Boundary == "denied-authority", lost = root.Boundary == "lost-response-no-replay";
        var ingress = packet.Ingress.Payload.Content; var commits = packet.Policy.Payload.Content.Commits;
        Require(ingress.Length == (cancel ? 0 : 1) && commits.Length <= 1 && (!(cancel || denied) || commits.Length == 0) &&
            packet.Storage.Payload.Content.Changes.Length == 0 && packet.Access.Payload.Content.Length == 0 &&
            receipt.Evidence == (cancel ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected : lost ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancel || lost) && (receipt.Cancelled ? receipt.Status is null : receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var entry in ingress)
            Require(requests.Add(entry.Request) && entry.Phase == "original" && entry.Actor == (denied ? root.Authorities.Denied : root.Authorities.Administrative) &&
                entry.Kind == MemberPermissionActorKind.Machine && entry.Organization == root.Organization && entry.Authorized == !denied &&
                entry.IntentHash == receipt.IntentHash && entry.Path == originalPath && entry.Method == (WorkspacePermissionContract.Create(root.Operation) ? "POST" : "PATCH"), "effect-mismatch");
        Outcome = WorkspacePermissionOutcome.NonApplied;
        if (commits.Length == 1)
        {
            var commit = commits[0];
            Require(commit.Request == ingress.Single().Request && commit.PreviousRevision == revision && commit.Policy.Revision != revision &&
                commit.Policy.Resource == Issued.Id(Plan.PolicyKey), "effect-mismatch");
            if (WorkspacePermissionContract.Create(root.Operation))
                Require(Issued.Bindings.Single(b => b.Intent == Plan.PolicyKey).Request == commit.Request, "effect-mismatch");
            revision = commit.Policy.Revision; policies = [commit.Policy];
            Outcome = PolicyMatches(commit.Policy, root.Action) ? WorkspacePermissionOutcome.Applied : WorkspacePermissionOutcome.Partial;
        }
        Require(lost || (cancel || denied ? Outcome == WorkspacePermissionOutcome.NonApplied : Outcome == WorkspacePermissionOutcome.Applied), "effect-mismatch");
        CheckState(packet); CheckPolicies(packet); Require(receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
    }
    internal void Activated(WorkspacePermissionReceipt receipt)
    {
        Require(stage == 6 && !failed && activation is null && receipt.Evidence == DispatchEvidence.Applied && receipt.Native.Evidence == receipt.Evidence &&
            receipt.Status == SecretStatus.Success && !receipt.Cancelled, "effect-mismatch"); activation = receipt;
    }
    internal async ValueTask ObserveAsync(bool after, WorkspacePermissionAttempt[] attempts, CancellationToken token)
    {
        // Preserve the original request selectors before newly committed IDs arrive.
        var prior = Issued;
        var packet = await StepAsync(after ? WorkspacePermissionStep.ObserveAfter : WorkspacePermissionStep.ObserveBefore, null, token);
        var ingress = packet.Ingress.Payload.Content; var decisions = packet.Access.Payload.Content; var changes = packet.Storage.Payload.Content.Changes;
        bool activate = after && Outcome == WorkspacePermissionOutcome.Applied && (WorkspacePermissionContract.Template(root.Operation) ||
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
            policies = WorkspacePermissionContract.Template(root.Operation) ? [.. policies, commit.Policy] : [commit.Policy];
        }
        for (int i = 0; i < attempts.Length; i++)
        {
            var attempt = attempts[i]; var row = attempt.Row; var decision = decisions[i]; var actor = Issued.Actors[row.Actor];
            bool allowed = WorkspacePermissionContract.Allowed(root, row, after, Outcome);
            Require(attempt.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) && attempt.Complete &&
                attempt.CredentialHash == actor.CredentialHash && attempt.Evidence == (allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected), "effect-mismatch");
            var entry = ingress.SingleOrDefault(e => e.Request == decision.Request);
            Require(entry is not null && entry.Phase == "action" && entry.Actor == actor.Principal && entry.Kind == actor.Kind &&
                entry.CredentialHash == actor.CredentialHash && entry.Organization == actor.Organization && entry.Authorized == allowed &&
                entry.BodyHash == attempt.IntentHash && entry.Method == WorkspacePermissionClient.Method(row.Action) && entry.Path == WorkspacePermissionClient.Path(root, Plan, prior, row), "effect-mismatch");
            Require(decision.Actor == actor.Principal && decision.Kind == actor.Kind && decision.CredentialId == actor.CredentialId &&
                decision.CredentialHash == actor.CredentialHash && decision.Organization == Issued.Id(row.Organization) && decision.Project == Issued.Id(row.Project) &&
                decision.Target == Issued.Id(row.Target) && decision.Revision == revision && decision.Action == row.Action && decision.Allowed == allowed, "effect-mismatch");
            var before = states.GetValueOrDefault(row.Target);
            var expected = !allowed ? before : row.Action switch
            {
                WorkspacePermissionAction.Create => Plan.Initial(row, Issued),
                WorkspacePermissionAction.Delete => null,
                WorkspacePermissionAction.Edit => before! with { Name = row.Name + "-edited", Slug = row.Slug + "-v2", Description = "closed-v2", Configuration = WorkspacePermissionPlan.Configuration(true), Version = 2 },
                _ => before
            };
            Require(changes[i] == new WorkspacePermissionChange(decision.Request, row.Key, before, expected), "effect-mismatch");
            if (expected is null) states.Remove(row.Target); else states[row.Target] = expected;
            if (allowed && row.Action == WorkspacePermissionAction.Delete) CheckCascade(packet, decision, actor);
            if (!allowed) { Require(attempt.Value is null, "effect-mismatch"); continue; }
            if (row.Action == WorkspacePermissionAction.Create)
                Require(Issued.Bindings.Single(b => b.Intent == row.Target).Request == decision.Request, "effect-mismatch");
            Require(attempt.Value == (row.Action == WorkspacePermissionAction.Delete ? before : expected), "effect-mismatch");
        }
        Require(packet.Storage.Payload.Content.Cascades.Length == attempts.Count(a => a.Status == SecretStatus.Success && a.Row.Action == WorkspacePermissionAction.Delete), "effect-mismatch");
        policies = policies.Where(p => !deletedProjects.Contains(p.Project)).ToArray();
        CheckState(packet); CheckPolicies(packet); CheckJoins(packet, after);
        if (after) Require(Original is not null && Original.Native.Evidence == Original.Evidence, "effect-mismatch");
    }
    private void CheckCascade(WorkspacePermissionPacket packet, WorkspacePermissionAccess decision, WorkspacePermissionActor actor)
    {
        Require(predispatch is not null && deletedProjects.Add(decision.Project), "effect-mismatch");
        var before = predispatch!;
        var grant = before.Policy.Payload.Content.Inventory.SingleOrDefault(p => p.Project == decision.Project && p.Actor == actor.Principal);
        var membership = before.Membership.Payload.Content.SingleOrDefault(m => m.Project == decision.Project && m.Principal == actor.Principal);
        Require(grant is not null && membership is not null && PolicyMatches(grant, root.Action) && membership.Assigned &&
            membership.Active && membership.Status == "accepted" && membership.RoleId == grant.Resource && membership.RoleSlug == grant.Role &&
            membership.Kind == (actor.Kind == MemberPermissionActorKind.User ? "user" : "machine") && membership.Organization == actor.Organization, "effect-mismatch");
        var closure = before.Owner.Payload.Content.Remaining.Where(r => r.CanonicalId == decision.Project ||
            Issued.Bindings.Any(b => b.CanonicalId == r.CanonicalId && b.Scope == decision.Project)).OrderBy(r => r.Intent).ToArray();
        var retained = before.Owner.Payload.Content.Remaining.Except(closure).OrderBy(r => r.Intent).ToArray();
        var cascade = packet.Storage.Payload.Content.Cascades.SingleOrDefault(c => c.Request == decision.Request);
        Require(cascade is not null && cascade.Project == decision.Project && cascade.PolicyHash == WorkspacePermissionContract.Hash(grant) &&
            cascade.MembershipHash == WorkspacePermissionContract.Hash(membership) && cascade.CredentialId == actor.CredentialId &&
            cascade.CredentialHash == actor.CredentialHash && cascade.Removed.OrderBy(r => r.Intent).SequenceEqual(closure) &&
            cascade.Retained.OrderBy(r => r.Intent).SequenceEqual(retained) &&
            packet.Owner.Payload.Content.Remaining.OrderBy(r => r.Intent).SequenceEqual(retained) &&
            packet.Issuer.Payload.Content.Bindings.Any(b => b.CanonicalId == decision.Project) &&
            !packet.Storage.Payload.Content.Inventory.Any(s => s.Target == decision.Project) &&
            !packet.Membership.Payload.Content.Any(j => j.Project == decision.Project) &&
            !packet.Policy.Payload.Content.Inventory.Any(p => p.Project == decision.Project), "effect-mismatch");
    }
    private bool PolicyMatches(WorkspacePermissionPolicy policy, WorkspacePermissionAction? action) =>
        Guid.TryParse(policy.Resource, out _) &&
        (policy.Resource == Issued.Id(Plan.PolicyKey) || policy.Resource == Issued.Id(WorkspacePermissionPlan.CopiedRole)) &&
        policy.Actor == Issued.Actors[0].Principal && policy.Kind == root.ActorKind && policy.Organization == root.Organization &&
        policy.Project == (root.ScopeProfile == WorkspacePermissionScope.Organization || WorkspacePermissionContract.Template(root.Operation) && policy.Resource == Issued.Id(Plan.PolicyKey) ? "" :
            policy.Resource == Issued.Id(WorkspacePermissionPlan.CopiedRole) ? Issued.Id(WorkspacePermissionPlan.CopyProject) : Issued.Id(WorkspacePermissionPlan.Project)) &&
        policy.Subject == "workspace" && policy.Actions.SequenceEqual(action is null ? [] : new[] { WorkspacePermissionContract.Wire(action.Value) }) && policy.Names.Length == 0 && policy.Role == Plan.Slug &&
        (!WorkspacePermissionContract.Template(root.Operation) || action is null || policy.TemplateConfiguration == Plan.TemplateConfiguration());
    private void CheckState(WorkspacePermissionPacket packet)
    {
        Require(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Row).SequenceEqual(states.Values.OrderBy(s => s.Row)), "effect-mismatch");
        foreach (var state in states.Values)
            Require(packet.Owner.Payload.Content.Remaining.Any(r => r.CanonicalId == state.Target), "effect-mismatch");
    }
    private void CheckPolicies(WorkspacePermissionPacket packet) => Require(WorkspacePermissionContract.Hash(packet.Policy.Payload.Content.Inventory.OrderBy(p => p.Resource)) ==
        WorkspacePermissionContract.Hash(policies.OrderBy(p => p.Resource)), "effect-mismatch");
    private void CheckJoins(WorkspacePermissionPacket packet, bool after)
    {
        bool copy = after && WorkspacePermissionContract.Template(root.Operation) && Outcome == WorkspacePermissionOutcome.Applied;
        bool assigned = !WorkspacePermissionContract.Template(root.Operation) &&
            (!WorkspacePermissionContract.Create(root.Operation) || after && Outcome == WorkspacePermissionOutcome.Applied);
        var expected = Issued.Actors.Select((actor, i) => new WorkspacePermissionJoin(actor.Principal,
            actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization,
            root.ScopeProfile == WorkspacePermissionScope.Project ? Issued.Id(WorkspacePermissionPlan.Project) : "", Issued.Id(Plan.ActorMembership(i)),
            i == 0 && assigned, i == 0 && assigned ? Issued.Id(Plan.PolicyKey) : "", i == 0 && assigned ? Plan.Slug : "no-access", true, "accepted")).ToList();
        if (copy) expected.Add(new(Issued.Actors[0].Principal, "user", root.Organization, Issued.Id(WorkspacePermissionPlan.CopyProject),
            Issued.Id(Plan.ActorMembership(0, true)), true, Issued.Id(WorkspacePermissionPlan.CopiedRole), Plan.Slug, true, "accepted"));
        expected.RemoveAll(j => deletedProjects.Contains(j.Project));
        var actual = packet.Membership.Payload.Content;
        Require(expected.All(j => Guid.TryParse(j.Membership, out _) && Issued.Bindings.Any(b =>
                b.CanonicalId == j.Membership && b.Kind == "membership" && b.Scope == (j.Project.Length == 0 ? j.Organization : j.Project))) &&
            actual.Length == expected.Count && actual.Distinct().Count() == actual.Length && expected.All(actual.Contains), "effect-mismatch");
    }
    private async ValueTask<WorkspacePermissionPacket> StepAsync(WorkspacePermissionStep step, SecretMaterial? capability, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step); busy = failed = true; stage++;
        try
        {
            var packet = await source.StepAsync(root, step, capability, token);
            if (step == WorkspacePermissionStep.Open) issued = new(packet.Owner.Payload.Content.Actors, []);
            verifier.Check(packet, step); ownership.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
            if (step is not (WorkspacePermissionStep.Reserve or WorkspacePermissionStep.Open))
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
            var packet = await source.StepAsync(root, WorkspacePermissionStep.Close, null, deadline.Token);
            verifier.Check(packet, WorkspacePermissionStep.Close); ownership.Check(packet, WorkspacePermissionStep.Close);
        }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { issued?.Erase(); verifier.Dispose(); }
    }
    private void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) failed = true; WorkspacePermissionContract.Require(condition, code); }
}
