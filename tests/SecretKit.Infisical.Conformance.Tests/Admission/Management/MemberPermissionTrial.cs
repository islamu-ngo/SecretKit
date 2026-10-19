using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class MemberPermissionTrial : IAsyncDisposable
{
    private readonly IMemberPermissionSource source;
    private readonly MemberPermissionRoot root;
    private readonly MemberPermissionVerifier verifier;
    private readonly Dictionary<string, MemberPermissionState> states = [];
    private readonly HashSet<string> requestIds = [];
    private MemberPermissionOwner? reservation;
    private MemberPermissionCredential[] credentials = [];
    private MemberPermissionIssued? issued;
    private MemberPermissionPolicy[] policies = [];
    private int stage;
    private bool closed, failed, busy;
    private string revision = "";
    private MemberPermissionReceipt? activation;
    internal MemberPermissionIssued Issued => issued ?? throw new NativeCaseFailureException("observer-unavailable");
    internal MemberPermissionReceipt? Original { get; private set; }
    internal MemberPermissionOutcome Outcome { get; private set; }
    private MemberPermissionTrial(IMemberPermissionSource source, MemberPermissionRoot root)
    { this.source = source; this.root = root; verifier = new(root); }
    internal static async ValueTask<MemberPermissionTrial> OpenAsync(IMemberPermissionSource source,
        MemberPermissionRoot root, SecretMaterial capability, Action<MemberPermissionTrial> retain, CancellationToken token)
    {
        MemberPermissionContract.Require(source.Identity == root.Source && source.Kind == root.Kind &&
            Enum.IsDefined(root.Kind) && MemberPermissionContract.Operations.Contains(root.Operation) &&
            root.ScopeProfile == MemberPermissionContract.Scope(root.Operation) &&
            root.ActorKind == MemberPermissionContract.ActorKind(root.Operation) &&
            MemberPermissionContract.Actions(root.ScopeProfile).Contains(root.Action) &&
            MemberPermissionContract.Gate(root.ScopeProfile, root.Action) is null &&
            root.Variant == MemberPermissionContract.Variant(root.Action) && MemberPermissionContract.Boundaries.Contains(root.Boundary) &&
            root.Authorities.All.All(MemberPermissionContract.Text) && root.Authorities.All.Distinct().Count() == 5 &&
            !root.Authorities.All.Contains(root.Source) && root.Profile.Pins.All(p =>
                p.Writer != root.Source && !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(MemberPermissionContract.Text), "missing-input");
        var trial = new MemberPermissionTrial(source, root);
        retain(trial);
        var reserved = await trial.StepAsync(MemberPermissionStep.Reserve, capability, token);
        trial.reservation = reserved.Owner.Payload.Content;
        trial.Require(trial.reservation.Remaining.Length == 0 && reserved.Storage.Payload.Content.Inventory.Length == 0 &&
            reserved.Policy.Payload.Content.Inventory.Length == 0 && reserved.Issuer.Payload.Content.Length == 0 &&
            reserved.Membership.Payload.Content.Length == 0);
        var opened = await trial.StepAsync(MemberPermissionStep.Open, null, token);
        trial.Require(trial.issued is not null);
        var value = trial.Issued;
        trial.Require(value.Principals.Length == 3 && value.Principals[0].Kind == root.ActorKind &&
            value.Principals[1].Kind == root.ActorKind && value.Principals[2].Kind != root.ActorKind &&
            value.Principals.Select(p => p.Id).Distinct().Count() == 3 &&
            new[] { value.Project, value.OtherProject, value.CopyProject }.Distinct().Count() == 3 &&
            root.Organization != value.OtherOrganization && MemberPermissionContract.Text(value.BaselineRevision));
        foreach (var principal in value.Principals)
        {
            trial.Require(Enum.IsDefined(principal.Kind) && principal.Owned == (principal.Kind == MemberPermissionActorKind.User) &&
                (principal.Owned ? principal.Credential.Length > 0 &&
                    MemberPermissionContract.RawHash(principal.Credential) == principal.CredentialHash :
                    principal.Credential.Length == 0 && root.Authorities.All.Contains(principal.Id)));
            if (principal.Kind == MemberPermissionActorKind.User)
                trial.Require(!root.Authorities.All.Contains(principal.Id));
        }
        if (root.ActorKind == MemberPermissionActorKind.Machine)
            trial.Require(value.Principals[0].Id == root.Authorities.Runtime);
        trial.credentials = opened.Issuer.Payload.Content;
        trial.Require(trial.credentials.Select(c => c.Id).Distinct().Count() == trial.credentials.Length);
        foreach (var principal in value.Principals)
            trial.Require(trial.credentials.Contains(new(principal.CredentialId, principal.Id, principal.Kind,
                principal.CredentialHash, principal.Owned)));
        var actions = MemberPermissionContract.Supported(root.ScopeProfile);
        trial.Require(value.Rows.Length == 3 * actions.Sum(a => MemberPermissionContract.Controls(a).Length) &&
            value.Rows.Select(r => r.Id).Distinct().Count() == value.Rows.Length &&
            value.Rows.Select(r => r.Membership).Distinct().Count() == value.Rows.Length &&
            value.Rows.Select(r => r.User.Id).Distinct().Count() == value.Rows.Length &&
            trial.credentials.Length == value.Rows.Length + value.Principals.Length);
        foreach (string window in new[] { "before", "after", "copy" })
            foreach (var action in actions)
                foreach (string control in MemberPermissionContract.Controls(action))
                {
                    var rows = value.Rows.Where(r => r.Window == window && r.Action == action && r.Control == control).ToArray();
                    trial.Require(rows.Length == 1);
                    var row = rows[0];
                    trial.Require(row.Actor == (control is "actor" or "credential" ? 1 : control == "kind" ? 2 : 0) &&
                        row.Organization == (control == "scope" && root.ScopeProfile == MemberPermissionScope.Organization ?
                            value.OtherOrganization : root.Organization) &&
                        row.Project == (root.ScopeProfile == MemberPermissionScope.Organization ? "" :
                            control == "scope" ? value.OtherProject : window == "copy" ? value.CopyProject : value.Project) &&
                        !value.Principals.Any(p => p.Id == row.User.Id) &&
                        !root.Authorities.All.Contains(row.User.Id) &&
                        new[] { row.User.Id, row.User.Username, row.User.Email, row.Membership }.All(MemberPermissionContract.Text) &&
                        trial.credentials.Contains(new(row.User.CredentialId, row.User.Id, MemberPermissionActorKind.User,
                            row.User.CredentialHash, true)));
                    if (row.Action != MemberPermissionAction.Create && window != "copy")
                        trial.states.Add(row.Membership, MemberPermissionContract.Initial(row));
                }
        trial.revision = value.BaselineRevision;
        var enrolled = trial.reservation!.Enrolled;
        foreach (var row in value.Rows)
            trial.Require(enrolled.Any(e => e.Kind == "membership" && e.Id == row.Membership));
        foreach (var principal in value.Principals)
            foreach (string membership in new[] { principal.OrganizationMembership, principal.ProjectMembership, principal.CopyMembership })
                trial.Require(enrolled.Any(e => e.Kind == "membership" && e.Id == membership));
        foreach (var resource in new[] { ("policy", value.PolicyId), ("template", value.TemplateId), ("role", value.AssignedRole),
            ("project", value.Project), ("project", value.OtherProject), ("project", value.CopyProject),
            ("organization", value.OtherOrganization), ("issuer-work", root.Id), ("dispatch-work", root.Id),
            ("registration", root.Id), ("canary", root.Id) })
            trial.Require(enrolled.Any(e => e.Kind == resource.Item1 && e.Id == resource.Item2));
        trial.policies = opened.Policy.Payload.Content.Inventory;
        trial.Require(trial.policies.Length == (MemberPermissionContract.Create(root.Operation) ? 0 : 1));
        foreach (var policy in trial.policies)
        {
            trial.Require(policy.Resource == (MemberPermissionContract.Template(root.Operation) ? value.TemplateId : value.PolicyId));
            trial.CheckPolicy(policy, MemberPermissionContract.Baseline(root));
        }
        trial.CheckState(opened);
        trial.CheckJoins(opened, false);
        return trial;
    }
    internal MemberPermissionRow[] Rows(bool after) => Issued.Rows.Where(r => r.Window == (!after ? "before" :
        MemberPermissionContract.Template(root.Operation) && Outcome == MemberPermissionOutcome.Applied ? "copy" : "after")).ToArray();
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        var packet = await StepAsync(after ? MemberPermissionStep.After : MemberPermissionStep.Before, null, token);
        if (after && MemberPermissionContract.Template(root.Operation) && Outcome == MemberPermissionOutcome.Applied)
            foreach (var row in Rows(true).Where(r => r.Action != MemberPermissionAction.Create))
                states.Add(row.Membership, MemberPermissionContract.Initial(row));
        CheckState(packet);
    }
    internal async ValueTask ArmAsync(CancellationToken token)
    {
        var packet = await StepAsync(MemberPermissionStep.Arm, null, token);
        CheckState(packet); CheckPolicyInventory(packet);
    }
    internal async ValueTask SettleAsync(MemberPermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
        Original = receipt;
        var packet = await StepAsync(MemberPermissionStep.Settle, null, token);
        bool cancel = root.Boundary == "cancellation-boundary", denied = root.Boundary == "denied-authority",
            lost = root.Boundary == "lost-response-no-replay";
        var ingress = packet.Ingress.Payload.Content;
        var commits = packet.Policy.Payload.Content.Commits;
        Require(ingress.Length == (cancel ? 0 : 1) && commits.Length <= 1 &&
            (!(cancel || denied) || commits.Length == 0) && packet.Access.Payload.Content.Length == 0 &&
            packet.Storage.Payload.Content.Changes.Length == 0, "effect-mismatch");
        Require(receipt.Evidence == (cancel ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected :
            lost ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancel || lost) && (receipt.Cancelled ? receipt.Status is null :
                receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var entry in ingress)
            Require(requestIds.Add(entry.Request) && entry.Phase == "original" &&
                entry.ActorId == (denied ? root.Authorities.Denied : root.Authorities.Administrative) &&
                entry.ActorKind == MemberPermissionActorKind.Machine && entry.Authorized == !denied &&
                entry.IntentHash == receipt.IntentHash && entry.Path == MemberPermissionEffects.OriginalPath(root, Issued) &&
                entry.Method == (MemberPermissionContract.Create(root.Operation) ? "POST" : "PATCH"), "effect-mismatch");
        Outcome = MemberPermissionOutcome.NonApplied;
        if (commits.Length == 1)
        {
            var commit = commits[0];
            Require(commit.Request == ingress.Single().Request && commit.PreviousRevision == revision &&
                commit.Policy.Revision != revision &&
                commit.Policy.Resource == (MemberPermissionContract.Template(root.Operation) ? Issued.TemplateId : Issued.PolicyId),
                "effect-mismatch");
            revision = commit.Policy.Revision;
            // Partial requires a real, causally joined stored change. Missing evidence fails above.
            Outcome = PolicyMatches(commit.Policy, root.Action) ? MemberPermissionOutcome.Applied : MemberPermissionOutcome.Partial;
            policies = [commit.Policy];
        }
        Require(lost || (cancel || denied ? Outcome == MemberPermissionOutcome.NonApplied :
            Outcome == MemberPermissionOutcome.Applied), "effect-mismatch");
        CheckState(packet); CheckPolicyInventory(packet);
        Require(receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
    }
    internal void Activated(MemberPermissionReceipt receipt)
    {
        Require(stage == 6 && !failed && activation is null && receipt.Evidence == DispatchEvidence.Applied &&
            receipt.Native.Evidence == receipt.Evidence && receipt.Status == SecretStatus.Success && !receipt.Cancelled, "effect-mismatch");
        activation = receipt;
    }
    internal async ValueTask ObserveAsync(bool after, MemberPermissionAttempt[] attempts, CancellationToken token)
    {
        var packet = await StepAsync(after ? MemberPermissionStep.ObserveAfter : MemberPermissionStep.ObserveBefore, null, token);
        var ingress = packet.Ingress.Payload.Content;
        var decisions = packet.Access.Payload.Content;
        var changes = packet.Storage.Payload.Content.Changes;
        var commits = packet.Policy.Payload.Content.Commits;
        bool activate = after && Outcome == MemberPermissionOutcome.Applied &&
            (MemberPermissionContract.Template(root.Operation) ||
                root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal) ||
                root.Operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal));
        Require(attempts.Select(a => a.Row).SequenceEqual(Rows(after)) &&
            decisions.Length == attempts.Length && changes.Length == attempts.Length &&
            ingress.Length == attempts.Length + (activate ? 1 : 0) && commits.Length == (activate ? 1 : 0), "effect-mismatch");
        foreach (var entry in ingress) Require(requestIds.Add(entry.Request), "effect-mismatch");
        if (activate)
        {
            var commit = commits.Single();
            var entry = ingress.Single(i => i.Request == commit.Request);
            Require(activation is not null && entry.Phase == "activation" && entry.ActorId == root.Authorities.Setup &&
                entry.ActorKind == MemberPermissionActorKind.Machine && entry.Authorized &&
                entry.IntentHash == activation.IntentHash && commit.PreviousRevision == revision &&
                commit.Policy.Revision == revision &&
                commit.Policy.Resource == (MemberPermissionContract.Template(root.Operation) ? Issued.CopyProject : Issued.PolicyId) &&
                PolicyMatches(commit.Policy, root.Action), "effect-mismatch");
            policies = MemberPermissionContract.Template(root.Operation) ? [.. policies, commit.Policy] : [commit.Policy];
        }
        for (int i = 0; i < attempts.Length; i++)
        {
            var attempt = attempts[i]; var row = attempt.Row; var decision = decisions[i];
            var actor = Issued.Principals[row.Actor];
            bool allowed = MemberPermissionContract.Allowed(root, row, after, Outcome);
            bool read = row.Action == MemberPermissionAction.Read;
            Require(attempt.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) &&
                attempt.Evidence == (read ? null : allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected) &&
                attempt.CredentialHash == actor.CredentialHash && attempt.Complete, "effect-mismatch");
            var request = ingress.SingleOrDefault(e => e.Request == decision.Request);
            Require(request is not null && request.Phase == "action" && request.ActorId == actor.Id &&
                request.ActorKind == actor.Kind && request.CredentialHash == actor.CredentialHash &&
                request.Authorized == allowed && request.Method == MemberPermissionClient.Method(root.ScopeProfile, row.Action) &&
                request.Path == MemberPermissionClient.Path(root.ScopeProfile, row), "effect-mismatch");
            Require(decision.ActorId == actor.Id && decision.ActorKind == actor.Kind && decision.CredentialId == actor.CredentialId &&
                decision.CredentialHash == actor.CredentialHash && decision.Organization == row.Organization &&
                decision.Project == row.Project && decision.Revision == revision && decision.Action == row.Action &&
                decision.Allowed == allowed && (root.ScopeProfile == MemberPermissionScope.Organization && read ?
                    decision.User is null && decision.Membership is null :
                    decision.User == row.User.Id && decision.Membership == row.Membership), "effect-mismatch");
            var previous = states.GetValueOrDefault(row.Membership);
            var expected = !allowed ? previous : row.Action switch
            {
                MemberPermissionAction.Create => MemberPermissionContract.Initial(row),
                MemberPermissionAction.Delete => null,
                MemberPermissionAction.Edit => previous! with { Active = false, Version = previous.Version + 1 },
                MemberPermissionAction.GrantPrivileges or MemberPermissionAction.AssignRole =>
                    previous! with { Role = Issued.AssignedRole, Version = previous.Version + 1 },
                _ => previous
            };
            Require(changes[i] == new MemberPermissionChange(decision.Request, row.Membership, previous, expected), "effect-mismatch");
            if (expected is null) states.Remove(row.Membership); else states[row.Membership] = expected;
            if (allowed)
            {
                if (root.ScopeProfile == MemberPermissionScope.Organization && read)
                {
                    var expectedRows = states.Values.Where(s => s.Organization == row.Organization).OrderBy(s => s.Membership).ToArray();
                    Require(attempt.Values.OrderBy(s => s.Membership).Select(s => s with { Version = 0 })
                        .SequenceEqual(expectedRows.Select(s => s with { Version = 0 })), "effect-mismatch");
                }
                else
                {
                    Require(attempt.Values.Length == 1, "effect-mismatch");
                    var value = attempt.Values[0];
                    var intended = row.Action == MemberPermissionAction.Delete ? previous! : expected!;
                    // Typed mutation responses omit some fields; independently signed storage owns those fields.
                    Require(value.Membership == intended.Membership && value.User == intended.User &&
                        value.Organization == intended.Organization && value.Project == intended.Project &&
                        (row.Action != MemberPermissionAction.Read || value.Username == intended.Username), "effect-mismatch");
                }
            }
            else Require(attempt.Values.Length == 0, "effect-mismatch");
        }
        CheckState(packet); CheckPolicyInventory(packet); CheckJoins(packet, after);
    }
    private bool PolicyMatches(MemberPermissionPolicy policy, MemberPermissionAction action) =>
        policy.ActorId == Issued.Principals[0].Id && policy.ActorKind == root.ActorKind &&
        policy.Organization == root.Organization && policy.Project == (root.ScopeProfile == MemberPermissionScope.Organization ? "" :
            policy.Resource == Issued.CopyProject ? Issued.CopyProject : Issued.Project) &&
        policy.Subject == "member" && policy.Actions.SequenceEqual([MemberPermissionContract.Wire(action)]) &&
        policy.Emails.Order().SequenceEqual((action == MemberPermissionAction.AssignRole ?
            Issued.Rows.Where(r => r.Control == "selected").Select(r => r.User.Email).ToArray() : []).Order()) &&
        policy.AssignedRole == (action == MemberPermissionAction.AssignRole ? Issued.AssignedRole : "");
    private void CheckPolicy(MemberPermissionPolicy policy, MemberPermissionAction action) =>
        Require(PolicyMatches(policy, action), "effect-mismatch");
    private void CheckState(MemberPermissionPacket packet)
    {
        Require(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Membership)
            .SequenceEqual(states.Values.OrderBy(s => s.Membership)), "effect-mismatch");
        var remaining = packet.Owner.Payload.Content.Remaining;
        foreach (var state in states.Values)
            Require(remaining.Any(e => e.Kind == "membership" && e.Id == state.Membership), "effect-mismatch");
    }
    private void CheckPolicyInventory(MemberPermissionPacket packet) =>
        Require(MemberPermissionContract.Hash(packet.Policy.Payload.Content.Inventory.OrderBy(p => p.Resource).ToArray()) ==
            MemberPermissionContract.Hash(policies.OrderBy(p => p.Resource).ToArray()), "effect-mismatch");
    private void CheckJoins(MemberPermissionPacket packet, bool after)
    {
        var joins = packet.Membership.Payload.Content;
        Require(joins.Select(j => (j.Principal, j.Organization, j.Project)).Distinct().Count() == joins.Length);
        bool copied = after && MemberPermissionContract.Template(root.Operation) && Outcome == MemberPermissionOutcome.Applied;
        var expected = Issued.Rows.Where(r => r.Window != "copy" || copied).Select(row =>
            new MemberPermissionJoin(row.User.Id, MemberPermissionActorKind.User, row.Organization, row.Project, row.Membership, false)).ToList();
        for (int i = 0; i < Issued.Principals.Length; i++)
        {
            var principal = Issued.Principals[i];
            expected.Add(new(principal.Id, principal.Kind, root.Organization,
                root.ScopeProfile == MemberPermissionScope.Organization ? "" : Issued.Project,
                root.ScopeProfile == MemberPermissionScope.Organization ? principal.OrganizationMembership : principal.ProjectMembership,
                i == 0 && (!MemberPermissionContract.Create(root.Operation) || after && Outcome == MemberPermissionOutcome.Applied && !copied)));
        }
        if (copied) expected.Add(new(Issued.Principals[0].Id, root.ActorKind, root.Organization, Issued.CopyProject,
            Issued.Principals[0].CopyMembership, true));
        Require(joins.Length == expected.Count && expected.All(joins.Contains));
        var actor = Issued.Principals[0];
        string project = root.ScopeProfile == MemberPermissionScope.Organization ? "" :
            after && MemberPermissionContract.Template(root.Operation) && Outcome == MemberPermissionOutcome.Applied ? Issued.CopyProject : Issued.Project;
        string membership = root.ScopeProfile == MemberPermissionScope.Organization ? actor.OrganizationMembership :
            project == Issued.CopyProject ? actor.CopyMembership : actor.ProjectMembership;
        Require(joins.Contains(new(actor.Id, actor.Kind, root.Organization, project, membership,
            !MemberPermissionContract.Create(root.Operation) || after && Outcome == MemberPermissionOutcome.Applied)));
    }
    private async ValueTask<MemberPermissionPacket> StepAsync(MemberPermissionStep step, SecretMaterial? cap, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step);
        busy = failed = true; stage++;
        try
        {
            var packet = await source.StepAsync(root, step, cap, token);
            // Retain returned private bytes before any verification can reject their joins.
            if (step == MemberPermissionStep.Open) issued = packet.Owner.Payload.Content.Issued;
            Validate(packet, step);
            failed = false;
            return packet;
        }
        finally { busy = false; }
    }
    private void Validate(MemberPermissionPacket packet, MemberPermissionStep step)
    {
        Require(packet.Seals.Length == 7 && packet.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 7);
        var owner = verifier.Journal(packet.Owner, packet, MemberPermissionJournal.Ownership, step);
        _ = verifier.Journal(packet.Ingress, packet, MemberPermissionJournal.Ingress, step);
        _ = verifier.Journal(packet.Policy, packet, MemberPermissionJournal.Policy, step);
        _ = verifier.Journal(packet.Storage, packet, MemberPermissionJournal.Storage, step);
        var issuer = verifier.Journal(packet.Issuer, packet, MemberPermissionJournal.Issuer, step);
        _ = verifier.Journal(packet.Membership, packet, MemberPermissionJournal.Membership, step);
        _ = verifier.Journal(packet.Access, packet, MemberPermissionJournal.Access, step);
        Require(owner.CollisionChecked && owner.PreEnrolled && owner.Exclusive && owner.Pending == 0 &&
            (step is not (MemberPermissionStep.Settle or MemberPermissionStep.Close) || owner.IssuerFence && owner.IngressFence) &&
            owner.Enrolled.Distinct().Count() == owner.Enrolled.Length &&
            owner.Remaining.Distinct().Count() == owner.Remaining.Length &&
            owner.Borrowed.Select(b => (b.Kind, b.Id)).Distinct().Count() == owner.Borrowed.Length &&
            owner.Enrolled.All(e => e.Root == root.Id && e.Nonce == root.Nonce) &&
            owner.Remaining.All(owner.Enrolled.Contains) &&
            !owner.Enrolled.Any(e => owner.Borrowed.Any(b => e.Kind == b.Kind && e.Id == b.Id)) &&
            (reservation is null || owner.Borrowed.SequenceEqual(reservation.Borrowed) &&
                owner.Enrolled.SequenceEqual(reservation.Enrolled)));
        if (step is not (MemberPermissionStep.Reserve or MemberPermissionStep.Open or MemberPermissionStep.Close))
            Require(issuer.SequenceEqual(credentials));
        if (step == MemberPermissionStep.Open)
        {
            foreach (var c in issuer.Where(c => c.Owned))
                Require(owner.Enrolled.Any(e => e.Kind == "credential" && e.Id == c.Id) &&
                    owner.Enrolled.Any(e => e.Kind == "user" && e.Id == c.Principal));
        }
    }
    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        closed = true;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var packet = await source.StepAsync(root, MemberPermissionStep.Close, null, timeout.Token);
            Validate(packet, MemberPermissionStep.Close);
            var owner = packet.Owner.Payload.Content;
            Require(owner.Registrations == 0 && owner.Remaining.Length == 0 &&
                packet.Policy.Payload.Content.Inventory.Length == 0 && packet.Storage.Payload.Content.Inventory.Length == 0 &&
                packet.Issuer.Payload.Content.Length == 0 && packet.Membership.Payload.Content.Length == 0, "cleanup-incomplete");
        }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { issued?.Erase(); verifier.Dispose(); }
    }
    private void Require(bool value, string code = "observer-unavailable")
    { if (!value) failed = true; MemberPermissionContract.Require(value, code); }
}
