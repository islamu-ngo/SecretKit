using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class SettingsPermissionTrial : IAsyncDisposable
{
    private readonly ISettingsPermissionSource source;
    private readonly SettingsPermissionVerifier verifier;
    private SettingsPermissionIssued? issued;
    private int stage, requestStart, policyStart;
    private bool busy, failed, closed;
    private SettingsPermissionReceipt? activation;
    internal SettingsPermissionRoot Root { get; }
    internal SettingsPermissionPlan Plan { get; }
    internal SettingsPermissionIssued Issued => issued ?? throw new SecretKit.TestFixtures.NativeCaseFailureException("observer-unavailable");
    internal SettingsPermissionReceipt? Original { get; private set; }
    internal SettingsPermissionOutcome Outcome { get; private set; }
    internal SettingsPermissionState[] Inventory => verifier.Inventory;
    private SettingsPermissionTrial(ISettingsPermissionSource source, SettingsPermissionRoot root)
    { this.source = source; Root = root; Plan = new(root); verifier = new(root); }
    internal static async ValueTask<SettingsPermissionTrial> OpenAsync(ISettingsPermissionSource source, SettingsPermissionRoot root,
        SecretMaterial capability, Action<SettingsPermissionTrial> retain, CancellationToken token)
    {
        Require(source.Identity == root.Source && source.Kind == root.Kind && Enum.IsDefined(root.Kind) &&
            SettingsPermissionContract.Operations.Contains(root.Operation) && root.ScopeProfile == SettingsPermissionScope.Project && SettingsPermissionContract.Scope(root.Operation) == root.ScopeProfile &&
            root.ActorKind == SettingsPermissionContract.ActorKind(root.Operation) && root.Action == SettingsPermissionAction.Edit &&
            root.Variant == SettingsPermissionContract.Variant(root.Action) && SettingsPermissionContract.Boundaries.Contains(root.Boundary) &&
            root.Authorities.All.Distinct().Count() == 5 && root.Authorities.All.All(MemberPermissionContract.Text) &&
            !root.Authorities.All.Contains(root.Source) && root.Profile.Pins.All(p => p.Writer != root.Source && !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(MemberPermissionContract.Text), "missing-input");
        var trial = new SettingsPermissionTrial(source, root);
        retain(trial); // Retain original-root cleanup BEFORE Reserve or Open can fail.
        await trial.StepAsync(SettingsPermissionStep.Reserve, capability, token);
        await trial.StepAsync(SettingsPermissionStep.Open, null, token);
        var v = trial.Issued; var plan = trial.Plan;
        Require(v.Actors.Length == 4 && v.Actors.Select(a => a.Identity.Principal).Distinct().Count() == 4 &&
            v.Actors.Select(a => a.Identity.Id).Distinct().Count() == 4 && v.Actors.Select(a => a.Identity.Hash).Distinct().Count() == 4 &&
            v.Actors.All(a => a.Identity.Owned && !root.Authorities.All.Contains(a.Identity.Principal)));
        for (int i = 0; i < 4; i++)
        {
            var a = v.Actors[i]; var c = a.Identity;
            Require(c.Principal == v.Id(plan.ActorKey(i)) && c.Kind == plan.ActorKind(i) && c.Organization == root.Organization &&
                c.Owned == !plan.ActorKey(i).StartsWith('@') && trial.verifier.Credentials.Contains(c) &&
                (c.Owned ? c.Id == v.Id("credential-" + i) && a.Credential.Length > 0 &&
                    c.Hash == SettingsPermissionContract.RawHash(a.Credential) : a.Credential.Length == 0));
        }
        trial.CheckInitial(); return trial;
    }
    private bool Copied(bool after) => after && Outcome == SettingsPermissionOutcome.Applied && SettingsPermissionContract.Template(Root.Operation);
    internal SettingsPermissionRow[] Rows(bool after) => Plan.Rows(Copied(after));
    private void CheckInitial()
    {
        Require(verifier.Inventory.Length == 2 && verifier.Members.Length == 4 &&
            verifier.Policies.Length == (SettingsPermissionContract.Create(Root.Operation) ? 0 : 1));
        foreach (var p in verifier.Policies) Require(PolicyMatches(p, "read") && p.Revision == "policy-1" && p.Configuration == "bootstrap");
        CheckMembers(false);
    }
    private bool PolicyMatches(SettingsPermissionPolicy p, string action) =>
        p.Actor == Issued.Actors[0].Identity.Principal && p.Kind == Root.ActorKind && p.Organization == Root.Organization &&
        p.Project == (SettingsPermissionContract.Template(Root.Operation) && p.Id == Issued.Id(Plan.PolicyKey) ? "" :
            Issued.Id(p.Id == Issued.Id(SettingsPermissionPlan.CopyPolicy) ? SettingsPermissionPlan.CopyProject : SettingsPermissionPlan.Project)) &&
        p.Subject == "settings" && p.Actions.SequenceEqual([action]) && p.Role == Plan.Slug;
    private void CheckMembers(bool copied)
    {
        Require(verifier.Members.Length == (copied ? 5 : 4));
        bool assigned = !SettingsPermissionContract.Template(Root.Operation) &&
            (!SettingsPermissionContract.Create(Root.Operation) || Outcome == SettingsPermissionOutcome.Applied);
        for (int i = 0; i < 4; i++)
        {
            var actor = Issued.Actors[i].Identity;
            var expected = new SettingsPermissionMember(Issued.Id("member-" + i), actor.Principal, actor.Kind, Root.Organization,
                Issued.Id(SettingsPermissionPlan.Project), i == 0 && assigned ? Issued.Id(Plan.PolicyKey) : "",
                i == 0 && assigned ? Plan.Slug : "no-access", true, "accepted",
                i == 0 && assigned && actor.Kind == MemberPermissionActorKind.User ? Issued.Id("assignment") : "");
            Require(verifier.Members.Contains(expected), "effect-mismatch");
        }
        if (copied)
        {
            var c = verifier.Copies.Single();
            Require(verifier.Members.Contains(new(c.Membership, Issued.Actors[0].Identity.Principal, Root.ActorKind,
                Root.Organization, c.Project, c.Policy, Plan.Slug, true, "accepted", Issued.Id("copy-assignment"))), "effect-mismatch");
        }
    }
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        await StepAsync(after ? SettingsPermissionStep.After : SettingsPermissionStep.Before, null, token);
        if (Copied(after)) Require(verifier.Copies.Length == 1 && verifier.Inventory.Length == 3);
        else Require(verifier.Copies.Length == 0 && verifier.Inventory.Length == 2);
        CheckMembers(Copied(after));
    }
    internal async ValueTask ArmAsync(CancellationToken token)
    {
        await StepAsync(SettingsPermissionStep.Arm, null, token);
        requestStart = verifier.Requests.Length; policyStart = verifier.PolicyChanges.Length;
    }
    internal async ValueTask SettleAsync(SettingsPermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Native.Evidence == receipt.Evidence, "effect-mismatch"); Original = receipt;
        await StepAsync(SettingsPermissionStep.Settle, null, token);
        bool cancel = Root.Boundary == "cancellation-boundary", denied = Root.Boundary == "denied-authority", lost = Root.Boundary == "lost-response-no-replay";
        var entries = verifier.Requests.Skip(requestStart).ToArray(); var commits = verifier.PolicyChanges.Skip(policyStart).ToArray();
        Require(entries.Length == (cancel ? 0 : 1) && commits.Length <= 1 && (!(cancel || denied) || commits.Length == 0) &&
            receipt.Evidence == (cancel ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected : lost ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancel || lost) && (receipt.Cancelled ? receipt.Status is null : receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var e in entries)
            Require(e.Phase == "original" && e.Actor == (denied ? Root.Authorities.Denied : Root.Authorities.Administrative) &&
                e.Kind == MemberPermissionActorKind.Machine && e.IntentHash == receipt.IntentHash &&
                e.Method == (SettingsPermissionContract.Create(Root.Operation) ? "POST" : "PATCH") &&
                e.Path == SettingsPermissionEffects.OriginalPath(Root, Plan, Issued), "effect-mismatch");
        Outcome = SettingsPermissionOutcome.NonApplied;
        if (commits.Length == 1)
        {
            var commit = commits[0]; var policy = commit.After;
            Require(policy is not null && commit.Request == entries.Single().Id && policy.Id == Issued.Id(Plan.PolicyKey) &&
                policy.Configuration == entries.Single().BodyHash && policy.Revision == "policy-2", "effect-mismatch");
            Outcome = PolicyMatches(policy!, "edit") ? SettingsPermissionOutcome.Applied : SettingsPermissionOutcome.Partial;
        }
        Require(lost || (cancel || denied ? Outcome == SettingsPermissionOutcome.NonApplied : Outcome == SettingsPermissionOutcome.Applied), "effect-mismatch");
        requestStart = verifier.Requests.Length; policyStart = verifier.PolicyChanges.Length;
    }
    internal void Activated(SettingsPermissionReceipt receipt)
    {
        Require(stage == 6 && activation is null && receipt.Status == SecretStatus.Success && !receipt.Cancelled &&
            receipt.Evidence == DispatchEvidence.Applied && receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
        activation = receipt;
    }
    internal async ValueTask ObserveAsync(bool after, SettingsPermissionAttempt[] attempts, CancellationToken token)
    {
        await StepAsync(after ? SettingsPermissionStep.ObserveAfter : SettingsPermissionStep.ObserveBefore, null, token);
        var events = verifier.Requests.Skip(requestStart).ToArray();
        bool activate = after && Outcome == SettingsPermissionOutcome.Applied &&
            (SettingsPermissionContract.Template(Root.Operation) || Root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal));
        Require(attempts.Select(a => a.Row).SequenceEqual(Rows(after)) && events.Length == 5 + (activate ? 1 : 0), "effect-mismatch");
        if (activate)
            Require(activation is not null && events[0].Phase == "activation" && events[0].Actor == Root.Authorities.Setup &&
                events[0].IntentHash == activation.IntentHash, "effect-mismatch");
        var reads = events.Where(e => e.Phase == "patch").ToArray(); Require(reads.Length == 5, "effect-mismatch");
        for (int i = 0; i < attempts.Length; i++)
        {
            var a = attempts[i]; var actor = Issued.Actors[a.Row.Actor].Identity; var entry = reads[i];
            bool allowed = after && Outcome == SettingsPermissionOutcome.Applied && a.Row.Control == "selected";
            var change = verifier.Changes.Single(c => c.Request == entry.Id);
            Require(a.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) &&
                a.Evidence == (allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected) && a.Receipt.Evidence == a.Evidence &&
                a.InputHash == Plan.PatchHash && entry.BodyHash == a.InputHash && entry.IntentHash == a.InputHash &&
                a.CredentialHash == actor.Hash && entry.Actor == actor.Principal && entry.Kind == actor.Kind &&
                entry.CredentialId == actor.Id && entry.CredentialHash == actor.Hash &&
                entry.Path == "/api/v1/projects/" + Issued.Id(a.Row.Project), "effect-mismatch");
            if (allowed) { Require(a.Value is not null, "effect-mismatch"); SettingsPermissionReadback.Match(a.Value!, change.After!, false); }
            else Require(a.Value is null, "effect-mismatch");
        }
        CheckMembers(Copied(after));
        if (after)
        {
            Require(Original is not null && Original.Native.Evidence == Original.Evidence, "effect-mismatch");
            foreach (var p in verifier.Policies) Require(PolicyMatches(p, Outcome == SettingsPermissionOutcome.Applied ? "edit" : "read"), "effect-mismatch");
        }
    }
    private async ValueTask StepAsync(SettingsPermissionStep step, SecretMaterial? capability, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step); busy = failed = true; stage++;
        try
        {
            var packet = await source.StepAsync(Root, step, capability, token);
            // Retain unverified owned bytes too, so signature failure still erases them.
            if (step == SettingsPermissionStep.Open) issued = new([], packet.Actors);
            verifier.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = verifier.Bindings };
            if (step == SettingsPermissionStep.Before) requestStart = verifier.Requests.Length;
            failed = false;
        }
        finally { busy = false; }
    }
    public async ValueTask DisposeAsync()
    {
        if (closed) return; closed = true;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var packet = await source.StepAsync(Root, SettingsPermissionStep.Close, null, deadline.Token);
            verifier.Check(packet, SettingsPermissionStep.Close);
        }
        catch (SecretKit.TestFixtures.NativeCaseFailureException) { throw new SecretKit.TestFixtures.NativeCaseFailureException("cleanup-incomplete"); }
        finally { issued?.Erase(); verifier.Dispose(); }
    }
    private static void Require(bool value, string code = "observer-unavailable") => SettingsPermissionContract.Require(value, code);
}
