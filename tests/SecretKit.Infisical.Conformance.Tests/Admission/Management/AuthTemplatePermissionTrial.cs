using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class AuthTemplatePermissionTrial : IAsyncDisposable
{
    private readonly IAuthTemplatePermissionSource source;
    private readonly AuthTemplatePermissionVerifier verifier;
    private AuthTemplatePermissionIssued? issued;
    private int stage, requestStart, policyStart;
    private bool busy, failed, closed;
    private AuthTemplatePermissionReceipt? activation;
    internal AuthTemplatePermissionRoot Root { get; }
    internal AuthTemplatePermissionPlan Plan { get; }
    internal AuthTemplatePermissionIssued Issued => issued ?? throw new NativeCaseFailureException("observer-unavailable");
    internal AuthTemplatePermissionReceipt? Original { get; private set; }
    internal AuthTemplatePermissionOutcome Outcome { get; private set; }
    internal AuthTemplatePermissionState[] Inventory => verifier.Inventory;
    private AuthTemplatePermissionTrial(IAuthTemplatePermissionSource source, AuthTemplatePermissionRoot root)
    { this.source = source; Root = root; Plan = new(root); verifier = new(root); }
    internal static async ValueTask<AuthTemplatePermissionTrial> OpenAsync(IAuthTemplatePermissionSource source, AuthTemplatePermissionRoot root,
        SecretMaterial capability, Action<AuthTemplatePermissionTrial> retain, CancellationToken token)
    {
        Require(source.Identity == root.Source && source.Kind == root.Kind && Enum.IsDefined(root.Kind) &&
            AuthTemplatePermissionContract.Operations.Contains(root.Operation) && Enum.IsDefined(root.Action) &&
            AuthTemplatePermissionContract.Gate(root.Action) is null && root.Variant == AuthTemplatePermissionContract.Variant(root.Action) &&
            AuthTemplatePermissionContract.Boundaries.Contains(root.Boundary) && root.Authorities.All.Distinct().Count() == 5 &&
            root.Authorities.All.All(MemberPermissionContract.Text) && !root.Authorities.All.Contains(root.Source) &&
            root.Profile.Pins.All(p => p.Writer != root.Source && !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(MemberPermissionContract.Text), "missing-input");
        var trial = new AuthTemplatePermissionTrial(source, root);
        retain(trial); // Root cleanup is retained before either Reserve or Open.
        await trial.StepAsync(AuthTemplatePermissionStep.Reserve, capability, token);
        await trial.StepAsync(AuthTemplatePermissionStep.Open, null, token);
        var issued = trial.Issued;
        Require(issued.Actors.Length == 5 && issued.Actors.Select(a => a.Identity.Principal).Distinct().Count() == 5 &&
            issued.Actors.Select(a => a.Identity.Id).Distinct().Count() == 5 && issued.Actors.Select(a => a.Identity.Hash).Distinct().Count() == 5);
        for (int i = 0; i < 5; i++)
        {
            var actor = issued.Actors[i]; var c = actor.Identity;
            Require(c.Owned && !root.Authorities.All.Contains(c.Principal) && c.Principal == issued.Id(trial.Plan.ActorKey(i)) &&
                c.Kind == trial.Plan.ActorKind(i) && c.Organization == issued.Id(trial.Plan.OrganizationKey(i)) &&
                c.Id == issued.Id("credential-" + i) && actor.Credential.Length > 0 && c.Hash == AuthTemplatePermissionContract.RawHash(actor.Credential) &&
                trial.verifier.Credentials.Contains(c));
        }
        Require(trial.verifier.Inventory.Length == 3 && trial.verifier.Members.Length == 5 &&
            trial.verifier.Policies.Length == (AuthTemplatePermissionContract.Create(root.Operation) ? 0 : 1));
        foreach (var p in trial.verifier.Policies) Require(trial.PolicyMatches(p, []) && p.Revision == "policy-1" && p.Configuration == "bootstrap");
        trial.CheckMembers(false); return trial;
    }
    private bool PolicyMatches(AuthTemplatePermissionPolicy p, string[] actions) =>
        p.Id == Issued.Id(AuthTemplatePermissionPlan.Policy) && p.Actor == Issued.Actors[0].Identity.Principal &&
        p.Kind == MemberPermissionActorKind.User && p.Organization == Root.Organization &&
        p.Subject == AuthTemplatePermissionContract.Subject && p.Actions.SequenceEqual(actions) && p.Slug == Plan.Slug;
    private void CheckMembers(bool applied)
    {
        Require(verifier.Members.Length == 5);
        for (int i = 0; i < 5; i++)
        {
            var c = Issued.Actors[i].Identity;
            Require(verifier.Members.Contains(new(Issued.Id("member-" + i), c.Principal, c.Kind, c.Organization,
                applied && i == 0 ? Issued.Id(AuthTemplatePermissionPlan.Policy) : "", applied && i == 0 ? Plan.Slug : "no-access",
                true, "accepted", applied && i == 0 ? Issued.Id("assignment") : "")), "effect-mismatch");
        }
    }
    internal AuthTemplatePermissionRow[] Rows() => Plan.Rows();
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        await StepAsync(after ? AuthTemplatePermissionStep.After : AuthTemplatePermissionStep.Before, null, token);
        CheckMembers(after && Outcome == AuthTemplatePermissionOutcome.Applied);
    }
    internal async ValueTask ArmAsync(CancellationToken token)
    {
        await StepAsync(AuthTemplatePermissionStep.Arm, null, token);
        requestStart = verifier.Requests.Length; policyStart = verifier.PolicyChanges.Length;
    }
    internal async ValueTask SettleAsync(AuthTemplatePermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Native.Evidence == receipt.Evidence, "effect-mismatch"); Original = receipt;
        await StepAsync(AuthTemplatePermissionStep.Settle, null, token);
        bool cancel = Root.Boundary == "cancellation-boundary", denied = Root.Boundary == "denied-authority", lost = Root.Boundary == "lost-response-no-replay";
        var entries = verifier.Requests.Skip(requestStart).ToArray(); var commits = verifier.PolicyChanges.Skip(policyStart).ToArray();
        Require(entries.Length == (cancel ? 0 : 1) && commits.Length <= 1 && (!(cancel || denied) || commits.Length == 0) &&
            receipt.Evidence == (cancel ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected : lost ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancel || lost) && (receipt.Cancelled ? receipt.Status is null : receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var e in entries)
            Require(e.Phase == "original" && e.Actor == (denied ? Root.Authorities.Denied : Root.Authorities.Administrative) &&
                e.IntentHash == receipt.IntentHash && e.Path == AuthTemplatePermissionEffects.OriginalPath(Root, Issued), "effect-mismatch");
        Outcome = AuthTemplatePermissionOutcome.NonApplied;
        if (commits.Length == 1)
        {
            var policy = commits[0].After;
            Require(policy is not null && commits[0].Request == entries.Single().Id && policy.Configuration == entries.Single().BodyHash &&
                policy.Revision == "policy-2", "effect-mismatch");
            Outcome = PolicyMatches(policy!, [AuthTemplatePermissionContract.Wire(Root.Action)]) ?
                AuthTemplatePermissionOutcome.Applied : AuthTemplatePermissionOutcome.Partial;
        }
        Require(lost || (cancel || denied ? Outcome == AuthTemplatePermissionOutcome.NonApplied : Outcome == AuthTemplatePermissionOutcome.Applied), "effect-mismatch");
        requestStart = verifier.Requests.Length;
    }
    internal void Activated(AuthTemplatePermissionReceipt receipt)
    {
        Require(stage == 6 && activation is null && receipt.Status == SecretStatus.Success && !receipt.Cancelled &&
            receipt.Evidence == DispatchEvidence.Applied && receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
        activation = receipt;
    }
    internal async ValueTask ObserveAsync(bool after, AuthTemplatePermissionAttempt[] attempts, CancellationToken token)
    {
        await StepAsync(after ? AuthTemplatePermissionStep.ObserveAfter : AuthTemplatePermissionStep.ObserveBefore, null, token);
        var events = verifier.Requests.Skip(requestStart).ToArray();
        bool applied = after && Outcome == AuthTemplatePermissionOutcome.Applied;
        Require(attempts.Select(a => a.Row).SequenceEqual(Rows()) && events.Length == attempts.Length + (applied ? 1 : 0), "effect-mismatch");
        if (applied) Require(activation is not null && events[0].Phase == "activation" && events[0].IntentHash == activation.IntentHash, "effect-mismatch");
        var requests = events.Where(e => e.Phase == "template").ToArray();
        Require(requests.Length == attempts.Length, "effect-mismatch");
        for (int i = 0; i < attempts.Length; i++)
        {
            var attempt = attempts[i]; var r = requests[i]; var actor = Issued.Actors[attempt.Row.Actor].Identity;
            bool allowed = applied && attempt.Row.Control == "selected";
            Require(attempt.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) && attempt.Complete &&
                attempt.CredentialHash == actor.Hash && r.Actor == actor.Principal && r.Kind == actor.Kind &&
                r.Organization == actor.Organization && r.CredentialId == actor.Id && r.CredentialHash == actor.Hash &&
                r.Path == Plan.RequestPath(attempt.Row.Action, Issued.Id) && r.IntentHash == attempt.IntentHash, "effect-mismatch");
            if (r.Method != "GET")
            {
                Require(attempt.Receipt is not null && attempt.Receipt.Evidence == attempt.Evidence &&
                    attempt.Evidence == (allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected), "effect-mismatch");
                var change = verifier.Changes.Single(c => c.Request == r.Id);
                if (allowed && attempt.Row.Action != AuthTemplatePermissionAction.Delete)
                { Require(attempt.Values.Length == 1 && change.After is not null, "effect-mismatch"); AuthTemplatePermissionEffects.Match(attempt.Values.Single(), change.After!); }
            }
            else if (allowed)
            {
                var collection = verifier.Collections.Single(c => c.Request == r.Id);
                Require(attempt.Values.Length == collection.Rows.Length && attempt.Values.Any(v => v.Id == Issued.Id(AuthTemplatePermissionPlan.Selected)), "effect-mismatch");
                for (int j = 0; j < attempt.Values.Length; j++) AuthTemplatePermissionEffects.Match(attempt.Values[j], collection.Rows[j]);
            }
            if (!allowed) Require(attempt.Values.Length == 0, "effect-mismatch");
        }
        CheckMembers(applied);
        if (after) Require(Original is not null && Original.Native.Evidence == Original.Evidence, "effect-mismatch");
    }
    private async ValueTask StepAsync(AuthTemplatePermissionStep step, SecretMaterial? capability, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step); busy = failed = true; stage++;
        try
        {
            var packet = await source.StepAsync(Root, step, capability, token);
            if (step == AuthTemplatePermissionStep.Open) issued = new([], packet.Actors);
            verifier.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = verifier.Bindings };
            if (step == AuthTemplatePermissionStep.Before) requestStart = verifier.Requests.Length;
            failed = false;
        }
        finally { busy = false; }
    }
    public async ValueTask DisposeAsync()
    {
        if (closed) return; closed = true;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try { verifier.Check(await source.StepAsync(Root, AuthTemplatePermissionStep.Close, null, deadline.Token), AuthTemplatePermissionStep.Close); }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { issued?.Erase(); verifier.Dispose(); }
    }
    private static void Require(bool condition, string code = "observer-unavailable") => AuthTemplatePermissionContract.Require(condition, code);
}
