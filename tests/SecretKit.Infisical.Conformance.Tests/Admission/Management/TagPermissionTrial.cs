using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class TagPermissionTrial : IAsyncDisposable
{
    private readonly ITagPermissionSource source;
    private readonly TagPermissionRoot root;
    private readonly TagPermissionVerifier verify, fences, policyInventory;
    private readonly HashSet<string> requests = [];
    private readonly Dictionary<Guid, TagPermissionState> states = [];
    private readonly Dictionary<string, TagPermissionPolicyState> policies = [];
    private TagPermissionOwner? reservation;
    private int stage;
    private bool busy, failed, closed;
    private string revision = "";
    private TagPermissionReceipt? activation;
    internal TagPermissionIssued Issued { get; private set; } = null!;
    internal TagPermissionReceipt? Original { get; private set; }
    internal TagPermissionOutcome Outcome { get; private set; }
    internal string Revision => revision;
    private TagPermissionTrial(ITagPermissionSource source, TagPermissionRoot root)
    { this.source = source; this.root = root; verify = new(root); fences = new(root); policyInventory = new(root); }
    internal static async ValueTask<TagPermissionTrial> OpenAsync(ITagPermissionSource source,
        TagPermissionRoot root, SecretMaterial capability, Action<TagPermissionTrial> retain, CancellationToken token)
    {
        TagPermissionContract.Require(source.Identity == root.Source && source.Kind == root.Kind &&
            Enum.IsDefined(root.Kind) && Enum.IsDefined(root.Action) && TagPermissionContract.Operations.Contains(root.Operation) &&
            root.Variant == TagPermissionContract.Variant(root.Operation, root.Action) &&
            root.Boundary is ("selected-contract" or "independent-effect" or "denied-authority" or
                "cancellation-boundary" or "lost-response-no-replay") &&
            root.Authorities.All.All(TagPermissionContract.Text) && root.Authorities.All.Distinct().Count() == 5 &&
            !root.Authorities.All.Contains(root.Source) && root.Profile.Pins.All(p => p.Writer != root.Source &&
                !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(TagPermissionContract.Text),
            "missing-input");
        var trial = new TagPermissionTrial(source, root);
        retain(trial); // original root/nonce recovery exists BEFORE Reserve, not after returned IDs
        var reserve = await trial.StepAsync(TagPermissionStep.Reserve, capability, token);
        trial.reservation = trial.Owner(reserve, TagPermissionStep.Reserve);
        trial.Require(trial.reservation.CollisionChecked && trial.reservation.PreEnrolled &&
            trial.reservation.Remaining.Length == 0);
        trial.Require(trial.verify.Verify(reserve.Inventory, TagPermissionJournal.Resources, "Reserve").Length == 0 &&
            trial.policyInventory.Verify(reserve.Policies, TagPermissionJournal.Policy, "Reserve").Length == 0);
        var opened = await trial.StepAsync(TagPermissionStep.Open, null, token);
        var owner = trial.Owner(opened, TagPermissionStep.Open);
        trial.Require(owner.Issued is not null);
        trial.Issued = owner.Issued!;
        var issued = trial.Issued;
        trial.Require(new[] { issued.Project, issued.ControlProject, issued.CopyProject }.Distinct().Count() == 3 &&
            TagPermissionContract.Text(issued.BaselineRevision) && issued.Rows.Length == 90 &&
            issued.Rows.Select(r => r.Id).Distinct().Count() == 90 &&
            issued.Rows.All(r => r.Id != Guid.Empty && TagPermissionContract.Text(r.Name) && TagPermissionContract.Text(r.TagSlug) &&
                r.Name != r.TagSlug && r.Id.ToString() != r.TagSlug && TagPermissionContract.Text(r.Color)) &&
            owner.Enrolled.All(e => !owner.Borrowed.Any(b => b.Kind == e.Kind && b.Id == e.Id)));
        foreach (string window in new[] { "before", "after", "copy" })
        {
            var rows = issued.Rows.Where(r => r.Window == window).ToArray();
            foreach (var action in Enum.GetValues<TagPermissionAction>())
            {
                foreach (string control in new[] { "selected", "project" })
                    trial.Require(rows.Count(r => r.Principal == root.Authorities.Runtime && r.Control == control && r.Action == action && !r.List) == 1);
                foreach (string principal in new[] { root.Authorities.Setup, root.Authorities.Denied,
                    root.Authorities.Administrative, root.Authorities.Observer })
                    trial.Require(rows.Count(r => r.Principal == principal && r.Control == "selected" &&
                        r.Action == action && !r.List) == 1);
            }
            trial.Require(rows.Length == 30 && rows.Count(r => r.List) == 6 &&
                rows.Where(r => r.List).All(r => r.Action == TagPermissionAction.Read));
        }
        foreach (var row in issued.Rows)
        {
            bool copied = row.Window == "copy";
            trial.Require(row.Project == (row.Control == "project" ? issued.ControlProject : copied ? issued.CopyProject : issued.Project) &&
                owner.Enrolled.Any(e => e.Kind == "tag" && e.Id == row.Id.ToString()));
            if (row.Action != TagPermissionAction.Create && (!copied || row.Control == "project"))
                trial.states.Add(row.Id, new(row.Id, true, 1, Initial(row)));
        }
        trial.revision = issued.BaselineRevision;
        if (!TagPermissionContract.Create(root.Operation))
        {
            var baseline = new TagPermissionPolicyState(issued.PolicyId, root.Authorities.Runtime, issued.Project,
                issued.BaselineRevision, TagPermissionContract.PolicyHash(TagPermissionContract.Baseline(root)));
            trial.policies.Add(baseline.Resource, baseline);
            if (TagPermissionContract.Template(root.Operation))
                trial.policies.Add(issued.TemplateId, baseline with { Resource = issued.TemplateId });
        }
        trial.CheckInventory(opened, TagPermissionStep.Open);
        return trial;
    }
    internal static TagPermissionValue Initial(TagPermissionRow row) =>
        new(row.Id, row.Project, row.Name, row.TagSlug, row.Color);
    internal TagPermissionRow[] Rows(bool after) => Issued.Rows.Where(r => r.Window ==
        (!after ? "before" : TagPermissionContract.Template(root.Operation) &&
            Outcome == TagPermissionOutcome.Applied ? "copy" : "after")).ToArray();
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        var step = after ? TagPermissionStep.After : TagPermissionStep.Before;
        var packet = await StepAsync(step, null, token);
        Owner(packet, step);
        if (after && TagPermissionContract.Template(root.Operation) && Outcome == TagPermissionOutcome.Applied)
        {
            foreach (var row in Rows(true).Where(r => r.Project == Issued.CopyProject && r.Action != TagPermissionAction.Create))
                states.Add(row.Id, new(row.Id, true, 1, Initial(row)));
            policies.Add(Issued.CopyProject, new(Issued.CopyProject, root.Authorities.Runtime, Issued.CopyProject,
                revision, TagPermissionContract.PolicyHash(root.Action)));
        }
        CheckInventory(packet, step);
    }
    internal async ValueTask ArmAsync(CancellationToken token)
    {
        var packet = await StepAsync(TagPermissionStep.Arm, null, token);
        Owner(packet, TagPermissionStep.Arm); CheckInventory(packet, TagPermissionStep.Arm);
    }
    internal async ValueTask SettleAsync(TagPermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Evidence == receipt.Native.Evidence, "effect-mismatch");
        Original = receipt; // snapshot of the real caller-held receipt; NEVER rewritten
        var packet = await StepAsync(TagPermissionStep.Settle, null, token);
        Owner(packet, TagPermissionStep.Settle);
        bool cancelled = root.Boundary == "cancellation-boundary", denied = root.Boundary == "denied-authority",
            lost = root.Boundary == "lost-response-no-replay";
        Require(packet.Requests.Length == (cancelled ? 0 : 1) && packet.Commits.Length <= 1 &&
            (!(cancelled || denied) || packet.Commits.Length == 0) &&
            packet.Decisions.Length == 0 && packet.Changes.Length == 0, "effect-mismatch");
        Require(receipt.Evidence == (cancelled ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected :
            lost ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancelled || lost) && (receipt.Cancelled ? receipt.Status is null :
                receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var signed in packet.Requests)
        {
            var ingress = verify.Verify(signed, TagPermissionJournal.Ingress, "original");
            Require(requests.Add(ingress.Request) && ingress.Principal == (denied ? root.Authorities.Denied : root.Authorities.Administrative) &&
                ingress.Authorized == !denied && !ingress.Bootstrap && ingress.IntentHash == receipt.IntentHash &&
                TagPermissionContract.Text(ingress.BodyHash) && TagPermissionContract.Text(ingress.TokenHash) &&
                ingress.Method == (TagPermissionContract.Create(root.Operation) ? "POST" : "PATCH") &&
                ingress.Path == TagPermissionEffects.OriginalPath(root, Issued), "effect-mismatch");
        }
        Outcome = TagPermissionOutcome.NonApplied;
        foreach (var signed in packet.Commits)
        {
            var commit = verify.Verify(signed, TagPermissionJournal.Policy, "original");
            Require(commit.Request == packet.Requests.Single().Payload.Content.Request &&
                commit.PreviousRevision == revision && commit.Revision != revision &&
                commit.Resource == (TagPermissionContract.Template(root.Operation) ? Issued.TemplateId : Issued.PolicyId) &&
                commit.Principal == root.Authorities.Runtime && commit.Project == Issued.Project, "effect-mismatch");
            revision = commit.Revision;
            policies[commit.Resource] = new(commit.Resource, commit.Principal, commit.Project, commit.Revision, commit.PolicyHash);
            Outcome = commit.PolicyHash == TagPermissionContract.PolicyHash(root.Action) ?
                TagPermissionOutcome.Applied : TagPermissionOutcome.Partial;
        }
        Require(lost || (cancelled || denied ? Outcome == TagPermissionOutcome.NonApplied :
            Outcome == TagPermissionOutcome.Applied), "effect-mismatch");
        Require(receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
        CheckInventory(packet, TagPermissionStep.Settle);
    }
    internal void Activated(TagPermissionReceipt receipt)
    {
        Require(stage == 6 && !failed && activation is null && receipt.Evidence == receipt.Native.Evidence &&
            receipt.Evidence == DispatchEvidence.Applied &&
            receipt.Status == SecretStatus.Success && !receipt.Cancelled, "effect-mismatch");
        activation = receipt;
    }
    internal async ValueTask ObserveAsync(bool after, TagPermissionAttempt[] attempts, CancellationToken token)
    {
        var step = after ? TagPermissionStep.ObserveAfter : TagPermissionStep.ObserveBefore;
        var packet = await StepAsync(step, null, token); Owner(packet, step);
        string window = after ? "after" : "before";
        var ingresses = packet.Requests.Select(s => verify.Verify(s, TagPermissionJournal.Ingress, window)).ToArray();
        foreach (var ingress in ingresses) Require(requests.Add(ingress.Request), "effect-mismatch");
        var activationRequests = ingresses.Where(i => i.Tag is null).ToArray();
        bool activate = after && Outcome == TagPermissionOutcome.Applied &&
            (TagPermissionContract.Template(root.Operation) || root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal));
        Require(packet.Commits.Length == (activate ? 1 : 0) && activationRequests.Length == (activate ? 1 : 0), "effect-mismatch");
        if (activate)
        {
            var ingress = activationRequests.Single();
            var commit = verify.Verify(packet.Commits.Single(), TagPermissionJournal.Policy, window);
            bool template = TagPermissionContract.Template(root.Operation);
            Require(activation is not null && ingress.IntentHash == activation.IntentHash &&
                ingress.Principal == root.Authorities.Setup && ingress.Authorized && !ingress.Bootstrap &&
                commit.Request == ingress.Request && commit.SourceRevision == revision &&
                commit.PolicyHash == TagPermissionContract.PolicyHash(root.Action) &&
                commit.Principal == root.Authorities.Runtime &&
                commit.Project == (template ? Issued.CopyProject : Issued.Project) &&
                commit.Resource == (template ? Issued.CopyProject : Issued.Membership), "effect-mismatch");
        }
        var decisions = packet.Decisions.Select(s => verify.Verify(s, TagPermissionJournal.Policy, window)).ToArray();
        var changes = packet.Changes.Select(s => verify.Verify(s, TagPermissionJournal.Resources, window)).ToArray();
        Require(attempts.Length == 30 && decisions.Length == attempts.Length && changes.Length == attempts.Length &&
            attempts.Select(a => a.Row.Id).Distinct().Count() == 30 &&
            attempts.Select(a => a.Row).SequenceEqual(Rows(after)), "effect-mismatch");

        for (int i = 0; i < attempts.Length; i++)
        {
            var attempt = attempts[i]; var row = attempt.Row; var decision = decisions[i];
            bool allowed = TagPermissionContract.Allowed(root, row, after, Outcome);
            Require(attempt.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) &&
                attempt.Evidence == (row.Action == TagPermissionAction.Read ? null :
                    allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected), "effect-mismatch");
            var request = ingresses.SingleOrDefault(r => r.Request == decision.Request);
            Require(request is not null && !request.Bootstrap && request.Principal == row.Principal &&
                request.TokenHash == attempt.TokenHash && request.Tag == row.Id && request.Authorized == allowed &&
                request.Method == Method(row.Action) && request.Path == Path(row) &&
                request.BodyHash == TagPermissionEffects.ActionBodyHash(row), "effect-mismatch");
            Require(ingresses.All(i => !i.Bootstrap) && attempt.SetupHash is null, "effect-mismatch");
            Require(decision.Principal == row.Principal && decision.TokenHash == attempt.TokenHash &&
                decision.Project == row.Project && decision.Tag == row.Id && decision.Revision == revision &&
                decision.Action == row.Action && decision.Allowed == allowed, "effect-mismatch");
            var previous = states.GetValueOrDefault(row.Id) ?? new(row.Id, false, 0, null);
            var expected = allowed ? row.Action switch
            {
                TagPermissionAction.Create => new(row.Id, true, 1, Initial(row) with { Color = "#A1B2C3" }),
                TagPermissionAction.Edit => new(row.Id, true, 2, Initial(row) with { Slug = row.TagSlug + "-changed", Color = "#A1B2C3" }),
                TagPermissionAction.Delete => new(row.Id, false, 0, null),
                _ => previous
            } : previous;
            Require(changes[i].Request == decision.Request && changes[i].Before == previous && changes[i].After == expected,
                "effect-mismatch");
            if (expected.Exists) states[row.Id] = expected; else states.Remove(row.Id);
            TagPermissionValue[] expectedValues = !allowed ? [] : row.List ? states.Values
                .Where(s => Issued.Rows.Any(r => r.Id == s.Tag && r.Project == row.Project))
                .Select(s => s.Value!).OrderBy(v => v.Id).ToArray() :
                [row.Action == TagPermissionAction.Delete ? previous.Value! : expected.Value!];
            Require(attempt.Complete && attempt.Values.Select(v => v.Id).Distinct().Count() == attempt.Values.Length &&
                attempt.Values.OrderBy(v => v.Id).SequenceEqual(expectedValues), "effect-mismatch");
            if (allowed && row.List) Require(attempt.Values.Length > 0, "effect-mismatch");
        }
        Require(ingresses.Length == attempts.Length + (activate ? 1 : 0), "effect-mismatch");
        CheckInventory(packet, step);
    }
    internal static string Method(TagPermissionAction action) => action switch
    {
        TagPermissionAction.Read => "GET",
        TagPermissionAction.Create => "POST",
        TagPermissionAction.Edit => "PATCH",
        TagPermissionAction.Delete => "DELETE",
        _ => ""
    };
    internal static string Path(TagPermissionRow row) => "/api/v1/projects/" + row.Project + "/tags" +
        (row.List || row.Action == TagPermissionAction.Create ? "" : "/" + row.Id);
    private async ValueTask<TagPermissionPacket> StepAsync(TagPermissionStep step, SecretMaterial? cap, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step);
        busy = failed = true; stage++;
        try { var packet = await source.StepAsync(root, step, cap, token); failed = false; return packet; }
        finally { busy = false; }
    }
    private TagPermissionOwner Owner(TagPermissionPacket packet, TagPermissionStep step)
    {
        var owner = verify.Verify(packet.Owner, TagPermissionJournal.Ownership, step.ToString());
        Require(packet.Seals.Length == 4 && packet.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 4);
        foreach (var journal in new[] { TagPermissionJournal.Ingress, TagPermissionJournal.Policy,
            TagPermissionJournal.Resources, TagPermissionJournal.Issuance })
        {
            var signed = packet.Seals.Single(s => s.Payload.Header.Journal == journal);
            var seal = fences.Verify(signed, journal, step.ToString());
            var content = TagPermissionContract.Contents(packet, journal);
            Require(seal.Terminal && seal.Pending == 0 && seal.Count == content.Headers.Length &&
                seal.ContentHash == content.Hash && content.Headers.All(h => h.Sequence < signed.Payload.Header.Sequence));
        }
        Require(owner.Step == step && owner.CollisionChecked && owner.PreEnrolled && owner.Exclusive &&
            owner.Pending == 0 && (step != TagPermissionStep.Settle || owner.Terminal) &&
            owner.Enrolled.Distinct().Count() == owner.Enrolled.Length &&
            owner.Enrolled.All(e => e.Root == root.Id && e.Nonce == root.Nonce) &&
            owner.Remaining.All(e => owner.Enrolled.Contains(e)) &&
            (reservation is null || owner.Borrowed.SequenceEqual(reservation.Borrowed) &&
                reservation.Enrolled.All(e => owner.Enrolled.Contains(e))));
        return owner;
    }
    private void CheckInventory(TagPermissionPacket packet, TagPermissionStep step)
    {
        var currentPolicies = policyInventory.Verify(packet.Policies, TagPermissionJournal.Policy, step.ToString());
        Require(currentPolicies.OrderBy(p => p.Resource).SequenceEqual(policies.Values.OrderBy(p => p.Resource)), "effect-mismatch");
        var inventory = verify.Verify(packet.Inventory, TagPermissionJournal.Resources, step.ToString());
        Require(inventory.OrderBy(s => s.Tag).SequenceEqual(states.Values.OrderBy(s => s.Tag)), "effect-mismatch");
    }
    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        closed = true;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var packet = await source.StepAsync(root, TagPermissionStep.Close, null, deadline.Token);
            var owner = Owner(packet, TagPermissionStep.Close);
            var inventory = verify.Verify(packet.Inventory, TagPermissionJournal.Resources, TagPermissionStep.Close.ToString());
            var remainingPolicies = policyInventory.Verify(packet.Policies, TagPermissionJournal.Policy, TagPermissionStep.Close.ToString());
            Require(owner.Terminal && owner.Registrations == 0 && owner.Remaining.Length == 0 && inventory.Length == 0 &&
                remainingPolicies.Length == 0 &&
                (reservation is null || reservation.Enrolled.All(e => owner.Enrolled.Contains(e))), "cleanup-incomplete");
        }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { verify.Dispose(); fences.Dispose(); policyInventory.Dispose(); }
    }
    private void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) failed = true; TagPermissionContract.Require(condition, code); }
}
