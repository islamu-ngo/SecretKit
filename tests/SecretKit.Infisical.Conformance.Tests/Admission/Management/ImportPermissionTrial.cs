using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class ImportPermissionTrial : IAsyncDisposable
{
    private readonly IImportPermissionSource source;
    private readonly ImportPermissionRoot root;
    private readonly ImportPermissionVerifier verify, fences, policyInventory;
    private readonly HashSet<string> requests = [];
    private readonly Dictionary<Guid, ImportPermissionState> states = [];
    private readonly Dictionary<string, ImportPermissionPolicyState> policies = [];
    private ImportPermissionOwner? reservation;
    private int stage;
    private bool busy, failed, closed;
    private string revision = "";
    private ImportPermissionReceipt? activation;
    internal ImportPermissionIssued Issued { get; private set; } = null!;
    internal ImportPermissionReceipt? Original { get; private set; }
    internal ImportPermissionOutcome Outcome { get; private set; }
    internal string Revision => revision;
    private ImportPermissionTrial(IImportPermissionSource source, ImportPermissionRoot root)
    { this.source = source; this.root = root; verify = new(root); fences = new(root); policyInventory = new(root); }
    internal static async ValueTask<ImportPermissionTrial> OpenAsync(IImportPermissionSource source,
        ImportPermissionRoot root, SecretMaterial capability, Action<ImportPermissionTrial> retain, CancellationToken token)
    {
        ImportPermissionContract.Require(source.Identity == root.Source && source.Kind == root.Kind &&
            Enum.IsDefined(root.Kind) && Enum.IsDefined(root.Action) && ImportPermissionContract.Operations.Contains(root.Operation) &&
            root.Variant == ImportPermissionContract.Variant(root.Operation, root.Action) &&
            root.Authorities.All.All(ImportPermissionContract.Text) && root.Authorities.All.Distinct().Count() == 5 &&
            !root.Authorities.All.Contains(root.Source) && root.Profile.Pins.All(p => p.Writer != root.Source &&
                !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(ImportPermissionContract.Text),
            "missing-input");
        var trial = new ImportPermissionTrial(source, root);
        retain(trial); // original root/nonce recovery exists BEFORE Reserve, not after returned IDs
        var reserve = await trial.StepAsync(ImportPermissionStep.Reserve, capability, token);
        trial.reservation = trial.Owner(reserve, ImportPermissionStep.Reserve);
        trial.Require(trial.reservation.CollisionChecked && trial.reservation.PreEnrolled &&
            trial.reservation.Remaining.Length == 0);
        trial.Require(trial.verify.Verify(reserve.Inventory, ImportPermissionJournal.Resources, "Reserve").Length == 0 &&
            trial.policyInventory.Verify(reserve.Policies, ImportPermissionJournal.Policy, "Reserve").Length == 0 &&
            trial.verify.Verify(reserve.Sources, ImportPermissionJournal.Resources, "Reserve").Length == 0 &&
            trial.verify.Verify(reserve.Receivers, ImportPermissionJournal.Resources, "Reserve").Length == 0);
        var opened = await trial.StepAsync(ImportPermissionStep.Open, null, token);
        var owner = trial.Owner(opened, ImportPermissionStep.Open);
        trial.Require(owner.Issued is not null);
        trial.Issued = owner.Issued!;
        var issued = trial.Issued;
        trial.Require(new[] { issued.Project, issued.ControlProject, issued.CopyProject }.Distinct().Count() == 3 &&
            ImportPermissionContract.Text(issued.BaselineRevision) && issued.Rows.Length == 120 &&
            issued.Rows.Select(r => r.Id).Distinct().Count() == 120 &&
            issued.Rows.All(r => r.Id != Guid.Empty && r.EnvironmentId != Guid.Empty) &&
            owner.Enrolled.All(e => !owner.Borrowed.Any(b => b.Kind == e.Kind && b.Id == e.Id)));
        trial.Require(issued.Rows.All(r => r.FolderId != Guid.Empty && r.SourceFolderId != Guid.Empty &&
            r.ChangedSourceFolderId != Guid.Empty &&
            owner.Enrolled.Any(e => e.Kind == "receiver" && e.Id == r.FolderId.ToString()) &&
            owner.Enrolled.Any(e => e.Kind == "source" && e.Id == r.Id + ":a") &&
            owner.Enrolled.Any(e => e.Kind == "source" && e.Id == r.Id + ":b") &&
            owner.Enrolled.Any(e => e.Kind == "source-folder" && e.Id == r.SourceFolderId.ToString()) &&
            owner.Enrolled.Any(e => e.Kind == "source-folder" && e.Id == r.ChangedSourceFolderId.ToString())) &&
            root.Authorities.All.All(p => owner.Enrolled.Any(e => e.Kind == "credential-use" && e.Id == p)));
        foreach (string window in new[] { "before", "after", "copy" })
        {
            var rows = issued.Rows.Where(r => r.Window == window).ToArray();
            foreach (var action in Enum.GetValues<ImportPermissionAction>())
            {
                foreach (string control in new[] { "selected", "project", "environment", "path" })
                    trial.Require(rows.Count(r => r.Principal == root.Authorities.Runtime && r.Control == control && r.Action == action && !r.List) == 1);
                foreach (string principal in new[] { root.Authorities.Setup, root.Authorities.Denied,
                    root.Authorities.Administrative, root.Authorities.Observer })
                    trial.Require(rows.Count(r => r.Principal == principal && r.Control == "selected" &&
                        r.Action == action && !r.List) == 1);
            }
            trial.Require(rows.Length == 40 && rows.Count(r => r.List) == 8 &&
                rows.Where(r => r.List).All(r => r.Action == ImportPermissionAction.Read));
        }
        foreach (var row in issued.Rows)
        {
            bool copied = row.Window == "copy";
            trial.Require(row.Project == (row.Control == "project" ? issued.ControlProject : copied ? issued.CopyProject : issued.Project) &&
                row.Environment == (row.Control == "environment" ? "outside" : "witness") &&
                row.Path == (row.Control == "path" ? "/outside" : "/") &&
                owner.Enrolled.Any(e => e.Kind == "import" && e.Id == row.Id.ToString()) &&
                owner.Enrolled.Any(e => e.Kind == "environment" && e.Id == row.EnvironmentId.ToString()));
            if (row.Action != ImportPermissionAction.Create && (!copied || row.Control == "project"))
                trial.states.Add(row.Id, new(row.Id, true, 1, Initial(row)));
        }
        trial.revision = issued.BaselineRevision;
        if (!ImportPermissionContract.Create(root.Operation))
        {
            var baseline = new ImportPermissionPolicyState(issued.PolicyId, root.Authorities.Runtime, issued.Project,
                issued.BaselineRevision, ImportPermissionContract.PolicyHash(ImportPermissionContract.Baseline(root)));
            trial.policies.Add(baseline.Resource, baseline);
            if (ImportPermissionContract.Template(root.Operation))
                trial.policies.Add(issued.TemplateId, baseline with { Resource = issued.TemplateId });
        }
        trial.CheckInventory(opened, ImportPermissionStep.Open);
        return trial;
    }
    internal static ImportPermissionValue Initial(ImportPermissionRow row) =>
        new(row.Id, row.FolderId, "source-a", ImportPermissionContract.SourcePath(row, false), row.Project,
            1, false, false, "idle", null);
    internal ImportPermissionRow[] Rows(bool after) => Issued.Rows.Where(r => r.Window ==
        (!after ? "before" : ImportPermissionContract.Template(root.Operation) &&
            Outcome == ImportPermissionOutcome.Applied ? "copy" : "after")).ToArray();
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        var step = after ? ImportPermissionStep.After : ImportPermissionStep.Before;
        var packet = await StepAsync(step, null, token);
        Owner(packet, step);
        if (after && ImportPermissionContract.Template(root.Operation) && Outcome == ImportPermissionOutcome.Applied)
        {
            foreach (var row in Rows(true).Where(r => r.Project == Issued.CopyProject && r.Action != ImportPermissionAction.Create))
                states.Add(row.Id, new(row.Id, true, 1, Initial(row)));
            policies.Add(Issued.CopyProject, new(Issued.CopyProject, root.Authorities.Runtime, Issued.CopyProject,
                revision, ImportPermissionContract.PolicyHash(root.Action)));
        }
        CheckInventory(packet, step);
    }
    internal async ValueTask ArmAsync(CancellationToken token)
    {
        var packet = await StepAsync(ImportPermissionStep.Arm, null, token);
        Owner(packet, ImportPermissionStep.Arm); CheckInventory(packet, ImportPermissionStep.Arm);
    }
    internal async ValueTask SettleAsync(ImportPermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Evidence == receipt.Native.Evidence, "effect-mismatch");
        Original = receipt; // snapshot of the real caller-held receipt; NEVER rewritten
        var packet = await StepAsync(ImportPermissionStep.Settle, null, token);
        Owner(packet, ImportPermissionStep.Settle);
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
            var ingress = verify.Verify(signed, ImportPermissionJournal.Ingress, "original");
            Require(requests.Add(ingress.Request) && ingress.Principal == (denied ? root.Authorities.Denied : root.Authorities.Administrative) &&
                ingress.Authorized == !denied && !ingress.Bootstrap && ingress.IntentHash == receipt.IntentHash &&
                ImportPermissionContract.Text(ingress.BodyHash) && ImportPermissionContract.Text(ingress.TokenHash) &&
                ingress.Method == (ImportPermissionContract.Create(root.Operation) ? "POST" : "PATCH") &&
                ingress.Path == ImportPermissionEffects.OriginalPath(root, Issued), "effect-mismatch");
        }
        Outcome = ImportPermissionOutcome.NonApplied;
        foreach (var signed in packet.Commits)
        {
            var commit = verify.Verify(signed, ImportPermissionJournal.Policy, "original");
            Require(commit.Request == packet.Requests.Single().Payload.Content.Request &&
                commit.PreviousRevision == revision && commit.Revision != revision &&
                commit.Resource == (ImportPermissionContract.Template(root.Operation) ? Issued.TemplateId : Issued.PolicyId) &&
                commit.Principal == root.Authorities.Runtime && commit.Project == Issued.Project, "effect-mismatch");
            revision = commit.Revision;
            policies[commit.Resource] = new(commit.Resource, commit.Principal, commit.Project, commit.Revision, commit.PolicyHash);
            Outcome = commit.PolicyHash == ImportPermissionContract.PolicyHash(root.Action) ?
                ImportPermissionOutcome.Applied : ImportPermissionOutcome.Partial;
        }
        Require(lost || (cancelled || denied ? Outcome == ImportPermissionOutcome.NonApplied :
            Outcome == ImportPermissionOutcome.Applied), "effect-mismatch");
        Require(receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
        CheckInventory(packet, ImportPermissionStep.Settle);
    }
    internal void Activated(ImportPermissionReceipt receipt)
    {
        Require(stage == 6 && !failed && activation is null && receipt.Evidence == receipt.Native.Evidence &&
            receipt.Evidence == DispatchEvidence.Applied &&
            receipt.Status == SecretStatus.Success && !receipt.Cancelled, "effect-mismatch");
        activation = receipt;
    }
    internal async ValueTask ObserveAsync(bool after, ImportPermissionAttempt[] attempts, CancellationToken token)
    {
        var step = after ? ImportPermissionStep.ObserveAfter : ImportPermissionStep.ObserveBefore;
        var packet = await StepAsync(step, null, token); Owner(packet, step);
        string window = after ? "after" : "before";
        var ingresses = packet.Requests.Select(s => verify.Verify(s, ImportPermissionJournal.Ingress, window)).ToArray();
        foreach (var ingress in ingresses) Require(requests.Add(ingress.Request), "effect-mismatch");
        var activationRequests = ingresses.Where(i => i.Folder is null).ToArray();
        bool activate = after && Outcome == ImportPermissionOutcome.Applied &&
            (ImportPermissionContract.Template(root.Operation) || root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal));
        Require(packet.Commits.Length == (activate ? 1 : 0) && activationRequests.Length == (activate ? 1 : 0), "effect-mismatch");
        if (activate)
        {
            var ingress = activationRequests.Single();
            var commit = verify.Verify(packet.Commits.Single(), ImportPermissionJournal.Policy, window);
            bool template = ImportPermissionContract.Template(root.Operation);
            Require(activation is not null && ingress.IntentHash == activation.IntentHash &&
                ingress.Principal == root.Authorities.Setup && ingress.Authorized && !ingress.Bootstrap &&
                commit.Request == ingress.Request && commit.SourceRevision == revision &&
                commit.PolicyHash == ImportPermissionContract.PolicyHash(root.Action) &&
                commit.Principal == root.Authorities.Runtime &&
                commit.Project == (template ? Issued.CopyProject : Issued.Project) &&
                commit.Resource == (template ? Issued.CopyProject : Issued.Membership), "effect-mismatch");
        }
        var decisions = packet.Decisions.Select(s => verify.Verify(s, ImportPermissionJournal.Policy, window)).ToArray();
        var changes = packet.Changes.Select(s => verify.Verify(s, ImportPermissionJournal.Resources, window)).ToArray();
        Require(attempts.Length == 40 && decisions.Length == attempts.Length && changes.Length == attempts.Length &&
            attempts.Select(a => a.Row.Id).Distinct().Count() == 40 &&
            attempts.Select(a => a.Row).SequenceEqual(Rows(after)), "effect-mismatch");

        for (int i = 0; i < attempts.Length; i++)
        {
            var attempt = attempts[i]; var row = attempt.Row; var decision = decisions[i];
            bool allowed = ImportPermissionContract.Allowed(root, row, after, Outcome);
            Require(attempt.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) &&
                attempt.Evidence == (row.Action == ImportPermissionAction.Read ? null :
                    allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected), "effect-mismatch");
            var request = ingresses.SingleOrDefault(r => r.Request == decision.Request);
            Require(request is not null && !request.Bootstrap && request.Principal == row.Principal &&
                request.TokenHash == attempt.TokenHash && request.Folder == row.Id && request.Authorized == allowed &&
                request.Method == Method(row.Action) && request.Path == Path(row) &&
                request.BodyHash == ImportPermissionEffects.ActionBodyHash(row), "effect-mismatch");
            Require(ingresses.All(i => !i.Bootstrap) && attempt.SetupHash is null, "effect-mismatch");
            Require(decision.Principal == row.Principal && decision.TokenHash == attempt.TokenHash &&
                decision.Project == row.Project && decision.Folder == row.Id && decision.Revision == revision &&
                decision.Action == row.Action && decision.Allowed == allowed, "effect-mismatch");
            var previous = states.GetValueOrDefault(row.Id) ?? new(row.Id, false, 0, null);
            var expected = allowed ? row.Action switch
            {
                ImportPermissionAction.Create => new(row.Id, true, 1, Initial(row) with { SourceEnvironment = "source-b", SourcePath = ImportPermissionContract.SourcePath(row, true) }),
                ImportPermissionAction.Edit => new(row.Id, true, 2, Initial(row) with { SourceEnvironment = "source-b", SourcePath = ImportPermissionContract.SourcePath(row, true), Position = 7.5 }),
                ImportPermissionAction.Delete => new(row.Id, false, 0, null),
                _ => previous
            } : previous;
            Require(changes[i].Request == decision.Request && changes[i].Before == previous && changes[i].After == expected,
                "effect-mismatch");
            if (expected.Exists) states[row.Id] = expected; else states.Remove(row.Id);
            ImportPermissionValue[] expectedValues = !allowed ? [] : row.List ? states.Values
                .Where(s => Issued.Rows.Any(r => r.Id == s.Folder && r.Project == row.Project &&
                    r.Environment == row.Environment && r.Path == row.Path))
                .Select(s => s.Value!).OrderBy(v => v.Id).ToArray() :
                [row.Action == ImportPermissionAction.Delete ? previous.Value! : expected.Value!];
            Require(attempt.Complete && attempt.Values.Select(v => v.Id).Distinct().Count() == attempt.Values.Length &&
                attempt.Values.OrderBy(v => v.Id).SequenceEqual(expectedValues), "effect-mismatch");
            if (allowed && row.List) Require(attempt.Values.Length > 0, "effect-mismatch");
        }
        Require(ingresses.Length == attempts.Length + (activate ? 1 : 0), "effect-mismatch");
        CheckInventory(packet, step);
    }
    internal static string Method(ImportPermissionAction action) => action switch
    {
        ImportPermissionAction.Read => "GET",
        ImportPermissionAction.Create => "POST",
        ImportPermissionAction.Edit => "PATCH",
        ImportPermissionAction.Delete => "DELETE",
        _ => ""
    };
    internal static string Path(ImportPermissionRow row) => "/api/v2/secret-imports" +
        (row.List || row.Action == ImportPermissionAction.Create ? "" : "/" + row.Id);
    private async ValueTask<ImportPermissionPacket> StepAsync(ImportPermissionStep step, SecretMaterial? cap, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step);
        busy = failed = true; stage++;
        try { var packet = await source.StepAsync(root, step, cap, token); failed = false; return packet; }
        finally { busy = false; }
    }
    private ImportPermissionOwner Owner(ImportPermissionPacket packet, ImportPermissionStep step)
    {
        var owner = verify.Verify(packet.Owner, ImportPermissionJournal.Ownership, step.ToString());
        Require(packet.Seals.Length == 4 && packet.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 4);
        foreach (var journal in new[] { ImportPermissionJournal.Ingress, ImportPermissionJournal.Policy,
            ImportPermissionJournal.Resources, ImportPermissionJournal.Issuance })
        {
            var signed = packet.Seals.Single(s => s.Payload.Header.Journal == journal);
            var seal = fences.Verify(signed, journal, step.ToString());
            var content = ImportPermissionContract.Contents(packet, journal);
            Require(seal.Terminal && seal.Pending == 0 && seal.Count == content.Headers.Length &&
                seal.ContentHash == content.Hash && content.Headers.All(h => h.Sequence < signed.Payload.Header.Sequence));
        }
        Require(owner.Step == step && owner.CollisionChecked && owner.PreEnrolled && owner.Exclusive &&
            owner.Pending == 0 && (step != ImportPermissionStep.Settle || owner.Terminal) &&
            owner.Enrolled.Distinct().Count() == owner.Enrolled.Length &&
            owner.Enrolled.All(e => e.Root == root.Id && e.Nonce == root.Nonce) &&
            owner.Remaining.All(e => owner.Enrolled.Contains(e)) &&
            (reservation is null || owner.Borrowed.SequenceEqual(reservation.Borrowed) &&
                reservation.Enrolled.All(e => owner.Enrolled.Contains(e))));
        return owner;
    }
    private void CheckInventory(ImportPermissionPacket packet, ImportPermissionStep step)
    {
        var currentPolicies = policyInventory.Verify(packet.Policies, ImportPermissionJournal.Policy, step.ToString());
        Require(currentPolicies.OrderBy(p => p.Resource).SequenceEqual(policies.Values.OrderBy(p => p.Resource)), "effect-mismatch");
        var inventory = verify.Verify(packet.Inventory, ImportPermissionJournal.Resources, step.ToString());
        Require(inventory.OrderBy(s => s.Folder).SequenceEqual(states.Values.OrderBy(s => s.Folder)), "effect-mismatch");
        var sources = verify.Verify(packet.Sources, ImportPermissionJournal.Resources, step.ToString());
        var receivers = verify.Verify(packet.Receivers, ImportPermissionJournal.Resources, step.ToString());
        var expectedReceivers = Issued.Rows.Select(r => new ImportPermissionReceiver(r.FolderId, r.Project, r.Environment, r.Path)).Distinct().ToArray();
        Require(receivers.Distinct().Count() == receivers.Length && receivers.OrderBy(r => r.FolderId)
            .SequenceEqual(expectedReceivers.OrderBy(r => r.FolderId)), "effect-mismatch");
        var expectedSources = Issued.Rows.SelectMany(r => new[] { false, true }.Select(changed =>
            new ImportPermissionSourceState(changed ? r.ChangedSourceFolderId : r.SourceFolderId, r.Project, changed ? "source-b" : "source-a",
                ImportPermissionContract.SourcePath(r, changed), "IMPORTED", ImportPermissionContract.MaterialHash(root, r, changed), root.Id, root.Nonce))).ToArray();
        Require(sources.Distinct().Count() == sources.Length && sources.OrderBy(s => s.Path)
            .SequenceEqual(expectedSources.OrderBy(s => s.Path)), "effect-mismatch");
    }
    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        closed = true;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var packet = await source.StepAsync(root, ImportPermissionStep.Close, null, deadline.Token);
            var owner = Owner(packet, ImportPermissionStep.Close);
            var inventory = verify.Verify(packet.Inventory, ImportPermissionJournal.Resources, ImportPermissionStep.Close.ToString());
            var remainingPolicies = policyInventory.Verify(packet.Policies, ImportPermissionJournal.Policy, ImportPermissionStep.Close.ToString());
            Require(owner.Terminal && owner.Registrations == 0 && owner.Remaining.Length == 0 && inventory.Length == 0 &&
                remainingPolicies.Length == 0 &&
                verify.Verify(packet.Sources, ImportPermissionJournal.Resources, "Close").Length == 0 &&
                verify.Verify(packet.Receivers, ImportPermissionJournal.Resources, "Close").Length == 0 &&
                (reservation is null || reservation.Enrolled.All(e => owner.Enrolled.Contains(e))), "cleanup-incomplete");
        }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { verify.Dispose(); fences.Dispose(); policyInventory.Dispose(); }
    }
    private void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) failed = true; ImportPermissionContract.Require(condition, code); }
}
