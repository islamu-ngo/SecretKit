using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class DynamicPermissionTrial : IAsyncDisposable
{
    private readonly IDynamicPermissionSource source;
    private readonly DynamicPermissionRoot root;
    private readonly DynamicPermissionVerifier verify, fences, policyInventory;
    private readonly HashSet<string> requests = [], materials = [];
    private readonly HashSet<Guid> leases = [];
    private readonly List<DynamicPermissionSql> sql = [];
    private readonly Dictionary<Guid, DynamicPermissionState> states = [];
    private readonly Dictionary<string, DynamicPermissionPolicyState> policies = [];
    private DynamicPermissionOwner? reservation;
    private int stage;
    private bool busy, failed, closed;
    private string revision = "";
    private DynamicPermissionReceipt? activation;
    internal DynamicPermissionIssued Issued { get; private set; } = null!;
    internal DynamicPermissionReceipt? Original { get; private set; }
    internal DynamicPermissionOutcome Outcome { get; private set; }
    internal string Revision => revision;
    private DynamicPermissionTrial(IDynamicPermissionSource source, DynamicPermissionRoot root)
    { this.source = source; this.root = root; verify = new(root); fences = new(root); policyInventory = new(root); }
    internal static async ValueTask<DynamicPermissionTrial> OpenAsync(IDynamicPermissionSource source,
        DynamicPermissionRoot root, SecretMaterial capability, Action<DynamicPermissionTrial> retain, CancellationToken token)
    {
        DynamicPermissionContract.Require(source.Identity == root.Source && source.Kind == root.Kind &&
            Enum.IsDefined(root.Kind) && Enum.IsDefined(root.Action) && DynamicPermissionContract.Operations.Contains(root.Operation) &&
            root.Variant == DynamicPermissionContract.Variant(root.Operation, root.Action) &&
            root.Authorities.All.All(DynamicPermissionContract.Text) && root.Authorities.All.Distinct().Count() == 5 &&
            !root.Authorities.All.Contains(root.Source) && root.Profile.Pins.All(p => p.Writer != root.Source &&
                !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(DynamicPermissionContract.Text),
            "missing-input");
        var trial = new DynamicPermissionTrial(source, root);
        retain(trial); // original root/nonce recovery exists BEFORE Reserve, not after returned IDs
        var reserve = await trial.StepAsync(DynamicPermissionStep.Reserve, capability, token);
        trial.reservation = trial.Owner(reserve, DynamicPermissionStep.Reserve);
        trial.Require(trial.reservation.CollisionChecked && trial.reservation.PreEnrolled &&
            trial.reservation.Remaining.Length == 0);
        trial.Require(trial.verify.Verify(reserve.Inventory, DynamicPermissionJournal.Resources, "Reserve").Length == 0 &&
            trial.policyInventory.Verify(reserve.Policies, DynamicPermissionJournal.Policy, "Reserve").Length == 0);
        var emptyBackend = trial.verify.Verify(reserve.Backend, DynamicPermissionJournal.Backend, "Reserve");
        trial.Require(emptyBackend.Credentials == 0 && emptyBackend.ProtectedRows == 0 && emptyBackend.Leases == 0 &&
            emptyBackend.LeaseIds.Length == 0);
        var opened = await trial.StepAsync(DynamicPermissionStep.Open, null, token);
        var owner = trial.Owner(opened, DynamicPermissionStep.Open);
        trial.Require(owner.Issued is not null);
        trial.Issued = owner.Issued!;
        var issued = trial.Issued;
        trial.Require(new[] { issued.Project, issued.ControlProject, issued.CopyProject }.Distinct().Count() == 3 &&
            DynamicPermissionContract.Text(issued.BaselineRevision) && issued.Rows.Length == 90 &&
            issued.Rows.Select(r => r.Definition).Distinct().Count() == 90 &&
            issued.Rows.All(r => r.Definition != Guid.Empty && r.Folder != Guid.Empty) &&
            owner.Enrolled.All(e => !owner.Borrowed.Any(b => b.Kind == e.Kind && b.Id == e.Id)));
        foreach (string window in new[] { "before", "after", "copy" })
        {
            var rows = issued.Rows.Where(r => r.Window == window).ToArray();
            foreach (var action in Enum.GetValues<DynamicPermissionAction>())
            {
                foreach (string control in new[] { "selected", "project", "environment", "path" })
                    trial.Require(rows.Count(r => r.Principal == root.Authorities.Runtime && r.Control == control && r.Action == action) == 1);
                foreach (string principal in new[] { root.Authorities.Denied, root.Authorities.Observer })
                    trial.Require(rows.Count(r => r.Principal == principal && r.Control == "selected" && r.Action == action) == 1);
            }
        }
        foreach (var row in issued.Rows)
        {
            bool copied = row.Window == "copy";
            trial.Require(row.Project == (row.Control == "project" ? issued.ControlProject : copied ? issued.CopyProject : issued.Project) &&
                row.Environment == (row.Control == "environment" ? "outside" : "witness") &&
                row.Path == (row.Control == "path" ? "/outside" : "/") &&
                owner.Enrolled.Any(e => e.Kind == "definition" && e.Id == row.Definition.ToString()) &&
                owner.Enrolled.Any(e => e.Kind == "folder" && e.Id == row.Folder.ToString()));
            if (row.Action != DynamicPermissionAction.Create && (!copied || row.Control == "project"))
                trial.states.Add(row.Definition, new(row.Definition, true, 1, ProfileHash(issued.Sql, 300)));
        }
        trial.revision = issued.BaselineRevision;
        if (!DynamicPermissionContract.Create(root.Operation))
        {
            var baseline = new DynamicPermissionPolicyState(issued.PolicyId, root.Authorities.Runtime, issued.Project,
                issued.BaselineRevision, DynamicPermissionContract.PolicyHash(DynamicPermissionContract.Baseline(root)));
            trial.policies.Add(baseline.Resource, baseline);
            if (DynamicPermissionContract.Template(root.Operation))
                trial.policies.Add(issued.TemplateId, baseline with { Resource = issued.TemplateId });
        }
        trial.CheckInventory(opened, DynamicPermissionStep.Open);
        return trial;
    }
    internal static string ProfileHash(DynamicPermissionSqlProfile profile, int ttl) =>
        DynamicPermissionContract.Hash(new { Sql = profile, Ttl = ttl });
    internal DynamicPermissionRow[] Rows(bool after) => Issued.Rows.Where(r => r.Window ==
        (!after ? "before" : DynamicPermissionContract.Template(root.Operation) &&
            Outcome == DynamicPermissionOutcome.Applied ? "copy" : "after")).ToArray();
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        var step = after ? DynamicPermissionStep.After : DynamicPermissionStep.Before;
        var packet = await StepAsync(step, null, token);
        Owner(packet, step);
        if (after && DynamicPermissionContract.Template(root.Operation) && Outcome == DynamicPermissionOutcome.Applied)
        {
            foreach (var row in Rows(true).Where(r => r.Project == Issued.CopyProject && r.Action != DynamicPermissionAction.Create))
                states.Add(row.Definition, new(row.Definition, true, 1, ProfileHash(Issued.Sql, 300)));
            policies.Add(Issued.CopyProject, new(Issued.CopyProject, root.Authorities.Runtime, Issued.CopyProject,
                revision, DynamicPermissionContract.PolicyHash(root.Action)));
        }
        CheckInventory(packet, step);
        sql.Clear();
    }
    internal async ValueTask ArmAsync(CancellationToken token)
    {
        var packet = await StepAsync(DynamicPermissionStep.Arm, null, token);
        Owner(packet, DynamicPermissionStep.Arm); CheckInventory(packet, DynamicPermissionStep.Arm);
    }
    internal async ValueTask SettleAsync(DynamicPermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Evidence == receipt.Native.Evidence, "effect-mismatch");
        Original = receipt; // snapshot of the real caller-held receipt; NEVER rewritten
        var packet = await StepAsync(DynamicPermissionStep.Settle, null, token);
        Owner(packet, DynamicPermissionStep.Settle);
        bool cancelled = root.Boundary == "cancellation-boundary", denied = root.Boundary == "denied-authority",
            lost = root.Boundary == "lost-response-no-replay";
        Require(packet.Requests.Length == (cancelled ? 0 : 1) && packet.Commits.Length <= 1 &&
            (!(cancelled || denied) || packet.Commits.Length == 0) &&
            packet.Decisions.Length == 0 && packet.Changes.Length == 0 && packet.Leases.Length == 0, "effect-mismatch");
        Require(receipt.Evidence == (cancelled ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected :
            lost ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancelled || lost) && (receipt.Cancelled ? receipt.Status is null :
                receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var signed in packet.Requests)
        {
            var ingress = verify.Verify(signed, DynamicPermissionJournal.Ingress, "original");
            Require(requests.Add(ingress.Request) && ingress.Principal == (denied ? root.Authorities.Denied : root.Authorities.Administrative) &&
                ingress.Authorized == !denied && !ingress.Bootstrap && ingress.IntentHash == receipt.IntentHash &&
                DynamicPermissionContract.Text(ingress.BodyHash) && DynamicPermissionContract.Text(ingress.TokenHash) &&
                ingress.Method == (DynamicPermissionContract.Create(root.Operation) ? "POST" : "PATCH") &&
                ingress.Path == DynamicPermissionEffects.OriginalPath(root, Issued), "effect-mismatch");
        }
        Outcome = DynamicPermissionOutcome.NonApplied;
        foreach (var signed in packet.Commits)
        {
            var commit = verify.Verify(signed, DynamicPermissionJournal.Policy, "original");
            Require(commit.Request == packet.Requests.Single().Payload.Content.Request &&
                commit.PreviousRevision == revision && commit.Revision != revision &&
                commit.Resource == (DynamicPermissionContract.Template(root.Operation) ? Issued.TemplateId : Issued.PolicyId) &&
                commit.Principal == root.Authorities.Runtime && commit.Project == Issued.Project, "effect-mismatch");
            revision = commit.Revision;
            policies[commit.Resource] = new(commit.Resource, commit.Principal, commit.Project, commit.Revision, commit.PolicyHash);
            Outcome = commit.PolicyHash == DynamicPermissionContract.PolicyHash(root.Action) ?
                DynamicPermissionOutcome.Applied : DynamicPermissionOutcome.Partial;
        }
        Require(lost || (cancelled || denied ? Outcome == DynamicPermissionOutcome.NonApplied :
            Outcome == DynamicPermissionOutcome.Applied), "effect-mismatch");
        Require(receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
        CheckInventory(packet, DynamicPermissionStep.Settle);
    }
    internal void Activated(DynamicPermissionReceipt receipt)
    {
        Require(stage == 6 && !failed && activation is null && receipt.Evidence == receipt.Native.Evidence &&
            receipt.Evidence == DispatchEvidence.Applied &&
            receipt.Status == SecretStatus.Success && !receipt.Cancelled, "effect-mismatch");
        activation = receipt;
    }
    internal async ValueTask MeasureAsync(Guid lease, DynamicPermissionRow row, string username, string password,
        DynamicPermissionSqlAction action, bool after, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (after ? 7 : 3));
        failed = busy = true;
        try
        {
            using var user = SecretMaterial.FromText(username);
            string supplied = action == DynamicPermissionSqlAction.WrongCredential ? password + "-wrong" : password;
            using var secret = SecretMaterial.FromText(supplied);
            var fact = verify.Verify(await source.MeasureAsync(root, lease, user, secret, action, token),
                DynamicPermissionJournal.Backend, after ? "after" : "before");
            bool allowed = action is DynamicPermissionSqlAction.Read or DynamicPermissionSqlAction.Recheck;
            Require(fact.Lease == lease && fact.MaterialHash == DynamicPermissionContract.MaterialHash(username, supplied) &&
                fact.Principal == row.Principal && fact.Project == row.Project && fact.Action == action &&
                fact.Authenticated == (action != DynamicPermissionSqlAction.WrongCredential) && fact.Allowed == allowed &&
                fact.ProtectedHash == (allowed ? Issued.ProtectedHash : ""), "effect-mismatch");
            sql.Add(fact); failed = false;
        }
        finally { busy = false; }
    }
    internal async ValueTask ObserveAsync(bool after, DynamicPermissionAttempt[] attempts, CancellationToken token)
    {
        var step = after ? DynamicPermissionStep.ObserveAfter : DynamicPermissionStep.ObserveBefore;
        var packet = await StepAsync(step, null, token); Owner(packet, step);
        string window = after ? "after" : "before";
        var ingresses = packet.Requests.Select(s => verify.Verify(s, DynamicPermissionJournal.Ingress, window)).ToArray();
        foreach (var ingress in ingresses) Require(requests.Add(ingress.Request), "effect-mismatch");
        var activationRequests = ingresses.Where(i => i.Definition is null).ToArray();
        bool activate = after && Outcome == DynamicPermissionOutcome.Applied &&
            (DynamicPermissionContract.Template(root.Operation) || root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal));
        Require(packet.Commits.Length == (activate ? 1 : 0) && activationRequests.Length == (activate ? 1 : 0), "effect-mismatch");
        if (activate)
        {
            var ingress = activationRequests.Single();
            var commit = verify.Verify(packet.Commits.Single(), DynamicPermissionJournal.Policy, window);
            bool template = DynamicPermissionContract.Template(root.Operation);
            Require(activation is not null && ingress.IntentHash == activation.IntentHash &&
                ingress.Principal == root.Authorities.Setup && ingress.Authorized && !ingress.Bootstrap &&
                commit.Request == ingress.Request && commit.SourceRevision == revision &&
                commit.PolicyHash == DynamicPermissionContract.PolicyHash(root.Action) &&
                commit.Principal == root.Authorities.Runtime &&
                commit.Project == (template ? Issued.CopyProject : Issued.Project) &&
                commit.Resource == (template ? Issued.CopyProject : Issued.Membership), "effect-mismatch");
        }
        var decisions = packet.Decisions.Select(s => verify.Verify(s, DynamicPermissionJournal.Policy, window)).ToArray();
        var changes = packet.Changes.Select(s => verify.Verify(s, DynamicPermissionJournal.Resources, window)).ToArray();
        var issued = packet.Leases.Select(s => verify.Verify(s, DynamicPermissionJournal.Issuance, window)).ToArray();
        Require(attempts.Length == 30 && decisions.Length == attempts.Length && changes.Length == attempts.Length &&
            attempts.Select(a => a.Row.Definition).Distinct().Count() == 30 &&
            attempts.Select(a => a.Row).SequenceEqual(Rows(after)), "effect-mismatch");
        int bootstrapCount = 0, leaseCount = 0;
        for (int i = 0; i < attempts.Length; i++)
        {
            var attempt = attempts[i]; var row = attempt.Row; var decision = decisions[i];
            bool allowed = DynamicPermissionContract.Allowed(root, row, after, Outcome);
            Require(attempt.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) &&
                attempt.Evidence == (row.Action == DynamicPermissionAction.Read ? null :
                    allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected), "effect-mismatch");
            var request = ingresses.SingleOrDefault(r => r.Request == decision.Request);
            Require(request is not null && !request.Bootstrap && request.Principal == row.Principal &&
                request.TokenHash == attempt.TokenHash && request.Definition == row.Definition && request.Authorized == allowed &&
                request.Method == Method(row.Action) && request.Path == Path(row) &&
                request.BodyHash == DynamicPermissionEffects.ActionBodyHash(Issued, row), "effect-mismatch");
            var bootstraps = ingresses.Where(r => r.Definition == row.Definition && r.Bootstrap).ToArray();
            bool bootstrap = DynamicPermissionContract.Bootstrap(row.Action);
            Require(bootstraps.Length == (bootstrap ? 1 : 0), "effect-mismatch");
            if (bootstrap)
            {
                bootstrapCount++;
                var b = bootstraps.Single();
                Require(b.Principal == root.Authorities.Setup && b.Authorized && b.TokenHash == attempt.SetupHash &&
                    b.TokenHash != attempt.TokenHash && b.Method == "GET" &&
                    b.Path == "/api/v1/dynamic-secrets/" + row.Name && b.BodyHash == DynamicPermissionContract.RawHash([]) &&
                    Array.IndexOf(ingresses, b) < Array.IndexOf(ingresses, request!), "effect-mismatch");
            }
            Require(decision.Principal == row.Principal && decision.TokenHash == attempt.TokenHash &&
                decision.Project == row.Project && decision.Definition == row.Definition && decision.Revision == revision &&
                decision.Action == row.Action && decision.Allowed == allowed, "effect-mismatch");
            var previous = states.GetValueOrDefault(row.Definition) ?? new(row.Definition, false, 0, "");
            var expected = allowed ? row.Action switch
            {
                DynamicPermissionAction.Create => new(row.Definition, true, 1, ProfileHash(Issued.Sql, 300)),
                DynamicPermissionAction.Edit => new(row.Definition, true, 2, ProfileHash(Issued.Sql, 240)),
                DynamicPermissionAction.Delete => new(row.Definition, false, 0, ""),
                _ => previous
            } : previous;
            Require(changes[i].Request == decision.Request && changes[i].Before == previous && changes[i].After == expected,
                "effect-mismatch");
            if (expected.Exists) states[row.Definition] = expected; else states.Remove(row.Definition);
            var ls = issued.Where(l => l.Request == decision.Request).ToArray();
            bool acquired = allowed && row.Action == DynamicPermissionAction.Lease;
            Require(ls.Length == (acquired ? 1 : 0) && (acquired || attempt.Lease is null && attempt.MaterialHash is null), "effect-mismatch");
            if (!acquired) continue;
            leaseCount++;
            var lease = ls.Single();
            Require(leases.Add(lease.Lease) && materials.Add(lease.MaterialHash) && lease.Lease == attempt.Lease &&
                lease.MaterialHash == attempt.MaterialHash && lease.Principal == row.Principal && lease.Project == row.Project &&
                lease.Definition == row.Definition && lease.Revision == revision &&
                lease.Decision == packet.Decisions[i].Payload.Header.Event &&
                sql.Count(s => s.Lease == lease.Lease) == 4, "effect-mismatch");
        }
        Require(ingresses.Length == attempts.Length + bootstrapCount + (activate ? 1 : 0) &&
            issued.Length == leaseCount && sql.Count == leaseCount * 4, "effect-mismatch");
        CheckInventory(packet, step);
    }
    internal static string Method(DynamicPermissionAction action) => action switch
    {
        DynamicPermissionAction.Read => "GET",
        DynamicPermissionAction.Create or DynamicPermissionAction.Lease => "POST",
        DynamicPermissionAction.Edit => "PATCH",
        DynamicPermissionAction.Delete => "DELETE",
        _ => ""
    };
    internal static string Path(DynamicPermissionRow row) => "/api/v1/dynamic-secrets" +
        (row.Action == DynamicPermissionAction.Lease ? "/leases" : row.Action == DynamicPermissionAction.Create ? "" : "/" + row.Name);
    private async ValueTask<DynamicPermissionPacket> StepAsync(DynamicPermissionStep step, SecretMaterial? cap, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step);
        busy = failed = true; stage++;
        try { var packet = await source.StepAsync(root, step, cap, token); failed = false; return packet; }
        finally { busy = false; }
    }
    private DynamicPermissionOwner Owner(DynamicPermissionPacket packet, DynamicPermissionStep step)
    {
        var owner = verify.Verify(packet.Owner, DynamicPermissionJournal.Ownership, step.ToString());
        Require(packet.Seals.Length == 4 && packet.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 4);
        foreach (var journal in new[] { DynamicPermissionJournal.Ingress, DynamicPermissionJournal.Policy,
            DynamicPermissionJournal.Resources, DynamicPermissionJournal.Issuance })
        {
            var signed = packet.Seals.Single(s => s.Payload.Header.Journal == journal);
            var seal = fences.Verify(signed, journal, step.ToString());
            var content = DynamicPermissionContract.Contents(packet, journal);
            Require(seal.Terminal && seal.Pending == 0 && seal.Count == content.Headers.Length &&
                seal.ContentHash == content.Hash && content.Headers.All(h => h.Sequence < signed.Payload.Header.Sequence));
        }
        Require(owner.Step == step && owner.CollisionChecked && owner.PreEnrolled && owner.Exclusive &&
            owner.Pending == 0 && (step != DynamicPermissionStep.Settle || owner.Terminal) &&
            owner.Enrolled.Distinct().Count() == owner.Enrolled.Length &&
            owner.Enrolled.All(e => e.Root == root.Id && e.Nonce == root.Nonce) &&
            owner.Remaining.All(e => owner.Enrolled.Contains(e)) &&
            (reservation is null || owner.Borrowed.SequenceEqual(reservation.Borrowed) &&
                reservation.Enrolled.All(e => owner.Enrolled.Contains(e))));
        return owner;
    }
    private void CheckInventory(DynamicPermissionPacket packet, DynamicPermissionStep step)
    {
        var currentPolicies = policyInventory.Verify(packet.Policies, DynamicPermissionJournal.Policy, step.ToString());
        Require(currentPolicies.OrderBy(p => p.Resource).SequenceEqual(policies.Values.OrderBy(p => p.Resource)), "effect-mismatch");
        var inventory = verify.Verify(packet.Inventory, DynamicPermissionJournal.Resources, step.ToString());
        Require(inventory.OrderBy(s => s.Definition).SequenceEqual(states.Values.OrderBy(s => s.Definition)), "effect-mismatch");
        var backend = verify.Verify(packet.Backend, DynamicPermissionJournal.Backend, step.ToString());
        Require(backend.Credentials == leases.Count && backend.Leases == leases.Count && backend.ProtectedRows == 1 &&
            backend.LeaseIds.Order().SequenceEqual(leases.Order()), "effect-mismatch");
    }
    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        closed = true;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var packet = await source.StepAsync(root, DynamicPermissionStep.Close, null, deadline.Token);
            var owner = Owner(packet, DynamicPermissionStep.Close);
            var inventory = verify.Verify(packet.Inventory, DynamicPermissionJournal.Resources, DynamicPermissionStep.Close.ToString());
            var backend = verify.Verify(packet.Backend, DynamicPermissionJournal.Backend, DynamicPermissionStep.Close.ToString());
            var remainingPolicies = policyInventory.Verify(packet.Policies, DynamicPermissionJournal.Policy, DynamicPermissionStep.Close.ToString());
            Require(owner.Terminal && owner.Registrations == 0 && owner.Remaining.Length == 0 && inventory.Length == 0 &&
                remainingPolicies.Length == 0 &&
                backend.Credentials == 0 && backend.ProtectedRows == 0 && backend.Leases == 0 && backend.LeaseIds.Length == 0 &&
                leases.All(l => owner.Enrolled.Any(e => e.Kind == "lease" && e.Id == l.ToString())), "cleanup-incomplete");
        }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { verify.Dispose(); fences.Dispose(); policyInventory.Dispose(); }
    }
    private void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) failed = true; DynamicPermissionContract.Require(condition, code); }
}
