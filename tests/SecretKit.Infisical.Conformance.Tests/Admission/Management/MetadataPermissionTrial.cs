using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class MetadataPermissionTrial : IAsyncDisposable
{
    private readonly IMetadataPermissionSource source;
    private readonly MetadataPermissionRoot root;
    private readonly MetadataPermissionVerifier verifier;
    private readonly MetadataPermissionVerifier seals;
    private readonly HashSet<string> requests = [];
    private readonly HashSet<Guid> leases = [];
    private readonly HashSet<string> materials = [];
    private readonly List<MetadataPermissionBackend> actions = [];
    private MetadataPermissionOwner? reservation;
    private int stage;
    private bool busy, failed, closed;
    private string revision = "";
    internal MetadataPermissionIssued Issued { get; private set; } = null!;
    internal MetadataPermissionOutcome Outcome { get; private set; }
    internal MetadataPermissionReceipt? Original { get; private set; }
    private MetadataPermissionReceipt? activation;
    internal string Revision => revision;
    internal MetadataPermissionRow[] Rows(bool after) => after &&
        MetadataPermissionContract.Template(root.Operation) && Outcome == MetadataPermissionOutcome.Applied ?
        Issued.CopyRows : Issued.Rows;
    private MetadataPermissionTrial(IMetadataPermissionSource source, MetadataPermissionRoot root)
    { this.source = source; this.root = root; verifier = new(root); seals = new(root); }

    internal static async ValueTask<MetadataPermissionTrial> OpenAsync(IMetadataPermissionSource source,
        MetadataPermissionRoot root, SecretMaterial capability, Action<MetadataPermissionTrial> retain,
        CancellationToken token)
    {
        MetadataPermissionContract.Require(source.Identity == root.Source && source.Kind == root.Kind &&
            Enum.IsDefined(root.Kind) && root.Subject == MetadataPermissionSubject.DynamicSecrets &&
            root.Authorities.All.All(MetadataPermissionContract.Text) && root.Authorities.All.Distinct().Count() == 5 &&
            !root.Authorities.All.Contains(root.Source) && root.Profile.Pins.All(p =>
                p.Writer != root.Source && !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(MetadataPermissionContract.Text),
            "missing-input");
        var trial = new MetadataPermissionTrial(source, root);
        void Require(bool condition, string code = "observer-unavailable") => trial.Require(condition, code);
        retain(trial); // recovery owner exists before any reservation/bootstrap side effect
        var reserve = await trial.StepAsync(MetadataPermissionStep.Reserve, capability, token);
        trial.reservation = trial.Owner(reserve, MetadataPermissionStep.Reserve);
        Require(trial.reservation.CollisionChecked && trial.reservation.PreEnrolled &&
            trial.reservation.Remaining.Length == 0);
        var opened = await trial.StepAsync(MetadataPermissionStep.Open, null, token);
        var owner = trial.Owner(opened, MetadataPermissionStep.Open);
        Require(owner.Issued is not null);
        trial.Issued = owner.Issued!;
        var issued = trial.Issued;
        Require(issued.Project != issued.ControlProject && MetadataPermissionContract.Text(issued.BaselineRevision) &&
            issued.Rows.Length == 6 && issued.Rows.Select(r => r.Name).Order().SequenceEqual(
                new[] { "cross-scope", "empty", "key-only", "same-entry", "split-entry", "value-only" }) &&
            issued.Rows.Select(r => r.Definition).Distinct().Count() == 6 &&
            issued.Rows.All(r => r.Definition != Guid.Empty && r.Folder != Guid.Empty &&
                MetadataPermissionContract.Text(r.MetadataRevision)) &&
            issued.Rows.All(r => r.Name == "cross-scope" ? r.Project == issued.ControlProject :
                r.Project == issued.Project) && owner.Enrolled.All(e =>
                e.Root == root.Id && e.Nonce == root.Nonce) &&
            owner.Remaining.All(e => owner.Enrolled.Contains(e)) &&
            trial.reservation.Enrolled.All(e => owner.Enrolled.Contains(e)));
        Require(issued.CopyRows.Length == 6 && issued.CopyRows[0].Project != issued.Project &&
            issued.CopyRows[0].Project != issued.ControlProject && issued.CopyRows.Select(r => r.Name).Order()
                .SequenceEqual(issued.Rows.Select(r => r.Name).Order()) &&
            issued.CopyRows.All(r => r.Name == "cross-scope" ? MetadataPermissionContract.Hash(r) ==
                MetadataPermissionContract.Hash(issued.Rows.Single(o => o.Name == "cross-scope")) :
                r.Project == issued.CopyRows[0].Project && r.ProjectSlug == issued.CopySlug) &&
            issued.Rows.Concat(issued.CopyRows).Select(r => r.Definition).Distinct().Count() == 11 &&
            issued.Rows.Concat(issued.CopyRows).All(r => owner.Enrolled.Any(e => e.Kind == "definition" &&
                e.Id == r.Definition.ToString()) && owner.Enrolled.Any(e => e.Kind == "folder" && e.Id == r.Folder.ToString())) &&
            owner.Enrolled.All(e => !owner.Borrowed.Any(b => b.Kind == e.Kind && b.Id == e.Id)));
        foreach (var row in issued.Rows.Concat(issued.CopyRows))
        {
            var expected = row.Name switch
            {
                "same-entry" or "cross-scope" => new[] { new MetadataPermissionEntry("team", "blue") },
                "split-entry" => [new MetadataPermissionEntry("team", "red"), new("other", "blue")],
                "key-only" => [new MetadataPermissionEntry("team", "red")],
                "value-only" => [new MetadataPermissionEntry("other", "blue")],
                _ => []
            };
            Require(row.Metadata.SequenceEqual(expected) && row.Environment ==
                (row.Name == "cross-scope" ? "outside" : "witness") && row.Path == "/");
        }
        trial.revision = issued.BaselineRevision;
        return trial;
    }

    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        var step = after ? MetadataPermissionStep.After : MetadataPermissionStep.Before;
        Owner(await StepAsync(step, null, token), step);
        actions.Clear();
    }
    internal void Activated(MetadataPermissionReceipt receipt)
    {
        Require(stage == (int)MetadataPermissionStep.After && !failed && activation is null &&
            receipt.Evidence == DispatchEvidence.Applied && receipt.Status == SecretStatus.Success && !receipt.Cancelled,
            "effect-mismatch");
        activation = receipt;
    }
    internal async ValueTask ArmAsync(CancellationToken token) =>
        Owner(await StepAsync(MetadataPermissionStep.Arm, null, token), MetadataPermissionStep.Arm);
    internal async ValueTask SettleAsync(MetadataPermissionReceipt receipt, CancellationToken token)
    {
        Original = receipt;
        var packet = await StepAsync(MetadataPermissionStep.Settle, null, token);
        Owner(packet, MetadataPermissionStep.Settle);
        bool cancel = root.Boundary == "cancellation-boundary", denied = root.Boundary == "denied-authority",
            lost = root.Boundary == "lost-response-no-replay";
        Require(packet.Requests.Length == (cancel ? 0 : 1) && packet.Commits.Length <= 1 &&
            (!(cancel || denied) || packet.Commits.Length == 0), "effect-mismatch");
        Require(receipt.Evidence == (cancel ? DispatchEvidence.NotDispatched : lost ? DispatchEvidence.PossiblyDispatched :
            denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancel || lost) && (receipt.Cancelled ? receipt.Status is null :
                receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var signed in packet.Requests)
        {
            var ingress = Verify(signed, MetadataPermissionJournal.Ingress, "original");
            Require(requests.Add(ingress.Request) && ingress.Actor == (denied ? root.Authorities.Denied :
                root.Authorities.Administrative) && ingress.Authorized == !denied &&
                ingress.IntentHash == receipt.IntentHash &&
                ingress.Method == (MetadataPermissionContract.Create(root.Operation) ? "POST" : "PATCH") &&
                ingress.Path == MetadataPermissionEffects.OriginalPath(root, Issued), "effect-mismatch");
        }
        Outcome = MetadataPermissionOutcome.NonApplied;
        foreach (var signed in packet.Commits)
        {
            var commit = Verify(signed, MetadataPermissionJournal.Storage, "original");
            Require(commit.Request == packet.Requests.Single().Content.Request && commit.PreviousRevision == revision &&
                commit.Revision != revision && MetadataPermissionContract.Text(commit.Revision) &&
                commit.Resource == (MetadataPermissionContract.Template(root.Operation) ? Issued.TemplateId : Issued.PolicyId) &&
                commit.Principal == root.Authorities.Runtime &&
                commit.Project == Issued.Project, "effect-mismatch");
            revision = commit.Revision;
            Outcome = commit.PolicyHash == MetadataPermissionContract.PolicyHash(root.Operator) ?
                MetadataPermissionOutcome.Applied : MetadataPermissionOutcome.Partial;
        }
        Require(lost || (cancel || denied ? Outcome == MetadataPermissionOutcome.NonApplied :
            Outcome == MetadataPermissionOutcome.Applied), "effect-mismatch");
    }

    internal async ValueTask MeasureAsync(Guid lease, string username, string password, string actor,
        string project, MetadataPermissionAction action, bool after, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (after ? 7 : 3));
        busy = failed = true;
        try
        {
            using var user = SecretMaterial.FromText(username);
            using var secret = SecretMaterial.FromText(action == MetadataPermissionAction.WrongCredential ? password + "-wrong" : password);
            var signed = await source.MeasureAsync(root, lease, user, secret, action, token);
            var fact = Verify(signed, MetadataPermissionJournal.Backend, after ? "after" : "before");
            bool auth = action != MetadataPermissionAction.WrongCredential;
            bool allowed = action is MetadataPermissionAction.Select or MetadataPermissionAction.Recheck;
            Require(fact.Lease == lease && fact.MaterialHash == MetadataPermissionContract.MaterialHash(username,
                action == MetadataPermissionAction.WrongCredential ? password + "-wrong" : password) &&
                fact.Principal == actor && fact.Project == project && fact.Action == action &&
                fact.Authenticated == auth && fact.Allowed == allowed &&
                fact.ProtectedRowHash == (allowed ? Issued.ProtectedRowHash : ""), "effect-mismatch");
            actions.Add(fact);
            failed = false;
        }
        finally { busy = false; }
    }

    internal async ValueTask ObserveAsync(bool after, MetadataPermissionAttempt[] attempts, CancellationToken token)
    {
        var step = after ? MetadataPermissionStep.ObserveAfter : MetadataPermissionStep.ObserveBefore;
        var packet = await StepAsync(step, null, token);
        Owner(packet, step);
        string window = after ? "after" : "before";
        Require(packet.Decisions.Length == attempts.Length && packet.Leases.Length == attempts.Count(a => a.Allowed),
            "effect-mismatch");
        var decisions = packet.Decisions.Select(s => Verify(s, MetadataPermissionJournal.Policy, window)).ToArray();
        var issued = packet.Leases.Select(s => Verify(s, MetadataPermissionJournal.Issuance, window)).ToArray();
        for (int i = 0; i < attempts.Length; i++)
        {
            var attempt = attempts[i]; var decision = decisions[i];
            Require(requests.Add(decision.Request) && decision.Actor == attempt.Actor &&
                decision.Project == attempt.Row.Project && decision.Definition == attempt.Row.Definition &&
                decision.ConfigurationRevision == revision && decision.MetadataRevision == attempt.Row.MetadataRevision &&
                decision.Action == "lease" && decision.TokenHash == attempt.TokenHash &&
                decision.Allowed == attempt.Allowed, "effect-mismatch");
            var matching = issued.Where(l => l.Request == decision.Request).ToArray();
            Require(matching.Length == (attempt.Allowed ? 1 : 0), "effect-mismatch");
            if (matching.Length == 0) continue;
            var lease = matching[0];
            Require(leases.Add(lease.Lease) && materials.Add(lease.MaterialHash) && lease.Decision == decision.Header.Event &&
                lease.Lease == attempt.Lease && lease.MaterialHash == attempt.MaterialHash &&
                lease.Actor == attempt.Actor && lease.Project == decision.Project && lease.Definition == decision.Definition &&
                lease.ConfigurationRevision == revision && lease.MetadataRevision == decision.MetadataRevision &&
                actions.Count(a => a.Lease == lease.Lease) == 4, "effect-mismatch");
        }
        if (after && (MetadataPermissionContract.Template(root.Operation) ||
            root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal)) && Outcome == MetadataPermissionOutcome.Applied)
        {
            Require(packet.Commits.Length == 1 && packet.Requests.Length == 1 && activation is not null, "effect-mismatch");
            var copy = Verify(packet.Commits[0], MetadataPermissionJournal.Storage, window);
            var ingress = Verify(packet.Requests[0], MetadataPermissionJournal.Ingress, window);
            bool template = MetadataPermissionContract.Template(root.Operation);
            Require(requests.Add(ingress.Request) && ingress.Actor == root.Authorities.Setup && ingress.Authorized &&
                ingress.IntentHash == activation!.IntentHash && copy.Request == ingress.Request &&
                ingress.Method == (template ? "POST" : "PATCH") &&
                ingress.Path == (template ? "/api/v1/projects" : "/api/v1/projects/" + Issued.Project +
                    "/memberships/identities/" + root.Authorities.Runtime) &&
                copy.SourceRevision == revision && copy.PolicyHash == MetadataPermissionContract.PolicyHash(root.Operator) &&
                copy.Principal == root.Authorities.Runtime && copy.Project == (template ? Issued.CopyRows[0].Project : Issued.Project) &&
                copy.Resource == (template ? Issued.CopyRows[0].Project : Issued.Membership) &&
                MetadataPermissionContract.Text(copy.Request), "effect-mismatch");
        }
        else Require(packet.Commits.Length == 0 && packet.Requests.Length == 0, "effect-mismatch");
    }
    private async ValueTask<MetadataPermissionPacket> StepAsync(MetadataPermissionStep step,
        SecretMaterial? capability, CancellationToken token)
    {
        Require(!closed && !busy && !failed && stage == (int)step);
        busy = failed = true; stage++;
        try
        {
            var packet = await source.StepAsync(root, step, capability, token);
            failed = false;
            return packet;
        }
        finally { busy = false; }
    }
    private MetadataPermissionOwner Owner(MetadataPermissionPacket packet, MetadataPermissionStep step)
    {
        var owner = Verify(packet.Owner, MetadataPermissionJournal.Ownership, step.ToString());
        Require(packet.Seals.Length == 4 && packet.Seals.Select(s => s.Content.Header.Journal).Distinct().Count() == 4 &&
            packet.Seals.All(s => s.Content.Header.Journal is MetadataPermissionJournal.Ingress or MetadataPermissionJournal.Storage or
                MetadataPermissionJournal.Policy or MetadataPermissionJournal.Issuance));
        foreach (var journal in new[] { MetadataPermissionJournal.Ingress, MetadataPermissionJournal.Storage,
            MetadataPermissionJournal.Policy, MetadataPermissionJournal.Issuance })
        {
            var seal = Verify(packet.Seals.Single(s => s.Content.Header.Journal == journal), journal, step.ToString(), true);
            var content = MetadataPermissionContract.Contents(packet, journal);
            Require(seal.Terminal && seal.Pending == 0 && seal.Count == content.Headers.Length &&
                seal.ContentHash == content.Hash && content.Headers.All(h => h.Sequence < seal.Header.Sequence));
        }
        Require(owner.Step == step && owner.Exclusive && owner.Pending == 0 &&
            (step != MetadataPermissionStep.Settle || owner.Terminal) &&
            owner.Enrolled.Distinct().Count() == owner.Enrolled.Length &&
            owner.Enrolled.All(e => e.Root == root.Id && e.Nonce == root.Nonce) &&
            (reservation is null || owner.Borrowed.SequenceEqual(reservation.Borrowed)));
        return owner;
    }
    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        closed = true;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var packet = await source.StepAsync(root, MetadataPermissionStep.Close, null, timeout.Token);
            var owner = Owner(packet, MetadataPermissionStep.Close);
            Require(owner.Terminal && owner.PreEnrolled && owner.Registrations == 0 && owner.Remaining.Length == 0 &&
                (reservation is null || reservation.Enrolled.All(e => owner.Enrolled.Contains(e))) &&
                leases.All(l => owner.Enrolled.Any(e => e.Kind == "lease" && e.Id == l.ToString())),
                "cleanup-incomplete");
        }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { verifier.Dispose(); seals.Dispose(); }
    }
    private T Verify<T>(MetadataPermissionSigned<T> value, MetadataPermissionJournal journal, string window, bool seal = false)
        where T : IMetadataPermissionEvidence
    {
        try { return (seal ? seals : verifier).Verify(value, journal, window); }
        catch { failed = true; throw; }
    }
    private void Require(bool condition, string code = "observer-unavailable")
    {
        if (!condition) failed = true;
        MetadataPermissionContract.Require(condition, code);
    }
}
