using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class RotationPermissionTrial : IAsyncDisposable
{
    private readonly IRotationPermissionSource source;
    private readonly RotationPermissionRoot root;
    private readonly RotationPermissionVerifier journals, seals, inventories;
    private readonly Dictionary<Guid, RotationPermissionState> states = [];
    private readonly Dictionary<string, RotationPermissionPolicy> policies = [];
    private readonly HashSet<string> requests = [];
    private RotationPermissionOwner? reservation;
    private RotationPermissionReceipt? activation;
    private string revision = "", protectedHash = "";
    private int stage;
    private bool failed, busy, closed;
    internal RotationPermissionIssued Issued { get; private set; } = null!;
    internal RotationPermissionReceipt? Original { get; private set; }
    internal RotationPermissionOutcome Outcome { get; private set; }
    private RotationPermissionTrial(IRotationPermissionSource source, RotationPermissionRoot root)
    {
        this.source = source; this.root = root;
        journals = new(root); seals = new(root); inventories = new(root);
    }
    internal static async ValueTask<RotationPermissionTrial> OpenAsync(IRotationPermissionSource source,
        RotationPermissionRoot root, SecretMaterial capability, Action<RotationPermissionTrial> retain, CancellationToken token)
    {
        RotationPermissionContract.Validate(root.Profile);
        RotationPermissionContract.Require(source.Identity == root.Source && source.Kind == root.Kind &&
            root.Profile.SqlProfile is (InfisicalRotationProfile.PostgresCredentials or
                InfisicalRotationProfile.MysqlCredentials or InfisicalRotationProfile.MssqlCredentials) &&
            Enum.IsDefined(root.Kind) && Enum.IsDefined(root.Action) &&
            RotationPermissionContract.Operations.Contains(root.Operation) &&
            root.Variant == RotationPermissionContract.Variant(root.Action) &&
            RotationPermissionContract.Boundaries.Contains(root.Boundary) &&
            root.Authorities.All.All(RotationPermissionContract.Text) && root.Authorities.All.Distinct().Count() == 5 &&
            !root.Authorities.All.Contains(root.Source) && root.Profile.Pins.All(p => p.Writer != root.Source &&
                !root.Authorities.All.Contains(p.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(RotationPermissionContract.Text),
            "missing-input");
        var trial = new RotationPermissionTrial(source, root);
        retain(trial); // Compensation owns the ORIGINAL root before Reserve/Open.
        var reserved = await trial.StepAsync(RotationPermissionStep.Reserve, capability, token);
        trial.reservation = trial.Owner(reserved, RotationPermissionStep.Reserve);
        trial.Require(trial.reservation.Remaining.Length == 0 && reserved.Owner.Payload.Content.Issued is null);
        trial.CheckInventory(reserved, RotationPermissionStep.Reserve);
        var opened = await trial.StepAsync(RotationPermissionStep.Open, null, token);
        var owner = trial.Owner(opened, RotationPermissionStep.Open);
        trial.Require(owner.Issued is not null);
        trial.Issued = owner.Issued!;
        var issued = trial.Issued;
        trial.Require(new[] { issued.Project, issued.ControlProject, issued.CopyProject }.Distinct().Count() == 3 &&
            Guid.TryParse(issued.Connection, out _) && Guid.TryParse(issued.ControlConnection, out _) &&
            issued.Connection != issued.ControlConnection && issued.Rows.Length == 180 &&
            issued.Rows.Select(r => r.Id).Distinct().Count() == 180 &&
            issued.Rows.All(r => r.SqlProfile == root.Profile.SqlProfile));
        foreach (string window in new[] { "before", "after", "copy" })
        {
            var rows = issued.Rows.Where(r => r.Window == window).ToArray();
            trial.Require(rows.Length == 60 && rows.Count(r => r.List) == 6);
            foreach (var action in Enum.GetValues<RotationPermissionAction>())
            {
                foreach (string control in new[] { "selected", "project", "environment", "path", "connection" })
                    trial.Require(rows.Count(r => !r.List && r.Action == action && r.Principal == root.Authorities.Runtime &&
                        r.Control == control) == 1);
                foreach (string principal in root.Authorities.All.Where(p => p != root.Authorities.Runtime))
                    trial.Require(rows.Count(r => !r.List && r.Action == action && r.Principal == principal &&
                        r.Control == "selected") == 1);
            }
        }
        foreach (var row in issued.Rows)
        {
            trial.Require(row.Id != Guid.Empty && row.Name.Length <= 56 &&
                row.Project == (row.Control == "project" ? issued.ControlProject :
                    row.Window == "copy" ? issued.CopyProject : issued.Project) &&
                row.Environment == (row.Control == "environment" ? "outside" : "witness") &&
                row.Path == (row.Control == "path" ? "/outside" : "/owned") &&
                row.Connection == (row.Control == "connection" ? issued.ControlConnection : issued.Connection) &&
                (!row.List || row.Action == RotationPermissionAction.Read) &&
                owner.Enrolled.Any(e => e.Kind == "rotation" && e.Id == row.Id.ToString()));
        }
        trial.revision = issued.BaselineRevision;
        if (!RotationPermissionContract.Create(root.Operation))
        {
            var policy = new RotationPermissionPolicy(issued.PolicyId, root.Authorities.Runtime, issued.Project,
                issued.BaselineRevision, RotationPermissionContract.PolicyHash(RotationPermissionContract.Baseline(root), issued.Connection), null);
            trial.policies.Add(policy.Resource, policy);
            if (RotationPermissionContract.Template(root.Operation))
                trial.policies.Add(issued.TemplateId, policy with { Resource = issued.TemplateId });
        }
        var initial = trial.inventories.Verify(opened.Inventory, RotationPermissionJournal.Resources, "Open");
        foreach (var row in issued.Rows.Where(r => r.Action != RotationPermissionAction.Create &&
            (r.Window != "copy" || r.Control == "project")))
        {
            var state = initial.Single(s => s.Id == row.Id);
            trial.Require(state.Exists && state.Version == 1 && state.Generation == 1 &&
                state.Configuration == RotationPermissionContract.Initial(row) && RotationPermissionContract.Text(state.MaterialHash));
            trial.states.Add(row.Id, state);
        }
        trial.Require(initial.Length == trial.states.Count);
        trial.CheckPolicies(opened, RotationPermissionStep.Open);
        trial.CheckStores(opened, RotationPermissionStep.Open, trial.states.Count * 2);
        return trial;
    }
    internal RotationPermissionRow[] Rows(bool after) => Issued.Rows.Where(r => r.Window ==
        (!after ? "before" : RotationPermissionContract.Template(root.Operation) &&
            Outcome == RotationPermissionOutcome.Applied ? "copy" : "after")).ToArray();
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    {
        var step = after ? RotationPermissionStep.After : RotationPermissionStep.Before;
        var packet = await StepAsync(step, null, token); Owner(packet, step);
        if (after && RotationPermissionContract.Template(root.Operation) && Outcome == RotationPermissionOutcome.Applied)
        {
            var inventory = inventories.Verify(packet.Inventory, RotationPermissionJournal.Resources, step.ToString());
            foreach (var row in Rows(true).Where(r => r.Project == Issued.CopyProject && r.Action != RotationPermissionAction.Create))
            {
                var value = inventory.Single(s => s.Id == row.Id);
                Require(value.Exists && value.Version == 1 && value.Generation == 1 &&
                    value.Configuration == RotationPermissionContract.Initial(row) && RotationPermissionContract.Text(value.MaterialHash));
                states.Add(row.Id, value);
            }
            Require(inventory.OrderBy(x => x.Id).SequenceEqual(states.Values.OrderBy(x => x.Id)), "effect-mismatch");
            policies.Add(Issued.CopyProject, new(Issued.CopyProject, root.Authorities.Runtime, Issued.CopyProject,
                revision, RotationPermissionContract.PolicyHash(root.Action, Issued.Connection), revision));
            CheckPolicies(packet, step);
            CheckStores(packet, step, states.Count * 2);
        }
        else CheckInventory(packet, step);
    }
    internal async ValueTask ArmAsync(CancellationToken token)
    {
        var packet = await StepAsync(RotationPermissionStep.Arm, null, token);
        Owner(packet, RotationPermissionStep.Arm); CheckInventory(packet, RotationPermissionStep.Arm);
    }
    internal async ValueTask SettleAsync(RotationPermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Evidence == receipt.Native.Evidence, "effect-mismatch");
        Original = receipt; // Immutable causal receipt, never reconciled by a GET.
        var p = await StepAsync(RotationPermissionStep.Settle, null, token); Owner(p, RotationPermissionStep.Settle);
        bool cancelled = root.Boundary == "cancellation-boundary", denied = root.Boundary == "denied-authority",
            lost = root.Boundary == "lost-response-no-replay";
        Require(p.Requests.Length == (cancelled ? 0 : 1) && p.Commits.Length <= 1 &&
            (!(cancelled || denied) || p.Commits.Length == 0) && p.Decisions.Length == 0 && p.Changes.Length == 0 &&
            p.Materials.Length == 0 && p.Backend.Length == 0, "effect-mismatch");
        Require(receipt.Evidence == (cancelled ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected :
            lost ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancelled || lost) &&
            (receipt.Cancelled ? receipt.Status is null : receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var signed in p.Requests)
        {
            var i = journals.Verify(signed, RotationPermissionJournal.Ingress, "original");
            Require(requests.Add(i.Request) && i.Principal == (denied ? root.Authorities.Denied : root.Authorities.Administrative) &&
                i.Authorized == !denied && !i.Bootstrap && i.IntentHash == receipt.IntentHash &&
                i.TokenHash == receipt.TokenHash && RotationPermissionContract.Text(i.TokenHash) && RotationPermissionContract.Text(i.BodyHash) &&
                i.Method == (RotationPermissionContract.Create(root.Operation) ? "POST" : "PATCH") &&
                i.Path == RotationPermissionEffects.OriginalPath(root, Issued), "effect-mismatch");
        }
        Outcome = RotationPermissionOutcome.NonApplied;
        foreach (var signed in p.Commits)
        {
            var c = journals.Verify(signed, RotationPermissionJournal.Policy, "original");
            var s = c.State;
            Require(c.Request == p.Requests.Single().Payload.Content.Request && c.PreviousRevision == revision &&
                s.Revision != revision && s.Resource == (RotationPermissionContract.Template(root.Operation) ? Issued.TemplateId : Issued.PolicyId) &&
                s.Principal == root.Authorities.Runtime && s.Project == Issued.Project && s.SourceRevision is null, "effect-mismatch");
            revision = s.Revision; policies[s.Resource] = s;
            Outcome = s.PolicyHash == RotationPermissionContract.PolicyHash(root.Action, Issued.Connection) ?
                RotationPermissionOutcome.Applied : RotationPermissionOutcome.Partial;
        }
        Require(lost || (cancelled || denied ? Outcome == RotationPermissionOutcome.NonApplied :
            Outcome == RotationPermissionOutcome.Applied), "effect-mismatch");
        CheckInventory(p, RotationPermissionStep.Settle);
        Require(receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
    }
    internal void Activated(RotationPermissionReceipt receipt)
    {
        Require(stage == 6 && activation is null && receipt.Evidence == receipt.Native.Evidence &&
            receipt.Evidence == DispatchEvidence.Applied && receipt.Status == SecretStatus.Success && !receipt.Cancelled,
            "effect-mismatch");
        activation = receipt;
    }
    internal async ValueTask ObserveAsync(bool after, RotationPermissionAttempt[] attempts, CancellationToken token)
    {
        var step = after ? RotationPermissionStep.ObserveAfter : RotationPermissionStep.ObserveBefore;
        var p = await StepAsync(step, null, token); Owner(p, step);
        string window = after ? "after" : "before";
        var ingress = p.Requests.Select(s => journals.Verify(s, RotationPermissionJournal.Ingress, window)).ToArray();
        foreach (var i in ingress) Require(requests.Add(i.Request));
        bool activate = after && Outcome == RotationPermissionOutcome.Applied &&
            (RotationPermissionContract.Template(root.Operation) || root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal));
        Require(p.Commits.Length == (activate ? 1 : 0) && ingress.Length == attempts.Length + (activate ? 1 : 0), "effect-mismatch");
        if (activate)
        {
            var i = ingress.Single(x => x.Rotation is null);
            var c = journals.Verify(p.Commits.Single(), RotationPermissionJournal.Policy, window);
            Require(activation is not null && i.Principal == root.Authorities.Setup && i.Authorized && !i.Bootstrap &&
                i.IntentHash == activation.IntentHash && c.Request == i.Request && c.State.SourceRevision == revision &&
                c.State.PolicyHash == RotationPermissionContract.PolicyHash(root.Action, Issued.Connection) &&
                c.State.Principal == root.Authorities.Runtime, "effect-mismatch");
        }
        var decisions = p.Decisions.Select(s => journals.Verify(s, RotationPermissionJournal.Policy, window)).ToArray();
        var changes = p.Changes.Select(s => journals.Verify(s, RotationPermissionJournal.Resources, window)).ToArray();
        var materials = p.Materials.Select(s => journals.Verify(s, RotationPermissionJournal.Issuance, window)).ToArray();
        var backend = p.Backend.Select(s => journals.Verify(s, RotationPermissionJournal.Backend, window)).ToArray();
        Require(attempts.Length == 60 && decisions.Length == 60 && changes.Length == 60 &&
            attempts.Select(a => a.Row).SequenceEqual(Rows(after)), "effect-mismatch");
        var materialRequests = new HashSet<string>(); var backendRequests = new HashSet<string>();
        for (int n = 0; n < attempts.Length; n++)
        {
            var a = attempts[n]; var r = a.Row; var d = decisions[n];
            bool allowed = RotationPermissionContract.Allowed(root, r, after, Outcome);
            var i = ingress.Single(x => x.Request == d.Request);
            Require(a.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) &&
                i.Principal == r.Principal && !i.Bootstrap && i.TokenHash == a.TokenHash && i.Rotation == r.Id &&
                i.Method == Method(r.Action) && i.Path == Path(r) && RotationPermissionContract.Text(i.BodyHash) &&
                i.Authorized == allowed && d.Allowed == allowed && d.Principal == r.Principal &&
                d.TokenHash == a.TokenHash && d.Rotation == r.Id && d.Project == r.Project &&
                d.Environment == r.Environment && d.Path == r.Path && d.Connection == r.Connection &&
                d.Action == r.Action && d.Revision == revision, "effect-mismatch");
            if (r.Action == RotationPermissionAction.RotateSecrets)
                Require(a.RotationDispatch == (allowed ? InfisicalRotationDispatch.ResponseObserved : InfisicalRotationDispatch.Rejected));
            else if (r.Action is not (RotationPermissionAction.Read or RotationPermissionAction.ReadGeneratedCredentials))
                Require(a.Evidence == (allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected));
            var previous = states.GetValueOrDefault(r.Id) ?? new(r.Id, false, 0, null, 0, "");
            var change = changes[n];
            Require(change.Request == d.Request && change.Before == previous, "effect-mismatch");
            var expected = allowed ? r.Action switch
            {
                RotationPermissionAction.Create => new(r.Id, true, 1, RotationPermissionContract.Initial(r), 1, change.After.MaterialHash),
                RotationPermissionAction.Edit => previous with
                {
                    Version = previous.Version + 1,
                    Configuration = RotationPermissionContract.Edited(previous.Configuration!)
                },
                RotationPermissionAction.Delete => new(r.Id, false, 0, null, 0, ""),
                RotationPermissionAction.RotateSecrets => previous with
                {
                    Version = previous.Version + 1,
                    Generation = previous.Generation + 1,
                    MaterialHash = change.After.MaterialHash
                },
                _ => previous
            } : previous;
            Require(change.After == expected, "effect-mismatch");
            if (allowed && r.Action is RotationPermissionAction.Create or RotationPermissionAction.RotateSecrets)
                Require(RotationPermissionContract.Text(expected.MaterialHash) && expected.MaterialHash != previous.MaterialHash, "effect-mismatch");
            if (expected.Exists) states[r.Id] = expected; else states.Remove(r.Id);
            RotationPermissionConfiguration[] values = !allowed ? [] : r.List ?
                states.Values.Where(s => Issued.Rows.Any(row => row.Id == s.Id && row.Project == r.Project &&
                    (r.Principal != root.Authorities.Runtime || row.Environment == "witness" && row.Path == "/owned" && row.Connection == Issued.Connection)))
                    .Select(s => s.Configuration!).OrderBy(v => v.Id).ToArray() :
                r.Action is RotationPermissionAction.ReadGeneratedCredentials or RotationPermissionAction.RotateSecrets ? [] :
                [r.Action == RotationPermissionAction.Delete ? previous.Configuration! : expected.Configuration!];
            Require(a.Complete && a.Values.OrderBy(v => v.Id).SequenceEqual(values), "effect-mismatch");
            var m = materials.Where(x => x.Request == d.Request).ToArray();
            var b = backend.Where(x => x.Request == d.Request).ToArray();
            if (allowed && !r.List)
            {
                Require(b.Length == 2 && b.All(x => x.Rotation == r.Id && x.WrongRejected && x.WriteDenied &&
                    x.Authenticated == expected.Exists && x.ReadAllowed == expected.Exists), "effect-mismatch");
                foreach (var measurement in b)
                {
                    if (protectedHash.Length == 0) protectedHash = measurement.ProtectedHash;
                    Require(measurement.ProtectedHash == protectedHash && RotationPermissionContract.Text(protectedHash), "effect-mismatch");
                }
                if (expected.Exists)
                {
                    Require(m.Length == 2 && m.All(x => x.Rotation == r.Id && x.Generation == expected.Generation) &&
                        m.Select(x => x.UsernameHash).SequenceEqual(new[] { RotationPermissionContract.Hash(r.Username1),
                            RotationPermissionContract.Hash(r.Username2) }) &&
                        (r.Action == RotationPermissionAction.Edit || m.All(x => x.MeetsRequirements)) &&
                        RotationPermissionContract.Hash(m.Select(x => x.MaterialHash).ToArray()) == expected.MaterialHash &&
                        b.Select(x => x.MaterialHash).SequenceEqual(m.Select(x => x.MaterialHash)), "effect-mismatch");
                    if (r.Action == RotationPermissionAction.ReadGeneratedCredentials)
                        Require(a.MaterialHashes.SequenceEqual(m.Select(x => x.MaterialHash)), "effect-mismatch");
                }
                else Require(m.Length == 0);
                materialRequests.Add(d.Request); backendRequests.Add(d.Request);
            }
            else Require(m.Length == 0 && b.Length == 0);
        }
        Require(materials.All(m => materialRequests.Contains(m.Request)) && backend.All(b => backendRequests.Contains(b.Request)));
        CheckInventory(p, step);
        Require(Original is null || Original.Native.Evidence == Original.Evidence, "effect-mismatch");
    }
    private async ValueTask<RotationPermissionPacket> StepAsync(RotationPermissionStep step, SecretMaterial? capability, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step);
        busy = failed = true; stage++;
        try { var p = await source.StepAsync(root, step, capability, token); failed = false; return p; }
        finally { busy = false; }
    }
    private static string Method(RotationPermissionAction action) => action switch
    {
        RotationPermissionAction.Read or RotationPermissionAction.ReadGeneratedCredentials => "GET",
        RotationPermissionAction.Edit => "PATCH",
        RotationPermissionAction.Delete => "DELETE",
        _ => "POST"
    };
    private static string Path(RotationPermissionRow row) => "/api/v2/secret-rotations/" +
        RotationPermissionContract.ProfileWire(row.SqlProfile) +
        (row.List || row.Action == RotationPermissionAction.Create ? "" : "/" + row.Id +
            (row.Action == RotationPermissionAction.ReadGeneratedCredentials ? "/generated-credentials" :
                row.Action == RotationPermissionAction.RotateSecrets ? "/rotate-secrets" : ""));
    private RotationPermissionOwner Owner(RotationPermissionPacket p, RotationPermissionStep step)
    {
        var owner = journals.Verify(p.Owner, RotationPermissionJournal.Ownership, step.ToString());
        Require(p.Seals.Length == 6 && p.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 6);
        foreach (var j in Enum.GetValues<RotationPermissionJournal>())
        {
            var seal = seals.Verify(p.Seals.Single(s => s.Payload.Header.Journal == j), j, step.ToString());
            var contents = RotationPermissionContract.Contents(p, j);
            Require(seal.Terminal && seal.Pending == 0 && seal.Count == contents.Length &&
                seal.Hash == RotationPermissionContract.Hash(contents));
        }
        Require(owner.Step == step && owner.CollisionChecked && owner.PreEnrolled && owner.Exclusive && owner.Pending == 0 &&
            (step != RotationPermissionStep.Settle || owner.Terminal) && owner.Enrolled.Distinct().Count() == owner.Enrolled.Length &&
            owner.Enrolled.All(e => e.Root == root.Id && e.Nonce == root.Nonce) &&
            owner.Remaining.All(e => owner.Enrolled.Contains(e)) &&
            !owner.Enrolled.Any(e => owner.Borrowed.Any(b => b.Kind == e.Kind && b.Id == e.Id)) &&
            (reservation is null || owner.Borrowed.SequenceEqual(reservation.Borrowed) &&
                reservation.Enrolled.SequenceEqual(owner.Enrolled)));
        return owner;
    }
    private void CheckPolicies(RotationPermissionPacket p, RotationPermissionStep step) =>
        Require(inventories.Verify(p.Policies, RotationPermissionJournal.Policy, step.ToString())
            .OrderBy(x => x.Resource).SequenceEqual(policies.Values.OrderBy(x => x.Resource)), "effect-mismatch");
    private void CheckInventory(RotationPermissionPacket p, RotationPermissionStep step)
    {
        CheckPolicies(p, step);
        Require(inventories.Verify(p.Inventory, RotationPermissionJournal.Resources, step.ToString())
            .OrderBy(x => x.Id).SequenceEqual(states.Values.OrderBy(x => x.Id)), "effect-mismatch");
        CheckStores(p, step, states.Count * 2);
    }
    private void CheckStores(RotationPermissionPacket p, RotationPermissionStep step, int expected)
    {
        var issuer = inventories.Verify(p.IssuanceInventory, RotationPermissionJournal.Issuance, step.ToString());
        var backend = inventories.Verify(p.BackendInventory, RotationPermissionJournal.Backend, step.ToString());
        Require(issuer.Count == expected && backend.Count == expected && issuer.Pending == 0 && backend.Pending == 0 &&
            issuer.Registrations == 0 && backend.Registrations == 0 && issuer.BorrowedPreserved && backend.BorrowedPreserved,
            step == RotationPermissionStep.Close ? "cleanup-incomplete" : "effect-mismatch");
        Require(issuer.ProtectedRows == 0 && backend.ProtectedRows ==
            (step is RotationPermissionStep.Reserve or RotationPermissionStep.Close ? 0 : 1),
            step == RotationPermissionStep.Close ? "cleanup-incomplete" : "effect-mismatch");
    }
    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        closed = true;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var p = await source.StepAsync(root, RotationPermissionStep.Close, null, timeout.Token);
            var owner = Owner(p, RotationPermissionStep.Close);
            Require(owner.Terminal && owner.Registrations == 0 && owner.Remaining.Length == 0 &&
                inventories.Verify(p.Inventory, RotationPermissionJournal.Resources, "Close").Length == 0 &&
                inventories.Verify(p.Policies, RotationPermissionJournal.Policy, "Close").Length == 0,
                "cleanup-incomplete");
            CheckStores(p, RotationPermissionStep.Close, 0);
        }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { journals.Dispose(); seals.Dispose(); inventories.Dispose(); }
    }
    private void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) failed = true; RotationPermissionContract.Require(condition, code); }
}
