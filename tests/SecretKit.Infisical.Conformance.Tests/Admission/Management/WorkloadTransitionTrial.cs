using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class WorkloadTransitionTrial(IWorkloadTransitionSource source, WorkloadTransitionRoot root,
    int seconds) : IAsyncDisposable
{
    private WorkloadTransitionReservation? reservation;
    private WorkloadTransitionIssuance? issuance;
    private WorkloadTransitionWindow? window;
    private WorkloadTransitionArm? arm;
    private WorkloadTransitionConfiguration? settled;
    private readonly HashSet<string> events = [];
    private readonly HashSet<string> requests = [];
    private readonly HashSet<string> tokenHashes = [];
    private readonly HashSet<string> tokenIds = [];
    private readonly Dictionary<string, long> journalSequences = [];
    private long sequence = -1;
    private DateTimeOffset at;
    private string? registration;
    private int stage;
    private bool busy, failed, closed;
    internal WorkloadTransitionIssuance Issued => issuance ?? throw new NativeCaseFailureException("observer-unavailable");
    internal WorkloadTransitionOutcome Outcome { get; private set; }
    internal WorkloadTransitionIntent Intent => WorkloadTransitionContract.Intent(root, Issued);

    internal static async ValueTask<WorkloadTransitionTrial> OpenAsync(IWorkloadTransitionSource source,
        WorkloadTransitionRoot root, SecretMaterial capability, int seconds, Action<WorkloadTransitionTrial> retain,
        CancellationToken token)
    {
        WorkloadTransitionContract.Profile(root.Profile);
        Require(root.Source == source.Identity && root.Kind == source.Kind && Enum.IsDefined(root.Kind) &&
            root.Authorities.All.All(WorkloadTransitionContract.Text) && root.Authorities.All.Distinct().Count() == 5 &&
            !root.Authorities.All.Contains(root.Source) && root.Profile.Journals.All(j =>
                j.Writer != root.Source && !root.Authorities.All.Contains(j.Writer)) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Operation, root.Scope }.All(WorkloadTransitionContract.Text) &&
            WorkloadTransitionContract.Cases.Contains(root.Boundary) && seconds is >= 1 and <= 300, "missing-input");
        var trial = new WorkloadTransitionTrial(source, root, seconds);
        retain(trial); // Host-root recovery is retained BEFORE even Reserve.
        trial.busy = trial.failed = true;
        using var deadline = trial.Deadline(token);
        var reserved = await source.ReserveAsync(root, capability, deadline.Token);
        trial.Stamp(reserved.Stamp);
        Require(reserved.CollisionChecked && reserved.Exclusive && reserved.EnrolledBeforeCreation &&
            WorkloadTransitionContract.Borrowed(reserved.Borrowed, reserved.Borrowed));
        trial.reservation = reserved;
        var issued = await source.OpenAsync(root, deadline.Token);
        trial.Stamp(issued.Stamp);
        Require(issued.Complete && trial.Inventory(issued.Inventory) &&
            issued.Target.Identity != issued.Control.Identity && issued.Target.Project != issued.Control.Project &&
            !root.Authorities.All.Contains(issued.Target.Identity) && !root.Authorities.All.Contains(issued.Control.Identity) &&
            issued.TemplateA != issued.TemplateB && issued.ReviewerA != issued.ReviewerB &&
            issued.ReviewerHashA != issued.ReviewerHashB &&
            WorkloadTransitionContract.Hash(issued.ReviewerCredentialB) == issued.ReviewerHashB &&
            issued.Proofs.Length == 3 && issued.Proofs.Select(p => p.Name).Order().SequenceEqual(new[] { "new", "old", "wrong" }) &&
            issued.Proofs.Select(p => p.Jwt).Distinct().Count() == 3 &&
            issued.Proofs.Select(p => p.PublicKey).Distinct().Count() == 3 &&
            issued.TemplateConfigurationA.PublicKey == issued.Proofs.Single(p => p.Name == "old").PublicKey &&
            issued.TemplateConfigurationB.PublicKey == issued.Proofs.Single(p => p.Name == "new").PublicKey &&
            issued.TemplateConfigurationA.Template == issued.TemplateA && issued.TemplateConfigurationB.Template == issued.TemplateB &&
            issued.Baseline.Attached == !WorkloadTransitionContract.Attach(root) &&
            issued.Inventory.Any(r => r.Kind == "identity" && r.Id == issued.Target.Identity) &&
            issued.Inventory.Any(r => r.Kind == "identity" && r.Id == issued.Control.Identity) &&
            issued.Inventory.Any(r => r.Kind == "project" && r.Id == issued.Target.Project) &&
            issued.Inventory.Any(r => r.Kind == "project" && r.Id == issued.Control.Project) &&
            issued.Inventory.All(r => !reserved.Borrowed.Any(b => b.Kind == r.Kind && b.Id == r.Id)));
        trial.issuance = issued;
        trial.busy = trial.failed = false;
        return trial;
    }

    internal async ValueTask BeginAsync(string phase, CancellationToken token)
    {
        Enter(phase == "before" ? 0 : 4);
        try
        {
            using var deadline = Deadline(token);
            var facts = await source.BeginAsync(root, phase, deadline.Token);
            Stamp(facts.Stamp);
            Require(phase is "before" or "after" && facts.Phase == phase && facts.Exclusive && facts.StateHeld);
            window = facts; failed = false;
        }
        finally { busy = false; }
    }

    internal WorkloadTransitionConfiguration Configuration(bool after) => after ?
        settled ?? throw new NativeCaseFailureException("observer-unavailable") : Issued.Baseline;
    internal bool Allowed(string identity, WorkloadTransitionProof proof, bool after)
    {
        var config = identity == Issued.Control.Identity ? Issued.TemplateConfigurationB : Configuration(after);
        return config.Attached && config.PublicKey == proof.PublicKey && config.Subject == proof.Subject &&
            config.Issuer == Issued.Issuer && config.Audience == Issued.Audience;
    }

    internal async ValueTask ObserveAsync(string phase, WorkloadTransitionAttempt[] attempts,
        WorkloadTransitionRead[] hostControls, CancellationToken token)
    {
        Enter(phase == "before" ? 1 : 5);
        try
        {
            using var deadline = Deadline(token);
            var facts = await source.ObserveAsync(root, phase, deadline.Token);
            Stamp(facts.Stamp);
            Require(window is not null && facts.Window == window.Stamp.Event && facts.Phase == phase &&
                facts.Complete && facts.Target == Configuration(phase == "after") &&
                facts.Control == Issued.TemplateConfigurationB &&
                WorkloadTransitionContract.Borrowed(facts.Borrowed, reservation!.Borrowed));
            Require(facts.Snapshots.Length == 2);
            foreach (var snapshot in facts.Snapshots)
            {
                Event(snapshot.Event, "storage", facts.Window);
                Require(snapshot.Identity == Issued.Target.Identity ? snapshot.Configuration == facts.Target :
                    snapshot.Identity == Issued.Control.Identity && snapshot.Configuration == facts.Control);
            }
            Require(facts.Snapshots.Select(s => s.Identity).Distinct().Count() == 2 &&
                attempts.Length == 6 && facts.Logins.Length == attempts.Length &&
                facts.Reviews.Length == attempts.Length && facts.Tokens.Length == attempts.Count(a => a.Allowed),
                "effect-mismatch");
            foreach (var login in facts.Logins) Event(login.Event, "ingress", facts.Window);
            foreach (var review in facts.Reviews) Event(review.Event, "reviewer", facts.Window);
            foreach (var issued in facts.Tokens) Event(issued.Event, "issuance", facts.Window);
            foreach (var access in facts.Access) Event(access.Event, "access", facts.Window);
            for (int i = 0; i < attempts.Length; i++)
            {
                var attempt = attempts[i];
                var login = facts.Logins[i];
                Require(requests.Add(login.RequestId) && WorkloadTransitionContract.Text(login.RequestId) &&
                    login.Identity == attempt.Identity && login.Actor == attempt.Identity &&
                    login.Method == "POST" && login.Path == "/api/v1/auth/" + WorkloadTransitionContract.Mechanism(root) + "-auth/login" &&
                    login.ProofHash == attempt.ProofHash && login.Authorized == attempt.Allowed, "effect-mismatch");
                var config = attempt.Identity == Issued.Target.Identity ? facts.Target : facts.Control;
                Require(login.ConfigurationRevision == config.Revision, "effect-mismatch");
                var reviews = facts.Reviews.Where(r => r.LoginRequest == login.RequestId).ToArray();
                Require(reviews.Length == 1, "effect-mismatch");
                var review = reviews[0];
                string mechanism = WorkloadTransitionContract.Mechanism(root);
                string reviewer = mechanism == "kubernetes" ? config.Reviewer ?? "client-proof" : mechanism + "-signature";
                string credentialHash = mechanism != "kubernetes" ? WorkloadTransitionContract.Hash(config.PublicKey) :
                    config.Reviewer == Issued.ReviewerA ? Issued.ReviewerHashA :
                    config.Reviewer == Issued.ReviewerB ? Issued.ReviewerHashB : attempt.ProofHash;
                Require(review.Identity == attempt.Identity && review.ConfigurationRevision == config.Revision &&
                    review.ProofHash == attempt.ProofHash && review.Reviewer == reviewer &&
                    review.CredentialHash == credentialHash && review.Allowed == attempt.Allowed, "effect-mismatch");
                var tokens = facts.Tokens.Where(t => t.LoginRequest == login.RequestId).ToArray();
                Require(tokens.Length == (attempt.Allowed ? 1 : 0), "effect-mismatch");
                if (attempt.Allowed)
                {
                    var issued = tokens[0];
                    Require(tokenHashes.Add(issued.TokenHash) && WorkloadTransitionContract.Text(issued.TokenId) &&
                        tokenIds.Add(issued.TokenId) && issued.TokenHash == attempt.TokenHash &&
                        issued.Identity == attempt.Identity && issued.ReviewEvent == review.Event.Id &&
                        issued.ConfigurationRevision == config.Revision && attempt.Reads.Length == 2, "effect-mismatch");
                }
                else Require(attempt.TokenHash is null && attempt.Reads.Length == 0, "effect-mismatch");
            }
            var expectedReads = attempts.SelectMany(a => a.Reads).Concat(hostControls).ToArray();
            Require(hostControls.Length == 3 &&
                hostControls[0].Identity == root.Authorities.Runtime && !hostControls[0].Allowed &&
                hostControls[1].Identity == root.Authorities.Denied && !hostControls[1].Allowed &&
                hostControls[2].Identity == root.Authorities.Observer && hostControls[2].Allowed &&
                facts.Access.Length == expectedReads.Length, "effect-mismatch");
            for (int i = 0; i < expectedReads.Length; i++)
            {
                var actual = facts.Access[i]; var expected = expectedReads[i];
                Require(requests.Add(actual.RequestId) && WorkloadTransitionContract.Text(actual.RequestId) &&
                    actual.TokenHash == expected.TokenHash && actual.Identity == expected.Identity &&
                    actual.Project == expected.Project && actual.Key == expected.Key && actual.Allowed == expected.Allowed,
                    "effect-mismatch");
            }
            failed = false;
        }
        finally { busy = false; }
    }

    internal async ValueTask ArmAsync(CancellationToken token)
    {
        Enter(2);
        try
        {
            using var deadline = Deadline(token);
            var facts = await source.ArmAsync(root, deadline.Token);
            Stamp(facts.Stamp);
            Require(facts.Exclusive && facts.MaximumRequests == 1 && facts.Intent == Intent);
            arm = facts; failed = false;
        }
        finally { busy = false; }
    }

    internal async ValueTask SettleAsync(WorkloadTransitionReceipt receipt, CancellationToken token)
    {
        Enter(3);
        try
        {
            using var deadline = Deadline(token);
            var facts = await source.SettleAsync(root, deadline.Token);
            Stamp(facts.Stamp);
            bool presend = root.Boundary == "cancellation-boundary", denied = root.Boundary == "denied-authority";
            bool lost = root.Boundary == "lost-response-no-replay";
            Require(arm is not null && facts.Arm == arm.Stamp.Event && facts.Terminal && facts.Exclusive &&
                facts.NoReplay && facts.PendingWork == 0 && facts.Requests.Length == (presend ? 0 : 1));
            Require(receipt.Evidence == (presend ? DispatchEvidence.NotDispatched : lost ? DispatchEvidence.PossiblyDispatched :
                denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied) &&
                receipt.Cancelled == (presend || lost) && (receipt.Cancelled ? receipt.Status is null :
                    receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
            foreach (var original in facts.Requests)
            {
                Event(original.Event, "ingress", facts.Arm);
                Require(requests.Add(original.RequestId) && WorkloadTransitionContract.Text(original.RequestId) &&
                    original.Actor == root.Authorities.Actor(root.Boundary) && original.Identity == Issued.Target.Identity &&
                    original.Method == Intent.Method && original.Path == Intent.Path && original.Intent == Intent &&
                    original.Authorized == !denied && WorkloadTransitionContract.Text(original.SdkIntentHash) &&
                    original.SdkIntentHash == receipt.IntentHash, "effect-mismatch");
            }
            Require(facts.Commits.Length <= 1 && (!(presend || denied) || facts.Commits.Length == 0), "effect-mismatch");
            var current = Issued.Baseline;
            foreach (var commit in facts.Commits)
            {
                Event(commit.Event, "storage", facts.Arm);
                Require(commit.CauseRequest == facts.Requests.Single().RequestId &&
                    commit.Identity == Issued.Target.Identity && commit.PreviousRevision == current.Revision &&
                    WorkloadTransitionContract.Text(commit.Configuration.Revision) &&
                    commit.Configuration.Revision != current.Revision, "effect-mismatch");
                current = commit.Configuration;
            }
            // Revision changes without all requested semantic effects are Partial.
            // A silent ignored original is NonApplied, even if the SDK returned 200.
            Outcome = facts.Commits.Length == 0 ? WorkloadTransitionOutcome.NonApplied :
                WorkloadTransitionContract.SemanticEqual(current, WorkloadTransitionContract.Expected(root, Issued)) ?
                    WorkloadTransitionOutcome.Applied : WorkloadTransitionOutcome.Partial;
            Require(lost || (presend || denied ? Outcome == WorkloadTransitionOutcome.NonApplied :
                Outcome == WorkloadTransitionOutcome.Applied), "effect-mismatch");
            settled = current; failed = false;
        }
        finally { busy = false; }
    }

    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        closed = true;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        try
        {
            var facts = await source.CloseAsync(root, deadline.Token);
            Stamp(facts.Stamp);
            Require(facts.CreationFence && facts.DispatchFence && facts.CompleteInventory &&
                facts.PendingWork == 0 && facts.Registrations == 0 && Inventory(facts.Enrolled) &&
                facts.Remaining.Length == 0 && (issuance is null || issuance.Inventory.All(facts.Enrolled.Contains)) &&
                tokenIds.All(id => facts.Enrolled.Any(r => r.Kind == "token" && r.Id == id)) &&
                (reservation is null || WorkloadTransitionContract.Borrowed(facts.Borrowed, reservation.Borrowed)),
                "cleanup-incomplete");
        }
        catch (Exception) { throw new NativeCaseFailureException("cleanup-incomplete"); }
    }
    private bool Inventory(WorkloadTransitionResource[] rows) =>
        rows.All(r => r.Root == root.Id && r.Nonce == root.Nonce && WorkloadTransitionContract.Text(r.Id) &&
            r.Kind is "identity" or "project" or "secret" or "template" or "proof" or "reviewer" or "issuer-key" or "issuer-work" or "token") &&
        rows.Select(r => (r.Kind, r.Id)).Distinct().Count() == rows.Length;
    private void Stamp(WorkloadTransitionStamp stamp)
    {
        Require(WorkloadTransitionContract.SameRoot(stamp.Root, root) && WorkloadTransitionContract.Text(stamp.Registration) &&
            (registration is null || registration == stamp.Registration) && events.Add("source/" + stamp.Event) &&
            WorkloadTransitionContract.Text(stamp.Event) && stamp.Sequence > sequence && stamp.At != default &&
            stamp.At.Offset == TimeSpan.Zero && stamp.At >= at);
        registration ??= stamp.Registration; sequence = stamp.Sequence; at = stamp.At;
    }
    private void Event(WorkloadTransitionEvent e, string journal, string selectedWindow)
    {
        var profile = root.Profile.Journals.Single(j => j.Kind == journal);
        Require(e.Root == root.Id && e.Nonce == root.Nonce && e.Deployment == root.Profile.Deployment &&
            e.Epoch == root.Profile.Epoch && e.ProviderRevision == root.Profile.Revision &&
            e.Journal == journal && e.Writer == profile.Writer && e.Schema == profile.Schema &&
            e.Window == selectedWindow && WorkloadTransitionContract.Text(e.Id) && events.Add(journal + "/" + e.Id) &&
            e.Sequence > journalSequences.GetValueOrDefault(journal));
        journalSequences[journal] = e.Sequence;
    }
    private void Enter(int expected)
    {
        Require(!busy && !failed && !closed && stage == expected);
        busy = failed = true; stage++;
    }
    private CancellationTokenSource Deadline(CancellationToken token)
    {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(seconds));
        return deadline;
    }
    private static void Require(bool value, string reason = "observer-unavailable") =>
        WorkloadTransitionContract.Require(value, reason);
    public override string ToString() => "[WorkloadTransitionTrial]";
}
