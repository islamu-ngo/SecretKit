using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class AuditPermissionTrial : IAsyncDisposable
{
    private readonly IAuditPermissionSource source;
    private readonly AuditPermissionRoot root;
    private readonly AuditPermissionVerifier verifier;
    private readonly AuditPermissionOwnership ownership;
    private readonly AuditPermissionPublicationProof publication;
    private AuditPermissionIssued? issued;
    private AuditPermissionCredential[] credentials = [];
    private AuditPermissionPolicy[] policies = [];
    private AuditPermissionState[] census = [];
    private int stage, reads, seedCount;
    private string revision = "policy-1";
    private bool closed, failed, busy;
    private AuditPermissionReceipt? activation;
    internal AuditPermissionPlan Plan { get; }
    internal AuditPermissionIssued Issued => issued ?? throw new NativeCaseFailureException("observer-unavailable");
    internal AuditPermissionReceipt? Original { get; private set; }
    internal AuditPermissionOutcome Outcome { get; private set; }
    private AuditPermissionTrial(IAuditPermissionSource source, AuditPermissionRoot root)
    { this.source = source; this.root = root; Plan = new(root); verifier = new(root); ownership = new(root, Plan); publication = new(root, Plan); }
    internal static async ValueTask<AuditPermissionTrial> OpenAsync(IAuditPermissionSource source, AuditPermissionRoot root,
        SecretMaterial capability, Action<AuditPermissionTrial> retain, CancellationToken token)
    {
        AuditPermissionContract.Require(source.Identity == root.Source && source.Kind == root.Kind && Enum.IsDefined(root.Kind) &&
            AuditPermissionContract.Operations.Contains(root.Operation) && root.ScopeProfile == AuditPermissionContract.Scope(root.Operation) &&
            root.ActorKind == AuditPermissionContract.ActorKind(root.Operation) && AuditPermissionContract.Gate(root.Action) is null &&
            root.Variant == AuditPermissionContract.Variant(root.Action) && AuditPermissionContract.Boundaries.Contains(root.Boundary) &&
            root.Authorities.All.Distinct().Count() == 5 && root.Authorities.All.All(MemberPermissionContract.Text) &&
            !root.Authorities.All.Contains(root.Source) && root.Profile.Pins.All(p => p.Writer != root.Source && !root.Authorities.All.Contains(p.Writer)) &&
            root.Until > root.From && root.Until - root.From <= TimeSpan.FromMinutes(10) && root.RetainUntil > root.Until &&
            root.RetainUntil - root.Until <= TimeSpan.FromDays(30) &&
            new[] { root.Id, root.Nonce, root.Origin, root.Organization, root.Scope }.All(MemberPermissionContract.Text), "missing-input");
        var trial = new AuditPermissionTrial(source, root);
        retain(trial); // Retain root recovery BEFORE either enrollment or Open can lose its reply.
        _ = await trial.StepAsync(AuditPermissionStep.Reserve, capability, token);
        var packet = await trial.StepAsync(AuditPermissionStep.Open, null, token);
        var v = trial.Issued; var p = trial.Plan;
        trial.Require(v.Actors.Length == (root.ScopeProfile == AuditPermissionScope.Organization ? 4 : 3));
        trial.credentials = packet.Issuer.Payload.Content.Credentials;
        for (int i = 0; i < v.Actors.Length; i++)
        {
            var actor = v.Actors[i];
            trial.Require(actor.Principal == v.Id(p.ActorKey(i)) && actor.Kind == p.ActorKind(i) && actor.Organization == v.Id(p.ActorScope(i)) &&
                actor.Owned == !p.ActorKey(i).StartsWith("@", StringComparison.Ordinal) &&
                (actor.Owned ? actor.Credential.Length > 0 && AuditPermissionContract.RawHash(actor.Credential) == actor.CredentialHash &&
                    actor.CredentialId == v.Id("actor-credential-" + i) : actor.Credential.Length == 0 && root.Authorities.All.Contains(actor.Principal)) &&
                trial.credentials.Contains(new(actor.CredentialId, actor.Principal, actor.Kind, actor.Organization, actor.CredentialHash, actor.Owned)));
        }
        foreach (var credential in trial.credentials.Where(c => c.Owned))
            trial.Require(v.Bindings.Any(b => b.CanonicalId == credential.Id && b.Kind == "credential" && b.Scope == credential.Organization) &&
                v.Bindings.Any(b => b.CanonicalId == credential.Principal && b.Kind == (credential.Kind == MemberPermissionActorKind.User ? "user" : "machine")));
        trial.Require(trial.credentials.Count(c => c.Owned) == packet.Owner.Payload.Content.Remaining.Count(r => v.Bindings.Any(b => b.Intent == r.Intent && b.Kind == "credential")));
        trial.policies = packet.Policy.Payload.Content.Inventory;
        trial.Require(trial.policies.Length == (AuditPermissionContract.Create(root.Operation) ? 0 : 1) && trial.policies.All(p => trial.PolicyMatches(p, false)) &&
            packet.Storage.Payload.Content.Seeds.Length == 0 && packet.Storage.Payload.Content.Inventory.Length == 0);
        trial.CheckJoins(packet, false);
        return trial;
    }
    internal AuditPermissionRow[] Rows(bool after) => Plan.WindowRows(after, Outcome);
    internal async ValueTask BeginSeedsAsync(bool after, CancellationToken token)
    {
        var packet = await StepAsync(after ? AuditPermissionStep.SeedAfter : AuditPermissionStep.SeedBefore, null, token);
        bool activate = after && Outcome == AuditPermissionOutcome.Applied && (AuditPermissionContract.Template(root.Operation) ||
            root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal) || root.Operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal));
        if (activate)
        {
            var entries = packet.Ingress.Payload.Content.Where(e => e.Phase == "activation").ToArray();
            var commits = packet.Policy.Payload.Content.Commits.Where(c => entries.Any(e => e.Request == c.Request)).ToArray();
            Require(activation is not null && entries.Length == 1 && commits.Length == 1 && entries[0].Actor == root.Authorities.Setup &&
                entries[0].Kind == MemberPermissionActorKind.Machine && entries[0].Authorized && entries[0].IntentHash == activation.IntentHash &&
                commits[0].PreviousRevision == revision && commits[0].Policy.Revision == revision && PolicyMatches(commits[0].Policy, true), "effect-mismatch");
            policies = AuditPermissionContract.Template(root.Operation) ? [.. policies, commits[0].Policy] : [commits[0].Policy];
        }
        CheckPolicies(packet); CheckJoins(packet, after);
    }
    internal async ValueTask PublishedAsync(bool after, AuditPermissionSeedReceipt[] receipts, CancellationToken token)
    {
        Require(receipts.Select(r => r.Seed).SequenceEqual(Plan.WindowSeeds(after, Outcome)), "effect-mismatch");
        var packet = await StepAsync(after ? AuditPermissionStep.PublishedAfter : AuditPermissionStep.PublishedBefore, null, token);
        var seeds = packet.Storage.Payload.Content.Seeds;
        Require(seeds.Length == seedCount + receipts.Length, "effect-mismatch");
        foreach (var r in receipts)
        {
            var commit = seeds.SingleOrDefault(s => s.Seed == r.Seed.Key);
            Require(commit is not null && r.Target == commit.Target && r.Receipt.IntentHash == commit.InputHash &&
                r.Receipt.Evidence == DispatchEvidence.Applied && r.Receipt.Native.Evidence == r.Receipt.Evidence &&
                r.Receipt.Status == SecretStatus.Success && !r.Receipt.Cancelled, "effect-mismatch");
        }
        seedCount = seeds.Length; census = packet.Storage.Payload.Content.Inventory.ToArray(); CheckPolicies(packet);
    }
    internal async ValueTask BeginAsync(bool after, CancellationToken token)
    { var packet = await StepAsync(after ? AuditPermissionStep.After : AuditPermissionStep.Before, null, token); CheckCensus(packet); }
    internal async ValueTask ArmAsync(CancellationToken token)
    { var packet = await StepAsync(AuditPermissionStep.Arm, null, token); CheckCensus(packet); CheckPolicies(packet); }
    internal async ValueTask SettleAsync(AuditPermissionReceipt receipt, CancellationToken token)
    {
        Require(Original is null && receipt.Native.Evidence == receipt.Evidence, "effect-mismatch"); Original = receipt;
        var packet = await StepAsync(AuditPermissionStep.Settle, null, token);
        var ingress = packet.Ingress.Payload.Content.Where(e => e.Phase == "original").ToArray();
        var commits = packet.Policy.Payload.Content.Commits;
        bool cancel = root.Boundary == "cancellation-boundary", denied = root.Boundary == "denied-authority", lost = root.Boundary == "lost-response-no-replay";
        Require(ingress.Length == (cancel ? 0 : 1) && commits.Length <= 1 && (!(cancel || denied) || commits.Length == 0) &&
            receipt.Evidence == (cancel ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected : lost ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied) &&
            receipt.Cancelled == (cancel || lost) && (receipt.Cancelled ? receipt.Status is null : receipt.Status == (denied ? SecretStatus.Denied : SecretStatus.Success)), "effect-mismatch");
        foreach (var e in ingress)
            Require(e.Actor == (denied ? root.Authorities.Denied : root.Authorities.Administrative) && e.Kind == MemberPermissionActorKind.Machine &&
                e.Organization == root.Organization && e.Authorized == !denied && e.IntentHash == receipt.IntentHash &&
                e.Path == AuditPermissionEffects.OriginalPath(root, Plan, Issued) && e.Method == (AuditPermissionContract.Create(root.Operation) ? "POST" : "PATCH"), "effect-mismatch");
        Outcome = AuditPermissionOutcome.NonApplied;
        if (commits.Length == 1)
        {
            var c = commits[0];
            Require(c.Request == ingress.Single().Request && c.PreviousRevision == revision && c.Policy.Revision != revision && c.Policy.Resource == Issued.Id(Plan.PolicyKey), "effect-mismatch");
            if (AuditPermissionContract.Create(root.Operation)) Require(Issued.Bindings.Single(b => b.Intent == Plan.PolicyKey).Request == c.Request, "effect-mismatch");
            revision = c.Policy.Revision; policies = [c.Policy];
            Outcome = PolicyMatches(c.Policy, true) ? AuditPermissionOutcome.Applied : AuditPermissionOutcome.Partial;
        }
        Require(lost || (cancel || denied ? Outcome == AuditPermissionOutcome.NonApplied : Outcome == AuditPermissionOutcome.Applied), "effect-mismatch");
        CheckCensus(packet); CheckPolicies(packet); Require(receipt.Native.Evidence == receipt.Evidence, "effect-mismatch");
    }
    internal void Activated(AuditPermissionReceipt receipt)
    {
        Require(stage == (int)AuditPermissionStep.SeedAfter && !failed && activation is null && receipt.Evidence == DispatchEvidence.Applied &&
            receipt.Native.Evidence == receipt.Evidence && receipt.Status == SecretStatus.Success && !receipt.Cancelled, "effect-mismatch"); activation = receipt;
    }
    internal async ValueTask ObserveAsync(bool after, AuditPermissionAttempt[] attempts, CancellationToken token)
    {
        var packet = await StepAsync(after ? AuditPermissionStep.ObserveAfter : AuditPermissionStep.ObserveBefore, null, token);
        var decisions = packet.Access.Payload.Content.Skip(reads).ToArray();
        Require(attempts.Select(a => a.Row).SequenceEqual(Rows(after)) && decisions.Length == attempts.Sum(a => a.Pages.Length), "effect-mismatch");
        int decisionIndex = 0;
        foreach (var attempt in attempts)
        {
            var row = attempt.Row; var actor = Issued.Actors[row.Actor];
            bool allowed = AuditPermissionContract.Allowed(root, row, after, Outcome);
            var expected = census.Where(s => s.Organization == Issued.Id(row.Organization) &&
                (row.Project.Length == 0 || s.Project == Issued.Id(row.Project))).Select(s => new AuditPermissionView(s.Id, s.Project,
                    s.Kind == MemberPermissionActorKind.Machine ? "identity" : "user", s.EventType, s.EventClass, s.At)).ToArray();
            Require(attempt.CredentialHash == actor.CredentialHash && attempt.Pages.Length is > 0 and <= AuditPermissionClient.MaximumPages, "effect-mismatch");
            int offset = 0; var returned = new HashSet<string>();
            foreach (var page in attempt.Pages)
            {
                var d = decisions[decisionIndex++]; var e = packet.Ingress.Payload.Content.SingleOrDefault(e => e.Request == d.Request);
                using var query = AuditPermissionClient.Request(root, Plan, Issued, row, offset);
                Require(page.Offset == offset && page.Limit == AuditPermissionClient.PageSize && page.QueryHash == query.Target.SecondaryId &&
                    page.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) &&
                    d.Actor == actor.Principal && d.Kind == actor.Kind && d.CredentialId == actor.CredentialId && d.CredentialHash == actor.CredentialHash &&
                    d.Organization == Issued.Id(row.Organization) && d.Project == Issued.Id(row.Project) && d.Revision == revision && d.QueryHash == page.QueryHash &&
                    d.Offset == offset && d.Limit == page.Limit && d.Allowed == allowed && d.Returned.SequenceEqual(page.Values.Select(v => v.Id)) &&
                    e is not null && e.Phase == "read" && e.Actor == actor.Principal && e.Kind == actor.Kind && e.CredentialHash == actor.CredentialHash &&
                    e.Organization == actor.Organization && e.Method == "GET" && e.IntentHash == page.QueryHash && e.Authorized == allowed &&
                    e.Path.StartsWith("/api/v1/organization/audit-logs?", StringComparison.Ordinal) &&
                    e.IntentHash == AuditPermissionContract.Hash(new { query = e.Path["/api/v1/organization/audit-logs?".Length..], classArray = true, typeArray = true }), "effect-mismatch");
                int count = allowed ? Math.Min(page.Limit, expected.Length - offset) : 0;
                Require(page.Values.Length == count && page.Values.All(v => expected.Contains(v) && returned.Add(v.Id)) &&
                    page.Complete == (!allowed || count < page.Limit), "effect-mismatch");
                offset += page.Values.Length;
            }
            Require(attempt.Pages[^1].Complete && attempt.Pages.Take(attempt.Pages.Length - 1).All(p => !p.Complete) &&
                (allowed ? offset == expected.Length && returned.Count == expected.Length : attempt.Pages.Length == 1 && offset == 0), "effect-mismatch");
        }
        reads += decisions.Length; CheckCensus(packet); CheckPolicies(packet); CheckJoins(packet, after);
        if (after) Require(Original is not null && Original.Native.Evidence == Original.Evidence, "effect-mismatch");
    }
    private bool PolicyMatches(AuditPermissionPolicy p, bool granted) =>
        p.Actor == Issued.Actors[0].Principal && p.Kind == root.ActorKind && p.Organization == root.Organization &&
        p.Project == (root.ScopeProfile == AuditPermissionScope.Organization ? "" : p.Resource == Issued.Id(AuditPermissionPlan.CopiedRole) ? Issued.Id(AuditPermissionPlan.CopyProject) : Issued.Id(AuditPermissionPlan.Project)) &&
        p.Subject == "audit-logs" && p.Actions.SequenceEqual(granted ? new[] { "read" } : []) && p.Names.Length == 0 && p.Role == Plan.Slug &&
        p.Configuration == (AuditPermissionContract.Template(root.Operation) ? Plan.Configuration : "");
    private void CheckCensus(AuditPermissionPacket p) => Require(p.Storage.Payload.Content.Inventory.SequenceEqual(census), "effect-mismatch");
    private void CheckPolicies(AuditPermissionPacket p) => Require(AuditPermissionContract.Hash(p.Policy.Payload.Content.Inventory.OrderBy(p => p.Resource)) ==
        AuditPermissionContract.Hash(policies.OrderBy(p => p.Resource)), "effect-mismatch");
    private void CheckJoins(AuditPermissionPacket packet, bool after)
    {
        bool copy = after && AuditPermissionContract.Template(root.Operation) && Outcome == AuditPermissionOutcome.Applied;
        bool assigned = !AuditPermissionContract.Create(root.Operation) || after && Outcome == AuditPermissionOutcome.Applied && !copy;
        var expected = Issued.Actors.Select((actor, i) => new AuditPermissionJoin(actor.Principal,
            actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization,
            root.ScopeProfile == AuditPermissionScope.Project ? Issued.Id(AuditPermissionPlan.Project) : "", Issued.Id(Plan.ActorMembership(i)),
            i == 0 && assigned, i == 0 && assigned ? Issued.Id(Plan.PolicyKey) : "", i == 0 && assigned ? Plan.Slug : "no-access", true, "accepted")).ToList();
        if (copy) expected.Add(new(Issued.Actors[0].Principal, "user", root.Organization, Issued.Id(AuditPermissionPlan.CopyProject),
            Issued.Id(Plan.ActorMembership(0, true)), true, Issued.Id(AuditPermissionPlan.CopiedRole), Plan.Slug, true, "accepted"));
        var actual = packet.Membership.Payload.Content;
        Require(actual.Length == expected.Count && actual.Distinct().Count() == actual.Length && expected.All(actual.Contains), "effect-mismatch");
    }
    private async ValueTask<AuditPermissionPacket> StepAsync(AuditPermissionStep step, SecretMaterial? capability, CancellationToken token)
    {
        Require(!closed && !failed && !busy && stage == (int)step); busy = failed = true; stage++;
        try
        {
            var packet = await source.StepAsync(root, step, capability, token);
            if (step == AuditPermissionStep.Open) issued = new(packet.Owner.Payload.Content.Actors, []);
            verifier.Check(packet, step); ownership.Check(packet, step);
            publication.Check(packet, step is not (AuditPermissionStep.SeedBefore or AuditPermissionStep.SeedAfter));
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
            if (step is not (AuditPermissionStep.Reserve or AuditPermissionStep.Open)) Require(packet.Issuer.Payload.Content.Credentials.SequenceEqual(credentials));
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
            var packet = await source.StepAsync(root, AuditPermissionStep.Close, null, deadline.Token);
            verifier.Check(packet, AuditPermissionStep.Close); ownership.Check(packet, AuditPermissionStep.Close); publication.Check(packet, true);
        }
        catch (NativeCaseFailureException) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { issued?.Erase(); verifier.Dispose(); }
    }
    private void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) failed = true; AuditPermissionContract.Require(condition, code); }
}
