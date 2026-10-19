using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class OrganizationUserTrial(IOrganizationUserSource source, OrganizationUserRoot root,
    int seconds) : IAsyncDisposable
{
    private OrganizationUserReservation? reservation;
    private OrganizationUserIssuance? issuance;
    private OrganizationUserWindow? window;
    private OrganizationUserArm? arm;
    private OrganizationUserFence? fence;
    private readonly HashSet<string> events = [];
    private string? registration;
    private long sequence = -1;
    private DateTimeOffset at;
    private int stage;
    private bool busy, failed, closed;
    internal OrganizationUserIssuance Issued => issuance ?? throw new NativeCaseFailureException("observer-unavailable");
    internal OrganizationUserIntent Intent => OrganizationUserContract.Intent(root, Issued);
    internal OrganizationUserFence Fence => fence ?? throw new NativeCaseFailureException("observer-unavailable");

    internal static async ValueTask<OrganizationUserTrial> OpenAsync(IOrganizationUserSource source,
        OrganizationUserRoot root, SecretMaterial capability, int seconds, Action<OrganizationUserTrial> retain,
        CancellationToken token)
    {
        OrganizationUserContract.Require(seconds is >= 1 and <= 300 && root.Source == source.Kind &&
            root.SourceIdentity == source.Identity && Enum.IsDefined(root.Source) &&
            new[] { root.Id, root.Nonce, root.OrganizationId, root.Scope, root.ProviderRevision,
                root.Deployment, root.Epoch, root.SourceIdentity }.All(OrganizationUserContract.Text) &&
            root.Authorities.All.All(OrganizationUserContract.Text) && root.Authorities.All.Distinct().Count() == 5 &&
            !root.Authorities.All.Contains(root.SourceIdentity) &&
            OrganizationUserContract.Owns(root.Operation) && !OrganizationUserContract.Gated(root.Variant) &&
            OrganizationUserContract.Cases.Contains(root.Case) &&
            !(OrganizationUserContract.List(root) && root.Case == "lost-response-no-replay"), "missing-input");
        var trial = new OrganizationUserTrial(source, root, seconds);
        retain(trial); // PRECEDES Reserve and Open; Close needs no returned IDs.
        trial.busy = trial.failed = true;
        using var deadline = trial.Deadline(token);
        var reserved = await source.ReserveAsync(root, capability, deadline.Token);
        trial.Stamp(reserved.Stamp);
        OrganizationUserContract.Require(reserved.CollisionChecked && reserved.ExclusiveRoot &&
            reserved.TransactionalIssuanceInventory && reserved.Complete && reserved.Owned.Length == 0 &&
            OrganizationUserContract.BorrowedEqual(reserved.Borrowed, reserved.Borrowed));
        trial.reservation = reserved;
        OrganizationUserIssuance? issued = null;
        try
        {
            issued = await source.OpenAsync(root, deadline.Token);
            trial.Stamp(issued.Stamp);
            OrganizationUserContract.Require(issued.RootReservedBeforeIssuance && issued.Complete &&
                issued.IndependentCredentialUserJoin &&
                new[] { issued.AllowedRole, issued.DeniedRole, issued.AllowedRoleId, issued.DeniedRoleId,
                    issued.CanaryId, issued.CanaryName }.All(OrganizationUserContract.Text) &&
                issued.AllowedRole != issued.DeniedRole && issued.AllowedRoleId != issued.DeniedRoleId &&
                trial.Inventory(issued.Inventory) &&
                issued.Principals.Length == OrganizationUserContract.Targets(root) + 1 &&
                issued.Principals.Select(p => p.Slot).Order().SequenceEqual(
                    Enumerable.Range(0, issued.Principals.Length)) &&
                issued.Principals.All(p => new[] { p.UserId, p.Username, p.MembershipId, p.CredentialId }
                    .All(OrganizationUserContract.Text) && !root.Authorities.All.Contains(p.UserId) &&
                    p.Credential.Length is >= 16 and <= 16384 &&
                    p.CredentialHash == OrganizationUserContract.Hash(p.Credential)) &&
                issued.Principals.Select(p => p.UserId).Distinct().Count() == issued.Principals.Length &&
                issued.Principals.Select(p => p.MembershipId).Distinct().Count() == issued.Principals.Length &&
                issued.Principals.Select(p => p.CredentialId).Distinct().Count() == issued.Principals.Length &&
                issued.Principals.Select(p => p.CredentialHash).Distinct().Count() == issued.Principals.Length &&
                issued.Principals.Select(p => p.Username).Distinct().Count() == issued.Principals.Length);
            var expected = issued.Principals.SelectMany(p => new[]
            {
                new OrganizationUserResource(root.Id, root.Nonce, "user", p.UserId),
                new OrganizationUserResource(root.Id, root.Nonce, "membership", p.MembershipId),
                new OrganizationUserResource(root.Id, root.Nonce, "credential", p.CredentialId)
            }).Concat(new[]
            {
                new OrganizationUserResource(root.Id, root.Nonce, "group", issued.CanaryId),
                new OrganizationUserResource(root.Id, root.Nonce, "role", issued.AllowedRoleId),
                new OrganizationUserResource(root.Id, root.Nonce, "role", issued.DeniedRoleId)
            }).ToArray();
            OrganizationUserContract.Require(issued.Inventory.Length == expected.Length &&
                expected.All(issued.Inventory.Contains));
            trial.issuance = issued;
            trial.busy = trial.failed = false;
            return trial;
        }
        catch { issued?.Erase(); throw; }
    }

    internal async ValueTask BeginAsync(string phase, CancellationToken token)
    {
        Enter(phase == "before" ? 0 : 4);
        try
        {
            OrganizationUserContract.Require(phase is "before" or "after");
            using var deadline = Deadline(token);
            var facts = await source.BeginAsync(root, phase, deadline.Token);
            Stamp(facts.Stamp);
            OrganizationUserContract.Require(facts.Phase == phase && facts.Exclusive && facts.StateHeld);
            window = facts; failed = false;
        }
        finally { busy = false; }
    }

    internal OrganizationUserState[] Expected(bool after)
    {
        string[] commits = after ? Fence.CommittedMembershipIds : [];
        var intent = Intent;
        return Issued.Principals.OrderBy(p => p.Slot).Select(p =>
        {
            bool wrong = p.Slot == OrganizationUserContract.Targets(root);
            bool changed = !wrong && commits.Contains(p.MembershipId);
            if (changed && intent.Method == "DELETE") return null;
            return new OrganizationUserState(p.UserId, p.MembershipId, p.Username,
                changed && intent.Role is not null ? intent.Role :
                !wrong && OrganizationUserContract.BaselineGranted(root) ? Issued.AllowedRole : Issued.DeniedRole,
                changed && intent.Active is not null ? intent.Active.Value :
                wrong || OrganizationUserContract.BaselineActive(root), "accepted");
        }).Where(s => s is not null).Cast<OrganizationUserState>().ToArray();
    }
    internal bool Allowed(int slot, bool after) => Expected(after).Any(s =>
        s.UserId == Issued.Principals.Single(p => p.Slot == slot).UserId &&
        s.Active && s.Role == Issued.AllowedRole);

    internal async ValueTask ObserveAsync(string phase, OrganizationUserAccess[] expectedAccess, CancellationToken token)
    {
        Enter(phase == "before" ? 1 : 5);
        try
        {
            using var deadline = Deadline(token);
            var facts = await source.ObserveAsync(root, phase, deadline.Token);
            Stamp(facts.Stamp);
            OrganizationUserContract.Require(window is not null && facts.Phase == phase &&
                facts.WindowEvent == window.Stamp.Event && facts.Complete &&
                facts.IndependentMembershipStorage && facts.IndependentAuthenticatedAccess &&
                facts.CredentialIssuanceUnchanged);
            var expected = Expected(phase == "after");
            OrganizationUserContract.Require(facts.Memberships.Length == expected.Length &&
                facts.Memberships.Select(m => m.MembershipId).Distinct().Count() == expected.Length &&
                expected.All(facts.Memberships.Contains) &&
                OrganizationUserContract.BorrowedEqual(facts.Borrowed, reservation!.Borrowed) &&
                facts.Access.Length == expectedAccess.Length &&
                facts.Access.Select(a => a.RequestId).Distinct().Count() == facts.Access.Length &&
                facts.Access.All(a => OrganizationUserContract.Text(a.RequestId)) &&
                facts.Access.Zip(expectedAccess).All(pair =>
                    pair.First with { RequestId = "" } == pair.Second with { RequestId = "" }), "effect-mismatch");
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
            var facts = await source.ArmAsync(root, Intent, deadline.Token);
            Stamp(facts.Stamp);
            OrganizationUserContract.Require(facts.ExactIntent && facts.ExclusiveIngress &&
                facts.MaximumOriginalRequests == 1);
            arm = facts; failed = false;
        }
        finally { busy = false; }
    }

    internal async ValueTask SettleAsync(OrganizationUserReceipt receipt, CancellationToken token)
    {
        Enter(3);
        try
        {
            using var deadline = Deadline(token);
            var facts = await source.SettleAsync(root, receipt, deadline.Token);
            Stamp(facts.Stamp);
            OrganizationUserContract.Require(arm is not null && facts.ArmEvent == arm.Stamp.Event &&
                facts.Receipt == receipt && facts.ExactAuthenticatedOriginal && facts.Terminal &&
                facts.LateDispatchExcluded && facts.NoReplay && facts.PendingWork == 0 &&
                facts.RequestIds.Length <= 1 && facts.RequestIds.All(OrganizationUserContract.Text) &&
                facts.CommittedMembershipIds.Distinct().Count() == facts.CommittedMembershipIds.Length &&
                facts.CommittedMembershipIds.All(Intent.MembershipIds.Contains) && Enum.IsDefined(facts.Outcome));
            int requests = root.Case == "cancellation-boundary" ? 0 : 1;
            bool mutation = !OrganizationUserContract.List(root);
            OrganizationUserContract.Require(facts.RequestIds.Length == requests &&
                (mutation ? receipt.Evidence == (root.Case switch
                {
                    "cancellation-boundary" => DispatchEvidence.NotDispatched,
                    "denied-authority" => DispatchEvidence.Rejected,
                    "lost-response-no-replay" => DispatchEvidence.PossiblyDispatched,
                    _ => DispatchEvidence.Applied
                }) : receipt.Evidence == DispatchEvidence.NotDispatched) &&
                receipt.Cancelled == (root.Case is "cancellation-boundary" or "lost-response-no-replay") &&
                (receipt.Cancelled ? receipt.Status is null : receipt.Status ==
                    (root.Case == "denied-authority" ? SecretStatus.Denied : SecretStatus.Success)) &&
                facts.Outcome == (facts.CommittedMembershipIds.Length == 0 ? OrganizationUserOutcome.NonApplied :
                    facts.CommittedMembershipIds.Length == Intent.MembershipIds.Length ? OrganizationUserOutcome.Applied :
                        OrganizationUserOutcome.Partial) &&
                (root.Case is not ("denied-authority" or "cancellation-boundary") ||
                    facts.Outcome == OrganizationUserOutcome.NonApplied) &&
                (!mutation || root.Case is not ("selected-contract" or "independent-effect") ||
                    facts.Outcome == OrganizationUserOutcome.Applied), "effect-mismatch");
            fence = facts; failed = false;
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
            OrganizationUserContract.Require(facts.Root == root && facts.SourceIdentity == source.Identity &&
                Clock(facts.Clock) && facts.CompleteIssuanceInventory && facts.CreationFence &&
                facts.DispatchFence && facts.OriginalTerminal && facts.PrivateCopiesReleased &&
                facts.PendingIssuers == 0 && facts.PendingDispatches == 0 && facts.Registrations == 0 &&
                Inventory(facts.Issued) && facts.Remaining.Length == 0 &&
                (issuance is null || issuance.Inventory.All(facts.Issued.Contains)) &&
                facts.BorrowedPreserved && (reservation is null ||
                    OrganizationUserContract.BorrowedEqual(facts.Borrowed, reservation.Borrowed)), "cleanup-incomplete");
        }
        catch (Exception) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { issuance?.Erase(); }
    }
    private bool Inventory(OrganizationUserResource[] inventory) =>
        inventory.All(r => r.RootId == root.Id && r.Nonce == root.Nonce &&
            r.Kind is "user" or "membership" or "credential" or "group" or "role" &&
            OrganizationUserContract.Text(r.Id)) &&
        inventory.Select(r => (r.Kind, r.Id)).Distinct().Count() == inventory.Length;
    private void Stamp(OrganizationUserStamp stamp)
    {
        OrganizationUserContract.Require(stamp.Root == root && OrganizationUserContract.Text(stamp.Registration) &&
            (registration is null || stamp.Registration == registration) &&
            OrganizationUserContract.Text(stamp.Event) && events.Add(stamp.Event) && Clock(stamp.Clock));
        registration ??= stamp.Registration;
    }
    private bool Clock(OrganizationUserScopeClock clock)
    {
        if (clock.Deployment != root.Deployment || clock.Authority != "provider-application-clock" ||
            clock.Epoch != root.Epoch || clock.Sequence <= sequence || clock.At == default ||
            clock.At.Offset != TimeSpan.Zero || clock.At < at) return false;
        sequence = clock.Sequence; at = clock.At; return true;
    }
    private void Enter(int expected)
    {
        OrganizationUserContract.Require(!busy && !failed && !closed && stage == expected);
        busy = failed = true; stage++;
    }
    private CancellationTokenSource Deadline(CancellationToken token)
    {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(seconds));
        return deadline;
    }
    public override string ToString() => "[OrganizationUserTrial]";
}
