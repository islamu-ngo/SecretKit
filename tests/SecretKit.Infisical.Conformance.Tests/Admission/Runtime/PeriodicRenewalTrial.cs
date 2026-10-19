using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class PeriodicRenewalTrial : IAsyncDisposable
{
    private readonly IInfisicalPeriodicRenewalSource source;
    private readonly HashSet<string> events = new(StringComparer.Ordinal);
    private long sequence = -1;
    private DateTimeOffset at;
    private bool closed;
    private bool armed;
    private bool settled;
    private bool inspected;
    internal PeriodicRenewalRoot Root { get; }
    internal PeriodicRenewalBinding Binding { get; private set; } = null!;
    internal PeriodicRenewalArm Arm { get; private set; } = null!;
    internal PeriodicRenewalSettlement Settlement { get; private set; } = null!;
    internal PeriodicRenewalArrival? Arrival { get; private set; }

    private PeriodicRenewalTrial(IInfisicalPeriodicRenewalSource source, PeriodicRenewalRoot root)
    {
        this.source = source;
        Root = root;
    }

    internal static PeriodicRenewalRoot CreateRoot(PeriodicRenewalInput input, NativeCaseDefinition row,
        bool expectsRequest, PeriodicRenewalBoundary boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), row.Key.Identity,
            row.Key.Operation, row.Key.Variant, row.Key.Case, "v0.166.3", input.Deployment,
            input.SourceIdentity, input.Epoch, input.Source, input.IdentityId, input.TokenRow,
            expectsRequest, boundary);

    internal static async ValueTask<PeriodicRenewalTrial> OpenAsync(IInfisicalPeriodicRenewalSource source,
        PeriodicRenewalInput input, NativeCaseDefinition row, SecretMaterial borrowed,
        InfisicalTokenLifetimeEvidence evidence, bool expectsRequest, PeriodicRenewalBoundary boundary,
        CancellationToken token)
    {
        Require(Text(input.Deployment) && Text(input.SourceIdentity) && Text(input.Epoch) &&
            Text(input.IdentityId) && Text(input.TokenRow) && Text(input.Capability) &&
            Text(input.AllowedKey) && Text(input.DeniedKey) && input.AllowedKey != input.DeniedKey &&
            Enum.IsDefined(input.Source) && input.SourceIdentity is not
                ("setup" or "runtime" or "denied" or "administrative" or "observer"), "missing-input");
        var trial = new PeriodicRenewalTrial(source, CreateRoot(input, row, expectsRequest, boundary));
        // Cleanup ownership exists before any remote registration can be created.
        try
        {
            using var capability = SecretMaterial.FromText(input.Capability);
            var binding = await source.OpenAsync(trial.Root, borrowed, capability, token);
            trial.Stamp(binding.Stamp);
            Require(Text(binding.CredentialHandle) && binding.ExactCredentialRowJoin &&
                binding.IndependentJournal && binding.BorrowedIdentityAndGrants);
            Require(binding.Lifetime == PeriodicRenewalLifetime.From(evidence), "effect-mismatch");
            trial.Binding = binding;
            return trial;
        }
        catch { await trial.DisposeAsync(); throw; }
    }

    internal async ValueTask ExpireAsync(CancellationToken token)
    {
        Require(!closed && !armed && Root.Variant == "session.expired");
        var expired = await source.ExpireAsync(Binding, token);
        Stamp(expired.Stamp, Binding.Stamp.Registration);
        Require(expired.Lifetime == Binding.Lifetime && expired.NaturalExpiry &&
            expired.PolicyAndGrantsUnchanged && expired.Stamp.At >= Binding.Lifetime.ExpiresAt &&
            expired.InjectedClock == (Root.Source == PeriodicRenewalSourceKind.ControlledFixture));
    }

    internal async ValueTask ArmAsync(CancellationToken token)
    {
        Require(!closed && !armed);
        armed = true;
        var arm = await source.ArmAsync(Binding, token);
        Stamp(arm.Stamp, Binding.Stamp.Registration);
        Require(arm.Binding == Binding && Text(arm.Window) && arm.ExclusiveOriginalWindow &&
            arm.CaptureArmed && arm.PendingWork == 0);
        Arm = arm;
    }

    internal async Task AwaitBoundaryAsync(CancellationToken token)
    {
        Require(!closed && armed && !settled && Root.ExpectsRequest &&
            Root.Boundary != PeriodicRenewalBoundary.None && Arrival is null);
        var arrival = await source.AwaitBoundaryAsync(Arm, token);
        Stamp(arrival.Stamp, Arm.Stamp.Registration);
        Require(arrival.Window == Arm.Window && Text(arrival.RequestId) &&
            arrival.CredentialHandle == Binding.CredentialHandle &&
            arrival.Boundary == Root.Boundary && arrival.ResponseHeld);
        Arrival = arrival;
    }

    internal async ValueTask SettleAsync(PeriodicRenewalReceipt receipt, CancellationToken token)
    {
        Require(!closed && armed && !settled);
        settled = true;
        var s = await source.SettleAsync(Arm, receipt, token);
        Stamp(s.Stamp, Arm.Stamp.Registration);
        Require(s.Arm == Arm && s.Receipt == receipt && s.CredentialHandle == Binding.CredentialHandle &&
            Enum.IsDefined(s.Outcome) && s.OriginalRequests is >= 0 and <= 1 &&
            s.OriginalCommits is >= 0 and <= 1 && s.OriginalCommits <= s.OriginalRequests &&
            s.ForeignRequests == 0 && s.PendingWork == 0 && s.PendingDeliveries == 0 &&
            s.OriginalTerminal && s.ExcludesLateWork && s.CompleteInventory && s.NoReplay &&
            s.BorrowedIdentityAndGrants);
        Require(s.OriginalRequests == (Root.ExpectsRequest ? 1 : 0) &&
            (Root.ExpectsRequest ? Text(s.RequestId) : s.RequestId == "") &&
            (Arrival is null || s.RequestId == Arrival.RequestId));
        Require(Root.ExpectsRequest ? receipt.Evidence is not null :
            receipt.Evidence is null && s.Outcome == PeriodicRenewalOutcome.NonApplied);
        Require(Root.Boundary == PeriodicRenewalBoundary.None || Arrival is not null);
        Require(receipt.Evidence != InfisicalRenewalEvidence.Applied ||
            s.Outcome == PeriodicRenewalOutcome.Applied && s.OriginalCommits == 1, "effect-mismatch");
        Require(receipt.Evidence != InfisicalRenewalEvidence.Rejected ||
            s.Outcome == PeriodicRenewalOutcome.NonApplied && s.OriginalCommits == 0, "effect-mismatch");
        Require(s.Outcome != PeriodicRenewalOutcome.NonApplied || s.OriginalCommits == 0 &&
            s.OriginalLifetime == Binding.Lifetime && s.CapturedLifetime is null &&
            s.CapturedTokenRow is null && s.CapturedCredentialHandle is null, "effect-mismatch");
        if (s.Outcome != PeriodicRenewalOutcome.NonApplied)
        {
            Require(s.OriginalRequests == 1 && s.OriginalCommits == 1 && s.CapturedLifetime is not null &&
                Text(s.CapturedTokenRow) && Text(s.CapturedCredentialHandle), "effect-mismatch");
            // Every lifetime component is authenticated by the source. Renewal may
            // change expiry only, including the borrowed row's qualified expiry.
            Require((s.OriginalLifetime with { ExpiresAt = Binding.Lifetime.ExpiresAt }) == Binding.Lifetime &&
                (s.CapturedLifetime! with { ExpiresAt = Binding.Lifetime.ExpiresAt }) == Binding.Lifetime &&
                s.OriginalLifetime.ExpiresAt >= Binding.Lifetime.ExpiresAt &&
                s.CapturedLifetime!.ExpiresAt >= Binding.Lifetime.ExpiresAt, "effect-mismatch");
        }
        Settlement = s;
        // Terminal Partial is recorded but never promoted into a passing effect.
        Require(s.Outcome != PeriodicRenewalOutcome.Partial, "effect-mismatch");
    }

    internal async ValueTask InspectDeliveryAsync(InfisicalAccessToken actual,
        bool renewed, CancellationToken token)
    {
        Require(!closed && settled && !inspected);
        inspected = true;
        var d = await source.InspectDeliveryAsync(Arm, actual.Material, token);
        Stamp(d.Stamp, Arm.Stamp.Registration);
        Require(d.Window == Arm.Window && d.ExactSuppliedCredential &&
            d.TokenRow == (renewed ? Settlement.CapturedTokenRow : Root.TokenRow) &&
            d.CredentialHandle == (renewed ? Settlement.CapturedCredentialHandle : Binding.CredentialHandle) &&
            d.Lifetime == (renewed ? Settlement.CapturedLifetime : Binding.Lifetime) &&
            actual.ExpiresAt == d.Lifetime.ExpiresAt, "effect-mismatch");
    }

    private void Stamp(PeriodicRenewalStamp stamp, string? registration = null)
    {
        Require(stamp.Root == Root && Text(stamp.Registration) &&
            (registration is null || stamp.Registration == registration) &&
            Text(stamp.Event) && events.Add(stamp.Event) && stamp.Sequence > sequence &&
            stamp.At != default && stamp.At.Offset == TimeSpan.Zero && stamp.At >= at &&
            stamp.ClockAuthority == "provider-application-clock");
        sequence = stamp.Sequence;
        at = stamp.At;
    }

    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        closed = true;
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var c = await source.CloseAsync(Root, deadline.Token);
            Require(c.Root == Root && c.OriginalTerminal && c.ExcludesLateWork && c.CompleteInventory &&
                c.BorrowedIdentityAndGrants && c.QualifiedLifetimePreserved &&
                c.OwnedCapturedResourcesAbsent && c.PrivateCopiesDestroyed &&
                c.Registrations == 0 && c.PendingWork == 0 && c.PendingDeliveries == 0, "cleanup-incomplete");
        }
        catch (Exception) { throw new NativeCaseFailureException("cleanup-incomplete"); }
    }

    internal static bool Text(string? value) => value is { Length: > 0 and <= 16384 } && !value.Any(char.IsControl);
    internal static void Require(bool condition, string code = "observer-unavailable")
    {
        if (!condition) throw new NativeCaseFailureException(code);
    }
    public override string ToString() => "[PeriodicRenewalTrial]";
}
