using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class RotationMutationTrial : IAsyncDisposable
{
    private readonly IInfisicalRotationMutationSource source;
    private readonly RotationMutationInput input;
    private readonly RotationMaterialPacket baseline;
    private readonly HashSet<string> events = new(StringComparer.Ordinal);
    private long sequence = -1;
    private DateTimeOffset at;
    private bool armed;
    private bool settled;
    private bool authenticated;
    private bool closed;
    internal RotationMutationRoot Root { get; }
    internal RotationMutationBinding Binding { get; private set; } = null!;
    internal RotationMutationArm Arm { get; private set; } = null!;
    internal RotationMutationSettlement Settlement { get; private set; } = null!;

    private RotationMutationTrial(IInfisicalRotationMutationSource source, RotationMutationInput input,
        RotationMutationRoot root, RotationMaterialPacket baseline)
    {
        this.source = source;
        this.input = input;
        Root = root;
        this.baseline = baseline;
    }

    internal static async ValueTask<RotationMutationTrial> OpenAsync(IInfisicalRotationMutationSource source,
        RotationMutationInput input, NativeCaseDefinition row, InfisicalRotationAction action,
        InfisicalRotationPrecondition precondition, CancellationToken token)
    {
        var m = input.Material;
        Require(RotationMaterialTrial.Text(m.DeploymentId) && RotationMaterialTrial.Text(m.SourceIdentity) &&
            m.SourceIdentity is not ("setup" or "runtime" or "denied" or "administrative" or "observer") &&
            RotationMaterialTrial.Text(m.ClockEpoch) && Enum.IsDefined(m.Source) &&
            Guid.TryParseExact(m.ProjectId, "D", out var project) && project != Guid.Empty &&
            Guid.TryParseExact(m.RotationId, "D", out var rotation) && rotation != Guid.Empty &&
            RotationMaterialTrial.Text(m.Environment) && RotationMaterialTrial.Text(m.Folder) &&
            m.Folder.StartsWith('/') && m.Folder != "/" && RotationMaterialTrial.Text(m.SetupCapability) &&
            m.TimeoutSeconds is >= 1 and <= 900 && m.MaximumItems is > 0 and <= 4096 &&
            input.MaximumOriginalDeliveries is > 0 and <= 4096 &&
            m.AllowedActions is { Length: > 0 } && m.DeniedActions is { Length: > 0 } &&
            m.AllowedActions.All(RotationMaterialTrial.Text) && m.DeniedActions.All(RotationMaterialTrial.Text) &&
            !m.AllowedActions.Intersect(m.DeniedActions, StringComparer.Ordinal).Any() &&
            (!row.Key.Variant.StartsWith("profile.", StringComparison.Ordinal) ||
                row.Key.Variant == "profile." + m.Profile), "missing-input");
        var packet = new RotationMaterialPacket(m.Profile, m.Kind, m.Generation, m.Fields);
        var materialRoot = new RotationMaterialRoot(Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("N"),
            row.Key.Identity, "v0.166.3", m.DeploymentId, m.SourceIdentity, m.ClockEpoch, m.Source,
            m.ProjectId, m.Environment, m.Folder, m.RotationId, m.Profile, m.Kind, m.Generation);
        var root = new RotationMutationRoot(materialRoot, Guid.NewGuid().ToString("N"), action, precondition);
        var trial = new RotationMutationTrial(source, input, root, packet);
        try
        {
            using var capability = SecretMaterial.FromText(m.SetupCapability);
            using var deadline = trial.Deadline(token);
            var binding = await source.OpenAsync(root, packet, capability, deadline.Token);
            trial.Stamp(binding.Stamp);
            Require(binding.OwnedSetup && binding.SetupSettled && binding.ConfigurationAndMappingMatch &&
                binding.ExactMaterialKnown && binding.CompleteBackendInventory && binding.IndependentJournals &&
                binding.AdminAccepted && binding.WrongAdminRejected && binding.ValidAdminRechecked);
            trial.Binding = binding;
            return trial;
        }
        catch { await trial.DisposeAsync(); throw; }
    }

    internal async ValueTask ArmAsync(CancellationToken token)
    {
        Require(!closed && !armed);
        armed = true;
        using var deadline = Deadline(token);
        var arm = await source.ArmAsync(Binding, deadline.Token);
        Stamp(arm.Stamp);
        Require(arm.Binding == Binding && arm.CaptureArmed && arm.ExclusiveOriginalWindow &&
            arm.Stamp.RegistrationId != Binding.Stamp.RegistrationId);
        Arm = arm;
    }

    internal async ValueTask<RotationMaterialInput> SettleAsync(RotationMutationReceipt receipt, CancellationToken token)
    {
        Require(!closed && armed && !settled && Arm is not null);
        settled = true;
        Require(receipt.AttemptId == Root.AttemptId && receipt.Action == Root.Action);
        using var deadline = Deadline(token);
        var s = await source.SettleAsync(Arm!, receipt, deadline.Token);
        Stamp(s.Stamp, Arm!.Stamp.RegistrationId);
        Require(s.Arm == Arm && s.Receipt == receipt && Enum.IsDefined(s.Outcome) &&
            s.OriginalRequests is >= 0 and <= 1 && s.OriginalCommits is >= 0 and <= 1 &&
            s.OriginalCommits <= s.OriginalRequests &&
            s.OriginalBackendDeliveries >= 0 && s.OriginalBackendDeliveries <= input.MaximumOriginalDeliveries &&
            s.QueuedBackendDeliveries >= 0 && s.QueuedBackendDeliveries <= input.MaximumOriginalDeliveries &&
            s.OriginalTerminal && s.ExcludesLateWork && s.CompleteDeliveryInventory && s.NoReplay &&
            s.PendingDeliveries == 0 && s.PendingWork == 0);
        bool noDispatch = receipt.Dispatch == InfisicalRotationDispatch.NotDispatched;
        bool rejected = receipt.Dispatch == InfisicalRotationDispatch.Rejected;
        Require(!noDispatch || s.OriginalRequests == 0);
        Require(!rejected || s.OriginalRequests == 1 && s.OriginalCommits == 0);
        Require(!(noDispatch || rejected) || s.Outcome == RotationMutationOutcome.NonApplied &&
            s.OriginalBackendDeliveries == 0);
        // Unknown is a dispatch classification, not a non-occurrence oracle.
        // Partial is a terminal source outcome, never silently promoted to Applied.
        Require(receipt.Status != SecretStatus.Success || s.Outcome == RotationMutationOutcome.Applied &&
            s.OriginalRequests == 1 && s.OriginalCommits == 1, "effect-mismatch");
        Require(s.Outcome != RotationMutationOutcome.NonApplied || s.OriginalCommits == 0 &&
            s.OriginalBackendDeliveries == 0, "effect-mismatch");
        Require(s.Outcome != RotationMutationOutcome.Applied || s.OriginalRequests == 1 &&
            s.OriginalCommits == 1, "effect-mismatch");
        Require(s.Outcome != RotationMutationOutcome.Partial || s.OriginalRequests == 1 &&
            (s.OriginalCommits > 0 || s.OriginalBackendDeliveries > 0), "effect-mismatch");
        Require(s.ConfigurationMatchesOutcome && s.MappingPreserved &&
            s.CompleteCredentialHistory && s.IdentityRetirementQualified, "effect-mismatch");
        if (s.OriginalBackendDeliveries > 0)
            Require(s.EventAttemptId == Root.AttemptId && s.Event == (Root.Action == InfisicalRotationAction.RotateSecrets ?
                RotationMutationEvent.OriginalManual : RotationMutationEvent.ScheduledOpportunity), "effect-mismatch");

        bool changed = s.Generation != input.Material.Generation;
        if (s.Outcome == RotationMutationOutcome.Applied)
        {
            bool manual = Root.Action == InfisicalRotationAction.RotateSecrets;
            bool enable = Root.Action == InfisicalRotationAction.EnableAutomaticRotation;
            Require(s.EventAttemptId == Root.AttemptId, "effect-mismatch");
            if (manual)
                Require(s.Event == RotationMutationEvent.OriginalManual && changed &&
                    s.OriginalBackendDeliveries > 0, "effect-mismatch");
            else
                Require(s.Enabled == enable && s.Event == RotationMutationEvent.ScheduledOpportunity &&
                    s.QualifiedOpportunity && s.QueueTerminalBeforeOpportunity &&
                    s.InjectedClock == (Root.Material.Source == RotationMaterialSource.ControlledFixture) &&
                    (s.Generation != s.OpportunityBaselineGeneration) == enable && (enable ? s.OriginalBackendDeliveries > 0 :
                        s.OriginalBackendDeliveries == 0), "effect-mismatch");
        }
        else if (s.Outcome == RotationMutationOutcome.NonApplied)
            Require(s.Generation == input.Material.Generation + s.QueuedBackendDeliveries &&
                s.Event == RotationMutationEvent.None, "effect-mismatch");
        if (changed && s.Outcome != RotationMutationOutcome.Partial)
            Require(s.Generation == input.Material.Generation + s.QueuedBackendDeliveries +
                (s.Outcome == RotationMutationOutcome.Applied &&
                    Root.Action != InfisicalRotationAction.DisableAutomaticRotation ? 1 : 0) &&
                s.PreviousActiveAccepted == RotationMaterialProfile.For(Root.Material.Profile).Overlap &&
                s.OverwrittenRetired, "effect-mismatch");
        if (Root.Material.Profile == InfisicalRotationProfile.GcpServiceAccountKey)
        {
            // One complete key file, not split mappings. A key change cannot
            // silently replace the immutable selected service-account target.
            byte[] before = [];
            byte[] after = [];
            try
            {
                Require(s.Fields is { Length: 1 } && s.Fields[0].Field == "serviceAccountKey", "effect-mismatch");
                before = Encoding.UTF8.GetBytes(input.Material.Fields[0].Value);
                after = Encoding.UTF8.GetBytes(s.Fields[0].Value);
                using var oldKey = JsonDocument.Parse(before);
                using var currentKey = JsonDocument.Parse(after);
                Require(oldKey.RootElement.TryGetProperty("client_email", out var oldEmail) &&
                    currentKey.RootElement.TryGetProperty("client_email", out var currentEmail) &&
                    oldEmail.ValueKind == JsonValueKind.String && currentEmail.ValueKind == JsonValueKind.String &&
                    RotationMaterialTrial.Text(oldEmail.GetString()) &&
                    currentEmail.GetString() == oldEmail.GetString(), "effect-mismatch");
            }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
        }
        Settlement = s;
        return input.Material with { Generation = s.Generation, Fields = s.Fields };
    }

    internal async ValueTask AuthenticateAsync(RotationMaterialPacket actual, CancellationToken token)
    {
        Require(!closed && settled && !authenticated);
        authenticated = true;
        using var expected = new RotationMaterialPacket(Root.Material.Profile, Root.Material.Kind,
            Settlement.Generation, Settlement.Fields);
        Require(actual.Matches(expected), "effect-mismatch");
        using var wrong = actual.Wrong();
        using var deadline = Deadline(token);
        var f = await source.AuthenticateAsync(Arm, actual, wrong, deadline.Token);
        Stamp(f.Stamp, Arm.Stamp.RegistrationId);
        Require(f.Arm == Arm && f.Generation == Settlement.Generation && f.ExactSuppliedMaterial &&
            f.CoherentGeneration && f.FreshSessions && f.IndependentBackend &&
            f.Valid == BackendAuthentication.Accepted && f.Wrong == BackendAuthentication.Rejected &&
            f.Recheck == BackendAuthentication.Accepted &&
            f.AllowedActions.SequenceEqual(input.Material.AllowedActions) &&
            f.DeniedActions.SequenceEqual(input.Material.DeniedActions), "effect-mismatch");
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
                c.CapturedSetsRetired && c.OwnedIdentitiesAbsent && c.OwnedResourcesAbsent &&
                c.NativeSetupAbsent && c.MappedSecretsAbsent && c.BorrowedPreserved && c.PrivateDestroyed &&
                c.Registrations == 0 && c.PendingDeliveries == 0 && c.PendingWork == 0, "cleanup-incomplete");
        }
        catch (Exception) { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { baseline.Dispose(); }
    }

    private void Stamp(RotationMutationStamp stamp, string? registration = null)
    {
        Require(stamp.Root == Root && RotationMaterialTrial.Text(stamp.RegistrationId) &&
            (registration is null || stamp.RegistrationId == registration) &&
            RotationMaterialTrial.Text(stamp.EventId) && events.Add(stamp.EventId) &&
            stamp.Sequence > sequence && stamp.At != default && stamp.At.Offset == TimeSpan.Zero &&
            stamp.At >= at && stamp.ClockAuthority == "provider-application-clock");
        sequence = stamp.Sequence;
        at = stamp.At;
    }
    private CancellationTokenSource Deadline(CancellationToken token)
    {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(input.Material.TimeoutSeconds));
        return deadline;
    }
    private static void Require(bool value, string code = "observer-unavailable") => RotationMaterialTrial.Require(value, code);
    public override string ToString() => "[RotationMutationTrial]";
}
