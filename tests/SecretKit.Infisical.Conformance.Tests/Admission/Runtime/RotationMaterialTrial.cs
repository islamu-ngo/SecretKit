using System.Diagnostics.CodeAnalysis;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Source injection never bypasses host qualification. The immutable local root
// and cleanup owner exist before Open; Close does not depend on its reply.
internal sealed class RotationMaterialTrial : IAsyncDisposable
{
    private readonly IInfisicalRotationMaterialSource source;
    private readonly RotationMaterialInput input;
    private readonly RotationMaterialPacket packet;
    private readonly HashSet<string> events = new(StringComparer.Ordinal);
    private readonly HashSet<string> registrations = new(StringComparer.Ordinal);
    private long sequence = -1;
    private DateTimeOffset at;
    private bool armed;
    private bool authenticated;
    private bool completed;
    private bool closed;
    internal RotationMaterialRoot Root { get; }
    internal RotationMaterialBinding Binding { get; private set; } = null!;
    internal RotationMaterialArm Arm { get; private set; } = null!;

    private RotationMaterialTrial(IInfisicalRotationMaterialSource source, RotationMaterialInput input,
        RotationMaterialRoot root, RotationMaterialPacket packet)
    {
        this.source = source;
        this.input = input;
        Root = root;
        this.packet = packet;
    }

    internal static async ValueTask<RotationMaterialTrial> OpenAsync(IInfisicalRotationMaterialSource source,
        RotationMaterialInput input, NativeCaseDefinition row, CancellationToken token)
    {
        Require(input is not null && source is not null, "missing-input");
        Require(Text(input.DeploymentId) && Text(input.SourceIdentity) && Text(input.ClockEpoch) &&
            input.SourceIdentity is not ("setup" or "runtime" or "denied" or "administrative" or "observer") &&
            Enum.IsDefined(input.Source) && Guid.TryParseExact(input.ProjectId, "D", out var project) && project != Guid.Empty &&
            Guid.TryParseExact(input.RotationId, "D", out var rotation) && rotation != Guid.Empty &&
            Text(input.Environment) && Text(input.Folder) && input.Folder.StartsWith('/') && input.Folder != "/" &&
            Text(input.SetupCapability) && input.TimeoutSeconds is >= 1 and <= 900 &&
            input.MaximumItems is > 0 and <= 4096 && input.AllowedActions is { Length: > 0 } &&
            input.DeniedActions is { Length: > 0 } && input.AllowedActions.All(Text) && input.DeniedActions.All(Text) &&
            !input.AllowedActions.Intersect(input.DeniedActions, StringComparer.Ordinal).Any() &&
            (!row.Key.Variant.StartsWith("profile.", StringComparison.Ordinal) ||
                row.Key.Variant == "profile." + input.Profile), "missing-input");
        var packet = new RotationMaterialPacket(input.Profile, input.Kind, input.Generation, input.Fields);
        var root = new RotationMaterialRoot(Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("N"),
            row.Key.Identity, "v0.166.3", input.DeploymentId, input.SourceIdentity, input.ClockEpoch,
            input.Source, input.ProjectId, input.Environment, input.Folder, input.RotationId,
            input.Profile, input.Kind, input.Generation);
        var trial = new RotationMaterialTrial(source, input, root, packet);
        try
        {
            using var capability = SecretMaterial.FromText(input.SetupCapability);
            using var deadline = trial.Deadline(token);
            var binding = await source.OpenAsync(root, packet, capability, deadline.Token);
            trial.Stamp(binding.Stamp, newRegistration: true);
            Require(binding.OwnedSetup && binding.NeverEnabled && binding.SetupSettled &&
                binding.ConfigurationAndMappingMatch && binding.ExactMaterialKnown &&
                binding.CompleteBackendInventory && binding.IndependentJournals && binding.AdminAccepted &&
                binding.WrongAdminRejected && binding.ValidAdminRechecked);
            trial.Binding = binding;
            return trial;
        }
        catch
        {
            await trial.DisposeAsync();
            throw;
        }
    }

    internal async ValueTask ArmAsync(CancellationToken token)
    {
        Require(!closed && !armed);
        armed = true; // Consume before the await; unknown arm still belongs to Root.
        using var deadline = Deadline(token);
        var facts = await source.ArmAsync(Binding, deadline.Token);
        Stamp(facts.Stamp, newRegistration: true);
        Require(facts.Binding == Binding && facts.CaptureArmed);
        Arm = facts;
    }

    internal async ValueTask AuthenticateAsync(RotationMaterialPacket actual, CancellationToken token)
    {
        Require(!closed && armed && Arm is not null && !authenticated);
        authenticated = true;
        Require(actual.Profile == Root.Profile && actual.Kind == Root.Kind && actual.Generation == Root.Generation,
            "effect-mismatch");
        Require(actual.Matches(packet), "effect-mismatch");
        using var wrong = actual.Wrong();
        using var deadline = Deadline(token);
        var facts = await source.AuthenticateAsync(Arm!, actual, wrong, deadline.Token);
        Stamp(facts.Stamp);
        Require(facts.Arm == Arm && facts.FreshSessions && facts.IndependentBackend);
        Require(facts.ExactSuppliedMaterial && facts.CoherentGeneration &&
            facts.Valid == BackendAuthentication.Accepted && facts.Wrong == BackendAuthentication.Rejected &&
            facts.Recheck == BackendAuthentication.Accepted &&
            facts.AllowedActions is not null && facts.AllowedActions.SequenceEqual(input.AllowedActions) &&
            facts.DeniedActions is not null && facts.DeniedActions.SequenceEqual(input.DeniedActions), "effect-mismatch");
    }

    internal async ValueTask CompleteAsync(SecretStatus status, CancellationToken token)
    {
        Require(!closed && armed && Arm is not null && authenticated && !completed);
        completed = true;
        using var deadline = Deadline(token);
        var facts = await source.CompleteAsync(Arm!, status, deadline.Token);
        Stamp(facts.Stamp);
        Require(facts.Arm == Arm && facts.Status == status && facts.OriginalSettled && facts.ExcludesLateWork &&
            facts.IndependentReadWindow && facts.NoReplay &&
            (status == SecretStatus.Unknown ? facts.OriginalReads is >= 0 and <= 1 : facts.OriginalReads == 1) &&
            facts.PendingDeliveries == 0 && facts.PendingWork == 0);
        Require(facts.ConfigurationUnchanged && facts.MappingUnchanged && facts.MaterialUnchanged &&
            facts.BackendInventoryUnchanged, "effect-mismatch");
    }

    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        closed = true;
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var facts = await source.CloseAsync(Root, deadline.Token);
            Require(facts.Root == Root && facts.OriginalSettled && facts.ExcludesLateWork &&
                facts.OwnedSetupAbsent && facts.MappedSecretsAbsent && facts.BackendResourcesAbsent &&
                facts.CapturedMaterialRetired && facts.BorrowedPreserved && facts.PrivateDestroyed &&
                facts.CompleteInventory && facts.Registrations == 0 &&
                facts.PendingDeliveries == 0 && facts.PendingWork == 0, "cleanup-incomplete");
        }
        catch (Exception)
        { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { packet.Dispose(); }
    }

    private void Stamp(RotationMaterialStamp? stamp, bool newRegistration = false)
    {
        Require(stamp is not null && stamp.Root == Root && stamp.ClockAuthority == "provider-application-clock" &&
            Text(stamp.EventId) && events.Add(stamp.EventId) && Text(stamp.RegistrationId) &&
            (newRegistration ? registrations.Add(stamp.RegistrationId) : stamp.RegistrationId == Arm.Stamp.RegistrationId) &&
            stamp.Sequence > sequence && stamp.At != default && stamp.At.Offset == TimeSpan.Zero && stamp.At >= at);
        sequence = stamp!.Sequence;
        at = stamp.At;
    }
    private CancellationTokenSource Deadline(CancellationToken token)
    {
        var result = CancellationTokenSource.CreateLinkedTokenSource(token);
        result.CancelAfter(TimeSpan.FromSeconds(input.TimeoutSeconds));
        return result;
    }
    internal static bool Text(string? value) => value is { Length: > 0 and <= 256 } &&
        !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
    internal static void Require([DoesNotReturnIf(false)] bool value, string code = "observer-unavailable")
    {
        if (!value) throw new NativeCaseFailureException(code);
    }
    public override string ToString() => "[RotationMaterialTrial]";
}
