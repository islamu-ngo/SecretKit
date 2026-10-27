using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Whether an independent native observation established the selected effect.</summary>
public enum InfisicalEffectEvidence { /** <summary>No effect was established.</summary> */ Unknown, /** <summary>The selected effect was observed.</summary> */ Observed }
/// <summary>Destination application evidence, kept separate from import configuration.</summary>
public enum InfisicalDestinationEvidence { /** <summary>Destination state is not established.</summary> */ Unknown, /** <summary>Approval is pending, not applied.</summary> */ ApprovalPending, /** <summary>Application has been established.</summary> */ Applied }

/// <summary>
/// Import configuration, replication report and fresh delivery are independent evidence.
/// The published v2 status string has no established approval vocabulary.
/// </summary>
public sealed class InfisicalImportEffectObservation
{
    internal InfisicalImportEffectObservation(SecretStatus visibility, SecretStatus delivery,
        InfisicalImport? import, DateTimeOffset? deliveredAt, string? deliveredVersion)
    {
        VisibilityStatus = visibility;
        DeliveryStatus = delivery;
        Import = import;
        DeliveredAt = deliveredAt;
        DeliveredVersion = deliveredVersion;
    }
    /// <summary>Outcome of fresh import inspection, independent of intended-reader delivery.</summary>
    public SecretStatus VisibilityStatus { get; }
    /// <summary>Outcome of a separate fresh read by the explicitly supplied intended client.</summary>
    public SecretStatus DeliveryStatus { get; }
    /// <summary>Observed configuration presence only; not destination application.</summary>
    public InfisicalEffectEvidence ImportCreated => Import is null ? InfisicalEffectEvidence.Unknown : InfisicalEffectEvidence.Observed;
    /// <summary>Whether inspected configuration requests replication, or null if unobserved.</summary>
    public bool? ReplicationRequested => Import?.IsReplication;
    /// <summary>Provider-reported replication success, not intended-reader delivery proof.</summary>
    public bool? ReplicationReportedSuccessful => Import?.ReplicationReportedSuccessful;
    /// <summary>No published v2 field establishes destination approval/application state.</summary>
    public InfisicalDestinationEvidence Destination => InfisicalDestinationEvidence.Unknown;
    /// <summary>Whether the fresh intended-client read succeeded; administrative visibility cannot substitute for it.</summary>
    public bool FreshIntendedReadSucceeded => DeliveryStatus == SecretStatus.Success;
    /// <summary>The observed import, or null when inspection did not succeed.</summary>
    [JsonIgnore]
    public InfisicalImport? Import { get; }
    /// <summary>Time of the successful intended read, or null when delivery was not observed.</summary>
    [JsonIgnore]
    public DateTimeOffset? DeliveredAt { get; }
    /// <summary>Version from that read; absent evidence is not reconstructed from configuration.</summary>
    [JsonIgnore]
    public string? DeliveredVersion { get; }
    /// <summary>Returns a fixed label without import or read coordinates.</summary>
    public override string ToString() => "[InfisicalImportEffectObservation]";
}

public sealed partial class InfisicalClient
{
    /// <summary>
    /// Performs a new native observation and a new read through the explicitly supplied intended client.
    /// Neither an administrative token nor successful configuration is substituted for intended delivery.
    /// </summary>
    public async ValueTask<SecretOutcome<InfisicalImportEffectObservation>> ObserveImportEffectsAsync(
        SecretReference target, InfisicalClient intendedReader, SecretReference intendedSecret,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(intendedReader);
        ArgumentNullException.ThrowIfNull(intendedSecret);
        cancellationToken.ThrowIfCancellationRequested();
        if (!NativeTargetValid(target, null) || target.Address is not InfisicalImportAddress { ImportId: not null } address ||
            !intendedSecret.BelongsTo(intendedReader.Authority) || intendedSecret.Address is not InfisicalSecretAddress secret ||
            secret.ProjectId != address.ProjectId || secret.Environment != address.Environment ||
            secret.Folder != address.Folder || secret.Version is not null)
        {
            return SecretOutcome<InfisicalImportEffectObservation>.Failure(SecretStatus.Invalid);
        }
        SecretOutcome<InfisicalImport> visibility = await GetImportAsync(target, cancellationToken).ConfigureAwait(false);
        // Denied/unknown inspection still cannot stand in for an independently authorized runtime read.
        SecretOutcome<SecretRead> delivery = await intendedReader.ReadAsync(intendedSecret, cancellationToken).ConfigureAwait(false);
        DateTimeOffset? deliveredAt = null;
        string? version = null;
        if (delivery.IsSuccess)
        {
            using SecretRead read = delivery.Value;
            deliveredAt = read.Observation.ObservedAt;
            version = read.Observation.Version;
        }
        return SecretOutcome<InfisicalImportEffectObservation>.Success(new(visibility.Status, delivery.Status,
            visibility.IsSuccess ? visibility.Value : null, deliveredAt, version));
    }
}
