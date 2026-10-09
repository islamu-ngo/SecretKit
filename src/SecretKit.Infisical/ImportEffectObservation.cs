using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

public enum InfisicalEffectEvidence { Unknown, Observed }
public enum InfisicalDestinationEvidence { Unknown, ApprovalPending, Applied }

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
    public SecretStatus VisibilityStatus { get; }
    public SecretStatus DeliveryStatus { get; }
    public InfisicalEffectEvidence ImportCreated => Import is null ? InfisicalEffectEvidence.Unknown : InfisicalEffectEvidence.Observed;
    public bool? ReplicationRequested => Import?.IsReplication;
    public bool? ReplicationReportedSuccessful => Import?.ReplicationReportedSuccessful;
    /// <summary>No published v2 field establishes destination approval/application state.</summary>
    public InfisicalDestinationEvidence Destination => InfisicalDestinationEvidence.Unknown;
    public bool FreshIntendedReadSucceeded => DeliveryStatus == SecretStatus.Success;
    [JsonIgnore]
    public InfisicalImport? Import { get; }
    [JsonIgnore]
    public DateTimeOffset? DeliveredAt { get; }
    [JsonIgnore]
    public string? DeliveredVersion { get; }
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
