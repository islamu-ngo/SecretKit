using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Samples.ProviderAssessment;

public enum DeliveryKind
{
    Direct,
    Indirect,
    NotChecked
}

public enum AssessmentState
{
    Ready,
    Absent,
    Denied,
    Unverified,
    Indirect,
    Unusable
}

/// <summary>Consumer-owned key policy, with an explicitly selected native reference.</summary>
public sealed class KeyRequirement
{
    public KeyRequirement(string key, SecretReference reference, DeliveryKind delivery)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(reference);
        if (!Enum.IsDefined(delivery))
        {
            throw new ArgumentOutOfRangeException(nameof(delivery));
        }

        Key = key;
        Reference = reference;
        Delivery = delivery;
    }

    [JsonIgnore]
    public string Key { get; }

    [JsonIgnore]
    public SecretReference Reference { get; }

    public DeliveryKind Delivery { get; }

    public override string ToString() => "[KeyRequirement]";
}

/// <summary>All keys are needed to enable this feature; the consumer selects whether it is required.</summary>
public sealed class FeatureRequirement
{
    public FeatureRequirement(string featureKey, bool required, IEnumerable<KeyRequirement> keys)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(featureKey);
        ArgumentNullException.ThrowIfNull(keys);
        KeyRequirement[] copy = keys.ToArray();
        if (copy.Length == 0 || copy.Any(key => key is null))
        {
            throw new ArgumentException("A feature requires at least one selected key.", nameof(keys));
        }

        FeatureKey = featureKey;
        Required = required;
        Keys = Array.AsReadOnly(copy);
    }

    [JsonIgnore]
    public string FeatureKey { get; }

    public bool Required { get; }

    [JsonIgnore]
    public IReadOnlyList<KeyRequirement> Keys { get; }

    public override string ToString() => "[FeatureRequirement]";
}

// Indices correlate with the caller's ordered input without exporting protected key names.
public sealed record KeyAssessment(int KeyIndex, AssessmentState State,
    SecretStatus? ReadStatus, SecretValidity? Validity);

public sealed record FeatureAssessment(int FeatureIndex, bool Required,
    IReadOnlyList<KeyAssessment> Keys)
{
    public bool CanEnable => Keys.All(key => key.State == AssessmentState.Ready);
}

public sealed record InventoryAssessment(SecretStatus Status, int? VisibleItems,
    DateTimeOffset? StartedAt, DateTimeOffset? CompletedAt, bool IsComplete)
{
    public bool IsPointInTime => false;
}

public sealed record AssessmentReport(InventoryAssessment Inventory,
    IReadOnlyList<FeatureAssessment> Features)
{
    public bool CanProceed => Features.All(feature => !feature.Required || feature.CanEnable);
}

/// <summary>
/// Collects admin metadata separately from intended-identity delivery evidence.
/// Each check is fresh; there is no saved report, material cache, activation or fallback principal.
/// </summary>
public sealed class AssessmentScenario
{
    private readonly ISecretInventory _adminInventory;
    private readonly ISecretReader _intendedReader;

    public AssessmentScenario(ISecretInventory adminInventory, ISecretReader intendedReader)
    {
        ArgumentNullException.ThrowIfNull(adminInventory);
        ArgumentNullException.ThrowIfNull(intendedReader);
        if (ReferenceEquals(adminInventory, intendedReader))
        {
            throw new ArgumentException("Select separate administrative and intended-identity clients.");
        }

        _adminInventory = adminInventory;
        _intendedReader = intendedReader;
    }

    public async Task<AssessmentReport> CheckAsync(SecretInventoryScope adminScope,
        IEnumerable<FeatureRequirement> requirements, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(adminScope);
        ArgumentNullException.ThrowIfNull(requirements);
        FeatureRequirement[] selected = requirements.ToArray();
        if (selected.Any(feature => feature is null))
        {
            throw new ArgumentException("A feature selection cannot be null.", nameof(requirements));
        }

        cancellationToken.ThrowIfCancellationRequested();
        SecretOutcome<SecretInventory> inventory = await _adminInventory.InspectAsync(adminScope, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        InventoryAssessment inspection = inventory.IsSuccess
            ? new(inventory.Status, inventory.Value.Items.Count, inventory.Value.StartedAt,
                inventory.Value.CompletedAt, inventory.Value.IsComplete)
            : new(inventory.Status, null, null, null, false);

        var features = new List<FeatureAssessment>();
        for (int featureIndex = 0; featureIndex < selected.Length; featureIndex++)
        {
            FeatureRequirement feature = selected[featureIndex];
            var keys = new List<KeyAssessment>();
            for (int keyIndex = 0; keyIndex < feature.Keys.Count; keyIndex++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                KeyRequirement key = feature.Keys[keyIndex];
                if (key.Delivery == DeliveryKind.NotChecked)
                {
                    keys.Add(new(keyIndex, AssessmentState.Unverified, null, null));
                    continue;
                }

                // Admin references must never be rebound or substituted for runtime references.
                if (!key.Reference.BelongsTo(_intendedReader.Authority))
                {
                    keys.Add(new(keyIndex, AssessmentState.Unusable, SecretStatus.Invalid, null));
                    continue;
                }

                SecretOutcome<SecretRead> outcome = await _intendedReader.ReadAsync(key.Reference, cancellationToken);
                if (!outcome.IsSuccess)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    AssessmentState state = outcome.Status switch
                    {
                        SecretStatus.Absent => AssessmentState.Absent,
                        SecretStatus.Denied => AssessmentState.Denied,
                        SecretStatus.Invalid or SecretStatus.Expired => AssessmentState.Unusable,
                        _ => AssessmentState.Unverified
                    };
                    keys.Add(new(keyIndex, state, outcome.Status, null));
                    continue;
                }

                using SecretRead read = outcome.Value;
                cancellationToken.ThrowIfCancellationRequested();
                // Do not inspect plaintext, recursively expand imports, or certify source-side resolution.
                bool indirect = key.Delivery == DeliveryKind.Indirect ||
                    key.Reference.Address is InfisicalSecretAddress
                    {
                        Resolution: InfisicalResolution.ExpandedReferences
                    } or InfisicalSecretAddress { IncludeImports: true };
                AssessmentState successfulState = read.Observation.Validity switch
                {
                    SecretValidity.Unknown => AssessmentState.Unverified,
                    SecretValidity.Valid when indirect => AssessmentState.Indirect,
                    SecretValidity.Valid => AssessmentState.Ready,
                    _ => AssessmentState.Unusable
                };
                keys.Add(new(keyIndex, successfulState, outcome.Status, read.Observation.Validity));
            }

            features.Add(new(featureIndex, feature.Required, keys.AsReadOnly()));
        }

        cancellationToken.ThrowIfCancellationRequested();
        return new(inspection, features.AsReadOnly());
    }
}
