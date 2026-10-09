using System.Text.Json.Serialization;

namespace SecretKit.Core;

public enum SecretValidity
{
    Valid,
    Disabled,
    NotYetValid,
    Expired,
    Unknown
}

/// <summary>Value-free observation. Provider coordinates and versions are controlled metadata.</summary>
public sealed class SecretObservation
{
    public SecretObservation(SecretReference reference, string? version, DateTimeOffset observedAt,
        SecretValidity validity, DateTimeOffset? expiresAt = null)
    {
        ArgumentNullException.ThrowIfNull(reference);
        Reference = reference;
        Version = version;
        ObservedAt = observedAt;
        Validity = validity;
        ExpiresAt = expiresAt;
    }

    [JsonIgnore]
    public SecretReference Reference { get; }

    [JsonIgnore]
    public string? Version { get; }

    public DateTimeOffset ObservedAt { get; }

    public SecretValidity Validity { get; }

    public DateTimeOffset? ExpiresAt { get; }

    public override string ToString() => $"[SecretObservation:{Validity}]";
}

/// <summary>An independently owned read result; dispose it to clear its material.</summary>
public sealed class SecretRead : IDisposable
{
    public SecretRead(SecretMaterial material, SecretObservation observation)
    {
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(observation);
        Material = material;
        Observation = observation;
    }

    [JsonIgnore]
    public SecretMaterial Material { get; }

    public SecretObservation Observation { get; }

    public void Dispose() => Material.Dispose();

    public override string ToString() => "[SecretRead]";
}
