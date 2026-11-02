using System.Text.Json.Serialization;

namespace SecretKit.Core;

/// <summary>Observed material validity, not proof of application readiness or delivery permission.</summary>
public enum SecretValidity
{
    /// <summary>The observation reports usable material.</summary>
    Valid,
    /// <summary>The resource is disabled.</summary>
    Disabled,
    /// <summary>The material's validity period has not started.</summary>
    NotYetValid,
    /// <summary>The material's validity period has ended.</summary>
    Expired,
    /// <summary>The available evidence does not establish validity.</summary>
    Unknown
}

/// <summary>Value-free observation. Provider coordinates and versions are controlled metadata.</summary>
public sealed class SecretObservation
{
    /// <summary>Captures value-free evidence while retaining the supplied reference instance.</summary>
    /// <param name="reference">The observed reference; successful readers retain the exact requested object.</param>
    /// <param name="version">Optional provider version, not a portable sequence number.</param>
    /// <param name="observedAt">When the observation was made.</param>
    /// <param name="validity">Reported validity at observation time.</param>
    /// <param name="expiresAt">Reported expiry, or null when no expiry is established.</param>
    /// <exception cref="ArgumentNullException"><paramref name="reference"/> is null.</exception>
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

    /// <summary>Gets the retained reference object; its coordinates remain controlled metadata.</summary>
    [JsonIgnore]
    public SecretReference Reference { get; }

    /// <summary>Gets the optional provider version; it is not a cross-provider concurrency token.</summary>
    [JsonIgnore]
    public string? Version { get; }

    /// <summary>Gets when this evidence was observed, not a guarantee of current remote state.</summary>
    public DateTimeOffset ObservedAt { get; }

    /// <summary>Gets the observed validity category.</summary>
    public SecretValidity Validity { get; }

    /// <summary>Gets the reported expiry, or null when none was established.</summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary>Returns only a validity marker, without coordinates or version.</summary>
    public override string ToString() => $"[SecretObservation:{Validity}]";
}

/// <summary>An independently owned read result; dispose it to clear its material.</summary>
public sealed class SecretRead : IDisposable
{
    /// <summary>Takes ownership of supplied material without copying it and retains the observation.</summary>
    /// <param name="material">Material this read will dispose; make a separate copy for another owner.</param>
    /// <param name="observation">Value-free evidence accompanying the material.</param>
    /// <exception cref="ArgumentNullException">Either argument is null.</exception>
    public SecretRead(SecretMaterial material, SecretObservation observation)
    {
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(observation);
        Material = material;
        Observation = observation;
    }

    /// <summary>Gets material owned by this read; dispose the read when finished with it.</summary>
    [JsonIgnore]
    public SecretMaterial Material { get; }

    /// <summary>Gets the retained observation, which remains available after material disposal.</summary>
    public SecretObservation Observation { get; }

    /// <summary>Clears this read's material; independent copies remain owned by their callers.</summary>
    public void Dispose() => Material.Dispose();

    /// <summary>Returns a fixed marker without material or observation coordinates.</summary>
    public override string ToString() => "[SecretRead]";
}
