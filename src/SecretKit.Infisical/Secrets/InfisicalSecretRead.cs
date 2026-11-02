using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>One independently owned raw read with qualified native resource evidence.</summary>
public sealed class InfisicalSecretRead : IDisposable
{
    internal InfisicalSecretRead(SecretMaterial material, SecretObservation observation,
        InfisicalSecretRevision revision)
    {
        Material = material;
        Observation = observation;
        Revision = revision;
    }

    /// <summary>Material owned by this read; exports create ordinary plaintext copies.</summary>
    [JsonIgnore]
    public SecretMaterial Material { get; }
    /// <summary>Observation bound to the exact requested reference.</summary>
    public SecretObservation Observation { get; }
    /// <summary>Qualified raw resource identity and version, not expanded-content equality.</summary>
    public InfisicalSecretRevision Revision { get; }
    /// <summary>Disposes this read's material without modifying the remote secret.</summary>
    public void Dispose() => Material.Dispose();
    /// <summary>Returns a fixed label without material or coordinates.</summary>
    public override string ToString() => "[InfisicalSecretRead]";
}
