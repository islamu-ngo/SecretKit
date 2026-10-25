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

    [JsonIgnore]
    public SecretMaterial Material { get; }
    public SecretObservation Observation { get; }
    public InfisicalSecretRevision Revision { get; }
    public void Dispose() => Material.Dispose();
    public override string ToString() => "[InfisicalSecretRead]";
}
