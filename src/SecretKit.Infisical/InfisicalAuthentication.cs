using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Supplies an independent token copy from the explicitly selected host identity.</summary>
public interface IInfisicalTokenSource
{
    ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken);
}

/// <summary>Owns a token copy. The caller-provided source retains its own credentials.</summary>
public sealed class InfisicalAccessToken : IDisposable
{
    public InfisicalAccessToken(SecretMaterial material, DateTimeOffset? expiresAt = null)
    {
        ArgumentNullException.ThrowIfNull(material);
        Material = material;
        ExpiresAt = expiresAt;
    }

    [JsonIgnore]
    public SecretMaterial Material { get; }

    public DateTimeOffset? ExpiresAt { get; }

    public void Dispose() => Material.Dispose();

    public override string ToString() => "[InfisicalAccessToken]";
}
