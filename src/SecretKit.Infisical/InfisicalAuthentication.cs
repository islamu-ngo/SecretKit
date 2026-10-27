using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Supplies an independent token copy from the explicitly selected host identity.</summary>
public interface IInfisicalTokenSource
{
    /// <summary>Returns a caller-owned token copy; cancellation must propagate without exposing credentials.</summary>
    ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken);
}

/// <summary>Owns a token copy. The caller-provided source retains its own credentials.</summary>
public sealed class InfisicalAccessToken : IDisposable
{
    /// <summary>Takes ownership of the supplied material without copying it; expiry is optional host evidence.</summary>
    public InfisicalAccessToken(SecretMaterial material, DateTimeOffset? expiresAt = null)
    {
        ArgumentNullException.ThrowIfNull(material);
        Material = material;
        ExpiresAt = expiresAt;
    }

    /// <summary>The owned token material; explicit reveal/export creates plaintext outside this wrapper.</summary>
    [JsonIgnore]
    public SecretMaterial Material { get; }

    /// <summary>The selected expiry, or null when no expiry evidence was supplied.</summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary>Disposes this token's material without revoking the remote credential.</summary>
    public void Dispose() => Material.Dispose();

    /// <summary>Returns a fixed label without token material.</summary>
    public override string ToString() => "[InfisicalAccessToken]";
}
