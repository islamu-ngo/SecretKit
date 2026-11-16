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

internal sealed class InfisicalAuthTransportLease(InfisicalTransportBinding binding) : IDisposable
{
    private readonly Lock _gate = new();
    private int _active;
    private bool _disposed;

    internal void ThrowIfDisposed(object owner)
    {
        lock (_gate) ObjectDisposedException.ThrowIf(_disposed, owner);
    }

    internal void BeginOperation(object owner, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, owner);
            _active++;
        }
    }

    internal void EndOperation()
    {
        bool release;
        lock (_gate)
        {
            _active--;
            release = _disposed && _active == 0;
        }
        if (release) binding.Dispose();
    }

    public void Dispose()
    {
        bool release;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            release = _active == 0;
        }
        if (release) binding.Dispose();
    }
}
