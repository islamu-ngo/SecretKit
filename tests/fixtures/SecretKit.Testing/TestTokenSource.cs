using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Testing;

/// <summary>Test-only token rotation and expiry without a remote identity or clock delays.</summary>
public sealed class TestTokenSource(TimeProvider? clock = null) : IInfisicalTokenSource, IDisposable
{
    private readonly object _gate = new();
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private SecretMaterial? _material;
    private DateTimeOffset _expiresAt;
    private bool _disposed;

    public void Rotate(SecretMaterial material, DateTimeOffset expiresAt)
    {
        ArgumentNullException.ThrowIfNull(material);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            SecretMaterial copy = material.Copy();
            _material?.Dispose();
            _material = copy;
            _expiresAt = expiresAt;
        }
    }

    public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_material is null)
                return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Failure(SecretStatus.Denied));
            if (_clock.GetUtcNow() >= _expiresAt)
                return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Failure(SecretStatus.Expired));
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(_material.Copy(), _expiresAt)));
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _material?.Dispose();
            _material = null;
        }
    }
}
