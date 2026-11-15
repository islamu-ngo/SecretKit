using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Supplies independent copies of one explicitly selected host credential.</summary>
/// <remarks>No JWT claims are interpreted, and no renewal or remote revocation is performed.</remarks>
public sealed class InfisicalSuppliedTokenSource : IInfisicalTokenSource, IDisposable
{
    private readonly object _gate = new();
    private readonly DateTimeOffset? _expiresAt;
    private readonly TimeProvider _time;
    private SecretMaterial? _material;

    /// <summary>Copies borrowed material into storage owned by this source.</summary>
    /// <param name="material">Host-owned input; neither construction nor disposal transfers its ownership.</param>
    /// <param name="expiresAt">Optional host expiry evidence; null means remote expiry is unobserved.</param>
    /// <param name="timeProvider">Clock used to evaluate supplied expiry; defaults to system time.</param>
    public InfisicalSuppliedTokenSource(SecretMaterial material, DateTimeOffset? expiresAt = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(material);
        _expiresAt = expiresAt;
        _time = timeProvider ?? TimeProvider.System;
        _material = material.Copy();
    }

    /// <summary>Returns a fresh caller-owned token, or Expired at or after the supplied expiry.</summary>
    /// <remarks>Copy publication and disposal share a lock. Disposal winning that lock rejects the copy;
    /// a published copy survives source disposal. The host clock runs outside the lock.</remarks>
    /// <exception cref="OperationCanceledException">Cancellation was observed before copying.</exception>
    /// <exception cref="ObjectDisposedException">The source was disposed before copying.</exception>
    public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
            ObjectDisposedException.ThrowIf(_material is null, this);

        DateTimeOffset? now = _expiresAt.HasValue ? _time.GetUtcNow() : null;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_material is null, this);
            cancellationToken.ThrowIfCancellationRequested();
            if (_expiresAt <= now)
                return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Failure(
                    SecretStatus.Expired, reason: SecretFailureReason.CredentialUnavailable));
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new InfisicalAccessToken(_material.Copy(), _expiresAt)));
        }
    }

    /// <summary>Clears only this source's copy; repeated disposal is harmless and never revokes remotely.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            _material?.Dispose();
            _material = null;
        }
    }

    /// <summary>Returns a fixed marker without credential material.</summary>
    public override string ToString() => "[InfisicalSuppliedTokenSource]";
}
