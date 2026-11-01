using Microsoft.Extensions.Configuration;
using SecretKit.Core;

namespace SecretKit.Extensions.Configuration;

/// <summary>Owns one prepared generation and its optional explicit string export.</summary>
public sealed class PreparedSecretConfiguration : IDisposable
{
    private readonly object _gate = new();
    private readonly SecretSnapshotLoader _loader;
    private readonly SecretSnapshotHandle _handle;
    private SecretConfigurationExport? _export;
    private IConfigurationRoot? _root;
    private bool _disposed;

    private PreparedSecretConfiguration(SecretSnapshotLoader loader, SecretSnapshotHandle handle)
    {
        _loader = loader;
        _handle = handle;
    }

    /// <summary>Asynchronously prepares material without exporting ordinary managed strings.</summary>
    /// <remarks>Owns the loader and one pinned generation; readers and transports remain borrowed.</remarks>
    /// <returns>A prepared owner or the original bounded collection failure.</returns>
    /// <exception cref="OperationCanceledException">The caller canceled preparation.</exception>
    public static async ValueTask<SecretOutcome<PreparedSecretConfiguration>> PrepareAsync(
        IEnumerable<SecretSelection> selections, TimeProvider? timeProvider = null,
        SecretCollectionOptions? options = null, CancellationToken cancellationToken = default)
    {
        var loader = new SecretSnapshotLoader(selections, timeProvider, options);
        try
        {
            SecretOutcome<long> outcome = await loader.RefreshAsync(cancellationToken).ConfigureAwait(false);
            if (!outcome.IsSuccess)
            {
                loader.Dispose();
                return SecretOutcome<PreparedSecretConfiguration>.Failure(outcome.Status, outcome.RetryAfter, outcome.Reason);
            }
            return SecretOutcome<PreparedSecretConfiguration>.Success(
                new PreparedSecretConfiguration(loader, loader.Acquire()));
        }
        catch
        {
            loader.Dispose();
            throw;
        }
    }

    /// <summary>Copies a present selected value into a caller-owned read.</summary>
    public SecretRead Read(string consumerKey)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _handle.Read(consumerKey);
        }
    }

    /// <summary>Copies a present selected value or returns explicit optional absence.</summary>
    public SecretOutcome<SecretRead> ReadOutcome(string consumerKey)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _handle.ReadOutcome(consumerKey);
        }
    }

    /// <summary>Explicitly exports ordinary managed strings once, returning a borrowed root.</summary>
    /// <remarks>The root belongs to this owner. Build and Load perform no reader I/O.</remarks>
    /// <exception cref="ArgumentException">A mapped selection is unknown or destinations collide.</exception>
    /// <exception cref="InvalidOperationException">This owner has already exported its generation.</exception>
    /// <exception cref="ObjectDisposedException">This owner was disposed.</exception>
    public IConfigurationRoot ExportAcknowledgingManagedStrings(IEnumerable<SecretConfigurationMapping> mapping)
    {
        ArgumentNullException.ThrowIfNull(mapping);
        // Enumerating host-supplied mappings may execute host code; do it outside the owner gate.
        SecretConfigurationMapping[] entries = mapping.ToArray();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_export is not null)
                throw new InvalidOperationException("Prepared configuration supports only one export.");
            SecretConfigurationExport export =
                SecretConfigurationExport.CreateAcknowledgingManagedStrings(_handle, entries);
            try
            {
                _root = new ConfigurationBuilder().Add(export).Build();
                _export = export;
                return _root;
            }
            catch
            {
                export.Dispose();
                throw;
            }
        }
    }

    /// <summary>Releases owned resources without disposing borrowed readers.</summary>
    public void Dispose()
    {
        IConfigurationRoot? root;
        SecretConfigurationExport? export;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            root = _root;
            export = _export;
            _root = null;
            _export = null;
        }
        // Framework registrations and callbacks must not run under the owner gate.
        try { (root as IDisposable)?.Dispose(); }
        finally
        {
            try { export?.Dispose(); }
            finally
            {
                _handle.Dispose();
                _loader.Dispose();
            }
        }
    }

    /// <summary>Returns a bounded description without selected keys, references or material.</summary>
    public override string ToString() => "[PreparedSecretConfiguration]";
}
