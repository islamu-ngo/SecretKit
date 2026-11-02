using SecretKit.Core;

namespace SecretKit.Extensions.Configuration;

/// <summary>
/// Pins one local generation for a logical multi-key operation. Reads return independent
/// caller-owned copies; disposing the handle does not dispose copies already returned.
/// </summary>
public sealed class SecretSnapshotHandle : IDisposable
{
    private readonly object _gate = new();
    private SecretSnapshotGeneration? _storage;

    internal SecretSnapshotHandle(SecretSnapshotGeneration storage)
    {
        _storage = storage;
        Generation = storage.Generation;
        CollectionStartedAt = storage.StartedAt;
        CollectionCompletedAt = storage.CompletedAt;
        Count = storage.Count;
        SelectionCount = storage.SelectionCount;
    }

    /// <summary>The loader-local generation number pinned by this handle, not a provider revision.</summary>
    public long Generation { get; }
    /// <summary>The injected-clock time when this generation's collection began.</summary>
    public DateTimeOffset CollectionStartedAt { get; }
    /// <summary>The injected-clock time when all required reads completed.</summary>
    public DateTimeOffset CollectionCompletedAt { get; }
    /// <summary>The number of present consumer selections retained by this generation.</summary>
    public int Count { get; }
    /// <summary>The number of declared selections, including absent optional selections.</summary>
    public int SelectionCount { get; }

    /// <summary>Copies material and preserves actual provider observation metadata.</summary>
    /// <returns>An independent read that the caller must dispose.</returns>
    /// <exception cref="ObjectDisposedException">This handle was disposed.</exception>
    /// <exception cref="ArgumentException">The key is not part of this generation.</exception>
    public SecretRead Read(string consumerKey)
    {
        SecretOutcome<SecretRead> outcome = ReadOutcome(consumerKey);
        return outcome.IsSuccess ? outcome.Value :
            throw new InvalidOperationException("Selected value is absent from this generation.");
    }

    /// <summary>Returns an owned read or explicit absence for a declared key.</summary>
    public SecretOutcome<SecretRead> ReadOutcome(string consumerKey)
    {
        ArgumentNullException.ThrowIfNull(consumerKey);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_storage is null, this);
            return _storage.ReadOutcome(consumerKey);
        }
    }

    internal void ValidateKeys(IEnumerable<string> keys)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_storage is null, this);
            foreach (string key in keys) _storage.ValidateKey(key);
        }
    }

    /// <summary>Releases this pin; generation storage clears after its final publication or handle owner releases it.</summary>
    /// <remarks>Already returned reads remain independently usable and caller-owned.</remarks>
    public void Dispose()
    {
        lock (_gate)
        {
            _storage?.Release();
            _storage = null;
        }
    }

    /// <summary>Returns a bounded description without generation values or selected coordinates.</summary>
    public override string ToString() => "[SecretSnapshotHandle]";
}

internal sealed class SecretSnapshotGeneration
{
    private readonly object _gate = new();
    private readonly Dictionary<string, SecretRead?> _entries;
    // One initial reference belongs to the current-publication pointer.
    private int _references = 1;

    internal SecretSnapshotGeneration(long generation, Dictionary<string, SecretRead?> entries,
        DateTimeOffset startedAt, DateTimeOffset completedAt)
    {
        Generation = generation;
        _entries = entries;
        StartedAt = startedAt;
        CompletedAt = completedAt;
    }

    internal long Generation { get; }
    internal DateTimeOffset StartedAt { get; }
    internal DateTimeOffset CompletedAt { get; }
    internal int Count => _entries.Values.Count(read => read is not null);
    internal int SelectionCount => _entries.Count;

    // Only the loader's current-pointer lock can acquire a new reference.
    internal SecretSnapshotHandle Acquire()
    {
        lock (_gate)
        {
            _references++;
            return new SecretSnapshotHandle(this);
        }
    }

    internal void ValidateKey(string key)
    {
        if (!_entries.ContainsKey(key))
            throw new ArgumentException("Consumer key is not in this generation.");
    }

    internal SecretOutcome<SecretRead> ReadOutcome(string key)
    {
        lock (_gate)
        {
            ValidateKey(key);
            SecretRead? read = _entries[key];
            return read is null ? SecretOutcome<SecretRead>.Failure(SecretStatus.Absent) :
                SecretOutcome<SecretRead>.Success(new SecretRead(read.Material.Copy(), read.Observation));
        }
    }

    internal void Release()
    {
        lock (_gate)
        {
            if (--_references != 0) return;
            foreach (SecretRead? read in _entries.Values) read?.Dispose();
            _entries.Clear();
        }
    }
}
