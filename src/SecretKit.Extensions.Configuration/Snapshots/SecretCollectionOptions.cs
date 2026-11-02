namespace SecretKit.Extensions.Configuration;

/// <summary>Explicit work and payload bounds for one serialized collection.</summary>
public sealed class SecretCollectionOptions
{
    /// <summary>Sets collection bounds. Timeout begins after serialized admission.</summary>
    public SecretCollectionOptions(int maximumConcurrency = 1, int maximumSelections = 1000,
        int maximumMaterialBytes = 16 * 1024 * 1024, TimeSpan? collectionTimeout = null)
    {
        if (maximumConcurrency is < 1 or > 32)
            throw new ArgumentOutOfRangeException(nameof(maximumConcurrency), "Concurrency must be from 1 through 32.");
        if (maximumSelections is < 1 or > 10000)
            throw new ArgumentOutOfRangeException(nameof(maximumSelections), "Selections must be from 1 through 10000.");
        if (maximumMaterialBytes is < 1024 or > 64 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(maximumMaterialBytes), "Payload limit must be from 1 KiB through 64 MiB.");
        if (collectionTimeout is { } timeout && (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(10)))
            throw new ArgumentOutOfRangeException(nameof(collectionTimeout), "Timeout must be positive and at most ten minutes.");
        MaximumConcurrency = maximumConcurrency;
        MaximumSelections = maximumSelections;
        MaximumMaterialBytes = maximumMaterialBytes;
        CollectionTimeout = collectionTimeout ?? TimeSpan.FromMinutes(1);
    }

    /// <summary>The maximum unresolved or staged reads, from 1 through 32.</summary>
    public int MaximumConcurrency { get; }
    /// <summary>The maximum declared selections, from 1 through 10000.</summary>
    public int MaximumSelections { get; }
    /// <summary>The maximum candidate UTF-8 payload bytes, not a process heap limit.</summary>
    public int MaximumMaterialBytes { get; }
    /// <summary>The cooperative collection deadline, positive and at most ten minutes.</summary>
    public TimeSpan CollectionTimeout { get; }
}
