using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Extensions.Configuration;

/// <summary>Explicitly selects one required consumer key and its reader authority.</summary>
public sealed class SecretSelection
{
    /// <summary>Binds a nonblank consumer key to the exact reader-owned reference, without reading it.</summary>
    /// <exception cref="ArgumentException">The key is blank or the reference has a different authority.</exception>
    public SecretSelection(string consumerKey, ISecretReader reader, SecretReference reference)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(consumerKey);
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(reference);
        if (!reference.BelongsTo(reader.Authority))
            throw new ArgumentException("Reference does not belong to the selected reader.");
        ConsumerKey = consumerKey;
        Reader = reader;
        Reference = reference;
    }

    /// <summary>The protected, case-sensitive key used to retrieve this selection from a generation.</summary>
    [JsonIgnore]
    public string ConsumerKey { get; }
    /// <summary>The borrowed reader; the loader never disposes it or selects another identity.</summary>
    [JsonIgnore]
    public ISecretReader Reader { get; }
    /// <summary>The exact reference that successful reader observations must preserve.</summary>
    [JsonIgnore]
    public SecretReference Reference { get; }

    /// <summary>Returns a bounded description without selected keys or coordinates.</summary>
    public override string ToString() => "[SecretSelection]";
}

/// <summary>Bounded evidence for the last collection; contains no key or provider exception.</summary>
public sealed class SecretCollectionAttempt
{
    internal SecretCollectionAttempt(DateTimeOffset started, DateTimeOffset completed,
        SecretStatus status, TimeSpan? retryAfter = null, bool wasCanceled = false)
    {
        StartedAt = started;
        CompletedAt = completed;
        Status = status;
        RetryAfter = retryAfter;
        WasCanceled = wasCanceled;
    }

    /// <summary>The injected-clock time immediately before this serialized collection.</summary>
    public DateTimeOffset StartedAt { get; }
    /// <summary>The injected-clock time when this attempt completed or was recorded as canceled.</summary>
    public DateTimeOffset CompletedAt { get; }
    /// <summary>The bounded collection outcome; failure never replaces the published generation.</summary>
    public SecretStatus Status { get; }
    /// <summary>The reader's optional retry advice, not an automatic retry or timer.</summary>
    public TimeSpan? RetryAfter { get; }
    /// <summary>Whether collection cancellation propagated instead of returning an ordinary outcome.</summary>
    public bool WasCanceled { get; }
    /// <summary>Returns only bounded collection status, without keys or provider diagnostics.</summary>
    public override string ToString() => $"[SecretCollectionAttempt:{Status}]";
}
