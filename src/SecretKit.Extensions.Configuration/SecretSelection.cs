using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Extensions.Configuration;

/// <summary>Explicitly selects one required consumer key and its reader authority.</summary>
public sealed class SecretSelection
{
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

    [JsonIgnore]
    public string ConsumerKey { get; }
    [JsonIgnore]
    public ISecretReader Reader { get; }
    [JsonIgnore]
    public SecretReference Reference { get; }

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

    public DateTimeOffset StartedAt { get; }
    public DateTimeOffset CompletedAt { get; }
    public SecretStatus Status { get; }
    public TimeSpan? RetryAfter { get; }
    public bool WasCanceled { get; }
    public override string ToString() => $"[SecretCollectionAttempt:{Status}]";
}
