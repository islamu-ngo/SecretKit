using System.Collections.ObjectModel;

namespace SecretKit.Core;

/// <summary>Enumerates metadata, not secret material or delivery permission.</summary>
public interface ISecretInventory
{
    ValueTask<SecretOutcome<SecretInventory>> InspectAsync(
        SecretInventoryScope scope, CancellationToken cancellationToken = default);
}

/// <summary>A bounded collection window, never an implied remote point-in-time snapshot.</summary>
public sealed class SecretInventory
{
    public SecretInventory(IEnumerable<SecretObservation> items, DateTimeOffset startedAt,
        DateTimeOffset completedAt, bool complete)
    {
        ArgumentNullException.ThrowIfNull(items);
        if (completedAt < startedAt)
        {
            throw new ArgumentException("Collection end precedes start.", nameof(completedAt));
        }

        Items = new ReadOnlyCollection<SecretObservation>(items.ToArray());
        StartedAt = startedAt;
        CompletedAt = completedAt;
        IsComplete = complete;
    }

    public IReadOnlyList<SecretObservation> Items { get; }

    public DateTimeOffset StartedAt { get; }

    public DateTimeOffset CompletedAt { get; }

    public bool IsComplete { get; }

    public bool IsPointInTime => false;

    public override string ToString() => "[SecretInventory]";
}
