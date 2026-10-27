using System.Collections.ObjectModel;

namespace SecretKit.Core;

/// <summary>Enumerates metadata, not secret material or delivery permission.</summary>
public interface ISecretInventory
{
    /// <summary>Collects value-free observations within the selected authority and scope.</summary>
    /// <param name="scope">Provider-owned selection bound to the inventory adapter's authority.</param>
    /// <param name="cancellationToken">Cancels collection; cancellation propagates rather than becoming an absence.</param>
    /// <returns>A bounded collection or a failure status; success does not prove value-read permission.</returns>
    /// <exception cref="OperationCanceledException">Collection was cancelled.</exception>
    ValueTask<SecretOutcome<SecretInventory>> InspectAsync(
        SecretInventoryScope scope, CancellationToken cancellationToken = default);
}

/// <summary>A bounded collection window, never an implied remote point-in-time snapshot.</summary>
public sealed class SecretInventory
{
    /// <summary>Copies the observation sequence and records its collection window.</summary>
    /// <param name="items">Value-free observations; the sequence is copied, not the observation objects.</param>
    /// <param name="startedAt">Collection start time.</param>
    /// <param name="completedAt">Collection end time, at or after the start.</param>
    /// <param name="complete">Whether collection covered the full admitted scope without truncation.</param>
    /// <exception cref="ArgumentNullException"><paramref name="items"/> is null.</exception>
    /// <exception cref="ArgumentException">The end time precedes the start.</exception>
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

    /// <summary>Gets the read-only observation list captured at construction, without secret material.</summary>
    public IReadOnlyList<SecretObservation> Items { get; }

    /// <summary>Gets the start of the collection window.</summary>
    public DateTimeOffset StartedAt { get; }

    /// <summary>Gets the end of the collection window.</summary>
    public DateTimeOffset CompletedAt { get; }

    /// <summary>Gets whether collection is complete within its admitted scope, not whether delivery is authorized.</summary>
    public bool IsComplete { get; }

    /// <summary>Always returns false; collection does not establish simultaneous remote state.</summary>
    public bool IsPointInTime => false;

    /// <summary>Returns a fixed marker without enumerating observations or coordinates.</summary>
    public override string ToString() => "[SecretInventory]";
}
