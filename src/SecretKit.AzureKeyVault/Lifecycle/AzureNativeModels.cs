using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault;

/// <summary>Protected native metadata, without vendor DTOs or secret values.</summary>
public sealed class AzureSecretMetadata
{
    internal AzureSecretMetadata(SecretReference reference, bool? enabled, DateTimeOffset? notBefore,
        DateTimeOffset? expiresOn, DateTimeOffset? createdOn, DateTimeOffset? updatedOn,
        string? contentType, IDictionary<string, string> tags,
        DateTimeOffset? deletedOn = null, DateTimeOffset? scheduledPurgeOn = null)
    {
        Reference = reference;
        Enabled = enabled;
        NotBefore = notBefore;
        ExpiresOn = expiresOn;
        CreatedOn = createdOn;
        UpdatedOn = updatedOn;
        ContentType = contentType;
        Tags = new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(tags));
        DeletedOn = deletedOn;
        ScheduledPurgeOn = scheduledPurgeOn;
    }

    /// <summary>Gets the authority-bound reference observed in the response.</summary>
    [JsonIgnore] public SecretReference Reference { get; }
    /// <summary>Gets the native enabled flag, or null when the service omitted it.</summary>
    [JsonIgnore] public bool? Enabled { get; }
    /// <summary>Gets the native earliest-use time, if supplied.</summary>
    [JsonIgnore] public DateTimeOffset? NotBefore { get; }
    /// <summary>Gets the native expiry time, if supplied.</summary>
    [JsonIgnore] public DateTimeOffset? ExpiresOn { get; }
    /// <summary>Gets the service-reported creation time, if supplied.</summary>
    [JsonIgnore] public DateTimeOffset? CreatedOn { get; }
    /// <summary>Gets the service-reported update time, if supplied.</summary>
    [JsonIgnore] public DateTimeOffset? UpdatedOn { get; }
    /// <summary>Gets protected content-type metadata, if supplied.</summary>
    [JsonIgnore] public string? ContentType { get; }
    /// <summary>Gets a copied, read-only tag map; values remain protected metadata.</summary>
    [JsonIgnore] public IReadOnlyDictionary<string, string> Tags { get; }
    /// <summary>Gets the reported soft-deletion time, if this is a deleted-secret observation.</summary>
    [JsonIgnore] public DateTimeOffset? DeletedOn { get; }
    /// <summary>Gets the reported scheduled purge time, not a guarantee of immediate disappearance.</summary>
    [JsonIgnore] public DateTimeOffset? ScheduledPurgeOn { get; }
    /// <summary>Returns a marker without metadata or coordinates.</summary>
    public override string ToString() => "[AzureSecretMetadata]";
}

/// <summary>Bounded observations collected over a window, never a remote snapshot.</summary>
public sealed class AzureNativeInventory
{
    internal AzureNativeInventory(IEnumerable<AzureSecretMetadata> items, DateTimeOffset startedAt,
        DateTimeOffset completedAt, bool isComplete)
    {
        Items = Array.AsReadOnly(items.ToArray());
        StartedAt = startedAt;
        CompletedAt = completedAt;
        IsComplete = isComplete;
    }

    /// <summary>Gets the copied observations, which may span concurrent remote changes.</summary>
    [JsonIgnore] public IReadOnlyList<AzureSecretMetadata> Items { get; }
    /// <summary>Gets the local start of the collection window.</summary>
    public DateTimeOffset StartedAt { get; }
    /// <summary>Gets the local end of the collection window.</summary>
    public DateTimeOffset CompletedAt { get; }
    /// <summary>Gets whether enumeration ended without exhausting local bounds.</summary>
    public bool IsComplete { get; }
    /// <summary>Returns a marker without collected metadata.</summary>
    public override string ToString() => "[AzureNativeInventory]";
}

/// <summary>Exact-version attribute patch. Null fields are omitted, not cleared. Tags are copied.</summary>
public sealed class AzureUpdatePropertiesRequest
{
    /// <summary>Copies a bounded patch for one exact secret version without changing its value.</summary>
    /// <param name="target">The owning client's exact-version reference.</param>
    /// <param name="enabled">The enabled value to set, or null to omit it.</param>
    /// <param name="notBefore">The earliest-use time to set, or null to omit it.</param>
    /// <param name="expiresOn">The expiry time to set, or null to omit it.</param>
    /// <param name="contentType">Content-type metadata to set, or null to omit it.</param>
    /// <param name="tags">A tag map to copy, or null to omit tag changes.</param>
    /// <param name="precondition">The requested condition; only None is supported by execution.</param>
    /// <exception cref="ArgumentNullException">The target is null.</exception>
    /// <exception cref="ArgumentException">Metadata exceeds the local byte or tag-count budget.</exception>
    public AzureUpdatePropertiesRequest(SecretReference target, bool? enabled = null,
        DateTimeOffset? notBefore = null, DateTimeOffset? expiresOn = null, string? contentType = null,
        IReadOnlyDictionary<string, string>? tags = null,
        AzureSetSecretPrecondition precondition = AzureSetSecretPrecondition.None)
    {
        ArgumentNullException.ThrowIfNull(target);
        // Local metadata envelope budget, independent of the service's tag policy.
        // Check before copying an untrusted map or letting the SDK build its JSON.
        const int maximumMetadataBytes = 64 * 1024;
        long metadataBytes = contentType is null ? 0 : Encoding.UTF8.GetByteCount(contentType);
        if (metadataBytes > maximumMetadataBytes || tags is { Count: > 128 })
            throw new ArgumentException("Native metadata exceeds the local request budget.");
        if (tags is not null)
        {
            foreach (var pair in tags)
            {
                metadataBytes += Encoding.UTF8.GetByteCount(pair.Key) + Encoding.UTF8.GetByteCount(pair.Value);
                if (metadataBytes > maximumMetadataBytes)
                    throw new ArgumentException("Native metadata exceeds the local request budget.");
            }
        }
        Target = target;
        Enabled = enabled;
        NotBefore = notBefore;
        ExpiresOn = expiresOn;
        ContentType = contentType;
        Tags = tags is null ? null : new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(tags));
        Precondition = precondition;
    }

    /// <summary>Gets the protected exact-version patch target.</summary>
    [JsonIgnore] public SecretReference Target { get; }
    /// <summary>Gets the enabled value to send, or null for omission.</summary>
    [JsonIgnore] public bool? Enabled { get; }
    /// <summary>Gets the earliest-use time to send, or null for omission.</summary>
    [JsonIgnore] public DateTimeOffset? NotBefore { get; }
    /// <summary>Gets the expiry time to send, or null for omission.</summary>
    [JsonIgnore] public DateTimeOffset? ExpiresOn { get; }
    /// <summary>Gets content-type metadata to send, or null for omission.</summary>
    [JsonIgnore] public string? ContentType { get; }
    /// <summary>Gets the copied tag map, or null for omission.</summary>
    [JsonIgnore] public IReadOnlyDictionary<string, string>? Tags { get; }
    /// <summary>Gets the caller's required update condition.</summary>
    [JsonIgnore] public AzureSetSecretPrecondition Precondition { get; }
    /// <summary>Returns a marker without patch contents.</summary>
    public override string ToString() => "[AzureUpdatePropertiesRequest]";
}

/// <summary>Native lifecycle knowledge from an accepted start or an explicit availability observation.</summary>
public enum AzureLifecycleState
{
    /// <summary>The service acknowledged a start; completion has not been observed.</summary>
    Pending,
    /// <summary>An explicit read observed the expected state; attribution to this caller is not established.</summary>
    Applied
}

/// <summary>The native all-version secret lifecycle action selected by the caller.</summary>
public enum AzureLifecycleKind
{
    /// <summary>Move a secret into the deleted-secret collection.</summary>
    Delete,
    /// <summary>Recover a soft-deleted secret into the active collection.</summary>
    Recover
}

/// <summary>Local status selector from an observed start, not a durable or uniquely attributable service ID.</summary>
public sealed class AzureLifecycleOperation
{
    internal AzureLifecycleOperation(SecretReference target, AzureLifecycleKind kind)
    {
        Target = target;
        Kind = kind;
    }

    /// <summary>Gets the protected target bound to the accepted lifecycle start.</summary>
    [JsonIgnore] public SecretReference Target { get; }
    /// <summary>Gets which native availability state a status check will observe.</summary>
    public AzureLifecycleKind Kind { get; }
    /// <summary>Returns a marker without target coordinates.</summary>
    public override string ToString() => "[AzureLifecycleOperation]";
}

/// <summary>An acknowledged lifecycle start or subsequent bounded availability observation.</summary>
public sealed class AzureLifecycleResult
{
    internal AzureLifecycleResult(AzureLifecycleOperation operation, AzureLifecycleState state,
        AzureSecretMetadata? metadata)
    {
        Operation = operation;
        State = state;
        Metadata = metadata;
    }

    /// <summary>Gets the local selector for explicit follow-up observations.</summary>
    [JsonIgnore] public AzureLifecycleOperation Operation { get; }
    /// <summary>Gets the observed lifecycle state without changing the original mutation receipt.</summary>
    public AzureLifecycleState State { get; }
    /// <summary>Gets observed native metadata when available, otherwise null.</summary>
    [JsonIgnore] public AzureSecretMetadata? Metadata { get; }
    /// <summary>Returns only the lifecycle category.</summary>
    public override string ToString() => $"[AzureLifecycleResult:{State}]";
}

/// <summary>Service acknowledgement of purge, not proof of immediate global disappearance.</summary>
public sealed class AzurePurgeResult
{
    internal AzurePurgeResult() { }
    /// <summary>Returns a marker without purged coordinates.</summary>
    public override string ToString() => "[AzurePurgeResult]";
}

/// <summary>
/// Independently owned encrypted Azure backup bytes. Export creates a caller-owned copy.
/// Azure enforces subscription/geography restore restrictions; this is not a portable export.
/// </summary>
public sealed class AzureSecretBackup : IDisposable
{
    private readonly object _gate = new();
    private byte[]? _bytes;

    private AzureSecretBackup(ReadOnlySpan<byte> bytes) => _bytes = bytes.ToArray();

    /// <summary>Copies opaque encrypted backup bytes into an independently disposable owner.</summary>
    /// <param name="bytes">Nonempty backup bytes, at most 16 MiB; authenticity is not checked locally.</param>
    /// <returns>A new owner; the caller retains responsibility for the input storage.</returns>
    /// <exception cref="ArgumentException">The backup size is outside the local bound.</exception>
    public static AzureSecretBackup FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < 1 or > 16 * 1024 * 1024)
        {
            throw new ArgumentException("Backup size is outside the supported bound.", nameof(bytes));
        }
        return new AzureSecretBackup(bytes);
    }

    /// <summary>Creates an independent byte array that the caller must protect and clear.</summary>
    /// <returns>A copy of the encrypted native artifact.</returns>
    /// <exception cref="ObjectDisposedException">This backup has been disposed.</exception>
    public byte[] Export()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_bytes is null, this);
            return _bytes.ToArray();
        }
    }

    /// <summary>Creates a separate owner with its own disposable copy of the artifact.</summary>
    /// <returns>An independently owned backup.</returns>
    /// <exception cref="ObjectDisposedException">This backup has been disposed.</exception>
    public AzureSecretBackup Copy()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_bytes is null, this);
            return new AzureSecretBackup(_bytes);
        }
    }

    /// <summary>Clears this owner's bytes; previously exported arrays and copies remain caller-owned.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_bytes is not null)
            {
                CryptographicOperations.ZeroMemory(_bytes);
                _bytes = null;
            }
        }
    }

    /// <summary>Returns a marker without backup bytes.</summary>
    public override string ToString() => "[AzureSecretBackup]";
}

/// <summary>
/// Restore an opaque artifact into the fixed vault, expecting this unversioned name.
/// The service chooses the name from the artifact; this target is validation, not rename or CAS.
/// </summary>
public sealed class AzureRestoreSecretRequest
{
    /// <summary>Describes restoration while borrowing an opaque backup; it does not rename the artifact.</summary>
    /// <param name="target">The owning client's unversioned reference expected in the restored response.</param>
    /// <param name="backup">Caller-owned backup that must remain usable through execution.</param>
    /// <param name="precondition">The requested condition; only None is supported.</param>
    /// <exception cref="ArgumentNullException">The target or backup is null.</exception>
    public AzureRestoreSecretRequest(SecretReference target, AzureSecretBackup backup,
        AzureSetSecretPrecondition precondition = AzureSetSecretPrecondition.None)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(backup);
        Target = target;
        Backup = backup;
        Precondition = precondition;
    }

    /// <summary>Gets the protected expected restored target, not a service-side rename instruction.</summary>
    [JsonIgnore] public SecretReference Target { get; }
    /// <summary>Gets the borrowed backup; this request does not dispose it.</summary>
    [JsonIgnore] public AzureSecretBackup Backup { get; }
    /// <summary>Gets the caller's required restore condition.</summary>
    [JsonIgnore] public AzureSetSecretPrecondition Precondition { get; }
    /// <summary>Returns a marker without target or backup content.</summary>
    public override string ToString() => "[AzureRestoreSecretRequest]";
}
