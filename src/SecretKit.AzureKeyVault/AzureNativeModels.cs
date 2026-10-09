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

    [JsonIgnore] public SecretReference Reference { get; }
    [JsonIgnore] public bool? Enabled { get; }
    [JsonIgnore] public DateTimeOffset? NotBefore { get; }
    [JsonIgnore] public DateTimeOffset? ExpiresOn { get; }
    [JsonIgnore] public DateTimeOffset? CreatedOn { get; }
    [JsonIgnore] public DateTimeOffset? UpdatedOn { get; }
    [JsonIgnore] public string? ContentType { get; }
    [JsonIgnore] public IReadOnlyDictionary<string, string> Tags { get; }
    [JsonIgnore] public DateTimeOffset? DeletedOn { get; }
    [JsonIgnore] public DateTimeOffset? ScheduledPurgeOn { get; }
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

    [JsonIgnore] public IReadOnlyList<AzureSecretMetadata> Items { get; }
    public DateTimeOffset StartedAt { get; }
    public DateTimeOffset CompletedAt { get; }
    public bool IsComplete { get; }
    public override string ToString() => "[AzureNativeInventory]";
}

/// <summary>Exact-version attribute patch. Null fields are omitted, not cleared. Tags are copied.</summary>
public sealed class AzureUpdatePropertiesRequest
{
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

    [JsonIgnore] public SecretReference Target { get; }
    [JsonIgnore] public bool? Enabled { get; }
    [JsonIgnore] public DateTimeOffset? NotBefore { get; }
    [JsonIgnore] public DateTimeOffset? ExpiresOn { get; }
    [JsonIgnore] public string? ContentType { get; }
    [JsonIgnore] public IReadOnlyDictionary<string, string>? Tags { get; }
    [JsonIgnore] public AzureSetSecretPrecondition Precondition { get; }
    public override string ToString() => "[AzureUpdatePropertiesRequest]";
}

public enum AzureLifecycleState
{
    Pending,
    Applied
}

public enum AzureLifecycleKind
{
    Delete,
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

    [JsonIgnore] public SecretReference Target { get; }
    public AzureLifecycleKind Kind { get; }
    public override string ToString() => "[AzureLifecycleOperation]";
}

public sealed class AzureLifecycleResult
{
    internal AzureLifecycleResult(AzureLifecycleOperation operation, AzureLifecycleState state,
        AzureSecretMetadata? metadata)
    {
        Operation = operation;
        State = state;
        Metadata = metadata;
    }

    [JsonIgnore] public AzureLifecycleOperation Operation { get; }
    public AzureLifecycleState State { get; }
    [JsonIgnore] public AzureSecretMetadata? Metadata { get; }
    public override string ToString() => $"[AzureLifecycleResult:{State}]";
}

/// <summary>Service acknowledgement of purge, not proof of immediate global disappearance.</summary>
public sealed class AzurePurgeResult
{
    internal AzurePurgeResult() { }
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

    public static AzureSecretBackup FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < 1 or > 16 * 1024 * 1024)
        {
            throw new ArgumentException("Backup size is outside the supported bound.", nameof(bytes));
        }
        return new AzureSecretBackup(bytes);
    }

    public byte[] Export()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_bytes is null, this);
            return _bytes.ToArray();
        }
    }

    public AzureSecretBackup Copy()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_bytes is null, this);
            return new AzureSecretBackup(_bytes);
        }
    }

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

    public override string ToString() => "[AzureSecretBackup]";
}

/// <summary>
/// Restore an opaque artifact into the fixed vault, expecting this unversioned name.
/// The service chooses the name from the artifact; this target is validation, not rename or CAS.
/// </summary>
public sealed class AzureRestoreSecretRequest
{
    public AzureRestoreSecretRequest(SecretReference target, AzureSecretBackup backup,
        AzureSetSecretPrecondition precondition = AzureSetSecretPrecondition.None)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(backup);
        Target = target;
        Backup = backup;
        Precondition = precondition;
    }

    [JsonIgnore] public SecretReference Target { get; }
    [JsonIgnore] public AzureSecretBackup Backup { get; }
    [JsonIgnore] public AzureSetSecretPrecondition Precondition { get; }
    public override string ToString() => "[AzureRestoreSecretRequest]";
}
