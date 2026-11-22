using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Internal;

namespace SecretKit.Infisical;

/// <summary>Whether metadata describes a direct resource or an unresolved imported candidate.</summary>
public enum InfisicalInventoryOrigin
{
    /// <summary>A resource in the selected direct folder.</summary>
    Direct,
    /// <summary>An imported candidate, not a local writable resource or effective winner.</summary>
    Imported
}

/// <summary>Closed reasons why the selected visible view could not be fully established.</summary>
public enum InfisicalInventoryIncompleteReason
{
    /// <summary>The aggregate entry allowance was exhausted.</summary>
    ItemLimit,
    /// <summary>The aggregate folder allowance was exhausted.</summary>
    FolderLimit,
    /// <summary>The aggregate request allowance was exhausted.</summary>
    RequestLimit,
    /// <summary>A response or aggregate consumed-body byte allowance was exceeded.</summary>
    ByteLimit,
    /// <summary>Children remain beyond the selected depth.</summary>
    DepthLimit,
    /// <summary>A selected child could not be enumerated.</summary>
    FolderFailure,
    /// <summary>Returned evidence did not establish direct-child ancestry.</summary>
    AncestryUnestablished,
    /// <summary>A direct row lacks the evidence required for a native revision.</summary>
    RevisionUnestablished,
    /// <summary>Returned import source evidence is missing or malformed.</summary>
    ImportProvenanceUnestablished
}

/// <summary>An authority-bound, value-free selection with operation-wide resource limits.</summary>
public sealed class InfisicalInventorySelection : SecretInventoryScope
{
    /// <summary>Selects a visible folder view; recursive selection requires the expected environment UUID.</summary>
    /// <remarks>Timeout defaults to the client's operation timeout and cannot exceed it.
    /// Folder count includes the selected root. Depth zero still checks for child presence.</remarks>
    public InfisicalInventorySelection(SecretAuthority authority, string projectId, string environment,
        string folder, bool recursive = false, string? environmentId = null, bool includeImports = false,
        int maximumItems = 1000, int maximumFolders = 100, int maximumRequests = 100,
        int maximumResponseBytes = 1024 * 1024, int maximumDepth = 20, TimeSpan? timeout = null) : base(authority)
    {
        InfisicalNativeAddress.NativeText(projectId);
        InfisicalNativeAddress.NativeText(environment);
        if (!CanonicalPath(folder)) throw new ArgumentException("A canonical absolute folder is required.", nameof(folder));
        if (recursive && environmentId is null || environmentId is not null && !Guid.TryParse(environmentId, out _))
            throw new ArgumentException("Recursive inventory requires an environment UUID.", nameof(environmentId));
        if (maximumItems is < 1 or > 10000) throw new ArgumentOutOfRangeException(nameof(maximumItems));
        if (maximumFolders is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(maximumFolders));
        if (maximumRequests is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(maximumRequests));
        if (!TransferLimits.IsValidByteBudget(maximumResponseBytes)) throw new ArgumentOutOfRangeException(nameof(maximumResponseBytes));
        if (maximumDepth is < 0 or > 20) throw new ArgumentOutOfRangeException(nameof(maximumDepth));
        if (timeout is { } duration && (!TransferLimits.IsValidTimeout(duration)))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        ProjectId = projectId;
        Environment = environment;
        Folder = folder;
        Recursive = recursive;
        EnvironmentId = environmentId;
        IncludeImports = includeImports;
        MaximumItems = maximumItems;
        MaximumFolders = maximumFolders;
        MaximumRequests = maximumRequests;
        MaximumResponseBytes = maximumResponseBytes;
        MaximumDepth = maximumDepth;
        Timeout = timeout;
    }

    /// <summary>The protected selected project.</summary>
    [JsonIgnore] public string ProjectId { get; }
    /// <summary>The protected selected environment slug.</summary>
    [JsonIgnore] public string Environment { get; }
    /// <summary>The protected canonical selected root.</summary>
    [JsonIgnore] public string Folder { get; }
    /// <summary>Whether direct-child folders are traversed serially.</summary>
    [JsonIgnore] public bool Recursive { get; }
    /// <summary>The expected environment UUID for folder response validation.</summary>
    [JsonIgnore] public string? EnvironmentId { get; }
    /// <summary>Whether the value-free list includes unresolved import groups.</summary>
    [JsonIgnore] public bool IncludeImports { get; }
    /// <summary>The aggregate direct and imported entry allowance.</summary>
    [JsonIgnore] public int MaximumItems { get; }
    /// <summary>The aggregate folder allowance, including the root.</summary>
    [JsonIgnore] public int MaximumFolders { get; }
    /// <summary>The aggregate transport request allowance.</summary>
    [JsonIgnore] public int MaximumRequests { get; }
    /// <summary>The aggregate consumed-body byte allowance, including discarded fields and failures.</summary>
    [JsonIgnore] public int MaximumResponseBytes { get; }
    /// <summary>The maximum child depth relative to the selected root.</summary>
    [JsonIgnore] public int MaximumDepth { get; }
    /// <summary>The optional whole-operation timeout, bounded by the client timeout.</summary>
    [JsonIgnore] public TimeSpan? Timeout { get; }

    internal static bool CanonicalPath(string? path) =>
        path is { Length: > 0 and <= 1024 } && path[0] == '/' &&
        (path == "/" || path[1..].Split('/').All(Segment));

    internal static bool Segment(string name) => !string.IsNullOrWhiteSpace(name) && name is not ("." or "..") &&
        !name.Any(character => char.IsControl(character) || character is '/' or '\\' or '%');
}

/// <summary>Protected metadata only; imported candidates never contain a direct reference or revision.</summary>
public sealed class InfisicalInventoryEntry
{
    internal InfisicalInventoryEntry(string key, string folder, InfisicalInventoryOrigin origin,
        SecretReference? reference, InfisicalSecretRevision? revision, string? version, DateTimeOffset observedAt,
        DateTimeOffset? modifiedAt, IReadOnlyList<string>? tagIds, bool? isRotatedSecret,
        string? sourceEnvironment = null, string? sourcePath = null)
    {
        Key = key;
        Folder = folder;
        Origin = origin;
        Reference = reference;
        Revision = revision;
        Version = version;
        ObservedAt = observedAt;
        ModifiedAt = modifiedAt;
        TagIds = tagIds;
        IsRotatedSecret = isRotatedSecret;
        SourceEnvironment = sourceEnvironment;
        SourcePath = sourcePath;
    }

    /// <summary>The protected returned secret key.</summary>
    [JsonIgnore] public string Key { get; }
    /// <summary>The logical destination folder, not an imported source path.</summary>
    [JsonIgnore] public string Folder { get; }
    /// <summary>The direct or imported classification, not precedence.</summary>
    [JsonIgnore] public InfisicalInventoryOrigin Origin { get; }
    /// <summary>A direct reference only; it grants no write or read permission.</summary>
    [JsonIgnore] public SecretReference? Reference { get; }
    /// <summary>The existing opaque revision, only when direct returned identity is established.</summary>
    [JsonIgnore] public InfisicalSecretRevision? Revision { get; }
    /// <summary>The optional positive version, without implied qualification.</summary>
    [JsonIgnore] public string? Version { get; }
    /// <summary>The local observation time.</summary>
    [JsonIgnore] public DateTimeOffset ObservedAt { get; }
    /// <summary>The optional returned modification time.</summary>
    [JsonIgnore] public DateTimeOffset? ModifiedAt { get; }
    /// <summary>Returned tag IDs, or null when unestablished; names and colors are discarded.</summary>
    [JsonIgnore] public IReadOnlyList<string>? TagIds { get; }
    /// <summary>True or false only when the provider returned a Boolean; null means unknown.</summary>
    [JsonIgnore] public bool? IsRotatedSecret { get; }
    /// <summary>The import group's returned source environment, or null.</summary>
    [JsonIgnore] public string? SourceEnvironment { get; }
    /// <summary>The import group's returned canonical source path, or null.</summary>
    [JsonIgnore] public string? SourcePath { get; }
    /// <summary>Formats no protected metadata.</summary>
    public override string ToString() => "[InfisicalInventoryEntry]";
}

/// <summary>One returned import group; duplicate groups and order remain observable without a winner.</summary>
public sealed class InfisicalInventoryImportGroup
{
    internal InfisicalInventoryImportGroup(int order, string destinationPath, string? sourceEnvironment,
        string? sourcePath, IReadOnlyList<InfisicalInventoryEntry> entries, bool provenanceEstablished)
    {
        Order = order;
        DestinationPath = destinationPath;
        SourceEnvironment = sourceEnvironment;
        SourcePath = sourcePath;
        Entries = entries;
        IsProvenanceEstablished = provenanceEstablished;
    }
    /// <summary>The group's zero-based order within this destination's returned import array.</summary>
    [JsonIgnore] public int Order { get; }
    /// <summary>The selected logical destination, never a direct write target inferred from an import.</summary>
    [JsonIgnore] public string DestinationPath { get; }
    /// <summary>The returned source environment, if established.</summary>
    [JsonIgnore] public string? SourceEnvironment { get; }
    /// <summary>The returned canonical source folder, if established.</summary>
    [JsonIgnore] public string? SourcePath { get; }
    /// <summary>The value-free candidates in provider order.</summary>
    [JsonIgnore] public IReadOnlyList<InfisicalInventoryEntry> Entries { get; }
    /// <summary>Whether the group's source coordinates were returned and validated.</summary>
    [JsonIgnore] public bool IsProvenanceEstablished { get; }
    /// <summary>Formats no source or destination metadata.</summary>
    public override string ToString() => "[InfisicalInventoryImportGroup]";
}

/// <summary>A bounded visible-view observation, never ACL completeness or an atomic remote snapshot.</summary>
public sealed class InfisicalInventory
{
    internal InfisicalInventory(InfisicalInventorySelection selection, List<InfisicalInventoryEntry> entries,
        List<InfisicalInventoryImportGroup> groups, DateTimeOffset startedAt, DateTimeOffset completedAt,
        HashSet<InfisicalInventoryIncompleteReason> reasons)
    {
        Selection = selection;
        Entries = entries.AsReadOnly();
        ImportGroups = groups.AsReadOnly();
        StartedAt = startedAt;
        CompletedAt = completedAt;
        IncompleteReasons = Array.AsReadOnly(reasons.Order().ToArray());
    }
    /// <summary>The requested coverage and limits.</summary>
    [JsonIgnore] public InfisicalInventorySelection Selection { get; }
    /// <summary>Direct entries and import candidates in traversal and returned order.</summary>
    [JsonIgnore] public IReadOnlyList<InfisicalInventoryEntry> Entries { get; }
    /// <summary>Returned groups, including duplicates and empty groups.</summary>
    [JsonIgnore] public IReadOnlyList<InfisicalInventoryImportGroup> ImportGroups { get; }
    /// <summary>The start of the observation window.</summary>
    [JsonIgnore] public DateTimeOffset StartedAt { get; }
    /// <summary>The end of the observation window.</summary>
    [JsonIgnore] public DateTimeOffset CompletedAt { get; }
    /// <summary>Whether the selected visible view was established without a known gap.</summary>
    public bool IsComplete => IncompleteReasons.Count == 0;
    /// <summary>Closed reasons for unestablished coverage; omission is never proof of absence.</summary>
    public IReadOnlyList<InfisicalInventoryIncompleteReason> IncompleteReasons { get; }
    /// <summary>Formats no entries or coordinates.</summary>
    public override string ToString() => "[InfisicalInventory]";
}

internal sealed class InfisicalInventoryContext(InfisicalInventorySelection selection, InfisicalOperationBudget budget)
{
    internal InfisicalInventorySelection Selection { get; } = selection;
    internal InfisicalOperationBudget Budget { get; } = budget;
    internal int RemainingBytes { get; private set; } = selection.MaximumResponseBytes;
    internal int RemainingRequests { get; private set; } = selection.MaximumRequests;
    internal bool ByteLimitExceeded { get; private set; }
    internal List<InfisicalInventoryEntry> Entries { get; } = [];
    internal List<InfisicalInventoryImportGroup> Groups { get; } = [];
    internal HashSet<InfisicalInventoryIncompleteReason> Reasons { get; } = [];
    internal HashSet<string> ResourceIds { get; } = new(StringComparer.Ordinal);

    internal bool TryBeginRequest()
    {
        Budget.Check();
        if (RemainingRequests == 0)
        {
            Reasons.Add(InfisicalInventoryIncompleteReason.RequestLimit);
            return false;
        }
        RemainingRequests--;
        return true;
    }

    internal bool ConsumeBytes(int count)
    {
        if (count > RemainingBytes)
        {
            ByteLimitExceeded = true;
            Reasons.Add(InfisicalInventoryIncompleteReason.ByteLimit);
            RemainingBytes = 0;
            return false;
        }
        RemainingBytes -= count;
        return true;
    }
}

public sealed partial class InfisicalClient
{
    /// <summary>Collects bounded value-free native metadata with explicit traversal and import provenance.</summary>
    /// <remarks>One deadline covers credentials, all children, parsing and publication. Completeness
    /// never proves hidden-resource absence, read permission, an effective import winner or atomicity.</remarks>
    public ValueTask<SecretOutcome<InfisicalInventory>> InspectNativeAsync(InfisicalInventorySelection selection,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selection);
        ThrowIfDisposed(cancellationToken);
        TimeSpan timeout = selection.Timeout ?? _operationTimeout;
        if (timeout > _operationTimeout) throw new ArgumentOutOfRangeException(nameof(selection));
        return InfisicalOperationBudget.RunAsync(timeout, _time, cancellationToken, InfisicalOperation.Inventory,
            token => InspectInventoryAsync(selection, timeout, token), shutdown: _shutdown.Token);
    }

    private async ValueTask<SecretOutcome<InfisicalInventory>> InspectInventoryAsync(
        InfisicalInventorySelection selection, TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (!selection.BelongsTo(Authority))
            return SecretOutcome<InfisicalInventory>.Failure(SecretStatus.Invalid, reason: SecretFailureReason.AuthorityMismatch);
        using var budget = new InfisicalOperationBudget(timeout, _time, cancellationToken, _shutdown.Token);
        var context = new InfisicalInventoryContext(selection, budget);
        var pending = new Queue<InventoryFolder>();
        var paths = new HashSet<string>(StringComparer.Ordinal) { selection.Folder };
        var ids = new HashSet<Guid>();
        pending.Enqueue(new(selection.Folder, null, 0));
        DateTimeOffset startedAt = _time.GetUtcNow();
        IDisposable operationLease = _operations.Enter();
        try
        {
            while (pending.TryDequeue(out InventoryFolder? folder))
            {
                budget.Check();
                using HttpRequestMessage request = await _staticWire.InspectAsync(selection.ProjectId,
                    selection.Environment, folder.Path, "false", "false", "false",
                    Boolean(selection.IncludeImports), "false", budget.Token).ConfigureAwait(false);
                SecretOutcome<JsonDocument> response = await ReadInventoryDocumentAsync(request, context).ConfigureAwait(false);
                using JsonDocument? document = response.IsSuccess ? response.Value : null;
                if (!response.IsSuccess)
                {
                    if (response.Reason == SecretFailureReason.ResponseTooLarge)
                        context.Reasons.Add(InfisicalInventoryIncompleteReason.ByteLimit);
                    else if (folder.Depth == 0 && !context.Reasons.Contains(InfisicalInventoryIncompleteReason.RequestLimit))
                        return response.ConvertFailure<InfisicalInventory>();
                    else context.Reasons.Add(InfisicalInventoryIncompleteReason.FolderFailure);
                    break;
                }
                budget.Check();
                SecretStatus parsed = ParseInventoryPage(document!.RootElement, folder.Path, context);
                if (parsed != SecretStatus.Success)
                    return SecretOutcome<InfisicalInventory>.Failure(parsed, reason: SecretFailureReason.InvalidResponse);
                if (context.Reasons.Contains(InfisicalInventoryIncompleteReason.ItemLimit)) break;
                if (!selection.Recursive) continue;
                var children = await ListInventoryFoldersAsync(folder.Path, context).ConfigureAwait(false);
                budget.Check();
                if (!children.IsSuccess)
                {
                    if (children.Status == SecretStatus.Invalid && children.Reason != SecretFailureReason.ResponseTooLarge)
                        return children.ConvertFailure<InfisicalInventory>();
                    context.Reasons.Add(children.Reason == SecretFailureReason.ResponseTooLarge
                        ? InfisicalInventoryIncompleteReason.ByteLimit : InfisicalInventoryIncompleteReason.FolderFailure);
                    break;
                }
                foreach (InfisicalFolder child in children.Value)
                {
                    budget.Check();
                    string expected = folder.Path == "/" ? "/" + child.Name : folder.Path + "/" + child.Name;
                    if (!InfisicalInventorySelection.Segment(child.Name) || !InfisicalInventorySelection.CanonicalPath(expected) ||
                        child.Path is { } path && (!InfisicalInventorySelection.CanonicalPath(path) || path != expected) ||
                        child.ParentId is { } parentId && (!Guid.TryParse(parentId, out Guid parent) ||
                            folder.Id is { } knownId && parent != knownId))
                        return SecretOutcome<InfisicalInventory>.Failure(SecretStatus.Invalid, reason: SecretFailureReason.InvalidResponse);
                    bool established = child.Path is not null ||
                        folder.Id is { } verified && Guid.TryParse(child.ParentId, out Guid returned) && returned == verified;
                    if (!established)
                    {
                        context.Reasons.Add(InfisicalInventoryIncompleteReason.AncestryUnestablished);
                        continue;
                    }
                    if (!ids.Add(Guid.Parse(child.Id)) || !paths.Add(expected))
                        return SecretOutcome<InfisicalInventory>.Failure(SecretStatus.Invalid, reason: SecretFailureReason.InvalidResponse);
                    if (folder.Depth == selection.MaximumDepth)
                    {
                        context.Reasons.Add(InfisicalInventoryIncompleteReason.DepthLimit);
                        continue;
                    }
                    if (paths.Count > selection.MaximumFolders)
                    {
                        context.Reasons.Add(InfisicalInventoryIncompleteReason.FolderLimit);
                        break;
                    }
                    pending.Enqueue(new(expected, Guid.Parse(child.Id), folder.Depth + 1));
                }
                if (context.Reasons.Contains(InfisicalInventoryIncompleteReason.FolderLimit)) break;
            }
            budget.Check();
            return SecretOutcome<InfisicalInventory>.Success(new(selection, context.Entries, context.Groups,
                startedAt, _time.GetUtcNow(), context.Reasons));
        }
        finally { operationLease.Dispose(); }
    }

    private sealed record InventoryFolder(string Path, Guid? Id, int Depth);

    private ValueTask<SecretOutcome<JsonDocument>> ReadInventoryDocumentAsync(HttpRequestMessage request,
        InfisicalInventoryContext context) => ReadDocumentAsync(request, context.Budget, inventory: context);

    private SecretStatus ParseInventoryPage(JsonElement root, string folder, InfisicalInventoryContext context,
        bool qualifyRevisions = true)
    {
        if (!NativeArray(root, "secrets", out JsonElement rows)) return SecretStatus.Unknown;
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonElement row in rows.EnumerateArray())
        {
            context.Budget.Check();
            if (context.Entries.Count == context.Selection.MaximumItems)
            {
                context.Reasons.Add(InfisicalInventoryIncompleteReason.ItemLimit);
                return SecretStatus.Success;
            }
            SecretStatus status = ParseInventoryEntry(row, folder, context, null, null, false, out var entry);
            if (status != SecretStatus.Success) return status;
            if (!qualifyRevisions && ReadScope(row, context.Selection.ProjectId,
                context.Selection.Environment, folder, false) != SecretStatus.Success) return SecretStatus.Unknown;
            if (!names.Add(entry!.Key)) return SecretStatus.Invalid;
            if (NativeString(row, "id") is { Length: > 0 } id && !context.ResourceIds.Add(id))
                return SecretStatus.Invalid;
            if (qualifyRevisions && entry.Revision is null)
                context.Reasons.Add(InfisicalInventoryIncompleteReason.RevisionUnestablished);
            context.Entries.Add(entry);
        }
        if (!context.Selection.IncludeImports) return SecretStatus.Success;
        if (!NativeArray(root, "imports", out JsonElement imports))
        {
            context.Reasons.Add(InfisicalInventoryIncompleteReason.ImportProvenanceUnestablished);
            return SecretStatus.Success;
        }
        int order = 0;
        foreach (JsonElement group in imports.EnumerateArray())
        {
            context.Budget.Check();
            // Groups are observations too: empty groups cannot create an unbounded result.
            if (context.Groups.Count == context.Selection.MaximumItems)
            {
                context.Reasons.Add(InfisicalInventoryIncompleteReason.ItemLimit);
                break;
            }
            string? sourceEnvironment = NativeString(group, "environment");
            string? sourcePath = NativeString(group, "secretPath");
            if (sourcePath is not null && !InfisicalInventorySelection.CanonicalPath(sourcePath))
                return SecretStatus.Invalid;
            if (sourceEnvironment is not null && (string.IsNullOrWhiteSpace(sourceEnvironment) ||
                sourceEnvironment.Length > 1024 || sourceEnvironment.Any(char.IsControl))) sourceEnvironment = null;
            bool established = sourceEnvironment is not null && sourcePath is not null;
            if (!established) context.Reasons.Add(InfisicalInventoryIncompleteReason.ImportProvenanceUnestablished);
            if (!NativeArray(group, "secrets", out JsonElement imported)) return SecretStatus.Unknown;
            var entries = new List<InfisicalInventoryEntry>();
            foreach (JsonElement row in imported.EnumerateArray())
            {
                context.Budget.Check();
                if (context.Entries.Count == context.Selection.MaximumItems)
                {
                    context.Reasons.Add(InfisicalInventoryIncompleteReason.ItemLimit);
                    break;
                }
                SecretStatus status = ParseInventoryEntry(row, folder, context, sourceEnvironment, sourcePath, true, out var entry);
                if (status != SecretStatus.Success) return status;
                entries.Add(entry!);
                context.Entries.Add(entry!);
            }
            context.Groups.Add(new(order++, folder, sourceEnvironment, sourcePath, entries.AsReadOnly(), established));
            if (context.Reasons.Contains(InfisicalInventoryIncompleteReason.ItemLimit)) break;
        }
        return SecretStatus.Success;
    }

    private SecretStatus ParseInventoryEntry(JsonElement row, string folder, InfisicalInventoryContext context,
        string? sourceEnvironment, string? sourcePath, bool imported, out InfisicalInventoryEntry? entry)
    {
        entry = null;
        string? key = NativeString(row, "secretKey");
        if (string.IsNullOrWhiteSpace(key) || key is "." or ".." || key.Length > 1024 || key.Any(char.IsControl))
            return SecretStatus.Unknown;
        var selection = context.Selection;
        SecretStatus scope = imported
            ? ReadImportedInventoryScope(row, selection.ProjectId, sourceEnvironment, sourcePath)
            : ReadScope(row, selection.ProjectId, selection.Environment, folder, false);
        if (scope == SecretStatus.Invalid) return scope;
        if (imported && scope == SecretStatus.Unknown)
            context.Reasons.Add(InfisicalInventoryIncompleteReason.ImportProvenanceUnestablished);
        string? version = Version(row);
        InfisicalSecretRevision? revision = null;
        string? id = NativeString(row, "id");
        if (!imported && ReadScope(row, selection.ProjectId, selection.Environment, folder, true) == SecretStatus.Success &&
            id is { Length: > 0 and <= 1024 } && !string.IsNullOrWhiteSpace(id) && !id.Any(char.IsControl) &&
            version is not null)
            revision = new(_origin, selection.ProjectId, selection.Environment, folder, id,
                int.Parse(version, System.Globalization.CultureInfo.InvariantCulture));
        IReadOnlyList<string>? tagIds = null;
        if (NativeArray(row, "tags", out JsonElement tags))
        {
            var ids = new List<string>();
            bool valid = true;
            foreach (JsonElement tag in tags.EnumerateArray())
            {
                context.Budget.Check();
                if (!NativeGuid(tag, "id", out string tagId)) { valid = false; break; }
                ids.Add(tagId);
            }
            if (valid) tagIds = ids.AsReadOnly();
        }
        bool? rotated = row.TryGetProperty("isRotatedSecret", out JsonElement flag) &&
            flag.ValueKind is JsonValueKind.True or JsonValueKind.False ? flag.GetBoolean() : null;
        entry = new(key, folder, imported ? InfisicalInventoryOrigin.Imported : InfisicalInventoryOrigin.Direct,
            imported ? null : new SecretReference(Authority, new InfisicalSecretAddress(selection.ProjectId,
                selection.Environment, folder, key)), revision, version, _time.GetUtcNow(), NativeDate(row, "updatedAt"),
            tagIds, rotated, sourceEnvironment, sourcePath);
        return SecretStatus.Success;
    }

    private static SecretStatus ReadImportedInventoryScope(JsonElement row, string project, string? environment, string? path)
    {
        bool complete = true;
        foreach ((string field, string? expected) in new[]
        {
            ("workspace", project), ("environment", environment), ("secretPath", path), ("type", "shared")
        })
        {
            if (expected is null) continue;
            string? returned = NativeString(row, field);
            if (returned is null) { complete = false; continue; }
            if (returned != expected) return SecretStatus.Invalid;
        }
        return complete ? SecretStatus.Success : SecretStatus.Unknown;
    }
}
