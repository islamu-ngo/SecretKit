using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

public enum InfisicalOrganizationSelector { Id, Slug }

public sealed class InfisicalEnvironmentAddress : InfisicalNativeAddress
{
    public InfisicalEnvironmentAddress(string projectId, string selector,
        InfisicalOrganizationSelector selection = InfisicalOrganizationSelector.Id) : base(projectId)
    {
        NativeText(selector, selection == InfisicalOrganizationSelector.Slug ? 64 : 1024);
        if (!Enum.IsDefined(selection))
        {
            throw new ArgumentException("Invalid native selector.");
        }
        Selector = selector;
        Selection = selection;
    }
    [JsonIgnore]
    public string Selector { get; }
    [JsonIgnore]
    public InfisicalOrganizationSelector Selection { get; }
}

public sealed class InfisicalTagAddress : InfisicalNativeAddress
{
    public InfisicalTagAddress(string projectId, string? selector = null,
        InfisicalOrganizationSelector selection = InfisicalOrganizationSelector.Id) : base(projectId)
    {
        if (selector is not null)
        {
            NativeText(selector, selection == InfisicalOrganizationSelector.Slug ? 64 : 1024);
        }
        if (!Enum.IsDefined(selection))
        {
            throw new ArgumentException("Invalid native selector.");
        }
        Selector = selector;
        Selection = selection;
    }
    [JsonIgnore]
    public string? Selector { get; }
    [JsonIgnore]
    public InfisicalOrganizationSelector Selection { get; }
}

/// <summary>Parent folder scope, with the expected environment ID and an optional selected child.</summary>
public sealed class InfisicalFolderAddress : InfisicalNativeAddress
{
    public InfisicalFolderAddress(string projectId, string environment, string environmentId,
        string parentPath, string? id = null, string? name = null) : base(projectId, environment, parentPath)
    {
        if (!Guid.TryParse(environmentId, out _))
        {
            throw new ArgumentException("An environment ID is required.");
        }
        if (id is not null && !Guid.TryParse(id, out _))
        {
            throw new ArgumentException("A folder ID is required.");
        }
        if (name is not null)
        {
            NativeText(name);
            if (name.Contains('/'))
            {
                throw new ArgumentException("A child folder name is required.");
            }
        }
        EnvironmentId = environmentId;
        Id = id;
        Name = name;
    }
    [JsonIgnore]
    public string EnvironmentId { get; }
    [JsonIgnore]
    public string? Id { get; }
    [JsonIgnore]
    public string? Name { get; }
}

public sealed class InfisicalEnvironment
{
    internal InfisicalEnvironment(string id, string project, string name, string slug, double position,
        DateTimeOffset? softDeletedAt, DateTimeOffset? deleteAfter)
    {
        Id = id;
        ProjectId = project;
        Name = name;
        Slug = slug;
        Position = position;
        SoftDeletedAt = softDeletedAt;
        DeleteAfter = deleteAfter;
    }
    [JsonIgnore]
    public string Id { get; }
    [JsonIgnore]
    public string ProjectId { get; }
    [JsonIgnore]
    public string Name { get; }
    [JsonIgnore]
    public string Slug { get; }
    [JsonIgnore]
    public double Position { get; }
    [JsonIgnore]
    public DateTimeOffset? SoftDeletedAt { get; }
    [JsonIgnore]
    public DateTimeOffset? DeleteAfter { get; }
    public override string ToString() => "[InfisicalEnvironment]";
}

public sealed class InfisicalTag
{
    internal InfisicalTag(string id, string project, string slug, string? color, string? name)
    {
        Id = id;
        ProjectId = project;
        Slug = slug;
        Color = color;
        Name = name;
    }
    [JsonIgnore]
    public string Id { get; }
    [JsonIgnore]
    public string ProjectId { get; }
    [JsonIgnore]
    public string Slug { get; }
    [JsonIgnore]
    public string? Color { get; }
    [JsonIgnore]
    public string? Name { get; }
    public override string ToString() => "[InfisicalTag]";
}

public sealed class InfisicalFolder
{
    internal InfisicalFolder(string id, string environmentId, string name, string? parentId,
        string? path, string? description)
    {
        Id = id;
        EnvironmentId = environmentId;
        Name = name;
        ParentId = parentId;
        Path = path;
        Description = description;
    }
    [JsonIgnore]
    public string Id { get; }
    [JsonIgnore]
    public string EnvironmentId { get; }
    [JsonIgnore]
    public string Name { get; }
    [JsonIgnore]
    public string? ParentId { get; }
    [JsonIgnore]
    public string? Path { get; }
    [JsonIgnore]
    public string? Description { get; }
    public override string ToString() => "[InfisicalFolder]";
}

public sealed class InfisicalFolderUpdate
{
    public InfisicalFolderUpdate(string id, string name, string? description = null, bool clearDescription = false)
    {
        if (!Guid.TryParse(id, out _))
        {
            throw new ArgumentException("A folder ID is required.");
        }
        InfisicalNativeAddress.NativeText(name);
        if (name.Contains('/') || (clearDescription && description is not null) || description?.Length > 4096)
        {
            throw new ArgumentException("Invalid folder update.");
        }
        Id = id;
        Name = name;
        Description = description;
        ClearDescription = clearDescription;
    }
    [JsonIgnore]
    public string Id { get; }
    [JsonIgnore]
    public string Name { get; }
    [JsonIgnore]
    public string? Description { get; }
    [JsonIgnore]
    public bool ClearDescription { get; }
    public override string ToString() => "[InfisicalFolderUpdate]";
}

public sealed class InfisicalFolderMove
{
    internal InfisicalFolderMove(string id, string sourceEnvironment, string sourcePath,
        string destinationEnvironment, string destinationPath)
    {
        FolderId = id;
        SourceEnvironment = sourceEnvironment;
        SourcePath = sourcePath;
        DestinationEnvironment = destinationEnvironment;
        DestinationPath = destinationPath;
    }
    [JsonIgnore]
    public string FolderId { get; }
    [JsonIgnore]
    public string SourceEnvironment { get; }
    [JsonIgnore]
    public string SourcePath { get; }
    [JsonIgnore]
    public string DestinationEnvironment { get; }
    [JsonIgnore]
    public string DestinationPath { get; }
    public override string ToString() => "[InfisicalFolderMove]";
}

public sealed partial class InfisicalClient
{
    private static readonly JsonSerializerOptions NativePayloadOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public ValueTask<SecretOutcome<InfisicalEnvironment>> GetEnvironmentAsync(SecretReference target,
        CancellationToken cancellationToken = default) =>
        EnvironmentOperationAsync(target, HttpMethod.Get, null, null, null, false, false, cancellationToken);

    public ValueTask<SecretOutcome<InfisicalEnvironment>> CreateEnvironmentAsync(SecretReference target,
        string name, InfisicalNativeAuthority authority, MutationReceipt receipt, double? position = null,
        CancellationToken cancellationToken = default)
    {
        InfisicalNativeAddress.NativeText(name, 255);
        if (position is { } number && (!double.IsFinite(number) || number < 1))
        {
            throw new ArgumentException("Invalid environment position.");
        }
        if (target.Address is not InfisicalEnvironmentAddress { Selection: InfisicalOrganizationSelector.Slug } address)
        {
            return ValueTask.FromResult(SecretOutcome<InfisicalEnvironment>.Failure(SecretStatus.Invalid));
        }
        return EnvironmentOperationAsync(target, HttpMethod.Post,
            JsonSerializer.SerializeToUtf8Bytes(new { name, slug = address.Selector, position }, NativePayloadOptions),
            authority, receipt, false, false, cancellationToken);
    }

    public ValueTask<SecretOutcome<InfisicalEnvironment>> UpdateEnvironmentAsync(SecretReference target,
        InfisicalNativeAuthority authority, MutationReceipt receipt, string? name = null, string? slug = null,
        double? position = null, CancellationToken cancellationToken = default)
    {
        if (name is not null) { InfisicalNativeAddress.NativeText(name, 255); }
        if (slug is not null) { InfisicalNativeAddress.NativeText(slug, 64); }
        if (position is { } number && !double.IsFinite(number))
        {
            throw new ArgumentException("Invalid environment position.");
        }
        return EnvironmentOperationAsync(target, HttpMethod.Patch,
            JsonSerializer.SerializeToUtf8Bytes(new { name, slug, position }, NativePayloadOptions),
            authority, receipt, false, false, cancellationToken);
    }

    public ValueTask<SecretOutcome<InfisicalEnvironment>> DeleteEnvironmentAsync(SecretReference target,
        InfisicalNativeAuthority authority, MutationReceipt receipt, bool hardDelete = false,
        CancellationToken cancellationToken = default) =>
        EnvironmentOperationAsync(target, HttpMethod.Delete, null, authority, receipt, false, hardDelete, cancellationToken);

    public ValueTask<SecretOutcome<InfisicalEnvironment>> RestoreEnvironmentAsync(SecretReference target,
        InfisicalNativeAuthority authority, MutationReceipt receipt, CancellationToken cancellationToken = default) =>
        EnvironmentOperationAsync(target, HttpMethod.Post, null, authority, receipt, true, false, cancellationToken);

    private async ValueTask<SecretOutcome<InfisicalEnvironment>> EnvironmentOperationAsync(SecretReference target,
        HttpMethod method, byte[]? payload, InfisicalNativeAuthority? authority, MutationReceipt? receipt,
        bool restore, bool hardDelete, CancellationToken cancellationToken)
    {
        if (target.Address is not InfisicalEnvironmentAddress address ||
            (method != HttpMethod.Get && (authority is null || receipt is null)) ||
            ((restore || method == HttpMethod.Patch || method == HttpMethod.Delete) &&
                address.Selection != InfisicalOrganizationSelector.Id))
        {
            if (payload is not null) { Array.Clear(payload); }
            return SecretOutcome<InfisicalEnvironment>.Failure(SecretStatus.Invalid);
        }
        string path = $"api/v1/projects/{Uri.EscapeDataString(address.ProjectId)}/environments";
        if (method != HttpMethod.Post || restore)
        {
            path += (method == HttpMethod.Get && address.Selection == InfisicalOrganizationSelector.Slug ? "/slug/" : "/") +
                Uri.EscapeDataString(address.Selector);
        }
        if (restore) { path += "/restore"; }
        if (method == HttpMethod.Delete) { path += "?hardDelete=" + Boolean(hardDelete); }
        SecretOutcome<JsonDocument> outcome = await NativeDocumentAsync(target, path, method, payload, authority, receipt, cancellationToken);
        if (!outcome.IsSuccess) { return SecretOutcome<InfisicalEnvironment>.Failure(outcome.Status, outcome.RetryAfter); }
        using JsonDocument document = outcome.Value;
        if (!NativeObject(document.RootElement, "environment", out JsonElement item) ||
            NativeString(item, "projectId") != address.ProjectId ||
            !NativeGuid(item, "id", out string id) || NativeString(item, "name") is not { } name ||
            NativeString(item, "slug") is not { } slug || !NativeNumber(item, "position", out double position) ||
            !NativeDates(item) ||
            (address.Selection == InfisicalOrganizationSelector.Id ? id != address.Selector : slug != address.Selector))
        {
            return SecretOutcome<InfisicalEnvironment>.Failure(SecretStatus.Unknown);
        }
        receipt?.Record(DispatchEvidence.Applied);
        return SecretOutcome<InfisicalEnvironment>.Success(new(id, address.ProjectId, name, slug, position,
            NativeDate(item, "softDeletedAt"), NativeDate(item, "deleteAfter")));
    }

    public ValueTask<SecretOutcome<InfisicalTag>> GetTagAsync(SecretReference target,
        CancellationToken cancellationToken = default) =>
        TagOperationAsync(target, HttpMethod.Get, null, null, null, cancellationToken);

    public ValueTask<SecretOutcome<InfisicalTag>> CreateTagAsync(SecretReference target, string color,
        InfisicalNativeAuthority authority, MutationReceipt receipt, CancellationToken cancellationToken = default)
    {
        InfisicalNativeAddress.NativeText(color);
        if (target.Address is not InfisicalTagAddress { Selection: InfisicalOrganizationSelector.Slug, Selector: not null } address)
        {
            return ValueTask.FromResult(SecretOutcome<InfisicalTag>.Failure(SecretStatus.Invalid));
        }
        return TagOperationAsync(target, HttpMethod.Post, JsonSerializer.SerializeToUtf8Bytes(new { slug = address.Selector, color }),
            authority, receipt, cancellationToken);
    }

    public ValueTask<SecretOutcome<InfisicalTag>> UpdateTagAsync(SecretReference target, string slug, string color,
        InfisicalNativeAuthority authority, MutationReceipt receipt, CancellationToken cancellationToken = default)
    {
        InfisicalNativeAddress.NativeText(slug, 64);
        InfisicalNativeAddress.NativeText(color);
        return TagOperationAsync(target, HttpMethod.Patch, JsonSerializer.SerializeToUtf8Bytes(new { slug, color }),
            authority, receipt, cancellationToken);
    }

    public ValueTask<SecretOutcome<InfisicalTag>> DeleteTagAsync(SecretReference target,
        InfisicalNativeAuthority authority, MutationReceipt receipt, CancellationToken cancellationToken = default) =>
        TagOperationAsync(target, HttpMethod.Delete, null, authority, receipt, cancellationToken);

    private async ValueTask<SecretOutcome<InfisicalTag>> TagOperationAsync(SecretReference target, HttpMethod method,
        byte[]? payload, InfisicalNativeAuthority? authority, MutationReceipt? receipt, CancellationToken cancellationToken)
    {
        if (target.Address is not InfisicalTagAddress { Selector: not null } address ||
            ((method == HttpMethod.Patch || method == HttpMethod.Delete) && address.Selection != InfisicalOrganizationSelector.Id))
        {
            if (payload is not null) { Array.Clear(payload); }
            return SecretOutcome<InfisicalTag>.Failure(SecretStatus.Invalid);
        }
        string path = $"api/v1/projects/{Uri.EscapeDataString(address.ProjectId)}/tags";
        if (method != HttpMethod.Post)
        {
            path += (method == HttpMethod.Get && address.Selection == InfisicalOrganizationSelector.Slug ? "/slug/" : "/") +
                Uri.EscapeDataString(address.Selector);
        }
        SecretOutcome<JsonDocument> outcome = await NativeDocumentAsync(target, path, method, payload, authority, receipt, cancellationToken);
        if (!outcome.IsSuccess) { return SecretOutcome<InfisicalTag>.Failure(outcome.Status, outcome.RetryAfter); }
        using JsonDocument document = outcome.Value;
        if (!NativeObject(document.RootElement, "tag", out JsonElement item) ||
            ParseTag(item, address.ProjectId) is not { } tag ||
            (address.Selection == InfisicalOrganizationSelector.Id ? tag.Id != address.Selector : tag.Slug != address.Selector))
        {
            return SecretOutcome<InfisicalTag>.Failure(SecretStatus.Unknown);
        }
        receipt?.Record(DispatchEvidence.Applied);
        return SecretOutcome<InfisicalTag>.Success(tag);
    }

    public async ValueTask<SecretOutcome<InfisicalNativeList<InfisicalTag>>> ListTagsAsync(SecretReference target,
        int maximumItems = 1000, CancellationToken cancellationToken = default)
    {
        NativeCount(maximumItems);
        if (target.Address is not InfisicalTagAddress { Selector: null } address)
        {
            return SecretOutcome<InfisicalNativeList<InfisicalTag>>.Failure(SecretStatus.Invalid);
        }
        SecretOutcome<JsonDocument> outcome = await NativeDocumentAsync(target,
            $"api/v1/projects/{Uri.EscapeDataString(address.ProjectId)}/tags", HttpMethod.Get, null, null, null, cancellationToken);
        if (!outcome.IsSuccess) { return SecretOutcome<InfisicalNativeList<InfisicalTag>>.Failure(outcome.Status, outcome.RetryAfter); }
        using JsonDocument document = outcome.Value;
        if (!NativeArray(document.RootElement, "tags", out JsonElement items))
        {
            return SecretOutcome<InfisicalNativeList<InfisicalTag>>.Failure(SecretStatus.Unknown);
        }
        var tags = new List<InfisicalTag>();
        foreach (JsonElement item in items.EnumerateArray().Take(maximumItems))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (ParseTag(item, address.ProjectId) is not { } tag)
            {
                return SecretOutcome<InfisicalNativeList<InfisicalTag>>.Failure(SecretStatus.Unknown);
            }
            tags.Add(tag);
        }
        return SecretOutcome<InfisicalNativeList<InfisicalTag>>.Success(new(tags, items.GetArrayLength() <= maximumItems));
    }

    public async ValueTask<SecretOutcome<InfisicalNativeList<InfisicalFolder>>> ListFoldersAsync(SecretReference target,
        int maximumItems = 1000, bool recursive = false, DateTimeOffset? lastSecretModified = null,
        CancellationToken cancellationToken = default)
    {
        NativeCount(maximumItems);
        if (target.Address is not InfisicalFolderAddress address)
        {
            return SecretOutcome<InfisicalNativeList<InfisicalFolder>>.Failure(SecretStatus.Invalid);
        }
        string path = "api/v2/folders" + OrganizationQuery(address) + "&recursive=" + Boolean(recursive) +
            (lastSecretModified is { } date ? "&lastSecretModified=" + Uri.EscapeDataString(date.ToString("O", CultureInfo.InvariantCulture)) : "");
        SecretOutcome<JsonDocument> outcome = await NativeDocumentAsync(target, path, HttpMethod.Get, null, null, null, cancellationToken);
        if (!outcome.IsSuccess) { return SecretOutcome<InfisicalNativeList<InfisicalFolder>>.Failure(outcome.Status, outcome.RetryAfter); }
        using JsonDocument document = outcome.Value;
        if (!NativeArray(document.RootElement, "folders", out JsonElement items))
        {
            return SecretOutcome<InfisicalNativeList<InfisicalFolder>>.Failure(SecretStatus.Unknown);
        }
        var folders = new List<InfisicalFolder>();
        foreach (JsonElement item in items.EnumerateArray().Take(maximumItems))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (ParseFolder(item, address.EnvironmentId) is not { } folder)
            {
                return SecretOutcome<InfisicalNativeList<InfisicalFolder>>.Failure(SecretStatus.Unknown);
            }
            folders.Add(folder);
        }
        return SecretOutcome<InfisicalNativeList<InfisicalFolder>>.Success(new(folders, items.GetArrayLength() <= maximumItems));
    }

    public ValueTask<SecretOutcome<InfisicalFolder>> GetFolderAsync(SecretReference target,
        CancellationToken cancellationToken = default) =>
        FolderOperationAsync(target, HttpMethod.Get, null, null, null, cancellationToken);

    public ValueTask<SecretOutcome<InfisicalFolder>> CreateFolderAsync(SecretReference target,
        InfisicalNativeAuthority authority, MutationReceipt receipt, string? description = null,
        CancellationToken cancellationToken = default) =>
        ChangeFolderAsync(target, authority, receipt, HttpMethod.Post, description, false, cancellationToken);

    public ValueTask<SecretOutcome<InfisicalFolder>> UpdateFolderAsync(SecretReference target,
        InfisicalNativeAuthority authority, MutationReceipt receipt, string? description = null,
        bool clearDescription = false, CancellationToken cancellationToken = default) =>
        ChangeFolderAsync(target, authority, receipt, HttpMethod.Patch, description, clearDescription, cancellationToken);

    private ValueTask<SecretOutcome<InfisicalFolder>> ChangeFolderAsync(SecretReference target,
        InfisicalNativeAuthority authority, MutationReceipt receipt, HttpMethod method, string? description,
        bool clearDescription, CancellationToken cancellationToken)
    {
        if (description?.Length > 4096 || (description is not null && clearDescription))
        {
            throw new ArgumentException("Invalid folder description.");
        }
        if (target.Address is not InfisicalFolderAddress { Name: not null } address)
        {
            return ValueTask.FromResult(SecretOutcome<InfisicalFolder>.Failure(SecretStatus.Invalid));
        }
        var body = new Dictionary<string, object?>
        {
            ["projectId"] = address.ProjectId,
            ["environment"] = address.Environment,
            ["path"] = address.Folder,
            ["name"] = address.Name
        };
        if (description is not null || clearDescription) { body["description"] = description; }
        return FolderOperationAsync(target, method, JsonSerializer.SerializeToUtf8Bytes(body),
            authority, receipt, cancellationToken);
    }

    public ValueTask<SecretOutcome<InfisicalFolder>> DeleteFolderAsync(SecretReference target,
        InfisicalNativeAuthority authority, MutationReceipt receipt, bool forceDelete = false,
        CancellationToken cancellationToken = default)
    {
        if (target.Address is not InfisicalFolderAddress address)
        {
            return ValueTask.FromResult(SecretOutcome<InfisicalFolder>.Failure(SecretStatus.Invalid));
        }
        return FolderOperationAsync(target, HttpMethod.Delete, JsonSerializer.SerializeToUtf8Bytes(new
        {
            projectId = address.ProjectId,
            environment = address.Environment,
            path = address.Folder,
            forceDelete
        }), authority, receipt, cancellationToken);
    }

    private async ValueTask<SecretOutcome<InfisicalFolder>> FolderOperationAsync(SecretReference target, HttpMethod method,
        byte[]? payload, InfisicalNativeAuthority? authority, MutationReceipt? receipt, CancellationToken cancellationToken)
    {
        if (target.Address is not InfisicalFolderAddress address ||
            ((method == HttpMethod.Get || method == HttpMethod.Patch) && address.Id is null) ||
            (method == HttpMethod.Delete && address.Id is null && address.Name is null))
        {
            if (payload is not null) { Array.Clear(payload); }
            return SecretOutcome<InfisicalFolder>.Failure(SecretStatus.Invalid);
        }
        string path = "api/v2/folders";
        if (method != HttpMethod.Post) { path += "/" + Uri.EscapeDataString(address.Id ?? address.Name!); }
        SecretOutcome<JsonDocument> outcome = await NativeDocumentAsync(target, path, method, payload, authority, receipt, cancellationToken);
        if (!outcome.IsSuccess) { return SecretOutcome<InfisicalFolder>.Failure(outcome.Status, outcome.RetryAfter); }
        using JsonDocument document = outcome.Value;
        if (!NativeObject(document.RootElement, "folder", out JsonElement item) ||
            ParseFolder(item, address.EnvironmentId) is not { } folder ||
            (address.Id is not null && folder.Id != address.Id) ||
            (address.Name is not null && folder.Name != address.Name) ||
            (method == HttpMethod.Get && (NativeString(item, "projectId") != address.ProjectId ||
                !NativeObject(item, "environment", out JsonElement environment) ||
                NativeString(environment, "envSlug") != address.Environment)))
        {
            return SecretOutcome<InfisicalFolder>.Failure(SecretStatus.Unknown);
        }
        receipt?.Record(DispatchEvidence.Applied);
        return SecretOutcome<InfisicalFolder>.Success(folder);
    }

    public async ValueTask<SecretOutcome<InfisicalNativeList<InfisicalFolder>>> UpdateFoldersAsync(SecretReference target,
        IReadOnlyList<InfisicalFolderUpdate> updates, InfisicalNativeAuthority authority, MutationReceipt receipt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(updates);
        if (updates.Count is < 1 or > 128 || updates.Any(item => item is null) ||
            updates.Select(item => item.Id).Distinct(StringComparer.Ordinal).Count() != updates.Count ||
            target.Address is not InfisicalFolderAddress address)
        {
            return SecretOutcome<InfisicalNativeList<InfisicalFolder>>.Failure(SecretStatus.Invalid);
        }
        InfisicalFolderUpdate[] owned = updates.ToArray();
        var bodies = owned.Select(update =>
        {
            var body = new Dictionary<string, object?>
            {
                ["id"] = update.Id,
                ["name"] = update.Name,
                ["environment"] = address.Environment,
                ["path"] = address.Folder
            };
            if (update.Description is not null || update.ClearDescription) { body["description"] = update.Description; }
            return body;
        }).ToArray();
        SecretOutcome<JsonDocument> outcome = await NativeDocumentAsync(target, "api/v2/folders/batch",
            HttpMethod.Patch, JsonSerializer.SerializeToUtf8Bytes(new { projectId = address.ProjectId, folders = bodies }),
            authority, receipt, cancellationToken);
        if (!outcome.IsSuccess) { return SecretOutcome<InfisicalNativeList<InfisicalFolder>>.Failure(outcome.Status, outcome.RetryAfter); }
        using JsonDocument document = outcome.Value;
        if (!NativeArray(document.RootElement, "folders", out JsonElement items) || items.GetArrayLength() > owned.Length)
        {
            return SecretOutcome<InfisicalNativeList<InfisicalFolder>>.Failure(SecretStatus.Unknown);
        }
        var folders = new List<InfisicalFolder>();
        foreach (JsonElement item in items.EnumerateArray())
        {
            if (ParseFolder(item, address.EnvironmentId) is not { } folder ||
                !owned.Any(update => update.Id == folder.Id && update.Name == folder.Name) ||
                folders.Any(previous => previous.Id == folder.Id))
            {
                return SecretOutcome<InfisicalNativeList<InfisicalFolder>>.Failure(SecretStatus.Unknown);
            }
            folders.Add(folder);
        }
        bool complete = folders.Count == owned.Length;
        if (complete) { receipt.Record(DispatchEvidence.Applied); }
        return SecretOutcome<InfisicalNativeList<InfisicalFolder>>.Success(new(folders, complete));
    }

    public async ValueTask<SecretOutcome<InfisicalFolderMove>> MoveFolderAsync(SecretReference target,
        InfisicalFolderAddress destination, InfisicalNativeAuthority authority, MutationReceipt receipt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (target.Address is not InfisicalFolderAddress { Id: not null } address ||
            address.ProjectId != destination.ProjectId || !authority.Matches(Authority, destination))
        {
            return SecretOutcome<InfisicalFolderMove>.Failure(SecretStatus.Invalid);
        }
        SecretOutcome<JsonDocument> outcome = await NativeDocumentAsync(target, "api/v2/folders/move",
            HttpMethod.Post, JsonSerializer.SerializeToUtf8Bytes(new
            {
                projectId = address.ProjectId,
                folderId = address.Id,
                destinationEnvironment = destination.Environment,
                destinationPath = destination.Folder
            }), authority, receipt, cancellationToken);
        if (!outcome.IsSuccess) { return SecretOutcome<InfisicalFolderMove>.Failure(outcome.Status, outcome.RetryAfter); }
        using JsonDocument document = outcome.Value;
        JsonElement item = document.RootElement;
        if (NativeString(item, "folderId") != address.Id ||
            NativeString(item, "sourceEnvironment") != address.Environment ||
            NativeString(item, "sourcePath") is not { } sourcePath ||
            NativeString(item, "destinationEnvironment") != destination.Environment ||
            NativeString(item, "destinationPath") != destination.Folder)
        {
            return SecretOutcome<InfisicalFolderMove>.Failure(SecretStatus.Unknown);
        }
        receipt.Record(DispatchEvidence.Applied);
        return SecretOutcome<InfisicalFolderMove>.Success(new(address.Id, address.Environment!, sourcePath,
            destination.Environment!, destination.Folder!));
    }

    private static InfisicalTag? ParseTag(JsonElement item, string project) =>
        NativeGuid(item, "id", out string id) && NativeString(item, "projectId") == project &&
        NativeString(item, "slug") is { } slug && NativeDates(item)
            ? new(id, project, slug, NativeString(item, "color"), NativeString(item, "name")) : null;

    private static InfisicalFolder? ParseFolder(JsonElement item, string environmentId) =>
        NativeGuid(item, "id", out string id) && NativeString(item, "envId") == environmentId &&
        NativeString(item, "name") is { } name && NativeDates(item)
            ? new(id, environmentId, name, NativeString(item, "parentId"),
                NativeString(item, "path") ?? NativeString(item, "relativePath"), NativeString(item, "description")) : null;

    private static string OrganizationQuery(InfisicalNativeAddress address) =>
        $"?projectId={Uri.EscapeDataString(address.ProjectId)}&environment={Uri.EscapeDataString(address.Environment!)}&path={Uri.EscapeDataString(address.Folder!)}";

    private static bool NativeObject(JsonElement item, string property, out JsonElement value)
    {
        value = default;
        return item.ValueKind == JsonValueKind.Object && item.TryGetProperty(property, out value) && value.ValueKind == JsonValueKind.Object;
    }
    private static bool NativeArray(JsonElement item, string property, out JsonElement value)
    {
        value = default;
        return item.ValueKind == JsonValueKind.Object && item.TryGetProperty(property, out value) && value.ValueKind == JsonValueKind.Array;
    }
    private static bool NativeGuid(JsonElement item, string property, out string value)
    {
        value = NativeString(item, property) ?? "";
        return Guid.TryParse(value, out _);
    }
    private static bool NativeNumber(JsonElement item, string property, out double value)
    {
        value = 0;
        return item.ValueKind == JsonValueKind.Object && item.TryGetProperty(property, out JsonElement number) &&
            number.ValueKind == JsonValueKind.Number && number.TryGetDouble(out value) && double.IsFinite(value);
    }
    private static DateTimeOffset? NativeDate(JsonElement item, string property) =>
        NativeString(item, property) is { } value && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind, out DateTimeOffset date) ? date : null;
    private static bool NativeDates(JsonElement item) =>
        NativeDate(item, "createdAt") is not null && NativeDate(item, "updatedAt") is not null;
    private static void NativeCount(int count)
    {
        if (count is < 1 or > 1000) { throw new ArgumentOutOfRangeException(nameof(count)); }
    }
}
