using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Destination coordinates and the known folder identity protect ID-only responses.</summary>
public sealed class InfisicalImportAddress : InfisicalNativeAddress
{
    /// <summary>Selects a destination folder UUID and optional import UUID within protected native scope.</summary>
    public InfisicalImportAddress(string projectId, string environment, string folder, string folderId,
        string? importId = null) : base(projectId, environment, folder)
    {
        if (!Guid.TryParse(folderId, out _) || (importId is not null && !Guid.TryParse(importId, out _)))
        {
            throw new ArgumentException("Invalid import or destination folder identity.");
        }
        FolderId = folderId;
        ImportId = importId;
    }
    /// <summary>Expected destination folder identity used to validate import responses.</summary>
    [JsonIgnore]
    public string FolderId { get; }
    /// <summary>Selected import identity, or null for creation/listing.</summary>
    [JsonIgnore]
    public string? ImportId { get; }
}

/// <summary>Protected explicit import source coordinates; no source acquisition or recursion is implied.</summary>
public sealed class InfisicalImportSource
{
    /// <summary>Selects an absolute source path and environment, optionally in another project.</summary>
    public InfisicalImportSource(string environment, string path, string? sourceProjectId = null)
    {
        InfisicalNativeAddress.NativeText(environment);
        InfisicalNativeAddress.NativeFolder(path);
        if (sourceProjectId is not null) { InfisicalNativeAddress.NativeText(sourceProjectId); }
        Environment = environment;
        Path = path;
        ProjectId = sourceProjectId;
    }
    /// <summary>The protected source environment slug.</summary>
    [JsonIgnore]
    public string Environment { get; }
    /// <summary>The absolute source folder path.</summary>
    [JsonIgnore]
    public string Path { get; }
    /// <summary>The optional explicit source project.</summary>
    [JsonIgnore]
    public string? ProjectId { get; }
    /// <summary>Returns a fixed label without source coordinates.</summary>
    public override string ToString() => "[InfisicalImportSource]";
}

/// <summary>Observed import configuration and provider replication metadata, not delivery or approval proof.</summary>
public sealed class InfisicalImport
{
    internal InfisicalImport(string id, string folderId, string sourceEnvironment, string sourcePath,
        string? sourceProjectId, double position, bool? replication, bool? replicationSuccess,
        string? replicationStatus, DateTimeOffset? lastReplicated)
    {
        Id = id;
        FolderId = folderId;
        SourceEnvironment = sourceEnvironment;
        SourcePath = sourcePath;
        SourceProjectId = sourceProjectId;
        Position = position;
        IsReplication = replication;
        ReplicationReportedSuccessful = replicationSuccess;
        ReplicationStatus = replicationStatus;
        LastReplicated = lastReplicated;
    }
    /// <summary>The observed native import identity.</summary>
    [JsonIgnore]
    public string Id { get; }
    /// <summary>The validated destination folder identity.</summary>
    [JsonIgnore]
    public string FolderId { get; }
    /// <summary>The observed source environment slug.</summary>
    [JsonIgnore]
    public string SourceEnvironment { get; }
    /// <summary>The observed absolute source path.</summary>
    [JsonIgnore]
    public string SourcePath { get; }
    /// <summary>The source project if reported; not inferred when absent.</summary>
    [JsonIgnore]
    public string? SourceProjectId { get; }
    /// <summary>The native import ordering position; local precedence is not resolved.</summary>
    [JsonIgnore]
    public double Position { get; }
    /// <summary>Whether configuration requests replication, or null if unreported.</summary>
    public bool? IsReplication { get; }
    /// <summary>Reported replication success only; not a fresh intended-client read.</summary>
    public bool? ReplicationReportedSuccessful { get; }
    /// <summary>Protected provider text with no established status vocabulary; never interpreted as approval evidence.</summary>
    [JsonIgnore]
    public string? ReplicationStatus { get; }
    /// <summary>The last reported replication time, if available.</summary>
    [JsonIgnore]
    public DateTimeOffset? LastReplicated { get; }
    /// <summary>Returns a fixed label without protected fields.</summary>
    public override string ToString() => "[InfisicalImport]";
}

/// <summary>One owned imported value with observed source coordinates; default formatting does not reveal it.</summary>
public sealed class InfisicalImportedSecret : IDisposable
{
    internal InfisicalImportedSecret(string key, string project, string environment, string path,
        string? version, SecretMaterial material)
    {
        Key = key;
        ProjectId = project;
        Environment = environment;
        Path = path;
        Version = version;
        Material = material;
    }
    /// <summary>The protected observed secret key.</summary>
    [JsonIgnore]
    public string Key { get; }
    /// <summary>The observed source project identity.</summary>
    [JsonIgnore]
    public string ProjectId { get; }
    /// <summary>The observed source environment.</summary>
    [JsonIgnore]
    public string Environment { get; }
    /// <summary>The source group path.</summary>
    [JsonIgnore]
    public string Path { get; }
    /// <summary>The validated returned version.</summary>
    [JsonIgnore]
    public string? Version { get; }
    /// <summary>The owned imported material; reveal/export creates ordinary plaintext copies.</summary>
    [JsonIgnore]
    public SecretMaterial Material { get; }
    /// <summary>Disposes this imported value's material only.</summary>
    public void Dispose() => Material.Dispose();
    /// <summary>Returns a fixed label without coordinates or material.</summary>
    public override string ToString() => "[InfisicalImportedSecret]";
}

/// <summary>Preserves one provider import group and its order without deduplicating or resolving precedence.</summary>
public sealed class InfisicalImportedSecretGroup
{
    internal InfisicalImportedSecretGroup(string environment, string path, string folderId,
        IEnumerable<InfisicalImportedSecret> items)
    {
        Environment = environment;
        Path = path;
        FolderId = folderId;
        Items = Array.AsReadOnly(items.ToArray());
    }
    /// <summary>The protected source environment.</summary>
    [JsonIgnore]
    public string Environment { get; }
    /// <summary>The observed source path.</summary>
    [JsonIgnore]
    public string Path { get; }
    /// <summary>The observed native source folder identity.</summary>
    [JsonIgnore]
    public string FolderId { get; }
    /// <summary>Read-only group items shared with the owning imported-secrets result.</summary>
    [JsonIgnore]
    public IReadOnlyList<InfisicalImportedSecret> Items { get; }
    /// <summary>Returns a fixed label without group details.</summary>
    public override string ToString() => "[InfisicalImportedSecretGroup]";
}

/// <summary>Provider groups and order retained without local precedence resolution or recursive acquisition.</summary>
public sealed class InfisicalImportedSecrets : IDisposable
{
    internal InfisicalImportedSecrets(IEnumerable<InfisicalImportedSecret> items,
        IEnumerable<InfisicalImportedSecretGroup> groups, bool complete)
    {
        Items = Array.AsReadOnly(items.ToArray());
        Groups = Array.AsReadOnly(groups.ToArray());
        IsComplete = complete;
    }
    /// <summary>Flattened observed values in provider order, owned by this result.</summary>
    [JsonIgnore]
    public IReadOnlyList<InfisicalImportedSecret> Items { get; }
    /// <summary>Provider groups referencing the same owned items, with no local precedence resolution.</summary>
    [JsonIgnore]
    public IReadOnlyList<InfisicalImportedSecretGroup> Groups { get; }
    /// <summary>Whether all returned values fit the local item budget; not a transactional snapshot.</summary>
    public bool IsComplete { get; }
    /// <summary>Disposes every owned imported value; previously exported plaintext cannot be erased here.</summary>
    public void Dispose()
    {
        foreach (InfisicalImportedSecret item in Items) { item.Dispose(); }
    }
    /// <summary>Returns a fixed label without source coordinates or values.</summary>
    public override string ToString() => "[InfisicalImportedSecrets]";
}

public sealed partial class InfisicalClient
{
    /// <summary>Inspects one import through this client's identity; unvalidated response correspondence yields Unknown.</summary>
    public ValueTask<SecretOutcome<InfisicalImport>> GetImportAsync(SecretReference target,
        CancellationToken cancellationToken = default) =>
        ImportOperationAsync(target, HttpMethod.Get, null, null, null, null, null, null, cancellationToken);

    /// <summary>Creates import configuration under explicit native authority and caller-held dispatch evidence.</summary>
    /// <remarks>Applied receipt evidence concerns configuration only, not replication, approval or intended delivery.
    /// Cancellation and uncertain responses do not authorize replay.</remarks>
    public ValueTask<SecretOutcome<InfisicalImport>> CreateImportAsync(SecretReference target,
        InfisicalImportSource source, bool replication, InfisicalNativeAuthority authority, MutationReceipt receipt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (target.Address is not InfisicalImportAddress { ImportId: null } address)
        {
            return ValueTask.FromResult(SecretOutcome<InfisicalImport>.Failure(SecretStatus.Invalid));
        }
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            projectId = address.ProjectId,
            environment = address.Environment,
            path = address.Folder,
            import = new { environment = source.Environment, path = source.Path, sourceProjectId = source.ProjectId },
            isReplication = replication
        }, NativePayloadOptions);
        return ImportOperationAsync(target, HttpMethod.Post, payload, authority, receipt,
            source.Environment, source.Path, replication, cancellationToken);
    }

    /// <summary>Updates explicitly supplied source/order fields; omitted fields remain unspecified.</summary>
    /// <remarks>Retain the receipt after failure or cancellation. Configuration success does not prove destination application.</remarks>
    public ValueTask<SecretOutcome<InfisicalImport>> UpdateImportAsync(SecretReference target,
        InfisicalNativeAuthority authority, MutationReceipt receipt, string? sourceEnvironment = null,
        string? sourcePath = null, double? position = null, CancellationToken cancellationToken = default)
    {
        if (sourceEnvironment is not null) { InfisicalNativeAddress.NativeText(sourceEnvironment); }
        if (sourcePath is not null) { InfisicalNativeAddress.NativeFolder(sourcePath); }
        if (position is { } number && !double.IsFinite(number)) { throw new ArgumentException("Invalid import position."); }
        if (target.Address is not InfisicalImportAddress address)
        {
            return ValueTask.FromResult(SecretOutcome<InfisicalImport>.Failure(SecretStatus.Invalid));
        }
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            projectId = address.ProjectId,
            environment = address.Environment,
            path = address.Folder,
            import = new { environment = sourceEnvironment, path = sourcePath, position }
        }, NativePayloadOptions);
        return ImportOperationAsync(target, HttpMethod.Patch, payload, authority, receipt,
            sourceEnvironment, sourcePath, null, cancellationToken);
    }

    /// <summary>Deletes selected import configuration with explicit authority and retained receipt; no remote rollback is implied.</summary>
    public ValueTask<SecretOutcome<InfisicalImport>> DeleteImportAsync(SecretReference target,
        InfisicalNativeAuthority authority, MutationReceipt receipt, CancellationToken cancellationToken = default)
    {
        if (target.Address is not InfisicalImportAddress address)
        {
            return ValueTask.FromResult(SecretOutcome<InfisicalImport>.Failure(SecretStatus.Invalid));
        }
        return ImportOperationAsync(target, HttpMethod.Delete, JsonSerializer.SerializeToUtf8Bytes(new
        {
            projectId = address.ProjectId,
            environment = address.Environment,
            path = address.Folder
        }), authority, receipt, null, null, null, cancellationToken);
    }

    private async ValueTask<SecretOutcome<InfisicalImport>> ImportOperationAsync(SecretReference target,
        HttpMethod method, byte[]? payload, InfisicalNativeAuthority? authority, MutationReceipt? receipt,
        string? sourceEnvironment, string? sourcePath, bool? replication, CancellationToken cancellationToken)
    {
        if (target.Address is not InfisicalImportAddress address ||
            (method != HttpMethod.Post && address.ImportId is null))
        {
            if (payload is not null) { Array.Clear(payload); }
            return SecretOutcome<InfisicalImport>.Failure(SecretStatus.Invalid);
        }
        string path = "api/v2/secret-imports" + (method == HttpMethod.Post ? "" : "/" + Uri.EscapeDataString(address.ImportId!));
        SecretOutcome<JsonDocument> outcome = await NativeDocumentAsync(target, path, method, payload, authority, receipt, cancellationToken);
        if (!outcome.IsSuccess) { return SecretOutcome<InfisicalImport>.Failure(outcome.Status, outcome.RetryAfter); }
        using JsonDocument document = outcome.Value;
        if (!NativeObject(document.RootElement, "secretImport", out JsonElement item) ||
            ParseImport(item, address.FolderId) is not { } import ||
            (address.ImportId is not null && import.Id != address.ImportId) ||
            (sourceEnvironment is not null && import.SourceEnvironment != sourceEnvironment) ||
            (sourcePath is not null && import.SourcePath != sourcePath) ||
            (replication is not null && import.IsReplication != replication) ||
            (method == HttpMethod.Get && (NativeString(item, "projectId") != address.ProjectId ||
                NativeString(item, "secretPath") != address.Folder ||
                !NativeObject(item, "environment", out JsonElement environment) ||
                NativeString(environment, "slug") != address.Environment)))
        {
            return SecretOutcome<InfisicalImport>.Failure(SecretStatus.Unknown);
        }
        // This receipt proves the configuration mutation only, never destination application.
        receipt?.Record(DispatchEvidence.Applied);
        return SecretOutcome<InfisicalImport>.Success(import);
    }

    /// <summary>Lists bounded import configuration for a destination without inferring replication or delivery.</summary>
    public async ValueTask<SecretOutcome<InfisicalNativeList<InfisicalImport>>> ListImportsAsync(SecretReference target,
        int maximumItems = 1000, CancellationToken cancellationToken = default)
    {
        NativeCount(maximumItems);
        if (target.Address is not InfisicalImportAddress { ImportId: null } address)
        {
            return SecretOutcome<InfisicalNativeList<InfisicalImport>>.Failure(SecretStatus.Invalid);
        }
        SecretOutcome<JsonDocument> outcome = await NativeDocumentAsync(target,
            "api/v2/secret-imports" + OrganizationQuery(address), HttpMethod.Get, null, null, null, cancellationToken);
        if (!outcome.IsSuccess) { return SecretOutcome<InfisicalNativeList<InfisicalImport>>.Failure(outcome.Status, outcome.RetryAfter); }
        using JsonDocument document = outcome.Value;
        if (!NativeArray(document.RootElement, "secretImports", out JsonElement items))
        {
            return SecretOutcome<InfisicalNativeList<InfisicalImport>>.Failure(SecretStatus.Unknown);
        }
        var imports = new List<InfisicalImport>();
        foreach (JsonElement item in items.EnumerateArray().Take(maximumItems))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (ParseImport(item, address.FolderId) is not { } import)
            {
                return SecretOutcome<InfisicalNativeList<InfisicalImport>>.Failure(SecretStatus.Unknown);
            }
            imports.Add(import);
        }
        return SecretOutcome<InfisicalNativeList<InfisicalImport>>.Success(new(imports, items.GetArrayLength() <= maximumItems));
    }

    /// <summary>Returns caller-owned imported material in provider groups/order, without recursive acquisition or precedence resolution.</summary>
    /// <remarks>Dispose a successful result. Unknown indicates missing or unvalidated native evidence;
    /// incomplete local coverage is reported separately. Cancellation propagates and untransferred material is disposed.</remarks>
    public async ValueTask<SecretOutcome<InfisicalImportedSecrets>> ReadImportedSecretsAsync(SecretReference target,
        int maximumItems = 1000, CancellationToken cancellationToken = default)
    {
        NativeCount(maximumItems);
        if (target.Address is not InfisicalImportAddress { ImportId: null } address)
        {
            return SecretOutcome<InfisicalImportedSecrets>.Failure(SecretStatus.Invalid);
        }
        SecretOutcome<JsonDocument> outcome = await NativeDocumentAsync(target,
            "api/v2/secret-imports/secrets" + OrganizationQuery(address), HttpMethod.Get, null, null, null, cancellationToken);
        if (!outcome.IsSuccess) { return SecretOutcome<InfisicalImportedSecrets>.Failure(outcome.Status, outcome.RetryAfter); }
        using JsonDocument document = outcome.Value;
        if (!NativeArray(document.RootElement, "secrets", out JsonElement groups) || groups.GetArrayLength() > 1000)
        {
            return SecretOutcome<InfisicalImportedSecrets>.Failure(SecretStatus.Unknown);
        }
        var secrets = new List<InfisicalImportedSecret>();
        var importedGroups = new List<InfisicalImportedSecretGroup>();
        bool transferred = false;
        bool complete = true;
        try
        {
            foreach (JsonElement group in groups.EnumerateArray())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (NativeString(group, "environment") is not { } environment ||
                    NativeString(group, "secretPath") is not { } path ||
                    !NativeGuid(group, "folderId", out string folderId) || !NativeArray(group, "secrets", out JsonElement items))
                {
                    return SecretOutcome<InfisicalImportedSecrets>.Failure(SecretStatus.Unknown);
                }
                int start = secrets.Count;
                foreach (JsonElement item in items.EnumerateArray())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (secrets.Count == maximumItems) { complete = false; break; }
                    if (NativeString(item, "secretKey") is not { } key || NativeString(item, "secretValue") is not { } value ||
                        NativeString(item, "workspace") is not { } project || NativeString(item, "environment") != environment ||
                        NativeString(item, "type") != "shared" || Version(item) is not { } version)
                    {
                        return SecretOutcome<InfisicalImportedSecrets>.Failure(SecretStatus.Unknown);
                    }
                    secrets.Add(new(key, project, environment, path, version, SecretMaterial.FromText(value)));
                }
                importedGroups.Add(new(environment, path, folderId, secrets.Skip(start)));
            }
            cancellationToken.ThrowIfCancellationRequested();
            var result = new InfisicalImportedSecrets(secrets, importedGroups, complete);
            transferred = true;
            return SecretOutcome<InfisicalImportedSecrets>.Success(result);
        }
        finally
        {
            if (!transferred) { foreach (InfisicalImportedSecret secret in secrets) { secret.Dispose(); } }
        }
    }

    private static InfisicalImport? ParseImport(JsonElement item, string folderId)
    {
        if (!NativeGuid(item, "id", out string id) || NativeString(item, "folderId") != folderId ||
            !NativeObject(item, "importEnv", out JsonElement environment) ||
            NativeString(environment, "slug") is not { } sourceEnvironment ||
            NativeString(environment, "id") is null || NativeString(environment, "name") is null ||
            NativeString(item, "importPath") is not { } path || !NativeNumber(item, "position", out double position) ||
            !NativeDates(item))
        {
            return null;
        }
        try
        {
            InfisicalNativeAddress.NativeFolder(path);
            InfisicalNativeAddress.NativeText(sourceEnvironment);
            return new(id, folderId, sourceEnvironment, path, NativeString(environment, "projectId"), position,
                NativeNullableBoolean(item, "isReplication"), NativeNullableBoolean(item, "isReplicationSuccess"),
                NativeOptionalString(item, "replicationStatus"), NativeDate(item, "lastReplicated"));
        }
        catch (ArgumentException) { return null; }
        catch (InvalidOperationException) { return null; }
    }
}
