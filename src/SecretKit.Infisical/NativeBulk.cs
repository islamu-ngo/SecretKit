using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

public sealed class InfisicalBulkAddress : InfisicalNativeAddress
{
    public InfisicalBulkAddress(string projectId, string environment, string folder, string? folderId = null) : base(projectId, environment, folder)
    {
        if (folderId is not null && !Guid.TryParse(folderId, out _))
        {
            throw new ArgumentException("Invalid destination folder identity.");
        }
        FolderId = folderId;
    }
    [JsonIgnore]
    public string? FolderId { get; }
}

public enum InfisicalBulkUpdateMode { Ignore, Upsert, FailOnNotFound }
public enum InfisicalSecretType { Shared, Personal }

public sealed class InfisicalSecretMetadata
{
    public InfisicalSecretMetadata(string key, string? value = null, bool encrypted = false)
    {
        InfisicalNativeAddress.NativeText(key, 255);
        if (value?.Length > 1020) { throw new ArgumentException("Invalid metadata length."); }
        Key = key;
        Value = value;
        IsEncrypted = encrypted;
    }
    [JsonIgnore]
    public string Key { get; }
    [JsonIgnore]
    public string? Value { get; }
    [JsonIgnore]
    public bool IsEncrypted { get; }
    public override string ToString() => "[InfisicalSecretMetadata]";
}

/// <summary>Host-owned input material is copied before the first await.</summary>
public sealed class InfisicalBulkSecret
{
    public InfisicalBulkSecret(string key, SecretMaterial? material = null, string? newName = null,
        string? comment = null, IReadOnlyList<InfisicalSecretMetadata>? metadata = null,
        IReadOnlyList<string>? tagIds = null, string? secretPath = null, bool? skipMultilineEncoding = null,
        string? reminderNote = null, double? reminderRepeatDays = null,
        bool clearReminderNote = false, bool clearReminderRepeatDays = false,
        IReadOnlyDictionary<string, string>? creationMetadata = null, InfisicalSecretType type = InfisicalSecretType.Shared)
    {
        InfisicalNativeAddress.NativeText(key);
        if (newName is not null) { InfisicalNativeAddress.NativeText(newName); }
        if (secretPath is not null) { InfisicalNativeAddress.NativeFolder(secretPath); }
        if (comment?.Length > 65536 || reminderNote?.Length > 1024 ||
            (reminderNote is not null && clearReminderNote) || (reminderRepeatDays is not null && clearReminderRepeatDays) ||
            (reminderRepeatDays is { } days && !double.IsFinite(days)) || !Enum.IsDefined(type) ||
            metadata is { Count: > 128 } || metadata?.Any(item => item is null) == true ||
            tagIds is { Count: > 128 } || creationMetadata is { Count: > 128 })
        {
            throw new ArgumentException("Invalid bounded bulk input.");
        }
        if (tagIds is not null)
        {
            foreach (string id in tagIds) { InfisicalNativeAddress.NativeText(id); }
        }
        if (creationMetadata is not null)
        {
            foreach (KeyValuePair<string, string> pair in creationMetadata)
            {
                InfisicalNativeAddress.NativeText(pair.Key, 255);
                if (pair.Value is null || pair.Value.Length > 65536) { throw new ArgumentException("Invalid metadata input."); }
            }
        }
        Key = key;
        Material = material;
        NewName = newName;
        Comment = comment;
        Metadata = metadata is null ? null : Array.AsReadOnly(metadata.ToArray());
        TagIds = tagIds is null ? null : Array.AsReadOnly(tagIds.ToArray());
        SecretPath = secretPath;
        SkipMultilineEncoding = skipMultilineEncoding;
        ReminderNote = reminderNote;
        ReminderRepeatDays = reminderRepeatDays;
        ClearReminderNote = clearReminderNote;
        ClearReminderRepeatDays = clearReminderRepeatDays;
        CreationMetadata = creationMetadata is null ? null :
            new System.Collections.ObjectModel.ReadOnlyDictionary<string, string>(new Dictionary<string, string>(creationMetadata, StringComparer.Ordinal));
        Type = type;
    }
    [JsonIgnore]
    public string Key { get; }
    [JsonIgnore]
    public SecretMaterial? Material { get; }
    [JsonIgnore]
    public string? NewName { get; }
    [JsonIgnore]
    public string? Comment { get; }
    [JsonIgnore]
    public IReadOnlyList<InfisicalSecretMetadata>? Metadata { get; }
    [JsonIgnore]
    public IReadOnlyList<string>? TagIds { get; }
    [JsonIgnore]
    public string? SecretPath { get; }
    [JsonIgnore]
    public bool? SkipMultilineEncoding { get; }
    [JsonIgnore]
    public string? ReminderNote { get; }
    [JsonIgnore]
    public double? ReminderRepeatDays { get; }
    [JsonIgnore]
    public bool ClearReminderNote { get; }
    [JsonIgnore]
    public bool ClearReminderRepeatDays { get; }
    [JsonIgnore]
    public IReadOnlyDictionary<string, string>? CreationMetadata { get; }
    [JsonIgnore]
    public InfisicalSecretType Type { get; }
    public override string ToString() => "[InfisicalBulkSecret]";
}

public sealed class InfisicalBulkItemObservation
{
    internal InfisicalBulkItemObservation(int index, DispatchEvidence evidence, string? version)
    {
        InputIndex = index;
        Evidence = evidence;
        Version = version;
    }
    public int InputIndex { get; }
    public DispatchEvidence Evidence { get; }
    [JsonIgnore]
    public string? Version { get; }
    public override string ToString() => $"[InfisicalBulkItemObservation:{Evidence}]";
}

public sealed class InfisicalBulkObservation
{
    internal InfisicalBulkObservation(IEnumerable<InfisicalBulkItemObservation> items, string? approvalId)
    {
        Items = Array.AsReadOnly(items.ToArray());
        ApprovalId = approvalId;
    }
    [JsonIgnore]
    public IReadOnlyList<InfisicalBulkItemObservation> Items { get; }
    [JsonIgnore]
    public string? ApprovalId { get; }
    public bool AllApplied => Items.All(item => item.Evidence == DispatchEvidence.Applied);
    public bool ApprovalPending => ApprovalId is not null;
    public override string ToString() => "[InfisicalBulkObservation]";
}

public sealed partial class InfisicalClient
{
    public ValueTask<SecretOutcome<InfisicalBulkObservation>> CreateSecretsAsync(SecretReference target,
        IReadOnlyList<InfisicalBulkSecret> inputs, InfisicalNativeAuthority authority, MutationReceipt receipt,
        CancellationToken cancellationToken = default) =>
        BulkSecretsAsync(target, inputs, authority, receipt, HttpMethod.Post, InfisicalBulkUpdateMode.FailOnNotFound, cancellationToken);

    public ValueTask<SecretOutcome<InfisicalBulkObservation>> UpdateSecretsAsync(SecretReference target,
        IReadOnlyList<InfisicalBulkSecret> inputs, InfisicalNativeAuthority authority, MutationReceipt receipt,
        InfisicalBulkUpdateMode mode = InfisicalBulkUpdateMode.FailOnNotFound, CancellationToken cancellationToken = default) =>
        BulkSecretsAsync(target, inputs, authority, receipt, HttpMethod.Patch, mode, cancellationToken);

    public ValueTask<SecretOutcome<InfisicalBulkObservation>> DeleteSecretsAsync(SecretReference target,
        IReadOnlyList<InfisicalBulkSecret> inputs, InfisicalNativeAuthority authority, MutationReceipt receipt,
        CancellationToken cancellationToken = default) =>
        BulkSecretsAsync(target, inputs, authority, receipt, HttpMethod.Delete, InfisicalBulkUpdateMode.FailOnNotFound, cancellationToken);

    private async ValueTask<SecretOutcome<InfisicalBulkObservation>> BulkSecretsAsync(SecretReference target,
        IReadOnlyList<InfisicalBulkSecret> inputs, InfisicalNativeAuthority authority, MutationReceipt receipt,
        HttpMethod method, InfisicalBulkUpdateMode mode, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        cancellationToken.ThrowIfCancellationRequested();
        if (!Enum.IsDefined(mode) || inputs.Count is < 1 or > 128 || inputs.Any(input => input is null) ||
            target.Address is not InfisicalBulkAddress address || !NativeTargetValid(target, authority, receipt))
        {
            return SecretOutcome<InfisicalBulkObservation>.Failure(SecretStatus.Invalid);
        }
        InfisicalBulkSecret[] owned = inputs.ToArray();
        if (owned.Select(input => (input.NewName ?? input.Key, input.Type)).Distinct().Count() != owned.Length)
        {
            return SecretOutcome<InfisicalBulkObservation>.Failure(SecretStatus.Invalid);
        }
        var bodies = new List<Dictionary<string, object?>>();
        long inputCharacters = 0;
        foreach (InfisicalBulkSecret input in owned)
        {
            cancellationToken.ThrowIfCancellationRequested();
            inputCharacters += input.Key.Length + (input.NewName?.Length ?? 0) + (input.Comment?.Length ?? 0) +
                (input.SecretPath?.Length ?? 0) + (input.ReminderNote?.Length ?? 0) +
                (input.Metadata?.Sum(item => (long)item.Key.Length + (item.Value?.Length ?? 0)) ?? 0) +
                (input.TagIds?.Sum(id => (long)id.Length) ?? 0) +
                (input.CreationMetadata?.Sum(pair => (long)pair.Key.Length + pair.Value.Length) ?? 0);
            if (inputCharacters > _responseLimit)
            {
                return SecretOutcome<InfisicalBulkObservation>.Failure(SecretStatus.Invalid);
            }
            // The bulk result does not identify row paths. Do not manufacture per-path correlation.
            if (input.SecretPath is not null && input.SecretPath != address.Folder)
            {
                return SecretOutcome<InfisicalBulkObservation>.Failure(SecretStatus.Unsupported);
            }
            if (method == HttpMethod.Post && (input.Material is null || input.NewName is not null ||
                    input.SecretPath is not null || input.ReminderNote is not null || input.ReminderRepeatDays is not null ||
                    input.ClearReminderNote || input.ClearReminderRepeatDays || input.Type != InfisicalSecretType.Shared) ||
                method == HttpMethod.Patch && (input.CreationMetadata is not null || input.Type != InfisicalSecretType.Shared) ||
                method == HttpMethod.Delete && (input.Material is not null || input.NewName is not null ||
                    input.Comment is not null || input.Metadata is not null || input.TagIds is not null ||
                    input.SecretPath is not null || input.SkipMultilineEncoding is not null ||
                    input.ReminderNote is not null || input.ReminderRepeatDays is not null ||
                    input.ClearReminderNote || input.ClearReminderRepeatDays || input.CreationMetadata is not null))
            {
                return SecretOutcome<InfisicalBulkObservation>.Failure(SecretStatus.Invalid);
            }
            var body = new Dictionary<string, object?> { ["secretKey"] = input.Key };
            if (input.Material is not null)
            {
                using SecretMaterial material = input.Material.Copy();
                string text = material.Reveal();
                inputCharacters += text.Length;
                if (inputCharacters > _responseLimit)
                {
                    return SecretOutcome<InfisicalBulkObservation>.Failure(SecretStatus.Invalid);
                }
                body["secretValue"] = text;
            }
            if (method == HttpMethod.Delete) { body["type"] = input.Type == InfisicalSecretType.Shared ? "shared" : "personal"; }
            if (input.NewName is not null) { body["newSecretName"] = input.NewName; }
            if (input.Comment is not null) { body["secretComment"] = input.Comment; }
            if (input.Metadata is not null)
            {
                body["secretMetadata"] = input.Metadata.Select(item => new
                {
                    key = item.Key,
                    value = item.Value,
                    isEncrypted = item.IsEncrypted
                }).Select(item => JsonSerializer.SerializeToElement(item, NativePayloadOptions)).ToArray();
            }
            if (input.TagIds is not null) { body["tagIds"] = input.TagIds; }
            if (input.SecretPath is not null) { body["secretPath"] = input.SecretPath; }
            if (input.SkipMultilineEncoding is not null) { body["skipMultilineEncoding"] = input.SkipMultilineEncoding; }
            if (input.ReminderNote is not null || input.ClearReminderNote) { body["secretReminderNote"] = input.ReminderNote; }
            if (input.ReminderRepeatDays is not null || input.ClearReminderRepeatDays) { body["secretReminderRepeatDays"] = input.ReminderRepeatDays; }
            if (input.CreationMetadata is not null) { body["metadata"] = input.CreationMetadata; }
            bodies.Add(body);
        }
        var requestBody = new Dictionary<string, object?>
        {
            ["projectId"] = address.ProjectId,
            ["environment"] = address.Environment,
            ["secretPath"] = address.Folder,
            ["secrets"] = bodies
        };
        if (method == HttpMethod.Patch)
        {
            requestBody["mode"] = mode switch
            {
                InfisicalBulkUpdateMode.Ignore => "ignore",
                InfisicalBulkUpdateMode.Upsert => "upsert",
                _ => "failOnNotFound"
            };
        }
        SecretOutcome<JsonDocument> outcome = await NativeDocumentAsync(target, "api/v4/secrets/batch",
            method, JsonSerializer.SerializeToUtf8Bytes(requestBody), authority, receipt, cancellationToken);
        if (!outcome.IsSuccess) { return SecretOutcome<InfisicalBulkObservation>.Failure(outcome.Status, outcome.RetryAfter); }
        using JsonDocument document = outcome.Value;
        JsonElement root = document.RootElement;
        if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("approval", out JsonElement approval))
        {
            if (approval.ValueKind != JsonValueKind.Object || root.TryGetProperty("secrets", out _) ||
                !NativeGuid(approval, "id", out string id) || address.FolderId is null ||
                NativeString(approval, "folderId") != address.FolderId || !NativeGuid(approval, "policyId", out _) ||
                (approval.TryGetProperty("hasMerged", out JsonElement merged) && merged.ValueKind != JsonValueKind.False))
            {
                return SecretOutcome<InfisicalBulkObservation>.Failure(SecretStatus.Unknown);
            }
            receipt.Record(DispatchEvidence.Pending);
            return SecretOutcome<InfisicalBulkObservation>.Success(new(
                owned.Select((_, index) => new InfisicalBulkItemObservation(index, DispatchEvidence.Pending, null)), id));
        }
        if (!NativeArray(root, "secrets", out JsonElement items) || items.GetArrayLength() > owned.Length)
        {
            return SecretOutcome<InfisicalBulkObservation>.Failure(SecretStatus.Unknown);
        }
        var observations = owned.Select((_, index) =>
            new InfisicalBulkItemObservation(index, DispatchEvidence.PossiblyDispatched, null)).ToArray();
        foreach (JsonElement item in items.EnumerateArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            string? key = NativeString(item, "secretKey");
            string? type = NativeString(item, "type");
            int index = Array.FindIndex(owned, input => (input.NewName ?? input.Key) == key &&
                (input.Type == InfisicalSecretType.Shared ? "shared" : "personal") == type);
            if (index < 0 || observations[index].Evidence != DispatchEvidence.PossiblyDispatched ||
                NativeString(item, "workspace") != address.ProjectId || NativeString(item, "environment") != address.Environment ||
                Version(item) is not { } version)
            {
                return SecretOutcome<InfisicalBulkObservation>.Failure(SecretStatus.Unknown);
            }
            observations[index] = new(index, DispatchEvidence.Applied, version);
        }
        var result = new InfisicalBulkObservation(observations, null);
        if (result.AllApplied) { receipt.Record(DispatchEvidence.Applied); }
        return SecretOutcome<InfisicalBulkObservation>.Success(result);
    }
}
