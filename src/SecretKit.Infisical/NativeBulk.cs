using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Protected batch destination; optional folder identity enables approval correlation.</summary>
public sealed class InfisicalBulkAddress : InfisicalNativeAddress
{
    /// <summary>Selects one project/environment/folder and an optional expected folder UUID.</summary>
    public InfisicalBulkAddress(string projectId, string environment, string folder, string? folderId = null) : base(projectId, environment, folder)
    {
        if (folderId is not null && !Guid.TryParse(folderId, out _))
        {
            throw new ArgumentException("Invalid destination folder identity.");
        }
        FolderId = folderId;
    }
    /// <summary>Expected folder identity for approval validation, or null if not supplied.</summary>
    [JsonIgnore]
    public string? FolderId { get; }
}

/// <summary>Explicit native policy for update targets absent at the provider.</summary>
public enum InfisicalBulkUpdateMode { /** <summary>Ignore missing update targets.</summary> */ Ignore, /** <summary>Create missing update targets.</summary> */ Upsert, /** <summary>Reject missing update targets.</summary> */ FailOnNotFound }
/// <summary>Native shared or personal secret selection; operations admit only their documented subset.</summary>
public enum InfisicalSecretType { /** <summary>A shared secret.</summary> */ Shared, /** <summary>A personal secret.</summary> */ Personal }

/// <summary>The single native batch intent bound to a caller-held receipt.</summary>
public enum InfisicalBulkOperation { /** <summary>Create a batch.</summary> */ Create, /** <summary>Update a batch.</summary> */ Update, /** <summary>Delete a batch.</summary> */ Delete }

/// <summary>Retains immutable item snapshots independently of an operation return or cancellation.</summary>
/// <remarks>Binds the exact client/target, method, update mode and ordered nonmaterial selectors.
/// It retains no secret values or value hashes. One accepted invocation consumes it, even
/// when token acquisition fails before dispatch. Earlier snapshots never change.</remarks>
public sealed class InfisicalBulkReceipt
{
    private readonly object _gate = new();
    private readonly InfisicalClient _owner;
    private readonly SecretReference _target;
    private readonly InfisicalBulkOperation _operation;
    private readonly InfisicalBulkUpdateMode _mode;
    private readonly Selector[] _selectors;
    private readonly InfisicalBulkItemObservation[] _items;
    private bool _invoked;
    internal MutationReceipt Envelope { get; }

    /// <summary>Freezes ordered selectors before any credential acquisition or dispatch.</summary>
    /// <exception cref="ArgumentException">The target is foreign or selectors/operation are invalid.</exception>
    public InfisicalBulkReceipt(InfisicalClient client, SecretReference target,
        IReadOnlyList<InfisicalBulkSecret> inputs, InfisicalBulkOperation operation,
        InfisicalBulkUpdateMode mode = InfisicalBulkUpdateMode.FailOnNotFound)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(inputs);
        if (!target.BelongsTo(client.Authority) || target.Address is not InfisicalBulkAddress ||
            !Enum.IsDefined(operation) || !Enum.IsDefined(mode) ||
            inputs.Count > 128 || inputs.Any(input => input is null))
            throw new ArgumentException("Invalid bulk receipt selection.");
        _owner = client;
        _target = target;
        _operation = operation;
        _mode = mode;
        _selectors = inputs.Select(Select).ToArray();
        _items = Enumerable.Range(0, inputs.Count)
            .Select(index => new InfisicalBulkItemObservation(index, DispatchEvidence.NotDispatched, null)).ToArray();
        Envelope = new(target);
    }

    /// <summary>Envelope evidence does not imply all individual items were applied.</summary>
    public DispatchEvidence Evidence => Envelope.Evidence;

    /// <summary>A fresh immutable snapshot in input order, including uncertain or unobserved items.</summary>
    [JsonIgnore]
    public IReadOnlyList<InfisicalBulkItemObservation> Items
    {
        get { lock (_gate) return Array.AsReadOnly(_items.ToArray()); }
    }

    internal bool Claim(InfisicalClient client, SecretReference target,
        IReadOnlyList<InfisicalBulkSecret> inputs, InfisicalBulkOperation operation, InfisicalBulkUpdateMode mode)
    {
        lock (_gate)
        {
            if (_invoked || !ReferenceEquals(client, _owner) || !ReferenceEquals(target, _target) ||
                operation != _operation || mode != _mode || inputs.Count != _selectors.Length ||
                !inputs.Select(Select).SequenceEqual(_selectors))
                return false;
            _invoked = true;
            return true;
        }
    }

    internal void BeginDispatch()
    {
        lock (_gate)
        {
            Envelope.BeginDispatch(_target);
            for (int index = 0; index < _items.Length; index++)
                _items[index] = new(index, DispatchEvidence.PossiblyDispatched, null);
        }
    }

    internal void RecordItem(int index, DispatchEvidence evidence, string? version)
    {
        lock (_gate) _items[index] = new(index, evidence, version);
    }

    private static Selector Select(InfisicalBulkSecret input) => new(input.Key, input.NewName, input.Type, input.SecretPath);
    private sealed record Selector(string Key, string? NewName, InfisicalSecretType Type, string? SecretPath);

    /// <summary>Returns bounded evidence without selectors, material or observations.</summary>
    public override string ToString() => $"[InfisicalBulkReceipt:{Evidence}]";
}

/// <summary>Bounded native metadata; values remain protected from default JSON and formatting.</summary>
public sealed class InfisicalSecretMetadata
{
    /// <summary>Selects a metadata key, optional value and provider encryption flag.</summary>
    public InfisicalSecretMetadata(string key, string? value = null, bool encrypted = false)
    {
        InfisicalNativeAddress.NativeText(key, 255);
        if (value?.Length > 1020) { throw new ArgumentException("Invalid metadata length."); }
        Key = key;
        Value = value;
        IsEncrypted = encrypted;
    }
    /// <summary>The protected metadata key.</summary>
    [JsonIgnore]
    public string Key { get; }
    /// <summary>The optional protected metadata value.</summary>
    [JsonIgnore]
    public string? Value { get; }
    /// <summary>Whether provider-side encrypted metadata is requested.</summary>
    [JsonIgnore]
    public bool IsEncrypted { get; }
    /// <summary>Returns a fixed label without metadata fields.</summary>
    public override string ToString() => "[InfisicalSecretMetadata]";
}

/// <summary>Host-owned input material is copied before the first await.</summary>
public sealed class InfisicalBulkSecret
{
    /// <summary>Freezes bounded nonmaterial fields; borrows material until the selected operation copies it before awaiting.</summary>
    /// <remarks>Not all fields apply to every operation. Create/update/delete validate their own admitted input shape.</remarks>
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
    /// <summary>The existing or new secret key.</summary>
    [JsonIgnore]
    public string Key { get; }
    /// <summary>Borrowed input material; this input object never disposes it.</summary>
    [JsonIgnore]
    public SecretMaterial? Material { get; }
    /// <summary>Optional rename for an update.</summary>
    [JsonIgnore]
    public string? NewName { get; }
    /// <summary>Optional protected secret comment.</summary>
    [JsonIgnore]
    public string? Comment { get; }
    /// <summary>Frozen metadata input, or null to leave it unspecified.</summary>
    [JsonIgnore]
    public IReadOnlyList<InfisicalSecretMetadata>? Metadata { get; }
    /// <summary>Frozen tag identifiers, or null to leave them unspecified.</summary>
    [JsonIgnore]
    public IReadOnlyList<string>? TagIds { get; }
    /// <summary>Optional path; cross-folder rows are unsupported because responses cannot correlate them.</summary>
    [JsonIgnore]
    public string? SecretPath { get; }
    /// <summary>Optional provider multiline-encoding selection.</summary>
    [JsonIgnore]
    public bool? SkipMultilineEncoding { get; }
    /// <summary>Optional protected reminder text.</summary>
    [JsonIgnore]
    public string? ReminderNote { get; }
    /// <summary>Optional finite native reminder repeat interval in days.</summary>
    [JsonIgnore]
    public double? ReminderRepeatDays { get; }
    /// <summary>Explicitly clears the reminder note rather than omitting it.</summary>
    [JsonIgnore]
    public bool ClearReminderNote { get; }
    /// <summary>Explicitly clears the reminder interval rather than omitting it.</summary>
    [JsonIgnore]
    public bool ClearReminderRepeatDays { get; }
    /// <summary>Frozen creation-only metadata, not receipt intent or a value hash.</summary>
    [JsonIgnore]
    public IReadOnlyDictionary<string, string>? CreationMetadata { get; }
    /// <summary>The native secret kind; create/update currently admit shared secrets only.</summary>
    [JsonIgnore]
    public InfisicalSecretType Type { get; }
    /// <summary>Returns a fixed label without selectors, metadata or material.</summary>
    public override string ToString() => "[InfisicalBulkSecret]";
}

/// <summary>Immutable evidence for one input position; absence of application proof remains uncertain.</summary>
public sealed class InfisicalBulkItemObservation
{
    internal InfisicalBulkItemObservation(int index, DispatchEvidence evidence, string? version)
    {
        InputIndex = index;
        Evidence = evidence;
        Version = version;
    }
    /// <summary>Zero-based input position, independent of response row ordering.</summary>
    public int InputIndex { get; }
    /// <summary>Evidence for this item, not the batch envelope.</summary>
    public DispatchEvidence Evidence { get; }
    /// <summary>Validated returned version when applied; otherwise null.</summary>
    [JsonIgnore]
    public string? Version { get; }
    /// <summary>Returns evidence without version or secret coordinates.</summary>
    public override string ToString() => $"[InfisicalBulkItemObservation:{Evidence}]";
}

/// <summary>A response snapshot that may contain partial application or pending approval, not atomic batch success.</summary>
public sealed class InfisicalBulkObservation
{
    internal InfisicalBulkObservation(IEnumerable<InfisicalBulkItemObservation> items, string? approvalId)
    {
        Items = Array.AsReadOnly(items.ToArray());
        ApprovalId = approvalId;
    }
    /// <summary>Immutable observations in input order; retain the receipt for evidence across failure paths.</summary>
    [JsonIgnore]
    public IReadOnlyList<InfisicalBulkItemObservation> Items { get; }
    /// <summary>Validated approval identifier when submission, rather than application, was observed.</summary>
    [JsonIgnore]
    public string? ApprovalId { get; }
    /// <summary>True only for a nonempty snapshot whose every item has applied evidence.</summary>
    public bool AllApplied => Items.Count > 0 && Items.All(item => item.Evidence == DispatchEvidence.Applied);
    /// <summary>Whether a validated approval response was observed; does not prove eventual application.</summary>
    public bool ApprovalPending => ApprovalId is not null;
    /// <summary>Returns a fixed label without item or approval details.</summary>
    public override string ToString() => "[InfisicalBulkObservation]";
}

public sealed partial class InfisicalClient
{
    /// <summary>Creates a bounded batch under explicit native authority and a matching caller-held Create receipt.</summary>
    /// <remarks>Material is copied before awaiting. Retain receipt snapshots after cancellation, partial
    /// responses or malformed later rows. Envelope success does not imply every item was applied; no replay occurs.</remarks>
    public ValueTask<SecretOutcome<InfisicalBulkObservation>> CreateSecretsAsync(SecretReference target,
        IReadOnlyList<InfisicalBulkSecret> inputs, InfisicalNativeAuthority authority, InfisicalBulkReceipt receipt,
        CancellationToken cancellationToken = default) =>
        BulkSecretsAsync(target, inputs, authority, receipt, HttpMethod.Post, InfisicalBulkUpdateMode.FailOnNotFound, cancellationToken);

    /// <summary>Updates a bounded batch using the exact mode and ordered selectors frozen by its receipt.</summary>
    /// <remarks>A reused, foreign or changed-intent receipt is Invalid before dispatch.
    /// Partial or pending evidence must be reconciled by the caller, not automatically retried.</remarks>
    public ValueTask<SecretOutcome<InfisicalBulkObservation>> UpdateSecretsAsync(SecretReference target,
        IReadOnlyList<InfisicalBulkSecret> inputs, InfisicalNativeAuthority authority, InfisicalBulkReceipt receipt,
        InfisicalBulkUpdateMode mode = InfisicalBulkUpdateMode.FailOnNotFound, CancellationToken cancellationToken = default) =>
        BulkSecretsAsync(target, inputs, authority, receipt, HttpMethod.Patch, mode, cancellationToken);

    /// <summary>Deletes selected batch items with explicit native authority and a matching Delete receipt.</summary>
    /// <remarks>Cancellation does not undo deletion; caller-held immutable snapshots preserve each observed item.</remarks>
    public ValueTask<SecretOutcome<InfisicalBulkObservation>> DeleteSecretsAsync(SecretReference target,
        IReadOnlyList<InfisicalBulkSecret> inputs, InfisicalNativeAuthority authority, InfisicalBulkReceipt receipt,
        CancellationToken cancellationToken = default) =>
        BulkSecretsAsync(target, inputs, authority, receipt, HttpMethod.Delete, InfisicalBulkUpdateMode.FailOnNotFound, cancellationToken);

    private async ValueTask<SecretOutcome<InfisicalBulkObservation>> BulkSecretsAsync(SecretReference target,
        IReadOnlyList<InfisicalBulkSecret> inputs, InfisicalNativeAuthority authority, InfisicalBulkReceipt receipt,
        HttpMethod method, InfisicalBulkUpdateMode mode, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        cancellationToken.ThrowIfCancellationRequested();
        if (!Enum.IsDefined(mode) || inputs.Count is < 1 or > 128 || inputs.Any(input => input is null) ||
            receipt is null || target.Address is not InfisicalBulkAddress address ||
            !NativeTargetValid(target, authority, receipt.Envelope))
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
        InfisicalBulkOperation operation = method == HttpMethod.Post ? InfisicalBulkOperation.Create :
            method == HttpMethod.Patch ? InfisicalBulkOperation.Update : InfisicalBulkOperation.Delete;
        if (!receipt.Claim(this, target, owned, operation, mode))
            return SecretOutcome<InfisicalBulkObservation>.Failure(SecretStatus.Invalid);
        SecretOutcome<JsonDocument> outcome = await NativeDocumentAsync(target, "api/v4/secrets/batch",
            method, JsonSerializer.SerializeToUtf8Bytes(requestBody), authority, receipt.Envelope, cancellationToken, receipt);
        if (!outcome.IsSuccess) { return SecretOutcome<InfisicalBulkObservation>.Failure(outcome.Status, outcome.RetryAfter); }
        using JsonDocument document = outcome.Value;
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            root.EnumerateObject().Select(property => property.Name).Distinct(StringComparer.Ordinal).Count() !=
                root.EnumerateObject().Count() ||
            root.EnumerateObject().Any(property => property.Name != "secrets" && !UniqueBulkProperties(property.Value)))
            return SecretOutcome<InfisicalBulkObservation>.Failure(SecretStatus.Invalid);
        if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("approval", out JsonElement approval))
        {
            if (approval.ValueKind != JsonValueKind.Object || root.TryGetProperty("secrets", out _) ||
                !NativeGuid(approval, "id", out string id) || address.FolderId is null ||
                NativeString(approval, "folderId") != address.FolderId || !NativeGuid(approval, "policyId", out _) ||
                (approval.TryGetProperty("hasMerged", out JsonElement merged) && merged.ValueKind != JsonValueKind.False))
            {
                return SecretOutcome<InfisicalBulkObservation>.Failure(SecretStatus.Unknown);
            }
            receipt.Envelope.Record(DispatchEvidence.Pending);
            for (int index = 0; index < owned.Length; index++)
                receipt.RecordItem(index, DispatchEvidence.Pending, null);
            return SecretOutcome<InfisicalBulkObservation>.Success(new(receipt.Items, id));
        }
        if (!NativeArray(root, "secrets", out JsonElement items))
        {
            return SecretOutcome<InfisicalBulkObservation>.Failure(SecretStatus.Unknown);
        }
        var seen = new HashSet<int>();
        foreach (JsonElement item in items.EnumerateArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            string? key = NativeString(item, "secretKey");
            string? type = NativeString(item, "type");
            int index = Array.FindIndex(owned, input => (input.NewName ?? input.Key) == key &&
                (input.Type == InfisicalSecretType.Shared ? "shared" : "personal") == type);
            if (!UniqueBulkProperties(item) || index < 0 || !seen.Add(index) ||
                NativeString(item, "workspace") != address.ProjectId || NativeString(item, "environment") != address.Environment ||
                item.TryGetProperty("secretPath", out JsonElement path) &&
                    (path.ValueKind != JsonValueKind.String || path.GetString() != address.Folder) ||
                Version(item) is not { } version)
            {
                return SecretOutcome<InfisicalBulkObservation>.Failure(SecretStatus.Invalid);
            }
            receipt.RecordItem(index, DispatchEvidence.Applied, version);
        }
        var result = new InfisicalBulkObservation(receipt.Items, null);
        if (result.AllApplied) { receipt.Envelope.Record(DispatchEvidence.Applied); }
        return SecretOutcome<InfisicalBulkObservation>.Success(result);
    }

    private static bool UniqueBulkProperties(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in value.EnumerateObject())
                if (!names.Add(property.Name) || !UniqueBulkProperties(property.Value)) return false;
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in value.EnumerateArray())
                if (!UniqueBulkProperties(item)) return false;
        }
        return true;
    }
}
