using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal enum BulkAuxiliarySourceKind { NativeProvider, ControlledFixture }

// Private capability, not a vendor JSON escape hatch. The string map is restricted
// to two interop annotations; neither key is assigned provider-specific meaning.
// Primary interface facts retrieved through Tavily on 2026-10-14:
// https://infisical.com/docs/api-reference/endpoints/secrets/create-many.md
// https://infisical.com/docs/api-reference/endpoints/secrets/update-many.md
// https://infisical.com/docs/api-reference/endpoints/secrets/delete-many
// These establish typed field vocabulary/defaults, nullable reminders and three
// batch modes. They do NOT establish native omission/replacement persistence,
// encryption-at-rest, interop annotation interpretation or approval semantics.
internal sealed record BulkAuxiliaryInput(NativeBulkEffects.BulkInput Bulk,
    BulkAuxiliaryRow[] Baseline, BulkAuxiliaryRow[] Expected, string ProviderRevision,
    string DeploymentId, string SourceProfile, string RootNonce, int TimeoutSeconds)
{
    public override string ToString() => "[BulkAuxiliaryInput]";
}

internal sealed record BulkAuxiliaryRoot(string Id, string CaseIdentity, string Origin,
    string ProjectId, string Environment, string Namespace, string Folder, string FolderId,
    string Method, string Shape, NativeIdentityRole Role, string ProviderRevision,
    string DeploymentId, string SourceProfile, string Nonce, BulkAuxiliarySourceKind Source)
{
    public override string ToString() => "[BulkAuxiliaryRoot]";
}

// Plaintext field bytes are independent storage reads, not the SDK response.
// Encrypted metadata carries a separate stored representation and authenticated
// decryption measurement. No key or ciphertext is included in a report.
internal sealed record BulkAuxiliaryMetadata(string Key, byte[] Plaintext, bool Encrypted,
    byte[] Stored, bool AuthenticatedDecryption)
{
    public override string ToString() => "[BulkAuxiliaryMetadata]";
}

internal sealed record BulkAuxiliaryRow(string Key, byte[] Material, byte[] Comment,
    BulkAuxiliaryMetadata[] Metadata, string[] TagIds, Dictionary<string, string> CreationMetadata,
    bool? SkipMultilineEncoding, byte[]? ReminderNote, double? ReminderRepeatDays, int Version)
{
    internal void Erase()
    {
        CryptographicOperations.ZeroMemory(Material);
        CryptographicOperations.ZeroMemory(Comment);
        if (ReminderNote is not null) CryptographicOperations.ZeroMemory(ReminderNote);
        foreach (var field in Metadata)
        {
            CryptographicOperations.ZeroMemory(field.Plaintext);
            CryptographicOperations.ZeroMemory(field.Stored);
        }
    }
    public override string ToString() => "[BulkAuxiliaryRow]";
}

internal sealed record BulkAuxiliaryBinding(
    [property: JsonRequired] BulkAuxiliaryRoot Root,
    [property: JsonRequired] string Registration,
    [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] string ClockAuthority,
    [property: JsonRequired] string ClockEpoch,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset At,
    [property: JsonRequired] bool NamespaceCollisionCheckedBeforeSetup,
    [property: JsonRequired] bool RootInitiallyAbsent,
    [property: JsonRequired] bool ProtectedStorageQualified,
    [property: JsonRequired] bool OriginalCaptureArmed,
    [property: JsonRequired] bool BorrowedPreserved,
    [property: JsonRequired] BulkAuxiliaryRow[] Baseline)
{
    public override string ToString() => "[BulkAuxiliaryBinding]";
}

internal sealed record BulkAuxiliaryFence(
    [property: JsonRequired] BulkAuxiliaryRoot Root,
    [property: JsonRequired] string Registration,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] string? RequestId,
    [property: JsonRequired] int OriginalRequests,
    [property: JsonRequired] int CommittedRows,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset At,
    [property: JsonRequired] DispatchEvidence Receipt,
    [property: JsonRequired] bool ExactOriginalScopeIdentityMethodShape,
    [property: JsonRequired] bool Settled,
    [property: JsonRequired] bool LateWorkExcluded,
    [property: JsonRequired] bool NoReplay)
{
    public override string ToString() => "[BulkAuxiliaryFence]";
}

internal sealed record BulkAuxiliarySnapshot(
    [property: JsonRequired] BulkAuxiliaryRoot Root,
    [property: JsonRequired] string Registration,
    [property: JsonRequired] string FenceEvent,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset At,
    [property: JsonRequired] bool FullBatchMappedBackendInventory,
    [property: JsonRequired] bool IndependentProtectedStorageRead,
    [property: JsonRequired] bool BorrowedPreserved,
    [property: JsonRequired] BulkAuxiliaryRow[] Rows)
{
    public override string ToString() => "[BulkAuxiliarySnapshot]";
}

internal sealed record BulkAuxiliaryCleanup(
    [property: JsonRequired] BulkAuxiliaryRoot Root,
    [property: JsonRequired] bool OriginalSettled,
    [property: JsonRequired] bool LateWorkExcluded,
    [property: JsonRequired] bool RootAbsent,
    [property: JsonRequired] bool FullInventoryEmpty,
    [property: JsonRequired] bool BorrowedPreserved,
    [property: JsonRequired] bool PrivateCopiesReleased,
    [property: JsonRequired] int Registrations,
    [property: JsonRequired] int PendingDeliveries)
{
    public override string ToString() => "[BulkAuxiliaryCleanup]";
}

internal interface IBulkAuxiliarySource
{
    BulkAuxiliarySourceKind Kind { get; }
    string Identity { get; }
    ValueTask<BulkAuxiliaryBinding> OpenAsync(BulkAuxiliaryRoot root,
        BulkAuxiliaryRow[] baseline, CancellationToken token);
    ValueTask<BulkAuxiliaryFence> CompleteAsync(BulkAuxiliaryRoot root,
        DispatchEvidence receipt, CancellationToken token);
    ValueTask<BulkAuxiliarySnapshot> ObserveAsync(BulkAuxiliaryRoot root, CancellationToken token);
    ValueTask<BulkAuxiliaryCleanup> CloseAsync(BulkAuxiliaryRoot root, CancellationToken token);
}

internal static class BulkAuxiliaryContract
{
    internal static JsonSerializerOptions Options { get; } = new(InfisicalStaticFamilies.Options)
    { IgnoreReadOnlyProperties = false };
    internal const string Prefix = "i.runtime.InfisicalClient.";
    internal static readonly string[] Methods = ["CreateSecretsAsync", "UpdateSecretsAsync", "DeleteSecretsAsync"];
    internal static readonly string[] Cases = ["selected-contract", "denied-authority",
        "cancellation-boundary", "independent-effect", "lost-response-no-replay"];
    internal static bool Gated(string variant) => variant is "type.Personal" or
        "result.approval-pending" or "result.unobserved-items";
    internal static string Method(NativeCaseDefinition d) => d.Key.Operation switch
    {
        Prefix + "CreateSecretsAsync" => "POST",
        Prefix + "UpdateSecretsAsync" => "PATCH",
        Prefix + "DeleteSecretsAsync" => "DELETE",
        _ => throw new NativeCaseFailureException("contract-mismatch")
    };
    internal static string Member(string method) => "SecretKit.Infisical.InfisicalClient." + method +
        "(SecretKit.Core.SecretReference,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.InfisicalBulkSecret>," +
        "SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt," +
        (method == "UpdateSecretsAsync" ? "SecretKit.Infisical.InfisicalBulkUpdateMode," : "") +
        "System.Threading.CancellationToken)";

    // Canonical closed input shape: source must reconstruct it from the ORIGINAL
    // batch. It is never the SDK response or a hash of an arbitrary vendor object.
    internal static string Shape(NativeBulkEffects.BulkSecretInput[] items, InfisicalBulkUpdateMode mode)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new { items, mode }, Options);
        try { return Convert.ToHexString(SHA256.HashData(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static byte[] Bytes(string value) => Encoding.UTF8.GetBytes(value);
    internal static bool Equal(BulkAuxiliaryRow[] actual, BulkAuxiliaryRow[] expected, bool storage)
    {
        if (actual.Length != expected.Length || actual.Select(r => r.Key).Distinct().Count() != actual.Length) return false;
        return expected.All(e => actual.SingleOrDefault(a => a.Key == e.Key) is { } a &&
            a.Material.AsSpan().SequenceEqual(e.Material) && a.Comment.AsSpan().SequenceEqual(e.Comment) &&
            a.Version == e.Version && a.SkipMultilineEncoding == e.SkipMultilineEncoding &&
            a.ReminderRepeatDays == e.ReminderRepeatDays &&
            (a.ReminderNote is null ? e.ReminderNote is null :
                e.ReminderNote is not null && a.ReminderNote.AsSpan().SequenceEqual(e.ReminderNote)) &&
            a.TagIds.Order(StringComparer.Ordinal).SequenceEqual(e.TagIds.Order(StringComparer.Ordinal)) &&
            a.CreationMetadata.Count == e.CreationMetadata.Count &&
            e.CreationMetadata.All(p => a.CreationMetadata.TryGetValue(p.Key, out var v) && v == p.Value) &&
            a.Metadata.Length == e.Metadata.Length && a.Metadata.Select(m => m.Key).Distinct().Count() == a.Metadata.Length &&
            e.Metadata.All(m => a.Metadata.SingleOrDefault(n => n.Key == m.Key) is { } n &&
                n.Plaintext.AsSpan().SequenceEqual(m.Plaintext) && n.Encrypted == m.Encrypted &&
                (!storage || (n.Encrypted ? n.AuthenticatedDecryption && n.Stored.Length >= 28 &&
                    !n.Stored.AsSpan().SequenceEqual(n.Plaintext) :
                    !n.AuthenticatedDecryption && n.Stored.AsSpan().SequenceEqual(n.Plaintext)))));
    }
    internal static void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) throw new NativeCaseFailureException(code); }
}
