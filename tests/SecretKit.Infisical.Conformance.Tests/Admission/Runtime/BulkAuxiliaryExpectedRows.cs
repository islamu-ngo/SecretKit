using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// Disposable SDK-owned expectation copies. This is the selected local persistence
// profile, NOT evidence of native server semantics. The provider/source never
// receives After. A native operator must qualify that profile independently.
internal sealed class BulkAuxiliaryExpectedRows : IDisposable
{
    internal BulkAuxiliaryRow[] Rows { get; }
    internal BulkAuxiliaryExpectedRows(BulkAuxiliaryInput input, string method, string boundary)
    {
        var rows = input.Baseline.ToDictionary(r => r.Key, Copy);
        if (boundary is not ("denied-authority" or "cancellation-boundary") &&
            input.Bulk.ExpectedStatus == SecretStatus.Success)
        {
            foreach (var item in input.Bulk.Items)
            {
                rows.TryGetValue(item.Key, out var seed);
                if (method == "DELETE")
                {
                    if (rows.Remove(item.Key, out var removed)) removed.Erase();
                    continue;
                }
                if (method == "PATCH" && seed is null && input.Bulk.Mode == InfisicalBulkUpdateMode.Ignore) continue;
                var row = new BulkAuxiliaryRow(item.NewName ?? item.Key,
                    item.Value is null ? seed?.Material.ToArray() ?? [] : BulkAuxiliaryContract.Bytes(item.Value),
                    item.Comment is null ? seed?.Comment.ToArray() ?? [] : BulkAuxiliaryContract.Bytes(item.Comment),
                    item.Metadata is null ? CopyMetadata(seed?.Metadata ?? []) :
                        item.Metadata.Select(m => new BulkAuxiliaryMetadata(m.Key,
                            BulkAuxiliaryContract.Bytes(m.Value ?? ""), m.Encrypted, [], false)).ToArray(),
                    item.TagIds?.ToArray() ?? seed?.TagIds.ToArray() ?? [],
                    item.CreationMetadata is null ? new(seed?.CreationMetadata ?? []) : new(item.CreationMetadata),
                    item.SkipMultilineEncoding ?? seed?.SkipMultilineEncoding ?? false,
                    item.ClearReminderNote ? null : item.ReminderNote is not null ?
                        BulkAuxiliaryContract.Bytes(item.ReminderNote) : seed?.ReminderNote?.ToArray(),
                    item.ClearReminderRepeatDays ? null : item.ReminderRepeatDays ?? seed?.ReminderRepeatDays,
                    (seed?.Version ?? 0) + 1);
                rows.Remove(item.Key);
                seed?.Erase();
                rows.Add(row.Key, row);
            }
        }
        Rows = rows.Values.ToArray();
    }
    internal static BulkAuxiliaryRow Copy(BulkAuxiliaryRow row) => new(row.Key,
        row.Material.ToArray(), row.Comment.ToArray(), CopyMetadata(row.Metadata), row.TagIds.ToArray(),
        new(row.CreationMetadata), row.SkipMultilineEncoding, row.ReminderNote?.ToArray(),
        row.ReminderRepeatDays, row.Version);
    private static BulkAuxiliaryMetadata[] CopyMetadata(BulkAuxiliaryMetadata[] values) =>
        values.Select(m => new BulkAuxiliaryMetadata(m.Key, m.Plaintext.ToArray(), m.Encrypted, [], false)).ToArray();
    public void Dispose() { foreach (var row in Rows) row.Erase(); }
}
