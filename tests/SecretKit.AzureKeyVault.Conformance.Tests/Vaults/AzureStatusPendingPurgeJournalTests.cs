using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments("selector")]
    [Arguments("marker")]
    [Arguments("illegal-stage")]
    public async Task StatusPendingPurgeHistoryCorruptionCannotReviveAfterRestore(string fault)
    {
        var f = new PurgeServiceFixture(statusPendingPurge: true);
        try
        {
            var lease = await f.PrepareAndBaseline();
            await f.Start(lease);
            byte[] original = await File.ReadAllBytesAsync(f.Native.JournalPath);
            int last = 0;
            for (int position = 0; position < original.Length;)
            {
                last = position;
                position += BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(position, 4)) + 36;
            }
            int length = BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(last, 4));
            var frame = JsonNode.Parse(original.AsSpan(last + 4, length))!;
            if (fault == "selector") frame["state"]!.AsObject().Remove("selector");
            else if (fault == "marker") frame["state"]!["purgeDeletedVault"]!.AsObject().Remove("pendingStage");
            else frame["state"]!["purgeDeletedVault"]!["pendingStage"] = "CleanupTerminal";
            byte[] payload = JsonSerializer.SerializeToUtf8Bytes(frame, ManagementAdmission.Json);
            byte[] corrupt = new byte[last + payload.Length + 36];
            original.AsSpan(0, last).CopyTo(corrupt);
            BinaryPrimitives.WriteInt32LittleEndian(corrupt.AsSpan(last, 4), payload.Length);
            payload.CopyTo(corrupt, last + 4);
            SHA256.HashData(payload).CopyTo(corrupt, last + 4 + payload.Length);
            Exception? observed = null;
            try
            {
                await File.WriteAllBytesAsync(f.Native.JournalPath, corrupt);
                try { f.Native.Read(); }
                catch (Exception exception) { observed = exception; }
            }
            finally { await File.WriteAllBytesAsync(f.Native.JournalPath, original); }
            bool revived = false;
            try
            {
                f.Source.RetryStatusPendingPurgePersistence(f.Native.Selector);
                revived = true;
            }
            catch (RoleFixtureJournal.StatusPendingPurgeHistoryException) { }
            catch (InvalidOperationException) { }
            await Assert.That(revived).IsFalse();
            await Assert.That(observed is RoleFixtureJournal.StatusPendingPurgeHistoryException).IsTrue();
            await Assert.That(f.SelectedPurges).IsEqualTo(1);
        }
        finally
        {
            try { await f.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (RoleFixtureJournal.StatusPendingPurgeHistoryException) { }
            catch (InvalidOperationException) { }
        }
    }

}
