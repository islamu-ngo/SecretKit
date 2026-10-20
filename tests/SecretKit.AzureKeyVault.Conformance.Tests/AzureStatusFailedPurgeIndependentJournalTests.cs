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
    public async Task StatusFailedPurgeIndependentHistoryCorruptionCannotReviveAfterRestore(string fault)
    {
        var f = new PurgeServiceFixture("independent-effect", statusFailedPurgeIndependent: true);
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
            else if (fault == "marker") frame["state"]!["purgeDeletedVault"]!.AsObject().Remove("failedStage");
            else frame["state"]!["purgeDeletedVault"]!["failedStage"] = "CleanupTerminal";
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
                f.Source.RetryStatusFailedPurgeIndependentPersistence(f.Native.Selector);
                revived = true;
            }
            catch (RoleFixtureJournal.StatusFailedPurgeIndependentHistoryException) { }
            catch (InvalidOperationException) { }
            await Assert.That(revived).IsFalse();
            await Assert.That(observed is RoleFixtureJournal.StatusFailedPurgeIndependentHistoryException).IsTrue();
            await Assert.That(f.SelectedPurges).IsEqualTo(1);
        }
        finally
        {
            try { await f.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (RoleFixtureJournal.StatusFailedPurgeIndependentHistoryException) { }
            catch (InvalidOperationException) { }
        }
    }


    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusFailedPurgeIndependentCompleteFrameTruncationCannotReviveAfterRestore(bool fork)
    {
        var f = new PurgeServiceFixture("independent-effect", statusFailedPurgeIndependent: true);
        try
        {
            var lease = await f.PrepareAndBaseline();
            await f.Start(lease);
            await Assert.That(f.Native.Read().PurgeDeletedVault!.FailedStage.ToString()).IsEqualTo("OriginalDrained");
            byte[] original = await File.ReadAllBytesAsync(f.Native.JournalPath);
            int last = 0, preceding = 0;
            for (int position = 0; position < original.Length;)
            {
                preceding = last;
                last = position;
                position += BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(position, 4)) + 36;
            }
            byte[] altered = original.AsMemory(0, last).ToArray();
            if (fork)
            {
                int length = BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(last, 4));
                int priorLength = BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(preceding, 4));
                var frame = JsonNode.Parse(original.AsSpan(last + 4, length))!;
                var priorFrame = JsonNode.Parse(original.AsSpan(preceding + 4, priorLength))!;
                frame["state"] = priorFrame["state"]!.DeepClone();
                frame["state"]!["closing"] = true;
                byte[] payload = JsonSerializer.SerializeToUtf8Bytes(frame, ManagementAdmission.Json);
                altered = new byte[last + payload.Length + 36];
                original.AsSpan(0, last).CopyTo(altered);
                BinaryPrimitives.WriteInt32LittleEndian(altered.AsSpan(last, 4), payload.Length);
                payload.CopyTo(altered, last + 4);
                SHA256.HashData(payload).CopyTo(altered, last + 4 + payload.Length);
            }
            Exception? observed = null;
            try
            {
                await File.WriteAllBytesAsync(f.Native.JournalPath, altered);
                if (fork)
                {
                    var fresh = new RoleFixtureJournal(Path.GetDirectoryName(f.Native.JournalPath)!);
                    await Assert.That(fresh.Read(Owner, f.Native.Selector).Closing).IsTrue();
                }
                try { f.Native.Read(); }
                catch (InvalidOperationException exception) { observed = exception; }
            }
            finally { await File.WriteAllBytesAsync(f.Native.JournalPath, original); }
            bool revived = false;
            try
            {
                f.Source.RetryStatusFailedPurgeIndependentPersistence(f.Native.Selector);
                revived = true;
            }
            catch (InvalidOperationException) { }
            await Assert.That(observed is InvalidOperationException).IsTrue();
            await Assert.That(revived).IsFalse();
            await Assert.That(() => f.Native.Read()).Throws<InvalidOperationException>();
            await Assert.That(f.SelectedPurges).IsEqualTo(1);
        }
        finally
        {
            try { await f.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (InvalidOperationException) { }
        }
    }
}
