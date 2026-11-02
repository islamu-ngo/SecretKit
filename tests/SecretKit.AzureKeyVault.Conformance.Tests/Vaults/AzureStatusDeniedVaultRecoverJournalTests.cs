using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task StatusDeniedVaultRecoverGenericJournalCannotEndOrSettleOriginalDispatch()
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.RecoverVault,
            statusDeniedVaultRecover: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var before = f.Native.Read();
        var row = before.Resources.Single(r => r.SelectedAttempted);
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch, false))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch, true))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Revision).IsEqualTo(before.Revision);
        await Assert.That(f.Native.Read().RecoverVault!.SettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Denied);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selector")]
    [Arguments("marker")]
    [Arguments("configuration")]
    [Arguments("payload")]
    [Arguments("fork")]
    [Arguments("truncate")]
    public async Task StatusDeniedVaultRecoverCorruptHistoryCannotReviveAfterRestoration(string fault)
    {
        var f = new PurgeServiceFixture("denied-authority", ManagementMutation.RecoverVault,
            statusDeniedVaultRecover: true);
        try
        {
            var lease = await f.PrepareAndBaseline();
            await f.Start(lease);
            _ = f.Native.Read();
            byte[] original = await File.ReadAllBytesAsync(f.Native.JournalPath);
            int last = 0;
            for (int position = 0; position < original.Length;)
            {
                last = position;
                position += BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(position, 4)) + 36;
            }
            int length = BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(last, 4));
            var frame = JsonNode.Parse(original.AsSpan(last + 4, length))!;
            if (fault == "selector") frame["state"]!["selector"]!["case"] = "independent-effect";
            else if (fault == "marker") frame["state"]!["recoverVault"]!["settledDispatch"] = Guid.NewGuid();
            else if (fault == "configuration") frame["state"]!["recoverVault"]!["baseline"]!["publicNetworkAccess"] = false;
            else if (fault == "payload") frame["state"]!["purgeDeletedVault"] =
                new JsonObject { ["deniedStage"] = "DeniedObserved" };
            else frame["state"]!["closing"] = true;
            byte[] payload = JsonSerializer.SerializeToUtf8Bytes(frame, ManagementAdmission.Json);
            byte[] corrupt = new byte[last + payload.Length + 36];
            original.AsSpan(0, last).CopyTo(corrupt);
            BinaryPrimitives.WriteInt32LittleEndian(corrupt.AsSpan(last, 4), payload.Length);
            payload.CopyTo(corrupt, last + 4);
            SHA256.HashData(payload).CopyTo(corrupt, last + 4 + payload.Length);
            if (fault == "truncate") corrupt = original.AsSpan(0, last).ToArray();
            try
            {
                await File.WriteAllBytesAsync(f.Native.JournalPath, corrupt);
                await Assert.That(() => f.Native.Read()).Throws<InvalidOperationException>();
            }
            finally { await File.WriteAllBytesAsync(f.Native.JournalPath, original); }
            await Assert.That(() => f.Native.Read())
                .Throws<RoleFixtureJournal.StatusDeniedVaultRecoverHistoryException>();
            await Assert.That(() => f.Source.RetryStatusDeniedVaultRecoverPersistence(f.Native.Selector))
                .Throws<InvalidOperationException>();
            await Assert.That(f.SelectedRecoveries).IsEqualTo(1);
            await Assert.That(f.SetupDeletes + f.SetupPurges).IsEqualTo(1);
        }
        finally
        {
            try { await f.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (InvalidOperationException) { }
        }
    }
}
