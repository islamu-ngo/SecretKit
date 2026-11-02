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
    public async Task StatusDeniedPrivateConnectionDeleteFinalAbsenceRequiresFlushBeforeRelease()
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeletePrivateConnection,
            statusDeniedPrivateConnectionDelete: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Denied);
        f.BeforeDeniedFinalAbsence = () => f.Native.Journal.FailStatusDeniedPrivateConnectionDeleteFlushOnce(
            Owner, f.Native.Selector, f.Native.Read().Revision + 1);
        var failed = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(failed, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Read().Released).IsTrue();
        long revision = f.Native.Read().Revision;
        int reads = f.ResourceReads + f.PrivateChildResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(revision);
        await Assert.That(f.ResourceReads + f.PrivateChildResourceReads + f.OriginalStatusReads + f.IndependentStatusReads)
            .IsEqualTo(reads);
        await Assert.That(f.PrivateEndpoint!.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedPrivateConnectionDeleteObservationFlushRetryPreservesExactCandidate(bool releaseFirst)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeletePrivateConnection,
            statusDeniedPrivateConnectionDelete: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        f.Native.Journal.FailStatusDeniedPrivateConnectionDeleteFlushOnce(Owner, f.Native.Selector,
            f.Native.Read().Revision + 2);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<IOException>();
        long revision = f.Native.Read().Revision;
        int reads = f.PrivateChildResourceReads + f.ResourceReads + f.IndependentStatusReads + f.OriginalStatusReads;
        if (!releaseFirst)
        {
            var retried = f.Source.RetryStatusDeniedPrivateConnectionDeletePersistence(f.Native.Selector);
            await Assert.That(retried.Revision).IsEqualTo(revision);
            await Assert.That(f.PrivateChildResourceReads + f.ResourceReads + f.IndependentStatusReads + f.OriginalStatusReads)
                .IsEqualTo(reads);
        }
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.PrivateEndpoint!.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
    }

    [Test]
    public async Task StatusDeniedPrivateConnectionDeleteGenericJournalCannotClearSelectedDispatch()
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeletePrivateConnection,
            statusDeniedPrivateConnectionDelete: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var before = f.Native.Read();
        var child = before.PrivateEndpoint!.Connection!;
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, child.Id, child.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, child.Id, child.ActiveDispatch, true))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Revision).IsEqualTo(before.Revision);
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(child.ActiveDispatch);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Denied);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selector")]
    [Arguments("marker")]
    [Arguments("payload")]
    [Arguments("fork")]
    [Arguments("truncate")]
    public async Task StatusDeniedPrivateConnectionDeleteCorruptHistoryCannotReviveAfterRestore(string fault)
    {
        var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeletePrivateConnection,
            statusDeniedPrivateConnectionDelete: true);
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
            else if (fault == "marker") frame["state"]!["privateEndpoint"]!["statusDeleteSettledDispatch"] = Guid.NewGuid();
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
            await Assert.That(() => f.Source.RetryStatusDeniedPrivateConnectionDeletePersistence(f.Native.Selector))
                .Throws<InvalidOperationException>();
            await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        }
        finally
        {
            try { await f.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (InvalidOperationException) { }
        }
    }
}
