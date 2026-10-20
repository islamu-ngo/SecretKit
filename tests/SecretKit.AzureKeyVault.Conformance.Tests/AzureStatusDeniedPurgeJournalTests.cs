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
    [Arguments(NativeProvisioningState.Succeeded)]
    [Arguments(NativeProvisioningState.Pending)]
    [Arguments(NativeProvisioningState.Failed)]
    [Arguments(NativeProvisioningState.Canceled)]
    [Arguments(NativeProvisioningState.Unknown)]
    public async Task StatusDeniedPurgeStatusReleaseRetriesExactObservationWithoutNewCheck(NativeProvisioningState variant)
    {
        await using var f = new PurgeServiceFixture("denied-authority",
            statusDeniedPurge: true, statusDeniedVariant: variant);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        f.Native.Journal.FailStatusDeniedPurgeFlushOnce(Owner, f.Native.Selector, f.Native.Read().Revision + 2);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<IOException>();
        long revision = f.Native.Read().Revision;
        int reads = f.ResourceReads;
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(revision + 2);
        await Assert.That(f.ResourceReads).IsEqualTo(reads + 2);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments(NativeProvisioningState.Succeeded)]
    [Arguments(NativeProvisioningState.Pending)]
    [Arguments(NativeProvisioningState.Failed)]
    [Arguments(NativeProvisioningState.Canceled)]
    [Arguments(NativeProvisioningState.Unknown)]
    public async Task StatusDeniedPurgeStatusHistoryCannotChangeToAnotherAdmittedVariant(NativeProvisioningState variant)
    {
        var f = new PurgeServiceFixture("denied-authority",
            statusDeniedPurge: true, statusDeniedVariant: variant);
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
            frame["state"]!["selector"]!["variant"] = "operation.PurgeDeletedVault";
            byte[] payload = JsonSerializer.SerializeToUtf8Bytes(frame, ManagementAdmission.Json);
            byte[] corrupt = new byte[last + payload.Length + 36];
            original.AsSpan(0, last).CopyTo(corrupt);
            BinaryPrimitives.WriteInt32LittleEndian(corrupt.AsSpan(last, 4), payload.Length);
            payload.CopyTo(corrupt, last + 4);
            SHA256.HashData(payload).CopyTo(corrupt, last + 4 + payload.Length);
            try
            {
                await File.WriteAllBytesAsync(f.Native.JournalPath, corrupt);
                await Assert.That(() => f.Native.Read()).Throws<InvalidOperationException>();
            }
            finally { await File.WriteAllBytesAsync(f.Native.JournalPath, original); }
            await Assert.That(() => f.Source.RetryStatusDeniedPurgePersistence(f.Native.Selector))
                .Throws<InvalidOperationException>();
            await Assert.That(f.SelectedPurges).IsEqualTo(1);
        }
        finally
        {
            try { await f.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (InvalidOperationException) { }
        }
    }

    [Test]
    [Arguments("selector")]
    [Arguments("marker")]
    [Arguments("illegal-stage")]
    [Arguments("truncate")]
    [Arguments("fork")]
    public async Task StatusDeniedPurgeCorruptOrRolledBackHistoryCannotReviveAfterRestore(string fault)
    {
        var f = new PurgeServiceFixture("denied-authority", statusDeniedPurge: true);
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
            else if (fault == "marker") frame["state"]!["purgeDeletedVault"]!.AsObject().Remove("deniedStage");
            else if (fault == "fork") frame["state"]!["closing"] = true;
            else frame["state"]!["purgeDeletedVault"]!["deniedStage"] = "DeniedObserved";
            byte[] payload = JsonSerializer.SerializeToUtf8Bytes(frame, ManagementAdmission.Json);
            byte[] corrupt = new byte[last + payload.Length + 36];
            original.AsSpan(0, last).CopyTo(corrupt);
            BinaryPrimitives.WriteInt32LittleEndian(corrupt.AsSpan(last, 4), payload.Length);
            payload.CopyTo(corrupt, last + 4);
            SHA256.HashData(payload).CopyTo(corrupt, last + 4 + payload.Length);
            if (fault == "truncate") corrupt = original.AsSpan(0, last).ToArray();
            Exception? observed = null;
            try
            {
                await File.WriteAllBytesAsync(f.Native.JournalPath, corrupt);
                try { f.Native.Read(); }
                catch (InvalidOperationException exception) { observed = exception; }
            }
            finally { await File.WriteAllBytesAsync(f.Native.JournalPath, original); }
            await Assert.That(observed is InvalidOperationException).IsTrue();
            await Assert.That(() => f.Source.RetryStatusDeniedPurgePersistence(f.Native.Selector))
                .Throws<InvalidOperationException>();
            await Assert.That(f.SelectedPurges).IsEqualTo(1);
        }
        finally
        {
            try { await f.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (InvalidOperationException) { }
        }
    }

    [Test]
    public async Task StatusDeniedPurgeJoinedObservationFlushRetryDoesNotReadCachedFailedHandle()
    {
        await using var f = new PurgeServiceFixture("denied-authority", statusDeniedPurge: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var before = f.Native.Read();
        f.Native.Journal.FailStatusDeniedPurgeFlushOnce(Owner, f.Native.Selector, before.Revision + 2);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<IOException>();
        long readableRevision = f.Native.Read().Revision;
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        var retried = f.Source.RetryStatusDeniedPurgePersistence(f.Native.Selector);
        await Assert.That(retried.Revision).IsEqualTo(readableRevision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
        await Assert.That(retried.PurgeDeletedVault!.DeniedStage.ToString()).IsEqualTo("DeniedObserved");
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusDeniedPurgeReleaseFlushesRetainedObservationBeforeClosing()
    {
        await using var f = new PurgeServiceFixture("denied-authority", statusDeniedPurge: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        f.Native.Journal.FailStatusDeniedPurgeFlushOnce(Owner, f.Native.Selector, f.Native.Read().Revision + 2);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<IOException>();
        long readableRevision = f.Native.Read().Revision;
        int reads = f.ResourceReads;
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        var released = f.Native.Read();
        await Assert.That(released.Released && released.Closing && released.Idle).IsTrue();
        await Assert.That(released.Revision).IsEqualTo(readableRevision + 2);
        await Assert.That(f.ResourceReads).IsEqualTo(reads + 2);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task StatusDeniedPurgeFinalAbsenceRequiresRealFlushBeforeSuccessfulRelease()
    {
        await using var f = new PurgeServiceFixture("denied-authority", statusDeniedPurge: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Denied);
        f.BeforeDeniedFinalAbsence = () => f.Native.Journal.FailStatusDeniedPurgeFlushOnce(
            Owner, f.Native.Selector, f.Native.Read().Revision + 1);
        var failed = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(failed, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Read().Released).IsTrue();
        long readableRevision = f.Native.Read().Revision;
        int reads = f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(readableRevision);
        await Assert.That(f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(reads);
    }
}
