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
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedNotificationDeleteObservationFlushRetryDoesNotRepeatProviderWork(bool releaseFirst)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        f.Native.Journal.FailStatusDeniedNotificationDeleteFlushOnce(Owner, f.Native.Selector, f.Native.Read().Revision + 2);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<IOException>();
        long revision = f.Native.Read().Revision;
        int reads = f.NotificationResourceReads + f.ResourceReads + f.IndependentStatusReads + f.OriginalStatusReads;
        await Assert.That(f.Native.Read().Closing).IsFalse();
        if (!releaseFirst)
        {
            await Assert.That(f.Source.RetryStatusDeniedNotificationDeletePersistence(f.Native.Selector).Revision)
                .IsEqualTo(revision);
            await Assert.That(f.NotificationResourceReads + f.ResourceReads + f.IndependentStatusReads + f.OriginalStatusReads)
                .IsEqualTo(reads);
        }
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes).IsEqualTo(0);
    }

    [Test]
    public async Task StatusDeniedNotificationDeleteFinalAbsenceNeedsRealFlushBeforeAcknowledgment()
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Denied);
        bool reached = false;
        f.BeforeUnknownFinalAbsence = () =>
        {
            reached = true;
            var deleted = f.Native.Read().Resources.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal));
            if (!deleted.InvocationTerminated || deleted.ActiveDispatch != Guid.Empty)
                throw new InvalidOperationException("final-absence-before-purge-drain");
            f.Native.Journal.FailStatusDeniedNotificationDeleteFlushOnce(Owner, f.Native.Selector, f.Native.Read().Revision + 1);
        };
        var failed = await f.Release();
        await Assert.That(reached).IsTrue();
        await Assert.That(() => RoleFixtureRelease.Validate(failed, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Read().Released).IsTrue();
        long revision = f.Native.Read().Revision;
        int reads = f.NotificationResourceReads + f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads;
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(revision);
        await Assert.That(f.NotificationResourceReads + f.ResourceReads + f.OriginalStatusReads + f.IndependentStatusReads)
            .IsEqualTo(reads);
    }

    [Test]
    [Arguments("selector")]
    [Arguments("variant")]
    [Arguments("payload")]
    [Arguments("sequence")]
    [Arguments("truncate")]
    [Arguments("borrowed")]
    public async Task StatusDeniedNotificationDeleteCorruptThenRestoredHistoryCannotReviveAuthority(string fault)
    {
        var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true);
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
            if (fault == "selector") frame["state"]!["selector"]!["case"] = "selected-contract";
            else if (fault == "variant") frame["state"]!["selector"]!["variant"] = "operation.UpdateNotification";
            else if (fault == "payload") frame["state"]!["purgeDeletedVault"] = new JsonObject();
            else if (fault == "borrowed") frame["state"]!["resources"]![0]!["borrowed"] = true;
            else frame["sequence"] = frame["sequence"]!.GetValue<long>() + 2;
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
                await Assert.That(() => f.Native.Read())
                    .Throws<RoleFixtureJournal.StatusDeniedNotificationDeleteHistoryException>();
            }
            finally { await File.WriteAllBytesAsync(f.Native.JournalPath, original); }
            await Assert.That(() => f.Native.Read())
                .Throws<RoleFixtureJournal.StatusDeniedNotificationDeleteHistoryException>();
            await Assert.That(() => f.Source.RetryStatusDeniedNotificationDeletePersistence(f.Native.Selector))
                .Throws<InvalidOperationException>();
            await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        }
        finally
        {
            try { await f.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (InvalidOperationException) { }
        }
    }

    [Test]
    public async Task StatusDeniedNotificationDeleteConstructedReadAdmissionCannotConsumeOriginalDispatch()
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        var before = f.Native.Read();
        var selected = before.Resources.Single(r => r.SelectedAttempted);
        await Assert.That(() => f.Native.Journal.AdmitStatusDeniedNotificationDeleteRead(
            Owner, f.Native.Selector, lease.Facts.LeaseId, selected.ActiveDispatch,
            new ManagementOperationFixtureObserverService.StatusDeniedNotificationDeleteReadAdmission(f.Source)))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Revision).IsEqualTo(before.Revision);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Denied);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
    }
}
