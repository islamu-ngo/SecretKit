using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task StatusDeniedNotificationDeleteRepeatedReleaseRequiresFreshAbsence()
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Denied);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        int childReads = f.NotificationDeleteCleanupReads;
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.NotificationDeleteCleanupReads > childReads).IsTrue();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
    }

    [Test]
    [Arguments("missing")]
    [Arguments("epoch")]
    [Arguments("writers")]
    [Arguments("older")]
    [Arguments("reuse")]
    [Arguments("revoked")]
    public async Task StatusDeniedNotificationDeleteRequiresOriginalExclusionBeforeSetup(string fault)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true);
        f.UnknownExclusion = fault != "missing";
        f.UnknownNoOlderInflight = fault != "older";
        f.UnknownNoNameReuse = fault != "reuse";
        if (fault == "revoked") f.UnknownContinuity.Cancel();
        await Assert.That(() => f.NewSource(notificationEpoch: fault == "epoch" ? Guid.Empty : f.UnknownEpoch,
            continuousWriterExclusion: fault != "writers")).Throws<InvalidOperationException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
        await Assert.That(f.SelectedDeletes + f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedNotificationDeleteLostExclusionNeverBorrowsAnotherEpoch(bool afterObservation)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        if (afterObservation) await f.Observe(lease);
        f.UnknownContinuity.Cancel();
        try { await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default); }
        catch (InvalidOperationException) { }
        catch (OperationCanceledException) { }
        var failed = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(failed, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedNotificationDeleteColdSelectedRootCannotRecoverHotCleanupAuthority(bool settled)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        if (settled)
        {
            await f.Observe(lease);
            await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
                .IsEqualTo(SecretStatus.Denied);
        }
        await f.Source.DisposeAsync();
        await f.DrainParentAsync();
        await using var parent = f.ReopenProvisioner();
        await using var cleanup = f.NewSource(cleanupOnly: true, parent: parent);
        var released = await f.NewObserver(cleanup).PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(() => RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task StatusDeniedNotificationDeleteColdNeverSelectedSetupHasDistinctBoundedCleanup()
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true);
        var lease = await f.PrepareAndBaseline();
        await f.Source.DisposeAsync();
        await f.DrainParentAsync();
        await using var parent = f.ReopenProvisioner();
        await using var cleanup = f.NewSource(cleanupOnly: true, parent: parent);
        var released = await f.NewObserver(cleanup).PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(f.SelectedDeletes + f.OriginalStatusReads + f.IndependentStatusReads).IsEqualTo(0);
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
        RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedNotificationDeleteReappearanceCannotAuthorizeAnotherChildDelete(bool malformed)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true);
        var lease = await f.PrepareAndBaseline();
        var original = f.NotificationRow!.DeepClone().AsObject();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Denied);
        f.NotificationRow = original;
        if (malformed) f.NotificationRow["properties"] = null;
        await Assert.That(async () => RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Resources.Single(r => r.SelectedAttempted).Absent).IsFalse();
    }

    [Test]
    [Arguments("""{"error":{"code":"ResourceNotFound"}}""")]
    [Arguments("{}")]
    [Arguments("{")]
    public async Task StatusDeniedNotificationDeleteCleanupNeedsFreshAuthenticatedChildAbsence(string body)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Denied);
        f.NotificationDeleteCleanup404Body = body;
        await Assert.That(async () => RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.NotificationDeleteSelectedReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeleteCleanupReads > 0).IsTrue();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }
}
