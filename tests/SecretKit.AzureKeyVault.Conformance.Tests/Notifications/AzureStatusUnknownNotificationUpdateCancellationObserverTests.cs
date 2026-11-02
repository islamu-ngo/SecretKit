using System.Text.Json;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Op = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    private static async Task<Op.Lease> ObserveOriginalUnknownCancellationNotification(PurgeServiceFixture f)
    {
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await Assert.That(started.IsSuccess).IsTrue();
        await f.Observe(lease);
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Unknown);
        await Assert.That(started.Value!.State).IsEqualTo(NativeProvisioningState.Unknown);
        await Assert.That(f.OriginalReceipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        var selected = f.Native.Read().Resources.Single(r => r.SelectedAttempted);
        await Assert.That(selected.ActiveDispatch != Guid.Empty && selected.InvocationTerminated).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        return lease;
    }

    [Test]
    public async Task StatusUnknownNotificationUpdateCancellationOriginalRetainsUnknownUntilTerminalReleaseWitness()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdateNotification,
            statusUnknownNotificationUpdateCancellation: true);
        var tap = new CancellationStatusTap(f.Source);
        var result = await f.RunOriginal(tap);
        await Assert.That(tap.Checks.Count).IsEqualTo(2);
        await Assert.That(tap.Checks[0].Canceled && tap.Checks[0].Task.IsCanceled).IsTrue();
        await Assert.That(tap.Checks[1].Canceled).IsFalse();
        await Assert.That(f.UnknownTerminalReads).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(tap.Start!.Result.Value.State).IsEqualTo(NativeProvisioningState.Unknown);
        await Assert.That(tap.Checks.Count).IsEqualTo(2);
        await Assert.That(tap.Checks[1].Task.Result).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.UnknownTerminalReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released && f.Native.Read().Idle).IsTrue();
        await Assert.That(JsonSerializer.Serialize(f.Native.Read()).Contains(Material, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusUnknownNotificationUpdateCancellationPairUsesOneAdmissionAndNoCanceledFrame(bool finish)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdateNotification,
            statusUnknownNotificationUpdateCancellation: true);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        long before = f.Native.Read().Revision;
        await f.Observe(lease);
        await Assert.That(f.Native.Read().Revision).IsEqualTo(before + 1);
        await Assert.That(f.Native.Read().Resources.Single(r => r.SelectedAttempted).InvocationTerminated).IsFalse();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        if (finish)
        {
            await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
                .IsEqualTo(SecretStatus.Unknown);
            await Assert.That(f.Native.Read().Revision).IsEqualTo(before + 2);
            await Assert.That(f.Native.Read().Resources.Single(r => r.SelectedAttempted).ActiveDispatch != Guid.Empty).IsTrue();
            RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
            await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        }
        else
        {
            await f.Release();
            await Assert.That(f.Native.Read().Released).IsFalse();
            await Assert.That(f.Native.Read().Resources.Single(r => r.SelectedAttempted).ActiveDispatch != Guid.Empty).IsTrue();
            await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        }
    }

    [Test]
    [Arguments("status-denied")]
    [Arguments("status-malformed")]
    [Arguments("status-future")]
    [Arguments("status-foreign-id")]
    [Arguments("status-foreign-name")]
    [Arguments("status-foreign-type")]
    [Arguments("status-foreign-topic")]
    [Arguments("status-foreign-label")]
    [Arguments("status-missing-label")]
    [Arguments("status-baseline")]
    [Arguments("status-foreign-endpoint")]
    [Arguments("status-hidden-mappings")]
    [Arguments("status-extra-field")]
    [Arguments("lost")]
    [Arguments("foreign-label")]
    [Arguments("missing-label")]
    [Arguments("foreign-topic")]
    [Arguments("hidden-configuration")]
    [Arguments("configuration")]
    [Arguments("absent")]
    [Arguments("malformed")]
    [Arguments("failed")]
    [Arguments("nonterminal")]
    [Arguments("original-denied")]
    [Arguments("original-malformed")]
    [Arguments("original-lost")]
    [Arguments("original-updating")]
    [Arguments("original-foreign-topic")]
    public async Task StatusUnknownNotificationUpdateCancellationHistoricalWitnessCannotBeSubstituted(string fault)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdateNotification,
            statusUnknownNotificationUpdateCancellation: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
    }

    [Test]
    [Arguments("Unknown")]
    [Arguments("Updating")]
    [Arguments("Failed")]
    [Arguments("Canceled")]
    [Arguments("absent")]
    [Arguments("denied")]
    [Arguments("lost")]
    [Arguments("malformed")]
    [Arguments("baseline")]
    [Arguments("foreign-label")]
    [Arguments("foreign-topic")]
    public async Task StatusUnknownNotificationUpdateCancellationUnprovenTerminalReadCannotAuthorizeCleanup(string terminal)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdateNotification,
            statusUnknownNotificationUpdateCancellation: true);
        var lease = await ObserveOriginalUnknownCancellationNotification(f);
        var before = f.Native.Read().Resources.Single(r => r.SelectedAttempted).ActiveDispatch;
        f.Fault = "terminal-" + terminal;
        var release = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(release, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Read().Resources.Single(r => r.SelectedAttempted).ActiveDispatch).IsEqualTo(before);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.UnknownTerminalReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("Unknown")]
    [Arguments("Updating")]
    public async Task StatusUnknownNotificationUpdateCancellationSeparateReleaseCanObserveGenuineTerminalState(string first)
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdateNotification,
            statusUnknownNotificationUpdateCancellation: true);
        var lease = await ObserveOriginalUnknownCancellationNotification(f);
        f.Fault = "terminal-" + first;
        await f.Release();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        f.Fault = null;
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.UnknownTerminalReads).IsEqualTo(2);
        await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes).IsEqualTo(1);
    }

    [Test]
    public async Task StatusUnknownNotificationUpdateCancellationLostContinuityCannotBeHealedBySucceededRead()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdateNotification,
            statusUnknownNotificationUpdateCancellation: true);
        await ObserveOriginalUnknownCancellationNotification(f);
        f.UnknownContinuity.Cancel();
        await f.Release();
        await f.Release();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Single(r => r.SelectedAttempted).ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    public async Task StatusUnknownNotificationUpdateCancellationRejectsForeignCasesBeforeSetup(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary, ManagementMutation.UpdateNotification,
            statusUnknownNotificationUpdateCancellation: true);
        await Assert.That(async () => await f.PrepareAndBaseline()).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges + f.SelectedUpdates).IsEqualTo(0);
    }

    [Test]
    public async Task StatusUnknownNotificationUpdateCancellationColdUnresolvedRootCannotRecreateLiveAuthority()
    {
        await using var f = new PurgeServiceFixture("cancellation-boundary", ManagementMutation.UpdateNotification,
            statusUnknownNotificationUpdateCancellation: true);
        await ObserveOriginalUnknownCancellationNotification(f);
        await f.Source.DisposeAsync();
        await using var parent = f.ReopenProvisioner();
        await using var recovered = f.NewSource(cleanupOnly: true, parent: parent);
        using var observer = f.NewObserver(recovered);
        await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>("operation/release", f.Native.Selector, default);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Single(r => r.SelectedAttempted).ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
    }
}
