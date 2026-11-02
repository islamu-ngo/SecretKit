using System.Text.Json;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments(false, false)]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task StatusDeniedNotificationDeleteOriginalJoinsOperationClosureThenNewAbsence(
        bool unauthorized, bool aaoOnly)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true)
        {
            Fault = unauthorized ? "original-unauthorized" : null,
            NotificationDeleteAaoOnly = aaoOnly
        };
        var tap = new CancellationStatusTap(f.Source);
        await Assert.That((await f.RunOriginal(tap)).Passed).IsTrue();
        await Assert.That(tap.Checks.Count).IsEqualTo(1);
        await Assert.That(tap.Checks[0].Task.Result).IsEqualTo(SecretStatus.Denied);
        await Assert.That(ReferenceEquals(tap.Start!.Result.Value, tap.Checks[0].Handle)).IsTrue();
        await Assert.That(tap.Checks[0].Handle.State).IsEqualTo(NativeProvisioningState.Failed);
        await Assert.That(tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeleteSelectedReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeleteCleanupReads >= 3).IsTrue();
        await Assert.That(f.NotificationDeletes).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        var released = f.Native.Read();
        await Assert.That(released.Released && released.Idle).IsTrue();
        await Assert.That(released.Resources.Count()).IsEqualTo(4);
        await Assert.That(released.Resources.All(r => r.Absent)).IsTrue();
        await Assert.That(released.Resources.Single(r => r.SelectedAttempted).DeleteAttempted).IsFalse();
        await Assert.That(f.Prejournaled).IsTrue();
        await Assert.That(JsonSerializer.Serialize(released).Contains(Material, StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(released).Contains("https://unused.example/webhook", StringComparison.Ordinal))
            .IsFalse();
    }

    [Test]
    [Arguments(200, """{"status":"InProgress"}""")]
    [Arguments(200, """{"status":"Deleting"}""")]
    [Arguments(200, """{"status":"Failed"}""")]
    [Arguments(200, """{"status":"future-state"}""")]
    [Arguments(200, """{"Status":"Succeeded"}""")]
    [Arguments(200, """{"status":"Succeeded","error":{}}""")]
    [Arguments(200, "{}")]
    [Arguments(202, """{"status":"Succeeded"}""")]
    [Arguments(404, """{"error":{"code":"NotFound"}}""")]
    [Arguments(403, """{"error":{"code":"AuthorizationFailed","message":"controlled"}}""")]
    public async Task StatusDeniedNotificationDeleteAbsenceCannotReplaceIndependentOriginalClosure(int code, string body)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true)
        {
            NotificationDeleteStatusCode = code,
            NotificationDeleteStatusBody = body
        };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.NotificationDeleteSelectedReads).IsEqualTo(0);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("""{"error":{"code":"ResourceNotFound"}}""")]
    [Arguments("""{"error":{"code":"Forbidden"}}""")]
    [Arguments("""{"error":{"code":"NotFound"},"unexpected":true}""")]
    [Arguments("{}")]
    [Arguments("{")]
    public async Task StatusDeniedNotificationDeleteTerminalStatusCannotReplaceStrictNewChildAbsence(string body)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true) { NotificationDeleteSelected404Body = body };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeleteSelectedReads).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("start-denied")]
    [Arguments("missing-aao")]
    [Arguments("nonempty")]
    [Arguments("lost")]
    public async Task StatusDeniedNotificationDeleteUncertainStartCannotCreateCleanupAuthority(string fault)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads + f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("original-pending")]
    [Arguments("original-malformed")]
    [Arguments("original-lost")]
    public async Task StatusDeniedNotificationDeleteInvalidOriginalCheckCannotClearDispatch(string fault)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true) { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeleteSelectedReads).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(1);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("selected-credential")]
    [Arguments("selected-send")]
    [Arguments("selected-body")]
    [Arguments("selected-sdk")]
    [Arguments("status-credential")]
    [Arguments("status-send")]
    [Arguments("status-body")]
    [Arguments("notification-read")]
    [Arguments("notification-read-body")]
    [Arguments("original-status")]
    [Arguments("original-status-body")]
    public async Task StatusDeniedNotificationDeleteDisposalJoinsActualBorrowers(string barrier)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true);
        var lease = await f.PrepareAndBaseline();
        Task work;
        if (barrier.StartsWith("selected", StringComparison.Ordinal))
        {
            f.Barrier = barrier;
            work = f.Start(lease);
        }
        else
        {
            var started = await f.Start(lease);
            if (barrier.StartsWith("original", StringComparison.Ordinal))
            {
                await f.Observe(lease);
                f.Barrier = barrier;
                work = f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default).AsTask();
            }
            else
            {
                f.Barrier = barrier;
                work = f.Observe(lease).AsTask();
            }
        }
        Task? disposing = null;
        Task<RoleFixtureRelease.Measurement>? releasing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            releasing = f.Release().AsTask();
            disposing = f.Source.DisposeAsync().AsTask();
            await Assert.That(work.IsCompleted || disposing.IsCompleted).IsFalse();
            await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or NativeCaseFailureException or InvalidOperationException) { }
        await Assert.That(async () => RoleFixtureRelease.Validate(
            await releasing!.WaitAsync(TimeSpan.FromSeconds(10)), f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedNotificationDeleteRetainsRawCallerVetoAfterStartCtsDisposal(bool afterObservation)
    {
        await using var f = new PurgeServiceFixture("denied-authority", ManagementMutation.DeleteNotification,
            statusDeniedNotificationDelete: true);
        using var caller = new CancellationTokenSource();
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease, caller.Token);
        if (afterObservation) await f.Observe(lease);
        caller.Cancel();
        try
        {
            if (afterObservation) await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
            else await f.Observe(lease);
        }
        catch (Exception exception) when (exception is OperationCanceledException or NativeCaseFailureException or InvalidOperationException) { }
        var released = await f.Release();
        await Assert.That(() => RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.NotificationDeletes + f.SetupDeletes + f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
    }
}
