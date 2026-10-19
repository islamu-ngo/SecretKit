using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments(200, false)]
    [Arguments(200, true)]
    [Arguments(204, false)]
    [Arguments(204, true)]
    public async Task StatusNotificationDeleteIndependentCaptureBindsActualStartAndSingleCachedCheck(int status, bool nullIngress)
    {
        using var f = new Fixture("DeleteNotification", boundary: "independent-effect",
            statusNotificationDeleteIndependent: true);
        f.Backend.StartStatus = status;
        f.Backend.NullResponseStream = nullIngress;
        Task? start = null, check = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(f.Source.TryGetStatusNotificationDeleteIndependentStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out var issued)).IsTrue();
        await Assert.That(issued).IsNotNull();
        await Assert.That(f.Source.TryGetStatusNotificationDeleteIndependentStart(f.Window, f.Binding with { }, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusNotificationDeleteIndependentStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, Task.CompletedTask, f.Handle!, out _)).IsFalse();
        var copiedReceipt = f.Client.PrepareReceipt(f.Scope, ManagementMutation.DeleteNotification);
        await Assert.That(f.Source.TryGetStatusNotificationDeleteIndependentStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, copiedReceipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusNotificationDeleteCancellationStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(await f.Check(retained: t => check = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusNotificationDeleteIndependentCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, check!, out var completion)).IsTrue();
        await Assert.That(completion).IsNotNull();
        var foreign = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        foreign.SetResult(SecretStatus.Success);
        await Assert.That(ReferenceEquals(check, foreign.Task)).IsFalse();
        await Assert.That(f.Source.TryGetStatusNotificationDeleteIndependentCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, foreign.Task, out _)).IsFalse();
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await Assert.That(f.Source.TryGetStatusTarget(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(0);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Backend.RequestBytes.Length).IsEqualTo(0);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(async () => await f.Check()).Throws<InvalidOperationException>();
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Window.Start!.Owned.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(f.Backend.Disposed).IsFalse();
    }

    [Test]
    public async Task StatusNotificationDeleteIndependentRawInstrumentationCannotMintTypedProof()
    {
        using var f = new Fixture("DeleteNotification", boundary: "independent-effect");
        Task? start = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusNotificationDeleteIndependentStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("Location")]
    [Arguments("Azure-AsyncOperation")]
    [Arguments("Operation-Location")]
    [Arguments("Retry-After")]
    [Arguments("Content-Encoding")]
    [Arguments("Content-Range")]
    public async Task StatusNotificationDeleteIndependentCaptureRejectsContinuationAndPartialHeaders(string header)
    {
        using var f = new Fixture("DeleteNotification", boundary: "independent-effect",
            statusNotificationDeleteIndependent: true);
        f.Backend.ExtraHeaders.Add((header, header == "Retry-After" ? "1" :
            header == "Content-Encoding" ? "gzip" : header == "Content-Range" ? "bytes 0-0/1" :
                Origin + Notification + "?api-version=2025-02-15"));
        Task? start = null;
        await f.Start(retained: t => start = t);
        bool proof = f.Handle is not null && f.Source.TryGetStatusNotificationDeleteIndependentStart(f.Window,
            f.Binding, f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle, out _);
        await Assert.That(proof).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("accepted202")]
    [Arguments("denied")]
    [Arguments("nonempty200")]
    [Arguments("nonempty204")]
    [Arguments("declared-length")]
    public async Task StatusNotificationDeleteIndependentCaptureCannotInventEmptySynchronousProof(string fault)
    {
        using var f = new Fixture("DeleteNotification", boundary: "independent-effect",
            statusNotificationDeleteIndependent: true);
        f.Backend.StartStatus = fault == "accepted202" ? 202 : fault == "denied" ? 403 :
            fault == "nonempty204" ? 204 : 200;
        if (fault.StartsWith("nonempty", StringComparison.Ordinal)) f.Backend.StartBody = """{"status":"Succeeded"}""";
        if (fault == "declared-length") f.Backend.DeclaredLength = 1;
        Task? start = null;
        await f.Start(retained: t => start = t);
        bool proof = f.Handle is not null && f.Source.TryGetStatusNotificationDeleteIndependentStart(f.Window,
            f.Binding, f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle, out _);
        await Assert.That(proof).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments(200, "response")]
    [Arguments(200, "stream")]
    [Arguments(200, "null-stream")]
    [Arguments(204, "response")]
    [Arguments(204, "stream")]
    [Arguments(204, "null-stream")]
    public async Task StatusNotificationDeleteIndependentCaptureRejectsPhysicalEmptyResponseSubstitution(int status, string change)
    {
        NotificationEmptySubstitution? substitution = null;
        using var f = new Fixture("DeleteNotification", boundary: "independent-effect",
            decorate: inner => substitution = new(inner, change), statusNotificationDeleteIndependent: true);
        f.Backend.StartStatus = status;
        Task? start = null;
        await f.Start(retained: t => start = t);
        bool proof = f.Handle is not null && f.Source.TryGetStatusNotificationDeleteIndependentStart(f.Window,
            f.Binding, f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle, out _);
        await Assert.That(proof).IsFalse();
        await Assert.That(substitution!.Replacements).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusNotificationDeleteIndependentForeignHandleCannotConsumeCheck()
    {
        using var f = new Fixture("DeleteNotification", boundary: "independent-effect",
            statusNotificationDeleteIndependent: true);
        using var other = new Fixture("DeleteNotification");
        await f.Start();
        await other.Start();
        Task? retained = null;
        await Assert.That(async () => await f.Source.CheckStatusAsync(f.Window, f.Binding.Selector,
            other.Handle!, default, t => retained = t)).Throws<InvalidOperationException>();
        await Assert.That(retained is null).IsTrue();
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    public async Task StatusNotificationDeleteIndependentFailedCheckRetentionCannotMintCompletion()
    {
        using var f = new Fixture("DeleteNotification", boundary: "independent-effect",
            statusNotificationDeleteIndependent: true);
        Task? start = null, check = null;
        await f.Start(retained: t => start = t);
        await Assert.That(async () => await f.Check(retained: t =>
        {
            check = t;
            throw new InvalidOperationException("controlled-retention-failure");
        })).Throws<InvalidOperationException>();
        await Assert.That(check).IsNotNull();
        await Assert.That(f.Source.TryGetStatusNotificationDeleteIndependentCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, check!, out _)).IsFalse();
        await Assert.That(async () => await f.Check()).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusNotificationDeleteIndependentCaptureSealJoinsActualCredentialTask()
    {
        using var f = new Fixture("DeleteNotification", boundary: "independent-effect",
            statusNotificationDeleteIndependent: true);
        f.Credential.Block = true;
        using var cancellation = new CancellationTokenSource();
        Task? sealing = null;
        var work = f.Start(cancellation.Token);
        try
        {
            await f.Credential.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            sealing = f.Source.SealAsync(f.Window);
            cancellation.Cancel();
            await f.Credential.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(10));
            f.Window.Start!.Drained.TrySetResult();
            f.Window.Start.SdkTask = Task.CompletedTask;
            await Assert.That(sealing.IsCompleted).IsFalse();
            await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        }
        finally { f.Credential.Release.TrySetResult(); }
        await Assert.That(async () => await work.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        await sealing!.WaitAsync(TimeSpan.FromSeconds(10));
    }
}
