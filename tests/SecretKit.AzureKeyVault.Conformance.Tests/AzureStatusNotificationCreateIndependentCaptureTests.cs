using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments("UpdateNotification")]
    [Arguments("DeleteNotification")]
    public async Task StatusNotificationCreateIndependentHookRejectsOtherOperations(string operation)
    {
        using var f = new Fixture(operation, boundary: "independent-effect", statusNotificationCreateIndependent: true);
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("cancellation-boundary")]
    [Arguments("denied-authority")]
    public async Task StatusNotificationCreateIndependentHookRejectsOtherCasesBeforeNativeDispatch(string boundary)
    {
        using var f = new Fixture("CreateOrUpdateNotification", boundary: boundary, statusNotificationCreateIndependent: true);
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task StatusNotificationCreateIndependentRawInstrumentationCannotIssueProfileProof()
    {
        using var f = new Fixture("CreateOrUpdateNotification", boundary: "independent-effect");
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Source.TryGetStatusNotificationCreateIndependentStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusNotificationCreateIndependentForeignHandleCannotStealActualCheck()
    {
        using var f = new Fixture("CreateOrUpdateNotification", boundary: "independent-effect", statusNotificationCreateIndependent: true);
        using var other = new Fixture("CreateOrUpdateNotification");
        await f.Start();
        await other.Start();
        Task? task = null;
        await Assert.That(async () => await f.Source.CheckStatusAsync(f.Window, f.Binding.Selector,
            other.Handle!, default, t => task = t)).Throws<InvalidOperationException>();
        await Assert.That(task is null).IsTrue();
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
        await f.Source.SealAsync(f.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    public async Task StatusNotificationCreateIndependentCaptureRetainsPendingStartAndOneActualGet()
    {
        using var f = new Fixture("CreateOrUpdateNotification", boundary: "independent-effect", statusNotificationCreateIndependent: true);
        Task? start = null, later = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Source.TryGetStatusNotificationCreateIndependentStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out var proof)).IsTrue();
        await Assert.That(JsonSerializer.Serialize(proof)).IsEqualTo("{}");
        await Assert.That(f.Source.TryGetStatusNotificationCreateIndependentStart(f.Window, f.Binding with { },
            f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusNotificationCreateIndependentStart(f.Window, f.Binding,
            f.Client, (NotificationScope)f.Scope, f.Receipt, Task.CompletedTask, f.Handle!, out _)).IsFalse();
        await Assert.That(await f.Check(retained: t => later = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
        await Assert.That(f.Source.TryGetStatusNotificationCreateIndependentCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, later!, out _)).IsTrue();
        var foreign = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        foreign.SetResult(SecretStatus.Success);
        await Assert.That(ReferenceEquals(later, foreign.Task)).IsFalse();
        await Assert.That(f.Source.TryGetStatusNotificationCreateIndependentCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, foreign.Task, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Window.Start!.Owned.Concat(f.Window.Status!.Owned).All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(f.Backend.Disposed).IsFalse();
    }

    [Test]
    [Arguments("200")]
    [Arguments("202")]
    [Arguments("denied")]
    [Arguments("empty")]
    [Arguments("malformed")]
    [Arguments("succeeded")]
    [Arguments("foreign-topic")]
    [Arguments("lost")]
    public async Task StatusNotificationCreateIndependentCaptureCannotInventPendingStartProof(string fault)
    {
        using var f = new Fixture("CreateOrUpdateNotification", boundary: "independent-effect", statusNotificationCreateIndependent: true);
        if (fault == "200") f.Backend.StartStatus = 200;
        if (fault == "202") f.Backend.StartStatus = 202;
        if (fault == "denied") f.Backend.StartStatus = 403;
        if (fault == "empty") f.Backend.StartBody = "";
        if (fault == "malformed") f.Backend.StartBody = "{";
        if (fault == "succeeded") f.Backend.StartBody = f.Backend.StartBody.Replace("Updating", "Succeeded", StringComparison.Ordinal);
        if (fault == "foreign-topic") f.Backend.StartBody = f.Backend.StartBody.Replace(Vault, Vault + "-foreign", StringComparison.Ordinal);
        if (fault == "lost") f.Backend.LoseStart = true;
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusNotificationCreateIndependentStart(f.Window,
            f.Binding, f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("denied")]
    [Arguments("malformed")]
    [Arguments("updating")]
    [Arguments("failed")]
    [Arguments("foreign-topic")]
    [Arguments("lost")]
    public async Task StatusNotificationCreateIndependentCaptureRequiresActualTerminalNativeGet(string fault)
    {
        using var f = new Fixture("CreateOrUpdateNotification", boundary: "independent-effect", statusNotificationCreateIndependent: true);
        Task? start = null, later = null;
        await f.Start(retained: t => start = t);
        if (fault == "denied") f.Backend.StatusStatus = 403;
        if (fault == "malformed") f.Backend.StatusBody = "{";
        if (fault == "updating") f.Backend.StatusBody = f.Backend.StatusBody.Replace("Succeeded", "Updating", StringComparison.Ordinal);
        if (fault == "failed") f.Backend.StatusBody = f.Backend.StatusBody.Replace("Succeeded", "Failed", StringComparison.Ordinal);
        if (fault == "foreign-topic") f.Backend.StatusBody = f.Backend.StatusBody.Replace(Vault, Vault + "-foreign", StringComparison.Ordinal);
        if (fault == "lost") f.Backend.LoseStatus = true;
        await f.Check(retained: t => later = t);
        await Assert.That(f.Source.TryGetStatusNotificationCreateIndependentCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, later!, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("Location")]
    [Arguments("Azure-AsyncOperation")]
    [Arguments("Operation-Location")]
    [Arguments("Retry-After")]
    [Arguments("Content-Encoding")]
    [Arguments("Content-Range")]
    public async Task StatusNotificationCreateIndependentCaptureRejectsForeignContinuationAndPartialHeaders(string header)
    {
        using var f = new Fixture("CreateOrUpdateNotification", boundary: "independent-effect", statusNotificationCreateIndependent: true);
        f.Backend.ExtraHeaders.Add((header, header == "Retry-After" ? "1" :
            header == "Content-Encoding" ? "gzip" : header == "Content-Range" ? "bytes 0-0/1" : StatusUrl));
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusNotificationCreateIndependentStart(f.Window,
            f.Binding, f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments(1, "response")]
    [Arguments(1, "stream")]
    [Arguments(1, "null-stream")]
    [Arguments(2, "response")]
    [Arguments(2, "stream")]
    [Arguments(2, "null-stream")]
    public async Task StatusNotificationCreateIndependentCaptureRejectsOriginalOrStatusParserSubstitution(int stage, string change)
    {
        NotificationUpdateSubstitution? substitution = null;
        using var f = new Fixture("CreateOrUpdateNotification", boundary: "independent-effect", statusNotificationCreateIndependent: true,
            decorate: inner => substitution = new(inner, stage, change));
        substitution!.Bytes = Encoding.UTF8.GetBytes(stage == 1 ? f.Backend.StartBody : f.Backend.StatusBody);
        Task? start = null, later = null;
        await f.Start(retained: t => start = t);
        if (stage == 1)
            await Assert.That(f.Handle is not null && f.Source.TryGetStatusNotificationCreateIndependentStart(f.Window,
                f.Binding, f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsFalse();
        else
        {
            await f.Check(retained: t => later = t);
            await Assert.That(f.Source.TryGetStatusNotificationCreateIndependentCompletion(f.Window, f.Binding, f.Client,
                (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, later!, out _)).IsFalse();
        }
        await Assert.That(substitution.Replacements).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusNotificationCreateIndependentCaptureSealIgnoresForgedDiagnosticDrain()
    {
        using var f = new Fixture("CreateOrUpdateNotification", boundary: "independent-effect", statusNotificationCreateIndependent: true);
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
