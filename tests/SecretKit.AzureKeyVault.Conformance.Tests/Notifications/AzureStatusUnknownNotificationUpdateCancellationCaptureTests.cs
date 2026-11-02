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
    public async Task StatusUnknownNotificationUpdateCancellationRequiresActualCanceledTaskAndExactPair()
    {
        using var f = new Fixture("UpdateNotification", "status.Unknown", boundary: "cancellation-boundary",
            statusUnknownNotificationUpdateCancellation: true);
        Task? start = null, selected = null;
        await f.Start(retained: task => start = task);
        int requests = f.Backend.Requests.Count;
        int credentials = f.Credential.Audiences.Count;
        await f.CancelUnknownCheck();
        await Assert.That(f.UnknownCanceledTask is { IsCanceled: true }).IsTrue();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(requests);
        await Assert.That(f.Credential.Audiences.Count).IsEqualTo(credentials);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Source.TryGetStatusUnknownNotificationUpdateCancellationCanceled(f.Window, f.Binding,
            f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, f.UnknownCanceledTask!, out var canceled)).IsTrue();
        await Assert.That(ReferenceEquals(canceled!.CanceledTask, f.UnknownCanceledTask)).IsTrue();
        var copied = Task.FromCanceled<SecretStatus>(new CancellationToken(canceled: true));
        await Assert.That(f.Source.TryGetStatusUnknownNotificationUpdateCancellationCanceled(f.Window, f.Binding,
            f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, copied, out _)).IsFalse();
        await Assert.That(await f.Check(retained: task => selected = task)).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Source.TryGetStatusUnknownNotificationUpdateCancellationCompletion(f.Window, f.Binding,
            f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, copied, selected!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusUnknownNotificationUpdateCancellationCompletion(f.Window, f.Binding,
            f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, f.UnknownCanceledTask!, selected!, out var complete)).IsTrue();
        await Assert.That(ReferenceEquals(complete!.Canceled, canceled)).IsTrue();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(requests + 1);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("Pending")]
    [Arguments("Failed")]
    [Arguments("Canceled")]
    public async Task StatusUnknownNotificationUpdateCancellationActualOtherStatusTasksCannotSupplyAuthority(string status)
    {
        using var owned = new Fixture("UpdateNotification", "status.Unknown", boundary: "cancellation-boundary",
            statusUnknownNotificationUpdateCancellation: true);
        using var other = new Fixture("PurgeDeletedVault", "status." + status,
            statusPendingPurge: status == "Pending", statusFailedPurge: status == "Failed",
            statusCanceledPurge: status == "Canceled");
        if (status != "Pending") other.Backend.StatusBody = "{\"status\":\"" + status + "\"}";
        Task? ownStart = null, otherStart = null;
        await owned.Start(retained: task => ownStart = task);
        await other.Start(retained: task => otherStart = task);
        await Assert.That(other.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(other.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(owned.Source.TryGetStatusUnknownNotificationUpdateCancellationStart(owned.Window, owned.Binding,
            owned.Client, (NotificationScope)owned.Scope, owned.Receipt, otherStart!, other.Handle, out _)).IsFalse();
        await Assert.That(owned.Source.TryGetStatusUnknownNotificationUpdateCancellationStart(owned.Window, owned.Binding,
            owned.Client, (NotificationScope)owned.Scope, owned.Receipt, ownStart!, owned.Handle!, out _)).IsTrue();
        await Assert.That(await owned.Check()).IsEqualTo(SecretStatus.Unknown);
        var outcome = status == "Pending"
            ? await other.Source.CheckStatusPendingPurgeAsync(other.Window, other.Binding.Selector, other.Handle, default)
            : await other.Check();
        await Assert.That(outcome).IsEqualTo(status == "Pending" ? SecretStatus.Pending : SecretStatus.Unknown);
        await Assert.That(other.Handle.State.ToString()).IsEqualTo(status);
        await owned.Source.SealAsync(owned.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    public async Task StatusUnknownNotificationUpdateCancellationActualSelectedContractCannotSupplyTaskAuthority()
    {
        using var owned = new Fixture("UpdateNotification", "status.Unknown", boundary: "cancellation-boundary",
            statusUnknownNotificationUpdateCancellation: true);
        using var other = new Fixture("UpdateNotification", "status.Unknown", boundary: "selected-contract",
            statusUnknownNotificationUpdate: true);
        Task? ownStart = null, otherStart = null;
        await owned.Start(retained: task => ownStart = task);
        await other.Start(retained: task => otherStart = task);
        await Assert.That(other.Source.TryGetStatusUnknownNotificationUpdateStart(other.Window, other.Binding,
            other.Client, (NotificationScope)other.Scope, other.Receipt, otherStart!, other.Handle!, out _)).IsTrue();
        await Assert.That(owned.Source.TryGetStatusUnknownNotificationUpdateCancellationStart(owned.Window, owned.Binding,
            owned.Client, (NotificationScope)owned.Scope, owned.Receipt, otherStart!, other.Handle!, out _)).IsFalse();
        await Assert.That(owned.Source.TryGetStatusUnknownNotificationUpdateStart(owned.Window, owned.Binding,
            owned.Client, (NotificationScope)owned.Scope, owned.Receipt, ownStart!, owned.Handle!, out _)).IsFalse();
        await Assert.That(owned.Source.TryGetStatusUnknownNotificationUpdateCancellationStart(owned.Window, owned.Binding,
            owned.Client, (NotificationScope)owned.Scope, owned.Receipt, ownStart!, owned.Handle!, out _)).IsTrue();
        await Assert.That(await owned.Check()).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(await other.Check()).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(owned.Backend.Requests.Count).IsEqualTo(2);
        await Assert.That(other.Backend.Requests.Count).IsEqualTo(2);
        await owned.Source.SealAsync(owned.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    public async Task StatusUnknownNotificationUpdateCancellationHookRejectsOtherCasesBeforeNativeDispatch(string boundary)
    {
        using var f = new Fixture("UpdateNotification", "status.Unknown", boundary: boundary, statusUnknownNotificationUpdateCancellation: true);
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task StatusUnknownNotificationUpdateCancellationRawInstrumentationCannotIssueProfileProof()
    {
        using var f = new Fixture("UpdateNotification");
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Source.TryGetStatusUnknownNotificationUpdateCancellationStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusUnknownNotificationUpdateCancellationRawExactSelectorCannotBypassTypedEnrollment()
    {
        using var f = new Fixture("UpdateNotification", "status.Unknown", boundary: "cancellation-boundary");
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task StatusUnknownNotificationUpdateCancellationFutureStateCannotIssueExactUnknownProof()
    {
        using var f = new Fixture("UpdateNotification", "status.Unknown", boundary: "cancellation-boundary",
            statusUnknownNotificationUpdateCancellation: true);
        Task? start = null, selected = null;
        await f.Start(retained: task => start = task);
        f.Backend.StatusBody = f.Backend.StatusBody.Replace("Unknown", "future-state", StringComparison.Ordinal);
        await f.Check(retained: task => selected = task);
        await Assert.That(f.Source.TryGetStatusUnknownNotificationUpdateCancellationCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, f.UnknownCanceledTask!, selected!, out _)).IsFalse();
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusUnknownNotificationUpdateCancellationForeignHandleCannotStealActualCheck()
    {
        using var f = new Fixture("UpdateNotification", "status.Unknown", boundary: "cancellation-boundary", statusUnknownNotificationUpdateCancellation: true);
        using var other = new Fixture("UpdateNotification");
        await f.Start();
        await other.Start();
        Task? task = null;
        await Assert.That(async () => await f.Source.CheckStatusAsync(f.Window, f.Binding.Selector,
            other.Handle!, default, t => task = t)).Throws<InvalidOperationException>();
        await Assert.That(task is null).IsTrue();
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
        await f.Source.SealAsync(f.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    public async Task StatusUnknownNotificationUpdateCancellationCaptureRetainsPendingStartAndOneActualGet()
    {
        using var f = new Fixture("UpdateNotification", "status.Unknown", boundary: "cancellation-boundary", statusUnknownNotificationUpdateCancellation: true);
        Task? start = null, later = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Source.TryGetStatusUnknownNotificationUpdateCancellationStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out var proof)).IsTrue();
        await Assert.That(JsonSerializer.Serialize(proof)).IsEqualTo("{}");
        await Assert.That(f.Source.TryGetStatusUnknownNotificationUpdateCancellationStart(f.Window, f.Binding with { },
            f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusUnknownNotificationUpdateCancellationStart(f.Window, f.Binding,
            f.Client, (NotificationScope)f.Scope, f.Receipt, Task.CompletedTask, f.Handle!, out _)).IsFalse();
        await Assert.That(await f.Check(retained: t => later = t)).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Handle.State).IsEqualTo(NativeProvisioningState.Unknown);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await Assert.That(f.Source.TryGetStatusUnknownNotificationUpdateCancellationCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, f.UnknownCanceledTask!, later!, out _)).IsTrue();
        var foreign = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        foreign.SetResult(SecretStatus.Unknown);
        await Assert.That(ReferenceEquals(later, foreign.Task)).IsFalse();
        await Assert.That(f.Source.TryGetStatusUnknownNotificationUpdateCancellationCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, f.UnknownCanceledTask!, foreign.Task, out _)).IsFalse();
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
    public async Task StatusUnknownNotificationUpdateCancellationCaptureCannotInventPendingStartProof(string fault)
    {
        using var f = new Fixture("UpdateNotification", "status.Unknown", boundary: "cancellation-boundary", statusUnknownNotificationUpdateCancellation: true);
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
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusUnknownNotificationUpdateCancellationStart(f.Window,
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
    public async Task StatusUnknownNotificationUpdateCancellationCaptureRequiresActualUnknownNativeGet(string fault)
    {
        using var f = new Fixture("UpdateNotification", "status.Unknown", boundary: "cancellation-boundary", statusUnknownNotificationUpdateCancellation: true);
        Task? start = null, later = null;
        await f.Start(retained: t => start = t);
        if (fault == "denied") f.Backend.StatusStatus = 403;
        if (fault == "malformed") f.Backend.StatusBody = "{";
        if (fault == "updating") f.Backend.StatusBody = f.Backend.StatusBody.Replace("Unknown", "Updating", StringComparison.Ordinal);
        if (fault == "failed") f.Backend.StatusBody = f.Backend.StatusBody.Replace("Unknown", "Failed", StringComparison.Ordinal);
        if (fault == "foreign-topic") f.Backend.StatusBody = f.Backend.StatusBody.Replace(Vault, Vault + "-foreign", StringComparison.Ordinal);
        if (fault == "lost") f.Backend.LoseStatus = true;
        await f.Check(retained: t => later = t);
        await Assert.That(f.Source.TryGetStatusUnknownNotificationUpdateCancellationCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, f.UnknownCanceledTask!, later!, out _)).IsFalse();
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
    public async Task StatusUnknownNotificationUpdateCancellationCaptureRejectsForeignContinuationAndPartialHeaders(string header)
    {
        using var f = new Fixture("UpdateNotification", "status.Unknown", boundary: "cancellation-boundary", statusUnknownNotificationUpdateCancellation: true);
        f.Backend.ExtraHeaders.Add((header, header == "Retry-After" ? "1" :
            header == "Content-Encoding" ? "gzip" : header == "Content-Range" ? "bytes 0-0/1" : StatusUrl));
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusUnknownNotificationUpdateCancellationStart(f.Window,
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
    public async Task StatusUnknownNotificationUpdateCancellationCaptureRejectsOriginalOrStatusParserSubstitution(int stage, string change)
    {
        NotificationUpdateSubstitution? substitution = null;
        using var f = new Fixture("UpdateNotification", "status.Unknown", boundary: "cancellation-boundary", statusUnknownNotificationUpdateCancellation: true,
            decorate: inner => substitution = new(inner, stage, change));
        substitution!.Bytes = Encoding.UTF8.GetBytes(stage == 1 ? f.Backend.StartBody : f.Backend.StatusBody);
        Task? start = null, later = null;
        await f.Start(retained: t => start = t);
        if (stage == 1)
            await Assert.That(f.Handle is not null && f.Source.TryGetStatusUnknownNotificationUpdateCancellationStart(f.Window,
                f.Binding, f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsFalse();
        else
        {
            await f.Check(retained: t => later = t);
            await Assert.That(f.Source.TryGetStatusUnknownNotificationUpdateCancellationCompletion(f.Window, f.Binding, f.Client,
                (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, f.UnknownCanceledTask!, later!, out _)).IsFalse();
        }
        await Assert.That(substitution.Replacements).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusUnknownNotificationUpdateCancellationCaptureSealIgnoresForgedDiagnosticDrain()
    {
        using var f = new Fixture("UpdateNotification", "status.Unknown", boundary: "cancellation-boundary", statusUnknownNotificationUpdateCancellation: true);
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
