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
    public async Task StatusNotificationUpdateCancellationCaptureRetainsPendingStartAndOneActualGet()
    {
        using var f = new Fixture("UpdateNotification", boundary: "cancellation-boundary");
        Task? start = null, canceled = null, later = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Source.TryGetStatusNotificationUpdateCancellationStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out var proof)).IsTrue();
        await Assert.That(JsonSerializer.Serialize(proof)).IsEqualTo("{}");
        await Assert.That(f.Source.TryGetStatusNotificationUpdateCancellationStart(f.Window, f.Binding with { },
            f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusNotificationUpdateCancellationStart(f.Window, f.Binding,
            f.Client, (NotificationScope)f.Scope, f.Receipt, Task.CompletedTask, f.Handle!, out _)).IsFalse();
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token, t => canceled = t)).Throws<OperationCanceledException>();
        await Assert.That(canceled!.IsCanceled).IsTrue();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Source.OwnsNotificationUpdateCanceledStatusAttempt(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, canceled)).IsTrue();
        await Assert.That(f.Source.OwnsNotificationUpdateCanceledStatusAttempt(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, Task.FromCanceled<SecretStatus>(stop.Token))).IsFalse();
        await Assert.That(await f.Check(retained: t => later = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await Assert.That(f.Source.OwnsStatusNotificationUpdateCancellationCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, canceled, later!)).IsTrue();
        var foreign = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        foreign.SetResult(SecretStatus.Success);
        await Assert.That(ReferenceEquals(later, foreign.Task)).IsFalse();
        await Assert.That(f.Source.OwnsStatusNotificationUpdateCancellationCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, canceled, foreign.Task)).IsFalse();
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
    public async Task StatusNotificationUpdateCancellationCaptureCannotInventPendingStartProof(string fault)
    {
        using var f = new Fixture("UpdateNotification", boundary: "cancellation-boundary");
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
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusNotificationUpdateCancellationStart(f.Window,
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
    public async Task StatusNotificationUpdateCancellationCaptureRequiresActualTerminalNativeGet(string fault)
    {
        using var f = new Fixture("UpdateNotification", boundary: "cancellation-boundary");
        Task? start = null, canceled = null, later = null;
        await f.Start(retained: t => start = t);
        if (fault == "denied") f.Backend.StatusStatus = 403;
        if (fault == "malformed") f.Backend.StatusBody = "{";
        if (fault == "updating") f.Backend.StatusBody = f.Backend.StatusBody.Replace("Succeeded", "Updating", StringComparison.Ordinal);
        if (fault == "failed") f.Backend.StatusBody = f.Backend.StatusBody.Replace("Succeeded", "Failed", StringComparison.Ordinal);
        if (fault == "foreign-topic") f.Backend.StatusBody = f.Backend.StatusBody.Replace(Vault, Vault + "-foreign", StringComparison.Ordinal);
        if (fault == "lost") f.Backend.LoseStatus = true;
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token, t => canceled = t)).Throws<OperationCanceledException>();
        await f.Check(retained: t => later = t);
        await Assert.That(f.Source.OwnsStatusNotificationUpdateCancellationCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, canceled!, later!)).IsFalse();
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
    public async Task StatusNotificationUpdateCancellationCaptureRejectsForeignContinuationAndPartialHeaders(string header)
    {
        using var f = new Fixture("UpdateNotification", boundary: "cancellation-boundary");
        f.Backend.ExtraHeaders.Add((header, header == "Retry-After" ? "1" :
            header == "Content-Encoding" ? "gzip" : header == "Content-Range" ? "bytes 0-0/1" : StatusUrl));
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusNotificationUpdateCancellationStart(f.Window,
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
    public async Task StatusNotificationUpdateCancellationCaptureRejectsOriginalOrStatusParserSubstitution(int stage, string change)
    {
        NotificationUpdateSubstitution? substitution = null;
        using var f = new Fixture("UpdateNotification", boundary: "cancellation-boundary",
            decorate: inner => substitution = new(inner, stage, change));
        substitution!.Bytes = Encoding.UTF8.GetBytes(stage == 1 ? f.Backend.StartBody : f.Backend.StatusBody);
        Task? start = null, canceled = null, later = null;
        await f.Start(retained: t => start = t);
        if (stage == 1)
            await Assert.That(f.Handle is not null && f.Source.TryGetStatusNotificationUpdateCancellationStart(f.Window,
                f.Binding, f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsFalse();
        else
        {
            using var stop = new CancellationTokenSource();
            stop.Cancel();
            await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
                f.Handle!, stop.Token, t => canceled = t)).Throws<OperationCanceledException>();
            await f.Check(retained: t => later = t);
            await Assert.That(f.Source.OwnsStatusNotificationUpdateCancellationCompletion(f.Window, f.Binding, f.Client,
                (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, canceled!, later!)).IsFalse();
        }
        await Assert.That(substitution.Replacements).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("uncanceled")]
    [Arguments("foreign-handle")]
    [Arguments("retention")]
    public async Task StatusNotificationUpdateCancellationCaptureRejectsInvalidFirstCheck(string fault)
    {
        using var f = new Fixture("UpdateNotification", boundary: "cancellation-boundary");
        using var other = new Fixture("UpdateNotification");
        Task? start = null, canceled = null;
        await f.Start(retained: t => start = t);
        await other.Start();
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        Task<SecretStatus> Invoke() => f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            fault == "foreign-handle" ? other.Handle! : f.Handle!, fault == "uncanceled" ? default : stop.Token, t =>
            {
                canceled = t;
                if (fault == "retention") throw new InvalidOperationException("controlled-retention-failure");
            });
        if (fault == "retention")
        {
            await Assert.That(async () => await Invoke()).Throws<OperationCanceledException>();
            await Assert.That(canceled!.IsCanceled).IsTrue();
            await Assert.That(f.Source.OwnsNotificationUpdateCanceledStatusAttempt(f.Window, f.Binding, f.Client,
                (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, canceled)).IsFalse();
        }
        else
        {
            await Assert.That(async () => await Invoke()).Throws<InvalidOperationException>();
            await Assert.That(canceled is null).IsTrue();
        }
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusNotificationUpdateCancellationCaptureInvalidFirstCheckPermanentlyRejectsLaterSlot(bool repeated)
    {
        using var f = new Fixture("UpdateNotification", boundary: "cancellation-boundary");
        await f.Start();
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        if (repeated)
            await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
                f.Handle!, stop.Token)).Throws<OperationCanceledException>();
        else await Assert.That(async () => await f.Check()).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token)).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Check()).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusNotificationUpdateCancellationCaptureSealIgnoresForgedDiagnosticDrain()
    {
        using var f = new Fixture("UpdateNotification", boundary: "cancellation-boundary");
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

    private sealed class NotificationUpdateSubstitution(HttpPipelineTransport inner, int stage, string change) : HttpPipelineTransport
    {
        internal byte[] Bytes = [];
        internal int Replacements;
        private int calls;
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            if (++calls != stage) return;
            Replacements++;
            if (change == "response") message.Response = new OwnedArmResponse(message.Response.Status,
                message.Response.ReasonPhrase, message.Response.ClientRequestId, message.Response.Headers.ToArray(),
                new MemoryStream(Bytes, false));
            else message.Response.ContentStream = change == "stream" ? new MemoryStream(Bytes, false) : null;
        }
    }
}
