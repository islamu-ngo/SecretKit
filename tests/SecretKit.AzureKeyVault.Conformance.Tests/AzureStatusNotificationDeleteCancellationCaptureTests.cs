using Azure.Core;
using Azure.Core.Pipeline;
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
    public async Task StatusNotificationDeleteCancellationCaptureRetainsRealEmptyResponseAndBothActualTasks(int status, bool nullIngress)
    {
        using var f = new Fixture("DeleteNotification", boundary: "cancellation-boundary");
        f.Backend.StartStatus = status;
        f.Backend.NullResponseStream = nullIngress;
        Task? start = null, canceled = null, later = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(f.Source.TryGetStatusNotificationDeleteCancellationStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out var issued)).IsTrue();
        await Assert.That(issued).IsNotNull();
        await Assert.That(f.Source.TryGetStatusNotificationDeleteCancellationStart(f.Window, f.Binding with { }, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusNotificationDeleteCancellationStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, Task.CompletedTask, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token, t => canceled = t)).Throws<OperationCanceledException>();
        await Assert.That(canceled!.IsCanceled).IsTrue();
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(f.Source.OwnsNotificationDeleteCanceledStatusAttempt(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, canceled)).IsTrue();
        await Assert.That(f.Source.OwnsNotificationDeleteCanceledStatusAttempt(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, Task.FromCanceled<SecretStatus>(stop.Token))).IsFalse();
        await Assert.That(await f.Check(retained: t => later = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(ReferenceEquals(canceled, later)).IsFalse();
        await Assert.That(f.Source.OwnsStatusNotificationDeleteCancellationCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, canceled, later!)).IsTrue();
        var foreignCompletion = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        foreignCompletion.SetResult(SecretStatus.Success);
        await Assert.That(ReferenceEquals(later, foreignCompletion.Task)).IsFalse();
        await Assert.That(f.Source.OwnsStatusNotificationDeleteCancellationCompletion(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, canceled, foreignCompletion.Task)).IsFalse();
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await Assert.That(f.Source.TryGetStatusTarget(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(0);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Backend.RequestBytes.Length).IsEqualTo(0);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Window.Start!.Owned.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(f.Backend.Disposed).IsFalse();
    }

    [Test]
    [Arguments("Location")]
    [Arguments("Azure-AsyncOperation")]
    [Arguments("Operation-Location")]
    [Arguments("Retry-After")]
    [Arguments("Content-Encoding")]
    [Arguments("Content-Range")]
    public async Task StatusNotificationDeleteCancellationCaptureRejectsAsyncAndPartialHeaders(string header)
    {
        using var f = new Fixture("DeleteNotification", boundary: "cancellation-boundary");
        f.Backend.ExtraHeaders.Add((header, header == "Retry-After" ? "1" :
            header == "Content-Encoding" ? "gzip" : header == "Content-Range" ? "bytes 0-0/1" :
                Origin + Notification + "?api-version=2025-02-15"));
        Task? start = null;
        await f.Start(retained: t => start = t);
        bool proof = f.Handle is not null && f.Source.TryGetStatusNotificationDeleteCancellationStart(f.Window,
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
    public async Task StatusNotificationDeleteCancellationCaptureCannotInventEmptySynchronousProof(string fault)
    {
        using var f = new Fixture("DeleteNotification", boundary: "cancellation-boundary");
        f.Backend.StartStatus = fault == "accepted202" ? 202 : fault == "denied" ? 403 :
            fault == "nonempty204" ? 204 : 200;
        if (fault.StartsWith("nonempty", StringComparison.Ordinal)) f.Backend.StartBody = """{"status":"Succeeded"}""";
        if (fault == "declared-length") f.Backend.DeclaredLength = 1;
        Task? start = null;
        await f.Start(retained: t => start = t);
        bool proof = f.Handle is not null && f.Source.TryGetStatusNotificationDeleteCancellationStart(f.Window,
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
    public async Task StatusNotificationDeleteCancellationCaptureRejectsPlausibleEmptyResponseSubstitution(int status, string change)
    {
        NotificationEmptySubstitution? substitution = null;
        using var f = new Fixture("DeleteNotification", boundary: "cancellation-boundary",
            decorate: inner => substitution = new(inner, change));
        f.Backend.StartStatus = status;
        Task? start = null;
        await f.Start(retained: t => start = t);
        bool proof = f.Handle is not null && f.Source.TryGetStatusNotificationDeleteCancellationStart(f.Window,
            f.Binding, f.Client, (NotificationScope)f.Scope, f.Receipt, start!, f.Handle, out _);
        await Assert.That(proof).IsFalse();
        await Assert.That(substitution!.Replacements).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("uncanceled")]
    [Arguments("foreign-handle")]
    [Arguments("retention")]
    public async Task StatusNotificationDeleteCancellationCaptureRejectsUnqualifiedFirstCheck(string fault)
    {
        using var f = new Fixture("DeleteNotification", boundary: "cancellation-boundary");
        using var other = new Fixture("DeleteNotification");
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
            await Assert.That(f.Source.OwnsNotificationDeleteCanceledStatusAttempt(f.Window, f.Binding, f.Client,
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
    public async Task StatusNotificationDeleteCancellationCaptureMissingAndRepeatedCancelCannotStealLaterSlot()
    {
        using var f = new Fixture("DeleteNotification", boundary: "cancellation-boundary");
        await f.Start();
        await Assert.That(async () => await f.Check()).Throws<InvalidOperationException>();
        await Assert.That(f.Window.Status).IsNull();
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token)).Throws<OperationCanceledException>();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token)).Throws<InvalidOperationException>();
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(0);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusNotificationDeleteCancellationCaptureSealIgnoresForgedDiagnosticDrain()
    {
        using var f = new Fixture("DeleteNotification", boundary: "cancellation-boundary");
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

    private sealed class NotificationEmptySubstitution(HttpPipelineTransport inner, string change) : HttpPipelineTransport
    {
        internal int Replacements;
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            Replacements++;
            if (change == "response") message.Response = new OwnedArmResponse(message.Response.Status,
                message.Response.ReasonPhrase, message.Response.ClientRequestId, message.Response.Headers.ToArray(),
                new MemoryStream([]));
            else message.Response.ContentStream = change == "stream" ? new MemoryStream([]) : null;
        }
    }
}
