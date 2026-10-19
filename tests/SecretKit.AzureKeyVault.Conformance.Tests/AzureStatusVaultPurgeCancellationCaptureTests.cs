using System.Text;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    public async Task StatusVaultPurgeCancellationCaptureJoinsActualTasksAndTwoNativeGets()
    {
        using var f = new Fixture("PurgeDeletedVault", boundary: "cancellation-boundary");
        ConfigureCancellationPurge(f);
        Task? start = null, canceled = null, later = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token, t => canceled = t)).Throws<OperationCanceledException>();
        await Assert.That(canceled!.IsCanceled).IsTrue();
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Source.OwnsPurgeCanceledStatusAttempt(f.Window, f.Binding, f.Client, (DeletedVaultScope)f.Scope,
            f.Receipt, start!, f.Handle!, canceled)).IsTrue();
        var scope = (DeletedVaultScope)f.Scope;
        var copy = new DeletedVaultScope(scope.Subscription, scope.Location, scope.VaultName);
        await Assert.That(f.Source.OwnsPurgeCanceledStatusAttempt(f.Window, f.Binding, f.Client, copy,
            f.Receipt, start!, f.Handle!, canceled)).IsFalse();
        await Assert.That(f.Source.OwnsPurgeCanceledStatusAttempt(f.Window, f.Binding with { }, f.Client, scope,
            f.Receipt, start!, f.Handle!, canceled)).IsFalse();
        await Assert.That(f.Source.OwnsPurgeCanceledStatusAttempt(f.Window, f.Binding, f.Client, scope,
            f.Receipt, start!, f.Handle!, Task.FromCanceled<SecretStatus>(stop.Token))).IsFalse();
        await Assert.That(await f.Check(retained: t => later = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(ReferenceEquals(canceled, later)).IsFalse();
        await Assert.That(f.Source.OwnsStatusVaultPurgeCancellationCompletion(f.Window, f.Binding, f.Client,
            scope, f.Receipt, start!, f.Handle!, canceled, later!)).IsTrue();
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsTrue();
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(2);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(3);
        await Assert.That(f.Backend.Requests.Skip(1).All(r => r.Method == "GET" && r.Path == f.Backend.StatusPath)).IsTrue();
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("uncanceled")]
    [Arguments("foreign-handle")]
    [Arguments("retention")]
    public async Task StatusVaultPurgeCancellationCaptureRejectsUnqualifiedCanceledAttempt(string fault)
    {
        using var f = new Fixture("PurgeDeletedVault", boundary: "cancellation-boundary");
        using var other = new Fixture("PurgeDeletedVault");
        ConfigureCancellationPurge(f);
        ConfigureCancellationPurge(other);
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
            await Assert.That(async () => await Invoke()).Throws<OperationCanceledException>();
        else
            await Assert.That(async () => await Invoke()).Throws<InvalidOperationException>();
        if (fault == "retention")
        {
            await Assert.That(canceled!.IsCanceled).IsTrue();
            await Assert.That(f.Source.OwnsPurgeCanceledStatusAttempt(f.Window, f.Binding, f.Client, (DeletedVaultScope)f.Scope,
                f.Receipt, start!, f.Handle!, canceled)).IsFalse();
        }
        else await Assert.That(canceled is null).IsTrue();
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    public async Task StatusVaultPurgeCancellationCaptureDoesNotAdmitLaterCheckBeforeCanceledTask()
    {
        using var f = new Fixture("PurgeDeletedVault", boundary: "cancellation-boundary");
        ConfigureCancellationPurge(f);
        await f.Start();
        await Assert.That(async () => await f.Check()).Throws<InvalidOperationException>();
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusVaultPurgeCancellationCaptureRejectsRepeatedCanceledTaskWithoutConsumingLaterSlot()
    {
        using var f = new Fixture("PurgeDeletedVault", boundary: "cancellation-boundary");
        ConfigureCancellationPurge(f);
        await f.Start();
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token)).Throws<OperationCanceledException>();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token)).Throws<InvalidOperationException>();
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(3);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusVaultPurgeCancellationSealCannotTrustPoisonedDiagnosticsBeforeRetentionReturns()
    {
        using var f = new Fixture("PurgeDeletedVault", boundary: "cancellation-boundary");
        ConfigureCancellationPurge(f);
        await f.Start();
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task? canceled = null;
        var work = Task.Run(() => f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector, f.Handle!, stop.Token, t =>
        {
            canceled = t;
            entered.TrySetResult();
            resume.Task.WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
        }));
        Task? sealing = null;
        Task? dispatchSeal = null;
        var sealReturned = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(canceled!.IsCanceled).IsTrue();
            dispatchSeal = Task.Run(() =>
            {
                try { sealing = f.Source.SealAsync(f.Window); }
                finally { sealReturned.TrySetResult(); }
            });
            await sealReturned.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await dispatchSeal.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(sealing!.IsCompleted).IsFalse();
            f.Window.Start!.Drained.TrySetResult();
            f.Window.Start.SdkTask = Task.CompletedTask;
            await Assert.That(sealing.IsCompleted).IsFalse();
        }
        finally
        {
            resume.TrySetResult();
            if (dispatchSeal is not null) await dispatchSeal.WaitAsync(TimeSpan.FromSeconds(10));
        }
        await Assert.That(async () => await work.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        await sealing!.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Test]
    [Arguments(1, false)]
    [Arguments(1, true)]
    [Arguments(2, false)]
    [Arguments(2, true)]
    [Arguments(3, false)]
    [Arguments(3, true)]
    public async Task StatusVaultPurgeCancellationRejectsResponseOrStreamSubstitution(int stage, bool streamOnly)
    {
        PurgeCancellationSubstitution? substitution = null;
        using var f = new Fixture("PurgeDeletedVault", boundary: "cancellation-boundary",
            decorate: inner => substitution = new(inner, stage, streamOnly));
        ConfigureCancellationPurge(f);
        Task? start = null, canceled = null, later = null;
        await f.Start(retained: t => start = t);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        if (stage == 1)
            await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
                f.Handle!, stop.Token)).Throws<InvalidOperationException>();
        else
        {
            await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
                f.Handle!, stop.Token, t => canceled = t)).Throws<OperationCanceledException>();
            await f.Check(retained: t => later = t);
            await Assert.That(f.Source.OwnsStatusVaultPurgeCancellationCompletion(f.Window, f.Binding, f.Client,
                (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, canceled!, later!)).IsFalse();
        }
        await Assert.That(substitution!.Replacements).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    private sealed class PurgeCancellationSubstitution(HttpPipelineTransport inner, int stage, bool streamOnly)
        : HttpPipelineTransport
    {
        private int sends;
        internal int Replacements;
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            if (++sends != stage) return;
            Replacements++;
            var replacement = new MemoryStream(Encoding.UTF8.GetBytes(stage == 1
                ? """{"status":"InProgress"}""" : """{"status":"Succeeded"}"""));
            if (streamOnly) message.Response.ContentStream = replacement;
            else message.Response = new OwnedArmResponse(message.Response.Status, message.Response.ReasonPhrase,
                message.Response.ClientRequestId, message.Response.Headers.ToArray(), replacement);
        }
    }

    private static void ConfigureCancellationPurge(Fixture f)
    {
        f.AsyncStart();
        f.Backend.StartBody = """{"status":"InProgress"}""";
        f.Backend.StatusBody = """{"status":"Succeeded"}""";
        f.Backend.ExtraHeaders.Add(("x-ms-request-id", "native-purge-capture"));
    }
}
