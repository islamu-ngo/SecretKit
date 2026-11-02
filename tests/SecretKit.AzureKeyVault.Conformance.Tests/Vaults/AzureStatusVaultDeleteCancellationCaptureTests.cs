using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    public async Task StatusVaultDeleteCancellationCaptureRetainsTwoDistinctActualSdkTasks()
    {
        using var f = new Fixture("DeleteVault", boundary: "cancellation-boundary");
        ConfigureCancellationDelete(f);
        Task? start = null, canceled = null, later = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        var receiptBeforeStatus = f.Receipt.Evidence;
        await Assert.That(receiptBeforeStatus).IsEqualTo(DispatchEvidence.Applied);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token, t => canceled = t)).Throws<OperationCanceledException>();
        await Assert.That(canceled!.IsCanceled).IsTrue();
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(f.Source.OwnsCanceledStatusAttempt(f.Window, f.Binding, f.Client, (VaultScope)f.Scope,
            f.Receipt, start!, f.Handle!, canceled)).IsTrue();
        var copiedScope = new VaultScope(((VaultScope)f.Scope).ResourceGroup, ((VaultScope)f.Scope).VaultName);
        await Assert.That(f.Source.OwnsCanceledStatusAttempt(f.Window, f.Binding, f.Client, copiedScope,
            f.Receipt, start!, f.Handle!, canceled)).IsFalse();
        await Assert.That(f.Source.OwnsCanceledStatusAttempt(f.Window, f.Binding with { }, f.Client, (VaultScope)f.Scope,
            f.Receipt, start!, f.Handle!, canceled)).IsFalse();
        await Assert.That(f.Source.OwnsCanceledStatusAttempt(f.Window, f.Binding, f.Client, (VaultScope)f.Scope,
            f.Receipt, start!, f.Handle!, Task.FromCanceled<SecretStatus>(stop.Token))).IsFalse();
        await Assert.That(await f.Check(retained: t => later = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(ReferenceEquals(canceled, later)).IsFalse();
        await Assert.That(f.Source.OwnsStatusVaultDeleteCancellationCompletion(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle!, canceled, later!)).IsTrue();
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(0);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(receiptBeforeStatus);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusVaultDeleteCancellationCaptureRejectsAnUncanceledFirstTokenBeforeSdkWork()
    {
        using var f = new Fixture("DeleteVault", boundary: "cancellation-boundary");
        ConfigureCancellationDelete(f);
        await f.Start();
        Task? captured = null;
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, default, t => captured = t)).Throws<InvalidOperationException>();
        await Assert.That(captured is null).IsTrue();
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusVaultDeleteCancellationCaptureRepeatedAttemptCannotConsumeLaterStatusSlot()
    {
        using var f = new Fixture("DeleteVault", boundary: "cancellation-boundary");
        ConfigureCancellationDelete(f);
        await f.Start();
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token)).Throws<OperationCanceledException>();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token)).Throws<InvalidOperationException>();
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusVaultDeleteCancellationCaptureRejectsForeignHandleBeforeCanceledInvocation()
    {
        using var f = new Fixture("DeleteVault", boundary: "cancellation-boundary");
        using var foreign = new Fixture("DeleteVault");
        ConfigureCancellationDelete(f);
        ConfigureCancellationDelete(foreign);
        await f.Start();
        await foreign.Start();
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        Task? captured = null;
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            foreign.Handle!, stop.Token, t => captured = t)).Throws<InvalidOperationException>();
        await Assert.That(captured is null).IsTrue();
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
        await foreign.Source.SealAsync(foreign.Window);
    }

    [Test]
    public async Task StatusVaultDeleteCancellationRetentionFailureAwaitsActualCanceledTaskButCannotQualify()
    {
        using var f = new Fixture("DeleteVault", boundary: "cancellation-boundary");
        ConfigureCancellationDelete(f);
        Task? start = null, canceled = null;
        await f.Start(retained: t => start = t);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        Exception? failure = null;
        try
        {
            await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector, f.Handle!, stop.Token, t =>
            {
                canceled = t;
                throw new InvalidOperationException("controlled-cancellation-retention-failure");
            });
        }
        catch (Exception ex) { failure = ex; }
        await Assert.That(failure).IsNotNull();
        await Assert.That(canceled!.IsCanceled).IsTrue();
        await Assert.That(f.Source.OwnsCanceledStatusAttempt(f.Window, f.Binding, f.Client, (VaultScope)f.Scope,
            f.Receipt, start!, f.Handle!, canceled)).IsFalse();
        await Assert.That(async () => await f.Check()).Throws<InvalidOperationException>();
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusVaultDeleteCancellationSealWaitsForRetainedHookAfterSdkTaskCanceled()
    {
        using var f = new Fixture("DeleteVault", boundary: "cancellation-boundary");
        ConfigureCancellationDelete(f);
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

    private static void ConfigureCancellationDelete(Fixture f)
    {
        f.AsyncStart();
        f.Backend.StartStatus = 200;
        f.Backend.StartBody = """{"status":"InProgress"}""";
    }
}
