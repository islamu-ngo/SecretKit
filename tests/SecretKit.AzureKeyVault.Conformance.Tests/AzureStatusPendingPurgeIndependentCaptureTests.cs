using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using Capture = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    public async Task StatusPendingPurgeIndependentCaptureSeparatesHistoricalPendingFromTerminalCleanup()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "independent-effect", statusPendingPurgeIndependent: true);
        Task? start = null, selected = null, cleanup = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusPendingPurgeIndependentStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsTrue();
        await Assert.That(await f.Source.CheckStatusPendingPurgeIndependentAsync(f.Window, f.Binding.Selector,
            f.Handle!, default, t => selected = t)).IsEqualTo(SecretStatus.Pending);
        await Assert.That(f.Source.TryGetStatusPendingPurgeIndependentSelected(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out var observed)).IsTrue();
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        var history = f.Window.Status;
        f.Source.RevokeStatusPendingPurgeIndependentSelected(f.Window);
        f.Backend.StatusBody = "{\"status\":\"Succeeded\"}";
        await Assert.That(await f.Source.CheckStatusPendingPurgeIndependentCleanupAsync(f.Window, f.Binding.Selector,
            f.Handle, default, t => cleanup = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusPendingPurgeIndependentCleanup(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle, cleanup!, out _)).IsTrue();
        await Assert.That(ReferenceEquals(f.Window.Status, history)).IsTrue();
        await Assert.That(ReferenceEquals(selected, cleanup)).IsFalse();
        await Assert.That(selected!.IsCompletedSuccessfully && cleanup!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(f.Handle.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "POST")).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(3);
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Window.Start!.Owned.Concat(history!.Owned).All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments("cancellation-boundary")]
    [Arguments("selected-contract")]
    [Arguments("denied-authority")]
    public async Task StatusPendingPurgeIndependentCaptureRejectsForeignCasesBeforeNativeDispatch(string boundary)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: boundary, statusPendingPurgeIndependent: true);
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task StatusPendingPurgeIndependentCaptureForeignHandleCannotConsumeSelectedSlot()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "independent-effect", statusPendingPurgeIndependent: true);
        using var other = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "independent-effect", statusPendingPurgeIndependent: true);
        await f.Start();
        await other.Start();
        Task? leaked = null;
        await Assert.That(async () => await f.Source.CheckStatusPendingPurgeIndependentAsync(f.Window, f.Binding.Selector,
            other.Handle!, default, t => leaked = t)).Throws<InvalidOperationException>();
        await Assert.That(leaked is null).IsTrue();
        await Assert.That(await f.Source.CheckStatusPendingPurgeIndependentAsync(f.Window, f.Binding.Selector,
            f.Handle!, default)).IsEqualTo(SecretStatus.Pending);
        await f.Source.SealAsync(f.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusPendingPurgeIndependentCaptureCannotUseFabricatedStartOrCheckTask(bool fabricateStart)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "independent-effect", statusPendingPurgeIndependent: true);
        Task? start = null, selected = null;
        await f.Start(retained: t => start = t);
        await f.Source.CheckStatusPendingPurgeIndependentAsync(f.Window, f.Binding.Selector, f.Handle!, default, t => selected = t);
        var forged = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        forged.SetResult(SecretStatus.Pending);
        await Assert.That(f.Source.TryGetStatusPendingPurgeIndependentSelected(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, fabricateStart ? forged.Task : start!, f.Handle!,
            fabricateStart ? selected! : forged.Task, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("pending")]
    [Arguments("denied")]
    [Arguments("malformed")]
    [Arguments("lost")]
    public async Task StatusPendingPurgeIndependentCaptureCleanupFailureIsConsumedWithoutTerminalProof(string fault)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "independent-effect", statusPendingPurgeIndependent: true);
        Task? start = null, cleanup = null;
        await f.Start(retained: t => start = t);
        await f.Source.CheckStatusPendingPurgeIndependentAsync(f.Window, f.Binding.Selector, f.Handle!, default);
        f.Source.RevokeStatusPendingPurgeIndependentSelected(f.Window);
        if (fault == "denied") f.Backend.StatusStatus = 403;
        if (fault == "malformed") f.Backend.StatusBody = "{";
        if (fault == "lost") f.Backend.LoseStatus = true;
        await f.Source.CheckStatusPendingPurgeIndependentCleanupAsync(f.Window, f.Binding.Selector, f.Handle!, default, t => cleanup = t);
        await Assert.That(f.Source.TryGetStatusPendingPurgeIndependentCleanup(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, cleanup!, out _)).IsFalse();
        int sends = f.Backend.Requests.Count;
        await Assert.That(async () => await f.Source.CheckStatusPendingPurgeIndependentCleanupAsync(f.Window,
            f.Binding.Selector, f.Handle!, default)).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(sends);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("margin")]
    [Arguments("negative-jump")]
    [Arguments("zero-delay")]
    public async Task StatusPendingPurgeIndependentClockRejectsUnqualifiedEnvelopeBeforeNativeWork(string fault)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "independent-effect");
        var bounds = new Capture.StatusPendingPurgeClockBounds(
            fault == "negative-jump" ? TimeSpan.FromTicks(-1) : TimeSpan.FromSeconds(1),
            fault == "zero-delay" ? TimeSpan.Zero : TimeSpan.FromSeconds(1));
        DateTimeOffset expiry = fault == "margin" ? DateTimeOffset.UtcNow.AddMinutes(5) : DateTimeOffset.MaxValue;
        await Assert.That(() => f.Source.EnrollStatusPendingPurgeIndependent(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, expiry, bounds, TimeSpan.FromSeconds(20), default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task StatusPendingPurgeIndependentCaptureOriginalCallerRemainsVetoAfterSelectedTaskDrains()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "independent-effect", statusPendingPurgeIndependent: true);
        using var caller = new CancellationTokenSource();
        Task? start = null, selected = null;
        await f.Start(caller.Token, t => start = t);
        await f.Source.CheckStatusPendingPurgeIndependentAsync(f.Window, f.Binding.Selector, f.Handle!, default, t => selected = t);
        await Assert.That(f.Source.TryGetStatusPendingPurgeIndependentSelected(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out _)).IsTrue();
        caller.Cancel();
        await Assert.That(f.Source.TryGetStatusPendingPurgeIndependentSelected(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out _)).IsFalse();
        f.Source.RevokeStatusPendingPurgeIndependentSelected(f.Window);
        int sends = f.Backend.Requests.Count;
        try { await f.Source.CheckStatusPendingPurgeIndependentCleanupAsync(f.Window, f.Binding.Selector, f.Handle!, default); }
        catch (InvalidOperationException) { }
        catch (OperationCanceledException) { }
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(sends);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusPendingPurgeIndependentCaptureSealIgnoresForgedDiagnosticDrain()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "independent-effect", statusPendingPurgeIndependent: true);
        f.Credential.Block = true;
        using var caller = new CancellationTokenSource();
        Task? sealing = null;
        var work = f.Start(caller.Token);
        try
        {
            await f.Credential.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            caller.Cancel();
            await f.Credential.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(10));
            f.Window.Start!.Drained.TrySetResult();
            f.Window.Start.SdkTask = Task.CompletedTask;
            sealing = f.Source.SealAsync(f.Window);
            await Assert.That(sealing.IsCompleted).IsFalse();
            await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        }
        finally { f.Credential.Release.TrySetResult(); }
        await Assert.That(async () => await work.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        await sealing!.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Test]
    [Arguments(1, "response")]
    [Arguments(1, "stream")]
    [Arguments(1, "null-stream")]
    [Arguments(2, "response")]
    [Arguments(2, "stream")]
    [Arguments(2, "null-stream")]
    [Arguments(3, "response")]
    [Arguments(3, "stream")]
    [Arguments(3, "null-stream")]
    [Arguments(4, "response")]
    [Arguments(4, "stream")]
    [Arguments(4, "null-stream")]
    public async Task StatusPendingPurgeIndependentCaptureRejectsSameBytesParserSubstitutionInEveryNativePhase(int stage, string change)
    {
        NotificationUpdateSubstitution? substitution = null;
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "independent-effect", statusPendingPurgeIndependent: true,
            decorate: inner => substitution = new(inner, stage, change));
        substitution!.Bytes = System.Text.Encoding.UTF8.GetBytes(f.Backend.StartBody);
        Task? start = null, selected = null, cleanup = null;
        await f.Start(retained: t => start = t);
        if (stage == 1)
            await Assert.That(f.Handle is not null && f.Source.TryGetStatusPendingPurgeIndependentStart(f.Window, f.Binding,
                f.Client, (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsFalse();
        else
        {
            await f.Source.CheckStatusPendingPurgeIndependentAsync(f.Window, f.Binding.Selector, f.Handle!, default, t => selected = t);
            if (stage == 2)
                await Assert.That(f.Source.TryGetStatusPendingPurgeIndependentSelected(f.Window, f.Binding, f.Client,
                    (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out _)).IsFalse();
            else
            {
                f.Source.RevokeStatusPendingPurgeIndependentSelected(f.Window);
                f.Backend.StatusBody = "{\"status\":\"Succeeded\"}";
                substitution.Bytes = System.Text.Encoding.UTF8.GetBytes(f.Backend.StatusBody);
                await f.Source.CheckStatusPendingPurgeIndependentCleanupAsync(f.Window, f.Binding.Selector,
                    f.Handle!, default, t => cleanup = t);
                await Assert.That(f.Source.TryGetStatusPendingPurgeIndependentCleanup(f.Window, f.Binding, f.Client,
                    (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, cleanup!, out _)).IsFalse();
            }
        }
        await Assert.That(substitution.Replacements).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusPendingPurgeIndependentProofCannotCrossSelectedContractMembership(bool independent)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending",
            boundary: independent ? "independent-effect" : "selected-contract",
            statusPendingPurge: !independent, statusPendingPurgeIndependent: independent);
        Task? start = null;
        await f.Start(retained: task => start = task);
        if (independent)
        {
            await Assert.That(f.Source.TryGetStatusPendingPurgeIndependentStart(f.Window, f.Binding, f.Client,
                (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsTrue();
            await Assert.That(f.Source.TryGetStatusPendingPurgeStart(f.Window, f.Binding, f.Client,
                (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        }
        else
        {
            await Assert.That(f.Source.TryGetStatusPendingPurgeStart(f.Window, f.Binding, f.Client,
                (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsTrue();
            await Assert.That(f.Source.TryGetStatusPendingPurgeIndependentStart(f.Window, f.Binding, f.Client,
                (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        }
        await f.Source.SealAsync(f.Window);
    }
}
