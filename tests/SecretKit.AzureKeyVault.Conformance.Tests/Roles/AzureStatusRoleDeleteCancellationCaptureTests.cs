using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusRoleDeleteCancellationCaptureRetainsReal204AndActualTasks(bool nullIngress)
    {
        using var f = new Fixture("DeleteRoleAssignment", boundary: "cancellation-boundary");
        f.Backend.NullResponseStream = nullIngress;
        Task? start = null, canceled = null, later = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(f.Source.TryGetStatusRoleDeleteCancellationStart(f.Window, f.Binding, f.Client,
            (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle!, out var proof)).IsTrue();
        await Assert.That(proof).IsNotNull();
        await Assert.That(f.Source.TryGetStatusRoleDeleteCancellationStart(f.Window, f.Binding with { }, f.Client,
            (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusRoleDeleteCancellationStart(f.Window, f.Binding, f.Client,
            (RoleAssignmentScope)f.Scope, f.Receipt, Task.CompletedTask, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token, t => canceled = t)).Throws<OperationCanceledException>();
        await Assert.That(canceled!.IsCanceled).IsTrue();
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(f.Source.OwnsRoleDeleteCanceledStatusAttempt(f.Window, f.Binding, f.Client,
            (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle!, canceled)).IsTrue();
        await Assert.That(f.Source.OwnsRoleDeleteCanceledStatusAttempt(f.Window, f.Binding, f.Client,
            (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle!,
            Task.FromCanceled<SecretStatus>(stop.Token))).IsFalse();
        await Assert.That(await f.Check(retained: t => later = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(ReferenceEquals(canceled, later)).IsFalse();
        await Assert.That(f.Source.OwnsStatusRoleDeleteCancellationCompletion(f.Window, f.Binding, f.Client,
            (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle!, canceled, later!)).IsTrue();
        var foreign = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        foreign.SetResult(SecretStatus.Success);
        await Assert.That(ReferenceEquals(later, foreign.Task)).IsFalse();
        await Assert.That(f.Source.OwnsStatusRoleDeleteCancellationCompletion(f.Window, f.Binding, f.Client,
            (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle!, canceled, foreign.Task)).IsFalse();
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await Assert.That(f.Source.TryGetStatusTarget(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(0);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Backend.RequestBytes.Length).IsEqualTo(0);
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
    public async Task StatusRoleDeleteCancellationCaptureRejectsAsyncOrPartialResponse(string header)
    {
        using var f = new Fixture("DeleteRoleAssignment", boundary: "cancellation-boundary");
        f.Backend.ExtraHeaders.Add((header, header == "Retry-After" ? "1" :
            header == "Content-Encoding" ? "gzip" : header == "Content-Range" ? "bytes 0-0/1" :
                Origin + Role + "?api-version=2022-04-01"));
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusRoleDeleteCancellationStart(f.Window,
            f.Binding, f.Client, (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("200")]
    [Arguments("202")]
    [Arguments("denied")]
    [Arguments("nonempty")]
    [Arguments("declared-length")]
    [Arguments("lost")]
    public async Task StatusRoleDeleteCancellationCaptureCannotInventSynchronous204Proof(string fault)
    {
        using var f = new Fixture("DeleteRoleAssignment", boundary: "cancellation-boundary");
        f.Backend.StartStatus = fault == "200" ? 200 : fault == "202" ? 202 : fault == "denied" ? 403 : 204;
        if (fault == "nonempty") f.Backend.StartBody = """{"status":"Succeeded"}""";
        if (fault == "declared-length") f.Backend.DeclaredLength = 1;
        if (fault == "lost") f.Backend.LoseStart = true;
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusRoleDeleteCancellationStart(f.Window,
            f.Binding, f.Client, (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("response")]
    [Arguments("stream")]
    [Arguments("null-stream")]
    public async Task StatusRoleDeleteCancellationCaptureRejectsPhysicalEmptyResponseSubstitution(string change)
    {
        NotificationEmptySubstitution? substitution = null;
        using var f = new Fixture("DeleteRoleAssignment", boundary: "cancellation-boundary",
            decorate: inner => substitution = new(inner, change));
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusRoleDeleteCancellationStart(f.Window,
            f.Binding, f.Client, (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsFalse();
        await Assert.That(substitution!.Replacements).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("uncanceled")]
    [Arguments("foreign-handle")]
    [Arguments("retention")]
    public async Task StatusRoleDeleteCancellationCaptureRejectsInvalidFirstStatus(string fault)
    {
        using var f = new Fixture("DeleteRoleAssignment", boundary: "cancellation-boundary");
        using var other = new Fixture("DeleteRoleAssignment");
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
            await Assert.That(f.Source.OwnsRoleDeleteCanceledStatusAttempt(f.Window, f.Binding, f.Client,
                (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle!, canceled)).IsFalse();
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
    public async Task StatusRoleDeleteCancellationCaptureMissingAndRepeatedCancelCannotStealLaterSlot()
    {
        using var f = new Fixture("DeleteRoleAssignment", boundary: "cancellation-boundary");
        await f.Start();
        await Assert.That(async () => await f.Check()).Throws<InvalidOperationException>();
        await Assert.That(f.Window.Status).IsNull();
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token)).Throws<OperationCanceledException>();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token)).Throws<InvalidOperationException>();
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(0);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusRoleDeleteCancellationCaptureSealIgnoresForgedDiagnosticDrain()
    {
        using var f = new Fixture("DeleteRoleAssignment", boundary: "cancellation-boundary");
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
