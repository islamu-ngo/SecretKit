using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments("selected-contract")]
    [Arguments("cancellation-boundary")]
    [Arguments("denied-authority")]
    public async Task StatusRoleDeleteIndependentHookRejectsOtherCasesBeforeNativeDispatch(string boundary)
    {
        using var f = new Fixture("DeleteRoleAssignment", boundary: boundary, statusRoleDeleteIndependent: true);
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task StatusRoleDeleteIndependentRawInstrumentationCannotIssueProfileProof()
    {
        using var f = new Fixture("DeleteRoleAssignment", boundary: "independent-effect");
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Source.TryGetStatusRoleDeleteIndependentStart(f.Window, f.Binding, f.Client,
            (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusRoleDeleteIndependentForeignHandleCannotStealCheckSlot()
    {
        using var f = new Fixture("DeleteRoleAssignment", boundary: "independent-effect", statusRoleDeleteIndependent: true);
        using var other = new Fixture("DeleteRoleAssignment");
        await f.Start();
        await other.Start();
        Task? task = null;
        await Assert.That(async () => await f.Source.CheckStatusAsync(f.Window, f.Binding.Selector,
            other.Handle!, default, t => task = t)).Throws<InvalidOperationException>();
        await Assert.That(task is null).IsTrue();
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    public async Task StatusRoleDeleteIndependentFailedRetentionCannotMintCompletion()
    {
        using var f = new Fixture("DeleteRoleAssignment", boundary: "independent-effect", statusRoleDeleteIndependent: true);
        Task? start = null, check = null;
        await f.Start(retained: t => start = t);
        await Assert.That(async () => await f.Check(retained: t =>
        {
            check = t;
            throw new InvalidOperationException("controlled-role-retention-failure");
        })).Throws<InvalidOperationException>();
        await Assert.That(f.Source.TryGetStatusRoleDeleteIndependentCompletion(f.Window, f.Binding, f.Client,
            (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle!, check!, out _)).IsFalse();
        await Assert.That(async () => await f.Check()).Throws<InvalidOperationException>();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusRoleDeleteIndependentCaptureRetainsReal204AndActualTasks(bool nullIngress)
    {
        using var f = new Fixture("DeleteRoleAssignment", boundary: "independent-effect", statusRoleDeleteIndependent: true);
        f.Backend.NullResponseStream = nullIngress;
        Task? start = null, later = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(f.Source.TryGetStatusRoleDeleteIndependentStart(f.Window, f.Binding, f.Client,
            (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle!, out var proof)).IsTrue();
        await Assert.That(proof).IsNotNull();
        await Assert.That(f.Source.TryGetStatusRoleDeleteIndependentStart(f.Window, f.Binding with { }, f.Client,
            (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusRoleDeleteIndependentStart(f.Window, f.Binding, f.Client,
            (RoleAssignmentScope)f.Scope, f.Receipt, Task.CompletedTask, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(await f.Check(retained: t => later = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusRoleDeleteIndependentCompletion(f.Window, f.Binding, f.Client,
            (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle!, later!, out _)).IsTrue();
        var foreign = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        foreign.SetResult(SecretStatus.Success);
        await Assert.That(ReferenceEquals(later, foreign.Task)).IsFalse();
        await Assert.That(f.Source.TryGetStatusRoleDeleteIndependentCompletion(f.Window, f.Binding, f.Client,
            (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle!, foreign.Task, out _)).IsFalse();
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
    public async Task StatusRoleDeleteIndependentCaptureRejectsAsyncOrPartialResponse(string header)
    {
        using var f = new Fixture("DeleteRoleAssignment", boundary: "independent-effect", statusRoleDeleteIndependent: true);
        f.Backend.ExtraHeaders.Add((header, header == "Retry-After" ? "1" :
            header == "Content-Encoding" ? "gzip" : header == "Content-Range" ? "bytes 0-0/1" :
                Origin + Role + "?api-version=2022-04-01"));
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusRoleDeleteIndependentStart(f.Window,
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
    public async Task StatusRoleDeleteIndependentCaptureCannotInventSynchronous204Proof(string fault)
    {
        using var f = new Fixture("DeleteRoleAssignment", boundary: "independent-effect", statusRoleDeleteIndependent: true);
        f.Backend.StartStatus = fault == "200" ? 200 : fault == "202" ? 202 : fault == "denied" ? 403 : 204;
        if (fault == "nonempty") f.Backend.StartBody = """{"status":"Succeeded"}""";
        if (fault == "declared-length") f.Backend.DeclaredLength = 1;
        if (fault == "lost") f.Backend.LoseStart = true;
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusRoleDeleteIndependentStart(f.Window,
            f.Binding, f.Client, (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("response")]
    [Arguments("stream")]
    [Arguments("null-stream")]
    public async Task StatusRoleDeleteIndependentCaptureRejectsPhysicalEmptyResponseSubstitution(string change)
    {
        NotificationEmptySubstitution? substitution = null;
        using var f = new Fixture("DeleteRoleAssignment", boundary: "independent-effect", statusRoleDeleteIndependent: true,
            decorate: inner => substitution = new(inner, change));
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusRoleDeleteIndependentStart(f.Window,
            f.Binding, f.Client, (RoleAssignmentScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsFalse();
        await Assert.That(substitution!.Replacements).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusRoleDeleteIndependentCaptureSealIgnoresForgedDiagnosticDrain()
    {
        using var f = new Fixture("DeleteRoleAssignment", boundary: "independent-effect", statusRoleDeleteIndependent: true);
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
