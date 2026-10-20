using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments(NativeProvisioningState.Succeeded, NativeProvisioningState.Pending)]
    [Arguments(NativeProvisioningState.Pending, NativeProvisioningState.Failed)]
    [Arguments(NativeProvisioningState.Failed, NativeProvisioningState.Canceled)]
    [Arguments(NativeProvisioningState.Canceled, NativeProvisioningState.Unknown)]
    [Arguments(NativeProvisioningState.Unknown, NativeProvisioningState.Succeeded)]
    public async Task StatusDeniedPurgeStatusKeysCannotBorrowAnotherRealInvocation(
        NativeProvisioningState variant, NativeProvisioningState foreign)
    {
        using var f = new Fixture("PurgeDeletedVault", "status." + variant,
            boundary: "denied-authority", statusDeniedPurge: true);
        f.Backend.StatusStatus = 403;
        f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-denial"}}""";
        Task? start = null, check = null, foreignStart = null, foreignCheck = null;
        await f.Start(retained: task => start = task);
        await f.Check(retained: task => check = task);
        await Assert.That(f.Source.TryGetStatusDeniedPurgeDenied(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, check!, out var proof)).IsTrue();
        var binding = f.Binding with
        {
            Selector = f.Binding.Selector with { Variant = "status." + foreign, Nonce = Guid.NewGuid() },
            LeaseId = Guid.NewGuid()
        };
        var window = f.Source.ArmStatusDeniedPurge(binding);
        var receipt = f.Client.PrepareReceipt(f.Scope, ManagementMutation.PurgeDeletedVault);
        var started = await f.Source.StartStatusDeniedPurgeAsync(window, binding.Selector, f.Client,
            f.Scope, f.Input, receipt, default, task => foreignStart = task);
        await Assert.That(started.IsSuccess).IsTrue();
        await Assert.That(await f.Source.CheckStatusDeniedPurgeAsync(window, binding.Selector,
            started.Value!, default, task => foreignCheck = task)).IsEqualTo(SecretStatus.Denied);
        await Assert.That(f.Source.TryGetStatusDeniedPurgeDenied(window, binding, f.Client,
            (DeletedVaultScope)f.Scope, receipt, foreignStart!, started.Value!, foreignCheck!, out var other)).IsTrue();
        await Assert.That(f.Source.OwnsStatusDeniedPurgeDenied(proof!, window, binding, f.Client,
            (DeletedVaultScope)f.Scope, receipt, foreignStart!, started.Value!, foreignCheck!)).IsFalse();
        await Assert.That(f.Source.OwnsStatusDeniedPurgeDenied(other!, f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, check!)).IsFalse();
        await f.Source.SealAsync(window);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments(401)]
    [Arguments(403)]
    public async Task StatusDeniedPurgeRequiresActualOriginalDeniedTaskNotCachedUnknown(int status)
    {
        using var f = new Fixture("PurgeDeletedVault", boundary: "denied-authority", statusDeniedPurge: true);
        f.Backend.StatusStatus = status;
        f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-status-denial"}}""";
        Task? start = null, selected = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusDeniedPurgeStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out var issued)).IsTrue();
        await Assert.That(await f.Check(retained: task => selected = task)).IsEqualTo(SecretStatus.Denied);
        await Assert.That(f.Source.TryGetStatusDeniedPurgeDenied(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out var denied)).IsTrue();
        await Assert.That(ReferenceEquals(denied!.Start, issued)).IsTrue();
        await Assert.That(denied.Outcome).IsEqualTo(SecretStatus.Denied);
        await Assert.That(denied.State).IsEqualTo(NativeProvisioningState.Failed);
        await Assert.That(denied.ReceiptEvidence).IsEqualTo(DispatchEvidence.Pending);
        var fabricated = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        fabricated.SetResult(SecretStatus.Denied);
        await Assert.That(f.Source.TryGetStatusDeniedPurgeDenied(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, fabricated.Task, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusDeniedPurgeDenied(f.Window, f.Binding with { }, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out _)).IsFalse();
        await Assert.That(await f.Handle!.CheckStatusAsync()).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Source.OwnsStatusDeniedPurgeDenied(denied, f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle, selected!)).IsTrue();
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "POST")).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("pending")]
    [Arguments("succeeded")]
    [Arguments("failed")]
    [Arguments("canceled")]
    [Arguments("unknown")]
    [Arguments("malformed")]
    [Arguments("lost")]
    [Arguments("absent")]
    public async Task StatusDeniedPurgeOtherActualResultCannotMintDenial(string result)
    {
        using var f = new Fixture("PurgeDeletedVault", boundary: "denied-authority", statusDeniedPurge: true);
        Task? start = null, selected = null;
        await f.Start(retained: task => start = task);
        f.Backend.StatusBody = result switch
        {
            "pending" => """{"status":"InProgress"}""",
            "succeeded" => """{"status":"Succeeded"}""",
            "failed" => """{"status":"Failed"}""",
            "canceled" => """{"status":"Canceled"}""",
            "unknown" => """{"status":"future-state"}""",
            "absent" => """{"error":{"code":"ResourceNotFound"}}""",
            _ => "{"
        };
        if (result == "absent") f.Backend.StatusStatus = 404;
        if (result == "lost") f.Backend.LoseStatus = true;
        try { await f.Check(retained: task => selected = task); }
        catch (InvalidOperationException) { }
        await Assert.That(f.Source.TryGetStatusDeniedPurgeDenied(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("denied")]
    [Arguments("synchronous")]
    [Arguments("no-target")]
    [Arguments("lost")]
    public async Task StatusDeniedPurgeUnqualifiedStartCannotSupplyPendingAuthority(string fault)
    {
        using var f = new Fixture("PurgeDeletedVault", boundary: "denied-authority", statusDeniedPurge: true);
        if (fault == "denied")
        {
            f.Backend.StartStatus = 403;
            f.Backend.StartBody = """{"error":{"code":"AuthorizationFailed"}}""";
        }
        if (fault == "synchronous")
        {
            f.Backend.StartStatus = 200;
            f.Backend.StartBody = """{"status":"Succeeded"}""";
        }
        if (fault == "no-target") f.Backend.Targets.Clear();
        if (fault == "lost") f.Backend.LoseStart = true;
        Task? start = null;
        try { await f.Start(retained: task => start = task); }
        catch (InvalidOperationException) { }
        bool issued = f.Handle is not null && f.Source.TryGetStatusDeniedPurgeStart(f.Window, f.Binding,
            f.Client, (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle, out _);
        await Assert.That(issued).IsFalse();
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(0);
        await f.Source.SealAsync(f.Window);
    }
}
