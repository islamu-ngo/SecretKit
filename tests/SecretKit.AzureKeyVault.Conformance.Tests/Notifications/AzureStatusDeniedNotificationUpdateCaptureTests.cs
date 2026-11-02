using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    public async Task StatusDeniedNotificationUpdateRawFactsCannotEnrollQualifiedProofs()
    {
        using var f = new Fixture("UpdateNotification", boundary: "denied-authority", statusDeniedNotificationUpdate: true);
        f.Backend.StatusStatus = 403;
        f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-denial"}}""";
        Task? start = null, check = null;
        var started = await f.Source.StartAsync(f.Window, f.Binding.Selector, f.Client, f.Scope,
            f.Input, f.Receipt, retained: task => start = task);
        await Assert.That(started.IsSuccess).IsTrue();
        await Assert.That(await f.Source.CheckStatusAsync(f.Window, f.Binding.Selector, started.Value!,
            default, task => check = task)).IsEqualTo(SecretStatus.Denied);
        await Assert.That(f.Source.TryGetStatusDeniedNotificationUpdateStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, started.Value!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusDeniedNotificationUpdateDenied(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, started.Value!, check!, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusDeniedNotificationUpdateBindsFirstActualScopeWithoutAllowingLaterSubstitution()
    {
        using var f = new Fixture("UpdateNotification", boundary: "denied-authority", statusDeniedNotificationUpdate: true);
        var planned = (NotificationScope)f.Scope;
        var actual = new NotificationScope(planned.Vault, planned.SubscriptionName);
        var receipt = f.Client.PrepareReceipt(actual, ManagementMutation.UpdateNotification);
        f.Backend.StatusStatus = 403;
        f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-denial"}}""";
        Task? start = null, check = null;
        var started = await f.Source.StartStatusDeniedNotificationUpdateAsync(f.Window, f.Binding.Selector, f.Client,
            actual, f.Input, receipt, default, task => start = task);
        await Assert.That(started.IsSuccess).IsTrue();
        await Assert.That(f.Source.TryGetStatusDeniedNotificationUpdateStart(f.Window, f.Binding, f.Client,
            actual, receipt, start!, started.Value!, out _)).IsTrue();
        await Assert.That(f.Source.TryGetStatusDeniedNotificationUpdateStart(f.Window, f.Binding, f.Client,
            planned, receipt, start!, started.Value!, out _)).IsFalse();
        await Assert.That(await f.Source.CheckStatusDeniedNotificationUpdateAsync(f.Window, f.Binding.Selector,
            started.Value!, default, task => check = task)).IsEqualTo(SecretStatus.Denied);
        await Assert.That(f.Source.TryGetStatusDeniedNotificationUpdateDenied(f.Window, f.Binding, f.Client,
            actual, receipt, start!, started.Value!, check!, out _)).IsTrue();
        await Assert.That(f.Source.TryGetStatusDeniedNotificationUpdateDenied(f.Window, f.Binding, f.Client,
            planned, receipt, start!, started.Value!, check!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments(401)]
    [Arguments(403)]
    public async Task StatusDeniedNotificationUpdateOwnsActualStartAndDeniedTasks(int status)
    {
        using var f = new Fixture("UpdateNotification", boundary: "denied-authority", statusDeniedNotificationUpdate: true);
        f.Backend.StatusStatus = status;
        f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-denial"}}""";
        Task? start = null, check = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusDeniedNotificationUpdateStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out var issued)).IsTrue();
        await Assert.That(await f.Check(retained: task => check = task)).IsEqualTo(SecretStatus.Denied);
        await Assert.That(f.Source.TryGetStatusDeniedNotificationUpdateDenied(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, check!, out var proof)).IsTrue();
        await Assert.That(ReferenceEquals(proof!.Start, issued)).IsTrue();
        await Assert.That(proof.HttpStatus).IsEqualTo(status);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Failed);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        var forged = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        forged.SetResult(SecretStatus.Denied);
        await Assert.That(f.Source.TryGetStatusDeniedNotificationUpdateDenied(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle, forged.Task, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusDeniedNotificationUpdateDenied(f.Window, f.Binding with { }, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle, check!, out _)).IsFalse();
        await Assert.That(await f.Handle.CheckStatusAsync()).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "PATCH")).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("empty")]
    [Arguments("malformed")]
    [Arguments("missing-message")]
    [Arguments("duplicate")]
    [Arguments("state-only")]
    [Arguments("success")]
    [Arguments("lost")]
    public async Task StatusDeniedNotificationUpdateUnqualifiedWireCannotMintDenial(string fault)
    {
        using var f = new Fixture("UpdateNotification", boundary: "denied-authority", statusDeniedNotificationUpdate: true);
        Task? start = null, check = null;
        await f.Start(retained: task => start = task);
        f.Backend.StatusStatus = fault == "success" ? 200 : 403;
        f.Backend.StatusBody = fault switch
        {
            "empty" => "",
            "missing-message" => """{"error":{"code":"AuthorizationFailed"}}""",
            "duplicate" => """{"error":{"code":"AuthorizationFailed","message":"one","message":"two"}}""",
            "state-only" => """{"status":"Forbidden"}""",
            "success" => f.Backend.StartBody.Replace("Updating", "Succeeded", StringComparison.Ordinal),
            _ => "{"
        };
        if (fault == "lost") f.Backend.LoseStatus = true;
        try { await f.Check(retained: task => check = task); }
        catch (InvalidOperationException) { }
        await Assert.That(f.Source.TryGetStatusDeniedNotificationUpdateDenied(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, check!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }
}
