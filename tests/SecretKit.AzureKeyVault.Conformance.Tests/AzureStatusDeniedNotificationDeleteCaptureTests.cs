using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments(401, false)]
    [Arguments(403, false)]
    [Arguments(401, true)]
    [Arguments(403, true)]
    public async Task StatusDeniedNotificationDeleteOwnsOriginalIssuedAaoAndActualDeniedTask(int denial, bool aaoOnly)
    {
        using var f = new Fixture("DeleteNotification", boundary: "denied-authority",
            statusDeniedNotificationDelete: true);
        if (aaoOnly) f.Backend.Targets.RemoveAll(h => h.Name == "Location");
        Task? start = null, check = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Source.TryGetStatusDeniedNotificationDeleteStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out var issued)).IsTrue();
        var proof = issued ?? throw new InvalidOperationException("missing-start-proof");
        await Assert.That(f.Source.OwnsStatusDeniedNotificationDeleteStart(proof, f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!)).IsTrue();
        await Assert.That(f.Source.TryGetStatusTarget(f.Window, f.Binding, out var issuedTarget)).IsTrue();
        var target = issuedTarget ?? throw new InvalidOperationException("missing-original-target");
        await Assert.That(target.Kind).IsEqualTo(
            ManagementOperationNativeCapture.StatusTargetKind.EventGridDeleteAsyncOperation);
        await Assert.That(target.TargetUri.AbsoluteUri).IsEqualTo(EventGridAsyncOperation);
        var forged = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        forged.SetResult();
        await Assert.That(f.Source.TryGetStatusDeniedNotificationDeleteStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, forged.Task, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusDeniedNotificationDeleteStart(f.Window, f.Binding with { }, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();

        f.Backend.StatusStatus = denial;
        f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-denied"}}""";
        await Assert.That(await f.Check(retained: task => check = task)).IsEqualTo(SecretStatus.Denied);
        await Assert.That(check!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Failed);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Source.TryGetStatusDeniedNotificationDeleteDenied(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, check!, out var denied)).IsTrue();
        await Assert.That(f.Source.OwnsStatusDeniedNotificationDeleteDenied(
            denied ?? throw new InvalidOperationException("missing-denied-proof"), f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, check!)).IsTrue();
        await Assert.That(f.Source.TryGetStatusDeniedNotificationDeleteDenied(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, forged.Task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
        await Assert.That(f.Backend.Requests[1].Path).IsEqualTo(new Uri(EventGridAsyncOperation).AbsolutePath);
        await Assert.That(f.Backend.Authorizations.Distinct().Count()).IsEqualTo(1);
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("missing-aao")]
    [Arguments("selected-child-aao")]
    [Arguments("wrong-query")]
    [Arguments("nonempty")]
    [Arguments("initial-200")]
    [Arguments("initial-204")]
    [Arguments("retry")]
    [Arguments("operation-location")]
    public async Task StatusDeniedNotificationDeleteCannotMintStartFromAnotherWireShape(string fault)
    {
        using var f = new Fixture("DeleteNotification", boundary: "denied-authority",
            statusDeniedNotificationDelete: true);
        if (fault == "missing-aao") f.Backend.Targets.RemoveAll(h => h.Name == "Azure-AsyncOperation");
        if (fault is "selected-child-aao" or "wrong-query")
        {
            f.Backend.Targets.RemoveAll(h => h.Name == "Azure-AsyncOperation");
            f.Backend.Targets.Add(("Azure-AsyncOperation", fault == "selected-child-aao"
                ? Origin + Notification + "?api-version=2025-02-15"
                : EventGridAsyncOperation + "&unestablished=true"));
        }
        if (fault == "nonempty") f.Backend.StartBody = """{"status":"InProgress"}""";
        if (fault == "initial-200") f.Backend.StartStatus = 200;
        if (fault == "initial-204") f.Backend.StartStatus = 204;
        if (fault == "retry") f.Backend.ExtraHeaders.Add(("Retry-After", "1"));
        if (fault == "operation-location") f.Backend.Targets.Add(("Operation-Location", EventGridAsyncOperation));
        Task? start = null;
        try { await f.Start(retained: task => start = task); }
        catch (InvalidOperationException) { }
        await Assert.That(f.Source.TryGetStatusDeniedNotificationDeleteStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusTarget(f.Window, f.Binding, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments(200, """{"status":"InProgress"}""")]
    [Arguments(200, """{"status":"Succeeded"}""")]
    [Arguments(404, """{"error":{"code":"NotFound"}}""")]
    [Arguments(403, "{")]
    public async Task StatusDeniedNotificationDeleteRequiresActualWellFramedDenial(int code, string body)
    {
        using var f = new Fixture("DeleteNotification", boundary: "denied-authority",
            statusDeniedNotificationDelete: true);
        Task? start = null, check = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        f.Backend.StatusStatus = code;
        f.Backend.StatusBody = body;
        try { await f.Check(retained: task => check = task); }
        catch (InvalidOperationException) { }
        await Assert.That(f.Source.TryGetStatusDeniedNotificationDeleteDenied(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, check!, out _)).IsFalse();
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }
}
