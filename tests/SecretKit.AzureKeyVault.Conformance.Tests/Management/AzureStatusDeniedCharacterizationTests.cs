using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using Capture = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments("CreateOrUpdateVault", 401)]
    [Arguments("CreateOrUpdateVault", 403)]
    [Arguments("RecoverVault", 401)]
    [Arguments("RecoverVault", 403)]
    [Arguments("DeleteVault", 401)]
    [Arguments("DeleteVault", 403)]
    [Arguments("PurgeDeletedVault", 401)]
    [Arguments("PurgeDeletedVault", 403)]
    [Arguments("DeletePrivateConnection", 401)]
    [Arguments("DeletePrivateConnection", 403)]
    [Arguments("CreateOrUpdateNotification", 401)]
    [Arguments("CreateOrUpdateNotification", 403)]
    [Arguments("UpdateNotification", 401)]
    [Arguments("UpdateNotification", 403)]
    [Arguments("DeleteNotification", 401)]
    [Arguments("DeleteNotification", 403)]
    public async Task NativeOriginalHandleDeterminesWhetherConfiguredStatusDenialIsRead(string operation, int denied)
    {
        using var f = new Fixture(operation, boundary: "denied-authority");
        string body = f.Backend.StartBody;
        f.AsyncStart();
        if (operation is "CreateOrUpdateVault" or "RecoverVault" or
            "CreateOrUpdateNotification" or "UpdateNotification")
        {
            f.Backend.StartStatus = 201;
            f.Backend.StartBody = body.Replace("Succeeded", "Updating", StringComparison.Ordinal);
        }
        if (operation == "DeleteVault")
        {
            f.Backend.StartStatus = 200;
            f.Backend.StartBody = """{"status":"InProgress"}""";
        }
        f.Backend.StatusStatus = denied;
        f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-status-denial"}}""";
        Task? start = null, check = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        var handle = f.Handle!;
        if (operation == "DeleteVault")
        {
            // Actual HTTP200 plus a continuation and InProgress body is still
            // cached complete in this installed adapter, just like HTTP204.
            await Assert.That(handle.State).IsEqualTo(NativeProvisioningState.Succeeded);
            await Assert.That(await f.Check(retained: task => check = task)).IsEqualTo(SecretStatus.Success);
            var cached = await f.Source.SealAsync(f.Window);
            await Assert.That(start!.IsCompletedSuccessfully && check!.IsCompletedSuccessfully).IsTrue();
            await Assert.That(ReferenceEquals(cached.Start!.SdkTask, start)).IsTrue();
            await Assert.That(ReferenceEquals(cached.Status!.SdkTask, check)).IsTrue();
            await Assert.That(cached.Status.Attempts.Count).IsEqualTo(0);
            await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
            await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
            return;
        }
        await Assert.That(handle.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(await f.Check(retained: task => check = task)).IsEqualTo(SecretStatus.Denied);
        await Assert.That(start!.IsCompletedSuccessfully && check!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(ReferenceEquals(handle, f.Handle)).IsTrue();
        await Assert.That(handle.State).IsEqualTo(NativeProvisioningState.Failed);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        var captured = await f.Source.SealAsync(f.Window);
        await Assert.That(ReferenceEquals(captured.Start!.SdkTask, start)).IsTrue();
        await Assert.That(ReferenceEquals(captured.Status!.SdkTask, check)).IsTrue();
        var read = captured.Status.Attempts.Single();
        await Assert.That(read.HttpStatus).IsEqualTo(denied);
        await Assert.That(read.State).IsEqualTo(Capture.WireState.Denied);
        await Assert.That(read.Valid && read.TransportTerminated && read.ResponseObserved).IsTrue();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
        await Assert.That(f.Backend.Requests[1].Method).IsEqualTo("GET");
        await Assert.That(f.Backend.Authorizations.Distinct().Count()).IsEqualTo(1);
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        // A denied read does not establish remote failure or grant another read:
        // the installed wrapper subsequently reports its cached local state.
        await Assert.That(await handle.CheckStatusAsync()).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
    }

    [Test]
    [Arguments("DeleteVault")]
    [Arguments("DeleteRoleAssignment")]
    [Arguments("DeleteNotification")]
    [Arguments("UpdatePrivateConnection")]
    public async Task CachedNativeCompletionCannotObserveConfiguredStatusDenial(string operation)
    {
        using var f = new Fixture(operation, boundary: "denied-authority");
        f.Backend.StatusStatus = 403;
        f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed"}}""";
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        var captured = await f.Source.SealAsync(f.Window);
        await Assert.That(captured.Status!.Attempts.Count).IsEqualTo(0);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
    }
}
