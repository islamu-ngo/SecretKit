using System.Text.Json;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments(404, "absent")]
    [Arguments(204, "empty")]
    [Arguments(200, "envelope")]
    [Arguments(200, "Deleting")]
    [Arguments(200, "Succeeded")]
    [Arguments(401, "denied")]
    [Arguments(403, "denied")]
    public async Task NotificationDeleteTerminalNativeResponseIsNotIndependentSettlement(int status, string shape)
    {
        using var f = new Fixture("DeleteNotification", boundary: "denied-authority");
        f.AsyncStart();
        f.Backend.StatusStatus = status;
        f.Backend.StatusBody = shape switch
        {
            "absent" => """{"error":{"code":"ResourceNotFound","message":"controlled-absent"}}""",
            "denied" => """{"error":{"code":"AuthorizationFailed","message":"controlled-denied"}}""",
            "empty" => "",
            "envelope" => """{"status":"Succeeded"}""",
            _ => JsonSerializer.Serialize(new
            {
                id = Notification,
                name = "capture-notification",
                type = "Microsoft.EventGrid/eventSubscriptions",
                properties = new { topic = Vault, provisioningState = shape }
            })
        };
        Task? start = null, check = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        var handle = f.Handle!;
        await Assert.That(handle.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        var result = await f.Check(retained: task => check = task);
        bool denied = status is 401 or 403;
        await Assert.That(result).IsEqualTo(denied ? SecretStatus.Denied : SecretStatus.Success);
        await Assert.That(handle.State).IsEqualTo(
            denied ? NativeProvisioningState.Failed : NativeProvisioningState.Succeeded);
        await Assert.That(start!.IsCompletedSuccessfully && check!.IsCompletedSuccessfully).IsTrue();
        var captured = await f.Source.SealAsync(f.Window);
        await Assert.That(ReferenceEquals(captured.Start!.SdkTask, start)).IsTrue();
        await Assert.That(ReferenceEquals(captured.Status!.SdkTask, check)).IsTrue();
        await Assert.That(ReferenceEquals(handle, f.Handle)).IsTrue();
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
        await Assert.That(f.Backend.Requests[1].Method).IsEqualTo("GET");
        await Assert.That(f.Backend.Requests[1].Path).IsEqualTo(Notification);
        await Assert.That(f.Backend.Requests[1].Query).IsEqualTo("?api-version=2025-02-15");
        await Assert.That(f.Backend.Authorizations.Distinct().Count()).IsEqualTo(1);
        var read = captured.Status.Attempts.Single();
        await Assert.That(read.HttpStatus).IsEqualTo(status);
        await Assert.That(read.TransportTerminated && read.ResponseObserved).IsTrue();
        // This diagnostic cannot mint DELETE D settlement, even for a native success.
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await Assert.That(await handle.CheckStatusAsync()).IsEqualTo(
            denied ? SecretStatus.Unknown : SecretStatus.Success);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
    }
}
