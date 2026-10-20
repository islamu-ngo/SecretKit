using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusFailedPurgeNonemptyPendingStartRetainsActualTerminalFailure(bool includeError)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Failed", statusFailedPurge: true);
        f.Backend.StartBody = "{\"status\":\"InProgress\"}";
        f.Backend.StatusBody = includeError
            ? "{\"status\":\"Failed\",\"error\":{\"code\":\"OperationFailed\",\"message\":\"controlled failure\"}}"
            : "{\"status\":\"Failed\"}";
        Task? start = null, selected = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(await f.Check(retained: task => selected = task)).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(start!.IsCompletedSuccessfully && selected!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(f.Handle.State).IsEqualTo(NativeProvisioningState.Failed);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "POST")).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await Assert.That(await f.Handle.CheckStatusAsync()).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusFailedPurgeDistinctSetupCleanupCanFinishWithoutExtraNativeRead()
    {
        using var f = new Fixture("PurgeDeletedVault");
        f.Backend.StartBody = "{\"status\":\"Succeeded\"}";
        f.Backend.ExtraHeaders.Add(("x-ms-request-id", "controlled-failed-cleanup"));
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(await f.Handle!.CheckStatusAsync()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Single().Method).IsEqualTo("POST");
        await f.Source.SealAsync(f.Window);
    }
}
