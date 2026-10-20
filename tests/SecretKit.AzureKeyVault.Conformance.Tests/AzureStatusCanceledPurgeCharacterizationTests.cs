using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusCanceledPurgeNonemptyStartRetainsActualNativeCanceledState(bool includeError)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Canceled", statusCanceledPurge: true);
        f.Backend.StartBody = "{\"status\":\"InProgress\"}";
        f.Backend.StatusBody = includeError
            ? "{\"status\":\"Canceled\",\"error\":{\"code\":\"OperationCanceled\",\"message\":\"controlled cancellation\"}}"
            : "{\"status\":\"Canceled\"}";
        Task? start = null, selected = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(await f.Check(retained: task => selected = task)).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(start!.IsCompletedSuccessfully && selected!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(f.Handle.State).IsEqualTo(NativeProvisioningState.Canceled);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "POST")).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await Assert.That(await f.Handle.CheckStatusAsync()).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }
}
