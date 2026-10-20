using Azure.Core;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments("Succeeded", NativeProvisioningState.Succeeded, SecretStatus.Success)]
    [Arguments("InProgress", NativeProvisioningState.Pending, SecretStatus.Pending)]
    [Arguments("Deleting", NativeProvisioningState.Pending, SecretStatus.Pending)]
    public async Task StatusDeniedNotificationDeleteIndependentStatusUsesOriginalIssuedOperation(
        string state, NativeProvisioningState expected, SecretStatus status)
    {
        using var f = new Fixture("DeleteNotification", boundary: "denied-authority",
            statusDeniedNotificationDelete: true);
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusTarget(f.Window, f.Binding, out var issued)).IsTrue();
        var target = issued ?? throw new InvalidOperationException("missing-original-target");
        f.Backend.StatusBody = "{\"status\":\"" + state + "\"}";
        var collector = new ManagementOperationStatusCollector(f.Source,
            new("independent-status", new NotificationDeleteStatusCredential(), f.Backend),
            new(65536, 8192, 16, TimeSpan.FromSeconds(20)));
        var window = collector.Arm(target, f.Binding);
        var task = collector.CollectAsync(window, f.Binding).AsTask();
        var measured = await task;
        await Assert.That(task.IsCompletedSuccessfully).IsTrue();
        await Assert.That(measured.OperationState).IsEqualTo(expected);
        await Assert.That(measured.Status).IsEqualTo(status);
        await Assert.That(measured.ResponseComplete).IsTrue();
        await Assert.That(measured.Terminal).IsEqualTo(expected == NativeProvisioningState.Succeeded);
        await Assert.That(ReferenceEquals(measured.Binding, f.Binding)).IsTrue();
        await Assert.That(measured.TargetSha256).IsEqualTo(target.TargetSha256);
        await Assert.That(measured.WindowId).IsEqualTo(window.Id);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
        await Assert.That(f.Backend.Requests[1].Path).IsEqualTo(new Uri(EventGridAsyncOperation).AbsolutePath);
        await Assert.That(f.Backend.Authorizations[1]).IsEqualTo("Bearer independent-delete-status");
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments(200, "{}")]
    [Arguments(200, """{"Status":"Succeeded"}""")]
    [Arguments(200, """{"status":"Succeeded","status":"Succeeded"}""")]
    [Arguments(200, """{"status":"Succeeded","properties":{}}""")]
    [Arguments(200, """{"properties":{"provisioningState":"Succeeded"}}""")]
    [Arguments(200, """{"status":"Succeeded","error":{}}""")]
    [Arguments(200, """{"status":"future-state"}""")]
    [Arguments(200, """{"status":"Failed"}""")]
    [Arguments(200, """{"status":"Canceled"}""")]
    [Arguments(202, """{"status":"Succeeded"}""")]
    [Arguments(204, "")]
    [Arguments(404, """{"error":{"code":"NotFound"}}""")]
    [Arguments(403, """{"error":{"code":"AuthorizationFailed","message":"controlled"}}""")]
    public async Task StatusDeniedNotificationDeleteIndependentNonterminalOrMalformedCannotSupplyQ(int code, string body)
    {
        using var f = new Fixture("DeleteNotification", boundary: "denied-authority",
            statusDeniedNotificationDelete: true);
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusTarget(f.Window, f.Binding, out var issued)).IsTrue();
        var target = issued ?? throw new InvalidOperationException("missing-original-target");
        f.Backend.StatusStatus = code;
        f.Backend.StatusBody = body;
        var collector = new ManagementOperationStatusCollector(f.Source,
            new("independent-status", new NotificationDeleteStatusCredential(), f.Backend),
            new(65536, 8192, 16, TimeSpan.FromSeconds(20)));
        var measured = await collector.CollectAsync(collector.Arm(target, f.Binding), f.Binding);
        await Assert.That(measured.Status == SecretStatus.Success &&
            measured.OperationState == NativeProvisioningState.Succeeded && measured.Terminal).IsFalse();
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusDeniedNotificationDeleteIndependentWindowRejectsCopiedBinding()
    {
        using var f = new Fixture("DeleteNotification", boundary: "denied-authority",
            statusDeniedNotificationDelete: true);
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusTarget(f.Window, f.Binding, out var issued)).IsTrue();
        var collector = new ManagementOperationStatusCollector(f.Source,
            new("independent-status", new NotificationDeleteStatusCredential(), f.Backend),
            new(65536, 8192, 16, TimeSpan.FromSeconds(20)));
        await Assert.That(() => collector.Arm(issued!, f.Binding with { })).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    private sealed class NotificationDeleteStatusCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return new("independent-delete-status", DateTimeOffset.MaxValue);
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken token) =>
            ValueTask.FromResult(GetToken(context, token));
    }
}
