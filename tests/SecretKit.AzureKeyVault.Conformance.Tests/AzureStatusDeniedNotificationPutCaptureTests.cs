using Azure.Core;
using Azure.Core.Pipeline;
using System.Text;
using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments(true, "flat")]
    [Arguments(true, "labels")]
    [Arguments(true, "mappings")]
    [Arguments(false, "wrapped")]
    public async Task StatusDeniedNotificationPutRejectsWrongRequestShapeBeforeSend(bool put, string fault)
    {
        using var f = new Fixture(put ? "CreateOrUpdateNotification" : "UpdateNotification",
            decorate: inner => new DeniedNotificationPutRequestMutation(inner, fault),
            boundary: "denied-authority", statusDeniedNotificationUpdate: true);
        Task? start = null;
        try { await f.Start(retained: task => start = task); }
        catch (InvalidOperationException) { }
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        await Assert.That(f.Source.TryGetStatusDeniedNotificationUpdateStart(f.Window, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    private sealed class DeniedNotificationPutRequestMutation(HttpPipelineTransport inner, string fault)
        : HttpPipelineTransport
    {
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            using var original = message.Request.Content!;
            using var bytes = new MemoryStream();
            await original.WriteToAsync(bytes, message.CancellationToken);
            var root = JsonNode.Parse(bytes.ToArray())!.AsObject();
            var properties = message.Request.Method == RequestMethod.Put ? root["properties"]!.AsObject() : root;
            if (fault == "flat") root = (JsonObject)properties.DeepClone();
            else if (fault == "wrapped") root = new JsonObject { ["properties"] = root.DeepClone() };
            else if (fault == "labels") properties["labels"] = new JsonArray("injected");
            else properties["destination"]!["properties"]!["deliveryAttributeMappings"] = new JsonArray();
            message.Request.Content = RequestContent.Create(Encoding.UTF8.GetBytes(root.ToJsonString()));
            await inner.ProcessAsync(message);
        }
    }

    [Test]
    public async Task StatusDeniedNotificationPutCannotBorrowPatchProofs()
    {
        using var put = new Fixture("CreateOrUpdateNotification", boundary: "denied-authority", statusDeniedNotificationUpdate: true);
        using var patch = new Fixture("UpdateNotification", boundary: "denied-authority", statusDeniedNotificationUpdate: true);
        foreach (var f in new[] { put, patch })
        {
            f.Backend.StatusStatus = 403;
            f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-denial"}}""";
        }
        Task? putStart = null, putCheck = null, patchStart = null, patchCheck = null;
        await put.Start(retained: task => putStart = task);
        await patch.Start(retained: task => patchStart = task);
        await put.Check(retained: task => putCheck = task);
        await patch.Check(retained: task => patchCheck = task);
        await Assert.That(patch.Source.TryGetStatusDeniedNotificationUpdateDenied(patch.Window, patch.Binding, patch.Client,
            (NotificationScope)patch.Scope, patch.Receipt, patchStart!, patch.Handle!, patchCheck!, out var patchProof)).IsTrue();
        await Assert.That(put.Source.OwnsStatusDeniedNotificationUpdateDenied(patchProof!, put.Window, put.Binding, put.Client,
            (NotificationScope)put.Scope, put.Receipt, putStart!, put.Handle!, putCheck!)).IsFalse();
        await Assert.That(put.Source.TryGetStatusDeniedNotificationUpdateDenied(put.Window, patch.Binding, put.Client,
            (NotificationScope)put.Scope, put.Receipt, putStart!, put.Handle!, putCheck!, out _)).IsFalse();
        await Assert.That(put.Source.TryGetStatusDeniedNotificationUpdateDenied(put.Window, put.Binding, put.Client,
            (NotificationScope)put.Scope, put.Receipt, putStart!, put.Handle!, putCheck!, out var putProof)).IsTrue();
        await Assert.That(patch.Source.OwnsStatusDeniedNotificationUpdateDenied(putProof!, patch.Window, patch.Binding, patch.Client,
            (NotificationScope)patch.Scope, patch.Receipt, patchStart!, patch.Handle!, patchCheck!)).IsFalse();
        await put.Source.SealAsync(put.Window);
        await patch.Source.SealAsync(patch.Window);
    }

    [Test]
    public async Task StatusDeniedNotificationPutRawFactsCannotEnrollQualifiedProofs()
    {
        using var f = new Fixture("CreateOrUpdateNotification", boundary: "denied-authority", statusDeniedNotificationUpdate: true);
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
    public async Task StatusDeniedNotificationPutBindsFirstActualScopeWithoutAllowingLaterSubstitution()
    {
        using var f = new Fixture("CreateOrUpdateNotification", boundary: "denied-authority", statusDeniedNotificationUpdate: true);
        var planned = (NotificationScope)f.Scope;
        var actual = new NotificationScope(planned.Vault, planned.SubscriptionName);
        var receipt = f.Client.PrepareReceipt(actual, ManagementMutation.CreateOrUpdateNotification);
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
    public async Task StatusDeniedNotificationPutOwnsActualStartAndDeniedTasks(int status)
    {
        using var f = new Fixture("CreateOrUpdateNotification", boundary: "denied-authority", statusDeniedNotificationUpdate: true);
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
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
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
    public async Task StatusDeniedNotificationPutUnqualifiedWireCannotMintDenial(string fault)
    {
        using var f = new Fixture("CreateOrUpdateNotification", boundary: "denied-authority", statusDeniedNotificationUpdate: true);
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
