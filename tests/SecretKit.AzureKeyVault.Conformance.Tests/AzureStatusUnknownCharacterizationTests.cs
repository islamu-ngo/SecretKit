using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments("missing-id", SecretStatus.Invalid)]
    [Arguments("null", SecretStatus.Unknown)]
    [Arguments("foreign-id", SecretStatus.Unknown)]
    public async Task StatusUnknownVaultInvalidFinalValueDoesNotMakeHandleUnknown(string shape, SecretStatus expected)
    {
        using var f = new Fixture("CreateOrUpdateVault", "status.Unknown");
        f.AsyncStart();
        f.Backend.StartStatus = 201;
        f.Backend.StartBody = f.Backend.FinalBody!.Replace("Succeeded", "Updating", StringComparison.Ordinal);
        f.Backend.StatusBody = "{\"status\":\"Succeeded\"}";
        var final = JsonNode.Parse(f.Backend.FinalBody)!;
        if (shape == "missing-id") final.AsObject().Remove("id");
        if (shape == "foreign-id") final["id"] = Vault + "-foreign";
        f.Backend.FinalBody = shape == "null" ? "null" : final.ToJsonString();
        Task? start = null, selected = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        SecretStatus outcome = await f.Check(retained: task => selected = task);
        await Assert.That(outcome).IsEqualTo(expected);
        await Assert.That(start!.IsCompletedSuccessfully && selected!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(f.Handle.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(2);
        await Assert.That(f.Backend.Requests.Where(r => r.Method == "GET").All(r =>
            r.Path == f.Backend.StatusPath || r.Path == Vault)).IsTrue();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusUnknownPurgeUnknownTextDoesNotMakeHandleUnknown()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Unknown");
        f.AsyncStart();
        f.Backend.StartBody = "{\"status\":\"InProgress\"}";
        f.Backend.StatusBody = "{\"status\":\"future-state\"}";
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Pending);
        await Assert.That(f.Handle.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "POST")).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("CreateOrUpdateNotification", "Unknown")]
    [Arguments("CreateOrUpdateNotification", "future-state")]
    [Arguments("UpdateNotification", "Unknown")]
    [Arguments("UpdateNotification", "future-state")]
    public async Task StatusUnknownNotificationFinalValueCanMakeHandleUnknown(string operation, string state)
    {
        using var f = new Fixture(operation);
        var body = JsonNode.Parse(f.Backend.StartBody)!;
        body["properties"]!["provisioningState"] = "Updating";
        body["properties"]!["labels"] = new JsonArray("secretkit-fixture-" + f.Binding.Selector.Nonce.ToString("N"));
        body["properties"]!["filter"] = new JsonObject
        {
            ["includedEventTypes"] = new JsonArray("Microsoft.KeyVault.SecretNewVersionCreated")
        };
        body["properties"]!["destination"]!["properties"]!["deliveryAttributeMappings"] = new JsonArray();
        f.Backend.StartBody = body.ToJsonString();
        f.Backend.Targets.Clear();
        f.Backend.ExtraHeaders.Clear();
        f.Backend.Targets.Add(("Location", Origin + Notification + "?api-version=" + f.Revision));
        f.Backend.ExtraHeaders.Add(("x-ms-request-id", "controlled-unknown-notification"));
        f.Backend.StatusPath = Notification;
        body["properties"]!["provisioningState"] = state;
        f.Backend.StatusBody = body.ToJsonString();
        Task? start = null, selected = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(await f.Check(retained: task => selected = task)).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(start!.IsCompletedSuccessfully && selected!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(f.Handle.State).IsEqualTo(NativeProvisioningState.Unknown);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "PUT" || r.Method == "PATCH")).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await Assert.That(await f.Handle.CheckStatusAsync()).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }
}
