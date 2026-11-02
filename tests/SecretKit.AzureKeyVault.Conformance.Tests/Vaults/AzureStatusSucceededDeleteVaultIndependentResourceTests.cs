using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using R = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationResourceCollectorTests
{
    [Test]
    [Arguments("BaselineActive")]
    [Arguments("BaselineDeleted")]
    [Arguments("SelectedActive")]
    [Arguments("SelectedDeleted")]
    public async Task StatusSucceededDeleteVaultIndependentResourceProofRequiresActualPhaseAndReadTask(string phaseName)
    {
        var phase = Enum.Parse<R.StatusSucceededDeleteVaultIndependentReadPhase>(phaseName);
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "independent-effect");
        ConfigureSucceededIndependentResource(f, phase);
        var binding = SucceededIndependentResourceBinding(f, phase);
        var window = f.Collector.ArmStatusSucceededDeleteVaultIndependent(binding, SucceededIndependentResourceBaseline(), phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusSucceededDeleteVaultIndependentRead(window, binding, task, out var proof)).IsTrue();
        await Assert.That(proof).IsNotNull();
        await Assert.That(f.Collector.TryGetStatusSucceededDeleteVaultIndependentRead(window, binding with { }, task, out _)).IsFalse();
        var copied = new TaskCompletionSource<R.Measurement>(TaskCreationOptions.RunContinuationsAsynchronously);
        copied.SetResult(result);
        await Assert.That(ReferenceEquals(task, copied.Task)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusSucceededDeleteVaultIndependentRead(window, binding, copied.Task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        bool deleted = phase is R.StatusSucceededDeleteVaultIndependentReadPhase.BaselineDeleted or
            R.StatusSucceededDeleteVaultIndependentReadPhase.SelectedDeleted;
        await Assert.That(f.Backend.Requests[0].Contains(deleted ? "/deletedVaults/" : "/vaults/", StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    public async Task StatusSucceededDeleteVaultIndependentRawResourceWindowCannotMintProfileProof()
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "independent-effect");
        ConfigureSucceededIndependentResource(f, R.StatusSucceededDeleteVaultIndependentReadPhase.BaselineActive);
        var window = f.Collector.Arm(f.Binding);
        var task = f.Collector.CollectAsync(window, f.Binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusSucceededDeleteVaultIndependentRead(window, f.Binding, task, out _)).IsFalse();
    }

    [Test]
    [Arguments("empty")]
    [Arguments("malformed")]
    [Arguments("forbidden")]
    [Arguments("contradictory")]
    public async Task StatusSucceededDeleteVaultIndependentResourceAbsenceRequiresNativeErrorAgreement(string fault)
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "independent-effect");
        ConfigureSucceededIndependentResource(f, R.StatusSucceededDeleteVaultIndependentReadPhase.SelectedActive);
        f.Body = fault switch
        {
            "empty" => "",
            "malformed" => "{",
            "forbidden" => """{"error":{"code":"Forbidden"}}""",
            _ => """{"error":{"code":"ResourceNotFound","details":[{"code":"Forbidden"}]}}"""
        };
        var window = f.Collector.ArmStatusSucceededDeleteVaultIndependent(f.Binding, SucceededIndependentResourceBaseline(),
            R.StatusSucceededDeleteVaultIndependentReadPhase.SelectedActive);
        var task = f.Collector.CollectAsync(window, f.Binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusSucceededDeleteVaultIndependentRead(window, f.Binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("id")]
    [Arguments("nonce")]
    [Arguments("tenant")]
    [Arguments("private")]
    [Arguments("policy")]
    [Arguments("network")]
    public async Task StatusSucceededDeleteVaultIndependentResourceBaselineCannotProjectMissingOrForeignFields(string field)
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "independent-effect");
        ConfigureSucceededIndependentResource(f, R.StatusSucceededDeleteVaultIndependentReadPhase.BaselineActive);
        var body = JsonNode.Parse(f.Body)!;
        switch (field)
        {
            case "id": body["id"] = Vault + "-foreign"; break;
            case "nonce": body["tags"]!["secretkit-fixture"] = Guid.NewGuid().ToString("N"); break;
            case "tenant": body["properties"]!["tenantId"] = Guid.NewGuid().ToString(); break;
            case "private": body["properties"]!.AsObject().Remove("privateEndpointConnections"); break;
            case "policy": body["properties"]!.AsObject().Remove("accessPolicies"); break;
            default: body["properties"]!["publicNetworkAccess"] = "Disabled"; break;
        }
        f.Body = body.ToJsonString();
        var window = f.Collector.ArmStatusSucceededDeleteVaultIndependent(f.Binding, SucceededIndependentResourceBaseline(),
            R.StatusSucceededDeleteVaultIndependentReadPhase.BaselineActive);
        var task = f.Collector.CollectAsync(window, f.Binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusSucceededDeleteVaultIndependentRead(window, f.Binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("vault")]
    [Arguments("tag")]
    [Arguments("retention")]
    [Arguments("protection")]
    public async Task StatusSucceededDeleteVaultIndependentResourceDeletedCounterpartRequiresOriginalOwnership(string field)
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "independent-effect");
        ConfigureSucceededIndependentResource(f, R.StatusSucceededDeleteVaultIndependentReadPhase.SelectedDeleted);
        var body = JsonNode.Parse(f.Body)!;
        switch (field)
        {
            case "vault": body["properties"]!["vaultId"] = Vault + "-foreign"; break;
            case "tag": body["properties"]!["tags"]!["secretkit-fixture"] = Guid.NewGuid().ToString("N"); break;
            case "retention": body["properties"]!["scheduledPurgeDate"] = "2026-10-14T00:00:01Z"; break;
            default: body["properties"]!["purgeProtectionEnabled"] = true; break;
        }
        f.Body = body.ToJsonString();
        var binding = SucceededIndependentResourceBinding(f, R.StatusSucceededDeleteVaultIndependentReadPhase.SelectedDeleted);
        var window = f.Collector.ArmStatusSucceededDeleteVaultIndependent(binding, SucceededIndependentResourceBaseline(),
            R.StatusSucceededDeleteVaultIndependentReadPhase.SelectedDeleted);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusSucceededDeleteVaultIndependentRead(window, binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    private static VaultAdministrationEffects.Configuration SucceededIndependentResourceBaseline() =>
        new("eastus", Guid.Parse(Tenant), VaultSku.Standard, true, false, 7, true, []);

    private static ManagementOperationNativeCapture.Binding SucceededIndependentResourceBinding(Fixture f,
        R.StatusSucceededDeleteVaultIndependentReadPhase phase) => phase is R.StatusSucceededDeleteVaultIndependentReadPhase.BaselineDeleted or
            R.StatusSucceededDeleteVaultIndependentReadPhase.SelectedDeleted
        ? f.Binding with { Resource = new DeletedVaultScope(((VaultScope)f.Binding.Resource).ResourceGroup.Subscription, "eastus", "resource-vault") }
        : f.Binding;

    private static void ConfigureSucceededIndependentResource(Fixture f, R.StatusSucceededDeleteVaultIndependentReadPhase phase)
    {
        bool deleted = phase is R.StatusSucceededDeleteVaultIndependentReadPhase.BaselineDeleted or
            R.StatusSucceededDeleteVaultIndependentReadPhase.SelectedDeleted;
        bool present = phase is R.StatusSucceededDeleteVaultIndependentReadPhase.BaselineActive or
            R.StatusSucceededDeleteVaultIndependentReadPhase.SelectedDeleted;
        f.Path = deleted ? "/subscriptions/" + Subscription +
            "/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/resource-vault" : Vault;
        f.Status = present ? 200 : 404;
        if (!present) { f.Body = """{"error":{"code":"ResourceNotFound"}}"""; return; }
        if (deleted)
            f.Body = JsonSerializer.Serialize(new
            {
                id = f.Path,
                name = "resource-vault",
                type = "Microsoft.KeyVault/locations/deletedVaults",
                properties = new
                {
                    location = "eastus",
                    vaultId = Vault,
                    tags = new Dictionary<string, string> { ["secretkit-fixture"] = f.Binding.Selector.Nonce.ToString("N") },
                    purgeProtectionEnabled = false,
                    deletionDate = "2026-10-14T00:00:00Z",
                    scheduledPurgeDate = "2026-10-21T00:00:00Z"
                }
            });
        else
        {
            var body = JsonNode.Parse(f.Body)!;
            body["tags"] = new JsonObject { ["secretkit-fixture"] = f.Binding.Selector.Nonce.ToString("N") };
            body["properties"]!["privateEndpointConnections"] = new JsonArray();
            f.Body = body.ToJsonString();
        }
    }
}
