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
    public async Task StatusSucceededDeleteVaultCancellationResourceProofRequiresActualPhaseAndReadTask(string phaseName)
    {
        var phase = Enum.Parse<R.StatusSucceededDeleteVaultCancellationReadPhase>(phaseName);
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "cancellation-boundary");
        ConfigureSucceededCancellationResource(f, phase);
        var binding = SucceededCancellationResourceBinding(f, phase);
        var window = f.Collector.ArmStatusSucceededDeleteVaultCancellation(binding, SucceededCancellationResourceBaseline(), phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusSucceededDeleteVaultCancellationRead(window, binding, task, out var proof)).IsTrue();
        await Assert.That(proof).IsNotNull();
        await Assert.That(f.Collector.TryGetStatusSucceededDeleteVaultCancellationRead(window, binding with { }, task, out _)).IsFalse();
        var copied = new TaskCompletionSource<R.Measurement>(TaskCreationOptions.RunContinuationsAsynchronously);
        copied.SetResult(result);
        await Assert.That(ReferenceEquals(task, copied.Task)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusSucceededDeleteVaultCancellationRead(window, binding, copied.Task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        bool deleted = phase is R.StatusSucceededDeleteVaultCancellationReadPhase.BaselineDeleted or
            R.StatusSucceededDeleteVaultCancellationReadPhase.SelectedDeleted;
        await Assert.That(f.Backend.Requests[0].Contains(deleted ? "/deletedVaults/" : "/vaults/", StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    public async Task StatusSucceededDeleteVaultCancellationRawResourceWindowCannotMintProfileProof()
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "cancellation-boundary");
        ConfigureSucceededCancellationResource(f, R.StatusSucceededDeleteVaultCancellationReadPhase.BaselineActive);
        var window = f.Collector.Arm(f.Binding);
        var task = f.Collector.CollectAsync(window, f.Binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusSucceededDeleteVaultCancellationRead(window, f.Binding, task, out _)).IsFalse();
    }

    [Test]
    [Arguments("empty")]
    [Arguments("malformed")]
    [Arguments("forbidden")]
    [Arguments("contradictory")]
    public async Task StatusSucceededDeleteVaultCancellationResourceAbsenceRequiresNativeErrorAgreement(string fault)
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "cancellation-boundary");
        ConfigureSucceededCancellationResource(f, R.StatusSucceededDeleteVaultCancellationReadPhase.SelectedActive);
        f.Body = fault switch
        {
            "empty" => "",
            "malformed" => "{",
            "forbidden" => """{"error":{"code":"Forbidden"}}""",
            _ => """{"error":{"code":"ResourceNotFound","details":[{"code":"Forbidden"}]}}"""
        };
        var window = f.Collector.ArmStatusSucceededDeleteVaultCancellation(f.Binding, SucceededCancellationResourceBaseline(),
            R.StatusSucceededDeleteVaultCancellationReadPhase.SelectedActive);
        var task = f.Collector.CollectAsync(window, f.Binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusSucceededDeleteVaultCancellationRead(window, f.Binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("id")]
    [Arguments("nonce")]
    [Arguments("tenant")]
    [Arguments("private")]
    [Arguments("policy")]
    [Arguments("network")]
    public async Task StatusSucceededDeleteVaultCancellationResourceBaselineCannotProjectMissingOrForeignFields(string field)
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "cancellation-boundary");
        ConfigureSucceededCancellationResource(f, R.StatusSucceededDeleteVaultCancellationReadPhase.BaselineActive);
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
        var window = f.Collector.ArmStatusSucceededDeleteVaultCancellation(f.Binding, SucceededCancellationResourceBaseline(),
            R.StatusSucceededDeleteVaultCancellationReadPhase.BaselineActive);
        var task = f.Collector.CollectAsync(window, f.Binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusSucceededDeleteVaultCancellationRead(window, f.Binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("vault")]
    [Arguments("tag")]
    [Arguments("retention")]
    [Arguments("protection")]
    public async Task StatusSucceededDeleteVaultCancellationResourceDeletedCounterpartRequiresOriginalOwnership(string field)
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "cancellation-boundary");
        ConfigureSucceededCancellationResource(f, R.StatusSucceededDeleteVaultCancellationReadPhase.SelectedDeleted);
        var body = JsonNode.Parse(f.Body)!;
        switch (field)
        {
            case "vault": body["properties"]!["vaultId"] = Vault + "-foreign"; break;
            case "tag": body["properties"]!["tags"]!["secretkit-fixture"] = Guid.NewGuid().ToString("N"); break;
            case "retention": body["properties"]!["scheduledPurgeDate"] = "2026-10-14T00:00:01Z"; break;
            default: body["properties"]!["purgeProtectionEnabled"] = true; break;
        }
        f.Body = body.ToJsonString();
        var binding = SucceededCancellationResourceBinding(f, R.StatusSucceededDeleteVaultCancellationReadPhase.SelectedDeleted);
        var window = f.Collector.ArmStatusSucceededDeleteVaultCancellation(binding, SucceededCancellationResourceBaseline(),
            R.StatusSucceededDeleteVaultCancellationReadPhase.SelectedDeleted);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusSucceededDeleteVaultCancellationRead(window, binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    private static VaultAdministrationEffects.Configuration SucceededCancellationResourceBaseline() =>
        new("eastus", Guid.Parse(Tenant), VaultSku.Standard, true, false, 7, true, []);

    private static ManagementOperationNativeCapture.Binding SucceededCancellationResourceBinding(Fixture f,
        R.StatusSucceededDeleteVaultCancellationReadPhase phase) => phase is R.StatusSucceededDeleteVaultCancellationReadPhase.BaselineDeleted or
            R.StatusSucceededDeleteVaultCancellationReadPhase.SelectedDeleted
        ? f.Binding with { Resource = new DeletedVaultScope(((VaultScope)f.Binding.Resource).ResourceGroup.Subscription, "eastus", "resource-vault") }
        : f.Binding;

    private static void ConfigureSucceededCancellationResource(Fixture f, R.StatusSucceededDeleteVaultCancellationReadPhase phase)
    {
        bool deleted = phase is R.StatusSucceededDeleteVaultCancellationReadPhase.BaselineDeleted or
            R.StatusSucceededDeleteVaultCancellationReadPhase.SelectedDeleted;
        bool present = phase is R.StatusSucceededDeleteVaultCancellationReadPhase.BaselineActive or
            R.StatusSucceededDeleteVaultCancellationReadPhase.SelectedDeleted;
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
