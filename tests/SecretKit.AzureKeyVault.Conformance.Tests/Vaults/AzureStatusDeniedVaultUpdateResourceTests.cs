using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector;
using Capture = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationResourceCollectorTests
{
    [Test]
    [Arguments("NotFound", true)]
    [Arguments("ResourceNotFound", true)]
    [Arguments("VaultNotFound", true)]
    [Arguments("Forbidden", false)]
    [Arguments("Unknown", false)]
    public async Task StatusDeniedVaultUpdateAbsenceRequiresNativeErrorAgreement(string code, bool valid)
    {
        using var f = new Fixture(boundary: "denied-authority");
        const C.StatusDeniedVaultUpdateReadPhase phase = C.StatusDeniedVaultUpdateReadPhase.SelectedDeletedAbsent;
        var (binding, expected) = ConfigureDeniedVaultUpdateRead(f, phase);
        f.Body = JsonSerializer.Serialize(new { error = new { code } });
        var window = f.Collector.ArmStatusDeniedVaultUpdate(binding, expected, phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedVaultUpdateRead(window, binding, phase, task, out var proof)).IsEqualTo(valid);
        if (valid)
        {
            await Assert.That(proof!.NativeTask.IsFaulted).IsTrue();
            await Assert.That(proof.NativeError!.ErrorCode).IsEqualTo(code);
            await Assert.That(proof.ErrorCode).IsEqualTo(code);
        }
        await Cleared(f);
    }

    [Test]
    public async Task StatusDeniedVaultUpdateGenericReadCannotGrantTypedProof()
    {
        using var f = new Fixture(boundary: "denied-authority");
        const C.StatusDeniedVaultUpdateReadPhase phase = C.StatusDeniedVaultUpdateReadPhase.SelectedActive;
        var (binding, _) = ConfigureDeniedVaultUpdateRead(f, phase);
        var window = f.Collector.Arm(binding);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedVaultUpdateRead(window, binding, phase, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Cleared(f);
    }

    [Test]
    public async Task StatusDeniedVaultUpdateLateOriginalCallerCancellationRevokesReadProof()
    {
        using var f = new Fixture(boundary: "denied-authority");
        using var caller = new CancellationTokenSource();
        const C.StatusDeniedVaultUpdateReadPhase phase = C.StatusDeniedVaultUpdateReadPhase.SelectedActive;
        var (binding, expected) = ConfigureDeniedVaultUpdateRead(f, phase);
        var window = f.Collector.ArmStatusDeniedVaultUpdate(binding, expected, phase);
        var task = f.Collector.CollectAsync(window, binding, default, caller.Token).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedVaultUpdateRead(window, binding, phase, task, out _)).IsTrue();
        caller.Cancel();
        await Assert.That(f.Collector.TryGetStatusDeniedVaultUpdateRead(window, binding, phase, task, out _)).IsFalse();
        await Cleared(f);
    }

    [Test]
    [Arguments("ReadyActive")]
    [Arguments("ReadyDeletedAbsent")]
    [Arguments("BaselineActive")]
    [Arguments("BaselineDeletedAbsent")]
    [Arguments("SelectedActive")]
    [Arguments("SelectedDeletedAbsent")]
    [Arguments("CleanupActive")]
    [Arguments("CleanupDeletedAbsent")]
    [Arguments("FinalActiveAbsent")]
    [Arguments("FinalDeletedAbsent")]
    public async Task StatusDeniedVaultUpdateReadOwnsExactPhaseAndNativeTask(string phaseName)
    {
        using var f = new Fixture(boundary: "denied-authority");
        var phase = Enum.Parse<C.StatusDeniedVaultUpdateReadPhase>(phaseName);
        var (binding, expected) = ConfigureDeniedVaultUpdateRead(f, phase);
        var window = f.Collector.ArmStatusDeniedVaultUpdate(binding, expected, phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(measured.ResponseComplete).IsTrue();
        await Assert.That(f.Collector.TryGetStatusDeniedVaultUpdateRead(window, binding, phase, task, out var proof)).IsTrue();
        await Assert.That(f.Collector.OwnsStatusDeniedVaultUpdateRead(proof!, window, binding, phase, task)).IsTrue();
        await Assert.That(ReferenceEquals(proof!.ReadTask, task)).IsTrue();
        await Assert.That(proof.NativeTask.IsCompleted).IsTrue();
        await Assert.That(proof.NativeTask.IsFaulted).IsEqualTo(f.Status == 404);
        var fake = new TaskCompletionSource<C.Measurement>(TaskCreationOptions.RunContinuationsAsynchronously);
        fake.SetResult(measured);
        await Assert.That(f.Collector.TryGetStatusDeniedVaultUpdateRead(window, binding, phase, fake.Task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusDeniedVaultUpdateRead(window, binding with { }, phase, task, out _)).IsFalse();
        var wrong = phase == C.StatusDeniedVaultUpdateReadPhase.ReadyActive
            ? C.StatusDeniedVaultUpdateReadPhase.BaselineActive : C.StatusDeniedVaultUpdateReadPhase.ReadyActive;
        await Assert.That(f.Collector.TryGetStatusDeniedVaultUpdateRead(window, binding, wrong, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Cleared(f);
    }

    [Test]
    [Arguments("id")]
    [Arguments("name")]
    [Arguments("type")]
    [Arguments("location")]
    [Arguments("tags")]
    [Arguments("properties.tenantId")]
    [Arguments("properties.vaultUri")]
    [Arguments("properties.sku.family")]
    [Arguments("properties.sku.name")]
    [Arguments("properties.enableRbacAuthorization")]
    [Arguments("properties.enableSoftDelete")]
    [Arguments("properties.enablePurgeProtection")]
    [Arguments("properties.softDeleteRetentionInDays")]
    [Arguments("properties.publicNetworkAccess")]
    [Arguments("properties.accessPolicies")]
    [Arguments("properties.privateEndpointConnections")]
    public async Task StatusDeniedVaultUpdateReadCannotDefaultMissingConfiguration(string field)
    {
        using var f = new Fixture(boundary: "denied-authority");
        const C.StatusDeniedVaultUpdateReadPhase phase = C.StatusDeniedVaultUpdateReadPhase.SelectedActive;
        var (binding, expected) = ConfigureDeniedVaultUpdateRead(f, phase);
        var body = JsonNode.Parse(f.Body)!;
        string[] parts = field.Split('.');
        JsonNode current = body;
        foreach (string part in parts[..^1]) current = current[part]!;
        current.AsObject().Remove(parts[^1]);
        f.Body = body.ToJsonString();
        var window = f.Collector.ArmStatusDeniedVaultUpdate(binding, expected, phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedVaultUpdateRead(window, binding, phase, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Cleared(f);
    }

    private static (Capture.Binding, VaultAdministrationEffects.Configuration) ConfigureDeniedVaultUpdateRead(
        Fixture f, C.StatusDeniedVaultUpdateReadPhase phase)
    {
        const string name = "skv0123456789abcdef01234";
        var vault = new VaultScope(new(new(Guid.Parse(Subscription)), "resource-group"), name);
        bool active = phase is C.StatusDeniedVaultUpdateReadPhase.ReadyActive or C.StatusDeniedVaultUpdateReadPhase.BaselineActive or
            C.StatusDeniedVaultUpdateReadPhase.SelectedActive or C.StatusDeniedVaultUpdateReadPhase.CleanupActive or
            C.StatusDeniedVaultUpdateReadPhase.FinalActiveAbsent;
        bool present = active && phase != C.StatusDeniedVaultUpdateReadPhase.FinalActiveAbsent;
        var expected = new VaultAdministrationEffects.Configuration("eastus", Guid.Parse(Tenant), VaultSku.Standard,
            true, false, 7, phase is not (C.StatusDeniedVaultUpdateReadPhase.ReadyActive or
                C.StatusDeniedVaultUpdateReadPhase.ReadyDeletedAbsent or C.StatusDeniedVaultUpdateReadPhase.BaselineActive or
                C.StatusDeniedVaultUpdateReadPhase.BaselineDeletedAbsent), []);
        ManagementScope scope = active ? vault : new DeletedVaultScope(vault.ResourceGroup.Subscription, "eastus", name);
        var binding = f.Binding with { Resource = scope };
        f.Path = active ? vault.ExportResourceId() :
            "/subscriptions/" + Subscription + "/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/" + name;
        f.Status = present ? 200 : 404;
        f.Body = !present ? """{"error":{"code":"ResourceNotFound"}}""" : JsonSerializer.Serialize(new
        {
            id = vault.ExportResourceId(), name, type = "Microsoft.KeyVault/vaults", location = "eastus",
            tags = new Dictionary<string, string> { ["secretkit-fixture"] = binding.Selector.Nonce.ToString("N") },
            properties = new
            {
                tenantId = Tenant, sku = new { family = "A", name = "standard" },
                vaultUri = "https://" + name + ".vault.azure.net/", provisioningState = "Succeeded",
                enableRbacAuthorization = true, enablePurgeProtection = false, enableSoftDelete = true,
                softDeleteRetentionInDays = 7, publicNetworkAccess = expected.PublicNetworkAccess ? "Enabled" : "Disabled",
                accessPolicies = Array.Empty<object>(), privateEndpointConnections = Array.Empty<object>()
            }
        });
        return (binding, expected);
    }
}
