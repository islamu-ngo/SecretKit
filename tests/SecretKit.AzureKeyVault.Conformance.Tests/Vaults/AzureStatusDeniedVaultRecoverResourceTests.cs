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
    [Arguments("id")]
    [Arguments("name")]
    [Arguments("type")]
    [Arguments("properties.vaultId")]
    [Arguments("properties.location")]
    [Arguments("properties.tags")]
    [Arguments("properties.purgeProtectionEnabled")]
    [Arguments("properties.deletionDate")]
    [Arguments("properties.scheduledPurgeDate")]
    public async Task StatusDeniedVaultRecoverTombstoneCannotDefaultMissingFields(string field)
    {
        using var f = new Fixture("RecoverVault", boundary: "denied-authority");
        const C.StatusDeniedVaultRecoverReadPhase phase = C.StatusDeniedVaultRecoverReadPhase.BaselineDeleted;
        var (binding, expected) = ConfigureDeniedVaultRecoverRead(f, phase);
        var body = JsonNode.Parse(f.Body)!;
        string[] parts = field.Split('.');
        JsonNode current = body;
        foreach (string part in parts[..^1]) current = current[part]!;
        current.AsObject().Remove(parts[^1]);
        f.Body = body.ToJsonString();
        var window = f.Collector.ArmStatusDeniedVaultRecover(binding, expected, phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedVaultRecoverRead(window, binding, phase, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Cleared(f);
    }

    [Test]
    [Arguments("dates")]
    [Arguments("vault")]
    [Arguments("tag")]
    [Arguments("protection")]
    [Arguments("location")]
    public async Task StatusDeniedVaultRecoverTombstoneRequiresExactPreDeleteIdentity(string fault)
    {
        using var f = new Fixture("RecoverVault", boundary: "denied-authority");
        const C.StatusDeniedVaultRecoverReadPhase phase = C.StatusDeniedVaultRecoverReadPhase.BaselineDeleted;
        var (binding, expected) = ConfigureDeniedVaultRecoverRead(f, phase);
        var body = JsonNode.Parse(f.Body)!;
        if (fault == "dates") body["properties"]!["scheduledPurgeDate"] = "2026-10-24T00:00:00Z";
        if (fault == "vault") body["properties"]!["vaultId"] = Vault;
        if (fault == "tag") body["properties"]!["tags"]!["secretkit-fixture"] = Guid.NewGuid().ToString("N");
        if (fault == "protection") body["properties"]!["purgeProtectionEnabled"] = true;
        if (fault == "location") body["properties"]!["location"] = "westus";
        f.Body = body.ToJsonString();
        var window = f.Collector.ArmStatusDeniedVaultRecover(binding, expected, phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedVaultRecoverRead(window, binding, phase, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Cleared(f);
    }

    [Test]
    [Arguments("NotFound", true)]
    [Arguments("ResourceNotFound", true)]
    [Arguments("VaultNotFound", true)]
    [Arguments("Forbidden", false)]
    [Arguments("Unknown", false)]
    public async Task StatusDeniedVaultRecoverAbsenceRequiresNativeErrorAgreement(string code, bool valid)
    {
        using var f = new Fixture("RecoverVault", boundary: "denied-authority");
        const C.StatusDeniedVaultRecoverReadPhase phase = C.StatusDeniedVaultRecoverReadPhase.SelectedDeletedAbsent;
        var (binding, expected) = ConfigureDeniedVaultRecoverRead(f, phase);
        f.Body = JsonSerializer.Serialize(new { error = new { code } });
        var window = f.Collector.ArmStatusDeniedVaultRecover(binding, expected, phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedVaultRecoverRead(window, binding, phase, task, out var proof)).IsEqualTo(valid);
        if (valid)
        {
            await Assert.That(proof!.NativeTask.IsFaulted).IsTrue();
            await Assert.That(proof.NativeError!.ErrorCode).IsEqualTo(code);
            await Assert.That(proof.ErrorCode).IsEqualTo(code);
        }
        await Cleared(f);
    }

    [Test]
    public async Task StatusDeniedVaultRecoverGenericReadCannotGrantTypedProof()
    {
        using var f = new Fixture("RecoverVault", boundary: "denied-authority");
        const C.StatusDeniedVaultRecoverReadPhase phase = C.StatusDeniedVaultRecoverReadPhase.SelectedActive;
        var (binding, _) = ConfigureDeniedVaultRecoverRead(f, phase);
        var window = f.Collector.Arm(binding);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedVaultRecoverRead(window, binding, phase, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Cleared(f);
    }

    [Test]
    public async Task StatusDeniedVaultRecoverLateOriginalCallerCancellationRevokesReadProof()
    {
        using var f = new Fixture("RecoverVault", boundary: "denied-authority");
        using var caller = new CancellationTokenSource();
        const C.StatusDeniedVaultRecoverReadPhase phase = C.StatusDeniedVaultRecoverReadPhase.SelectedActive;
        var (binding, expected) = ConfigureDeniedVaultRecoverRead(f, phase);
        var window = f.Collector.ArmStatusDeniedVaultRecover(binding, expected, phase);
        var task = f.Collector.CollectAsync(window, binding, default, caller.Token).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedVaultRecoverRead(window, binding, phase, task, out _)).IsTrue();
        caller.Cancel();
        await Assert.That(f.Collector.TryGetStatusDeniedVaultRecoverRead(window, binding, phase, task, out _)).IsFalse();
        await Cleared(f);
    }

    [Test]
    [Arguments("ReadyActive")]
    [Arguments("ReadyDeletedAbsent")]
    [Arguments("BaselineActiveAbsent")]
    [Arguments("BaselineDeleted")]
    [Arguments("SelectedActive")]
    [Arguments("SelectedDeletedAbsent")]
    [Arguments("CleanupActiveRecovered")]
    [Arguments("CleanupActiveAbsent")]
    [Arguments("CleanupDeletedPresent")]
    [Arguments("CleanupDeletedAbsent")]
    [Arguments("FinalActiveAbsent")]
    [Arguments("FinalDeletedAbsent")]
    public async Task StatusDeniedVaultRecoverReadOwnsExactPhaseAndNativeTask(string phaseName)
    {
        using var f = new Fixture("RecoverVault", boundary: "denied-authority");
        var phase = Enum.Parse<C.StatusDeniedVaultRecoverReadPhase>(phaseName);
        var (binding, expected) = ConfigureDeniedVaultRecoverRead(f, phase);
        var window = f.Collector.ArmStatusDeniedVaultRecover(binding, expected, phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(measured.ResponseComplete).IsTrue();
        await Assert.That(f.Collector.TryGetStatusDeniedVaultRecoverRead(window, binding, phase, task, out var proof)).IsTrue();
        await Assert.That(f.Collector.OwnsStatusDeniedVaultRecoverRead(proof!, window, binding, phase, task)).IsTrue();
        await Assert.That(ReferenceEquals(proof!.ReadTask, task)).IsTrue();
        await Assert.That(proof.NativeTask.IsCompleted).IsTrue();
        await Assert.That(proof.NativeTask.IsFaulted).IsEqualTo(f.Status == 404);
        var fake = new TaskCompletionSource<C.Measurement>(TaskCreationOptions.RunContinuationsAsynchronously);
        fake.SetResult(measured);
        await Assert.That(f.Collector.TryGetStatusDeniedVaultRecoverRead(window, binding, phase, fake.Task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusDeniedVaultRecoverRead(window, binding with { }, phase, task, out _)).IsFalse();
        var wrong = phase == C.StatusDeniedVaultRecoverReadPhase.ReadyActive
            ? C.StatusDeniedVaultRecoverReadPhase.BaselineActiveAbsent : C.StatusDeniedVaultRecoverReadPhase.ReadyActive;
        await Assert.That(f.Collector.TryGetStatusDeniedVaultRecoverRead(window, binding, wrong, task, out _)).IsFalse();
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
    public async Task StatusDeniedVaultRecoverReadCannotDefaultMissingConfiguration(string field)
    {
        using var f = new Fixture("RecoverVault", boundary: "denied-authority");
        const C.StatusDeniedVaultRecoverReadPhase phase = C.StatusDeniedVaultRecoverReadPhase.SelectedActive;
        var (binding, expected) = ConfigureDeniedVaultRecoverRead(f, phase);
        var body = JsonNode.Parse(f.Body)!;
        string[] parts = field.Split('.');
        JsonNode current = body;
        foreach (string part in parts[..^1]) current = current[part]!;
        current.AsObject().Remove(parts[^1]);
        f.Body = body.ToJsonString();
        var window = f.Collector.ArmStatusDeniedVaultRecover(binding, expected, phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var result = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedVaultRecoverRead(window, binding, phase, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Cleared(f);
    }

    private static (Capture.Binding, VaultAdministrationEffects.Configuration) ConfigureDeniedVaultRecoverRead(
        Fixture f, C.StatusDeniedVaultRecoverReadPhase phase)
    {
        const string name = "skv0123456789abcdef01234";
        var vault = new VaultScope(new(new(Guid.Parse(Subscription)), "resource-group"), name);
        bool active = phase is C.StatusDeniedVaultRecoverReadPhase.ReadyActive or C.StatusDeniedVaultRecoverReadPhase.BaselineActiveAbsent or
            C.StatusDeniedVaultRecoverReadPhase.SelectedActive or C.StatusDeniedVaultRecoverReadPhase.CleanupActiveRecovered or
            C.StatusDeniedVaultRecoverReadPhase.CleanupActiveAbsent or C.StatusDeniedVaultRecoverReadPhase.FinalActiveAbsent;
        bool present = phase is C.StatusDeniedVaultRecoverReadPhase.ReadyActive or C.StatusDeniedVaultRecoverReadPhase.BaselineDeleted or
            C.StatusDeniedVaultRecoverReadPhase.SelectedActive or C.StatusDeniedVaultRecoverReadPhase.CleanupActiveRecovered or
            C.StatusDeniedVaultRecoverReadPhase.CleanupDeletedPresent;
        var expected = new VaultAdministrationEffects.Configuration("eastus", Guid.Parse(Tenant), VaultSku.Standard,
            true, false, 7, true, []);
        ManagementScope scope = active ? vault : new DeletedVaultScope(vault.ResourceGroup.Subscription, "eastus", name);
        var binding = f.Binding with { Resource = scope };
        f.Path = active ? vault.ExportResourceId() :
            "/subscriptions/" + Subscription + "/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/" + name;
        f.Status = present ? 200 : 404;
        var tags = new Dictionary<string, string> { ["secretkit-fixture"] = binding.Selector.Nonce.ToString("N") };
        f.Body = !present ? """{"error":{"code":"ResourceNotFound"}}""" : active ? JsonSerializer.Serialize(new
        {
            id = vault.ExportResourceId(), name, type = "Microsoft.KeyVault/vaults", location = "eastus", tags,
            properties = new
            {
                tenantId = Tenant, sku = new { family = "A", name = "standard" },
                vaultUri = "https://" + name + ".vault.azure.net/", provisioningState = "Succeeded",
                enableRbacAuthorization = true, enablePurgeProtection = false, enableSoftDelete = true,
                softDeleteRetentionInDays = 7, publicNetworkAccess = "Enabled",
                createMode = phase == C.StatusDeniedVaultRecoverReadPhase.ReadyActive ? "default" : "recover",
                accessPolicies = Array.Empty<object>(), privateEndpointConnections = Array.Empty<object>()
            }
        }) : JsonSerializer.Serialize(new
        {
            id = f.Path, name, type = "Microsoft.KeyVault/locations/deletedVaults",
            properties = new
            {
                vaultId = vault.ExportResourceId(), location = "eastus", tags, purgeProtectionEnabled = false,
                deletionDate = "2026-10-16T00:00:00Z", scheduledPurgeDate = "2026-10-23T00:00:00Z"
            }
        });
        return (binding, expected);
    }
}
