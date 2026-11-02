using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using R = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationResourceCollectorTests
{
    [Test]
    [Arguments("ReadyActiveAbsent")]
    [Arguments("ReadyDeletedPresent")]
    [Arguments("BaselineActiveAbsent")]
    [Arguments("BaselineDeletedPresent")]
    [Arguments("SelectedActiveAbsent")]
    [Arguments("SelectedDeletedPresent")]
    [Arguments("CleanupActiveAbsent")]
    [Arguments("CleanupDeletedPresent")]
    [Arguments("FinalActiveAbsent")]
    [Arguments("FinalDeletedAbsent")]
    public async Task StatusFailedPurgeResourceProofRequiresExactPhaseAndActualNativeTask(string phaseName)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Failed", boundary: "selected-contract");
        var phase = Enum.Parse<R.StatusFailedPurgeReadPhase>(phaseName);
        var binding = ConfigureFailedPurgeResource(f, phaseName);
        var window = f.Collector.ArmStatusFailedPurge(binding, FailedPurgeResourceBaseline(), phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusFailedPurgeRead(window, binding, phase, task, out var proof)).IsTrue();
        await Assert.That(f.Collector.OwnsStatusFailedPurgeRead(proof!, window, binding, phase, task)).IsTrue();
        var forged = new TaskCompletionSource<R.Measurement>(TaskCreationOptions.RunContinuationsAsynchronously);
        forged.SetResult(measured);
        await Assert.That(f.Collector.TryGetStatusFailedPurgeRead(window, binding, phase, forged.Task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusFailedPurgeRead(window, binding with { }, phase, task, out _)).IsFalse();
        var foreign = phase == R.StatusFailedPurgeReadPhase.ReadyActiveAbsent
            ? R.StatusFailedPurgeReadPhase.FinalActiveAbsent : R.StatusFailedPurgeReadPhase.ReadyActiveAbsent;
        await Assert.That(f.Collector.TryGetStatusFailedPurgeRead(window, binding, foreign, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("ReadyActiveAbsent", "")]
    [Arguments("FinalDeletedAbsent", "")]
    [Arguments("ReadyActiveAbsent", "{ ")]
    [Arguments("FinalDeletedAbsent", "{ ")]
    [Arguments("ReadyActiveAbsent", "Forbidden")]
    [Arguments("FinalDeletedAbsent", "VaultNotFound")]
    [Arguments("FinalDeletedAbsent", "DeletedVaultNotFound")]
    public async Task StatusFailedPurgeResourceAbsenceRequiresStrictNativeResourceNotFound(string phaseName, string code)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Failed", boundary: "selected-contract");
        var phase = Enum.Parse<R.StatusFailedPurgeReadPhase>(phaseName);
        var binding = ConfigureFailedPurgeResource(f, phaseName);
        f.Body = code.Length == 0 || code.StartsWith('{') ? code : new JsonObject
        { ["error"] = new JsonObject { ["code"] = code } }.ToJsonString();
        var window = f.Collector.ArmStatusFailedPurge(binding, FailedPurgeResourceBaseline(), phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusFailedPurgeRead(window, binding, phase, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("id")]
    [Arguments("vaultId")]
    [Arguments("location")]
    [Arguments("tags")]
    [Arguments("purgeProtectionEnabled")]
    [Arguments("deletionDate")]
    public async Task StatusFailedPurgeDeletedReadRequiresCompleteOwnedNativeMetadata(string field)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Failed", boundary: "selected-contract");
        var binding = ConfigureFailedPurgeResource(f, "SelectedDeletedPresent");
        var body = JsonNode.Parse(f.Body)!;
        if (field == "id") body["id"] = f.Path + "-foreign";
        else body["properties"]!.AsObject().Remove(field);
        f.Body = body.ToJsonString();
        var phase = R.StatusFailedPurgeReadPhase.SelectedDeletedPresent;
        var window = f.Collector.ArmStatusFailedPurge(binding, FailedPurgeResourceBaseline(), phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusFailedPurgeRead(window, binding, phase, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    private static VaultAdministrationEffects.Configuration FailedPurgeResourceBaseline() =>
        new("eastus", Guid.Parse(Tenant), VaultSku.Standard, true, false, 7, true, []);

    private static ManagementOperationNativeCapture.Binding ConfigureFailedPurgeResource(Fixture f, string phase)
    {
        string name = "skv" + f.Binding.Selector.Nonce.ToString("N")[..21];
        var vault = new VaultScope(new(new(Guid.Parse(Subscription)), "resource-group"), name);
        ManagementScope scope = phase.Contains("Active", StringComparison.Ordinal)
            ? vault : new DeletedVaultScope(vault.ResourceGroup.Subscription, "eastus", name);
        var binding = f.Binding with { Resource = scope };
        f.Path = scope is VaultScope ? vault.ExportResourceId() :
            "/subscriptions/" + Subscription + "/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/" + name;
        if (phase.EndsWith("Absent", StringComparison.Ordinal))
        {
            f.Status = 404;
            f.Body = "{\"error\":{\"code\":\"ResourceNotFound\"}}";
            return binding;
        }
        var body = JsonNode.Parse(f.Body)!;
        body["id"] = f.Path;
        body["name"] = name;
        body["type"] = "Microsoft.KeyVault/deletedVaults";
        body["properties"]!["vaultId"] = vault.ExportResourceId();
        body["properties"]!["tags"] = new JsonObject { ["secretkit-fixture"] = f.Binding.Selector.Nonce.ToString("N") };
        f.Body = body.ToJsonString();
        return binding;
    }


    [Test]
    public async Task StatusFailedPurgeResourceRequiresExplicitRegistrationNotGenericRead()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Failed");
        var binding = ConfigureFailedPurgeResource(f, "SelectedDeletedPresent");
        await Assert.That(() => f.Collector.Arm(binding)).Throws<ArgumentException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        var window = f.Collector.ArmStatusFailedPurge(binding, FailedPurgeResourceBaseline(),
            R.StatusFailedPurgeReadPhase.SelectedDeletedPresent);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusFailedPurgeRead(window, binding,
            R.StatusFailedPurgeReadPhase.SelectedDeletedPresent, task, out var proof)).IsTrue();
        await Assert.That(f.Collector.OwnsStatusFailedPurgeRead(proof!, window, binding,
            R.StatusFailedPurgeReadPhase.SelectedDeletedPresent, task)).IsTrue();
        await Assert.That(f.Collector.TryGetStatusPendingPurgeRead(window, binding,
            R.StatusPendingPurgeReadPhase.SelectedDeletedPresent, task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusPendingPurgeIndependentRead(window, binding,
            R.StatusPendingPurgeIndependentReadPhase.SelectedDeletedPresent, task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusPendingPurgeCancellationRead(window, binding,
            R.StatusPendingPurgeCancellationReadPhase.SelectedDeletedPresent, task, out _)).IsFalse();
    }
}
