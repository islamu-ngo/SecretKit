using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using R = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationResourceCollectorTests
{
    [Test]
    [Arguments(NativeProvisioningState.Succeeded)]
    [Arguments(NativeProvisioningState.Pending)]
    [Arguments(NativeProvisioningState.Failed)]
    [Arguments(NativeProvisioningState.Canceled)]
    [Arguments(NativeProvisioningState.Unknown)]
    public async Task StatusDeniedPurgeStatusResourceKeysRetainExactReadMembership(NativeProvisioningState variant)
    {
        using var f = new Fixture("PurgeDeletedVault", "status." + variant, boundary: "denied-authority");
        var binding = ConfigureFailedPurgeResource(f, "BaselineDeletedPresent");
        var phase = R.StatusDeniedPurgeReadPhase.BaselineDeletedPresent;
        var window = f.Collector.ArmStatusDeniedPurge(binding, FailedPurgeResourceBaseline(), phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedPurgeRead(window, binding, phase, task, out var proof)).IsTrue();
        var foreign = binding with { Selector = binding.Selector with { Variant = "operation.PurgeDeletedVault" } };
        var otherCollector = new R(new("host-owned-observer", f.Credential, f.Backend), Bounds, f.Clock, Guid.Parse(Tenant));
        var otherWindow = otherCollector.ArmStatusDeniedPurge(foreign, FailedPurgeResourceBaseline(), phase);
        var otherTask = otherCollector.CollectAsync(otherWindow, foreign).AsTask();
        using var otherMeasured = await otherTask;
        await Assert.That(otherCollector.TryGetStatusDeniedPurgeRead(otherWindow, foreign, phase, otherTask, out var other)).IsTrue();
        await Assert.That(otherCollector.OwnsStatusDeniedPurgeRead(proof!, otherWindow, foreign, phase, otherTask)).IsFalse();
        await Assert.That(f.Collector.OwnsStatusDeniedPurgeRead(other!, window, binding, phase, task)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
    }

    [Test]
    [Arguments("id")]
    [Arguments("vaultId")]
    [Arguments("location")]
    [Arguments("tags")]
    [Arguments("purgeProtectionEnabled")]
    [Arguments("deletionDate")]
    public async Task StatusDeniedPurgeBaselineRequiresCompleteOwnedDeletedMetadata(string field)
    {
        using var f = new Fixture("PurgeDeletedVault", boundary: "denied-authority");
        var binding = ConfigureFailedPurgeResource(f, "BaselineDeletedPresent");
        var body = JsonNode.Parse(f.Body)!;
        if (field == "id") body["id"] = f.Path + "-foreign";
        else body["properties"]!.AsObject().Remove(field);
        f.Body = body.ToJsonString();
        var phase = R.StatusDeniedPurgeReadPhase.BaselineDeletedPresent;
        var window = f.Collector.ArmStatusDeniedPurge(binding, FailedPurgeResourceBaseline(), phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedPurgeRead(window, binding, phase, task, out _)).IsFalse();
    }

    [Test]
    [Arguments("ReadyActiveAbsent")]
    [Arguments("ReadyDeletedPresent")]
    [Arguments("BaselineActiveAbsent")]
    [Arguments("BaselineDeletedPresent")]
    [Arguments("SelectedActiveAbsent")]
    [Arguments("SelectedDeletedAbsent")]
    [Arguments("FinalActiveAbsent")]
    [Arguments("FinalDeletedAbsent")]
    public async Task StatusDeniedPurgeResourceRequiresExactPhaseAndNativeTask(string phaseName)
    {
        using var f = new Fixture("PurgeDeletedVault", boundary: "denied-authority");
        var phase = Enum.Parse<R.StatusDeniedPurgeReadPhase>(phaseName);
        var binding = ConfigureFailedPurgeResource(f, phaseName);
        var window = f.Collector.ArmStatusDeniedPurge(binding, FailedPurgeResourceBaseline(), phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedPurgeRead(window, binding, phase, task, out var proof)).IsTrue();
        await Assert.That(f.Collector.OwnsStatusDeniedPurgeRead(proof!, window, binding, phase, task)).IsTrue();
        var forged = new TaskCompletionSource<R.Measurement>(TaskCreationOptions.RunContinuationsAsynchronously);
        forged.SetResult(measured);
        await Assert.That(f.Collector.TryGetStatusDeniedPurgeRead(window, binding, phase, forged.Task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusDeniedPurgeRead(window, binding with { }, phase, task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusPendingPurgeRead(window, binding,
            R.StatusPendingPurgeReadPhase.FinalDeletedAbsent, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("ReadyActiveAbsent")]
    [Arguments("BaselineActiveAbsent")]
    [Arguments("SelectedActiveAbsent")]
    [Arguments("SelectedDeletedAbsent")]
    [Arguments("FinalActiveAbsent")]
    [Arguments("FinalDeletedAbsent")]
    public async Task StatusDeniedPurgeAbsenceRejectsDifferentNativeError(string phaseName)
    {
        using var f = new Fixture("PurgeDeletedVault", boundary: "denied-authority");
        var phase = Enum.Parse<R.StatusDeniedPurgeReadPhase>(phaseName);
        var binding = ConfigureFailedPurgeResource(f, phaseName);
        f.Body = """{"error":{"code":"VaultNotFound"}}""";
        var window = f.Collector.ArmStatusDeniedPurge(binding, FailedPurgeResourceBaseline(), phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedPurgeRead(window, binding, phase, task, out _)).IsFalse();
    }
}
