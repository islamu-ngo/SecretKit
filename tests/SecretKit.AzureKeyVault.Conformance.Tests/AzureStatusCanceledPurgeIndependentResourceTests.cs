using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using R = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationResourceCollectorTests
{
    [Test]
    public async Task StatusCanceledPurgeIndependentCannotBorrowSelectedResourceAuthority()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Canceled", boundary: "selected-contract");
        var binding = ConfigureCanceledPurgeResource(f, "SelectedDeletedPresent");
        var window = f.Collector.ArmStatusCanceledPurge(binding, CanceledPurgeResourceBaseline(),
            R.StatusCanceledPurgeReadPhase.SelectedDeletedPresent);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusCanceledPurgeIndependentRead(window, binding,
            R.StatusCanceledPurgeIndependentReadPhase.SelectedDeletedPresent, task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusCanceledPurgeRead(window, binding,
            R.StatusCanceledPurgeReadPhase.SelectedDeletedPresent, task, out _)).IsTrue();
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("cancellation-boundary")]
    public async Task StatusCanceledPurgeIndependentCannotBorrowActualFailedResourceAuthority(string boundary)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Failed", boundary: boundary);
        var binding = ConfigureFailedPurgeResource(f, "SelectedDeletedPresent");
        var baseline = FailedPurgeResourceBaseline();
        var window = boundary switch
        {
            "selected-contract" => f.Collector.ArmStatusFailedPurge(binding, baseline,
                R.StatusFailedPurgeReadPhase.SelectedDeletedPresent),
            "independent-effect" => f.Collector.ArmStatusFailedPurgeIndependent(binding, baseline,
                R.StatusFailedPurgeIndependentReadPhase.SelectedDeletedPresent),
            _ => f.Collector.ArmStatusFailedPurgeCancellation(binding, baseline,
                R.StatusFailedPurgeCancellationReadPhase.SelectedDeletedPresent)
        };
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusCanceledPurgeIndependentRead(window, binding,
            R.StatusCanceledPurgeIndependentReadPhase.SelectedDeletedPresent, task, out _)).IsFalse();
        bool owned = boundary switch
        {
            "selected-contract" => f.Collector.TryGetStatusFailedPurgeRead(window, binding,
                R.StatusFailedPurgeReadPhase.SelectedDeletedPresent, task, out _),
            "independent-effect" => f.Collector.TryGetStatusFailedPurgeIndependentRead(window, binding,
                R.StatusFailedPurgeIndependentReadPhase.SelectedDeletedPresent, task, out _),
            _ => f.Collector.TryGetStatusFailedPurgeCancellationRead(window, binding,
                R.StatusFailedPurgeCancellationReadPhase.SelectedDeletedPresent, task, out _)
        };
        await Assert.That(owned).IsTrue();
    }

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
    public async Task StatusCanceledPurgeIndependentResourceProofRequiresExactPhaseAndActualNativeTask(string phaseName)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Canceled", boundary: "independent-effect");
        var phase = Enum.Parse<R.StatusCanceledPurgeIndependentReadPhase>(phaseName);
        var binding = ConfigureCanceledPurgeIndependentResource(f, phaseName);
        var window = f.Collector.ArmStatusCanceledPurgeIndependent(binding, CanceledPurgeIndependentResourceBaseline(), phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusCanceledPurgeIndependentRead(window, binding, phase, task, out var proof)).IsTrue();
        await Assert.That(f.Collector.OwnsStatusCanceledPurgeIndependentRead(proof!, window, binding, phase, task)).IsTrue();
        var forged = new TaskCompletionSource<R.Measurement>(TaskCreationOptions.RunContinuationsAsynchronously);
        forged.SetResult(measured);
        await Assert.That(f.Collector.TryGetStatusCanceledPurgeIndependentRead(window, binding, phase, forged.Task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusCanceledPurgeIndependentRead(window, binding with { }, phase, task, out _)).IsFalse();
        var foreign = phase == R.StatusCanceledPurgeIndependentReadPhase.ReadyActiveAbsent
            ? R.StatusCanceledPurgeIndependentReadPhase.FinalActiveAbsent : R.StatusCanceledPurgeIndependentReadPhase.ReadyActiveAbsent;
        await Assert.That(f.Collector.TryGetStatusCanceledPurgeIndependentRead(window, binding, foreign, task, out _)).IsFalse();
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
    public async Task StatusCanceledPurgeIndependentResourceAbsenceRequiresStrictNativeResourceNotFound(string phaseName, string code)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Canceled", boundary: "independent-effect");
        var phase = Enum.Parse<R.StatusCanceledPurgeIndependentReadPhase>(phaseName);
        var binding = ConfigureCanceledPurgeIndependentResource(f, phaseName);
        f.Body = code.Length == 0 || code.StartsWith('{') ? code : new JsonObject
        { ["error"] = new JsonObject { ["code"] = code } }.ToJsonString();
        var window = f.Collector.ArmStatusCanceledPurgeIndependent(binding, CanceledPurgeIndependentResourceBaseline(), phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusCanceledPurgeIndependentRead(window, binding, phase, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("id")]
    [Arguments("vaultId")]
    [Arguments("location")]
    [Arguments("tags")]
    [Arguments("purgeProtectionEnabled")]
    [Arguments("deletionDate")]
    public async Task StatusCanceledPurgeIndependentDeletedReadRequiresCompleteOwnedNativeMetadata(string field)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Canceled", boundary: "independent-effect");
        var binding = ConfigureCanceledPurgeIndependentResource(f, "SelectedDeletedPresent");
        var body = JsonNode.Parse(f.Body)!;
        if (field == "id") body["id"] = f.Path + "-foreign";
        else body["properties"]!.AsObject().Remove(field);
        f.Body = body.ToJsonString();
        var phase = R.StatusCanceledPurgeIndependentReadPhase.SelectedDeletedPresent;
        var window = f.Collector.ArmStatusCanceledPurgeIndependent(binding, CanceledPurgeIndependentResourceBaseline(), phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusCanceledPurgeIndependentRead(window, binding, phase, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    private static VaultAdministrationEffects.Configuration CanceledPurgeIndependentResourceBaseline() =>
        new("eastus", Guid.Parse(Tenant), VaultSku.Standard, true, false, 7, true, []);

    private static ManagementOperationNativeCapture.Binding ConfigureCanceledPurgeIndependentResource(Fixture f, string phase)
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
    public async Task StatusCanceledPurgeIndependentResourceRequiresExplicitRegistrationNotGenericRead()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Canceled", boundary: "independent-effect");
        var binding = ConfigureCanceledPurgeIndependentResource(f, "SelectedDeletedPresent");
        await Assert.That(() => f.Collector.Arm(binding)).Throws<ArgumentException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        var window = f.Collector.ArmStatusCanceledPurgeIndependent(binding, CanceledPurgeIndependentResourceBaseline(),
            R.StatusCanceledPurgeIndependentReadPhase.SelectedDeletedPresent);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusCanceledPurgeIndependentRead(window, binding,
            R.StatusCanceledPurgeIndependentReadPhase.SelectedDeletedPresent, task, out var proof)).IsTrue();
        await Assert.That(f.Collector.OwnsStatusCanceledPurgeIndependentRead(proof!, window, binding,
            R.StatusCanceledPurgeIndependentReadPhase.SelectedDeletedPresent, task)).IsTrue();
        await Assert.That(f.Collector.TryGetStatusCanceledPurgeRead(window, binding,
            R.StatusCanceledPurgeReadPhase.SelectedDeletedPresent, task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusFailedPurgeRead(window, binding,
            R.StatusFailedPurgeReadPhase.SelectedDeletedPresent, task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusFailedPurgeIndependentRead(window, binding,
            R.StatusFailedPurgeIndependentReadPhase.SelectedDeletedPresent, task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusFailedPurgeCancellationRead(window, binding,
            R.StatusFailedPurgeCancellationReadPhase.SelectedDeletedPresent, task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusPendingPurgeRead(window, binding,
            R.StatusPendingPurgeReadPhase.SelectedDeletedPresent, task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusPendingPurgeIndependentRead(window, binding,
            R.StatusPendingPurgeIndependentReadPhase.SelectedDeletedPresent, task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusPendingPurgeCancellationRead(window, binding,
            R.StatusPendingPurgeCancellationReadPhase.SelectedDeletedPresent, task, out _)).IsFalse();
    }
}
