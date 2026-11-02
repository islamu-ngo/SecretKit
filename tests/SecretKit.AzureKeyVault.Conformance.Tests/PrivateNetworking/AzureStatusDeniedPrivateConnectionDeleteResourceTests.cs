using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using R = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationResourceCollectorTests
{
    [Test]
    [Arguments("Discovery")]
    [Arguments("Baseline")]
    [Arguments("SelectedState")]
    [Arguments("Cleanup")]
    public async Task StatusDeniedPrivateConnectionDeleteResourceProofRequiresActualTaskAndPhase(string phaseName)
    {
        using var f = new Fixture("DeletePrivateConnection");
        var phase = Enum.Parse<R.StatusDeniedPrivateConnectionDeleteReadPhase>(phaseName);
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "denied-authority" } };
        ConfigureDeniedPrivateDeleteResource(f, phaseName);
        var window = f.Collector.ArmStatusDeniedPrivateConnectionDelete(binding, phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedPrivateConnectionDeleteRead(window, binding, task, out var proof)).IsTrue();
        await Assert.That(proof!.Phase).IsEqualTo(phase);
        await Assert.That(f.Collector.OwnsStatusDeniedPrivateConnectionDeleteRead(proof, window, binding, task)).IsTrue();
        var copied = new TaskCompletionSource<R.Measurement>(TaskCreationOptions.RunContinuationsAsynchronously);
        copied.SetResult(measured);
        await Assert.That(f.Collector.TryGetStatusDeniedPrivateConnectionDeleteRead(window, binding, copied.Task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusDeniedPrivateConnectionDeleteRead(window, binding with { }, task, out _)).IsFalse();
        using var other = new Fixture("DeletePrivateConnection");
        await Assert.That(other.Collector.OwnsStatusDeniedPrivateConnectionDeleteRead(proof, window, binding, task)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task StatusDeniedPrivateConnectionDeleteRawResourceInstrumentationCannotIssueProof()
    {
        using var f = new Fixture("DeletePrivateConnection");
        ConfigureDeniedPrivateDeleteResource(f, "Baseline");
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "denied-authority" } };
        var window = f.Collector.Arm(binding);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedPrivateConnectionDeleteRead(window, binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("empty")]
    [Arguments("malformed")]
    [Arguments("forbidden")]
    [Arguments("contradictory")]
    public async Task StatusDeniedPrivateConnectionDeleteResourceAbsenceRequiresActualNativeError(string fault)
    {
        using var f = new Fixture("DeletePrivateConnection");
        ConfigureDeniedPrivateDeleteResource(f, "SelectedState");
        f.Body = fault switch
        {
            "empty" => "",
            "malformed" => "{",
            "forbidden" => """{"error":{"code":"Forbidden"}}""",
            _ => """{"error":{"code":"ResourceNotFound","details":[{"code":"Forbidden"}]}}"""
        };
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "denied-authority" } };
        var window = f.Collector.ArmStatusDeniedPrivateConnectionDelete(binding, R.StatusDeniedPrivateConnectionDeleteReadPhase.SelectedState);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedPrivateConnectionDeleteRead(window, binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("id")]
    [Arguments("endpoint")]
    [Arguments("approval")]
    [Arguments("approved")]
    [Arguments("state")]
    public async Task StatusDeniedPrivateConnectionDeleteResourceBaselineRequiresFullOwnedNativeConfiguration(string fault)
    {
        using var f = new Fixture("DeletePrivateConnection");
        ConfigureDeniedPrivateDeleteResource(f, "Baseline");
        var body = JsonNode.Parse(f.Body)!;
        switch (fault)
        {
            case "id": body["id"] = f.Path + "-foreign"; break;
            case "endpoint": body["properties"]!.AsObject().Remove("privateEndpoint"); break;
            case "approval": body["properties"]!["privateLinkServiceConnectionState"]!["status"] = "Future"; break;
            case "approved": body["properties"]!["privateLinkServiceConnectionState"]!["status"] = "Approved"; break;
            default: body["properties"]!["provisioningState"] = "Future"; break;
        }
        f.Body = body.ToJsonString();
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "denied-authority" } };
        var window = f.Collector.ArmStatusDeniedPrivateConnectionDelete(binding, R.StatusDeniedPrivateConnectionDeleteReadPhase.Baseline);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedPrivateConnectionDeleteRead(window, binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("Azure-AsyncOperation")]
    [Arguments("Retry-After")]
    [Arguments("Content-Range")]
    public async Task StatusDeniedPrivateConnectionDeleteResourceRejectsContinuationOrPartialMetadata(string header)
    {
        using var f = new Fixture("DeletePrivateConnection");
        ConfigureDeniedPrivateDeleteResource(f, "Baseline");
        f.Headers.Add((header, header == "Retry-After" ? "1" : header == "Content-Range" ? "bytes 0-1/2" :
            "https://management.azure.com" + f.Path + "?api-version=2026-02-01"));
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "denied-authority" } };
        var window = f.Collector.ArmStatusDeniedPrivateConnectionDelete(binding, R.StatusDeniedPrivateConnectionDeleteReadPhase.Baseline);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusDeniedPrivateConnectionDeleteRead(window, binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    private static void ConfigureDeniedPrivateDeleteResource(Fixture f, string phase)
    {
        f.Status = phase is "Baseline" or "Discovery" ? 200 : 404;
        if (phase is not ("Baseline" or "Discovery")) { f.Body = """{"error":{"code":"ResourceNotFound"}}"""; return; }
        var body = JsonNode.Parse(f.Body)!;
        body["properties"]!["provisioningState"] = "Succeeded";
        body["properties"]!["privateLinkServiceConnectionState"]!["status"] = "Pending";
        body["properties"]!["privateEndpoint"] = new JsonObject
        {
            ["id"] = "/subscriptions/" + Subscription +
                "/resourceGroups/resource-group/providers/Microsoft.Network/privateEndpoints/resource-endpoint"
        };
        f.Body = body.ToJsonString();
    }
}
