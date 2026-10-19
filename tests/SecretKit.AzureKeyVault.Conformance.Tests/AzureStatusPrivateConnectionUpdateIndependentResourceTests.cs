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
    [Arguments("BeforeEndpointDelete")]
    [Arguments("Cleanup")]
    public async Task StatusPrivateUpdateIndependentResourceProofRequiresActualTaskAndPhase(string phaseName)
    {
        using var f = new Fixture("UpdatePrivateConnection");
        var phase = Enum.Parse<R.StatusPrivateConnectionUpdateIndependentReadPhase>(phaseName);
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "independent-effect" } };
        ConfigurePrivateUpdateIndependentResource(f, phaseName);
        var window = f.Collector.ArmStatusPrivateConnectionUpdateIndependent(binding, phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusPrivateConnectionUpdateIndependentRead(window, binding, task, out var proof)).IsTrue();
        await Assert.That(proof!.Phase).IsEqualTo(phase);
        await Assert.That(f.Collector.OwnsStatusPrivateConnectionUpdateIndependentRead(proof, window, binding, task)).IsTrue();
        var copied = new TaskCompletionSource<R.Measurement>(TaskCreationOptions.RunContinuationsAsynchronously);
        copied.SetResult(measured);
        await Assert.That(f.Collector.TryGetStatusPrivateConnectionUpdateIndependentRead(window, binding, copied.Task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusPrivateConnectionUpdateIndependentRead(window, binding with { }, task, out _)).IsFalse();
        using var other = new Fixture("UpdatePrivateConnection");
        await Assert.That(other.Collector.OwnsStatusPrivateConnectionUpdateIndependentRead(proof, window, binding, task)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task StatusPrivateUpdateIndependentRawResourceInstrumentationCannotIssueProof()
    {
        using var f = new Fixture("UpdatePrivateConnection");
        ConfigurePrivateUpdateIndependentResource(f, "Baseline");
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "independent-effect" } };
        var window = f.Collector.Arm(binding);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusPrivateConnectionUpdateIndependentRead(window, binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("empty")]
    [Arguments("malformed")]
    [Arguments("forbidden")]
    [Arguments("contradictory")]
    public async Task StatusPrivateUpdateIndependentResourceAbsenceRequiresActualNativeError(string fault)
    {
        using var f = new Fixture("UpdatePrivateConnection");
        ConfigurePrivateUpdateIndependentResource(f, "Cleanup");
        f.Body = fault switch
        {
            "empty" => "",
            "malformed" => "{",
            "forbidden" => """{"error":{"code":"Forbidden"}}""",
            _ => """{"error":{"code":"ResourceNotFound","details":[{"code":"Forbidden"}]}}"""
        };
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "independent-effect" } };
        var window = f.Collector.ArmStatusPrivateConnectionUpdateIndependent(binding, R.StatusPrivateConnectionUpdateIndependentReadPhase.Cleanup);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusPrivateConnectionUpdateIndependentRead(window, binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("id")]
    [Arguments("endpoint")]
    [Arguments("approval")]
    [Arguments("approved")]
    [Arguments("state")]
    public async Task StatusPrivateUpdateIndependentResourceBaselineRequiresFullOwnedNativeConfiguration(string fault)
    {
        using var f = new Fixture("UpdatePrivateConnection");
        ConfigurePrivateUpdateIndependentResource(f, "Baseline");
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
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "independent-effect" } };
        var window = f.Collector.ArmStatusPrivateConnectionUpdateIndependent(binding, R.StatusPrivateConnectionUpdateIndependentReadPhase.Baseline);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusPrivateConnectionUpdateIndependentRead(window, binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("Azure-AsyncOperation")]
    [Arguments("Retry-After")]
    [Arguments("Content-Range")]
    public async Task StatusPrivateUpdateIndependentResourceRejectsContinuationOrPartialMetadata(string header)
    {
        using var f = new Fixture("UpdatePrivateConnection");
        ConfigurePrivateUpdateIndependentResource(f, "Baseline");
        f.Headers.Add((header, header == "Retry-After" ? "1" : header == "Content-Range" ? "bytes 0-1/2" :
            "https://management.azure.com" + f.Path + "?api-version=2026-02-01"));
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "independent-effect" } };
        var window = f.Collector.ArmStatusPrivateConnectionUpdateIndependent(binding, R.StatusPrivateConnectionUpdateIndependentReadPhase.Baseline);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusPrivateConnectionUpdateIndependentRead(window, binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    private static void ConfigurePrivateUpdateIndependentResource(Fixture f, string phase)
    {
        f.Status = phase == "Cleanup" ? 404 : 200;
        if (phase == "Cleanup") { f.Body = """{"error":{"code":"NotFound"}}"""; return; }
        var body = JsonNode.Parse(f.Body)!;
        body["properties"]!["provisioningState"] = "Succeeded";
        body["properties"]!["privateLinkServiceConnectionState"]!["status"] =
            phase is "Discovery" or "Baseline" ? "Pending" : "Approved";
        body["properties"]!["privateEndpoint"] = new JsonObject
        {
            ["id"] = "/subscriptions/" + Subscription +
                "/resourceGroups/resource-group/providers/Microsoft.Network/privateEndpoints/resource-endpoint"
        };
        f.Body = body.ToJsonString();
    }
}
