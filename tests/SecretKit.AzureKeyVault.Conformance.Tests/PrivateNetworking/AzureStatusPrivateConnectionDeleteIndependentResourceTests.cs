using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using R = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationResourceCollectorTests
{
    [Test]
    [Arguments("Baseline")]
    [Arguments("SelectedState")]
    [Arguments("Cleanup")]
    public async Task StatusPrivateDeleteIndependentResourceProofRequiresActualTaskAndPhase(string phaseName)
    {
        using var f = new Fixture("DeletePrivateConnection");
        var phase = Enum.Parse<R.StatusPrivateConnectionDeleteIndependentReadPhase>(phaseName);
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "independent-effect" } };
        ConfigurePrivateDeleteIndependentResource(f, phaseName);
        var window = f.Collector.ArmStatusPrivateConnectionDeleteIndependent(binding, phase);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusPrivateConnectionDeleteIndependentRead(window, binding, task, out var proof)).IsTrue();
        await Assert.That(proof!.Phase).IsEqualTo(phase);
        await Assert.That(f.Collector.OwnsStatusPrivateConnectionDeleteIndependentRead(proof, window, binding, task)).IsTrue();
        var copied = new TaskCompletionSource<R.Measurement>(TaskCreationOptions.RunContinuationsAsynchronously);
        copied.SetResult(measured);
        await Assert.That(f.Collector.TryGetStatusPrivateConnectionDeleteIndependentRead(window, binding, copied.Task, out _)).IsFalse();
        await Assert.That(f.Collector.TryGetStatusPrivateConnectionDeleteIndependentRead(window, binding with { }, task, out _)).IsFalse();
        using var other = new Fixture("DeletePrivateConnection");
        await Assert.That(other.Collector.OwnsStatusPrivateConnectionDeleteIndependentRead(proof, window, binding, task)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task StatusPrivateDeleteIndependentRawResourceInstrumentationCannotIssueProof()
    {
        using var f = new Fixture("DeletePrivateConnection");
        ConfigurePrivateDeleteIndependentResource(f, "Baseline");
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "independent-effect" } };
        var window = f.Collector.Arm(binding);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusPrivateConnectionDeleteIndependentRead(window, binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("empty")]
    [Arguments("malformed")]
    [Arguments("forbidden")]
    [Arguments("contradictory")]
    public async Task StatusPrivateDeleteIndependentResourceAbsenceRequiresActualNativeError(string fault)
    {
        using var f = new Fixture("DeletePrivateConnection");
        ConfigurePrivateDeleteIndependentResource(f, "SelectedState");
        f.Body = fault switch
        {
            "empty" => "",
            "malformed" => "{",
            "forbidden" => """{"error":{"code":"Forbidden"}}""",
            _ => """{"error":{"code":"ResourceNotFound","details":[{"code":"Forbidden"}]}}"""
        };
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "independent-effect" } };
        var window = f.Collector.ArmStatusPrivateConnectionDeleteIndependent(binding, R.StatusPrivateConnectionDeleteIndependentReadPhase.SelectedState);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusPrivateConnectionDeleteIndependentRead(window, binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("id")]
    [Arguments("endpoint")]
    [Arguments("approval")]
    [Arguments("approved")]
    [Arguments("state")]
    public async Task StatusPrivateDeleteIndependentResourceBaselineRequiresFullOwnedNativeConfiguration(string fault)
    {
        using var f = new Fixture("DeletePrivateConnection");
        ConfigurePrivateDeleteIndependentResource(f, "Baseline");
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
        var window = f.Collector.ArmStatusPrivateConnectionDeleteIndependent(binding, R.StatusPrivateConnectionDeleteIndependentReadPhase.Baseline);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusPrivateConnectionDeleteIndependentRead(window, binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("Azure-AsyncOperation")]
    [Arguments("Retry-After")]
    [Arguments("Content-Range")]
    public async Task StatusPrivateDeleteIndependentResourceRejectsContinuationOrPartialMetadata(string header)
    {
        using var f = new Fixture("DeletePrivateConnection");
        ConfigurePrivateDeleteIndependentResource(f, "Baseline");
        f.Headers.Add((header, header == "Retry-After" ? "1" : header == "Content-Range" ? "bytes 0-1/2" :
            "https://management.azure.com" + f.Path + "?api-version=2026-02-01"));
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "independent-effect" } };
        var window = f.Collector.ArmStatusPrivateConnectionDeleteIndependent(binding, R.StatusPrivateConnectionDeleteIndependentReadPhase.Baseline);
        var task = f.Collector.CollectAsync(window, binding).AsTask();
        using var measured = await task;
        await Assert.That(f.Collector.TryGetStatusPrivateConnectionDeleteIndependentRead(window, binding, task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    private static void ConfigurePrivateDeleteIndependentResource(Fixture f, string phase)
    {
        f.Status = phase == "Baseline" ? 200 : 404;
        if (phase != "Baseline") { f.Body = """{"error":{"code":"ResourceNotFound"}}"""; return; }
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
