using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecretKit.Release.Tests;

public sealed class ProducerWorkflowTests
{
    private static string Workflow()
    {
        DirectoryInfo? root = new(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "SecretKit.slnx")))
            root = root.Parent;
        return Path.Combine(root?.FullName ?? throw new InvalidOperationException(), ".github/workflows/verify.yml");
    }

    [Test]
    public void ProtectedProducerHasAllCurrentRunDependencies() =>
        WorkflowPolicy.ValidateProducer(File.ReadAllBytes(Workflow()));

    [Test]
    [Arguments("dispatch")]
    [Arguments("pr")]
    [Arguments("permission")]
    [Arguments("no-native")]
    [Arguments("no-preparation")]
    [Arguments("unprotected")]
    [Arguments("self-index")]
    [Arguments("old-artifact")]
    [Arguments("short-retention")]
    [Arguments("ignored-failure")]
    [Arguments("missing-windows")]
    [Arguments("no-live-kind")]
    [Arguments("native-exclusion")]
    [Arguments("report-name")]
    [Arguments("unchecked-upload")]
    [Arguments("routine-secret")]
    public async Task UnsafeProducerBranchesAreRejected(string fault)
    {
        JsonNode root = JsonNode.Parse(File.ReadAllText(Workflow()))!;
        JsonNode jobs = root["jobs"]!;
        JsonNode candidate = jobs["candidate"]!;
        switch (fault)
        {
            case "dispatch": root["on"]!["workflow_dispatch"] = new JsonObject(); break;
            case "pr": candidate["if"] = "${{ github.event_name == 'pull_request' }}"; break;
            case "permission": jobs["native"]!["permissions"]!["id-token"] = "write"; break;
            case "no-native":
                candidate["needs"]!.AsArray().Remove(candidate["needs"]!.AsArray()
                    .Single(n => n!.GetValue<string>() == "native"));
                break;
            case "no-preparation":
                jobs["native"]!["needs"]!.AsArray().Remove(jobs["native"]!["needs"]!.AsArray()
                    .Single(n => n!.GetValue<string>() == "prerequisites"));
                break;
            case "unprotected": candidate["environment"] = "release-evidence"; break;
            case "self-index":
                Step(candidate, "collect")["env"]!["SECRETKIT_REVIEWED_EVIDENCE_INDEX"] = "${{ steps.collect.outputs.index }}";
                break;
            case "old-artifact":
                jobs["native"]!["steps"]!.AsArray().Single(s => s?["with"]?["path"]?.GetValue<string>() == "inputs")!
                    ["with"]!["name"] = "latest";
                break;
            case "short-retention": Step(candidate, "candidate_upload")["with"]!["retention-days"] = 14; break;
            case "ignored-failure": Step(jobs["native"]!, "harness")["continue-on-error"] = true; break;
            case "missing-windows": jobs["compatibility"]!["strategy"]!["matrix"]!["include"]!.AsArray().RemoveAt(1); break;
            case "no-live-kind": jobs["native"]!["strategy"]!["matrix"]!["kind"]!.AsArray().RemoveAt(1); break;
            case "native-exclusion":
                jobs["native"]!["strategy"]!["matrix"]!["exclude"]!.AsArray()
                    .Add(new JsonObject { ["platform"] = "windows-x64-net10.0" });
                break;
            case "report-name":
                jobs["compatibility"]!["steps"]!.AsArray().Last()!["with"]!["name"] = "offline";
                break;
            case "unchecked-upload": Step(candidate, "content")["run"] = "true"; break;
            case "routine-secret":
                jobs["offline"]!["env"]!["NUGET_API_KEY"] = "${{ secrets.NUGET_API_KEY }}";
                break;
        }
        if (fault == "routine-secret")
        {
            string[] hosts = jobs["offline"]!["env"]!["SECRETKIT_TEST_HOSTS"]!.GetValue<string>().Split(' ');
            await Assert.That(() => WorkflowPolicy.ValidateRoutine(JsonSerializer.SerializeToUtf8Bytes(root), hosts))
                .Throws<ReleaseException>();
        }
        else
            await Assert.That(() => WorkflowPolicy.ValidateProducer(JsonSerializer.SerializeToUtf8Bytes(root)))
                .Throws<ReleaseException>();
    }

    private static JsonNode Step(JsonNode job, string id) =>
        job["steps"]!.AsArray().Single(s => s?["id"]?.GetValue<string>() == id)!;
}
