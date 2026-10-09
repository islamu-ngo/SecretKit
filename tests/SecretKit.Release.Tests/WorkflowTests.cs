using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class WorkflowTests
{
    [Test]
    public async Task ActualWorkflowIsOfflineParseableAndSatisfiesAuthorityPolicy()
    {
        byte[] bytes = await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory, "publish.yml"));
        WorkflowPolicy.Validate(bytes);
        using JsonDocument document = JsonDocument.Parse(bytes);
        await Assert.That(document.RootElement.GetProperty("jobs").EnumerateObject().Count()).IsEqualTo(2);
    }

    [Test]
    [Arguments("pull-request")]
    [Arguments("global-token")]
    [Arguments("environment")]
    [Arguments("floating-action")]
    [Arguments("rebuild")]
    [Arguments("checkpoint")]
    [Arguments("checkout-credentials")]
    [Arguments("ignore-failure")]
    [Arguments("artifact-source")]
    [Arguments("execute-flag")]
    [Arguments("login-endpoint")]
    public async Task UnsafeWorkflowMachineValuesAreRejected(string fault)
    {
        JsonNode root = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "publish.yml")))!;
        JsonNode publish = root["jobs"]!["publish"]!;
        switch (fault)
        {
            case "pull-request": root["on"]!["pull_request"] = new JsonObject(); break;
            case "global-token": root["permissions"]!["id-token"] = "write"; break;
            case "environment": publish["environment"] = "unprotected"; break;
            case "floating-action": root["jobs"]!["verify"]!["steps"]![0]!["uses"] = "actions/checkout@v4"; break;
            case "checkout-credentials": root["jobs"]!["verify"]!["steps"]![0]!["with"]!["persist-credentials"] = true; break;
            case "rebuild": publish["steps"]!.AsArray().Add(new JsonObject { ["run"] = "dotnet pack" }); break;
            case "checkpoint":
                JsonNode step = publish["steps"]!.AsArray().Single(s => s?["id"]?.GetValue<string>() == "before_0")!;
                step["if"] = "${{ false }}";
                break;
            case "ignore-failure": publish["steps"]![0]!["continue-on-error"] = true; break;
            case "artifact-source":
                publish["steps"]!.AsArray().Single(s => s?["id"]?.GetValue<string>() == "artifact_download")!
                    ["with"]!["repository"] = "fork/SecretKit";
                break;
            case "execute-flag": publish["env"]!["SECRETKIT_EXECUTE"] = "true"; break;
            case "login-endpoint":
                publish["steps"]!.AsArray().Single(s => s?["id"]?.GetValue<string>() == "login")!
                    ["with"]!["token-service-url"] = "https://example.invalid";
                break;
        }

        await Assert.That(() => WorkflowPolicy.Validate(JsonSerializer.SerializeToUtf8Bytes(root)))
            .Throws<ReleaseException>();
    }

    [Test]
    public async Task SourceRunMustBeSuccessfulSameRepositoryMainPush()
    {
        using var bundle = new TestBundle();
        bundle.Write("artifact-metadata.json", new
        {
            id = 34,
            expired = false,
            digest = "sha256:" + bundle.Approval.ArtifactDigest,
            workflow_run = new { id = 12, head_sha = TestBundle.Commit }
        });
        var run = new
        {
            id = 12,
            head_sha = TestBundle.Commit,
            head_branch = "main",
            @event = "push",
            status = "completed",
            conclusion = "success",
            path = ".github/workflows/verify.yml",
            repository = new { full_name = Manifest.RepositoryName },
            head_repository = new { full_name = Manifest.RepositoryName }
        };
        bundle.Write("run-metadata.json", run);
        Program.VerifyArtifactMetadata(bundle.Root, bundle.Approval);
        bundle.Write("run-metadata.json", run with { @event = "pull_request" });
        await Assert.That(() => Program.VerifyArtifactMetadata(bundle.Root, bundle.Approval)).Throws<ReleaseException>();
        bundle.Write("run-metadata.json", run with { head_repository = new { full_name = "fork/SecretKit" } });
        await Assert.That(() => Program.VerifyArtifactMetadata(bundle.Root, bundle.Approval)).Throws<ReleaseException>();
    }
}
