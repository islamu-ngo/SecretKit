using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class WorkflowTests
{
    private static string RepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "SecretKit.slnx")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Repository root unavailable.");
    }

    private static string[] OfflineHosts()
    {
        string root = RepositoryRoot();
        return XDocument.Load(Path.Combine(root, "SecretKit.slnx")).Descendants("Project")
            .Select(p => p.Attribute("Path")!.Value)
            .Where(p => p.StartsWith("tests/", StringComparison.Ordinal))
            .Select(Path.GetFileNameWithoutExtension).Select(p => p!).ToArray();
    }

    [Test]
    public async Task RoutineWorkflowIncludesEveryOfflineHostWithoutReleaseAuthority()
    {
        byte[] bytes = await File.ReadAllBytesAsync(Path.Combine(RepositoryRoot(), ".github", "workflows", "verify.yml"));
        WorkflowPolicy.ValidateRoutine(bytes, OfflineHosts());
    }

    [Test]
    [Arguments("omitted-host")]
    [Arguments("zero-discovery")]
    [Arguments("unsafe-authority")]
    [Arguments("wrong-order")]
    [Arguments("release-purpose")]
    [Arguments("ignored-failure")]
    [Arguments("missing-platform")]
    [Arguments("repacked-install")]
    [Arguments("wrong-artifact")]
    public async Task RoutineWorkflowRejectsMissingCoverageAndPromotion(string fault)
    {
        JsonNode root = JsonNode.Parse(await File.ReadAllTextAsync(
            Path.Combine(RepositoryRoot(), ".github", "workflows", "verify.yml")))!;
        JsonNode offline = root["jobs"]!["offline"]!;
        JsonArray steps = offline["steps"]!.AsArray();
        JsonNode Step(string id) => steps.Single(s => s?["id"]?.GetValue<string>() == id)!;
        switch (fault)
        {
            case "omitted-host": offline["env"]!["SECRETKIT_TEST_HOSTS"] = "SecretKit.Core.Tests"; break;
            case "zero-discovery":
                Step("tests")["run"] = Step("tests")["run"]!.GetValue<string>()
                    .Replace("--minimum-expected-tests 1", "", StringComparison.Ordinal);
                break;
            case "unsafe-authority": root["permissions"]!["id-token"] = "write"; break;
            case "wrong-order":
                JsonNode pack = Step("pack");
                steps.Remove(pack);
                steps.Add(pack);
                break;
            case "release-purpose": Step("metadata")["env"]!["PURPOSE"] = "release-ready"; break;
            case "ignored-failure": Step("tests")["continue-on-error"] = true; break;
            case "missing-platform":
                root["jobs"]!["install"]!["strategy"]!["matrix"]!["include"]!.AsArray().RemoveAt(1);
                break;
            case "repacked-install":
                root["jobs"]!["install"]!["steps"]!.AsArray()
                    .Single(s => s?["id"]?.GetValue<string>() == "test")!["run"] = "dotnet pack\n--minimum-expected-tests 27";
                break;
            case "wrong-artifact":
                root["jobs"]!["install"]!["steps"]!.AsArray()
                    .Single(s => s?["uses"]?.GetValue<string>().StartsWith("actions/download-artifact@", StringComparison.Ordinal) == true)!
                    ["with"]!["name"] = "unbound-originals";
                break;
        }

        await Assert.That(() => WorkflowPolicy.ValidateRoutine(JsonSerializer.SerializeToUtf8Bytes(root), OfflineHosts()))
            .Throws<ReleaseException>();
    }

    [Test]
    public async Task ActualWorkflowIsOfflineParseableAndSatisfiesAuthorityPolicy()
    {
        byte[] bytes = await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory, "publish.yml"));
        WorkflowPolicy.Validate(bytes);
        using JsonDocument document = JsonDocument.Parse(bytes);
        await Assert.That(document.RootElement.GetProperty("jobs").EnumerateObject().Count()).IsEqualTo(3);
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
    [Arguments("observation-token")]
    [Arguments("observation-login")]
    [Arguments("observation-dispatch")]
    [Arguments("missing-original-hash")]
    [Arguments("missing-action-hash")]
    [Arguments("wrong-package")]
    [Arguments("recovered-dispatch")]
    [Arguments("initializing-publish")]
    [Arguments("missing-producer-job")]
    [Arguments("missing-checkpoint-proof")]
    [Arguments("login-before-proof")]
    [Arguments("mutable-head")]
    [Arguments("missing-mode")]
    [Arguments("extra-dispatch")]
    [Arguments("action-on-observation")]
    [Arguments("skipped-verification")]
    [Arguments("key-before-validation")]
    [Arguments("missing-result")]
    [Arguments("wrong-checkpoint-name")]
    public async Task UnsafeWorkflowMachineValuesAreRejected(string fault)
    {
        JsonNode root = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "publish.yml")))!;
        JsonNode publish = root["jobs"]!["publish_one"]!;
        JsonNode observe = root["jobs"]!["observe"]!;
        JsonArray steps = publish["steps"]!.AsArray();
        JsonNode Step(string id) => steps.Single(s => s?["id"]?.GetValue<string>() == id)!;
        switch (fault)
        {
            case "pull-request": root["on"]!["pull_request"] = new JsonObject(); break;
            case "global-token": root["permissions"]!["id-token"] = "write"; break;
            case "environment": publish["environment"] = "unprotected"; break;
            case "floating-action": root["jobs"]!["verify"]!["steps"]![0]!["uses"] = "actions/checkout@v4"; break;
            case "checkout-credentials": root["jobs"]!["verify"]!["steps"]![0]!["with"]!["persist-credentials"] = true; break;
            case "rebuild": steps.Add(new JsonObject { ["run"] = "dotnet pack" }); break;
            case "checkpoint": Step("before")["if"] = "${{ false }}"; break;
            case "ignore-failure": steps[0]!["continue-on-error"] = true; break;
            case "artifact-source": Step("artifact_download")["with"]!["repository"] = "fork/SecretKit"; break;
            case "execute-flag": publish["env"]!["SECRETKIT_EXECUTE"] = "true"; break;
            case "login-endpoint": Step("login")["with"]!["token-service-url"] = "https://example.invalid"; break;
            case "observation-token": observe["permissions"] = new JsonObject { ["id-token"] = "write" }; break;
            case "observation-login": observe["steps"]!.AsArray().Add(Step("login").DeepClone()); break;
            case "observation-dispatch": observe["steps"]!.AsArray().Add(Step("dispatch").DeepClone()); break;
            case "missing-original-hash": publish["env"]!.AsObject().Remove("SECRETKIT_APPROVED_ORIGINAL_ADMISSION_SHA256"); break;
            case "missing-action-hash": publish["env"]!.AsObject().Remove("SECRETKIT_APPROVED_ACTION_AUTHORIZATION_SHA256"); break;
            case "wrong-package": Step("prepare")["env"]!["PACKAGE_ID"] = "SecretKit.Core"; break;
            case "recovered-dispatch": Step("dispatch")["if"] = "${{ inputs.journal_artifact_id != '' }}"; break;
            case "initializing-publish": steps.Add(new JsonObject { ["id"] = "initialize", ["run"] = "dotnet runner/SecretKit.Release.dll initialize bundle journal" }); break;
            case "missing-producer-job": Step("producer_job")["run"] = "true"; break;
            case "missing-checkpoint-proof": Step("dispatch")["env"]!.AsObject().Remove("SECRETKIT_CHECKPOINT_METADATA_FILE"); break;
            case "login-before-proof":
                JsonNode login = Step("login");
                steps.Remove(login);
                steps.Insert(0, login);
                break;
            case "mutable-head": Step("prepare")["run"] += "\necho SECRETKIT_APPROVED_JOURNAL_HEAD=new >> \"$GITHUB_ENV\""; break;
            case "missing-mode": root["on"]!["workflow_dispatch"]!["inputs"]!.AsObject().Remove("mode"); break;
            case "extra-dispatch": steps.Add(Step("dispatch").DeepClone()); break;
            case "action-on-observation": observe["env"]!["SECRETKIT_ACTION_AUTHORIZATION_FILE"] = "action.json"; break;
            case "skipped-verification": Step("verify_artifacts")["if"] = "${{ false }}"; break;
            case "key-before-validation":
                Step("prepare")["env"]!["NUGET_API_KEY"] = "${{ steps.login.outputs.NUGET_API_KEY }}";
                break;
            case "missing-result": Step("after")["if"] = "${{ false }}"; break;
            case "wrong-checkpoint-name": Step("before")["with"]!["name"] = "recovered-checkpoint"; break;
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
