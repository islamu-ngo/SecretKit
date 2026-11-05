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
    [Arguments("prerequisites", "preparation")]
    [Arguments("native", "job")]
    [Arguments("native", "harness")]
    [Arguments("compatibility", "measured_install")]
    [Arguments("archive_evidence", "job")]
    [Arguments("candidate", "runner")]
    [Arguments("candidate", "collect")]
    public async Task ProtectedStepsRejectAdditionalExecutableCommands(string job, string step)
    {
        JsonNode root = JsonNode.Parse(File.ReadAllBytes(Workflow()))!;
        Step(root["jobs"]![job]!, step)["run"] += "\nprintf extra-executable-command";

        await Assert.That(() => WorkflowPolicy.ValidateProducer(JsonSerializer.SerializeToUtf8Bytes(root)))
            .Throws<ReleaseException>();
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task RequiredWindowsDemoOutcomeControlsActualCandidateAssembly(bool windowsPassed)
    {
        JsonNode workflow = JsonNode.Parse(File.ReadAllBytes(Workflow()))!;
        using var bundle = new TestBundle();
        DateTimeOffset now = TestBundle.RunStart.AddMinutes(11);
        bundle.WriteRun("in_progress", null);
        File.Delete(Path.Combine(bundle.OracleRoot, "artifact-metadata.json"));
        bundle.Write("candidate-inputs.json", new CandidateInputs(1, "candidate-inputs-not-approved", 1,
            bundle.Data with { Gates = [] }));
        File.Copy(Path.Combine(bundle.OracleRoot, "THIRD-PARTY-NOTICES.md"),
            Path.Combine(bundle.Root, "THIRD-PARTY-NOTICES.md"));
        ReportOrigin origin = bundle.Index.Reports.First(report => report.Kind == "native-operations");
        MachineReport report = Manifest.Parse<MachineReport>(
            File.ReadAllBytes(Path.Combine(bundle.OracleRoot, origin.Report.File)));
        string preparation = Path.Combine(bundle.Root, "preparation");
        string candidate = Path.Combine(bundle.Root, "candidate");
        Directory.CreateDirectory(preparation);
        File.WriteAllBytes(Path.Combine(preparation, "preparation.json"), JsonSerializer.SerializeToUtf8Bytes(
            new CandidatePreparation(1, TestBundle.Commit, 12, 1, bundle.Data.Scope.Sha256, "setup-owner", "reviewer",
                TestBundle.RunStart.AddMinutes(6), now.AddDays(120), report.Prerequisites, bundle.Index.Attestations),
            Manifest.JsonOptions));
        foreach (ReportOrigin item in bundle.Index.Reports)
        {
            string artifact = Path.Combine(bundle.OracleRoot, $"{item.ArtifactId}-artifact.json");
            JsonNode metadata = JsonNode.Parse(File.ReadAllBytes(artifact))!;
            metadata["expires_at"] = now.AddDays(120);
            File.WriteAllText(artifact, metadata.ToJsonString());
        }
        // Offline fixture of GitHub's required-job semantics, not a CI observation:
        // the Linux demo passed, but one failed Windows matrix child fails demos.
        var outcomes = workflow["jobs"]!.AsObject().ToDictionary(pair => pair.Key, _ => true);
        outcomes["demos"] = new[] { true, windowsPassed }.All(success => success);
        bool admitted = workflow["jobs"]!["candidate"]!["needs"]!.AsArray()
            .All(dependency => outcomes[dependency!.GetValue<string>()]);

        if (admitted)
            Candidate.Assemble(bundle.Root, bundle.OracleRoot, preparation, candidate, now);

        await Assert.That(File.Exists(Path.Combine(candidate, "manifest.json"))).IsEqualTo(windowsPassed);
        if (windowsPassed)
        {
            Manifest.CheckCandidate(candidate, new IndependentEvidence(bundle.OracleRoot));
            await Assert.That(Directory.GetFiles(candidate, "*.nupkg").Length).IsEqualTo(7);
        }
    }

    [Test]
    public async Task NativeHarnessFileGuardsResolveInTheCheckout()
    {
        string workflow = Workflow();
        JsonNode root = JsonNode.Parse(File.ReadAllText(workflow))!;
        string script = Step(root["jobs"]!["native"]!, "harness")["run"]!.GetValue<string>();
        string[] files = script.Split('\n')
            .Where(line => line.StartsWith("test -f tests/", StringComparison.Ordinal))
            .Select(line => line.Split(' ')[2]).ToArray();
        await Assert.That(files.Length).IsGreaterThan(0);
        string checkout = Path.GetFullPath("../..", Path.GetDirectoryName(workflow)!);
        foreach (string file in files)
            await Assert.That(File.Exists(Path.Combine(checkout, file))).IsTrue();
    }

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
