using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class DependencyAuditTests
{
    [Test]
    [NotInParallel]
    [Arguments(false)]
    [Arguments(true)]
    public async Task InstalledGraphCollectorBindsIsolatedAssetsAndCannotReplaceRecordedBytes(bool substitute)
    {
        string directory = Path.Combine(Path.GetTempPath(), "secretkit-installed-audit-" + Guid.NewGuid().ToString("N"));
        string? previous = Environment.GetEnvironmentVariable("SECRETKIT_DEPENDENCY_AUDIT_GRAPHS");
        Directory.CreateDirectory(directory);
        try
        {
            string project = Path.Combine(directory, "SecretKit.InfisicalConsumer.csproj");
            string intermediate = Path.Combine(directory, "isolated-obj");
            string reports = Path.Combine(directory, "graphs");
            Directory.CreateDirectory(intermediate);
            File.WriteAllText(project, "<Project Sdk=\"Microsoft.NET.Sdk\" />");
            string assetsPath = Path.Combine(intermediate, "project.assets.json");
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new
            {
                libraries = new Dictionary<string, object>
                {
                    ["SecretKit.Core/0.2.0"] = new { type = "package" },
                    ["SecretKit.Infisical/0.2.0"] = new { type = "package" },
                    ["SecretKit.Extensions.Hosting/0.2.0"] = new { type = "package" }
                },
                project = new
                {
                    restore = new
                    {
                        projectPath = project,
                        packagesPath = Path.Combine(directory, "cache"),
                        outputPath = intermediate + Path.DirectorySeparatorChar,
                        frameworks = new Dictionary<string, object>
                        {
                            ["net10.0"] = new { projectReferences = new { } }
                        }
                    }
                }
            });
            File.WriteAllBytes(assetsPath, bytes);
            using var assets = JsonDocument.Parse(bytes);
            Environment.SetEnvironmentVariable("SECRETKIT_DEPENDENCY_AUDIT_GRAPHS", reports);
            DependencyAudit.RecordInstalledGraph(assetsPath, assets.RootElement);
            string selected = Directory.GetFiles(reports).Single();
            byte[] original = File.ReadAllBytes(selected);
            var graph = Manifest.Parse<InstalledAuditGraph>(original);
            await Assert.That(graph.Assets).IsEqualTo(assetsPath);
            await Assert.That(graph.Project).IsEqualTo(project);
            await Assert.That(graph.Mode).IsEqualTo("hosting");
            await Assert.That(graph.Version).IsEqualTo("0.2.0");
            await Assert.That(graph.Files.Single(file => file.File == assetsPath).Sha256).IsEqualTo(Manifest.Hash(bytes));
            if (substitute)
            {
                File.AppendAllText(project, "<!-- substituted -->");
                await Assert.That(() => DependencyAudit.RecordInstalledGraph(assetsPath, assets.RootElement))
                    .Throws<ReleaseException>();
            }
            else DependencyAudit.RecordInstalledGraph(assetsPath, assets.RootElement);
            await Assert.That(File.ReadAllBytes(selected).SequenceEqual(original)).IsTrue();
        }
        finally
        {
            Environment.SetEnvironmentVariable("SECRETKIT_DEPENDENCY_AUDIT_GRAPHS", previous);
            Directory.Delete(directory, recursive: true);
        }
    }

    [Test]
    [NotInParallel]
    [Arguments("graph")]
    [Arguments("receipt")]
    [Arguments("graph-and-receipt")]
    [Arguments("content")]
    [Arguments("extra-graph")]
    public async Task FinalizedGraphInventoryRejectsRemovedSubstitutedOrAddedInstallations(string defect)
    {
        string directory = Path.Combine(Path.GetTempPath(), "secretkit-audit-inventory-" + Guid.NewGuid().ToString("N"));
        string graphs = Path.Combine(directory, "graphs");
        string installations = Path.Combine(directory, "installations");
        Directory.CreateDirectory(graphs);
        Directory.CreateDirectory(installations);
        try
        {
            foreach (string name in new[] { "first.json", "second.json" })
            {
                string assets = Path.Combine(directory, name + ".assets");
                File.WriteAllText(assets, "{}");
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new InstalledAuditGraph(
                    Path.Combine(directory, "consumer.csproj"), assets, Path.Combine(directory, "packages"),
                    "0.2.0", "minimal", [new(assets, Manifest.Hash(File.ReadAllBytes(assets)))]), Manifest.JsonOptions);
                File.WriteAllBytes(Path.Combine(graphs, name), bytes);
                File.WriteAllBytes(Path.Combine(installations, name),
                    JsonSerializer.SerializeToUtf8Bytes(new FileDigest(name, Manifest.Hash(bytes)), Manifest.JsonOptions));
            }
            string cohort = new('a', 64);
            DependencyAudit.SealInstalledGraphs(directory, cohort, "linux-x64");
            await Assert.That(DependencyAudit.ValidateInstalledInventory(directory, cohort, "linux-x64").Length).IsEqualTo(2);
            switch (defect)
            {
                case "graph": File.Delete(Path.Combine(graphs, "first.json")); break;
                case "receipt": File.Delete(Path.Combine(installations, "first.json")); break;
                case "graph-and-receipt":
                    File.Delete(Path.Combine(graphs, "first.json"));
                    File.Delete(Path.Combine(installations, "first.json"));
                    break;
                case "content": File.AppendAllText(Path.Combine(graphs, "first.json"), " "); break;
                case "extra-graph": File.WriteAllText(Path.Combine(graphs, "extra.json"), "{}"); break;
            }
            await Assert.That(() => DependencyAudit.ValidateInstalledInventory(directory, cohort, "linux-x64"))
                .Throws<ReleaseException>();
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Test]
    public async Task GraphInventoryCannotSealAnInstallationWhoseAssetsWereDeleted()
    {
        string directory = Path.Combine(Path.GetTempPath(), "secretkit-deleted-graph-" + Guid.NewGuid().ToString("N"));
        string graphs = Path.Combine(directory, "graphs");
        string receipts = Path.Combine(directory, "installations");
        Directory.CreateDirectory(graphs);
        Directory.CreateDirectory(receipts);
        try
        {
            string assets = Path.Combine(directory, "project.assets.json");
            File.WriteAllText(assets, "{}");
            byte[] graph = JsonSerializer.SerializeToUtf8Bytes(new InstalledAuditGraph(
                Path.Combine(directory, "consumer.csproj"), assets, Path.Combine(directory, "packages"),
                "0.2.0", "minimal", [new(assets, Manifest.Hash(File.ReadAllBytes(assets)))]), Manifest.JsonOptions);
            File.WriteAllBytes(Path.Combine(graphs, "graph.json"), graph);
            File.WriteAllBytes(Path.Combine(receipts, "graph.json"),
                JsonSerializer.SerializeToUtf8Bytes(new FileDigest("graph.json", Manifest.Hash(graph)), Manifest.JsonOptions));
            File.Delete(assets);

            await Assert.That(() => DependencyAudit.SealInstalledGraphs(directory, new string('a', 64), "linux-x64"))
                .Throws<ReleaseException>();
            await Assert.That(File.Exists(Path.Combine(directory, "installed-graphs.json"))).IsFalse();
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private const string Source = "https://api.nuget.org/v3/index.json";
    private const string Advisory = "https://github.com/advisories/GHSA-2345-6789-abcd";
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-05T00:00:00Z");

    [Test]
    public async Task CleanCompleteNativeReportClearsOnlyTheSelectedGraph()
    {
        var fixture = new Fixture();
        var result = fixture.Evaluate();
        await Assert.That(result.Cleared).IsTrue();
        await Assert.That(result.Findings.Length).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NativeExitZeroDoesNotClearDirectOrTransitiveAdvisories(bool transitive)
    {
        var fixture = new Fixture();
        fixture.Vulnerable("first.csproj", "First.Package", transitive);
        var result = fixture.Evaluate();
        await Assert.That(result.Cleared).IsFalse();
        await Assert.That(result.Findings.Length).IsEqualTo(1);
        await Assert.That(result.Findings[0].Transitive).IsEqualTo(transitive);
    }

    [Test]
    [Arguments("missing-project")]
    [Arguments("extra-project")]
    [Arguments("duplicate-project")]
    [Arguments("unavailable")]
    [Arguments("wrong-source")]
    [Arguments("missing-source")]
    [Arguments("wrong-version")]
    [Arguments("missing-transitive")]
    [Arguments("empty-frameworks")]
    [Arguments("missing-frameworks")]
    [Arguments("foreign-framework")]
    [Arguments("unknown-severity")]
    [Arguments("wrong-package")]
    [Arguments("wrong-package-version")]
    [Arguments("empty-advisories")]
    public async Task IncompleteOrUntrustedReportNeverClears(string defect)
    {
        var fixture = new Fixture();
        fixture.Vulnerable("first.csproj", "First.Package");
        JsonArray projects = fixture.Report["projects"]!.AsArray();
        JsonObject first = projects[0]!.AsObject();
        JsonObject framework = first["frameworks"]![0]!.AsObject();
        JsonObject package = framework["topLevelPackages"]![0]!.AsObject();
        switch (defect)
        {
            case "missing-project": projects.RemoveAt(1); break;
            case "extra-project": projects.Add(new JsonObject { ["path"] = "foreign.csproj" }); break;
            case "duplicate-project": projects.Add(first.DeepClone()); break;
            case "unavailable": fixture.Report["logs"] = JsonNode.Parse("""[{"level":"Error","message":"data unavailable"}]"""); break;
            case "wrong-source": fixture.Report["sources"]![0] = "https://foreign.invalid/index.json"; break;
            case "missing-source": fixture.Report.Remove("sources"); break;
            case "wrong-version": fixture.Report["version"] = 2; break;
            case "missing-transitive": fixture.Report["parameters"] = "--vulnerable"; break;
            case "empty-frameworks": first["frameworks"] = new JsonArray(); break;
            case "missing-frameworks": first.AsObject().Remove("frameworks"); break;
            case "foreign-framework": framework["framework"] = "net9.0"; break;
            case "unknown-severity": package["vulnerabilities"]![0]!["severity"] = "Unrated"; break;
            case "wrong-package": package["id"] = "Unresolved.Package"; break;
            case "wrong-package-version": package["resolvedVersion"] = "9.9.9"; break;
            case "empty-advisories": package["vulnerabilities"] = new JsonArray(); break;
        }
        var result = fixture.Evaluate();
        await Assert.That(result.Cleared).IsFalse();
        await Assert.That(result.Failures.Any(code => code != "audit-vulnerable")).IsTrue();
    }

    [Test]
    [Arguments("")]
    [Arguments("{")]
    [Arguments("null")]
    [Arguments("""{"version":1,"version":1}""")]
    public async Task MalformedReportFailsEvenWhenNativeProcessSucceeded(string report)
    {
        var fixture = new Fixture();
        var result = fixture.Evaluate(Encoding.UTF8.GetBytes(report));
        await Assert.That(result.Cleared).IsFalse();
    }

    [Test]
    [Arguments("owner")]
    [Arguments("rationale")]
    [Arguments("evidence")]
    [Arguments("expired")]
    [Arguments("not-utc")]
    [Arguments("blanket")]
    [Arguments("wrong-project")]
    [Arguments("wrong-package")]
    [Arguments("wrong-version")]
    [Arguments("wrong-advisory")]
    [Arguments("duplicate")]
    [Arguments("unused")]
    public async Task ExceptionsMustBeOwnedCurrentAndExact(string defect)
    {
        var fixture = new Fixture();
        if (defect != "unused") fixture.Vulnerable("first.csproj", "First.Package");
        JsonObject exception = fixture.Exception();
        switch (defect)
        {
            case "owner" or "rationale" or "evidence": exception[defect] = ""; break;
            case "expired": exception["expiresAt"] = "2026-11-05T00:00:00Z"; break;
            case "not-utc": exception["expiresAt"] = "2026-11-06T01:00:00+01:00"; break;
            case "blanket": exception["package"] = "*"; break;
            case "wrong-project": exception["project"] = "second.csproj"; break;
            case "wrong-package": exception["package"] = "Second.Package"; break;
            case "wrong-version": exception["version"] = "2.0.0"; break;
            case "wrong-advisory": exception["advisory"] = "https://github.com/advisories/GHSA-abcd-2345-6789"; break;
            case "duplicate": fixture.Registry["exceptions"]!.AsArray().Add(exception.DeepClone()); break;
        }
        var result = fixture.Evaluate();
        await Assert.That(result.Cleared).IsFalse();
        await Assert.That(result.Failures).Contains("audit-exception");
    }

    [Test]
    public async Task ExactRiskRecordNeverWaivesVulnerableReportOrSharedAdvisory()
    {
        var fixture = new Fixture();
        fixture.Vulnerable("first.csproj", "First.Package");
        fixture.Vulnerable("second.csproj", "Second.Package", true);
        fixture.Exception();
        var result = fixture.Evaluate();
        await Assert.That(result.Cleared).IsFalse();
        await Assert.That(result.MatchedExceptions).IsEqualTo(1);
        await Assert.That(result.Findings.Select(f => f.Package)).IsEquivalentTo(new[] { "First.Package", "Second.Package" });
        await Assert.That(result.Failures).Contains("audit-vulnerable");
    }

    [Test]
    [Arguments("restore")]
    [Arguments("graph")]
    [Arguments("report")]
    public async Task ExactRiskRecordCannotTurnNativeFailureIntoClearance(string stage)
    {
        var fixture = new Fixture();
        fixture.Vulnerable("first.csproj", "First.Package");
        fixture.Exception();
        var result = fixture.Evaluate(restoreExit: stage == "restore" ? 1 : 0,
            graphExit: stage == "graph" ? 1 : 0, reportExit: stage == "report" ? 1 : 0);
        await Assert.That(result.Cleared).IsFalse();
        await Assert.That(result.Failures).Contains("audit-native-failure");
    }

    private sealed class Fixture
    {
        internal JsonObject Report { get; } = JsonNode.Parse("""
            {"version":1,"parameters":"--vulnerable --include-transitive",
             "sources":["https://api.nuget.org/v3/index.json"],
             "projects":[
              {"path":"first.csproj","frameworks":[{"framework":"net10.0","topLevelPackages":[]}]},
              {"path":"second.csproj","frameworks":[{"framework":"net10.0","topLevelPackages":[]}]}]}
            """)!.AsObject();
        internal JsonObject Graph { get; } = JsonNode.Parse("""
            {"version":1,"parameters":"--include-transitive","projects":[
             {"path":"first.csproj","frameworks":[{"framework":"net10.0",
              "topLevelPackages":[{"id":"First.Package","requestedVersion":"1.0.0","resolvedVersion":"1.0.0"}],
              "transitivePackages":[]}]},
             {"path":"second.csproj","frameworks":[{"framework":"net10.0",
              "topLevelPackages":[{"id":"Second.Package","requestedVersion":"1.0.0","resolvedVersion":"1.0.0"}],
              "transitivePackages":[]}]}]}
            """)!.AsObject();
        internal JsonObject Registry { get; } = JsonNode.Parse("""{"schemaVersion":1,"exceptions":[]}""")!.AsObject();
        internal void Vulnerable(string project, string package, bool transitive = false)
        {
            if (transitive)
            {
                JsonObject graphFramework = Graph["projects"]!.AsArray()
                    .Single(p => p!["path"]!.GetValue<string>() == project)!["frameworks"]![0]!.AsObject();
                var resolved = graphFramework["topLevelPackages"]![0]!.DeepClone().AsObject();
                resolved.Remove("requestedVersion");
                graphFramework["topLevelPackages"] = new JsonArray();
                graphFramework["transitivePackages"] = new JsonArray(resolved);
            }
            JsonObject selected = Report["projects"]!.AsArray().Select(p => p!.AsObject())
                .Single(p => p["path"]!.GetValue<string>() == project);
            selected["frameworks"] = new JsonArray(new JsonObject
            {
                ["framework"] = "net10.0",
                [transitive ? "transitivePackages" : "topLevelPackages"] = new JsonArray(new JsonObject
                {
                    ["id"] = package,
                    ["resolvedVersion"] = "1.0.0",
                    ["vulnerabilities"] = new JsonArray(new JsonObject { ["severity"] = "High", ["advisoryurl"] = Advisory })
                })
            });
        }
        internal JsonObject Exception()
        {
            var value = new JsonObject
            {
                ["project"] = "first.csproj",
                ["framework"] = "net10.0",
                ["package"] = "First.Package",
                ["version"] = "1.0.0",
                ["advisory"] = Advisory,
                ["owner"] = "security-owner",
                ["rationale"] = "Synthetic scoped risk decision",
                ["evidence"] = "review-123",
                ["expiresAt"] = "2026-11-06T00:00:00Z"
            };
            Registry["exceptions"]!.AsArray().Add(value);
            return value;
        }
        internal DependencyAuditDecision Evaluate(byte[]? report = null, int restoreExit = 0, int graphExit = 0, int reportExit = 0) =>
            DependencyAudit.Evaluate(report ?? Bytes(Report), Bytes(Graph), Bytes(Registry),
                ["first.csproj", "second.csproj"], [Source], restoreExit, graphExit, reportExit, Now);
        private static byte[] Bytes(JsonNode node) => Encoding.UTF8.GetBytes(node.ToJsonString());
    }
}
