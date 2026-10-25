using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecretKit.Release.Tests;

public sealed class DemoInputsTests
{
    [Test]
    public async Task ExactTemporaryBundleChecksWithoutPublicationAuthority()
    {
        using var fixture = new DemoFixture();
        await Assert.That(await fixture.CheckAsync()).IsEqualTo(0);
        await Assert.That(fixture.SourceLocksUnchanged()).IsTrue();
    }

    [Test]
    [Arguments("missing-app")]
    [Arguments("extra-app")]
    [Arguments("duplicate-app")]
    [Arguments("missing-lock")]
    [Arguments("missing-qualification")]
    [Arguments("extra-root")]
    [Arguments("duplicate-field")]
    [Arguments("missing-input")]
    [Arguments("duplicate-input")]
    [Arguments("input-traversal")]
    [Arguments("traversal")]
    [Arguments("lock-link")]
    [Arguments("directory-link")]
    [Arguments("qualification")]
    [Arguments("source")]
    [Arguments("commit")]
    [Arguments("version")]
    [Arguments("archive")]
    [Arguments("source-lock")]
    [Arguments("staged-lock")]
    [Arguments("external-hash")]
    [Arguments("dependency")]
    [Arguments("framework")]
    [Arguments("range")]
    [Arguments("input")]
    [Arguments("extra-input")]
    [Arguments("run")]
    [Arguments("attempt")]
    [Arguments("sdk")]
    [Arguments("unknown")]
    public async Task SubstitutionCannotBeAdmitted(string fault)
    {
        using var fixture = new DemoFixture();
        string staged = Path.Combine(fixture.Bundle, "locks/console/packages.lock.json");
        switch (fault)
        {
            case "missing-lock": File.Delete(staged); break;
            case "missing-qualification":
                File.Delete(Path.Combine(fixture.Bundle, "qualification/local-qualification.json"));
                break;
            case "extra-root": File.WriteAllText(Path.Combine(fixture.Bundle, "unexpected"), "extra"); break;
            case "duplicate-field":
                string path = Path.Combine(fixture.Bundle, "demo-inputs.json");
                File.WriteAllText(path, File.ReadAllText(path).Replace("\"schemaVersion\": 1",
                    "\"schemaVersion\": 1, \"schemaVersion\": 1", StringComparison.Ordinal));
                break;
            case "qualification":
                File.AppendAllText(Path.Combine(fixture.Bundle, "qualification/local-qualification.json"), " ");
                break;
            case "source": File.AppendAllText(Path.Combine(fixture.Local.Source, "input.cs"), "changed"); break;
            case "archive":
                File.AppendAllText(Path.Combine(fixture.Bundle, $"originals/SecretKit.Core.{TestBundle.Version}.nupkg"), " ");
                break;
            case "source-lock":
                File.AppendAllText(Path.Combine(fixture.Local.Source, "samples/Infisical.ConsoleDemo/packages.lock.json"), " ");
                break;
            case "input":
                File.AppendAllText(Path.Combine(fixture.Local.Source, "samples/Infisical.ConsoleDemo/Program.cs"), "changed");
                break;
            case "extra-input": File.WriteAllText(Path.Combine(fixture.Bundle, "locks/console/extra"), "extra"); break;
            case "lock-link":
                File.Move(staged, Path.Combine(fixture.Local.Root, "original-lock"));
                File.CreateSymbolicLink(staged, Path.Combine(fixture.Local.Root, "original-lock"));
                break;
            case "directory-link":
                Directory.Move(Path.GetDirectoryName(staged)!, Path.Combine(fixture.Local.Root, "original-directory"));
                Directory.CreateSymbolicLink(Path.GetDirectoryName(staged)!, Path.Combine(fixture.Local.Root, "original-directory"));
                break;
            case "staged-lock": File.AppendAllText(staged, " "); break;
            case "external-hash":
            case "dependency":
            case "framework":
            case "range":
                JsonObject graph = JsonNode.Parse(File.ReadAllBytes(staged))!.AsObject();
                JsonNode framework = graph["dependencies"]!["net10.0"]!;
                if (fault == "external-hash") framework["Refit"]!["contentHash"] = Convert.ToBase64String(new byte[64]);
                if (fault == "dependency") framework["SecretKit.Infisical"]!["dependencies"]!["Refit"] = "99.0.0";
                if (fault == "range") framework["SecretKit.Core"]!["requested"] = "[0.0.0, )";
                if (fault == "framework") graph["dependencies"]!["net9.0"] = framework.DeepClone();
                File.WriteAllText(staged, graph.ToJsonString());
                fixture.ChangeManifest(m => m["apps"]![0]!["lockSha256"] = Manifest.Hash(File.ReadAllBytes(staged)));
                break;
            default:
                fixture.ChangeManifest(m =>
                {
                    JsonArray apps = m["apps"]!.AsArray();
                    switch (fault)
                    {
                        case "missing-app": apps.RemoveAt(0); break;
                        case "extra-app":
                            JsonNode other = apps[0]!.DeepClone();
                            other["id"] = "other";
                            apps.Add(other);
                            break;
                        case "duplicate-app": apps.Add(apps[0]!.DeepClone()); break;
                        case "missing-input": apps[0]!["inputs"]!.AsArray().RemoveAt(0); break;
                        case "duplicate-input":
                            apps[0]!["inputs"]!.AsArray().Add(apps[0]!["inputs"]![0]!.DeepClone());
                            break;
                        case "input-traversal": apps[0]!["inputs"]![0]!["file"] = "../Program.cs"; break;
                        case "traversal": apps[0]!["id"] = "../console"; break;
                        case "commit": m["sourceCommit"] = new string('b', 40); break;
                        case "version": m["version"] = "0.2.0"; break;
                        case "run": m["workflowRunId"] = 99; break;
                        case "attempt": m["workflowRunAttempt"] = 99; break;
                        case "sdk": m["sdk"] = "10.0.999"; break;
                        case "unknown": m["approval"] = "not-authority"; break;
                        default: throw new InvalidOperationException();
                    }
                });
                break;
        }
        await Assert.That(await fixture.CheckAsync()).IsEqualTo(1);
    }

    [Test]
    public async Task PreparationRejectsMismatchedBaselineWithoutRegeneratingSourceLocks()
    {
        using var fixture = new DemoFixture();
        string path = Path.Combine(fixture.Local.Source, "samples/Infisical.ConsoleDemo/packages.lock.json");
        File.WriteAllText(path, File.ReadAllText(path).Replace(TestBundle.Version, "0.2.0", StringComparison.Ordinal));
        string qualification = Path.Combine(fixture.Local.Root, "changed-record");
        LocalQualification.Prepare(fixture.Local.Source, fixture.Local.Packages, qualification);
        byte[] baseline = File.ReadAllBytes(path);
        string output = Path.Combine(fixture.Local.Root, "new-bundle");
        await Assert.That(await Program.Main(["local-demo-prepare", fixture.Local.Source, fixture.Local.Packages,
            qualification, output, TestBundle.Commit, "12", "1", "10.0.302"])).IsEqualTo(1);
        await Assert.That(Directory.Exists(output)).IsFalse();
        await Assert.That(File.ReadAllBytes(path).SequenceEqual(baseline)).IsTrue();
    }

    internal sealed class DemoFixture : IDisposable
    {
        internal LocalQualificationTests.LocalFixture Local { get; } = new();
        internal string Bundle => Path.Combine(Local.Root, "bundle");
        private readonly Dictionary<string, byte[]> _locks = [];
        internal static readonly string[] Kinds = ["Console", "Worker", "Web"];

        internal DemoFixture()
        {
            string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
            foreach (string kind in Kinds)
            {
                string relative = $"samples/Infisical.{kind}Demo";
                Directory.CreateDirectory(Path.Combine(Local.Source, relative));
                foreach (string path in Directory.GetFiles(Path.Combine(root, relative)))
                    File.Copy(path, Path.Combine(Local.Source, relative, Path.GetFileName(path)));
                string sourceLock = Path.Combine(Local.Source, relative, "packages.lock.json");
                // Fixture versions are independent of the parent's current local candidate.
                JsonObject graph = JsonNode.Parse(File.ReadAllBytes(sourceLock))!.AsObject();
                foreach (var entry in graph["dependencies"]!["net10.0"]!.AsObject())
                {
                    if (!entry.Key.StartsWith("SecretKit.", StringComparison.Ordinal)) continue;
                    string previous = entry.Value!["resolved"]!.GetValue<string>();
                    graph = JsonNode.Parse(graph.ToJsonString().Replace(previous, TestBundle.Version,
                        StringComparison.Ordinal))!.AsObject();
                }
                File.WriteAllText(sourceLock, graph.ToJsonString());
                _locks.Add(kind, File.ReadAllBytes(sourceLock));
            }
            foreach (string relative in new[]
            {
                "samples/Infisical.Demos/DemoInput.cs", "samples/Infisical.Demos/DemoInputReader.cs",
                "samples/Infisical.Demos/DemoOutput.cs", "samples/Infisical.Demos/DemoTokenSource.cs",
                "samples/Infisical.Demos/MutationInput.cs", "samples/Infisical.Demos/WorkerInput.cs",
                "samples/RuntimeConfiguration/RuntimeIntegrationCoordinator.cs",
                "samples/RuntimeConfiguration/RuntimeGenerationLease.cs", "global.json"
            })
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Path.Combine(Local.Source, relative))!);
                File.Copy(Path.Combine(root, relative), Path.Combine(Local.Source, relative));
            }
            LocalQualification.Prepare(Local.Source, Local.Packages, Local.Output);
            Directory.CreateDirectory(Path.Combine(Bundle, "qualification"));
            Directory.CreateDirectory(Path.Combine(Bundle, "originals"));
            File.Copy(Local.RecordPath, Path.Combine(Bundle, "qualification/local-qualification.json"));
            foreach (string path in Directory.GetFiles(Local.Packages))
                File.Copy(path, Path.Combine(Bundle, "originals", Path.GetFileName(path)));
            var apps = new List<object>();
            foreach (string kind in Kinds)
            {
                string id = kind.ToLowerInvariant();
                JsonObject graph = JsonNode.Parse(_locks[kind])!.AsObject();
                foreach (var entry in graph["dependencies"]!["net10.0"]!.AsObject())
                    if (entry.Key.StartsWith("SecretKit.", StringComparison.Ordinal))
                        entry.Value!["contentHash"] = Convert.ToBase64String(SHA512.HashData(
                            File.ReadAllBytes(Path.Combine(Local.Packages, $"{entry.Key}.{TestBundle.Version}.nupkg"))));
                string directory = Path.Combine(Bundle, "locks", id);
                Directory.CreateDirectory(directory);
                byte[] staged = JsonSerializer.SerializeToUtf8Bytes(graph);
                File.WriteAllBytes(Path.Combine(directory, "packages.lock.json"), staged);
                string[] inputs =
                [
                    $"samples/Infisical.{kind}Demo/Infisical.{kind}Demo.csproj",
                    $"samples/Infisical.{kind}Demo/Program.cs",
                    $"samples/Infisical.{kind}Demo/README.md",
                    "samples/Infisical.Demos/DemoInput.cs", "samples/Infisical.Demos/DemoInputReader.cs",
                    "samples/Infisical.Demos/DemoOutput.cs",
                    .. kind == "Worker" ? new[] { "samples/Infisical.Demos/WorkerInput.cs" } :
                        new[] { "samples/Infisical.Demos/DemoTokenSource.cs" },
                    .. kind switch
                    {
                        "Console" => new[]
                        {
                            "samples/Infisical.Demos/MutationInput.cs",
                            "samples/Infisical.ConsoleDemo/ConsoleDemoApplication.cs",
                            "samples/Infisical.ConsoleDemo/ConsoleDemoCommand.cs",
                            "samples/Infisical.ConsoleDemo/ConsoleDemoOutcomes.cs"
                        },
                        "Worker" => new[] { "samples/Infisical.WorkerDemo/WorkerDemoApplication.cs",
                            "samples/Infisical.WorkerDemo/SecretWorker.cs" },
                        "Web" => new[] { "samples/Infisical.WebDemo/WebDemoApplication.cs",
                            "samples/Infisical.WebDemo/WebDemoRuntime.cs", "samples/Infisical.WebDemo/WebDemoEndpoints.cs",
                            "samples/Infisical.WebDemo/WebDemoOptions.cs", "samples/Infisical.WebDemo/JobClient.cs" },
                        _ => throw new InvalidOperationException()
                    },
                    .. kind == "Web" ? new[]
                    {
                        "samples/RuntimeConfiguration/RuntimeIntegrationCoordinator.cs",
                        "samples/RuntimeConfiguration/RuntimeGenerationLease.cs"
                    } : []
                ];
                apps.Add(new
                {
                    id,
                    sourceLockSha256 = Manifest.Hash(_locks[kind]),
                    lockSha256 = Manifest.Hash(staged),
                    inputs = inputs.Select(path => new FileDigest(path, Manifest.Hash(
                        File.ReadAllBytes(Path.Combine(Local.Source, path))))).ToArray()
                });
            }
            File.WriteAllBytes(Path.Combine(Bundle, "demo-inputs.json"), JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                purpose = "ci-temporary-verification",
                workflowRunId = 12,
                workflowRunAttempt = 1,
                sourceCommit = TestBundle.Commit,
                sdk = "10.0.302",
                version = TestBundle.Version,
                qualificationSha256 = Manifest.Hash(File.ReadAllBytes(Local.RecordPath)),
                apps
            }, Manifest.JsonOptions));
        }

        internal Task<int> CheckAsync() => Program.Main(["local-demo-check", Local.Source, Bundle,
            TestBundle.Commit, "12", "1", "10.0.302"]);

        internal bool SourceLocksUnchanged() => Kinds.All(kind => _locks[kind].SequenceEqual(
            File.ReadAllBytes(Path.Combine(Local.Source, $"samples/Infisical.{kind}Demo/packages.lock.json"))));

        internal void ChangeManifest(Action<JsonObject> change)
        {
            string path = Path.Combine(Bundle, "demo-inputs.json");
            JsonObject manifest = JsonNode.Parse(File.ReadAllBytes(path))!.AsObject();
            change(manifest);
            File.WriteAllText(path, manifest.ToJsonString(Manifest.JsonOptions));
        }

        public void Dispose() => Local.Dispose();
    }
}
