using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class VerificationCohortTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task FreshObservationDestinationsAreCreatedWithoutReplacingProducerInputs(bool explicitPath)
    {
        string root = Path.Combine(Path.GetTempPath(), "secretkit-observation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string cohort = Path.Combine(root, "cohort");
            Directory.CreateDirectory(cohort);
            string original = Path.Combine(cohort, "producer.json");
            File.WriteAllText(original, "original");
            string? selected = explicitPath ? Path.Combine(root, "missing", "parent", "observations") : null;

            string created = VerificationCohort.CreateObservationDirectory(root, cohort, selected);

            await Assert.That(Directory.Exists(created)).IsTrue();
            if (selected is not null) await Assert.That(created).IsEqualTo(selected);
            await Assert.That(File.ReadAllText(original)).IsEqualTo("original");
            await Assert.That(() => VerificationCohort.CreateObservationDirectory(root, cohort, created))
                .Throws<ReleaseException>();
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Test]
    public async Task ObservationPathAliasesCannotEnterTheProducerCohort()
    {
        string root = Path.Combine(Path.GetTempPath(), "secretkit-observation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "cohort"));
        try
        {
            string alias = Path.Combine(root, "other", "..", "cohort", "consumer");
            await Assert.That(() => VerificationCohort.CreateObservationDirectory(root, Path.Combine(root, "cohort"), alias))
                .Throws<ReleaseException>();
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Test]
    [Arguments("linux-x64")]
    [Arguments("windows-x64")]
    public void CompleteHardeningObservationsBindEveryModeToTheSelectedCohort(string platform)
    {
        using var fixture = new Observations(platform);
        fixture.Check();
    }

    [Test]
    [Arguments("missing-mode")]
    [Arguments("extra-mode")]
    [Arguments("duplicate-scenario")]
    [Arguments("missing-scenario")]
    [Arguments("failed-scenario")]
    [Arguments("native-promotion")]
    [Arguments("cohort")]
    [Arguments("platform")]
    [Arguments("runtime")]
    [Arguments("sdk")]
    [Arguments("run")]
    [Arguments("attempt")]
    [Arguments("swapped-mode")]
    [Arguments("platform-failure")]
    [Arguments("platform-originals")]
    public async Task IncompleteFailedOrSubstitutedHardeningObservationsReject(string fault)
    {
        using var fixture = new Observations("linux-x64");
        JsonNode report = fixture.Read("full");
        switch (fault)
        {
            case "missing-mode": File.Delete(fixture.PathFor("full")); break;
            case "extra-mode": File.WriteAllText(fixture.PathFor("unexpected"), "{}"); break;
            case "duplicate-scenario":
                report["scenarios"]!.AsArray().Add(report["scenarios"]![0]!.DeepClone()); break;
            case "missing-scenario": report["scenarios"]!.AsArray().RemoveAt(0); break;
            case "failed-scenario": report["scenarios"]![0]!["status"] = "failed"; break;
            case "native-promotion": report["nativeQualified"] = true; break;
            case "cohort": report["cohortSha256"] = new string('b', 64); break;
            case "platform": report["platform"] = "windows-x64"; break;
            case "runtime": report["runtime"] = "10.0.9"; break;
            case "sdk": report["sdk"] = "10.0.999"; break;
            case "run": report["run"] = 2; break;
            case "attempt": report["attempt"] = 2; break;
            case "swapped-mode": report["mode"] = "minimal"; break;
            case "platform-failure": fixture.ChangePlatform("processExitCode", JsonValue.Create(1)!); break;
            case "platform-originals":
                fixture.ChangePlatformPackage(); break;
            default: throw new InvalidOperationException("Unknown fixture fault.");
        }
        if (fault is not ("missing-mode" or "extra-mode"))
            File.WriteAllText(fixture.PathFor("full"), report.ToJsonString());

        await Assert.That(() => fixture.Check()).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("family", "missing")]
    [Arguments("symbols", "changed")]
    [Arguments("rebuild-family", "changed")]
    [Arguments("rebuild-symbols", "missing")]
    [Arguments("local", "mixed")]
    [Arguments("local-symbols", "changed")]
    public async Task EveryOriginalAndSymbolSelectionIsBound(string folder, string fault)
    {
        using var fixture = new Artifacts();
        _ = VerificationCohort.ReadArtifacts(fixture.Root);
        string extension = folder.EndsWith("symbols", StringComparison.Ordinal) ? "snupkg" : "nupkg";
        string path = Path.Combine(fixture.Root, folder, $"SecretKit.Core.0.2.0-integration.9.{extension}");
        if (fault == "missing") File.Delete(path);
        else File.WriteAllText(path, "substituted-original");

        if (fault == "missing")
            await Assert.That(() => VerificationCohort.ReadArtifacts(fixture.Root)).Throws<FileNotFoundException>();
        else
            await Assert.That(() => VerificationCohort.ReadArtifacts(fixture.Root)).Throws<ReleaseException>();
    }

    [Test]
    public async Task SelectedFourCannotDivergeEvenWithRecomputedFileDigests()
    {
        using var fixture = new Artifacts();
        string file = "local/SecretKit.Core.0.2.0-integration.9.nupkg";
        File.WriteAllText(Path.Combine(fixture.Root, file), "another-build");
        VerificationCohortRecord record = fixture.Record with
        {
            Files = fixture.Record.Files.Select(item => item.File == file
                ? item with { Sha256 = Manifest.Hash(File.ReadAllBytes(Path.Combine(fixture.Root, file))) } : item).ToArray()
        };
        fixture.Write(record);

        await Assert.That(() => VerificationCohort.ReadArtifacts(fixture.Root)).Throws<ReleaseException>();
    }

    [Test]
    public void SelectedVersionMigratesOnlyInternalDemoLockBindings()
    {
        byte[] baseline = Lock("0.1.0-preview.1");
        byte[] selected = Lock("0.2.0-integration.9");

        DemoInputs.ValidateLockChange(baseline, selected, "console", "0.2.0-integration.9", null);
    }

    [Test]
    public async Task SelectedVersionCannotChangeExternalDemoDependencies()
    {
        byte[] baseline = Lock("0.1.0-preview.1");
        JsonNode selected = JsonNode.Parse(Lock("0.2.0-integration.9"))!;
        selected["dependencies"]!["net10.0"]!["Refit"]!["resolved"] = "99.0.0";

        await Assert.That(() => DemoInputs.ValidateLockChange(baseline,
            Encoding.UTF8.GetBytes(selected.ToJsonString()), "console", "0.2.0-integration.9", null))
            .Throws<ReleaseException>();
    }

    private static byte[] Lock(string version) => Encoding.UTF8.GetBytes($$"""
        {
          "version": 1,
          "dependencies": {
            "net10.0": {
              "SecretKit.Core": {
                "type": "Direct", "requested": "[{{version}}, {{version}}]",
                "resolved": "{{version}}", "contentHash": "{{Convert.ToBase64String(new byte[64])}}"
              },
              "SecretKit.Infisical": {
                "type": "Direct", "requested": "[{{version}}, {{version}}]",
                "resolved": "{{version}}", "contentHash": "{{Convert.ToBase64String(new byte[64])}}",
                "dependencies": { "SecretKit.Core": "{{version}}", "Refit": "16.3.0" }
              },
              "Refit": { "type": "Transitive", "resolved": "16.3.0",
                "contentHash": "{{Convert.ToBase64String(new byte[64])}}" }
            }
          }
        }
        """);

    private sealed class Observations : IDisposable
    {
        private readonly Artifacts _artifacts = new();
        private readonly string _platform;
        private readonly string _directory;
        private readonly Dictionary<string, string[]> _modes = new(StringComparer.Ordinal);
        private const string CohortHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        internal Observations(string platform)
        {
            _platform = platform;
            _directory = Path.Combine(_artifacts.Root, "observations");
            Directory.CreateDirectory(Path.Combine(_directory, "hardening"));
            VerificationCohortRecord record = _artifacts.Record;
            string[] modes = ["minimal", "configuration", "hosting", "full", "seven-package"];
            foreach (string mode in modes)
            {
                string[] ids = mode switch
                {
                    "minimal" => ["S03", "S12", "S14", "S16", "S17"],
                    "configuration" => ["S03", "S12", "S14", "S16", "S17", "S07", "S25"],
                    "hosting" => ["S03", "S12", "S14", "S16", "S17", "S08", "S09"],
                    "full" => ["S03", "S12", "S14", "S16", "S17", "S07", "S25", "S08", "S09"],
                    _ => ["S02", "S03", "S05", "S06", "S10", "S11", "S12", "S13"]
                };
                _modes.Add(mode, ids);
                var observed = new HardeningInstalledObservation(1, "enterprise-hardening",
                    "controlled-installed-offline", false, mode, CohortHash, platform, "10.0.10",
                    record.Sdk, record.Run, record.Attempt,
                    ids.Select(id => new HardeningInstalledScenario(id, "passed", "controlled-subset")).ToArray());
                File.WriteAllBytes(PathFor(mode), JsonSerializer.SerializeToUtf8Bytes(observed, Manifest.JsonOptions));
            }
            var packages = Manifest.PackageIds.Select(id =>
            {
                string file = $"{id}.{record.Version}.nupkg";
                return new PackageRecord(id, file, record.Files.Single(item => item.File == "family/" + file).Sha256);
            }).ToArray();
            var installation = new PlatformObservation(1, "installed-platform-observation", record.Version,
                record.SourceCommit, platform.Split('-')[0], "x64", "net10.0", "10.0.10", record.Sdk,
                0, 0, true, "candidate-only", packages, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
            File.WriteAllBytes(Path.Combine(_directory, "platform.json"),
                JsonSerializer.SerializeToUtf8Bytes(installation, Manifest.JsonOptions));
        }

        internal string PathFor(string mode) => Path.Combine(_directory, "hardening", mode + ".json");
        internal JsonNode Read(string mode) => JsonNode.Parse(File.ReadAllBytes(PathFor(mode)))!;
        internal void Check() => VerificationCohort.CheckObservations(_artifacts.Record, CohortHash, _platform, _directory, _modes);
        internal void ChangePlatform(string property, JsonNode value)
        {
            string path = Path.Combine(_directory, "platform.json");
            JsonNode record = JsonNode.Parse(File.ReadAllBytes(path))!;
            record[property] = value;
            File.WriteAllText(path, record.ToJsonString());
        }
        internal void ChangePlatformPackage()
        {
            string path = Path.Combine(_directory, "platform.json");
            JsonNode record = JsonNode.Parse(File.ReadAllBytes(path))!;
            record["packages"]![0]!["sha256"] = new string('b', 64);
            File.WriteAllText(path, record.ToJsonString());
        }
        public void Dispose() => _artifacts.Dispose();
    }

    private sealed class Artifacts : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "secretkit-cohort-" + Guid.NewGuid().ToString("N"));
        internal VerificationCohortRecord Record { get; }

        internal Artifacts()
        {
            foreach (string file in VerificationCohort.ExpectedFiles("0.2.0-integration.9"))
            {
                string path = Path.Combine(Root, file);
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                // The byte-binding reader is independent of archive semantics.
                // Same-named selected originals have the same exact bytes.
                File.WriteAllText(path, Path.GetFileName(file));
            }
            Record = new(1, "local-verification-not-native-qualified", "0.2.0-integration.9",
                "10.0.403", new string('a', 40), 1, 1,
                VerificationCohort.ExpectedFiles("0.2.0-integration.9").Select(file =>
                    new FileDigest(file, Manifest.Hash(File.ReadAllBytes(Path.Combine(Root, file))))).ToArray());
            Write(Record);
        }

        internal void Write(VerificationCohortRecord record) =>
            File.WriteAllBytes(Path.Combine(Root, VerificationCohort.RecordFile),
                JsonSerializer.SerializeToUtf8Bytes(record, Manifest.JsonOptions));

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
