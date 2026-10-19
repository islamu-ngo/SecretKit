using System.Text;
using System.Text.Json;

namespace SecretKit.Release.Tests;

// Fixture ONLY. These controlled oracles are not GitHub metadata, provider
// observations, rights evidence or protected approval. No producer may use this
// class. Independent bytes are captured once and never updated by bundle.Save().
internal sealed class TestBundle : IDisposable
{
    public string Root { get; } = Path.Combine(Path.GetTempPath(), "secretkit-release-tests-" + Guid.NewGuid().ToString("N"));
    public string OracleRoot => Root + "-oracle";
    public string JournalPath => Path.Combine(Root, "journal");
    public ReleaseManifest Data { get; set; }
    public Approval Approval { get; private set; }
    public EvidenceIndex Index { get; set; }
    public const string Version = "0.1.0-preview.1";
    public static string Commit => new('a', 40);
    public static DateTimeOffset RunStart => new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public TestBundle()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(OracleRoot);
        const string notices = "Controlled fixture notices: not release evidence";
        File.WriteAllText(Path.Combine(OracleRoot, "THIRD-PARTY-NOTICES.md"), notices);
        PackageRecord[] packages = Manifest.PackageIds.Select(id =>
        {
            string nuspec = $"""
                <package><metadata><id>{id}</id><version>{Version}</version>
                <license type="expression">MIT</license>
                <repository type="git" url="{Manifest.Repository}" commit="{Commit}"/>
                </metadata></package>
                """;
            byte[] bytes = ArchiveTests.Zip((id + ".nuspec", nuspec), ("README.md", "test"),
                ("THIRD-PARTY-NOTICES.md", notices));
            string file = $"{id}.{Version}.nupkg";
            File.WriteAllBytes(Path.Combine(Root, file), bytes);
            return new PackageRecord(id, file, Manifest.Hash(bytes));
        }).ToArray();
        AdmissionInventory[] inventories = new[] { "Infisical", "AzureKeyVault" }.Select(provider =>
            new AdmissionInventory(1, "current-admission", provider, "complete-live",
                [new($"src/SecretKit.{provider}/Client.cs", new string('a', 64))],
                [new("read", $"SecretKit.{provider}.Client.ReadAsync", ["selected-version", "current-version"],
                    "implemented-subset", "Independently witnessed selected read outcome.",
                    ["read-effect", "denied-read"], ["owned-environment", "runtime-identity", "observer-identity"])],
                ["Fixture denominator only; never production admission."])).ToArray();
        FileDigest[] inventoryFiles = inventories.Select(i =>
        {
            string file = i.Provider == "Infisical" ? "infisical.json" : "azure-key-vault.json";
            WriteOracle(file, i);
            return Write(file, i);
        }).ToArray();
        ProviderScope[] providerScopes =
        [
            new("test-scope", "Infisical", "deployment-a", "api-v1", "runtime-a", "observer-a",
                "setup-a", "denied-a", "administrative-a"),
            new("test-vault", "AzureKeyVault", "deployment-b", "api-v1", "runtime-b", "observer-b",
                "setup-b", "denied-b", "administrative-b")
        ];
        var scope = new ReleaseScope(Version, Commit, Manifest.PackageIds.ToArray(),
            providerScopes.SelectMany(s => inventories.Single(i => i.Provider == s.Provider).Operations
                .SelectMany(o => o.Variants.Select(v => new NativeOperation(s.Provider, o.Id, v, s.Label, "complete")))).ToArray(),
            ["linux-x64-net10.0", "windows-x64-net10.0"], inventoryFiles, "complete-live", providerScopes);
        FileDigest scopeFile = Write("scope.json", scope);
        string noticesHash = Manifest.Hash(Encoding.UTF8.GetBytes(notices));
        var origins = new List<ReportOrigin>();
        var attestations = new List<AuthorityAttestation>();
        GateRecord[] gates = Manifest.GateKinds.Select(kind =>
        {
            string[] checks = kind switch
            {
                "native-operations" or "live-conformance" => scope.NativeOperations.Select(o => o.Key).ToArray(),
                "compatibility-install" => scope.Platforms,
                "namespace-rights" => [.. Manifest.PackageIds, "SecretKit."],
                "publisher-rights" => ["publisher:test-user", "owner:test-owner"],
                "oidc-registration" => [$"{Manifest.RepositoryName}/publish.yml/release", "https://www.nuget.org"],
                "protected-environment" => ["release", "required-reviewers", "prevent-self-review", "main-only"],
                "provenance" => [Commit, .. packages.Select(p => p.Sha256)],
                "notices" => [noticesHash],
                _ => throw new InvalidOperationException()
            };
            var reports = new List<MachineReport>();
            AuthorityAttestation? attestation = null;
            if (kind is "native-operations" or "live-conformance" or "compatibility-install" or "provenance" or "notices")
            {
                foreach (string platform in kind is "provenance" or "notices" ? ["none"] : scope.Platforms)
                {
                    long jobId = 100 + origins.Count;
                    long artifactId = 200 + origins.Count;
                    bool native = kind is "native-operations" or "live-conformance";
                    string environment = native ? "release-evidence" : "none";
                    NativeCaseObservation[] cases = native ? scope.NativeOperations.SelectMany(o =>
                        new[] { "read-effect", "denied-read" }.Select(c =>
                            new NativeCaseObservation(o.Provider, o.Operation, o.Variant, o.Scope, c, true, true, "observed")))
                        .ToArray() : [];
                    CheckObservation[] results = (kind == "compatibility-install" ? [platform] : checks)
                        .Select(c => new CheckObservation(c, true, "observed")).ToArray();
                    PrerequisiteObservation[] prerequisites = native ? providerScopes.SelectMany(s =>
                        new[] { "owned-environment", "runtime-identity", "observer-identity" }
                            .Select(p => new PrerequisiteObservation(s.Provider, s.Label, p, true))).ToArray() : [];
                    var report = new MachineReport(2, "release-observation", kind, Version, Commit, 12, 1, jobId,
                        platform, environment, scopeFile.Sha256, inventoryFiles, packages, providerScopes,
                        RunStart.AddMinutes(1), RunStart.AddMinutes(2), native ? cases.Length : results.Length, 0, 0, 0,
                        results, cases, prerequisites, native || kind == "compatibility-install"
                            ? new(platform.Split('-')[0], "x64", "net10.0", 0, 0, true, "candidate-only") : null);
                    FileDigest rawFile = WriteOracle($"{artifactId}-report.json", report);
                    string digest = new('d', 64);
                    origins.Add(new(kind, platform, jobId, artifactId, digest, rawFile, environment, "reviewed-job-deployment"));
                    WriteOracle($"{jobId}-job.json", new
                    {
                        id = jobId,
                        run_id = 12,
                        run_attempt = 1,
                        head_sha = Commit,
                        name = $"{kind}-{platform}",
                        status = "completed",
                        conclusion = "success",
                        started_at = RunStart,
                        completed_at = RunStart.AddMinutes(4)
                    });
                    WriteOracle($"{artifactId}-artifact.json", new
                    {
                        id = artifactId,
                        expired = false,
                        digest = "sha256:" + digest,
                        name = $"secretkit-report-{jobId}",
                        workflow_run = new { id = 12, head_sha = Commit },
                        created_at = RunStart.AddMinutes(3),
                        expires_at = RunStart.AddDays(120)
                    });
                    reports.Add(report);
                }
            }
            else
            {
                attestation = new(kind, "test-owner", "native-owner", "independent-reviewer", RunStart.AddMinutes(5),
                    "controlled-native-evidence", new string('e', 64),
                    checks.Select(c => new CheckObservation(c, true, "observed")).ToArray());
                attestations.Add(attestation);
            }
            FileDigest record = Write(kind + "-record.json", new SemanticGateRecord(2, reports.ToArray(), attestation));
            FileDigest file = Write(kind + ".json", new GateEvidence(kind, "passed", Version, Commit, scopeFile.Sha256,
                Manifest.PackageIds.ToArray(), checks, record));
            return new GateRecord(kind, file.File, file.Sha256);
        }).ToArray();
        Data = new(2, "SecretKit", Version, Commit, Manifest.Repository, 12, "test-user", "test-owner",
            "SecretKit.", "release", noticesHash, scopeFile, packages, gates);
        Index = new(1, "independent-release-evidence", Manifest.RepositoryName, Commit, Version, 12, 1,
            RunStart.AddMinutes(10), inventoryFiles, origins.ToArray(), attestations.ToArray());
        Approval = new("", Commit, Version, 12, 34, new string('b', 64), scopeFile.Sha256,
            "test-user", "test-owner", new string('c', 64), "new", "");
        WriteOracle("artifact-metadata.json", new
        {
            id = 34,
            expired = false,
            digest = "sha256:" + Approval.ArtifactDigest,
            workflow_run = new { id = 12, head_sha = Commit },
            expires_at = RunStart.AddDays(120)
        });
        WriteRun();
        SaveIndex();
        Save();
    }

    public void WriteRun(string status = "completed", string? conclusion = "success") =>
        WriteOracle("run-metadata.json", new
        {
            id = 12,
            run_attempt = 1,
            head_sha = Commit,
            head_branch = "main",
            @event = "push",
            status,
            conclusion,
            path = ".github/workflows/verify.yml",
            repository = new { full_name = Manifest.RepositoryName },
            head_repository = new { full_name = Manifest.RepositoryName },
            created_at = RunStart
        });

    public FileDigest Write<T>(string file, T value) => WriteAt(Root, file, value);
    public FileDigest WriteOracle<T>(string file, T value) => WriteAt(OracleRoot, file, value);
    private static FileDigest WriteAt<T>(string directory, string file, T value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value, Manifest.JsonOptions);
        File.WriteAllBytes(Path.Combine(directory, file), bytes);
        return new(file, Manifest.Hash(bytes));
    }

    public void SaveIndex() => Approval = Approval with { EvidenceSha256 = WriteOracle("evidence-index.json", Index).Sha256 };
    public void Save() => Approval = Approval with { ManifestSha256 = Write("manifest.json", Data).Sha256 };
    public VerifiedRelease Verify() => Manifest.Verify(Root, Approval, new IndependentEvidence(OracleRoot));

    public void EditRecord(string kind, Func<SemanticGateRecord, SemanticGateRecord> edit)
    {
        GateRecord gate = Data.Gates.Single(g => g.Kind == kind);
        GateEvidence evidence = Manifest.Parse<GateEvidence>(File.ReadAllBytes(Path.Combine(Root, gate.File)));
        SemanticGateRecord record = Manifest.Parse<SemanticGateRecord>(File.ReadAllBytes(Path.Combine(Root, evidence.Record.File)));
        FileDigest recordFile = Write(evidence.Record.File, edit(record));
        FileDigest file = Write(gate.File, evidence with { Record = recordFile });
        Data = Data with { Gates = Data.Gates.Select(g => g.Kind == kind ? g with { Sha256 = file.Sha256 } : g).ToArray() };
        Save();
    }

    public void ReviewScope(ReleaseScope scope)
    {
        FileDigest scopeFile = Write(Data.Scope.File, scope);
        GateRecord[] gates = Data.Gates.Select(g =>
        {
            GateEvidence evidence = Manifest.Parse<GateEvidence>(File.ReadAllBytes(Path.Combine(Root, g.File)));
            FileDigest file = Write(g.File, evidence with { ScopeSha256 = scopeFile.Sha256 });
            return g with { Sha256 = file.Sha256 };
        }).ToArray();
        Data = Data with { Scope = scopeFile, Gates = gates };
        Approval = Approval with { ScopeSha256 = scopeFile.Sha256 };
        Save();
    }

    public void Dispose()
    {
        Directory.Delete(Root, recursive: true);
        Directory.Delete(OracleRoot, recursive: true);
    }
}
