using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecretKit.Release.Tests;

public sealed class CandidateTests
{
    [Test]
    public async Task SerializedInputsAssembleContentWithoutPostUploadAuthority()
    {
        using var fixture = new ProducerFixture();
        fixture.Bundle.WriteRun("in_progress", null);
        File.Delete(Path.Combine(fixture.Bundle.OracleRoot, "artifact-metadata.json"));
        Candidate.Assemble(fixture.Bundle.Root, fixture.Bundle.OracleRoot, fixture.PreparationDirectory,
            fixture.Output, fixture.Now);
        Manifest.CheckCandidate(fixture.Output, new IndependentEvidence(fixture.Bundle.OracleRoot));
        ReleaseManifest manifest = Manifest.Parse<ReleaseManifest>(
            File.ReadAllBytes(Path.Combine(fixture.Output, "manifest.json")));
        await Assert.That(manifest.Packages).IsEquivalentTo(fixture.Bundle.Data.Packages);
        await Assert.That(Directory.GetFiles(fixture.Output, "*.nupkg").Length).IsEqualTo(7);
        await Assert.That(File.Exists(Path.Combine(fixture.Output, "artifact-metadata.json"))).IsFalse();
        await Assert.That(File.Exists(Path.Combine(fixture.Output, "evidence-index.json"))).IsFalse();
        await Assert.That(File.Exists(Path.Combine(fixture.Output, "candidate-inputs.json"))).IsFalse();
        Approval approval = fixture.Bundle.Approval with
        {
            ManifestSha256 = Manifest.Hash(File.ReadAllBytes(Path.Combine(fixture.Output, "manifest.json")))
        };
        await Assert.That(() => Manifest.Verify(fixture.Output, approval,
            new IndependentEvidence(fixture.Bundle.OracleRoot))).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("old-attempt")]
    [Arguments("old-source")]
    [Arguments("missing-origin")]
    [Arguments("failed-job")]
    [Arguments("wrong-job")]
    [Arguments("expired-report")]
    [Arguments("short-retention")]
    [Arguments("missing-preparation")]
    [Arguments("unconfirmed-prerequisite")]
    [Arguments("self-review")]
    [Arguments("changed-attestation")]
    public async Task AssemblyRejectsUntrustedOrIncompleteEvidence(string fault)
    {
        using var fixture = new ProducerFixture();
        ReportOrigin origin = fixture.Bundle.Index.Reports[0];
        switch (fault)
        {
            case "old-attempt":
                fixture.Bundle.Index = fixture.Bundle.Index with { RunAttempt = 2 };
                fixture.Bundle.SaveIndex();
                break;
            case "old-source":
                fixture.Bundle.Index = fixture.Bundle.Index with { SourceCommit = new string('b', 40) };
                fixture.Bundle.SaveIndex();
                break;
            case "missing-origin":
                fixture.Bundle.Index = fixture.Bundle.Index with { Reports = fixture.Bundle.Index.Reports[1..] };
                fixture.Bundle.SaveIndex();
                break;
            case "failed-job": fixture.EditOracle($"{origin.JobId}-job.json", n => n["conclusion"] = "failure"); break;
            case "wrong-job": fixture.EditOracle($"{origin.JobId}-job.json", n => n["name"] = "offline"); break;
            case "expired-report": fixture.EditOracle($"{origin.ArtifactId}-artifact.json", n => n["expired"] = true); break;
            case "short-retention":
                fixture.EditOracle($"{origin.ArtifactId}-artifact.json", n => n["expires_at"] = fixture.Now.AddDays(89));
                break;
            case "missing-preparation": File.Delete(Path.Combine(fixture.PreparationDirectory, "preparation.json")); break;
            case "unconfirmed-prerequisite":
                fixture.SavePreparation(fixture.Preparation with
                {
                    Prerequisites = fixture.Preparation.Prerequisites.Select(p => p with { Confirmed = false }).ToArray()
                });
                break;
            case "self-review": fixture.SavePreparation(fixture.Preparation with { Reviewer = fixture.Preparation.Issuer }); break;
            case "changed-attestation":
                fixture.SavePreparation(fixture.Preparation with
                {
                    Attestations = fixture.Preparation.Attestations.Select(a => a with { EvidenceLocator = "other" }).ToArray()
                });
                break;
        }
        await Assert.That(() => Candidate.Assemble(fixture.Bundle.Root, fixture.Bundle.OracleRoot,
            fixture.PreparationDirectory, fixture.Output, fixture.Now)).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("provenance", 8)]
    [Arguments("notices", 1)]
    public async Task ArchiveReportsMeasureOriginalBytesAndSource(string kind, int discovered)
    {
        using var fixture = new ProducerFixture();
        MachineReport report = Candidate.Measure(fixture.Bundle.Root, kind, "none", 900, fixture.Observations);
        await Assert.That(report.Discovered).IsEqualTo(discovered);
        await Assert.That(report.Checks.All(c => c.Passed && c.ReasonCode == "observed")).IsTrue();
        await Assert.That(report.NativeCases.Length).IsEqualTo(0);
        await Assert.That(report.Installation).IsNull();
        File.AppendAllText(Path.Combine(fixture.Bundle.Root, fixture.Bundle.Data.Packages[0].File), "changed");
        await Assert.That(() => Candidate.Measure(fixture.Bundle.Root, kind, "none", 900,
            fixture.Observations)).Throws<ReleaseException>();
    }

    [Test]
    public async Task InstalledReportUsesTheMeasuredProcessAndOriginalHashes()
    {
        using var fixture = new ProducerFixture();
        var observed = new PlatformObservation(1, "installed-platform-observation", TestBundle.Version,
            TestBundle.Commit, "linux", "x64", "net10.0", "10.0.0", "10.0.302",
            0, 0, true, "candidate-only", fixture.Bundle.Data.Packages, TestBundle.RunStart,
            TestBundle.RunStart.AddMinutes(1));
        fixture.WriteObservation("installation.json", observed);
        MachineReport report = Candidate.Measure(fixture.Bundle.Root, "compatibility-install",
            "linux-x64-net10.0", 900, fixture.Observations);
        await Assert.That(report.StartedAt).IsEqualTo(observed.StartedAt);
        await Assert.That(report.Installation!.PackageSource).IsEqualTo("candidate-only");
        await Assert.That(() => Candidate.Measure(fixture.Bundle.Root, "compatibility-install",
            "windows-x64-net10.0", 900, fixture.Observations)).Throws<ReleaseException>();
        fixture.WriteObservation("installation.json", observed with { ProcessExitCode = 1 });
        await Assert.That(() => Candidate.Measure(fixture.Bundle.Root, "compatibility-install",
            "linux-x64-net10.0", 900, fixture.Observations)).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("none")]
    [Arguments("missing")]
    [Arguments("test-count-only")]
    [Arguments("failed-effect")]
    [Arguments("wrong-job")]
    [Arguments("wrong-attempt")]
    [Arguments("wrong-scope")]
    [Arguments("offline")]
    [Arguments("missing-installation")]
    [Arguments("source-reference")]
    [Arguments("shared-cache")]
    [Arguments("substitute-source")]
    [Arguments("different-installation")]
    [Arguments("original-bytes")]
    [Arguments("swapped-identities")]
    [Arguments("missing-identity")]
    [Arguments("missing-prerequisite")]
    public async Task NativeReportsRequireActualCompleteCaseFacts(string fault)
    {
        using var fixture = new ProducerFixture();
        fixture.WriteNativeObservations();
        string path = Path.Combine(fixture.Observations, "Infisical.json");
        MachineReport raw = Manifest.Parse<MachineReport>(File.ReadAllBytes(path));
        switch (fault)
        {
            case "missing": File.Delete(path); break;
            case "test-count-only": fixture.WriteObservation("Infisical.json", raw with { NativeCases = [] }); break;
            case "failed-effect":
                fixture.WriteObservation("Infisical.json", raw with
                {
                    NativeCases = raw.NativeCases.Select(c => c with { EffectObserved = false }).ToArray()
                });
                break;
            case "wrong-job": fixture.WriteObservation("Infisical.json", raw with { JobId = 901 }); break;
            case "wrong-attempt": fixture.WriteObservation("Infisical.json", raw with { RunAttempt = 2 }); break;
            case "wrong-scope": fixture.WriteObservation("Infisical.json", raw with { ScopeSha256 = new string('f', 64) }); break;
            case "offline": fixture.WriteObservation("Infisical.json", raw with { Purpose = "offline-verification" }); break;
            case "missing-installation": fixture.WriteObservation("Infisical.json", raw with { Installation = null }); break;
            case "source-reference":
                fixture.WriteObservation("Infisical.json", raw with
                {
                    Installation = raw.Installation! with { ProjectReferences = 1 }
                });
                break;
            case "shared-cache":
                fixture.WriteObservation("Infisical.json", raw with
                {
                    Installation = raw.Installation! with { IsolatedCache = false }
                });
                break;
            case "substitute-source":
                fixture.WriteObservation("Infisical.json", raw with
                {
                    Installation = raw.Installation! with { PackageSource = "public-feed" }
                });
                break;
            case "different-installation":
                string otherPath = Path.Combine(fixture.Observations, "AzureKeyVault.json");
                MachineReport other = Manifest.Parse<MachineReport>(File.ReadAllBytes(otherPath));
                fixture.WriteObservation("AzureKeyVault.json", other with
                {
                    Installation = other.Installation! with { OperatingSystem = "windows" }
                });
                break;
            case "original-bytes":
                fixture.WriteObservation("Infisical.json", raw with
                {
                    Packages = [raw.Packages[0] with { Sha256 = new string('f', 64) }, .. raw.Packages[1..]]
                });
                break;
            case "swapped-identities":
                fixture.WriteObservation("Infisical.json", raw with
                {
                    ProviderScopes = [raw.ProviderScopes[0] with
                    {
                        SetupIdentity = raw.ProviderScopes[0].DeniedIdentity,
                        DeniedIdentity = raw.ProviderScopes[0].SetupIdentity
                    }, .. raw.ProviderScopes[1..]]
                });
                break;
            case "missing-identity":
                JsonNode node = JsonNode.Parse(File.ReadAllBytes(path))!;
                node["providerScopes"]![0]!.AsObject().Remove("administrativeIdentity");
                fixture.WriteObservation("Infisical.json", node);
                break;
            case "missing-prerequisite":
                fixture.WriteObservation("Infisical.json", raw with { Prerequisites = raw.Prerequisites[..^1] });
                break;
        }
        if (fault == "none")
        {
            MachineReport report = Candidate.Measure(fixture.Bundle.Root, "native-operations",
                "linux-x64-net10.0", 900, fixture.Observations);
            await Assert.That(report.Discovered).IsEqualTo(report.NativeCases.Length);
            await Assert.That(report.NativeCases.Select(c => c.Provider).Distinct().Count()).IsEqualTo(2);
            await Assert.That(report.Installation).IsEqualTo(raw.Installation);
        }
        else
            await Assert.That(() => Candidate.Measure(fixture.Bundle.Root, "native-operations",
                "linux-x64-net10.0", 900, fixture.Observations)).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("runtimeIdentity")]
    [Arguments("observerIdentity")]
    [Arguments("setupIdentity")]
    [Arguments("deniedIdentity")]
    [Arguments("administrativeIdentity")]
    public async Task ProposalRequiresEveryDistinctExplicitRole(string role)
    {
        using var fixture = new ProducerFixture();
        string proposalDirectory = Path.Combine(fixture.Observations, "docs/internal/releases");
        Directory.CreateDirectory(proposalDirectory);
        ReleaseScope scope = Manifest.Parse<ReleaseScope>(
            File.ReadAllBytes(Path.Combine(fixture.Bundle.Root, "scope.json")));
        JsonNode proposal = JsonSerializer.SerializeToNode(
            new CandidateProposal(1, TestBundle.Version, "publisher", "owner", scope.ProviderScopes),
            Manifest.JsonOptions)!;
        string path = Path.Combine(proposalDirectory, "candidate.json");
        void Save() => File.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(proposal, Manifest.JsonOptions));
        Save();
        await Assert.That(Candidate.ReadProposal(fixture.Observations).ProviderScopes).IsEquivalentTo(scope.ProviderScopes);
        JsonObject selected = proposal["providerScopes"]![0]!.AsObject();
        string original = selected[role]!.GetValue<string>();
        selected.Remove(role);
        Save();
        await Assert.That(() => Candidate.ReadProposal(fixture.Observations)).Throws<ReleaseException>();
        selected[role] = role == "runtimeIdentity" ? scope.ProviderScopes[0].ObserverIdentity : scope.ProviderScopes[0].RuntimeIdentity;
        Save();
        await Assert.That(() => Candidate.ReadProposal(fixture.Observations)).Throws<ReleaseException>();
        selected[role] = "unsafe/identity";
        Save();
        await Assert.That(() => Candidate.ReadProposal(fixture.Observations)).Throws<ReleaseException>();
        selected[role] = original;
    }

    [Test]
    [Arguments("pull_request")]
    [Arguments("workflow_dispatch")]
    public async Task ManualOrPullRequestContextCannotProduce(string eventName) =>
        await Assert.That(() => Candidate.ValidateProducerContext(Manifest.RepositoryName, eventName,
            "refs/heads/main", "true", $"{Manifest.RepositoryName}/.github/workflows/verify.yml@refs/heads/main"))
            .Throws<ReleaseException>();

    [Test]
    public async Task SourceProposalWithRetainedGapCannotPrepare()
    {
        using var fixture = new ProducerFixture();
        string proposalDirectory = Path.Combine(fixture.Observations, "docs/internal/releases");
        Directory.CreateDirectory(Path.Combine(proposalDirectory, "admission"));
        ReleaseScope scope = Manifest.Parse<ReleaseScope>(File.ReadAllBytes(Path.Combine(fixture.Bundle.Root, "scope.json")));
        File.WriteAllBytes(Path.Combine(proposalDirectory, "candidate.json"),
            JsonSerializer.SerializeToUtf8Bytes(new CandidateProposal(1, TestBundle.Version, "publisher", "owner",
                scope.ProviderScopes), Manifest.JsonOptions));
        AdmissionInventory inventory = Manifest.Parse<AdmissionInventory>(
            File.ReadAllBytes(Path.Combine(fixture.Bundle.Root, "infisical.json")));
        File.WriteAllBytes(Path.Combine(proposalDirectory, "admission/infisical.json"),
            JsonSerializer.SerializeToUtf8Bytes(inventory with
            {
                Operations = inventory.Operations.Select(o => o with { Contract = "contract-gap" }).ToArray()
            }, Manifest.JsonOptions));
        await Assert.That(() => Candidate.Prepare(fixture.Observations, fixture.Bundle.Root, fixture.Output,
            TestBundle.Commit, 12, 1)).Throws<ReleaseException>();
        await Assert.That(Directory.Exists(fixture.Output)).IsFalse();
    }

    [Test]
    public async Task PreparationCopiesOneOriginalFamilyAndChecksSourceInventoryHashes()
    {
        using var fixture = new ProducerFixture();
        string proposalDirectory = Path.Combine(fixture.Observations, "docs/internal/releases");
        Directory.CreateDirectory(Path.Combine(proposalDirectory, "admission"));
        ReleaseScope scope = Manifest.Parse<ReleaseScope>(File.ReadAllBytes(Path.Combine(fixture.Bundle.Root, "scope.json")));
        File.WriteAllBytes(Path.Combine(proposalDirectory, "candidate.json"),
            JsonSerializer.SerializeToUtf8Bytes(new CandidateProposal(1, TestBundle.Version, "publisher", "owner",
                scope.ProviderScopes), Manifest.JsonOptions));
        foreach (string file in new[] { "infisical.json", "azure-key-vault.json" })
        {
            AdmissionInventory inventory = Manifest.Parse<AdmissionInventory>(
                File.ReadAllBytes(Path.Combine(fixture.Bundle.Root, file)));
            string source = inventory.Sources[0].File;
            string path = Path.Combine(fixture.Observations, source);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            byte[] sourceBytes = System.Text.Encoding.UTF8.GetBytes("// Controlled test source; no remote evidence.");
            File.WriteAllBytes(path, sourceBytes);
            File.WriteAllBytes(Path.Combine(proposalDirectory, "admission", file),
                JsonSerializer.SerializeToUtf8Bytes(inventory with
                {
                    Sources = [new(source, Manifest.Hash(sourceBytes))]
                }, Manifest.JsonOptions));
        }
        File.Copy(Path.Combine(fixture.Bundle.Root, "THIRD-PARTY-NOTICES.md"),
            Path.Combine(fixture.Observations, "THIRD-PARTY-NOTICES.md"));
        File.WriteAllText(Path.Combine(fixture.Bundle.Root, "outside-originals.snupkg"), "not copied");
        Candidate.Prepare(fixture.Observations, fixture.Bundle.Root, fixture.Output, TestBundle.Commit, 12, 1);
        CandidateInputs inputs = Candidate.ReadInputs(fixture.Output);
        await Assert.That(inputs.Manifest.Packages).IsEquivalentTo(fixture.Bundle.Data.Packages);
        await Assert.That(inputs.Manifest.Gates.Length).IsEqualTo(0);
        await Assert.That(Directory.GetFiles(fixture.Output, "*.snupkg").Length).IsEqualTo(0);
        await Assert.That(File.Exists(Path.Combine(fixture.Output, "manifest.json"))).IsFalse();
        Directory.Delete(fixture.Output, recursive: true);
        File.AppendAllText(Path.Combine(fixture.Observations, "src/SecretKit.Infisical/Client.cs"), "changed");
        await Assert.That(() => Candidate.Prepare(fixture.Observations, fixture.Bundle.Root, fixture.Output,
            TestBundle.Commit, 12, 1)).Throws<ReleaseException>();
    }

    private sealed class ProducerFixture : IDisposable
    {
        public TestBundle Bundle { get; } = new();
        public string PreparationDirectory => Bundle.Root + "-preparation";
        public string Observations => Bundle.Root + "-observations";
        public string Output => Bundle.Root + "-output";
        public DateTimeOffset Now => TestBundle.RunStart.AddMinutes(11);
        public CandidatePreparation Preparation { get; }

        public ProducerFixture()
        {
            Directory.CreateDirectory(PreparationDirectory);
            Directory.CreateDirectory(Observations);
            Bundle.Write("candidate-inputs.json", new CandidateInputs(1, "candidate-inputs-not-approved", 1,
                Bundle.Data with { Gates = [] }));
            File.Copy(Path.Combine(Bundle.OracleRoot, "THIRD-PARTY-NOTICES.md"),
                Path.Combine(Bundle.Root, "THIRD-PARTY-NOTICES.md"));
            ReportOrigin origin = Bundle.Index.Reports.First(r => r.Kind == "native-operations");
            MachineReport report = Manifest.Parse<MachineReport>(
                File.ReadAllBytes(Path.Combine(Bundle.OracleRoot, origin.Report.File)));
            Preparation = new(1, TestBundle.Commit, 12, 1, Bundle.Data.Scope.Sha256, "setup-owner", "reviewer",
                TestBundle.RunStart.AddMinutes(6), Now.AddDays(120), report.Prerequisites, Bundle.Index.Attestations);
            SavePreparation(Preparation);
            foreach (ReportOrigin item in Bundle.Index.Reports)
                EditOracle($"{item.ArtifactId}-artifact.json", n => n["expires_at"] = Now.AddDays(120));
        }

        public void SavePreparation(CandidatePreparation preparation) =>
            File.WriteAllBytes(Path.Combine(PreparationDirectory, "preparation.json"),
                JsonSerializer.SerializeToUtf8Bytes(preparation, Manifest.JsonOptions));

        public void WriteObservation<T>(string file, T value) =>
            File.WriteAllBytes(Path.Combine(Observations, file), JsonSerializer.SerializeToUtf8Bytes(value, Manifest.JsonOptions));

        public void EditOracle(string file, Action<JsonNode> edit)
        {
            string path = Path.Combine(Bundle.OracleRoot, file);
            JsonNode node = JsonNode.Parse(File.ReadAllBytes(path))!;
            edit(node);
            File.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(node));
        }

        public void WriteNativeObservations()
        {
            ReportOrigin origin = Bundle.Index.Reports.First(r => r.Kind == "native-operations");
            MachineReport raw = Manifest.Parse<MachineReport>(
                File.ReadAllBytes(Path.Combine(Bundle.OracleRoot, origin.Report.File)));
            foreach (string provider in new[] { "Infisical", "AzureKeyVault" })
            {
                NativeCaseObservation[] cases = raw.NativeCases.Where(c => c.Provider == provider).ToArray();
                WriteObservation(provider + ".json", raw with
                {
                    JobId = 900,
                    NativeCases = cases,
                    Checks = raw.Checks.Where(c => c.Key.StartsWith(provider + "/", StringComparison.Ordinal)).ToArray(),
                    Prerequisites = raw.Prerequisites.Where(p => p.Provider == provider).ToArray(),
                    Discovered = cases.Length
                });
            }
        }

        public void Dispose()
        {
            foreach (string path in new[] { Output, Observations, PreparationDirectory })
                if (Directory.Exists(path))
                    Directory.Delete(path, recursive: true);
            Bundle.Dispose();
        }
    }
}
