using System.Text.Json;

namespace SecretKit.Release.Tests;

public sealed class GateEvidenceTests
{
    [Test]
    public async Task CompleteCurrentCaseMatrixFitsOnlyTheBoundedReportContract()
    {
        DirectoryInfo? root = new(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "SecretKit.slnx")))
            root = root.Parent;
        if (root is null)
            throw new InvalidOperationException("Repository root unavailable.");
        var cases = new List<NativeCaseObservation>();
        foreach (string file in new[] { "infisical.json", "azure-key-vault.json" })
        {
            AdmissionInventory inventory = Manifest.Parse<AdmissionInventory>(
                await File.ReadAllBytesAsync(Path.Combine(root.FullName, "docs", "internal",
                    "releases", "admission", file)));
            foreach (AdmissionOperation operation in inventory.Operations)
                foreach (string variant in operation.Variants)
                    foreach (string required in operation.RequiredCases)
                        cases.Add(new(inventory.Provider, operation.Id, variant, "fixture-scope",
                            required, true, true, "fixture-control"));
        }
        MachineReport report = new(2, "fixture-only", "native-operations", "0.1.0-preview.1",
            new string('a', 40), 1, 1, 1, "linux-x64-net10.0", "fixture-environment",
            new string('a', 64), [], [], [], DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch,
            cases.Count, 0, 0, 0, [], cases.ToArray(), [], null);
        byte[] reportBytes = JsonSerializer.SerializeToUtf8Bytes(report, Manifest.JsonOptions);
        await Assert.That(reportBytes.Length > 4 * 1024 * 1024).IsTrue();
        await Assert.That(reportBytes.Length <= EvidenceLimits.ReportBytes).IsTrue();
        await Assert.That(() => Manifest.Parse<MachineReport>(reportBytes)).Throws<ReleaseException>();
        await Assert.That(Manifest.Parse<MachineReport>(reportBytes, EvidenceLimits.ReportBytes)
            .NativeCases.Length).IsEqualTo(cases.Count);
        byte[] recordBytes = JsonSerializer.SerializeToUtf8Bytes(
            new SemanticGateRecord(2, [report, report with { Platform = "windows-x64-net10.0" }], null),
            Manifest.JsonOptions);
        await Assert.That(Manifest.Parse<SemanticGateRecord>(recordBytes, EvidenceLimits.RecordBytes)
            .Reports.Length).IsEqualTo(2);
        await Assert.That(() => Manifest.Parse<MachineReport>(new byte[EvidenceLimits.ReportBytes + 1],
            EvidenceLimits.ReportBytes)).Throws<ReleaseException>();
    }

    [Test]
    public async Task SchemaOneCannotAuthorizeRelease()
    {
        using var bundle = new TestBundle();
        bundle.Data = bundle.Data with { SchemaVersion = 1 };
        bundle.Save();
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    public async Task CorrectlyHashedFalseRecordCannotAuthorizeRelease()
    {
        using var bundle = new TestBundle();
        GateRecord gate = bundle.Data.Gates.Single(g => g.Kind == "native-operations");
        GateEvidence evidence = Manifest.Parse<GateEvidence>(
            File.ReadAllBytes(Path.Combine(bundle.Root, gate.File)));
        FileDigest record = bundle.Write("false-record.json",
            new { status = "failed", discovered = 0, observed = false });
        FileDigest edited = bundle.Write(gate.File, evidence with { Record = record });
        bundle.Data = bundle.Data with
        {
            Gates = bundle.Data.Gates.Select(g => g.Kind == gate.Kind ? g with { Sha256 = edited.Sha256 } : g).ToArray()
        };
        bundle.Save();
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    public async Task ControlledIndependentOracleAllowsExactFixtureContentOnly()
    {
        using var bundle = new TestBundle();
        await Assert.That(bundle.Verify().Packages.Count).IsEqualTo(7);
        File.Delete(Path.Combine(bundle.OracleRoot, "evidence-index.json"));
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    public async Task CandidateCheckCannotMintFinalArtifactOrRunApproval()
    {
        using var bundle = new TestBundle();
        bundle.WriteRun("in_progress", null);
        File.Delete(Path.Combine(bundle.OracleRoot, "artifact-metadata.json"));
        Manifest.CheckCandidate(bundle.Root, new IndependentEvidence(bundle.OracleRoot));
        await Assert.That(await Program.Main(["candidate-check", bundle.Root, bundle.OracleRoot])).IsEqualTo(0);
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    public async Task CompletedRunAndProtectedIndependentIndexRemainMandatory()
    {
        using var bundle = new TestBundle();
        bundle.WriteRun("in_progress", null);
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
        bundle.WriteRun();
        IndependentEvidence oracle = new(bundle.OracleRoot);
        await Assert.That(() => Manifest.Verify(bundle.Root, bundle.Approval with
        {
            EvidenceSha256 = new string('0', 64)
        }, oracle)).Throws<ReleaseException>();
        await Assert.That(() => Manifest.CheckCandidate(bundle.Root, new IndependentEvidence(bundle.Root)))
            .Throws<ReleaseException>();
    }

    [Test]
    public async Task RoutineOfflineArtifactCannotBecomeAReleaseBundleFromItsWorkflowPath()
    {
        using var bundle = new TestBundle();
        // The actual routine metadata contract is checks.txt, sdk.txt and
        // packages.sha256, plus test-host TRX files, not a release manifest.
        string offline = Path.Combine(bundle.Root, "offline");
        Directory.CreateDirectory(offline);
        File.WriteAllText(Path.Combine(offline, "checks.txt"),
            $"purpose=offline-verification\nsource={TestBundle.Commit}\nversion={TestBundle.Version}\n" +
            "restore=success\nbuild=success\npack=success\ntests=success\nsamples=success\n");
        File.WriteAllText(Path.Combine(offline, "sdk.txt"), "10.0.302\n");
        File.WriteAllLines(Path.Combine(offline, "packages.sha256"),
            bundle.Data.Packages.Select(p => $"{p.Sha256}  {p.File}"));
        // Even independently successful canonical verify.yml metadata cannot
        // turn these actual offline output fields into the nine semantic gates.
        Program.VerifyArtifactMetadata(bundle.OracleRoot, bundle.Approval);
        await Assert.That(() => Manifest.CheckCandidate(offline, new IndependentEvidence(bundle.OracleRoot)))
            .Throws<ReleaseException>();
        await Assert.That(() => Manifest.Verify(offline, bundle.Approval, new IndependentEvidence(bundle.OracleRoot)))
            .Throws<ReleaseException>();
    }

    [Test]
    public async Task CorrectHashesAndIdsDoNotPermitBundledObservationSubstitution()
    {
        using var bundle = new TestBundle();
        ReportOrigin origin = bundle.Index.Reports.First(r => r.Kind == "live-conformance");
        MachineReport raw = Manifest.Parse<MachineReport>(
            File.ReadAllBytes(Path.Combine(bundle.OracleRoot, origin.Report.File)));
        // Independent observer reports failure; the bundle still claims success.
        // All raw hashes, source/run IDs and approvals are recomputed correctly.
        FileDigest digest = bundle.WriteOracle(origin.Report.File, raw with
        {
            NativeCases = [raw.NativeCases[0] with { EffectObserved = false }, .. raw.NativeCases[1..]]
        });
        bundle.Index = bundle.Index with
        {
            Reports = bundle.Index.Reports.Select(r => r == origin ? r with { Report = digest } : r).ToArray()
        };
        bundle.SaveIndex();
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("job-name")]
    [Arguments("job-id")]
    [Arguments("attempt")]
    [Arguments("artifact-name")]
    [Arguments("artifact-digest")]
    [Arguments("expired")]
    public async Task CorrectRawReportCannotComeFromAnotherJobOrArtifact(string fault)
    {
        using var bundle = new TestBundle();
        ReportOrigin origin = bundle.Index.Reports[0];
        if (fault.StartsWith("job", StringComparison.Ordinal) || fault == "attempt")
            bundle.WriteOracle($"{origin.JobId}-job.json", new
            {
                id = fault == "job-id" ? origin.JobId + 1 : origin.JobId,
                run_id = 12,
                run_attempt = fault == "attempt" ? 2 : 1,
                head_sha = TestBundle.Commit,
                name = fault == "job-name" ? "offline-linux" : $"{origin.Kind}-{origin.Platform}",
                status = "completed",
                conclusion = "success",
                started_at = TestBundle.RunStart,
                completed_at = TestBundle.RunStart.AddMinutes(4)
            });
        else
            bundle.WriteOracle($"{origin.ArtifactId}-artifact.json", new
            {
                id = origin.ArtifactId,
                expired = fault == "expired",
                digest = "sha256:" + (fault == "artifact-digest" ? new string('f', 64) : origin.ArtifactDigest),
                name = fault == "artifact-name" ? "secretkit-report-999" : $"secretkit-report-{origin.JobId}",
                workflow_run = new { id = 12, head_sha = TestBundle.Commit },
                created_at = TestBundle.RunStart.AddMinutes(3)
            });
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("missing-case")]
    [Arguments("duplicate-case")]
    [Arguments("false-case")]
    [Arguments("effect")]
    [Arguments("prerequisite")]
    [Arguments("zero")]
    [Arguments("count")]
    [Arguments("failed")]
    [Arguments("skipped")]
    [Arguments("exit")]
    [Arguments("source")]
    [Arguments("version")]
    [Arguments("run")]
    [Arguments("attempt")]
    [Arguments("job")]
    [Arguments("environment")]
    [Arguments("scope")]
    [Arguments("platform")]
    [Arguments("inventory")]
    [Arguments("package")]
    [Arguments("identity")]
    [Arguments("stale")]
    [Arguments("fixture")]
    [Arguments("offline")]
    public async Task InternallyConsistentReportsStillRequireObservedSemantics(string fault)
    {
        using var bundle = new TestBundle();
        ChangeReportAndOracle(bundle, "native-operations", r => fault switch
        {
            "missing-case" => r with { NativeCases = r.NativeCases[..^1], Discovered = r.Discovered - 1 },
            "duplicate-case" => r with { NativeCases = [.. r.NativeCases, r.NativeCases[0]], Discovered = r.Discovered + 1 },
            "false-case" => r with { NativeCases = [r.NativeCases[0] with { Passed = false }, .. r.NativeCases[1..]] },
            "effect" => r with { NativeCases = [r.NativeCases[0] with { EffectObserved = false }, .. r.NativeCases[1..]] },
            "prerequisite" => r with { Prerequisites = [r.Prerequisites[0] with { Confirmed = false }, .. r.Prerequisites[1..]] },
            "zero" => r with { Discovered = 0 },
            "count" => r with { Discovered = r.Discovered + 1 },
            "failed" => r with { Failed = 1 },
            "skipped" => r with { Skipped = 1 },
            "exit" => r with { ExitCode = 1 },
            "source" => r with { SourceCommit = new string('f', 40) },
            "version" => r with { Version = "0.2.0" },
            "run" => r with { RunId = 13 },
            "attempt" => r with { RunAttempt = 2 },
            "job" => r with { JobId = 999 },
            "environment" => r with { Environment = "offline" },
            "scope" => r with { ScopeSha256 = new string('f', 64) },
            "platform" => r with { Platform = "macos-arm64-net10.0" },
            "inventory" => r with { Inventories = r.Inventories[..^1] },
            "package" => r with { Packages = [r.Packages[0] with { Sha256 = new string('f', 64) }, .. r.Packages[1..]] },
            "identity" => r with { ProviderScopes = [r.ProviderScopes[0] with { RuntimeIdentity = "other" }, .. r.ProviderScopes[1..]] },
            "stale" => r with { StartedAt = TestBundle.RunStart.AddDays(-1) },
            "fixture" => r with { Purpose = "synthetic-fixture" },
            "offline" => r with { Purpose = "offline-verification" },
            _ => throw new InvalidOperationException()
        });
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("compatibility-install", "missing")]
    [Arguments("compatibility-install", "exit")]
    [Arguments("compatibility-install", "project")]
    [Arguments("compatibility-install", "cache")]
    [Arguments("compatibility-install", "source")]
    [Arguments("compatibility-install", "architecture")]
    [Arguments("compatibility-install", "framework")]
    [Arguments("compatibility-install", "platform")]
    [Arguments("native-operations", "missing")]
    [Arguments("native-operations", "exit")]
    [Arguments("native-operations", "project")]
    [Arguments("native-operations", "cache")]
    [Arguments("native-operations", "source")]
    [Arguments("native-operations", "architecture")]
    [Arguments("native-operations", "framework")]
    [Arguments("native-operations", "platform")]
    [Arguments("live-conformance", "missing")]
    [Arguments("live-conformance", "exit")]
    [Arguments("live-conformance", "project")]
    [Arguments("live-conformance", "cache")]
    [Arguments("live-conformance", "source")]
    [Arguments("live-conformance", "architecture")]
    [Arguments("live-conformance", "framework")]
    [Arguments("live-conformance", "platform")]
    public async Task PlatformClaimsRequireActualInstalledProcessWitness(string kind, string fault)
    {
        using var bundle = new TestBundle();
        ChangeReportAndOracle(bundle, kind, r => r with
        {
            Installation = fault switch
            {
                "missing" => null,
                "exit" => r.Installation! with { ProcessExitCode = 1 },
                "project" => r.Installation! with { ProjectReferences = 1 },
                "cache" => r.Installation! with { IsolatedCache = false },
                "source" => r.Installation! with { PackageSource = "public-feed" },
                "architecture" => r.Installation! with { Architecture = "arm64" },
                "framework" => r.Installation! with { Framework = "net9.0" },
                "platform" => r.Installation! with { OperatingSystem = "windows" },
                _ => throw new InvalidOperationException()
            }
        });
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("runtime")]
    [Arguments("observer")]
    [Arguments("setup")]
    [Arguments("denied")]
    [Arguments("administrative")]
    public async Task RehashedRawReportsCannotSwapReviewedRoleLabels(string role)
    {
        using var bundle = new TestBundle();
        ChangeReportAndOracle(bundle, "live-conformance", r =>
        {
            ProviderScope scope = r.ProviderScopes[0];
            ProviderScope changed = role switch
            {
                "runtime" => scope with { RuntimeIdentity = scope.SetupIdentity, SetupIdentity = scope.RuntimeIdentity },
                "observer" => scope with { ObserverIdentity = scope.SetupIdentity, SetupIdentity = scope.ObserverIdentity },
                "setup" => scope with { SetupIdentity = scope.DeniedIdentity, DeniedIdentity = scope.SetupIdentity },
                "denied" => scope with { DeniedIdentity = scope.AdministrativeIdentity, AdministrativeIdentity = scope.DeniedIdentity },
                "administrative" => scope with { AdministrativeIdentity = scope.RuntimeIdentity, RuntimeIdentity = scope.AdministrativeIdentity },
                _ => throw new InvalidOperationException()
            };
            return r with { ProviderScopes = [changed, .. r.ProviderScopes[1..]] };
        });
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("runtimeIdentity")]
    [Arguments("observerIdentity")]
    [Arguments("setupIdentity")]
    [Arguments("deniedIdentity")]
    [Arguments("administrativeIdentity")]
    public async Task RawMachineReportRequiresEveryRoleField(string role)
    {
        using var bundle = new TestBundle();
        JsonElement report = Manifest.Parse<JsonElement>(File.ReadAllBytes(
            Path.Combine(bundle.OracleRoot, bundle.Index.Reports[0].Report.File)));
        var node = System.Text.Json.Nodes.JsonNode.Parse(report.GetRawText())!;
        node["providerScopes"]![0]!.AsObject().Remove(role);
        await Assert.That(() => Manifest.Parse<MachineReport>(JsonSerializer.SerializeToUtf8Bytes(node)))
            .Throws<ReleaseException>();
    }

    [Test]
    [Arguments("self-review")]
    [Arguments("publisher-review")]
    [Arguments("owner-review")]
    [Arguments("wrong-owner")]
    [Arguments("stale")]
    [Arguments("false-rights")]
    [Arguments("missing-check")]
    [Arguments("no-evidence")]
    public async Task AuthorityAttestationsAreAccountableNotAutomatedPasses(string fault)
    {
        using var bundle = new TestBundle();
        AuthorityAttestation original = bundle.Index.Attestations[0];
        AuthorityAttestation changed = fault switch
        {
            "self-review" => original with { Reviewer = original.Issuer },
            "publisher-review" => original with { Reviewer = bundle.Data.Publisher },
            "owner-review" => original with { Reviewer = bundle.Data.Owner },
            "wrong-owner" => original with { Subject = "other-owner" },
            "stale" => original with { ObservedAt = TestBundle.RunStart.AddDays(-1) },
            "false-rights" => original with { Checks = [original.Checks[0] with { Passed = false }, .. original.Checks[1..]] },
            "missing-check" => original with { Checks = original.Checks[..^1] },
            "no-evidence" => original with { EvidenceLocator = "" },
            _ => throw new InvalidOperationException()
        };
        bundle.Index = bundle.Index with
        {
            Attestations = bundle.Index.Attestations.Select(a => a == original ? changed : a).ToArray()
        };
        bundle.SaveIndex();
        bundle.EditRecord(original.Kind, r => r with { Attestation = changed });
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    public async Task IndependentReportArchiveIsDigestBoundAndHasOneBoundedEntry()
    {
        using var bundle = new TestBundle();
        MachineReport report = Manifest.Parse<MachineReport>(File.ReadAllBytes(
            Path.Combine(bundle.OracleRoot, bundle.Index.Reports[0].Report.File)));
        byte[] archive = ArchiveTests.Zip(("report.json", JsonSerializer.Serialize(report, Manifest.JsonOptions)));
        File.WriteAllBytes(Path.Combine(bundle.Root, "400.zip"), archive);
        Program.ExtractReport(bundle.Root, 400, Manifest.Hash(archive), bundle.OracleRoot);
        await Assert.That(Manifest.Parse<MachineReport>(
            File.ReadAllBytes(Path.Combine(bundle.OracleRoot, "400-report.json"))).JobId).IsEqualTo(report.JobId);
        await Assert.That(() => Program.ExtractReport(bundle.Root, 400, new string('f', 64), bundle.OracleRoot))
            .Throws<ReleaseException>();
        byte[] extra = ArchiveTests.Zip(("report.json", "{}"), ("extra.json", "{}"));
        File.WriteAllBytes(Path.Combine(bundle.Root, "401.zip"), extra);
        await Assert.That(() => Program.ExtractReport(bundle.Root, 401, Manifest.Hash(extra), bundle.OracleRoot))
            .Throws<ReleaseException>();
        byte[] oversized = ArchiveTests.Zip(("report.json", new string('x', 4 * 1024 * 1024 + 1)));
        File.WriteAllBytes(Path.Combine(bundle.Root, "402.zip"), oversized);
        await Assert.That(() => Program.ExtractReport(bundle.Root, 402, Manifest.Hash(oversized), bundle.OracleRoot))
            .Throws<ReleaseException>();
    }

    [Test]
    public async Task UnrecognizedRawMaterialCannotEnterTypedReportsOrDiagnostics()
    {
        using var bundle = new TestBundle();
        byte[] bytes = File.ReadAllBytes(Path.Combine(bundle.OracleRoot, bundle.Index.Reports[0].Report.File));
        var document = System.Text.Json.Nodes.JsonNode.Parse(bytes)!;
        document["responseBody"] = "protected-canary-do-not-log";
        await Assert.That(() => Manifest.Parse<MachineReport>(JsonSerializer.SerializeToUtf8Bytes(document)))
            .Throws<ReleaseException>();
    }

    [Test]
    public void SerializedEvidenceDocumentsMatchTheirPublishedSchemaFields()
    {
        using var bundle = new TestBundle();
        DirectoryInfo? root = new(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "SecretKit.slnx")))
            root = root.Parent;
        if (root is null) throw new InvalidOperationException("Repository root unavailable.");
        JsonElement schema = Manifest.Parse<JsonElement>(
            File.ReadAllBytes(Path.Combine(root.FullName, "docs/internal/releases/manifest.schema.json")));
        JsonElement definitions = schema.GetProperty("$defs");
        void Check(string definition, byte[] bytes)
        {
            JsonElement actual = Manifest.Parse<JsonElement>(bytes);
            JsonElement contract = definitions.GetProperty(definition);
            Manifest.ExactSet(actual.EnumerateObject().Select(p => p.Name),
                contract.GetProperty("required").EnumerateArray().Select(p => p.GetString()!), "schema-required-fields");
            Manifest.ExactSet(actual.EnumerateObject().Select(p => p.Name),
                contract.GetProperty("properties").EnumerateObject().Select(p => p.Name), "schema-properties");
        }
        Check("scope", File.ReadAllBytes(Path.Combine(bundle.Root, bundle.Data.Scope.File)));
        ReleaseScope scope = Manifest.Parse<ReleaseScope>(
            File.ReadAllBytes(Path.Combine(bundle.Root, bundle.Data.Scope.File)));
        Check("providerScope", JsonSerializer.SerializeToUtf8Bytes(scope.ProviderScopes[0], Manifest.JsonOptions));
        Check("evidenceIndex", File.ReadAllBytes(Path.Combine(bundle.OracleRoot, "evidence-index.json")));
        foreach (GateRecord gate in bundle.Data.Gates)
        {
            byte[] gateBytes = File.ReadAllBytes(Path.Combine(bundle.Root, gate.File));
            Check("gateEvidence", gateBytes);
            GateEvidence evidence = Manifest.Parse<GateEvidence>(gateBytes);
            Check("semanticGateRecord", File.ReadAllBytes(Path.Combine(bundle.Root, evidence.Record.File)));
        }
        foreach (ReportOrigin report in bundle.Index.Reports)
        {
            Check("reportOrigin", JsonSerializer.SerializeToUtf8Bytes(report, Manifest.JsonOptions));
            Check("machineReport", File.ReadAllBytes(Path.Combine(bundle.OracleRoot, report.Report.File)));
            MachineReport raw = Manifest.Parse<MachineReport>(
                File.ReadAllBytes(Path.Combine(bundle.OracleRoot, report.Report.File)));
            if (raw.Installation is not null)
                Check("installation", JsonSerializer.SerializeToUtf8Bytes(raw.Installation, Manifest.JsonOptions));
        }
        Check("attestation", JsonSerializer.SerializeToUtf8Bytes(bundle.Index.Attestations[0], Manifest.JsonOptions));
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task IndependentReportDenominatorCannotBeOmittedOrDuplicated(bool duplicate)
    {
        using var bundle = new TestBundle();
        bundle.Index = bundle.Index with
        {
            Reports = duplicate ? [.. bundle.Index.Reports, bundle.Index.Reports[0]] : bundle.Index.Reports[..^1]
        };
        bundle.SaveIndex();
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    private static void ChangeReportAndOracle(TestBundle bundle, string kind, Func<MachineReport, MachineReport> change)
    {
        ReportOrigin origin = bundle.Index.Reports.First(r => r.Kind == kind);
        MachineReport original = Manifest.Parse<MachineReport>(
            File.ReadAllBytes(Path.Combine(bundle.OracleRoot, origin.Report.File)));
        MachineReport changed = change(original);
        FileDigest digest = bundle.WriteOracle(origin.Report.File, changed);
        bundle.Index = bundle.Index with
        {
            Reports = bundle.Index.Reports.Select(r => r == origin ? r with { Report = digest } : r).ToArray()
        };
        bundle.SaveIndex();
        bundle.EditRecord(kind, record => record with
        {
            Reports = record.Reports.Select(r => r.Platform == original.Platform ? changed : r).ToArray()
        });
    }
}
