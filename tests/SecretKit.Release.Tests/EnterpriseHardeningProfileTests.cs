using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class EnterpriseHardeningProfileTests
{
    [Test]
    public async Task ExactControlledBindingDoesNotGrantNativeQualification()
    {
        using var fixture = new Fixture();
        var result = fixture.Admit();
        await Assert.That(result.Status).IsEqualTo("bindings-matched");
        await Assert.That(result.NativeQualified).IsFalse();
    }

    [Test]
    [Arguments("profileSha256")]
    [Arguments("sourceRevision")]
    [Arguments("sourceContentSha256")]
    [Arguments("runId")]
    [Arguments("sdk")]
    [Arguments("runtime")]
    [Arguments("platform")]
    [Arguments("evidenceSha256")]
    [Arguments("cohortSha256")]
    [Arguments("transportSha256")]
    [Arguments("deploymentSha256")]
    [Arguments("principalSha256")]
    [Arguments("policySha256")]
    [Arguments("effectSha256")]
    [Arguments("authorizationSha256")]
    public async Task IndependentlySelectedBindingRejectsSubstitutedEvidence(string field)
    {
        using var fixture = new Fixture(native: true);
        var wire = fixture.Wire;
        wire["binding"]![field] = field switch
        {
            "sourceRevision" => Manifest.Hash("different-source"u8.ToArray())[..40],
            "runId" => "older-run",
            "sdk" => "10.0.303",
            "runtime" => "10.0.11",
            "platform" => "win-x64",
            _ => Manifest.Hash(System.Text.Encoding.UTF8.GetBytes(field + "-substituted"))
        };
        fixture.Write(wire);
        await Assert.That(() => fixture.Admit()).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("archive")]
    [Arguments("duplicate-archive")]
    [Arguments("duplicate-case")]
    [Arguments("foreign-case")]
    [Arguments("missing-case")]
    [Arguments("foreign-profile")]
    [Arguments("controlled-promotion")]
    [Arguments("native-promotion")]
    [Arguments("missing-effect")]
    [Arguments("unknown")]
    [Arguments("duplicate-property")]
    [Arguments("null-binding")]
    [Arguments("explicit-null")]
    [Arguments("oversize")]
    [Arguments("depth")]
    public async Task MalformedOrPromotedClaimsRejectBeforeAdmission(string defect)
    {
        using var fixture = new Fixture(native: defect != "controlled-promotion");
        var wire = fixture.Wire;
        switch (defect)
        {
            case "archive": wire["binding"]!["archives"]![0]!["sha256"] = Manifest.Hash("other"u8.ToArray()); break;
            case "duplicate-archive": wire["binding"]!["archives"]!.AsArray().Add(wire["binding"]!["archives"]![0]!.DeepClone()); break;
            case "duplicate-case": wire["scenarioIds"]!.AsArray().Add("S24"); break;
            case "foreign-case": wire["scenarioIds"] = new JsonArray("RH01"); break;
            case "missing-case": wire["scenarioIds"] = new JsonArray(); break;
            case "foreign-profile": wire["profile"] = "runtime-hardening"; break;
            case "controlled-promotion" or "native-promotion": wire["nativeQualified"] = true; break;
            case "missing-effect": wire["binding"]!.AsObject().Remove("effectSha256"); break;
            case "unknown": wire["binding"]!["tokenProof"] = true; break;
            case "null-binding": wire["binding"] = null; break;
            case "explicit-null": wire["binding"]!["graphSha256"] = null; break;
        }
        string json = wire.ToJsonString();
        if (defect == "duplicate-property") json = "{\"schemaVersion\":1," + json[1..];
        if (defect == "oversize") json += new string(' ', EnterpriseHardeningProfile.MaximumBytes);
        if (defect == "depth") json = "{\"x\":" + new string('[', 17) + "0" + new string(']', 17) + "}";
        File.WriteAllText(Path.Combine(fixture.Directory, "observation.json"), json);
        await Assert.That(() => fixture.Admit()).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("Infisical", "G1")]
    [Arguments("AzureKeyVault", "G2")]
    public async Task DigestConsistentNativeDeclarationRetainsUnavailableGate(string provider, string gate)
    {
        using var fixture = new Fixture(native: true);
        var result = EnterpriseHardeningProfile.Admit(fixture.Directory, "observation.json",
            fixture.Expected with { Provider = provider });
        await Assert.That(result.Status).IsEqualTo("unavailable");
        await Assert.That(result.Gate).IsEqualTo(gate);
        await Assert.That(result.NativeQualified).IsFalse();
    }

    [Test]
    [Arguments("failed")]
    [Arguments("unavailable")]
    public async Task NonPassingObservationCannotBecomeBindingSuccess(string status)
    {
        using var fixture = new Fixture();
        var wire = fixture.Wire;
        wire["status"] = status;
        fixture.Write(wire);
        await Assert.That(fixture.Admit().Status).IsEqualTo(status);
    }

    [Test]
    [Arguments("../observation.json")]
    [Arguments("/observation.json")]
    [Arguments("nested/observation.json")]
    public async Task ObservationPathsStayInsideSelectedDirectory(string name)
    {
        using var fixture = new Fixture();
        await Assert.That(() => EnterpriseHardeningProfile.Admit(fixture.Directory, name, fixture.Expected))
            .Throws<ReleaseException>();
    }

    [Test]
    public async Task LinkedObservationCannotSubstituteOutsideBytes()
    {
        using var fixture = new Fixture();
        File.CreateSymbolicLink(Path.Combine(fixture.Directory, "link.json"),
            Path.Combine(fixture.Directory, "observation.json"));
        await Assert.That(() => EnterpriseHardeningProfile.Admit(fixture.Directory, "link.json", fixture.Expected))
            .Throws<ReleaseException>();
    }

    [Test]
    [Arguments("unknown-mode")]
    [Arguments("missing-mode")]
    [Arguments("changed-subset")]
    [Arguments("duplicate-case")]
    [Arguments("null-subset")]
    public async Task InstalledDeclarationCannotOmitOrReplaceAReviewedSubset(string defect)
    {
        using var fixture = new SourceFixture();
        string directory = Path.Combine(fixture.Source, "docs", "internal", "compatibility");
        string path = Path.Combine(directory, "enterprise-hardening-profile.json");
        JsonNode declaration = JsonNode.Parse(File.ReadAllBytes(path))!;
        JsonObject modes = declaration["installedModes"]!.AsObject();
        switch (defect)
        {
            case "unknown-mode": modes["other"] = modes["minimal"]!.DeepClone(); break;
            case "missing-mode": modes.Remove("hosting"); break;
            case "changed-subset": modes["minimal"]![0] = "S01"; break;
            case "duplicate-case": modes["full"]!.AsArray().Add("S25"); break;
            case "null-subset": modes["minimal"] = null; break;
        }
        File.WriteAllText(path, declaration.ToJsonString());

        await Assert.That(() => EnterpriseHardeningProfile.ReadDeclaration(directory)).Throws<ReleaseException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CommandReopensSelectedBytesAndCannotPromoteAContentCheck(bool substitute)
    {
        using var fixture = new SourceFixture();
        fixture.WriteObservation(fixture.Select());
        if (substitute) File.AppendAllText(Path.Combine(fixture.Source, "changed.cs"), "// changed");

        int exit = await Program.Main(["enterprise-hardening-check", fixture.Source,
            Path.Combine(fixture.Root, "selection.json"), Path.Combine(fixture.Root, "observation.json")]);

        await Assert.That(exit).IsEqualTo(substitute ? 1 : 0);
    }

    [Test]
    public async Task SourceSelectionReadsOriginalBytesWithoutACandidate()
    {
        using var fixture = new SourceFixture();
        EnterpriseHardeningExpectation selected = fixture.Select();
        fixture.WriteObservation(selected);

        var result = EnterpriseHardeningProfile.Admit(fixture.Root, "observation.json", selected);
        await Assert.That(result.Status).IsEqualTo("bindings-matched");
        await Assert.That(selected.Binding.EvidenceSha256).IsEqualTo(Manifest.Hash("observed-source-test"u8.ToArray()));
        await Assert.That(selected.Binding.Archives).IsNull();
        await Assert.That(result.NativeQualified).IsFalse();
    }

    [Test]
    [Arguments("source")]
    [Arguments("profile")]
    [Arguments("evidence")]
    public async Task ReopenedOriginalInputsRejectOldObservation(string changed)
    {
        using var fixture = new SourceFixture();
        fixture.WriteObservation(fixture.Select());
        switch (changed)
        {
            case "source": File.WriteAllText(Path.Combine(fixture.Source, "source.cs"), "// changed source"); break;
            case "profile": File.AppendAllText(fixture.Profile, "\n"); break;
            case "evidence":
                byte[] bytes = "new-observation"u8.ToArray();
                File.WriteAllBytes(Path.Combine(fixture.Root, "evidence.json"), bytes);
                fixture.Selection = fixture.Selection with { Proofs = new(new("evidence.json", Manifest.Hash(bytes))) };
                fixture.WriteSelection();
                break;
        }

        var current = fixture.Select();
        await Assert.That(() => EnterpriseHardeningProfile.Admit(fixture.Root, "observation.json", current))
            .Throws<ReleaseException>();
    }

    [Test]
    [Arguments("Evidence")]
    [Arguments("Transport")]
    [Arguments("Deployment")]
    [Arguments("Principal")]
    [Arguments("Policy")]
    [Arguments("Effect")]
    [Arguments("Graph")]
    [Arguments("Authorization")]
    public async Task SelectedProofRequiresActualIndependentlyHashedFile(string field)
    {
        using var fixture = new SourceFixture();
        var selected = JsonSerializer.SerializeToNode(fixture.Selection, EnterpriseHardeningProfile.JsonOptions)!;
        selected["proofs"]![char.ToLowerInvariant(field[0]) + field[1..]] =
            JsonSerializer.SerializeToNode(new FileDigest("evidence.json", Manifest.Hash("substitution"u8.ToArray())),
                EnterpriseHardeningProfile.JsonOptions);
        File.WriteAllText(Path.Combine(fixture.Root, "selection.json"), selected.ToJsonString());
        await Assert.That(() => fixture.Select()).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("denominator")]
    [Arguments("scenario")]
    [Arguments("gate")]
    [Arguments("unknown")]
    [Arguments("duplicate")]
    [Arguments("native")]
    public async Task DeclarationCannotChangeHistoricalCoverageOrClaimResults(string defect)
    {
        using var fixture = new SourceFixture();
        var wire = JsonNode.Parse(File.ReadAllBytes(fixture.Profile))!;
        switch (defect)
        {
            case "denominator": wire["preservedDenominators"]!["fullNative"] = 28; break;
            case "scenario": wire["scenarioIds"]!.AsArray().RemoveAt(0); break;
            case "gate": wire["gates"]!.AsArray().RemoveAt(0); break;
            case "unknown": wire["observations"] = new JsonArray(); break;
            case "native": wire["nativeQualified"] = true; break;
        }
        string json = wire.ToJsonString();
        if (defect == "duplicate") json = "{\"schemaVersion\":1," + json[1..];
        File.WriteAllText(fixture.Profile, json);
        await Assert.That(() => EnterpriseHardeningProfile.ReadDeclaration(Path.GetDirectoryName(fixture.Profile)!))
            .Throws<ReleaseException>();
    }

    private sealed class SourceFixture : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "enterprise-source-" + Guid.NewGuid().ToString("N"));
        internal string Source => Path.Combine(Root, "source");
        internal string Profile => Path.Combine(Source, "docs/internal/compatibility/enterprise-hardening-profile.json");
        internal EnterpriseHardeningSelection Selection { get; set; }

        internal SourceFixture()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Profile)!);
            DirectoryInfo? repository = new(AppContext.BaseDirectory);
            while (repository is not null && !File.Exists(Path.Combine(repository.FullName, "SecretKit.slnx")))
                repository = repository.Parent;
            if (repository is null) throw new InvalidOperationException("test-repository");
            File.Copy(Path.Combine(repository.FullName, "docs/internal/compatibility/enterprise-hardening-profile.json"), Profile);
            byte[] evidence = "observed-source-test"u8.ToArray();
            File.WriteAllBytes(Path.Combine(Root, "evidence.json"), evidence);
            Selection = new(1, "enterprise-hardening", "source-offline", ["S24"], "infisical-runtime",
                Manifest.Hash("selected-revision"u8.ToArray())[..40], "selected-run", "10.0.302", "10.0.10", "linux-x64",
                new(new("evidence.json", Manifest.Hash(evidence))));
            WriteSelection();
        }

        internal void WriteSelection() => File.WriteAllBytes(Path.Combine(Root, "selection.json"),
            JsonSerializer.SerializeToUtf8Bytes(Selection, EnterpriseHardeningProfile.JsonOptions));
        internal EnterpriseHardeningExpectation Select() => EnterpriseHardeningProfile.Select(Source, null, Root, "selection.json");
        internal void WriteObservation(EnterpriseHardeningExpectation expected) =>
            File.WriteAllBytes(Path.Combine(Root, "observation.json"), JsonSerializer.SerializeToUtf8Bytes(
                new EnterpriseHardeningObservation(1, "enterprise-hardening", expected.Kind,
                    expected.ScenarioIds, "passed", false, expected.Binding), EnterpriseHardeningProfile.JsonOptions));
        public void Dispose() => Directory.Delete(Root, recursive: true);
    }

    private sealed class Fixture : IDisposable
    {
        internal string Directory { get; } = Path.Combine(Path.GetTempPath(), "enterprise-admission-" + Guid.NewGuid().ToString("N"));
        internal EnterpriseHardeningExpectation Expected { get; }
        internal JsonObject Wire { get; }

        internal Fixture(bool native = false)
        {
            System.IO.Directory.CreateDirectory(Directory);
            string Hash(string label) => Manifest.Hash(System.Text.Encoding.UTF8.GetBytes(label));
            var binding = new EnterpriseHardeningBinding(Hash("profile"), Hash("source")[..40], Hash("content"),
                "selected-run", "10.0.302", "10.0.10", "linux-x64", Hash("independent-evidence"))
            {
                Archives = [new("SecretKit.Core", "0.2.0-test.1", Hash("original-archive"))],
                CohortSha256 = Hash("cohort"),
                TransportSha256 = Hash("network"),
                DeploymentSha256 = native ? Hash("deployment") : null,
                PrincipalSha256 = native ? Hash("principal") : null,
                PolicySha256 = native ? Hash("policy") : null,
                EffectSha256 = native ? Hash("effect") : null,
                AuthorizationSha256 = native ? Hash("authorization") : null
            };
            Expected = new(native ? "native-observation" : "controlled-installed-offline", ["S24"],
                native ? "Infisical" : null, binding);
            Wire = JsonSerializer.SerializeToNode(new EnterpriseHardeningObservation(1, "enterprise-hardening",
                Expected.Kind, ["S24"], "passed", false, binding), EnterpriseHardeningProfile.JsonOptions)!.AsObject();
            Write(Wire);
        }

        internal void Write(JsonObject wire) => File.WriteAllText(Path.Combine(Directory, "observation.json"), wire.ToJsonString());
        internal EnterpriseHardeningAdmission Admit() =>
            EnterpriseHardeningProfile.Admit(Directory, "observation.json", Expected);
        public void Dispose() => System.IO.Directory.Delete(Directory, recursive: true);
    }
}
