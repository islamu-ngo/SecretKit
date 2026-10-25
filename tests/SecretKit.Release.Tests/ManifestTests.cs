using System.Text;

namespace SecretKit.Release.Tests;

public sealed class ManifestTests
{
    [Test]
    public async Task LocalQualificationCannotBecomePublicCandidateOrVerifiedRelease()
    {
        using var local = new LocalQualificationTests.LocalFixture();
        await Assert.That(await Program.Main(["local-prepare", local.Source, local.Packages, local.Output]))
            .IsEqualTo(0);
        using var bundle = new TestBundle();
        byte[] bytes = File.ReadAllBytes(local.RecordPath);
        File.WriteAllBytes(Path.Combine(bundle.Root, "manifest.json"), bytes);
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
        await Assert.That(() => Manifest.CheckCandidate(bundle.Root, new IndependentEvidence(bundle.OracleRoot)))
            .Throws<ReleaseException>();
        await Assert.That(Directory.Exists(bundle.JournalPath)).IsFalse();
    }

    [Test]
    [Arguments("runtime")]
    [Arguments("observer")]
    [Arguments("setup")]
    [Arguments("denied")]
    [Arguments("administrative")]
    public async Task ProtectedScopeRequiresDistinctSafeRoles(string role)
    {
        using var bundle = new TestBundle();
        ReleaseScope scope = Manifest.Parse<ReleaseScope>(
            File.ReadAllBytes(Path.Combine(bundle.Root, bundle.Data.Scope.File)));
        ProviderScope selected = scope.ProviderScopes[0];
        ProviderScope duplicate = role switch
        {
            "runtime" => selected with { RuntimeIdentity = selected.SetupIdentity },
            "observer" => selected with { ObserverIdentity = selected.RuntimeIdentity },
            "setup" => selected with { SetupIdentity = selected.DeniedIdentity },
            "denied" => selected with { DeniedIdentity = selected.AdministrativeIdentity },
            "administrative" => selected with { AdministrativeIdentity = selected.ObserverIdentity },
            _ => throw new InvalidOperationException()
        };
        bundle.ReviewScope(scope with { ProviderScopes = [duplicate, .. scope.ProviderScopes[1..]] });
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("historical")]
    [Arguments("duplicate-operation")]
    [Arguments("duplicate-variant")]
    [Arguments("missing-variant")]
    [Arguments("missing-case")]
    [Arguments("source-copy")]
    [Arguments("platform")]
    [Arguments("duplicate-scope")]
    [Arguments("depth")]
    public async Task ReviewedScopeCannotShrinkOrReplaceCurrentAdmission(string fault)
    {
        using var bundle = new TestBundle();
        ReleaseScope scope = Manifest.Parse<ReleaseScope>(File.ReadAllBytes(Path.Combine(bundle.Root, bundle.Data.Scope.File)));
        if (fault is "platform" or "duplicate-scope" or "depth" or "missing-variant")
        {
            bundle.ReviewScope(fault switch
            {
                "platform" => scope with { Platforms = ["linux-x64-net10.0"] },
                "duplicate-scope" => scope with { NativeOperations = [.. scope.NativeOperations, scope.NativeOperations[0]] },
                "depth" => scope with { Policy = "offline-only" },
                "missing-variant" => scope with { NativeOperations = scope.NativeOperations[..^1] },
                _ => throw new InvalidOperationException()
            });
        }
        else
        {
            AdmissionInventory inventory = Manifest.Parse<AdmissionInventory>(
                File.ReadAllBytes(Path.Combine(bundle.Root, "infisical.json")));
            AdmissionInventory changed = fault switch
            {
                "historical" => inventory with { Kind = "ContractResearchOnly" },
                "duplicate-operation" => inventory with { Operations = [.. inventory.Operations, inventory.Operations[0]] },
                "duplicate-variant" => inventory with
                {
                    Operations = [inventory.Operations[0] with { Variants = ["selected-version", "selected-version"] }]
                },
                "missing-case" => inventory with { Operations = [inventory.Operations[0] with { RequiredCases = [] }] },
                "source-copy" => inventory with { Exclusions = ["Unreviewed bundled exclusion."] },
                _ => throw new InvalidOperationException()
            };
            FileDigest file = bundle.Write("infisical.json", changed);
            if (fault != "source-copy")
                bundle.WriteOracle("infisical.json", changed);
            bundle.Index = bundle.Index with
            {
                Inventories = bundle.Index.Inventories.Select(i => i.File == file.File ? file : i).ToArray()
            };
            bundle.SaveIndex();
            bundle.ReviewScope(scope with
            {
                Inventories = scope.Inventories.Select(i => i.File == file.File ? file : i).ToArray()
            });
        }
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CurrentAdmissionCannotBeIncompleteOrOmittedFromScope(bool omit)
    {
        using var bundle = new TestBundle();
        ReleaseScope scope = Manifest.Parse<ReleaseScope>(File.ReadAllBytes(Path.Combine(bundle.Root, bundle.Data.Scope.File)));
        AdmissionInventory original = Manifest.Parse<AdmissionInventory>(
            File.ReadAllBytes(Path.Combine(bundle.Root, "infisical.json")));
        AdmissionInventory changed = original with
        {
            Operations = omit
                ? [.. original.Operations, original.Operations[0] with { Id = "additional", Member = "Other.ReadAsync" }]
                : [original.Operations[0] with { Contract = "contract-gap" }]
        };
        FileDigest registry = bundle.Write("infisical.json", changed);
        bundle.WriteOracle("infisical.json", changed);
        bundle.Index = bundle.Index with
        {
            Inventories = bundle.Index.Inventories.Select(r => r.File == registry.File ? registry : r).ToArray()
        };
        bundle.SaveIndex();
        bundle.ReviewScope(scope with
        {
            Inventories = scope.Inventories.Select(r => r.File == registry.File ? registry : r).ToArray()
        });
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    public async Task ExactSevenPackageFamilyAndAllGatesAreRequired()
    {
        using var bundle = new TestBundle();
        await Assert.That(bundle.Verify().Packages.Count).IsEqualTo(7);
        bundle.Data = bundle.Data with { Packages = bundle.Data.Packages[..^1] };
        bundle.Save();
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("version")]
    [Arguments("source")]
    [Arguments("prefix")]
    [Arguments("artifact")]
    [Arguments("environment")]
    [Arguments("gate")]
    [Arguments("hash")]
    public async Task ReviewedManifestCannotRelaxBindingGates(string fault)
    {
        using var bundle = new TestBundle();
        bundle.Data = fault switch
        {
            "version" => bundle.Data with { Version = "0.2.0" },
            "source" => bundle.Data with { SourceCommit = new string('d', 40) },
            "prefix" => bundle.Data with { Prefix = "Secret*" },
            "artifact" => bundle.Data with { SourceRunId = 13 },
            "environment" => bundle.Data with { Environment = "unprotected" },
            "gate" => bundle.Data with { Gates = bundle.Data.Gates[..^1] },
            "hash" => bundle.Data with { NoticesSha256 = new string('0', 64) },
            _ => throw new InvalidOperationException()
        };
        bundle.Save();
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    public async Task MissingNativeCoverageCannotPassWithAValidEvidenceHash()
    {
        using var bundle = new TestBundle();
        GateRecord original = bundle.Data.Gates.Single(g => g.Kind == "native-operations");
        GateEvidence evidence = Manifest.Parse<GateEvidence>(File.ReadAllBytes(Path.Combine(bundle.Root, original.File)));
        FileDigest edited = bundle.Write(original.File, evidence with { Checks = evidence.Checks[..^1] });
        bundle.Data = bundle.Data with
        {
            Gates = bundle.Data.Gates.Select(g => g.Kind == original.Kind ? g with { Sha256 = edited.Sha256 } : g).ToArray()
        };
        bundle.Save();
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }

    [Test]
    public async Task EvidenceBytesAndArtifactsMustMatchTheirApprovedHashes()
    {
        using var bundle = new TestBundle();
        File.AppendAllText(Path.Combine(bundle.Root, "live-conformance.json"), " ");
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
        await Assert.That(() => Manifest.Verify(bundle.Root, bundle.Approval with { ManifestSha256 = new string('e', 64) },
            new IndependentEvidence(bundle.OracleRoot)))
            .Throws<ReleaseException>();
    }

    [Test]
    public async Task DuplicateJsonFieldsAndTraversalReferencesAreRejected()
    {
        await Assert.That(() => Manifest.Parse<FileDigest>(Encoding.UTF8.GetBytes(
            """{"file":"a","file":"b","sha256":"x"}"""))).Throws<ReleaseException>();
        using var bundle = new TestBundle();
        await Assert.That(() => Manifest.ReadFile(bundle.Root, "../manifest.json", 10000)).Throws<ReleaseException>();
    }

    [Test]
    public async Task NuspecIdentityIsCheckedEvenAfterHashApproval()
    {
        using var bundle = new TestBundle();
        PackageRecord package = bundle.Data.Packages[0];
        byte[] bytes = ArchiveTests.Zip(("wrong.nuspec", "<package/>"));
        File.WriteAllBytes(Path.Combine(bundle.Root, package.File), bytes);
        bundle.Data = bundle.Data with
        {
            Packages = bundle.Data.Packages.Select(p => p.Id == package.Id ? p with { Sha256 = Manifest.Hash(bytes) } : p).ToArray()
        };
        GateRecord provenance = bundle.Data.Gates.Single(g => g.Kind == "provenance");
        GateEvidence evidence = Manifest.Parse<GateEvidence>(File.ReadAllBytes(Path.Combine(bundle.Root, provenance.File)));
        FileDigest reviewed = bundle.Write(provenance.File, evidence with
        {
            Checks = [TestBundle.Commit, .. bundle.Data.Packages.Select(p => p.Sha256)]
        });
        bundle.Data = bundle.Data with
        {
            Gates = bundle.Data.Gates.Select(g => g.Kind == "provenance" ? g with { Sha256 = reviewed.Sha256 } : g).ToArray()
        };
        bundle.Save();
        await Assert.That(bundle.Verify).Throws<ReleaseException>();
    }
}
