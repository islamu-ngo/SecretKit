using System.Text;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class ManifestTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AdmittedRegistryCannotBeIncompleteOrOmittedFromScope(bool omit)
    {
        using var bundle = new TestBundle();
        ReleaseScope scope = Manifest.Parse<ReleaseScope>(File.ReadAllBytes(Path.Combine(bundle.Root, bundle.Data.Scope.File)));
        FileDigest registry = bundle.Write("infisical-operations.json", new
        {
            provider = "Infisical",
            operations = omit
                ? new[] { new { id = "read", admitted = true, implemented = true, liveVerified = true },
                    new { id = "additional", admitted = true, implemented = true, liveVerified = true } }
                : [new { id = "read", admitted = true, implemented = false, liveVerified = false }]
        });
        bundle.ReviewScope(scope with
        {
            Registries = scope.Registries.Select(r => r.File == registry.File ? registry : r).ToArray()
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
        await Assert.That(() => Manifest.Verify(bundle.Root, bundle.Approval with { ManifestSha256 = new string('e', 64) }))
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
