using System.IO.Compression;
using System.Reflection.Metadata;
using System.Text.Json;
using SecretKit.Release;
using SecretKit.TestFixtures;

namespace SecretKit.Package.Tests;

public sealed class PackageDebuggingTests
{
    [Test]
    public async Task SelectedOriginalSymbolsBindExactCapturedCompileInputs()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        string originals = Required("SECRETKIT_INTEGRATION_QUALITY_ORIGINALS");
        string version = Required("SECRETKIT_INTEGRATION_QUALITY_VERSION");
        string symbols = Required("SECRETKIT_INTEGRATION_QUALITY_SYMBOLS");
        LocalPackageCandidate candidate = LocalPackageCandidate.Select(originals, version);
        var observations = new Dictionary<string, LocalDebuggingEvidence>();
        foreach (string id in LocalPackageCandidate.PackageIds)
        {
            Console.WriteLine("Inspecting exact archive symbols for " + id);
            ArchiveContent symbolContents = PackageArchive.Read(
                File.ReadAllBytes(Path.Combine(symbols, $"{id}.{version}.snupkg")));
            using (MetadataReaderProvider metadata = MetadataReaderProvider.FromPortablePdbStream(
                new MemoryStream(symbolContents.Files[$"lib/net10.0/{id}.pdb"], writable: false)))
            {
                MetadataReader reader = metadata.GetMetadataReader();
                foreach (string name in reader.Documents.Select(h => reader.GetString(reader.GetDocument(h).Name))
                    .Where(name => name.Contains("Refit", StringComparison.Ordinal)).Take(64))
                    Console.WriteLine("Generated symbol document: " + name);
            }
            using ZipArchive archive = ZipFile.OpenRead(candidate.ArchivePath(id));
            await PackageInstallTests.VerifyXmlDocumentationAsync(archive, id);
            LocalDebuggingEvidence evidence = LocalQualification.VerifyDebugging(
                root, candidate.ArchivePath(id), Path.Combine(symbols, $"{id}.{version}.snupkg"), id);
            await Assert.That(evidence.RemoteSource).IsEqualTo("unverified");
            await Assert.That(evidence.Documents.Any(d => d.Kind == "captured-source")).IsTrue();
            observations.Add(id, evidence);
        }
        LocalProfile profile = LocalQualification.ReadProfile(root);
        await Assert.That(profile.Version).IsEqualTo(version);
        await Assert.That(profile.Operations.Length).IsEqualTo(8);
        await Assert.That(profile.Scenarios.Length).IsEqualTo(16);
        string output = Path.Combine(root, "artifacts/integration-quality/debugging", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(output);
        await File.WriteAllTextAsync(Path.Combine(output, "debugging.json"), JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            profile = "integration-quality",
            kind = "controlled-artifact-offline",
            nativeQualified = false,
            version,
            denominator = Enumerable.Range(1, 20).Select(i => $"IQ-S{i:D2}").ToArray(),
            scenarios = new[]
            {
                new { id = "IQ-S19", status = "passed", subset = "selected-archive-xml-portable-pdb-local-source" },
                new { id = "IQ-S20", status = "passed", subset = "historical-denominators-preserved-no-native-or-publication-claim" }
            },
            observations,
            unverifiedGates = new[] { "remote-sourcelink", "native-provider", "publication", "trimming", "aot", "other-platforms" }
        }, Manifest.JsonOptions));
    }

    [Test]
    public async Task IndependentRebuildMatchesCompileOutputsWithoutRequiringIdenticalZipBytes()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        string version = Required("SECRETKIT_INTEGRATION_QUALITY_VERSION");
        LocalPackageCandidate first = LocalPackageCandidate.Select(
            Required("SECRETKIT_INTEGRATION_QUALITY_ORIGINALS"), version);
        LocalPackageCandidate second = LocalPackageCandidate.Select(
            Required("SECRETKIT_INTEGRATION_QUALITY_REBUILD_ORIGINALS"), version);
        string firstSymbols = Required("SECRETKIT_INTEGRATION_QUALITY_SYMBOLS");
        string secondSymbols = Required("SECRETKIT_INTEGRATION_QUALITY_REBUILD_SYMBOLS");
        var observations = new Dictionary<string, LocalRebuildEvidence>();
        foreach (string id in LocalPackageCandidate.PackageIds)
            observations.Add(id, LocalQualification.CompareRebuild(root,
                first.ArchivePath(id), Path.Combine(firstSymbols, $"{id}.{version}.snupkg"),
                second.ArchivePath(id), Path.Combine(secondSymbols, $"{id}.{version}.snupkg"), id));
        string output = Path.Combine(root, "artifacts/integration-quality/rebuild", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(output);
        await File.WriteAllTextAsync(Path.Combine(output, "rebuild.json"), JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            kind = "independent-build-comparison-not-attestation",
            version,
            nativeQualified = false,
            observations
        }, Manifest.JsonOptions));
    }

    private static string Required(string name) => Environment.GetEnvironmentVariable(name) ??
        throw new InvalidOperationException("integration-quality-artifact-input-missing");
}
