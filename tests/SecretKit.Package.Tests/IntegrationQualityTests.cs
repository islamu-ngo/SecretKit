using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Release;
using SecretKit.TestFixtures;

namespace SecretKit.Package.Tests;

public sealed class IntegrationQualityTests
{
    [Test]
    [Arguments("minimal")]
    [Arguments("configuration")]
    [Arguments("hosting")]
    [Arguments("full")]
    public async Task SelectedOriginalsExerciseSeparateIntegrationQualityScenarios(string mode)
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        string originals = Environment.GetEnvironmentVariable("SECRETKIT_INTEGRATION_QUALITY_ORIGINALS") ??
            throw new InvalidOperationException("integration-quality-originals-missing");
        string version = Environment.GetEnvironmentVariable("SECRETKIT_INTEGRATION_QUALITY_VERSION") ??
            throw new InvalidOperationException("integration-quality-version-missing");
        string qualification = Environment.GetEnvironmentVariable("SECRETKIT_LOCAL_QUALIFICATION_DIRECTORY") ??
            throw new InvalidOperationException("integration-quality-qualification-missing");
        LocalQualificationRecord qualified = LocalQualification.Check(root, originals, qualification);
        await Assert.That(qualified.Version).IsEqualTo(version);
        string qualificationHash = Convert.ToHexStringLower(SHA256.HashData(
            File.ReadAllBytes(Path.Combine(qualification, LocalQualification.RecordFile))));
        LocalPackageCandidate candidate = LocalPackageCandidate.Select(originals, version);
        var hashes = LocalPackageCandidate.PackageIds.ToDictionary(id => id,
            id => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(candidate.ArchivePath(id)))));
        string output = Path.Combine(root, "artifacts/integration-quality", Guid.NewGuid().ToString("N"));
        ConsumerInstallation installation = candidate.PrepareConsumer(output, mode);
        string project = Path.Combine(root, "tests/fixtures/SecretKit.InfisicalConsumer/SecretKit.InfisicalConsumer.csproj");
        await PackageInstallTests.Run(root, ["restore", project, "--configfile", installation.Configuration,
            .. installation.Properties]);
        string assets = Path.Combine(installation.Intermediate, "project.assets.json");
        candidate.VerifyRestored(assets, installation.Packages, mode);
        await PackageInstallTests.Run(root, ["build", project, "--configuration", "Release", "--no-restore",
            .. installation.Properties]);
        string text = await PackageInstallTests.Run(root,
            [Path.Combine(installation.Binary, "Release/net10.0/SecretKit.InfisicalConsumer.dll"),
                "integration-quality", "offline"]);
        using JsonDocument report = JsonDocument.Parse(text);
        JsonElement result = report.RootElement;
        await Assert.That(result.GetProperty("profile").GetString()).IsEqualTo("integration-quality");
        await Assert.That(result.GetProperty("kind").GetString()).IsEqualTo("controlled-installed-offline");
        await Assert.That(result.GetProperty("mode").GetString()).IsEqualTo(mode);
        await Assert.That(result.GetProperty("nativeQualified").GetBoolean()).IsFalse();
        JsonElement platform = result.GetProperty("platform");
        await Assert.That(platform.GetProperty("runtimeIdentifier").GetString())
            .IsEqualTo(qualified.Platform.RuntimeIdentifier);
        await Assert.That(platform.GetProperty("framework").GetString()).IsEqualTo(qualified.Platform.Framework);
        await Assert.That(platform.GetProperty("operatingSystem").GetString()).IsEqualTo(qualified.Platform.OperatingSystem);
        JsonElement[] observations = result.GetProperty("scenarios").EnumerateArray().ToArray();
        await Assert.That(observations.Select(s => s.GetProperty("id").GetString()!).ToArray())
            .IsEquivalentTo(Expected(mode));
        await Assert.That(observations.All(s => s.GetProperty("status").GetString() == "passed" &&
            !string.IsNullOrWhiteSpace(s.GetProperty("subset").GetString()))).IsTrue();
        candidate.VerifyRestored(assets, installation.Packages, mode);
        foreach (string id in LocalPackageCandidate.PackageIds)
            await Assert.That(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(candidate.ArchivePath(id)))))
                .IsEqualTo(hashes[id]);
        _ = LocalQualification.Check(root, originals, qualification);
        await Assert.That(Convert.ToHexStringLower(SHA256.HashData(
            File.ReadAllBytes(Path.Combine(qualification, LocalQualification.RecordFile)))))
            .IsEqualTo(qualificationHash);
        // This supplemental record never replaces local S01-S16/native S01-S21.
        // It contains only scenarios the installed fixture actually reported.
        await File.WriteAllTextAsync(Path.Combine(output, "integration-quality.json"), JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            profile = "integration-quality",
            kind = "controlled-installed-offline",
            nativeQualified = false,
            version,
            mode,
            sourceSnapshotSha256 = qualified.Source.Sha256,
            profileSha256 = qualified.Profile.Sha256,
            qualificationSha256 = qualificationHash,
            sourceCommit = qualified.SourceCommit,
            platform,
            originals = hashes,
            denominator = Enumerable.Range(1, 20).Select(ScenarioId).ToArray(),
            scenarios = observations,
            unobservedScenarios = Enumerable.Range(1, 20).Select(ScenarioId).Except(Expected(mode)).ToArray(),
            unverifiedGates = new[] { "native-provider", "publication", "trimming", "aot", "other-platforms" }
        }));
    }

    internal static string[] Expected(string mode) => Enumerable.Range(1, 10)
        .Concat(mode is "configuration" or "full" ? Enumerable.Range(11, 6) : [])
        .Concat(mode is "hosting" or "full" ? Enumerable.Range(17, 2) : [])
        .Select(ScenarioId).ToArray();

    private static string ScenarioId(int id) => "IQ-S" + id.ToString("D2", CultureInfo.InvariantCulture);
}
