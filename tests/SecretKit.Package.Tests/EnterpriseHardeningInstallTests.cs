using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Release;
using SecretKit.TestFixtures;

namespace SecretKit.Package.Tests;

public sealed class EnterpriseHardeningInstallTests
{
    [Test]
    public async Task SevenOriginalPackagesExerciseSupplementalManagementAndAzureContracts()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        string cohort = Environment.GetEnvironmentVariable("SECRETKIT_VERIFICATION_COHORT_DIRECTORY") ??
            throw new InvalidOperationException("enterprise-hardening-cohort-missing");
        VerificationCohortRecord binding = VerificationCohort.Check(root, cohort);
        var candidate = PackageCandidate.FromEnvironment(root);
        await Assert.That(candidate.Version).IsEqualTo(binding.Version);
        await Assert.That(Path.GetFullPath(candidate.Directory))
            .IsEqualTo(Path.GetFullPath(Path.Combine(cohort, "family")));
        string output = Path.Combine(root, "artifacts/enterprise-hardening", Guid.NewGuid().ToString("N"));
        ConsumerInstallation installation = candidate.PrepareConsumer(output);
        string project = Path.Combine(root, "tests/fixtures/SecretKit.PackageConsumer/SecretKit.PackageConsumer.csproj");
        await PackageInstallTests.Run(root, ["restore", project, "--configfile", installation.Configuration,
            .. installation.Properties]);
        string assets = Path.Combine(installation.Intermediate, "project.assets.json");
        candidate.VerifyRestored(assets, installation.Packages);
        await PackageInstallTests.Run(root, ["build", project, "-c", "Release", "--no-restore",
            "-p:UseSharedCompilation=false", .. installation.Properties]);
        string text = await PackageInstallTests.Run(root,
            [Path.Combine(installation.Binary, "Release/net10.0/SecretKit.PackageConsumer.dll"),
                "enterprise-hardening", "offline"]);
        await RecordAsync(text, "seven-package", output, cohort);
        candidate.VerifyRestored(assets, installation.Packages);
        _ = VerificationCohort.Check(root, cohort);
    }

    internal static async Task ObserveLocalAsync(string root, ConsumerInstallation installation, string mode, string output)
    {
        string cohort = Environment.GetEnvironmentVariable("SECRETKIT_VERIFICATION_COHORT_DIRECTORY") ??
            throw new InvalidOperationException("enterprise-hardening-cohort-missing");
        _ = VerificationCohort.Check(root, cohort);
        string text = await PackageInstallTests.Run(root,
            [Path.Combine(installation.Binary, "Release/net10.0/SecretKit.InfisicalConsumer.dll"),
                "enterprise-hardening", "offline"]);
        await RecordAsync(text, mode, output, cohort);
        _ = VerificationCohort.Check(root, cohort);
    }

    private static async Task RecordAsync(string text, string mode, string output, string cohort)
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        VerificationCohortRecord binding = VerificationCohort.Check(root, cohort);
        string reports = Environment.GetEnvironmentVariable("SECRETKIT_ENTERPRISE_HARDENING_REPORTS") ??
            throw new InvalidOperationException("enterprise-hardening-reports-missing");
        using JsonDocument report = JsonDocument.Parse(text);
        JsonElement result = report.RootElement;
        await Assert.That(result.GetProperty("profile").GetString()).IsEqualTo("enterprise-hardening");
        await Assert.That(result.GetProperty("kind").GetString()).IsEqualTo("controlled-installed-offline");
        await Assert.That(result.GetProperty("mode").GetString()).IsEqualTo(mode);
        await Assert.That(result.GetProperty("nativeQualified").GetBoolean()).IsFalse();
        JsonElement[] observations = result.GetProperty("scenarios").EnumerateArray().ToArray();
        await Assert.That(observations.Select(s => s.GetProperty("id").GetString()!).ToArray())
            .IsEquivalentTo(Expected(mode));
        await Assert.That(observations.All(s => s.GetProperty("status").GetString() == "passed" &&
            !string.IsNullOrWhiteSpace(s.GetProperty("subset").GetString()))).IsTrue();
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1,
            profile = "enterprise-hardening",
            kind = "controlled-installed-offline",
            nativeQualified = false,
            mode,
            platform = PlatformEvidence.CurrentPlatform,
            runtime = Environment.Version.ToString(),
            sdk = binding.Sdk,
            run = binding.Run,
            attempt = binding.Attempt,
            cohortSha256 = Convert.ToHexStringLower(SHA256.HashData(
                File.ReadAllBytes(Path.Combine(cohort, VerificationCohort.RecordFile)))),
            scenarios = observations
        });
        string[] producers = new[]
        {
            cohort,
            Environment.GetEnvironmentVariable("SECRETKIT_CANDIDATE_DIRECTORY"),
            Environment.GetEnvironmentVariable("SECRETKIT_LOCAL_CANDIDATE_DIRECTORY"),
            Environment.GetEnvironmentVariable("SECRETKIT_INTEGRATION_QUALITY_ORIGINALS"),
            Environment.GetEnvironmentVariable("SECRETKIT_DEMO_CANDIDATE_DIRECTORY")
        }.OfType<string>().Select(path => Path.GetFullPath(path, root)).ToArray();
        await PublishAsync(Path.Combine(reports, mode + ".json"), bytes, producers);
        await PublishAsync(Path.Combine(output, "enterprise-hardening.json"), bytes, producers);
    }

    private static async Task PublishAsync(string path, byte[] bytes, string[] producers)
    {
        if (!Path.IsPathFullyQualified(path)) throw new IOException("hardening-report-absolute-path-required");
        path = Path.GetFullPath(path);
        foreach (string producer in producers)
        {
            string relative = Path.GetRelativePath(producer, path);
            if (relative == "." || !Path.IsPathRooted(relative) && relative != ".." &&
                !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new IOException("hardening-report-producer-destination");
        }
        string parent = Path.GetDirectoryName(path)!;
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
            if (Path.Exists(current) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("hardening-report-linked-destination");
        Directory.CreateDirectory(parent);
        await using var destination = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await destination.WriteAsync(bytes);
    }

    [Test]
    [Arguments("existing")]
    [Arguments("producer")]
    [Arguments("linked")]
    public async Task SupplementalWriterRejectsReplacementProducerAndLinkedDestinations(string selection)
    {
        string root = Path.Combine(Path.GetTempPath(), "secretkit-hardening-" + Guid.NewGuid().ToString("N"));
        string producer = Path.Combine(root, "producer");
        Directory.CreateDirectory(producer);
        string retained = Path.Combine(producer, "minimal.json");
        byte[] original = "original-producer-evidence"u8.ToArray();
        await File.WriteAllBytesAsync(retained, original);
        try
        {
            string path = selection switch
            {
                "existing" => Path.Combine(root, "minimal.json"),
                "producer" => Path.Combine(producer, "replacement.json"),
                "linked" => Path.Combine(root, "linked", "minimal.json"),
                _ => throw new ArgumentException("Unknown writer control.")
            };
            if (selection == "existing") await File.WriteAllBytesAsync(path, original);
            if (selection == "linked") Directory.CreateSymbolicLink(Path.Combine(root, "linked"), producer);
            await Assert.That(async () => await PublishAsync(path, "replacement"u8.ToArray(), [producer]))
                .Throws<IOException>();
            await Assert.That(await File.ReadAllBytesAsync(retained)).IsEquivalentTo(original);
            if (selection == "existing")
                await Assert.That(await File.ReadAllBytesAsync(path)).IsEquivalentTo(original);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    internal static string[] Expected(string mode) => mode == "seven-package"
        ? ["S02", "S03", "S05", "S06", "S10", "S11", "S12", "S13"]
        : new[] { "S03", "S12", "S14", "S16", "S17" }
            .Concat(mode is "configuration" or "full" ? ["S07", "S25"] : Array.Empty<string>())
            .Concat(mode is "hosting" or "full" ? ["S08", "S09"] : Array.Empty<string>()).ToArray();
}
