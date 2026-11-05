using System.Globalization;
using System.Text.Json;

namespace SecretKit.Release;

public sealed record VerificationCohortRecord(int SchemaVersion, string Kind, string Version,
    string Sdk, string SourceCommit, long Run, int Attempt, FileDigest[] Files);

internal sealed record HardeningInstalledScenario(string Id, string Status, string Subset);
internal sealed record HardeningInstalledObservation(int SchemaVersion, string Profile, string Kind,
    bool NativeQualified, string Mode, string CohortSha256, string Platform, string Runtime,
    string Sdk, long Run, int Attempt, HardeningInstalledScenario[] Scenarios);

public static class VerificationCohort
{
    public const string RecordFile = "verification-cohort.json";

    public static async Task PrepareAsync(string source, string destination)
    {
        source = Path.GetFullPath(source);
        Guard.Require(Path.IsPathFullyQualified(destination), "cohort-absolute-output");
        destination = Path.GetFullPath(destination);
        Guard.Require(!Directory.Exists(destination) && !File.Exists(destination), "cohort-output-exists");
        NoLinks(Path.GetDirectoryName(destination)!);
        string relative = Path.GetRelativePath(source, destination).Replace('\\', '/');
        Guard.Require(relative.StartsWith("artifacts/", StringComparison.Ordinal) ||
            relative.StartsWith("../", StringComparison.Ordinal) || Path.IsPathRooted(relative),
            "cohort-output-in-source");
        LocalProfile profile = LocalQualification.ReadProfile(source);
        string sdk = Manifest.Parse<JsonElement>(Manifest.ReadFile(source, "global.json", 64 * 1024))
            .GetProperty("sdk").GetProperty("version").GetString()!;
        await DemoInputs.RequireSdkAsync(source, sdk);
        LocalSourceSnapshot snapshot = LocalQualification.CaptureSource(source);
        Directory.CreateDirectory(destination);
        using var ownership = new FileStream(Path.Combine(destination, "producer.lock"),
            FileMode.CreateNew, FileAccess.Write, FileShare.None);
        foreach (string directory in new[] { "family", "symbols", "local", "local-symbols",
            "rebuild-family", "rebuild-symbols", "rebuild-local", "rebuild-local-symbols", "work" })
            Directory.CreateDirectory(Path.Combine(destination, directory));

        foreach (string build in new[] { "first", "second" })
        {
            string work = Path.Combine(destination, "work", build);
            string packages = Path.Combine(work, "packages");
            string[] properties = ["--artifacts-path", work, "-p:Version=" + profile.Version,
                "-p:ContinuousIntegrationBuild=true", "-p:EmbedAllSources=true",
                "-p:PathMap=" + work + "=/__secretkit_build__"];
            await Run(["restore", "SecretKit.slnx", "--locked-mode", .. properties]);
            await Run(["build", "SecretKit.slnx", "-c", "Release", "--no-restore", "--tl:off", .. properties]);
            await Run(["pack", "SecretKit.slnx", "-c", "Release", "--no-build", "--no-restore",
                "--output", packages, "--tl:off", .. properties]);
            string prefix = build == "first" ? "" : "rebuild-";
            foreach (string id in Manifest.PackageIds)
                foreach ((string extension, string folder, string local) in new[]
                {
                    ("nupkg", "family", "local"), ("snupkg", "symbols", "local-symbols")
                })
                {
                    string file = $"{id}.{profile.Version}.{extension}";
                    byte[] bytes = Manifest.ReadFile(packages, file, PackageArchive.MaximumBytes);
                    File.WriteAllBytes(Path.Combine(destination, prefix + folder, file), bytes);
                    if (LocalQualification.PackageIds.Contains(id))
                        File.WriteAllBytes(Path.Combine(destination, prefix + local, file), bytes);
                }
        }
        Guard.Require(LocalQualification.CaptureSource(source).Sha256 == snapshot.Sha256, "cohort-source-changed");
        foreach (string id in Manifest.PackageIds)
            _ = LocalQualification.CompareRebuild(source,
                Archive("family", id, "nupkg"), Archive("symbols", id, "snupkg"),
                Archive("rebuild-family", id, "nupkg"), Archive("rebuild-symbols", id, "snupkg"), id);
        LocalQualificationRecord qualification = LocalQualification.Prepare(source,
            Path.Combine(destination, "local"), Path.Combine(destination, "qualification"));
        long run = ReadNumber("GITHUB_RUN_ID", 1);
        int attempt = checked((int)ReadNumber("GITHUB_RUN_ATTEMPT", 1));
        await DemoInputs.PrepareAsync(source, Path.Combine(destination, "local"),
            Path.Combine(destination, "qualification"), Path.Combine(destination, "demos"),
            qualification.SourceCommit, run, attempt, sdk);
        Guard.Require(LocalQualification.CaptureSource(source).Sha256 == snapshot.Sha256, "cohort-source-changed");
        var record = new VerificationCohortRecord(1, "local-verification-not-native-qualified",
            profile.Version, sdk, qualification.SourceCommit, run, attempt,
            ExpectedFiles(profile.Version).Select(file => new FileDigest(file,
                Manifest.Hash(Read(destination, file)))).ToArray());
        using (var output = new FileStream(Path.Combine(destination, RecordFile),
            FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            await output.WriteAsync(JsonSerializer.SerializeToUtf8Bytes(record, Manifest.JsonOptions));
            output.Flush(flushToDisk: true);
        }
        _ = Check(source, destination);

        string Archive(string folder, string id, string extension) =>
            Path.Combine(destination, folder, $"{id}.{profile.Version}.{extension}");
        async Task Run(string[] arguments) =>
            Guard.Require(await Verification.RunProcessAsync(source, arguments) == 0, "cohort-build-failed");
    }

    public static VerificationCohortRecord Check(string source, string directory)
    {
        VerificationCohortRecord record = ReadArtifacts(directory);
        Guard.Require(record.Version == LocalQualification.ReadProfile(source).Version, "cohort-version");
        LocalQualificationRecord qualification = LocalQualification.Check(source,
            Path.Combine(directory, "local"), Path.Combine(directory, "qualification"));
        Guard.Require(qualification.Version == record.Version && qualification.SourceCommit == record.SourceCommit,
            "cohort-source-binding");
        _ = DemoInputs.Check(source, Path.Combine(directory, "demos"),
            record.SourceCommit, record.Run, record.Attempt, record.Sdk);
        foreach (string id in Manifest.PackageIds)
            _ = LocalQualification.CompareRebuild(source,
                Path.Combine(directory, "family", $"{id}.{record.Version}.nupkg"),
                Path.Combine(directory, "symbols", $"{id}.{record.Version}.snupkg"),
                Path.Combine(directory, "rebuild-family", $"{id}.{record.Version}.nupkg"),
                Path.Combine(directory, "rebuild-symbols", $"{id}.{record.Version}.snupkg"), id);
        return record;
    }

    internal static VerificationCohortRecord ReadArtifacts(string directory)
    {
        Guard.Require(Path.IsPathFullyQualified(directory), "cohort-absolute-input");
        NoLinks(directory);
        VerificationCohortRecord record = Manifest.Parse<VerificationCohortRecord>(
            Manifest.ReadFile(directory, RecordFile, 4 * 1024 * 1024));
        Guard.Require(record.SchemaVersion == 1 && record.Kind == "local-verification-not-native-qualified" &&
            record.Version.Length is > 0 and <= 100 &&
            record.Version.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-'),
            "cohort-record");
        Manifest.ExactSet(record.Files.Select(file => file.File), ExpectedFiles(record.Version), "cohort-file-coverage");
        foreach (FileDigest file in record.Files)
            Guard.Require(Manifest.IsHash(file.Sha256) &&
                Manifest.Hash(Read(directory, file.File)) == file.Sha256, "cohort-file-changed");
        foreach (string folder in new[] { "family", "symbols", "local", "local-symbols",
            "rebuild-family", "rebuild-symbols", "rebuild-local", "rebuild-local-symbols" })
            Manifest.ExactSet(Directory.EnumerateFileSystemEntries(Path.Combine(directory, folder))
                .Select(Path.GetFileName)!,
                record.Files.Where(file => file.File.StartsWith(folder + "/", StringComparison.Ordinal))
                    .Select(file => Path.GetFileName(file.File)), "cohort-directory-coverage");
        foreach (string prefix in new[] { "", "rebuild-" })
            foreach (string id in LocalQualification.PackageIds)
                foreach ((string family, string local, string extension) in new[]
                {
                    ("family", "local", "nupkg"), ("symbols", "local-symbols", "snupkg")
                })
                    Guard.Require(record.Files.Single(file => file.File ==
                        $"{prefix}{family}/{id}.{record.Version}.{extension}").Sha256 ==
                        record.Files.Single(file => file.File ==
                        $"{prefix}{local}/{id}.{record.Version}.{extension}").Sha256, "cohort-selected-original");
        return record;
    }

    public static async Task<int> PostPackAsync(string source, string directory, string? observationDirectory = null)
    {
        source = Path.GetFullPath(source);
        directory = Path.GetFullPath(directory);
        VerificationCohortRecord record = Check(source, directory);
        await DemoInputs.RequireSdkAsync(source, record.Sdk);
        string observation = CreateObservationDirectory(source, directory, observationDirectory);
        string qualification = Path.Combine(observation, "qualification");
        _ = LocalQualification.Prepare(source, Path.Combine(directory, "local"), qualification);
        var inputs = new Dictionary<string, string>
        {
            ["SECRETKIT_VERIFICATION_COHORT_DIRECTORY"] = directory,
            ["SECRETKIT_CANDIDATE_DIRECTORY"] = Path.Combine(directory, "family"),
            ["SECRETKIT_CANDIDATE_VERSION"] = record.Version,
            ["SECRETKIT_LOCAL_CANDIDATE_DIRECTORY"] = Path.Combine(directory, "local"),
            ["SECRETKIT_LOCAL_CANDIDATE_VERSION"] = record.Version,
            ["SECRETKIT_LOCAL_QUALIFICATION_DIRECTORY"] = qualification,
            ["SECRETKIT_INTEGRATION_QUALITY_ORIGINALS"] = Path.Combine(directory, "local"),
            ["SECRETKIT_INTEGRATION_QUALITY_VERSION"] = record.Version,
            ["SECRETKIT_INTEGRATION_QUALITY_SYMBOLS"] = Path.Combine(directory, "local-symbols"),
            ["SECRETKIT_INTEGRATION_QUALITY_REBUILD_ORIGINALS"] = Path.Combine(directory, "rebuild-local"),
            ["SECRETKIT_INTEGRATION_QUALITY_REBUILD_SYMBOLS"] = Path.Combine(directory, "rebuild-local-symbols"),
            ["SECRETKIT_RUNTIME_HARDENING_ORIGINALS"] = Path.Combine(directory, "local"),
            ["SECRETKIT_RUNTIME_HARDENING_VERSION"] = record.Version,
            ["SECRETKIT_DEMO_CANDIDATE_DIRECTORY"] = Path.Combine(directory, "demos", "originals"),
            ["SECRETKIT_DEMO_CANDIDATE_VERSION"] = record.Version,
            ["SECRETKIT_DEMO_STAGED_LOCK_DIRECTORY"] = Path.Combine(directory, "demos"),
            ["SECRETKIT_DEMO_SDK"] = record.Sdk,
            ["SECRETKIT_LOCAL_INSTALL_REPORTS"] = Path.Combine(observation, "local"),
            ["SECRETKIT_DEMO_INSTALL_REPORTS"] = Path.Combine(observation, "demos"),
            ["SECRETKIT_PLATFORM_OBSERVATION"] = Path.Combine(observation, "platform.json"),
            ["SECRETKIT_ENTERPRISE_HARDENING_REPORTS"] = Path.Combine(observation, "hardening"),
            ["SECRETKIT_DEPENDENCY_AUDIT_GRAPHS"] = Path.Combine(observation, "graphs"),
            ["GITHUB_SHA"] = record.SourceCommit,
            ["GITHUB_RUN_ID"] = record.Run.ToString(CultureInfo.InvariantCulture),
            ["GITHUB_RUN_ATTEMPT"] = record.Attempt.ToString(CultureInfo.InvariantCulture)
        };
        int exit = await Verification.RunAsync(source, "post-pack", inputs);
        _ = Check(source, directory);
        if (exit == 0)
        {
            string digest = Manifest.Hash(Manifest.ReadFile(directory, RecordFile, 4 * 1024 * 1024));
            CheckObservations(record, digest,
                PlatformEvidence.CurrentPlatform, observation,
                EnterpriseHardeningProfile.ReadDeclaration(Path.Combine(source, "docs", "internal", "compatibility")).InstalledModes);
            DependencyAudit.SealInstalledGraphs(observation, digest, PlatformEvidence.CurrentPlatform);
        }
        Console.WriteLine("verification-observations:" + observation);
        return exit;
    }

    internal static string CreateObservationDirectory(string source, string cohort, string? selected)
    {
        cohort = Path.GetFullPath(cohort);
        Guard.Require(selected is null || Path.IsPathFullyQualified(selected), "cohort-observation-absolute");
        string observation = Path.GetFullPath(selected ??
            Path.Combine(source, "artifacts", "verification", "observations", Guid.NewGuid().ToString("N")));
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        Guard.Require(!Directory.Exists(observation) && !File.Exists(observation) &&
            !string.Equals(observation, cohort, comparison) &&
            !observation.StartsWith(cohort + Path.DirectorySeparatorChar, comparison), "cohort-observation-output");
        NoLinks(observation);
        string parent = Path.GetDirectoryName(observation)!;
        Directory.CreateDirectory(parent);
        string temporary = Path.Combine(parent, ".observation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temporary);
        try { Directory.Move(temporary, observation); }
        finally { if (Directory.Exists(temporary)) Directory.Delete(temporary); }
        return observation;
    }

    internal static void CheckObservations(VerificationCohortRecord record, string cohortSha256,
        string platform, string observations, IReadOnlyDictionary<string, string[]> installedModes)
    {
        Guard.Require(Manifest.IsHash(cohortSha256), "hardening-cohort-digest");
        var installed = Manifest.Parse<PlatformObservation>(
            Manifest.ReadFile(observations, "platform.json", 131072), 131072);
        var scope = new ReleaseScope(record.Version, record.SourceCommit, Manifest.PackageIds.ToArray(),
            [], [platform + "-net10.0"], [], "controlled-installed-offline", []);
        _ = PlatformEvidence.Validate(installed, scope);
        Guard.Require(installed.SdkVersion == record.Sdk, "hardening-platform-sdk");
        PlatformEvidence.MatchOriginals(installed, Manifest.PackageIds.Select(id =>
        {
            string file = $"{id}.{record.Version}.nupkg";
            return new PackageRecord(id, file, record.Files.Single(item => item.File == "family/" + file).Sha256);
        }).ToArray());
        string directory = Path.Combine(observations, "hardening");
        NoLinks(directory);
        string[] modes = installedModes.Keys.Order(StringComparer.Ordinal).ToArray();
        Manifest.ExactSet(Directory.EnumerateFileSystemEntries(directory).Select(Path.GetFileName)!,
            modes.Select(mode => mode + ".json"), "hardening-mode-coverage");
        foreach (string mode in modes)
        {
            var observed = Manifest.Parse<HardeningInstalledObservation>(
                Manifest.ReadFile(directory, mode + ".json", 131072), 131072);
            Guard.Require(observed.SchemaVersion == 1 && observed.Profile == "enterprise-hardening" &&
                observed.Kind == "controlled-installed-offline" && !observed.NativeQualified &&
                observed.Mode == mode && observed.CohortSha256 == cohortSha256 &&
                observed.Platform == platform && observed.Runtime == installed.RuntimeVersion &&
                observed.Sdk == record.Sdk && observed.Run == record.Run && observed.Attempt == record.Attempt,
                "hardening-observation-binding");
            Manifest.ExactSet(observed.Scenarios.Select(scenario => scenario.Id), installedModes[mode],
                "hardening-scenario-coverage");
            Guard.Require(observed.Scenarios.All(scenario => scenario.Status == "passed" &&
                scenario.Subset.Length is > 0 and <= 256 &&
                scenario.Subset.All(character => character is >= ' ' and <= '~')),
                "hardening-scenario-result");
        }
    }

    internal static string[] ExpectedFiles(string version)
    {
        var files = new List<string>();
        foreach (string prefix in new[] { "", "rebuild-" })
            foreach (string id in Manifest.PackageIds)
            {
                files.Add($"{prefix}family/{id}.{version}.nupkg");
                files.Add($"{prefix}symbols/{id}.{version}.snupkg");
                if (!LocalQualification.PackageIds.Contains(id)) continue;
                files.Add($"{prefix}local/{id}.{version}.nupkg");
                files.Add($"{prefix}local-symbols/{id}.{version}.snupkg");
            }
        files.Add("qualification/" + LocalQualification.RecordFile);
        files.Add("demos/" + DemoInputs.ManifestFile);
        files.Add("demos/qualification/" + LocalQualification.RecordFile);
        foreach (string id in LocalQualification.PackageIds) files.Add($"demos/originals/{id}.{version}.nupkg");
        foreach (string app in new[] { "console", "worker", "web" }) files.Add($"demos/locks/{app}/packages.lock.json");
        return files.Order(StringComparer.Ordinal).ToArray();
    }

    private static byte[] Read(string directory, string relative)
    {
        string full = Path.Combine(directory, relative);
        NoLinks(full);
        if (!File.Exists(full)) throw new FileNotFoundException("Selected verification input is missing.");
        return Manifest.ReadLocalFile(full, PackageArchive.MaximumBytes);
    }

    private static void NoLinks(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
        {
            FileSystemInfo entry = Directory.Exists(current) ? new DirectoryInfo(current) : new FileInfo(current);
            Guard.Require(entry.LinkTarget is null && (!entry.Exists ||
                (entry.Attributes & FileAttributes.ReparsePoint) == 0), "cohort-link");
        }
    }

    private static long ReadNumber(string name, long local) =>
        Environment.GetEnvironmentVariable(name) is string text
            ? long.Parse(text, NumberStyles.None, CultureInfo.InvariantCulture) : local;
}
