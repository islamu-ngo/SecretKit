using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Package.Tests;

public sealed class PlatformInstallTests
{
    [Test]
    [NotInParallel]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ConsumerObservationCannotBeCreatedInsideProducerInputs(bool cohort)
    {
        string root = Path.Combine(Path.GetTempPath(), "secretkit-platform-" + Guid.NewGuid().ToString("N"));
        string? previous = Environment.GetEnvironmentVariable("SECRETKIT_PLATFORM_OBSERVATION");
        string? previousCohort = Environment.GetEnvironmentVariable("SECRETKIT_VERIFICATION_COHORT_DIRECTORY");
        Directory.CreateDirectory(root);
        try
        {
            PackageCandidate candidate = CreateCandidate(root);
            string producer = cohort ? Path.Combine(root, "cohort") : candidate.Directory;
            Directory.CreateDirectory(producer);
            string destination = Path.Combine(producer, "consumer-observation.json");
            Environment.SetEnvironmentVariable("SECRETKIT_PLATFORM_OBSERVATION", destination);
            Environment.SetEnvironmentVariable("SECRETKIT_VERIFICATION_COHORT_DIRECTORY", cohort ? producer : null);

            await Assert.That(async () => await ObserveAsync(candidate, new string('a', 40),
                DateTimeOffset.UtcNow, 0, 0, "10.0.302")).Throws<IOException>();

            await Assert.That(File.Exists(destination)).IsFalse();
        }
        finally
        {
            Environment.SetEnvironmentVariable("SECRETKIT_PLATFORM_OBSERVATION", previous);
            Environment.SetEnvironmentVariable("SECRETKIT_VERIFICATION_COHORT_DIRECTORY", previousCohort);
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    [NotInParallel]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PlatformObservationCannotReplaceExistingOrLinkedEvidence(bool link)
    {
        string root = Path.Combine(Path.GetTempPath(), "secretkit-platform-" + Guid.NewGuid().ToString("N"));
        string? previous = Environment.GetEnvironmentVariable("SECRETKIT_PLATFORM_OBSERVATION");
        Directory.CreateDirectory(root);
        try
        {
            PackageCandidate candidate = CreateCandidate(root);
            string original = Path.Combine(root, "original.json");
            await File.WriteAllTextAsync(original, "original-evidence");
            string destination = link ? Path.Combine(root, "linked.json") : original;
            if (link) File.CreateSymbolicLink(destination, original);
            Environment.SetEnvironmentVariable("SECRETKIT_PLATFORM_OBSERVATION", destination);

            await Assert.That(async () => await ObserveAsync(candidate, new string('a', 40),
                DateTimeOffset.UtcNow, 0, 0, "10.0.302")).Throws<IOException>();

            await Assert.That(await File.ReadAllTextAsync(original)).IsEqualTo("original-evidence");
        }
        finally
        {
            Environment.SetEnvironmentVariable("SECRETKIT_PLATFORM_OBSERVATION", previous);
            Directory.Delete(root, recursive: true);
        }
    }

    private static PackageCandidate CreateCandidate(string root)
    {
        string originals = Path.Combine(root, "originals");
        Directory.CreateDirectory(originals);
        foreach (string id in PackageCandidate.PackageIds)
        {
            using var archive = System.IO.Compression.ZipFile.Open(
                Path.Combine(originals, id + ".0.1.0.nupkg"), System.IO.Compression.ZipArchiveMode.Create);
            using var writer = new StreamWriter(archive.CreateEntry(id + ".nuspec").Open());
            writer.Write($"<package><metadata><id>{id}</id><version>0.1.0</version></metadata></package>");
        }
        return PackageCandidate.Select(root, "0.1.0", originals);
    }

    [Test]
    [NotInParallel]
    public async Task ConcurrentPlatformWritersPublishOneCompleteObservation()
    {
        string root = Path.Combine(Path.GetTempPath(), "secretkit-platform-" + Guid.NewGuid().ToString("N"));
        string? previous = Environment.GetEnvironmentVariable("SECRETKIT_PLATFORM_OBSERVATION");
        Directory.CreateDirectory(root);
        try
        {
            PackageCandidate candidate = CreateCandidate(root);
            string destination = Path.Combine(root, "observation.json");
            Environment.SetEnvironmentVariable("SECRETKIT_PLATFORM_OBSERVATION", destination);
            Task<bool>[] writes = Enumerable.Range(0, 2).Select(async _ =>
            {
                try
                {
                    await ObserveAsync(candidate, new string('a', 40), DateTimeOffset.UtcNow, 0, 0, "10.0.302");
                    return true;
                }
                catch (IOException) { return false; }
            }).ToArray();

            bool[] results = await Task.WhenAll(writes);

            await Assert.That(results.Count(success => success)).IsEqualTo(1);
            using JsonDocument record = JsonDocument.Parse(await File.ReadAllBytesAsync(destination));
            await Assert.That(record.RootElement.GetProperty("packages").GetArrayLength()).IsEqualTo(7);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SECRETKIT_PLATFORM_OBSERVATION", previous);
            Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task SelectedPlatformIdentityComesFromTheExecutingHost()
    {
        string operatingSystem = OperatingSystem.IsLinux() ? "linux" : OperatingSystem.IsWindows() ? "windows" : "unsupported";
        await Assert.That(operatingSystem is "linux" or "windows").IsTrue();
        await Assert.That(RuntimeInformation.ProcessArchitecture).IsEqualTo(Architecture.X64);
        await Assert.That(Environment.Version.Major).IsEqualTo(10);
    }

    internal static async Task ObserveAsync(PackageCandidate candidate, string sourceCommit,
        DateTimeOffset startedAt, int processExitCode, int projectReferences, string sdkVersion)
    {
        string? destination = Environment.GetEnvironmentVariable("SECRETKIT_PLATFORM_OBSERVATION");
        if (string.IsNullOrEmpty(destination))
            return;
        string operatingSystem = OperatingSystem.IsLinux() ? "linux" : OperatingSystem.IsWindows() ? "windows" : "unsupported";
        if (operatingSystem == "unsupported" || RuntimeInformation.ProcessArchitecture != Architecture.X64 ||
            Environment.Version.Major != 10 || !Path.IsPathFullyQualified(destination))
            throw new InvalidOperationException("Unsupported platform observation.");
        destination = Path.GetFullPath(destination);
        foreach (string producer in new[] { candidate.Directory,
            Environment.GetEnvironmentVariable("SECRETKIT_VERIFICATION_COHORT_DIRECTORY") }
            .OfType<string>())
        {
            string relative = Path.GetRelativePath(Path.GetFullPath(producer), destination);
            if (!relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) &&
                relative != ".." && !Path.IsPathRooted(relative))
                throw new IOException("Platform observation must be separate from producer inputs.");
        }
        for (string? current = destination; current is not null; current = Path.GetDirectoryName(current))
        {
            if (new FileInfo(current).LinkTarget is not null || new DirectoryInfo(current).LinkTarget is not null)
                throw new IOException("Linked platform observation destination.");
        }
        if (File.Exists(destination) || Directory.Exists(destination))
            throw new IOException("Platform observation already exists.");
        var packages = new List<object>();
        foreach (string id in PackageCandidate.PackageIds)
        {
            string file = $"{id}.{candidate.Version}.nupkg";
            byte[] bytes = await File.ReadAllBytesAsync(Path.Combine(candidate.Directory, file));
            packages.Add(new { id, file, sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)) });
        }
        var observation = new
        {
            schemaVersion = 1,
            purpose = "installed-platform-observation",
            version = candidate.Version,
            sourceCommit,
            operatingSystem,
            architecture = "x64",
            framework = "net10.0",
            runtimeVersion = Environment.Version.ToString(),
            sdkVersion,
            processExitCode,
            projectReferences,
            isolatedCache = true,
            packageSource = "candidate-only",
            packages,
            startedAt,
            completedAt = DateTimeOffset.UtcNow
        };
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        string temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                await stream.WriteAsync(JsonSerializer.SerializeToUtf8Bytes(observation));
                stream.Flush(flushToDisk: true);
            }
            // The rename's non-overwrite check alone can race on Unix. Only
            // the holder of this exclusive claim may publish this destination.
            string claim = destination + ".publish";
            var publication = new FileStream(claim, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            try { File.Move(temporary, destination, overwrite: false); }
            finally
            {
                publication.Dispose();
                File.Delete(claim);
            }
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
