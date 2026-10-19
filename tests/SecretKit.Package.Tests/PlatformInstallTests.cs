using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Package.Tests;

public sealed class PlatformInstallTests
{
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
        await File.WriteAllBytesAsync(destination, JsonSerializer.SerializeToUtf8Bytes(observation));
    }
}
