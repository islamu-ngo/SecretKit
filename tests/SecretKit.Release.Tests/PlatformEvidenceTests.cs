using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class PlatformEvidenceTests
{
    private static ReleaseScope Scope() => new("0.1.0-preview.1", new string('a', 40),
        Manifest.PackageIds.ToArray(), [], ["linux-x64-net10.0", "windows-x64-net10.0"],
        [], "complete-live", []);
    private static PlatformObservation Observation(string operatingSystem = "linux") =>
        new(1, "installed-platform-observation", Scope().Version, Scope().SourceCommit,
            operatingSystem, "x64", "net10.0", "10.0.10", "10.0.302", 0, 0, true, "candidate-only",
            Manifest.PackageIds.Select(id => new PackageRecord(id, $"{id}.{Scope().Version}.nupkg",
                new string('b', 64))).ToArray(), DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddSeconds(1));

    [Test]
    [Arguments("linux")]
    [Arguments("windows")]
    public async Task ActualSelectedInstallBindingDoesNotGrantReleaseAuthority(string operatingSystem)
    {
        PlatformObservation observation = Observation(operatingSystem);
        InstallationObservation installation = PlatformEvidence.Validate(observation, Scope());
        PlatformEvidence.MatchOriginals(observation, observation.Packages);
        await Assert.That(installation.OperatingSystem).IsEqualTo(operatingSystem);
        await Assert.That(installation.ProjectReferences).IsEqualTo(0);
    }

    [Test]
    [Arguments("version")]
    [Arguments("source")]
    [Arguments("process")]
    [Arguments("reference")]
    [Arguments("cache")]
    [Arguments("source-map")]
    [Arguments("platform")]
    [Arguments("framework")]
    [Arguments("runtime")]
    [Arguments("sdk")]
    [Arguments("family")]
    [Arguments("time")]
    [Arguments("purpose")]
    public async Task WrongFailedOrUnselectedInstallFactsFailClosed(string fault)
    {
        PlatformObservation observation = Observation();
        observation = fault switch
        {
            "version" => observation with { Version = "0.1.0-preview.2" },
            "source" => observation with { SourceCommit = new string('c', 40) },
            "process" => observation with { ProcessExitCode = 1 },
            "reference" => observation with { ProjectReferences = 1 },
            "cache" => observation with { IsolatedCache = false },
            "source-map" => observation with { PackageSource = "public-feed" },
            "platform" => observation with { OperatingSystem = "macos" },
            "framework" => observation with { Framework = "net9.0" },
            "runtime" => observation with { RuntimeVersion = "9.0.10" },
            "sdk" => observation with { SdkVersion = "9.0.302" },
            "family" => observation with { Packages = observation.Packages[..^1] },
            "time" => observation with { CompletedAt = observation.StartedAt.AddTicks(-1) },
            "purpose" => observation with { Purpose = "release-ready" },
            _ => throw new InvalidOperationException()
        };
        await Assert.That(() => PlatformEvidence.Validate(observation, Scope())).Throws<ReleaseException>();
    }

    [Test]
    public async Task DifferentOriginalArchivesCannotUseMatchingPlatformLabels()
    {
        PlatformObservation observation = Observation();
        PackageRecord[] different = observation.Packages.Select(p => p with { Sha256 = new string('c', 64) }).ToArray();
        await Assert.That(() => PlatformEvidence.MatchOriginals(observation, different)).Throws<ReleaseException>();
    }
}
