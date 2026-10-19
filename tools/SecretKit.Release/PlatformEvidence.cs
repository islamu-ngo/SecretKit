namespace SecretKit.Release;

public sealed record PlatformObservation(int SchemaVersion, string Purpose,
    string Version, string SourceCommit, string OperatingSystem, string Architecture,
    string Framework, string RuntimeVersion, string SdkVersion,
    int ProcessExitCode, int ProjectReferences, bool IsolatedCache,
    string PackageSource, PackageRecord[] Packages, DateTimeOffset StartedAt, DateTimeOffset CompletedAt);

public static class PlatformEvidence
{
    public static InstallationObservation Validate(PlatformObservation observation, ReleaseScope scope)
    {
        string platform = $"{observation.OperatingSystem}-{observation.Architecture}-{observation.Framework}";
        Guard.Require(observation.SchemaVersion == 1 &&
            observation.Purpose == "installed-platform-observation" &&
            observation.Version == scope.Version && observation.SourceCommit == scope.SourceCommit &&
            observation.StartedAt.Offset == TimeSpan.Zero && observation.CompletedAt.Offset == TimeSpan.Zero &&
            observation.CompletedAt >= observation.StartedAt, "platform-observation-binding");
        Guard.Require(platform is "linux-x64-net10.0" or "windows-x64-net10.0" &&
            scope.Platforms.Contains(platform, StringComparer.Ordinal) &&
            Version.TryParse(observation.RuntimeVersion, out Version? runtime) && runtime.Major == 10 &&
            observation.SdkVersion == "10.0.302", "platform-observation-platform");
        Guard.Require(observation.ProcessExitCode == 0 && observation.ProjectReferences == 0 &&
            observation.IsolatedCache && observation.PackageSource == "candidate-only",
            "platform-observation-install");
        Manifest.ExactSet(observation.Packages.Select(p => p.Id), scope.PackageIds, "platform-observation-family");
        Guard.Require(observation.Packages.All(p =>
            p.File == $"{p.Id}.{scope.Version}.nupkg" && Manifest.IsHash(p.Sha256)),
            "platform-observation-bytes");
        return new(observation.OperatingSystem, observation.Architecture, observation.Framework,
            observation.ProcessExitCode, observation.ProjectReferences, observation.IsolatedCache,
            observation.PackageSource);
    }

    public static void MatchOriginals(PlatformObservation observation, IReadOnlyCollection<PackageRecord> originals)
    {
        Manifest.ExactSet(observation.Packages.Select(p => $"{p.Id}/{p.File}/{p.Sha256}"),
            originals.Select(p => $"{p.Id}/{p.File}/{p.Sha256}"), "platform-observation-originals");
    }
}
