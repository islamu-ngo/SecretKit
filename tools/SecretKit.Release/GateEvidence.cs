using System.Text.Json;

namespace SecretKit.Release;

public static class EvidenceLimits
{
    public const int ReportBytes = 16 * 1024 * 1024;
    public const int RecordBytes = 32 * 1024 * 1024;
}

public sealed record CheckObservation(string Key, bool Passed, string ReasonCode);
public sealed record NativeCaseObservation(string Provider, string Operation, string Variant, string Scope,
    string Case, bool Passed, bool EffectObserved, string ReasonCode);
public sealed record PrerequisiteObservation(string Provider, string Scope, string Prerequisite, bool Confirmed);
public sealed record InstallationObservation(string OperatingSystem, string Architecture, string Framework,
    int ProcessExitCode, int ProjectReferences, bool IsolatedCache, string PackageSource);
public sealed record MachineReport(int SchemaVersion, string Purpose, string Kind, string Version,
    string SourceCommit, long RunId, int RunAttempt, long JobId, string Platform, string Environment,
    string ScopeSha256, FileDigest[] Inventories, PackageRecord[] Packages, ProviderScope[] ProviderScopes,
    DateTimeOffset StartedAt, DateTimeOffset CompletedAt, int Discovered, int Failed, int Skipped,
    int ExitCode, CheckObservation[] Checks, NativeCaseObservation[] NativeCases,
    PrerequisiteObservation[] Prerequisites, InstallationObservation? Installation);
public sealed record AuthorityAttestation(string Kind, string Subject, string Issuer, string Reviewer,
    DateTimeOffset ObservedAt, string EvidenceLocator, string EvidenceSha256, CheckObservation[] Checks);
public sealed record SemanticGateRecord(int SchemaVersion, MachineReport[] Reports, AuthorityAttestation? Attestation);
public sealed record ReportOrigin(string Kind, string Platform, long JobId, long ArtifactId,
    string ArtifactDigest, FileDigest Report, string Environment, string EnvironmentEvidence);
public sealed record EvidenceIndex(int SchemaVersion, string Kind, string Repository, string SourceCommit,
    string Version, long RunId, int RunAttempt, DateTimeOffset ReviewedAt, FileDigest[] Inventories,
    ReportOrigin[] Reports, AuthorityAttestation[] Attestations);

// This directory is populated by the trusted collector, outside the bundle.
// Its index is independently reviewed and hashed in protected approval. Neither
// the manifest nor a report may select its own oracle or establish job ownership.
public sealed class IndependentEvidence
{
    public string Directory { get; }
    public EvidenceIndex Index { get; }
    public string IndexSha256 { get; }

    public IndependentEvidence(string directory)
    {
        Directory = Path.GetFullPath(directory);
        byte[] bytes = Manifest.ReadFile(Directory, "evidence-index.json", 4 * 1024 * 1024);
        Index = Manifest.Parse<EvidenceIndex>(bytes);
        IndexSha256 = Manifest.Hash(bytes);
    }

    internal void Validate(ReleaseManifest manifest, ReleaseScope scope, bool candidate)
    {
        Guard.Require(Index.SchemaVersion == 1 && Index.Kind == "independent-release-evidence" &&
            Index.Repository == Manifest.RepositoryName && Index.SourceCommit == manifest.SourceCommit &&
            Index.Version == manifest.Version && Index.RunId == manifest.SourceRunId &&
            Index.RunAttempt > 0, "independent-evidence-binding");
        GateSemantics.SameFiles(Index.Inventories, scope.Inventories, "independent-inventories");
        Guard.Require(Manifest.Hash(Manifest.ReadFile(Directory, "THIRD-PARTY-NOTICES.md", 1024 * 1024)) ==
            manifest.NoticesSha256, "independent-source-notices");
        JsonElement run = Manifest.Parse<JsonElement>(Manifest.ReadFile(Directory, "run-metadata.json", 1024 * 1024));
        Guard.Require(run.GetProperty("id").GetInt64() == Index.RunId &&
            run.GetProperty("run_attempt").GetInt32() == Index.RunAttempt &&
            run.GetProperty("head_sha").GetString() == Index.SourceCommit &&
            run.GetProperty("head_branch").GetString() == "main" &&
            run.GetProperty("event").GetString() == "push" &&
            run.GetProperty("path").GetString() == ".github/workflows/verify.yml" &&
            run.GetProperty("repository").GetProperty("full_name").GetString() == Manifest.RepositoryName &&
            run.GetProperty("head_repository").GetProperty("full_name").GetString() == Manifest.RepositoryName,
            "report-run-provenance");
        string? status = run.GetProperty("status").GetString();
        Guard.Require(status == "completed" && run.GetProperty("conclusion").GetString() == "success" ||
            candidate && status == "in_progress", "report-run-status");
        DateTimeOffset created = run.GetProperty("created_at").GetDateTimeOffset();
        Guard.Require(Index.ReviewedAt >= created, "evidence-review-time");
        Manifest.ExactSet(Index.Reports.Select(r => r.Kind + "/" + r.Platform),
            GateSemantics.AutomatedKinds.SelectMany(k => GateSemantics.ReportPlatforms(k).Select(p => k + "/" + p)),
            "independent-report-coverage");
        Guard.Require(Index.Reports.All(r => r.JobId > 0 && r.ArtifactId > 0 &&
            Manifest.IsHash(r.ArtifactDigest) && Manifest.IsHash(r.Report.Sha256) &&
            r.Report.File == $"{r.ArtifactId}-report.json" &&
            r.Environment == GateSemantics.ReportEnvironment(r.Kind) &&
            Manifest.SafeLabel(r.EnvironmentEvidence)) &&
            Index.Reports.Select(r => r.ArtifactId).Distinct().Count() == Index.Reports.Length &&
            Index.Reports.Select(r => r.Report.File).Distinct().Count() == Index.Reports.Length,
            "independent-report-origin");
        Manifest.ExactSet(Index.Attestations.Select(a => a.Kind),
            Manifest.GateKinds.Except(GateSemantics.AutomatedKinds), "independent-attestation-coverage");
        foreach (AuthorityAttestation attestation in Index.Attestations)
        {
            Guard.Require(attestation.Subject == manifest.Owner && Manifest.SafeIdentity(attestation.Issuer) &&
                Manifest.SafeIdentity(attestation.Reviewer) && attestation.Reviewer != attestation.Issuer &&
                attestation.Reviewer != manifest.Publisher && attestation.Reviewer != manifest.Owner &&
                attestation.ObservedAt >= created &&
                attestation.ObservedAt <= Index.ReviewedAt && Manifest.SafeLabel(attestation.EvidenceLocator) &&
                Manifest.IsHash(attestation.EvidenceSha256), "authority-attestation");
        }
    }

    internal MachineReport ReadReport(ReportOrigin origin, MachineReport assertion)
    {
        byte[] bytes = Manifest.ReadDigest(Directory, origin.Report);
        // Exact serialization of parsed facts, not a synthetic marker, detects
        // a correctly rehashed bundled assertion substituted for the raw result.
        MachineReport raw = Manifest.Parse<MachineReport>(bytes, EvidenceLimits.ReportBytes);
        Guard.Require(JsonSerializer.Serialize(raw, Manifest.JsonOptions) ==
            JsonSerializer.Serialize(assertion, Manifest.JsonOptions), "independent-report-substitution");
        JsonElement job = Manifest.Parse<JsonElement>(Manifest.ReadFile(Directory,
            $"{origin.JobId}-job.json", 1024 * 1024));
        JsonElement artifact = Manifest.Parse<JsonElement>(Manifest.ReadFile(Directory,
            $"{origin.ArtifactId}-artifact.json", 1024 * 1024));
        Guard.Require(job.GetProperty("id").GetInt64() == origin.JobId &&
            job.GetProperty("run_id").GetInt64() == Index.RunId &&
            job.GetProperty("run_attempt").GetInt32() == Index.RunAttempt &&
            job.GetProperty("head_sha").GetString() == Index.SourceCommit &&
            job.GetProperty("name").GetString() == $"{origin.Kind}-{origin.Platform}" &&
            job.GetProperty("status").GetString() == "completed" &&
            job.GetProperty("conclusion").GetString() == "success", "report-job-origin");
        Guard.Require(artifact.GetProperty("id").GetInt64() == origin.ArtifactId &&
            !artifact.GetProperty("expired").GetBoolean() &&
            artifact.GetProperty("digest").GetString() == "sha256:" + origin.ArtifactDigest &&
            artifact.GetProperty("name").GetString() == $"secretkit-report-{origin.JobId}" &&
            artifact.GetProperty("workflow_run").GetProperty("id").GetInt64() == Index.RunId &&
            artifact.GetProperty("workflow_run").GetProperty("head_sha").GetString() == Index.SourceCommit,
            "report-artifact-origin");
        DateTimeOffset start = job.GetProperty("started_at").GetDateTimeOffset();
        DateTimeOffset finish = job.GetProperty("completed_at").GetDateTimeOffset();
        DateTimeOffset uploaded = artifact.GetProperty("created_at").GetDateTimeOffset();
        Guard.Require(start <= raw.StartedAt && raw.StartedAt <= raw.CompletedAt &&
            raw.CompletedAt <= uploaded && uploaded <= finish && finish <= Index.ReviewedAt,
            "report-observation-time");
        return raw;
    }
}

public static class GateSemantics
{
    public static IReadOnlyList<string> Platforms { get; } =
        Array.AsReadOnly(new[] { "linux-x64-net10.0", "windows-x64-net10.0" });
    public static IReadOnlyList<string> AutomatedKinds { get; } = Array.AsReadOnly(new[]
    {
        "native-operations", "live-conformance", "compatibility-install", "provenance", "notices"
    });

    public static IEnumerable<string> ReportPlatforms(string kind) =>
        kind is "native-operations" or "live-conformance" or "compatibility-install" ? Platforms : ["none"];
    public static string ReportEnvironment(string kind) =>
        kind is "native-operations" or "live-conformance" ? "release-evidence" : "none";

    internal static void SameFiles(IEnumerable<FileDigest> actual, IEnumerable<FileDigest> expected, string code) =>
        Manifest.ExactSet(actual.Select(f => $"{f.File}/{f.Sha256}"), expected.Select(f => $"{f.File}/{f.Sha256}"), code);

    internal static void ValidateInstallation(MachineReport report)
    {
        if (report.Kind is "native-operations" or "live-conformance" or "compatibility-install")
        {
            InstallationObservation? installed = report.Installation;
            Guard.Require(installed is not null && installed.ProcessExitCode == 0 &&
                installed.ProjectReferences == 0 && installed.IsolatedCache &&
                installed.PackageSource == "candidate-only" && installed.Architecture == "x64" &&
                installed.Framework == "net10.0" && Platforms.Contains(report.Platform) &&
                $"{installed.OperatingSystem}-x64-net10.0" == report.Platform, "installed-process");
        }
        else
            Guard.Require(report.Installation is null, "unexpected-installation");
    }

    public static void Validate(SemanticGateRecord record, GateEvidence evidence, ReleaseManifest manifest,
        ReleaseScope scope, IReadOnlyList<AdmissionInventory> inventories, IndependentEvidence independent)
    {
        Guard.Require(record.SchemaVersion == 2, "gate-record-schema");
        if (!AutomatedKinds.Contains(evidence.Kind))
        {
            Guard.Require(record.Reports.Length == 0 && record.Attestation is not null, "attestation-kind");
            AuthorityAttestation attestation = record.Attestation!;
            AuthorityAttestation approved = independent.Index.Attestations.Single(a => a.Kind == evidence.Kind);
            Guard.Require(JsonSerializer.Serialize(attestation, Manifest.JsonOptions) ==
                JsonSerializer.Serialize(approved, Manifest.JsonOptions), "independent-attestation-substitution");
            ValidateChecks(attestation.Checks, evidence.Checks);
            return;
        }

        Guard.Require(record.Attestation is null, "automated-kind");
        Manifest.ExactSet(record.Reports.Select(r => r.Platform), ReportPlatforms(evidence.Kind), "report-platforms");
        foreach (MachineReport assertion in record.Reports)
        {
            ReportOrigin origin = independent.Index.Reports.Single(r =>
                r.Kind == evidence.Kind && r.Platform == assertion.Platform);
            MachineReport report = independent.ReadReport(origin, assertion);
            Guard.Require(report.SchemaVersion == 2 && report.Purpose == "release-observation" &&
                report.Kind == evidence.Kind && report.Version == manifest.Version &&
                report.SourceCommit == manifest.SourceCommit && report.RunId == manifest.SourceRunId &&
                report.RunAttempt == independent.Index.RunAttempt && report.JobId == origin.JobId &&
                report.Environment == origin.Environment && report.ScopeSha256 == manifest.Scope.Sha256,
                "report-binding");
            SameFiles(report.Inventories, scope.Inventories, "report-inventories");
            Manifest.ExactSet(report.Packages.Select(p => $"{p.Id}/{p.File}/{p.Sha256}"),
                manifest.Packages.Select(p => $"{p.Id}/{p.File}/{p.Sha256}"), "report-package-bytes");
            Manifest.ExactSet(report.ProviderScopes.Select(s => JsonSerializer.Serialize(s, Manifest.JsonOptions)),
                scope.ProviderScopes.Select(s => JsonSerializer.Serialize(s, Manifest.JsonOptions)), "report-provider-scope");
            Guard.Require(report.ExitCode == 0 && report.Failed == 0 && report.Skipped == 0 &&
                report.Discovered > 0 && report.Checks.Length <= 65536 && report.NativeCases.Length <= 65536 &&
                report.Prerequisites.Length <= 65536 &&
                report.Discovered == (evidence.Kind is "native-operations" or "live-conformance"
                    ? report.NativeCases.Length : report.Checks.Length), "report-discovery");
            ValidateChecks(report.Checks, evidence.Kind == "compatibility-install" ? [report.Platform] : evidence.Checks);
            ValidateInstallation(report);
            if (evidence.Kind is not ("native-operations" or "live-conformance"))
            {
                Guard.Require(report.NativeCases.Length == 0 && report.Prerequisites.Length == 0, "unexpected-native-cases");
                continue;
            }

            Manifest.ExactSet(report.Prerequisites.Select(p => $"{p.Provider}/{p.Scope}/{p.Prerequisite}"),
                scope.ProviderScopes.SelectMany(s => inventories.Single(i => i.Provider == s.Provider)
                    .Operations.SelectMany(o => o.Prerequisites).Distinct()
                    .Select(p => $"{s.Provider}/{s.Label}/{p}")), "native-prerequisites");
            Guard.Require(report.Prerequisites.All(p => p.Confirmed), "native-prerequisite-unconfirmed");
            // The denominator comes from reviewed current admission, not passes.
            var expected = scope.NativeOperations.SelectMany(o =>
                inventories.Single(i => i.Provider == o.Provider).Operations.Single(i => i.Id == o.Operation)
                    .RequiredCases.Select(c => CaseKey(o.Provider, o.Operation, o.Variant, o.Scope, c)));
            Manifest.ExactSet(report.NativeCases.Select(c => CaseKey(c.Provider, c.Operation, c.Variant, c.Scope, c.Case)),
                expected, "native-case-coverage");
            Guard.Require(report.NativeCases.All(c => c.Passed && c.EffectObserved && c.ReasonCode == "observed"),
                "native-case-effect");
        }
    }

    private static string CaseKey(string provider, string operation, string variant, string scope, string @case) =>
        $"{provider}/{operation}/{Uri.EscapeDataString(variant)}/{scope}/{@case}";

    private static void ValidateChecks(CheckObservation[] checks, IEnumerable<string> expected)
    {
        Manifest.ExactSet(checks.Select(c => c.Key), expected, "observed-checks");
        Guard.Require(checks.All(c => c.Passed && c.ReasonCode == "observed"), "observed-check-result");
    }
}
