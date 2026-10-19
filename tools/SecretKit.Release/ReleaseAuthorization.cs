namespace SecretKit.Release;

public enum AuthorizationPurpose
{
    InitialAdmission,
    ReadOnlyRecovery,
    MutationAction
}

public sealed record OriginalAdmission(int SchemaVersion, string ManifestSha256,
    string EvidenceSha256, long ArtifactId, string ArtifactDigest, DateTimeOffset AdmittedAt,
    DateTimeOffset ProducerCompletedAt);
public sealed record ActionAuthorization(int SchemaVersion, string Kind, string ManifestSha256,
    string JournalHead, DateTimeOffset ApprovedAt, string Reviewer, bool RightsConfirmed,
    bool EnvironmentConfirmed, bool Revoked, string PackageId, string PackageSha256,
    string ExecutionAttempt, string WorkflowCommit);

public static class ReleaseAuthorization
{
    public static void BindOriginal(OriginalAdmission original, IndependentEvidence independent)
    {
        Guard.Require(original.EvidenceSha256 == independent.IndexSha256 &&
            original.AdmittedAt == independent.Index.ReviewedAt, "original-admission-review");
        var job = Manifest.Parse<System.Text.Json.JsonElement>(Manifest.ReadFile(independent.Directory,
            "producer-job.json", 1024 * 1024));
        Guard.Require(job.GetProperty("run_id").GetInt64() == independent.Index.RunId &&
            job.GetProperty("run_attempt").GetInt32() == independent.Index.RunAttempt &&
            job.GetProperty("head_sha").GetString() == independent.Index.SourceCommit &&
            job.GetProperty("name").GetString() == "candidate" &&
            job.GetProperty("status").GetString() == "completed" &&
            job.GetProperty("conclusion").GetString() == "success" &&
            job.GetProperty("completed_at").GetDateTimeOffset() == original.ProducerCompletedAt,
            "original-producer-completion");
    }

    public static void ValidateRetention(OriginalAdmission original, IndependentEvidence independent)
    {
        DateTimeOffset horizon = original.ProducerCompletedAt.AddDays(90);
        foreach (string file in independent.Index.Reports.Select(r => $"{r.ArtifactId}-artifact.json")
            .Prepend("artifact-metadata.json"))
        {
            var artifact = Manifest.Parse<System.Text.Json.JsonElement>(
                Manifest.ReadFile(independent.Directory, file, 1024 * 1024));
            Guard.Require(!artifact.GetProperty("expired").GetBoolean() &&
                artifact.GetProperty("expires_at").GetDateTimeOffset() >= horizon,
                file == "artifact-metadata.json" ? "candidate-retention-window" : "evidence-retention-window");
        }
    }

    public static void Validate(AuthorizationPurpose purpose, OriginalAdmission original,
        Approval approval, string manifestSha256, string journalHead, bool artifactAvailable,
        ActionAuthorization? action, TimeProvider clock)
    {
        DateTimeOffset now = clock.GetUtcNow();
        Guard.Require(original.SchemaVersion == 1 && Manifest.IsHash(original.ManifestSha256) &&
            Manifest.IsHash(original.EvidenceSha256) && original.ArtifactId > 0 &&
            Manifest.IsHash(original.ArtifactDigest) && original.AdmittedAt.Offset == TimeSpan.Zero &&
            original.ProducerCompletedAt.Offset == TimeSpan.Zero &&
            original.ProducerCompletedAt <= original.AdmittedAt &&
            original.AdmittedAt - original.ProducerCompletedAt <= TimeSpan.FromHours(24) &&
            original.AdmittedAt <= now && original.ManifestSha256 == manifestSha256 &&
            original.ManifestSha256 == approval.ManifestSha256 &&
            original.EvidenceSha256 == approval.EvidenceSha256 &&
            original.ArtifactId == approval.ArtifactId &&
            original.ArtifactDigest == approval.ArtifactDigest && artifactAvailable,
            "original-admission-binding");
        if (purpose == AuthorizationPurpose.InitialAdmission)
        {
            Guard.Require(now - original.ProducerCompletedAt <= TimeSpan.FromHours(24), "initial-admission-expired");
            Guard.Require(action is null, "initial-action-confusion");
            return;
        }

        Guard.Require(now - original.ProducerCompletedAt <= TimeSpan.FromDays(90), "recovery-window-expired");
        if (purpose == AuthorizationPurpose.ReadOnlyRecovery)
        {
            Guard.Require(action is null, "recovery-mutation-authority");
            return;
        }

        Guard.Require(purpose == AuthorizationPurpose.MutationAction && action is not null,
            "mutation-authorization-required");
        Guard.Require(action!.SchemaVersion == 1 && action.Kind == "protected-mutation-action" &&
            action.ManifestSha256 == original.ManifestSha256 &&
            Manifest.IsHash(journalHead) && action.JournalHead == journalHead &&
            action.JournalHead == approval.JournalHead &&
            action.ApprovedAt.Offset == TimeSpan.Zero && action.ApprovedAt <= now &&
            now - action.ApprovedAt <= TimeSpan.FromHours(24) &&
            Manifest.SafeIdentity(action.Reviewer) && action.Reviewer != approval.Publisher &&
            action.Reviewer != approval.Owner &&
            action.RightsConfirmed && action.EnvironmentConfirmed && !action.Revoked,
            "mutation-authorization-invalid");
    }

    public static void ValidateTransaction(ActionAuthorization action, Journal journal,
        VerifiedRelease release, string packageId, string attempt, string workflowCommit, bool dispatch)
    {
        Guard.Require(Manifest.PackageIds.Contains(packageId) && action.PackageId == packageId &&
            action.PackageSha256 == release.Manifest.Packages.Single(p => p.Id == packageId).Sha256 &&
            action.ExecutionAttempt == attempt && Manifest.IsHash(action.PackageSha256) &&
            workflowCommit.Length == 40 && workflowCommit.All(char.IsAsciiHexDigitLower) &&
            action.WorkflowCommit == workflowCommit, "action-transaction-binding");
        if (!dispatch)
        {
            Guard.Require(journal.HeadSha256 == action.JournalHead &&
                journal.Head.Packages.All(p => p.State != "unknown") &&
                journal.Head.Packages.Single(p => p.Id == packageId).State == "pending",
                "action-starting-head");
            return;
        }

        Checkpoint? previous = journal.Previous;
        Guard.Require(previous is not null && journal.Head.PreviousSha256 == action.JournalHead &&
            journal.Head.Sequence == previous.Sequence + 1, "action-successor-head");
        foreach (PackageState before in previous!.Packages)
        {
            PackageState after = journal.Head.Packages.Single(p => p.Id == before.Id);
            Guard.Require(before.State != "unknown" && (before.Id == packageId
                ? before.State == "pending" && after == before with { State = "unknown", Attempt = attempt }
                : after == before), "action-successor-transition");
        }
    }
}
