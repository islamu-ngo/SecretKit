using System.Text.Json.Nodes;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class ReleaseAuthorizationTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);
    private sealed class Clock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private static readonly string Hash = new('a', 64);
    private static readonly string Head = new('b', 64);
    private static Approval Approval() => new(Hash, new string('c', 40), "0.1.0-preview.1",
        12, 34, Hash, Hash, "publisher", "owner", Hash, Head, Hash);
    private static OriginalAdmission Original(TimeSpan age) => new(1, Hash, Hash, 34, Hash, Now - age, Now - age);
    private static ActionAuthorization Action(TimeSpan age) => new(1, "protected-mutation-action",
        Hash, Head, Now - age, "independent-reviewer", true, true, false,
        Manifest.PackageIds[0], Hash, "12-1", new string('c', 40));

    [Test]
    public async Task OriginalAgeCannotBeResetWhilePreservingTheEvidenceDigest()
    {
        using var bundle = new TestBundle();
        var independent = new IndependentEvidence(bundle.OracleRoot);
        OriginalAdmission original = new(1, bundle.Approval.ManifestSha256,
            independent.IndexSha256, bundle.Approval.ArtifactId, bundle.Approval.ArtifactDigest,
            independent.Index.ReviewedAt, TestBundle.RunStart.AddMinutes(6));
        bundle.WriteOracle("producer-job.json", new
        {
            run_id = 12,
            run_attempt = 1,
            head_sha = TestBundle.Commit,
            name = "candidate",
            status = "completed",
            conclusion = "success",
            completed_at = original.ProducerCompletedAt
        });
        ReleaseAuthorization.BindOriginal(original, independent);
        await Assert.That(() => ReleaseAuthorization.BindOriginal(
            original with { AdmittedAt = original.AdmittedAt.AddTicks(1) }, independent))
            .Throws<ReleaseException>();
        await Assert.That(() => ReleaseAuthorization.BindOriginal(
            original with { ProducerCompletedAt = original.ProducerCompletedAt.AddTicks(1) }, independent))
            .Throws<ReleaseException>();
    }

    [Test]
    [Arguments("valid")]
    [Arguments("candidate-short")]
    [Arguments("report-short")]
    [Arguments("candidate-expired")]
    [Arguments("report-expired")]
    public async Task ActualRetentionMustCoverOriginalCompletionNotReviewDate(string fault)
    {
        using var bundle = new TestBundle();
        var independent = new IndependentEvidence(bundle.OracleRoot);
        OriginalAdmission original = new(1, bundle.Approval.ManifestSha256,
            independent.IndexSha256, bundle.Approval.ArtifactId, bundle.Approval.ArtifactDigest,
            independent.Index.ReviewedAt, TestBundle.RunStart.AddMinutes(6));
        DateTimeOffset horizon = original.ProducerCompletedAt.AddDays(90);
        bundle.WriteOracle("artifact-metadata.json", new
        {
            expired = fault == "candidate-expired",
            expires_at = fault == "candidate-short" ? horizon.AddTicks(-1) : horizon
        });
        foreach (ReportOrigin report in independent.Index.Reports)
        {
            bundle.WriteOracle($"{report.ArtifactId}-artifact.json", new
            {
                expired = fault == "report-expired",
                expires_at = fault == "report-short" ? horizon.AddTicks(-1) : horizon
            });
        }
        Action check = () => ReleaseAuthorization.ValidateRetention(original, independent);
        if (fault == "valid")
            check();
        else
            await Assert.That(check).Throws<ReleaseException>();
    }

    [Test]
    public void IntactOlderOriginalPermitsObservationButNotImplicitMutation()
    {
        OriginalAdmission original = Original(TimeSpan.FromDays(30));
        ReleaseAuthorization.Validate(AuthorizationPurpose.ReadOnlyRecovery, original,
            Approval(), Hash, Head, true, null, new Clock());
        ReleaseAuthorization.Validate(AuthorizationPurpose.MutationAction, original,
            Approval(), Hash, Head, true, Action(TimeSpan.FromHours(1)), new Clock());
    }

    [Test]
    [Arguments(AuthorizationPurpose.InitialAdmission, 24.0)]
    [Arguments(AuthorizationPurpose.ReadOnlyRecovery, 2160.0)]
    public async Task JustOverExpiryIsRejected(AuthorizationPurpose purpose, double hours)
    {
        await Assert.That(() => ReleaseAuthorization.Validate(purpose, Original(TimeSpan.FromHours(hours).Add(TimeSpan.FromTicks(1))),
            Approval(), Hash, Head, true, null, new Clock())).Throws<ReleaseException>();
    }

    [Test]
    public void EqualityAtEachBoundaryRemainsValid()
    {
        ReleaseAuthorization.Validate(AuthorizationPurpose.InitialAdmission,
            Original(TimeSpan.FromHours(24)),
            Approval(), Hash, Head, true, null, new Clock());
        ReleaseAuthorization.Validate(AuthorizationPurpose.ReadOnlyRecovery,
            Original(TimeSpan.FromDays(90)),
            Approval(), Hash, Head, true, null, new Clock());
        ReleaseAuthorization.Validate(AuthorizationPurpose.MutationAction,
            Original(TimeSpan.FromDays(30)), Approval(), Hash, Head, true,
            Action(TimeSpan.FromHours(24)), new Clock());
    }

    [Test]
    public async Task LaterAdmissionCannotExtendTheOriginalRecoveryWindow()
    {
        OriginalAdmission original = Original(TimeSpan.FromDays(90).Add(TimeSpan.FromTicks(1)));
        original = original with { AdmittedAt = original.ProducerCompletedAt.AddHours(23) };
        await Assert.That(() => ReleaseAuthorization.Validate(AuthorizationPurpose.ReadOnlyRecovery,
            original, Approval(), Hash, Head, true, null, new Clock())).Throws<ReleaseException>();
    }

    [Test]
    public async Task AdmissionAfterProductionWindowNeverCreatesRecoveryEligibility()
    {
        OriginalAdmission original = Original(TimeSpan.FromDays(30)) with
        {
            AdmittedAt = Now.AddDays(-29).AddTicks(1)
        };
        await Assert.That(() => ReleaseAuthorization.Validate(AuthorizationPurpose.ReadOnlyRecovery,
            original, Approval(), Hash, Head, true, null, new Clock())).Throws<ReleaseException>();
    }

    [Test]
    public async Task OneApprovalPermitsOnlyTheExactPreparedSuccessor()
    {
        using var bundle = new TestBundle();
        VerifiedRelease release = bundle.Verify();
        using var journal = new Journal(Path.Combine(bundle.Root, "journal"), release);
        journal.Save(journal.Head.Packages);
        string package = Manifest.PackageIds[0];
        ActionAuthorization action = Action(TimeSpan.Zero) with
        {
            ManifestSha256 = release.ManifestSha256,
            JournalHead = journal.HeadSha256,
            PackageSha256 = release.Manifest.Packages.Single(p => p.Id == package).Sha256,
            WorkflowCommit = TestBundle.Commit
        };
        ReleaseAuthorization.ValidateTransaction(action, journal, release, package, "12-1", TestBundle.Commit, false);
        var publication = new Publication(release, journal, new NoFeed());
        await Assert.That(publication.Prepare(package, "12-1")).IsTrue();
        ReleaseAuthorization.ValidateTransaction(action, journal, release, package, "12-1", TestBundle.Commit, true);
        await Assert.That(() => ReleaseAuthorization.ValidateTransaction(action, journal, release,
            package, "12-2", TestBundle.Commit, true)).Throws<ReleaseException>();
        await Assert.That(() => ReleaseAuthorization.ValidateTransaction(action, journal, release,
            Manifest.PackageIds[1], "12-1", TestBundle.Commit, true)).Throws<ReleaseException>();
        journal.Save(journal.Head.Packages);
        await Assert.That(() => ReleaseAuthorization.ValidateTransaction(action, journal, release,
            package, "12-1", TestBundle.Commit, true)).Throws<ReleaseException>();
        await Assert.That(journal.Head.Packages.Single(p => p.Id == package).State).IsEqualTo("unknown");
    }

    private sealed class NoFeed : IPackageFeed
    {
        public Task<byte[]?> DownloadAsync(string id, string version, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No feed operation is authorized.");
        public Task VerifySignatureAsync(byte[] package, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No feed operation is authorized.");
        public Task<bool> PushAsync(string id, byte[] package, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No feed operation is authorized.");
    }

    [Test]
    [Arguments("valid")]
    [Arguments("expired")]
    [Arguments("digest")]
    [Arguments("run")]
    [Arguments("attempt")]
    [Arguments("source")]
    [Arguments("id")]
    [Arguments("retention")]
    [Arguments("retention-boundary")]
    public async Task PersistedCheckpointMustBelongToTheExactUninterruptedExecution(string fault)
    {
        using var bundle = new TestBundle();
        bundle.WriteOracle("checkpoint.json", new
        {
            id = fault == "id" ? 35 : 34,
            expired = fault == "expired",
            expires_at = fault == "retention" ? Now.AddDays(90).AddTicks(-1) :
                fault == "retention-boundary" ? Now.AddDays(90) : Now.AddDays(120),
            digest = "sha256:" + (fault == "digest" ? Head : Hash),
            name = fault == "attempt" ? "publication-checkpoint-12-2-before" : "publication-checkpoint-12-1-before",
            workflow_run = new
            {
                id = fault == "run" ? 13 : 12,
                head_sha = fault == "source" ? new string('d', 40) : TestBundle.Commit
            }
        });
        Action check = () => Program.ValidateCheckpointMetadata(
            Path.Combine(bundle.OracleRoot, "checkpoint.json"), 34, Hash, 12, "1", TestBundle.Commit, Original(TimeSpan.Zero));
        if (fault is "valid" or "retention-boundary")
            check();
        else
            await Assert.That(check).Throws<ReleaseException>();
    }

    [Test]
    [Arguments(0, false)]
    [Arguments(0, true)]
    [Arguments(89, false)]
    [Arguments(89, true)]
    public async Task CheckpointRetentionUsesOriginalCompletionWithoutRenewingRecovery(int ageDays, bool shorter)
    {
        using var bundle = new TestBundle();
        OriginalAdmission original = Original(TimeSpan.FromDays(ageDays));
        bundle.WriteOracle("checkpoint.json", new
        {
            id = 34,
            expired = false,
            expires_at = original.ProducerCompletedAt.AddDays(90).AddTicks(shorter ? -1 : 0),
            digest = "sha256:" + Hash,
            name = "publication-checkpoint-12-1-before",
            workflow_run = new { id = 12, head_sha = TestBundle.Commit }
        });

        Action check = () => Program.ValidateCheckpointMetadata(
            Path.Combine(bundle.OracleRoot, "checkpoint.json"), 34, Hash, 12, "1", TestBundle.Commit, original);

        if (shorter)
            await Assert.That(check).Throws<ReleaseException>().WithMessage("checkpoint-retention-window");
        else
            check();
    }

    [Test]
    [Arguments("missing")]
    [Arguments("malformed")]
    [Arguments("wrong-type")]
    public async Task CheckpointWithoutValidRetentionEvidenceFailsClosed(string fault)
    {
        using var bundle = new TestBundle();
        var metadata = new JsonObject
        {
            ["id"] = 34,
            ["expired"] = false,
            ["digest"] = "sha256:" + Hash,
            ["name"] = "publication-checkpoint-12-1-before",
            ["workflow_run"] = new JsonObject { ["id"] = 12, ["head_sha"] = TestBundle.Commit }
        };
        if (fault == "malformed") metadata["expires_at"] = "not-a-timestamp";
        if (fault == "wrong-type") metadata["expires_at"] = 12;
        bundle.WriteOracle("checkpoint.json", metadata);

        await Assert.That(() => Program.ValidateCheckpointMetadata(
            Path.Combine(bundle.OracleRoot, "checkpoint.json"), 34, Hash, 12, "1", TestBundle.Commit, Original(TimeSpan.Zero)))
            .Throws<ReleaseException>().WithMessage("checkpoint-retention-window");
    }

    [Test]
    [Arguments("absent")]
    [Arguments("expired")]
    [Arguments("future")]
    [Arguments("revoked")]
    [Arguments("rights")]
    [Arguments("environment")]
    [Arguments("manifest")]
    [Arguments("head")]
    [Arguments("self-review")]
    public async Task OlderOriginalNeverRenewsMissingOrInvalidActionAuthority(string fault)
    {
        ActionAuthorization? action = Action(TimeSpan.FromHours(1));
        action = fault switch
        {
            "absent" => null,
            "expired" => action with { ApprovedAt = Now.AddHours(-24).AddTicks(-1) },
            "future" => action with { ApprovedAt = Now.AddTicks(1) },
            "revoked" => action with { Revoked = true },
            "rights" => action with { RightsConfirmed = false },
            "environment" => action with { EnvironmentConfirmed = false },
            "manifest" => action with { ManifestSha256 = new string('d', 64) },
            "head" => action with { JournalHead = new string('d', 64) },
            "self-review" => action with { Reviewer = "publisher" },
            _ => throw new InvalidOperationException()
        };
        await Assert.That(() => ReleaseAuthorization.Validate(AuthorizationPurpose.MutationAction,
            Original(TimeSpan.FromDays(30)), Approval(), Hash, Head, true, action, new Clock()))
            .Throws<ReleaseException>();
    }

    [Test]
    [Arguments("future-original")]
    [Arguments("unavailable")]
    [Arguments("different-original")]
    [Arguments("different-evidence")]
    [Arguments("recovery-with-action")]
    public async Task RecoveryCannotResetOrSubstituteOriginalHistory(string fault)
    {
        OriginalAdmission original = Original(TimeSpan.FromDays(30));
        original = fault switch
        {
            "future-original" => original with { AdmittedAt = Now.AddTicks(1) },
            "different-original" => original with { ManifestSha256 = new string('d', 64) },
            "different-evidence" => original with { EvidenceSha256 = new string('d', 64) },
            _ => original
        };
        await Assert.That(() => ReleaseAuthorization.Validate(AuthorizationPurpose.ReadOnlyRecovery,
            original, Approval(), Hash, Head, fault != "unavailable",
            fault == "recovery-with-action" ? Action(TimeSpan.Zero) : null, new Clock()))
            .Throws<ReleaseException>();
    }
}
