using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class PublicationTests
{
    [Test]
    [Arguments("valid")]
    [Arguments("missing-journal")]
    [Arguments("expired-original")]
    [Arguments("wrong-head")]
    [Arguments("wrong-original-hash")]
    [Arguments("initial-short-retention")]
    [Arguments("initial-valid")]
    public async Task RecoveryCliVerifiesOriginalUnknownHistoryWithoutCredentials(string fault)
    {
        using var bundle = new TestBundle();
        bool initial = fault.StartsWith("initial-", StringComparison.Ordinal);
        bool valid = fault is "valid" or "initial-valid";
        DateTimeOffset produced = initial
            ? DateTimeOffset.UtcNow.AddMinutes(-30)
            : DateTimeOffset.UtcNow.AddDays(fault == "expired-original" ? -100 : -30);
        bundle.Index = bundle.Index with { ReviewedAt = produced.AddMinutes(1) };
        bundle.SaveIndex();
        VerifiedRelease release = bundle.Verify();
        string head;
        using (var journal = new Journal(bundle.JournalPath, release))
        {
            journal.Save(journal.Head.Packages);
            journal.Set(journal.Head.Packages[0] with { State = "unknown", Attempt = "12-1" });
            head = journal.HeadSha256;
        }
        var original = new OriginalAdmission(1, bundle.Approval.ManifestSha256,
            bundle.Approval.EvidenceSha256, bundle.Approval.ArtifactId, bundle.Approval.ArtifactDigest,
            bundle.Index.ReviewedAt, produced);
        FileDigest originalFile = bundle.WriteOracle("original-admission.json", original);
        bundle.WriteOracle("producer-job.json", new
        {
            run_id = 12,
            run_attempt = 1,
            head_sha = TestBundle.Commit,
            name = "candidate",
            status = "completed",
            conclusion = "success",
            completed_at = produced
        });
        if (initial)
        {
            bundle.WriteOracle("artifact-metadata.json", new
            {
                id = bundle.Approval.ArtifactId,
                expired = false,
                digest = "sha256:" + bundle.Approval.ArtifactDigest,
                workflow_run = new { id = bundle.Approval.SourceRunId, head_sha = TestBundle.Commit },
                expires_at = produced.AddDays(fault == "initial-short-retention" ? 30 : 120)
            });
            foreach (ReportOrigin report in bundle.Index.Reports)
            {
                bundle.WriteOracle($"{report.ArtifactId}-artifact.json", new
                {
                    id = report.ArtifactId,
                    expired = false,
                    digest = "sha256:" + report.ArtifactDigest,
                    name = $"secretkit-report-{report.JobId}",
                    workflow_run = new { id = bundle.Approval.SourceRunId, head_sha = TestBundle.Commit },
                    created_at = TestBundle.RunStart.AddMinutes(3),
                    expires_at = produced.AddDays(120)
                });
            }
        }
        Approval approval = bundle.Approval with { JournalHead = fault == "wrong-head" ? new string('f', 64) : head };
        string testAssembly = typeof(PublicationTests).Assembly.Location;
        var start = new System.Diagnostics.ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        start.ArgumentList.Add("exec");
        start.ArgumentList.Add("--runtimeconfig");
        start.ArgumentList.Add(Path.ChangeExtension(testAssembly, ".runtimeconfig.json"));
        start.ArgumentList.Add("--depsfile");
        start.ArgumentList.Add(Path.ChangeExtension(testAssembly, ".deps.json"));
        start.ArgumentList.Add(typeof(Program).Assembly.Location);
        start.ArgumentList.Add("verify");
        start.ArgumentList.Add(bundle.Root);
        if (!initial)
            start.ArgumentList.Add(fault == "missing-journal" ? Path.Combine(bundle.Root, "absent") : bundle.JournalPath);
        start.Environment.Clear();
        start.Environment["PATH"] = Environment.GetEnvironmentVariable("PATH");
        var inputs = new Dictionary<string, string>
        {
            ["SECRETKIT_APPROVED_MANIFEST_SHA256"] = approval.ManifestSha256,
            ["SECRETKIT_APPROVED_SOURCE_COMMIT"] = approval.SourceCommit,
            ["SECRETKIT_APPROVED_VERSION"] = approval.Version,
            ["SECRETKIT_APPROVED_SOURCE_RUN_ID"] = approval.SourceRunId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["SECRETKIT_APPROVED_ARTIFACT_ID"] = approval.ArtifactId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["SECRETKIT_APPROVED_ARTIFACT_DIGEST"] = approval.ArtifactDigest,
            ["SECRETKIT_APPROVED_SCOPE_SHA256"] = approval.ScopeSha256,
            ["SECRETKIT_APPROVED_EVIDENCE_SHA256"] = approval.EvidenceSha256,
            ["SECRETKIT_NUGET_USER"] = approval.Publisher,
            ["SECRETKIT_NUGET_OWNER"] = approval.Owner,
            ["SECRETKIT_NUGET_REPOSITORY_CERT_SHA256"] = approval.RepositoryCertificateSha256,
            ["SECRETKIT_APPROVED_JOURNAL_HEAD"] = approval.JournalHead,
            ["SECRETKIT_EVIDENCE_DIRECTORY"] = bundle.OracleRoot,
            ["SECRETKIT_VERIFY_PURPOSE"] = initial ? "initial-admission" : "read-only-recovery",
            ["SECRETKIT_ORIGINAL_ADMISSION_FILE"] = Path.Combine(bundle.OracleRoot, originalFile.File),
            ["SECRETKIT_APPROVED_ORIGINAL_ADMISSION_SHA256"] = fault == "wrong-original-hash" ? new string('f', 64) : originalFile.Sha256
        };
        foreach (var input in inputs)
            start.Environment[input.Key] = input.Value;
        string[] checkpoints = Directory.GetFiles(bundle.JournalPath, "*.json").Order().ToArray();
        byte[][] before = checkpoints.Select(File.ReadAllBytes).ToArray();
        using var process = System.Diagnostics.Process.Start(start)!;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(deadline.Token);
        Task<string> stderr = process.StandardError.ReadToEndAsync(deadline.Token);
        try
        {
            await process.WaitForExitAsync(deadline.Token);
        }
        finally
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        await Assert.That(process.ExitCode).IsEqualTo(valid ? 0 : 1);
        await Assert.That((await stdout).Contains(initial ? "exact-artifacts-verified"
            : "original-artifacts-and-history-verified")).IsEqualTo(valid);
        string expectedError = fault switch
        {
            "valid" or "initial-valid" => "",
            "missing-journal" => "existing-journal-required",
            "expired-original" => "recovery-window-expired",
            "wrong-head" => "journal-approval",
            "wrong-original-hash" => "protected-authorization-hash",
            "initial-short-retention" => "candidate-retention-window",
            _ => throw new InvalidOperationException()
        };
        await Assert.That((await stderr).Trim()).IsEqualTo(expectedError);
        await Assert.That(Directory.GetFiles(bundle.JournalPath, "*.json").Length).IsEqualTo(checkpoints.Length);
        for (int i = 0; i < checkpoints.Length; i++)
            await Assert.That(File.ReadAllBytes(checkpoints[i]).SequenceEqual(before[i])).IsTrue();
        await Assert.That(Directory.Exists(Path.Combine(bundle.Root, "absent"))).IsFalse();
    }

    [Test]
    public async Task IdenticalPayloadWithDifferentArchiveBytesIsNotTheApprovedPackage()
    {
        using var bundle = new TestBundle();
        VerifiedRelease release = bundle.Verify();
        string id = Manifest.PackageIds[0];
        ArchiveContent original = PackageArchive.Read(release.Packages[id]);
        byte[] changed = ArchiveTests.ZipAt(new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [.. original.Files.Select(p => (p.Key, System.Text.Encoding.UTF8.GetString(p.Value))),
                (".signature.p7s", "test-signature")]);
        ArchiveContent reconstructed = PackageArchive.Read(changed);
        await Assert.That(original.Files.All(file => reconstructed.Files[file.Key].SequenceEqual(file.Value))).IsTrue();
        using var journal = new Journal(bundle.JournalPath, release, "new");
        var feed = new TestFeed();
        feed.Stored[id] = changed;
        var publication = new Publication(release, journal, feed);
        await Assert.That(() => publication.ReconcileAsync(CancellationToken.None)).Throws<ReleaseException>();
        await Assert.That(feed.Published.Count).IsEqualTo(0);
    }

    [Test]
    public async Task CancellationAfterDispatchPreservesUnknownUntilNativeReconciliation()
    {
        using var bundle = new TestBundle();
        using var journal = new Journal(bundle.JournalPath, bundle.Verify(), "new");
        var feed = new TestFeed { HoldAcknowledgement = true };
        var publication = new Publication(bundle.Verify(), journal, feed);
        using var cancellation = new CancellationTokenSource();
        publication.Prepare(Manifest.PackageIds[0], "1-1");
        Task dispatch = publication.DispatchAsync(Manifest.PackageIds[0], "1-1", cancellation.Token);
        await feed.Committed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        await Assert.That(async () => await dispatch).Throws<OperationCanceledException>();
        await Assert.That(journal.Head.Packages[0].State).IsEqualTo("unknown");
        await publication.ReconcileAsync(CancellationToken.None);
        await Assert.That(journal.Head.Packages[0].Available).IsTrue();
        await Assert.That(feed.Published.Count).IsEqualTo(1);
    }

    [Test]
    public async Task LostAcknowledgementStaysUnknownAndIsNeverReplayed()
    {
        using var bundle = new TestBundle();
        VerifiedRelease release = bundle.Verify();
        using var journal = new Journal(bundle.JournalPath, release, "new");
        var feed = new TestFeed { LoseAcknowledgement = true };
        var publication = new Publication(release, journal, feed);
        await publication.ReconcileAsync(CancellationToken.None);
        string id = Manifest.PackageIds[0];
        publication.Prepare(id, "1-1");
        await Assert.That(() => publication.DispatchAsync(id, "1-1", CancellationToken.None)).Throws<IOException>();
        await Assert.That(journal.Head.Packages.Single(p => p.Id == id).State).IsEqualTo("unknown");
        await Assert.That(() => publication.Prepare(id, "1-2")).Throws<ReleaseException>();
        await Assert.That(() => publication.DispatchAsync(id, "1-2", CancellationToken.None)).Throws<ReleaseException>();
        await publication.ReconcileAsync(CancellationToken.None);
        await Assert.That(journal.Head.Packages.Single(p => p.Id == id).Available).IsTrue();
        await Assert.That(publication.Prepare(id, "2-1")).IsFalse();
        await Assert.That(feed.Published.Count).IsEqualTo(1);
    }

    [Test]
    public async Task UnknownMissingFromFeedDoesNotBecomePending()
    {
        using var bundle = new TestBundle();
        using var journal = new Journal(bundle.JournalPath, bundle.Verify(), "new");
        var publication = new Publication(bundle.Verify(), journal, new TestFeed());
        publication.Prepare(Manifest.PackageIds[0], "1-1");
        await publication.ReconcileAsync(CancellationToken.None);
        await Assert.That(journal.Head.Packages[0].State).IsEqualTo("unknown");
        await Assert.That(() => publication.Prepare(Manifest.PackageIds[1], "2-1")).Throws<ReleaseException>();
    }

    [Test]
    public async Task PartialFamilyResumesOnlyPendingExactArtifacts()
    {
        using var bundle = new TestBundle();
        VerifiedRelease release = bundle.Verify();
        var feed = new TestFeed();
        string previousHead;
        using (var journal = new Journal(bundle.JournalPath, release, "new"))
        {
            var publication = new Publication(release, journal, feed);
            for (int i = 0; i < 2; i++)
            {
                publication.Prepare(Manifest.PackageIds[i], "1-1");
                await publication.DispatchAsync(Manifest.PackageIds[i], "1-1", CancellationToken.None);
            }

            await Assert.That(publication.Complete).IsFalse();
            previousHead = journal.HeadSha256;
        }

        using (var journal = new Journal(bundle.JournalPath, release, previousHead))
        {
            var publication = new Publication(release, journal, feed);
            await publication.ReconcileAsync(CancellationToken.None);
            foreach (string id in Manifest.PackageIds)
            {
                if (publication.Prepare(id, "2-1"))
                {
                    await publication.DispatchAsync(id, "2-1", CancellationToken.None);
                }
            }

            await publication.ReconcileAsync(CancellationToken.None);
            await Assert.That(publication.Complete).IsTrue();
            await Assert.That(feed.Published.Order()).IsEquivalentTo(Manifest.PackageIds.Order());
        }
    }

    [Test]
    public async Task NativeAcceptanceIsNotAvailabilityAndCannotBeRetried()
    {
        using var bundle = new TestBundle();
        using var journal = new Journal(bundle.JournalPath, bundle.Verify(), "new");
        var feed = new TestFeed { HideDownloads = true };
        var publication = new Publication(bundle.Verify(), journal, feed);
        publication.Prepare(Manifest.PackageIds[0], "1-1");
        await publication.DispatchAsync(Manifest.PackageIds[0], "1-1", CancellationToken.None);
        await publication.ReconcileAsync(CancellationToken.None);
        await Assert.That(journal.Head.Packages[0].State).IsEqualTo("accepted");
        await Assert.That(publication.Complete).IsFalse();
        await Assert.That(publication.Prepare(Manifest.PackageIds[0], "2-1")).IsFalse();
    }

    [Test]
    public async Task WrongExistingHashAndUntrustedSignatureBlockReconciliation()
    {
        using var bundle = new TestBundle();
        using var journal = new Journal(bundle.JournalPath, bundle.Verify(), "new");
        var feed = new TestFeed();
        feed.Stored[Manifest.PackageIds[0]] = ArchiveTests.Zip(("wrong", "bytes"), (".signature.p7s", "sig"));
        var publication = new Publication(bundle.Verify(), journal, feed);
        await Assert.That(() => publication.ReconcileAsync(CancellationToken.None)).Throws<ReleaseException>();
        await Assert.That(feed.Published.Count).IsEqualTo(0);
        feed.Stored.Clear();
        publication.Prepare(Manifest.PackageIds[0], "1-1");
        await publication.DispatchAsync(Manifest.PackageIds[0], "1-1", CancellationToken.None);
        feed.SignatureTrusted = false;
        await Assert.That(() => publication.ReconcileAsync(CancellationToken.None)).Throws<ReleaseException>();
        await Assert.That(journal.Head.Packages[0].Available).IsFalse();
    }

    [Test]
    public async Task JournalRejectsTamperingStaleApprovalAndConcurrentWriters()
    {
        using var bundle = new TestBundle();
        VerifiedRelease release = bundle.Verify();
        using (var journal = new Journal(bundle.JournalPath, release, "new"))
        {
            journal.Save(journal.Head.Packages);
            await Assert.That(() => new Journal(bundle.JournalPath, release)).Throws<IOException>();
        }

        await Assert.That(() => new Journal(bundle.JournalPath, release, "new")).Throws<ReleaseException>();
        File.AppendAllText(Path.Combine(bundle.JournalPath, "000001.json"), " ");
        await Assert.That(() => new Journal(bundle.JournalPath, release, new string('f', 64))).Throws<ReleaseException>();
    }

    private sealed class TestFeed : IPackageFeed
    {
        public Dictionary<string, byte[]> Stored { get; } = new();
        public List<string> Published { get; } = [];
        public bool LoseAcknowledgement { get; init; }
        public bool HideDownloads { get; init; }
        public bool SignatureTrusted { get; set; } = true;
        public bool HoldAcknowledgement { get; init; }
        public TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource acknowledgment = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<byte[]?> DownloadAsync(string id, string version, CancellationToken cancellationToken) =>
            Task.FromResult(HideDownloads ? null : Stored.GetValueOrDefault(id));
        public Task VerifySignatureAsync(byte[] package, CancellationToken cancellationToken)
        {
            Guard.Require(SignatureTrusted, "test-untrusted-signature");
            return Task.CompletedTask;
        }
        public async Task<bool> PushAsync(string id, byte[] package, CancellationToken cancellationToken)
        {
            // Repository signing simulation is independent ZIP creation; a real
            // independently signed fixture anchors reconstruction in ArchiveTests.
            ArchiveContent archive = PackageArchive.Read(package);
            Stored.Add(id, ArchiveTests.Zip([.. archive.Files.Select(p =>
                (p.Key, System.Text.Encoding.UTF8.GetString(p.Value))), (".signature.p7s", "test-signature")]));
            Published.Add(id);
            Committed.TrySetResult();
            if (HoldAcknowledgement)
            {
                await acknowledgment.Task.WaitAsync(cancellationToken);
            }

            if (LoseAcknowledgement)
            {
                throw new IOException("synthetic lost ack");
            }

            return true;
        }
    }
}
