using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class PublicationTests
{
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
