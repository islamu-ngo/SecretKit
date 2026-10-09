namespace SecretKit.Release;

public interface IPackageFeed
{
    // null is an authoritative native 404, never a transport error.
    Task<byte[]?> DownloadAsync(string id, string version, CancellationToken cancellationToken);
    Task VerifySignatureAsync(byte[] package, CancellationToken cancellationToken);
    Task<bool> PushAsync(string id, byte[] package, CancellationToken cancellationToken);
}

public sealed class Publication(VerifiedRelease release, Journal journal, IPackageFeed feed)
{
    public async Task ReconcileAsync(CancellationToken cancellationToken)
    {
        // Validate the entire family before allowing any subsequent mutation.
        var next = journal.Head.Packages.ToArray();
        for (int i = 0; i < next.Length; i++)
        {
            PackageState state = next[i];
            byte[]? remote = await feed.DownloadAsync(state.Id, release.Manifest.Version, cancellationToken);
            if (remote is null)
            {
                Guard.Require(!state.Available, "available-package-disappeared");
                continue;
            }

            ArchiveContent archive = PackageArchive.Read(remote);
            Guard.Require(archive.HasSignature, "remote-signature-required");
            Guard.Require(Manifest.Hash(archive.Original) == state.Sha256, "remote-original-hash-mismatch");
            await feed.VerifySignatureAsync(remote, cancellationToken);
            next[i] = state with { State = "accepted", Available = true };
        }

        journal.Save(next);
    }

    public bool Prepare(string id, string attempt)
    {
        Guard.Require(journal.Head.Packages.All(p => p.State != "unknown"), "unresolved-dispatch");
        PackageState state = journal.Head.Packages.Single(p => p.Id == id);
        if (state.State == "accepted")
        {
            return false;
        }

        Guard.Require(state.State == "pending", "dispatch-state");
        journal.Set(state with { State = "unknown", Attempt = attempt });
        return true;
    }

    public async Task DispatchAsync(string id, string attempt, CancellationToken cancellationToken)
    {
        PackageState state = journal.Head.Packages.Single(p => p.Id == id);
        Guard.Require(state.State == "unknown" && state.Attempt == attempt, "dispatch-not-prepared");
        // A durable write-ahead checkpoint must have been uploaded before entry.
        // A second invocation in the same attempt fails at CreateNew; a rerun has
        // a different attempt and cannot reuse this uncertain dispatch.
        journal.MarkDispatchStarted(id, attempt);
        byte[]? existing = await feed.DownloadAsync(id, release.Manifest.Version, cancellationToken);
        if (existing is not null)
        {
            ArchiveContent archive = PackageArchive.Read(existing);
            Guard.Require(archive.HasSignature && Manifest.Hash(archive.Original) == state.Sha256, "remote-original-hash-mismatch");
            await feed.VerifySignatureAsync(existing, cancellationToken);
            journal.Set(state with { State = "accepted", Available = true });
            return;
        }

        // All possible-dispatch failures retain unknown, including cancellation,
        // rejected/conflict responses and a server commit followed by lost ack.
        bool accepted = await feed.PushAsync(id, release.Packages[id], cancellationToken);
        if (accepted)
        {
            journal.Set(state with { State = "accepted" });
        }
        else
        {
            throw new ReleaseException("publish-outcome-unknown");
        }
    }

    public bool Complete => journal.Head.Packages.All(p => p.State == "accepted" && p.Available);
}
