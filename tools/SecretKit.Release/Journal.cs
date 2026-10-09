using System.Text.Json;

namespace SecretKit.Release;

public sealed record PackageState(string Id, string Sha256, string State, bool Available, string Attempt);
public sealed record Checkpoint(int Sequence, string PreviousSha256, string ManifestSha256, PackageState[] Packages);

public sealed class Journal : IDisposable
{
    private readonly string directory;
    private readonly FileStream lease;
    public Checkpoint Head { get; private set; }
    public string HeadSha256 { get; private set; }

    public Journal(string directory, VerifiedRelease release, string? approvedHead = null)
    {
        this.directory = Path.GetFullPath(directory);
        Directory.CreateDirectory(this.directory);
        Guard.Require((File.GetAttributes(this.directory) & FileAttributes.ReparsePoint) == 0, "journal-link");
        lease = new FileStream(Path.Combine(this.directory, ".lock"), FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None);
        try
        {
            string[] paths = Directory.GetFiles(this.directory, "*.json").Order(StringComparer.Ordinal).ToArray();
            Checkpoint? previous = null;
            string previousHash = "new";
            foreach (string path in paths)
            {
                Guard.Require(Path.GetFileName(path) == $"{(previous?.Sequence ?? 0) + 1:D6}.json", "journal-sequence");
                byte[] bytes = Manifest.ReadFile(this.directory, Path.GetFileName(path), 1024 * 1024);
                Checkpoint checkpoint = Manifest.Parse<Checkpoint>(bytes);
                Validate(checkpoint, previous, previousHash, release);
                previous = checkpoint;
                previousHash = Manifest.Hash(bytes);
            }

            Guard.Require(approvedHead is null || approvedHead == previousHash, "journal-approval");
            Head = previous ?? new(0, "new", release.ManifestSha256,
                release.Manifest.Packages.Select(p => new PackageState(p.Id, p.Sha256, "pending", false, "")).ToArray());
            HeadSha256 = previousHash;
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    public void Save(PackageState[] packages)
    {
        var next = new Checkpoint(Head.Sequence + 1, HeadSha256, Head.ManifestSha256, packages);
        ValidateTransition(Head.Packages, packages);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(next, Manifest.JsonOptions);
        using (var output = new FileStream(Path.Combine(directory, $"{next.Sequence:D6}.json"),
            FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
        {
            output.Write(bytes);
            output.Flush(flushToDisk: true);
        }

        Head = next;
        HeadSha256 = Manifest.Hash(bytes);
    }

    public void Set(PackageState state) => Save(Head.Packages.Select(p => p.Id == state.Id ? state : p).ToArray());

    public void MarkDispatchStarted(string id, string attempt)
    {
        Guard.Require(Manifest.PackageIds.Contains(id) && attempt.Length > 0 &&
            attempt.All(c => char.IsAsciiDigit(c) || c == '-'), "dispatch-attempt");
        using var marker = new FileStream(Path.Combine(directory, $"{id}.{attempt}.started"),
            FileMode.CreateNew, FileAccess.Write, FileShare.Read, 1, FileOptions.WriteThrough);
        marker.WriteByte(1);
        marker.Flush(flushToDisk: true);
    }

    public void Dispose() => lease.Dispose();

    private static void Validate(Checkpoint checkpoint, Checkpoint? previous, string previousHash, VerifiedRelease release)
    {
        Guard.Require(checkpoint.Sequence == (previous?.Sequence ?? 0) + 1 &&
            checkpoint.PreviousSha256 == previousHash && checkpoint.ManifestSha256 == release.ManifestSha256, "journal-chain");
        Manifest.ExactSet(checkpoint.Packages.Select(p => p.Id), Manifest.PackageIds, "journal-family");
        foreach (PackageState state in checkpoint.Packages)
        {
            Guard.Require(state.Sha256 == release.Manifest.Packages.Single(p => p.Id == state.Id).Sha256 &&
                state.State is "pending" or "accepted" or "unknown" &&
                (!state.Available || state.State == "accepted") &&
                (state.State != "pending" || state.Attempt == "") &&
                state.Attempt.Length <= 60 && state.Attempt.All(c => char.IsAsciiDigit(c) || c == '-'), "journal-state");
        }

        if (previous is not null)
        {
            ValidateTransition(previous.Packages, checkpoint.Packages);
        }
    }

    private static void ValidateTransition(PackageState[] previous, PackageState[] next)
    {
        Manifest.ExactSet(next.Select(p => p.Id), previous.Select(p => p.Id), "journal-transition-family");
        foreach (PackageState state in next)
        {
            PackageState before = previous.Single(p => p.Id == state.Id);
            Guard.Require(before.Sha256 == state.Sha256 &&
                (before.State == "pending" || state.State == before.State ||
                    (before.State == "unknown" && state.State == "accepted")) &&
                (before.State == "pending" || before.Attempt == state.Attempt) &&
                (!before.Available || state.Available), "journal-transition");
        }
    }
}
