using System.Text;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class SourceCoverageTests
{
    [Test]
    public async Task NestedHandwrittenSourceCannotBeOmitted()
    {
        using var fixture = new SourceTree();
        FileDigest top = fixture.Add("Client.cs", "top");
        _ = fixture.Add("Secrets/Reads.cs", "nested");

        await Assert.That(() => fixture.Verify([top])).Throws<ReleaseException>();
    }

    [Test]
    public async Task ChangedNestedSourceBytesCannotReuseAnEarlierDigest()
    {
        using var fixture = new SourceTree();
        FileDigest source = fixture.Add("Secrets/Reads.cs", "original");
        fixture.Verify([source]);
        _ = fixture.Add("Secrets/Reads.cs", "changed");

        await Assert.That(() => fixture.Verify([source])).Throws<InvalidDataException>();
    }

    [Test]
    public void GeneratedDirectoriesDoNotEnterHandwrittenSourceCoverage()
    {
        using var fixture = new SourceTree();
        FileDigest source = fixture.Add("Secrets/Reads.cs", "handwritten");
        _ = fixture.Add("obj/Release/net10.0/Generated.cs", "generated");
        _ = fixture.Add("bin/Release/net10.0/Generated.cs", "generated");
        _ = fixture.Add("Secrets/obj/Generated.cs", "generated");

        fixture.Verify([source]);
    }

    [Test]
    public async Task DuplicateSourceEntriesCannotReplaceCompleteCoverage()
    {
        using var fixture = new SourceTree();
        FileDigest source = fixture.Add("Client.cs", "handwritten");

        await Assert.That(() => fixture.Verify([source, source])).Throws<ReleaseException>();
    }

    private sealed class SourceTree : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "secretkit-source-" + Guid.NewGuid().ToString("N"));
        private string SourceRoot => Path.Combine(_root, "src", "Provider");

        internal FileDigest Add(string relative, string content)
        {
            string path = Path.Combine(SourceRoot, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            byte[] bytes = Encoding.UTF8.GetBytes(content);
            File.WriteAllBytes(path, bytes);
            return new(Path.GetRelativePath(_root, path).Replace('\\', '/'), Manifest.Hash(bytes));
        }

        internal void Verify(IEnumerable<FileDigest> sources) =>
            AdmissionSourceCoverage.Verify(_root, [SourceRoot], sources);

        public void Dispose() => Directory.Delete(_root, recursive: true);
    }
}
