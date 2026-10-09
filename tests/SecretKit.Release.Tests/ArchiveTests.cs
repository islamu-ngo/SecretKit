using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class ArchiveTests
{
    [Test]
    public async Task UnsignedArchiveIsPreservedByteForByte()
    {
        byte[] original = Zip(("a.txt", "alpha"), ("b.txt", "beta"));
        ArchiveContent parsed = PackageArchive.Read(original);
        await Assert.That(parsed.Original.SequenceEqual(original)).IsTrue();
        await Assert.That(parsed.HasSignature).IsFalse();
    }

    [Test]
    public async Task RemovingMiddleSignatureRestoresOffsetsCountsAndExactBytes()
    {
        byte[] original = Zip(("a.txt", "alpha"), ("b.txt", "beta"));
        byte[] signed = Zip(("a.txt", "alpha"), (".signature.p7s", "signature"), ("b.txt", "beta"));
        ArchiveContent parsed = PackageArchive.Read(signed);
        await Assert.That(parsed.Original.SequenceEqual(original)).IsTrue();
        await Assert.That(parsed.HasSignature).IsTrue();
    }

    [Test]
    public async Task IndependentNuGetFixtureMatchesItsCryptographicallySignedOriginalHash()
    {
        byte[] signed = Convert.FromBase64String(await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "Fixtures", "microsoft.netcore.platforms.1.1.0.nupkg.base64")));
        await Assert.That(Convert.ToHexStringLower(SHA256.HashData(signed)))
            .IsEqualTo("15e338d24b5c39b4099389cc612841eb51ff13c07bb4829f97d39b27420e7023");
        ArchiveContent parsed = PackageArchive.Read(signed);
        await Assert.That(parsed.HasSignature).IsTrue();
        // Independent oracle: CMS content extracted and signature mathematics checked with OpenSSL.
        await Assert.That(Convert.ToBase64String(SHA256.HashData(parsed.Original)))
            .IsEqualTo("ScOW1SKYEECOkS1XH7HyHPovkoU9Svyzx3aB0UHQlqc=");
        await Assert.That(PackageArchive.Read(parsed.Original).HasSignature).IsFalse();
    }

    [Test]
    [Arguments("../a")]
    [Arguments("/a")]
    [Arguments("a\\b")]
    [Arguments("a//b")]
    [Arguments("a/./b")]
    [Arguments("a/%2e%2e/b")]
    [Arguments("C:a")]
    [Arguments(".SIGNATURE.P7S")]
    public async Task UnsafeOrAmbiguousPathsAreRejected(string name)
    {
        await Assert.That(() => PackageArchive.Read(Zip((name, "data")))).Throws<ReleaseException>();
    }

    [Test]
    public async Task DuplicateNamesAndSignatureEntriesAreRejected()
    {
        await Assert.That(() => PackageArchive.Read(Zip(("a", "one"), ("A", "two")))).Throws<ReleaseException>();
        await Assert.That(() => PackageArchive.Read(Zip((".signature.p7s", "one"), (".signature.p7s", "two"))))
            .Throws<ReleaseException>();
    }

    [Test]
    [Arguments("crc")]
    [Arguments("offset")]
    [Arguments("count")]
    [Arguments("disk")]
    [Arguments("zip64")]
    [Arguments("flags")]
    [Arguments("trailing")]
    [Arguments("extra")]
    [Arguments("symlink")]
    [Arguments("local-name")]
    public async Task CorruptAndUnsupportedLayoutsFailClosed(string fault)
    {
        byte[] bytes = Zip(("a.txt", "data"));
        int end = bytes.Length - 22;
        int central = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(end + 16));
        switch (fault)
        {
            case "crc": bytes[35] ^= 1; break;
            case "offset": bytes[central + 42] = 1; break;
            case "count": bytes[end + 10] = 2; break;
            case "disk": bytes[end + 4] = 1; break;
            case "zip64": bytes[end + 10] = 255; bytes[end + 11] = 255; break;
            case "flags": bytes[central + 8] = 1; break;
            case "trailing": bytes = [.. bytes, 0]; break;
            case "extra": bytes[central + 30] = 1; break;
            case "symlink": BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(central + 38), 0xa0000000); break;
            case "local-name": bytes[30] = (byte)'b'; break;
        }

        await Assert.That(() => PackageArchive.Read(bytes)).Throws<ReleaseException>();
    }

    public static byte[] Zip(params (string Name, string Content)[] entries) =>
        ZipAt(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), entries);

    public static byte[] ZipAt(DateTimeOffset timestamp, params (string Name, string Content)[] entries)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach ((string name, string content) in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
                entry.LastWriteTime = timestamp;
                entry.ExternalAttributes = 0;
                using Stream output = entry.Open();
                output.Write(Encoding.UTF8.GetBytes(content));
            }
        }

        return stream.ToArray();
    }
}
