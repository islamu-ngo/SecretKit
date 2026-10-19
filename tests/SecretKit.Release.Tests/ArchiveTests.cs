using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class ArchiveTests
{
    [Test]
    public async Task FreshlyPackedSevenPackageFamilyPreservesOriginalsAndEmbeddedMetadata()
    {
        string[] ids =
        [
            "SecretKit.Core", "SecretKit.Infisical", "SecretKit.AzureKeyVault",
            "SecretKit.Extensions.Configuration", "SecretKit.Extensions.Hosting",
            "SecretKit.Infisical.Management", "SecretKit.AzureKeyVault.Management"
        ];
        DirectoryInfo? root = new(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "SecretKit.slnx")))
        {
            root = root.Parent;
        }

        if (root is null) throw new InvalidOperationException("Candidate repository missing.");
        string directory = Path.GetFullPath(
            Environment.GetEnvironmentVariable("SECRETKIT_CANDIDATE_DIRECTORY") ??
            Path.Combine("artifacts", "packages"), root.FullName);
        string? version = Environment.GetEnvironmentVariable("SECRETKIT_CANDIDATE_VERSION");
        // Native pack includes symbols beside the originals. Never choose another
        // directory, a latest version, or a subset of an ambiguous original family.
        string[] paths = Directory.EnumerateFiles(directory, "*.nupkg").Take(8).ToArray();
        await Assert.That(paths.Length).IsEqualTo(ids.Length);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string? source = null;
        byte[] notices = await File.ReadAllBytesAsync(Path.Combine(root.FullName, "THIRD-PARTY-NOTICES.md"));
        foreach (string path in paths)
        {
            byte[] original = Manifest.ReadFile(directory, Path.GetFileName(path), PackageArchive.MaximumBytes);
            ArchiveContent archive = PackageArchive.Read(original);
            await Assert.That(archive.HasSignature).IsFalse();
            await Assert.That(archive.Original.SequenceEqual(original)).IsTrue();
            await Assert.That(SHA256.HashData(archive.Original).SequenceEqual(SHA256.HashData(original))).IsTrue();
            string[] manifests = archive.Files.Keys.Where(name =>
                name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)).Take(2).ToArray();
            await Assert.That(manifests.Length).IsEqualTo(1);
            using var stream = new MemoryStream(archive.Files[manifests[0]]);
            using XmlReader reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 65536
            });
            XDocument document = XDocument.Load(reader);
            XElement package = document.Root ?? throw new InvalidOperationException("Candidate nuspec missing.");
            XNamespace ns = package.Name.Namespace;
            await Assert.That(package.Name.LocalName).IsEqualTo("package");
            XElement metadata = package.Elements(ns + "metadata").Single();
            string id = metadata.Elements(ns + "id").Single().Value;
            string declaredVersion = metadata.Elements(ns + "version").Single().Value;
            await Assert.That(ids.Contains(id, StringComparer.Ordinal) && seen.Add(id)).IsTrue();
            await Assert.That(manifests[0]).IsEqualTo(id + ".nuspec");
            await Assert.That(Regex.IsMatch(declaredVersion,
                @"\A(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-[a-z][a-z0-9-]*(\.(0|[1-9][0-9]{0,8}|[a-z][a-z0-9-]*))*)?\z",
                RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)).IsTrue();
            version ??= declaredVersion;
            await Assert.That(declaredVersion).IsEqualTo(version);
            await Assert.That(Path.GetFileName(path)).IsEqualTo($"{id}.{version}.nupkg");
            XElement repository = metadata.Elements(ns + "repository").Single();
            await Assert.That(repository.Attribute("type")?.Value).IsEqualTo("git");
            await Assert.That(repository.Attribute("url")?.Value).IsEqualTo("https://github.com/islamu-ngo/SecretKit");
            string commit = repository.Attribute("commit")?.Value ??
                throw new InvalidOperationException("Candidate source missing.");
            await Assert.That(commit.Length == 40 && commit.All(character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f')).IsTrue();
            source ??= commit;
            await Assert.That(commit).IsEqualTo(source);
            XElement license = metadata.Elements(ns + "license").Single();
            await Assert.That(license.Value).IsEqualTo("MIT");
            await Assert.That(license.Attribute("type")?.Value).IsEqualTo("expression");
            string readmePath = metadata.Elements(ns + "readme").Single().Value;
            await Assert.That(archive.Files[readmePath].Length > 0).IsTrue();
            await Assert.That(archive.Files["README.md"].Length > 0).IsTrue();
            await Assert.That(archive.Files["THIRD-PARTY-NOTICES.md"].SequenceEqual(notices)).IsTrue();
            await Assert.That(archive.Files.ContainsKey($"lib/net10.0/{id}.dll")).IsTrue();
        }

        await Assert.That(seen.SetEquals(ids)).IsTrue();
    }

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
    [Arguments("descriptor")]
    [Arguments("local-extra")]
    [Arguments("expanded-size")]
    [Arguments("compressed-size")]
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
            case "descriptor": bytes[central + 8] = 8; bytes[6] = 8; break;
            case "local-extra": bytes[28] = 1; break;
            case "expanded-size":
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(central + 24), 128 * 1024 * 1024 + 1);
                break;
            case "compressed-size":
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(central + 20), PackageArchive.MaximumBytes);
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(central + 24), PackageArchive.MaximumBytes);
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(18), PackageArchive.MaximumBytes);
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(22), PackageArchive.MaximumBytes);
                break;
        }

        await Assert.That(() => PackageArchive.Read(bytes)).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("crc")]
    [Arguments("truncated-content")]
    [Arguments("overlong-content")]
    [Arguments("invalid-deflate")]
    public async Task DeflatedContentStillRequiresExactLengthAndCrc(string fault)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            ZipArchiveEntry entry = archive.CreateEntry("a.txt", CompressionLevel.Optimal);
            entry.ExternalAttributes = 0;
            using Stream output = entry.Open();
            output.Write(Encoding.ASCII.GetBytes(new string('a', 1024)));
        }

        byte[] bytes = stream.ToArray();
        int central = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(bytes.Length - 6));
        await Assert.That(BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(central + 10))).IsEqualTo((ushort)8);
        await Assert.That(PackageArchive.Read(bytes).Files["a.txt"].Length).IsEqualTo(1024);
        switch (fault)
        {
            case "crc":
                bytes[14] ^= 1;
                bytes[central + 16] ^= 1;
                break;
            case "truncated-content":
            case "overlong-content":
                uint length = fault == "truncated-content" ? 1025u : 1023u;
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(22), length);
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(central + 24), length);
                break;
            case "invalid-deflate": bytes[35] = 7; break; // Reserved DEFLATE block type.
        }

        await Assert.That(() => PackageArchive.Read(bytes)).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("empty")]
    [Arguments("deflated")]
    [Arguments("utf8-flag")]
    public async Task SignatureRestrictionsRemainIndependentOfOrdinaryDeflateSupport(string fault)
    {
        byte[] bytes = Zip(("a.txt", "data"), (".signature.p7s", fault == "empty" ? "" : "signature"));
        int central = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(bytes.Length - 6));
        int signatureCentral = central + 46 + 5;
        int signatureLocal = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(signatureCentral + 42));
        if (fault == "deflated")
        {
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(signatureLocal + 8), 8);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(signatureCentral + 10), 8);
        }
        else if (fault == "utf8-flag")
        {
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(signatureLocal + 6), 0x800);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(signatureCentral + 8), 0x800);
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
