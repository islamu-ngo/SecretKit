using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace SecretKit.Release;

public sealed record LocalOperation(string Id, string Member);
public sealed record LocalProfile(int SchemaVersion, string Kind, string Id, string Version,
    string NativeReadPolicy, string[] PackageIds, LocalOperation[] Operations, string[] Scenarios);
public sealed record LocalSourceSnapshot(string Kind, string Sha256, FileDigest[] Files);
public sealed record LocalPlatform(string RuntimeIdentifier, string Framework, string OperatingSystem);
public sealed record LocalQualificationRecord(int SchemaVersion, string Kind, string Status,
    FileDigest Profile, string Version, string SourceCommit, LocalSourceSnapshot Source,
    PackageRecord[] Packages, LocalPlatform Platform);
// Supplemental evidence is intentionally not part of the strict historical record.
public sealed record LocalDebuggingDocument(string File, string Sha256, string? SourceLink, string Kind);
public sealed record LocalDebuggingEvidence(string Kind, string PackageId, string Version, string SourceCommit,
    string PackageSha256, string SymbolsSha256,
    string AssemblySha256, string PdbSha256, string SourceSha256, string RemoteSource,
    LocalDebuggingDocument[] Documents);
public sealed record LocalRebuildEvidence(string Kind, bool ArchiveBytesEqual,
    LocalDebuggingEvidence First, LocalDebuggingEvidence Second);

// Offline consistency only. There is deliberately no approval, VerifiedRelease,
// journal, provider transport or public candidate in this API.
public static partial class LocalQualification
{
    private static readonly Guid SourceLinkId = new("cc110556-a091-4d38-9fec-25ab9a351a6a");
    private static readonly Guid EmbeddedSourceId = new("0e8a571b-6926-466e-b4ad-8ab04611f5fe");
    private static readonly Guid Sha256Id = new("8829d00f-11b8-4213-878b-770e8597ac16");
    private static readonly Guid Sha1Id = new("ff1816ec-aa5e-4d10-87f7-6f4963833460");

    // Checks local bytes only: neither the repository commit label nor a SourceLink
    // URL establishes remote availability, clean source, native authority or publication.
    public static LocalDebuggingEvidence VerifyDebugging(
        string source, string packagePath, string symbolsPath, string id)
    {
        Guard.Require(PackageIds.Contains(id), "debug-package-id");
        string root = Path.GetFullPath(source);
        LocalSourceSnapshot snapshot = CaptureSource(root);
        byte[] packageBytes = ReadArchive(packagePath);
        byte[] symbolsBytes = ReadArchive(symbolsPath);
        ArchiveContent package = PackageArchive.Read(packageBytes);
        ArchiveContent symbols = PackageArchive.Read(symbolsBytes);
        XElement metadata = Metadata(package);
        XElement symbolMetadata = Metadata(symbols);
        XNamespace ns = metadata.Name.Namespace;
        XNamespace sns = symbolMetadata.Name.Namespace;
        string commit = metadata.Element(ns + "repository")?.Attribute("commit")?.Value ?? "";
        string version = metadata.Element(ns + "version")?.Value ?? "";
        Guard.Require(metadata.Element(ns + "id")?.Value == id && VersionPattern().IsMatch(version) &&
            CommitPattern().IsMatch(commit) &&
            metadata.Element(ns + "repository")?.Attribute("url")?.Value == Manifest.Repository &&
            symbolMetadata.Element(sns + "id")?.Value == id &&
            symbolMetadata.Element(sns + "version")?.Value == version &&
            symbolMetadata.Element(sns + "repository")?.Attribute("commit")?.Value == commit &&
            symbolMetadata.Element(sns + "repository")?.Attribute("url")?.Value == Manifest.Repository,
            "debug-symbol-binding");
        Guard.Require(package.Files.ContainsKey($"lib/net10.0/{id}.dll") &&
            symbols.Files.ContainsKey($"lib/net10.0/{id}.pdb"), "debug-symbol-missing");
        byte[] assembly = package.Files[$"lib/net10.0/{id}.dll"];
        byte[] pdb = symbols.Files[$"lib/net10.0/{id}.pdb"];
        Guard.Require(!package.Files.TryGetValue($"lib/net10.0/{id}.pdb", out byte[]? packagedPdb) ||
            packagedPdb.SequenceEqual(pdb), "debug-packaged-pdb");
        try
        {
            using var pe = new PEReader(new MemoryStream(assembly, writable: false));
            using var provider = MetadataReaderProvider.FromPortablePdbStream(new MemoryStream(pdb, writable: false));
            MetadataReader reader = provider.GetMetadataReader();
            DebugMetadataHeader header = reader.DebugMetadataHeader ?? throw new ReleaseException("debug-pdb-header");
            var pdbId = new BlobContentId(header.Id);
            DebugDirectoryEntry[] directory = pe.ReadDebugDirectory().ToArray();
            DebugDirectoryEntry[] codeViews = directory.Where(e => e.Type == DebugDirectoryEntryType.CodeView).ToArray();
            Guard.Require(codeViews.Length == 1, "debug-codeview");
            CodeViewDebugDirectoryData codeView = pe.ReadCodeViewDebugDirectoryData(codeViews[0]);
            Guard.Require(codeView.Age == 1 && codeView.Guid == pdbId.Guid &&
                codeViews[0].Stamp == pdbId.Stamp, "debug-pdb-identity");
            DebugDirectoryEntry[] checksums = directory.Where(e => e.Type == DebugDirectoryEntryType.PdbChecksum).ToArray();
            Guard.Require(checksums.Length == 1, "debug-pdb-checksum");
            PdbChecksumDebugDirectoryData checksum = pe.ReadPdbChecksumDebugDirectoryData(checksums[0]);
            // Deterministic portable PDB hashing treats the subsequently filled ID as zero.
            byte[] normalized = pdb.ToArray();
            normalized.AsSpan(header.IdStartOffset, header.Id.Length).Clear();
            Guard.Require(checksum.AlgorithmName == "SHA256" &&
                checksum.Checksum.AsSpan().SequenceEqual(SHA256.HashData(normalized)), "debug-pdb-checksum");
            Dictionary<string, string>? mappings = null;
            foreach (CustomDebugInformationHandle handle in reader.CustomDebugInformation)
            {
                CustomDebugInformation information = reader.GetCustomDebugInformation(handle);
                if (reader.GetGuid(information.Kind) != SourceLinkId) continue;
                Guard.Require(information.Parent.Kind == HandleKind.ModuleDefinition && mappings is null,
                    "debug-sourcelink");
                mappings = Manifest.Parse<SourceLinkMap>(reader.GetBlobBytes(information.Value)).Documents;
            }
            Guard.Require(mappings is { Count: > 0 }, "debug-sourcelink");
            var documents = new List<LocalDebuggingDocument>();
            foreach (DocumentHandle handle in reader.Documents)
            {
                Document document = reader.GetDocument(handle);
                string name = reader.GetString(document.Name).Replace('\\', '/');
                var matched = mappings!.Where(m => m.Key.EndsWith('*')
                    ? name.StartsWith(m.Key[..^1], StringComparison.Ordinal)
                    : name == m.Key).ToArray();
                Guard.Require(matched.Length <= 1, "debug-sourcelink-ambiguous");
                string? url = null;
                string relative;
                bool generated;
                byte[] contents;
                if (matched.Length == 1)
                {
                    var mapping = matched[0];
                    Guard.Require(mapping.Key.Count(c => c == '*') <= 1 &&
                        mapping.Value.Count(c => c == '*') == (mapping.Key.EndsWith('*') ? 1 : 0) &&
                        (!mapping.Value.Contains('*') || mapping.Value.EndsWith('*')), "debug-sourcelink-pattern");
                    url = mapping.Key.EndsWith('*')
                        ? mapping.Value[..^1] + name[(mapping.Key.Length - 1)..] : mapping.Value;
                    string prefix = $"https://raw.githubusercontent.com/islamu-ngo/SecretKit/{commit}/";
                    Guard.Require(url.StartsWith(prefix, StringComparison.Ordinal), "debug-sourcelink-repository");
                    relative = Uri.UnescapeDataString(url[prefix.Length..]);
                    Guard.Require(relative.Split('/').All(p => p.Length > 0 && p is not "." and not "..") &&
                        !relative.Contains('\\') && !relative.Contains(':') && !relative.Contains('?') &&
                        !relative.Contains('#'), "debug-source-path");
                    string path = Path.GetFullPath(Path.Combine(root, relative));
                    Guard.Require(Within(root, path), "debug-source-path");
                    generated = !snapshot.Files.Any(f => f.File == relative) && IsGeneratedDocument(relative, id);
                    contents = generated && !File.Exists(path)
                        ? ReadEmbeddedDocument(reader, handle) : ReadDocument(path);
                    if (generated) url = null;
                    if (!generated)
                        Guard.Require(snapshot.Files.Any(f => f.File == relative &&
                            f.Sha256 == Manifest.Hash(contents)), "debug-source-capture");
                }
                else
                {
                    // Compiler/generated documents do not have a remote mapping.
                    // They must still carry checksum-verifiable exact local/embedded bytes.
                    generated = true;
                    string path = Path.IsPathFullyQualified(name) ? Path.GetFullPath(name) : "";
                    if (path.Length > 0 && Within(root, path) && File.Exists(path))
                    {
                        relative = Path.GetRelativePath(root, path).Replace('\\', '/');
                        Guard.Require(IsGeneratedDocument(relative, id), "debug-source-unmapped");
                        contents = ReadDocument(path);
                    }
                    else
                    {
                        Guard.Require(IsGeneratedDocument(name, id), "debug-source-unmapped");
                        relative = name;
                        contents = ReadEmbeddedDocument(reader, handle);
                    }
                }
                Guid algorithm = reader.GetGuid(document.HashAlgorithm);
                Guard.Require(algorithm == Sha256Id || algorithm == Sha1Id, "debug-document-algorithm");
                byte[] hash = algorithm == Sha256Id ? SHA256.HashData(contents) : SHA1.HashData(contents);
                Guard.Require(hash.AsSpan().SequenceEqual(reader.GetBlobBytes(document.Hash)), "debug-document-checksum");
                documents.Add(new(relative, Manifest.Hash(contents), url, generated ? "generated" : "captured-source"));
            }
            Guard.Require(documents.Count > 0 && documents.Any(d => d.Kind == "captured-source") &&
                documents.Select(d => d.File).Distinct(StringComparer.Ordinal).Count() == documents.Count,
                "debug-documents");
            RequireSameSource(snapshot, CaptureSource(root));
            return new("local-debugging", id, version, commit, Manifest.Hash(packageBytes), Manifest.Hash(symbolsBytes),
                Manifest.Hash(assembly), Manifest.Hash(pdb), snapshot.Sha256, "unverified",
                documents.OrderBy(d => d.File, StringComparer.Ordinal).ToArray());
        }
        catch (Exception error) when (error is BadImageFormatException or InvalidDataException or
            ArgumentException or EndOfStreamException or XmlException)
        {
            throw new ReleaseException("debug-format");
        }

        XElement Metadata(ArchiveContent archive)
        {
            Guard.Require(archive.Files.ContainsKey(id + ".nuspec") &&
                archive.Files.Keys.Count(n => n.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)) == 1,
                "debug-nuspec");
            using var stream = new MemoryStream(archive.Files[id + ".nuspec"]);
            using XmlReader xml = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 1024 * 1024
            });
            XElement packageRoot = XDocument.Load(xml).Root ?? throw new ReleaseException("debug-nuspec");
            XElement[] entries = packageRoot.Elements(packageRoot.Name.Namespace + "metadata").ToArray();
            Guard.Require(entries.Length == 1, "debug-nuspec");
            XElement selected = entries[0];
            Guard.Require(new[] { "id", "version", "repository" }.All(name =>
                selected.Elements(selected.Name.Namespace + name).Count() == 1), "debug-nuspec-fields");
            return selected;
        }
    }

    public static LocalRebuildEvidence CompareRebuild(string source, string firstPackage, string firstSymbols,
        string secondPackage, string secondSymbols, string id)
    {
        Guard.Require(Path.GetFullPath(firstPackage) != Path.GetFullPath(secondPackage) &&
            Path.GetFullPath(firstSymbols) != Path.GetFullPath(secondSymbols), "debug-rebuild-inputs");
        LocalDebuggingEvidence first = VerifyDebugging(source, firstPackage, firstSymbols, id);
        LocalDebuggingEvidence second = VerifyDebugging(source, secondPackage, secondSymbols, id);
        Guard.Require(first.PackageId == second.PackageId && first.Version == second.Version &&
            first.SourceCommit == second.SourceCommit &&
            first.SourceSha256 == second.SourceSha256 && first.AssemblySha256 == second.AssemblySha256 &&
            first.PdbSha256 == second.PdbSha256 && first.Documents.SequenceEqual(second.Documents), "debug-rebuild");
        return new("independent-build-comparison-not-attestation",
            first.PackageSha256 == second.PackageSha256 && first.SymbolsSha256 == second.SymbolsSha256, first, second);
    }

    private sealed record SourceLinkMap(Dictionary<string, string> Documents);

    private static byte[] ReadArchive(string path)
    {
        string full = Path.GetFullPath(path);
        return Manifest.ReadFile(Path.GetDirectoryName(full)!, Path.GetFileName(full), PackageArchive.MaximumBytes);
    }

    private static bool IsGeneratedDocument(string name, string id)
    {
        string path = name.Replace('\\', '/');
        return path.StartsWith($"src/{id}/obj/", StringComparison.Ordinal) ||
            path.Contains($"/src/{id}/obj/", StringComparison.Ordinal) ||
            (id == "SecretKit.Infisical" && path.EndsWith(".g.cs", StringComparison.Ordinal) &&
                (path.StartsWith("Refit.Generator/", StringComparison.Ordinal) ||
                    path.Contains("/Refit.Generator/", StringComparison.Ordinal)));
    }

    private static byte[] ReadEmbeddedDocument(MetadataReader reader, DocumentHandle handle)
    {
        CustomDebugInformation[] embedded = reader.GetCustomDebugInformation(handle)
            .Select(reader.GetCustomDebugInformation)
            .Where(i => reader.GetGuid(i.Kind) == EmbeddedSourceId).ToArray();
        Guard.Require(embedded.Length == 1, "debug-source-unmapped");
        byte[] blob = reader.GetBlobBytes(embedded[0].Value);
        Guard.Require(blob.Length >= 4, "debug-embedded-source");
        int size = BinaryPrimitives.ReadInt32LittleEndian(blob);
        Guard.Require(size is >= 0 and <= 4 * 1024 * 1024, "debug-embedded-source");
        if (size == 0)
        {
            Guard.Require(blob.Length - 4 <= 4 * 1024 * 1024, "debug-embedded-source");
            return blob[4..];
        }
        using var compressed = new MemoryStream(blob, 4, blob.Length - 4);
        using var deflate = new DeflateStream(compressed, CompressionMode.Decompress);
        byte[] contents = new byte[size];
        deflate.ReadExactly(contents);
        Guard.Require(deflate.ReadByte() == -1, "debug-embedded-source");
        return contents;
    }

    private static byte[] ReadDocument(string path) =>
        Manifest.ReadLocalFile(path, 4 * 1024 * 1024);

    public const string RecordFile = "local-qualification.json";
    public const string ProfileFile = "infisical-runtime.json";
    private const string ProfileDirectory = "docs/internal/local";
    private const string Prepared = "prepared-not-native-qualified";
    public static IReadOnlyList<string> PackageIds { get; } = Array.AsReadOnly(new[]
    {
        "SecretKit.Core", "SecretKit.Infisical",
        "SecretKit.Extensions.Configuration", "SecretKit.Extensions.Hosting"
    });
    private static readonly LocalOperation[] Operations =
    [
        new("read", "SecretKit.Infisical.InfisicalClient.ReadAsync(SecretKit.Core.SecretReference,System.Threading.CancellationToken)"),
        new("inspect", "SecretKit.Infisical.InfisicalClient.InspectAsync(SecretKit.Core.SecretInventoryScope,System.Threading.CancellationToken)"),
        new("create", "SecretKit.Infisical.InfisicalClient.CreateAsync(SecretKit.Core.SecretReference,SecretKit.Core.SecretMaterial,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)"),
        new("update-value", "SecretKit.Infisical.InfisicalClient.UpdateValueAsync(SecretKit.Core.SecretReference,SecretKit.Core.SecretMaterial,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)"),
        new("universal-login", "SecretKit.Infisical.InfisicalUniversalAuthentication.LoginAsync(System.String,SecretKit.Core.SecretMaterial,SecretKit.Infisical.InfisicalUniversalLoginReceipt,System.String,System.Threading.CancellationToken)"),
        new("get-token", "SecretKit.Infisical.InfisicalPeriodicTokenSession.GetTokenAsync(System.Threading.CancellationToken)"),
        new("renew-token", "SecretKit.Infisical.InfisicalPeriodicTokenSession.RenewAsync(System.Threading.CancellationToken)"),
        new("read-native", "SecretKit.Infisical.InfisicalClient.ReadNativeAsync(SecretKit.Core.SecretReference,System.Threading.CancellationToken)")
    ];

    public static LocalProfile ReadProfile(string source)
    {
        LocalProfile profile = Manifest.Parse<LocalProfile>(
            Manifest.ReadFile(Path.Combine(source, ProfileDirectory), ProfileFile, 1024 * 1024));
        Guard.Require(profile.SchemaVersion == 1 && profile.Kind == "local-profile" &&
            profile.Id == "infisical-runtime" && VersionPattern().IsMatch(profile.Version) &&
            profile.NativeReadPolicy == "Raw IncludeImports=false", "local-profile");
        Manifest.ExactSet(profile.PackageIds, PackageIds, "local-package-family");
        Manifest.ExactSet(profile.Operations.Select(o => o.Id), Operations.Select(o => o.Id), "local-operations");
        Guard.Require(profile.Operations.All(o => Operations.Contains(o)), "local-members");
        Manifest.ExactSet(profile.Scenarios, Enumerable.Range(1, 16).Select(i =>
            "S" + i.ToString("D2", CultureInfo.InvariantCulture)), "local-scenarios");
        return profile;
    }

    public static LocalQualificationRecord Prepare(string source, string originals, string output)
    {
        LocalProfile profile = ReadProfile(source);
        LocalSourceSnapshot snapshot = CaptureSource(source);
        byte[] profileBytes = Manifest.ReadFile(Path.Combine(source, ProfileDirectory), ProfileFile, 1024 * 1024);
        Guard.Require(snapshot.Files.Single(f => f.File == $"{ProfileDirectory}/{ProfileFile}").Sha256 ==
            Manifest.Hash(profileBytes), "local-profile-changed");
        PackageRecord[] packages = InspectOriginals(source, originals, profile, null, null, out string commit);
        var record = new LocalQualificationRecord(1, "local-qualification", Prepared,
            new(ProfileFile, Manifest.Hash(profileBytes)), profile.Version, commit, snapshot, packages,
            new(RuntimeInformation.RuntimeIdentifier, RuntimeInformation.FrameworkDescription,
                RuntimeInformation.OSDescription));
        // Catch source edits during archive inspection. Callers must freeze inputs
        // across packing and native evidence; this is not a trusted build attestation.
        RequireSameSource(snapshot, CaptureSource(source));
        Guard.Require(JsonSerializer.SerializeToUtf8Bytes(record, Manifest.JsonOptions).Length <= 4 * 1024 * 1024,
            "local-record-size");
        string destination = Path.GetFullPath(output);
        Guard.Require(!Directory.Exists(destination) && !File.Exists(destination), "local-output-exists");
        CheckDirectory(Path.GetDirectoryName(destination)!);
        Guard.Require(!Within(source, destination) || ExcludedOutput(source, destination), "local-output-in-source");
        Directory.CreateDirectory(destination);
        CheckDirectory(destination);
        Candidate.Write(destination, RecordFile, record);
        return record;
    }

    public static LocalQualificationRecord Check(string source, string originals, string directory)
    {
        LocalQualificationRecord record = Manifest.Parse<LocalQualificationRecord>(
            Manifest.ReadFile(directory, RecordFile, 4 * 1024 * 1024));
        Guard.Require(record.SchemaVersion == 1 && record.Kind == "local-qualification" &&
            record.Status == Prepared && record.Profile.File == ProfileFile, "local-record");
        LocalProfile profile = ReadProfile(source);
        Guard.Require(record.Version == profile.Version && CommitPattern().IsMatch(record.SourceCommit),
            "local-record-binding");
        _ = Manifest.ReadDigest(Path.Combine(source, ProfileDirectory), record.Profile);
        Guard.Require(Manifest.SafeLabel(record.Platform.RuntimeIdentifier) &&
            record.Platform.Framework.StartsWith(".NET ", StringComparison.Ordinal) &&
            record.Platform.Framework.Length <= 100 &&
            record.Platform.OperatingSystem.Length is > 0 and <= 1024, "local-platform");
        RequireSameSource(record.Source, CaptureSource(source));
        _ = InspectOriginals(source, originals, profile, record.Packages, record.SourceCommit, out _);
        RequireSameSource(record.Source, CaptureSource(source));
        return record;
    }

    // Explicit source-content route works for dirty trees and untracked source.
    // Do not use Git's HEAD or ignore rules as a substitute for source bytes.
    public static LocalSourceSnapshot CaptureSource(string source)
    {
        string root = Path.GetFullPath(source);
        CheckDirectory(root);
        var files = new List<FileDigest>();
        Visit(root);
        Guard.Require(files.Count > 0, "local-source-empty");
        FileDigest[] sorted = files.OrderBy(f => f.File, StringComparer.Ordinal).ToArray();
        return new("source-content-v1", Manifest.Hash(JsonSerializer.SerializeToUtf8Bytes(sorted, Manifest.JsonOptions)),
            sorted);

        void Visit(string directory)
        {
            CheckDirectory(directory);
            foreach (string path in Directory.EnumerateFileSystemEntries(directory).Order(StringComparer.Ordinal))
            {
                string relative = Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/');
                if (Excluded(relative)) continue;
                FileAttributes attributes = File.GetAttributes(path);
                Guard.Require((attributes & FileAttributes.ReparsePoint) == 0, "local-source-link");
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    Visit(path);
                }
                else
                {
                    Guard.Require(files.Count < 20000, "local-source-size");
                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                    files.Add(new(relative, Convert.ToHexStringLower(SHA256.HashData(stream))));
                }
            }
        }
    }

    private static void RequireSameSource(LocalSourceSnapshot expected, LocalSourceSnapshot actual)
    {
        Guard.Require(expected.Kind == "source-content-v1" && Manifest.IsHash(expected.Sha256) &&
            expected.Sha256 == actual.Sha256 &&
            expected.Files.SequenceEqual(actual.Files), "local-source-content");
    }

    private static bool Excluded(string relative)
    {
        string[] parts = relative.Split('/');
        return parts[0] is ".git" or "artifacts" or "dev" or ".worktrees" ||
            parts.Any(p => p is "bin" or "obj" or "TestResults");
    }

    private static bool Within(string root, string path) =>
        Path.GetRelativePath(Path.GetFullPath(root), path) is string relative &&
        relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) &&
        !Path.IsPathRooted(relative);

    private static bool ExcludedOutput(string source, string output) =>
        Excluded(Path.GetRelativePath(Path.GetFullPath(source), output).Replace(Path.DirectorySeparatorChar, '/'));

    private static void CheckDirectory(string directory)
    {
        for (DirectoryInfo? part = new(Path.GetFullPath(directory)); part is not null; part = part.Parent)
            Guard.Require(part.Exists && (part.Attributes & FileAttributes.ReparsePoint) == 0, "local-directory-link");
    }

    private static PackageRecord[] InspectOriginals(string source, string originals, LocalProfile profile,
        PackageRecord[]? expected, string? sourceCommit, out string observedCommit)
    {
        CheckDirectory(originals);
        Manifest.ExactSet(Directory.EnumerateFileSystemEntries(originals).Select(Path.GetFileName).Select(n => n!),
            PackageIds.Select(id => $"{id}.{profile.Version}.nupkg"), "local-original-family");
        if (expected is not null)
            Manifest.ExactSet(expected.Select(p => p.Id), PackageIds, "local-record-family");
        byte[] notices = Manifest.ReadFile(source, "THIRD-PARTY-NOTICES.md", 1024 * 1024);
        var packages = new List<PackageRecord>();
        string? commit = sourceCommit;
        foreach (string id in PackageIds)
        {
            string file = $"{id}.{profile.Version}.nupkg";
            byte[] bytes;
            if (expected is null)
                bytes = Manifest.ReadFile(originals, file, PackageArchive.MaximumBytes);
            else
            {
                PackageRecord package = expected.Single(p => p.Id == id);
                Guard.Require(package.File == file, "local-original-name");
                bytes = Manifest.ReadDigest(originals, new(package.File, package.Sha256));
            }
            ArchiveContent archive = PackageArchive.Read(bytes);
            Guard.Require(!archive.HasSignature && archive.Files.ContainsKey(id + ".nuspec") &&
                archive.Files.Keys.Count(n => n.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)) == 1 &&
                archive.Files.ContainsKey("README.md") &&
                archive.Files.TryGetValue("THIRD-PARTY-NOTICES.md", out byte[]? embedded) &&
                embedded.SequenceEqual(notices), "local-original-content");
            using var stream = new MemoryStream(archive.Files[id + ".nuspec"]);
            using XmlReader reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 1024 * 1024
            });
            XElement document = XDocument.Load(reader).Root ?? throw new ReleaseException("local-nuspec");
            XNamespace ns = document.Name.Namespace;
            Guard.Require(document.Name.LocalName == "package" &&
                document.Elements(ns + "metadata").Count() == 1, "local-nuspec");
            XElement metadata = document.Element(ns + "metadata")!;
            Guard.Require(new[] { "id", "version", "repository", "license", "dependencies" }.All(name =>
                metadata.Elements(ns + name).Count() == 1), "local-nuspec-fields");
            XElement repository = metadata.Element(ns + "repository")!;
            string declaredCommit = repository.Attribute("commit")?.Value ?? "";
            commit ??= declaredCommit;
            Guard.Require(metadata.Element(ns + "id")!.Value == id &&
                metadata.Element(ns + "version")!.Value == profile.Version &&
                CommitPattern().IsMatch(declaredCommit) && declaredCommit == commit &&
                repository.Attribute("type")?.Value == "git" &&
                repository.Attribute("url")?.Value == Manifest.Repository &&
                metadata.Element(ns + "license")!.Value == "MIT" &&
                metadata.Element(ns + "license")!.Attribute("type")?.Value == "expression", "local-nuspec-binding");
            XElement dependencies = metadata.Element(ns + "dependencies")!;
            Guard.Require(dependencies.Elements().All(e => e.Name == ns + "group") &&
                dependencies.Elements().Count() == 1, "local-dependency-group");
            XElement group = dependencies.Elements().Single();
            Guard.Require(group.Attribute("targetFramework")?.Value == "net10.0" &&
                group.Elements().All(e => e.Name == ns + "dependency"), "local-dependency-framework");
            XElement[] entries = group.Elements().ToArray();
            string[] internalIds = id switch
            {
                "SecretKit.Core" => [],
                "SecretKit.Extensions.Hosting" => ["SecretKit.Core", "SecretKit.Infisical"],
                _ => ["SecretKit.Core"]
            };
            Manifest.ExactSet(entries.Where(e => ((string?)e.Attribute("id"))?.StartsWith("SecretKit.",
                StringComparison.OrdinalIgnoreCase) == true).Select(e => (string)e.Attribute("id")!), internalIds,
                "local-dependency-closure");
            string[] externalIds = id switch
            {
                "SecretKit.Core" => [],
                "SecretKit.Infisical" => ["Refit"],
                "SecretKit.Extensions.Configuration" => ["Microsoft.Extensions.Configuration"],
                _ => ["Microsoft.Extensions.Hosting.Abstractions", "Microsoft.Extensions.Diagnostics.HealthChecks",
                    "Microsoft.Extensions.DependencyInjection.Abstractions"]
            };
            Manifest.ExactSet(entries.Select(e => (string?)e.Attribute("id") ?? ""),
                internalIds.Concat(externalIds), "local-dependency-family");
            Guard.Require(entries.All(e => e.Attribute("id") is not null && e.Attribute("version") is not null) &&
                entries.Select(e => (string)e.Attribute("id")!).Distinct(StringComparer.OrdinalIgnoreCase).Count() ==
                    entries.Length &&
                entries.Where(e => internalIds.Contains((string)e.Attribute("id")!)).All(e =>
                    e.Attribute("version")!.Value == $"[{profile.Version}]" ||
                    e.Attribute("version")!.Value == profile.Version) &&
                !metadata.Descendants(ns + "frameworkReference").Any() &&
                !metadata.Descendants(ns + "frameworkAssembly").Any(), "local-dependencies");
            packages.Add(new(id, file, Manifest.Hash(bytes)));
        }
        observedCommit = commit!;
        return packages.ToArray();
    }

    [GeneratedRegex(@"\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[a-z][a-z0-9-]*(\.(0|[1-9][0-9]*|[a-z][a-z0-9-]*))*)?\z", RegexOptions.CultureInvariant)]
    private static partial Regex VersionPattern();
    [GeneratedRegex(@"\A[0-9a-f]{40}\z", RegexOptions.CultureInvariant)]
    private static partial Regex CommitPattern();
}
