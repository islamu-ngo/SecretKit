using System.Globalization;
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

// Offline consistency only. There is deliberately no approval, VerifiedRelease,
// journal, provider transport or public candidate in this API.
public static partial class LocalQualification
{
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
                _ => ["Microsoft.Extensions.Hosting.Abstractions", "Microsoft.Extensions.Diagnostics.HealthChecks.Abstractions"]
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
