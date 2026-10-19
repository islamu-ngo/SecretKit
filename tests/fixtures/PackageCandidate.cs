using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace SecretKit.TestFixtures;

internal sealed class PackageCandidate
{
    internal static readonly string[] PackageIds =
    [
        "SecretKit.Core", "SecretKit.Infisical", "SecretKit.AzureKeyVault",
        "SecretKit.Extensions.Configuration", "SecretKit.Extensions.Hosting",
        "SecretKit.Infisical.Management", "SecretKit.AzureKeyVault.Management"
    ];

    private readonly IReadOnlyDictionary<string, byte[]> _hashes;

    private PackageCandidate(string directory, string version, IReadOnlyDictionary<string, byte[]> hashes)
    {
        Directory = directory;
        Version = version;
        _hashes = hashes;
    }

    internal string Directory { get; }
    internal string Version { get; }

    internal static PackageCandidate FromEnvironment(string root) => Select(root,
        Environment.GetEnvironmentVariable("SECRETKIT_CANDIDATE_VERSION"),
        Environment.GetEnvironmentVariable("SECRETKIT_CANDIDATE_DIRECTORY"));

    internal static PackageCandidate Select(string root, string? version = null, string? directory = null)
    {
        try
        {
            if (version is not null) RequireVersion(version);
            directory ??= Path.Combine(root, "artifacts", "packages");
            RequirePath(directory);
            string source = Path.GetFullPath(directory, root);
            if (!System.IO.Directory.Exists(source)) throw Failure();
            // Ordinary pack also emits symbols; only the original installation archives form this family.
            string[] paths = System.IO.Directory.EnumerateFiles(source, "*.nupkg").Take(8).ToArray();
            if (paths.Length != PackageIds.Length) throw Failure();
            var hashes = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (string path in paths)
            {
                if (new FileInfo(path).Length > 64 * 1024 * 1024) throw Failure();
                using ZipArchive archive = ZipFile.OpenRead(path);
                ZipArchiveEntry[] manifests = archive.Entries.Where(entry =>
                    entry.FullName.EndsWith(".nuspec", StringComparison.Ordinal)).Take(2).ToArray();
                if (manifests.Length != 1 || manifests[0].Length > 65536) throw Failure();
                using Stream stream = manifests[0].Open();
                using XmlReader reader = XmlReader.Create(stream, new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = 65536
                });
                XDocument manifest = XDocument.Load(reader);
                XElement metadata = manifest.Root?.Element(manifest.Root.Name.Namespace + "metadata") ?? throw Failure();
                XNamespace ns = metadata.Name.Namespace;
                string id = metadata.Element(ns + "id")?.Value ?? throw Failure();
                string declaredVersion = metadata.Element(ns + "version")?.Value ?? throw Failure();
                RequireVersion(declaredVersion);
                version ??= declaredVersion;
                if (!PackageIds.Contains(id, StringComparer.Ordinal) || declaredVersion != version ||
                    Path.GetFileName(path) != $"{id}.{version}.nupkg" || hashes.ContainsKey(id))
                    throw Failure();
                using FileStream original = File.OpenRead(path);
                hashes.Add(id, SHA256.HashData(original));
            }
            if (version is null || PackageIds.Any(id => !hashes.ContainsKey(id))) throw Failure();
            return new PackageCandidate(source, version, hashes);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or XmlException)
        {
            throw Failure();
        }
    }

    internal string ArchivePath(string id) => Path.Combine(Directory, $"{id}.{Version}.nupkg");

    internal ConsumerInstallation PrepareConsumer(string outputs)
    {
        RequirePath(outputs);
        string packages = Path.Combine(outputs, "packages");
        // Refuse reuse even when a previous cache happens to contain the right version.
        if (System.IO.Directory.Exists(packages) || File.Exists(packages)) throw Failure();
        System.IO.Directory.CreateDirectory(packages);
        string intermediate = Path.Combine(outputs, "obj") + Path.DirectorySeparatorChar;
        string binary = Path.Combine(outputs, "bin") + Path.DirectorySeparatorChar;
        if (System.IO.Directory.Exists(intermediate) || System.IO.Directory.Exists(binary)) throw Failure();
        string configuration = Path.Combine(outputs, "NuGet.Config");
        new XDocument(new XElement("configuration",
            new XElement("packageSources", new XElement("clear"),
                new XElement("add", new XAttribute("key", "candidate"), new XAttribute("value", Directory)),
                new XElement("add", new XAttribute("key", "nuget.org"),
                    new XAttribute("value", "https://api.nuget.org/v3/index.json"))),
            new XElement("packageSourceMapping", new XElement("clear"),
                new XElement("packageSource", new XAttribute("key", "candidate"),
                    new XElement("package", new XAttribute("pattern", "SecretKit.*"))),
                new XElement("packageSource", new XAttribute("key", "nuget.org"),
                    new XElement("package", new XAttribute("pattern", "*")))))).Save(configuration);
        return new ConsumerInstallation(configuration, packages, intermediate, binary,
        [
            $"-p:SecretKitCandidateVersion={Version}",
            $"-p:RestorePackagesPath={packages}",
            $"-p:BaseIntermediateOutputPath={intermediate}",
            $"-p:MSBuildProjectExtensionsPath={intermediate}",
            $"-p:BaseOutputPath={binary}"
        ]);
    }

    internal void VerifyRestored(string assetsPath, string packagesPath)
    {
        try
        {
            using JsonDocument assets = JsonDocument.Parse(File.ReadAllText(assetsPath));
            JsonProperty[] folders = assets.RootElement.GetProperty("packageFolders").EnumerateObject().ToArray();
            if (folders.Length != 1 ||
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(folders[0].Name)) !=
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(packagesPath))) throw Failure();
            var resolved = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty library in assets.RootElement.GetProperty("libraries").EnumerateObject())
            {
                if (library.Value.GetProperty("type").GetString() != "package") throw Failure();
                if (!library.Name.StartsWith("SecretKit.", StringComparison.OrdinalIgnoreCase)) continue;
                string[] identity = library.Name.Split('/');
                if (identity.Length != 2 || identity[1] != Version || !_hashes.TryGetValue(identity[0], out byte[]? hash) ||
                    !resolved.Add(identity[0])) throw Failure();
                string relative = $"{identity[0].ToLowerInvariant()}/{Version.ToLowerInvariant()}";
                if (library.Value.GetProperty("path").GetString() != relative) throw Failure();
                string restored = Path.Combine(packagesPath, relative,
                    $"{identity[0].ToLowerInvariant()}.{Version.ToLowerInvariant()}.nupkg");
                using FileStream original = File.OpenRead(restored);
                if (!SHA256.HashData(original).AsSpan().SequenceEqual(hash)) throw Failure();
            }
            if (resolved.Count != PackageIds.Length) throw Failure();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or
            KeyNotFoundException or ArgumentException)
        {
            throw Failure();
        }
    }

    private static void RequireVersion(string version)
    {
        // NuGet-normalized three-part SemVer, without metadata or MSBuild delimiters.
        if (version.Length is 0 or > 100 || !Regex.IsMatch(version,
            @"\A(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?\z",
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)) throw Failure();
        int separator = version.IndexOf('-');
        if (separator >= 0 && version[(separator + 1)..].Split('.').Any(identifier =>
            identifier.Length > 1 && identifier[0] == '0' && identifier.All(char.IsAsciiDigit))) throw Failure();
    }

    private static void RequirePath(string path)
    {
        if (path.Length is 0 or > 4096 || path.Any(character => char.IsControl(character) ||
            character is ';' or ',' or '%' or '$')) throw Failure();
    }

    private static InvalidOperationException Failure() =>
        new("Candidate package verification failed; protected diagnostics withheld.");
}

internal sealed record ConsumerInstallation(string Configuration, string Packages, string Intermediate,
    string Binary, string[] Properties);
