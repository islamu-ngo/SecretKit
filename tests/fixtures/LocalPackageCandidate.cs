using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace SecretKit.TestFixtures;

internal sealed class LocalPackageCandidate
{
    internal static readonly string[] PackageIds =
    [
        "SecretKit.Core", "SecretKit.Infisical",
        "SecretKit.Extensions.Configuration", "SecretKit.Extensions.Hosting"
    ];
    private readonly Dictionary<string, byte[]> _hashes;
    private readonly Dictionary<string, string[]> _dependencies;

    private LocalPackageCandidate(string directory, string version, Dictionary<string, byte[]> hashes,
        Dictionary<string, string[]> dependencies)
    {
        Directory = directory;
        Version = version;
        _hashes = hashes;
        _dependencies = dependencies;
    }

    internal string Directory { get; }
    internal string Version { get; }
    internal string ArchivePath(string id) => Path.Combine(Directory, $"{id}.{Version}.nupkg");

    // Select four bytes-identical originals from the separately validated seven-pack family.
    // Never install directly from the seven-pack feed or modify its witnesses.
    internal static LocalPackageCandidate CopyFromFamily(string root, string version, string family, string output)
    {
        PackageCandidate seven = PackageCandidate.Select(root, version, family);
        Require(!System.IO.Directory.Exists(output) && !File.Exists(output));
        System.IO.Directory.CreateDirectory(output);
        foreach (string id in PackageIds)
        {
            string original = seven.ArchivePath(id);
            byte[] expected = Hash(original);
            string destination = Path.Combine(output, Path.GetFileName(original));
            File.Copy(original, destination);
            Require(Hash(destination).AsSpan().SequenceEqual(expected) && Hash(original).AsSpan().SequenceEqual(expected));
        }
        return Select(output, version);
    }

    internal static LocalPackageCandidate Select(string directory, string version)
    {
        Require(version.Length <= 100 && Regex.IsMatch(version,
            @"\A(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?\z",
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking));
        SafePath(directory);
        string full = Path.GetFullPath(directory);
        NoLinks(full);
        Require(System.IO.Directory.Exists(full));
        string[] archives = System.IO.Directory.GetFiles(full, "*.nupkg");
        Require(archives.Length == 4);
        var hashes = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var dependencies = new Dictionary<string, string[]>(StringComparer.Ordinal);
        foreach (string path in archives)
        {
            NoLinks(path);
            Require(new FileInfo(path).Length <= 64 * 1024 * 1024);
            using ZipArchive archive = ZipFile.OpenRead(path);
            ZipArchiveEntry[] manifests = archive.Entries.Where(e =>
                e.FullName.EndsWith(".nuspec", StringComparison.Ordinal)).ToArray();
            Require(manifests.Length == 1 && manifests[0].Length <= 65536);
            using Stream stream = manifests[0].Open();
            using XmlReader reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 65536
            });
            XElement package = XDocument.Load(reader).Root ?? throw Failure();
            XNamespace ns = package.Name.Namespace;
            XElement metadata = package.Element(ns + "metadata") ?? throw Failure();
            string id = metadata.Element(ns + "id")?.Value ?? throw Failure();
            Require(PackageIds.Contains(id, StringComparer.Ordinal) &&
                metadata.Element(ns + "version")?.Value == version &&
                Path.GetFileName(path) == $"{id}.{version}.nupkg" && !hashes.ContainsKey(id));
            XElement[] native = metadata.Descendants(ns + "dependency").ToArray();
            foreach (XElement dependency in native)
            {
                string name = (string?)dependency.Attribute("id") ?? throw Failure();
                Require(!Excluded(name));
                if (name.StartsWith("SecretKit.", StringComparison.OrdinalIgnoreCase))
                    Require(PackageIds.Contains(name, StringComparer.Ordinal) &&
                        (string?)dependency.Attribute("version") is string bound &&
                        (bound == version || bound == $"[{version}]"));
            }
            Require(!metadata.Descendants(ns + "frameworkReference").Any(e =>
                (string?)e.Attribute("name") != "Microsoft.NETCore.App"));
            dependencies.Add(id, native.Select(d => (string)d.Attribute("id")!).Distinct(StringComparer.Ordinal).ToArray());
            hashes.Add(id, Hash(path));
        }
        Require(PackageIds.All(hashes.ContainsKey) && dependencies["SecretKit.Core"].Length == 0 &&
            dependencies["SecretKit.Infisical"].Contains("SecretKit.Core", StringComparer.Ordinal) &&
            dependencies["SecretKit.Extensions.Configuration"].Contains("SecretKit.Core", StringComparer.Ordinal) &&
            dependencies["SecretKit.Extensions.Hosting"].Contains("SecretKit.Infisical", StringComparer.Ordinal));
        return new(full, version, hashes, dependencies);
    }

    internal void CreateBundle(string output)
    {
        SafePath(output);
        Require(Path.IsPathFullyQualified(output) && !System.IO.Directory.Exists(output) && !File.Exists(output));
        string? parent = Path.GetDirectoryName(output);
        while (parent is not null && !System.IO.Directory.Exists(parent)) parent = Path.GetDirectoryName(parent);
        Require(parent is not null);
        NoLinks(parent!);
        foreach (string id in PackageIds)
            Require(File.Exists(ArchivePath(id)) && Hash(ArchivePath(id)).AsSpan().SequenceEqual(_hashes[id]));
        string feed = Path.Combine(output, "feed");
        System.IO.Directory.CreateDirectory(feed);
        foreach (string id in PackageIds)
        {
            string destination = Path.Combine(feed, Path.GetFileName(ArchivePath(id)));
            File.Copy(ArchivePath(id), destination);
            Require(Hash(destination).AsSpan().SequenceEqual(_hashes[id]));
        }
        Configuration("feed/").Save(Path.Combine(output, "NuGet.Config"));
        File.WriteAllText(Path.Combine(output, "packages.sha256"), HashRecord());
        File.WriteAllText(Path.Combine(output, "README.md"),
            $"""
            # SecretKit local development bundle

            In development. Not ready for production. APIs may change without backward compatibility.

            Keep this directory intact when copying it into a repository or container build context.
            Use exact bracketed PackageReference versions [{Version}] for SecretKit.Core and
            SecretKit.Infisical; Configuration and Hosting are independently optional.
            Restore with: dotnet restore <project> --configfile <bundle>/NuGet.Config --packages <empty-cache>
            Verify packages.sha256 from this directory with: sha256sum --check packages.sha256
            SecretKit.* resolves only from feed/. External dependencies use nuget.org;
            this is not a fully offline dependency bundle. No publishing credentials are needed.
            Retain the embedded README and THIRD-PARTY-NOTICES. Replace version, archives and hashes together.
            Local installation does not establish native qualification or production readiness.
            """ + "\n");
    }

    internal static LocalPackageCandidate SelectBundle(string bundle, string version)
    {
        SafePath(bundle);
        Require(System.IO.Directory.Exists(bundle) && System.IO.Directory.Exists(Path.Combine(bundle, "feed")));
        NoLinks(bundle);
        LocalPackageCandidate candidate = Select(Path.Combine(bundle, "feed"), version);
        string configuration = Path.Combine(bundle, "NuGet.Config");
        string hashes = Path.Combine(bundle, "packages.sha256");
        Require(File.Exists(configuration) && File.Exists(hashes));
        NoLinks(configuration);
        NoLinks(hashes);
        Require(XNode.DeepEquals(XDocument.Load(configuration), Configuration("feed/")) &&
            File.ReadAllText(hashes) == candidate.HashRecord());
        return candidate;
    }

    private string HashRecord() => string.Concat(PackageIds.Select(id =>
        $"{Convert.ToHexStringLower(_hashes[id])}  feed/{Path.GetFileName(ArchivePath(id))}\n"));

    internal ConsumerInstallation PrepareBundledConsumer(string output, string mode)
    {
        string bundle = Path.GetDirectoryName(Directory)!;
        _ = SelectBundle(bundle, Version);
        return PrepareConsumer(output, mode, Path.Combine(bundle, "NuGet.Config"));
    }

    internal ConsumerInstallation PrepareConsumer(string output, string mode) => PrepareConsumer(output, mode, null);

    private ConsumerInstallation PrepareConsumer(string output, string mode, string? bundledConfiguration)
    {
        _ = Expected(mode);
        SafePath(output);
        Require(!System.IO.Directory.Exists(output) && !File.Exists(output));
        System.IO.Directory.CreateDirectory(output);
        NoLinks(output);
        string packages = Path.Combine(output, "packages");
        System.IO.Directory.CreateDirectory(packages);
        string intermediate = Path.Combine(output, "obj") + Path.DirectorySeparatorChar;
        string binary = Path.Combine(output, "bin") + Path.DirectorySeparatorChar;
        string configuration = bundledConfiguration ?? Path.Combine(output, "NuGet.Config");
        if (bundledConfiguration is null) Configuration(Directory).Save(configuration);
        return new(configuration, packages, intermediate, binary,
        [
            $"-p:SecretKitCandidateVersion={Version}", $"-p:LocalConsumerMode={mode}",
            $"-p:RestorePackagesPath={packages}", $"-p:BaseIntermediateOutputPath={intermediate}",
            $"-p:MSBuildProjectExtensionsPath={intermediate}", $"-p:BaseOutputPath={binary}",
            "-p:RestoreFallbackFolders=", "-p:NuGetAudit=false"
        ]);
    }

    private static XDocument Configuration(string source) => new(new XElement("configuration",
            new XElement("packageSources", new XElement("clear"),
                new XElement("add", new XAttribute("key", "local"), new XAttribute("value", source)),
                new XElement("add", new XAttribute("key", "nuget.org"),
                    new XAttribute("value", "https://api.nuget.org/v3/index.json"))),
            new XElement("fallbackPackageFolders", new XElement("clear")),
            new XElement("packageSourceMapping", new XElement("clear"),
                new XElement("packageSource", new XAttribute("key", "local"),
                    new XElement("package", new XAttribute("pattern", "SecretKit.*"))),
                new XElement("packageSource", new XAttribute("key", "nuget.org"),
                    new XElement("package", new XAttribute("pattern", "*"))))));

    internal void VerifyRestored(string assetsPath, string cache, string mode)
    {
        using JsonDocument assets = JsonDocument.Parse(File.ReadAllText(assetsPath));
        JsonElement document = assets.RootElement;
        JsonProperty[] folders = document.GetProperty("packageFolders").EnumerateObject().ToArray();
        Require(folders.Length == 1 && SamePath(folders[0].Name, cache));
        NoLinks(cache);
        string[] expected = Expected(mode);
        var resolved = new HashSet<string>(StringComparer.Ordinal);
        JsonProperty[] libraries = document.GetProperty("libraries").EnumerateObject().ToArray();
        foreach (JsonProperty library in libraries)
        {
            Require(library.Value.GetProperty("type").GetString() == "package" && !Excluded(library.Name));
            if (!library.Name.StartsWith("SecretKit.", StringComparison.OrdinalIgnoreCase)) continue;
            string[] identity = library.Name.Split('/');
            Require(identity.Length == 2 && identity[1] == Version &&
                expected.Contains(identity[0], StringComparer.Ordinal) && resolved.Add(identity[0]));
            string relative = $"{identity[0].ToLowerInvariant()}/{Version.ToLowerInvariant()}";
            Require(library.Value.GetProperty("path").GetString() == relative);
            string restoredDirectory = Path.Combine(cache, relative);
            string restored = Path.Combine(restoredDirectory,
                $"{identity[0].ToLowerInvariant()}.{Version.ToLowerInvariant()}.nupkg");
            NoLinks(restored);
            Require(Hash(restored).AsSpan().SequenceEqual(_hashes[identity[0]]) &&
                Hash(ArchivePath(identity[0])).AsSpan().SequenceEqual(_hashes[identity[0]]));
            using JsonDocument metadata = JsonDocument.Parse(File.ReadAllText(Path.Combine(restoredDirectory, ".nupkg.metadata")));
            Require(metadata.RootElement.GetProperty("source").GetString() is { } source && SamePath(source, Directory));
        }
        Require(resolved.SetEquals(expected));
        foreach (string id in expected)
            foreach (string dependency in _dependencies[id])
                Require(libraries.Any(library => library.Name.StartsWith(dependency + "/", StringComparison.Ordinal)));
        foreach (JsonProperty framework in document.GetProperty("project").GetProperty("frameworks").EnumerateObject())
            foreach (JsonProperty reference in framework.Value.GetProperty("frameworkReferences").EnumerateObject())
                Require(reference.Name == "Microsoft.NETCore.App");
    }

    internal static string[] Expected(string mode) => mode switch
    {
        "minimal" => ["SecretKit.Core", "SecretKit.Infisical"],
        "configuration" => ["SecretKit.Core", "SecretKit.Infisical", "SecretKit.Extensions.Configuration"],
        "hosting" => ["SecretKit.Core", "SecretKit.Infisical", "SecretKit.Extensions.Hosting"],
        "full" => PackageIds,
        _ => throw Failure()
    };

    internal static bool Excluded(string name) =>
        name.StartsWith("Azure.", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("Microsoft.Azure", StringComparison.OrdinalIgnoreCase) ||
        name.Contains(".Management", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("Event", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("Infisical.Sdk", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("Npgsql", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("MySql", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("MariaDB", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("Microsoft.Data.", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("System.Data.", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("SQLite", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("Oracle.", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("MongoDB.", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("IBM.Data.", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("Dapper", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("Microsoft.AspNetCore", StringComparison.OrdinalIgnoreCase);

    private static bool SamePath(string left, string right) =>
        string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    private static void SafePath(string path) => Require(path.Length is > 0 and <= 4096 &&
        !path.Any(c => char.IsControl(c) || c is ';' or ',' or '%' or '$'));
    private static void NoLinks(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            Require((File.GetAttributes(current) & FileAttributes.ReparsePoint) == 0);
    }
    private static byte[] Hash(string path)
    {
        using FileStream stream = File.OpenRead(path);
        return SHA256.HashData(stream);
    }
    private static void Require(bool condition)
    {
        if (!condition) throw Failure();
    }
    private static InvalidOperationException Failure() =>
        new("Local installed-package verification failed; protected diagnostics withheld.");
}
