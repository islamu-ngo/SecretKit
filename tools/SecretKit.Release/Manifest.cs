using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace SecretKit.Release;

public sealed record FileDigest(string File, string Sha256);
public sealed record PackageRecord(string Id, string File, string Sha256);
public sealed record GateRecord(string Kind, string File, string Sha256);
public sealed record NativeOperation(string Provider, string Operation, string Scope, string Depth)
{
    [JsonIgnore]
    public string Key => $"{Provider}/{Operation}/{Scope}/{Depth}";
}
public sealed record ReleaseScope(string Version, string SourceCommit, string[] PackageIds,
    NativeOperation[] NativeOperations, string[] Platforms, FileDigest[] Registries);
public sealed record GateEvidence(string Kind, string Status, string Version, string SourceCommit,
    string ScopeSha256, string[] PackageIds, string[] Checks, FileDigest Record);
public sealed record ReleaseManifest(int SchemaVersion, string Family, string Version, string SourceCommit,
    string Repository, long SourceRunId, string Publisher, string Owner, string Prefix,
    string Environment, string NoticesSha256, FileDigest Scope, PackageRecord[] Packages, GateRecord[] Gates);
public sealed record Approval(string ManifestSha256, string SourceCommit, string Version, long SourceRunId,
    long ArtifactId, string ArtifactDigest, string ScopeSha256, string Publisher, string Owner,
    string RepositoryCertificateSha256, string JournalHead);

public sealed record VerifiedRelease(ReleaseManifest Manifest, string ManifestSha256,
    IReadOnlyDictionary<string, byte[]> Packages);

public static partial class Manifest
{
    public const string Repository = "https://github.com/islamu-ngo/SecretKit";
    public const string RepositoryName = "islamu-ngo/SecretKit";
    public static IReadOnlyList<string> PackageIds { get; } = Array.AsReadOnly(new[]
    {
        "SecretKit.Core", "SecretKit.Infisical", "SecretKit.AzureKeyVault",
        "SecretKit.Extensions.Configuration", "SecretKit.Extensions.Hosting",
        "SecretKit.Infisical.Management", "SecretKit.AzureKeyVault.Management"
    });
    public static IReadOnlyList<string> GateKinds { get; } = Array.AsReadOnly(new[]
    {
        "native-operations", "live-conformance", "compatibility-install", "provenance", "notices",
        "namespace-rights", "publisher-rights", "oidc-registration", "protected-environment"
    });
    public static JsonSerializerOptions JsonOptions { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectNullableAnnotations = true,
        RespectRequiredConstructorParameters = true,
        WriteIndented = true,
        MaxDepth = 32
    };

    public static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    public static bool IsHash(string value) => value is not null && HashPattern().IsMatch(value);

    public static T Parse<T>(byte[] bytes)
    {
        Guard.Require(bytes.Length is > 0 and <= 4 * 1024 * 1024, "json-size");
        using JsonDocument document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
        RejectDuplicateProperties(document.RootElement);
        return JsonSerializer.Deserialize<T>(bytes, JsonOptions) ?? throw new ReleaseException("json-null");
    }

    public static VerifiedRelease Verify(string directory, Approval approval)
    {
        byte[] manifestBytes = ReadFile(directory, "manifest.json", 4 * 1024 * 1024);
        Guard.Require(IsHash(approval.ManifestSha256) && Hash(manifestBytes) == approval.ManifestSha256,
            "manifest-approval");
        ReleaseManifest manifest = Parse<ReleaseManifest>(manifestBytes);
        Guard.Require(manifest.SchemaVersion == 1 && manifest.Family == "SecretKit" &&
            VersionPattern().IsMatch(manifest.Version) && manifest.Version == approval.Version, "family-version");
        Guard.Require(CommitPattern().IsMatch(manifest.SourceCommit) &&
            manifest.SourceCommit == approval.SourceCommit && manifest.Repository == Repository, "source-approval");
        Guard.Require(manifest.SourceRunId > 0 && manifest.SourceRunId == approval.SourceRunId &&
            approval.ArtifactId > 0 &&
            IsHash(approval.ArtifactDigest), "artifact-approval");
        Guard.Require(manifest.Environment == "release" && manifest.Prefix == "SecretKit." &&
            SafeIdentity(manifest.Publisher) && SafeIdentity(manifest.Owner) &&
            manifest.Publisher == approval.Publisher && manifest.Owner == approval.Owner &&
            IsHash(approval.RepositoryCertificateSha256), "publisher-approval");
        Guard.Require(IsHash(manifest.NoticesSha256) && manifest.Scope.Sha256 == approval.ScopeSha256, "scope-approval");
        ExactSet(manifest.Packages.Select(p => p.Id), PackageIds, "package-family");
        ExactSet(manifest.Gates.Select(g => g.Kind), GateKinds, "gate-coverage");
        ReleaseScope scope = Parse<ReleaseScope>(ReadDigest(directory, manifest.Scope));
        Guard.Require(scope.Version == manifest.Version && scope.SourceCommit == manifest.SourceCommit, "scope-binding");
        ExactSet(scope.PackageIds, PackageIds, "scope-family");
        Guard.Require(scope.Platforms.Length > 0 && scope.Platforms.All(SafeLabel), "platform-coverage");
        Guard.Require(scope.NativeOperations.Length > 0 && scope.NativeOperations.All(o =>
            o.Provider is "Infisical" or "AzureKeyVault" && SafeLabel(o.Operation) && SafeLabel(o.Scope) &&
            o.Depth == "complete") && scope.NativeOperations.Select(o => o.Key).Distinct().Count() ==
            scope.NativeOperations.Length &&
            scope.NativeOperations.Select(o => o.Provider).Distinct().Count() == 2, "native-scope");
        ExactSet(scope.Registries.Select(r => r.File),
            ["infisical-operations.json", "azure-key-vault-operations.json"], "registry-coverage");
        foreach (FileDigest registry in scope.Registries)
        {
            using JsonDocument document = JsonDocument.Parse(ReadDigest(directory, registry),
                new JsonDocumentOptions { MaxDepth = 32 });
            RejectDuplicateProperties(document.RootElement);
            string provider = registry.File == "infisical-operations.json" ? "Infisical" : "AzureKeyVault";
            Guard.Require(document.RootElement.GetProperty("provider").GetString() == provider, "registry-provider");
            JsonElement[] rows = document.RootElement.GetProperty("operations").EnumerateArray().ToArray();
            string[] allIds = rows.Select(row => row.GetProperty("id").GetString()!).ToArray();
            Guard.Require(allIds.Length == allIds.Distinct(StringComparer.Ordinal).Count(), "registry-duplicate");
            JsonElement[] admitted = rows.Where(row => row.GetProperty("admitted").GetBoolean()).ToArray();
            Guard.Require(admitted.Length > 0 && admitted.All(row => row.GetProperty("implemented").GetBoolean() &&
                row.GetProperty("liveVerified").GetBoolean() &&
                (!row.TryGetProperty("fullOperationImplemented", out JsonElement full) || full.GetBoolean())),
                "registry-incomplete");
            ExactSet(scope.NativeOperations.Where(o => o.Provider == provider).Select(o => o.Operation).Distinct(),
                admitted.Select(row => row.GetProperty("id").GetString()!), "registry-scope");
        }
        foreach (GateRecord gate in manifest.Gates)
        {
            GateEvidence evidence = Parse<GateEvidence>(ReadDigest(directory, new(gate.File, gate.Sha256)));
            Guard.Require(evidence.Kind == gate.Kind && evidence.Status == "passed" &&
                evidence.SourceCommit == manifest.SourceCommit && evidence.Version == manifest.Version &&
                evidence.ScopeSha256 == manifest.Scope.Sha256, "gate-binding");
            ExactSet(evidence.PackageIds, PackageIds, "gate-family");
            IEnumerable<string> expected = gate.Kind switch
            {
                "native-operations" or "live-conformance" => scope.NativeOperations.Select(o => o.Key),
                "compatibility-install" => scope.Platforms,
                "namespace-rights" => [.. PackageIds, manifest.Prefix],
                "publisher-rights" => [$"publisher:{manifest.Publisher}", $"owner:{manifest.Owner}"],
                "oidc-registration" => [$"{RepositoryName}/publish.yml/release", "https://www.nuget.org"],
                "protected-environment" => ["release", "required-reviewers", "prevent-self-review", "main-only"],
                "provenance" => [manifest.SourceCommit, .. manifest.Packages.Select(p => p.Sha256)],
                "notices" => [manifest.NoticesSha256],
                _ => throw new ReleaseException("gate-kind")
            };
            ExactSet(evidence.Checks, expected, "gate-checks");
            _ = ReadDigest(directory, evidence.Record);
        }

        var packages = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (PackageRecord package in manifest.Packages)
        {
            Guard.Require(package.File == $"{package.Id}.{manifest.Version}.nupkg", "package-file");
            byte[] bytes = ReadDigest(directory, new(package.File, package.Sha256));
            ArchiveContent archive = PackageArchive.Read(bytes);
            Guard.Require(!archive.HasSignature, "local-package-must-be-unsigned");
            VerifyMetadata(archive, package.Id, manifest);
            packages.Add(package.Id, bytes);
        }

        ExactSet(Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
            .Where(path => path.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase) ||
                path.EndsWith(".snupkg", StringComparison.OrdinalIgnoreCase))
            .Select(Path.GetFileName).Select(name => name!), manifest.Packages.Select(p => p.File), "artifact-family");
        return new(manifest, approval.ManifestSha256, packages);
    }

    public static byte[] ReadDigest(string directory, FileDigest file)
    {
        Guard.Require(IsHash(file.Sha256), "file-hash-format");
        byte[] bytes = ReadFile(directory, file.File, PackageArchive.MaximumBytes);
        Guard.Require(Hash(bytes) == file.Sha256, "file-hash");
        return bytes;
    }

    public static byte[] ReadFile(string directory, string name, int maximum)
    {
        Guard.Require(FilePattern().IsMatch(name) && name is not "." and not "..", "file-path");
        var root = new DirectoryInfo(Path.GetFullPath(directory));
        for (DirectoryInfo? part = root; part is not null; part = part.Parent)
        {
            Guard.Require((part.Attributes & FileAttributes.ReparsePoint) == 0, "directory-link");
        }

        string path = Path.Combine(root.FullName, name);
        var info = new FileInfo(path);
        Guard.Require(info.Exists && (info.Attributes & FileAttributes.ReparsePoint) == 0 &&
            info.Length is > 0 && info.Length <= maximum, "file-missing-or-size");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Guard.Require(stream.Length == info.Length, "file-changed");
        byte[] bytes = new byte[stream.Length];
        stream.ReadExactly(bytes);
        return bytes;
    }

    public static void ExactSet(IEnumerable<string> actual, IEnumerable<string> expected, string code)
    {
        string[] values = actual.ToArray();
        string[] wanted = expected.ToArray();
        Guard.Require(values.Length == values.Distinct(StringComparer.Ordinal).Count() &&
            values.Order(StringComparer.Ordinal).SequenceEqual(wanted.Order(StringComparer.Ordinal)), code);
    }

    private static void VerifyMetadata(ArchiveContent archive, string id, ReleaseManifest manifest)
    {
        Guard.Require(archive.Files.ContainsKey(id + ".nuspec") &&
            archive.Files.Keys.Count(key => key.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)) == 1,
            "nuspec-file");
        using var stream = new MemoryStream(archive.Files[id + ".nuspec"]);
        using XmlReader reader = XmlReader.Create(stream, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = 1024 * 1024
        });
        XDocument document = XDocument.Load(reader);
        XElement root = document.Root ?? throw new ReleaseException("nuspec-root");
        XNamespace ns = root.Name.Namespace;
        Guard.Require(root.Elements(ns + "metadata").Count() == 1, "nuspec-metadata-count");
        XElement metadata = root.Element(ns + "metadata") ?? throw new ReleaseException("nuspec-metadata");
        Guard.Require(new[] { "id", "version", "repository", "license" }.All(name =>
            metadata.Elements(ns + name).Count() == 1), "nuspec-duplicate-field");
        Guard.Require(root.Name.LocalName == "package" && metadata.Element(ns + "id")?.Value == id &&
            metadata.Element(ns + "version")?.Value == manifest.Version, "nuspec-identity");
        XElement? repository = metadata.Element(ns + "repository");
        Guard.Require(repository?.Attribute("type")?.Value == "git" &&
            repository.Attribute("url")?.Value == Repository &&
            repository.Attribute("commit")?.Value == manifest.SourceCommit, "nuspec-source");
        Guard.Require(metadata.Element(ns + "license")?.Value == "MIT" &&
            metadata.Element(ns + "license")?.Attribute("type")?.Value == "expression" &&
            archive.Files.ContainsKey("README.md") &&
            archive.Files.TryGetValue("THIRD-PARTY-NOTICES.md", out byte[]? notices) &&
            Hash(notices) == manifest.NoticesSha256, "package-notices");
    }

    private static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in element.EnumerateObject())
            {
                Guard.Require(names.Add(property.Name), "json-duplicate-property");
                RejectDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement child in element.EnumerateArray())
            {
                RejectDuplicateProperties(child);
            }
        }
    }

    private static bool SafeIdentity(string value) => IdentityPattern().IsMatch(value);
    private static bool SafeLabel(string value) => value.Length is > 0 and <= 200 &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' or ':');
    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex HashPattern();
    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex CommitPattern();
    [GeneratedRegex(@"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[a-z][a-z0-9-]*(\.(0|[1-9][0-9]*|[a-z][a-z0-9-]*))*)?$", RegexOptions.CultureInvariant)]
    private static partial Regex VersionPattern();
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,180}$", RegexOptions.CultureInvariant)]
    private static partial Regex FilePattern();
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9_-]{0,80}$", RegexOptions.CultureInvariant)]
    private static partial Regex IdentityPattern();
}
