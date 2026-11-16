using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace SecretKit.Release;

/// <summary>Validates embedded SPDX 2.2 SBOM manifests inside shipped SecretKit NuGet archives.</summary>
public static class SbomManifest
{
    public const string ManifestPath = "_manifest/spdx_2.2/manifest.spdx.json";
    public const string DigestPath = "_manifest/spdx_2.2/manifest.spdx.json.sha256";
    public const string NamespacePrefix = "https://github.com/islamu-ngo/SecretKit/spdx/";

    private static readonly HashSet<string> BuildOnlyToolIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft.NET.ILLink.Tasks",
        "Microsoft.Sbom.Targets"
    };

    /// <summary>Verifies that <paramref name="archive"/> embeds a valid SPDX 2.2 manifest matching its contents and dependencies.</summary>
    public static void Verify(ArchiveContent archive, string id, string version)
    {
        ArgumentNullException.ThrowIfNull(archive);
        Guard.Require(!string.IsNullOrWhiteSpace(id) && !string.IsNullOrWhiteSpace(version), "sbom-identity");
        if (!archive.Files.TryGetValue(ManifestPath, out byte[]? json) ||
            json.Length is <= 0 or > EvidenceLimits.RecordBytes)
        {
            throw new ReleaseException("sbom-manifest-missing");
        }

        if (!archive.Files.TryGetValue(DigestPath, out byte[]? digestBytes) ||
            digestBytes.Length != 64 || Manifest.Hash(json) != Encoding.ASCII.GetString(digestBytes))
        {
            throw new ReleaseException("sbom-digest-mismatch");
        }

        using JsonDocument document = ParseDocument(json);
        JsonElement root = document.RootElement;
        ValidateDocumentHeader(root, id, version);
        ValidateFileHashes(root, archive.Files);
        ValidatePackagesAndDependencies(root, archive, id, version);
    }

    private static JsonDocument ParseDocument(byte[] json)
    {
        try
        {
            return JsonDocument.Parse(json, new JsonDocumentOptions
            {
                AllowDuplicateProperties = false,
                MaxDepth = 32
            });
        }
        catch (JsonException)
        {
            throw new ReleaseException("sbom-json");
        }
    }

    private static void ValidateDocumentHeader(JsonElement root, string id, string version)
    {
        Guard.Require(root.ValueKind == JsonValueKind.Object, "sbom-root");
        Guard.Require(RequiredString(root, "spdxVersion") == "SPDX-2.2", "sbom-version");
        Guard.Require(RequiredString(root, "dataLicense") == "CC0-1.0", "sbom-data-license");
        Guard.Require(RequiredString(root, "SPDXID") == "SPDXRef-DOCUMENT", "sbom-spdx-id");
        Guard.Require(RequiredString(root, "name") == $"{id} {version}", "sbom-name");

        string ns = RequiredString(root, "documentNamespace");
        string expectedPrefix = $"{NamespacePrefix}{id}/{version}/";
        Guard.Require(ns.StartsWith(expectedPrefix, StringComparison.Ordinal) &&
            ns.Length > expectedPrefix.Length &&
            !ns[expectedPrefix.Length..].Contains('/', StringComparison.Ordinal) &&
            !ns[NamespacePrefix.Length..].Contains("//", StringComparison.Ordinal),
            "sbom-namespace");

        Guard.Require(root.TryGetProperty("creationInfo", out JsonElement creation) &&
            creation.ValueKind == JsonValueKind.Object, "sbom-creation-info");
        string created = RequiredString(creation, "created");
        Guard.Require(created.EndsWith('Z') &&
            DateTimeOffset.TryParse(created, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset createdAt) &&
            createdAt.Offset == TimeSpan.Zero, "sbom-created");
        Guard.Require(creation.TryGetProperty("creators", out JsonElement creators) &&
            creators.ValueKind == JsonValueKind.Array && creators.GetArrayLength() > 0 &&
            creators.EnumerateArray().All(c => c.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(c.GetString())),
            "sbom-creators");

        Guard.Require(root.TryGetProperty("documentDescribes", out JsonElement describes) &&
            describes.ValueKind == JsonValueKind.Array &&
            describes.EnumerateArray().Any(item => item.ValueKind == JsonValueKind.String && item.GetString() == "SPDXRef-RootPackage"),
            "sbom-describes");
    }

    private static void ValidateFileHashes(JsonElement root, IReadOnlyDictionary<string, byte[]> archiveFiles)
    {
        var expectedHashes = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach ((string name, byte[] content) in archiveFiles)
        {
            if (name is ManifestPath or DigestPath)
            {
                continue;
            }

            expectedHashes.Add(name, Manifest.Hash(content));
        }

        Guard.Require(root.TryGetProperty("files", out JsonElement files) &&
            files.ValueKind == JsonValueKind.Array, "sbom-files");
        var seenPaths = new HashSet<string>(StringComparer.Ordinal);
        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonElement file in files.EnumerateArray())
        {
            Guard.Require(file.ValueKind == JsonValueKind.Object, "sbom-file-entry");
            string fileName = RequiredString(file, "fileName");
            string spdxId = RequiredString(file, "SPDXID");
            Guard.Require(fileName.StartsWith("./", StringComparison.Ordinal) &&
                seenPaths.Add(fileName[2..]) && seenIds.Add(spdxId), "sbom-file-name");
            Guard.Require(expectedHashes.TryGetValue(fileName[2..], out string? expectedSha256), "sbom-file-unexpected");
            Guard.Require(TryReadSha256(file, out string? actualSha256) && actualSha256 == expectedSha256, "sbom-file-hash");
        }

        Manifest.ExactSet(seenPaths, expectedHashes.Keys, "sbom-file-coverage");
    }

    private static void ValidatePackagesAndDependencies(JsonElement root, ArchiveContent archive, string id, string version)
    {
        Guard.Require(root.TryGetProperty("packages", out JsonElement packages) &&
            packages.ValueKind == JsonValueKind.Array, "sbom-packages");

        int rootCount = 0;
        var packageList = new List<(string Name, string Version, List<string> Purls)>();
        foreach (JsonElement pkg in packages.EnumerateArray())
        {
            Guard.Require(pkg.ValueKind == JsonValueKind.Object, "sbom-package-entry");
            string spdxId = RequiredString(pkg, "SPDXID");
            string name = RequiredString(pkg, "name");
            string pkgVersion = RequiredString(pkg, "versionInfo");
            if (spdxId == "SPDXRef-RootPackage")
            {
                Guard.Require(name == id && pkgVersion == version, "sbom-root-package");
                rootCount++;
            }
            else
            {
                Guard.Require(!string.Equals(name, id, StringComparison.OrdinalIgnoreCase), "sbom-duplicate-self");
            }

            var purls = new List<string>();
            if (pkg.TryGetProperty("externalRefs", out JsonElement refs) && refs.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement reference in refs.EnumerateArray())
                {
                    if (reference.ValueKind == JsonValueKind.Object &&
                        reference.TryGetProperty("referenceType", out JsonElement refType) &&
                        refType.ValueKind == JsonValueKind.String &&
                        refType.GetString() == "purl" &&
                        reference.TryGetProperty("referenceLocator", out JsonElement locator) &&
                        locator.ValueKind == JsonValueKind.String &&
                        !string.IsNullOrWhiteSpace(locator.GetString()))
                    {
                        purls.Add(locator.GetString()!);
                    }
                }
            }

            packageList.Add((name, pkgVersion, purls));
        }

        Guard.Require(rootCount == 1, "sbom-root-package");
        ValidateNuspecDependencies(archive, id, packageList);
    }

    private static void ValidateNuspecDependencies(ArchiveContent archive, string id,
        List<(string Name, string Version, List<string> Purls)> packageList)
    {
        if (!archive.Files.TryGetValue(id + ".nuspec", out byte[]? nuspecBytes))
        {
            throw new ReleaseException("sbom-nuspec-missing");
        }
        using var stream = new MemoryStream(nuspecBytes, writable: false);
        using XmlReader reader = XmlReader.Create(stream, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = 1024 * 1024
        });
        XDocument doc = XDocument.Load(reader);
        XElement root = doc.Root ?? throw new ReleaseException("sbom-nuspec");
        XNamespace ns = root.Name.Namespace;
        foreach (XElement dep in root.Descendants(ns + "dependency"))
        {
            string depId = dep.Attribute("id")?.Value ?? throw new ReleaseException("sbom-nuspec-dependency");
            string rawVersion = dep.Attribute("version")?.Value ?? throw new ReleaseException("sbom-nuspec-dependency");
            Guard.Require(!BuildOnlyToolIds.Contains(depId), "sbom-build-tool-dependency");
            if (depId.StartsWith("SecretKit.", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string normalized = rawVersion.Trim('[', ']', '(', ')', ' ');
            bool matched = packageList.Any(entry =>
                string.Equals(entry.Name, depId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(entry.Version, normalized, StringComparison.OrdinalIgnoreCase) &&
                entry.Purls.Any(purl => purl.StartsWith($"pkg:nuget/{depId}@{normalized}", StringComparison.OrdinalIgnoreCase)));
            Guard.Require(matched, "sbom-missing-dependency");
        }
    }

    private static bool TryReadSha256(JsonElement file, out string? sha256)
    {
        sha256 = null;
        if (!file.TryGetProperty("checksums", out JsonElement checksums) || checksums.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (JsonElement item in checksums.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.Object &&
                item.TryGetProperty("algorithm", out JsonElement algorithm) &&
                algorithm.ValueKind == JsonValueKind.String &&
                algorithm.GetString() == "SHA256" &&
                item.TryGetProperty("checksumValue", out JsonElement value) &&
                value.ValueKind == JsonValueKind.String &&
                value.GetString() is string hex && Manifest.IsHash(hex))
            {
                sha256 = hex;
                return true;
            }
        }

        return false;
    }

    private static string RequiredString(JsonElement obj, string propertyName)
    {
        Guard.Require(obj.TryGetProperty(propertyName, out JsonElement property) &&
            property.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(property.GetString()), "sbom-property");
        return property.GetString()!;
    }
}
