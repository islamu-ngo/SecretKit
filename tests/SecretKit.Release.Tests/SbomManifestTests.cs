using System.Text;
using System.Text.Json.Nodes;

namespace SecretKit.Release.Tests;

public sealed class SbomManifestTests
{
    private const string Id = "SecretKit.Infisical";
    private const string Version = "0.2.0-integration.3";

    private static string Nuspec(string extraDependencies = """<dependency id="Refit" version="16.3.0" />""") =>
        $"""
        <package><metadata><id>{Id}</id><version>{Version}</version>
        <license type="expression">MIT</license>
        <repository type="git" url="{Manifest.Repository}" commit="{TestBundle.Commit}"/>
        <dependencies><group targetFramework="net10.0">
        <dependency id="SecretKit.Core" version="{Version}" />
        {extraDependencies}
        </group></dependencies>
        </metadata></package>
        """;

    private static (string Name, string Content)[] BaseEntries(string extraDependencies = """<dependency id="Refit" version="16.3.0" />""") =>
    [
        (Id + ".nuspec", Nuspec(extraDependencies)),
        ("README.md", "# " + Id),
        ("THIRD-PARTY-NOTICES.md", "controlled")
    ];

    [Test]
    public async Task ValidMinimalSpdxManifestAndDependencyClosurePass()
    {
        var baseEntries = BaseEntries();
        string json = Encoding.UTF8.GetString(ArchiveTests.CreateSpdxJson(Id, Version, baseEntries, ("Refit", "16.3.0")));
        string digest = Manifest.Hash(Encoding.UTF8.GetBytes(json));
        byte[] zip = ArchiveTests.Zip([.. baseEntries, (SbomManifest.ManifestPath, json), (SbomManifest.DigestPath, digest)]);
        SbomManifest.Verify(PackageArchive.Read(zip), Id, Version);
        await Task.CompletedTask;
    }

    [Test]
    [Arguments("missing-manifest")]
    [Arguments("missing-digest")]
    [Arguments("bad-digest")]
    [Arguments("duplicate-json")]
    [Arguments("wrong-spdx-version")]
    [Arguments("wrong-namespace")]
    [Arguments("double-slash-namespace")]
    [Arguments("non-utc-created")]
    [Arguments("extra-archive-file")]
    [Arguments("extra-manifest-file")]
    [Arguments("extra-manifest-file-registered")]
    [Arguments("missing-file-in-sbom")]
    [Arguments("wrong-file-hash")]
    [Arguments("stale-self-version")]
    [Arguments("stale-sibling-dependency")]
    [Arguments("duplicate-dependency-name")]
    [Arguments("unanchored-purl")]
    [Arguments("build-tool-in-sbom-packages")]
    [Arguments("missing-external-dependency")]
    [Arguments("leaked-sbom-tool-dependency")]
    [Arguments("leaked-illink-dependency")]
    [Arguments("missing-describes-relationship")]
    public async Task TamperedOrIncompleteSpdxManifestsFailClosed(string fault)
    {
        (string Name, string Content)[] baseEntries = fault switch
        {
            "leaked-sbom-tool-dependency" => BaseEntries("""<dependency id="Microsoft.Sbom.Targets" version="4.1.13" />"""),
            "leaked-illink-dependency" => BaseEntries("""<dependency id="Microsoft.NET.ILLink.Tasks" version="10.0.15" />"""),
            "stale-sibling-dependency" =>
            [
                (Id + ".nuspec", $"""
                    <package><metadata><id>{Id}</id><version>{Version}</version>
                    <license type="expression">MIT</license>
                    <repository type="git" url="{Manifest.Repository}" commit="{TestBundle.Commit}"/>
                    <dependencies><group targetFramework="net10.0">
                    <dependency id="SecretKit.Core" version="0.1.0-stale.1" />
                    <dependency id="Refit" version="16.3.0" />
                    </group></dependencies>
                    </metadata></package>
                    """),
                ("README.md", "# " + Id),
                ("THIRD-PARTY-NOTICES.md", "controlled")
            ],
            _ => BaseEntries()
        };

        (string Name, string Version)[] declaredDeps = fault switch
        {
            "missing-external-dependency" => [],
            "duplicate-dependency-name" => [("Refit", "16.3.0"), ("Refit", "15.0.0")],
            "build-tool-in-sbom-packages" => [("Refit", "16.3.0"), ("Microsoft.Sbom.Targets", "4.1.13")],
            _ => [("Refit", "16.3.0")]
        };

        (string Name, string Content)[] sbomEntries = fault switch
        {
            "missing-file-in-sbom" => baseEntries.Where(e => e.Name != "README.md").ToArray(),
            "extra-manifest-file-registered" => [.. baseEntries, ("_manifest/spdx_2.2/extra.bin", "trojan")],
            _ => baseEntries
        };

        byte[] rawJson = ArchiveTests.CreateSpdxJson(Id, Version, sbomEntries, declaredDeps);
        JsonObject root = JsonNode.Parse(rawJson)!.AsObject();

        switch (fault)
        {
            case "wrong-spdx-version":
                root["spdxVersion"] = "SPDX-2.3";
                break;
            case "wrong-namespace":
                root["documentNamespace"] = "https://example.com/spdx/1";
                break;
            case "double-slash-namespace":
                root["documentNamespace"] = $"{SbomManifest.NamespacePrefix}/{Id}/{Version}/abc";
                break;
            case "non-utc-created":
                root["creationInfo"]!["created"] = "2026-01-01T00:00:00+02:00";
                break;
            case "wrong-file-hash":
                root["files"]![0]!["checksums"]![0]!["checksumValue"] = new string('0', 64);
                break;
            case "unanchored-purl":
                root["packages"]![0]!["externalRefs"]![0]!["referenceLocator"] = "pkg:nuget/Refit@16.3.0-tampered";
                break;
            case "stale-self-version":
                root["packages"]!.AsArray().Add(new JsonObject
                {
                    ["SPDXID"] = "SPDXRef-Package-Stale",
                    ["name"] = Id,
                    ["versionInfo"] = "0.1.0-local.1"
                });
                break;
            case "missing-describes-relationship":
                root["relationships"] = new JsonArray();
                break;
        }

        string jsonText = fault == "duplicate-json"
            ? """{"spdxVersion":"SPDX-2.2","spdxVersion":"SPDX-2.2"}"""
            : root.ToJsonString();
        string digest = fault == "bad-digest"
            ? new string('a', 64)
            : Manifest.Hash(Encoding.UTF8.GetBytes(jsonText));

        var entries = baseEntries.ToList();
        if (fault == "extra-archive-file")
        {
            entries.Add(("lib/net10.0/unlisted.dll", "trojan"));
        }
        else if (fault is "extra-manifest-file" or "extra-manifest-file-registered")
        {
            entries.Add(("_manifest/spdx_2.2/extra.bin", "trojan"));
        }

        if (fault != "missing-manifest")
        {
            entries.Add((SbomManifest.ManifestPath, jsonText));
        }

        if (fault != "missing-digest")
        {
            entries.Add((SbomManifest.DigestPath, digest));
        }

        ArchiveContent archive = PackageArchive.Read(ArchiveTests.Zip([.. entries]));
        await Assert.That(() => SbomManifest.Verify(archive, Id, Version)).Throws<ReleaseException>();
    }
}
