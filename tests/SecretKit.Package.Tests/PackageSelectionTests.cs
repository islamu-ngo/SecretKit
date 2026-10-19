using System.IO.Compression;
using System.Text.Json;
using System.Xml.Linq;
using SecretKit.TestFixtures;

namespace SecretKit.Package.Tests;

public sealed class PackageSelectionTests
{
    [Test]
    public async Task ExplicitNonDefaultCandidateIgnoresStaleDefaultDirectory()
    {
        using var fixture = new CandidateFixture();
        fixture.Family(fixture.DefaultDirectory, "0.1.0-preview.1");
        fixture.Family(fixture.SelectedDirectory, "0.1.0-preview.2");
        var candidate = PackageCandidate.Select(fixture.Root, "0.1.0-preview.2", fixture.SelectedDirectory);
        await Assert.That(candidate.Version).IsEqualTo("0.1.0-preview.2");
        await Assert.That(candidate.Directory).IsEqualTo(fixture.SelectedDirectory);
    }

    [Test]
    public async Task AbsentVersionDerivesOnlyCompleteSelectedFamily()
    {
        using var fixture = new CandidateFixture();
        fixture.Family(fixture.SelectedDirectory, "0.1.0-preview.2");
        await Assert.That(PackageCandidate.Select(fixture.Root, directory: fixture.SelectedDirectory).Version)
            .IsEqualTo("0.1.0-preview.2");
    }

    [Test]
    [Arguments("missing")]
    [Arguments("mixed")]
    [Arguments("ambiguous")]
    [Arguments("mismatch")]
    [Arguments("duplicate")]
    public async Task InvalidFamilyFailsClosed(string defect)
    {
        using var fixture = new CandidateFixture();
        fixture.Family(fixture.SelectedDirectory, "0.1.0-preview.2");
        string core = Path.Combine(fixture.SelectedDirectory, "SecretKit.Core.0.1.0-preview.2.nupkg");
        if (defect == "missing") File.Delete(core);
        if (defect == "mixed")
        {
            File.Delete(core);
            fixture.Archive(fixture.SelectedDirectory, "SecretKit.Core", "0.1.0-preview.1");
        }
        if (defect == "ambiguous") fixture.Family(fixture.SelectedDirectory, "0.1.0-preview.3");
        if (defect == "mismatch") fixture.Archive(fixture.SelectedDirectory, "SecretKit.Core", "0.1.0-preview.2",
            metadataVersion: "0.1.0-preview.3");
        if (defect == "duplicate") File.Copy(core, Path.Combine(fixture.SelectedDirectory, "duplicate.nupkg"));
        await Assert.That(() => PackageCandidate.Select(fixture.Root, directory: fixture.SelectedDirectory))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("latest")]
    [Arguments("0.1.0-preview.2;Injected=true")]
    [Arguments("01.1.0")]
    [Arguments("")]
    public async Task InvalidVersionFailsClosed(string version)
    {
        using var fixture = new CandidateFixture();
        fixture.Family(fixture.SelectedDirectory, "0.1.0-preview.2");
        await Assert.That(() => PackageCandidate.Select(fixture.Root, version, fixture.SelectedDirectory))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task MissingDirectoryFailsWithoutDefaultFallback()
    {
        using var fixture = new CandidateFixture();
        fixture.Family(fixture.DefaultDirectory, "0.1.0-preview.1");
        await Assert.That(() => PackageCandidate.Select(fixture.Root, directory: Path.Combine(fixture.Root, "absent")))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("")]
    [Arguments("candidate;Injected=true")]
    [Arguments("candidate\n")]
    public async Task InvalidDirectoryInputFailsClosed(string directory)
    {
        using var fixture = new CandidateFixture();
        fixture.Family(fixture.DefaultDirectory, "0.1.0-preview.1");
        await Assert.That(() => PackageCandidate.Select(fixture.Root, directory: directory))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task OversizedInputsFailClosed()
    {
        using var fixture = new CandidateFixture();
        fixture.Family(fixture.SelectedDirectory, "0.1.0-preview.2");
        await Assert.That(() => PackageCandidate.Select(fixture.Root, new string('1', 101), fixture.SelectedDirectory))
            .Throws<InvalidOperationException>();
        await Assert.That(() => PackageCandidate.Select(fixture.Root, directory: new string('a', 4097)))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ConsumerArgumentsBindVersionSourceAndFreshIsolatedPaths()
    {
        using var fixture = new CandidateFixture();
        fixture.Family(fixture.SelectedDirectory, "0.1.0-preview.2");
        var candidate = PackageCandidate.Select(fixture.Root, "0.1.0-preview.2", fixture.SelectedDirectory);
        string first = Path.Combine(fixture.Root, "first-consumer");
        string second = Path.Combine(fixture.Root, "second-consumer");
        var installations = new[] { candidate.PrepareConsumer(first), candidate.PrepareConsumer(second) };
        foreach (var installation in installations)
        {
            await Assert.That(installation.Properties.Contains("-p:SecretKitCandidateVersion=0.1.0-preview.2")).IsTrue();
            await Assert.That(installation.Properties.Contains($"-p:RestorePackagesPath={installation.Packages}")).IsTrue();
            await Assert.That(installation.Properties.Contains($"-p:BaseIntermediateOutputPath={installation.Intermediate}")).IsTrue();
            await Assert.That(installation.Properties.Contains($"-p:MSBuildProjectExtensionsPath={installation.Intermediate}")).IsTrue();
            await Assert.That(installation.Properties.Contains($"-p:BaseOutputPath={installation.Binary}")).IsTrue();
            await Assert.That(Directory.EnumerateFileSystemEntries(installation.Packages).Any()).IsFalse();
            XElement configuration = XDocument.Load(installation.Configuration).Root!;
            await Assert.That(configuration.Element("packageSources")!.Elements("add")
                .Single(source => (string?)source.Attribute("key") == "candidate").Attribute("value")!.Value)
                .IsEqualTo(fixture.SelectedDirectory);
            await Assert.That(configuration.Element("packageSourceMapping")!.Elements("packageSource")
                .Single(source => (string?)source.Attribute("key") == "candidate").Element("package")!.Attribute("pattern")!.Value)
                .IsEqualTo("SecretKit.*");
            await Assert.That(configuration.Element("packageSources")!.Elements("add")
                .Single(source => (string?)source.Attribute("key") == "nuget.org").Attribute("value")!.Value)
                .IsEqualTo("https://api.nuget.org/v3/index.json");
        }
        await Assert.That(installations[0].Packages == installations[1].Packages).IsFalse();
        await Assert.That(() => candidate.PrepareConsumer(first)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalRestoredArchiveBytesMustMatchSelectedFamily(bool substituted)
    {
        using var fixture = new CandidateFixture();
        fixture.Family(fixture.SelectedDirectory, "0.1.0-preview.2");
        var candidate = PackageCandidate.Select(fixture.Root, "0.1.0-preview.2", fixture.SelectedDirectory);
        string cache = Path.Combine(fixture.Root, "stale-cache");
        var libraries = new Dictionary<string, object>();
        foreach (string id in PackageCandidate.PackageIds)
        {
            string relative = $"{id.ToLowerInvariant()}/0.1.0-preview.2";
            string destination = Path.Combine(cache, relative);
            Directory.CreateDirectory(destination);
            File.Copy(Path.Combine(fixture.SelectedDirectory, $"{id}.0.1.0-preview.2.nupkg"),
                Path.Combine(destination, $"{id.ToLowerInvariant()}.0.1.0-preview.2.nupkg"));
            libraries.Add($"{id}/0.1.0-preview.2", new { type = "package", path = relative });
        }
        string assets = Path.Combine(fixture.Root, "project.assets.json");
        File.WriteAllText(assets, JsonSerializer.Serialize(new
        {
            libraries,
            packageFolders = new Dictionary<string, object> { [cache] = new { } }
        }));
        if (substituted)
        {
            fixture.Archive(fixture.Root, "SecretKit.Core", "0.1.0-preview.2", marker: "stale-different-bytes");
            File.Copy(Path.Combine(fixture.Root, "SecretKit.Core.0.1.0-preview.2.nupkg"),
                Path.Combine(cache, "secretkit.core", "0.1.0-preview.2", "secretkit.core.0.1.0-preview.2.nupkg"), true);
            await Assert.That(() => candidate.VerifyRestored(assets, cache)).Throws<InvalidOperationException>();
        }
        else candidate.VerifyRestored(assets, cache);
    }

    [Test]
    [Arguments("missing")]
    [Arguments("version")]
    [Arguments("path")]
    [Arguments("project")]
    [Arguments("cache")]
    [Arguments("archive")]
    public async Task IncompleteOrSubstitutedAssetsFailClosed(string defect)
    {
        using var fixture = new CandidateFixture();
        fixture.Family(fixture.SelectedDirectory, "0.1.0-preview.2");
        var candidate = PackageCandidate.Select(fixture.Root, "0.1.0-preview.2", fixture.SelectedDirectory);
        string cache = Path.Combine(fixture.Root, "cache");
        var libraries = new Dictionary<string, object>();
        foreach (string id in PackageCandidate.PackageIds)
        {
            string relative = $"{id.ToLowerInvariant()}/0.1.0-preview.2";
            string destination = Path.Combine(cache, relative);
            Directory.CreateDirectory(destination);
            string original = Path.Combine(destination, $"{id.ToLowerInvariant()}.0.1.0-preview.2.nupkg");
            File.Copy(candidate.ArchivePath(id), original);
            bool changed = id == "SecretKit.Core";
            if (changed && defect == "missing") continue;
            if (changed && defect == "archive") File.Delete(original);
            libraries.Add($"{id}/{(changed && defect == "version" ? "0.1.0-preview.1" : "0.1.0-preview.2")}",
                new
                {
                    type = changed && defect == "project" ? "project" : "package",
                    path = changed && defect == "path" ? "../foreign" : relative
                });
        }
        string assets = Path.Combine(fixture.Root, "project.assets.json");
        File.WriteAllText(assets, JsonSerializer.Serialize(new
        {
            libraries,
            packageFolders = new Dictionary<string, object>
            {
                [defect == "cache" ? fixture.SelectedDirectory : cache] = new { }
            }
        }));
        await Assert.That(() => candidate.VerifyRestored(assets, cache)).Throws<InvalidOperationException>();
    }

    private sealed class CandidateFixture : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "secretkit-selection-" + Guid.NewGuid().ToString("N"));
        internal string DefaultDirectory => Path.Combine(Root, "artifacts", "packages");
        internal string SelectedDirectory => Path.Combine(Root, "candidate");

        internal void Family(string directory, string version)
        {
            foreach (string id in PackageCandidate.PackageIds) Archive(directory, id, version);
        }

        internal void Archive(string directory, string id, string version, string? metadataVersion = null,
            string marker = "selected-original-bytes")
        {
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, $"{id}.{version}.nupkg");
            File.Delete(path);
            using ZipArchive archive = ZipFile.Open(path, ZipArchiveMode.Create);
            using (var writer = new StreamWriter(archive.CreateEntry($"{id}.nuspec").Open()))
                new XDocument(new XElement("package", new XElement("metadata",
                    new XElement("id", id), new XElement("version", metadataVersion ?? version)))).Save(writer);
            using var content = new StreamWriter(archive.CreateEntry("marker").Open());
            content.Write(marker);
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
