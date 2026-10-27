using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using SecretKit.TestFixtures;

namespace SecretKit.Package.Tests;

public sealed class LocalInfisicalInstallTests
{
    private const string Version = "0.1.0-local.20261024.1";

    [Test]
    [Arguments("minimal")]
    [Arguments("configuration")]
    [Arguments("hosting")]
    [Arguments("full")]
    public async Task RuntimeHardeningInstallsFreshSelectedOriginals(string mode)
    {
        // No historical archive/default-feed fallback for the new API profile.
        string selected = Environment.GetEnvironmentVariable("SECRETKIT_RUNTIME_HARDENING_ORIGINALS") ??
            throw new InvalidOperationException("runtime-hardening-originals-missing");
        string version = Environment.GetEnvironmentVariable("SECRETKIT_RUNTIME_HARDENING_VERSION") ??
            throw new InvalidOperationException("runtime-hardening-version-missing");
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        string output = Path.Combine(root, "artifacts", "runtime-hardening", Guid.NewGuid().ToString("N"));
        LocalPackageCandidate candidate = LocalPackageCandidate.Select(selected, version);
        var hashes = LocalPackageCandidate.PackageIds.ToDictionary(id => id,
            id => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(candidate.ArchivePath(id)))));
        foreach (string id in LocalPackageCandidate.PackageIds)
        {
            using ZipArchive archive = ZipFile.OpenRead(candidate.ArchivePath(id));
            await PackageInstallTests.VerifyXmlDocumentationAsync(archive, id);
        }
        ConsumerInstallation installation = candidate.PrepareConsumer(output, mode);
        string project = Path.Combine(root, "tests/fixtures/SecretKit.InfisicalConsumer/SecretKit.InfisicalConsumer.csproj");
        await Run(root, ["restore", project, "--configfile", installation.Configuration, .. installation.Properties]);
        string assets = Path.Combine(installation.Intermediate, "project.assets.json");
        candidate.VerifyRestored(assets, installation.Packages, mode);
        await Run(root, ["build", project, "--configuration", "Release", "--no-restore", .. installation.Properties]);
        string text = await Run(root,
            [Path.Combine(installation.Binary, "Release/net10.0/SecretKit.InfisicalConsumer.dll"),
                "runtime-hardening", "offline"]);
        string[] lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        using JsonDocument report = JsonDocument.Parse(lines[^1]);
        await Assert.That(report.RootElement.GetProperty("record").GetString()).IsEqualTo("REPORT");
        await Assert.That(report.RootElement.GetProperty("profile").GetString()).IsEqualTo("runtime-hardening");
        await Assert.That(report.RootElement.GetProperty("packageProfile").GetString()).IsEqualTo("infisical-runtime");
        await Assert.That(report.RootElement.GetProperty("kind").GetString()).IsEqualTo("controlled-installed-offline");
        await Assert.That(report.RootElement.GetProperty("mode").GetString()).IsEqualTo(mode);
        await Assert.That(report.RootElement.GetProperty("nativeQualified").GetBoolean()).IsFalse();
        var observations = lines[..^1].Select(line => JsonSerializer.Deserialize<JsonElement>(line)).ToArray();
        string[] expected = ["RH01", "RH04", "RH05", "RH06", "RH07", "RH08"];
        if (mode is "configuration" or "full") expected = [.. expected, "RH02", "RH03"];
        if (mode is "hosting" or "full") expected = [.. expected, "RH09"];
        await Assert.That(observations.Length).IsEqualTo(expected.Length * 2);
        foreach (string transport in new[] { "SafeDefault", "HostControlled" })
        {
            var cases = observations.Where(c => c.GetProperty("transport").GetString() == transport).ToArray();
            await Assert.That(cases.Select(c => c.GetProperty("id").GetString()).Order(StringComparer.Ordinal)
                .SequenceEqual(expected.Order(StringComparer.Ordinal))).IsTrue();
        }
        await Assert.That(observations.All(c => c.GetProperty("record").GetString() == "SCENARIO" &&
            c.GetProperty("profile").GetString() == "runtime-hardening" &&
            c.GetProperty("mode").GetString() == mode && c.GetProperty("status").GetString() == "passed" &&
            c.GetProperty("reason").GetString() == "controlled-observed" &&
            !c.GetProperty("nativeQualified").GetBoolean())).IsTrue();
        candidate.VerifyRestored(assets, installation.Packages, mode);
        foreach (string id in LocalPackageCandidate.PackageIds)
            await Assert.That(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(candidate.ArchivePath(id)))))
                .IsEqualTo(hashes[id]);
        await File.WriteAllTextAsync(Path.Combine(output, "runtime-hardening.json"), JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            profile = "runtime-hardening",
            packageProfile = "infisical-runtime",
            kind = "controlled-installed-offline",
            nativeQualified = false,
            mode,
            version,
            originals = hashes,
            installedPackageIds = LocalPackageCandidate.Expected(mode),
            scenarios = observations,
            report = report.RootElement.Clone()
        }));
    }

    [Test]
    [Arguments("minimal")]
    [Arguments("configuration")]
    [Arguments("hosting")]
    [Arguments("full")]
    public async Task OriginalLocalProfileInstallsAndRunsIndependentModes(string mode)
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        string outputs = Path.Combine(root, "artifacts", "local-package-consumers", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outputs);
        string? selected = Environment.GetEnvironmentVariable("SECRETKIT_LOCAL_CANDIDATE_DIRECTORY");
        string version = Environment.GetEnvironmentVariable("SECRETKIT_LOCAL_CANDIDATE_VERSION") ??
            Environment.GetEnvironmentVariable("SECRETKIT_CANDIDATE_VERSION") ?? "0.1.0-preview.1";
        LocalPackageCandidate candidate = selected is null
            ? LocalPackageCandidate.CopyFromFamily(root, version,
                Environment.GetEnvironmentVariable("SECRETKIT_CANDIDATE_DIRECTORY") ??
                    Path.Combine(root, "artifacts", "packages"), Path.Combine(outputs, "originals"))
            : LocalPackageCandidate.Select(selected, version);
        foreach (string package in LocalPackageCandidate.PackageIds)
        {
            using ZipArchive archive = ZipFile.OpenRead(candidate.ArchivePath(package));
            await PackageInstallTests.VerifyXmlDocumentationAsync(archive, package);
        }
        string? qualificationDirectory = Environment.GetEnvironmentVariable("SECRETKIT_LOCAL_QUALIFICATION_DIRECTORY");
        JsonElement? qualificationBinding = null;
        string release = Path.Combine(root, "tools", "SecretKit.Release", "bin", "Release", "net10.0", "SecretKit.Release.dll");
        if (qualificationDirectory is not null)
        {
            await Run(root, [release, "local-check", root, candidate.Directory, qualificationDirectory]);
            byte[] bytes = await File.ReadAllBytesAsync(Path.Combine(qualificationDirectory, "local-qualification.json"));
            using JsonDocument qualification = JsonDocument.Parse(bytes);
            JsonElement prepared = qualification.RootElement;
            await Assert.That(prepared.GetProperty("status").GetString()).IsEqualTo("prepared-not-native-qualified");
            await Assert.That(prepared.GetProperty("version").GetString()).IsEqualTo(version);
            foreach (JsonElement package in prepared.GetProperty("packages").EnumerateArray())
                await Assert.That(package.GetProperty("sha256").GetString()).IsEqualTo(Convert.ToHexStringLower(
                    SHA256.HashData(await File.ReadAllBytesAsync(candidate.ArchivePath(package.GetProperty("id").GetString()!)))));
            qualificationBinding = JsonSerializer.SerializeToElement(new
            {
                recordSha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)),
                profile = prepared.GetProperty("profile").Clone(),
                source = new
                {
                    kind = prepared.GetProperty("source").GetProperty("kind").GetString(),
                    sha256 = prepared.GetProperty("source").GetProperty("sha256").GetString()
                }
            });
        }
        ConsumerInstallation installation = candidate.PrepareConsumer(Path.Combine(outputs, "consumer"), mode);
        string project = Path.Combine(root, "tests", "fixtures", "SecretKit.InfisicalConsumer",
            "SecretKit.InfisicalConsumer.csproj");
        await Run(root, ["restore", project, "--configfile", installation.Configuration, .. installation.Properties]);
        candidate.VerifyRestored(Path.Combine(installation.Intermediate, "project.assets.json"), installation.Packages, mode);
        await Run(root, ["build", project, "--configuration", "Release", "--no-restore", .. installation.Properties]);
        string output = await Run(root,
            [Path.Combine(installation.Binary, "Release", "net10.0", "SecretKit.InfisicalConsumer.dll"), "offline"]);
        using JsonDocument report = JsonDocument.Parse(output);
        await Assert.That(report.RootElement.GetProperty("kind").GetString()).IsEqualTo("local-installed-offline");
        await Assert.That(report.RootElement.GetProperty("mode").GetString()).IsEqualTo(mode);
        await Assert.That(report.RootElement.GetProperty("nativeQualified").GetBoolean()).IsFalse();
        JsonElement[] scenarios = report.RootElement.GetProperty("scenarios").EnumerateArray().ToArray();
        string[] expected = mode is "configuration" or "full"
            ? ["S03", "S04", "S05", "S06", "S07", "S08", "S09", "S10", "S11", "S12", "S13", "S16"]
            : ["S03", "S04", "S05", "S06", "S07", "S08", "S09", "S10", "S12", "S13", "S16"];
        await Assert.That(scenarios.Select(s => s.GetProperty("id").GetString()).Order().SequenceEqual(expected)).IsTrue();
        await Assert.That(scenarios.All(s => s.GetProperty("status").GetString() == "passed")).IsTrue();
        await Assert.That(scenarios.All(s => !string.IsNullOrWhiteSpace(s.GetProperty("subset").GetString()))).IsTrue();
        await Assert.That(report.RootElement.GetProperty("unqualifiedScenarios").EnumerateArray()
            .Select(s => s.GetString()).SequenceEqual(new[] { "S15" })).IsTrue();
        await Assert.That(report.RootElement.GetProperty("requests").GetInt32() > 0).IsTrue();
        candidate.VerifyRestored(Path.Combine(installation.Intermediate, "project.assets.json"), installation.Packages, mode);
        if (qualificationDirectory is not null)
            await Run(root, [release, "local-check", root, candidate.Directory, qualificationDirectory]);
        var record = new
        {
            schemaVersion = 1,
            kind = "local-installation",
            nativeQualified = false,
            version,
            mode,
            qualificationBinding,
            installedPackageIds = LocalPackageCandidate.Expected(mode),
            originals = LocalPackageCandidate.PackageIds.Select(id => new
            {
                id,
                sha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(candidate.ArchivePath(id))))
            }).ToArray(),
            installation = report.RootElement.Clone(),
            boundaryScenarios = new[]
            {
                new { id = "S01", subset = "four-original-archives-and-hashes", status = "passed" },
                new { id = "S02", subset = "isolated-source-mapped-restore-and-runtime", status = "passed" },
                new { id = "S14", subset = "independent-mode-library-and-framework-closure", status = "passed" }
            }
        };
        string evidence = Path.Combine(outputs, "installation.json");
        await File.WriteAllTextAsync(evidence, JsonSerializer.Serialize(record));
        if (Environment.GetEnvironmentVariable("SECRETKIT_LOCAL_INSTALL_REPORTS") is { } reports)
        {
            Directory.CreateDirectory(reports);
            File.Copy(evidence, Path.Combine(reports, mode + ".json"), overwrite: false);
        }
    }

    [Test]
    [Arguments("missing")]
    [Arguments("mixed")]
    [Arguments("extra")]
    [Arguments("duplicate")]
    [Arguments("missing-closure")]
    [Arguments("foreign-dependency")]
    public async Task InvalidLocalArchiveFamiliesAreRejected(string defect)
    {
        using var fixture = new Fixture();
        fixture.Family();
        string core = fixture.ArchivePath("SecretKit.Core");
        switch (defect)
        {
            case "missing": File.Delete(core); break;
            case "mixed":
                fixture.Archive("SecretKit.Core", version: "0.1.0-local.20261023.2");
                File.Delete(core);
                break;
            case "extra": fixture.Archive("SecretKit.AzureKeyVault"); break;
            case "duplicate": File.Copy(core, Path.Combine(fixture.Originals, "duplicate.nupkg")); break;
            case "missing-closure": fixture.Archive("SecretKit.Infisical", dependency: ""); break;
            case "foreign-dependency": fixture.Archive("SecretKit.Infisical", dependency: "Azure.Core"); break;
        }
        await Assert.That(() => LocalPackageCandidate.Select(fixture.Originals, Version))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("mutated-original")]
    [Arguments("mutated-cache")]
    [Arguments("mixed-version")]
    [Arguments("missing-library")]
    [Arguments("default-cache")]
    [Arguments("polluted-cache")]
    [Arguments("wrong-source")]
    [Arguments("project-reference")]
    [Arguments("aspnet")]
    [Arguments("azure")]
    [Arguments("management")]
    [Arguments("database")]
    [Arguments("event")]
    public async Task RestoredGraphAndOriginalBytesCannotBeSubstituted(string defect)
    {
        using var fixture = new Fixture();
        fixture.Family();
        LocalPackageCandidate candidate = LocalPackageCandidate.Select(fixture.Originals, Version);
        (string assets, string cache) = fixture.Restore();
        JsonObject graph = JsonNode.Parse(File.ReadAllText(assets))!.AsObject();
        JsonObject libraries = graph["libraries"]!.AsObject();
        string core = "SecretKit.Core/" + Version;
        switch (defect)
        {
            case "mutated-original": fixture.Archive("SecretKit.Core", marker: "mutated"); break;
            case "mutated-cache":
                File.AppendAllText(Path.Combine(cache, "secretkit.core", Version, $"secretkit.core.{Version}.nupkg"), "mutation");
                break;
            case "mixed-version":
                libraries["SecretKit.Core/0.1.0-local.20261023.2"] = libraries[core]!.DeepClone();
                libraries.Remove(core);
                break;
            case "missing-library": libraries.Remove(core); break;
            case "default-cache": graph["packageFolders"] = new JsonObject { [fixture.Originals] = new JsonObject() }; break;
            case "polluted-cache": graph["packageFolders"]![fixture.Originals] = new JsonObject(); break;
            case "wrong-source":
                File.WriteAllText(Path.Combine(cache, "secretkit.core", Version, ".nupkg.metadata"),
                    JsonSerializer.Serialize(new { source = fixture.Root }));
                break;
            case "project-reference": libraries[core]!["type"] = "project"; break;
            case "aspnet":
                graph["project"]!["frameworks"]!["net10.0"]!["frameworkReferences"]!["Microsoft.AspNetCore.App"] = new JsonObject();
                break;
            default:
                string name = defect switch
                {
                    "azure" => "Azure.Core/1.0.0",
                    "management" => "SecretKit.Infisical.Management/" + Version,
                    "database" => "Microsoft.Data.SqlClient/6.0.0",
                    "event" => "Event.Core/1.0.0",
                    _ => throw new InvalidOperationException()
                };
                libraries[name] = new JsonObject { ["type"] = "package" };
                break;
        }
        File.WriteAllText(assets, graph.ToJsonString());
        await Assert.That(() => candidate.VerifyRestored(assets, cache, "full")).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task BundleConfigurationSurvivesRelocation()
    {
        using var fixture = new Fixture();
        fixture.Family();
        LocalPackageCandidate candidate = LocalPackageCandidate.Select(fixture.Originals, Version);
        string source = Path.Combine(fixture.Root, "source");
        candidate.CreateBundle(source);
        string moved = Path.Combine(fixture.Root, "moved");
        Directory.Move(source, moved);
        Directory.Move(fixture.Originals, fixture.Originals + "-unavailable");
        XElement config = XDocument.Load(Path.Combine(moved, "NuGet.Config")).Root!;
        await Assert.That(config.Element("packageSources")!.Elements("add")
            .Single(e => (string?)e.Attribute("key") == "local").Attribute("value")!.Value).IsEqualTo("feed/");
        LocalPackageCandidate relocated = LocalPackageCandidate.SelectBundle(moved, Version);
        ConsumerInstallation installation = relocated.PrepareBundledConsumer(Path.Combine(fixture.Root, "consumer"), "minimal");
        await Assert.That(installation.Configuration).IsEqualTo(Path.Combine(moved, "NuGet.Config"));
        await Assert.That(Directory.EnumerateFileSystemEntries(installation.Packages).Any()).IsFalse();
        await Assert.That(Directory.GetFiles(relocated.Directory).Length).IsEqualTo(4);
        string[] hashes = File.ReadAllLines(Path.Combine(moved, "packages.sha256"));
        await Assert.That(hashes.Length).IsEqualTo(4);
        foreach (string id in new[] { "SecretKit.Core", "SecretKit.Infisical",
            "SecretKit.Extensions.Configuration", "SecretKit.Extensions.Hosting" })
            await Assert.That(hashes.Contains(
                $"{Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(relocated.ArchivePath(id))))}  feed/{id}.{Version}.nupkg"))
                .IsTrue();
    }

    [Test]
    [Arguments("missing")]
    [Arguments("changed")]
    [Arguments("absolute-source")]
    [Arguments("public-fallback")]
    [Arguments("absent-feed")]
    [Arguments("stale-version")]
    [Arguments("hash-record")]
    public async Task DamagedBundlesCannotBeSelected(string defect)
    {
        using var fixture = new Fixture();
        fixture.Family();
        string bundle = Path.Combine(fixture.Root, "bundle");
        LocalPackageCandidate.Select(fixture.Originals, Version).CreateBundle(bundle);
        string core = Path.Combine(bundle, "feed", $"SecretKit.Core.{Version}.nupkg");
        string config = Path.Combine(bundle, "NuGet.Config");
        switch (defect)
        {
            case "missing": File.Delete(core); break;
            case "changed": File.AppendAllText(core, "changed"); break;
            case "absolute-source":
            case "public-fallback":
                XDocument document = XDocument.Load(config);
                if (defect == "absolute-source")
                    document.Root!.Element("packageSources")!.Elements("add").First().SetAttributeValue("value", fixture.Originals);
                else
                    document.Root!.Element("packageSourceMapping")!.Elements("packageSource").First().Remove();
                document.Save(config);
                break;
            case "absent-feed": Directory.Move(Path.Combine(bundle, "feed"), Path.Combine(bundle, "absent")); break;
            case "hash-record": File.WriteAllText(Path.Combine(bundle, "packages.sha256"), "substituted"); break;
        }
        await Assert.That(() => LocalPackageCandidate.SelectBundle(bundle,
            defect == "stale-version" ? "0.1.0-local.20261023.2" : Version)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("missing-original")]
    [Arguments("changed-original")]
    [Arguments("existing-directory")]
    [Arguments("existing-file")]
    [Arguments("relative-output")]
    [Arguments("invalid-output")]
    public async Task BundleCreationRejectsSubstitutionAndUnsafeOutputs(string defect)
    {
        using var fixture = new Fixture();
        fixture.Family();
        LocalPackageCandidate candidate = LocalPackageCandidate.Select(fixture.Originals, Version);
        string output = Path.Combine(fixture.Root, "bundle");
        switch (defect)
        {
            case "missing-original": File.Delete(fixture.ArchivePath("SecretKit.Core")); break;
            case "changed-original": File.AppendAllText(fixture.ArchivePath("SecretKit.Core"), "changed"); break;
            case "existing-directory": Directory.CreateDirectory(output); break;
            case "existing-file": File.WriteAllText(output, "preserve"); break;
            case "relative-output": output = "relative-bundle"; break;
            case "invalid-output": output += ";invalid"; break;
        }
        await Assert.That(() => candidate.CreateBundle(output)).Throws<InvalidOperationException>();
        if (defect == "existing-file") await Assert.That(File.ReadAllText(output)).IsEqualTo("preserve");
    }

    [Test]
    public async Task FreshPathsAndSourceMappingBindTheSelectedOriginals()
    {
        using var fixture = new Fixture();
        fixture.Family();
        LocalPackageCandidate candidate = LocalPackageCandidate.Select(fixture.Originals, Version);
        string output = Path.Combine(fixture.Root, "consumer");
        ConsumerInstallation first = candidate.PrepareConsumer(output, "minimal");
        ConsumerInstallation second = candidate.PrepareConsumer(Path.Combine(fixture.Root, "other"), "hosting");
        await Assert.That(Directory.EnumerateFileSystemEntries(first.Packages).Any()).IsFalse();
        await Assert.That(first.Packages != second.Packages).IsTrue();
        await Assert.That(() => candidate.PrepareConsumer(output, "minimal")).Throws<InvalidOperationException>();
        XElement config = XDocument.Load(first.Configuration).Root!;
        await Assert.That(config.Element("packageSources")!.Elements("add")
            .Single(e => (string?)e.Attribute("key") == "local").Attribute("value")!.Value).IsEqualTo(fixture.Originals);
        await Assert.That(config.Element("packageSourceMapping")!.Elements("packageSource")
            .Single(e => (string?)e.Attribute("key") == "local").Element("package")!.Attribute("pattern")!.Value)
            .IsEqualTo("SecretKit.*");
        (string assets, string cache) = fixture.Restore();
        candidate.VerifyRestored(assets, cache, "full");
    }

    [Test]
    public async Task FourPackSelectionPreservesSevenPackOriginalHashes()
    {
        using var fixture = new Fixture();
        fixture.Family();
        foreach (string id in PackageCandidate.PackageIds.Except(LocalPackageCandidate.PackageIds))
            fixture.Archive(id);
        Dictionary<string, string> before = PackageCandidate.PackageIds.ToDictionary(id => id,
            id => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(fixture.ArchivePath(id)))));
        LocalPackageCandidate selected = LocalPackageCandidate.CopyFromFamily(fixture.Root, Version,
            fixture.Originals, Path.Combine(fixture.Root, "four"));
        await Assert.That(Directory.GetFiles(selected.Directory, "*.nupkg").Length).IsEqualTo(4);
        foreach (string id in PackageCandidate.PackageIds)
        {
            await Assert.That(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(fixture.ArchivePath(id)))))
                .IsEqualTo(before[id]);
            if (LocalPackageCandidate.PackageIds.Contains(id))
                await Assert.That(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(selected.ArchivePath(id)))))
                    .IsEqualTo(before[id]);
        }
    }

    internal static async Task<string> Run(string root, string[] arguments, int expectedExit = 0)
    {
        using var process = new Process
        {
            StartInfo = new("dotnet")
            {
                WorkingDirectory = root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            },
            EnableRaisingEvents = true
        };
        foreach (string argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        // Package paths are explicitly bound by properties; inherited defaults cannot supply a fallback.
        process.StartInfo.Environment.Remove("NUGET_PACKAGES");
        process.StartInfo.Environment.Remove("NUGET_FALLBACK_PACKAGES");
        var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        process.Exited += (_, _) => exited.TrySetResult();
        process.Start();
        Task<string> stdout = process.StandardOutput.ReadToEndAsync();
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        try { await exited.Task.WaitAsync(TimeSpan.FromMinutes(3)); }
        catch (TimeoutException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            throw;
        }
        string output = await stdout;
        _ = await stderr;
        await Assert.That(process.ExitCode).IsEqualTo(expectedExit).Because("Installed workflow failed; protected diagnostics withheld.");
        return output;
    }

    private sealed class Fixture : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "secretkit-local-" + Guid.NewGuid().ToString("N"));
        internal string Originals => Path.Combine(Root, "originals");
        internal string ArchivePath(string id, string version = Version) => Path.Combine(Originals, $"{id}.{version}.nupkg");
        internal void Family()
        {
            foreach (string id in LocalPackageCandidate.PackageIds) Archive(id);
        }
        internal void Archive(string id, string version = Version, string? dependency = null, string marker = "original")
        {
            Directory.CreateDirectory(Originals);
            string path = ArchivePath(id, version);
            File.Delete(path);
            using ZipArchive archive = ZipFile.Open(path, ZipArchiveMode.Create);
            using (var writer = new StreamWriter(archive.CreateEntry(id + ".nuspec").Open()))
            {
                string? required = dependency ?? (id switch
                {
                    "SecretKit.Core" => null,
                    "SecretKit.Extensions.Hosting" => "SecretKit.Infisical",
                    _ => "SecretKit.Core"
                });
                new XDocument(new XElement("package", new XElement("metadata",
                    new XElement("id", id), new XElement("version", version),
                    new XElement("dependencies", string.IsNullOrEmpty(required) ? null :
                        new XElement("dependency", new XAttribute("id", required),
                            new XAttribute("version", version)))))).Save(writer);
            }
            using var content = new StreamWriter(archive.CreateEntry("marker").Open());
            content.Write(marker);
        }
        internal (string Assets, string Cache) Restore()
        {
            string cache = Path.Combine(Root, "cache");
            var libraries = new Dictionary<string, object>();
            foreach (string id in LocalPackageCandidate.PackageIds)
            {
                string relative = $"{id.ToLowerInvariant()}/{Version}";
                string destination = Path.Combine(cache, relative);
                Directory.CreateDirectory(destination);
                File.Copy(ArchivePath(id), Path.Combine(destination, $"{id.ToLowerInvariant()}.{Version}.nupkg"));
                File.WriteAllText(Path.Combine(destination, ".nupkg.metadata"), JsonSerializer.Serialize(new { source = Originals }));
                libraries.Add(id + "/" + Version, new { type = "package", path = relative });
            }
            string assets = Path.Combine(Root, "project.assets.json");
            File.WriteAllText(assets, JsonSerializer.Serialize(new
            {
                libraries,
                packageFolders = new Dictionary<string, object> { [cache] = new { } },
                project = new
                {
                    frameworks = new Dictionary<string, object>
                    {
                        ["net10.0"] = new
                        {
                            frameworkReferences = new Dictionary<string, object>
                            {
                                ["Microsoft.NETCore.App"] = new { }
                            }
                        }
                    }
                }
            }));
            return (assets, cache);
        }
        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}

public sealed class LocalInfisicalBundleTests
{
    [Test]
    public async Task RetainedBundleInstallsAllModesAfterRelocation()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        string scratch = Path.Combine(Path.GetTempPath(), "secretkit-bundle-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(scratch);
        try
        {
            string version = Environment.GetEnvironmentVariable("SECRETKIT_LOCAL_CANDIDATE_VERSION") ??
                Environment.GetEnvironmentVariable("SECRETKIT_CANDIDATE_VERSION") ?? "0.1.0-preview.1";
            string originals = Path.Combine(scratch, "originals");
            LocalPackageCandidate candidate;
            if (Environment.GetEnvironmentVariable("SECRETKIT_LOCAL_CANDIDATE_DIRECTORY") is { } selected)
            {
                LocalPackageCandidate input = LocalPackageCandidate.Select(selected, version);
                Directory.CreateDirectory(originals);
                foreach (string id in LocalPackageCandidate.PackageIds)
                    File.Copy(input.ArchivePath(id), Path.Combine(originals, Path.GetFileName(input.ArchivePath(id))));
                candidate = LocalPackageCandidate.Select(originals, version);
            }
            else
                candidate = LocalPackageCandidate.CopyFromFamily(root, version,
                    Environment.GetEnvironmentVariable("SECRETKIT_CANDIDATE_DIRECTORY") ??
                        Path.Combine(root, "artifacts", "packages"), originals);
            string[] ids = ["SecretKit.Core", "SecretKit.Infisical",
                "SecretKit.Extensions.Configuration", "SecretKit.Extensions.Hosting"];
            Dictionary<string, string> expectedHashes = ids.ToDictionary(id => id,
                id => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(candidate.ArchivePath(id)))));
            string retained = Environment.GetEnvironmentVariable("SECRETKIT_LOCAL_HANDOFF_DIRECTORY") ??
                Path.Combine(scratch, "handoff");
            candidate.CreateBundle(retained);
            string source = Path.Combine(scratch, "source-bundle");
            foreach (string file in Directory.GetFiles(retained, "*", SearchOption.AllDirectories))
            {
                string destination = Path.Combine(source, Path.GetRelativePath(retained, file));
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Copy(file, destination);
            }
            string moved = Path.Combine(scratch, "relocated-checkout", "vendor", "secretkit");
            Directory.CreateDirectory(Path.GetDirectoryName(moved)!);
            Directory.Move(source, moved);
            Directory.Move(originals, originals + "-unavailable");
            await Assert.That(Directory.Exists(source) || Directory.Exists(originals)).IsFalse();
            LocalPackageCandidate relocated = LocalPackageCandidate.SelectBundle(moved, version);
            var caches = new HashSet<string>(StringComparer.Ordinal);
            string project = Path.Combine(root, "tests", "fixtures", "SecretKit.InfisicalConsumer", "SecretKit.InfisicalConsumer.csproj");
            foreach (string mode in new[] { "minimal", "configuration", "hosting", "full" })
            {
                ConsumerInstallation installation = relocated.PrepareBundledConsumer(Path.Combine(scratch, mode), mode);
                await Assert.That(installation.Configuration).IsEqualTo(Path.Combine(moved, "NuGet.Config"));
                await Assert.That(caches.Add(installation.Packages)).IsTrue();
                await Assert.That(Directory.EnumerateFileSystemEntries(installation.Packages).Any()).IsFalse();
                await LocalInfisicalInstallTests.Run(root, ["restore", project, "--configfile", installation.Configuration, .. installation.Properties]);
                string assets = Path.Combine(installation.Intermediate, "project.assets.json");
                relocated.VerifyRestored(assets, installation.Packages, mode);
                using (JsonDocument graph = JsonDocument.Parse(File.ReadAllText(assets)))
                {
                    string[] expectedIds = mode switch
                    {
                        "minimal" => ["SecretKit.Core", "SecretKit.Infisical"],
                        "configuration" => ["SecretKit.Core", "SecretKit.Infisical", "SecretKit.Extensions.Configuration"],
                        "hosting" => ["SecretKit.Core", "SecretKit.Infisical", "SecretKit.Extensions.Hosting"],
                        _ => ids
                    };
                    await Assert.That(graph.RootElement.GetProperty("libraries").EnumerateObject()
                        .Where(p => p.Name.StartsWith("SecretKit.", StringComparison.Ordinal)).Select(p => p.Name).Order()
                        .SequenceEqual(expectedIds.Select(id => id + "/" + version).Order())).IsTrue();
                    foreach (string id in expectedIds)
                    {
                        string cache = Path.Combine(installation.Packages, id.ToLowerInvariant(), version.ToLowerInvariant());
                        using JsonDocument metadata = JsonDocument.Parse(File.ReadAllText(Path.Combine(cache, ".nupkg.metadata")));
                        await Assert.That(Path.TrimEndingDirectorySeparator(Path.GetFullPath(
                            metadata.RootElement.GetProperty("source").GetString()!)))
                            .IsEqualTo(Path.TrimEndingDirectorySeparator(relocated.Directory));
                        await Assert.That(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(
                            Path.Combine(cache, $"{id.ToLowerInvariant()}.{version.ToLowerInvariant()}.nupkg")))))
                            .IsEqualTo(expectedHashes[id]);
                    }
                }
                await LocalInfisicalInstallTests.Run(root, ["build", project, "--configuration", "Release", "--no-restore", .. installation.Properties]);
                string output = await LocalInfisicalInstallTests.Run(root,
                    [Path.Combine(installation.Binary, "Release", "net10.0", "SecretKit.InfisicalConsumer.dll"), "offline"]);
                using JsonDocument report = JsonDocument.Parse(output);
                await Assert.That(report.RootElement.GetProperty("kind").GetString()).IsEqualTo("local-installed-offline");
                await Assert.That(report.RootElement.GetProperty("mode").GetString()).IsEqualTo(mode);
                await Assert.That(report.RootElement.GetProperty("nativeQualified").GetBoolean()).IsFalse();
                JsonElement[] scenarios = report.RootElement.GetProperty("scenarios").EnumerateArray().ToArray();
                string[] expectedScenarios = mode is "configuration" or "full"
                    ? ["S03", "S04", "S05", "S06", "S07", "S08", "S09", "S10", "S11", "S12", "S13", "S16"]
                    : ["S03", "S04", "S05", "S06", "S07", "S08", "S09", "S10", "S12", "S13", "S16"];
                await Assert.That(scenarios.Select(s => s.GetProperty("id").GetString()).Order().SequenceEqual(expectedScenarios)).IsTrue();
                await Assert.That(scenarios.All(s => s.GetProperty("status").GetString() == "passed")).IsTrue();
                relocated.VerifyRestored(assets, installation.Packages, mode);
                await Assert.That(() => relocated.PrepareBundledConsumer(Path.Combine(scratch, mode), mode))
                    .Throws<InvalidOperationException>();
            }
            ConsumerInstallation missing = relocated.PrepareBundledConsumer(Path.Combine(scratch, "missing"), "minimal");
            File.Move(relocated.ArchivePath("SecretKit.Core"), Path.Combine(scratch, "unavailable.nupkg"));
            await LocalInfisicalInstallTests.Run(root,
                ["restore", project, "--configfile", missing.Configuration, .. missing.Properties], expectedExit: 1);
            foreach (string id in ids)
                await Assert.That(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(
                    Path.Combine(retained, "feed", $"{id}.{version}.nupkg"))))).IsEqualTo(expectedHashes[id]);
        }
        finally
        {
            Directory.Delete(scratch, recursive: true);
        }
    }
}
