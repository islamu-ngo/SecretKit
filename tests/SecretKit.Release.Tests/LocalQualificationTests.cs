using System.Text.Json.Nodes;

namespace SecretKit.Release.Tests;

public sealed class LocalQualificationTests
{
    [Test]
    public async Task ExplicitLocalProfilePreparesAndChecksWithoutPublicationAuthority()
    {
        using var fixture = new LocalFixture();
        await Assert.That(await Program.Main(["local-prepare", fixture.Source, fixture.Packages, fixture.Output]))
            .IsEqualTo(0);
        await Assert.That(await Program.Main(["local-check", fixture.Source, fixture.Packages, fixture.Output]))
            .IsEqualTo(0);
        await Assert.That(Directory.GetFiles(fixture.Output).Select(p => Path.GetFileName(p)!).ToArray())
            .IsEquivalentTo(["local-qualification.json"]);
        LocalQualificationRecord record = LocalQualification.Check(fixture.Source, fixture.Packages, fixture.Output);
        await Assert.That(record.Source.Kind).IsEqualTo("source-content-v1");
        await Assert.That(Manifest.IsHash(record.Source.Sha256)).IsTrue();
        await Assert.That(record.Source.Files.Any(f => f.File == "empty")).IsTrue();
        await Assert.That(record.Packages.Length).IsEqualTo(4);
        await Assert.That(record.Platform.RuntimeIdentifier).IsEqualTo(System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier);
        await Assert.That(record.Platform.Framework).IsEqualTo(System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
    }

    [Test]
    public async Task ProfileMembersMatchExactRuntimeSignatures()
    {
        using var fixture = new LocalFixture();
        LocalProfile profile = LocalQualification.ReadProfile(fixture.Source);
        Type[] types =
        [
            typeof(Infisical.InfisicalClient), typeof(Infisical.InfisicalUniversalAuthentication),
            typeof(Infisical.InfisicalPeriodicTokenSession)
        ];
        string[] signatures = types.SelectMany(t => t.GetMethods(System.Reflection.BindingFlags.Public |
            System.Reflection.BindingFlags.Instance).Select(m =>
                $"{t.FullName}.{m.Name}({string.Join(",", m.GetParameters().Select(p => p.ParameterType.FullName))})"))
            .ToArray();
        await Assert.That(profile.Operations.Length).IsEqualTo(8);
        await Assert.That(profile.Operations.All(o => signatures.Contains(o.Member))).IsTrue();
        await Assert.That(profile.Operations[^1].Id).IsEqualTo("read-native");
        await Assert.That(profile.NativeReadPolicy).IsEqualTo("Raw IncludeImports=false");
    }

    [Test]
    public async Task PublicManifestCannotBeReadAsLocalQualification()
    {
        using var fixture = new LocalFixture();
        using var bundle = new TestBundle();
        Directory.CreateDirectory(fixture.Output);
        File.Copy(Path.Combine(bundle.Root, "manifest.json"), fixture.RecordPath);
        await Assert.That(await Program.Main(["local-check", fixture.Source, fixture.Packages, fixture.Output]))
            .IsEqualTo(1);
    }

    [Test]
    [Arguments("missing-package")]
    [Arguments("extra-package")]
    [Arguments("duplicate-package")]
    [Arguments("missing-member")]
    [Arguments("extra-member")]
    [Arguments("duplicate-member")]
    [Arguments("wrong-signature")]
    [Arguments("swapped-member")]
    [Arguments("missing-scenario")]
    [Arguments("extra-scenario")]
    [Arguments("duplicate-scenario")]
    [Arguments("unknown-field")]
    [Arguments("duplicate-field")]
    [Arguments("version")]
    [Arguments("schema")]
    [Arguments("kind")]
    [Arguments("native-policy")]
    public async Task ProfileHasAnExactBoundedDenominator(string fault)
    {
        using var fixture = new LocalFixture();
        if (fault == "duplicate-field")
            File.WriteAllText(fixture.ProfilePath, File.ReadAllText(fixture.ProfilePath)
                .Replace("\"schemaVersion\": 1", "\"schemaVersion\": 1, \"schemaVersion\": 1", StringComparison.Ordinal));
        else
            fixture.ChangeProfile(p =>
            {
                switch (fault)
                {
                    case "missing-package": p["packageIds"]!.AsArray().RemoveAt(0); break;
                    case "extra-package": p["packageIds"]!.AsArray().Add("SecretKit.AzureKeyVault"); break;
                    case "duplicate-package": p["packageIds"]!.AsArray().Add("SecretKit.Core"); break;
                    case "missing-member": p["operations"]!.AsArray().RemoveAt(0); break;
                    case "extra-member":
                        p["operations"]!.AsArray().Add(new JsonObject { ["id"] = "other", ["member"] = "Unknown.Other()" });
                        break;
                    case "duplicate-member": p["operations"]!.AsArray().Add(p["operations"]![0]!.DeepClone()); break;
                    case "wrong-signature": p["operations"]![0]!["member"] = "Unknown.ReadAsync()"; break;
                    case "swapped-member":
                        (p["operations"]![0]!["member"], p["operations"]![1]!["member"]) =
                            (p["operations"]![1]!["member"]!.DeepClone(), p["operations"]![0]!["member"]!.DeepClone());
                        break;
                    case "missing-scenario": p["scenarios"]!.AsArray().RemoveAt(0); break;
                    case "extra-scenario": p["scenarios"]!.AsArray().Add("S17"); break;
                    case "duplicate-scenario": p["scenarios"]!.AsArray().Add("S01"); break;
                    case "unknown-field": p["publisher"] = "not-authority"; break;
                    case "version": p["version"] = "../0.1.0"; break;
                    case "schema": p["schemaVersion"] = 2; break;
                    case "kind": p["kind"] = "current-admission"; break;
                    case "native-policy": p["nativeReadPolicy"] = "Expanded IncludeImports=true"; break;
                    default: throw new InvalidOperationException();
                }
            });
        await Assert.That(await Program.Main(["local-prepare", fixture.Source, fixture.Packages, fixture.Output]))
            .IsEqualTo(1);
        await Assert.That(Directory.Exists(fixture.Output)).IsFalse();
    }

    [Test]
    [Arguments("missing")]
    [Arguments("extra")]
    [Arguments("mixed-version")]
    [Arguments("wrong-source")]
    [Arguments("bad-notices")]
    [Arguments("dependency")]
    [Arguments("internal-version")]
    [Arguments("traversal-archive")]
    [Arguments("symlink-file")]
    [Arguments("symlink-directory")]
    public async Task InvalidOriginalArchivesFailBeforeRecordCreation(string fault)
    {
        using var fixture = new LocalFixture();
        string file = Path.Combine(fixture.Packages, $"SecretKit.Core.{TestBundle.Version}.nupkg");
        switch (fault)
        {
            case "missing": File.Delete(file); break;
            case "extra": File.Copy(file, Path.Combine(fixture.Packages, "extra.nupkg")); break;
            case "mixed-version": fixture.WritePackage("SecretKit.Core", "0.2.0"); break;
            case "wrong-source":
            case "bad-notices":
                ArchiveContent archive = PackageArchive.Read(File.ReadAllBytes(file));
                var files = archive.Files.Select(p => (p.Key, System.Text.Encoding.UTF8.GetString(p.Value))).ToArray();
                files = files.Select(p => fault == "wrong-source"
                    ? (p.Key, p.Item2.Replace(TestBundle.Commit, new string('b', 40), StringComparison.Ordinal))
                    : (p.Key, p.Key == "THIRD-PARTY-NOTICES.md" ? "wrong" : p.Item2)).ToArray();
                File.WriteAllBytes(file, ArchiveTests.Zip(files));
                break;
            case "dependency":
                fixture.WritePackage("SecretKit.Infisical", dependency:
                    """<dependency id="SecretKit.AzureKeyVault" version="[0.1.0-preview.1]" />""");
                break;
            case "internal-version":
                fixture.WritePackage("SecretKit.Infisical", internalVersion: "0.2.0");
                break;
            case "traversal-archive": File.WriteAllBytes(file, ArchiveTests.Zip(("../bad", "bad"))); break;
            case "symlink-file":
                string original = Path.Combine(fixture.Root, "original.nupkg");
                File.Move(file, original);
                File.CreateSymbolicLink(file, original);
                break;
            case "symlink-directory":
                string moved = fixture.Packages + "-original";
                Directory.Move(fixture.Packages, moved);
                Directory.CreateSymbolicLink(fixture.Packages, moved);
                break;
            default: throw new InvalidOperationException();
        }
        await Assert.That(await Program.Main(["local-prepare", fixture.Source, fixture.Packages, fixture.Output]))
            .IsEqualTo(1);
        await Assert.That(Directory.Exists(fixture.Output)).IsFalse();
    }

    [Test]
    [Arguments("mutated-original")]
    [Arguments("source-change")]
    [Arguments("source-add")]
    [Arguments("source-delete")]
    [Arguments("empty-source-change")]
    [Arguments("source-link")]
    [Arguments("source-directory-link")]
    [Arguments("record-hash")]
    [Arguments("record-bad-hash")]
    [Arguments("record-traversal")]
    [Arguments("record-kind")]
    [Arguments("record-schema")]
    [Arguments("record-version")]
    [Arguments("record-source-commit")]
    [Arguments("record-profile-hash")]
    [Arguments("record-status")]
    [Arguments("record-unknown")]
    [Arguments("record-duplicate")]
    [Arguments("record-package-duplicate")]
    [Arguments("record-source-digest")]
    [Arguments("record-source-files")]
    [Arguments("record-link")]
    public async Task CheckReopensOriginalsAndRecomputesSourceContent(string fault)
    {
        using var fixture = new LocalFixture();
        await Assert.That(await Program.Main(["local-prepare", fixture.Source, fixture.Packages, fixture.Output]))
            .IsEqualTo(0);
        switch (fault)
        {
            case "mutated-original":
                File.AppendAllText(Path.Combine(fixture.Packages, $"SecretKit.Core.{TestBundle.Version}.nupkg"), " ");
                break;
            case "source-change": File.AppendAllText(Path.Combine(fixture.Source, "input.cs"), "changed"); break;
            case "source-add": File.WriteAllText(Path.Combine(fixture.Source, "added.cs"), "added"); break;
            case "source-delete": File.Delete(Path.Combine(fixture.Source, "input.cs")); break;
            case "empty-source-change": File.WriteAllText(Path.Combine(fixture.Source, "empty"), "changed"); break;
            case "source-link": File.CreateSymbolicLink(Path.Combine(fixture.Source, "linked"), fixture.ProfilePath); break;
            case "source-directory-link":
                Directory.CreateSymbolicLink(Path.Combine(fixture.Source, "linked"), fixture.Packages);
                break;
            case "record-duplicate":
                File.WriteAllText(fixture.RecordPath, File.ReadAllText(fixture.RecordPath)
                    .Replace("\"schemaVersion\": 1", "\"schemaVersion\": 1, \"schemaVersion\": 1", StringComparison.Ordinal));
                break;
            case "record-link":
                string record = fixture.RecordPath + ".original";
                File.Move(fixture.RecordPath, record);
                File.CreateSymbolicLink(fixture.RecordPath, record);
                break;
            default:
                fixture.ChangeRecord(p =>
                {
                    switch (fault)
                    {
                        case "record-hash": p["packages"]![0]!["sha256"] = new string('0', 64); break;
                        case "record-bad-hash": p["packages"]![0]!["sha256"] = "bad"; break;
                        case "record-traversal": p["packages"]![0]!["file"] = "../bad.nupkg"; break;
                        case "record-kind": p["kind"] = "release-observation"; break;
                        case "record-schema": p["schemaVersion"] = 2; break;
                        case "record-version": p["version"] = "0.2.0"; break;
                        case "record-source-commit": p["sourceCommit"] = new string('b', 40); break;
                        case "record-profile-hash": p["profile"]!["sha256"] = new string('0', 64); break;
                        case "record-status": p["status"] = "native-qualified"; break;
                        case "record-unknown": p["approval"] = "not-authority"; break;
                        case "record-package-duplicate":
                            p["packages"]!.AsArray().Add(p["packages"]![0]!.DeepClone()); break;
                        case "record-source-digest": p["source"]!["sha256"] = new string('0', 64); break;
                        case "record-source-files": p["source"]!["files"]!.AsArray().RemoveAt(0); break;
                        default: throw new InvalidOperationException();
                    }
                });
                break;
        }
        await Assert.That(await Program.Main(["local-check", fixture.Source, fixture.Packages, fixture.Output]))
            .IsEqualTo(1);
    }

    [Test]
    public async Task PreparationNeverOverwritesPriorEvidence()
    {
        using var fixture = new LocalFixture();
        await Assert.That(await Program.Main(["local-prepare", fixture.Source, fixture.Packages, fixture.Output]))
            .IsEqualTo(0);
        byte[] original = File.ReadAllBytes(fixture.RecordPath);
        await Assert.That(await Program.Main(["local-prepare", fixture.Source, fixture.Packages, fixture.Output]))
            .IsEqualTo(1);
        await Assert.That(File.ReadAllBytes(fixture.RecordPath).SequenceEqual(original)).IsTrue();
    }

    [Test]
    public async Task OutputCannotBecomeAnUnrecordedSourceInputOrFollowALink()
    {
        using var fixture = new LocalFixture();
        string destination = Path.Combine(fixture.Source, "record");
        await Assert.That(await Program.Main(["local-prepare", fixture.Source, fixture.Packages, destination]))
            .IsEqualTo(1);
        await Assert.That(Directory.Exists(destination)).IsFalse();
        string link = Path.Combine(fixture.Root, "link");
        Directory.CreateSymbolicLink(link, fixture.Source);
        await Assert.That(await Program.Main(["local-prepare", fixture.Source, fixture.Packages,
            Path.Combine(link, "artifacts-record")])).IsEqualTo(1);
        await Assert.That(Directory.Exists(Path.Combine(fixture.Source, "artifacts-record"))).IsFalse();
    }

    [Test]
    public async Task BuildOutputsAndPrivateNotesDoNotInvalidateSourceContent()
    {
        using var fixture = new LocalFixture();
        await Assert.That(await Program.Main(["local-prepare", fixture.Source, fixture.Packages, fixture.Output]))
            .IsEqualTo(0);
        foreach (string directory in new[] { ".git", "artifacts", "dev", ".worktrees", "src/Example/bin", "src/Example/obj", "TestResults" })
        {
            string path = Path.Combine(fixture.Source, directory);
            Directory.CreateDirectory(path);
            File.WriteAllText(Path.Combine(path, "output"), "excluded");
        }
        await Assert.That(await Program.Main(["local-check", fixture.Source, fixture.Packages, fixture.Output]))
            .IsEqualTo(0);
    }

    internal sealed class LocalFixture : IDisposable
    {
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "secretkit-local-" + Guid.NewGuid().ToString("N"));
        public string Source => Path.Combine(Root, "source");
        public string Packages => Path.Combine(Root, "packages");
        public string Output => Path.Combine(Root, "record");
        public string ProfilePath => Path.Combine(Source, "docs/internal/local/infisical-runtime.json");
        public string RecordPath => Path.Combine(Output, "local-qualification.json");
        public string[] Ids { get; } =
        [
            "SecretKit.Core", "SecretKit.Infisical",
            "SecretKit.Extensions.Configuration", "SecretKit.Extensions.Hosting"
        ];

        public LocalFixture()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ProfilePath)!);
            Directory.CreateDirectory(Packages);
            DirectoryInfo? checkout = new(AppContext.BaseDirectory);
            while (checkout is not null && !File.Exists(Path.Combine(checkout.FullName, "SecretKit.slnx")))
                checkout = checkout.Parent;
            File.Copy(Path.Combine(checkout!.FullName, "docs/internal/local/infisical-runtime.json"), ProfilePath);
            ChangeProfile(p => p["version"] = TestBundle.Version);
            File.WriteAllText(Path.Combine(Source, "input.cs"), "controlled source");
            File.WriteAllText(Path.Combine(Source, "empty"), "");
            File.WriteAllText(Path.Combine(Source, "THIRD-PARTY-NOTICES.md"), "controlled notices");
            foreach (string id in Ids) WritePackage(id);
        }

        public void WritePackage(string id, string version = TestBundle.Version, string? dependency = null,
            string internalVersion = TestBundle.Version)
        {
            string[] dependencies = id switch
            {
                "SecretKit.Core" => [],
                "SecretKit.Extensions.Hosting" => ["SecretKit.Core", "SecretKit.Infisical"],
                _ => ["SecretKit.Core"]
            };
            string entries = string.Concat(dependencies.Select(d =>
                $"""<dependency id="{d}" version="[{internalVersion}]" />"""));
            string[] external = id switch
            {
                "SecretKit.Core" => [],
                "SecretKit.Infisical" => ["Refit"],
                "SecretKit.Extensions.Configuration" => ["Microsoft.Extensions.Configuration"],
                _ => ["Microsoft.Extensions.Hosting.Abstractions", "Microsoft.Extensions.Diagnostics.HealthChecks.Abstractions"]
            };
            entries += string.Concat(external.Select(d => $"""<dependency id="{d}" version="1.0.0" />"""));
            if (dependency is not null) entries += dependency;
            byte[] archive = ArchiveTests.Zip((id + ".nuspec", $"""
                <package><metadata><id>{id}</id><version>{version}</version>
                <license type="expression">MIT</license>
                <repository type="git" url="{Manifest.Repository}" commit="{TestBundle.Commit}"/>
                <dependencies><group targetFramework="net10.0">{entries}</group></dependencies>
                </metadata></package>
                """), ("README.md", "controlled"),
                ("THIRD-PARTY-NOTICES.md", "controlled notices"));
            File.WriteAllBytes(Path.Combine(Packages, $"{id}.{TestBundle.Version}.nupkg"), archive);
        }

        public void ChangeProfile(Action<JsonObject> change) => ChangeJson(ProfilePath, change);
        public void ChangeRecord(Action<JsonObject> change) => ChangeJson(RecordPath, change);

        private static void ChangeJson(string path, Action<JsonObject> change)
        {
            JsonObject json = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
            change(json);
            File.WriteAllText(path, json.ToJsonString(Manifest.JsonOptions));
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
