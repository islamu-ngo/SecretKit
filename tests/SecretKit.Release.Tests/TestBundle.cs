using System.Text;
using System.Text.Json;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

// These temporary, synthetic attestations exercise validation only. They are
// never shipped as release evidence or usable against a protected environment.
internal sealed class TestBundle : IDisposable
{
    public string Root { get; } = Path.Combine(Path.GetTempPath(), "secretkit-release-tests-" + Guid.NewGuid().ToString("N"));
    public string JournalPath => Path.Combine(Root, "journal");
    public ReleaseManifest Data { get; set; }
    public Approval Approval { get; private set; }
    public const string Version = "0.1.0-preview.1";
    public static string Commit => new('a', 40);

    public TestBundle()
    {
        Directory.CreateDirectory(Root);
        const string notices = "Synthetic test notices";
        PackageRecord[] packages = Manifest.PackageIds.Select(id =>
        {
            string nuspec = $"""
                <package><metadata><id>{id}</id><version>{Version}</version>
                <license type="expression">MIT</license>
                <repository type="git" url="{Manifest.Repository}" commit="{Commit}"/>
                </metadata></package>
                """;
            byte[] bytes = ArchiveTests.Zip((id + ".nuspec", nuspec), ("README.md", "test"),
                ("THIRD-PARTY-NOTICES.md", notices));
            string file = $"{id}.{Version}.nupkg";
            File.WriteAllBytes(Path.Combine(Root, file), bytes);
            return new PackageRecord(id, file, Manifest.Hash(bytes));
        }).ToArray();
        var scope = new ReleaseScope(Version, Commit, Manifest.PackageIds.ToArray(),
            [new("Infisical", "read", "test-scope", "complete"), new("AzureKeyVault", "get", "test-vault", "complete")],
            ["linux-net10"],
            [
                Write("infisical-operations.json", new { provider = "Infisical",
                    operations = new[] { new { id = "read", admitted = true, implemented = true, liveVerified = true } } }),
                Write("azure-key-vault-operations.json", new { provider = "AzureKeyVault",
                    operations = new[] { new { id = "get", admitted = true, implemented = true, liveVerified = true } } })
            ]);
        FileDigest scopeFile = Write("scope.json", scope);
        FileDigest record = Write("synthetic-test-record.json", new { synthetic = true });
        string noticesHash = Manifest.Hash(Encoding.UTF8.GetBytes(notices));
        GateRecord[] gates = Manifest.GateKinds.Select(kind =>
        {
            string[] checks = kind switch
            {
                "native-operations" or "live-conformance" => scope.NativeOperations.Select(o => o.Key).ToArray(),
                "compatibility-install" => scope.Platforms,
                "namespace-rights" => [.. Manifest.PackageIds, "SecretKit."],
                "publisher-rights" => ["publisher:test-user", "owner:test-owner"],
                "oidc-registration" => [$"{Manifest.RepositoryName}/publish.yml/release", "https://www.nuget.org"],
                "protected-environment" => ["release", "required-reviewers", "prevent-self-review", "main-only"],
                "provenance" => [Commit, .. packages.Select(p => p.Sha256)],
                "notices" => [noticesHash],
                _ => throw new InvalidOperationException()
            };
            FileDigest file = Write(kind + ".json", new GateEvidence(kind, "passed", Version, Commit, scopeFile.Sha256,
                Manifest.PackageIds.ToArray(), checks, record));
            return new GateRecord(kind, file.File, file.Sha256);
        }).ToArray();
        Data = new(1, "SecretKit", Version, Commit, Manifest.Repository, 12, "test-user", "test-owner",
            "SecretKit.", "release", noticesHash, scopeFile, packages, gates);
        Approval = new("", Commit, Version, 12, 34, new string('b', 64), scopeFile.Sha256,
            "test-user", "test-owner", new string('c', 64), "new");
        Save();
    }

    public FileDigest Write<T>(string file, T value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value, Manifest.JsonOptions);
        File.WriteAllBytes(Path.Combine(Root, file), bytes);
        return new(file, Manifest.Hash(bytes));
    }

    public void Save()
    {
        FileDigest file = Write("manifest.json", Data);
        Approval = Approval with { ManifestSha256 = file.Sha256 };
    }

    public VerifiedRelease Verify() => Manifest.Verify(Root, Approval);

    public void ReviewScope(ReleaseScope scope)
    {
        FileDigest scopeFile = Write(Data.Scope.File, scope);
        GateRecord[] gates = Data.Gates.Select(g =>
        {
            GateEvidence evidence = Manifest.Parse<GateEvidence>(File.ReadAllBytes(Path.Combine(Root, g.File)));
            FileDigest file = Write(g.File, evidence with { ScopeSha256 = scopeFile.Sha256 });
            return g with { Sha256 = file.Sha256 };
        }).ToArray();
        Data = Data with { Scope = scopeFile, Gates = gates };
        Approval = Approval with { ScopeSha256 = scopeFile.Sha256 };
        Save();
    }

    public void Dispose() => Directory.Delete(Root, recursive: true);
}
