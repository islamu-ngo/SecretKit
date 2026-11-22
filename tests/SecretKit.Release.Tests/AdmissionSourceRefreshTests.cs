using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class AdmissionSourceRefreshTests
{
    [Test]
    public async Task AzureRefreshBindsOnlyReviewedGeneratorInputsAndLock()
    {
        using var fixture = new Sources("AzureKeyVault");
        var paths = new[] { "eng/ArmContracts/Bindings.txt", "eng/ArmContracts/ArmContractReader.cs",
            "eng/ArmContracts/Generate.cs", "eng/ArmContracts/LockedPackage.fsx", "eng/ArmContracts/ArmContracts.targets",
            "src/SecretKit.AzureKeyVault.Management/packages.lock.json" };
        Directory.CreateDirectory(Path.Combine(fixture.Root, "eng/ArmContracts"));
        foreach (string path in paths.Append("eng/ArmContracts/Unowned.cs"))
            File.WriteAllText(Path.Combine(fixture.Root, path), path);
        JsonObject original = JsonNode.Parse(File.ReadAllBytes(fixture.Inventory))!.AsObject();
        original.Remove("sources");
        for (int pass = 0; pass < 2; pass++)
        {
            if (pass == 1)
                foreach (string path in paths) File.AppendAllText(Path.Combine(fixture.Root, path), "changed");
            await Assert.That(await Program.Main(["admission-refresh-sources", fixture.Root, fixture.Inventory])).IsEqualTo(0);
            var refreshed = Manifest.Parse<AdmissionInventory>(File.ReadAllBytes(fixture.Inventory));
            foreach (string path in paths)
            {
                await Assert.That(refreshed.Sources.SingleOrDefault(s => s.File == path)?.Sha256)
                    .IsEqualTo(Manifest.Hash(File.ReadAllBytes(Path.Combine(fixture.Root, path))));
                await Assert.That(() => Admission.Validate(refreshed with
                {
                    Sources = refreshed.Sources.Where(s => s.File != path).ToArray()
                }, refreshed.Operations.Select(o => o.Member).ToArray())).Throws<ReleaseException>();
            }
            await Assert.That(refreshed.Sources.Any(s => s.File.EndsWith("Unowned.cs", StringComparison.Ordinal))).IsFalse();
            JsonObject current = JsonNode.Parse(File.ReadAllBytes(fixture.Inventory))!.AsObject();
            current.Remove("sources");
            await Assert.That(JsonNode.DeepEquals(original, current)).IsTrue();
        }
        byte[] before = File.ReadAllBytes(fixture.Inventory);
        string bindings = Path.Combine(fixture.Root, paths[0]);
        File.Delete(bindings);
        await Assert.That(await Program.Main(["admission-refresh-sources", fixture.Root, fixture.Inventory])).IsEqualTo(1);
        File.CreateSymbolicLink(bindings, Path.Combine(fixture.Root, paths[1]));
        await Assert.That(await Program.Main(["admission-refresh-sources", fixture.Root, fixture.Inventory])).IsEqualTo(1);
        await Assert.That(File.ReadAllBytes(fixture.Inventory).SequenceEqual(before)).IsTrue();
    }

    [Test]
    public async Task RefreshDiscoversChangedAndAddedSourcesWithoutChangingContractRows()
    {
        using var fixture = new Sources();
        JsonObject before = JsonNode.Parse(File.ReadAllBytes(fixture.Inventory))!.AsObject();
        fixture.WriteSource("Secrets/Added.cs", "added");
        fixture.WriteSource("Client.cs", "changed");

        int exit = await Program.Main(["admission-refresh-sources", fixture.Root, fixture.Inventory]);

        await Assert.That(exit).IsEqualTo(0);
        AdmissionInventory inventory = Manifest.Parse<AdmissionInventory>(File.ReadAllBytes(fixture.Inventory));
        AdmissionSourceCoverage.Verify(fixture.Root, fixture.SourceRoots, inventory.Sources);
        JsonObject after = JsonNode.Parse(File.ReadAllBytes(fixture.Inventory))!.AsObject();
        before.Remove("sources");
        after.Remove("sources");
        await Assert.That(JsonNode.DeepEquals(before, after)).IsTrue();
    }

    [Test]
    public async Task RefreshIncludesSharedSourceBytesWithoutChangingContractRows()
    {
        using var fixture = new Sources();
        string shared = Path.Combine(fixture.Root, "src", "Shared", "Http", "Policy.cs");
        Directory.CreateDirectory(Path.GetDirectoryName(shared)!);
        File.WriteAllText(shared, "shared-policy-original");
        JsonObject before = JsonNode.Parse(File.ReadAllBytes(fixture.Inventory))!.AsObject();

        int exit = await Program.Main(["admission-refresh-sources", fixture.Root, fixture.Inventory]);

        await Assert.That(exit).IsEqualTo(0);
        AdmissionInventory inventory = Manifest.Parse<AdmissionInventory>(File.ReadAllBytes(fixture.Inventory));
        AdmissionSourceCoverage.Verify(fixture.Root,
            [.. fixture.SourceRoots, Path.Combine(fixture.Root, "src", "Shared")], inventory.Sources);
        JsonObject after = JsonNode.Parse(File.ReadAllBytes(fixture.Inventory))!.AsObject();
        before.Remove("sources");
        after.Remove("sources");
        await Assert.That(JsonNode.DeepEquals(before, after)).IsTrue();

        File.WriteAllText(shared, "shared-policy-changed");
        await Assert.That(await Program.Main(["admission-refresh-sources", fixture.Root, fixture.Inventory])).IsEqualTo(0);
        AdmissionInventory refreshed = Manifest.Parse<AdmissionInventory>(File.ReadAllBytes(fixture.Inventory));
        AdmissionSourceCoverage.Verify(fixture.Root,
            [.. fixture.SourceRoots, Path.Combine(fixture.Root, "src", "Shared")], refreshed.Sources);
    }

    [Test]
    public async Task UnchangedRefreshPreservesExactInventoryBytes()
    {
        using var fixture = new Sources();
        byte[] before = File.ReadAllBytes(fixture.Inventory);

        int exit = await Program.Main(["admission-refresh-sources", fixture.Root, fixture.Inventory]);

        await Assert.That(exit).IsEqualTo(0);
        await Assert.That(File.ReadAllBytes(fixture.Inventory).SequenceEqual(before)).IsTrue();
    }

    [Test]
    [Arguments("foreign")]
    [Arguments("foreign-generator")]
    [Arguments("missing")]
    [Arguments("link")]
    [Arguments("directory-link")]
    [Arguments("shared-link")]
    [Arguments("member-drift")]
    [Arguments("empty-cases")]
    [Arguments("duplicate-operation")]
    public async Task InvalidSourcesOrContractsRejectWithoutWriting(string fault)
    {
        using var fixture = new Sources();
        JsonObject inventory = JsonNode.Parse(File.ReadAllBytes(fixture.Inventory))!.AsObject();
        switch (fault)
        {
            case "foreign":
                inventory["sources"]![0]!["file"] = "src/SecretKit.Core/Client.cs";
                break;
            case "foreign-generator":
                inventory["sources"]![0]!["file"] = "eng/ArmContracts/Generate.cs";
                break;
            case "missing":
                inventory["sources"]![0]!["file"] = "src/SecretKit.Infisical/Missing.cs";
                break;
            case "link":
                File.CreateSymbolicLink(Path.Combine(fixture.SourceRoots[0], "Link.cs"),
                    Path.Combine(fixture.SourceRoots[0], "Client.cs"));
                break;
            case "directory-link":
                Directory.CreateSymbolicLink(Path.Combine(fixture.SourceRoots[0], "Linked"), fixture.SourceRoots[1]);
                break;
            case "shared-link":
                Directory.CreateSymbolicLink(Path.Combine(fixture.Root, "src", "Shared"), fixture.SourceRoots[0]);
                break;
            case "member-drift":
                inventory["operations"]![0]!["member"] = "SecretKit.Infisical.Client.NewRemoteAsync()";
                break;
            case "empty-cases":
                inventory["operations"]![0]!["requiredCases"] = new JsonArray();
                break;
            case "duplicate-operation":
                inventory["operations"]!.AsArray().Add(inventory["operations"]![0]!.DeepClone());
                break;
        }
        File.WriteAllText(fixture.Inventory, inventory.ToJsonString(Manifest.JsonOptions));
        byte[] before = File.ReadAllBytes(fixture.Inventory);

        int exit = await Program.Main(["admission-refresh-sources", fixture.Root, fixture.Inventory]);

        await Assert.That(exit).IsEqualTo(1);
        await Assert.That(File.ReadAllBytes(fixture.Inventory).SequenceEqual(before)).IsTrue();
    }

    private sealed class Sources : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "secretkit-admission-" + Guid.NewGuid().ToString("N"));
        private readonly string _provider;
        private string FileName => _provider == "AzureKeyVault" ? "azure-key-vault.json" : "infisical.json";
        internal string Inventory => Path.Combine(Root, "docs/internal/releases/admission", FileName);
        internal string[] SourceRoots => [Path.Combine(Root, "src/SecretKit." + _provider),
            Path.Combine(Root, "src/SecretKit." + _provider + ".Management")];

        internal Sources(string provider = "Infisical")
        {
            _provider = provider;
            foreach (string source in SourceRoots) Directory.CreateDirectory(source);
            Directory.CreateDirectory(Path.GetDirectoryName(Inventory)!);
            WriteSource("Client.cs", "original");
            File.WriteAllText(Path.Combine(SourceRoots[1], "Client.cs"), "management");
            System.Reflection.Assembly[] assemblies = provider == "AzureKeyVault" ?
                [typeof(SecretKit.AzureKeyVault.AzureKeyVaultClient).Assembly,
                    typeof(SecretKit.AzureKeyVault.Management.VaultAdministration).Assembly] :
                [typeof(SecretKit.Infisical.InfisicalClient).Assembly,
                    typeof(SecretKit.Infisical.Management.ManagementClient).Assembly];
            foreach (System.Reflection.Assembly assembly in assemblies)
            {
                string name = assembly.GetName().Name!;
                string output = Path.Combine(Root, "src", name, "bin", "Release", "net10.0");
                Directory.CreateDirectory(output);
                File.Copy(assembly.Location, Path.Combine(output, name + ".dll"));
            }
            AdmissionInventory original = Manifest.Parse<AdmissionInventory>(File.ReadAllBytes(
                Path.Combine(VerificationTests.Repository.Source, "docs/internal/releases/admission", FileName)));
            FileDigest[] sources = SourceRoots.Select(directory => Path.Combine(directory, "Client.cs"))
                .Select(path => new FileDigest(Path.GetRelativePath(Root, path).Replace('\\', '/'),
                    Manifest.Hash(File.ReadAllBytes(path)))).OrderBy(item => item.File, StringComparer.Ordinal).ToArray();
            File.WriteAllBytes(Inventory, JsonSerializer.SerializeToUtf8Bytes(original with { Sources = sources }, Manifest.JsonOptions));
        }

        internal void WriteSource(string path, string content)
        {
            string destination = Path.Combine(SourceRoots[0], path);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.WriteAllText(destination, content);
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
