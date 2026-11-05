using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class AdmissionSourceRefreshTests
{
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
    [Arguments("missing")]
    [Arguments("link")]
    [Arguments("directory-link")]
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
        internal string Inventory => Path.Combine(Root, "docs/internal/releases/admission/infisical.json");
        internal string[] SourceRoots => [Path.Combine(Root, "src/SecretKit.Infisical"),
            Path.Combine(Root, "src/SecretKit.Infisical.Management")];

        internal Sources()
        {
            foreach (string source in SourceRoots) Directory.CreateDirectory(source);
            Directory.CreateDirectory(Path.GetDirectoryName(Inventory)!);
            WriteSource("Client.cs", "original");
            File.WriteAllText(Path.Combine(SourceRoots[1], "Client.cs"), "management");
            foreach (System.Reflection.Assembly assembly in new[] {
                typeof(SecretKit.Infisical.InfisicalClient).Assembly,
                typeof(SecretKit.Infisical.Management.ManagementClient).Assembly })
            {
                string name = assembly.GetName().Name!;
                string output = Path.Combine(Root, "src", name, "bin", "Release", "net10.0");
                Directory.CreateDirectory(output);
                File.Copy(assembly.Location, Path.Combine(output, name + ".dll"));
            }
            AdmissionInventory original = Manifest.Parse<AdmissionInventory>(File.ReadAllBytes(
                Path.Combine(VerificationTests.Repository.Source, "docs/internal/releases/admission/infisical.json")));
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
