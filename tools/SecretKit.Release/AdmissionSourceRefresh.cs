using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecretKit.Release;

public static class AdmissionSourceRefresh
{
    public static void Refresh(string source, string inventoryPath)
    {
        source = Path.GetFullPath(source);
        inventoryPath = Path.GetFullPath(inventoryPath);
        NoLinks(source);
        NoLinks(inventoryPath);
        byte[] original = Manifest.ReadLocalFile(inventoryPath, 4 * 1024 * 1024);
        AdmissionInventory inventory = Manifest.Parse<AdmissionInventory>(original);
        string file = inventory.Provider switch
        {
            "Infisical" => "infisical.json",
            "AzureKeyVault" => "azure-key-vault.json",
            _ => throw new ReleaseException("admission-provider")
        };
        Guard.Require(inventoryPath == Path.Combine(source, "docs", "internal", "releases", "admission", file),
            "admission-inventory-owner");
        string[] owners = ["SecretKit." + inventory.Provider, "SecretKit." + inventory.Provider + ".Management"];
        string[] members = owners.SelectMany(owner =>
        {
            string assembly = Path.Combine(source, "src", owner, "bin", "Release", "net10.0", owner + ".dll");
            NoLinks(assembly);
            return Admission.PublicRemoteMembers(assembly);
        }).ToArray();
        Admission.Validate(inventory, members);
        foreach (FileDigest item in inventory.Sources)
        {
            string[] segments = item.File.Split('/');
            Guard.Require(segments.Length >= 3 && segments[0] == "src" && owners.Contains(segments[1]) &&
                segments.All(segment => segment.Length > 0 && segment is not "." and not ".." &&
                    !segment.Contains('\\') && !segment.Contains(':') &&
                    !segment.Equals("obj", StringComparison.OrdinalIgnoreCase) &&
                    !segment.Equals("bin", StringComparison.OrdinalIgnoreCase)), "admission-source-owner");
            string path = Path.Combine(source, item.File);
            NoLinks(path);
            Guard.Require(File.Exists(path), "admission-source-missing");
        }
        FileDigest[] sources = owners.SelectMany(owner => Discover(Path.Combine(source, "src", owner)))
            .Select(path => new FileDigest(Path.GetRelativePath(source, path).Replace('\\', '/'),
                Manifest.Hash(Manifest.ReadLocalFile(path, 4 * 1024 * 1024))))
            .OrderBy(item => item.File, StringComparer.Ordinal).ToArray();
        Admission.Validate(inventory with { Sources = sources }, members);
        if (inventory.Sources.SequenceEqual(sources)) return;

        // Keep every non-source JSON value, including operation/case order.
        // Refreshing hashes cannot mint admission policy.
        JsonObject document = JsonNode.Parse(original)!.AsObject();
        document["sources"] = JsonSerializer.SerializeToNode(sources, Manifest.JsonOptions);
        byte[] updated = JsonSerializer.SerializeToUtf8Bytes(document, Manifest.JsonOptions);
        Guard.Require(File.ReadAllBytes(inventoryPath).SequenceEqual(original), "admission-inventory-changed");
        string temporary = inventoryPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            output.Write(updated);
            output.Flush(flushToDisk: true);
        }
        File.Move(temporary, inventoryPath, overwrite: true);
    }

    private static IEnumerable<string> Discover(string directory)
    {
        NoLinks(directory);
        foreach (string path in Directory.EnumerateFileSystemEntries(directory))
        {
            string name = Path.GetFileName(path);
            if (name.Equals("bin", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("obj", StringComparison.OrdinalIgnoreCase)) continue;
            NoLinks(path);
            if (Directory.Exists(path))
                foreach (string child in Discover(path)) yield return child;
            else if (path.EndsWith(".cs", StringComparison.Ordinal))
                yield return path;
        }
    }

    private static void NoLinks(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            Guard.Require((File.GetAttributes(current) & FileAttributes.ReparsePoint) == 0, "admission-source-link");
    }
}
