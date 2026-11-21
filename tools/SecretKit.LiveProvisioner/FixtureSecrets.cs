using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Infisical.Management;

namespace SecretKit.LiveProvisioner;

internal static class FixtureSecrets
{
    internal static async Task ResetAsync(ProvisioningSession session, string a, string b, string imports,
        SecretMaterial expectedA, SecretMaterial expectedB, CancellationToken ct)
    {
        const string conformance = "SDK_CONFORMANCE_VALUE";
        const string optional = "SDK_OPTIONAL_PACKAGE_VALUE";
        const string imported = "SDK_IMPORTED_VALUE";
        const string source = "/sdk-source";
        const string destination = "/sdk-destination";
        await using var client = session.CreateSecretsClient();
        foreach (var (project, expected) in new[] { (a, expectedA), (b, expectedB) })
        {
            var inventory = await Inventory(project, "dev", "/");
            if (inventory.Entries.Any(entry => entry.Key == optional))
                await Remove(project, "dev", "/", optional);
            await Write(project, "dev", "/", conformance, expected, inventory.Entries.Any(entry => entry.Key == conformance));
        }

        string org = session.OrganizationId;
        var dev = await session.Apply(ProjectOperations.GetEnvironmentBySlug(org, imports, "dev"), "read import source environment", ct);
        var prod = await session.Apply(ProjectOperations.GetEnvironmentBySlug(org, imports, "prod"), "read import destination environment", ct);
        _ = await EnsureFolder("dev", dev.Id, source[1..]);
        var destinationFolder = await EnsureFolder("prod", prod.Id, destination[1..]);
        var sourceInventory = await Inventory(imports, "dev", source);
        var destinationInventory = await Inventory(imports, "prod", destination);
        if (destinationInventory.Entries.Any(e => e.Key == imported))
            await Remove(imports, "prod", destination, imported);
        await Write(imports, "dev", source, imported, expectedA, sourceInventory.Entries.Any(e => e.Key == imported));

        var importTarget = new SecretReference(client.Authority,
            new InfisicalImportAddress(imports, "prod", destination, destinationFolder.Id));
        var links = ProvisioningSession.Require(await client.ListImportsAsync(importTarget, cancellationToken: ct), "list fixture imports");
        if (!links.IsComplete)
            throw new ProvisioningException("Incomplete import inventory.");
        var matching = links.Items.Where(link => link.SourceEnvironment == "dev" && link.SourcePath == source &&
            (link.SourceProjectId is null || link.SourceProjectId == imports) && link.IsReplication != true).ToArray();
        if (links.Items.Count != matching.Length || matching.Length > 1)
            throw new ProvisioningException("Unexpected or ambiguous import links in the fixture destination.");
        if (matching.Length == 0)
        {
            var receipt = client.CreateReceipt(importTarget);
            var outcome = await client.CreateImportAsync(importTarget, new("dev", source), false,
                session.NativeAuthority(client, imports, "prod", destination), receipt, ct);
            ProvisioningSession.Require(outcome, "create fixture import", receipt.Evidence);
        }

        async Task<InfisicalFolder> EnsureFolder(string environment, string environmentId, string name)
        {
            var listTarget = new SecretReference(client.Authority, new InfisicalFolderAddress(imports, environment, environmentId, "/"));
            var folders = ProvisioningSession.Require(await client.ListFoldersAsync(listTarget, cancellationToken: ct), "list fixture folders");
            if (!folders.IsComplete)
                throw new ProvisioningException("Incomplete fixture folder inventory.");
            var found = folders.Items.Where(folder => folder.Name == name).Take(2).ToArray();
            if (found.Length > 1)
                throw new ProvisioningException("Ambiguous fixture folder.");
            if (found.Length == 1)
                return found[0];
            var target = new SecretReference(client.Authority, new InfisicalFolderAddress(imports, environment, environmentId, "/", name: name));
            var receipt = client.CreateReceipt(target);
            return ProvisioningSession.Require(await client.CreateFolderAsync(target,
                session.NativeAuthority(client, imports, environment, "/"), receipt, cancellationToken: ct), "create fixture folder", receipt.Evidence);
        }

        async Task<InfisicalInventory> Inventory(string project, string environment, string path)
        {
            var result = ProvisioningSession.Require(await client.InspectNativeAsync(
                new(client.Authority, project, environment, path), ct), "inventory fixture keys");
            if (!result.IsComplete)
                throw new ProvisioningException("Incomplete fixture key inventory.");
            return result;
        }

        async Task Write(string project, string environment, string path, string key, SecretMaterial value, bool exists)
        {
            var target = new SecretReference(client.Authority, new InfisicalSecretAddress(project, environment, path, key));
            var receipt = client.CreateReceipt(target);
            var result = exists ? await client.UpdateValueAsync(target, value, receipt, ct) : await client.CreateAsync(target, value, receipt, ct);
            ProvisioningSession.Require(result, "seed fixture value", receipt.Evidence);
            if (receipt.Evidence != DispatchEvidence.Applied)
                throw new ProvisioningException($"Seed fixture value was not applied: {receipt.Evidence}.");
        }

        async Task Remove(string project, string environment, string path, string key)
        {
            var target = new SecretReference(client.Authority, new InfisicalBulkAddress(project, environment, path));
            InfisicalBulkSecret[] input = [new(key)];
            var receipt = new InfisicalBulkReceipt(client, target, input, InfisicalBulkOperation.Delete);
            var outcome = await client.DeleteSecretsAsync(target, input, session.NativeAuthority(client, project, environment, path), receipt, ct);
            var result = ProvisioningSession.Require(outcome, "delete stale fixture value", receipt.Evidence);
            if (!result.AllApplied)
                throw new ProvisioningException($"Delete stale fixture value was not applied: {receipt.Evidence}.");
        }
    }
}
