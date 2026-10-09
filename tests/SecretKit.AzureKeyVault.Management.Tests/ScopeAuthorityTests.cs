using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management.Tests;

public sealed class ScopeAuthorityTests
{
    internal const string Id = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/group-canary/providers/Microsoft.KeyVault/vaults/vault-canary";
    internal static string VaultJson(string id, string state = "Succeeded") =>
        $$$"""{"id":"{{{id}}}","name":"vault-canary","type":"Microsoft.KeyVault/vaults","location":"eastus","properties":{"tenantId":"22222222-2222-2222-2222-222222222222","sku":{"family":"A","name":"standard"},"provisioningState":"{{{state}}}","vaultUri":"https://vault-canary.vault.azure.net/"}}""";

    [Test]
    public async Task SubstitutedVaultCannotBecomeRequestedVaultEvidence()
    {
        var backend = new WireBackend((_, _) => Task.FromResult(
            WireBackend.Json(200, VaultJson(Id.Replace("group-canary", "other-group")))));
        var client = new VaultAdministration(new Credential(), backend);
        var returned = await client.GetVaultAsync(Scope());
        await Assert.That(returned.Status).IsEqualTo(SecretStatus.Invalid);
    }

    internal static VaultScope Scope() => new(new ResourceGroupScope(
        new SubscriptionScope(Guid.Parse("11111111-1111-1111-1111-111111111111")), "group-canary"), "vault-canary");
}
