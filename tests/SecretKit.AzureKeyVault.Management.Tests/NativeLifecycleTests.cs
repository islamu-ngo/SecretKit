using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management.Tests;

public sealed class NativeLifecycleTests
{
    private static VaultScope Scope() => ScopeAuthorityTests.Scope();
    private static DeletedVaultScope Deleted() => new(Scope().ResourceGroup.Subscription, "eastus", "vault-canary");
    private static string DeletedId =>
        "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/vault-canary";
    private static string DeletedJson =>
        $$$"""{"id":"{{{DeletedId}}}","name":"vault-canary","type":"Microsoft.KeyVault/deletedVaults","properties":{"vaultId":"{{{ScopeAuthorityTests.Id}}}","location":"eastus","deletionDate":"2026-01-01T00:00:00Z","scheduledPurgeDate":"2026-01-08T00:00:00Z","purgeProtectionEnabled":true}}""";
    private static PrivateConnectionScope Connection() => new(Scope(), "connection-canary");
    private static string ConnectionId => ScopeAuthorityTests.Id + "/privateEndpointConnections/connection-canary";
    private static string ConnectionJson(string state = "Approved") =>
        $$$$"""{"id":"{{{{ConnectionId}}}}","name":"connection-canary","type":"Microsoft.KeyVault/vaults/privateEndpointConnections","properties":{"privateLinkServiceConnectionState":{"status":"{{{{state}}}}"},"provisioningState":"Succeeded","privateEndpoint":{"id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/group-canary/providers/Microsoft.Network/privateEndpoints/endpoint-canary"}}}""";

    [Test]
    public async Task DeletedGetAndInventoryRetainRetentionNotSecretMaterial()
    {
        var backend = new WireBackend((request, _) => Task.FromResult(WireBackend.Json(200,
            request.RequestUri!.AbsolutePath.EndsWith("/deletedVaults", StringComparison.Ordinal)
                ? $$$"""{"value":[{{{DeletedJson}}}]}""" : DeletedJson)));
        var client = new VaultAdministration(new Credential(), backend);
        var result = await client.GetDeletedVaultAsync(Deleted());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.PurgeProtected).IsTrue();
        await Assert.That(result.Value.DeletedOn).IsNotNull();
        var listed = await client.ListDeletedVaultsAsync(Scope().ResourceGroup.Subscription, new CollectionLimits());
        await Assert.That(listed.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(listed.Items.Count).IsEqualTo(1);
        await Assert.That(listed.Complete).IsTrue();
        await Assert.That(JsonSerializer.Serialize(result.Value).Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task SubscriptionInventoryCannotSubstituteSubscription()
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            $$$"""{"value":[{{{ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id.Replace("11111111", "99999999"))}}}]}""")));
        var result = await new VaultAdministration(new Credential(), backend)
            .ListVaultsAsync(Scope().ResourceGroup.Subscription, new CollectionLimits());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(result.Items.Count).IsEqualTo(0);
    }

    [Test]
    public async Task NameAvailabilityIsNotAReservation()
    {
        string? selected = null;
        var backend = new WireBackend(async (request, token) =>
        {
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            selected = body.RootElement.GetProperty("name").GetString();
            return WireBackend.Json(200, """{"nameAvailable":true}""");
        });
        var result = await new VaultAdministration(new Credential(), backend)
            .CheckNameAvailabilityAsync(Scope().ResourceGroup.Subscription, Scope().VaultName);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(selected).IsEqualTo("vault-canary");
        await Assert.That(result.Value.Available).IsTrue();
        await Assert.That(result.Value.NameReserved).IsFalse();
    }

    [Test]
    [Arguments(200)]
    [Arguments(204)]
    public async Task VaultDeleteUsesNativeDeleteWithoutPolling(int status)
    {
        bool exists = true;
        var backend = new WireBackend((request, _) =>
        {
            if (request.Method != HttpMethod.Delete)
            {
                throw new InvalidOperationException("Implicit status read.");
            }

            exists = false;
            return Task.FromResult(WireBackend.Json(status, status == 204 ? "" : "{}"));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Scope();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.DeleteVault);
        var result = await client.DeleteVaultAsync(scope, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(exists).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
    }

    [Test]
    public async Task PendingPurgeNeedsExplicitBoundedStatusCheck()
    {
        bool purged = false;
        bool allowStatus = false;
        var operationUrl = "https://management.azure.com/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.KeyVault/locations/eastus/operations/55555555-5555-5555-5555-555555555555?api-version=2026-02-01";
        var backend = new WireBackend((request, _) =>
        {
            if (request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath == DeletedId + "/purge")
            {
                var response = WireBackend.Json(202, "");
                response.Headers.TryAddWithoutValidation("Location", operationUrl);
                response.Headers.TryAddWithoutValidation("Azure-AsyncOperation", operationUrl);
                return Task.FromResult(response);
            }

            if (!allowStatus || request.RequestUri!.AbsoluteUri != operationUrl)
            {
                throw new InvalidOperationException("Unexpected implicit polling.");
            }

            purged = true;
            return Task.FromResult(WireBackend.Json(200, """{"status":"Succeeded"}"""));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Deleted();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.PurgeDeletedVault);
        var result = await client.PurgeDeletedVaultAsync(scope, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(purged).IsFalse();
        allowStatus = true;
        await Assert.That(await result.Value.CheckStatusAsync()).IsEqualTo(SecretStatus.Success);
        await Assert.That(purged).IsTrue();
        // A pending receipt remains historical initial evidence; checking cannot manufacture runtime delivery.
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
    }

    [Test]
    public async Task PendingPurgeCanUseTheSameHandleForOneLaterTerminalCheck()
    {
        const string target = "https://management.azure.com/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.KeyVault/locations/eastus/operations/55555555-5555-5555-5555-555555555555?api-version=2026-02-01";
        var requests = new List<(HttpMethod Method, string Target)>();
        bool terminal = false;
        var backend = new WireBackend((request, _) =>
        {
            requests.Add((request.Method, request.RequestUri!.AbsoluteUri));
            if (request.Method == HttpMethod.Post)
            {
                var response = WireBackend.Json(202, """{"status":"InProgress"}""");
                response.Headers.TryAddWithoutValidation("Location", target);
                response.Headers.TryAddWithoutValidation("Azure-AsyncOperation", target);
                return Task.FromResult(response);
            }
            if (request.Method != HttpMethod.Get || request.RequestUri.AbsoluteUri != target)
                throw new InvalidOperationException("unexpected-purge-status-request");
            return Task.FromResult(WireBackend.Json(200, terminal
                ? """{"status":"Succeeded"}""" : """{"status":"InProgress"}"""));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Deleted();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.PurgeDeletedVault);
        var start = client.PurgeDeletedVaultAsync(scope, receipt).AsTask();
        var result = await start;
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var handle = result.Value!;
        var pending = handle.CheckStatusAsync().AsTask();
        await Assert.That(await pending).IsEqualTo(SecretStatus.Pending);
        await Assert.That(handle.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(requests.Count(r => r.Method == HttpMethod.Get)).IsEqualTo(1);
        terminal = true;
        var completed = handle.CheckStatusAsync().AsTask();
        await Assert.That(await completed).IsEqualTo(SecretStatus.Success);
        await Assert.That(handle.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(requests.Count(r => r.Method == HttpMethod.Post)).IsEqualTo(1);
        await Assert.That(requests.Count(r => r.Method == HttpMethod.Get)).IsEqualTo(3);
        await Assert.That(requests.Where(r => r.Method == HttpMethod.Get).All(r => r.Target == target)).IsTrue();
    }

    [Test]
    public async Task ForgedAsyncLocationNeverEscapesAndRetainsUncertainty()
    {
        bool requestedPurge = false;
        var backend = new WireBackend((request, _) =>
        {
            if (request.RequestUri!.Host != "management.azure.com" || request.Method != HttpMethod.Post)
            {
                throw new InvalidOperationException("Forged status URL escaped.");
            }

            requestedPurge = true;
            var response = WireBackend.Json(202, "");
            response.Headers.TryAddWithoutValidation("Location", "https://evil.invalid/status?api-version=2026-02-01");
            return Task.FromResult(response);
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Deleted();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.PurgeDeletedVault);
        var result = await client.PurgeDeletedVaultAsync(scope, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(requestedPurge).IsTrue();
    }

    [Test]
    [Arguments("Canceled", NativeProvisioningState.Canceled)]
    [Arguments("Failed", NativeProvisioningState.Failed)]
    [Arguments("InProgress", NativeProvisioningState.Pending)]
    public async Task ExplicitStatusPreservesTerminalAndPendingStates(string state, NativeProvisioningState expected)
    {
        bool allowStatus = false;
        string statusUrl = "https://management.azure.com/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.KeyVault/locations/eastus/operations/55555555-5555-5555-5555-555555555555?api-version=2026-02-01";
        var backend = new WireBackend((request, _) =>
        {
            if (request.Method == HttpMethod.Post)
            {
                var response = WireBackend.Json(202, "");
                response.Headers.TryAddWithoutValidation("Azure-AsyncOperation", statusUrl);
                response.Headers.TryAddWithoutValidation("Location", statusUrl);
                return Task.FromResult(response);
            }

            if (!allowStatus)
            {
                throw new InvalidOperationException("Implicit status polling.");
            }

            return Task.FromResult(WireBackend.Json(200,
                $$$"""{"status":"{{{state}}}","error":{"code":"failure-canary","message":"protected-canary"}}"""));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Deleted();
        var result = await client.PurgeDeletedVaultAsync(scope,
            client.PrepareReceipt(scope, ManagementMutation.PurgeDeletedVault));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        allowStatus = true;
        var observed = await result.Value.CheckStatusAsync();
        await Assert.That(observed).IsEqualTo(expected == NativeProvisioningState.Pending ? SecretStatus.Pending : SecretStatus.Unknown);
        await Assert.That(result.Value.State).IsEqualTo(expected);
        await Assert.That(result.Value.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task PrivateConnectionsAndPrivateLinksStayWithinVault()
    {
        var backend = new WireBackend((request, _) => Task.FromResult(WireBackend.Json(200,
            request.RequestUri!.AbsolutePath.EndsWith("/privateEndpointConnections", StringComparison.Ordinal)
                ? $$$"""{"value":[{{{ConnectionJson()}}}]}""" :
            request.RequestUri.AbsolutePath.EndsWith("/privateLinkResources", StringComparison.Ordinal)
                ? $$$"""{"value":[{"id":"{{{ScopeAuthorityTests.Id}}}/privateLinkResources/vault","name":"vault","properties":{"groupId":"vault","requiredMembers":["default"],"requiredZoneNames":["privatelink.vaultcore.azure.net"]}}]}"""
                : ConnectionJson())));
        var client = new VaultAdministration(new Credential(), backend);
        var single = await client.GetPrivateConnectionAsync(Connection());
        await Assert.That(single.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(single.Value.State).IsEqualTo(PrivateConnectionState.Approved);
        var listed = await client.ListPrivateConnectionsAsync(Scope(), new CollectionLimits());
        await Assert.That(listed.Items.Count).IsEqualTo(1);
        await Assert.That(listed.Complete).IsTrue();
        var links = await client.ListPrivateLinkResourcesAsync(Scope(), new CollectionLimits());
        await Assert.That(links.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(links.Items.Count).IsEqualTo(1);
        await Assert.That(JsonSerializer.Serialize(links.Items[0])).IsEqualTo("{}");
    }

    [Test]
    public async Task PrivateConnectionUpdateAndDeleteChangeBackendState()
    {
        string state = "Pending";
        bool exists = true;
        var backend = new WireBackend(async (request, token) =>
        {
            if (request.Method == HttpMethod.Put)
            {
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                state = body.RootElement.GetProperty("properties").GetProperty("privateLinkServiceConnectionState")
                    .GetProperty("status").GetString()!;
                return WireBackend.Json(200, ConnectionJson(state));
            }

            if (request.Method == HttpMethod.Delete)
            {
                exists = false;
                return WireBackend.Json(204, "");
            }

            throw new InvalidOperationException("Implicit connection polling.");
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Connection();
        var result = await client.UpdatePrivateConnectionAsync(scope, PrivateConnectionState.Approved,
            client.PrepareReceipt(scope, ManagementMutation.UpdatePrivateConnection));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(state).IsEqualTo("Approved");
        var deleted = await client.DeletePrivateConnectionAsync(scope,
            client.PrepareReceipt(scope, ManagementMutation.DeletePrivateConnection));
        await Assert.That(deleted.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(exists).IsFalse();
    }

    [Test]
    public async Task AvailabilityInventoryCoversEveryAdmittedManagementFamily()
    {
        await Assert.That(OperationSupport.Inventory.Count).IsEqualTo(34);
        await Assert.That(OperationSupport.Inventory.Select(o => o.Operation).Distinct().Count()).IsEqualTo(34);
        await Assert.That(OperationSupport.Inventory.Count(o => o.Support == ManagementSupport.ProjectionNotImplemented))
            .IsEqualTo(0);
        await Assert.That(OperationSupport.Inventory.All(o => !o.LiveVerified && !o.PermissionChecked)).IsTrue();
    }
}
