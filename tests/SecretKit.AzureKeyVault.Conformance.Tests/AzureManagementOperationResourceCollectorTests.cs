using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector;
using Capture = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationResourceCollectorTests
{
    [Test]
    [Arguments("https://resource-vault.vault.azure.net/", true)]
    [Arguments("https://resource-vault.vault.azure.net", true)]
    [Arguments("http://resource-vault.vault.azure.net/", false)]
    [Arguments("https://foreign.vault.azure.net/", false)]
    [Arguments("https://resource-vault.vault.azure.net:444/", false)]
    [Arguments("https://resource-vault.vault.azure.net/?foreign=1", false)]
    [Arguments("https://resource-vault.vault.azure.net/#foreign", false)]
    [Arguments("https://user@resource-vault.vault.azure.net/", false)]
    public async Task NativeVaultMetadataEndpointKeepsExactAuthorityAcrossRootForms(string endpoint, bool allowed)
    {
        using var f = new Fixture("DeleteVault");
        var body = JsonNode.Parse(f.Body)!;
        body["properties"]!["vaultUri"] = endpoint;
        f.Body = body.ToJsonString();
        using var measured = await f.Read();
        await Assert.That(measured.ResponseComplete).IsEqualTo(allowed);
        await Assert.That(measured.PersistedStateEligible).IsEqualTo(allowed);
        await Assert.That(measured.PrincipalQualified || measured.AsyncSettlementProven || measured.EgressQualified).IsFalse();
        await Cleared(f);
    }

    [Test]
    [Arguments("default", true)]
    [Arguments("recover", true)]
    [Arguments(null, true)]
    [Arguments("future-mode", false)]
    public async Task NativeVaultMetadataCreationModeIsPreservedOrRemainsIneligible(string? mode, bool eligible)
    {
        using var f = new Fixture("DeleteVault");
        var body = JsonNode.Parse(f.Body)!;
        body["properties"]!["createMode"] = mode;
        f.Body = body.ToJsonString();
        using var measured = await f.Read();
        await Assert.That(measured.ResponseComplete).IsEqualTo(eligible);
        await Assert.That(measured.ResourceStatus).IsEqualTo(eligible ? SecretStatus.Success : SecretStatus.Unavailable);
        await Assert.That(measured.PersistedStateEligible).IsEqualTo(eligible);
        if (eligible) await Assert.That(measured.VaultConfiguration!.CreateMode).IsEqualTo(mode);
        else await Assert.That(measured.VaultConfiguration).IsNull();
        await Cleared(f);
    }

    private const string Subscription = "11111111-1111-1111-1111-111111111111";
    private const string Tenant = "22222222-2222-2222-2222-222222222222";
    private const string Assignment = "33333333-3333-3333-3333-333333333333";
    private const string Protected = "resource-private-material";
    private const string Vault = "/subscriptions/" + Subscription + "/resourceGroups/resource-group/providers/Microsoft.KeyVault/vaults/resource-vault";
    private const string Origin = "https://management.azure.com";
    private const string Endpoint = "/subscriptions/" + Subscription +
        "/resourceGroups/network-group/providers/Microsoft.Network/privateEndpoints/generated-endpoint";
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 0, 0, 0, TimeSpan.Zero);
    private static readonly C.Limits Bounds = new(65536, 32768, 4096, 256, 16, TimeSpan.FromSeconds(20));

    [Test]
    [Arguments("UpdatePrivateConnection")]
    [Arguments("DeletePrivateConnection")]
    public async Task PrivateConnectionEndpointIdentityComesFromIndependentNativeRead(string operation)
    {
        using var f = new Fixture(operation);
        using var measured = await f.Read();
        await Assert.That(measured.PrivateEndpointId).IsEqualTo(Endpoint);
        await Assert.That(measured.PersistedStateEligible).IsTrue();
        await Assert.That(measured.AsyncSettlementProven || measured.PrincipalQualified || measured.EgressQualified).IsFalse();
        await Assert.That(JsonSerializer.Serialize(measured)).IsEqualTo("{}");
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Cleared(f);
    }

    [Test]
    [Arguments("omitted")]
    [Arguments("null")]
    public async Task MissingEndpointIdentityCannotBeInventedFromConnectionCoordinates(string fault)
    {
        using var f = new Fixture("UpdatePrivateConnection");
        var body = JsonNode.Parse(f.Body)!;
        if (fault == "omitted") body["properties"]!.AsObject().Remove("privateEndpoint");
        else body["properties"]!["privateEndpoint"] = null;
        f.Body = body.ToJsonString();
        using var measured = await f.Read();
        await Assert.That(measured.PrivateEndpointId).IsNull();
        await Assert.That(measured.ResourceStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(measured.ConnectionState).IsEqualTo(PrivateConnectionState.Approved);
    }

    [Test]
    [Arguments("missing-id")]
    [Arguments("null-id")]
    [Arguments("empty-id")]
    [Arguments("wrong-kind")]
    [Arguments("url")]
    [Arguments("subresource")]
    [Arguments("encoded")]
    [Arguments("non-guid")]
    public async Task MalformedEndpointIdentityInvalidatesTheWholeObservation(string fault)
    {
        using var f = new Fixture("UpdatePrivateConnection");
        var body = JsonNode.Parse(f.Body)!;
        var endpoint = body["properties"]!["privateEndpoint"]!.AsObject();
        if (fault == "missing-id") endpoint.Remove("id");
        else endpoint["id"] = fault switch
        {
            "null-id" => null,
            "empty-id" => "",
            "wrong-kind" => Endpoint.Replace("privateEndpoints", "networkInterfaces", StringComparison.Ordinal),
            "url" => Origin + Endpoint,
            "subresource" => Endpoint + "/children/foreign",
            "encoded" => Endpoint.Replace("generated-endpoint", "generated%2Fendpoint", StringComparison.Ordinal),
            _ => Endpoint.Replace(Subscription, "not-a-guid", StringComparison.Ordinal)
        };
        f.Body = body.ToJsonString();
        using var measured = await f.Read();
        await Assert.That(measured.ResponseComplete).IsFalse();
        await Assert.That(measured.PrivateEndpointId).IsNull();
        await Assert.That(measured.ConnectionState).IsNull();
        await Assert.That(measured.PersistedStateEligible).IsFalse();
        await Cleared(f);
    }

    [Test]
    public async Task DifferentEndpointIsAnObservedFactNotOwnershipOrSelection()
    {
        using var f = new Fixture("UpdatePrivateConnection");
        string foreign = Endpoint.Replace(Subscription, Tenant, StringComparison.Ordinal);
        f.Body = f.Body.Replace(Endpoint, foreign, StringComparison.Ordinal);
        using var measured = await f.Read();
        await Assert.That(measured.PrivateEndpointId).IsEqualTo(foreign);
        await Assert.That(measured.ResourceStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(measured.AsyncSettlementProven || measured.PrincipalQualified).IsFalse();
    }

    [Test]
    [Arguments(404)]
    [Arguments(403)]
    public async Task UnsuccessfulPrivateConnectionReadCannotRetainEndpointIdentity(int status)
    {
        using var f = new Fixture("DeletePrivateConnection") { Status = status };
        using var measured = await f.Read();
        await Assert.That(measured.PrivateEndpointId).IsNull();
        await Assert.That(measured.ConnectionState).IsNull();
        await Assert.That(measured.PersistedStateEligible).IsFalse();
    }

    [Test]
    [Arguments("CreateOrUpdateVault")]
    [Arguments("RecoverVault")]
    [Arguments("DeleteVault")]
    [Arguments("PurgeDeletedVault")]
    [Arguments("UpdatePrivateConnection")]
    [Arguments("DeletePrivateConnection")]
    [Arguments("DeleteRoleAssignment")]
    [Arguments("CreateOrUpdateNotification")]
    [Arguments("UpdateNotification")]
    [Arguments("DeleteNotification")]
    public async Task AllTenKindsReadIndependentPersistedNativeState(string operation)
    {
        using var f = new Fixture(operation);
        using var measured = await f.Read();
        await Assert.That(measured.ResourceStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(measured.ResponseComplete).IsTrue();
        await Assert.That(measured.Binding).IsEqualTo(f.Binding);
        await Assert.That(measured.Binding.Selector.Scope).IsEqualTo("original-controlled-scope");
        await Assert.That(measured.ResourceId).IsEqualTo(f.Path);
        await Assert.That(measured.ApiRevision).IsEqualTo(f.Binding.ApiRevision);
        await Assert.That(measured.NativeRequestId).IsEqualTo("resource-reader");
        await Assert.That(measured.ArmedAt).IsEqualTo(Now);
        await Assert.That(measured.StartedAt).IsEqualTo(Now);
        await Assert.That(measured.FinishedAt).IsEqualTo(Now);
        await Assert.That(measured.AsyncSettlementProven || measured.PrincipalQualified || measured.EgressQualified).IsFalse();
        await Assert.That(f.Backend.Requests.Single()).IsEqualTo("GET " + Origin + f.Path + "?api-version=" + f.Binding.ApiRevision);
        await Assert.That(f.Backend.Authorization).IsEqualTo("Bearer independent-resource-reader");
        await Assert.That(f.Credential.Scopes.Single()).IsEqualTo(Origin + "/.default");
        await Cleared(f);
    }

    [Test]
    [Arguments("status.Pending")]
    [Arguments("status.Succeeded")]
    [Arguments("status.Failed")]
    [Arguments("status.Canceled")]
    [Arguments("status.Unknown")]
    public async Task RequestedStatusVariantDoesNotProjectIntoResourceState(string variant)
    {
        using var f = new Fixture(variant: variant);
        f.Body = f.Body.Replace("Succeeded", "Updating", StringComparison.Ordinal);
        using var result = await f.Read();
        await Assert.That(result.NativeState).IsEqualTo("Updating");
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.PersistedStateEligible).IsFalse();
        await Assert.That(result.AsyncSettlementProven).IsFalse();
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    public async Task OriginalCaseLabelsDoNotDetermineIndependentObserverAuthorityOrOutcome(string selection)
    {
        using var f = new Fixture();
        var body = JsonNode.Parse(f.Body)!;
        body["tags"] = new JsonObject { ["secretkit-fixture"] = f.Binding.Selector.Nonce.ToString("N") };
        body["properties"]!["privateEndpointConnections"] = new JsonArray();
        f.Body = body.ToJsonString();
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = selection } };
        using var result = await f.Collector.CollectAsync(f.Collector.Arm(binding), binding);
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Binding.Selector.Case).IsEqualTo(selection);
        await Assert.That(result.PrincipalQualified || result.EgressQualified || result.AsyncSettlementProven).IsFalse();
    }

    [Test]
    [Arguments("missing-tags")]
    [Arguments("foreign-tags")]
    [Arguments("missing-relationships")]
    [Arguments("nonempty-relationships")]
    public async Task UpdateCancellationCollectorRequiresFullOwnedResourceDespitePlausibleNativeConfiguration(string fault)
    {
        using var f = new Fixture();
        var body = JsonNode.Parse(f.Body)!;
        body["tags"] = new JsonObject { ["secretkit-fixture"] = f.Binding.Selector.Nonce.ToString("N") };
        body["properties"]!["privateEndpointConnections"] = new JsonArray();
        if (fault == "missing-tags") body.AsObject().Remove("tags");
        else if (fault == "foreign-tags") body["tags"]!["secretkit-fixture"] = "foreign";
        else if (fault == "missing-relationships") body["properties"]!.AsObject().Remove("privateEndpointConnections");
        else body["properties"]!["privateEndpointConnections"]!.AsArray()
            .Add(new JsonObject { ["id"] = Vault + "/privateEndpointConnections/foreign" });
        f.Body = body.ToJsonString();
        var binding = f.Binding with { Selector = f.Binding.Selector with { Case = "cancellation-boundary" } };
        using var result = await f.Collector.CollectAsync(f.Collector.Arm(binding), binding);
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.PersistedStateEligible || result.PrincipalQualified ||
            result.EgressQualified || result.AsyncSettlementProven).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Cleared(f);
    }

    [Test]
    [Arguments("CreateOrUpdateVault")]
    [Arguments("RecoverVault")]
    public async Task ExactVaultConfigurationComesFromNativeReader(string operation)
    {
        using var f = new Fixture(operation);
        using var result = await f.Read();
        var configuration = result.VaultConfiguration ?? throw new InvalidOperationException("test-missing-configuration");
        await Assert.That(configuration.Location).IsEqualTo("eastus");
        await Assert.That(configuration.TenantId).IsEqualTo(Guid.Parse(Tenant));
        await Assert.That(configuration.Sku).IsEqualTo(VaultSku.Standard);
        await Assert.That(configuration.Rbac && configuration.PublicNetworkAccess).IsTrue();
        await Assert.That(configuration.PurgeProtection).IsFalse();
        await Assert.That(configuration.RetentionDays).IsEqualTo(7);
        await Assert.That(configuration.Policies.Length).IsEqualTo(0);
        await Assert.That(result.PersistedStateEligible).IsTrue();
    }

    [Test]
    [Arguments("enableSoftDelete", "null")]
    [Arguments("enablePurgeProtection", "null")]
    [Arguments("publicNetworkAccess", "\"future-network\"")]
    [Arguments("softDeleteRetentionInDays", "0")]
    [Arguments("provisioningState", "\"future-state\"")]
    public async Task MissingOrUnknownVaultFieldsNeverBecomeDefaults(string field, string value)
    {
        using var f = new Fixture();
        using var doc = JsonDocument.Parse(f.Body);
        var properties = doc.RootElement.GetProperty("properties").EnumerateObject()
            .ToDictionary(p => p.Name, p => p.Value.Clone());
        using var replacement = JsonDocument.Parse(value);
        properties[field] = replacement.RootElement.Clone();
        f.Body = JsonSerializer.Serialize(new { id = Vault, name = "resource-vault", type = "Microsoft.KeyVault/vaults", location = "eastus", properties });
        using var result = await f.Read();
        await Assert.That(result.PersistedStateEligible).IsFalse();
        if (field != "provisioningState") await Assert.That(result.VaultConfiguration).IsNull();
    }

    [Test]
    [Arguments("Pending")]
    [Arguments("Approved")]
    [Arguments("Rejected")]
    [Arguments("Disconnected")]
    [Arguments("new-status")]
    public async Task PrivateConnectionStateIsExactAndUnknownStaysIneligible(string state)
    {
        using var f = new Fixture("UpdatePrivateConnection");
        f.Body = f.Body.Replace("\"Approved\"", JsonSerializer.Serialize(state), StringComparison.Ordinal);
        using var result = await f.Read();
        await Assert.That(result.ConnectionState).IsEqualTo(state == "new-status" ? null : Enum.Parse<PrivateConnectionState>(state));
        await Assert.That(result.PersistedStateEligible).IsEqualTo(state != "new-status");
    }

    [Test]
    public async Task NotificationConfigurationUsesOneResponseAndEmptyFiltersAreUnrestricted()
    {
        using var f = new Fixture("UpdateNotification");
        using var result = await f.Read();
        var configuration = result.NotificationConfiguration ?? throw new InvalidOperationException("test-missing-configuration");
        await Assert.That(configuration.Endpoint.Reveal()).IsEqualTo("https://delivery.invalid/" + Protected);
        await Assert.That(configuration.Events.Single()).IsEqualTo(VaultNotificationEvent.SecretNewVersionCreated);
        await Assert.That(configuration.Attributes.Count).IsEqualTo(0);
        await Assert.That(result.PersistedStateEligible).IsTrue();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("event")]
    [Arguments("filter")]
    [Arguments("hidden")]
    [Arguments("masked")]
    [Arguments("attributes-omitted")]
    [Arguments("destination")]
    public async Task NativeEventsAndUnrepresentableConfigurationAreNotFabricated(string change)
    {
        using var f = new Fixture("CreateOrUpdateNotification");
        f.Body = change switch
        {
            "event" => f.Body.Replace("Microsoft.KeyVault.SecretNewVersionCreated", "Microsoft.KeyVault.CertificateNewVersionCreated", StringComparison.Ordinal),
            "filter" => f.Body.Replace("\"advancedFilters\":[]", "\"advancedFilters\":[{\"operatorType\":\"StringIn\",\"key\":\"data.name\",\"values\":[\"selected\"]}]", StringComparison.Ordinal),
            "hidden" => f.Body.Replace("\"endpointUrl\"", "\"endpointBaseUrl\"", StringComparison.Ordinal),
            "masked" => f.Body.Replace("https://delivery.invalid/" + Protected, "https://delivery.invalid/*****", StringComparison.Ordinal),
            "attributes-omitted" => f.Body.Replace(",\"deliveryAttributeMappings\":[]", "", StringComparison.Ordinal),
            _ => f.Body.Replace("\"WebHook\"", "\"FutureDestination\"", StringComparison.Ordinal)
        };
        using var result = await f.Read();
        await Assert.That(result.NotificationConfiguration).IsNull();
        await Assert.That(result.PersistedStateEligible).IsFalse();
        if (change == "event")
        {
            await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Success);
            await Assert.That(result.EventTypes.Single()).IsEqualTo("Microsoft.KeyVault.CertificateNewVersionCreated");
        }
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments(404, "Absent")]
    [Arguments(401, "Denied")]
    [Arguments(403, "Denied")]
    [Arguments(409, "Unavailable")]
    [Arguments(429, "Unavailable")]
    [Arguments(500, "Unavailable")]
    public async Task ConcreteNativeErrorsHaveResourceMeaningNotSettlement(int status, string expected)
    {
        using var f = new Fixture("DeleteVault");
        f.Status = status;
        f.Body = """{"error":{"code":"ResourceNotFound","message":"resource-private-material"}}""";
        using var result = await f.Read();
        await Assert.That(result.ResourceStatus).IsEqualTo(Enum.Parse<SecretStatus>(expected));
        await Assert.That(result.AsyncSettlementProven).IsFalse();
        await Assert.That(result.PersistedStateEligible).IsFalse();
        await Assert.That(result.VaultConfiguration).IsNull();
        await Cleared(f);
    }

    [Test]
    [Arguments("CreateOrUpdateVault")]
    [Arguments("RecoverVault")]
    [Arguments("DeleteVault")]
    [Arguments("PurgeDeletedVault")]
    [Arguments("UpdatePrivateConnection")]
    [Arguments("DeletePrivateConnection")]
    [Arguments("DeleteRoleAssignment")]
    [Arguments("CreateOrUpdateNotification")]
    [Arguments("UpdateNotification")]
    [Arguments("DeleteNotification")]
    public async Task EachConcreteTypedResourceCanBeAbsentWithoutAnyOperationSettlement(string operation)
    {
        using var f = new Fixture(operation);
        f.Status = 404;
        f.Body = """{"error":{"code":"ResourceNotFound","message":"resource-private-material","details":[]}}""";
        using var result = await f.Read();
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.ResourceAbsent).IsTrue();
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(result.AsyncSettlementProven).IsFalse();
        await Assert.That(result.ResourceId).IsNull();
        await Assert.That(result.Binding.Resource).IsEqualTo(f.Binding.Resource);
        await Assert.That(result.ApiRevision).IsEqualTo(f.Binding.ApiRevision);
        await Cleared(f);
    }

    [Test]
    [Arguments("PurgeDeletedVault", "id")]
    [Arguments("PurgeDeletedVault", "original")]
    [Arguments("PurgeDeletedVault", "region")]
    [Arguments("UpdatePrivateConnection", "id")]
    [Arguments("UpdatePrivateConnection", "type")]
    [Arguments("DeleteRoleAssignment", "scope")]
    [Arguments("DeleteRoleAssignment", "definition")]
    [Arguments("DeleteRoleAssignment", "principal")]
    [Arguments("UpdateNotification", "topic")]
    [Arguments("UpdateNotification", "name")]
    public async Task FamilySpecificForeignIdentitiesNeverMaterializeAsSelectedResources(string operation, string field)
    {
        using var f = new Fixture(operation);
        f.Body = field switch
        {
            "id" => f.Body.Replace("\"id\":\"" + f.Path + "\"", "\"id\":\"" + f.Path + "-foreign\"", StringComparison.Ordinal),
            "original" => f.Body.Replace("\"vaultId\":\"" + Vault + "\"", "\"vaultId\":\"" + Vault + "-foreign\"", StringComparison.Ordinal),
            "region" => f.Body.Replace("\"location\":\"eastus\"", "\"location\":\"westus\"", StringComparison.Ordinal),
            "type" => f.Body.Replace("\"type\":\"Microsoft.KeyVault/vaults/privateEndpointConnections\"", "\"type\":\"Microsoft.KeyVault/vaults\"", StringComparison.Ordinal),
            "scope" => f.Body.Replace("\"scope\":\"" + Vault + "\"", "\"scope\":\"" + Vault + "-foreign\"", StringComparison.Ordinal),
            "definition" => f.Body.Replace("\"roleDefinitionId\":\"/subscriptions/" + Subscription,
                "\"roleDefinitionId\":\"/subscriptions/" + Tenant, StringComparison.Ordinal),
            "principal" => f.Body.Replace("\"principalId\":\"" + Tenant + "\"", "\"principalId\":\"00000000-0000-0000-0000-000000000000\"", StringComparison.Ordinal),
            "topic" => f.Body.Replace("\"topic\":\"" + Vault + "\"", "\"topic\":\"" + Vault + "-foreign\"", StringComparison.Ordinal),
            _ => f.Body.Replace("\"name\":\"resource-notification\"", "\"name\":\"foreign\"", StringComparison.Ordinal)
        };
        using var result = await f.Read();
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.PersistedStateEligible).IsFalse();
        await Assert.That(result.ResourceId).IsNull();
    }

    [Test]
    [Arguments("vault")]
    [Arguments("group")]
    [Arguments("subscription")]
    public async Task RoleAssignmentParentIsPreservedAtEachSupportedScope(string kind)
    {
        using var f = new Fixture("DeleteRoleAssignment");
        var vault = (VaultScope)((RoleAssignmentScope)f.Binding.Resource).Parent;
        ManagementScope parent = kind switch { "group" => vault.ResourceGroup, "subscription" => vault.ResourceGroup.Subscription, _ => vault };
        string parentId = kind switch
        {
            "group" => "/subscriptions/" + Subscription + "/resourceGroups/resource-group",
            "subscription" => "/subscriptions/" + Subscription,
            _ => Vault
        };
        var binding = f.Binding with { Resource = new RoleAssignmentScope(parent, Guid.Parse(Assignment)) };
        f.Body = f.Body.Replace(Vault, parentId, StringComparison.Ordinal);
        using var result = await f.Collector.CollectAsync(f.Collector.Arm(binding), binding);
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.RoleAssignment!.Scope).IsEqualTo(parentId);
        await Assert.That(result.RoleAssignment.PrincipalId).IsEqualTo(Guid.Parse(Tenant));
        await Assert.That(result.RoleAssignment.PrincipalType).IsEqualTo("ServicePrincipal");
        await Assert.That(result.PrincipalQualified).IsFalse();
        await Assert.That(f.Backend.Requests.Single()).IsEqualTo("GET " + Origin + parentId +
            "/providers/Microsoft.Authorization/roleAssignments/" + Assignment + "?api-version=2022-04-01");
    }

    [Test]
    public async Task DeletedVaultNativeMetadataIsNotActiveVaultConfiguration()
    {
        using var f = new Fixture("PurgeDeletedVault");
        using var result = await f.Read();
        await Assert.That(result.DeletedVault!.OriginalResourceId).IsEqualTo(Vault);
        await Assert.That(result.DeletedVault.DeletedOn).IsEqualTo(Now.AddDays(-1));
        await Assert.That(result.DeletedVault.ScheduledPurgeOn).IsEqualTo(Now.AddDays(6));
        await Assert.That(result.DeletedVault.PurgeProtected).IsFalse();
        await Assert.That(result.VaultConfiguration).IsNull();
        await Assert.That(result.AsyncSettlementProven).IsFalse();
    }

    [Test]
    [Arguments("keys")]
    [Arguments("unknown-secret")]
    [Arguments("hidden")]
    [Arguments("foreign-tenant")]
    public async Task AccessPoliciesDoNotSilentlyDropUnsupportedPermissions(string change)
    {
        using var f = new Fixture();
        string permissions = change switch
        {
            "keys" => "\"secrets\":[\"get\"],\"keys\":[\"decrypt\"]",
            "unknown-secret" => "\"secrets\":[\"future-permission\"]",
            "hidden" => "\"keys\":[]",
            _ => "\"secrets\":[\"get\"]"
        };
        string policyTenant = change == "foreign-tenant" ? Assignment : Tenant;
        f.Body = f.Body.Replace("\"accessPolicies\":[]",
            "\"accessPolicies\":[{\"tenantId\":\"" + policyTenant + "\",\"objectId\":\"" + Assignment +
            "\",\"permissions\":{" + permissions + "}}]", StringComparison.Ordinal);
        using var result = await f.Read();
        await Assert.That(result.VaultConfiguration).IsNull();
        await Assert.That(result.PersistedStateEligible).IsFalse();
    }

    [Test]
    [Arguments("Static", false)]
    [Arguments("Static", true)]
    [Arguments("Dynamic", false)]
    public async Task CompleteAttributesAreTakenOnlyFromTheSameNativeResponse(string kind, bool secret)
    {
        using var f = new Fixture("UpdateNotification");
        string properties = kind == "Static"
            ? "\"value\":\"" + Protected + "\",\"isSecret\":" + (secret ? "true" : "false")
            : "\"sourceField\":\"data.name\"";
        f.Body = f.Body.Replace("\"deliveryAttributeMappings\":[]",
            "\"deliveryAttributeMappings\":[{\"name\":\"x-resource\",\"type\":\"" + kind + "\",\"properties\":{" + properties + "}}]",
            StringComparison.Ordinal);
        using var result = await f.Read();
        var attribute = result.NotificationConfiguration!.Attributes.Single();
        await Assert.That(attribute.Name).IsEqualTo("x-resource");
        await Assert.That(attribute.Kind).IsEqualTo(Enum.Parse<NotificationAttributeKind>(kind));
        await Assert.That(attribute.IsSecret).IsEqualTo(secret);
        await Assert.That(attribute.Value.Reveal()).IsEqualTo(kind == "Static" ? Protected : "data.name");
        await Assert.That(JsonSerializer.Serialize(attribute)).IsEqualTo("{}");
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("null-value")]
    [Arguments("omitted-value")]
    [Arguments("masked-value")]
    [Arguments("null-flag")]
    [Arguments("omitted-flag")]
    [Arguments("unknown-kind")]
    public async Task HiddenDeliveryAttributesDoNotAcquireInventedValuesOrSecretFlags(string change)
    {
        using var f = new Fixture("UpdateNotification");
        string properties = change switch
        {
            "null-value" => "\"value\":null,\"isSecret\":true",
            "omitted-value" => "\"isSecret\":true",
            "masked-value" => "\"value\":\"*****\",\"isSecret\":true",
            "null-flag" => "\"value\":\"" + Protected + "\",\"isSecret\":null",
            "omitted-flag" => "\"value\":\"" + Protected + "\"",
            _ => "\"value\":\"" + Protected + "\",\"isSecret\":true"
        };
        f.Body = f.Body.Replace("\"deliveryAttributeMappings\":[]",
            "\"deliveryAttributeMappings\":[{\"name\":\"x-resource\",\"type\":\"" + (change == "unknown-kind" ? "Future" : "Static") +
            "\",\"properties\":{" + properties + "}}]", StringComparison.Ordinal);
        using var result = await f.Read();
        await Assert.That(result.NotificationConfiguration).IsNull();
        await Assert.That(result.PersistedStateEligible).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("empty-404")]
    [Arguments("success-404")]
    [Arguments("malformed")]
    [Arguments("error-200")]
    [Arguments("partial")]
    [Arguments("duplicate")]
    [Arguments("case")]
    [Arguments("id")]
    [Arguments("name")]
    [Arguments("type")]
    [Arguments("tenant")]
    [Arguments("region")]
    [Arguments("range")]
    [Arguments("encoding")]
    [Arguments("length")]
    [Arguments("redirect")]
    [Arguments("continuation")]
    [Arguments("header-budget")]
    [Arguments("bytes")]
    [Arguments("depth")]
    [Arguments("nodes")]
    [Arguments("row")]
    public async Task AmbiguousPartialForeignAndUnboundedRepliesFailClosed(string change)
    {
        using var f = new Fixture();
        switch (change)
        {
            case "empty-404": f.Status = 404; f.Body = ""; break;
            case "success-404": f.Status = 404; break;
            case "malformed": f.Body = "{"; break;
            case "error-200": f.Body = """{"error":{"code":"Denied"}}"""; break;
            case "partial": f.Body = f.Body.Insert(1, "\"partial\":true,"); break;
            case "duplicate": f.Body = f.Body.Insert(1, "\"ID\":\"" + Vault + "\","); break;
            case "case": f.Body = f.Body.Replace("\"tenantId\"", "\"TenantId\"", StringComparison.Ordinal); break;
            case "id": f.Body = f.Body.Replace(Vault, Vault + "-foreign", StringComparison.Ordinal); break;
            case "name": f.Body = f.Body.Replace("\"name\":\"resource-vault\"", "\"name\":\"foreign\"", StringComparison.Ordinal); break;
            case "type": f.Body = f.Body.Replace("\"type\":\"Microsoft.KeyVault/vaults\"", "\"type\":\"Microsoft.KeyVault/other\"", StringComparison.Ordinal); break;
            case "tenant": f.Body = f.Body.Replace(Tenant, Assignment, StringComparison.Ordinal); break;
            case "region": f.Body = f.Body.Replace("eastus", "westus", StringComparison.Ordinal); break;
            case "range": f.Headers.Add(("Content-Range", "bytes 0-10/20")); break;
            case "encoding": f.Headers.Add(("Content-Encoding", "gzip")); break;
            case "length": f.Headers.Add(("Content-Length", "1")); break;
            case "redirect": f.Status = 302; f.Headers.Add(("Location", Origin + f.Path)); break;
            case "continuation": f.Headers.Add(("Azure-AsyncOperation", Origin + f.Path)); break;
            case "header-budget": f.Headers.Add(("x-private", new string('x', 4097))); break;
            case "bytes": f.Body = new string(' ', Bounds.MaximumResponseBytes + 1); break;
            case "depth": f.Body = new string('[', 18) + "0" + new string(']', 18); break;
            case "nodes": f.Body = "[" + string.Join(',', Enumerable.Repeat("0", 5000)) + "]"; break;
            case "row": f.Body = f.Body.Insert(1, "\"padding\":\"" + new string('x', 33000) + "\","); break;
        }
        using var result = await f.Read();
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.ResponseComplete || result.PersistedStateEligible).IsFalse();
        await Assert.That(result.VaultConfiguration).IsNull();
        await Cleared(f);
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("lease")]
    [Arguments("scope")]
    [Arguments("variant")]
    [Arguments("case")]
    [Arguments("operation")]
    [Arguments("resource")]
    [Arguments("revision")]
    [Arguments("location")]
    public async Task EntireOriginalBindingIsComparedBeforeConsumption(string field)
    {
        using var f = new Fixture();
        var window = f.Collector.Arm(f.Binding);
        var b = f.Binding;
        var forged = field switch
        {
            "nonce" => b with { Selector = b.Selector with { Nonce = Guid.NewGuid() } },
            "lease" => b with { LeaseId = Guid.NewGuid() },
            "scope" => b with { Selector = b.Selector with { Scope = "another-original-scope" } },
            "variant" => b with { Selector = b.Selector with { Variant = "status.Pending" } },
            "case" => b with { Selector = b.Selector with { Case = "independent-effect" } },
            "operation" => b with { Operation = ManagementMutation.RecoverVault },
            "resource" => b with { Resource = new VaultScope(new(new(Guid.Parse(Subscription)), "resource-group"), "resource-vault") },
            "revision" => b with { ApiRevision = "2022-04-01" },
            _ => b with { Location = "westus" }
        };
        await Assert.That(async () => { using var ignored = await f.Collector.CollectAsync(window, forged); })
            .Throws<InvalidOperationException>();
        using var actual = await f.Collector.CollectAsync(window, b);
        await Assert.That(actual.ResourceStatus).IsEqualTo(SecretStatus.Success);
    }

    [Test]
    public async Task WindowsArePrivateOwnerBoundOneUseAndRegistrationsAreBounded()
    {
        using var f = new Fixture();
        using var other = new Fixture();
        var window = f.Collector.Arm(f.Binding);
        var forgery = C.Window.Create(f.Binding, Now);
        await Assert.That(async () => { using var ignored = await f.Collector.CollectAsync(forgery, f.Binding); })
            .Throws<InvalidOperationException>();
        await Assert.That(async () => { using var ignored = await other.Collector.CollectAsync(window, f.Binding); })
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Collector.Arm(f.Binding with { LeaseId = Guid.NewGuid() })).Throws<InvalidOperationException>();
        await Assert.That(() => f.Collector.Arm(f.Binding with { Selector = f.Binding.Selector with { Nonce = Guid.NewGuid() } }))
            .Throws<InvalidOperationException>();
        using var result = await f.Collector.CollectAsync(window, f.Binding);
        await Assert.That(async () => { using var ignored = await f.Collector.CollectAsync(window, f.Binding); })
            .Throws<InvalidOperationException>();
        for (int i = 1; i < 32; i++)
            f.Collector.Arm(f.Binding with { LeaseId = Guid.NewGuid(), Selector = f.Binding.Selector with { Nonce = Guid.NewGuid() } });
        await Assert.That(() => f.Collector.Arm(f.Binding with
        {
            LeaseId = Guid.NewGuid(),
            Selector = f.Binding.Selector with { Nonce = Guid.NewGuid() }
        })).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("credential")]
    [Arguments("send")]
    [Arguments("body")]
    public async Task CancellationRetainsActualBorrowedTaskAndStorageUntilReleased(string phase)
    {
        using var f = new Fixture();
        f.Credential.Block = phase == "credential";
        f.Barrier = phase;
        using var cancellation = new CancellationTokenSource();
        var entered = phase == "credential" ? f.Credential.Entered.Task :
            phase == "send" ? f.Backend.SendEntered.Task : f.Backend.BodyEntered.Task;
        var canceled = f.Canceled.Task;
        var task = f.Collector.CollectAsync(f.Collector.Arm(f.Binding), f.Binding, cancellation.Token).AsTask();
        var completedAfterBorrower = task.ContinueWith(_ => f.BorrowerExited.Task.IsCompleted,
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        try
        {
            await entered.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Cancel();
            await canceled.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(task.IsCompleted).IsFalse();
            if (phase == "body")
                await Assert.That(f.Backend.Buffers.Any(b => b.Any(v => v == 0x5a))).IsTrue();
            await Assert.That(f.Credential.Disposed || f.Backend.Disposed).IsFalse();
        }
        finally
        {
            f.Release.TrySetResult();
            // Drain the actual invocation even when an assertion above fails.
            try { using var ignored = await task; }
            catch (OperationCanceledException) { }
        }
        await Assert.That(async () => await task).Throws<OperationCanceledException>();
        await Assert.That(await completedAfterBorrower).IsTrue();
        await Assert.That(f.StorageRetainedAtBorrowerExit).IsTrue();
        await Cleared(f);
    }

    [Test]
    [Arguments("credential")]
    [Arguments("send")]
    [Arguments("body")]
    public async Task InjectedDeadlineAlsoWaitsForActualUncooperativeTaskCompletion(string phase)
    {
        using var f = new Fixture();
        f.Credential.Block = phase == "credential";
        f.Barrier = phase;
        var entered = phase == "credential" ? f.Credential.Entered.Task :
            phase == "send" ? f.Backend.SendEntered.Task : f.Backend.BodyEntered.Task;
        var canceled = f.Canceled.Task;
        var task = f.Collector.CollectAsync(f.Collector.Arm(f.Binding), f.Binding).AsTask();
        var completedAfterBorrower = task.ContinueWith(_ => f.BorrowerExited.Task.IsCompleted,
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        try
        {
            await entered.WaitAsync(TimeSpan.FromSeconds(10));
            f.Clock.Advance(TimeSpan.FromSeconds(21));
            await canceled.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(task.IsCompleted).IsFalse();
            if (phase == "body") await Assert.That(f.Backend.Buffers.Any(b => b.Any(v => v == 0x5a))).IsTrue();
        }
        finally
        {
            f.Release.TrySetResult();
            using var ignored = await task;
        }
        using var result = await task;
        await Assert.That(await completedAfterBorrower).IsTrue();
        await Assert.That(f.StorageRetainedAtBorrowerExit).IsTrue();
        await Assert.That(result.Failure).IsEqualTo(C.Failure.Deadline);
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Unavailable);
        await Cleared(f);
    }

    [Test]
    [Arguments("credential")]
    [Arguments("send")]
    [Arguments("body")]
    public async Task ProtectedExceptionsAreSanitizedAndOwnedStorageIsCleared(string phase)
    {
        using var f = new Fixture();
        f.Throw = phase;
        using var result = await f.Read();
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.VaultConfiguration).IsNull();
        await Assert.That(result.ToString().Contains(Protected, StringComparison.Ordinal)).IsFalse();
        await Cleared(f);
    }

    [Test]
    [Arguments("host")]
    [Arguments("headers")]
    [Arguments("body")]
    [Arguments("uri")]
    public async Task BoundRequestIsCheckedBeforeTransportDispatch(string change)
    {
        using var f = new Fixture();
        f.Credential.BeforeReturn = () =>
        {
            var request = f.Backend.LastRequest ?? throw new InvalidOperationException("test-no-request");
            switch (change)
            {
                case "host": request.Headers.SetValue("Host", "foreign.invalid"); break;
                case "headers": request.Headers.SetValue("x-private", new string('x', 4097)); break;
                case "body": request.Content = RequestContent.Create(Encoding.UTF8.GetBytes("{}")); break;
                case "uri": request.Uri.Reset(new Uri("https://foreign.invalid/" + Protected)); break;
            }
        };
        using var result = await f.Read();
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task NativeObjectRowBudgetIsAppliedBeforeMaterialization()
    {
        using var f = new Fixture();
        f.Body = f.Body.Insert(1, "\"padding\":[" + string.Join(',', Enumerable.Repeat("{}", 257)) + "],");
        using var result = await f.Read();
        await Assert.That(result.Failure).IsEqualTo(C.Failure.Budget);
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Unavailable);
        await Cleared(f);
    }

    [Test]
    [Arguments("variant")]
    [Arguments("revision")]
    [Arguments("type")]
    [Arguments("operation")]
    [Arguments("nonce")]
    [Arguments("lease")]
    [Arguments("empty-scope")]
    public async Task InvalidRegistrationDoesNotDispatchOrReserveAnOtherwiseValidBinding(string change)
    {
        using var f = new Fixture();
        var binding = change switch
        {
            "variant" => f.Binding with { Selector = f.Binding.Selector with { Variant = "operation.DeleteVault" } },
            "revision" => f.Binding with { ApiRevision = "2025-02-15" },
            "type" => f.Binding with { Resource = new SubscriptionScope(Guid.Parse(Subscription)) },
            "operation" => f.Binding with { Operation = ManagementMutation.DeleteNotification },
            "nonce" => f.Binding with { Selector = f.Binding.Selector with { Nonce = Guid.Empty } },
            "lease" => f.Binding with { LeaseId = Guid.Empty },
            _ => f.Binding with { Selector = f.Binding.Selector with { Scope = "" } }
        };
        await Assert.That(() => f.Collector.Arm(binding)).Throws<ArgumentException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        using var actual = await f.Read();
        await Assert.That(actual.ResourceStatus).IsEqualTo(SecretStatus.Success);
    }

    [Test]
    [Arguments("wall-expired")]
    [Arguments("monotonic-expired")]
    [Arguments("wall-rollback")]
    [Arguments("monotonic-rollback")]
    [Arguments("credential-expired")]
    [Arguments("send-expired")]
    public async Task InjectedWallAndMonotonicTimeFailClosedBeforeNextBoundary(string change)
    {
        using var f = new Fixture();
        var window = f.Collector.Arm(f.Binding);
        switch (change)
        {
            case "wall-expired": f.Clock.WallTicks = TimeSpan.FromSeconds(21).Ticks; break;
            case "monotonic-expired": f.Clock.Ticks = TimeSpan.FromSeconds(21).Ticks; break;
            case "wall-rollback": f.Clock.WallTicks = -1; break;
            case "monotonic-rollback": f.Clock.Ticks = -1; break;
            case "credential-expired": f.Credential.BeforeReturn = () => f.Clock.WallTicks = TimeSpan.FromSeconds(21).Ticks; break;
            case "send-expired": f.Backend.BeforeReturn = () => f.Clock.WallTicks = TimeSpan.FromSeconds(21).Ticks; break;
        }
        using var result = await f.Collector.CollectAsync(window, f.Binding);
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.PersistedStateEligible).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(change == "send-expired" ? 1 : 0);
        await Cleared(f);
    }

    [Test]
    public async Task DefaultFormattingJsonAndExceptionsRedactMaterialAndCoordinates()
    {
        using var f = new Fixture("UpdateNotification");
        var window = f.Collector.Arm(f.Binding);
        using var result = await f.Collector.CollectAsync(window, f.Binding);
        object[] values = [f.Collector, window, f.Binding, result,
            result.NotificationConfiguration!, new C.Authority(Protected, f.Credential, f.Backend)];
        foreach (var value in values)
        {
            await Assert.That(JsonSerializer.Serialize(value)).IsEqualTo("{}");
            await Assert.That(value.ToString()!.Contains(Protected, StringComparison.Ordinal)).IsFalse();
            await Assert.That(value.ToString()!.Contains(Subscription, StringComparison.Ordinal)).IsFalse();
            await Assert.That(value.ToString()!.Contains("https://", StringComparison.Ordinal)).IsFalse();
        }
        ArgumentException? failure = null;
        try { f.Collector.Arm(f.Binding with { ApiRevision = Protected }); }
        catch (ArgumentException exception) { failure = exception; }
        await Assert.That(failure).IsNotNull();
        await Assert.That(failure!.ToString().Contains(Protected, StringComparison.Ordinal)).IsFalse();
        await Assert.That(failure.ToString().Contains(Subscription, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task DisposingOwnedConfigurationDoesNotClaimToEraseOrdinaryManagedStrings()
    {
        using var f = new Fixture("UpdateNotification");
        using var result = await f.Read();
        var endpoint = result.NotificationConfiguration!.Endpoint;
        string ordinary = endpoint.Reveal();
        result.Dispose();
        await Assert.That(() => endpoint.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(ordinary).IsEqualTo("https://delivery.invalid/" + Protected);
        await Cleared(f);
    }

    [Test]
    public async Task PreCanceledCollectionConsumesItsWindowWithoutUsingBorrowedAuthority()
    {
        using var f = new Fixture();
        var window = f.Collector.Arm(f.Binding);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.That(async () => { using var ignored = await f.Collector.CollectAsync(window, f.Binding, cancellation.Token); })
            .Throws<OperationCanceledException>();
        await Assert.That(f.Credential.Scopes.Count).IsEqualTo(0);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        await Assert.That(async () => { using var ignored = await f.Collector.CollectAsync(window, f.Binding); })
            .Throws<InvalidOperationException>();
    }

    private static async Task Cleared(Fixture f)
    {
        await Assert.That(f.Backend.Buffers.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(f.Backend.Disposed || f.Credential.Disposed).IsFalse();
    }

    private sealed class Fixture : IDisposable
    {
        internal readonly Credential Credential;
        internal readonly Backend Backend;
        internal readonly C Collector;
        internal readonly Capture.Binding Binding;
        internal readonly Clock Clock = new();
        internal readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Canceled = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource BorrowerExited = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool StorageRetainedAtBorrowerExit = true;
        internal readonly List<(string, string)> Headers = [];
        internal string Path, Body, Barrier = "", Throw = "";
        internal int Status = 200;
        internal Fixture(string operation = "CreateOrUpdateVault", string? variant = null, string boundary = "selected-contract")
        {
            var mutation = Enum.Parse<ManagementMutation>(operation);
            var vault = new VaultScope(new(new(Guid.Parse(Subscription)), "resource-group"), "resource-vault");
            ManagementScope scope = mutation switch
            {
                ManagementMutation.PurgeDeletedVault => new DeletedVaultScope(vault.ResourceGroup.Subscription, "eastus", vault.VaultName),
                ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection => new PrivateConnectionScope(vault, "resource-connection"),
                ManagementMutation.DeleteRoleAssignment => new RoleAssignmentScope(vault, Guid.Parse(Assignment)),
                ManagementMutation.CreateOrUpdateNotification or ManagementMutation.UpdateNotification or ManagementMutation.DeleteNotification =>
                    new NotificationScope(vault, "resource-notification"),
                _ => vault
            };
            Path = scope switch
            {
                DeletedVaultScope => "/subscriptions/" + Subscription + "/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/resource-vault",
                PrivateConnectionScope => Vault + "/privateEndpointConnections/resource-connection",
                RoleAssignmentScope => Vault + "/providers/Microsoft.Authorization/roleAssignments/" + Assignment,
                NotificationScope => Vault + "/providers/Microsoft.EventGrid/eventSubscriptions/resource-notification",
                _ => Vault
            };
            Binding = new(new(Guid.NewGuid(), "original-controlled-scope", ManagementOperationEffects.Members[0].Operation,
                variant ?? "operation." + operation, boundary), Guid.NewGuid(), scope, mutation, "eastus",
                scope is NotificationScope ? "2025-02-15" : scope is RoleAssignmentScope ? "2022-04-01" : "2026-02-01");
            Body = scope switch
            {
                DeletedVaultScope => JsonSerializer.Serialize(new
                {
                    id = Path,
                    name = "resource-vault",
                    type = "Microsoft.KeyVault/locations/deletedVaults",
                    properties = new { location = "eastus", vaultId = Vault, deletionDate = "2026-10-14T00:00:00Z", scheduledPurgeDate = "2026-10-21T00:00:00Z", purgeProtectionEnabled = false }
                }),
                PrivateConnectionScope => JsonSerializer.Serialize(new
                {
                    id = Path,
                    name = "resource-connection",
                    type = "Microsoft.KeyVault/vaults/privateEndpointConnections",
                    properties = new { provisioningState = "Succeeded", privateLinkServiceConnectionState = new { status = "Approved" }, privateEndpoint = new { id = Endpoint } }
                }),
                RoleAssignmentScope => JsonSerializer.Serialize(new
                {
                    id = Path,
                    name = Assignment,
                    type = "Microsoft.Authorization/roleAssignments",
                    properties = new
                    {
                        scope = Vault,
                        principalId = Tenant,
                        principalType = "ServicePrincipal",
                        roleDefinitionId = "/subscriptions/" + Subscription + "/providers/Microsoft.Authorization/roleDefinitions/" + Assignment
                    }
                }),
                NotificationScope => JsonSerializer.Serialize(new
                {
                    id = Path,
                    name = "resource-notification",
                    type = "Microsoft.EventGrid/eventSubscriptions",
                    properties = new
                    {
                        topic = Vault,
                        provisioningState = "Succeeded",
                        filter = new { includedEventTypes = new[] { "Microsoft.KeyVault.SecretNewVersionCreated" }, advancedFilters = Array.Empty<object>() },
                        destination = new { endpointType = "WebHook", properties = new { endpointUrl = "https://delivery.invalid/" + Protected, deliveryAttributeMappings = Array.Empty<object>() } }
                    }
                }),
                _ => JsonSerializer.Serialize(new
                {
                    id = Vault,
                    name = "resource-vault",
                    type = "Microsoft.KeyVault/vaults",
                    location = "eastus",
                    properties = new
                    {
                        tenantId = Tenant,
                        sku = new { family = "A", name = "standard" },
                        vaultUri = "https://resource-vault.vault.azure.net/",
                        provisioningState = "Succeeded",
                        enableRbacAuthorization = true,
                        enablePurgeProtection = false,
                        enableSoftDelete = true,
                        softDeleteRetentionInDays = 7,
                        publicNetworkAccess = "Enabled",
                        accessPolicies = Array.Empty<object>()
                    }
                })
            };
            Credential = new(this);
            Backend = new(this);
            Collector = new(new("host-owned-observer", Credential, Backend), Bounds, Clock, Guid.Parse(Tenant));
        }
        internal ValueTask<C.Measurement> Read() => Collector.CollectAsync(Collector.Arm(Binding), Binding);
        internal async Task AwaitBorrowerRelease()
        {
            try { await Release.Task.ConfigureAwait(false); }
            finally
            {
                if (Barrier == "body")
                    StorageRetainedAtBorrowerExit = Backend.Buffers.Any(b => b.Any(v => v == 0x5a));
                BorrowerExited.TrySetResult();
            }
        }
        public void Dispose() { Backend.Dispose(); Credential.Dispose(); }
    }

    private sealed class Credential(Fixture fixture) : TokenCredential, IDisposable
    {
        internal readonly List<string> Scopes = [];
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Block, Disposed;
        internal Action? BeforeReturn;
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("test-async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken)
        {
            Scopes.AddRange(context.Scopes);
            using var registration = cancellationToken.Register(() => fixture.Canceled.TrySetResult());
            Entered.TrySetResult();
            if (Block) await fixture.AwaitBorrowerRelease().ConfigureAwait(false);
            BeforeReturn?.Invoke();
            if (fixture.Throw == "credential") throw new InvalidOperationException(Protected);
            cancellationToken.ThrowIfCancellationRequested();
            return new("independent-resource-reader", DateTimeOffset.MaxValue);
        }
        public void Dispose() => Disposed = true;
    }

    private sealed class Backend : HttpPipelineTransport, IDisposable
    {
        private readonly HttpClient client;
        private readonly HttpClientTransport transport;
        internal readonly List<string> Requests = [];
        internal readonly List<byte[]> Buffers = [];
        internal readonly TaskCompletionSource SendEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource BodyEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Disposed;
        internal string? Authorization;
        internal Request? LastRequest;
        internal Action? BeforeReturn;
        internal Backend(Fixture f)
        {
            client = new(new Handler(async (request, token) =>
            {
                Requests.Add(request.Method + " " + request.RequestUri!.AbsoluteUri);
                Authorization = request.Headers.Authorization?.ToString();
                if (request.Content is not null) throw new InvalidOperationException("test-unexpected-request-body");
                using var registration = token.Register(() => f.Canceled.TrySetResult());
                SendEntered.TrySetResult();
                if (f.Barrier == "send") await f.AwaitBorrowerRelease().ConfigureAwait(false);
                BeforeReturn?.Invoke();
                if (f.Throw == "send") throw new InvalidOperationException(Protected);
                var response = new HttpResponseMessage((HttpStatusCode)f.Status)
                {
                    Content = new StreamContent(new BodyStream(Encoding.UTF8.GetBytes(f.Body), this, f, token))
                };
                response.Content.Headers.ContentType = new("application/json");
                response.Headers.TryAddWithoutValidation("x-ms-request-id", "resource-reader");
                foreach (var (name, value) in f.Headers)
                    if (name.StartsWith("Content-", StringComparison.OrdinalIgnoreCase)) response.Content.Headers.TryAddWithoutValidation(name, value);
                    else response.Headers.TryAddWithoutValidation(name, value);
                return response;
            }));
            transport = new(client);
        }
        public override Request CreateRequest() => LastRequest = transport.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("test-async-only");
        public override ValueTask ProcessAsync(HttpMessage message) => transport.ProcessAsync(message);
        public void Dispose() { Disposed = true; client.Dispose(); }
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
    }

    // Composition deliberately intercepts both async overloads; MemoryStream's
    // special optimized paths cannot bypass the exact ingress barrier.
    private sealed class BodyStream(byte[] bytes, Backend backend, Fixture f, CancellationToken actualToken) : Stream
    {
        private readonly MemoryStream input = new(bytes, false);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => input.Length;
        public override long Position { get => input.Position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException("test-async-only");
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment) && segment.Array is { } storage)
                backend.Buffers.Add(storage);
            if (f.Barrier == "body")
            {
                buffer.Span.Fill(0x5a);
                using var a = actualToken.Register(() => f.Canceled.TrySetResult());
                using var b = cancellationToken.Register(() => f.Canceled.TrySetResult());
                backend.BodyEntered.TrySetResult();
                await f.AwaitBorrowerRelease().ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
            if (f.Throw == "body") throw new InvalidOperationException(Protected);
            return await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        protected override void Dispose(bool disposing) { if (disposing) input.Dispose(); base.Dispose(disposing); }
    }

    private sealed class Clock : TimeProvider
    {
        internal long Ticks, WallTicks;
        private readonly List<Hook> timers = [];
        public override DateTimeOffset GetUtcNow() => Now.AddTicks(WallTicks);
        public override long GetTimestamp() => Ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new Hook(this, callback, state);
            timer.Change(dueTime, period);
            timers.Add(timer);
            return timer;
        }
        internal void Advance(TimeSpan duration)
        {
            Ticks += duration.Ticks;
            WallTicks += duration.Ticks;
            foreach (var timer in timers.ToArray())
                if (timer.Due <= Ticks) { timer.Due = long.MaxValue; timer.Fire(); }
        }
        private sealed class Hook(Clock clock, TimerCallback callback, object? state) : ITimer
        {
            internal long Due;
            internal void Fire() => callback(state);
            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                Due = dueTime == Timeout.InfiniteTimeSpan ? long.MaxValue : clock.Ticks + dueTime.Ticks;
                return true;
            }
            public void Dispose() => Due = long.MaxValue;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
