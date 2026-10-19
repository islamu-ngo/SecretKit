using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureVaultAdministrationCollectorTests
{
    private static readonly Guid Subscription = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Tenant = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid Principal = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly Guid Application = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static string SubscriptionId => $"/subscriptions/{Subscription:D}";
    private static string GroupId => SubscriptionId + "/resourceGroups/collector-group";
    private static string VaultId => GroupId + "/providers/Microsoft.KeyVault/vaults/collector-vault";
    private static string DeletedId => SubscriptionId + "/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/collector-vault";
    private static string ConnectionId => VaultId + "/privateEndpointConnections/connection";
    private static string EndpointId => "/subscriptions/" + Subscription.ToString("D") +
        "/resourceGroups/network-group/providers/Microsoft.Network/privateEndpoints/generated-endpoint";

    [Test]
    [Arguments((int)C.ReadKind.GetPrivateConnection)]
    [Arguments((int)C.ReadKind.ListPrivateConnections)]
    public async Task NativeConnectionCoordinatesSurviveReadAndCompleteInventory(int kind)
    {
        using var f = new Fixture();
        f.Backend.ConnectionEndpointId = EndpointId;
        var result = await f.Collect(Binding((C.ReadKind)kind));
        await Assert.That(result.ResponseComplete).IsTrue();
        var row = result.Connections.Single();
        await Assert.That(row.ResourceId).IsEqualTo(ConnectionId);
        await Assert.That(row.PrivateEndpointId).IsEqualTo(EndpointId);
        await Assert.That(row.State).IsEqualTo(PrivateConnectionState.Approved);
        await Assert.That(JsonSerializer.Serialize(row)).IsEqualTo("{}");
        await Assert.That(row.ToString().Contains(EndpointId, StringComparison.Ordinal)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments((int)C.ReadKind.GetPrivateConnection)]
    [Arguments((int)C.ReadKind.ListPrivateConnections)]
    public async Task MissingNativeEndpointCannotBeDerivedFromTheConnectionName(int kind)
    {
        using var f = new Fixture();
        var result = await f.Collect(Binding((C.ReadKind)kind));
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.Connections.Single().ResourceId).IsEqualTo(ConnectionId);
        await Assert.That(result.Connections.Single().PrivateEndpointId).IsNull();
    }

    [Test]
    public async Task InventoryPreservesDifferentEndpointAsMetadataWithoutReplacingItWithRequestedCoordinates()
    {
        using var f = new Fixture();
        string foreign = EndpointId.Replace(Subscription.ToString("D"), Tenant.ToString("D"), StringComparison.Ordinal);
        f.Backend.ConnectionEndpointId = foreign;
        var result = await f.Collect(Binding(C.ReadKind.ListPrivateConnections));
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.Connections.Single().PrivateEndpointId).IsEqualTo(foreign);
    }

    [Test]
    [Arguments(403)]
    [Arguments(404)]
    public async Task FailedNativeInventoryCannotPublishConnectionCoordinates(int status)
    {
        using var f = new Fixture();
        f.Backend.ConnectionEndpointId = EndpointId;
        f.Backend.Status = status;
        var result = await f.Collect(Binding(C.ReadKind.ListPrivateConnections));
        await Assert.That(result.Status == SecretStatus.Success).IsFalse();
        await Assert.That(result.Connections.Count).IsEqualTo(0);
    }

    [Test]
    public async Task RetainedCoordinatesCannotTurnTruncatedDiscoveryIntoACompleteInventory()
    {
        using var f = new Fixture(pages: 1);
        f.Backend.ConnectionEndpointId = EndpointId;
        f.Backend.Next = "https://management.azure.com" + VaultId +
            "/privateEndpointConnections?api-version=2026-02-01&$skiptoken=next";
        var result = await f.Collect(Binding(C.ReadKind.ListPrivateConnections));
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.Connections.Single().ResourceId).IsEqualTo(ConnectionId);
        await Assert.That(result.Connections.Single().PrivateEndpointId).IsEqualTo(EndpointId);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task EmptyNativeInventoryCannotInventAGeneratedChildCoordinate()
    {
        using var f = new Fixture();
        f.Backend.ConnectionEndpointId = EndpointId;
        f.Backend.Empty = true;
        var result = await f.Collect(Binding(C.ReadKind.ListPrivateConnections));
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.Connections.Count).IsEqualTo(0);
    }

    private static C.Binding Binding(C.ReadKind read = C.ReadKind.GetVault) => new(
        new(Guid.NewGuid(), "controlled", "a.management.VaultAdministration." + Operation(read),
            read >= C.ReadKind.ListVaultsGroup && read <= C.ReadKind.ListPrivateLinkResources ? "collection.bounded" : "selector.exact",
            "selected-contract"), Guid.NewGuid(), Query(read), read, Subscription,
        "collector-group", "eastus", "collector-vault", "connection");

    private static C.QueryKind Query(C.ReadKind read) => read switch
    {
        C.ReadKind.ListVaultsGroup => C.QueryKind.ListVaultsResourceGroup,
        C.ReadKind.ListVaultsSubscription => C.QueryKind.ListVaultsSubscription,
        _ => Enum.Parse<C.QueryKind>(read.ToString())
    };

    private static string Operation(C.ReadKind read) => read switch
    {
        C.ReadKind.ListVaultsGroup => "ListVaultsAsync.ResourceGroup",
        C.ReadKind.ListVaultsSubscription => "ListVaultsAsync.Subscription",
        _ => read + "Async"
    };

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(6)]
    [Arguments(7)]
    [Arguments(8)]
    public async Task NativeReadsUseIndependentStateAndExactFixedEndpoints(int kind)
    {
        var read = (C.ReadKind)kind;
        using var f = new Fixture();
        var b = Binding(read);
        var result = await f.Collect(b);
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Binding).IsEqualTo(b);
        await Assert.That(result.Identity).IsEqualTo("host-reader");
        await Assert.That(result.ApiRevision).IsEqualTo("2026-02-01");
        await Assert.That(result.StartedAt).IsEqualTo(Now);
        await Assert.That(result.FinishedAt).IsEqualTo(Now);
        await Assert.That(result.NativeRequestIds.Single()).IsEqualTo("native-read-1");
        await Assert.That(f.Backend.Requests.Single().Path).IsEqualTo(PathFor(read));
        await Assert.That(f.Backend.Requests.Single().Origin).IsEqualTo("https://management.azure.com");
        await Assert.That(f.Backend.Requests.Single().Query).IsEqualTo("?api-version=2026-02-01");
        await Assert.That(f.Backend.Requests.Single().Method).IsEqualTo(
            read == C.ReadKind.CheckNameAvailability ? HttpMethod.Post : HttpMethod.Get);
        await Assert.That(f.Credential.Scopes.Single()).IsEqualTo("https://management.azure.com/.default");
        await Assert.That(f.Backend.Requests.Single().Authorization).IsEqualTo("Bearer independent-reader");
        if (read == C.ReadKind.CheckNameAvailability)
        {
            await Assert.That(result.NameAvailable).IsTrue();
            using var body = JsonDocument.Parse(f.Backend.Requests.Single().Body!);
            await Assert.That(body.RootElement.GetProperty("name").GetString()).IsEqualTo("collector-vault");
            await Assert.That(body.RootElement.GetProperty("type").GetString()).IsEqualTo("Microsoft.KeyVault/vaults");
        }
        else
        {
            int count = result.Vaults.Count + result.DeletedVaults.Count + result.Connections.Count + result.PrivateLinks.Count;
            await Assert.That(count).IsEqualTo(1);
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ExactConfigurationRetainsApplicationIdsAndEmptyPermissions(bool emptyPolicies)
    {
        using var f = new Fixture();
        if (emptyPolicies) f.Backend.Vault["properties"]!["accessPolicies"] = new JsonArray();
        var result = await f.Collect(Binding());
        var vault = result.Vaults.Single();
        var configuration = vault.Configuration!;
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(configuration.Location).IsEqualTo("eastus");
        await Assert.That(configuration.TenantId).IsEqualTo(Tenant);
        await Assert.That(configuration.Sku).IsEqualTo(VaultSku.Premium);
        await Assert.That(configuration.Rbac).IsFalse();
        await Assert.That(configuration.PurgeProtection).IsFalse();
        await Assert.That(configuration.RetentionDays).IsEqualTo(23);
        await Assert.That(configuration.PublicNetworkAccess).IsFalse();
        await Assert.That(configuration.Policies.Length).IsEqualTo(emptyPolicies ? 0 : 1);
        if (!emptyPolicies)
        {
            await Assert.That(configuration.Policies.Single().ApplicationId).IsEqualTo(Application);
            await Assert.That(configuration.Policies.Single().Permissions.Length).IsEqualTo(0);
            await Assert.That(vault.Policies.Single().Secrets.Count).IsEqualTo(0);
        }
    }

    [Test]
    [Arguments("enableRbacAuthorization")]
    [Arguments("enablePurgeProtection")]
    [Arguments("softDeleteRetentionInDays")]
    [Arguments("publicNetworkAccess")]
    public async Task OmittedConfigurationNeverBecomesExplicitFalse(string field)
    {
        using var f = new Fixture();
        f.Backend.Vault["properties"]!.AsObject().Remove(field);
        var result = await f.Collect(Binding());
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.Vaults.Single().Configuration).IsNull();
        var vault = result.Vaults.Single();
        if (field == "enableRbacAuthorization") await Assert.That(vault.Row.Rbac).IsNull();
        if (field == "enablePurgeProtection") await Assert.That(vault.Row.PurgeProtection).IsNull();
        if (field == "softDeleteRetentionInDays") await Assert.That(vault.Row.RetentionDays).IsNull();
        if (field == "publicNetworkAccess") await Assert.That(vault.PublicNetworkAccess).IsNull();
    }

    [Test]
    [Arguments("false")]
    [Arguments("null")]
    [Arguments("omitted")]
    public async Task UnrepresentableSoftDeleteNeverBecomesARebuildableConfiguration(string state)
    {
        using var f = new Fixture();
        var properties = f.Backend.Vault["properties"]!.AsObject();
        if (state == "omitted") properties.Remove("enableSoftDelete");
        else properties["enableSoftDelete"] = state == "false" ? JsonValue.Create(false) : null;
        var result = await f.Collect(Binding());
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.Vaults.Single().Configuration).IsNull();
        await Assert.That(result.Vaults.Single().SoftDelete).IsEqualTo(state == "false" ? false : (bool?)null);
    }

    [Test]
    [Arguments("sku", "0")]
    [Arguments("sku", "future")]
    [Arguments("permission", "0")]
    [Arguments("permission", "future")]
    [Arguments("provisioning", "1")]
    [Arguments("provisioning", "future")]
    public async Task UnknownNativeSpellingsNeverBecomeNamedEnums(string field, string value)
    {
        using var f = new Fixture();
        var p = f.Backend.Vault["properties"]!;
        if (field == "sku") p["sku"]!["name"] = value;
        if (field == "permission") p["accessPolicies"]![0]!["permissions"]!["secrets"] = new JsonArray(JsonValue.Create(value));
        if (field == "provisioning") p["provisioningState"] = value;
        var result = await f.Collect(Binding());
        if (field == "sku")
        {
            // The pinned SDK's closed SKU enum cannot materialize these values.
            await Assert.That(result.ResponseComplete).IsFalse();
            await Assert.That(result.Failure).IsEqualTo(C.Failure.Boundary);
            await Assert.That(result.Vaults.Count).IsEqualTo(0);
            return;
        }
        await Assert.That(result.ResponseComplete).IsTrue();
        var vault = result.Vaults.Single();
        if (field == "provisioning")
        {
            await Assert.That(vault.Row.ProvisioningState).IsEqualTo(NativeProvisioningState.Unknown);
            await Assert.That(vault.NativeProvisioningState).IsEqualTo(value);
        }
        else await Assert.That(vault.Configuration).IsNull();
        if (field == "permission") await Assert.That(vault.Policies.Single().Secrets.Single()).IsEqualTo(value);
    }

    [Test]
    [Arguments("0")]
    [Arguments("1")]
    [Arguments("future")]
    public async Task ConnectionNumericAndUnknownStatesRemainUnknown(string value)
    {
        using var f = new Fixture();
        f.Backend.Connection["properties"]!["privateLinkServiceConnectionState"]!["status"] = value;
        var result = await f.Collect(Binding(C.ReadKind.GetPrivateConnection));
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.Connections.Single().State).IsEqualTo(PrivateConnectionState.Unknown);
    }

    [Test]
    public async Task DeletedDatesAndPrivateLinkEmptyArraysAreActualNativeMetadata()
    {
        using var f = new Fixture();
        var deleted = await f.Collect(Binding(C.ReadKind.GetDeletedVault));
        await Assert.That(deleted.DeletedVaults.Single().DeletedOn).IsEqualTo(Now);
        await Assert.That(deleted.DeletedVaults.Single().ScheduledPurgeOn).IsEqualTo(Now.AddDays(23));
        await Assert.That(deleted.DeletedVaults.Single().PurgeProtected).IsFalse();
        var links = await f.Collect(Binding(C.ReadKind.ListPrivateLinkResources));
        await Assert.That(links.PrivateLinks.Single().RequiredMembers.Length).IsEqualTo(0);
        await Assert.That(links.PrivateLinks.Single().RequiredZoneNames.Length).IsEqualTo(0);
    }

    [Test]
    public async Task PolicyApplicationOmissionAndNonSecretPermissionsAreNotHidden()
    {
        using var f = new Fixture();
        var policy = f.Backend.Vault["properties"]!["accessPolicies"]![0]!;
        policy.AsObject().Remove("applicationId");
        policy["permissions"]!["keys"] = new JsonArray(JsonValue.Create("get"));
        var result = await f.Collect(Binding());
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.Vaults.Single().Policies.Single().ApplicationId).IsNull();
        await Assert.That(result.Vaults.Single().Policies.Single().Keys.Single()).IsEqualTo("get");
        await Assert.That(result.Vaults.Single().Configuration).IsNull();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NameAvailabilityRetainsActualNativeBoolean(bool available)
    {
        using var f = new Fixture();
        f.Backend.Available = available;
        var result = await f.Collect(Binding(C.ReadKind.CheckNameAvailability));
        await Assert.That(result.NameAvailable).IsEqualTo(available);
        await Assert.That(result.ResourceAbsent).IsNull();
    }

    [Test]
    [Arguments("missing-name")]
    [Arguments("null-name")]
    [Arguments("numeric-name")]
    public async Task MissingAndMalformedNameAvailabilityCannotDefaultToFalse(string fault)
    {
        using var f = new Fixture();
        f.Backend.Fault = fault;
        var result = await f.Collect(Binding(C.ReadKind.CheckNameAvailability));
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.NameAvailable).IsNull();
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("lease")]
    [Arguments("scope")]
    [Arguments("variant")]
    [Arguments("case")]
    [Arguments("operation")]
    [Arguments("query")]
    [Arguments("read")]
    [Arguments("subscription")]
    [Arguments("group")]
    [Arguments("location")]
    [Arguments("vault")]
    [Arguments("connection")]
    public async Task FullBindingSubstitutionCannotReuseAnArmedWindow(string field)
    {
        using var f = new Fixture();
        var b = Binding();
        var window = f.Source.Arm(b);
        var changed = field switch
        {
            "nonce" => b with { Selector = b.Selector with { Nonce = Guid.NewGuid() } },
            "lease" => b with { LeaseId = Guid.NewGuid() },
            "scope" => b with { Selector = b.Selector with { Scope = "other" } },
            "variant" => b with { Selector = b.Selector with { Variant = "other" } },
            "case" => b with { Selector = b.Selector with { Case = "other" } },
            "operation" => b with { Selector = b.Selector with { Operation = "other" } },
            "query" => b with { Query = C.QueryKind.DeleteVault },
            "read" => b with { Read = C.ReadKind.GetDeletedVault },
            "subscription" => b with { SubscriptionId = Guid.NewGuid() },
            "group" => b with { ResourceGroup = "other" },
            "location" => b with { Location = "westus" },
            "vault" => b with { VaultName = "other-vault" },
            _ => b with { ConnectionName = "other" }
        };
        await Assert.That(async () => await f.Source.CollectAsync(window, changed)).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        await Assert.That((await f.Source.CollectAsync(window, b)).ResponseComplete).IsTrue();
        await Assert.That(async () => await f.Source.CollectAsync(window, b)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(200)]
    [Arguments(404)]
    public async Task PolicyDeletedReadKeepsOriginalSelectorAndIndependentNativeStatus(int status)
    {
        using var f = new Fixture();
        f.Backend.Status = status;
        var original = Binding() with
        {
            Query = C.QueryKind.ChangeAccessPolicies,
            Selector = new(Guid.NewGuid(), "original-policy", C.Operation(C.QueryKind.ChangeAccessPolicies),
                "change.Add", "independent-effect")
        };
        var paired = original with { Read = C.ReadKind.GetDeletedVault };
        var window = f.Source.Arm(paired);
        await Assert.That(async () => await f.Source.CollectAsync(window, original)).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        var actual = await f.Source.CollectAsync(window, paired);
        await Assert.That(actual.Binding).IsEqualTo(paired);
        await Assert.That(actual.Binding.Selector).IsEqualTo(original.Selector);
        await Assert.That(actual.ResponseComplete).IsTrue();
        await Assert.That(actual.Status).IsEqualTo(status == 200 ? SecretStatus.Success : SecretStatus.Absent);
        await Assert.That(f.Backend.Requests.Single().Path).IsEqualTo(DeletedId);
        await Assert.That(C.DefaultRead(C.QueryKind.ChangeAccessPolicies)).IsEqualTo(C.ReadKind.GetVault);
    }

    [Test]
    [Arguments("GetVault")]
    [Arguments("UpdateSettings")]
    [Arguments("CreateOrUpdateVault")]
    public async Task PolicyPairingDoesNotAuthorizeUnrelatedDeletedReads(string name)
    {
        using var f = new Fixture();
        var query = Enum.Parse<C.QueryKind>(name);
        var member = VaultAdministrationEffects.Members.Single(m => m.Operation == C.Operation(query));
        var invalid = Binding(C.ReadKind.GetDeletedVault) with
        {
            Query = query,
            Selector = new(Guid.NewGuid(), "controlled", member.Operation, member.Variants[0], "selected-contract")
        };
        await Assert.That(() => f.Source.Arm(invalid)).Throws<ArgumentException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task EveryOriginatingMemberIsBoundWithoutEnablingMutation()
    {
        using var f = new Fixture();
        foreach (C.QueryKind query in Enum.GetValues<C.QueryKind>())
        {
            var member = VaultAdministrationEffects.Members.Single(m => m.Operation == C.Operation(query));
            C.ReadKind read = C.DefaultRead(query);
            var b = Binding(read) with
            {
                Query = query,
                Selector = new(Guid.NewGuid(), "controlled", member.Operation, member.Variants[0], "selected-contract")
            };
            await Assert.That((await f.Collect(b)).ResponseComplete).IsTrue();
        }
        await Assert.That(f.Backend.Requests.All(r => r.Method == HttpMethod.Get ||
            r.Method == HttpMethod.Post && r.Path.EndsWith("/checkNameAvailability", StringComparison.Ordinal))).IsTrue();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(5)]
    [Arguments(8)]
    public async Task NotFoundOnlyEstablishesConcreteResourceAbsence(int kind)
    {
        var read = (C.ReadKind)kind;
        using var f = new Fixture();
        f.Backend.Status = 404;
        var result = await f.Collect(Binding(read));
        bool concrete = read <= C.ReadKind.GetPrivateConnection;
        await Assert.That(result.ResourceAbsent).IsEqualTo(concrete ? true : (bool?)null);
        await Assert.That(result.ResponseComplete).IsEqualTo(concrete);
        await Assert.That(result.InventoryComplete).IsFalse();
    }

    [Test]
    [Arguments(401)]
    [Arguments(403)]
    [Arguments(206)]
    [Arguments(429)]
    [Arguments(500)]
    public async Task ErrorsAndPartialHttpResponsesCannotProveInventoryOrAbsence(int status)
    {
        using var f = new Fixture();
        f.Backend.Status = status;
        var result = await f.Collect(Binding(C.ReadKind.ListVaultsGroup));
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.ResourceAbsent).IsNull();
        await Assert.That(result.InventoryComplete).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("duplicate-id")]
    [Arguments("duplicate-json")]
    [Arguments("wrong-subscription")]
    [Arguments("wrong-group")]
    [Arguments("wrong-name")]
    [Arguments("missing-properties")]
    [Arguments("wrong-type")]
    [Arguments("wrong-boolean")]
    [Arguments("bad-policy-id")]
    [Arguments("missing-permissions")]
    [Arguments("too-many-policies")]
    [Arguments("row-bytes")]
    [Arguments("declared-bytes")]
    [Arguments("stream-bytes")]
    [Arguments("error-in-200")]
    [Arguments("missing-value")]
    [Arguments("too-many-rows")]
    [Arguments("request-id")]
    [Arguments("redirect")]
    public async Task MalformedOrOverBudgetRowsAreRejectedBeforeNativeModels(string fault)
    {
        using var f = new Fixture(maximumBytes: fault is "declared-bytes" or "stream-bytes" ? 2048 : 65536);
        f.Backend.Fault = fault;
        var result = await f.Collect(Binding(C.ReadKind.ListVaultsGroup));
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.ResourceAbsent).IsNull();
        await Assert.That(result.Vaults.Count).IsEqualTo(0);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        if (fault == "stream-bytes") await Assert.That(f.Backend.LastStream!.ReadBytes).IsEqualTo(2049);
    }

    [Test]
    [Arguments("foreign-origin")]
    [Arguments("foreign-scope")]
    [Arguments("wrong-revision")]
    [Arguments("duplicate-query")]
    [Arguments("credentials")]
    [Arguments("fragment")]
    [Arguments("cycle")]
    public async Task ProviderAuthoredHostileNextLinksNeverEscapeTheBoundary(string fault)
    {
        using var f = new Fixture();
        f.Backend.Next = fault switch
        {
            "foreign-origin" => "https://foreign.invalid" + PathFor(C.ReadKind.ListVaultsGroup) + "?api-version=2026-02-01&$skiptoken=2",
            "foreign-scope" => Next().Replace("collector-group", "other", StringComparison.Ordinal),
            "wrong-revision" => Next().Replace("2026-02-01", "2025-01-01", StringComparison.Ordinal),
            "duplicate-query" => Next() + "&api-version=2026-02-01",
            "credentials" => Next().Replace("https://", "https://user@", StringComparison.Ordinal),
            "fragment" => Next() + "#fragment",
            _ => "https://management.azure.com" + PathFor(C.ReadKind.ListVaultsGroup) + "?api-version=2026-02-01"
        };
        var result = await f.Collect(Binding(C.ReadKind.ListVaultsGroup));
        await Assert.That(result.InventoryComplete).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("complete")]
    [Arguments("page-budget")]
    [Arguments("item-budget")]
    [Arguments("second-error")]
    [Arguments("second-duplicate")]
    public async Task NativePagesPreserveActualPartialRowsWithoutHidingExtras(string outcome)
    {
        using var f = new Fixture(pages: outcome == "page-budget" ? 1 : 3, items: outcome == "item-budget" ? 1 : 4);
        f.Backend.Next = Next();
        f.Backend.SecondFault = outcome;
        var result = await f.Collect(Binding(C.ReadKind.ListVaultsGroup));
        await Assert.That(result.InventoryComplete).IsEqualTo(outcome == "complete");
        await Assert.That(result.Vaults.Count).IsEqualTo(outcome == "complete" ? 2 : 1);
        await Assert.That(result.Vaults[0].Row.ResourceId).IsEqualTo(VaultId);
        if (outcome == "complete")
            await Assert.That(result.Vaults[1].Row.ResourceId).IsEqualTo(VaultId.Replace("collector-vault", "extra-vault", StringComparison.Ordinal));
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(outcome is "page-budget" or "item-budget" ? 1 : 2);
        await Assert.That(result.ResourceAbsent).IsNull();
    }

    [Test]
    public async Task EmptyNativeInventoryIsCompleteButNotResourceOrAuthorityProof()
    {
        using var f = new Fixture();
        f.Backend.Empty = true;
        var result = await f.Collect(Binding(C.ReadKind.ListVaultsSubscription));
        await Assert.That(result.InventoryComplete).IsTrue();
        await Assert.That(result.Vaults.Count).IsEqualTo(0);
        await Assert.That(result.ResourceAbsent).IsNull();
    }

    [Test]
    public async Task SubscriptionInventoryKeepsOtherGroupsAndLocationsWithoutFiltering()
    {
        using var f = new Fixture();
        f.Backend.Vault["id"] = VaultId.Replace("collector-group", "other-group", StringComparison.Ordinal);
        f.Backend.Vault["location"] = "westus";
        var result = await f.Collect(Binding(C.ReadKind.ListVaultsSubscription));
        await Assert.That(result.InventoryComplete).IsTrue();
        await Assert.That(result.Vaults.Single().Location).IsEqualTo("westus");
        await Assert.That(result.Vaults.Single().Row.ResourceId).IsEqualTo(
            VaultId.Replace("collector-group", "other-group", StringComparison.Ordinal));
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CancellationUsesExactReadBarrierAndKeepsHostResourcesOwned(bool before)
    {
        using var f = new Fixture();
        var b = Binding();
        var window = f.Source.Arm(b);
        using var cancel = new CancellationTokenSource();
        if (before) cancel.Cancel();
        else f.Backend.PauseRead = true;
        var pending = f.Source.CollectAsync(window, b, cancel.Token).AsTask();
        if (!before)
        {
            await f.Backend.ReadEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
        }
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(f.Backend.Disposed).IsFalse();
        await Assert.That(f.Credential.Disposed).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(before ? 0 : 1);
        if (!before)
        {
            await Assert.That(f.Backend.LastStream!.Disposed).IsTrue();
            await Assert.That(f.Backend.LastStream.Destination!.All(v => v == 0)).IsTrue();
        }
        var next = await f.Collect(Binding());
        await Assert.That(next.ResponseComplete).IsTrue();
    }

    [Test]
    public async Task CancellationRetainsOwnershipUntilTheActualNativeReadTerminates()
    {
        using var f = new Fixture();
        f.Backend.PauseRead = true;
        f.Backend.IgnoreCancellationUntilReleased = true;
        using var cancel = new CancellationTokenSource();
        var b = Binding();
        var window = f.Source.Arm(b);
        var pending = f.Source.CollectAsync(window, b, cancel.Token).AsTask();
        await f.Backend.ReadEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancel.Cancel();
        await Assert.That(pending.IsCompleted).IsFalse();
        await Assert.That(f.Backend.LastStream!.Disposed).IsFalse();
        await Assert.That(f.Backend.Disposed).IsFalse();
        f.Backend.ReleaseRead.TrySetResult();
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(f.Backend.LastStream.Disposed).IsTrue();
        await Assert.That(f.Backend.LastStream.Destination!.All(v => v == 0)).IsTrue();
    }

    [Test]
    public async Task ForeignAndConcurrentWindowsDoNotStartAdditionalNativeInvocations()
    {
        using var f = new Fixture();
        var b = Binding();
        var other = new C(new("other-host-reader", f.Credential, f.Transport), f.Limits, f.Clock);
        await Assert.That(async () => await f.Source.CollectAsync(other.Arm(b), b)).Throws<InvalidOperationException>();
        f.Backend.PauseRead = true;
        var window = f.Source.Arm(b);
        using var cancel = new CancellationTokenSource();
        var pending = f.Source.CollectAsync(window, b, cancel.Token).AsTask();
        await f.Backend.ReadEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That(async () => await f.Source.CollectAsync(window, b)).Throws<InvalidOperationException>();
        cancel.Cancel();
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task DeadlineAndExpiredWindowAreDrivenByInjectedTime()
    {
        using var f = new Fixture();
        var b = Binding();
        var expired = f.Source.Arm(b);
        f.Clock.Advance(TimeSpan.FromSeconds(11));
        var result = await f.Source.CollectAsync(expired, b);
        await Assert.That(result.Failure).IsEqualTo(C.Failure.Deadline);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        f.Backend.PauseRead = true;
        var pending = f.Collect(Binding()).AsTask();
        await f.Backend.ReadEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        f.Clock.Advance(TimeSpan.FromSeconds(11));
        await Assert.That((await pending).Failure).IsEqualTo(C.Failure.Deadline);
        await Assert.That(f.Backend.LastStream!.Disposed).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OwnedResponseBuffersAreClearedOnSuccessAndFailure(bool malformed)
    {
        using var f = new Fixture();
        using var spying = new BufferSpy(f.Transport);
        var source = new C(new("host-reader", f.Credential, spying), f.Limits, f.Clock);
        if (malformed) f.Backend.Fault = "wrong-boolean";
        var b = Binding();
        var result = await source.CollectAsync(source.Arm(b), b);
        await Assert.That(result.ResponseComplete).IsEqualTo(!malformed);
        await Assert.That(spying.Storage.Count > 0).IsTrue();
        await Assert.That(spying.Storage.All(s => s.All(v => v == 0))).IsTrue();
        await Assert.That(f.Backend.Disposed).IsFalse();
    }

    [Test]
    public async Task MetadataObjectsDoNotSerializeProtectedCoordinatesOrNativeErrors()
    {
        using var f = new Fixture();
        var b = Binding();
        var result = await f.Collect(b);
        await Assert.That(JsonSerializer.Serialize(b)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(result)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(result.Vaults.Single())).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(result.Vaults.Single().Policies.Single())).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(result.Vaults.Single().Row)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(result.Vaults.Single().Configuration)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(result.Vaults.Single().Configuration!.Policies.Single())).IsEqualTo("{}");
        f.Backend.Throw = true;
        var failed = await f.Collect(Binding());
        await Assert.That(failed.Failure).IsEqualTo(C.Failure.Unavailable);
        await Assert.That(JsonSerializer.Serialize(failed)).IsEqualTo("{}");
        await Assert.That(failed.ResourceAbsent).IsNull();
    }

    private static string PathFor(C.ReadKind read) => read switch
    {
        C.ReadKind.GetVault => VaultId,
        C.ReadKind.GetDeletedVault => DeletedId,
        C.ReadKind.GetPrivateConnection => ConnectionId,
        C.ReadKind.ListVaultsGroup => GroupId + "/providers/Microsoft.KeyVault/vaults",
        C.ReadKind.ListVaultsSubscription => SubscriptionId + "/providers/Microsoft.KeyVault/vaults",
        C.ReadKind.ListDeletedVaults => SubscriptionId + "/providers/Microsoft.KeyVault/deletedVaults",
        C.ReadKind.ListPrivateConnections => VaultId + "/privateEndpointConnections",
        C.ReadKind.ListPrivateLinkResources => VaultId + "/privateLinkResources",
        _ => SubscriptionId + "/providers/Microsoft.KeyVault/checkNameAvailability"
    };

    private static string Next() => "https://management.azure.com" + PathFor(C.ReadKind.ListVaultsGroup) +
        "?api-version=2026-02-01&$skiptoken=page2";

    private sealed class Fixture : IDisposable
    {
        internal readonly Clock Clock = new();
        internal readonly Credential Credential = new();
        internal readonly Backend Backend = new();
        private readonly HttpClient client;
        internal readonly HttpClientTransport Transport;
        internal readonly C Source;
        internal readonly C.Limits Limits;
        internal Fixture(int pages = 3, int items = 4, int maximumBytes = 65536)
        {
            client = new(Backend);
            Transport = new(client);
            Limits = new(pages, items, maximumBytes, 8192, TimeSpan.FromSeconds(10));
            Source = new(new("host-reader", Credential, Transport), Limits, Clock);
        }
        internal ValueTask<C.Measurement> Collect(C.Binding b) => Source.CollectAsync(Source.Arm(b), b);
        public void Dispose() { client.Dispose(); Credential.Dispose(); }
    }

    private sealed class Credential : TokenCredential, IDisposable
    {
        internal readonly HashSet<string> Scopes = [];
        internal bool Disposed;
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            foreach (string scope in context.Scopes) Scopes.Add(scope);
            return new("independent-reader", DateTimeOffset.MaxValue);
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken token) =>
            ValueTask.FromResult(GetToken(context, token));
        public void Dispose() => Disposed = true;
    }

    private sealed record RequestRow(HttpMethod Method, string Origin, string Path, string Query, string? Body, string? Authorization);

    // This resource state exists independently of selected SecretKit outcomes.
    private sealed class Backend : HttpMessageHandler
    {
        internal readonly JsonObject Vault = JsonNode.Parse(JsonSerializer.Serialize(new
        {
            id = VaultId,
            name = "collector-vault",
            type = "Microsoft.KeyVault/vaults",
            location = "eastus",
            properties = new
            {
                tenantId = Tenant,
                sku = new { family = "A", name = "premium" },
                provisioningState = "Succeeded",
                enableRbacAuthorization = false,
                enablePurgeProtection = false,
                enableSoftDelete = true,
                softDeleteRetentionInDays = 23,
                publicNetworkAccess = "Disabled",
                accessPolicies = new[] { new { tenantId = Tenant, objectId = Principal, applicationId = Application,
                    permissions = new { secrets = Array.Empty<string>(), keys = Array.Empty<string>(),
                        certificates = Array.Empty<string>(), storage = Array.Empty<string>() } } }
            }
        }))!.AsObject();
        internal readonly JsonObject Connection = JsonNode.Parse(JsonSerializer.Serialize(new
        {
            id = ConnectionId,
            name = "connection",
            type = "Microsoft.KeyVault/vaults/privateEndpointConnections",
            properties = new { provisioningState = "Succeeded", privateLinkServiceConnectionState = new { status = "Approved" } }
        }))!.AsObject();
        internal readonly List<RequestRow> Requests = [];
        internal readonly TaskCompletionSource ReadEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource ReleaseRead = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal string? Fault, Next, SecondFault, ConnectionEndpointId;
        internal int Status = 200;
        internal bool Empty, Throw, PauseRead, Disposed, IgnoreCancellationUntilReleased, Available = true;
        internal ReadStream? LastStream;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            var uri = request.RequestUri!;
            Requests.Add(new(request.Method, uri.GetLeftPart(UriPartial.Authority), uri.AbsolutePath, uri.Query,
                request.Content is null ? null : await request.Content.ReadAsStringAsync(token), request.Headers.Authorization?.ToString()));
            if (Throw) throw new HttpRequestException("protected-native-payload");
            int status = Status;
            bool second = uri.Query.Contains("skiptoken", StringComparison.Ordinal);
            string path = uri.AbsolutePath;
            JsonObject row = path.Contains("privateEndpointConnections", StringComparison.Ordinal) ? Connection.DeepClone().AsObject() :
                path.Contains("privateLinkResources", StringComparison.Ordinal) ? JsonNode.Parse(JsonSerializer.Serialize(new
                {
                    id = VaultId + "/privateLinkResources/vault",
                    name = "vault",
                    type = "Microsoft.KeyVault/vaults/privateLinkResources",
                    properties = new { groupId = "vault", requiredMembers = Array.Empty<string>(), requiredZoneNames = Array.Empty<string>() }
                }))!.AsObject() :
                path.Contains("deletedVaults", StringComparison.Ordinal) ? JsonNode.Parse(JsonSerializer.Serialize(new
                {
                    id = DeletedId,
                    name = "collector-vault",
                    type = "Microsoft.KeyVault/locations/deletedVaults",
                    properties = new
                    {
                        vaultId = VaultId,
                        location = "eastus",
                        deletionDate = Now,
                        scheduledPurgeDate = Now.AddDays(23),
                        purgeProtectionEnabled = false
                    }
                }))!.AsObject() : Vault.DeepClone().AsObject();
            if (ConnectionEndpointId is not null && (path == ConnectionId || path.EndsWith("/privateEndpointConnections", StringComparison.Ordinal)))
                row["properties"]!["privateEndpoint"] = new JsonObject { ["id"] = ConnectionEndpointId };
            if (second && SecondFault != "second-duplicate")
            {
                row["id"] = VaultId.Replace("collector-vault", "extra-vault", StringComparison.Ordinal);
                row["name"] = "extra-vault";
            }
            if (second && SecondFault == "second-error") status = 500;
            if (Fault == "wrong-subscription") row["id"] = VaultId.Replace(Subscription.ToString("D"), Tenant.ToString("D"), StringComparison.Ordinal);
            if (Fault == "wrong-group") row["id"] = VaultId.Replace("collector-group", "other", StringComparison.Ordinal);
            if (Fault == "wrong-name") row["name"] = "other";
            if (Fault == "missing-properties") row.Remove("properties");
            if (Fault == "wrong-type") row["type"] = "Microsoft.KeyVault/deletedVaults";
            if (Fault == "wrong-boolean") row["properties"]!["enableRbacAuthorization"] = "false";
            if (Fault == "bad-policy-id") row["properties"]!["accessPolicies"]![0]!["objectId"] = "invalid";
            if (Fault == "missing-permissions") row["properties"]!["accessPolicies"]![0]!.AsObject().Remove("permissions");
            if (Fault == "too-many-policies")
            {
                var policies = row["properties"]!["accessPolicies"]!.AsArray();
                for (int i = 0; i < 17; i++) policies.Add(policies[0]!.DeepClone());
            }
            if (Fault == "row-bytes") row["padding"] = new string('x', 9000);
            bool inventory = path != VaultId && path != DeletedId && path != ConnectionId &&
                !path.EndsWith("/checkNameAvailability", StringComparison.Ordinal);
            JsonObject payload = inventory ? new() { ["value"] = Empty ? new JsonArray() : new JsonArray(row) } : row;
            if (inventory && Fault == "duplicate-id") payload["value"]!.AsArray().Add(row.DeepClone());
            if (inventory && Fault == "too-many-rows")
                for (int i = 0; i < 4; i++) payload["value"]!.AsArray().Add(row.DeepClone());
            if (inventory && !second && Next is not null) payload["nextLink"] = Next;
            if (path.EndsWith("/checkNameAvailability", StringComparison.Ordinal)) payload = new() { ["nameAvailable"] = Available };
            if (Fault == "missing-name") payload.Remove("nameAvailable");
            if (Fault == "null-name") payload["nameAvailable"] = null;
            if (Fault == "numeric-name") payload["nameAvailable"] = 0;
            if (Fault == "error-in-200") payload["error"] = new JsonObject { ["code"] = "Partial" };
            if (Fault == "missing-value") payload.Remove("value");
            string body = status >= 400 ? """{"error":{"code":"Failure","message":"protected-native-error"}}""" : payload.ToJsonString();
            if (Fault == "duplicate-json") body = body.Replace("\"properties\":", "\"properties\":{},\"properties\":", StringComparison.Ordinal);
            if (Fault is "declared-bytes" or "stream-bytes") body = new string('x', 70000);
            var response = new HttpResponseMessage((HttpStatusCode)status);
            response.Headers.TryAddWithoutValidation("x-ms-request-id", "native-read-" + Requests.Count);
            if (Fault == "request-id") response.Headers.TryAddWithoutValidation("x-ms-request-id", "duplicate-id");
            if (Fault == "redirect")
            {
                response.StatusCode = HttpStatusCode.TemporaryRedirect;
                response.Headers.Location = new("https://foreign.invalid/");
            }
            bool pause = PauseRead;
            PauseRead = false;
            LastStream = new(Encoding.UTF8.GetBytes(body), pause, ReadEntered,
                IgnoreCancellationUntilReleased ? ReleaseRead : null);
            response.Content = new StreamContent(LastStream);
            if (Fault != "stream-bytes") response.Content.Headers.ContentLength = Encoding.UTF8.GetByteCount(body);
            return response;
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }

    private sealed class ReadStream(byte[] bytes, bool pause, TaskCompletionSource entered,
        TaskCompletionSource? release) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
        internal int ReadBytes;
        internal bool Disposed;
        internal byte[]? Destination;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment)) Destination = segment.Array;
            if (pause)
            {
                buffer.Span.Fill(0x5a);
                entered.TrySetResult();
                if (release is not null)
                {
                    await release.Task;
                    token.ThrowIfCancellationRequested();
                }
                else
                {
                    var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    using var registration = token.Register(() => canceled.TrySetCanceled(token));
                    await canceled.Task;
                }
            }
            int count = await base.ReadAsync(buffer, token);
            ReadBytes += count;
            return count;
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }

    // An outer policy sees the stream the collector gives the installed SDK. It
    // retains only the backing array reference to verify disposal actually zeroed it.
    private sealed class BufferSpy(HttpPipelineTransport inner) : HttpPipelineTransport, IDisposable
    {
        internal readonly List<byte[]> Storage = [];
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            message.Response = new WatchedResponse(message.Response, Capture);
        }
        internal void Capture(Stream? stream)
        {
            if (stream is MemoryStream memory && memory.TryGetBuffer(out var segment) && segment.Array is { } bytes)
                Storage.Add(bytes);
        }
        public void Dispose() { }
        private sealed class WatchedResponse(Response inner, Action<Stream?> capture) : Response
        {
            public override int Status => inner.Status;
            public override string ReasonPhrase => inner.ReasonPhrase;
            public override string ClientRequestId { get => inner.ClientRequestId; set => inner.ClientRequestId = value; }
            public override Stream? ContentStream
            {
                get => inner.ContentStream;
                set { capture(value); inner.ContentStream = value; }
            }
            public override void Dispose() => inner.Dispose();
            protected override bool ContainsHeader(string name) => inner.Headers.Contains(name);
            protected override IEnumerable<HttpHeader> EnumerateHeaders() => inner.Headers;
            protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) => inner.Headers.TryGetValue(name, out value);
            protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) => inner.Headers.TryGetValues(name, out values);
        }
    }

    private sealed class Clock : TimeProvider
    {
        private long ticks;
        private readonly List<Hook> timers = [];
        public override DateTimeOffset GetUtcNow() => Now.AddTicks(ticks);
        public override long GetTimestamp() => ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new Hook(this, callback, state) { Due = ticks + dueTime.Ticks };
            timers.Add(timer);
            return timer;
        }
        internal void Advance(TimeSpan duration)
        {
            ticks += duration.Ticks;
            foreach (var timer in timers.ToArray())
                if (timer.Due <= ticks) { timer.Due = long.MaxValue; timer.Fire(); }
        }
        private sealed class Hook(Clock clock, TimerCallback callback, object? state) : ITimer
        {
            internal long Due;
            internal void Fire() => callback(state);
            public bool Change(TimeSpan dueTime, TimeSpan period) { Due = clock.ticks + dueTime.Ticks; return true; }
            public void Dispose() => Due = long.MaxValue;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
