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
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationAdministrationCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureNotificationAdministrationCollectorTests
{
    private const string Origin = "https://management.azure.com";
    private const string VaultId = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/notify-group/providers/Microsoft.KeyVault/vaults/notify-vault";
    private const string Collection = VaultId + "/providers/Microsoft.EventGrid/eventSubscriptions";
    private const string Resource = Collection + "/notify-subscription";
    private const string Protected = "notification-protected-sentinel";
    private const string Endpoint = "https://observer.invalid/callback?secret=" + Protected;
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 0, 0, 0, TimeSpan.Zero);
    private static readonly C.Limits Limits = new(3, 10, 65536, 16384, 4096, TimeSpan.FromSeconds(20));

    private static VaultScope Vault() => new(new(new(Guid.Parse("11111111-1111-1111-1111-111111111111")), "notify-group"), "notify-vault");

    private static C.Binding Binding(C.QueryKind query = C.QueryKind.GetNotification,
        C.ReadKind read = C.ReadKind.Metadata)
    {
        bool operation = query >= C.QueryKind.OperationCreateOrUpdateNotification;
        string member = operation ? "a.management.ManagementOperation.CheckStatusAsync" :
            "a.management.VaultAdministration." + query + "Async";
        string variant = operation ? "operation." + query.ToString()["Operation".Length..] :
            query is C.QueryKind.CreateOrUpdateNotification or C.QueryKind.UpdateNotification ? "attributes.omitted" :
            query == C.QueryKind.DeleteNotification ? "input.scope" :
            query == C.QueryKind.ListNotifications ? "collection.bounded" : "selector.exact";
        ManagementScope scope = read == C.ReadKind.Inventory ? Vault() : new NotificationScope(Vault(), "notify-subscription");
        return new(new(Guid.NewGuid(), "original-owned-case-scope", member, variant, "selected-contract"),
            Guid.NewGuid(), query, read, scope);
    }

    [Test]
    [Arguments("Metadata", "GetNotification", "GET", "")]
    [Arguments("Configuration", "GetNotification", "GET", "")]
    [Arguments("Inventory", "ListNotifications", "GET", "")]
    [Arguments("DeliveryAttributes", "GetNotificationDeliveryAttributes", "POST", "/getDeliveryAttributes")]
    [Arguments("FullUrl", "GetNotificationFullUrl", "POST", "/getFullUrl")]
    public async Task InstalledNativeReadersConsumeIndependentResourceResponses(string read, string query, string method, string action)
    {
        using var f = new Fixture();
        var binding = Binding(Enum.Parse<C.QueryKind>(query), Enum.Parse<C.ReadKind>(read));
        using var result = await f.Collect(binding);
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Binding).IsEqualTo(binding);
        await Assert.That(result.Binding.Selector.Scope).IsEqualTo("original-owned-case-scope");
        await Assert.That(result.ApiRevision).IsEqualTo("2025-02-15");
        await Assert.That(result.ArmedAt).IsEqualTo(Now);
        await Assert.That(result.FinishedAt).IsEqualTo(Now);
        var request = f.Backend.Requests.Single();
        await Assert.That(request.Method).IsEqualTo(method);
        await Assert.That(request.Uri).IsEqualTo(Origin + (read == "Inventory" ? Collection : Resource) + action + "?api-version=2025-02-15");
        await Assert.That(request.Body).IsNull();
        bool protectedRead = read is "Configuration" or "DeliveryAttributes" or "FullUrl";
        await Assert.That(request.Authorization).IsEqualTo("Bearer " + (protectedRead ? "protected-reader" : "metadata-reader"));
        await Assert.That(result.Access).IsEqualTo(protectedRead ? C.Access.ProtectedConfiguration : C.Access.Metadata);
        await Assert.That(result.PrincipalQualified).IsFalse();
        await Assert.That(result.EgressQualified).IsFalse();
        await Assert.That(result.AsyncSettlementProven).IsFalse();
        await Assert.That(result.RuntimeDeliveryProven).IsFalse();
        if (read == "FullUrl") await Assert.That(result.FullUrl!.Reveal()).IsEqualTo(Endpoint);
        else if (read == "DeliveryAttributes")
        {
            await Assert.That(result.Attributes.Single().Value!.Reveal()).IsEqualTo(Protected);
            await Assert.That(result.InventoryComplete).IsTrue();
        }
        else
        {
            var row = result.Notifications.Single();
            await Assert.That(row.ResourceId).IsEqualTo(Resource);
            await Assert.That(row.Topic).IsEqualTo(VaultId);
            await Assert.That(row.Destination).IsEqualTo(NotificationDestinationKind.WebHook);
            if (read == "Configuration")
            {
                await Assert.That(row.Configuration!.Endpoint.Reveal()).IsEqualTo(Endpoint);
                await Assert.That(row.Configuration.Attributes!.Single().Value!.Reveal()).IsEqualTo(Protected);
            }
            else await Assert.That(row.Configuration).IsNull();
        }
        await Assert.That((protectedRead ? f.ProtectedCredential : f.MetadataCredential).Scopes.Single()).IsEqualTo(Origin + "/.default");
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("CreateOrUpdateNotification")]
    [Arguments("DeleteNotification")]
    [Arguments("GetNotification")]
    [Arguments("GetNotificationDeliveryAttributes")]
    [Arguments("GetNotificationFullUrl")]
    [Arguments("ListNotifications")]
    [Arguments("UpdateNotification")]
    [Arguments("OperationCreateOrUpdateNotification")]
    [Arguments("OperationUpdateNotification")]
    [Arguments("OperationDeleteNotification")]
    public async Task EveryOriginatingMemberRetainsItsOwnQueryAndSelector(string query)
    {
        using var f = new Fixture();
        var kind = Enum.Parse<C.QueryKind>(query);
        var read = kind switch
        {
            C.QueryKind.ListNotifications => C.ReadKind.Inventory,
            C.QueryKind.GetNotificationDeliveryAttributes => C.ReadKind.DeliveryAttributes,
            C.QueryKind.GetNotificationFullUrl => C.ReadKind.FullUrl,
            _ => C.ReadKind.Metadata
        };
        var b = Binding(kind, read);
        using var result = await f.Collect(b);
        await Assert.That(result.Binding).IsEqualTo(b);
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(result.AsyncSettlementProven).IsFalse();
    }

    [Test]
    [Arguments("scope")]
    [Arguments("nonce")]
    [Arguments("lease")]
    [Arguments("query")]
    [Arguments("read")]
    [Arguments("variant")]
    [Arguments("case")]
    [Arguments("resource")]
    public async Task WholeBindingMustMatchBeforeSingleUseConsumption(string field)
    {
        using var f = new Fixture();
        var b = Binding();
        var window = f.Source.Arm(b);
        var changed = field switch
        {
            "scope" => b with { Selector = b.Selector with { Scope = "AzureKeyVault" } },
            "nonce" => b with { Selector = b.Selector with { Nonce = Guid.NewGuid() } },
            "lease" => b with { LeaseId = Guid.NewGuid() },
            "query" => b with { Query = C.QueryKind.DeleteNotification },
            "read" => b with { Read = C.ReadKind.Configuration },
            "variant" => b with { Selector = b.Selector with { Variant = "response.destination.Other" } },
            "case" => b with { Selector = b.Selector with { Case = "denied-authority" } },
            _ => b with { Scope = new NotificationScope(Vault(), "another-subscription") }
        };
        await Assert.That(async () => await f.Source.CollectAsync(window, changed)).Throws<InvalidOperationException>();
        using var actual = await f.Source.CollectAsync(window, b);
        await Assert.That(actual.ResponseComplete).IsTrue();
        await Assert.That(async () => await f.Source.CollectAsync(window, b)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Source.Arm(b)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ForgedAndForeignWindowsNeverGainSourceAuthority()
    {
        using var f = new Fixture();
        using var other = new Fixture();
        var b = Binding();
        var real = f.Source.Arm(b);
        var forged = new C.Window(b, real.ArmedAt);
        await Assert.That(async () => await f.Source.CollectAsync(forged, b)).Throws<InvalidOperationException>();
        await Assert.That(async () => await other.Source.CollectAsync(real, b)).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        using var result = await f.Source.CollectAsync(real, b);
        await Assert.That(result.ResponseComplete).IsTrue();
    }

    [Test]
    [Arguments("Configuration")]
    [Arguments("DeliveryAttributes")]
    [Arguments("FullUrl")]
    public async Task MetadataAuthorityCannotPerformProtectedReads(string read)
    {
        using var f = new Fixture(protectedAuthority: false);
        var kind = Enum.Parse<C.ReadKind>(read);
        var query = kind == C.ReadKind.DeliveryAttributes ? C.QueryKind.GetNotificationDeliveryAttributes :
            kind == C.ReadKind.FullUrl ? C.QueryKind.GetNotificationFullUrl : C.QueryKind.GetNotification;
        await Assert.That(() => f.Source.Arm(Binding(query, kind))).Throws<InvalidOperationException>();
        await Assert.That(f.MetadataCredential.Scopes.Count).IsEqualTo(0);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("endpoint-omitted")]
    [Arguments("endpoint-null")]
    [Arguments("endpoint-masked")]
    [Arguments("secret-omitted")]
    [Arguments("secret-null")]
    [Arguments("secret-masked")]
    [Arguments("flag-omitted")]
    [Arguments("flag-null")]
    [Arguments("attributes-null")]
    [Arguments("filter-omitted")]
    [Arguments("additional-filter")]
    [Arguments("advanced-nonempty")]
    public async Task HiddenOrUnrepresentableMetadataNeverFabricatesExactConfiguration(string fault)
    {
        using var f = new Fixture();
        var p = f.Backend.Resource["properties"]!.AsObject();
        var destination = p["destination"]!["properties"]!.AsObject();
        var attribute = destination["deliveryAttributeMappings"]![0]!["properties"]!.AsObject();
        switch (fault)
        {
            case "endpoint-omitted": destination.Remove("endpointUrl"); break;
            case "endpoint-null": destination["endpointUrl"] = null; break;
            case "endpoint-masked": destination["endpointUrl"] = "*****"; break;
            case "secret-omitted": attribute.Remove("value"); break;
            case "secret-null": attribute["value"] = null; break;
            case "secret-masked": attribute["value"] = "*****"; break;
            case "flag-omitted": attribute.Remove("isSecret"); break;
            case "flag-null": attribute["isSecret"] = null; break;
            case "attributes-null": destination["deliveryAttributeMappings"] = null; break;
            case "filter-omitted": p.Remove("filter"); break;
            case "additional-filter": p["filter"]!["subjectBeginsWith"] = "restricted/"; break;
            case "advanced-nonempty":
                p["filter"]!["advancedFilters"] = JsonNode.Parse(
                    """[{"operatorType":"StringIn","key":"data.objectName","values":["restricted"]}]""");
                break;
        }
        using var result = await f.Collect(Binding(read: C.ReadKind.Configuration));
        // A masked string need not be a URI the installed native reader can
        // materialize. Either way it cannot become exact configuration.
        if (fault != "endpoint-masked") await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.Notifications.SingleOrDefault()?.Configuration).IsNull();
        // Separate action results have no resource/version authority to repair
        // the metadata observation, even when they happen to match desired data.
        using var full = await f.Collect(Binding(C.QueryKind.GetNotificationFullUrl, C.ReadKind.FullUrl));
        await Assert.That(full.FullUrl!.Reveal()).IsEqualTo(Endpoint);
        await Assert.That(result.Notifications.SingleOrDefault()?.Configuration).IsNull();
    }

    [Test]
    [Arguments("Metadata")]
    [Arguments("Inventory")]
    [Arguments("Configuration")]
    public async Task NativeEventStringsRemainMetadataWithoutAnInventedSupportedConfiguration(string read)
    {
        using var f = new Fixture();
        string[] events = ["Microsoft.KeyVault.KeyExpired", "Microsoft.KeyVault.KeyNewVersionCreated",
            "Microsoft.KeyVault.KeyNearExpiry", "Microsoft.KeyVault.CertificateExpired"];
        f.Backend.Resource["properties"]!["filter"]!["includedEventTypes"] = JsonSerializer.SerializeToNode(events);
        var kind = Enum.Parse<C.ReadKind>(read);
        using var result = await f.Collect(Binding(kind == C.ReadKind.Inventory ?
            C.QueryKind.ListNotifications : C.QueryKind.GetNotification, kind));
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.Notifications.Single().EventTypes.SequenceEqual(events)).IsTrue();
        await Assert.That(result.Notifications.Single().Configuration).IsNull();
        await Assert.That(result.ProtectedValuesComplete).IsFalse();
    }

    [Test]
    public async Task EmptyNativeAdvancedFiltersDoNotRestrictSupportedConfiguration()
    {
        using var f = new Fixture();
        f.Backend.Resource["properties"]!["filter"]!["advancedFilters"] = new JsonArray();
        using var result = await f.Collect(Binding(read: C.ReadKind.Configuration));
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.ProtectedValuesComplete).IsTrue();
        await Assert.That(result.Notifications.Single().Configuration!.Events.Count).IsEqualTo(2);
    }

    [Test]
    [Arguments("omitted")]
    [Arguments("empty")]
    [Arguments("false")]
    [Arguments("dynamic")]
    public async Task NativeAttributePresenceAndSecretFlagsRemainDistinct(string state)
    {
        using var f = new Fixture();
        var destination = f.Backend.Resource["properties"]!["destination"]!["properties"]!.AsObject();
        if (state == "omitted") destination.Remove("deliveryAttributeMappings");
        if (state == "empty") destination["deliveryAttributeMappings"] = new JsonArray();
        if (state == "false") destination["deliveryAttributeMappings"]![0]!["properties"]!["isSecret"] = false;
        if (state == "dynamic") destination["deliveryAttributeMappings"] = JsonNode.Parse(
            """[{"name":"x-dynamic","type":"Dynamic","properties":{"sourceField":"data.objectName"}}]""");
        using var result = await f.Collect(Binding(read: C.ReadKind.Configuration));
        var row = result.Notifications.Single();
        await Assert.That(row.Configuration is not null).IsEqualTo(state != "omitted");
        await Assert.That(row.AttributesPresence).IsEqualTo(state == "omitted" ? C.Presence.Omitted : C.Presence.Value);
        if (state == "omitted") await Assert.That(row.Configuration).IsNull();
        if (state == "empty") await Assert.That(row.Configuration!.Attributes!.Count).IsEqualTo(0);
        if (state is "false" or "dynamic")
        {
            var attribute = row.Attributes.Single();
            await Assert.That(attribute.Kind).IsEqualTo(state == "dynamic" ? NotificationAttributeKind.Dynamic : NotificationAttributeKind.Static);
            await Assert.That(attribute.IsSecret).IsEqualTo(state == "false" ? false : (bool?)null);
            await Assert.That(attribute.SecretFlagPresence).IsEqualTo(state == "false" ? C.Presence.Value : C.Presence.Omitted);
            await Assert.That(attribute.Value!.Reveal()).IsEqualTo(state == "dynamic" ? "data.objectName" : Protected);
        }
    }

    [Test]
    [Arguments("Unknown")]
    [Arguments("WebHook")]
    [Arguments("Other")]
    public async Task DestinationVariantsAreNativeMetadataNotInventedWebhookConfiguration(string destination)
    {
        using var f = new Fixture();
        var p = f.Backend.Resource["properties"]!.AsObject();
        if (destination == "Unknown") p.Remove("destination");
        if (destination == "Other") p["destination"] = JsonNode.Parse(
            """{"endpointType":"EventHub","properties":{"resourceId":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/notify-group/providers/Microsoft.EventHub/namespaces/events/eventhubs/events"}}""");
        using var result = await f.Collect(Binding(read: C.ReadKind.Configuration));
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.Notifications.Single().Destination).IsEqualTo(Enum.Parse<NotificationDestinationKind>(destination));
        if (destination != "WebHook") await Assert.That(result.Notifications.Single().Configuration).IsNull();
    }

    [Test]
    [Arguments("provisioningState", "1")]
    [Arguments("provisioningState", "future")]
    [Arguments("destination", "1")]
    [Arguments("destination", "future")]
    [Arguments("attribute", "0")]
    [Arguments("attribute", "future")]
    [Arguments("event", "0")]
    [Arguments("event", "future")]
    public async Task UnknownNativeEnumsNeverBecomeSuccessfulDefaults(string field, string value)
    {
        using var f = new Fixture();
        var p = f.Backend.Resource["properties"]!;
        if (field == "provisioningState") p[field] = value;
        if (field == "destination") p["destination"]!["endpointType"] = value;
        if (field == "attribute") p["destination"]!["properties"]!["deliveryAttributeMappings"]![0]!["type"] = value;
        if (field == "event") p["filter"]!["includedEventTypes"] = new JsonArray(JsonValue.Create(value));
        using var result = await f.Collect(Binding(read: C.ReadKind.Configuration));
        if (field == "event")
        {
            // Native event types are strings, not the supported secret-event
            // enum. Preserve them without making a supported configuration.
            await Assert.That(result.ResponseComplete).IsTrue();
            await Assert.That(result.Notifications.Single().EventTypes.Single()).IsEqualTo(value);
            await Assert.That(result.Notifications.Single().Configuration).IsNull();
            await Assert.That(result.ProtectedValuesComplete).IsFalse();
        }
        else
        {
            await Assert.That(result.ResponseComplete).IsFalse();
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unavailable);
        }
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("Succeeded", "Succeeded")]
    [Arguments("Creating", "Pending")]
    [Arguments("Updating", "Pending")]
    [Arguments("Deleting", "Pending")]
    [Arguments("Failed", "Failed")]
    [Arguments("Canceled", "Canceled")]
    [Arguments("Unknown", "Unknown")]
    public async Task NativeProvisioningRemainsMetadataAndNeverAsyncDeletionSettlement(string state, string expected)
    {
        using var f = new Fixture();
        f.Backend.Resource["properties"]!["provisioningState"] = state;
        using var result = await f.Collect(Binding(C.QueryKind.OperationDeleteNotification));
        await Assert.That(result.Notifications.Single().ProvisioningState).IsEqualTo(Enum.Parse<NativeProvisioningState>(expected));
        await Assert.That(result.Status).IsEqualTo(expected == "Unknown" ? SecretStatus.Unknown : SecretStatus.Success);
        await Assert.That(result.AsyncSettlementProven).IsFalse();
    }

    [Test]
    [Arguments(404, "Metadata", true)]
    [Arguments(404, "Configuration", true)]
    [Arguments(404, "Inventory", false)]
    [Arguments(404, "FullUrl", false)]
    [Arguments(404, "DeliveryAttributes", false)]
    [Arguments(403, "Metadata", false)]
    [Arguments(500, "Inventory", false)]
    public async Task OnlyConcreteNativeNotFoundCanWitnessResourceAbsence(int status, string read, bool absent)
    {
        using var f = new Fixture();
        f.Backend.Status = status;
        var kind = Enum.Parse<C.ReadKind>(read);
        var query = kind switch
        {
            C.ReadKind.Inventory => C.QueryKind.ListNotifications,
            C.ReadKind.FullUrl => C.QueryKind.GetNotificationFullUrl,
            C.ReadKind.DeliveryAttributes => C.QueryKind.GetNotificationDeliveryAttributes,
            _ => C.QueryKind.OperationDeleteNotification
        };
        using var result = await f.Collect(Binding(query, kind));
        await Assert.That(result.ResourceAbsent).IsEqualTo(absent ? true : (bool?)null);
        await Assert.That(result.InventoryComplete).IsFalse();
        await Assert.That(result.AsyncSettlementProven).IsFalse();
        if (status == 403) await Assert.That(result.Failure).IsEqualTo(C.Failure.Denied);
    }

    [Test]
    [Arguments("complete")]
    [Arguments("page-bound")]
    [Arguments("item-bound")]
    [Arguments("error")]
    [Arguments("duplicate")]
    [Arguments("extra-scope")]
    public async Task SourceOwnedPaginationKeepsPartialRowsWithoutFalseCompleteness(string scenario)
    {
        using var f = new Fixture(limits: scenario == "page-bound" ? Limits with { MaximumPages = 1 } :
            scenario == "item-bound" ? Limits with { MaximumItems = 1 } : Limits);
        f.Backend.Pages = 2;
        f.Backend.Scenario = scenario;
        using var result = await f.Collect(Binding(C.QueryKind.ListNotifications, C.ReadKind.Inventory));
        await Assert.That(result.InventoryComplete).IsEqualTo(scenario == "complete");
        await Assert.That(result.Notifications.Count).IsEqualTo(scenario == "complete" ? 2 : 1);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(scenario is "page-bound" or "item-bound" ? 1 : 2);
        await Assert.That(result.ResourceAbsent).IsNull();
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("https://evil.invalid/collect?api-version=2025-02-15&$skipToken=next")]
    [Arguments("http://management.azure.com/path?api-version=2025-02-15&$skipToken=next")]
    [Arguments("https://management.azure.com:444/path?api-version=2025-02-15&$skipToken=next")]
    [Arguments("relative")]
    [Arguments("fragment")]
    [Arguments("revision")]
    [Arguments("duplicate-query")]
    [Arguments("same-page")]
    [Arguments("other-scope")]
    public async Task HostileProviderContinuationsNeverBecomeAnOutboundRequest(string next)
    {
        using var f = new Fixture();
        string basis = Origin + Collection + "?api-version=2025-02-15";
        f.Backend.Next = next switch
        {
            "relative" => Collection + "?api-version=2025-02-15&$skipToken=next",
            "fragment" => basis + "&$skipToken=next#x",
            "revision" => basis.Replace("2025-02-15", "2020-01-01", StringComparison.Ordinal) + "&$skipToken=next",
            "duplicate-query" => basis + "&api-version=2025-02-15&$skipToken=next",
            "same-page" => basis,
            "other-scope" => basis.Replace("notify-vault", "another-vault", StringComparison.Ordinal) + "&$skipToken=next",
            _ => next
        };
        using var result = await f.Collect(Binding(C.QueryKind.ListNotifications, C.ReadKind.Inventory));
        await Assert.That(result.InventoryComplete).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("root-error")]
    [Arguments("duplicate-field")]
    [Arguments("case-conflict")]
    [Arguments("null-root")]
    [Arguments("wrong-id")]
    [Arguments("wrong-topic")]
    [Arguments("wrong-type")]
    [Arguments("redirect")]
    [Arguments("content-type")]
    [Arguments("encoding")]
    [Arguments("range")]
    [Arguments("length")]
    [Arguments("header-bound")]
    [Arguments("body-bound")]
    [Arguments("row-bound")]
    [Arguments("depth")]
    [Arguments("nodes")]
    public async Task AmbiguousOrUnboundedWireDataFailsBeforeNativeMaterialization(string fault)
    {
        using var f = new Fixture(limits: fault == "nodes" ? Limits with { MaximumNodes = 8 } :
            fault == "row-bound" ? Limits with { MaximumRowBytes = 256 } : Limits);
        f.Backend.Fault = fault;
        using var result = await f.Collect(Binding());
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.Notifications.Count).IsEqualTo(0);
        await Assert.That(result.ResourceAbsent).IsNull();
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("method")]
    [Arguments("path")]
    [Arguments("query")]
    [Arguments("body")]
    [Arguments("host")]
    public async Task FinalRequestIsValidatedAfterCredentialAndBeforeBorrowedSend(string tamper)
    {
        using var f = new Fixture();
        f.MetadataCredential.BeforeToken = () =>
        {
            var request = f.Backend.LastRequest!;
            if (tamper == "method") request.Method = RequestMethod.Delete;
            if (tamper == "path") request.Uri.Reset(new Uri("https://evil.invalid/"));
            if (tamper == "query") request.Uri.Reset(new Uri(Origin + Resource + "?api-version=2020-01-01"));
            if (tamper == "body") request.Content = RequestContent.Create(new byte[] { 1 });
            if (tamper == "host") request.Headers.SetValue("Host", "evil.invalid");
        };
        using var result = await f.Collect(Binding());
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("wall")]
    [Arguments("monotonic")]
    [Arguments("wall-rollback")]
    [Arguments("monotonic-rollback")]
    public async Task ExpiredOrRolledBackWindowStopsBeforeAnyCredential(string clock)
    {
        using var f = new Fixture();
        var b = Binding();
        var window = f.Source.Arm(b);
        if (clock == "wall") f.Time.WallTicks = Limits.Timeout.Ticks;
        if (clock == "monotonic") f.Time.Ticks = Limits.Timeout.Ticks;
        if (clock == "wall-rollback") f.Time.WallTicks = -1;
        if (clock == "monotonic-rollback") f.Time.Ticks = -1;
        using var result = await f.Source.CollectAsync(window, b);
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(f.MetadataCredential.Scopes.Count).IsEqualTo(0);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("wall")]
    [Arguments("monotonic")]
    public async Task ExpiryDuringCredentialStopsBeforeSendEvenWithoutTimerTick(string clock)
    {
        using var f = new Fixture();
        f.MetadataCredential.BeforeToken = () =>
        {
            if (clock == "wall") f.Time.WallTicks += Limits.Timeout.Ticks;
            else f.Time.Ticks += Limits.Timeout.Ticks;
        };
        using var result = await f.Collect(Binding());
        await Assert.That(result.Failure).IsEqualTo(C.Failure.Deadline);
        await Assert.That(result.FinishedAt).IsEqualTo(f.Time.GetUtcNow());
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("credential", false)]
    [Arguments("send", false)]
    [Arguments("body", false)]
    [Arguments("credential", true)]
    [Arguments("send", true)]
    [Arguments("body", true)]
    public async Task CancellationAwaitsActualBorrowerTerminationBeforeErasingBuffers(string barrier, bool expiry)
    {
        using var f = new Fixture();
        using var cancel = new CancellationTokenSource();
        f.MetadataCredential.Block = barrier == "credential";
        f.Backend.Barrier = barrier;
        var b = Binding();
        var entered = barrier == "credential" ? f.MetadataCredential.Entered.Task :
            barrier == "send" ? f.Backend.SendEntered.Task : f.Backend.BodyEntered.Task;
        var canceled = barrier == "credential" ? f.MetadataCredential.CancellationObserved.Task : f.Backend.CancellationObserved.Task;
        Task<C.Measurement> actual = f.Source.CollectAsync(f.Source.Arm(b), b, cancel.Token).AsTask();
        await entered.WaitAsync(TimeSpan.FromSeconds(10));
        if (expiry) f.Time.Advance(Limits.Timeout);
        else cancel.Cancel();
        await canceled.WaitAsync(TimeSpan.FromSeconds(10));
        if (expiry) f.Time.Advance(Limits.Timeout);
        await Assert.That(actual.IsCompleted).IsFalse();
        if (barrier == "body")
            await Assert.That(f.Backend.Buffers.Any(bytes => bytes.Contains((byte)0x5a))).IsTrue();
        f.MetadataCredential.Release.TrySetResult();
        f.Backend.Release.TrySetResult();
        if (expiry)
        {
            using var result = await actual.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(result.Failure).IsEqualTo(C.Failure.Deadline);
            await Assert.That(result.FinishedAt).IsEqualTo(Now + Limits.Timeout + Limits.Timeout);
        }
        else await Assert.That(async () => await actual.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        await ClearedAndBorrowed(f);
    }

    [Test]
    public async Task ProtectedObservationsAndFailuresNeverFormatOrSerializeMaterialOrCoordinates()
    {
        using var f = new Fixture();
        var b = Binding(read: C.ReadKind.Configuration);
        using var result = await f.Collect(b);
        var row = result.Notifications.Single();
        foreach (var value in new object[] { f.Source, b, result, row, row.Configuration!, row.Attributes.Single() })
        {
            string text = value + JsonSerializer.Serialize(value, value.GetType());
            await Assert.That(text.Contains(Protected, StringComparison.Ordinal)).IsFalse();
            await Assert.That(text.Contains("notify-group", StringComparison.Ordinal)).IsFalse();
            await Assert.That(text.Contains("observer.invalid", StringComparison.Ordinal)).IsFalse();
        }
        var material = row.Configuration!.Endpoint;
        result.Dispose();
        await Assert.That(() => material.Reveal()).Throws<ObjectDisposedException>();
        f.MetadataCredential.Throw = true;
        using var failure = await f.Collect(Binding());
        await Assert.That(failure.ResponseComplete).IsFalse();
        await Assert.That(JsonSerializer.Serialize(failure).Contains(Protected, StringComparison.Ordinal)).IsFalse();
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("lease")]
    [Arguments("query")]
    [Arguments("read")]
    [Arguments("scope-type")]
    [Arguments("operation")]
    [Arguments("variant")]
    [Arguments("case")]
    [Arguments("control")]
    [Arguments("wrong-operation-variant")]
    public async Task InvalidSelectorsCannotAcquireAReadWindow(string fault)
    {
        using var f = new Fixture();
        var b = Binding();
        b = fault switch
        {
            "nonce" => b with { Selector = b.Selector with { Nonce = Guid.Empty } },
            "lease" => b with { LeaseId = Guid.Empty },
            "query" => b with { Query = (C.QueryKind)999 },
            "read" => b with { Read = (C.ReadKind)999 },
            "scope-type" => b with { Scope = Vault() },
            "operation" => b with { Selector = b.Selector with { Operation = "unrecognized" } },
            "variant" => b with { Selector = b.Selector with { Variant = "unrecognized" } },
            "case" => b with { Selector = b.Selector with { Case = "unrecognized" } },
            "control" => b with { Selector = b.Selector with { Scope = "original\nscope" } },
            _ => Binding(C.QueryKind.OperationUpdateNotification) with
            {
                Selector = Binding(C.QueryKind.OperationDeleteNotification).Selector
            }
        };
        await Assert.That(() => f.Source.Arm(b)).Throws<ArgumentException>();
        await Assert.That(f.MetadataCredential.Scopes.Count).IsEqualTo(0);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DeclarationOfAuthorityMustSeparateMetadataAndProtectedReadRoles(bool protectedRole)
    {
        using var f = new Fixture();
        var metadata = new C.Authority("metadata", f.MetadataCredential, f.Backend,
            protectedRole ? C.Access.Metadata : C.Access.ProtectedConfiguration);
        var material = new C.Authority("protected", f.ProtectedCredential, f.Backend,
            protectedRole ? C.Access.Metadata : C.Access.ProtectedConfiguration);
        await Assert.That(() => new C(metadata, material, Limits, f.Time)).Throws<ArgumentException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("omitted")]
    [Arguments("null")]
    [Arguments("false")]
    [Arguments("true")]
    [Arguments("dynamic")]
    [Arguments("hidden")]
    public async Task ProtectedAttributeActionPreservesNativeValuesAndNullableSecretAuthority(string state)
    {
        using var f = new Fixture();
        var destination = f.Backend.Resource["properties"]!["destination"]!["properties"]!;
        var properties = destination["deliveryAttributeMappings"]![0]!["properties"]!.AsObject();
        if (state == "omitted") properties.Remove("isSecret");
        if (state == "null") properties["isSecret"] = null;
        if (state == "false") properties["isSecret"] = false;
        if (state == "hidden") properties.Remove("value");
        if (state == "dynamic") destination["deliveryAttributeMappings"] = JsonNode.Parse(
            """[{"name":"x-dynamic","type":"Dynamic","properties":{"sourceField":"data.objectName"}}]""");
        using var result = await f.Collect(Binding(C.QueryKind.GetNotificationDeliveryAttributes, C.ReadKind.DeliveryAttributes));
        await Assert.That(result.InventoryComplete).IsTrue();
        await Assert.That(result.ProtectedValuesComplete).IsEqualTo(state is "false" or "true" or "dynamic");
        var attribute = result.Attributes.Single();
        await Assert.That(attribute.IsSecret).IsEqualTo(state is "omitted" or "null" or "dynamic" ? (bool?)null : state != "false");
        await Assert.That(attribute.SecretFlagPresence).IsEqualTo(state == "null" ? C.Presence.Null :
            state is "omitted" or "dynamic" ? C.Presence.Omitted : C.Presence.Value);
        if (state == "hidden")
        {
            await Assert.That(attribute.ValuePresence).IsEqualTo(C.Presence.Omitted);
            await Assert.That(attribute.Value).IsNull();
        }
        else await Assert.That(attribute.Value!.Reveal()).IsEqualTo(state == "dynamic" ? "data.objectName" : Protected);
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("complete")]
    [Arguments("duplicate")]
    [Arguments("error")]
    [Arguments("page-bound")]
    public async Task ProtectedAttributePaginationUsesNativeMappingsAndRetainsPartialMaterial(string scenario)
    {
        using var f = new Fixture(limits: scenario == "page-bound" ? Limits with { MaximumPages = 1 } : Limits);
        f.Backend.Pages = 2;
        f.Backend.Scenario = scenario;
        using var result = await f.Collect(Binding(C.QueryKind.GetNotificationDeliveryAttributes, C.ReadKind.DeliveryAttributes));
        await Assert.That(result.InventoryComplete).IsEqualTo(scenario == "complete");
        await Assert.That(result.Attributes.Count).IsEqualTo(scenario == "complete" ? 2 : 1);
        await Assert.That(result.Attributes[0].Value!.Reveal()).IsEqualTo(Protected);
        foreach (var request in f.Backend.Requests)
            await Assert.That(request.Method).IsEqualTo("POST");
        var material = result.Attributes[0].Value!;
        result.Dispose();
        await Assert.That(() => material.Reveal()).Throws<ObjectDisposedException>();
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("full-omitted")]
    [Arguments("full-null")]
    [Arguments("full-masked")]
    [Arguments("full-base-only")]
    [Arguments("full-http")]
    [Arguments("full-fragment")]
    [Arguments("full-userinfo")]
    [Arguments("full-number")]
    public async Task FullUrlActionRequiresAnActualCompleteProtectedNativeEndpoint(string fault)
    {
        using var f = new Fixture();
        f.Backend.Fault = fault;
        using var result = await f.Collect(Binding(C.QueryKind.GetNotificationFullUrl, C.ReadKind.FullUrl));
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.FullUrl).IsNull();
        await Assert.That(result.ResourceAbsent).IsNull();
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("events-omitted")]
    [Arguments("events-null")]
    [Arguments("events-empty")]
    [Arguments("events-three")]
    [Arguments("events-duplicate")]
    public async Task NativeEventSetsRetainPresenceWithoutAssumingAllEvents(string scenario)
    {
        using var f = new Fixture();
        var filter = f.Backend.Resource["properties"]!["filter"]!.AsObject();
        if (scenario == "events-omitted") filter.Remove("includedEventTypes");
        if (scenario == "events-null") filter["includedEventTypes"] = null;
        if (scenario == "events-empty") filter["includedEventTypes"] = new JsonArray();
        if (scenario == "events-three") filter["includedEventTypes"] = JsonNode.Parse(
            """["Microsoft.KeyVault.SecretNewVersionCreated","Microsoft.KeyVault.SecretNearExpiry","Microsoft.KeyVault.SecretExpired"]""");
        if (scenario == "events-duplicate") filter["includedEventTypes"] = JsonNode.Parse(
            """["Microsoft.KeyVault.SecretExpired","Microsoft.KeyVault.SecretExpired"]""");
        using var result = await f.Collect(Binding(read: C.ReadKind.Configuration));
        await Assert.That(result.ResponseComplete).IsEqualTo(scenario != "events-duplicate");
        if (!result.ResponseComplete) return;
        var row = result.Notifications.Single();
        await Assert.That(row.EventsPresence).IsEqualTo(scenario == "events-omitted" ? C.Presence.Omitted :
            scenario == "events-null" ? C.Presence.Null : C.Presence.Value);
        await Assert.That(row.Configuration is not null).IsEqualTo(scenario == "events-three");
        if (scenario == "events-three") await Assert.That(row.Configuration!.Events.Count).IsEqualTo(3);
    }

    [Test]
    [Arguments("root-status")]
    [Arguments("root-provisioning")]
    [Arguments("case-only")]
    [Arguments("empty-error")]
    [Arguments("success-not-found")]
    public async Task RootAndErrorAmbiguityCannotProduceResourceOrAbsenceProof(string fault)
    {
        using var f = new Fixture();
        f.Backend.Fault = fault;
        if (fault is "empty-error" or "success-not-found") f.Backend.Status = 404;
        using var result = await f.Collect(Binding());
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.ResourceAbsent).IsNull();
    }

    [Test]
    public async Task EmptyInventoryIsCompleteButNeverConcreteAbsenceOrPrincipalProof()
    {
        using var f = new Fixture();
        f.Backend.Fault = "empty-inventory";
        using var result = await f.Collect(Binding(C.QueryKind.ListNotifications, C.ReadKind.Inventory));
        await Assert.That(result.InventoryComplete).IsTrue();
        await Assert.That(result.Notifications.Count).IsEqualTo(0);
        await Assert.That(result.ResourceAbsent).IsNull();
        await Assert.That(result.PrincipalQualified).IsFalse();
        await Assert.That(result.Pages).IsEqualTo(1);
    }

    [Test]
    public async Task MetadataReadDoesNotRetainProtectedHeaderValuesOrFullCallback()
    {
        using var f = new Fixture();
        using var result = await f.Collect(Binding());
        var row = result.Notifications.Single();
        await Assert.That(row.Attributes.Single().Value).IsNull();
        await Assert.That(row.Attributes.Single().IsSecret).IsTrue();
        await Assert.That(row.Configuration).IsNull();
        await Assert.That(result.FullUrl).IsNull();
        await Assert.That(f.ProtectedCredential.Scopes.Count).IsEqualTo(0);
    }

    [Test]
    public async Task AlreadyCanceledInvocationConsumesItsWindowWithoutCallingCredentialOrTransport()
    {
        using var f = new Fixture();
        var b = Binding();
        var window = f.Source.Arm(b);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.That(async () => await f.Source.CollectAsync(window, b, canceled.Token)).Throws<OperationCanceledException>();
        await Assert.That(async () => await f.Source.CollectAsync(window, b)).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        await Assert.That(f.MetadataCredential.Scopes.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("lost-send")]
    [Arguments("late-body-expiry")]
    public async Task TransportFailureOrLateClockExpiryDoesNotReplayOrReturnNativeSuccess(string fault)
    {
        using var f = new Fixture();
        f.Backend.Fault = fault;
        if (fault == "late-body-expiry") f.Backend.AfterRead = () => f.Time.WallTicks += Limits.Timeout.Ticks;
        using var result = await f.Collect(Binding());
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(result.ResourceAbsent).IsNull();
        await ClearedAndBorrowed(f);
    }

    private static async Task ClearedAndBorrowed(Fixture f)
    {
        foreach (var storage in f.Backend.Buffers)
            await Assert.That(storage.All(value => value == 0)).IsTrue();
        await Assert.That(f.MetadataCredential.Disposed).IsFalse();
        await Assert.That(f.ProtectedCredential.Disposed).IsFalse();
        await Assert.That(f.Backend.Disposed).IsFalse();
    }

    private sealed class Fixture : IDisposable
    {
        internal readonly Clock Time = new();
        internal readonly Credential MetadataCredential = new("metadata-reader");
        internal readonly Credential ProtectedCredential = new("protected-reader");
        internal readonly Backend Backend = new();
        internal readonly C Source;
        internal Fixture(C.Limits? limits = null, bool protectedAuthority = true)
        {
            Source = new(new("metadata-label", MetadataCredential, Backend, C.Access.Metadata),
                protectedAuthority ? new("protected-label", ProtectedCredential, Backend, C.Access.ProtectedConfiguration) : null,
                limits ?? Limits, Time);
        }
        internal ValueTask<C.Measurement> Collect(C.Binding b) => Source.CollectAsync(Source.Arm(b), b);
        public void Dispose() { Backend.Dispose(); MetadataCredential.Dispose(); ProtectedCredential.Dispose(); }
    }

    private sealed class Credential(string token) : TokenCredential, IDisposable
    {
        internal readonly List<string> Scopes = [];
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource CancellationObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Action? BeforeToken;
        internal bool Block, Throw, Disposed;
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken)
        {
            Scopes.AddRange(context.Scopes);
            using var registration = cancellationToken.Register(() => CancellationObserved.TrySetResult());
            Entered.TrySetResult();
            if (Block) await Release.Task.ConfigureAwait(false);
            BeforeToken?.Invoke();
            if (Throw) throw new InvalidOperationException(Protected + Resource);
            return new(token, DateTimeOffset.MaxValue);
        }
        public void Dispose() => Disposed = true;
    }

    private sealed record RequestRow(string Method, string Uri, string? Authorization, string? Body);

    // This independent resource backend never invokes the selected SecretKit
    // adapter, manufactures an Operation, or derives state from a success result.
    private sealed class Backend : HttpPipelineTransport, IDisposable
    {
        private readonly HttpClient client;
        private readonly HttpClientTransport transport;
        internal readonly JsonObject Resource = JsonNode.Parse($$$$"""
            {"id":"{{{{AzureNotificationAdministrationCollectorTests.Resource}}}}","name":"notify-subscription","type":"Microsoft.EventGrid/eventSubscriptions",
            "properties":{"topic":"{{{{VaultId}}}}","provisioningState":"Succeeded",
            "destination":{"endpointType":"WebHook","properties":{"endpointUrl":"{{{{Endpoint}}}}","endpointBaseUrl":"https://observer.invalid",
            "deliveryAttributeMappings":[{"name":"x-secret","type":"Static","properties":{"value":"{{{{Protected}}}}","isSecret":true}}]}},
            "filter":{"includedEventTypes":["Microsoft.KeyVault.SecretNewVersionCreated","Microsoft.KeyVault.SecretExpired"]}}}
            """)!.AsObject();
        internal readonly List<RequestRow> Requests = [];
        internal readonly List<byte[]> Buffers = [];
        internal readonly TaskCompletionSource SendEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource BodyEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource CancellationObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Request? LastRequest;
        internal string? Fault, Next, Barrier, Scenario;
        internal Action? AfterRead;
        internal int Pages = 1, Status = 200;
        internal bool Disposed;

        internal Backend()
        {
            client = new(new Handler(async (request, token) =>
            {
                Requests.Add(new(request.Method.Method, request.RequestUri!.AbsoluteUri,
                    request.Headers.Authorization?.ToString(), request.Content is null ? null : await request.Content.ReadAsStringAsync(token)));
                using var registration = token.Register(() => CancellationObserved.TrySetResult());
                SendEntered.TrySetResult();
                if (Barrier == "send") await Release.Task.ConfigureAwait(false);
                if (Fault == "lost-send") throw new HttpRequestException(Protected + Resource);
                int status = Fault == "redirect" ? 302 : Scenario == "error" && Requests.Count == 2 ? 500 : Status;
                string body = Body(request.RequestUri!, status);
                var response = new HttpResponseMessage((HttpStatusCode)status)
                {
                    Content = new StreamContent(new BodyStream(Encoding.UTF8.GetBytes(body), this, Barrier == "body", token))
                };
                response.Content.Headers.ContentType = new(Fault == "content-type" ? "text/plain" : "application/json");
                response.Headers.TryAddWithoutValidation("x-ms-request-id", "native-notification-" + Requests.Count);
                if (Fault == "redirect") response.Headers.TryAddWithoutValidation("Location", "https://evil.invalid/");
                if (Fault == "encoding") response.Content.Headers.TryAddWithoutValidation("Content-Encoding", "gzip");
                if (Fault == "range") response.Content.Headers.TryAddWithoutValidation("Content-Range", "bytes 0-1/10");
                if (Fault == "length") response.Content.Headers.TryAddWithoutValidation("Content-Length", "999");
                if (Fault == "header-bound") response.Headers.TryAddWithoutValidation("x-large", new string('x', 4097));
                return response;
            }));
            transport = new(client);
        }

        private string Body(Uri uri, int status)
        {
            if (Fault == "empty-error") return """{"error":{}}""";
            if (Fault == "success-not-found") return Resource.ToJsonString();
            if (status >= 400) return """{"error":{"code":"ResourceNotFound","message":"notification-protected-sentinel"}}""";
            if (Fault == "root-error") return """{"error":{"code":"Unexpected","message":"notification-protected-sentinel"}}""";
            if (Fault == "null-root") return "null";
            if (Fault == "depth") return new string('[', 20) + "0" + new string(']', 20);
            if (Fault == "body-bound") return new string(' ', 65537);
            var row = Resource.DeepClone().AsObject();
            if (Fault == "wrong-id") row["id"] = AzureNotificationAdministrationCollectorTests.Resource + "-other";
            if (Fault == "wrong-topic") row["properties"]!["topic"] = VaultId + "-other";
            if (Fault == "wrong-type") row["type"] = "Microsoft.KeyVault/vaults";
            string path = uri.AbsolutePath;
            if (path.EndsWith("/getFullUrl", StringComparison.Ordinal))
                return Fault switch
                {
                    "full-omitted" => "{}",
                    "full-null" => """{"endpointUrl":null}""",
                    "full-masked" => """{"endpointUrl":"*****"}""",
                    "full-base-only" => """{"endpointBaseUrl":"https://observer.invalid"}""",
                    "full-http" => """{"endpointUrl":"http://observer.invalid"}""",
                    "full-fragment" => """{"endpointUrl":"https://observer.invalid#fragment"}""",
                    "full-userinfo" => """{"endpointUrl":"https://user@observer.invalid"}""",
                    "full-number" => """{"endpointUrl":1}""",
                    _ => JsonSerializer.Serialize(new { endpointUrl = Endpoint })
                };
            if (path.EndsWith("/getDeliveryAttributes", StringComparison.Ordinal))
            {
                var values = row["properties"]!["destination"]!["properties"]!["deliveryAttributeMappings"]!.DeepClone();
                if (Requests.Count == 2 && Scenario != "duplicate") values[0]!["name"] = "x-second";
                var page = new JsonObject { ["value"] = values };
                if (Requests.Count < Pages) page["nextLink"] = Origin + path + "?api-version=2025-02-15&$skipToken=next";
                return page.ToJsonString();
            }
            if (path == Collection)
            {
                if (Fault == "empty-inventory") return """{"value":[]}""";
                if (Requests.Count == 2 && Scenario != "duplicate")
                {
                    row["name"] = "second-subscription";
                    row["id"] = Collection + "/second-subscription";
                    if (Scenario == "extra-scope") row["properties"]!["topic"] = VaultId + "-other";
                }
                var page = new JsonObject { ["value"] = new JsonArray(row) };
                if (Requests.Count < Pages) page["nextLink"] = Origin + Collection + "?api-version=2025-02-15&$skipToken=next";
                if (Next is not null) page["nextLink"] = Next;
                return page.ToJsonString();
            }
            string text = row.ToJsonString();
            if (Fault == "root-status") row["status"] = "Failed";
            if (Fault == "root-provisioning") row["provisioningState"] = "Failed";
            if (Fault is "root-status" or "root-provisioning") text = row.ToJsonString();
            if (Fault == "case-only") text = text.Replace("\"provisioningState\":", "\"ProvisioningState\":", StringComparison.Ordinal);
            if (Fault == "duplicate-field") text = text.Replace("\"provisioningState\":", "\"provisioningState\":\"Failed\",\"provisioningState\":", StringComparison.Ordinal);
            if (Fault == "case-conflict") text = text.Replace("\"provisioningState\":", "\"ProvisioningState\":\"Failed\",\"provisioningState\":", StringComparison.Ordinal);
            return text;
        }
        public override Request CreateRequest() => LastRequest = transport.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override ValueTask ProcessAsync(HttpMessage message) => transport.ProcessAsync(message);
        public void Dispose() { Disposed = true; client.Dispose(); }
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }

    // Composition, not MemoryStream inheritance: either async overload reaches
    // the exact cancellation and borrowed-buffer lifetime barrier.
    private sealed class BodyStream(byte[] bytes, Backend backend, bool block, CancellationToken actualToken) : Stream
    {
        private readonly MemoryStream source = new(bytes, false);
        public override bool CanRead => true;
        public override bool CanWrite => false;
        public override bool CanSeek => false;
        public override long Length => source.Length;
        public override long Position { get => source.Position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException("async-only");
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment) && segment.Array is { } storage)
                backend.Buffers.Add(storage);
            if (block)
            {
                buffer.Span.Fill(0x5a);
                using var actual = actualToken.Register(() => backend.CancellationObserved.TrySetResult());
                using var read = cancellationToken.Register(() => backend.CancellationObserved.TrySetResult());
                backend.BodyEntered.TrySetResult();
                await backend.Release.Task.ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
            int count = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            backend.AfterRead?.Invoke();
            return count;
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) source.Dispose();
            base.Dispose(disposing);
        }
    }

    private sealed class Clock : TimeProvider
    {
        internal long Ticks, WallTicks;
        private readonly List<Hook> timers = [];
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override DateTimeOffset GetUtcNow() => Now.AddTicks(WallTicks);
        public override long GetTimestamp() => Ticks;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new Hook(this, callback, state) { Due = Ticks + dueTime.Ticks };
            timers.Add(timer);
            return timer;
        }
        internal void Advance(TimeSpan amount)
        {
            Ticks += amount.Ticks;
            WallTicks += amount.Ticks;
            foreach (var timer in timers.ToArray())
                if (timer.Due <= Ticks) { timer.Due = long.MaxValue; timer.Fire(); }
        }
        private sealed class Hook(Clock clock, TimerCallback callback, object? state) : ITimer
        {
            internal long Due;
            internal void Fire() => callback(state);
            public bool Change(TimeSpan dueTime, TimeSpan period) { Due = clock.Ticks + dueTime.Ticks; return true; }
            public void Dispose() => Due = long.MaxValue;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
