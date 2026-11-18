using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management.Tests;

public sealed class SubscriptionAdministrationTests
{
    private const string First = "33333333-3333-3333-3333-333333333333";
    private const string Second = "11111111-1111-1111-1111-111111111111";
    private const string Tenant = "22222222-2222-2222-2222-222222222222";
    private const string Next = "https://management.azure.com/subscriptions?api-version=2022-12-01&$skiptoken=next";

    private static JsonObject Subscription(string id) => new()
    {
        ["id"] = "/subscriptions/" + id,
        ["subscriptionId"] = id,
        ["displayName"] = "subscription-canary-" + id,
        ["state"] = "Enabled",
        ["tenantId"] = Tenant
    };

    private static string Page(JsonArray items, string? next = null) =>
        new JsonObject { ["value"] = items, ["nextLink"] = next }.ToJsonString();

    [Test]
    public async Task SubscriptionSupportDescriptorPreservesNativeRevisions()
    {
        var subscriptions = OperationSupport.Inventory.Single(o => o.Operation == ManagementOperationFamily.SubscriptionList);
        await Assert.That(subscriptions.ApiRevision).IsEqualTo("2022-12-01");
        await Assert.That(subscriptions.SuccessfulHttpStatuses).IsEquivalentTo([200]);
        await Assert.That(OperationSupport.Inventory.Where(o => o.Operation >= ManagementOperationFamily.NotificationCreateOrUpdate)
            .Select(o => o.ApiRevision).Distinct().ToArray()).IsEquivalentTo(["2025-02-15"]);
    }

    [Test]
    public async Task SubscriptionDiscoveryProjectsMetadataInProviderOrderAcrossPages()
    {
        var credential = new Credential();
        var backend = new WireBackend((request, _) =>
        {
            if (request.Method != HttpMethod.Get || request.RequestUri!.Host != "management.azure.com" ||
                request.RequestUri.AbsolutePath != "/subscriptions" ||
                !request.RequestUri.Query.Contains("api-version=2022-12-01", StringComparison.Ordinal))
                throw new InvalidOperationException("Unexpected subscription discovery authority.");
            return Task.FromResult(WireBackend.Json(200,
                request.RequestUri.Query.Contains("skiptoken", StringComparison.Ordinal)
                    ? Page(new JsonArray(Subscription(Second)))
                    : Page(new JsonArray(Subscription(First)), Next)));
        });

        var result = await new VaultAdministration(credential, backend).ListSubscriptionsAsync();

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Complete).IsTrue();
        await Assert.That(result.Items.Select(item => item.SubscriptionId)
            .SequenceEqual([Guid.Parse(First), Guid.Parse(Second)])).IsTrue();
        await Assert.That(result.Items[0].Id.ToString()).IsEqualTo("/subscriptions/" + First);
        await Assert.That(result.Items[0].DisplayName).IsEqualTo("subscription-canary-" + First);
        await Assert.That(result.Items[0].State).IsEqualTo("Enabled");
        await Assert.That(result.Items[0].TenantId).IsEqualTo(Guid.Parse(Tenant));
        await Assert.That(JsonSerializer.Serialize(result.Items[0])).IsEqualTo("{}");
        await Assert.That(result.Items[0].ToString().Contains(First, StringComparison.Ordinal)).IsFalse();
        await Assert.That(credential.Audiences.Distinct().ToArray())
            .IsEquivalentTo(["https://management.azure.com/.default"]);
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task PageAndItemBudgetsRetainPartialResultsWithoutFollowingContinuation(bool pageBudget)
    {
        var backend = new WireBackend((request, _) =>
        {
            if (request.RequestUri!.Query.Contains("skiptoken", StringComparison.Ordinal))
                throw new InvalidOperationException("Enumeration exceeded the selected budget.");
            return Task.FromResult(WireBackend.Json(200,
                Page(new JsonArray(Subscription(First)), Next)));
        });
        var limits = pageBudget ? new CollectionLimits(1, 10) : new CollectionLimits(4, 1);

        var result = await new VaultAdministration(new Credential(), backend).ListSubscriptionsAsync(limits);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(result.Items.Select(item => item.SubscriptionId).ToArray()).IsEquivalentTo([Guid.Parse(First)]);
    }

    [Test]
    public async Task OversizedPageRetainsOnlyItemBudgetAndReportsIncomplete()
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            Page(new JsonArray(Subscription(First), Subscription(Second))))));

        var result = await new VaultAdministration(new Credential(), backend)
            .ListSubscriptionsAsync(new CollectionLimits(maximumItems: 1));

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(result.Items.Select(item => item.SubscriptionId).ToArray()).IsEquivalentTo([Guid.Parse(First)]);
    }

    [Test]
    [Arguments("missing-subscription")]
    [Arguments("invalid-subscription")]
    [Arguments("empty-subscription")]
    [Arguments("missing-name")]
    [Arguments("empty-name")]
    [Arguments("blank-name")]
    [Arguments("missing-id")]
    [Arguments("substituted-id")]
    [Arguments("extra-id-segment")]
    [Arguments("empty-tenant")]
    public async Task MalformedSubscriptionCannotBecomePickerMetadata(string fault)
    {
        var item = Subscription(First);
        switch (fault)
        {
            case "missing-subscription": item.Remove("subscriptionId"); break;
            case "invalid-subscription": item["subscriptionId"] = "invalid-canary"; break;
            case "empty-subscription": item["subscriptionId"] = Guid.Empty.ToString(); break;
            case "missing-name": item.Remove("displayName"); break;
            case "empty-name": item["displayName"] = ""; break;
            case "blank-name": item["displayName"] = " \t"; break;
            case "missing-id": item.Remove("id"); break;
            case "substituted-id": item["id"] = "/subscriptions/" + Second; break;
            case "extra-id-segment": item["id"] = "/subscriptions/" + First + "/resourceGroups/group"; break;
            case "empty-tenant": item["tenantId"] = Guid.Empty.ToString(); break;
            default: throw new InvalidOperationException("Unknown subscription fixture.");
        }
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200, Page(new JsonArray(item)))));

        var result = await new VaultAdministration(new Credential(), backend).ListSubscriptionsAsync();

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(result.Items.Count).IsEqualTo(0);
    }

    [Test]
    public async Task OverflowRowsAreValidatedEvenAfterItemBudgetIsFull()
    {
        var invalid = Subscription(Second);
        invalid.Remove("displayName");
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            Page(new JsonArray(Subscription(First), invalid)))));

        var result = await new VaultAdministration(new Credential(), backend)
            .ListSubscriptionsAsync(new CollectionLimits(maximumItems: 1));

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(result.Items.Count).IsEqualTo(1);
    }

    [Test]
    public async Task OmittedOptionalMetadataDoesNotSupplyTenantOrState()
    {
        var item = Subscription(First);
        item.Remove("tenantId");
        item.Remove("state");
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200, Page(new JsonArray(item)))));

        var result = await new VaultAdministration(new Credential(), backend).ListSubscriptionsAsync();

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Items.Single().TenantId).IsNull();
        await Assert.That(result.Items.Single().State).IsNull();
    }

    [Test]
    [Arguments("https://untrusted.example.test/subscriptions?api-version=2022-12-01")]
    [Arguments("https://management.azure.com/subscriptions?api-version=2026-02-01")]
    [Arguments("https://management.azure.com/tenants?api-version=2022-12-01")]
    public async Task UnselectedContinuationCannotEscapeSubscriptionAuthority(string next)
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            Page(new JsonArray(Subscription(First)), next))));

        var result = await new VaultAdministration(new Credential(), backend).ListSubscriptionsAsync();

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(result.Items.Count).IsEqualTo(0);
    }

    [Test]
    public async Task CancellationPropagatesDuringSubscriptionEnumeration()
    {
        using var cancellation = new CancellationTokenSource();
        var backend = new WireBackend((_, _) =>
        {
            cancellation.Cancel();
            return Task.FromResult(WireBackend.Json(200, Page(new JsonArray(Subscription(First)))));
        });

        await Assert.That(async () => await new VaultAdministration(new Credential(), backend)
            .ListSubscriptionsAsync(cancellationToken: cancellation.Token)).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task SubscriptionCollectionDeadlineCannotPublishALatePage()
    {
        var time = new BoundaryBudgetTests.ManualTime();
        var backend = new WireBackend((_, _) =>
        {
            time.FireDeadline();
            return Task.FromResult(WireBackend.Json(200, Page(new JsonArray(Subscription(First)))));
        });

        var result = await new VaultAdministration(new Credential(), backend, timeProvider: time)
            .ListSubscriptionsAsync(new CollectionLimits(timeout: TimeSpan.FromSeconds(1)));

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(result.Items.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments(403, SecretStatus.Denied)]
    [Arguments(429, SecretStatus.Throttled)]
    [Arguments(500, SecretStatus.Unavailable)]
    public async Task SubscriptionFailuresUseEstablishedInventoryOutcomes(int status, SecretStatus expected)
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(status,
            """{"error":{"code":"Rejected","message":"provider-canary"}}""")));

        var result = await new VaultAdministration(new Credential(), backend).ListSubscriptionsAsync();

        await Assert.That(result.Status).IsEqualTo(expected);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(result.Items.Count).IsEqualTo(0);
    }
}
