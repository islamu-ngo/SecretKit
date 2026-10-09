using System.Text.Json;
using Azure.ResourceManager.EventGrid;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management.Tests;

public sealed class NotificationAdministrationTests
{
    [Test]
    public async Task DirectSdkPatchResponseContract()
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(201, Resource())));
        var options = new Azure.ResourceManager.ArmClientOptions { Transport = backend };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        options.SetApiVersion("Microsoft.EventGrid/eventSubscriptions", "2025-02-15");
        var client = new Azure.ResourceManager.ArmClient(new Credential(), null, options);
        var operation = await client.GetEventSubscriptionResource(new Azure.Core.ResourceIdentifier(Path))
            .UpdateAsync(Azure.WaitUntil.Started, new Azure.ResourceManager.EventGrid.Models.EventGridSubscriptionPatch());
        await Assert.That(operation.HasCompleted).IsFalse();
    }
    private static NotificationScope Scope() => new(ScopeAuthorityTests.Scope(), "notification-canary");
    private static string Path => ScopeAuthorityTests.Id + "/providers/Microsoft.EventGrid/eventSubscriptions/notification-canary";
    private const string Endpoint = "https://delivery.example.test/events?key=protected-canary";
    private static string Resource(string? id = null, string state = "Succeeded", string? topic = null) =>
        JsonSerializer.Serialize(new
        {
            id = id ?? Path,
            name = "notification-canary",
            type = "Microsoft.EventGrid/eventSubscriptions",
            properties = new
            {
                topic = topic ?? ScopeAuthorityTests.Id,
                provisioningState = state,
                destination = new { endpointType = "WebHook", properties = new { endpointUrl = Endpoint } }
            }
        });
    private static NotificationConfiguration Configuration() =>
        new(Endpoint, [VaultNotificationEvent.SecretNewVersionCreated]);

    [Test]
    public async Task SevenNativeRoutesChangeStateAndProtectMaterial()
    {
        bool exists = false;
        string? deliveredEndpoint = null;
        var credential = new Credential();
        var backend = new WireBackend(async (request, token) =>
        {
            var uri = request.RequestUri!;
            if (uri.Host != "management.azure.com" || uri.Query != "?api-version=2025-02-15" ||
                request.Headers.Authorization is null)
                throw new InvalidOperationException("Incorrect notification authority.");
            if (request.Method == HttpMethod.Put || request.Method == HttpMethod.Patch)
            {
                if (uri.AbsolutePath != Path) throw new InvalidOperationException("Incorrect selected resource.");
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                // Native PATCH uses the properties object directly; PUT wraps it in properties.
                var properties = request.Method == HttpMethod.Patch ? body.RootElement :
                    body.RootElement.GetProperty("properties");
                deliveredEndpoint = properties.GetProperty("destination").GetProperty("properties").GetProperty("endpointUrl").GetString();
                if (properties.GetProperty("filter").GetProperty("includedEventTypes")[0].GetString() !=
                    "Microsoft.KeyVault.SecretNewVersionCreated") throw new InvalidOperationException("Wrong event filter.");
                exists = true;
                return WireBackend.Json(201, Resource());
            }
            if (request.Method == HttpMethod.Delete && uri.AbsolutePath == Path)
            {
                exists = false;
                return WireBackend.Json(204, "");
            }
            if (request.Method == HttpMethod.Post && uri.AbsolutePath == Path + "/getFullUrl")
                return WireBackend.Json(200, JsonSerializer.Serialize(new { endpointUrl = Endpoint }));
            if (request.Method == HttpMethod.Post && uri.AbsolutePath == Path + "/getDeliveryAttributes")
                return WireBackend.Json(200, """{"value":[{"name":"Authorization","type":"Static","properties":{"value":"credential-canary","isSecret":true}},{"name":"x-event","type":"Dynamic","properties":{"sourceField":"eventType"}}]}""");
            if (request.Method == HttpMethod.Get && uri.AbsolutePath == Path)
                return WireBackend.Json(exists ? 200 : 404, exists ? Resource() : "{}");
            if (request.Method == HttpMethod.Get && uri.AbsolutePath == ScopeAuthorityTests.Id + "/providers/Microsoft.EventGrid/eventSubscriptions")
                return WireBackend.Json(200, "{\"value\":[" + Resource() + "]}");
            throw new InvalidOperationException("Unexpected notification route.");
        });
        var client = new VaultAdministration(credential, backend);
        var scope = Scope();
        using var configuration = Configuration();
        var create = client.PrepareReceipt(scope, ManagementMutation.CreateOrUpdateNotification);
        var created = await client.CreateOrUpdateNotificationAsync(scope, configuration, create);
        await Assert.That(created.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(created.Value.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(create.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(exists).IsTrue();
        await Assert.That(deliveredEndpoint).IsEqualTo(Endpoint);
        await Assert.That(await created.Value.CheckStatusAsync()).IsEqualTo(SecretStatus.Success);
        await Assert.That(created.Value.State).IsEqualTo(NativeProvisioningState.Succeeded);
        var update = await client.UpdateNotificationAsync(scope, configuration,
            client.PrepareReceipt(scope, ManagementMutation.UpdateNotification));
        await Assert.That(update.Status).IsEqualTo(SecretStatus.Success);
        var get = await client.GetNotificationAsync(scope);
        await Assert.That(get.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(JsonSerializer.Serialize(get.Value).Contains("canary", StringComparison.Ordinal)).IsFalse();
        var list = await client.ListNotificationsAsync(scope.Vault, new CollectionLimits());
        await Assert.That(list.Complete).IsTrue();
        await Assert.That(list.Items.Count).IsEqualTo(1);
        var full = await client.GetNotificationFullUrlAsync(scope);
        await Assert.That(full.Status).IsEqualTo(SecretStatus.Success);
        using var url = full.Value;
        await Assert.That(url.Endpoint.Reveal()).IsEqualTo(Endpoint);
        await Assert.That(JsonSerializer.Serialize(url)).IsEqualTo("{}");
        var attributes = await client.GetNotificationDeliveryAttributesAsync(scope, new CollectionLimits());
        await Assert.That(attributes.Complete).IsTrue();
        await Assert.That(attributes.Items.Count).IsEqualTo(2);
        using var first = attributes.Items[0];
        using var second = attributes.Items[1];
        await Assert.That(first.Value.Reveal()).IsEqualTo("credential-canary");
        await Assert.That(first.IsSecret).IsTrue();
        await Assert.That(JsonSerializer.Serialize(first).Contains("canary", StringComparison.Ordinal)).IsFalse();
        var delete = client.PrepareReceipt(scope, ManagementMutation.DeleteNotification);
        await Assert.That((await client.DeleteNotificationAsync(scope, delete)).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(delete.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(exists).IsFalse();
        await Assert.That((await client.GetNotificationAsync(scope)).Status).IsEqualTo(SecretStatus.Absent);
        await Assert.That(credential.Audiences.All(a => a == "https://management.azure.com/.default")).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SubstitutedReturnedCoordinatesFailClosed(bool wrongTopic)
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            wrongTopic ? Resource(topic: ScopeAuthorityTests.Id.Replace("vault-canary", "other-vault")) :
                Resource(id: Path.Replace("notification-canary", "other-name")))));
        var result = await new VaultAdministration(new Credential(), backend).GetNotificationAsync(Scope());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task LostCommittedResponseDoesNotReplayOrEraseReceipt()
    {
        bool exists = false;
        var backend = new WireBackend((_, _) =>
        {
            if (exists) throw new InvalidOperationException("Mutation was replayed.");
            exists = true;
            throw new IOException("protected-provider-error");
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Scope();
        using var configuration = Configuration();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.CreateOrUpdateNotification);
        var result = await client.CreateOrUpdateNotificationAsync(scope, configuration, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(exists).IsTrue();
        await Assert.That((await client.CreateOrUpdateNotificationAsync(scope, configuration, receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task ReceiptBindsClientExactScopeAndOperationBeforeAuthentication()
    {
        var credential = new Credential();
        var backend = new WireBackend((_, _) => throw new InvalidOperationException("Unselected mutation."));
        var client = new VaultAdministration(credential, backend);
        var scope = Scope();
        using var configuration = Configuration();
        var foreign = new VaultAdministration(credential, backend).PrepareReceipt(scope, ManagementMutation.CreateOrUpdateNotification);
        await Assert.That((await client.CreateOrUpdateNotificationAsync(scope, configuration, foreign)).Status).IsEqualTo(SecretStatus.Invalid);
        var receipt = client.PrepareReceipt(scope, ManagementMutation.CreateOrUpdateNotification);
        await Assert.That((await client.CreateOrUpdateNotificationAsync(Scope(), configuration, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That((await client.UpdateNotificationAsync(scope, configuration, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(credential.Audiences.Count).IsEqualTo(0);
    }

    [Test]
    public async Task PendingCreationUsesOnlyExplicitSelectedResourceStatusReads()
    {
        bool completed = false;
        bool allowStatus = false;
        var backend = new WireBackend((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath != Path) throw new InvalidOperationException("Status escaped selection.");
            if (request.Method == HttpMethod.Put)
                return Task.FromResult(WireBackend.Json(201, Resource(state: "Creating")));
            if (!allowStatus || request.Method != HttpMethod.Get)
                throw new InvalidOperationException("Hidden polling.");
            completed = true;
            return Task.FromResult(WireBackend.Json(200, Resource()));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Scope();
        using var configuration = Configuration();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.CreateOrUpdateNotification);
        var result = await client.CreateOrUpdateNotificationAsync(scope, configuration, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(completed).IsFalse();
        allowStatus = true;
        await Assert.That(await result.Value.CheckStatusAsync()).IsEqualTo(SecretStatus.Success);
        await Assert.That(completed).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(result.Value.RuntimeDeliveryProven).IsFalse();
    }

    [Test]
    [Arguments(200)]
    [Arguments(202)]
    [Arguments(204)]
    public async Task DeleteDistinguishesPendingFromCompletedWithoutHiddenReads(int status)
    {
        bool deleted = false;
        var backend = new WireBackend((request, _) =>
        {
            if (request.Method != HttpMethod.Delete) throw new InvalidOperationException("Hidden status check.");
            deleted = status != 202;
            var response = WireBackend.Json(status, "");
            if (status == 202) response.Headers.TryAddWithoutValidation("Location",
                "https://management.azure.com" + Path + "?api-version=2025-02-15");
            return Task.FromResult(response);
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Scope();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.DeleteNotification);
        var result = await client.DeleteNotificationAsync(scope, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.State).IsEqualTo(status == 202 ? NativeProvisioningState.Pending : NativeProvisioningState.Succeeded);
        await Assert.That(deleted).IsEqualTo(status != 202);
        await Assert.That(receipt.Evidence).IsEqualTo(status == 202 ? DispatchEvidence.Pending : DispatchEvidence.Applied);
    }

    [Test]
    [Arguments("https://attacker.example.test/status?api-version=2025-02-15")]
    [Arguments("https://management.azure.com/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.EventGrid/operations/55555555-5555-5555-5555-555555555555?api-version=2025-02-15")]
    public async Task UnestablishedStatusUrlsRetainPossibleDispatchWithoutFollowing(string url)
    {
        bool requested = false;
        var backend = new WireBackend((request, _) =>
        {
            if (request.Method != HttpMethod.Delete) throw new InvalidOperationException("Forged status followed.");
            requested = true;
            var response = WireBackend.Json(202, "");
            response.Headers.TryAddWithoutValidation("Location", url);
            return Task.FromResult(response);
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Scope();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.DeleteNotification);
        await Assert.That((await client.DeleteNotificationAsync(scope, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(requested).IsTrue();
    }

    [Test]
    public async Task ListBudgetAndForgedContinuationAreObservable()
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            "{\"value\":[" + Resource() + "," + Resource() + "]}")));
        var client = new VaultAdministration(new Credential(), backend);
        var inventory = await client.ListNotificationsAsync(Scope().Vault, new CollectionLimits(maximumItems: 1));
        await Assert.That(inventory.Items.Count).IsEqualTo(1);
        await Assert.That(inventory.Complete).IsFalse();
        var forged = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            "{\"value\":[" + Resource() + "],\"nextLink\":\"https://attacker.example.test/list?api-version=2025-02-15\"}")));
        var rejected = await new VaultAdministration(new Credential(), forged).ListNotificationsAsync(Scope().Vault, new CollectionLimits());
        await Assert.That(rejected.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(rejected.Items.Count).IsEqualTo(0);
    }

    [Test]
    public async Task AttributeOverflowIsBoundedAndProtectedValuesHaveIndependentOwners()
    {
        using var header = new NotificationDeliveryAttribute("Authorization", NotificationAttributeKind.Static, "credential-canary");
        using var configuration = new NotificationConfiguration(Endpoint, [VaultNotificationEvent.SecretExpired], [header]);
        header.Dispose();
        await Assert.That(configuration.DeliveryAttributes[0].Value.Reveal()).IsEqualTo("credential-canary");
        await Assert.That(JsonSerializer.Serialize(configuration)).IsEqualTo("{}");
        await Assert.That(configuration.ToString()).IsEqualTo("[NotificationConfiguration]");
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            """{"value":[{"name":"x-one","type":"Static","properties":{"value":"credential-canary","isSecret":true}},{"name":"x-two","type":"Dynamic","properties":{"sourceField":"eventType"}}]}""")));
        var inventory = await new VaultAdministration(new Credential(), backend)
            .GetNotificationDeliveryAttributesAsync(Scope(), new CollectionLimits(maximumItems: 1));
        await Assert.That(inventory.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(inventory.Items.Count).IsEqualTo(1);
        await Assert.That(inventory.Complete).IsFalse();
        inventory.Items[0].Dispose();
    }

    [Test]
    public async Task ResponseByteBudgetPreventsProtectedUrlPublication()
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            JsonSerializer.Serialize(new { endpointUrl = "https://delivery.example.test/" + new string('x', 2000) }))));
        var result = await new VaultAdministration(new Credential(), backend, maximumResponseBytes: 1024)
            .GetNotificationFullUrlAsync(Scope());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task CancellationAtAuthenticatedSendKeepsUncertainCommittedState()
    {
        using var cancellation = new CancellationTokenSource();
        bool committed = false;
        ManagementReceipt? receipt = null;
        DispatchEvidence atSend = DispatchEvidence.NotDispatched;
        var backend = new WireBackend((_, token) =>
        {
            atSend = receipt!.Evidence;
            committed = true;
            cancellation.Cancel();
            token.ThrowIfCancellationRequested();
            throw new InvalidOperationException("Cancellation did not propagate.");
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Scope();
        receipt = client.PrepareReceipt(scope, ManagementMutation.CreateOrUpdateNotification);
        using var configuration = Configuration();
        bool canceled = false;
        try { await client.CreateOrUpdateNotificationAsync(scope, configuration, receipt, cancellation.Token); }
        catch (OperationCanceledException) { canceled = true; }
        await Assert.That(canceled).IsTrue();
        await Assert.That(committed).IsTrue();
        await Assert.That(atSend).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    [Arguments("Failed")]
    [Arguments("Unrecognized")]
    public async Task InitialNativeFailureStateCannotBecomeApplied(string state)
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(201, Resource(state: state))));
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Scope();
        using var configuration = Configuration();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.CreateOrUpdateNotification);
        var result = await client.CreateOrUpdateNotificationAsync(scope, configuration, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    public async Task PreSendCancellationAndCredentialFailureNeverAdvanceReceipts()
    {
        var credential = new Credential();
        var backend = new WireBackend((_, _) => throw new InvalidOperationException("Unexpected authenticated send."));
        var client = new VaultAdministration(credential, backend);
        var scope = Scope();
        using var configuration = Configuration();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.UpdateNotification);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        bool canceled = false;
        try { await client.UpdateNotificationAsync(scope, configuration, receipt, cancellation.Token); }
        catch (OperationCanceledException) { canceled = true; }
        await Assert.That(canceled).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(credential.Audiences.Count).IsEqualTo(0);
        var failing = new VaultAdministration(new Credential { Fail = true }, backend);
        var failingReceipt = failing.PrepareReceipt(scope, ManagementMutation.UpdateNotification);
        await Assert.That((await failing.UpdateNotificationAsync(scope, configuration, failingReceipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(failingReceipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    public async Task ValidNativeContinuationStopsAtPageBudget()
    {
        bool secondPage = false;
        var backend = new WireBackend((request, _) =>
        {
            if (request.RequestUri!.Query.Contains("skiptoken", StringComparison.Ordinal))
            {
                secondPage = true;
                return Task.FromResult(WireBackend.Json(200, """{"value":[]}"""));
            }
            var next = "https://management.azure.com" + ScopeAuthorityTests.Id +
                "/providers/Microsoft.EventGrid/eventSubscriptions?api-version=2025-02-15&$skiptoken=next";
            return Task.FromResult(WireBackend.Json(200, "{\"value\":[" + Resource() + "],\"nextLink\":" +
                JsonSerializer.Serialize(next) + "}"));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var bounded = await client.ListNotificationsAsync(Scope().Vault, new CollectionLimits(maximumPages: 1));
        await Assert.That(bounded.Items.Count).IsEqualTo(1);
        await Assert.That(bounded.Complete).IsFalse();
        await Assert.That(secondPage).IsFalse();
        var complete = await client.ListNotificationsAsync(Scope().Vault, new CollectionLimits(maximumPages: 2));
        await Assert.That(complete.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(complete.Complete).IsTrue();
        await Assert.That(secondPage).IsTrue();
    }

    [Test]
    public async Task UnknownDeliveryMappingCannotBecomeAnUnprotectedEscape()
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            """{"value":[{"name":"Authorization","type":"Unknown","properties":{"value":"credential-canary"}}]}""")));
        var result = await new VaultAdministration(new Credential(), backend)
            .GetNotificationDeliveryAttributesAsync(Scope(), new CollectionLimits());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(result.Items.Count).IsEqualTo(0);
    }
}
