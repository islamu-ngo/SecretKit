using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Azure.ResourceManager.EventGrid;
using Azure.ResourceManager.EventGrid.Models;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    private const string AuthenticationAudience = "55555555-5555-5555-5555-555555555555";
    private const string AuthenticationEndpoint = "https://notification-auth.example.invalid/hook";

    // These tests characterize native configuration, not sender identity,
    // token validation, same-tenant authority, exclusion or remote closure.
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NotificationWebhookAuthenticationNativePairRoundtrips(bool uriAudience)
    {
        string audience = uriAudience ? "api://" + AuthenticationAudience : AuthenticationAudience;
        using var wire = new AuthenticationFieldWire(tenant: Tenant, audience: audience);
        using var http = new HttpClient(wire);
        var writer = AuthenticationFieldClient(http);
        var data = new EventGridSubscriptionData
        {
            Destination = new WebHookEventSubscriptionDestination
            {
                Endpoint = new Uri(AuthenticationEndpoint),
                AzureActiveDirectoryTenantId = Guid.Parse(Tenant),
                UriOrAzureActiveDirectoryApplicationId = audience
            }
        };
        var start = writer.GetEventSubscriptions(new ResourceIdentifier(Vault))
            .CreateOrUpdateAsync(WaitUntil.Started, "capture-notification", data);
        var operation = await start;
        await Assert.That(start.IsCompletedSuccessfully).IsTrue();
        // Native201 retains a pending operation even with Succeeded in the
        // resource body. Field readback must not be called write settlement.
        await Assert.That(operation.HasCompleted).IsFalse();
        await Assert.That(wire.Requests.Count).IsEqualTo(1);
        using var sent = JsonDocument.Parse(wire.Requests[0].Body!);
        var properties = sent.RootElement.GetProperty("properties").GetProperty("destination").GetProperty("properties");
        await Assert.That(properties.GetProperty("azureActiveDirectoryTenantId").GetGuid()).IsEqualTo(Guid.Parse(Tenant));
        await Assert.That(properties.GetProperty("azureActiveDirectoryApplicationIdOrUri").GetString()).IsEqualTo(audience);

        // A new client issues a real GET; requested values are not readback.
        var readTask = AuthenticationFieldClient(http).GetEventSubscriptionResource(new ResourceIdentifier(Notification)).GetAsync();
        var resource = await readTask;
        var destination = (WebHookEventSubscriptionDestination)resource.Value.Data.Destination;
        await Assert.That(readTask.IsCompletedSuccessfully).IsTrue();
        await Assert.That(destination.AzureActiveDirectoryTenantId).IsEqualTo(Guid.Parse(Tenant));
        await Assert.That(destination.UriOrAzureActiveDirectoryApplicationId).IsEqualTo(audience);
        await Assert.That(operation.HasCompleted).IsFalse();
        await Assert.That(wire.Requests.Select(r => r.Method)).IsEquivalentTo([HttpMethod.Put, HttpMethod.Get]);
    }

    [Test]
    [Arguments("omitted")]
    [Arguments("null")]
    [Arguments("tenant-only")]
    [Arguments("audience-only")]
    [Arguments("empty-tenant")]
    public async Task NotificationWebhookAuthenticationNativeReadDoesNotSupplyMissingAuthority(string shape)
    {
        using var wire = new AuthenticationFieldWire(
            tenant: shape is "tenant-only" ? Tenant : shape == "empty-tenant" ? Guid.Empty.ToString() : null,
            audience: shape is "audience-only" or "empty-tenant" ? AuthenticationAudience : null,
            explicitNull: shape == "null");
        using var http = new HttpClient(wire);
        var read = AuthenticationFieldClient(http).GetEventSubscriptionResource(new ResourceIdentifier(Notification)).GetAsync();
        var resource = await read;
        var destination = (WebHookEventSubscriptionDestination)resource.Value.Data.Destination;
        await Assert.That(read.IsCompletedSuccessfully).IsTrue();
        await Assert.That(destination.AzureActiveDirectoryTenantId)
            .IsEqualTo(shape == "tenant-only" ? Guid.Parse(Tenant) : shape == "empty-tenant" ? Guid.Empty : null);
        await Assert.That(destination.UriOrAzureActiveDirectoryApplicationId)
            .IsEqualTo(shape is "audience-only" or "empty-tenant" ? AuthenticationAudience : null);
        await Assert.That(wire.Requests.Single().Method).IsEqualTo(HttpMethod.Get);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NotificationWebhookAuthenticationNativeReadReturnsActualFieldsNotRequestedPair(bool differentTenant)
    {
        string returnedTenant = differentTenant ? Assignment : Tenant;
        string returnedAudience = differentTenant ? AuthenticationAudience : "api://different-audience";
        using var wire = new AuthenticationFieldWire(Tenant, AuthenticationAudience)
        {
            ReadTenant = returnedTenant,
            ReadAudience = returnedAudience
        };
        using var http = new HttpClient(wire);
        var data = new EventGridSubscriptionData
        {
            Destination = new WebHookEventSubscriptionDestination
            {
                Endpoint = new Uri(AuthenticationEndpoint),
                AzureActiveDirectoryTenantId = Guid.Parse(Tenant),
                UriOrAzureActiveDirectoryApplicationId = AuthenticationAudience
            }
        };
        var started = await AuthenticationFieldClient(http).GetEventSubscriptions(new ResourceIdentifier(Vault))
            .CreateOrUpdateAsync(WaitUntil.Started, "capture-notification", data);
        await Assert.That(started.HasCompleted).IsFalse();
        var resource = await AuthenticationFieldClient(http).GetEventSubscriptionResource(new ResourceIdentifier(Notification)).GetAsync();
        var actual = (WebHookEventSubscriptionDestination)resource.Value.Data.Destination;
        await Assert.That(actual.AzureActiveDirectoryTenantId).IsEqualTo(Guid.Parse(returnedTenant));
        await Assert.That(actual.UriOrAzureActiveDirectoryApplicationId).IsEqualTo(returnedAudience);
        await Assert.That(actual.AzureActiveDirectoryTenantId != Guid.Parse(Tenant) ||
            actual.UriOrAzureActiveDirectoryApplicationId != AuthenticationAudience).IsTrue();
        await Assert.That(wire.Requests.Count).IsEqualTo(2);
    }

    private static ArmClient AuthenticationFieldClient(HttpClient http)
    {
        var options = new ArmClientOptions { Transport = new HttpClientTransport(http) };
        options.SetApiVersion("Microsoft.EventGrid/eventSubscriptions", "2025-02-15");
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        return new ArmClient(new Credential(), Subscription, options);
    }

    private sealed class AuthenticationFieldWire(string? tenant, string? audience, bool explicitNull = false) : HttpMessageHandler
    {
        internal sealed record Request(HttpMethod Method, string? Body);
        internal readonly List<Request> Requests = [];
        private readonly string? writeTenant = tenant;
        private readonly string? writeAudience = audience;
        internal string? ReadTenant = tenant;
        internal string? ReadAudience = audience;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri?.GetLeftPart(UriPartial.Authority) != "https://management.azure.com" ||
                request.RequestUri.AbsolutePath != Notification || request.RequestUri.Query != "?api-version=2025-02-15" ||
                request.Method != HttpMethod.Put && request.Method != HttpMethod.Get)
                throw new InvalidOperationException("authentication-field-route");
            Requests.Add(new(request.Method, request.Content is null ? null :
                await request.Content.ReadAsStringAsync(cancellationToken)));
            var properties = new JsonObject
            {
                ["endpointUrl"] = AuthenticationEndpoint,
                ["endpointBaseUrl"] = AuthenticationEndpoint,
                ["deliveryAttributeMappings"] = new JsonArray()
            };
            string? actualTenant = request.Method == HttpMethod.Put ? writeTenant : ReadTenant;
            string? actualAudience = request.Method == HttpMethod.Put ? writeAudience : ReadAudience;
            if (actualTenant is not null || explicitNull) properties["azureActiveDirectoryTenantId"] = actualTenant;
            if (actualAudience is not null || explicitNull) properties["azureActiveDirectoryApplicationIdOrUri"] = actualAudience;
            var body = new JsonObject
            {
                ["id"] = Notification,
                ["name"] = "capture-notification",
                ["type"] = "Microsoft.EventGrid/eventSubscriptions",
                ["properties"] = new JsonObject
                {
                    ["provisioningState"] = "Succeeded",
                    ["destination"] = new JsonObject { ["endpointType"] = "WebHook", ["properties"] = properties }
                }
            };
            var response = new HttpResponseMessage(request.Method == HttpMethod.Put ? HttpStatusCode.Created : HttpStatusCode.OK)
            {
                Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
            };
            response.Headers.TryAddWithoutValidation("x-ms-request-id", OperationId);
            return response;
        }
    }
}
