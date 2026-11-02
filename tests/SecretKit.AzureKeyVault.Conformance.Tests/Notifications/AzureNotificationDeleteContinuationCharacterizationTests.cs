using System.Net;
using System.Text;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Azure.ResourceManager.EventGrid;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    // Public2025-02-15 DELETE examples issue distinct operation URLs. These
    // controlled responses characterize the installed SDK, not a live provider.
    private const string EventGridContinuationRoot = Origin + "/subscriptions/" + Subscription +
        "/resourceGroups/capture-group/providers/Microsoft.EventGrid/locations/eastus/";
    private const string EventGridLocation = EventGridContinuationRoot +
        "operationStatus/default/operationId/" + OperationId + "?api-version=2025-02-15";
    private const string EventGridAsyncOperation = EventGridContinuationRoot +
        "operationResults/" + OperationId + "/Spring/default?api-version=2025-02-15";

    [Test]
    [Arguments(true, 200, "Succeeded")]
    [Arguments(true, 200, "InProgress")]
    [Arguments(true, 200, "Deleting")]
    [Arguments(true, 401, "denied")]
    [Arguments(true, 403, "denied")]
    [Arguments(false, 200, "empty")]
    [Arguments(false, 204, "empty")]
    [Arguments(false, 202, "empty")]
    [Arguments(false, 401, "denied")]
    [Arguments(false, 403, "denied")]
    public async Task NotificationDeleteDocumentedContinuationRetainsNativeStatusAndHeaderPriority(
        bool asyncHeader, int status, string state)
    {
        using var transport = new EventGridContinuationTransport(asyncHeader, status, state);
        var options = new ArmClientOptions { Transport = transport };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        options.SetApiVersion("Microsoft.EventGrid/eventSubscriptions", "2025-02-15");
        var client = new ArmClient(new Credential(), Subscription, options);
        var start = client.GetEventSubscriptionResource(new ResourceIdentifier(Notification)).DeleteAsync(WaitUntil.Started);
        var operation = await start;
        await Assert.That(start.IsCompletedSuccessfully).IsTrue();
        await Assert.That(operation.HasCompleted).IsFalse();
        await Assert.That(transport.Requests.Count).IsEqualTo(1);
        var check = operation.UpdateStatusAsync().AsTask();
        if (status is 401 or 403)
        {
            await Assert.That(async () => await check).Throws<RequestFailedException>();
            await Assert.That(check.IsFaulted).IsTrue();
            var exception = check.Exception!.GetBaseException() as RequestFailedException;
            await Assert.That(exception!.Status).IsEqualTo(status);
        }
        else
        {
            var response = await check;
            await Assert.That(check.IsCompletedSuccessfully).IsTrue();
            await Assert.That(response.Status).IsEqualTo(status);
        }
        bool pending = status == 202 || asyncHeader && status == 200 && state != "Succeeded";
        if (pending)
            await Assert.That(operation.HasCompleted).IsFalse();
        else
            await Assert.That(operation.HasCompleted).IsTrue();
        await Assert.That(transport.Requests.Count).IsEqualTo(2);
        await Assert.That(transport.Requests[0].Method).IsEqualTo("DELETE");
        await Assert.That(transport.Requests[0].Uri).IsEqualTo(Origin + Notification + "?api-version=2025-02-15");
        await Assert.That(transport.Requests[1].Method).IsEqualTo("GET");
        await Assert.That(transport.Requests[1].Uri).IsEqualTo(
            asyncHeader ? EventGridAsyncOperation : EventGridLocation);
        await Assert.That(transport.Authorizations.Distinct().Count()).IsEqualTo(1);
        await Assert.That(transport.Authorizations[0]).IsEqualTo("Bearer selected-capture-token");
    }

    [Test]
    [Arguments(true, 200, "Succeeded")]
    [Arguments(true, 200, "InProgress")]
    [Arguments(true, 401, "denied")]
    [Arguments(true, 403, "denied")]
    [Arguments(false, 200, "empty")]
    [Arguments(false, 204, "empty")]
    [Arguments(false, 202, "empty")]
    [Arguments(false, 401, "denied")]
    [Arguments(false, 403, "denied")]
    public async Task NotificationDeleteDocumentedContinuationPreservesOriginalPendingAndStatus(
        bool asyncHeader, int status, string state)
    {
        using var transport = new EventGridContinuationTransport(asyncHeader, status, state);
        var client = new VaultAdministration(new Credential(), transport);
        var scope = new NotificationScope(
            new VaultScope(new(new(Guid.Parse(Subscription)), "capture-group"), "capture-vault"), "capture-notification");
        var receipt = client.PrepareReceipt(scope, ManagementMutation.DeleteNotification);
        var start = client.DeleteNotificationAsync(scope, receipt).AsTask();
        var result = await start;
        await Assert.That(start.IsCompletedSuccessfully).IsTrue();
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        var handle = result.Value;
        await Assert.That(handle.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(transport.Requests.Count).IsEqualTo(1);
        await Assert.That(transport.Requests[0].Method).IsEqualTo("DELETE");
        await Assert.That(transport.Requests[0].Uri).IsEqualTo(Origin + Notification + "?api-version=2025-02-15");
        await Assert.That(transport.Authorizations.Single()).IsEqualTo("Bearer selected-capture-token");
        var check = handle.CheckStatusAsync().AsTask();
        var outcome = await check;
        await Assert.That(check.IsCompletedSuccessfully).IsTrue();
        bool pending = status == 202 || asyncHeader && status == 200 && state != "Succeeded";
        await Assert.That(outcome).IsEqualTo(status is 401 or 403 ? SecretStatus.Denied :
            pending ? SecretStatus.Pending : SecretStatus.Success);
        await Assert.That(handle.State).IsEqualTo(status is 401 or 403 ? NativeProvisioningState.Failed :
            pending ? NativeProvisioningState.Pending : NativeProvisioningState.Succeeded);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(transport.Requests.Count).IsEqualTo(2);
        await Assert.That(transport.Requests[1].Uri).IsEqualTo(
            asyncHeader ? EventGridAsyncOperation : EventGridLocation);
        await Assert.That(transport.Authorizations.Distinct().Count()).IsEqualTo(1);
    }

    [Test]
    [Arguments("foreign-host")]
    [Arguments("foreign-subscription")]
    [Arguments("foreign-group")]
    [Arguments("foreign-provider")]
    [Arguments("wrong-version")]
    [Arguments("extra-query")]
    [Arguments("no-guid")]
    [Arguments("encoded-region")]
    [Arguments("empty-region")]
    [Arguments("trailing-path")]
    [Arguments("wrong-result-suffix")]
    [Arguments("wrong-status-suffix")]
    [Arguments("relative-url")]
    [Arguments("explicit-port")]
    [Arguments("dot-segment")]
    [Arguments("operation-location")]
    public async Task NotificationDeleteDocumentedContinuationRejectsUnsafeIssuedTargets(string variant)
    {
        string target = variant switch
        {
            "foreign-host" => EventGridLocation.Replace("management.azure.com", "foreign.example.test"),
            "foreign-subscription" => EventGridLocation.Replace(Subscription, Tenant),
            "foreign-group" => EventGridLocation.Replace("capture-group", "foreign-group"),
            "foreign-provider" => EventGridLocation.Replace("Microsoft.EventGrid", "Microsoft.Resources"),
            "wrong-version" => EventGridLocation.Replace("2025-02-15", "2024-01-01"),
            "extra-query" => EventGridLocation + "&unestablished=true",
            "no-guid" => EventGridLocation.Replace(OperationId, "not-an-operation-id"),
            "encoded-region" => EventGridLocation.Replace("eastus", "%65astus"),
            "empty-region" => EventGridLocation.Replace("/eastus/", "//"),
            "trailing-path" => EventGridLocation.Replace("?api-version", "/extra?api-version"),
            "wrong-result-suffix" => EventGridAsyncOperation.Replace("/Spring/default", "/foreign/default"),
            "wrong-status-suffix" => EventGridLocation.Replace("/operationId/", "/foreign/"),
            "relative-url" => new Uri(EventGridLocation).PathAndQuery,
            "explicit-port" => EventGridLocation.Replace("management.azure.com", "management.azure.com:443"),
            "dot-segment" => EventGridLocation.Replace("/locations/", "/unused/../locations/"),
            _ => EventGridLocation
        };
        using var transport = new EventGridContinuationTransport(false, 200, "empty", target,
            variant == "operation-location" ? "Operation-Location" : "Location");
        var client = new VaultAdministration(new Credential(), transport);
        var scope = new NotificationScope(
            new VaultScope(new(new(Guid.Parse(Subscription)), "capture-group"), "capture-vault"), "capture-notification");
        var receipt = client.PrepareReceipt(scope, ManagementMutation.DeleteNotification);
        var result = await client.DeleteNotificationAsync(scope, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(transport.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("CreateOrUpdateNotification")]
    [Arguments("UpdateNotification")]
    public async Task NotificationDeleteDocumentedContinuationDoesNotBroadenOtherMutations(string name)
    {
        using var backend = new Backend(name, "2025-02-15");
        backend.Targets.Add(("Location", EventGridLocation));
        backend.Targets.Add(("Azure-AsyncOperation", EventGridAsyncOperation));
        var client = new VaultAdministration(new Credential(), backend);
        var scope = new NotificationScope(
            new VaultScope(new(new(Guid.Parse(Subscription)), "capture-group"), "capture-vault"), "capture-notification");
        using var configuration = new NotificationConfiguration(Material, [VaultNotificationEvent.SecretNewVersionCreated]);
        var receipt = client.PrepareReceipt(scope, Enum.Parse<ManagementMutation>(name));
        var result = name == "UpdateNotification"
            ? await client.UpdateNotificationAsync(scope, configuration, receipt)
            : await client.CreateOrUpdateNotificationAsync(scope, configuration, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(backend.Requests.Count).IsEqualTo(1);
    }

    private sealed class EventGridContinuationTransport : HttpPipelineTransport, IDisposable
    {
        private readonly HttpClient http;
        private readonly HttpClientTransport inner;
        private readonly bool asyncHeader;
        private readonly int status;
        private readonly string state;
        private readonly string? targetOverride;
        private readonly string overrideHeader;
        internal readonly List<(string Method, string Uri)> Requests = [];
        internal readonly List<string?> Authorizations = [];

        internal EventGridContinuationTransport(bool asyncHeader, int status, string state,
            string? targetOverride = null, string overrideHeader = "Location")
        {
            this.asyncHeader = asyncHeader;
            this.status = status;
            this.state = state;
            this.targetOverride = targetOverride;
            this.overrideHeader = overrideHeader;
            http = new HttpClient(new EventGridContinuationHandler(this));
            inner = new HttpClientTransport(http);
        }

        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override ValueTask ProcessAsync(HttpMessage message) => inner.ProcessAsync(message);
        public void Dispose() => http.Dispose();

        private HttpResponseMessage Respond(HttpRequestMessage request)
        {
            string uri = request.RequestUri!.AbsoluteUri;
            bool start = request.Method == HttpMethod.Delete &&
                uri == Origin + Notification + "?api-version=2025-02-15";
            bool poll = request.Method == HttpMethod.Get &&
                (uri == EventGridLocation || asyncHeader && uri == EventGridAsyncOperation);
            if (!start && !poll) throw new InvalidOperationException("unexpected-eventgrid-continuation-route");
            Requests.Add((request.Method.Method, uri));
            Authorizations.Add(request.Headers.Authorization?.ToString());
            int code = start ? 202 : uri == EventGridLocation && asyncHeader ? 204 : status;
            string body = start || code == 204 || state == "empty" ? "" : code is 401 or 403
                ? """{"error":{"code":"AuthorizationFailed","message":"controlled-denial"}}"""
                : "{\"status\":\"" + state + "\"}";
            var response = new HttpResponseMessage((HttpStatusCode)code)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
            response.Headers.TryAddWithoutValidation("x-ms-request-id", "controlled-eventgrid-continuation");
            if (start)
            {
                response.Headers.TryAddWithoutValidation(overrideHeader, targetOverride ?? EventGridLocation);
                if (asyncHeader)
                    response.Headers.TryAddWithoutValidation("Azure-AsyncOperation", EventGridAsyncOperation);
            }
            return response;
        }

        private sealed class EventGridContinuationHandler(EventGridContinuationTransport owner) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                return Task.FromResult(owner.Respond(request));
            }
        }
    }
}
