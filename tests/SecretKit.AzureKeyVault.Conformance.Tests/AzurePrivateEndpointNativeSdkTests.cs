using System.Net;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Azure.ResourceManager.Resources;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

// Installed generic ARM behavior only, not fixture ownership or native qualification.
public sealed class AzurePrivateEndpointNativeSdkTests
{
    private const string Subscription = "11111111-1111-1111-1111-111111111111";
    private const string Group = "/subscriptions/" + Subscription + "/resourceGroups/endpoint-group";
    private const string Endpoint = Group + "/providers/Microsoft.Network/privateEndpoints/generated-endpoint";
    private const string Subnet = Group + "/providers/Microsoft.Network/virtualNetworks/borrowed-network/subnets/borrowed-subnet";
    private const string Vault = Group + "/providers/Microsoft.KeyVault/vaults/owned-vault";
    private const string Nic = Group + "/providers/Microsoft.Network/networkInterfaces/generated-nic";
    private const string Origin = "https://management.azure.com";
    private const string Revision = "2026-01-01";
    private const string Poll = "/subscriptions/" + Subscription +
        "/providers/Microsoft.Network/locations/eastus/operations/22222222-2222-2222-2222-222222222222";

    [Test]
    [Arguments(200, false)]
    [Arguments(201, false)]
    [Arguments(201, true)]
    public async Task GenericEndpointCreationUsesExplicitRevisionAndRetainsOriginalOperation(int status, bool asynchronous)
    {
        using var f = new Fixture(status, asynchronous);
        var data = new GenericResourceData("eastus")
        {
            Properties = BinaryData.FromObjectAsJson(new
            {
                subnet = new { id = Subnet },
                customNetworkInterfaceName = "generated-nic",
                manualPrivateLinkServiceConnections = new[]
                {
                    new { name = "network-side-name", properties = new { privateLinkServiceId = Vault, groupIds = new[] { "vault" } } }
                }
            })
        };
        data.Tags.Add("fixture-owner", "controlled-owner");
        var task = f.Client.GetGenericResources().CreateOrUpdateAsync(WaitUntil.Started, new(Endpoint), data);
        var operation = await task;
        await Assert.That(task.IsCompletedSuccessfully).IsTrue();
        await Assert.That(f.Requests.Single().Method).IsEqualTo("PUT");
        using (var request = JsonDocument.Parse(f.RequestBody))
        {
            var properties = request.RootElement.GetProperty("properties");
            await Assert.That(properties.GetProperty("subnet").GetProperty("id").GetString()).IsEqualTo(Subnet);
            var connection = properties.GetProperty("manualPrivateLinkServiceConnections")[0];
            await Assert.That(connection.GetProperty("properties").GetProperty("privateLinkServiceId").GetString()).IsEqualTo(Vault);
            await Assert.That(connection.GetProperty("name").GetString()).IsEqualTo("network-side-name");
        }
        await operation.UpdateStatusAsync();
        await Assert.That(operation.HasCompleted && operation.HasValue).IsTrue();
        await Assert.That(operation.Value.Id.ToString()).IsEqualTo(Endpoint);
        await Assert.That(f.Requests.All(r => r.Query == "?api-version=" + Revision)).IsTrue();
        await Assert.That(f.Requests.Count).IsEqualTo(asynchronous ? 3 : 1);
        await Assert.That(f.Requests.Skip(1).All(r => r.Method == "GET" && r.Path is Endpoint or Poll)).IsTrue();
        await Assert.That(f.Credential.Scopes.All(s => s == Origin + "/.default")).IsTrue();
    }

    [Test]
    [Arguments(204, false)]
    [Arguments(202, true)]
    public async Task GenericEndpointDeletionDoesNotMutateGeneratedNic(int status, bool asynchronous)
    {
        using var f = new Fixture(status, asynchronous);
        var task = f.Client.GetGenericResource(new(Endpoint)).DeleteAsync(WaitUntil.Started);
        var operation = await task;
        await Assert.That(task.IsCompletedSuccessfully).IsTrue();
        await operation.UpdateStatusAsync();
        await Assert.That(operation.HasCompleted).IsTrue();
        await Assert.That(f.Requests.First()).IsEqualTo(("DELETE", Endpoint, "?api-version=" + Revision));
        await Assert.That(f.Requests.Skip(1).All(r => r.Method == "GET" && r.Path == Poll)).IsTrue();
        await Assert.That(f.Requests.Count).IsEqualTo(asynchronous ? 2 : 1);
        await Assert.That(f.Requests.Any(r => r.Path == Nic)).IsFalse();
    }

    internal sealed class Credential : TokenCredential
    {
        internal readonly List<string> Scopes = [];
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("controlled-async-only");
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Scopes.AddRange(context.Scopes);
            return ValueTask.FromResult(new AccessToken("controlled-endpoint-setup", DateTimeOffset.MaxValue));
        }
    }

    internal sealed class Fixture : IDisposable
    {
        private readonly HttpClient http;
        internal readonly Credential Credential = new();
        internal readonly ArmClient Client;
        internal readonly HttpPipelineTransport Transport;
        internal readonly List<(string Method, string Path, string Query)> Requests = [];
        internal byte[] RequestBody = [];
        internal Func<CancellationToken, Task>? BeforeSend;
        internal Func<HttpResponseMessage, Task>? AfterReply;
        internal Fixture(int initialStatus, bool asynchronous)
        {
            http = new(new Handler(async (request, token) =>
            {
                if (BeforeSend is not null) await BeforeSend(token);
                var uri = request.RequestUri!;
                if (uri.GetLeftPart(UriPartial.Authority) != Origin ||
                    uri.Query != "?api-version=" + Revision || uri.AbsolutePath is not (Endpoint or Poll))
                    throw new InvalidOperationException("controlled-endpoint-route");
                Requests.Add((request.Method.Method, uri.AbsolutePath, uri.Query));
                bool initial = request.Method != HttpMethod.Get;
                if (initial)
                    RequestBody = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(token);
                string body = uri.AbsolutePath == Poll ? """{"status":"Succeeded"}""" :
                    initial && request.Method == HttpMethod.Delete ? "" : JsonSerializer.Serialize(new
                    {
                        id = Endpoint,
                        name = "generated-endpoint",
                        type = "Microsoft.Network/privateEndpoints",
                        location = "eastus",
                        tags = new Dictionary<string, string> { ["fixture-owner"] = "controlled-owner" },
                        properties = new
                        {
                            provisioningState = initial && asynchronous ? "Updating" : "Succeeded",
                            subnet = new { id = Subnet },
                            networkInterfaces = new[] { new { id = Nic } },
                            manualPrivateLinkServiceConnections = new[]
                            {
                                new
                                {
                                    name = "network-side-name",
                                    properties = new
                                    {
                                        privateLinkServiceId = Vault,
                                        groupIds = new[] { "vault" },
                                        privateLinkServiceConnectionState = new { status = "Pending" }
                                    }
                                }
                            }
                        }
                    });
                var response = new HttpResponseMessage((HttpStatusCode)(initial ? initialStatus : 200))
                {
                    Content = new StringContent(body, Encoding.UTF8, "application/json")
                };
                if (initial && asynchronous) response.Headers.Add("Azure-AsyncOperation", Origin + Poll + "?api-version=" + Revision);
                response.Headers.Add("x-ms-request-id", "controlled-endpoint-native");
                if (AfterReply is not null) await AfterReply(response);
                return response;
            }));
            Transport = new HttpClientTransport(http);
            var options = new ArmClientOptions
            {
                Environment = new(new Uri(Origin), Origin),
                Transport = Transport
            };
            options.Retry.MaxRetries = 0;
            options.SetApiVersion("Microsoft.Network/privateEndpoints", Revision);
            Client = new(Credential, Subscription, options);
        }
        public void Dispose() => http.Dispose();
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }
}
