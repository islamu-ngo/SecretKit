using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using Microsoft.Extensions.Configuration;
using SecretKit.AzureKeyVault;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;
using SecretKit.Extensions.Hosting;
using SecretKit.Infisical;
using SecretKit.Samples.ProviderAssessment;
using SecretKit.Samples.RuntimeConfiguration;

string value = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
using (SecretMaterial source = SecretMaterial.FromText(value))
using (SecretMaterial copy = source.Copy())
{
    source.Dispose();
    Require(copy.Reveal() == value);
    Require(!JsonSerializer.Serialize(copy).Contains(value, StringComparison.Ordinal));
}

string version = "0123456789abcdef0123456789abcdef";
using var transport = new HttpClientTransport(new HttpClient(new AzureWire(value, version)));
var azure = new AzureKeyVaultClient(new Uri("https://fixture.vault.azure.net"), new FixtureCredential(), transport);
SecretOutcome<SecretRead> azureOutcome = await azure.ReadAsync(new SecretReference(azure.Authority,
    new AzureSecretAddress("fixture", version)));
using (SecretRead read = azureOutcome.Value)
{
    Require(read.Material.Reveal() == value);
}

using var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
listener.Start();
int port = ((IPEndPoint)listener.LocalEndpoint).Port;
Task<System.Net.Sockets.TcpClient> accepted = listener.AcceptTcpClientAsync();
var tokens = new FixtureTokens();
await using var infisical = new InfisicalClient(new Uri($"http://127.0.0.1:{port}"), tokens,
    new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
Task<SecretOutcome<SecretRead>> pending = infisical.ReadAsync(new SecretReference(infisical.Authority,
    new InfisicalSecretAddress("fixture-project", "fixture", "/", "fixture", 1))).AsTask();
using System.Net.Sockets.TcpClient request = await accepted.WaitAsync(TimeSpan.FromSeconds(10));
await using System.Net.Sockets.NetworkStream stream = request.GetStream();
using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
string? requestLine = await reader.ReadLineAsync(deadline.Token);
Require(requestLine?.StartsWith("GET /api/v4/secrets/fixture?", StringComparison.Ordinal) == true);
bool bearerPresent = false;
while (await reader.ReadLineAsync(deadline.Token) is { Length: > 0 } header)
{
    bearerPresent |= header.StartsWith("Authorization: Bearer ", StringComparison.OrdinalIgnoreCase);
}

Require(bearerPresent);
byte[] response = JsonSerializer.SerializeToUtf8Bytes(new
{
    secret = new { secretKey = "fixture", secretValue = value, secretValueHidden = false, version = 1 }
});
byte[] responseHeaders = Encoding.ASCII.GetBytes(
    $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n");
await stream.WriteAsync(responseHeaders, deadline.Token);
await stream.WriteAsync(response, deadline.Token);
SecretOutcome<SecretRead> infisicalOutcome = await pending;
using (SecretRead read = infisicalOutcome.Value)
{
    Require(read.Material.Reveal() == value);
    Require(!JsonSerializer.Serialize(read).Contains(value, StringComparison.Ordinal));
}

using var generationLoader = new SecretSnapshotLoader([
    new SecretSelection("first", azure, new SecretReference(azure.Authority, new AzureSecretAddress("fixture", version))),
    new SecretSelection("second", azure, new SecretReference(azure.Authority, new AzureSecretAddress("fixture", version)))
]);
Require((await generationLoader.RefreshAsync()).IsSuccess);
using SecretSnapshotHandle generation = generationLoader.Acquire();
using SecretRead ownedFirst = generation.Read("first");
using SecretRead ownedSecond = generation.Read("second");
ownedFirst.Dispose();
Require(ownedSecond.Material.Reveal() == value);
using SecretConfigurationExport export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(generation, [
    new SecretConfigurationMapping("first", "consumer:first"),
    new SecretConfigurationMapping("second", "consumer:second")
]);
var configurationBuilder = new ConfigurationBuilder();
configurationBuilder.Add(export);
using var configuration = (ConfigurationRoot)configurationBuilder.Build();
Require(configuration["consumer:first"] == value && configuration["consumer:second"] == value);
Require(!export.GetRedactedDebugView().Contains(value, StringComparison.Ordinal));
Require(!generation.RemoteSnapshotGuaranteed);
SecretReference runtimeReference = new(azure.Authority, new AzureSecretAddress("fixture", version));
SecretOutcome<BootstrapCandidate> bootstrap = await BootstrapScenario.PrepareAsync(azure,
    new Dictionary<string, SecretReference> { ["consumer:required"] = runtimeReference });
Require(bootstrap.IsSuccess);
using (BootstrapCandidate prepared = bootstrap.Value)
{
    Require(prepared.ExportOver(new Dictionary<string, string> { ["consumer:required"] = "local-default" })
        ["consumer:required"] == value);
}
var administrative = new AzureKeyVaultClient(new Uri("https://fixture.vault.azure.net"),
    new FixtureCredential(), transport);
var assessment = new AssessmentScenario(administrative, azure);
AssessmentReport assessed = await assessment.CheckAsync(new AzureInventoryScope(administrative.Authority),
    [new FeatureRequirement("optional", false, [new KeyRequirement("fixture", runtimeReference, DeliveryKind.Direct)])]);
Require(assessed.Inventory.IsComplete && assessed.Inventory.VisibleItems == 1 &&
    assessed.Features.Single().CanEnable && assessed.CanProceed);

DateTimeOffset issued = DateTimeOffset.UtcNow;
using SecretMaterial suppliedToken = SecretMaterial.FromText(value);
await using var session = new InfisicalPeriodicTokenSession(new Uri("https://fixture.infisical.invalid"),
    suppliedToken, new InfisicalTokenLifetimeEvidence
    {
        OriginalIssuedAt = issued,
        ExpiresAt = issued.AddMinutes(5),
        Lifetime = InfisicalTokenLifetime.Finite,
        ReportedMaximumTtl = TimeSpan.FromMinutes(5)
    }, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(3));
await using var maintenance = new InfisicalAuthenticationMaintenance(session, TimeSpan.FromSeconds(3));
Require(maintenance.State == AuthenticationMaintenanceState.NotStarted);
suppliedToken.Dispose();
using (InfisicalAccessToken tokenCopy = (await session.GetTokenAsync(CancellationToken.None)).Value)
{
    Require(tokenCopy.Material.Reveal() == value);
}
await maintenance.StartAsync(CancellationToken.None);
Require(maintenance.State == AuthenticationMaintenanceState.Ready);
await maintenance.StopAsync(CancellationToken.None);
Require(maintenance.State == AuthenticationMaintenanceState.Stopped);
using var managementTransport = new SecretKit.Infisical.Management.ManagementTransport(
    new Uri("https://fixture.infisical.invalid"));
var infisicalManagement = new SecretKit.Infisical.Management.ManagementClient(managementTransport);
Require(infisicalManagement.Authority is not null);
var vaultAdministration = new SecretKit.AzureKeyVault.Management.VaultAdministration(
    new FixtureCredential(), transport);
var vaultScope = new SecretKit.AzureKeyVault.Management.VaultScope(
    new SecretKit.AzureKeyVault.Management.ResourceGroupScope(
        new SecretKit.AzureKeyVault.Management.SubscriptionScope(Guid.NewGuid()), "fixture-group"),
    "fixture-vault");
Require(vaultAdministration.PrepareReceipt(vaultScope,
    SecretKit.AzureKeyVault.Management.ManagementMutation.UpdateVault).Evidence ==
    DispatchEvidence.NotDispatched);
var assignmentScope = new SecretKit.AzureKeyVault.Management.RoleAssignmentScope(vaultScope, Guid.NewGuid());
Require(vaultAdministration.PrepareReceipt(assignmentScope,
    SecretKit.AzureKeyVault.Management.ManagementMutation.CreateRoleAssignment).Evidence ==
    DispatchEvidence.NotDispatched);
Console.WriteLine("PACKAGE_CONSUMER_OK");

static void Require(bool condition)
{
    if (!condition)
    {
        throw new InvalidOperationException("Installed-package contract failed.");
    }
}

sealed class FixtureTokens : IInfisicalTokenSource
{
    public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new InfisicalAccessToken(
            SecretMaterial.FromText(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))))));
    }
}

sealed class FixtureCredential : TokenCredential
{
    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        new(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)), DateTimeOffset.UtcNow.AddMinutes(5));

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext,
        CancellationToken cancellationToken) => ValueTask.FromResult(GetToken(requestContext, cancellationToken));
}

sealed class AzureWire(string value, string version) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri?.Host != "fixture.vault.azure.net")
        {
            throw new InvalidOperationException("Unexpected package-consumer origin.");
        }

        if (request.RequestUri.AbsolutePath.TrimEnd('/') == "/secrets")
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    value = new[]
                    {
                        new
                        {
                            id = $"https://fixture.vault.azure.net/secrets/fixture/{version}",
                            attributes = new { enabled = true }
                        }
                    }
                }), Encoding.UTF8, "application/json")
            });
        }
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                value,
                id = $"https://fixture.vault.azure.net/secrets/fixture/{version}",
                attributes = new { enabled = true }
            }), Encoding.UTF8, "application/json")
        });
    }
}
