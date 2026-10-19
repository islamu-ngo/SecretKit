using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault;
using SecretKit.Core;

namespace SecretKit.ProviderContract.Tests;

internal sealed class AzureFixture : IProviderFixture
{
    private const string Version = "0123456789abcdef0123456789abcdef";
    private readonly HttpClient _http;
    private readonly HttpClientTransport _transport;
    private readonly AzureKeyVaultClient _client;
    private readonly string _token = Guid.NewGuid().ToString("N");
    public AzureFixture()
    {
        Wire = new FixtureHandler { ExpectedToken = _token, ChallengeUnauthenticated = true };
        _http = new HttpClient(Wire);
        _transport = new HttpClientTransport(_http);
        _client = new AzureKeyVaultClient(new Uri("https://unit.vault.azure.net"),
            new Credential(this), _transport, maximumResponseBytes: 1024);
    }

    public FixtureHandler Wire { get; }
    public bool RejectUse { get; set; }
    public ISecretReader Reader => _client;
    public ISecretInventory Inventory => _client;
    public SecretReference Reference => new(_client.Authority, new AzureSecretAddress("name-canary", Version));
    public SecretInventoryScope Scope(int maximumItems = 1000) =>
        new AzureInventoryScope(_client.Authority, maximumItems: maximumItems);
    public HttpResponseMessage ReadResponse(string material, bool wrongCoordinates = false) =>
        FixtureHandler.Json(JsonSerializer.Serialize(new
        {
            value = material,
            id = $"https://unit.vault.azure.net/secrets/{(wrongCoordinates ? "foreign-name" : "name-canary")}/{Version}",
            attributes = new { enabled = true }
        }));
    public HttpResponseMessage InventoryResponse(string canary) => FixtureHandler.Json(
        JsonSerializer.Serialize(new
        {
            value = new[]
            {
                new { id = "https://unit.vault.azure.net/secrets/name-canary", attributes = new { enabled = true }, value = canary },
                new { id = "https://unit.vault.azure.net/secrets/second", attributes = new { enabled = true }, value = canary }
            }
        }));

    public ValueTask DisposeAsync()
    {
        // These resources belong to this fixture, not to the Azure adapter.
        _transport.Dispose();
        _http.Dispose();
        return ValueTask.CompletedTask;
    }

    private sealed class Credential(AzureFixture fixture) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Async only.");
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (fixture.RejectUse)
            {
                throw new InvalidOperationException("Foreign credential acquisition.");
            }

            return ValueTask.FromResult(new AccessToken(fixture._token, DateTimeOffset.MaxValue));
        }
    }
}
