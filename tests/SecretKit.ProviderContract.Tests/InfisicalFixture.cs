using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.ProviderContract.Tests;

internal sealed class InfisicalFixture : IProviderFixture
{
    private readonly InfisicalClient _client;
    private readonly string _token = Guid.NewGuid().ToString("N");
    public InfisicalFixture()
    {
        Wire = new FixtureHandler { ExpectedToken = _token };
        _client = new InfisicalClient(new Uri("https://provider.test"), new Tokens(this),
            new InfisicalNetworkOptions { MaximumResponseBytes = 1024 }, null, Wire);
    }

    public FixtureHandler Wire { get; }
    public bool RejectUse { get; set; }
    public ISecretReader Reader => _client;
    public ISecretInventory Inventory => _client;
    public SecretReference Reference => new(_client.Authority,
        new InfisicalSecretAddress("project", "test", "/", "name-canary", 1));
    public SecretInventoryScope Scope(int maximumItems = 1000) =>
        new InfisicalInventoryScope(_client.Authority, "project", "test", "/", maximumItems);
    public HttpResponseMessage ReadResponse(string material, bool wrongCoordinates = false) =>
        FixtureHandler.Json(JsonSerializer.Serialize(new
        {
            secret = new
            {
                secretKey = wrongCoordinates ? "foreign-name" : "name-canary",
                secretValue = material,
                secretValueHidden = false,
                version = 1
            }
        }));
    public HttpResponseMessage InventoryResponse(string canary) => FixtureHandler.Json(
        JsonSerializer.Serialize(new
        {
            secrets = new[]
            {
                new { secretKey = "name-canary", version = 1, secretValue = canary },
                new { secretKey = "second", version = 1, secretValue = canary }
            }
        }));
    public ValueTask DisposeAsync() => _client.DisposeAsync();

    private sealed class Tokens(InfisicalFixture fixture) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (fixture.RejectUse)
            {
                throw new InvalidOperationException("Foreign credential acquisition.");
            }

            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new InfisicalAccessToken(SecretMaterial.FromText(fixture._token))));
        }
    }
}

internal sealed class FixtureHandler : HttpMessageHandler
{
    public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Respond { get; set; } =
        (_, _) => throw new InvalidOperationException("Unexpected native send.");
    public bool Disposed { get; private set; }
    public string? ExpectedToken { get; init; }
    public bool ChallengeUnauthenticated { get; init; }
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (ChallengeUnauthenticated && request.Headers.Authorization is null)
        {
            HttpResponseMessage challenge = Json("{}", 401);
            challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                "Bearer authorization=\"https://login.microsoftonline.com/test-tenant\", resource=\"https://vault.azure.net\"");
            return Task.FromResult(challenge);
        }

        if (ExpectedToken is not null && request.Headers.Authorization?.Parameter != ExpectedToken)
        {
            throw new InvalidOperationException("Unexpected fixture identity.");
        }

        return Respond(request, cancellationToken);
    }
    protected override void Dispose(bool disposing)
    {
        Disposed = true;
        base.Dispose(disposing);
    }
    public static HttpResponseMessage Json(string json, int status = 200) => new((HttpStatusCode)status)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json")
    };
}
