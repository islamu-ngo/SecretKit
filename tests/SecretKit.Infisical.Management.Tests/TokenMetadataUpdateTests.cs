using System.Net;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class TokenMetadataUpdateTests
{
    private const string Token = "11111111-1111-4111-8111-111111111111";

    [Test]
    [Arguments(null)]
    [Arguments("")]
    [Arguments("private-name")]
    public async Task NativePatchPreservesOmittedEmptyAndNamedInput(string? name)
    {
        var wire = new Wire();
        var tokens = new Tokens();
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        using var request = name is null ? IdentityAuthenticationOperations.RenameToken("org", Token) :
            IdentityAuthenticationOperations.RenameToken("org", Token, name);
        var approved = IdentityAuthenticationOperations.TokenRenameTarget("org", Token, name);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(
            "infisical.patch.v1.auth.token.auth.tokens.by.tokenId", approved), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(wire.Path).IsEqualTo("/api/v1/auth/token-auth/tokens/" + Token);
        using var json = JsonDocument.Parse(wire.Body!);
        await Assert.That(json.RootElement.TryGetProperty("name", out var field)).IsEqualTo(name is not null);
        await Assert.That(json.RootElement.EnumerateObject().Count()).IsEqualTo(name is null ? 0 : 1);
        if (name is not null) await Assert.That(field.GetString()).IsEqualTo(name);
        await Assert.That(result.Value.Id).IsEqualTo(Token);
        await Assert.That(JsonSerializer.Serialize(result.Value).Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That((await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, approved), receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Dispatched).IsEqualTo(1);
    }

    [Test]
    [Arguments(null, "")]
    [Arguments("", null)]
    [Arguments(null, "private-name")]
    [Arguments("private-name", null)]
    [Arguments("", "private-name")]
    [Arguments("private-name", "")]
    public async Task OmissionCannotBorrowNamedMetadataApproval(string? selected, string? supplied)
    {
        var wire = new Wire();
        var tokens = new Tokens();
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        using var request = IdentityAuthenticationOperations.RenameToken("org", Token, supplied);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            IdentityAuthenticationOperations.TokenRenameTarget("org", Token, selected)), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Dispatched).IsEqualTo(0);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    private static ManagementTransport Transport(Wire wire) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
        }
    }
    private sealed class Wire : HttpMessageHandler
    {
        public int Dispatched { get; private set; }
        public string? Body { get; private set; }
        public string? Path { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method != HttpMethod.Patch) return new(HttpStatusCode.NotFound);
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            Path = request.RequestUri!.AbsolutePath;
            Dispatched++;
            return new(HttpStatusCode.OK)
            {
                Content = new StringContent("""
                    {"token":{"id":"11111111-1111-4111-8111-111111111111","identityId":"22222222-2222-4222-8222-222222222222",
                    "authMethod":"token-auth","name":null,"createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z",
                    "accessTokenTTL":0,"accessTokenMaxTTL":0,"accessTokenPeriod":0,"accessTokenNumUses":0,
                    "accessTokenNumUsesLimit":0,"isAccessTokenRevoked":false,"subOrganizationId":null,
                    "accessTokenLastUsedAt":null,"accessTokenLastRenewedAt":null,"identityUAClientSecretId":null}}
                    """)
            };
        }
    }
}
