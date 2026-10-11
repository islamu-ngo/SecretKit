using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class TokenMetadataPresenceTests
{
    private const string Token = "11111111-1111-4111-8111-111111111111";
    private const string Identity = "22222222-2222-4222-8222-222222222222";
    private const string Coordinate = "33333333-3333-4333-8333-333333333333";
    private static readonly string[] Fields =
        ["name", "subOrganizationId", "identityUAClientSecretId", "accessTokenLastUsedAt", "accessTokenLastRenewedAt"];

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task EveryTokenAdapterPreservesAbsentNullAndCopiedValues(int route)
    {
        foreach (string shape in new[] { "absent", "null", "empty-name", "value" })
        {
            var row = Row();
            string date = shape == "empty-name" ? "2026-10-10T02:00:00+02:00" : "2026-10-11T00:00:00Z";
            foreach (string field in Fields)
                if (shape != "absent")
                    row[field] = shape == "null" ? null : field == "name" ? shape == "empty-name" ? "" : "private-name" :
                        field.Contains("At", StringComparison.Ordinal) ? date : Coordinate;
            var metadata = await Execute(route, row, true) ?? throw new InvalidOperationException("Expected typed token metadata.");
            foreach (var field in new[] { metadata.Name, metadata.SubOrganizationId, metadata.IdentityUAClientSecretId })
            {
                await Assert.That(field.IsPresent).IsEqualTo(shape != "absent");
                await Assert.That(field.IsNull).IsEqualTo(shape == "null");
            }
            foreach (var field in new[] { metadata.AccessTokenLastUsedAt, metadata.AccessTokenLastRenewedAt })
            {
                await Assert.That(field.IsPresent).IsEqualTo(shape != "absent");
                await Assert.That(field.IsNull).IsEqualTo(shape == "null");
                if (shape is "empty-name" or "value")
                {
                    var expected = DateTimeOffset.Parse(date, CultureInfo.InvariantCulture);
                    await Assert.That(field.Value).IsEqualTo(expected);
                    await Assert.That(field.Value.Offset).IsEqualTo(expected.Offset);
                }
            }
            if (shape is "empty-name" or "value")
            {
                await Assert.That(metadata.Name.Value).IsEqualTo(shape == "empty-name" ? "" : "private-name");
                await Assert.That(metadata.SubOrganizationId.Value).IsEqualTo(Coordinate);
                await Assert.That(metadata.IdentityUAClientSecretId.Value).IsEqualTo(Coordinate);
            }
            await Assert.That(JsonSerializer.Serialize(metadata)).IsEqualTo("{}");
            await Assert.That(metadata.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
            await Assert.That(metadata.Name.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
        }
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task EveryTokenAdapterRejectsKnownNullableFieldTypeDefects(int route)
    {
        foreach (string field in Fields)
        {
            var row = Row();
            row[field] = 42;
            await Execute(route, row, false);
        }
        foreach (string field in new[] { "accessTokenLastUsedAt", "accessTokenLastRenewedAt" })
        {
            var row = Row();
            row[field] = "not-a-date";
            await Execute(route, row, false);
        }
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task DeclaredUuidFieldsRejectMalformedMatchingIdentityAndSuborganization(int route)
    {
        foreach (string invalid in new[] { "identity", "{22222222-2222-4222-8222-222222222222}", "22222222222242228222222222222222" })
        {
            var identity = Row();
            identity["identityId"] = invalid;
            await Execute(route, identity, false, invalid);
            var suborganization = Row();
            suborganization["subOrganizationId"] = invalid;
            await Execute(route, suborganization, false);
        }
        var empty = Row();
        empty["subOrganizationId"] = "";
        await Execute(route, empty, false);
        var upperCase = Row();
        upperCase["subOrganizationId"] = "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE";
        var copied = await Execute(route, upperCase, true) ?? throw new InvalidOperationException("Expected UUID metadata.");
        await Assert.That(copied.SubOrganizationId.Value).IsEqualTo("AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE");
    }

    private static JsonObject Row() => new()
    {
        ["id"] = Token,
        ["identityId"] = Identity,
        ["authMethod"] = "token-auth",
        ["createdAt"] = "2026-10-10T00:00:00Z",
        ["updatedAt"] = "2026-10-10T00:00:00Z"
    };

    private static async Task<TokenAuthToken?> Execute(int route, JsonObject row, bool valid, string selectedIdentity = Identity)
    {
        var root = route switch
        {
            0 => new JsonObject { ["tokens"] = new JsonArray(row) },
            1 => new JsonObject
            {
                ["tokenData"] = row,
                ["accessToken"] = "private-issued-token",
                ["tokenType"] = "Bearer",
                ["expiresIn"] = 30,
                ["accessTokenMaxTTL"] = 30
            },
            _ => new JsonObject { ["token"] = row }
        };
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false,
            new Wire(root.ToJsonString()));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        switch (route)
        {
            case 0:
                return await Verify(IdentityAuthenticationOperations.ListTokens("org", selectedIdentity),
                    new("org", resourceId: selectedIdentity), page => page.Items.Single());
            case 1:
                return await Verify(IdentityAuthenticationOperations.CreateToken("org", selectedIdentity),
                    IdentityAuthenticationOperations.TokenCreateTarget("org", selectedIdentity), creation => creation.Metadata);
            case 2:
                return await Verify(IdentityAuthenticationOperations.GetToken("org", Token),
                    new("org", resourceId: Token), value => value);
            default:
                return await Verify(IdentityAuthenticationOperations.RenameToken("org", Token),
                    IdentityAuthenticationOperations.TokenRenameTarget("org", Token), value => value);
        }
        async Task<TokenAuthToken?> Verify<T>(ManagementRequest<T> request, ManagementTarget approved,
            Func<T, TokenAuthToken> metadata) where T : notnull
        {
            using (request)
            {
                var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, approved), receipt);
                await Assert.That(result.Status).IsEqualTo(valid ? SecretStatus.Success : SecretStatus.Unknown);
                if (receipt is not null)
                    await Assert.That(receipt.Evidence).IsEqualTo(valid ? DispatchEvidence.Applied : DispatchEvidence.PossiblyDispatched);
                if (!result.IsSuccess) return null;
                try { return metadata(result.Value); }
                finally { (result.Value as IDisposable)?.Dispose(); }
            }
        }
    }

    private sealed class Wire(string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) });
    }
    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
    }
}
