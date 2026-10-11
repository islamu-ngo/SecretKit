using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class AuthenticationDateTimeTests
{
    private const string Identity = "11111111-1111-4111-8111-111111111111";
    private const string Configuration = "22222222-2222-4222-8222-222222222222";
    private const string Token = "private-token-id";
    private const string Secret = "private-secret-id";
    private const string Zulu = "2026-10-11T03:04:05Z";
    // This dispatch basis covers 12 WG09 rows / 34 date occurrences, not all 61 / 135.
    // Other rows inherit AuthenticationJson.Date through the same metadata readers.
    private static readonly string[] Operations =
    [
        "infisical.get.v1.auth.aws.auth.identities.by.identityId",
        "infisical.get.v1.auth.jwt.auth.identities.by.identityId",
        "infisical.get.v1.auth.universal.auth.identities.by.identityId",
        "infisical.get.v1.auth.token.auth.identities.by.identityId",
        "infisical.get.v1.auth.spiffe.auth.identities.by.identityId",
        "infisical.post.v1.auth.spiffe.auth.identities.by.identityId.refresh.bundle",
        "infisical.get.v1.auth.universal.auth.identities.by.identityId.client.secrets.by.clientSecretId",
        "infisical.post.v1.auth.universal.auth.identities.by.identityId.client.secrets",
        "infisical.get.v1.auth.token.auth.identities.by.identityId.tokens",
        "infisical.post.v1.auth.token.auth.identities.by.identityId.tokens",
        "infisical.get.v1.auth.token.auth.tokens.by.tokenId",
        "infisical.patch.v1.auth.token.auth.tokens.by.tokenId"
    ];

    [Test]
    [Arguments(0, "2026-10-11")]
    [Arguments(0, "2026-10-11T03:04:05")]
    [Arguments(1, "2026-10-11")]
    [Arguments(1, "2026-10-11T03:04:05")]
    [Arguments(2, "2026-10-11")]
    [Arguments(2, "2026-10-11T03:04:05")]
    [Arguments(3, "2026-10-11")]
    [Arguments(3, "2026-10-11T03:04:05")]
    [Arguments(4, "2026-10-11")]
    [Arguments(4, "2026-10-11T03:04:05")]
    [Arguments(5, "2026-10-11")]
    [Arguments(5, "2026-10-11T03:04:05")]
    [Arguments(6, "2026-10-11")]
    [Arguments(6, "2026-10-11T03:04:05")]
    [Arguments(7, "2026-10-11")]
    [Arguments(7, "2026-10-11T03:04:05")]
    [Arguments(8, "2026-10-11")]
    [Arguments(8, "2026-10-11T03:04:05")]
    [Arguments(9, "2026-10-11")]
    [Arguments(9, "2026-10-11T03:04:05")]
    [Arguments(10, "2026-10-11")]
    [Arguments(10, "2026-10-11T03:04:05")]
    [Arguments(11, "2026-10-11")]
    [Arguments(11, "2026-10-11T03:04:05")]
    public async Task PublicAdaptersRejectDateOnlyAndMissingZone(int route, string invalid)
    {
        foreach (string field in DateFields(route))
        {
            // Given one defective date with all neighboring fields valid.
            var row = Row(route);
            Dates(row, route, Zulu);
            DateOwner(row, field)[field] = invalid;
            // When dispatched, then the result is Unknown and mutations stay uncertain.
            await Execute(route, row, false);
        }
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(6)]
    [Arguments(7)]
    [Arguments(8)]
    [Arguments(9)]
    [Arguments(10)]
    [Arguments(11)]
    public async Task PublicAdaptersCopyZuluAndSignedOffsetsAfterDisposal(int route)
    {
        foreach (var (text, expected) in new[]
        {
            (Zulu, new DateTimeOffset(2026, 10, 11, 3, 4, 5, TimeSpan.Zero)),
            ("2026-10-11T03:04:05.1234567+02:30",
                new DateTimeOffset(2026, 10, 11, 3, 4, 5, TimeSpan.FromMinutes(150)).AddTicks(1234567)),
            ("2026-10-11T03:04:05-04:00",
                new DateTimeOffset(2026, 10, 11, 3, 4, 5, TimeSpan.FromHours(-4)))
        })
        {
            // Given independently specified Z/offset dates in the native response.
            var row = Row(route);
            Dates(row, route, text);
            // When the public adapter finishes and its request/transport/material are disposed.
            object metadata = await Execute(route, row, true)
                ?? throw new InvalidOperationException("Expected date metadata.");
            // Then copied values retain their original offset and remain private.
            foreach (DateTimeOffset date in CopiedDates(metadata))
            {
                await Assert.That(date).IsEqualTo(expected);
                await Assert.That(date.Offset).IsEqualTo(expected.Offset);
            }
            await Assert.That(JsonSerializer.Serialize(metadata, metadata.GetType())).IsEqualTo("{}");
            await Assert.That(metadata.ToString()!.Contains("private", StringComparison.Ordinal)).IsFalse();
        }
    }

    [Test]
    [Arguments(8)]
    [Arguments(9)]
    [Arguments(10)]
    [Arguments(11)]
    public async Task TokenOptionalDatesPreserveAbsentAndNull(int route)
    {
        foreach (bool present in new[] { false, true })
        {
            // Given absent or explicitly null optional date fields.
            var row = Row(route);
            if (present)
            {
                row["accessTokenLastUsedAt"] = null;
                row["accessTokenLastRenewedAt"] = null;
            }
            // When parsed through each public token adapter.
            var token = (TokenAuthToken)(await Execute(route, row, true)
                ?? throw new InvalidOperationException("Expected token metadata."));
            // Then presence survives disposal without a manufactured date.
            foreach (var date in new[] { token.AccessTokenLastUsedAt, token.AccessTokenLastRenewedAt })
            {
                await Assert.That(date.IsPresent).IsEqualTo(present);
                await Assert.That(date.IsNull).IsEqualTo(present);
            }
        }
    }

    [Test]
    [Arguments(4)]
    [Arguments(5)]
    public async Task SpiffeCachedDatePresenceIsConditionalOnWebProfile(int route)
    {
        foreach (string shape in new[] { "absent", "null", "static", "static-extra" })
        {
            // Given the declared profile-specific optional cached date.
            var row = Row(route);
            var bundle = row["trustBundleDistribution"]!.AsObject();
            if (shape == "null") bundle["cachedBundleLastRefreshedAt"] = null;
            if (shape is "static" or "static-extra")
            {
                bundle = new JsonObject { ["profile"] = "static", ["bundle"] = "private-bundle" };
                row["trustBundleDistribution"] = bundle;
                if (shape == "static-extra") bundle["cachedBundleLastRefreshedAt"] = Zulu;
            }
            // When dispatched, a static profile with a cached date is rejected.
            var metadata = await Execute(route, row, shape != "static-extra");
            if (metadata is not SpiffeAuthConfiguration configuration) continue;
            // Then the web null is present, while absence/static remain absent.
            var date = configuration.TrustBundleDistribution.CachedBundleLastRefreshedAt;
            await Assert.That(date.IsPresent).IsEqualTo(shape == "null");
            await Assert.That(date.IsNull).IsEqualTo(shape == "null");
            await Assert.That(JsonSerializer.Serialize(configuration.TrustBundleDistribution)).IsEqualTo("{}");
        }
    }

    private static string[] DateFields(int route) => route switch
    {
        4 or 5 => ["createdAt", "updatedAt", "cachedBundleLastRefreshedAt"],
        >= 8 => ["createdAt", "updatedAt", "accessTokenLastUsedAt", "accessTokenLastRenewedAt"],
        _ => ["createdAt", "updatedAt"]
    };

    private static JsonObject DateOwner(JsonObject row, string field) =>
        field == "cachedBundleLastRefreshedAt" ? row["trustBundleDistribution"]!.AsObject() : row;

    private static void Dates(JsonObject row, int route, string text)
    {
        foreach (string field in DateFields(route)) DateOwner(row, field)[field] = text;
    }

    private static IEnumerable<DateTimeOffset> CopiedDates(object metadata)
    {
        switch (metadata)
        {
            case WorkloadAuthConfiguration configuration:
                yield return configuration.CreatedAt;
                yield return configuration.UpdatedAt;
                if (configuration is SpiffeAuthConfiguration spiffe)
                    yield return spiffe.TrustBundleDistribution.CachedBundleLastRefreshedAt.Value;
                break;
            case IdentityAuthenticationConfiguration configuration:
                yield return configuration.CreatedAt;
                yield return configuration.UpdatedAt;
                break;
            case UniversalAuthClientSecret secret:
                yield return secret.CreatedAt;
                yield return secret.UpdatedAt;
                break;
            case TokenAuthToken token:
                yield return token.CreatedAt;
                yield return token.UpdatedAt;
                yield return token.AccessTokenLastUsedAt.Value;
                yield return token.AccessTokenLastRenewedAt.Value;
                break;
            default:
                throw new InvalidOperationException("Unexpected date metadata.");
        }
    }

    private static JsonObject Row(int route)
    {
        var row = new JsonObject
        {
            ["id"] = route >= 8 ? Token : route >= 6 ? Secret : Configuration,
            ["createdAt"] = Zulu,
            ["updatedAt"] = Zulu
        };
        if (route is 6 or 7)
        {
            row["identityUAId"] = Configuration;
            row["description"] = "private-description";
            row["clientSecretPrefix"] = "private-prefix";
        }
        else row["identityId"] = Identity;
        switch (route)
        {
            case 0:
                row["type"] = "private-returned-type";
                row["allowedPrincipalArns"] = "";
                row["allowedAccountIds"] = "";
                row["stsEndpoint"] = "";
                break;
            case 1:
                row["configurationType"] = "static";
                row["jwksUrl"] = "";
                row["boundIssuer"] = "";
                row["boundAudiences"] = "";
                row["boundSubject"] = "";
                row["jwksCaCert"] = "";
                row["publicKeys"] = new JsonArray();
                break;
            case 2:
                row["clientId"] = "private-client-id";
                break;
            case 4:
            case 5:
                row["trustDomain"] = "private-domain";
                row["allowedSpiffeIds"] = "";
                row["allowedAudiences"] = "";
                row["trustBundleDistribution"] = new JsonObject
                {
                    ["profile"] = "https_web_bundle",
                    ["endpointUrl"] = "",
                    ["caCert"] = "private-ca",
                    ["refreshHintSeconds"] = 0
                };
                break;
            case >= 8:
                row["authMethod"] = "token-auth";
                break;
        }
        return row;
    }

    private static async Task<object?> Execute(int route, JsonObject row, bool valid)
    {
        JsonObject response = route switch
        {
            0 => new() { ["identityAwsAuth"] = row },
            1 => new() { ["identityJwtAuth"] = row },
            2 => new() { ["identityUniversalAuth"] = row },
            3 => new() { ["identityTokenAuth"] = row },
            4 or 5 => new() { ["identitySpiffeAuth"] = row },
            6 => new() { ["clientSecretData"] = row },
            7 => new() { ["clientSecretData"] = row, ["clientSecret"] = "private-issued-secret" },
            8 => new() { ["tokens"] = new JsonArray(row) },
            9 => new()
            {
                ["tokenData"] = row,
                ["accessToken"] = "private-issued-token",
                ["tokenType"] = "Bearer",
                ["expiresIn"] = 30,
                ["accessTokenMaxTTL"] = 30
            },
            _ => new() { ["token"] = row }
        };
        string path = route switch
        {
            0 => $"/api/v1/auth/aws-auth/identities/{Identity}",
            1 => $"/api/v1/auth/jwt-auth/identities/{Identity}",
            2 => $"/api/v1/auth/universal-auth/identities/{Identity}",
            3 => $"/api/v1/auth/token-auth/identities/{Identity}",
            4 => $"/api/v1/auth/spiffe-auth/identities/{Identity}",
            5 => $"/api/v1/auth/spiffe-auth/identities/{Identity}/refresh-bundle",
            6 => $"/api/v1/auth/universal-auth/identities/{Identity}/client-secrets/{Secret}",
            7 => $"/api/v1/auth/universal-auth/identities/{Identity}/client-secrets",
            8 or 9 => $"/api/v1/auth/token-auth/identities/{Identity}/tokens",
            _ => $"/api/v1/auth/token-auth/tokens/{Token}"
        };
        string method = route is 5 or 7 or 9 ? "POST" : route == 11 ? "PATCH" : "GET";
        var wire = new Wire(response.ToJsonString());
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        var identityTarget = new ManagementTarget("org", resourceId: Identity);
        return route switch
        {
            0 => await Verify(CloudIdentityAuthenticationOperations.GetAwsAuth("org", Identity), identityTarget, value => value),
            1 => await Verify(WorkloadIdentityAuthenticationOperations.GetJwtAuth("org", Identity), identityTarget, value => value),
            2 => await Verify(IdentityAuthenticationOperations.GetUniversalAuth("org", Identity), identityTarget, value => value),
            3 => await Verify(IdentityAuthenticationOperations.GetTokenAuth("org", Identity), identityTarget, value => value),
            4 => await Verify(ExternalIdentityAuthenticationOperations.GetSpiffeAuth("org", Identity), identityTarget, value => value),
            5 => await Verify(ExternalIdentityAuthenticationOperations.RefreshSpiffeBundle("org", Identity), identityTarget, value => value),
            6 => await Verify(IdentityAuthenticationOperations.GetUniversalClientSecret("org", Identity, Secret),
                new("org", resourceId: Identity, secondaryId: Secret), value => value),
            7 => await Verify(IdentityAuthenticationOperations.CreateUniversalClientSecret("org", Identity),
                IdentityAuthenticationOperations.ClientSecretCreateTarget("org", Identity), value => value.Metadata),
            8 => await Verify(IdentityAuthenticationOperations.ListTokens("org", Identity), identityTarget, value => value.Items.Single()),
            9 => await Verify(IdentityAuthenticationOperations.CreateToken("org", Identity),
                IdentityAuthenticationOperations.TokenCreateTarget("org", Identity), value => value.Metadata),
            10 => await Verify(IdentityAuthenticationOperations.GetToken("org", Token), new("org", resourceId: Token), value => value),
            11 => await Verify(IdentityAuthenticationOperations.RenameToken("org", Token),
                IdentityAuthenticationOperations.TokenRenameTarget("org", Token), value => value),
            _ => throw new InvalidOperationException("Unexpected date adapter.")
        };

        async Task<object?> Verify<T>(ManagementRequest<T> request, ManagementTarget approved,
            Func<T, object> metadata) where T : notnull
        {
            using (request)
            {
                var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                var result = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(Operations[route], approved), receipt);
                try
                {
                    await Assert.That(wire.Observed).IsTrue();
                    await Assert.That(wire.Method).IsEqualTo(method);
                    await Assert.That(wire.Path).IsEqualTo(path);
                    await Assert.That(result.Status).IsEqualTo(valid ? SecretStatus.Success : SecretStatus.Unknown);
                    if (receipt is not null)
                        await Assert.That(receipt.Evidence).IsEqualTo(valid ? DispatchEvidence.Applied : DispatchEvidence.PossiblyDispatched);
                    return result.IsSuccess ? metadata(result.Value) : null;
                }
                finally { (result.IsSuccess ? result.Value as IDisposable : null)?.Dispose(); }
            }
        }
    }

    private sealed class Wire(string body) : HttpMessageHandler
    {
        public bool Observed { get; private set; }
        public string? Method { get; private set; }
        public string? Path { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Observed = true;
            Method = request.Method.Method;
            Path = request.RequestUri!.AbsolutePath;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) });
        }
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
    }
}
