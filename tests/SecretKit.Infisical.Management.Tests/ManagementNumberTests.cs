using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ManagementNumberTests
{
    private const string IdentityId = "11111111-1111-4111-8111-111111111111";
    private const string Common = """
        "id":"22222222-2222-4222-8222-222222222222","identityId":"11111111-1111-4111-8111-111111111111",
        "createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z"
        """;

    [Test]
    [Arguments("9007199254740993")]
    [Arguments("9223372036854775807")]
    [Arguments("0.1234567890123456789012345678")]
    public async Task ReturnedAuthenticationNumberPreservesExactlyRepresentableDecimal(string token)
    {
        using var request = IdentityAuthenticationOperations.GetTokenAuth("org", IdentityId);
        var result = await Execute(request, "{\"identityTokenAuth\":{" + Common +
            ",\"accessTokenNumUsesLimit\":" + token + "}}");

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.AccessTokenNumUsesLimit!.Value.GetDecimal())
            .IsEqualTo(decimal.Parse(token, CultureInfo.InvariantCulture));
    }

    [Test]
    public async Task ReturnedAuthenticationNumberBeyondDoubleRangeRemainsAdmitted()
    {
        using var request = IdentityAuthenticationOperations.GetTokenAuth("org", IdentityId);
        var result = await Execute(request, "{\"identityTokenAuth\":{" + Common +
            ",\"accessTokenNumUsesLimit\":1e999}}");

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.AccessTokenNumUsesLimit!.Value.Export()).IsEqualTo("1e999");
    }

    [Test]
    [Arguments("0", "0", "0")]
    [Arguments("-0.00e999999999999999999999999", "0", "0")]
    [Arguments("9007199254740991", "9007199254740991", "9007199254740991")]
    [Arguments("9007199254740992", "9007199254740992", "9007199254740992")]
    [Arguments("9007199254740993", "9007199254740993", "9007199254740993")]
    [Arguments("9223372036854775807", "9223372036854775807", "9223372036854775807")]
    [Arguments("9223372036854775808", "9223372036854775808", null)]
    [Arguments("-9223372036854775808", "-9223372036854775808", "-9223372036854775808")]
    [Arguments("-9223372036854775809", "-9223372036854775809", null)]
    [Arguments("92233720368547758070e-1", "9223372036854775807", "9223372036854775807")]
    [Arguments("-92233720368547758080e-1", "-9223372036854775808", "-9223372036854775808")]
    [Arguments("1.2300e+4", "12300", "12300")]
    [Arguments("1.2300E-2", "0.0123", null)]
    [Arguments("1e00000000000000000000000000000002", "100", "100")]
    [Arguments("0.1234567890123456789012345678", "0.1234567890123456789012345678", null)]
    [Arguments("0.12345678901234567890123456789", null, null)]
    [Arguments("1.00000000000000000000000000001", null, null)]
    [Arguments("1.00000000000000000000000000000", "1", "1")]
    [Arguments("0.00000000000000000000000000010", "0.0000000000000000000000000001", null)]
    [Arguments("1e-28", "0.0000000000000000000000000001", null)]
    [Arguments("1e-29", null, null)]
    [Arguments("-1e-29", null, null)]
    [Arguments("5e-29", null, null)]
    [Arguments("9e-29", null, null)]
    [Arguments("1e28", "10000000000000000000000000000", null)]
    [Arguments("1e29", null, null)]
    [Arguments("79228162514264337593543950335", "79228162514264337593543950335", null)]
    [Arguments("-79228162514264337593543950335", "-79228162514264337593543950335", null)]
    [Arguments("79228162514264337593543950336", null, null)]
    [Arguments("7922816251426433759354395033.5", "7922816251426433759354395033.5", null)]
    [Arguments("7922816251426433759354395033.6", null, null)]
    [Arguments("79228162514264337593543950335.0", "79228162514264337593543950335", null)]
    [Arguments("79228162514264337593543950335.1", null, null)]
    [Arguments("1e999", null, null)]
    [Arguments("1e-999", null, null)]
    [Arguments("1e999999999999999999999999999999999999999999", null, null)]
    [Arguments("1e-999999999999999999999999999999999999999999", null, null)]
    public async Task CheckedAccessSucceedsOnlyForExactRepresentationsAndKeepsRawToken(
        string token, string? exactDecimal, string? exactInteger)
    {
        ManagementNumber number = await Number(token);

        await Assert.That(number.IsInitialized).IsTrue();
        await Assert.That(number.TryGetDecimal(out decimal decimalValue)).IsEqualTo(exactDecimal is not null);
        if (exactDecimal is null)
            await Assert.That(() => number.GetDecimal()).Throws<OverflowException>();
        else
        {
            decimal expected = decimal.Parse(exactDecimal, CultureInfo.InvariantCulture);
            await Assert.That(decimalValue).IsEqualTo(expected);
            await Assert.That(number.GetDecimal()).IsEqualTo(expected);
        }
        await Assert.That(number.TryGetInt64(out long integerValue)).IsEqualTo(exactInteger is not null);
        if (exactInteger is null)
            await Assert.That(() => number.GetInt64()).Throws<OverflowException>();
        else
        {
            long expected = long.Parse(exactInteger, CultureInfo.InvariantCulture);
            await Assert.That(integerValue).IsEqualTo(expected);
            await Assert.That(number.GetInt64()).IsEqualTo(expected);
        }
        await Assert.That(number.Export()).IsEqualTo(token);
    }

    [Test]
    public async Task ExponentsAndSignificandsAreBoundedByTokenLengthWithoutExpansion()
    {
        foreach (string token in new[]
        {
            "1e" + new string('9', 16000),
            "-1e-" + new string('9', 16000),
            "0." + new string('0', 16000) + "1",
            new string('9', 16000)
        })
        {
            ManagementNumber number = await Number(token);
            await Assert.That(number.TryGetDecimal(out _)).IsFalse();
            await Assert.That(number.TryGetInt64(out _)).IsFalse();
            await Assert.That(number.Export()).IsEqualTo(token);
        }
        foreach (string token in new[]
        {
            "1" + new string('0', 16000) + "e-16000",
            "0." + new string('0', 16000) + "1e16001",
            "1e+" + new string('0', 16000)
        })
        {
            ManagementNumber number = await Number(token);
            await Assert.That(number.GetDecimal()).IsEqualTo(1m);
            await Assert.That(number.GetInt64()).IsEqualTo(1L);
            await Assert.That(number.Export()).IsEqualTo(token);
        }
    }

    [Test]
    public async Task DefaultIsUninitializedAndCannotBeExportedOrConvertedToZero()
    {
        ManagementNumber number = default;
        await Assert.That(number.IsInitialized).IsFalse();
        await Assert.That(number.TryGetDecimal(out _)).IsFalse();
        await Assert.That(number.TryGetInt64(out _)).IsFalse();
        await Assert.That(() => number.Export()).Throws<InvalidOperationException>();
        await Assert.That(() => number.GetDecimal()).Throws<InvalidOperationException>();
        await Assert.That(() => number.GetInt64()).Throws<InvalidOperationException>();
        await Assert.That(JsonSerializer.Serialize(number)).IsEqualTo("{}");
        await Assert.That(number.ToString()).IsEqualTo("[ManagementNumber]");
    }

    [Test]
    public async Task DetachedTokenSurvivesDocumentDisposalAndOnlyExplicitExportDisclosesIt()
    {
        using var request = ExternalIdentityAuthenticationOperations.ClearLdapAuthLockouts("org", IdentityId);
        ManagementNumber number;
        using (var document = JsonDocument.Parse("""{"deleted":1234567890.123400e+002}"""))
            number = request.Parse(document.RootElement).Deleted;

        await Assert.That(number.Export()).IsEqualTo("1234567890.123400e+002");
        await Assert.That(number.GetDecimal()).IsEqualTo(123456789012.34m);
        await Assert.That($"{number}").IsEqualTo("[ManagementNumber]");
        await Assert.That(JsonSerializer.Serialize(new { Number = number })).IsEqualTo("""{"Number":{}}""");
        await Assert.That(number.TryGetInt64(out _)).IsFalse();
        var failure = await Assert.That(() => number.GetInt64()).Throws<OverflowException>();
        await Assert.That(failure!.Message.Contains("1234567890", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task ResponseBudgetStillRejectsOversizedNumericTokens()
    {
        using var request = IdentityAuthenticationOperations.GetTokenAuth("org", IdentityId);
        var result = await Execute(request, "{\"identityTokenAuth\":{" + Common +
            ",\"accessTokenTTL\":1e" + new string('9', 2048) + "}}", responseLimit: 1024);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    public async Task CredentialMetadataRetainsEveryOptionalNumberWithoutNullOrNegativeAdmission()
    {
        using var secret = IdentityAuthenticationOperations.GetUniversalClientSecret("org", IdentityId, "secret");
        const string secretFields = """
            "id":"secret","identityUAId":"22222222-2222-4222-8222-222222222222",
            "description":"","clientSecretPrefix":"","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z"
            """;
        await CheckFields(secret, (field, node) => "{\"clientSecretData\":{" + secretFields + Member(field, node) + "}}",
            required: false, signed: false,
            ("clientSecretNumUses", value => value.ClientSecretNumUses),
            ("clientSecretNumUsesLimit", value => value.ClientSecretNumUsesLimit),
            ("clientSecretTTL", value => value.ClientSecretTTL));
        using var token = IdentityAuthenticationOperations.GetToken("org", "22222222-2222-4222-8222-222222222222");
        await CheckFields(token, (field, node) => "{\"token\":{" + Common + ",\"authMethod\":\"token-auth\"" +
            Member(field, node) + "}}", required: false, signed: false,
            ("accessTokenTTL", value => value.AccessTokenTTL),
            ("accessTokenMaxTTL", value => value.AccessTokenMaxTTL),
            ("accessTokenNumUses", value => value.AccessTokenNumUses),
            ("accessTokenNumUsesLimit", value => value.AccessTokenNumUsesLimit),
            ("accessTokenPeriod", value => value.AccessTokenPeriod));
    }

    [Test]
    public async Task IssuanceAndLockoutCountsRetainRequirednessAndTheirOwnSignPolicy()
    {
        using var issuance = IdentityAuthenticationOperations.CreateToken("org", IdentityId);
        await CheckFields(issuance, (field, node) => "{\"tokenData\":{" + Common +
            ",\"authMethod\":\"token-auth\"},\"accessToken\":\"issued-fixture\",\"tokenType\":\"Bearer\"" +
            Member(field == "expiresIn" ? "accessTokenMaxTTL" : "expiresIn", "0") + Member(field, node) + "}",
            required: true, signed: false,
            ("expiresIn", value => value.ExpiresIn),
            ("accessTokenMaxTTL", value => value.AccessTokenMaxTTL));
        using var universal = IdentityAuthenticationOperations.ClearUniversalAuthLockouts("org", IdentityId);
        await CheckFields(universal, (field, node) => "{" + Member(field, node).TrimStart(',') + "}",
            required: true, signed: false, ("deleted", value => value.Deleted));
        using var ldap = ExternalIdentityAuthenticationOperations.ClearLdapAuthLockouts("org", IdentityId);
        await CheckFields(ldap, (field, node) => "{" + Member(field, node).TrimStart(',') + "}",
            required: true, signed: true, ("deleted", value => value.Deleted));
    }

    [Test]
    public async Task SpiffeRefreshHintIsRequiredOnlyForHttpsBundleAndRemainsSigned()
    {
        using var request = ExternalIdentityAuthenticationOperations.GetSpiffeAuth("org", IdentityId);
        string prefix = "{\"identitySpiffeAuth\":{" + Common +
            ",\"trustDomain\":\"\",\"allowedSpiffeIds\":\"\",\"allowedAudiences\":\"\",\"trustBundleDistribution\":";
        await CheckFields(request, (field, node) => prefix +
            "{\"profile\":\"https_web_bundle\",\"endpointUrl\":\"\",\"caCert\":\"\"" + Member(field, node) + "}}}",
            required: true, signed: true, ("refreshHintSeconds", value => value.TrustBundleDistribution.RefreshHintSeconds));
        var result = await Execute(request, prefix + "{\"profile\":\"static\",\"bundle\":\"fixture-bundle\"}}}");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        using var configuration = result.Value;
        await Assert.That(configuration.TrustBundleDistribution.RefreshHintSeconds).IsNull();
    }

    private static async Task CheckFields<T>(ManagementRequest<T> request,
        Func<string, string?, string> response, bool required, bool signed,
        params (string Name, Func<T, ManagementNumber?> Read)[] fields) where T : notnull
    {
        foreach (var field in fields)
            foreach (string? node in new string?[] { null, "null", "false", "\"1\"", "[]", "{}", "0", "-0",
                "9007199254740993", "1.2300e+4", "1e99999", "-1.5", "-1e99999", "-1e-99999" })
            {
                var result = await Execute(request, response(field.Name, node));
                bool rejected = node is null && required || node is "null" or "false" or "\"1\"" or "[]" or "{}" ||
                    !signed && node is not null && node.StartsWith('-') && node != "-0";
                await Assert.That(result.Status).IsEqualTo(rejected ? SecretStatus.Unknown : SecretStatus.Success);
                if (rejected) continue;
                using (result.Value as IDisposable)
                {
                    ManagementNumber? number = field.Read(result.Value);
                    await Assert.That(number.HasValue).IsEqualTo(node is not null);
                    if (number is { } present) await Assert.That(present.Export()).IsEqualTo(node);
                }
            }
    }

    private static string Member(string field, string? node) => node is null ? "" : ",\"" + field + "\":" + node;

    private static async Task<ManagementNumber> Number(string token)
    {
        using var request = ExternalIdentityAuthenticationOperations.ClearLdapAuthLockouts("org", IdentityId);
        var result = await Execute(request, "{\"deleted\":" + token + "}");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        return result.Value.Deleted;
    }

    private static async Task<SecretOutcome<T>> Execute<T>(ManagementRequest<T> request, string response,
        int responseLimit = 1024 * 1024) where T : notnull
    {
        using var transport = new ManagementTransport(new("https://management.test"), responseLimit,
            null, false, new Wire(response));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        return await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, request.Target),
            request.IsMutation ? client.CreateReceipt(request) : null);
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText("fixture-admin"))));
    }

    private sealed class Wire(string response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(response, Encoding.UTF8, "application/json")
            });
    }
}
