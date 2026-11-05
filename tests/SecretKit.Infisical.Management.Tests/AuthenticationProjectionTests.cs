using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class AuthenticationProjectionTests
{
    private const string IdentityId = "11111111-1111-4111-8111-111111111111";
    private const string Common = """
        "id":"22222222-2222-4222-8222-222222222222","identityId":"11111111-1111-4111-8111-111111111111",
        "createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z"
        """;
    private static readonly string?[] Nodes =
    [
        null, "null", "{}", "[]",
        """{ "selector-canary": ["value-canary", null, {"nested":true}], "number":1.2300e+4 }""",
        """[{"returned-canary":false},["nested-canary",17],null]""",
        """{"escaped-canary":"line\n\u0061","empty":""}""",
        "\"scalar-canary\"", "9007199254740993", "true", "false"
    ];

    [Test]
    [Arguments("universal")]
    [Arguments("token")]
    [Arguments("jwt")]
    [Arguments("oidc")]
    [Arguments("kubernetes")]
    [Arguments("aws")]
    [Arguments("azure")]
    [Arguments("gcp")]
    [Arguments("alicloud")]
    [Arguments("ldap")]
    [Arguments("oci")]
    [Arguments("spiffe")]
    [Arguments("tls-cert")]
    public async Task ReturnedNumbersPreserveEachFamilyFieldContract(string strategy)
    {
        switch (strategy)
        {
            case "universal":
            case "token":
                using (var request = strategy == "universal"
                    ? IdentityAuthenticationOperations.GetUniversalAuth("org", IdentityId)
                    : IdentityAuthenticationOperations.GetTokenAuth("org", IdentityId))
                {
                    List<(string, Func<IdentityAuthenticationConfiguration, ManagementNumber?>)> fields =
                    [
                        ("accessTokenTTL", value => value.AccessTokenTTL),
                        ("accessTokenMaxTTL", value => value.AccessTokenMaxTTL),
                        ("accessTokenNumUsesLimit", value => value.AccessTokenNumUsesLimit),
                        ("accessTokenPeriod", value => value.AccessTokenPeriod)
                    ];
                    if (strategy == "universal")
                        fields.AddRange([
                            ("lockoutThreshold", value => value.LockoutThreshold),
                            ("lockoutDurationSeconds", value => value.LockoutDurationSeconds),
                            ("lockoutCounterResetSeconds", value => value.LockoutCounterResetSeconds)]);
                    else
                    {
                        var token = await Read(request, Response(strategy, null));
                        await Assert.That(token.LockoutThreshold).IsNull();
                        await Assert.That(token.LockoutDurationSeconds).IsNull();
                        await Assert.That(token.LockoutCounterResetSeconds).IsNull();
                    }
                    await CheckNumbers(request, strategy, false, fields);
                }
                break;
            case "jwt":
                await CheckWorkloadNumbers(WorkloadIdentityAuthenticationOperations.GetJwtAuth("org", IdentityId),
                    strategy, ("accessTokenPeriod", value => value.AccessTokenPeriod));
                break;
            case "oidc":
                await CheckWorkloadNumbers(WorkloadIdentityAuthenticationOperations.GetOidcAuth("org", IdentityId), strategy);
                break;
            case "kubernetes":
                await CheckWorkloadNumbers(WorkloadIdentityAuthenticationOperations.GetKubernetesAuth("org", IdentityId), strategy);
                break;
            case "aws":
                await CheckWorkloadNumbers(CloudIdentityAuthenticationOperations.GetAwsAuth("org", IdentityId),
                    strategy, ("accessTokenPeriod", value => value.AccessTokenPeriod));
                break;
            case "azure":
                await CheckWorkloadNumbers(CloudIdentityAuthenticationOperations.GetAzureAuth("org", IdentityId),
                    strategy, ("accessTokenPeriod", value => value.AccessTokenPeriod));
                break;
            case "gcp":
                await CheckWorkloadNumbers(CloudIdentityAuthenticationOperations.GetGcpAuth("org", IdentityId),
                    strategy, ("accessTokenPeriod", value => value.AccessTokenPeriod));
                break;
            case "alicloud":
                await CheckWorkloadNumbers(CloudIdentityAuthenticationOperations.GetAliCloudAuth("org", IdentityId), strategy);
                break;
            case "ldap":
                await CheckWorkloadNumbers(ExternalIdentityAuthenticationOperations.GetLdapAuth("org", IdentityId),
                    strategy, ("accessTokenPeriod", value => value.AccessTokenPeriod),
                    ("lockoutThreshold", value => value.LockoutThreshold),
                    ("lockoutDurationSeconds", value => value.LockoutDurationSeconds),
                    ("lockoutCounterResetSeconds", value => value.LockoutCounterResetSeconds));
                break;
            case "oci":
                await CheckWorkloadNumbers(ExternalIdentityAuthenticationOperations.GetOciAuth("org", IdentityId),
                    strategy, ("accessTokenPeriod", value => value.AccessTokenPeriod));
                break;
            case "spiffe":
                await CheckWorkloadNumbers(ExternalIdentityAuthenticationOperations.GetSpiffeAuth("org", IdentityId), strategy);
                break;
            case "tls-cert":
                await CheckWorkloadNumbers(ExternalIdentityAuthenticationOperations.GetTlsCertAuth("org", IdentityId), strategy);
                break;
        }
    }

    private static async Task CheckWorkloadNumbers<T>(ManagementRequest<T> request, string strategy,
        params (string Name, Func<T, ManagementNumber?> Read)[] additional) where T : WorkloadAuthConfiguration
    {
        using (request)
        {
            List<(string, Func<T, ManagementNumber?>)> fields =
            [
                ("accessTokenTTL", value => value.AccessTokenTTL),
                ("accessTokenMaxTTL", value => value.AccessTokenMaxTTL),
                ("accessTokenNumUsesLimit", value => value.AccessTokenNumUsesLimit)
            ];
            fields.AddRange(additional);
            await CheckNumbers(request, strategy, true, fields);
        }
    }

    private static async Task CheckNumbers<T>(ManagementRequest<T> request, string strategy, bool signed,
        IEnumerable<(string Name, Func<T, ManagementNumber?> Read)> fields) where T : notnull
    {
        foreach (var field in fields)
        {
            foreach (string? node in new string?[]
            {
                null, "0", "-0", "9007199254740993", "1.2300e+4",
                "0.123456789012345678901234567890123456789", "1e999999999999999999999999",
                "-0.25", "-1e999999999999999999999999", "-1e-999999999999999999999999",
                "null", "\"1\"", "false", "[]", "{}"
            })
            {
                string response = Response(strategy, null);
                if (node is not null)
                    response = response.Insert(response.IndexOf("\"createdAt\"", StringComparison.Ordinal),
                        "\"" + field.Name + "\":" + node + ",");
                using var transport = Transport(response);
                var client = new ManagementClient(transport);
                var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
                var result = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, new("org", resourceId: IdentityId)));
                bool rejected = node is "null" or "\"1\"" or "false" or "[]" or "{}" ||
                    !signed && node is not null && node.StartsWith('-') && node != "-0";
                await Assert.That(result.Status).IsEqualTo(rejected ? SecretStatus.Unknown : SecretStatus.Success);
                if (rejected) continue;
                using (result.Value as IDisposable)
                {
                    ManagementNumber? number = field.Read(result.Value);
                    await Assert.That(number.HasValue).IsEqualTo(node is not null);
                    if (number is { } present)
                    {
                        await Assert.That(present.Export()).IsEqualTo(node);
                        await Assert.That(JsonSerializer.Serialize(present)).IsEqualTo("{}");
                        await Assert.That(present.ToString()).IsEqualTo("[ManagementNumber]");
                    }
                }
            }
        }
    }

    [Test]
    [Arguments("universal")]
    [Arguments("token")]
    [Arguments("jwt")]
    [Arguments("oidc")]
    [Arguments("kubernetes")]
    [Arguments("aws")]
    [Arguments("azure")]
    [Arguments("gcp")]
    [Arguments("alicloud")]
    [Arguments("ldap")]
    [Arguments("oci")]
    [Arguments("spiffe")]
    [Arguments("tls-cert")]
    public async Task ReturnedJsonSurvivesParserAndClientDocumentDisposalWithoutShapeInference(string strategy)
    {
        foreach (string? node in Nodes)
        {
            string response = Response(strategy, node);
            switch (strategy)
            {
                case "universal":
                    await Check(IdentityAuthenticationOperations.GetUniversalAuth("org", IdentityId), response, node,
                        value => value.AccessTokenTrustedIps, value => value.ClientSecretTrustedIps);
                    break;
                case "token":
                    await Check(IdentityAuthenticationOperations.GetTokenAuth("org", IdentityId), response, node,
                        value => value.AccessTokenTrustedIps);
                    break;
                case "jwt":
                    await Check(WorkloadIdentityAuthenticationOperations.GetJwtAuth("org", IdentityId), response, node,
                        value => value.AccessTokenTrustedIps, value => value.BoundClaims);
                    break;
                case "oidc":
                    await Check(WorkloadIdentityAuthenticationOperations.GetOidcAuth("org", IdentityId), response, node,
                        value => value.AccessTokenTrustedIps, value => value.BoundClaims, value => value.ClaimMetadataMapping);
                    break;
                case "kubernetes":
                    await Check(WorkloadIdentityAuthenticationOperations.GetKubernetesAuth("org", IdentityId), response, node,
                        value => value.AccessTokenTrustedIps);
                    break;
                case "aws":
                    await Check(CloudIdentityAuthenticationOperations.GetAwsAuth("org", IdentityId), response, node,
                        value => value.AccessTokenTrustedIps);
                    break;
                case "azure":
                    await Check(CloudIdentityAuthenticationOperations.GetAzureAuth("org", IdentityId), response, node,
                        value => value.AccessTokenTrustedIps);
                    break;
                case "gcp":
                    await Check(CloudIdentityAuthenticationOperations.GetGcpAuth("org", IdentityId), response, node,
                        value => value.AccessTokenTrustedIps);
                    break;
                case "alicloud":
                    await Check(CloudIdentityAuthenticationOperations.GetAliCloudAuth("org", IdentityId), response, node,
                        value => value.AccessTokenTrustedIps);
                    break;
                case "ldap":
                    await Check(ExternalIdentityAuthenticationOperations.GetLdapAuth("org", IdentityId), response, node,
                        value => value.AccessTokenTrustedIps, value => value.AllowedFields);
                    break;
                case "oci":
                    await Check(ExternalIdentityAuthenticationOperations.GetOciAuth("org", IdentityId), response, node,
                        value => value.AccessTokenTrustedIps);
                    break;
                case "spiffe":
                    await Check(ExternalIdentityAuthenticationOperations.GetSpiffeAuth("org", IdentityId), response, node,
                        value => value.AccessTokenTrustedIps);
                    break;
                case "tls-cert":
                    await Check(ExternalIdentityAuthenticationOperations.GetTlsCertAuth("org", IdentityId), response, node,
                        value => value.AccessTokenTrustedIps);
                    break;
                default:
                    throw new InvalidOperationException("Unknown test strategy.");
            }
        }
    }

    [Test]
    public async Task OptionalFieldsRetainIndependentPresenceAndValues()
    {
        using var universal = IdentityAuthenticationOperations.GetUniversalAuth("org", IdentityId);
        var identity = await Read(universal, Response("universal", null)
            .Replace("\"clientId\":\"client-canary\"", """
                "clientId":"client-canary","accessTokenTrustedIps":null,"clientSecretTrustedIps":[{"returned-canary":17}]
                """, StringComparison.Ordinal));
        await Assert.That(identity.AccessTokenTrustedIps.IsNull).IsTrue();
        await AssertField(identity.ClientSecretTrustedIps, """[{"returned-canary":17}]""");
        await Assert.That(identity.ClientSecretTrustedIps.Value[0].GetProperty("returned-canary").GetInt32()).IsEqualTo(17);

        using var oidc = WorkloadIdentityAuthenticationOperations.GetOidcAuth("org", IdentityId);
        var workload = await Read(oidc, Response("oidc", null)
            .Replace("\"caCert\":\"\"", """
                "caCert":"","boundClaims":null,"claimMetadataMapping":{"returned-canary":["value-canary"]}
                """, StringComparison.Ordinal));
        await Assert.That(workload.AccessTokenTrustedIps.IsPresent).IsFalse();
        await Assert.That(workload.BoundClaims.IsNull).IsTrue();
        await AssertField(workload.ClaimMetadataMapping, """{"returned-canary":["value-canary"]}""");
        await Assert.That(workload.ClaimMetadataMapping.Value.GetProperty("returned-canary")[0].GetString()).IsEqualTo("value-canary");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task EncryptedCaRetainsJsonAndIndependentMaterialCustody(bool read)
    {
        foreach (string node in Nodes.OfType<string>())
        {
            using var request = read
                ? ExternalIdentityAuthenticationOperations.GetTlsCertAuth("org", IdentityId)
                : ExternalIdentityAuthenticationOperations.DeleteTlsCertAuth("org", IdentityId);
            string response = Response("tls-cert", null).Replace("\"encryptedCaCertificate\":null",
                "\"encryptedCaCertificate\":" + node, StringComparison.Ordinal);
            if (!read) response = response.Replace(",\"caCertificate\":\"ca-canary\"", "", StringComparison.Ordinal);
            TlsCertAuthConfiguration parsed;
            using (var document = JsonDocument.Parse(response))
                parsed = request.Parse(document.RootElement);
            using (parsed)
                await AssertEncryptedCa(parsed, node, read);
            using var received = await Read(request, response);
            await AssertEncryptedCa(received, node, read);
        }
    }

    [Test]
    public async Task EncryptedCaMissingStillFailsTheRequiredFieldContract()
    {
        using var request = ExternalIdentityAuthenticationOperations.GetTlsCertAuth("org", IdentityId);
        string response = Response("tls-cert", null)
            .Replace(",\"encryptedCaCertificate\":null", "", StringComparison.Ordinal);
        using var document = JsonDocument.Parse(response);
        await Assert.That(() => request.Parse(document.RootElement)).Throws<ManagementContractException>();
        using var transport = Transport(response);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new("org", resourceId: IdentityId)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(result.ToString()!.Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("duplicate")]
    [Arguments("depth")]
    [Arguments("identity")]
    [Arguments("extra")]
    public async Task PreservingJsonDoesNotBypassClientResponseValidation(string defect)
    {
        using var request = WorkloadIdentityAuthenticationOperations.GetJwtAuth("org", IdentityId);
        string node = defect switch
        {
            "duplicate" => """{"nested":{"value-canary":1,"value-canary":2}}""",
            "depth" => new string('[', 65) + "\"value-canary\"" + new string(']', 65),
            _ => """{"value-canary":[false,null]}"""
        };
        string response = Response("jwt", node);
        if (defect == "identity") response = response.Replace(IdentityId,
            "33333333-3333-4333-8333-333333333333", StringComparison.Ordinal);
        if (defect == "extra") response = response.Replace("\"jwksUrl\":\"\"",
            "\"jwksUrl\":\"\",\"undeclared\":\"value-canary\"", StringComparison.Ordinal);
        using var transport = Transport(response);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new("org", resourceId: IdentityId)));
        await Assert.That(result.Status).IsEqualTo(defect == "identity" ? SecretStatus.Invalid : SecretStatus.Unknown);
        await Assert.That(JsonSerializer.Serialize(result).Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    private static async Task Check<T>(ManagementRequest<T> request, string response, string? expected,
        params Func<T, ProjectField<JsonElement>>[] fields) where T : notnull
    {
        using (request)
        {
            T parsed;
            using (var document = JsonDocument.Parse(response))
                parsed = request.Parse(document.RootElement);
            using (parsed as IDisposable)
            {
                await AssertProtected(parsed);
                foreach (var field in fields) await AssertField(field(parsed), expected);
            }
            // ExecuteAsync has disposed its source document and cleared response bytes before returning.
            T received = await Read(request, response);
            using (received as IDisposable)
            {
                await AssertProtected(received);
                foreach (var field in fields) await AssertField(field(received), expected);
            }
        }
    }

    private static async Task AssertField(ProjectField<JsonElement> field, string? expected)
    {
        await Assert.That(field.IsPresent).IsEqualTo(expected is not null);
        await Assert.That(field.IsNull).IsEqualTo(expected == "null");
        await Assert.That(field.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
        using var serialized = JsonDocument.Parse(JsonSerializer.Serialize(field));
        await Assert.That(serialized.RootElement.EnumerateObject().Select(property => property.Name)
            .SequenceEqual(["IsPresent", "IsNull"])).IsTrue();
        if (expected is null or "null")
            await Assert.That(() => field.Value).Throws<InvalidOperationException>();
        else
            // Exact JSON retains nested values, empty collections, escapes and numeric precision.
            await Assert.That(field.Value.GetRawText()).IsEqualTo(expected);
    }

    private static async Task AssertEncryptedCa(TlsCertAuthConfiguration value, string expected, bool read)
    {
        await AssertProtected(value);
        var field = value.EncryptedCaCertificate;
        await Assert.That(field.IsPresent).IsTrue();
        await Assert.That(field.IsNull).IsEqualTo(expected == "null");
        await Assert.That(JsonSerializer.Serialize(field).Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(field.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
        if (field.IsNull)
        {
            await Assert.That(() => field.Value).Throws<InvalidOperationException>();
            value.Dispose();
            if (read)
                await Assert.That(() => value.CaCertificate!.Reveal()).Throws<ObjectDisposedException>();
            return;
        }
        await Assert.That(JsonSerializer.Serialize(field.Value)).IsEqualTo("{}");
        await Assert.That(field.Value.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
        using var copy = field.Value.Copy();
        using var certificateCopy = value.CaCertificate?.Copy();
        value.Dispose();
        value.Dispose();
        await Assert.That(() => field.Value.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(copy.Reveal()).IsEqualTo(expected);
        using var exported = JsonDocument.Parse(copy.Reveal());
        await Assert.That(exported.RootElement.GetRawText()).IsEqualTo(expected);
        if (read)
        {
            await Assert.That(certificateCopy!.Reveal()).IsEqualTo("ca-canary");
            await Assert.That(() => value.CaCertificate!.Reveal()).Throws<ObjectDisposedException>();
        }
        else await Assert.That(value.CaCertificate is null).IsTrue();
        await AssertProtected(value);
    }

    private static async Task AssertProtected<T>(T value) where T : notnull
    {
        await Assert.That(JsonSerializer.Serialize(value, value.GetType())).IsEqualTo("{}");
        await Assert.That(value.ToString()!.Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    private static async Task<T> Read<T>(ManagementRequest<T> request, string response) where T : notnull
    {
        using var transport = Transport(response);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new("org", resourceId: IdentityId)),
            request.IsMutation ? client.CreateReceipt(request) : null);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        return result.Value;
    }

    private static string Response(string strategy, string? node)
    {
        string envelope = strategy switch
        {
            "universal" => "identityUniversalAuth",
            "token" => "identityTokenAuth",
            "jwt" => "identityJwtAuth",
            "oidc" => "identityOidcAuth",
            "kubernetes" => "identityKubernetesAuth",
            "aws" => "identityAwsAuth",
            "azure" => "identityAzureAuth",
            "gcp" => "identityGcpAuth",
            "alicloud" => "identityAliCloudAuth",
            "ldap" => "identityLdapAuth",
            "oci" => "identityOciAuth",
            "spiffe" => "identitySpiffeAuth",
            "tls-cert" => "identityTlsCertAuth",
            _ => throw new InvalidOperationException("Unknown test strategy.")
        };
        string fields = strategy switch
        {
            "universal" => ",\"clientId\":\"client-canary\"",
            "token" => "",
            "jwt" => ""","configurationType":"static","jwksUrl":"","jwksCaCert":"","publicKeys":[],"boundIssuer":"","boundAudiences":"","boundSubject":"" """,
            "oidc" => ""","oidcDiscoveryUrl":"","boundIssuer":"","boundAudiences":"","caCert":"" """,
            "kubernetes" => ""","allowedAudience":"","allowedNames":"","allowedNamespaces":"","caCert":"" """,
            "aws" => ""","type":"native","allowedPrincipalArns":"","allowedAccountIds":"","stsEndpoint":"" """,
            "azure" => ""","tenantId":"","resource":"","allowedServicePrincipalIds":"" """,
            "gcp" => ""","type":"iam" """,
            "alicloud" => ""","type":"native","allowedArns":"" """,
            "ldap" => ""","url":"","searchBase":"","searchFilter":"","bindDN":"" """,
            "oci" => ""","tenancyOcid":"","type":"native" """,
            "spiffe" => ""","trustDomain":"","allowedSpiffeIds":"","allowedAudiences":"","trustBundleDistribution":{"profile":"static","bundle":"bundle-canary"}""",
            "tls-cert" => ""","allowedSubjectAltNames":null,"encryptedCaCertificate":null,"caCertificate":"ca-canary" """,
            _ => throw new InvalidOperationException("Unknown test strategy.")
        };
        if (node is not null)
        {
            fields += ",\"accessTokenTrustedIps\":" + node;
            if (strategy == "universal") fields += ",\"clientSecretTrustedIps\":" + node;
            if (strategy is "jwt" or "oidc") fields += ",\"boundClaims\":" + node;
            if (strategy == "oidc") fields += ",\"claimMetadataMapping\":" + node;
            if (strategy == "ldap") fields += ",\"allowedFields\":" + node;
        }
        return "{\"" + envelope + "\":{" + Common + fields + "}}";
    }

    private static ManagementTransport Transport(string response) =>
        new(new("https://management.test"), 1024 * 1024, null, false, new Wire(response));

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("admin-canary"))));
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
