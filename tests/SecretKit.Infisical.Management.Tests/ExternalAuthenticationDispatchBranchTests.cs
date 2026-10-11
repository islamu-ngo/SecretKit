using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ExternalAuthenticationDispatchBranchTests
{
    private const string IdentityId = "11111111-1111-4111-8111-111111111111";
    private const string ConfigurationId = "22222222-2222-4222-8222-222222222222";
    private const string TemplateId = "44444444-4444-4444-8444-444444444444";

    // WG01-WG08: bounded request alternatives, not scalar Cartesian products.
    // Expected JSON is literal and is compared to the actual handler content.
    // Approvals are independently constructed; Applied is only a local receipt,
    // not evidence of native persistence, issuer acceptance or effective policy.
    [Test]
    [Arguments(false, "full")]
    [Arguments(false, "omitted")]
    [Arguments(false, "empty")]
    [Arguments(true, "full")]
    [Arguments(true, "omitted")]
    [Arguments(true, "empty")]
    [Arguments(true, "material")]
    public async Task LdapConnectionAndPatchDispatchRetainIndependentFields(bool update, string basis)
    {
        using var input = Ldap(basis, update);
        using var approved = Ldap(basis, update);
        using var denied = Ldap(basis == "full" ? "omitted" : "full", update);
        using var request = update
            ? ExternalIdentityAuthenticationOperations.UpdateLdapAuth("org", IdentityId, input)
            : ExternalIdentityAuthenticationOperations.AttachLdapAuth("org", IdentityId, input);
        var target = ExternalIdentityAuthenticationOperations.LdapAuthConfigurationTarget("org", IdentityId, approved, update);
        var wrong = ExternalIdentityAuthenticationOperations.LdapAuthConfigurationTarget("org", IdentityId, denied, update);
        input.Dispose();
        approved.Dispose();
        denied.Dispose();
        await Assert.That(() => ExternalIdentityAuthenticationOperations.LdapAuthConfigurationTarget("org", IdentityId, input, update))
            .Throws<ObjectDisposedException>();
        await PrivateInput(input);
        await Dispatch(request, "ldap", update, ExpectedLdap(basis, update), target, wrong);
    }

    [Test]
    [Arguments(false, "full")]
    [Arguments(false, "omitted")]
    [Arguments(false, "null")]
    [Arguments(false, "empty")]
    [Arguments(true, "full")]
    [Arguments(true, "omitted")]
    [Arguments(true, "null")]
    [Arguments(true, "empty")]
    public async Task OciDispatchRetainsUsernamePresenceAndPolicy(bool update, string basis)
    {
        var input = Oci(basis, update);
        using var request = update
            ? ExternalIdentityAuthenticationOperations.UpdateOciAuth("org", IdentityId, input)
            : ExternalIdentityAuthenticationOperations.AttachOciAuth("org", IdentityId, input);
        var target = ExternalIdentityAuthenticationOperations.OciAuthConfigurationTarget("org", IdentityId, Oci(basis, update), update);
        var wrong = ExternalIdentityAuthenticationOperations.OciAuthConfigurationTarget("org", IdentityId,
            Oci(basis == "full" ? "omitted" : "full", update), update);
        await PrivateInput(input);
        await Dispatch(request, "oci", update, ExpectedOci(basis, update), target, wrong);
    }

    [Test]
    [Arguments(false, "full")]
    [Arguments(false, "minimal")]
    [Arguments(false, "empty")]
    [Arguments(true, "full")]
    [Arguments(true, "minimal")]
    [Arguments(true, "empty")]
    [Arguments(true, "omitted")]
    public async Task SpiffeDispatchRetainsHttpsBundleRequestAlternatives(bool update, string basis)
    {
        using var input = Spiffe(basis, update);
        using var approved = Spiffe(basis, update);
        using var denied = Spiffe(basis == "full" ? "minimal" : "full", update);
        using var request = update
            ? ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth("org", IdentityId, input)
            : ExternalIdentityAuthenticationOperations.AttachSpiffeAuth("org", IdentityId, input);
        var target = ExternalIdentityAuthenticationOperations.SpiffeAuthConfigurationTarget("org", IdentityId, approved, update);
        var wrong = ExternalIdentityAuthenticationOperations.SpiffeAuthConfigurationTarget("org", IdentityId, denied, update);
        input.Dispose();
        approved.Dispose();
        denied.Dispose();
        await Assert.That(() => ExternalIdentityAuthenticationOperations.SpiffeAuthConfigurationTarget("org", IdentityId, input, update))
            .Throws<ObjectDisposedException>();
        await PrivateInput(input);
        await Dispatch(request, "spiffe", update, ExpectedSpiffe(basis, update), target, wrong);
    }

    [Test]
    [Arguments(false, "full")]
    [Arguments(false, "omitted")]
    [Arguments(false, "null")]
    [Arguments(false, "empty")]
    [Arguments(true, "full")]
    [Arguments(true, "omitted")]
    [Arguments(true, "null")]
    [Arguments(true, "empty")]
    public async Task TlsDispatchRetainsNamesSansChainFlagAndPolicy(bool update, string basis)
    {
        using var input = Tls(basis, update);
        using var approved = Tls(basis, update);
        using var denied = Tls(basis == "full" ? "omitted" : "full", update);
        using var request = update
            ? ExternalIdentityAuthenticationOperations.UpdateTlsCertAuth("org", IdentityId, input)
            : ExternalIdentityAuthenticationOperations.AttachTlsCertAuth("org", IdentityId, input);
        var target = ExternalIdentityAuthenticationOperations.TlsCertAuthConfigurationTarget("org", IdentityId, approved, update);
        var wrong = ExternalIdentityAuthenticationOperations.TlsCertAuthConfigurationTarget("org", IdentityId, denied, update);
        input.Dispose();
        approved.Dispose();
        denied.Dispose();
        await Assert.That(() => ExternalIdentityAuthenticationOperations.TlsCertAuthConfigurationTarget("org", IdentityId, input, update))
            .Throws<ObjectDisposedException>();
        await PrivateInput(input);
        await Dispatch(request, "tls-cert", update, ExpectedTls(basis, update), target, wrong);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task TlsEmptyCommonNameIsRejectedRatherThanInventingDispatchedAcceptance(bool update)
    {
        using var certificate = SecretMaterial.FromText("certificate-canary");
        await Assert.That(() =>
        {
            using var input = new TlsCertAuthConfigurationInput(certificate,
                WorkloadAuthNullableText.FromValue(""));
            using var request = update
                ? ExternalIdentityAuthenticationOperations.UpdateTlsCertAuth("org", IdentityId, input)
                : ExternalIdentityAuthenticationOperations.AttachTlsCertAuth("org", IdentityId, input);
        }).Throws<ArgumentException>();
    }

    private static WorkloadAuthTokenPolicy Policy(string basis, bool update, bool positiveAttachMax = true)
    {
        if (basis is "omitted" or "minimal" or "material") return new();
        if (basis == "empty") return new(0, positiveAttachMax && !update ? 1 : 0, 0, []);
        var ips = new List<IdentityTrustedIp> { new("127.0.0.1/32"), new("::1") };
        var policy = new WorkloadAuthTokenPolicy(17, 23, 5, ips);
        ips.Clear();
        return policy;
    }

    private static LdapAuthConfigurationInput Ldap(string basis, bool update)
    {
        using var password = SecretMaterial.FromText("bind-canary");
        using var certificate = SecretMaterial.FromText(basis == "empty" ? "" : "ldap-ca-canary");
        if (basis == "material") return LdapAuthConfigurationInput.Patch(bindPass: password);
        if (basis == "omitted") return update ? LdapAuthConfigurationInput.Patch()
            : LdapAuthConfigurationInput.FromConnection("ldaps://directory.test", "dn-canary", password, "base-canary");
        var fields = new List<LdapAuthAllowedField> { new("attribute-canary", "value-canary"), new("", "") };
        var settings = basis == "empty"
            ? new LdapAuthSettings(allowedFields: [], lockoutEnabled: false, policy: Policy(basis, update))
            : new LdapAuthSettings("(uid=filter-canary)", fields, false, 1.5, 30.5, 5.5, Policy(basis, update));
        fields.Clear();
        return update
            ? LdapAuthConfigurationInput.Patch(TemplateId, "ldaps://directory.test", "dn-canary", password, "base-canary", settings)
            : LdapAuthConfigurationInput.FromConnection("ldaps://directory.test", "dn-canary", password, "base-canary", certificate, settings);
    }

    private static OciAuthConfigurationInput Oci(string basis, bool update) => new("tenancy-canary", basis switch
    {
        "omitted" => null,
        "null" => WorkloadAuthNullableText.Null(),
        "empty" => WorkloadAuthNullableText.FromValue(""),
        _ => WorkloadAuthNullableText.FromValue("username-canary")
    }, Policy(basis, update));

    private static SpiffeAuthConfigurationInput Spiffe(string basis, bool update)
    {
        if (basis == "omitted") return new();
        using var certificate = SecretMaterial.FromText(basis == "empty" ? "" : "bundle-ca-canary");
        using var distribution = basis == "minimal"
            ? SpiffeTrustBundleInput.HttpsWebBundle("https://bundle.test/keys")
            : SpiffeTrustBundleInput.HttpsWebBundle("https://bundle.test/keys", certificate, basis == "empty" ? 0 : 37);
        return new("domain-canary", "spiffe://domain.test/id-canary", "audience-canary", distribution, Policy(basis, update, false));
    }

    private static TlsCertAuthConfigurationInput Tls(string basis, bool update)
    {
        if (basis == "omitted" && update) return new();
        using var certificate = SecretMaterial.FromText("certificate-canary");
        var names = new List<string> { "dns-canary.test", "uri-canary" };
        var sans = basis switch
        {
            "omitted" => null,
            "null" => TlsAuthSubjectAltNames.Null(),
            "empty" => TlsAuthSubjectAltNames.FromValues([]),
            _ => TlsAuthSubjectAltNames.FromValues(names)
        };
        names.Clear();
        return new(certificate, basis switch
        {
            "omitted" or "empty" => null,
            "null" => WorkloadAuthNullableText.Null(),
            _ => WorkloadAuthNullableText.FromValue("name-canary")
        }, sans, basis == "omitted" ? null : false, Policy(basis, update));
    }

    private static string ExpectedPolicy(string basis, bool update, bool positiveAttachMax = true) => basis switch
    {
        "omitted" or "minimal" or "material" => "",
        "empty" => $$"""
            ,"accessTokenTTL":0,"accessTokenMaxTTL":{{(positiveAttachMax && !update ? 1 : 0)}},"accessTokenNumUsesLimit":0,"accessTokenTrustedIps":[]
            """,
        _ => """
            ,"accessTokenTTL":17,"accessTokenMaxTTL":23,"accessTokenNumUsesLimit":5,"accessTokenTrustedIps":[{"ipAddress":"127.0.0.1/32"},{"ipAddress":"::1"}]
            """
    };

    private static string ExpectedLdap(string basis, bool update)
    {
        if (basis == "material") return """{"bindPass":"bind-canary"}""";
        if (basis == "omitted") return update ? "{}"
            : """{"url":"ldaps://directory.test","bindDN":"dn-canary","bindPass":"bind-canary","searchBase":"base-canary"}""";
        string connection = """
            "url":"ldaps://directory.test","bindDN":"dn-canary","bindPass":"bind-canary","searchBase":"base-canary"
            """;
        string fields = basis == "empty"
            ? """
                ,"allowedFields":[],"lockoutEnabled":false
                """
            : """
                ,"searchFilter":"(uid=filter-canary)","allowedFields":[{"key":"attribute-canary","value":"value-canary"},{"key":"","value":""}],
                "lockoutEnabled":false,"lockoutThreshold":1.5,"lockoutDurationSeconds":30.5,"lockoutCounterResetSeconds":5.5
                """;
        string attachment = update ? $",\"templateId\":\"{TemplateId}\""
            : basis == "empty" ? ",\"ldapCaCertificate\":\"\"" : ",\"ldapCaCertificate\":\"ldap-ca-canary\"";
        return "{" + connection + attachment + fields + ExpectedPolicy(basis, update) + "}";
    }

    private static string ExpectedOci(string basis, bool update)
    {
        string usernames = basis switch
        {
            "omitted" => "",
            "null" => ",\"allowedUsernames\":null",
            "empty" => ",\"allowedUsernames\":\"\"",
            _ => ",\"allowedUsernames\":\"username-canary\""
        };
        return "{\"tenancyOcid\":\"tenancy-canary\"" + usernames + ExpectedPolicy(basis, update) + "}";
    }

    private static string ExpectedSpiffe(string basis, bool update)
    {
        if (basis == "omitted") return "{}";
        string distribution = basis switch
        {
            "minimal" => """{"profile":"https_web_bundle","endpointUrl":"https://bundle.test/keys"}""",
            "empty" => """{"profile":"https_web_bundle","endpointUrl":"https://bundle.test/keys","caCert":"","refreshHintSeconds":0}""",
            _ => """{"profile":"https_web_bundle","endpointUrl":"https://bundle.test/keys","caCert":"bundle-ca-canary","refreshHintSeconds":37}"""
        };
        return """
            {"trustDomain":"domain-canary","allowedSpiffeIds":"spiffe://domain.test/id-canary","allowedAudiences":"audience-canary","trustBundleDistribution":
            """ + distribution + ExpectedPolicy(basis, update, false) + "}";
    }

    private static string ExpectedTls(string basis, bool update)
    {
        if (basis == "omitted") return update ? "{}" : """{"caCertificate":"certificate-canary"}""";
        string names = basis switch
        {
            "null" => ""","allowedCommonNames":null,"allowedSubjectAltNames":null""",
            "empty" => ""","allowedSubjectAltNames":[]""",
            _ => ""","allowedCommonNames":"name-canary","allowedSubjectAltNames":["dns-canary.test","uri-canary"]"""
        };
        return "{\"caCertificate\":\"certificate-canary\"" + names + ",\"verifyClientCertificateChain\":false"
            + ExpectedPolicy(basis, update) + "}";
    }

    private static async Task PrivateInput(object input)
    {
        await Assert.That(JsonSerializer.Serialize(input, input.GetType())).IsEqualTo("{}");
        await Assert.That(input.ToString()!.Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    private static async Task Dispatch<T>(ManagementRequest<T> request, string strategy, bool update,
        string expected, ManagementTarget approved, ManagementTarget denied) where T : WorkloadAuthConfiguration
    {
        string method = update ? "PATCH" : "POST";
        var tokens = new Tokens();
        var wire = new Wire(strategy, method, expected, request.Dispose);
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        await Assert.That(request.OperationId).IsEqualTo(
            $"infisical.{method.ToLowerInvariant()}.v1.auth.{strategy.Replace('-', '.')}.auth.identities.by.identityId");
        await Assert.That(request.IsMutation).IsTrue();
        var receipt = client.CreateReceipt(request);
        wire.Receipt = receipt;
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        var rejected = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, denied), receipt);
        await Assert.That(rejected.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();

        var grant = authority.IssueGrant(request.OperationId, approved);
        var result = await client.ExecuteAsync(request, authority, grant, receipt);
        try
        {
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(wire.Observed).IsTrue();
            await Assert.That(tokens.Acquired).IsTrue();
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            await Assert.That(result.Value.Id).IsEqualTo(ConfigurationId);
            await Assert.That(result.Value.IdentityId).IsEqualTo(IdentityId);
            await Assert.That(result.Value.HasUnestablishedTrustedIpProjection).IsTrue();
            await Assert.That(result.Value.AccessTokenTTL).IsEqualTo(0.5);
            await Assert.That(JsonSerializer.Serialize(result.Value, result.Value.GetType())).IsEqualTo("{}");
            if (result.Value is SpiffeAuthConfiguration spiffe)
            {
                using var copy = spiffe.TrustBundleDistribution.Bundle!.Copy();
                spiffe.Dispose();
                await Assert.That(copy.Reveal()).IsEqualTo("returned-bundle-canary");
                await Assert.That(() => spiffe.TrustBundleDistribution.Bundle.Reveal()).Throws<ObjectDisposedException>();
            }
            foreach (object value in new object[] { request, approved, grant, receipt, result.Value })
                await Assert.That(value.ToString()!.Contains("canary", StringComparison.Ordinal)).IsFalse();
            await Assert.That(JsonSerializer.Serialize(request).Contains("canary", StringComparison.Ordinal)).IsFalse();
            await Assert.That(JsonSerializer.Serialize(receipt).Contains("canary", StringComparison.Ordinal)).IsFalse();
            await Assert.That(() => request.CopyBody()).Throws<ObjectDisposedException>();
            var replay = await client.ExecuteAsync(request, authority, grant, receipt);
            await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        }
        finally
        {
            if (result.IsSuccess && result.Value is IDisposable disposable) disposable.Dispose();
        }
    }

    private static string Response(string strategy)
    {
        string envelope = strategy switch
        {
            "ldap" => "identityLdapAuth",
            "oci" => "identityOciAuth",
            "spiffe" => "identitySpiffeAuth",
            _ => "identityTlsCertAuth"
        };
        string fields = strategy switch
        {
            "ldap" => $$"""
                "url":"returned-url","searchBase":"returned-base","searchFilter":"returned-filter","templateId":"{{TemplateId}}",
                "allowedFields":42,"lockoutEnabled":true,"lockoutThreshold":2.5,"lockoutDurationSeconds":40.5,"lockoutCounterResetSeconds":6.5,"accessTokenPeriod":1.25
                """,
            "oci" => """ "tenancyOcid":"returned-tenancy","type":"returned-type","allowedUsernames":null,"accessTokenPeriod":1.25 """,
            "spiffe" => """
                "trustDomain":"returned-domain","allowedSpiffeIds":"returned-ids","allowedAudiences":"returned-audiences",
                "trustBundleDistribution":{"profile":"static","bundle":"returned-bundle-canary"}
                """,
            _ => """ "allowedCommonNames":null,"allowedSubjectAltNames":null,"encryptedCaCertificate":42,"verifyClientCertificateChain":true """
        };
        string common = $$"""
            {"{{envelope}}":{"id":"{{ConfigurationId}}","identityId":"{{IdentityId}}","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-11T00:00:00Z",
            "accessTokenTTL":0.5,"accessTokenMaxTTL":1.5,"accessTokenNumUsesLimit":0,"accessTokenTrustedIps":{"opaque":false},
            """;
        return common + fields + "}}";
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        internal bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("admin-canary"))));
        }
    }

    private sealed class Wire(string strategy, string method, string expected, Action disposeRequest) : HttpMessageHandler
    {
        internal bool Observed { get; private set; }
        internal ManagementReceipt? Receipt { get; set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            disposeRequest();
            await Assert.That(Observed).IsFalse();
            Observed = true;
            await Assert.That(Receipt!.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            await Assert.That(request.Method.Method).IsEqualTo(method);
            await Assert.That(request.RequestUri!.AbsolutePath).IsEqualTo($"/api/v1/auth/{strategy}-auth/identities/{IdentityId}");
            await Assert.That(request.Headers.Authorization!.Scheme).IsEqualTo("Bearer");
            await Assert.That(request.Headers.Authorization.Parameter).IsEqualTo("admin-canary");
            await Assert.That(request.Content!.Headers.ContentType!.MediaType).IsEqualTo("application/json");
            byte[] bytes = await request.Content.ReadAsByteArrayAsync(cancellationToken);
            try
            {
                using var actual = JsonDocument.Parse(bytes);
                using var literal = JsonDocument.Parse(expected);
                await Assert.That(JsonElement.DeepEquals(actual.RootElement, literal.RootElement)).IsTrue();
            }
            finally { Array.Clear(bytes); }
            return new(HttpStatusCode.OK) { Content = new StringContent(Response(strategy), Encoding.UTF8, "application/json") };
        }
    }
}
