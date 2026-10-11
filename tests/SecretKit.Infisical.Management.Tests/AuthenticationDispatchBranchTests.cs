using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class AuthenticationDispatchBranchTests
{
    private const string IdentityId = "11111111-1111-4111-8111-111111111111";
    private const string ConfigurationId = "22222222-2222-4222-8222-222222222222";
    private const string TemplateId = "44444444-4444-4444-8444-444444444444";
    private const string GatewayId = "55555555-5555-4555-8555-555555555555";
    private const string GatewayPoolId = "66666666-6666-4666-8666-666666666666";

    // W01: exactly POST/PATCH for these seven strategies. Bounded basis, not a
    // scalar Cartesian product: full fields; alternate native discriminator;
    // required-only/omitted; admitted empty/zero/false; PATCH-only explicit null.
    // The literal expected bodies are independent of Write, CopyBody and intent
    // hashing. Each approval is built from a fresh input, never request.Target.
    // All 14 rows are RemoteConfigurationOrAccessChange. Applied is a local
    // receipt, not proof of persistence, issuer acceptance or destructive effect.
    [Test]
    [Arguments("alicloud", false, "full")]
    [Arguments("alicloud", true, "full")]
    [Arguments("aws", false, "full")]
    [Arguments("aws", true, "full")]
    [Arguments("azure", false, "full")]
    [Arguments("azure", true, "full")]
    [Arguments("gcp", false, "full")]
    [Arguments("gcp", true, "full")]
    [Arguments("jwt", false, "full")]
    [Arguments("jwt", true, "full")]
    [Arguments("kubernetes", false, "full")]
    [Arguments("kubernetes", true, "full")]
    [Arguments("oidc", false, "full")]
    [Arguments("oidc", true, "full")]
    [Arguments("gcp", false, "alternative")]
    [Arguments("gcp", true, "alternative")]
    [Arguments("jwt", false, "alternative")]
    [Arguments("jwt", true, "alternative")]
    [Arguments("kubernetes", false, "alternative")]
    [Arguments("kubernetes", true, "alternative")]
    [Arguments("alicloud", false, "omitted")]
    [Arguments("alicloud", true, "omitted")]
    [Arguments("aws", false, "omitted")]
    [Arguments("aws", true, "omitted")]
    [Arguments("azure", false, "omitted")]
    [Arguments("azure", true, "omitted")]
    [Arguments("gcp", false, "omitted")]
    [Arguments("gcp", true, "omitted")]
    [Arguments("jwt", false, "omitted")]
    [Arguments("jwt", true, "omitted")]
    [Arguments("kubernetes", false, "omitted")]
    [Arguments("kubernetes", true, "omitted")]
    [Arguments("oidc", false, "omitted")]
    [Arguments("oidc", true, "omitted")]
    [Arguments("alicloud", false, "empty")]
    [Arguments("alicloud", true, "empty")]
    [Arguments("aws", false, "empty")]
    [Arguments("aws", true, "empty")]
    [Arguments("azure", false, "empty")]
    [Arguments("azure", true, "empty")]
    [Arguments("gcp", false, "empty")]
    [Arguments("gcp", true, "empty")]
    [Arguments("jwt", false, "empty")]
    [Arguments("jwt", true, "empty")]
    [Arguments("kubernetes", false, "empty")]
    [Arguments("kubernetes", true, "empty")]
    [Arguments("oidc", false, "empty")]
    [Arguments("oidc", true, "empty")]
    [Arguments("kubernetes", true, "null")]
    [Arguments("oidc", true, "null")]
    public async Task ExactRowDispatchRetainsIndependentBodyAndAuthority(string strategy, bool update, string basis)
    {
        string deniedBasis = basis == "full"
            ? strategy is "gcp" or "jwt" or "kubernetes" ? "alternative" : "omitted"
            : "full";
        switch (strategy)
        {
            case "alicloud":
                var ali = Ali(basis, update);
                using (var request = update
                    ? CloudIdentityAuthenticationOperations.UpdateAliCloudAuth("org", IdentityId, ali)
                    : CloudIdentityAuthenticationOperations.AttachAliCloudAuth("org", IdentityId, ali))
                    await Dispatch(request, strategy, update, basis,
                        CloudIdentityAuthenticationOperations.AliCloudAuthConfigurationTarget("org", IdentityId, Ali(basis, update), update),
                        CloudIdentityAuthenticationOperations.AliCloudAuthConfigurationTarget("org", IdentityId, Ali(deniedBasis, update), update));
                break;
            case "aws":
                var aws = Aws(basis, update);
                using (var request = update
                    ? CloudIdentityAuthenticationOperations.UpdateAwsAuth("org", IdentityId, aws)
                    : CloudIdentityAuthenticationOperations.AttachAwsAuth("org", IdentityId, aws))
                    await Dispatch(request, strategy, update, basis,
                        CloudIdentityAuthenticationOperations.AwsAuthConfigurationTarget("org", IdentityId, Aws(basis, update), update),
                        CloudIdentityAuthenticationOperations.AwsAuthConfigurationTarget("org", IdentityId, Aws(deniedBasis, update), update));
                break;
            case "azure":
                var azure = Azure(basis, update);
                using (var request = update
                    ? CloudIdentityAuthenticationOperations.UpdateAzureAuth("org", IdentityId, azure)
                    : CloudIdentityAuthenticationOperations.AttachAzureAuth("org", IdentityId, azure))
                    await Dispatch(request, strategy, update, basis,
                        CloudIdentityAuthenticationOperations.AzureAuthConfigurationTarget("org", IdentityId, Azure(basis, update), update),
                        CloudIdentityAuthenticationOperations.AzureAuthConfigurationTarget("org", IdentityId, Azure(deniedBasis, update), update));
                break;
            case "gcp":
                var gcp = Gcp(basis, update);
                using (var request = update
                    ? CloudIdentityAuthenticationOperations.UpdateGcpAuth("org", IdentityId, gcp)
                    : CloudIdentityAuthenticationOperations.AttachGcpAuth("org", IdentityId, gcp))
                    await Dispatch(request, strategy, update, basis,
                        CloudIdentityAuthenticationOperations.GcpAuthConfigurationTarget("org", IdentityId, Gcp(basis, update), update),
                        CloudIdentityAuthenticationOperations.GcpAuthConfigurationTarget("org", IdentityId, Gcp(deniedBasis, update), update));
                break;
            case "jwt":
                var jwt = Jwt(basis, update);
                using (var request = update
                    ? WorkloadIdentityAuthenticationOperations.UpdateJwtAuth("org", IdentityId, jwt)
                    : WorkloadIdentityAuthenticationOperations.AttachJwtAuth("org", IdentityId, jwt))
                    await Dispatch(request, strategy, update, basis,
                        WorkloadIdentityAuthenticationOperations.JwtAuthConfigurationTarget("org", IdentityId, Jwt(basis, update), update),
                        WorkloadIdentityAuthenticationOperations.JwtAuthConfigurationTarget("org", IdentityId, Jwt(deniedBasis, update), update));
                break;
            case "oidc":
                var oidc = Oidc(basis, update);
                using (var request = update
                    ? WorkloadIdentityAuthenticationOperations.UpdateOidcAuth("org", IdentityId, oidc)
                    : WorkloadIdentityAuthenticationOperations.AttachOidcAuth("org", IdentityId, oidc))
                    await Dispatch(request, strategy, update, basis,
                        WorkloadIdentityAuthenticationOperations.OidcAuthConfigurationTarget("org", IdentityId, Oidc(basis, update), update),
                        WorkloadIdentityAuthenticationOperations.OidcAuthConfigurationTarget("org", IdentityId, Oidc(deniedBasis, update), update));
                break;
            default:
                using (var input = Kubernetes(basis, update))
                using (var approved = Kubernetes(basis, update))
                using (var denied = Kubernetes(deniedBasis, update))
                using (var request = update
                    ? WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth("org", IdentityId, input)
                    : WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth("org", IdentityId, input))
                {
                    var target = WorkloadIdentityAuthenticationOperations.KubernetesAuthConfigurationTarget("org", IdentityId, approved, update);
                    var wrong = WorkloadIdentityAuthenticationOperations.KubernetesAuthConfigurationTarget("org", IdentityId, denied, update);
                    input.Dispose();
                    approved.Dispose();
                    denied.Dispose();
                    await Assert.That(() => WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth("org", IdentityId, input))
                        .Throws<ObjectDisposedException>();
                    await Dispatch(request, strategy, update, basis, target, wrong);
                }
                break;
        }
    }

    private static async Task Dispatch<T>(ManagementRequest<T> request, string strategy, bool update,
        string basis, ManagementTarget approved, ManagementTarget denied) where T : WorkloadAuthConfiguration
    {
        string method = update ? "PATCH" : "POST";
        var tokens = new Tokens();
        var wire = new Wire(Response(strategy), Expected(strategy, update, basis), method,
            request.Dispose);
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        await Assert.That(request.OperationId).IsEqualTo($"infisical.{method.ToLowerInvariant()}.v1.auth.{strategy}.auth.identities.by.identityId");
        await Assert.That(request.IsMutation).IsTrue();
        var receipt = client.CreateReceipt(request);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        var rejected = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, denied), receipt);
        await Assert.That(rejected.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();

        var grant = authority.IssueGrant(request.OperationId, approved);
        var result = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(wire.Observed).IsTrue();
        await Assert.That(tokens.Acquired).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(result.Value.Id).IsEqualTo(ConfigurationId);
        await Assert.That(result.Value.IdentityId).IsEqualTo(IdentityId);
        await Assert.That(result.Value.HasUnestablishedTrustedIpProjection).IsTrue();
        // Native success is deliberately different from every input branch.
        if (result.Value is JwtAuthConfiguration jwt)
        {
            await Assert.That(jwt.ConfigurationType).IsEqualTo("static");
            await Assert.That(jwt.HasUnestablishedBoundClaimsProjection).IsTrue();
        }
        if (result.Value is OidcAuthConfiguration oidc)
            await Assert.That(oidc.HasUnestablishedClaimMetadataMappingProjection).IsTrue();
        if (result.Value is KubernetesAuthConfiguration kubernetes)
        {
            using var copy = kubernetes.TokenReviewerJwt.Value.Copy();
            kubernetes.Dispose();
            await Assert.That(copy.Reveal()).IsEqualTo("returned-reviewer-canary");
            await Assert.That(() => kubernetes.TokenReviewerJwt.Value.Reveal()).Throws<ObjectDisposedException>();
        }
        await Assert.That(JsonSerializer.Serialize(result.Value, result.Value.GetType())).IsEqualTo("{}");
        foreach (object value in new object[] { request, approved, grant, receipt, result.Value })
            await Assert.That(value.ToString()!.Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(request).Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(receipt).Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(() => request.CopyBody()).Throws<ObjectDisposedException>();
        var replay = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
    }

    private static WorkloadAuthTokenPolicy Policy(string basis, bool update, bool positiveMax = false)
    {
        if (basis is "omitted" or "null") return new();
        if (basis == "empty") return new(0, positiveMax && !update ? 1 : 0, 0, []);
        var ips = new List<IdentityTrustedIp> { new("127.0.0.1/32"), new("::1") };
        var policy = new WorkloadAuthTokenPolicy(17, 23, 5, ips);
        ips.Clear();
        return policy;
    }

    private static AliCloudAuthConfigurationInput Ali(string basis, bool update) =>
        new("arn-canary", Policy(basis, update, true));
    private static AwsAuthConfigurationInput Aws(string basis, bool update) => basis switch
    {
        "omitted" => new(),
        "empty" => new("", "", policy: Policy(basis, update, true)),
        _ => new("principal-canary", "account-canary", "https://sts.test", Policy(basis, update))
    };
    private static AzureAuthConfigurationInput Azure(string basis, bool update) => basis switch
    {
        "omitted" => update ? new() : new("", ""),
        "empty" => new("", "", "", Policy(basis, update)),
        _ => new("tenant-canary", "resource-canary", "principal-canary", Policy(basis, update))
    };
    private static GcpAuthConfigurationInput Gcp(string basis, bool update) => basis switch
    {
        "omitted" => new(update ? null : GcpAuthConfigurationType.Iam),
        "empty" => new(GcpAuthConfigurationType.Gce, "", "", "", Policy(basis, update)),
        _ => new(basis == "alternative" ? GcpAuthConfigurationType.Gce : GcpAuthConfigurationType.Iam,
            "account-canary", "project-canary", "zone-canary", Policy(basis, update))
    };
    private static JwtAuthConfigurationInput Jwt(string basis, bool update)
    {
        if (basis == "omitted") return new(JwtAuthConfigurationType.Jwks, "https://issuer.test/keys",
            boundClaims: update ? null : new Dictionary<string, string>());
        if (basis == "empty") return new(JwtAuthConfigurationType.Static, "", [], new Dictionary<string, string>(),
            "", "", "", "", Policy(basis, update));
        var keys = new List<string> { basis == "alternative" ? "" : "key-canary" };
        var claims = new Dictionary<string, string> { ["z"] = "", ["a"] = "claim-canary" };
        var input = new JwtAuthConfigurationInput(
            basis == "alternative" ? JwtAuthConfigurationType.Jwks : JwtAuthConfigurationType.Static,
            "https://issuer.test/keys", keys, claims, "ca-canary", "issuer-canary", "audience-canary", "subject-canary",
            Policy(basis, update));
        keys.Clear();
        claims.Clear();
        return input;
    }
    private static OidcAuthConfigurationInput Oidc(string basis, bool update)
    {
        if (basis == "omitted") return new(boundClaims: update ? null : new Dictionary<string, string>());
        if (basis == "null") return new(templateId: WorkloadAuthNullableText.Null());
        if (basis == "empty") return new(new Dictionary<string, string>(), boundAudiences: "", boundSubject: "",
            caCert: "", claimMetadataMapping: new Dictionary<string, string>(), policy: Policy(basis, update));
        var claims = new Dictionary<string, string> { ["z"] = "", ["a"] = "claim-canary" };
        var mapping = new Dictionary<string, string> { ["source"] = "target-canary", ["empty"] = "" };
        var input = new OidcAuthConfigurationInput(claims, "https://issuer.test/discovery", "issuer-canary",
            "audience-canary", "subject-canary", "ca-canary", mapping, WorkloadAuthNullableText.FromValue(TemplateId),
            Policy(basis, update));
        claims.Clear();
        mapping.Clear();
        return input;
    }
    private static KubernetesAuthConfigurationInput Kubernetes(string basis, bool update)
    {
        if (basis == "omitted") return update ? new() : new("", "");
        if (basis == "null") return new(kubernetesHost: WorkloadAuthNullableText.Null(),
            gatewayId: WorkloadAuthNullableText.Null(), gatewayPoolId: WorkloadAuthNullableText.Null(),
            templateId: WorkloadAuthNullableText.Null(), clearTokenReviewerJwt: true);
        using var reviewer = SecretMaterial.FromText(basis == "empty" ? "" : "reviewer-canary");
        if (basis == "empty") return new("", "", "", "", WorkloadAuthNullableText.Null(),
            WorkloadAuthNullableText.Null(), WorkloadAuthNullableText.Null(), tokenReviewerJwt: reviewer,
            tokenReviewMode: KubernetesTokenReviewMode.Api, verifyTlsCertificate: false, policy: Policy(basis, update));
        return new("name-canary", "namespace-canary", "audience-canary", "ca-canary",
            WorkloadAuthNullableText.FromValue("https://cluster.test"), WorkloadAuthNullableText.FromValue(GatewayId),
            WorkloadAuthNullableText.FromValue(GatewayPoolId), WorkloadAuthNullableText.FromValue(TemplateId),
            reviewer, tokenReviewMode: basis == "alternative" ? KubernetesTokenReviewMode.Gateway : KubernetesTokenReviewMode.Api,
            verifyTlsCertificate: basis != "alternative", policy: Policy(basis, update));
    }

    private static string Expected(string strategy, bool update, string basis)
    {
        if (basis == "null") return strategy == "oidc" ? """{"templateId":null}"""
            : """{"kubernetesHost":null,"gatewayId":null,"gatewayPoolId":null,"templateId":null,"tokenReviewerJwt":null}""";
        if (basis == "omitted") return strategy switch
        {
            "alicloud" => """{"allowedArns":"arn-canary"}""",
            "azure" => update ? "{}" : """{"tenantId":"","resource":""}""",
            "gcp" => update ? "{}" : """{"type":"iam"}""",
            "jwt" => update ? """{"configurationType":"jwks","jwksUrl":"https://issuer.test/keys"}"""
                : """{"configurationType":"jwks","jwksUrl":"https://issuer.test/keys","boundClaims":{}}""",
            "oidc" => update ? "{}" : """{"boundClaims":{}}""",
            "kubernetes" => update ? "{}" : """{"allowedNames":"","allowedNamespaces":""}""",
            _ => "{}"
        };
        string fields = basis == "empty" ? strategy switch
        {
            "alicloud" => "\"allowedArns\":\"arn-canary\"",
            "aws" => "\"allowedPrincipalArns\":\"\",\"allowedAccountIds\":\"\"",
            "azure" => "\"tenantId\":\"\",\"resource\":\"\",\"allowedServicePrincipalIds\":\"\"",
            "gcp" => "\"type\":\"gce\",\"allowedServiceAccounts\":\"\",\"allowedProjects\":\"\",\"allowedZones\":\"\"",
            "jwt" => """
                "configurationType":"static","jwksUrl":"","publicKeys":[],"boundClaims":{},
                "jwksCaCert":"","boundIssuer":"","boundAudiences":"","boundSubject":""
                """,
            "oidc" => """
                "boundClaims":{},"claimMetadataMapping":{},"boundAudiences":"","boundSubject":"","caCert":""
                """,
            _ => """
                "allowedNames":"","allowedNamespaces":"","allowedAudience":"","caCert":"",
                "kubernetesHost":null,"gatewayId":null,"gatewayPoolId":null,"tokenReviewerJwt":"",
                "tokenReviewMode":"api","verifyTlsCertificate":false
                """
        } : strategy switch
        {
            "alicloud" => "\"allowedArns\":\"arn-canary\"",
            "aws" => """
                "allowedPrincipalArns":"principal-canary","allowedAccountIds":"account-canary","stsEndpoint":"https://sts.test"
                """,
            "azure" => """
                "tenantId":"tenant-canary","resource":"resource-canary","allowedServicePrincipalIds":"principal-canary"
                """,
            "gcp" => $$"""
                "type":"{{(basis == "alternative" ? "gce" : "iam")}}",
                "allowedServiceAccounts":"account-canary","allowedProjects":"project-canary","allowedZones":"zone-canary"
                """,
            "jwt" => $$"""
                "configurationType":"{{(basis == "alternative" ? "jwks" : "static")}}","jwksUrl":"https://issuer.test/keys",
                "publicKeys":["{{(basis == "alternative" ? "" : "key-canary")}}"],"boundClaims":{"a":"claim-canary","z":""},
                "jwksCaCert":"ca-canary","boundIssuer":"issuer-canary","boundAudiences":"audience-canary","boundSubject":"subject-canary"
                """,
            "oidc" => $$"""
                "boundClaims":{"a":"claim-canary","z":""},"claimMetadataMapping":{"source":"target-canary","empty":""},
                "oidcDiscoveryUrl":"https://issuer.test/discovery","boundIssuer":"issuer-canary",
                "boundAudiences":"audience-canary","boundSubject":"subject-canary","caCert":"ca-canary","templateId":"{{TemplateId}}"
                """,
            _ => $$"""
                "allowedNames":"name-canary","allowedNamespaces":"namespace-canary","allowedAudience":"audience-canary","caCert":"ca-canary",
                "kubernetesHost":"https://cluster.test","gatewayId":"{{GatewayId}}","gatewayPoolId":"{{GatewayPoolId}}","templateId":"{{TemplateId}}",
                "tokenReviewerJwt":"reviewer-canary","tokenReviewMode":"{{(basis == "alternative" ? "gateway" : "api")}}",
                "verifyTlsCertificate":{{(basis == "alternative" ? "false" : "true")}}
                """
        };
        string policy = basis == "empty" ? $$"""
            "accessTokenTTL":0,"accessTokenMaxTTL":{{(!update && strategy is "aws" or "alicloud" ? 1 : 0)}},
            "accessTokenNumUsesLimit":0,"accessTokenTrustedIps":[]
            """ : """
            "accessTokenTTL":17,"accessTokenMaxTTL":23,"accessTokenNumUsesLimit":5,
            "accessTokenTrustedIps":[{"ipAddress":"127.0.0.1/32"},{"ipAddress":"::1"}]
            """;
        return "{" + fields + "," + policy + "}";
    }

    private static string Response(string strategy)
    {
        string envelope = strategy switch
        {
            "alicloud" => "identityAliCloudAuth",
            "aws" => "identityAwsAuth",
            "azure" => "identityAzureAuth",
            "gcp" => "identityGcpAuth",
            "jwt" => "identityJwtAuth",
            "oidc" => "identityOidcAuth",
            _ => "identityKubernetesAuth"
        };
        string common = $$"""
            "id":"{{ConfigurationId}}","identityId":"{{IdentityId}}","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-11T00:00:00Z",
            "accessTokenTTL":0.5,"accessTokenMaxTTL":1.5,"accessTokenNumUsesLimit":0,"accessTokenTrustedIps":{"opaque":false}
            """;
        string fields = strategy switch
        {
            "alicloud" => "\"type\":\"returned-ali\",\"allowedArns\":\"returned-arns\"",
            "aws" => "\"type\":\"returned-aws\",\"allowedPrincipalArns\":\"returned-principals\",\"allowedAccountIds\":\"\",\"stsEndpoint\":\"\"",
            "azure" => "\"tenantId\":\"\",\"resource\":\"returned-resource\",\"allowedServicePrincipalIds\":\"\"",
            "gcp" => "\"type\":\"returned-gcp\",\"allowedProjects\":null,\"allowedServiceAccounts\":\"\",\"allowedZones\":null",
            "jwt" => """
                "configurationType":"static","jwksUrl":"","jwksCaCert":"returned-ca","publicKeys":["returned-key"],
                "boundIssuer":"","boundAudiences":"","boundSubject":"","boundClaims":42
                """,
            "oidc" => $$"""
                "oidcDiscoveryUrl":"","caCert":"returned-ca","boundIssuer":"","boundAudiences":"","boundSubject":null,
                "boundClaims":[],"claimMetadataMapping":null,"templateId":"{{TemplateId}}"
                """,
            _ => $$"""
                "allowedAudience":"","allowedNames":"","allowedNamespaces":"","caCert":"returned-ca",
                "gatewayId":"{{GatewayId}}","gatewayPoolId":"{{GatewayPoolId}}","templateId":null,"kubernetesHost":null,
                "tokenReviewerJwt":"returned-reviewer-canary","verifyTlsCertificate":false,"tokenReviewMode":"gateway",
                "isTokenReviewerJwtTemplateSourced":false
                """
        };
        return "{\"" + envelope + "\":{" + common + "," + fields + "}}";
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

    private sealed class Wire(string response, string expected, string method, Action disposeRequest) : HttpMessageHandler
    {
        internal bool Observed { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Dispose the owning request before consuming the actual transport
            // content: its independent in-flight copy must remain usable.
            disposeRequest();
            await Assert.That(Observed).IsFalse();
            Observed = true;
            await Assert.That(request.Method.Method).IsEqualTo(method);
            await Assert.That(request.RequestUri!.AbsolutePath).IsEqualTo(
                $"/api/v1/auth/{Strategy(response)}-auth/identities/{IdentityId}");
            await Assert.That(request.Headers.Authorization!.Scheme).IsEqualTo("Bearer");
            await Assert.That(request.Headers.Authorization.Parameter).IsEqualTo("admin-canary");
            await Assert.That(request.Content!.Headers.ContentType!.MediaType).IsEqualTo("application/json");
            using var actual = JsonDocument.Parse(await request.Content.ReadAsByteArrayAsync(cancellationToken));
            using var literal = JsonDocument.Parse(expected);
            await Assert.That(JsonElement.DeepEquals(actual.RootElement, literal.RootElement)).IsTrue();
            return new(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }

        private static string Strategy(string response)
        {
            using var document = JsonDocument.Parse(response);
            return document.RootElement.EnumerateObject().Single().Name switch
            {
                "identityAliCloudAuth" => "alicloud",
                "identityAwsAuth" => "aws",
                "identityAzureAuth" => "azure",
                "identityGcpAuth" => "gcp",
                "identityJwtAuth" => "jwt",
                "identityOidcAuth" => "oidc",
                _ => "kubernetes"
            };
        }
    }
}
