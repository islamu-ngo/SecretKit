using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class WorkloadIdentityAuthenticationTests
{
    private const string IdentityId = "11111111-1111-4111-8111-111111111111";
    private const string ConfigurationId = "22222222-2222-4222-8222-222222222222";
    private const string ForeignIdentityId = "33333333-3333-4333-8333-333333333333";
    private const string TemplateId = "44444444-4444-4444-8444-444444444444";
    private const string GatewayId = "55555555-5555-4555-8555-555555555555";
    private const string GatewayPoolId = "66666666-6666-4666-8666-666666666666";

    [Test]
    [Arguments("jwt", "GET")]
    [Arguments("jwt", "POST")]
    [Arguments("jwt", "PATCH")]
    [Arguments("jwt", "DELETE")]
    [Arguments("oidc", "GET")]
    [Arguments("oidc", "POST")]
    [Arguments("oidc", "PATCH")]
    [Arguments("oidc", "DELETE")]
    [Arguments("kubernetes", "GET")]
    [Arguments("kubernetes", "POST")]
    [Arguments("kubernetes", "PATCH")]
    [Arguments("kubernetes", "DELETE")]
    public async Task ConfigurationBindingUsesControlledManagementSeam(string strategy, string method)
    {
        switch (strategy)
        {
            case "jwt":
                using (var request = Jwt(method)) await Binding(request, strategy, method);
                break;
            case "oidc":
                using (var request = Oidc(method)) await Binding(request, strategy, method);
                break;
            default:
                using (var request = Kubernetes(method)) await Binding(request, strategy, method);
                break;
        }
    }

    private static async Task Binding<T>(ManagementRequest<T> request, string strategy, string method) where T : notnull
    {
        var wire = new Wire(Response(strategy, method));
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, Approved(strategy, method)), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(wire.Observed).IsTrue();
        await Assert.That(wire.Method).IsEqualTo(method);
        await Assert.That(wire.Path).IsEqualTo($"/api/v1/auth/{strategy}-auth/identities/{IdentityId}");
        if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        if (result.Value is IDisposable disposable) disposable.Dispose();
        foreach (bool nested in new[] { false, true })
        {
            var response = JsonNode.Parse(Response(strategy, method))!.AsObject();
            var selected = nested ? response.First().Value!.AsObject() : response;
            selected["notDeclared"] = "private-extra";
            using var malformedTransport = new ManagementTransport(new("https://management.test"), 1024 * 1024,
                null, false, new Wire(response.ToJsonString()));
            var malformedClient = new ManagementClient(malformedTransport);
            var malformedAuthority = new ManagementAuthority(malformedClient.Authority, new Tokens(), "org");
            var malformedReceipt = request.IsMutation ? malformedClient.CreateReceipt(request) : null;
            var malformed = await malformedClient.ExecuteAsync(request, malformedAuthority,
                malformedAuthority.IssueGrant(request.OperationId, Approved(strategy, method)), malformedReceipt);
            await Assert.That(malformed.Status).IsEqualTo(SecretStatus.Unknown);
            if (malformedReceipt is not null)
                await Assert.That(malformedReceipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
        string[] fields = strategy switch
        {
            "oidc" => ["id", "templateId"],
            "kubernetes" => ["id", "templateId", "gatewayId", "gatewayPoolId"],
            _ => ["id"]
        };
        foreach (string field in fields)
        {
            var root = JsonNode.Parse(Response(strategy, method))!.AsObject();
            root.First().Value![field] = "not-a-uuid";
            using var uuidTransport = new ManagementTransport(new("https://management.test"), 1024 * 1024,
                null, false, new Wire(root.ToJsonString()));
            var uuidClient = new ManagementClient(uuidTransport);
            var uuidAuthority = new ManagementAuthority(uuidClient.Authority, new Tokens(), "org");
            var uuidReceipt = request.IsMutation ? uuidClient.CreateReceipt(request) : null;
            var uuidResult = await uuidClient.ExecuteAsync(request, uuidAuthority,
                uuidAuthority.IssueGrant(request.OperationId, Approved(strategy, method)), uuidReceipt);
            (uuidResult.IsSuccess ? uuidResult.Value as IDisposable : null)?.Dispose();
            await Assert.That(uuidResult.Status).IsEqualTo(SecretStatus.Unknown);
            if (uuidReceipt is not null)
                await Assert.That(uuidReceipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
    }

    private static string Response(string strategy, string method)
    {
        var root = JsonNode.Parse(Response(strategy))!.AsObject();
        if (method == "DELETE")
        {
            var configuration = root.First().Value!.AsObject();
            configuration.Remove("caCert");
            configuration.Remove("jwksCaCert");
            configuration.Remove("publicKeys");
            configuration.Remove("tokenReviewerJwt");
        }
        return root.ToJsonString();
    }

    [Test]
    [Arguments("jwt")]
    [Arguments("oidc")]
    [Arguments("kubernetes")]
    public async Task DeletionRejectsMembersDeclaredOnlyForNonDeletionResults(string strategy)
    {
        switch (strategy)
        {
            case "jwt": await Verify(Jwt("DELETE")); break;
            case "oidc": await Verify(Oidc("DELETE")); break;
            default: await Verify(Kubernetes("DELETE")); break;
        }
        async Task Verify<T>(ManagementRequest<T> request) where T : notnull
        {
            using (request)
            {
                using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024,
                    null, false, new Wire(Response(strategy)));
                var client = new ManagementClient(transport);
                var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
                var receipt = client.CreateReceipt(request);
                var result = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, Approved(strategy, "DELETE")), receipt);
                (result.IsSuccess ? result.Value as IDisposable : null)?.Dispose();
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            }
        }
    }

    [Test]
    public async Task EstablishedEmptyTrustedIpInputRemainsExplicit()
    {
        // The workload contract allows an empty array, unlike the older policy helper.
        var ips = new WorkloadAuthTokenPolicy(accessTokenTrustedIps: []).AccessTokenTrustedIps;
        await Assert.That(ips!.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("POST")]
    [Arguments("PATCH")]
    [Arguments("GET")]
    [Arguments("DELETE")]
    public async Task KnownParserAndFactoryProofsDoNotInferResponseFromRequest(string method)
    {
        using var jwt = Jwt(method);
        using var oidc = Oidc(method);
        using var kubernetes = Kubernetes(method);
        using var jwtDocument = JsonDocument.Parse(Response("jwt", method));
        using var oidcDocument = JsonDocument.Parse(Response("oidc", method));
        using var kubernetesDocument = JsonDocument.Parse(Response("kubernetes", method));
        var jwtResult = jwt.Parse(jwtDocument.RootElement);
        var oidcResult = oidc.Parse(oidcDocument.RootElement);
        using var kubernetesResult = kubernetes.Parse(kubernetesDocument.RootElement);
        foreach (WorkloadAuthConfiguration result in new WorkloadAuthConfiguration[] { jwtResult, oidcResult, kubernetesResult })
        {
            await Assert.That(result.Id).IsEqualTo(ConfigurationId);
            await Assert.That(result.IdentityId).IsEqualTo(IdentityId);
        }
        await Assert.That(jwtResult.ConfigurationType).IsEqualTo("static"); // Request uses jwks.
        await Assert.That(jwtResult.AccessTokenTTL).IsEqualTo(0.5d);
        await Assert.That(jwtResult.AccessTokenMaxTTL).IsEqualTo(1.5d);
        await Assert.That(jwtResult.AccessTokenNumUsesLimit).IsEqualTo(0d);
        await Assert.That(jwtResult.AccessTokenPeriod).IsEqualTo(1.25d);
        await Assert.That(jwtResult.BoundIssuer).IsEqualTo("");
        await Assert.That(jwtResult.BoundAudiences).IsEqualTo("");
        await Assert.That(jwtResult.BoundSubject).IsEqualTo("");
        await Assert.That(jwtResult.JwksUrl).IsEqualTo("");
        await Assert.That(jwtResult.HasUnestablishedTrustedIpProjection).IsTrue();
        await Assert.That(jwtResult.HasUnestablishedBoundClaimsProjection).IsTrue();
        await Assert.That(oidcResult.HasUnestablishedBoundClaimsProjection).IsTrue();
        await Assert.That(oidcResult.HasUnestablishedClaimMetadataMappingProjection).IsTrue();
        await Assert.That(oidcResult.BoundSubject.IsNull).IsTrue();
        await Assert.That(oidcResult.TemplateId.Value).IsEqualTo(TemplateId);
        await Assert.That(oidcResult.OidcDiscoveryUrl).IsEqualTo("");
        await Assert.That(kubernetesResult.AllowedAudience).IsEqualTo("");
        await Assert.That(kubernetesResult.AllowedNames).IsEqualTo("");
        await Assert.That(kubernetesResult.AllowedNamespaces).IsEqualTo("");
        await Assert.That(kubernetesResult.GatewayId.Value).IsEqualTo(GatewayId);
        await Assert.That(kubernetesResult.GatewayPoolId.Value).IsEqualTo(GatewayPoolId);
        await Assert.That(kubernetesResult.KubernetesHost.IsNull).IsTrue();
        await Assert.That(kubernetesResult.TemplateId.Value).IsEqualTo(TemplateId);
        await Assert.That(kubernetesResult.TokenReviewMode).IsEqualTo("gateway");
        await Assert.That(kubernetesResult.VerifyTlsCertificate).IsFalse();
        await Assert.That(kubernetesResult.IsTokenReviewerJwtTemplateSourced).IsFalse();
        await Assert.That(kubernetesResult.HasUnestablishedTrustedIpProjection).IsTrue();
        await Assert.That(jwtResult.JwksCaCert).IsEqualTo(method == "DELETE" ? null : "ca-canary");
        await Assert.That(jwtResult.PublicKeys is null).IsEqualTo(method == "DELETE");
        await Assert.That(oidcResult.CaCert).IsEqualTo(method == "DELETE" ? null : "ca-canary");
        await Assert.That(kubernetesResult.CaCert).IsEqualTo(method == "DELETE" ? null : "ca-canary");
        await Assert.That(kubernetesResult.TokenReviewerJwt.IsPresent).IsEqualTo(method != "DELETE");
        if (method != "DELETE")
        {
            await Assert.That(jwtResult.PublicKeys!.Single()).IsEqualTo("key-canary");
            using var copy = kubernetesResult.TokenReviewerJwt.Value.Copy();
            kubernetesResult.Dispose();
            await Assert.That(copy.Reveal()).IsEqualTo("reviewer-canary");
        }
        foreach (object result in new object[] { jwtResult, oidcResult, kubernetesResult })
        {
            await Assert.That(JsonSerializer.Serialize(result)).IsEqualTo("{}");
            await Assert.That(result.ToString()!.Contains("canary", StringComparison.Ordinal)).IsFalse();
        }
        await Assert.That(jwt.OperationId).IsEqualTo($"infisical.{method.ToLowerInvariant()}.v1.auth.jwt.auth.identities.by.identityId");
        await Assert.That(oidc.OperationId).IsEqualTo($"infisical.{method.ToLowerInvariant()}.v1.auth.oidc.auth.identities.by.identityId");
        await Assert.That(kubernetes.OperationId).IsEqualTo($"infisical.{method.ToLowerInvariant()}.v1.auth.kubernetes.auth.identities.by.identityId");
        await Assert.That(jwt.CopyBody() is null).IsEqualTo(method is "GET" or "DELETE");
        await Assert.That(oidc.CopyBody() is null).IsEqualTo(method is "GET" or "DELETE");
        await Assert.That(kubernetes.CopyBody() is null).IsEqualTo(method is "GET" or "DELETE");
    }

    [Test]
    [Arguments(JwtAuthConfigurationType.Jwks, false)]
    [Arguments(JwtAuthConfigurationType.Jwks, true)]
    [Arguments(JwtAuthConfigurationType.Static, false)]
    [Arguments(JwtAuthConfigurationType.Static, true)]
    public async Task JwtEveryFieldAndDiscriminatorAreCopiedAndBound(JwtAuthConfigurationType type, bool update)
    {
        var claims = new Dictionary<string, string> { ["z"] = "", ["a"] = "claim-canary" };
        var keys = new List<string> { type == JwtAuthConfigurationType.Jwks ? "" : "key-canary" };
        var ips = new List<IdentityTrustedIp> { new("127.0.0.1/32") };
        var input = new JwtAuthConfigurationInput(type, "https://issuer.test/keys", keys, claims,
            "ca-canary", "", "", "", new(0, 0, 0, ips));
        using var request = update ? WorkloadIdentityAuthenticationOperations.UpdateJwtAuth("org", IdentityId, input)
            : WorkloadIdentityAuthenticationOperations.AttachJwtAuth("org", IdentityId, input);
        claims.Clear();
        keys.Clear();
        ips.Clear();
        using var document = Body(request);
        var body = document.RootElement;
        await Assert.That(body.EnumerateObject().Count()).IsEqualTo(12);
        await Assert.That(body.GetProperty("configurationType").GetString()).IsEqualTo(type == JwtAuthConfigurationType.Jwks ? "jwks" : "static");
        await Assert.That(body.GetProperty("jwksUrl").GetString()).IsEqualTo("https://issuer.test/keys");
        await Assert.That(body.GetProperty("jwksCaCert").GetString()).IsEqualTo("ca-canary");
        await Assert.That(body.GetProperty("boundIssuer").GetString()).IsEqualTo("");
        await Assert.That(body.GetProperty("boundAudiences").GetString()).IsEqualTo("");
        await Assert.That(body.GetProperty("boundSubject").GetString()).IsEqualTo("");
        await Assert.That(body.GetProperty("boundClaims").GetProperty("a").GetString()).IsEqualTo("claim-canary");
        await Assert.That(body.GetProperty("boundClaims").GetProperty("z").GetString()).IsEqualTo("");
        await Assert.That(body.GetProperty("publicKeys")[0].GetString()).IsEqualTo(type == JwtAuthConfigurationType.Jwks ? "" : "key-canary");
        await Assert.That(body.GetProperty("accessTokenTTL").GetInt32()).IsEqualTo(0);
        await Assert.That(body.GetProperty("accessTokenMaxTTL").GetInt32()).IsEqualTo(0);
        await Assert.That(body.GetProperty("accessTokenNumUsesLimit").GetInt64()).IsEqualTo(0L);
        await Assert.That(body.GetProperty("accessTokenTrustedIps")[0].GetProperty("ipAddress").GetString()).IsEqualTo("127.0.0.1/32");
        await Assert.That(request.Target.SecondaryId).IsEqualTo(
            WorkloadIdentityAuthenticationOperations.JwtAuthConfigurationTarget("org", IdentityId, input, update).SecondaryId);
        await Assert.That(JsonSerializer.Serialize(input)).IsEqualTo("{}");
    }

    [Test]
    public async Task EmptyAndOmittedCollectionsRemainDistinctIncludingCanonicalMapIntent()
    {
        var omitted = new JwtAuthConfigurationInput(JwtAuthConfigurationType.Static, publicKeys: []);
        using var patch = WorkloadIdentityAuthenticationOperations.UpdateJwtAuth("org", IdentityId, omitted);
        using var empty = WorkloadIdentityAuthenticationOperations.UpdateJwtAuth("org", IdentityId,
            new(JwtAuthConfigurationType.Static, publicKeys: [], boundClaims: new Dictionary<string, string>(),
                policy: new(accessTokenTrustedIps: [])));
        using var omittedBody = Body(patch);
        using var emptyBody = Body(empty);
        await Assert.That(omittedBody.RootElement.GetProperty("publicKeys").GetArrayLength()).IsEqualTo(0);
        await Assert.That(omittedBody.RootElement.TryGetProperty("boundClaims", out _)).IsFalse();
        await Assert.That(emptyBody.RootElement.GetProperty("boundClaims").EnumerateObject().Count()).IsEqualTo(0);
        await Assert.That(emptyBody.RootElement.GetProperty("accessTokenTrustedIps").GetArrayLength()).IsEqualTo(0);
        await Assert.That(patch.Target.SecondaryId == empty.Target.SecondaryId).IsFalse();
        var a = new OidcAuthConfigurationInput(new Dictionary<string, string> { ["a"] = "", ["b"] = "b" });
        var b = new OidcAuthConfigurationInput(new Dictionary<string, string> { ["b"] = "b", ["a"] = "" });
        await Assert.That(WorkloadIdentityAuthenticationOperations.OidcAuthConfigurationTarget("org", IdentityId, a).SecondaryId)
            .IsEqualTo(WorkloadIdentityAuthenticationOperations.OidcAuthConfigurationTarget("org", IdentityId, b).SecondaryId);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OidcAllFieldsAndNullablePatchAreEstablished(bool update)
    {
        var claims = new Dictionary<string, string> { [""] = "" };
        var mapping = new Dictionary<string, string> { ["source"] = "target" };
        var input = new OidcAuthConfigurationInput(claims, "https://issuer.test/discovery", "issuer", "", "", "",
            mapping, update ? WorkloadAuthNullableText.Null() : WorkloadAuthNullableText.FromValue("00000000-0000-0000-0000-000000000001"),
            new(0, 315360000, long.MaxValue, []));
        claims.Clear();
        mapping.Clear();
        using var request = update ? WorkloadIdentityAuthenticationOperations.UpdateOidcAuth("org", IdentityId, input)
            : WorkloadIdentityAuthenticationOperations.AttachOidcAuth("org", IdentityId, input);
        using var document = Body(request);
        var body = document.RootElement;
        await Assert.That(body.EnumerateObject().Count()).IsEqualTo(12);
        await Assert.That(body.GetProperty("boundClaims").GetProperty("").GetString()).IsEqualTo("");
        await Assert.That(body.GetProperty("claimMetadataMapping").GetProperty("source").GetString()).IsEqualTo("target");
        await Assert.That(body.GetProperty("templateId").ValueKind).IsEqualTo(update ? JsonValueKind.Null : JsonValueKind.String);
        await Assert.That(body.GetProperty("oidcDiscoveryUrl").GetString()).IsEqualTo("https://issuer.test/discovery");
        await Assert.That(body.GetProperty("boundIssuer").GetString()).IsEqualTo("issuer");
        foreach (string field in new[] { "boundAudiences", "boundSubject", "caCert" })
            await Assert.That(body.GetProperty(field).GetString()).IsEqualTo("");
        await Assert.That(body.GetProperty("accessTokenTTL").GetInt32()).IsEqualTo(0);
        await Assert.That(body.GetProperty("accessTokenMaxTTL").GetInt32()).IsEqualTo(315360000);
        await Assert.That(body.GetProperty("accessTokenNumUsesLimit").GetInt64()).IsEqualTo(long.MaxValue);
        await Assert.That(body.GetProperty("accessTokenTrustedIps").GetArrayLength()).IsEqualTo(0);
        await Assert.That(JsonSerializer.Serialize(input)).IsEqualTo("{}");
    }

    [Test]
    [Arguments(KubernetesTokenReviewMode.Api, false)]
    [Arguments(KubernetesTokenReviewMode.Api, true)]
    [Arguments(KubernetesTokenReviewMode.Gateway, false)]
    [Arguments(KubernetesTokenReviewMode.Gateway, true)]
    public async Task KubernetesEveryAlternativeAndNullableFieldIsRetained(KubernetesTokenReviewMode mode, bool update)
    {
        using var material = SecretMaterial.FromText("reviewer-canary");
        var uuid = WorkloadAuthNullableText.FromValue("00000000-0000-0000-0000-000000000001");
        using var input = new KubernetesAuthConfigurationInput("", "", "", "",
            update ? WorkloadAuthNullableText.Null() : WorkloadAuthNullableText.FromValue("host"),
            WorkloadAuthNullableText.Null(), uuid, update ? WorkloadAuthNullableText.Null() : uuid,
            update ? null : material, update, mode, false, new(0, 0, 0, []));
        material.Dispose();
        using var request = update ? WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth("org", IdentityId, input)
            : WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth("org", IdentityId, input);
        input.Dispose();
        using var document = Body(request);
        var body = document.RootElement;
        await Assert.That(body.EnumerateObject().Count()).IsEqualTo(15);
        foreach (string field in new[] { "allowedNames", "allowedNamespaces", "allowedAudience", "caCert" })
            await Assert.That(body.GetProperty(field).GetString()).IsEqualTo("");
        await Assert.That(body.GetProperty("tokenReviewMode").GetString()).IsEqualTo(mode == KubernetesTokenReviewMode.Api ? "api" : "gateway");
        await Assert.That(body.GetProperty("gatewayId").ValueKind).IsEqualTo(JsonValueKind.Null);
        await Assert.That(body.GetProperty("gatewayPoolId").GetString()).IsEqualTo(uuid.Value);
        await Assert.That(body.GetProperty("templateId").ValueKind).IsEqualTo(update ? JsonValueKind.Null : JsonValueKind.String);
        await Assert.That(body.GetProperty("kubernetesHost").ValueKind).IsEqualTo(update ? JsonValueKind.Null : JsonValueKind.String);
        await Assert.That(body.GetProperty("tokenReviewerJwt").ValueKind).IsEqualTo(update ? JsonValueKind.Null : JsonValueKind.String);
        if (!update) await Assert.That(body.GetProperty("tokenReviewerJwt").GetString()).IsEqualTo("reviewer-canary");
        await Assert.That(body.GetProperty("verifyTlsCertificate").GetBoolean()).IsFalse();
        await Assert.That(body.GetProperty("accessTokenTrustedIps").GetArrayLength()).IsEqualTo(0);
        foreach (string field in new[] { "accessTokenTTL", "accessTokenMaxTTL", "accessTokenNumUsesLimit" })
            await Assert.That(body.GetProperty(field).GetInt32()).IsEqualTo(0);
        await Assert.That(JsonSerializer.Serialize(input)).IsEqualTo("{}");
    }

    [Test]
    public async Task KubernetesEmptyReviewerAndOmittedPatchDoNotInventDefaults()
    {
        using var material = SecretMaterial.FromText("");
        using var input = new KubernetesAuthConfigurationInput(tokenReviewerJwt: material);
        using var explicitEmpty = WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth("org", IdentityId, input);
        using var omittedInput = new KubernetesAuthConfigurationInput();
        using var omitted = WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth("org", IdentityId, omittedInput);
        using var body = Body(explicitEmpty);
        using var omittedBody = Body(omitted);
        await Assert.That(body.RootElement.GetProperty("tokenReviewerJwt").GetString()).IsEqualTo("");
        await Assert.That(omittedBody.RootElement.EnumerateObject().Count()).IsEqualTo(0);
        await Assert.That(explicitEmpty.Target.SecondaryId == omitted.Target.SecondaryId).IsFalse();
    }

    [Test]
    public async Task InvalidNativeBranchesAreRejectedBeforeDispatch()
    {
        await Assert.That(() => new JwtAuthConfigurationInput(JwtAuthConfigurationType.Jwks)).Throws<ArgumentException>();
        await Assert.That(() => new JwtAuthConfigurationInput(JwtAuthConfigurationType.Static)).Throws<ArgumentException>();
        await Assert.That(() => new JwtAuthConfigurationInput(JwtAuthConfigurationType.Static, publicKeys: [""])).Throws<ArgumentException>();
        await Assert.That(() => new JwtAuthConfigurationInput((JwtAuthConfigurationType)9)).Throws<ArgumentException>();
        await Assert.That(() => WorkloadIdentityAuthenticationOperations.AttachJwtAuth("org", IdentityId,
            new(JwtAuthConfigurationType.Static, publicKeys: []))).Throws<ArgumentException>();
        await Assert.That(() => WorkloadIdentityAuthenticationOperations.AttachOidcAuth("org", IdentityId, new())).Throws<ArgumentException>();
        await Assert.That(() => WorkloadIdentityAuthenticationOperations.AttachOidcAuth("org", IdentityId,
            new(boundClaims: new Dictionary<string, string>(), templateId: WorkloadAuthNullableText.Null()))).Throws<ArgumentException>();
        await Assert.That(() => new OidcAuthConfigurationInput(boundIssuer: "")).Throws<ArgumentException>();
        await Assert.That(() => new OidcAuthConfigurationInput(oidcDiscoveryUrl: "relative")).Throws<ArgumentException>();
        await Assert.That(() => new OidcAuthConfigurationInput(templateId: WorkloadAuthNullableText.FromValue("bad"))).Throws<ArgumentException>();
        await Assert.That(() => new WorkloadAuthTokenPolicy(accessTokenTTL: -1)).Throws<ArgumentException>();
        await Assert.That(() => new WorkloadAuthTokenPolicy(accessTokenMaxTTL: 315360001)).Throws<ArgumentException>();
        await Assert.That(() => new WorkloadAuthTokenPolicy(accessTokenNumUsesLimit: -1)).Throws<ArgumentException>();
        await Assert.That(() => new WorkloadAuthTokenPolicy(accessTokenTrustedIps: Enumerable.Repeat(new IdentityTrustedIp("::1"), 101))).Throws<ArgumentException>();
        await Assert.That(() => new JwtAuthConfigurationInput(JwtAuthConfigurationType.Static, publicKeys: [null!])).Throws<ArgumentException>();
        await Assert.That(() => new OidcAuthConfigurationInput(boundClaims: new Dictionary<string, string> { ["a"] = null! })).Throws<ArgumentException>();
        using var missing = new KubernetesAuthConfigurationInput();
        await Assert.That(() => WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth("org", IdentityId, missing)).Throws<ArgumentException>();
        using var clear = new KubernetesAuthConfigurationInput("", "", clearTokenReviewerJwt: true);
        await Assert.That(() => WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth("org", IdentityId, clear)).Throws<ArgumentException>();
        await Assert.That(() => new KubernetesAuthConfigurationInput(allowedAudience: new string('a', 1001))).Throws<ArgumentException>();
        await Assert.That(() => new KubernetesAuthConfigurationInput(kubernetesHost: WorkloadAuthNullableText.FromValue(""))).Throws<ArgumentException>();
        await Assert.That(() => new KubernetesAuthConfigurationInput(tokenReviewMode: (KubernetesTokenReviewMode)9)).Throws<ArgumentException>();
        using var token = SecretMaterial.FromText("secret");
        await Assert.That(() => new KubernetesAuthConfigurationInput(tokenReviewerJwt: token, clearTokenReviewerJwt: true)).Throws<ArgumentException>();
        using var disposed = new KubernetesAuthConfigurationInput("", "");
        disposed.Dispose();
        await Assert.That(() => WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth("org", IdentityId, disposed)).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments("jwt")]
    [Arguments("oidc")]
    [Arguments("kubernetes")]
    public async Task ChangedWholeIntentOrOrganizationIsDeniedBeforeAcquisition(string strategy)
    {
        var tokens = new Tokens();
        var wire = new Wire("{}");
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        using var jwt = WorkloadIdentityAuthenticationOperations.UpdateJwtAuth("org", IdentityId,
            new(JwtAuthConfigurationType.Static, publicKeys: []));
        using var oidc = WorkloadIdentityAuthenticationOperations.UpdateOidcAuth("org", IdentityId,
            new(templateId: WorkloadAuthNullableText.Null()));
        using var input = new KubernetesAuthConfigurationInput(verifyTlsCertificate: false);
        using var kubernetes = WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth("org", IdentityId, input);
        if (strategy == "jwt") await Denied(client, authority, jwt, Approved("jwt", "PATCH"));
        else if (strategy == "oidc") await Denied(client, authority, oidc, Approved("oidc", "PATCH"));
        else await Denied(client, authority, kubernetes, Approved("kubernetes", "PATCH"));
        await Assert.That(() => authority.IssueGrant(oidc.OperationId,
            new("foreign", resourceId: IdentityId, secondaryId: oidc.Target.SecondaryId))).Throws<ArgumentException>();
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();
    }

    [Test]
    [Arguments("jwt")]
    [Arguments("oidc")]
    [Arguments("kubernetes")]
    public async Task MalformedKnownFieldsFailAndUnknownNodesRemainUninterpreted(string strategy)
    {
        string response = Response(strategy);
        using var foreign = JsonDocument.Parse(response.Replace($"\"identityId\":\"{IdentityId}\"", $"\"identityId\":\"{ForeignIdentityId}\"", StringComparison.Ordinal));
        using var number = JsonDocument.Parse(response.Replace("\"accessTokenTTL\":0.5", "\"accessTokenTTL\":null", StringComparison.Ordinal));
        using var missing = JsonDocument.Parse(response.Replace("\"createdAt\":\"2026-10-10T00:00:00Z\",", "", StringComparison.Ordinal));
        using var request = strategy == "jwt" ? (IDisposable)Jwt("GET") : strategy == "oidc" ? Oidc("GET") : Kubernetes("GET");
        foreach (var document in new[] { foreign, number, missing })
        {
            if (request is ManagementRequest<JwtAuthConfiguration> jwt)
                await Assert.That(() => jwt.Parse(document.RootElement)).Throws<ManagementContractException>();
            else if (request is ManagementRequest<OidcAuthConfiguration> oidc)
                await Assert.That(() => oidc.Parse(document.RootElement)).Throws<ManagementContractException>();
            else
                await Assert.That(() => ((ManagementRequest<KubernetesAuthConfiguration>)request).Parse(document.RootElement)).Throws<ManagementContractException>();
        }
    }

    [Test]
    public async Task NullableResultFieldsRetainAbsenceNullAndEmpty()
    {
        using var oidc = Oidc("GET");
        foreach (string replacement in new[] { "\"boundSubject\":\"\",", "", "\"boundSubject\":null," })
        {
            using var document = JsonDocument.Parse(Response("oidc").Replace("\"boundSubject\":null,", replacement, StringComparison.Ordinal));
            var result = oidc.Parse(document.RootElement);
            await Assert.That(result.BoundSubject.IsPresent).IsEqualTo(replacement.Length != 0);
            if (replacement.Contains("\"\",", StringComparison.Ordinal))
                await Assert.That(result.BoundSubject.Value).IsEqualTo("");
        }
        using var kubernetes = Kubernetes("GET");
        using var nullable = JsonDocument.Parse(Response("kubernetes").Replace("\"tokenReviewerJwt\":\"reviewer-canary\"", "\"tokenReviewerJwt\":null", StringComparison.Ordinal));
        using var resultNull = kubernetes.Parse(nullable.RootElement);
        await Assert.That(resultNull.TokenReviewerJwt.IsNull).IsTrue();
        using var absent = JsonDocument.Parse(Response("kubernetes").Replace("\"tokenReviewerJwt\":\"reviewer-canary\",", "", StringComparison.Ordinal));
        using var resultAbsent = kubernetes.Parse(absent.RootElement);
        await Assert.That(resultAbsent.TokenReviewerJwt.IsPresent).IsFalse();
    }

    [Test]
    [Arguments("jwt", "GET")]
    [Arguments("jwt", "POST")]
    [Arguments("jwt", "PATCH")]
    [Arguments("jwt", "DELETE")]
    [Arguments("oidc", "GET")]
    [Arguments("oidc", "POST")]
    [Arguments("oidc", "PATCH")]
    [Arguments("oidc", "DELETE")]
    [Arguments("kubernetes", "GET")]
    [Arguments("kubernetes", "POST")]
    [Arguments("kubernetes", "PATCH")]
    [Arguments("kubernetes", "DELETE")]
    public async Task HandwrittenRefitRoutesConstructWithoutDispatch(string strategy, string method)
    {
        var wire = new Wire("{}");
        using var client = new HttpClient(wire) { BaseAddress = new("https://management.test") };
        var api = RestService.For<IWorkloadIdentityAuthenticationApi>(client,
            new RefitSettings { ExceptionFactory = _ => ValueTask.FromResult<Exception?>(null) });
        using var body = new StringContent("""{"canary":false}""", Encoding.UTF8, "application/json");
        string identity = IdentityId;
        using var request = await ((strategy, method) switch
        {
            ("jwt", "GET") => api.GetJwt(identity, default),
            ("jwt", "POST") => api.AttachJwt(identity, body, default),
            ("jwt", "PATCH") => api.UpdateJwt(identity, body, default),
            ("jwt", "DELETE") => api.DeleteJwt(identity, default),
            ("oidc", "GET") => api.GetOidc(identity, default),
            ("oidc", "POST") => api.AttachOidc(identity, body, default),
            ("oidc", "PATCH") => api.UpdateOidc(identity, body, default),
            ("oidc", "DELETE") => api.DeleteOidc(identity, default),
            ("kubernetes", "GET") => api.GetKubernetes(identity, default),
            ("kubernetes", "POST") => api.AttachKubernetes(identity, body, default),
            ("kubernetes", "PATCH") => api.UpdateKubernetes(identity, body, default),
            _ => api.DeleteKubernetes(identity, default)
        });
        await Assert.That(request.Method.Method).IsEqualTo(method);
        await Assert.That(new Uri(client.BaseAddress, request.RequestUri!).AbsolutePath).IsEqualTo($"/api/v1/auth/{strategy}-auth/identities/{IdentityId}");
        if (method is "POST" or "PATCH")
            await Assert.That(await request.Content!.ReadAsStringAsync()).IsEqualTo("""{"canary":false}""");
        else await Assert.That(request.Content is null).IsTrue();
        await Assert.That(wire.Observed).IsFalse();
    }

    private static JsonDocument Body<T>(ManagementRequest<T> request) where T : notnull
    {
        byte[] bytes = request.CopyBody()!;
        try
        {
            using var stream = new MemoryStream(bytes, writable: false);
            return JsonDocument.Parse(stream);
        }
        finally { Array.Clear(bytes); }
    }
    private static async Task Denied<T>(ManagementClient client, ManagementAuthority authority,
        ManagementRequest<T> request, ManagementTarget target) where T : notnull
    {
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    private static JwtAuthConfigurationInput JwtInput() => new(JwtAuthConfigurationType.Jwks,
        jwksUrl: "https://issuer.test/keys", boundClaims: new Dictionary<string, string>());
    private static OidcAuthConfigurationInput OidcInput() => new(boundClaims: new Dictionary<string, string>());
    private static ManagementTarget Approved(string strategy, string method)
    {
        if (method is "GET" or "DELETE") return new("org", resourceId: IdentityId);
        return strategy switch
        {
            "jwt" => WorkloadIdentityAuthenticationOperations.JwtAuthConfigurationTarget("org", IdentityId, JwtInput(), method == "PATCH"),
            "oidc" => WorkloadIdentityAuthenticationOperations.OidcAuthConfigurationTarget("org", IdentityId, OidcInput(), method == "PATCH"),
            _ => KubernetesTarget(method)
        };
    }
    private static ManagementTarget KubernetesTarget(string method)
    {
        using var input = new KubernetesAuthConfigurationInput("", "");
        return WorkloadIdentityAuthenticationOperations.KubernetesAuthConfigurationTarget("org", IdentityId, input, method == "PATCH");
    }
    private static ManagementRequest<JwtAuthConfiguration> Jwt(string method) => method switch
    {
        "POST" => WorkloadIdentityAuthenticationOperations.AttachJwtAuth("org", IdentityId, JwtInput()),
        "PATCH" => WorkloadIdentityAuthenticationOperations.UpdateJwtAuth("org", IdentityId, JwtInput()),
        "GET" => WorkloadIdentityAuthenticationOperations.GetJwtAuth("org", IdentityId),
        _ => WorkloadIdentityAuthenticationOperations.DeleteJwtAuth("org", IdentityId)
    };
    private static ManagementRequest<OidcAuthConfiguration> Oidc(string method) => method switch
    {
        "POST" => WorkloadIdentityAuthenticationOperations.AttachOidcAuth("org", IdentityId, OidcInput()),
        "PATCH" => WorkloadIdentityAuthenticationOperations.UpdateOidcAuth("org", IdentityId, OidcInput()),
        "GET" => WorkloadIdentityAuthenticationOperations.GetOidcAuth("org", IdentityId),
        _ => WorkloadIdentityAuthenticationOperations.DeleteOidcAuth("org", IdentityId)
    };
    private static ManagementRequest<KubernetesAuthConfiguration> Kubernetes(string method)
    {
        using var input = new KubernetesAuthConfigurationInput("", "");
        return method switch
        {
            "POST" => WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth("org", IdentityId, input),
            "PATCH" => WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth("org", IdentityId, input),
            "GET" => WorkloadIdentityAuthenticationOperations.GetKubernetesAuth("org", IdentityId),
            _ => WorkloadIdentityAuthenticationOperations.DeleteKubernetesAuth("org", IdentityId)
        };
    }

    private const string Common = $$"""
        "id":"{{ConfigurationId}}","identityId":"{{IdentityId}}","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z",
        "accessTokenTTL":0.5,"accessTokenMaxTTL":1.5,"accessTokenNumUsesLimit":0,"accessTokenTrustedIps":{"unspecified":"canary"}
        """;
    private static string Response(string strategy) => "{\"" + (strategy switch
    {
        "jwt" => "identityJwtAuth",
        "oidc" => "identityOidcAuth",
        _ => "identityKubernetesAuth"
    }) + "\":{" + Common + "," + (strategy switch
    {
        "jwt" => """
            "configurationType":"static","jwksUrl":"","jwksCaCert":"ca-canary","publicKeys":["key-canary"],
            "boundIssuer":"","boundAudiences":"","boundSubject":"","boundClaims":42,"accessTokenPeriod":1.25
            """,
        "oidc" => $$"""
            "oidcDiscoveryUrl":"","caCert":"ca-canary","boundIssuer":"","boundAudiences":"","boundSubject":null,
            "boundClaims":[],"claimMetadataMapping":null,"templateId":"{{TemplateId}}"
            """,
        _ => $$"""
            "allowedAudience":"","allowedNames":"","allowedNamespaces":"","caCert":"ca-canary",
            "gatewayId":"{{GatewayId}}","gatewayPoolId":"{{GatewayPoolId}}","templateId":"{{TemplateId}}","kubernetesHost":null,"tokenReviewerJwt":"reviewer-canary",
            "verifyTlsCertificate":false,"tokenReviewMode":"gateway","isTokenReviewerJwtTemplateSourced":false
            """
    }) + "}}";

    private sealed class Tokens : IInfisicalTokenSource
    {
        internal bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            Acquire();
        private ValueTask<SecretOutcome<InfisicalAccessToken>> Acquire()
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("admin-canary"))));
        }
    }

    private sealed class Wire(string response) : HttpMessageHandler
    {
        internal bool Observed { get; private set; }
        internal string? Method { get; private set; }
        internal string? Path { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Observed = true;
            Method = request.Method.Method;
            Path = request.RequestUri!.AbsolutePath;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(response, Encoding.UTF8, "application/json")
            });
        }
    }
}
