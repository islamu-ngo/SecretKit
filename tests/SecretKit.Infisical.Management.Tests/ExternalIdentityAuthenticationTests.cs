using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ExternalIdentityAuthenticationTests
{
    private const string IdentityId = "11111111-1111-4111-8111-111111111111";
    private const string ConfigurationId = "22222222-2222-4222-8222-222222222222";
    private const string ForeignIdentityId = "33333333-3333-4333-8333-333333333333";
    private const string TemplateId = "44444444-4444-4444-8444-444444444444";

    [Test]
    [Arguments("ldap", "GET")]
    [Arguments("ldap", "POST")]
    [Arguments("ldap", "PATCH")]
    [Arguments("ldap", "DELETE")]
    [Arguments("ldap", "clear-lockouts")]
    [Arguments("oci", "GET")]
    [Arguments("oci", "POST")]
    [Arguments("oci", "PATCH")]
    [Arguments("oci", "DELETE")]
    [Arguments("spiffe", "GET")]
    [Arguments("spiffe", "POST")]
    [Arguments("spiffe", "PATCH")]
    [Arguments("spiffe", "DELETE")]
    [Arguments("spiffe", "refresh-bundle")]
    [Arguments("tls-cert", "GET")]
    [Arguments("tls-cert", "POST")]
    [Arguments("tls-cert", "PATCH")]
    [Arguments("tls-cert", "DELETE")]
    public async Task ConfigurationBindingUsesRealManagementSeam(string strategy, string method)
    {
        switch (strategy)
        {
            case "ldap" when method == "clear-lockouts":
                using (var request = ExternalIdentityAuthenticationOperations.ClearLdapAuthLockouts("org", IdentityId))
                    await Binding(request, strategy, method);
                break;
            case "ldap": using (var request = Ldap(method)) await Binding(request, strategy, method); break;
            case "oci": using (var request = Oci(method)) await Binding(request, strategy, method); break;
            case "spiffe": using (var request = Spiffe(method)) await Binding(request, strategy, method); break;
            default: using (var request = Tls(method)) await Binding(request, strategy, method); break;
        }
    }

    private static async Task Binding<T>(ManagementRequest<T> request, string strategy, string method) where T : notnull
    {
        var wire = new Wire(Response(strategy, method));
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            Approved(strategy, method)), receipt);
        if (result.Status == SecretStatus.Success && result.Value is IDisposable disposable) disposable.Dispose();
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(wire.Observed).IsTrue();
        await Assert.That(wire.Method).IsEqualTo(method is "clear-lockouts" or "refresh-bundle" ? "POST" : method);
        await Assert.That(wire.Path).IsEqualTo($"/api/v1/auth/{strategy}-auth/identities/{IdentityId}" +
            (method is "clear-lockouts" or "refresh-bundle" ? "/" + method : ""));
        await Assert.That(wire.Authorization).IsEqualTo("Bearer admin-canary");
        byte[]? expectedBody = request.CopyBody();
        try
        {
            await Assert.That(wire.BodyHash).IsEqualTo(expectedBody is null ? null :
                Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(expectedBody)));
        }
        finally { if (expectedBody is not null) Array.Clear(expectedBody); }
        if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        foreach (bool nested in method == "clear-lockouts" ? new[] { false } : new[] { false, true })
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
                malformedAuthority.IssueGrant(request.OperationId, Approved(strategy, method)),
                malformedReceipt);
            (malformed.IsSuccess ? malformed.Value as IDisposable : null)?.Dispose();
            await Assert.That(malformed.Status).IsEqualTo(SecretStatus.Unknown);
            if (malformedReceipt is not null)
                await Assert.That(malformedReceipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
        if (method != "clear-lockouts")
            foreach (string field in strategy == "ldap" ? new[] { "id", "templateId" } : new[] { "id" })
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
        if (method == "clear-lockouts") return """{"deleted":0.5}""";
        var root = JsonNode.Parse(Response(strategy))!.AsObject();
        if (method != "GET")
        {
            var configuration = root.First().Value!.AsObject();
            if (strategy == "ldap") { configuration.Remove("bindDN"); configuration.Remove("ldapCaCertificate"); }
            if (strategy == "tls-cert") configuration.Remove("caCertificate");
        }
        return root.ToJsonString();
    }

    [Test]
    [Arguments("GET")]
    [Arguments("POST")]
    [Arguments("PATCH")]
    [Arguments("DELETE")]
    [Arguments("refresh-bundle")]
    public async Task KnownSpiffeBundleBranchesRejectCrossBranchAndUndeclaredMembers(string method)
    {
        foreach (bool web in new[] { false, true })
            foreach (bool extra in new[] { false, true })
            {
                var root = JsonNode.Parse(Response("spiffe", method))!.AsObject();
                var bundle = web ? new JsonObject
                {
                    ["profile"] = "https_web_bundle",
                    ["endpointUrl"] = "",
                    ["caCert"] = "private-ca",
                    ["refreshHintSeconds"] = 0,
                    ["cachedBundleLastRefreshedAt"] = null
                } : new JsonObject { ["profile"] = "static", ["bundle"] = "private-bundle" };
                root["identitySpiffeAuth"]!["trustBundleDistribution"] = bundle;
                if (extra) bundle[web ? "bundle" : "endpointUrl"] = "private-cross-branch";
                using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024,
                    null, false, new Wire(root.ToJsonString()));
                var client = new ManagementClient(transport);
                var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
                using var request = Spiffe(method);
                var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                var result = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, Approved("spiffe", method)), receipt);
                if (result.IsSuccess) result.Value.Dispose();
                await Assert.That(result.Status).IsEqualTo(extra ? SecretStatus.Unknown : SecretStatus.Success);
                if (receipt is not null)
                    await Assert.That(receipt.Evidence).IsEqualTo(extra ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied);
            }
    }

    [Test]
    [Arguments("ldap", "POST")]
    [Arguments("ldap", "PATCH")]
    [Arguments("ldap", "DELETE")]
    [Arguments("tls-cert", "POST")]
    [Arguments("tls-cert", "PATCH")]
    [Arguments("tls-cert", "DELETE")]
    public async Task MutationsRejectMaterialMembersDeclaredOnlyForInspection(string strategy, string method)
    {
        if (strategy == "ldap") await Verify(Ldap(method));
        else await Verify(Tls(method));
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
                    authority.IssueGrant(request.OperationId, Approved(strategy, method)), receipt);
                (result.IsSuccess ? result.Value as IDisposable : null)?.Dispose();
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            }
        }
    }

    [Test]
    [Arguments("GET")]
    [Arguments("POST")]
    [Arguments("PATCH")]
    [Arguments("DELETE")]
    public async Task KnownResultsAreProtectedBoundedAndNeverInferred(string method)
    {
        using var ldap = Ldap(method);
        using var oci = Oci(method);
        using var spiffe = Spiffe(method);
        using var tls = Tls(method);
        using var ld = JsonDocument.Parse(Response("ldap", method));
        using var od = JsonDocument.Parse(Response("oci", method));
        using var sd = JsonDocument.Parse(Response("spiffe", method));
        using var td = JsonDocument.Parse(Response("tls-cert", method));
        using var lr = ldap.Parse(ld.RootElement);
        var or = oci.Parse(od.RootElement);
        using var sr = spiffe.Parse(sd.RootElement);
        using var tr = tls.Parse(td.RootElement);
        foreach (WorkloadAuthConfiguration result in new WorkloadAuthConfiguration[] { lr, or, sr, tr })
        {
            await Assert.That(result.Id).IsEqualTo(ConfigurationId);
            await Assert.That(result.IdentityId).IsEqualTo(IdentityId);
            await Assert.That(result.AccessTokenTTL).IsEqualTo(0.5d);
            await Assert.That(result.AccessTokenMaxTTL).IsEqualTo(1.5d);
            await Assert.That(result.AccessTokenNumUsesLimit).IsEqualTo(0d);
            await Assert.That(result.HasUnestablishedTrustedIpProjection).IsTrue();
            await Assert.That(JsonSerializer.Serialize(result, result.GetType())).IsEqualTo("{}");
            await Assert.That(result.ToString()!.Contains("canary", StringComparison.Ordinal)).IsFalse();
        }
        await Assert.That(lr.HasUnestablishedAllowedFieldsProjection).IsTrue();
        await Assert.That(lr.Url).IsEqualTo("");
        await Assert.That(lr.SearchBase).IsEqualTo("");
        await Assert.That(lr.SearchFilter).IsEqualTo("");
        await Assert.That(lr.TemplateId.Value).IsEqualTo(TemplateId);
        await Assert.That(lr.AccessTokenPeriod).IsEqualTo(1.25d);
        await Assert.That(lr.LockoutEnabled).IsFalse();
        await Assert.That(lr.LockoutThreshold).IsEqualTo(1.5d);
        await Assert.That(lr.LockoutDurationSeconds).IsEqualTo(30.5d);
        await Assert.That(lr.LockoutCounterResetSeconds).IsEqualTo(5.5d);
        await Assert.That(lr.BindDN).IsEqualTo(method == "GET" ? "" : null);
        await Assert.That(lr.LdapCaCertificate is not null).IsEqualTo(method == "GET");
        await Assert.That(or.TenancyOcid).IsEqualTo("");
        await Assert.That(or.Type).IsEqualTo("native-canary");
        await Assert.That(or.AllowedUsernames.IsNull).IsTrue();
        await Assert.That(or.AccessTokenPeriod).IsEqualTo(1.25d);
        await Assert.That(sr.TrustDomain).IsEqualTo("");
        await Assert.That(sr.AllowedSpiffeIds).IsEqualTo("");
        await Assert.That(sr.AllowedAudiences).IsEqualTo("");
        await Assert.That(sr.TrustBundleDistribution.Profile).IsEqualTo("https_web_bundle");
        await Assert.That(sr.TrustBundleDistribution.EndpointUrl).IsEqualTo("");
        await Assert.That(sr.TrustBundleDistribution.RefreshHintSeconds).IsEqualTo(0.5d);
        await Assert.That(sr.TrustBundleDistribution.CachedBundleLastRefreshedAt.IsNull).IsTrue();
        using var ca = sr.TrustBundleDistribution.CaCert!.Copy();
        sr.Dispose();
        await Assert.That(ca.Reveal()).IsEqualTo("ca-canary");
        await Assert.That(tr.AllowedCommonNames.IsNull).IsTrue();
        await Assert.That(tr.AllowedSubjectAltNames.IsNull).IsTrue();
        await Assert.That(tr.VerifyClientCertificateChain).IsFalse();
        await Assert.That(tr.HasUnestablishedEncryptedCaCertificateProjection).IsTrue();
        await Assert.That(tr.CaCertificate is not null).IsEqualTo(method == "GET");
        if (method == "GET")
        {
            using var ldapCopy = lr.LdapCaCertificate!.Copy();
            using var tlsCopy = tr.CaCertificate!.Copy();
            lr.Dispose();
            tr.Dispose();
            await Assert.That(ldapCopy.Reveal()).IsEqualTo("ca-canary");
            await Assert.That(tlsCopy.Reveal()).IsEqualTo("ca-canary");
            await Assert.That(() => lr.LdapCaCertificate.Reveal()).Throws<ObjectDisposedException>();
            await Assert.That(() => tr.CaCertificate.Reveal()).Throws<ObjectDisposedException>();
        }
        foreach (var id in new[] { ldap.OperationId, oci.OperationId, spiffe.OperationId, tls.OperationId })
            await Assert.That(id.StartsWith("infisical." + method.ToLowerInvariant(), StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task LdapBothAttachAlternativesCopyAllMaterialAndFields(bool template)
    {
        var fields = new List<LdapAuthAllowedField> { new("", "field-canary") };
        using var password = SecretMaterial.FromText("password-canary");
        using var ca = SecretMaterial.FromText("ca-canary");
        var settings = new LdapAuthSettings("filter", fields, false, 1.5, 30.5, 5.5, new(0, 1, 0, []));
        using var input = template ? LdapAuthConfigurationInput.FromTemplate("", ca, settings) :
            LdapAuthConfigurationInput.FromConnection("", "", password, "", ca, settings);
        using var request = ExternalIdentityAuthenticationOperations.AttachLdapAuth("org", IdentityId, input);
        var independentlyApproved = ExternalIdentityAuthenticationOperations.LdapAuthConfigurationTarget("org", IdentityId, input);
        fields.Clear();
        password.Dispose();
        ca.Dispose();
        input.Dispose();
        using var body = Body(request);
        var root = body.RootElement;
        await Assert.That(root.GetProperty("ldapCaCertificate").GetString()).IsEqualTo("ca-canary");
        await Assert.That(root.GetProperty("allowedFields")[0].GetProperty("value").GetString()).IsEqualTo("field-canary");
        await Assert.That(root.GetProperty("lockoutEnabled").GetBoolean()).IsFalse();
        await Assert.That(root.GetProperty("lockoutThreshold").GetDouble()).IsEqualTo(1.5);
        await Assert.That(root.GetProperty("lockoutDurationSeconds").GetDouble()).IsEqualTo(30.5);
        await Assert.That(root.GetProperty("lockoutCounterResetSeconds").GetDouble()).IsEqualTo(5.5);
        await Assert.That(root.GetProperty("searchFilter").GetString()).IsEqualTo("filter");
        await Assert.That(root.GetProperty("accessTokenTTL").GetInt32()).IsEqualTo(0);
        await Assert.That(root.GetProperty("accessTokenMaxTTL").GetInt32()).IsEqualTo(1);
        await Assert.That(root.GetProperty("accessTokenNumUsesLimit").GetInt32()).IsEqualTo(0);
        await Assert.That(root.GetProperty("accessTokenTrustedIps").GetArrayLength()).IsEqualTo(0);
        await Assert.That(root.TryGetProperty("configurationType", out _)).IsFalse();
        await Assert.That(root.TryGetProperty("templateId", out _)).IsEqualTo(template);
        if (!template)
        {
            await Assert.That(root.GetProperty("url").GetString()).IsEqualTo("");
            await Assert.That(root.GetProperty("bindDN").GetString()).IsEqualTo("");
            await Assert.That(root.GetProperty("searchBase").GetString()).IsEqualTo("");
            await Assert.That(root.GetProperty("bindPass").GetString()).IsEqualTo("password-canary");
        }
        await Assert.That(request.Target.SecondaryId).IsEqualTo(independentlyApproved.SecondaryId);
        await Assert.That(JsonSerializer.Serialize(input)).IsEqualTo("{}");
        await Assert.That(() => ExternalIdentityAuthenticationOperations.AttachLdapAuth("org", IdentityId, input))
            .Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task LdapPatchHasEveryAdmittedFieldAndNoInventedCertificateUpdate()
    {
        using var password = SecretMaterial.FromText("password-canary");
        using var input = LdapAuthConfigurationInput.Patch("", "url", "bind", password, "base",
            new("filter", [], false, 1, 30, 5, new(0, 0, 0, [])));
        using var request = ExternalIdentityAuthenticationOperations.UpdateLdapAuth("org", IdentityId, input);
        using var document = Body(request);
        var body = document.RootElement;
        await Assert.That(body.EnumerateObject().Count()).IsEqualTo(15);
        await Assert.That(body.GetProperty("templateId").GetString()).IsEqualTo("");
        await Assert.That(body.GetProperty("url").GetString()).IsEqualTo("url");
        await Assert.That(body.GetProperty("bindDN").GetString()).IsEqualTo("bind");
        await Assert.That(body.GetProperty("bindPass").GetString()).IsEqualTo("password-canary");
        await Assert.That(body.GetProperty("searchBase").GetString()).IsEqualTo("base");
        await Assert.That(body.GetProperty("allowedFields").GetArrayLength()).IsEqualTo(0);
        await Assert.That(body.TryGetProperty("ldapCaCertificate", out _)).IsFalse();
        await Assert.That(body.GetProperty("accessTokenMaxTTL").GetInt32()).IsEqualTo(0);
        await Assert.That(() => ExternalIdentityAuthenticationOperations.AttachLdapAuth("org", IdentityId, input))
            .Throws<ArgumentException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SpiffeDistributionDiscriminatorsOwnIndependentCopies(bool https)
    {
        using var material = SecretMaterial.FromText("bundle-canary");
        using var distribution = https ? SpiffeTrustBundleInput.HttpsWebBundle("https://bundle.test", material, 0) :
            SpiffeTrustBundleInput.Static(material);
        using var input = new SpiffeAuthConfigurationInput("domain", "ids", "aud", distribution, new(0, 0, 0, []));
        material.Dispose();
        distribution.Dispose();
        using var request = ExternalIdentityAuthenticationOperations.AttachSpiffeAuth("org", IdentityId, input);
        input.Dispose();
        using var document = Body(request);
        var body = document.RootElement;
        await Assert.That(body.GetProperty("trustDomain").GetString()).IsEqualTo("domain");
        await Assert.That(body.GetProperty("allowedSpiffeIds").GetString()).IsEqualTo("ids");
        await Assert.That(body.GetProperty("allowedAudiences").GetString()).IsEqualTo("aud");
        var bundle = body.GetProperty("trustBundleDistribution");
        await Assert.That(bundle.GetProperty("profile").GetString()).IsEqualTo(https ? "https_web_bundle" : "static");
        await Assert.That(bundle.GetProperty(https ? "caCert" : "bundle").GetString()).IsEqualTo("bundle-canary");
        if (https)
        {
            await Assert.That(bundle.GetProperty("endpointUrl").GetString()).IsEqualTo("https://bundle.test");
            await Assert.That(bundle.GetProperty("refreshHintSeconds").GetInt32()).IsEqualTo(0);
        }
        await Assert.That(body.GetProperty("accessTokenMaxTTL").GetInt32()).IsEqualTo(0);
    }

    [Test]
    public async Task NullableEmptyFalseAndOmittedUpdatesStayDistinct()
    {
        using var omittedTls = ExternalIdentityAuthenticationOperations.UpdateTlsCertAuth("org", IdentityId, new());
        using var nullTls = ExternalIdentityAuthenticationOperations.UpdateTlsCertAuth("org", IdentityId,
            new(allowedCommonNames: WorkloadAuthNullableText.Null(), allowedSubjectAltNames: TlsAuthSubjectAltNames.Null(),
                verifyClientCertificateChain: false, policy: new(0, 0, 0, [])));
        using var emptyTls = ExternalIdentityAuthenticationOperations.UpdateTlsCertAuth("org", IdentityId,
            new(allowedSubjectAltNames: TlsAuthSubjectAltNames.FromValues([])));
        using var omitted = Body(omittedTls);
        using var clear = Body(nullTls);
        using var empty = Body(emptyTls);
        await Assert.That(omitted.RootElement.EnumerateObject().Count()).IsEqualTo(0);
        await Assert.That(clear.RootElement.GetProperty("allowedCommonNames").ValueKind).IsEqualTo(JsonValueKind.Null);
        await Assert.That(clear.RootElement.GetProperty("allowedSubjectAltNames").ValueKind).IsEqualTo(JsonValueKind.Null);
        await Assert.That(clear.RootElement.GetProperty("verifyClientCertificateChain").GetBoolean()).IsFalse();
        await Assert.That(empty.RootElement.GetProperty("allowedSubjectAltNames").GetArrayLength()).IsEqualTo(0);
        using var omitOci = ExternalIdentityAuthenticationOperations.UpdateOciAuth("org", IdentityId, new("tenancy"));
        using var nullOci = ExternalIdentityAuthenticationOperations.UpdateOciAuth("org", IdentityId,
            new("tenancy", WorkloadAuthNullableText.Null()));
        using var emptyOci = ExternalIdentityAuthenticationOperations.UpdateOciAuth("org", IdentityId,
            new("tenancy", WorkloadAuthNullableText.FromValue("")));
        using var oo = Body(omitOci);
        using var no = Body(nullOci);
        using var eo = Body(emptyOci);
        await Assert.That(oo.RootElement.TryGetProperty("allowedUsernames", out _)).IsFalse();
        await Assert.That(no.RootElement.GetProperty("allowedUsernames").ValueKind).IsEqualTo(JsonValueKind.Null);
        await Assert.That(eo.RootElement.GetProperty("allowedUsernames").GetString()).IsEqualTo("");
        await Assert.That(oo.RootElement.GetProperty("tenancyOcid").GetString()).IsEqualTo("tenancy");
        using var omittedSpiffe = ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth("org", IdentityId, new());
        using var omittedLdap = ExternalIdentityAuthenticationOperations.UpdateLdapAuth("org", IdentityId,
            LdapAuthConfigurationInput.Patch());
        using var os = Body(omittedSpiffe);
        using var ol = Body(omittedLdap);
        await Assert.That(os.RootElement.EnumerateObject().Count()).IsEqualTo(0);
        await Assert.That(ol.RootElement.EnumerateObject().Count()).IsEqualTo(0);
    }

    [Test]
    public async Task TlsCertificateAndSansAreCopiedBeforeCallerDisposal()
    {
        using var certificate = SecretMaterial.FromText("certificate-canary");
        var names = new List<string> { "name-canary" };
        using var input = new TlsCertAuthConfigurationInput(certificate, WorkloadAuthNullableText.FromValue("name"),
            TlsAuthSubjectAltNames.FromValues(names), false, new(0, 1, 0, []));
        names.Clear();
        certificate.Dispose();
        using var request = ExternalIdentityAuthenticationOperations.AttachTlsCertAuth("org", IdentityId, input);
        input.Dispose();
        using var document = Body(request);
        await Assert.That(document.RootElement.GetProperty("caCertificate").GetString()).IsEqualTo("certificate-canary");
        await Assert.That(document.RootElement.GetProperty("allowedCommonNames").GetString()).IsEqualTo("name");
        await Assert.That(document.RootElement.GetProperty("allowedSubjectAltNames")[0].GetString()).IsEqualTo("name-canary");
        await Assert.That(document.RootElement.GetProperty("verifyClientCertificateChain").GetBoolean()).IsFalse();
        await Assert.That(JsonSerializer.Serialize(input)).IsEqualTo("{}");
        await Assert.That(() => ExternalIdentityAuthenticationOperations.UpdateTlsCertAuth("org", IdentityId, input))
            .Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task AuxiliaryResultsHaveNativeNumbersAndBundleUnion()
    {
        using var clear = ExternalIdentityAuthenticationOperations.ClearLdapAuthLockouts("org", IdentityId);
        using var deleted = JsonDocument.Parse("""{"deleted":1.5}""");
        await Assert.That(clear.Parse(deleted.RootElement).Deleted).IsEqualTo(1.5);
        using var refresh = ExternalIdentityAuthenticationOperations.RefreshSpiffeBundle("org", IdentityId);
        using var document = JsonDocument.Parse(Response("spiffe").Replace(
            """{"profile":"https_web_bundle","endpointUrl":"","caCert":"ca-canary","refreshHintSeconds":0.5,"cachedBundleLastRefreshedAt":null}""",
            """{"profile":"static","bundle":"bundle-canary"}""", StringComparison.Ordinal));
        using var result = refresh.Parse(document.RootElement);
        using var copy = result.TrustBundleDistribution.Bundle!.Copy();
        result.Dispose();
        await Assert.That(copy.Reveal()).IsEqualTo("bundle-canary");
        await Assert.That(() => result.TrustBundleDistribution.Bundle.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(clear.CopyBody() is null).IsTrue();
        await Assert.That(refresh.CopyBody() is null).IsTrue();
    }

    [Test]
    [Arguments("ldap")]
    [Arguments("oci")]
    [Arguments("spiffe")]
    [Arguments("tls-cert")]
    public async Task ForeignEchoesNeverYieldData(string strategy)
    {
        using var document = JsonDocument.Parse(Response(strategy).Replace($"\"identityId\":\"{IdentityId}\"",
            $"\"identityId\":\"{ForeignIdentityId}\"", StringComparison.Ordinal));
        switch (strategy)
        {
            case "ldap": using (var r = Ldap("GET")) await Assert.That(() => r.Parse(document.RootElement)).Throws<ManagementContractException>(); break;
            case "oci": using (var r = Oci("GET")) await Assert.That(() => r.Parse(document.RootElement)).Throws<ManagementContractException>(); break;
            case "spiffe": using (var r = Spiffe("GET")) await Assert.That(() => r.Parse(document.RootElement)).Throws<ManagementContractException>(); break;
            default: using (var r = Tls("GET")) await Assert.That(() => r.Parse(document.RootElement)).Throws<ManagementContractException>(); break;
        }
    }

    [Test]
    [Arguments("\"verifyClientCertificateChain\":false", "\"verifyClientCertificateChain\":null")]
    [Arguments("\"allowedSubjectAltNames\":null", "\"allowedSubjectAltNames\":[null]")]
    [Arguments("\"encryptedCaCertificate\":42,", "")]
    [Arguments("\"createdAt\":\"2026-10-10T00:00:00Z\"", "\"createdAt\":\"invalid\"")]
    public async Task MalformedCertificateResultsFailBeforeSensitiveAllocation(string oldValue, string newValue)
    {
        using var request = Tls("GET");
        using var document = JsonDocument.Parse(Response("tls-cert").Replace(oldValue, newValue, StringComparison.Ordinal));
        await Assert.That(() => request.Parse(document.RootElement)).Throws<ManagementContractException>();
    }

    [Test]
    [Arguments("\"profile\":\"https_web_bundle\"", "\"profile\":\"unknown\"")]
    [Arguments("\"refreshHintSeconds\":0.5", "\"refreshHintSeconds\":null")]
    [Arguments("\"cachedBundleLastRefreshedAt\":null", "\"cachedBundleLastRefreshedAt\":\"invalid\"")]
    [Arguments("\"caCert\":\"ca-canary\"", "\"caCert\":null")]
    public async Task MalformedBundleResultsNeverRetainSensitiveMaterial(string oldValue, string newValue)
    {
        using var request = Spiffe("GET");
        using var document = JsonDocument.Parse(Response("spiffe").Replace(oldValue, newValue, StringComparison.Ordinal));
        await Assert.That(() => request.Parse(document.RootElement)).Throws<ManagementContractException>();
    }

    [Test]
    public async Task WholeIndependentChangeRejectsDifferentInputBeforeTokenAcquisition()
    {
        using var request = ExternalIdentityAuthenticationOperations.UpdateOciAuth("org", IdentityId, new("changed"));
        var wire = new Wire(Response("oci"));
        var tokens = new Tokens();
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        var approved = ExternalIdentityAuthenticationOperations.OciAuthConfigurationTarget("org", IdentityId,
            new("approved"), true);
        var receipt = client.CreateReceipt(request);
        var outcome = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, approved), receipt);
        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    public async Task EveryStrategyBindsSensitiveAndOptionalChangesIndependently()
    {
        var wire = new Wire("{}");
        var tokens = new Tokens();
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        using var password = SecretMaterial.FromText("password");
        using var changedPassword = SecretMaterial.FromText("changed-password");
        using var ldapApproved = LdapAuthConfigurationInput.Patch(bindPass: password);
        using var ldapChanged = LdapAuthConfigurationInput.Patch(bindPass: changedPassword);
        using var ldap = ExternalIdentityAuthenticationOperations.UpdateLdapAuth("org", IdentityId, ldapChanged);
        await Denied(client, authority, ldap,
            ExternalIdentityAuthenticationOperations.LdapAuthConfigurationTarget("org", IdentityId, ldapApproved, true));
        using var approvedBundle = SpiffeTrustBundleInput.Static(password);
        using var changedBundle = SpiffeTrustBundleInput.Static(changedPassword);
        using var spiffeApproved = new SpiffeAuthConfigurationInput(trustBundleDistribution: approvedBundle);
        using var spiffeChanged = new SpiffeAuthConfigurationInput(trustBundleDistribution: changedBundle);
        using var spiffe = ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth("org", IdentityId, spiffeChanged);
        await Denied(client, authority, spiffe,
            ExternalIdentityAuthenticationOperations.SpiffeAuthConfigurationTarget("org", IdentityId, spiffeApproved, true));
        using var tlsApproved = new TlsCertAuthConfigurationInput(password, verifyClientCertificateChain: true);
        using var tlsChanged = new TlsCertAuthConfigurationInput(password, verifyClientCertificateChain: false);
        using var tls = ExternalIdentityAuthenticationOperations.UpdateTlsCertAuth("org", IdentityId, tlsChanged);
        await Denied(client, authority, tls,
            ExternalIdentityAuthenticationOperations.TlsCertAuthConfigurationTarget("org", IdentityId, tlsApproved, true));
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();
    }

    private static async Task Denied<T>(ManagementClient client, ManagementAuthority authority,
        ManagementRequest<T> request, ManagementTarget target) where T : notnull
    {
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    public async Task CancellationBeforeDispatchPreservesCallerReceipt()
    {
        using var request = ExternalIdentityAuthenticationOperations.RefreshSpiffeBundle("org", IdentityId);
        var wire = new Wire(Response("spiffe"));
        var tokens = new Tokens();
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        var receipt = client.CreateReceipt(request);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.That(async () => await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new("org", resourceId: IdentityId)), receipt, cancellation.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments("ldap")]
    [Arguments("oci")]
    [Arguments("spiffe")]
    [Arguments("tls-cert")]
    public async Task OptionalResponseAbsenceDoesNotInjectMetadataDefaults(string strategy)
    {
        const string policy = "\"accessTokenTTL\":0.5,\"accessTokenMaxTTL\":1.5,\"accessTokenNumUsesLimit\":0," +
            "\"accessTokenTrustedIps\":{\"unknown\":\"canary\"},";
        string response = Response(strategy).Replace(policy, "", StringComparison.Ordinal);
        using var document = JsonDocument.Parse(response);
        switch (strategy)
        {
            case "ldap": using (var r = Ldap("GET")) using (var v = r.Parse(document.RootElement)) await Absent(v); break;
            case "oci": using (var r = Oci("GET")) await Absent(r.Parse(document.RootElement)); break;
            case "spiffe": using (var r = Spiffe("GET")) using (var v = r.Parse(document.RootElement)) await Absent(v); break;
            default: using (var r = Tls("GET")) using (var v = r.Parse(document.RootElement)) await Absent(v); break;
        }
    }
    private static async Task Absent(WorkloadAuthConfiguration value)
    {
        await Assert.That(value.AccessTokenTTL).IsNull();
        await Assert.That(value.AccessTokenMaxTTL).IsNull();
        await Assert.That(value.AccessTokenNumUsesLimit).IsNull();
        await Assert.That(value.HasUnestablishedTrustedIpProjection).IsFalse();
    }

    [Test]
    public async Task ResultAndInputBudgetsRejectOversizedKnownNodes()
    {
        using var tls = Tls("GET");
        using var hugeText = JsonDocument.Parse(Response("tls-cert").Replace("ca-canary", new string('x', 16385), StringComparison.Ordinal));
        await Assert.That(() => tls.Parse(hugeText.RootElement)).Throws<ManagementContractException>();
        string hugeArray = "[" + string.Join(",", Enumerable.Repeat("\"name\"", 101)) + "]";
        using var hugeNames = JsonDocument.Parse(Response("tls-cert").Replace("\"allowedSubjectAltNames\":null",
            "\"allowedSubjectAltNames\":" + hugeArray, StringComparison.Ordinal));
        await Assert.That(() => tls.Parse(hugeNames.RootElement)).Throws<ManagementContractException>();
        await Assert.That(() => TlsAuthSubjectAltNames.FromValues(Enumerable.Repeat("name", 101))).Throws<ArgumentException>();
        await Assert.That(() => new LdapAuthSettings(allowedFields: Enumerable.Repeat(new LdapAuthAllowedField("", ""), 101)))
            .Throws<ArgumentException>();
        using var oversizedCertificate = SecretMaterial.FromText(new string('x', 10241));
        await Assert.That(() => new TlsCertAuthConfigurationInput(oversizedCertificate)).Throws<ArgumentException>();
    }

    [Test]
    public async Task InvalidInputsRejectKnownConstraintsWithoutDefaults()
    {
        await Assert.That(() => new OciAuthConfigurationInput("")).Throws<ArgumentException>();
        await Assert.That(() => new OciAuthConfigurationInput("tenancy", WorkloadAuthNullableText.FromValue(new string('x', 501))))
            .Throws<ArgumentException>();
        await Assert.That(() => new LdapAuthSettings(lockoutThreshold: double.NaN)).Throws<ArgumentException>();
        await Assert.That(() => new LdapAuthSettings(lockoutDurationSeconds: 29)).Throws<ArgumentException>();
        await Assert.That(() => new LdapAuthSettings(lockoutCounterResetSeconds: 3601)).Throws<ArgumentException>();
        await Assert.That(() => LdapAuthConfigurationInput.Patch(url: "")).Throws<ArgumentException>();
        await Assert.That(() => TlsAuthSubjectAltNames.FromValues([""])).Throws<ArgumentException>();
        await Assert.That(() => TlsAuthSubjectAltNames.FromValues([null!])).Throws<ArgumentException>();
        using var empty = SecretMaterial.FromText("");
        await Assert.That(() => SpiffeTrustBundleInput.Static(empty)).Throws<ArgumentException>();
        await Assert.That(() => SpiffeTrustBundleInput.HttpsWebBundle("not-uri")).Throws<ArgumentException>();
        await Assert.That(() => SpiffeTrustBundleInput.HttpsWebBundle("https://bundle.test", refreshHintSeconds: -1))
            .Throws<ArgumentException>();
        await Assert.That(() => new TlsCertAuthConfigurationInput(empty)).Throws<ArgumentException>();
        await Assert.That(() => new TlsCertAuthConfigurationInput(allowedCommonNames: WorkloadAuthNullableText.FromValue("")))
            .Throws<ArgumentException>();
        using var missingTls = new TlsCertAuthConfigurationInput();
        await Assert.That(() => ExternalIdentityAuthenticationOperations.AttachTlsCertAuth("org", IdentityId, missingTls))
            .Throws<ArgumentException>();
        using var missingSpiffe = new SpiffeAuthConfigurationInput();
        await Assert.That(() => ExternalIdentityAuthenticationOperations.AttachSpiffeAuth("org", IdentityId, missingSpiffe))
            .Throws<ArgumentException>();
        await Assert.That(() => ExternalIdentityAuthenticationOperations.AttachOciAuth("org", IdentityId, new("tenancy", policy: new(0, 0))))
            .Throws<ArgumentException>();
        await Assert.That(() => LdapAuthConfigurationInput.FromTemplate("template", settings: new(policy: new(0, 0))))
            .Throws<ArgumentException>();
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

    private static ManagementTarget Approved(string strategy, string method)
    {
        if (method is "GET" or "DELETE" or "clear-lockouts" or "refresh-bundle") return new("org", resourceId: IdentityId);
        switch (strategy)
        {
            case "ldap":
                using (var input = method == "PATCH" ? LdapAuthConfigurationInput.Patch() : LdapAuthConfigurationInput.FromTemplate("template"))
                    return ExternalIdentityAuthenticationOperations.LdapAuthConfigurationTarget("org", IdentityId, input, method == "PATCH");
            case "oci": return ExternalIdentityAuthenticationOperations.OciAuthConfigurationTarget("org", IdentityId, new("tenancy"), method == "PATCH");
            case "spiffe":
                using (var material = SecretMaterial.FromText("bundle"))
                using (var distribution = SpiffeTrustBundleInput.Static(material))
                using (var input = new SpiffeAuthConfigurationInput("domain", "ids", "aud", distribution))
                    return ExternalIdentityAuthenticationOperations.SpiffeAuthConfigurationTarget("org", IdentityId, input, method == "PATCH");
            default:
                using (var material = SecretMaterial.FromText("certificate"))
                using (var input = new TlsCertAuthConfigurationInput(material))
                    return ExternalIdentityAuthenticationOperations.TlsCertAuthConfigurationTarget("org", IdentityId, input, method == "PATCH");
        }
    }
    private static ManagementRequest<LdapAuthConfiguration> Ldap(string method)
    {
        if (method == "GET") return ExternalIdentityAuthenticationOperations.GetLdapAuth("org", IdentityId);
        if (method == "DELETE") return ExternalIdentityAuthenticationOperations.DeleteLdapAuth("org", IdentityId);
        using var input = method == "PATCH" ? LdapAuthConfigurationInput.Patch() : LdapAuthConfigurationInput.FromTemplate("template");
        return method == "PATCH" ? ExternalIdentityAuthenticationOperations.UpdateLdapAuth("org", IdentityId, input) :
            ExternalIdentityAuthenticationOperations.AttachLdapAuth("org", IdentityId, input);
    }
    private static ManagementRequest<OciAuthConfiguration> Oci(string method) => method switch
    {
        "GET" => ExternalIdentityAuthenticationOperations.GetOciAuth("org", IdentityId),
        "DELETE" => ExternalIdentityAuthenticationOperations.DeleteOciAuth("org", IdentityId),
        "PATCH" => ExternalIdentityAuthenticationOperations.UpdateOciAuth("org", IdentityId, new("tenancy")),
        _ => ExternalIdentityAuthenticationOperations.AttachOciAuth("org", IdentityId, new("tenancy"))
    };
    private static ManagementRequest<SpiffeAuthConfiguration> Spiffe(string method)
    {
        if (method == "GET") return ExternalIdentityAuthenticationOperations.GetSpiffeAuth("org", IdentityId);
        if (method == "DELETE") return ExternalIdentityAuthenticationOperations.DeleteSpiffeAuth("org", IdentityId);
        if (method == "refresh-bundle") return ExternalIdentityAuthenticationOperations.RefreshSpiffeBundle("org", IdentityId);
        using var material = SecretMaterial.FromText("bundle");
        using var distribution = SpiffeTrustBundleInput.Static(material);
        using var input = new SpiffeAuthConfigurationInput("domain", "ids", "aud", distribution);
        return method == "PATCH" ? ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth("org", IdentityId, input) :
            ExternalIdentityAuthenticationOperations.AttachSpiffeAuth("org", IdentityId, input);
    }
    private static ManagementRequest<TlsCertAuthConfiguration> Tls(string method)
    {
        if (method == "GET") return ExternalIdentityAuthenticationOperations.GetTlsCertAuth("org", IdentityId);
        if (method == "DELETE") return ExternalIdentityAuthenticationOperations.DeleteTlsCertAuth("org", IdentityId);
        using var material = SecretMaterial.FromText("certificate");
        using var input = new TlsCertAuthConfigurationInput(material);
        return method == "PATCH" ? ExternalIdentityAuthenticationOperations.UpdateTlsCertAuth("org", IdentityId, input) :
            ExternalIdentityAuthenticationOperations.AttachTlsCertAuth("org", IdentityId, input);
    }

    private const string Common = $$"""
        "id":"{{ConfigurationId}}","identityId":"{{IdentityId}}","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z",
        "accessTokenTTL":0.5,"accessTokenMaxTTL":1.5,"accessTokenNumUsesLimit":0,"accessTokenTrustedIps":{"unknown":"canary"}
        """;
    private static string Response(string strategy) => "{\"" + (strategy switch
    {
        "ldap" => "identityLdapAuth",
        "oci" => "identityOciAuth",
        "spiffe" => "identitySpiffeAuth",
        _ => "identityTlsCertAuth"
    }) + "\":{" + Common + "," + (strategy switch
    {
        "ldap" => $$"""
            "url":"","searchBase":"","searchFilter":"","templateId":"{{TemplateId}}","allowedFields":42,"bindDN":"",
            "ldapCaCertificate":"ca-canary","lockoutEnabled":false,"lockoutThreshold":1.5,
            "lockoutDurationSeconds":30.5,"lockoutCounterResetSeconds":5.5,"accessTokenPeriod":1.25
            """,
        "oci" => """
            "tenancyOcid":"","type":"native-canary","allowedUsernames":null,"accessTokenPeriod":1.25
            """,
        "spiffe" => """
            "trustDomain":"","allowedSpiffeIds":"","allowedAudiences":"",
            "trustBundleDistribution":{"profile":"https_web_bundle","endpointUrl":"","caCert":"ca-canary","refreshHintSeconds":0.5,"cachedBundleLastRefreshedAt":null}
            """,
        _ => """
            "allowedCommonNames":null,"allowedSubjectAltNames":null,"encryptedCaCertificate":42,
            "caCertificate":"ca-canary","verifyClientCertificateChain":false
            """
    }) + "}}";

    private sealed class Tokens : IInfisicalTokenSource
    {
        internal bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
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
        internal string? Authorization { get; private set; }
        internal string? BodyHash { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Observed = true;
            Method = request.Method.Method;
            Path = request.RequestUri!.AbsolutePath;
            Authorization = request.Headers.Authorization?.ToString();
            if (request.Content is not null)
            {
                byte[] bytes = await request.Content.ReadAsByteArrayAsync(cancellationToken);
                try { BodyHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)); }
                finally { Array.Clear(bytes); }
            }
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(response, Encoding.UTF8, "application/json")
            };
        }
    }
}
