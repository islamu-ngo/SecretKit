using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class IdentityTemplateVariantTests
{
    private const string Org = "0000000a-0000-0000-0000-00000000000a";
    private const string OtherOrg = "0000000b-0000-0000-0000-00000000000b";
    private const string Template = "10000000-0000-0000-0000-000000000001";
    private const string Gateway = "20000000-0000-0000-0000-000000000002";
    private const string Pool = "30000000-0000-0000-0000-000000000003";
    private const string BasePath = "/api/v1/identity-templates";

    [Test]
    [Arguments("oidc", false)]
    [Arguments("ldap", false)]
    [Arguments("kubernetes", false)]
    [Arguments("oidc", true)]
    [Arguments("ldap", true)]
    [Arguments("kubernetes", true)]
    public async Task NativeCreateAndPatchUseApprovedFieldsAndSingleUseReceipts(string method, bool patch)
    {
        var fields = Fields(method);
        var approved = Fields(method);
        using var request = Request(fields, patch);
        (fields as IDisposable)?.Dispose();
        var wire = new Wire(method, patch);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        var grant = authority.IssueGrant(request.OperationId, Target(approved, patch));
        (approved as IDisposable)?.Dispose();
        var receipt = client.CreateReceipt(request);
        await Assert.That((await client.ExecuteAsync(request, authority, grant)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(tokens.Acquired).IsFalse();
        var result = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(wire.Revision).IsEqualTo(1);
        await Assert.That(wire.Body!["name"]!.GetValue<string>()).IsEqualTo("private-name");
        await Assert.That(wire.Body.ContainsKey("authMethod")).IsEqualTo(!patch);
        var config = wire.Configuration;
        switch (method)
        {
            case "oidc":
                await Assert.That(config.Count).IsEqualTo(4);
                await Assert.That(config["boundAudiences"]!.GetValue<string>()).IsEqualTo("aud-one,aud-two");
                await Assert.That(config["oidcDiscoveryUrl"]!.GetValue<string>()).IsEqualTo("https://issuer.test");
                await Assert.That(config["boundIssuer"]!.GetValue<string>()).IsEqualTo("private-issuer");
                break;
            case "ldap":
                await Assert.That(config.Count).IsEqualTo(5);
                await Assert.That(config["bindPass"]!.GetValue<string>()).IsEqualTo("private-password");
                await Assert.That(config["url"]!.GetValue<string>()).IsEqualTo("ldaps://ldap.test");
                await Assert.That(config["bindDN"]!.GetValue<string>()).IsEqualTo("cn=bind");
                await Assert.That(config["searchBase"]!.GetValue<string>()).IsEqualTo("ou=users");
                break;
            default:
                await Assert.That(config.Count).IsEqualTo(8);
                await Assert.That(config["tokenReviewMode"]!.GetValue<string>()).IsEqualTo("gateway");
                await Assert.That(config["kubernetesHost"]!.GetValue<string>()).IsEqualTo("kube.test:443");
                await Assert.That(config["tokenReviewerJwt"]!.GetValue<string>()).IsEqualTo("private-jwt");
                await Assert.That(config["verifyTlsCertificate"]!.GetValue<bool>()).IsFalse();
                await Assert.That(config["gatewayId"]!.GetValue<string>()).IsEqualTo(Gateway);
                await Assert.That(config["gatewayPoolId"]!.GetValue<string>()).IsEqualTo(Pool);
                await Assert.That(config["allowedAudience"]!.GetValue<string>()).IsEqualTo("");
                break;
        }
        await Assert.That(config[method == "ldap" ? "ldapCaCertificate" : "caCert"]!.GetValue<string>()).IsEqualTo("cert\nprivate");
        await Assert.That(result.Value.IncludesConfiguration).IsTrue();
        await Assert.That(result.Value.HasStoredCredential).IsEqualTo(method == "oidc" ? (bool?)null : true);
        await Assert.That(JsonSerializer.Serialize(result.Value)).IsEqualTo("""{"IncludesConfiguration":true}""");
        await Assert.That((await client.ExecuteAsync(request, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Revision).IsEqualTo(1);
        await Assert.That(request.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(fields)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(request.Target)).IsEqualTo("{}");
    }

    [Test]
    [Arguments("oidc")]
    [Arguments("ldap")]
    [Arguments("kubernetes")]
    public async Task PartialPatchesOmitUnselectedFieldsWithoutAuthDiscriminator(string method)
    {
        IdentityTemplateFields fields = method switch
        {
            "oidc" => new IdentityTemplateOidcPatch(boundAudiences: ""),
            "ldap" => new IdentityTemplateLdapFields(caCertificate: ""),
            _ => new IdentityTemplateKubernetesFields(verifyTlsCertificate: false)
        };
        using var request = IdentityTemplateOperations.UpdateIdentityTemplateConfiguration(Org, Template, fields);
        var wire = new Wire(method, true);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, IdentityTemplateOperations.IdentityTemplateUpdateTarget(Org, Template, fields: fields)),
            client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(wire.Body!.Count).IsEqualTo(1);
        var config = wire.Configuration;
        await Assert.That(config.Count).IsEqualTo(1);
        await Assert.That(config.ContainsKey(method == "oidc" ? "boundAudiences" : method == "ldap" ? "ldapCaCertificate" : "verifyTlsCertificate")).IsTrue();
        (fields as IDisposable)?.Dispose();
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task KubernetesOmissionAndExplicitNullRemainDistinct(bool explicitNull, bool patch)
    {
        using var fields = new IdentityTemplateKubernetesFields(
            kubernetesHost: explicitNull ? IdentityTemplateNullableText.Null() : null,
            gatewayId: explicitNull ? IdentityTemplateNullableText.Null() : null,
            gatewayPoolId: explicitNull ? IdentityTemplateNullableText.Null() : null);
        using var request = Request(fields, patch);
        var wire = new Wire("kubernetes", patch);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, Target(fields, patch)),
            client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var config = wire.Body!["templateFields"]!.AsObject();
        await Assert.That(config.Count).IsEqualTo(explicitNull ? 3 : 0);
        foreach (string name in new[] { "kubernetesHost", "gatewayId", "gatewayPoolId" })
        {
            await Assert.That(config.ContainsKey(name)).IsEqualTo(explicitNull);
            if (explicitNull) await Assert.That(config[name]).IsNull();
        }
    }

    [Test]
    public async Task EmptyReviewerJwtIsExplicitAndNotAnOmittedCredential()
    {
        using var empty = SecretMaterial.FromText("");
        using var fields = new IdentityTemplateKubernetesFields(tokenReviewerJwt: empty);
        using var request = Request(fields, true);
        var wire = new Wire("kubernetes", true);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, Target(fields, true)),
            client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var config = wire.Configuration;
        await Assert.That(config.Count).IsEqualTo(1);
        await Assert.That(config["tokenReviewerJwt"]!.GetValue<string>()).IsEqualTo("");
        using var omitted = new IdentityTemplateKubernetesFields();
        await Denied(request, Target(omitted, true));
    }

    [Test]
    public async Task PatchCanOmitBothOptionalTopLevelFields()
    {
        using var request = IdentityTemplateOperations.UpdateIdentityTemplate(Org, Template);
        var wire = new Wire("oidc", true);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            IdentityTemplateOperations.IdentityTemplateUpdateTarget(Org, Template)), client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(wire.Body!.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("discovery", false)]
    [Arguments("issuer", false)]
    [Arguments("audiences", false)]
    [Arguments("certificate", false)]
    [Arguments("method", false)]
    [Arguments("name", false)]
    [Arguments("discovery", true)]
    [Arguments("issuer", true)]
    [Arguments("audiences", true)]
    [Arguments("certificate", true)]
    [Arguments("name", true)]
    public async Task OidcCompleteChangeCannotBorrowAnotherGrant(string difference, bool patch)
    {
        var approved = new IdentityTemplateOidcFields("https://issuer.test", "issuer", "aud", "cert");
        IdentityTemplateFields changed = difference == "method" ? new IdentityTemplateKubernetesFields() :
            new IdentityTemplateOidcFields(difference == "discovery" ? "https://other.test" : "https://issuer.test",
                difference == "issuer" ? "other" : "issuer", difference == "audiences" ? "" : "aud",
                difference == "certificate" ? null : "cert");
        using var request = patch
            ? IdentityTemplateOperations.UpdateIdentityTemplateConfiguration(Org, Template, changed, difference == "name" ? "other" : "private-name")
            : difference == "method"
            ? IdentityTemplateOperations.CreateKubernetesIdentityTemplate(Org, "private-name", (IdentityTemplateKubernetesFields)changed)
            : IdentityTemplateOperations.CreateIdentityTemplate(Org, difference == "name" ? "other" : "private-name", (IdentityTemplateOidcFields)changed);
        await Denied(request, Target(approved, patch));
        (changed as IDisposable)?.Dispose();
    }

    [Test]
    [Arguments("mode", true)]
    [Arguments("host", true)]
    [Arguments("tls", true)]
    [Arguments("jwt", true)]
    [Arguments("gateway", true)]
    [Arguments("pool", true)]
    [Arguments("audience", true)]
    [Arguments("certificate", true)]
    [Arguments("mode", false)]
    [Arguments("host", false)]
    [Arguments("tls", false)]
    [Arguments("jwt", false)]
    [Arguments("gateway", false)]
    [Arguments("pool", false)]
    [Arguments("audience", false)]
    [Arguments("certificate", false)]
    public async Task KubernetesIntentBindsEveryOptionalValue(string difference, bool patch)
    {
        using var originalJwt = SecretMaterial.FromText("jwt");
        using var changedJwt = SecretMaterial.FromText("other");
        using var approved = new IdentityTemplateKubernetesFields(IdentityTemplateTokenReviewMode.Api,
            IdentityTemplateNullableText.FromValue("host"), "cert", true, originalJwt,
            IdentityTemplateNullableText.FromValue(Gateway), IdentityTemplateNullableText.FromValue(Pool), "aud");
        using var changed = new IdentityTemplateKubernetesFields(difference == "mode" ? null : IdentityTemplateTokenReviewMode.Api,
            difference == "host" ? IdentityTemplateNullableText.Null() : IdentityTemplateNullableText.FromValue("host"),
            difference == "certificate" ? "" : "cert", difference == "tls" ? false : true,
            difference == "jwt" ? changedJwt : originalJwt,
            difference == "gateway" ? IdentityTemplateNullableText.Null() : IdentityTemplateNullableText.FromValue(Gateway),
            difference == "pool" ? null : IdentityTemplateNullableText.FromValue(Pool),
            difference == "audience" ? null : "aud");
        using var request = Request(changed, patch);
        await Denied(request, Target(approved, patch));
    }

    [Test]
    [Arguments("url", false)]
    [Arguments("dn", false)]
    [Arguments("password", false)]
    [Arguments("base", false)]
    [Arguments("certificate", false)]
    [Arguments("url", true)]
    [Arguments("dn", true)]
    [Arguments("password", true)]
    [Arguments("base", true)]
    [Arguments("certificate", true)]
    public async Task LdapIntentBindsEveryField(string difference, bool patch)
    {
        using var password = SecretMaterial.FromText("password");
        using var other = SecretMaterial.FromText("other");
        using var approved = new IdentityTemplateLdapFields("ldap://host", "dn", password, "base", "cert");
        using var changed = new IdentityTemplateLdapFields(difference == "url" ? "ldap://other" : "ldap://host",
            difference == "dn" ? "other" : "dn", difference == "password" ? other : password,
            difference == "base" ? "other" : "base", difference == "certificate" ? null : "cert");
        using var request = Request(changed, patch);
        await Denied(request, Target(approved, patch));
    }

    [Test]
    [Arguments("oidc", false)]
    [Arguments("oidc", true)]
    [Arguments("ldap", false)]
    [Arguments("ldap", true)]
    [Arguments("kubernetes", false)]
    [Arguments("kubernetes", true)]
    public async Task PatchNamePresenceRequiresIndependentTemplateApproval(string strategy, bool selectedName)
    {
        var fields = Fields(strategy);
        try
        {
            using var request = IdentityTemplateOperations.UpdateIdentityTemplateConfiguration(Org, Template, fields,
                selectedName ? null : "private-name");
            var approved = IdentityTemplateOperations.IdentityTemplateUpdateTarget(Org, Template,
                selectedName ? "private-name" : null, fields);
            await Denied(request, approved);
        }
        finally { (fields as IDisposable)?.Dispose(); }
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task UnlinkSupportsEmptySubsetAndMultipleAcknowledgments(int count)
    {
        string[] identities = count == 0 ? [] : ["identity-a", "identity-b"];
        using var request = IdentityTemplateOperations.DeleteIdentityTemplateUsages(Org, Template, identities);
        var approved = IdentityTemplateOperations.IdentityTemplateUnlinkTarget(Org, Template, identities);
        if (identities.Length > 0) identities[0] = "tampered";
        var response = new JsonArray(Enumerable.Range(0, count).Select(i => (JsonNode)new JsonObject
        { ["identityId"] = i == 0 ? "identity-a" : "identity-b", ["identityName"] = "private", ["authId"] = "auth-" + i }).ToArray());
        var wire = new Wire("oidc", false, response.ToJsonString(), unlink: true);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, approved), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items.Count).IsEqualTo(count);
        await Assert.That(wire.Body!["identityIds"]!.AsArray().Count).IsEqualTo(count == 0 ? 0 : 2);
        await Assert.That(wire.LinkedIdentities.Contains("identity-a")).IsEqualTo(count == 0);
        await Assert.That(wire.LinkedIdentities.Contains("identity-b")).IsEqualTo(count == 0);
        if (count > 0) await Assert.That(wire.Body["identityIds"]![0]!.GetValue<string>()).IsEqualTo("identity-a");
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That((await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, approved), receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    [Arguments("foreign")]
    [Arguments("duplicate")]
    [Arguments("missing")]
    public async Task UnlinkValidatesOnlyReturnedSelectedCoordinates(string defect)
    {
        var row = new JsonObject { ["identityId"] = defect == "foreign" ? "other" : "identity-a", ["identityName"] = "name", ["authId"] = "auth" };
        if (defect == "missing") row.Remove("authId");
        var response = new JsonArray(row);
        if (defect == "duplicate") response.Add(row.DeepClone());
        using var request = IdentityTemplateOperations.DeleteIdentityTemplateUsages(Org, Template, ["identity-a", "identity-b"]);
        var wire = new Wire("oidc", false, response.ToJsonString(), unlink: true);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            IdentityTemplateOperations.IdentityTemplateUnlinkTarget(Org, Template, ["identity-a", "identity-b"])), receipt);
        await Assert.That(result.Status).IsEqualTo(defect == "missing" ? SecretStatus.Unknown : SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    [Arguments("order")]
    [Arguments("set")]
    [Arguments("empty")]
    public async Task UnlinkSelectionCannotBorrowApprovedGrant(string difference)
    {
        using var request = IdentityTemplateOperations.DeleteIdentityTemplateUsages(Org, Template,
            difference == "empty" ? [] : difference == "order" ? ["b", "a"] : ["a", "c"]);
        await Denied(request, IdentityTemplateOperations.IdentityTemplateUnlinkTarget(Org, Template, ["a", "b"]));
    }

    [Test]
    [Arguments("oidc", false)]
    [Arguments("ldap", false)]
    [Arguments("kubernetes", false)]
    [Arguments("oidc", true)]
    [Arguments("ldap", true)]
    [Arguments("kubernetes", true)]
    public async Task MutationCancellationKeepsUncertaintyAndPreventsReplay(string method, bool patch)
    {
        var fields = Fields(method);
        using var request = Request(fields, patch);
        var wire = new Wire(method, patch) { Hold = true };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var grant = authority.IssueGrant(request.OperationId, Target(fields, patch));
        (fields as IDisposable)?.Dispose();
        var receipt = client.CreateReceipt(request);
        using var cancel = new CancellationTokenSource();
        var entered = wire.Entered.Task;
        var pending = client.ExecuteAsync(request, authority, grant, receipt, cancel.Token).AsTask();
        await entered.WaitAsync(TimeSpan.FromSeconds(5));
        cancel.Cancel();
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That((await client.ExecuteAsync(request, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    [Arguments("orgId")]
    [Arguments("id")]
    [Arguments("name")]
    [Arguments("authMethod")]
    public async Task PatchEchoMismatchNeverRecordsApplied(string field)
    {
        var response = Response("oidc");
        response[field] = field == "authMethod" ? "ldap" : field == "orgId" ? OtherOrg :
            field == "id" ? Gateway : "other";
        var fields = new IdentityTemplateOidcPatch(boundAudiences: "");
        using var request = Request(fields, true);
        var wire = new Wire("oidc", true, response.ToJsonString());
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, Target(fields, true)), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    public async Task CredentialsCopyClearAndRespectLocalRequestBudget()
    {
        using var source = SecretMaterial.FromText("private-password");
        using var fields = new IdentityTemplateLdapFields("ldap://host", "dn", source, "base");
        source.Dispose();
        using var request = Request(fields, false);
        fields.Dispose();
        var wire = new Wire("ldap", false);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        using var approvedSecret = SecretMaterial.FromText("private-password");
        using var approved = new IdentityTemplateLdapFields("ldap://host", "dn", approvedSecret, "base");
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var grant = authority.IssueGrant(request.OperationId, Target(approved, false));
        await Assert.That((await client.ExecuteAsync(request, authority, grant, client.CreateReceipt(request))).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(wire.Body!["templateFields"]!["bindPass"]!.GetValue<string>()).IsEqualTo("private-password");
        request.Dispose();
        await Assert.That(async () => await client.ExecuteAsync(request, authority, grant, client.CreateReceipt(request))).Throws<ObjectDisposedException>();
        await Assert.That(() => Request(new IdentityTemplateOidcFields("https://issuer.test", "issuer", caCertificate: new string('x', 102400)), false))
            .Throws<ArgumentException>();
        await Assert.That(() => IdentityTemplateOperations.CreateLdapIdentityTemplate(Org, "name", new())).Throws<ArgumentException>();
        await Assert.That(() => new IdentityTemplateKubernetesFields(gatewayId: IdentityTemplateNullableText.FromValue("bad"))).Throws<ArgumentException>();
        await Assert.That(() => new IdentityTemplateKubernetesFields(tokenReviewMode: (IdentityTemplateTokenReviewMode)9)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => IdentityTemplateOperations.DeleteIdentityTemplateUsages(Org, Template, ["a", "a"])).Throws<ArgumentException>();
        await Assert.That(() => IdentityTemplateOperations.DeleteIdentityTemplateUsages(Org, Template, Enumerable.Repeat("a", 1001).ToArray())).Throws<ArgumentException>();
    }

    private static IdentityTemplateFields Fields(string method)
    {
        using var password = SecretMaterial.FromText("private-password");
        using var jwt = SecretMaterial.FromText("private-jwt");
        return method switch
        {
            "oidc" => new IdentityTemplateOidcFields("https://issuer.test", "private-issuer", "aud-one,aud-two", "cert\nprivate"),
            "ldap" => new IdentityTemplateLdapFields("ldaps://ldap.test", "cn=bind", password, "ou=users", "cert\nprivate"),
            _ => new IdentityTemplateKubernetesFields(IdentityTemplateTokenReviewMode.Gateway,
                IdentityTemplateNullableText.FromValue("kube.test:443"), "cert\nprivate", false, jwt,
                IdentityTemplateNullableText.FromValue(Gateway), IdentityTemplateNullableText.FromValue(Pool), "")
        };
    }

    private static ManagementRequest<IdentityTemplateSummary> Request(IdentityTemplateFields fields, bool patch) => patch
        ? IdentityTemplateOperations.UpdateIdentityTemplateConfiguration(Org, Template, fields, "private-name")
        : fields switch
        {
            IdentityTemplateLdapFields ldap => IdentityTemplateOperations.CreateLdapIdentityTemplate(Org, "private-name", ldap),
            IdentityTemplateKubernetesFields kubernetes => IdentityTemplateOperations.CreateKubernetesIdentityTemplate(Org, "private-name", kubernetes),
            _ => IdentityTemplateOperations.CreateIdentityTemplate(Org, "private-name", (IdentityTemplateOidcFields)fields)
        };

    private static ManagementTarget Target(IdentityTemplateFields fields, bool patch) => patch
        ? IdentityTemplateOperations.IdentityTemplateUpdateTarget(Org, Template, "private-name", fields)
        : IdentityTemplateOperations.IdentityTemplateCreateTarget(Org, "private-name", fields);

    private static async Task Denied<T>(ManagementRequest<T> request, ManagementTarget approved) where T : notnull
    {
        var wire = new Wire("oidc", false);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, approved), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Revision).IsEqualTo(0);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    private static JsonObject Response(string method) => new()
    {
        ["id"] = Template,
        ["orgId"] = Org,
        ["name"] = "private-name",
        ["authMethod"] = method,
        ["createdAt"] = "2026-10-10T00:00:00Z",
        ["updatedAt"] = "2026-10-10T00:00:00Z",
        ["templateFields"] = method switch
        {
            "ldap" => new JsonObject { ["hasBindPass"] = true },
            "kubernetes" => new JsonObject { ["hasTokenReviewerJwt"] = true },
            _ => new JsonObject { ["oidcDiscoveryUrl"] = "https://issuer.test", ["boundIssuer"] = "private-issuer" }
        }
    };

    private static ManagementTransport Transport(HttpMessageHandler handler) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, handler);

    private sealed class Wire(string method, bool patch, string? response = null, bool unlink = false) : HttpMessageHandler
    {
        public JsonObject? Body { get; private set; }
        public JsonObject Configuration { get; private set; } = new();
        public HashSet<string> LinkedIdentities { get; } = new(StringComparer.Ordinal) { "identity-a", "identity-b" };
        public int Revision { get; private set; }
        public bool Hold { get; init; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = BasePath + (unlink ? "/" + Template + "/delete-usage" : patch ? "/" + Template : "");
            if (request.Method != (patch ? HttpMethod.Patch : HttpMethod.Post) ||
                request.RequestUri!.PathAndQuery != path || request.Headers.Authorization?.Scheme != "Bearer")
                return new(HttpStatusCode.NotFound);
            Body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!.AsObject();
            if (unlink)
            {
                foreach (var identity in Body["identityIds"]!.AsArray())
                    LinkedIdentities.Remove(identity!.GetValue<string>());
            }
            else if (Body["templateFields"] is JsonObject configuration)
                Configuration = (JsonObject)configuration.DeepClone();
            Revision++;
            Entered.TrySetResult();
            if (Hold) await _release.Task.WaitAsync(cancellationToken);
            return new(HttpStatusCode.OK) { Content = new StringContent(response ?? Response(method).ToJsonString(), Encoding.UTF8, "application/json") };
        }
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("fixture-token"))));
        }
    }
}
