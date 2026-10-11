using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class IdentityTemplateTests
{
    private const string Org = "0000000a-0000-0000-0000-00000000000a";
    private const string OtherOrg = "0000000b-0000-0000-0000-00000000000b";
    private const string Template = "10000000-0000-0000-0000-000000000001";
    private const string Identity = "20000000-0000-0000-0000-000000000002";
    private const string BasePath = "/api/v1/identity-templates";

    [Test]
    [Arguments("oidc")]
    [Arguments("ldap")]
    [Arguments("kubernetes")]
    public async Task ReturnedConfigurationIsProjectedWithoutStoredCredentialMaterial(string method)
    {
        var row = Row();
        row["authMethod"] = method;
        row["templateFields"] = method switch
        {
            "ldap" => (object)new
            {
                url = "ldaps://private.test",
                bindDN = "private-bind",
                searchBase = "private-base",
                ldapCaCertificate = "",
                hasBindPass = false
            },
            "kubernetes" => new
            {
                kubernetesHost = (string?)null,
                gatewayId = (string?)null,
                gatewayPoolId = Identity,
                caCert = "",
                tokenReviewMode = "gateway",
                allowedAudience = "",
                verifyTlsCertificate = false,
                hasTokenReviewerJwt = true
            },
            _ => new
            {
                oidcDiscoveryUrl = "https://private.test",
                boundIssuer = "private-issuer",
                boundAudiences = "",
                caCert = ""
            }
        };
        using var request = IdentityTemplateOperations.GetIdentityTemplate(Org, Template);
        var result = await Execute(request, Fixture("get", JsonSerializer.Serialize(row)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.IncludesConfiguration).IsTrue();
        var settings = result.Value.Configuration;
        await Assert.That(JsonSerializer.Serialize(settings)).IsEqualTo("{}");
        await Assert.That(settings.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
        if (method == "ldap")
        {
            await Assert.That(settings.Url).IsEqualTo("ldaps://private.test");
            await Assert.That(settings.BindDn).IsEqualTo("private-bind");
            await Assert.That(settings.SearchBase).IsEqualTo("private-base");
            await Assert.That(settings.LdapCaCertificate).IsEqualTo("");
            await Assert.That(result.Value.HasStoredCredential).IsFalse();
        }
        else if (method == "oidc")
        {
            await Assert.That(settings.OidcDiscoveryUrl).IsEqualTo("https://private.test");
            await Assert.That(settings.BoundIssuer).IsEqualTo("private-issuer");
            await Assert.That(settings.BoundAudiences).IsEqualTo("");
            await Assert.That(settings.CaCertificate).IsEqualTo("");
        }
        else
        {
            await Assert.That(settings.HasKubernetesHost).IsTrue();
            await Assert.That(settings.KubernetesHost is null).IsTrue();
            await Assert.That(settings.HasGatewayId).IsTrue();
            await Assert.That(settings.GatewayId is null).IsTrue();
            await Assert.That(settings.GatewayPoolId).IsEqualTo(Identity);
            await Assert.That(settings.TokenReviewMode).IsEqualTo("gateway");
            await Assert.That(settings.AllowedAudience).IsEqualTo("");
            await Assert.That(settings.VerifyTlsCertificate).IsFalse();
        }
    }

    [Test]
    [Arguments("ldap", "url", "null")]
    [Arguments("ldap", "bindDN", "empty")]
    [Arguments("oidc", "boundIssuer", "empty")]
    [Arguments("oidc", "caCert", "over-certificate")]
    [Arguments("kubernetes", "gatewayId", "invalid")]
    [Arguments("kubernetes", "tokenReviewMode", "invalid")]
    [Arguments("kubernetes", "verifyTlsCertificate", "string")]
    [Arguments("kubernetes", "allowedAudience", "over-audience")]
    public async Task MalformedReturnedConfigurationRemainsUnknown(string method, string field, string variant)
    {
        var row = Row();
        row["authMethod"] = method;
        var fields = new Dictionary<string, object?>
        {
            ["hasBindPass"] = false,
            ["hasTokenReviewerJwt"] = false,
            ["oidcDiscoveryUrl"] = "https://id.test",
            ["boundIssuer"] = "issuer"
        };
        fields[field] = variant switch
        {
            "null" => null,
            "empty" => "",
            "over-certificate" => new string('x', 102401),
            "over-audience" => new string('x', 1001),
            "string" => "false",
            _ => "invalid"
        };
        row["templateFields"] = fields;
        using var request = IdentityTemplateOperations.GetIdentityTemplate(Org, Template);
        var result = await Execute(request, Fixture("get", JsonSerializer.Serialize(row)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    public async Task AbsentSettingsStayAbsentAndFullCertificateBudgetIsProjected()
    {
        var row = Row();
        row["authMethod"] = "kubernetes";
        row["templateFields"] = new { hasTokenReviewerJwt = false };
        using var request = IdentityTemplateOperations.GetIdentityTemplate(Org, Template);
        var absent = await Execute(request, Fixture("get", JsonSerializer.Serialize(row)));
        await Assert.That(absent.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(absent.Value.Configuration.HasKubernetesHost).IsFalse();
        await Assert.That(absent.Value.Configuration.HasGatewayId).IsFalse();
        await Assert.That(absent.Value.Configuration.HasGatewayPoolId).IsFalse();
        await Assert.That(absent.Value.Configuration.VerifyTlsCertificate is null).IsTrue();
        await Assert.That(absent.Value.Configuration.TokenReviewMode is null).IsTrue();

        row["authMethod"] = "oidc";
        row["templateFields"] = new
        {
            oidcDiscoveryUrl = "https://id.test",
            boundIssuer = "issuer",
            caCert = new string('x', 102400)
        };
        var full = await Execute(request, Fixture("get", JsonSerializer.Serialize(row)));
        await Assert.That(full.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(full.Value.Configuration.CaCertificate!.Length).IsEqualTo(102400);
    }

    [Test]
    public async Task CompleteCreateIntentCannotBorrowApprovedIssuer()
    {
        using var request = IdentityTemplateOperations.CreateIdentityTemplate(Org, "private-template",
            new("https://id.test/.well-known/openid-configuration", "unapproved-issuer"));
        var wire = Fixture("create");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        var receipt = client.CreateReceipt(request);
        var grant = authority.IssueGrant(request.OperationId,
            ApprovedTarget("create"));
        var result = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments("list")]
    [Arguments("search")]
    [Arguments("get")]
    [Arguments("create")]
    [Arguments("update")]
    [Arguments("delete")]
    [Arguments("usage")]
    [Arguments("delete-usage")]
    public async Task EightRoutesUseActualClientAndIndependentGrants(string operation)
    {
        var wire = Fixture(operation);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        switch (operation)
        {
            case "list":
                using (var request = IdentityTemplateOperations.ListIdentityTemplates(Org, IdentityTemplateAuthMethod.Oidc))
                {
                    var result = await client.ExecuteAsync(request, authority,
                        authority.IssueGrant("infisical.get.v1.identity.templates", new(Org, secondaryId: "oidc")));
                    await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
                    await Assert.That(result.Value.IsComplete).IsTrue();
                    await Protected(result.Value.Items.Single());
                }
                break;
            case "search":
                using (var request = IdentityTemplateOperations.SearchIdentityTemplates(Org, "private?name", 0, 5))
                {
                    var result = await client.ExecuteAsync(request, authority,
                        authority.IssueGrant("infisical.get.v1.identity.templates.search",
                            IdentityTemplateOperations.IdentityTemplateSearchTarget(Org, "private?name", 0, 5)));
                    await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
                    await Assert.That(result.Value.IsComplete).IsFalse();
                    await Assert.That(result.Value.NextOffset).IsEqualTo(1);
                    await Protected(result.Value.Items.Single());
                }
                break;
            case "delete":
                using (var request = IdentityTemplateOperations.DeleteIdentityTemplate(Org, Template))
                {
                    var receipt = client.CreateReceipt(request);
                    var result = await client.ExecuteAsync(request, authority,
                        authority.IssueGrant("infisical.delete.v1.identity.templates.by.templateId", new(Org, resourceId: Template)), receipt);
                    await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
                    await Assert.That(JsonSerializer.Serialize(result.Value)).IsEqualTo("{}");
                    await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
                }
                break;
            case "usage":
            case "delete-usage":
                using (var request = Usage(operation == "delete-usage"))
                {
                    var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                    var result = await client.ExecuteAsync(request, authority,
                        authority.IssueGrant("infisical." + (request.IsMutation ? "post" : "get") +
                            ".v1.identity.templates.by.templateId." + (request.IsMutation ? "delete.usage" : "usage"),
                            request.IsMutation ? ApprovedTarget("delete-usage") : new(Org, resourceId: Template)), receipt);
                    await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
                    await Assert.That(result.Value.Items.Single().IdentityId).IsEqualTo(Identity);
                    await Assert.That(result.Value.Items.Single().AuthId).IsEqualTo(request.IsMutation ? "auth" : null);
                    await Assert.That(JsonSerializer.Serialize(result.Value.Items.Single())).IsEqualTo("{}");
                    await Assert.That(result.Value.Items.Single().ToString().Contains(Identity, StringComparison.Ordinal)).IsFalse();
                    if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
                    if (!request.IsMutation)
                    {
                        var rejected = await Execute(request, Fixture("usage", "[" + UsageRow() + "]"));
                        await Assert.That(rejected.Status).IsEqualTo(SecretStatus.Unknown);
                    }
                }
                break;
            default:
                using (var request = Single(operation))
                {
                    var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                    var result = await client.ExecuteAsync(request, authority,
                        authority.IssueGrant("infisical." + wire.Method.ToLowerInvariant() + ".v1.identity.templates" +
                            (operation == "create" ? "" : ".by.templateId"),
                            operation is "create" or "update" ? ApprovedTarget(operation) : new(Org, resourceId: Template)), receipt);
                    await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
                    await Protected(result.Value);
                    if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
                }
                break;
        }
        await Assert.That(wire.Observed).IsTrue();
        if (operation == "create")
        {
            using JsonDocument body = JsonDocument.Parse(wire.Body!);
            await Assert.That(body.RootElement.GetProperty("authMethod").GetString()).IsEqualTo("oidc");
            await Assert.That(body.RootElement.GetProperty("name").GetString()).IsEqualTo("private-template");
            var fields = body.RootElement.GetProperty("templateFields");
            await Assert.That(fields.GetProperty("oidcDiscoveryUrl").GetString()).IsEqualTo("https://id.test/.well-known/openid-configuration");
            await Assert.That(fields.GetProperty("boundIssuer").GetString()).IsEqualTo("private-issuer");
            await Assert.That(fields.EnumerateObject().Count()).IsEqualTo(2);
            await Assert.That(body.RootElement.EnumerateObject().Count()).IsEqualTo(3);
        }
        else if (operation == "update")
            await Assert.That(wire.Body).IsEqualTo("""{"name":"private-template"}""");
        else if (operation == "delete-usage")
            await Assert.That(wire.Body).IsEqualTo("""{"identityIds":[""" + "\"" + Identity + "\"]}");
        else await Assert.That(wire.Body is null).IsTrue();
    }

    [Test]
    [Arguments("organization")]
    [Arguments("template")]
    [Arguments("identity")]
    [Arguments("operation")]
    [Arguments("issuer")]
    [Arguments("missing")]
    public async Task UsageMutationRejectsForeignGrantBeforeTokens(string mismatch)
    {
        var wire = Fixture("delete-usage");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        var issuer = mismatch is "organization" or "issuer"
            ? new ManagementAuthority(client.Authority, tokens, mismatch == "organization" ? OtherOrg : Org) : authority;
        using var request = Usage(true);
        var receipt = client.CreateReceipt(request);
        var grant = mismatch == "missing" ? null : issuer.IssueGrant(mismatch == "operation" ? "other" : request.OperationId,
            IdentityTemplateOperations.IdentityTemplateUnlinkTarget(mismatch == "organization" ? OtherOrg : Org,
                mismatch == "template" ? "other" : Template, [mismatch == "identity" ? "other" : Identity]));
        var result = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments("list")]
    [Arguments("search")]
    [Arguments("create")]
    public async Task FilterSearchAndCreateSelectionCannotBorrowAnotherGrant(string operation)
    {
        var wire = Fixture(operation);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        if (operation == "create")
        {
            using var request = Single(operation);
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, IdentityTemplateOperations.IdentityTemplateCreateTarget(Org, "other",
                    new IdentityTemplateOidcFields("https://id.test/.well-known/openid-configuration", "private-issuer"))),
                client.CreateReceipt(request));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        }
        else
        {
            using var request = operation == "list"
                ? IdentityTemplateOperations.ListIdentityTemplates(Org, IdentityTemplateAuthMethod.Oidc)
                : IdentityTemplateOperations.SearchIdentityTemplates(Org, "private?name");
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, new(Org, secondaryId: "other")));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        }
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();
    }

    [Test]
    [Arguments("orgId", OtherOrg, SecretStatus.Invalid)]
    [Arguments("id", Identity, SecretStatus.Invalid)]
    [Arguments("orgId", null, SecretStatus.Unknown)]
    [Arguments("createdAt", null, SecretStatus.Unknown)]
    [Arguments("templateFields", null, SecretStatus.Unknown)]
    [Arguments("authMethod", "unknown", SecretStatus.Unknown)]
    public async Task IndividualResponseScopeAndRequiredMetadataFailClosed(string field, string? value, SecretStatus expected)
    {
        var row = Row();
        if (value is null) row.Remove(field);
        else row[field] = value;
        using var request = Single("get");
        var result = await Execute(request, Fixture("get", JsonSerializer.Serialize(row)));
        await Assert.That(result.Status).IsEqualTo(expected);
    }

    [Test]
    [Arguments("ldap")]
    [Arguments("kubernetes")]
    [Arguments("oidc")]
    public async Task ListSupportsAllNativeMethodsAndValidatesTheirRequiredProjection(string method)
    {
        var auth = method == "ldap" ? IdentityTemplateAuthMethod.Ldap :
            method == "kubernetes" ? IdentityTemplateAuthMethod.Kubernetes : IdentityTemplateAuthMethod.Oidc;
        using var request = IdentityTemplateOperations.ListIdentityTemplates(Org, auth);
        var row = Row();
        row["authMethod"] = method;
        row["templateFields"] = method switch
        {
            "ldap" => new { hasBindPass = false },
            "kubernetes" => (object)new { hasTokenReviewerJwt = false },
            _ => new { oidcDiscoveryUrl = "https://id.test", boundIssuer = "issuer" }
        };
        var wire = new Wire("GET", BasePath + "?authMethod=" + method, JsonSerializer.Serialize(new[] { row }));
        var result = await Execute(request, wire, secondary: method);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items.Single().AuthMethod).IsEqualTo(auth);
        row["templateFields"] = new { };
        var invalid = await Execute(request, new Wire("GET", BasePath + "?authMethod=" + method,
            JsonSerializer.Serialize(new[] { row })), secondary: method);
        await Assert.That(invalid.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("foreign")]
    [Arguments("method")]
    [Arguments("oversize")]
    public async Task ListNeverPublishesForeignOrUnboundedRows(string defect)
    {
        var row = Row();
        if (defect == "foreign") row["orgId"] = OtherOrg;
        if (defect == "method")
        {
            row["authMethod"] = "ldap";
            row["templateFields"] = new { hasBindPass = false };
        }
        using var request = IdentityTemplateOperations.ListIdentityTemplates(Org, IdentityTemplateAuthMethod.Oidc);
        var result = await Execute(request, Fixture("list",
            JsonSerializer.Serialize(Enumerable.Repeat(row, defect == "oversize" ? 1001 : 1))), secondary: "oidc");
        await Assert.That(result.Status).IsEqualTo(defect == "oversize" ? SecretStatus.Unknown : SecretStatus.Invalid);
    }

    [Test]
    [Arguments("missing")]
    [Arguments("negative")]
    [Arguments("small")]
    [Arguments("too-many")]
    [Arguments("stalled")]
    public async Task SearchRejectsInvalidPageEvidence(string defect)
    {
        string response = defect == "missing" ? """{"templates":[]}""" :
            JsonSerializer.Serialize(new
            {
                templates = Enumerable.Repeat(Row(), defect == "too-many" ? 6 : defect == "stalled" ? 0 : 1),
                totalCount = defect == "negative" ? -1 : defect == "small" ? 0 : 10
            });
        using var request = IdentityTemplateOperations.SearchIdentityTemplates(Org, "private?name");
        var result = await Execute(request, Fixture("search", response), secondary: "private?name");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("foreign")]
    [Arguments("missing-auth")]
    [Arguments("missing-name")]
    [Arguments("duplicate")]
    public async Task DeleteUsageValidatesSelectedIdentitiesAndRequiredRows(string defect)
    {
        string row = defect switch
        {
            "foreign" => """{"identityId":"other","identityName":"private","authId":"auth"}""",
            "missing-auth" => JsonSerializer.Serialize(new { identityId = Identity, identityName = "private" }),
            "missing-name" => JsonSerializer.Serialize(new { identityId = Identity, authId = "auth" }),
            _ => UsageRow()
        };
        using var request = Usage(true);
        var result = await Execute(request, Fixture("delete-usage", "[" + row +
            (defect == "duplicate" ? "," + row : "") + "]"), secondary: Identity);
        await Assert.That(result.Status).IsEqualTo(defect is "foreign" or "duplicate" ? SecretStatus.Invalid : SecretStatus.Unknown);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task UsageDeletionRequiresReceiptAndNeverReplaysCommittedState(bool drop)
    {
        var wire = new StatefulWire(drop);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = Usage(true);
        var grant = authority.IssueGrant(request.OperationId, ApprovedTarget("delete-usage"));
        var noReceipt = await client.ExecuteAsync(request, authority, grant);
        await Assert.That(noReceipt.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Linked).IsTrue();
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(result.Status).IsEqualTo(drop ? SecretStatus.Unknown : SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(drop ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied);
        var replay = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        using var usage = Usage(false);
        var observed = await client.ExecuteAsync(usage, authority,
            authority.IssueGrant(usage.OperationId, new(Org, resourceId: Template)));
        await Assert.That(observed.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(observed.Value.Items.Count).IsEqualTo(0);
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task UsageMutationCancellationRetainsExactDispatchEvidence(bool before)
    {
        var wire = Fixture("delete-usage");
        wire.Hold = !before;
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        using var request = Usage(true);
        var receipt = client.CreateReceipt(request);
        using var cancel = new CancellationTokenSource();
        if (before) cancel.Cancel();
        var pending = client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, ApprovedTarget("delete-usage")),
            receipt, cancel.Token).AsTask();
        if (!before)
        {
            await wire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
        }
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(before ? DispatchEvidence.NotDispatched : DispatchEvidence.PossiblyDispatched);
        await Assert.That(tokens.Acquired).IsEqualTo(!before);
    }

    [Test]
    public async Task TypedInputBudgetsAndFormattingProtectCoordinates()
    {
        await Assert.That(() => IdentityTemplateOperations.CreateIdentityTemplate(Org, new string('x', 65),
            new("https://id.test", "issuer"))).Throws<ArgumentException>();
        await Assert.That(() => new IdentityTemplateOidcFields("not-uri", "issuer")).Throws<ArgumentException>();
        await Assert.That(() => new IdentityTemplateOidcFields("https://id.test", new string('x', 2049))).Throws<ArgumentException>();
        await Assert.That(() => IdentityTemplateOperations.UpdateIdentityTemplate(Org, Template, "")).Throws<ArgumentException>();
        await Assert.That(() => IdentityTemplateOperations.SearchIdentityTemplates(Org, limit: 101)).Throws<ArgumentException>();
        await Assert.That(() => IdentityTemplateOperations.DeleteIdentityTemplateUsage(Org, Template, "")).Throws<ArgumentException>();
        await Assert.That(() => IdentityTemplateOperations.ListIdentityTemplates(Org, (IdentityTemplateAuthMethod)99))
            .Throws<ArgumentOutOfRangeException>();
        var fields = new IdentityTemplateOidcFields("https://id.test", "private-issuer");
        await Assert.That(JsonSerializer.Serialize(fields)).IsEqualTo("{}");
        await Assert.That(fields.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
        using var request = Single("create");
        await Assert.That(JsonSerializer.Serialize(request).Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(request.Target)).IsEqualTo("{}");
    }

    [Test]
    [Arguments("create", "orgId")]
    [Arguments("create", "name")]
    [Arguments("create", "authMethod")]
    [Arguments("update", "orgId")]
    [Arguments("update", "name")]
    [Arguments("update", "id")]
    public async Task MutationResponseMismatchCannotBeRecordedApplied(string operation, string field)
    {
        var row = Row();
        row[field] = field == "authMethod" ? "ldap" : field == "orgId" ? OtherOrg :
            field == "id" ? Identity : "other";
        var wire = Fixture(operation, JsonSerializer.Serialize(row));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = Single(operation);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            ApprovedTarget(operation)), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    [Arguments("create")]
    [Arguments("update")]
    [Arguments("delete")]
    public async Task EveryTemplateMutationRequiresItsOwnSingleUseReceipt(string operation)
    {
        var wire = Fixture(operation);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        if (operation == "delete")
        {
            using var request = IdentityTemplateOperations.DeleteIdentityTemplate(Org, Template);
            var grant = authority.IssueGrant(request.OperationId, new(Org, resourceId: Template));
            var absent = await client.ExecuteAsync(request, authority, grant);
            await Assert.That(absent.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(tokens.Acquired).IsFalse();
            var receipt = client.CreateReceipt(request);
            var success = await client.ExecuteAsync(request, authority, grant, receipt);
            await Assert.That(success.Status).IsEqualTo(SecretStatus.Success);
            var replay = await client.ExecuteAsync(request, authority, grant, receipt);
            await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        }
        else
        {
            using var request = Single(operation);
            var grant = authority.IssueGrant(request.OperationId,
                ApprovedTarget(operation));
            using var other = Single(operation);
            var wrong = await client.ExecuteAsync(request, authority, grant, client.CreateReceipt(other));
            await Assert.That(wrong.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(tokens.Acquired).IsFalse();
            var receipt = client.CreateReceipt(request);
            var success = await client.ExecuteAsync(request, authority, grant, receipt);
            await Assert.That(success.Status).IsEqualTo(SecretStatus.Success);
            var replay = await client.ExecuteAsync(request, authority, grant, receipt);
            await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        }
    }

    [Test]
    [Arguments("organization")]
    [Arguments("template")]
    public async Task ReadTemplateAndUsageRejectIndependentTargetsBeforeTokens(string mismatch)
    {
        foreach (bool usage in new[] { false, true })
        {
            var wire = Fixture(usage ? "usage" : "get");
            using var transport = Transport(wire);
            var client = new ManagementClient(transport);
            var tokens = new Tokens();
            var authority = new ManagementAuthority(client.Authority, tokens, Org);
            var issuer = mismatch == "organization" ? new ManagementAuthority(client.Authority, tokens, OtherOrg) : authority;
            var target = new ManagementTarget(mismatch == "organization" ? OtherOrg : Org,
                resourceId: mismatch == "template" ? "other" : Template);
            if (usage)
            {
                using var request = Usage(false);
                var result = await client.ExecuteAsync(request, authority, issuer.IssueGrant(request.OperationId, target));
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
            }
            else
            {
                using var request = Single("get");
                var result = await client.ExecuteAsync(request, authority, issuer.IssueGrant(request.OperationId, target));
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
            }
            await Assert.That(tokens.Acquired).IsFalse();
            await Assert.That(wire.Observed).IsFalse();
        }
    }

    [Test]
    public async Task EscapedTemplateCoordinateCannotChangeUsageRoute()
    {
        const string template = "template/with?query#fragment";
        using var request = IdentityTemplateOperations.GetIdentityTemplateUsage(Org, template);
        var wire = new Wire("GET", BasePath + "/" + Uri.EscapeDataString(template) + "/usage", "[]");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(Org, resourceId: template)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(wire.Observed).IsTrue();
    }

    [Test]
    public async Task EmptySearchBeyondTotalIsCompleteWithoutInventedContinuation()
    {
        using var request = IdentityTemplateOperations.SearchIdentityTemplates(Org, offset: 10);
        var result = await Execute(request, new Wire("GET", BasePath + "/search?offset=10&limit=5",
            """{"templates":[],"totalCount":2}"""), offset: 10);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.IsComplete).IsTrue();
        await Assert.That(result.Value.NextOffset is null).IsTrue();
    }

    [Test]
    [Arguments("usage", 1001)]
    [Arguments("usage", 1000)]
    [Arguments("list", 0)]
    public async Task UnpaginatedCollectionsAreBoundedAndNeverTruncated(string operation, int count)
    {
        string row = operation == "usage" ? UsageRow(false) : JsonSerializer.Serialize(Row());
        using var request = Usage(false);
        if (operation == "usage")
        {
            var result = await Execute(request, Fixture(operation, "[" + string.Join(",", Enumerable.Repeat(row, count)) + "]"));
            await Assert.That(result.Status).IsEqualTo(count > 1000 ? SecretStatus.Unknown : SecretStatus.Success);
            if (result.IsSuccess) await Assert.That(result.Value.Items.Count).IsEqualTo(count);
        }
        else
        {
            using var list = IdentityTemplateOperations.ListIdentityTemplates(Org, IdentityTemplateAuthMethod.Oidc);
            var result = await Execute(list, Fixture("list", "[]"), secondary: "oidc");
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(result.Value.Items.Count).IsEqualTo(0);
        }
    }

    [Test]
    public async Task DeleteRequiresNativeAcknowledgementWithoutPublishingProviderMessage()
    {
        using var request = IdentityTemplateOperations.DeleteIdentityTemplate(Org, Template);
        var result = await Execute(request, Fixture("delete", "{}"));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    private static async Task Protected(IdentityTemplateSummary summary)
    {
        await Assert.That(summary.Id).IsEqualTo(Template);
        await Assert.That(summary.OrganizationId).IsEqualTo(Org);
        await Assert.That(summary.Name).IsEqualTo("private-template");
        await Assert.That(summary.IncludesConfiguration).IsTrue();
        await Assert.That(JsonSerializer.Serialize(summary)).IsEqualTo("""{"IncludesConfiguration":true}""");
        await Assert.That(summary.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
    }

    private static ManagementRequest<IdentityTemplateSummary> Single(string operation) => operation switch
    {
        "create" => IdentityTemplateOperations.CreateIdentityTemplate(Org, "private-template",
            new("https://id.test/.well-known/openid-configuration", "private-issuer")),
        "update" => IdentityTemplateOperations.UpdateIdentityTemplate(Org, Template, "private-template"),
        _ => IdentityTemplateOperations.GetIdentityTemplate(Org, Template)
    };

    private static ManagementRequest<ManagementPage<IdentityTemplateUsage>> Usage(bool delete) => delete
        ? IdentityTemplateOperations.DeleteIdentityTemplateUsage(Org, Template, Identity)
        : IdentityTemplateOperations.GetIdentityTemplateUsage(Org, Template);

    private static ManagementTarget ApprovedTarget(string operation) => operation switch
    {
        "create" => IdentityTemplateOperations.IdentityTemplateCreateTarget(Org, "private-template",
            new IdentityTemplateOidcFields("https://id.test/.well-known/openid-configuration", "private-issuer")),
        "update" => IdentityTemplateOperations.IdentityTemplateUpdateTarget(Org, Template, "private-template"),
        _ => IdentityTemplateOperations.IdentityTemplateUnlinkTarget(Org, Template, [Identity])
    };

    private static Dictionary<string, object?> Row() => new()
    {
        ["id"] = Template,
        ["orgId"] = Org,
        ["name"] = "private-template",
        ["authMethod"] = "oidc",
        ["createdAt"] = "2026-01-01T00:00:00Z",
        ["updatedAt"] = "2026-01-02T00:00:00Z",
        ["templateFields"] = new { oidcDiscoveryUrl = "https://id.test", boundIssuer = "private-issuer" }
    };

    private static string UsageRow(bool delete = true) => delete
        ? JsonSerializer.Serialize(new { identityId = Identity, identityName = "private-identity", authId = "auth" })
        : JsonSerializer.Serialize(new { identityId = Identity, identityName = "private-identity" });

    private static Wire Fixture(string operation, string? response = null) => operation switch
    {
        "list" => new("GET", BasePath + "?authMethod=oidc", response ?? "[" + JsonSerializer.Serialize(Row()) + "]"),
        "search" => new("GET", BasePath + "/search?offset=0&limit=5&search=private%3Fname",
            response ?? JsonSerializer.Serialize(new { templates = new[] { Row() }, totalCount = 2 })),
        "create" => new("POST", BasePath, response ?? JsonSerializer.Serialize(Row())),
        "update" => new("PATCH", BasePath + "/" + Template, response ?? JsonSerializer.Serialize(Row())),
        "delete" => new("DELETE", BasePath + "/" + Template, response ?? """{"message":"private-message"}"""),
        "usage" => new("GET", BasePath + "/" + Template + "/usage", response ?? "[" + UsageRow(false) + "]"),
        "delete-usage" => new("POST", BasePath + "/" + Template + "/delete-usage", response ?? "[" + UsageRow() + "]"),
        _ => new("GET", BasePath + "/" + Template, response ?? JsonSerializer.Serialize(Row()))
    };

    private static async Task<SecretOutcome<T>> Execute<T>(ManagementRequest<T> request, Wire wire,
        string? secondary = null, int offset = 0) where T : notnull
    {
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var target = new ManagementTarget(Org,
            resourceId: request.OperationId.EndsWith(".search", StringComparison.Ordinal) ||
                request.OperationId == "infisical.get.v1.identity.templates" ? null : Template,
            secondaryId: secondary);
        if (request.IsMutation)
            target = request.OperationId.Contains("delete.usage", StringComparison.Ordinal) ? ApprovedTarget("delete-usage") :
                request.OperationId.StartsWith("infisical.patch", StringComparison.Ordinal) ? ApprovedTarget("update") : target;
        if (request.OperationId == "infisical.get.v1.identity.templates.search")
            target = IdentityTemplateOperations.IdentityTemplateSearchTarget(Org, secondary, offset);
        return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target),
            request.IsMutation ? client.CreateReceipt(request) : null);
    }

    private static ManagementTransport Transport(HttpMessageHandler handler) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, handler);

    private sealed class Wire(string method, string path, string response) : HttpMessageHandler
    {
        public string Method => method;
        public bool Observed { get; private set; }
        public string? Body { get; private set; }
        public bool Hold { get; set; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method.Method != method || request.RequestUri!.PathAndQuery != path ||
                request.Headers.Authorization?.Scheme != "Bearer") return new(HttpStatusCode.NotFound);
            Observed = true;
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            Entered.TrySetResult();
            if (Hold) await _release.Task.WaitAsync(cancellationToken);
            return new(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
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

    private sealed class StatefulWire(bool drop) : HttpMessageHandler
    {
        public bool Linked { get; private set; } = true;
        public int Revision { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Headers.Authorization?.Scheme != "Bearer") return new(HttpStatusCode.Unauthorized);
            string response;
            if (request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath == BasePath + "/" + Template + "/delete-usage")
            {
                using JsonDocument body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
                if (body.RootElement.GetProperty("identityIds").GetArrayLength() != 1 ||
                    body.RootElement.GetProperty("identityIds")[0].GetString() != Identity || !Linked)
                    return new(HttpStatusCode.BadRequest);
                Linked = false;
                Revision++;
                if (drop) throw new HttpRequestException("Protected response lost.");
                response = "[" + UsageRow() + "]";
            }
            else if (request.Method == HttpMethod.Get && request.RequestUri!.AbsolutePath == BasePath + "/" + Template + "/usage")
                response = Linked ? "[" + UsageRow(false) + "]" : "[]";
            else return new(HttpStatusCode.NotFound);
            return new(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }
}
