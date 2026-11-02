using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalIdentityTemplateEffectTests
{
    [Test]
    public async Task LdapAllValidCreationVariantsConsumeTheirProtectedCredential()
    {
        string operation = "i.management.IdentityTemplateOperations.CreateLdapIdentityTemplate";
        foreach (string variant in InfisicalIdentityFamilies.Bindings[operation].Variants.Where(v =>
            v is not ("IdentityTemplateLdapFields.url.omitted" or "IdentityTemplateLdapFields.bindDn.omitted" or
                "IdentityTemplateLdapFields.bindPassword.omitted" or "IdentityTemplateLdapFields.searchBase.omitted")))
            foreach (string caseName in new[] { "selected-contract", "independent-effect", "denied-authority",
                "cancellation-boundary", "lost-response-no-replay" })
            {
                await using var fixture = new LdapIdentityFixture("good");
                var result = await fixture.RunAsync("CreateLdapIdentityTemplate", variant, caseName);
                if (!result.Passed)
                    throw new InvalidOperationException(variant + "/" + caseName + "/" + result.ReasonCode);
                await Assert.That(fixture.Source.Opened && fixture.Source.Closed).IsTrue();
                await Assert.That(fixture.ResidualCount).IsEqualTo(0);
                if (caseName is "selected-contract" or "independent-effect" or "lost-response-no-replay")
                    await Assert.That(fixture.Source.SuccessfulIdentityCount).IsEqualTo(2);
            }
    }

    [Test]
    [Arguments("CreateLdapIdentityTemplate", "IdentityTemplateLdapFields.bindPassword.value", "independent-effect")]
    [Arguments("UpdateIdentityTemplateConfiguration", "IdentityTemplateLdapFields.bindPassword.value", "independent-effect")]
    [Arguments("UpdateIdentityTemplateConfiguration", "fields.Ldap", "independent-effect")]
    [Arguments("UpdateIdentityTemplateConfiguration", "IdentityTemplateLdapFields.bindPassword.omitted", "independent-effect")]
    [Arguments("UpdateIdentityTemplateConfiguration", "IdentityTemplateLdapFields.bindPassword.value", "denied-authority")]
    [Arguments("UpdateIdentityTemplateConfiguration", "IdentityTemplateLdapFields.bindPassword.value", "cancellation-boundary")]
    [Arguments("UpdateIdentityTemplateConfiguration", "IdentityTemplateLdapFields.bindPassword.value", "lost-response-no-replay")]
    public async Task LdapPasswordsRequireIndependentBindLoginAndConsumerEvidence(string operation, string variant, string caseName)
    {
        await using var fixture = new LdapIdentityFixture("good");
        var result = await fixture.RunAsync(operation, variant, caseName);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(fixture.Source.Opened && fixture.Source.Closed).IsTrue();
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
        await Assert.That(fixture.SelectedMutations).IsEqualTo(
            caseName is "denied-authority" or "cancellation-boundary" ? 0 : 1);
        if (caseName == "independent-effect")
        {
            await Assert.That(fixture.Source.SuccessfulIdentityCount >= 2).IsTrue();
            await Assert.That(fixture.AllowedReads >= 2 && fixture.DeniedReads >= 2).IsTrue();
        }
    }

    [Test]
    [Arguments("ignored-password")]
    [Arguments("omission-overwrites")]
    [Arguments("linked-consumer-stale")]
    [Arguments("fresh-consumer-wrong")]
    [Arguments("login-wronguser")]
    [Arguments("canary-bypass")]
    [Arguments("unsettled")]
    [Arguments("cleanup-failure")]
    [Arguments("lost-metadata-only")]
    [Arguments("same-authority-substitution")]
    public async Task LdapPasswordMarkerCannotHideBrokenAuthentication(string mode)
    {
        await using var fixture = new LdapIdentityFixture(mode);
        var result = await fixture.RunAsync("UpdateIdentityTemplateConfiguration",
            mode == "omission-overwrites" ? "IdentityTemplateLdapFields.bindPassword.omitted" :
                "IdentityTemplateLdapFields.bindPassword.value",
            mode == "lost-metadata-only" ? "lost-response-no-replay" : "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Source.Opened).IsTrue();
        await Assert.That(fixture.Source.TemplateArms > 0).IsTrue();
    }

    private const string Org = "00000000-0000-0000-0000-000000000001";
    private const string Date = "2026-10-13T00:00:00.000Z";

    [Test]
    public async Task CleanupRejectsNameMatchedReplacementWithoutDeletingIt()
    {
        await using var backend = new Backend("replacement");
        var result = await RunAsync(backend, "GetIdentityTemplate", "selector.exact");
        await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(backend.ForeignDeleted).IsFalse();
        await Assert.That(backend.TemplateCount).IsEqualTo(1);
    }

    [Test]
    [Arguments("IdentityTemplateOidcPatch.discoveryUrl.value")]
    [Arguments("IdentityTemplateOidcPatch.boundIssuer.value")]
    [Arguments("IdentityTemplateOidcPatch.boundAudiences.value")]
    [Arguments("IdentityTemplateOidcPatch.caCertificate.value")]
    [Arguments("fields.OidcFull")]
    [Arguments("IdentityTemplateLdapFields.url.value")]
    [Arguments("IdentityTemplateLdapFields.bindDn.value")]
    [Arguments("IdentityTemplateLdapFields.searchBase.value")]
    [Arguments("IdentityTemplateLdapFields.caCertificate.value")]
    [Arguments("IdentityTemplateKubernetesFields.kubernetesHost.value")]
    [Arguments("IdentityTemplateKubernetesFields.gatewayId.value")]
    [Arguments("IdentityTemplateKubernetesFields.gatewayPoolId.value")]
    [Arguments("IdentityTemplateKubernetesFields.allowedAudience.value")]
    [Arguments("IdentityTemplateKubernetesFields.caCertificate.value")]
    [Arguments("IdentityTemplateKubernetesFields.tokenReviewMode.Api")]
    [Arguments("IdentityTemplateKubernetesFields.tokenReviewMode.Gateway")]
    [Arguments("IdentityTemplateKubernetesFields.verifyTlsCertificate.false")]
    [Arguments("IdentityTemplateKubernetesFields.verifyTlsCertificate.true")]
    [Arguments("IdentityTemplateKubernetesFields.tokenReviewerJwt.value")]
    public async Task IgnoredConfigurationPatchCannotPass(string variant)
    {
        await using var backend = new Backend("ignore-patch");
        var result = await RunAsync(backend, "UpdateIdentityTemplateConfiguration", variant);
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
        await Assert.That(backend.TemplateCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("IdentityTemplateLdapFields.bindPassword.value")]
    [Arguments("fields.Ldap")]
    public async Task StoredPasswordMarkerCannotCertifyProtectedContents(string variant)
    {
        await using var backend = new Backend("good");
        var result = await RunAsync(backend, "UpdateIdentityTemplateConfiguration", variant);
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(backend.TemplateCount).IsEqualTo(0);
    }

    [Test]
    public async Task UnavailableReviewerContentsCannotBecomePositiveEvidence()
    {
        await using var backend = new Backend("hide-reviewer");
        var result = await RunAsync(backend, "UpdateIdentityTemplateConfiguration",
            "IdentityTemplateKubernetesFields.tokenReviewerJwt.value");
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(backend.TemplateCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("ListIdentityTemplates", "authMethod.Oidc", "duplicate")]
    [Arguments("ListIdentityTemplates", "authMethod.Oidc", "omit-peer")]
    [Arguments("ListIdentityTemplates", "authMethod.Oidc", "ignore-filter")]
    [Arguments("SearchIdentityTemplates", "search.value", "duplicate")]
    [Arguments("SearchIdentityTemplates", "search.value", "omit-peer")]
    [Arguments("SearchIdentityTemplates", "search.value", "ignore-filter")]
    [Arguments("SearchIdentityTemplates", "search.omitted", "omit-peer")]
    public async Task CollectionRequiresUniqueOwnedPositivesAndExclusion(string operation, string variant, string mode)
    {
        await using var backend = new Backend(mode);
        var result = await RunAsync(backend, operation, variant);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.TemplateCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("CreateIdentityTemplate", "IdentityTemplateOidcFields.boundAudiences.value", "independent-effect")]
    [Arguments("CreateIdentityTemplate", "IdentityTemplateOidcFields.boundAudiences.value", "lost-response-no-replay")]
    [Arguments("CreateIdentityTemplate", "IdentityTemplateOidcFields.boundAudiences.value", "cancellation-boundary")]
    [Arguments("CreateIdentityTemplate", "IdentityTemplateOidcFields.boundAudiences.value", "denied-authority")]
    [Arguments("UpdateIdentityTemplateConfiguration", "fields.OidcFull", "independent-effect")]
    [Arguments("UpdateIdentityTemplateConfiguration", "fields.OidcFull", "lost-response-no-replay")]
    [Arguments("UpdateIdentityTemplateConfiguration", "fields.OidcFull", "cancellation-boundary")]
    [Arguments("UpdateIdentityTemplateConfiguration", "fields.OidcFull", "denied-authority")]
    [Arguments("UpdateIdentityTemplateConfiguration", "fields.Kubernetes", "independent-effect")]
    [Arguments("UpdateIdentityTemplateConfiguration", "IdentityTemplateKubernetesFields.tokenReviewerJwt.value", "independent-effect")]
    [Arguments("UpdateIdentityTemplateConfiguration", "IdentityTemplateKubernetesFields.tokenReviewMode.Api", "independent-effect")]
    [Arguments("UpdateIdentityTemplateConfiguration", "IdentityTemplateKubernetesFields.tokenReviewMode.Gateway", "independent-effect")]
    [Arguments("UpdateIdentityTemplateConfiguration", "IdentityTemplateKubernetesFields.verifyTlsCertificate.true", "independent-effect")]
    [Arguments("UpdateIdentityTemplateConfiguration", "IdentityTemplateKubernetesFields.verifyTlsCertificate.false", "independent-effect")]
    [Arguments("ListIdentityTemplates", "authMethod.Oidc", "independent-effect")]
    [Arguments("SearchIdentityTemplates", "search.value", "independent-effect")]
    [Arguments("SearchIdentityTemplates", "search.omitted", "independent-effect")]
    public async Task GoodEffectsRecoveryCancellationAndCleanupRemainObserved(string operation, string variant, string caseName)
    {
        await using var backend = new Backend("good");
        var result = await RunAsync(backend, operation, variant, caseName);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.TemplateCount).IsEqualTo(0);
        await Assert.That(backend.AdministrativeMutations).IsEqualTo(
            caseName is "cancellation-boundary" or "denied-authority" ? 0 :
            operation.StartsWith("Create", StringComparison.Ordinal) || operation.StartsWith("Update", StringComparison.Ordinal) ? 1 : 0);
    }

    private static async Task<NativeCaseResult> RunAsync(Backend backend, string operation, string variant,
        string caseName = "independent-effect")
    {
        string id = "i.management.IdentityTemplateOperations." + operation;
        var definition = new NativeCaseDefinition(new("Infisical", id, variant, "local", caseName),
            InfisicalIdentityFamilies.Bindings[id].Member);
        var input = new
        {
            organizationId = Org,
            identityRole = "member",
            oidcDiscoveryUrl = "https://issuer.invalid",
            baselineOidcDiscoveryUrl = "https://issuer.invalid/baseline",
            boundIssuer = "issuer",
            baselineBoundIssuer = "prior-issuer",
            boundAudiences = "audience",
            caCertificate = "ca",
            ldapUrl = "ldaps://ldap.invalid",
            baselineLdapUrl = "ldaps://ldap.invalid:636",
            bindDn = "cn=fixture",
            baselineBindDn = "cn=prior",
            bindPassword = "password",
            searchBase = "dc=fixture",
            baselineSearchBase = "dc=prior",
            ldapCaCertificate = "ldap-ca",
            kubernetesHost = "https://kubernetes.invalid",
            gatewayId = "00000000-0000-0000-0000-000000000005",
            gatewayPoolId = "00000000-0000-0000-0000-000000000006",
            tokenReviewerJwt = "reviewer",
            baselineTokenReviewMode = variant.EndsWith("tokenReviewMode.Gateway", StringComparison.Ordinal) ? "api" : "gateway",
            allowedAudience = "audience",
            allowedNames = "fixture",
            allowedNamespaces = "fixture",
            boundSubject = "subject"
        };
        using var environment = NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = backend.Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            administrative = "administrative",
            observer = "observer",
            runtime = "runtime",
            denied = "denied",
            families = new Dictionary<string, object>
            {
                ["C08-IM-" + InfisicalIdentityFamilies.Family(definition)] =
                    new { scopes = new Dictionary<string, object> { ["local"] = input } }
            }
        }));
        var registry = new NativeCaseRegistry();
        InfisicalIdentityFamilies.Register(registry, environment, [definition]);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }

    // Original offline state model of the public SDK's wire facts, not live admission evidence.
    private sealed class Backend : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly Dictionary<string, JsonObject> templates = [];
        private readonly Dictionary<string, JsonObject> identities = [];
        private readonly Dictionary<string, JsonObject> auth = [];
        private readonly Dictionary<string, string> reviewers = [];
        private readonly Task serving;
        private readonly string mode;
        private const string ForeignId = "00000000-0000-0000-0000-000000000099";
        internal Uri Origin { get; }
        internal bool ForeignDeleted { get; private set; }
        internal int AdministrativeMutations { get; private set; }
        internal int TemplateCount => templates.Count;

        internal Backend(string mode)
        {
            this.mode = mode;
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            serving = ServeAsync();
        }

        private async Task ServeAsync()
        {
            try
            {
                while (true)
                {
                    using var socket = await listener.AcceptTcpClientAsync(shutdown.Token);
                    var stream = socket.GetStream();
                    var header = new List<byte>();
                    byte[] next = new byte[1];
                    while (header.Count < 32768)
                    {
                        await stream.ReadExactlyAsync(next, shutdown.Token);
                        header.Add(next[0]);
                        if (header.Count >= 4 && header[^4] == 13 && header[^3] == 10 &&
                            header[^2] == 13 && header[^1] == 10) break;
                    }
                    string[] lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n");
                    string[] request = lines[0].Split(' ');
                    int length = int.Parse(lines.FirstOrDefault(l =>
                        l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?.Split(':')[1] ?? "0");
                    if (length is < 0 or > 65536) throw new InvalidOperationException("fixture-budget");
                    byte[] content = new byte[length];
                    await stream.ReadExactlyAsync(content, shutdown.Token);
                    var body = length == 0 ? new JsonObject() : JsonNode.Parse(content)!.AsObject();
                    string role = lines.Single(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))
                        .Split(' ')[^1];
                    string method = request[0];
                    if (role == "administrative" && method != "GET") AdministrativeMutations++;
                    (int status, JsonNode payload) = role == "denied" ? (403, new JsonObject())
                        : Handle(new Uri(Origin, request[1]), method, role, body);
                    byte[] bytes = Encoding.UTF8.GetBytes(payload.ToJsonString());
                    try
                    {
                        await stream.WriteAsync(Encoding.ASCII.GetBytes(
                            $"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                        await stream.WriteAsync(bytes, shutdown.Token);
                    }
                    catch (IOException) { }
                }
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        }

        private (int, JsonNode) Handle(Uri uri, string method, string role, JsonObject body)
        {
            string[] path = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (path[2] == "identity-templates")
            {
                if (method == "POST" && path.Length == 3)
                {
                    string id = Guid.NewGuid().ToString();
                    var fields = body["templateFields"]!.DeepClone().AsObject();
                    string kind = body["authMethod"]!.GetValue<string>();
                    if (kind == "ldap") { fields.Remove("bindPass"); fields["hasBindPass"] = true; }
                    if (kind == "kubernetes")
                    {
                        fields["hasTokenReviewerJwt"] = fields["tokenReviewerJwt"] is not null;
                        if (fields["tokenReviewerJwt"] is not null)
                            reviewers[id] = fields["tokenReviewerJwt"]!.GetValue<string>();
                        fields.Remove("tokenReviewerJwt");
                    }
                    templates[id] = new()
                    {
                        ["id"] = id,
                        ["orgId"] = Org,
                        ["name"] = body["name"]!.DeepClone(),
                        ["authMethod"] = kind,
                        ["templateFields"] = fields,
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date
                    };
                    return (200, templates[id].DeepClone());
                }
                if (path.Length == 3 || path[^1] == "search")
                {
                    bool corrupt = role == "administrative";
                    string? filter = uri.Query.Contains("authMethod=", StringComparison.Ordinal)
                        ? uri.Query.Split("authMethod=")[1].Split('&')[0] : null;
                    string? search = uri.Query.Contains("search=", StringComparison.Ordinal)
                        ? Uri.UnescapeDataString(uri.Query.Split("search=")[1].Split('&')[0]) : null;
                    var rows = templates.Values.Where(t => corrupt && mode == "ignore-filter" ||
                        (filter is null || t["authMethod"]!.GetValue<string>() == filter) &&
                        (search is null || t["name"]!.GetValue<string>().Contains(search, StringComparison.Ordinal)))
                        .Select(t => t.DeepClone()).ToList();
                    if (mode == "replacement")
                        foreach (var row in rows) row["id"] = ForeignId;
                    if (corrupt && mode == "duplicate" && rows.Count > 0) rows.Add(rows[0].DeepClone());
                    if (corrupt && mode == "omit-peer" && rows.Count > 1) rows.RemoveAt(1);
                    return (200, path.Length == 3 ? new JsonArray(rows.ToArray())
                        : new JsonObject { ["templates"] = new JsonArray(rows.ToArray()), ["totalCount"] = rows.Count });
                }
                string selected = path[3];
                if (path[^1] == "usage") return (200, new JsonArray());
                if (method == "DELETE" && selected == ForeignId)
                {
                    ForeignDeleted = true;
                    templates.Clear();
                    return (200, new JsonObject { ["message"] = "deleted" });
                }
                if (!templates.TryGetValue(selected, out var template)) return (404, new JsonObject());
                if (method == "PATCH")
                {
                    if (body["name"] is not null) template["name"] = body["name"]!.DeepClone();
                    if (mode != "ignore-patch" && body["templateFields"] is JsonObject fields)
                        foreach (var pair in fields)
                        {
                            if (pair.Key == "tokenReviewerJwt")
                            {
                                reviewers[selected] = pair.Value!.GetValue<string>();
                                template["templateFields"]!["hasTokenReviewerJwt"] = reviewers[selected].Length != 0;
                            }
                            else if (pair.Key == "bindPass") template["templateFields"]!["hasBindPass"] = true;
                            else template["templateFields"]![pair.Key] = pair.Value?.DeepClone();
                        }
                }
                if (method == "DELETE")
                {
                    templates.Remove(selected);
                    return (200, new JsonObject { ["message"] = "deleted" });
                }
                return (200, template.DeepClone());
            }
            if (path[2] == "auth")
            {
                string identity = path[^1];
                bool kubernetes = path[3] == "kubernetes-auth";
                if (method == "POST")
                {
                    string template = body["templateId"]!.GetValue<string>();
                    var value = templates[template]["templateFields"]!.DeepClone().AsObject();
                    value["templateId"] = template;
                    value["identityId"] = identity;
                    value["id"] = Guid.NewGuid().ToString();
                    value["createdAt"] = Date;
                    value["updatedAt"] = Date;
                    value["boundAudiences"] ??= "";
                    value["caCert"] ??= "";
                    if (kubernetes)
                    {
                        value.Remove("hasTokenReviewerJwt");
                        value.Remove("boundAudiences");
                        value["allowedAudience"] ??= "";
                        value["allowedNames"] = body["allowedNames"]!.DeepClone();
                        value["allowedNamespaces"] = body["allowedNamespaces"]!.DeepClone();
                        if (mode != "hide-reviewer" && reviewers.TryGetValue(template, out string? reviewer))
                            value["tokenReviewerJwt"] = reviewer;
                    }
                    auth[identity] = value;
                }
                return (200, new JsonObject
                {
                    [kubernetes ? "identityKubernetesAuth" : "identityOidcAuth"] = auth[identity].DeepClone()
                });
            }
            if (path[2] == "identities")
            {
                if (method == "GET" && path.Length == 3)
                    return (200, new JsonObject
                    {
                        ["identities"] = new JsonArray(identities.Values.Select(i => (JsonNode)new JsonObject
                        {
                            ["id"] = i["id"]!.DeepClone(),
                            ["identityId"] = i["id"]!.DeepClone(),
                            ["orgId"] = Org,
                            ["role"] = "member",
                            ["createdAt"] = Date,
                            ["updatedAt"] = Date,
                            ["identity"] = new JsonObject
                            {
                                ["id"] = i["id"]!.DeepClone(),
                                ["name"] = i["name"]!.DeepClone(),
                                ["hasDeleteProtection"] = false,
                                ["authMethods"] = new JsonArray()
                            }
                        }).ToArray()),
                        ["totalCount"] = identities.Count
                    });
                string id = path.Length == 3 ? Guid.NewGuid().ToString() : path[^1];
                if (method == "POST")
                    identities[id] = new()
                    {
                        ["id"] = id,
                        ["orgId"] = Org,
                        ["name"] = body["name"]!.DeepClone(),
                        ["hasDeleteProtection"] = false,
                        ["authMethods"] = new JsonArray(),
                        ["metadata"] = new JsonArray(),
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date
                    };
                if (!identities.TryGetValue(id, out var identity)) return (404, new JsonObject());
                if (method == "DELETE") { identities.Remove(id); auth.Remove(id); }
                var returned = identity.DeepClone().AsObject();
                if (method is "PATCH" or "DELETE") returned.Remove("authMethods");
                if (method == "DELETE") returned.Remove("metadata");
                return (200, new JsonObject { ["identity"] = returned });
            }
            return (404, new JsonObject());
        }

        public async ValueTask DisposeAsync()
        {
            shutdown.Cancel();
            await serving;
            listener.Stop();
            shutdown.Dispose();
        }
    }
}
