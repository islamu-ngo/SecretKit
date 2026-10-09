using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class ReferenceBoundaryTests
{
    [Test]
    [Arguments(InfisicalValidationKind.StaticSecrets)]
    [Arguments(InfisicalValidationKind.DynamicSecrets)]
    [Arguments(InfisicalValidationKind.SecretRotations)]
    public async Task TypedPolicyLifecycleRetainsProviderConstraintsAndCurrentRoutes(InfisicalValidationKind kind)
    {
        var backend = new ValidationBackend(kind);
        await using InfisicalClient client = Phase5TestSupport.Client(backend);
        InfisicalNativeAuthority admin = Phase5TestSupport.Admin(client);
        var create = new SecretReference(client.Authority, new InfisicalValidationAddress("project", kind, environment: "dev", secretPath: "/"));
        var constraints = new InfisicalTextConstraints(8, 64, "^[a-z]+$", "protected-prefix", "protected-suffix");
        var input = kind == InfisicalValidationKind.StaticSecrets
            ? new InfisicalValidationInput("rule", keyConstraints: new(1, 64),
                valueConstraints: new(8, 64, uniqueAcrossLastVersions: 3, uniqueWithinScope: true))
            : new InfisicalValidationInput("rule", passwordConstraints: constraints,
                providers: [kind == InfisicalValidationKind.DynamicSecrets ? InfisicalValidationProvider.SqlDatabase : InfisicalValidationProvider.PostgresCredentials]);
        var receipt = new MutationReceipt(create);
        InfisicalValidationRule rule = (await client.CreateValidationRuleAsync(create, input, admin, receipt)).Value;
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(rule.Kind).IsEqualTo(kind);
        var byId = new SecretReference(client.Authority, new InfisicalValidationAddress("project", kind, rule.Id, "dev", "/"));
        await Assert.That((await client.GetValidationRuleAsync(byId)).Value.Name).IsEqualTo("rule");
        var list = new SecretReference(client.Authority, new InfisicalValidationAddress("project", kind));
        await Assert.That((await client.ListValidationRulesAsync(list)).Value.Items.Single().Id).IsEqualTo(rule.Id);
        var patch = new InfisicalValidationInput(name: "renamed-rule", clearDescription: true, clearEnvironment: true);
        await Assert.That((await client.UpdateValidationRuleAsync(byId, patch, admin, new(byId))).Value.Name).IsEqualTo("renamed-rule");
        InfisicalValidationRule fresh = (await client.ListValidationRulesAsync(list)).Value.Items.Single();
        await Assert.That(fresh.Environment is null).IsTrue();
        await Assert.That(kind == InfisicalValidationKind.StaticSecrets ? fresh.ValueConstraints!.UniqueAcrossLastVersions == 3 :
            fresh.PasswordConstraints!.RegexPattern == "^[a-z]+$").IsTrue();
        await Assert.That(JsonSerializer.Serialize(fresh).Contains("protected-prefix", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(input).Contains("rule", StringComparison.Ordinal)).IsFalse();
        var cleared = new SecretReference(client.Authority, new InfisicalValidationAddress("project", kind, rule.Id));
        await Assert.That((await client.DeleteValidationRuleAsync(cleared, admin, new(cleared))).Value.Id).IsEqualTo(rule.Id);
        await Assert.That((await client.ListValidationRulesAsync(list)).Value.Items.Count).IsEqualTo(0);
    }

    [Test]
    public async Task OfficialAggregateUnionRetainsAllThreeKindsWithBoundedResults()
    {
        var backend = new ValidationBackend(InfisicalValidationKind.StaticSecrets) { Aggregate = true };
        await using InfisicalClient client = Phase5TestSupport.Client(backend);
        var list = new SecretReference(client.Authority, new InfisicalValidationAddress("project", InfisicalValidationKind.StaticSecrets));
        InfisicalNativeList<InfisicalValidationRule> full = (await client.ListValidationRulesAsync(list, allKinds: true)).Value;
        await Assert.That(full.Items.Select(item => item.Kind).Distinct().Count()).IsEqualTo(3);
        await Assert.That(full.IsComplete).IsTrue();
        InfisicalNativeList<InfisicalValidationRule> bounded = (await client.ListValidationRulesAsync(list, 1, allKinds: true)).Value;
        await Assert.That(bounded.Items.Count).IsEqualTo(1);
        await Assert.That(bounded.IsComplete).IsFalse();
    }

    [Test]
    public async Task InvalidPolicyBoundsProvidersAndAuthorityFailBeforeCredentials()
    {
        await using InfisicalClient client = Phase5TestSupport.Client(new ValidationBackend(InfisicalValidationKind.DynamicSecrets));
        var target = new SecretReference(client.Authority, new InfisicalValidationAddress("project", InfisicalValidationKind.DynamicSecrets, environment: "dev", secretPath: "/"));
        var receipt = new MutationReceipt(target);
        var forbidden = new Phase5TestSupport.Tokens("admin", true);
        var authority = new InfisicalNativeAuthority(client.Authority, forbidden, "project");
        var oversized = new InfisicalValidationInput("rule", passwordConstraints: new(2049),
            providers: [InfisicalValidationProvider.SqlDatabase]);
        await Assert.That((await client.CreateValidationRuleAsync(target, oversized, authority, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        var wrongProvider = new InfisicalValidationInput("rule", passwordConstraints: new(8),
            providers: [InfisicalValidationProvider.PostgresCredentials]);
        await Assert.That((await client.CreateValidationRuleAsync(target, wrongProvider, authority, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        var valid = new InfisicalValidationInput("rule", passwordConstraints: new(8), providers: [InfisicalValidationProvider.SqlDatabase]);
        var wrongProject = new InfisicalNativeAuthority(client.Authority, forbidden, "other-project");
        await Assert.That((await client.CreateValidationRuleAsync(target, valid, wrongProject, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        var folderOnly = new InfisicalNativeAuthority(client.Authority, forbidden, "project", "dev", "/other");
        await Assert.That((await client.CreateValidationRuleAsync(target, valid, folderOnly, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    public async Task PolicyResponseWithWrongProjectCannotBeAppliedOrLeakPayload()
    {
        var backend = new ValidationBackend(InfisicalValidationKind.StaticSecrets) { WrongProject = true };
        await using InfisicalClient client = Phase5TestSupport.Client(backend);
        var target = new SecretReference(client.Authority, new InfisicalValidationAddress("project", InfisicalValidationKind.StaticSecrets, environment: "dev", secretPath: "/"));
        var receipt = new MutationReceipt(target);
        var result = await client.CreateValidationRuleAsync(target, new("protected-policy-name"),
            Phase5TestSupport.Admin(client), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(JsonSerializer.Serialize(result).Contains("protected-policy-name", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task PatchNullAndAbsentConstraintsHaveDifferentEffects()
    {
        var backend = new ValidationBackend(InfisicalValidationKind.StaticSecrets);
        await using InfisicalClient client = Phase5TestSupport.Client(backend);
        var target = new SecretReference(client.Authority, new InfisicalValidationAddress("project", InfisicalValidationKind.StaticSecrets, environment: "dev", secretPath: "/"));
        InfisicalNativeAuthority admin = Phase5TestSupport.Admin(client);
        string id = (await client.CreateValidationRuleAsync(target, new("rule", keyConstraints: new(8), valueConstraints: new(10)),
            admin, new(target))).Value.Id;
        var byId = new SecretReference(client.Authority, new InfisicalValidationAddress("project", InfisicalValidationKind.StaticSecrets, id));
        InfisicalValidationRule renamed = (await client.UpdateValidationRuleAsync(byId, new(name: "renamed"), admin, new(byId))).Value;
        await Assert.That(renamed.KeyConstraints!.MinimumLength).IsEqualTo(8);
        InfisicalValidationRule cleared = (await client.UpdateValidationRuleAsync(byId, new(clearKeyConstraints: true), admin, new(byId))).Value;
        await Assert.That(cleared.KeyConstraints is null).IsTrue();
        await Assert.That(cleared.ValueConstraints!.MinimumLength).IsEqualTo(10);
    }

    [Test]
    public async Task ReferenceExpansionAndImportPrecedenceRemainProviderOwned()
    {
        var backend = new ReferenceBackend();
        await using InfisicalClient client = Phase5TestSupport.Client(backend);
        var raw = new SecretReference(client.Authority, new InfisicalSecretAddress("project", "dev", "/", "key"));
        using SecretRead literal = (await client.ReadAsync(raw)).Value;
        await Assert.That(literal.Material.Reveal()).IsEqualTo("${source.shared.KEY}");
        var expanded = new SecretReference(client.Authority, new InfisicalSecretAddress("project", "dev", "/", "key",
            resolution: InfisicalResolution.ExpandedReferences, includeImports: true));
        using SecretRead local = (await client.ReadAsync(expanded)).Value;
        await Assert.That(local.Material.Reveal()).IsEqualTo("local-wins");
        backend.Local = null;
        using SecretRead imported = (await client.ReadAsync(expanded)).Value;
        await Assert.That(imported.Material.Reveal()).IsEqualTo("bottom-import-wins");
        backend.Denied = true;
        await Assert.That((await client.ReadAsync(expanded)).Status).IsEqualTo(SecretStatus.Denied);
    }

    private sealed class ReferenceBackend : HttpMessageHandler
    {
        public string? Local { get; set; } = "local-wins";
        public bool Denied { get; set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath != "/api/v4/secrets/key")
            {
                throw new InvalidOperationException("The SDK must not recursively acquire source references.");
            }
            if (Denied) { return Task.FromResult(Phase5TestSupport.Json(403, new { })); }
            bool expanded = request.RequestUri.Query.Contains("expandSecretReferences=true", StringComparison.Ordinal);
            bool imports = request.RequestUri.Query.Contains("includeImports=true", StringComparison.Ordinal);
            string value = !expanded ? "${source.shared.KEY}" : imports ? Local ?? "bottom-import-wins" : "source-value";
            return Task.FromResult(Phase5TestSupport.Json(200, new
            {
                secret = new { secretKey = "key", secretValue = value, secretValueHidden = false, version = 1 }
            }));
        }
    }

    private sealed class ValidationBackend(InfisicalValidationKind kind) : HttpMessageHandler
    {
        private Dictionary<string, object?>? _rule;
        public bool Aggregate { get; init; }
        public bool WrongProject { get; init; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = request.RequestUri!.AbsolutePath;
            string wireKind = kind switch
            {
                InfisicalValidationKind.StaticSecrets => "static-secrets",
                InfisicalValidationKind.DynamicSecrets => "dynamic-secrets",
                _ => "secret-rotations"
            };
            if (request.Method != HttpMethod.Get && request.Headers.Authorization?.Parameter != "admin")
            {
                return Phase5TestSupport.Json(403, new { });
            }
            if (Aggregate && path == "/api/v1/secret-validation-rules")
            {
                return Phase5TestSupport.Json(200, new
                {
                    secretValidationRules = new[] { Rule("static-secrets"), Rule("dynamic-secrets"), Rule("secret-rotations") }
                });
            }
            if (!path.StartsWith("/api/v1/secret-validation-rules/" + wireKind, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Unexpected policy route.");
            }
            using JsonDocument? body = request.Content is null ? null : JsonDocument.Parse(await request.Content.ReadAsByteArrayAsync(cancellationToken));
            if (request.Method == HttpMethod.Post)
            {
                if (body!.RootElement.GetProperty("projectId").GetString() != "project" ||
                    body.RootElement.GetProperty("secretPath").GetString() != "/")
                {
                    return Phase5TestSupport.Json(400, new { });
                }
                _rule = Rule(wireKind);
            }
            if (body is not null && _rule is not null)
            {
                foreach (JsonProperty property in body.RootElement.EnumerateObject())
                {
                    if (property.Name == "environment")
                    {
                        _rule["environment"] = property.Value.ValueKind == JsonValueKind.Null ? null :
                            new { id = Phase5TestSupport.EnvironmentId, name = "Development", slug = property.Value.GetString() };
                    }
                    else if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        _rule.Remove(property.Name);
                    }
                    else { _rule[property.Name] = property.Value.Clone(); }
                }
            }
            if (request.Method == HttpMethod.Get && path.EndsWith("/" + wireKind, StringComparison.Ordinal))
            {
                if (!request.RequestUri.Query.Contains("projectId=project", StringComparison.Ordinal)) { return Phase5TestSupport.Json(400, new { }); }
                return Phase5TestSupport.Json(200, new { secretValidationRules = _rule is null ? [] : new[] { _rule } });
            }
            if (_rule is null) { return Phase5TestSupport.Json(404, new { }); }
            Dictionary<string, object?> returned = new(_rule);
            if (WrongProject) { returned["projectId"] = "other-project"; }
            if (request.Method == HttpMethod.Delete) { _rule = null; }
            return Phase5TestSupport.Json(200, new { secretValidationRule = returned });
        }

        private static Dictionary<string, object?> Rule(string kind)
        {
            var rule = new Dictionary<string, object?>
            {
                ["id"] = Phase5TestSupport.Id,
                ["projectId"] = "project",
                ["name"] = "rule",
                ["secretPath"] = "/",
                ["type"] = kind,
                ["isActive"] = true,
                ["createdAt"] = Phase5TestSupport.Date,
                ["updatedAt"] = Phase5TestSupport.Date,
                ["environment"] = new { id = Phase5TestSupport.EnvironmentId, name = "Development", slug = "dev" }
            };
            if (kind != "static-secrets")
            {
                rule["providers"] = new[] { kind == "dynamic-secrets" ? "sql-database" : "postgres-credentials" };
                rule["passwordConstraints"] = new { minLength = 8 };
            }
            return rule;
        }
    }
}
