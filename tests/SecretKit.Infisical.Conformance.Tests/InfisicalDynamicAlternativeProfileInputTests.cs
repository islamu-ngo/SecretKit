using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalDynamicAlternativeProfileInputTests
{
    [Test]
    [Arguments("ElasticSearch.api-key")]
    [Arguments("Kubernetes.static-account")]
    [Arguments("Ldap.static-account")]
    [Arguments("Totp.manual.Sha1")]
    [Arguments("Totp.manual.Sha256")]
    [Arguments("Totp.manual.Sha512")]
    [Arguments("Tailscale.auth_keys.oauth")]
    [Arguments("Tailscale.federated_keys.api_key")]
    [Arguments("Tailscale.federated_keys.oauth")]
    [Arguments("Tailscale.oauth_keys.api_key")]
    [Arguments("Tailscale.oauth_keys.oauth")]
    public async Task AlternativesMatchPublicConstructorsAndRejectInvalidSelections(string variant)
    {
        foreach (int options in new[] { 0, 1, 2 })
        {
            var sample = Sample(variant, options);
            using var expected = sample.Profile;
            string json = JsonSerializer.Serialize(sample.Input, InfisicalLifecycleFamilies.Options);
            var input = JsonSerializer.Deserialize<InfisicalDynamicAlternativeProfileInput>(
                json, InfisicalLifecycleFamilies.Options)!;
            using var actual = InfisicalDynamicAlternativeProfileInputs.Create(variant, input);
            await Assert.That(InfisicalDynamicAlternativeProfileInputs.TryProvider(variant, out var provider)).IsTrue();
            await Assert.That(provider).IsEqualTo(expected.Provider);
            await Assert.That(actual.Provider).IsEqualTo(provider);
            await Assert.That(JsonElement.DeepEquals(await Capture(actual), await Capture(expected))).IsTrue();
            await Assert.That(input.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
            await Assert.That(actual.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();

            var node = JsonNode.Parse(json)!.AsObject();
            var selection = node.Single(pair => pair.Value is not null);
            await Assert.That(input.ElasticSearchApiKey?.ToString().Contains("canary") ?? false).IsFalse();
            await Assert.That(input.KubernetesStaticAccount?.ToString().Contains("canary") ?? false).IsFalse();
            await Assert.That(input.LdapStaticAccount?.ToString().Contains("canary") ?? false).IsFalse();
            await Assert.That(input.TotpManualSecret?.ToString().Contains("canary") ?? false).IsFalse();
            await Assert.That(input.TailscaleOAuthAuthority?.ToString().Contains("canary") ?? false).IsFalse();
            await Assert.That(input.TailscaleFederatedApiKey?.ToString().Contains("canary") ?? false).IsFalse();
            await Assert.That(input.TailscaleFederatedOAuth?.ToString().Contains("canary") ?? false).IsFalse();
            await Assert.That(input.TailscaleOAuthKeyApiKey?.ToString().Contains("canary") ?? false).IsFalse();
            await Assert.That(input.TailscaleOAuthKeyOAuth?.ToString().Contains("canary") ?? false).IsFalse();
            var fields = selection.Value!.AsObject();
            fields.Remove(sample.RequiredField);
            await Assert.That(() => JsonSerializer.Deserialize<InfisicalDynamicAlternativeProfileInput>(
                node.ToJsonString(), InfisicalLifecycleFamilies.Options)).Throws<JsonException>();
            fields[sample.RequiredField] = null;
            await Assert.That(() => JsonSerializer.Deserialize<InfisicalDynamicAlternativeProfileInput>(
                node.ToJsonString(), InfisicalLifecycleFamilies.Options)).Throws<JsonException>();
            fields[sample.RequiredField] = "canary";
            fields["arbitraryField"] = "canary";
            await Assert.That(() => JsonSerializer.Deserialize<InfisicalDynamicAlternativeProfileInput>(
                node.ToJsonString(), InfisicalLifecycleFamilies.Options)).Throws<JsonException>();
        }

        await Assert.That(() => InfisicalDynamicAlternativeProfileInputs.Create(variant, new())).Throws<ArgumentException>();
        await Assert.That(() => InfisicalDynamicAlternativeProfileInputs.Create(variant, null!)).Throws<ArgumentNullException>();
        var wrong = variant.StartsWith("Totp.", StringComparison.Ordinal)
            ? new InfisicalDynamicAlternativeProfileInput(LdapStaticAccount: new("url", "dn", "pass", "ldif"))
            : new InfisicalDynamicAlternativeProfileInput(TotpManualSecret: new("secret"));
        await Assert.That(() => InfisicalDynamicAlternativeProfileInputs.Create(variant, wrong)).Throws<ArgumentException>();
        var sampleInput = Sample(variant, 0);
        using var unused = sampleInput.Profile;
        var multiple = sampleInput.Input.TotpManualSecret is null
            ? sampleInput.Input with { TotpManualSecret = new("secret") }
            : sampleInput.Input with { LdapStaticAccount = new("url", "dn", "pass", "ldif") };
        await Assert.That(() => InfisicalDynamicAlternativeProfileInputs.Create(variant, multiple)).Throws<ArgumentException>();
    }

    [Test]
    [Arguments("")]
    [Arguments("profile.Totp")]
    [Arguments("Totp.url")]
    [Arguments("Totp.manual.sha1")]
    [Arguments("Totp.manual.Sha999")]
    [Arguments("Tailscale.auth_keys.api_key")]
    [Arguments("Tailscale.oauth_keys.ApiKey")]
    [Arguments("Tailscale.federated_keys.oauth.extra")]
    [Arguments("ElasticSearch.user")]
    [Arguments("Kubernetes.dynamic-role")]
    [Arguments("Ldap.dynamic")]
    [Arguments("AwsIam.assume-role.IamUser")]
    [Arguments(null)]
    public async Task OnlyExactAdmittedAlternativeNamesAreAccepted(string? variant)
    {
        await Assert.That(InfisicalDynamicAlternativeProfileInputs.TryProvider(variant!, out _)).IsFalse();
        await Assert.That(() => InfisicalDynamicAlternativeProfileInputs.Create(variant!,
            new(TotpManualSecret: new("secret")))).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(NativeTotpAlgorithm.Sha1)]
    [Arguments(NativeTotpAlgorithm.Sha256)]
    [Arguments(NativeTotpAlgorithm.Sha512)]
    [Arguments((NativeTotpAlgorithm)999)]
    public async Task TotpAlgorithmMustMatchVariant(NativeTotpAlgorithm algorithm)
    {
        string variant = algorithm == NativeTotpAlgorithm.Sha1 ? "Totp.manual.Sha256" : "Totp.manual.Sha1";
        await Assert.That(() => InfisicalDynamicAlternativeProfileInputs.Create(variant,
            new(TotpManualSecret: new("secret", algorithm)))).Throws<ArgumentException>();
    }

    [Test]
    public async Task InvalidFieldsAndBranchOptionsFailBeforeDispatch()
    {
        (string Variant, InfisicalDynamicAlternativeProfileInput Input)[] invalid =
        [
            ("ElasticSearch.api-key", new(ElasticSearchApiKey: new(null!, 9200, "id", "key", ["role"]))),
            ("ElasticSearch.api-key", new(ElasticSearchApiKey: new("host", 0, "id", "key", ["role"]))),
            ("ElasticSearch.api-key", new(ElasticSearchApiKey: new("host", 9200, null!, "key", ["role"]))),
            ("ElasticSearch.api-key", new(ElasticSearchApiKey: new("host", 9200, "id", null!, ["role"]))),
            ("ElasticSearch.api-key", new(ElasticSearchApiKey: new("host", 9200, "id", "key", null!))),
            ("Kubernetes.static-account", new(KubernetesStaticAccount: new("ns", null!, []))),
            ("Kubernetes.static-account", new(KubernetesStaticAccount: new("ns", "account", null!))),
            ("Kubernetes.static-account", new(KubernetesStaticAccount: new("ns", "account", [],
                Authentication: (NativeKubernetesAuthentication)999))),
            ("Kubernetes.static-account", new(KubernetesStaticAccount: new("ns", "account", [],
                Gateway: new("id", ClearGatewayId: true)))),
            ("Ldap.static-account", new(LdapStaticAccount: new("url", "dn", null!, "ldif"))),
            ("Totp.manual.Sha1", new(TotpManualSecret: new(null!))),
            ("Totp.manual.Sha1", new(TotpManualSecret: new("secret", Digits: 0))),
            ("Totp.manual.Sha1", new(TotpManualSecret: new("secret", Period: 0))),
            ("Tailscale.auth_keys.oauth", new(TailscaleOAuthAuthority: new("id", null!))),
            ("Tailscale.auth_keys.oauth", new(TailscaleOAuthAuthority: new("id", "secret", new(Audience: "audience")))),
            ("Tailscale.federated_keys.api_key", new(TailscaleFederatedApiKey: new("key", null!, "subject", ["scope"]))),
            ("Tailscale.federated_keys.oauth", new(TailscaleFederatedOAuth: new("id", "secret", "issuer", "subject",
                ["scope"], new(Reusable: false)))),
            ("Tailscale.oauth_keys.api_key", new(TailscaleOAuthKeyApiKey: new("key", null!))),
            ("Tailscale.oauth_keys.oauth", new(TailscaleOAuthKeyOAuth: new("id", "secret", ["scope"],
                new(Audience: "audience"))))
        ];
        foreach (var item in invalid)
            await Assert.That(() => InfisicalDynamicAlternativeProfileInputs.Create(item.Variant, item.Input))
                .Throws<ArgumentException>();
    }

    [Test]
    public async Task ArrayAndTemporaryOptionCopiesSurviveIndependentDisposal()
    {
        string[] audiences = ["audience-canary"];
        var kubernetes = new InfisicalDynamicAlternativeProfileInput(KubernetesStaticAccount:
            new("ns-canary", "account-canary", audiences, Gateway: new(ClearGatewayId: true, ClearGatewayPoolId: true)));
        using var first = InfisicalDynamicAlternativeProfileInputs.Create("Kubernetes.static-account", kubernetes);
        using var second = InfisicalDynamicAlternativeProfileInputs.Create("Kubernetes.static-account", kubernetes);
        audiences[0] = "changed";
        first.Dispose();
        var wire = (await Capture(second)).GetProperty("inputs");
        await Assert.That(wire.GetProperty("audiences")[0].GetString()).IsEqualTo("audience-canary");
        await Assert.That(wire.GetProperty("gatewayId").ValueKind).IsEqualTo(JsonValueKind.Null);
        await Assert.That(wire.GetProperty("gatewayPoolId").ValueKind).IsEqualTo(JsonValueKind.Null);

        string[] scopes = ["scope-canary"];
        string[] tags = ["tag-canary"];
        var tailscale = new InfisicalDynamicAlternativeProfileInput(TailscaleFederatedOAuth:
            new("id", "secret", "issuer", "subject", scopes, new(Tags: tags, Audience: "audience-canary")));
        using var tailFirst = InfisicalDynamicAlternativeProfileInputs.Create("Tailscale.federated_keys.oauth", tailscale);
        using var tailSecond = InfisicalDynamicAlternativeProfileInputs.Create("Tailscale.federated_keys.oauth", tailscale);
        scopes[0] = "changed";
        tags[0] = "changed";
        tailFirst.Dispose();
        wire = (await Capture(tailSecond)).GetProperty("inputs");
        await Assert.That(wire.GetProperty("scopes")[0].GetString()).IsEqualTo("scope-canary");
        await Assert.That(wire.GetProperty("tags")[0].GetString()).IsEqualTo("tag-canary");
        await Assert.That(wire.GetProperty("audience").GetString()).IsEqualTo("audience-canary");
        await Assert.That(tailscale.TailscaleFederatedOAuth!.Options!.ToString().Contains("canary")).IsFalse();
        tailSecond.Dispose();
        using var handler = new CaptureTransport();
        await using var client = Client(handler);
        var target = client.Definition("offline");
        var receipt = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.CreateDefinition);
        await Assert.That(async () => await client.CreateDefinitionAsync(target, tailSecond, new(TimeSpan.FromSeconds(60)),
            new(TimeSpan.FromSeconds(120)), receipt)).Throws<ObjectDisposedException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(handler.Provider).IsNull();
    }

    internal static (InfisicalDynamicAlternativeProfileInput Input, InfisicalDynamicProfile Profile, string RequiredField)
        Sample(string variant, int mode)
    {
        bool selected = mode != 0;
        bool federated = variant.StartsWith("Tailscale.federated_keys.", StringComparison.Ordinal);
        bool authKeys = variant == "Tailscale.auth_keys.oauth";
        string? ca = selected ? "ca-canary" : null;
        using var gateway = selected ? new NativeGatewayOptions("gateway-canary", "pool-canary") : null;
        var gatewayInput = selected ? new DynamicGatewayInput("gateway-canary", "pool-canary") : null;
        var tailInput = selected ? new DynamicTailscaleOptionsInput("tailnet-canary",
            mode == 2 ? [] : ["tag-canary"], "description-canary", federated ? "audience-canary" : null,
            authKeys ? mode == 1 : null, authKeys ? mode == 1 : null) : null;
        using var tail = tailInput is null ? null : new NativeTailscaleOptions(tailInput.Tailnet, tailInput.Tags,
            tailInput.Description, tailInput.Audience, tailInput.Reusable, tailInput.Preauthorized);
        NativeTotpAlgorithm algorithm = variant switch
        {
            "Totp.manual.Sha256" => NativeTotpAlgorithm.Sha256,
            "Totp.manual.Sha512" => NativeTotpAlgorithm.Sha512,
            _ => NativeTotpAlgorithm.Sha1
        };
        return variant switch
        {
            "ElasticSearch.api-key" => (new(ElasticSearchApiKey: new("host-canary", 9200, mode == 2 ? "" : "id-canary",
                mode == 2 ? "" : "key-canary", ["role-canary"], ca)),
                NativeElasticsearchDefinitionProfile.ForApiKey("host-canary", 9200, mode == 2 ? "" : "id-canary",
                    mode == 2 ? "" : "key-canary", ["role-canary"], ca), "host"),
            "Kubernetes.static-account" => (new(KubernetesStaticAccount: new("ns-canary", "account-canary",
                mode == 2 ? [] : ["audience-canary"], selected ? "token-canary" : null,
                selected ? "https://cluster.test" : null, ca,
                selected ? mode == 1 ? NativeKubernetesAuthentication.Api : NativeKubernetesAuthentication.Gateway : null,
                gatewayInput, selected ? mode == 1 : null)),
                NativeKubernetesDefinitionProfile.ForStaticAccount("ns-canary", "account-canary",
                    mode == 2 ? [] : ["audience-canary"], selected ? "token-canary" : null,
                    selected ? "https://cluster.test" : null, ca,
                    selected ? mode == 1 ? NativeKubernetesAuthentication.Api : NativeKubernetesAuthentication.Gateway : null,
                    gateway, selected ? mode == 1 : null), "nameSpace"),
            "Ldap.static-account" => (new(LdapStaticAccount: new("ldaps://ldap.test", "dn-canary", "password-canary",
                "rotation-canary", ca)),
                NativeLdapDefinitionProfile.ForStaticAccount("ldaps://ldap.test", "dn-canary", "password-canary",
                    "rotation-canary", ca), "url"),
            "Totp.manual.Sha1" or "Totp.manual.Sha256" or "Totp.manual.Sha512" =>
                (new(TotpManualSecret: new("secret-canary", algorithm, selected ? 8 : null, selected ? 45 : null)),
                NativeTotpDefinitionProfile.ForManualSecret("secret-canary", algorithm, selected ? 8 : null,
                    selected ? 45 : null), "secret"),
            "Tailscale.auth_keys.oauth" => (new(TailscaleOAuthAuthority: new("id-canary", "secret-canary", tailInput)),
                NativeTailscaleDefinitionProfile.ForOAuthAuthority("id-canary", "secret-canary", tail), "clientId"),
            "Tailscale.federated_keys.api_key" => (new(TailscaleFederatedApiKey:
                new("key-canary", "issuer-canary", "subject-canary", ["scope-canary"], tailInput)),
                NativeTailscaleDefinitionProfile.ForFederatedApiKey("key-canary", "issuer-canary", "subject-canary",
                    ["scope-canary"], tail), "apiKey"),
            "Tailscale.federated_keys.oauth" => (new(TailscaleFederatedOAuth:
                new("id-canary", "secret-canary", "issuer-canary", "subject-canary", ["scope-canary"], tailInput)),
                NativeTailscaleDefinitionProfile.ForFederatedOAuth("id-canary", "secret-canary", "issuer-canary",
                    "subject-canary", ["scope-canary"], tail), "clientId"),
            "Tailscale.oauth_keys.api_key" => (new(TailscaleOAuthKeyApiKey: new("key-canary", ["scope-canary"], tailInput)),
                NativeTailscaleDefinitionProfile.ForOAuthKeyApiKey("key-canary", ["scope-canary"], tail), "apiKey"),
            "Tailscale.oauth_keys.oauth" => (new(TailscaleOAuthKeyOAuth:
                new("id-canary", "secret-canary", ["scope-canary"], tailInput)),
                NativeTailscaleDefinitionProfile.ForOAuthKeyOAuth("id-canary", "secret-canary", ["scope-canary"], tail), "clientId"),
            _ => throw new ArgumentException()
        };
    }

    private static InfisicalDynamicClient Client(CaptureTransport handler) => new(new("https://dynamic.test"),
        new Tokens(), new("project", "environment", "/folder", CaptureTransport.FolderId),
        new() { Transport = InfisicalTransportOptions.HostControlled(handler) });

    private static async Task<JsonElement> Capture(InfisicalDynamicProfile profile)
    {
        using var handler = new CaptureTransport();
        await using var client = Client(handler);
        var target = client.Definition("offline");
        var result = await client.CreateDefinitionAsync(target, profile, new(TimeSpan.FromSeconds(60)),
            new(TimeSpan.FromSeconds(120)), new(target, InfisicalDynamicOperation.CreateDefinition));
        await Assert.That(result.IsSuccess).IsTrue();
        return handler.Provider!.Value;
    }

    private sealed class CaptureTransport : HttpMessageHandler
    {
        internal static readonly Guid FolderId = new("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        internal JsonElement? Provider { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            await Assert.That(request.Method).IsEqualTo(HttpMethod.Post);
            await Assert.That(request.RequestUri!.AbsoluteUri).IsEqualTo("https://dynamic.test/api/v1/dynamic-secrets");
            using var document = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
            JsonElement body = document.RootElement;
            Provider = body.GetProperty("provider").Clone();
            return new(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    dynamicSecret = new
                    {
                        id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                        name = body.GetProperty("name").GetString(),
                        type = Provider.Value.GetProperty("type").GetString(),
                        folderId = FolderId,
                        defaultTTL = body.GetProperty("defaultTTL").GetString(),
                        maxTTL = body.GetProperty("maxTTL").GetString(),
                        createdAt = "2026-01-01T00:00:00Z",
                        updatedAt = "2026-01-01T00:00:00Z",
                        version = 1,
                        status = (string?)null
                    }
                }), Encoding.UTF8, "application/json")
            };
        }
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
        }
    }
}
