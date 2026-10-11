using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class IdentityAuthenticationTests
{
    private const string IdentityId = "11111111-1111-4111-8111-111111111111";
    private const string UniversalPath = "/api/v1/auth/universal-auth/identities/" + IdentityId;
    private const string TokenPath = "/api/v1/auth/token-auth/identities/" + IdentityId;
    private const string TokenIdentity = "22222222-2222-4222-8222-222222222222";
    private const string TokenMetadataPath = "/api/v1/auth/token-auth/identities/" + TokenIdentity;
    private const string Config = """{"id":"33333333-3333-4333-8333-333333333333","identityId":"11111111-1111-4111-8111-111111111111","clientId":"client-canary","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","accessTokenTTL":10,"accessTokenMaxTTL":20,"accessTokenPeriod":120,"accessTokenNumUsesLimit":0,"lockoutEnabled":false}""";
    private const string Secret = """{"id":"secret","identityUAId":"33333333-3333-4333-8333-333333333333","description":"description-canary","clientSecretPrefix":"prefix-canary","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","clientSecretTTL":0,"clientSecretNumUses":1,"clientSecretNumUsesLimit":2,"isClientSecretRevoked":false}""";
    private const string Token = """{"id":"token","identityId":"22222222-2222-4222-8222-222222222222","authMethod":"token-auth","name":null,"createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","accessTokenTTL":0,"accessTokenMaxTTL":0,"accessTokenPeriod":0,"accessTokenNumUses":0,"accessTokenNumUsesLimit":0,"isAccessTokenRevoked":false,"subOrganizationId":null,"accessTokenLastUsedAt":null,"accessTokenLastRenewedAt":null,"identityUAClientSecretId":null}""";

    [Test]
    [Arguments("universal", "attach")]
    [Arguments("universal", "update")]
    [Arguments("universal", "get")]
    [Arguments("universal", "delete")]
    [Arguments("token", "attach")]
    [Arguments("token", "update")]
    [Arguments("token", "get")]
    [Arguments("token", "delete")]
    public async Task EightConfigurationRoutesUseFullIntentAndNativeExpiryFields(string strategy, string operation)
    {
        bool universal = strategy == "universal";
        var input = new UniversalAuthConfigurationInput(10, 20, 0, 120,
            [new("127.0.0.1/32")], [new("::1/128")], false, 2.5, 60.5, 30.5);
        var tokenInput = new TokenAuthConfigurationInput(0, 0, 0, [new("127.0.0.1/32")]);
        using var request = Configuration(strategy, operation, input, tokenInput);
        var method = operation switch { "attach" => HttpMethod.Post, "update" => HttpMethod.Patch, "get" => HttpMethod.Get, _ => HttpMethod.Delete };
        var configuration = JsonNode.Parse(Config)!.AsObject();
        if (!universal) { configuration.Remove("clientId"); configuration.Remove("lockoutEnabled"); }
        string response = new JsonObject { [universal ? "identityUniversalAuth" : "identityTokenAuth"] = configuration }.ToJsonString();
        var wire = new Wire(method, universal ? UniversalPath : TokenPath, response);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        var approved = operation is "attach" or "update"
            ? universal ? IdentityAuthenticationOperations.UniversalAuthConfigurationTarget("org", IdentityId, input, operation == "update")
                : IdentityAuthenticationOperations.TokenAuthConfigurationTarget("org", IdentityId, tokenInput, operation == "update")
            : new ManagementTarget("org", resourceId: IdentityId);
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(
            "infisical." + method.Method.ToLowerInvariant() + ".v1.auth." + (universal ? "universal" : "token") +
            ".auth.identities.by.identityId", approved), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.AccessTokenPeriod).IsEqualTo(120d);
        await Assert.That(result.Value.AccessTokenMaxTTL).IsEqualTo(20d);
        await Assert.That(JsonSerializer.Serialize(result.Value)).IsEqualTo("{}");
        await Assert.That(wire.Observed).IsTrue();
        if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await AssertClosed(request, approved, method, universal ? UniversalPath : TokenPath, response);
        if (operation is "attach" or "update")
        {
            using var body = JsonDocument.Parse(wire.Body!);
            await Assert.That(body.RootElement.GetProperty("accessTokenNumUsesLimit").GetInt64()).IsEqualTo(0L);
            if (universal)
            {
                await Assert.That(body.RootElement.GetProperty("lockoutEnabled").GetBoolean()).IsFalse();
                await Assert.That(body.RootElement.GetProperty("accessTokenPeriod").GetInt32()).IsEqualTo(120);
                await Assert.That(body.RootElement.GetProperty("clientSecretTrustedIps")[0].GetProperty("ipAddress").GetString()).IsEqualTo("127.0.0.1/32");
            }
            else await Assert.That(body.RootElement.TryGetProperty("accessTokenPeriod", out _)).IsFalse();
        }
        else await Assert.That(wire.Body is null).IsTrue();
    }

    [Test]
    [Arguments("secret-create")]
    [Arguments("secret-list")]
    [Arguments("secret-get")]
    [Arguments("secret-revoke")]
    [Arguments("clear-lockouts")]
    [Arguments("token-create")]
    [Arguments("token-list")]
    [Arguments("token-get")]
    [Arguments("token-rename")]
    [Arguments("token-revoke")]
    public async Task TenCredentialRoutesRemainTypedAndMaterialProtected(string operation)
    {
        var (method, path, response) = CredentialWire(operation);
        var wire = new Wire(method, path, response);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        switch (operation)
        {
            case "secret-create":
                using (var request = IdentityAuthenticationOperations.CreateUniversalClientSecret("org", IdentityId, "", 2.5, 0))
                {
                    var result = await Execute(client, authority, request,
                        IdentityAuthenticationOperations.ClientSecretCreateTarget("org", IdentityId, "", 2.5, 0));
                    using var creation = result.Value;
                    using var copy = creation.ClientSecret.Copy();
                    creation.Dispose();
                    await Assert.That(copy.Reveal()).IsEqualTo("issued-secret-canary");
                    await Assert.That(creation.Metadata.ClientSecretTTL).IsEqualTo(0d);
                    await Assert.That(creation.Metadata.ClientSecretNumUsesLimit).IsEqualTo(2d);
                    await Assert.That(JsonSerializer.Serialize(creation)).IsEqualTo("{}");
                    await Assert.That(wire.Body).IsEqualTo("""{"description":"","numUsesLimit":2.5,"ttl":0}""");
                }
                break;
            case "secret-list":
                using (var request = IdentityAuthenticationOperations.ListUniversalClientSecrets("org", IdentityId))
                {
                    var result = await Execute(client, authority, request, new("org", resourceId: IdentityId));
                    await Assert.That(result.Value.Items.Single().Id).IsEqualTo("secret");
                    await Assert.That(result.Value.IsComplete).IsTrue();
                }
                break;
            case "secret-get":
            case "secret-revoke":
                using (var request = operation == "secret-get"
                    ? IdentityAuthenticationOperations.GetUniversalClientSecret("org", IdentityId, "secret")
                    : IdentityAuthenticationOperations.RevokeUniversalClientSecret("org", IdentityId, "secret"))
                {
                    var result = await Execute(client, authority, request, new("org", resourceId: IdentityId, secondaryId: "secret"));
                    await Assert.That(result.Value.Id).IsEqualTo("secret");
                    await Assert.That(JsonSerializer.Serialize(result.Value)).IsEqualTo("{}");
                }
                break;
            case "clear-lockouts":
                using (var request = IdentityAuthenticationOperations.ClearUniversalAuthLockouts("org", IdentityId))
                {
                    var result = await Execute(client, authority, request, new("org", resourceId: IdentityId));
                    await Assert.That(result.Value.Deleted).IsEqualTo(2d);
                }
                break;
            case "token-create":
                using (var request = IdentityAuthenticationOperations.CreateToken("org", TokenIdentity, "", "selected-org"))
                {
                    var result = await Execute(client, authority, request,
                        IdentityAuthenticationOperations.TokenCreateTarget("org", TokenIdentity, "", "selected-org"));
                    using var creation = result.Value;
                    using var copy = creation.AccessToken.Copy();
                    creation.Dispose();
                    await Assert.That(copy.Reveal()).IsEqualTo("issued-token-canary");
                    await Assert.That(creation.ExpiresIn).IsEqualTo(120d);
                    await Assert.That(creation.AccessTokenMaxTTL).IsEqualTo(30d);
                    await Assert.That(creation.Metadata.Name.IsPresent).IsTrue();
                    await Assert.That(creation.Metadata.Name.IsNull).IsTrue();
                    await Assert.That(JsonSerializer.Serialize(creation)).IsEqualTo("{}");
                    await Assert.That(wire.Body).IsEqualTo("""{"name":"","organizationSlug":"selected-org"}""");
                }
                break;
            case "token-list":
                using (var request = IdentityAuthenticationOperations.ListTokens("org", TokenIdentity))
                {
                    var result = await Execute(client, authority, request, new("org", resourceId: TokenIdentity));
                    await Assert.That(result.Value.Items.Single().IdentityId).IsEqualTo(TokenIdentity);
                }
                break;
            case "token-get":
            case "token-rename":
                using (var request = operation == "token-get" ? IdentityAuthenticationOperations.GetToken("org", "token")
                    : IdentityAuthenticationOperations.RenameToken("org", "token", "renamed-canary"))
                {
                    var target = operation == "token-get" ? new ManagementTarget("org", resourceId: "token")
                        : IdentityAuthenticationOperations.TokenRenameTarget("org", "token", "renamed-canary");
                    var result = await Execute(client, authority, request, target);
                    await Assert.That(result.Value.Id).IsEqualTo("token");
                    await Assert.That(JsonSerializer.Serialize(result.Value)).IsEqualTo("{}");
                }
                break;
            case "token-revoke":
                using (var request = IdentityAuthenticationOperations.RevokeToken("org", "token"))
                {
                    var result = await Execute(client, authority, request, new("org", resourceId: "token"));
                    await Assert.That(result.Value.Message).IsEqualTo("revoked");
                }
                break;
        }
        await Assert.That(wire.Observed).IsTrue();
        async Task<SecretOutcome<T>> Execute<T>(ManagementClient selectedClient, ManagementAuthority selectedAuthority,
            ManagementRequest<T> request, ManagementTarget target) where T : notnull
        {
            await AssertClosed(request, target, method, path, response);
            return await IdentityAuthenticationTests.Execute(selectedClient, selectedAuthority, request, target);
        }
    }

    [Test]
    [Arguments("policy")]
    [Arguments("secret")]
    [Arguments("token")]
    [Arguments("rename")]
    public async Task ChangedIntentCannotBorrowApprovedGrantBeforeCredentialAcquisition(string operation)
    {
        var wire = new Wire(HttpMethod.Post, UniversalPath, "{}");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        switch (operation)
        {
            case "policy":
                using (var request = IdentityAuthenticationOperations.AttachUniversalAuth("org", IdentityId, new(lockoutEnabled: false)))
                    await Denied(client, authority, request, IdentityAuthenticationOperations.UniversalAuthConfigurationTarget("org", IdentityId, new()));
                break;
            case "secret":
                using (var request = IdentityAuthenticationOperations.CreateUniversalClientSecret("org", IdentityId, ttl: 0))
                    await Denied(client, authority, request, IdentityAuthenticationOperations.ClientSecretCreateTarget("org", IdentityId));
                break;
            case "token":
                using (var request = IdentityAuthenticationOperations.CreateToken("org", IdentityId, organizationSlug: "foreign"))
                    await Denied(client, authority, request, IdentityAuthenticationOperations.TokenCreateTarget("org", IdentityId, organizationSlug: "approved"));
                break;
            default:
                using (var request = IdentityAuthenticationOperations.RenameToken("org", "token", "foreign"))
                    await Denied(client, authority, request, IdentityAuthenticationOperations.TokenRenameTarget("org", "token", "approved"));
                break;
        }
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();
    }

    [Test]
    public async Task NativeInputBudgetsAndOmissionRemainDistinct()
    {
        await Assert.That(() => new UniversalAuthConfigurationInput(accessTokenTTL: -1)).Throws<ArgumentException>();
        await Assert.That(() => new UniversalAuthConfigurationInput(lockoutThreshold: double.NaN)).Throws<ArgumentException>();
        await Assert.That(() => new TokenAuthConfigurationInput(accessTokenTrustedIps: [])).Throws<ArgumentException>();
        await Assert.That(() => new IdentityTrustedIp("https://untrusted.test")).Throws<ArgumentException>();
        var ips = new List<IdentityTrustedIp> { new("127.0.0.1/32") };
        var input = new TokenAuthConfigurationInput(accessTokenTrustedIps: ips);
        ips.Clear();
        await Assert.That(input.AccessTokenTrustedIps!.Count).IsEqualTo(1);
        using var request = IdentityAuthenticationOperations.AttachUniversalAuth("org", IdentityId, new());
        using var explicitFalse = IdentityAuthenticationOperations.AttachUniversalAuth("org", IdentityId, new(lockoutEnabled: false));
        await Assert.That(request.Target.SecondaryId == explicitFalse.Target.SecondaryId).IsFalse();
    }

    [Test]
    [Arguments("foreign-identity")]
    [Arguments("foreign-token")]
    [Arguments("duplicate")]
    [Arguments("oversize")]
    [Arguments("lost")]
    public async Task UncertainCredentialResponsesNeverExposeMaterialOrReplay(string mode)
    {
        string data = mode switch
        {
            "foreign-identity" => Token.Replace("\"identityId\":\"identity\"", "\"identityId\":\"foreign\"", StringComparison.Ordinal),
            "foreign-token" => Token.Replace("\"id\":\"token\"", "\"id\":\"foreign\"", StringComparison.Ordinal),
            _ => Token
        };
        string response = "{\"token\":" + data + (mode == "duplicate" ? ",\"token\":" + data : "") + "}";
        if (mode == "oversize") response = new string('x', 1024 * 1024 + 1);
        var wire = new Wire(HttpMethod.Patch, "/api/v1/auth/token-auth/tokens/token", response, mode == "lost");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        using var request = IdentityAuthenticationOperations.RenameToken("org", "token", "renamed-canary");
        var receipt = client.CreateReceipt(request);
        var grant = authority.IssueGrant("infisical.patch.v1.auth.token.auth.tokens.by.tokenId",
            IdentityAuthenticationOperations.TokenRenameTarget("org", "token", "renamed-canary"));
        var result = await client.ExecuteAsync(request, authority, grant, receipt);
        // The token-only route echoes no selected identity; that missing scope cannot be invented.
        await Assert.That(result.Status).IsEqualTo(mode == "foreign-identity" ? SecretStatus.Success :
            mode == "foreign-token" ? SecretStatus.Invalid : SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(mode == "foreign-identity" ? DispatchEvidence.Applied : DispatchEvidence.PossiblyDispatched);
        var replay = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Requests).IsEqualTo(1);
    }

    [Test]
    public async Task ListRejectsForeignIdentityInsteadOfInventingScope()
    {
        var wire = new Wire(HttpMethod.Get, TokenMetadataPath + "/tokens",
            "{\"tokens\":[" + Token.Replace(TokenIdentity, "33333333-3333-4333-8333-333333333333", StringComparison.Ordinal) + "]}");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        using var request = IdentityAuthenticationOperations.ListTokens("org", TokenIdentity);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant("infisical.get.v1.auth.token.auth.identities.by.identityId.tokens", new("org", resourceId: TokenIdentity)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task CanceledCredentialCreateRetainsCommittedLossWithoutReplay()
    {
        var wire = new CommittedWire();
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        using var request = IdentityAuthenticationOperations.CreateToken("org", IdentityId);
        var receipt = client.CreateReceipt(request);
        var grant = authority.IssueGrant("infisical.post.v1.auth.token.auth.identities.by.identityId.tokens",
            IdentityAuthenticationOperations.TokenCreateTarget("org", IdentityId));
        using var cancellation = new CancellationTokenSource();
        Task committed = wire.Committed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Task<SecretOutcome<TokenAuthTokenCreation>> pending = client.ExecuteAsync(request, authority, grant,
            receipt, cancellation.Token).AsTask();
        await committed;
        cancellation.Cancel();
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        var replay = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Requests).IsEqualTo(1);
    }

    [Test]
    public async Task CredentialCreateOmissionAndScopeAreValidatedBeforeSend()
    {
        var wire = new Wire(HttpMethod.Post, TokenMetadataPath + "/tokens",
            "{\"accessToken\":\"issued-token-canary\",\"expiresIn\":0,\"accessTokenMaxTTL\":0,\"tokenType\":\"Bearer\",\"tokenData\":" + Token + "}");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        using var request = IdentityAuthenticationOperations.CreateToken("org", TokenIdentity);
        var foreign = authority.IssueGrant(request.OperationId,
            IdentityAuthenticationOperations.TokenCreateTarget("org", "other"));
        var denied = await client.ExecuteAsync(request, authority, foreign, client.CreateReceipt(request));
        await Assert.That(denied.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        var result = await Execute(client, authority, request,
            IdentityAuthenticationOperations.TokenCreateTarget("org", TokenIdentity));
        using var created = result.Value;
        await Assert.That(wire.Body).IsEqualTo("{}");
        await Assert.That(created.ExpiresIn).IsEqualTo(0d);
        await Assert.That(created.AccessTokenMaxTTL).IsEqualTo(0d);
        // Administration reports zero, without constructing an unlimited runtime lifetime.
    }

    private static ManagementRequest<IdentityAuthenticationConfiguration> Configuration(string strategy, string operation,
        UniversalAuthConfigurationInput universal, TokenAuthConfigurationInput token) => (strategy, operation) switch
        {
            ("universal", "attach") => IdentityAuthenticationOperations.AttachUniversalAuth("org", IdentityId, universal),
            ("universal", "update") => IdentityAuthenticationOperations.UpdateUniversalAuth("org", IdentityId, universal),
            ("universal", "get") => IdentityAuthenticationOperations.GetUniversalAuth("org", IdentityId),
            ("universal", "delete") => IdentityAuthenticationOperations.DeleteUniversalAuth("org", IdentityId),
            ("token", "attach") => IdentityAuthenticationOperations.AttachTokenAuth("org", IdentityId, token),
            ("token", "update") => IdentityAuthenticationOperations.UpdateTokenAuth("org", IdentityId, token),
            ("token", "get") => IdentityAuthenticationOperations.GetTokenAuth("org", IdentityId),
            _ => IdentityAuthenticationOperations.DeleteTokenAuth("org", IdentityId)
        };

    private static (HttpMethod Method, string Path, string Response) CredentialWire(string operation) => operation switch
    {
        "secret-create" => (HttpMethod.Post, UniversalPath + "/client-secrets", "{\"clientSecret\":\"issued-secret-canary\",\"clientSecretData\":" + Secret + "}"),
        "secret-list" => (HttpMethod.Get, UniversalPath + "/client-secrets", "{\"clientSecretData\":[" + Secret + "]}"),
        "secret-get" => (HttpMethod.Get, UniversalPath + "/client-secrets/secret", "{\"clientSecretData\":" + Secret + "}"),
        "secret-revoke" => (HttpMethod.Post, UniversalPath + "/client-secrets/secret/revoke", "{\"clientSecretData\":" + Secret + "}"),
        "clear-lockouts" => (HttpMethod.Post, UniversalPath + "/clear-lockouts", """{"deleted":2}"""),
        "token-create" => (HttpMethod.Post, TokenMetadataPath + "/tokens", "{\"accessToken\":\"issued-token-canary\",\"expiresIn\":120,\"accessTokenMaxTTL\":30,\"tokenType\":\"Bearer\",\"tokenData\":" + Token + "}"),
        "token-list" => (HttpMethod.Get, TokenMetadataPath + "/tokens", "{\"tokens\":[" + Token + "]}"),
        "token-get" => (HttpMethod.Get, "/api/v1/auth/token-auth/tokens/token", "{\"token\":" + Token + "}"),
        "token-rename" => (HttpMethod.Patch, "/api/v1/auth/token-auth/tokens/token", "{\"token\":" + Token + "}"),
        _ => (HttpMethod.Post, "/api/v1/auth/token-auth/tokens/token/revoke", """{"message":"revoked"}""")
    };
    private static async Task AssertClosed<T>(ManagementRequest<T> request, ManagementTarget approved,
        HttpMethod method, string path, string response) where T : notnull
    {
        var original = JsonNode.Parse(response)!.AsObject();
        var child = original.FirstOrDefault(property => property.Value is JsonObject or JsonArray).Value;
        foreach (bool nested in child is null ? new[] { false } : new[] { false, true })
        {
            var root = original.DeepClone().AsObject();
            JsonObject selected = root;
            if (nested)
            {
                var value = root.First(property => property.Value is JsonObject or JsonArray).Value!;
                selected = value is JsonArray array ? array[0]!.AsObject() : value.AsObject();
            }
            selected["notDeclared"] = "private-extra";
            using var transport = Transport(new Wire(method, path, root.ToJsonString()));
            var client = new ManagementClient(transport);
            var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
            var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, approved), receipt);
            (result.IsSuccess ? result.Value as IDisposable : null)?.Dispose();
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
            if (receipt is not null)
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
        string envelope = original.FirstOrDefault(property => property.Value is JsonObject or JsonArray).Key ?? "";
        string? uuidField = envelope is "identityUniversalAuth" or "identityTokenAuth" ? "id" :
            envelope == "clientSecretData" ? "identityUAId" : null;
        if (uuidField is not null)
        {
            var root = original.DeepClone().AsObject();
            var value = root[envelope]!;
            var item = value is JsonArray array ? array[0]!.AsObject() : value.AsObject();
            item[uuidField] = "not-a-uuid";
            using var transport = Transport(new Wire(method, path, root.ToJsonString()));
            var client = new ManagementClient(transport);
            var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
            var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, approved), receipt);
            (result.IsSuccess ? result.Value as IDisposable : null)?.Dispose();
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
            if (receipt is not null)
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
    }

    private static async Task<SecretOutcome<T>> Execute<T>(ManagementClient client, ManagementAuthority authority,
        ManagementRequest<T> request, ManagementTarget target) where T : notnull
    {
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        return result;
    }
    private static async Task Denied<T>(ManagementClient client, ManagementAuthority authority, ManagementRequest<T> request,
        ManagementTarget target) where T : notnull
    {
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }
    private static ManagementTransport Transport(Wire handler) => new(new("https://management.test"), 1024 * 1024, null, false, handler);
    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("admin-canary"))));
        }
    }
    private sealed class CommittedWire : HttpMessageHandler
    {
        internal TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _never = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int Requests { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            await request.Content!.ReadAsStringAsync(cancellationToken);
            Committed.TrySetResult();
            await _never.Task.WaitAsync(cancellationToken);
            throw new InvalidOperationException("The committed response barrier must be canceled.");
        }
    }
    private sealed class Wire(HttpMethod method, string path, string response, bool lost = false) : HttpMessageHandler
    {
        public bool Observed { get; private set; }
        public string? Body { get; private set; }
        public int Requests { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Assert.That(request.Method).IsEqualTo(method);
            await Assert.That(request.RequestUri!.AbsoluteUri).IsEqualTo("https://management.test" + path);
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo("admin-canary");
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            Observed = true;
            Requests++;
            if (lost) throw new HttpRequestException("private-canary");
            return new(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }
}
