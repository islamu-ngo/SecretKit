using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class GatewayAdministrationTests
{
    private const string Org = "org-private";
    private const string Id = "7b15ac64-78ee-4fa5-a7b4-eb2da9ac5796";
    private const string Name = "gateway-private";

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task ActualManagementBindingsReturnEstablishedContracts(int route)
    {
        using var auth = GatewayAuthenticationInput.Token();
        using var wire = new Wire(route == 3 ? """{"token":"enrollment-private","expiresAt":"2026-10-10T00:00:00Z"}""" : Metadata("token").ToJsonString());
        using var transport = new ManagementTransport(new("https://management.test"), 65536, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        if (route == 3)
        {
            using var request = GatewayAdministrationOperations.GenerateEnrollmentToken(Org, Id);
            var receipt = client.CreateReceipt(request);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(
                "infisical.post.v3.gateways.by.gatewayId.token.auth.generate.enrollment.token", new(Org, resourceId: Id)), receipt);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            using var token = result.Value;
            await Assert.That(token.Material.Reveal()).IsEqualTo("enrollment-private");
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            await Assert.That(wire.LastPath).IsEqualTo("/api/v3/gateways/" + Id + "/token-auth/generate-enrollment-token");
            await Assert.That((await client.ExecuteAsync(request, authority, authority.IssueGrant(
                request.OperationId, new(Org, resourceId: Id)), receipt)).Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(wire.Revision).IsEqualTo(1);
        }
        else
        {
            using var request = route switch
            {
                0 => GatewayAdministrationOperations.Create(Org, new(Name, auth)),
                1 => GatewayAdministrationOperations.Get(Org, Id),
                _ => GatewayAdministrationOperations.Update(Org, Id, new(Name, auth))
            };
            var target = route switch
            {
                0 => GatewayAdministrationOperations.CreationTarget(Org, new(Name, auth)),
                1 => new ManagementTarget(Org, resourceId: Id),
                _ => GatewayAdministrationOperations.UpdateTarget(Org, Id, new(Name, auth))
            };
            var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(result.Value.Id).IsEqualTo(Id);
            await Assert.That(wire.LastPath).IsEqualTo(route == 0 ? "/api/v3/gateways" : "/api/v3/gateways/" + Id);
            if (route != 1)
            {
                await Assert.That(wire.Stored!["name"]!.GetValue<string>()).IsEqualTo(Name);
                await Assert.That(wire.Stored["authMethod"]!["method"]!.GetValue<string>()).IsEqualTo("token");
                await Assert.That(receipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
                await Assert.That((await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt)).Status).IsEqualTo(SecretStatus.Invalid);
                await Assert.That(wire.Revision).IsEqualTo(1);
            }
        }
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task HandwrittenBuildersUseExactRoutes(int route)
    {
        using var http = new HttpClient { BaseAddress = new("https://management.test") };
        var api = RestService.For<IGatewayAdministrationApi>(http);
        using var body = new StringContent("{}");
        using var message = await (route switch
        {
            0 => api.Create(body, default),
            1 => api.Get(Id, default),
            2 => api.Update(Id, body, default),
            _ => api.GenerateEnrollmentToken(Id, default)
        });
        await Assert.That(message.Method).IsEqualTo(route switch { 1 => HttpMethod.Get, 2 => HttpMethod.Patch, _ => HttpMethod.Post });
        await Assert.That(new Uri(http.BaseAddress!, message.RequestUri!).PathAndQuery).IsEqualTo(route switch
        {
            0 => "/api/v3/gateways",
            3 => "/api/v3/gateways/" + Id + "/token-auth/generate-enrollment-token",
            _ => "/api/v3/gateways/" + Id
        });
    }

    [Test]
    [Arguments("aws")]
    [Arguments("gcp")]
    [Arguments("kubernetes")]
    [Arguments("token")]
    [Arguments("identity")]
    public async Task IndependentlyPublishedSuccessVariantsRemainProtected(string method)
    {
        JsonObject fixture = Metadata(method);
        using var request = GatewayAdministrationOperations.Get(Org, Id);
        using var json = JsonDocument.Parse(fixture.ToJsonString());
        var result = request.Parse(json.RootElement);
        await Assert.That(result.Id).IsEqualTo(Id);
        await Assert.That(result.Authentication.Method.ToString().ToLowerInvariant()).IsEqualTo(method);
        await Assert.That(result.HeartbeatTTL).IsEqualTo(2.5);
        await Assert.That(result.HasDirectAddress).IsTrue();
        await Assert.That(result.DirectAddress).IsNull();
        if (method == "identity") await Assert.That(result.Authentication.IdentityName).IsNull();
        if (method == "gcp") await Assert.That(result.Authentication.Type).IsEqualTo("future-provider-type");
        if (method == "kubernetes")
        {
            await Assert.That(result.Authentication.TokenReviewMode).IsEqualTo("future-mode");
            await Assert.That(result.Authentication.VerifyTlsCertificate).IsFalse();
        }
        fixture["heartbeatTTL"] = null;
        using var nullable = JsonDocument.Parse(fixture.ToJsonString());
        await Assert.That(request.Parse(nullable.RootElement).HasHeartbeatTTL).IsTrue();
        fixture.Remove("heartbeatTTL");
        using var omitted = JsonDocument.Parse(fixture.ToJsonString());
        await Assert.That(request.Parse(omitted.RootElement).HasHeartbeatTTL).IsFalse();
        foreach (object value in new object[] { result, result.Authentication, request })
        {
            await Assert.That(value.ToString()!.Contains("private", StringComparison.Ordinal)).IsFalse();
            await Assert.That(JsonSerializer.Serialize(value).Contains("private", StringComparison.Ordinal)).IsFalse();
        }
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(6)]
    [Arguments(7)]
    public async Task InputAlternativesOwnMaterialAndExactIndependentHashes(int variant)
    {
        using var jwt = SecretMaterial.FromText("jwt-private");
        using var input = Input(variant, jwt);
        jwt.Dispose();
        using var request = GatewayAdministrationOperations.Create(Org, new(Name, input));
        using var independentJwt = SecretMaterial.FromText("jwt-private");
        using var independent = Input(variant, independentJwt);
        var target = GatewayAdministrationOperations.CreationTarget(Org, new(Name, independent));
        await Assert.That(request.Target.SecondaryId).IsEqualTo(target.SecondaryId);
        using var different = GatewayAuthenticationInput.Aws("different-private");
        await Assert.That(request.Target.SecondaryId == GatewayAdministrationOperations.CreationTarget(Org, new(Name, different)).SecondaryId).IsFalse();
        input.Dispose();
        byte[] bytes = request.CopyBody()!;
        try
        {
            using var json = JsonDocument.Parse(bytes);
            JsonElement auth = json.RootElement.GetProperty("authMethod");
            if (variant == 0) await Assert.That(auth.TryGetProperty("allowedAccountIds", out _)).IsFalse();
            if (variant == 1) await Assert.That(auth.GetProperty("allowedAccountIds").GetString()).IsEqualTo("");
            if (variant == 2) await Assert.That(auth.GetProperty("type").GetString()).IsEqualTo("iam");
            if (variant == 6) await Assert.That(auth.TryGetProperty("type", out _)).IsFalse();
            if (variant == 7) await Assert.That(auth.GetProperty("type").GetString()).IsEqualTo("gce");
            if (variant == 3)
            {
                await Assert.That(auth.GetProperty("tokenReviewerJwt").GetString()).IsEqualTo("jwt-private");
                await Assert.That(auth.GetProperty("gatewayId").ValueKind).IsEqualTo(JsonValueKind.Null);
                await Assert.That(auth.GetProperty("gatewayPoolId").GetString()).IsEqualTo(Id);
                await Assert.That(auth.GetProperty("verifyTlsCertificate").GetBoolean()).IsFalse();
            }
            if (variant == 5)
            {
                await Assert.That(auth.TryGetProperty("tokenReviewMode", out _)).IsFalse();
                await Assert.That(auth.TryGetProperty("verifyTlsCertificate", out _)).IsFalse();
            }
        }
        finally { Array.Clear(bytes); }
        await Assert.That(() => GatewayAdministrationOperations.Create(Org, new(Name, input))).Throws<ObjectDisposedException>();
        request.Dispose();
        await Assert.That(() => request.CopyBody()).Throws<ObjectDisposedException>();
        using var empty = GatewayAdministrationOperations.Update(Org, Id, new());
        byte[] patch = empty.CopyBody()!;
        try { await Assert.That(System.Text.Encoding.UTF8.GetString(patch)).IsEqualTo("{}"); }
        finally { Array.Clear(patch); }
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(6)]
    [Arguments(7)]
    [Arguments(8)]
    [Arguments(9)]
    public async Task InvalidPublishedInputBoundsAndEnumsFailLocally(int defect)
    {
        Action action = () =>
        {
            using var auth = defect switch
            {
                0 => GatewayAuthenticationInput.Aws(new string('x', 4097)),
                1 => GatewayAuthenticationInput.Gcp(allowedZones: new string('x', 1025)),
                2 => GatewayAuthenticationInput.Gcp(type: (GatewayGcpType)99),
                3 => GatewayAuthenticationInput.Kubernetes("", "", allowedAudience: new string('x', 256)),
                4 => GatewayAuthenticationInput.Kubernetes("", "", caCertificate: new string('x', 10241)),
                5 => GatewayAuthenticationInput.Kubernetes("", "", kubernetesHost: ""),
                6 => GatewayAuthenticationInput.Kubernetes("", "", tokenReviewMode: (GatewayTokenReviewMode)99),
                _ => GatewayAuthenticationInput.Token()
            };
            if (defect == 7) _ = new GatewayNullableId("invalid-private");
            if (defect == 8) _ = new GatewayCreation("", auth);
            if (defect == 9) _ = GatewayAdministrationOperations.Get(Org, "invalid-private");
        };
        await Assert.That(action).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    public async Task RequiredAndScopedResponseFailuresAreBounded(int defect)
    {
        var fixture = Metadata("kubernetes");
        switch (defect)
        {
            case 0: fixture.Remove("canRevoke"); break;
            case 1: fixture["id"] = "another-private"; break;
            case 2: fixture["createdAt"] = "invalid-private"; break;
            case 3: fixture["authMethod"]!["config"]!.AsObject().Remove("gatewayId"); break;
            case 4: fixture["heartbeatTTL"] = "invalid-private"; break;
            case 5: fixture["authMethod"]!["method"] = "unsupported-private"; break;
        }
        using var request = GatewayAdministrationOperations.Get(Org, Id);
        using var json = JsonDocument.Parse(fixture.ToJsonString());
        await Assert.That(() => request.Parse(json.RootElement)).Throws<ManagementContractException>();
    }

    [Test]
    public async Task EnrollmentMaterialIsCopiedProtectedAndDisposable()
    {
        using var request = GatewayAdministrationOperations.GenerateEnrollmentToken(Org, Id);
        using var json = JsonDocument.Parse("""{"token":"enrollment-private","expiresAt":"2026-10-10T00:00:00Z"}""");
        using var result = request.Parse(json.RootElement);
        json.Dispose();
        await Assert.That(result.Material.Reveal()).IsEqualTo("enrollment-private");
        await Assert.That(JsonSerializer.Serialize(result)).IsEqualTo("{}");
        result.Dispose();
        await Assert.That(() => result.Material.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task OptionalGatewayOutputKeepsOmissionNullAndSuppliedValues(int variant)
    {
        var metadata = Metadata("token");
        foreach (string field in new[] { "directAddress", "directHeartbeat", "heartbeat", "heartbeatTTL", "identityId", "relayId" })
            metadata.Remove(field);
        if (variant > 0)
        {
            metadata["directAddress"] = variant == 1 ? null : "direct-private";
            metadata["directHeartbeat"] = variant == 1 ? null : "2026-10-10T00:00:00Z";
            metadata["heartbeat"] = variant == 1 ? null : "2026-10-10T00:00:00Z";
            metadata["heartbeatTTL"] = variant == 1 ? null : 2.5;
            metadata["identityId"] = variant == 1 ? null : Id;
            metadata["relayId"] = variant == 1 ? null : Id;
        }
        using var request = GatewayAdministrationOperations.Get(Org, Id);
        using var json = JsonDocument.Parse(metadata.ToJsonString());
        var value = request.Parse(json.RootElement);
        await Assert.That(value.HasDirectAddress).IsEqualTo(variant > 0);
        await Assert.That(value.HasDirectHeartbeat).IsEqualTo(variant > 0);
        await Assert.That(value.HasHeartbeat).IsEqualTo(variant > 0);
        await Assert.That(value.HasHeartbeatTTL).IsEqualTo(variant > 0);
        await Assert.That(value.HasIdentityId).IsEqualTo(variant > 0);
        await Assert.That(value.HasRelayId).IsEqualTo(variant > 0);
        await Assert.That(value.HeartbeatTTL).IsEqualTo(variant == 2 ? 2.5 : null);
        await Assert.That(value.IdentityId).IsEqualTo(variant == 2 ? Id : null);
    }

    [Test]
    public async Task PublishedGatewayInputMaximumsAndEmptyJwtRemainEstablished()
    {
        using var jwt = SecretMaterial.FromText(new string('x', 8192));
        using var input = GatewayAuthenticationInput.Kubernetes(new string('x', 1024), new string('x', 1024),
            new string('x', 255), new string('x', 10240), new(Id), new(null), new string('x', 255), jwt,
            GatewayTokenReviewMode.Api, true);
        using var request = GatewayAdministrationOperations.Create(Org, new(new string('n', 64), input));
        byte[] bytes = request.CopyBody()!;
        try
        {
            using var json = JsonDocument.Parse(bytes);
            await Assert.That(json.RootElement.GetProperty("authMethod").GetProperty("tokenReviewerJwt").GetString()!.Length).IsEqualTo(8192);
        }
        finally { Array.Clear(bytes); }
        using var empty = SecretMaterial.FromText("");
        using var emptyInput = GatewayAuthenticationInput.Kubernetes("", "", tokenReviewerJwt: empty);
        using var emptyRequest = GatewayAdministrationOperations.Create(Org, new(Name, emptyInput));
        await Assert.That(JsonSerializer.Serialize(input)).IsEqualTo("{}");
        await Assert.That(input.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
        using var oversized = SecretMaterial.FromText(new string('x', 8193));
        await Assert.That(() => GatewayAuthenticationInput.Kubernetes("", "", tokenReviewerJwt: oversized)).Throws<ArgumentException>();
    }

    [Test]
    public async Task GatewayPreCancellationAndMissingReceiptNeverAcquireOrDispatch()
    {
        using var wire = new Wire(Metadata("token").ToJsonString());
        using var transport = new ManagementTransport(new("https://management.test"), 65536, null, false, wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        using var request = GatewayAdministrationOperations.GenerateEnrollmentToken(Org, Id);
        var grant = authority.IssueGrant(request.OperationId, new(Org, resourceId: Id));
        var receipt = client.CreateReceipt(request);
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        await Assert.That(async () => await client.ExecuteAsync(request, authority, grant, receipt, cancel.Token)).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That((await client.ExecuteAsync(request, authority, grant)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Revision).IsEqualTo(0);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task IndependentGrantRejectsScopeOriginOperationAndBodyTampering(int defect)
    {
        using var auth = GatewayAuthenticationInput.Token();
        using var request = GatewayAdministrationOperations.Create(Org, new(Name, auth));
        using var wire = new Wire(Metadata("token").ToJsonString());
        using var transport = new ManagementTransport(new("https://management.test"), 65536, null, false, wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        var target = GatewayAdministrationOperations.CreationTarget(Org, new(defect == 3 ? "changed-private" : Name, auth));
        if (defect == 0) target = new(Org, resourceId: "other-private", secondaryId: target.SecondaryId);
        var issuer = defect == 1 ? new ManagementAuthority(new(), tokens, Org) : authority;
        var grant = issuer.IssueGrant(defect == 2 ? "infisical.patch.v3.gateways.by.gatewayId" : request.OperationId, target);
        var result = await client.ExecuteAsync(request, authority, grant, client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Revision).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CommittedLossAndCancellationRetainUnknownWithoutReplay(bool cancel)
    {
        using var wire = new Wire(Metadata("token").ToJsonString()) { Lost = !cancel, Hold = cancel };
        using var transport = new ManagementTransport(new("https://management.test"), 65536, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var auth = GatewayAuthenticationInput.Token();
        using var request = GatewayAdministrationOperations.Create(Org, new(Name, auth));
        var target = GatewayAdministrationOperations.CreationTarget(Org, new(Name, auth));
        var grant = authority.IssueGrant(request.OperationId, target);
        var receipt = client.CreateReceipt(request);
        using var cancellation = new CancellationTokenSource();
        if (cancel)
        {
            Task committed = wire.Committed.Task;
            Task result = client.ExecuteAsync(request, authority, grant, receipt, cancellation.Token).AsTask();
            await Task.WhenAny(committed, result).WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(committed.IsCompletedSuccessfully).IsTrue();
            await committed.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Cancel();
            await Assert.That(async () => await result).Throws<OperationCanceledException>();
        }
        else await Assert.That((await client.ExecuteAsync(request, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That((await client.ExecuteAsync(request, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    private static GatewayAuthenticationInput Input(int variant, SecretMaterial jwt) => variant switch
    {
        0 => GatewayAuthenticationInput.Aws(),
        1 => GatewayAuthenticationInput.Aws("", "arn-private"),
        2 => GatewayAuthenticationInput.Gcp("", "service-private", "zone-private", GatewayGcpType.Iam),
        3 => GatewayAuthenticationInput.Kubernetes("", "", "", "", new(null), new(Id), "host-private", jwt, GatewayTokenReviewMode.Gateway, false),
        4 => GatewayAuthenticationInput.Token(),
        6 => GatewayAuthenticationInput.Gcp(),
        7 => GatewayAuthenticationInput.Gcp(type: GatewayGcpType.Gce),
        _ => GatewayAuthenticationInput.Kubernetes("", "")
    };

    private static JsonObject Metadata(string method)
    {
        JsonObject config = method switch
        {
            "aws" => new() { ["allowedAccountIds"] = "account-private", ["allowedPrincipalArns"] = "" },
            "gcp" => new() { ["allowedProjects"] = "", ["allowedServiceAccounts"] = "", ["allowedZones"] = "", ["type"] = "future-provider-type" },
            "identity" => new() { ["identityId"] = "identity-private", ["identityName"] = null },
            "kubernetes" => new()
            {
                ["allowedAudience"] = "",
                ["allowedNames"] = "",
                ["allowedNamespaces"] = "",
                ["caCertificate"] = "",
                ["gatewayId"] = null,
                ["gatewayPoolId"] = "pool-private",
                ["hasTokenReviewerJwt"] = true,
                ["kubernetesHost"] = "host-private",
                ["tokenReviewMode"] = "future-mode",
                ["verifyTlsCertificate"] = false
            },
            _ => new()
        };
        if (method is "aws" or "gcp" or "kubernetes")
        {
            config["id"] = Id;
            config["createdAt"] = "2026-10-10T00:00:00Z";
            config["updatedAt"] = "2026-10-10T00:00:00Z";
        }
        return new()
        {
            ["id"] = Id,
            ["name"] = Name,
            ["createdAt"] = "2026-10-10T00:00:00Z",
            ["updatedAt"] = "2026-10-10T00:00:00Z",
            ["canRevoke"] = true,
            ["authMethod"] = new JsonObject { ["method"] = method, ["config"] = config },
            ["directAddress"] = null,
            ["heartbeatTTL"] = 2.5,
            ["identityId"] = null,
            ["relayId"] = Id
        };
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
        }
    }

    private sealed class Wire(string response) : HttpMessageHandler
    {
        public string? LastPath { get; private set; }
        public JsonObject? Stored { get; private set; }
        public int Revision { get; private set; }
        public bool Lost { get; init; }
        public bool Hold { get; init; }
        public TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastPath = request.RequestUri!.PathAndQuery;
            if (request.RequestUri.GetLeftPart(UriPartial.Authority) != "https://management.test" ||
                request.Headers.Authorization?.Scheme != "Bearer") return new(HttpStatusCode.Unauthorized);
            if (request.Content is not null) Stored = JsonNode.Parse(await request.Content.ReadAsStringAsync(cancellationToken))!.AsObject();
            if (request.Method != HttpMethod.Get) Revision++;
            Committed.TrySetResult();
            if (Hold) await Release.Task.WaitAsync(cancellationToken);
            if (Lost) throw new IOException("Lost response.");
            return new(HttpStatusCode.OK) { Content = new StringContent(response, System.Text.Encoding.UTF8, "application/json") };
        }
    }
}
