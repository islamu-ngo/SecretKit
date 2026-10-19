using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalGatewayObserverTests
{
    private const string Gateway = "00000000-0000-0000-0000-000000000001";
    private const string Identity = "00000000-0000-0000-0000-000000000002";
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new("https://observer.invalid/owned/"), "service-token", "independent-service", 30);

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task GatewaySelectsOnlyExplicitFamilyRootObserver(bool configured)
    {
        var family = new JsonObject
        {
            ["scopes"] = new JsonObject
            {
                ["owned"] = new JsonObject { ["observer"] = JsonSerializer.SerializeToNode(Settings, Json) }
            }
        };
        if (configured) family["observer"] = JsonSerializer.SerializeToNode(Settings, Json);
        using JsonDocument settings = JsonDocument.Parse(new JsonObject
        {
            ["origin"] = "https://infisical.invalid",
            ["setup"] = "setup",
            ["runtime"] = "runtime",
            ["denied"] = "denied",
            ["administrative"] = "administrative",
            ["observer"] = "observer",
            ["families"] = new JsonObject
            {
                ["C08-IM-GatewayAdministration"] = family,
                ["C08-IM-Governance"] = new JsonObject { ["observer"] = JsonSerializer.SerializeToNode(Settings, Json) }
            }
        }.ToJsonString());
        using var environment = NativeEnvironment.Create(settings.RootElement);
        await Assert.That(InfisicalGatewayObserver.FromInputs(environment) is not null).IsEqualTo(configured);
    }

    [Test]
    public async Task GatewayMeasurementsUseTypedReadSelectedMaterialAndOwnedCleanup()
    {
        await using var sdk = new SdkBackend("owned");
        using var transport = new ManagementTransport(sdk.Origin, allowLoopbackDevelopmentHttp: true);
        var client = new ManagementClient(transport);
        bool exists = true;
        int enrolled = 0;
        DateTimeOffset heartbeat = default;
        using var handler = new Handler(async (request, token) =>
        {
            JsonObject body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo(Settings.Token);
            string action = request.RequestUri!.AbsolutePath.Split('/').Last();
            object facts;
            if (action == "enrollment")
            {
                await Assert.That(body["gatewayId"]!.GetValue<string>()).IsEqualTo(Gateway);
                facts = new { gatewayId = Gateway, issuedTokens = 1, enrolledAgents = enrolled };
            }
            else
            {
                await Assert.That(body["organizationId"]!.GetValue<string>()).IsEqualTo("org");
                await Assert.That(body["ownedName"]!.GetValue<string>()).IsEqualTo("owned");
                if (action == "find")
                {
                    await Assert.That(body["observerToken"]!.GetValue<string>()).IsEqualTo("observer");
                    facts = Lookup(exists);
                }
                else if (action == "cleanup")
                {
                    await Assert.That(body["setupToken"]!.GetValue<string>()).IsEqualTo("setup");
                    exists = false;
                    facts = Cleanup();
                }
                else
                {
                    await Assert.That(body["runtimeToken"]!.GetValue<string>()).IsEqualTo("runtime");
                    await Assert.That(body["gatewayId"]!.GetValue<string>()).IsEqualTo(Gateway);
                    await Assert.That(body["identityId"]!.GetValue<string>()).IsEqualTo(Identity);
                    await Assert.That(body["authentication"]!.GetValue<int>()).IsEqualTo((int)GatewayAuthenticationMethod.Token);
                    heartbeat = DateTimeOffset.UtcNow;
                    if (action == "enroll")
                    {
                        await Assert.That(body["enrollmentToken"]!.GetValue<string>()).IsEqualTo("owned-enrollment");
                        enrolled++;
                    }
                    facts = Agent(heartbeat, action == "enroll" ? Fingerprint : null);
                }
            }
            return Reply(body, facts);
        });
        var observer = new InfisicalGatewayObserver(new(Settings, handler), client);
        var measured = new Source("observer");
        var runtime = new Source("runtime");
        var setup = new Source("setup");
        SecretOutcome<GatewaySummary> found = await observer.FindOwnedAsync("org", "owned", measured, CancellationToken.None);
        await Assert.That(found.IsSuccess).IsTrue();
        await Assert.That(found.Value.Id).IsEqualTo(Gateway);
        await Assert.That(sdk.Path).IsEqualTo("/api/v3/gateways/" + Gateway);
        await Assert.That(sdk.Bearer).IsEqualTo("Bearer observer");
        GatewayAgentFacts authenticated = await observer.AuthenticateAsync("org", found.Value, runtime, CancellationToken.None);
        await Assert.That(authenticated.Heartbeat).IsEqualTo(heartbeat);
        GatewayEnrollmentFacts before = await observer.ObserveEnrollmentAsync(Gateway, CancellationToken.None);
        using var enrollment = SecretMaterial.FromText("owned-enrollment");
        GatewayAgentFacts accepted = await observer.EnrollAsync("org", found.Value, enrollment, runtime, CancellationToken.None);
        await Assert.That(accepted.IdentityId).IsEqualTo(Identity);
        await Assert.That(accepted.Heartbeat).IsEqualTo(heartbeat);
        await Assert.That(enrollment.Reveal()).IsEqualTo("owned-enrollment");
        GatewayEnrollmentFacts after = await observer.ObserveEnrollmentAsync(Gateway, CancellationToken.None);
        await Assert.That(after.EnrolledAgents).IsEqualTo(before.EnrolledAgents + 1);
        await Assert.That(after.IssuedTokens).IsEqualTo(before.IssuedTokens);
        await Assert.That(await observer.RemoveOwnedAsync("org", "owned", setup, CancellationToken.None))
            .IsEqualTo(SecretStatus.Success);
        await Assert.That((await observer.FindOwnedAsync("org", "owned", measured, CancellationToken.None)).Status)
            .IsEqualTo(SecretStatus.Absent);
        foreach (SecretMaterial copy in new[] { measured, runtime, setup }.SelectMany(s => s.Issued))
            await Assert.That(() => copy.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(authenticated.ToString()).IsEqualTo("[GatewayAgentFacts]");
        await Assert.That(after.ToString()).IsEqualTo("[GatewayEnrollmentFacts]");
    }

    [Test]
    [Arguments("organization")]
    [Arguments("name")]
    [Arguments("gateway")]
    [Arguments("identity")]
    [Arguments("authentication")]
    [Arguments("heartbeat")]
    [Arguments("accepted")]
    [Arguments("enrollment-token")]
    [Arguments("enrollment-gateway")]
    [Arguments("enrollment-count")]
    [Arguments("cleanup-organization")]
    [Arguments("cleanup-name")]
    [Arguments("cleanup-gateways")]
    [Arguments("cleanup-agents")]
    [Arguments("cleanup-tokens")]
    [Arguments("cleanup-status")]
    [Arguments("cleanup-missing")]
    public async Task GatewayRejectsSubstitutedMeasurementsAndIncompleteCleanup(string mode)
    {
        await using var sdk = new SdkBackend("owned");
        using var transport = new ManagementTransport(sdk.Origin, allowLoopbackDevelopmentHttp: true);
        var client = new ManagementClient(transport);
        var source = new Source("selected");
        using ManagementRequest<GatewaySummary> request = GatewayAdministrationOperations.Get("org", Gateway);
        var authority = new ManagementAuthority(client.Authority, source, "org");
        var found = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target));
        await Assert.That(found.IsSuccess).IsTrue();
        using var handler = new Handler(async (message, token) =>
        {
            JsonObject body = JsonNode.Parse(await message.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            JsonObject facts = JsonSerializer.SerializeToNode(mode.StartsWith("cleanup", StringComparison.Ordinal) ?
                Cleanup() : mode.StartsWith("enrollment-", StringComparison.Ordinal) && mode != "enrollment-token" ?
                new { gatewayId = Gateway, issuedTokens = 1, enrolledAgents = 1 } :
                Agent(DateTimeOffset.UtcNow, mode == "enrollment-token" ? Fingerprint : null), Json)!.AsObject();
            switch (mode)
            {
                case "organization": case "cleanup-organization": facts["organizationId"] = "other"; break;
                case "name": case "cleanup-name": facts["ownedName"] = "other"; break;
                case "gateway": case "enrollment-gateway": facts["gatewayId"] = Identity; break;
                case "identity": facts["identityId"] = Gateway; break;
                case "authentication": facts["authentication"] = (int)GatewayAuthenticationMethod.Aws; break;
                case "heartbeat": facts["heartbeat"] = DateTimeOffset.UnixEpoch; break;
                case "accepted": facts["acceptedAuthentications"] = 0; break;
                case "enrollment-token": facts["enrollmentFingerprint"] = "other"; break;
                case "enrollment-count": facts["issuedTokens"] = -1; break;
                case "cleanup-gateways": facts["remainingGateways"] = 1; break;
                case "cleanup-agents": facts["remainingAgents"] = 1; break;
                case "cleanup-tokens": facts["remainingEnrollmentTokens"] = 1; break;
                case "cleanup-status": facts["status"] = (int)SecretStatus.Denied; break;
                case "cleanup-missing": facts.Remove("remainingAgents"); break;
            }
            return Reply(body, facts);
        });
        var observer = new InfisicalGatewayObserver(new(Settings, handler), client);
        using var material = SecretMaterial.FromText("owned-enrollment");
        await Assert.That(async () =>
        {
            if (mode.StartsWith("cleanup", StringComparison.Ordinal))
                await observer.RemoveOwnedAsync("org", "owned", source, CancellationToken.None);
            else if (mode == "enrollment-token")
                await observer.EnrollAsync("org", found.Value, material, source, CancellationToken.None);
            else if (mode.StartsWith("enrollment-", StringComparison.Ordinal))
                await observer.ObserveEnrollmentAsync(Gateway, CancellationToken.None);
            else await observer.AuthenticateAsync("org", found.Value, source, CancellationToken.None);
        }).Throws<NativeCaseFailureException>();
        await Assert.That(material.Reveal()).IsEqualTo("owned-enrollment");
        foreach (SecretMaterial copy in source.Issued)
            await Assert.That(() => copy.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments("organization")]
    [Arguments("name")]
    [Arguments("id")]
    [Arguments("absent-id")]
    [Arguments("status")]
    [Arguments("sdk-name")]
    public async Task GatewayLookupRejectsSubstitutedOwnershipBeforeReturningSdkSummary(string mode)
    {
        await using var sdk = new SdkBackend(mode == "sdk-name" ? "other" : "owned");
        using var transport = new ManagementTransport(sdk.Origin, allowLoopbackDevelopmentHttp: true);
        using var handler = new Handler(async (message, token) =>
        {
            JsonObject body = JsonNode.Parse(await message.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            return Reply(body, new
            {
                organizationId = mode == "organization" ? "other" : "org",
                ownedName = mode == "name" ? "other" : "owned",
                status = mode == "absent-id" ? SecretStatus.Absent : mode == "status" ? SecretStatus.Denied : SecretStatus.Success,
                gatewayId = mode == "id" ? "invalid" : Gateway
            });
        });
        var observer = new InfisicalGatewayObserver(new(Settings, handler), new(transport));
        var source = new Source("observer");
        await Assert.That(async () => await observer.FindOwnedAsync("org", "owned", source, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(sdk.Path is not null).IsEqualTo(mode == "sdk-name");
        foreach (SecretMaterial copy in source.Issued)
            await Assert.That(() => copy.Reveal()).Throws<ObjectDisposedException>();
    }

    private static string Fingerprint => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("owned-enrollment")));
    private static object Lookup(bool exists) => new
    {
        organizationId = "org",
        ownedName = "owned",
        status = exists ? SecretStatus.Success : SecretStatus.Absent,
        gatewayId = exists ? Gateway : null
    };
    private static object Agent(DateTimeOffset heartbeat, string? fingerprint) => new
    {
        organizationId = "org",
        ownedName = "owned",
        gatewayId = Gateway,
        identityId = Identity,
        authentication = GatewayAuthenticationMethod.Token,
        heartbeat,
        acceptedAuthentications = 1,
        enrollmentFingerprint = fingerprint
    };
    private static object Cleanup() => new
    {
        organizationId = "org",
        ownedName = "owned",
        status = SecretStatus.Success,
        remainingGateways = 0,
        remainingAgents = 0,
        remainingEnrollmentTokens = 0
    };
    private static HttpResponseMessage Reply(JsonObject request, object facts) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            nonce = request["nonce"]!.GetValue<string>(),
            observerIdentity = Settings.Identity,
            observedAt = DateTimeOffset.UtcNow,
            facts
        }, Json))
    };
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) =>
            send(request, token);
    }
    private sealed class Source(string token) : IInfisicalTokenSource
    {
        internal List<SecretMaterial> Issued { get; } = [];
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var copy = SecretMaterial.FromText(token);
            Issued.Add(copy);
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(copy)));
        }
    }

    // One actual SDK GET through a public host-owned transport. Vendor response
    // fixtures stay in the host test, never in installed Admission code.
    private sealed class SdkBackend : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stop = new(TimeSpan.FromSeconds(10));
        private readonly Task serving;
        internal Uri Origin { get; }
        internal string? Path { get; private set; }
        internal string? Bearer { get; private set; }

        internal SdkBackend(string name)
        {
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            serving = ServeAsync(name);
        }

        private async Task ServeAsync(string name)
        {
            try
            {
                using TcpClient connection = await listener.AcceptTcpClientAsync(stop.Token);
                NetworkStream stream = connection.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                string first = (await reader.ReadLineAsync(stop.Token))!;
                Path = first.Split(' ')[1];
                string? line;
                while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(stop.Token)))
                    if (line.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))
                        Bearer = line["Authorization:".Length..].Trim();
                byte[] response = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    id = Gateway,
                    name,
                    createdAt = DateTimeOffset.UnixEpoch,
                    updatedAt = DateTimeOffset.UnixEpoch,
                    canRevoke = true,
                    identityId = Identity,
                    authMethod = new { method = "token", config = new { } }
                }, Json);
                byte[] header = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                    response.Length.ToString(CultureInfo.InvariantCulture) + "\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(header, stop.Token);
                await stream.WriteAsync(response, stop.Token);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }

        public async ValueTask DisposeAsync()
        {
            await stop.CancelAsync();
            try { await serving; }
            finally { listener.Stop(); stop.Dispose(); }
        }
    }
}
