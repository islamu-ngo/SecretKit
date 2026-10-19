using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalProxyObserverTests
{
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new("https://observer.invalid/owned/"), "service-token", "independent-service", 30);

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task InstalledProxyInputsSelectOnlyExplicitObserver(bool configured)
    {
        var family = new JsonObject();
        if (configured) family["observer"] = JsonSerializer.SerializeToNode(Settings, Json);
        using JsonDocument settings = JsonDocument.Parse(new JsonObject
        {
            ["origin"] = "https://infisical.invalid",
            ["setup"] = "setup",
            ["runtime"] = "runtime",
            ["denied"] = "denied",
            ["administrative"] = "administrative",
            ["observer"] = "observer",
            ["families"] = new JsonObject { ["C08-IM-ProxiedServiceAdministration"] = family }
        }.ToJsonString());
        using var environment = NativeEnvironment.Create(settings.RootElement);
        await Assert.That(InfisicalProxyObserver.FromInputs(environment) is not null).IsEqualTo(configured);
    }

    [Test]
    public async Task ProxyChannelMeasuresSelectedChallengeAndOwnsReturnedMaterial()
    {
        bool prepared = false;
        using var handler = new Handler(async (request, token) =>
        {
            JsonObject body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo("service-token");
            switch (request.RequestUri!.AbsolutePath.Split('/').Last())
            {
                case "prepare":
                    await Assert.That(body["setupToken"]!.GetValue<string>()).IsEqualTo("setup");
                    prepared = true;
                    return Reply(body, new
                    {
                        organizationId = "org",
                        projectId = "project",
                        environment = "env",
                        ownedName = "owned",
                        secretKey = "owned-key",
                        dynamicSecretName = "owned-dynamic",
                        dynamicSecretField = "password",
                        hostPattern = "backend.invalid",
                        expectedValue = "owned-backend-credential"
                    });
                case "send":
                    await Assert.That(prepared).IsTrue();
                    bool allowed = body["selectedToken"]!.GetValue<string>() == "runtime";
                    return Reply(body, new
                    {
                        serviceId = "service",
                        challenge = "selected-challenge",
                        status = allowed ? SecretStatus.Success : SecretStatus.Denied,
                        backendRequests = allowed ? 1 : 0,
                        substitutedValue = allowed ? "owned-backend-credential" : null,
                        observedRole = (ProxiedServiceCredentialRole?)ProxiedServiceCredentialRole.HeaderRewrite,
                        observedSurface = (ProxiedServiceSubstitutionSurface?)ProxiedServiceSubstitutionSurface.Header,
                        headerName = "X-Witness"
                    });
                default:
                    prepared = false;
                    return Reply(body, new
                    {
                        projectId = "project",
                        ownedName = "owned",
                        status = SecretStatus.Success,
                        remainingResources = 0
                    });
            }
        });
        var observer = new InfisicalProxyObserver(new(Settings, handler));
        var setup = new Source("setup");
        var runtime = new Source("runtime");
        var denied = new Source("denied");
        using ProxyCredentialFixture fixture = await observer.PrepareAsync("org", "project", "env", "owned",
            setup, CancellationToken.None);
        using ProxyBackendFacts allowedFacts = await observer.SendThroughAsync("service", "selected-challenge",
            ProxiedServiceCredentialRole.HeaderRewrite, ProxiedServiceSubstitutionSurface.Header, runtime, CancellationToken.None);
        using ProxyBackendFacts deniedFacts = await observer.SendThroughAsync("service", "selected-challenge",
            ProxiedServiceCredentialRole.HeaderRewrite, ProxiedServiceSubstitutionSurface.Header, denied, CancellationToken.None);
        await Assert.That(allowedFacts.SubstitutedValue!.Reveal()).IsEqualTo(fixture.ExpectedValue.Reveal());
        await Assert.That(deniedFacts.BackendRequests).IsEqualTo(0);
        await Assert.That(deniedFacts.SubstitutedValue).IsNull();
        await Assert.That(await observer.RemoveFixtureAsync("project", "owned", setup, CancellationToken.None))
            .IsEqualTo(SecretStatus.Success);
        await Assert.That(prepared).IsFalse();
        allowedFacts.Dispose();
        fixture.Dispose();
        await Assert.That(() => allowedFacts.SubstitutedValue!.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(() => fixture.ExpectedValue.Reveal()).Throws<ObjectDisposedException>();
        foreach (SecretMaterial copy in new[] { setup, runtime, denied }.SelectMany(s => s.Issued))
            await Assert.That(() => copy.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments("challenge")]
    [Arguments("service")]
    [Arguments("role")]
    [Arguments("surface")]
    [Arguments("cleanup")]
    [Arguments("cleanup-missing")]
    public async Task ProxySubstitutionAndCleanupMustMatchOwnedRequest(string mode)
    {
        using var handler = new Handler(async (request, token) =>
        {
            JsonObject body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            object facts = mode.StartsWith("cleanup", StringComparison.Ordinal) ?
                new
                {
                    projectId = "project",
                    ownedName = mode == "cleanup" ? "other" : "owned",
                    status = SecretStatus.Success,
                    remainingResources = 0
                } :
                new
                {
                    serviceId = mode == "service" ? "other" : "service",
                    challenge = mode == "challenge" ? "other" : "selected-challenge",
                    status = SecretStatus.Success,
                    backendRequests = 1,
                    substitutedValue = "owned",
                    observedRole = mode == "role" ? ProxiedServiceCredentialRole.CredentialSubstitution :
                        ProxiedServiceCredentialRole.HeaderRewrite,
                    observedSurface = mode == "surface" ? ProxiedServiceSubstitutionSurface.Body :
                        ProxiedServiceSubstitutionSurface.Header,
                    headerName = "X-Witness"
                };
            JsonNode wire = JsonSerializer.SerializeToNode(facts, Json)!;
            if (mode == "cleanup-missing") wire.AsObject().Remove("remainingResources");
            return Reply(body, wire);
        });
        var observer = new InfisicalProxyObserver(new(Settings, handler));
        var source = new Source("selected");
        await Assert.That(async () =>
        {
            if (mode.StartsWith("cleanup", StringComparison.Ordinal))
                await observer.RemoveFixtureAsync("project", "owned", source, CancellationToken.None);
            else using (await observer.SendThroughAsync("service", "selected-challenge",
                ProxiedServiceCredentialRole.HeaderRewrite, ProxiedServiceSubstitutionSurface.Header, source, CancellationToken.None)) { }
        }).Throws<NativeCaseFailureException>();
        await Assert.That(() => source.Issued.Single().Reveal()).Throws<ObjectDisposedException>();
    }

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
}
