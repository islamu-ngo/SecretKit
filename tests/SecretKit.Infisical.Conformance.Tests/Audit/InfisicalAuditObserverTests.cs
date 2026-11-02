using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalAuditObserverTests
{
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new("https://observer.invalid/owned/"), "service-token", "independent-service", 30);

    [Test]
    [Arguments("{}", 45)]
    [Arguments("{\"caseTimeoutSeconds\":45}", 45)]
    [Arguments("{\"caseTimeoutSeconds\":360}", 360)]
    [Arguments("{\"caseTimeoutSeconds\":900}", 900)]
    public async Task NativeExpiryCaseDeadlineUsesExplicitBoundedInput(string input, int seconds)
    {
        using JsonDocument document = JsonDocument.Parse(input);
        await Assert.That(InfisicalGovernanceFamilies.CaseTimeout(document.RootElement))
            .IsEqualTo(TimeSpan.FromSeconds(seconds));
    }

    [Test]
    [Arguments("0")]
    [Arguments("-1")]
    [Arguments("901")]
    [Arguments("null")]
    [Arguments("true")]
    [Arguments("\"360\"")]
    [Arguments("1.5")]
    public async Task InvalidNativeCaseDeadlineCannotBecomeAnUnboundedWait(string value)
    {
        using JsonDocument document = JsonDocument.Parse("{\"caseTimeoutSeconds\":" + value + "}");
        await Assert.That(() => InfisicalGovernanceFamilies.CaseTimeout(document.RootElement))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task InstalledGovernanceInputsSelectOnlyExplicitObserver(bool configured)
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
            ["families"] = new JsonObject { ["C08-IM-Governance"] = family }
        }.ToJsonString());
        using var environment = NativeEnvironment.Create(settings.RootElement);
        await Assert.That(InfisicalAuditObserver.FromInputs(environment) is not null).IsEqualTo(configured);
    }

    [Test]
    public async Task AuditChannelBindsOwnedScopeEventAndCleanupWithoutRetainingSelectedTokens()
    {
        var seen = new List<string>();
        using var handler = new Handler(async (request, token) =>
        {
            JsonObject body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            string action = request.RequestUri!.AbsolutePath.Split('/').Last();
            seen.Add(action);
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo("service-token");
            object facts;
            switch (action)
            {
                case "provision":
                    await Assert.That(body["setupToken"]!.GetValue<string>()).IsEqualTo("setup");
                    await Assert.That(body["administrativeToken"]!.GetValue<string>()).IsEqualTo("administrative");
                    await Assert.That(body["observerToken"]!.GetValue<string>()).IsEqualTo("observer");
                    facts = new { organizationId = "owned-org", projectId = "owned-project", ownedName = "owned" };
                    break;
                case "trigger":
                    await Assert.That(body["runtimeToken"]!.GetValue<string>()).IsEqualTo("runtime");
                    facts = Trigger("selected-correlation", "owned-project");
                    break;
                case "observe":
                    await Assert.That(body["observerToken"]!.GetValue<string>()).IsEqualTo("observer");
                    await Assert.That(body["eventId"]!.GetValue<string>()).IsEqualTo("selected-event");
                    facts = new
                    {
                        correlation = "selected-correlation",
                        producedEvents = 1,
                        persistedEventIds = new[] { "selected-event" },
                        enabledClasses = new[] { AuditEventClass.Management }
                    };
                    break;
                default:
                    await Assert.That(body["ownedName"]!.GetValue<string>()).IsEqualTo("owned");
                    facts = new { ownedName = "owned", remainingOrganizations = 0, remainingProjects = 0 };
                    break;
            }
            return Reply(body, facts);
        });
        var observer = new InfisicalAuditObserver(new(Settings, handler));
        var setup = new Source("setup");
        var admin = new Source("administrative");
        var runtime = new Source("runtime");
        var measured = new Source("observer");
        OwnedAuditScope scope = await observer.ProvisionAsync("owned", true, setup, admin, measured, CancellationToken.None);
        TriggeredAuditEvent triggered = await observer.TriggerAsync(scope, AuditEventClass.Management,
            "selected-correlation", runtime, CancellationToken.None);
        AuditEventFacts result = await observer.ObserveAsync(scope, triggered, measured, CancellationToken.None);
        await Assert.That(result.PersistedEventIds.Single()).IsEqualTo(triggered.Id);
        AuditCleanupFacts cleanup = await observer.RemoveOwnedAsync("owned", setup, CancellationToken.None);
        await Assert.That(cleanup.RemainingOrganizations + cleanup.RemainingProjects).IsEqualTo(0);
        await Assert.That(seen.SequenceEqual(["provision", "trigger", "observe", "cleanup"])).IsTrue();
        foreach (SecretMaterial copy in new[] { setup, admin, runtime, measured }.SelectMany(s => s.Issued))
            await Assert.That(() => copy.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments("correlation")]
    [Arguments("project")]
    [Arguments("cleanup-name")]
    [Arguments("cleanup-remains")]
    [Arguments("cleanup-missing")]
    public async Task SubstitutedAuditEventOrCleanupCannotBecomeMeasurement(string mode)
    {
        using var handler = new Handler(async (request, token) =>
        {
            JsonObject body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            JsonNode facts = JsonSerializer.SerializeToNode(mode.StartsWith("cleanup", StringComparison.Ordinal) ?
                new
                {
                    ownedName = mode == "cleanup-name" ? "other" : "owned",
                    remainingOrganizations = mode == "cleanup-remains" ? 1 : 0,
                    remainingProjects = 0
                } :
                Trigger(mode == "correlation" ? "other" : "selected-correlation",
                    mode == "project" ? "other" : "owned-project"), Json)!;
            if (mode == "cleanup-missing") facts.AsObject().Remove("remainingProjects");
            return Reply(body, facts);
        });
        var observer = new InfisicalAuditObserver(new(Settings, handler));
        var source = new Source("selected");
        await Assert.That(async () =>
        {
            if (mode.StartsWith("cleanup", StringComparison.Ordinal))
                await observer.RemoveOwnedAsync("owned", source, CancellationToken.None);
            else await observer.TriggerAsync(new("owned-org", "owned-project", "owned"), AuditEventClass.Management,
                "selected-correlation", source, CancellationToken.None);
        }).Throws<NativeCaseFailureException>();
        await Assert.That(() => source.Issued.Single().Reveal()).Throws<ObjectDisposedException>();
    }

    private static object Trigger(string correlation, string projectId) => new
    {
        id = "selected-event",
        correlation,
        organizationId = "owned-org",
        projectId,
        eventClass = AuditEventClass.Management,
        eventType = "create-secret",
        from = DateTimeOffset.UnixEpoch,
        until = DateTimeOffset.UnixEpoch.AddSeconds(1),
        actor = "owned-actor",
        actorType = "identity",
        environment = "env",
        secretKey = "owned-key",
        secretPath = "/owned",
        eventMetadata = "owned-metadata",
        userAgentType = "sdk"
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
}
