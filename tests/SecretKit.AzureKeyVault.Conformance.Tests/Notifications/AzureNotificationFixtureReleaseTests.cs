using System.Net;
using System.Text.Json;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureNotificationFixtureReleaseTests
{
    private const string Vault = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/owned-group/providers/Microsoft.KeyVault/vaults/owned-vault";
    private const string Notification = Vault + "/providers/Microsoft.EventGrid/eventSubscriptions/owned-notification";

    [Test]
    [Arguments("lost", true)]
    [Arguments("lost", false)]
    [Arguments("canceled", true)]
    [Arguments("canceled", false)]
    [Arguments("malformed", true)]
    [Arguments("malformed", false)]
    [Arguments("foreign-lease", true)]
    [Arguments("foreign-lease", false)]
    [Arguments("invalid-facts", true)]
    [Arguments("invalid-facts", false)]
    public async Task OriginalPreparationFailureReleasesOnlyOriginalSelector(string fault, bool absent)
    {
        using var fixture = new Fixture(fault, absent ? "complete" : "remaining");
        Exception? failure = await fixture.Execute();
        await Assert.That(failure is not null || fixture.Probe.Result(fixture.Definition.Key).Passed == false).IsTrue();
        await Assert.That(fixture.Released).IsTrue();
        await Assert.That(fixture.SelectedReached).IsFalse();
        await Assert.That(fixture.ReleaseSelector).IsEqualTo(fixture.Original);
        await Assert.That(fixture.ReleaseCanceled).IsFalse();
        await Assert.That(fixture.Probe.Result(fixture.Definition.Key).ReasonCode == "cleanup-incomplete").IsEqualTo(!absent);
        if (fault == "canceled" && absent)
            await Assert.That(failure is OperationCanceledException).IsTrue();
    }

    [Test]
    [Arguments("complete")]
    [Arguments("foreign-selector")]
    [Arguments("pending")]
    [Arguments("undrained")]
    [Arguments("remaining")]
    [Arguments("missing-owned-absence")]
    [Arguments("extra-absence")]
    [Arguments("borrowed-overlap")]
    [Arguments("duplicate-owned")]
    [Arguments("invalid-owned")]
    [Arguments("null-owned")]
    [Arguments("null-borrowed")]
    [Arguments("null-absent")]
    [Arguments("null-remaining")]
    [Arguments("malformed")]
    [Arguments("lost")]
    public async Task OriginalHandlerRequiresClosedDrainedExactOwnedAbsence(string release)
    {
        using var fixture = new Fixture("lost", release);
        _ = await fixture.Execute();
        await Assert.That(fixture.Released).IsTrue();
        await Assert.That(fixture.ReleaseSelector).IsEqualTo(fixture.Original);
        await Assert.That(fixture.Probe.Result(fixture.Definition.Key).ReasonCode == "cleanup-incomplete")
            .IsEqualTo(release != "complete");
    }

    [Test]
    [Arguments("normal", "complete")]
    [Arguments("normal", "known-owned-mismatch")]
    [Arguments("selected-failure", "complete")]
    [Arguments("selected-canceled", "complete")]
    public async Task ValidLeaseKeepsActualSelectedSdkWorkInsideReleaseProtection(string fault, string release)
    {
        using var fixture = new Fixture(fault, release);
        Exception? failure = await fixture.Execute();
        if (fault == "normal" && release == "complete")
            await Assert.That(failure).IsNull();
        await Assert.That(fixture.SelectedReached).IsTrue();
        await Assert.That(fixture.Released).IsTrue();
        await Assert.That(fixture.ReleaseSelector).IsEqualTo(fixture.Original);
        await Assert.That(fixture.ReleaseCanceled).IsFalse();
        await Assert.That(fixture.SelectedBackend.Disposed).IsFalse();
        if (fault == "selected-canceled")
            await Assert.That(failure is OperationCanceledException).IsTrue();
        else
            await Assert.That(fixture.Probe.Result(fixture.Definition.Key).ReasonCode).IsEqualTo(
                release != "complete" ? "cleanup-incomplete" : fault == "normal" ? "observed" : "contract-mismatch");
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string fault;
        private readonly string release;
        private readonly OwnedAzureEnvironment env;
        private readonly CancellationTokenSource caller = new();
        private readonly HttpClient selectedHttp;
        private readonly HttpClientTransport selectedTransport;
        private readonly NativeCaseRegistry registry = new();
        private readonly Guid leaseId = Guid.NewGuid();
        private readonly Guid subscriptionId = Guid.NewGuid();
        private readonly DateTimeOffset preparedAt = DateTimeOffset.UtcNow;
        private readonly NotificationAdministrationEffects.Configuration configuration =
            new("https://owned.invalid/webhook", [VaultNotificationEvent.SecretNearExpiry], []);
        internal NativeCaseDefinition Definition { get; }
        internal NativeCaseProbe Probe { get; } = new();
        internal FixtureSelector? Original { get; private set; }
        internal FixtureSelector? ReleaseSelector { get; private set; }
        internal bool Released { get; private set; }
        internal bool ReleaseCanceled { get; private set; }
        internal bool SelectedReached { get; private set; }
        internal Backend SelectedBackend { get; }

        internal Fixture(string fault, string release)
        {
            this.fault = fault;
            this.release = release;
            var endpoint = new ObserverEndpoint(new("https://fixture.invalid/"), "private-capability", TimeSpan.FromSeconds(5));
            var identities = new ManagementIdentities(Token("setup-arm"), Token("admin-arm"),
                Token("denied-arm"), Token("observer-arm"));
            var input = new NotificationAdministrationEffects.Input(endpoint, identities,
                Guid.Parse("11111111-1111-1111-1111-111111111111"), "owned-group", "eastus",
                Guid.Parse("22222222-2222-2222-2222-222222222222"), configuration,
                new("private", NotificationAttributeKind.Static, "private-value", true),
                new("public", NotificationAttributeKind.Static, "public-value", false),
                new("dynamic", NotificationAttributeKind.Dynamic, "data.Id", false),
                2, 20, TimeSpan.FromSeconds(5), VaultNotificationEvent.SecretExpired, "unused");
            using var settings = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                vaultUri = "https://owned-vault.vault.azure.net",
                setup = Credential("setup"),
                runtime = Credential("runtime"),
                denied = Credential("denied"),
                administrative = Credential("administrative"),
                observer = Credential("observer"),
                families = new Dictionary<string, object> { ["NotificationAdministration"] = input }
            }, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
            env = OwnedAzureEnvironment.Create(settings.RootElement);
            var member = NotificationAdministrationEffects.Members.Single(m =>
                m.Operation.EndsWith(".GetNotificationFullUrlAsync", StringComparison.Ordinal));
            Definition = new(new("AzureKeyVault", member.Operation, "selector.exact", "controlled",
                "selected-contract"), member.Member);
            SelectedBackend = new(async (request, token) =>
            {
                await Assert.That(request.Method).IsEqualTo(HttpMethod.Post);
                await Assert.That(request.RequestUri!.AbsolutePath).IsEqualTo(Notification + "/getFullUrl");
                await Assert.That(request.RequestUri.Query).IsEqualTo("?api-version=2025-02-15");
                await Assert.That(request.Headers.Authorization?.ToString()).IsEqualTo("Bearer admin-arm");
                SelectedReached = true;
                if (fault == "selected-canceled")
                {
                    // This actual selected dispatch is the barrier before cancellation.
                    caller.Cancel();
                    token.ThrowIfCancellationRequested();
                }
                if (fault == "selected-failure")
                    return new(HttpStatusCode.Forbidden) { Content = new StringContent("{\"error\":{\"code\":\"Forbidden\"}}") };
                return Json(new { endpointUrl = configuration.EndpointUrl });
            });
            selectedHttp = new(SelectedBackend);
            selectedTransport = new(selectedHttp);
            NotificationAdministrationEffects.Register(registry, env, [Definition],
                selected => new(selected, new Backend(Observe)), selectedTransport);
        }

        internal async Task<Exception?> Execute()
        {
            try { await registry.Find(Definition.Key)!.Execute(Probe, caller.Token); return null; }
            catch (Exception exception) { return exception; }
        }

        private async Task<HttpResponseMessage> Observe(HttpRequestMessage request, CancellationToken token)
        {
            using var body = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
            switch (request.RequestUri!.AbsolutePath)
            {
                case "/notification/prepare":
                    Original = body.RootElement.GetProperty("selection").Deserialize<FixtureSelector>(ManagementAdmission.Json)!;
                    if (fault == "lost") throw new HttpRequestException("controlled-response-loss");
                    if (fault == "canceled")
                    {
                        // The Prepare handler has received the original selector before canceling.
                        caller.Cancel();
                        throw new OperationCanceledException(caller.Token);
                    }
                    if (fault == "malformed") return Json(new { });
                    return Json(new NotificationAdministrationEffects.Lease(new(
                        fault == "foreign-lease" ? Guid.NewGuid() : Original.Nonce, leaseId, "source",
                        "https://management.azure.com", fault == "invalid-facts" ? "foreign-revision" : "2025-02-15",
                        preparedAt, [Vault, Notification]), "owned-vault", "owned-notification",
                        configuration, NotificationDestinationKind.WebHook, "selected", "wrong", "unused"));
                case "/notification/arm":
                    return Json(new ObservationSubscription(leaseId, Original!.Nonce, subscriptionId, preparedAt));
                case "/notification/trigger":
                    return Json(new NotificationAdministrationEffects.TriggerReceipt(leaseId, Original!.Nonce,
                        subscriptionId, ["selected-request", "wrong-request"]));
                case "/notification/observe":
                    return Json(new NotificationAdministrationEffects.Measurement(leaseId, Original!.Nonce,
                        subscriptionId, "source", preparedAt, preparedAt,
                        [new("owned-notification", NotificationDestinationKind.WebHook, NativeProvisioningState.Succeeded,
                            SecretStatus.Success, configuration)], [],
                        [new("selected-event", "selected", "owned-notification", Vault,
                            VaultNotificationEvent.SecretNearExpiry, preparedAt, [])],
                        ["wrong"], ["selected-request", "wrong-request"], [],
                        [new("wrong-event", "wrong", "owned-notification", Vault, VaultNotificationEvent.SecretExpired,
                            "wrong-request", preparedAt, NotificationAdministrationEffects.ExclusionKind.FilterNotMatched)]));
                case "/notification/release":
                    Released = true;
                    ReleaseCanceled = token.IsCancellationRequested;
                    ReleaseSelector = body.RootElement.Deserialize<FixtureSelector>(ManagementAdmission.Json)!;
                    if (release == "lost") throw new HttpRequestException("controlled-release-loss");
                    if (release == "malformed") return Json(new { });
                    var measured = new RoleFixtureRelease.Measurement(ReleaseSelector, true, 0,
                        [Vault, Notification], [], [Vault, Notification], []);
                    measured = release switch
                    {
                        "foreign-selector" => measured with { Selector = ReleaseSelector with { Nonce = Guid.NewGuid() } },
                        "pending" => measured with { Closing = false },
                        "undrained" => measured with { ActiveDispatches = 1 },
                        "remaining" => measured with { RemainingResourceIds = [Notification] },
                        "missing-owned-absence" => measured with { AbsentResourceIds = [Vault] },
                        "extra-absence" => measured with { AbsentResourceIds = [Vault, Notification, Vault + "-other"] },
                        "borrowed-overlap" => measured with { BorrowedResourceIds = [Notification] },
                        "duplicate-owned" => measured with { OwnedResourceIds = [Vault, Vault] },
                        "invalid-owned" => measured with { OwnedResourceIds = ["foreign"], AbsentResourceIds = ["foreign"] },
                        "null-owned" => measured with { OwnedResourceIds = null! },
                        "null-borrowed" => measured with { BorrowedResourceIds = null! },
                        "null-absent" => measured with { AbsentResourceIds = null! },
                        "null-remaining" => measured with { RemainingResourceIds = null! },
                        "known-owned-mismatch" => measured with { OwnedResourceIds = [Vault], AbsentResourceIds = [Vault] },
                        _ => measured
                    };
                    return Json(measured);
                default: throw new InvalidOperationException("unexpected-observer-action");
            }
        }

        public void Dispose()
        {
            selectedHttp.Dispose();
            caller.Dispose();
            env.Dispose();
        }
    }

    private static object Credential(string role) => new { token = role, expiresAt = "2099-01-01T00:00:00Z" };
    private static AudienceToken Token(string role) =>
        new(role, new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero), "https://management.azure.com/.default");
    private static HttpResponseMessage Json<T>(T value) => new(HttpStatusCode.OK)
    {
        Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value,
            new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }))
    };
    internal sealed class Backend(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        internal bool Disposed { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token);
        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }
}
