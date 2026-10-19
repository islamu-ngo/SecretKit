using System.Net;
using System.Text.Json;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureManagementFixtureReleaseTests
{
    [Test]
    [Arguments("vault", "lost", true)]
    [Arguments("vault", "lost", false)]
    [Arguments("vault", "malformed", true)]
    [Arguments("vault", "malformed", false)]
    [Arguments("vault", "foreign-lease", true)]
    [Arguments("vault", "foreign-lease", false)]
    [Arguments("vault", "invalid-facts", true)]
    [Arguments("vault", "invalid-facts", false)]
    [Arguments("vault", "canceled", true)]
    [Arguments("vault", "canceled", false)]
    [Arguments("operation", "lost", true)]
    [Arguments("operation", "lost", false)]
    [Arguments("operation", "malformed", true)]
    [Arguments("operation", "malformed", false)]
    [Arguments("operation", "foreign-lease", true)]
    [Arguments("operation", "foreign-lease", false)]
    [Arguments("operation", "invalid-facts", true)]
    [Arguments("operation", "invalid-facts", false)]
    [Arguments("operation", "canceled", true)]
    [Arguments("operation", "canceled", false)]
    public async Task OriginalPreparationFailureReleasesOriginalSelectorWithoutLeaseAuthority(
        string family, string fault, bool absent)
    {
        string directory = Path.Combine(Path.GetTempPath(), "management-release-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var subscription = Guid.Parse("11111111-1111-1111-1111-111111111111");
            var tenant = Guid.Parse("22222222-2222-2222-2222-222222222222");
            var configuration = new VaultAdministrationEffects.Configuration(
                "eastus", tenant, VaultSku.Standard, true, false, 7, true, []);
            var endpoint = new ObserverEndpoint(new("https://fixture.invalid/"),
                "private-capability", TimeSpan.FromSeconds(5));
            var arm = new ManagementIdentities(Token("setup-arm"), Token("admin-arm"),
                Token("denied-arm"), Token("observer-arm"));
            object input = family == "vault"
                ? new VaultAdministrationEffects.Input(endpoint, arm, subscription, "owned-group",
                    configuration, [], Guid.NewGuid(), 2, 20, TimeSpan.FromSeconds(5))
                : new ManagementOperationEffects.Input(endpoint, arm, subscription, "owned-group",
                    "eastus", tenant, VaultSku.Standard, 7, ManagementMutation.CreateOrUpdateVault,
                    "https://owned.invalid/webhook", Guid.NewGuid());
            using var settings = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                vaultUri = "https://owned-vault.vault.azure.net",
                setup = Credential("setup"),
                runtime = Credential("runtime"),
                denied = Credential("denied"),
                administrative = Credential("administrative"),
                observer = Credential("observer"),
                families = new Dictionary<string, object>
                {
                    [family == "vault" ? "VaultAdministration" : "ManagementOperation"] = input
                }
            }, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
            using var env = OwnedAzureEnvironment.Create(settings.RootElement);
            var member = family == "vault"
                ? VaultAdministrationEffects.Members.Single(m => m.Operation.EndsWith(".GetVaultAsync", StringComparison.Ordinal))
                : ManagementOperationEffects.Members.Single();
            var definition = new NativeCaseDefinition(
                new("AzureKeyVault", member.Operation, family == "vault" ? "selector.exact" : "operation.CreateOrUpdateVault",
                    "controlled", "selected-contract"), member.Member);
            var journal = new RoleFixtureJournal(directory);
            const string owned = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/owned-group/providers/Microsoft.KeyVault/vaults/owned-vault";
            FixtureSelector? original = null;
            bool released = false;
            using var caller = new CancellationTokenSource();
            OwnedManagementObserver Observer(ObserverEndpoint selected) => new(selected,
                new Backend(async (request, token) =>
                {
                    using var body = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
                    if (request.RequestUri!.AbsolutePath == "/" + family + "/prepare")
                    {
                        original = body.RootElement.GetProperty("selection").Deserialize<FixtureSelector>(ManagementAdmission.Json)!;
                        journal.Prepare("owner", original, [new(owned, false)]);
                        if (fault == "lost") throw new HttpRequestException("controlled-response-loss");
                        if (fault == "canceled")
                        {
                            caller.Cancel();
                            throw new OperationCanceledException(caller.Token);
                        }
                        if (fault == "malformed") return Json(new { });
                        var facts = new LeaseFacts(fault == "foreign-lease" ? Guid.NewGuid() : original.Nonce,
                            Guid.NewGuid(), "source", "https://management.azure.com",
                            fault == "invalid-facts" ? "foreign-revision" : "2026-02-01",
                            DateTimeOffset.UtcNow, [owned]);
                        return family == "vault"
                            ? Json(new VaultAdministrationEffects.Lease(facts, "owned-vault", null,
                                "canary", new string('A', 64), configuration, PrivateConnectionState.Unknown))
                            : Json(new ManagementOperationEffects.Lease(facts, "owned-vault", null, null,
                                null, ManagementMutation.CreateOrUpdateVault, NativeProvisioningState.Succeeded));
                    }
                    await Assert.That(request.RequestUri!.AbsolutePath).IsEqualTo("/" + family + "/release");
                    await Assert.That(token.IsCancellationRequested).IsFalse();
                    var selector = body.RootElement.Deserialize<FixtureSelector>(ManagementAdmission.Json)!;
                    await Assert.That(selector).IsEqualTo(original);
                    journal.Close("owner", selector);
                    if (absent) journal.RecordAbsence("owner", selector, owned);
                    released = true;
                    return Json(new RoleFixtureRelease.Measurement(selector, true, 0,
                        [owned], [], absent ? [owned] : [], absent ? [] : [owned]));
                }));
            var registry = new NativeCaseRegistry();
            if (family == "vault") VaultAdministrationEffects.Register(registry, env, [definition], Observer);
            else ManagementOperationEffects.Register(registry, env, [definition], Observer);
            var probe = new NativeCaseProbe();
            Exception? failure = null;
            try { await registry.Find(definition.Key)!.Execute(probe, caller.Token); }
            catch (Exception exception) { failure = exception; }
            await Assert.That(failure).IsNotNull();
            await Assert.That(released).IsTrue();
            await Assert.That(journal.Read("owner", original!).Released).IsEqualTo(absent);
            if (!absent)
                await Assert.That(probe.Result(definition.Key).ReasonCode).IsEqualTo("cleanup-incomplete");
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static object Credential(string role) => new { token = role, expiresAt = "2099-01-01T00:00:00Z" };
    private static AudienceToken Token(string role) =>
        new(role, new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero), "https://management.azure.com/.default");
    private static HttpResponseMessage Json<T>(T value) => new(HttpStatusCode.OK)
    {
        Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value, ManagementAdmission.Json))
    };
    private sealed class Backend(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token);
    }
}
