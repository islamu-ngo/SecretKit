using System.Net;
using System.Text.Json;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureAuditFixtureReleaseTests
{
    [Test]
    [Arguments("lost", true)]
    [Arguments("malformed", true)]
    [Arguments("foreign-lease", true)]
    [Arguments("lost", false)]
    [Arguments("malformed", false)]
    [Arguments("foreign-lease", false)]
    public async Task OriginalAuditPrepareFailureRetainsOriginalNonceAndStrictCleanup(string fault, bool absent)
    {
        string directory = Path.Combine(Path.GetTempPath(), "audit-release-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var journal = new RoleFixtureJournal(directory);
            string owned = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/audit-group/providers/Microsoft.KeyVault/vaults/audit-vault";
            FixtureSelector? original = null;
            bool releaseCalled = false;
            using var settings = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                vaultUri = "https://audit-vault.vault.azure.net",
                setup = Credential("setup"),
                runtime = Credential("runtime"),
                denied = Credential("denied"),
                administrative = Credential("administrative"),
                observer = Credential("observer"),
                families = new Dictionary<string, object>
                {
                    ["AuditDiagnostics"] = new AuditDiagnosticsEffects.Input(
                        new(new("https://fixture.invalid/"), "private-capability", TimeSpan.FromSeconds(5)),
                        Monitoring("monitor"), Monitoring("denied-monitor"),
                        Guid.Parse("11111111-1111-1111-1111-111111111111"), "audit-group", "eastus",
                        Guid.NewGuid(), Guid.NewGuid(), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5), 10,
                        "controlled-trigger-value")
                }
            }, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
            using var env = OwnedAzureEnvironment.Create(settings.RootElement);
            var member = AuditDiagnosticsEffects.Members[0];
            var definition = new NativeCaseDefinition(
                new("AzureKeyVault", member.Operation, "query.resource", "controlled", "selected-contract"), member.Member);
            var registry = new NativeCaseRegistry();
            AuditDiagnosticsEffects.Register(registry, env, [definition], endpoint =>
                new(endpoint, new Backend(async (request, token) =>
                {
                    using var body = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
                    if (request.RequestUri!.AbsolutePath == "/audit/prepare")
                    {
                        original = body.RootElement.GetProperty("selection").Deserialize<FixtureSelector>(ManagementAdmission.Json)!;
                        journal.Prepare("owner", original, [new(owned, false)]);
                        if (fault == "lost") throw new HttpRequestException("controlled-response-loss");
                        if (fault == "malformed") return Json(new { });
                        return Json(new AuditDiagnosticsEffects.Lease(new(
                            Guid.NewGuid(), Guid.NewGuid(), "source", "https://management.azure.com", "2026-02-01",
                            DateTimeOffset.UtcNow, [owned]), [], "untrusted-trigger"));
                    }
                    await Assert.That(request.RequestUri!.AbsolutePath).IsEqualTo("/audit/release");
                    var selector = body.RootElement.Deserialize<FixtureSelector>(ManagementAdmission.Json)!;
                    await Assert.That(selector).IsEqualTo(original);
                    journal.Close("owner", selector);
                    if (absent) journal.RecordAbsence("owner", selector, owned);
                    releaseCalled = true;
                    return Json(new RoleFixtureRelease.Measurement(selector, true, 0,
                        [owned], [], absent ? [owned] : [], absent ? [] : [owned]));
                })));
            var results = await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None);
            await Assert.That(results.Single().Passed).IsFalse();
            await Assert.That(releaseCalled).IsTrue();
            await Assert.That(journal.Read("owner", original!).Released).IsEqualTo(absent);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static object Credential(string role) => new { token = role, expiresAt = "2099-01-01T00:00:00Z" };
    private static AudienceToken Monitoring(string role) =>
        new(role, new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero), "https://api.loganalytics.io//.default");
    private static HttpResponseMessage Json<T>(T value) => new(HttpStatusCode.OK)
    {
        Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value, ManagementAdmission.Json))
    };
    private sealed class Backend(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token);
    }
}
