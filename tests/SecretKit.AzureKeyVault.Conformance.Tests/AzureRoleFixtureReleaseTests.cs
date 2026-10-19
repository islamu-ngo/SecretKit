using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureRoleFixtureReleaseTests
{
    private const string Owned = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/owned";
    private static FixtureSelector Selector() => new(Guid.NewGuid(), "scope", "operation", "variant", "case");
    private static RoleFixtureRelease.Measurement Complete(FixtureSelector selector) =>
        new(selector, true, 0, [Owned], [], [Owned], []);

    [Test]
    [Arguments(24, 0, true)]
    [Arguments(25, 0, false)]
    [Arguments(12, 12, true)]
    [Arguments(13, 12, false)]
    [Arguments(0, 24, true)]
    [Arguments(0, 25, false)]
    public async Task ReleaseBoundsCombinedOwnedAndBorrowedResources(int ownedCount, int borrowedCount, bool accepted)
    {
        var selector = Selector();
        string[] owned = Enumerable.Range(0, ownedCount).Select(i => Owned + "/owned-" + i).ToArray();
        string[] borrowed = Enumerable.Range(0, borrowedCount).Select(i => Owned + "/borrowed-" + i).ToArray();
        var measured = new RoleFixtureRelease.Measurement(selector, true, 0, owned, borrowed, owned.ToArray(), []);
        var known = new LeaseFacts(selector.Nonce, Guid.NewGuid(), "observer", "https://management.azure.com",
            "2022-04-01", DateTimeOffset.UnixEpoch, owned);
        if (accepted)
        {
            RoleFixtureRelease.Validate(measured, selector, null);
            RoleFixtureRelease.Validate(measured, selector, known);
        }
        else
            await Assert.That(() => RoleFixtureRelease.Validate(measured, selector, known))
                .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("known-owner")]
    [Arguments("known-nonce")]
    [Arguments("missing-absence")]
    [Arguments("remaining")]
    [Arguments("active")]
    public async Task ExpandedReleaseCapacityStillRequiresExactKnownOwnershipAndCompleteDrain(string fault)
    {
        var selector = Selector();
        string[] owned = Enumerable.Range(0, 24).Select(i => Owned + "/owned-" + i).ToArray();
        var measured = new RoleFixtureRelease.Measurement(selector, true, 0, owned, [], owned.ToArray(), []);
        var known = new LeaseFacts(fault == "known-nonce" ? Guid.NewGuid() : selector.Nonce,
            Guid.NewGuid(), "observer", "https://management.azure.com", "2022-04-01", DateTimeOffset.UnixEpoch,
            fault == "known-owner" ? [.. owned[..23], Owned + "/foreign"] : owned);
        measured = fault switch
        {
            "missing-absence" => measured with { AbsentResourceIds = owned[..23] },
            "remaining" => measured with { RemainingResourceIds = [owned[0]] },
            "active" => measured with { ActiveDispatches = 1 },
            _ => measured
        };
        await Assert.That(() => RoleFixtureRelease.Validate(measured, selector, known))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("missing-absence")]
    [Arguments("remaining")]
    [Arguments("active")]
    [Arguments("open")]
    [Arguments("foreign-selector")]
    [Arguments("borrowed")]
    [Arguments("duplicate")]
    [Arguments("foreign-absence")]
    public async Task ReleaseRequiresClosedDrainedCompleteOwnedAbsence(string fault)
    {
        FixtureSelector selector = Selector();
        var measured = Complete(selector);
        measured = fault switch
        {
            "missing-absence" => measured with { AbsentResourceIds = [] },
            "remaining" => measured with { RemainingResourceIds = [Owned] },
            "active" => measured with { ActiveDispatches = 1 },
            "open" => measured with { Closing = false },
            "foreign-selector" => measured with { Selector = Selector() },
            "borrowed" => measured with { BorrowedResourceIds = [Owned] },
            "duplicate" => measured with { OwnedResourceIds = [Owned, Owned] },
            _ => measured with { AbsentResourceIds = [Owned + "/other"] }
        };
        await Assert.That(() => RoleFixtureRelease.Validate(measured, selector, null))
            .Throws<NativeCaseFailureException>();
        RoleFixtureRelease.Validate(Complete(selector), selector, null);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task MissingClosingOrDrainCountCannotDefaultToSuccessfulRelease(bool closing)
    {
        var data = new Dictionary<string, object>
        {
            ["selector"] = Selector(),
            ["ownedResourceIds"] = new[] { Owned },
            ["borrowedResourceIds"] = Array.Empty<string>(),
            ["absentResourceIds"] = new[] { Owned },
            ["remainingResourceIds"] = Array.Empty<string>()
        };
        data.Add(closing ? "activeDispatches" : "closing", closing ? (object)0 : true);
        await Assert.That(() => JsonSerializer.Deserialize<RoleFixtureRelease.Measurement>(
            JsonSerializer.Serialize(data, ManagementAdmission.Json), ManagementAdmission.Json)).Throws<JsonException>();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    [Arguments("foreign-lease")]
    public async Task OriginalRoleCaseReleasesByOriginalNonceAfterPrepareFailure(string fault)
    {
        string directory = Path.Combine(Path.GetTempPath(), "secretkit-role-release-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var journal = new RoleFixtureJournal(directory);
            FixtureSelector? requested = null;
            bool released = false;
            using JsonDocument settings = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                vaultUri = "https://owned-vault.vault.azure.net",
                setup = Credential("setup"),
                runtime = Credential("runtime"),
                denied = Credential("denied"),
                administrative = Credential("administrative"),
                observer = Credential("observer"),
                families = new Dictionary<string, object>
                {
                    ["RoleAdministration"] = new RoleAdministrationEffects.Input(
                        new(new("https://fixture.invalid/"), "offline", TimeSpan.FromSeconds(5)),
                        new(ArmToken("setup"), ArmToken("administrative"), ArmToken("denied"), ArmToken("observer")),
                        Guid.NewGuid(), "owned", "eastus", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
                        10, 100, TimeSpan.FromSeconds(5))
                }
            }, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
            using OwnedAzureEnvironment env = OwnedAzureEnvironment.Create(settings.RootElement);
            var member = RoleAdministrationEffects.Members.Single(m => m.Operation.EndsWith(".GetRoleDefinitionAsync", StringComparison.Ordinal));
            var definition = new NativeCaseDefinition(
                new("AzureKeyVault", member.Operation, "selector.exact", "offline", "selected-contract"), member.Member);
            var registry = new NativeCaseRegistry();
            RoleAdministrationEffects.Register(registry, env, [definition], endpoint =>
                new(endpoint, new Backend(async (request, token) =>
                {
                    using JsonDocument body = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
                    if (request.RequestUri!.AbsolutePath == "/role/prepare")
                    {
                        requested = body.RootElement.GetProperty("selection").Deserialize<FixtureSelector>(ManagementAdmission.Json)!;
                        journal.Prepare("authenticated-owner", requested, [new(Owned, false)]);
                        if (fault == "lost") throw new HttpRequestException("offline-response-withheld");
                        if (fault == "malformed") return Json("{}");
                        var facts = new LeaseFacts(Guid.NewGuid(), Guid.NewGuid(), "observer", "https://management.azure.com",
                            "2022-04-01", DateTimeOffset.UtcNow, [Owned]);
                        return Json(JsonSerializer.Serialize(new RoleAdministrationEffects.Lease(facts, "owned",
                            Guid.NewGuid(), "canary", new string('1', 32), new string('0', 64),
                            SecretKit.Core.SecretStatus.Success), ManagementAdmission.Json));
                    }
                    FixtureSelector release = body.RootElement.Deserialize<FixtureSelector>(ManagementAdmission.Json)!;
                    await Assert.That(request.RequestUri!.AbsolutePath).IsEqualTo("/role/release");
                    await Assert.That(release).IsEqualTo(requested);
                    journal.Close("authenticated-owner", release);
                    // No dispatch happened; independent fixture storage reports absence.
                    journal.RecordAbsence("authenticated-owner", release, Owned);
                    released = journal.Read("authenticated-owner", release).Released;
                    return Json(JsonSerializer.Serialize(Complete(release), ManagementAdmission.Json));
                })));
            IReadOnlyList<NativeCaseResult> results = await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None);
            await Assert.That(results.Single().Passed).IsFalse();
            await Assert.That(released).IsTrue();
            await Assert.That(journal.Read("authenticated-owner", requested!).Closing).IsTrue();
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static object Credential(string role) => new { token = role + "-offline", expiresAt = "2099-01-01T00:00:00Z" };
    private static AudienceToken ArmToken(string role) => new(role + "-arm-offline",
        new DateTimeOffset(2099, 1, 1, 0, 0, 0, TimeSpan.Zero), "https://management.azure.com/.default");
    private static HttpResponseMessage Json(string value) =>
        new(HttpStatusCode.OK) { Content = new StringContent(value, Encoding.UTF8, "application/json") };
    private sealed class Backend(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token);
    }
}
