using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalMssqlCatalogSelectionTests
{
    private const string Family = "C08-IR-ValidationPolicies";
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };

    [Test]
    public async Task BothSelectedCollectorsKeepAuthorityFixedAcrossRealFactoryGeneratedSubjects()
    {
        var store = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var claimed = new List<string>();
        bool mysql = false;
        using var environment = Environment(Profile(), includeMysql: true);
        using var remote = new Handler((_, _) => throw new InvalidOperationException("Native catalog reached HTTP."));
        var catalog = InfisicalLifecycleObservers.FromInputs(environment, Family, remote,
            mysqlProcess: (_, _, _, _) =>
            {
                mysql = true;
                return Task.FromResult((0, """
                    {"principal":"catalog@%","database":"owned","accounts":[],"plugins":[],"components":[],"variables":[]}
                    """));
            },
            mssqlProcess: (query, arguments, _, _) =>
            {
                bool master = arguments[arguments.ToList().IndexOf("-d") + 1] == "master";
                string[] requested = Regex.Matches(query, "0x([A-F0-9]+)")
                    .Select(m => Encoding.Unicode.GetString(Convert.FromHexString(m.Groups[1].Value))).ToArray();
                var output = Observation(master ? "master" : "owned");
                var rows = output["principals"]!.AsArray();
                foreach ((string name, byte[] sid) in store.Where(p => requested.Contains(p.Key, StringComparer.Ordinal)))
                {
                    var row = new JsonObject
                    {
                        ["name"] = Hex(name),
                        ["sid"] = Convert.ToHexString(sid),
                        ["type"] = Hex(master ? "SQL_LOGIN" : "SQL_USER")
                    };
                    if (master)
                    {
                        row["policy"] = false;
                        row["expiration"] = false;
                        row["disabled"] = false;
                    }
                    else row["authentication"] = Hex("INSTANCE");
                    rows.Add(row);
                }
                return Task.FromResult((0, output.ToJsonString()));
            })!;
        using var ownerHandler = new Handler(async (request, token) =>
        {
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            JsonElement root = body.RootElement;
            string[] names = [root.GetProperty("username1").GetString()!, root.GetProperty("username2").GetString()!];
            var coordinate = root.GetProperty("coordinate").Deserialize<RotationBackendCoordinate>(Json)!;
            await Assert.That(coordinate.Account).IsEqualTo(names[0]);
            bool claim = request.RequestUri!.AbsolutePath.EndsWith("/claim", StringComparison.Ordinal);
            if (claim)
            {
                claimed.Add(names[0]);
                store.Add(names[0], [1, 2]);
                store.Add(names[1], [3, 4]);
            }
            else if (request.RequestUri.AbsolutePath.EndsWith("/release", StringComparison.Ordinal)) store.Clear();
            else await Assert.That(request.RequestUri.AbsolutePath.EndsWith("/remaining", StringComparison.Ordinal)).IsTrue();
            var facts = new InfisicalRotationValidationAccounts.Facts(
                root.GetProperty("ownershipNonce").GetString()!, root.GetProperty("organizationId").GetString()!,
                root.GetProperty("projectId").GetString()!, root.GetProperty("connectionId").GetString()!, coordinate,
                claim ? names : [], [], claim ? 2 : 0, true);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    schemaVersion = 1,
                    nonce = root.GetProperty("nonce").GetString(),
                    observerIdentity = "owner-service",
                    observedAt = DateTimeOffset.UtcNow,
                    facts
                }, Json), Encoding.UTF8, "application/json")
            };
        });
        var owner = new InfisicalLifecycleObservers(
            new(new Uri("https://owner.invalid/owned/"), "owner-token", "owner-service", 10), ownerHandler);
        var factory = new InfisicalRotationValidationAccounts(owner, catalog);
        var input = new ValidationPoliciesEffects.RotationValidationInput("organization", "connection", "database.invalid",
            1433, "owned", 60, ["select"], ["write"], InfisicalRotationProfile.MssqlCredentials);
        for (int i = 0; i < 2; i++)
        {
            await using (var accounts = await factory.CreateAsync("project", input, default))
            {
                var facts = await catalog.InspectIdentityCatalogAsync(accounts.Coordinate,
                    [accounts.Username1, accounts.Username2], default);
                await Assert.That(RotationSqlIdentityEvidence.Owned(facts, facts.RequestedUsernames)).IsTrue();
            }
            await Assert.That(store.Count).IsEqualTo(0);
        }
        await Assert.That(claimed.Distinct(StringComparer.Ordinal).Count()).IsEqualTo(2);
        await Assert.That(mysql).IsFalse();
        var mysqlFacts = await catalog.InspectIdentityCatalogAsync(
            new(InfisicalRotationProfile.MysqlCredentials, "database.invalid", 3306, "owned", "subject"),
            ["owned_a", "owned_b"], default);
        await Assert.That(mysql).IsTrue();
        await Assert.That(RotationSqlIdentityEvidence.IsAbsent(mysqlFacts)).IsTrue();
    }

    [Test]
    public async Task SelectedNativeFailureDoesNotAttemptTheRemoteCatalogTerminal()
    {
        bool reached = false;
        using var handler = new Handler((_, _) =>
        {
            reached = true;
            throw new InvalidOperationException("Native failure reached HTTP.");
        });
        using var environment = Environment(Profile());
        var observer = InfisicalLifecycleObservers.FromInputs(environment, Family, handler,
            mssqlProcess: (_, _, _, _) => Task.FromResult((1, "")))!;

        await Assert.That(async () => await observer.InspectIdentityCatalogAsync(
            new(InfisicalRotationProfile.MssqlCredentials, "database.invalid", 1433, "owned", "subject"),
            ["owned_a", "owned_b"], default)).Throws<NativeCaseFailureException>();
        await Assert.That(reached).IsFalse();
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token);
    }

    private static string Hex(string text) => Convert.ToHexString(Encoding.Unicode.GetBytes(text));

    private static JsonObject Observation(string database) => new()
    {
        ["serverIdentity"] = Hex("owned-server"),
        ["productVersion"] = Hex("17.0.1"),
        ["engineEdition"] = 3,
        ["database"] = Hex(database),
        ["originalLogin"] = Hex("catalog"),
        ["originalSid"] = "AABB",
        ["currentLogin"] = Hex("catalog"),
        ["currentSid"] = "AABB",
        ["databaseUser"] = Hex("dbo"),
        ["sysadmin"] = 1,
        ["columnCollation"] = Hex("Latin1_General_CI_AS_KS_WS"),
        ["catalogCollation"] = Hex("Latin1_General_CI_AS_KS_WS"),
        ["namesDistinct"] = true,
        ["principals"] = new JsonArray()
    };

    [Test]
    [Arguments("missing-password")]
    [Arguments("foreign-field")]
    [Arguments("port")]
    [Arguments("null")]
    public async Task ExplicitMalformedNativeSelectionCannotBecomeRemoteOnly(string fault)
    {
        JsonObject profile = Profile();
        if (fault == "missing-password") profile.Remove("password");
        if (fault == "foreign-field") profile["executable"] = "unselected";
        if (fault == "port") profile["port"] = 0;
        using var environment = Environment(fault == "null" ? null : profile);

        await Assert.That(() => InfisicalLifecycleObservers.FromInputs(environment, Family))
            .Throws<NativeCaseFailureException>();
    }

    private static JsonObject Profile() => new()
    {
        ["host"] = "database.invalid",
        ["port"] = 1433,
        ["database"] = "owned",
        ["username"] = "catalog",
        ["password"] = "private-catalog-password",
        ["serverIdentity"] = "owned-server",
        ["timeoutSeconds"] = 10
    };

    private static NativeEnvironment Environment(JsonNode? profile, bool includeMysql = false)
    {
        var family = new JsonObject
        {
            ["mssqlIdentityCatalog"] = profile,
            ["observer"] = new JsonObject
            {
                ["endpoint"] = "https://observer.invalid/owned/",
                ["token"] = "private-observer-token",
                ["identity"] = "independent-service",
                ["timeoutSeconds"] = 10
            }
        };
        if (includeMysql)
            family["mysqlIdentityCatalog"] = new JsonObject
            {
                ["host"] = "database.invalid",
                ["port"] = 3306,
                ["database"] = "owned",
                ["username"] = "catalog",
                ["password"] = "private-catalog-password",
                ["principal"] = "catalog@%",
                ["rootCertificate"] = Path.Combine(Path.GetTempPath(), "selected-ca.pem"),
                ["timeoutSeconds"] = 10
            };
        using var settings = JsonDocument.Parse(new JsonObject
        {
            ["origin"] = "https://infisical.invalid",
            ["setup"] = "setup",
            ["runtime"] = "runtime",
            ["denied"] = "denied",
            ["administrative"] = "administrative",
            ["observer"] = "observer",
            ["families"] = new JsonObject
            {
                [Family] = family
            }
        }.ToJsonString());
        return NativeEnvironment.Create(settings.RootElement);
    }
}
