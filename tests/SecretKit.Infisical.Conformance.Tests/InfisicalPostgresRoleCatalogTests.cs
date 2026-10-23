using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalPostgresRoleCatalogTests
{
    private const string Family = "C08-IR-InfisicalDynamicClient";
    private static readonly DynamicUsernameCoordinate Coordinate = new(NativeSqlEngine.Postgres, "database.invalid", 5432, "owned");
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };

    [Test]
    [Arguments("missing-password")]
    [Arguments("foreign-field")]
    [Arguments("port")]
    [Arguments("null")]
    public async Task ExplicitMalformedNativeCatalogCannotSilentlySelectRemoteInventory(string fault)
    {
        JsonObject profile = Profile();
        if (fault == "missing-password") profile.Remove("password");
        if (fault == "foreign-field") profile["executable"] = "unselected";
        if (fault == "port") profile["port"] = 0;
        using var environment = Environment(fault == "null" ? null : profile);

        await Assert.That(() => InfisicalLifecycleObservers.FromInputs(environment, Family))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task SelectedCatalogCollectsNamesWhileMeasurementKeepsItsIndependentChannel()
    {
        string[] names = ["owned'role", "owned_é"];
        bool measured = false;
        string? home = null;
        using var handler = new Handler(async (request, token) =>
        {
            await Assert.That(request.RequestUri!.AbsolutePath).IsEqualTo("/owned/dynamic/measure");
            measured = true;
            using JsonDocument body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            var coordinate = body.RootElement.GetProperty("coordinate").Deserialize<DynamicBackendCoordinate>(Json)!;
            return new(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    schemaVersion = 1,
                    nonce = body.RootElement.GetProperty("nonce").GetString(),
                    observerIdentity = "independent-service",
                    observedAt = DateTimeOffset.UtcNow,
                    facts = new DynamicBackendFacts(coordinate, BackendAuthentication.Accepted, ["select"], ["write"], null)
                }, Json), Encoding.UTF8, "application/json")
            };
        });
        using var environment = Environment(Profile());
        var observer = InfisicalLifecycleObservers.FromInputs(environment, Family, handler, async (query, injected, token) =>
        {
            token.ThrowIfCancellationRequested();
            home = injected["HOME"];
            await Assert.That(Directory.Exists(home)).IsTrue();
            await Assert.That(injected["PGUSER"]).IsEqualTo("catalog");
            await Assert.That(injected["PGSSLMODE"]).IsEqualTo("verify-full");
            await Assert.That(injected["PGCHANNELBINDING"]).IsEqualTo("require");
            await Assert.That(query.Contains(injected["PGPASSWORD"], StringComparison.Ordinal)).IsFalse();
            string hex = query.Split("decode('", StringSplitOptions.None)[1].Split('\'')[0];
            string[] decoded = JsonSerializer.Deserialize<string[]>(Convert.FromHexString(hex))!;
            await Assert.That(decoded).IsEquivalentTo(names);
            return (0, Output(names, [true, false]));
        })!;

        DynamicUsernameFacts facts = await observer.InspectUsernamesAsync(Coordinate, names, default);

        await Assert.That(facts.IsComplete).IsTrue();
        await Assert.That(facts.RequestedUsernames).IsEquivalentTo(names);
        await Assert.That(facts.ExistingUsernames).IsEquivalentTo(new[] { names[0] });
        await Assert.That(measured).IsFalse();
        await Assert.That(Directory.Exists(home)).IsFalse();
        using var username = SecretMaterial.FromText("issued-user");
        using var password = SecretMaterial.FromText("issued-password");
        var backend = new DynamicBackendCoordinate(NativeSqlEngine.Postgres, Coordinate.Host, Coordinate.Port,
            Coordinate.Database, Guid.NewGuid(), Guid.NewGuid());
        var measurement = await observer.MeasureAsync(backend, username, password, default);
        await Assert.That(measurement.Authentication).IsEqualTo(BackendAuthentication.Accepted);
        await Assert.That(measured).IsTrue();
    }

    [Test]
    [Arguments("foreign")]
    [Arguments("missing")]
    [Arguments("duplicate")]
    [Arguments("reordered")]
    [Arguments("null")]
    [Arguments("user")]
    [Arguments("syntax")]
    [Arguments("overflow")]
    [Arguments("exit")]
    [Arguments("duplicate-json")]
    public async Task FailedOrUnboundNativeOutputNeverBecomesCompleteAbsence(string fault)
    {
        string[] names = ["owned_a", "owned_b"];
        string output = Output(names, [false, false]);
        JsonObject value = JsonNode.Parse(output)!.AsObject();
        var rows = value["rows"]!.AsArray();
        switch (fault)
        {
            case "foreign": rows[1]!["name"] = "foreign"; break;
            case "missing": rows.RemoveAt(1); break;
            case "duplicate": rows[1]!["name"] = names[0]; break;
            case "reordered":
                rows[0]!["name"] = names[1];
                rows[1]!["name"] = names[0];
                break;
            case "null": rows[0]!["exists"] = null; break;
            case "user": value["user"] = "foreign"; break;
        }
        output = fault switch
        {
            "syntax" => "{",
            "overflow" => new string(' ', 65537),
            "duplicate-json" => "{\"user\":\"foreign\"," + value.ToJsonString()[1..],
            _ => value.ToJsonString()
        };
        bool remote = false;
        using var handler = new Handler((_, _) =>
        {
            remote = true;
            throw new InvalidOperationException("Remote inventory must not replace native failure.");
        });
        using var environment = Environment(Profile());
        var observer = InfisicalLifecycleObservers.FromInputs(environment, Family, handler,
            (_, _, _) => Task.FromResult((fault == "exit" ? 2 : 0, output)))!;

        await Assert.That(async () => await observer.InspectUsernamesAsync(Coordinate, names, default))
            .Throws<NativeCaseFailureException>();
        await Assert.That(remote).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ForeignEngineOrClusterFailsBeforeProcessLaunch(bool engine)
    {
        bool launched = false;
        using var environment = Environment(Profile());
        var observer = InfisicalLifecycleObservers.FromInputs(environment, Family, process: (_, _, _) =>
        {
            launched = true;
            throw new InvalidOperationException("Foreign cluster reached native process.");
        })!;
        var foreign = engine ? Coordinate with { Engine = NativeSqlEngine.Mysql } : Coordinate with { Database = "foreign" };

        await Assert.That(async () => await observer.InspectUsernamesAsync(foreign, ["owned"], default))
            .Throws<NativeCaseFailureException>();
        await Assert.That(launched).IsFalse();
    }

    [Test]
    public async Task CancellationRetainsClientHomeUntilTheActualProcessTaskDrains()
    {
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        string? home = null;
        using var environment = Environment(Profile());
        var observer = InfisicalLifecycleObservers.FromInputs(environment, Family, process: async (_, injected, _) =>
        {
            home = injected["HOME"];
            entered.TrySetResult();
            await release.Task;
            return (0, Output(["owned"], [false]));
        })!;
        var pending = observer.InspectUsernamesAsync(Coordinate, ["owned"], cancellation.Token).AsTask();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();
            await Assert.That(pending.IsCompleted).IsFalse();
            await Assert.That(Directory.Exists(home)).IsTrue();
        }
        finally { release.TrySetResult(); }
        await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(5))).Throws<OperationCanceledException>();
        await Assert.That(Directory.Exists(home)).IsFalse();
    }

    private static string Output(string[] names, bool[] exists) => JsonSerializer.Serialize(new
    {
        user = "catalog",
        rows = names.Select((name, i) => new { name, exists = exists[i] })
    });

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token);
    }

    private static JsonObject Profile() => new()
    {
        ["host"] = "database.invalid",
        ["port"] = 5432,
        ["database"] = "owned",
        ["username"] = "catalog",
        ["password"] = "private-catalog-password",
        ["timeoutSeconds"] = 10,
        ["rootCertificate"] = Path.Combine(Path.GetTempPath(), "selected-ca.pem")
    };

    private static NativeEnvironment Environment(JsonNode? profile)
    {
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
                [Family] = new JsonObject
                {
                    ["observer"] = new JsonObject
                    {
                        ["endpoint"] = "https://observer.invalid/owned/",
                        ["token"] = "service-token",
                        ["identity"] = "independent-service",
                        ["timeoutSeconds"] = 10
                    },
                    ["postgresRoleCatalog"] = profile
                }
            }
        }.ToJsonString());
        return NativeEnvironment.Create(settings.RootElement);
    }
}
