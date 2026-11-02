using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalMysqlIdentityCatalogTests
{
    private const string Family = "C08-IR-InfisicalRotationClient";
    private static readonly RotationBackendCoordinate Coordinate =
        new(InfisicalRotationProfile.MysqlCredentials, "database.invalid", 3306, "owned", "fixture-account");
    private static readonly string[] Names = ["sk_identity_a", "sk_identity_b"];
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };

    [Test]
    public async Task OnePreselectedCatalogSupportsTheRealFactoryAcrossFreshNonceOwnedPairs()
    {
        var store = new List<MysqlRotationAccountFacts>();
        var claimed = new List<string>();
        using var environment = Environment(Profile());
        var catalog = InfisicalLifecycleObservers.FromInputs(environment, Family,
            mysqlProcess: (_, _, _, _) =>
            {
                JsonObject output = Output("none");
                output["accounts"] = JsonSerializer.SerializeToNode(store, Json);
                return Task.FromResult((0, output.ToJsonString()));
            })!;
        using var handler = new OwnerHandler(async (request, token) =>
        {
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            var root = body.RootElement;
            string[] names = [root.GetProperty("username1").GetString()!, root.GetProperty("username2").GetString()!];
            var coordinate = root.GetProperty("coordinate").Deserialize<RotationBackendCoordinate>(Json)!;
            await Assert.That(coordinate.Account).IsEqualTo(names[0]);
            bool claim = request.RequestUri!.AbsolutePath.EndsWith("/claim", StringComparison.Ordinal);
            if (claim)
            {
                claimed.Add(names[0]);
                store.AddRange(names.Select(n => new MysqlRotationAccountFacts(n, "%", "caching_sha2_password")));
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
                }, Json), System.Text.Encoding.UTF8, "application/json")
            };
        });
        var owner = new InfisicalLifecycleObservers(
            new(new Uri("https://owner.invalid/owned/"), "owner-token", "owner-service", 10), handler);
        var factory = new InfisicalRotationValidationAccounts(owner, catalog);
        var input = new ValidationPoliciesEffects.RotationValidationInput("organization", "connection", Coordinate.Host,
            Coordinate.Port, Coordinate.Database, 60, ["select"], ["write"], InfisicalRotationProfile.MysqlCredentials);
        for (int i = 0; i < 2; i++)
        {
            await using (var accounts = await factory.CreateAsync("project", input, default))
            {
                await Assert.That(store.Select(a => a.Username).ToArray())
                    .IsEquivalentTo(new[] { accounts.Username1, accounts.Username2 });
                var facts = await catalog.InspectIdentityCatalogAsync(accounts.Coordinate,
                    [accounts.Username1, accounts.Username2], default);
                await Assert.That(RotationSqlIdentityEvidence.Owned(facts, facts.RequestedUsernames)).IsTrue();
            }
            await Assert.That(store.Count).IsEqualTo(0);
        }
        await Assert.That(claimed.Distinct(StringComparer.Ordinal).Count()).IsEqualTo(2);
    }

    private sealed class OwnerHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token);
    }

    [Test]
    [Arguments("none")]
    [Arguments("plugin")]
    [Arguments("component")]
    public async Task NativeCatalogPreservesAllHostRowsAndEffectivePolicyInExistingValidators(string validator)
    {
        JsonObject output = Output(validator);
        string? home = null;
        using var environment = Environment(Profile());
        var observer = InfisicalLifecycleObservers.FromInputs(environment, Family,
            mysqlProcess: async (query, arguments, injected, token) =>
            {
                token.ThrowIfCancellationRequested();
                home = injected["HOME"];
                await Assert.That(Directory.Exists(home)).IsTrue();
                await Assert.That(arguments.Contains("--no-defaults") && arguments.Contains("--no-login-paths") &&
                    arguments.Contains("--ssl-mode=VERIFY_IDENTITY") && arguments.Contains("--skip-reconnect")).IsTrue();
                await Assert.That(arguments.Any(a => a.Contains(injected["MYSQL_PWD"], StringComparison.Ordinal)) ||
                    query.Contains(injected["MYSQL_PWD"], StringComparison.Ordinal)).IsFalse();
                string hex = query.Split("UNHEX('", StringSplitOptions.None)[1].Split('\'')[0];
                await Assert.That(JsonSerializer.Deserialize<string[]>(Convert.FromHexString(hex))).IsEquivalentTo(Names);
                return (0, output.ToJsonString());
            })!;

        var absent = await observer.InspectIdentityCatalogAsync(Coordinate, Names, default);
        await Assert.That(RotationSqlIdentityEvidence.IsAbsent(absent)).IsTrue();
        await Assert.That(RotationSqlIdentityEvidence.PolicyCompatible(absent)).IsTrue();
        await Assert.That(absent.Mysql!.PasswordPolicy.ChangedCharactersPercentage).IsEqualTo(validator == "component" ? 0 : (int?)null);
        await Assert.That(Directory.Exists(home)).IsFalse();

        var rows = output["accounts"]!.AsArray();
        rows.Add(Account(Names[0], "%"));
        rows.Add(Account(Names[1], "%"));
        var owned = await observer.InspectIdentityCatalogAsync(Coordinate, Names, default);
        await Assert.That(RotationSqlIdentityEvidence.Owned(owned, Names)).IsTrue();
        rows.Add(Account(Names[0], "localhost"));
        var extraHost = await observer.InspectIdentityCatalogAsync(Coordinate, Names, default);
        await Assert.That(extraHost.Mysql!.Accounts.Length).IsEqualTo(3);
        await Assert.That(RotationSqlIdentityEvidence.Owned(extraHost, Names)).IsFalse();
        rows.Clear();
        rows.Add(Account(Names[0], "localhost"));
        await Assert.That(RotationSqlIdentityEvidence.IsAbsent(
            await observer.InspectIdentityCatalogAsync(Coordinate, Names, default))).IsFalse();
    }

    [Test]
    [Arguments("foreign-principal")]
    [Arguments("foreign-database")]
    [Arguments("foreign-account")]
    [Arguments("duplicate-account")]
    [Arguments("unknown-component")]
    [Arguments("unknown-plugin")]
    [Arguments("missing-variable")]
    [Arguments("null-variable")]
    [Arguments("duplicate-variable")]
    [Arguments("unknown-variable")]
    [Arguments("bad-policy")]
    [Arguments("bad-boolean")]
    [Arguments("overflow")]
    [Arguments("duplicate-json")]
    [Arguments("exit")]
    public async Task UnavailableNativeCatalogNeverCertifiesAbsenceOrUsesRemoteFallback(string fault)
    {
        JsonObject output = Output("component");
        switch (fault)
        {
            case "foreign-principal": output["principal"] = "foreign@%"; break;
            case "foreign-database": output["database"] = "foreign"; break;
            case "foreign-account": output["accounts"]!.AsArray().Add(Account("foreign", "%")); break;
            case "duplicate-account":
                output["accounts"]!.AsArray().Add(Account(Names[0], "%"));
                output["accounts"]!.AsArray().Add(Account(Names[0], "%"));
                break;
            case "unknown-component": output["components"]!.AsArray().Add("file://unreviewed"); break;
            case "unknown-plugin": output["plugins"]!.AsArray().Add("unreviewed"); break;
            case "missing-variable": output["variables"]!.AsArray().RemoveAt(0); break;
            case "null-variable": output["variables"]![0]!["value"] = null; break;
            case "duplicate-variable": output["variables"]!.AsArray().Add(output["variables"]![0]!.DeepClone()); break;
            case "unknown-variable": output["variables"]!.AsArray().Add(Variable("component", "foreign", "0")); break;
            case "bad-policy": output["variables"]![0]!["value"] = "unknown"; break;
            case "bad-boolean": output["variables"]![2]!["value"] = "unknown"; break;
        }
        string text = fault switch
        {
            "overflow" => new string(' ', 65537),
            "duplicate-json" => "{\"principal\":\"foreign@%\"," + output.ToJsonString()[1..],
            _ => output.ToJsonString()
        };
        using var handler = new RejectRemote();
        using var environment = Environment(Profile());
        var observer = InfisicalLifecycleObservers.FromInputs(environment, Family, handler,
            mysqlProcess: (_, _, _, _) => Task.FromResult((fault == "exit" ? 1 : 0, text)))!;

        await Assert.That(async () => await observer.InspectIdentityCatalogAsync(Coordinate, Names, default))
            .Throws<NativeCaseFailureException>();
        await Assert.That(handler.Reached).IsFalse();
    }

    [Test]
    public async Task StrongObservedPolicyIsNotRewrittenToQualifyWeakPasswordWitness()
    {
        JsonObject output = Output("component");
        output["variables"]![0]!["value"] = "STRONG";
        using var environment = Environment(Profile());
        var observer = InfisicalLifecycleObservers.FromInputs(environment, Family,
            mysqlProcess: (_, _, _, _) => Task.FromResult((0, output.ToJsonString())))!;

        var facts = await observer.InspectIdentityCatalogAsync(Coordinate, Names, default);

        await Assert.That(facts.Mysql!.PasswordPolicy.Policy).IsEqualTo(2);
        await Assert.That(RotationSqlIdentityEvidence.PolicyEstablished(facts)).IsTrue();
        await Assert.That(RotationSqlIdentityEvidence.PolicyCompatible(facts)).IsFalse();
    }

    [Test]
    public async Task ForeignBindingFailsBeforeNativeProcessWork()
    {
        bool launched = false;
        using var environment = Environment(Profile());
        var observer = InfisicalLifecycleObservers.FromInputs(environment, Family,
            mysqlProcess: (_, _, _, _) =>
            {
                launched = true;
                throw new InvalidOperationException("Foreign binding reached process.");
            })!;

        await Assert.That(async () => await observer.InspectIdentityCatalogAsync(
            Coordinate with { Database = "foreign" }, Names, default)).Throws<NativeCaseFailureException>();
        await Assert.That(launched).IsFalse();
    }

    [Test]
    public async Task CancellationDrainsActualQueryTaskBeforeDeletingItsPrivateHome()
    {
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        string? home = null;
        using var environment = Environment(Profile());
        var observer = InfisicalLifecycleObservers.FromInputs(environment, Family,
            mysqlProcess: async (_, _, injected, _) =>
            {
                home = injected["HOME"];
                entered.TrySetResult();
                await release.Task;
                return (0, Output("none").ToJsonString());
            })!;
        var pending = observer.InspectIdentityCatalogAsync(Coordinate, Names, cancellation.Token).AsTask();
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

    private sealed class RejectRemote : HttpMessageHandler
    {
        internal bool Reached { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Reached = true;
            throw new InvalidOperationException("Native failure reached remote fallback.");
        }
    }

    private static JsonObject Account(string name, string host) => new()
    {
        ["username"] = name,
        ["host"] = host,
        ["authenticationPlugin"] = "caching_sha2_password"
    };

    private static JsonObject Variable(string validator, string name, string value) => new()
    {
        ["name"] = (validator == "component" ? "validate_password." : "validate_password_") + name,
        ["value"] = value
    };

    private static JsonObject Output(string validator)
    {
        var variables = new JsonArray();
        if (validator != "none")
        {
            variables.Add(Variable(validator, "policy", "LOW"));
            variables.Add(Variable(validator, "length", "8"));
            variables.Add(Variable(validator, "check_user_name", "OFF"));
            variables.Add(Variable(validator, "mixed_case_count", "1"));
            variables.Add(Variable(validator, "number_count", "1"));
            variables.Add(Variable(validator, "special_char_count", "1"));
            variables.Add(Variable(validator, "dictionary_file", ""));
            if (validator == "component") variables.Add(Variable(validator, "changed_characters_percentage", "0"));
        }
        return new()
        {
            ["principal"] = "catalog@%",
            ["database"] = "owned",
            ["accounts"] = new JsonArray(),
            ["plugins"] = validator == "plugin" ? new JsonArray("validate_password") : new JsonArray(),
            ["components"] = validator == "component" ? new JsonArray("file://component_validate_password") : new JsonArray(),
            ["variables"] = variables
        };
    }

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

    private static JsonObject Profile() => new()
    {
        ["host"] = "database.invalid",
        ["port"] = 3306,
        ["database"] = "owned",
        ["username"] = "catalog",
        ["password"] = "private-catalog-password",
        ["principal"] = "catalog@%",
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
                    ["mysqlIdentityCatalog"] = profile,
                    ["observer"] = new JsonObject
                    {
                        ["endpoint"] = "https://observer.invalid/owned/",
                        ["token"] = "private-observer-token",
                        ["identity"] = "independent-service",
                        ["timeoutSeconds"] = 10
                    }
                }
            }
        }.ToJsonString());
        return NativeEnvironment.Create(settings.RootElement);
    }
}
