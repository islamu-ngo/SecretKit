using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalRotationIdentityCatalogTests
{
    private static readonly string[] Names = ["sk_identity_a", "sk_identity_b"];
    private static readonly JsonSerializerOptions ServiceJson = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new Uri("https://observer.invalid/owned/"), "fixture-token", "catalog-service", 30);

    private static RotationBackendCoordinate Coordinate(bool mysql) =>
        new(mysql ? InfisicalRotationProfile.MysqlCredentials : InfisicalRotationProfile.MssqlCredentials,
            "database.invalid", mysql ? 3306 : 1433, "owned", "fixture-account");

    private static MysqlPasswordPolicyFacts NoValidator() =>
        new(true, [], [], null, null, null, null, null, null, null, null);

    private static MysqlPasswordPolicyFacts Validator(bool component) =>
        new(true, component ? [] : ["validate_password"],
            component ? ["file://component_validate_password"] : [], 0, 8, false, 1, 1, 1, "", component ? 0 : null);

    private static RotationIdentityCatalogFacts Facts(bool mysql, bool owned = true) =>
        new(Coordinate(mysql), Names.ToArray(),
            mysql ? new("owned", true, owned ?
                [new(Names[0], "%", "caching_sha2_password"), new(Names[1], "%", "mysql_native_password")] : [],
                NoValidator()) : null,
            mysql ? null : new("owned", true, true, owned ?
                [new(Names[0], [1, 2], "SQL_LOGIN", false, false, false),
                    new(Names[1], [3, 4], "SQL_LOGIN", false, false, false)] : [],
                owned ? [new(Names[0], [1, 2], "SQL_USER", "INSTANCE"),
                    new(Names[1], [3, 4], "SQL_USER", "INSTANCE")] : []));

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task CatalogMeasuresIndependentStoresAcrossOwnershipAndCleanup(bool mysql)
    {
        var mysqlStore = new List<MysqlRotationAccountFacts>();
        var serverStore = new List<MssqlRotationLoginFacts>();
        var databaseStore = new List<MssqlRotationUserFacts>();
        using var handler = new Handler(async (request, token) =>
        {
            await Assert.That(request.Method).IsEqualTo(HttpMethod.Post);
            await Assert.That(request.RequestUri!.AbsoluteUri)
                .IsEqualTo("https://observer.invalid/owned/rotation/identity-catalog");
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo(Settings.Token);
            JsonObject body = await Body(request, token);
            await Assert.That(body["coordinate"]!.Deserialize<RotationBackendCoordinate>(ServiceJson))
                .IsEqualTo(Coordinate(mysql));
            await Assert.That(body["usernames"]!.Deserialize<string[]>(ServiceJson)!.SequenceEqual(Names)).IsTrue();
            await Assert.That(body.Select(pair => pair.Key).Order().ToArray())
                .IsEquivalentTo(new[] { "schemaVersion", "nonce", "coordinate", "usernames" });
            RotationIdentityCatalogFacts observed = Facts(mysql, false);
            observed = mysql
                ? observed with { Mysql = observed.Mysql! with { Accounts = mysqlStore.ToArray() } }
                : observed with
                {
                    Mssql = observed.Mssql! with
                    {
                        ServerPrincipals = serverStore.ToArray(),
                        DatabasePrincipals = databaseStore.ToArray()
                    }
                };
            return Reply(Envelope(body, observed));
        });
        IInfisicalRotationIdentityCatalogObserver observer = new InfisicalLifecycleObservers(Settings, handler);
        async Task<RotationIdentityCatalogFacts> Inspect() =>
            await observer.InspectIdentityCatalogAsync(Coordinate(mysql), Names, CancellationToken.None);
        await Assert.That(RotationSqlIdentityEvidence.IsAbsent(await Inspect())).IsTrue();
        if (mysql) mysqlStore.AddRange(Facts(true).Mysql!.Accounts);
        else serverStore.AddRange(Facts(false).Mssql!.ServerPrincipals);
        RotationIdentityCatalogFacts partial = await Inspect();
        await Assert.That(RotationSqlIdentityEvidence.IsAbsent(partial)).IsFalse();
        await Assert.That(RotationSqlIdentityEvidence.Owned(partial, Names)).IsEqualTo(mysql);
        if (!mysql) databaseStore.AddRange(Facts(false).Mssql!.DatabasePrincipals);
        await Assert.That(RotationSqlIdentityEvidence.Owned(await Inspect(), Names)).IsTrue();
        mysqlStore.Clear();
        serverStore.Clear();
        await Assert.That(RotationSqlIdentityEvidence.IsAbsent(await Inspect())).IsEqualTo(mysql);
        databaseStore.Clear();
        await Assert.That(RotationSqlIdentityEvidence.IsAbsent(await Inspect())).IsTrue();
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task EveryConstructorFieldIncludingNullableFieldsIsRequired(bool mysql)
    {
        JsonObject original = JsonSerializer.SerializeToNode(Facts(mysql), ServiceJson)!.AsObject();
        foreach (string[] path in FieldPaths(original, []))
        {
            using var handler = new Handler(async (request, token) =>
            {
                JsonObject response = Envelope(await Body(request, token), Facts(mysql));
                JsonNode node = response["facts"]!;
                foreach (string segment in path[..^1])
                    node = node is JsonArray array ? array[int.Parse(segment)]! : node[segment]!;
                node.AsObject().Remove(path[^1]);
                return Reply(response);
            });
            await Unavailable(new(Settings, handler), mysql);
        }
    }

    private static IEnumerable<string[]> FieldPaths(JsonNode node, string[] prefix)
    {
        if (node is JsonObject obj)
        {
            foreach ((string key, JsonNode? value) in obj)
            {
                string[] path = [.. prefix, key];
                yield return path;
                if (value is JsonObject or JsonArray)
                    foreach (string[] nested in FieldPaths(value, path)) yield return nested;
            }
        }
        else if (node is JsonArray array)
            for (int i = 0; i < array.Count; i++)
                if (array[i] is JsonObject item)
                    foreach (string[] nested in FieldPaths(item, [.. prefix, i.ToString()])) yield return nested;
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task CatalogRejectsSubstitutionIncompleteAndMalformedStructures(bool mysql)
    {
        string branch = mysql ? "mysql" : "mssql";
        string rows = mysql ? "accounts" : "serverPrincipals";
        var mutations = new List<Action<JsonObject>>
        {
            f => f["coordinate"]!["host"] = "other.invalid",
            f => f["coordinate"]!["account"] = "other",
            f => f["coordinate"]!["port"] = 1,
            f => f["coordinate"]!["database"] = "other",
            f => f["coordinate"]!["profile"] = "PostgresCredentials",
            f => f[branch]!["database"] = "other",
            f => f["requestedUsernames"] = new JsonArray(Names[1], Names[0]),
            f => f["requestedUsernames"] = new JsonArray(Names[0], "other"),
            f => f[branch] = null,
            f => f[mysql ? "mssql" : "mysql"] =
                JsonSerializer.SerializeToNode(Facts(!mysql), ServiceJson)![mysql ? "mssql" : "mysql"]!.DeepClone(),
            f => f[branch]![rows] = null,
            f => f[branch]![rows]![0] = null,
            f => f[branch]![rows]!.AsArray().Add(f[branch]![rows]![0]!.DeepClone()),
            f => f[branch]![rows]![0]![mysql ? "username" : "name"] = "other",
            f => f[branch]![mysql ? "allHostsComplete" : "serverPrincipalsComplete"] = false
        };
        if (mysql)
        {
            mutations.Add(f => f["mysql"]!["passwordPolicy"] = null);
            mutations.Add(f => f["mysql"]!["accounts"]![0]!["host"] = "");
            mutations.Add(f => f["mysql"]!["passwordPolicy"]!["activeValidationPlugins"] = null);
            mutations.Add(f => f["mysql"]!["passwordPolicy"]!["installedValidationComponents"] = new JsonArray(""));
            mutations.Add(f => f["mysql"]!["passwordPolicy"]!["activeValidationPlugins"] =
                new JsonArray("validate_password", "validate_password"));
        }
        else
        {
            mutations.Add(f => f["mssql"]!["databasePrincipalsComplete"] = false);
            mutations.Add(f => f["mssql"]!["databasePrincipals"] = null);
            mutations.Add(f => f["mssql"]!["databasePrincipals"]![0] = null);
            mutations.Add(f => f["mssql"]!["databasePrincipals"]!.AsArray()
                .Add(f["mssql"]!["databasePrincipals"]![0]!.DeepClone()));
            mutations.Add(f => f["mssql"]!["serverPrincipals"]![0]!["sid"] = null);
            mutations.Add(f => f["mssql"]!["databasePrincipals"]![0]!["sid"] = Convert.ToBase64String(new byte[86]));
        }
        foreach (Action<JsonObject> mutate in mutations)
        {
            using var handler = new Handler(async (request, token) =>
            {
                JsonObject response = Envelope(await Body(request, token), Facts(mysql));
                mutate(response["facts"]!.AsObject());
                return Reply(response);
            });
            await Unavailable(new(Settings, handler), mysql);
        }
        foreach (string[] names in new[] { Array.Empty<string>(), new[] { Names[0] },
            new[] { Names[0], Names[0] }, new[] { "", Names[1] } })
            await Assert.That(RotationSqlIdentityEvidence.Bound(Facts(mysql), Coordinate(mysql), names)).IsFalse();
    }

    [Test]
    public async Task BindingRetainsIncompatibleAndOtherHostCollisionEvidence()
    {
        RotationIdentityCatalogFacts mysql = Facts(true);
        mysql = mysql with { Mysql = mysql.Mysql! with { Accounts = [new(Names[0], "localhost", "auth_socket")] } };
        RotationIdentityCatalogFacts sql = Facts(false);
        sql = sql with
        {
            Mssql = sql.Mssql! with
            {
                ServerPrincipals = [new(Names[0], [], "WINDOWS_LOGIN", null, null, true)],
                DatabasePrincipals = [new(Names[1], [], "SQL_USER", "DATABASE")]
            }
        };
        foreach (RotationIdentityCatalogFacts collision in new[] { mysql, sql })
        {
            bool isMysql = collision.Mysql is not null;
            using var handler = new Handler(async (request, token) =>
                Reply(Envelope(await Body(request, token), collision)));
            var observer = new InfisicalLifecycleObservers(Settings, handler);
            RotationIdentityCatalogFacts measured =
                await observer.InspectIdentityCatalogAsync(Coordinate(isMysql), Names, CancellationToken.None);
            await Assert.That(RotationSqlIdentityEvidence.IsAbsent(measured)).IsFalse();
            await Assert.That(RotationSqlIdentityEvidence.Owned(measured, Names)).IsFalse();
        }
    }

    [Test]
    public async Task OwnershipUsesDeepSameNameDistinctSidMappingAndExactTypes()
    {
        RotationIdentityCatalogFacts facts = Facts(false);
        await Assert.That(RotationSqlIdentityEvidence.Owned(facts, Names)).IsTrue();
        MssqlRotationCatalogFacts catalog = facts.Mssql!;
        var invalid = new[]
        {
            catalog with { DatabasePrincipals = [catalog.DatabasePrincipals[0] with { Sid = [3, 4] },
                catalog.DatabasePrincipals[1] with { Sid = [1, 2] }] },
            catalog with { ServerPrincipals = [catalog.ServerPrincipals[0],
                catalog.ServerPrincipals[1] with { Sid = [1, 2] }],
                DatabasePrincipals = [catalog.DatabasePrincipals[0], catalog.DatabasePrincipals[1] with { Sid = [1, 2] }] },
            catalog with { ServerPrincipals = [catalog.ServerPrincipals[0] with { Sid = [] }, catalog.ServerPrincipals[1]] },
            catalog with { ServerPrincipals = [catalog.ServerPrincipals[0] with { IsPolicyChecked = true }, catalog.ServerPrincipals[1]] },
            catalog with { ServerPrincipals = [catalog.ServerPrincipals[0] with { IsExpirationChecked = null }, catalog.ServerPrincipals[1]] },
            catalog with { ServerPrincipals = [catalog.ServerPrincipals[0] with { IsDisabled = true }, catalog.ServerPrincipals[1]] },
            catalog with { ServerPrincipals = [catalog.ServerPrincipals[0] with { TypeDescription = "WINDOWS_LOGIN" }, catalog.ServerPrincipals[1]] },
            catalog with { DatabasePrincipals = [catalog.DatabasePrincipals[0] with { TypeDescription = "WINDOWS_USER" }, catalog.DatabasePrincipals[1]] },
            catalog with { DatabasePrincipals = [catalog.DatabasePrincipals[0] with { AuthenticationTypeDescription = "DATABASE" }, catalog.DatabasePrincipals[1]] },
            catalog with { DatabasePrincipals = [catalog.DatabasePrincipals[0]] }
        };
        foreach (MssqlRotationCatalogFacts changed in invalid)
        {
            await Assert.That(RotationSqlIdentityEvidence.Bound(facts with { Mssql = changed }, facts.Coordinate, Names)).IsTrue();
            await Assert.That(RotationSqlIdentityEvidence.Owned(facts with { Mssql = changed }, Names)).IsFalse();
        }
        RotationIdentityCatalogFacts mysql = Facts(true);
        foreach (MysqlRotationAccountFacts[] rows in new[]
        {
            new[] { mysql.Mysql!.Accounts[0] },
            new[] { mysql.Mysql!.Accounts[0] with { Host = "localhost" }, mysql.Mysql.Accounts[1] },
            new[] { mysql.Mysql!.Accounts[0] with { AuthenticationPlugin = "auth_socket" }, mysql.Mysql.Accounts[1] }
        })
            await Assert.That(RotationSqlIdentityEvidence.Owned(mysql with
            { Mysql = mysql.Mysql! with { Accounts = rows } }, Names)).IsFalse();
    }

    [Test]
    public async Task PolicyRequiresCompletePreparedLowOrStrictlyAbsentValidator()
    {
        RotationIdentityCatalogFacts facts = Facts(true, false);
        bool Compatible(MysqlPasswordPolicyFacts policy) =>
            RotationSqlIdentityEvidence.PolicyCompatible(facts with { Mysql = facts.Mysql! with { PasswordPolicy = policy } });
        await Assert.That(Compatible(NoValidator())).IsTrue();
        await Assert.That(Compatible(NoValidator() with { Policy = 0 })).IsFalse();
        await Assert.That(Compatible(NoValidator() with { IsComplete = false })).IsFalse();
        await Assert.That(RotationSqlIdentityEvidence.PolicyCompatible(Facts(false))).IsTrue();
        foreach (bool component in new[] { false, true })
        {
            MysqlPasswordPolicyFacts policy = Validator(component);
            await Assert.That(Compatible(policy)).IsTrue();
            await Assert.That(Compatible(policy with { MinimumLength = 1 })).IsTrue();
            await Assert.That(Compatible(policy with { MinimumLength = 24 })).IsTrue();
            foreach (MysqlPasswordPolicyFacts incompatible in new[]
            {
                policy with { IsComplete = false }, policy with { Policy = null }, policy with { Policy = 1 },
                policy with { MinimumLength = null }, policy with { MinimumLength = 0 },
                policy with { MinimumLength = 25 }, policy with { CheckUserName = null },
                policy with { CheckUserName = true }, policy with { MixedCaseCount = null },
                policy with { MixedCaseCount = -1 }, policy with { NumberCount = null },
                policy with { NumberCount = -1 }, policy with { SpecialCharCount = null },
                policy with { SpecialCharCount = -1 }, policy with { DictionaryFile = null },
                policy with { DictionaryFile = "dictionary" }, policy with { ChangedCharactersPercentage = 1 },
                policy with { ActiveValidationPlugins = ["unknown"] },
                policy with { InstalledValidationComponents = ["unknown"] },
                policy with { ActiveValidationPlugins = ["validate_password"],
                    InstalledValidationComponents = ["file://component_validate_password"] }
            })
                await Assert.That(Compatible(incompatible)).IsFalse();
            await Assert.That(Compatible(policy with { ChangedCharactersPercentage = null })).IsEqualTo(!component);
            await Assert.That(Compatible(policy with { ChangedCharactersPercentage = 0 })).IsTrue();
        }
    }

    [Test]
    public async Task PolicyEqualityComparesAllMeasuredFieldsAndDiscoveryArrays()
    {
        RotationIdentityCatalogFacts facts = Facts(true);
        MysqlPasswordPolicyFacts policy = Validator(false);
        facts = facts with { Mysql = facts.Mysql! with { PasswordPolicy = policy } };
        RotationIdentityCatalogFacts copy = JsonSerializer.Deserialize<RotationIdentityCatalogFacts>(
            JsonSerializer.Serialize(facts, ServiceJson), ServiceJson)!;
        await Assert.That(RotationSqlIdentityEvidence.SameMysqlPolicy(facts, copy)).IsTrue();
        foreach (MysqlPasswordPolicyFacts changed in new[]
        {
            policy with { IsComplete = false }, policy with { ActiveValidationPlugins = ["other"] },
            policy with { InstalledValidationComponents = ["other"] }, policy with { Policy = 1 },
            policy with { MinimumLength = 9 }, policy with { CheckUserName = true },
            policy with { MixedCaseCount = 2 }, policy with { NumberCount = 2 },
            policy with { SpecialCharCount = 2 }, policy with { DictionaryFile = "other" },
            policy with { ChangedCharactersPercentage = 0 }
        })
            await Assert.That(RotationSqlIdentityEvidence.SameMysqlPolicy(facts,
                copy with { Mysql = copy.Mysql! with { PasswordPolicy = changed } })).IsFalse();
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("identity")]
    [Arguments("schema")]
    [Arguments("stale")]
    [Arguments("future")]
    [Arguments("null")]
    [Arguments("unknown")]
    [Arguments("duplicate")]
    [Arguments("malformed")]
    [Arguments("budget")]
    [Arguments("depth")]
    public async Task CatalogRetainsStrictEnvelopeAndJsonBudgets(string mode)
    {
        using var handler = new Handler(async (request, token) =>
        {
            JsonObject response = Envelope(await Body(request, token), Facts(true));
            switch (mode)
            {
                case "nonce": response["nonce"] = "other"; break;
                case "identity": response["observerIdentity"] = "other"; break;
                case "schema": response["schemaVersion"] = 2; break;
                case "stale": response["observedAt"] = DateTimeOffset.UnixEpoch; break;
                case "future": response["observedAt"] = DateTimeOffset.UtcNow.AddDays(1); break;
                case "null": response["facts"] = null; break;
                case "unknown": response["facts"]!["unmeasured"] = true; break;
            }
            string json = response.ToJsonString();
            json = mode switch
            {
                "duplicate" => json.Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1", StringComparison.Ordinal),
                "malformed" => "{",
                "budget" => new string(' ', 1024 * 1024 + 1),
                "depth" => new string('[', 33) + "0" + new string(']', 33),
                _ => json
            };
            return new(HttpStatusCode.OK) { Content = new StringContent(json) };
        });
        await Unavailable(new(Settings, handler), true);
    }

    [Test]
    public async Task CatalogCancellationPropagatesAtExactHttpBoundary()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        using var handler = new Handler(async (_, token) =>
        {
            entered.TrySetResult();
            await new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously).Task.WaitAsync(token);
            throw new InvalidOperationException();
        });
        var observer = new InfisicalLifecycleObservers(Settings, handler);
        Task<RotationIdentityCatalogFacts> pending =
            observer.InspectIdentityCatalogAsync(Coordinate(true), Names, cancellation.Token).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task IdentityModelsHaveMaterialFreeFormattingAndRequiredCredentialFields()
    {
        object[] models = [Facts(true), Facts(true).Mysql!, Facts(true).Mysql!.Accounts[0], Validator(false),
            Facts(false).Mssql!, Facts(false).Mssql!.ServerPrincipals[0], Facts(false).Mssql!.DatabasePrincipals[0],
            new RotationCredentialIdentity(new("sensitive-user", "sensitive-database"), null),
            new MysqlCredentialIdentity("sensitive-user", "sensitive-database"),
            new MssqlCredentialIdentity("sensitive-user", [1], "sensitive-user", [1], "sensitive-user", [1], "sensitive-database")];
        foreach (object model in models)
        {
            await Assert.That(model.ToString()).IsEqualTo($"[{model.GetType().Name}]");
            if (model is RotationCredentialIdentity or MysqlCredentialIdentity or MssqlCredentialIdentity)
            {
                JsonObject original = JsonSerializer.SerializeToNode(model, model.GetType(), ServiceJson)!.AsObject();
                foreach (string key in original.Select(pair => pair.Key))
                {
                    JsonObject changed = original.DeepClone().AsObject();
                    changed.Remove(key);
                    await Assert.That(() => JsonSerializer.Deserialize(changed.ToJsonString(), model.GetType(), ServiceJson))
                        .Throws<JsonException>();
                }
            }
        }
    }

    private static async Task Unavailable(InfisicalLifecycleObservers observer, bool mysql)
    {
        string? reason = null;
        try { await observer.InspectIdentityCatalogAsync(Coordinate(mysql), Names, CancellationToken.None); }
        catch (NativeCaseFailureException error) { reason = error.Message; }
        await Assert.That(reason).IsEqualTo("observer-unavailable");
    }

    private static async Task<JsonObject> Body(HttpRequestMessage request, CancellationToken token) =>
        JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();

    private static JsonObject Envelope(JsonObject body, RotationIdentityCatalogFacts facts) => new()
    {
        ["schemaVersion"] = 1,
        ["nonce"] = body["nonce"]!.DeepClone(),
        ["observerIdentity"] = Settings.Identity,
        ["observedAt"] = DateTimeOffset.UtcNow,
        ["facts"] = JsonSerializer.SerializeToNode(facts, ServiceJson)
    };

    private static HttpResponseMessage Reply(JsonObject body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body.ToJsonString()) };

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }
}
