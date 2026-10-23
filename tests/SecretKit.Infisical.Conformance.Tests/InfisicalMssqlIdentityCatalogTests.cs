using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalMssqlIdentityCatalogTests
{
    private static readonly RotationBackendCoordinate Coordinate =
        new(InfisicalRotationProfile.MssqlCredentials, "database.invalid", 1433, "owned", "fixture-account");
    private static readonly string[] Names = ["sk_identity_a", "sk_identity_b"];

    [Test]
    public async Task IndependentStoresDriveExistingAbsenceOwnershipAndCompletenessValidators()
    {
        JsonObject master = Output("master"), database = Output("owned");
        var observer = Catalog(master, database);
        var absent = await observer.InspectIdentityCatalogAsync(Coordinate, Names, default);
        await Assert.That(RotationSqlIdentityEvidence.IsAbsent(absent)).IsTrue();
        await Assert.That(RotationSqlIdentityEvidence.PolicyEstablished(absent)).IsTrue();
        await Assert.That(absent.Mssql!.ServerPrincipalsComplete && absent.Mssql.DatabasePrincipalsComplete).IsTrue();
        await Assert.That(RotationSqlIdentityEvidence.Bound(absent with
        {
            Mssql = absent.Mssql with { ServerPrincipalsComplete = false }
        }, Coordinate, Names)).IsFalse();
        await Assert.That(RotationSqlIdentityEvidence.Bound(absent with
        {
            Mssql = absent.Mssql with { DatabasePrincipalsComplete = false }
        }, Coordinate, Names)).IsFalse();
        foreach (string name in Names) master["principals"]!.AsArray().Add(Login(name));
        var serverOnly = await observer.InspectIdentityCatalogAsync(Coordinate, Names, default);
        await Assert.That(RotationSqlIdentityEvidence.IsAbsent(serverOnly)).IsFalse();
        await Assert.That(RotationSqlIdentityEvidence.Owned(serverOnly, Names)).IsFalse();
        foreach (string name in Names) database["principals"]!.AsArray().Add(User(name));
        var owned = await observer.InspectIdentityCatalogAsync(Coordinate, Names, default);
        await Assert.That(RotationSqlIdentityEvidence.Owned(owned, Names)).IsTrue();
        master["principals"]!.AsArray().Clear();
        var databaseOnly = await observer.InspectIdentityCatalogAsync(Coordinate, Names, default);
        await Assert.That(RotationSqlIdentityEvidence.IsAbsent(databaseOnly)).IsFalse();
        await Assert.That(RotationSqlIdentityEvidence.Owned(databaseOnly, Names)).IsFalse();
        await Assert.That(RotationSqlIdentityEvidence.Bound(owned, Coordinate with { Account = "other" }, Names)).IsFalse();
        await Assert.That(RotationSqlIdentityEvidence.Bound(owned, Coordinate, Names.Reverse().ToArray())).IsFalse();
    }

    [Test]
    [Arguments("windows")]
    [Arguments("certificate")]
    [Arguments("contained")]
    [Arguments("external")]
    [Arguments("policy-null")]
    [Arguments("expiration-null")]
    [Arguments("policy")]
    [Arguments("expiration")]
    [Arguments("disabled")]
    [Arguments("empty-login-sid")]
    [Arguments("empty-user-sid")]
    [Arguments("mismatch")]
    [Arguments("same-sids")]
    public async Task NativeCollisionsFlagsAndSidDataArePreservedRatherThanDiscarded(string state)
    {
        JsonObject master = Output("master"), database = Output("owned");
        foreach (string name in Names)
        {
            master["principals"]!.AsArray().Add(Login(name));
            database["principals"]!.AsArray().Add(User(name));
        }
        JsonNode login = master["principals"]![0]!, user = database["principals"]![0]!;
        switch (state)
        {
            case "windows": login["type"] = Hex("WINDOWS_LOGIN"); break;
            case "certificate": login["type"] = Hex("CERTIFICATE_MAPPED_LOGIN"); break;
            case "contained": user["authentication"] = Hex("DATABASE"); break;
            case "external": user["type"] = Hex("EXTERNAL_USER"); user["authentication"] = Hex("EXTERNAL"); break;
            case "policy-null": login["policy"] = null; break;
            case "expiration-null": login["expiration"] = null; break;
            case "policy": login["policy"] = true; break;
            case "expiration": login["expiration"] = true; break;
            case "disabled": login["disabled"] = true; break;
            case "empty-login-sid": login["sid"] = ""; break;
            case "empty-user-sid": user["sid"] = ""; break;
            case "mismatch": user["sid"] = "FE"; break;
            case "same-sids":
                master["principals"]![1]!["sid"] = "01";
                database["principals"]![1]!["sid"] = "01";
                break;
        }
        var facts = await Catalog(master, database).InspectIdentityCatalogAsync(Coordinate, Names, default);
        await Assert.That(RotationSqlIdentityEvidence.Bound(facts, Coordinate, Names)).IsTrue();
        await Assert.That(RotationSqlIdentityEvidence.IsAbsent(facts)).IsFalse();
        await Assert.That(RotationSqlIdentityEvidence.Owned(facts, Names)).IsFalse();
        await Assert.That(facts.Mssql!.ServerPrincipals.Length).IsEqualTo(2);
        await Assert.That(facts.Mssql.DatabasePrincipals.Length).IsEqualTo(2);
        await Assert.That(facts.Mssql.ServerPrincipals[0].IsPolicyChecked)
            .IsEqualTo(state == "policy-null" ? null : state == "policy");
        await Assert.That(facts.Mssql.ServerPrincipals[0].IsExpirationChecked)
            .IsEqualTo(state == "expiration-null" ? null : state == "expiration");
        await Assert.That(facts.Mssql.ServerPrincipals[0].TypeDescription)
            .IsEqualTo(Encoding.Unicode.GetString(Convert.FromHexString(login["type"]!.GetValue<string>())));
        await Assert.That(facts.Mssql.DatabasePrincipals[0].AuthenticationTypeDescription)
            .IsEqualTo(Encoding.Unicode.GetString(Convert.FromHexString(user["authentication"]!.GetValue<string>())));
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task EachCatalogMustIndependentlyValidateEveryNativeAuthorityAndFramingField(bool server)
    {
        string[] faults = ["sysadmin-null", "sysadmin-zero", "sysadmin-negative", "reader", "execution-reader",
            "reader-sid-null", "reader-sid-empty", "execution-sid-null", "execution-sid-empty", "execution-sid-mismatch",
            "database-user", "server", "version-null", "version-empty", "edition-null", "edition-azure",
            "edition-unknown", "database", "column-null", "column-empty", "catalog-null", "collation-mismatch",
            "native-equal", "native-equal-null", "foreign-row", "equivalent-row", "duplicate-row", "null-row-sid",
            "invalid-row-sid", "long-row-sid", "null-type", "empty-type", "unknown-field", "missing-field",
            "missing-rows", "null-rows", "three-rows", "invalid-hex", "invalid-utf16", "control-text",
            "long-text", "duplicate-json", "partial-json", "overflow", "exit", "trailing-output", "wrong-row-field"];
        foreach (string fault in faults)
        {
            JsonObject master = Output("master"), database = Output("owned");
            JsonObject output = server ? master : database;
            JsonObject row = server ? Login(Names[0]) : User(Names[0]);
            switch (fault)
            {
                case "sysadmin-null": output["sysadmin"] = null; break;
                case "sysadmin-zero": output["sysadmin"] = 0; break;
                case "sysadmin-negative": output["sysadmin"] = -1; break;
                case "reader": output["originalLogin"] = Hex("other"); break;
                case "execution-reader": output["currentLogin"] = Hex("other"); break;
                case "reader-sid-null": output["originalSid"] = null; break;
                case "reader-sid-empty": output["originalSid"] = ""; break;
                case "execution-sid-null": output["currentSid"] = null; break;
                case "execution-sid-empty": output["currentSid"] = ""; break;
                case "execution-sid-mismatch": output["currentSid"] = "FE"; break;
                case "database-user": output["databaseUser"] = Hex("guest"); break;
                case "server": output["serverIdentity"] = Hex("foreign-server"); break;
                case "version-null": output["productVersion"] = null; break;
                case "version-empty": output["productVersion"] = ""; break;
                case "edition-null": output["engineEdition"] = null; break;
                case "edition-azure": output["engineEdition"] = 5; break;
                case "edition-unknown": output["engineEdition"] = 99; break;
                case "database": output["database"] = Hex("foreign"); break;
                case "column-null": output["columnCollation"] = null; break;
                case "column-empty": output["columnCollation"] = ""; break;
                case "catalog-null": output["catalogCollation"] = null; break;
                case "collation-mismatch": output["columnCollation"] = Hex("Latin1_General_100_BIN2"); break;
                case "native-equal": output["namesDistinct"] = false; break;
                case "native-equal-null": output["namesDistinct"] = null; break;
                case "foreign-row": row["name"] = Hex("foreign"); break;
                case "equivalent-row": row["name"] = Hex(Names[0].ToUpperInvariant()); break;
                case "duplicate-row": output["principals"]!.AsArray().Add(row.DeepClone()); break;
                case "null-row-sid": row["sid"] = null; break;
                case "invalid-row-sid": row["sid"] = "Z0"; break;
                case "long-row-sid": row["sid"] = new string('A', 172); break;
                case "null-type": row["type"] = null; break;
                case "empty-type": row["type"] = ""; break;
                case "unknown-field": output["extra"] = 1; break;
                case "missing-field": output.Remove("currentLogin"); break;
                case "missing-rows": output.Remove("principals"); break;
                case "null-rows": output["principals"] = null; break;
                case "three-rows":
                    output["principals"]!.AsArray().Add(row.DeepClone());
                    output["principals"]!.AsArray().Add(row.DeepClone());
                    break;
                case "invalid-hex": row["name"] = "ZZZZ"; break;
                case "invalid-utf16": row["name"] = "00D8"; break;
                case "control-text": row["name"] = Hex("bad\n"); break;
                case "long-text": row["type"] = Hex(new string('a', 129)); break;
                case "wrong-row-field": row["extra"] = false; break;
            }
            if (output["principals"] is JsonArray rows) rows.Add(row);
            var observer = new InfisicalMssqlIdentityCatalog(Element(Profile()), (_, arguments, _, _) =>
            {
                JsonObject selected = Database(arguments) == "master" ? master : database;
                string text = selected.ToJsonString();
                if (ReferenceEquals(selected, output))
                    text = fault switch
                    {
                        "duplicate-json" => "{\"sysadmin\":1," + text[1..],
                        "partial-json" => text[..^1],
                        "overflow" => text + new string(' ', 48001),
                        "trailing-output" => text + "\n1 rows affected",
                        _ => text
                    };
                return Task.FromResult((ReferenceEquals(selected, output) && fault == "exit" ? 1 : 0, text));
            });
            await Assert.That(async () => await observer.InspectIdentityCatalogAsync(Coordinate, Names, default))
                .Throws<NativeCaseFailureException>();
        }
    }

    [Test]
    [Arguments("policy")]
    [Arguments("expiration")]
    [Arguments("disabled")]
    [Arguments("authentication")]
    public async Task InvalidFlagAndAuthenticationTypesCannotBecomeFacts(string field)
    {
        JsonObject master = Output("master"), database = Output("owned");
        JsonObject row = field == "authentication" ? User(Names[0]) : Login(Names[0]);
        row[field] = field == "disabled" ? null : JsonValue.Create(1);
        (field == "authentication" ? database : master)["principals"]!.AsArray().Add(row);
        await Assert.That(async () => await Catalog(master, database).InspectIdentityCatalogAsync(Coordinate, Names, default))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("version")]
    [Arguments("edition")]
    [Arguments("sid")]
    public async Task TwoIndividuallyValidStoresCannotSubstituteDifferentSourceInstances(string field)
    {
        JsonObject master = Output("master"), database = Output("owned");
        if (field == "version") database["productVersion"] = Hex("16.0.2000.1");
        if (field == "edition") database["engineEdition"] = 2;
        if (field == "sid")
        {
            database["originalSid"] = "FE";
            database["currentSid"] = "FE";
        }
        await Assert.That(async () => await Catalog(master, database).InspectIdentityCatalogAsync(Coordinate, Names, default))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    public async Task TraditionalEditionsAndIndependentCatalogCollationsRemainValid(int edition)
    {
        JsonObject master = Output("master"), database = Output("owned");
        master["engineEdition"] = edition;
        database["engineEdition"] = edition;
        database["columnCollation"] = Hex("Latin1_General_100_BIN2");
        database["catalogCollation"] = Hex("Latin1_General_100_BIN2");
        var facts = await Catalog(master, database).InspectIdentityCatalogAsync(Coordinate, Names, default);
        await Assert.That(RotationSqlIdentityEvidence.IsAbsent(facts)).IsTrue();
    }

    [Test]
    public async Task LongHexFramedRowsSurviveBothDefaultClientTruncationThresholds()
    {
        JsonObject master = Output("master"), database = Output("owned");
        JsonObject profile = Profile();
        profile["username"] = new string('r', 128);
        profile["serverIdentity"] = new string('s', 128);
        foreach (JsonObject output in new[] { master, database })
        {
            output["originalLogin"] = Hex(new string('r', 128));
            output["currentLogin"] = Hex(new string('r', 128));
            output["serverIdentity"] = Hex(new string('s', 128));
        }
        string[] names = [new string('a', 128), new string('b', 128)];
        foreach (string name in names)
        {
            JsonObject login = Login(name), user = User(name);
            login["sid"] = new string('A', 170);
            user["sid"] = new string('A', 170);
            login["type"] = Hex(new string('T', 128));
            user["type"] = Hex(new string('T', 128));
            user["authentication"] = Hex(new string('I', 128));
            master["principals"]!.AsArray().Add(login);
            database["principals"]!.AsArray().Add(user);
        }
        await Assert.That(master.ToJsonString().Length > 4000 && database.ToJsonString().Length > 4000).IsTrue();
        var observer = new InfisicalMssqlIdentityCatalog(Element(profile), (_, arguments, _, _) =>
            Task.FromResult((0, (Database(arguments) == "master" ? master : database).ToJsonString())));
        var facts = await observer.InspectIdentityCatalogAsync(Coordinate, names, default);
        await Assert.That(facts.Mssql!.ServerPrincipals[0].Name.Length).IsEqualTo(128);
        await Assert.That(facts.Mssql.DatabasePrincipals[1].Sid.Length).IsEqualTo(85);
        await Assert.That(RotationSqlIdentityEvidence.Bound(facts, Coordinate, names)).IsTrue();
    }

    [Test]
    [Arguments(4000)]
    [Arguments(48000)]
    [Arguments(48001)]
    public async Task ScalarOutputBudgetIsEnforcedWithoutDefaultClientWidthTruncation(int length)
    {
        var observer = new InfisicalMssqlIdentityCatalog(Element(Profile()), (_, arguments, _, _) =>
        {
            string text = Output(Database(arguments)).ToJsonString();
            return Task.FromResult((0, text.PadRight(length)));
        });
        if (length > 48000)
            await Assert.That(async () => await observer.InspectIdentityCatalogAsync(Coordinate, Names, default))
                .Throws<NativeCaseFailureException>();
        else
            await Assert.That(RotationSqlIdentityEvidence.IsAbsent(
                await observer.InspectIdentityCatalogAsync(Coordinate, Names, default))).IsTrue();
    }

    [Test]
    public async Task FixedReaderAndEndpointAcceptChangingRequestSubjectsWithoutPasswordArguments()
    {
        var queries = new List<string[]>();
        var observer = new InfisicalMssqlIdentityCatalog(Element(Profile()), async (query, arguments, environment, token) =>
        {
            token.ThrowIfCancellationRequested();
            string[] subjects = Regex.Matches(query, @"0x([0-9A-F]+)")
                .Select(m => Encoding.Unicode.GetString(Convert.FromHexString(m.Groups[1].Value))).ToArray();
            queries.Add(subjects);
            await Assert.That(subjects.Length).IsEqualTo(2);
            await Assert.That(arguments[0]).IsEqualTo("-S");
            await Assert.That(arguments[1]).IsEqualTo("tcp:database.invalid,1433");
            await Assert.That(arguments[2]).IsEqualTo("-U");
            await Assert.That(arguments[3]).IsEqualTo("catalog");
            await Assert.That(arguments.Contains("-Nm") && arguments.Contains("-x") && arguments.Contains("-b")).IsTrue();
            foreach (string forbidden in new[] { "-W", "-Y", "-X", "-C", "-F", "-P", "-E", "-Q", "-i" })
                await Assert.That(arguments.Contains(forbidden)).IsFalse();
            foreach (var pair in new[] { ("-h", "-1"), ("-y", "0"), ("-w", "60000"), ("-r", "1") })
                await Assert.That(arguments[arguments.ToList().IndexOf(pair.Item1) + 1]).IsEqualTo(pair.Item2);
            await Assert.That(environment.Count).IsEqualTo(1);
            await Assert.That(environment["SQLCMDPASSWORD"]).IsEqualTo("private-catalog-password");
            await Assert.That(arguments.Any(a => a.Contains(environment["SQLCMDPASSWORD"], StringComparison.Ordinal)) ||
                query.Contains(environment["SQLCMDPASSWORD"], StringComparison.Ordinal)).IsFalse();
            return (0, Output(Database(arguments)).ToJsonString());
        });
        string[][] pairs = [Names, ["nonce_2_a", "nonce_2_b"], ["quote'$(data)", "semi;[data]"], ["\u0394_reader_a", "\u0394_reader_b"],
            ["\U0001F600_a", "\U0001F600_b"]];
        foreach (string[] names in pairs)
        {
            var coordinate = Coordinate with { Account = names[0] };
            var facts = await observer.InspectIdentityCatalogAsync(coordinate, names, default);
            await Assert.That(RotationSqlIdentityEvidence.Bound(facts, coordinate, names)).IsTrue();
        }
        await Assert.That(queries.Count).IsEqualTo(10);
        for (int i = 0; i < queries.Count; i++)
            await Assert.That(queries[i].SequenceEqual(pairs[i / 2], StringComparer.Ordinal)).IsTrue();
    }

    [Test]
    public async Task ForeignBindingsAndInvalidSubjectsFailBeforeAnyProcessStarts()
    {
        bool reached = false;
        var observer = new InfisicalMssqlIdentityCatalog(Element(Profile()), (_, _, _, _) =>
        {
            reached = true;
            throw new InvalidOperationException("Foreign request reached process.");
        });
        RotationBackendCoordinate[] coordinates = [Coordinate with { Profile = InfisicalRotationProfile.MysqlCredentials },
            Coordinate with { Host = "foreign.invalid" }, Coordinate with { Port = 1444 }, Coordinate with { Database = "foreign" },
            Coordinate with { Account = "" }, Coordinate with { Account = new string('a', 129) }];
        foreach (var coordinate in coordinates)
            await Assert.That(async () => await observer.InspectIdentityCatalogAsync(coordinate, Names, default))
                .Throws<NativeCaseFailureException>();
        string[][] pairs = [[], [Names[0]], [Names[0], Names[0]], [Names[0], Names[1], "extra"],
            ["", Names[1]], ["bad\n", Names[1]], [new string('a', 129), Names[1]]];
        foreach (var names in pairs)
            await Assert.That(async () => await observer.InspectIdentityCatalogAsync(Coordinate, names, default))
                .Throws<NativeCaseFailureException>();
        await Assert.That(reached).IsFalse();
    }

    [Test]
    public async Task StrictSevenFieldProfilesRejectMalformedOrForeignAuthority()
    {
        string[] faults = ["missing", "extra", "null", "duplicate", "host", "host-option", "port", "port-type",
            "database", "database-option", "username", "username-option", "password", "server", "timeout-zero", "timeout-long", "timeout-type"];
        foreach (string fault in faults)
        {
            JsonObject profile = Profile();
            switch (fault)
            {
                case "missing": profile.Remove("password"); break;
                case "extra": profile["executable"] = "other"; break;
                case "host": profile["host"] = ""; break;
                case "host-option": profile["host"] = "host,-E"; break;
                case "port": profile["port"] = 0; break;
                case "port-type": profile["port"] = "1433"; break;
                case "database": profile["database"] = new string('a', 129); break;
                case "database-option": profile["database"] = "-E"; break;
                case "username": profile["username"] = null; break;
                case "username-option": profile["username"] = "-E"; break;
                case "password": profile["password"] = ""; break;
                case "server": profile["serverIdentity"] = null; break;
                case "timeout-zero": profile["timeoutSeconds"] = 0; break;
                case "timeout-long": profile["timeoutSeconds"] = 61; break;
                case "timeout-type": profile["timeoutSeconds"] = "10"; break;
            }
            string text = fault switch
            {
                "null" => "null",
                "duplicate" => "{\"port\":1433," + profile.ToJsonString()[1..],
                _ => profile.ToJsonString()
            };
            using JsonDocument document = JsonDocument.Parse(text);
            await Assert.That(() => new InfisicalMssqlIdentityCatalog(document.RootElement))
                .Throws<NativeCaseFailureException>();
        }
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(false, true)]
    [Arguments(true, false)]
    [Arguments(true, true)]
    public async Task CancellationAndDeadlineDrainTheActualQueryBeforeReturning(bool deadline, bool selectedDatabase)
    {
        using var caller = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int queries = 0;
        JsonObject profile = Profile();
        profile["timeoutSeconds"] = 1;
        var observer = new InfisicalMssqlIdentityCatalog(Element(profile), async (_, arguments, _, token) =>
        {
            queries++;
            if (selectedDatabase && Database(arguments) == "master") return (0, Output("master").ToJsonString());
            using var registration = token.Register(() => cancelled.TrySetResult());
            entered.TrySetResult();
            await release.Task;
            return (0, Output(Database(arguments)).ToJsonString());
        });
        Task<RotationIdentityCatalogFacts> pending = observer.InspectIdentityCatalogAsync(Coordinate, Names, caller.Token).AsTask();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            if (!deadline) caller.Cancel();
            await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.That(pending.IsCompleted).IsFalse();
        }
        finally { release.TrySetResult(); }
        if (deadline)
            await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(5))).Throws<NativeCaseFailureException>();
        else
            await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(5))).Throws<OperationCanceledException>();
        await Assert.That(queries).IsEqualTo(selectedDatabase ? 2 : 1);
    }

    [Test]
    public async Task PrecancelledCallerCannotStartNativeObservation()
    {
        bool reached = false;
        var observer = new InfisicalMssqlIdentityCatalog(Element(Profile()), (_, _, _, _) =>
        {
            reached = true;
            throw new InvalidOperationException("Precancelled query started.");
        });
        using var caller = new CancellationTokenSource();
        caller.Cancel();
        await Assert.That(async () => await observer.InspectIdentityCatalogAsync(Coordinate, Names, caller.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(reached).IsFalse();
    }

    private static InfisicalMssqlIdentityCatalog Catalog(JsonObject master, JsonObject database) =>
        new(Element(Profile()), (_, arguments, _, _) =>
            Task.FromResult((0, (Database(arguments) == "master" ? master : database).ToJsonString())));

    private static string Database(IReadOnlyList<string> arguments) => arguments[arguments.ToList().IndexOf("-d") + 1];
    private static string Hex(string value) => Convert.ToHexString(Encoding.Unicode.GetBytes(value));
    private static JsonElement Element(JsonNode node) => JsonSerializer.SerializeToElement(node);
    private static JsonObject Profile() => new()
    {
        ["host"] = "database.invalid",
        ["port"] = 1433,
        ["database"] = "owned",
        ["username"] = "catalog",
        ["password"] = "private-catalog-password",
        ["serverIdentity"] = "fixture-server",
        ["timeoutSeconds"] = 10
    };

    private static JsonObject Output(string database) => new()
    {
        ["serverIdentity"] = Hex("fixture-server"),
        ["productVersion"] = Hex("16.0.1000.1"),
        ["engineEdition"] = 3,
        ["database"] = Hex(database),
        ["originalLogin"] = Hex("catalog"),
        ["originalSid"] = "AABB",
        ["currentLogin"] = Hex("catalog"),
        ["currentSid"] = "AABB",
        ["databaseUser"] = Hex("dbo"),
        ["sysadmin"] = 1,
        ["columnCollation"] = Hex("SQL_Latin1_General_CP1_CI_AS"),
        ["catalogCollation"] = Hex("SQL_Latin1_General_CP1_CI_AS"),
        ["namesDistinct"] = true,
        ["principals"] = new JsonArray()
    };

    private static JsonObject Login(string name) => new()
    {
        ["name"] = Hex(name),
        ["sid"] = name == Names[1] ? "02" : "01",
        ["type"] = Hex("SQL_LOGIN"),
        ["policy"] = false,
        ["expiration"] = false,
        ["disabled"] = false
    };

    private static JsonObject User(string name) => new()
    {
        ["name"] = Hex(name),
        ["sid"] = name == Names[1] ? "02" : "01",
        ["type"] = Hex("SQL_USER"),
        ["authentication"] = Hex("INSTANCE")
    };
}
