using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// This controlled source reads the fixture's committed store and session journal.
// Arm supplies correlation only. It cannot supply any successful effect fact.
internal sealed class InfisicalSqlInputEffectSource(InfisicalSqlInputEffectFixture fixture) : HttpMessageHandler
{
    private SqlInputRootAttempt? root;
    private SqlInputBinding? binding;
    private SqlInputArm? arm;
    private SqlInputFence? fence;
    private JsonObject? profiles;
    private long cursor;
    private bool ownedRoot;
    internal int Observations { get; private set; }
    internal int Closes { get; private set; }

    internal InfisicalSqlInputObserver CreateObserver() => new(
        new(new(new("https://controlled.invalid/private/"), "controlled-source-token", "sql-source", 30), this),
        "sql-source", SqlInputSource.ControlledFixture);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token);
        JsonObject command;
        try { command = JsonNode.Parse(bytes)!.AsObject(); }
        finally { Array.Clear(bytes); }
        object result = request.RequestUri!.Segments.Last() switch
        {
            "open" => Open(command),
            "arm" => Arm(command),
            "complete" => Complete(command),
            "observe" => Observe(command),
            "close" => Close(command),
            _ => throw new InvalidOperationException("controlled-source-command")
        };
        return new(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new
            {
                schemaVersion = 1,
                nonce = command["nonce"]!.GetValue<string>(),
                observerIdentity = "sql-source",
                observedAt = DateTimeOffset.UtcNow,
                facts = result
            }, options: InfisicalSqlInputEffectTests.Options)
        };
    }

    private SqlInputBinding Open(JsonObject command)
    {
        root = command["attempt"]!.Deserialize<SqlInputRootAttempt>(InfisicalSqlInputEffectTests.Options)!;
        profiles = command["profiles"]!.DeepClone().AsObject();
        bool absent = !ownedRoot && fixture.DefinitionCount == 0 && fixture.LeaseCount == 0 &&
            fixture.PrincipalCount == 0;
        ownedRoot = true;
        bool different = fixture.Baseline.Host != fixture.Selected.Host &&
            fixture.Baseline.Username != fixture.Selected.Username && fixture.Baseline.Database != fixture.Selected.Database &&
            fixture.Baseline.Port != fixture.Selected.Port && fixture.Baseline.Password != fixture.Selected.Password;
        binding = new(root, Guid.NewGuid().ToString(), "sql-source", "provider-application-clock", "controlled-epoch",
            Time(), Tick(), ownedRoot, absent,
            fixture.AdminAccepted(fixture.Baseline, fixture.Baseline.Password),
            fixture.AdminAccepted(fixture.Selected, fixture.Selected.Password),
            !fixture.AdminAccepted(fixture.Baseline, "wrong") && !fixture.AdminAccepted(fixture.Selected, "wrong"),
            different, fixture.Mode != "source-missing", true, true, true);
        return binding;
    }

    private SqlInputArm Arm(JsonObject command)
    {
        var attempt = command["attempt"]!.Deserialize<SqlInputAttempt>(InfisicalSqlInputEffectTests.Options)!;
        arm = new(attempt, Guid.NewGuid().ToString(), Tick(), Time(), true);
        return arm;
    }

    private SqlInputFence Complete(JsonObject command)
    {
        var received = command["arm"]!.Deserialize<SqlInputArm>(InfisicalSqlInputEffectTests.Options)!;
        var receipt = command["receipt"]!.Deserialize<DispatchEvidence>(InfisicalSqlInputEffectTests.Options);
        // Only original native requests recorded after the arm qualify. A host
        // cancellation with no upstream request remains zero, not invented one.
        var actual = fixture.Mutations.Where(m => m.Sequence > received.Cursor &&
            m.Name == received.Attempt.OriginalName).ToArray();
        int committed = actual.Count(m => m.Applied);
        Guid? definition = actual.LastOrDefault(m => m.Applied) is { } applied ?
            Guid.Parse(applied.Definition) : received.Attempt.DefinitionId;
        bool absent = definition is null || fixture.DefinitionCount == 0;
        fence = new(received, receipt, Guid.NewGuid().ToString(),
            actual.Length == 0 ? null : "native-request-" + actual[0].Sequence, Tick(), Time(),
            actual.Length, committed, committed > 0, definition, true, absent,
            fixture.Mode != "unsettled", fixture.Mode != "unsettled", actual.Length <= 1);
        arm = null;
        return fence;
    }

    private SqlInputObservation Observe(JsonObject command)
    {
        Guid definition = command["definitionId"]!.GetValue<Guid>();
        var configuration = command["configuration"]!.Deserialize<SqlInputConfiguration>(InfisicalSqlInputEffectTests.Options);
        string phase = command["phase"]!.GetValue<string>();
        var snapshot = fixture.Snapshot(definition);
        JsonObject actual = snapshot["committedInputs"]!.AsObject();
        var original = profiles!["baseline"]!.Deserialize<DynamicSqlInput>(InfisicalSqlInputEffectTests.Options)!;
        var selected = profiles["selected"]!.Deserialize<DynamicSqlInput>(InfisicalSqlInputEffectTests.Options)!;
        string variant = profiles["variant"]!.GetValue<string>();
        bool creation = profiles["operation"]!.GetValue<string>() == "CreateDefinitionAsync";
        JsonObject expected = configuration == SqlInputConfiguration.Selected && creation ?
            Map(selected, variant) : Map(original);
        if (configuration == SqlInputConfiguration.Selected && !creation && variant != "inputs.omitted")
            foreach (var pair in Map(selected, variant)) expected[pair.Key] = pair.Value?.DeepClone();
        var sessions = fixture.Sessions.Where(s => s.Definition == definition && s.Phase == "issue").ToArray();
        var latest = sessions.LastOrDefault();
        var fresh = fixture.Issuances.LastOrDefault(i => i.Definition == definition);
        bool storage = JsonNode.DeepEquals(actual, expected);
        bool admin = latest is not null && latest.Accepted && latest.Admin == Text(actual, "username");
        bool target = latest is not null && latest.Host == Text(actual, "host") &&
            fresh is not null && fresh.Host == latest.Host && fresh.Port == actual["port"]!.GetValue<int>() &&
            fresh.Database == Text(actual, "database");
        bool route = latest is not null && latest.Gateway == Text(actual, "gatewayId") &&
            latest.Pool == Text(actual, "gatewayPoolId") &&
            fixture.RouteAccepted(latest.Host, latest.Gateway, latest.Pool);
        bool tls = latest is not null && latest.Ca == Text(actual, "ca") &&
            latest.MssqlEncryption == (fixture.Engine == NativeSqlEngine.SqlServer &&
                actual["sslEnabled"]?.GetValue<bool>() == true);
        bool statements = latest is not null && fresh is not null &&
            latest.Statement == Text(actual, "creationStatement") && fresh.CreationStatement == latest.Statement;
        var settings = profiles["options"]!.AsObject();
        bool options = true;
        if (configuration == SqlInputConfiguration.Selected && settings["optionsSupplied"]?.GetValue<bool>() == true)
        {
            if (variant is "metadata.value" or "metadata.empty")
                options &= JsonNode.DeepEquals(snapshot["metadata"],
                    variant == "metadata.empty" ? new JsonArray() : settings["metadata"]);
            if (variant == "usernameTemplate.value")
                options &= JsonNode.DeepEquals(snapshot["usernameTemplate"], settings["usernameTemplate"]);
        }
        if (configuration == SqlInputConfiguration.Selected && settings["clearUsernameTemplate"]?.GetValue<bool>() == true)
            options &= snapshot["usernameTemplate"] is null;
        Observations++;
        return new(binding!, definition, configuration, phase, Guid.NewGuid().ToString(), Tick(), Time(),
            true, storage, options, admin, target,
            !fixture.AdminAccepted(fixture.Baseline, "wrong") && !fixture.AdminAccepted(fixture.Selected, "wrong"),
            latest is not null, route, tls, fixture.TrustAccepted(Text(actual, "host"), Text(actual, "ca")),
            !fixture.TrustAccepted(Text(actual, "host"), "invalid-trust"),
            fresh is not null && latest is not null && latest.Sequence > (fence?.Arm.Cursor ?? 0), statements);
    }

    private SqlInputCleanup Close(JsonObject command)
    {
        var original = command["attempt"]!.Deserialize<SqlInputRootAttempt>(InfisicalSqlInputEffectTests.Options)!;
        ownedRoot = false;
        profiles?.Clear();
        profiles = null;
        Closes++;
        return new(original, true, !ownedRoot, fixture.BorrowedRootIntact,
            fixture.DefinitionCount == 0, fixture.LeaseCount == 0, fixture.PrincipalCount == 0,
            profiles is null, fixture.Mode != "unsettled", fixture.Mode != "unsettled",
            arm is null ? 0 : 1, 0);
    }

    private long Tick()
    {
        cursor = fixture.Tick();
        return cursor;
    }
    private DateTimeOffset Time() => InfisicalSqlInputEffectFixture.Epoch.AddTicks(Math.Max(cursor, fixture.Sequence));
    private static string Text(JsonObject json, string key) => json[key]?.GetValue<string>() ?? "";

    private static JsonObject Map(DynamicSqlInput input, string variant = "full")
    {
        var result = new JsonObject
        {
            ["client"] = input.Engine switch
            {
                NativeSqlEngine.Postgres => "postgres",
                NativeSqlEngine.Mysql => "mysql2",
                NativeSqlEngine.Oracle => "oracledb",
                NativeSqlEngine.SqlServer => "mssql",
                NativeSqlEngine.SapAse => "sap-ase",
                NativeSqlEngine.Vertica => "vertica",
                _ => throw new InvalidOperationException("controlled-engine")
            },
            ["host"] = input.Host,
            ["port"] = input.Port,
            ["database"] = input.Database,
            ["username"] = input.Username,
            ["password"] = input.Password,
            ["creationStatement"] = input.CreationStatement,
            ["revocationStatement"] = input.RevocationStatement
        };
        if (variant != "sql.renewStatement.omitted" && input.RenewalStatement is not null)
            result["renewStatement"] = input.RenewalStatement;
        if (variant != "sql.ca.omitted" && input.Ca is not null) result["ca"] = input.Ca;
        if (variant != "sql.sslEnabled.omitted" && input.SslEnabled is not null)
            result["sslEnabled"] = variant == "sql.sslEnabled.false" ? false :
                variant == "sql.sslEnabled.true" ? true : input.SslEnabled;
        if (variant is "full" or "gatewayId.value") result["gatewayId"] = input.GatewayId;
        if (variant is "full" or "gatewayPoolId.value") result["gatewayPoolId"] = input.GatewayPoolId;
        if (variant == "gatewayId.null") result["gatewayId"] = null;
        if (variant == "gatewayPoolId.null") result["gatewayPoolId"] = null;
        if (variant == "passwordRequirements.value")
        {
            var policy = input.PasswordRequirements!;
            result["passwordRequirements"] = new JsonObject
            {
                ["length"] = policy.Length,
                ["allowedSymbols"] = policy.AllowedSymbols,
                ["required"] = new JsonObject
                {
                    ["lowercase"] = policy.Lowercase,
                    ["uppercase"] = policy.Uppercase,
                    ["digits"] = policy.Digits,
                    ["symbols"] = policy.Symbols
                }
            };
        }
        return result;
    }
}
