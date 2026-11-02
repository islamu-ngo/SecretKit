using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalSqlRotationPatchSource(InfisicalSqlRotationPatchFixture.Lease lease)
    : ISqlRotationPatchSource
{
    private SqlRotationPatchBinding? original;
    internal int Registrations { get; private set; }
    internal int CompletedCallbacks { get; private set; }
    internal DispatchEvidence? CallerReceipt { get; private set; }
    internal List<SqlRotationPatchBinding> RecoveryRoots { get; } = [];
    private InfisicalSqlRotationPatchFixture Store => lease.Owner;

    public ValueTask OpenAsync(SqlRotationPatchBinding binding, CancellationToken token)
    {
        original = binding;
        Registrations = 1;
        if (Store.Mode == "arm-loss") throw new NativeCaseFailureException("observer-unavailable");
        return ValueTask.CompletedTask;
    }
    private void Bound(SqlRotationPatchBinding binding) =>
        SqlRotationPatchTrial.Require(original is null || binding == original, "cleanup-incomplete");

    public ValueTask<SqlRotationPatchMeasurement> ReadAsync(SqlRotationPatchBinding binding,
        string rotationId, CancellationToken token)
    {
        Bound(binding);
        JsonObject row = Store.Configurations[rotationId];
        JsonNode p = row["parameters"]!, m = row["secretsMapping"]!, t = row["rotateAtUtc"]!;
        string S(JsonNode n, string key) => n[key]!.GetValue<string>();
        double N(JsonNode n, string key) => n[key]!.GetValue<double>();
        DatabasePasswordRequirements? requirements = p["passwordRequirements"] is not JsonObject r ? null :
            new(N(r, "length"), N(r["required"]!, "digits"), N(r["required"]!, "lowercase"),
                N(r["required"]!, "symbols"), N(r["required"]!, "uppercase"),
                r["allowedSymbols"]?.GetValue<string>());
        var configuration = new DatabaseConfiguration(S(row, "name"), S(row, "connectionId"),
            S(row["environment"]!, "slug"), S(row["folder"]!, "path"), S(p, "username1"),
            S(p, "username2"), S(m, "username"), S(m, "password"), N(row, "rotationInterval"),
            N(t, "hours"), N(t, "minutes"), row["isAutoRotationEnabled"]!.GetValue<bool>(),
            row.ContainsKey("description"), row["description"]?.GetValue<string>(), requirements);
        if (Store.Mode == "echo-only" && Store.Attempts[rotationId] == 1)
            configuration = new SqlRotationPatchPlan(lease, binding.Case.Key.Variant).Expected;
        SqlRotationPatchBinding returned = Store.Mode switch
        {
            "nonce" => binding with { Nonce = "foreign" },
            "version" => binding with { Version = "other" },
            "deployment" => binding with { Deployment = "other" },
            "clock" => binding with { ClockId = "other" },
            "source" => binding with { SourceId = "other" },
            "case" => binding with { Case = binding.Case with { Key = binding.Case.Key with { Case = "other" } } },
            "root" => binding with { ProjectId = "other" },
            _ => binding
        };
        return ValueTask.FromResult(new SqlRotationPatchMeasurement(returned, rotationId, configuration,
            Store.Statements.TryGetValue(rotationId, out string? statement) ? SecretMaterial.FromText(statement) : null,
            Store.Attempts[rotationId], Store.Pending[rotationId], Store.Pending[rotationId],
            Store.Attempts[rotationId], Registrations, Store.Configurations.Count,
            Store.BorrowedIntact, Store.Mode == "epoch" ? binding.Epoch + 1 : binding.Epoch,
            DateTimeOffset.Parse(InfisicalSqlRotationPatchFixture.Date),
            Store.Completion[rotationId].Task.IsCompletedSuccessfully ? Store.Attempts[rotationId] : 0));
    }

    internal static JsonObject InvalidPatch(string control, string username1, string username2)
    {
        var parameters = new JsonObject { ["username1"] = username1, ["username2"] = username2 };
        return control switch
        {
            "parameters.empty" => new() { ["parameters"] = new JsonObject() },
            "parameters.missing-username1" => new() { ["parameters"] = new JsonObject { ["username2"] = username2 } },
            "parameters.missing-username2" => new() { ["parameters"] = new JsonObject { ["username1"] = username1 } },
            "statement.null" => Parameters("rotationStatement", null),
            "passwordRequirements.null" => Parameters("passwordRequirements", null),
            "passwordRequirements.empty" => Parameters("passwordRequirements", new JsonObject()),
            "mapping.empty" => new() { ["secretsMapping"] = new JsonObject() },
            "mapping.missing-username" => new() { ["secretsMapping"] = new JsonObject { ["password"] = "PASSWORD" } },
            "mapping.missing-password" => new() { ["secretsMapping"] = new JsonObject { ["username"] = "USER" } },
            "time.empty" => new() { ["rotateAtUtc"] = new JsonObject() },
            "time.missing-hours" => new() { ["rotateAtUtc"] = new JsonObject { ["minutes"] = 3 } },
            "time.missing-minutes" => new() { ["rotateAtUtc"] = new JsonObject { ["hours"] = 2 } },
            _ => throw new InvalidOperationException("unknown-control")
        };
        JsonObject Parameters(string field, JsonNode? value)
        {
            parameters[field] = value;
            return new() { ["parameters"] = parameters };
        }
    }

    public async ValueTask<SqlRotationPatchControls> ControlsAsync(SqlRotationPatchBinding binding,
        string rotationId, CancellationToken token)
    {
        Bound(binding);
        using var http = new HttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "administrative");
        string type = Store.Configurations[rotationId]["type"]!.GetValue<string>();
        List<SqlRotationPatchControl> rows = [];
        try
        {
            foreach (string control in SqlRotationPatchTrial.RejectionControls)
            {
                using var content = new StringContent(InvalidPatch(control, lease.Username1, lease.Username2).ToJsonString(),
                    Encoding.UTF8, "application/json");
                using var response = await http.PatchAsync(new Uri(Store.Origin, $"api/v2/secret-rotations/{type}/{rotationId}"), content, token);
                rows.Add(new(control, (int)response.StatusCode, await ReadAsync(binding, rotationId, token)));
            }
            return new(rows.ToArray());
        }
        catch { foreach (var row in rows) row.State.Dispose(); throw; }
    }

    public async ValueTask<SqlRotationPatchMeasurement> CompleteAsync(SqlRotationPatchBinding binding,
        string rotationId, DispatchEvidence receipt, CancellationToken token)
    {
        Bound(binding);
        CompletedCallbacks++;
        CallerReceipt = receipt;
        if (Store.Attempts[rotationId] != 0 && Store.Mode != "unsettled")
            await Store.Completion[rotationId].Task.WaitAsync(token);
        return await ReadAsync(binding, rotationId, token);
    }
    public ValueTask RecoverAsync(SqlRotationPatchBinding binding, CancellationToken token)
    {
        Bound(binding);
        RecoveryRoots.Add(binding);
        SqlRotationPatchTrial.Require(Store.Pending.Values.Sum() == 0 && Store.BorrowedIntact, "cleanup-incomplete");
        return ValueTask.CompletedTask;
    }
    public ValueTask<SqlRotationPatchCleanup> CloseAsync(SqlRotationPatchBinding binding, CancellationToken token)
    {
        Bound(binding);
        RecoveryRoots.Add(binding);
        Registrations = 0;
        return ValueTask.FromResult(new SqlRotationPatchCleanup(binding, Store.Pending.Values.Sum(), 0,
            Registrations, Store.Residual, Store.BorrowedIntact));
    }
    public override string ToString() => "[IndependentSqlRotationPatchJournals]";
}
