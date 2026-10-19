using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// A private independent persistence/job observer, never a provider transport.
// Every reply must identify the pinned deployment, clock, root and owned trial.
internal sealed class SqlRotationPatchSource(InfisicalLifecycleObservers channel, NativeEnvironment environment)
    : ISqlRotationPatchSource
{
    internal static SqlRotationPatchTrial? FromInput(JsonElement input, InfisicalLifecycleObservers channel,
        NativeEnvironment environment, NativeCaseDefinition definition, string organization, string project,
        IDatabaseOwnedFixture fixture)
    {
        if (!input.TryGetProperty("sqlRotationPatch", out var settings)) return null;
        string Required(string name)
        {
            string value = settings.GetProperty(name).GetString()!;
            SqlRotationPatchTrial.Require(!string.IsNullOrWhiteSpace(value) && value.Length <= 1024 &&
                !value.Any(char.IsControl), "missing-input");
            return value;
        }
        long epoch = settings.GetProperty("epoch").GetInt64();
        SqlRotationPatchTrial.Require(epoch > 0, "missing-input");
        var binding = new SqlRotationPatchBinding(definition, Guid.NewGuid().ToString("N"), organization,
            project, fixture.Name, fixture.SourcePath, fixture.BackendCoordinate,
            Required("version"), Required("deployment"), Required("sourceId"), Required("clockId"), epoch);
        return new(binding, new SqlRotationPatchSource(channel, environment));
    }

    private async ValueTask<JsonElement> CallAsync(string action, SqlRotationPatchBinding binding,
        string? rotation, DispatchEvidence? receipt, CancellationToken token)
    {
        var selected = await environment.Tokens(NativeIdentityRole.Observer).GetTokenAsync(token);
        SqlRotationPatchTrial.Require(selected.IsSuccess, "missing-input");
        using var credential = selected.Value;
        return await channel.PostAsync<JsonElement>("database/patch/" + action, writer =>
        {
            WriteBinding(writer, binding);
            writer.WriteString("rotationId", rotation);
            if (receipt is not null) writer.WriteNumber("receipt", (int)receipt.Value);
            writer.WriteString("observerToken", credential.Material.Reveal());
        }, token);
    }

    internal static void WriteBinding(Utf8JsonWriter writer, SqlRotationPatchBinding b)
    {
        writer.WriteString("trialNonce", b.Nonce);
        writer.WriteString("provider", b.Case.Key.Provider);
        writer.WriteString("operation", b.Case.Key.Operation);
        writer.WriteString("variant", b.Case.Key.Variant);
        writer.WriteString("scope", b.Case.Key.Scope);
        writer.WriteString("case", b.Case.Key.Case);
        writer.WriteString("member", b.Case.Member);
        writer.WriteString("organizationId", b.OrganizationId);
        writer.WriteString("projectId", b.ProjectId);
        writer.WriteString("ownedName", b.OwnedName);
        writer.WriteString("sourcePath", b.SourcePath);
        writer.WriteNumber("profile", (int)b.Coordinate.Profile);
        writer.WriteString("connectionId", b.Coordinate.ConnectionId);
        writer.WriteString("host", b.Coordinate.Host);
        writer.WriteNumber("port", b.Coordinate.Port);
        writer.WriteString("database", b.Coordinate.Database);
        writer.WriteString("version", b.Version);
        writer.WriteString("deployment", b.Deployment);
        writer.WriteString("sourceId", b.SourceId);
        writer.WriteString("clockId", b.ClockId);
        writer.WriteNumber("epoch", b.Epoch);
    }

    private static void Identity(JsonElement facts, SqlRotationPatchBinding b)
    {
        string S(string name) => facts.GetProperty(name).GetString()!;
        SqlRotationPatchTrial.Require(S("trialNonce") == b.Nonce && S("provider") == b.Case.Key.Provider &&
            S("operation") == b.Case.Key.Operation && S("variant") == b.Case.Key.Variant &&
            S("scope") == b.Case.Key.Scope && S("case") == b.Case.Key.Case && S("member") == b.Case.Member &&
            S("organizationId") == b.OrganizationId && S("projectId") == b.ProjectId &&
            S("ownedName") == b.OwnedName && S("sourcePath") == b.SourcePath &&
            facts.GetProperty("profile").GetInt32() == (int)b.Coordinate.Profile &&
            S("connectionId") == b.Coordinate.ConnectionId && S("host") == b.Coordinate.Host &&
            facts.GetProperty("port").GetInt32() == b.Coordinate.Port && S("database") == b.Coordinate.Database &&
            S("version") == b.Version && S("deployment") == b.Deployment && S("sourceId") == b.SourceId &&
            S("clockId") == b.ClockId && facts.GetProperty("epoch").GetInt64() == b.Epoch);
    }

    private static SqlRotationPatchMeasurement Measure(JsonElement facts, SqlRotationPatchBinding binding, string rotation)
    {
        Identity(facts, binding);
        SqlRotationPatchTrial.Require(facts.GetProperty("rotationId").GetString() == rotation);
        JsonElement c = facts.GetProperty("configuration");
        string S(string name) => c.GetProperty(name).GetString()!;
        double N(string name) => c.GetProperty(name).GetDouble();
        DatabasePasswordRequirements? requirements = null;
        JsonElement r = c.GetProperty("passwordRequirements");
        if (r.ValueKind != JsonValueKind.Null)
            requirements = new(r.GetProperty("length").GetDouble(), r.GetProperty("digits").GetDouble(),
                r.GetProperty("lowercase").GetDouble(), r.GetProperty("symbols").GetDouble(),
                r.GetProperty("uppercase").GetDouble(), r.GetProperty("allowedSymbols").GetString());
        var configuration = new DatabaseConfiguration(S("name"), S("connectionId"), S("environment"), S("path"),
            S("username1"), S("username2"), S("usernameKey"), S("passwordKey"), N("interval"), N("hours"),
            N("minutes"), c.GetProperty("enabled").GetBoolean(), c.GetProperty("hasDescription").GetBoolean(),
            c.GetProperty("description").GetString(), requirements);
        string? protectedStatement = facts.GetProperty("rotationStatement").GetString();
        return new(binding, rotation, configuration,
            protectedStatement is null ? null : SecretMaterial.FromText(protectedStatement),
            facts.GetProperty("attempts").GetInt32(), facts.GetProperty("pending").GetInt32(),
            facts.GetProperty("locks").GetInt32(), facts.GetProperty("scheduled").GetInt32(),
            facts.GetProperty("sourceRegistrations").GetInt32(), facts.GetProperty("ownedRotations").GetInt32(),
            facts.GetProperty("borrowedStatePreserved").GetBoolean(), facts.GetProperty("epoch").GetInt64(),
            facts.GetProperty("observedAt").GetDateTimeOffset(), facts.GetProperty("terminalAttempts").GetInt32());
    }

    public async ValueTask OpenAsync(SqlRotationPatchBinding binding, CancellationToken token)
    {
        var facts = await CallAsync("arm", binding, null, null, token);
        Identity(facts, binding);
        SqlRotationPatchTrial.Require(facts.GetProperty("sourceRegistrations").GetInt32() == 1 &&
            facts.GetProperty("pending").GetInt32() == 0 && facts.GetProperty("borrowedStatePreserved").GetBoolean());
    }
    public async ValueTask<SqlRotationPatchMeasurement> ReadAsync(SqlRotationPatchBinding binding, string rotationId,
        CancellationToken token) => Measure(await CallAsync("read", binding, rotationId, null, token), binding, rotationId);

    public async ValueTask<SqlRotationPatchControls> ControlsAsync(SqlRotationPatchBinding binding, string rotationId,
        CancellationToken token)
    {
        var facts = await CallAsync("controls", binding, rotationId, null, token);
        Identity(facts, binding);
        List<SqlRotationPatchControl> rows = [];
        try
        {
            foreach (var row in facts.GetProperty("rows").EnumerateArray())
            {
                SqlRotationPatchTrial.Require(rows.Count < SqlRotationPatchTrial.RejectionControls.Length);
                rows.Add(new(row.GetProperty("name").GetString()!, row.GetProperty("status").GetInt32(),
                    Measure(row.GetProperty("state"), binding, rotationId)));
            }
            return new(rows.ToArray());
        }
        catch { foreach (var row in rows) row.State.Dispose(); throw; }
    }
    public async ValueTask<SqlRotationPatchMeasurement> CompleteAsync(SqlRotationPatchBinding binding,
        string rotationId, DispatchEvidence receipt, CancellationToken token) =>
        Measure(await CallAsync("complete", binding, rotationId, receipt, token), binding, rotationId);

    public async ValueTask RecoverAsync(SqlRotationPatchBinding binding, CancellationToken token)
    {
        var facts = await CallAsync("recover", binding, null, null, token);
        Identity(facts, binding);
        SqlRotationPatchTrial.Require(facts.GetProperty("pending").GetInt32() == 0 &&
            facts.GetProperty("locks").GetInt32() == 0 && facts.GetProperty("borrowedStatePreserved").GetBoolean(),
            "cleanup-incomplete");
        SqlRotationPatchTrial.Require(facts.GetProperty("attempts").GetInt32() ==
            facts.GetProperty("terminalAttempts").GetInt32(), "cleanup-incomplete");
    }
    public async ValueTask<SqlRotationPatchCleanup> CloseAsync(SqlRotationPatchBinding binding, CancellationToken token)
    {
        // Release only the locally selected trial subscription. No returned root,
        // rotation ID or forced cleanup coordinate is used.
        try
        {
            var facts = await CallAsync("release", binding, null, null, token);
            Identity(facts, binding);
        }
        catch (NativeCaseFailureException error) when (error.Message == "observer-unavailable")
        {
            // A lost acknowledgement is not replayed. The exact original root
            // is independently read below; nonzero/missing state still fails.
        }
        var measured = await CallAsync("remaining", binding, null, null, token);
        Identity(measured, binding);
        return new(binding, measured.GetProperty("pending").GetInt32(), measured.GetProperty("locks").GetInt32(),
            measured.GetProperty("sourceRegistrations").GetInt32(), measured.GetProperty("ownedResources").GetInt32(),
            measured.GetProperty("borrowedStatePreserved").GetBoolean());
    }
    public override string ToString() => "[SqlRotationPatchSource]";
}
