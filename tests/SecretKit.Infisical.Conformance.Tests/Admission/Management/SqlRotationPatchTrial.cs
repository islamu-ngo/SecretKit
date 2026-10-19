using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Optional stronger evidence. Old fixtures retain their existing GET/material/backend
// witnesses; opting in requires an independent source and original-attempt completion.
internal sealed class SqlRotationPatchTrial(SqlRotationPatchBinding binding, ISqlRotationPatchSource source)
{
    internal SqlRotationPatchBinding Binding => binding;
    internal static readonly string[] RejectionControls =
    [
        "parameters.empty", "parameters.missing-username1", "parameters.missing-username2",
        "statement.null", "passwordRequirements.null", "passwordRequirements.empty",
        "mapping.empty", "mapping.missing-username", "mapping.missing-password",
        "time.empty", "time.missing-hours", "time.missing-minutes"
    ];

    internal async ValueTask ExecuteAsync<T>(ProjectFamilyContext c, IDatabaseOwnedFixture fixture,
        Func<ManagementRequest<T>> create, Func<string, ManagementRequest<T>> get,
        Func<string, ManagementRequest<T>> update, Func<T, string> id,
        Func<T, DatabaseConfiguration> configuration, Func<T, SecretMaterial?> statement,
        Func<string, CancellationToken, ValueTask> credentials, CancellationToken token) where T : notnull
    {
        c.Probe.Contract(binding.Case == c.Definition && binding.ProjectId == c.ProjectId &&
            binding.OrganizationId == c.OrganizationId && binding.OwnedName == fixture.Name &&
            binding.SourcePath == fixture.SourcePath && binding.Coordinate == fixture.BackendCoordinate,
            NativeFailure.ContractMismatch);
        await source.OpenAsync(binding, token);
        // The source subscription/ownership registration precedes the bootstrap write.
        T seeded = await c.NeedAsync(create, NativeIdentityRole.Setup, token);
        string rotation;
        try { rotation = id(seeded); }
        finally { if (seeded is IDisposable owned) owned.Dispose(); }
        var plan = new SqlRotationPatchPlan(fixture, c.Variant);
        using (var before = await source.ReadAsync(binding, rotation, token))
        {
            Validate(before, rotation);
            c.Probe.Contract(before.Configuration == plan.Seed &&
                InfisicalDatabaseFamilies.SameMaterial(before.Statement, fixture.RotationStatement) &&
                before.Attempts == 0 && before.Pending == 0 && before.Locks == 0,
                NativeFailure.EffectMismatch);
        }
        T independent = await c.NeedAsync(() => get(rotation), NativeIdentityRole.Observer, token);
        try
        {
            c.Probe.Contract(configuration(independent) == plan.Seed &&
                InfisicalDatabaseFamilies.SameMaterial(statement(independent), fixture.RotationStatement),
                NativeFailure.EffectMismatch);
        }
        finally { if (independent is IDisposable owned) owned.Dispose(); }

        // Source-operated negative controls have their own attempt journal. They
        // must all reject, settle, and leave the same committed configuration.
        using (var controls = await source.ControlsAsync(binding, rotation, token))
        {
            c.Probe.Contract(controls.Rows.Length == RejectionControls.Length &&
                controls.Rows.Select(r => r.Name).Order(StringComparer.Ordinal)
                    .SequenceEqual(RejectionControls.Order(StringComparer.Ordinal)), NativeFailure.EffectMismatch);
            foreach (var row in controls.Rows)
            {
                Validate(row.State, rotation);
                c.Probe.Contract(row.Status == 400 && row.State.Configuration == plan.Seed &&
                    InfisicalDatabaseFamilies.SameMaterial(row.State.Statement, fixture.RotationStatement) &&
                    row.State.Attempts == 0 && row.State.Pending == 0 && row.State.Locks == 0,
                    NativeFailure.EffectMismatch);
            }
        }

        bool applied = c.Definition.Key.Case is "selected-contract" or "independent-effect" or "lost-response-no-replay";
        DatabaseConfiguration expected = applied ? plan.Expected : plan.Seed;
        SecretMaterial? expectedStatement = applied && plan.Parameters && !plan.Statement ? null : fixture.RotationStatement;
        await c.CaseAsync(() => update(rotation),
            s => id(s) == rotation && configuration(s) == expected &&
                InfisicalDatabaseFamilies.SameMaterial(statement(s), expectedStatement),
            async (_, ct) =>
            {
                using var committed = await source.ReadAsync(binding, rotation, ct);
                Validate(committed, rotation);
                if (committed.Configuration != expected ||
                    !InfisicalDatabaseFamilies.SameMaterial(committed.Statement, expectedStatement) ||
                    committed.Attempts != (applied ? 1 : 0) || committed.Pending != 0 || committed.Locks != 0 ||
                    committed.Scheduled != (applied ? 1 : 0) || committed.TerminalAttempts != committed.Attempts) return false;
                T observed = await c.NeedAsync(() => get(rotation), NativeIdentityRole.Observer, ct);
                try
                {
                    if (configuration(observed) != expected ||
                        !InfisicalDatabaseFamilies.SameMaterial(statement(observed), expectedStatement)) return false;
                }
                finally { if (observed is IDisposable owned) owned.Dispose(); }
                // This checks existing credential authentication/mappings, not a
                // claim that the new policy/statement was used in a later rotation.
                await credentials(rotation, ct);
                return true;
            }, token, async (receipt, ct) =>
            {
                using var settled = await source.CompleteAsync(binding, rotation, receipt, ct);
                Validate(settled, rotation);
                c.Probe.Contract(settled.TerminalAttempts == settled.Attempts && settled.Attempts == (applied ? 1 : 0) &&
                    settled.Pending == 0 && settled.Locks == 0, NativeFailure.EffectMismatch);
            });
    }

    private void Validate(SqlRotationPatchMeasurement state, string rotation) =>
        Require(state.Binding == binding && state.RotationId == rotation && state.ObservedAt != default &&
            state.Epoch == binding.Epoch && state.BorrowedStatePreserved && state.SourceRegistrations == 1 &&
            state.OwnedRotations == 1 && state.Configuration.ConnectionId == binding.Coordinate.ConnectionId &&
            state.Configuration.Path == binding.SourcePath);

    internal ValueTask RecoverAsync(CancellationToken token) => source.RecoverAsync(binding, token);
    internal async ValueTask CloseAsync(CancellationToken token)
    {
        var remaining = await source.CloseAsync(binding, token);
        Require(remaining.Binding == binding && remaining.Pending == 0 && remaining.Locks == 0 &&
            remaining.SourceRegistrations == 0 && remaining.OwnedResources == 0 &&
            remaining.BorrowedStatePreserved, "cleanup-incomplete");
    }

    internal static void Require(bool condition, string reason = "effect-mismatch")
    {
        if (!condition) throw new NativeCaseFailureException(reason);
    }
    public override string ToString() => "[SqlRotationPatchTrial]";
}

internal sealed class SqlRotationPatchPlan
{
    internal DatabaseConfiguration Seed { get; }
    internal DatabaseConfiguration Expected { get; }
    internal bool Parameters { get; }
    internal bool Requirements { get; }
    internal bool Statement { get; }
    internal DatabasePasswordRequirements? PasswordRequirements => Expected.PasswordRequirements;
    internal SqlRotationPatchPlan(IDatabaseOwnedFixture f, string v)
    {
        Seed = new(f.Name, f.ConnectionId, f.Environment, f.SourcePath, f.Username1, f.Username2,
            f.UsernameKey, f.PasswordKey, 2, 2, 3, false, true, f.Name,
            new(24, 2, 2, 2, 2, "!@"));
        Parameters = v.Contains("RotationParameters.", StringComparison.Ordinal) ||
            v.Contains("RotationPasswordRequirements.", StringComparison.Ordinal) ||
            v == "passwordRequirements.fractional-number" || v.EndsWith("parameters.value", StringComparison.Ordinal) ||
            v is "parameters.supplied-persistence-unestablished" or "patch.persistence-unestablished";
        Requirements = !v.EndsWith("passwordRequirements.omitted", StringComparison.Ordinal) &&
            !v.EndsWith("rotationStatement.value", StringComparison.Ordinal);
        Statement = !v.EndsWith("rotationStatement.omitted", StringComparison.Ordinal) &&
            !v.EndsWith("passwordRequirements.value", StringComparison.Ordinal) &&
            v != "parameters.supplied-persistence-unestablished" && v != "patch.persistence-unestablished";
        Expected = Seed with
        {
            Name = v.EndsWith("name.value", StringComparison.Ordinal) ? f.Name + "-updated" : f.Name,
            Description = v == "description.null" ? null :
                v.EndsWith("description.value", StringComparison.Ordinal) ? f.Name + "-updated" : f.Name,
            Enabled = v.EndsWith("isAutoRotationEnabled.true", StringComparison.Ordinal),
            Interval = v == "rotationInterval.fractional-number" ? 2.5 : v.EndsWith("rotationInterval.value", StringComparison.Ordinal) ? 3 : 2,
            UsernameKey = v.EndsWith("secretsMapping.value", StringComparison.Ordinal) ||
                v == "secretsMapping.supplied-persistence-unestablished" ? f.UpdatedUsernameKey : f.UsernameKey,
            Hours = v == "rotateAtUtc.fractional-number" ? 2.5 : v.EndsWith("rotateAtUtc.value", StringComparison.Ordinal) ? 4 : 2,
            PasswordRequirements = !Parameters ? Seed.PasswordRequirements : !Requirements ? null :
                new(v == "passwordRequirements.fractional-number" ? 24.5 : 24, 2, 2, 2, 2,
                    v.EndsWith("allowedSymbols.value", StringComparison.Ordinal) ? "!@" : null)
        };
    }
}

internal interface ISqlRotationPatchSource
{
    ValueTask OpenAsync(SqlRotationPatchBinding binding, CancellationToken token);
    ValueTask<SqlRotationPatchMeasurement> ReadAsync(SqlRotationPatchBinding binding, string rotationId, CancellationToken token);
    ValueTask<SqlRotationPatchControls> ControlsAsync(SqlRotationPatchBinding binding, string rotationId, CancellationToken token);
    ValueTask<SqlRotationPatchMeasurement> CompleteAsync(SqlRotationPatchBinding binding, string rotationId,
        DispatchEvidence receipt, CancellationToken token);
    // Recovery must settle original work, never replay the mutation or force deletion.
    ValueTask RecoverAsync(SqlRotationPatchBinding binding, CancellationToken token);
    ValueTask<SqlRotationPatchCleanup> CloseAsync(SqlRotationPatchBinding binding, CancellationToken token);
}

internal sealed record SqlRotationPatchBinding(
    [property: JsonIgnore] NativeCaseDefinition Case, [property: JsonIgnore] string Nonce,
    [property: JsonIgnore] string OrganizationId, [property: JsonIgnore] string ProjectId,
    [property: JsonIgnore] string OwnedName, [property: JsonIgnore] string SourcePath,
    [property: JsonIgnore] DatabaseBackendCoordinate Coordinate, [property: JsonIgnore] string Version,
    [property: JsonIgnore] string Deployment, [property: JsonIgnore] string SourceId,
    [property: JsonIgnore] string ClockId, [property: JsonIgnore] long Epoch)
{
    public override string ToString() => "[SqlRotationPatchBinding]";
}
internal sealed record SqlRotationPatchMeasurement(
    [property: JsonIgnore] SqlRotationPatchBinding Binding, [property: JsonIgnore] string RotationId,
    [property: JsonIgnore] DatabaseConfiguration Configuration, [property: JsonIgnore] SecretMaterial? Statement,
    [property: JsonIgnore] int Attempts, [property: JsonIgnore] int Pending, [property: JsonIgnore] int Locks,
    [property: JsonIgnore] int Scheduled, [property: JsonIgnore] int SourceRegistrations,
    [property: JsonIgnore] int OwnedRotations, [property: JsonIgnore] bool BorrowedStatePreserved,
    [property: JsonIgnore] long Epoch, [property: JsonIgnore] DateTimeOffset ObservedAt,
    [property: JsonIgnore] int TerminalAttempts) : IDisposable
{
    public void Dispose() => Statement?.Dispose();
    public override string ToString() => "[SqlRotationPatchMeasurement]";
}
internal sealed record SqlRotationPatchControl(
    [property: JsonIgnore] string Name, [property: JsonIgnore] int Status,
    [property: JsonIgnore] SqlRotationPatchMeasurement State)
{
    public override string ToString() => "[SqlRotationPatchControl]";
}
internal sealed record SqlRotationPatchControls([property: JsonIgnore] SqlRotationPatchControl[] Rows) : IDisposable
{
    public void Dispose() { foreach (var row in Rows) row.State.Dispose(); }
    public override string ToString() => "[SqlRotationPatchControls]";
}
internal sealed record SqlRotationPatchCleanup(
    [property: JsonIgnore] SqlRotationPatchBinding Binding, [property: JsonIgnore] int Pending,
    [property: JsonIgnore] int Locks, [property: JsonIgnore] int SourceRegistrations,
    [property: JsonIgnore] int OwnedResources, [property: JsonIgnore] bool BorrowedStatePreserved)
{
    public override string ToString() => "[SqlRotationPatchCleanup]";
}
