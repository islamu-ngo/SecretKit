using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class PostgresSecretRotationsEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, IDatabaseOwnedFixture f, CancellationToken token)
    {
        if (c.Operation == "Update" && f.SqlRotationPatch is { } trial)
        {
            await PatchAsync(c, f, trial, token);
            return;
        }
        string v = c.Variant, org = c.OrganizationId, project = c.ProjectId;
        bool applied = c.Definition.Key.Case is "selected-contract" or "independent-effect" or "lost-response-no-replay";
        using var parameters = Parameters(f, v);
        var creation = Creation(c, f, parameters);
        var backend = f.Backend!;
        InfisicalDatabaseFamilies.Authentication(c.Probe, await backend.MeasureAuthorityAsync(token), f, DatabaseAuthentication.Accepted);
        if (c.Operation == "Create")
        {
            await c.CaseAsync(() => PostgresSecretRotationOperations.Create(org, creation),
                s => MatchCreation(s, creation, f.CreationDefaults), async (changed, ct) =>
                {
                    var found = await c.ExecuteAsync(() => PostgresSecretRotationOperations.GetByName(org, project,
                        f.Environment, f.SourcePath, f.Name), NativeIdentityRole.Observer, ct);
                    if (!changed)
                    {
                        if (found.IsSuccess) found.Value.Dispose();
                        return found.Status == SecretStatus.Absent;
                    }
                    if (!found.IsSuccess) c.Probe.Effect(NativeObservation.Unavailable);
                    using var owned = found.Value;
                    if (!MatchCreation(owned, creation, f.CreationDefaults)) return false;
                    await CredentialsAsync(c, f, Address(project, owned), true, false, ct);
                    return true;
                }, token);
            return;
        }
        using var seeded = await c.NeedAsync(() => PostgresSecretRotationOperations.Create(org, creation), NativeIdentityRole.Setup, token);
        InfisicalRotationAddress address = Address(project, seeded);
        using var before = await c.NeedAsync(() => PostgresSecretRotationOperations.Get(org, address), NativeIdentityRole.Observer, token);
        c.Probe.Contract(MatchCreation(before, creation, f.CreationDefaults), NativeFailure.MissingPrerequisite);
        if (c.Operation == "GetGeneratedCredentials")
        {
            using var independentlyRead = await c.NeedAsync(() => PostgresSecretRotationOperations.GetGeneratedCredentials(org, address),
                NativeIdentityRole.Observer, token);
            await c.CaseAsync(() => PostgresSecretRotationOperations.GetGeneratedCredentials(org, address),
                g => SameCredentials(g, independentlyRead), async (_, ct) =>
                {
                    await CredentialsAsync(c, f, address, true, false, ct);
                    return true;
                }, token);
            return;
        }
        if (c.Operation == "List" || c.Operation == "ListPostgresSubset")
        {
            bool partial = c.Operation != "List";
            Func<ManagementRequest<PostgresSecretRotationList>> request = partial ?
                () => PostgresSecretRotationOperations.ListPostgresSubset(org, project) :
                () => PostgresSecretRotationOperations.List(org, project);
            using var independentlyRead = await c.NeedAsync(request, NativeIdentityRole.Observer, token);
            using var catalog = partial ? await f.ObserveCatalogAsync(false, token) : null;
            bool Match(PostgresSecretRotationList list) => list.IsComplete == !partial && list.Items.Count is > 0 and <= 4096 &&
                list.Items.Any(s => s.Id == before.Id && Same(s, before)) &&
                list.Items.Select(s => s.Id).Distinct().Count() == list.Items.Count &&
                list.Items.Count == independentlyRead.Items.Count && list.Items.All(s =>
                    independentlyRead.Items.Any(other => Same(s, other))) &&
                (!partial || list.Items.Select(s => s.Id).Order(StringComparer.Ordinal).SequenceEqual(
                    catalog!.Rows.Where(r => r.Type == "postgres-credentials").Select(r => r.Id).Order(StringComparer.Ordinal)));
            await c.CaseAsync(request, Match, async (_, ct) =>
            {
                using var observed = await c.NeedAsync(request, NativeIdentityRole.Observer, ct);
                return Match(observed);
            }, token);
            return;
        }
        if (c.Operation == "PostgresOptionsSubset")
        {
            using var catalog = await f.ObserveCatalogAsync(true, token);
            DatabaseCatalogOption[] expected = catalog.Options.Where(o => o.Type == "postgres-credentials").ToArray();
            bool Match(PostgresSecretRotationOptions options) => !options.IsComplete && options.Items.Count == expected.Length &&
                options.Items.Count is > 0 and <= 4096 && options.Items.All(o => expected.Any(e =>
                    e.UsernameKey == o.SecretsMapping.Username && e.PasswordKey == o.SecretsMapping.Password &&
                    InfisicalDatabaseFamilies.SameMaterial(e.CreateStatement, o.CreateUserStatement) &&
                    InfisicalDatabaseFamilies.SameMaterial(e.RotationStatement, o.RotationStatement)));
            await c.CaseAsync(() => PostgresSecretRotationOperations.PostgresOptionsSubset(org), Match, async (_, ct) =>
            {
                using var observed = await c.NeedAsync(() => PostgresSecretRotationOperations.PostgresOptionsSubset(org),
                    NativeIdentityRole.Observer, ct);
                return Match(observed);
            }, token);
            return;
        }
        if (c.Operation == "CheckCredentials")
        {
            await InfisicalDatabaseFamilies.CredentialCheckCaseAsync(c, () => PostgresSecretRotationOperations.CheckCredentials(org, address),
                async (_, ct) =>
                {
                    using var observed = await c.NeedAsync(() => PostgresSecretRotationOperations.Get(org, address), NativeIdentityRole.Observer, ct);
                    InfisicalDatabaseFamilies.Authentication(c.Probe, await backend.MeasureAuthorityAsync(ct), f, DatabaseAuthentication.Accepted);
                    return Same(before, observed);
                }, token);
            return;
        }
        bool deleting = c.Operation == "Delete", moving = c.Operation == "Move", updating = c.Operation == "Update";
        bool? delete = deleting ? InfisicalDatabaseFamilies.Flag(v, "deleteSecrets") : false;
        bool? revoke = deleting ? InfisicalDatabaseFamilies.Flag(v, "revokeGeneratedCredentials") : false;
        if (deleting && (delete is null && f.DefaultDeleteSecrets is null || revoke is null && f.DefaultRevokeCredentials is null))
            c.Probe.Effect(NativeObservation.Unavailable);
        bool deleteExpected = delete ?? f.DefaultDeleteSecrets!.Value;
        bool revokeExpected = revoke ?? f.DefaultRevokeCredentials!.Value;
        using var credentials = await c.NeedAsync(() => PostgresSecretRotationOperations.GetGeneratedCredentials(org, address),
            NativeIdentityRole.Observer, token);
        c.Probe.Contract(credentials.ActiveIndex is 0 or 1 && credentials.ActiveIndex < credentials.Items.Count, NativeFailure.ObserverUnavailable);
        var active = credentials.Items[(int)credentials.ActiveIndex];
        await using var rejection = deleting && applied && revokeExpected ?
            await backend.SubscribeRejectionAsync(active.Username, active.Password, token) : null;
        // Retain the exact subscription task before the mutation; no replay or progress polling.
        Task<DatabaseAuthenticationMeasurement>? rejected = rejection?.Rejected;
        using var updatedParameters = new PostgresRotationParameters(f.UpdatedUsername1, f.UpdatedUsername2,
            parameters.PasswordRequirements, parameters.RotationStatement is null ? null : f.UpdatedRotationStatement);
        var update = Update(c, f, updatedParameters);
        var move = new PostgresSecretRotationMove(f.DestinationEnvironment, f.DestinationPath,
            moving ? InfisicalDatabaseFamilies.Flag(v, "overwriteDestination") : null);
        Func<ManagementRequest<PostgresSecretRotationSummary>> factory = c.Operation switch
        {
            "Get" => () => PostgresSecretRotationOperations.Get(org, address),
            "GetByName" => () => PostgresSecretRotationOperations.GetByName(org, project, f.Environment, f.SourcePath, f.Name),
            "Delete" => () => PostgresSecretRotationOperations.Delete(org, address, delete, revoke),
            "Move" => () => PostgresSecretRotationOperations.Move(org, address, move),
            "Update" => () => PostgresSecretRotationOperations.Update(org, address, update),
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        bool MatchSummary(PostgresSecretRotationSummary s) => s.Id == before.Id && s.ProjectId == project &&
            (deleting || !moving && !updating ? Same(before, s) : updating ?
                Configuration(s) == f.ExpectedPatchConfiguration &&
                    InfisicalDatabaseFamilies.SameMaterial(s.Parameters.RotationStatement, f.ExpectedPatchStatement) :
                Configuration(s) == Configuration(before) with { Environment = f.DestinationEnvironment, Path = f.DestinationPath });
        await c.CaseAsync(factory, MatchSummary, async (changed, ct) =>
        {
            if (deleting && changed)
            {
                var absent = await c.ExecuteAsync(() => PostgresSecretRotationOperations.GetByName(org, project,
                    f.Environment, f.SourcePath, f.Name), NativeIdentityRole.Observer, ct);
                if (absent.IsSuccess) absent.Value.Dispose();
                if (absent.Status != SecretStatus.Absent) return false;
                await InfisicalDatabaseFamilies.MappingAsync(c, f, f.Environment, f.SourcePath,
                    active.Username, active.Password, !deleteExpected, ct);
                DatabaseAuthenticationMeasurement measured = rejected is null ?
                    await backend.AuthenticateAsync(active.Username, active.Password, ct) : await rejected.WaitAsync(ct);
                InfisicalDatabaseFamilies.Authentication(c.Probe, measured, f,
                    revokeExpected ? DatabaseAuthentication.Rejected : DatabaseAuthentication.Accepted);
                return true;
            }
            InfisicalRotationAddress destination = changed && moving ?
                new(project, f.DestinationEnvironment, f.DestinationPath, InfisicalRotationProfile.PostgresCredentials, before.Id) : address;
            using var observed = await c.NeedAsync(() => PostgresSecretRotationOperations.Get(org, destination), NativeIdentityRole.Observer, ct);
            if (!(changed ? MatchSummary(observed) : Same(before, observed))) return false;
            if (changed && moving)
            {
                var old = await c.ExecuteAsync(() => PostgresSecretRotationOperations.GetByName(org, project,
                    f.Environment, f.SourcePath, f.Name), NativeIdentityRole.Observer, ct);
                if (old.IsSuccess) old.Value.Dispose();
                if (old.Status != SecretStatus.Absent) return false;
                await InfisicalDatabaseFamilies.MappingAsync(c, f, f.Environment, f.SourcePath, active.Username, active.Password, false, ct);
            }
            await CredentialsAsync(c, f, destination, true, false, ct);
            return true;
        }, token);
    }

    private static async ValueTask PatchAsync(ProjectFamilyContext c, IDatabaseOwnedFixture f,
        SqlRotationPatchTrial trial, CancellationToken token)
    {
        var plan = new SqlRotationPatchPlan(f, c.Variant);
        using var seed = new PostgresRotationParameters(f.Username1, f.Username2,
            new(24, 2, 2, 2, 2, "!@"), f.RotationStatement);
        var creation = new PostgresSecretRotationCreation(f.Name, c.ProjectId, f.Environment, f.SourcePath,
            f.ConnectionId, 2, seed, new(f.UsernameKey, f.PasswordKey), new(2, 3), new(f.Name), false);
        DatabasePasswordRequirements? r = plan.PasswordRequirements;
        using var parameters = new PostgresRotationParameters(f.Username1, f.Username2,
            !plan.Requirements || r is null ? null : new(r.Length, r.Digits, r.Lowercase, r.Symbols, r.Uppercase, r.AllowedSymbols),
            plan.Statement ? f.RotationStatement : null);
        string v = c.Variant;
        var update = new PostgresSecretRotationUpdate(
            name: v.EndsWith("name.value", StringComparison.Ordinal) ? plan.Expected.Name : null,
            description: v == "description.null" ? new(null) :
                v.EndsWith("description.value", StringComparison.Ordinal) ? new(plan.Expected.Description) : null,
            isAutoRotationEnabled: v.EndsWith("isAutoRotationEnabled.true", StringComparison.Ordinal) ? true :
                v.EndsWith("isAutoRotationEnabled.false", StringComparison.Ordinal) ? false : null,
            rotationInterval: v == "rotationInterval.fractional-number" || v.EndsWith("rotationInterval.value", StringComparison.Ordinal) ? plan.Expected.Interval : null,
            parameters: plan.Parameters ? parameters : null,
            secretsMapping: v.EndsWith("secretsMapping.value", StringComparison.Ordinal) ||
                v == "secretsMapping.supplied-persistence-unestablished" ? new(plan.Expected.UsernameKey, f.PasswordKey) : null,
            rotateAtUtc: v == "rotateAtUtc.fractional-number" || v.EndsWith("rotateAtUtc.value", StringComparison.Ordinal) ?
                new(plan.Expected.Hours, plan.Seed.Minutes) : null);
        InfisicalRotationAddress AddressFor(string id) => new(c.ProjectId, f.Environment, f.SourcePath,
            InfisicalRotationProfile.PostgresCredentials, id);
        await trial.ExecuteAsync(c, f, () => PostgresSecretRotationOperations.Create(c.OrganizationId, creation),
            id => PostgresSecretRotationOperations.Get(c.OrganizationId, AddressFor(id)),
            id => PostgresSecretRotationOperations.Update(c.OrganizationId, AddressFor(id), update),
            s => s.Id, Configuration, s => s.Parameters.RotationStatement,
            (id, ct) => CredentialsAsync(c, f, AddressFor(id), true, false, ct), token);
    }

    internal static PostgresRotationParameters Parameters(IDatabaseOwnedFixture f, string v)
    {
        bool password = !v.EndsWith("passwordRequirements.omitted", StringComparison.Ordinal);
        bool statement = !v.EndsWith("rotationStatement.omitted", StringComparison.Ordinal);
        double length = v == "passwordRequirements.fractional-number" ? 24.5 : 24;
        string? symbols = v.EndsWith("allowedSymbols.value", StringComparison.Ordinal) ? "!@" : null;
        var requirements = password ? new PostgresRotationPasswordRequirements(length, 2, 2, 2, 2, symbols) : null;
        return new(f.Username1, f.Username2, requirements, statement ? f.RotationStatement : null);
    }

    internal static PostgresSecretRotationCreation Creation(ProjectFamilyContext c, IDatabaseOwnedFixture f, PostgresRotationParameters p)
    {
        string v = c.Variant;
        bool? enabled = v.EndsWith("isAutoRotationEnabled.omitted", StringComparison.Ordinal) ? null :
            v.EndsWith("isAutoRotationEnabled.true", StringComparison.Ordinal);
        PostgresRotationTime? time = v.EndsWith("rotateAtUtc.omitted", StringComparison.Ordinal) ? null :
            v == "rotateAtUtc.fractional-number" ? new(2.5, 3.5) : new(2, 3);
        PostgresRotationNullableText? description = v.EndsWith("description.omitted", StringComparison.Ordinal) ? null :
            new(v == "description.null" ? null : f.Name);
        return new(f.Name, c.ProjectId, f.Environment, f.SourcePath, f.ConnectionId,
            v == "rotationInterval.fractional-number" ? 2.5 : 2, p, new(f.UsernameKey, f.PasswordKey), time, description, enabled);
    }

    internal static PostgresSecretRotationUpdate Update(ProjectFamilyContext c, IDatabaseOwnedFixture f, PostgresRotationParameters p)
    {
        string v = c.Variant;
        bool nested = v.StartsWith("PostgresRotation", StringComparison.Ordinal) || v == "passwordRequirements.fractional-number";
        return new(name: v.EndsWith("name.value", StringComparison.Ordinal) ? f.Name + "-updated" : null,
            description: v.EndsWith("description.value", StringComparison.Ordinal) ? new(f.Name + "-updated") :
                v == "description.null" ? new(null) : null,
            isAutoRotationEnabled: v.EndsWith("isAutoRotationEnabled.true", StringComparison.Ordinal) ? true :
                v.EndsWith("isAutoRotationEnabled.false", StringComparison.Ordinal) ? false : null,
            rotationInterval: v == "rotationInterval.fractional-number" ? 2.5 :
                v.EndsWith("rotationInterval.value", StringComparison.Ordinal) ? 3 : null,
            parameters: nested || v.EndsWith("parameters.value", StringComparison.Ordinal) ? p : null,
            secretsMapping: v.EndsWith("secretsMapping.value", StringComparison.Ordinal) ? new(f.UpdatedUsernameKey, f.UpdatedPasswordKey) : null,
            rotateAtUtc: v == "rotateAtUtc.fractional-number" ? new(2.5, 3.5) :
                v.EndsWith("rotateAtUtc.value", StringComparison.Ordinal) ? new(4, 5) : null);
    }

    private static bool MatchCreation(PostgresSecretRotationSummary s, PostgresSecretRotationCreation creation, DatabaseConfiguration defaults) =>
        s.Name == creation.Name && s.ProjectId == creation.ProjectId && s.ConnectionId == creation.ConnectionId &&
        s.Environment == creation.Environment && s.SecretPath == creation.SecretPath && s.RotationInterval == creation.RotationInterval &&
        s.Parameters.Username1 == creation.Parameters.Username1 && s.Parameters.Username2 == creation.Parameters.Username2 &&
        Requirements(s.Parameters.PasswordRequirements) == Requirements(creation.Parameters.PasswordRequirements) &&
        InfisicalDatabaseFamilies.SameMaterial(s.Parameters.RotationStatement, creation.Parameters.RotationStatement) &&
        s.SecretsMapping.Username == creation.SecretsMapping.Username && s.SecretsMapping.Password == creation.SecretsMapping.Password &&
        s.RotateAtUtc.Hours == (creation.RotateAtUtc?.Hours ?? defaults.Hours) &&
        s.RotateAtUtc.Minutes == (creation.RotateAtUtc?.Minutes ?? defaults.Minutes) &&
        s.IsAutoRotationEnabled == (creation.IsAutoRotationEnabled ?? defaults.Enabled) &&
        s.HasDescription == (creation.Description is not null || defaults.HasDescription) &&
        s.Description == (creation.Description is not null ? creation.Description.Value : defaults.Description);

    internal static DatabaseConfiguration Configuration(PostgresSecretRotationSummary s) => new(s.Name, s.ConnectionId,
        s.Environment, s.SecretPath, s.Parameters.Username1, s.Parameters.Username2, s.SecretsMapping.Username,
        s.SecretsMapping.Password, s.RotationInterval, s.RotateAtUtc.Hours, s.RotateAtUtc.Minutes,
        s.IsAutoRotationEnabled, s.HasDescription, s.Description, Requirements(s.Parameters.PasswordRequirements));

    private static DatabasePasswordRequirements? Requirements(PostgresRotationPasswordRequirements? r) => r is null ? null :
        new(r.Length, r.Digits, r.Lowercase, r.Symbols, r.Uppercase, r.AllowedSymbols);

    private static bool Same(PostgresSecretRotationSummary a, PostgresSecretRotationSummary b) => a.Id == b.Id && a.ProjectId == b.ProjectId &&
        a.EnvironmentId == b.EnvironmentId && a.FolderId == b.FolderId && Configuration(a) == Configuration(b) &&
        InfisicalDatabaseFamilies.SameMaterial(a.Parameters.RotationStatement, b.Parameters.RotationStatement) &&
        a.RotationStatus == b.RotationStatus && a.ActiveIndex == b.ActiveIndex && a.LastRotatedAt == b.LastRotatedAt &&
        a.LastRotationAttemptedAt == b.LastRotationAttemptedAt && a.HasLastRotationJobId == b.HasLastRotationJobId &&
        a.LastRotationJobId == b.LastRotationJobId && a.IsLastRotationManual == b.IsLastRotationManual &&
        a.HasNextRotationAt == b.HasNextRotationAt && a.NextRotationAt == b.NextRotationAt &&
        a.HasLastRotationMessage == b.HasLastRotationMessage && a.LastRotationMessage == b.LastRotationMessage;

    private static bool SameCredentials(PostgresGeneratedCredentials a, PostgresGeneratedCredentials b) =>
        a.RotationId == b.RotationId && a.ActiveIndex == b.ActiveIndex && a.Items.Count == b.Items.Count &&
        a.Items.Zip(b.Items).All(pair => InfisicalDatabaseFamilies.SameMaterial(pair.First.Username, pair.Second.Username) &&
            InfisicalDatabaseFamilies.SameMaterial(pair.First.Password, pair.Second.Password));

    private static InfisicalRotationAddress Address(string project, PostgresSecretRotationSummary s) =>
        new(project, s.Environment, s.SecretPath, InfisicalRotationProfile.PostgresCredentials, s.Id);

    private static async ValueTask CredentialsAsync(ProjectFamilyContext c, IDatabaseOwnedFixture f, InfisicalRotationAddress address,
        bool mappingsPresent, bool revoked, CancellationToken token)
    {
        using var observed = await c.NeedAsync(() => PostgresSecretRotationOperations.GetGeneratedCredentials(c.OrganizationId, address),
            NativeIdentityRole.Observer, token);
        c.Probe.Contract(observed.ActiveIndex is 0 or 1 && observed.ActiveIndex < observed.Items.Count, NativeFailure.ObserverUnavailable);
        var active = observed.Items[(int)observed.ActiveIndex];
        InfisicalDatabaseFamilies.Authentication(c.Probe, await f.Backend!.AuthenticateAsync(active.Username, active.Password, token), f,
            revoked ? DatabaseAuthentication.Rejected : DatabaseAuthentication.Accepted);
        using var state = await c.NeedAsync(() => PostgresSecretRotationOperations.Get(c.OrganizationId, address), NativeIdentityRole.Observer, token);
        await InfisicalDatabaseFamilies.MappingAsync(c, f, address.Environment!, address.Folder!, active.Username, active.Password,
            mappingsPresent, token, state.SecretsMapping.Username, state.SecretsMapping.Password);
    }
}
