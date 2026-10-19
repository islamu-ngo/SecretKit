using System.Diagnostics.Tracing;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed record DatabaseFamilyBinding(string Member, string[] Variants, bool Mutation);

internal static class InfisicalDatabaseFamilies
{
    internal static readonly Dictionary<string, DatabaseFamilyBinding> Bindings = new(StringComparer.Ordinal)
    {
        ["i.management.MsSqlSecretRotationOperations.CheckCredentials"] = new("SecretKit.Infisical.Management.MsSqlSecretRotationOperations.CheckCredentials(System.String,SecretKit.Infisical.InfisicalRotationAddress)",
            ["input.organizationId-address"], true),
        ["i.management.MsSqlSecretRotationOperations.Create"] = new("SecretKit.Infisical.Management.MsSqlSecretRotationOperations.Create(System.String,SecretKit.Infisical.Management.MsSqlSecretRotationCreation)",
            ["MsSqlSecretRotationCreation.rotateAtUtc.omitted", "MsSqlSecretRotationCreation.rotateAtUtc.value", "MsSqlSecretRotationCreation.description.omitted", "MsSqlSecretRotationCreation.description.value", "MsSqlSecretRotationCreation.isAutoRotationEnabled.omitted", "MsSqlSecretRotationCreation.isAutoRotationEnabled.false", "MsSqlSecretRotationCreation.isAutoRotationEnabled.true", "MsSqlRotationParameters.passwordRequirements.omitted", "MsSqlRotationParameters.passwordRequirements.value", "MsSqlRotationParameters.rotationStatement.omitted", "MsSqlRotationParameters.rotationStatement.value", "MsSqlRotationPasswordRequirements.allowedSymbols.omitted", "MsSqlRotationPasswordRequirements.allowedSymbols.value", "description.null", "description.value", "description.omitted", "passwordRequirements.fractional-number", "rotationInterval.fractional-number", "rotateAtUtc.fractional-number"], true),
        ["i.management.MsSqlSecretRotationOperations.Delete"] = new("SecretKit.Infisical.Management.MsSqlSecretRotationOperations.Delete(System.String,SecretKit.Infisical.InfisicalRotationAddress,System.Nullable<System.Boolean>,System.Nullable<System.Boolean>)",
            ["deleteSecrets.omitted.revokeGeneratedCredentials.omitted", "deleteSecrets.omitted.revokeGeneratedCredentials.false", "deleteSecrets.omitted.revokeGeneratedCredentials.true", "deleteSecrets.false.revokeGeneratedCredentials.omitted", "deleteSecrets.false.revokeGeneratedCredentials.false", "deleteSecrets.false.revokeGeneratedCredentials.true", "deleteSecrets.true.revokeGeneratedCredentials.omitted", "deleteSecrets.true.revokeGeneratedCredentials.false", "deleteSecrets.true.revokeGeneratedCredentials.true"], true),
        ["i.management.MsSqlSecretRotationOperations.Get"] = new("SecretKit.Infisical.Management.MsSqlSecretRotationOperations.Get(System.String,SecretKit.Infisical.InfisicalRotationAddress)",
            ["selector.exact"], false),
        ["i.management.MsSqlSecretRotationOperations.GetByName"] = new("SecretKit.Infisical.Management.MsSqlSecretRotationOperations.GetByName(System.String,System.String,System.String,System.String,System.String)",
            ["selector.name"], false),
        ["i.management.MsSqlSecretRotationOperations.GetGeneratedCredentials"] = new("SecretKit.Infisical.Management.MsSqlSecretRotationOperations.GetGeneratedCredentials(System.String,SecretKit.Infisical.InfisicalRotationAddress)",
            ["selector.exact"], false),
        ["i.management.MsSqlSecretRotationOperations.List"] = new("SecretKit.Infisical.Management.MsSqlSecretRotationOperations.List(System.String,System.String)",
            ["collection.bounded"], false),
        ["i.management.MsSqlSecretRotationOperations.ListMsSqlSubset"] = new("SecretKit.Infisical.Management.MsSqlSecretRotationOperations.ListMsSqlSubset(System.String,System.String)",
            ["collection.bounded", "catalog.MsSql-only.partial"], false),
        ["i.management.MsSqlSecretRotationOperations.Move"] = new("SecretKit.Infisical.Management.MsSqlSecretRotationOperations.Move(System.String,SecretKit.Infisical.InfisicalRotationAddress,SecretKit.Infisical.Management.MsSqlSecretRotationMove)",
            ["overwriteDestination.omitted", "overwriteDestination.false", "overwriteDestination.true"], true),
        ["i.management.MsSqlSecretRotationOperations.MsSqlOptionsSubset"] = new("SecretKit.Infisical.Management.MsSqlSecretRotationOperations.MsSqlOptionsSubset(System.String)",
            ["catalog.MsSql-only.partial"], false),
        ["i.management.MsSqlSecretRotationOperations.Update"] = new("SecretKit.Infisical.Management.MsSqlSecretRotationOperations.Update(System.String,SecretKit.Infisical.InfisicalRotationAddress,SecretKit.Infisical.Management.MsSqlSecretRotationUpdate)",
            ["MsSqlSecretRotationUpdate.name.omitted", "MsSqlSecretRotationUpdate.name.value", "MsSqlSecretRotationUpdate.description.omitted", "MsSqlSecretRotationUpdate.description.value", "MsSqlSecretRotationUpdate.isAutoRotationEnabled.omitted", "MsSqlSecretRotationUpdate.isAutoRotationEnabled.false", "MsSqlSecretRotationUpdate.isAutoRotationEnabled.true", "MsSqlSecretRotationUpdate.rotationInterval.omitted", "MsSqlSecretRotationUpdate.rotationInterval.value", "MsSqlSecretRotationUpdate.parameters.omitted", "MsSqlSecretRotationUpdate.parameters.value", "MsSqlSecretRotationUpdate.secretsMapping.omitted", "MsSqlSecretRotationUpdate.secretsMapping.value", "MsSqlSecretRotationUpdate.rotateAtUtc.omitted", "MsSqlSecretRotationUpdate.rotateAtUtc.value", "MsSqlRotationParameters.passwordRequirements.omitted", "MsSqlRotationParameters.passwordRequirements.value", "MsSqlRotationParameters.rotationStatement.omitted", "MsSqlRotationParameters.rotationStatement.value", "MsSqlRotationPasswordRequirements.allowedSymbols.omitted", "MsSqlRotationPasswordRequirements.allowedSymbols.value", "description.null", "description.value", "description.omitted", "passwordRequirements.fractional-number", "rotationInterval.fractional-number", "rotateAtUtc.fractional-number", "patch.empty", "parameters.omitted", "parameters.supplied-persistence-unestablished", "secretsMapping.omitted", "secretsMapping.supplied-persistence-unestablished", "patch.persistence-unestablished"], true),
        ["i.management.MySqlSecretRotationOperations.CheckCredentials"] = new("SecretKit.Infisical.Management.MySqlSecretRotationOperations.CheckCredentials(System.String,SecretKit.Infisical.InfisicalRotationAddress)",
            ["input.organizationId-address"], true),
        ["i.management.MySqlSecretRotationOperations.Create"] = new("SecretKit.Infisical.Management.MySqlSecretRotationOperations.Create(System.String,SecretKit.Infisical.Management.MySqlSecretRotationCreation)",
            ["MySqlSecretRotationCreation.rotateAtUtc.omitted", "MySqlSecretRotationCreation.rotateAtUtc.value", "MySqlSecretRotationCreation.description.omitted", "MySqlSecretRotationCreation.description.value", "MySqlSecretRotationCreation.isAutoRotationEnabled.omitted", "MySqlSecretRotationCreation.isAutoRotationEnabled.false", "MySqlSecretRotationCreation.isAutoRotationEnabled.true", "MySqlRotationParameters.passwordRequirements.omitted", "MySqlRotationParameters.passwordRequirements.value", "MySqlRotationParameters.rotationStatement.omitted", "MySqlRotationParameters.rotationStatement.value", "MySqlRotationPasswordRequirements.allowedSymbols.omitted", "MySqlRotationPasswordRequirements.allowedSymbols.value", "description.null", "description.value", "description.omitted", "passwordRequirements.fractional-number", "rotationInterval.fractional-number", "rotateAtUtc.fractional-number"], true),
        ["i.management.MySqlSecretRotationOperations.Delete"] = new("SecretKit.Infisical.Management.MySqlSecretRotationOperations.Delete(System.String,SecretKit.Infisical.InfisicalRotationAddress,System.Nullable<System.Boolean>,System.Nullable<System.Boolean>)",
            ["deleteSecrets.omitted.revokeGeneratedCredentials.omitted", "deleteSecrets.omitted.revokeGeneratedCredentials.false", "deleteSecrets.omitted.revokeGeneratedCredentials.true", "deleteSecrets.false.revokeGeneratedCredentials.omitted", "deleteSecrets.false.revokeGeneratedCredentials.false", "deleteSecrets.false.revokeGeneratedCredentials.true", "deleteSecrets.true.revokeGeneratedCredentials.omitted", "deleteSecrets.true.revokeGeneratedCredentials.false", "deleteSecrets.true.revokeGeneratedCredentials.true"], true),
        ["i.management.MySqlSecretRotationOperations.Get"] = new("SecretKit.Infisical.Management.MySqlSecretRotationOperations.Get(System.String,SecretKit.Infisical.InfisicalRotationAddress)",
            ["selector.exact"], false),
        ["i.management.MySqlSecretRotationOperations.GetByName"] = new("SecretKit.Infisical.Management.MySqlSecretRotationOperations.GetByName(System.String,System.String,System.String,System.String,System.String)",
            ["selector.name"], false),
        ["i.management.MySqlSecretRotationOperations.GetGeneratedCredentials"] = new("SecretKit.Infisical.Management.MySqlSecretRotationOperations.GetGeneratedCredentials(System.String,SecretKit.Infisical.InfisicalRotationAddress)",
            ["selector.exact"], false),
        ["i.management.MySqlSecretRotationOperations.List"] = new("SecretKit.Infisical.Management.MySqlSecretRotationOperations.List(System.String,System.String)",
            ["collection.bounded"], false),
        ["i.management.MySqlSecretRotationOperations.ListMySqlSubset"] = new("SecretKit.Infisical.Management.MySqlSecretRotationOperations.ListMySqlSubset(System.String,System.String)",
            ["collection.bounded", "catalog.MySql-only.partial"], false),
        ["i.management.MySqlSecretRotationOperations.Move"] = new("SecretKit.Infisical.Management.MySqlSecretRotationOperations.Move(System.String,SecretKit.Infisical.InfisicalRotationAddress,SecretKit.Infisical.Management.MySqlSecretRotationMove)",
            ["overwriteDestination.omitted", "overwriteDestination.false", "overwriteDestination.true"], true),
        ["i.management.MySqlSecretRotationOperations.MySqlOptionsSubset"] = new("SecretKit.Infisical.Management.MySqlSecretRotationOperations.MySqlOptionsSubset(System.String)",
            ["catalog.MySql-only.partial"], false),
        ["i.management.MySqlSecretRotationOperations.Update"] = new("SecretKit.Infisical.Management.MySqlSecretRotationOperations.Update(System.String,SecretKit.Infisical.InfisicalRotationAddress,SecretKit.Infisical.Management.MySqlSecretRotationUpdate)",
            ["MySqlSecretRotationUpdate.name.omitted", "MySqlSecretRotationUpdate.name.value", "MySqlSecretRotationUpdate.description.omitted", "MySqlSecretRotationUpdate.description.value", "MySqlSecretRotationUpdate.isAutoRotationEnabled.omitted", "MySqlSecretRotationUpdate.isAutoRotationEnabled.false", "MySqlSecretRotationUpdate.isAutoRotationEnabled.true", "MySqlSecretRotationUpdate.rotationInterval.omitted", "MySqlSecretRotationUpdate.rotationInterval.value", "MySqlSecretRotationUpdate.parameters.omitted", "MySqlSecretRotationUpdate.parameters.value", "MySqlSecretRotationUpdate.secretsMapping.omitted", "MySqlSecretRotationUpdate.secretsMapping.value", "MySqlSecretRotationUpdate.rotateAtUtc.omitted", "MySqlSecretRotationUpdate.rotateAtUtc.value", "MySqlRotationParameters.passwordRequirements.omitted", "MySqlRotationParameters.passwordRequirements.value", "MySqlRotationParameters.rotationStatement.omitted", "MySqlRotationParameters.rotationStatement.value", "MySqlRotationPasswordRequirements.allowedSymbols.omitted", "MySqlRotationPasswordRequirements.allowedSymbols.value", "description.null", "description.value", "description.omitted", "passwordRequirements.fractional-number", "rotationInterval.fractional-number", "rotateAtUtc.fractional-number", "patch.empty", "parameters.omitted", "parameters.supplied-persistence-unestablished", "secretsMapping.omitted", "secretsMapping.supplied-persistence-unestablished", "patch.persistence-unestablished"], true),
        ["i.management.PostgresSecretRotationOperations.CheckCredentials"] = new("SecretKit.Infisical.Management.PostgresSecretRotationOperations.CheckCredentials(System.String,SecretKit.Infisical.InfisicalRotationAddress)",
            ["input.organizationId-address"], true),
        ["i.management.PostgresSecretRotationOperations.Create"] = new("SecretKit.Infisical.Management.PostgresSecretRotationOperations.Create(System.String,SecretKit.Infisical.Management.PostgresSecretRotationCreation)",
            ["PostgresSecretRotationCreation.rotateAtUtc.omitted", "PostgresSecretRotationCreation.rotateAtUtc.value", "PostgresSecretRotationCreation.description.omitted", "PostgresSecretRotationCreation.description.value", "PostgresSecretRotationCreation.isAutoRotationEnabled.omitted", "PostgresSecretRotationCreation.isAutoRotationEnabled.false", "PostgresSecretRotationCreation.isAutoRotationEnabled.true", "PostgresRotationParameters.passwordRequirements.omitted", "PostgresRotationParameters.passwordRequirements.value", "PostgresRotationParameters.rotationStatement.omitted", "PostgresRotationParameters.rotationStatement.value", "PostgresRotationPasswordRequirements.allowedSymbols.omitted", "PostgresRotationPasswordRequirements.allowedSymbols.value", "description.null", "description.value", "description.omitted", "passwordRequirements.fractional-number", "rotationInterval.fractional-number", "rotateAtUtc.fractional-number"], true),
        ["i.management.PostgresSecretRotationOperations.Delete"] = new("SecretKit.Infisical.Management.PostgresSecretRotationOperations.Delete(System.String,SecretKit.Infisical.InfisicalRotationAddress,System.Nullable<System.Boolean>,System.Nullable<System.Boolean>)",
            ["deleteSecrets.omitted.revokeGeneratedCredentials.omitted", "deleteSecrets.omitted.revokeGeneratedCredentials.false", "deleteSecrets.omitted.revokeGeneratedCredentials.true", "deleteSecrets.false.revokeGeneratedCredentials.omitted", "deleteSecrets.false.revokeGeneratedCredentials.false", "deleteSecrets.false.revokeGeneratedCredentials.true", "deleteSecrets.true.revokeGeneratedCredentials.omitted", "deleteSecrets.true.revokeGeneratedCredentials.false", "deleteSecrets.true.revokeGeneratedCredentials.true"], true),
        ["i.management.PostgresSecretRotationOperations.Get"] = new("SecretKit.Infisical.Management.PostgresSecretRotationOperations.Get(System.String,SecretKit.Infisical.InfisicalRotationAddress)",
            ["selector.exact"], false),
        ["i.management.PostgresSecretRotationOperations.GetByName"] = new("SecretKit.Infisical.Management.PostgresSecretRotationOperations.GetByName(System.String,System.String,System.String,System.String,System.String)",
            ["selector.name"], false),
        ["i.management.PostgresSecretRotationOperations.GetGeneratedCredentials"] = new("SecretKit.Infisical.Management.PostgresSecretRotationOperations.GetGeneratedCredentials(System.String,SecretKit.Infisical.InfisicalRotationAddress)",
            ["selector.exact"], false),
        ["i.management.PostgresSecretRotationOperations.List"] = new("SecretKit.Infisical.Management.PostgresSecretRotationOperations.List(System.String,System.String)",
            ["collection.bounded"], false),
        ["i.management.PostgresSecretRotationOperations.ListPostgresSubset"] = new("SecretKit.Infisical.Management.PostgresSecretRotationOperations.ListPostgresSubset(System.String,System.String)",
            ["collection.bounded", "catalog.Postgres-only.partial"], false),
        ["i.management.PostgresSecretRotationOperations.Move"] = new("SecretKit.Infisical.Management.PostgresSecretRotationOperations.Move(System.String,SecretKit.Infisical.InfisicalRotationAddress,SecretKit.Infisical.Management.PostgresSecretRotationMove)",
            ["overwriteDestination.omitted", "overwriteDestination.false", "overwriteDestination.true"], true),
        ["i.management.PostgresSecretRotationOperations.PostgresOptionsSubset"] = new("SecretKit.Infisical.Management.PostgresSecretRotationOperations.PostgresOptionsSubset(System.String)",
            ["catalog.Postgres-only.partial"], false),
        ["i.management.PostgresSecretRotationOperations.Update"] = new("SecretKit.Infisical.Management.PostgresSecretRotationOperations.Update(System.String,SecretKit.Infisical.InfisicalRotationAddress,SecretKit.Infisical.Management.PostgresSecretRotationUpdate)",
            ["PostgresSecretRotationUpdate.name.omitted", "PostgresSecretRotationUpdate.name.value", "PostgresSecretRotationUpdate.description.omitted", "PostgresSecretRotationUpdate.description.value", "PostgresSecretRotationUpdate.isAutoRotationEnabled.omitted", "PostgresSecretRotationUpdate.isAutoRotationEnabled.false", "PostgresSecretRotationUpdate.isAutoRotationEnabled.true", "PostgresSecretRotationUpdate.rotationInterval.omitted", "PostgresSecretRotationUpdate.rotationInterval.value", "PostgresSecretRotationUpdate.parameters.omitted", "PostgresSecretRotationUpdate.parameters.value", "PostgresSecretRotationUpdate.secretsMapping.omitted", "PostgresSecretRotationUpdate.secretsMapping.value", "PostgresSecretRotationUpdate.rotateAtUtc.omitted", "PostgresSecretRotationUpdate.rotateAtUtc.value", "PostgresRotationParameters.passwordRequirements.omitted", "PostgresRotationParameters.passwordRequirements.value", "PostgresRotationParameters.rotationStatement.omitted", "PostgresRotationParameters.rotationStatement.value", "PostgresRotationPasswordRequirements.allowedSymbols.omitted", "PostgresRotationPasswordRequirements.allowedSymbols.value", "description.null", "description.value", "description.omitted", "passwordRequirements.fractional-number", "rotationInterval.fractional-number", "rotateAtUtc.fractional-number", "patch.empty", "parameters.omitted", "parameters.supplied-persistence-unestablished", "secretsMapping.omitted", "secretsMapping.supplied-persistence-unestablished", "patch.persistence-unestablished"], true),
        ["i.management.ProjectConnectionOperations.ListAuthorizations"] = new("SecretKit.Infisical.Management.ProjectConnectionOperations.ListAuthorizations(System.String,System.String)",
            ["collection.bounded"], false),
        ["i.management.ProjectConnectionOperations.ListIntegrations"] = new("SecretKit.Infisical.Management.ProjectConnectionOperations.ListIntegrations(System.String,System.String)",
            ["collection.bounded"], false),
    };

    internal static bool Owns(string operation) => Bindings.ContainsKey(operation) ||
        new[] { "ProjectConnectionOperations", "PostgresSecretRotationOperations", "MySqlSecretRotationOperations",
            "MsSqlSecretRotationOperations" }.Any(f => operation.StartsWith("i.management." + f + ".", StringComparison.Ordinal));

    internal static bool Valid(NativeCaseDefinition d) => d.Key.Provider == "Infisical" &&
        !string.IsNullOrWhiteSpace(d.Key.Scope) && Bindings.TryGetValue(d.Key.Operation, out var binding) &&
        d.Member == binding.Member && binding.Variants.Contains(d.Key.Variant, StringComparer.Ordinal) &&
        (d.Key.Case is "selected-contract" or "independent-effect" or "denied-authority" or "cancellation-boundary" ||
            binding.Mutation && d.Key.Case == "lost-response-no-replay");

    internal static string? UnavailableReason(NativeCaseDefinition d) => !Valid(d) ? "contract-mismatch" :
        d.Key.Variant.Contains("unestablished", StringComparison.Ordinal) ? "primary-patch-persistence-unestablished" : null;

    public static void Register(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected) => Register(registry, environment, expected, null);

    internal static void Register(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected, IDatabaseFixtureFactory? fixtures)
    {
        foreach (var d in expected.Where(d => Owns(d.Key.Operation)))
            registry.Add(new(d, (probe, token) => RunAsync(environment, d, probe, fixtures, token)));
    }

    private static async ValueTask RunAsync(NativeEnvironment environment, NativeCaseDefinition d,
        NativeCaseProbe probe, IDatabaseFixtureFactory? fixtures, CancellationToken token)
    {
        probe.Contract(Valid(d), NativeFailure.ContractMismatch);
        string family = d.Key.Operation.Split('.')[2] switch
        {
            "ProjectConnectionOperations" => "ProjectConnections",
            "PostgresSecretRotationOperations" => "PostgresSecretRotations",
            "MySqlSecretRotationOperations" => "MySqlSecretRotations",
            _ => "MsSqlSecretRotations"
        };
        ProjectFamilyContext? context = null;
        IDatabaseOwnedFixture? fixture = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(45));
        try
        {
            if (family != "ProjectConnections")
            {
                fixtures ??= InfisicalDatabaseFixtureFactory.FromInputs(environment, family);
                if (fixtures is null) probe.Effect(NativeObservation.Unavailable);
            }
            context = new(environment, family, d, probe);
            if (family == "ProjectConnections")
                await ProjectConnectionsEffects.ExecuteAsync(context, deadline.Token);
            else
            {
                await context.EnsureProjectAsync(deadline.Token, runtimeMember: true);
                string name = ProjectFamilyContext.FreshName();
                fixture = await fixtures!.CreateAsync(environment, d, context.ProjectId, context.Input, name, deadline.Token);
                if (UnavailableReason(d) is not null && fixture.SqlRotationPatch is null)
                    probe.Effect(NativeObservation.Unavailable);
                InfisicalRotationProfile profile = family switch
                {
                    "PostgresSecretRotations" => InfisicalRotationProfile.PostgresCredentials,
                    "MySqlSecretRotations" => InfisicalRotationProfile.MysqlCredentials,
                    _ => InfisicalRotationProfile.MssqlCredentials
                };
                probe.Contract(fixture.Name == name && fixture.SourcePath == "/" + name &&
                    fixture.DestinationPath == "/" + name + "-moved" && fixture.Username1 != fixture.Username2 &&
                    fixture.UsernameKey != fixture.PasswordKey && fixture.AllowedActions.Length > 0 &&
                    fixture.DeniedActions.Length > 0 && fixture.BackendCoordinate.Profile == profile &&
                    fixture.BackendCoordinate.ConnectionId == fixture.ConnectionId &&
                    !string.IsNullOrWhiteSpace(fixture.BackendCoordinate.Host) &&
                    !string.IsNullOrWhiteSpace(fixture.BackendCoordinate.Database) &&
                    fixture.BackendCoordinate.Port is > 0 and <= 65535, NativeFailure.MissingPrerequisite);
                if (string.IsNullOrWhiteSpace(fixture.PrimaryShapeRevision) || fixture.Backend is null ||
                    context.Operation == "Update" && fixture.ExpectedPatchConfiguration is null && fixture.SqlRotationPatch is null)
                    probe.Effect(NativeObservation.Unavailable);
                switch (family)
                {
                    case "PostgresSecretRotations": await PostgresSecretRotationsEffects.ExecuteAsync(context, fixture, deadline.Token); break;
                    case "MySqlSecretRotations": await MySqlSecretRotationsEffects.ExecuteAsync(context, fixture, deadline.Token); break;
                    default: await MsSqlSecretRotationsEffects.ExecuteAsync(context, fixture, deadline.Token); break;
                }
            }
        }
        catch (NativeCaseFailureException error)
        {
            probe.Contract(false, error.Message switch
            {
                "missing-input" => NativeFailure.MissingInput,
                "missing-prerequisite" => NativeFailure.MissingPrerequisite,
                "observer-unavailable" => NativeFailure.ObserverUnavailable,
                "effect-mismatch" => NativeFailure.EffectMismatch,
                "cleanup-incomplete" => NativeFailure.CleanupIncomplete,
                "contract-mismatch" => NativeFailure.ContractMismatch,
                _ => NativeFailure.UnexpectedFailure
            });
        }
        catch (OperationCanceledException)
        {
            probe.Contract(false, token.IsCancellationRequested ? NativeFailure.UnexpectedCancellation : NativeFailure.DeadlineExceeded);
        }
        catch (Exception error) when (error is ArgumentException or JsonException or KeyNotFoundException)
        {
            probe.Contract(false, NativeFailure.MissingInput);
        }
        finally
        {
            bool clean = true;
            if (fixture is not null)
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                try
                {
                    if (fixture.SqlRotationPatch is { } patch) await patch.RecoverAsync(cleanup.Token);
                    await fixture.CleanupAsync(cleanup.Token);
                    DatabaseCleanupMeasurement remaining = await fixture.ObserveCleanupAsync(cleanup.Token);
                    clean = remaining.RemainingAccounts == 0 && remaining.RemainingMappings == 0 &&
                        remaining.RemainingRotations == 0;
                    if (fixture.SqlRotationPatch is { } completedPatch) await completedPatch.CloseAsync(cleanup.Token);
                }
                catch (Exception) { clean = false; }
                finally
                {
                    try { await fixture.DisposeAsync(); }
                    catch (Exception) { clean = false; }
                }
            }
            // Project cleanup is independent of backend cleanup and of operation cancellation.
            try { if (context is not null) await context.CleanupAsync(); }
            finally { probe.Contract(clean, NativeFailure.CleanupIncomplete); }
        }
    }

    internal static bool? Flag(string variant, string field)
    {
        string value = variant.Split('.').SkipWhile(s => s != field).Skip(1).First();
        return value == "omitted" ? null : value == "true";
    }

    internal static bool SameMaterial(SecretMaterial? left, SecretMaterial? right)
    {
        if (left is null || right is null) return left is null && right is null;
        char[] a = left.ExportCharacters(), b = right.ExportCharacters();
        try { return a.AsSpan().SequenceEqual(b); }
        finally { Array.Clear(a); Array.Clear(b); }
    }

    internal static async ValueTask CredentialCheckCaseAsync<T>(ProjectFamilyContext c,
        Func<ManagementRequest<T>> factory, Func<bool, CancellationToken, ValueTask<bool>> observe,
        CancellationToken token) where T : notnull
    {
        if (c.Definition.Key.Case != "lost-response-no-replay")
        {
            await c.CaseAsync(factory, _ => true, observe, token);
            return;
        }
        // A 204 has no body to lose. Cancel at the correlated header-read start,
        // after send and before any complete acknowledgement can be parsed.
        ManagementClient client = c.Environment.CreateManagementClient();
        using var intent = factory();
        using var request = factory();
        var authority = c.Environment.CreateManagementAuthority(client, NativeIdentityRole.Administrative,
            intent.Target.OrganizationId, intent.Target.ProjectId);
        var receipt = client.CreateReceipt(request);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var boundary = new DatabaseHeaderReadBoundary(c.Environment.Origin, cancellation);
        bool cancelled = false;
        using (boundary.Enter())
        {
            try
            {
                await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(intent.OperationId, intent.Target), receipt, cancellation.Token);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                cancelled = cancellation.IsCancellationRequested;
            }
        }
        c.Probe.Contract(boundary.Reached && cancelled && receipt.Evidence == DispatchEvidence.PossiblyDispatched,
            NativeFailure.ContractMismatch);
        c.Probe.Effect(await observe(true, token) ? NativeObservation.Matched : NativeObservation.Mismatched);
        c.Probe.Contract(receipt.Evidence == DispatchEvidence.PossiblyDispatched, NativeFailure.ContractMismatch);
    }

    internal static void Authentication(NativeCaseProbe probe, DatabaseAuthenticationMeasurement m,
        IDatabaseOwnedFixture f, DatabaseAuthentication expected)
    {
        if (m.Selected == DatabaseAuthentication.Unavailable || m.Denied == DatabaseAuthentication.Unavailable)
            probe.Effect(NativeObservation.Unavailable);
        probe.Contract(m.Coordinate == f.BackendCoordinate && m.Selected == expected && m.Denied == DatabaseAuthentication.Rejected &&
            (expected == DatabaseAuthentication.Rejected || m.AllowedActions.Order(StringComparer.Ordinal)
                .SequenceEqual(f.AllowedActions.Order(StringComparer.Ordinal)) && m.DeniedActions.Order(StringComparer.Ordinal)
                .SequenceEqual(f.DeniedActions.Order(StringComparer.Ordinal))) && m.ObservedAt != default,
            NativeFailure.EffectMismatch);
    }

    internal static async ValueTask MappingAsync(ProjectFamilyContext c, IDatabaseOwnedFixture f,
        string environment, string path, SecretMaterial username, SecretMaterial password, bool present, CancellationToken token,
        string? usernameKey = null, string? passwordKey = null)
    {
        await using var consumer = c.Environment.CreateRuntimeClient();
        await using var observer = c.Environment.CreateObserverClient();
        foreach (InfisicalClient client in new[] { consumer, observer })
        {
            var user = await client.ReadAsync(new(client.Authority, new InfisicalSecretAddress(c.ProjectId,
                environment, path, usernameKey ?? f.UsernameKey)), token);
            using SecretRead? ownedUser = user.IsSuccess ? user.Value : null;
            var pass = await client.ReadAsync(new(client.Authority, new InfisicalSecretAddress(c.ProjectId,
                environment, path, passwordKey ?? f.PasswordKey)), token);
            try
            {
                c.Probe.Contract(present ? user.IsSuccess && pass.IsSuccess && SameMaterial(user.Value.Material, username) &&
                    SameMaterial(pass.Value.Material, password) : user.Status == SecretStatus.Absent && pass.Status == SecretStatus.Absent,
                    NativeFailure.EffectMismatch);
            }
            finally
            {
                if (pass.IsSuccess) pass.Value.Dispose();
            }
        }
    }
}

internal sealed class DatabaseHeaderReadBoundary : EventListener
{
    private static readonly AsyncLocal<DatabaseHeaderReadBoundary?> current = new();
    private readonly Uri origin;
    private readonly CancellationTokenSource cancellation;
    private int started;
    internal bool Reached { get; private set; }
    internal DatabaseHeaderReadBoundary(Uri origin, CancellationTokenSource cancellation)
    { this.origin = origin; this.cancellation = cancellation; }
    internal IDisposable Enter()
    {
        var previous = current.Value;
        current.Value = this;
        return new Scope(previous);
    }
    protected override void OnEventSourceCreated(EventSource source)
    {
        if (source.Name == "System.Net.Http")
            EnableEvents(source, EventLevel.Informational, EventKeywords.All);
    }
    protected override void OnEventWritten(EventWrittenEventArgs message)
    {
        if (!ReferenceEquals(current.Value, this)) return;
        if (message.EventName == "RequestStart" && message.PayloadNames is not null && message.Payload is not null)
        {
            int scheme = message.PayloadNames.IndexOf("scheme"), host = message.PayloadNames.IndexOf("host"),
                port = message.PayloadNames.IndexOf("port");
            if (scheme >= 0 && host >= 0 && port >= 0 && message.Payload[scheme] is string observedScheme &&
                observedScheme == origin.Scheme && message.Payload[host] is string observedHost && observedHost == origin.Host &&
                message.Payload[port] is int observedPort && observedPort == origin.Port)
                Interlocked.Increment(ref started);
        }
        if (message.EventName != "ResponseHeadersStart" || Volatile.Read(ref started) != 1) return;
        Reached = true;
        cancellation.Cancel();
    }
    private sealed class Scope(DatabaseHeaderReadBoundary? previous) : IDisposable
    {
        public void Dispose() => current.Value = previous;
    }
}

// Caller-owned fixtures provision only an explicitly owned native sandbox and backend.
// Preparation must register compensation before dispatch; a failed preparation cleans itself.
// These interfaces carry measurements, not pass flags or remotely supplied case handlers.
internal interface IDatabaseFixtureFactory
{
    ValueTask<IDatabaseOwnedFixture> CreateAsync(NativeEnvironment environment, NativeCaseDefinition definition,
        string ownedProjectId, JsonElement scopeInput, string freshName, CancellationToken token);
}

internal interface IDatabaseOwnedFixture : IAsyncDisposable
{
    SqlRotationPatchTrial? SqlRotationPatch => null;
    string Name { get; }
    string Environment { get; }
    string SourcePath { get; }
    string DestinationEnvironment { get; }
    string DestinationPath { get; }
    string ConnectionId { get; }
    string Username1 { get; }
    string Username2 { get; }
    string UsernameKey { get; }
    string PasswordKey { get; }
    string UpdatedUsername1 { get; }
    string UpdatedUsername2 { get; }
    string UpdatedUsernameKey { get; }
    string UpdatedPasswordKey { get; }
    SecretMaterial UpdatedRotationStatement { get; }
    SecretMaterial RotationStatement { get; }
    string[] AllowedActions { get; }
    string[] DeniedActions { get; }
    string? PrimaryShapeRevision { get; }
    DatabaseConfiguration CreationDefaults { get; }
    DatabaseConfiguration? ExpectedPatchConfiguration { get; }
    SecretMaterial? ExpectedPatchStatement { get; }
    bool? DefaultDeleteSecrets { get; }
    bool? DefaultRevokeCredentials { get; }
    IDatabaseBackendObserver? Backend { get; }
    DatabaseBackendCoordinate BackendCoordinate { get; }
    // Must fetch the unfiltered catalog with the explicitly selected observer credential.
    ValueTask<DatabaseCatalogMeasurement> ObserveCatalogAsync(bool options, CancellationToken token);
    ValueTask CleanupAsync(CancellationToken token);
    ValueTask<DatabaseCleanupMeasurement> ObserveCleanupAsync(CancellationToken token);
}

internal enum DatabaseAuthentication { Accepted, Rejected, Unavailable }
internal sealed record DatabaseBackendCoordinate([property: JsonIgnore] InfisicalRotationProfile Profile,
    [property: JsonIgnore] string Host, [property: JsonIgnore] int Port, [property: JsonIgnore] string Database,
    [property: JsonIgnore] string ConnectionId)
{
    public override string ToString() => "[DatabaseBackendCoordinate]";
}
internal sealed record DatabaseAuthenticationMeasurement(
    [property: JsonIgnore] DatabaseBackendCoordinate Coordinate,
    [property: JsonIgnore] DatabaseAuthentication Selected, [property: JsonIgnore] DatabaseAuthentication Denied,
    [property: JsonIgnore] string[] AllowedActions, [property: JsonIgnore] string[] DeniedActions,
    [property: JsonIgnore] DateTimeOffset ObservedAt)
{
    public override string ToString() => "[DatabaseAuthenticationMeasurement]";
}
internal interface IDatabaseBackendObserver
{
    ValueTask<DatabaseAuthenticationMeasurement> MeasureAuthorityAsync(CancellationToken token);
    ValueTask<DatabaseAuthenticationMeasurement> AuthenticateAsync(SecretMaterial username, SecretMaterial password, CancellationToken token);
    // Arm the exact old-credential rejection event BEFORE Delete, never poll status.
    ValueTask<IDatabaseRejectionSubscription> SubscribeRejectionAsync(SecretMaterial username, SecretMaterial password, CancellationToken token);
}
internal interface IDatabaseRejectionSubscription : IAsyncDisposable
{
    Task<DatabaseAuthenticationMeasurement> Rejected { get; }
}
internal sealed record DatabaseCleanupMeasurement(int RemainingAccounts, int RemainingMappings, int RemainingRotations);

internal sealed record DatabaseConfiguration(
    [property: JsonIgnore] string Name, [property: JsonIgnore] string ConnectionId,
    [property: JsonIgnore] string Environment, [property: JsonIgnore] string Path,
    [property: JsonIgnore] string Username1, [property: JsonIgnore] string Username2,
    [property: JsonIgnore] string UsernameKey, [property: JsonIgnore] string PasswordKey,
    [property: JsonIgnore] double Interval, [property: JsonIgnore] double Hours, [property: JsonIgnore] double Minutes,
    [property: JsonIgnore] bool? Enabled, [property: JsonIgnore] bool HasDescription, [property: JsonIgnore] string? Description,
    [property: JsonIgnore] DatabasePasswordRequirements? PasswordRequirements)
{
    public override string ToString() => "[DatabaseConfiguration]";
}
internal sealed record DatabasePasswordRequirements(
    [property: JsonIgnore] double Length, [property: JsonIgnore] double Digits, [property: JsonIgnore] double Lowercase,
    [property: JsonIgnore] double Symbols, [property: JsonIgnore] double Uppercase, [property: JsonIgnore] string? AllowedSymbols)
{
    public override string ToString() => "[DatabasePasswordRequirements]";
}
internal sealed record DatabaseCatalogRow([property: JsonIgnore] string Id, [property: JsonIgnore] string Type)
{
    public override string ToString() => "[DatabaseCatalogRow]";
}
internal sealed record DatabaseCatalogOption([property: JsonIgnore] string Type,
    [property: JsonIgnore] string UsernameKey, [property: JsonIgnore] string PasswordKey,
    [property: JsonIgnore] SecretMaterial CreateStatement, [property: JsonIgnore] SecretMaterial RotationStatement) : IDisposable
{
    public void Dispose() { CreateStatement.Dispose(); RotationStatement.Dispose(); }
    public override string ToString() => "[DatabaseCatalogOption]";
}
internal sealed record DatabaseCatalogMeasurement([property: JsonIgnore] IReadOnlyList<DatabaseCatalogRow> Rows,
    [property: JsonIgnore] IReadOnlyList<DatabaseCatalogOption> Options) : IDisposable
{
    public void Dispose() { foreach (var option in Options) option.Dispose(); }
    public override string ToString() => "[DatabaseCatalogMeasurement]";
}
