using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Client for an explicitly operated private fixture service, not a database
// driver or a replacement provider transport. The service owns provisioning
// under a caller-generated capability; returned coordinates grant no authority.
internal sealed class InfisicalDatabaseFixtureFactory(InfisicalLifecycleObservers channel) : IDatabaseFixtureFactory
{
    internal static InfisicalDatabaseFixtureFactory? FromInputs(NativeEnvironment environment, string family)
    {
        if (!environment.TryGetFamilyInput("C08-IM-" + family, out _)) return null;
        var selected = InfisicalLifecycleObservers.FromInputs(environment, "C08-IM-" + family);
        return selected is null ? null : new(selected);
    }

    public async ValueTask<IDatabaseOwnedFixture> CreateAsync(NativeEnvironment environment,
        NativeCaseDefinition definition, string ownedProjectId, JsonElement scopeInput, string freshName,
        CancellationToken token)
    {
        Require(InfisicalDatabaseFamilies.Valid(definition), "contract-mismatch");
        InfisicalRotationProfile profile = definition.Key.Operation.Split('.')[2] switch
        {
            "PostgresSecretRotationOperations" => InfisicalRotationProfile.PostgresCredentials,
            "MySqlSecretRotationOperations" => InfisicalRotationProfile.MysqlCredentials,
            "MsSqlSecretRotationOperations" => InfisicalRotationProfile.MssqlCredentials,
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        string organization = scopeInput.GetProperty("organizationId").GetString()!;
        Require(Guid.TryParseExact(ownedProjectId, "D", out _) && !string.IsNullOrWhiteSpace(organization) &&
            freshName.StartsWith("sk", StringComparison.Ordinal) &&
            Guid.TryParseExact(freshName[2..], "N", out _));
        // Compensation exists before dispatch, including a lost/malformed claim
        // reply. Only this locally generated nonce is ever used for release.
        var fixture = new Fixture(channel, environment, organization, ownedProjectId, freshName, profile);
        try
        {
            await fixture.InitializeAsync(definition, token);
            if (definition.Key.Operation.EndsWith(".Update", StringComparison.Ordinal))
                fixture.SqlRotationPatch = SqlRotationPatchSource.FromInput(scopeInput, channel, environment,
                    definition, organization, ownedProjectId, fixture);
            return fixture;
        }
        catch
        {
            try
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                await fixture.CleanupAsync(cleanup.Token);
                await fixture.ObserveCleanupAsync(cleanup.Token);
            }
            finally { await fixture.DisposeAsync(); }
            throw;
        }
    }

    private static void Require([DoesNotReturnIf(false)] bool valid, string reason = "observer-unavailable")
    {
        if (!valid) throw new NativeCaseFailureException(reason);
    }

    private sealed class Fixture(InfisicalLifecycleObservers channel, NativeEnvironment environment,
        string organization, string project, string name, InfisicalRotationProfile profile)
        : IDatabaseOwnedFixture, IDatabaseBackendObserver
    {
        private readonly string ownership = Guid.NewGuid().ToString("N");
        private FixtureFacts facts = null!;
        private SecretMaterial statement = null!;
        private SecretMaterial updatedStatement = null!;
        private SecretMaterial? patchStatement;
        public string Name => name;
        public string Environment => facts.Environment;
        public string SourcePath => "/" + name;
        public string DestinationEnvironment => facts.DestinationEnvironment;
        public string DestinationPath => "/" + name + "-moved";
        public string ConnectionId => facts.ConnectionId;
        public string Username1 => name + "a";
        public string Username2 => name + "b";
        public string UsernameKey => name + "_USER";
        public string PasswordKey => name + "_PASSWORD";
        public string UpdatedUsername1 => name + "c";
        public string UpdatedUsername2 => name + "d";
        public string UpdatedUsernameKey => name + "_NEWUSER";
        public string UpdatedPasswordKey => name + "_NEWPASSWORD";
        public SecretMaterial RotationStatement => statement;
        public SecretMaterial UpdatedRotationStatement => updatedStatement;
        public string[] AllowedActions => facts.AllowedActions.ToArray();
        public string[] DeniedActions => facts.DeniedActions.ToArray();
        public string? PrimaryShapeRevision => facts.PrimaryShapeRevision;
        public DatabaseConfiguration CreationDefaults { get; private set; } = null!;
        public DatabaseConfiguration? ExpectedPatchConfiguration { get; private set; }
        public SecretMaterial? ExpectedPatchStatement => patchStatement;
        public SqlRotationPatchTrial? SqlRotationPatch { get; internal set; }
        public bool? DefaultDeleteSecrets => facts.DefaultDeleteSecrets;
        public bool? DefaultRevokeCredentials => facts.DefaultRevokeCredentials;
        public IDatabaseBackendObserver Backend => this;
        public DatabaseBackendCoordinate BackendCoordinate => new(profile, facts.Host, facts.Port, facts.Database, ConnectionId);

        private void Owned(Utf8JsonWriter writer)
        {
            writer.WriteString("ownershipNonce", ownership);
            writer.WriteString("organizationId", organization);
            writer.WriteString("projectId", project);
            writer.WriteString("ownedName", name);
            writer.WriteNumber("profile", (int)profile);
        }

        internal async ValueTask InitializeAsync(NativeCaseDefinition definition, CancellationToken token)
        {
            ClaimFacts claim = await channel.PostAsync<ClaimFacts>("database/claim", Owned, token);
            Require(claim.OwnershipNonce == ownership && claim.RemainingLeases == 1);
            using var setup = await SelectedToken(NativeIdentityRole.Setup, token);
            facts = await channel.PostAsync<FixtureFacts>("database/provision", writer =>
            {
                Owned(writer);
                writer.WriteString("setupToken", setup.Material.Reveal());
                writer.WriteString("origin", environment.Origin.AbsoluteUri);
                writer.WriteString("sourcePath", SourcePath);
                writer.WriteString("destinationPath", DestinationPath);
                writer.WriteString("username1", Username1);
                writer.WriteString("username2", Username2);
                writer.WriteString("updatedUsername1", UpdatedUsername1);
                writer.WriteString("updatedUsername2", UpdatedUsername2);
                writer.WriteString("usernameKey", UsernameKey);
                writer.WriteString("passwordKey", PasswordKey);
                writer.WriteString("updatedUsernameKey", UpdatedUsernameKey);
                writer.WriteString("updatedPasswordKey", UpdatedPasswordKey);
            }, token);
            Require(facts.OwnershipNonce == ownership && facts.OrganizationId == organization &&
                facts.ProjectId == project && facts.OwnedName == name && facts.Profile == profile &&
                facts.SourcePath == SourcePath && facts.DestinationPath == DestinationPath &&
                Guid.TryParseExact(facts.ConnectionId, "D", out _) && Text(facts.Host) && Text(facts.Database) &&
                facts.Port is > 0 and <= 65535 && Text(facts.Environment) && Text(facts.DestinationEnvironment) &&
                facts.Environment != facts.DestinationEnvironment && Text(facts.PrimaryShapeRevision) &&
                Actions(facts.AllowedActions) && Actions(facts.DeniedActions) &&
                !facts.AllowedActions.Intersect(facts.DeniedActions, StringComparer.Ordinal).Any() &&
                Statement(facts.RotationStatement) && Statement(facts.UpdatedRotationStatement) &&
                (facts.DefaultHasDescription || facts.DefaultDescription is null));
            statement = SecretMaterial.FromText(facts.RotationStatement);
            updatedStatement = SecretMaterial.FromText(facts.UpdatedRotationStatement);
            facts = facts with { RotationStatement = "", UpdatedRotationStatement = "" };
            // Construct the selected public SDK profiles. Constructors enforce
            // native coordinate, numeric and protected-statement constraints.
            switch (profile)
            {
                case InfisicalRotationProfile.PostgresCredentials:
                    using (var parameters = new PostgresRotationParameters(Username1, Username2, rotationStatement: statement))
                    using (var updated = new PostgresRotationParameters(UpdatedUsername1, UpdatedUsername2, rotationStatement: updatedStatement))
                        _ = new PostgresSecretRotationCreation(name, project, Environment, SourcePath, ConnectionId,
                            2, parameters, new(UsernameKey, PasswordKey), new(facts.DefaultHours, facts.DefaultMinutes));
                    break;
                case InfisicalRotationProfile.MysqlCredentials:
                    using (var parameters = new MySqlRotationParameters(Username1, Username2, rotationStatement: statement))
                    using (var updated = new MySqlRotationParameters(UpdatedUsername1, UpdatedUsername2, rotationStatement: updatedStatement))
                        _ = new MySqlSecretRotationCreation(name, project, Environment, SourcePath, ConnectionId,
                            2, parameters, new(UsernameKey, PasswordKey), new(facts.DefaultHours, facts.DefaultMinutes));
                    break;
                default:
                    using (var parameters = new MsSqlRotationParameters(Username1, Username2, rotationStatement: statement))
                    using (var updated = new MsSqlRotationParameters(UpdatedUsername1, UpdatedUsername2, rotationStatement: updatedStatement))
                        _ = new MsSqlSecretRotationCreation(name, project, Environment, SourcePath, ConnectionId,
                            2, parameters, new(UsernameKey, PasswordKey), new(facts.DefaultHours, facts.DefaultMinutes));
                    break;
            }
            CreationDefaults = new(name, ConnectionId, Environment, SourcePath, Username1, Username2,
                UsernameKey, PasswordKey, 2, facts.DefaultHours, facts.DefaultMinutes, facts.DefaultEnabled,
                facts.DefaultHasDescription, facts.DefaultDescription, null);
            ExpectedPatchConfiguration = ExpectedPatch(definition.Key.Variant);
        }

        private DatabaseConfiguration ExpectedPatch(string v)
        {
            bool nested = v.Contains("RotationParameters.", StringComparison.Ordinal) ||
                v.Contains("RotationPasswordRequirements.", StringComparison.Ordinal) ||
                v == "passwordRequirements.fractional-number" || v.EndsWith("parameters.value", StringComparison.Ordinal);
            bool requirements = !v.EndsWith("passwordRequirements.omitted", StringComparison.Ordinal);
            bool hasStatement = !v.EndsWith("rotationStatement.omitted", StringComparison.Ordinal);
            if (hasStatement) patchStatement = (nested ? updatedStatement : statement).Copy();
            return CreationDefaults with
            {
                Name = v.EndsWith("name.value", StringComparison.Ordinal) ? name + "-updated" : name,
                Username1 = nested ? UpdatedUsername1 : Username1,
                Username2 = nested ? UpdatedUsername2 : Username2,
                UsernameKey = v.EndsWith("secretsMapping.value", StringComparison.Ordinal) ? UpdatedUsernameKey : UsernameKey,
                PasswordKey = v.EndsWith("secretsMapping.value", StringComparison.Ordinal) ? UpdatedPasswordKey : PasswordKey,
                Interval = v == "rotationInterval.fractional-number" ? 2.5 :
                    v.EndsWith("rotationInterval.value", StringComparison.Ordinal) ? 3 : 2,
                Hours = v.EndsWith("rotateAtUtc.omitted", StringComparison.Ordinal) ? facts.DefaultHours :
                    v == "rotateAtUtc.fractional-number" ? 2.5 : v.EndsWith("rotateAtUtc.value", StringComparison.Ordinal) ? 4 : 2,
                Minutes = v.EndsWith("rotateAtUtc.omitted", StringComparison.Ordinal) ? facts.DefaultMinutes :
                    v == "rotateAtUtc.fractional-number" ? 3.5 : v.EndsWith("rotateAtUtc.value", StringComparison.Ordinal) ? 5 : 3,
                Enabled = v.EndsWith("isAutoRotationEnabled.omitted", StringComparison.Ordinal) ? facts.DefaultEnabled :
                    v.EndsWith("isAutoRotationEnabled.true", StringComparison.Ordinal),
                HasDescription = v.EndsWith("description.omitted", StringComparison.Ordinal) ? facts.DefaultHasDescription : true,
                Description = v.EndsWith("description.omitted", StringComparison.Ordinal) ? facts.DefaultDescription :
                    v == "description.null" ? null : v.EndsWith("description.value", StringComparison.Ordinal) ? name + "-updated" : name,
                PasswordRequirements = requirements ? new(v == "passwordRequirements.fractional-number" ? 24.5 : 24,
                    2, 2, 2, 2, v.EndsWith("allowedSymbols.value", StringComparison.Ordinal) ? "!@" : null) : null
            };
        }

        public async ValueTask<DatabaseCatalogMeasurement> ObserveCatalogAsync(bool options, CancellationToken token)
        {
            using var selected = await SelectedToken(NativeIdentityRole.Observer, token);
            CatalogFacts measured = await channel.PostAsync<CatalogFacts>("database/catalog", writer =>
            {
                Owned(writer);
                writer.WriteBoolean("options", options);
                writer.WriteString("observerToken", selected.Material.Reveal());
            }, token);
            Require(measured.OwnershipNonce == ownership && measured.OrganizationId == organization &&
                measured.ProjectId == project && measured.OptionsCatalog == options &&
                measured.Rows is not null && measured.Options is not null &&
                measured.Rows.Length <= 4096 && measured.Options.Length <= 4096 &&
                measured.Rows.All(r => Text(r.Id) && Text(r.Type)) &&
                measured.Rows.Select(r => r.Id).Distinct(StringComparer.Ordinal).Count() == measured.Rows.Length &&
                measured.Options.All(o => Text(o.Type) && Text(o.UsernameKey) && Text(o.PasswordKey) &&
                    o.UsernameKey != o.PasswordKey && Statement(o.CreateStatement) && Statement(o.RotationStatement)) &&
                measured.Options.Select(o => o.Type).Distinct(StringComparer.Ordinal).Count() == measured.Options.Length &&
                (options ? measured.Rows.Length == 0 : measured.Options.Length == 0));
            var owned = new List<DatabaseCatalogOption>();
            try
            {
                foreach (OptionFacts option in measured.Options)
                {
                    using var create = SecretMaterial.FromText(option.CreateStatement);
                    using var rotate = SecretMaterial.FromText(option.RotationStatement);
                    owned.Add(new(option.Type, option.UsernameKey, option.PasswordKey, create.Copy(), rotate.Copy()));
                }
                return new(measured.Rows.Select(r => new DatabaseCatalogRow(r.Id, r.Type)).ToArray(), owned);
            }
            catch { foreach (var option in owned) option.Dispose(); throw; }
        }

        public ValueTask<DatabaseAuthenticationMeasurement> MeasureAuthorityAsync(CancellationToken token) =>
            MeasureAsync("database/authority", null, null, null, token);

        public ValueTask<DatabaseAuthenticationMeasurement> AuthenticateAsync(SecretMaterial username,
            SecretMaterial password, CancellationToken token) =>
            MeasureAsync("database/authenticate", username, password, null, token);

        private async ValueTask<DatabaseAuthenticationMeasurement> MeasureAsync(string route, SecretMaterial? username,
            SecretMaterial? password, string? subscription, CancellationToken token)
        {
            using var user = username?.Copy();
            using var pass = password?.Copy();
            using var runtime = await SelectedToken(NativeIdentityRole.Runtime, token);
            using var denied = await SelectedToken(NativeIdentityRole.Denied, token);
            DateTimeOffset started = DateTimeOffset.UtcNow;
            AuthenticationFacts measured = await channel.PostAsync<AuthenticationFacts>(route, writer =>
            {
                Owned(writer);
                Coordinate(writer);
                writer.WriteString("subscriptionNonce", subscription);
                writer.WriteString("username", user?.Reveal());
                writer.WriteString("password", pass?.Reveal());
                writer.WriteString("runtimeToken", runtime.Material.Reveal());
                writer.WriteString("deniedToken", denied.Material.Reveal());
            }, token);
            Require(measured.OwnershipNonce == ownership && measured.SubscriptionNonce == subscription &&
                measured.Profile == profile && measured.Host == facts.Host && measured.Port == facts.Port &&
                measured.Database == facts.Database && measured.ConnectionId == ConnectionId &&
                Enum.IsDefined(measured.Selected) && Enum.IsDefined(measured.Denied) &&
                Actions(measured.AllowedActions, allowEmpty: true) && Actions(measured.DeniedActions, allowEmpty: true) &&
                measured.ObservedAt >= started.AddSeconds(-30) && measured.ObservedAt <= DateTimeOffset.UtcNow.AddSeconds(30));
            return new(BackendCoordinate, measured.Selected, measured.Denied,
                measured.AllowedActions, measured.DeniedActions, measured.ObservedAt);
        }

        private void Coordinate(Utf8JsonWriter writer)
        {
            writer.WriteString("host", facts.Host);
            writer.WriteNumber("port", facts.Port);
            writer.WriteString("database", facts.Database);
            writer.WriteString("connectionId", ConnectionId);
        }

        public async ValueTask<IDatabaseRejectionSubscription> SubscribeRejectionAsync(SecretMaterial username,
            SecretMaterial password, CancellationToken token)
        {
            var subscription = new Subscription(this, channel, Guid.NewGuid().ToString("N"), token);
            try
            {
                using var user = username.Copy();
                using var pass = password.Copy();
                RegistrationFacts armed = await channel.PostAsync<RegistrationFacts>("database/arm", writer =>
                {
                    Owned(writer);
                    Coordinate(writer);
                    writer.WriteString("subscriptionNonce", subscription.Nonce);
                    writer.WriteString("username", user.Reveal());
                    writer.WriteString("password", pass.Reveal());
                }, token);
                Require(armed.OwnershipNonce == ownership && armed.SubscriptionNonce == subscription.Nonce &&
                    armed.RemainingRegistrations == 1);
                subscription.Start(user, pass);
                return subscription;
            }
            catch { await subscription.DisposeAsync(); throw; }
        }

        public async ValueTask CleanupAsync(CancellationToken token)
        {
            using var selected = await SelectedToken(NativeIdentityRole.Setup, token);
            CleanupFacts measured = await channel.PostAsync<CleanupFacts>("database/release", writer =>
            {
                Owned(writer);
                writer.WriteString("setupToken", selected.Material.Reveal());
            }, token);
            ValidateCleanup(measured);
        }

        public async ValueTask<DatabaseCleanupMeasurement> ObserveCleanupAsync(CancellationToken token)
        {
            using var selected = await SelectedToken(NativeIdentityRole.Observer, token);
            CleanupFacts measured = await channel.PostAsync<CleanupFacts>("database/remaining", writer =>
            {
                Owned(writer);
                writer.WriteString("observerToken", selected.Material.Reveal());
            }, token);
            ValidateCleanup(measured);
            return new(measured.RemainingAccounts, measured.RemainingMappings, measured.RemainingRotations);
        }

        private void ValidateCleanup(CleanupFacts measured) =>
            Require(measured.OwnershipNonce == ownership && measured.OrganizationId == organization &&
                measured.ProjectId == project && measured.OwnedName == name &&
                measured.RemainingAccounts == 0 && measured.RemainingMappings == 0 &&
                measured.RemainingRotations == 0 && measured.RemainingConnections == 0 &&
                measured.RemainingFolders == 0 && measured.RemainingLeases == 0 &&
                measured.RemainingRegistrations == 0, "cleanup-incomplete");

        private async ValueTask<InfisicalAccessToken> SelectedToken(NativeIdentityRole role, CancellationToken token)
        {
            var selected = await environment.Tokens(role).GetTokenAsync(token);
            Require(selected.IsSuccess, "missing-input");
            return selected.Value;
        }

        public ValueTask DisposeAsync()
        {
            statement?.Dispose();
            updatedStatement?.Dispose();
            patchStatement?.Dispose();
            facts = null!;
            return ValueTask.CompletedTask;
        }
        public override string ToString() => "[OwnedDatabaseFixture]";

        private sealed class Subscription(Fixture owner, InfisicalLifecycleObservers channel, string nonce,
            CancellationToken token) : IDatabaseRejectionSubscription
        {
            private readonly CancellationTokenSource cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            public string Nonce => nonce;
            private Task<DatabaseAuthenticationMeasurement>? rejected;
            public Task<DatabaseAuthenticationMeasurement> Rejected => rejected!;
            internal void Start(SecretMaterial username, SecretMaterial password) =>
                rejected = ObserveAsync(username, password);
            private async Task<DatabaseAuthenticationMeasurement> ObserveAsync(SecretMaterial username, SecretMaterial password)
            {
                var result = await owner.MeasureAsync("database/rejected", username, password, nonce, cancellation.Token);
                Require(result.Selected == DatabaseAuthentication.Rejected);
                return result;
            }
            public async ValueTask DisposeAsync()
            {
                await cancellation.CancelAsync();
                try
                {
                    if (rejected is not null)
                    {
                        try { await rejected; }
                        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
                    }
                }
                finally
                {
                    try
                    {
                        RegistrationFacts remaining = await channel.PostAsync<RegistrationFacts>("database/disarm", writer =>
                        {
                            owner.Owned(writer);
                            writer.WriteString("subscriptionNonce", nonce);
                        }, CancellationToken.None);
                        Require(remaining.OwnershipNonce == owner.ownership && remaining.SubscriptionNonce == nonce &&
                            remaining.RemainingRegistrations == 0, "cleanup-incomplete");
                    }
                    finally { cancellation.Dispose(); }
                }
            }
        }
    }

    private static bool Text(string? value) => !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 16384 && !value.Any(char.IsControl);
    private static bool Statement(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 16384;
    private static bool Actions(string[]? actions, bool allowEmpty = false) => actions is { Length: <= 128 } &&
        (allowEmpty || actions.Length > 0) &&
        actions.All(Text) && actions.Distinct(StringComparer.Ordinal).Count() == actions.Length;

    private sealed record ClaimFacts(string OwnershipNonce, int RemainingLeases)
    {
        public override string ToString() => "[DatabaseClaimFacts]";
    }
    private sealed record FixtureFacts(string OwnershipNonce, string OrganizationId, string ProjectId, string OwnedName,
        InfisicalRotationProfile Profile, string Environment, string SourcePath, string DestinationEnvironment,
        string DestinationPath, string ConnectionId, string Host, int Port, string Database,
        string RotationStatement, string UpdatedRotationStatement, string[] AllowedActions, string[] DeniedActions,
        string PrimaryShapeRevision, double DefaultHours, double DefaultMinutes, bool DefaultEnabled,
        bool DefaultHasDescription, string? DefaultDescription, bool? DefaultDeleteSecrets, bool? DefaultRevokeCredentials)
    {
        public override string ToString() => "[DatabaseFixtureFacts]";
    }
    private sealed record RowFacts(string Id, string Type)
    {
        public override string ToString() => "[DatabaseCatalogRowFacts]";
    }
    private sealed record OptionFacts(string Type, string UsernameKey, string PasswordKey,
        string CreateStatement, string RotationStatement)
    {
        public override string ToString() => "[DatabaseCatalogOptionFacts]";
    }
    private sealed record CatalogFacts(string OwnershipNonce, string OrganizationId, string ProjectId,
        bool OptionsCatalog, RowFacts[] Rows, OptionFacts[] Options)
    {
        public override string ToString() => "[DatabaseCatalogFacts]";
    }
    private sealed record AuthenticationFacts(string OwnershipNonce, string? SubscriptionNonce,
        InfisicalRotationProfile Profile, string Host, int Port, string Database, string ConnectionId,
        DatabaseAuthentication Selected, DatabaseAuthentication Denied, string[] AllowedActions,
        string[] DeniedActions, DateTimeOffset ObservedAt)
    {
        public override string ToString() => "[DatabaseAuthenticationFacts]";
    }
    private sealed record RegistrationFacts(string OwnershipNonce, string SubscriptionNonce, int RemainingRegistrations)
    {
        public override string ToString() => "[DatabaseRegistrationFacts]";
    }
    private sealed record CleanupFacts(string OwnershipNonce, string OrganizationId, string ProjectId, string OwnedName,
        int RemainingAccounts, int RemainingMappings, int RemainingRotations, int RemainingConnections,
        int RemainingFolders, int RemainingLeases, int RemainingRegistrations)
    {
        public override string ToString() => "[DatabaseCleanupFacts]";
    }
}
