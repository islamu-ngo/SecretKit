using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalSqlRotationOwnerTests
{
    private static readonly JsonSerializerOptions ServiceJson = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new Uri("https://sql-owner.invalid/owned/"), "fixture-token", "sql-owner", 30);

    private static ValidationPoliciesEffects.RotationValidationInput Input(InfisicalRotationProfile profile) =>
        new("original-organization", "borrowed-connection", "database.invalid",
            profile == InfisicalRotationProfile.MysqlCredentials ? 3306 : 1433,
            "original-database", 60, ["select"], ["write"], profile);

    private static InfisicalRotationValidationAccounts Factory(SqlService service) =>
        new(new InfisicalLifecycleObservers(Settings, service), service);

    private static async Task<string?> Failure(Func<Task> action)
    {
        try { await action(); return null; }
        catch (NativeCaseFailureException error) { return error.Message; }
    }

    private static async Task PreservedForeignResources(SqlService service)
    {
        await Assert.That(service.Owners["existing-role"]).IsEqualTo("foreign-nonce");
        await Assert.That(service.MysqlRows.Contains(service.ForeignMysql)).IsTrue();
        await Assert.That(service.Logins.Contains(service.ForeignLogin)).IsTrue();
        await Assert.That(service.Users.Contains(service.ForeignUser)).IsTrue();
        await Assert.That(service.ConnectionRetained).IsTrue();
    }

    private static async Task OriginalScope(SqlService service)
    {
        await Assert.That(service.Claim is not null && service.Release is not null && service.Remaining is not null).IsTrue();
        await Assert.That(SameTarget(service.Claim!, service.Release!)).IsTrue();
        await Assert.That(SameTarget(service.Claim!, service.Remaining!)).IsTrue();
        await Assert.That(service.FinalCatalogAttempted).IsTrue();
        foreach (var observation in service.Observations)
        {
            await Assert.That(observation.Coordinate).IsEqualTo(service.Coordinate);
            await Assert.That(observation.RequestedUsernames.SequenceEqual(service.Names)).IsTrue();
        }
        await PreservedForeignResources(service);
    }

    private static async Task Clean(SqlService service)
    {
        await OriginalScope(service);
        foreach (string name in service.Names)
        {
            await Assert.That(service.Owners.ContainsKey(name)).IsFalse();
            await Assert.That(service.MysqlRows.Any(row => row.Username == name)).IsFalse();
            await Assert.That(service.Logins.Any(row => row.Name == name)).IsFalse();
            await Assert.That(service.Users.Any(row => row.Name == name)).IsFalse();
        }
        await Assert.That(service.Observations.Last().Mysql?.Accounts.Length ??
            service.Observations.Last().Mssql!.ServerPrincipals.Length).IsEqualTo(0);
        if (service.Profile == InfisicalRotationProfile.MssqlCredentials)
            await Assert.That(service.Observations.Last().Mssql!.DatabasePrincipals.Length).IsEqualTo(0);
    }

    private static bool SameTarget(JsonObject left, JsonObject right) =>
        new[] { "ownershipNonce", "organizationId", "projectId", "connectionId", "coordinate", "username1", "username2" }
            .All(field => JsonNode.DeepEquals(left[field], right[field]));

    // Owner transport and catalog share a database, not a response factory. Each
    // principal table evolves separately from the nonce ownership ledger.
    private sealed class SqlService : HttpMessageHandler, IInfisicalRotationIdentityCatalogObserver
    {
        internal InfisicalRotationProfile Profile { get; }
        internal string? BeforeFault { get; init; }
        internal string? PrincipalFault { get; init; }
        internal string? ClaimFault { get; init; }
        internal string? CleanupFault { get; init; }
        internal string? Drift { get; init; }
        internal MysqlPasswordPolicyFacts? InitialPolicy { get; init; }
        internal JsonObject? Claim { get; private set; }
        internal JsonObject? Release { get; private set; }
        internal JsonObject? Remaining { get; private set; }
        internal RotationBackendCoordinate? Coordinate { get; private set; }
        internal string[] Names { get; private set; } = [];
        internal bool FinalCatalogAttempted { get; private set; }
        internal bool ConnectionRetained { get; } = true;
        internal Dictionary<string, string> Owners { get; } = new(StringComparer.Ordinal)
        {
            ["existing-role"] = "foreign-nonce"
        };
        internal MysqlRotationAccountFacts ForeignMysql { get; } = new("existing-role", "private-host", "foreign-plugin");
        internal MssqlRotationLoginFacts ForeignLogin { get; } = new("existing-role", [91], "WINDOWS_LOGIN", true, true, false);
        internal MssqlRotationUserFacts ForeignUser { get; } = new("existing-role", [92], "WINDOWS_USER", "WINDOWS");
        internal List<MysqlRotationAccountFacts> MysqlRows { get; } = [];
        internal List<MssqlRotationLoginFacts> Logins { get; } = [];
        internal List<MssqlRotationUserFacts> Users { get; } = [];
        internal List<RotationIdentityCatalogFacts> Observations { get; } = [];
        internal List<MysqlPasswordPolicyFacts> PolicySnapshots { get; } = [];
        internal Dictionary<string, string> CommittedOwners { get; private set; } = [];
        internal MysqlRotationAccountFacts[] CommittedMysql { get; private set; } = [];
        internal MssqlRotationLoginFacts[] CommittedLogins { get; private set; } = [];
        internal MssqlRotationUserFacts[] CommittedUsers { get; private set; } = [];
        internal MysqlPasswordPolicyFacts Policy { get; private set; } = WeakPolicy();
        private bool allHostsComplete = true;
        private bool serverComplete = true;
        private bool databaseComplete = true;

        internal SqlService(InfisicalRotationProfile profile)
        {
            Profile = profile;
            MysqlRows.Add(ForeignMysql);
            Logins.Add(ForeignLogin);
            Users.Add(ForeignUser);
        }

        public override string ToString() => "[SqlOwnerService]";

        internal static MysqlPasswordPolicyFacts WeakPolicy() =>
            new(true, ["validate_password"], [], 0, 8, false, 1, 1, 1, "", null);

        public async ValueTask<RotationIdentityCatalogFacts> InspectIdentityCatalogAsync(
            RotationBackendCoordinate coordinate, IReadOnlyList<string> usernames, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            await Assert.That(coordinate.Profile).IsEqualTo(Profile);
            await Assert.That(coordinate).IsEqualTo(new RotationBackendCoordinate(Profile,
                Input(Profile).Host, Input(Profile).Port, Input(Profile).Database, usernames[0]));
            if (Coordinate is null)
            {
                Coordinate = coordinate;
                Names = usernames.ToArray();
                SeedPreflightFault();
            }
            else
            {
                await Assert.That(coordinate).IsEqualTo(Coordinate);
                await Assert.That(usernames.SequenceEqual(Names)).IsTrue();
            }
            if (Release is not null)
            {
                FinalCatalogAttempted = true;
                if (CleanupFault == "incomplete-server") serverComplete = false;
                if (CleanupFault == "incomplete-database") databaseComplete = false;
                if (CleanupFault == "incomplete-hosts") allHostsComplete = false;
                if (CleanupFault == "lost-final-catalog")
                    throw new NativeCaseFailureException("observer-unavailable");
                if (Drift == "final-length") Policy = Policy with { MinimumLength = 9 };
                if (Drift == "final-strong") Policy = Policy with { Policy = 2 };
                if (Drift == "final-mutable-plugin") Policy.ActiveValidationPlugins[0] = "unknown-validator";
                if (Drift == "final-mutable-component")
                    Policy.InstalledValidationComponents[0] = "file://unknown-validator";
            }
            // Filtering is by requested names across ALL hosts and BOTH SQL catalogs.
            // Completeness is independent of whether the filtered arrays are empty.
            var facts = new RotationIdentityCatalogFacts(coordinate, usernames.ToArray(),
                Profile == InfisicalRotationProfile.MysqlCredentials
                    ? new(Input(Profile).Database, allHostsComplete,
                        MysqlRows.Where(row => usernames.Contains(row.Username)).ToArray(), Policy) : null,
                Profile == InfisicalRotationProfile.MssqlCredentials
                    ? new(Input(Profile).Database, serverComplete, databaseComplete,
                        Logins.Where(row => usernames.Contains(row.Name)).ToArray(),
                        Users.Where(row => usernames.Contains(row.Name)).ToArray()) : null);
            Observations.Add(facts);
            if (facts.Mysql is not null)
                PolicySnapshots.Add(Policy with
                {
                    ActiveValidationPlugins = [.. Policy.ActiveValidationPlugins],
                    InstalledValidationComponents = [.. Policy.InstalledValidationComponents]
                });
            return facts;
        }

        private void SeedPreflightFault()
        {
            if (InitialPolicy is { } supplied) Policy = supplied;
            switch (BeforeFault)
            {
                case "other-host": MysqlRows.Add(new(Names[0], "other-host", "caching_sha2_password")); break;
                case "strong-policy": Policy = Policy with { Policy = 2 }; break;
                case "unknown-policy": Policy.ActiveValidationPlugins[0] = "unknown-validator"; break;
                case "incomplete-policy": Policy = Policy with { IsComplete = false }; break;
                case "incomplete-hosts": allHostsComplete = false; break;
                case "server-sql": Logins.Add(new(Names[0], [40], "SQL_LOGIN", false, false, false)); break;
                case "server-windows": Logins.Add(new(Names[0], [40], "WINDOWS_LOGIN", null, null, false)); break;
                case "database-sql": Users.Add(new(Names[0], [41], "SQL_USER", "INSTANCE")); break;
                case "database-external": Users.Add(new(Names[0], [41], "EXTERNAL_USER", "EXTERNAL")); break;
                case "incomplete-server": serverComplete = false; break;
                case "incomplete-database": databaseComplete = false; break;
            }
            if (BeforeFault is "other-host" or "server-sql" or "server-windows" or "database-sql" or "database-external")
                Owners.Add(Names[0], "collision-owner");
            if (Drift is "post-mutable-component" or "final-mutable-component")
                Policy = new(true, [], ["file://component_validate_password"], 0, 8, false, 1, 1, 1, "", 0);
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            await Assert.That(request.Method).IsEqualTo(HttpMethod.Post);
            await Assert.That(request.RequestUri!.Scheme).IsEqualTo("https");
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo(Settings.Token);
            var body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            await Assert.That(body["schemaVersion"]!.GetValue<int>()).IsEqualTo(1);
            await Assert.That(Regex.IsMatch(body["nonce"]!.GetValue<string>(), "^[0-9a-f]{32}$")).IsTrue();
            await Assert.That(body["organizationId"]!.GetValue<string>()).IsEqualTo(Input(Profile).OrganizationId);
            await Assert.That(body["projectId"]!.GetValue<string>()).IsEqualTo("original-project");
            await Assert.That(body["connectionId"]!.GetValue<string>()).IsEqualTo(Input(Profile).ConnectionId);
            await Assert.That(body["coordinate"]!.Deserialize<RotationBackendCoordinate>(ServiceJson)).IsEqualTo(Coordinate);
            await Assert.That(body["username1"]!.GetValue<string>()).IsEqualTo(Names[0]);
            await Assert.That(body["username2"]!.GetValue<string>()).IsEqualTo(Names[1]);
            string ownership = body["ownershipNonce"]!.GetValue<string>();
            await Assert.That(Regex.IsMatch(ownership, "^[0-9a-f]{32}$")).IsTrue();
            await Assert.That(Names[0]).IsEqualTo("sk_rv_" + ownership[..16] + "_a");
            await Assert.That(Names[1]).IsEqualTo("sk_rv_" + ownership[..16] + "_b");
            switch (request.RequestUri.AbsolutePath)
            {
                case "/owned/rotation-accounts/claim":
                    await Assert.That(Observations.Count == 1 && Claim is null).IsTrue();
                    Claim = body.DeepClone().AsObject();
                    Commit(ownership);
                    CommittedOwners = new(Owners, StringComparer.Ordinal);
                    CommittedMysql = MysqlRows.ToArray();
                    CommittedLogins = Logins.ToArray();
                    CommittedUsers = Users.ToArray();
                    if (ClaimFault == "lost") throw new HttpRequestException("fixture-response-lost");
                    if (ClaimFault == "http-error") return new(HttpStatusCode.ServiceUnavailable);
                    if (ClaimFault == "malformed")
                        return new(HttpStatusCode.OK) { Content = new StringContent("{") };
                    JsonObject claimed = Inventory(body);
                    MutateClaim(claimed["facts"]!.AsObject());
                    return Reply(claimed);
                case "/owned/rotation-accounts/release":
                    Release = body.DeepClone().AsObject();
                    await Assert.That(SameTarget(Claim!, body)).IsTrue();
                    if (CleanupFault is not ("ack-only" or "release-refused"))
                        RemoveOwned(ownership);
                    if (Drift is "post-length" or "post-strong-restored" or "post-mutable-restored")
                        Policy = WeakPolicy();
                    if (CleanupFault == "release-lost") throw new HttpRequestException("fixture-release-lost");
                    if (CleanupFault == "release-malformed")
                        return new(HttpStatusCode.OK) { Content = new StringContent("{") };
                    if (CleanupFault == "release-refused") return new(HttpStatusCode.ServiceUnavailable);
                    return Reply(Inventory(body));
                case "/owned/rotation-accounts/remaining":
                    Remaining = body.DeepClone().AsObject();
                    await Assert.That(SameTarget(Claim!, body)).IsTrue();
                    return Reply(Inventory(body));
                default: throw new InvalidOperationException("unexpected-owner-route");
            }
        }

        private void Commit(string nonce)
        {
            foreach (string name in Names) Owners.Add(name, nonce);
            if (Profile == InfisicalRotationProfile.MysqlCredentials)
            {
                MysqlRows.Add(new(Names[0], "%", "caching_sha2_password"));
                MysqlRows.Add(new(Names[1], "%", "mysql_native_password"));
                if (PrincipalFault == "wrong-host") MysqlRows[^2] = MysqlRows[^2] with { Host = "localhost" };
                if (PrincipalFault == "wrong-plugin") MysqlRows[^1] = MysqlRows[^1] with { AuthenticationPlugin = "auth_socket" };
            }
            else
            {
                Logins.Add(new(Names[0], [1, 2, 3], "SQL_LOGIN", false, false, false));
                Logins.Add(new(Names[1], [4, 5, 6], "SQL_LOGIN", false, false, false));
                // Database SIDs are separately allocated, never copied by reference.
                Users.Add(new(Names[0], [1, 2, 3], "SQL_USER", "INSTANCE"));
                Users.Add(new(Names[1], [4, 5, 6], "SQL_USER", "INSTANCE"));
                switch (PrincipalFault)
                {
                    case "login-type": Logins[^2] = Logins[^2] with { TypeDescription = "WINDOWS_LOGIN" }; break;
                    case "user-type": Users[^2] = Users[^2] with { TypeDescription = "WINDOWS_USER" }; break;
                    case "contained-user": Users[^2] = Users[^2] with { AuthenticationTypeDescription = "DATABASE" }; break;
                    case "crossmapped":
                        Users[^2] = Users[^2] with { Sid = [4, 5, 6] };
                        Users[^1] = Users[^1] with { Sid = [1, 2, 3] };
                        break;
                    case "duplicate-sid":
                        Logins[^1] = Logins[^1] with { Sid = [1, 2, 3] };
                        Users[^1] = Users[^1] with { Sid = [1, 2, 3] };
                        break;
                    case "policy-enabled": Logins[^2] = Logins[^2] with { IsPolicyChecked = true }; break;
                    case "policy-unknown": Logins[^2] = Logins[^2] with { IsPolicyChecked = null }; break;
                    case "expiry-enabled": Logins[^1] = Logins[^1] with { IsExpirationChecked = true }; break;
                    case "expiry-unknown": Logins[^1] = Logins[^1] with { IsExpirationChecked = null }; break;
                    case "disabled": Logins[^1] = Logins[^1] with { IsDisabled = true }; break;
                    case "empty-sid":
                        Logins[^2] = Logins[^2] with { Sid = [] };
                        Users[^2] = Users[^2] with { Sid = [] };
                        break;
                }
            }
            if (Drift == "post-length") Policy = Policy with { MinimumLength = 9 };
            if (Drift is "post-strong-restored" or "post-strong-persistent") Policy = Policy with { Policy = 2 };
            if (Drift is "post-mutable-restored" or "post-mutable-persistent")
                Policy.ActiveValidationPlugins[0] = "unknown-validator";
            if (Drift == "post-mutable-component")
                Policy.InstalledValidationComponents[0] = "file://unknown-validator";
        }

        private void RemoveOwned(string nonce)
        {
            foreach (string name in Names)
            {
                if (!Owners.TryGetValue(name, out string? owner) || owner != nonce) continue;
                Owners.Remove(name);
                MysqlRows.RemoveAll(row => row.Username == name);
                if (CleanupFault != "surviving-server") Logins.RemoveAll(row => row.Name == name);
                if (CleanupFault != "surviving-database") Users.RemoveAll(row => row.Name == name);
            }
        }

        private void MutateClaim(JsonObject facts)
        {
            switch (ClaimFault)
            {
                case "profile": facts["coordinate"]!["profile"] = "PostgresCredentials"; break;
                case "scope":
                    facts["ownershipNonce"] = "foreign-nonce";
                    facts["organizationId"] = "foreign-organization";
                    facts["projectId"] = "foreign-project";
                    facts["connectionId"] = "foreign-connection";
                    facts["coordinate"]!["database"] = "foreign-database";
                    facts["ownedUsernames"] = new JsonArray("existing-role", "foreign-account");
                    break;
                case "nonce": facts["ownershipNonce"] = "foreign-nonce"; break;
                case "names": facts["ownedUsernames"] = new JsonArray(Names[1], Names[0]); break;
                case "missing-coordinate": facts.Remove("coordinate"); break;
                case "missing-owned": facts.Remove("ownedUsernames"); break;
                case "missing-unowned": facts.Remove("unownedUsernames"); break;
            }
        }

        private JsonObject Inventory(JsonObject body)
        {
            string nonce = body["ownershipNonce"]!.GetValue<string>();
            string[] owned = Names.Where(name => Owners.TryGetValue(name, out string? value) && value == nonce).ToArray();
            // Ack-only lies in the owner channel, but cannot erase any table rows.
            if (CleanupFault == "ack-only" && Release is not null) owned = [];
            var facts = new InfisicalRotationValidationAccounts.Facts(nonce, Input(Profile).OrganizationId,
                "original-project", Input(Profile).ConnectionId, Coordinate!, owned, [], owned.Length, ConnectionRetained);
            return new()
            {
                ["schemaVersion"] = 1,
                ["nonce"] = body["nonce"]!.DeepClone(),
                ["observerIdentity"] = Settings.Identity,
                ["observedAt"] = DateTimeOffset.UtcNow,
                ["facts"] = JsonSerializer.SerializeToNode(facts, ServiceJson)
            };
        }

        private static HttpResponseMessage Reply(JsonObject body) =>
            new(HttpStatusCode.OK) { Content = new StringContent(body.ToJsonString()) };
    }

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials)]
    [Arguments(InfisicalRotationProfile.MssqlCredentials)]
    public async Task ClaimAndReleaseUseOriginalProfileAndRemoveOnlyOwnedPrincipals(InfisicalRotationProfile profile)
    {
        using var service = new SqlService(profile);
        var accounts = await Factory(service).CreateAsync("original-project", Input(profile), CancellationToken.None);
        await Assert.That(accounts.Coordinate.Profile).IsEqualTo(profile);
        await Assert.That(accounts.Username1).IsEqualTo(service.Names[0]);
        await Assert.That(accounts.Username2).IsEqualTo(service.Names[1]);
        string nonce = service.Claim!["ownershipNonce"]!.GetValue<string>();
        foreach (string name in service.Names)
            await Assert.That(service.Owners[name]).IsEqualTo(nonce);
        if (profile == InfisicalRotationProfile.MysqlCredentials)
        {
            foreach (string name in service.Names)
                await Assert.That(service.MysqlRows.Single(row => row.Username == name).Host).IsEqualTo("%");
        }
        else
        {
            foreach (string name in service.Names)
            {
                var login = service.Logins.Single(row => row.Name == name);
                var user = service.Users.Single(row => row.Name == name);
                await Assert.That(ReferenceEquals(login.Sid, user.Sid)).IsFalse();
                await Assert.That(login.Sid.AsSpan().SequenceEqual(user.Sid)).IsTrue();
                byte[] expectedSid = name == service.Names[0] ? [1, 2, 3] : [4, 5, 6];
                await Assert.That(login.Sid.SequenceEqual(expectedSid)).IsTrue();
                await Assert.That(user.Sid.SequenceEqual(expectedSid)).IsTrue();
                await Assert.That(login.TypeDescription).IsEqualTo("SQL_LOGIN");
                await Assert.That(user.AuthenticationTypeDescription).IsEqualTo("INSTANCE");
            }
            await Assert.That(service.Logins[^1].Sid.AsSpan().SequenceEqual(service.Logins[^2].Sid)).IsFalse();
        }
        await accounts.DisposeAsync();
        await Clean(service);
    }

    [Test]
    [Arguments("other-host", "missing-prerequisite")]
    [Arguments("strong-policy", "missing-prerequisite")]
    [Arguments("unknown-policy", "missing-prerequisite")]
    [Arguments("incomplete-policy", "observer-unavailable")]
    [Arguments("incomplete-hosts", "observer-unavailable")]
    public async Task MysqlPreflightRejectsActualCollisionsOrUnmeasuredPolicyWithoutMutations(string fault, string expected)
    {
        using var service = new SqlService(InfisicalRotationProfile.MysqlCredentials) { BeforeFault = fault };
        string? reason = await Failure(async () =>
            await Factory(service).CreateAsync("original-project", Input(service.Profile), CancellationToken.None));
        await Assert.That(reason).IsEqualTo(expected);
        await Assert.That(service.Claim is null && service.Release is null && service.Remaining is null).IsTrue();
        await Assert.That(service.FinalCatalogAttempted).IsFalse();
        var observed = service.Observations.Single().Mysql!;
        await Assert.That(observed.PasswordPolicy.IsComplete).IsEqualTo(fault != "incomplete-policy");
        await Assert.That(fault switch
        {
            "other-host" => observed.AllHostsComplete &&
                observed.Accounts.Single().Host == "other-host" &&
                service.Owners[observed.Accounts.Single().Username] == "collision-owner",
            "strong-policy" => observed.PasswordPolicy.Policy == 2,
            "unknown-policy" => observed.PasswordPolicy.ActiveValidationPlugins.Single() == "unknown-validator",
            "incomplete-policy" => !observed.PasswordPolicy.IsComplete,
            "incomplete-hosts" => !observed.AllHostsComplete && observed.Accounts.Length == 0,
            _ => false
        }).IsTrue();
        await PreservedForeignResources(service);
    }

    [Test]
    [Arguments("server-sql", "missing-prerequisite")]
    [Arguments("server-windows", "missing-prerequisite")]
    [Arguments("database-sql", "missing-prerequisite")]
    [Arguments("database-external", "missing-prerequisite")]
    [Arguments("incomplete-server", "observer-unavailable")]
    [Arguments("incomplete-database", "observer-unavailable")]
    public async Task MssqlPreflightRequiresBothIndependentCatalogsEvenForNonSqlNames(string fault, string expected)
    {
        using var service = new SqlService(InfisicalRotationProfile.MssqlCredentials) { BeforeFault = fault };
        string? reason = await Failure(async () =>
            await Factory(service).CreateAsync("original-project", Input(service.Profile), CancellationToken.None));
        await Assert.That(reason).IsEqualTo(expected);
        await Assert.That(service.Claim is null && service.Release is null && service.Remaining is null).IsTrue();
        var observed = service.Observations.Single().Mssql!;
        if (fault.StartsWith("server-", StringComparison.Ordinal))
        {
            await Assert.That(observed.ServerPrincipals.Single().Name).IsEqualTo(service.Names[0]);
            await Assert.That(observed.ServerPrincipals.Single().TypeDescription)
                .IsEqualTo(fault == "server-sql" ? "SQL_LOGIN" : "WINDOWS_LOGIN");
            await Assert.That(observed.DatabasePrincipals.Length).IsEqualTo(0);
            await Assert.That(service.Owners[service.Names[0]]).IsEqualTo("collision-owner");
        }
        else if (fault.StartsWith("database-", StringComparison.Ordinal))
        {
            await Assert.That(observed.DatabasePrincipals.Single().Name).IsEqualTo(service.Names[0]);
            await Assert.That(observed.DatabasePrincipals.Single().TypeDescription)
                .IsEqualTo(fault == "database-sql" ? "SQL_USER" : "EXTERNAL_USER");
            await Assert.That(observed.ServerPrincipals.Length).IsEqualTo(0);
            await Assert.That(service.Owners[service.Names[0]]).IsEqualTo("collision-owner");
        }
        else
        {
            await Assert.That(observed.ServerPrincipalsComplete).IsEqualTo(fault != "incomplete-server");
            await Assert.That(observed.DatabasePrincipalsComplete).IsEqualTo(fault != "incomplete-database");
            await Assert.That(service.Owners.Keys.SequenceEqual(["existing-role"])).IsTrue();
        }
        await PreservedForeignResources(service);
    }

    [Test]
    [Arguments("wrong-host")]
    [Arguments("wrong-plugin")]
    public async Task MysqlCommittedIdentityMustMatchWildcardHostAndPasswordPlugin(string fault)
    {
        using var service = new SqlService(InfisicalRotationProfile.MysqlCredentials) { PrincipalFault = fault };
        string? reason = await Failure(async () =>
            await Factory(service).CreateAsync("original-project", Input(service.Profile), CancellationToken.None));
        await Assert.That(reason).IsEqualTo("observer-unavailable");
        var committed = service.Observations[1].Mysql!.Accounts;
        await Assert.That(committed.Select(row => row.Username).SequenceEqual(service.Names)).IsTrue();
        await Assert.That(fault == "wrong-host" ? committed[0].Host == "localhost" :
            committed[1].AuthenticationPlugin == "auth_socket").IsTrue();
        await Clean(service);
    }

    [Test]
    [Arguments("login-type")]
    [Arguments("user-type")]
    [Arguments("contained-user")]
    [Arguments("crossmapped")]
    [Arguments("duplicate-sid")]
    [Arguments("policy-enabled")]
    [Arguments("policy-unknown")]
    [Arguments("expiry-enabled")]
    [Arguments("expiry-unknown")]
    [Arguments("disabled")]
    [Arguments("empty-sid")]
    public async Task MssqlCommittedPrincipalsMustBeDistinctMappedEnabledSqlIdentities(string fault)
    {
        using var service = new SqlService(InfisicalRotationProfile.MssqlCredentials) { PrincipalFault = fault };
        string? reason = await Failure(async () =>
            await Factory(service).CreateAsync("original-project", Input(service.Profile), CancellationToken.None));
        await Assert.That(reason).IsEqualTo("observer-unavailable");
        var committed = service.Observations[1].Mssql!;
        var firstLogin = committed.ServerPrincipals[0];
        var secondLogin = committed.ServerPrincipals[1];
        var firstUser = committed.DatabasePrincipals[0];
        await Assert.That(committed.ServerPrincipals.Select(row => row.Name).SequenceEqual(service.Names)).IsTrue();
        await Assert.That(committed.DatabasePrincipals.Select(row => row.Name).SequenceEqual(service.Names)).IsTrue();
        await Assert.That(fault switch
        {
            "login-type" => firstLogin.TypeDescription == "WINDOWS_LOGIN",
            "user-type" => firstUser.TypeDescription == "WINDOWS_USER",
            "contained-user" => firstUser.AuthenticationTypeDescription == "DATABASE",
            "crossmapped" => firstLogin.Sid.AsSpan().SequenceEqual(committed.DatabasePrincipals[1].Sid) &&
                secondLogin.Sid.AsSpan().SequenceEqual(firstUser.Sid) &&
                !firstLogin.Sid.AsSpan().SequenceEqual(firstUser.Sid),
            "duplicate-sid" => firstLogin.Sid.AsSpan().SequenceEqual(secondLogin.Sid) &&
                firstUser.Sid.AsSpan().SequenceEqual(committed.DatabasePrincipals[1].Sid),
            "policy-enabled" => firstLogin.IsPolicyChecked == true,
            "policy-unknown" => firstLogin.IsPolicyChecked is null,
            "expiry-enabled" => secondLogin.IsExpirationChecked == true,
            "expiry-unknown" => secondLogin.IsExpirationChecked is null,
            "disabled" => secondLogin.IsDisabled,
            "empty-sid" => firstLogin.Sid.Length == 0 && firstUser.Sid.Length == 0,
            _ => false
        }).IsTrue();
        await Clean(service);
    }

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials)]
    [Arguments(InfisicalRotationProfile.MssqlCredentials)]
    public async Task CommittedMalformedLostOrSubstitutedClaimAlwaysInspectsOriginalCatalog(
        InfisicalRotationProfile profile)
    {
        foreach (string fault in new[] { "malformed", "lost", "http-error", "profile", "scope", "nonce", "names",
            "missing-coordinate", "missing-owned", "missing-unowned" })
        {
            using var service = new SqlService(profile) { ClaimFault = fault };
            string? reason = await Failure(async () =>
                await Factory(service).CreateAsync("original-project", Input(profile), CancellationToken.None));
            await Assert.That(reason).IsEqualTo("observer-unavailable");
            string nonce = service.Claim!["ownershipNonce"]!.GetValue<string>();
            foreach (string name in service.Names)
            {
                await Assert.That(service.CommittedOwners[name]).IsEqualTo(nonce);
                if (profile == InfisicalRotationProfile.MysqlCredentials)
                    await Assert.That(service.CommittedMysql.Single(row => row.Username == name).Host).IsEqualTo("%");
                else
                {
                    await Assert.That(service.CommittedLogins.Single(row => row.Name == name).TypeDescription).IsEqualTo("SQL_LOGIN");
                    await Assert.That(service.CommittedUsers.Single(row => row.Name == name).AuthenticationTypeDescription)
                        .IsEqualTo("INSTANCE");
                }
            }
            // Invalid owner facts prevent post-claim acceptance, not final inspection.
            await Assert.That(service.Observations.Count).IsEqualTo(2);
            await Clean(service);
        }
    }

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "ack-only")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "incomplete-hosts")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "lost-final-catalog")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "ack-only")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "surviving-server")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "surviving-database")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "incomplete-server")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "incomplete-database")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "lost-final-catalog")]
    public async Task EmptyOwnerAcknowledgementCannotReplaceIndependentFinalCatalogProof(
        InfisicalRotationProfile profile, string fault)
    {
        using var service = new SqlService(profile) { CleanupFault = fault };
        var accounts = await Factory(service).CreateAsync("original-project", Input(profile), CancellationToken.None);
        string? reason = await Failure(async () => await accounts.DisposeAsync());
        await Assert.That(reason).IsEqualTo("cleanup-incomplete");
        await OriginalScope(service);
        if (fault == "ack-only")
        {
            foreach (string name in service.Names)
            {
                await Assert.That(service.Owners[name]).IsEqualTo(service.Claim!["ownershipNonce"]!.GetValue<string>());
                if (profile == InfisicalRotationProfile.MysqlCredentials)
                    await Assert.That(service.MysqlRows.Single(row => row.Username == name).Host).IsEqualTo("%");
                else
                {
                    await Assert.That(service.Logins.Single(row => row.Name == name).TypeDescription).IsEqualTo("SQL_LOGIN");
                    await Assert.That(service.Users.Single(row => row.Name == name).AuthenticationTypeDescription).IsEqualTo("INSTANCE");
                }
            }
        }
        else
        {
            foreach (string name in service.Names)
            {
                await Assert.That(service.Owners.ContainsKey(name)).IsFalse();
                await Assert.That(service.Logins.Any(row => row.Name == name)).IsEqualTo(fault == "surviving-server");
                await Assert.That(service.Users.Any(row => row.Name == name)).IsEqualTo(fault == "surviving-database");
                await Assert.That(service.MysqlRows.Any(row => row.Username == name)).IsFalse();
            }
            if (fault == "incomplete-hosts")
                await Assert.That(service.Observations.Last().Mysql!.AllHostsComplete).IsFalse();
            if (fault == "incomplete-server")
                await Assert.That(service.Observations.Last().Mssql!.ServerPrincipalsComplete).IsFalse();
            if (fault == "incomplete-database")
                await Assert.That(service.Observations.Last().Mssql!.DatabasePrincipalsComplete).IsFalse();
        }
    }

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials)]
    [Arguments(InfisicalRotationProfile.MssqlCredentials)]
    public async Task FailedReleaseResponseStillMeasuresActualFinalCatalog(InfisicalRotationProfile profile)
    {
        foreach (string fault in new[] { "release-lost", "release-malformed", "release-refused" })
        {
            using var service = new SqlService(profile) { CleanupFault = fault };
            var accounts = await Factory(service).CreateAsync("original-project", Input(profile), CancellationToken.None);
            string? reason = await Failure(async () => await accounts.DisposeAsync());
            await Assert.That(reason).IsEqualTo("cleanup-incomplete");
            await OriginalScope(service);
            foreach (string name in service.Names)
            {
                await Assert.That(service.Owners.ContainsKey(name)).IsEqualTo(fault == "release-refused");
                if (profile == InfisicalRotationProfile.MysqlCredentials)
                    await Assert.That(service.MysqlRows.Any(row => row.Username == name)).IsEqualTo(fault == "release-refused");
                else
                {
                    await Assert.That(service.Logins.Any(row => row.Name == name)).IsEqualTo(fault == "release-refused");
                    await Assert.That(service.Users.Any(row => row.Name == name)).IsEqualTo(fault == "release-refused");
                }
            }
        }
    }

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials)]
    [Arguments(InfisicalRotationProfile.MssqlCredentials)]
    public async Task MalformedCommittedClaimWithFailedReleaseStillAttemptsFinalCatalog(
        InfisicalRotationProfile profile)
    {
        using var service = new SqlService(profile) { ClaimFault = "malformed", CleanupFault = "release-refused" };
        string? reason = await Failure(async () =>
            await Factory(service).CreateAsync("original-project", Input(profile), CancellationToken.None));
        await Assert.That(reason).IsEqualTo("cleanup-incomplete");
        await OriginalScope(service);
        foreach (string name in service.Names)
        {
            await Assert.That(service.Owners[name]).IsEqualTo(service.Claim!["ownershipNonce"]!.GetValue<string>());
            if (profile == InfisicalRotationProfile.MysqlCredentials)
                await Assert.That(service.Observations.Last().Mysql!.Accounts.Any(row => row.Username == name)).IsTrue();
            else
            {
                await Assert.That(service.Observations.Last().Mssql!.ServerPrincipals.Any(row => row.Name == name)).IsTrue();
                await Assert.That(service.Observations.Last().Mssql!.DatabasePrincipals.Any(row => row.Name == name)).IsTrue();
            }
        }
    }

    [Test]
    [Arguments("post-length", "observer-unavailable")]
    [Arguments("post-strong-restored", "observer-unavailable")]
    [Arguments("post-mutable-restored", "observer-unavailable")]
    [Arguments("post-strong-persistent", "cleanup-incomplete")]
    [Arguments("post-mutable-persistent", "cleanup-incomplete")]
    [Arguments("post-mutable-component", "cleanup-incomplete")]
    public async Task MysqlPostclaimPolicyDriftCannotRewriteThePinnedPreflight(string drift, string expected)
    {
        using var service = new SqlService(InfisicalRotationProfile.MysqlCredentials) { Drift = drift };
        string? reason = await Failure(async () =>
            await Factory(service).CreateAsync("original-project", Input(service.Profile), CancellationToken.None));
        await Assert.That(reason).IsEqualTo(expected);
        var before = service.Observations[0].Mysql!.PasswordPolicy;
        var after = service.Observations[1].Mysql!.PasswordPolicy;
        if (drift.Contains("mutable", StringComparison.Ordinal))
        {
            // Both observations retain exactly the service's discovery array.
            // The client must not let it rewrite its own historical baseline.
            bool component = drift == "post-mutable-component";
            await Assert.That(component ?
                service.PolicySnapshots[0].InstalledValidationComponents.SequenceEqual(["file://component_validate_password"]) :
                service.PolicySnapshots[0].ActiveValidationPlugins.SequenceEqual(["validate_password"])).IsTrue();
            await Assert.That(component ?
                service.PolicySnapshots[1].InstalledValidationComponents.SequenceEqual(["file://unknown-validator"]) :
                service.PolicySnapshots[1].ActiveValidationPlugins.SequenceEqual(["unknown-validator"])).IsTrue();
            await Assert.That(ReferenceEquals(component ? before.InstalledValidationComponents : before.ActiveValidationPlugins,
                component ? after.InstalledValidationComponents : after.ActiveValidationPlugins)).IsTrue();
            await Assert.That(component ? after.InstalledValidationComponents[0] == "file://unknown-validator" :
                after.ActiveValidationPlugins[0] == "unknown-validator").IsTrue();
        }
        else if (drift == "post-length")
        {
            await Assert.That(before.MinimumLength).IsEqualTo(8);
            await Assert.That(after.MinimumLength).IsEqualTo(9);
            await Assert.That(after.Policy).IsEqualTo(0);
        }
        else
        {
            await Assert.That(before.Policy).IsEqualTo(0);
            await Assert.That(after.Policy).IsEqualTo(2);
        }
        await Clean(service);
    }

    [Test]
    [Arguments("final-length")]
    [Arguments("final-strong")]
    [Arguments("final-mutable-plugin")]
    [Arguments("final-mutable-component")]
    public async Task MysqlFinalPolicyDriftFailsEvenAfterAllOwnedRowsWereRemoved(string drift)
    {
        using var service = new SqlService(InfisicalRotationProfile.MysqlCredentials) { Drift = drift };
        var accounts = await Factory(service).CreateAsync("original-project", Input(service.Profile), CancellationToken.None);
        string? reason = await Failure(async () => await accounts.DisposeAsync());
        await Assert.That(reason).IsEqualTo("cleanup-incomplete");
        await Clean(service);
        var before = service.Observations[0].Mysql!.PasswordPolicy;
        var final = service.Observations.Last().Mysql!.PasswordPolicy;
        if (drift == "final-length")
        {
            await Assert.That(before.MinimumLength).IsEqualTo(8);
            await Assert.That(final.MinimumLength).IsEqualTo(9);
            await Assert.That(final.Policy).IsEqualTo(0);
        }
        else if (drift == "final-strong")
            await Assert.That(final.Policy).IsEqualTo(2);
        else
        {
            bool component = drift == "final-mutable-component";
            await Assert.That(component ?
                service.PolicySnapshots[0].InstalledValidationComponents.SequenceEqual(["file://component_validate_password"]) :
                service.PolicySnapshots[0].ActiveValidationPlugins.SequenceEqual(["validate_password"])).IsTrue();
            await Assert.That(component ?
                service.PolicySnapshots[^1].InstalledValidationComponents.SequenceEqual(["file://unknown-validator"]) :
                service.PolicySnapshots[^1].ActiveValidationPlugins.SequenceEqual(["unknown-validator"])).IsTrue();
            await Assert.That(ReferenceEquals(component ? before.InstalledValidationComponents : before.ActiveValidationPlugins,
                component ? final.InstalledValidationComponents : final.ActiveValidationPlugins)).IsTrue();
            await Assert.That(component ? final.InstalledValidationComponents[0] == "file://unknown-validator" :
                final.ActiveValidationPlugins[0] == "unknown-validator").IsTrue();
        }
    }

    [Test]
    public async Task MalformedClaimCannotHideFinalMysqlPolicyDriftBehindOriginalFailure()
    {
        using var service = new SqlService(InfisicalRotationProfile.MysqlCredentials)
        {
            ClaimFault = "malformed",
            Drift = "final-length"
        };
        string? reason = await Failure(async () =>
            await Factory(service).CreateAsync("original-project", Input(service.Profile), CancellationToken.None));
        await Assert.That(reason).IsEqualTo("cleanup-incomplete");
        await Clean(service);
        await Assert.That(service.Observations.Last().Mysql!.PasswordPolicy.MinimumLength).IsEqualTo(9);
    }

    [Test]
    [Arguments("policy", false)]
    [Arguments("length", false)]
    [Arguments("username", false)]
    [Arguments("mixed-case", false)]
    [Arguments("number", false)]
    [Arguments("special", false)]
    [Arguments("dictionary", false)]
    [Arguments("policy", true)]
    [Arguments("length", true)]
    [Arguments("username", true)]
    [Arguments("mixed-case", true)]
    [Arguments("number", true)]
    [Arguments("special", true)]
    [Arguments("dictionary", true)]
    [Arguments("changed-percent", true)]
    public async Task MissingApplicableMysqlSettingIsUnavailableNotMeasuredStrongPolicy(string setting, bool component)
    {
        var policy = new MysqlPasswordPolicyFacts(true, component ? [] : ["validate_password"],
            component ? ["file://component_validate_password"] : [], 0, 8, false, 1, 1, 1, "", component ? 0 : null);
        policy = setting switch
        {
            "policy" => policy with { Policy = null },
            "length" => policy with { MinimumLength = null },
            "username" => policy with { CheckUserName = null },
            "mixed-case" => policy with { MixedCaseCount = null },
            "number" => policy with { NumberCount = null },
            "special" => policy with { SpecialCharCount = null },
            "dictionary" => policy with { DictionaryFile = null },
            "changed-percent" => policy with { ChangedCharactersPercentage = null },
            _ => throw new InvalidOperationException("unexpected-setting")
        };
        using var service = new SqlService(InfisicalRotationProfile.MysqlCredentials) { InitialPolicy = policy };
        string? reason = await Failure(async () =>
            await Factory(service).CreateAsync("original-project", Input(service.Profile), CancellationToken.None));
        var measured = service.PolicySnapshots.Single();
        await Assert.That(measured.IsComplete).IsTrue();
        await Assert.That(measured.ActiveValidationPlugins.SequenceEqual(component ? [] : ["validate_password"])).IsTrue();
        await Assert.That(measured.InstalledValidationComponents.SequenceEqual(
            component ? ["file://component_validate_password"] : [])).IsTrue();
        object? missing = setting switch
        {
            "policy" => measured.Policy,
            "length" => measured.MinimumLength,
            "username" => measured.CheckUserName,
            "mixed-case" => measured.MixedCaseCount,
            "number" => measured.NumberCount,
            "special" => measured.SpecialCharCount,
            "dictionary" => measured.DictionaryFile,
            "changed-percent" => measured.ChangedCharactersPercentage,
            _ => throw new InvalidOperationException("unexpected-setting")
        };
        await Assert.That(missing is null).IsTrue();
        await Assert.That(service.Claim is null && service.Release is null && service.Remaining is null).IsTrue();
        await PreservedForeignResources(service);
        // A blanket completeness assertion does not supply the missing setting.
        await Assert.That(reason).IsEqualTo("observer-unavailable");
    }

    [Test]
    [Arguments(1, "missing-prerequisite")]
    [Arguments(2, "missing-prerequisite")]
    [Arguments(3, "observer-unavailable")]
    public async Task MeasuredMysqlPolicyLevelsDifferFromAnUninterpretableLevel(int level, string expected)
    {
        using var service = new SqlService(InfisicalRotationProfile.MysqlCredentials)
        {
            InitialPolicy = new(true, ["validate_password"], [], level, 8, false, 1, 1, 1, "", null)
        };
        string? reason = await Failure(async () =>
            await Factory(service).CreateAsync("original-project", Input(service.Profile), CancellationToken.None));
        var measured = service.PolicySnapshots.Single();
        await Assert.That(measured.IsComplete).IsTrue();
        await Assert.That(measured.Policy).IsEqualTo(level);
        await Assert.That(measured.MinimumLength).IsEqualTo(8);
        await Assert.That(measured.ActiveValidationPlugins.SequenceEqual(["validate_password"])).IsTrue();
        await Assert.That(service.Claim is null && service.Release is null && service.Remaining is null).IsTrue();
        await PreservedForeignResources(service);
        // MEDIUM and STRONG are measured incompatible prerequisites; 3 is not
        // a known LOW/MEDIUM/STRONG observation and cannot establish strength.
        await Assert.That(reason).IsEqualTo(expected);
    }
}
