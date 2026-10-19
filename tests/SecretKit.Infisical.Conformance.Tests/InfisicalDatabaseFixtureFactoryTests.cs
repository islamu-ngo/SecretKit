using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalDatabaseFixtureFactoryTests
{
    private const string Organization = "00000000-0000-0000-0000-000000000001";
    private const string Project = "00000000-0000-0000-0000-000000000002";
    private const string Connection = "00000000-0000-0000-0000-000000000003";
    private const string Name = "sk00000000000000000000000000000004";
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new("https://fixture.invalid/owned/"), "service-token", "fixture-identity", 30);
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };

    [Test]
    [Arguments("Postgres")]
    [Arguments("MySql")]
    [Arguments("MsSql")]
    public async Task PrivateLeaseConstructsTypedProfilesMeasuresBackendAndReleasesOnlyOwnedResources(string profile)
    {
        using var environment = Environment();
        using var service = new Service();
        var factory = new InfisicalDatabaseFixtureFactory(new(Settings, service));
        await using var fixture = await factory.CreateAsync(environment, Definition(profile), Project,
            Input(), Name, CancellationToken.None);
        await Assert.That(service.Leases).IsEqualTo(1);
        await Assert.That(service.Accounts).IsEqualTo(4);
        await Assert.That(fixture.BackendCoordinate.ConnectionId).IsEqualTo(Connection);
        await Assert.That(fixture.Name).IsEqualTo(Name);
        await Assert.That(fixture.SourcePath).IsEqualTo("/" + Name);
        await Assert.That(fixture.DestinationPath).IsEqualTo("/" + Name + "-moved");
        using var statement = fixture.RotationStatement.Copy();
        switch (profile)
        {
            case "Postgres":
                using (var parameters = PostgresSecretRotationsEffects.Parameters(fixture, "selector.exact"))
                    await Assert.That(parameters.RotationStatement!.Reveal()).IsEqualTo("owned-rotate");
                break;
            case "MySql":
                using (var parameters = new MySqlRotationParameters(fixture.Username1, fixture.Username2,
                    rotationStatement: statement))
                    await Assert.That(parameters.RotationStatement!.Reveal()).IsEqualTo("owned-rotate");
                break;
            default:
                using (var parameters = new MsSqlRotationParameters(fixture.Username1, fixture.Username2,
                    rotationStatement: statement))
                    await Assert.That(parameters.RotationStatement!.Reveal()).IsEqualTo("owned-rotate");
                break;
        }
        var authority = await fixture.Backend!.MeasureAuthorityAsync(CancellationToken.None);
        InfisicalDatabaseFamilies.Authentication(new(), authority, fixture, DatabaseAuthentication.Accepted);
        using var username = SecretMaterial.FromText(fixture.Username1);
        using var password = SecretMaterial.FromText("owned-password");
        var authenticated = await fixture.Backend.AuthenticateAsync(username, password, CancellationToken.None);
        InfisicalDatabaseFamilies.Authentication(new(), authenticated, fixture, DatabaseAuthentication.Accepted);
        await using (var rejection = await fixture.Backend.SubscribeRejectionAsync(username, password, CancellationToken.None))
        {
            await service.ObserveStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.That(service.Registrations).IsEqualTo(1);
            service.Revoke();
            var rejected = await rejection.Rejected.WaitAsync(TimeSpan.FromSeconds(5));
            InfisicalDatabaseFamilies.Authentication(new(), rejected, fixture, DatabaseAuthentication.Rejected);
        }
        await Assert.That(service.Registrations).IsEqualTo(0);
        using (var catalog = await fixture.ObserveCatalogAsync(false, CancellationToken.None))
        {
            await Assert.That(catalog.Rows.Count).IsEqualTo(2);
            await Assert.That(catalog.Rows[1].Type).IsEqualTo("other-profile");
        }
        SecretMaterial optionStatement;
        using (var catalog = await fixture.ObserveCatalogAsync(true, CancellationToken.None))
        {
            await Assert.That(catalog.Options.Count).IsEqualTo(1);
            optionStatement = catalog.Options[0].RotationStatement;
            await Assert.That(optionStatement.Reveal()).IsEqualTo("catalog-rotate");
        }
        await Assert.That(() => optionStatement.Reveal()).Throws<ObjectDisposedException>();
        await fixture.CleanupAsync(CancellationToken.None);
        var remaining = await fixture.ObserveCleanupAsync(CancellationToken.None);
        await Assert.That(remaining).IsEqualTo(new DatabaseCleanupMeasurement(0, 0, 0));
        await Assert.That(service.Leases).IsEqualTo(0);
        await Assert.That(service.Accounts).IsEqualTo(0);
        await Assert.That(service.ForeignResources).IsEqualTo(7);
        var retained = fixture.RotationStatement;
        await fixture.DisposeAsync();
        await Assert.That(() => retained.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(statement.Reveal()).IsEqualTo("owned-rotate");
        await Assert.That(password.Reveal()).IsEqualTo("owned-password");
        await Assert.That(service.Disposed).IsFalse();
        using var selected = (await environment.Tokens(NativeIdentityRole.Setup).GetTokenAsync(CancellationToken.None)).Value;
        await Assert.That(selected.Material.Reveal()).IsEqualTo("setup");
        await Assert.That(JsonSerializer.Serialize(authenticated)).IsEqualTo("{}");
        await Assert.That(fixture.ToString()).IsEqualTo("[OwnedDatabaseFixture]");
    }

    [Test]
    [Arguments("claim-substitution")]
    [Arguments("claim-response-loss")]
    [Arguments("claim-missing")]
    [Arguments("project")]
    [Arguments("name")]
    [Arguments("profile")]
    [Arguments("ownership")]
    [Arguments("path")]
    [Arguments("connection")]
    [Arguments("port")]
    [Arguments("missing-default")]
    [Arguments("duplicate")]
    [Arguments("statement")]
    [Arguments("defaults")]
    public async Task FailedPreparationReleasesLocalNonceWithoutTrustingReturnedCoordinates(string mode)
    {
        using var environment = Environment();
        using var service = new Service(mode);
        var factory = new InfisicalDatabaseFixtureFactory(new(Settings, service));
        if (mode == "defaults")
            await Assert.That(async () => await factory.CreateAsync(environment, Definition("Postgres"), Project,
                Input(), Name, CancellationToken.None)).Throws<ArgumentException>();
        else
            await Assert.That(async () => await factory.CreateAsync(environment, Definition("Postgres"), Project,
                Input(), Name, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(service.Leases).IsEqualTo(0);
        await Assert.That(service.Accounts).IsEqualTo(0);
        await Assert.That(service.ReleasedProject).IsEqualTo(Project);
        await Assert.That(service.ReleasedName).IsEqualTo(Name);
        await Assert.That(service.ReleasedNonce).IsEqualTo(service.Ownership);
        await Assert.That(service.ForeignResources).IsEqualTo(7);
        await Assert.That(service.Disposed).IsFalse();
    }

    [Test]
    public async Task CancellationAfterLeaseAcquisitionUsesIndependentOwnedCleanup()
    {
        using var environment = Environment();
        using var service = new Service("provision-cancellation");
        using var cancellation = new CancellationTokenSource();
        var factory = new InfisicalDatabaseFixtureFactory(new(Settings, service));
        Task<IDatabaseOwnedFixture> preparation = factory.CreateAsync(environment, Definition("Postgres"),
            Project, Input(), Name, cancellation.Token).AsTask();
        await service.ProvisionStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await cancellation.CancelAsync();
        await Assert.That(async () => await preparation).Throws<OperationCanceledException>();
        await Assert.That(service.Leases).IsEqualTo(0);
        await Assert.That(service.Accounts).IsEqualTo(0);
        await Assert.That(service.ForeignResources).IsEqualTo(7);
        await Assert.That(service.ReleasedNonce).IsEqualTo(service.Ownership);
    }

    [Test]
    [Arguments("host")]
    [Arguments("database")]
    [Arguments("authentication-connection")]
    [Arguments("authentication-profile")]
    [Arguments("authentication-time")]
    [Arguments("denied-accepted")]
    [Arguments("actions")]
    [Arguments("authentication-missing")]
    public async Task BackendSubstitutionCannotBecomeSuccessfulEffect(string mode)
    {
        using var environment = Environment();
        using var service = new Service(mode);
        var factory = new InfisicalDatabaseFixtureFactory(new(Settings, service));
        await using var fixture = await factory.CreateAsync(environment, Definition("Postgres"), Project,
            Input(), Name, CancellationToken.None);
        await Assert.That(async () =>
        {
            var measured = await fixture.Backend!.MeasureAuthorityAsync(CancellationToken.None);
            InfisicalDatabaseFamilies.Authentication(new(), measured, fixture, DatabaseAuthentication.Accepted);
        }).Throws<NativeCaseFailureException>();
        await fixture.CleanupAsync(CancellationToken.None);
        await fixture.ObserveCleanupAsync(CancellationToken.None);
        await Assert.That(service.ForeignResources).IsEqualTo(7);
    }

    [Test]
    [Arguments("remainingAccounts")]
    [Arguments("remainingMappings")]
    [Arguments("remainingRotations")]
    [Arguments("remainingConnections")]
    [Arguments("remainingFolders")]
    [Arguments("remainingLeases")]
    [Arguments("remainingRegistrations")]
    public async Task EveryCleanupCounterMustExplicitlyMeasureZero(string counter)
    {
        using var environment = Environment();
        using var service = new Service();
        var factory = new InfisicalDatabaseFixtureFactory(new(Settings, service));
        await using var fixture = await factory.CreateAsync(environment, Definition("Postgres"), Project,
            Input(), Name, CancellationToken.None);
        service.CleanupCounter = counter;
        await Assert.That(async () => await fixture.CleanupAsync(CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        service.CleanupCounter = null;
        await fixture.ObserveCleanupAsync(CancellationToken.None);
        service.MissingCounter = counter;
        await Assert.That(async () => await fixture.ObserveCleanupAsync(CancellationToken.None))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("arm-substitution")]
    [Arguments("rejection-substitution")]
    [Arguments("disarm-counter")]
    public async Task RejectionFailuresStillDisarmOnlyTheLocallyRegisteredSubscription(string mode)
    {
        using var environment = Environment();
        using var service = new Service(mode);
        var factory = new InfisicalDatabaseFixtureFactory(new(Settings, service));
        await using var fixture = await factory.CreateAsync(environment, Definition("Postgres"), Project,
            Input(), Name, CancellationToken.None);
        using var username = SecretMaterial.FromText(fixture.Username1);
        using var password = SecretMaterial.FromText("owned-password");
        if (mode == "arm-substitution")
            await Assert.That(async () => await fixture.Backend!.SubscribeRejectionAsync(username, password, CancellationToken.None))
                .Throws<NativeCaseFailureException>();
        else
        {
            var subscription = await fixture.Backend!.SubscribeRejectionAsync(username, password, CancellationToken.None);
            await service.ObserveStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            service.Revoke();
            if (mode == "rejection-substitution")
                await Assert.That(async () => await subscription.Rejected).Throws<NativeCaseFailureException>();
            else await subscription.Rejected.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.That(async () => await subscription.DisposeAsync()).Throws<NativeCaseFailureException>();
        }
        await Assert.That(service.Registrations).IsEqualTo(0);
        await fixture.CleanupAsync(CancellationToken.None);
        await fixture.ObserveCleanupAsync(CancellationToken.None);
    }

    [Test]
    [Arguments("catalog-project")]
    [Arguments("catalog-duplicate")]
    [Arguments("catalog-kind")]
    public async Task UnfilteredCatalogRequiresExactOwnedCoordinatesAndUniqueRows(string mode)
    {
        using var environment = Environment();
        using var service = new Service(mode);
        var factory = new InfisicalDatabaseFixtureFactory(new(Settings, service));
        await using var fixture = await factory.CreateAsync(environment, Definition("Postgres"), Project,
            Input(), Name, CancellationToken.None);
        await Assert.That(async () => await fixture.ObserveCatalogAsync(false, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await fixture.CleanupAsync(CancellationToken.None);
        await fixture.ObserveCleanupAsync(CancellationToken.None);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task InstalledFactoryReadsOnlyMatchingFamilyRootAndRegistrationIsLazy(bool configured)
    {
        JsonObject family = new()
        {
            ["scopes"] = new JsonObject { ["local"] = new JsonObject { ["observer"] = JsonSerializer.SerializeToNode(Settings, Json) } }
        };
        if (configured) family["observer"] = JsonSerializer.SerializeToNode(Settings, Json);
        using var environment = Environment(family);
        await Assert.That(InfisicalDatabaseFixtureFactory.FromInputs(environment, "PostgresSecretRotations") is not null)
            .IsEqualTo(configured);
        family["observer"] = new JsonObject { ["invalid"] = true };
        using var invalid = Environment(family);
        var registry = new NativeCaseRegistry();
        var definition = Definition("Postgres");
        InfisicalDatabaseFamilies.Register(registry, invalid, [definition]);
        registry.ValidateAgainst([definition]);
        await Assert.That(registry.Find(definition.Key) is not null).IsTrue();
    }

    private static NativeCaseDefinition Definition(string profile)
    {
        string operation = "i.management." + profile + "SecretRotationOperations.Get";
        return new(new("Infisical", operation, "selector.exact", "local", "independent-effect"),
            InfisicalDatabaseFamilies.Bindings[operation].Member);
    }
    private static JsonElement Input() => JsonSerializer.SerializeToElement(new { organizationId = Organization });
    private static NativeEnvironment Environment(JsonObject? family = null) => NativeEnvironment.Create(
        JsonSerializer.SerializeToElement(new
        {
            origin = "https://infisical.invalid/",
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families = new Dictionary<string, object>
            {
                ["C08-IM-PostgresSecretRotations"] = family ?? new(),
                ["C08-IM-MySqlSecretRotations"] = new JsonObject(),
                ["C08-IM-MsSqlSecretRotations"] = new JsonObject()
            }
        }, Json));

    // Deterministic private-service state; no service/provider/native effects
    // are claimed by these replies. No vendor responses occur in Admission.
    private sealed class Service(string mode = "good") : HttpMessageHandler
    {
        private readonly TaskCompletionSource revoked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource ObserveStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource ProvisionStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int Leases { get; private set; }
        internal int Accounts { get; private set; }
        internal int Registrations { get; private set; }
        internal int ForeignResources => 7;
        internal string? Ownership { get; private set; }
        internal string? ReleasedProject { get; private set; }
        internal string? ReleasedName { get; private set; }
        internal string? ReleasedNonce { get; private set; }
        internal string? CleanupCounter { get; set; }
        internal string? MissingCounter { get; set; }
        internal bool Disposed { get; private set; }
        private JsonObject? provision;
        private string? subscription;
        internal void Revoke() => revoked.TrySetResult();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            JsonObject body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo(Settings.Token);
            string action = request.RequestUri!.AbsolutePath.Split('/').Last();
            string own = body["ownershipNonce"]!.GetValue<string>();
            JsonObject facts;
            if (action == "claim")
            {
                Ownership = own;
                Leases = 1;
                facts = new() { ["ownershipNonce"] = mode == "claim-substitution" ? "foreign" : own, ["remainingLeases"] = 1 };
                if (mode == "claim-missing") facts.Remove("remainingLeases");
                if (mode == "claim-response-loss") throw new HttpRequestException("fixture-response-loss");
            }
            else
            {
                await Assert.That(own).IsEqualTo(Ownership);
                await Assert.That(body["projectId"]!.GetValue<string>()).IsEqualTo(Project);
                await Assert.That(body["ownedName"]!.GetValue<string>()).IsEqualTo(Name);
                if (action == "provision")
                {
                    await Assert.That(body["setupToken"]!.GetValue<string>()).IsEqualTo("setup");
                    Accounts = 4;
                    ProvisionStarted.TrySetResult();
                    if (mode == "provision-cancellation")
                        await revoked.Task.WaitAsync(token);
                    facts = new()
                    {
                        ["ownershipNonce"] = own,
                        ["organizationId"] = Organization,
                        ["projectId"] = Project,
                        ["ownedName"] = Name,
                        ["profile"] = body["profile"]!.DeepClone(),
                        ["environment"] = "owned",
                        ["sourcePath"] = "/" + Name,
                        ["destinationEnvironment"] = "owned-destination",
                        ["destinationPath"] = "/" + Name + "-moved",
                        ["connectionId"] = Connection,
                        ["host"] = "owned-host",
                        ["port"] = 5432,
                        ["database"] = "owned-database",
                        ["rotationStatement"] = "owned-rotate",
                        ["updatedRotationStatement"] = "owned-updated-rotate",
                        ["allowedActions"] = new JsonArray("select"),
                        ["deniedActions"] = new JsonArray("drop"),
                        ["primaryShapeRevision"] = "offline-only",
                        ["defaultHours"] = 0,
                        ["defaultMinutes"] = 0,
                        ["defaultEnabled"] = false,
                        ["defaultHasDescription"] = true,
                        ["defaultDescription"] = null,
                        ["defaultDeleteSecrets"] = true,
                        ["defaultRevokeCredentials"] = true
                    };
                    provision = (JsonObject)facts.DeepClone();
                    switch (mode)
                    {
                        case "project": facts["projectId"] = "foreign-project"; break;
                        case "name": facts["ownedName"] = "foreign-name"; break;
                        case "profile": facts["profile"] = -1; break;
                        case "ownership": facts["ownershipNonce"] = "foreign"; break;
                        case "path": facts["sourcePath"] = "/foreign"; break;
                        case "connection": facts["connectionId"] = "invalid"; break;
                        case "port": facts["port"] = 0; break;
                        case "missing-default": facts.Remove("defaultHours"); break;
                        case "statement": facts["rotationStatement"] = ""; break;
                        case "defaults": facts["defaultMinutes"] = 61; break;
                    }
                }
                else if (action is "release" or "remaining")
                {
                    if (action == "release")
                    {
                        await Assert.That(body["setupToken"]!.GetValue<string>()).IsEqualTo("setup");
                        ReleasedNonce = own;
                        ReleasedProject = body["projectId"]!.GetValue<string>();
                        ReleasedName = body["ownedName"]!.GetValue<string>();
                        Leases = 0; Accounts = 0; Registrations = 0;
                    }
                    else await Assert.That(body["observerToken"]!.GetValue<string>()).IsEqualTo("observer");
                    facts = new()
                    {
                        ["ownershipNonce"] = own,
                        ["organizationId"] = Organization,
                        ["projectId"] = Project,
                        ["ownedName"] = Name,
                        ["remainingAccounts"] = Accounts,
                        ["remainingMappings"] = 0,
                        ["remainingRotations"] = 0,
                        ["remainingConnections"] = 0,
                        ["remainingFolders"] = 0,
                        ["remainingLeases"] = Leases,
                        ["remainingRegistrations"] = Registrations
                    };
                    if (CleanupCounter is not null) facts[CleanupCounter] = 1;
                    if (MissingCounter is not null) facts.Remove(MissingCounter);
                }
                else if (action is "arm" or "disarm")
                {
                    if (action == "arm")
                    {
                        subscription = body["subscriptionNonce"]!.GetValue<string>();
                        Registrations = 1;
                    }
                    else
                    {
                        await Assert.That(body["subscriptionNonce"]!.GetValue<string>()).IsEqualTo(subscription);
                        Registrations = 0;
                    }
                    facts = new()
                    {
                        ["ownershipNonce"] = own,
                        ["subscriptionNonce"] = mode == "arm-substitution" && action == "arm" ? "foreign" : subscription,
                        ["remainingRegistrations"] = mode == "disarm-counter" && action == "disarm" ? 1 : Registrations
                    };
                }
                else if (action == "catalog")
                {
                    await Assert.That(body["observerToken"]!.GetValue<string>()).IsEqualTo("observer");
                    bool options = body["options"]!.GetValue<bool>();
                    facts = new()
                    {
                        ["ownershipNonce"] = own,
                        ["organizationId"] = Organization,
                        ["projectId"] = Project,
                        ["optionsCatalog"] = options,
                        ["rows"] = options ? new JsonArray() : new JsonArray(
                            new JsonObject { ["id"] = Connection, ["type"] = "postgres-credentials" },
                            new JsonObject { ["id"] = "other", ["type"] = "other-profile" }),
                        ["options"] = !options ? new JsonArray() : new JsonArray(new JsonObject
                        {
                            ["type"] = "postgres-credentials",
                            ["usernameKey"] = "USER",
                            ["passwordKey"] = "PASSWORD",
                            ["createStatement"] = "catalog-create",
                            ["rotationStatement"] = "catalog-rotate"
                        })
                    };
                    if (mode == "catalog-project") facts["projectId"] = "foreign";
                    if (mode == "catalog-kind") facts["optionsCatalog"] = !options;
                    if (mode == "catalog-duplicate") facts["rows"]!.AsArray()[1]!["id"] = Connection;
                }
                else
                {
                    await Assert.That(body["runtimeToken"]!.GetValue<string>()).IsEqualTo("runtime");
                    await Assert.That(body["deniedToken"]!.GetValue<string>()).IsEqualTo("denied");
                    await Assert.That(body["host"]!.GetValue<string>()).IsEqualTo("owned-host");
                    await Assert.That(body["connectionId"]!.GetValue<string>()).IsEqualTo(Connection);
                    if (action != "authority")
                    {
                        await Assert.That(body["username"]!.GetValue<string>()).IsEqualTo(Name + "a");
                        await Assert.That(body["password"]!.GetValue<string>()).IsEqualTo("owned-password");
                    }
                    if (action == "rejected")
                    {
                        ObserveStarted.TrySetResult();
                        await revoked.Task.WaitAsync(token);
                    }
                    facts = new()
                    {
                        ["ownershipNonce"] = own,
                        ["subscriptionNonce"] = body["subscriptionNonce"]?.DeepClone(),
                        ["profile"] = provision!["profile"]!.DeepClone(),
                        ["host"] = "owned-host",
                        ["port"] = 5432,
                        ["database"] = "owned-database",
                        ["connectionId"] = Connection,
                        ["selected"] = (int)(action == "rejected" ? DatabaseAuthentication.Rejected : DatabaseAuthentication.Accepted),
                        ["denied"] = (int)DatabaseAuthentication.Rejected,
                        ["allowedActions"] = new JsonArray("select"),
                        ["deniedActions"] = new JsonArray("drop"),
                        ["observedAt"] = JsonSerializer.SerializeToNode(DateTimeOffset.UtcNow)
                    };
                    switch (mode)
                    {
                        case "host": facts["host"] = "foreign"; break;
                        case "database": facts["database"] = "foreign"; break;
                        case "authentication-connection": facts["connectionId"] = Project; break;
                        case "authentication-profile": facts["profile"] = -1; break;
                        case "authentication-time": facts["observedAt"] = JsonSerializer.SerializeToNode(DateTimeOffset.UnixEpoch); break;
                        case "denied-accepted": facts["denied"] = (int)DatabaseAuthentication.Accepted; break;
                        case "actions": facts["allowedActions"] = new JsonArray("wrong"); break;
                        case "authentication-missing": facts.Remove("denied"); break;
                        case "rejection-substitution": facts["subscriptionNonce"] = "foreign"; break;
                    }
                }
            }
            string payload = JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                nonce = body["nonce"]!.GetValue<string>(),
                observerIdentity = Settings.Identity,
                observedAt = DateTimeOffset.UtcNow,
                facts
            }, Json);
            if (mode == "duplicate" && action == "provision")
                payload = payload.Replace("\"defaultHours\":0", "\"defaultHours\":0,\"defaultHours\":1", StringComparison.Ordinal);
            return new(HttpStatusCode.OK) { Content = new StringContent(payload) };
        }

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }
}
