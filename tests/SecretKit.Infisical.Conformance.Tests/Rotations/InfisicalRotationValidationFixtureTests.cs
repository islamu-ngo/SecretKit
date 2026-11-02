using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalRotationValidationFixtureTests
{
    private static readonly JsonSerializerOptions ServiceJson = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new Uri("https://observer.invalid/owned/"), "fixture-owner", "independent-owner", 30);
    private static readonly ValidationPoliciesEffects.RotationValidationInput Input =
        new("organization", "borrowed-connection", "database.invalid", 5432, "owned", 60, ["select"], ["write"]);

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "observer-unavailable")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "observer-unavailable")]
    [Arguments(InfisicalRotationProfile.Auth0ClientSecret, "missing-input")]
    public async Task ProfileRequiresItsOwnIdentityCatalogBeforeAccountClaim(
        InfisicalRotationProfile profile, string expectedReason)
    {
        // Given a selected profile but no independent provider-specific catalog.
        using var service = new OwnerService();
        // When the owner client is asked to create the selected account identities.
        string? reason = await Failure(async () =>
        {
            await using var accounts = await Factory(service).CreateAsync("project",
                Input with { Profile = profile }, CancellationToken.None);
        });
        // Then an unsupported or unmeasurable profile cannot silently claim PG roles.
        await Assert.That(reason).IsEqualTo(expectedReason);
        await Assert.That(service.Claim is null && service.Release is null && service.Remaining is null).IsTrue();
        await Assert.That(service.Roles.Count).IsEqualTo(1);
    }

    [Test]
    public async Task ClaimAndDisposeRemoveOnlyNonceOwnedAccounts()
    {
        // Given an independent owner with an existing role and borrowed connection.
        using var service = new OwnerService();
        var factory = Factory(service);

        // When a new pair is claimed and then disposed.
        IInfisicalRotationValidationAccounts accounts = await factory.CreateAsync("project", Input, CancellationToken.None);
        await Assert.That(Regex.IsMatch(accounts.Username1, "^sk_rv_[0-9a-f]{16}_a$")).IsTrue();
        await Assert.That(accounts.Username2).IsEqualTo(accounts.Username1[..^1] + "b");
        await Assert.That(service.Roles[accounts.Username1]).IsEqualTo(service.Claim!["ownershipNonce"]!.GetValue<string>());
        await Assert.That(service.Roles[accounts.Username2]).IsEqualTo(service.Roles[accounts.Username1]);
        await Assert.That(accounts.Coordinate).IsEqualTo(service.Claim["coordinate"]!
            .Deserialize<RotationBackendCoordinate>(ServiceJson));
        await accounts.DisposeAsync();

        // Then original ownership targets, not arbitrary roles, have been removed.
        await CleanOriginalScope(service);
    }

    [Test]
    [Arguments("ownershipNonce")]
    [Arguments("organizationId")]
    [Arguments("projectId")]
    [Arguments("connectionId")]
    [Arguments("coordinate")]
    [Arguments("ownedUsernames")]
    [Arguments("remainingOwnedAccounts")]
    [Arguments("unownedUsernames")]
    [Arguments("connectionRetained")]
    [Arguments("substituted-scope")]
    public async Task ForeignOrUnownedClaimFactsAreRejectedAndOriginalScopeCompensated(string fault)
    {
        // Given a claim which commits locally but returns unbound owner facts.
        using var service = new OwnerService { ClaimFault = fault };

        // When the factory attempts to accept those facts.
        string? reason = await Failure(async () => await Factory(service).CreateAsync("project", Input, CancellationToken.None));

        // Then no response substitution can redirect compensation.
        await Assert.That(reason).IsEqualTo("observer-unavailable");
        await CleanOriginalScope(service);
    }

    [Test]
    public async Task EveryRequiredOwnerFactMustBePresent()
    {
        // Given each required field independently omitted from an otherwise valid claim.
        foreach (string field in new[] { "ownershipNonce", "organizationId", "projectId", "connectionId",
            "coordinate", "ownedUsernames", "unownedUsernames", "remainingOwnedAccounts", "connectionRetained" })
        {
            using var service = new OwnerService { ClaimFault = "missing:" + field };

            // When deserialization crosses the typed channel boundary.
            string? reason = await Failure(async () => await Factory(service).CreateAsync("project", Input, CancellationToken.None));

            // Then the committed original roles are compensated despite missing evidence.
            await Assert.That(reason).IsEqualTo("observer-unavailable");
            await CleanOriginalScope(service);
        }
    }

    [Test]
    [Arguments("malformed")]
    [Arguments("http-error")]
    public async Task InterruptedClaimResponseStillReleasesOriginalCommittedPair(string fault)
    {
        // Given owner state committed before the response is lost or malformed.
        using var service = new OwnerService { ClaimFault = fault };

        // When the client fails to receive admissible claim evidence.
        string? reason = await Failure(async () => await Factory(service).CreateAsync("project", Input, CancellationToken.None));

        // Then compensation uses the exact pre-dispatch tuple and nonce.
        await Assert.That(reason).IsEqualTo("observer-unavailable");
        await CleanOriginalScope(service);
    }

    [Test]
    [Arguments("ack-only")]
    [Arguments("missing-remaining")]
    [Arguments("foreign-remaining")]
    public async Task ReleaseAcknowledgementCannotReplaceBoundFinalAbsence(string fault)
    {
        // Given a valid claim, but dishonest release acknowledgement or unusable final inventory.
        using var service = new OwnerService { CleanupFault = fault };
        IInfisicalRotationValidationAccounts accounts = await Factory(service).CreateAsync("project", Input, CancellationToken.None);

        // When cleanup requests independent remaining-account evidence.
        string? reason = await Failure(async () => await accounts.DisposeAsync());

        // Then uncertainty remains explicit, and the borrowed resources survive.
        await Assert.That(reason).IsEqualTo("cleanup-incomplete");
        await Assert.That(service.Remaining is not null).IsTrue();
        await Assert.That(SameTarget(service.Claim!, service.Remaining!)).IsTrue();
        await Assert.That(service.Roles.Count).IsEqualTo(fault == "ack-only" ? 3 : 1);
        await Assert.That(service.Roles["existing-role"]).IsEqualTo("foreign-owner");
        await Assert.That(service.ConnectionRetained).IsTrue();
    }

    [Test]
    public async Task ExistingRoleCannotBeAdoptedFromOwnerFacts()
    {
        // Given service facts asserting an existing foreign role belongs to this claim.
        using var service = new OwnerService { ClaimFault = "existing-role" };

        // When the factory receives that attempted adoption.
        string? reason = await Failure(async () => await Factory(service).CreateAsync("project", Input, CancellationToken.None));

        // Then the foreign role is neither adopted nor released.
        await Assert.That(reason).IsEqualTo("observer-unavailable");
        await CleanOriginalScope(service);
    }

    [Test]
    [Arguments("Accepted")]
    [Arguments("Rejected")]
    public async Task CredentialMeasurementForwardsSuppliedMaterialAndReturnsActualFacts(string authentication)
    {
        // Given independently returned facts rather than claimed action semantics.
        var coordinate = new RotationBackendCoordinate(InfisicalRotationProfile.PostgresCredentials,
            Input.Host, Input.Port, Input.Database, "measured-account");
        var expected = new RotationCredentialFacts(coordinate, Enum.Parse<BackendAuthentication>(authentication),
            authentication == "Accepted" ? "actual-account" : null, ["actual-select"], ["actual-write"]);
        using var handler = new Handler(async (request, token) =>
        {
            await Assert.That(request.RequestUri!.AbsoluteUri)
                .IsEqualTo("https://observer.invalid/owned/rotation/measure-credentials");
            await Assert.That(request.Method).IsEqualTo(HttpMethod.Post);
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo(Settings.Token);
            JsonObject body = await Body(request, token);
            await Assert.That(body["coordinate"]!.Deserialize<RotationBackendCoordinate>(ServiceJson)).IsEqualTo(coordinate);
            await Assert.That(body["username"]!.GetValue<string>() == "supplied-account").IsTrue();
            await Assert.That(body["password"]!.GetValue<string>() == "supplied-password").IsTrue();
            return Reply(Envelope(body, expected));
        });
        var observer = new InfisicalLifecycleObservers(Settings, handler);
        using var username = SecretMaterial.FromText("supplied-account");
        using var password = SecretMaterial.FromText("supplied-password");

        // When the typed channel measures the supplied credentials.
        RotationCredentialFacts actual = await observer.MeasureCredentialsAsync(coordinate, username, password, CancellationToken.None);

        // Then the actual returned fields survive without helper-level policy validation.
        await Assert.That(actual.Coordinate).IsEqualTo(expected.Coordinate);
        await Assert.That(actual.Authentication).IsEqualTo(expected.Authentication);
        await Assert.That(actual.AuthenticatedUsername).IsEqualTo(expected.AuthenticatedUsername);
        await Assert.That(actual.AllowedActions).IsEquivalentTo(expected.AllowedActions);
        await Assert.That(actual.DeniedActions).IsEquivalentTo(expected.DeniedActions);
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("identity")]
    [Arguments("schema")]
    [Arguments("missing-authenticated-username")]
    [Arguments("missing-authentication")]
    public async Task UnboundOrIncompleteCredentialFactsFailClosedWithoutMaterialInErrors(string fault)
    {
        // Given a wire response with one broken envelope or required credential field.
        var coordinate = new RotationBackendCoordinate(InfisicalRotationProfile.PostgresCredentials,
            Input.Host, Input.Port, Input.Database, "measured-account");
        using var handler = new Handler(async (request, token) =>
        {
            JsonObject response = Envelope(await Body(request, token),
                new RotationCredentialFacts(coordinate, BackendAuthentication.Accepted, "supplied-account", ["select"], ["write"]));
            switch (fault)
            {
                case "nonce": response["nonce"] = "other-request"; break;
                case "identity": response["observerIdentity"] = "other-owner"; break;
                case "schema": response["schemaVersion"] = 2; break;
                case "missing-authenticated-username": response["facts"]!.AsObject().Remove("authenticatedUsername"); break;
                case "missing-authentication": response["facts"]!.AsObject().Remove("authentication"); break;
            }
            return Reply(response);
        });
        var observer = new InfisicalLifecycleObservers(Settings, handler);
        using var username = SecretMaterial.FromText("supplied-account");
        using var password = SecretMaterial.FromText("supplied-password");

        // When malformed evidence reaches the typed channel.
        string? reason = await Failure(async () =>
            await observer.MeasureCredentialsAsync(coordinate, username, password, CancellationToken.None));

        // Then only a bounded diagnostic code is exposed.
        await Assert.That(reason).IsEqualTo("observer-unavailable");
    }

    private static InfisicalRotationValidationAccounts Factory(OwnerService service) =>
        new(new InfisicalLifecycleObservers(Settings, service));

    private static async Task<string?> Failure(Func<Task> action)
    {
        try { await action(); return null; }
        catch (NativeCaseFailureException error) { return error.Message; }
    }

    private static async Task CleanOriginalScope(OwnerService service)
    {
        await Assert.That(service.Release is not null && service.Remaining is not null).IsTrue();
        await Assert.That(SameTarget(service.Claim!, service.Release!)).IsTrue();
        await Assert.That(SameTarget(service.Claim!, service.Remaining!)).IsTrue();
        await Assert.That(service.Roles.Count).IsEqualTo(1);
        await Assert.That(service.Roles["existing-role"]).IsEqualTo("foreign-owner");
        await Assert.That(service.ConnectionRetained).IsTrue();
    }

    private static bool SameTarget(JsonObject left, JsonObject right) =>
        new[] { "ownershipNonce", "organizationId", "projectId", "connectionId", "coordinate", "username1", "username2" }
            .All(field => JsonNode.DeepEquals(left[field], right[field]));

    private static async Task<JsonObject> Body(HttpRequestMessage request, CancellationToken token) =>
        (JsonObject)JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!;

    private static JsonObject Envelope<T>(JsonObject body, T facts) => new()
    {
        ["schemaVersion"] = 1,
        ["nonce"] = body["nonce"]!.DeepClone(),
        ["observerIdentity"] = Settings.Identity,
        ["observedAt"] = DateTimeOffset.UtcNow,
        ["facts"] = JsonSerializer.SerializeToNode(facts, ServiceJson)
    };

    private static HttpResponseMessage Reply(JsonObject body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body.ToJsonString()) };

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }

    private sealed class OwnerService : HttpMessageHandler
    {
        internal string? ClaimFault { get; init; }
        internal string? CleanupFault { get; init; }
        internal JsonObject? Claim { get; private set; }
        internal JsonObject? Release { get; private set; }
        internal JsonObject? Remaining { get; private set; }
        internal Dictionary<string, string> Roles { get; } = new(StringComparer.Ordinal) { ["existing-role"] = "foreign-owner" };
        internal bool ConnectionRetained { get; } = true;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            await Assert.That(request.Method).IsEqualTo(HttpMethod.Post);
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo(Settings.Token);
            JsonObject body = await Body(request, token);
            string path = request.RequestUri!.AbsolutePath;
            if (path == "/owned/rotation-accounts/claim")
            {
                Claim = body.DeepClone().AsObject();
                string ownership = body["ownershipNonce"]!.GetValue<string>();
                string first = body["username1"]!.GetValue<string>();
                string second = body["username2"]!.GetValue<string>();
                await Assert.That(ownership.Length == 32 && Regex.IsMatch(ownership, "^[0-9a-f]+$")).IsTrue();
                await Assert.That(first == "sk_rv_" + ownership[..16] + "_a").IsTrue();
                await Assert.That(second == "sk_rv_" + ownership[..16] + "_b").IsTrue();
                await Assert.That(body["projectId"]!.GetValue<string>()).IsEqualTo("project");
                await Assert.That(body["organizationId"]!.GetValue<string>()).IsEqualTo(Input.OrganizationId);
                await Assert.That(body["connectionId"]!.GetValue<string>()).IsEqualTo(Input.ConnectionId);
                await Assert.That(body["coordinate"]!.Deserialize<RotationBackendCoordinate>(ServiceJson))
                    .IsEqualTo(new RotationBackendCoordinate(InfisicalRotationProfile.PostgresCredentials,
                        Input.Host, Input.Port, Input.Database, first));
                Roles.Add(first, ownership);
                Roles.Add(second, ownership);
                if (ClaimFault == "http-error") return new(HttpStatusCode.ServiceUnavailable);
                if (ClaimFault == "malformed")
                    return new(HttpStatusCode.OK) { Content = new StringContent("{") };
                JsonObject response = Inventory(body);
                JsonObject facts = response["facts"]!.AsObject();
                switch (ClaimFault)
                {
                    case "ownershipNonce": facts["ownershipNonce"] = "foreign-owner"; break;
                    case "organizationId": facts["organizationId"] = "foreign-organization"; break;
                    case "projectId": facts["projectId"] = "foreign-project"; break;
                    case "connectionId": facts["connectionId"] = "foreign-connection"; break;
                    case "coordinate": facts["coordinate"]!["database"] = "foreign-database"; break;
                    case "ownedUsernames": facts["ownedUsernames"] = new JsonArray(second, first); break;
                    case "remainingOwnedAccounts": facts["remainingOwnedAccounts"] = 1; break;
                    case "unownedUsernames": facts["unownedUsernames"] = new JsonArray("existing-role"); break;
                    case "connectionRetained": facts["connectionRetained"] = false; break;
                    case "existing-role": facts["ownedUsernames"] = new JsonArray(first, "existing-role"); break;
                    case "substituted-scope":
                        facts["ownershipNonce"] = "foreign-owner";
                        facts["organizationId"] = "foreign-organization";
                        facts["projectId"] = "foreign-project";
                        facts["connectionId"] = "foreign-connection";
                        facts["coordinate"]!["database"] = "foreign-database";
                        facts["ownedUsernames"] = new JsonArray("existing-role", "other-role");
                        break;
                }
                if (ClaimFault?.StartsWith("missing:", StringComparison.Ordinal) == true)
                    facts.Remove(ClaimFault["missing:".Length..]);
                return Reply(response);
            }
            if (path == "/owned/rotation-accounts/release")
            {
                Release = body.DeepClone().AsObject();
                if (SameTarget(Claim!, body) && CleanupFault != "ack-only")
                    foreach (string field in new[] { "username1", "username2" })
                    {
                        string name = body[field]!.GetValue<string>();
                        if (Roles.TryGetValue(name, out string? owner) && owner == body["ownershipNonce"]!.GetValue<string>())
                            Roles.Remove(name);
                    }
                JsonObject response = Inventory(body);
                if (CleanupFault == "ack-only")
                {
                    response["facts"]!["ownedUsernames"] = new JsonArray();
                    response["facts"]!["remainingOwnedAccounts"] = 0;
                }
                return Reply(response);
            }
            if (path == "/owned/rotation-accounts/remaining")
            {
                Remaining = body.DeepClone().AsObject();
                JsonObject response = Inventory(body);
                if (CleanupFault == "missing-remaining") response["facts"]!.AsObject().Remove("remainingOwnedAccounts");
                if (CleanupFault == "foreign-remaining") response["facts"]!["organizationId"] = "foreign-organization";
                return Reply(response);
            }
            throw new InvalidOperationException("unexpected-owner-route");
        }

        private JsonObject Inventory(JsonObject body)
        {
            string nonce = body["ownershipNonce"]!.GetValue<string>();
            string[] owned = new[] { body["username1"]!.GetValue<string>(), body["username2"]!.GetValue<string>() }
                .Where(name => Roles.TryGetValue(name, out string? owner) && owner == nonce).ToArray();
            return Envelope(body, new InfisicalRotationValidationAccounts.Facts(nonce,
                body["organizationId"]!.GetValue<string>(), body["projectId"]!.GetValue<string>(),
                body["connectionId"]!.GetValue<string>(), body["coordinate"]!.Deserialize<RotationBackendCoordinate>(ServiceJson)!,
                owned, [], owned.Length, ConnectionRetained));
        }
    }
}
