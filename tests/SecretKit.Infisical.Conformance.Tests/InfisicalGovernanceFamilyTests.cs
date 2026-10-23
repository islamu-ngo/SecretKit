using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalGovernanceFamilyTests
{
    private const string Org = "00000000-0000-0000-0000-000000000001";
    private const string Identity = "00000000-0000-0000-0000-000000000004";
    private const string Date = "2026-10-12T00:00:00.000Z";

    [Test]
    public async Task InventoryBindingsAreExactAndMissingInputsAreExecutionFailures()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using JsonDocument inventory = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        NativeCaseDefinition[] expected = inventory.RootElement.GetProperty("operations").EnumerateArray()
            .Where(o => InfisicalGovernanceFamilies.Owns(o.GetProperty("id").GetString()!))
            .SelectMany(o => o.GetProperty("variants").EnumerateArray().SelectMany(v =>
                o.GetProperty("requiredCases").EnumerateArray().Select(c => new NativeCaseDefinition(
                    new("Infisical", o.GetProperty("id").GetString()!, v.GetString()!, "local", c.GetString()!),
                    o.GetProperty("member").GetString()!)))).ToArray();
        await Assert.That(expected.All(InfisicalGovernanceFamilies.Valid)).IsTrue();
        await Assert.That(expected.Select(d => d.Key.Operation).Distinct().Count()).IsEqualTo(21);
        await Assert.That(expected.Length).IsGreaterThan(2000);
        using NativeEnvironment environment = Environment(new("http://127.0.0.1:1/"), false);
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, environment, expected);
        IReadOnlyList<NativeCaseResult> results = await NativeCaseRunner.RunAsync(registry, expected, CancellationToken.None);
        foreach (var reason in results.GroupBy(r => r.ReasonCode))
            Console.WriteLine($"C08 missing fixture execution: {reason.Key} cases={reason.Count()}");
        await Assert.That(results.All(r => !r.Passed && r.ReasonCode is "missing-input" or "observer-unavailable")).IsTrue();
        int executable = expected.Count(d => InfisicalGovernanceFamilies.UnavailableReason(d) is null);
        await Assert.That(executable).IsGreaterThan(0);
        await Assert.That(results.Count(r => r.ReasonCode == "observer-unavailable")).IsEqualTo(expected.Length - executable);
        Console.WriteLine($"C08 governance coverage: operations=21 variants={expected.Select(d => (d.Key.Operation, d.Key.Variant)).Distinct().Count()} cases={expected.Length} executable={executable} unavailable={expected.Length - executable}");
        foreach (var group in expected.Where(d => InfisicalGovernanceFamilies.UnavailableReason(d) is not null)
            .GroupBy(d => InfisicalGovernanceFamilies.UnavailableReason(d)))
            Console.WriteLine($"C08 unavailable: {group.Key} cases={group.Count()}");
    }

    [Test]
    [Arguments("member")]
    [Arguments("variant")]
    [Arguments("case")]
    [Arguments("scope")]
    public async Task CorruptBindingsCannotReachProvider(string field)
    {
        NativeCaseDefinition d = Definition("GatewayAdministrationOperations.Create", "auth.Token");
        d = field switch
        {
            "member" => d with { Member = d.Member + ".wrong" },
            "variant" => d with { Key = d.Key with { Variant = "wrong" } },
            "case" => d with { Key = d.Key with { Case = "wrong" } },
            _ => d with { Key = d.Key with { Scope = "wrong" } }
        };
        using NativeEnvironment environment = Environment(new("http://127.0.0.1:1/"));
        NativeCaseResult result = await RunAsync(environment, d, new());
        await Assert.That(result.ReasonCode).IsEqualTo(field == "scope" ? "missing-input" : "contract-mismatch");
    }

    [Test]
    [Arguments("selected-contract", "good", "observed")]
    [Arguments("independent-effect", "good", "observed")]
    [Arguments("denied-authority", "good", "observed")]
    [Arguments("cancellation-boundary", "good", "observed")]
    [Arguments("lost-response-no-replay", "good", "observed")]
    [Arguments("independent-effect", "heartbeat-drift", "effect-mismatch")]
    [Arguments("independent-effect", "cleanup", "cleanup-incomplete")]
    public async Task GatewayCreationMeasuresActualAgentAndCleanup(string caseName, string mode, string reason)
    {
        await using var backend = new Backend(mode);
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment, Definition("GatewayAdministrationOperations.Create",
            "auth.Token", caseName), backend.Observers);
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(backend.AdministrativeMutations).IsEqualTo(
            caseName is "denied-authority" or "cancellation-boundary" ? 0 : 1);
        if (mode != "cleanup") await Assert.That(backend.GatewayCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("auth.Aws")]
    [Arguments("Aws.allowedAccountIds.empty")]
    [Arguments("Aws.allowedPrincipalArns.value")]
    [Arguments("auth.Gcp.Gce")]
    [Arguments("auth.Gcp.Iam")]
    [Arguments("Gcp.allowedZones.value")]
    [Arguments("auth.Kubernetes.Api")]
    [Arguments("gatewayId.null")]
    [Arguments("gatewayPoolId.value")]
    [Arguments("verifyTlsCertificate.false")]
    [Arguments("Kubernetes.tokenReviewerJwt.value")]
    public async Task GatewayBranchesUseTheirActualTypedInputs(string variant)
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment,
            Definition("GatewayAdministrationOperations.Create", variant), backend.Observers);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.AcceptedAgents).IsEqualTo(1);
        await Assert.That(backend.GatewayCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    public async Task EnrollmentUsesReturnedTokenAndNativeHeartbeat(string caseName)
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment, Definition("GatewayAdministrationOperations.GenerateEnrollmentToken",
            "input.organizationId-gatewayId", caseName), backend.Observers);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.AcceptedAgents).IsEqualTo(caseName is "denied-authority" or "cancellation-boundary" ? 0 : 1);
        await Assert.That(backend.GatewayCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task SuppliedGatewayUpdateIsObservedWithoutAssumingNestedPatchPersistence(string caseName)
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment,
            Definition("GatewayAdministrationOperations.Update", "name.value", caseName), backend.Observers);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.GatewayCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("CreateShare", "password.value", "selected-contract")]
    [Arguments("CreateShare", "maximumViews.value", "independent-effect")]
    [Arguments("CreateShare", "authorizedEmails.values", "selected-contract")]
    [Arguments("CreateShare", "audience.Anyone", "selected-contract")]
    [Arguments("CreateShare", "password.omitted", "denied-authority")]
    [Arguments("CreateShare", "password.value", "cancellation-boundary")]
    [Arguments("CreateShare", "password.value", "lost-response-no-replay")]
    [Arguments("GetShare", "selector.exact", "selected-contract")]
    [Arguments("DeleteShare", "input.organizationId-shareId", "independent-effect")]
    [Arguments("ListShares", "collection.bounded", "selected-contract")]
    [Arguments("AccessShare", "password.value", "selected-contract")]
    [Arguments("AccessShare", "password.omitted", "lost-response-no-replay")]
    public async Task SharingMeasuresRecipientMaterialViewsExpiryAndDenial(string operation, string variant, string caseName)
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment,
            Definition("SharingOperations." + operation, variant, caseName), backend.Observers);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.ShareCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("CreateShare", "password.value", "share-renamed")]
    [Arguments("GetShare", "selector.exact", "share-renamed")]
    [Arguments("GetShare", "selector.exact", "share-delete-renamed")]
    public async Task RenamedAcknowledgedShareCannotBeCertifiedAsCleaned(string operation, string variant, string mode)
    {
        await using var backend = new Backend(mode);
        using NativeEnvironment environment = Environment(backend.Origin);

        NativeCaseResult result = await RunAsync(environment,
            Definition("SharingOperations." + operation, variant), backend.Observers);

        await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(backend.ShareCount).IsEqualTo(1);
    }

    [Test]
    [Arguments("SetOrganizationAuditSettings", "isEnabled.false", "selected-contract")]
    [Arguments("SetProjectAuditSettings", "eventClass.Authorization", "selected-contract")]
    [Arguments("SetProjectAuditSettings", "eventClass.Authentication", "denied-authority")]
    [Arguments("SetProjectAuditSettings", "eventClass.Authentication", "cancellation-boundary")]
    [Arguments("SetProjectAuditSettings", "eventClass.Authentication", "lost-response-no-replay")]
    [Arguments("GetOrganizationAuditSettings", "eventClass.Authentication", "selected-contract")]
    [Arguments("ReadAudit", "eventClass.array.values", "selected-contract")]
    [Arguments("ReadAudit", "eventType.array.catalog-values", "selected-contract")]
    [Arguments("ReadAudit", "actor.value", "selected-contract")]
    public async Task AuditNeedsASeparatelyProducedEvent(string operation, string variant, string caseName)
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment,
            Definition("GovernanceOperations." + operation, variant, caseName), backend.Observers);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.ProducedEvents).IsEqualTo(1);
        await Assert.That(backend.AuditScopeCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("SetOrganizationAuditSettings", "eventClass.Management")]
    [Arguments("SetOrganizationAuditSettings", "eventClass.DataAccess")]
    [Arguments("SetProjectAuditSettings", "eventClass.Management")]
    [Arguments("SetProjectAuditSettings", "eventClass.DataAccess")]
    public async Task PermanentAuditClassWritesRejectBeforeOwnedSetupOrProducer(string operation, string variant)
    {
        foreach (string caseName in new[] { "selected-contract", "independent-effect", "denied-authority",
            "cancellation-boundary", "lost-response-no-replay" })
        {
            await using var backend = new Backend("good");
            using NativeEnvironment environment = Environment(backend.Origin);
            var result = await RunAsync(environment, Definition("GovernanceOperations." + operation, variant, caseName),
                backend.Observers);

            await Assert.That(result.ReasonCode).IsEqualTo("observed");
            await Assert.That(backend.AuditProvisions).IsEqualTo(0);
            await Assert.That(backend.ProducedEvents).IsEqualTo(0);
            await Assert.That(backend.AdministrativeMutations).IsEqualTo(0);
            await Assert.That(backend.AuditScopeCount).IsEqualTo(0);
        }
    }

    [Test]
    [Arguments("Create", "credential.static-secret", "selected-contract")]
    [Arguments("Create", "credential.role.CredentialSubstitution", "independent-effect")]
    [Arguments("Create", "credential.surface.Path", "selected-contract")]
    [Arguments("Create", "credential.surface.Query", "selected-contract")]
    [Arguments("Create", "credential.surface.Body", "selected-contract")]
    [Arguments("Create", "credential.dynamic-secret", "selected-contract")]
    [Arguments("Create", "ProxiedServiceCreation.isEnabled.false", "selected-contract")]
    [Arguments("Create", "credential.static-secret", "denied-authority")]
    [Arguments("Create", "credential.static-secret", "cancellation-boundary")]
    [Arguments("Create", "credential.static-secret", "lost-response-no-replay")]
    [Arguments("Delete", "input.organizationId-projectId-serviceId", "selected-contract")]
    [Arguments("Get", "selector.exact", "selected-contract")]
    [Arguments("GetByName", "secretPath.value", "selected-contract")]
    [Arguments("List", "secretPath.omitted", "selected-contract")]
    public async Task ProxyRequiresActualTunneledBackendDelivery(string operation, string variant, string caseName)
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment,
            Definition("ProxiedServiceAdministrationOperations." + operation, variant, caseName), backend.Observers);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.ProjectCount).IsEqualTo(0);
        await Assert.That(backend.ProxyCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("factory.i.management.GatewayAdministrationOperations.Create", "selected-contract")]
    [Arguments("factory.i.management.SharingOperations.CreateShare", "lost-response-no-replay")]
    [Arguments("factory.i.management.GovernanceOperations.SetProjectAuditSettings", "denied-authority")]
    [Arguments("factory.i.management.ProxiedServiceAdministrationOperations.Create", "independent-effect")]
    public async Task GenericClientExecutesTheSelectedClosedFactory(string variant, string caseName)
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment, Definition("ManagementClient.ExecuteAsync", variant, caseName),
            backend.Observers);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.GatewayCount + backend.ShareCount + backend.ProxyCount + backend.ProjectCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("proxy-value")]
    [Arguments("proxy-surface")]
    [Arguments("audit-event")]
    [Arguments("share-material")]
    [Arguments("share-denial")]
    public async Task MetadataCannotConcealAnIncorrectIndependentEffect(string fault)
    {
        await using var backend = new Backend(fault);
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseDefinition definition = fault.StartsWith("proxy", StringComparison.Ordinal) ?
            Definition("ProxiedServiceAdministrationOperations.Create", "credential.surface.Path", "independent-effect") :
            fault == "audit-event" ? Definition("GovernanceOperations.SetProjectAuditSettings", "eventClass.Authentication", "independent-effect") :
            Definition("SharingOperations.CreateShare", "password.value", "independent-effect");
        NativeCaseResult result = await RunAsync(environment, definition, backend.Observers);
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
        await Assert.That(backend.ProjectCount + backend.ProxyCount + backend.ShareCount + backend.AuditScopeCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("share")]
    [Arguments("proxy")]
    public async Task CleanupNeverDeletesASubstitutedResourceId(string kind)
    {
        await using var backend = new Backend(kind + "-cleanup-substitution");
        using NativeEnvironment environment = Environment(backend.Origin);
        var definition = kind == "share" ? Definition("SharingOperations.GetShare", "selector.exact") :
            Definition("ProxiedServiceAdministrationOperations.Get", "selector.exact");
        var result = await RunAsync(environment, definition, backend.Observers);
        await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(kind == "share" ? backend.ShareCount : backend.ProxyCount).IsEqualTo(2);
    }

    [Test]
    [Arguments("actor.value")]
    [Arguments("eventClass.array.values")]
    [Arguments("eventType.array.catalog-values")]
    [Arguments("actorType.selected")]
    [Arguments("environment.value")]
    [Arguments("eventMetadata.value")]
    [Arguments("secretKey.value")]
    [Arguments("secretPath.value")]
    [Arguments("userAgentType.selected")]
    public async Task IgnoredAuditSelectorsCannotCertifyFiltering(string variant)
    {
        await using var backend = new Backend("ignore-audit-selectors");
        using NativeEnvironment environment = Environment(backend.Origin);
        var result = await RunAsync(environment, Definition("GovernanceOperations.ReadAudit", variant), backend.Observers);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.AuditScopeCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("actor.value")]
    [Arguments("actorType.selected")]
    [Arguments("environment.value")]
    [Arguments("eventMetadata.value")]
    [Arguments("secretKey.value")]
    [Arguments("secretPath.value")]
    [Arguments("userAgentType.selected")]
    [Arguments("eventClass.array.values")]
    [Arguments("eventType.array.catalog-values")]
    [Arguments("selectors.omitted")]
    [Arguments("eventClass.array.empty")]
    [Arguments("eventType.array.empty")]
    public async Task AuditSelectorsUsePositiveNegativeAndTimeWindowQueries(string variant)
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        var result = await RunAsync(environment, Definition("GovernanceOperations.ReadAudit", variant), backend.Observers);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.ProducedEvents).IsEqualTo(1);
        await Assert.That(backend.AuditScopeCount).IsEqualTo(0);
    }

    [Test]
    public async Task DuplicateAuditPersistenceCannotCertifySettings()
    {
        await using var backend = new Backend("duplicate-audit");
        using NativeEnvironment environment = Environment(backend.Origin);
        var result = await RunAsync(environment, Definition("GovernanceOperations.SetProjectAuditSettings",
            "eventClass.Authentication"), backend.Observers);
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
    }

    [Test]
    public async Task UnlimitedRecipientAccessCannotCertifyMaximumViews()
    {
        await using var backend = new Backend("unlimited-views");
        using NativeEnvironment environment = Environment(backend.Origin);
        var result = await RunAsync(environment, Definition("SharingOperations.CreateShare",
            "maximumViews.value"), backend.Observers);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.ShareCount).IsEqualTo(0);
    }

    [Test]
    public async Task InterruptedDeniedRecipientAccessDisposesTheEarlierMaterialCopy()
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        using SecretMaterial material = SecretMaterial.FromText("owned-recipient-material");
        var created = await backend.ReadAsync(() => SharingOperations.CreateShare(Org, "owned", material,
            5, ShareAudience.Organization), Org, environment.Tokens(NativeIdentityRole.Setup), CancellationToken.None);
        using var share = created.Value;
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var denied = new CancelOnToken(cancellation);
        try
        {
            await Assert.That(async () =>
            {
                using var facts = await backend.DeliverAsync(Org, share.Metadata.Id, null,
                    environment.Tokens(NativeIdentityRole.Runtime), denied, cancellation.Token);
            }).Throws<OperationCanceledException>();
            await Assert.That(denied.Entered.Task.IsCompletedSuccessfully).IsTrue();
            await Assert.That(backend.CopiedShareMaterial).IsNotNull();
            await Assert.That(() => backend.CopiedShareMaterial!.Reveal()).Throws<ObjectDisposedException>();
        }
        finally { backend.CopiedShareMaterial?.Dispose(); }
    }

    private sealed class CancelOnToken(CancellationTokenSource cancellation) : IInfisicalTokenSource
    {
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            Entered.TrySetResult();
            cancellation.Cancel();
            token.ThrowIfCancellationRequested();
            throw new InvalidOperationException("unreachable-token-boundary");
        }
    }

    [Test]
    public async Task MissingHostObserverFailsBeforeSetup()
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment,
            Definition("GatewayAdministrationOperations.Create", "auth.Token"), new());
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(backend.GatewayCount + backend.AdministrativeMutations).IsEqualTo(0);
    }

    [Test]
    public async Task ObserverFactsRedactCoordinatesAndMaterial()
    {
        const string protectedValue = "protected-observer-coordinate";
        using var proxy = new ProxyCredentialFixture(protectedValue, protectedValue, protectedValue,
            protectedValue, SecretMaterial.FromText(protectedValue));
        using var delivery = new ShareDeliveryFacts(protectedValue, SecretStatus.Success, SecretStatus.Denied,
            0, 1, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, SecretStatus.Absent,
            SecretMaterial.FromText(protectedValue), ShareAudience.Organization, 3, false, [protectedValue]);
        foreach (object value in new object[]
        {
            proxy, delivery, new GatewayAgentFacts(protectedValue, protectedValue, GatewayAuthenticationMethod.Token, DateTimeOffset.UnixEpoch, 1),
            new GatewayEnrollmentFacts(protectedValue, 1, 1), new OwnedAuditScope(protectedValue, protectedValue, protectedValue),
            new AuditEventFacts(protectedValue, 1, [protectedValue], [AuditEventClass.Management]),
            new AuditCleanupFacts(protectedValue, 0, 0), new ShareAccessFacts(protectedValue, 1)
        })
        {
            await Assert.That(value.ToString()!.Contains(protectedValue, StringComparison.Ordinal)).IsFalse();
            await Assert.That(JsonSerializer.Serialize(value).Contains(protectedValue, StringComparison.Ordinal)).IsFalse();
        }
    }

    private static NativeCaseDefinition Definition(string suffix, string variant, string caseName = "selected-contract")
    {
        string operation = "i.management." + suffix;
        return new(new("Infisical", operation, variant, "local", caseName),
            InfisicalGovernanceFamilies.Bindings[operation].Member);
    }

    private static async Task<NativeCaseResult> RunAsync(NativeEnvironment environment, NativeCaseDefinition d,
        GovernanceObservers observers)
    {
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, environment, [d], observers);
        return (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None))[0];
    }

    private static NativeEnvironment Environment(Uri origin, bool scopes = true)
    {
        var input = new
        {
            organizationId = Org,
            administrativeIdentityId = "00000000-0000-0000-0000-000000000002",
            observerIdentityId = "00000000-0000-0000-0000-000000000003",
            runtimeIdentityId = Identity,
            allowedAccountIds = "123456789012",
            allowedPrincipalArns = "arn:aws:iam::123456789012:role/witness",
            allowedProjects = "project-witness",
            allowedServiceAccounts = "witness@example.test",
            allowedZones = "zone-witness",
            allowedNames = "witness",
            allowedNamespaces = "witness",
            caCertificate = "certificate-witness",
            gatewayId = "00000000-0000-0000-0000-000000000005",
            gatewayPoolId = "00000000-0000-0000-0000-000000000006",
            kubernetesHost = "https://kubernetes.example.test",
            tokenReviewerJwt = "jwt-witness",
            recipientEmail = "recipient@example.test",
            secondRecipientEmail = "second@example.test"
        };
        var families = new Dictionary<string, object>();
        foreach (string family in new[] { "GatewayAdministration", "Governance", "ProxiedServiceAdministration", "ManagementClient" })
            families["C08-IM-" + family] = new { scopes = scopes ? new Dictionary<string, object> { ["local"] = input } : [] };
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup-token",
            runtime = "runtime-token",
            denied = "denied-token",
            administrative = "administrative-token",
            observer = "observer-token",
            families
        }));
    }

    private sealed class Backend : IAsyncDisposable, IGatewayAgentObserver, IShareRecipientObserver,
        IAuditEventObserver, IProxyBackendObserver
    {
        private readonly string mode;
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stop = new();
        private readonly Task accepting;
        private readonly ConcurrentBag<Task> connections = [];
        private readonly object gate = new();
        private readonly Dictionary<string, JsonObject> gateways = [], shares = [], projects = [], services = [];
        private readonly Dictionary<string, string> shareValues = [], enrollmentTokens = [], proxyValues = [];
        private readonly Dictionary<string, int> issued = [], enrolled = [], views = [];
        private readonly HashSet<string> expiredShares = [];
        private readonly Dictionary<string, List<AuditClassSetting>> auditSettings = [];
        private readonly Dictionary<string, OwnedAuditScope> auditScopes = [];
        private readonly Dictionary<string, JsonObject> auditEvents = [];
        private readonly Dictionary<string, TriggeredAuditEvent> auditSelectors = [];
        private const string ForeignId = "00000000-0000-0000-0000-000000000099";
        internal SecretMaterial? CopiedShareMaterial { get; private set; }
        public Uri Origin { get; }
        public GovernanceObservers Observers => new() { Gateway = this, Share = this, Audit = this, Proxy = this };
        public int AdministrativeMutations { get; private set; }
        public int AcceptedAgents { get; private set; }
        public int ProducedEvents { get; private set; }
        public int GatewayCount { get { lock (gate) return gateways.Count; } }
        public int ShareCount { get { lock (gate) return shares.Count; } }
        public int ProjectCount { get { lock (gate) return projects.Count; } }
        public int ProxyCount { get { lock (gate) return services.Count; } }
        public int AuditScopeCount { get { lock (gate) return auditSettings.Count; } }
        public int AuditProvisions { get; private set; }

        public Backend(string mode)
        {
            this.mode = mode;
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            accepting = AcceptAsync();
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (!stop.IsCancellationRequested)
                    connections.Add(HandleAsync(await listener.AcceptTcpClientAsync(stop.Token)));
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (SocketException) when (stop.IsCancellationRequested) { }
        }

        private async Task HandleAsync(TcpClient connection)
        {
            using (connection)
            {
                try
                {
                    NetworkStream stream = connection.GetStream();
                    var header = new List<byte>();
                    byte[] one = new byte[1];
                    while (header.Count < 65536)
                    {
                        if (await stream.ReadAsync(one, stop.Token) == 0) return;
                        header.Add(one[0]);
                        if (header.Count >= 4 && header[^4] == 13 && header[^3] == 10 && header[^2] == 13 && header[^1] == 10) break;
                    }
                    string[] lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                    string[] first = lines[0].Split(' ');
                    var headers = lines.Skip(1).Select(line => line.Split(':', 2))
                        .ToDictionary(parts => parts[0], parts => parts[1].Trim(), StringComparer.OrdinalIgnoreCase);
                    int length = headers.TryGetValue("Content-Length", out string? size) ? int.Parse(size, CultureInfo.InvariantCulture) : 0;
                    byte[] bytes = new byte[length];
                    await stream.ReadExactlyAsync(bytes, stop.Token);
                    JsonObject body = length == 0 ? new() : JsonNode.Parse(bytes)!.AsObject();
                    string role = headers["Authorization"].Replace("Bearer ", "", StringComparison.Ordinal);
                    Uri uri = new(Origin, first[1]);
                    (int status, JsonObject response) reply;
                    lock (gate) reply = Respond(first[0], uri, role, body);
                    byte[] response = Encoding.UTF8.GetBytes(reply.response.ToJsonString());
                    byte[] responseHeader = Encoding.ASCII.GetBytes($"HTTP/1.1 {reply.status} Response\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n");
                    await stream.WriteAsync(responseHeader, stop.Token);
                    await stream.WriteAsync(response, stop.Token);
                }
                catch (IOException) { }
                catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            }
        }

        private (int, JsonObject) Respond(string method, Uri uri, string role, JsonObject body)
        {
            if (role == "denied-token" && !(mode == "share-denial" && uri.AbsolutePath.EndsWith("/access", StringComparison.Ordinal)))
                return (403, new());
            string[] p = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (p[0] == "tunnel") return TunnelResponse(uri, p);
            if (method is "POST" or "PATCH" or "PUT" or "DELETE" && role == "administrative-token")
                AdministrativeMutations++;
            if (p[2] == "gateways")
            {
                if (p.Length == 3 && method == "POST")
                {
                    string id = Guid.NewGuid().ToString();
                    JsonObject auth = body["authMethod"]!.AsObject();
                    string kind = Text(auth, "method");
                    var config = new JsonObject();
                    if (kind is "aws" or "gcp" or "kubernetes")
                    {
                        config["id"] = Guid.NewGuid().ToString(); config["createdAt"] = Date; config["updatedAt"] = Date;
                        foreach ((string key, JsonNode? value) in auth.Where(a => a.Key != "method")) config[key] = value?.DeepClone();
                        foreach (string field in kind == "aws" ? new[] { "allowedAccountIds", "allowedPrincipalArns" } :
                            kind == "gcp" ? new[] { "allowedProjects", "allowedServiceAccounts", "allowedZones", "type" } :
                            new[] { "allowedAudience", "allowedNames", "allowedNamespaces", "caCertificate", "kubernetesHost", "tokenReviewMode" })
                            if (!config.ContainsKey(field)) config[field] = "";
                        if (kind == "kubernetes")
                        {
                            if (!config.ContainsKey("gatewayId")) config["gatewayId"] = null;
                            if (!config.ContainsKey("gatewayPoolId")) config["gatewayPoolId"] = null;
                            config["hasTokenReviewerJwt"] = auth["tokenReviewerJwt"] is not null && Text(auth, "tokenReviewerJwt") != "";
                            config["verifyTlsCertificate"] = auth["verifyTlsCertificate"]?.DeepClone() ?? JsonValue.Create(true);
                        }
                    }
                    gateways[id] = new JsonObject
                    {
                        ["id"] = id,
                        ["name"] = body["name"]!.DeepClone(),
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date,
                        ["canRevoke"] = true,
                        ["authMethod"] = new JsonObject { ["method"] = kind, ["config"] = config },
                        ["heartbeat"] = null,
                        ["identityId"] = null,
                        ["directAddress"] = null
                    };
                    issued[id] = 0; enrolled[id] = 0;
                    return (200, Clone(gateways[id]));
                }
                if (!gateways.TryGetValue(p[3], out JsonObject? g)) return (404, new());
                if (p.Length > 4)
                {
                    issued[p[3]]++;
                    string material = Guid.NewGuid().ToString("N");
                    enrollmentTokens[p[3]] = material;
                    return (200, new() { ["token"] = material, ["expiresAt"] = "2099-01-01T00:00:00.000Z" });
                }
                if (method == "PATCH") g["name"] = body["name"]!.DeepClone();
                return (200, Clone(g));
            }
            if (p[2] == "shared-secrets") return ShareResponse(method, p, body);
            if (uri.AbsolutePath.EndsWith("/audit-log-settings", StringComparison.Ordinal))
            {
                string scope = p[2] == "organization" ? "organization" : p[3];
                if (method == "PUT")
                    auditSettings[scope] = [new(AuditEventClass.Management, true), new(AuditEventClass.DataAccess, true),
                        .. body["eventClasses"]!.AsArray().Select(n =>
                            new AuditClassSetting(ParseClass(Text(n!.AsObject(), "eventClass")), n["isEnabled"]!.GetValue<bool>()))];
                return (200, new()
                {
                    ["auditLogSettings"] = new JsonObject
                    {
                        ["shouldUseNewPrivilegeSystem"] = true,
                        ["eventClasses"] = new JsonArray(auditSettings[scope].Select(s => (JsonNode)new JsonObject
                        { ["eventClass"] = Class(s.EventClass), ["isEnabled"] = s.IsEnabled }).ToArray())
                    }
                });
            }
            if (uri.AbsolutePath.EndsWith("/audit-logs", StringComparison.Ordinal))
            {
                var query = uri.Query.TrimStart('?').Split('&').Select(q => q.Split('=', 2))
                    .ToLookup(q => Uri.UnescapeDataString(q[0]), q => Uri.UnescapeDataString(q[1]));
                bool Matches(TriggeredAuditEvent e)
                {
                    foreach (var (field, value) in new[]
                    {
                        ("actor", e.Actor), ("actorType", e.ActorType), ("environment", e.Environment),
                        ("eventClass", Class(e.EventClass)), ("eventType", e.EventType),
                        ("eventMetadata", e.EventMetadata), ("secretKey", e.SecretKey),
                        ("secretPath", e.SecretPath), ("userAgentType", e.UserAgentType)
                    })
                        if (mode != "ignore-audit-selectors" && query.Contains(field) && !query[field].Contains(value))
                            return false;
                    var timestamp = DateTimeOffset.Parse(Date, CultureInfo.InvariantCulture);
                    return timestamp >= DateTimeOffset.Parse(query["startDate"].Single(), CultureInfo.InvariantCulture) &&
                        timestamp <= DateTimeOffset.Parse(query["endDate"].Single(), CultureInfo.InvariantCulture);
                }
                return (200, new()
                {
                    ["auditLogs"] = new JsonArray(auditEvents
                    .Where(e => Matches(auditSelectors[e.Key])).Select(e => e.Value.DeepClone()).ToArray())
                });
            }
            if (p[2] == "projects") return ProjectResponse(method, p, body);
            if (p[2] == "identities")
                return (200, new()
                {
                    ["identityMembership"] = new JsonObject
                    {
                        ["id"] = Guid.NewGuid().ToString(),
                        ["identityId"] = p[3],
                        ["projectId"] = Text(body, "projectId"),
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date
                    }
                });
            if (p[2] == "proxied-services") return ProxyResponse(method, uri, p, body);
            return (404, new());
        }

        private (int, JsonObject) ShareResponse(string method, string[] p, JsonObject body)
        {
            if (p.Length == 3 && method == "POST")
            {
                string id = Guid.NewGuid().ToString();
                shares[id] = new()
                {
                    ["id"] = id,
                    ["name"] = body["name"]!.DeepClone(),
                    ["orgId"] = Org,
                    ["expiresAt"] = "2099-01-01T00:00:00.000Z",
                    ["accessType"] = body["accessType"]!.DeepClone(),
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["type"] = "shared-secret",
                    ["isAuthorizedUser"] = true,
                    ["isPasswordProtected"] = body["password"] is not null,
                    ["allowExternalEmails"] = body["allowExternalEmails"]?.DeepClone() ?? JsonValue.Create(false),
                    ["expiresAfterViews"] = body["maxViews"]?.DeepClone(),
                    ["sharedSecretLink"] = "https://share.example.test/" + id,
                    ["authorizedEmails"] = body["authorizedEmails"]?.DeepClone(),
                    ["identityId"] = Identity,
                    ["lastViewedAt"] = null,
                    ["userId"] = null
                };
                shareValues[id] = Text(body, "secretValue"); views[id] = 0;
                if (mode == "share-cleanup-substitution")
                {
                    var foreign = Clone(shares[id]); foreign["id"] = ForeignId; foreign["name"] = "unrelated";
                    shares[ForeignId] = foreign; shareValues[ForeignId] = "unrelated"; views[ForeignId] = 0;
                }
                JsonObject created = Clone(shares[id]);
                created.Remove("isAuthorizedUser"); created.Remove("isPasswordProtected");
                return (200, created);
            }
            if (p.Length == 3)
                return (200, new()
                {
                    ["secrets"] = new JsonArray(shares.Values.Select(s =>
                    {
                        var value = ShareMetadata(s);
                        if (mode == "share-cleanup-substitution" && Text(s, "id") != ForeignId) value["id"] = ForeignId;
                        return (JsonNode)value;
                    }).ToArray()),
                    ["totalCount"] = shares.Count
                });
            if (!shares.TryGetValue(p[3], out JsonObject? share)) return (404, new());
            if (p.Length > 4 && expiredShares.Contains(p[3])) return (403, new());
            if (p.Length > 4 && mode != "unlimited-views" &&
                share["expiresAfterViews"]?.GetValue<int>() is { } maximum && views[p[3]] >= maximum)
                return (403, new());
            JsonObject result = ShareMetadata(share, method == "GET");
            if (method == "DELETE")
            {
                if (mode == "share-delete-renamed") share["name"] = "renamed-original";
                else { shares.Remove(p[3]); shareValues.Remove(p[3]); }
            }
            else if (p.Length > 4)
            {
                views[p[3]]++;
                result["secretValue"] = mode == "share-material" ? "incorrect-backend-material" : shareValues[p[3]];
                result["orgName"] = "witness";
            }
            return (200, result);
        }

        private static JsonObject ShareMetadata(JsonObject share, bool inspection = false)
        {
            JsonObject result = Clone(share);
            result.Remove("sharedSecretLink");
            if (inspection) { result.Remove("allowExternalEmails"); result.Remove("authorizedEmails"); }
            else { result.Remove("isAuthorizedUser"); result.Remove("isPasswordProtected"); }
            return result;
        }

        private (int, JsonObject) ProjectResponse(string method, string[] p, JsonObject body)
        {
            if (p.Length == 3 && method == "POST")
            {
                string id = Guid.NewGuid().ToString();
                projects[id] = new()
                {
                    ["id"] = id,
                    ["_id"] = id,
                    ["orgId"] = Org,
                    ["name"] = body["projectName"]!.DeepClone(),
                    ["slug"] = body["slug"]!.DeepClone(),
                    ["type"] = "secret-manager",
                    ["hasDeleteProtection"] = false,
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["environments"] = new JsonArray(),
                    ["deletedEnvironments"] = new JsonArray(),
                    ["description"] = null,
                    ["auditLogsRetentionDays"] = 30,
                    ["secretSharing"] = false,
                    ["autoCapitalization"] = false,
                    ["enforceEncryptedSecretManagerSecretMetadata"] = false,
                    ["pitVersionLimit"] = 10,
                    ["showSnapshotsLegacy"] = false,
                    ["secretDetectionIgnoreValues"] = new JsonArray()
                };
                return (200, new() { ["project"] = Clone(projects[id]) });
            }
            string? key = p[3] == "slug" ? projects.Keys.SingleOrDefault(id => Text(projects[id], "slug") == p[4]) : p[3];
            if (key is null || !projects.TryGetValue(key, out JsonObject? project)) return (404, new());
            if (p.Length > 4 && p[4] == "memberships")
                return (200, new()
                {
                    ["identityMembership"] = new JsonObject
                    {
                        ["id"] = Guid.NewGuid().ToString(),
                        ["identityId"] = p[6],
                        ["projectId"] = key,
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date
                    }
                });
            if (p.Length > 4 && p[4] == "environments")
            {
                string id = Guid.NewGuid().ToString();
                var environment = new JsonObject
                {
                    ["id"] = id,
                    ["projectId"] = key,
                    ["name"] = body["name"]!.DeepClone(),
                    ["slug"] = body["slug"]!.DeepClone(),
                    ["position"] = 1,
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["softDeletedAt"] = null,
                    ["deleteAfter"] = null
                };
                project["environments"]!.AsArray().Add(new JsonObject
                { ["id"] = id, ["name"] = body["name"]!.DeepClone(), ["slug"] = body["slug"]!.DeepClone() });
                return (200, new() { ["environment"] = environment, ["projectId"] = key });
            }
            JsonObject result = Clone(project);
            if (method == "DELETE")
            {
                projects.Remove(key);
                result.Remove("_id"); result.Remove("environments"); result.Remove("deletedEnvironments");
            }
            if (p[3] == "slug")
            {
                result.Remove("_id"); result.Remove("environments"); result.Remove("deletedEnvironments");
                return (200, result);
            }
            return (200, new() { ["project"] = result });
        }

        private (int, JsonObject) ProxyResponse(string method, Uri uri, string[] p, JsonObject body)
        {
            if (p.Length == 3 && method == "POST")
            {
                string id = Guid.NewGuid().ToString();
                var credentials = new JsonArray(body["credentials"]!.AsArray().Select(n =>
                {
                    JsonObject c = Clone(n!.AsObject()); c["id"] = Guid.NewGuid().ToString(); c["serviceId"] = id; c["callerCanLease"] = true;
                    return (JsonNode)c;
                }).ToArray());
                services[id] = new()
                {
                    ["id"] = id,
                    ["name"] = body["name"]!.DeepClone(),
                    ["folderId"] = Guid.NewGuid().ToString(),
                    ["hostPattern"] = body["hostPattern"]!.DeepClone(),
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["isEnabled"] = body["isEnabled"]?.DeepClone() ?? JsonValue.Create(true),
                    ["canProxy"] = true,
                    ["credentials"] = credentials
                };
                if (mode == "proxy-cleanup-substitution")
                {
                    var foreign = Clone(services[id]); foreign["id"] = ForeignId; foreign["name"] = "unrelated";
                    services[ForeignId] = foreign;
                }
                return (200, new() { ["service"] = Clone(services[id]) });
            }
            if (p.Length == 3)
            {
                var query = Query(uri);
                string slug = Text(projects[query["projectId"]], "slug");
                return (200, new() { ["projectSlug"] = slug, ["services"] = new JsonArray(services.Values.Select(s => s.DeepClone()).ToArray()) });
            }
            string? key = p[3] == "slug" ? services.Keys.SingleOrDefault(id => Text(services[id], "name") == p[4]) : p[3];
            if (key is null || !services.TryGetValue(key, out JsonObject? service)) return (404, new());
            JsonObject result = Clone(service);
            if (p[3] == "slug" && mode == "proxy-cleanup-substitution")
            {
                result["id"] = ForeignId;
                foreach (var credential in result["credentials"]!.AsArray()) credential!["serviceId"] = ForeignId;
            }
            if (method == "DELETE") { services.Remove(key); result.Remove("credentials"); }
            return (200, new() { ["service"] = result });
        }

        private (int, JsonObject) TunnelResponse(Uri uri, string[] path)
        {
            if (!services.TryGetValue(path[1], out JsonObject? service)) return (404, new());
            if (!service["isEnabled"]!.GetValue<bool>()) return (403, new());
            JsonObject credential = service["credentials"]![0]!.AsObject();
            string role = Text(credential, "role");
            string surface = credential["substitutionSurfaces"]?[0]?.GetValue<string>() ?? "header";
            if (mode == "proxy-surface") surface = "body";
            string name = Text(service, "name");
            string actual = (credential["headerPrefix"]?.GetValue<string>() ?? "") + proxyValues[name];
            if (mode == "proxy-value") actual = "incorrect-backend-material";
            // This is the owned loopback proxy's backend request capture, not canProxy metadata.
            return (200, new()
            {
                ["serviceId"] = path[1],
                ["challenge"] = path[2],
                ["backendRequests"] = 1,
                ["role"] = role,
                ["surface"] = surface,
                ["headerName"] = credential["headerName"]?.DeepClone(),
                ["value"] = actual
            });
        }

        public async ValueTask<SecretOutcome<GatewaySummary>> FindOwnedAsync(string organizationId, string name,
            IInfisicalTokenSource observer, CancellationToken token)
        {
            string? id;
            lock (gate) id = gateways.Keys.SingleOrDefault(k => Text(gateways[k], "name") == name);
            if (id is null) return SecretOutcome<GatewaySummary>.Failure(SecretStatus.Absent);
            return await ReadAsync(() => GatewayAdministrationOperations.Get(organizationId, id), organizationId, observer, token);
        }

        public async ValueTask<GatewayAgentFacts> AuthenticateAsync(string organizationId, GatewaySummary gateway,
            IInfisicalTokenSource runtime, CancellationToken token)
        {
            using InfisicalAccessToken selected = (await runtime.GetTokenAsync(token)).Value;
            if (selected.Material.Reveal() != "runtime-token") throw new NativeCaseFailureException("effect-mismatch");
            lock (gate)
            {
                gateways[gateway.Id]["heartbeat"] = Date; gateways[gateway.Id]["identityId"] = Identity; AcceptedAgents++;
                return new GatewayAgentFacts(gateway.Id, Identity, gateway.Authentication.Method,
                    mode == "heartbeat-drift" ? DateTimeOffset.Parse(Date, CultureInfo.InvariantCulture).AddMinutes(1) :
                        DateTimeOffset.Parse(Date, CultureInfo.InvariantCulture), 1);
            }
        }

        public ValueTask<GatewayAgentFacts> EnrollAsync(string organizationId, GatewaySummary gateway,
            SecretMaterial enrollmentToken, IInfisicalTokenSource runtime, CancellationToken token)
        {
            lock (gate)
            {
                if (enrollmentTokens[gateway.Id] != enrollmentToken.Reveal()) throw new NativeCaseFailureException("effect-mismatch");
                enrolled[gateway.Id]++;
            }
            return AuthenticateAsync(organizationId, gateway, runtime, token);
        }

        public ValueTask<GatewayEnrollmentFacts> ObserveEnrollmentAsync(string gatewayId, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (gate) return ValueTask.FromResult(new GatewayEnrollmentFacts(gatewayId, issued[gatewayId], enrolled[gatewayId]));
        }

        public ValueTask<SecretStatus> RemoveOwnedAsync(string organizationId, string name, IInfisicalTokenSource setup,
            CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (gate)
            {
                string? id = gateways.Keys.SingleOrDefault(k => Text(gateways[k], "name") == name);
                if (id is null) return ValueTask.FromResult(SecretStatus.Absent);
                if (mode == "cleanup") return ValueTask.FromResult(SecretStatus.Denied);
                gateways.Remove(id); return ValueTask.FromResult(SecretStatus.Success);
            }
        }

        async ValueTask<SecretOutcome<SharedSecretMetadata>> IShareRecipientObserver.FindOwnedAsync(string organizationId,
            string name, IInfisicalTokenSource observer, CancellationToken token)
        {
            SecretOutcome<ManagementPage<SharedSecretMetadata>> page = await ReadAsync(
                () => SharingOperations.ListShares(organizationId), organizationId, observer, token);
            if (!page.IsSuccess) return SecretOutcome<SharedSecretMetadata>.Failure(page.Status);
            SharedSecretMetadata? found = page.Value.Items.SingleOrDefault(m => m.Name == name);
            return found is null ? SecretOutcome<SharedSecretMetadata>.Failure(SecretStatus.Absent) :
                SecretOutcome<SharedSecretMetadata>.Success(found);
        }

        public ValueTask<ShareAccessFacts> ObserveViewsAsync(string shareId, IInfisicalTokenSource observer, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (gate) return ValueTask.FromResult(new ShareAccessFacts(shareId, views[shareId]));
        }

        public async ValueTask<ShareDeliveryFacts> DeliverAsync(string organizationId, string shareId, SecretMaterial? password,
            IInfisicalTokenSource runtime, IInfisicalTokenSource denied, CancellationToken token)
        {
            int before;
            DateTimeOffset expiry;
            ShareAudience audience;
            int? maximumViews;
            bool? external;
            string[]? emails;
            lock (gate)
            {
                before = views[shareId];
                expiry = DateTimeOffset.Parse(Text(shares[shareId], "expiresAt"), CultureInfo.InvariantCulture);
                audience = Text(shares[shareId], "accessType") == "organization" ? ShareAudience.Organization : ShareAudience.Anyone;
                maximumViews = shares[shareId]["expiresAfterViews"]?.GetValue<int>();
                external = shares[shareId]["allowExternalEmails"]?.GetValue<bool>();
                emails = shares[shareId]["authorizedEmails"]?.AsArray().Select(e => e!.GetValue<string>()).ToArray();
            }
            SecretOutcome<SharedValue> received = await ReadAsync(() => SharingOperations.AccessShare(organizationId, shareId, password),
                organizationId, runtime, token);
            SecretMaterial? material = null;
            if (received.IsSuccess)
            {
                using SharedValue value = received.Value;
                material = value.Material.Copy();
                CopiedShareMaterial = material;
            }
            try
            {
                SecretOutcome<SharedValue> refused = await ReadAsync(() => SharingOperations.AccessShare(organizationId, shareId, password),
                    organizationId, denied, token);
                if (refused.IsSuccess) refused.Value.Dispose();
                int after;
                lock (gate) after = views[shareId];
                ShareViewLimitFacts? limit = null;
                if (maximumViews is { } maximum)
                {
                    for (int consumed = after; consumed < maximum; consumed++)
                    {
                        var next = await ReadAsync(() => SharingOperations.AccessShare(organizationId, shareId, password),
                            organizationId, runtime, token);
                        if (!next.IsSuccess) throw new NativeCaseFailureException("effect-mismatch");
                        next.Value.Dispose();
                    }
                    int atLimit;
                    lock (gate) atLimit = views[shareId];
                    var exhausted = await ReadAsync(() => SharingOperations.AccessShare(organizationId, shareId, password),
                        organizationId, runtime, token);
                    bool returned = exhausted.IsSuccess;
                    if (returned) exhausted.Value.Dispose();
                    int remaining;
                    lock (gate) remaining = views[shareId];
                    limit = new(maximum, atLimit, remaining, DateTimeOffset.Parse(Date, CultureInfo.InvariantCulture),
                        exhausted.Status, returned);
                }
                // Expiry is isolated by the unlimited variants. An exhausted share's
                // later denial cannot independently establish expiry enforcement.
                lock (gate) expiredShares.Add(shareId);
                SecretOutcome<SharedValue> expired = await ReadAsync(() => SharingOperations.AccessShare(organizationId, shareId, password),
                    organizationId, runtime, token);
                if (expired.IsSuccess) expired.Value.Dispose();
                var facts = new ShareDeliveryFacts(shareId, received.Status, refused.Status, before, after,
                    expiry, expiry, expired.Status, material, audience, maximumViews, external, emails, limit);
                material = null;
                if (mode == "share-renamed")
                {
                    lock (gate) shares[shareId]["name"] = "renamed-original";
                }
                return facts;
            }
            finally { material?.Dispose(); }
        }

        public ValueTask<OwnedAuditScope> ProvisionAsync(string ownedName, bool projectScope, IInfisicalTokenSource setup,
            IInfisicalTokenSource administrative, IInfisicalTokenSource observer, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var scope = new OwnedAuditScope(Guid.NewGuid().ToString(), projectScope ? Guid.NewGuid().ToString() : null, ownedName);
            lock (gate)
            {
                AuditProvisions++;
                auditScopes[ownedName] = scope;
                auditSettings[scope.ProjectId ?? "organization"] = [new(AuditEventClass.Management, true),
                    new(AuditEventClass.DataAccess, true), new(AuditEventClass.Authentication, false),
                    new(AuditEventClass.Authorization, false)];
            }
            return ValueTask.FromResult(scope);
        }

        public ValueTask<TriggeredAuditEvent> TriggerAsync(OwnedAuditScope scope, AuditEventClass eventClass, string correlation,
            IInfisicalTokenSource runtime, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var from = DateTimeOffset.Parse(Date, CultureInfo.InvariantCulture);
            var triggered = new TriggeredAuditEvent(Guid.NewGuid().ToString(), correlation, scope.OrganizationId, scope.ProjectId,
                eventClass, "get-secret", from.AddMinutes(-1), from.AddMinutes(1), Identity, "identity", "witness",
                "WITNESS", "/", "metadata-witness", "cli");
            lock (gate)
            {
                ProducedEvents++;
                auditSelectors[triggered.Id] = triggered;
                if (mode != "audit-event" && auditSettings[scope.ProjectId ?? "organization"].Any(s => s.EventClass == eventClass && s.IsEnabled))
                    auditEvents[triggered.Id] = new()
                    {
                        ["id"] = triggered.Id,
                        ["orgId"] = scope.OrganizationId,
                        ["projectId"] = scope.ProjectId,
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date,
                        ["actor"] = new JsonObject { ["type"] = "identity" },
                        ["event"] = new JsonObject { ["type"] = "get-secret", ["class"] = Class(eventClass) }
                    };
            }
            return ValueTask.FromResult(triggered);
        }

        public ValueTask<AuditEventFacts> ObserveAsync(OwnedAuditScope scope, TriggeredAuditEvent triggered,
            IInfisicalTokenSource observer, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (gate) return ValueTask.FromResult(new AuditEventFacts(triggered.Correlation, ProducedEvents,
                mode == "duplicate-audit" ? [triggered.Id, triggered.Id] : auditEvents.Keys.ToArray(),
                auditSettings[scope.ProjectId ?? "organization"].Where(s => s.IsEnabled).Select(s => s.EventClass).ToArray()));
        }

        public ValueTask<AuditCleanupFacts> RemoveOwnedAsync(string ownedName, IInfisicalTokenSource setup, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (gate)
            {
                if (auditScopes.Remove(ownedName, out OwnedAuditScope? scope))
                    auditSettings.Remove(scope.ProjectId ?? "organization");
                auditEvents.Clear();
                auditSelectors.Clear();
                return ValueTask.FromResult(new AuditCleanupFacts(ownedName, auditScopes.Count, auditScopes.Count(s => s.Value.ProjectId is not null)));
            }
        }

        public ValueTask<ProxyCredentialFixture> PrepareAsync(string organizationId, string projectId, string environment,
            string ownedName, IInfisicalTokenSource setup, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (gate) proxyValues[ownedName] = Guid.NewGuid().ToString("N");
            return ValueTask.FromResult(new ProxyCredentialFixture("WITNESS", "dynamic-witness", "password",
                "backend.example.test", SecretMaterial.FromText(proxyValues[ownedName])));
        }

        public ValueTask<ProxyBackendFacts> SendThroughAsync(string serviceId, string challenge, ProxiedServiceCredentialRole role,
            ProxiedServiceSubstitutionSurface surface, IInfisicalTokenSource selectedIdentity, CancellationToken token) =>
            SendProxyAsync(serviceId, challenge, selectedIdentity, token);

        private async ValueTask<ProxyBackendFacts> SendProxyAsync(string serviceId, string challenge,
            IInfisicalTokenSource selectedIdentity, CancellationToken token)
        {
            SecretOutcome<InfisicalAccessToken> result = await selectedIdentity.GetTokenAsync(token);
            using InfisicalAccessToken access = result.Value;
            using var http = new HttpClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(Origin, "tunnel/" + serviceId + "/" + challenge));
            request.Headers.Authorization = new("Bearer", access.Material.Reveal());
            using HttpResponseMessage response = await http.SendAsync(request, token);
            if (response.StatusCode != HttpStatusCode.OK)
                return new(serviceId, challenge, response.StatusCode == HttpStatusCode.Forbidden ?
                    SecretStatus.Denied : SecretStatus.Absent, 0, null);
            using JsonDocument json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(token));
            JsonElement measured = json.RootElement;
            return new(measured.GetProperty("serviceId").GetString()!, measured.GetProperty("challenge").GetString()!,
                SecretStatus.Success, measured.GetProperty("backendRequests").GetInt32(),
                SecretMaterial.FromText(measured.GetProperty("value").GetString()!),
                measured.GetProperty("role").GetString() == "header-rewrite" ?
                    ProxiedServiceCredentialRole.HeaderRewrite : ProxiedServiceCredentialRole.CredentialSubstitution,
                measured.GetProperty("surface").GetString() switch
                {
                    "path" => ProxiedServiceSubstitutionSurface.Path,
                    "query" => ProxiedServiceSubstitutionSurface.Query,
                    "body" => ProxiedServiceSubstitutionSurface.Body,
                    _ => ProxiedServiceSubstitutionSurface.Header
                }, measured.GetProperty("headerName").GetString());
        }

        public ValueTask<SecretStatus> RemoveFixtureAsync(string projectId, string ownedName, IInfisicalTokenSource setup,
            CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (gate) proxyValues.Remove(ownedName);
            return ValueTask.FromResult(SecretStatus.Absent);
        }

        internal async ValueTask<SecretOutcome<T>> ReadAsync<T>(Func<ManagementRequest<T>> factory, string organizationId,
            IInfisicalTokenSource tokens, CancellationToken token) where T : notnull
        {
            using var transport = new ManagementTransport(Origin, allowLoopbackDevelopmentHttp: true);
            var client = new ManagementClient(transport);
            using ManagementRequest<T> request = factory();
            var authority = new ManagementAuthority(client.Authority, tokens, organizationId, request.Target.ProjectId);
            return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                request.IsMutation ? client.CreateReceipt(request) : null, token);
        }

        private static string Text(JsonObject value, string field) => value[field]!.GetValue<string>();
        private static JsonObject Clone(JsonObject value) => (JsonObject)value.DeepClone();
        private static Dictionary<string, string> Query(Uri uri) => uri.Query.TrimStart('?').Split('&')
            .Select(p => p.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]));
        private static string Class(AuditEventClass value) => value switch
        {
            AuditEventClass.Management => "management",
            AuditEventClass.Authentication => "authentication",
            AuditEventClass.Authorization => "authorization",
            _ => "data-access"
        };
        private static AuditEventClass ParseClass(string value) => value switch
        {
            "management" => AuditEventClass.Management,
            "authentication" => AuditEventClass.Authentication,
            "authorization" => AuditEventClass.Authorization,
            _ => AuditEventClass.DataAccess
        };
        public async ValueTask DisposeAsync()
        {
            stop.Cancel(); listener.Stop();
            await accepting; await Task.WhenAll(connections);
            stop.Dispose();
        }
    }
}
