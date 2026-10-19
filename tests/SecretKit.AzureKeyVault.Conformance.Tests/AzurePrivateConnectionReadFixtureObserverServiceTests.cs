using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Effects = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;
using PrivateReadSource = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultReadFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task PrivateConnectionReadMissingExplicitAuthoritiesCannotPrepareOrBorrowDefaults()
    {
        await using var f = new PrivateReadFixture();
        await using var source = f.Reopen(omitPrivate: true);
        using var observer = PrivateReadFixture.ObserverFor(source);
        await Assert.That(async () => await observer.PostAsync<Effects.Prepare, Effects.Lease>(
            "vault/prepare", f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Wire.Active).IsFalse();
        await Assert.That(f.Native.Wire.Secret is null).IsTrue();
        await Assert.That(f.Endpoint is null).IsTrue();
    }

    [Test]
    public async Task PrivateReadDispatchCannotBeClearedByGenericOrConstructedCapabilities()
    {
        await using var f = new PrivateReadFixture();
        var lease = await f.PrepareAndBaseline();
        f.Barrier = "selected-original-sdk";
        var read = f.Start(lease);
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var root = f.Native.Read();
            var child = root.PrivateEndpoint!.Connection!;
            var copiedParent = f.Parent.OpenCleanupPlan(Owner, f.Native.Selector);
            var forged = new VaultFixtureProvisioner.PrivateConnectionReadAdmission(f.Parent, copiedParent,
                null!, null!, child.Id);
            await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, child.Id, child.ActiveDispatch))
                .Throws<InvalidOperationException>();
            await Assert.That(() => f.Native.Journal.EndPrivateConnectionRead(Owner, f.Native.Selector, root.LeaseId,
                forged, child.ActiveDispatch)).Throws<InvalidOperationException>();
            await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(child.ActiveDispatch);
            await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.InvocationTerminated).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        await Assert.That((await read).Status).IsEqualTo(SecretStatus.Success);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task PrivateReadForeignScopeDoesNotConsumeTheValidOriginalRead()
    {
        await using var f = new PrivateReadFixture();
        var lease = await f.PrepareAndBaseline();
        var client = f.Client();
        await Assert.That(async () => await f.Source.RunGetPrivateConnectionAsync(f.Native.Selector, client,
            new(new(new(new(Subscription), "fixture-group"), lease.VaultName), "foreign-connection"), default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.SelectedReads).IsEqualTo(0);
        await Assert.That((await f.Start(lease)).Status).IsEqualTo(SecretStatus.Success);
        var measured = await f.Observe(lease);
        await Assert.That(measured.NetworkEffect!.PrivateReadStatus).IsEqualTo(SecretStatus.Denied);
        await Assert.That(measured.NetworkEffect.PublicReadStatus).IsEqualTo(SecretStatus.Success);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task PrivateReadCannotReplaySelectedGetOrMintApprovalSettlement()
    {
        await using var f = new PrivateReadFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedReads).IsEqualTo(1);
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PrivateReadRestartRetainsCleanupCoordinatesButCannotReconstructReadiness(bool afterRead)
    {
        await using var f = new PrivateReadFixture();
        var lease = await f.PrepareAndBaseline();
        if (afterRead) await f.Start(lease);
        await using var restarted = f.Reopen();
        await Assert.That(async () => await restarted.RunGetPrivateConnectionAsync(f.Native.Selector,
            f.Client(), f.Scope(lease), default)).Throws<InvalidOperationException>();
        using var observer = PrivateReadFixture.ObserverFor(restarted);
        RoleFixtureRelease.Validate(await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedReads).IsEqualTo(afterRead ? 1 : 0);
    }

    [Test]
    [Arguments("selected-arm", "credential", false)]
    [Arguments("selected-arm", "transport", true)]
    [Arguments("selected-arm", "body", false)]
    [Arguments("selected-original", "sdk", true)]
    [Arguments("connection-reader-arm", "credential", false)]
    [Arguments("connection-reader-arm", "transport", true)]
    [Arguments("connection-reader-arm", "body", false)]
    [Arguments("connection-reader-arm", "sdk", true)]
    [Arguments("endpoint-reader-arm", "credential", true)]
    [Arguments("endpoint-reader-arm", "transport", false)]
    [Arguments("endpoint-reader-arm", "body", true)]
    [Arguments("endpoint-reader-arm", "sdk", false)]
    [Arguments("read-arm", "credential", false)]
    [Arguments("read-arm", "transport", true)]
    [Arguments("read-arm", "body", false)]
    [Arguments("read-arm", "sdk", true)]
    [Arguments("read-secret", "credential", true)]
    [Arguments("read-secret", "transport", false)]
    [Arguments("read-secret", "body", true)]
    [Arguments("read-secret", "sdk", false)]
    [Arguments("private-runtime-secret", "credential", false)]
    [Arguments("private-runtime-secret", "transport", true)]
    [Arguments("private-runtime-secret", "body", false)]
    [Arguments("private-runtime-secret", "sdk", true)]
    [Arguments("public-runtime-secret", "credential", true)]
    [Arguments("public-runtime-secret", "transport", false)]
    [Arguments("public-runtime-secret", "body", true)]
    [Arguments("public-runtime-secret", "sdk", false)]
    public async Task PrivateReadClosureWaitsForActualSelectedAndIndependentBorrowers(string role, string stage, bool dispose)
    {
        await using var f = new PrivateReadFixture();
        var lease = await f.PrepareAndBaseline();
        bool selected = role.StartsWith("selected", StringComparison.Ordinal);
        if (!selected) await f.Start(lease);
        f.Barrier = role + "-" + stage;
        Task borrowed = selected ? f.Start(lease) : f.Observe(lease).AsTask();
        Task closing = Task.CompletedTask;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            closing = dispose ? f.Source.DisposeAsync().AsTask() : f.Release().AsTask();
            await Assert.That(f.Native.Read().Closing).IsTrue();
            await Assert.That(closing.IsCompleted).IsFalse();
            await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.SelectedAttempted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        bool rejected = false;
        try { await borrowed.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception failure) when (failure is OperationCanceledException or NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
        await closing.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(Guid.Empty);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalPrivateConnectionReadRequiresRealIndependentNetworkReads(string boundary)
    {
        await using var f = new PrivateReadFixture(boundary);
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        await Assert.That(f.PrivateReads > 0 && f.PublicReads > 0).IsTrue();
        await Assert.That(f.Native.Wire.Prejournaled).IsTrue();
        await Assert.That(f.Endpoint!.Requests.Any(r => r.Method == "DELETE")).IsTrue();
        await Assert.That(f.Endpoint.Requests.Any(r => r.Method != "GET" &&
            r.Path != f.Endpoint.Binding.EndpointId)).IsFalse();
        var child = f.Native.Read().PrivateEndpoint!.Connection!;
        await Assert.That(child.SelectedAttempted).IsFalse();
        await Assert.That(f.Native.Read().PrivateEndpoint!.ApprovalSettledDispatch).IsEqualTo(Guid.Empty);
    }

    [Test]
    [Arguments("private-success")]
    [Arguments("private-absent")]
    [Arguments("private-unavailable")]
    [Arguments("public-denied")]
    [Arguments("public-digest")]
    [Arguments("public-version")]
    [Arguments("private-no-request-id")]
    public async Task PrivateConnectionReadCannotInventTheRequiredRuntimeEvidence(string fault)
    {
        await using var f = new PrivateReadFixture { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedReads).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-endpoint")]
    [Arguments("selected-name")]
    [Arguments("selected-state")]
    [Arguments("selected-malformed")]
    [Arguments("selected-continuation")]
    [Arguments("selected-oversized")]
    [Arguments("denial-without-response")]
    [Arguments("post-endpoint")]
    public async Task PrivateConnectionReadOriginalAndIndependentNativeFactsMustAgree(string fault)
    {
        await using var f = new PrivateReadFixture { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedReads).IsEqualTo(1);
    }

    private sealed class PrivateReadFixture : IAsyncDisposable
    {
        private const string Capability = "controlled-private-connection-read";
        private static readonly Uri Origin = new("https://private-connection-read.invalid/");
        internal readonly Fixture Native = new(allowPurge: true);
        internal readonly PrivateReadSource Source;
        internal readonly OwnedManagementObserver Observer;
        internal EndpointBindingWire? Endpoint;
        private readonly Effects.Configuration baseline;
        private readonly VaultFixtureProvisioner provisioner;
        internal VaultFixtureProvisioner Parent => provisioner;
        private readonly SecretMaterial capability = SecretMaterial.FromText(Capability);
        private readonly List<HttpClient> clients = [];
        private readonly Dictionary<string, HttpPipelineTransport> transports = [];
        internal string? Fault, Barrier;
        internal int SelectedReads, PrivateReads, PublicReads;
        internal readonly bool Inventory;
        internal readonly bool Links;
        internal string[] LinkMembers = ["member-a", "member-b"];
        internal string[] LinkZones = ["zone-one.invalid", "zone-two.invalid"];
        internal int ChildObservations, LinkQueries;
        internal Request? CurrentConnectionRequest;
        internal string BarrierRole(string role, Request? request) =>
            Links && role == "connection-reader-arm" &&
            request?.Uri.ToUri().AbsolutePath.Contains("/privateLinkResources", StringComparison.Ordinal) == true
                ? "link-reader-arm" : role;
        internal readonly CollectionLimits OriginalLimits;
        internal VaultScope? OriginalListScope;
        internal int CollectionQueries;
        internal readonly TaskCompletionSource Entered = Signal(), Resume = Signal();
        private ObservationSubscription? subscription;

        internal PrivateReadFixture(string boundary = "selected-contract", bool inventory = false,
            CollectionLimits? limits = null, bool links = false)
        {
            Inventory = inventory;
            Links = links;
            OriginalLimits = limits ?? new(2, 32, TimeSpan.FromSeconds(20));
            Native.Selector = Native.Selector with
            {
                Operation = Effects.Members.Single(m => m.Operation.EndsWith(links ? ".ListPrivateLinkResourcesAsync" :
                    inventory ? ".ListPrivateConnectionsAsync" : ".GetPrivateConnectionAsync", StringComparison.Ordinal)).Operation,
                Variant = inventory || links ? "collection.bounded" : "selector.exact",
                Case = boundary
            };
            baseline = Native.Baseline with { PublicNetworkAccess = true };
            provisioner = new(Native.Journal, new(Subscription, "fixture-group", "eastus", Tenant, true, true), baseline,
                new("setup-arm", CredentialFor("setup-arm"), Transport("setup-arm")),
                new("setup-secret", CredentialFor("setup-secret"), Transport("setup-secret")),
                new("read-arm", CredentialFor("read-arm"), Transport("read-arm")),
                new("read-secret", CredentialFor("read-secret"), Transport("read-secret")),
                new(65536, TimeSpan.FromSeconds(20)));
            Source = Reopen();
            Observer = ObserverFor(Source);
        }
        private PrivateReadCredential CredentialFor(string role) => new(role, this);
        private HttpPipelineTransport Transport(string role)
        {
            if (transports.TryGetValue(role, out var existing)) return existing;
            var client = new HttpClient(new VaultForwarder((request, token) => Send(request, role, token)));
            clients.Add(client);
            var transport = new PrivateReadSdk(new HttpClientTransport(client), this, role);
            transports.Add(role, transport);
            return transport;
        }
        internal PrivateReadSource Reopen(bool omitPrivate = false) => new(Origin, Owner, "private-read-source", capability,
            new(Subscription, "fixture-group", "eastus", Tenant, true, true), provisioner,
            new("child-metadata", CredentialFor("metadata-arm"), Transport("metadata-arm")),
            Transport("selected-arm"),
            new(2, 32, 65536, 8192, TimeSpan.FromSeconds(20)),
            new(65536, 65536, TimeSpan.FromSeconds(20)), null,
            omitPrivate ? null : new(DeclaredSubnet,
                new("endpoint-setup", CredentialFor("endpoint-setup-arm"), Transport("endpoint-setup-arm")),
                new("endpoint-reader", CredentialFor("endpoint-reader-arm"), Transport("endpoint-reader-arm")),
                new("connection-reader", CredentialFor("connection-reader-arm"), Transport("connection-reader-arm")),
                new(65536, 8192, 4096, 32, 16, TimeSpan.FromSeconds(20)),
                new(2, 32, 65536, 8192, TimeSpan.FromSeconds(20)),
                new("private-runtime", CredentialFor("private-runtime-secret"), Transport("private-runtime-secret")),
                new("public-runtime", CredentialFor("public-runtime-secret"), Transport("public-runtime-secret")),
                new(65536, 8192, 4096, 4, 16, TimeSpan.FromSeconds(20))));
        internal static OwnedManagementObserver ObserverFor(PrivateReadSource source) =>
            new(new(Origin, Capability, TimeSpan.FromSeconds(20)), new VaultForwarder(source.DispatchAsync));
        internal Effects.Prepare PrepareRequest() => new(Native.Selector, Subscription, "fixture-group",
            baseline, [new(Tenant, Principal, [SecretPermission.Get], null)], Guid.Empty);
        internal async Task<Effects.Lease> PrepareAndBaseline()
        {
            var lease = await Observer.PostAsync<Effects.Prepare, Effects.Lease>("vault/prepare", PrepareRequest(), default);
            subscription = await Observer.SubscribeAsync("vault", lease.Facts, default);
            await Observe(lease, true);
            return lease;
        }
        internal ValueTask<Effects.Measurement> Observe(Effects.Lease lease, bool before = false) =>
            Observer.PostAsync<ObserveLease, Effects.Measurement>("vault/observe",
                new(lease.Facts.LeaseId, lease.Facts.Nonce, before ? "baseline-before-dispatch" : "post-operation",
                    subscription!.SubscriptionId), default);
        internal Task<SecretOutcome<PrivateConnectionObservation>> Start(Effects.Lease lease) =>
            Source.RunGetPrivateConnectionAsync(Native.Selector, Client(), Scope(lease), default).AsTask();
        internal VaultAdministration Client(string role = "selected-arm", bool bypassSource = false) => new(CredentialFor(role),
            new PrivateReadSdk(bypassSource ? Transport("selected-arm") : Source.SelectedTransport, this, "selected-original"));
        internal PrivateConnectionScope Scope(Effects.Lease lease) =>
            new(new(new(new(Subscription), "fixture-group"), lease.VaultName), lease.PrivateConnectionName!);
        internal Task<ManagementInventory<PrivateConnectionObservation>> StartInventory(Effects.Lease lease)
        {
            OriginalListScope = new(new(new(Subscription), "fixture-group"), lease.VaultName);
            return Source.RunListPrivateConnectionsAsync(Native.Selector, Client(), OriginalListScope, OriginalLimits,
                default).AsTask();
        }
        internal Task<ManagementInventory<PrivateLinkObservation>> StartLinks(Effects.Lease lease)
        {
            OriginalListScope = new(new(new(Subscription), "fixture-group"), lease.VaultName);
            return Source.RunListPrivateLinkResourcesAsync(Native.Selector, Client(), OriginalListScope, OriginalLimits,
                default).AsTask();
        }
        internal ValueTask<RoleFixtureRelease.Measurement> Release() =>
            Observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>("vault/release", Native.Selector, default);
        internal async Task<NativeCaseResult> RunOriginal()
        {
            object Runtime(string role) => new { token = role, expiresAt = "2099-01-01T00:00:00Z" };
            AudienceToken Arm(string role) => new(role, DateTimeOffset.MaxValue, "https://management.azure.com/.default");
            using var json = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                vaultUri = "https://controlled.vault.azure.net",
                setup = Runtime("setup-secret"),
                runtime = Runtime("runtime-secret"),
                denied = Runtime("denied-secret"),
                administrative = Runtime("admin-secret"),
                observer = Runtime("observer-secret"),
                families = new Dictionary<string, object>
                {
                    ["VaultAdministration"] = new Effects.Input(new(Origin, Capability, TimeSpan.FromSeconds(20)),
                        new(Arm("setup-arm"), Arm("selected-arm"), Arm("denied-arm"), Arm("observer-arm")),
                        Subscription, "fixture-group", baseline, PrepareRequest().IntendedPolicies,
                        Guid.Empty, OriginalLimits.MaximumPages, OriginalLimits.MaximumItems, TimeSpan.FromSeconds(20))
                }
            }, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
            using var environment = OwnedAzureEnvironment.Create(json.RootElement);
            var member = Effects.Members.Single(m => m.Operation == Native.Selector.Operation);
            var definition = new NativeCaseDefinition(new("AzureKeyVault", member.Operation, Native.Selector.Variant,
                "controlled", Native.Selector.Case), member.Member);
            var registry = new NativeCaseRegistry();
            Effects.Register(registry, environment, [definition], endpoint => new(endpoint,
                new VaultForwarder(async (request, token) =>
                {
                    if (request.RequestUri!.AbsolutePath == "/vault/prepare")
                        Native.Selector = JsonSerializer.Deserialize<Effects.Prepare>(
                            await request.Content!.ReadAsByteArrayAsync(token), ManagementAdmission.Json)!.Selection;
                    return await Source.DispatchAsync(request, token);
                })), selectedTransport: new PrivateReadSdk(Source.SelectedTransport, this, "selected-original"),
                readSelectedInvocation: Source);
            return (await NativeCaseRunner.RunAsync(registry, [definition], default)).Single();
        }
        private async Task<HttpResponseMessage> Send(HttpRequestMessage request, string role, CancellationToken token)
        {
            string path = request.RequestUri!.AbsolutePath;
            if (Native.Wire.VaultId.Length == 0 && path.Contains("/vaults/", StringComparison.Ordinal))
            {
                Native.Wire.VaultId = path;
                Native.Wire.VaultName = path[(path.LastIndexOf('/') + 1)..];
            }
            bool network = path.Contains("/providers/Microsoft.Network/", StringComparison.Ordinal);
            bool child = path.Contains("/privateEndpointConnections", StringComparison.Ordinal);
            bool link = path.Contains("/privateLinkResources", StringComparison.Ordinal);
            if (network || child || link)
            {
                if (request.RequestUri.Host != "management.azure.com" ||
                    !(request.Headers.Authorization?.Parameter == role ||
                        role == "selected-arm" && request.Headers.Authorization?.Parameter == "denied-arm") ||
                    request.RequestUri.Query != (network ? "?api-version=2026-01-01" : "?api-version=2026-02-01"))
                    throw new InvalidOperationException("private-read-arm-boundary");
                Endpoint ??= new(Native) { AllowEndpointDelete = true };
                bool selected = role == "selected-arm";
                if (Links && link && path == Endpoint.Binding.VaultId + "/privateLinkResources" &&
                    request.Method == HttpMethod.Get && Endpoint.EndpointExists)
                {
                    LinkQueries++;
                    if (selected) SelectedReads++;
                    await Block(role == "connection-reader-arm" ? "link-reader-arm" : role, "transport");
                    if (selected && Fault == "denial-without-response")
                        throw new Azure.RequestFailedException(403, "controlled-no-response");
                    if (request.Headers.Authorization?.Parameter == "denied-arm")
                        return Reply(403, """{"error":{"code":"Forbidden"}}""", role);
                    string? fault = selected ? Fault?.StartsWith("selected-", StringComparison.Ordinal) == true ? Fault[9..] : null :
                        Fault?.StartsWith("baseline-", StringComparison.Ordinal) == true ? Fault[9..] :
                        SelectedReads > 0 && Fault?.StartsWith("post-", StringComparison.Ordinal) == true ? Fault[5..] : null;
                    var row = new JsonObject
                    {
                        ["id"] = Endpoint.Binding.VaultId + "/privateLinkResources/vault",
                        ["name"] = "vault",
                        ["type"] = "Microsoft.KeyVault/vaults/privateLinkResources",
                        ["properties"] = new JsonObject
                        {
                            ["groupId"] = "vault",
                            ["requiredMembers"] = new JsonArray(LinkMembers.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()),
                            ["requiredZoneNames"] = new JsonArray(LinkZones.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray())
                        }
                    };
                    if (fault == "id") row["id"] = Endpoint.Binding.VaultId + "-foreign/privateLinkResources/vault";
                    if (fault == "name") row["name"] = "foreign";
                    if (fault == "type") row["type"] = "Microsoft.Network/privateEndpoints";
                    var properties = row["properties"]!;
                    if (fault == "group") properties["groupId"] = "foreign";
                    if (fault == "members") properties["requiredMembers"] = new JsonArray("foreign-member");
                    if (fault == "zones") properties["requiredZoneNames"] = new JsonArray("foreign-zone.invalid");
                    if (fault == "member-order") properties["requiredMembers"] = new JsonArray("member-b", "member-a");
                    if (fault == "zone-order") properties["requiredZoneNames"] = new JsonArray("zone-two.invalid", "zone-one.invalid");
                    if (fault == "member-case") properties["requiredMembers"] = new JsonArray("MEMBER-A", "member-b");
                    if (fault == "zone-case") properties["requiredZoneNames"] = new JsonArray("ZONE-ONE.INVALID", "zone-two.invalid");
                    if (fault == "duplicate-member") properties["requiredMembers"] = new JsonArray("member-a", "MEMBER-A");
                    if (fault == "duplicate-zone") properties["requiredZoneNames"] = new JsonArray("zone-one.invalid", "ZONE-ONE.INVALID");
                    if (fault == "null-members") properties["requiredMembers"] = null;
                    if (fault == "missing-zones") properties.AsObject().Remove("requiredZoneNames");
                    if (fault == "numeric-member") properties["requiredMembers"] = new JsonArray(JsonValue.Create(1));
                    if (fault == "too-many-members") properties["requiredMembers"] = new JsonArray(
                        Enumerable.Range(0, 257).Select(i => (JsonNode?)JsonValue.Create("member-" + i)).ToArray());
                    if (fault == "case-property") properties["GroupId"] = "vault";
                    var rows = new JsonArray(row);
                    if (fault == "empty") rows.Clear();
                    if (fault == "duplicate") rows.Add(row.DeepClone());
                    var body = new JsonObject { ["value"] = rows };
                    if (fault == "missing") body.Remove("value");
                    if (fault == "shape") body["value"] = new JsonObject();
                    if (fault == "error") body["error"] = new JsonObject { ["code"] = "Forbidden" };
                    if (fault == "partial") body["partial"] = true;
                    if (fault == "continuation") body["nextLink"] = request.RequestUri.AbsoluteUri + "&$skiptoken=next";
                    if (fault == "foreign-continuation") body["nextLink"] = "https://foreign.invalid/next";
                    if (fault == "empty-continuation") body["nextLink"] = "";
                    if (fault == "numeric-continuation") body["nextLink"] = 1;
                    if (fault == "null-continuation") body["nextLink"] = null;
                    string payload = fault == "malformed" ? "{" :
                        fault == "oversized" ? "{\"value\":[],\"padding\":\"" + new string('x', 70000) + "\"}" :
                        fault == "duplicate-field" ? body.ToJsonString()[..^1] + ",\"value\":[]}" : body.ToJsonString();
                    return await Body(Reply(200, payload, role), role == "connection-reader-arm" ? "link-reader-arm" : role);
                }
                if (Inventory && path == Endpoint.Binding.VaultId + "/privateEndpointConnections" &&
                    request.Method == HttpMethod.Get && Endpoint.EndpointExists &&
                    Native.Read().PrivateEndpoint!.Connection is not null &&
                    role is "selected-arm" or "connection-reader-arm")
                {
                    CollectionQueries++;
                    if (selected) SelectedReads++;
                    await Block(role, "transport");
                    if (selected && Fault == "denial-without-response")
                        throw new Azure.RequestFailedException(403, "controlled-no-response");
                    if (request.Headers.Authorization?.Parameter == "denied-arm")
                        return Reply(403, """{"error":{"code":"Forbidden"}}""", role);
                    var row = Endpoint.ConnectionData();
                    row.Remove("location");
                    string? fault = selected ? Fault?.StartsWith("selected-", StringComparison.Ordinal) == true ? Fault[9..] : null :
                        Fault?.StartsWith("baseline-", StringComparison.Ordinal) == true ? Fault[9..] :
                        SelectedReads > 0 && Fault?.StartsWith("post-", StringComparison.Ordinal) == true ? Fault[5..] : null;
                    if (fault == "endpoint") row["properties"]!["privateEndpoint"]!["id"] = Endpoint.Binding.EndpointId + "-foreign";
                    if (fault == "id") row["id"] = Endpoint.ConnectionId + "-foreign";
                    if (fault == "name") row["name"] = "foreign-connection";
                    if (fault == "type") row["type"] = "Microsoft.KeyVault/vaults";
                    if (fault == "state") row["properties"]!["privateLinkServiceConnectionState"]!["status"] = "Approved";
                    var rows = new JsonArray(row);
                    if (fault is "empty" or "omission") rows.Clear();
                    if (fault is "duplicate" or "extra")
                    {
                        var second = row.DeepClone();
                        if (fault == "extra")
                        {
                            second["id"] = Endpoint.ConnectionId + "-foreign";
                            second["name"] = "foreign-connection";
                        }
                        rows.Add(second);
                    }
                    if (fault == "case-row") row["ID"] = Endpoint.ConnectionId;
                    var body = new JsonObject { ["value"] = rows };
                    if (fault == "missing") body.Remove("value");
                    if (fault == "shape") body["value"] = new JsonObject();
                    if (fault == "error") body["error"] = new JsonObject { ["code"] = "Forbidden" };
                    if (fault == "partial") body["partial"] = true;
                    if (fault == "continuation") body["nextLink"] = request.RequestUri.AbsoluteUri + "&$skiptoken=next";
                    if (fault == "foreign-continuation") body["nextLink"] = "https://foreign.invalid/next";
                    if (fault == "empty-continuation") body["nextLink"] = "";
                    if (fault == "numeric-continuation") body["nextLink"] = 1;
                    if (fault == "null-continuation") body["nextLink"] = null;
                    if (fault == "case-field") body["Value"] = new JsonArray();
                    string payload = fault == "malformed" ? "{" :
                        fault == "oversized" ? "{\"value\":[],\"padding\":\"" + new string('x', 70000) + "\"}" :
                        fault == "duplicate-field" ? body.ToJsonString()[..^1] + ",\"value\":[]}" : body.ToJsonString();
                    return await Body(Reply(200, payload, role), role);
                }
                if (selected && path == Endpoint.ConnectionId)
                {
                    SelectedReads++;
                    await Block(role, "transport");
                    if (Fault == "denial-without-response") throw new Azure.RequestFailedException(403, "controlled-no-response");
                    if (request.Headers.Authorization?.Parameter == "denied-arm")
                        return Reply(403, """{"error":{"code":"Forbidden"}}""", role);
                }
                if (path == Endpoint.ConnectionId && request.Method == HttpMethod.Get && Endpoint.EndpointExists)
                {
                    if (Links && Native.Read().PrivateEndpoint!.Connection is not null) ChildObservations++;
                    var body = Endpoint.ConnectionData();
                    // The native Key Vault child schema has no Network-style
                    // location. Leave the existing PPS helper's setup replies
                    // untouched; this is the bound read profile only.
                    if (Native.Read().PrivateEndpoint!.Connection is not null) body.Remove("location");
                    if (Links && (Fault == "baseline-child" || SelectedReads > 0 && Fault == "post-child") &&
                        Native.Read().PrivateEndpoint!.Connection is not null)
                        body["properties"]!["privateEndpoint"]!["id"] = Endpoint.Binding.EndpointId + "-foreign";
                    if (selected && Fault == "selected-endpoint" || !selected && SelectedReads > 0 && Fault == "post-endpoint")
                        body["properties"]!["privateEndpoint"]!["id"] = Endpoint.Binding.EndpointId + "-foreign";
                    if (selected && Fault == "selected-name") body["name"] = "foreign-connection";
                    if (selected && Fault == "selected-state")
                        body["properties"]!["privateLinkServiceConnectionState"]!["status"] = "Approved";
                    if (selected && Fault == "selected-continuation") body["nextLink"] = "https://management.azure.com/foreign";
                    string payload = selected && Fault == "selected-malformed" ? "{" :
                        selected && Fault == "selected-oversized" ? "{\"padding\":\"" + new string('x', 70000) + "\"}" :
                        body.ToJsonString();
                    var reply = Reply(200, payload, role);
                    await Block(role, "transport");
                    if (Barrier == role + "-body")
                    {
                        reply.Content!.Dispose();
                        reply.Content = new StreamContent(new PrivateReadBody(Encoding.UTF8.GetBytes(payload), this));
                        reply.Content.Headers.ContentType = new("application/json");
                    }
                    return reply;
                }
                await Block(role, "transport");
                return await Body(await Endpoint.Respond(request, token), role);
            }
            if (role is "private-runtime-secret" or "public-runtime-secret")
            {
                if (request.Headers.Authorization is null)
                {
                    var challenge = Reply(401, "{}", role);
                    challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                        $"Bearer authorization=\"https://login.microsoftonline.com/{Tenant:D}\", resource=\"https://vault.azure.net\"");
                    return challenge;
                }
                if (request.Method != HttpMethod.Get || request.Headers.Authorization.Parameter != role ||
                    request.RequestUri.Host != Native.Wire.VaultName + ".vault.azure.net" ||
                    path != "/secrets/canary/" + Version || request.RequestUri.Query != "?api-version=2025-07-01")
                    throw new InvalidOperationException("private-read-runtime-boundary");
                bool privateRead = role == "private-runtime-secret";
                if (privateRead) PrivateReads++; else PublicReads++;
                await Block(role, "transport");
                if (privateRead && Fault == "private-unavailable") throw new IOException("controlled-network-unavailable");
                if (privateRead && Fault != "private-success" || !privateRead && Fault == "public-denied")
                    return await Body(Reply(privateRead && Fault == "private-absent" ? 404 : 403,
                        privateRead && Fault == "private-absent" ? """{"error":{"code":"SecretNotFound"}}""" :
                        """{"error":{"code":"Forbidden"}}""", role, Fault != "private-no-request-id"), role);
                string payload = JsonSerializer.Serialize(new
                {
                    id = $"https://{Native.Wire.VaultName}.vault.azure.net/secrets/canary/{(Fault == "public-version" ? new string('b', 32) : Version)}",
                    value = Fault == "public-digest" ? "foreign-controlled-material" : Native.Wire.Secret,
                    attributes = new { enabled = true }
                });
                return await Body(Reply(200, payload, role), role);
            }
            await Block(role, "transport");
            return await Body(await Native.Wire.Respond(request, role, token), role);
        }
        private async Task<HttpResponseMessage> Body(HttpResponseMessage response, string role)
        {
            if (Barrier == role + "-body")
            {
                byte[] bytes = await response.Content!.ReadAsByteArrayAsync();
                response.Content.Dispose();
                response.Content = new StreamContent(new PrivateReadBody(bytes, this));
                response.Content.Headers.ContentType = new("application/json");
            }
            return response;
        }
        internal async Task Block(string role, string stage)
        {
            if (Barrier != role + "-" + stage) return;
            Entered.TrySetResult();
            await Resume.Task;
        }
        private static HttpResponseMessage Reply(int status, string payload, string role, bool requestId = true)
        {
            var response = new HttpResponseMessage((HttpStatusCode)status)
            { Content = new StringContent(payload, Encoding.UTF8, "application/json") };
            if (requestId) response.Headers.Add("x-ms-request-id", "controlled-private-read-" + role + "-" + Guid.NewGuid().ToString("N"));
            return response;
        }
        public async ValueTask DisposeAsync()
        {
            Resume.TrySetResult();
            try { await Source.DisposeAsync(); }
            finally
            {
                try { await provisioner.DisposeAsync(); }
                finally
                {
                    Observer.Dispose();
                    Endpoint?.Dispose();
                    foreach (var client in clients) client.Dispose();
                    capability.Dispose();
                    Native.Dispose();
                }
            }
        }
    }
    private sealed class PrivateReadCredential(string role, PrivateReadFixture fixture) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("controlled-async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken)
        {
            string audience = role.EndsWith("arm", StringComparison.Ordinal) ? "https://management.azure.com/.default" : "https://vault.azure.net/.default";
            if (context.Scopes.Length != 1 || context.Scopes[0] != audience) throw new InvalidOperationException("controlled-audience");
            await fixture.Block(fixture.BarrierRole(role, fixture.CurrentConnectionRequest), "credential");
            return new(role, DateTimeOffset.MaxValue);
        }
    }
    private sealed class PrivateReadSdk(HttpPipelineTransport inner, PrivateReadFixture fixture, string role) : HttpPipelineTransport
    {
        public override Request CreateRequest()
        {
            var request = inner.CreateRequest();
            if (role == "connection-reader-arm") fixture.CurrentConnectionRequest = request;
            return request;
        }
        public override void Process(HttpMessage message) => throw new InvalidOperationException("controlled-async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            if (message.Request.Headers.TryGetValue("Authorization", out _))
                await fixture.Block(fixture.BarrierRole(role, message.Request), "sdk");
        }
    }
    private sealed class PrivateReadBody(byte[] bytes, PrivateReadFixture fixture) : MemoryStream(bytes)
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            fixture.Entered.TrySetResult();
            await fixture.Resume.Task;
            return await base.ReadAsync(buffer, CancellationToken.None);
        }
    }
}
