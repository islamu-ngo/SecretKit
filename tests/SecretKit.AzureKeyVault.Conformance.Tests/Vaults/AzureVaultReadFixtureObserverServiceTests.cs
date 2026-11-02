using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Effects = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;
using ReadSource = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultReadFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task CopiedVaultReadLoanCannotObserveOrReleaseOriginalBorrower()
    {
        await using var f = new ReadServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var parent = f.Parent.OpenCleanupPlan(Owner, f.Native.Selector);
        await Assert.That(f.Parent.TryEnterVaultRead(parent, out var original)).IsTrue();
        try
        {
            var copy = new VaultFixtureProvisioner.VaultReadLoan(parent, original!.Dispatch);
            await Assert.That(() => f.Parent.CheckVaultRead(copy)).Throws<InvalidOperationException>();
            await Assert.That(async () => await f.Parent.ObserveVaultReadAsync(copy)).Throws<InvalidOperationException>();
            await Assert.That(() => f.Parent.ExitVaultRead(copy)).Throws<InvalidOperationException>();
            await Assert.That(f.Native.Read().Idle).IsFalse();
        }
        finally { f.Parent.ExitVaultRead(original!); }
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RestartedGetVaultServiceCleansOriginalSelectorWithoutReplayingRead(bool selected)
    {
        await using var f = new ReadServiceFixture();
        var lease = await f.PrepareAndBaseline();
        if (selected) await f.Start(lease);
        await f.Source.DisposeAsync();
        await using var restarted = f.Reopen();
        using var observer = f.ObserverFor(restarted);
        var released = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default);
        RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.SelectedGets).IsEqualTo(selected ? 1 : 0);
    }

    [Test]
    public async Task NativeGetVaultDenialCannotComeFromAnExceptionWithoutResponseEvidence()
    {
        await using var f = new ReadServiceFixture("denied-authority") { Fault = "denial-without-response" };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    public async Task GetVaultTimerFailureReleasesOriginalReadLoan()
    {
        var clock = new ReadTimer();
        await using var f = new ReadServiceFixture(time: clock);
        var lease = await f.PrepareAndBaseline();
        clock.Fail = true;
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        clock.Fail = false;
        await Assert.That(f.Native.Read().Idle).IsTrue();
        await Assert.That(f.SelectedGets).IsEqualTo(0);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalGetVaultHandlerUsesOneSelectedReadAndFreshIndependentPreparedState(string boundary)
    {
        await using var f = new ReadServiceFixture(boundary);
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        await Assert.That(f.MetadataGets >= 2).IsTrue();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(3);
        await Assert.That(f.Native.Read().Resources.Any(r => r.SelectedAttempted)).IsFalse();
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("selected-malformed")]
    [Arguments("selected-oversized")]
    [Arguments("metadata-malformed")]
    [Arguments("metadata-foreign")]
    public async Task OriginalGetVaultCannotQualifyMissingOrUnboundNativeMetadata(string fault)
    {
        await using var f = new ReadServiceFixture { Fault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.SelectedGets <= 1).IsTrue();
    }

    [Test]
    public async Task GetVaultServiceRejectsUnsupportedSelectorBeforeProvisioning()
    {
        await using var f = new ReadServiceFixture();
        var input = f.PrepareRequest();
        input = input with { Selection = input.Selection with { Variant = "collection.bounded" } };
        await Assert.That(async () => await f.Observer.PostAsync<Effects.Prepare, Effects.Lease>(
            "vault/prepare", input, default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    public async Task OriginalGetVaultReadCannotReplayTheSelectedWindow()
    {
        await using var f = new ReadServiceFixture();
        var lease = await f.PrepareAndBaseline();
        await Assert.That((await f.Start(lease)).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task ForeignGetVaultScopeCannotConsumeOriginalReadAdmission()
    {
        await using var f = new ReadServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var client = new VaultAdministration(new Credential("selected-arm"), f.Source.SelectedTransport);
        await Assert.That(async () => await f.Source.RunGetVaultAsync(f.Native.Selector, client,
            new(new(new(Subscription), "fixture-group"), "foreign-read-vault"), default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.SelectedGets).IsEqualTo(0);
        await Assert.That((await f.Start(lease)).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task GetVaultRoutesRequireTheExactCapabilityBeforeReadingPayload()
    {
        await using var f = new ReadServiceFixture();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://vault-read.invalid/vault/prepare")
        {
            Content = new StringContent("{", Encoding.UTF8, "application/json")
        };
        request.Headers.Authorization = new("Bearer", "not-the-private-read-capability");
        using var response = await f.Source.DispatchAsync(request, default);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    [Arguments(false, "credential")]
    [Arguments(true, "credential")]
    [Arguments(false, "body")]
    [Arguments(true, "body")]
    [Arguments(false, "sdk")]
    [Arguments(true, "sdk")]
    public async Task OriginalGetVaultClosureDrainsTheActualSelectedBorrower(bool dispose, string barrier)
    {
        await using var f = new ReadServiceFixture();
        var lease = await f.PrepareAndBaseline();
        f.BlockCredential = barrier == "credential";
        f.BlockBody = barrier == "body";
        f.BlockSdk = barrier == "sdk";
        var selected = f.Start(lease);
        Task closing = Task.CompletedTask;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            closing = dispose ? f.Source.DisposeAsync().AsTask() : f.Release().AsTask();
            await Assert.That(f.Native.Read().Closing).IsTrue();
            await Assert.That(closing.IsCompleted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        await Assert.That(async () => await selected.WaitAsync(TimeSpan.FromSeconds(10)))
            .Throws<OperationCanceledException>();
        await closing.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.SelectedGets).IsEqualTo(barrier == "credential" ? 0 : 1);
        await Assert.That(f.Native.Read().Idle).IsTrue();
    }

    private sealed class ReadServiceFixture : IAsyncDisposable
    {
        private const string Capability = "private-read-service-capability";
        private static readonly Uri Origin = new("https://vault-read.invalid/");
        internal readonly Fixture Native = new(allowPurge: true);
        internal readonly ReadSource Source;
        internal readonly OwnedManagementObserver Observer;
        private readonly SecretMaterial capability = SecretMaterial.FromText(Capability);
        private readonly List<HttpClient> clients = [];
        private readonly VaultFixtureProvisioner provisioner;
        internal VaultFixtureProvisioner Parent => provisioner;
        private readonly HttpPipelineTransport metadataTransport, selectedTransport;
        private ObservationSubscription? subscription;
        internal string? Fault;
        internal bool BlockCredential;
        internal bool BlockBody, BlockSdk;
        internal int SelectedGets, MetadataGets;
        internal readonly bool GroupList;
        internal readonly bool SubscriptionList;
        internal readonly CollectionLimits OriginalLimits;
        internal string? Barrier;
        internal readonly Dictionary<string, Request> CurrentRequests = [];
        internal string BarrierRole(string role, Request? request = null)
        {
            if (role == "read-arm" && request?.Uri.ToUri().AbsolutePath.Contains("/deletedVaults/", StringComparison.Ordinal) == true)
                return "deleted-reader-arm";
            return role;
        }
        internal async ValueTask Block(string role, string stage)
        {
            if (Barrier != role + "-" + stage) return;
            Entered.TrySetResult();
            await Resume.Task;
        }
        internal readonly TaskCompletionSource Entered = Signal(), Resume = Signal();

        internal ReadServiceFixture(string boundary = "selected-contract", TimeProvider? time = null,
            bool groupList = false, CollectionLimits? limits = null, bool subscriptionList = false)
        {
            GroupList = groupList || subscriptionList;
            SubscriptionList = subscriptionList;
            OriginalLimits = limits ?? new(2, 32, TimeSpan.FromSeconds(20));
            Native.Selector = Native.Selector with
            {
                Operation = Effects.Members.Single(m => m.Operation.EndsWith(subscriptionList ?
                    ".ListVaultsAsync.Subscription" : groupList ?
                    ".ListVaultsAsync.ResourceGroup" : ".GetVaultAsync", StringComparison.Ordinal)).Operation,
                Variant = GroupList ? "collection.bounded" : "selector.exact",
                Case = boundary
            };
            HttpPipelineTransport Transport(string role)
            {
                var client = new HttpClient(new VaultForwarder((request, token) => Send(request, role, token)));
                clients.Add(client);
                HttpPipelineTransport transport = new HttpClientTransport(client);
                return GroupList ? new ReadRoleSdk(transport, this, role) : transport;
            }
            TokenCredential RoleCredential(string role) => GroupList ? new ReadRoleCredential(this, role) : new Credential(role);
            var host = new VaultFixtureProvisioner.HostScope(Subscription, "fixture-group", "eastus", Tenant, true, true);
            provisioner = new(Native.Journal, host, Native.Baseline,
                new("setup-arm", RoleCredential("setup-arm"), Transport("setup-arm")),
                new("setup-secret", RoleCredential("setup-secret"), Transport("setup-secret")),
                new("read-arm", RoleCredential("read-arm"), Transport("read-arm")),
                new("read-secret", RoleCredential("read-secret"), Transport("read-secret")),
                new(65536, TimeSpan.FromSeconds(20)));
            metadataTransport = Transport("read-metadata-arm");
            selectedTransport = Transport("selected-arm");
            Source = Reopen(time);
            Observer = ObserverFor(Source);
        }

        internal ReadSource Reopen(TimeProvider? time = null) => new(Origin, Owner, "vault-read-source", capability,
            new(Subscription, "fixture-group", "eastus", Tenant, true, true), provisioner,
            new("metadata-reader", GroupList ? new ReadRoleCredential(this, "read-metadata-arm") :
                new Credential("read-metadata-arm"), metadataTransport), selectedTransport,
            new(2, 32, 65536, 8192, TimeSpan.FromSeconds(20)),
            new(65536, 65536, TimeSpan.FromSeconds(20)), time);
        internal OwnedManagementObserver ObserverFor(ReadSource source) =>
            new(new(Origin, Capability, TimeSpan.FromSeconds(20)), new VaultForwarder(source.DispatchAsync));

        internal Effects.Prepare PrepareRequest() => new(Native.Selector, Subscription, "fixture-group",
            Native.Baseline, [new(Tenant, Principal, [SecretPermission.Get], null)], Guid.Empty);
        internal async Task<Effects.Lease> PrepareAndBaseline()
        {
            var lease = await Observer.PostAsync<Effects.Prepare, Effects.Lease>("vault/prepare", PrepareRequest(), default);
            subscription = await Observer.SubscribeAsync("vault", lease.Facts, default);
            await Observer.PostAsync<ObserveLease, Effects.Measurement>("vault/observe",
                new(lease.Facts.LeaseId, lease.Facts.Nonce, "baseline-before-dispatch", subscription.SubscriptionId), default);
            return lease;
        }
        internal Task<SecretOutcome<VaultObservation>> Start(Effects.Lease lease) =>
            Source.RunGetVaultAsync(Native.Selector, new VaultAdministration(new ReadCredential(this),
                new ReadSdkTransport(Source.SelectedTransport, this)),
                new(new(new(Subscription), "fixture-group"), lease.VaultName), default).AsTask();
        internal VaultAdministration GroupClient(bool bypass = false) => new(new ReadRoleCredential(this, "selected-arm"),
            new ReadRoleSdk(bypass ? selectedTransport : Source.SelectedTransport, this, "selected-original"));
        internal Task<ManagementInventory<VaultObservation>> StartGroup(ResourceGroupScope? scope = null) =>
            Source.RunListVaultsResourceGroupAsync(Native.Selector, GroupClient(),
                scope ?? new(new(Subscription), "fixture-group"), OriginalLimits, default).AsTask();
        internal Task<ManagementInventory<VaultObservation>> StartSubscription(SubscriptionScope? scope = null) =>
            Source.RunListVaultsSubscriptionAsync(Native.Selector, GroupClient(),
                scope ?? new(Subscription), OriginalLimits, default).AsTask();
        internal ValueTask<Effects.Measurement> ObserveGroup() =>
            Observer.PostAsync<ObserveLease, Effects.Measurement>("vault/observe",
                new(subscription!.LeaseId, subscription.Nonce, "post-operation", subscription.SubscriptionId), default);
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
                        Subscription, "fixture-group", Native.Baseline, PrepareRequest().IntendedPolicies,
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
                })), selectedTransport: Source.SelectedTransport, readSelectedInvocation: Source);
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
            if (role == "selected-arm")
            {
                if (request.Method != HttpMethod.Get || path != (GroupList ? GroupRoute : Native.Wire.VaultId) ||
                    request.RequestUri!.Query != "?api-version=2026-02-01")
                    throw new InvalidOperationException("unexpected-selected-read");
                SelectedGets++;
                if (Fault == "denial-without-response") throw new Azure.RequestFailedException(403, "controlled-no-response");
                if (request.Headers.Authorization?.Parameter == "denied-arm") return Reply(403, "{\"error\":{\"code\":\"Forbidden\"}}");
                if (Fault == "selected-malformed") return Reply(200, "{");
                if (Fault == "selected-oversized") return Reply(200, "{\"padding\":\"" + new string('x', 70000) + "\"}");
            }
            string barrierRole = role == "read-arm" && path.Contains("/deletedVaults/", StringComparison.Ordinal)
                ? "deleted-reader-arm" : role;
            await Block(barrierRole, "transport");
            if (GroupList && path == GroupRoute)
            {
                if (role == "read-metadata-arm") MetadataGets++;
                string? fault = role == "selected-arm" ?
                    Fault?.StartsWith("selected-", StringComparison.Ordinal) == true ? Fault[9..] : null :
                    Fault?.StartsWith("baseline-", StringComparison.Ordinal) == true ? Fault[9..] :
                    SelectedGets > 0 && Fault?.StartsWith("post-", StringComparison.Ordinal) == true ? Fault[5..] : null;
                var row = Native.Wire.Vault!.DeepClone();
                row["id"] = Native.Wire.VaultId;
                row["name"] = Native.Wire.VaultName;
                row["type"] = "Microsoft.KeyVault/vaults";
                if (fault == "id") row["id"] = Native.Wire.VaultId + "-foreign";
                if (fault == "foreign-group") row["id"] = Native.Wire.VaultId.Replace(
                    "/resourceGroups/fixture-group/", "/resourceGroups/foreign-group/", StringComparison.Ordinal);
                if (fault == "name") row["name"] = "foreign";
                if (fault == "type") row["type"] = "Microsoft.Network/privateEndpoints";
                if (fault == "location") row["location"] = "westus";
                if (fault == "tag") row["tags"]!["secretkit-fixture"] = "foreign";
                if (fault == "extra-tag") row["tags"]!["extra"] = "value";
                if (fault == "missing-id") row.AsObject().Remove("id");
                if (fault == "case-id") row["ID"] = Native.Wire.VaultId;
                var p = row["properties"]!;
                if (fault == "provisioning") p["provisioningState"] = "Failed";
                if (fault == "rbac") p["enableRbacAuthorization"] = true;
                if (fault == "purge") p["enablePurgeProtection"] = true;
                if (fault == "retention") p["softDeleteRetentionInDays"] = 24;
                if (fault == "soft-delete") p["enableSoftDelete"] = false;
                if (fault == "tenant") p["tenantId"] = Guid.NewGuid().ToString();
                if (fault == "sku") p["sku"]!["family"] = "B";
                if (fault == "public") p["publicNetworkAccess"] = Native.Baseline.PublicNetworkAccess ? "Disabled" : "Enabled";
                if (fault == "uri") p["vaultUri"] = "https://foreign.vault.azure.net/";
                if (fault == "missing-policies") p.AsObject().Remove("accessPolicies");
                if (fault == "null-policies") p["accessPolicies"] = null;
                if (fault == "create-mode") p["createMode"] = "recover";
                if (fault == "create-mode-case") p["createMode"] = "Default";
                var rows = new JsonArray(row);
                if (fault == "empty") rows.Clear();
                if (fault == "duplicate") rows.Add(row.DeepClone());
                if (fault == "foreign-row")
                {
                    var foreign = row.DeepClone();
                    foreign["id"] = Native.Wire.VaultId + "-foreign";
                    foreign["name"] = Native.Wire.VaultName + "-foreign";
                    rows.Add(foreign);
                }
                var body = new JsonObject { ["value"] = rows };
                if (fault == "missing") body.Remove("value");
                if (fault == "error") body["error"] = new JsonObject { ["code"] = "Forbidden" };
                if (fault == "partial") body["partial"] = true;
                if (fault == "continuation") body["nextLink"] = request.RequestUri.AbsoluteUri + "&$skiptoken=next";
                if (fault == "foreign-continuation") body["nextLink"] = "https://foreign.invalid/next";
                if (fault == "empty-continuation") body["nextLink"] = "";
                if (fault == "numeric-continuation") body["nextLink"] = 1;
                if (fault == "null-continuation") body["nextLink"] = null;
                string payload = fault == "malformed" ? "{" : fault == "duplicate-field" ?
                    body.ToJsonString()[..^1] + ",\"value\":[]}" : body.ToJsonString();
                return await GroupBody(Reply(200, payload), barrierRole);
            }
            if (role == "read-metadata-arm")
            {
                MetadataGets++;
                if (Fault == "metadata-malformed") return Reply(200, "{");
                if (Fault == "metadata-foreign")
                {
                    var body = Native.Wire.Vault!.DeepClone();
                    body["id"] = Native.Wire.VaultId + "-foreign";
                    return Reply(200, body.ToJsonString());
                }
            }
            var reply = await Native.Wire.Respond(request, role, token);
            if (role == "selected-arm" && BlockBody)
            {
                byte[] bytes = await reply.Content!.ReadAsByteArrayAsync(token);
                reply.Content.Dispose();
                reply.Content = new StreamContent(new ReadBody(bytes, this));
                reply.Content.Headers.ContentType = new("application/json");
            }
            return GroupList ? await GroupBody(reply, barrierRole) : reply;
        }
        private string GroupRoute => SubscriptionList ? $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/vaults" :
            $"/subscriptions/{Subscription:D}/resourceGroups/fixture-group/providers/Microsoft.KeyVault/vaults";
        private async ValueTask<HttpResponseMessage> GroupBody(HttpResponseMessage response, string role)
        {
            if (Barrier == role + "-body")
            {
                var original = response.Content;
                response.Content = new StreamContent(new GroupReadBody(await original.ReadAsByteArrayAsync(), this, role));
                original.Dispose();
                response.Content.Headers.ContentType = new("application/json");
            }
            return response;
        }
        private static HttpResponseMessage Reply(int status, string body)
        {
            var response = new HttpResponseMessage((HttpStatusCode)status)
            { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            response.Headers.Add("x-ms-request-id", "controlled-vault-read");
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
                    foreach (var client in clients) client.Dispose();
                    capability.Dispose();
                    Native.Dispose();
                }
            }
        }
    }
    private sealed class GroupReadBody(byte[] bytes, ReadServiceFixture fixture, string role) : MemoryStream(bytes)
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await fixture.Block(role, "body");
            return await base.ReadAsync(buffer, cancellationToken);
        }
    }
    private sealed class ReadRoleCredential(ReadServiceFixture fixture, string role) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            fixture.CurrentRequests.TryGetValue(role, out var request);
            await fixture.Block(fixture.BarrierRole(role, request), "credential");
            cancellationToken.ThrowIfCancellationRequested();
            return new(role, DateTimeOffset.MaxValue);
        }
    }
    private sealed class ReadRoleSdk(HttpPipelineTransport inner, ReadServiceFixture fixture, string role) : HttpPipelineTransport
    {
        public override Request CreateRequest()
        {
            var request = inner.CreateRequest();
            fixture.CurrentRequests[role] = request;
            return request;
        }
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            if (message.Request.Headers.Contains("Authorization"))
                await fixture.Block(fixture.BarrierRole(role, message.Request), "sdk");
        }
    }
    private sealed class ReadBody(byte[] bytes, ReadServiceFixture fixture) : MemoryStream(bytes)
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            fixture.Entered.TrySetResult();
            await fixture.Resume.Task;
            return await base.ReadAsync(buffer, cancellationToken);
        }
    }
    private sealed class ReadSdkTransport(HttpPipelineTransport inner, ReadServiceFixture fixture) : HttpPipelineTransport
    {
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            if (fixture.BlockSdk)
            {
                fixture.Entered.TrySetResult();
                await fixture.Resume.Task;
            }
        }
    }
    private sealed class ReadCredential(ReadServiceFixture fixture) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext,
            CancellationToken cancellationToken)
        {
            if (fixture.BlockCredential)
            {
                fixture.Entered.TrySetResult();
                await fixture.Resume.Task;
            }
            cancellationToken.ThrowIfCancellationRequested();
            return new("selected-arm", DateTimeOffset.MaxValue);
        }
    }
    private sealed class ReadTimer : TimeProvider
    {
        internal bool Fail;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            Fail ? throw new InvalidOperationException("controlled-read-timer-failure") :
                TimeProvider.System.CreateTimer(callback, state, dueTime, period);
    }
}
