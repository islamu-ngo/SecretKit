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
    public async Task LostInitialVaultCreateCannotAuthorizeDeletedReadPreparationOrCleanupDelete()
    {
        await using var f = new DeletedReadFixture();
        f.Native.Wire.CreateFault = "lost";
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await f.Release();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.SelectedGets + f.SetupDeletes + f.Purges).IsEqualTo(0);
    }

    [Test]
    [Arguments(false, "observer-credential")]
    [Arguments(true, "observer-credential")]
    [Arguments(false, "observer-body")]
    [Arguments(true, "observer-body")]
    [Arguments(false, "observer-transport")]
    [Arguments(true, "observer-transport")]
    public async Task DeletedReadClosureDrainsActualIndependentObservation(bool dispose, string barrier)
    {
        await using var f = new DeletedReadFixture();
        var lease = await f.PrepareAndArm();
        f.Barrier = barrier;
        var observed = f.Baseline(lease).AsTask();
        Task closing = Task.CompletedTask;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            closing = dispose ? f.Source.DisposeAsync().AsTask() : f.Release().AsTask();
            await Assert.That(f.Native.Read().Closing).IsTrue();
            await Assert.That(closing.IsCompleted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        await Assert.That(async () => await observed.WaitAsync(TimeSpan.FromSeconds(10)))
            .Throws<NativeCaseFailureException>();
        await closing.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Idle).IsTrue();
        await Assert.That(f.SelectedGets).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
    }

    [Test]
    [Arguments("parent-owner")]
    [Arguments("parent-protection")]
    [Arguments("parent-date")]
    public async Task UnprovenDeletedParentWitnessCannotAuthorizePurge(string fault)
    {
        await using var f = new DeletedReadFixture { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.Purges).IsEqualTo(0);
    }

    [Test]
    [Arguments("preparation")]
    [Arguments("purge")]
    public async Task LostDeletedRootMutationCannotBeReplayedByReadCleanup(string phase)
    {
        await using var f = new DeletedReadFixture();
        if (phase == "preparation") f.Native.Wire.DeleteFault = "lost";
        else f.Native.Wire.PurgeFault = "lost";
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await f.Release();
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.Purges).IsEqualTo(phase == "preparation" ? 0 : 1);
        await Assert.That(f.SelectedGets).IsEqualTo(phase == "preparation" ? 0 : 1);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalDeletedVaultReadJoinsNativePreparationAndPurgeOnlyCleanup(string boundary)
    {
        await using var f = new DeletedReadFixture(boundary);
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        await Assert.That(f.MetadataGets >= 2).IsTrue();
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.Purges).IsEqualTo(1);
        var root = f.Native.Read();
        await Assert.That(root.Resources.Length).IsEqualTo(3);
        await Assert.That(root.Resources.Single(r => r.Id == f.Native.Wire.VaultId).DeleteAttempted).IsFalse();
        await Assert.That(root.Resources.Any(r => r.SelectedAttempted)).IsFalse();
        await Assert.That(root.Released).IsTrue();
    }

    [Test]
    [Arguments("selected-malformed")]
    [Arguments("selected-oversized")]
    [Arguments("selected-owner")]
    [Arguments("selected-vault")]
    [Arguments("selected-date")]
    [Arguments("metadata-malformed")]
    [Arguments("metadata-vault")]
    [Arguments("post-date")]
    public async Task DeletedVaultReadRejectsUnboundSelectedOrIndependentFacts(string fault)
    {
        await using var f = new DeletedReadFixture { Fault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedGets <= 1).IsTrue();
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    public async Task DeletedVaultExceptionOnlyDenialCannotQualifyWithoutNativeResponse()
    {
        await using var f = new DeletedReadFixture("denied-authority") { Fault = "denial-without-response" };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    public async Task DeletedVaultReadTimerFailureCannotStrandTheOriginalLoan()
    {
        var clock = new ReadTimer();
        await using var f = new DeletedReadFixture(time: clock);
        var lease = await f.PrepareAndBaseline();
        clock.Fail = true;
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        clock.Fail = false;
        await Assert.That(f.Native.Read().Idle).IsTrue();
        await Assert.That(f.SelectedGets).IsEqualTo(0);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task DeletedVaultReadRejectsReplayedSelectedInvocation()
    {
        await using var f = new DeletedReadFixture();
        var lease = await f.PrepareAndBaseline();
        await Assert.That((await f.Start(lease)).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task ForeignDeletedScopeCannotConsumeOriginalReadAdmission()
    {
        await using var f = new DeletedReadFixture();
        var lease = await f.PrepareAndBaseline();
        var client = new VaultAdministration(new Credential("selected-arm"), f.Source.SelectedTransport);
        await Assert.That(async () => await f.Source.RunGetDeletedVaultAsync(f.Native.Selector, client,
            new(new(Subscription), "eastus", "foreign-deleted-vault"), default)).Throws<InvalidOperationException>();
        await Assert.That((await f.Start(lease)).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.SelectedGets).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task DeletedReadCleanupNeverDeletesAnUnexpectedActiveVault()
    {
        await using var f = new DeletedReadFixture();
        await f.PrepareAndBaseline();
        f.Native.Wire.Active = true;
        await f.Release();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.Purges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Native.Wire.VaultId).DeleteAttempted).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DeletedReadRestartRecoversOnlyCleanupCoordinates(bool selected)
    {
        await using var f = new DeletedReadFixture();
        var lease = await f.PrepareAndBaseline();
        if (selected) await f.Start(lease);
        await f.Source.DisposeAsync();
        await using var restarted = f.Reopen();
        using var observer = f.ObserverFor(restarted);
        RoleFixtureRelease.Validate(await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default), f.Native.Selector, lease.Facts);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.SelectedGets).IsEqualTo(selected ? 1 : 0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
    }

    [Test]
    [Arguments(false, "credential")]
    [Arguments(true, "credential")]
    [Arguments(false, "body")]
    [Arguments(true, "body")]
    [Arguments(false, "sdk")]
    [Arguments(true, "sdk")]
    [Arguments(false, "transport")]
    [Arguments(true, "transport")]
    public async Task DeletedReadCloseDrainsActualSelectedBorrowers(bool dispose, string barrier)
    {
        await using var f = new DeletedReadFixture();
        var lease = await f.PrepareAndBaseline();
        f.Barrier = barrier;
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
        await Assert.That(f.Native.Read().Idle).IsTrue();
        await Assert.That(f.SelectedGets).IsEqualTo(barrier == "credential" ? 0 : 1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
    }

    private sealed class DeletedReadFixture : IAsyncDisposable
    {
        private const string Capability = "private-deleted-read-capability";
        private static readonly Uri Origin = new("https://deleted-vault-read.invalid/");
        internal readonly Fixture Native = new(allowPurge: true);
        internal readonly ReadSource Source;
        internal readonly OwnedManagementObserver Observer;
        private readonly VaultFixtureProvisioner provisioner;
        internal VaultFixtureProvisioner Parent => provisioner;
        private readonly SecretMaterial capability = SecretMaterial.FromText(Capability);
        private readonly List<HttpClient> clients = [];
        private readonly HttpPipelineTransport metadataTransport, selectedTransport;
        private ObservationSubscription? subscription;
        internal string? Fault, Barrier;
        internal int SelectedGets, MetadataGets, SetupDeletes, Purges;
        internal int DenialStatus = 403;
        internal readonly bool Inventory;
        internal readonly CollectionLimits OriginalLimits;
        internal readonly Dictionary<string, Request> CurrentRequests = [];
        internal string Role(string role, Request? request) =>
            role == "read-arm" && request?.Uri.ToUri().AbsolutePath.Contains("/deletedVaults/", StringComparison.Ordinal) == true
                ? "deleted-parent-arm" : role;
        internal async ValueTask Block(string role, string stage)
        {
            if (Barrier != role + "-" + stage) return;
            Entered.TrySetResult();
            await Resume.Task;
        }
        internal readonly TaskCompletionSource Entered = Signal(), Resume = Signal();

        internal DeletedReadFixture(string boundary = "selected-contract", TimeProvider? time = null,
            bool inventory = false, CollectionLimits? limits = null)
        {
            Inventory = inventory;
            OriginalLimits = limits ?? new(2, 32, TimeSpan.FromSeconds(20));
            Native.Selector = Native.Selector with
            {
                Operation = Effects.Members.Single(m => m.Operation.EndsWith(inventory ?
                    ".ListDeletedVaultsAsync" : ".GetDeletedVaultAsync", StringComparison.Ordinal)).Operation,
                Variant = inventory ? "collection.bounded" : "selector.exact",
                Case = boundary
            };
            HttpPipelineTransport Transport(string role)
            {
                var client = new HttpClient(new VaultForwarder((request, token) => Send(request, role, token)));
                clients.Add(client);
                HttpPipelineTransport transport = new HttpClientTransport(client);
                return inventory ? new DeletedListSdk(transport, this, role) : transport;
            }
            TokenCredential CredentialFor(string role) => inventory ? new DeletedListCredential(this, role) : new Credential(role);
            provisioner = new(Native.Journal, new(Subscription, "fixture-group", "eastus", Tenant, true, true), Native.Baseline,
                new("setup-arm", CredentialFor("setup-arm"), Transport("setup-arm")),
                new("setup-secret", CredentialFor("setup-secret"), Transport("setup-secret")),
                new("read-arm", CredentialFor("read-arm"), Transport("read-arm")),
                new("read-secret", CredentialFor("read-secret"), Transport("read-secret")),
                new(65536, TimeSpan.FromSeconds(20)));
            metadataTransport = Transport("read-deleted-metadata-arm");
            selectedTransport = Transport("selected-arm");
            Source = Reopen(time);
            Observer = ObserverFor(Source);
        }

        internal ReadSource Reopen(TimeProvider? time = null) => new(Origin, Owner, "deleted-read-source", capability,
            new(Subscription, "fixture-group", "eastus", Tenant, true, true), provisioner,
            new("deleted-metadata", Inventory ? new DeletedListCredential(this, "read-deleted-metadata-arm") :
                new DeletedMetadataCredential(this), metadataTransport), selectedTransport,
            new(2, 32, 65536, 8192, TimeSpan.FromSeconds(20)),
            new(65536, 65536, TimeSpan.FromSeconds(20)), time);
        internal OwnedManagementObserver ObserverFor(ReadSource source) =>
            new(new(Origin, Capability, TimeSpan.FromSeconds(20)), new VaultForwarder(source.DispatchAsync));
        internal Effects.Prepare PrepareRequest() => new(Native.Selector, Subscription, "fixture-group",
            Native.Baseline, [new(Tenant, Principal, [SecretPermission.Get], null)], Guid.Empty);
        internal async Task<Effects.Lease> PrepareAndBaseline()
        {
            var lease = await PrepareAndArm();
            await Baseline(lease);
            return lease;
        }
        internal async Task<Effects.Lease> PrepareAndArm()
        {
            var lease = await Observer.PostAsync<Effects.Prepare, Effects.Lease>("vault/prepare", PrepareRequest(), default);
            subscription = await Observer.SubscribeAsync("vault", lease.Facts, default);
            return lease;
        }
        internal ValueTask<Effects.Measurement> Baseline(Effects.Lease lease) =>
            Observer.PostAsync<ObserveLease, Effects.Measurement>("vault/observe",
                new(lease.Facts.LeaseId, lease.Facts.Nonce, "baseline-before-dispatch", subscription!.SubscriptionId), default);
        internal Task<SecretOutcome<DeletedVaultObservation>> Start(Effects.Lease lease) =>
            Source.RunGetDeletedVaultAsync(Native.Selector,
                new VaultAdministration(new DeletedReadCredential(this), new DeletedReadSdk(Source.SelectedTransport, this)),
                new(new(Subscription), "eastus", lease.VaultName), default).AsTask();
        internal VaultAdministration ListClient(bool bypass = false) => new(new DeletedListCredential(this, "selected-arm"),
            new DeletedListSdk(bypass ? selectedTransport : Source.SelectedTransport, this, "selected-original"));
        internal Task<ManagementInventory<DeletedVaultObservation>> StartList(SubscriptionScope? scope = null) =>
            Source.RunListDeletedVaultsAsync(Native.Selector, ListClient(), scope ?? new(Subscription), OriginalLimits, default).AsTask();
        internal ValueTask<Effects.Measurement> Post() =>
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
            if (role == "setup-arm" && request.Method == HttpMethod.Delete) SetupDeletes++;
            if (role == "setup-arm" && request.Method == HttpMethod.Post) Purges++;
            if (role == "selected-arm")
            {
                if (request.Method != HttpMethod.Get || (Inventory ? path != ListRoute :
                    !path.Contains("/deletedVaults/", StringComparison.Ordinal)) ||
                    request.RequestUri.Query != "?api-version=2026-02-01")
                    throw new InvalidOperationException("unexpected-deleted-read");
                SelectedGets++;
                if (Fault == "denial-without-response") throw new Azure.RequestFailedException(403, "controlled-no-response");
                if (request.Headers.Authorization?.Parameter == "denied-arm") return Reply(DenialStatus, "{\"error\":{\"code\":\"Forbidden\"}}");
                if (Fault == "selected-malformed") return Reply(200, "{");
                if (Fault == "selected-oversized") return Reply(200, "{\"padding\":\"" + new string('x', 70000) + "\"}");
            }
            if (role == "selected-arm" && Barrier == "transport" ||
                role == "read-deleted-metadata-arm" && Barrier == "observer-transport")
            {
                Entered.TrySetResult();
                await Resume.Task;
            }
            if (role == "read-deleted-metadata-arm")
            {
                MetadataGets++;
                if (Fault == "metadata-malformed") return Reply(200, "{");
            }
            string barrierRole = role == "read-arm" && path.Contains("/deletedVaults/", StringComparison.Ordinal)
                ? "deleted-parent-arm" : role;
            await Block(barrierRole, "transport");
            if (Inventory && path == ListRoute && request.Method == HttpMethod.Get)
            {
                string? fault = role == "selected-arm" ?
                    Fault?.StartsWith("selected-", StringComparison.Ordinal) == true ? Fault[9..] : null :
                    Fault?.StartsWith("baseline-", StringComparison.Ordinal) == true ? Fault[9..] :
                    SelectedGets > 0 && Fault?.StartsWith("post-", StringComparison.Ordinal) == true ? Fault[5..] : null;
                string id = $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/{Native.Wire.VaultName}";
                var row = DeletedData(id);
                if (fault == "id") row["id"] = id + "-foreign";
                if (fault == "case-id") row["id"] = id.Replace("/deletedVaults/", "/deletedvaults/", StringComparison.Ordinal);
                if (fault == "location-id") row["id"] = id.Replace("/eastus/", "/westus/", StringComparison.Ordinal);
                if (fault == "name") row["name"] = "foreign";
                if (fault == "type") row["type"] = "Microsoft.KeyVault/vaults";
                if (fault == "missing-id") row.Remove("id");
                if (fault == "duplicate-id") row["ID"] = id;
                var p = row["properties"]!;
                if (fault == "vault") p["vaultId"] = Native.Wire.VaultId + "-foreign";
                if (fault == "group") p["vaultId"] = Native.Wire.VaultId.Replace(
                    "/resourceGroups/fixture-group/", "/resourceGroups/foreign-group/", StringComparison.Ordinal);
                if (fault == "owner") p["tags"]!["secretkit-fixture"] = "foreign";
                if (fault == "extra-tag") p["tags"]!["extra"] = "value";
                if (fault == "location") p["location"] = "westus";
                if (fault == "protection") p["purgeProtectionEnabled"] = true;
                if (fault == "null-protection") p["purgeProtectionEnabled"] = null;
                if (fault == "missing-protection") p.AsObject().Remove("purgeProtectionEnabled");
                if (fault == "date") p["deletionDate"] = "2026-10-16T00:00:00Z";
                if (fault == "null-date") p["deletionDate"] = null;
                if (fault == "invalid-date") p["deletionDate"] = "invalid";
                if (fault == "purge-date") p["scheduledPurgeDate"] = "2026-11-08T00:00:00Z";
                if (fault == "shifted-dates")
                {
                    p["deletionDate"] = "2026-10-16T00:00:00Z";
                    p["scheduledPurgeDate"] = "2026-11-08T00:00:00Z";
                }
                if (fault == "extra-property") p["extra"] = true;
                var rows = new JsonArray(row);
                if (fault == "empty") rows.Clear();
                if (fault == "duplicate") rows.Add(row.DeepClone());
                if (fault == "foreign-row")
                {
                    var foreign = row.DeepClone();
                    foreign["id"] = id + "-foreign";
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
                if (fault == "bool-continuation") body["nextLink"] = true;
                if (fault == "array-continuation") body["nextLink"] = new JsonArray();
                if (fault == "object-continuation") body["nextLink"] = new JsonObject();
                if (fault == "null-continuation") body["nextLink"] = null;
                string payload = fault == "malformed" ? "{" : fault == "duplicate-field" ?
                    body.ToJsonString()[..^1] + ",\"value\":[]}" : body.ToJsonString();
                return await ListBody(Reply(200, payload), barrierRole);
            }
            if (request.Method == HttpMethod.Get && path.Contains("/deletedVaults/", StringComparison.Ordinal) && Native.Wire.Deleted)
            {
                var body = DeletedData(path);
                if (role == "read-arm" && SelectedGets > 0)
                {
                    if (Fault == "parent-owner") body["properties"]!["tags"]!["secretkit-fixture"] = Guid.NewGuid().ToString("N");
                    if (Fault == "parent-protection") body["properties"]!["purgeProtectionEnabled"] = true;
                    if (Fault == "parent-date") body["properties"]!["deletionDate"] = "2026-10-16T00:00:00Z";
                }
                if (role == "selected-arm" && Fault == "selected-owner")
                    body["properties"]!["tags"]!["secretkit-fixture"] = Guid.NewGuid().ToString("N");
                if (role == "selected-arm" && Fault == "selected-vault" ||
                    role == "read-deleted-metadata-arm" && Fault == "metadata-vault")
                    body["properties"]!["vaultId"] = Native.Wire.VaultId + "-foreign";
                if (role == "selected-arm" && Fault == "selected-date" ||
                    role == "read-deleted-metadata-arm" && Fault == "post-date" && SelectedGets > 0)
                    body["properties"]!["deletionDate"] = "2026-10-16T00:00:00Z";
                var response = Reply(200, body.ToJsonString());
                if (role == "selected-arm" && Barrier == "body" ||
                    role == "read-deleted-metadata-arm" && Barrier == "observer-body")
                {
                    response.Content!.Dispose();
                    response.Content = new StreamContent(new DeletedReadBody(Encoding.UTF8.GetBytes(body.ToJsonString()), this));
                    response.Content.Headers.ContentType = new("application/json");
                }
                return Inventory ? await ListBody(response, barrierRole) : response;
            }
            var native = await Native.Wire.Respond(request, role, token);
            return Inventory ? await ListBody(native, barrierRole) : native;
        }
        private string ListRoute => $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/deletedVaults";
        private async ValueTask<HttpResponseMessage> ListBody(HttpResponseMessage response, string role)
        {
            if (Barrier == role + "-body")
            {
                var original = response.Content;
                response.Content = new StreamContent(new DeletedListBody(await original.ReadAsByteArrayAsync(), this, role));
                original.Dispose();
                response.Content.Headers.ContentType = new("application/json");
            }
            return response;
        }
        private JsonObject DeletedData(string id) => new()
        {
            ["id"] = id,
            ["name"] = Native.Wire.VaultName,
            ["type"] = "Microsoft.KeyVault/locations/deletedVaults",
            ["properties"] = new JsonObject
            {
                ["vaultId"] = Native.Wire.VaultId,
                ["location"] = "eastus",
                ["tags"] = Native.Wire.Vault!["tags"]!.DeepClone(),
                ["purgeProtectionEnabled"] = false,
                ["deletionDate"] = "2026-10-15T00:00:00Z",
                ["scheduledPurgeDate"] = "2026-11-07T00:00:00Z"
            }
        };
        private static HttpResponseMessage Reply(int status, string body)
        {
            var response = new HttpResponseMessage((HttpStatusCode)status)
            { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            response.Headers.Add("x-ms-request-id", "controlled-deleted-read");
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
    private sealed class DeletedListBody(byte[] bytes, DeletedReadFixture fixture, string role) : MemoryStream(bytes)
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await fixture.Block(role, "body");
            return await base.ReadAsync(buffer, cancellationToken);
        }
    }
    private sealed class DeletedListCredential(DeletedReadFixture fixture, string role) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            fixture.CurrentRequests.TryGetValue(role, out var request);
            await fixture.Block(fixture.Role(role, request), "credential");
            cancellationToken.ThrowIfCancellationRequested();
            return new(role, DateTimeOffset.MaxValue);
        }
    }
    private sealed class DeletedListSdk(HttpPipelineTransport inner, DeletedReadFixture fixture, string role) : HttpPipelineTransport
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
                await fixture.Block(fixture.Role(role, message.Request), "sdk");
        }
    }
    private sealed class DeletedMetadataCredential(DeletedReadFixture fixture) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext,
            CancellationToken cancellationToken)
        {
            if (fixture.Barrier == "observer-credential")
            {
                fixture.Entered.TrySetResult();
                await fixture.Resume.Task;
            }
            cancellationToken.ThrowIfCancellationRequested();
            return new("read-deleted-metadata-arm", DateTimeOffset.MaxValue);
        }
    }
    private sealed class DeletedReadCredential(DeletedReadFixture fixture) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext,
            CancellationToken cancellationToken)
        {
            if (fixture.Barrier == "credential")
            {
                fixture.Entered.TrySetResult();
                await fixture.Resume.Task;
            }
            cancellationToken.ThrowIfCancellationRequested();
            return new("selected-arm", DateTimeOffset.MaxValue);
        }
    }
    private sealed class DeletedReadBody(byte[] bytes, DeletedReadFixture fixture) : MemoryStream(bytes)
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            fixture.Entered.TrySetResult();
            await fixture.Resume.Task;
            return await base.ReadAsync(buffer, cancellationToken);
        }
    }
    private sealed class DeletedReadSdk(HttpPipelineTransport inner, DeletedReadFixture fixture) : HttpPipelineTransport
    {
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            if (fixture.Barrier == "sdk")
            {
                fixture.Entered.TrySetResult();
                await fixture.Resume.Task;
            }
        }
    }
}
