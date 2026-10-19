using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Effects = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;
using Service = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments("rbac.omitted")]
    [Arguments("rbac.false")]
    [Arguments("rbac.true")]
    [Arguments("purgeProtection.omitted")]
    [Arguments("purgeProtection.true")]
    [Arguments("purgeProtection.false.rejected")]
    [Arguments("publicNetworkAccess.omitted")]
    [Arguments("publicNetworkAccess.false")]
    [Arguments("publicNetworkAccess.true")]
    public async Task OriginalSettingsHandlerRetainsAllFiveBoundariesAndHonestProtectedCleanup(string variant)
    {
        foreach (string boundary in new[] { "selected-contract", "independent-effect", "denied-authority",
            "cancellation-boundary", "lost-response-no-replay" })
        {
            await using var f = new SettingsFixture(variant, boundary);
            var result = await f.RunOriginal();
            bool protectedRemainder = variant == "purgeProtection.true" && boundary != "denied-authority";
            if (protectedRemainder)
            {
                await Assert.That(result.Passed).IsFalse();
                await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
                await Assert.That(f.Native.Read().Released).IsFalse();
                await Assert.That(f.Purges).IsEqualTo(0);
                await Assert.That(f.Native.Wire.Deleted).IsTrue();
            }
            else await Assert.That(result.Passed).IsTrue();
            await Assert.That(f.Patches).IsEqualTo(variant.EndsWith(".rejected", StringComparison.Ordinal) ? 0 : 1);
            await Assert.That(f.SelectedGets).IsEqualTo(0);
            await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(3);
            await Assert.That(f.SecretRequests).IsEqualTo(0);
            if (f.LastPatch is not null)
            {
                await Assert.That(f.LastPatch.Count).IsEqualTo(1);
                await Assert.That(f.LastPatch["properties"]!.AsObject().Count).IsEqualTo(1);
            }
            if (variant.EndsWith(".rejected", StringComparison.Ordinal))
                await Assert.That(f.Native.Read().Resources.Any(r => r.SelectedAttempted)).IsFalse();
        }
    }

    [Test]
    [Arguments(200)]
    [Arguments(201)]
    public async Task SettingsImmediateNativeResourceIsSettledWithFreshPostRatherThanOperationPolling(int status)
    {
        await using var f = new SettingsFixture { ReplyStatus = status };
        var lease = await f.PrepareAndBaseline();
        var result = await f.Select(lease);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(ReferenceEquals(result.Value.Scope, f.OriginalScope)).IsTrue();
        await Assert.That(result.Value.EnableRbacAuthorization).IsTrue();
        await Assert.That(result.Value.RuntimeDeliveryProven).IsFalse();
        await Assert.That(f.Patches).IsEqualTo(1);
        await Assert.That(f.SelectedGets).IsEqualTo(0);
        var measured = await f.Post(lease);
        await Assert.That(measured.Configuration!.Rbac).IsTrue();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("no-mutation")]
    [Arguments("id")]
    [Arguments("type")]
    [Arguments("owner")]
    [Arguments("provisioning")]
    [Arguments("missing-rbac")]
    [Arguments("null-purge")]
    [Arguments("retention")]
    [Arguments("sku")]
    [Arguments("policy")]
    [Arguments("untouched-network")]
    [Arguments("malformed")]
    [Arguments("oversized")]
    [Arguments("missing-request-id")]
    [Arguments("async")]
    [Arguments("exception-denial")]
    public async Task SettingsAcknowledgmentCannotReplaceNativeAndIndependentSettlement(string fault)
    {
        await using var f = new SettingsFixture { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.Patches).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Deletes + f.Purges).IsEqualTo(0);
    }

    [Test]
    public async Task SettingsNativeDenialRetainsActualReceiptAndUnchangedState()
    {
        await using var f = new SettingsFixture();
        var lease = await f.PrepareAndBaseline();
        var result = await f.Select(lease, denied: true);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        var post = await f.Post(lease);
        await Assert.That(post.Configuration!.Rbac).IsEqualTo(f.Baseline.Rbac);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task SettingsForwardsItsValidatedSnapshotRatherThanReserializingStatefulNativeContent()
    {
        await using var f = new SettingsFixture { Fault = "stateful-content" };
        var lease = await f.PrepareAndBaseline();
        await Assert.That((await f.Select(lease)).Status).IsEqualTo(SecretStatus.Success);
        await f.Post(lease);
        await Assert.That(f.ContentWrites).IsEqualTo(1);
        await Assert.That(f.LastPatch!["properties"]!["enableRbacAuthorization"]!.GetValue<bool>()).IsTrue();
        await Assert.That(f.LastPatch["properties"]!.AsObject().Count).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task SettingsForeignParentParserResultCannotQualifyCapturedOwnedResource()
    {
        await using var f = new SettingsFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Select(lease);
        f.Fault = "parent-parser-substitution";
        bool accepted = false;
        try { await f.Post(lease); accepted = true; }
        catch (NativeCaseFailureException) { }
        await Assert.That(f.ParentResponseSubstitutions > 0).IsTrue();
        await Assert.That(accepted && f.ForeignParentStreams > 0).IsFalse();
        if (!accepted) await Assert.That(f.Native.Read().Settings!.SettledDispatch).IsEqualTo(Guid.Empty);
    }

    [Test]
    public async Task SettingsReplayCannotPerformAnotherPatch()
    {
        await using var f = new SettingsFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Select(lease);
        await f.Post(lease);
        await Assert.That(async () => await f.Select(lease)).Throws<InvalidOperationException>();
        await Assert.That(f.Patches).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task SettingsTimerFailureCannotLeakLocalActivity()
    {
        var clock = new ReadTimer();
        await using var f = new SettingsFixture(time: clock);
        var lease = await f.PrepareAndBaseline();
        clock.Fail = true;
        await Assert.That(async () => await f.Select(lease)).Throws<InvalidOperationException>();
        clock.Fail = false;
        await f.Release();
        await Assert.That(f.Patches).IsEqualTo(0);
    }

    [Test]
    public async Task SettingsNativeCompletionCannotClearItsJournalThroughGenericTransitions()
    {
        await using var f = new SettingsFixture();
        var lease = await f.PrepareAndBaseline();
        f.Barrier = "selected-original-sdk";
        var selected = f.Select(lease);
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var row = f.Native.Read().Resources.Single(r => r.Id == f.Native.Wire.VaultId);
            await Assert.That(row.ActiveDispatch != Guid.Empty).IsTrue();
            await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
                .Throws<InvalidOperationException>();
            await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch, nativeSettled: false))
                .Throws<InvalidOperationException>();
            await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
                .Throws<InvalidOperationException>();
            await Assert.That(f.Native.Read().Resources.Single(r => r.Id == row.Id).ActiveDispatch).IsEqualTo(row.ActiveDispatch);
        }
        finally { f.Resume.TrySetResult(); }
        await selected.WaitAsync(TimeSpan.FromSeconds(10));
        await f.Post(lease);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task SettingsUnsettledRestartCannotMintCompletionFromExpectedNativeState()
    {
        await using var f = new SettingsFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Select(lease);
        await using var restarted = f.Reopen();
        using var observer = f.ObserverFor(restarted);
        await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Deletes + f.Purges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    public async Task SettingsSettledRestartCanUseDurableConfigurationForCleanupOnly()
    {
        await using var f = new SettingsFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Select(lease);
        await f.Post(lease);
        await using var restarted = f.Reopen();
        using var observer = f.ObserverFor(restarted);
        RoleFixtureRelease.Validate(await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default), f.Native.Selector, lease.Facts);
        await Assert.That(f.Patches).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    public async Task SettingsCertificateConstructionCannotReserveTerminateOrSettleOriginalInvocation()
    {
        await using var f = new SettingsFixture();
        var lease = await f.PrepareAndBaseline();
        var counterfeitAdmission = new Service.SettingsAdmission(f.Source);
        await Assert.That(() => f.Native.Journal.BeginSettingsInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, counterfeitAdmission)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Settings!.InvocationDispatch).IsEqualTo(Guid.Empty);
        await f.Select(lease);
        Guid dispatch = f.Native.Read().Settings!.InvocationDispatch;
        await Assert.That(dispatch != Guid.Empty).IsTrue();
        await Assert.That(() => f.Native.Journal.EndSettingsInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new Service.SettingsTermination(f.Source, dispatch))).Throws<InvalidOperationException>();
        var counterfeitSettlement = new Service.SettingsSettlement(f.Source, dispatch);
        await Assert.That(() => f.Native.Journal.RegisterSettingsSettlement(Owner, f.Native.Selector,
            lease.Facts.LeaseId, counterfeitSettlement)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleSettingsInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, counterfeitSettlement)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Settings!.SettledDispatch).IsEqualTo(Guid.Empty);
        await f.Post(lease);
        await Assert.That(f.Native.Read().Settings!.SettledDispatch).IsEqualTo(dispatch);
        await Assert.That(() => f.Native.Journal.SettleSettingsInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, counterfeitSettlement)).Throws<InvalidOperationException>();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selected-arm", "credential", false)]
    [Arguments("selected-arm", "transport", true)]
    [Arguments("selected-arm", "body", false)]
    [Arguments("selected-original", "sdk", true)]
    [Arguments("metadata-arm", "credential", true)]
    [Arguments("metadata-arm", "transport", false)]
    [Arguments("metadata-arm", "body", true)]
    [Arguments("metadata-arm", "sdk", false)]
    [Arguments("read-arm", "credential", false)]
    [Arguments("read-arm", "transport", true)]
    [Arguments("read-arm", "body", false)]
    [Arguments("read-arm", "sdk", true)]
    [Arguments("deleted-settings-arm", "credential", true)]
    [Arguments("deleted-settings-arm", "transport", false)]
    [Arguments("deleted-settings-arm", "body", true)]
    [Arguments("deleted-settings-arm", "sdk", false)]
    public async Task SettingsCloseDrainsActualPatchAndIndependentBorrowers(string role, string stage, bool dispose)
    {
        await using var f = new SettingsFixture();
        var lease = await f.PrepareAndBaseline();
        bool selected = role.StartsWith("selected", StringComparison.Ordinal);
        if (!selected) await f.Select(lease);
        f.Barrier = role + "-" + stage;
        Task borrowed = selected ? f.Select(lease) : f.Post(lease).AsTask();
        Task closing = Task.CompletedTask;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            closing = dispose ? f.Source.DisposeAsync().AsTask() : f.Release().AsTask();
            await Assert.That(f.Native.Read().Closing).IsTrue();
            await Assert.That(closing.IsCompleted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        bool rejected = false;
        try { await borrowed.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception failure) when (failure is OperationCanceledException or NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
        await closing.WaitAsync(TimeSpan.FromSeconds(10));
    }

    private sealed class SettingsFixture : IAsyncDisposable
    {
        private const string Capability = "private-vault-settings-capability";
        private static readonly Uri Origin = new("https://vault-settings.invalid/");
        internal readonly Fixture Native;
        internal readonly Effects.Configuration Baseline;
        internal readonly Service Source;
        internal readonly VaultFixtureProvisioner Parent;
        internal readonly OwnedManagementObserver Observer;
        private readonly Service.SettingsSource source;
        private readonly SecretMaterial capability = SecretMaterial.FromText(Capability);
        private readonly List<HttpClient> clients = [];
        private readonly TimeProvider? time;
        private ObservationSubscription? subscription;
        internal string? Fault, Barrier;
        internal int Patches, Deletes, Purges, SelectedGets, SecretRequests;
        internal int ContentWrites;
        internal int ParentResponseSubstitutions, ForeignParentStreams;
        internal int ReplyStatus = 200;
        internal JsonObject? LastPatch;
        internal VaultScope? OriginalScope;
        internal ManagementReceipt? OriginalReceipt;
        internal readonly TaskCompletionSource Entered = Signal(), Resume = Signal();
        private readonly Dictionary<string, Request> requests = [];

        internal SettingsFixture(string variant = "rbac.true", string boundary = "selected-contract", TimeProvider? time = null)
        {
            this.time = time;
            Native = new(rbac: variant == "rbac.false", allowPurge: true);
            Baseline = Native.Baseline with { PublicNetworkAccess = variant == "publicNetworkAccess.false" };
            Native.Selector = Native.Selector with
            {
                Operation = Effects.Members.Single(m => m.Operation.EndsWith(".UpdateSettingsAsync", StringComparison.Ordinal)).Operation,
                Variant = variant,
                Case = boundary
            };
            HttpPipelineTransport Transport(string role)
            {
                var client = new HttpClient(new VaultForwarder((request, token) => Send(request, role, token)));
                clients.Add(client);
                return new SettingsSdk(new HttpClientTransport(client), this, role);
            }
            var host = new VaultFixtureProvisioner.HostScope(Subscription, "fixture-group", "eastus", Tenant, true, true);
            Parent = VaultFixtureProvisioner.ForSettings(Native.Journal, host, Baseline,
                new("settings-admin", new SettingsCredential(this, "setup-arm"), Transport("setup-arm")),
                new("settings-parent", new SettingsCredential(this, "read-arm"), Transport("read-arm")),
                new(65536, TimeSpan.FromSeconds(20)), time);
            source = new(Native.Journal, Parent,
                new("settings-metadata", new SettingsCredential(this, "metadata-arm"), Transport("metadata-arm")),
                new(2, 32, 65536, 8192, TimeSpan.FromSeconds(20)), Transport("selected-arm"));
            Source = Reopen();
            Observer = ObserverFor(Source);
        }
        internal Service Reopen() => new(Origin, Owner, "settings-source", capability,
            new(Subscription, "fixture-group", "eastus", Tenant, true, true), Baseline, source,
            new(65536, 65536, TimeSpan.FromSeconds(20)), time);
        internal OwnedManagementObserver ObserverFor(Service service) =>
            new(new(Origin, Capability, TimeSpan.FromSeconds(20)), new VaultForwarder(service.DispatchAsync));
        internal Effects.Configuration Selected => Native.Selector.Variant switch
        {
            "rbac.omitted" or "publicNetworkAccess.true" => Baseline with { PublicNetworkAccess = true },
            "rbac.false" => Baseline with { Rbac = false },
            "rbac.true" or "purgeProtection.omitted" or "publicNetworkAccess.omitted" => Baseline with { Rbac = true },
            "purgeProtection.true" => Baseline with { PurgeProtection = true },
            "publicNetworkAccess.false" => Baseline with { PublicNetworkAccess = false },
            _ => Baseline
        };
        internal static VaultSettingsPatch Patch(string variant) => variant switch
        {
            "rbac.omitted" or "publicNetworkAccess.true" => new(publicNetworkAccess: true),
            "rbac.false" => new(enableRbacAuthorization: false),
            "rbac.true" or "purgeProtection.omitted" or "publicNetworkAccess.omitted" => new(enableRbacAuthorization: true),
            "purgeProtection.true" => new(enablePurgeProtection: true),
            "purgeProtection.false.rejected" => new(enablePurgeProtection: false),
            "publicNetworkAccess.false" => new(publicNetworkAccess: false),
            _ => throw new InvalidOperationException("unexpected-settings-variant")
        };
        internal async Task<Effects.Lease> PrepareAndBaseline()
        {
            var lease = await Observer.PostAsync<Effects.Prepare, Effects.Lease>("vault/prepare",
                new(Native.Selector, Subscription, "fixture-group", Selected, Baseline.Policies, Guid.Empty), default);
            subscription = await Observer.SubscribeAsync("vault", lease.Facts, default);
            await Observer.PostAsync<ObserveLease, Effects.Measurement>("vault/observe",
                new(lease.Facts.LeaseId, lease.Facts.Nonce, "baseline-before-dispatch", subscription.SubscriptionId), default);
            return lease;
        }
        internal Task<SecretOutcome<VaultObservation>> Select(Effects.Lease lease, bool denied = false)
        {
            var client = new VaultAdministration(new SettingsCredential(this, denied ? "denied-arm" : "selected-arm"),
                new SettingsSdk(Source.SelectedTransport, this, "selected-original"));
            OriginalScope = new(new(new(Subscription), "fixture-group"), lease.VaultName);
            OriginalReceipt = client.PrepareReceipt(OriginalScope, ManagementMutation.UpdateVault);
            return Source.RunUpdateSettingsAsync(Native.Selector, client, OriginalScope,
                Patch(Native.Selector.Variant), OriginalReceipt, default).AsTask();
        }
        internal ValueTask<Effects.Measurement> Post(Effects.Lease lease) =>
            Observer.PostAsync<ObserveLease, Effects.Measurement>("vault/observe",
                new(lease.Facts.LeaseId, lease.Facts.Nonce, "post-operation", subscription!.SubscriptionId), default);
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
                        Subscription, "fixture-group", Baseline, Baseline.Policies, Guid.Empty,
                        2, 32, TimeSpan.FromSeconds(20))
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
                })), selectedTransport: Source.SelectedTransport, selectedInvocation: Source);
            return (await NativeCaseRunner.RunAsync(registry, [definition], default)).Single();
        }
        private string BarrierRole(string role, Request? request) =>
            role == "read-arm" && request?.Uri.ToUri().AbsolutePath.Contains("/deletedVaults/", StringComparison.Ordinal) == true
                ? "deleted-settings-arm" : role;
        private async ValueTask Block(string role, string stage)
        {
            if (Barrier != role + "-" + stage) return;
            Entered.TrySetResult();
            await Resume.Task;
        }
        private async Task<HttpResponseMessage> Send(HttpRequestMessage request, string role, CancellationToken token)
        {
            string path = request.RequestUri!.AbsolutePath;
            if (Native.Wire.VaultId.Length == 0 && path.Contains("/vaults/", StringComparison.Ordinal))
            {
                Native.Wire.VaultId = path;
                Native.Wire.VaultName = path[(path.LastIndexOf('/') + 1)..];
            }
            if (request.RequestUri.Host != "management.azure.com") SecretRequests++;
            string channel = role == "read-arm" && path.Contains("/deletedVaults/", StringComparison.Ordinal)
                ? "deleted-settings-arm" : role;
            await Block(channel, "transport");
            if (role == "selected-arm")
            {
                if (request.Method == HttpMethod.Get) SelectedGets++;
                if (request.Method != HttpMethod.Patch || path != Native.Wire.VaultId ||
                    request.RequestUri.Query != "?api-version=2026-02-01")
                    throw new InvalidOperationException("unexpected-settings-request");
                Patches++;
                LastPatch = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
                if (Fault == "exception-denial") throw new Azure.RequestFailedException(403, "controlled-no-response");
                if (request.Headers.Authorization?.Parameter == "denied-arm")
                    return Reply(403, """{"error":{"code":"Forbidden","message":"controlled-denial"}}""");
                var acknowledged = Native.Wire.Vault!.DeepClone();
                foreach (var property in LastPatch["properties"]!.AsObject())
                    acknowledged["properties"]![property.Key] = property.Value?.DeepClone();
                if (Fault != "no-mutation") Native.Wire.Vault = acknowledged.DeepClone().AsObject();
                if (Fault == "id") acknowledged["id"] = Native.Wire.VaultId + "-foreign";
                if (Fault == "type") acknowledged["type"] = "Microsoft.Network/privateEndpoints";
                if (Fault == "owner") acknowledged["tags"]!["secretkit-fixture"] = "foreign";
                if (Fault == "provisioning") acknowledged["properties"]!["provisioningState"] = "Updating";
                if (Fault == "missing-rbac") acknowledged["properties"]!.AsObject().Remove("enableRbacAuthorization");
                if (Fault == "null-purge") acknowledged["properties"]!["enablePurgeProtection"] = null;
                if (Fault == "retention") acknowledged["properties"]!["softDeleteRetentionInDays"] = 24;
                if (Fault == "sku") acknowledged["properties"]!["sku"]!["name"] = "standard";
                if (Fault == "policy") acknowledged["properties"]!["accessPolicies"] = new JsonArray();
                if (Fault == "untouched-network") acknowledged["properties"]!["publicNetworkAccess"] = "Enabled";
                string payload = Fault == "malformed" ? "{" : Fault == "oversized" ?
                    "{\"padding\":\"" + new string('x', 70000) + "\"}" : acknowledged.ToJsonString();
                var response = Reply(ReplyStatus, payload, Fault != "missing-request-id");
                if (Fault == "async") response.Headers.Add("Azure-AsyncOperation", "https://management.azure.com/operations/controlled");
                return await Body(response, channel);
            }
            if (role == "setup-arm" && request.Method == HttpMethod.Delete) Deletes++;
            if (role == "setup-arm" && request.Method == HttpMethod.Post) Purges++;
            if (request.Method == HttpMethod.Get && path.Contains("/deletedVaults/", StringComparison.Ordinal) && Native.Wire.Deleted)
            {
                var deleted = new JsonObject
                {
                    ["id"] = path,
                    ["name"] = Native.Wire.VaultName,
                    ["type"] = "Microsoft.KeyVault/locations/deletedVaults",
                    ["properties"] = new JsonObject
                    {
                        ["vaultId"] = Native.Wire.VaultId,
                        ["location"] = "eastus",
                        ["tags"] = Native.Wire.Vault!["tags"]!.DeepClone(),
                        ["purgeProtectionEnabled"] = Native.Wire.Vault["properties"]!["enablePurgeProtection"]!.DeepClone(),
                        ["deletionDate"] = "2026-10-16T00:00:00Z",
                        ["scheduledPurgeDate"] = "2026-11-08T00:00:00Z"
                    }
                };
                return await Body(Reply(200, deleted.ToJsonString()), channel);
            }
            return await Body(await Native.Wire.Respond(request, role, token), channel);
        }
        private static HttpResponseMessage Reply(int status, string body, bool id = true)
        {
            var response = new HttpResponseMessage((HttpStatusCode)status)
            { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            if (id) response.Headers.Add("x-ms-request-id", "controlled-settings-" + Guid.NewGuid().ToString("N"));
            return response;
        }
        private async ValueTask<HttpResponseMessage> Body(HttpResponseMessage response, string channel)
        {
            if (Barrier == channel + "-body")
            {
                var content = response.Content;
                response.Content = new StreamContent(new SettingsBody(await content.ReadAsByteArrayAsync(), this, channel));
                content.Dispose();
                response.Content.Headers.ContentType = new("application/json");
            }
            return response;
        }
        public async ValueTask DisposeAsync()
        {
            Resume.TrySetResult();
            try { await Source.DisposeAsync(); }
            finally
            {
                try { await Parent.DisposeAsync(); }
                finally
                {
                    Observer.Dispose();
                    foreach (var client in clients) client.Dispose();
                    capability.Dispose();
                    Native.Dispose();
                }
            }
        }
        private sealed class SettingsCredential(SettingsFixture fixture, string role) : TokenCredential
        {
            public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
                throw new InvalidOperationException("async-only");
            public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
            {
                fixture.requests.TryGetValue(role, out var request);
                await fixture.Block(fixture.BarrierRole(role, request), "credential");
                cancellationToken.ThrowIfCancellationRequested();
                return new(role, DateTimeOffset.MaxValue);
            }
        }
        private sealed class SettingsSdk(HttpPipelineTransport inner, SettingsFixture fixture, string role) : HttpPipelineTransport
        {
            public override Request CreateRequest()
            {
                var request = inner.CreateRequest();
                fixture.requests[role] = request;
                return request;
            }
            public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
            public override async ValueTask ProcessAsync(HttpMessage message)
            {
                if (role == "selected-original" && fixture.Fault == "stateful-content" &&
                    message.Request.Method == RequestMethod.Patch && message.Request.Content is { } original)
                    message.Request.Content = new SettingsChangingContent(original, fixture);
                await inner.ProcessAsync(message);
                if (role == "read-arm" && fixture.Fault == "parent-parser-substitution" &&
                    message.Request.Uri.ToUri().AbsolutePath == fixture.Native.Wire.VaultId &&
                    message.Response.Status == 200)
                {
                    fixture.ParentResponseSubstitutions++;
                    message.Response = new SettingsChangingParentResponse(message.Response, fixture);
                }
                if (message.Request.Headers.Contains("Authorization"))
                    await fixture.Block(fixture.BarrierRole(role, message.Request), "sdk");
            }
        }
        private sealed class SettingsChangingParentResponse(Response inner, SettingsFixture fixture) : Response
        {
            private bool captured;
            private readonly List<Stream> foreign = [];
            public override int Status => inner.Status;
            public override string ReasonPhrase => inner.ReasonPhrase;
            public override string ClientRequestId { get => inner.ClientRequestId; set => inner.ClientRequestId = value; }
            public override Stream? ContentStream
            {
                get
                {
                    if (!captured) return inner.ContentStream;
                    fixture.ForeignParentStreams++;
                    var row = fixture.Native.Wire.Vault!.DeepClone();
                    row["id"] = fixture.Native.Wire.VaultId + "-foreign";
                    row["tags"]!["secretkit-fixture"] = "foreign";
                    row["properties"]!["vaultUri"] = "https://foreign.vault.azure.net/";
                    var stream = new MemoryStream(Encoding.UTF8.GetBytes(row.ToJsonString()));
                    foreign.Add(stream);
                    return stream;
                }
                set { captured = true; inner.ContentStream = value; }
            }
            public override void Dispose()
            {
                try { inner.Dispose(); }
                finally { foreach (var stream in foreign) stream.Dispose(); }
            }
            protected override bool ContainsHeader(string name) => inner.Headers.Contains(name);
            protected override IEnumerable<HttpHeader> EnumerateHeaders() => inner.Headers;
            protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) => inner.Headers.TryGetValue(name, out value);
            protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) =>
                inner.Headers.TryGetValues(name, out values);
        }
        private sealed class SettingsChangingContent(RequestContent original, SettingsFixture fixture) : RequestContent
        {
            private static readonly byte[] Foreign = Encoding.UTF8.GetBytes(
                """{"properties":{"enableRbacAuthorization":false}}""");
            public override void WriteTo(Stream stream, CancellationToken cancellation)
            {
                if (++fixture.ContentWrites == 1) original.WriteTo(stream, cancellation);
                else stream.Write(Foreign);
            }
            public override async Task WriteToAsync(Stream stream, CancellationToken cancellation)
            {
                if (++fixture.ContentWrites == 1) await original.WriteToAsync(stream, cancellation);
                else await stream.WriteAsync(Foreign, cancellation);
            }
            public override bool TryComputeLength(out long length) => original.TryComputeLength(out length);
            public override void Dispose() => original.Dispose();
        }
        private sealed class SettingsBody(byte[] bytes, SettingsFixture fixture, string role) : MemoryStream(bytes)
        {
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                await fixture.Block(role, "body");
                return await base.ReadAsync(buffer, cancellationToken);
            }
        }
    }
}
