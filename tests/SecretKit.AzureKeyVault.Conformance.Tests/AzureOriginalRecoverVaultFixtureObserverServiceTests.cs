using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using RecoverService = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationFixtureObserverService;
using V = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    public static IEnumerable<(string Variant, string Boundary)> OriginalRecoverConfigurations()
    {
        foreach (string variant in V.ConfigurationVariants)
            foreach (string boundary in new[]
            {
                "selected-contract", "independent-effect", "denied-authority",
                "cancellation-boundary", "lost-response-no-replay"
            })
                yield return (variant, boundary);
    }

    [Test]
    [MethodDataSource(nameof(OriginalRecoverConfigurations))]
    public async Task OriginalVaultRecoverRestoresExactConfiguration(string variant, string boundary)
    {
        await using var f = new OriginalVaultRecoverFixture(boundary, variant);
        var result = await f.RunOriginal();
        bool uncertain = boundary is "cancellation-boundary" or "lost-response-no-replay";
        bool denied = boundary == "denied-authority";
        bool incomplete = uncertain || f.Configuration.PurgeProtection;
        await Assert.That(result.Passed).IsEqualTo(!incomplete);
        if (incomplete) await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(f.SelectedPuts).IsEqualTo(1);
        await Assert.That(f.SetupPuts).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.StatusReads).IsEqualTo(denied || uncertain ? 0 : 1);
        await Assert.That(f.SelectedPolls).IsEqualTo(denied || uncertain ? 0 : 1);
        await Assert.That(f.SelectedFinals).IsEqualTo(denied || uncertain ? 0 : 1);
        await Assert.That(f.Tap.Completions).IsEqualTo(denied || uncertain ? 0 : 1);
        await Assert.That(f.CleanupDeletes).IsEqualTo(denied || uncertain ? 0 : 1);
        await Assert.That(f.CleanupPurges).IsEqualTo(incomplete ? 0 : 1);
        await Assert.That(f.SecretRequests).IsEqualTo(0);
        await Assert.That(f.Prejournaled && f.Native.Wire.Prejournaled).IsTrue();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(3);
        await Assert.That(f.Native.Read().Released).IsEqualTo(!incomplete);
        if (!uncertain)
            await Assert.That(f.Tap.Receipt!.Evidence).IsEqualTo(denied ? DispatchEvidence.Rejected : DispatchEvidence.Pending);
        if (!denied)
        {
            await Assert.That(f.SelectedBody!.ContainsKey("tags")).IsFalse();
            var p = f.SelectedBody["properties"]!;
            await Assert.That(p["createMode"]!.GetValue<string>()).IsEqualTo("recover");
            await Assert.That(p["publicNetworkAccess"]!.GetValue<string>())
                .IsEqualTo(f.Configuration.PublicNetworkAccess ? "Enabled" : "Disabled");
            await Assert.That(p["enablePurgeProtection"]!.GetValue<bool>()).IsEqualTo(f.Configuration.PurgeProtection);
            await Assert.That(p["enableRbacAuthorization"]!.GetValue<bool>()).IsEqualTo(f.Configuration.Rbac);
            await Assert.That(p["accessPolicies"]!.AsArray().Count).IsEqualTo(f.Configuration.Policies.Length);
        }
        if (uncertain)
            await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    [Arguments("pending")]
    [Arguments("failed")]
    [Arguments("canceled")]
    [Arguments("unknown")]
    [Arguments("status-malformed")]
    [Arguments("status-denied")]
    [Arguments("selected-malformed")]
    [Arguments("synchronous")]
    [Arguments("accepted")]
    [Arguments("no-target")]
    [Arguments("foreign-target")]
    [Arguments("unchanged")]
    [Arguments("deleted-present")]
    [Arguments("missing-owner")]
    [Arguments("foreign-owner")]
    [Arguments("wrong-retention")]
    [Arguments("wrong-network")]
    [Arguments("missing-child")]
    [Arguments("nonempty-child")]
    [Arguments("poll-malformed")]
    [Arguments("poll-denied")]
    [Arguments("final-malformed")]
    [Arguments("final-lost")]
    public async Task OriginalVaultRecoverRejectsIncompleteNativeConjunction(string fault)
    {
        await using var f = new OriginalVaultRecoverFixture();
        f.Fault = fault;
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SelectedPuts).IsEqualTo(1);
        await Assert.That(f.CleanupDeletes + f.CleanupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("publicNetworkAccess.false")]
    [Arguments("accessPolicies.selected")]
    [Arguments("lro.started")]
    public async Task OriginalVaultRecoverPostPreservesPendingUntilActualCompletion(string variant)
    {
        await using var f = new OriginalVaultRecoverFixture(variant: variant);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await Assert.That(started.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(started.Value!.State).IsEqualTo(NativeProvisioningState.Pending);
        await f.Post(lease);
        await Assert.That(started.Value.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.SelectedPolls + f.SelectedFinals).IsEqualTo(0);
        await Assert.That(f.StatusReads).IsEqualTo(1);
        await f.Post(lease);
        await Assert.That(f.StatusReads).IsEqualTo(1);
        await Assert.That(await f.Source.CompleteRecoverVaultAsync(f.Native.Selector, started.Value, default))
            .IsEqualTo(SecretStatus.Success);
        await Assert.That(started.Value.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await f.Release();
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("unequal")]
    [Arguments("tenant")]
    [Arguments("location")]
    [Arguments("retention")]
    [Arguments("variant")]
    [Arguments("empty-policies")]
    public async Task OriginalVaultRecoverRejectsInvalidRestorationPair(string fault)
    {
        await using var f = new OriginalVaultRecoverFixture();
        var baseline = f.Configuration;
        var selected = baseline;
        string variant = f.Native.Selector.Variant;
        switch (fault)
        {
            case "unequal": selected = selected with { Sku = VaultSku.Premium }; break;
            case "tenant": selected = selected with { TenantId = Guid.NewGuid() }; break;
            case "location": selected = selected with { Location = "westus" }; break;
            case "retention": selected = selected with { RetentionDays = 24 }; break;
            case "variant": variant = "publicNetworkAccess.false"; break;
            case "empty-policies": variant = "accessPolicies.selected"; break;
        }
        await Assert.That(VaultFixtureProvisioner.ValidRecoverVaultConfigurations(variant, baseline, selected)).IsFalse();
        await Assert.That(f.SetupPuts + f.SelectedPuts).IsEqualTo(0);
    }

    [Test]
    [Arguments("unresolved")]
    [Arguments("recovered")]
    [Arguments("denied")]
    [Arguments("protected")]
    public async Task OriginalVaultRecoverRestartUsesOnlyDurableDisposition(string state)
    {
        bool denied = state == "denied";
        await using var f = new OriginalVaultRecoverFixture(denied ? "denied-authority" : "selected-contract",
            state == "protected" ? "purgeProtection.true" : "publicNetworkAccess.true");
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease, denied);
        if (state != "unresolved")
        {
            await f.Post(lease);
            if (!denied) await f.Source.CompleteRecoverVaultAsync(f.Native.Selector, started.Value!, default);
        }
        await using var parent = f.CleanupParent();
        await using var source = RecoverService.ForRecoverVaultCleanup(OriginalVaultRecoverFixture.Origin, Owner,
            "recover-restart", f.CapabilityMaterial, OriginalVaultRecoverFixture.Host, parent,
            new(65536, 65536, TimeSpan.FromSeconds(20)));
        using var observer = new OwnedManagementObserver(
            new(OriginalVaultRecoverFixture.Origin, OriginalVaultRecoverFixture.Capability, TimeSpan.FromSeconds(20)),
            new VaultForwarder(source.DispatchAsync));
        await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>("vault/release", f.Native.Selector, default);
        bool complete = state is "recovered" or "denied";
        await Assert.That(f.Native.Read().Released).IsEqualTo(complete);
        await Assert.That(f.SelectedPuts).IsEqualTo(1);
        await Assert.That(f.CleanupDeletes).IsEqualTo(state is "recovered" or "protected" ? 1 : 0);
        await Assert.That(f.CleanupPurges).IsEqualTo(complete ? 1 : 0);
    }

    [Test]
    public async Task OriginalVaultRecoverRejectsGenericAndCounterfeitProofs()
    {
        await using var f = new OriginalVaultRecoverFixture();
        var lease = await f.PrepareAndBaseline();
        await Assert.That(() => f.Native.Journal.BeginRecoverVaultInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new RecoverService.RecoverVaultAdmission(f.Source))).Throws<InvalidOperationException>();
        await f.Start(lease);
        var row = f.Native.Read().Resources.Single(r => r.Id == f.Native.Wire.VaultId);
        await Assert.That(row.ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(() => f.Native.Journal.EndRecoverVaultInvocation(Owner, f.Native.Selector, lease.Facts.LeaseId,
            new RecoverService.RecoverVaultTermination(f.Source, row.ActiveDispatch))).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleRecoverVaultInvocation(Owner, f.Native.Selector, lease.Facts.LeaseId,
            new RecoverService.RecoverVaultSettlement(f.Source, row.ActiveDispatch))).Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch, nativeSettled: false))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        f.Native.Journal.Close(Owner, f.Native.Selector);
        await Assert.That(() => f.Native.Journal.RecordAbsence(Owner, f.Native.Selector, row.Id)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == row.Id).ActiveDispatch).IsEqualTo(row.ActiveDispatch);
    }

    [Test]
    [Arguments("start")]
    [Arguments("status")]
    [Arguments("parent")]
    [Arguments("deleted")]
    [Arguments("poll")]
    [Arguments("final")]
    public async Task OriginalVaultRecoverCloseDrainsActualBorrowerBeforeCleanup(string stage)
    {
        await using var f = new OriginalVaultRecoverFixture();
        var lease = await f.PrepareAndBaseline();
        Task work;
        if (stage == "start")
        {
            f.Barrier = stage;
            work = f.Start(lease);
        }
        else
        {
            var started = await f.Start(lease);
            if (stage is "poll" or "final")
            {
                await f.Post(lease);
                f.Barrier = stage;
                work = f.Source.CompleteRecoverVaultAsync(f.Native.Selector, started.Value!, default).AsTask();
            }
            else
            {
                f.Barrier = stage;
                work = f.Post(lease).AsTask();
            }
        }
        Task? disposing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await f.Release();
            disposing = f.Source.DisposeAsync().AsTask();
            await Assert.That(work.IsCompleted || disposing.IsCompleted).IsFalse();
            await Assert.That(f.CleanupDeletes + f.CleanupPurges).IsEqualTo(0);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception ex) when (ex is OperationCanceledException or NativeCaseFailureException or InvalidOperationException) { }
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("start", false)]
    [Arguments("start", true)]
    [Arguments("poll", false)]
    [Arguments("poll", true)]
    [Arguments("final", false)]
    [Arguments("final", true)]
    public async Task OriginalVaultRecoverRejectsIndependentSdkResponseReplacement(string stage, bool disposeOriginal)
    {
        await using var f = new OriginalVaultRecoverFixture();
        f.ReplaceStage = stage;
        f.DisposeOriginal = disposeOriginal;
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.Replacements).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.CleanupDeletes + f.CleanupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("retry")]
    [Arguments("close")]
    [Arguments("dispose")]
    public async Task OriginalVaultRecoverPersistsDrainedDecisionWithoutProviderReplay(string mode)
    {
        await using var f = new OriginalVaultRecoverFixture();
        var lease = await f.PrepareAndBaseline();
        f.LockOnFinalization = true;
        var started = await f.Start(lease);
        await f.Post(lease);
        await Assert.That(f.JournalLock).IsNull();
        Exception? failure = null;
        try { await f.Source.CompleteRecoverVaultAsync(f.Native.Selector, started.Value!, default); }
        catch (Exception ex) { failure = ex; }
        try
        {
            await Assert.That(failure).IsNotNull();
            await Assert.That(f.JournalLock).IsNotNull();
        }
        finally { f.UnlockJournal(); }
        int reads = f.ParentReads;
        if (mode == "retry")
        {
            await Assert.That(await f.Source.CompleteRecoverVaultAsync(f.Native.Selector, started.Value!, default))
                .IsEqualTo(SecretStatus.Success);
            await Assert.That(f.ParentReads).IsEqualTo(reads);
            await Assert.That(f.Native.Read().Idle).IsTrue();
            RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        }
        else
        {
            if (mode == "close") await f.Release();
            await f.Source.DisposeAsync();
            await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
            await Assert.That(f.ParentReads).IsEqualTo(reads);
            await Assert.That(f.CleanupDeletes + f.CleanupPurges).IsEqualTo(0);
        }
        await Assert.That(f.SelectedPuts).IsEqualTo(1);
        await Assert.That(f.SelectedPolls).IsEqualTo(1);
        await Assert.That(f.SelectedFinals).IsEqualTo(1);
    }

    private sealed class OriginalVaultRecoverFixture : IAsyncDisposable
    {
        internal const string Capability = "original-vault-recover-controlled-capability";
        internal static readonly Uri Origin = new("https://original-vault-recover.invalid/");
        private static readonly string StatusPath =
            $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/operations/77777777-7777-7777-7777-777777777777";
        internal readonly Fixture Native = new(rbac: true, allowPurge: true, emptyPolicies: true);
        internal readonly V.Configuration Configuration;
        internal readonly V.Policy[] IntendedPolicies =
        [
            new(Tenant, Principal, [SecretPermission.Get, SecretPermission.Set], null),
            new(Tenant, Guid.Parse("33333333-3333-3333-3333-333333333334"), [SecretPermission.Get],
                Guid.Parse("44444444-4444-4444-4444-444444444445"))
        ];
        internal readonly VaultFixtureProvisioner Parent;
        internal readonly RecoverService Source;
        internal readonly OwnedManagementObserver Observer;
        internal readonly RecoverTap Tap;
        private readonly SecretMaterial capability = SecretMaterial.FromText(Capability);
        internal SecretMaterial CapabilityMaterial => capability;
        private readonly List<HttpClient> clients = [];
        private ObservationSubscription? subscription;
        internal string? Fault;
        internal string? Barrier;
        internal string? ReplaceStage;
        internal bool DisposeOriginal;
        internal int Replacements;
        internal bool LockOnFinalization;
        internal FileStream? JournalLock;
        internal readonly TaskCompletionSource Entered = Signal(), Resume = Signal();
        internal JsonObject? SelectedBody;
        internal int SelectedPuts, SetupPuts, SetupDeletes, StatusReads, SelectedPolls, SelectedFinals;
        internal int CleanupDeletes, CleanupPurges, SecretRequests, ParentReads;
        internal bool Prejournaled = true;
        internal static VaultFixtureProvisioner.HostScope Host => new(Subscription, "fixture-group", "eastus", Tenant, true, true);
        private string DeletedId =>
            $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/{Native.Wire.VaultName}";

        internal OriginalVaultRecoverFixture(string boundary = "selected-contract", string variant = "publicNetworkAccess.true")
        {
            Native.Selector = Native.Selector with
            {
                Operation = "a.management.VaultAdministration.RecoverVaultAsync", Variant = variant, Case = boundary
            };
            Configuration = V.SelectConfiguration(Native.Baseline with
            { Sku = VaultSku.Standard, PublicNetworkAccess = true }, IntendedPolicies, variant);
            Parent = VaultFixtureProvisioner.ForRecoverVault(Native.Journal, Host, variant, Configuration, Configuration,
                new("recover-admin", new Credential("setup-arm"), Transport("setup-arm")),
                new("recover-parent", new Credential("read-arm"), Transport("read-arm")),
                new(65536, TimeSpan.FromSeconds(20)));
            Source = new(Origin, Owner, "original-recover-source", capability, Host,
                new RecoverService.RecoverVaultSource(Parent,
                    new("recover-status", new Credential("status-arm"), Transport("status-arm")),
                    Transport("selected-arm"), new(65536, 8192, 512, TimeSpan.FromSeconds(20))),
                new(65536, 65536, TimeSpan.FromSeconds(20)));
            Observer = new(new(Origin, Capability, TimeSpan.FromSeconds(20)), new VaultForwarder(Source.DispatchAsync));
            Tap = new(Source);
        }
        private HttpPipelineTransport Transport(string role)
        {
            var client = new HttpClient(new VaultForwarder((request, token) => Send(request, role, token)));
            clients.Add(client);
            var transport = new HttpClientTransport(client);
            return role == "selected-arm" ? new RecoverBackend(transport, this) : transport;
        }
        internal async Task<V.Lease> PrepareAndBaseline()
        {
            var lease = await Observer.PostAsync<V.Prepare, V.Lease>("vault/prepare",
                new(Native.Selector, Subscription, "fixture-group", Configuration, IntendedPolicies, Guid.Empty), default);
            subscription = await Observer.SubscribeAsync("vault", lease.Facts, default);
            await Observer.PostAsync<ObserveLease, V.Measurement>("vault/observe",
                new(lease.Facts.LeaseId, lease.Facts.Nonce, "baseline-before-dispatch", subscription.SubscriptionId), default);
            return lease;
        }
        internal Task<SecretOutcome<ManagementOperation>> Start(V.Lease lease, bool denied = false)
        {
            var client = new VaultAdministration(new RecoverCredential(denied ? "denied-arm" : "selected-original"),
                new RecoverSdk(Source.SelectedTransport, this));
            var scope = new VaultScope(new(new(Subscription), "fixture-group"), lease.VaultName);
            return Tap.RunRecoverVaultAsync(Native.Selector, client, scope, Configuration.Build(),
                client.PrepareReceipt(scope, ManagementMutation.RecoverVault), default).AsTask();
        }
        internal ValueTask<V.Measurement> Post(V.Lease lease) => Observer.PostAsync<ObserveLease, V.Measurement>(
            "vault/observe", new(lease.Facts.LeaseId, lease.Facts.Nonce, "post-operation", subscription!.SubscriptionId), default);
        internal ValueTask<RoleFixtureRelease.Measurement> Release() =>
            Observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>("vault/release", Native.Selector, default);
        internal VaultFixtureProvisioner CleanupParent() => VaultFixtureProvisioner.ForCleanup(
            new RoleFixtureJournal(Path.GetDirectoryName(Native.JournalPath) ?? throw new InvalidOperationException("journal-directory")),
            Host, new("recover-cleanup-admin", new Credential("setup-arm"), Transport("setup-arm")),
            new("recover-cleanup-parent", new Credential("read-arm"), Transport("read-arm")),
            new(65536, TimeSpan.FromSeconds(20)));
        internal async Task<NativeCaseResult> RunOriginal()
        {
            object Runtime(string role) => new { token = role, expiresAt = "2099-01-01T00:00:00Z" };
            AudienceToken Arm(string role) => new(role, DateTimeOffset.MaxValue, "https://management.azure.com/.default");
            using var json = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                vaultUri = "https://controlled.vault.azure.net",
                setup = Runtime("setup-secret"), runtime = Runtime("runtime-secret"), denied = Runtime("denied-secret"),
                administrative = Runtime("admin-secret"), observer = Runtime("observer-secret"),
                families = new Dictionary<string, object>
                {
                    ["VaultAdministration"] = new V.Input(new(Origin, Capability, TimeSpan.FromSeconds(20)),
                        new(Arm("setup-arm"), Arm("selected-original"), Arm("denied-arm"), Arm("observer-arm")),
                        Subscription, "fixture-group", Configuration, IntendedPolicies,
                        Guid.Empty, 2, 32, TimeSpan.FromSeconds(20))
                }
            }, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
            using var environment = OwnedAzureEnvironment.Create(json.RootElement);
            var member = V.Members.Single(m => m.Operation == Native.Selector.Operation);
            var definition = new NativeCaseDefinition(new("AzureKeyVault", member.Operation, Native.Selector.Variant,
                "controlled", Native.Selector.Case), member.Member);
            var registry = new NativeCaseRegistry();
            V.Register(registry, environment, [definition], endpoint => new(endpoint,
                new VaultForwarder(async (request, token) =>
                {
                    if (request.RequestUri!.AbsolutePath == "/vault/prepare")
                        Native.Selector = JsonSerializer.Deserialize<V.Prepare>(
                            await request.Content!.ReadAsByteArrayAsync(token), ManagementAdmission.Json)!.Selection;
                    return await Source.DispatchAsync(request, token);
                })), selectedTransport: new RecoverSdk(Source.SelectedTransport, this), recoverSelectedInvocation: Tap);
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
            if (request.RequestUri.Host != "management.azure.com") SecretRequests++;
            string? bearer = request.Headers.Authorization?.Parameter;
            if (role == "read-arm") ParentReads++;
            if (request.RequestUri.Host != "management.azure.com" || request.RequestUri.Query != "?api-version=2026-02-01" ||
                (role == "selected-arm" ? bearer is not ("selected-original" or "denied-arm") : bearer != role))
                throw new InvalidOperationException("unexpected-recover-authority-or-route");
            string stage = role == "selected-arm" ? request.Method == HttpMethod.Put ? "start" :
                path == StatusPath ? "poll" : "final" : role == "status-arm" ? "status" :
                role == "read-arm" ? path == DeletedId ? "deleted" : "parent" : "setup";
            if (Barrier == stage)
            {
                Entered.TrySetResult();
                await Resume.Task;
            }
            if (role == "selected-arm" && request.Method == HttpMethod.Put)
            {
                if (path != Native.Wire.VaultId) throw new InvalidOperationException("unexpected-selected-recover");
                SelectedPuts++;
                Prejournaled &= Native.Read().Resources.Single(r => r.Id == path).ActiveDispatch != Guid.Empty;
                if (bearer == "denied-arm") return Reply(403, """{"error":{"code":"Forbidden"}}""");
                SelectedBody = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
                // Controlled restoration/retained tags are not live Azure evidence.
                if (Fault != "unchanged") Native.Wire.Active = true;
                Native.Wire.Deleted = Fault is "deleted-present" or "unchanged";
                var payload = Native.Wire.Vault!.DeepClone();
                payload["properties"]!["provisioningState"] = "Updating";
                var response = Reply(Fault == "synchronous" ? 200 : Fault == "accepted" ? 202 : 201,
                    Fault == "selected-malformed" ? "{" : payload.ToJsonString());
                if (Fault is not ("no-target" or "synchronous"))
                    response.Headers.Add("Azure-AsyncOperation",
                        (Fault == "foreign-target" ? "https://foreign.invalid" : "https://management.azure.com") +
                        StatusPath + "?api-version=2026-02-01");
                return response;
            }
            if (role == "status-arm" || role == "selected-arm" && request.Method == HttpMethod.Get && path == StatusPath)
            {
                if (request.Method != HttpMethod.Get || path != StatusPath) throw new InvalidOperationException("unexpected-recover-status");
                if (role == "status-arm") StatusReads++; else SelectedPolls++;
                if (Fault == stage + "-denied") return Reply(403, """{"error":{"code":"Forbidden"}}""");
                if (Fault == stage + "-malformed") return Reply(200, "{");
                string state = role == "status-arm" ? Fault switch
                {
                    "pending" => "InProgress", "failed" => "Failed", "canceled" => "Canceled",
                    "unknown" => "future-state", _ => "Succeeded"
                } : "Succeeded";
                return Reply(200, JsonSerializer.Serialize(new
                { id = StatusPath, name = StatusPath[(StatusPath.LastIndexOf('/') + 1)..], status = state }));
            }
            if (role == "selected-arm")
            {
                if (request.Method != HttpMethod.Get || path != Native.Wire.VaultId)
                    throw new InvalidOperationException("unexpected-recover-final");
                SelectedFinals++;
                if (Fault == "final-lost") throw new IOException("controlled-final-loss");
                return Reply(200, Fault == "final-malformed" ? "{" : Native.Wire.Vault!.ToJsonString());
            }
            if (role == "setup-arm")
            {
                if (request.Method == HttpMethod.Put) SetupPuts++;
                if (request.Method == HttpMethod.Delete)
                {
                    if (SelectedPuts == 0) SetupDeletes++; else CleanupDeletes++;
                }
                if (request.Method == HttpMethod.Post) CleanupPurges++;
            }
            if (request.Method == HttpMethod.Get && path == Native.Wire.VaultId && Native.Wire.Active)
            {
                var row = Native.Wire.Vault!.DeepClone();
                if (SelectedPuts > 0)
                {
                    if (Fault == "missing-owner") row.AsObject().Remove("tags");
                    if (Fault == "foreign-owner") row["tags"]!["secretkit-fixture"] = "foreign";
                    if (Fault == "wrong-retention") row["properties"]!["softDeleteRetentionInDays"] = 7;
                    if (Fault == "wrong-network") row["properties"]!["publicNetworkAccess"] = "Disabled";
                    if (Fault == "missing-child") row["properties"]!.AsObject().Remove("privateEndpointConnections");
                    if (Fault == "nonempty-child")
                        row["properties"]!["privateEndpointConnections"] = new JsonArray(new JsonObject { ["id"] = path + "/privateEndpointConnections/foreign" });
                }
                return Reply(200, row.ToJsonString());
            }
            if (request.Method == HttpMethod.Get && path == DeletedId && Native.Wire.Deleted)
                return Reply(200, JsonSerializer.Serialize(new
                {
                    id = path, name = Native.Wire.VaultName, type = "Microsoft.KeyVault/locations/deletedVaults",
                    properties = new
                    {
                        vaultId = Native.Wire.VaultId, location = "eastus", tags = Native.Wire.Vault!["tags"],
                        purgeProtectionEnabled = Configuration.PurgeProtection,
                        deletionDate = "2026-10-16T00:00:00Z", scheduledPurgeDate = "2026-11-08T00:00:00Z"
                    }
                }));
            var native = await Native.Wire.Respond(request, role, token);
            if (Native.Wire.Vault is not null)
                Native.Wire.Vault["properties"]!["privateEndpointConnections"] = new JsonArray();
            return native;
        }
        private static HttpResponseMessage Reply(int status, string body) => new((HttpStatusCode)status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
            Headers = { { "x-ms-request-id", "controlled-original-recover-" + Guid.NewGuid().ToString("N") } }
        };
        public async ValueTask DisposeAsync()
        {
            Resume.TrySetResult();
            UnlockJournal();
            try { await Source.DisposeAsync(); }
            finally
            {
                UnlockJournal();
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
        internal void UnlockJournal() { JournalLock?.Dispose(); JournalLock = null; }
        internal sealed class RecoverTap(RecoverService source) : V.RecoverSelectedInvocation
        {
            internal ManagementReceipt? Receipt;
            internal int Completions;
            public ValueTask<SecretOutcome<ManagementOperation>> RunRecoverVaultAsync(FixtureSelector selector,
                VaultAdministration client, VaultScope scope, VaultConfiguration configuration, ManagementReceipt receipt,
                CancellationToken token)
            {
                Receipt = receipt;
                return source.RunRecoverVaultAsync(selector, client, scope, configuration, receipt, token);
            }
            public ValueTask<SecretStatus> CompleteRecoverVaultAsync(FixtureSelector selector,
                ManagementOperation handle, CancellationToken token)
            {
                Completions++;
                return source.CompleteRecoverVaultAsync(selector, handle, token);
            }
        }
        private sealed class RecoverBackend(HttpPipelineTransport inner, OriginalVaultRecoverFixture fixture) : HttpPipelineTransport
        {
            public override Request CreateRequest() => inner.CreateRequest();
            public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
            public override async ValueTask ProcessAsync(HttpMessage message)
            {
                await inner.ProcessAsync(message);
                if (message.Request.Method == RequestMethod.Put && fixture.LockOnFinalization)
                    message.Response = new RecoverFinalizeResponse(message.Response, fixture);
            }
        }
        private sealed class RecoverFinalizeResponse(Response original, OriginalVaultRecoverFixture fixture) : Response
        {
            public override int Status => original.Status;
            public override string ReasonPhrase => original.ReasonPhrase;
            public override string ClientRequestId { get => original.ClientRequestId; set => original.ClientRequestId = value; }
            public override Stream? ContentStream { get => original.ContentStream; set => original.ContentStream = value; }
            public override void Dispose()
            {
                original.Dispose();
                if (!fixture.LockOnFinalization) return;
                fixture.LockOnFinalization = false;
                fixture.JournalLock = new FileStream(fixture.Native.JournalPath, FileMode.Open,
                    FileAccess.ReadWrite, FileShare.None);
            }
            protected override bool ContainsHeader(string name) => original.Headers.Contains(name);
            protected override IEnumerable<HttpHeader> EnumerateHeaders() => original.Headers;
            protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) =>
                original.Headers.TryGetValue(name, out value);
            protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) =>
                original.Headers.TryGetValues(name, out values);
        }
        private sealed class RecoverCredential(string role) : TokenCredential
        {
            public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken) =>
                throw new InvalidOperationException("async-only");
            public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (context.Scopes.Length != 1 || context.Scopes[0] != "https://management.azure.com/.default")
                    throw new InvalidOperationException("controlled-arm-audience");
                return ValueTask.FromResult(new AccessToken(role, DateTimeOffset.MaxValue));
            }
        }
        private sealed class RecoverSdk(HttpPipelineTransport inner, OriginalVaultRecoverFixture fixture) : HttpPipelineTransport
        {
            public override Request CreateRequest() => inner.CreateRequest();
            public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
            public override async ValueTask ProcessAsync(HttpMessage message)
            {
                await inner.ProcessAsync(message);
                string stage = message.Request.Method == RequestMethod.Put ? "start" :
                    message.Request.Uri.ToUri().AbsolutePath == StatusPath ? "poll" : "final";
                if (fixture.ReplaceStage != stage) return;
                fixture.Replacements++;
                var headers = message.Response.Headers.ToArray();
                int status = message.Response.Status;
                string body;
                if (stage == "poll") body = """{"status":"Succeeded"}""";
                else
                {
                    var row = fixture.Native.Wire.Vault!.DeepClone();
                    if (stage == "start") row["properties"]!["provisioningState"] = "Updating";
                    body = row.ToJsonString();
                }
                if (fixture.DisposeOriginal) message.Response.Dispose();
                message.Response = new RecoverIndependentResponse(status, body, headers);
            }
        }
        private sealed class RecoverIndependentResponse(int status, string body, HttpHeader[] headers) : Response
        {
            public override int Status => status;
            public override string ReasonPhrase => "Controlled";
            public override string ClientRequestId { get; set; } = "independent";
            public override Stream? ContentStream { get; set; } = new MemoryStream(Encoding.UTF8.GetBytes(body));
            public override void Dispose() => ContentStream?.Dispose();
            protected override bool ContainsHeader(string name) => headers.Any(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            protected override IEnumerable<HttpHeader> EnumerateHeaders() => headers;
            protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value)
            {
                value = headers.FirstOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
                return value is not null;
            }
            protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values)
            {
                bool found = TryGetHeader(name, out var value);
                values = found ? [value!] : null;
                return found;
            }
        }
    }
}
