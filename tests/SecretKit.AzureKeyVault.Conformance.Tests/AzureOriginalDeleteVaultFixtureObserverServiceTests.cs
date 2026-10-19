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
using DeleteService = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationFixtureObserverService;
using V = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalVaultDeleteKeepsItsOwnSelectorAndActualBoundaryEvidence(string boundary)
    {
        await using var f = new OriginalVaultDeleteFixture(boundary);
        var result = await f.RunOriginal();
        bool uncertain = boundary is "cancellation-boundary" or "lost-response-no-replay";
        bool denied = boundary == "denied-authority";
        await Assert.That(result.Passed).IsEqualTo(!uncertain);
        if (uncertain) await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.StatusReads).IsEqualTo(uncertain || denied ? 0 : 1);
        await Assert.That(f.SelectedGets).IsEqualTo(0);
        await Assert.That(f.Deletes).IsEqualTo(denied ? 1 : 0);
        await Assert.That(f.Purges).IsEqualTo(uncertain ? 0 : 1);
        await Assert.That(f.SecretRequests).IsEqualTo(0);
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(3);
        await Assert.That(f.Native.Read().Released).IsEqualTo(!uncertain);
        await Assert.That(f.Prejournaled).IsTrue();
        await Assert.That(f.Native.Selector.Operation).IsEqualTo(
            "a.management.VaultAdministration.DeleteVaultAsync");
        if (uncertain)
        {
            await Assert.That(f.Native.Wire.Active).IsFalse();
            await Assert.That(f.Native.Wire.Deleted).IsTrue();
            await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        }
        if (denied) await Assert.That(f.Tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Rejected);
    }

    [Test]
    [Arguments("pending")]
    [Arguments("unknown")]
    [Arguments("failed")]
    [Arguments("canceled")]
    [Arguments("status-malformed")]
    [Arguments("status-denied")]
    [Arguments("active-present")]
    [Arguments("deleted-absent")]
    [Arguments("deleted-id")]
    [Arguments("deleted-vault-id")]
    [Arguments("deleted-owner")]
    [Arguments("deleted-retention")]
    [Arguments("deleted-protected")]
    [Arguments("no-target")]
    [Arguments("foreign-target")]
    [Arguments("selected-malformed")]
    [Arguments("delete-202")]
    [Arguments("synchronous")]
    [Arguments("exception-denial")]
    public async Task OriginalVaultDeleteRequiresEveryIndependentNativeConjunct(string fault)
    {
        await using var f = new OriginalVaultDeleteFixture { Fault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Deletes + f.Purges).IsEqualTo(0);
    }

    [Test]
    [Arguments("missing-child")]
    [Arguments("nonempty-child")]
    public async Task OriginalVaultDeleteNeedsActualNativeEmptyRelationshipBaseline(string fault)
    {
        await using var f = new OriginalVaultDeleteFixture { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(0);
        await Assert.That(f.RelationshipFaults > 0).IsTrue();
    }

    [Test]
    public async Task OriginalVaultDeletePostIsNotASecondStatusOrMutationAttempt()
    {
        await using var f = new OriginalVaultDeleteFixture();
        var lease = await f.PrepareAndBaseline();
        var result = await f.Start(lease);
        await Assert.That(result.IsSuccess).IsTrue();
        var first = await f.Post(lease);
        var second = await f.Post(lease);
        await Assert.That(first.VaultStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(first.DeletedVaultStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(second.ObservedAt).IsEqualTo(first.ObservedAt);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.StatusReads).IsEqualTo(1);
        await Assert.That(f.SelectedGets).IsEqualTo(0);
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task OriginalVaultDeleteRejectsConstructedAdmissionAndGenericSettlement()
    {
        await using var f = new OriginalVaultDeleteFixture();
        var lease = await f.PrepareAndBaseline();
        await Assert.That(() => f.Native.Journal.BeginDeleteVaultInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new DeleteService.DeleteVaultAdmission(f.Source))).Throws<InvalidOperationException>();
        await f.Start(lease);
        var row = f.Native.Read().Resources.Single(r => r.Id == f.Native.Wire.VaultId);
        await Assert.That(row.ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(() => f.Native.Journal.EndDeleteVaultInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new DeleteService.DeleteVaultTermination(f.Source, row.ActiveDispatch)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.RegisterDeleteVaultSettlement(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new DeleteService.DeleteVaultSettlement(f.Source, row.ActiveDispatch)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDeleteVaultInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new DeleteService.DeleteVaultSettlement(f.Source, row.ActiveDispatch)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch, nativeSettled: false))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await f.Post(lease);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task OriginalVaultDeleteRestartCannotSettleFromAbsence()
    {
        await using var f = new OriginalVaultDeleteFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        await using var restarted = f.CleanupSource();
        using var observer = f.ObserverFor(restarted);
        await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>("vault/release", f.Native.Selector, default);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Deletes + f.Purges).IsEqualTo(0);
        await Assert.That(f.StatusReads).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalVaultDeletePersistedDispositionControlsRestartCleanup(bool denied)
    {
        await using var f = new OriginalVaultDeleteFixture(denied ? "denied-authority" : "selected-contract");
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease, denied);
        await f.Post(lease);
        await using var restarted = f.CleanupSource();
        using var observer = f.ObserverFor(restarted);
        var released = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default);
        RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts);
        await Assert.That(f.Deletes).IsEqualTo(denied ? 1 : 0);
        await Assert.That(f.Purges).IsEqualTo(1);
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
    }

    [Test]
    public async Task OriginalVaultDeleteResurrectionCannotAuthorizeAnotherDelete()
    {
        await using var f = new OriginalVaultDeleteFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        await f.Post(lease);
        f.Native.Wire.Active = true;
        await f.Release();
        await Assert.That(f.Deletes + f.Purges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task OriginalVaultDeleteFalseAbsenceFlagCannotAuthorizeResurrectionCleanup()
    {
        await using var f = new OriginalVaultDeleteFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        await f.Post(lease);
        await f.Source.DisposeAsync();
        f.Native.Wire.Active = true;
        await f.Parent.ReleaseAsync(Owner, f.Native.Selector, purge: true, requireActiveVaultAbsent: false);
        await Assert.That(f.Deletes + f.Purges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task OriginalVaultDeleteLostCleanupPurgeCannotBeReplayed()
    {
        await using var f = new OriginalVaultDeleteFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        await f.Post(lease);
        f.Fault = "purge-lost";
        await f.Release();
        await f.Release();
        await Assert.That(f.Purges).IsEqualTo(1);
        await Assert.That(f.Deletes).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("selected-arm")]
    [Arguments("status-arm")]
    [Arguments("read-arm")]
    [Arguments("deleted-arm")]
    public async Task OriginalVaultDeleteCannotQualifyHostParserStreamSubstitution(string channel)
    {
        bool activeRead = channel == "read-arm";
        await using var f = new OriginalVaultDeleteFixture(activeRead ? "denied-authority" : "selected-contract");
        var lease = await f.PrepareAndBaseline();
        f.SwapChannel = channel;
        bool accepted = false;
        try
        {
            await f.Start(lease, denied: activeRead);
            await f.Post(lease);
            accepted = true;
        }
        catch (Exception ex) when (ex is NativeCaseFailureException or InvalidOperationException) { }
        await Assert.That(f.SwapsInstalled > 0).IsTrue();
        await Assert.That(accepted && f.ForeignStreams > 0).IsFalse();
        if (accepted) RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        else
        {
            await Assert.That(f.Native.Read().Released).IsFalse();
            await Assert.That(f.Deletes + f.Purges).IsEqualTo(0);
        }
    }

    [Test]
    public async Task OriginalVaultDeleteTimerConstructionFailureLeavesNoActivityOrDispatchLeak()
    {
        var clock = new ReadTimer();
        await using var f = new OriginalVaultDeleteFixture(time: clock);
        var lease = await f.PrepareAndBaseline();
        clock.Fail = true;
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        clock.Fail = false;
        await f.Release();
        await Assert.That(f.SelectedDeletes).IsEqualTo(0);
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Native.Wire.VaultId).SelectedAttempted).IsFalse();
        await f.Source.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Test]
    public async Task OriginalVaultDeleteRetriesTerminationPersistenceWithoutRepeatingProviderWork()
    {
        await using var f = new OriginalVaultDeleteFixture();
        var lease = await f.PrepareAndBaseline();
        f.LockJournalOnFinalization = true;
        await f.Start(lease);
        try
        {
            await Assert.That(async () => await f.Post(lease)).Throws<NativeCaseFailureException>();
            await Assert.That(f.JournalLock is not null).IsTrue();
        }
        finally { f.UnlockJournal(); }
        int reads = f.ParentReads;
        await f.Post(lease);
        await Assert.That(f.Native.Read().Idle).IsTrue();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.StatusReads).IsEqualTo(1);
        await Assert.That(f.ParentReads).IsEqualTo(reads);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalVaultDeleteCloseAfterTerminationContentionCannotRegisterNewSettlement(bool denied)
    {
        await using var f = new OriginalVaultDeleteFixture(denied ? "denied-authority" : "selected-contract");
        var lease = await f.PrepareAndBaseline();
        f.LockJournalOnFinalization = true;
        await f.Start(lease, denied);
        try
        {
            await Assert.That(async () => await f.Post(lease)).Throws<NativeCaseFailureException>();
            await Assert.That(f.JournalLock is not null).IsTrue();
        }
        finally { f.UnlockJournal(); }
        int reads = f.ParentReads;
        await f.Release();
        await f.Source.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        var state = f.Native.Read();
        await Assert.That(state.Closing).IsTrue();
        await Assert.That(state.DeleteVault!.SettledDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(state.Idle || state.Released).IsFalse();
        await Assert.That(f.SelectedDeletes).IsEqualTo(1);
        await Assert.That(f.StatusReads).IsEqualTo(denied ? 0 : 1);
        await Assert.That(f.ParentReads).IsEqualTo(reads);
        await Assert.That(f.Deletes + f.Purges).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-original-credential")]
    [Arguments("selected-arm-transport")]
    [Arguments("selected-arm-body")]
    [Arguments("selected-original-sdk")]
    [Arguments("status-arm-credential")]
    [Arguments("status-arm-transport")]
    [Arguments("status-arm-body")]
    [Arguments("read-arm-credential")]
    [Arguments("read-arm-transport")]
    [Arguments("read-arm-body")]
    [Arguments("deleted-arm-credential")]
    [Arguments("deleted-arm-transport")]
    [Arguments("deleted-arm-body")]
    public async Task OriginalVaultDeleteCannotCleanupThroughActualBorrowers(string barrier)
    {
        await using var f = new OriginalVaultDeleteFixture();
        var lease = await f.PrepareAndBaseline();
        f.Barrier = barrier;
        Task work;
        if (barrier.StartsWith("selected", StringComparison.Ordinal)) work = f.Start(lease);
        else
        {
            await f.Start(lease);
            work = f.Post(lease).AsTask();
        }
        Task? disposing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var release = await f.Release();
            await Assert.That(release.ActiveDispatches > 0 || !f.Native.Read().Released).IsTrue();
            disposing = f.Source.DisposeAsync().AsTask();
            await Assert.That(work.IsCompleted || disposing.IsCompleted).IsFalse();
            await Assert.That(f.Deletes + f.Purges).IsEqualTo(0);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception ex) when (ex is OperationCanceledException or NativeCaseFailureException or InvalidOperationException) { }
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
    }

    private sealed class OriginalVaultDeleteFixture : IAsyncDisposable
    {
        private const string Capability = "original-vault-delete-controlled-capability";
        private static readonly Uri Origin = new("https://original-vault-delete.invalid/");
        private static readonly string StatusPath =
            $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/operations/55555555-5555-5555-5555-555555555555";
        internal readonly Fixture Native = new(allowPurge: true, emptyPolicies: true);
        internal readonly VaultFixtureProvisioner Parent;
        internal readonly DeleteService Source;
        internal readonly OwnedManagementObserver Observer;
        internal readonly DeleteTap Tap;
        private readonly SecretMaterial capability = SecretMaterial.FromText(Capability);
        private readonly List<HttpClient> clients = [];
        private readonly Dictionary<string, Request> requests = [];
        private readonly HttpPipelineTransport setupTransport, parentTransport;
        private ObservationSubscription? subscription;
        internal string? Fault, Barrier, SwapChannel;
        internal int SelectedDeletes, SelectedGets, StatusReads, Deletes, Purges, SecretRequests;
        internal int SwapsInstalled, ForeignStreams;
        internal int RelationshipFaults;
        internal int ParentReads;
        internal bool LockJournalOnFinalization;
        internal FileStream? JournalLock;
        internal bool Prejournaled = true;
        internal readonly TaskCompletionSource Entered = Signal(), Resume = Signal();
        private static VaultFixtureProvisioner.HostScope Host => new(Subscription, "fixture-group", "eastus", Tenant, true, true);

        internal OriginalVaultDeleteFixture(string boundary = "selected-contract", TimeProvider? time = null)
        {
            Native.Selector = Native.Selector with
            {
                Operation = "a.management.VaultAdministration.DeleteVaultAsync",
                Variant = "input.scope",
                Case = boundary
            };
            setupTransport = Transport("setup-arm");
            parentTransport = Transport("read-arm");
            Parent = VaultFixtureProvisioner.ForDeleteVault(Native.Journal, Host, Native.Baseline,
                new("delete-admin", new DeleteCredential(this, "setup-arm"), setupTransport),
                new("delete-parent", new DeleteCredential(this, "read-arm"), parentTransport),
                new(65536, TimeSpan.FromSeconds(20)), time);
            Source = new(Origin, Owner, "original-delete-source", capability, Host,
                new DeleteService.DeleteVaultSource(Parent,
                    new("delete-status", new DeleteCredential(this, "status-arm"), Transport("status-arm")),
                    Transport("selected-arm"), new(65536, 8192, 512, TimeSpan.FromSeconds(20))),
                new(65536, 65536, TimeSpan.FromSeconds(20)), time);
            Observer = ObserverFor(Source);
            Tap = new(Source);
        }
        private HttpPipelineTransport Transport(string role)
        {
            var client = new HttpClient(new VaultForwarder((request, token) => Send(request, role, token)));
            clients.Add(client);
            return new DeleteSdk(new HttpClientTransport(client), this, role);
        }
        internal OwnedManagementObserver ObserverFor(DeleteService source) =>
            new(new(Origin, Capability, TimeSpan.FromSeconds(20)), new VaultForwarder(source.DispatchAsync));
        internal DeleteService CleanupSource() => DeleteService.ForDeleteVaultCleanup(Origin, Owner, "delete-cleanup",
            capability, Host, VaultFixtureProvisioner.ForCleanup(Native.Journal, Host,
                new("delete-admin", new DeleteCredential(this, "setup-arm"), setupTransport),
                new("delete-parent", new DeleteCredential(this, "read-arm"), parentTransport),
                new(65536, TimeSpan.FromSeconds(20))), new(65536, 65536, TimeSpan.FromSeconds(20)));
        internal async Task<V.Lease> PrepareAndBaseline()
        {
            var lease = await Observer.PostAsync<V.Prepare, V.Lease>("vault/prepare",
                new(Native.Selector, Subscription, "fixture-group", Native.Baseline, Native.Baseline.Policies, Guid.Empty), default);
            subscription = await Observer.SubscribeAsync("vault", lease.Facts, default);
            await Observer.PostAsync<ObserveLease, V.Measurement>("vault/observe",
                new(lease.Facts.LeaseId, lease.Facts.Nonce, "baseline-before-dispatch", subscription.SubscriptionId), default);
            return lease;
        }
        internal Task<SecretOutcome<ManagementOperation>> Start(V.Lease lease, bool denied = false)
        {
            var client = new VaultAdministration(new DeleteCredential(this, denied ? "denied-arm" : "selected-original"),
                new DeleteSdk(Source.SelectedTransport, this, "selected-original"));
            var scope = new VaultScope(new(new(Subscription), "fixture-group"), lease.VaultName);
            return Tap.RunDeleteVaultAsync(Native.Selector, client, scope,
                client.PrepareReceipt(scope, ManagementMutation.DeleteVault), default).AsTask();
        }
        internal ValueTask<V.Measurement> Post(V.Lease lease) => Observer.PostAsync<ObserveLease, V.Measurement>(
            "vault/observe", new(lease.Facts.LeaseId, lease.Facts.Nonce, "post-operation", subscription!.SubscriptionId), default);
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
                    ["VaultAdministration"] = new V.Input(new(Origin, Capability, TimeSpan.FromSeconds(20)),
                        new(Arm("setup-arm"), Arm("selected-original"), Arm("denied-arm"), Arm("observer-arm")),
                        Subscription, "fixture-group", Native.Baseline,
                        [new(Tenant, Principal, [SecretPermission.Get], null)], Guid.Empty,
                        2, 32, TimeSpan.FromSeconds(20))
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
                })), selectedTransport: Source.SelectedTransport, deleteSelectedInvocation: Tap);
            return (await NativeCaseRunner.RunAsync(registry, [definition], default)).Single();
        }
        private string Channel(string role, Request? request) =>
            role == "read-arm" && request?.Uri.ToUri().AbsolutePath.Contains("/deletedVaults/", StringComparison.Ordinal) == true
                ? "deleted-arm" : role;
        private async ValueTask Block(string channel, string stage)
        {
            if (Barrier != channel + "-" + stage) return;
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
            string? bearer = request.Headers.Authorization?.Parameter;
            if (request.RequestUri.Host != "management.azure.com" ||
                request.RequestUri.Query != "?api-version=2026-02-01" ||
                (role == "selected-arm" ? bearer is not ("selected-original" or "denied-arm") : bearer != role))
                throw new InvalidOperationException("unexpected-delete-authority-or-route");
            string channel = role == "read-arm" && path.Contains("/deletedVaults/", StringComparison.Ordinal)
                ? "deleted-arm" : role;
            if (role == "read-arm") ParentReads++;
            await Block(channel, "transport");
            if (role == "selected-arm")
            {
                if (request.Method == HttpMethod.Get) SelectedGets++;
                if (request.Method != HttpMethod.Delete || path != Native.Wire.VaultId)
                    throw new InvalidOperationException("unexpected-original-delete");
                SelectedDeletes++;
                Prejournaled &= Native.Read().Resources.Single(r => r.Id == path).ActiveDispatch != Guid.Empty;
                if (Fault == "exception-denial") throw new RequestFailedException(403, "controlled-no-response");
                if (request.Headers.Authorization?.Parameter == "denied-arm")
                    return await Body(Reply(403, """{"error":{"code":"Forbidden"}}"""), channel);
                Native.Wire.Active = Fault == "active-present";
                Native.Wire.Deleted = Fault != "deleted-absent";
                var reply = Reply(Fault == "delete-202" ? 202 : Fault == "synchronous" ? 204 : 200,
                    Fault == "selected-malformed" ? "{" : Fault == "synchronous" ? "" : """{"status":"InProgress"}""");
                if (Fault is not ("no-target" or "synchronous"))
                {
                    string target = (Fault == "foreign-target" ? "https://foreign.invalid" : "https://management.azure.com") +
                        StatusPath + "?api-version=2026-02-01";
                    reply.Headers.Add("Azure-AsyncOperation", target);
                    reply.Headers.Add("Location", target);
                }
                return await Body(reply, channel);
            }
            if (role == "status-arm")
            {
                if (request.Method != HttpMethod.Get || path != StatusPath) throw new InvalidOperationException("unexpected-delete-status");
                StatusReads++;
                string state = Fault switch
                {
                    "pending" => "InProgress",
                    "unknown" => "future-state",
                    "failed" => "Failed",
                    "canceled" => "Canceled",
                    _ => "Succeeded"
                };
                return await Body(Reply(Fault == "status-denied" ? 403 : 200,
                    Fault == "status-malformed" ? "{" : Fault == "status-denied" ? """{"error":{"code":"Forbidden"}}""" :
                    JsonSerializer.Serialize(new { id = StatusPath, name = StatusPath[(StatusPath.LastIndexOf('/') + 1)..], status = state })), channel);
            }
            if (role == "setup-arm" && request.Method == HttpMethod.Delete) Deletes++;
            if (role == "setup-arm" && request.Method == HttpMethod.Post) Purges++;
            if (request.Method == HttpMethod.Get && path.Contains("/deletedVaults/", StringComparison.Ordinal) && Native.Wire.Deleted)
            {
                var row = new JsonObject
                {
                    ["id"] = Fault == "deleted-id" ? path + "-foreign" : path,
                    ["name"] = Native.Wire.VaultName,
                    ["type"] = "Microsoft.KeyVault/locations/deletedVaults",
                    ["properties"] = new JsonObject
                    {
                        ["vaultId"] = Fault == "deleted-vault-id" ? Native.Wire.VaultId + "-foreign" : Native.Wire.VaultId,
                        ["location"] = "eastus",
                        ["tags"] = Fault == "deleted-owner" ? new JsonObject { ["secretkit-fixture"] = "foreign" } :
                            Native.Wire.Vault!["tags"]!.DeepClone(),
                        ["purgeProtectionEnabled"] = Fault == "deleted-protected",
                        ["deletionDate"] = "2026-10-16T00:00:00Z",
                        ["scheduledPurgeDate"] = Fault == "deleted-retention" ? "2026-11-09T00:00:00Z" : "2026-11-08T00:00:00Z"
                    }
                };
                return await Body(Reply(200, row.ToJsonString()), channel);
            }
            if (request.Method == HttpMethod.Get && path == Native.Wire.VaultId && Native.Wire.Active)
            {
                var row = Native.Wire.Vault!.DeepClone();
                if (Fault is "missing-child" or "nonempty-child") RelationshipFaults++;
                if (Fault == "missing-child") row["properties"]!.AsObject().Remove("privateEndpointConnections");
                else row["properties"]!["privateEndpointConnections"] = Fault == "nonempty-child"
                    ? new JsonArray(new JsonObject { ["id"] = path + "/privateEndpointConnections/foreign" }) : new JsonArray();
                return await Body(Reply(200, row.ToJsonString()), channel);
            }
            var response = await Native.Wire.Respond(request, role, token);
            if (Native.Wire.Vault is not null)
                Native.Wire.Vault["properties"]!["privateEndpointConnections"] = new JsonArray();
            if (role == "setup-arm" && request.Method == HttpMethod.Post && Fault == "purge-lost")
            {
                response.Dispose();
                throw new IOException("controlled-cleanup-purge-loss");
            }
            return await Body(response, channel);
        }
        private static HttpResponseMessage Reply(int status, string body) => new((HttpStatusCode)status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
            Headers = { { "x-ms-request-id", "controlled-original-delete-" + Guid.NewGuid().ToString("N") } }
        };
        private async ValueTask<HttpResponseMessage> Body(HttpResponseMessage response, string channel)
        {
            if (Barrier == channel + "-body")
            {
                var content = response.Content;
                response.Content = new StreamContent(new DeleteBody(await content.ReadAsByteArrayAsync(), this, channel));
                content.Dispose();
                response.Content.Headers.ContentType = new("application/json");
            }
            return response;
        }
        public async ValueTask DisposeAsync()
        {
            Resume.TrySetResult();
            UnlockJournal();
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
        internal void UnlockJournal()
        {
            JournalLock?.Dispose();
            JournalLock = null;
        }
        internal sealed class DeleteTap(DeleteService source) : V.DeleteSelectedInvocation
        {
            internal ManagementReceipt? Receipt;
            public ValueTask<SecretOutcome<ManagementOperation>> RunDeleteVaultAsync(FixtureSelector selector,
                VaultAdministration client, VaultScope scope, ManagementReceipt receipt, CancellationToken token)
            {
                Receipt = receipt;
                return source.RunDeleteVaultAsync(selector, client, scope, receipt, token);
            }
        }
        private sealed class DeleteCredential(OriginalVaultDeleteFixture fixture, string role) : TokenCredential
        {
            public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
                throw new InvalidOperationException("async-only");
            public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
            {
                fixture.requests.TryGetValue(role, out var request);
                await fixture.Block(fixture.Channel(role, request), "credential");
                cancellationToken.ThrowIfCancellationRequested();
                return new(role, DateTimeOffset.MaxValue);
            }
        }
        private sealed class DeleteSdk(HttpPipelineTransport inner, OriginalVaultDeleteFixture fixture, string role) : HttpPipelineTransport
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
                await inner.ProcessAsync(message);
                if (fixture.SwapChannel == fixture.Channel(role, message.Request) &&
                    message.Response.Status == 200)
                {
                    fixture.SwapsInstalled++;
                    message.Response = new DeleteChangingResponse(message.Response, fixture);
                }
                if (role == "selected-arm" && fixture.LockJournalOnFinalization)
                    message.Response = new DeleteFinalizationResponse(message.Response, fixture);
                if (message.Request.Headers.Contains("Authorization"))
                    await fixture.Block(fixture.Channel(role, message.Request), "sdk");
            }
        }
        private sealed class DeleteFinalizationResponse(Response original, OriginalVaultDeleteFixture fixture) : Response
        {
            public override int Status => original.Status;
            public override string ReasonPhrase => original.ReasonPhrase;
            public override string ClientRequestId { get => original.ClientRequestId; set => original.ClientRequestId = value; }
            public override Stream? ContentStream { get => original.ContentStream; set => original.ContentStream = value; }
            public override void Dispose()
            {
                original.Dispose();
                if (!fixture.LockJournalOnFinalization) return;
                fixture.LockJournalOnFinalization = false;
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
        private sealed class DeleteChangingResponse(Response original, OriginalVaultDeleteFixture fixture) : Response
        {
            private bool assigned;
            private readonly List<Stream> foreign = [];
            public override int Status => original.Status;
            public override string ReasonPhrase => original.ReasonPhrase;
            public override string ClientRequestId { get => original.ClientRequestId; set => original.ClientRequestId = value; }
            public override Stream? ContentStream
            {
                get
                {
                    if (!assigned) return original.ContentStream;
                    fixture.ForeignStreams++;
                    var stream = new MemoryStream(Encoding.UTF8.GetBytes("""{"id":"foreign","status":"Failed","properties":{}}"""));
                    foreign.Add(stream);
                    return stream;
                }
                set { assigned = true; original.ContentStream = value; }
            }
            public override void Dispose()
            {
                try { original.Dispose(); }
                finally { foreach (var stream in foreign) stream.Dispose(); }
            }
            protected override bool ContainsHeader(string name) => original.Headers.Contains(name);
            protected override IEnumerable<HttpHeader> EnumerateHeaders() => original.Headers;
            protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) =>
                original.Headers.TryGetValue(name, out value);
            protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) =>
                original.Headers.TryGetValues(name, out values);
        }
        private sealed class DeleteBody(byte[] bytes, OriginalVaultDeleteFixture fixture, string channel) : MemoryStream(bytes)
        {
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                await fixture.Block(channel, "body");
                return await base.ReadAsync(buffer, cancellationToken);
            }
        }
    }
}
