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
using PurgeService = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationFixtureObserverService;
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
    public async Task OriginalVaultPurgeKeepsActualHandleReceiptAndBothNativeAbsences(string boundary)
    {
        await using var f = new OriginalVaultPurgeFixture(boundary);
        var result = await f.RunOriginal();
        bool uncertain = boundary is "cancellation-boundary" or "lost-response-no-replay";
        bool denied = boundary == "denied-authority";
        await Assert.That(result.Passed).IsEqualTo(!uncertain);
        if (uncertain) await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.StatusReads).IsEqualTo(denied || uncertain ? 0 : 1);
        await Assert.That(f.SelectedGets).IsEqualTo(denied || uncertain ? 0 : 2);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.CleanupPurges).IsEqualTo(denied ? 1 : 0);
        await Assert.That(f.SecretRequests).IsEqualTo(0);
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(3);
        await Assert.That(f.Native.Read().Released).IsEqualTo(!uncertain);
        await Assert.That(f.Prejournaled).IsTrue();
        if (!denied && !uncertain)
            await Assert.That(f.Tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        if (denied) await Assert.That(f.Tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Rejected);
        if (uncertain)
        {
            await Assert.That(f.Native.Wire.Active || f.Native.Wire.Deleted).IsFalse();
            await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        }
    }

    [Test]
    [Arguments("pending")]
    [Arguments("unknown")]
    [Arguments("failed")]
    [Arguments("canceled")]
    [Arguments("status-malformed")]
    [Arguments("status-denied")]
    [Arguments("active-present")]
    [Arguments("deleted-present")]
    [Arguments("active-absence-malformed")]
    [Arguments("deleted-absence-malformed")]
    [Arguments("no-target")]
    [Arguments("foreign-target")]
    [Arguments("selected-malformed")]
    [Arguments("synchronous")]
    [Arguments("exception-denial")]
    [Arguments("poll-denied")]
    [Arguments("poll-malformed")]
    [Arguments("final-denied")]
    [Arguments("final-lost")]
    public async Task OriginalVaultPurgeRejectsMissingNativeLifecycleEvidence(string fault)
    {
        await using var f = new OriginalVaultPurgeFixture { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.CleanupPurges).IsEqualTo(0);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("missing-child")]
    [Arguments("nonempty-child")]
    [Arguments("deleted-owner")]
    [Arguments("deleted-id")]
    [Arguments("deleted-vault-id")]
    [Arguments("deleted-retention")]
    [Arguments("deleted-protected")]
    public async Task OriginalVaultPurgeRequiresRealOwnedDeletedPreparation(string fault)
    {
        await using var f = new OriginalVaultPurgeFixture { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.FaultsInstalled > 0).IsTrue();
        await Assert.That(f.SelectedPurges).IsEqualTo(0);
    }

    [Test]
    public async Task OriginalVaultPurgeRepeatedPostCannotRepeatProviderWork()
    {
        await using var f = new OriginalVaultPurgeFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        var first = await f.Post(lease);
        int reads = f.ParentReads;
        var second = await f.Post(lease);
        await Assert.That(first.VaultStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(first.DeletedVaultStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(second.ObservedAt).IsEqualTo(first.ObservedAt);
        await Assert.That(f.ParentReads).IsEqualTo(reads);
        await Assert.That(f.StatusReads).IsEqualTo(1);
        await Assert.That(f.SelectedGets).IsEqualTo(2);
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await f.Release();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.CleanupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task OriginalVaultPurgeDenialRequiresUnchangedCompleteDeletedRepresentation()
    {
        await using var f = new OriginalVaultPurgeFixture("denied-authority");
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease, denied: true);
        f.Fault = "denied-post-extra";
        await f.Post(lease);
        await Assert.That(f.FaultsInstalled > 0).IsTrue();
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
        await Assert.That(f.CleanupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task OriginalVaultPurgeConstructorTokensAndGenericJournalCallsCannotSettle()
    {
        await using var f = new OriginalVaultPurgeFixture();
        var lease = await f.PrepareAndBaseline();
        await Assert.That(() => f.Native.Journal.BeginPurgeDeletedVaultInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new PurgeService.PurgeDeletedVaultAdmission(f.Source))).Throws<InvalidOperationException>();
        await f.Start(lease);
        var row = f.Native.Read().Resources.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal));
        await Assert.That(row.ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(() => f.Native.Journal.EndPurgeDeletedVaultInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new PurgeService.PurgeDeletedVaultTermination(f.Source, row.ActiveDispatch)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.RegisterPurgeDeletedVaultSettlement(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new PurgeService.PurgeDeletedVaultSettlement(f.Source, row.ActiveDispatch)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettlePurgeDeletedVaultInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new PurgeService.PurgeDeletedVaultSettlement(f.Source, row.ActiveDispatch)))
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
    [Arguments("unresolved")]
    [Arguments("purged")]
    [Arguments("denied")]
    public async Task OriginalVaultPurgeRestartUsesOnlyPersistedDisposition(string state)
    {
        bool denied = state == "denied";
        await using var f = new OriginalVaultPurgeFixture(denied ? "denied-authority" : "selected-contract");
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease, denied);
        if (state != "unresolved") await f.Post(lease);
        await using var restarted = f.CleanupSource();
        using var observer = f.ObserverFor(restarted);
        var released = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default);
        if (state != "unresolved") RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts);
        await Assert.That(f.Native.Read().Released).IsEqualTo(state != "unresolved");
        await Assert.That(f.CleanupPurges).IsEqualTo(denied ? 1 : 0);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
    }

    [Test]
    public async Task OriginalVaultPurgeResurrectionAndFalseAbsenceFlagNeverAuthorizeMutation()
    {
        await using var f = new OriginalVaultPurgeFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        await f.Post(lease);
        await f.Source.DisposeAsync();
        f.Native.Wire.Active = true;
        await f.Parent.ReleaseAsync(Owner, f.Native.Selector, purge: true, requireActiveVaultAbsent: false);
        await Assert.That(f.SetupDeletes).IsEqualTo(1);
        await Assert.That(f.CleanupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task OriginalVaultPurgeLostCleanupCannotTriggerASecondPurge()
    {
        await using var f = new OriginalVaultPurgeFixture("denied-authority");
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease, denied: true);
        await f.Post(lease);
        f.Fault = "cleanup-lost";
        await f.Release();
        await f.Release();
        await Assert.That(f.CleanupPurges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("retry")]
    [Arguments("close-purged")]
    [Arguments("close-denied")]
    public async Task OriginalVaultPurgeTerminationContentionRetriesOnlyLocalPersistence(string mode)
    {
        bool denied = mode == "close-denied";
        await using var f = new OriginalVaultPurgeFixture(denied ? "denied-authority" : "selected-contract");
        var lease = await f.PrepareAndBaseline();
        f.LockOnFinalization = true;
        await f.Start(lease, denied);
        try
        {
            await Assert.That(async () => await f.Post(lease)).Throws<NativeCaseFailureException>();
            await Assert.That(f.JournalLock is not null).IsTrue();
        }
        finally { f.UnlockJournal(); }
        int reads = f.ParentReads;
        if (mode == "retry")
        {
            await f.Post(lease);
            await Assert.That(f.ParentReads).IsEqualTo(reads);
            await Assert.That(f.Native.Read().Idle).IsTrue();
            RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        }
        else
        {
            await f.Release();
            await f.Source.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
            await Assert.That(f.Native.Read().PurgeDeletedVault!.SettledDispatch).IsEqualTo(Guid.Empty);
            await Assert.That(f.ParentReads).IsEqualTo(reads);
        }
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.StatusReads).IsEqualTo(denied ? 0 : 1);
        await Assert.That(f.SelectedGets).IsEqualTo(denied ? 0 : 2);
        await Assert.That(f.CleanupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-arm")]
    [Arguments("selected-poll")]
    [Arguments("selected-final")]
    [Arguments("status-arm")]
    [Arguments("read-arm")]
    [Arguments("deleted-arm")]
    public async Task OriginalVaultPurgeHostParserSubstitutionCannotQualify(string channel)
    {
        bool denied = channel == "deleted-arm";
        await using var f = new OriginalVaultPurgeFixture(denied ? "denied-authority" : "selected-contract");
        var lease = await f.PrepareAndBaseline();
        f.SwapChannel = channel;
        bool accepted = false;
        try { await f.Start(lease, denied); await f.Post(lease); accepted = true; }
        catch (Exception ex) when (ex is NativeCaseFailureException or InvalidOperationException) { }
        await Assert.That(f.SwapsInstalled > 0).IsTrue();
        await Assert.That(accepted && f.ForeignStreams > 0).IsFalse();
        if (accepted) RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        else await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task OriginalVaultPurgeClosedJournalCannotCreateTerminationCertificate()
    {
        await using var f = new OriginalVaultPurgeFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        var row = f.Native.Read().Resources.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal));
        f.Native.Journal.Close(Owner, f.Native.Selector);
        bool created = false;
        var completion = f.Native.Journal.RegisterPurgeDeletedVaultTermination(Owner, f.Native.Selector,
            lease.Facts.LeaseId, row.ActiveDispatch, () =>
            {
                created = true;
                return new PurgeService.PurgeDeletedVaultTermination(f.Source, row.ActiveDispatch);
            });
        await Assert.That(completion).IsNull();
        await Assert.That(created).IsFalse();
        await f.Release();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == row.Id).InvocationTerminated).IsFalse();
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
        await Assert.That(f.CleanupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalVaultPurgeIndependentFinalResponseCannotQualify(bool disposeOriginal)
    {
        await using var f = new OriginalVaultPurgeFixture
        {
            IndependentFinalResponse = true,
            DisposeReplacedResponse = disposeOriginal
        };
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        bool accepted = false;
        try { await f.Post(lease); accepted = f.Native.Read().Idle; }
        catch (Exception ex) when (ex is NativeCaseFailureException or InvalidOperationException) { }
        await Assert.That(accepted).IsFalse();
        await Assert.That(f.SwapsInstalled).IsEqualTo(1);
        await Assert.That(f.SelectedGets).IsEqualTo(2);
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
        await Assert.That(f.CleanupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-original-credential")]
    [Arguments("selected-arm-transport")]
    [Arguments("selected-arm-body")]
    [Arguments("selected-original-sdk")]
    [Arguments("selected-poll-transport")]
    [Arguments("selected-poll-body")]
    [Arguments("selected-poll-sdk")]
    [Arguments("selected-final-transport")]
    [Arguments("selected-final-body")]
    [Arguments("selected-final-sdk")]
    [Arguments("status-arm-credential")]
    [Arguments("status-arm-transport")]
    [Arguments("status-arm-body")]
    [Arguments("read-arm-credential")]
    [Arguments("read-arm-transport")]
    [Arguments("read-arm-body")]
    [Arguments("deleted-arm-credential")]
    [Arguments("deleted-arm-transport")]
    [Arguments("deleted-arm-body")]
    public async Task OriginalVaultPurgeCannotDisposeThroughActualSdkBorrowers(string barrier)
    {
        await using var f = new OriginalVaultPurgeFixture();
        var lease = await f.PrepareAndBaseline();
        bool startBarrier = barrier.StartsWith("selected-original", StringComparison.Ordinal) ||
            barrier.StartsWith("selected-arm", StringComparison.Ordinal);
        Task work;
        if (startBarrier) { f.Barrier = barrier; work = f.Start(lease); }
        else { await f.Start(lease); f.Barrier = barrier; work = f.Post(lease).AsTask(); }
        Task? disposing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await f.Release();
            disposing = f.Source.DisposeAsync().AsTask();
            await Assert.That(work.IsCompleted || disposing.IsCompleted).IsFalse();
            await Assert.That(f.CleanupPurges).IsEqualTo(0);
            await Assert.That(f.SetupDeletes).IsEqualTo(1);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception ex) when (ex is OperationCanceledException or NativeCaseFailureException or InvalidOperationException) { }
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Test]
    public async Task OriginalVaultPurgeTimerFailureDoesNotLeakLocalActivity()
    {
        var clock = new ReadTimer();
        await using var f = new OriginalVaultPurgeFixture(time: clock);
        var lease = await f.PrepareAndBaseline();
        clock.Fail = true;
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        clock.Fail = false;
        await f.Release();
        await f.Source.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.SelectedPurges).IsEqualTo(0);
    }

    private sealed class OriginalVaultPurgeFixture : IAsyncDisposable
    {
        private const string Capability = "original-vault-purge-controlled-capability";
        private static readonly Uri Origin = new("https://original-vault-purge.invalid/");
        private static readonly string StatusPath =
            $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/operations/66666666-6666-6666-6666-666666666666";
        internal readonly Fixture Native = new(allowPurge: true, emptyPolicies: true);
        internal readonly VaultFixtureProvisioner Parent;
        internal readonly PurgeService Source;
        internal readonly OwnedManagementObserver Observer;
        internal readonly PurgeTap Tap;
        private readonly SecretMaterial capability = SecretMaterial.FromText(Capability);
        private readonly List<HttpClient> clients = [];
        private readonly Dictionary<string, Request> requests = [];
        private readonly Dictionary<Request, string> channels = new(ReferenceEqualityComparer.Instance);
        private readonly HttpPipelineTransport setupTransport, parentTransport;
        private ObservationSubscription? subscription;
        internal string? Fault, Barrier, SwapChannel;
        internal int SelectedPurges, SelectedGets, StatusReads, SetupDeletes, CleanupPurges, SecretRequests, ParentReads;
        internal int FaultsInstalled, SwapsInstalled, ForeignStreams;
        internal bool Prejournaled = true, LockOnFinalization, IndependentFinalResponse, DisposeReplacedResponse;
        internal FileStream? JournalLock;
        internal readonly TaskCompletionSource Entered = Signal(), Resume = Signal();
        private static VaultFixtureProvisioner.HostScope Host => new(Subscription, "fixture-group", "eastus", Tenant, true, true);
        private string DeletedId =>
            $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/{Native.Wire.VaultName}";

        internal OriginalVaultPurgeFixture(string boundary = "selected-contract", TimeProvider? time = null)
        {
            Native.Selector = Native.Selector with
            {
                Operation = "a.management.VaultAdministration.PurgeDeletedVaultAsync",
                Variant = "input.scope",
                Case = boundary
            };
            setupTransport = Transport("setup-arm");
            parentTransport = Transport("read-arm");
            Parent = VaultFixtureProvisioner.ForPurgeDeletedVault(Native.Journal, Host, Native.Baseline,
                new("purge-admin", new PurgeCredential(this, "setup-arm"), setupTransport),
                new("purge-parent", new PurgeCredential(this, "read-arm"), parentTransport),
                new(65536, TimeSpan.FromSeconds(20)), time);
            Source = new(Origin, Owner, "original-purge-source", capability, Host,
                new PurgeService.PurgeDeletedVaultSource(Parent,
                    new("purge-status", new PurgeCredential(this, "status-arm"), Transport("status-arm")),
                    Transport("selected-arm"), new(65536, 8192, 512, TimeSpan.FromSeconds(20))),
                new(65536, 65536, TimeSpan.FromSeconds(20)), time);
            Observer = ObserverFor(Source);
            Tap = new(Source);
        }
        private HttpPipelineTransport Transport(string role)
        {
            var client = new HttpClient(new VaultForwarder((request, token) => Send(request, role, token)));
            clients.Add(client);
            return new PurgeSdk(new HttpClientTransport(client), this, role);
        }
        internal OwnedManagementObserver ObserverFor(PurgeService source) =>
            new(new(Origin, Capability, TimeSpan.FromSeconds(20)), new VaultForwarder(source.DispatchAsync));
        internal PurgeService CleanupSource() => PurgeService.ForPurgeDeletedVaultCleanup(Origin, Owner, "purge-cleanup",
            capability, Host, VaultFixtureProvisioner.ForCleanup(Native.Journal, Host,
                new("purge-admin", new PurgeCredential(this, "setup-arm"), setupTransport),
                new("purge-parent", new PurgeCredential(this, "read-arm"), parentTransport),
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
            var client = new VaultAdministration(new PurgeCredential(this, denied ? "denied-arm" : "selected-original"),
                new PurgeSdk(Source.SelectedTransport, this, "selected-original"));
            var scope = new DeletedVaultScope(new(Subscription), "eastus", lease.VaultName);
            return Tap.RunPurgeDeletedVaultAsync(Native.Selector, client, scope,
                client.PrepareReceipt(scope, ManagementMutation.PurgeDeletedVault), default).AsTask();
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
                })), selectedTransport: Source.SelectedTransport, purgeSelectedInvocation: Tap);
            return (await NativeCaseRunner.RunAsync(registry, [definition], default)).Single();
        }
        private string Channel(string role, Request? request)
        {
            if (role == "read-arm" && request?.Uri.ToUri().AbsolutePath.Contains("/deletedVaults/", StringComparison.Ordinal) == true)
                return "deleted-arm";
            if (role is "selected-arm" or "selected-original" && request is not null &&
                request.Method == RequestMethod.Get && request.Uri.ToUri().AbsolutePath == StatusPath)
            {
                if (!channels.TryGetValue(request, out string? channel))
                    channels.Add(request, channel = SelectedGets == 0 ? "selected-poll" : "selected-final");
                return channel;
            }
            return role;
        }
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
                throw new InvalidOperationException("unexpected-purge-authority-or-route");
            string channel = role == "read-arm" && path.Contains("/deletedVaults/", StringComparison.Ordinal)
                ? "deleted-arm" : role;
            if (role == "read-arm") ParentReads++;
            if (role == "selected-arm" && request.Method == HttpMethod.Get)
            {
                SelectedGets++;
                channel = SelectedGets == 1 ? "selected-poll" : "selected-final";
                if (path != StatusPath || SelectedGets > 2) throw new InvalidOperationException("unexpected-purge-check");
                await Block(channel, "transport");
                if (SelectedGets == 2 && Fault == "final-lost") throw new IOException("controlled-final-get-loss");
                return await Body(StatusReply(SelectedGets == 1 ? "poll" : "final"), channel);
            }
            await Block(channel, "transport");
            if (role == "selected-arm")
            {
                if (request.Method != HttpMethod.Post || path != DeletedId + "/purge")
                    throw new InvalidOperationException("unexpected-original-purge");
                SelectedPurges++;
                Prejournaled &= Native.Read().Resources.Single(r => r.Id == DeletedId).ActiveDispatch != Guid.Empty;
                if (Fault == "exception-denial") throw new RequestFailedException(403, "controlled-no-response");
                if (bearer == "denied-arm") return await Body(Reply(403, """{"error":{"code":"Forbidden"}}"""), channel);
                Native.Wire.Deleted = Fault == "deleted-present";
                Native.Wire.Active = Fault == "active-present";
                var response = Reply(Fault == "synchronous" ? 200 : 202,
                    Fault == "selected-malformed" ? "{" : Fault == "synchronous" ?
                        """{"status":"Succeeded"}""" : """{"status":"InProgress"}""");
                if (Fault is not ("no-target" or "synchronous"))
                {
                    string target = (Fault == "foreign-target" ? "https://foreign.invalid" : "https://management.azure.com") +
                        StatusPath + "?api-version=2026-02-01";
                    response.Headers.Add("Azure-AsyncOperation", target);
                    response.Headers.Add("Location", target);
                }
                return await Body(response, channel);
            }
            if (role == "status-arm")
            {
                if (request.Method != HttpMethod.Get || path != StatusPath) throw new InvalidOperationException("unexpected-purge-status");
                StatusReads++;
                return await Body(StatusReply("status"), channel);
            }
            if (role == "setup-arm" && request.Method == HttpMethod.Delete) SetupDeletes++;
            if (role == "setup-arm" && request.Method == HttpMethod.Post) CleanupPurges++;
            if (request.Method == HttpMethod.Get && path == Native.Wire.VaultId && Native.Wire.Active)
            {
                var row = Native.Wire.Vault!.DeepClone();
                if (Fault is "missing-child" or "nonempty-child") FaultsInstalled++;
                if (Fault == "missing-child") row["properties"]!.AsObject().Remove("privateEndpointConnections");
                else row["properties"]!["privateEndpointConnections"] = Fault == "nonempty-child"
                    ? new JsonArray(new JsonObject { ["id"] = path + "/privateEndpointConnections/foreign" }) : new JsonArray();
                return await Body(Reply(200, row.ToJsonString()), channel);
            }
            if (request.Method == HttpMethod.Get && path == DeletedId && Native.Wire.Deleted)
            {
                if (Fault is "deleted-owner" or "deleted-id" or "deleted-vault-id" or "deleted-retention" or "deleted-protected")
                    FaultsInstalled++;
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
                if (Fault == "denied-post-extra")
                {
                    FaultsInstalled++;
                    row["properties"]!["unselectedField"] = "changed";
                }
                return await Body(Reply(200, row.ToJsonString()), channel);
            }
            if (SelectedPurges > 0 && request.Method == HttpMethod.Get &&
                (path == Native.Wire.VaultId && Fault == "active-absence-malformed" ||
                    path == DeletedId && Fault == "deleted-absence-malformed"))
                return await Body(Reply(404, "{"), channel);
            var native = await Native.Wire.Respond(request, role, token);
            if (Native.Wire.Vault is not null)
                Native.Wire.Vault["properties"]!["privateEndpointConnections"] = new JsonArray();
            if (role == "setup-arm" && request.Method == HttpMethod.Post && Fault == "cleanup-lost")
            {
                native.Dispose();
                throw new IOException("controlled-cleanup-purge-loss");
            }
            return await Body(native, channel);
        }
        private HttpResponseMessage StatusReply(string stage)
        {
            string state = stage == "status" ? Fault switch
            {
                "pending" => "InProgress",
                "unknown" => "future-state",
                "failed" => "Failed",
                "canceled" => "Canceled",
                _ => "Succeeded"
            } : "Succeeded";
            bool denied = Fault == stage + "-denied";
            return Reply(denied ? 403 : 200, Fault == stage + "-malformed" ? "{" :
                denied ? """{"error":{"code":"Forbidden"}}""" : JsonSerializer.Serialize(new
                { id = StatusPath, name = StatusPath[(StatusPath.LastIndexOf('/') + 1)..], status = state }));
        }
        private static HttpResponseMessage Reply(int status, string body) => new((HttpStatusCode)status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
            Headers = { { "x-ms-request-id", "controlled-original-purge-" + Guid.NewGuid().ToString("N") } }
        };
        private async ValueTask<HttpResponseMessage> Body(HttpResponseMessage response, string channel)
        {
            if (Barrier == channel + "-body")
            {
                var content = response.Content;
                response.Content = new StreamContent(new PurgeBody(await content.ReadAsByteArrayAsync(), this, channel));
                content.Dispose();
                response.Content.Headers.ContentType = new("application/json");
            }
            return response;
        }
        internal void UnlockJournal() { JournalLock?.Dispose(); JournalLock = null; }
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
        internal sealed class PurgeTap(PurgeService source) : V.PurgeSelectedInvocation
        {
            internal ManagementReceipt? Receipt;
            public ValueTask<SecretOutcome<ManagementOperation>> RunPurgeDeletedVaultAsync(FixtureSelector selector,
                VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, CancellationToken token)
            {
                Receipt = receipt;
                return source.RunPurgeDeletedVaultAsync(selector, client, scope, receipt, token);
            }
        }
        private sealed class PurgeCredential(OriginalVaultPurgeFixture fixture, string role) : TokenCredential
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
        private sealed class PurgeSdk(HttpPipelineTransport inner, OriginalVaultPurgeFixture fixture, string role) : HttpPipelineTransport
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
                string channel = fixture.Channel(role, message.Request);
                await inner.ProcessAsync(message);
                if (role == "selected-original" && channel == "selected-final" && fixture.IndependentFinalResponse)
                {
                    fixture.SwapsInstalled++;
                    if (fixture.DisposeReplacedResponse) message.Response.Dispose();
                    message.Response = new PurgeIndependentResponse();
                }
                if (fixture.SwapChannel == channel)
                {
                    fixture.SwapsInstalled++;
                    message.Response = new PurgeChangingResponse(message.Response, fixture);
                }
                if (role == "selected-arm" && message.Request.Method == RequestMethod.Post && fixture.LockOnFinalization)
                    message.Response = new PurgeFinalizeResponse(message.Response, fixture);
                if (message.Request.Headers.Contains("Authorization")) await fixture.Block(channel, "sdk");
            }
        }
        private sealed class PurgeBody(byte[] bytes, OriginalVaultPurgeFixture fixture, string channel) : MemoryStream(bytes)
        {
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                await fixture.Block(channel, "body");
                return await base.ReadAsync(buffer, cancellationToken);
            }
        }
        private abstract class PurgeResponse(Response original) : Response
        {
            protected Response Original => original;
            public override int Status => original.Status;
            public override string ReasonPhrase => original.ReasonPhrase;
            public override string ClientRequestId { get => original.ClientRequestId; set => original.ClientRequestId = value; }
            public override Stream? ContentStream { get => original.ContentStream; set => original.ContentStream = value; }
            public override void Dispose() => original.Dispose();
            protected override bool ContainsHeader(string name) => original.Headers.Contains(name);
            protected override IEnumerable<HttpHeader> EnumerateHeaders() => original.Headers;
            protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) =>
                original.Headers.TryGetValue(name, out value);
            protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) =>
                original.Headers.TryGetValues(name, out values);
        }
        private sealed class PurgeFinalizeResponse(Response original, OriginalVaultPurgeFixture fixture) : PurgeResponse(original)
        {
            public override void Dispose()
            {
                base.Dispose();
                if (!fixture.LockOnFinalization) return;
                fixture.LockOnFinalization = false;
                fixture.JournalLock = new FileStream(fixture.Native.JournalPath, FileMode.Open,
                    FileAccess.ReadWrite, FileShare.None);
            }
        }
        private sealed class PurgeIndependentResponse : Response
        {
            public override int Status => 200;
            public override string ReasonPhrase => "OK";
            public override string ClientRequestId { get; set; } = "independent";
            public override Stream? ContentStream { get; set; } =
                new MemoryStream(Encoding.UTF8.GetBytes("""{"status":"Succeeded"}"""));
            public override void Dispose() => ContentStream?.Dispose();
            protected override bool ContainsHeader(string name) => false;
            protected override IEnumerable<HttpHeader> EnumerateHeaders() => [];
            protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value)
            { value = null; return false; }
            protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values)
            { values = null; return false; }
        }
        private sealed class PurgeChangingResponse(Response original, OriginalVaultPurgeFixture fixture) : PurgeResponse(original)
        {
            private bool assigned;
            private readonly List<Stream> foreign = [];
            public override Stream? ContentStream
            {
                get
                {
                    if (!assigned) return Original.ContentStream;
                    fixture.ForeignStreams++;
                    var stream = new MemoryStream(Encoding.UTF8.GetBytes("""{"id":"foreign","status":"Failed","properties":{}}"""));
                    foreign.Add(stream);
                    return stream;
                }
                set { assigned = true; Original.ContentStream = value; }
            }
            public override void Dispose()
            {
                try { base.Dispose(); }
                finally { foreach (var stream in foreign) stream.Dispose(); }
            }
        }
    }
}
