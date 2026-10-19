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
using Op = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;
using OpService = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    public async Task OriginalPurgeStatusHandlerJoinsIndependentStateAndExactOwnedAbsence(string boundary)
    {
        await using var f = new PurgeServiceFixture(boundary);
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(2);
        await Assert.That(f.ResourceReads).IsEqualTo(2);
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(3);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Prejournaled).IsTrue();
    }

    [Test]
    [Arguments("pending")]
    [Arguments("unknown")]
    [Arguments("failed")]
    [Arguments("canceled")]
    [Arguments("status-malformed")]
    [Arguments("status-denied")]
    public async Task IndependentPurgeStatusCannotBeReplacedBySelectedOrAbsentState(string fault)
    {
        await using var f = new PurgeServiceFixture { Fault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(0);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("no-target")]
    [Arguments("synchronous")]
    [Arguments("selected-malformed")]
    public async Task UnqualifiedOriginalPurgeNeverTriggersAnotherPurgeDuringRelease(string fault)
    {
        await using var f = new PurgeServiceFixture { Fault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    public async Task LostPurgePreparationReplyStillReleasesOnlyOriginalSelector(string fault)
    {
        await using var f = new PurgeServiceFixture { PrepareReplyFault = fault };
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedPurges).IsEqualTo(0);
        await Assert.That(f.SetupPurges).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("operation.CreateOrUpdateVault", "selected-contract")]
    [Arguments("status.Succeeded", "selected-contract")]
    [Arguments("operation.PurgeDeletedVault", "denied-authority")]
    public async Task UnsupportedPurgeServiceSelectionsDoNotProvision(string variant, string boundary)
    {
        await using var f = new PurgeServiceFixture();
        var input = f.PrepareRequest();
        input = input with { Selection = input.Selection with { Variant = variant, Case = boundary } };
        await Assert.That(async () => await f.Observer.PostAsync<Op.Prepare, Op.Lease>("operation/prepare", input, default))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Wire.Vault).IsNull();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    public async Task PurgeServiceBaselineAndPostWindowsKeepSameOriginalNonce()
    {
        await using var f = new PurgeServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var result = await f.Start(lease);
        await Assert.That(result.IsSuccess).IsTrue();
        var independent = await f.Observe(lease);
        await Assert.That(independent.ResourceStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(independent.OperationState).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(independent.ResourceId).IsEqualTo(f.Plan().DeletedId);
        await Assert.That(independent.Nonce).IsEqualTo(lease.Facts.Nonce);
        var originalStatus = await f.Source.RunCheckStatusAsync(f.Native.Selector, result.Value!, default);
        await Assert.That(originalStatus).IsEqualTo(SecretStatus.Success);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(async () => await f.Observe(lease)).Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task CachedOriginalPurgeSuccessAndAbsenceCannotSupplyNativeStatusAuthority()
    {
        await using var f = new PurgeServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var result = await f.Start(lease);
        await Assert.That(result.IsSuccess).IsTrue();
        // Complete the actual SDK handle through real native reads outside the
        // observer hook, then deny its independent reader. Cached success alone
        // cannot fill that missing independent authority.
        f.StatusCaptureBypass = true;
        try { await Assert.That(await result.Value!.CheckStatusAsync()).IsEqualTo(SecretStatus.Success); }
        finally { f.StatusCaptureBypass = false; }
        await Assert.That(result.Value!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.OriginalStatusReads).IsEqualTo(2);
        f.Fault = "status-denied";
        await Assert.That(async () => await f.Observe(lease)).Throws<NativeCaseFailureException>();
        await Assert.That(f.IndependentStatusReads).IsEqualTo(1);
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("lease")]
    [Arguments("subscription")]
    public async Task PurgeObservationRejectsForeignBindingsBeforeReading(string field)
    {
        await using var f = new PurgeServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var input = new ObserveLease(lease.Facts.LeaseId, lease.Facts.Nonce, "selected-state", f.Armed!.SubscriptionId);
        input = field switch
        {
            "nonce" => input with { Nonce = Guid.NewGuid() },
            "lease" => input with { LeaseId = Guid.NewGuid() },
            _ => input with { SubscriptionId = Guid.NewGuid() }
        };
        await Assert.That(async () => await f.Observer.PostAsync<ObserveLease, Op.Measurement>("operation/observe", input, default))
            .Throws<NativeCaseFailureException>();
        await Assert.That(f.IndependentStatusReads).IsEqualTo(0);
        await Assert.That(f.ResourceReads).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selected-credential")]
    [Arguments("selected-send")]
    [Arguments("selected-body")]
    [Arguments("selected-sdk")]
    [Arguments("status-credential")]
    [Arguments("status-send")]
    [Arguments("resource-body")]
    public async Task PurgeServiceDisposalJoinsActualBorrowers(string barrier)
    {
        await using var f = new PurgeServiceFixture();
        var lease = await f.PrepareAndBaseline();
        f.Barrier = barrier;
        Task work;
        if (barrier.StartsWith("selected", StringComparison.Ordinal)) work = f.Start(lease);
        else
        {
            await f.Start(lease);
            work = f.Observe(lease).AsTask();
        }
        Task? disposing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var release = await f.Release();
            await Assert.That(release.ActiveDispatches > 0).IsTrue();
            await Assert.That(f.SetupPurges).IsEqualTo(0);
            disposing = f.Source.DisposeAsync().AsTask();
            await Assert.That(work.IsCompleted || disposing.IsCompleted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or NativeCaseFailureException or InvalidOperationException) { }
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.SelectedPurges).IsEqualTo(barrier == "selected-credential" ? 0 : 1);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task RestartCannotSettleSelectedPurgeFromResourceAbsence()
    {
        await using var f = new PurgeServiceFixture { Fault = "lost" };
        var lease = await f.PrepareAndBaseline();
        try { await f.Start(lease); } catch (InvalidOperationException) { }
        Guid dispatch = f.Native.Read().Resources.Single(r => r.Id == f.Plan().DeletedId).ActiveDispatch;
        await f.Source.DisposeAsync();
        await using var restarted = f.NewSource();
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(release.ActiveDispatches > 0).IsTrue();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Plan().DeletedId).ActiveDispatch).IsEqualTo(dispatch);
        await Assert.That(f.SelectedPurges).IsEqualTo(1);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task SelectedPurgeCleanupCannotDeleteUnexpectedActiveVault()
    {
        await using var f = new PurgeServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        f.Native.Wire.Active = true;
        int deleted = f.SetupDeletes;
        var release = await f.Release();
        await Assert.That(release.RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.SetupDeletes).IsEqualTo(deleted);
        await Assert.That(f.SetupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Wire.Active).IsTrue();
    }

    [Test]
    [Arguments("capability")]
    [Arguments("duplicate")]
    [Arguments("unknown")]
    [Arguments("oversized-header")]
    public async Task PurgeServiceRejectsInvalidIngressBeforeCreatingRoot(string fault)
    {
        await using var f = new PurgeServiceFixture();
        string json = JsonSerializer.Serialize(f.PrepareRequest(), ManagementAdmission.Json);
        if (fault == "duplicate") json = json[..^1] + ",\"operation\":3}";
        if (fault == "unknown") json = json[..^1] + ",\"callerStatus\":\"Succeeded\"}";
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://purge-observer.example/operation/prepare")
        { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        request.Headers.Authorization = new("Bearer", fault == "capability" ? "foreign" : "private-purge-service-capability");
        if (fault == "oversized-header") request.Content.Headers.Add("X-Large", new string('x', 17000));
        using var response = await f.Source.DispatchAsync(request, default);
        await Assert.That(response.StatusCode).IsEqualTo(fault == "capability" ? HttpStatusCode.Unauthorized : HttpStatusCode.ServiceUnavailable);
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
        await Assert.That(f.Native.Wire.Vault).IsNull();
    }

    [Test]
    public async Task PurgeServiceTimerFailureDoesNotStrandRequestDrain()
    {
        await using var f = new PurgeServiceFixture();
        await using var source = f.NewSource(new WebhookFailingTimer());
        using var observer = f.NewObserver(source);
        await Assert.That(async () => await observer.PostAsync<Op.Prepare, Op.Lease>(
            "operation/prepare", f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await source.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    private sealed class PurgeServiceFixture : IAsyncDisposable
    {
        private const string Capability = "private-purge-service-capability";
        private static readonly Uri Origin = new("https://purge-observer.example/");
        private static readonly string StatusPath = $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/operations/33333333-3333-3333-3333-333333333333";
        internal readonly Fixture Native;
        private readonly SecretMaterial capability = SecretMaterial.FromText(Capability);
        private readonly List<HttpClient> clients = [];
        private readonly HttpPipelineTransport selectedTransport, statusTransport, resourceTransport;
        private readonly VaultFixtureProvisioner provisioner;
        internal readonly ManagementMutation Operation;
        internal readonly VaultAdministrationEffects.Configuration Baseline;
        private readonly bool recoveryCancellation;
        private readonly bool updateCancellation;
        private readonly bool exclusiveNotificationCreation;
        private readonly bool statusSucceededDeleteVault;
        private readonly bool statusSucceededDeleteVaultIndependent;
        private readonly bool statusSucceededDeleteVaultCancellation;
        private readonly bool succeededDeleteVaultWire;
        private readonly bool statusPrivateDeleteIndependent;
        private readonly bool statusNotificationUpdateIndependent;
        private readonly bool statusNotificationCreateIndependent;
        private readonly bool statusPrivateUpdateIndependent;
        private readonly bool statusPendingPurge, statusPendingPurgeIndependent, statusPendingPurgeCancellation;
        private bool PendingWire => statusPendingPurge || statusPendingPurgeIndependent || statusPendingPurgeCancellation;
        private readonly Credential pendingReadCredential = new("read-arm");
        private readonly HttpPipelineTransport pendingReadTransport;
        private readonly Credential statusSucceededResourceCredential = new("resource-arm");
        internal int SucceededBaselineReads, SucceededSelectedReads, SucceededCleanupReads;
        internal Action<JsonObject>? SucceededBaselineTransform, SucceededSelectedTransform;
        internal int SucceededResourceMutations;
        internal readonly Guid NotificationNamespaceEpoch = Guid.NewGuid();
        private readonly PurgeCredential statusCredential;
        private readonly NotificationConfiguration notificationBaseline =
            new("https://unused.example/webhook", [VaultNotificationEvent.SecretNearExpiry]);
        private readonly HttpPipelineTransport notificationSetup, notificationObserver;
        private readonly HttpPipelineTransport endpointSetup, endpointRead, endpointVaultRead;
        internal EndpointBindingWire? PrivateEndpoint;
        private readonly Credential notificationSetupCredential = new("notification-setup-arm");
        private readonly Credential notificationObserverCredential = new("notification-observer-arm");
        internal JsonObject? NotificationRow;
        internal Action<JsonObject>? NotificationBaselineTransform, NotificationPostTransform;
        internal int NotificationBaselineMutations, NotificationPostMutations;
        private bool notificationSubscribed;
        internal int NotificationDeletes;
        internal int NotificationSetupPuts, NotificationPreparationAbsences, NotificationArmedAbsences;
        internal string? NotificationAbsent404Body;
        internal string NotificationCreatedLabels = "absent";
        internal int NotificationParserReplacementStage, NotificationParserReplacements;
        internal string? NotificationParserReplacement;
        internal int NotificationReadFaultsReached;
        internal Action<JsonObject>? PrivateBaselineTransform, PrivatePostTransform;
        internal int PrivateBaselineMutations, PrivatePostMutations;
        internal int PrivateChildResourceReads;
        internal Action<JsonObject>? PrivateEndpointPostTransform;
        internal int PrivateEndpointPostMutations;
        internal string? PrivateDeleteRead404Body;
        internal int PrivateDeleteRead404Reached;
        internal string? PrivateCleanup404Body;
        internal int PrivateCleanup404Reached;
        internal int PrivateStartStatus = 200;
        internal int SelectedNotificationDeleteStatus = 204;
        internal readonly OpService Source;
        internal readonly OwnedManagementObserver Observer;
        internal readonly TaskCompletionSource Entered = Signal(), Resume = Signal();
        internal ObservationSubscription? Armed;
        internal ManagementReceipt? OriginalReceipt;
        internal string? Fault, PrepareReplyFault, Barrier;
        internal bool StatusCaptureBypass;
        internal HttpPipelineTransport SelectedBackend => selectedTransport;
        internal int SelectedPurges, SelectedDeletes, SelectedRecoveries, SelectedUpdates, OriginalStatusReads, OriginalResourceReads,
            IndependentStatusReads, ResourceReads, SetupPurges, SetupDeletes;
        internal int NotificationResourceReads;
        internal int DeletedResourceReads, ActiveCounterpartReads, ResourceFaultsReached, SelectedStatusFaultsReached, CleanupFaultsReached;
        internal JsonObject? RecoveryRequest;
        internal bool Prejournaled = true;
        internal Op.Input input;

        internal PurgeServiceFixture(string boundary = "selected-contract",
            ManagementMutation operation = ManagementMutation.PurgeDeletedVault,
            Func<VaultAdministrationEffects.Configuration, VaultAdministrationEffects.Configuration>? baselineOverride = null,
            bool exclusiveNotificationCreation = false, bool statusSucceededDeleteVault = false,
            bool statusPrivateDeleteIndependent = false, bool statusSucceededDeleteVaultIndependent = false,
            bool statusSucceededDeleteVaultCancellation = false, bool statusNotificationUpdateIndependent = false,
            bool statusNotificationCreateIndependent = false, bool statusPrivateUpdateIndependent = false,
            bool statusPendingPurge = false, bool statusPendingPurgeIndependent = false, bool statusPendingPurgeCancellation = false)
        {
            Operation = operation;
            this.exclusiveNotificationCreation = exclusiveNotificationCreation;
            this.statusSucceededDeleteVault = statusSucceededDeleteVault;
            this.statusSucceededDeleteVaultIndependent = statusSucceededDeleteVaultIndependent;
            this.statusSucceededDeleteVaultCancellation = statusSucceededDeleteVaultCancellation;
            succeededDeleteVaultWire = statusSucceededDeleteVault || statusSucceededDeleteVaultIndependent || statusSucceededDeleteVaultCancellation;
            this.statusPrivateDeleteIndependent = statusPrivateDeleteIndependent;
            this.statusNotificationUpdateIndependent = statusNotificationUpdateIndependent;
            this.statusNotificationCreateIndependent = statusNotificationCreateIndependent;
            this.statusPrivateUpdateIndependent = statusPrivateUpdateIndependent;
            this.statusPendingPurge = statusPendingPurge;
            this.statusPendingPurgeIndependent = statusPendingPurgeIndependent;
            this.statusPendingPurgeCancellation = statusPendingPurgeCancellation;
            if ((statusPendingPurge ? 1 : 0) + (statusPendingPurgeIndependent ? 1 : 0) + (statusPendingPurgeCancellation ? 1 : 0) > 1) throw new InvalidOperationException("test-profile-conflict");
            recoveryCancellation = operation == ManagementMutation.RecoverVault && boundary == "cancellation-boundary";
            updateCancellation = operation == ManagementMutation.CreateOrUpdateVault && boundary == "cancellation-boundary";
            Native = new(rbac: PendingWire || succeededDeleteVaultWire || statusNotificationUpdateIndependent || statusNotificationCreateIndependent || statusPrivateUpdateIndependent ||
                operation == ManagementMutation.CreateOrUpdateVault || recoveryCancellation, allowPurge: true,
                emptyPolicies: PendingWire || succeededDeleteVaultWire || statusNotificationUpdateIndependent || statusNotificationCreateIndependent || statusPrivateUpdateIndependent ||
                operation == ManagementMutation.CreateOrUpdateVault || recoveryCancellation);
            Baseline = PendingWire || recoveryCancellation || succeededDeleteVaultWire ? Native.Baseline with { PublicNetworkAccess = true } : Native.Baseline;
            if (baselineOverride is not null) Baseline = baselineOverride(Baseline);
            Native.Selector = Native.Selector with
            {
                Operation = Op.Members[0].Operation,
                Variant = PendingWire ? "status.Pending" : succeededDeleteVaultWire ? "status.Succeeded" : "operation." + operation,
                Case = boundary
            };
            HttpPipelineTransport Wire(string role)
            {
                var http = new HttpClient(new VaultForwarder((request, token) => Send(request, role, token)));
                clients.Add(http);
                return new HttpClientTransport(http);
            }
            var setup = Wire("setup-arm");
            var secretSetup = Wire("setup-secret");
            var read = Wire("read-arm");
            pendingReadTransport = read;
            var secretRead = Wire("read-secret");
            selectedTransport = Wire("selected-arm");
            statusTransport = Wire("status-arm");
            resourceTransport = Wire("resource-arm");
            statusCredential = new("status-arm", this);
            if (statusPendingPurgeCancellation)
                provisioner = VaultFixtureProvisioner.ForStatusPendingPurgeCancellation(Native.Journal,
                    new(Subscription, "fixture-group", "eastus", Tenant, true, true), Baseline,
                    new("setup-arm", new Credential("setup-arm"), setup),
                    new("setup-secret", new Credential("setup-secret"), secretSetup),
                    new("read-arm", pendingReadCredential, read),
                    new("read-secret", new Credential("read-secret"), secretRead),
                    new(65536, TimeSpan.FromSeconds(20)));
            else if (statusPendingPurgeIndependent)
                provisioner = VaultFixtureProvisioner.ForStatusPendingPurgeIndependent(Native.Journal,
                    new(Subscription, "fixture-group", "eastus", Tenant, true, true), Baseline,
                    new("setup-arm", new Credential("setup-arm"), setup),
                    new("setup-secret", new Credential("setup-secret"), secretSetup),
                    new("read-arm", pendingReadCredential, read),
                    new("read-secret", new Credential("read-secret"), secretRead),
                    new(65536, TimeSpan.FromSeconds(20)));
            else if (statusPendingPurge)
                provisioner = VaultFixtureProvisioner.ForStatusPendingPurge(Native.Journal,
                    new(Subscription, "fixture-group", "eastus", Tenant, true, true), Baseline,
                    new("setup-arm", new Credential("setup-arm"), setup),
                    new("setup-secret", new Credential("setup-secret"), secretSetup),
                    new("read-arm", pendingReadCredential, read),
                    new("read-secret", new Credential("read-secret"), secretRead),
                    new(65536, TimeSpan.FromSeconds(20)));
            else if (statusSucceededDeleteVaultCancellation)
                provisioner = VaultFixtureProvisioner.ForStatusSucceededDeleteVaultCancellation(Native.Journal,
                    new(Subscription, "fixture-group", "eastus", Tenant, true, true), Baseline,
                    new("setup-arm", new Credential("setup-arm"), setup),
                    new("resource-reader", statusSucceededResourceCredential, resourceTransport),
                    new(65536, TimeSpan.FromSeconds(20)));
            else if (statusSucceededDeleteVaultIndependent)
                provisioner = VaultFixtureProvisioner.ForStatusSucceededDeleteVaultIndependent(Native.Journal,
                    new(Subscription, "fixture-group", "eastus", Tenant, true, true), Baseline,
                    new("setup-arm", new Credential("setup-arm"), setup),
                    new("resource-reader", statusSucceededResourceCredential, resourceTransport),
                    new(65536, TimeSpan.FromSeconds(20)));
            else if (statusSucceededDeleteVault)
                provisioner = VaultFixtureProvisioner.ForStatusSucceededDeleteVault(Native.Journal,
                    new(Subscription, "fixture-group", "eastus", Tenant, true, true), Baseline,
                    new("setup-arm", new Credential("setup-arm"), setup),
                    new("resource-reader", statusSucceededResourceCredential, resourceTransport),
                    new(65536, TimeSpan.FromSeconds(20)));
            else
                provisioner = new(Native.Journal, new(Subscription, "fixture-group", "eastus", Tenant, true, true),
                    Baseline, new("setup-arm", new Credential("setup-arm"), setup),
                    new("setup-secret", new Credential("setup-secret"), secretSetup),
                    new("read-arm", new Credential("read-arm"), read),
                    new("read-secret", new Credential("read-secret"), secretRead), new(65536, TimeSpan.FromSeconds(20)));
            notificationSetup = Wire("notification-setup-arm");
            notificationObserver = Wire("notification-observer-arm");
            endpointSetup = Wire("endpoint-setup-arm");
            endpointRead = Wire("endpoint-reader-arm");
            endpointVaultRead = Wire("endpoint-vault-reader-arm");
            Source = NewSource();
            Observer = NewObserver(Source);
            AudienceToken Arm(string value) => new(value, DateTimeOffset.MaxValue, "https://management.azure.com/.default");
            input = new(new(Origin, Capability, TimeSpan.FromSeconds(20)),
                new(Arm("setup-arm"), Arm("selected-arm"), Arm("denied-arm"), Arm("observer-arm")),
                Subscription, "fixture-group", "eastus", Tenant, VaultSku.Premium, 23,
                operation, "https://unused.example/webhook", Guid.Empty);
        }
        internal OpService NewSource(TimeProvider? time = null, VaultFixtureProvisioner.HostScope? declaredScope = null,
            bool cleanupOnly = false, bool omitNotificationSource = false, bool omitPrivateConnectionSource = false,
            VaultFixtureProvisioner? parent = null, bool omitExclusiveCreation = false,
            Guid? notificationEpoch = null, bool continuousWriterExclusion = true)
        {
            OpService.PrivateConnectionSource? endpoint = Operation is ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection &&
                !omitPrivateConnectionSource
                ? new(DeclaredSubnet,
                    new("endpoint-setup", new Credential("endpoint-setup-arm"), endpointSetup),
                    new("endpoint-reader", new Credential("endpoint-reader-arm"), endpointRead),
                    new("endpoint-vault-reader", new Credential("endpoint-vault-reader-arm"), endpointVaultRead),
                    new(65536, 8192, 4096, 32, 16, TimeSpan.FromSeconds(20)),
                    new(1, 4, 65536, 8192, TimeSpan.FromSeconds(20)))
                : null;
            if (statusPendingPurgeCancellation)
                return cleanupOnly
                    ? OpService.ForStatusPendingPurgeCancellationCleanup(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System)
                    : OpService.ForStatusPendingPurgeCancellation(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        new("status-reader", statusCredential, statusTransport),
                        new("read-arm", pendingReadCredential, pendingReadTransport), selectedTransport,
                        new(65536, 8192, 512, TimeSpan.FromSeconds(20)),
                        new(65536, 8192, 4096, 32, 16, TimeSpan.FromSeconds(20)),
                        new(65536, 65536, TimeSpan.FromSeconds(20)),
                        new(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30)), time ?? TimeProvider.System);
            if (statusPendingPurgeIndependent)
                return cleanupOnly
                    ? OpService.ForStatusPendingPurgeIndependentCleanup(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System)
                    : OpService.ForStatusPendingPurgeIndependent(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        new("status-reader", statusCredential, statusTransport),
                        new("read-arm", pendingReadCredential, pendingReadTransport), selectedTransport,
                        new(65536, 8192, 512, TimeSpan.FromSeconds(20)),
                        new(65536, 8192, 4096, 32, 16, TimeSpan.FromSeconds(20)),
                        new(65536, 65536, TimeSpan.FromSeconds(20)),
                        new(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30)), time ?? TimeProvider.System);
            if (statusPendingPurge)
                return cleanupOnly
                    ? OpService.ForStatusPendingPurgeCleanup(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System)
                    : OpService.ForStatusPendingPurge(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        new("status-reader", statusCredential, statusTransport),
                        new("read-arm", pendingReadCredential, pendingReadTransport), selectedTransport,
                        new(65536, 8192, 512, TimeSpan.FromSeconds(20)),
                        new(65536, 8192, 4096, 32, 16, TimeSpan.FromSeconds(20)),
                        new(65536, 65536, TimeSpan.FromSeconds(20)),
                        new(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30)), time ?? TimeProvider.System);
            if (statusPrivateUpdateIndependent)
                return cleanupOnly
                    ? OpService.ForStatusPrivateConnectionUpdateIndependentCleanup(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        endpoint!, new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System)
                    : OpService.ForStatusPrivateConnectionUpdateIndependent(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        new("status-reader", statusCredential, statusTransport),
                        new("resource-reader", new Credential("resource-arm"), resourceTransport), selectedTransport,
                        new(65536, 8192, 512, TimeSpan.FromSeconds(20)),
                        new(65536, 8192, 4096, 32, 16, TimeSpan.FromSeconds(20)),
                        new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System, endpoint!);
            if (statusNotificationCreateIndependent)
            {
                var notification = new OpService.NotificationSource(
                    new(notificationSetupCredential, notificationSetup), new(notificationObserverCredential, notificationObserver),
                    new(65536, 65536, 65536, 16, 32, 8192, TimeSpan.FromSeconds(20)),
                    cleanupOnly ? null : notificationBaseline, !cleanupOnly);
                return cleanupOnly
                    ? OpService.ForStatusNotificationCreateIndependentCleanup(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        notification, new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System)
                    : OpService.ForStatusNotificationCreateIndependent(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        new("status-reader", statusCredential, statusTransport),
                        new("resource-reader", new Credential("resource-arm"), resourceTransport), selectedTransport,
                        new(65536, 8192, 512, TimeSpan.FromSeconds(20)),
                        new(65536, 8192, 4096, 32, 16, TimeSpan.FromSeconds(20)),
                        new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System, notification);
            }
            if (statusNotificationUpdateIndependent)
            {
                var notification = new OpService.NotificationSource(
                    new(notificationSetupCredential, notificationSetup), new(notificationObserverCredential, notificationObserver),
                    new(65536, 65536, 65536, 16, 32, 8192, TimeSpan.FromSeconds(20)),
                    cleanupOnly ? null : notificationBaseline, !cleanupOnly);
                return cleanupOnly
                    ? OpService.ForStatusNotificationUpdateIndependentCleanup(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        notification, new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System)
                    : OpService.ForStatusNotificationUpdateIndependent(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        new("status-reader", statusCredential, statusTransport),
                        new("resource-reader", new Credential("resource-arm"), resourceTransport), selectedTransport,
                        new(65536, 8192, 512, TimeSpan.FromSeconds(20)),
                        new(65536, 8192, 4096, 32, 16, TimeSpan.FromSeconds(20)),
                        new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System, notification);
            }
            return statusPrivateDeleteIndependent
                ? cleanupOnly
                    ? OpService.ForStatusPrivateConnectionDeleteIndependentCleanup(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        endpoint!, new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System)
                    : OpService.ForStatusPrivateConnectionDeleteIndependent(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        new("status-reader", statusCredential, statusTransport),
                        new("resource-reader", new Credential("resource-arm"), resourceTransport), selectedTransport,
                        new(65536, 8192, 512, TimeSpan.FromSeconds(20)),
                        new(65536, 8192, 4096, 32, 16, TimeSpan.FromSeconds(20)),
                        new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System, endpoint!)
                : statusSucceededDeleteVaultCancellation
                ? cleanupOnly
                    ? OpService.ForStatusSucceededDeleteVaultCancellationCleanup(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System)
                    : OpService.ForStatusSucceededDeleteVaultCancellation(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        new("status-reader", statusCredential, statusTransport),
                        new("resource-reader", statusSucceededResourceCredential, resourceTransport), selectedTransport,
                        new(65536, 8192, 512, TimeSpan.FromSeconds(20)),
                        new(65536, 8192, 4096, 32, 16, TimeSpan.FromSeconds(20)),
                        new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System)
                : statusSucceededDeleteVaultIndependent
                ? cleanupOnly
                    ? OpService.ForStatusSucceededDeleteVaultIndependentCleanup(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System)
                    : OpService.ForStatusSucceededDeleteVaultIndependent(Origin, Owner, "purge-source", capability,
                        declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                        new("status-reader", statusCredential, statusTransport),
                        new("resource-reader", statusSucceededResourceCredential, resourceTransport), selectedTransport,
                        new(65536, 8192, 512, TimeSpan.FromSeconds(20)),
                        new(65536, 8192, 4096, 32, 16, TimeSpan.FromSeconds(20)),
                        new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System)
                : statusSucceededDeleteVault
            ? cleanupOnly
                ? OpService.ForStatusSucceededDeleteVaultCleanup(Origin, Owner, "purge-source", capability,
                    declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                    new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System)
                : OpService.ForStatusSucceededDeleteVault(Origin, Owner, "purge-source", capability,
                    declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
                    new("status-reader", statusCredential, statusTransport),
                    new("resource-reader", statusSucceededResourceCredential, resourceTransport), selectedTransport,
                    new(65536, 8192, 512, TimeSpan.FromSeconds(20)),
                    new(65536, 8192, 4096, 32, 16, TimeSpan.FromSeconds(20)),
                    new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System)
            : new(Origin, Owner, "purge-source", capability,
            declaredScope ?? new(Subscription, "fixture-group", "eastus", Tenant, true, true), parent ?? provisioner,
            new("status-reader", statusCredential, statusTransport),
            new("resource-reader", new Credential("resource-arm"), resourceTransport), selectedTransport,
            new(65536, 8192, 512, TimeSpan.FromSeconds(20)),
            new(65536, 8192, 4096, 32, 16, TimeSpan.FromSeconds(20)),
            new(65536, 65536, TimeSpan.FromSeconds(20)), time ?? TimeProvider.System,
            Operation is ManagementMutation.UpdateNotification or ManagementMutation.CreateOrUpdateNotification or ManagementMutation.DeleteNotification &&
                !omitNotificationSource
                ? new(new(notificationSetupCredential, notificationSetup), new(notificationObserverCredential, notificationObserver),
                    new(65536, 65536, 65536, 16, 32, 8192, TimeSpan.FromSeconds(20)),
                    cleanupOnly ? null : notificationBaseline, !cleanupOnly,
                    exclusiveNotificationCreation && !omitExclusiveCreation
                        ? new(notificationEpoch ?? NotificationNamespaceEpoch, continuousWriterExclusion) : null)
                : null,
            endpoint);
        }
        internal OwnedManagementObserver NewObserver(OpService source) => new(new(Origin, Capability, TimeSpan.FromSeconds(20)),
            new VaultForwarder(async (request, token) =>
            {
                var response = await source.DispatchAsync(request, token);
                if (response.IsSuccessStatusCode && request.RequestUri!.AbsolutePath.EndsWith("/operation/arm", StringComparison.Ordinal))
                    notificationSubscribed = true;
                return response;
            }));
        internal VaultFixtureProvisioner.Plan Plan() => provisioner.OpenCleanupPlan(Owner, Native.Selector);
        internal ValueTask DrainParentAsync() => provisioner.DisposeAsync();
        internal ValueTask<VaultFixtureProvisioner.Result> SettleParentAsync() => provisioner.SettleAsync(Owner, Native.Selector);
        internal VaultFixtureProvisioner ReopenProvisioner()
        {
            HttpPipelineTransport Wire(string role)
            {
                var http = new HttpClient(new VaultForwarder((request, token) => Send(request, role, token)));
                clients.Add(http);
                return new HttpClientTransport(http);
            }
            if (statusPendingPurgeCancellation)
                return VaultFixtureProvisioner.ForStatusPendingPurgeCancellation(Native.Journal,
                    new(Subscription, "fixture-group", "eastus", Tenant, true, true), Baseline,
                    new("setup-arm", new Credential("setup-arm"), Wire("setup-arm")),
                    new("setup-secret", new Credential("setup-secret"), Wire("setup-secret")),
                    new("read-arm", new Credential("read-arm"), Wire("read-arm")),
                    new("read-secret", new Credential("read-secret"), Wire("read-secret")),
                    new(65536, TimeSpan.FromSeconds(20)));
            if (statusPendingPurgeIndependent)
                return VaultFixtureProvisioner.ForStatusPendingPurgeIndependent(Native.Journal,
                    new(Subscription, "fixture-group", "eastus", Tenant, true, true), Baseline,
                    new("setup-arm", new Credential("setup-arm"), Wire("setup-arm")),
                    new("setup-secret", new Credential("setup-secret"), Wire("setup-secret")),
                    new("read-arm", new Credential("read-arm"), Wire("read-arm")),
                    new("read-secret", new Credential("read-secret"), Wire("read-secret")),
                    new(65536, TimeSpan.FromSeconds(20)));
            if (statusPendingPurge)
                return VaultFixtureProvisioner.ForStatusPendingPurge(Native.Journal,
                    new(Subscription, "fixture-group", "eastus", Tenant, true, true), Baseline,
                    new("setup-arm", new Credential("setup-arm"), Wire("setup-arm")),
                    new("setup-secret", new Credential("setup-secret"), Wire("setup-secret")),
                    new("read-arm", new Credential("read-arm"), Wire("read-arm")),
                    new("read-secret", new Credential("read-secret"), Wire("read-secret")),
                    new(65536, TimeSpan.FromSeconds(20)));
            if (succeededDeleteVaultWire)
                return VaultFixtureProvisioner.ForCleanup(Native.Journal,
                    new(Subscription, "fixture-group", "eastus", Tenant, true, true),
                    new("setup-arm", new Credential("setup-arm"), Wire("setup-arm")),
                    new("resource-reader", statusSucceededResourceCredential, resourceTransport),
                    new(65536, TimeSpan.FromSeconds(20)));
            return new(Native.Journal, new(Subscription, "fixture-group", "eastus", Tenant, true, true),
                Baseline, new("setup-arm", new Credential("setup-arm"), Wire("setup-arm")),
                new("setup-secret", new Credential("setup-secret"), Wire("setup-secret")),
                new("read-arm", new Credential("read-arm"), Wire("read-arm")),
                new("read-secret", new Credential("read-secret"), Wire("read-secret")),
                new(65536, TimeSpan.FromSeconds(20)));
        }
        internal Op.Prepare PrepareRequest() => new(Native.Selector, Subscription, "fixture-group", "eastus", Tenant,
            VaultSku.Premium, 23, Operation, input.WebhookUrl, Guid.Empty);
        internal async Task<Op.Lease> PrepareAndBaseline()
        {
            var lease = await Observer.PostAsync<Op.Prepare, Op.Lease>("operation/prepare", PrepareRequest(), default);
            Armed = await Observer.SubscribeAsync("operation", lease.Facts, default);
            await Observer.PostAsync<ObserveLease, Op.Measurement>("operation/observe",
                new(lease.Facts.LeaseId, lease.Facts.Nonce, "baseline-before-dispatch", Armed.SubscriptionId), default);
            return lease;
        }
        private ManagementOperation? PendingHandle;
        internal async Task<SecretOutcome<ManagementOperation>> Start(Op.Lease lease)
        {
            var client = new VaultAdministration(new PurgeCredential("selected-arm", this),
                new PurgeSdkSeam(Source.SelectedTransport, this));
            ManagementScope scope = Operation is ManagementMutation.UpdateNotification or ManagementMutation.CreateOrUpdateNotification or ManagementMutation.DeleteNotification
                ? new NotificationScope(new(new(new(Subscription), "fixture-group"), lease.VaultName), lease.NotificationName!)
                : Operation is ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection
                ? new PrivateConnectionScope(new(new(new(Subscription), "fixture-group"), lease.VaultName), lease.PrivateConnectionName!)
                : Operation == ManagementMutation.PurgeDeletedVault
                ? new DeletedVaultScope(new(Subscription), "eastus", lease.VaultName)
                : new VaultScope(new(new(Subscription), "fixture-group"), lease.VaultName);
            var receipt = client.PrepareReceipt(scope, Operation);
            OriginalReceipt = receipt;
            var result = await Source.RunStartAsync(Native.Selector, client, scope, Operation, input, receipt, default);
            PendingHandle = result.IsSuccess ? result.Value : null;
            return result;
        }
        internal async ValueTask<Op.Measurement> Observe(Op.Lease lease, bool cancelPending = true)
        {
            var measured = await Observer.PostAsync<ObserveLease, Op.Measurement>("operation/observe",
                new(lease.Facts.LeaseId, lease.Facts.Nonce, "selected-state", Armed!.SubscriptionId), default);
            if (statusPendingPurgeCancellation && cancelPending)
            {
                using var canceled = new CancellationTokenSource();
                canceled.Cancel();
                int before = OriginalStatusReads;
                await Assert.That(async () => await Source.RunCheckStatusAsync(Native.Selector,
                    PendingHandle!, canceled.Token)).Throws<OperationCanceledException>();
                await Assert.That(OriginalStatusReads).IsEqualTo(before);
            }
            return measured;
        }
        internal ValueTask<RoleFixtureRelease.Measurement> Release() => Observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", Native.Selector, default);
        internal async Task<NativeCaseResult> RunOriginal(Op.SelectedInvocation? selectedInvocation = null)
        {
            object Runtime(string role) => new { token = role, expiresAt = "2099-01-01T00:00:00Z" };
            using var json = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                vaultUri = "https://controlled.vault.azure.net",
                setup = Runtime("setup-secret"),
                runtime = Runtime("runtime-secret"),
                denied = Runtime("denied-secret"),
                administrative = Runtime("admin-secret"),
                observer = Runtime("observer-secret"),
                families = new Dictionary<string, object> { ["ManagementOperation"] = input }
            }, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
            using var environment = OwnedAzureEnvironment.Create(json.RootElement);
            var definition = new NativeCaseDefinition(new("AzureKeyVault", Op.Members[0].Operation, Native.Selector.Variant,
                "controlled", Native.Selector.Case), Op.Members[0].Member);
            var registry = new NativeCaseRegistry();
            Op.Register(registry, environment, [definition], endpoint => new(endpoint,
                new VaultForwarder(async (request, token) =>
                {
                    bool prepare = request.RequestUri!.AbsolutePath == "/operation/prepare";
                    if (prepare) Native.Selector = JsonSerializer.Deserialize<Op.Prepare>(
                        await request.Content!.ReadAsByteArrayAsync(token), ManagementAdmission.Json)!.Selection;
                    var reply = await Source.DispatchAsync(request, token);
                    if (reply.IsSuccessStatusCode && request.RequestUri.AbsolutePath == "/operation/arm")
                        notificationSubscribed = true;
                    if (!prepare || PrepareReplyFault is null) return reply;
                    reply.Dispose();
                    if (PrepareReplyFault == "lost") throw new IOException("controlled-lost-prepare");
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    { Content = new StringContent("{", Encoding.UTF8, "application/json") };
                })), Source.SelectedTransport, selectedInvocation ?? Source);
            return (await NativeCaseRunner.RunAsync(registry, [definition], default)).Single();
        }
        private async Task<HttpResponseMessage> Send(HttpRequestMessage request, string role, CancellationToken token)
        {
            string path = request.RequestUri!.AbsolutePath;
            if (Operation is ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection &&
                (path.Contains("/providers/Microsoft.Network/", StringComparison.Ordinal) ||
                    path.Contains("/privateEndpointConnections", StringComparison.Ordinal)))
            {
                if (request.RequestUri.Host != "management.azure.com" || request.Headers.Authorization?.Parameter != role ||
                    request.RequestUri.Query != (path.Contains("/providers/Microsoft.Network/", StringComparison.Ordinal)
                        ? "?api-version=2026-01-01" : "?api-version=2026-02-01"))
                    throw new InvalidOperationException("private-approval-native-boundary");
                PrivateEndpoint ??= new(Native) { AllowEndpointDelete = true };
                if (path == PrivateEndpoint.ConnectionId && request.Method == HttpMethod.Get &&
                    Native.Read().Closing && PrivateCleanup404Body is not null &&
                    !(PrivateEndpoint.ConnectionPresent ?? PrivateEndpoint.EndpointExists))
                {
                    PrivateCleanup404Reached++;
                    return Reply(404, PrivateCleanup404Body);
                }
                if (role == "selected-arm" && request.Method == HttpMethod.Put && path == PrivateEndpoint.ConnectionId)
                {
                    SelectedUpdates++;
                    Prejournaled &= Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch != Guid.Empty;
                    var body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!;
                    if (body["properties"]?["privateLinkServiceConnectionState"]?["status"]?.GetValue<string>() != "Approved")
                        throw new InvalidOperationException("unexpected-private-approval");
                    PrivateEndpoint.ConnectionState = "Approved";
                    if (Fault == "approval-lost") throw new IOException("controlled-approval-loss");
                    var response = PrivateEndpoint.ConnectionData();
                    // The strict approval profile has the native child schema,
                    // not the network reader's location-bearing projection.
                    response.Remove("location");
                    if (Fault == "approval-initial-pending")
                        response["properties"]!["privateLinkServiceConnectionState"]!["status"] = "Pending";
                    if (Fault == "approval-wrong-endpoint")
                        response["properties"]!["privateEndpoint"]!["id"] = PrivateEndpoint.Binding.EndpointId + "-foreign";
                    if (Fault == "approval-initial-updating") response["properties"]!["provisioningState"] = "Updating";
                    var selected = Reply(PrivateStartStatus, response.ToJsonString());
                    if (Barrier == "private-start-body") await Body(selected, "private-start-body");
                    return selected;
                }
                if (Operation == ManagementMutation.DeletePrivateConnection && role == "selected-arm" &&
                    request.Method == HttpMethod.Delete && path == PrivateEndpoint.ConnectionId)
                {
                    SelectedDeletes++;
                    Prejournaled &= Native.Read().PrivateEndpoint!.Connection is
                    { DeleteAttempted: true, ActiveDispatch: var dispatch } && dispatch != Guid.Empty;
                    if (request.Content is not null)
                        throw new InvalidOperationException("private-delete-body");
                    PrivateEndpoint.ConnectionPresent = Fault == "private-delete-child-present";
                    PrivateEndpoint.ConnectionState = "Disconnected";
                    var row = PrivateEndpoint.ConnectionData();
                    row.Remove("location");
                    if (Fault == "private-delete-wrong-endpoint")
                        row["properties"]!["privateEndpoint"]!["id"] = PrivateEndpoint.Binding.EndpointId + "-foreign";
                    if (Fault == "private-delete-pending")
                        row["properties"]!["privateLinkServiceConnectionState"]!["status"] = "Pending";
                    if (Fault == "private-delete-updating") row["properties"]!["provisioningState"] = "Updating";
                    await Pause("selected-send");
                    if (Fault == "private-delete-lost") throw new IOException("controlled-private-delete-loss");
                    var response = Reply(PrivateStartStatus, Fault == "private-delete-empty" ? "" : row.ToJsonString());
                    if (Barrier == "private-start-body") await Body(response, "private-start-body");
                    return response;
                }
                if (role == "resource-arm" && request.Method == HttpMethod.Get && path == PrivateEndpoint.ConnectionId)
                {
                    ResourceReads++;
                    PrivateChildResourceReads++;
                    await Pause(SelectedUpdates + SelectedDeletes == 0 ? "private-baseline" : "private-read");
                    if (SelectedDeletes > 0 && PrivateDeleteRead404Body is not null)
                    {
                        PrivateDeleteRead404Reached++;
                        return Reply(404, PrivateDeleteRead404Body);
                    }
                    if (SelectedUpdates == 0 && Fault == "approval-baseline-approved" ||
                        SelectedUpdates > 0 && Fault == "approval-post-pending")
                    {
                        var body = PrivateEndpoint.ConnectionData();
                        body["properties"]!["privateLinkServiceConnectionState"]!["status"] =
                            SelectedUpdates == 0 ? "Approved" : "Pending";
                        return Reply(200, body.ToJsonString());
                    }
                    var observed = await PrivateEndpoint.Respond(request, token);
                    if (observed.StatusCode == HttpStatusCode.OK &&
                        (SelectedUpdates + SelectedDeletes == 0 ? PrivateBaselineTransform : PrivatePostTransform) is { } transform)
                    {
                        if (SelectedUpdates + SelectedDeletes == 0) PrivateBaselineMutations++;
                        else PrivatePostMutations++;
                        var body = JsonNode.Parse(await observed.Content.ReadAsByteArrayAsync(token))!.AsObject();
                        transform(body);
                        observed.Content.Dispose();
                        observed.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
                    }
                    if (SelectedUpdates + SelectedDeletes > 0 && Barrier == "private-read-body") await Body(observed, "private-read-body");
                    return observed;
                }
                var endpointResponse = await PrivateEndpoint.Respond(request, token);
                if (statusPrivateUpdateIndependent && SelectedUpdates > 0 &&
                    request.Method == HttpMethod.Get && path == PrivateEndpoint.Binding.EndpointId &&
                    endpointResponse.StatusCode == HttpStatusCode.OK)
                {
                    var row = JsonNode.Parse(await endpointResponse.Content.ReadAsByteArrayAsync(token))!.AsObject();
                    row["properties"]!["manualPrivateLinkServiceConnections"]![0]!["properties"]!["privateLinkServiceConnectionState"]!["status"] =
                        PrivateEndpoint.ConnectionState;
                    if (PrivateEndpointPostTransform is { } transform)
                    {
                        PrivateEndpointPostMutations++;
                        transform(row);
                    }
                    endpointResponse.Content.Dispose();
                    endpointResponse.Content = new StringContent(row.ToJsonString(), Encoding.UTF8, "application/json");
                }
                if (Operation == ManagementMutation.DeletePrivateConnection && SelectedDeletes > 0 &&
                    request.Method == HttpMethod.Get && path == PrivateEndpoint.Binding.EndpointId &&
                    endpointResponse.StatusCode == HttpStatusCode.OK)
                {
                    var row = JsonNode.Parse(await endpointResponse.Content.ReadAsByteArrayAsync(token))!;
                    row["properties"]!["manualPrivateLinkServiceConnections"]![0]!["properties"]!["privateLinkServiceConnectionState"]!["status"] =
                        Fault == "private-delete-endpoint-pending" ? "Pending" : "Disconnected";
                    if (Fault == "private-delete-endpoint-subnet")
                        row["properties"]!["subnet"]!["id"] = PrivateEndpoint.Binding.SubnetId + "-foreign";
                    endpointResponse.Dispose();
                    return Reply(200, row.ToJsonString());
                }
                return endpointResponse;
            }
            if (request.RequestUri.Host != "management.azure.com" || request.RequestUri.Query != "?api-version=2026-02-01" ||
                request.Headers.Authorization?.Parameter != role)
            {
                if (Operation is ManagementMutation.UpdateNotification or ManagementMutation.CreateOrUpdateNotification or ManagementMutation.DeleteNotification &&
                    request.RequestUri.Host == "management.azure.com" &&
                    request.RequestUri.Query == "?api-version=2025-02-15" &&
                    request.Headers.Authorization?.Parameter == role)
                    return await SendNotification(request, role, token);
                throw new InvalidOperationException("purge-native-boundary");
            }
            if (Native.Wire.VaultId.Length == 0 && path.Contains("/vaults/", StringComparison.Ordinal))
            {
                Native.Wire.VaultId = path;
                Native.Wire.VaultName = path[(path.LastIndexOf('/') + 1)..];
            }
            if ((succeededDeleteVaultWire && role == "resource-arm" ||
                (PendingWire || statusNotificationUpdateIndependent || statusNotificationCreateIndependent || statusPrivateUpdateIndependent) && role is "resource-arm" or "read-arm") && request.Method == HttpMethod.Get)
            {
                ResourceReads++;
                bool closing = Native.Read().Closing, selected = SelectedDeletes > 0 || PendingWire && SelectedPurges > 0;
                if ((PendingWire || statusNotificationUpdateIndependent || statusNotificationCreateIndependent || statusPrivateUpdateIndependent) && role == "read-arm" && closing)
                    await Pause("parent-cleanup-read");
                if (closing) SucceededCleanupReads++;
                else if (selected) SucceededSelectedReads++;
                else if (notificationSubscribed) SucceededBaselineReads++;
                var plan = Plan();
                if (path != plan.VaultId && path != plan.DeletedId)
                    throw new InvalidOperationException("foreign-succeeded-resource");
                bool deleted = path == plan.DeletedId;
                if (deleted) DeletedResourceReads++;
                if (selected && !closing) await Pause("resource-body");
                if (closing && Fault?.StartsWith("cleanup-", StringComparison.Ordinal) == true)
                {
                    CleanupFaultsReached++;
                    if (Fault == "cleanup-active-present" && !deleted)
                        return Reply(200, Native.Wire.Vault!.ToJsonString());
                    if (Fault != "cleanup-active-present")
                        return Reply(404, Fault.EndsWith("-empty", StringComparison.Ordinal) ? "" :
                            Fault.EndsWith("-malformed", StringComparison.Ordinal) ? "{" : """{"error":{"code":"Forbidden"}}""");
                }
                if (selected && !closing && (Fault == "resource-denied" || Fault == "resource-malformed"))
                {
                    ResourceFaultsReached++;
                    return Reply(Fault == "resource-denied" ? 403 : 200,
                        Fault == "resource-denied" ? """{"error":{"code":"Forbidden"}}""" : "{");
                }
                bool present = deleted ? Native.Wire.Deleted : Native.Wire.Active ||
                    selected && Fault == "active-reappeared";
                if (deleted && selected && Fault == "deleted-missing") present = false;
                if (!present)
                {
                    if (selected && Fault == "deleted-missing") ResourceFaultsReached++;
                    return Reply(404, """{"error":{"code":"ResourceNotFound"}}""");
                }
                JsonObject payload = deleted ? JsonNode.Parse(JsonSerializer.Serialize(new
                {
                    id = path,
                    name = plan.VaultName,
                    type = PendingWire ? "Microsoft.KeyVault/deletedVaults" : "Microsoft.KeyVault/locations/deletedVaults",
                    properties = new
                    {
                        location = "eastus",
                        vaultId = plan.VaultId,
                        tags = Native.Wire.Vault!["tags"],
                        purgeProtectionEnabled = false,
                        deletionDate = "2026-10-16T00:00:00Z",
                        scheduledPurgeDate = "2026-11-08T00:00:00Z"
                    }
                }))!.AsObject() : Native.Wire.Vault!.DeepClone().AsObject();
                if (selected && !closing && Fault is "deleted-foreign" or "deleted-protected" or "deleted-malformed" or "active-reappeared")
                {
                    ResourceFaultsReached++;
                    if (deleted && Fault == "deleted-malformed") return Reply(200, "{");
                    if (deleted && Fault == "deleted-foreign") payload["properties"]!["vaultId"] = plan.VaultId + "-foreign";
                    if (deleted && Fault == "deleted-protected") payload["properties"]!["purgeProtectionEnabled"] = true;
                }
                if (!closing && notificationSubscribed &&
                    (selected ? SucceededSelectedTransform : SucceededBaselineTransform) is { } transform)
                {
                    SucceededResourceMutations++;
                    transform(payload);
                }
                return Reply(200, payload.ToJsonString());
            }
            if (role == "read-arm" && request.Method == HttpMethod.Get &&
                Fault?.StartsWith("cleanup-", StringComparison.Ordinal) == true && Native.Read().Closing &&
                path == (Fault.StartsWith("cleanup-active-", StringComparison.Ordinal) ? Plan().VaultId : Plan().DeletedId))
            {
                CleanupFaultsReached++;
                return Reply(404, Fault.EndsWith("-empty", StringComparison.Ordinal) ? "" :
                    Fault.EndsWith("-malformed", StringComparison.Ordinal) ? "{" : """{"error":{"code":"Forbidden"}}""");
            }
            if ((recoveryCancellation || updateCancellation) && role == "read-arm" && request.Method == HttpMethod.Get &&
                path == Plan().DeletedId && Native.Wire.Deleted)
                return Reply(200, JsonSerializer.Serialize(new
                {
                    id = path,
                    name = Native.Wire.VaultName,
                    type = "Microsoft.KeyVault/locations/deletedVaults",
                    properties = new
                    {
                        location = "eastus",
                        vaultId = Native.Wire.VaultId,
                        tags = Native.Wire.Vault!["tags"],
                        purgeProtectionEnabled = Baseline.PurgeProtection,
                        deletionDate = "2026-10-16T00:00:00Z",
                        scheduledPurgeDate = "2026-11-08T00:00:00Z"
                    }
                }));
            if (role == "selected-arm" && request.Method == HttpMethod.Put)
            {
                var plan = Plan();
                if (Operation is not (ManagementMutation.RecoverVault or ManagementMutation.CreateOrUpdateVault) ||
                    path != plan.VaultId)
                    throw new InvalidOperationException("foreign-selected-recovery");
                if (Operation == ManagementMutation.RecoverVault) SelectedRecoveries++;
                else SelectedUpdates++;
                Prejournaled &= Native.Read().Resources.Single(r => r.Id == plan.VaultId).ActiveDispatch != Guid.Empty;
                RecoveryRequest = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
                // Controlled provider assumption, not Azure evidence: omitted tags
                // retain the deleted vault's tags. Negative cases remove/substitute them.
                var previous = Native.Wire.Vault!.DeepClone().AsObject();
                var tags = previous["tags"]!.DeepClone();
                Native.Wire.Vault = RecoveryRequest.DeepClone().AsObject();
                Native.Wire.Vault["tags"] = tags;
                Native.Wire.Vault["id"] = plan.VaultId;
                Native.Wire.Vault["name"] = plan.VaultName;
                Native.Wire.Vault["type"] = "Microsoft.KeyVault/vaults";
                Native.Wire.Vault["properties"]!["vaultUri"] = $"https://{plan.VaultName}.vault.azure.net";
                Native.Wire.Vault["properties"]!["provisioningState"] = "Succeeded";
                if (recoveryCancellation || updateCancellation) Native.Wire.Vault["properties"]!["privateEndpointConnections"] = new JsonArray();
                if (Fault == "missing-tags") Native.Wire.Vault.Remove("tags");
                if (Fault == "foreign-tags") Native.Wire.Vault["tags"]!["secretkit-fixture"] = Guid.NewGuid().ToString("N");
                if (Fault == "configuration") Native.Wire.Vault["properties"]!["softDeleteRetentionInDays"] = 7;
                if (Fault == "ownership-configuration") Native.Wire.ReadFault = "configuration";
                if (Fault == "unchanged") Native.Wire.Vault = previous;
                Native.Wire.Active = true;
                Native.Wire.Deleted = Fault == "deleted-present";
                await Pause("selected-send");
                if (Fault == "lost") throw new IOException("controlled-selected-recovery-loss");
                var payload = Native.Wire.Vault.DeepClone();
                payload["properties"]!["provisioningState"] = "Updating";
                var response = Reply(Fault == "synchronous" ? 200 : 201,
                    Fault == "selected-malformed" ? "{" : payload.ToJsonString());
                if (Fault is not ("no-target" or "synchronous"))
                    response.Headers.TryAddWithoutValidation("Azure-AsyncOperation",
                        "https://management.azure.com" + StatusPath + "?api-version=2026-02-01");
                if (Barrier == "selected-body") await Body(response, "selected-body");
                return response;
            }
            if (role == "selected-arm" && request.Method is { } method && (method == HttpMethod.Post || method == HttpMethod.Delete))
            {
                var plan = Plan();
                string id;
                if (Operation == ManagementMutation.DeleteVault)
                {
                    if (method != HttpMethod.Delete || path != plan.VaultId) throw new InvalidOperationException("foreign-selected-delete");
                    SelectedDeletes++;
                    id = plan.VaultId;
                    Native.Wire.Active = Fault == "active-present";
                    Native.Wire.Deleted = true;
                }
                else
                {
                    if (method != HttpMethod.Post || path != plan.DeletedId + "/purge") throw new InvalidOperationException("foreign-selected-purge");
                    SelectedPurges++;
                    id = plan.DeletedId;
                    Native.Wire.Deleted = PendingWire;
                }
                Prejournaled &= Native.Read().Resources.Single(r => r.Id == id).ActiveDispatch != Guid.Empty;
                await Pause("selected-send");
                if (Fault == "lost") throw new IOException("controlled-selected-purge-loss");
                int status = Operation == ManagementMutation.DeleteVault
                    ? Fault == "synchronous" ? 204 : Fault == "delete-202" ? 202 : 200
                    : Fault == "synchronous" ? 200 : 202;
                var response = Reply(status, status == 204 ? "" : Fault == "selected-malformed"
                    ? "{" : Fault == "synchronous" ? "{\"status\":\"Succeeded\"}" : "{\"status\":\"InProgress\"}");
                if (Fault is not ("no-target" or "synchronous"))
                {
                    response.Headers.TryAddWithoutValidation("Azure-AsyncOperation", "https://management.azure.com" + StatusPath + "?api-version=2026-02-01");
                    if (!succeededDeleteVaultWire)
                        response.Headers.TryAddWithoutValidation("Location", "https://management.azure.com" + StatusPath + "?api-version=2026-02-01");
                }
                if (Barrier == "selected-body") await Body(response, "selected-body");
                return response;
            }
            if (PendingWire && role is "selected-arm" or "status-arm" &&
                request.Method == HttpMethod.Get && path == StatusPath)
            {
                bool cleanup = role == "selected-arm" && Native.Read().Closing;
                if (role == "selected-arm") OriginalStatusReads++;
                else IndependentStatusReads++;
                await Pause(cleanup ? "pending-cleanup" : role == "selected-arm" ? "original-poll" : "status-send");
                string phaseFault = cleanup ? "pending-cleanup-" : role == "selected-arm" ? "pending-selected-" : "pending-independent-";
                string? fault = Fault?.StartsWith(phaseFault, StringComparison.Ordinal) == true ? Fault[phaseFault.Length..] : null;
                if (fault == "lost") throw new IOException("controlled-pending-response-loss");
                if (fault == "denied") return Reply(403, "{\"error\":{\"code\":\"Forbidden\"}}");
                if (fault == "malformed") return Reply(200, "{");
                if (cleanup && fault != "pending") Native.Wire.Deleted = false;
                string state = cleanup && fault != "pending" || fault == "succeeded" ? "Succeeded" : "InProgress";
                var response = Reply(200, role == "selected-arm"
                    ? JsonSerializer.Serialize(new { id = StatusPath, status = state })
                    : JsonSerializer.Serialize(new { id = StatusPath,
                        name = StatusPath[(StatusPath.LastIndexOf('/') + 1)..], status = state }));
                if (cleanup && fault == "challenge")
                {
                    response.StatusCode = HttpStatusCode.Unauthorized;
                    response.Headers.TryAddWithoutValidation("WWW-Authenticate",
                        "Bearer authorization_uri=\"https://login.microsoftonline.com/common\", error=\"insufficient_claims\", claims=\"eyJhY2Nlc3NfdG9rZW4iOnt9fQ==\"");
                    Native.Wire.Deleted = true;
                }
                if (Barrier == (cleanup ? "pending-cleanup-body" : "original-poll-body"))
                    await Body(response, cleanup ? "pending-cleanup-body" : "original-poll-body");
                return response;
            }
            if (role is "selected-arm" or "status-arm")
            {
                if (role == "selected-arm" && Operation is ManagementMutation.RecoverVault or ManagementMutation.CreateOrUpdateVault &&
                    request.Method == HttpMethod.Get && path == Plan().VaultId)
                {
                    OriginalResourceReads++;
                    await Pause("original-final");
                    if ((recoveryCancellation || updateCancellation) && Fault?.StartsWith("check-2-", StringComparison.Ordinal) == true)
                    {
                        SelectedStatusFaultsReached++;
                        string kind = Fault["check-2-".Length..];
                        if (kind == "lost") throw new IOException("controlled-recovery-final-loss");
                        if (kind == "denied") return Reply(403, """{"error":{"code":"Forbidden"}}""");
                        if (kind == "malformed") return Reply(200, "{");
                        var final = Native.Wire.Vault!.DeepClone();
                        final["properties"]!["provisioningState"] = kind switch
                        {
                            "pending" => "Updating",
                            "failed" => "Failed",
                            "canceled" => "Canceled",
                            _ => "future-state"
                        };
                        return Reply(200, final.ToJsonString());
                    }
                    var finalResponse = await Native.Wire.Respond(request, role, token);
                    if ((recoveryCancellation || updateCancellation) && Barrier == "original-final-body")
                        await Body(finalResponse, "original-final-body");
                    return finalResponse;
                }
                if (request.Method != HttpMethod.Get || path != StatusPath) throw new InvalidOperationException("foreign-purge-status");
                if (role == "selected-arm")
                {
                    OriginalStatusReads++;
                    await Pause(OriginalStatusReads == 1 ? "original-poll" : "original-final");
                    if ((Operation == ManagementMutation.PurgeDeletedVault && Native.Selector.Case == "cancellation-boundary" ||
                        recoveryCancellation || updateCancellation) &&
                        Fault?.StartsWith($"check-{OriginalStatusReads}-", StringComparison.Ordinal) == true)
                    {
                        SelectedStatusFaultsReached++;
                        string kind = Fault[$"check-{OriginalStatusReads}-".Length..];
                        if (kind == "lost") throw new IOException("controlled-purge-status-loss");
                        return Reply(kind == "denied" ? 403 : 200, kind switch
                        {
                            "malformed" => "{",
                            "denied" => """{"error":{"code":"Forbidden"}}""",
                            "pending" => """{"status":"InProgress"}""",
                            "failed" => """{"status":"Failed"}""",
                            "canceled" => """{"status":"Canceled"}""",
                            _ => """{"status":"future-state"}"""
                        });
                    }
                }
                else IndependentStatusReads++;
                if (role == "status-arm") await Pause("status-send");
                string state = role == "status-arm" ? Fault switch
                {
                    "pending" => "InProgress",
                    "unknown" => "future-state",
                    "failed" => "Failed",
                    "canceled" => "Canceled",
                    _ => "Succeeded"
                } : "Succeeded";
                var response = Reply(role == "status-arm" && Fault == "status-denied" ? 403 : 200,
                    role == "status-arm" && Fault == "status-malformed" ? "{" :
                    role == "status-arm" && Fault == "status-denied" ? "{\"error\":{\"code\":\"Forbidden\"}}" :
                    recoveryCancellation || updateCancellation
                        ? JsonSerializer.Serialize(new { id = StatusPath, status = state })
                        : JsonSerializer.Serialize(new { id = StatusPath, name = StatusPath[(StatusPath.LastIndexOf('/') + 1)..], status = state }));
                if (role == "selected-arm")
                {
                    string bodyBarrier = OriginalStatusReads == 1 ? "original-poll-body" : "original-final-body";
                    if (Barrier == bodyBarrier) await Body(response, bodyBarrier);
                }
                return response;
            }
            if (role == "resource-arm")
            {
                ResourceReads++;
                string id = Operation == ManagementMutation.PurgeDeletedVault ? Plan().DeletedId : Plan().VaultId;
                bool counterpart = (Operation == ManagementMutation.DeleteVault && Native.Selector.Case == "cancellation-boundary" ||
                    recoveryCancellation || updateCancellation) &&
                    path == Plan().DeletedId;
                bool activeCounterpart = Operation == ManagementMutation.PurgeDeletedVault && Native.Selector.Case == "cancellation-boundary" &&
                    path == Plan().VaultId;
                if (request.Method != HttpMethod.Get || path != id && !counterpart && !activeCounterpart) throw new InvalidOperationException("foreign-operation-resource");
                bool selected = SelectedDeletes + SelectedPurges + SelectedRecoveries + SelectedUpdates > 0;
                if (activeCounterpart)
                {
                    ActiveCounterpartReads++;
                    if (Fault == (selected ? "purge-active-after" : "purge-active-before"))
                    {
                        ResourceFaultsReached++;
                        return Reply(200, Native.Wire.Vault!.ToJsonString());
                    }
                    if (selected && Fault == "purge-active-denied")
                    {
                        ResourceFaultsReached++;
                        return Reply(403, """{"error":{"code":"Forbidden"}}""");
                    }
                    return await Native.Wire.Respond(request, role, token);
                }
                if (Operation == ManagementMutation.PurgeDeletedVault && Native.Selector.Case == "cancellation-boundary" &&
                    (!selected && Fault is "purge-deleted-missing" or "purge-deleted-foreign" or "purge-deleted-protected" or "purge-deleted-malformed" ||
                        selected && Fault == "purge-deleted-after"))
                {
                    ResourceFaultsReached++;
                    if (Fault == "purge-deleted-missing") return Reply(404, """{"error":{"code":"VaultNotFound"}}""");
                    if (Fault == "purge-deleted-malformed") return Reply(200, "{");
                    return Reply(200, JsonSerializer.Serialize(new
                    {
                        id = path,
                        name = Native.Wire.VaultName,
                        type = "Microsoft.KeyVault/locations/deletedVaults",
                        properties = new
                        {
                            location = "eastus",
                            vaultId = Native.Wire.VaultId + (Fault == "purge-deleted-foreign" ? "-foreign" : ""),
                            purgeProtectionEnabled = Fault == "purge-deleted-protected",
                            deletionDate = "2026-10-16T00:00:00Z",
                            scheduledPurgeDate = "2026-11-08T00:00:00Z"
                        }
                    }));
                }
                if (counterpart)
                {
                    DeletedResourceReads++;
                    if (!Native.Wire.Deleted || selected && Fault == "deleted-missing")
                    {
                        if (selected && Fault == "deleted-missing") ResourceFaultsReached++;
                        return Reply(404, """{"error":{"code":"ResourceNotFound"}}""");
                    }
                    if (Fault == "deleted-malformed")
                    {
                        ResourceFaultsReached++;
                        return Reply(200, "{");
                    }
                    bool foreign = Fault == "deleted-foreign", protectedVault = Fault == "deleted-protected";
                    if (foreign || protectedVault) ResourceFaultsReached++;
                    return Reply(200, JsonSerializer.Serialize(new
                    {
                        id = path,
                        name = Native.Wire.VaultName,
                        type = "Microsoft.KeyVault/locations/deletedVaults",
                        properties = new
                        {
                            location = "eastus",
                            vaultId = Native.Wire.VaultId + (foreign ? "-foreign" : ""),
                            tags = recoveryCancellation || updateCancellation ? Native.Wire.Vault!["tags"] : null,
                            purgeProtectionEnabled = protectedVault,
                            deletionDate = "2026-10-16T00:00:00Z",
                            scheduledPurgeDate = "2026-11-08T00:00:00Z"
                        }
                    }));
                }
                if (Operation == ManagementMutation.DeleteVault && Native.Selector.Case == "cancellation-boundary" &&
                    selected && Fault == "active-reappeared")
                {
                    ResourceFaultsReached++;
                    return Reply(200, Native.Wire.Vault!.ToJsonString());
                }
                if (selected && Fault == "resource-malformed") return Reply(200, "{");
                if (selected && Fault == "resource-denied") return Reply(403, "{\"error\":{\"code\":\"Forbidden\"}}");
                if (Operation != ManagementMutation.PurgeDeletedVault)
                {
                    var current = await Native.Wire.Respond(request, role, token);
                    if ((Operation is ManagementMutation.RecoverVault or ManagementMutation.CreateOrUpdateVault ? selected : !Native.Wire.Active) &&
                        Barrier == "resource-body") await Body(current, "resource-body");
                    return current;
                }
                var response = !Native.Wire.Deleted ? Reply(404, "{\"error\":{\"code\":\"VaultNotFound\"}}") :
                    Reply(200, JsonSerializer.Serialize(new
                    {
                        id = path,
                        name = Native.Wire.VaultName,
                        type = "Microsoft.KeyVault/locations/deletedVaults",
                        properties = new
                        {
                            location = "eastus",
                            vaultId = Native.Wire.VaultId,
                            purgeProtectionEnabled = false,
                            deletionDate = "2026-10-16T00:00:00Z",
                            scheduledPurgeDate = "2026-11-08T00:00:00Z"
                        }
                    }));
                if (!Native.Wire.Deleted && Barrier == "resource-body") await Body(response, "resource-body");
                return response;
            }
            if (role == "setup-arm" && request.Method == HttpMethod.Post) SetupPurges++;
            if (role == "setup-arm" && request.Method == HttpMethod.Delete) SetupDeletes++;
            var native = await Native.Wire.Respond(request, role, token);
            if ((recoveryCancellation || updateCancellation || PendingWire || succeededDeleteVaultWire || statusNotificationUpdateIndependent || statusNotificationCreateIndependent || statusPrivateUpdateIndependent) &&
                Native.Wire.Vault is not null)
                Native.Wire.Vault["properties"]!["privateEndpointConnections"] = new JsonArray();
            if ((PendingWire || statusNotificationUpdateIndependent || statusNotificationCreateIndependent || statusPrivateUpdateIndependent) && role == "setup-arm")
            {
                if (request.Method == HttpMethod.Put) await Pause("parent-setup");
                if (Barrier == "parent-cleanup-body" && request.Method == HttpMethod.Delete)
                    await Body(native, "parent-cleanup-body");
            }
            return native;
        }
        private async Task<HttpResponseMessage> SendNotification(HttpRequestMessage request, string role, CancellationToken token)
        {
            if (request.Method == HttpMethod.Get) NotificationResourceReads++;
            string id = request.RequestUri!.AbsolutePath;
            var plan = Plan();
            if (!plan.OwnedNotificationIds.Contains(id)) throw new InvalidOperationException("foreign-notification-scope");
            if (request.Method == HttpMethod.Put && role == "notification-setup-arm")
            {
                NotificationSetupPuts++;
                NotificationRow = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
                NotificationRow["id"] = id;
                NotificationRow["name"] = id[(id.LastIndexOf('/') + 1)..];
                NotificationRow["type"] = "Microsoft.EventGrid/eventSubscriptions";
                NotificationRow["properties"]!["topic"] = plan.VaultId;
                NotificationRow["properties"]!["provisioningState"] = "Succeeded";
                await Pause("notification-setup");
                var response = Reply(201, NotificationRow.ToJsonString());
                response.Headers.TryAddWithoutValidation("Location", request.RequestUri.AbsoluteUri);
                return response;
            }
            if ((request.Method == HttpMethod.Patch || request.Method == HttpMethod.Put) && role == "selected-arm")
            {
                SelectedUpdates++;
                Prejournaled &= Native.Read().Resources.Single(r => r.Id == id).ActiveDispatch != Guid.Empty;
                RecoveryRequest = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
                // Separate controlled PUT/PATCH retention assumptions for omitted
                // mappings and labels. The real SDK request remains untouched.
                var changes = request.Method == HttpMethod.Put
                    ? RecoveryRequest["properties"]!.AsObject() : RecoveryRequest;
                if (exclusiveNotificationCreation && NotificationRow is null)
                {
                    NotificationRow = new JsonObject
                    {
                        ["id"] = id,
                        ["name"] = id[(id.LastIndexOf('/') + 1)..],
                        ["type"] = "Microsoft.EventGrid/eventSubscriptions",
                        ["properties"] = new JsonObject { ["topic"] = plan.VaultId }
                    };
                    var properties = NotificationRow["properties"]!.AsObject();
                    if (NotificationCreatedLabels != "absent")
                        properties["labels"] = NotificationCreatedLabels switch
                        {
                            "empty" => new JsonArray(),
                            "null" => null,
                            "nonce" => new JsonArray("secretkit-fixture-" + Native.Selector.Nonce.ToString("N")),
                            _ => new JsonArray("foreign-owner")
                        };
                }
                var mappings = NotificationRow!["properties"]!["destination"]?["properties"]?["deliveryAttributeMappings"]?.DeepClone();
                if (Fault != "unchanged")
                    foreach (var field in changes)
                        NotificationRow["properties"]![field.Key] = field.Value?.DeepClone();
                if (mappings is not null)
                    NotificationRow["properties"]!["destination"]!["properties"]!["deliveryAttributeMappings"] = mappings;
                else if (exclusiveNotificationCreation)
                    NotificationRow["properties"]!["destination"]!["properties"]!["deliveryAttributeMappings"] = new JsonArray();
                NotificationRow["properties"]!["provisioningState"] = "Succeeded";
                var responseBody = NotificationRow.DeepClone();
                responseBody["properties"]!["provisioningState"] = "Updating";
                await Pause("selected-send");
                if (Fault == "lost") throw new IOException("controlled-notification-update-loss");
                var response = Reply(201, responseBody.ToJsonString());
                response.Headers.TryAddWithoutValidation("Location", request.RequestUri.AbsoluteUri);
                if (Barrier == "selected-body") await Body(response, "selected-body");
                return response;
            }
            if (request.Method == HttpMethod.Delete && role == "notification-setup-arm")
            {
                NotificationDeletes++;
                NotificationRow = null;
                var response = Reply(204, "");
                if (Barrier == "notification-cleanup-body") await Body(response, "notification-cleanup-body");
                return response;
            }
            if (request.Method == HttpMethod.Delete && role == "selected-arm")
            {
                SelectedDeletes++;
                Prejournaled &= Native.Read().Resources.Single(r => r.Id == id).ActiveDispatch != Guid.Empty;
                if (Fault != "surviving") NotificationRow = null;
                await Pause("selected-send");
                if (Fault == "lost") throw new IOException("controlled-notification-delete-loss");
                var response = Reply(SelectedNotificationDeleteStatus,
                    Fault == "nonempty" ? """{"status":"Succeeded"}""" : "");
                if (Fault == "continuation")
                    response.Headers.TryAddWithoutValidation("Location", request.RequestUri.AbsoluteUri);
                if (Fault == "retry") response.Headers.TryAddWithoutValidation("Retry-After", "1");
                if (Barrier == "selected-body") await Body(response, "selected-body");
                return response;
            }
            if (request.Method != HttpMethod.Get) throw new InvalidOperationException("foreign-notification-write");
            bool notificationCancellation = Operation == ManagementMutation.DeleteNotification &&
                Native.Selector.Case is "cancellation-boundary" or "independent-effect";
            if (notificationCancellation && role == "notification-observer-arm" &&
                (SelectedDeletes > 0 && Fault?.StartsWith("read404-", StringComparison.Ordinal) == true ||
                    Native.Read().Closing && Fault?.StartsWith("cleanup404-", StringComparison.Ordinal) == true))
            {
                NotificationReadFaultsReached++;
                string kind = Fault[(Fault.IndexOf('-') + 1)..];
                return Reply(404, kind switch
                {
                    "empty" => "",
                    "malformed" => "{",
                    "forbidden" => """{"error":{"code":"Forbidden"}}""",
                    _ => """{"error":{"code":"NotFound","details":[{"code":"Forbidden"}]}}"""
                });
            }
            if (role == "notification-observer-arm" && SelectedDeletes > 0)
            {
                await Pause("notification-read");
                if (Fault == "read-denied") return Reply(403, """{"error":{"code":"Forbidden"}}""");
                if (Fault == "read-malformed") return Reply(200, "{");
            }
            if (role == "status-arm")
            {
                IndependentStatusReads++;
                await Pause("status-send");
                if (Fault == "status-denied") return Reply(403, """{"error":{"code":"Forbidden"}}""");
            }
            if (role == "selected-arm")
            {
                OriginalStatusReads++;
                await Pause("original-final");
                if (Operation is ManagementMutation.UpdateNotification or ManagementMutation.CreateOrUpdateNotification &&
                    (Native.Selector.Case == "cancellation-boundary" || statusNotificationUpdateIndependent || statusNotificationCreateIndependent))
                {
                    if (Fault == "original-denied") return Reply(403, """{"error":{"code":"Forbidden"}}""");
                    if (Fault == "original-malformed") return Reply(200, "{");
                    if (Fault == "original-lost") throw new IOException("controlled-notification-status-loss");
                }
            }
            if (NotificationRow is null)
            {
                if (exclusiveNotificationCreation && role == "notification-observer-arm" &&
                    SelectedUpdates == 0 && !Native.Read().Closing)
                {
                    if (notificationSubscribed) NotificationArmedAbsences++;
                    else NotificationPreparationAbsences++;
                    if (notificationSubscribed && NotificationAbsent404Body is not null)
                        return Reply(404, NotificationAbsent404Body);
                }
                var absence = Reply(404, """{"error":{"code":"NotFound"}}""");
                if ((notificationCancellation || exclusiveNotificationCreation) && Barrier == "notification-read-body")
                    await Body(absence, "notification-read-body");
                return absence;
            }
            var copy = NotificationRow.DeepClone().AsObject();
            if (role == "notification-observer-arm" && notificationSubscribed && !Native.Read().Closing &&
                (SelectedUpdates == 0 ? NotificationBaselineTransform : NotificationPostTransform) is { } transform)
            {
                if (SelectedUpdates == 0) NotificationBaselineMutations++;
                else NotificationPostMutations++;
                transform(copy);
            }
            if (role == "selected-arm" && Operation is ManagementMutation.UpdateNotification or ManagementMutation.CreateOrUpdateNotification &&
                (Native.Selector.Case == "cancellation-boundary" || statusNotificationUpdateIndependent || statusNotificationCreateIndependent))
            {
                if (Fault == "original-updating") copy["properties"]!["provisioningState"] = "Updating";
                if (Fault == "original-foreign-topic") copy["properties"]!["topic"] = plan.VaultId + "-foreign";
                if (Fault == "original-foreign-name") copy["name"] = "foreign-subscription";
            }
            if (SelectedUpdates > 0 && role == "notification-observer-arm")
            {
                await Pause("notification-read");
                if (Fault == "foreign-label") copy["properties"]!["labels"] = new JsonArray("foreign");
                if (Fault == "missing-label") copy["properties"]!.AsObject().Remove("labels");
                if (Fault == "foreign-topic") copy["properties"]!["topic"] = plan.VaultId + "-foreign";
                if (Fault == "hidden-configuration")
                    copy["properties"]!["destination"]!["properties"]!.AsObject().Remove("deliveryAttributeMappings");
                if (Fault == "configuration") copy["properties"]!["filter"]!["includedEventTypes"] = new JsonArray("Microsoft.KeyVault.SecretNearExpiry");
                if (Fault == "absent") return Reply(404, """{"error":{"code":"NotFound"}}""");
                if (Fault == "malformed") return Reply(200, "{");
                if (Fault == "failed") copy["properties"]!["provisioningState"] = "Failed";
                if (Fault == "nonterminal") copy["properties"]!["provisioningState"] = "Updating";
            }
            var readback = Reply(200, copy.ToJsonString());
            if (Barrier == "notification-read-body" && role == "notification-observer-arm")
                await Body(readback, "notification-read-body");
            if (Barrier == "notification-status-body" && role == "selected-arm")
                await Body(readback, "notification-status-body");
            if (Barrier == "notification-setup-status-body" && role == "notification-setup-arm")
                await Body(readback, "notification-setup-status-body");
            return readback;
        }
        private async Task Body(HttpResponseMessage response, string barrier)
        {
            byte[] bytes = await response.Content.ReadAsByteArrayAsync();
            response.Content.Dispose();
            response.Content = new StreamContent(new PurgeBody(bytes, this, barrier));
            response.Content.Headers.ContentType = new("application/json");
        }
        internal async Task Pause(string barrier)
        {
            if (Barrier != barrier) return;
            Entered.TrySetResult();
            await Resume.Task;
        }
        private static HttpResponseMessage Reply(int status, string body)
        {
            var response = new HttpResponseMessage((HttpStatusCode)status)
            { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            response.Headers.Add("x-ms-request-id", "native-purge-" + Guid.NewGuid().ToString("N"));
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
                    PrivateEndpoint?.Dispose();
                    foreach (var client in clients) client.Dispose();
                    capability.Dispose();
                    notificationBaseline.Dispose();
                    Native.Dispose();
                }
            }
        }
    }
    private sealed class PurgeBody(byte[] bytes, PurgeServiceFixture fixture, string barrier) : MemoryStream(bytes)
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await fixture.Pause(barrier);
            return await base.ReadAsync(buffer, cancellationToken);
        }
    }
    private sealed class PurgeCredential(string role, PurgeServiceFixture fixture) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            if (requestContext.Scopes.Single() != "https://management.azure.com/.default") throw new InvalidOperationException("foreign-audience");
            await fixture.Pause(role == "selected-arm" ? "selected-credential" : "status-credential");
            cancellationToken.ThrowIfCancellationRequested();
            return new(role, DateTimeOffset.MaxValue);
        }
    }
    private sealed class PurgeSdkSeam(HttpPipelineTransport inner, PurgeServiceFixture fixture) : HttpPipelineTransport
    {
        private int calls;
        public override Request CreateRequest() => fixture.StatusCaptureBypass
            ? fixture.SelectedBackend.CreateRequest() : inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            if (fixture.StatusCaptureBypass) await fixture.SelectedBackend.ProcessAsync(message);
            else await inner.ProcessAsync(message);
            if (++calls == fixture.NotificationParserReplacementStage)
            {
                fixture.NotificationParserReplacements++;
                var row = fixture.NotificationRow!.DeepClone();
                if (calls == 1) row["properties"]!["provisioningState"] = "Updating";
                byte[] bytes = Encoding.UTF8.GetBytes(row.ToJsonString());
                if (fixture.NotificationParserReplacement == "response")
                    message.Response = new OwnedArmResponse(message.Response.Status,
                        message.Response.ReasonPhrase, message.Response.ClientRequestId,
                        message.Response.Headers.ToArray(), new MemoryStream(bytes, false));
                else message.Response.ContentStream = fixture.NotificationParserReplacement == "stream"
                    ? new MemoryStream(bytes, false) : null;
            }
            await fixture.Pause("selected-sdk");
        }
    }
}
