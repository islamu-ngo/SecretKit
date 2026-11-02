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
using CreateService = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationFixtureObserverService;
using V = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    public static IEnumerable<(string Variant, string Boundary)> RemainingOriginalCreateConfigurations()
    {
        foreach (string variant in V.ConfigurationVariants.Where(v => v != "publicNetworkAccess.true"))
            foreach (string boundary in new[]
            {
                "selected-contract", "independent-effect", "denied-authority",
                "cancellation-boundary", "lost-response-no-replay"
            })
                yield return (variant, boundary);
    }

    [Test]
    [MethodDataSource(nameof(RemainingOriginalCreateConfigurations))]
    public async Task OriginalVaultCreateRemainingConfigurationsUseExactNativeEffect(string variant, string boundary)
    {
        await using var f = new OriginalVaultCreateOrUpdateFixture(boundary, variant);
        var result = await f.RunOriginal();
        bool uncertain = boundary is "cancellation-boundary" or "lost-response-no-replay";
        bool denied = boundary == "denied-authority";
        bool protectedConfiguration = denied ? f.Baseline.PurgeProtection : f.Selected.PurgeProtection;
        bool incomplete = uncertain || protectedConfiguration;
        await Assert.That(result.Passed).IsEqualTo(!incomplete);
        if (incomplete) await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(f.SelectedPuts).IsEqualTo(1);
        await Assert.That(f.SetupPuts).IsEqualTo(1);
        await Assert.That(f.SelectedPolls).IsEqualTo(denied || uncertain ? 0 : 1);
        await Assert.That(f.SelectedFinals).IsEqualTo(denied || uncertain ? 0 : 1);
        await Assert.That(f.StatusReads).IsEqualTo(denied || uncertain ? 0 : 1);
        await Assert.That(f.Tap.Completions).IsEqualTo(denied || uncertain ? 0 : 1);
        await Assert.That(f.CleanupDeletes).IsEqualTo(uncertain ? 0 : 1);
        await Assert.That(f.CleanupPurges).IsEqualTo(incomplete ? 0 : 1);
        await Assert.That(f.Native.Read().Released).IsEqualTo(!incomplete);
        await Assert.That(f.SecretRequests).IsEqualTo(0);
        await Assert.That(f.Prejournaled && f.Native.Wire.Prejournaled).IsTrue();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(3);
        if (!denied)
        {
            await Assert.That(f.SelectedBody!.ContainsKey("tags")).IsFalse();
            var properties = f.SelectedBody["properties"]!;
            await Assert.That(properties["enablePurgeProtection"]!.GetValue<bool>()).IsEqualTo(f.Selected.PurgeProtection);
            await Assert.That(properties["enableRbacAuthorization"]!.GetValue<bool>()).IsEqualTo(f.Selected.Rbac);
            await Assert.That(properties["publicNetworkAccess"]!.GetValue<string>())
                .IsEqualTo(f.Selected.PublicNetworkAccess ? "Enabled" : "Disabled");
            await Assert.That(properties["sku"]!["name"]!.GetValue<string>())
                .IsEqualTo(f.Selected.Sku == VaultSku.Standard ? "standard" : "premium");
        }
        if (!uncertain)
            await Assert.That(f.Tap.Receipt!.Evidence).IsEqualTo(denied ? DispatchEvidence.Rejected : DispatchEvidence.Pending);
    }

    [Test]
    public async Task OriginalVaultCreateGenericAndCounterfeitCertificatesCannotClearActualDispatch()
    {
        await using var f = new OriginalVaultCreateOrUpdateFixture();
        var lease = await f.PrepareAndBaseline();
        await Assert.That(() => f.Native.Journal.BeginCreateOrUpdateVaultInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new CreateService.CreateOrUpdateVaultAdmission(f.Source))).Throws<InvalidOperationException>();
        await f.Start(lease);
        var row = f.Native.Read().Resources.Single(r => r.Id == f.Native.Wire.VaultId);
        await Assert.That(row.ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(() => f.Native.Journal.EndCreateOrUpdateVaultInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new CreateService.CreateOrUpdateVaultTermination(f.Source, row.ActiveDispatch)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.RegisterCreateOrUpdateVaultSettlement(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new CreateService.CreateOrUpdateVaultSettlement(f.Source, row.ActiveDispatch)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleCreateOrUpdateVaultInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new CreateService.CreateOrUpdateVaultSettlement(f.Source, row.ActiveDispatch)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch, nativeSettled: false))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        f.Native.Journal.Close(Owner, f.Native.Selector);
        await Assert.That(() => f.Native.Journal.RecordAbsence(Owner, f.Native.Selector, row.Id))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == row.Id).ActiveDispatch).IsEqualTo(row.ActiveDispatch);
        await Assert.That(f.CleanupDeletes + f.CleanupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("unresolved")]
    [Arguments("updated")]
    [Arguments("denied")]
    [Arguments("protected")]
    public async Task OriginalVaultCreateRestartUsesDispositionWithoutReconstructingProof(string state)
    {
        bool denied = state == "denied";
        await using var f = new OriginalVaultCreateOrUpdateFixture(denied ? "denied-authority" : "selected-contract",
            protectedConfiguration: state == "protected");
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease, denied);
        if (state != "unresolved")
        {
            await f.Post(lease);
            if (!denied)
                await f.Source.CompleteCreateOrUpdateVaultAsync(f.Native.Selector, started.Value!, default);
        }
        await using var parent = f.CleanupParent();
        await using var restarted = f.CleanupSource(parent);
        using var observer = f.ObserverFor(restarted);
        var released = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default);
        bool complete = state is "updated" or "denied";
        if (complete) RoleFixtureRelease.Validate(released, f.Native.Selector, lease.Facts);
        await Assert.That(f.Native.Read().Released).IsEqualTo(complete);
        await Assert.That(f.SelectedPuts).IsEqualTo(1);
        await Assert.That(f.CleanupDeletes).IsEqualTo(state == "unresolved" ? 0 : 1);
        await Assert.That(f.CleanupPurges).IsEqualTo(complete ? 1 : 0);
        await Assert.That(f.SelectedPolls).IsEqualTo(state is "updated" or "protected" ? 1 : 0);
        await Assert.That(f.SelectedFinals).IsEqualTo(state is "updated" or "protected" ? 1 : 0);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalVaultCreateJoinsActualConfigurationAndRetainedHandle(string boundary)
    {
        await using var f = new OriginalVaultCreateOrUpdateFixture(boundary);
        var result = await f.RunOriginal();
        bool uncertain = boundary is "cancellation-boundary" or "lost-response-no-replay";
        bool denied = boundary == "denied-authority";
        await Assert.That(result.Passed).IsEqualTo(!uncertain);
        if (uncertain) await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(f.SelectedPuts).IsEqualTo(1);
        await Assert.That(f.SetupPuts).IsEqualTo(1);
        await Assert.That(f.StatusReads).IsEqualTo(denied || uncertain ? 0 : 1);
        await Assert.That(f.SelectedPolls).IsEqualTo(denied || uncertain ? 0 : 1);
        await Assert.That(f.SelectedFinals).IsEqualTo(denied || uncertain ? 0 : 1);
        await Assert.That(f.Tap.Completions).IsEqualTo(denied || uncertain ? 0 : 1);
        await Assert.That(f.CleanupDeletes).IsEqualTo(uncertain ? 0 : 1);
        await Assert.That(f.CleanupPurges).IsEqualTo(uncertain ? 0 : 1);
        await Assert.That(f.SecretRequests).IsEqualTo(0);
        await Assert.That(f.Prejournaled && f.Native.Wire.Prejournaled).IsTrue();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(3);
        await Assert.That(f.Native.Read().Released).IsEqualTo(!uncertain);
        if (!uncertain)
            await Assert.That(f.Tap.Receipt!.Evidence).IsEqualTo(denied ? DispatchEvidence.Rejected : DispatchEvidence.Pending);
        if (!denied)
        {
            await Assert.That(f.SelectedBody!.ContainsKey("tags")).IsFalse();
            await Assert.That(f.SelectedBody["properties"]!["publicNetworkAccess"]!.GetValue<string>()).IsEqualTo("Enabled");
        }
        if (uncertain)
            await Assert.That(f.Native.Read().Resources.Any(row => row.ActiveDispatch != Guid.Empty)).IsTrue();
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
    [Arguments("no-target")]
    [Arguments("foreign-target")]
    [Arguments("exception-denial")]
    [Arguments("poll-denied")]
    [Arguments("poll-malformed")]
    [Arguments("final-lost")]
    [Arguments("final-malformed")]
    [Arguments("unchanged")]
    [Arguments("missing-owner")]
    [Arguments("foreign-owner")]
    [Arguments("wrong-retention")]
    [Arguments("wrong-sku")]
    [Arguments("missing-child")]
    [Arguments("nonempty-child")]
    [Arguments("deleted-present")]
    public async Task OriginalVaultCreateRejectsMissingNativeConjunction(string fault)
    {
        await using var f = new OriginalVaultCreateOrUpdateFixture { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedPuts).IsEqualTo(1);
        await Assert.That(f.CleanupDeletes + f.CleanupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("publicNetworkAccess.true")]
    [Arguments("publicNetworkAccess.false")]
    [Arguments("accessPolicies.selected")]
    public async Task OriginalVaultCreatePostDoesNotCompleteOrReleaseOriginalHandle(string variant)
    {
        await using var f = new OriginalVaultCreateOrUpdateFixture(variant: variant);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await Assert.That(started.IsSuccess).IsTrue();
        await f.Post(lease);
        await Assert.That(started.Value!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.SelectedPolls + f.SelectedFinals).IsEqualTo(0);
        await Assert.That(f.Native.Read().Idle).IsFalse();
        await Assert.That(await f.Source.CompleteCreateOrUpdateVaultAsync(f.Native.Selector, started.Value!, default))
            .IsEqualTo(SecretStatus.Success);
        int reads = f.ParentReads;
        await f.Post(lease);
        await Assert.That(f.ParentReads).IsEqualTo(reads);
        await Assert.That(f.SelectedPolls).IsEqualTo(1);
        await Assert.That(f.SelectedFinals).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedPuts).IsEqualTo(1);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("denied-authority")]
    public async Task OriginalVaultCreateRetainsInheritedProtectionOnNetworkVariant(string boundary)
    {
        await using var f = new OriginalVaultCreateOrUpdateFixture(boundary, protectedConfiguration: true);
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(f.CleanupDeletes).IsEqualTo(1);
        await Assert.That(f.CleanupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Wire.Active).IsFalse();
        await Assert.That(f.Native.Wire.Deleted).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("no-effect")]
    [Arguments("protection-downgrade")]
    [Arguments("wrong-tenant")]
    [Arguments("wrong-location")]
    [Arguments("wrong-retention")]
    [Arguments("wrong-selected-variant")]
    [Arguments("empty-selected-policy")]
    public async Task OriginalVaultCreateRejectsInvalidTrustedConfigurationPairs(string fault)
    {
        await using var f = new OriginalVaultCreateOrUpdateFixture();
        var baseline = f.Baseline;
        var selected = f.Selected;
        string variant = f.Native.Selector.Variant;
        switch (fault)
        {
            case "no-effect": baseline = selected; break;
            case "protection-downgrade": baseline = baseline with { PurgeProtection = true }; break;
            case "wrong-tenant": selected = selected with { TenantId = Guid.NewGuid() }; break;
            case "wrong-location": selected = selected with { Location = "westus" }; break;
            case "wrong-retention": selected = selected with { RetentionDays = 24 }; break;
            case "wrong-selected-variant": variant = "publicNetworkAccess.false"; break;
            case "empty-selected-policy":
                variant = "authorization.access-policy";
                selected = selected with { Rbac = false, Policies = [] };
                break;
        }
        await Assert.That(VaultFixtureProvisioner.ValidCreateVaultConfigurations(variant, baseline, selected)).IsFalse();
        await Assert.That(f.SetupPuts + f.SelectedPuts + f.CleanupDeletes + f.CleanupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("retry")]
    [Arguments("close")]
    [Arguments("dispose")]
    public async Task OriginalVaultCreatePersistsDrainedDecisionWithoutProviderReplay(string mode)
    {
        await using var f = new OriginalVaultCreateOrUpdateFixture();
        var lease = await f.PrepareAndBaseline();
        f.LockOnFinalization = true;
        var started = await f.Start(lease);
        await f.Post(lease);
        await Assert.That(f.JournalLock).IsNull();
        Exception? failure = null;
        try { await f.Source.CompleteCreateOrUpdateVaultAsync(f.Native.Selector, started.Value!, default); }
        catch (Exception exception) { failure = exception; }
        try
        {
            await Assert.That(failure).IsNotNull();
            await Assert.That(f.JournalLock).IsNotNull();
            await Assert.That(f.Native.Wire.Active).IsTrue();
        }
        finally { f.UnlockJournal(); }
        int reads = f.ParentReads;
        if (mode == "retry")
        {
            await Assert.That(await f.Source.CompleteCreateOrUpdateVaultAsync(f.Native.Selector, started.Value!, default))
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
            await Assert.That(f.Native.Read().Resources.Any(row => row.ActiveDispatch != Guid.Empty)).IsTrue();
            await Assert.That(f.ParentReads).IsEqualTo(reads);
            await Assert.That(f.CleanupDeletes + f.CleanupPurges).IsEqualTo(0);
        }
        await Assert.That(f.SelectedPuts).IsEqualTo(1);
        await Assert.That(f.SelectedPolls).IsEqualTo(1);
        await Assert.That(f.SelectedFinals).IsEqualTo(1);
    }

    [Test]
    public async Task OriginalVaultCreateCannotAdoptGenericSelectorCoordinates()
    {
        await using var f = new OriginalVaultCreateOrUpdateFixture();
        _ = f.Native.Plan();
        await Assert.That(f.Native.Read().CreateOrUpdateVault).IsNull();
        await Assert.That(async () => await f.Release()).Throws<NativeCaseFailureException>();
        await Assert.That(f.SetupPuts + f.SelectedPuts + f.CleanupDeletes + f.CleanupPurges).IsEqualTo(0);
        await Assert.That(f.Native.Writes).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("sku.Standard")]
    [Arguments("sku.Premium")]
    [Arguments("authorization.rbac")]
    [Arguments("authorization.access-policy")]
    [Arguments("purgeProtection.false")]
    [Arguments("purgeProtection.true")]
    [Arguments("publicNetworkAccess.false")]
    [Arguments("accessPolicies.empty")]
    [Arguments("accessPolicies.selected")]
    [Arguments("lro.started")]
    [Arguments("lro.completed")]
    public async Task OriginalVaultCreateFirstSliceRejectsOtherConfigurationsBeforeWork(string variant)
    {
        await using var f = new OriginalVaultCreateOrUpdateFixture();
        f.Native.Selector = f.Native.Selector with { Variant = variant };
        bool accepted = false;
        try { await f.PrepareAndBaseline(); accepted = true; }
        catch (Exception ex) when (ex is NativeCaseFailureException or InvalidOperationException) { }
        await Assert.That(accepted).IsFalse();
        await Assert.That(f.SetupPuts + f.SelectedPuts + f.CleanupDeletes + f.CleanupPurges).IsEqualTo(0);
    }

    [Test]
    public async Task OriginalVaultCreateCloseBeforeCompletionKeepsSelectedDispatchFenced()
    {
        await using var f = new OriginalVaultCreateOrUpdateFixture();
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Post(lease);
        await f.Release();
        await Assert.That(async () => await f.Source.CompleteCreateOrUpdateVaultAsync(
            f.Native.Selector, started.Value!, default)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
        await Assert.That(f.CleanupDeletes + f.CleanupPurges).IsEqualTo(0);
        await Assert.That(f.SelectedPolls + f.SelectedFinals).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-original", false)]
    [Arguments("selected-original", true)]
    [Arguments("selected-poll", false)]
    [Arguments("selected-poll", true)]
    [Arguments("selected-final", false)]
    [Arguments("selected-final", true)]
    public async Task OriginalVaultCreateIndependentSdkResponseCannotQualify(string channel, bool disposeOriginal)
    {
        await using var f = new OriginalVaultCreateOrUpdateFixture
        {
            ReplaceChannel = channel,
            DisposeReplacedResponse = disposeOriginal
        };
        var lease = await f.PrepareAndBaseline();
        bool accepted = false;
        try
        {
            var started = await f.Start(lease);
            await f.Post(lease);
            if (started.IsSuccess)
                await f.Source.CompleteCreateOrUpdateVaultAsync(f.Native.Selector, started.Value!, default);
            accepted = f.Native.Read().Idle;
        }
        catch (Exception ex) when (ex is NativeCaseFailureException or InvalidOperationException) { }
        await Assert.That(f.Replacements).IsEqualTo(1);
        await Assert.That(accepted).IsFalse();
        await Assert.That(f.CleanupDeletes + f.CleanupPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-original-credential")]
    [Arguments("selected-arm-transport")]
    [Arguments("selected-arm-body")]
    [Arguments("selected-original-sdk")]
    [Arguments("status-arm-transport")]
    [Arguments("status-arm-body")]
    [Arguments("read-arm-transport")]
    [Arguments("read-arm-body")]
    [Arguments("deleted-arm-body")]
    [Arguments("selected-poll-sdk")]
    [Arguments("selected-poll-body")]
    [Arguments("selected-final-sdk")]
    [Arguments("selected-final-body")]
    public async Task OriginalVaultCreateRetainsActualBorrowersAcrossClose(string barrier)
    {
        await using var f = new OriginalVaultCreateOrUpdateFixture();
        var lease = await f.PrepareAndBaseline();
        Task work;
        if (barrier.StartsWith("selected-original", StringComparison.Ordinal) || barrier.StartsWith("selected-arm", StringComparison.Ordinal))
        {
            f.Barrier = barrier;
            work = f.Start(lease);
        }
        else
        {
            var started = await f.Start(lease);
            if (barrier.StartsWith("selected-", StringComparison.Ordinal))
            {
                await f.Post(lease);
                f.Barrier = barrier;
                work = f.Source.CompleteCreateOrUpdateVaultAsync(f.Native.Selector, started.Value!, default).AsTask();
            }
            else { f.Barrier = barrier; work = f.Post(lease).AsTask(); }
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
    }

    private sealed class OriginalVaultCreateOrUpdateFixture : IAsyncDisposable
    {
        private const string Capability = "original-vault-create-controlled-capability";
        private static readonly Uri Origin = new("https://original-vault-create.invalid/");
        private static readonly string StatusPath =
            $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/operations/77777777-7777-7777-7777-777777777777";
        internal readonly Fixture Native = new(rbac: true, allowPurge: true, emptyPolicies: true);
        internal readonly V.Configuration Baseline, Selected;
        internal readonly V.Policy[] IntendedPolicies =
        [
            new(Tenant, Principal, [SecretPermission.Get, SecretPermission.Set], null),
            new(Tenant, Guid.Parse("33333333-3333-3333-3333-333333333334"), [SecretPermission.Get],
                Guid.Parse("44444444-4444-4444-4444-444444444445"))
        ];
        internal readonly VaultFixtureProvisioner Parent;
        internal readonly CreateService Source;
        internal readonly OwnedManagementObserver Observer;
        internal readonly CreateTap Tap;
        private readonly SecretMaterial capability = SecretMaterial.FromText(Capability);
        private readonly List<HttpClient> clients = [];
        private readonly Dictionary<string, Request> requests = [];
        private ObservationSubscription? subscription;
        internal string? Fault, Barrier, ReplaceChannel;
        internal bool DisposeReplacedResponse;
        internal bool LockOnFinalization;
        internal FileStream? JournalLock;
        internal int Replacements;
        internal JsonObject? SelectedBody;
        internal int SelectedPuts, SetupPuts, StatusReads, SelectedPolls, SelectedFinals;
        internal int CleanupDeletes, CleanupPurges, SecretRequests, ParentReads;
        internal bool Prejournaled = true;
        internal readonly TaskCompletionSource Entered = Signal(), Resume = Signal();
        private static VaultFixtureProvisioner.HostScope Host => new(Subscription, "fixture-group", "eastus", Tenant, true, true);
        private string DeletedId =>
            $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/{Native.Wire.VaultName}";

        internal OriginalVaultCreateOrUpdateFixture(string boundary = "selected-contract", string variant = "publicNetworkAccess.true",
            bool protectedConfiguration = false)
        {
            Native.Selector = Native.Selector with
            {
                Operation = "a.management.VaultAdministration.CreateOrUpdateVaultAsync",
                Variant = variant,
                Case = boundary
            };
            var canonical = Native.Baseline with
            { Sku = VaultSku.Standard, PublicNetworkAccess = true, PurgeProtection = protectedConfiguration };
            Selected = V.SelectConfiguration(canonical, IntendedPolicies, variant);
            Baseline = variant switch
            {
                "publicNetworkAccess.false" => Selected with { PublicNetworkAccess = true },
                "sku.Standard" => Selected with { Sku = VaultSku.Premium },
                "sku.Premium" => Selected with { Sku = VaultSku.Standard },
                "authorization.rbac" => Selected with { Rbac = false, Policies = [] },
                "authorization.access-policy" or "accessPolicies.selected" => Selected with { Rbac = true, Policies = [] },
                "accessPolicies.empty" => Selected with { Rbac = false, Policies = IntendedPolicies },
                "purgeProtection.true" => Selected with { PurgeProtection = false },
                _ => Selected with { PublicNetworkAccess = false }
            };
            Parent = VaultFixtureProvisioner.ForCreateOrUpdateVault(Native.Journal, Host,
                Native.Selector.Variant, Baseline, Selected,
                new("create-admin", new CreateCredential(this, "setup-arm"), Transport("setup-arm")),
                new("create-parent", new CreateCredential(this, "read-arm"), Transport("read-arm")),
                new(65536, TimeSpan.FromSeconds(20)));
            Source = new(Origin, Owner, "original-create-source", capability, Host,
                new CreateService.CreateOrUpdateVaultSource(Parent,
                    new("create-status", new CreateCredential(this, "status-arm"), Transport("status-arm")),
                    Transport("selected-arm"), new(65536, 8192, 512, TimeSpan.FromSeconds(20))),
                new(65536, 65536, TimeSpan.FromSeconds(20)));
            Observer = new(new(Origin, Capability, TimeSpan.FromSeconds(20)), new VaultForwarder(Source.DispatchAsync));
            Tap = new(Source);
        }
        private HttpPipelineTransport Transport(string role)
        {
            var client = new HttpClient(new VaultForwarder((request, token) => Send(request, role, token)));
            clients.Add(client);
            return new CreateSdk(new HttpClientTransport(client), this, role);
        }
        internal async Task<V.Lease> PrepareAndBaseline()
        {
            var lease = await Observer.PostAsync<V.Prepare, V.Lease>("vault/prepare",
                new(Native.Selector, Subscription, "fixture-group", Selected, IntendedPolicies, Guid.Empty), default);
            subscription = await Observer.SubscribeAsync("vault", lease.Facts, default);
            await Observer.PostAsync<ObserveLease, V.Measurement>("vault/observe",
                new(lease.Facts.LeaseId, lease.Facts.Nonce, "baseline-before-dispatch", subscription.SubscriptionId), default);
            return lease;
        }
        internal Task<SecretOutcome<ManagementOperation>> Start(V.Lease lease, bool denied = false)
        {
            var client = new VaultAdministration(new CreateCredential(this, denied ? "denied-arm" : "selected-original"),
                new CreateSdk(Source.SelectedTransport, this, "selected-original"));
            var scope = new VaultScope(new(new(Subscription), "fixture-group"), lease.VaultName);
            return Tap.RunCreateOrUpdateVaultAsync(Native.Selector, client, scope, Selected.Build(),
                client.PrepareReceipt(scope, ManagementMutation.CreateOrUpdateVault), default).AsTask();
        }
        internal ValueTask<V.Measurement> Post(V.Lease lease) => Observer.PostAsync<ObserveLease, V.Measurement>(
            "vault/observe", new(lease.Facts.LeaseId, lease.Facts.Nonce, "post-operation", subscription!.SubscriptionId), default);
        internal ValueTask<RoleFixtureRelease.Measurement> Release() =>
            Observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>("vault/release", Native.Selector, default);
        internal VaultFixtureProvisioner CleanupParent()
        {
            string directory = Path.GetDirectoryName(Native.JournalPath) ?? throw new InvalidOperationException("journal-directory");
            return VaultFixtureProvisioner.ForCleanup(new RoleFixtureJournal(directory), Host,
                new("create-cleanup-admin", new CreateCredential(this, "setup-arm"), Transport("setup-arm")),
                new("create-cleanup-parent", new CreateCredential(this, "read-arm"), Transport("read-arm")),
                new(65536, TimeSpan.FromSeconds(20)));
        }
        internal CreateService CleanupSource(VaultFixtureProvisioner parent) =>
            CreateService.ForCreateOrUpdateVaultCleanup(Origin, Owner, "original-create-cleanup", capability,
                Host, parent, new(65536, 65536, TimeSpan.FromSeconds(20)));
        internal OwnedManagementObserver ObserverFor(CreateService source) =>
            new(new(Origin, Capability, TimeSpan.FromSeconds(20)), new VaultForwarder(source.DispatchAsync));
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
                        Subscription, "fixture-group", Selected, IntendedPolicies,
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
                })), selectedTransport: Source.SelectedTransport, createSelectedInvocation: Tap);
            return (await NativeCaseRunner.RunAsync(registry, [definition], default)).Single();
        }
        private string Channel(string role, Request? request)
        {
            if (role == "read-arm" && request?.Uri.ToUri().AbsolutePath.Contains("/deletedVaults/", StringComparison.Ordinal) == true)
                return "deleted-arm";
            if (role is "selected-original" or "selected-arm" && request?.Method == RequestMethod.Get)
                return request.Uri.ToUri().AbsolutePath == StatusPath ? "selected-poll" : "selected-final";
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
            if (request.RequestUri.Host != "management.azure.com" || request.RequestUri.Query != "?api-version=2026-02-01" ||
                (role == "selected-arm" ? bearer is not ("selected-original" or "denied-arm") : bearer != role))
                throw new InvalidOperationException("unexpected-create-authority-or-route");
            string channel = role == "selected-arm" && request.Method == HttpMethod.Get
                ? path == StatusPath ? "selected-poll" : "selected-final" :
                role == "read-arm" && path.Contains("/deletedVaults/", StringComparison.Ordinal) ? "deleted-arm" : role;
            await Block(channel, "transport");
            if (role == "read-arm") ParentReads++;
            if (role == "selected-arm" && request.Method == HttpMethod.Put)
            {
                if (path != Native.Wire.VaultId) throw new InvalidOperationException("unexpected-selected-create");
                SelectedPuts++;
                Prejournaled &= Native.Read().Resources.Single(row => row.Id == path).ActiveDispatch != Guid.Empty;
                if (Fault == "exception-denial") throw new Azure.RequestFailedException(403, "controlled-no-response");
                if (bearer == "denied-arm") return Reply(403, """{"error":{"code":"Forbidden"}}""");
                SelectedBody = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
                if (Fault != "unchanged")
                {
                    // Controlled native retained-tag behavior, not a claim about Azure.
                    var tags = Native.Wire.Vault!["tags"]!.DeepClone();
                    Native.Wire.Vault = SelectedBody.DeepClone().AsObject();
                    Native.Wire.Vault["tags"] = tags;
                    Native.Wire.Vault["id"] = path;
                    Native.Wire.Vault["name"] = Native.Wire.VaultName;
                    Native.Wire.Vault["type"] = "Microsoft.KeyVault/vaults";
                    Native.Wire.Vault["properties"]!["vaultUri"] = $"https://{Native.Wire.VaultName}.vault.azure.net";
                    Native.Wire.Vault["properties"]!["provisioningState"] = "Succeeded";
                    Native.Wire.Vault["properties"]!["privateEndpointConnections"] = new JsonArray();
                }
                Native.Wire.Deleted = Fault == "deleted-present";
                var payload = Native.Wire.Vault!.DeepClone();
                payload["properties"]!["provisioningState"] = "Updating";
                var response = Reply(Fault == "synchronous" ? 200 : 201,
                    Fault == "selected-malformed" ? "{" : payload.ToJsonString());
                if (Fault is not ("no-target" or "synchronous"))
                    response.Headers.Add("Azure-AsyncOperation",
                        (Fault == "foreign-target" ? "https://foreign.invalid" : "https://management.azure.com") +
                        StatusPath + "?api-version=2026-02-01");
                return await Body(response, channel);
            }
            if (role == "status-arm" || role == "selected-arm" && request.Method == HttpMethod.Get && path == StatusPath)
            {
                if (request.Method != HttpMethod.Get || path != StatusPath) throw new InvalidOperationException("unexpected-create-status");
                if (role == "status-arm") StatusReads++; else SelectedPolls++;
                string stage = role == "status-arm" ? "status" : "poll";
                if (Fault == stage + "-denied") return Reply(403, """{"error":{"code":"Forbidden"}}""");
                if (Fault == stage + "-malformed") return Reply(200, "{");
                string state = role == "status-arm" ? Fault switch
                {
                    "pending" => "InProgress", "failed" => "Failed", "canceled" => "Canceled",
                    "unknown" => "future-state", _ => "Succeeded"
                } : "Succeeded";
                return await Body(Reply(200, JsonSerializer.Serialize(new
                {
                    id = StatusPath,
                    name = StatusPath[(StatusPath.LastIndexOf('/') + 1)..],
                    status = state
                })), channel);
            }
            if (role == "selected-arm")
            {
                if (request.Method != HttpMethod.Get || path != Native.Wire.VaultId)
                    throw new InvalidOperationException("unexpected-create-final");
                SelectedFinals++;
                if (Fault == "final-lost") throw new IOException("controlled-final-loss");
                return await Body(Reply(200, Fault == "final-malformed" ? "{" : Native.Wire.Vault!.ToJsonString()), channel);
            }
            if (role == "setup-arm")
            {
                if (request.Method == HttpMethod.Put) SetupPuts++;
                if (request.Method == HttpMethod.Delete) CleanupDeletes++;
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
                    if (Fault == "wrong-sku") row["properties"]!["sku"]!["name"] = "premium";
                    if (Fault == "missing-child") row["properties"]!.AsObject().Remove("privateEndpointConnections");
                    if (Fault == "nonempty-child")
                        row["properties"]!["privateEndpointConnections"] = new JsonArray(new JsonObject { ["id"] = path + "/privateEndpointConnections/foreign" });
                }
                return await Body(Reply(200, row.ToJsonString()), channel);
            }
            if (request.Method == HttpMethod.Get && path == DeletedId && Native.Wire.Deleted)
                return Reply(200, JsonSerializer.Serialize(new
                {
                    id = path, name = Native.Wire.VaultName, type = "Microsoft.KeyVault/locations/deletedVaults",
                    properties = new
                    {
                        vaultId = Native.Wire.VaultId, location = "eastus", tags = Native.Wire.Vault!["tags"],
                        purgeProtectionEnabled = Native.Wire.Vault!["properties"]!["enablePurgeProtection"]!.GetValue<bool>(),
                        deletionDate = "2026-10-16T00:00:00Z", scheduledPurgeDate = "2026-11-08T00:00:00Z"
                    }
                }));
            var native = await Native.Wire.Respond(request, role, token);
            if (Native.Wire.Vault is not null)
                Native.Wire.Vault["properties"]!["privateEndpointConnections"] = new JsonArray();
            return await Body(native, channel);
        }
        private async ValueTask<HttpResponseMessage> Body(HttpResponseMessage response, string channel)
        {
            if (Barrier != channel + "-body") return response;
            var original = response.Content;
            response.Content = new StreamContent(new CreateBody(await original.ReadAsByteArrayAsync(), this, channel));
            response.Content.Headers.ContentType = new("application/json");
            original.Dispose();
            return response;
        }
        private static HttpResponseMessage Reply(int status, string body) => new((HttpStatusCode)status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
            Headers = { { "x-ms-request-id", "controlled-original-create-" + Guid.NewGuid().ToString("N") } }
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
        internal sealed class CreateTap(CreateService source) : V.CreateSelectedInvocation
        {
            internal ManagementReceipt? Receipt;
            internal int Completions;
            public ValueTask<SecretOutcome<ManagementOperation>> RunCreateOrUpdateVaultAsync(FixtureSelector selector,
                VaultAdministration client, VaultScope scope, VaultConfiguration configuration, ManagementReceipt receipt,
                CancellationToken token)
            {
                Receipt = receipt;
                return source.RunCreateOrUpdateVaultAsync(selector, client, scope, configuration, receipt, token);
            }
            public ValueTask<SecretStatus> CompleteCreateOrUpdateVaultAsync(FixtureSelector selector,
                ManagementOperation handle, CancellationToken token)
            {
                Completions++;
                return source.CompleteCreateOrUpdateVaultAsync(selector, handle, token);
            }
        }
        private sealed class CreateCredential(OriginalVaultCreateOrUpdateFixture fixture, string role) : TokenCredential
        {
            public override AccessToken GetToken(TokenRequestContext context, CancellationToken token) =>
                throw new InvalidOperationException("async-only");
            public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken token)
            {
                fixture.requests.TryGetValue(role, out var request);
                await fixture.Block(fixture.Channel(role, request), "credential");
                token.ThrowIfCancellationRequested();
                return new(role, DateTimeOffset.MaxValue);
            }
        }
        private sealed class CreateSdk(HttpPipelineTransport inner, OriginalVaultCreateOrUpdateFixture fixture, string role)
            : HttpPipelineTransport
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
                if (role == "selected-arm" && message.Request.Method == RequestMethod.Put && fixture.LockOnFinalization)
                    message.Response = new CreateFinalizeResponse(message.Response, fixture);
                if (role == "selected-original" && channel == fixture.ReplaceChannel)
                {
                    fixture.Replacements++;
                    var headers = message.Response.Headers.ToArray();
                    int status = message.Response.Status;
                    string body;
                    if (channel == "selected-poll") body = """{"status":"Succeeded"}""";
                    else
                    {
                        var row = fixture.Native.Wire.Vault!.DeepClone();
                        if (channel == "selected-original") row["properties"]!["provisioningState"] = "Updating";
                        body = row.ToJsonString();
                    }
                    if (fixture.DisposeReplacedResponse) message.Response.Dispose();
                    message.Response = new CreateIndependentResponse(status, body, headers);
                }
                if (message.Request.Headers.Contains("Authorization")) await fixture.Block(channel, "sdk");
            }
        }
        private sealed class CreateBody(byte[] bytes, OriginalVaultCreateOrUpdateFixture fixture, string channel) : MemoryStream(bytes)
        {
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                await fixture.Block(channel, "body");
                return await base.ReadAsync(buffer, cancellationToken);
            }
        }
        private sealed class CreateFinalizeResponse(Response original, OriginalVaultCreateOrUpdateFixture fixture) : Response
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
        private sealed class CreateIndependentResponse(int status, string body, HttpHeader[] headers) : Response
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
