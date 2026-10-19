using System.Net;
using System.Text;
using System.Text.Json;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using Provisioner = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureProvisioner;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments("selected-contract", false)]
    [Arguments("independent-effect", false)]
    [Arguments("selected-contract", true)]
    [Arguments("independent-effect", true)]
    public async Task SettledSelectedDeletePurgesOnlyAfterFreshActiveAbsence(string boundary, bool restart)
    {
        using var f = new Fixture(allowPurge: true);
        SelectDeleteCleanup(f, boundary);
        var plan = f.Plan(seedCanary: false);
        await Assert.That((await f.Source.ProvisionAsync(plan)).State).IsEqualTo(Provisioner.State.Ready);
        await DispatchCleanupSelectedDelete(f, plan);
        int reads = f.Backends[2].Requests.Count;
        var beforeMutation = f.Wire.BeforeMutation;
        bool freshAbsenceBeforePurge = false;
        f.Wire.BeforeMutation = path =>
        {
            beforeMutation(path);
            freshAbsenceBeforePurge = path == plan.DeletedId + "/purge" && !f.Wire.Active &&
                f.Backends[2].Requests.Skip(reads).Any(r => r.Method == HttpMethod.Get && r.Path == plan.VaultId);
        };
        await using var cleanup = f.Cleanup();
        var source = restart ? cleanup : f.Source;
        var restored = source.OpenCleanupPlan(Owner, f.Selector);
        if (restart)
        {
            await Assert.That(restored.Restored).IsTrue();
            await Assert.That(restored.Receipts.Count).IsEqualTo(0);
            await Assert.That(restored.CanarySha256).IsNull();
        }
        var result = await source.ReleaseAsync(Owner, f.Selector, purge: true, requireActiveVaultAbsent: true);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Released);
        await Assert.That(result.Journal.Resources.Length).IsEqualTo(3);
        await Assert.That(result.Journal.Resources.All(r => r.Absent && r.ActiveDispatch == Guid.Empty)).IsTrue();
        await Assert.That(result.Journal.Resources.Single(r => r.Id == plan.VaultId).DeleteAttempted).IsFalse();
        await Assert.That(result.Journal.Resources.Single(r => r.Id == plan.DeletedId).DeleteAttempted).IsTrue();
        await Assert.That(freshAbsenceBeforePurge && f.Wire.Prejournaled).IsTrue();
        await Assert.That(f.Wire.Active || f.Wire.Deleted).IsFalse();
        await Assert.That(f.Backends[0].Requests.Any(r => r.Method == HttpMethod.Delete)).IsFalse();
        await Assert.That(f.Backends[0].Requests.Count(r => r.Method == HttpMethod.Post)).IsEqualTo(1);
        // Releasing the same original root again observes only; purge is never replayed.
        await Assert.That((await source.ReleaseAsync(Owner, f.Selector, purge: true,
            requireActiveVaultAbsent: true)).State).IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Backends[0].Requests.Count(r => r.Method == HttpMethod.Post)).IsEqualTo(1);
    }

    [Test]
    [Arguments("unprepared")]
    [Arguments("unselected")]
    [Arguments("absent")]
    [Arguments("deleted")]
    [Arguments("selected-deleted")]
    [Arguments("canary")]
    [Arguments("borrowed")]
    [Arguments("policy-child")]
    [Arguments("notification")]
    [Arguments("cleanup-delete")]
    public async Task SelectedDeleteCombinedCleanupRejectsOtherSourceHistories(string history)
    {
        using var f = new Fixture(allowPurge: true);
        SelectDeleteCleanup(f);
        using var material = SecretMaterial.FromText(Material);
        var plan = f.Plan(history == "absent" ? Provisioner.Preparation.Absent :
            history is "deleted" or "selected-deleted" ? Provisioner.Preparation.Deleted : Provisioner.Preparation.Active,
            seedCanary: history == "canary",
            borrowed: history == "borrowed" ? [Group + "/providers/Microsoft.Network/privateEndpoints/borrowed"] : [],
            children: history == "policy-child" ? [new("policy-child", Provisioner.Preparation.Active, material)] : [],
            notifications: history == "notification" ? ["notification-child"] : []);
        if (history != "unprepared")
            await Assert.That((await f.Source.ProvisionAsync(plan, material)).State).IsEqualTo(Provisioner.State.Ready);
        if (history is not ("unprepared" or "unselected" or "absent" or "deleted" or "selected-deleted"))
            await DispatchCleanupSelectedDelete(f, plan);
        if (history == "selected-deleted")
        {
            Guid dispatch = f.Journal.BeginSelectedDispatch(Owner, f.Selector, plan.DeletedId, delete: true);
            f.Journal.EndDispatch(Owner, f.Selector, plan.DeletedId, dispatch);
        }
        if (history == "cleanup-delete")
        {
            f.Source.CloseSelectedRoot(Owner, f.Selector);
            Guid dispatch = f.Journal.BeginDispatch(Owner, f.Selector, plan.VaultId, delete: true);
            f.Journal.EndDispatch(Owner, f.Selector, plan.VaultId, dispatch);
        }
        int requests = f.Backends.Sum(b => b.Requests.Count);
        var result = await f.Source.ReleaseAsync(Owner, f.Selector, purge: true, requireActiveVaultAbsent: true);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(result.Journal.Released).IsFalse();
        await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(requests);
        await using var cleanup = f.Cleanup();
        var restored = cleanup.OpenCleanupPlan(Owner, f.Selector);
        await Assert.That(restored.Restored).IsTrue();
        await Assert.That(restored.Receipts.Count).IsEqualTo(0);
        await Assert.That((await cleanup.ReleaseAsync(Owner, f.Selector, purge: true,
            requireActiveVaultAbsent: true)).State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(requests);
    }

    [Test]
    [Arguments("operation")]
    [Arguments("variant")]
    [Arguments("case")]
    public async Task SelectedDeleteCombinedCleanupRejectsForeignOriginalSelectors(string field)
    {
        using var f = new Fixture(allowPurge: true);
        SelectDeleteCleanup(f);
        f.Selector = field switch
        {
            "operation" => f.Selector with { Operation = "a.management.VaultAdministration.DeleteVaultAsync" },
            "variant" => f.Selector with { Variant = "operation.RecoverVault" },
            _ => f.Selector with { Case = "denied-authority" }
        };
        var plan = f.Plan(seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        await DispatchCleanupSelectedDelete(f, plan);
        int requests = f.Backends.Sum(b => b.Requests.Count);
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true,
            requireActiveVaultAbsent: true)).State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(requests);
    }

    [Test]
    public async Task SelectedDeleteCleanupRejectsSubstitutedOwnerAndSelectorBeforeReading()
    {
        using var f = new Fixture(allowPurge: true);
        SelectDeleteCleanup(f);
        var plan = f.Plan(seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        await DispatchCleanupSelectedDelete(f, plan);
        int requests = f.Backends.Sum(b => b.Requests.Count);
        await Assert.That(async () => await f.Source.ReleaseAsync("foreign-owner", f.Selector, purge: true,
            requireActiveVaultAbsent: true)).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Source.ReleaseAsync(Owner, f.Selector with { Scope = "foreign" }, purge: true,
            requireActiveVaultAbsent: true)).Throws<InvalidOperationException>();
        await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(requests);
        await Assert.That(f.Read().Closing).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SelectedPurgeCannotBorrowDeleteCleanupAuthorityOrRepurge(bool requireAbsence)
    {
        using var f = new Fixture(allowPurge: true);
        SelectDeleteCleanup(f);
        f.Selector = f.Selector with { Variant = "operation.PurgeDeletedVault" };
        var plan = f.Plan(Provisioner.Preparation.Deleted, seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        // A settled selected counterpart must never authorize another purge,
        // even when an independent read would still find that counterpart.
        Guid dispatch = f.Journal.BeginSelectedDispatch(Owner, f.Selector, plan.DeletedId, delete: true);
        f.Journal.EndDispatch(Owner, f.Selector, plan.DeletedId, dispatch);
        int requests = f.Backends.Sum(b => b.Requests.Count);
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true,
            requireActiveVaultAbsent: requireAbsence)).State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(requests);
        await Assert.That(f.Wire.Deleted).IsTrue();
        await Assert.That(f.Read().Released).IsFalse();
    }

    [Test]
    public async Task SettledSelectedDeleteDoesNotGrantHostPurgeAuthority()
    {
        using var f = new Fixture();
        SelectDeleteCleanup(f);
        var plan = f.Plan(seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        await DispatchCleanupSelectedDelete(f, plan);
        int requests = f.Backends.Sum(b => b.Requests.Count);
        await Assert.That(async () => await f.Source.ReleaseAsync(Owner, f.Selector, purge: true,
            requireActiveVaultAbsent: true)).Throws<InvalidOperationException>();
        await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(requests);
        await Assert.That(f.Read().Closing).IsFalse();
        await Assert.That(f.Wire.Deleted).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SelectedDeleteActiveResurrectionNeverRetriesDelete(bool restart)
    {
        using var f = new Fixture(allowPurge: true);
        SelectDeleteCleanup(f);
        var plan = f.Plan(seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        await DispatchCleanupSelectedDelete(f, plan);
        f.Wire.Active = true;
        f.Wire.Deleted = false;
        int writes = f.Writes;
        await using var cleanup = f.Cleanup();
        var source = restart ? cleanup : f.Source;
        await Assert.That((await source.ReleaseAsync(Owner, f.Selector, purge: true,
            requireActiveVaultAbsent: true)).State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(f.Writes).IsEqualTo(writes);
        await Assert.That(f.Wire.Active).IsTrue();
        await Assert.That(f.Read().Released).IsFalse();
        await Assert.That(f.Read().Resources.Single(r => r.Id == plan.VaultId).DeleteAttempted).IsFalse();
    }

    [Test]
    [Arguments("protected")]
    [Arguments("foreign")]
    [Arguments("denied")]
    [Arguments("oversized")]
    public async Task SelectedDeleteCleanupRetainsNativeProtectionAndOwnershipChecks(string fault)
    {
        using var f = new Fixture(allowPurge: true);
        SelectDeleteCleanup(f);
        var plan = f.Plan(seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        await DispatchCleanupSelectedDelete(f, plan);
        if (fault == "protected") f.Wire.Vault!["properties"]!["enablePurgeProtection"] = true;
        else if (fault == "foreign") f.Wire.Vault!["tags"]!["secretkit-fixture"] = Guid.NewGuid().ToString("N");
        else f.Wire.ReadFault = fault;
        int writes = f.Writes;
        var result = await f.Source.ReleaseAsync(Owner, f.Selector, purge: true, requireActiveVaultAbsent: true);
        await Assert.That(result.State).IsEqualTo(fault == "protected" ? Provisioner.State.SoftDeleted :
            fault == "denied" ? Provisioner.State.Denied : Provisioner.State.Uncertain);
        await Assert.That(f.Writes).IsEqualTo(writes);
        await Assert.That(f.Wire.Deleted).IsTrue();
        await Assert.That(result.Journal.Released).IsFalse();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    [Arguments("async")]
    [Arguments("foreign-status")]
    public async Task SelectedDeletePurgeUncertaintySurvivesCoordinateOnlyRestartWithoutReplay(string fault)
    {
        using var f = new Fixture(allowPurge: true);
        SelectDeleteCleanup(f);
        var plan = f.Plan(seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        await DispatchCleanupSelectedDelete(f, plan);
        f.Wire.PurgeFault = fault;
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true,
            requireActiveVaultAbsent: true)).State).IsEqualTo(Provisioner.State.Pending);
        Guid fence = f.Read().Resources.Single(r => r.Id == plan.DeletedId).ActiveDispatch;
        await Assert.That(fence).IsNotEqualTo(Guid.Empty);
        await Assert.That(f.Wire.Active || f.Wire.Deleted).IsFalse();
        int requests = f.Backends.Sum(b => b.Requests.Count);
        await using var cleanup = f.Cleanup();
        var restored = cleanup.OpenCleanupPlan(Owner, f.Selector);
        await Assert.That(restored.Restored).IsTrue();
        await Assert.That(restored.Receipts.Count).IsEqualTo(0);
        await Assert.That((await cleanup.SettleAsync(restored)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That((await cleanup.ReleaseAsync(Owner, f.Selector, purge: true,
            requireActiveVaultAbsent: true)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true,
            requireActiveVaultAbsent: true)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(requests);
        await Assert.That(f.Read().Resources.Single(r => r.Id == plan.DeletedId).ActiveDispatch).IsEqualTo(fence);
        await Assert.That(f.Read().Released).IsFalse();
        await Assert.That(f.Backends[0].Requests.Count(r => r.Method == HttpMethod.Post)).IsEqualTo(1);
        await Assert.That(f.Backends[0].Requests.Any(r => r.Method == HttpMethod.Delete)).IsFalse();
    }

    [Test]
    public async Task CachedActualDeleteWrapperAndAbsenceCannotSettleSelectedCleanupFence()
    {
        using var f = new Fixture(allowPurge: true);
        SelectDeleteCleanup(f);
        var plan = f.Plan(seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        await DispatchCleanupSelectedDelete(f, plan, settle: false);
        Guid fence = f.Read().Resources.Single(r => r.Id == plan.VaultId).ActiveDispatch;
        int requests = f.Backends.Sum(b => b.Requests.Count);
        await using var cleanup = f.Cleanup();
        var restored = cleanup.OpenCleanupPlan(Owner, f.Selector);
        await Assert.That(restored.Receipts.Count).IsEqualTo(0);
        await Assert.That((await cleanup.SettleAsync(restored)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That((await cleanup.ReleaseAsync(Owner, f.Selector, purge: true,
            requireActiveVaultAbsent: true)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true,
            requireActiveVaultAbsent: true)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(requests);
        await Assert.That(f.Read().Resources.Single(r => r.Id == plan.VaultId).ActiveDispatch).IsEqualTo(fence);
        await Assert.That(f.Read().Released).IsFalse();
        await Assert.That(f.Wire.Active).IsFalse();
        await Assert.That(f.Wire.Deleted).IsTrue();
    }

    [Test]
    public async Task SelectedDeleteCleanupRefreshesClosedRootBeforeAnyNativeRead()
    {
        using var f = new Fixture(allowPurge: true);
        SelectDeleteCleanup(f);
        var plan = f.Plan(seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        await DispatchCleanupSelectedDelete(f, plan);
        Guid fence = Guid.Empty;
        await using var cleanup = f.Reopen(time: new CleanupAdmissionTime(() =>
            fence = f.Journal.BeginDispatch(Owner, f.Selector, plan.DeletedId, delete: true)));
        int requests = f.Backends.Sum(b => b.Requests.Count);
        await Assert.That((await cleanup.ReleaseAsync(Owner, f.Selector, purge: true,
            requireActiveVaultAbsent: true)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(fence).IsNotEqualTo(Guid.Empty);
        await Assert.That(f.Read().Resources.Single(r => r.Id == plan.DeletedId).ActiveDispatch).IsEqualTo(fence);
        await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(requests);
        await Assert.That(f.Wire.Deleted).IsTrue();
    }

    [Test]
    public async Task SelectedDeleteCleanupRechecksConcurrentFenceAtNativePurgeAdmission()
    {
        using var f = new Fixture(allowPurge: true);
        SelectDeleteCleanup(f);
        var plan = f.Plan(seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        await DispatchCleanupSelectedDelete(f, plan);
        Guid fence = Guid.Empty;
        f.BeforeSetupCredential(() =>
            fence = f.Journal.BeginDispatch(Owner, f.Selector, plan.DeletedId, delete: true));
        int writes = f.Writes;
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true,
            requireActiveVaultAbsent: true)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(fence).IsNotEqualTo(Guid.Empty);
        await Assert.That(f.Read().Resources.Single(r => r.Id == plan.DeletedId).ActiveDispatch).IsEqualTo(fence);
        await Assert.That(f.Writes).IsEqualTo(writes);
        await Assert.That(f.Wire.Deleted).IsTrue();
        await Assert.That(f.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("operation.DeleteVault")]
    [Arguments("operation.PurgeDeletedVault")]
    public async Task BeforeSelectionOrdinaryAuthorizedCleanupRemainsAvailable(string variant)
    {
        using var f = new Fixture(allowPurge: true);
        SelectDeleteCleanup(f);
        f.Selector = f.Selector with { Variant = variant };
        var plan = f.Plan(variant == "operation.DeleteVault" ? Provisioner.Preparation.Active :
            Provisioner.Preparation.Deleted, seedCanary: false);
        await f.Source.ProvisionAsync(plan);
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true)).State)
            .IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Read().Resources.All(r => !r.SelectedAttempted)).IsTrue();
        await Assert.That(f.Backends[0].Requests.Count(r => r.Method == HttpMethod.Delete)).IsEqualTo(1);
        await Assert.That(f.Backends[0].Requests.Count(r => r.Method == HttpMethod.Post)).IsEqualTo(1);
    }

    private static void SelectDeleteCleanup(Fixture fixture, string boundary = "selected-contract") =>
        fixture.Selector = fixture.Selector with
        {
            Operation = "a.management.ManagementOperation.CheckStatusAsync",
            Variant = "operation.DeleteVault",
            Case = boundary
        };

    private static async Task DispatchCleanupSelectedDelete(Fixture fixture, Provisioner.Plan plan, bool settle = true)
    {
        Guid dispatch = fixture.Journal.BeginSelectedDispatch(Owner, fixture.Selector, plan.VaultId, delete: true);
        string statusPath = $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/operationResults/44444444-4444-4444-4444-444444444444";
        int selectedDeletes = 0, selectedStatusReads = 0;
        using var http = new HttpClient(new VaultForwarder(async (request, token) =>
        {
            if (request.Method == HttpMethod.Get) selectedStatusReads++;
            if (request.Method != HttpMethod.Delete || request.RequestUri!.AbsolutePath != plan.VaultId)
                throw new InvalidOperationException("selected-delete-request");
            selectedDeletes++;
            using var applied = await fixture.Wire.Respond(request, "selected-arm", token);
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent("{\"status\":\"InProgress\"}", Encoding.UTF8, "application/json") };
            response.Headers.Add("Azure-AsyncOperation", "https://management.azure.com" + statusPath + "?api-version=2026-02-01");
            response.Headers.Add("Location", "https://management.azure.com" + statusPath + "?api-version=2026-02-01");
            return response;
        }));
        var client = new VaultAdministration(new Credential("selected-arm"), new HttpClientTransport(http));
        var scope = fixture.Source.Scope(plan);
        var receipt = client.PrepareReceipt(scope, ManagementMutation.DeleteVault);
        var started = await client.DeleteVaultAsync(scope, receipt);
        await Assert.That(started.IsSuccess).IsTrue();
        await Assert.That(await started.Value!.CheckStatusAsync()).IsEqualTo(SecretStatus.Success);
        await Assert.That(started.Value!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(selectedDeletes).IsEqualTo(1);
        await Assert.That(selectedStatusReads).IsEqualTo(0);
        fixture.Journal.EndDispatch(Owner, fixture.Selector, plan.VaultId, dispatch, nativeSettled: false);
        if (!settle) return;

        // The real SDK's cached terminal wrapper above is not native settlement.
        // This source attests a separate native status read and typed absence.
        fixture.Wire.NativeStatus = "Succeeded";
        using var independent = new HttpClient(new VaultForwarder((request, token) =>
            fixture.Wire.Respond(request, "read-arm", token)));
        independent.DefaultRequestHeaders.Authorization = new("Bearer", "read-arm");
        using var status = await independent.GetAsync("https://management.azure.com" + statusPath + "?api-version=2026-02-01");
        await Assert.That(status.StatusCode).IsEqualTo(HttpStatusCode.OK);
        using var body = JsonDocument.Parse(await status.Content.ReadAsByteArrayAsync());
        await Assert.That(body.RootElement.GetProperty("status").GetString()).IsEqualTo("Succeeded");
        var observed = await fixture.Source.ObserveAsync(Owner, fixture.Selector);
        await Assert.That(observed.VaultPresent).IsFalse();
        await Assert.That(observed.DeletedVaultPresent).IsTrue();
        fixture.Journal.SettleDispatch(Owner, fixture.Selector, plan.VaultId, dispatch);
    }

    private sealed class CleanupAdmissionTime(Action admit) : TimeProvider
    {
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            admit();
            return TimeProvider.System.CreateTimer(callback, state, dueTime, period);
        }
    }
}
