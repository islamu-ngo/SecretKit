using System.Net;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureRoleFixtureProvisionerTests
{
    [Test]
    public async Task OriginalRoleSelectedDeleteCannotAdoptActiveSetupReceipt()
    {
        using var f = new Fixture(allowPurge: true, selector: new(Guid.NewGuid(), "controlled",
            ManagementOperationEffects.Members[0].Operation, "operation.DeleteRoleAssignment", "selected-contract"));
        var plan = f.Plan();
        f.State.SetupAssignmentApplied = new(TaskCreationOptions.RunContinuationsAsynchronously);
        f.State.SetupAssignmentTerminate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var preparing = f.Source.ProvisionAsync(plan, Material).AsTask();
        RoleFixtureProvisioner.Result completed;
        try
        {
            await f.State.SetupAssignmentApplied.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var row = f.Read().Resources.Single(r => r.Id == plan.AssignmentId);
            var receipt = plan.Receipts.Single(r => r.Dispatch == row.ActiveDispatch);
            await Assert.That(row.SelectedAttempted).IsFalse();
            await Assert.That(receipt.Action).IsEqualTo(RoleFixtureProvisioner.Action.CreateAssignment);
            await Assert.That(receipt.Attempted && !receipt.Terminated).IsTrue();
            await Assert.That(() => f.Source.EndSelectedDispatch("owner", f.Selector, plan.AssignmentId,
                row.ActiveDispatch, true)).Throws<InvalidOperationException>();
            await Assert.That(receipt.Terminated || receipt.RemoteSettled).IsFalse();
            await Assert.That(f.Read().Resources.Single(r => r.Id == plan.AssignmentId).ActiveDispatch).IsEqualTo(row.ActiveDispatch);
        }
        finally
        {
            f.State.SetupAssignmentTerminate.TrySetResult();
            completed = await preparing.WaitAsync(TimeSpan.FromSeconds(10));
        }
        await Assert.That(completed.State).IsEqualTo(RoleFixtureProvisioner.State.Ready);
    }

    [Test]
    public async Task OriginalRoleSelectedDeleteRetainsActionBeforeNativeCallbacks()
    {
        using var f = await SelectedRoleDeletion.Create();
        f.Begin();
        var before = f.Plan.Receipts.SingleOrDefault(r => r.Dispatch == f.Dispatch);
        await Assert.That(before).IsNotNull();
        await Assert.That(before!.Action).IsEqualTo(RoleFixtureProvisioner.Action.DeleteAssignment);
        await Assert.That(before.Attempted && !before.Terminated && !before.RemoteSettled).IsTrue();
        await Assert.That((await f.Start()).IsSuccess).IsTrue();
        await Assert.That(ReferenceEquals(before, f.ObservedReceipt)).IsTrue();
        f.End(true);
        await Assert.That(ReferenceEquals(before, f.Plan.Receipts.Single(r => r.Dispatch == f.Dispatch))).IsTrue();
        await Assert.That(before.Terminated && before.RemoteSettled).IsTrue();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Plan.AssignmentId).ActiveDispatch).IsEqualTo(Guid.Empty);
    }

    [Test]
    public async Task OriginalRoleSelectedDeleteEndsOneOriginalReceiptWithoutReclassification()
    {
        using var f = await SelectedRoleDeletion.Create();
        f.Begin();
        await f.Start();
        f.End(true);
        var retained = f.Plan.Receipts.Single(r => r.Dispatch == f.Dispatch);
        await Assert.That(retained.Action).IsEqualTo(RoleFixtureProvisioner.Action.DeleteAssignment);
        await Assert.That(() => f.End(false)).Throws<InvalidOperationException>();
        await Assert.That(retained.RemoteSettled).IsTrue();
        await Assert.That(f.Plan.Receipts.Count(r => r.Dispatch == f.Dispatch)).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalRoleSelectedDeleteJournalContentionRetainsActualTermination(bool settled)
    {
        using var f = await SelectedRoleDeletion.Create();
        if (!settled) f.Native.State.SelectedDeleteFault = "lost";
        f.Begin();
        var native = await f.Start();
        await Assert.That(native.IsSuccess).IsEqualTo(settled);
        var path = Path.Combine(f.Native.DirectoryPath, f.Native.Selector.Nonce.ToString("N") + ".journal");
        using (var held = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            await Assert.That(() => f.End(settled)).Throws<InvalidOperationException>();
            var receipt = f.Plan.Receipts.Single(r => r.Dispatch == f.Dispatch);
            await Assert.That(receipt.Action).IsEqualTo(RoleFixtureProvisioner.Action.DeleteAssignment);
            await Assert.That(receipt.Terminated).IsTrue();
            await Assert.That(receipt.RemoteSettled).IsEqualTo(settled);
        }
        int writes = f.Native.WriteCount;
        await f.Native.Source.SettleAsync(f.Plan);
        var released = await f.Native.Source.ReleaseAsync("owner", f.Native.Selector, purge: true);
        await Assert.That(RoleReleaseJournal(released).Released).IsEqualTo(settled);
        if (!settled)
        {
            await Assert.That(f.Native.WriteCount).IsEqualTo(writes);
            await Assert.That(RoleReleaseJournal(released).Resources.Single(r => r.Id == f.Plan.AssignmentId).ActiveDispatch).IsEqualTo(f.Dispatch);
        }
        await Assert.That(f.Plan.Receipts.Count(r => r.Dispatch == f.Dispatch)).IsEqualTo(1);
        await Assert.That(f.SelectedRequests.Count(r => r.Method == HttpMethod.Delete)).IsEqualTo(1);
    }

    [Test]
    public async Task OriginalRoleSelectedDeleteRestartCannotReconstructLostTerminationReceipt()
    {
        using var f = await SelectedRoleDeletion.Create();
        f.Begin();
        await f.Start();
        var path = Path.Combine(f.Native.DirectoryPath, f.Native.Selector.Nonce.ToString("N") + ".journal");
        using (var held = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            await Assert.That(() => f.End(true)).Throws<InvalidOperationException>();
        var restarted = f.Native.Reopen();
        await Assert.That(() => restarted.EndSelectedDispatch("owner", f.Native.Selector, f.Plan.AssignmentId, f.Dispatch, true))
            .Throws<InvalidOperationException>();
        int writes = f.Native.WriteCount;
        var release = await restarted.ReleaseAsync("owner", f.Native.Selector, purge: true);
        await Assert.That(RoleReleaseJournal(release).Released).IsFalse();
        await Assert.That(RoleReleaseJournal(release).Resources.Single(r => r.Id == f.Plan.AssignmentId).ActiveDispatch).IsEqualTo(f.Dispatch);
        await Assert.That(f.Native.WriteCount).IsEqualTo(writes);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalRoleSelectedDeleteReappearanceBlocksReplayAndParentTeardown(bool restart)
    {
        using var f = await SelectedRoleDeletion.Create();
        f.Begin();
        await f.Start();
        f.End(true);
        f.Native.State.AssignmentPath = f.Plan.AssignmentId;
        int writes = f.Native.WriteCount;
        var source = restart ? f.Native.Reopen() : f.Native.Source;
        var release = await source.ReleaseAsync("owner", f.Native.Selector, purge: true);
        await Assert.That(f.Native.WriteCount).IsEqualTo(writes);
        await Assert.That(release.State).IsEqualTo(RoleFixtureProvisioner.State.Uncertain);
        await Assert.That(RoleReleaseJournal(release).Released).IsFalse();
        await Assert.That(f.Native.State.AssignmentPath).IsEqualTo(f.Plan.AssignmentId);
        await Assert.That(f.Native.State.VaultExists).IsTrue();
        await Assert.That(f.Native.State.DeletedVaultExists).IsFalse();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("no-op")]
    public async Task OriginalRoleSelectedDeleteUnknownOutcomeNeverSettlesFromResourceState(string fault)
    {
        using var f = await SelectedRoleDeletion.Create();
        f.Native.State.SelectedDeleteFault = fault;
        f.Begin();
        await f.Start();
        // No service response-proof/independent-effect join was established.
        f.End(false);
        await Assert.That(() => f.End(false)).Throws<InvalidOperationException>();
        int writes = f.Native.WriteCount;
        var release = await f.Native.Source.ReleaseAsync("owner", f.Native.Selector, purge: true);
        await Assert.That(RoleReleaseJournal(release).Released).IsFalse();
        await Assert.That(RoleReleaseJournal(release).Resources.Single(r => r.Id == f.Plan.AssignmentId).ActiveDispatch).IsEqualTo(f.Dispatch);
        await Assert.That(f.Native.WriteCount).IsEqualTo(writes);
        var receipt = f.Plan.Receipts.Single(r => r.Dispatch == f.Dispatch);
        await Assert.That(receipt.Action).IsEqualTo(RoleFixtureProvisioner.Action.DeleteAssignment);
        await Assert.That(receipt.Terminated && !receipt.RemoteSettled).IsTrue();
    }

    [Test]
    public async Task OriginalRoleSelectedDeletePreparationOnlyCleanupRemainsAvailable()
    {
        using var f = await SelectedRoleDeletion.Create();
        var release = await f.Native.Source.ReleaseAsync("owner", f.Native.Selector, purge: true);
        await Assert.That(RoleReleaseJournal(release).Released).IsTrue();
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task OriginalRoleSelectedDeleteSettledAbsencePermitsOwnedCleanupOnly()
    {
        using var f = await SelectedRoleDeletion.Create();
        f.Begin();
        await f.Start();
        f.End(true);
        int roleDeletes = f.Native.Backends.SelectMany(b => b.Requests)
            .Count(r => r.Method == HttpMethod.Delete && r.Path == f.Plan.AssignmentId);
        var release = await f.Native.Source.ReleaseAsync("owner", f.Native.Selector, purge: true);
        await Assert.That(RoleReleaseJournal(release).Released).IsTrue();
        await Assert.That(f.Native.Backends.SelectMany(b => b.Requests)
            .Count(r => r.Method == HttpMethod.Delete && r.Path == f.Plan.AssignmentId)).IsEqualTo(roleDeletes);
        await Assert.That(f.Native.Backends.SelectMany(b => b.Requests)
            .Where(r => r.Path == DefinitionPath).All(r => r.Method == HttpMethod.Get)).IsTrue();
    }

    [Test]
    [Arguments("scope")]
    [Arguments("dispatch")]
    [Arguments("owner")]
    public async Task OriginalRoleSelectedDeleteRejectsForeignEndWithoutChangingReceipt(string fault)
    {
        using var f = await SelectedRoleDeletion.Create();
        f.Begin();
        await f.Start();
        var original = f.Plan.Receipts.SingleOrDefault(r => r.Dispatch == f.Dispatch);
        await Assert.That(original).IsNotNull();
        string id = fault == "scope" ? f.Plan.AssignmentId + "-foreign" : f.Plan.AssignmentId;
        await Assert.That(() => f.Native.Source.EndSelectedDispatch(fault == "owner" ? "foreign" : "owner",
            f.Native.Selector, id, fault == "dispatch" ? Guid.NewGuid() : f.Dispatch, true))
            .Throws<InvalidOperationException>();
        await Assert.That(original!.Terminated || original.RemoteSettled).IsFalse();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Plan.AssignmentId).ActiveDispatch).IsEqualTo(f.Dispatch);
        f.End(true);
    }

    [Test]
    [Arguments("vault")]
    [Arguments("foreign-assignment")]
    public async Task OriginalRoleSelectedDeleteRejectsUnownedSelectionBeforeJournalAdmission(string fault)
    {
        using var f = await SelectedRoleDeletion.Create();
        string id = fault == "vault" ? f.Plan.VaultId : f.Plan.AssignmentId + "-foreign";
        await Assert.That(() => f.Native.Source.BeginSelectedDispatch("owner", f.Native.Selector, id, delete: true))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalRoleSelectedDeleteReleaseRetainsActualBorrowerUntilNativeTermination(bool cancel)
    {
        using var f = await SelectedRoleDeletion.Create();
        f.Native.State.SelectedApplied = new(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Native.State.SelectedTerminate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Begin();
        using var cancellation = new CancellationTokenSource();
        var native = f.Start(cancellation.Token);
        try
        {
            await f.Native.State.SelectedApplied.Task.WaitAsync(TimeSpan.FromSeconds(10));
            if (cancel) cancellation.Cancel();
            int writes = f.Native.WriteCount;
            var release = await f.Native.Source.ReleaseAsync("owner", f.Native.Selector, purge: true);
            await Assert.That(native.IsCompleted).IsFalse();
            await Assert.That(RoleReleaseJournal(release).Resources.Single(r => r.Id == f.Plan.AssignmentId).ActiveDispatch).IsEqualTo(f.Dispatch);
            await Assert.That(f.Native.WriteCount).IsEqualTo(writes);
            var retained = f.Plan.Receipts.Single(r => r.Dispatch == f.Dispatch);
            await Assert.That(retained.Terminated).IsFalse();
        }
        finally { f.Native.State.SelectedTerminate.TrySetResult(); }
        if (cancel)
            await Assert.That(async () => await native.WaitAsync(TimeSpan.FromSeconds(10)))
                .Throws<OperationCanceledException>();
        else
            await Assert.That((await native.WaitAsync(TimeSpan.FromSeconds(10))).IsSuccess).IsTrue();
        // Release already closed admission: no service qualification is implied.
        f.End(false);
        var final = await f.Native.Source.ReleaseAsync("owner", f.Native.Selector, purge: true);
        await Assert.That(RoleReleaseJournal(final).Released).IsFalse();
        await Assert.That(RoleReleaseJournal(final).Resources.Single(r => r.Id == f.Plan.AssignmentId).ActiveDispatch).IsEqualTo(f.Dispatch);
    }

    private static RoleFixtureJournal.Snapshot RoleReleaseJournal(RoleFixtureProvisioner.Result result) =>
        result.Journal ?? throw new InvalidOperationException("role-release-journal-missing");

    private sealed class SelectedRoleDeletion : IDisposable
    {
        internal readonly Fixture Native;
        internal readonly RoleFixtureProvisioner.Plan Plan;
        internal readonly RoleAssignmentScope Scope;
        private readonly Backend backend;
        private readonly HttpClient http;
        private readonly VaultAdministration client;
        private readonly ManagementReceipt receipt;
        internal Guid Dispatch;
        internal RoleFixtureProvisioner.Receipt? ObservedReceipt;
        internal IReadOnlyList<(HttpMethod Method, string Path)> SelectedRequests => backend.Requests;

        private SelectedRoleDeletion(Fixture native, RoleFixtureProvisioner.Plan plan)
        {
            Native = native;
            Plan = plan;
            Scope = new(new VaultScope(new(new(Subscription), "fixture-group"), plan.VaultName),
                Guid.Parse(plan.AssignmentId.Split('/')[^1]));
            backend = new("administrative-arm", native.State);
            http = new(backend);
            client = new(new Credential("administrative-arm"), new HttpClientTransport(http));
            receipt = client.PrepareReceipt(Scope, ManagementMutation.DeleteRoleAssignment);
            var before = native.State.BeforeMutation;
            native.State.BeforeMutation = id =>
            {
                before(id);
                if (id == Plan.AssignmentId && Dispatch != Guid.Empty)
                    ObservedReceipt = Plan.Receipts.SingleOrDefault(r => r.Dispatch == Dispatch);
            };
        }

        internal static async Task<SelectedRoleDeletion> Create()
        {
            var selector = new FixtureSelector(Guid.NewGuid(), "controlled", ManagementOperationEffects.Members[0].Operation,
                "operation.DeleteRoleAssignment", "selected-contract");
            var native = new Fixture(allowPurge: true, selector: selector);
            var plan = native.Plan();
            var provisioned = await native.Source.ProvisionAsync(plan, Material);
            if (provisioned.State != RoleFixtureProvisioner.State.Ready)
            {
                native.Dispose();
                throw new InvalidOperationException("role-deletion-setup-unavailable");
            }
            return new(native, plan);
        }

        internal void Begin() => Dispatch = Native.Source.BeginSelectedDispatch("owner", Native.Selector, Plan.AssignmentId, delete: true);
        internal Task<SecretOutcome<ManagementOperation>> Start(CancellationToken token = default) =>
            client.DeleteRoleAssignmentAsync(Scope, receipt, token).AsTask();
        internal void End(bool settled) => Native.Source.EndSelectedDispatch("owner", Native.Selector, Plan.AssignmentId, Dispatch, settled);
        public void Dispose()
        {
            http.Dispose();
            Native.Dispose();
        }
    }
}
