using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using Capture = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;
using Notification = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationFixtureProvisioner;
using Op = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task SelectedNotificationDeletionAbsenceDoesNotSettleOrRecordJournalAbsence()
    {
        await using var f = await SelectedNotificationFixture.Create(operation: ManagementMutation.DeleteNotification);
        using var measured = await f.Read();
        await Assert.That(measured.State).IsEqualTo(Notification.State.Pending);
        await Assert.That(measured.Present).IsFalse();
        await Assert.That(measured.Configuration).IsNull();
        await Assert.That(measured.NativeState).IsNull();
        await Assert.That(ReferenceEquals(measured.SelectedPlan, f.Child)).IsTrue();
        await Assert.That(measured.SelectedDispatch).IsEqualTo(f.Dispatch);
        var row = f.Native.Read().Resources.Single(r => r.Id == f.Child.ResourceId);
        await Assert.That(row.ActiveDispatch).IsEqualTo(f.Dispatch);
        await Assert.That(row.Absent || row.DeleteAttempted).IsFalse();
        int writes = f.Children.Requests.Count(r => r.Method != System.Net.Http.HttpMethod.Get);
        using var release = await f.Children.Source.ReleaseAsync(Owner, f.Native.Selector, "one-child");
        await f.Native.Source.ReleaseAsync(Owner, f.Native.Selector, purge: true);
        await Assert.That(f.Children.Requests.Count(r => r.Method != System.Net.Http.HttpMethod.Get)).IsEqualTo(writes);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SelectedNotificationDeletionCleanupCannotDeleteAReappearingOwnedChild(bool restart)
    {
        await using var f = await SelectedNotificationFixture.Create(operation: ManagementMutation.DeleteNotification);
        using var measured = await f.Read();
        await Assert.That(measured.Present).IsFalse();
        // Isolate the post-settlement cleanup invariant. This test-only journal
        // settlement is not an implemented service evidence join.
        f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, f.Child.ResourceId, f.Dispatch);
        f.Children.Seed(f.Child);
        if (restart) await f.Children.Source.DisposeAsync();
        await using var cleanup = restart ? f.Children.Cleanup(f.Native.Source) : null;
        int deletes = f.Children.Requests.Count(r => r.Method == System.Net.Http.HttpMethod.Delete);
        int parentWrites = f.Native.Writes;
        using var release = await (cleanup ?? f.Children.Source).ReleaseAsync(Owner, f.Native.Selector, "one-child");
        await Assert.That(f.Children.Requests.Count(r => r.Method == System.Net.Http.HttpMethod.Delete)).IsEqualTo(deletes);
        await Assert.That(release.Present).IsTrue();
        await Assert.That(release.State).IsEqualTo(Notification.State.Uncertain);
        await f.Native.Source.ReleaseAsync(Owner, f.Native.Selector, purge: true);
        await Assert.That(f.Native.Writes).IsEqualTo(parentWrites);
        await Assert.That(f.Children.Resources.ContainsKey(f.Child.ResourceId)).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("copy")]
    [Arguments("dispatch")]
    [Arguments("closing")]
    [Arguments("restored")]
    public async Task SelectedNotificationDeletionReadRejectsSubstitutedOrClosedOwnership(string fault)
    {
        await using var f = await SelectedNotificationFixture.Create(operation: ManagementMutation.DeleteNotification);
        var plan = f.Child;
        if (fault == "copy")
            plan = new(plan.Source, plan.Owner, plan.Selector, plan.LeaseId, plan.Scope, plan.Preparation,
                objectPlan: f.Parent, manifest: plan.Manifest);
        if (fault == "closing") f.Children.Source.CloseSelectedRoot(Owner, f.Native.Selector);
        await using var restored = fault == "restored" ? f.Children.Cleanup(f.Native.Source) : null;
        int reads = f.Children.Requests.Count;
        await Assert.That(async () =>
        {
            using var measured = await (restored ?? f.Children.Source).ObserveSelectedAsync(plan,
                fault == "dispatch" ? Guid.NewGuid() : f.Dispatch);
        }).Throws<InvalidOperationException>();
        await Assert.That(f.Children.Requests.Count).IsEqualTo(reads);
    }

    [Test]
    [Arguments("denied-authority")]
    public async Task SelectedNotificationDeletionReadRejectsUnadmittedCasesBeforeGet(string boundary)
    {
        await using var f = await SelectedNotificationFixture.Create(boundary, ManagementMutation.DeleteNotification);
        int reads = f.Children.Requests.Count;
        await Assert.That(async () => { using var measured = await f.Read(); }).Throws<InvalidOperationException>();
        await Assert.That(f.Children.Requests.Count).IsEqualTo(reads);
    }

    [Test]
    [Arguments("credential")]
    [Arguments("preflight")]
    [Arguments("read-body")]
    public async Task SelectedNotificationDeletionAbsenceRetainsBothNativeGates(string barrier)
    {
        await using var f = await SelectedNotificationFixture.Create(operation: ManagementMutation.DeleteNotification);
        f.Children.Barrier = barrier;
        f.Children.Entered = Signal();
        f.Children.Resume = Signal();
        using var cancellation = new CancellationTokenSource();
        var reading = f.Read(cancellation.Token).AsTask();
        Task? disposal = null;
        try
        {
            await f.Children.Entered.Task.WaitAsync(OwnedBound);
            cancellation.Cancel();
            disposal = f.Children.Source.DisposeAsync().AsTask();
            await Assert.That(reading.IsCompleted || disposal.IsCompleted).IsFalse();
            await Assert.That(f.Parent.Busy).IsEqualTo(1);
            await Assert.That(f.Child.Gate.CurrentCount).IsEqualTo(0);
        }
        finally { f.Children.Resume.TrySetResult(); }
        await Assert.That(async () => { using var measured = await reading.WaitAsync(OwnedBound); })
            .Throws<OperationCanceledException>();
        await disposal!.WaitAsync(OwnedBound);
        await Assert.That(f.Parent.Busy).IsEqualTo(0);
        await Assert.That(f.Child.Gate.CurrentCount).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Child.ResourceId).ActiveDispatch).IsEqualTo(f.Dispatch);
    }

    [Test]
    public async Task SelectedNotificationDeletionSettledAbsencePermitsOnlyStagedParentCleanup()
    {
        await using var f = await SelectedNotificationFixture.Create(operation: ManagementMutation.DeleteNotification);
        using var measured = await f.Read();
        await Assert.That(measured.Present).IsFalse();
        // Test the cleanup primitive after explicit test-only settlement, not a
        // service qualification claim or an inference from this 404.
        f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, f.Child.ResourceId, f.Dispatch);
        int deletes = f.Children.Requests.Count(r => r.Method == System.Net.Http.HttpMethod.Delete);
        using var child = await f.Children.Source.ReleaseAsync(Owner, f.Native.Selector, "one-child");
        await Assert.That(child.State).IsEqualTo(Notification.State.Closing);
        await f.Native.Source.ReleaseAsync(Owner, f.Native.Selector, purge: true);
        using var afterDelete = await f.Children.Source.ObserveAsync(Owner, f.Native.Selector, "one-child");
        await Assert.That(afterDelete.Present).IsFalse();
        await f.Native.Source.ReleaseAsync(Owner, f.Native.Selector, purge: true);
        using var afterPurge = await f.Children.Source.ObserveAsync(Owner, f.Native.Selector, "one-child");
        await Assert.That(afterPurge.Present).IsFalse();
        var completed = await f.Native.Source.ReleaseAsync(Owner, f.Native.Selector, purge: true);
        await Assert.That(completed.State).IsEqualTo(VaultFixtureProvisioner.State.Released);
        await Assert.That(f.Children.Requests.Count(r => r.Method == System.Net.Http.HttpMethod.Delete)).IsEqualTo(deletes);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    public async Task SelectedNotificationDeletionReadReportsActualSurvivingOwnedChild()
    {
        await using var f = await SelectedNotificationFixture.Create(operation: ManagementMutation.DeleteNotification);
        f.Children.Seed(f.Child);
        using var measured = await f.Read();
        await Assert.That(measured.State).IsEqualTo(Notification.State.Pending);
        await Assert.That(measured.Present).IsTrue();
        await Assert.That(measured.NativeState).IsEqualTo("Succeeded");
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Child.ResourceId).ActiveDispatch).IsEqualTo(f.Dispatch);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task OriginalNotificationUpdateTerminalSequenceUsesActualCapturedHandle()
    {
        await using var f = await SelectedNotificationFixture.Create();
        var status = await f.CheckOriginal();
        await Assert.That(status).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.StatusAttempts).IsEqualTo(1);
        await Assert.That(f.OwnsCompletion).IsTrue();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Child.ResourceId).ActiveDispatch).IsEqualTo(f.Dispatch);
    }

    [Test]
    public async Task OriginalOwnedNotificationPutTerminalSequenceUsesActualCapturedHandle()
    {
        await using var f = await SelectedNotificationFixture.Create(operation: ManagementMutation.CreateOrUpdateNotification);
        await Assert.That(await f.CheckOriginal()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.StatusAttempts).IsEqualTo(1);
        await Assert.That(f.OwnsCompletion).IsTrue();
        var body = f.Children.SelectedPatch ?? throw new InvalidOperationException("missing-selected-put");
        await Assert.That(body["properties"]!.AsObject().Select(p => p.Key).ToArray())
            .IsEquivalentTo(["destination", "filter"]);
        using var measured = await f.Read();
        await Assert.That(measured.Configuration!.EventTypes.Single()).IsEqualTo(VaultNotificationEvent.SecretNewVersionCreated);
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Child.ResourceId).ActiveDispatch).IsEqualTo(f.Dispatch);
    }

    [Test]
    public async Task CachedOwnedNotificationPutCannotMintCompletionProof()
    {
        await using var f = await SelectedNotificationFixture.Create(operation: ManagementMutation.CreateOrUpdateNotification);
        await Assert.That(await f.CompleteOutsideCapture()).IsEqualTo(SecretStatus.Success);
        await Assert.That(await f.CheckOriginal()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.StatusAttempts).IsEqualTo(0);
        await Assert.That(f.OwnsCompletion).IsFalse();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Child.ResourceId).ActiveDispatch).IsEqualTo(f.Dispatch);
    }

    [Test]
    [Arguments("foreign-topic")]
    [Arguments("foreign-label")]
    [Arguments("missing-label")]
    [Arguments("hidden-configuration")]
    public async Task OwnedNotificationPutRequiresActualOwnershipAndCompleteConfiguration(string fault)
    {
        await using var f = await SelectedNotificationFixture.Create(operation: ManagementMutation.CreateOrUpdateNotification);
        f.Children.ReadFault = fault;
        using var measured = await f.Read();
        await Assert.That(measured.Configuration).IsNull();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Child.ResourceId).ActiveDispatch).IsEqualTo(f.Dispatch);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task CachedNotificationUpdateCannotMintOriginalCompletionProof()
    {
        await using var f = await SelectedNotificationFixture.Create();
        await Assert.That(await f.CompleteOutsideCapture()).IsEqualTo(SecretStatus.Success);
        await Assert.That(await f.CheckOriginal()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.StatusAttempts).IsEqualTo(0);
        await Assert.That(f.OwnsCompletion).IsFalse();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Child.ResourceId).ActiveDispatch).IsEqualTo(f.Dispatch);
    }

    [Test]
    public async Task OriginalNotificationUpdateReadbackPreservesSelectedDispatchFence()
    {
        await using var f = await SelectedNotificationFixture.Create();
        var patch = f.Children.SelectedPatch ?? throw new InvalidOperationException("missing-selected-patch");
        await Assert.That(patch.Select(p => p.Key).ToArray())
            .IsEquivalentTo(["destination", "filter"]);
        await Assert.That(patch["filter"]!.AsObject().Select(p => p.Key).ToArray())
            .IsEquivalentTo(["includedEventTypes"]);
        await Assert.That(patch["destination"]!["properties"]!.AsObject().Select(p => p.Key).ToArray())
            .IsEquivalentTo(["endpointUrl"]);
        var before = f.Native.Read();
        int reads = f.Children.Requests.Count;
        using var ordinary = await f.Children.Source.ObserveAsync(Owner, f.Native.Selector, "one-child");
        await Assert.That(ordinary.State).IsEqualTo(Notification.State.Pending);
        await Assert.That(f.Children.Requests.Count).IsEqualTo(reads);
        using var measured = await f.Read();
        await Assert.That(measured.State).IsEqualTo(Notification.State.Pending);
        await Assert.That(measured.Present).IsTrue();
        await Assert.That(measured.NativeState).IsEqualTo("Succeeded");
        await Assert.That(ReferenceEquals(measured.SelectedPlan, f.Child)).IsTrue();
        await Assert.That(measured.SelectedDispatch).IsEqualTo(f.Dispatch);
        await Assert.That(measured.Configuration!.EventTypes.Single()).IsEqualTo(VaultNotificationEvent.SecretNewVersionCreated);
        await Assert.That(f.BaselineEvent).IsEqualTo(VaultNotificationEvent.SecretNearExpiry);
        await Assert.That(f.Children.Requests.Count).IsEqualTo(reads + 1);
        await Assert.That(f.Children.SelectedPatch!.ContainsKey("labels")).IsFalse();
        await Assert.That(f.Native.Read().Resources.SequenceEqual(before.Resources)).IsTrue();
        int mutations = f.Native.Writes + f.Children.Requests.Count(r => r.Method != HttpMethod.Get);
        using var released = await f.Children.Source.ReleaseAsync(Owner, f.Native.Selector, "one-child");
        await Assert.That(released.State).IsEqualTo(Notification.State.Pending);
        await f.Native.Source.ReleaseAsync(Owner, f.Native.Selector, purge: true);
        await Assert.That(f.Native.Writes + f.Children.Requests.Count(r => r.Method != HttpMethod.Get)).IsEqualTo(mutations);
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("foreign-topic")]
    [Arguments("foreign-label")]
    [Arguments("missing-label")]
    [Arguments("invalid-json")]
    [Arguments("read-dispose")]
    public async Task SelectedNotificationReadCannotPublishForeignOrUndrainedEvidence(string fault)
    {
        await using var f = await SelectedNotificationFixture.Create();
        f.Children.ReadFault = fault;
        using var result = await f.Read();
        await Assert.That(result.State).IsEqualTo(Notification.State.Uncertain);
        await Assert.That(result.Configuration).IsNull();
        await Assert.That(result.SelectedPlan).IsNull();
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Child.ResourceId).ActiveDispatch).IsEqualTo(f.Dispatch);
        await Assert.That(f.Parent.Busy).IsEqualTo(0);
        await Assert.That(f.Child.Gate.CurrentCount).IsEqualTo(1);
    }

    [Test]
    [Arguments("hidden-configuration")]
    [Arguments("Updating")]
    [Arguments("Failed")]
    public async Task SelectedNotificationReadPreservesUnknownConfigurationAndActualNativeState(string state)
    {
        await using var f = await SelectedNotificationFixture.Create();
        if (state == "hidden-configuration") f.Children.ReadFault = state;
        else f.Children.Resources[f.Child.ResourceId]["properties"]!["provisioningState"] = state;
        using var result = await f.Read();
        await Assert.That(result.State).IsEqualTo(Notification.State.Pending);
        await Assert.That(result.NativeState).IsEqualTo(state == "hidden-configuration" ? "Succeeded" : state);
        await Assert.That(result.ConfigurationKnown).IsEqualTo(state != "hidden-configuration");
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Child.ResourceId).ActiveDispatch).IsEqualTo(f.Dispatch);
    }

    [Test]
    [Arguments("copy")]
    [Arguments("dispatch")]
    [Arguments("closing")]
    [Arguments("status-active")]
    [Arguments("settled")]
    [Arguments("restored")]
    public async Task SelectedNotificationReadRejectsInvalidAdmissionBeforeNativeIo(string fault)
    {
        await using var f = await SelectedNotificationFixture.Create();
        var plan = f.Child;
        Guid dispatch = f.Dispatch;
        if (fault == "copy")
            plan = new(plan.Source, plan.Owner, plan.Selector, plan.LeaseId, plan.Scope, plan.Preparation,
                objectPlan: f.Parent, manifest: plan.Manifest);
        if (fault == "dispatch") dispatch = Guid.NewGuid();
        if (fault == "closing") f.Children.Source.CloseSelectedRoot(Owner, f.Native.Selector);
        if (fault == "status-active")
            f.Native.Journal.AdmitStatusRead(Owner, f.Native.Selector, f.Child.LeaseId, f.Child.ResourceId, f.Dispatch);
        if (fault == "settled")
            f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, f.Child.ResourceId, f.Dispatch);
        await using var restored = fault == "restored" ? f.Children.Cleanup(f.Native.Source) : null;
        int reads = f.Children.Requests.Count;
        await Assert.That(async () =>
        {
            using var result = await (restored ?? f.Children.Source).ObserveSelectedAsync(plan, dispatch);
        }).Throws<InvalidOperationException>();
        await Assert.That(f.Children.Requests.Count).IsEqualTo(reads);
    }

    [Test]
    [Arguments("credential")]
    [Arguments("preflight")]
    [Arguments("read-body")]
    public async Task SelectedNotificationReadRetainsBothGatesThroughClosureAndIgnoredCancellation(string barrier)
    {
        await using var f = await SelectedNotificationFixture.Create();
        f.Children.Barrier = barrier;
        f.Children.Entered = Signal();
        f.Children.Resume = Signal();
        using var cancellation = new CancellationTokenSource();
        var reading = f.Read(cancellation.Token).AsTask();
        Task? disposal = null;
        try
        {
            await f.Children.Entered.Task.WaitAsync(OwnedBound);
            cancellation.Cancel();
            disposal = f.Children.Source.DisposeAsync().AsTask();
            await Assert.That(disposal.IsCompleted || reading.IsCompleted).IsFalse();
            await Assert.That(f.Parent.Busy).IsEqualTo(1);
            await Assert.That(f.Child.Gate.CurrentCount).IsEqualTo(0);
            await Assert.That((await f.Native.Source.ReleaseAsync(Owner, f.Native.Selector)).State)
                .IsEqualTo(VaultFixtureProvisioner.State.Pending);
        }
        finally { f.Children.Resume.TrySetResult(); }
        await Assert.That(async () => { using var result = await reading; }).Throws<OperationCanceledException>();
        await disposal!.WaitAsync(OwnedBound);
        await Assert.That(f.Parent.Busy).IsEqualTo(0);
        await Assert.That(f.Child.Gate.CurrentCount).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Single(r => r.Id == f.Child.ResourceId).ActiveDispatch).IsEqualTo(f.Dispatch);
    }

    [Test]
    public async Task SelectedNotificationReadRechecksClosureBeforePublishing()
    {
        await using var f = await SelectedNotificationFixture.Create();
        f.Children.Barrier = "read-body";
        f.Children.Entered = Signal();
        f.Children.Resume = Signal();
        var reading = f.Read().AsTask();
        try
        {
            await f.Children.Entered.Task.WaitAsync(OwnedBound);
            f.Children.Source.CloseSelectedRoot(Owner, f.Native.Selector);
        }
        finally { f.Children.Resume.TrySetResult(); }
        using var result = await reading.WaitAsync(OwnedBound);
        await Assert.That(result.State).IsEqualTo(Notification.State.Uncertain);
        await Assert.That(result.SelectedPlan).IsNull();
        await Assert.That(result.Configuration).IsNull();
    }

    [Test]
    public async Task SelectedNotificationReadTimerFailureCannotStrandEitherGate()
    {
        await using var f = await SelectedNotificationFixture.Create();
        f.Children.Clock.ThrowOnCreate = true;
        using var result = await f.Read();
        await Assert.That(result.State).IsEqualTo(Notification.State.Uncertain);
        await Assert.That(f.Parent.Busy).IsEqualTo(0);
        await Assert.That(f.Child.Gate.CurrentCount).IsEqualTo(1);
    }

    [Test]
    public async Task SelectedNotificationAbsenceIsObservationNotSettlementOrJournalAbsence()
    {
        await using var f = await SelectedNotificationFixture.Create();
        f.Children.Resources.Remove(f.Child.ResourceId);
        using var result = await f.Read();
        await Assert.That(result.Present).IsFalse();
        await Assert.That(result.Configuration).IsNull();
        await Assert.That(result.NativeState).IsNull();
        await Assert.That(result.State).IsEqualTo(Notification.State.Pending);
        var row = f.Native.Read().Resources.Single(r => r.Id == f.Child.ResourceId);
        await Assert.That(row.ActiveDispatch).IsEqualTo(f.Dispatch);
        await Assert.That(row.Absent).IsFalse();
    }

    [Test]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    public async Task SelectedNotificationReadRejectsUnadmittedCasesBeforeNativeIo(string boundary)
    {
        {
            bool denied = boundary == "denied-authority";
            await using var owned = new PurgeServiceFixture(boundary, ManagementMutation.UpdateNotification,
                statusNotificationUpdateIndependent: !denied, statusDeniedNotificationUpdate: denied);
            var lease = await owned.PrepareAndBaseline();
            var (source, plan) = RetainedNotificationUpdateIndependentFixture(owned.Source, owned.Native.Selector.Nonce);
            int before = owned.NotificationResourceReads;
            await Assert.That(async () => { using var result = await source.ObserveSelectedAsync(plan, Guid.NewGuid()); })
                .Throws<InvalidOperationException>();
            await Assert.That(owned.NotificationResourceReads).IsEqualTo(before);
            var started = await owned.Start(lease);
            await owned.Observe(lease);
            if (denied)
                await Assert.That(await owned.Source.RunCheckStatusAsync(owned.Native.Selector, started.Value!, default))
                    .IsEqualTo(SecretStatus.Denied);
            else await FinishNotificationUpdateIndependent(owned, started.Value!);
            RoleFixtureRelease.Validate(await owned.Release(), owned.Native.Selector, lease.Facts);
        }
    }

    private sealed class SelectedNotificationFixture : IAsyncDisposable
    {
        internal readonly Fixture Native = new(allowPurge: true);
        internal readonly VaultFixtureProvisioner.Plan Parent;
        internal readonly OwnedNotifications Children;
        internal readonly Notification.Plan Child;
        private readonly Capture capture;
        private readonly Capture.Window window;
        internal Guid Dispatch;
        internal VaultNotificationEvent BaselineEvent;
        private ManagementOperation? handle;
        private bool bypassCapture;
        internal int StatusAttempts => window.Status?.Attempts.Count ?? 0;
        internal bool OwnsCompletion => capture.OwnsNativeStatusCompletion(window, window.Binding);
        internal Task<SecretStatus> CheckOriginal() => capture.CheckStatusAsync(window, Native.Selector,
            handle ?? throw new InvalidOperationException("missing-original-notification-handle"));
        internal async Task<SecretStatus> CompleteOutsideCapture()
        {
            bypassCapture = true;
            try { return await handle!.CheckStatusAsync(); }
            finally { bypassCapture = false; }
        }
        private SelectedNotificationFixture(string boundary, ManagementMutation operation)
        {
            Native.Selector = Native.Selector with
            {
                Operation = Op.Members[0].Operation,
                Variant = "operation." + operation,
                Case = boundary
            };
            Parent = Native.Plan(seedCanary: false, notifications: ["one-child"]);
            Children = new(Native, Parent, [VaultNotificationEvent.SecretNearExpiry]);
            Child = Children.Source.PlanDeclaredSubscription(Parent, "one-child", Notification.Preparation.Present);
            capture = new(Children.SelectedBackend);
            window = capture.Arm(new(Native.Selector, Parent.LeaseId, Child.Scope,
                operation, "eastus", "2025-02-15"));
        }
        internal static async Task<SelectedNotificationFixture> Create(string boundary = "selected-contract",
            ManagementMutation operation = ManagementMutation.UpdateNotification)
        {
            var f = new SelectedNotificationFixture(boundary, operation);
            try
            {
                await f.Native.Source.ProvisionAsync(f.Parent);
                using var prepared = await f.Children.Source.ProvisionAsync(f.Child);
                if (prepared.State != Notification.State.Ready) throw new InvalidOperationException("controlled-notification-preparation");
                f.BaselineEvent = prepared.Configuration!.EventTypes.Single();
                var client = new VaultAdministration(f.Children.SelectedCredential, new NotificationStatusSeam(f));
                var receipt = client.PrepareReceipt(f.Child.Scope, operation);
                var input = new Op.Input(null!, null!, Subscription, "fixture-group", "eastus", Tenant, VaultSku.Premium, 23,
                    operation, "https://fixture.invalid/owned-notification", Guid.Empty);
                f.Dispatch = operation == ManagementMutation.DeleteNotification
                    ? f.Native.Journal.BeginSelectedDispatch(Owner, f.Native.Selector, f.Child.ResourceId, delete: true)
                    : f.Native.Journal.BeginSelectedUpdate(Owner, f.Native.Selector, f.Child.ResourceId);
                try
                {
                    var result = await f.capture.StartAsync(f.window, f.Native.Selector, client, f.Child.Scope, input, receipt);
                    if (!result.IsSuccess) throw new InvalidOperationException("controlled-original-notification-start");
                    f.handle = result.Value;
                }
                finally { f.Native.Journal.EndDispatch(Owner, f.Native.Selector, f.Child.ResourceId, f.Dispatch, nativeSettled: false); }
                // Explicit progression only after the actual original SDK task:
                // no elapsed time or cached wrapper implies native completion.
                if (operation != ManagementMutation.DeleteNotification)
                    f.Children.Resources[f.Child.ResourceId]["properties"]!["provisioningState"] = "Succeeded";
                return f;
            }
            catch { await f.DisposeAsync(); throw; }
        }
        internal ValueTask<Notification.Result> Read(CancellationToken token = default) =>
            Children.Source.ObserveSelectedAsync(Child, Dispatch, token);
        public async ValueTask DisposeAsync()
        {
            Children.Resume?.TrySetResult();
            try { await capture.SealAsync(window); }
            finally { try { await Children.DisposeAsync(); } finally { Native.Dispose(); } }
        }
        private sealed class NotificationStatusSeam(SelectedNotificationFixture fixture) : Azure.Core.Pipeline.HttpPipelineTransport
        {
            public override Azure.Core.Request CreateRequest() => (fixture.bypassCapture
                ? fixture.Children.SelectedBackend : fixture.capture.SelectedTransport).CreateRequest();
            public override void Process(Azure.Core.HttpMessage message) => throw new InvalidOperationException("async-only");
            public override ValueTask ProcessAsync(Azure.Core.HttpMessage message) => (fixture.bypassCapture
                ? fixture.Children.SelectedBackend : fixture.capture.SelectedTransport).ProcessAsync(message);
        }
    }
}
