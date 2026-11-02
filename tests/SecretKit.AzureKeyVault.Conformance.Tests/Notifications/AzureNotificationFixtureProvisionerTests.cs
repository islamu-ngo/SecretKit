using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using Provisioner = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationFixtureProvisioner;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

// Offline installed-SDK operations over a controlled HTTP backend, not native
// qualification, an observer service, delivery evidence or a webhook handshake.
public sealed class AzureNotificationFixtureProvisionerTests
{
    [Test]
    [Arguments(VaultNotificationEvent.SecretNewVersionCreated)]
    [Arguments(VaultNotificationEvent.SecretNearExpiry)]
    [Arguments(VaultNotificationEvent.SecretExpired)]
    public async Task PresentBaselineUsesActualSdkAndIndependentReadback(VaultNotificationEvent type)
    {
        await using var f = new Fixture([type]);
        var plan = f.Plan();
        using var result = await f.Source.ProvisionAsync(plan);
        await Assert.That(plan.Receipts.Single().CreateTask!.Exception).IsNull();
        await Assert.That(plan.Receipts.Single().StatusTask?.Exception).IsNull();
        var initial = plan.Receipts.Single();
        await Assert.That(initial.NativeOperation!.HasCompleted).IsTrue();
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(result.Configuration!.EventTypes.Single()).IsEqualTo(type);
        await Assert.That(result.Configuration.Endpoint.Reveal()).IsEqualTo(Endpoint);
        await Assert.That(f.Wire.Prejournaled).IsTrue();
        await Assert.That(plan.Receipts.Single().CreateTask!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(plan.Receipts.Single().NativeOperation).IsNotNull();
        await Assert.That(f.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsFalse();
        await Assert.That(f.Wire.Requests.Any(r => r.Role == "observer" && r.Method == HttpMethod.Get)).IsTrue();
        await Assert.That(f.Wire.Requests.All(r => r.Path == plan.ResourceId)).IsTrue();
        await Assert.That(result.ObservedAt).IsEqualTo(f.Clock.GetUtcNow());
    }

    [Test]
    public async Task AbsentBaselineDoesNotManufactureSelectedCreation()
    {
        await using var f = new Fixture();
        f.Plan(Provisioner.Preparation.Absent);
        using var result = await f.Source.ProvisionAsync(f.Current!);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(result.Present).IsFalse();
        await Assert.That(result.ConfigurationKnown).IsFalse();
        await Assert.That(f.Wire.Writes).IsEqualTo(0);
        using var released = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(released.State).IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Read().Resources.Single(r => r.Borrowed).Id).IsEqualTo(f.Vault.ExportResourceId());
        await Assert.That(f.Read().Resources.Single(r => r.Borrowed).Absent).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PreexistingResourceCannotBeAdoptedEvenWithMatchingLabel(bool sameOwner)
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.Seed(plan, sameOwner ? f.Selector.Nonce : Guid.NewGuid());
        using var result = await f.Source.ProvisionAsync(plan);
        using var cleanup = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(cleanup.State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(f.Wire.Writes).IsEqualTo(0);
        await Assert.That(f.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("invalid-json")]
    [Arguments("foreign-id")]
    [Arguments("foreign-topic")]
    [Arguments("foreign-label")]
    [Arguments("duplicate")]
    [Arguments("redirect")]
    public async Task InvalidMutationReplyRetainsUncertaintyWithoutReplay(string fault)
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.CreateFault = fault;
        using var result = await f.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsNotEqualTo(Provisioner.State.Ready);
        await Assert.That(f.Read().Resources.Single(r => !r.Borrowed).ActiveDispatch).IsNotEqualTo(Guid.Empty);
        using var settled = await f.Source.SettleAsync(Owner, f.Selector);
        using var released = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(released.State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Wire.Writes).IsEqualTo(1);
        await Assert.That(plan.Receipts.Single().Terminated).IsTrue();
        await Assert.That(plan.Receipts.Single().CreateTask!.IsCompleted).IsTrue();
    }

    [Test]
    [Arguments("denied")]
    [Arguments("oversized")]
    [Arguments("redirect")]
    public async Task UnestablishedPreflightNeverDispatchesSetup(string fault)
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.ReadFault = fault;
        using var result = await f.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsNotEqualTo(Provisioner.State.Ready);
        await Assert.That(f.Wire.Writes).IsEqualTo(0);
        await Assert.That(f.Read().Resources.All(r => !r.CreateAttempted)).IsTrue();
    }

    [Test]
    public async Task NativeDeniedMutationSettlesWithoutClaimingPresence()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.CreateFault = "denied";
        using var result = await f.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Denied);
        await Assert.That(plan.Receipts.Single().RemoteSettled).IsTrue();
        using var released = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(released.State).IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Wire.Resource).IsNull();
    }

    [Test]
    [Arguments("hidden-endpoint")]
    [Arguments("masked-endpoint")]
    [Arguments("omitted-headers")]
    [Arguments("masked-header")]
    [Arguments("omitted-secret-flag")]
    [Arguments("omitted-events")]
    [Arguments("extra-filter")]
    [Arguments("extra-destination")]
    public async Task PartialPersistedConfigurationIsUnknownNotRequestReadiness(string fault)
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.ReadFault = fault;
        using var result = await f.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Incomplete);
        await Assert.That(result.ConfigurationKnown).IsFalse();
        await Assert.That(result.Present).IsTrue();
        await Assert.That(f.Wire.Requests.All(r => !r.Path.Contains("/get", StringComparison.OrdinalIgnoreCase))).IsTrue();
    }

    [Test]
    [Arguments("changed-endpoint")]
    [Arguments("changed-event")]
    [Arguments("changed-header")]
    public async Task RepresentableButDifferentReadbackCannotBecomeReady(string fault)
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.ReadFault = fault;
        using var result = await f.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Incomplete);
        await Assert.That(result.ConfigurationKnown).IsTrue();
    }

    [Test]
    [Arguments("numeric-event")]
    [Arguments("foreign-id")]
    [Arguments("foreign-topic")]
    [Arguments("foreign-label")]
    public async Task InvalidIndependentReadbackDoesNotPermitCleanup(string fault)
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.ReadFault = fault;
        using var setup = await f.Source.ProvisionAsync(plan);
        using var released = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(setup.State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(released.State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(f.Wire.Requests.Any(r => r.Method == HttpMethod.Delete)).IsFalse();
    }

    [Test]
    public async Task Synchronous201RetainsActualNativeStatusTask()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        using var result = await f.Source.ProvisionAsync(plan);
        var receipt = plan.Receipts.Single();
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(receipt.CreateTask!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(receipt.NativeOperation!.HasCompleted).IsTrue();
        await Assert.That(receipt.StatusTask is null || receipt.StatusTask.IsCompleted).IsTrue();
        await Assert.That(f.Wire.Requests.Count(r => r.Method == HttpMethod.Put)).IsEqualTo(1);
    }

    [Test]
    [Arguments("202")]
    [Arguments("foreign-status")]
    [Arguments("unsupported-status")]
    public async Task PendingNativeStartHasNoStatusFallbackOrMutationReplay(string fault)
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.CreateFault = fault;
        using var setup = await f.Source.ProvisionAsync(plan);
        using var first = await f.Source.SettleAsync(Owner, f.Selector);
        int requests = f.Wire.Requests.Count;
        using var second = await f.Source.SettleAsync(Owner, f.Selector);
        using var cleanup = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(setup.State).IsNotEqualTo(Provisioner.State.Ready);
        await Assert.That(second.State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(cleanup.State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Wire.Requests.Count).IsEqualTo(requests);
        await Assert.That(f.Wire.Requests.All(r => r.Path == plan.ResourceId)).IsTrue();
        await Assert.That(f.Wire.Writes).IsEqualTo(1);
    }

    [Test]
    public async Task AsyncCreateRequiresOneActualTerminalStatusBeforeIndependentRead()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.CreateFault = "async";
        using var setup = await f.Source.ProvisionAsync(plan);
        await Assert.That(setup.State).IsEqualTo(Provisioner.State.Pending);
        f.Wire.NativeState = "Succeeded";
        f.Wire.Resource!["properties"]!["provisioningState"] = "Succeeded";
        using var settled = await f.Source.SettleAsync(Owner, f.Selector);
        await Assert.That(plan.Receipts.Single().StatusTask!.IsCompleted).IsTrue();
        await Assert.That(plan.Receipts.Single().Boundary!.StatusSent).IsTrue();
        await Assert.That(plan.Receipts.Single().RemoteSettled).IsTrue();
        using var observed = await f.Source.ObserveAsync(Owner, f.Selector);
        await Assert.That(observed.State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(f.Wire.Writes).IsEqualTo(1);
    }

    [Test]
    public async Task OnePendingStatusAttemptCannotBeRepeatedAfterStateChanges()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.CreateFault = "async";
        using var setup = await f.Source.ProvisionAsync(plan);
        using var first = await f.Source.SettleAsync(Owner, f.Selector);
        int requests = f.Wire.Requests.Count;
        f.Wire.NativeState = "Succeeded";
        using var second = await f.Source.SettleAsync(Owner, f.Selector);
        await Assert.That(second.State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Wire.Requests.Count).IsEqualTo(requests);
        await Assert.That(plan.Receipts.Single().StatusAttempted).IsTrue();
    }

    [Test]
    public async Task ActualTerminalNativeFailureSettlesWithoutBecomingReady()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.CreateFault = "async";
        using var setup = await f.Source.ProvisionAsync(plan);
        f.Wire.NativeState = "Failed";
        f.Wire.Resource!["properties"]!["provisioningState"] = "Failed";
        using var settled = await f.Source.SettleAsync(Owner, f.Selector);
        await Assert.That(plan.Receipts.Single().RemoteSettled).IsTrue();
        await Assert.That(settled.State == Provisioner.State.Ready).IsFalse();
        await Assert.That(f.Read().Resources.Single(r => !r.Borrowed).ActiveDispatch).IsEqualTo(Guid.Empty);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AbsentPreflightCannotHideConcurrentClosureOrSelectedDispatch(bool selected)
    {
        await using var f = new Fixture();
        var plan = f.Plan(Provisioner.Preparation.Absent);
        f.Wire.ReadEntered = Signal();
        f.Wire.ReadResume = Signal();
        var preparation = f.Source.ProvisionAsync(plan).AsTask();
        await f.Wire.ReadEntered.Task.WaitAsync(Bound);
        if (selected) f.Journal.BeginSelectedDispatch(Owner, f.Selector, plan.ResourceId, delete: false);
        else f.Source.CloseSelectedRoot(Owner, f.Selector);
        f.Wire.ReadResume.TrySetResult();
        using var result = await preparation.WaitAsync(Bound);
        await Assert.That(result.State).IsEqualTo(selected ? Provisioner.State.Pending : Provisioner.State.Closing);
    }

    [Test]
    public async Task CachedNativeDelete202DoesNotProveRemoteDeletion()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        using var setup = await f.Source.ProvisionAsync(plan);
        f.Wire.DeleteFault = "202";
        using var cleanup = await f.Source.ReleaseAsync(Owner, f.Selector);
        using var status = await f.Source.SettleAsync(Owner, f.Selector);
        using var again = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(cleanup.State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(again.State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(plan.Receipts.Last().DeleteTask!.IsCompleted).IsTrue();
        await Assert.That(plan.Receipts.Last().RemoteSettled).IsFalse();
        await Assert.That(f.Read().Released).IsFalse();
        await Assert.That(f.Wire.Requests.Count(r => r.Method == HttpMethod.Delete)).IsEqualTo(1);
    }

    [Test]
    [Arguments("lost")]
    [Arguments("invalid-json")]
    public async Task UncertainDeleteIsNeverReplayedEvenWhenRemoteResourceIsGone(string fault)
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        using var setup = await f.Source.ProvisionAsync(plan);
        f.Wire.DeleteFault = fault;
        using var first = await f.Source.ReleaseAsync(Owner, f.Selector);
        using var second = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(second.State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Wire.Resource).IsNull();
        await Assert.That(f.Read().Resources.Single(r => !r.Borrowed).Absent).IsFalse();
        await Assert.That(f.Wire.Requests.Count(r => r.Method == HttpMethod.Delete)).IsEqualTo(1);
    }

    [Test]
    public async Task CleanupNeedsConcreteIndependent404AndNeverMutatesBorrowedDependencies()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        using var setup = await f.Source.ProvisionAsync(plan);
        using var cleanup = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(cleanup.State).IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Wire.Requests.Last().Role).IsEqualTo("observer");
        await Assert.That(f.Wire.Requests.Last().Method).IsEqualTo(HttpMethod.Get);
        await Assert.That(f.Wire.Requests.All(r => r.Path == plan.ResourceId)).IsTrue();
        await Assert.That(f.Read().Resources.Single(r => r.Borrowed).CreateAttempted).IsFalse();
        await Assert.That(f.Read().Resources.Single(r => r.Borrowed).DeleteAttempted).IsFalse();
        await Assert.That(f.Wire.BorrowedState).IsEqualTo("host-vault|runtime-secret|webhook|roles|diagnostics");
        await Assert.That(f.Backends.All(b => !b.Disposed)).IsTrue();
    }

    [Test]
    public async Task PositiveMalformedReadInvalidatesPreviouslyRecordedAbsence()
    {
        await using var f = new Fixture();
        var plan = f.Plan(Provisioner.Preparation.Absent);
        using var prepared = await f.Source.ProvisionAsync(plan);
        using var released = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(f.Read().Released).IsTrue();
        f.Wire.Seed(plan, f.Selector.Nonce);
        f.Wire.ReadFault = "invalid-json";
        using var observed = await f.Source.ObserveAsync(Owner, f.Selector);
        await Assert.That(observed.State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(f.Read().Released).IsFalse();
        await Assert.That(f.Read().Resources.Single(r => !r.Borrowed).Absent).IsFalse();
    }

    [Test]
    public async Task RestartPreservesUnknownNativeHistoryInsteadOfInferringSettlement()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.CreateFault = "lost";
        using var setup = await f.Source.ProvisionAsync(plan);
        await using var reopened = f.Reopen();
        using var observed = await reopened.ObserveAsync(Owner, f.Selector);
        using var settled = await reopened.SettleAsync(Owner, f.Selector);
        using var cleanup = await reopened.ReleaseAsync(Owner, f.Selector);
        await Assert.That(observed.Receipts.Count).IsEqualTo(0);
        await Assert.That(settled.State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(cleanup.State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Wire.Writes).IsEqualTo(1);
    }

    [Test]
    public async Task KnownDurableCoordinatesCanBeCleanedAfterRestartWithoutInventingBaseline()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        using var setup = await f.Source.ProvisionAsync(plan);
        await using var reopened = f.Reopen();
        using var observed = await reopened.ObserveAsync(Owner, f.Selector);
        await Assert.That(observed.State).IsEqualTo(Provisioner.State.Incomplete);
        using var cleanup = await reopened.ReleaseAsync(Owner, f.Selector);
        await Assert.That(cleanup.State).IsEqualTo(Provisioner.State.Released);
    }

    [Test]
    public async Task ReleaseClosesBeforeLateNativeTaskDrainsAndNeverRunsConcurrentCleanup()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.Applied = Signal();
        f.Wire.Resume = Signal();
        Task<Provisioner.Result> setup = f.Source.ProvisionAsync(plan).AsTask();
        await f.Wire.Applied.Task.WaitAsync(Bound);
        using var closing = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(closing.State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Read().Closing).IsTrue();
        await Assert.That(plan.Receipts.Single().Terminated).IsFalse();
        await Assert.That(plan.Receipts.Single().CreateTask!.IsCompleted).IsFalse();
        await Assert.That(f.Wire.Requests.Any(r => r.Method == HttpMethod.Delete)).IsFalse();
        f.Wire.Resume.SetResult();
        using var finished = await setup.WaitAsync(Bound);
        await Assert.That(plan.Receipts.Single().Terminated).IsTrue();
        using var cleanup = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(cleanup.State).IsEqualTo(Provisioner.State.Released);
    }

    [Test]
    public async Task CancellationRetainsLateInvocationAndUncertaintyUntilActualDrain()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.Applied = Signal();
        f.Wire.Resume = Signal();
        using var cancellation = new CancellationTokenSource();
        Task<Provisioner.Result> setup = f.Source.ProvisionAsync(plan, cancellation.Token).AsTask();
        await f.Wire.Applied.Task.WaitAsync(Bound);
        cancellation.Cancel();
        using var closing = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(setup.IsCompleted).IsFalse();
        await Assert.That(f.Read().Resources.Single(r => !r.Borrowed).InvocationTerminated).IsFalse();
        f.Wire.Resume.SetResult();
        await Assert.That(async () => await setup.WaitAsync(Bound)).Throws<OperationCanceledException>();
        await Assert.That(plan.Receipts.Single().Terminated).IsTrue();
        await Assert.That(plan.Receipts.Single().RemoteSettled).IsFalse();
        await Assert.That(f.Read().Resources.Single(r => !r.Borrowed).ActiveDispatch).IsNotEqualTo(Guid.Empty);
    }

    [Test]
    public async Task InjectedDeadlineCancelsActualWorkWithoutWallClockDelay()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.Applied = Signal();
        f.Wire.Resume = Signal();
        Task<Provisioner.Result> setup = f.Source.ProvisionAsync(plan).AsTask();
        await f.Wire.Applied.Task.WaitAsync(Bound);
        f.Clock.Advance(TimeSpan.FromSeconds(11));
        f.Wire.Resume.SetResult();
        using var result = await setup.WaitAsync(Bound);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(result.ObservedAt).IsEqualTo(f.Clock.GetUtcNow());
        await Assert.That(plan.Receipts.Single().RemoteSettled).IsFalse();
    }

    [Test]
    public async Task SourceDisposalClosesAndDrainsBeforeRejectingLateBorrowers()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        f.Wire.Applied = Signal();
        f.Wire.Resume = Signal();
        Task<Provisioner.Result> setup = f.Source.ProvisionAsync(plan).AsTask();
        await f.Wire.Applied.Task.WaitAsync(Bound);
        Task dispose = f.Source.DisposeAsync().AsTask();
        await Assert.That(dispose.IsCompleted).IsFalse();
        await Assert.That(f.Read().Closing).IsTrue();
        await Assert.That(async () => await f.Source.ObserveAsync(Owner, f.Selector)).Throws<InvalidOperationException>();
        f.Wire.Resume.SetResult();
        using var result = await setup.WaitAsync(Bound);
        await dispose.WaitAsync(Bound);
        await Assert.That(plan.Receipts.Single().CreateTask!.IsCompleted).IsTrue();
        await Assert.That(f.Backends.All(b => !b.Disposed)).IsTrue();
    }

    [Test]
    public async Task AllActiveDispatchesFenceCleanupNotJustSourceReceipts()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        using var setup = await f.Source.ProvisionAsync(plan);
        Guid dispatch = f.Journal.BeginSelectedUpdate(Owner, f.Selector, plan.ResourceId);
        using var blocked = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(blocked.State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Wire.Requests.Any(r => r.Method == HttpMethod.Delete)).IsFalse();
        f.Journal.EndDispatch(Owner, f.Selector, plan.ResourceId, dispatch);
        using var cleanup = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(cleanup.State).IsEqualTo(Provisioner.State.Released);
    }

    [Test]
    public async Task SelectedDispatchFencesPreparationBeforeAnySourceNativeSend()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        Guid dispatch = f.Journal.BeginSelectedDispatch(Owner, f.Selector, plan.ResourceId, delete: false);
        using var setup = await f.Source.ProvisionAsync(plan);
        await Assert.That(setup.State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(f.Wire.Requests.Count).IsEqualTo(0);
        await Assert.That(f.Read().Resources.Single(r => !r.Borrowed).ActiveDispatch).IsEqualTo(dispatch);
    }

    [Test]
    public async Task CancellationBeforeInvocationDoesNotBorrowOrDispatch()
    {
        await using var f = new Fixture();
        var plan = f.Plan();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.That(async () => await f.Source.ProvisionAsync(plan, cancellation.Token)).Throws<OperationCanceledException>();
        await Assert.That(f.Wire.Requests.Count).IsEqualTo(0);
        await Assert.That(plan.Receipts.Count).IsEqualTo(0);
        await Assert.That(f.Read().Resources.Single(r => !r.Borrowed).CreateAttempted).IsFalse();
    }

    [Test]
    public async Task ClosingWinsBeforePrepareAndPreventsNonceReuse()
    {
        await using var f = new Fixture();
        f.Source.CloseSelectedRoot(Owner, f.Selector);
        await Assert.That(() => f.Plan()).Throws<InvalidOperationException>();
        await Assert.That(f.Wire.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task OwnerFullSelectorAndHostScopeRemainBoundToDurableCoordinates()
    {
        await using var f = new Fixture();
        f.Plan();
        await Assert.That(async () => await f.Source.ReleaseAsync("other", f.Selector)).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Source.ReleaseAsync(Owner,
            f.Selector with { Scope = "other" })).Throws<InvalidOperationException>();
        var foreignVault = new VaultScope(f.Vault.ResourceGroup, "other-fixture");
        await using var foreign = f.Reopen(foreignVault);
        await Assert.That(async () => await foreign.ObserveAsync(Owner, f.Selector)).Throws<InvalidOperationException>();
        await Assert.That(async () => await foreign.ReleaseAsync(Owner, f.Selector)).Throws<InvalidOperationException>();
        await Assert.That(f.Read().Closing).IsFalse();
        await Assert.That(() => foreign.CloseSelectedRoot(Owner, f.Selector)).Throws<InvalidOperationException>();
        await Assert.That(f.Wire.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments(false, true)]
    [Arguments(true, false)]
    public async Task HostDeclarationsAreRequiredBeforeAnyNativeTask(bool exclusive, bool webhook)
    {
        await using var f = new Fixture();
        using var configuration = Config();
        await Assert.That(() => f.Construct(configuration, exclusive, webhook)).Throws<InvalidOperationException>();
        await Assert.That(f.Wire.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task SourceSnapshotSurvivesMutableInputArraysAndCallerMaterialDisposal()
    {
        VaultNotificationEvent[] events = [VaultNotificationEvent.SecretNearExpiry, VaultNotificationEvent.SecretExpired];
        await using var f = new Fixture(events);
        events[0] = VaultNotificationEvent.SecretNewVersionCreated;
        f.Input.Dispose();
        var plan = f.Plan();
        using var result = await f.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(result.Configuration!.EventTypes.Contains(VaultNotificationEvent.SecretNearExpiry)).IsTrue();
        result.Configuration.Dispose();
        using var next = await f.Source.ObserveAsync(Owner, f.Selector);
        await Assert.That(next.Configuration!.Endpoint.Reveal()).IsEqualTo(Endpoint);
        await Assert.That(next.Configuration.DeliveryAttributes[0].Value.Reveal()).IsEqualTo("protected-header");
        await Assert.That(JsonSerializer.Serialize(next).Contains("protected-header", StringComparison.Ordinal)).IsFalse();
        await Assert.That(next.ToString().Contains(Endpoint, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("request")]
    [Arguments("response")]
    [Arguments("row")]
    [Arguments("depth")]
    [Arguments("headers")]
    [Arguments("header-bytes")]
    [Arguments("length")]
    [Arguments("too-many-attributes")]
    public async Task BoundaryBudgetsFailClosedWithoutUnboundedReadsOrMutationReplay(string budget)
    {
        await using var f = new Fixture(requestBudget: budget == "request" ? 1024 : 64 * 1024,
            longEndpoint: budget == "request", rowBudget: budget == "row" ? 1024 : 64 * 1024);
        var plan = f.Plan();
        if (budget != "request") f.Wire.CreateFault = budget;
        using var result = await f.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsNotEqualTo(Provisioner.State.Ready);
        await Assert.That(f.Wire.Writes <= 1).IsTrue();
        if (budget == "request")
        {
            await Assert.That(f.Wire.Writes).IsEqualTo(0);
            await Assert.That(f.Read().Resources.All(r => !r.CreateAttempted)).IsTrue();
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RequestCompositionStreamBoundsBothAsyncOverloadsAndClearsAliases(bool arrayOverload)
    {
        using var buffer = new Provisioner.RequestBuffer(4);
        byte[] value = [1, 2, 3, 4];
        if (arrayOverload) await buffer.WriteAsync(value, 0, value.Length, CancellationToken.None);
        else await buffer.WriteAsync(value.AsMemory());
        value[0] = 99;
        await Assert.That(buffer.Written.Span[0]).IsEqualTo((byte)1);
        ReadOnlyMemory<byte> retained = buffer.Written;
        await Assert.That(async () =>
        {
            if (arrayOverload) await buffer.WriteAsync(value, 0, 1, CancellationToken.None);
            else await buffer.WriteAsync(value.AsMemory(0, 1));
        }).Throws<InvalidOperationException>();
        buffer.Dispose();
        await Assert.That(retained.ToArray().All(b => b == 0)).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task BufferedResponseReadOverloadsShareOwnedStorageAndCancellation(bool arrayOverload)
    {
        byte[] bytes = [1, 2, 3, 4];
        using var stream = new Provisioner.OwnedStream(bytes);
        ReadOnlyMemory<byte> retained = stream.Bytes;
        bytes[0] = 99;
        byte[] result = new byte[4];
        int count = arrayOverload ? await stream.ReadAsync(result, 0, 4, CancellationToken.None) :
            await stream.ReadAsync(result.AsMemory());
        await Assert.That(count).IsEqualTo(4);
        await Assert.That(result.SequenceEqual(new byte[] { 1, 2, 3, 4 })).IsTrue();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.That(async () => arrayOverload
            ? await stream.ReadAsync(result, 0, 4, cancellation.Token)
            : await stream.ReadAsync(result.AsMemory(), cancellation.Token)).Throws<OperationCanceledException>();
        stream.Dispose();
        await Assert.That(retained.ToArray().All(b => b == 0)).IsTrue();
        await Assert.That(bytes[0]).IsEqualTo((byte)99);
    }

    [Test]
    public async Task NativeConsumerCloseCannotEraseSourceOwnedCachedResponse()
    {
        using var stream = new Provisioner.OwnedStream(new byte[] { 1, 2, 3 }, leaveOpen: true);
        ReadOnlyMemory<byte> retained = stream.Bytes;
        stream.Dispose();
        byte[] first = new byte[3];
        await stream.ReadExactlyAsync(first);
        await Assert.That(first.SequenceEqual(new byte[] { 1, 2, 3 })).IsTrue();
        // Native Response.Content materializes the entire MemoryStream rather
        // than treating a previously consumed cursor as a second empty reply.
        await Assert.That(stream.ToArray().SequenceEqual(first)).IsTrue();
        stream.Clear();
        await Assert.That(retained.Span.IndexOfAnyExcept((byte)0)).IsEqualTo(-1);
        await Assert.That(stream.CanRead).IsFalse();
    }

    private const string Owner = "notification-source-owner";
    private const string Endpoint = "https://fixture.invalid/owned-webhook?key=protected-endpoint";
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);
    private static readonly Guid Subscription = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static NotificationConfiguration Config(VaultNotificationEvent[]? events = null, bool longEndpoint = false)
    {
        using var header = new NotificationDeliveryAttribute("X-Fixture", NotificationAttributeKind.Static, "protected-header");
        using var dynamic = new NotificationDeliveryAttribute("X-Event", NotificationAttributeKind.Dynamic, "data.ObjectName");
        return new(longEndpoint ? Endpoint + new string('q', 1800) : Endpoint,
            events ?? [VaultNotificationEvent.SecretNearExpiry], [header, dynamic]);
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "notification-source-" + Guid.NewGuid().ToString("N"));
        private readonly HttpClient[] clients;
        private readonly HttpClientTransport[] transports;
        private readonly Credential[] credentials;
        private readonly Provisioner.Limits limits;
        internal readonly VaultScope Vault = new(new(new(Subscription), "fixture-group"), "fixture-vault");
        internal readonly FixtureSelector Selector = new(Guid.NewGuid(), "controlled",
            "a.management.VaultAdministration.CreateOrUpdateNotificationAsync", "events.multiple", "selected-contract");
        internal readonly NotificationConfiguration Input;
        internal readonly RoleFixtureJournal Journal;
        internal readonly ManualTime Clock = new();
        internal readonly WireState Wire = new();
        internal readonly Backend[] Backends;
        internal readonly Provisioner Source;
        internal Provisioner.Plan? Current;
        internal Fixture(VaultNotificationEvent[]? events = null, int requestBudget = 64 * 1024,
            bool longEndpoint = false, int rowBudget = 64 * 1024)
        {
            Directory.CreateDirectory(directory);
            Journal = new(directory);
            Input = Config(events, longEndpoint);
            limits = new(64 * 1024, requestBudget, rowBudget, 16, 32, 8192, TimeSpan.FromSeconds(10));
            Backends = new[] { "setup", "observer" }.Select(role => new Backend(role, Wire)).ToArray();
            clients = Backends.Select(b => new HttpClient(b)).ToArray();
            transports = clients.Select(c => new HttpClientTransport(c)).ToArray();
            credentials = Backends.Select(b => new Credential(b.Role)).ToArray();
            Wire.BeforeMutation = path =>
            {
                var state = Read();
                Wire.Prejournaled &= state.Resources.Any(r => !r.Borrowed && r.Id == path &&
                    r.ActiveDispatch != Guid.Empty && !r.InvocationTerminated) &&
                    state.Resources.Any(r => r.Borrowed && r.Id == Vault.ExportResourceId());
            };
            Source = Construct(Input);
        }
        internal Provisioner Construct(NotificationConfiguration configuration, bool exclusive = true, bool webhook = true,
            VaultScope? vault = null) => new(new RoleFixtureJournal(directory), new(vault ?? Vault, exclusive, webhook),
                configuration, new(credentials[0], transports[0]), new(credentials[1], transports[1]), limits, Clock);
        internal Provisioner Reopen(VaultScope? vault = null)
        {
            using var configuration = Config();
            return Construct(configuration, vault: vault);
        }
        internal Provisioner.Plan Plan(Provisioner.Preparation preparation = Provisioner.Preparation.Present)
        {
            Current = Source.PlanFixture(Owner, Selector, preparation);
            Wire.Id = Current.ResourceId;
            Wire.Name = Current.Scope.SubscriptionName;
            Wire.Vault = Vault.ExportResourceId();
            Wire.Nonce = Selector.Nonce;
            return Current;
        }
        internal RoleFixtureJournal.Snapshot Read() => Journal.Read(Owner, Selector);
        public async ValueTask DisposeAsync()
        {
            // A failing assertion must still unblock a deliberately late task.
            Wire.Resume?.TrySetResult();
            Wire.ReadResume?.TrySetResult();
            await Source.DisposeAsync();
            Input.Dispose();
            foreach (var client in clients) client.Dispose();
            Directory.Delete(directory, true);
        }
    }
    private sealed class Credential(string role) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (requestContext.Scopes.Length != 1 || requestContext.Scopes[0] != "https://management.azure.com/.default")
                throw new InvalidOperationException("controlled-audience");
            return new(role, DateTimeOffset.MaxValue);
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }
    private sealed record RequestRow(string Role, HttpMethod Method, string Path);
    private sealed class Backend(string role, WireState wire) : HttpMessageHandler
    {
        internal string Role => role;
        internal bool Disposed;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            wire.Respond(request, role, cancellationToken);
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
    private sealed class WireState
    {
        internal readonly List<RequestRow> Requests = [];
        internal string Id = "", Name = "", Vault = "";
        internal Guid Nonce;
        internal JsonObject? Resource;
        internal string? CreateFault, DeleteFault, ReadFault;
        internal string NativeState = "Succeeded";
        internal readonly string BorrowedState = "host-vault|runtime-secret|webhook|roles|diagnostics";
        internal bool Prejournaled = true;
        internal Action<string> BeforeMutation = null!;
        internal TaskCompletionSource? Applied, Resume;
        internal TaskCompletionSource? ReadEntered, ReadResume;
        internal int Writes => Requests.Count(r => r.Method != HttpMethod.Get);
        internal void Seed(Provisioner.Plan plan, Guid nonce)
        {
            Id = plan.ResourceId;
            Name = plan.Scope.SubscriptionName;
            Vault = plan.Scope.Vault.ExportResourceId();
            Resource = JsonNode.Parse(JsonSerializer.Serialize(new
            {
                id = Id,
                name = Name,
                type = "Microsoft.EventGrid/eventSubscriptions",
                properties = new
                {
                    topic = Vault,
                    provisioningState = "Succeeded",
                    labels = new[] { "secretkit-fixture-" + nonce.ToString("N") },
                    destination = new
                    {
                        endpointType = "WebHook",
                        properties = new
                        {
                            endpointUrl = Endpoint,
                            deliveryAttributeMappings = new object[]
                            {
                                new { name = "X-Fixture", type = "Static", properties = new { value = "protected-header", isSecret = true } },
                                new { name = "X-Event", type = "Dynamic", properties = new { sourceField = "data.ObjectName" } }
                            }
                        }
                    },
                    filter = new { includedEventTypes = new[] { "Microsoft.KeyVault.SecretNearExpiry" } }
                }
            }))!.AsObject();
        }
        internal async Task<HttpResponseMessage> Respond(HttpRequestMessage request, string role, CancellationToken token)
        {
            string path = request.RequestUri!.AbsolutePath;
            Requests.Add(new(role, request.Method, path));
            if (request.RequestUri.Host != "management.azure.com" || path != Id ||
                request.RequestUri.Query != "?api-version=2025-02-15" ||
                request.Headers.Authorization?.Parameter != role || role == "observer" && request.Method != HttpMethod.Get)
                throw new InvalidOperationException("controlled-fixed-boundary");
            if (request.Method == HttpMethod.Put)
            {
                BeforeMutation(path);
                if (CreateFault == "denied") return Json(403, """{"error":{"code":"Forbidden"}}""");
                Resource = JsonNode.Parse(await request.Content!.ReadAsStringAsync(token))!.AsObject();
                Resource["id"] = Id;
                Resource["name"] = Name;
                Resource["type"] = "Microsoft.EventGrid/eventSubscriptions";
                Resource["properties"]!["topic"] = Vault;
                if (CreateFault == "async") NativeState = "Creating";
                Resource["properties"]!["provisioningState"] = NativeState;
                Applied?.TrySetResult();
                // Deliberately ignores cancellation until the exact late-work
                // barrier: caller cancellation is not native task termination.
                if (Resume is not null) await Resume.Task;
                return Reply(CreateFault, 201, Resource.DeepClone().AsObject());
            }
            if (request.Method == HttpMethod.Delete)
            {
                BeforeMutation(path);
                Resource = null;
                return Reply(DeleteFault, 204, null);
            }
            if (ReadFault == "denied") return Json(403, """{"error":{"code":"Forbidden"}}""");
            if (ReadFault == "oversized") return Json(200, "{\"padding\":\"" + new string('x', 70000) + "\"}");
            if (ReadFault == "redirect") return Json(302, "{}");
            if (Resource is null)
            {
                ReadEntered?.TrySetResult();
                if (ReadResume is not null) await ReadResume.Task;
                return Json(404, """{"error":{"code":"NotFound"}}""");
            }
            var row = Resource.DeepClone().AsObject();
            if (role == "setup") row["properties"]!["provisioningState"] = NativeState;
            return Reply(role == "observer" ? ReadFault : null, 200, row);
        }
        private HttpResponseMessage Reply(string? fault, int status, JsonObject? row)
        {
            if (fault == "lost") throw new IOException("controlled-lost-native-response");
            if (fault == "invalid-json") return Json(200, "{");
            if (fault == "redirect") return Json(302, "{}");
            if (fault == "response") return Json(200, "{\"padding\":\"" + new string('x', 70000) + "\"}");
            if (row is not null)
            {
                var p = row["properties"]!.AsObject();
                var settings = p["destination"]!["properties"]!.AsObject();
                var filter = p["filter"]!.AsObject();
                if (fault == "foreign-id") row["id"] = Id + "-foreign";
                if (fault == "foreign-topic") p["topic"] = Vault + "-foreign";
                if (fault == "foreign-label") p["labels"]![0] = "foreign-fixture";
                if (fault == "hidden-endpoint") { settings.Remove("endpointUrl"); settings["endpointBaseUrl"] = "https://fixture.invalid"; }
                if (fault == "masked-endpoint") settings["endpointUrl"] = "https://fixture.invalid/****";
                if (fault == "omitted-headers") settings.Remove("deliveryAttributeMappings");
                if (fault == "masked-header") settings["deliveryAttributeMappings"]![0]!["properties"]!["value"] = "****";
                if (fault == "omitted-secret-flag") settings["deliveryAttributeMappings"]![0]!["properties"]!.AsObject().Remove("isSecret");
                if (fault == "omitted-events") filter.Remove("includedEventTypes");
                if (fault == "extra-filter") filter["subjectBeginsWith"] = "not-the-baseline";
                if (fault == "extra-destination") settings["maxEventsPerBatch"] = 7;
                if (fault == "changed-endpoint") settings["endpointUrl"] = "https://different.invalid/hook";
                if (fault == "changed-event") filter["includedEventTypes"] = new JsonArray("Microsoft.KeyVault.SecretExpired");
                if (fault == "numeric-event") filter["includedEventTypes"] = new JsonArray("1");
                if (fault == "changed-header") settings["deliveryAttributeMappings"]![0]!["properties"]!["value"] = "changed";
                if (fault == "row") row["padding"] = new string('x', 2000);
                if (fault == "depth")
                {
                    JsonNode deep = new JsonObject();
                    for (int i = 0; i < 20; i++) deep = new JsonObject { ["nested"] = deep };
                    row["padding"] = deep;
                }
                if (fault == "too-many-attributes")
                    for (int i = 0; i < 11; i++)
                        settings["deliveryAttributeMappings"]!.AsArray().Add(new JsonObject
                        {
                            ["name"] = "X-" + i,
                            ["type"] = "Dynamic",
                            ["properties"] = new JsonObject { ["sourceField"] = "data.ObjectName" }
                        });
            }
            string body = row?.ToJsonString() ?? "";
            if (fault == "duplicate") body = body.Insert(1, "\"id\":\"foreign\",");
            var response = Json(fault == "async" ? 201 :
                fault is "202" or "foreign-status" or "unsupported-status" ? 202 : status, body);
            if (fault is "async" or "foreign-status" or "unsupported-status" || status == 201)
                response.Headers.TryAddWithoutValidation("Location", fault == "foreign-status"
                    ? "https://foreign.invalid/status" : "https://management.azure.com" +
                        (fault == "unsupported-status" ? Vault + "/operations/unknown" : Id) + "?api-version=2025-02-15");
            if (fault == "headers")
                for (int i = 0; i < 40; i++) response.Headers.TryAddWithoutValidation("X-Fault-" + i, "x");
            if (fault == "header-bytes") response.Headers.TryAddWithoutValidation("X-Fault", new string('x', 9000));
            if (fault == "length") response.Content.Headers.ContentLength = 70000;
            return response;
        }
        private static HttpResponseMessage Json(int status, string body) => new((HttpStatusCode)status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };
    }
    private sealed class ManualTime : TimeProvider
    {
        private DateTimeOffset now = new(2026, 10, 15, 0, 0, 0, TimeSpan.Zero);
        private readonly List<ManualTimer> timers = [];
        public override DateTimeOffset GetUtcNow() => now;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new ManualTimer(callback, state, now + dueTime);
            timers.Add(timer);
            return timer;
        }
        internal void Advance(TimeSpan amount)
        {
            now += amount;
            foreach (var timer in timers.ToArray())
                if (!timer.Disposed && timer.Due <= now) { timer.Disposed = true; timer.Callback(timer.State); }
        }
        private sealed class ManualTimer(TimerCallback callback, object? state, DateTimeOffset due) : ITimer
        {
            internal readonly TimerCallback Callback = callback;
            internal readonly object? State = state;
            internal readonly DateTimeOffset Due = due;
            internal bool Disposed;
            public bool Change(TimeSpan dueTime, TimeSpan period) => throw new InvalidOperationException("controlled-one-shot-timer");
            public void Dispose() => Disposed = true;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
