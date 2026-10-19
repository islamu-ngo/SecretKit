using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using Provisioner = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureProvisioner;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task ExplicitEndpointRefreshPermitsParentDeletePurgeAndFinalRelease()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f) { AllowEndpointDelete = true };
        await using var source = wire.Service();
        await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        await Assert.That((await source.CleanupAsync(parent)).State.ToString()).IsEqualTo("DependenciesAbsent");
        var released = await f.Source.ReleaseAsync(Owner, f.Selector, purge: true, privateEndpointCleanup: source);
        await Assert.That(released.State).IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Read().Released).IsTrue();
        await Assert.That(f.Read().PrivateEndpointAbsent).IsTrue();
        await Assert.That(wire.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
        await Assert.That(wire.Requests.Where(r => r.Method != "GET").All(r => r.Path == wire.Binding.EndpointId)).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ValidatedRestartCanCleanOnlyDurablyOwnedOrSettledEndpointState(bool alreadyDeleted)
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f) { AllowEndpointDelete = true };
        await using (var source = wire.Service())
        {
            await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
            if (alreadyDeleted)
                await Assert.That((await source.CleanupAsync(parent)).State.ToString()).IsEqualTo("DependenciesAbsent");
        }
        await using var cleanup = f.Cleanup();
        var restored = cleanup.OpenCleanupPlan(Owner, f.Selector);
        await Assert.That(cleanup.OwnsPreparedPlan(restored)).IsFalse();
        await using var restarted = wire.Service(cleanup);
        await Assert.That((await restarted.CleanupAsync(restored)).State.ToString()).IsEqualTo("DependenciesAbsent");
        await Assert.That(wire.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
        var released = await cleanup.ReleaseAsync(Owner, f.Selector, purge: true, privateEndpointCleanup: restarted);
        await Assert.That(released.State).IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Read().Released).IsTrue();
    }

    [Test]
    public async Task LostOriginalEndpointDeletionCannotBeReplayedOrSettledByRestartedAbsence()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f) { AllowEndpointDelete = true };
        await using (var source = wire.Service())
        {
            await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
            wire.Fault = "lost-delete";
            await Assert.That((await source.CleanupAsync(parent)).State.ToString()).IsNotEqualTo("DependenciesAbsent");
        }
        var dispatch = f.Read().PrivateEndpoint!.DeletionDispatch;
        await Assert.That(dispatch != Guid.Empty).IsTrue();
        await Assert.That(() => f.Journal.SettleDispatch(Owner, f.Selector, wire.Binding.EndpointId, dispatch))
            .Throws<InvalidOperationException>();
        wire.Fault = null;
        await using var cleanup = f.Cleanup();
        var restored = cleanup.OpenCleanupPlan(Owner, f.Selector);
        await using var restarted = wire.Service(cleanup);
        await Assert.That((await restarted.CleanupAsync(restored)).State.ToString()).IsNotEqualTo("DependenciesAbsent");
        await Assert.That((await restarted.RefreshAbsenceAsync(restored)).State.ToString()).IsNotEqualTo("DependenciesAbsent");
        await Assert.That(f.Read().PrivateEndpoint!.DeletionDispatch).IsEqualTo(dispatch);
        await Assert.That(wire.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
        await Assert.That(f.Read().Released).IsFalse();
    }

    [Test]
    public async Task CompetingJournalRevisionRejectsAnOtherwiseCompleteAbsenceTuple()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f) { AllowEndpointDelete = true };
        await using var source = wire.Service();
        await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        wire.AfterConcrete = () => f.Journal.BeginPrivateEndpointAbsence(Owner, f.Selector, parent.LeaseId);
        await Assert.That((await source.CleanupAsync(parent)).State.ToString()).IsNotEqualTo("DependenciesAbsent");
        await Assert.That(f.Read().PrivateEndpointAbsent).IsFalse();
        wire.AfterConcrete = null;
        await Assert.That((await source.RefreshAbsenceAsync(parent)).State.ToString()).IsEqualTo("DependenciesAbsent");
        await Assert.That(wire.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
    }

    [Test]
    public async Task GenericAndConstructedCandidatesCannotBypassOriginalEndpointDeletionOrAbsence()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f) { AllowEndpointDelete = true };
        await using var source = wire.Service();
        await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        bool endRejected = false, candidateRejected = false;
        wire.BeforeDelete = () =>
        {
            var row = f.Read().Resources.Single(r => r.Id == wire.Binding.EndpointId);
            try { f.Journal.EndDispatch(Owner, f.Selector, row.Id, row.ActiveDispatch, true); }
            catch (InvalidOperationException) { endRejected = true; }
            try { f.Journal.SettlePrivateEndpointDeletion(Owner, f.Selector, parent.LeaseId, new(source)); }
            catch (InvalidOperationException) { candidateRejected = true; }
        };
        await Assert.That((await source.CleanupAsync(parent)).State.ToString()).IsEqualTo("DependenciesAbsent");
        await Assert.That(endRejected && candidateRejected).IsTrue();
        f.Journal.InvalidatePrivateEndpointAbsence(Owner, f.Selector);
        await Assert.That(() => f.Journal.CommitPrivateEndpointAbsence(Owner, f.Selector, parent.LeaseId, new(source)))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Read().PrivateEndpointAbsent).IsFalse();
        await Assert.That((await source.RefreshAbsenceAsync(parent)).State.ToString()).IsEqualTo("DependenciesAbsent");
        await Assert.That(wire.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CleanupCancellationAndDisposalDrainOriginalDeletionWithoutClearingItsFence(bool dispose)
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f) { AllowEndpointDelete = true };
        await using var source = wire.Service();
        await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        wire.BeforeDeleteAsync = async token =>
        {
            using var registration = token.Register(() => canceled.TrySetResult());
            entered.TrySetResult();
            await resume.Task;
        };
        using var cancellation = new CancellationTokenSource();
        var cleanup = source.CleanupAsync(parent, cancellation.Token).AsTask();
        Task? close = null;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            if (dispose) close = source.DisposeAsync().AsTask();
            else cancellation.Cancel();
            await canceled.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(cleanup.IsCompleted || close?.IsCompleted == true).IsFalse();
            await Assert.That(f.Read().PrivateEndpoint!.DeletionDispatch != Guid.Empty).IsTrue();
        }
        finally { resume.TrySetResult(); }
        if (dispose)
        {
            await Assert.That((await cleanup.WaitAsync(TimeSpan.FromSeconds(10))).State.ToString()).IsNotEqualTo("DependenciesAbsent");
            await close!.WaitAsync(TimeSpan.FromSeconds(10));
        }
        else await Assert.That(async () => await cleanup.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        await Assert.That(f.Read().PrivateEndpoint!.DeletionDispatch != Guid.Empty).IsTrue();
        await Assert.That(f.Read().PrivateEndpointAbsent).IsFalse();
        await Assert.That(f.Read().Released).IsFalse();
        await Assert.That(wire.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
    }

    [Test]
    public async Task OriginalEndpointDeletionAndThreeIndependentAbsencesPermitOnlyDependencyCompletion()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f) { AllowEndpointDelete = true };
        await using var source = wire.Service();
        await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        int vaultWrites = f.Writes;
        var result = await source.CleanupAsync(parent);
        await Assert.That(result.State.ToString()).IsEqualTo("DependenciesAbsent");
        var root = f.Read();
        await Assert.That(root.Closing && root.PrivateEndpointAbsent).IsTrue();
        await Assert.That(root.Released).IsFalse();
        await Assert.That(root.PrivateEndpoint!.Connection?.Id).IsEqualTo(wire.ConnectionId);
        await Assert.That(root.PrivateEndpoint.Connection!.Absent).IsTrue();
        await Assert.That(root.PrivateEndpoint.NicAbsent).IsTrue();
        await Assert.That(root.Resources.Single(r => r.Id == wire.Binding.EndpointId).DeleteAttempted).IsTrue();
        await Assert.That(f.Writes).IsEqualTo(vaultWrites);
        await Assert.That(wire.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
        await Assert.That(wire.Requests.Where(r => r.Method != "GET").All(r => r.Path == wire.Binding.EndpointId)).IsTrue();
    }

    [Test]
    public async Task RemainingVaultConnectionRetainsParentUntilAnObservationOnlyRefreshFindsAbsence()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f) { AllowEndpointDelete = true };
        await using var source = wire.Service();
        await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        wire.ConnectionPresent = true;
        await Assert.That((await source.CleanupAsync(parent)).State.ToString()).IsEqualTo("Incomplete");
        int writes = f.Writes;
        await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(f.Writes).IsEqualTo(writes);
        await Assert.That(f.Read().PrivateEndpointAbsent).IsFalse();
        await Assert.That(wire.Requests.Any(r => r.Method == "DELETE" && r.Path == wire.ConnectionId)).IsFalse();
        wire.ConnectionPresent = false;
        await Assert.That((await source.RefreshAbsenceAsync(parent)).State.ToString()).IsEqualTo("DependenciesAbsent");
        await Assert.That(f.Read().PrivateEndpointAbsent).IsTrue();
        await Assert.That(wire.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
    }

    [Test]
    public async Task EndpointAbsenceCannotSubstituteForManagedNicAbsence()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f) { AllowEndpointDelete = true, PreserveNicAfterDelete = true };
        await using var source = wire.Service();
        await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        await Assert.That((await source.CleanupAsync(parent)).State.ToString()).IsEqualTo("Incomplete");
        await Assert.That(f.Read().PrivateEndpoint!.NicAbsent).IsFalse();
        wire.NicExists = false;
        await Assert.That((await source.RefreshAbsenceAsync(parent)).State.ToString()).IsEqualTo("DependenciesAbsent");
        await Assert.That(wire.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
        await Assert.That(wire.Requests.Any(r => r.Method != "GET" && r.Path == wire.Binding.NicId)).IsFalse();
    }

    [Test]
    public async Task NeverDispatchedUnboundEndpointNeedsAbsenceButHasNoDeletionAuthority()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f);
        await using var source = wire.Service();
        await Assert.That((await source.CleanupAsync(parent)).State.ToString()).IsEqualTo("DependenciesAbsent");
        await Assert.That(f.Read().PrivateEndpoint!.Connection).IsNull();
        await Assert.That(f.Read().PrivateEndpointAbsent).IsTrue();
        await Assert.That(wire.Requests.All(r => r.Method == "GET")).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NeverDispatchedMatchingPresenceCannotGrantCleanupOwnership(bool nic)
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f)
        {
            EndpointExists = !nic,
            NicExists = nic,
            AllowEndpointDelete = true
        };
        await using var source = wire.Service();
        await Assert.That((await source.CleanupAsync(parent)).State.ToString()).IsNotEqualTo("DependenciesAbsent");
        await Assert.That(f.Read().PrivateEndpointAbsent).IsFalse();
        await Assert.That(wire.Requests.All(r => r.Method == "GET")).IsTrue();
    }

    [Test]
    public async Task UnboundAdmittedCreationCannotBeCleanedUpOrSettledFromDisappearance()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f) { AllowEndpointDelete = true, Fault = "ambiguous" };
        await using var source = wire.Service();
        await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        var dispatch = f.Read().PrivateEndpoint!.CreationDispatch;
        await Assert.That(dispatch != Guid.Empty).IsTrue();
        wire.EndpointExists = wire.NicExists = false;
        wire.ConnectionPresent = false;
        await Assert.That((await source.CleanupAsync(parent)).State.ToString()).IsNotEqualTo("DependenciesAbsent");
        await Assert.That((await source.RefreshAbsenceAsync(parent)).State.ToString()).IsNotEqualTo("DependenciesAbsent");
        await Assert.That(f.Read().PrivateEndpoint!.CreationDispatch).IsEqualTo(dispatch);
        await Assert.That(wire.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(0);
        await Assert.That(f.Read().Released).IsFalse();
    }
}
