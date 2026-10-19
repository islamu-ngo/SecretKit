using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalWorkspacePermissionSourceTests
{
    [Test]
    public async Task ReserveHasOnlyLogicalIntentsAndNoCanonicalIds()
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(WorkspacePermissionContract.Operations[0], WorkspacePermissionAction.Delete, "independent-effect");
        using var capability = SecretMaterial.FromText("workspace-capability");
        var reserved = await source.StepAsync(root, WorkspacePermissionStep.Reserve, capability, CancellationToken.None);
        await Assert.That(provider.Generated).IsEqualTo(0);
        await Assert.That(reserved.Issuer.Payload.Content.Bindings.Length).IsEqualTo(0);
        await Assert.That(reserved.Storage.Payload.Content.Bindings.Length).IsEqualTo(0);
        await Assert.That(reserved.Owner.Payload.Content.Intents.Any(i => i.Kind == "project")).IsTrue();
        var opened = await source.StepAsync(root, WorkspacePermissionStep.Open, null, CancellationToken.None);
        try
        {
            await Assert.That(provider.Generated > 0).IsTrue();
            await Assert.That(WorkspacePermissionContract.Hash(reserved.Owner.Payload.Content.Intents)).IsEqualTo(WorkspacePermissionContract.Hash(opened.Owner.Payload.Content.Intents));
            await Assert.That(opened.Storage.Payload.Content.Bindings.All(b => Guid.TryParse(b.CanonicalId, out _))).IsTrue();
            await Assert.That(opened.Storage.Payload.Content.Bindings.Select(b => b.CanonicalId).Distinct().Count()).IsEqualTo(provider.Generated);
        }
        finally
        {
            await source.StepAsync(root, WorkspacePermissionStep.Close, null, CancellationToken.None);
            foreach (var actor in opened.Owner.Payload.Content.Actors) actor.Erase();
        }
        await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments("lost-open")]
    [Arguments("partial-open")]
    public async Task RootAloneRecoversUnreturnedCanonicalBindings(string fault)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(fault);
        var root = provider.Root(WorkspacePermissionContract.Operations[0], WorkspacePermissionAction.Delete, "independent-effect");
        using var capability = SecretMaterial.FromText("workspace-capability"); WorkspacePermissionTrial? retained = null;
        await Rejected(() => WorkspacePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None).AsTask());
        await Assert.That(provider.Generated > 0).IsTrue();
        await Assert.That(provider.Remaining > 0).IsTrue();
        await retained!.DisposeAsync(); await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task LostOpenCleanupFencesAndDrainsPreviouslyAdmittedIssuer()
    {
        await using var provider = new InfisicalWorkspacePermissionFixture("delayed-issuer");
        var root = provider.Root(WorkspacePermissionContract.Operations[0], WorkspacePermissionAction.Delete, "independent-effect");
        using var capability = SecretMaterial.FromText("workspace-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        WorkspacePermissionTrial? retained = null; Task admitted = provider.IssuerEntered.Task, closing = provider.CloseEntered.Task;
        await Rejected(() => WorkspacePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token).AsTask());
        await admitted.WaitAsync(deadline.Token); int before = provider.Generated;
        var cleanup = retained!.DisposeAsync().AsTask();
        try
        {
            await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse();
        }
        finally { provider.IssuerRelease.TrySetResult(); await cleanup.WaitAsync(deadline.Token); }
        await Assert.That(provider.Generated).IsEqualTo(before + 1); await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CleanupFencesAndDrainsAnAdmittedPolicyDispatch()
    {
        await using var provider = new InfisicalWorkspacePermissionFixture("delayed-dispatch");
        string operation = WorkspacePermissionContract.Operations[0];
        using var env = provider.Environment(operation, WorkspacePermissionAction.Delete);
        var root = provider.Root(operation, WorkspacePermissionAction.Delete, "independent-effect");
        using var capability = SecretMaterial.FromText("workspace-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        WorkspacePermissionTrial? retained = null; Task admitted = provider.DispatchEntered.Task, closing = provider.CloseEntered.Task;
        Task<WorkspacePermissionReceipt>? dispatch = null; Task? cleanup = null;
        try
        {
            var trial = await WorkspacePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token);
            await WorkspacePermissionEffects.WitnessAsync(env, root, trial, false, deadline.Token); await trial.ArmAsync(deadline.Token);
            dispatch = WorkspacePermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token).AsTask();
            await admitted.WaitAsync(deadline.Token);
            cleanup = trial.DisposeAsync().AsTask();
            await closing.WaitAsync(deadline.Token);
            await Assert.That(cleanup.IsCompleted).IsFalse();
        }
        finally
        {
            provider.DispatchRelease.TrySetResult();
            if (dispatch is not null) await dispatch.WaitAsync(deadline.Token);
            if (cleanup is not null) await cleanup.WaitAsync(deadline.Token);
            else if (retained is not null) await retained.DisposeAsync();
        }
        await Assert.That(provider.Originals).IsEqualTo(1);
        await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CancellationDuringOpenReleasesAllOwnedMaterialAndRootRegistration()
    {
        await using var provider = new InfisicalWorkspacePermissionFixture("interrupted-open"); var source = provider.Source.CreateClient();
        var root = provider.Root(WorkspacePermissionContract.Operations[0], WorkspacePermissionAction.Delete, "independent-effect");
        using var capability = SecretMaterial.FromText("workspace-capability"); using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        WorkspacePermissionTrial? retained = null; Task entered = provider.OpenEntered.Task;
        var open = WorkspacePermissionTrial.OpenAsync(source, root, capability, t => retained = t, cancellation.Token).AsTask();
        try
        {
            await entered.WaitAsync(cancellation.Token); cancellation.Cancel(); bool cancelled = false;
            try { await open; } catch (OperationCanceledException) { cancelled = true; }
            await Assert.That(cancelled).IsTrue();
        }
        finally
        {
            provider.OpenRelease.TrySetResult(); try { await open; } catch (OperationCanceledException) { }
            if (retained is not null) await retained.DisposeAsync();
        }
        await Rejected(() => source.StepAsync(root, WorkspacePermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task RejectedIssuedMaterialIsErasedEvenAfterSignatureFailure()
    {
        await using var provider = new InfisicalWorkspacePermissionFixture("forged-journal");
        var root = provider.Root(WorkspacePermissionContract.Operations[0], WorkspacePermissionAction.Delete, "independent-effect");
        using var capability = SecretMaterial.FromText("workspace-capability"); WorkspacePermissionTrial? retained = null;
        await Rejected(() => WorkspacePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None).AsTask());
        var actors = retained!.Issued.Actors;
        await Assert.That(actors.Any(a => a.Credential.Any(v => v != 0))).IsTrue();
        await retained.DisposeAsync(); await Assert.That(actors.All(a => a.Credential.All(v => v == 0))).IsTrue();
        await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments("lost-membership-binding")]
    [Arguments("lost-policy-binding")]
    public async Task MissingCanonicalMembershipCannotBecomeAnAcceptedEmptyIdentifier(string fault)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(fault);
        string operation = WorkspacePermissionContract.Operations[fault == "lost-policy-binding" ? 7 : 0];
        var root = provider.Root(operation, WorkspacePermissionContract.Supported(WorkspacePermissionContract.Scope(operation))[0], "independent-effect");
        using var capability = SecretMaterial.FromText("workspace-capability"); WorkspacePermissionTrial? retained = null;
        bool rejected = false;
        try
        {
            await WorkspacePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None);
        }
        catch (NativeCaseFailureException) { rejected = true; }
        finally
        {
            if (retained is not null)
            {
                try { await retained.DisposeAsync(); }
                // An inconsistent earlier complete ledger cannot certify cleanup,
                // even when original-root recovery removes the actual resources.
                catch (NativeCaseFailureException error) { await Assert.That(error.Message).IsEqualTo("cleanup-incomplete"); }
            }
        }
        await Assert.That(rejected).IsTrue();
        await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ChangedRootOrClosedSessionCannotIssueMoreWork()
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(WorkspacePermissionContract.Operations[0], WorkspacePermissionAction.Delete, "independent-effect");
        using var cap = SecretMaterial.FromText("workspace-capability");
        await source.StepAsync(root, WorkspacePermissionStep.Reserve, cap, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "different" }, WorkspacePermissionStep.Open, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, WorkspacePermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, WorkspacePermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task FactoryScopeAndActorKindAreExplicit(bool scope)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture();
        var root = provider.Root(WorkspacePermissionContract.Operations[0], WorkspacePermissionAction.Delete, "independent-effect");
        root = scope ? root with { ScopeProfile = WorkspacePermissionScope.Organization } : root with { ActorKind = MemberPermissionActorKind.User };
        using var cap = SecretMaterial.FromText("workspace-capability");
        await Rejected(() => WorkspacePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, _ => throw new InvalidOperationException(), CancellationToken.None).AsTask());
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    [Test]
    public async Task RepeatedKeyDoesNotEstablishIndependentJournals()
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(); var pins = provider.Profile.Pins.ToArray();
        pins[1] = pins[1] with { Spki = pins[0].Spki };
        await Rejected(() => { WorkspacePermissionVerifier.Validate(provider.Profile with { Pins = pins }); return Task.CompletedTask; });
    }
    internal static async Task Rejected(Func<Task> action)
    {
        bool rejected = false; try { await action(); } catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
    }
}
