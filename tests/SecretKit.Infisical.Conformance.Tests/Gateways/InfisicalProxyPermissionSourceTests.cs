using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalProxyPermissionSourceTests
{
    [Test]
    public async Task ReserveHasOnlyLogicalIntentsAndNoCanonicalIds()
    {
        await using var provider = new InfisicalProxyPermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(ProxyPermissionContract.Operations[0], ProxyPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("proxy-capability");
        var reserved = await source.StepAsync(root, ProxyPermissionStep.Reserve, capability, CancellationToken.None);
        await Assert.That(provider.Generated).IsEqualTo(0);
        await Assert.That(reserved.Issuer.Payload.Content.Bindings.Length).IsEqualTo(0);
        await Assert.That(reserved.Storage.Payload.Content.Bindings.Length).IsEqualTo(0);
        await Assert.That(reserved.Owner.Payload.Content.Intents.Any(i => i.Kind == "service")).IsTrue();
        var opened = await source.StepAsync(root, ProxyPermissionStep.Open, null, CancellationToken.None);
        try
        {
            await Assert.That(provider.Generated > 0).IsTrue();
            await Assert.That(ProxyPermissionContract.Hash(reserved.Owner.Payload.Content.Intents)).IsEqualTo(ProxyPermissionContract.Hash(opened.Owner.Payload.Content.Intents));
            await Assert.That(opened.Storage.Payload.Content.Bindings.All(b => Guid.TryParse(b.CanonicalId, out _))).IsTrue();
            await Assert.That(opened.Storage.Payload.Content.Bindings.Select(b => b.CanonicalId).Distinct().Count()).IsEqualTo(provider.Generated);
        }
        finally
        {
            await source.StepAsync(root, ProxyPermissionStep.Close, null, CancellationToken.None);
            foreach (var actor in opened.Owner.Payload.Content.Actors) actor.Erase();
        }
        await InfisicalProxyPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments("lost-open")]
    [Arguments("partial-open")]
    public async Task RootAloneRecoversUnreturnedCanonicalBindings(string fault)
    {
        await using var provider = new InfisicalProxyPermissionFixture(fault);
        var root = provider.Root(ProxyPermissionContract.Operations[0], ProxyPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("proxy-capability"); ProxyPermissionTrial? retained = null;
        await Rejected(() => ProxyPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None).AsTask());
        await Assert.That(provider.Generated > 0).IsTrue();
        await Assert.That(provider.Remaining > 0).IsTrue();
        await retained!.DisposeAsync(); await InfisicalProxyPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task LostOpenCleanupFencesAndDrainsPreviouslyAdmittedIssuer()
    {
        await using var provider = new InfisicalProxyPermissionFixture("delayed-issuer");
        var root = provider.Root(ProxyPermissionContract.Operations[0], ProxyPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("proxy-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        ProxyPermissionTrial? retained = null; Task admitted = provider.IssuerEntered.Task, closing = provider.CloseEntered.Task;
        await Rejected(() => ProxyPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token).AsTask());
        await admitted.WaitAsync(deadline.Token); int before = provider.Generated;
        var cleanup = retained!.DisposeAsync().AsTask();
        try
        {
            await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse();
        }
        finally { provider.IssuerRelease.TrySetResult(); await cleanup.WaitAsync(deadline.Token); }
        await Assert.That(provider.Generated).IsEqualTo(before + 1); await InfisicalProxyPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CancellationDuringOpenReleasesAllOwnedMaterialAndRootRegistration()
    {
        await using var provider = new InfisicalProxyPermissionFixture("interrupted-open"); var source = provider.Source.CreateClient();
        var root = provider.Root(ProxyPermissionContract.Operations[0], ProxyPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("proxy-capability"); using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        ProxyPermissionTrial? retained = null; Task entered = provider.OpenEntered.Task;
        var open = ProxyPermissionTrial.OpenAsync(source, root, capability, t => retained = t, cancellation.Token).AsTask();
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
        await Rejected(() => source.StepAsync(root, ProxyPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalProxyPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task RejectedIssuedMaterialIsErasedEvenAfterSignatureFailure()
    {
        await using var provider = new InfisicalProxyPermissionFixture("forged-journal");
        var root = provider.Root(ProxyPermissionContract.Operations[0], ProxyPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("proxy-capability"); ProxyPermissionTrial? retained = null;
        await Rejected(() => ProxyPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None).AsTask());
        var actors = retained!.Issued.Actors;
        await Assert.That(actors.Any(a => a.Credential.Any(v => v != 0))).IsTrue();
        await retained.DisposeAsync(); await Assert.That(actors.All(a => a.Credential.All(v => v == 0))).IsTrue();
        await InfisicalProxyPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ChangedRootOrClosedSessionCannotIssueMoreWork()
    {
        await using var provider = new InfisicalProxyPermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(ProxyPermissionContract.Operations[0], ProxyPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("proxy-capability");
        await source.StepAsync(root, ProxyPermissionStep.Reserve, cap, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "different" }, ProxyPermissionStep.Open, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, ProxyPermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, ProxyPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalProxyPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task FactoryScopeAndActorKindAreExplicit(bool scope)
    {
        await using var provider = new InfisicalProxyPermissionFixture();
        var root = provider.Root(ProxyPermissionContract.Operations[0], ProxyPermissionAction.Read, "independent-effect");
        root = scope ? root with { ScopeProfile = ProxyPermissionScope.Organization } : root with { ActorKind = MemberPermissionActorKind.User };
        using var cap = SecretMaterial.FromText("proxy-capability");
        await Rejected(() => ProxyPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, _ => throw new InvalidOperationException(), CancellationToken.None).AsTask());
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    [Test]
    public async Task RepeatedKeyDoesNotEstablishIndependentJournals()
    {
        await using var provider = new InfisicalProxyPermissionFixture(); var pins = provider.Profile.Pins.ToArray();
        pins[1] = pins[1] with { Spki = pins[0].Spki };
        await Rejected(() => { ProxyPermissionVerifier.Validate(provider.Profile with { Pins = pins }); return Task.CompletedTask; });
    }
    [Test]
    public async Task CloseDrainsCommittedDispatchWhoseCanonicalIdsNeverReturned()
    {
        await using var provider = new InfisicalProxyPermissionFixture("delayed-dispatch");
        string operation = ProxyPermissionContract.Operations.Single(op => op.EndsWith(".UpdateProjectPrivilege", StringComparison.Ordinal));
        using var env = provider.Environment(operation, ProxyPermissionAction.Read);
        var root = provider.Root(operation, ProxyPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("proxy-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
        ProxyPermissionTrial? retained = null; Task committed = provider.DispatchEntered.Task, closing = provider.CloseEntered.Task;
        var trial = await ProxyPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token);
        await trial.BeginAsync(false, deadline.Token);
        var row = trial.Rows(false).Single(r => r.Action == ProxyPermissionAction.Create && r.Control == "selected");
        int before = provider.Generated;
        var dispatch = ProxyPermissionClient.ExecuteAsync(env, root, trial.Plan, trial.Issued, row, cancellation.Token).AsTask();
        Task? cleanup = null;
        try
        {
            await committed.WaitAsync(deadline.Token); cancellation.Cancel();
            bool cancelled = false; try { await dispatch; } catch (OperationCanceledException) { cancelled = true; }
            await Assert.That(cancelled).IsTrue(); await Assert.That(trial.Issued.Id(row.Target)).IsEqualTo("");
            cleanup = retained!.DisposeAsync().AsTask(); await closing.WaitAsync(deadline.Token);
            await Assert.That(cleanup.IsCompleted).IsFalse();
        }
        finally
        {
            provider.DispatchRelease.TrySetResult();
            try { await dispatch; } catch (OperationCanceledException) { }
            if (cleanup is not null) await cleanup.WaitAsync(deadline.Token); else await retained!.DisposeAsync();
        }
        await Assert.That(provider.Generated).IsEqualTo(before + 1);
        await InfisicalProxyPermissionEffectTests.Clean(provider);
    }
    internal static async Task Rejected(Func<Task> action)
    {
        bool rejected = false; try { await action(); } catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
    }
}
