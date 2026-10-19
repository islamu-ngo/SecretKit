using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalGroupPermissionSourceTests
{
    [Test]
    public async Task ReserveHasOnlyLogicalIntentsAndNoCanonicalIds()
    {
        await using var provider = new InfisicalGroupPermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(GroupPermissionContract.Operations[0], GroupPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("group-capability");
        var reserved = await source.StepAsync(root, GroupPermissionStep.Reserve, capability, CancellationToken.None);
        await Assert.That(provider.Generated).IsEqualTo(0);
        await Assert.That(reserved.Issuer.Payload.Content.Bindings.Length).IsEqualTo(0);
        await Assert.That(reserved.Storage.Payload.Content.Bindings.Length).IsEqualTo(0);
        await Assert.That(reserved.Owner.Payload.Content.Intents.Any(i => i.Kind == "group")).IsTrue();
        var opened = await source.StepAsync(root, GroupPermissionStep.Open, null, CancellationToken.None);
        try
        {
            await Assert.That(provider.Generated > 0).IsTrue();
            await Assert.That(GroupPermissionContract.Hash(reserved.Owner.Payload.Content.Intents)).IsEqualTo(GroupPermissionContract.Hash(opened.Owner.Payload.Content.Intents));
            await Assert.That(opened.Storage.Payload.Content.Bindings.All(b => Guid.TryParse(b.CanonicalId, out _))).IsTrue();
            await Assert.That(opened.Storage.Payload.Content.Bindings.Select(b => b.CanonicalId).Distinct().Count()).IsEqualTo(provider.Generated);
        }
        finally
        {
            await source.StepAsync(root, GroupPermissionStep.Close, null, CancellationToken.None);
            foreach (var actor in opened.Owner.Payload.Content.Actors) actor.Erase();
        }
        await InfisicalGroupPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments("lost-open")]
    [Arguments("partial-open")]
    public async Task RootAloneRecoversUnreturnedCanonicalBindings(string fault)
    {
        await using var provider = new InfisicalGroupPermissionFixture(fault);
        var root = provider.Root(GroupPermissionContract.Operations[0], GroupPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("group-capability"); GroupPermissionTrial? retained = null;
        await Rejected(() => GroupPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None).AsTask());
        await Assert.That(provider.Generated > 0).IsTrue();
        await Assert.That(provider.Remaining > 0).IsTrue();
        await retained!.DisposeAsync(); await InfisicalGroupPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task LostOpenCleanupFencesAndDrainsPreviouslyAdmittedIssuer()
    {
        await using var provider = new InfisicalGroupPermissionFixture("delayed-issuer");
        var root = provider.Root(GroupPermissionContract.Operations[0], GroupPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("group-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        GroupPermissionTrial? retained = null; Task admitted = provider.IssuerEntered.Task, closing = provider.CloseEntered.Task;
        await Rejected(() => GroupPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token).AsTask());
        await admitted.WaitAsync(deadline.Token); int before = provider.Generated;
        var cleanup = retained!.DisposeAsync().AsTask();
        try
        {
            await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse();
        }
        finally { provider.IssuerRelease.TrySetResult(); await cleanup.WaitAsync(deadline.Token); }
        await Assert.That(provider.Generated).IsEqualTo(before + 1); await InfisicalGroupPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CancellationDuringOpenReleasesAllOwnedMaterialAndRootRegistration()
    {
        await using var provider = new InfisicalGroupPermissionFixture("interrupted-open"); var source = provider.Source.CreateClient();
        var root = provider.Root(GroupPermissionContract.Operations[2], GroupPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("group-capability"); using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        GroupPermissionTrial? retained = null; Task entered = provider.OpenEntered.Task;
        var open = GroupPermissionTrial.OpenAsync(source, root, capability, t => retained = t, cancellation.Token).AsTask();
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
        await Rejected(() => source.StepAsync(root, GroupPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalGroupPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task RejectedIssuedMaterialIsErasedEvenAfterSignatureFailure()
    {
        await using var provider = new InfisicalGroupPermissionFixture("forged-journal");
        var root = provider.Root(GroupPermissionContract.Operations[2], GroupPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("group-capability"); GroupPermissionTrial? retained = null;
        await Rejected(() => GroupPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None).AsTask());
        var actors = retained!.Issued.Actors;
        await Assert.That(actors.Any(a => a.Credential.Any(v => v != 0))).IsTrue();
        await retained.DisposeAsync(); await Assert.That(actors.All(a => a.Credential.All(v => v == 0))).IsTrue();
        await InfisicalGroupPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ChangedRootOrClosedSessionCannotIssueMoreWork()
    {
        await using var provider = new InfisicalGroupPermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(GroupPermissionContract.Operations[0], GroupPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("group-capability");
        await source.StepAsync(root, GroupPermissionStep.Reserve, cap, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "different" }, GroupPermissionStep.Open, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, GroupPermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, GroupPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalGroupPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task FactoryScopeAndActorKindAreExplicit(bool scope)
    {
        await using var provider = new InfisicalGroupPermissionFixture();
        var root = provider.Root(GroupPermissionContract.Operations[0], GroupPermissionAction.Read, "independent-effect");
        root = scope ? root with { ScopeProfile = GroupPermissionScope.Organization } : root with { ActorKind = MemberPermissionActorKind.User };
        using var cap = SecretMaterial.FromText("group-capability");
        await Rejected(() => GroupPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, _ => throw new InvalidOperationException(), CancellationToken.None).AsTask());
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    [Test]
    public async Task RepeatedKeyDoesNotEstablishIndependentJournals()
    {
        await using var provider = new InfisicalGroupPermissionFixture(); var pins = provider.Profile.Pins.ToArray();
        pins[1] = pins[1] with { Spki = pins[0].Spki };
        await Rejected(() => { GroupPermissionVerifier.Validate(provider.Profile with { Pins = pins }); return Task.CompletedTask; });
    }
    internal static async Task Rejected(Func<Task> action)
    {
        bool rejected = false; try { await action(); } catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
    }
}
