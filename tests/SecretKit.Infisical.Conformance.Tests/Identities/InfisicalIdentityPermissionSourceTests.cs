using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalIdentityPermissionSourceTests
{
    [Test]
    public async Task ReserveHasOnlyLogicalIntentsAndNoCanonicalIds()
    {
        await using var provider = new InfisicalIdentityPermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(IdentityPermissionContract.Operations[0], IdentityPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("identity-capability");
        var reserved = await source.StepAsync(root, IdentityPermissionStep.Reserve, capability, CancellationToken.None);
        await Assert.That(provider.Generated).IsEqualTo(0);
        await Assert.That(reserved.Issuer.Payload.Content.Bindings.Length).IsEqualTo(0);
        await Assert.That(reserved.Storage.Payload.Content.Bindings.Length).IsEqualTo(0);
        await Assert.That(reserved.Owner.Payload.Content.Intents.Any(i => i.Kind == "target-token")).IsTrue();
        var opened = await source.StepAsync(root, IdentityPermissionStep.Open, null, CancellationToken.None);
        try
        {
            await Assert.That(provider.Generated > 0).IsTrue();
            await Assert.That(IdentityPermissionContract.Hash(reserved.Owner.Payload.Content.Intents)).IsEqualTo(IdentityPermissionContract.Hash(opened.Owner.Payload.Content.Intents));
            await Assert.That(opened.Storage.Payload.Content.Bindings.All(b => Guid.TryParse(b.CanonicalId, out _))).IsTrue();
            await Assert.That(opened.Storage.Payload.Content.Bindings.Select(b => b.CanonicalId).Distinct().Count()).IsEqualTo(provider.Generated);
        }
        finally
        {
            await source.StepAsync(root, IdentityPermissionStep.Close, null, CancellationToken.None);
            foreach (var actor in opened.Owner.Payload.Content.Actors) actor.Erase();
        }
        await InfisicalIdentityPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments("lost-open")]
    [Arguments("partial-open")]
    public async Task RootAloneRecoversUnreturnedCanonicalBindings(string fault)
    {
        await using var provider = new InfisicalIdentityPermissionFixture(fault);
        var root = provider.Root(IdentityPermissionContract.Operations[0], IdentityPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("identity-capability"); IdentityPermissionTrial? retained = null;
        await Rejected(() => IdentityPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None).AsTask());
        await Assert.That(provider.Generated > 0).IsTrue();
        await Assert.That(provider.Remaining > 0).IsTrue();
        await retained!.DisposeAsync(); await InfisicalIdentityPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task LostOpenCleanupFencesAndDrainsPreviouslyAdmittedIssuer()
    {
        await using var provider = new InfisicalIdentityPermissionFixture("delayed-issuer");
        var root = provider.Root(IdentityPermissionContract.Operations[0], IdentityPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("identity-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        IdentityPermissionTrial? retained = null; Task admitted = provider.IssuerEntered.Task, closing = provider.CloseEntered.Task;
        await Rejected(() => IdentityPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token).AsTask());
        await admitted.WaitAsync(deadline.Token); int before = provider.Generated;
        var cleanup = retained!.DisposeAsync().AsTask();
        try
        {
            await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse();
        }
        finally { provider.IssuerRelease.TrySetResult(); await cleanup.WaitAsync(deadline.Token); }
        await Assert.That(provider.Generated).IsEqualTo(before + 1); await InfisicalIdentityPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CancellationDuringOpenReleasesAllOwnedMaterialAndRootRegistration()
    {
        await using var provider = new InfisicalIdentityPermissionFixture("interrupted-open"); var source = provider.Source.CreateClient();
        var root = provider.Root(IdentityPermissionContract.Operations[2], IdentityPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("identity-capability"); using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        IdentityPermissionTrial? retained = null; Task entered = provider.OpenEntered.Task;
        var open = IdentityPermissionTrial.OpenAsync(source, root, capability, t => retained = t, cancellation.Token).AsTask();
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
        await Rejected(() => source.StepAsync(root, IdentityPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalIdentityPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task RejectedIssuedMaterialIsErasedEvenAfterSignatureFailure()
    {
        await using var provider = new InfisicalIdentityPermissionFixture("forged-journal");
        var root = provider.Root(IdentityPermissionContract.Operations[2], IdentityPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("identity-capability"); IdentityPermissionTrial? retained = null;
        await Rejected(() => IdentityPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None).AsTask());
        var actors = retained!.Issued.Actors;
        await Assert.That(actors.Any(a => a.Credential.Any(v => v != 0))).IsTrue();
        await retained.DisposeAsync(); await Assert.That(actors.All(a => a.Credential.All(v => v == 0))).IsTrue();
        await InfisicalIdentityPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ChangedRootOrClosedSessionCannotIssueMoreWork()
    {
        await using var provider = new InfisicalIdentityPermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(IdentityPermissionContract.Operations[0], IdentityPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("identity-capability");
        await source.StepAsync(root, IdentityPermissionStep.Reserve, cap, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "different" }, IdentityPermissionStep.Open, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, IdentityPermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, IdentityPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalIdentityPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task FactoryScopeAndActorKindAreExplicit(bool scope)
    {
        await using var provider = new InfisicalIdentityPermissionFixture();
        var root = provider.Root(IdentityPermissionContract.Operations[0], IdentityPermissionAction.Read, "independent-effect");
        root = scope ? root with { ScopeProfile = IdentityPermissionScope.Organization } : root with { ActorKind = MemberPermissionActorKind.User };
        using var cap = SecretMaterial.FromText("identity-capability");
        await Rejected(() => IdentityPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, _ => throw new InvalidOperationException(), CancellationToken.None).AsTask());
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    [Test]
    public async Task RepeatedKeyDoesNotEstablishIndependentJournals()
    {
        await using var provider = new InfisicalIdentityPermissionFixture(); var pins = provider.Profile.Pins.ToArray();
        pins[1] = pins[1] with { Spki = pins[0].Spki };
        await Rejected(() => { IdentityPermissionVerifier.Validate(provider.Profile with { Pins = pins }); return Task.CompletedTask; });
    }

    [Test]
    public async Task DeferredPrivateCaptureDrainsBeforeRevocationAndTerminalCleanup()
    {
        await using var provider = new InfisicalIdentityPermissionFixture("deferred-capture");
        string operation = IdentityPermissionContract.Operations[0];
        using var env = provider.Environment(operation, IdentityPermissionAction.CreateToken);
        var root = provider.Root(operation, IdentityPermissionAction.CreateToken, "independent-effect");
        using var cap = SecretMaterial.FromText("identity-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var interruption = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
        IdentityPermissionTrial? retained = null;
        var trial = await IdentityPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
        try
        {
            await IdentityPermissionEffects.WitnessAsync(env, root, trial, false, deadline.Token); await trial.ArmAsync(deadline.Token);
            await trial.SettleAsync(await IdentityPermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token), deadline.Token);
            Task capture = provider.CaptureEntered.Task, closing = provider.CloseEntered.Task;
            var witness = IdentityPermissionEffects.WitnessAsync(env, root, trial, true, interruption.Token).AsTask();
            await capture.WaitAsync(deadline.Token); interruption.Cancel();
            try { await witness; } catch (OperationCanceledException) { }
            var cleanup = retained!.DisposeAsync().AsTask();
            try { await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse(); }
            finally { provider.CaptureRelease.TrySetResult(); await cleanup.WaitAsync(deadline.Token); }
        }
        finally { provider.CaptureRelease.TrySetResult(); if (retained is not null) await retained.DisposeAsync(); }
        await InfisicalIdentityPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ReplayedPrivateCaptureCannotBecomeASecondTokenProof()
    {
        await using var provider = new InfisicalIdentityPermissionFixture();
        var source = new ReplayingCapture(provider.Source.CreateClient());
        var result = await InfisicalIdentityPermissionEffectTests.RunAsync(provider, IdentityPermissionContract.Operations[0],
            "permission.Identity.create-token", "independent-effect", source);
        await Assert.That(source.Reached).IsTrue();
        await Assert.That(result.Passed).IsFalse();
        await InfisicalIdentityPermissionEffectTests.Clean(provider);
    }
    private sealed class ReplayingCapture(IIdentityPermissionSource inner) : IIdentityPermissionSource
    {
        public string Identity => inner.Identity;
        public MemberPermissionSourceKind Kind => inner.Kind;
        internal bool Reached { get; private set; }
        public ValueTask<IdentityPermissionPacket> StepAsync(IdentityPermissionRoot root, IdentityPermissionStep step,
            SecretMaterial? capability, CancellationToken token) => inner.StepAsync(root, step, capability, token);
        public async ValueTask CaptureAsync(IdentityPermissionRoot root, string row, string tokenId, SecretMaterial material, CancellationToken token)
        {
            await inner.CaptureAsync(root, row, tokenId, material, token);
            Reached = true;
            await inner.CaptureAsync(root, row, tokenId, material, token);
        }
    }
    internal static async Task Rejected(Func<Task> action)
    {
        bool rejected = false; try { await action(); } catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
    }
}
