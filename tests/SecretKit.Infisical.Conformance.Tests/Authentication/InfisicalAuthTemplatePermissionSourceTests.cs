using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalAuthTemplatePermissionSourceTests
{
    [Test]
    public async Task SimulatorEnrollmentCannotBeRelabeledAsNativeProviderQualification()
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture();
        var root = provider.Root(AuthTemplatePermissionContract.Operations[0], AuthTemplatePermissionAction.List, "independent-effect") with { Kind = MemberPermissionSourceKind.NativeProvider };
        using var capability = SecretMaterial.FromText("auth-template-capability");
        bool retained = false;
        await Rejected(() => AuthTemplatePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability,
            _ => retained = true, CancellationToken.None).AsTask());
        await Assert.That(retained).IsFalse(); await Assert.That(provider.Generated).IsEqualTo(0);
    }
    [Test]
    public async Task CleanupDrainsAnAdmittedStorageCommitAndRetainsItsCausalHistory()
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture("delayed-storage");
        string operation = AuthTemplatePermissionContract.Operations[0];
        using var env = provider.Environment(operation, AuthTemplatePermissionAction.Edit);
        var root = provider.Root(operation, AuthTemplatePermissionAction.Edit, "independent-effect"); var source = provider.Source.CreateClient();
        using var cap = SecretMaterial.FromText("auth-template-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        AuthTemplatePermissionTrial? retained = null;
        var trial = await AuthTemplatePermissionTrial.OpenAsync(source, root, cap, t => retained = t, deadline.Token);
        await AuthTemplatePermissionEffects.WitnessAsync(env, trial, false, deadline.Token);
        await trial.ArmAsync(deadline.Token);
        await trial.SettleAsync(await AuthTemplatePermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token), deadline.Token);
        await AuthTemplatePermissionEffects.ActivateAsync(env, trial, deadline.Token);
        await trial.BeginAsync(true, deadline.Token);
        Task entered = provider.StorageEntered.Task, closing = provider.CloseEntered.Task;
        var patch = AuthTemplatePermissionEffects.AttemptAsync(env, root, trial.Issued, trial.Rows()[0], deadline.Token).AsTask();
        Task? cleanup = null;
        try
        {
            await entered.WaitAsync(deadline.Token);
            var pending = await source.StepAsync(root, AuthTemplatePermissionStep.ObserveAfter, null, deadline.Token);
            var capture = pending.Journals.Single(j => j.Content.Journal == AuthTemplatePermissionJournal.Storage).Content;
            await Assert.That(capture.Pending).IsEqualTo(1); await Assert.That(capture.Terminal).IsFalse();
            cleanup = retained!.DisposeAsync().AsTask();
            await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse();
        }
        finally
        {
            provider.StorageRelease.TrySetResult(); await patch.WaitAsync(deadline.Token);
            await (cleanup ?? retained!.DisposeAsync().AsTask()).WaitAsync(deadline.Token);
        }
        var change = provider.ClosedPacket!.Values<AuthTemplatePermissionChange>(AuthTemplatePermissionJournal.Storage, "change").Last(c => c.DecisionHash.Length > 0);
        await Assert.That(change.After!.Name).IsEqualTo("auth-changed-" + root.Nonce);
        await Assert.That(change.After.Configuration.Host).IsEqualTo(change.Before!.Configuration.Host);
        await Assert.That(change.Commit.Length > 0).IsTrue();
        await InfisicalAuthTemplatePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task AnAdmittedUnfinishedPatchCannotReceiveATerminalCompletenessSeal()
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture("delayed-dispatch");
        string operation = AuthTemplatePermissionContract.Operations[0]; using var env = provider.Environment(operation, AuthTemplatePermissionAction.Edit);
        var root = provider.Root(operation, AuthTemplatePermissionAction.Edit, "independent-effect"); var source = provider.Source.CreateClient();
        using var cap = SecretMaterial.FromText("auth-template-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        AuthTemplatePermissionTrial? retained = null;
        var trial = await AuthTemplatePermissionTrial.OpenAsync(source, root, cap, t => retained = t, deadline.Token);
        await trial.BeginAsync(false, deadline.Token);
        Task entered = provider.DispatchEntered.Task;
        var read = AuthTemplatePermissionEffects.AttemptAsync(env, root, trial.Issued, trial.Rows()[0], deadline.Token).AsTask();
        try
        {
            await entered.WaitAsync(deadline.Token);
            var pending = await source.StepAsync(root, AuthTemplatePermissionStep.ObserveBefore, null, deadline.Token);
            var capture = pending.Journals.Single(j => j.Content.Journal == AuthTemplatePermissionJournal.Ingress).Content;
            await Assert.That(capture.Pending).IsEqualTo(1);
            await Assert.That(capture.Terminal).IsFalse();
        }
        finally
        {
            provider.DispatchRelease.TrySetResult(); await read.WaitAsync(deadline.Token);
            await retained!.DisposeAsync();
        }
        await InfisicalAuthTemplatePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ReserveAllocatesNoNativeIdsAndOpenAllocatesBoundCanonicalResources()
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(AuthTemplatePermissionContract.Operations[0], AuthTemplatePermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("auth-template-capability"); using var verify = new AuthTemplatePermissionVerifier(root);
        var reserved = await source.StepAsync(root, AuthTemplatePermissionStep.Reserve, cap, CancellationToken.None);
        verify.Check(reserved, AuthTemplatePermissionStep.Reserve);
        await Assert.That(provider.Generated).IsEqualTo(0);
        var opened = await source.StepAsync(root, AuthTemplatePermissionStep.Open, null, CancellationToken.None);
        try
        {
            verify.Check(opened, AuthTemplatePermissionStep.Open);
            await Assert.That(verify.Bindings.Length > 0).IsTrue();
            await Assert.That(verify.Bindings.All(b => Guid.TryParse(b.CanonicalId, out _) && b.IntentHash.Length > 0 &&
                b.InputHash.Length > 0 && b.RequestInputHash.Length > 0 && b.ParentCommit.Length > 0)).IsTrue();
        }
        finally
        {
            verify.Check(await source.StepAsync(root, AuthTemplatePermissionStep.Close, null, CancellationToken.None), AuthTemplatePermissionStep.Close);
            foreach (var actor in opened.Actors) actor.Erase();
        }
        await InfisicalAuthTemplatePermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments("lost-open")]
    [Arguments("partial-open")]
    public async Task OriginalRootRecoversCanonicalResourcesWithoutAnyOpenResponse(string fault)
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture(fault);
        var root = provider.Root(AuthTemplatePermissionContract.Operations[0], AuthTemplatePermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("auth-template-capability"); AuthTemplatePermissionTrial? retained = null;
        await Rejected(() => AuthTemplatePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, CancellationToken.None).AsTask());
        await Assert.That(provider.Generated > 0 && provider.Remaining > 0).IsTrue();
        await retained!.DisposeAsync(); await InfisicalAuthTemplatePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CleanupFencesAndDrainsIssuerAdmittedBeforeLostOpen()
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture("delayed-issuer");
        var root = provider.Root(AuthTemplatePermissionContract.Operations[0], AuthTemplatePermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("auth-template-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        AuthTemplatePermissionTrial? retained = null; Task entered = provider.IssuerEntered.Task, closing = provider.CloseEntered.Task;
        await Rejected(() => AuthTemplatePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token).AsTask());
        await entered.WaitAsync(deadline.Token); int before = provider.Generated;
        var cleanup = retained!.DisposeAsync().AsTask();
        try { await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse(); }
        finally { provider.IssuerRelease.TrySetResult(); await cleanup.WaitAsync(deadline.Token); }
        await Assert.That(provider.Generated).IsEqualTo(before + 1); await InfisicalAuthTemplatePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CleanupDrainsAuthenticatedPatchBeforeRetiringOwnedResources()
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture("delayed-dispatch");
        string operation = AuthTemplatePermissionContract.Operations[0]; using var env = provider.Environment(operation, AuthTemplatePermissionAction.Edit);
        var root = provider.Root(operation, AuthTemplatePermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("auth-template-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        AuthTemplatePermissionTrial? retained = null;
        var trial = await AuthTemplatePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
        await trial.BeginAsync(false, deadline.Token);
        Task entered = provider.DispatchEntered.Task, closing = provider.CloseEntered.Task;
        var read = AuthTemplatePermissionEffects.AttemptAsync(env, root, trial.Issued, trial.Rows()[0], deadline.Token).AsTask();
        Task? cleanup = null;
        try
        {
            await entered.WaitAsync(deadline.Token); cleanup = retained!.DisposeAsync().AsTask();
            await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse();
        }
        finally
        {
            provider.DispatchRelease.TrySetResult(); await read.WaitAsync(deadline.Token);
            await (cleanup ?? retained!.DisposeAsync().AsTask()).WaitAsync(deadline.Token);
        }
        await Assert.That(provider.ClosedPacket!.Values<AuthTemplatePermissionChange>(AuthTemplatePermissionJournal.Storage, "change").Count(c => c.DecisionHash.Length > 0)).IsEqualTo(1);
        await InfisicalAuthTemplatePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CancellationDuringOpenErasesUnreturnedCredentialsAndAllCaptures()
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture("interrupted-open"); var source = provider.Source.CreateClient();
        var root = provider.Root(AuthTemplatePermissionContract.Operations[0], AuthTemplatePermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("auth-template-capability"); using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        AuthTemplatePermissionTrial? retained = null; Task entered = provider.OpenEntered.Task;
        var open = AuthTemplatePermissionTrial.OpenAsync(source, root, cap, t => retained = t, cancellation.Token).AsTask();
        bool cancelled = false;
        try
        {
            await entered.WaitAsync(cancellation.Token); cancellation.Cancel();
            try { await open; } catch (OperationCanceledException) { cancelled = true; }
        }
        finally
        {
            provider.OpenRelease.TrySetResult(); try { await open; } catch (OperationCanceledException) { }
            if (retained is not null) await retained.DisposeAsync();
        }
        await Assert.That(cancelled).IsTrue();
        await Rejected(() => source.StepAsync(root, AuthTemplatePermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalAuthTemplatePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task SignatureFailureStillErasesDecodedActorMaterial()
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture("forge-Issuer");
        var root = provider.Root(AuthTemplatePermissionContract.Operations[0], AuthTemplatePermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("auth-template-capability"); AuthTemplatePermissionTrial? retained = null;
        await Rejected(() => AuthTemplatePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, CancellationToken.None).AsTask());
        var actors = retained!.Issued.Actors;
        await Assert.That(actors.Any(a => a.Credential.Any(b => b != 0))).IsTrue();
        await retained.DisposeAsync();
        await Assert.That(actors.All(a => a.Credential.All(b => b == 0))).IsTrue();
        await InfisicalAuthTemplatePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ChangedRootAndClosedSessionCannotAdmitMoreWork()
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(AuthTemplatePermissionContract.Operations[0], AuthTemplatePermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("auth-template-capability");
        await source.StepAsync(root, AuthTemplatePermissionStep.Reserve, cap, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "foreign" }, AuthTemplatePermissionStep.Open, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, AuthTemplatePermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, AuthTemplatePermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalAuthTemplatePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task PatchWitnessUsesPooledTransportAndFreshOneUseTokens()
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture();
        var result = await InfisicalAuthTemplatePermissionEffectTests.RunAsync(provider, AuthTemplatePermissionContract.Operations[0], AuthTemplatePermissionAction.Edit, "independent-effect");
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(provider.ConnectionCount <= 2).IsTrue(); // Ten patches, eight observer reads and the original mutation.
        await InfisicalAuthTemplatePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task DistinctLabelsCannotDisguiseARepeatedWriterKey()
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture(); var pins = provider.Profile.Pins.ToArray();
        pins[1] = pins[1] with { Spki = pins[0].Spki };
        await Rejected(() => { AuthTemplatePermissionVerifier.Validate(provider.Profile with { Pins = pins }); return Task.CompletedTask; });
    }
    internal static async Task Rejected(Func<Task> action)
    {
        bool rejected = false; try { await action(); } catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
    }
}
