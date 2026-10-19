using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalSettingsPermissionSourceTests
{
    [Test]
    public async Task MissingSdkFieldsAreCoveredByCompleteIndependentConfiguration()
    {
        await using var provider = new InfisicalSettingsPermissionFixture("omitted-sdk-fields");
        var result = await InfisicalSettingsPermissionEffectTests.RunAsync(provider, SettingsPermissionContract.SupportedOperations[0],
            "permission.Settings.edit", "independent-effect");
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        var changed = provider.ClosedPacket!.Values<SettingsPermissionChange>(SettingsPermissionJournal.Storage, "change")
            .Single(c => c.DecisionHash.Length > 0 && c.Commit.Length > 0);
        await Assert.That(changed.After!.Fixed).IsEqualTo(changed.Before!.Fixed);
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CleanupDrainsAnAdmittedStorageCommitAndRetainsItsCausalHistory()
    {
        await using var provider = new InfisicalSettingsPermissionFixture("delayed-storage");
        string operation = SettingsPermissionContract.SupportedOperations[0];
        using var env = provider.Environment(operation, SettingsPermissionAction.Edit);
        var root = provider.Root(operation, SettingsPermissionAction.Edit, "independent-effect"); var source = provider.Source.CreateClient();
        using var cap = SecretMaterial.FromText("settings-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        SettingsPermissionTrial? retained = null;
        var trial = await SettingsPermissionTrial.OpenAsync(source, root, cap, t => retained = t, deadline.Token);
        await SettingsPermissionEffects.WitnessAsync(env, trial, false, deadline.Token);
        await trial.ArmAsync(deadline.Token);
        await trial.SettleAsync(await SettingsPermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token), deadline.Token);
        await trial.BeginAsync(true, deadline.Token);
        Task entered = provider.StorageEntered.Task, closing = provider.CloseEntered.Task;
        var patch = SettingsPermissionEffects.PatchAsync(env, root, trial.Issued, trial.Rows(true)[0], deadline.Token).AsTask();
        Task? cleanup = null;
        try
        {
            await entered.WaitAsync(deadline.Token);
            var pending = await source.StepAsync(root, SettingsPermissionStep.ObserveAfter, null, deadline.Token);
            var capture = pending.Journals.Single(j => j.Content.Journal == SettingsPermissionJournal.Storage).Content;
            await Assert.That(capture.Pending).IsEqualTo(1); await Assert.That(capture.Terminal).IsFalse();
            cleanup = retained!.DisposeAsync().AsTask();
            await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse();
        }
        finally
        {
            provider.StorageRelease.TrySetResult(); await patch.WaitAsync(deadline.Token);
            await (cleanup ?? retained!.DisposeAsync().AsTask()).WaitAsync(deadline.Token);
        }
        var change = provider.ClosedPacket!.Values<SettingsPermissionChange>(SettingsPermissionJournal.Storage, "change").Last(c => c.DecisionHash.Length > 0);
        await Assert.That(change.After!.Name).IsEqualTo("changed-" + root.Nonce);
        await Assert.That(change.After.Fixed).IsEqualTo(change.Before!.Fixed);
        await Assert.That(change.Commit.Length > 0).IsTrue();
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    public static IEnumerable<string> UserFactories() => SettingsPermissionContract.SupportedOperations.Where(op => SettingsPermissionContract.ActorKind(op) == MemberPermissionActorKind.User);
    [Test]
    [MethodDataSource(nameof(UserFactories))]
    public async Task RoleAndTemplateAssignmentsHaveCanonicalCreationAndRetirementBindings(string operation)
    {
        await using var provider = new InfisicalSettingsPermissionFixture();
        var result = await InfisicalSettingsPermissionEffectTests.RunAsync(provider, operation, "permission.Settings.edit", "independent-effect");
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        var packet = provider.ClosedPacket!;
        var assignments = packet.Values<SettingsPermissionBinding>(SettingsPermissionJournal.Storage, "bind").Where(b => b.Kind == "role-assignment").ToArray();
        await Assert.That(assignments.Length).IsEqualTo(1);
        await Assert.That(packet.Values<SettingsPermissionMemberChange>(SettingsPermissionJournal.Membership, "change")
            .Any(c => c.After?.Assignment == assignments[0].CanonicalId)).IsTrue();
        await Assert.That(packet.Values<SettingsPermissionRetirement>(SettingsPermissionJournal.Storage, "retire")
            .Any(r => r.Id == assignments[0].CanonicalId && r.BindingHash == SettingsPermissionContract.Hash(assignments[0]))).IsTrue();
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task AnAdmittedUnfinishedPatchCannotReceiveATerminalCompletenessSeal()
    {
        await using var provider = new InfisicalSettingsPermissionFixture("delayed-dispatch");
        string operation = SettingsPermissionContract.Operations[0]; using var env = provider.Environment(operation, SettingsPermissionAction.Edit);
        var root = provider.Root(operation, SettingsPermissionAction.Edit, "independent-effect"); var source = provider.Source.CreateClient();
        using var cap = SecretMaterial.FromText("settings-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        SettingsPermissionTrial? retained = null;
        var trial = await SettingsPermissionTrial.OpenAsync(source, root, cap, t => retained = t, deadline.Token);
        await trial.BeginAsync(false, deadline.Token);
        Task entered = provider.DispatchEntered.Task;
        var read = SettingsPermissionEffects.PatchAsync(env, root, trial.Issued, trial.Rows(false)[0], deadline.Token).AsTask();
        try
        {
            await entered.WaitAsync(deadline.Token);
            var pending = await source.StepAsync(root, SettingsPermissionStep.ObserveBefore, null, deadline.Token);
            var capture = pending.Journals.Single(j => j.Content.Journal == SettingsPermissionJournal.Ingress).Content;
            await Assert.That(capture.Pending).IsEqualTo(1);
            await Assert.That(capture.Terminal).IsFalse();
        }
        finally
        {
            provider.DispatchRelease.TrySetResult(); await read.WaitAsync(deadline.Token);
            await retained!.DisposeAsync();
        }
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ReserveAllocatesNoNativeIdsAndOpenAllocatesBoundCanonicalResources()
    {
        await using var provider = new InfisicalSettingsPermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(SettingsPermissionContract.Operations[0], SettingsPermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("settings-capability"); using var verify = new SettingsPermissionVerifier(root);
        var reserved = await source.StepAsync(root, SettingsPermissionStep.Reserve, cap, CancellationToken.None);
        verify.Check(reserved, SettingsPermissionStep.Reserve);
        await Assert.That(provider.Generated).IsEqualTo(0);
        var opened = await source.StepAsync(root, SettingsPermissionStep.Open, null, CancellationToken.None);
        try
        {
            verify.Check(opened, SettingsPermissionStep.Open);
            await Assert.That(verify.Bindings.Length > 0).IsTrue();
            await Assert.That(verify.Bindings.All(b => Guid.TryParse(b.CanonicalId, out _) && b.IntentHash.Length > 0 &&
                b.InputHash.Length > 0 && b.RequestInputHash.Length > 0 && b.ParentCommit.Length > 0)).IsTrue();
        }
        finally
        {
            verify.Check(await source.StepAsync(root, SettingsPermissionStep.Close, null, CancellationToken.None), SettingsPermissionStep.Close);
            foreach (var actor in opened.Actors) actor.Erase();
        }
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments("lost-open")]
    [Arguments("partial-open")]
    public async Task OriginalRootRecoversCanonicalResourcesWithoutAnyOpenResponse(string fault)
    {
        await using var provider = new InfisicalSettingsPermissionFixture(fault);
        var root = provider.Root(SettingsPermissionContract.Operations[0], SettingsPermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("settings-capability"); SettingsPermissionTrial? retained = null;
        await Rejected(() => SettingsPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, CancellationToken.None).AsTask());
        await Assert.That(provider.Generated > 0 && provider.Remaining > 0).IsTrue();
        await retained!.DisposeAsync(); await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CleanupFencesAndDrainsIssuerAdmittedBeforeLostOpen()
    {
        await using var provider = new InfisicalSettingsPermissionFixture("delayed-issuer");
        var root = provider.Root(SettingsPermissionContract.Operations[0], SettingsPermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("settings-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        SettingsPermissionTrial? retained = null; Task entered = provider.IssuerEntered.Task, closing = provider.CloseEntered.Task;
        await Rejected(() => SettingsPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token).AsTask());
        await entered.WaitAsync(deadline.Token); int before = provider.Generated;
        var cleanup = retained!.DisposeAsync().AsTask();
        try { await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse(); }
        finally { provider.IssuerRelease.TrySetResult(); await cleanup.WaitAsync(deadline.Token); }
        await Assert.That(provider.Generated).IsEqualTo(before + 1); await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CleanupDrainsAuthenticatedPatchBeforeRetiringOwnedResources()
    {
        await using var provider = new InfisicalSettingsPermissionFixture("delayed-dispatch");
        string operation = SettingsPermissionContract.Operations[0]; using var env = provider.Environment(operation, SettingsPermissionAction.Edit);
        var root = provider.Root(operation, SettingsPermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("settings-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        SettingsPermissionTrial? retained = null;
        var trial = await SettingsPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
        await trial.BeginAsync(false, deadline.Token);
        Task entered = provider.DispatchEntered.Task, closing = provider.CloseEntered.Task;
        var read = SettingsPermissionEffects.PatchAsync(env, root, trial.Issued, trial.Rows(false)[0], deadline.Token).AsTask();
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
        await Assert.That(provider.ClosedPacket!.Values<SettingsPermissionChange>(SettingsPermissionJournal.Storage, "change").Count(c => c.DecisionHash.Length > 0)).IsEqualTo(1);
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CancellationDuringOpenErasesUnreturnedCredentialsAndAllCaptures()
    {
        await using var provider = new InfisicalSettingsPermissionFixture("interrupted-open"); var source = provider.Source.CreateClient();
        var root = provider.Root(SettingsPermissionContract.Operations[0], SettingsPermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("settings-capability"); using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        SettingsPermissionTrial? retained = null; Task entered = provider.OpenEntered.Task;
        var open = SettingsPermissionTrial.OpenAsync(source, root, cap, t => retained = t, cancellation.Token).AsTask();
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
        await Rejected(() => source.StepAsync(root, SettingsPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task SignatureFailureStillErasesDecodedActorMaterial()
    {
        await using var provider = new InfisicalSettingsPermissionFixture("forge-Issuer");
        var root = provider.Root(SettingsPermissionContract.Operations[0], SettingsPermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("settings-capability"); SettingsPermissionTrial? retained = null;
        await Rejected(() => SettingsPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, CancellationToken.None).AsTask());
        var actors = retained!.Issued.Actors;
        await Assert.That(actors.Any(a => a.Credential.Any(b => b != 0))).IsTrue();
        await retained.DisposeAsync();
        await Assert.That(actors.All(a => a.Credential.All(b => b == 0))).IsTrue();
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ChangedRootAndClosedSessionCannotAdmitMoreWork()
    {
        await using var provider = new InfisicalSettingsPermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(SettingsPermissionContract.Operations[0], SettingsPermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("settings-capability");
        await source.StepAsync(root, SettingsPermissionStep.Reserve, cap, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "foreign" }, SettingsPermissionStep.Open, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, SettingsPermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, SettingsPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task PatchWitnessUsesPooledTransportAndFreshOneUseTokens()
    {
        await using var provider = new InfisicalSettingsPermissionFixture();
        var result = await InfisicalSettingsPermissionEffectTests.RunAsync(provider, SettingsPermissionContract.Operations[0], "permission.Settings.edit", "independent-effect");
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(provider.ConnectionCount <= 2).IsTrue(); // Ten patches, eight observer reads and the original mutation.
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task ScopeAndActorKindMustMatchTheSelectedFactory(bool scope)
    {
        await using var provider = new InfisicalSettingsPermissionFixture();
        var root = provider.Root(SettingsPermissionContract.Operations[0], SettingsPermissionAction.Edit, "independent-effect");
        root = scope ? root with { ScopeProfile = SettingsPermissionScope.Organization } : root with { ActorKind = MemberPermissionActorKind.User };
        using var cap = SecretMaterial.FromText("settings-capability");
        await Rejected(() => SettingsPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, _ => throw new InvalidOperationException(), CancellationToken.None).AsTask());
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    [Test]
    public async Task DistinctLabelsCannotDisguiseARepeatedWriterKey()
    {
        await using var provider = new InfisicalSettingsPermissionFixture(); var pins = provider.Profile.Pins.ToArray();
        pins[1] = pins[1] with { Spki = pins[0].Spki };
        await Rejected(() => { SettingsPermissionVerifier.Validate(provider.Profile with { Pins = pins }); return Task.CompletedTask; });
    }
    internal static async Task Rejected(Func<Task> action)
    {
        bool rejected = false; try { await action(); } catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
    }
}
