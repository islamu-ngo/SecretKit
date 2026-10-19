using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalIntegrationPermissionSourceTests
{
    public static IEnumerable<string> UserFactories() => IntegrationPermissionContract.Operations.Where(op => IntegrationPermissionContract.ActorKind(op) == MemberPermissionActorKind.User);
    [Test]
    [MethodDataSource(nameof(UserFactories))]
    public async Task RoleAndTemplateAssignmentsHaveCanonicalCreationAndRetirementBindings(string operation)
    {
        await using var provider = new InfisicalIntegrationPermissionFixture();
        var result = await InfisicalIntegrationPermissionEffectTests.RunAsync(provider, operation, "permission.Integrations.read", "independent-effect");
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        var packet = provider.ClosedPacket!;
        var assignments = packet.Values<IntegrationPermissionBinding>(IntegrationPermissionJournal.Storage, "bind").Where(b => b.Kind == "role-assignment").ToArray();
        await Assert.That(assignments.Length).IsEqualTo(1);
        await Assert.That(packet.Values<IntegrationPermissionMemberChange>(IntegrationPermissionJournal.Membership, "change")
            .Any(c => c.After?.Assignment == assignments[0].CanonicalId)).IsTrue();
        await Assert.That(packet.Values<IntegrationPermissionRetirement>(IntegrationPermissionJournal.Storage, "retire")
            .Any(r => r.Id == assignments[0].CanonicalId && r.BindingHash == IntegrationPermissionContract.Hash(assignments[0]))).IsTrue();
        await InfisicalIntegrationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task AnAdmittedUnfinishedReadCannotReceiveATerminalCompletenessSeal()
    {
        await using var provider = new InfisicalIntegrationPermissionFixture("delayed-dispatch");
        string operation = IntegrationPermissionContract.Operations[0]; using var env = provider.Environment(operation, IntegrationPermissionAction.Read);
        var root = provider.Root(operation, IntegrationPermissionAction.Read, "independent-effect"); var source = provider.Source.CreateClient();
        using var cap = SecretMaterial.FromText("integration-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        IntegrationPermissionTrial? retained = null;
        var trial = await IntegrationPermissionTrial.OpenAsync(source, root, cap, t => retained = t, deadline.Token);
        await trial.BeginAsync(false, deadline.Token);
        Task entered = provider.DispatchEntered.Task;
        var read = IntegrationPermissionEffects.ReadAsync(env, root, trial.Issued, trial.Rows(false)[0], deadline.Token).AsTask();
        try
        {
            await entered.WaitAsync(deadline.Token);
            var pending = await source.StepAsync(root, IntegrationPermissionStep.ObserveBefore, null, deadline.Token);
            var capture = pending.Journals.Single(j => j.Content.Journal == IntegrationPermissionJournal.Ingress).Content;
            await Assert.That(capture.Pending).IsEqualTo(1);
            await Assert.That(capture.Terminal).IsFalse();
        }
        finally
        {
            provider.DispatchRelease.TrySetResult(); await read.WaitAsync(deadline.Token);
            await retained!.DisposeAsync();
        }
        await InfisicalIntegrationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ReserveAllocatesNoNativeIdsAndOpenAllocatesBoundCanonicalResources()
    {
        await using var provider = new InfisicalIntegrationPermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(IntegrationPermissionContract.Operations[0], IntegrationPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("integration-capability"); using var verify = new IntegrationPermissionVerifier(root);
        var reserved = await source.StepAsync(root, IntegrationPermissionStep.Reserve, cap, CancellationToken.None);
        verify.Check(reserved, IntegrationPermissionStep.Reserve);
        await Assert.That(provider.Generated).IsEqualTo(0);
        var opened = await source.StepAsync(root, IntegrationPermissionStep.Open, null, CancellationToken.None);
        try
        {
            verify.Check(opened, IntegrationPermissionStep.Open);
            await Assert.That(verify.Bindings.Length > 0).IsTrue();
            await Assert.That(verify.Bindings.All(b => Guid.TryParse(b.CanonicalId, out _) && b.IntentHash.Length > 0 &&
                b.InputHash.Length > 0 && b.RequestInputHash.Length > 0 && b.ParentCommit.Length > 0)).IsTrue();
        }
        finally
        {
            verify.Check(await source.StepAsync(root, IntegrationPermissionStep.Close, null, CancellationToken.None), IntegrationPermissionStep.Close);
            foreach (var actor in opened.Actors) actor.Erase();
        }
        await InfisicalIntegrationPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments("lost-open")]
    [Arguments("partial-open")]
    public async Task OriginalRootRecoversCanonicalResourcesWithoutAnyOpenResponse(string fault)
    {
        await using var provider = new InfisicalIntegrationPermissionFixture(fault);
        var root = provider.Root(IntegrationPermissionContract.Operations[0], IntegrationPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("integration-capability"); IntegrationPermissionTrial? retained = null;
        await Rejected(() => IntegrationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, CancellationToken.None).AsTask());
        await Assert.That(provider.Generated > 0 && provider.Remaining > 0).IsTrue();
        await retained!.DisposeAsync(); await InfisicalIntegrationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CleanupFencesAndDrainsIssuerAdmittedBeforeLostOpen()
    {
        await using var provider = new InfisicalIntegrationPermissionFixture("delayed-issuer");
        var root = provider.Root(IntegrationPermissionContract.Operations[0], IntegrationPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("integration-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        IntegrationPermissionTrial? retained = null; Task entered = provider.IssuerEntered.Task, closing = provider.CloseEntered.Task;
        await Rejected(() => IntegrationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token).AsTask());
        await entered.WaitAsync(deadline.Token); int before = provider.Generated;
        var cleanup = retained!.DisposeAsync().AsTask();
        try { await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse(); }
        finally { provider.IssuerRelease.TrySetResult(); await cleanup.WaitAsync(deadline.Token); }
        await Assert.That(provider.Generated).IsEqualTo(before + 1); await InfisicalIntegrationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CleanupDrainsAuthenticatedReadBeforeRetiringOwnedResources()
    {
        await using var provider = new InfisicalIntegrationPermissionFixture("delayed-dispatch");
        string operation = IntegrationPermissionContract.Operations[0]; using var env = provider.Environment(operation, IntegrationPermissionAction.Read);
        var root = provider.Root(operation, IntegrationPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("integration-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        IntegrationPermissionTrial? retained = null;
        var trial = await IntegrationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
        await trial.BeginAsync(false, deadline.Token);
        Task entered = provider.DispatchEntered.Task, closing = provider.CloseEntered.Task;
        var read = IntegrationPermissionEffects.ReadAsync(env, root, trial.Issued, trial.Rows(false)[0], deadline.Token).AsTask();
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
        await Assert.That(provider.ClosedPacket!.Values<IntegrationPermissionCollection>(IntegrationPermissionJournal.Collection, "read").Length).IsEqualTo(1);
        await InfisicalIntegrationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CancellationDuringOpenErasesUnreturnedCredentialsAndAllCaptures()
    {
        await using var provider = new InfisicalIntegrationPermissionFixture("interrupted-open"); var source = provider.Source.CreateClient();
        var root = provider.Root(IntegrationPermissionContract.Operations[0], IntegrationPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("integration-capability"); using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        IntegrationPermissionTrial? retained = null; Task entered = provider.OpenEntered.Task;
        var open = IntegrationPermissionTrial.OpenAsync(source, root, cap, t => retained = t, cancellation.Token).AsTask();
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
        await Rejected(() => source.StepAsync(root, IntegrationPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalIntegrationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task SignatureFailureStillErasesDecodedActorMaterial()
    {
        await using var provider = new InfisicalIntegrationPermissionFixture("forge-Issuer");
        var root = provider.Root(IntegrationPermissionContract.Operations[0], IntegrationPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("integration-capability"); IntegrationPermissionTrial? retained = null;
        await Rejected(() => IntegrationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, CancellationToken.None).AsTask());
        var actors = retained!.Issued.Actors;
        await Assert.That(actors.Any(a => a.Credential.Any(b => b != 0))).IsTrue();
        await retained.DisposeAsync();
        await Assert.That(actors.All(a => a.Credential.All(b => b == 0))).IsTrue();
        await InfisicalIntegrationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ChangedRootAndClosedSessionCannotAdmitMoreWork()
    {
        await using var provider = new InfisicalIntegrationPermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(IntegrationPermissionContract.Operations[0], IntegrationPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("integration-capability");
        await source.StepAsync(root, IntegrationPermissionStep.Reserve, cap, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "foreign" }, IntegrationPermissionStep.Open, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, IntegrationPermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, IntegrationPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalIntegrationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ReadWitnessUsesPooledTransportAndFreshOneUseTokens()
    {
        await using var provider = new InfisicalIntegrationPermissionFixture();
        var result = await InfisicalIntegrationPermissionEffectTests.RunAsync(provider, IntegrationPermissionContract.Operations[0], "permission.Integrations.read", "independent-effect");
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(provider.ConnectionCount <= 2).IsTrue(); // Actual sockets for eleven SDK calls.
        await InfisicalIntegrationPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task ScopeAndActorKindMustMatchTheSelectedFactory(bool scope)
    {
        await using var provider = new InfisicalIntegrationPermissionFixture();
        var root = provider.Root(IntegrationPermissionContract.Operations[0], IntegrationPermissionAction.Read, "independent-effect");
        root = scope ? root with { ScopeProfile = IntegrationPermissionScope.Organization } : root with { ActorKind = MemberPermissionActorKind.User };
        using var cap = SecretMaterial.FromText("integration-capability");
        await Rejected(() => IntegrationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, _ => throw new InvalidOperationException(), CancellationToken.None).AsTask());
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    [Test]
    public async Task DistinctLabelsCannotDisguiseARepeatedWriterKey()
    {
        await using var provider = new InfisicalIntegrationPermissionFixture(); var pins = provider.Profile.Pins.ToArray();
        pins[1] = pins[1] with { Spki = pins[0].Spki };
        await Rejected(() => { IntegrationPermissionVerifier.Validate(provider.Profile with { Pins = pins }); return Task.CompletedTask; });
    }
    internal static async Task Rejected(Func<Task> action)
    {
        bool rejected = false; try { await action(); } catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
    }
}
