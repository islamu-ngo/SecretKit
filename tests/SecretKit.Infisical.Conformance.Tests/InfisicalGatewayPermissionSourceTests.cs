using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalGatewayPermissionSourceTests
{
    [Test]
    public async Task ReserveHasOnlyLogicalIntentsAndNoCanonicalIds()
    {
        await using var provider = new InfisicalGatewayPermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(GatewayPermissionContract.Operations[0], GatewayPermissionAction.Create, "independent-effect");
        using var capability = SecretMaterial.FromText("gateway-capability");
        var reserved = await source.StepAsync(root, GatewayPermissionStep.Reserve, capability, CancellationToken.None);
        await Assert.That(provider.Generated).IsEqualTo(0);
        await Assert.That(reserved.Issuer.Payload.Content.Bindings.Length).IsEqualTo(0);
        await Assert.That(reserved.Storage.Payload.Content.Bindings.Length).IsEqualTo(0);
        await Assert.That(reserved.Owner.Payload.Content.Intents.Any(i => i.Kind == "gateway")).IsTrue();
        var opened = await source.StepAsync(root, GatewayPermissionStep.Open, null, CancellationToken.None);
        try
        {
            await Assert.That(provider.Generated > 0).IsTrue();
            await Assert.That(GatewayPermissionContract.Hash(reserved.Owner.Payload.Content.Intents)).IsEqualTo(GatewayPermissionContract.Hash(opened.Owner.Payload.Content.Intents));
            await Assert.That(opened.Storage.Payload.Content.Bindings.All(b => Guid.TryParse(b.CanonicalId, out _))).IsTrue();
            await Assert.That(opened.Storage.Payload.Content.Bindings.Select(b => b.CanonicalId).Distinct().Count()).IsEqualTo(provider.Generated);
        }
        finally
        {
            await source.StepAsync(root, GatewayPermissionStep.Close, null, CancellationToken.None);
            foreach (var actor in opened.Owner.Payload.Content.Actors) actor.Erase();
        }
        await InfisicalGatewayPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments("lost-open")]
    [Arguments("partial-open")]
    public async Task RootAloneRecoversUnreturnedCanonicalBindings(string fault)
    {
        await using var provider = new InfisicalGatewayPermissionFixture(fault);
        var root = provider.Root(GatewayPermissionContract.Operations[0], GatewayPermissionAction.Create, "independent-effect");
        using var capability = SecretMaterial.FromText("gateway-capability"); GatewayPermissionTrial? retained = null;
        await Rejected(() => GatewayPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None).AsTask());
        await Assert.That(provider.Generated > 0).IsTrue();
        await Assert.That(provider.Remaining > 0).IsTrue();
        await retained!.DisposeAsync(); await InfisicalGatewayPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task LostOpenCleanupFencesAndDrainsPreviouslyAdmittedIssuer()
    {
        await using var provider = new InfisicalGatewayPermissionFixture("delayed-issuer");
        var root = provider.Root(GatewayPermissionContract.Operations[0], GatewayPermissionAction.Create, "independent-effect");
        using var capability = SecretMaterial.FromText("gateway-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        GatewayPermissionTrial? retained = null; Task admitted = provider.IssuerEntered.Task, closing = provider.CloseEntered.Task;
        await Rejected(() => GatewayPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token).AsTask());
        await admitted.WaitAsync(deadline.Token); int before = provider.Generated;
        var cleanup = retained!.DisposeAsync().AsTask();
        try
        {
            await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse();
        }
        finally { provider.IssuerRelease.TrySetResult(); await cleanup.WaitAsync(deadline.Token); }
        await Assert.That(provider.Generated).IsEqualTo(before + 1); await InfisicalGatewayPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task RootCleanupFencesAndDrainsAnAdmittedGatewayDispatch()
    {
        await using var provider = new InfisicalGatewayPermissionFixture("delayed-dispatch");
        string operation = GatewayPermissionContract.Operations.Single(op => op.EndsWith(".UpdateOrganizationRole", StringComparison.Ordinal));
        using var env = provider.Environment(operation, GatewayPermissionAction.Create);
        var root = provider.Root(operation, GatewayPermissionAction.Create, "independent-effect");
        using var capability = SecretMaterial.FromText("gateway-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        GatewayPermissionTrial? retained = null;
        var trial = await GatewayPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token);
        await trial.BeginAsync(false, deadline.Token);
        var row = trial.Rows(false).Single(r => r.Action == GatewayPermissionAction.Edit);
        var actor = trial.Issued.Actors[0]; using var tokens = new MemberPermissionTokens(actor.Credential);
        using var auth = GatewayAuthenticationInput.Aws("222222222222", "arn:aws:iam::222222222222:role/closed-witness-v2");
        using var request = GatewayAdministrationOperations.Update(root.Organization, trial.Issued.Id(row.Target), new(row.Name + "-edited", auth));
        var client = env.CreateManagementClient(); var authority = new ManagementAuthority(client.Authority, tokens, root.Organization);
        var receipt = client.CreateReceipt(request); Task entered = provider.DispatchEntered.Task, closing = provider.CloseEntered.Task;
        var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token).AsTask();
        Task? cleanup = null;
        try
        {
            await entered.WaitAsync(deadline.Token);
            cleanup = retained!.DisposeAsync().AsTask();
            await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse();
        }
        finally
        {
            provider.DispatchRelease.TrySetResult();
            var result = await execution.WaitAsync(deadline.Token); await Assert.That(result.IsSuccess).IsTrue();
            await (cleanup ?? retained!.DisposeAsync().AsTask()).WaitAsync(deadline.Token);
        }
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await InfisicalGatewayPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CancellationDuringOpenReleasesAllOwnedMaterialAndRootRegistration()
    {
        await using var provider = new InfisicalGatewayPermissionFixture("interrupted-open"); var source = provider.Source.CreateClient();
        var root = provider.Root(GatewayPermissionContract.Operations[0], GatewayPermissionAction.Create, "independent-effect");
        using var capability = SecretMaterial.FromText("gateway-capability"); using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        GatewayPermissionTrial? retained = null; Task entered = provider.OpenEntered.Task;
        var open = GatewayPermissionTrial.OpenAsync(source, root, capability, t => retained = t, cancellation.Token).AsTask();
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
        await Rejected(() => source.StepAsync(root, GatewayPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalGatewayPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task RejectedIssuedMaterialIsErasedEvenAfterSignatureFailure()
    {
        await using var provider = new InfisicalGatewayPermissionFixture("forged-journal");
        var root = provider.Root(GatewayPermissionContract.Operations[0], GatewayPermissionAction.Create, "independent-effect");
        using var capability = SecretMaterial.FromText("gateway-capability"); GatewayPermissionTrial? retained = null;
        await Rejected(() => GatewayPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None).AsTask());
        var actors = retained!.Issued.Actors;
        await Assert.That(actors.Any(a => a.Credential.Any(v => v != 0))).IsTrue();
        await retained.DisposeAsync(); await Assert.That(actors.All(a => a.Credential.All(v => v == 0))).IsTrue();
        await InfisicalGatewayPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ChangedRootOrClosedSessionCannotIssueMoreWork()
    {
        await using var provider = new InfisicalGatewayPermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(GatewayPermissionContract.Operations[0], GatewayPermissionAction.Create, "independent-effect");
        using var cap = SecretMaterial.FromText("gateway-capability");
        await source.StepAsync(root, GatewayPermissionStep.Reserve, cap, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "different" }, GatewayPermissionStep.Open, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, GatewayPermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, GatewayPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalGatewayPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task FactoryScopeAndActorKindAreExplicit(bool scope)
    {
        await using var provider = new InfisicalGatewayPermissionFixture();
        var root = provider.Root(GatewayPermissionContract.Operations[0], GatewayPermissionAction.Create, "independent-effect");
        root = scope ? root with { ScopeProfile = GatewayPermissionScope.Project } : root with { ActorKind = MemberPermissionActorKind.Machine };
        using var cap = SecretMaterial.FromText("gateway-capability");
        await Rejected(() => GatewayPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, _ => throw new InvalidOperationException(), CancellationToken.None).AsTask());
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    [Test]
    public async Task RepeatedKeyDoesNotEstablishIndependentJournals()
    {
        await using var provider = new InfisicalGatewayPermissionFixture(); var pins = provider.Profile.Pins.ToArray();
        pins[1] = pins[1] with { Spki = pins[0].Spki };
        await Rejected(() => { GatewayPermissionVerifier.Validate(provider.Profile with { Pins = pins }); return Task.CompletedTask; });
    }
    internal static async Task Rejected(Func<Task> action)
    {
        bool rejected = false; try { await action(); } catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
    }
}
