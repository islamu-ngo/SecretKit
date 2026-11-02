using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalRolePermissionSourceTests
{
    [Test]
    public async Task ReserveHasOnlyLogicalIntentsAndNoCanonicalIds()
    {
        await using var provider = new InfisicalRolePermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(RolePermissionContract.Operations[0], RolePermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("role-capability");
        var reserved = await source.StepAsync(root, RolePermissionStep.Reserve, capability, CancellationToken.None);
        await Assert.That(provider.Generated).IsEqualTo(0);
        await Assert.That(reserved.Issuer.Payload.Content.Bindings.Length).IsEqualTo(0);
        await Assert.That(reserved.Storage.Payload.Content.Bindings.Length).IsEqualTo(0);
        await Assert.That(reserved.Owner.Payload.Content.Intents.Any(i => i.Kind == "target-role")).IsTrue();
        var opened = await source.StepAsync(root, RolePermissionStep.Open, null, CancellationToken.None);
        try
        {
            await Assert.That(provider.Generated > 0).IsTrue();
            await Assert.That(RolePermissionContract.Hash(reserved.Owner.Payload.Content.Intents)).IsEqualTo(RolePermissionContract.Hash(opened.Owner.Payload.Content.Intents));
            await Assert.That(opened.Storage.Payload.Content.Bindings.All(b => Guid.TryParse(b.CanonicalId, out _))).IsTrue();
            await Assert.That(opened.Storage.Payload.Content.Bindings.Select(b => b.CanonicalId).Distinct().Count()).IsEqualTo(provider.Generated);
        }
        finally
        {
            await source.StepAsync(root, RolePermissionStep.Close, null, CancellationToken.None);
            foreach (var actor in opened.Owner.Payload.Content.Actors) actor.Erase();
        }
        await InfisicalRolePermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments("lost-open")]
    [Arguments("partial-open")]
    public async Task RootAloneRecoversUnreturnedCanonicalBindings(string fault)
    {
        await using var provider = new InfisicalRolePermissionFixture(fault);
        var root = provider.Root(RolePermissionContract.Operations[0], RolePermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("role-capability"); RolePermissionTrial? retained = null;
        await Rejected(() => RolePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None).AsTask());
        await Assert.That(provider.Generated > 0).IsTrue();
        await Assert.That(provider.Remaining > 0).IsTrue();
        await retained!.DisposeAsync(); await InfisicalRolePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task LostOpenCleanupFencesAndDrainsPreviouslyAdmittedIssuer()
    {
        await using var provider = new InfisicalRolePermissionFixture("delayed-issuer");
        var root = provider.Root(RolePermissionContract.Operations[0], RolePermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("role-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        RolePermissionTrial? retained = null; Task admitted = provider.IssuerEntered.Task, closing = provider.CloseEntered.Task;
        await Rejected(() => RolePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token).AsTask());
        await admitted.WaitAsync(deadline.Token); int before = provider.Generated;
        var cleanup = retained!.DisposeAsync().AsTask();
        try
        {
            await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse();
        }
        finally { provider.IssuerRelease.TrySetResult(); await cleanup.WaitAsync(deadline.Token); }
        await Assert.That(provider.Generated).IsEqualTo(before + 1); await InfisicalRolePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CancellationDuringOpenReleasesAllOwnedMaterialAndRootRegistration()
    {
        await using var provider = new InfisicalRolePermissionFixture("interrupted-open"); var source = provider.Source.CreateClient();
        var root = provider.Root(RolePermissionContract.Operations[0], RolePermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("role-capability"); using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        RolePermissionTrial? retained = null; Task entered = provider.OpenEntered.Task;
        var open = RolePermissionTrial.OpenAsync(source, root, capability, t => retained = t, cancellation.Token).AsTask();
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
        await Rejected(() => source.StepAsync(root, RolePermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalRolePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task RejectedIssuedMaterialIsErasedEvenAfterSignatureFailure()
    {
        await using var provider = new InfisicalRolePermissionFixture("forged-journal");
        var root = provider.Root(RolePermissionContract.Operations[0], RolePermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("role-capability"); RolePermissionTrial? retained = null;
        await Rejected(() => RolePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None).AsTask());
        var actors = retained!.Issued.Actors;
        await Assert.That(actors.Any(a => a.Credential.Any(v => v != 0))).IsTrue();
        await retained.DisposeAsync(); await Assert.That(actors.All(a => a.Credential.All(v => v == 0))).IsTrue();
        await InfisicalRolePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ChangedRootOrClosedSessionCannotIssueMoreWork()
    {
        await using var provider = new InfisicalRolePermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(RolePermissionContract.Operations[0], RolePermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("role-capability");
        await source.StepAsync(root, RolePermissionStep.Reserve, cap, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "different" }, RolePermissionStep.Open, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, RolePermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, RolePermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalRolePermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task FactoryScopeAndActorKindAreExplicit(bool scope)
    {
        await using var provider = new InfisicalRolePermissionFixture();
        var root = provider.Root(RolePermissionContract.Operations[0], RolePermissionAction.Read, "independent-effect");
        root = scope ? root with { ScopeProfile = RolePermissionScope.Organization } : root with { ActorKind = MemberPermissionActorKind.User };
        using var cap = SecretMaterial.FromText("role-capability");
        await Rejected(() => RolePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, _ => throw new InvalidOperationException(), CancellationToken.None).AsTask());
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    [Test]
    public async Task RepeatedKeyDoesNotEstablishIndependentJournals()
    {
        await using var provider = new InfisicalRolePermissionFixture(); var pins = provider.Profile.Pins.ToArray();
        pins[1] = pins[1] with { Spki = pins[0].Spki };
        await Rejected(() => { RolePermissionVerifier.Validate(provider.Profile with { Pins = pins }); return Task.CompletedTask; });
    }
    [Test]
    public async Task RoleConditionDelegationIsNotInventedForUnconditionalCrud()
    {
        bool projectRejected = false, organizationRejected = false;
        try { _ = new ProjectRolePermission(ProjectRoleSubject.Role, ProjectRoleAction.Read, conditions: [new(RoleConditionField.AssignableRole, RoleStringClause.Literal("no-access"))]); }
        catch (ArgumentException) { projectRejected = true; }
        try { _ = new OrganizationRolePermission(OrganizationRoleSubject.Role, OrganizationRoleAction.Read, conditions: [new(RoleConditionField.AssignableRole, RoleStringClause.Literal("no-access"))]); }
        catch (ArgumentException) { organizationRejected = true; }
        await Assert.That(projectRejected && organizationRejected).IsTrue();
    }
    internal static async Task Rejected(Func<Task> action)
    {
        bool rejected = false; try { await action(); } catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
    }
}
