using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalAuthTemplatePermissionOriginalTests
{
    [Test]
    public async Task ConfiguredNativeListReachesIndependentTemplateWitness()
    {
        await using var fixture = new InfisicalAuthTemplatePermissionFixture();
        using var env = fixture.Environment(AuthTemplatePermissionContract.Operations[0], AuthTemplatePermissionAction.List);
        var definition = InfisicalAuthTemplatePermissionEffectTests.Definition(
            AuthTemplatePermissionContract.Operations[0], AuthTemplatePermissionAction.List, "selected-contract");
        var registry = new NativeCaseRegistry();
        InfisicalPermissionFamilies.Register(registry, env, [definition], authTemplatePermissions: fixture.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await InfisicalAuthTemplatePermissionEffectTests.Clean(fixture);
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task ConfiguredOriginalEntrypointsRetainEveryBoundary(string operation, int action, string boundary, bool generic)
    {
        await using var fixture = new InfisicalAuthTemplatePermissionFixture();
        var result = await ConfiguredAsync(fixture, operation, (AuthTemplatePermissionAction)action, boundary, generic);
        bool supported = action != (int)AuthTemplatePermissionAction.Unlink;
        await Assert.That(result.Passed).IsEqualTo(supported).Because(result.ReasonCode);
        await Assert.That(fixture.Opens).IsEqualTo(supported ? 1 : 0);
        await Assert.That(fixture.Originals).IsEqualTo(supported && boundary != "cancellation-boundary" ? 1 : 0);
        await Assert.That(result.Variant).IsEqualTo(generic ? "factory." + operation :
            AuthTemplatePermissionContract.Variant((AuthTemplatePermissionAction)action));
        await InfisicalAuthTemplatePermissionEffectTests.Clean(fixture);
    }

    public static IEnumerable<(string Operation, int Action, string Fault)> ConfiguredFaults() =>
        InfisicalAuthTemplatePermissionEffectTests.Faults();
    [Test]
    [MethodDataSource(nameof(ConfiguredFaults))]
    public async Task OriginalRoutesRejectAuthorityStateAndRecoveryFaults(string operation, int action, string fault)
    {
        await using var fixture = new InfisicalAuthTemplatePermissionFixture(fault);
        var result = await ConfiguredAsync(fixture, operation, (AuthTemplatePermissionAction)action, "independent-effect", true);
        await Assert.That(result.Passed).IsFalse().Because(fault);
        await Assert.That(fixture.Closes).IsEqualTo(1);
        if (fault is "cleanup" or "borrowed-change")
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        else await InfisicalAuthTemplatePermissionEffectTests.Clean(fixture);
    }

    private static async Task<NativeCaseResult> ConfiguredAsync(InfisicalAuthTemplatePermissionFixture fixture,
        string operation, AuthTemplatePermissionAction action, string boundary, bool generic)
    {
        using var env = fixture.Environment(operation, action);
        var selected = InfisicalAuthTemplatePermissionEffectTests.Definition(operation, action, boundary);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalAuthTemplatePermissionEffectTests.Execute,
            "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalAuthTemplatePermissionEffectTests.Execute].Member) : selected;
        var registry = new NativeCaseRegistry();
        var source = fixture.Source.CreateClient();
        if (generic) InfisicalGovernanceFamilies.Register(registry, env, [definition], new() { AuthTemplatePermissions = source });
        else InfisicalPermissionFamilies.Register(registry, env, [definition], authTemplatePermissions: source);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }

    public static IEnumerable<(string Operation, int Action, string Boundary, bool Generic)> Cases() => InfisicalAuthTemplatePermissionEffectTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalUnconfiguredEntrypointsCannotCertifyTemplatePermissions(string operation, int action, string boundary, bool generic)
    {
        await using var fixture = new InfisicalAuthTemplatePermissionFixture();
        using var env = fixture.Environment(operation, (AuthTemplatePermissionAction)action, false);
        var selected = InfisicalAuthTemplatePermissionEffectTests.Definition(operation, (AuthTemplatePermissionAction)action, boundary);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalAuthTemplatePermissionEffectTests.Execute,
            "factory." + operation, "local", boundary), InfisicalGovernanceFamilies.Bindings[InfisicalAuthTemplatePermissionEffectTests.Execute].Member) : selected;
        var registry = new NativeCaseRegistry();
        if (generic) InfisicalGovernanceFamilies.Register(registry, env, [definition]);
        else InfisicalPermissionFamilies.Register(registry, env, [definition]);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.Variant).IsEqualTo(definition.Key.Variant);
        await Assert.That(fixture.Opens).IsEqualTo(0);
        await InfisicalAuthTemplatePermissionEffectTests.Clean(fixture);
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task LocalUnitMissingConfigurationDoesNotEnrollAnySource(string operation, int action, string boundary, bool generic)
    {
        await using var fixture = new InfisicalAuthTemplatePermissionFixture();
        var result = await InfisicalAuthTemplatePermissionEffectTests.RunAsync(fixture, operation, (AuthTemplatePermissionAction)action, boundary, generic, false);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(fixture.Opens).IsEqualTo(0);
        await InfisicalAuthTemplatePermissionEffectTests.Clean(fixture);
    }
    [Test]
    public async Task UnlinkIsRejectedBeforeRetainingOrEnrollingARoot()
    {
        await using var fixture = new InfisicalAuthTemplatePermissionFixture();
        var root = fixture.Root(AuthTemplatePermissionContract.Operations[0], AuthTemplatePermissionAction.Unlink, "independent-effect");
        using var cap = SecretMaterial.FromText("auth-template-capability"); bool retained = false;
        await InfisicalAuthTemplatePermissionSourceTests.Rejected(() =>
            AuthTemplatePermissionTrial.OpenAsync(fixture.Source.CreateClient(), root, cap, _ => retained = true, CancellationToken.None).AsTask());
        await Assert.That(retained).IsFalse();
        await Assert.That(fixture.Generated).IsEqualTo(0);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
    }
    public static IEnumerable<(string Operation, string Fault, int Outcome)> Lost() =>
        from op in AuthTemplatePermissionContract.Operations
        from row in new[] { ("lost-nonapplied", 0), ("partial", 2) }
        select (op, row.Item1, row.Item2);
    [Test]
    [MethodDataSource(nameof(Lost))]
    public async Task LostOriginalOutcomeReconcilesWithoutMutationReplay(string operation, string fault, int outcome)
    {
        await using var fixture = new InfisicalAuthTemplatePermissionFixture(fault);
        using var env = fixture.Environment(operation, AuthTemplatePermissionAction.Edit);
        var root = fixture.Root(operation, AuthTemplatePermissionAction.Edit, "lost-response-no-replay");
        using var cap = SecretMaterial.FromText("auth-template-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        AuthTemplatePermissionTrial? retained = null;
        try
        {
            var trial = await AuthTemplatePermissionTrial.OpenAsync(fixture.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
            await AuthTemplatePermissionEffects.WitnessAsync(env, trial, false, deadline.Token); await trial.ArmAsync(deadline.Token);
            var receipt = await AuthTemplatePermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token);
            await trial.SettleAsync(receipt, deadline.Token);
            await Assert.That((int)trial.Outcome).IsEqualTo(outcome);
            await Assert.That(ReferenceEquals(receipt, trial.Original)).IsTrue();
            await Assert.That(receipt.Native.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            if (outcome == 0) await AuthTemplatePermissionEffects.WitnessAsync(env, trial, true, deadline.Token);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(fixture.Originals).IsEqualTo(1);
        await InfisicalAuthTemplatePermissionEffectTests.Clean(fixture);
    }
}
