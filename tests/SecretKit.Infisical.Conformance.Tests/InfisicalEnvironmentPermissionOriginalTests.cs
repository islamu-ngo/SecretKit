using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original routes explicitly select the owned source and retain all factory labels.
public sealed class InfisicalEnvironmentPermissionOriginalTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalEnvironmentPermissionGateTests.Cases();
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from operation in EnvironmentPermissionContract.Operations
        from boundary in EnvironmentPermissionContract.Boundaries
        from action in Enum.GetValues<EnvironmentPermissionAction>()
        select (operation, boundary, (int)action);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeEnvironmentActionsRequireIndependentEffect(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalEnvironmentPermissionFixture(); using var env = provider.Environment(operation, InfisicalEnvironmentPermissionGateTests.Action(variant));
        var definition = InfisicalEnvironmentPermissionGateTests.Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [definition], environmentPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], environmentPermissions: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Assert.That(provider.Opens).IsEqualTo(1);
        await InfisicalEnvironmentPermissionEffectTests.Clean(provider);
    }
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task OriginalGenericRetainsAllSixFactoriesAndConfiguredAction(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalEnvironmentPermissionFixture(); using var env = provider.Environment(operation, (EnvironmentPermissionAction)action);
        var definition = new NativeCaseDefinition(new("Infisical", InfisicalEnvironmentPermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalEnvironmentPermissionGateTests.Execute].Member);
        var selected = ManagementClientEffects.Resolve(definition, env);
        await Assert.That(selected?.Key.Variant).IsEqualTo(EnvironmentPermissionContract.Variant((EnvironmentPermissionAction)action));
        var registry = new NativeCaseRegistry(); InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { EnvironmentPermissions = provider.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Assert.That(result.Variant).IsEqualTo(definition.Key.Variant);
        await InfisicalEnvironmentPermissionEffectTests.Clean(provider);
    }

    public static IEnumerable<(string Operation, string Fault, bool Generic)> Failures() =>
        from operation in EnvironmentPermissionContract.Operations
        from fault in new[] { "ignored-policy", "incomplete-policy", "self-policy-overwrite", "wrong-environment",
            "missing-deleted-record", "actor-kind", "binding-borrowed", "forged-journal", "lost-open", "partial-open" }
        from generic in new[] { false, true }
        select (operation, fault, generic);

    [Test]
    [MethodDataSource(nameof(Failures))]
    public async Task OriginalRoutesRejectUnprovenEnvironmentEffectsAndRecover(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalEnvironmentPermissionFixture(fault);
        using var env = provider.Environment(operation, EnvironmentPermissionAction.Read);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalEnvironmentPermissionGateTests.Execute,
            "factory." + operation, "local", "independent-effect"),
            InfisicalGovernanceFamilies.Bindings[InfisicalEnvironmentPermissionGateTests.Execute].Member) :
            InfisicalEnvironmentPermissionGateTests.Definition(operation, "permission.Environments.read", "independent-effect");
        var registry = new NativeCaseRegistry();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [definition],
                new GovernanceObservers { EnvironmentPermissions = provider.Source.CreateClient() });
        else if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [definition], environmentPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], environmentPermissions: provider.Source.CreateClient());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Closes).IsEqualTo(1);
        await InfisicalEnvironmentPermissionEffectTests.Clean(provider);
    }
}
