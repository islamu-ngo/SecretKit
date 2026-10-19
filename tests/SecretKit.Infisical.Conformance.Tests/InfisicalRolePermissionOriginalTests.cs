using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original routes explicitly select the owned source and retain all factory labels.
public sealed class InfisicalRolePermissionOriginalTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalRolePermissionGateTests.Cases();
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from operation in RolePermissionContract.Operations
        from boundary in RolePermissionContract.Boundaries
        from action in Enum.GetValues<RolePermissionAction>()
        select (operation, boundary, (int)action);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeRoleActionsRequireIndependentEffect(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalRolePermissionFixture(); using var env = provider.Environment(operation, InfisicalRolePermissionGateTests.Action(variant));
        var definition = InfisicalRolePermissionGateTests.Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [definition], rolePermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], rolePermissions: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Assert.That(provider.Opens).IsEqualTo(1);
        await InfisicalRolePermissionEffectTests.Clean(provider);
    }
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task OriginalGenericRetainsAllEightFactoriesAndConfiguredAction(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalRolePermissionFixture(); using var env = provider.Environment(operation, (RolePermissionAction)action);
        var definition = new NativeCaseDefinition(new("Infisical", InfisicalRolePermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalRolePermissionGateTests.Execute].Member);
        var selected = ManagementClientEffects.Resolve(definition, env);
        await Assert.That(selected?.Key.Variant).IsEqualTo(RolePermissionContract.Variant((RolePermissionAction)action));
        var registry = new NativeCaseRegistry(); InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { RolePermissions = provider.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Assert.That(result.Variant).IsEqualTo(definition.Key.Variant);
        await InfisicalRolePermissionEffectTests.Clean(provider);
    }

    public static IEnumerable<(string Operation, string Fault, bool Generic)> Failures() =>
        from operation in RolePermissionContract.Operations
        from fault in new[] { "ignored-policy", "incomplete-policy", "self-policy-overwrite", "wrong-target-role",
            "actor-kind", "binding-borrowed", "forged-journal", "lost-open", "partial-open" }
        from generic in new[] { false, true }
        select (operation, fault, generic);

    [Test]
    [MethodDataSource(nameof(Failures))]
    public async Task OriginalRoutesRejectUnprovenRoleEffectsAndRecover(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalRolePermissionFixture(fault);
        using var env = provider.Environment(operation, RolePermissionAction.Read);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalRolePermissionGateTests.Execute,
            "factory." + operation, "local", "independent-effect"),
            InfisicalGovernanceFamilies.Bindings[InfisicalRolePermissionGateTests.Execute].Member) :
            InfisicalRolePermissionGateTests.Definition(operation, "permission.Role.read", "independent-effect");
        var registry = new NativeCaseRegistry();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [definition],
                new GovernanceObservers { RolePermissions = provider.Source.CreateClient() });
        else if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [definition], rolePermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], rolePermissions: provider.Source.CreateClient());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Closes).IsEqualTo(1);
        await InfisicalRolePermissionEffectTests.Clean(provider);
    }
}
