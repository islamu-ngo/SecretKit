using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original registrar/resolver routes retain their factory labels and explicitly
// select a source independently of the provider transport.
public sealed class InfisicalGroupPermissionOriginalTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalGroupPermissionGateTests.Cases()
        .Where(c => GroupPermissionContract.Gate(GroupPermissionContract.Scope(c.Operation), InfisicalGroupPermissionGateTests.Action(c.Variant)) is null);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeGroupsRouteRequiresIndependentEffect(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalGroupPermissionFixture(); using var env = provider.Environment(operation, InfisicalGroupPermissionGateTests.Action(variant));
        var definition = InfisicalGroupPermissionGateTests.Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [definition], groupPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], groupPermissions: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(provider.Opens).IsEqualTo(1);
        await InfisicalGroupPermissionEffectTests.Clean(provider);
    }
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from operation in GroupPermissionContract.Operations.Take(6)
        from boundary in GroupPermissionContract.Boundaries
        from action in GroupPermissionContract.Supported(GroupPermissionScope.Project)
        select (operation, boundary, (int)action);
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task OriginalGenericFactorySelectsConfiguredGroupAction(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalGroupPermissionFixture(); using var env = provider.Environment(operation, (GroupPermissionAction)action);
        var definition = new NativeCaseDefinition(new("Infisical", InfisicalGroupPermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalGroupPermissionGateTests.Execute].Member);
        var selected = ManagementClientEffects.Resolve(definition, env);
        await Assert.That(selected?.Key.Variant).IsEqualTo(GroupPermissionContract.Variant((GroupPermissionAction)action));
        var registry = new NativeCaseRegistry(); InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { GroupPermissions = provider.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(result.Variant).IsEqualTo(definition.Key.Variant);
        await InfisicalGroupPermissionEffectTests.Clean(provider);
    }

    public static IEnumerable<(string Operation, string Fault, bool Generic)> Failures() =>
        from operation in GroupPermissionContract.Operations
        from fault in new[] { "ignored-policy", "actor-kind", "binding-substitution", "binding-borrowed",
            "forged-journal", "lost-open", "partial-open" }
        from generic in GroupPermissionContract.Operations.Take(6).Contains(operation) ? new[] { false, true } : new[] { false }
        select (operation, fault, generic);

    [Test]
    [MethodDataSource(nameof(Failures))]
    public async Task OriginalRoutesRejectUnboundCanonicalIdsOrPolicyEvidence(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalGroupPermissionFixture(fault);
        using var env = provider.Environment(operation, GroupPermissionAction.Read);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalGroupPermissionGateTests.Execute,
            "factory." + operation, "local", "independent-effect"),
            InfisicalGovernanceFamilies.Bindings[InfisicalGroupPermissionGateTests.Execute].Member) :
            InfisicalGroupPermissionGateTests.Definition(operation, "permission.Groups.read", "independent-effect");
        var registry = new NativeCaseRegistry();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [definition],
                new GovernanceObservers { GroupPermissions = provider.Source.CreateClient() });
        else if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [definition], groupPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], groupPermissions: provider.Source.CreateClient());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Closes).IsEqualTo(1);
        await InfisicalGroupPermissionEffectTests.Clean(provider);
    }
}
