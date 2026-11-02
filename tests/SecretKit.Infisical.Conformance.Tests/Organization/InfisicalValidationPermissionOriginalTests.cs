using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original routes select independently signed validation enforcement evidence.
public sealed class InfisicalValidationPermissionOriginalTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalValidationPermissionGateTests.Cases();
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from operation in ValidationPermissionContract.Operations
        from boundary in ValidationPermissionContract.Boundaries
        from action in Enum.GetValues<ValidationPermissionAction>()
        select (operation, boundary, (int)action);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeRequiresIndependentValidationEffects(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalValidationPermissionFixture(); using var env = provider.Environment(operation, InfisicalValidationPermissionGateTests.Action(variant));
        var definition = InfisicalValidationPermissionGateTests.Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [definition], validationPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], validationPermissions: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode + ";" + provider.Progress);
        await Assert.That(provider.Opens).IsEqualTo(1);
        await InfisicalValidationPermissionEffectTests.Clean(provider);
    }
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task OriginalGenericRetainsFactoryAndConfiguredValidationAction(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalValidationPermissionFixture(); using var env = provider.Environment(operation, (ValidationPermissionAction)action);
        var definition = new NativeCaseDefinition(new("Infisical", InfisicalValidationPermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalValidationPermissionGateTests.Execute].Member);
        await Assert.That(ManagementClientEffects.Resolve(definition, env)?.Key.Variant).IsEqualTo(ValidationPermissionContract.Variant((ValidationPermissionAction)action));
        var registry = new NativeCaseRegistry(); InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { ValidationPermissions = provider.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode + ";" + provider.Progress);
        await Assert.That(result.Variant).IsEqualTo(definition.Key.Variant);
        await InfisicalValidationPermissionEffectTests.Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, bool Generic)> Failures() =>
        from operation in ValidationPermissionContract.Operations
        from fault in new[] { "ignored-policy", "incomplete-policy", "rule-revision", "protected-input",
            "fake-enforcement-success", "authorized-uncommitted", "unauthorized-commit",
            "forged-backend", "lost-open", "partial-open" }
        from generic in new[] { false, true }
        select (operation, fault, generic);

    [Test]
    [MethodDataSource(nameof(Failures))]
    public async Task OriginalRoutesRejectUnprovenEnforcementAndRecover(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalValidationPermissionFixture(fault);
        using var env = provider.Environment(operation, ValidationPermissionAction.Read);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalValidationPermissionGateTests.Execute,
            "factory." + operation, "local", "independent-effect"),
            InfisicalGovernanceFamilies.Bindings[InfisicalValidationPermissionGateTests.Execute].Member) :
            InfisicalValidationPermissionGateTests.Definition(operation, "permission.SecretValidationRules.read", "independent-effect");
        var registry = new NativeCaseRegistry();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [definition],
                new GovernanceObservers { ValidationPermissions = provider.Source.CreateClient() });
        else if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [definition], validationPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], validationPermissions: provider.Source.CreateClient());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Closes).IsEqualTo(1);
        await InfisicalValidationPermissionEffectTests.Clean(provider);
    }
}
