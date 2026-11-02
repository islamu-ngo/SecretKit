using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original registrars must select the configured independently captured witness.
public sealed class InfisicalIntegrationPermissionOriginalTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary, bool Generic)> Cases() =>
        from row in InfisicalIntegrationPermissionGateTests.Cases()
        from generic in new[] { false, true }
        select (row.Operation, row.Variant, row.Boundary, generic);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalRoutesRequireIndependentIntegrationReadEffects(string operation, string variant, string boundary, bool generic)
    {
        await using var provider = new InfisicalIntegrationPermissionFixture();
        var action = InfisicalIntegrationPermissionGateTests.Action(variant);
        using var env = provider.Environment(operation, action);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalIntegrationPermissionGateTests.Execute,
            "factory." + operation, "local", boundary), InfisicalGovernanceFamilies.Bindings[InfisicalIntegrationPermissionGateTests.Execute].Member) :
            InfisicalIntegrationPermissionGateTests.Definition(operation, variant, boundary);
        if (generic) await Assert.That(ManagementClientEffects.Resolve(definition, env)?.Key.Variant).IsEqualTo(variant);
        var registry = new NativeCaseRegistry();
        if (generic) InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { IntegrationPermissions = provider.Source.CreateClient() });
        else if (InfisicalPermissionFamilies.Owns(operation)) InfisicalPermissionFamilies.Register(registry, env, [definition],
            integrationPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], integrationPermissions: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsEqualTo(action == IntegrationPermissionAction.Read).Because(result.ReasonCode + ";" + provider.Progress);
        await Assert.That(provider.Opens).IsEqualTo(action == IntegrationPermissionAction.Read ? 1 : 0);
        await Assert.That(result.Variant).IsEqualTo(definition.Key.Variant);
        await InfisicalIntegrationPermissionEffectTests.Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, bool Generic)> Failures() =>
        from operation in IntegrationPermissionContract.Operations
        from fault in new[] { "ignored-policy", "wrong-subject", "wrong-actor", "wrong-scope", "wrong-configuration",
            "metadata-storage", "incomplete", "missing-journal", "lost-open", "partial-open" }
        from generic in new[] { false, true }
        select (operation, fault, generic);
    [Test]
    [MethodDataSource(nameof(Failures))]
    public async Task OriginalRoutesRejectUnprovenReadAndRecover(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalIntegrationPermissionFixture(fault);
        using var env = provider.Environment(operation, IntegrationPermissionAction.Read);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalIntegrationPermissionGateTests.Execute,
            "factory." + operation, "local", "independent-effect"), InfisicalGovernanceFamilies.Bindings[InfisicalIntegrationPermissionGateTests.Execute].Member) :
            InfisicalIntegrationPermissionGateTests.Definition(operation, "permission.Integrations.read", "independent-effect");
        var registry = new NativeCaseRegistry();
        if (generic) InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { IntegrationPermissions = provider.Source.CreateClient() });
        else if (InfisicalPermissionFamilies.Owns(operation)) InfisicalPermissionFamilies.Register(registry, env, [definition],
            integrationPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], integrationPermissions: provider.Source.CreateClient());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Closes).IsEqualTo(1);
        await InfisicalIntegrationPermissionEffectTests.Clean(provider);
    }
}
