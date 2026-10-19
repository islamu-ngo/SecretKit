using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original routes explicitly select independent Gateway configuration evidence.
public sealed class InfisicalGatewayPermissionOriginalTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalGatewayPermissionGateTests.SupportedCases();
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from operation in GatewayPermissionContract.Operations
        from boundary in GatewayPermissionContract.Boundaries
        from action in GatewayPermissionContract.Supported(GatewayPermissionScope.Organization)
        select (operation, boundary, (int)action);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeGatewayActionsRequireIndependentEffect(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalGatewayPermissionFixture(); using var env = provider.Environment(operation, InfisicalGatewayPermissionGateTests.Action(variant));
        var definition = InfisicalGatewayPermissionGateTests.Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        InfisicalPermissionFamilies.Register(registry, env, [definition], gatewayPermissions: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Assert.That(provider.Opens).IsEqualTo(1);
        await InfisicalGatewayPermissionEffectTests.Clean(provider);
    }
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task OriginalGenericMustResolveConfiguredGatewayAction(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalGatewayPermissionFixture(); using var env = provider.Environment(operation, (GatewayPermissionAction)action);
        var definition = new NativeCaseDefinition(new("Infisical", InfisicalGatewayPermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalGatewayPermissionGateTests.Execute].Member);
        await Assert.That(ManagementClientEffects.Resolve(definition, env)?.Key.Variant).IsEqualTo(GatewayPermissionContract.Variant((GatewayPermissionAction)action));
        var registry = new NativeCaseRegistry(); InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { GatewayPermissions = provider.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Assert.That(provider.Opens).IsEqualTo(1);
        await Assert.That(result.Variant).IsEqualTo(definition.Key.Variant);
        await InfisicalGatewayPermissionEffectTests.Clean(provider);
    }

    public static IEnumerable<(string Operation, string Variant, string Boundary, bool Generic)> MissingCases() =>
        from c in InfisicalGatewayPermissionGateTests.MissingCases()
        from generic in new[] { false, true }
        select (c.Operation, c.Variant, c.Boundary, generic);

    [Test]
    [MethodDataSource(nameof(MissingCases))]
    public async Task OriginalMissingSeamsKeepConfiguredActionAndNeverDispatch(string operation, string variant, string boundary, bool generic)
    {
        await using var provider = new InfisicalGatewayPermissionFixture();
        using var env = provider.Environment(operation, InfisicalGatewayPermissionGateTests.Action(variant));
        var definition = Definition(operation, variant, boundary, generic);
        var registry = Register(provider, env, definition, generic);
        if (generic) await Assert.That(ManagementClientEffects.Resolve(definition, env)?.Key.Variant).IsEqualTo(variant);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
        await Assert.That(provider.Originals).IsEqualTo(0);
        await InfisicalGatewayPermissionEffectTests.Clean(provider);
    }

    public static IEnumerable<(string Operation, int Action, string Fault, bool Generic)> Failures() =>
        from operation in GatewayPermissionContract.Operations
        from action in GatewayPermissionContract.Supported(GatewayPermissionScope.Organization)
        from fault in new[] { "ignored-policy", "incomplete-policy", "config-parent", "config-request",
            "config-id-history", "forged-config", "lost-open", "partial-open" }
        from generic in new[] { false, true }
        select (operation, (int)action, fault, generic);

    [Test]
    [MethodDataSource(nameof(Failures))]
    public async Task OriginalRoutesRejectUnprovenConfigurationAndRecover(string operation, int action, string fault, bool generic)
    {
        await using var provider = new InfisicalGatewayPermissionFixture(fault, retainConfigId: false);
        using var env = provider.Environment(operation, (GatewayPermissionAction)action);
        var definition = Definition(operation, GatewayPermissionContract.Variant((GatewayPermissionAction)action), "independent-effect", generic);
        var registry = Register(provider, env, definition, generic);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Closes).IsEqualTo(1);
        await InfisicalGatewayPermissionEffectTests.Clean(provider);
    }

    private static NativeCaseDefinition Definition(string operation, string variant, string boundary, bool generic) =>
        generic ? new(new("Infisical", InfisicalGatewayPermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalGatewayPermissionGateTests.Execute].Member) :
            InfisicalGatewayPermissionGateTests.Definition(operation, variant, boundary);

    private static NativeCaseRegistry Register(InfisicalGatewayPermissionFixture provider, NativeEnvironment env,
        NativeCaseDefinition definition, bool generic)
    {
        var registry = new NativeCaseRegistry();
        if (generic) InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { GatewayPermissions = provider.Source.CreateClient() });
        else InfisicalPermissionFamilies.Register(registry, env, [definition], gatewayPermissions: provider.Source.CreateClient());
        return registry;
    }
}
