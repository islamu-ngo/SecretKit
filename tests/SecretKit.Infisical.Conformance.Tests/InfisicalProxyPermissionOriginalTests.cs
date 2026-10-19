using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original routes explicitly select independent proxy collection evidence.
public sealed class InfisicalProxyPermissionOriginalTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalProxyPermissionGateTests.SupportedCases();
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from operation in ProxyPermissionContract.Operations
        from boundary in ProxyPermissionContract.Boundaries
        from action in Enum.GetValues<ProxyPermissionAction>()
        select (operation, boundary, (int)action);
    public static IEnumerable<(string Operation, string Boundary, int Action)> SupportedGenericCases() => GenericCases().Where(c => c.Action < 4);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeProxyActionsRequireIndependentEffect(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalProxyPermissionFixture(); using var env = provider.Environment(operation, InfisicalProxyPermissionGateTests.Action(variant));
        var definition = InfisicalProxyPermissionGateTests.Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [definition], proxyPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], proxyPermissions: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Assert.That(provider.Opens).IsEqualTo(1);
        await InfisicalProxyPermissionEffectTests.Clean(provider);
    }
    [Test]
    [MethodDataSource(nameof(SupportedGenericCases))]
    public async Task OriginalGenericRetainsAllSixFactoriesAndConfiguredAction(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalProxyPermissionFixture(); using var env = provider.Environment(operation, (ProxyPermissionAction)action);
        var definition = new NativeCaseDefinition(new("Infisical", InfisicalProxyPermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalProxyPermissionGateTests.Execute].Member);
        var selected = ManagementClientEffects.Resolve(definition, env);
        await Assert.That(selected?.Key.Variant).IsEqualTo(ProxyPermissionContract.Variant((ProxyPermissionAction)action));
        var registry = new NativeCaseRegistry(); InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { ProxyPermissions = provider.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Assert.That(result.Variant).IsEqualTo(definition.Key.Variant);
        await InfisicalProxyPermissionEffectTests.Clean(provider);
    }

    public static IEnumerable<(string Operation, string Variant, string Boundary, bool Generic)> RuntimeCases() =>
        from c in InfisicalProxyPermissionGateTests.RuntimeCases()
        from generic in new[] { false, true }
        select (c.Operation, c.Variant, c.Boundary, generic);

    [Test]
    [MethodDataSource(nameof(RuntimeCases))]
    public async Task OriginalRuntimeGatesKeepActionAndNeverDispatch(string operation, string variant, string boundary, bool generic)
    {
        await using var provider = new InfisicalProxyPermissionFixture();
        using var env = provider.Environment(operation, InfisicalProxyPermissionGateTests.Action(variant));
        var definition = Definition(operation, variant, boundary, generic);
        var registry = Register(provider, env, definition, generic);
        if (generic) await Assert.That(ManagementClientEffects.Resolve(definition, env)?.Key.Variant).IsEqualTo(variant);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
        await Assert.That(provider.Originals).IsEqualTo(0);
        await InfisicalProxyPermissionEffectTests.Clean(provider);
    }

    public static IEnumerable<(string Operation, int Action, string Fault, bool Generic)> Failures() =>
        from operation in ProxyPermissionContract.Operations
        from fault in new[] { "ignored-policy", "incomplete-policy", "allocation-parent", "allocation-substituted",
            "history-request", "forged-collection", "lost-open", "partial-open",
            "retirement-missing", "retirement-substituted", "deleted-inventory-missing", "orphaned-replaced-collection" }
        from generic in new[] { false, true }
        select (operation, fault is "retirement-missing" or "retirement-substituted" or "deleted-inventory-missing" or
            "orphaned-replaced-collection" ? (int)ProxyPermissionAction.Edit : (int)ProxyPermissionAction.Read, fault, generic);

    [Test]
    [MethodDataSource(nameof(Failures))]
    public async Task OriginalRoutesRejectUnprovenCollectionAndRecover(string operation, int action, string fault, bool generic)
    {
        await using var provider = new InfisicalProxyPermissionFixture(fault);
        using var env = provider.Environment(operation, (ProxyPermissionAction)action);
        var definition = Definition(operation, ProxyPermissionContract.Variant((ProxyPermissionAction)action), "independent-effect", generic);
        var registry = Register(provider, env, definition, generic);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Closes).IsEqualTo(1);
        await InfisicalProxyPermissionEffectTests.Clean(provider);
    }

    private static NativeCaseDefinition Definition(string operation, string variant, string boundary, bool generic) =>
        generic ? new(new("Infisical", InfisicalProxyPermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalProxyPermissionGateTests.Execute].Member) :
            InfisicalProxyPermissionGateTests.Definition(operation, variant, boundary);

    private static NativeCaseRegistry Register(InfisicalProxyPermissionFixture provider, NativeEnvironment env,
        NativeCaseDefinition definition, bool generic)
    {
        var registry = new NativeCaseRegistry();
        if (generic) InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { ProxyPermissions = provider.Source.CreateClient() });
        else if (InfisicalPermissionFamilies.Owns(definition.Key.Operation))
            InfisicalPermissionFamilies.Register(registry, env, [definition], proxyPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], proxyPermissions: provider.Source.CreateClient());
        return registry;
    }
}
