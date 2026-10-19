using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original entrypoints require configured, independently captured settings effects.
public sealed class InfisicalSettingsPermissionOriginalTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary, bool Generic)> ConfiguredCases() =>
        from row in InfisicalSettingsPermissionGateTests.Cases()
        from generic in new[] { false, true }
        select (row.Operation, row.Variant, row.Boundary, generic);
    [Test]
    [MethodDataSource(nameof(ConfiguredCases))]
    public async Task OriginalConfiguredRoutesRequireIndependentSettingsEffects(string operation, string variant, string boundary, bool generic)
    {
        await using var provider = new InfisicalSettingsPermissionFixture();
        var action = InfisicalSettingsPermissionGateTests.Action(variant);
        using var env = provider.Environment(operation, action);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalSettingsPermissionGateTests.Execute,
            "factory." + operation, "local", boundary), InfisicalGovernanceFamilies.Bindings[InfisicalSettingsPermissionGateTests.Execute].Member) :
            InfisicalSettingsPermissionGateTests.Definition(operation, variant, boundary);
        if (generic) await Assert.That(ManagementClientEffects.Resolve(definition, env)?.Key.Variant).IsEqualTo(variant);
        var registry = new NativeCaseRegistry();
        if (generic) InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { SettingsPermissions = provider.Source.CreateClient() });
        else if (InfisicalPermissionFamilies.Owns(operation)) InfisicalPermissionFamilies.Register(registry, env, [definition],
            settingsPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], settingsPermissions: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        bool supported = SettingsPermissionContract.Gate(SettingsPermissionContract.Scope(operation), action) is null;
        await Assert.That(result.Passed).IsEqualTo(supported).Because(result.ReasonCode);
        await Assert.That(provider.Opens).IsEqualTo(supported ? 1 : 0);
        await Assert.That(result.Variant).IsEqualTo(definition.Key.Variant);
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, bool Generic)> Failures() =>
        from operation in SettingsPermissionContract.SupportedOperations
        from fault in new[] { "ignored-policy", "wrong-scope", "wrong-name", "wrong-slug", "wrong-description",
            "unprojected-change", "authorized-uncommitted", "readback-echo", "lost-open", "partial-open" }
        from generic in new[] { false, true }
        select (operation, fault, generic);
    [Test]
    [MethodDataSource(nameof(Failures))]
    public async Task OriginalRoutesRejectUnprovenSettingsAndRecover(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalSettingsPermissionFixture(fault);
        using var env = provider.Environment(operation, SettingsPermissionAction.Edit);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalSettingsPermissionGateTests.Execute,
            "factory." + operation, "local", "independent-effect"), InfisicalGovernanceFamilies.Bindings[InfisicalSettingsPermissionGateTests.Execute].Member) :
            InfisicalSettingsPermissionGateTests.Definition(operation, "permission.Settings.edit", "independent-effect");
        var registry = new NativeCaseRegistry();
        if (generic) InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { SettingsPermissions = provider.Source.CreateClient() });
        else if (InfisicalPermissionFamilies.Owns(operation)) InfisicalPermissionFamilies.Register(registry, env, [definition],
            settingsPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], settingsPermissions: provider.Source.CreateClient());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Closes).IsEqualTo(1);
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalSettingsPermissionGateTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalUnconfiguredNativeRouteCannotCertifySettings(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalSettingsPermissionFixture();
        using var env = provider.Environment(operation, InfisicalSettingsPermissionGateTests.Action(variant), false);
        var definition = InfisicalSettingsPermissionGateTests.Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation)) InfisicalPermissionFamilies.Register(registry, env, [definition]);
        else InfisicalProjectFamilies.Register(registry, env, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse(); await Assert.That(provider.Opens).IsEqualTo(0);
    }
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalSettingsPermissionGateTests.GenericCases();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task OriginalUnconfiguredGenericRoutePreservesFactoryAndFailsClosed(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalSettingsPermissionFixture(); using var env = provider.Environment(operation, (SettingsPermissionAction)action, false);
        var definition = new NativeCaseDefinition(new("Infisical", InfisicalSettingsPermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalSettingsPermissionGateTests.Execute].Member);
        var registry = new NativeCaseRegistry(); InfisicalGovernanceFamilies.Register(registry, env, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse(); await Assert.That(result.Variant).IsEqualTo("factory." + operation);
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
}
