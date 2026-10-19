using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalProxyPermissionGateTests
{
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        from pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings)
        where ProxyPermissionContract.Operations.Contains(pair.Key)
        from variant in pair.Value.Variants
        where variant.StartsWith("permission.ProxiedServices.", StringComparison.Ordinal)
        from boundary in ProxyPermissionContract.Boundaries
        select (pair.Key, variant, boundary);
    public static IEnumerable<(string Operation, string Variant, string Boundary)> SupportedCases() => Cases().Where(c => ProxyPermissionContract.Gate(ProxyPermissionScope.Project, Action(c.Variant)) is null);
    public static IEnumerable<(string Operation, string Variant, string Boundary)> RuntimeCases() => Cases().Where(c => ProxyPermissionContract.Gate(ProxyPermissionScope.Project, Action(c.Variant)) is not null);
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary), InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var binding) ?
            binding.Member : InfisicalProjectFamilies.Bindings[operation].Member);
    internal static ProxyPermissionAction Action(string variant) => Enum.GetValues<ProxyPermissionAction>().Single(a => ProxyPermissionContract.Variant(a) == variant);
    [Test]
    public async Task ExactThirtySixPairsRetainTwentyFourCrudAndTwelveRuntimeGates()
    {
        var cases = Cases().ToArray();
        await Assert.That(InfisicalProxyPermissionOriginalTests.GenericCases().Count()).IsEqualTo(180);
        await Assert.That(cases.Length).IsEqualTo(180);
        await Assert.That(cases.Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(36);
        await Assert.That(cases.Count(c => ProxyPermissionContract.Scope(c.Operation) == ProxyPermissionScope.Project)).IsEqualTo(180);
        await Assert.That(cases.Count(c => ProxyPermissionContract.Scope(c.Operation) == ProxyPermissionScope.Organization)).IsEqualTo(0);
        await Assert.That(cases.Count(c => ProxyPermissionContract.Gate(ProxyPermissionContract.Scope(c.Operation), Action(c.Variant)) is null)).IsEqualTo(120);
        await Assert.That(cases.All(c => ProxyPermissionContract.Owns(Definition(c.Operation, c.Variant, c.Boundary)))).IsTrue();
        await Assert.That(ProxyPermissionContract.Operations.All(op => InfisicalGovernanceFamilies.Bindings[Execute].Variants.Contains("factory." + op))).IsTrue();
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task SourceAbsentGateRemainsFailClosed(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalProxyPermissionFixture(); using var env = provider.Environment(operation, Action(variant), false);
        var definition = Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation)) InfisicalPermissionFamilies.Register(registry, env, [definition]);
        else InfisicalProjectFamilies.Register(registry, env, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalProxyPermissionOriginalTests.GenericCases();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task SourceAbsentGenericNeverSelectsOrCertifiesRoleCrud(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalProxyPermissionFixture(); using var env = provider.Environment(operation, (ProxyPermissionAction)action, false);
        var definition = new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[Execute].Member);
        await Assert.That(ManagementClientEffects.Resolve(definition, env)?.Key.Variant == ProxyPermissionContract.Variant((ProxyPermissionAction)action)).IsFalse();
        var registry = new NativeCaseRegistry(); InfisicalGovernanceFamilies.Register(registry, env, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse(); await Assert.That(provider.Opens).IsEqualTo(0);
    }
    [Test]
    [MethodDataSource(nameof(RuntimeCases))]
    public async Task ConfiguredRuntimeActionNeedsActualIndependentEffectSeam(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalProxyPermissionFixture();
        var native = await InfisicalProxyPermissionEffectTests.RunAsync(provider, operation, variant, boundary);
        await Assert.That(native.Passed).IsFalse(); await Assert.That(native.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    public static IEnumerable<(string Operation, string Boundary, int Action)> RuntimeGenericCases() => GenericCases().Where(c => c.Action >= 4);
    [Test]
    [MethodDataSource(nameof(RuntimeGenericCases))]
    public async Task ConfiguredGenericRuntimeGatesRetainOriginalFactoryAndSelection(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalProxyPermissionFixture(); using var env = provider.Environment(operation, (ProxyPermissionAction)action);
        var definition = new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", boundary), InfisicalGovernanceFamilies.Bindings[Execute].Member);
        await Assert.That(ProxyPermissionContract.Resolve(definition, env)?.Key.Variant).IsEqualTo(ProxyPermissionContract.Variant((ProxyPermissionAction)action));
        var result = await InfisicalProxyPermissionEffectTests.RunAsync(provider, operation, ProxyPermissionContract.Variant((ProxyPermissionAction)action), boundary, true);
        await Assert.That(result.Passed).IsFalse(); await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(result.Variant).IsEqualTo(definition.Key.Variant); await Assert.That(provider.Opens).IsEqualTo(0);
    }
}
