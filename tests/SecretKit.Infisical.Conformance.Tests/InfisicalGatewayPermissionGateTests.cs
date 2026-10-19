using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalGatewayPermissionGateTests
{
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        from pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings)
        where GatewayPermissionContract.Operations.Contains(pair.Key)
        from variant in pair.Value.Variants
        where variant.StartsWith("permission.Gateway.", StringComparison.Ordinal)
        from boundary in GatewayPermissionContract.Boundaries
        select (pair.Key, variant, boundary);
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary), InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var binding) ?
            binding.Member : InfisicalProjectFamilies.Bindings[operation].Member);
    internal static GatewayPermissionAction Action(string variant) => Enum.GetValues<GatewayPermissionAction>().Single(a => GatewayPermissionContract.Variant(a) == variant);
    internal static IEnumerable<(string Operation, string Variant, string Boundary)> SupportedCases() => Cases().Where(c => GatewayPermissionContract.Gate(GatewayPermissionScope.Organization, Action(c.Variant)) is null);
    [Test]
    public async Task TwelvePairsRetainFourSupportedAndEightExplicitMissingSeams()
    {
        var cases = Cases().ToArray();
        await Assert.That(cases.Length).IsEqualTo(60); await Assert.That(cases.Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(12);
        await Assert.That(SupportedCases().Count()).IsEqualTo(20); await Assert.That(InfisicalGatewayPermissionOriginalTests.GenericCases().Count()).IsEqualTo(20);
        await Assert.That(cases.All(c => GatewayPermissionContract.Owns(Definition(c.Operation, c.Variant, c.Boundary)))).IsTrue();
        await Assert.That(GatewayPermissionContract.Operations.All(op => InfisicalGovernanceFamilies.Bindings[Execute].Variants.Contains("factory." + op))).IsTrue();
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task ConfiguredGenericResolverKeepsEveryActionEvenWhenGated(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalGatewayPermissionFixture(); using var env = provider.Environment(operation, Action(variant));
        var definition = new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", boundary), InfisicalGovernanceFamilies.Bindings[Execute].Member);
        await Assert.That(GatewayPermissionContract.Resolve(definition, env)?.Key.Variant).IsEqualTo(variant);
    }
    public static IEnumerable<(string Operation, string Variant, string Boundary)> MissingCases() => Cases().Except(SupportedCases());
    [Test]
    [MethodDataSource(nameof(MissingCases))]
    public async Task MissingTypedSeamsNeverDispatchNativeOrConfiguredGeneric(string operation, string variant, string boundary)
    {
        foreach (bool generic in new[] { false, true })
        {
            await using var provider = new InfisicalGatewayPermissionFixture();
            var result = await InfisicalGatewayPermissionEffectTests.RunAsync(provider, operation, variant, boundary, generic);
            await Assert.That(result.Passed).IsFalse(); await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
            await Assert.That(provider.Opens).IsEqualTo(0); await Assert.That(provider.Originals).IsEqualTo(0);
        }
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task SourceAbsentGateRemainsFailClosed(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalGatewayPermissionFixture(); using var env = provider.Environment(operation, Action(variant), false);
        var definition = Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation)) InfisicalPermissionFamilies.Register(registry, env, [definition]);
        else InfisicalProjectFamilies.Register(registry, env, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalGatewayPermissionOriginalTests.GenericCases();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task SourceAbsentGenericNeverSelectsOrCertifiesRoleCrud(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalGatewayPermissionFixture(); using var env = provider.Environment(operation, (GatewayPermissionAction)action, false);
        var definition = new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[Execute].Member);
        await Assert.That(ManagementClientEffects.Resolve(definition, env)?.Key.Variant == GatewayPermissionContract.Variant((GatewayPermissionAction)action)).IsFalse();
        var registry = new NativeCaseRegistry(); InfisicalGovernanceFamilies.Register(registry, env, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse(); await Assert.That(provider.Opens).IsEqualTo(0);
    }
}
