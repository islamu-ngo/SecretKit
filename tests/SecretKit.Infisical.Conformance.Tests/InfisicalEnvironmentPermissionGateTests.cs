using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalEnvironmentPermissionGateTests
{
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        from pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings)
        where EnvironmentPermissionContract.Operations.Contains(pair.Key)
        from variant in pair.Value.Variants
        where variant.StartsWith("permission.Environments.", StringComparison.Ordinal)
        from boundary in EnvironmentPermissionContract.Boundaries
        select (pair.Key, variant, boundary);
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary), InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var binding) ?
            binding.Member : InfisicalProjectFamilies.Bindings[operation].Member);
    internal static EnvironmentPermissionAction Action(string variant) => Enum.GetValues<EnvironmentPermissionAction>().Single(a => EnvironmentPermissionContract.Variant(a) == variant);
    [Test]
    public async Task ExactTwentyFourProjectPairsAndGenericFactoriesRemainSeparate()
    {
        var cases = Cases().ToArray();
        await Assert.That(InfisicalEnvironmentPermissionOriginalTests.GenericCases().Count()).IsEqualTo(120);
        await Assert.That(cases.Length).IsEqualTo(120);
        await Assert.That(cases.Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(24);
        await Assert.That(cases.Count(c => EnvironmentPermissionContract.Scope(c.Operation) == EnvironmentPermissionScope.Project)).IsEqualTo(120);
        await Assert.That(cases.Count(c => EnvironmentPermissionContract.Scope(c.Operation) == EnvironmentPermissionScope.Organization)).IsEqualTo(0);
        await Assert.That(cases.Count(c => EnvironmentPermissionContract.Gate(EnvironmentPermissionContract.Scope(c.Operation), Action(c.Variant)) is null)).IsEqualTo(120);
        await Assert.That(cases.All(c => EnvironmentPermissionContract.Owns(Definition(c.Operation, c.Variant, c.Boundary)))).IsTrue();
        await Assert.That(EnvironmentPermissionContract.Operations.All(op => InfisicalGovernanceFamilies.Bindings[Execute].Variants.Contains("factory." + op))).IsTrue();
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task SourceAbsentGateRemainsFailClosed(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalEnvironmentPermissionFixture(); using var env = provider.Environment(operation, Action(variant), false);
        var definition = Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation)) InfisicalPermissionFamilies.Register(registry, env, [definition]);
        else InfisicalProjectFamilies.Register(registry, env, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalEnvironmentPermissionOriginalTests.GenericCases();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task SourceAbsentGenericNeverSelectsOrCertifiesRoleCrud(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalEnvironmentPermissionFixture(); using var env = provider.Environment(operation, (EnvironmentPermissionAction)action, false);
        var definition = new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[Execute].Member);
        await Assert.That(ManagementClientEffects.Resolve(definition, env)?.Key.Variant == EnvironmentPermissionContract.Variant((EnvironmentPermissionAction)action)).IsFalse();
        var registry = new NativeCaseRegistry(); InfisicalGovernanceFamilies.Register(registry, env, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse(); await Assert.That(provider.Opens).IsEqualTo(0);
    }
}
