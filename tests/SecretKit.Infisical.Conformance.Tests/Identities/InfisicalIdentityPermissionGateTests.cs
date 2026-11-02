using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalIdentityPermissionGateTests
{
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        from pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings)
        where IdentityPermissionContract.Operations.Contains(pair.Key)
        from variant in pair.Value.Variants
        where variant.StartsWith("permission.Identity.", StringComparison.Ordinal)
        from boundary in IdentityPermissionContract.Boundaries
        select (pair.Key, variant, boundary);
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary), InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var binding) ?
            binding.Member : InfisicalProjectFamilies.Bindings[operation].Member);
    internal static IdentityPermissionAction Action(string variant) => Enum.GetValues<IdentityPermissionAction>().Single(a => IdentityPermissionContract.Variant(a) == variant);
    [Test]
    public async Task FullIdentityDenominatorAndGenericLabelsRemainSeparate()
    {
        var cases = Cases().ToArray();
        await Assert.That(cases.Length).IsEqualTo(490);
        await Assert.That(cases.Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(98);
        await Assert.That(cases.Count(c => IdentityPermissionContract.Gate(IdentityPermissionContract.Scope(c.Operation), Action(c.Variant)) is null)).IsEqualTo(430);
        await Assert.That(cases.All(c => IdentityPermissionContract.Owns(Definition(c.Operation, c.Variant, c.Boundary)))).IsTrue();
        await Assert.That(IdentityPermissionContract.Operations.Take(6).All(op => InfisicalGovernanceFamilies.Bindings[Execute].Variants.Contains("factory." + op))).IsTrue();
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task SourceAbsentGateRemainsFailClosed(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalIdentityPermissionFixture(); using var env = provider.Environment(operation, Action(variant), false);
        var definition = Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation)) InfisicalPermissionFamilies.Register(registry, env, [definition]);
        else InfisicalProjectFamilies.Register(registry, env, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
}
