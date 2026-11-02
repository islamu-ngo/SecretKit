using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalGroupPermissionGateTests
{
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        from pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings)
        where GroupPermissionContract.Operations.Contains(pair.Key)
        from variant in pair.Value.Variants
        where variant.StartsWith("permission.Groups.", StringComparison.Ordinal)
        from boundary in GroupPermissionContract.Boundaries
        select (pair.Key, variant, boundary);
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary), InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var binding) ?
            binding.Member : InfisicalProjectFamilies.Bindings[operation].Member);
    internal static GroupPermissionAction Action(string variant) => Enum.GetValues<GroupPermissionAction>().Single(a => GroupPermissionContract.Variant(a) == variant);
    [Test]
    public async Task FullGroupsDenominatorAndGenericLabelsRemainSeparate()
    {
        var cases = Cases().ToArray();
        await Assert.That(cases.Length).IsEqualTo(270);
        await Assert.That(cases.Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(54);
        await Assert.That(cases.Count(c => GroupPermissionContract.Gate(GroupPermissionContract.Scope(c.Operation), Action(c.Variant)) is null)).IsEqualTo(210);
        await Assert.That(cases.All(c => GroupPermissionContract.Owns(Definition(c.Operation, c.Variant, c.Boundary)))).IsTrue();
        await Assert.That(GroupPermissionContract.Operations.Take(6).All(op => InfisicalGovernanceFamilies.Bindings[Execute].Variants.Contains("factory." + op))).IsTrue();
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task SourceAbsentGateRemainsFailClosed(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalGroupPermissionFixture(); using var env = provider.Environment(operation, Action(variant), false);
        var definition = Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation)) InfisicalPermissionFamilies.Register(registry, env, [definition]);
        else InfisicalProjectFamilies.Register(registry, env, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        // The pre-existing organization Groups.read canary enters its old setup
        // path. This fixture refuses that unregistered work, including cleanup.
        // Other Groups actions stop at the original unavailable gate.
        bool legacyCanary = GroupPermissionContract.Scope(operation) == GroupPermissionScope.Organization &&
            variant == "permission.Groups.read";
        await Assert.That(result.ReasonCode).IsEqualTo(legacyCanary ? "cleanup-incomplete" : "observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
}
