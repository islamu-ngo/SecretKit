using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalProjectTemplatePermissionGateTests
{
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        from pair in InfisicalPermissionFamilies.Bindings
        where ProjectTemplatePermissionContract.Operations.Contains(pair.Key)
        from variant in pair.Value.Variants
        where variant.StartsWith("permission.ProjectTemplates.", StringComparison.Ordinal)
        from boundary in ProjectTemplatePermissionContract.Boundaries
        select (pair.Key, variant, boundary);
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary), InfisicalPermissionFamilies.Bindings[operation].Member);
    internal static ProjectTemplatePermissionAction Action(string variant) => Enum.GetValues<ProjectTemplatePermissionAction>().Single(a => ProjectTemplatePermissionContract.Variant(a) == variant);
    [Test]
    public async Task ExactEightPairsFortyNativeAndFortyGenericRowsRemainDistinct()
    {
        var cases = Cases().ToArray();
        await Assert.That(cases.Length).IsEqualTo(40);
        await Assert.That(cases.Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(8);
        await Assert.That(cases.All(c => ProjectTemplatePermissionContract.Owns(Definition(c.Operation, c.Variant, c.Boundary)))).IsTrue();
        await Assert.That(ProjectTemplatePermissionContract.Operations.All(op => InfisicalGovernanceFamilies.Bindings[Execute].Variants.Contains("factory." + op))).IsTrue();
        await Assert.That(InfisicalProjectTemplatePermissionOriginalTests.GenericCases().Count()).IsEqualTo(40);
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task SourceAbsentOriginalGateRemainsFailClosed(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalProjectTemplatePermissionFixture(); using var env = provider.Environment(operation, Action(variant), false);
        var definition = Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        InfisicalPermissionFamilies.Register(registry, env, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse(); await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
}
