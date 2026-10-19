using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalWorkspacePermissionGateTests
{
    public static IEnumerable<string> ProjectFactories() => WorkspacePermissionContract.Operations
        .Where(op => WorkspacePermissionContract.Scope(op) == WorkspacePermissionScope.Project);
    [Test]
    [MethodDataSource(nameof(ProjectFactories))]
    public async Task WorkspaceEditCannotCertifyTheSettingsUpdateEndpoint(string operation)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture();
        var result = await InfisicalWorkspacePermissionEffectTests.RunAsync(provider, operation,
            "permission.Workspace.edit", "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Opens).IsEqualTo(0);
        await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        from pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings)
        where WorkspacePermissionContract.Operations.Contains(pair.Key)
        from variant in pair.Value.Variants
        where variant.StartsWith("permission.Workspace.", StringComparison.Ordinal)
        from boundary in WorkspacePermissionContract.Boundaries
        select (pair.Key, variant, boundary);
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary), InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var binding) ?
            binding.Member : InfisicalProjectFamilies.Bindings[operation].Member);
    internal static WorkspacePermissionAction Action(string variant) => Enum.GetValues<WorkspacePermissionAction>().Single(a => WorkspacePermissionContract.Variant(a) == variant);
    [Test]
    public async Task ExactFourteenPairsAndBothGenericScopesRemainSeparate()
    {
        var cases = Cases().ToArray();
        await Assert.That(InfisicalWorkspacePermissionOriginalTests.GenericCases().Count()).IsEqualTo(70);
        await Assert.That(cases.Length).IsEqualTo(70);
        await Assert.That(cases.Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(14);
        await Assert.That(cases.Count(c => WorkspacePermissionContract.Scope(c.Operation) == WorkspacePermissionScope.Project)).IsEqualTo(60);
        await Assert.That(cases.Count(c => WorkspacePermissionContract.Scope(c.Operation) == WorkspacePermissionScope.Organization)).IsEqualTo(10);
        await Assert.That(cases.Count(c => WorkspacePermissionContract.Gate(WorkspacePermissionContract.Scope(c.Operation), Action(c.Variant)) is null)).IsEqualTo(40);
        await Assert.That(cases.Count(c => WorkspacePermissionContract.Gate(WorkspacePermissionContract.Scope(c.Operation), Action(c.Variant)) is not null)).IsEqualTo(30);
        await Assert.That(cases.All(c => WorkspacePermissionContract.Owns(Definition(c.Operation, c.Variant, c.Boundary)))).IsTrue();
        await Assert.That(WorkspacePermissionContract.Operations.All(op => InfisicalGovernanceFamilies.Bindings[Execute].Variants.Contains("factory." + op))).IsTrue();
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task SourceAbsentGateRemainsFailClosed(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(); using var env = provider.Environment(operation, Action(variant), false);
        var definition = Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation)) InfisicalPermissionFamilies.Register(registry, env, [definition]);
        else InfisicalProjectFamilies.Register(registry, env, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalWorkspacePermissionOriginalTests.GenericCases();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task SourceAbsentGenericNeverSelectsOrCertifiesRoleCrud(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(); using var env = provider.Environment(operation, (WorkspacePermissionAction)action, false);
        var definition = new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[Execute].Member);
        await Assert.That(ManagementClientEffects.Resolve(definition, env)?.Key.Variant == WorkspacePermissionContract.Variant((WorkspacePermissionAction)action)).IsFalse();
        var registry = new NativeCaseRegistry(); InfisicalGovernanceFamilies.Register(registry, env, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse(); await Assert.That(provider.Opens).IsEqualTo(0);
    }
}
