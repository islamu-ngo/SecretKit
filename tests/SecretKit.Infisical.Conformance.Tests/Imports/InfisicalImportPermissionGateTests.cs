using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalImportPermissionGateTests
{
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    internal static readonly string[] Boundaries = ["selected-contract", "independent-effect", "denied-authority",
        "cancellation-boundary", "lost-response-no-replay"];
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        from pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings)
        where ImportPermissionContract.Operations.Contains(pair.Key)
        from variant in pair.Value.Variants
        where Enum.GetValues<ImportPermissionAction>().Any(a => ImportPermissionContract.Variant(pair.Key, a) == variant)
        from boundary in Boundaries
        select (pair.Key, variant, boundary);
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary), InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var p) ?
            p.Member : InfisicalProjectFamilies.Bindings[operation].Member);
    internal static ImportPermissionAction Action(string operation, string variant) =>
        Enum.GetValues<ImportPermissionAction>().Single(a => ImportPermissionContract.Variant(operation, a) == variant);
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from c in Cases().Select(c => (c.Operation, c.Boundary)).Distinct()
        from action in Enum.GetValues<ImportPermissionAction>()
        select (c.Operation, c.Boundary, (int)action);
    [Test]
    public async Task DiscoveryAccountsTwentyFourPairsAndSixFactories()
    {
        await Assert.That(Cases().Count()).IsEqualTo(120);
        await Assert.That(Cases().Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(24);
        await Assert.That(GenericCases().Count()).IsEqualTo(120);
        await Assert.That(Cases().All(c => ImportPermissionContract.Owns(Definition(c.Operation, c.Variant, c.Boundary)))).IsTrue();
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativePositiveRequiresImportWitness(string operation, string variant, string boundary)
    {
        await using var fixture = new InfisicalImportPermissionFixture();
        using var env = fixture.Environment(Action(operation, variant));
        var d = Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [d], importPermissions: fixture.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [d], importPermissions: fixture.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await InfisicalImportPermissionEffectTests.Clean(fixture);
    }
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task OriginalGenericPositiveRequiresExplicitImportSelection(string operation, string boundary, int action)
    {
        await using var fixture = new InfisicalImportPermissionFixture();
        using var env = fixture.Environment((ImportPermissionAction)action);
        var d = new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[Execute].Member);
        var selected = ManagementClientEffects.Resolve(d, env);
        await Assert.That(selected?.Key.Variant).IsEqualTo(ImportPermissionContract.Variant(operation, (ImportPermissionAction)action));
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, env, [d],
            new GovernanceObservers { ImportPermissions = fixture.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(result.Variant).IsEqualTo("factory." + operation);
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await InfisicalImportPermissionEffectTests.Clean(fixture);
    }
    [Test]
    [Arguments(false, "ignored-policy")]
    [Arguments(true, "ignored-policy")]
    [Arguments(false, "action-leak")]
    [Arguments(true, "action-leak")]
    [Arguments(false, "wrong-linkage")]
    [Arguments(true, "wrong-linkage")]
    [Arguments(false, "forged-journal")]
    [Arguments(true, "forged-journal")]
    [Arguments(false, "lost-open")]
    [Arguments(true, "lost-open")]
    public async Task OriginalRoutesRejectIndependentImportFaults(bool generic, string fault)
    {
        await using var fixture = new InfisicalImportPermissionFixture(fault);
        using var env = fixture.Environment(ImportPermissionAction.Edit);
        const string operation = "i.management.RoleChangeOperations.UpdateProjectRole";
        var d = generic ?
            new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", "independent-effect"),
                InfisicalGovernanceFamilies.Bindings[Execute].Member) :
            Definition(operation, ImportPermissionContract.Variant(operation, ImportPermissionAction.Edit), "independent-effect");
        var registry = new NativeCaseRegistry();
        var source = fixture.Source.CreateClient();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [d], new GovernanceObservers { ImportPermissions = source });
        else InfisicalPermissionFamilies.Register(registry, env, [d], importPermissions: source);
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await InfisicalImportPermissionEffectTests.Clean(fixture);
        if (fault == "forged-journal")
        {
            await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
            await Assert.That(fixture.Originals).IsEqualTo(0);
        }
    }
}
