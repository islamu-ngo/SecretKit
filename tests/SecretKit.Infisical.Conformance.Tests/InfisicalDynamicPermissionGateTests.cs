using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalDynamicPermissionGateTests
{
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    internal static readonly string[] Boundaries = ["selected-contract", "independent-effect", "denied-authority",
        "cancellation-boundary", "lost-response-no-replay"];
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        from pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings)
        where DynamicPermissionContract.Operations.Contains(pair.Key)
        from variant in pair.Value.Variants
        where Enum.GetValues<DynamicPermissionAction>().Any(a => DynamicPermissionContract.Variant(pair.Key, a) == variant)
        from boundary in Boundaries
        select (pair.Key, variant, boundary);
    public static IEnumerable<(string Operation, string Boundary)> GenericCases() =>
        Cases().Select(c => (c.Operation, c.Boundary)).Distinct();
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary),
            InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var p) ? p.Member :
                InfisicalProjectFamilies.Bindings[operation].Member);
    internal static DynamicPermissionAction Action(string operation, string variant) =>
        Enum.GetValues<DynamicPermissionAction>().Single(a => DynamicPermissionContract.Variant(operation, a) == variant);

    [Test]
    public async Task DiscoveryAccountsAllThirtyPairsAndSixGenericLabels()
    {
        await Assert.That(Cases().Count()).IsEqualTo(150);
        await Assert.That(Cases().Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(30);
        await Assert.That(GenericCases().Select(c => c.Operation).Distinct().Count()).IsEqualTo(6);
        await Assert.That(GenericCases().Count()).IsEqualTo(30);
        await Assert.That(Cases().All(c => DynamicPermissionContract.Owns(Definition(c.Operation, c.Variant, c.Boundary)))).IsTrue();
        await Assert.That(GenericCases().All(c => InfisicalGovernanceFamilies.Bindings[Execute].Variants.Contains("factory." + c.Operation))).IsTrue();
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeRouteRequiresDynamicPermissionEffect(string operation, string variant, string boundary)
    {
        await using var fixture = new InfisicalDynamicPermissionFixture();
        using var env = fixture.Environment(Action(operation, variant));
        var d = Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [d], dynamicPermissions: fixture.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [d], dynamicPermissions: fixture.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await CheckCleanAsync(fixture);
    }
    [Test]
    [MethodDataSource(nameof(ProfileGenericCases))]
    public async Task OriginalGenericRouteRequiresDynamicPermissionSelection(string operation, string boundary, int action)
    {
        await using var fixture = new InfisicalDynamicPermissionFixture();
        using var env = fixture.Environment((DynamicPermissionAction)action);
        var d = new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[Execute].Member);
        var selected = ManagementClientEffects.Resolve(d, env);
        // Fail before unrelated baseline factories can provision anything.
        await Assert.That(selected?.Key.Variant).IsEqualTo(DynamicPermissionContract.Variant(operation, (DynamicPermissionAction)action));
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, env, [d], new GovernanceObservers { DynamicPermissions = fixture.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Variant).IsEqualTo("factory." + operation);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await CheckCleanAsync(fixture);
    }

    public static IEnumerable<(string Operation, string Boundary, int Action)> ProfileGenericCases() =>
        from c in GenericCases()
        from action in Enum.GetValues<DynamicPermissionAction>()
        select (c.Operation, c.Boundary, (int)action);

    private static async Task CheckCleanAsync(InfisicalDynamicPermissionFixture fixture)
    {
        await Assert.That(fixture.Closes).IsEqualTo(1);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
        await Assert.That(fixture.Remaining).IsEqualTo(0);
        await Assert.That(fixture.BorrowedPreserved).IsTrue();
        await Assert.That(fixture.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments(false, "ignored-policy")]
    [Arguments(true, "ignored-policy")]
    [Arguments(false, "action-leak")]
    [Arguments(true, "action-leak")]
    [Arguments(false, "forged-journal")]
    [Arguments(true, "forged-journal")]
    [Arguments(false, "lost-open")]
    [Arguments(true, "lost-open")]
    public async Task OriginalRoutesRejectIndependentActionFaults(bool generic, string fault)
    {
        await using var fixture = new InfisicalDynamicPermissionFixture(fault);
        using var env = fixture.Environment(DynamicPermissionAction.Lease);
        const string operation = "i.management.RoleChangeOperations.UpdateProjectRole";
        var d = generic ?
            new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", "independent-effect"),
                InfisicalGovernanceFamilies.Bindings[Execute].Member) :
            Definition(operation, DynamicPermissionContract.Variant(operation, DynamicPermissionAction.Lease), "independent-effect");
        var registry = new NativeCaseRegistry();
        var source = fixture.Source.CreateClient();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [d],
                new GovernanceObservers { DynamicPermissions = source });
        else InfisicalPermissionFamilies.Register(registry, env, [d], dynamicPermissions: source);
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await CheckCleanAsync(fixture);
        if (fault == "forged-journal")
        {
            await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
            await Assert.That(fixture.Originals).IsEqualTo(0);
        }
    }
}
