using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalRotationPermissionGateTests
{
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        from pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings)
        from variant in pair.Value.Variants
        where variant.StartsWith("permission.SecretRotation.", StringComparison.Ordinal)
        from boundary in RotationPermissionContract.Boundaries
        select (pair.Key, variant, boundary);
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from c in Cases().Select(c => (c.Operation, c.Boundary)).Distinct()
        from action in Enum.GetValues<RotationPermissionAction>()
        select (c.Operation, c.Boundary, (int)action);
    internal static RotationPermissionAction Action(string variant) =>
        Enum.GetValues<RotationPermissionAction>().Single(a => RotationPermissionContract.Variant(a) == variant);
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary),
            InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var p) ? p.Member :
                InfisicalProjectFamilies.Bindings[operation].Member);
    [Test]
    public async Task EnumeratesEveryRetainedPairCaseGenericLabelAndExplicitProfileGate()
    {
        var cases = Cases().ToArray();
        await Assert.That(cases.Length).IsEqualTo(180);
        await Assert.That(cases.Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(36);
        await Assert.That(cases.Select(c => c.Operation).Distinct().Order()
            .SequenceEqual(RotationPermissionContract.Operations.Order())).IsTrue();
        await Assert.That(cases.All(c => RotationPermissionContract.Supported(Definition(c.Operation, c.Variant, c.Boundary),
            InfisicalRotationProfile.PostgresCredentials))).IsTrue();
        await Assert.That(cases.All(c => RotationPermissionContract.Supported(Definition(c.Operation, c.Variant, c.Boundary),
            InfisicalRotationProfile.MysqlCredentials) && RotationPermissionContract.Supported(Definition(c.Operation, c.Variant, c.Boundary),
            InfisicalRotationProfile.MssqlCredentials))).IsTrue();
        await Assert.That(GenericCases().Select(c => c.Operation).Distinct().Count()).IsEqualTo(6);
        await Assert.That(GenericCases().Select(c => (c.Operation, c.Boundary)).Distinct().Count()).IsEqualTo(30);
        await Assert.That(GenericCases().Count()).IsEqualTo(180);
        await Assert.That(GenericCases().All(c => InfisicalGovernanceFamilies.Bindings[Execute].Variants.Contains("factory." + c.Operation))).IsTrue();
        await Assert.That(RotationPermissionContract.NativeGates.Length).IsEqualTo(8);
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeRouteRequiresRotationPermissionEffect(string operation, string variant, string boundary)
    {
        await using var fixture = new InfisicalRotationPermissionFixture();
        using var env = fixture.Environment(Action(variant));
        var d = Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [d], rotationPermissions: fixture.Source.CreateClient(),
                rotationPermissionRuntime: fixture.Runtime);
        else InfisicalProjectFamilies.Register(registry, env, [d], rotationPermissions: fixture.Source.CreateClient(),
            rotationPermissionRuntime: fixture.Runtime);
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await InfisicalRotationPermissionEffectTests.CleanAsync(fixture);
    }
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task OriginalGenericRouteRequiresRotationPermissionSelection(string operation, string boundary, int action)
    {
        await using var fixture = new InfisicalRotationPermissionFixture();
        using var env = fixture.Environment((RotationPermissionAction)action);
        var d = new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[Execute].Member);
        var selected = ManagementClientEffects.Resolve(d, env);
        // Fail before an unrelated baseline factory can provision anything.
        await Assert.That(selected?.Key.Variant).IsEqualTo(RotationPermissionContract.Variant((RotationPermissionAction)action));
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, env, [d],
            new GovernanceObservers { RotationPermissions = fixture.Source.CreateClient(), RotationPermissionRuntime = fixture.Runtime });
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Variant).IsEqualTo("factory." + operation);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await InfisicalRotationPermissionEffectTests.CleanAsync(fixture);
    }
    [Test]
    [Arguments(false, "ignored-policy")]
    [Arguments(true, "ignored-policy")]
    [Arguments(false, "wrong-credential")]
    [Arguments(true, "wrong-credential")]
    [Arguments(false, "ignored-rotation")]
    [Arguments(true, "ignored-rotation")]
    [Arguments(false, "forged-journal")]
    [Arguments(true, "forged-journal")]
    [Arguments(false, "lost-open")]
    [Arguments(true, "lost-open")]
    public async Task OriginalRoutesRejectIndependentRotationFaults(bool generic, string fault)
    {
        await using var fixture = new InfisicalRotationPermissionFixture(fault);
        using var env = fixture.Environment(RotationPermissionAction.Edit);
        const string operation = "i.management.RoleChangeOperations.UpdateProjectRole";
        var d = generic ?
            new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", "independent-effect"),
                InfisicalGovernanceFamilies.Bindings[Execute].Member) :
            Definition(operation, RotationPermissionContract.Variant(RotationPermissionAction.Edit), "independent-effect");
        var registry = new NativeCaseRegistry();
        var source = fixture.Source.CreateClient();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [d],
                new GovernanceObservers { RotationPermissions = source, RotationPermissionRuntime = fixture.Runtime });
        else InfisicalPermissionFamilies.Register(registry, env, [d], rotationPermissions: source,
            rotationPermissionRuntime: fixture.Runtime);
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await InfisicalRotationPermissionEffectTests.CleanAsync(fixture);
        if (fault == "forged-journal")
        {
            await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
            await Assert.That(fixture.Originals).IsEqualTo(0);
        }
    }
}
