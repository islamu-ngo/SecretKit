using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalSettingsPermissionGateTests
{
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        from pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings)
        where SettingsPermissionContract.Operations.Contains(pair.Key)
        from variant in pair.Value.Variants
        where variant.StartsWith("permission.Settings.", StringComparison.Ordinal)
        from boundary in SettingsPermissionContract.Boundaries
        select (pair.Key, variant, boundary);
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from operation in SettingsPermissionContract.Operations
        from boundary in SettingsPermissionContract.Boundaries
        from action in Enum.GetValues<SettingsPermissionAction>()
        select (operation, boundary, (int)action);
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary), InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var binding) ?
            binding.Member : InfisicalProjectFamilies.Bindings[operation].Member);
    internal static SettingsPermissionAction Action(string variant) => Enum.GetValues<SettingsPermissionAction>().Single(a => SettingsPermissionContract.Variant(a) == variant);
    [Test]
    public async Task RetainedDenominatorHasSixProjectEditAndTwentySixExplicitGates()
    {
        var cases = Cases().ToArray();
        await Assert.That(cases.Length).IsEqualTo(160);
        await Assert.That(GenericCases().Count()).IsEqualTo(160);
        await Assert.That(cases.Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(32);
        await Assert.That(cases.Count(c => SettingsPermissionContract.Gate(SettingsPermissionContract.Scope(c.Operation), Action(c.Variant)) is null)).IsEqualTo(30);
        await Assert.That(cases.All(c => SettingsPermissionContract.Owns(Definition(c.Operation, c.Variant, c.Boundary)))).IsTrue();
        await Assert.That(SettingsPermissionContract.Operations.All(op => InfisicalGovernanceFamilies.Bindings[Execute].Variants.Contains("factory." + op))).IsTrue();
        await Assert.That(SettingsPermissionContract.Gate(SettingsPermissionScope.Organization, SettingsPermissionAction.Read)).IsNotNull();
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task MissingSourceCannotCertifyAnyRetainedNativeCase(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalSettingsPermissionFixture();
        var result = await InfisicalSettingsPermissionEffectTests.RunAsync(provider, operation, variant, boundary, configured: false);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task MissingSourceNeverTurnsGenericFactoryIntoRoleCrudEvidence(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalSettingsPermissionFixture();
        var result = await InfisicalSettingsPermissionEffectTests.RunAsync(provider, operation,
            SettingsPermissionContract.Variant((SettingsPermissionAction)action), boundary, true, false);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.Variant).IsEqualTo("factory." + operation);
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
}
