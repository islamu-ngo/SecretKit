using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalIntegrationPermissionGateTests
{
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        from pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings)
        where IntegrationPermissionContract.Operations.Contains(pair.Key)
        from variant in pair.Value.Variants
        where variant.StartsWith("permission.Integrations.", StringComparison.Ordinal)
        from boundary in IntegrationPermissionContract.Boundaries
        select (pair.Key, variant, boundary);
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from operation in IntegrationPermissionContract.Operations
        from boundary in IntegrationPermissionContract.Boundaries
        from action in Enum.GetValues<IntegrationPermissionAction>()
        select (operation, boundary, (int)action);
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary), InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var binding) ?
            binding.Member : InfisicalProjectFamilies.Bindings[operation].Member);
    internal static IntegrationPermissionAction Action(string variant) => Enum.GetValues<IntegrationPermissionAction>().Single(a => IntegrationPermissionContract.Variant(a) == variant);
    [Test]
    public async Task RetainedDenominatorHasSixReadAndEighteenExplicitlyGatedMutationPairs()
    {
        var cases = Cases().ToArray();
        await Assert.That(cases.Length).IsEqualTo(120);
        await Assert.That(GenericCases().Count()).IsEqualTo(120);
        await Assert.That(cases.Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(24);
        await Assert.That(cases.Count(c => IntegrationPermissionContract.Gate(IntegrationPermissionScope.Project, Action(c.Variant)) is null)).IsEqualTo(30);
        await Assert.That(cases.All(c => IntegrationPermissionContract.Owns(Definition(c.Operation, c.Variant, c.Boundary)))).IsTrue();
        await Assert.That(IntegrationPermissionContract.Operations.All(op => !op.Contains("OrganizationRole", StringComparison.Ordinal) &&
            InfisicalGovernanceFamilies.Bindings[Execute].Variants.Contains("factory." + op))).IsTrue();
        await Assert.That(IntegrationPermissionContract.Gate(IntegrationPermissionScope.Organization, IntegrationPermissionAction.Read)).IsNotNull();
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task MissingSourceCannotCertifyAnyRetainedNativeCase(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalIntegrationPermissionFixture();
        var result = await InfisicalIntegrationPermissionEffectTests.RunAsync(provider, operation, variant, boundary, configured: false);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task MissingSourceNeverTurnsGenericFactoryIntoRoleCrudEvidence(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalIntegrationPermissionFixture();
        var result = await InfisicalIntegrationPermissionEffectTests.RunAsync(provider, operation,
            IntegrationPermissionContract.Variant((IntegrationPermissionAction)action), boundary, true, false);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.Variant).IsEqualTo("factory." + operation);
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
}
