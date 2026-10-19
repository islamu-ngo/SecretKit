using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalAuditPermissionGateTests
{
    public static IEnumerable<(string Operation, string Boundary, bool Generic)> Edits() =>
        from operation in AuditPermissionContract.Operations
        from boundary in AuditPermissionContract.Boundaries
        from generic in new[] { false, true }
        select (operation, boundary, generic);

    [Test]
    [MethodDataSource(nameof(Edits))]
    public async Task ConfiguredEditNeverBecomesAnAuditSettingsWrite(string operation, string boundary, bool generic)
    {
        await using var provider = new InfisicalAuditPermissionFixture();
        var result = await InfisicalAuditPermissionEffectTests.RunAsync(provider, operation, "permission.AuditLogs.edit", boundary, generic);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
        await Assert.That(provider.Originals).IsEqualTo(0);
        await Assert.That(provider.Generated).IsEqualTo(0);
    }

    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        from pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings)
        where AuditPermissionContract.Operations.Contains(pair.Key)
        from variant in pair.Value.Variants
        where variant.StartsWith("permission.AuditLogs.", StringComparison.Ordinal)
        from boundary in AuditPermissionContract.Boundaries
        select (pair.Key, variant, boundary);
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary), InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var binding) ?
            binding.Member : InfisicalProjectFamilies.Bindings[operation].Member);
    internal static AuditPermissionAction Action(string variant) =>
        Enum.GetValues<AuditPermissionAction>().Single(a => AuditPermissionContract.Variant(a) == variant);

    [Test]
    public async Task SixteenPairsRetainReadSupportAndExplicitEditGate()
    {
        var cases = Cases().ToArray();
        await Assert.That(cases.Length).IsEqualTo(80);
        await Assert.That(cases.Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(16);
        await Assert.That(cases.Count(c => Action(c.Variant) == AuditPermissionAction.Read)).IsEqualTo(40);
        await Assert.That(InfisicalAuditPermissionOriginalTests.GenericCases().Count()).IsEqualTo(80);
        await Assert.That(AuditPermissionContract.Operations.Length).IsEqualTo(8);
        await Assert.That(cases.All(c => AuditPermissionContract.Owns(Definition(c.Operation, c.Variant, c.Boundary)))).IsTrue();
        await Assert.That(cases.Count(c => AuditPermissionContract.Gate(Action(c.Variant)) is not null)).IsEqualTo(40);
        await Assert.That(AuditPermissionContract.Operations.All(op => InfisicalGovernanceFamilies.Bindings[Execute].Variants.Contains("factory." + op))).IsTrue();
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task MissingSourceRemainsUnavailableWithoutDispatch(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalAuditPermissionFixture();
        using var environment = provider.Environment(operation, Action(variant), false);
        var definition = Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation)) InfisicalPermissionFamilies.Register(registry, environment, [definition]);
        else InfisicalProjectFamilies.Register(registry, environment, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
        await Assert.That(provider.Originals).IsEqualTo(0);
    }
}
