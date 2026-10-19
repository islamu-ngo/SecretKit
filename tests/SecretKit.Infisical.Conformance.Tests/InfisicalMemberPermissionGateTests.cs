using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalMemberPermissionGateTests
{
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        from pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings)
        where MemberPermissionContract.Operations.Contains(pair.Key)
        from variant in pair.Value.Variants
        where variant.StartsWith("permission.Member.", StringComparison.Ordinal)
        from boundary in MemberPermissionContract.Boundaries
        select (pair.Key, variant, boundary);
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary), InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var p) ?
            p.Member : InfisicalProjectFamilies.Bindings[operation].Member);
    internal static MemberPermissionAction Action(string variant) =>
        Enum.GetValues<MemberPermissionAction>().Single(a => MemberPermissionContract.Variant(a) == variant);
    [Test]
    public async Task RetainedMatrixAndExactTypedSeamGatesStayVisible()
    {
        var cases = Cases().ToArray();
        await Assert.That(cases.Length).IsEqualTo(290);
        await Assert.That(cases.Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(58);
        await Assert.That(cases.Count(c => MemberPermissionContract.Gate(MemberPermissionContract.Scope(c.Operation), Action(c.Variant)) is null)).IsEqualTo(160);
        await Assert.That(cases.Count(c => c.Variant == "permission.Member.assume-privileges")).IsEqualTo(30);
        await Assert.That(cases.All(c => MemberPermissionContract.Owns(Definition(c.Operation, c.Variant, c.Boundary)))).IsTrue();
        await Assert.That(MemberPermissionContract.Operations.Take(6).All(op =>
            InfisicalGovernanceFamilies.Bindings[Execute].Variants.Contains("factory." + op))).IsTrue();
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task SourceAbsentOriginalGateIsUnchanged(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalMemberPermissionFixture();
        using var env = provider.Environment(operation, Action(variant), configured: false);
        var d = Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation)) InfisicalPermissionFamilies.Register(registry, env, [d]);
        else InfisicalProjectFamilies.Register(registry, env, [d]);
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
}
