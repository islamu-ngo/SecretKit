using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalMetadataPermissionGateTests
{
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    internal static readonly string[] Boundaries = ["selected-contract", "independent-effect",
        "denied-authority", "cancellation-boundary", "lost-response-no-replay"];

    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases()
    {
        foreach (var pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings))
            foreach (string variant in pair.Value.Variants.Where(v =>
                v is "condition.metadata.elemMatch" or "permissions.metadata.elemMatch"))
                foreach (string boundary in Boundaries)
                    yield return (pair.Key, variant, boundary);
    }
    public static IEnumerable<(string Operation, string Boundary)> GenericCases() =>
        Cases().Select(c => (c.Operation, c.Boundary)).Distinct();
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary),
            InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var p) ? p.Member :
                InfisicalProjectFamilies.Bindings[operation].Member);

    [Test]
    [Arguments(false, "ignored-permissions")]
    [Arguments(true, "ignored-permissions")]
    [Arguments(false, "split-entry")]
    [Arguments(true, "split-entry")]
    [Arguments(false, "coordinator-forged-attestation")]
    [Arguments(true, "coordinator-forged-attestation")]
    [Arguments(false, "lost-open")]
    [Arguments(true, "lost-open")]
    public async Task OriginalRoutesRejectIndependentMetadataFaults(bool generic, string fault)
    {
        await using var fixture = new InfisicalMetadataPermissionFixture(fault);
        using var env = fixture.Environment();
        const string operation = "i.management.RoleChangeOperations.UpdateProjectRole";
        var d = generic ?
            new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", "independent-effect"),
                InfisicalGovernanceFamilies.Bindings[Execute].Member) :
            Definition(operation, "condition.metadata.elemMatch", "independent-effect");
        var registry = new NativeCaseRegistry();
        var source = fixture.Source.CreateClient();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [d],
                new GovernanceObservers { MetadataPermissions = source });
        else InfisicalPermissionFamilies.Register(registry, env, [d], metadataPermissions: source);
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await Assert.That(fixture.Closes).IsEqualTo(1);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
        await Assert.That(fixture.Remaining).IsEqualTo(0);
        await Assert.That(fixture.BorrowedPreserved).IsTrue();
        await Assert.That(fixture.Copies.All(b => b.All(v => v == 0))).IsTrue();
        if (fault == "coordinator-forged-attestation")
        {
            await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
            await Assert.That(fixture.Originals).IsEqualTo(0);
        }
    }

    [Test]
    public async Task DiscoveryAccountsEveryNativePairAndGenericLabel()
    {
        await Assert.That(Cases().Count()).IsEqualTo(40);
        await Assert.That(Cases().Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(8);
        await Assert.That(Cases().Select(c => c.Operation).Distinct().Count()).IsEqualTo(6);
        await Assert.That(GenericCases().Count()).IsEqualTo(30);
        var factories = InfisicalGovernanceFamilies.Bindings[Execute].Variants;
        await Assert.That(GenericCases().All(c => factories.Contains("factory." + c.Operation))).IsTrue();
    }

    public static IEnumerable<(string Operation, string Variant, string Boundary, string Operator)> ProfileCases() =>
        Cases().SelectMany(c => Enum.GetValues<MetadataPermissionOperator>()
            .Select(op => (c.Operation, c.Variant, c.Boundary, op.ToString())));
    public static IEnumerable<(string Operation, string Boundary, string Operator)> ProfileGenericCases() =>
        GenericCases().SelectMany(c => Enum.GetValues<MetadataPermissionOperator>()
            .Select(op => (c.Operation, c.Boundary, op.ToString())));

    [Test]
    [MethodDataSource(nameof(ProfileCases))]
    public async Task OriginalRegistrationRequiresMetadataProfile(string operation, string variant, string boundary,
        string op)
    {
        await using var fixture = new InfisicalMetadataPermissionFixture();
        using var env = fixture.Environment(Enum.Parse<MetadataPermissionOperator>(op));
        var d = Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [d], metadataPermissions: fixture.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [d], metadataPermissions: fixture.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
        await Assert.That(fixture.Remaining).IsEqualTo(0);
        await Assert.That(fixture.BorrowedPreserved).IsTrue();
        await Assert.That(fixture.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [MethodDataSource(nameof(ProfileGenericCases))]
    public async Task OriginalGenericResolverRequiresMetadataVariant(string operation, string boundary,
        string op)
    {
        await using var fixture = new InfisicalMetadataPermissionFixture();
        using var env = fixture.Environment(Enum.Parse<MetadataPermissionOperator>(op));
        var d = new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[Execute].Member);
        var selected = ManagementClientEffects.Resolve(d, env);
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, env, [d],
            new GovernanceObservers { MetadataPermissions = fixture.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Variant).IsEqualTo("factory." + operation);
        await Assert.That(result.Passed && selected?.Key.Variant is "condition.metadata.elemMatch" or
            "permissions.metadata.elemMatch").IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
        await Assert.That(fixture.Remaining).IsEqualTo(0);
        await Assert.That(fixture.BorrowedPreserved).IsTrue();
        await Assert.That(fixture.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }

}
