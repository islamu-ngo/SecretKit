using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original registrars share the scoped source with generic factory dispatch.
public sealed class InfisicalProjectTypeGateTests
{
    public static IEnumerable<(string Variant, string Boundary)> Cases() =>
        InfisicalProjectTypeCalibrationTests.Cases();
    public static IEnumerable<string> Boundaries() => ProjectTypeContract.Cases;
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalProjectRegistrationRequiresOwnedMatchingType(string variant, string boundary)
    {
        await using var provider = new InfisicalProjectTypeFixture();
        using var env = provider.Environment(InfisicalProjectTypeCalibrationTests.Families());
        var d = InfisicalProjectTypeCalibrationTests.Definition(variant, boundary);
        var registry = new NativeCaseRegistry();
        InfisicalProjectFamilies.Register(registry, env, [d], projectTypes: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(provider.Source.Opens).IsEqualTo(1);
        await Assert.That(provider.Source.Observations).IsEqualTo(2);
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }
    [Test]
    [MethodDataSource(nameof(Boundaries))]
    public async Task OriginalGenericFactoryRetainsLabelAndDefaultSelectedVariant(string boundary)
    {
        await using var provider = new InfisicalProjectTypeFixture();
        using var env = provider.Environment(InfisicalProjectTypeCalibrationTests.Families());
        const string execute = "i.management.ManagementClient.ExecuteAsync";
        var d = new NativeCaseDefinition(new("Infisical", execute, "factory." + ProjectTypeContract.Operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[execute].Member);
        var selected = ManagementClientEffects.Resolve(d);
        await Assert.That(selected?.Key.Operation).IsEqualTo(ProjectTypeContract.Operation);
        await Assert.That(selected?.Key.Variant).IsEqualTo("type.SecretManager");
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, env, [d],
            new GovernanceObservers { ProjectTypes = provider.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Variant).IsEqualTo("factory." + ProjectTypeContract.Operation);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(provider.Source.Opens).IsEqualTo(1);
        await Assert.That(provider.Source.Observations).IsEqualTo(2);
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }
    [Test]
    public async Task OriginalGenericReadOnlyLostResponseRemainsGated()
    {
        const string execute = "i.management.ManagementClient.ExecuteAsync";
        var d = new NativeCaseDefinition(new("Infisical", execute, "factory." + ProjectTypeContract.Operation,
            "local", "lost-response-no-replay"), InfisicalGovernanceFamilies.Bindings[execute].Member);
        await Assert.That(ManagementClientEffects.Resolve(d)).IsNull();
        await Assert.That(ManagementClientEffects.UnavailableReason(d)).IsEqualTo("read-only-factory-has-no-mutation-receipt");
    }

    [Test]
    [Arguments(false, "ignored-filter")]
    [Arguments(true, "ignored-filter")]
    [Arguments(false, "missing-positive")]
    [Arguments(true, "missing-positive")]
    [Arguments(false, "source-echo")]
    [Arguments(true, "source-echo")]
    [Arguments(false, "lost-open")]
    [Arguments(true, "lost-open")]
    public async Task OriginalRoutesRejectIndependentInventoryFaults(bool generic, string fault)
    {
        await using var provider = new InfisicalProjectTypeFixture(fault);
        using var env = provider.Environment(InfisicalProjectTypeCalibrationTests.Families());
        const string execute = "i.management.ManagementClient.ExecuteAsync";
        var d = generic ?
            new NativeCaseDefinition(new("Infisical", execute, "factory." + ProjectTypeContract.Operation,
                "local", "independent-effect"), InfisicalGovernanceFamilies.Bindings[execute].Member) :
            InfisicalProjectTypeCalibrationTests.Definition("type.CertificateManager", "independent-effect");
        var registry = new NativeCaseRegistry();
        var source = provider.Source.CreateClient();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [d], new GovernanceObservers { ProjectTypes = source });
        else InfisicalProjectFamilies.Register(registry, env, [d], projectTypes: source);
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Source.Opens).IsEqualTo(1);
        await Assert.That(provider.Source.Closes).IsEqualTo(1);
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }
}
