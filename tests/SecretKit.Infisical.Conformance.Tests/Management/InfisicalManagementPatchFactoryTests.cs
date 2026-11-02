using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalManagementPatchFactoryTests
{
    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task GenericProxyUpdateUsesTheSelectedIndependentWitness(string boundary)
    {
        await using var fixture = new InfisicalProxyPatchEffectFixture();
        using var environment = fixture.Environment();
        const string operation = "i.management.ManagementClient.ExecuteAsync";
        var definition = new NativeCaseDefinition(
            new("Infisical", operation, "factory." + InfisicalProxyPatchEffectTests.Operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[operation].Member);
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, environment, [definition], fixture.Observers);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None))[0];
        await Assert.That(fixture.Source.Opens).IsEqualTo(1).Because(result.ReasonCode);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Source.Registrations).IsEqualTo(0);
        await Assert.That(fixture.Source.PrivateCopiesDestroyed).IsTrue();
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
    }
}
