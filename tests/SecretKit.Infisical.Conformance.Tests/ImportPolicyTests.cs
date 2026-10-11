namespace SecretKit.Infisical.Conformance.Tests;

public sealed class ImportPolicyTests
{
    [Test]
    public async Task CreationAndFreshDeniedDeliveryDoNotAttestDestinationPolicy() =>
        await IdentitySetupTests.RunAsync(OwnedConformanceScenario.ImportEffects);

    [Test]
    public async Task ReplicationRequiresAnActuallyEntitledOwnedSandbox() =>
        await IdentitySetupTests.RunAsync(OwnedConformanceScenario.ImportPolicy);
}
