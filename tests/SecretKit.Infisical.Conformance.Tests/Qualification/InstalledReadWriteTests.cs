namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InstalledReadWriteTests
{
    [Test]
    public async Task PackageOnlyConsumerRunsNativeAndConsumerWorkflowsWithSeparateActors() =>
        await IdentitySetupTests.RunAsync(OwnedConformanceScenario.InstalledWorkflows);
}
