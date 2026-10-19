using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class NativeInfrastructureTests
{
    [Test]
    public async Task MissingSelectedRoleFailsWithoutConstructingRemoteClients()
    {
        using JsonDocument settings = JsonDocument.Parse("""{"origin":"https://fixture.infisical.invalid","families":{}}""");
        await Assert.That(() => NativeEnvironment.Create(settings.RootElement)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task InstalledNativeCasesRequireOwnedGateInputs()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        var report = await NativeConsumerLauncher.RunFromEnvironmentAsync(root, "Infisical", CancellationToken.None);
        await Assert.That(report.Discovered).IsGreaterThan(0);
        await Assert.That(report.ExitCode).IsEqualTo(0).Because("Native gate failed; protected diagnostics withheld.");
        await Assert.That(report.Failed).IsEqualTo(0);
    }
}
