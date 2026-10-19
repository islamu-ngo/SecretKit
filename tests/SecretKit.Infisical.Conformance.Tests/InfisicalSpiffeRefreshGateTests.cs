using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Positive requirement against the original registration and generic dispatcher.
public sealed class InfisicalSpiffeRefreshGateTests
{
    public static IEnumerable<string> Cases() => InfisicalSpiffeRefreshCalibrationTests.Boundaries;

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalRegistrationMustReachSelectedSpiffeRefreshSource(string boundary)
    {
        await using var fixture = new InfisicalSpiffeRefreshFixture();
        using var env = InfisicalSpiffeRefreshCalibrationTests.Environment(fixture);
        const string operation = "i.management.ExternalIdentityAuthenticationOperations.RefreshSpiffeBundle";
        var binding = InfisicalIdentityAuthenticationFamilies.Bindings[operation];
        var row = new NativeCaseDefinition(new("Infisical", operation, "input.organizationId-identityId", "local", boundary),
            binding.Member);
        var registry = new NativeCaseRegistry();
        InfisicalIdentityAuthenticationFamilies.Register(registry, env, [row],
            spiffeRefresh: fixture.Source.Client());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = (await NativeCaseRunner.RunAsync(registry, [row], deadline.Token)).Single();
        Console.WriteLine($"SPIFFE original registration {boundary}: {result.ReasonCode}, opens={fixture.Source.Opens}, requests={fixture.Requests.Count}");
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
        await Assert.That(fixture.OwnedManagementResources).IsEqualTo(0);
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalGenericDispatchMustReachSelectedSpiffeRefreshSource(string boundary)
    {
        await using var fixture = new InfisicalSpiffeRefreshFixture();
        using var env = InfisicalSpiffeRefreshCalibrationTests.Environment(fixture);
        const string operation = "i.management.ManagementClient.ExecuteAsync";
        var row = new NativeCaseDefinition(new("Infisical", operation,
            "factory." + InfisicalSpiffeRefreshEffects.Operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[operation].Member);
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, env, [row],
            new GovernanceObservers { SpiffeRefresh = fixture.Source.Client() });
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = (await NativeCaseRunner.RunAsync(registry, [row], deadline.Token)).Single();
        Console.WriteLine($"SPIFFE original generic dispatch {boundary}: {result.ReasonCode}, opens={fixture.Source.Opens}, requests={fixture.Requests.Count}");
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
        await Assert.That(fixture.OwnedManagementResources).IsEqualTo(0);
    }

    [Test]
    [Arguments("ack-only", false)]
    [Arguments("wrong-cache", false)]
    [Arguments("ack-only", true)]
    [Arguments("wrong-cache", true)]
    public async Task OriginalHandlersRejectNoOpAndWrongIssuerCache(string mode, bool generic)
    {
        await using var fixture = new InfisicalSpiffeRefreshFixture(mode);
        using var env = InfisicalSpiffeRefreshCalibrationTests.Environment(fixture);
        string operation = generic ? "i.management.ManagementClient.ExecuteAsync" : InfisicalSpiffeRefreshEffects.Operation;
        string variant = generic ? "factory." + InfisicalSpiffeRefreshEffects.Operation : "input.organizationId-identityId";
        string member = generic ? InfisicalGovernanceFamilies.Bindings[operation].Member :
            InfisicalIdentityAuthenticationFamilies.Bindings[operation].Member;
        var row = new NativeCaseDefinition(new("Infisical", operation, variant, "local", "independent-effect"), member);
        var registry = new NativeCaseRegistry();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [row],
                new GovernanceObservers { SpiffeRefresh = fixture.Source.Client() });
        else
            InfisicalIdentityAuthenticationFamilies.Register(registry, env, [row], spiffeRefresh: fixture.Source.Client());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = (await NativeCaseRunner.RunAsync(registry, [row], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
        await Assert.That(fixture.Requests.Count).IsEqualTo(1);
        await Assert.That(fixture.OwnedManagementResources).IsEqualTo(0);
    }
}
