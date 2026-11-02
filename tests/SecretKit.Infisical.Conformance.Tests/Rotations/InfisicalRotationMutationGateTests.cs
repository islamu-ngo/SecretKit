using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Reaches the selected witness through the original registration, never a
// duplicate standalone registry.
public sealed class InfisicalRotationMutationGateTests
{
    public static IEnumerable<(string Method, string Variant, string Boundary)> Cases() =>
        InfisicalRotationMutationTests.OriginalCases();

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalRegistrationMustReachSelectedMutationSource(string method, string variant, string boundary)
    {
        await using var fixture = new InfisicalRotationMutationFixture(InfisicalRotationMutationTests.Profile(variant));
        var row = InfisicalRotationMutationTests.Row(method, variant, boundary);
        using var environment = InfisicalRotationMutationTests.Environment(row, fixture.Input());
        var registry = new NativeCaseRegistry();
        InfisicalRotationClientEffects.Register(registry, environment, [row], factory: new LegacyUnavailable(),
            offlineTransport: fixture.Transport,
            offlineConsumerFactory: env => fixture.Consumer(env, NativeIdentityRole.Runtime),
            rotationMutations: fixture.Source.Client(),
            rotationMutationConsumers: role => fixture.Consumer(environment, role));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = (await NativeCaseRunner.RunAsync(registry, [row], deadline.Token)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
    }

    private sealed class LegacyUnavailable : IInfisicalRotationFixtureFactory
    {
        public ValueTask<IInfisicalRotationOwnedFixture> CreateAsync(NativeEnvironment env,
            InfisicalRotationClientEffects.RotationInput input, NativeCaseProbe probe, CancellationToken token) =>
            throw new NativeCaseFailureException("observer-unavailable");
    }
}
