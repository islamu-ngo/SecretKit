using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Exercises the original registry rather than the standalone calibration registry.
public sealed class InfisicalRotationMaterialGateTests
{
    public static IEnumerable<(string Method, string Variant, string Boundary)> Cases() =>
        InfisicalRotationMaterialTests.OriginalCases();

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalReadDispatchMustReachSourceQualifiedMaterialWitness(
        string method, string variant, string boundary)
    {
        var profile = variant.StartsWith("profile.", StringComparison.Ordinal) ?
            Enum.Parse<InfisicalRotationProfile>(variant[8..]) : InfisicalRotationProfile.PostgresCredentials;
        await using var fixture = new InfisicalRotationMaterialFixture(profile);
        var row = InfisicalRotationMaterialTests.Row(method, variant, boundary);
        using var environment = InfisicalRotationMaterialTests.Environment(row, fixture.Input());
        var registry = new NativeCaseRegistry();
        // The legacy no-I/O tripwire must never own an explicitly selected
        // material trial; it also prevents accidental external setup.
        InfisicalRotationClientEffects.Register(registry, environment, [row], factory: new LegacyUnavailable(),
            offlineTransport: fixture.MetadataTransport,
            offlineConsumerFactory: env => fixture.Consumer(env, NativeIdentityRole.Runtime),
            rotationMaterials: fixture.Source.Client(),
            rotationMaterialConsumers: role => fixture.Consumer(environment, role));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = (await NativeCaseRunner.RunAsync(registry, [row], deadline.Token)).Single();
        bool pinned = RotationMaterialProfile.For(profile).Pinned;
        await Assert.That(result.Passed).IsEqualTo(pinned).Because(result.ReasonCode);
        if (pinned) await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        else await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
    }

    private sealed class LegacyUnavailable : IInfisicalRotationFixtureFactory
    {
        public ValueTask<IInfisicalRotationOwnedFixture> CreateAsync(NativeEnvironment env,
            InfisicalRotationClientEffects.RotationInput input, NativeCaseProbe probe, CancellationToken token) =>
            throw new NativeCaseFailureException("observer-unavailable");
    }
}
