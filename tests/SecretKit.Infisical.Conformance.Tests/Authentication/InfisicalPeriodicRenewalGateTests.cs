using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original registration gate; a standalone witness registry cannot pass it.
public sealed class InfisicalPeriodicRenewalGateTests
{
    public static IEnumerable<(string Method, string Variant, string Boundary)> Cases() =>
        InfisicalPeriodicRenewalTests.OriginalCases();

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalRegistrationMustReachSelectedPeriodicSource(string method, string variant, string boundary)
    {
        await using var fixture = new InfisicalPeriodicRenewalFixture(variant);
        var row = InfisicalPeriodicRenewalTests.Row(method, variant, boundary);
        using var env = InfisicalPeriodicRenewalTests.Environment(fixture, row);
        var registry = new NativeCaseRegistry();
        InfisicalPeriodicTokenSessionEffects.Register(registry, env, [row], fixture.Clock, new LegacyUnavailable(),
            periodicRenewals: fixture.Source.Client());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = (await NativeCaseRunner.RunAsync(registry, [row], deadline.Token)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
    }

    private sealed class LegacyUnavailable : IInfisicalSessionLifetimeObserver
    {
        public ValueTask<SessionLifetimeFacts> MeasureAsync(SecretMaterial token, CancellationToken cancellationToken) =>
            throw new NativeCaseFailureException("observer-unavailable");
        public ValueTask ExpiredAsync(SecretMaterial token, InfisicalTokenLifetimeEvidence previous,
            CancellationToken cancellationToken) => throw new NativeCaseFailureException("observer-unavailable");
    }
}
