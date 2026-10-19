using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalBulkAuxiliaryGateTests
{
    public static IEnumerable<(string Method, string Variant, string Boundary)> Cases() =>
        InfisicalBulkAuxiliaryCalibrationTests.Cases();

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalRegistrationPreservesEveryBulkVariantAndBoundary(string method, string variant, string boundary)
    {
        await using var provider = new InfisicalBulkAuxiliaryFixture();
        var definition = InfisicalBulkAuxiliaryCalibrationTests.Definition(method, variant, boundary);
        var input = InfisicalBulkAuxiliaryCalibrationTests.Input(method, variant, boundary);
        try
        {
            using var env = provider.Environment(InfisicalBulkAuxiliaryCalibrationTests.Family(definition, input));
            var registry = new NativeCaseRegistry();
            InfisicalStaticFamilies.Register(registry, env, [definition],
                bulkAuxiliary: provider.Source.CreateObserver());
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(40));
            var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
            bool gated = BulkAuxiliaryContract.Gated(variant);
            await Assert.That(result.Passed).IsEqualTo(!gated).Because(result.ReasonCode);
            await Assert.That(result.ReasonCode).IsEqualTo(gated ? "observer-unavailable" : "observed");
            await Assert.That(provider.Source.Opens).IsEqualTo(gated ? 0 : 1);
            await Assert.That(provider.Source.Observations).IsEqualTo(gated ? 0 : 1);
            await Assert.That(provider.ResidualCount).IsEqualTo(0);
            await Assert.That(provider.Source.Registrations).IsEqualTo(0);
            await Assert.That(provider.BorrowedPreserved).IsTrue();
        }
        finally { InfisicalBulkAuxiliaryCalibrationTests.Erase(input); }
    }

    [Test]
    public async Task OriginalRegistrationMustOpenAuxiliarySourceBeforeClaimingEncryptedPersistence()
    {
        await using var provider = new InfisicalBulkAuxiliaryFixture();
        var definition = InfisicalBulkAuxiliaryCalibrationTests.Definition("CreateSecretsAsync",
            "metadata.encrypted", "independent-effect");
        var input = InfisicalBulkAuxiliaryCalibrationTests.Input("CreateSecretsAsync",
            "metadata.encrypted", "independent-effect");
        try
        {
            using var env = provider.Environment(InfisicalBulkAuxiliaryCalibrationTests.Family(definition, input));
            var registry = new NativeCaseRegistry();
            InfisicalStaticFamilies.Register(registry, env, [definition],
                bulkAuxiliary: provider.Source.CreateObserver());
            var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
            // Positive original registration gate, not a standalone registry.
            await Assert.That(provider.Source.Opens).IsEqualTo(1).Because("source-not-opened:" + result.ReasonCode);
            await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
            await Assert.That(provider.Source.Observations).IsEqualTo(1);
            await Assert.That(provider.ResidualCount).IsEqualTo(0);
        }
        finally { InfisicalBulkAuxiliaryCalibrationTests.Erase(input); }
    }
}
