using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalProjectTypeEffectTests
{
    public static IEnumerable<(string Variant, string Boundary)> Cases() => InfisicalProjectTypeCalibrationTests.Cases();
    public static IEnumerable<string> Faults() => new[]
    {
        "ignored-filter", "ignored-roles-filter", "storage-wrong-type", "missing-positive", "empty-positive", "singleton-positive",
        "duplicate", "incomplete-list", "wrong-scope", "denied-accepted", "borrowed-mutated", "cleanup-residual",
        "source-echo", "roles-omitted", "roles-wrong-project", "field-mismatch", "missing-field", "storage-incomplete",
        "metadata-mismatch", "metadata-omitted",
        "incomplete-inventory", "unqualified-access", "unqualified-issuance", "unheld-window",
        "unexclusive-ingress", "wrong-original-actor", "wrong-original-query", "replayed-original",
        "nonterminal", "late-work", "access-wrong-actor", "access-wrong-query", "access-replay",
        "wrong-epoch", "wrong-deployment", "wrong-clock", "stale-sequence", "wrong-root", "wrong-revision",
        "wrong-registration", "wrong-source", "duplicate-event", "inventory-missing", "lost-reserve",
        "partial-open", "lost-open", "collision"
    };

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OwnedTypedEffectsCoverAllRetainedNativeCases(string variant, string boundary)
    {
        await using var provider = new InfisicalProjectTypeFixture();
        using var env = provider.Environment(InfisicalProjectTypeCalibrationTests.Families());
        var result = await Run(provider, env, variant, boundary);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(provider.Source.Opens).IsEqualTo(1);
        await Assert.That(provider.Source.Observations).IsEqualTo(2);
        await Assert.That(provider.RequestJournal.Count).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.Source.Kind).IsEqualTo(ProjectTypeSourceKind.ControlledFixture);
    }
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task ActualNativeAndIndependentSourceFaultsCannotCertifySuccess(string fault)
    {
        await using var provider = new InfisicalProjectTypeFixture(fault);
        using var env = provider.Environment(InfisicalProjectTypeCalibrationTests.Families());
        var result = await Run(provider, env, fault is "roles-omitted" or "roles-wrong-project" ?
            "includeRoles.true" : "type.CertificateManager",
            "independent-effect");
        await Assert.That(result.Passed).IsFalse().Because(fault);
        await Assert.That(provider.Source.Closes).IsEqualTo(1).Because(result.ReasonCode);
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.Remaining == 0 || fault == "cleanup-residual").IsTrue();
        await Assert.That(provider.BorrowedPreserved || fault == "borrowed-mutated").IsTrue();
        if (fault is "cleanup-residual" or "borrowed-mutated")
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
    }
    [Test]
    public async Task ReadOnlyLostResponseIsNotAdmittedEvenWithPrivateInput()
    {
        await using var provider = new InfisicalProjectTypeFixture();
        using var env = provider.Environment(InfisicalProjectTypeCalibrationTests.Families());
        var result = await Run(provider, env, "type.CertificateManager", "lost-response-no-replay");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Source.Opens).IsEqualTo(0);
    }
    internal static async Task<NativeCaseResult> Run(InfisicalProjectTypeFixture provider, NativeEnvironment env,
        string variant, string boundary)
    {
        var d = InfisicalProjectTypeCalibrationTests.Definition(variant, boundary);
        var registry = new NativeCaseRegistry();
        registry.Add(new(d, async (probe, token) =>
        {
            ProjectFamilyContext? context = null;
            try
            {
                context = new(env, "Projects", d, probe);
                await ProjectTypeEffects.ExecuteAsync(context, provider.Source.CreateClient(), token);
            }
            finally { if (context is not null) await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
    }
}
