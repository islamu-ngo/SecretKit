using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalWorkloadTransitionEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        InfisicalWorkloadTransitionCalibrationTests.Cases();
    internal const string UpdateKubernetes = WorkloadTransitionContract.Prefix + "UpdateKubernetesAuth";
    internal const string UpdateOidc = WorkloadTransitionContract.Prefix + "UpdateOidcAuth";
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OptionalOperatorProvesActualMutationLoginAndFreshAccess(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalWorkloadTransitionFixture();
        var result = await RunAsync(provider, operation, variant, boundary);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(provider.Source.Opens).IsEqualTo(1);
        await Assert.That(provider.Source.Closes).IsEqualTo(1);
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Copies.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
    }
    [Test]
    [Arguments("ignored-mutation")]
    [Arguments("partial")]
    [Arguments("template-copy-unchanged")]
    [Arguments("wrong-reviewer")]
    [Arguments("fallback-reviewer")]
    [Arguments("wrong-issued-principal")]
    [Arguments("issuer-join")]
    [Arguments("source-echo")]
    [Arguments("review-revision")]
    [Arguments("review-duplicate")]
    [Arguments("access-principal")]
    [Arguments("runtime-fallback")]
    [Arguments("duplicate-request")]
    [Arguments("wrong-epoch")]
    [Arguments("wrong-deployment")]
    [Arguments("journal-schema")]
    [Arguments("commit-cause")]
    [Arguments("commit-predecessor")]
    [Arguments("intent-hash")]
    [Arguments("unterminated")]
    [Arguments("replay")]
    [Arguments("unheld-window")]
    [Arguments("unenrolled")]
    [Arguments("lost-reserve")]
    [Arguments("lost-open")]
    [Arguments("partial-open")]
    [Arguments("lost-arm")]
    [Arguments("cleanup-residual")]
    [Arguments("cleanup-incomplete-inventory")]
    [Arguments("cleanup-token-inventory")]
    [Arguments("borrowed-mutated")]
    public async Task IndependentFaultCannotBecomeAQualifiedEffect(string fault)
    {
        await using var provider = new InfisicalWorkloadTransitionFixture(fault);
        var result = await RunAsync(provider, UpdateKubernetes, "templateId.value", "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Source.Closes).IsEqualTo(1);
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        if (fault != "cleanup-residual") await Assert.That(provider.Remaining).IsEqualTo(0);
        if (fault != "borrowed-mutated") await Assert.That(provider.BorrowedPreserved).IsTrue();
        if (fault is "cleanup-residual" or "cleanup-incomplete-inventory" or "cleanup-token-inventory" or "borrowed-mutated")
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
    }
    [Test]
    [Arguments("ignored-mutation")]
    [Arguments("template-copy-unchanged")]
    [Arguments("issuer-join")]
    public async Task OidcTemplateEffectsAlsoRejectIndependentFaults(string fault)
    {
        await using var provider = new InfisicalWorkloadTransitionFixture(fault);
        var result = await RunAsync(provider, UpdateOidc, "templateId.value", "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Remaining).IsEqualTo(0);
    }
    [Test]
    [Arguments("lost-nonapplied", true, 0)]
    [Arguments("partial", false, 1)]
    [Arguments("", true, 1)]
    public async Task LostOriginalUsesCausalCommitJournalNotSdkEcho(string fault, bool passed, int commits)
    {
        await using var provider = new InfisicalWorkloadTransitionFixture(fault);
        var result = await RunAsync(provider, UpdateKubernetes, "templateId.value", "lost-response-no-replay");
        await Assert.That(result.Passed).IsEqualTo(passed);
        await Assert.That(provider.Source.Fences.Single().Commits.Length).IsEqualTo(commits);
        await Assert.That(provider.Source.Fences.Single().Requests.Length).IsEqualTo(1);
        await Assert.That(provider.Originals).IsEqualTo(1);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }
    internal static async Task<NativeCaseResult> RunAsync(InfisicalWorkloadTransitionFixture provider,
        string operation, string variant, string boundary)
    {
        using var env = provider.Environment(InfisicalWorkloadTransitionCalibrationTests.Families());
        var d = InfisicalWorkloadTransitionCalibrationTests.Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        registry.Add(new(d, async (probe, token) =>
        {
            await using var context = new IdentityAuthContext(env, "C08-IM-WorkloadIdentityAuthentication", d, probe);
            await WorkloadTransitionEffects.ExecuteAsync(context, provider.Source.CreateClient(), token);
        }));
        return (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
    }
}
