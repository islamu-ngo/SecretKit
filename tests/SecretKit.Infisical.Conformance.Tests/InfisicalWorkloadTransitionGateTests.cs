using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalWorkloadTransitionGateTests
{
    [Test]
    [Arguments(false, "ignored-mutation")]
    [Arguments(true, "ignored-mutation")]
    [Arguments(false, "issuer-join")]
    [Arguments(true, "issuer-join")]
    [Arguments(false, "source-echo")]
    [Arguments(true, "source-echo")]
    [Arguments(false, "lost-open")]
    [Arguments(true, "lost-open")]
    public async Task OriginalRoutesRejectIndependentCausalFaults(bool generic, string fault)
    {
        await using var provider = new InfisicalWorkloadTransitionFixture(fault);
        using var env = provider.Environment(InfisicalWorkloadTransitionCalibrationTests.Families());
        const string operation = WorkloadTransitionContract.Prefix + "UpdateKubernetesAuth";
        const string execute = "i.management.ManagementClient.ExecuteAsync";
        var d = generic ?
            new NativeCaseDefinition(new("Infisical", execute, "factory." + operation, "local", "independent-effect"),
                InfisicalGovernanceFamilies.Bindings[execute].Member) :
            InfisicalWorkloadTransitionCalibrationTests.Definition(operation, "templateId.value", "independent-effect");
        var registry = new NativeCaseRegistry();
        var source = provider.Source.CreateClient();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [d],
                new GovernanceObservers { WorkloadTransitions = source });
        else InfisicalIdentityAuthenticationFamilies.Register(registry, env, [d], workloadTransitions: source);
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Source.Opens).IsEqualTo(1);
        await Assert.That(provider.Source.Closes).IsEqualTo(1);
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }

    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases()
    {
        foreach (var pair in InfisicalIdentityAuthenticationFamilies.Bindings.Where(p =>
            p.Key.StartsWith("i.management.WorkloadIdentityAuthenticationOperations.", StringComparison.Ordinal)))
            foreach (string variant in pair.Value.Variants.Where(v =>
                !v.EndsWith(".rejected", StringComparison.Ordinal) && (v == "publicKeys.empty" ||
                v.Contains("templateId", StringComparison.Ordinal) || v.Contains("tokenReviewerJwt", StringComparison.Ordinal) ||
                v.Contains("reviewerJwt", StringComparison.Ordinal) || v.Contains("clearTokenReviewerJwt", StringComparison.Ordinal))))
                foreach (string boundary in new[] { "selected-contract", "independent-effect", "denied-authority",
                    "cancellation-boundary", "lost-response-no-replay" })
                    yield return (pair.Key, variant, boundary);
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeRegistrationRemainsUnavailableWithoutProfile(string operation, string variant, string boundary)
    {
        using var env = NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = "https://unreachable.invalid/",
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families = new Dictionary<string, object>()
        }));
        var d = new NativeCaseDefinition(new("Infisical", operation, variant, "local", boundary),
            InfisicalIdentityAuthenticationFamilies.Bindings[operation].Member);
        var registry = new NativeCaseRegistry();
        InfisicalIdentityAuthenticationFamilies.Register(registry, env, [d]);
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(InfisicalIdentityAuthenticationFamilies.UnavailableReason(d)).IsNotNull();
    }

    [Test]
    public async Task RetainedRejectedClearPairNeverEntersOptionalTransition()
    {
        const string operation = "i.management.WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth";
        var d = new NativeCaseDefinition(new("Infisical", operation,
            "KubernetesAuthConfigurationInput.clearTokenReviewerJwt.true.rejected", "local", "selected-contract"),
            InfisicalIdentityAuthenticationFamilies.Bindings[operation].Member);
        await Assert.That(InfisicalIdentityAuthenticationFamilies.UnavailableReason(d)).IsNull();
        await Assert.That(Cases().Count()).IsEqualTo(120);
        await Assert.That(Cases().Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(24);
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeRegistrationUsesOptionalProfile(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalWorkloadTransitionFixture();
        using var env = provider.Environment(InfisicalWorkloadTransitionCalibrationTests.Families());
        var d = InfisicalWorkloadTransitionCalibrationTests.Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        InfisicalIdentityAuthenticationFamilies.Register(registry, env, [d], workloadTransitions: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        bool gated = variant == "publicKeys.empty";
        await Assert.That(result.Passed).IsEqualTo(!gated).Because(result.ReasonCode);
        await Assert.That(provider.Source.Opens).IsEqualTo(gated ? 0 : 1);
        await Assert.That(provider.Originals).IsEqualTo(gated || boundary == "cancellation-boundary" ? 0 : 1);
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }

    public static IEnumerable<(string Operation, string Boundary)> GenericCases() =>
        Cases().Select(c => (c.Operation, c.Boundary)).Distinct();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task OriginalGenericRegistrationRetainsLabelAndSelectsOwnedProfile(string operation, string boundary)
    {
        await using var provider = new InfisicalWorkloadTransitionFixture();
        using var env = provider.Environment(InfisicalWorkloadTransitionCalibrationTests.Families());
        const string execute = "i.management.ManagementClient.ExecuteAsync";
        var d = new NativeCaseDefinition(new("Infisical", execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[execute].Member);
        var registry = new NativeCaseRegistry();
        var selected = ManagementClientEffects.Resolve(d, env);
        await Assert.That(selected is not null && WorkloadTransitionContract.Owns(selected)).IsTrue();
        InfisicalGovernanceFamilies.Register(registry, env, [d],
            new GovernanceObservers { WorkloadTransitions = provider.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        bool gated = selected!.Key.Variant == "publicKeys.empty";
        await Assert.That(result.Passed).IsEqualTo(!gated).Because(result.ReasonCode);
        await Assert.That(result.Variant).IsEqualTo("factory." + operation);
        await Assert.That(provider.Source.Opens).IsEqualTo(gated ? 0 : 1);
        await Assert.That(provider.Originals).IsEqualTo(gated || boundary == "cancellation-boundary" ? 0 : 1);
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }
}
