using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalOrganizationUserEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        InfisicalOrganizationUserCalibrationTests.Cases();

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OwnedEffectsCoverEveryRetainedNativeRowWithoutMetadataPromotion(
        string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalOrganizationUserFixture();
        var definition = InfisicalOrganizationUserCalibrationTests.Definition(operation, variant, boundary);
        var result = await RunAsync(provider, definition);
        bool gated = OrganizationUserContract.Gated(variant);
        await Assert.That(result.Passed).IsEqualTo(!gated).Because(result.ReasonCode);
        await Assert.That(result.ReasonCode).IsEqualTo(gated ? "observer-unavailable" : "observed");
        await Assert.That(provider.Source.Opens).IsEqualTo(gated ? 0 : 1);
        await Assert.That(provider.Source.Observations).IsEqualTo(gated ? 0 : 2);
        await Assert.That(provider.Source.Closes).IsEqualTo(gated ? 0 : 1);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        if (!gated)
        {
            await Assert.That(provider.RequestJournal.Count).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            await Assert.That(provider.AccessJournal.Any(e => e.Access.PrincipalId == InfisicalOrganizationUserFixture.Authorities.Runtime)).IsFalse();
            await Assert.That(provider.AccessJournal.Where(e => e.Access.CredentialId is not null)
                .All(e => provider.UserIssuerJournal.Any(j => j.User == e.Access.PrincipalId &&
                    j.Credential == e.Access.CredentialId && j.Hash == e.Access.CredentialHash))).IsTrue();
        }
    }

    [Test]
    [Arguments("ignored-mutation", "effect-mismatch")]
    [Arguments("access-ignores-role", "effect-mismatch")]
    [Arguments("wrong-user-accepted", "effect-mismatch")]
    [Arguments("denied-accepted", "effect-mismatch")]
    [Arguments("valid-recheck-denied", "effect-mismatch")]
    [Arguments("list-duplicate", "effect-mismatch")]
    [Arguments("list-missing", "effect-mismatch")]
    [Arguments("borrowed-mutated", "cleanup-incomplete")]
    [Arguments("credential-wrong-user", "observer-unavailable")]
    [Arguments("membership-wrong-user", "observer-unavailable")]
    [Arguments("metadata-echo", "observer-unavailable")]
    [Arguments("access-wrong-principal", "effect-mismatch")]
    [Arguments("wrong-epoch", "observer-unavailable")]
    [Arguments("nonterminal", "observer-unavailable")]
    [Arguments("late-work", "observer-unavailable")]
    [Arguments("replayed-original", "observer-unavailable")]
    [Arguments("cleanup-residual", "cleanup-incomplete")]
    [Arguments("lost-open", "observer-unavailable")]
    public async Task IndependentProviderFaultsCannotBecomeSuccessfulEffects(string fault, string reason)
    {
        await using var provider = new InfisicalOrganizationUserFixture(fault);
        var definition = InfisicalOrganizationUserCalibrationTests.Definition(
            OrganizationUserContract.Prefix + "UpdateOrganizationMembership", "role.value", "independent-effect");
        var result = await RunAsync(provider, definition);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(provider.Source.Opens).IsEqualTo(1);
        await Assert.That(provider.Source.Closes).IsEqualTo(1);
        await Assert.That(provider.Remaining).IsEqualTo(fault == "cleanup-residual" ? 2 : 0);
    }

    [Test]
    [Arguments("", true, "observed")]
    [Arguments("lost-nonapplied", true, "observed")]
    [Arguments("lost-partial", false, "observer-unavailable")]
    [Arguments("receipt-substituted", false, "observer-unavailable")]
    public async Task LostOutcomeUsesTerminalSourceClassificationWithoutReceiptUpgrade(
        string fault, bool passed, string reason)
    {
        await using var provider = new InfisicalOrganizationUserFixture(fault);
        var definition = InfisicalOrganizationUserCalibrationTests.Definition(OrganizationUserContract.Batch,
            "input.organizationId-membershipIds", "lost-response-no-replay");
        var result = await RunAsync(provider, definition);
        await Assert.That(result.Passed).IsEqualTo(passed).Because(result.ReasonCode);
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(provider.RequestJournal.Count).IsEqualTo(1);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        if (fault != "receipt-substituted")
            await Assert.That(provider.Source.Fences.Single().Receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    internal static async Task<NativeCaseResult> RunAsync(InfisicalOrganizationUserFixture provider, NativeCaseDefinition definition)
    {
        using var env = provider.Environment(InfisicalOrganizationUserCalibrationTests.Families());
        provider.Source.LoseResponse = definition.Key.Case == "lost-response-no-replay";
        var registry = new NativeCaseRegistry();
        registry.Add(new(definition, async (probe, token) =>
        {
            var context = new ProjectFamilyContext(env, definition.Key.Operation == OrganizationUserContract.Batch ?
                "MembershipMutations" : "OrganizationMemberships", definition, probe);
            try { await OrganizationUserEffects.ExecuteAsync(context, provider.Source.CreateClient(), token); }
            finally { await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
    }
}
