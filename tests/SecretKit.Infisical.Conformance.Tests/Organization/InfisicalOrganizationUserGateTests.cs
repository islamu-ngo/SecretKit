using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalOrganizationUserGateTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        InfisicalOrganizationUserCalibrationTests.Cases();
    public static IEnumerable<(string Operation, string Boundary)> Factories() =>
        new[] { OrganizationUserContract.Prefix + "UpdateOrganizationMembership",
            OrganizationUserContract.Prefix + "DeleteOrganizationMembership",
            OrganizationUserContract.Prefix + "ListOrganizationMemberships", OrganizationUserContract.Batch }
        .SelectMany(op => OrganizationUserContract.Cases.Select(boundary => (op, boundary)));

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeRegistrationRequiresFreshSourceOwnership(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalOrganizationUserFixture();
        using var env = provider.Environment(InfisicalOrganizationUserCalibrationTests.Families());
        var definition = InfisicalOrganizationUserCalibrationTests.Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        if (operation == OrganizationUserContract.Batch)
            InfisicalProjectFamilies.Register(registry, env, [definition], organizationUsers: provider.Source.CreateClient());
        else InfisicalIdentityAuthenticationFamilies.Register(registry, env, [definition],
            organizationUsers: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        bool gated = OrganizationUserContract.Gated(variant);
        await Assert.That(provider.Source.Opens).IsEqualTo(gated ? 0 : 1).Because(result.ReasonCode);
        await Assert.That(result.Passed).IsEqualTo(!gated).Because(result.ReasonCode);
        await Assert.That(result.ReasonCode).IsEqualTo(gated ? "observer-unavailable" : "observed");
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }

    [Test]
    [MethodDataSource(nameof(Factories))]
    public async Task OriginalGenericFactoryRequiresTheSameOwnedSource(string operation, string boundary)
    {
        await using var provider = new InfisicalOrganizationUserFixture();
        using var env = provider.Environment(InfisicalOrganizationUserCalibrationTests.Families());
        const string execute = "i.management.ManagementClient.ExecuteAsync";
        var definition = new NativeCaseDefinition(new("Infisical", execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[execute].Member);
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { OrganizationUsers = provider.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        bool gated = operation.EndsWith(".ListOrganizationMemberships", StringComparison.Ordinal) &&
            boundary == "lost-response-no-replay";
        await Assert.That(provider.Source.Opens).IsEqualTo(gated ? 0 : 1).Because(result.ReasonCode);
        await Assert.That(result.Passed).IsEqualTo(!gated).Because(result.ReasonCode);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }

    [Test]
    [Arguments(false, "ignored-mutation", "effect-mismatch")]
    [Arguments(true, "ignored-mutation", "effect-mismatch")]
    [Arguments(false, "wrong-user-accepted", "effect-mismatch")]
    [Arguments(true, "wrong-user-accepted", "effect-mismatch")]
    [Arguments(false, "credential-wrong-user", "observer-unavailable")]
    [Arguments(true, "credential-wrong-user", "observer-unavailable")]
    [Arguments(false, "lost-open", "observer-unavailable")]
    [Arguments(true, "lost-open", "observer-unavailable")]
    public async Task OriginalRoutesRejectIndependentUserFaults(bool generic, string fault, string reason)
    {
        await using var provider = new InfisicalOrganizationUserFixture(fault);
        using var env = provider.Environment(InfisicalOrganizationUserCalibrationTests.Families());
        const string operation = OrganizationUserContract.Prefix + "UpdateOrganizationMembership";
        const string execute = "i.management.ManagementClient.ExecuteAsync";
        var definition = generic ?
            new NativeCaseDefinition(new("Infisical", execute, "factory." + operation, "local", "independent-effect"),
                InfisicalGovernanceFamilies.Bindings[execute].Member) :
            InfisicalOrganizationUserCalibrationTests.Definition(operation, "role.value", "independent-effect");
        var registry = new NativeCaseRegistry();
        var source = provider.Source.CreateClient();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [definition],
                new GovernanceObservers { OrganizationUsers = source });
        else InfisicalIdentityAuthenticationFamilies.Register(registry, env, [definition], organizationUsers: source);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(provider.Source.Opens).IsEqualTo(1);
        await Assert.That(provider.Source.Closes).IsEqualTo(1);
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }
}
