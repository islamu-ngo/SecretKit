using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original native and generic routes share explicit principal source ownership.
public sealed class InfisicalTemplatePrincipalGateTests
{
    [Test]
    [Arguments(false, "ignored-copy")]
    [Arguments(true, "ignored-copy")]
    [Arguments(false, "copied-wrong-user")]
    [Arguments(true, "copied-wrong-user")]
    [Arguments(false, "coordinator-forgery")]
    [Arguments(true, "coordinator-forgery")]
    [Arguments(false, "lost-open")]
    [Arguments(true, "lost-open")]
    public async Task OriginalRoutesRejectIndependentPrincipalFaults(bool generic, string fault)
    {
        await using var fixture = new InfisicalTemplatePrincipalFixture(fault);
        using var env = fixture.Environment();
        const string execute = "i.management.ManagementClient.ExecuteAsync";
        var d = generic ?
            new NativeCaseDefinition(new("Infisical", execute, "factory." + TemplatePrincipalContract.Update,
                "local", "independent-effect"), InfisicalGovernanceFamilies.Bindings[execute].Member) :
            InfisicalTemplatePrincipalCalibrationTests.Definition(TemplatePrincipalContract.Update,
                "ProjectTemplateConfiguration.users.value", "independent-effect");
        var registry = new NativeCaseRegistry();
        var source = fixture.Source.CreateClient();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [d],
                new GovernanceObservers { TemplatePrincipals = source });
        else InfisicalProjectFamilies.Register(registry, env, [d], templatePrincipals: source);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = (await NativeCaseRunner.RunAsync(registry, [d], timeout.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await InfisicalTemplatePrincipalCalibrationTests.CleanAsync(fixture);
        if (fault == "coordinator-forgery")
        {
            await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
            await Assert.That(fixture.Originals).IsEqualTo(0);
        }
    }

    public static IEnumerable<(string Operation, string Variant, string Boundary)> NativeCases() =>
        TemplatePrincipalContract.CasesInventory();
    public static IEnumerable<(string Label, string Boundary)> GenericCases() =>
        from label in TemplatePrincipalContract.GenericLabels
        from boundary in TemplatePrincipalContract.Cases
        select (label, boundary);
    public static IEnumerable<(string Operation, string Variant, string Boundary, int Shape)> ProfileCases() =>
        from c in NativeCases()
        from shape in Enum.GetValues<TemplatePrincipalShape>()
        where shape == TemplatePrincipalShape.Values || c.Variant.EndsWith(".value", StringComparison.Ordinal)
        select (c.Operation, c.Variant, c.Boundary, (int)shape);
    [Test]
    [MethodDataSource(nameof(ProfileCases))]
    public async Task ORIGINALNativeRoutingMustUsePrincipalSource(string operation, string variant, string boundary, int shape)
    {
        await using var fixture = new InfisicalTemplatePrincipalFixture();
        using var env = fixture.Environment((TemplatePrincipalShape)shape);
        var d = InfisicalTemplatePrincipalCalibrationTests.Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        InfisicalProjectFamilies.Register(registry, env, [d], templatePrincipals: fixture.Source.CreateClient());
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = (await NativeCaseRunner.RunAsync(registry, [d], timeout.Token)).Single();
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await InfisicalTemplatePrincipalCalibrationTests.CleanAsync(fixture);
    }
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task ORIGINALGenericRoutingMustSelectPrincipalVariantAndRetainFactoryLabel(string label, string boundary)
    {
        await using var fixture = new InfisicalTemplatePrincipalFixture();
        using var env = fixture.Environment();
        const string execute = "i.management.ManagementClient.ExecuteAsync";
        var d = new NativeCaseDefinition(new("Infisical", execute, label, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[execute].Member);
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, env, [d],
            new GovernanceObservers { TemplatePrincipals = fixture.Source.CreateClient() });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = (await NativeCaseRunner.RunAsync(registry, [d], timeout.Token)).Single();
        await Assert.That(result.Variant).IsEqualTo(label);
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(ManagementClientEffects.Resolve(d, env)?.Key.Variant).IsEqualTo("ProjectTemplateConfiguration.users.value");
        await InfisicalTemplatePrincipalCalibrationTests.CleanAsync(fixture);
    }
}
