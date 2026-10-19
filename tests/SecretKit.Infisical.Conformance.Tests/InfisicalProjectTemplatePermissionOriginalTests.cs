using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original routes select the owned source explicitly and retain factory labels.
public sealed class InfisicalProjectTemplatePermissionOriginalTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalProjectTemplatePermissionGateTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeTemplatePermissionsRequireIndependentEffect(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalProjectTemplatePermissionFixture(); using var env = provider.Environment(operation, InfisicalProjectTemplatePermissionGateTests.Action(variant));
        var definition = InfisicalProjectTemplatePermissionGateTests.Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        InfisicalPermissionFamilies.Register(registry, env, [definition],
            projectTemplatePermissions: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(provider.Opens).IsEqualTo(1); await InfisicalProjectTemplatePermissionEffectTests.Clean(provider);
    }
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from operation in ProjectTemplatePermissionContract.Operations
        from boundary in ProjectTemplatePermissionContract.Boundaries
        from action in Enum.GetValues<ProjectTemplatePermissionAction>()
        select (operation, boundary, (int)action);
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task OriginalGenericRetainsFactoryAndSelectsConfiguredAction(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalProjectTemplatePermissionFixture(); using var env = provider.Environment(operation, (ProjectTemplatePermissionAction)action);
        var definition = new NativeCaseDefinition(new("Infisical", InfisicalProjectTemplatePermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalProjectTemplatePermissionGateTests.Execute].Member);
        var selected = ManagementClientEffects.Resolve(definition, env);
        await Assert.That(selected?.Key.Variant).IsEqualTo(ProjectTemplatePermissionContract.Variant((ProjectTemplatePermissionAction)action));
        var registry = new NativeCaseRegistry(); InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { ProjectTemplatePermissions = provider.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Assert.That(result.Variant).IsEqualTo(definition.Key.Variant);
        await InfisicalProjectTemplatePermissionEffectTests.Clean(provider);
    }

    public static IEnumerable<(string Operation, string Fault, bool Generic)> Failures() =>
        from operation in ProjectTemplatePermissionContract.Operations
        from fault in new[] { "ignored-policy", "incomplete-policy", "wrong-template", "actor-kind",
            "binding-borrowed", "forged-journal", "lost-open", "partial-open" }
        from generic in new[] { false, true }
        select (operation, fault, generic);

    [Test]
    [MethodDataSource(nameof(Failures))]
    public async Task OriginalRoutesRejectUnprovenTemplatePermissionAndRecover(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalProjectTemplatePermissionFixture(fault);
        using var env = provider.Environment(operation, ProjectTemplatePermissionAction.Read);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalProjectTemplatePermissionGateTests.Execute,
            "factory." + operation, "local", "independent-effect"),
            InfisicalGovernanceFamilies.Bindings[InfisicalProjectTemplatePermissionGateTests.Execute].Member) :
            InfisicalProjectTemplatePermissionGateTests.Definition(operation,
                "permission.ProjectTemplates.read", "independent-effect");
        var registry = new NativeCaseRegistry();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [definition],
                new GovernanceObservers { ProjectTemplatePermissions = provider.Source.CreateClient() });
        else InfisicalPermissionFamilies.Register(registry, env, [definition],
            projectTemplatePermissions: provider.Source.CreateClient());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Closes).IsEqualTo(1);
        await InfisicalProjectTemplatePermissionEffectTests.Clean(provider);
    }
}
