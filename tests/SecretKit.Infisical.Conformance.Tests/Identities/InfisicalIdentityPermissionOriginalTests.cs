using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original registrar/resolver routes retain their factory labels and explicitly
// select a source independently of the provider transport.
public sealed class InfisicalIdentityPermissionOriginalTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalIdentityPermissionGateTests.Cases()
        .Where(c => IdentityPermissionContract.Gate(IdentityPermissionContract.Scope(c.Operation), InfisicalIdentityPermissionGateTests.Action(c.Variant)) is null);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeIdentityRouteRequiresIndependentEffect(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalIdentityPermissionFixture(); using var env = provider.Environment(operation, InfisicalIdentityPermissionGateTests.Action(variant));
        var definition = InfisicalIdentityPermissionGateTests.Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [definition], identityPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], identityPermissions: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(provider.Opens).IsEqualTo(1);
        await InfisicalIdentityPermissionEffectTests.Clean(provider);
    }
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from operation in IdentityPermissionContract.Operations.Take(6)
        from boundary in IdentityPermissionContract.Boundaries
        from action in IdentityPermissionContract.Supported(IdentityPermissionScope.Project)
        select (operation, boundary, (int)action);
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task OriginalGenericFactorySelectsConfiguredIdentityAction(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalIdentityPermissionFixture(); using var env = provider.Environment(operation, (IdentityPermissionAction)action);
        var definition = new NativeCaseDefinition(new("Infisical", InfisicalIdentityPermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalIdentityPermissionGateTests.Execute].Member);
        var selected = ManagementClientEffects.Resolve(definition, env);
        await Assert.That(selected?.Key.Variant).IsEqualTo(IdentityPermissionContract.Variant((IdentityPermissionAction)action));
        var registry = new NativeCaseRegistry(); InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { IdentityPermissions = provider.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(result.Variant).IsEqualTo(definition.Key.Variant);
        await InfisicalIdentityPermissionEffectTests.Clean(provider);
    }

    public static IEnumerable<(string Operation, int Action, string Fault, bool Generic)> Failures() =>
        from operation in IdentityPermissionContract.Operations
        from control in new[]
        {
            (IdentityPermissionAction.Read, "ignored-policy"),
            (IdentityPermissionAction.Read, "actor-kind"),
            (IdentityPermissionAction.Read, "binding-substitution"),
            (IdentityPermissionAction.Read, "forged-journal"),
            (IdentityPermissionAction.Read, "lost-open"),
            (IdentityPermissionAction.CreateToken, "replayed-token"),
            (IdentityPermissionAction.CreateToken, "target-read-policy-actor"),
            (IdentityPermissionAction.DeleteToken, "revoke-ack-only")
        }
        from generic in IdentityPermissionContract.Operations.Take(6).Contains(operation) ? new[] { false, true } : new[] { false }
        select (operation, (int)control.Item1, control.Item2, generic);

    [Test]
    [MethodDataSource(nameof(Failures))]
    public async Task OriginalRoutesRejectUnprovenIdentityOrTargetTokenEffects(string operation, int action, string fault, bool generic)
    {
        await using var provider = new InfisicalIdentityPermissionFixture(fault);
        using var env = provider.Environment(operation, (IdentityPermissionAction)action);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalIdentityPermissionGateTests.Execute,
            "factory." + operation, "local", "independent-effect"),
            InfisicalGovernanceFamilies.Bindings[InfisicalIdentityPermissionGateTests.Execute].Member) :
            InfisicalIdentityPermissionGateTests.Definition(operation,
                IdentityPermissionContract.Variant((IdentityPermissionAction)action), "independent-effect");
        var registry = new NativeCaseRegistry();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [definition],
                new GovernanceObservers { IdentityPermissions = provider.Source.CreateClient() });
        else if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [definition], identityPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], identityPermissions: provider.Source.CreateClient());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Closes).IsEqualTo(1);
        await InfisicalIdentityPermissionEffectTests.Clean(provider);
    }

}
