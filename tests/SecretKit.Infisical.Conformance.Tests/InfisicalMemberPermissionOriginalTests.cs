using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// These exercise the original registrar/resolver routes with an explicitly owned
// source. Source-absent behavior is characterized separately by the gate tests.
public sealed class InfisicalMemberPermissionOriginalTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        InfisicalMemberPermissionCalibrationTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeMemberRouteRequiresIndependentEffect(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalMemberPermissionFixture();
        using var env = provider.Environment(operation, InfisicalMemberPermissionGateTests.Action(variant));
        var d = InfisicalMemberPermissionGateTests.Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [d], memberPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [d], memberPermissions: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(provider.Opens).IsEqualTo(1);
        await InfisicalMemberPermissionEffectTests.Clean(provider);
    }
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from operation in MemberPermissionContract.Operations.Take(6)
        from boundary in MemberPermissionContract.Boundaries
        from action in MemberPermissionContract.Supported(MemberPermissionScope.Project)
        select (operation, boundary, (int)action);
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task OriginalGenericFactoryRequiresConfiguredMemberAction(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalMemberPermissionFixture();
        using var env = provider.Environment(operation, (MemberPermissionAction)action);
        var d = new NativeCaseDefinition(new("Infisical", InfisicalMemberPermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalMemberPermissionGateTests.Execute].Member);
        var selected = ManagementClientEffects.Resolve(d, env);
        // Do not dispatch a different factory variant as a workaround.
        await Assert.That(selected?.Key.Variant).IsEqualTo(MemberPermissionContract.Variant((MemberPermissionAction)action));
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, env, [d],
            new GovernanceObservers { MemberPermissions = provider.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(result.Variant).IsEqualTo(d.Key.Variant);
        await Assert.That(provider.Opens).IsEqualTo(1);
        await InfisicalMemberPermissionEffectTests.Clean(provider);
    }

    public static IEnumerable<(string Operation, string Fault, bool Generic)> Failures() =>
        from operation in MemberPermissionContract.Operations
        from fault in new[] { "ignored-policy", "wrong-member", "actor-kind", "forged-journal", "lost-open" }
        from generic in MemberPermissionContract.Operations.Take(6).Contains(operation) ? new[] { false, true } : new[] { false }
        select (operation, fault, generic);

    [Test]
    [MethodDataSource(nameof(Failures))]
    public async Task OriginalRoutesRejectBrokenPolicyMemberOrSourceEvidence(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalMemberPermissionFixture(fault);
        using var env = provider.Environment(operation, MemberPermissionAction.Read);
        var d = generic ? new NativeCaseDefinition(new("Infisical", InfisicalMemberPermissionGateTests.Execute,
            "factory." + operation, "local", "independent-effect"),
            InfisicalGovernanceFamilies.Bindings[InfisicalMemberPermissionGateTests.Execute].Member) :
            InfisicalMemberPermissionGateTests.Definition(operation, "permission.Member.read", "independent-effect");
        var registry = new NativeCaseRegistry();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [d],
                new GovernanceObservers { MemberPermissions = provider.Source.CreateClient() });
        else if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [d], memberPermissions: provider.Source.CreateClient());
        else
            InfisicalProjectFamilies.Register(registry, env, [d], memberPermissions: provider.Source.CreateClient());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var result = (await NativeCaseRunner.RunAsync(registry, [d], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Closes).IsEqualTo(1);
        await Assert.That(provider.Registrations).IsEqualTo(0);
        await InfisicalMemberPermissionEffectTests.Clean(provider);
    }
}
