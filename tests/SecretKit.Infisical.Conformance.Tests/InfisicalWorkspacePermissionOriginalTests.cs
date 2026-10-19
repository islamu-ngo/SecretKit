using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original routes select the independent Workspace lifecycle source.
public sealed class InfisicalWorkspacePermissionOriginalTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalWorkspacePermissionGateTests.Cases();
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from operation in WorkspacePermissionContract.Operations
        from boundary in WorkspacePermissionContract.Boundaries
        from action in WorkspacePermissionContract.Actions(WorkspacePermissionContract.Scope(operation))
        select (operation, boundary, (int)action);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeWorkspaceRequiresIndependentEffect(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture();
        using var env = provider.Environment(operation, InfisicalWorkspacePermissionGateTests.Action(variant));
        var definition = InfisicalWorkspacePermissionGateTests.Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [definition], workspacePermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], workspacePermissions: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        bool supported = WorkspacePermissionContract.Gate(WorkspacePermissionContract.Scope(operation), InfisicalWorkspacePermissionGateTests.Action(variant)) is null;
        await Assert.That(result.Passed).IsEqualTo(supported).Because(result.ReasonCode);
        await Assert.That(provider.Opens).IsEqualTo(supported ? 1 : 0);
        await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task OriginalGenericRetainsConfiguredScopeLegalAction(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(); using var env = provider.Environment(operation, (WorkspacePermissionAction)action);
        var definition = new NativeCaseDefinition(new("Infisical", InfisicalWorkspacePermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalWorkspacePermissionGateTests.Execute].Member);
        await Assert.That(ManagementClientEffects.Resolve(definition, env)?.Key.Variant).IsEqualTo(WorkspacePermissionContract.Variant((WorkspacePermissionAction)action));
        var registry = new NativeCaseRegistry(); InfisicalGovernanceFamilies.Register(registry, env, [definition],
            new GovernanceObservers { WorkspacePermissions = provider.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        bool supported = WorkspacePermissionContract.Gate(WorkspacePermissionContract.Scope(operation), (WorkspacePermissionAction)action) is null;
        await Assert.That(result.Passed).IsEqualTo(supported).Because(result.ReasonCode);
        await Assert.That(provider.Opens).IsEqualTo(supported ? 1 : 0);
        await Assert.That(result.Variant).IsEqualTo(definition.Key.Variant);
        await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }

    public static IEnumerable<(string Operation, int Action, string Fault, bool Generic)> Failures() =>
        from operation in WorkspacePermissionContract.Operations
        from action in WorkspacePermissionContract.Actions(WorkspacePermissionContract.Scope(operation))
        from fault in action == WorkspacePermissionAction.Delete ?
            new[] { "acknowledged-not-deleted", "omitted-cascade", "wrong-cascade", "lost-tombstone", "recycled-scope", "retained-corruption" } :
            new[] { "ignored-policy", "incomplete-policy", "wrong-settings", "omitted-settings", "lost-open", "partial-open" }
        from generic in new[] { false, true }
        select (operation, (int)action, fault, generic);

    [Test]
    [MethodDataSource(nameof(Failures))]
    public async Task OriginalRoutesRejectUnprovenLifecycleAndRecover(string operation, int action, string fault, bool generic)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(fault);
        using var env = provider.Environment(operation, (WorkspacePermissionAction)action);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalWorkspacePermissionGateTests.Execute,
            "factory." + operation, "local", "independent-effect"),
            InfisicalGovernanceFamilies.Bindings[InfisicalWorkspacePermissionGateTests.Execute].Member) :
            InfisicalWorkspacePermissionGateTests.Definition(operation,
                WorkspacePermissionContract.Variant((WorkspacePermissionAction)action), "independent-effect");
        var registry = new NativeCaseRegistry();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [definition],
                new GovernanceObservers { WorkspacePermissions = provider.Source.CreateClient() });
        else if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [definition], workspacePermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, env, [definition], workspacePermissions: provider.Source.CreateClient());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        bool supported = WorkspacePermissionContract.Gate(WorkspacePermissionContract.Scope(operation), (WorkspacePermissionAction)action) is null;
        await Assert.That(provider.Closes).IsEqualTo(supported ? 1 : 0);
        await Assert.That(provider.Opens).IsEqualTo(supported ? 1 : 0);
        await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }
}
