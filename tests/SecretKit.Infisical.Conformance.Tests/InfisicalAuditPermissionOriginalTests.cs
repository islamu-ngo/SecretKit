using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Original native and generic routes select the independent owned source.
// Read requires causal publication proof; edit remains a discovered gate.
public sealed class InfisicalAuditPermissionOriginalTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalAuditPermissionGateTests.Cases();
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        from operation in AuditPermissionContract.Operations
        from boundary in AuditPermissionContract.Boundaries
        from action in Enum.GetValues<AuditPermissionAction>()
        select (operation, boundary, (int)action);

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalNativeAuditPermissionRequiresIndependentEffect(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalAuditPermissionFixture();
        using var environment = provider.Environment(operation, InfisicalAuditPermissionGateTests.Action(variant));
        var definition = InfisicalAuditPermissionGateTests.Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, environment, [definition], auditPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, environment, [definition], auditPermissions: provider.Source.CreateClient());
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        if (variant == "permission.AuditLogs.edit")
        {
            await Assert.That(result.Passed).IsFalse();
            await Assert.That(provider.Opens).IsEqualTo(0);
            return;
        }
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(provider.Opens).IsEqualTo(1);
        await InfisicalAuditPermissionEffectTests.Clean(provider);
    }

    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task OriginalGenericRetainsFactoryLabelAndConfiguredAuditAction(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalAuditPermissionFixture();
        using var environment = provider.Environment(operation, (AuditPermissionAction)action);
        var definition = new NativeCaseDefinition(new("Infisical", InfisicalAuditPermissionGateTests.Execute,
            "factory." + operation, "local", boundary), InfisicalGovernanceFamilies.Bindings[InfisicalAuditPermissionGateTests.Execute].Member);
        var selected = ManagementClientEffects.Resolve(definition, environment);
        await Assert.That(selected?.Key.Variant).IsEqualTo(AuditPermissionContract.Variant((AuditPermissionAction)action));
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, environment, [definition],
            new GovernanceObservers { AuditPermissions = provider.Source.CreateClient() });
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Variant).IsEqualTo("factory." + operation);
        await Assert.That(result.Passed).IsEqualTo((AuditPermissionAction)action == AuditPermissionAction.Read).Because(result.ReasonCode);
        if ((AuditPermissionAction)action == AuditPermissionAction.Edit)
        {
            await Assert.That(provider.Opens).IsEqualTo(0);
            await Assert.That(provider.Originals).IsEqualTo(0);
        }
        await InfisicalAuditPermissionEffectTests.Clean(provider);
    }

    public static IEnumerable<(string Operation, string Fault, bool Generic)> Failures() =>
        from operation in AuditPermissionContract.Operations
        from fault in new[] { "ignored-policy", "incomplete-policy", "causal-gap", "wrong-parent", "omitted-row",
            "partial-invalid-page", "unsealed-publication", "forged-publisher", "lost-open", "partial-open" }
        from generic in new[] { false, true }
        select (operation, fault, generic);

    [Test]
    [MethodDataSource(nameof(Failures))]
    public async Task OriginalRoutesRejectUnprovenPublicationAndRecover(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalAuditPermissionFixture(fault);
        using var environment = provider.Environment(operation, AuditPermissionAction.Read);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalAuditPermissionGateTests.Execute,
            "factory." + operation, "local", "independent-effect"),
            InfisicalGovernanceFamilies.Bindings[InfisicalAuditPermissionGateTests.Execute].Member) :
            InfisicalAuditPermissionGateTests.Definition(operation, "permission.AuditLogs.read", "independent-effect");
        var registry = new NativeCaseRegistry();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, environment, [definition],
                new GovernanceObservers { AuditPermissions = provider.Source.CreateClient() });
        else if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, environment, [definition], auditPermissions: provider.Source.CreateClient());
        else InfisicalProjectFamilies.Register(registry, environment, [definition], auditPermissions: provider.Source.CreateClient());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Closes).IsEqualTo(1);
        await InfisicalAuditPermissionEffectTests.Clean(provider);
    }
}
