using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalIntegrationPermissionEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalIntegrationPermissionGateTests.Cases();
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalIntegrationPermissionGateTests.GenericCases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task ReadWorksThroughActualTypedSeamAndMutationRowsRemainGated(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalIntegrationPermissionFixture();
        var result = await RunAsync(provider, operation, variant, boundary);
        bool read = InfisicalIntegrationPermissionGateTests.Action(variant) == IntegrationPermissionAction.Read;
        await Assert.That(result.Passed).IsEqualTo(read).Because(result.ReasonCode + ";" + provider.Progress);
        await Assert.That(provider.Opens).IsEqualTo(read ? 1 : 0);
        await Assert.That(provider.Originals).IsEqualTo(read && boundary != "cancellation-boundary" ? 1 : 0);
        await Clean(provider);
    }
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task ConfiguredReadRetainsEveryOriginalGenericFactoryLabel(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalIntegrationPermissionFixture();
        var result = await RunAsync(provider, operation, IntegrationPermissionContract.Variant((IntegrationPermissionAction)action), boundary, true);
        await Assert.That(result.Passed).IsEqualTo(action == 0).Because(result.ReasonCode + ";" + provider.Progress);
        await Assert.That(result.Variant).IsEqualTo("factory." + operation); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, bool Generic)> Faults() =>
        from operation in IntegrationPermissionContract.Operations
        from fault in new[] { "ignored-policy", "wrong-subject", "wrong-actor", "wrong-scope", "wrong-configuration", "scope-leak", "actor-leak",
            "wrong-credential", "metadata-storage", "missing-row", "duplicate-row", "reordered-row", "foreign-row", "optional-field", "incomplete",
            "missing-journal", "lost-open", "partial-open", "collision", "cleanup", "borrowed-change" }
        from generic in new[] { false, true }
        select (operation, fault, generic);
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task IndependentEffectsAndCleanupRejectActualAdversarialFailures(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalIntegrationPermissionFixture(fault);
        var result = await RunAsync(provider, operation, "permission.Integrations.read", "independent-effect", generic);
        await Assert.That(result.Passed).IsFalse().Because(fault + ";" + provider.Progress);
        await Assert.That(provider.Closes).IsEqualTo(1);
        if (fault is "cleanup" or "borrowed-change") await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        else await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault)> Copies() =>
        from op in IntegrationPermissionContract.Operations.Where(IntegrationPermissionContract.Template)
        from fault in new[] { "copy-policy", "copy-configuration", "copy-environment" }
        select (op, fault);
    [Test]
    [MethodDataSource(nameof(Copies))]
    public async Task TemplateCopyNeedsActualConfigurationAndCanonicalNativeBindings(string operation, string fault)
    {
        await using var provider = new InfisicalIntegrationPermissionFixture(fault);
        var result = await RunAsync(provider, operation, "permission.Integrations.read", "independent-effect");
        await Assert.That(result.Passed).IsFalse(); await Clean(provider);
    }
    [Test]
    public async Task RoleCreationNeedsActualMembershipAssignmentNotResponseEcho()
    {
        string operation = IntegrationPermissionContract.Operations.Single(o => o.EndsWith(".CreateProjectRole", StringComparison.Ordinal));
        await using var provider = new InfisicalIntegrationPermissionFixture("assignment-echo");
        var result = await RunAsync(provider, operation, "permission.Integrations.read", "independent-effect");
        await Assert.That(result.Passed).IsFalse(); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, int Outcome)> Lost() =>
        from op in IntegrationPermissionContract.Operations
        from row in new[] { ("lost-nonapplied", 0), ("partial", 2) }
        select (op, row.Item1, row.Item2);
    [Test]
    [MethodDataSource(nameof(Lost))]
    public async Task LostOriginalReconcilesWithoutRewritingReceiptOrReplaying(string operation, string fault, int outcome)
    {
        await using var provider = new InfisicalIntegrationPermissionFixture(fault); using var env = provider.Environment(operation, IntegrationPermissionAction.Read);
        var root = provider.Root(operation, IntegrationPermissionAction.Read, "lost-response-no-replay");
        using var cap = SecretMaterial.FromText("integration-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        IntegrationPermissionTrial? retained = null;
        try
        {
            var trial = await IntegrationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
            await IntegrationPermissionEffects.WitnessAsync(env, trial, false, deadline.Token); await trial.ArmAsync(deadline.Token);
            var receipt = await IntegrationPermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token);
            await trial.SettleAsync(receipt, deadline.Token);
            await Assert.That((int)trial.Outcome).IsEqualTo(outcome);
            await Assert.That(ReferenceEquals(receipt, trial.Original)).IsTrue();
            await Assert.That(receipt.Native.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            if (outcome == 0) await IntegrationPermissionEffects.WitnessAsync(env, trial, true, deadline.Token);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(provider.Originals).IsEqualTo(1); await Clean(provider);
    }
    internal static async Task<NativeCaseResult> RunAsync(InfisicalIntegrationPermissionFixture provider, string operation,
        string variant, string boundary, bool generic = false, bool configured = true)
    {
        using var env = provider.Environment(operation, InfisicalIntegrationPermissionGateTests.Action(variant), configured);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var selected = InfisicalIntegrationPermissionGateTests.Definition(operation, variant, boundary);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalIntegrationPermissionGateTests.Execute,
            "factory." + operation, "local", boundary), InfisicalGovernanceFamilies.Bindings[InfisicalIntegrationPermissionGateTests.Execute].Member) : selected;
        var registry = new NativeCaseRegistry(); registry.Add(new(definition, async (probe, token) =>
        {
            probe.Contract(IntegrationPermissionContract.Owns(selected), NativeFailure.ContractMismatch);
            var context = new ProjectFamilyContext(env, IntegrationPermissionContract.Family(operation), selected, probe);
            try { await IntegrationPermissionEffects.ExecuteAsync(context, provider.Source.CreateClient(), token); }
            finally { await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }
    internal static async Task Clean(InfisicalIntegrationPermissionFixture provider)
    {
        await provider.DrainAsync();
        await Assert.That(provider.Remaining).IsEqualTo(0); await Assert.That(provider.Registrations).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }
}
