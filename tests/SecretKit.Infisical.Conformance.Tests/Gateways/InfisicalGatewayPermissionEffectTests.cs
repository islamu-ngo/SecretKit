using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalGatewayPermissionEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalGatewayPermissionGateTests.SupportedCases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task FourSupportedPairsHaveFiveIndependentEffectBoundaries(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalGatewayPermissionFixture();
        var result = await RunAsync(provider, operation, variant, boundary);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Assert.That(provider.Opens).IsEqualTo(1);
        await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1); await Clean(provider);
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task ReplacedConfigurationIdsAlsoRequireCompleteRetirement(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalGatewayPermissionFixture(retainConfigId: false);
        var result = await RunAsync(provider, operation, variant, boundary);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalGatewayPermissionOriginalTests.GenericCases();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task ConfiguredActionEffectsRetainGenericFactoryLabel(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalGatewayPermissionFixture();
        var result = await RunAsync(provider, operation, GatewayPermissionContract.Variant((GatewayPermissionAction)action), boundary, true);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Assert.That(result.Variant).IsEqualTo("factory." + operation); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, bool Generic)> Faults() =>
        from operation in GatewayPermissionContract.Operations
        from fault in new[] { "ignored-policy", "wrong-policy-target", "wrong-condition", "incomplete-policy", "self-policy-overwrite", "wrong-role-binding", "action-leak", "scope-leak", "wrong-gateway", "wrong-actor", "wrong-credential",
            "actor-kind", "credential-wrong-actor", "membership-wrong-member", "assignment-echo", "forged-journal", "forged-owner", "forged-ingress", "forged-policy", "forged-storage",
            "forged-membership", "forged-access", "forged-config", "forged-seal", "missing-seal", "missing-journal", "nonterminal", "pending-issuer", "missing-inventory",
            "binding-substitution", "binding-duplicate", "binding-work", "binding-input", "binding-scope", "binding-borrowed", "binding-missing", "intent-mutation",
            "lost-open", "partial-open", "collision", "cleanup", "borrowed-change", "borrowed-config-change", "config-parent", "config-request", "config-id-history", "config-revision", "config-root", "config-inventory", "config-cleanup", "response-config-id", "omitted-auth", "omitted-name", "readback-mismatch", "persistence-echo" }
        where fault != "assignment-echo" || operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal) || operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal)
        from generic in new[] { false, true }
        select (operation, fault, generic);
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task ForgedOrIncompleteEvidenceCannotCertifyEffectsOrCleanup(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalGatewayPermissionFixture(fault);
        var result = await RunAsync(provider, operation, "permission.Gateway.create-gateways", "independent-effect", generic);
        await Assert.That(result.Passed).IsFalse(); await Assert.That(provider.Closes).IsEqualTo(1);
        if (fault is "cleanup" or "borrowed-change" or "borrowed-config-change" or "config-cleanup") await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete"); else await Clean(provider);
    }
    public static IEnumerable<(string Operation, int Action, string Fault, bool Generic)> Configurations() =>
        from operation in GatewayPermissionContract.Operations
        from action in new[] { 1 }
        from fault in new[] { "wrong-auth", "wrong-name", "unaccounted-retirement", "orphan-replaced-config" }
        from generic in new[] { false, true }
        select (operation, action, fault, generic);
    [Test]
    [MethodDataSource(nameof(Configurations))]
    public async Task FullPersistedAwsConfigurationCannotBeReplacedByMetadataEcho(string operation, int action, string fault, bool generic)
    {
        await using var provider = new InfisicalGatewayPermissionFixture(fault, retainConfigId: false);
        var result = await RunAsync(provider, operation, GatewayPermissionContract.Variant((GatewayPermissionAction)action), "independent-effect", generic);
        await Assert.That(result.Passed).IsFalse(); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, int Outcome)> Lost() =>
        GatewayPermissionContract.Operations.SelectMany(op => new[] { (op, "lost-nonapplied", 0), (op, "partial", 2) });
    [Test]
    [MethodDataSource(nameof(Lost))]
    public async Task LostPolicyReceiptRemainsImmutableAndCausal(string operation, string fault, int outcome)
    {
        await using var provider = new InfisicalGatewayPermissionFixture(fault); using var env = provider.Environment(operation, GatewayPermissionAction.Create);
        var root = provider.Root(operation, GatewayPermissionAction.Create, "lost-response-no-replay");
        using var cap = SecretMaterial.FromText("gateway-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        GatewayPermissionTrial? retained = null;
        try
        {
            var trial = await GatewayPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
            await GatewayPermissionEffects.WitnessAsync(env, root, trial, false, deadline.Token); await trial.ArmAsync(deadline.Token);
            var receipt = await GatewayPermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token);
            await trial.SettleAsync(receipt, deadline.Token);
            await Assert.That((int)trial.Outcome).IsEqualTo(outcome); await Assert.That(ReferenceEquals(receipt, trial.Original)).IsTrue();
            await Assert.That(receipt.Native.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            if (outcome == 0) await GatewayPermissionEffects.WitnessAsync(env, root, trial, true, deadline.Token);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(provider.Originals).IsEqualTo(1); await Clean(provider);
    }
    internal static async Task<NativeCaseResult> RunAsync(InfisicalGatewayPermissionFixture provider, string operation, string variant, string boundary, bool generic = false)
    {
        using var env = provider.Environment(operation, InfisicalGatewayPermissionGateTests.Action(variant));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var selected = InfisicalGatewayPermissionGateTests.Definition(operation, variant, boundary);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalGatewayPermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalGatewayPermissionGateTests.Execute].Member) : selected;
        if (generic) selected = GatewayPermissionContract.Resolve(definition, env) ?? throw new NativeCaseFailureException("missing-input");
        var registry = new NativeCaseRegistry(); registry.Add(new(definition, async (probe, token) =>
        {
            probe.Contract(GatewayPermissionContract.Owns(selected), NativeFailure.ContractMismatch);
            var context = new ProjectFamilyContext(env, GatewayPermissionContract.Family(operation), selected, probe);
            try { await GatewayPermissionEffects.ExecuteAsync(context, provider.Source.CreateClient(), token); }
            finally { await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }
    internal static async Task Clean(InfisicalGatewayPermissionFixture provider)
    {
        await provider.DrainAsync(); await Assert.That(provider.Remaining).IsEqualTo(0); await Assert.That(provider.Registrations).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue(); await Assert.That(provider.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }
}
