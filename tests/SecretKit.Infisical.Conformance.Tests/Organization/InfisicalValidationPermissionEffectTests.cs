using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalValidationPermissionEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalValidationPermissionGateTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task AllTwentyFourPairsHaveFiveIndependentEffectBoundaries(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalValidationPermissionFixture();
        var result = await RunAsync(provider, operation, variant, boundary);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode + ";" + provider.Progress); await Assert.That(provider.Opens).IsEqualTo(1);
        await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalValidationPermissionOriginalTests.GenericCases();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task ConfiguredActionEffectsRetainGenericFactoryLabel(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalValidationPermissionFixture();
        var result = await RunAsync(provider, operation, ValidationPermissionContract.Variant((ValidationPermissionAction)action), boundary, true);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode + ";" + provider.Progress); await Assert.That(result.Variant).IsEqualTo("factory." + operation); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, bool Generic)> Faults() =>
        from operation in ValidationPermissionContract.Operations
        from fault in new[] { "ignored-policy", "wrong-policy-target", "wrong-condition", "incomplete-policy", "wrong-configuration", "wrong-project", "wrong-organization", "stale-rule-scope", "self-policy-overwrite", "wrong-role-binding", "action-leak", "scope-leak", "wrong-rule", "wrong-actor", "wrong-credential",
            "actor-kind", "credential-wrong-actor", "membership-wrong-member", "assignment-echo", "forged-journal", "forged-owner", "forged-ingress", "forged-policy", "forged-storage",
            "forged-membership", "forged-access", "forged-seal", "missing-seal", "missing-journal", "nonterminal", "pending-issuer", "missing-inventory",
            "binding-substitution", "binding-duplicate", "binding-work", "binding-input", "input-constraint", "binding-scope", "binding-borrowed", "binding-missing", "intent-mutation",
            "lost-open", "partial-open", "collision", "cleanup", "borrowed-change", "rule-revision", "rule-configuration", "protected-input", "fake-enforcement-success", "violating-accepted", "allowed-rejected",
            "authorized-uncommitted", "unauthorized-commit", "enforcement-actor", "enforcement-credential", "enforcement-authority", "omitted-enforcement", "duplicate-enforcement",
            "omitted-backend", "duplicate-backend", "missing-secret-inventory", "forged-enforcement", "forged-backend", "borrowed-backend-change" }
        where fault != "assignment-echo" || operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal) || operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal)
        from generic in new[] { false, true }
        select (operation, fault, generic);
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task ForgedOrIncompleteEvidenceCannotCertifyEffectsOrCleanup(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalValidationPermissionFixture(fault);
        var result = await RunAsync(provider, operation, "permission.SecretValidationRules.read", "independent-effect", generic);
        await Assert.That(result.Passed).IsFalse(); await Assert.That(provider.Closes).IsEqualTo(1).Because(result.ReasonCode + ";" + provider.Progress);
        if (fault is "cleanup" or "borrowed-change" or "borrowed-backend-change") await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete"); else await Clean(provider);
    }
    public static IEnumerable<(string Operation, int Action, string Fault, bool Generic)> Configurations() =>
        from operation in ValidationPermissionContract.Operations
        from action in new[] { 1, 2 }
        from fault in new[] { "wrong-name", "wrong-description", "wrong-path", "wrong-active", "wrong-constraint" }
        from generic in new[] { false, true }
        select (operation, action, fault, generic);
    [Test]
    [MethodDataSource(nameof(Configurations))]
    public async Task FullPersistedRuleCannotBeReplacedByMetadataEcho(string operation, int action, string fault, bool generic)
    {
        await using var provider = new InfisicalValidationPermissionFixture(fault);
        var result = await RunAsync(provider, operation, ValidationPermissionContract.Variant((ValidationPermissionAction)action), "independent-effect", generic);
        await Assert.That(result.Passed).IsFalse(); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, int Outcome)> Lost() =>
        ValidationPermissionContract.Operations.SelectMany(op => new[] { (op, "lost-nonapplied", 0), (op, "partial", 2) });
    [Test]
    [MethodDataSource(nameof(Lost))]
    public async Task LostPolicyReceiptRemainsImmutableAndCausal(string operation, string fault, int outcome)
    {
        await using var provider = new InfisicalValidationPermissionFixture(fault); using var env = provider.Environment(operation, ValidationPermissionAction.Read);
        var root = provider.Root(operation, ValidationPermissionAction.Read, "lost-response-no-replay");
        using var cap = SecretMaterial.FromText("validation-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        ValidationPermissionTrial? retained = null;
        try
        {
            var trial = await ValidationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
            await ValidationPermissionEffects.WitnessAsync(env, root, trial, false, deadline.Token); await trial.ArmAsync(deadline.Token);
            var receipt = await ValidationPermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token);
            await trial.SettleAsync(receipt, deadline.Token);
            await Assert.That((int)trial.Outcome).IsEqualTo(outcome); await Assert.That(ReferenceEquals(receipt, trial.Original)).IsTrue();
            await Assert.That(receipt.Native.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            if (outcome == 0) await ValidationPermissionEffects.WitnessAsync(env, root, trial, true, deadline.Token);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(provider.Originals).IsEqualTo(1); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault)> TemplateCopies() =>
        from operation in ValidationPermissionContract.Operations.Where(ValidationPermissionContract.Template)
        from fault in new[] { "template-echo", "template-configuration-echo", "template-environment-echo" }
        select (operation, fault);
    [Test]
    [MethodDataSource(nameof(TemplateCopies))]
    public async Task SelectedTemplateConfigurationMustCopyIntoIndependentStorage(string operation, string fault)
    {
        await using var provider = new InfisicalValidationPermissionFixture(fault);
        var result = await RunAsync(provider, operation, "permission.SecretValidationRules.read", "independent-effect");
        await Assert.That(result.Passed).IsFalse(); await Clean(provider);
    }
    internal static async Task<NativeCaseResult> RunAsync(InfisicalValidationPermissionFixture provider, string operation, string variant, string boundary, bool generic = false)
    {
        using var env = provider.Environment(operation, InfisicalValidationPermissionGateTests.Action(variant));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var selected = InfisicalValidationPermissionGateTests.Definition(operation, variant, boundary);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalValidationPermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalValidationPermissionGateTests.Execute].Member) : selected;
        var registry = new NativeCaseRegistry(); registry.Add(new(definition, async (probe, token) =>
        {
            probe.Contract(ValidationPermissionContract.Owns(selected), NativeFailure.ContractMismatch);
            var context = new ProjectFamilyContext(env, ValidationPermissionContract.Family(operation), selected, probe);
            try { await ValidationPermissionEffects.ExecuteAsync(context, provider.Source.CreateClient(), token); }
            finally { await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }
    internal static async Task Clean(InfisicalValidationPermissionFixture provider)
    {
        await provider.DrainAsync(); await Assert.That(provider.Remaining).IsEqualTo(0); await Assert.That(provider.Registrations).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue(); await Assert.That(provider.Copies.All(b => b.All(v => v == 0)) && provider.BackendBuffers.All(b => b.All(v => v == 0))).IsTrue();
    }
}
