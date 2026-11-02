using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalProxyPermissionEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalProxyPermissionGateTests.SupportedCases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task AllTwentyFourPairsHaveFiveIndependentEffectBoundaries(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalProxyPermissionFixture();
        var result = await RunAsync(provider, operation, variant, boundary);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Assert.That(provider.Opens).IsEqualTo(1);
        await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalProxyPermissionOriginalTests.SupportedGenericCases();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task ConfiguredActionEffectsRetainGenericFactoryLabel(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalProxyPermissionFixture();
        var result = await RunAsync(provider, operation, ProxyPermissionContract.Variant((ProxyPermissionAction)action), boundary, true);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Assert.That(result.Variant).IsEqualTo("factory." + operation); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, bool Generic)> Faults() =>
        from operation in ProxyPermissionContract.Operations
        from fault in new[] { "ignored-policy", "wrong-policy-target", "wrong-condition", "incomplete-policy", "wrong-configuration", "wrong-project", "wrong-organization", "self-policy-overwrite", "wrong-role-binding", "action-leak", "scope-leak", "wrong-service", "wrong-actor", "wrong-credential",
            "actor-kind", "credential-wrong-actor", "membership-wrong-member", "assignment-echo", "forged-journal", "forged-owner", "forged-ingress", "forged-policy", "forged-storage",
            "forged-membership", "forged-access", "forged-seal", "missing-seal", "missing-journal", "nonterminal", "pending-issuer", "missing-inventory",
            "binding-request", "binding-commit", "dispatch-history-missing", "binding-substitution", "binding-duplicate", "binding-work", "binding-input", "input-configuration", "binding-scope", "binding-borrowed", "binding-missing", "intent-mutation", "forged-collection", "allocation-missing", "allocation-duplicate", "allocation-reordered", "allocation-substituted", "allocation-parent", "allocation-borrowed", "allocation-actor-credential", "history-root", "history-request", "history-commit", "history-protected-input", "history-missing", "history-duplicate", "history-reordered", "collection-inventory-missing",
            "lost-open", "partial-open", "collision", "cleanup", "borrowed-change" }
        where fault != "assignment-echo" || operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal) || operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal)
        from generic in new[] { false, true }
        select (operation, fault, generic);
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task ForgedOrIncompleteEvidenceCannotCertifyEffectsOrCleanup(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalProxyPermissionFixture(fault);
        var result = await RunAsync(provider, operation, "permission.ProxiedServices.read", "independent-effect", generic);
        await Assert.That(result.Passed).IsFalse(); await Assert.That(provider.Closes).IsEqualTo(1);
        if (fault is "cleanup" or "borrowed-change") await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete"); else await Clean(provider);
    }
    public static IEnumerable<(string Operation, int Action, string Fault, bool Generic)> Configurations() =>
        from operation in ProxyPermissionContract.Operations
        from action in new[] { 1, 2 }
        from fault in new[] { "wrong-destination", "wrong-environment", "wrong-path", "wrong-enabled", "wrong-protected-configuration", "false-persistence", "false-readback", "false-inventory" }
        from generic in new[] { false, true }
        select (operation, action, fault, generic);
    [Test]
    [MethodDataSource(nameof(Configurations))]
    public async Task FullPersistedServiceCannotBeReplacedByMetadataEcho(string operation, int action, string fault, bool generic)
    {
        await using var provider = new InfisicalProxyPermissionFixture(fault);
        var result = await RunAsync(provider, operation, ProxyPermissionContract.Variant((ProxyPermissionAction)action), "independent-effect", generic);
        await Assert.That(result.Passed).IsFalse(); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, int Outcome)> Lost() =>
        ProxyPermissionContract.Operations.SelectMany(op => new[] { (op, "lost-nonapplied", 0), (op, "partial", 2) });
    [Test]
    [MethodDataSource(nameof(Lost))]
    public async Task LostPolicyReceiptRemainsImmutableAndCausal(string operation, string fault, int outcome)
    {
        await using var provider = new InfisicalProxyPermissionFixture(fault); using var env = provider.Environment(operation, ProxyPermissionAction.Read);
        var root = provider.Root(operation, ProxyPermissionAction.Read, "lost-response-no-replay");
        using var cap = SecretMaterial.FromText("proxy-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        ProxyPermissionTrial? retained = null;
        try
        {
            var trial = await ProxyPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
            await ProxyPermissionEffects.WitnessAsync(env, root, trial, false, deadline.Token); await trial.ArmAsync(deadline.Token);
            var receipt = await ProxyPermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token);
            await trial.SettleAsync(receipt, deadline.Token);
            await Assert.That((int)trial.Outcome).IsEqualTo(outcome); await Assert.That(ReferenceEquals(receipt, trial.Original)).IsTrue();
            await Assert.That(receipt.Native.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            if (outcome == 0) await ProxyPermissionEffects.WitnessAsync(env, root, trial, true, deadline.Token);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(provider.Originals).IsEqualTo(1); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault)> TemplateCopies() =>
        from operation in ProxyPermissionContract.Operations.Where(ProxyPermissionContract.Template)
        from fault in new[] { "template-echo", "template-configuration-echo", "template-proxy-echo" }
        select (operation, fault);
    [Test]
    [MethodDataSource(nameof(TemplateCopies))]
    public async Task SelectedTemplateConfigurationMustCopyIntoIndependentStorage(string operation, string fault)
    {
        await using var provider = new InfisicalProxyPermissionFixture(fault);
        var result = await RunAsync(provider, operation, "permission.ProxiedServices.read", "independent-effect");
        await Assert.That(result.Passed).IsFalse(); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, bool Retain)> Retirements() =>
        from operation in ProxyPermissionContract.Operations
        from fault in new[] { "retirement-missing", "retirement-duplicate", "retirement-reordered", "retirement-substituted", "deleted-inventory-missing", "orphaned-replaced-collection" }
        from retain in new[] { false, true }
        select (operation, fault, retain);
    [Test]
    [MethodDataSource(nameof(Retirements))]
    public async Task EverySupersededRevisionRequiresCompleteIndependentRetirement(string operation, string fault, bool retain)
    {
        await using var provider = new InfisicalProxyPermissionFixture(fault, retain);
        var result = await RunAsync(provider, operation, "permission.ProxiedServices.edit", "independent-effect");
        await Assert.That(result.Passed).IsFalse(); await Assert.That(provider.Closes).IsEqualTo(1);
        await Clean(provider);
    }
    public static IEnumerable<(string Operation, int Action)> RetainedIds() =>
        from operation in ProxyPermissionContract.Operations from action in Enumerable.Range(0, 4) select (operation, action);
    [Test]
    [MethodDataSource(nameof(RetainedIds))]
    public async Task RetainedCredentialIdsAreObservedWithoutInventedReallocation(string operation, int action)
    {
        await using var provider = new InfisicalProxyPermissionFixture(retainIds: true);
        var result = await RunAsync(provider, operation, ProxyPermissionContract.Variant((ProxyPermissionAction)action), "independent-effect");
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode); await Clean(provider);
    }
    internal static async Task<NativeCaseResult> RunAsync(InfisicalProxyPermissionFixture provider, string operation, string variant, string boundary, bool generic = false)
    {
        using var env = provider.Environment(operation, InfisicalProxyPermissionGateTests.Action(variant));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var selected = InfisicalProxyPermissionGateTests.Definition(operation, variant, boundary);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalProxyPermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalProxyPermissionGateTests.Execute].Member) : selected;
        if (generic) selected = ProxyPermissionContract.Resolve(definition, env) ?? throw new NativeCaseFailureException("observer-unavailable");
        var registry = new NativeCaseRegistry(); registry.Add(new(definition, async (probe, token) =>
        {
            probe.Contract(ProxyPermissionContract.Owns(selected), NativeFailure.ContractMismatch);
            var context = new ProjectFamilyContext(env, ProxyPermissionContract.Family(operation), selected, probe);
            try { await ProxyPermissionEffects.ExecuteAsync(context, provider.Source.CreateClient(), token); }
            finally { await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }
    internal static async Task Clean(InfisicalProxyPermissionFixture provider)
    {
        await provider.DrainAsync(); await Assert.That(provider.Remaining).IsEqualTo(0); await Assert.That(provider.Registrations).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue(); await Assert.That(provider.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }
}
