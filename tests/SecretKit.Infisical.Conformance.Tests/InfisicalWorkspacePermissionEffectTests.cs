using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalWorkspacePermissionEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalWorkspacePermissionGateTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task AllFourteenPairsHaveFiveIndependentEffectBoundaries(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture();
        var result = await RunAsync(provider, operation, variant, boundary);
        bool supported = WorkspacePermissionContract.Gate(WorkspacePermissionContract.Scope(operation), InfisicalWorkspacePermissionGateTests.Action(variant)) is null;
        await Assert.That(result.Passed).IsEqualTo(supported).Because(result.ReasonCode); await Assert.That(provider.Opens).IsEqualTo(supported ? 1 : 0);
        await Assert.That(provider.Originals).IsEqualTo(!supported || boundary == "cancellation-boundary" ? 0 : 1); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalWorkspacePermissionOriginalTests.GenericCases();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task ConfiguredActionEffectsRetainGenericFactoryLabel(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture();
        var result = await RunAsync(provider, operation, WorkspacePermissionContract.Variant((WorkspacePermissionAction)action), boundary, true);
        bool supported = WorkspacePermissionContract.Gate(WorkspacePermissionContract.Scope(operation), (WorkspacePermissionAction)action) is null;
        await Assert.That(result.Passed).IsEqualTo(supported).Because(result.ReasonCode); await Assert.That(result.Variant).IsEqualTo("factory." + operation);
        await Assert.That(provider.Opens).IsEqualTo(supported ? 1 : 0); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, bool Generic)> Faults() =>
        from operation in WorkspacePermissionContract.Operations
        from fault in new[] { "ignored-policy", "wrong-policy-target", "wrong-condition", "incomplete-policy", "self-policy-overwrite", "wrong-role-binding", "scope-leak", "wrong-target-project", "wrong-actor", "wrong-credential",
            "actor-kind", "credential-wrong-actor", "membership-wrong-member", "assignment-echo", "forged-journal", "forged-owner", "forged-ingress", "forged-policy", "forged-storage",
            "forged-membership", "forged-access", "forged-seal", "missing-seal", "missing-journal", "nonterminal", "pending-issuer", "missing-inventory",
            "binding-substitution", "binding-duplicate", "binding-work", "binding-input", "binding-scope", "binding-borrowed", "binding-missing", "intent-mutation",
            "lost-open", "partial-open", "collision", "cleanup", "borrowed-change" }
        where fault != "assignment-echo" || operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal) || operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal)
        where fault != "missing-inventory" || WorkspacePermissionContract.Scope(operation) == WorkspacePermissionScope.Project
        from generic in new[] { false, true }
        select (operation, fault, generic);
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task ForgedOrIncompleteEvidenceCannotCertifyEffectsOrCleanup(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(fault);
        var result = await RunAsync(provider, operation, WorkspacePermissionContract.Variant(WorkspacePermissionContract.Supported(WorkspacePermissionContract.Scope(operation))[0]), "independent-effect", generic);
        await Assert.That(result.Passed).IsFalse(); await Assert.That(provider.Closes).IsEqualTo(1);
        if (fault is "cleanup" or "borrowed-change") await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete"); else await Clean(provider);
    }
    public static IEnumerable<(string Operation, int Action, string Fault, bool Generic)> Configurations() =>
        from operation in WorkspacePermissionContract.Operations
        from action in WorkspacePermissionContract.Actions(WorkspacePermissionContract.Scope(operation)).Where(a => a != WorkspacePermissionAction.Delete).Select(a => (int)a)
        from fault in new[] { "wrong-description", "wrong-settings", "wrong-slug", "omitted-settings", "wrong-defaults" }
        from generic in new[] { false, true }
        select (operation, action, fault, generic);
    [Test]
    [MethodDataSource(nameof(Configurations))]
    public async Task FullPersistedRoleCannotBeReplacedByMetadataEcho(string operation, int action, string fault, bool generic)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(fault);
        var result = await RunAsync(provider, operation, WorkspacePermissionContract.Variant((WorkspacePermissionAction)action), "independent-effect", generic);
        await Assert.That(result.Passed).IsFalse(); await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, int Outcome)> Lost() =>
        WorkspacePermissionContract.Operations.SelectMany(op => new[] { (op, "lost-nonapplied", 0), (op, "partial", 2) });
    [Test]
    [MethodDataSource(nameof(Lost))]
    public async Task LostPolicyReceiptRemainsImmutableAndCausal(string operation, string fault, int outcome)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(fault); using var env = provider.Environment(operation, WorkspacePermissionContract.Supported(WorkspacePermissionContract.Scope(operation))[0]);
        var root = provider.Root(operation, WorkspacePermissionContract.Supported(WorkspacePermissionContract.Scope(operation))[0], "lost-response-no-replay");
        using var cap = SecretMaterial.FromText("workspace-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        WorkspacePermissionTrial? retained = null;
        try
        {
            var trial = await WorkspacePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
            await WorkspacePermissionEffects.WitnessAsync(env, root, trial, false, deadline.Token); await trial.ArmAsync(deadline.Token);
            var receipt = await WorkspacePermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token);
            await trial.SettleAsync(receipt, deadline.Token);
            await Assert.That((int)trial.Outcome).IsEqualTo(outcome); await Assert.That(ReferenceEquals(receipt, trial.Original)).IsTrue();
            await Assert.That(receipt.Native.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            if (outcome == 0) await WorkspacePermissionEffects.WitnessAsync(env, root, trial, true, deadline.Token);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(provider.Originals).IsEqualTo(1); await Clean(provider);
    }
    internal static async Task<NativeCaseResult> RunAsync(InfisicalWorkspacePermissionFixture provider, string operation, string variant, string boundary, bool generic = false)
    {
        using var env = provider.Environment(operation, InfisicalWorkspacePermissionGateTests.Action(variant));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var selected = InfisicalWorkspacePermissionGateTests.Definition(operation, variant, boundary);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalWorkspacePermissionGateTests.Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[InfisicalWorkspacePermissionGateTests.Execute].Member) : selected;
        var registry = new NativeCaseRegistry(); registry.Add(new(definition, async (probe, token) =>
        {
            probe.Contract(WorkspacePermissionContract.Owns(selected), NativeFailure.ContractMismatch);
            var context = new ProjectFamilyContext(env, WorkspacePermissionContract.Family(operation), selected, probe);
            try { await WorkspacePermissionEffects.ExecuteAsync(context, provider.Source.CreateClient(), token); }
            finally { await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }
    internal static async Task Clean(InfisicalWorkspacePermissionFixture provider)
    {
        await provider.DrainAsync(); await Assert.That(provider.Remaining).IsEqualTo(0); await Assert.That(provider.Registrations).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue(); await Assert.That(provider.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }
}
