using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalAuditPermissionEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        InfisicalAuditPermissionGateTests.Cases().Where(c => c.Variant == "permission.AuditLogs.read");
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() =>
        InfisicalAuditPermissionOriginalTests.GenericCases().Where(c => c.Action == (int)AuditPermissionAction.Read);

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task EightReadPairsHaveFiveIndependentEffectBoundaries(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalAuditPermissionFixture();
        var result = await RunAsync(provider, operation, variant, boundary);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(provider.Opens).IsEqualTo(1);
        await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await Assert.That(provider.HistoricalRows > 0).IsTrue();
        await Clean(provider);
    }

    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task ConfiguredReadEffectsRetainGenericFactoryLabel(string operation, string boundary, int action)
    {
        await using var provider = new InfisicalAuditPermissionFixture();
        var result = await RunAsync(provider, operation, AuditPermissionContract.Variant((AuditPermissionAction)action), boundary, true);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(result.Variant).IsEqualTo("factory." + operation);
        await Clean(provider);
    }

    public static IEnumerable<(string Operation, string Fault)> Faults() =>
        from operation in AuditPermissionContract.Operations
        from fault in new[]
        {
            "ignored-policy", "incomplete-policy", "wrong-policy-target", "wrong-condition", "wrong-role-binding",
            "scope-leak", "actor-leak", "wrong-actor", "wrong-credential", "actor-kind", "credential-wrong-actor", "membership-wrong-member",
            "forged-journal", "forged-owner", "forged-ingress", "forged-policy", "forged-storage", "forged-membership", "forged-access", "forged-publisher",
            "forged-seal", "missing-seal", "nonterminal", "pending-issuer", "binding-substitution", "binding-duplicate",
            "binding-work", "binding-input", "binding-scope", "binding-borrowed", "binding-missing", "intent-mutation",
            "causal-gap", "omitted-row", "duplicate-row", "fabricated-row", "wrong-parent", "wrong-input", "wrong-event-actor",
            "wrong-event-kind", "wrong-event-credential", "wrong-event-type", "wrong-event-class", "late-event", "duplicate-event",
            "canonical-parent", "canonical-binding", "unsealed-publication", "pending-publication",
            "producer-censorship", "wrong-read-path", "wrong-event-scope", "missing-journal",
            "omitted-page", "duplicate-page", "fabricated-page", "partial-invalid-page", "late-page", "overfull-page",
            "lost-reserve", "lost-open", "partial-open", "collision", "cleanup", "borrowed-change", "borrowed-history", "history-rewrite"
        }
        select (operation, fault);

    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task IncompleteOrSubstitutedEvidenceCannotCertifyPermission(string operation, string fault)
    {
        await using var provider = new InfisicalAuditPermissionFixture(fault);
        var result = await RunAsync(provider, operation, "permission.AuditLogs.read", "independent-effect");
        await Assert.That(result.Passed).IsFalse().Because(fault);
        await Assert.That(provider.Closes).IsEqualTo(1);
        if (fault is "cleanup" or "borrowed-change" or "borrowed-history" or "history-rewrite")
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        else await Clean(provider);
    }

    public static IEnumerable<(string Operation, string Fault)> Templates() =>
        from operation in AuditPermissionContract.Operations.Where(AuditPermissionContract.Template)
        from fault in new[] { "template-echo", "template-configuration" }
        select (operation, fault);
    [Test]
    [MethodDataSource(nameof(Templates))]
    public async Task TemplateCopyNeedsPersistedPolicyAndIndependentConfiguration(string operation, string fault)
    {
        await using var provider = new InfisicalAuditPermissionFixture(fault);
        var result = await RunAsync(provider, operation, "permission.AuditLogs.read", "independent-effect", true);
        await Assert.That(result.Passed).IsFalse();
        await Clean(provider);
    }

    public static IEnumerable<(string Operation, string Fault, int Outcome)> Lost() =>
        AuditPermissionContract.Operations.SelectMany(op => new[] { (op, "lost-nonapplied", 0), (op, "partial", 2) });
    [Test]
    [MethodDataSource(nameof(Lost))]
    public async Task LostOriginalReceiptRemainsImmutableWithoutReplay(string operation, string fault, int outcome)
    {
        await using var provider = new InfisicalAuditPermissionFixture(fault);
        using var environment = provider.Environment(operation, AuditPermissionAction.Read);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        using var capability = SecretMaterial.FromText("audit-capability");
        var root = provider.Root(operation, AuditPermissionAction.Read, "lost-response-no-replay");
        AuditPermissionTrial? retained = null;
        try
        {
            var trial = await AuditPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token);
            await AuditPermissionEffects.WitnessAsync(environment, root, trial, false, deadline.Token);
            await trial.ArmAsync(deadline.Token);
            var receipt = await AuditPermissionEffects.DispatchAsync(environment, root, trial.Plan, trial.Issued, deadline.Token);
            await trial.SettleAsync(receipt, deadline.Token);
            await Assert.That((int)trial.Outcome).IsEqualTo(outcome);
            await Assert.That(ReferenceEquals(receipt, trial.Original)).IsTrue();
            await Assert.That(receipt.Native.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            if (outcome == 0) await AuditPermissionEffects.WitnessAsync(environment, root, trial, true, deadline.Token);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(provider.Originals).IsEqualTo(1);
        await Clean(provider);
    }

    internal static async Task<NativeCaseResult> RunAsync(InfisicalAuditPermissionFixture provider, string operation,
        string variant, string boundary, bool generic = false)
    {
        using var environment = provider.Environment(operation, InfisicalAuditPermissionGateTests.Action(variant));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var selected = InfisicalAuditPermissionGateTests.Definition(operation, variant, boundary);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", InfisicalAuditPermissionGateTests.Execute,
            "factory." + operation, "local", boundary), InfisicalGovernanceFamilies.Bindings[InfisicalAuditPermissionGateTests.Execute].Member) : selected;
        var registry = new NativeCaseRegistry();
        registry.Add(new(definition, async (probe, token) =>
        {
            probe.Contract(AuditPermissionContract.Owns(selected), NativeFailure.ContractMismatch);
            var context = new ProjectFamilyContext(environment, AuditPermissionContract.Family(operation), selected, probe);
            try { await AuditPermissionEffects.ExecuteAsync(context, provider.Source.CreateClient(), token); }
            finally { await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }
    internal static async Task Clean(InfisicalAuditPermissionFixture provider)
    {
        await provider.DrainAsync();
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.PendingPublication).IsEqualTo(0);
        await Assert.That(provider.Registrations).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Copies.All(bytes => bytes.All(b => b == 0))).IsTrue();
    }
}
