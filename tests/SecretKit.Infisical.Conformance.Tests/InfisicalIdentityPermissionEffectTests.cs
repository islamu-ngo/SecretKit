using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalIdentityPermissionEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalIdentityPermissionGateTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task ExactTypedIdentityEffectsAndExplicitMissingSeams(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalIdentityPermissionFixture();
        var result = await RunAsync(provider, operation, variant, boundary);
        bool supported = IdentityPermissionContract.Gate(IdentityPermissionContract.Scope(operation), InfisicalIdentityPermissionGateTests.Action(variant)) is null;
        await Assert.That(result.Passed).IsEqualTo(supported).Because(result.ReasonCode);
        await Assert.That(provider.Opens).IsEqualTo(supported ? 1 : 0);
        await Assert.That(provider.Originals).IsEqualTo(supported && boundary != "cancellation-boundary" ? 1 : 0);
        if (supported) await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault)> Faults() =>
        from operation in IdentityPermissionContract.Operations
        from fault in new[] { "ignored-policy", "wrong-policy-target", "action-leak", "scope-leak", "wrong-identity", "wrong-membership", "wrong-actor", "wrong-credential",
            "actor-kind", "credential-wrong-actor", "membership-wrong-membership", "forged-journal", "forged-owner", "forged-ingress", "forged-policy", "forged-storage",
            "forged-membership", "forged-access", "forged-capture", "forged-token-state", "forged-seal", "missing-seal", "missing-journal", "nonterminal", "pending-issuer", "missing-inventory",
            "binding-substitution", "binding-duplicate", "binding-work", "binding-input", "binding-scope", "binding-borrowed", "binding-missing", "intent-mutation",
            "lost-open", "partial-open", "collision", "cleanup", "borrowed-change" }
        select (operation, fault);
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task CounterexamplesCannotCertifyIdentityOrCleanup(string operation, string fault)
    {
        await using var provider = new InfisicalIdentityPermissionFixture(fault);
        var result = await RunAsync(provider, operation, "permission.Identity.read", "independent-effect");
        await Assert.That(result.Passed).IsFalse(); await Assert.That(provider.Closes).IsEqualTo(1);
        if (fault is "cleanup" or "borrowed-change") await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        else await Clean(provider);
    }
    [Test]
    [Arguments("i.management.ProjectTemplateOperations.CreateProjectTemplate", "template-echo")]
    [Arguments("i.management.ProjectTemplateOperations.UpdateProjectTemplate", "template-echo")]
    [Arguments("i.management.RoleChangeOperations.CreateProjectRole", "assignment-echo")]
    [Arguments("i.management.RoleChangeOperations.CreateOrganizationRole", "assignment-echo")]
    public async Task ActorActivationRequiresRealPersistedAssignment(string operation, string fault)
    {
        await using var provider = new InfisicalIdentityPermissionFixture(fault);
        await Assert.That((await RunAsync(provider, operation, "permission.Identity.read", "independent-effect")).Passed).IsFalse();
        await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, int Outcome)> Lost() =>
        IdentityPermissionContract.Operations.SelectMany(op => new[] { (op, "lost-nonapplied", 0), (op, "partial", 2) });
    [Test]
    [MethodDataSource(nameof(Lost))]
    public async Task LostOriginalIsCausalImmutableAndNeverReplayed(string operation, string fault, int outcome)
    {
        await using var provider = new InfisicalIdentityPermissionFixture(fault); using var env = provider.Environment(operation, IdentityPermissionAction.Read);
        var root = provider.Root(operation, IdentityPermissionAction.Read, "lost-response-no-replay");
        using var cap = SecretMaterial.FromText("identity-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        IdentityPermissionTrial? retained = null;
        try
        {
            var trial = await IdentityPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
            await IdentityPermissionEffects.WitnessAsync(env, root, trial, false, deadline.Token); await trial.ArmAsync(deadline.Token);
            var original = await IdentityPermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token);
            await trial.SettleAsync(original, deadline.Token);
            await Assert.That((int)trial.Outcome).IsEqualTo(outcome);
            await Assert.That(ReferenceEquals(original, trial.Original)).IsTrue();
            await Assert.That(original.Native.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            if (outcome == 0) await IdentityPermissionEffects.WitnessAsync(env, root, trial, true, deadline.Token);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(provider.Originals).IsEqualTo(1); await Clean(provider);
    }

    public static IEnumerable<(string Operation, string Variant, string Fault)> TokenFailures() =>
        from operation in IdentityPermissionContract.Operations
        from action in new[] { IdentityPermissionAction.CreateToken, IdentityPermissionAction.DeleteToken, IdentityPermissionAction.RevokeAuth }
        from fault in new[] { "actor-inventory-mutated", "token-state-mismatch", "omitted-capture", "token-owner", "authentication-substitution", "target-read-policy-actor",
            "capture-substitution", "invalidated-token", "replayed-token", "revoke-ack-only", "scope403-not-invalid" }
        where !(fault is "capture-substitution" or "invalidated-token" or "replayed-token") || action == IdentityPermissionAction.CreateToken
        where !(fault is "revoke-ack-only" or "scope403-not-invalid") || action != IdentityPermissionAction.CreateToken
        select (operation, IdentityPermissionContract.Variant(action), fault);
    [Test]
    [MethodDataSource(nameof(TokenFailures))]
    public async Task TargetTokenFailuresCannotChangeActorInventoryOrCertifyAuthentication(string operation, string variant, string fault)
    {
        await using var provider = new InfisicalIdentityPermissionFixture(fault);
        var result = await RunAsync(provider, operation, variant, "independent-effect");
        await Assert.That(result.Passed).IsFalse(); await Assert.That(provider.Closes).IsEqualTo(1);
        await Clean(provider);
    }
    internal static async Task<NativeCaseResult> RunAsync(InfisicalIdentityPermissionFixture provider, string operation, string variant, string boundary,
        IIdentityPermissionSource? source = null)
    {
        using var env = provider.Environment(operation, InfisicalIdentityPermissionGateTests.Action(variant));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var definition = InfisicalIdentityPermissionGateTests.Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        registry.Add(new(definition, async (probe, token) =>
        {
            probe.Contract(IdentityPermissionContract.Owns(definition), NativeFailure.ContractMismatch);
            var context = new ProjectFamilyContext(env, IdentityPermissionContract.Family(operation), definition, probe);
            try { await IdentityPermissionEffects.ExecuteAsync(context, source ?? provider.Source.CreateClient(), token); }
            finally { await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }
    internal static async Task Clean(InfisicalIdentityPermissionFixture provider)
    {
        await provider.DrainAsync(); await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.Registrations).IsEqualTo(0); await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }
}
