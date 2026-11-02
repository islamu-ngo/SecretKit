using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalGroupPermissionEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalGroupPermissionGateTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task ExactTypedGroupsEffectsAndExplicitMissingSeams(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalGroupPermissionFixture();
        var result = await RunAsync(provider, operation, variant, boundary);
        bool supported = GroupPermissionContract.Gate(GroupPermissionContract.Scope(operation), InfisicalGroupPermissionGateTests.Action(variant)) is null;
        await Assert.That(result.Passed).IsEqualTo(supported).Because(result.ReasonCode);
        await Assert.That(provider.Opens).IsEqualTo(supported ? 1 : 0);
        await Assert.That(provider.Originals).IsEqualTo(supported && boundary != "cancellation-boundary" ? 1 : 0);
        if (supported) await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault)> Faults() =>
        from operation in GroupPermissionContract.Operations
        from fault in new[] { "ignored-policy", "wrong-policy-target", "action-leak", "scope-leak", "wrong-group", "wrong-member", "wrong-actor", "wrong-credential",
            "actor-kind", "credential-wrong-actor", "membership-wrong-member", "forged-journal", "forged-owner", "forged-ingress", "forged-policy", "forged-storage",
            "forged-membership", "forged-access", "forged-seal", "missing-seal", "missing-journal", "nonterminal", "pending-issuer", "missing-inventory",
            "binding-substitution", "binding-duplicate", "binding-work", "binding-input", "binding-scope", "binding-borrowed", "binding-missing", "intent-mutation",
            "lost-open", "partial-open", "collision", "cleanup", "borrowed-change" }
        select (operation, fault);
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task CounterexamplesCannotCertifyGroupsOrCleanup(string operation, string fault)
    {
        await using var provider = new InfisicalGroupPermissionFixture(fault);
        var result = await RunAsync(provider, operation, "permission.Groups.read", "independent-effect");
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
        await using var provider = new InfisicalGroupPermissionFixture(fault);
        await Assert.That((await RunAsync(provider, operation, "permission.Groups.read", "independent-effect")).Passed).IsFalse();
        await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, int Outcome)> Lost() =>
        GroupPermissionContract.Operations.SelectMany(op => new[] { (op, "lost-nonapplied", 0), (op, "partial", 2) });
    [Test]
    [MethodDataSource(nameof(Lost))]
    public async Task LostOriginalIsCausalImmutableAndNeverReplayed(string operation, string fault, int outcome)
    {
        await using var provider = new InfisicalGroupPermissionFixture(fault); using var env = provider.Environment(operation, GroupPermissionAction.Read);
        var root = provider.Root(operation, GroupPermissionAction.Read, "lost-response-no-replay");
        using var cap = SecretMaterial.FromText("group-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        GroupPermissionTrial? retained = null;
        try
        {
            var trial = await GroupPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
            await GroupPermissionEffects.WitnessAsync(env, root, trial, false, deadline.Token); await trial.ArmAsync(deadline.Token);
            var original = await GroupPermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token);
            await trial.SettleAsync(original, deadline.Token);
            await Assert.That((int)trial.Outcome).IsEqualTo(outcome);
            await Assert.That(ReferenceEquals(original, trial.Original)).IsTrue();
            await Assert.That(original.Native.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            if (outcome == 0) await GroupPermissionEffects.WitnessAsync(env, root, trial, true, deadline.Token);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(provider.Originals).IsEqualTo(1); await Clean(provider);
    }
    internal static async Task<NativeCaseResult> RunAsync(InfisicalGroupPermissionFixture provider, string operation, string variant, string boundary)
    {
        using var env = provider.Environment(operation, InfisicalGroupPermissionGateTests.Action(variant));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var definition = InfisicalGroupPermissionGateTests.Definition(operation, variant, boundary); var registry = new NativeCaseRegistry();
        registry.Add(new(definition, async (probe, token) =>
        {
            probe.Contract(GroupPermissionContract.Owns(definition), NativeFailure.ContractMismatch);
            var context = new ProjectFamilyContext(env, GroupPermissionContract.Family(operation), definition, probe);
            try { await GroupPermissionEffects.ExecuteAsync(context, provider.Source.CreateClient(), token); }
            finally { await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }
    internal static async Task Clean(InfisicalGroupPermissionFixture provider)
    {
        await provider.DrainAsync(); await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.Registrations).IsEqualTo(0); await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }
}
