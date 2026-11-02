using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalMemberPermissionEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalMemberPermissionGateTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task EffectsCoverExactTypedSeamsAndRetainMissingContracts(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalMemberPermissionFixture();
        var result = await RunAsync(provider, operation, variant, boundary);
        bool supported = MemberPermissionContract.Gate(MemberPermissionContract.Scope(operation), InfisicalMemberPermissionGateTests.Action(variant)) is null;
        await Assert.That(result.Passed).IsEqualTo(supported).Because(result.ReasonCode);
        await Assert.That(provider.Opens).IsEqualTo(supported ? 1 : 0);
        await Assert.That(provider.Originals).IsEqualTo(supported && boundary != "cancellation-boundary" ? 1 : 0);
        if (supported) await Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault)> Faults() =>
        from operation in MemberPermissionContract.Operations
        from fault in new[] { "ignored-policy", "wrong-policy-target", "action-leak", "scope-leak", "wrong-member", "wrong-actor", "wrong-credential",
            "credential-wrong-user", "membership-wrong-user", "actor-kind", "forged-journal", "missing-journal",
            "forged-owner", "forged-ingress", "forged-policy", "forged-storage", "forged-membership", "forged-access", "forged-seal",
            "missing-seal", "nonterminal", "pending-issuer", "missing-inventory", "lost-open", "partial-open",
            "collision", "cleanup", "policy-cleanup", "borrowed-change" }
        select (operation, fault);
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task IndependentCounterexamplesFailWithoutCertifyingAnEffect(string operation, string fault)
    {
        await using var provider = new InfisicalMemberPermissionFixture(fault);
        var result = await RunAsync(provider, operation, "permission.Member.read", "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Closes).IsEqualTo(1);
        await Assert.That(provider.Registrations).IsEqualTo(0);
        if (fault is "cleanup" or "policy-cleanup" or "borrowed-change")
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        else await Clean(provider);
    }
    [Test]
    [Arguments("i.management.ProjectTemplateOperations.CreateProjectTemplate", "template-echo")]
    [Arguments("i.management.ProjectTemplateOperations.UpdateProjectTemplate", "template-echo")]
    [Arguments("i.management.RoleChangeOperations.CreateProjectRole", "assignment-echo")]
    [Arguments("i.management.RoleChangeOperations.CreateOrganizationRole", "assignment-echo")]
    public async Task PolicyAcknowledgementCannotSubstituteForActorMembershipActivation(string operation, string fault)
    {
        await using var provider = new InfisicalMemberPermissionFixture(fault);
        var result = await RunAsync(provider, operation, "permission.Member.read", "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await InfisicalMemberPermissionEffectTests.Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, int Outcome)> LostCases() =>
        MemberPermissionContract.Operations.SelectMany(operation => new[] { (operation, "lost-nonapplied", 0), (operation, "partial", 2) });
    [Test]
    [MethodDataSource(nameof(LostCases))]
    public async Task LostOriginalClassificationIsCausalAndReceiptIsUnchanged(string operation, string fault, int outcome)
    {
        await using var provider = new InfisicalMemberPermissionFixture(fault);
        using var env = provider.Environment(operation, MemberPermissionAction.Read);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var capability = SecretMaterial.FromText("member-capability");
        var root = provider.Root(operation, MemberPermissionAction.Read, "lost-response-no-replay");
        MemberPermissionTrial? retained = null;
        try
        {
            var trial = await MemberPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, timeout.Token);
            await MemberPermissionEffects.WitnessAsync(env, root, trial, false, timeout.Token);
            await trial.ArmAsync(timeout.Token);
            var original = await MemberPermissionEffects.DispatchAsync(env, root, trial.Issued, timeout.Token);
            await trial.SettleAsync(original, timeout.Token);
            await Assert.That((int)trial.Outcome).IsEqualTo(outcome);
            await Assert.That(ReferenceEquals(original, trial.Original)).IsTrue();
            await Assert.That(original.Native.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            if (outcome == 0) await MemberPermissionEffects.WitnessAsync(env, root, trial, true, timeout.Token);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(provider.Originals).IsEqualTo(1);
        await Clean(provider);
    }
    internal static async Task<NativeCaseResult> RunAsync(InfisicalMemberPermissionFixture provider,
        string operation, string variant, string boundary)
    {
        using var env = provider.Environment(operation, InfisicalMemberPermissionGateTests.Action(variant));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var definition = InfisicalMemberPermissionGateTests.Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        registry.Add(new(definition, async (probe, token) =>
        {
            probe.Contract(MemberPermissionContract.Owns(definition), NativeFailure.ContractMismatch);
            var context = new ProjectFamilyContext(env, MemberPermissionContract.Family(operation), definition, probe);
            try { await MemberPermissionEffects.ExecuteAsync(context, provider.Source.CreateClient(), token); }
            finally { await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }
    internal static async Task Clean(InfisicalMemberPermissionFixture provider)
    {
        await provider.DrainAsync();
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }
}
