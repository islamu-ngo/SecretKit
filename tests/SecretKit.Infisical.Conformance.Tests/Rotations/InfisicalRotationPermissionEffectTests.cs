using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalRotationPermissionEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        InfisicalRotationPermissionGateTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OptionalEffectsObserveAllActionsScopesPrincipalsAndOriginalBoundaries(string operation, string variant, string boundary)
    {
        await using var fixture = new InfisicalRotationPermissionFixture();
        var result = await RunAsync(fixture, operation, variant, boundary);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await Assert.That(fixture.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await CleanAsync(fixture);
    }
    internal static async Task<NativeCaseResult> RunAsync(InfisicalRotationPermissionFixture fixture,
        string operation, string variant, string boundary)
    {
        using var env = fixture.Environment(InfisicalRotationPermissionGateTests.Action(variant));
        var definition = InfisicalRotationPermissionGateTests.Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        registry.Add(new(definition, async (probe, token) =>
        {
            probe.Contract(RotationPermissionContract.Owns(definition), NativeFailure.ContractMismatch);
            string family = operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal) ? "RoleChanges" :
                operation.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal) ? "ProjectTemplates" : "IdentityPrivilegeChanges";
            var context = new ProjectFamilyContext(env, family, definition, probe);
            try { await RotationPermissionEffects.ExecuteAsync(context, fixture.Source.CreateClient(), token, fixture.Runtime); }
            finally { await context.CleanupAsync(); }
        }));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        return (await NativeCaseRunner.RunAsync(registry, [definition], timeout.Token)).Single();
    }
    [Test]
    [Arguments("ignored-policy")]
    [Arguments("action-leak")]
    [Arguments("scope-leak")]
    [Arguments("wrong-principal")]
    [Arguments("wrong-credential")]
    [Arguments("wrong-route")]
    [Arguments("wrong-source")]
    [Arguments("forged-journal")]
    [Arguments("forged-owner")]
    [Arguments("strip-action")]
    [Arguments("tamper-commit")]
    [Arguments("ignored-config")]
    [Arguments("ignored-rotation")]
    [Arguments("wrong-material")]
    [Arguments("ignored-backend")]
    [Arguments("backend-permission")]
    [Arguments("incomplete-list")]
    [Arguments("partial-open")]
    [Arguments("lost-open")]
    [Arguments("collision")]
    public async Task IndependentFaultsCannotQualifyEffects(string fault)
    {
        await using var fixture = new InfisicalRotationPermissionFixture(fault);
        var result = await RunAsync(fixture, "i.management.RoleChangeOperations.UpdateProjectRole",
            "permission.SecretRotation.edit", "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await CleanAsync(fixture);
    }
    [Test]
    [Arguments("cleanup")]
    [Arguments("policy-cleanup")]
    [Arguments("backend-cleanup")]
    [Arguments("borrowed-change")]
    public async Task CleanupInventoriesAndBorrowedStateAreMandatory(string fault)
    {
        await using var fixture = new InfisicalRotationPermissionFixture(fault);
        var result = await RunAsync(fixture, "i.management.RoleChangeOperations.UpdateProjectRole",
            "permission.SecretRotation.edit", "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
    }
    [Test]
    [Arguments("lost-nonapplied", 1)]
    [Arguments("partial", 2)]
    public async Task LostOriginalReceiptRemainsUnknownAcrossCausalSettlement(string fault, int expected)
    {
        await using var fixture = new InfisicalRotationPermissionFixture(fault);
        using var env = fixture.Environment(RotationPermissionAction.Edit);
        var root = fixture.Root("i.management.RoleChangeOperations.UpdateProjectRole", RotationPermissionAction.Edit, "lost-response-no-replay");
        RotationPermissionTrial? retained = null;
        using var capability = SecretMaterial.FromText("rotation-capability");
        try
        {
            var trial = await RotationPermissionTrial.OpenAsync(fixture.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None);
            await RotationPermissionEffects.WitnessAsync(env, root, trial, false, CancellationToken.None, fixture.Runtime);
            await trial.ArmAsync(CancellationToken.None);
            var original = await RotationPermissionEffects.DispatchAsync(env, root, trial.Issued, CancellationToken.None);
            await trial.SettleAsync(original, CancellationToken.None);
            await Assert.That((int)trial.Outcome).IsEqualTo(expected);
            await Assert.That(original.Native.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            await Assert.That(original.Cancelled).IsTrue();
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(fixture.Originals).IsEqualTo(1);
        await CleanAsync(fixture);
    }
    internal static async Task CleanAsync(InfisicalRotationPermissionFixture fixture)
    {
        await fixture.DrainAsync();
        await Assert.That(fixture.Closes).IsEqualTo(1);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
        await Assert.That(fixture.Remaining).IsEqualTo(0);
        await Assert.That(fixture.BorrowedPreserved).IsTrue();
        await Assert.That(fixture.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }
}
