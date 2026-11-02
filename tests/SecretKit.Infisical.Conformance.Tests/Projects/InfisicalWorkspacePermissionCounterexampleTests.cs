using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalWorkspacePermissionCounterexampleTests
{
    public static IEnumerable<(string Operation, string Fault, bool Generic)> Cascades() =>
        from operation in WorkspacePermissionContract.Operations
        where WorkspacePermissionContract.Scope(operation) == WorkspacePermissionScope.Project
        from fault in new[] { "acknowledged-not-deleted", "omitted-cascade", "wrong-cascade", "lost-tombstone", "recycled-scope", "retained-corruption", "action-leak" }
        from generic in new[] { false, true }
        select (operation, fault, generic);
    [Test]
    [MethodDataSource(nameof(Cascades))]
    public async Task DeletionAcknowledgementCannotReplaceTerminalClosure(string operation, string fault, bool generic)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(fault);
        var result = await InfisicalWorkspacePermissionEffectTests.RunAsync(provider, operation, "permission.Workspace.delete", "independent-effect", generic);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(provider.Closes).IsEqualTo(1);
        await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }
    public static IEnumerable<(string Operation, string Fault, int Action)> Templates() =>
        from operation in WorkspacePermissionContract.Operations.Where(WorkspacePermissionContract.Template)
        from fault in new[] { "template-echo", "template-settings", "template-copy-configuration" }
        from action in new[] { WorkspacePermissionAction.Edit, WorkspacePermissionAction.Delete }
        select (operation, fault, (int)action);
    [Test]
    [MethodDataSource(nameof(Templates))]
    public async Task ActualCopiedPolicyAndConfigurationAreRequired(string operation, string fault, int action)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(fault);
        var result = await InfisicalWorkspacePermissionEffectTests.RunAsync(provider, operation,
            WorkspacePermissionContract.Variant((WorkspacePermissionAction)action), "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }
    public static IEnumerable<(string Operation, int Action)> ProjectActions() =>
        from operation in WorkspacePermissionContract.Operations
        where WorkspacePermissionContract.Scope(operation) == WorkspacePermissionScope.Project
        from action in new[] { WorkspacePermissionAction.Edit, WorkspacePermissionAction.Delete }
        select (operation, (int)action);
    [Test]
    [MethodDataSource(nameof(ProjectActions))]
    public async Task OriginalScopeSurvivesBaselineAndBindingsSurviveDeletion(string operation, int action)
    {
        await using var provider = new InfisicalWorkspacePermissionFixture(); using var env = provider.Environment(operation, (WorkspacePermissionAction)action);
        if (WorkspacePermissionContract.Gate(WorkspacePermissionContract.Scope(operation), (WorkspacePermissionAction)action) is not null)
        {
            var rejected = await InfisicalWorkspacePermissionEffectTests.RunAsync(provider, operation,
                WorkspacePermissionContract.Variant((WorkspacePermissionAction)action), "independent-effect");
            await Assert.That(rejected.Passed).IsFalse();
            await Assert.That(provider.Opens).IsEqualTo(0);
            await InfisicalWorkspacePermissionEffectTests.Clean(provider);
            return;
        }
        var root = provider.Root(operation, (WorkspacePermissionAction)action, "independent-effect");
        using var cap = SecretMaterial.FromText("workspace-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        WorkspacePermissionTrial? retained = null;
        try
        {
            var trial = await WorkspacePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
            string originalScope = trial.Issued.Id(WorkspacePermissionPlan.Project);
            var originalBindings = trial.Issued.Bindings.ToArray();
            await WorkspacePermissionEffects.WitnessAsync(env, root, trial, false, deadline.Token);
            await Assert.That(trial.Inventory.Any(s => s.Target == originalScope)).IsTrue();
            await Assert.That(trial.Issued.Bindings.SequenceEqual(originalBindings)).IsTrue();
            await trial.ArmAsync(deadline.Token);
            var receipt = await WorkspacePermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token);
            await trial.SettleAsync(receipt, deadline.Token);
            await WorkspacePermissionEffects.ActivateAsync(env, root, trial, deadline.Token);
            await WorkspacePermissionEffects.WitnessAsync(env, root, trial, true, deadline.Token);
            await Assert.That(trial.Issued.Id(WorkspacePermissionPlan.Project)).IsEqualTo(originalScope);
            await Assert.That(trial.Issued.Bindings.Take(originalBindings.Length).SequenceEqual(originalBindings)).IsTrue();
            await Assert.That(ReferenceEquals(receipt, trial.Original)).IsTrue();
            await Assert.That(receipt.Native.Evidence).IsEqualTo(DispatchEvidence.Applied);
            if ((WorkspacePermissionAction)action == WorkspacePermissionAction.Delete)
            {
                string deleted = trial.Issued.Id(WorkspacePermissionContract.Template(operation) ? WorkspacePermissionPlan.CopyProject : WorkspacePermissionPlan.Project);
                await Assert.That(trial.Inventory.Any(s => s.Target == deleted)).IsFalse();
                await Assert.That(trial.Issued.Bindings.Any(b => b.CanonicalId == deleted)).IsTrue();
            }
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await InfisicalWorkspacePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ControlledEvidenceDoesNotCloseNativeCertificationGates()
    {
        await using var provider = new InfisicalWorkspacePermissionFixture();
        await Assert.That(provider.Source.CreateClient().Kind).IsEqualTo(MemberPermissionSourceKind.ControlledFixture);
        await Assert.That(WorkspacePermissionContract.NativeGates.Length).IsEqualTo(5);
        await Assert.That(WorkspacePermissionContract.Actions(WorkspacePermissionScope.Organization).SequenceEqual([WorkspacePermissionAction.Create])).IsTrue();
        await Assert.That(WorkspacePermissionContract.Actions(WorkspacePermissionScope.Project).SequenceEqual([WorkspacePermissionAction.Edit, WorkspacePermissionAction.Delete])).IsTrue();
    }
}
