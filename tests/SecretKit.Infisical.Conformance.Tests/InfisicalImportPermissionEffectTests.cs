using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalImportPermissionEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        InfisicalImportPermissionGateTests.Cases();
    public static IEnumerable<(string Operation, string Fault)> Faults()
    {
        foreach (string operation in ImportPermissionContract.Operations)
            foreach (string fault in new[] { "ignored-policy", "action-leak", "scope-leak", "wrong-principal",
                "forged-journal", "forged-owner", "strip-action", "tamper-commit", "wrong-linkage", "ignored-linkage", "ignored-source", "ignored-environment", "source-cleanup", "receiver-cleanup", "incomplete-list", "duplicate-list",
                "cleanup", "policy-cleanup", "lost-open", "partial-open", "borrowed-change", "collision",
                "incomplete-source-inventory", "duplicate-source-inventory" })
                yield return (operation, fault);
        foreach (string operation in ImportPermissionContract.Operations.Where(ImportPermissionContract.Template))
            yield return (operation, "template-echo");
        yield return ("i.management.RoleChangeOperations.CreateProjectRole", "assignment-echo");
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task EffectsRequireOneActionAndRejectEveryOtherActionScopeAndPrincipal(string operation, string variant, string boundary)
    {
        await using var fixture = new InfisicalImportPermissionFixture();
        var result = await RunAsync(fixture, operation, variant, boundary);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await Assert.That(fixture.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await Clean(fixture);
    }
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task IndependentProviderPolicyJournalBackendAndCleanupFaultsFail(string operation, string fault)
    {
        await using var fixture = new InfisicalImportPermissionFixture(fault);
        var result = await RunAsync(fixture, operation, ImportPermissionContract.Variant(operation, ImportPermissionAction.Edit),
            "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Opens).IsEqualTo(fault == "collision" ? 0 : 1);
        await Assert.That(fixture.Closes).IsEqualTo(1);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
        if (fault is "cleanup" or "policy-cleanup" or "source-cleanup" or "receiver-cleanup")
        {
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
            await Assert.That(fixture.Remaining > 0).IsTrue();
        }
        else if (fault == "borrowed-change")
        {
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
            await Assert.That(fixture.BorrowedPreserved).IsFalse();
            await Assert.That(fixture.Remaining).IsEqualTo(0);
        }
        else await Clean(fixture);
        if (fault is "forged-journal" or "forged-owner")
        {
            await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
            await Assert.That(fixture.Originals).IsEqualTo(0);
        }
    }
    public static IEnumerable<(string Operation, string Fault, int Outcome)> LostCases() =>
        ImportPermissionContract.Operations.SelectMany(op => new[] { (op, "lost-nonapplied", 1), (op, "partial", 2) });
    [Test]
    [MethodDataSource(nameof(LostCases))]
    public async Task LostOriginalSettlesCausallyWithoutReplayOrReceiptRewrite(string operation, string fault, int expected)
    {
        await using var fixture = new InfisicalImportPermissionFixture(fault);
        using var env = fixture.Environment(ImportPermissionAction.Edit);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        using var capability = SecretMaterial.FromText("import-capability");
        var root = fixture.Root(operation, ImportPermissionAction.Edit, "lost-response-no-replay");
        ImportPermissionTrial? retained = null;
        try
        {
            var trial = await ImportPermissionTrial.OpenAsync(fixture.Source.CreateClient(), root, capability, t => retained = t, deadline.Token);
            await ImportPermissionEffects.WitnessAsync(env, root, trial, false, deadline.Token);
            await trial.ArmAsync(deadline.Token);
            var receipt = await ImportPermissionEffects.DispatchAsync(env, root, trial.Issued, deadline.Token);
            await trial.SettleAsync(receipt, deadline.Token);
            await Assert.That((int)trial.Outcome).IsEqualTo(expected);
            await Assert.That(ReferenceEquals(trial.Original, receipt)).IsTrue();
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            await Assert.That(receipt.Cancelled).IsTrue();
            if (fault == "lost-nonapplied")
                await ImportPermissionEffects.WitnessAsync(env, root, trial, true, deadline.Token);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(fixture.Originals).IsEqualTo(1);
        await Clean(fixture);
    }
    [Test]
    public async Task OptionalSelectionDoesNotBroadenOtherSubjectsMetadataOrDefaults()
    {
        foreach (var pair in InfisicalPermissionFamilies.Bindings.Concat(InfisicalProjectFamilies.Bindings))
            foreach (string variant in pair.Value.Variants)
            {
                var d = new NativeCaseDefinition(new("Infisical", pair.Key, variant, "local", "independent-effect"), pair.Value.Member);
                bool expected = ImportPermissionContract.Operations.Contains(pair.Key) &&
                    Enum.GetValues<ImportPermissionAction>().Any(a => ImportPermissionContract.Variant(pair.Key, a) == variant);
                await Assert.That(ImportPermissionContract.Owns(d)).IsEqualTo(expected);
            }
    }
    internal static async Task<NativeCaseResult> RunAsync(InfisicalImportPermissionFixture fixture,
        string operation, string variant, string boundary)
    {
        using var env = fixture.Environment(InfisicalImportPermissionGateTests.Action(operation, variant));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var d = InfisicalImportPermissionGateTests.Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        registry.Add(new(d, async (probe, token) =>
        {
            probe.Contract(ImportPermissionContract.Owns(d), NativeFailure.ContractMismatch);
            var context = new ProjectFamilyContext(env, ImportPermissionContract.Template(operation) ? "ProjectTemplates" :
                operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal) ? "RoleChanges" : "IdentityPrivilegeChanges", d, probe);
            try { await ImportPermissionEffects.ExecuteAsync(context, fixture.Source.CreateClient(), token); }
            finally { await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [d], deadline.Token)).Single();
    }
    internal static async Task Clean(InfisicalImportPermissionFixture fixture)
    {
        await fixture.DrainAsync();
        await Assert.That(fixture.Closes).IsEqualTo(1);
        await Assert.That(fixture.Remaining).IsEqualTo(0);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
        await Assert.That(fixture.BorrowedPreserved).IsTrue();
        await Assert.That(fixture.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }
}
