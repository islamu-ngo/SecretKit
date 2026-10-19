using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalAuthTemplatePermissionEffectTests
{
    internal const string Execute = "i.management.ManagementClient.ExecuteAsync";
    public static IEnumerable<(string Operation, int Action, string Boundary, bool Generic)> Cases() =>
        from op in AuthTemplatePermissionContract.Operations
        from action in Enum.GetValues<AuthTemplatePermissionAction>()
        from boundary in AuthTemplatePermissionContract.Boundaries
        from generic in new[] { false, true }
        select (op, (int)action, boundary, generic);
    [Test]
    public async Task OrganizationOnlyDenominatorRetainsAllTwelvePairs()
    {
        await Assert.That(Cases().Count()).IsEqualTo(120);
        await Assert.That(Cases().Count(c => c.Action != (int)AuthTemplatePermissionAction.Unlink)).IsEqualTo(100);
        foreach (var row in Cases())
        {
            var d = Definition(row.Operation, (AuthTemplatePermissionAction)row.Action, row.Boundary);
            await Assert.That(InfisicalPermissionFamilies.Valid(d) && AuthTemplatePermissionContract.Owns(d)).IsTrue();
            await Assert.That(InfisicalGovernanceFamilies.Bindings[Execute].Variants.Contains("factory." + row.Operation)).IsTrue();
        }
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task TypedRoleAndTemplateEffectsPreserveOriginalBoundaries(string operation, int action, string boundary, bool generic)
    {
        await using var fixture = new InfisicalAuthTemplatePermissionFixture();
        var result = await RunAsync(fixture, operation, (AuthTemplatePermissionAction)action, boundary, generic);
        bool supported = action != (int)AuthTemplatePermissionAction.Unlink;
        await Assert.That(result.Passed).IsEqualTo(supported).Because(result.ReasonCode);
        await Assert.That(fixture.Opens).IsEqualTo(supported ? 1 : 0);
        await Assert.That(fixture.Originals).IsEqualTo(supported && boundary != "cancellation-boundary" ? 1 : 0);
        await Assert.That(result.Variant).IsEqualTo(generic ? "factory." + operation : AuthTemplatePermissionContract.Variant((AuthTemplatePermissionAction)action));
        await Clean(fixture);
    }
    public static IEnumerable<(string Operation, int Action, string Fault)> Faults() =>
        from op in AuthTemplatePermissionContract.Operations
        from action in AuthTemplatePermissionContract.Supported
        from fault in new[] { "ignored-policy", "wrong-subject", "wrong-actor", "wrong-organization", "wrong-configuration",
            "actor-leak", "organization-leak", "kind-leak", "credential-leak", "wrong-credential", "assignment-echo",
            "missing-journal", "lost-open", "partial-open", "collision", "cleanup", "borrowed-change" }
        select (op, (int)action, fault);
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task ActualAuthorityAndRecoveryAdversariesFailClosed(string operation, int action, string fault)
    {
        await using var fixture = new InfisicalAuthTemplatePermissionFixture(fault);
        var result = await RunAsync(fixture, operation, (AuthTemplatePermissionAction)action, "independent-effect");
        await Assert.That(result.Passed).IsFalse().Because(fault);
        await Assert.That(fixture.Closes).IsEqualTo(1);
        if (fault is "cleanup" or "borrowed-change")
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        else await Clean(fixture);
    }
    public static IEnumerable<(int Action, string Fault)> StateFaults() =>
        from action in new[] { AuthTemplatePermissionAction.Create, AuthTemplatePermissionAction.Edit, AuthTemplatePermissionAction.Delete }
        from fault in new[] { "authorized-uncommitted", "unauthorized-commit", "peer-change", "wrong-state" }
        select ((int)action, fault);
    [Test]
    [MethodDataSource(nameof(StateFaults))]
    public async Task PersistedStateNotMutationResponseDeterminesSuccess(int action, string fault)
    {
        await using var fixture = new InfisicalAuthTemplatePermissionFixture(fault);
        var result = await RunAsync(fixture, AuthTemplatePermissionContract.Operations[0], (AuthTemplatePermissionAction)action, "independent-effect");
        await Assert.That(result.Passed).IsFalse().Because(fault); await Clean(fixture);
    }
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task EmptyAvailableOrSearchSuccessCannotReplaceOwnedSelectedRow(bool attach)
    {
        await using var fixture = new InfisicalAuthTemplatePermissionFixture("empty-collection");
        var result = await RunAsync(fixture, AuthTemplatePermissionContract.Operations[0],
            attach ? AuthTemplatePermissionAction.Attach : AuthTemplatePermissionAction.List, "independent-effect");
        await Assert.That(result.Passed).IsFalse(); await Clean(fixture);
    }
    internal static NativeCaseDefinition Definition(string operation, AuthTemplatePermissionAction action, string boundary) =>
        new(new("Infisical", operation, AuthTemplatePermissionContract.Variant(action), "local", boundary),
            InfisicalPermissionFamilies.Bindings[operation].Member);
    internal static async Task<NativeCaseResult> RunAsync(InfisicalAuthTemplatePermissionFixture fixture, string operation,
        AuthTemplatePermissionAction action, string boundary, bool generic = false, bool configured = true)
    {
        using var env = fixture.Environment(operation, action, configured);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var selected = Definition(operation, action, boundary);
        var definition = generic ? new NativeCaseDefinition(new("Infisical", Execute, "factory." + operation, "local", boundary),
            InfisicalGovernanceFamilies.Bindings[Execute].Member) : selected;
        var registry = new NativeCaseRegistry();
        registry.Add(new(definition, async (probe, token) =>
        {
            probe.Contract(AuthTemplatePermissionContract.Owns(selected), NativeFailure.ContractMismatch);
            var context = new ProjectFamilyContext(env, "RoleChanges", selected, probe);
            try { await AuthTemplatePermissionEffects.ExecuteAsync(context, fixture.Source.CreateClient(), token); }
            finally { await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }
    internal static async Task Clean(InfisicalAuthTemplatePermissionFixture fixture)
    {
        await fixture.DrainAsync();
        await Assert.That(fixture.Remaining).IsEqualTo(0);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
        await Assert.That(fixture.BorrowedPreserved).IsTrue();
        await Assert.That(fixture.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }
}
