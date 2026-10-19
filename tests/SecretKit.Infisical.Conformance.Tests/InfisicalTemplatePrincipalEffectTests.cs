using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalTemplatePrincipalEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary, int Shape)> Cases() =>
        InfisicalTemplatePrincipalCalibrationTests.Cases();
    public static IEnumerable<(string Field, string Fault)> Faults() =>
        from field in TemplatePrincipalContract.Fields
        from fault in new[] { "ignored-copy", "ignored-principal-update", "copied-wrong-user", "wrong-group-membership", "unchanged-copied-roles",
            "extra-copied-role", "wrong-principal", "denied-accepted", "valid-recheck-denied", "host-runtime-access",
            "source-echo", "coordinator-forgery", "content-tamper", "cleanup", "borrowed-change", "lost-open", "partial-open" }
        select (field, fault);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OptionalEffectsRequireSdkMembershipCopyAndFreshPrincipalAccess(string operation,
        string variant, string boundary, int shape)
    {
        await using var fixture = new InfisicalTemplatePrincipalFixture();
        var result = await RunAsync(fixture, operation, variant, boundary, (TemplatePrincipalShape)shape);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await Assert.That(fixture.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await InfisicalTemplatePrincipalCalibrationTests.CleanAsync(fixture);
    }
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task IndependentProviderAndSourceFaultsFailActualEffect(string field, string fault)
    {
        await using var fixture = new InfisicalTemplatePrincipalFixture(fault);
        var result = await RunAsync(fixture, TemplatePrincipalContract.Update,
            "ProjectTemplateConfiguration." + field + ".value", "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await Assert.That(fixture.Closes).IsEqualTo(1);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
        if (fault == "cleanup")
        {
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
            await Assert.That(fixture.Remaining > 0).IsTrue();
            await Assert.That(fixture.Copies.Any(b => b.Any(x => x != 0))).IsTrue();
        }
        else if (fault == "borrowed-change")
        {
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
            await Assert.That(fixture.BorrowedPreserved).IsFalse();
        }
        else await InfisicalTemplatePrincipalCalibrationTests.CleanAsync(fixture);
        if (fault == "coordinator-forgery")
        {
            await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
            await Assert.That(fixture.Originals).IsEqualTo(0);
        }
    }
    [Test]
    [Arguments("lost-nonapplied", true)]
    [Arguments("lost-partial", false)]
    public async Task LostEffectsDistinguishNonAppliedFromPartialWithoutReplaying(string fault, bool passed)
    {
        await using var fixture = new InfisicalTemplatePrincipalFixture(fault);
        var result = await RunAsync(fixture, TemplatePrincipalContract.Update,
            "ProjectTemplateConfiguration.users.value", "lost-response-no-replay");
        await Assert.That(result.Passed).IsEqualTo(passed);
        await Assert.That(fixture.Originals).IsEqualTo(1);
        await InfisicalTemplatePrincipalCalibrationTests.CleanAsync(fixture);
    }
    internal static async Task<NativeCaseResult> RunAsync(InfisicalTemplatePrincipalFixture fixture,
        string operation, string variant, string boundary, TemplatePrincipalShape shape = TemplatePrincipalShape.Values)
    {
        using var env = fixture.Environment(shape);
        var d = InfisicalTemplatePrincipalCalibrationTests.Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        registry.Add(new(d, async (probe, token) =>
        {
            var c = new ProjectFamilyContext(env, "ProjectTemplates", d, probe);
            try { await TemplatePrincipalEffects.ExecuteAsync(c, fixture.Source.CreateClient(), token); }
            finally { await c.CleanupAsync(); }
        }));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        return (await NativeCaseRunner.RunAsync(registry, [d], timeout.Token)).Single();
    }
    [Test]
    public async Task InterruptedOpenClosesOriginalRootWithoutReturnedIdentifiers()
    {
        await using var fixture = new InfisicalTemplatePrincipalFixture("blocked-open");
        var root = fixture.Root(TemplatePrincipalContract.Create, "ProjectTemplateConfiguration.users.value", "independent-effect");
        using var capability = SecretMaterial.FromText("private-user-capability");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        TemplatePrincipalTrial? retained = null;
        Task entered = fixture.OpenEntered.Task;
        var opening = TemplatePrincipalTrial.OpenAsync(fixture.Source.CreateClient(), root, capability, 20,
            t => retained = t, timeout.Token).AsTask();
        await entered.WaitAsync(timeout.Token);
        await retained!.DisposeAsync();
        bool failed = false;
        try { await opening; } catch (NativeCaseFailureException) { failed = true; }
        await Assert.That(failed).IsTrue();
        await InfisicalTemplatePrincipalCalibrationTests.CleanAsync(fixture);
    }
    [Test]
    [Arguments("collision")]
    [Arguments("lost-reserve")]
    public async Task FailedReservationIssuesNothingAndOriginalRootStillCleans(string fault)
    {
        await using var fixture = new InfisicalTemplatePrincipalFixture(fault);
        var result = await RunAsync(fixture, TemplatePrincipalContract.Create,
            "ProjectTemplateConfiguration.users.value", "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Opens).IsEqualTo(0);
        await Assert.That(fixture.Issuers.Count).IsEqualTo(0);
        await InfisicalTemplatePrincipalCalibrationTests.CleanAsync(fixture);
    }
    [Test]
    public async Task SettledOriginalCannotReplayOrDispatchAfterClose()
    {
        await using var fixture = new InfisicalTemplatePrincipalFixture();
        using var env = fixture.Environment();
        var root = fixture.Root(TemplatePrincipalContract.Update, "ProjectTemplateConfiguration.users.value", "independent-effect");
        using var capability = SecretMaterial.FromText("private-user-capability");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        TemplatePrincipalTrial? retained = null;
        try
        {
            var trial = await TemplatePrincipalTrial.OpenAsync(fixture.Source.CreateClient(), root, capability, 20,
                t => retained = t, timeout.Token);
            await TemplatePrincipalEffects.SetupAsync(env, trial, timeout.Token);
            await TemplatePrincipalEffects.WitnessAsync(env, trial, false, timeout.Token);
            using (var original = TemplatePrincipalEffects.Original(root, trial.Issued))
                await trial.ArmAsync(original.Target.SecondaryId!, timeout.Token);
            await trial.SettleAsync(await TemplatePrincipalEffects.DispatchAsync(env, root, trial.Issued, timeout.Token), timeout.Token);
            var replay = await TemplatePrincipalEffects.DispatchAsync(env, root, trial.Issued, timeout.Token);
            await Assert.That(replay.Status == SecretStatus.Success).IsFalse();
            await Assert.That(fixture.Originals).IsEqualTo(1);
            await trial.DisposeAsync();
            var late = await TemplatePrincipalEffects.DispatchAsync(env, root, trial.Issued, timeout.Token);
            await Assert.That(late.Status == SecretStatus.Success).IsFalse();
            await Assert.That(fixture.Originals).IsEqualTo(1);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await InfisicalTemplatePrincipalCalibrationTests.CleanAsync(fixture);
    }
}
